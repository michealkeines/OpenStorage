//! os-events — in-process pub/sub event bus with bounded ring buffer.
//!
//! Any module emits `events/.publish(event)`; subscribers register a glob
//! filter and receive events on a tokio mpsc channel. A reconnecting
//! subscriber may pass `since` to replay events still in the ring buffer.

#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use os_types::{Hlc, VaultId};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    pub event_id: u64,
    pub name: String,
    pub vault_id: Option<VaultId>,
    pub hlc: Hlc,
    pub payload: serde_json::Value,
}

impl Event {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            event_id: 0,
            name: name.into(),
            vault_id: None,
            hlc: Hlc::ZERO,
            payload: serde_json::Value::Null,
        }
    }
    pub fn with_vault(mut self, v: VaultId) -> Self {
        self.vault_id = Some(v);
        self
    }
    pub fn with_payload(mut self, p: serde_json::Value) -> Self {
        self.payload = p;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Filter {
    pub pattern: String,
}

impl Filter {
    pub fn matches(&self, name: &str) -> bool {
        glob_match(&self.pattern, name)
    }
}

fn glob_match(pattern: &str, name: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix(".*") {
        return name.starts_with(prefix) && name.len() > prefix.len() && name.as_bytes()[prefix.len()] == b'.';
    }
    pattern == name
}

pub struct EventBus {
    inner: Arc<Mutex<BusInner>>,
}

struct BusInner {
    next_id: u64,
    ring: VecDeque<Event>,
    capacity: usize,
    subscribers: Vec<Subscriber>,
}

struct Subscriber {
    id: u64,
    filter: Filter,
    sender: mpsc::Sender<Event>,
}

pub struct Subscription {
    pub id: u64,
    pub receiver: mpsc::Receiver<Event>,
}

impl EventBus {
    pub fn new() -> Self {
        Self::with_capacity(10_000)
    }
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(BusInner {
                next_id: 1,
                ring: VecDeque::with_capacity(capacity),
                capacity,
                subscribers: Vec::new(),
            })),
        }
    }

    pub fn publish(&self, mut e: Event) -> u64 {
        let mut g = self.inner.lock().expect("event bus mutex");
        let id = g.next_id;
        g.next_id += 1;
        e.event_id = id;
        // ring buffer
        if g.ring.len() == g.capacity {
            g.ring.pop_front();
        }
        g.ring.push_back(e.clone());
        // fanout
        let subs = g.subscribers.clone_for_iter();
        drop(g);
        for s in subs {
            if s.filter.matches(&e.name) {
                let _ = s.sender.try_send(e.clone());
            }
        }
        id
    }

    /// Subscribe with optional replay-from id. Returns a `Subscription` whose
    /// `receiver` yields matching events.
    pub fn subscribe(&self, filter: Filter, since: Option<u64>) -> Subscription {
        let (tx, rx) = mpsc::channel(256);
        let mut g = self.inner.lock().expect("event bus mutex");
        let id = g.next_id;
        g.next_id += 1;
        // replay
        if let Some(s) = since {
            for e in g.ring.iter() {
                if e.event_id > s && filter.matches(&e.name) {
                    let _ = tx.try_send(e.clone());
                }
            }
        }
        g.subscribers.push(Subscriber {
            id,
            filter,
            sender: tx,
        });
        Subscription { id, receiver: rx }
    }

    pub fn unsubscribe(&self, id: u64) {
        let mut g = self.inner.lock().expect("event bus mutex");
        g.subscribers.retain(|s| s.id != id);
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

trait CloneForIter {
    fn clone_for_iter(&self) -> Vec<Subscriber>;
}

impl CloneForIter for Vec<Subscriber> {
    fn clone_for_iter(&self) -> Vec<Subscriber> {
        self.iter()
            .map(|s| Subscriber {
                id: s.id,
                filter: s.filter.clone(),
                sender: s.sender.clone(),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn deliver_matching_events() {
        let bus = EventBus::new();
        let mut sub = bus.subscribe(
            Filter {
                pattern: "vault.*".into(),
            },
            None,
        );
        let id1 = bus.publish(Event::new("vault.unlocked"));
        let id2 = bus.publish(Event::new("repair.started")); // not matched
        let id3 = bus.publish(Event::new("vault.locked"));
        let _ = (id1, id2, id3);
        let e = sub.receiver.recv().await.unwrap();
        assert_eq!(e.name, "vault.unlocked");
        let e = sub.receiver.recv().await.unwrap();
        assert_eq!(e.name, "vault.locked");
    }

    #[tokio::test]
    async fn replay_from_since() {
        let bus = EventBus::new();
        let id = bus.publish(Event::new("write.quorum_acked"));
        let mut sub = bus.subscribe(
            Filter {
                pattern: "*".into(),
            },
            Some(id - 1),
        );
        let e = sub.receiver.recv().await.unwrap();
        assert_eq!(e.event_id, id);
    }

    #[test]
    fn glob_match_basic() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("vault.*", "vault.unlocked"));
        assert!(!glob_match("vault.*", "vaultlike"));
        assert!(!glob_match("vault.*", "share.created"));
        assert!(glob_match("share.created", "share.created"));
    }
}
