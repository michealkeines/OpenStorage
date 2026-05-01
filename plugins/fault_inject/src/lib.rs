//! `os-plugin-fault-inject` — wraps any other `PluginContract` and injects
//! configurable failures so the state machines (chunk Degraded/Lost,
//! shard Healthy→Degraded, repair task transitions, shadow registration)
//! become reachable from external callers.
//!
//! Failure modes:
//! - `fail_next_n_puts(n)`     → next N `put` calls return `Unavailable`.
//! - `fail_next_n_gets(n)`     → next N `get` calls return `Unavailable`.
//! - `corrupt_next_n_gets(n)`  → next N `get` calls return random bytes
//!                                (drives AEAD verify failure → read-repair).
//! - `fail_handles(set)`       → any `put`/`get`/`delete` against a handle
//!                                in `set` fails.
//! - `pause()` / `resume()`    → all calls return `Unavailable` until resumed.

#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use os_entities::{NativeHandle, PutHint};
use os_plugin_host::contract::{
    DeleteResult, HealthReport, HealthState, PeekResult, PluginContract, PutResult,
};
use os_plugin_host::PluginError;
use os_types::{HealthScore, Range};

#[derive(Default, Debug)]
struct State {
    fail_puts: u32,
    fail_gets: u32,
    corrupt_gets: u32,
    failed_handles: HashSet<Vec<u8>>,
    paused: bool,
}

pub struct FaultInjectPlugin {
    inner: Arc<dyn PluginContract>,
    state: Arc<Mutex<State>>,
}

impl FaultInjectPlugin {
    pub fn new(inner: Arc<dyn PluginContract>) -> Self {
        Self {
            inner,
            state: Arc::new(Mutex::new(State::default())),
        }
    }

    pub fn handle(&self) -> FaultHandle {
        FaultHandle {
            state: self.state.clone(),
        }
    }
}

#[derive(Clone)]
pub struct FaultHandle {
    state: Arc<Mutex<State>>,
}

impl FaultHandle {
    pub fn fail_next_puts(&self, n: u32) {
        self.state.lock().expect("fault state").fail_puts = n;
    }
    pub fn fail_next_gets(&self, n: u32) {
        self.state.lock().expect("fault state").fail_gets = n;
    }
    pub fn corrupt_next_gets(&self, n: u32) {
        self.state.lock().expect("fault state").corrupt_gets = n;
    }
    pub fn fail_handle(&self, h: &NativeHandle) {
        self.state
            .lock()
            .expect("fault state")
            .failed_handles
            .insert(h.0.clone());
    }
    pub fn pause(&self) {
        self.state.lock().expect("fault state").paused = true;
    }
    pub fn resume(&self) {
        self.state.lock().expect("fault state").paused = false;
    }
    pub fn clear(&self) {
        let mut s = self.state.lock().expect("fault state");
        s.fail_puts = 0;
        s.fail_gets = 0;
        s.corrupt_gets = 0;
        s.failed_handles.clear();
        s.paused = false;
    }
    pub fn snapshot(&self) -> FaultSnapshot {
        let s = self.state.lock().expect("fault state");
        FaultSnapshot {
            fail_puts: s.fail_puts,
            fail_gets: s.fail_gets,
            corrupt_gets: s.corrupt_gets,
            failed_handle_count: s.failed_handles.len(),
            paused: s.paused,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct FaultSnapshot {
    pub fail_puts: u32,
    pub fail_gets: u32,
    pub corrupt_gets: u32,
    pub failed_handle_count: usize,
    pub paused: bool,
}

#[async_trait]
impl PluginContract for FaultInjectPlugin {
    fn rate_limit_profile(&self) -> os_plugin_host::RateLimitProfile {
        // Forward the inner plugin's profile unchanged — fault injection
        // doesn't change rate-limit characteristics, it just simulates them.
        self.inner.rate_limit_profile()
    }

    async fn put(&self, payload: &[u8], hint: &PutHint) -> Result<PutResult, PluginError> {
        let take = {
            let mut s = self.state.lock().expect("fault state");
            if s.paused {
                return Err(PluginError::Unavailable("fault: paused".into()));
            }
            if s.fail_puts > 0 {
                s.fail_puts -= 1;
                true
            } else {
                false
            }
        };
        if take {
            return Err(PluginError::Unavailable("fault: forced put failure".into()));
        }
        self.inner.put(payload, hint).await
    }

    async fn get(
        &self,
        handle: &NativeHandle,
        range: Option<Range>,
    ) -> Result<Vec<u8>, PluginError> {
        let mode = {
            let mut s = self.state.lock().expect("fault state");
            if s.paused {
                return Err(PluginError::Unavailable("fault: paused".into()));
            }
            if s.failed_handles.contains(&handle.0) {
                Some(GetMode::Fail)
            } else if s.fail_gets > 0 {
                s.fail_gets -= 1;
                Some(GetMode::Fail)
            } else if s.corrupt_gets > 0 {
                s.corrupt_gets -= 1;
                Some(GetMode::Corrupt)
            } else {
                None
            }
        };
        match mode {
            Some(GetMode::Fail) => Err(PluginError::Unavailable("fault: forced get failure".into())),
            Some(GetMode::Corrupt) => {
                // Return one byte off from the real ciphertext so the AEAD verify fails.
                let real = self.inner.get(handle, range).await?;
                let mut corrupt = real;
                if !corrupt.is_empty() {
                    corrupt[0] ^= 0xFF;
                }
                Ok(corrupt)
            }
            None => self.inner.get(handle, range).await,
        }
    }

    async fn peek(&self, handle: &NativeHandle) -> Result<PeekResult, PluginError> {
        if self.state.lock().expect("fault state").paused {
            return Err(PluginError::Unavailable("fault: paused".into()));
        }
        self.inner.peek(handle).await
    }

    async fn delete(&self, handle: &NativeHandle) -> Result<DeleteResult, PluginError> {
        if self.state.lock().expect("fault state").paused {
            return Err(PluginError::Unavailable("fault: paused".into()));
        }
        self.inner.delete(handle).await
    }

    async fn health(&self) -> Result<HealthReport, PluginError> {
        let snap = self.handle().snapshot();
        let mut rep = self.inner.health().await?;
        if snap.paused {
            rep.state = HealthState::Unhealthy;
            rep.score = HealthScore::new(0.0);
        } else if snap.fail_puts + snap.fail_gets + snap.corrupt_gets > 0 {
            rep.state = HealthState::Degraded;
            rep.score = HealthScore::new(0.5);
        }
        Ok(rep)
    }
}

#[derive(Debug)]
enum GetMode {
    Fail,
    Corrupt,
}
