//! HLC generator. Wraps `os_types::Hlc::tick_local` with a thread-safe
//! current-time source.

use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use os_types::Hlc;

pub struct HlcGenerator {
    last: Mutex<Hlc>,
}

impl HlcGenerator {
    pub fn new() -> Self {
        Self {
            last: Mutex::new(Hlc::ZERO),
        }
    }

    pub fn from_seed(seed: Hlc) -> Self {
        Self {
            last: Mutex::new(seed),
        }
    }

    /// Generate a fresh HLC for a local event.
    pub fn next_local(&self) -> Hlc {
        let now_ms = now_ms();
        let mut g = self.last.lock().expect("HLC mutex");
        let next = Hlc::tick_local(*g, now_ms);
        *g = next;
        next
    }

    /// Update local view with a remote HLC and return the new local clock.
    pub fn observe_remote(&self, remote: Hlc) -> Hlc {
        let now_ms = now_ms();
        let mut g = self.last.lock().expect("HLC mutex");
        let next = Hlc::merge_remote(*g, remote, now_ms);
        *g = next;
        next
    }

    pub fn current(&self) -> Hlc {
        *self.last.lock().expect("HLC mutex")
    }
}

impl Default for HlcGenerator {
    fn default() -> Self {
        Self::new()
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_local_strictly_increasing() {
        let g = HlcGenerator::new();
        let mut prev = Hlc::ZERO;
        for _ in 0..1000 {
            let h = g.next_local();
            assert!(h > prev);
            prev = h;
        }
    }

    #[test]
    fn observe_remote_jumps_forward() {
        let g = HlcGenerator::new();
        let _ = g.next_local();
        let far_future = Hlc::new(now_ms() + 60_000, 0);
        let after = g.observe_remote(far_future);
        assert!(after > far_future);
    }
}
