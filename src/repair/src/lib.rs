//! os-repair — priority repair scheduler + GC sweep.
//!
//! Skeleton implementation: a priority queue of repair tasks. The actual
//! plugin-driven repair (read source replica → re-place → write new shard) is
//! reserved for a follow-up.

#![forbid(unsafe_code)]

use std::collections::BinaryHeap;
use std::sync::Mutex;

use os_types::ChunkHash;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RepairError {
    #[error("queue overflow ({size}/{max})")]
    QueueOverflow { size: usize, max: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepairSource {
    ReadRepair,
    Scrub,
    AntiEntropy,
    GcSweep,
    Rebalance,
}

#[derive(Debug, Clone)]
pub struct RepairTask {
    pub chunk_hash: ChunkHash,
    pub priority: u32,
    pub source: RepairSource,
    pub attempt: u32,
}

impl PartialEq for RepairTask {
    fn eq(&self, o: &Self) -> bool {
        self.priority == o.priority && self.chunk_hash == o.chunk_hash
    }
}
impl Eq for RepairTask {}
impl PartialOrd for RepairTask {
    fn partial_cmp(&self, o: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(o))
    }
}
impl Ord for RepairTask {
    fn cmp(&self, o: &Self) -> std::cmp::Ordering {
        // Higher priority first; tie-break by chunk_hash bytes for determinism.
        self.priority
            .cmp(&o.priority)
            .then_with(|| self.chunk_hash.as_bytes().cmp(o.chunk_hash.as_bytes()))
    }
}

pub struct RepairScheduler {
    queue: Mutex<BinaryHeap<RepairTask>>,
    max_size: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct QueueState {
    pub depth: usize,
    pub max: usize,
}

impl RepairScheduler {
    pub fn new(max_size: usize) -> Self {
        Self {
            queue: Mutex::new(BinaryHeap::new()),
            max_size,
        }
    }

    pub fn enqueue(&self, task: RepairTask) -> Result<(), RepairError> {
        let mut q = self.queue.lock().expect("repair queue mutex");
        if q.len() >= self.max_size {
            return Err(RepairError::QueueOverflow {
                size: q.len(),
                max: self.max_size,
            });
        }
        q.push(task);
        Ok(())
    }

    pub fn drain_one(&self) -> Option<RepairTask> {
        self.queue.lock().expect("repair queue mutex").pop()
    }

    pub fn state(&self) -> QueueState {
        let q = self.queue.lock().expect("repair queue mutex");
        QueueState {
            depth: q.len(),
            max: self.max_size,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn task(p: u32) -> RepairTask {
        RepairTask {
            chunk_hash: ChunkHash::from_bytes([p as u8; 32]),
            priority: p,
            source: RepairSource::Scrub,
            attempt: 0,
        }
    }

    #[test]
    fn higher_priority_first() {
        let s = RepairScheduler::new(8);
        s.enqueue(task(1)).unwrap();
        s.enqueue(task(5)).unwrap();
        s.enqueue(task(3)).unwrap();
        assert_eq!(s.drain_one().unwrap().priority, 5);
        assert_eq!(s.drain_one().unwrap().priority, 3);
        assert_eq!(s.drain_one().unwrap().priority, 1);
    }

    #[test]
    fn overflow_returns_error() {
        let s = RepairScheduler::new(2);
        s.enqueue(task(1)).unwrap();
        s.enqueue(task(2)).unwrap();
        assert!(matches!(
            s.enqueue(task(3)),
            Err(RepairError::QueueOverflow { .. })
        ));
    }
}
