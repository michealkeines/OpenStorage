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
    #[error("metadata: {0}")]
    Metadata(String),
}

impl RepairError {
    /// Convenience for converting a metadata-scan error into a `Metadata`
    /// variant while preserving the cause text.
    fn with_msg(self, msg: String) -> Self {
        match self {
            Self::QueueOverflow { .. } => Self::Metadata(msg),
            other => other,
        }
    }
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

    /// F-HM-5 GC Sweep — walk every Chunk; if its `refcount` is ≤ 0,
    /// enqueue a `GcSweep` task. Caller wires a worker that picks the
    /// task off the queue and invokes plugin deletes per shard.
    /// Returns the number of tasks enqueued.
    pub fn gc_sweep(&self, store: &os_metadata::Store) -> Result<usize, RepairError> {
        let mut count = 0usize;
        for kv in store
            .backend()
            .scan_prefix(os_metadata::ColumnFamily::Chunks, b"")
            .map_err(|e| RepairError::QueueOverflow {
                size: 0,
                max: 0,
            }
            .with_msg(format!("scan: {e}")))?
        {
            let (_, v) = kv.map_err(|e| RepairError::QueueOverflow {
                size: 0,
                max: 0,
            }
            .with_msg(format!("scan: {e}")))?;
            let chunk: os_entities::Chunk = match ciborium::from_reader(&v[..]) {
                Ok(c) => c,
                Err(_) => continue,
            };
            if chunk.refcount.value() <= 0 {
                self.enqueue(RepairTask {
                    chunk_hash: chunk.chunk_hash,
                    priority: 1,
                    source: RepairSource::GcSweep,
                    attempt: 0,
                })?;
                count += 1;
            }
        }
        Ok(count)
    }

    /// F-HM-1 Background Scrub — sample a fraction of chunks (default 5 %)
    /// and enqueue `Scrub` tasks. The caller's worker loop is responsible
    /// for the actual peek + repair-on-mismatch step. Returns the number
    /// of tasks enqueued.
    pub fn scrub_sweep(
        &self,
        store: &os_metadata::Store,
        sample_per_thousand: u32,
    ) -> Result<usize, RepairError> {
        let mut count = 0usize;
        let mut idx: u64 = 0;
        for kv in store
            .backend()
            .scan_prefix(os_metadata::ColumnFamily::Chunks, b"")
            .map_err(|e| RepairError::QueueOverflow {
                size: 0,
                max: 0,
            }
            .with_msg(format!("scan: {e}")))?
        {
            let (_, v) = kv.map_err(|e| RepairError::QueueOverflow {
                size: 0,
                max: 0,
            }
            .with_msg(format!("scan: {e}")))?;
            let chunk: os_entities::Chunk = match ciborium::from_reader(&v[..]) {
                Ok(c) => c,
                Err(_) => continue,
            };
            // Deterministic sampling: hash(chunk_hash || idx) mod 1000 < N.
            let mut h = blake3::Hasher::new();
            h.update(chunk.chunk_hash.as_bytes());
            h.update(&idx.to_be_bytes());
            let bucket =
                u32::from_be_bytes(h.finalize().as_bytes()[..4].try_into().unwrap()) % 1000;
            idx += 1;
            if bucket < sample_per_thousand {
                self.enqueue(RepairTask {
                    chunk_hash: chunk.chunk_hash,
                    priority: 1,
                    source: RepairSource::Scrub,
                    attempt: 0,
                })?;
                count += 1;
            }
        }
        Ok(count)
    }

    /// F-HM-4 Rebalance on Plugin Add — when a new provider becomes
    /// available, enqueue a fraction of existing chunks for placement
    /// re-evaluation. The actual placement decision happens in the worker
    /// after dequeue (the spec calls for `placement.evaluate_rebalance_targets`).
    /// Returns the number of tasks enqueued.
    pub fn rebalance_on_plugin_add(
        &self,
        store: &os_metadata::Store,
        fraction_per_thousand: u32,
    ) -> Result<usize, RepairError> {
        let mut count = 0usize;
        let mut idx: u64 = 0;
        for kv in store
            .backend()
            .scan_prefix(os_metadata::ColumnFamily::Chunks, b"")
            .map_err(|e| RepairError::QueueOverflow {
                size: 0,
                max: 0,
            }
            .with_msg(format!("scan: {e}")))?
        {
            let (_, v) = kv.map_err(|e| RepairError::QueueOverflow {
                size: 0,
                max: 0,
            }
            .with_msg(format!("scan: {e}")))?;
            let chunk: os_entities::Chunk = match ciborium::from_reader(&v[..]) {
                Ok(c) => c,
                Err(_) => continue,
            };
            let mut h = blake3::Hasher::new();
            h.update(b"rebalance:");
            h.update(chunk.chunk_hash.as_bytes());
            h.update(&idx.to_be_bytes());
            let bucket =
                u32::from_be_bytes(h.finalize().as_bytes()[..4].try_into().unwrap()) % 1000;
            idx += 1;
            if bucket < fraction_per_thousand {
                self.enqueue(RepairTask {
                    chunk_hash: chunk.chunk_hash,
                    priority: 0,
                    source: RepairSource::Rebalance,
                    attempt: 0,
                })?;
                count += 1;
            }
        }
        Ok(count)
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

    use os_metadata::{backend::MemoryBackend, ColumnFamily, Store, Txn};
    use std::sync::Arc;

    fn store_with_chunks(refcount_zero: usize, refcount_pos: usize) -> Arc<Store> {
        let store = Arc::new(Store::new(Arc::new(MemoryBackend::new())));
        let mut txn = Txn::new();
        for i in 0..(refcount_zero + refcount_pos) {
            let mut bytes = [0u8; 32];
            bytes[..8].copy_from_slice(&(i as u64).to_be_bytes());
            let chunk_hash = ChunkHash::from_bytes(bytes);
            let mut refcount = os_entities::Counter::default();
            if i >= refcount_zero {
                refcount.inc(os_types::DeviceId::new_v7(), 1);
            }
            let chunk = os_entities::Chunk {
                chunk_hash,
                plaintext_length: 0,
                ec_scheme: os_types::ECScheme { k: 1, n: 1 },
                shard_list: Vec::new(),
                refcount,
                replication_state: os_entities::ReplicationState::Full,
                last_scrubbed_at: os_types::Timestamp::from_string("t0"),
                access_count_window: os_entities::Counter::default(),
                tier: os_types::Tier::Hot,
            };
            let mut buf = Vec::new();
            ciborium::into_writer(&chunk, &mut buf).unwrap();
            txn.put(ColumnFamily::Chunks, chunk_hash.as_bytes().to_vec(), buf);
        }
        store.commit(txn).unwrap();
        store
    }

    /// F-HM-5 — `gc_sweep` enqueues exactly the chunks with refcount ≤ 0.
    #[test]
    fn gc_sweep_enqueues_zero_refcount_chunks() {
        let s = RepairScheduler::new(64);
        let store = store_with_chunks(3, 5);
        let n = s.gc_sweep(&store).unwrap();
        assert_eq!(n, 3);
        for _ in 0..3 {
            let task = s.drain_one().unwrap();
            assert!(matches!(task.source, RepairSource::GcSweep));
        }
    }

    /// F-HM-1 — `scrub_sweep(50)` samples roughly 5 % of chunks. Allow a
    /// generous range since the sample is bucket-deterministic per chunk.
    #[test]
    fn scrub_sweep_samples_chunks() {
        let s = RepairScheduler::new(2048);
        let store = store_with_chunks(0, 1000);
        let n = s.scrub_sweep(&store, 50).unwrap();
        assert!(
            (1..=200).contains(&n),
            "expected scrub sample in [1,200], got {n}"
        );
        for _ in 0..n {
            let t = s.drain_one().unwrap();
            assert!(matches!(t.source, RepairSource::Scrub));
        }
    }

    /// F-HM-4 — `rebalance_on_plugin_add(100)` enqueues a fraction of
    /// existing chunks for placement re-evaluation.
    #[test]
    fn rebalance_enqueues_a_fraction() {
        let s = RepairScheduler::new(2048);
        let store = store_with_chunks(0, 1000);
        let n = s.rebalance_on_plugin_add(&store, 100).unwrap();
        assert!(
            (10..=300).contains(&n),
            "expected rebalance fraction in [10,300], got {n}"
        );
        for _ in 0..n {
            let t = s.drain_one().unwrap();
            assert!(matches!(t.source, RepairSource::Rebalance));
        }
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
