//! Backend trait and two implementations: in-memory and sled.
//!
//! A `Backend` is the byte-level KV. Higher-level entity (de)serialization
//! lives in `store.rs`.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use crate::{ColumnFamily, MetadataError, Result};

/// One pending write within a transaction.
#[derive(Debug, Clone)]
pub enum WriteOp {
    Put {
        cf: ColumnFamily,
        key: Vec<u8>,
        value: Vec<u8>,
    },
    Delete {
        cf: ColumnFamily,
        key: Vec<u8>,
    },
}

#[derive(Debug, Default, Clone)]
pub struct Txn {
    pub ops: Vec<WriteOp>,
}

impl Txn {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn put(&mut self, cf: ColumnFamily, key: impl Into<Vec<u8>>, value: impl Into<Vec<u8>>) {
        self.ops.push(WriteOp::Put {
            cf,
            key: key.into(),
            value: value.into(),
        });
    }
    pub fn delete(&mut self, cf: ColumnFamily, key: impl Into<Vec<u8>>) {
        self.ops.push(WriteOp::Delete {
            cf,
            key: key.into(),
        });
    }
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }
}

/// Read-side iterator yielding `(key, value)`.
pub trait ScanIter: Iterator<Item = Result<(Vec<u8>, Vec<u8>)>> + Send {}
impl<T: Iterator<Item = Result<(Vec<u8>, Vec<u8>)>> + Send> ScanIter for T {}

pub trait Backend: Send + Sync {
    fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>>;
    fn commit(&self, txn: Txn) -> Result<()>;
    fn scan_prefix(
        &self,
        cf: ColumnFamily,
        prefix: &[u8],
    ) -> Result<Box<dyn Iterator<Item = Result<(Vec<u8>, Vec<u8>)>> + Send + '_>>;
    fn flush(&self) -> Result<()>;
}

// ──────────────────────────────────────────────────────────────────────────
// In-memory backend
// ──────────────────────────────────────────────────────────────────────────

#[derive(Default)]
pub struct MemoryBackend {
    inner: Arc<Mutex<MemInner>>,
}

#[derive(Default)]
struct MemInner {
    cfs: BTreeMap<&'static str, BTreeMap<Vec<u8>, Vec<u8>>>,
}

impl MemoryBackend {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Backend for MemoryBackend {
    fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let g = self.inner.lock().expect("memory backend mutex");
        Ok(g.cfs.get(cf.as_str()).and_then(|m| m.get(key).cloned()))
    }

    fn commit(&self, txn: Txn) -> Result<()> {
        let mut g = self.inner.lock().expect("memory backend mutex");
        for op in txn.ops {
            match op {
                WriteOp::Put { cf, key, value } => {
                    g.cfs.entry(cf.as_str()).or_default().insert(key, value);
                }
                WriteOp::Delete { cf, key } => {
                    if let Some(m) = g.cfs.get_mut(cf.as_str()) {
                        m.remove(&key);
                    }
                }
            }
        }
        Ok(())
    }

    fn scan_prefix(
        &self,
        cf: ColumnFamily,
        prefix: &[u8],
    ) -> Result<Box<dyn Iterator<Item = Result<(Vec<u8>, Vec<u8>)>> + Send + '_>> {
        let g = self.inner.lock().expect("memory backend mutex");
        let snapshot: Vec<(Vec<u8>, Vec<u8>)> = match g.cfs.get(cf.as_str()) {
            Some(m) => m
                .range(prefix.to_vec()..)
                .take_while(|(k, _)| k.starts_with(prefix))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            None => Vec::new(),
        };
        Ok(Box::new(snapshot.into_iter().map(Ok)))
    }

    fn flush(&self) -> Result<()> {
        Ok(())
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Sled backend
// ──────────────────────────────────────────────────────────────────────────

pub struct SledBackend {
    db: sled::Db,
    trees: BTreeMap<&'static str, sled::Tree>,
}

impl SledBackend {
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self> {
        let db = sled::open(path).map_err(|e| MetadataError::Backend(e.to_string()))?;
        let mut trees = BTreeMap::new();
        for cf in ColumnFamily::ALL {
            let t = db
                .open_tree(cf.as_str())
                .map_err(|e| MetadataError::Backend(e.to_string()))?;
            trees.insert(cf.as_str(), t);
        }
        Ok(Self { db, trees })
    }
}

impl Backend for SledBackend {
    fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let t = self.trees.get(cf.as_str()).expect("cf must be opened");
        Ok(t.get(key)
            .map_err(|e| MetadataError::Backend(e.to_string()))?
            .map(|iv| iv.to_vec()))
    }

    fn commit(&self, txn: Txn) -> Result<()> {
        // sled exposes tree-level transactions; for cross-tree atomicity we
        // use `sled::Tree::transaction` over the set of trees touched.
        use sled::transaction::TransactionError;
        use std::collections::BTreeSet;

        let touched: BTreeSet<&'static str> = txn
            .ops
            .iter()
            .map(|op| match op {
                WriteOp::Put { cf, .. } | WriteOp::Delete { cf, .. } => cf.as_str(),
            })
            .collect();
        let trees: Vec<&sled::Tree> = touched
            .iter()
            .map(|n| self.trees.get(n).expect("cf"))
            .collect();
        let result: std::result::Result<(), TransactionError<()>> =
            sled::Transactional::transaction(trees.as_slice(), |tx_trees| {
                let name_to_idx: BTreeMap<&'static str, usize> = touched
                    .iter()
                    .enumerate()
                    .map(|(i, n)| (*n, i))
                    .collect();
                for op in &txn.ops {
                    let (cf, _) = match op {
                        WriteOp::Put { cf, .. } | WriteOp::Delete { cf, .. } => (cf, ()),
                    };
                    let idx = *name_to_idx.get(cf.as_str()).expect("cf indexed");
                    let tree = &tx_trees[idx];
                    match op {
                        WriteOp::Put { key, value, .. } => {
                            tree.insert(key.as_slice(), value.as_slice())?;
                        }
                        WriteOp::Delete { key, .. } => {
                            tree.remove(key.as_slice())?;
                        }
                    }
                }
                Ok(())
            });
        result.map_err(|e| MetadataError::Backend(format!("{e:?}")))
    }

    fn scan_prefix(
        &self,
        cf: ColumnFamily,
        prefix: &[u8],
    ) -> Result<Box<dyn Iterator<Item = Result<(Vec<u8>, Vec<u8>)>> + Send + '_>> {
        let t = self.trees.get(cf.as_str()).expect("cf must be opened");
        let it = t.scan_prefix(prefix).map(|r| {
            r.map(|(k, v)| (k.to_vec(), v.to_vec()))
                .map_err(|e| MetadataError::Backend(e.to_string()))
        });
        Ok(Box::new(it))
    }

    fn flush(&self) -> Result<()> {
        self.db
            .flush()
            .map(|_| ())
            .map_err(|e| MetadataError::Backend(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_round_trip() {
        let b = MemoryBackend::new();
        let mut txn = Txn::new();
        txn.put(ColumnFamily::Files, b"k1", b"v1");
        txn.put(ColumnFamily::Files, b"k2", b"v2");
        b.commit(txn).unwrap();
        assert_eq!(
            b.get(ColumnFamily::Files, b"k1").unwrap(),
            Some(b"v1".to_vec())
        );
    }

    #[test]
    fn memory_scan_prefix_inclusive() {
        let b = MemoryBackend::new();
        let mut txn = Txn::new();
        for k in ["a-1", "a-2", "b-1"] {
            txn.put(ColumnFamily::Files, k.as_bytes(), b"v");
        }
        b.commit(txn).unwrap();
        let count: usize = b
            .scan_prefix(ColumnFamily::Files, b"a-")
            .unwrap()
            .count();
        assert_eq!(count, 2);
    }

    #[test]
    fn memory_delete_within_txn() {
        let b = MemoryBackend::new();
        let mut t1 = Txn::new();
        t1.put(ColumnFamily::Files, b"k", b"v");
        b.commit(t1).unwrap();
        let mut t2 = Txn::new();
        t2.delete(ColumnFamily::Files, b"k");
        b.commit(t2).unwrap();
        assert!(b.get(ColumnFamily::Files, b"k").unwrap().is_none());
    }
}
