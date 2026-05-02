//! Append-only WAL. Entries are stored on disk in a simple length-prefixed
//! framed format and indexed by `(device_id, seq)`.
//!
//! On-disk layout per entry:
//! ```text
//! [u32 BE length] [CBOR-encoded WalEntry] [u32 BE crc32 over CBOR]
//! ```
//! Crash safety: each append fsyncs the file. A short read at the tail
//! (truncated length prefix or body) is treated as not-yet-committed and
//! discarded on open.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::Mutex;

use os_crypto::{sign, SymKey};
use os_entities::{Op, WalEntry};
use os_types::{
    DeviceId, Ed25519Priv, Ed25519Sig, IdempotencyKey, KeyPurpose, WalEntryId,
};

use crate::policy::{check_indirect_allowed, WalConfig};
use crate::{HlcGenerator, Result, WalError};

const FRAME_LEN_BYTES: usize = 4;
const FRAME_CRC_BYTES: usize = 4;

pub struct Wal {
    cfg: WalConfig,
    device_id: DeviceId,
    device_priv: Ed25519Priv,
    hlc: HlcGenerator,
    inner: Mutex<WalInner>,
}

struct WalInner {
    file: File,
    next_seq: u64,
    /// Lowest retained seq. After `truncate_through(cutoff)` this advances to
    /// `cutoff` and entries < cutoff are gone from disk.
    min_seq: u64,
    /// Cached (offset, len) for each retained entry. `index[i]` corresponds
    /// to seq `min_seq + i`.
    index: Vec<EntrySlot>,
}

#[derive(Debug, Clone, Copy)]
struct EntrySlot {
    offset: u64,
    len: u32,
}

pub struct WalBuilder {
    cfg: WalConfig,
    path: Option<PathBuf>,
}

impl WalBuilder {
    pub fn new() -> Self {
        Self {
            cfg: WalConfig::default(),
            path: None,
        }
    }
    pub fn config(mut self, cfg: WalConfig) -> Self {
        self.cfg = cfg;
        self
    }
    pub fn path(mut self, p: impl Into<PathBuf>) -> Self {
        self.path = Some(p.into());
        self
    }
    pub fn build(self, device_id: DeviceId, device_priv: Ed25519Priv) -> Result<Wal> {
        let path = self
            .path
            .ok_or_else(|| WalError::Io("WalBuilder needs a path".into()))?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| WalError::Io(e.to_string()))?;
        }
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(false)
            .write(true)
            .open(&path)
            .map_err(|e| WalError::Io(e.to_string()))?;
        let mut wal = Wal {
            cfg: self.cfg,
            device_id,
            device_priv,
            hlc: HlcGenerator::new(),
            inner: Mutex::new(WalInner {
                file,
                next_seq: 0,
                min_seq: 0,
                index: Vec::new(),
            }),
        };
        wal.recover()?;
        Ok(wal)
    }
}

impl Default for WalBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl Wal {
    pub fn config(&self) -> WalConfig {
        self.cfg
    }
    pub fn device_id(&self) -> DeviceId {
        self.device_id
    }
    pub fn current_hlc(&self) -> os_types::Hlc {
        self.hlc.current()
    }
    pub fn next_seq(&self) -> u64 {
        self.inner.lock().expect("wal mutex").next_seq
    }
    /// Lowest seq still retained on disk. Advances after `truncate_through`.
    pub fn min_seq(&self) -> u64 {
        self.inner.lock().expect("wal mutex").min_seq
    }

    /// Append an op. Returns the resulting entry.
    pub fn append(&self, op: Op, idem: Option<IdempotencyKey>) -> Result<WalEntry> {
        check_indirect_allowed(&op)?;
        let hlc = self.hlc.next_local();
        let mut inner = self.inner.lock().expect("wal mutex");
        let seq = inner.next_seq;
        let wal_id = WalEntryId::new(self.device_id, seq);
        // canonical encoding for signature
        let mut canon = Vec::new();
        ciborium::into_writer(
            &(&wal_id, hlc, self.device_id, &op, &idem),
            &mut canon,
        )
        .map_err(|e| WalError::Serde(e.to_string()))?;
        let sig: Ed25519Sig = sign_with_subkey(&self.device_priv, &canon);
        let entry = WalEntry {
            wal_id,
            hlc,
            device_id: self.device_id,
            op,
            signature: sig,
            idempotency_key: idem,
        };
        let mut body = Vec::new();
        ciborium::into_writer(&entry, &mut body)
            .map_err(|e| WalError::Serde(e.to_string()))?;
        if body.len() > self.cfg.max_entry_bytes {
            return Err(WalError::EntryTooLarge {
                size: body.len(),
                limit: self.cfg.max_entry_bytes,
            });
        }
        // frame: [len BE u32][body][crc BE u32 of body]
        let len = body.len() as u32;
        let crc = crc32(&body);
        let offset = inner
            .file
            .seek(SeekFrom::End(0))
            .map_err(|e| WalError::Io(e.to_string()))?;
        inner
            .file
            .write_all(&len.to_be_bytes())
            .map_err(|e| WalError::Io(e.to_string()))?;
        inner
            .file
            .write_all(&body)
            .map_err(|e| WalError::Io(e.to_string()))?;
        inner
            .file
            .write_all(&crc.to_be_bytes())
            .map_err(|e| WalError::Io(e.to_string()))?;
        inner
            .file
            .sync_data()
            .map_err(|e| WalError::Io(e.to_string()))?;
        inner.index.push(EntrySlot { offset, len });
        inner.next_seq += 1;
        Ok(entry)
    }

    /// Read an entry by seq (originating-device-local).
    pub fn read(&self, seq: u64) -> Result<WalEntry> {
        let mut inner = self.inner.lock().expect("wal mutex");
        if seq < inner.min_seq {
            return Err(WalError::NotFound(seq));
        }
        let idx = (seq - inner.min_seq) as usize;
        let slot = *inner.index.get(idx).ok_or(WalError::NotFound(seq))?;
        let mut buf = vec![0u8; slot.len as usize];
        inner
            .file
            .seek(SeekFrom::Start(slot.offset + FRAME_LEN_BYTES as u64))
            .map_err(|e| WalError::Io(e.to_string()))?;
        inner
            .file
            .read_exact(&mut buf)
            .map_err(|e| WalError::Io(e.to_string()))?;
        let entry: WalEntry =
            ciborium::from_reader(&buf[..]).map_err(|e| WalError::Serde(e.to_string()))?;
        Ok(entry)
    }

    /// Iterate entries from `since_seq` (inclusive) to the current tail. The
    /// returned vec is owned for simplicity; future revisions may stream.
    pub fn scan_since(&self, since_seq: u64) -> Result<Vec<WalEntry>> {
        let last = self.next_seq();
        let mut out = Vec::with_capacity((last.saturating_sub(since_seq)) as usize);
        for s in since_seq..last {
            out.push(self.read(s)?);
        }
        Ok(out)
    }

    /// Drop entries with `seq < cutoff` from disk. Used after a snapshot
    /// rotation: once a seq is contained in a durable snapshot, the WAL
    /// no longer needs to retain it. Idempotent for `cutoff <= min_seq`.
    pub fn truncate_through(&self, cutoff: u64) -> Result<()> {
        let mut inner = self.inner.lock().expect("wal mutex");
        if cutoff <= inner.min_seq {
            return Ok(());
        }
        if cutoff > inner.next_seq {
            return Err(WalError::NotFound(cutoff));
        }
        // Read retained bodies into memory, then rewrite the file.
        let keep_from_idx = (cutoff - inner.min_seq) as usize;
        let kept_slots: Vec<EntrySlot> = inner.index[keep_from_idx..].to_vec();
        let mut bodies: Vec<Vec<u8>> = Vec::with_capacity(kept_slots.len());
        for slot in kept_slots {
            inner
                .file
                .seek(SeekFrom::Start(slot.offset + FRAME_LEN_BYTES as u64))
                .map_err(|e| WalError::Io(e.to_string()))?;
            let mut body = vec![0u8; slot.len as usize];
            inner
                .file
                .read_exact(&mut body)
                .map_err(|e| WalError::Io(e.to_string()))?;
            bodies.push(body);
        }
        // Truncate to zero and rewrite.
        inner
            .file
            .set_len(0)
            .map_err(|e| WalError::Io(e.to_string()))?;
        inner
            .file
            .seek(SeekFrom::Start(0))
            .map_err(|e| WalError::Io(e.to_string()))?;
        let mut new_index: Vec<EntrySlot> = Vec::with_capacity(bodies.len());
        let mut pos = 0u64;
        for body in &bodies {
            let len = body.len() as u32;
            let crc = crc32(body);
            inner
                .file
                .write_all(&len.to_be_bytes())
                .map_err(|e| WalError::Io(e.to_string()))?;
            inner
                .file
                .write_all(body)
                .map_err(|e| WalError::Io(e.to_string()))?;
            inner
                .file
                .write_all(&crc.to_be_bytes())
                .map_err(|e| WalError::Io(e.to_string()))?;
            new_index.push(EntrySlot { offset: pos, len });
            pos += FRAME_LEN_BYTES as u64 + len as u64 + FRAME_CRC_BYTES as u64;
        }
        inner
            .file
            .sync_data()
            .map_err(|e| WalError::Io(e.to_string()))?;
        inner.index = new_index;
        inner.min_seq = cutoff;
        Ok(())
    }

    /// Recover index from on-disk frames. Truncates a partial trailing entry.
    /// If entries exist on disk, the first entry's `wal_id.seq` is taken
    /// as `min_seq` (allowing post-truncate recovery to keep the original
    /// seq numbering rather than restarting at zero).
    fn recover(&mut self) -> Result<()> {
        let mut inner = self.inner.lock().expect("wal mutex");
        let len = inner
            .file
            .seek(SeekFrom::End(0))
            .map_err(|e| WalError::Io(e.to_string()))?;
        inner
            .file
            .seek(SeekFrom::Start(0))
            .map_err(|e| WalError::Io(e.to_string()))?;
        let mut pos = 0u64;
        let mut index = Vec::new();
        let mut len_buf = [0u8; FRAME_LEN_BYTES];
        let mut crc_buf = [0u8; FRAME_CRC_BYTES];
        let mut keep_until = 0u64;
        while pos < len {
            if pos + FRAME_LEN_BYTES as u64 > len {
                break;
            }
            inner
                .file
                .read_exact(&mut len_buf)
                .map_err(|e| WalError::Io(e.to_string()))?;
            let body_len = u32::from_be_bytes(len_buf);
            let body_start = pos + FRAME_LEN_BYTES as u64;
            let body_end = body_start + body_len as u64;
            let crc_end = body_end + FRAME_CRC_BYTES as u64;
            if crc_end > len {
                break; // partial trailing frame
            }
            let mut body = vec![0u8; body_len as usize];
            inner
                .file
                .read_exact(&mut body)
                .map_err(|e| WalError::Io(e.to_string()))?;
            inner
                .file
                .read_exact(&mut crc_buf)
                .map_err(|e| WalError::Io(e.to_string()))?;
            let on_disk_crc = u32::from_be_bytes(crc_buf);
            if on_disk_crc != crc32(&body) {
                break; // partial / corrupt; truncate
            }
            index.push(EntrySlot {
                offset: pos,
                len: body_len,
            });
            pos = crc_end;
            keep_until = pos;
        }
        if keep_until < len {
            inner
                .file
                .set_len(keep_until)
                .map_err(|e| WalError::Io(e.to_string()))?;
        }
        inner
            .file
            .seek(SeekFrom::End(0))
            .map_err(|e| WalError::Io(e.to_string()))?;
        // Read the first surviving entry to recover min_seq (in case the WAL
        // was previously truncated). Falls back to 0 if the log is empty.
        let min_seq = if let Some(first) = index.first() {
            inner
                .file
                .seek(SeekFrom::Start(first.offset + FRAME_LEN_BYTES as u64))
                .map_err(|e| WalError::Io(e.to_string()))?;
            let mut body = vec![0u8; first.len as usize];
            inner
                .file
                .read_exact(&mut body)
                .map_err(|e| WalError::Io(e.to_string()))?;
            let entry: WalEntry = ciborium::from_reader(&body[..])
                .map_err(|e| WalError::Serde(e.to_string()))?;
            entry.wal_id.seq
        } else {
            0
        };
        inner
            .file
            .seek(SeekFrom::End(0))
            .map_err(|e| WalError::Io(e.to_string()))?;
        inner.min_seq = min_seq;
        inner.next_seq = min_seq + index.len() as u64;
        inner.index = index;
        Ok(())
    }
}

fn sign_with_subkey(priv_key: &Ed25519Priv, message: &[u8]) -> Ed25519Sig {
    // Use the device's primary signing key directly. Domain separation could
    // derive a sub-key, but Ed25519 keys are not HKDF-derivable as drop-in
    // signing keys without a deterministic conversion routine; reserve that
    // for a follow-up.
    let _ = SymKey::from_bytes([0u8; 32]); // touch type to avoid unused-import warning
    let _ = KeyPurpose::WAL_SIGN;
    sign(priv_key, message)
}

fn crc32(buf: &[u8]) -> u32 {
    // Simple CRC-32/IEEE; we only need integrity at the framing level. blake3
    // would be overkill and this avoids another dependency.
    const POLY: u32 = 0xEDB88320;
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in buf {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ POLY
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;
    use os_crypto::generate_keypair;
    use os_entities::{Key, KeyKind};
    use rand::rngs::OsRng;

    fn tempdir() -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("os-wal-test-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn open_wal(path: PathBuf) -> Wal {
        let (sk, _pk) = generate_keypair(&mut OsRng);
        WalBuilder::new()
            .path(path)
            .build(DeviceId::new_v7(), sk)
            .unwrap()
    }

    #[test]
    fn append_scan_round_trip() {
        let path = tempdir().join("wal.bin");
        let wal = open_wal(path);
        let op = Op::CounterInc {
            target: Key::new(KeyKind::Chunk, vec![1, 2, 3], "refcount"),
            delta: 1,
        };
        let e = wal.append(op.clone(), None).unwrap();
        let read_back = wal.read(0).unwrap();
        assert_eq!(read_back.wal_id.seq, 0);
        assert_eq!(read_back.hlc, e.hlc);
        match read_back.op {
            Op::CounterInc { delta, .. } => assert_eq!(delta, 1),
            _ => panic!("wrong op kind"),
        }
    }

    #[test]
    fn hlc_strictly_increases_across_appends() {
        let path = tempdir().join("wal.bin");
        let wal = open_wal(path);
        let mut prev = os_types::Hlc::ZERO;
        for i in 0..50 {
            let op = Op::CounterInc {
                target: Key::new(KeyKind::Chunk, vec![i as u8], "refcount"),
                delta: 1,
            };
            let e = wal.append(op, None).unwrap();
            assert!(e.hlc > prev);
            prev = e.hlc;
        }
    }

    #[test]
    fn recovers_index_after_reopen() {
        let path = tempdir().join("wal.bin");
        {
            let wal = open_wal(path.clone());
            for i in 0..5 {
                wal.append(
                    Op::CounterInc {
                        target: Key::new(KeyKind::Chunk, vec![i], "refcount"),
                        delta: 1,
                    },
                    None,
                )
                .unwrap();
            }
        }
        // reopen with a fresh keypair (the index recovery doesn't depend on
        // the device key — only signing newly-appended entries does).
        let (sk, _pk) = generate_keypair(&mut OsRng);
        let wal = WalBuilder::new()
            .path(path)
            .build(DeviceId::new_v7(), sk)
            .unwrap();
        assert_eq!(wal.next_seq(), 5);
        let entries = wal.scan_since(0).unwrap();
        assert_eq!(entries.len(), 5);
    }

    #[test]
    fn truncates_partial_trailing_frame() {
        let path = tempdir().join("wal.bin");
        {
            let wal = open_wal(path.clone());
            wal.append(
                Op::CounterInc {
                    target: Key::new(KeyKind::Chunk, vec![1], "refcount"),
                    delta: 1,
                },
                None,
            )
            .unwrap();
        }
        // append garbage to simulate a partially-written frame
        {
            let mut f = OpenOptions::new().append(true).open(&path).unwrap();
            f.write_all(&[0, 0, 0, 100, 0xAA, 0xBB]).unwrap();
        }
        let (sk, _pk) = generate_keypair(&mut OsRng);
        let wal = WalBuilder::new()
            .path(&path)
            .build(DeviceId::new_v7(), sk)
            .unwrap();
        assert_eq!(wal.next_seq(), 1);
    }

    #[test]
    fn rejects_oversize_entry() {
        let path = tempdir().join("wal.bin");
        let cfg = WalConfig {
            max_entry_bytes: 64,
        };
        let (sk, _pk) = generate_keypair(&mut OsRng);
        let wal = WalBuilder::new()
            .path(&path)
            .config(cfg)
            .build(DeviceId::new_v7(), sk)
            .unwrap();
        let big = vec![0u8; 1024];
        let op = Op::LwwRegister {
            target: Key::new(KeyKind::File, vec![0u8; 16], "content_type"),
            value: big,
        };
        assert!(matches!(
            wal.append(op, None),
            Err(WalError::EntryTooLarge { .. })
        ));
    }
}
