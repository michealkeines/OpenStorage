//! os-entities — record types and CRDT field wrappers.
//!
//! L1 foundation: depends only on `os-types`. Pure data; no behavior beyond
//! constructors, accessors, and CRDT merge semantics on the field wrappers.
//!
//! See `../../ABSTRACTIONS.md` §4 (entities) and §7 (CRDT op vocabulary).

#![forbid(unsafe_code)]

pub mod crdt;
pub mod records;
pub mod wal_entry;

pub use crdt::*;
pub use records::*;
pub use wal_entry::*;
