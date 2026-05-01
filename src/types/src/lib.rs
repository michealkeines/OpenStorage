//! os-types — identifiers, value types, and the error taxonomy.
//!
//! L1 foundation: no internal dependencies. Pure shapes plus equality,
//! ordering, and serialization. See `FLOW.md` and `../../ABSTRACTIONS.md` §2–3.

#![forbid(unsafe_code)]

pub(crate) mod serde_helpers;

pub mod crypto;
pub mod error;
pub mod health;
pub mod ids;
pub mod plugin;
pub mod time;
pub mod trust;

pub use crypto::*;
pub use error::*;
pub use health::*;
pub use ids::*;
pub use plugin::*;
pub use time::*;
pub use trust::*;
