//! Domain types shared by every Vigil crate (SPEC §7).
//!
//! Deviations from the spec, kept deliberately small:
//! - `CapabilityTag` wraps `Cow<'static, str>` instead of `&'static str` so tags
//!   can be deserialized from the store and IPC (see `tag.rs`).
//! - `FileInfo::sha256` serializes as a lowercase hex string.

mod allow;
pub(crate) mod event;
mod file;
mod observation;
mod os;
mod process;
mod tag;
mod verdict;

pub use allow::AllowEntry;
pub use event::{Event, EventKind, PersistenceKind, Proto, SensitiveClass};
pub use file::{FileInfo, Origin, PathClass, SignState};
pub use observation::Observation;
pub use os::Os;
pub use process::ProcessInfo;
pub use tag::CapabilityTag;
pub use verdict::{Action, ResponseMode, Verdict, VerdictLabel};
