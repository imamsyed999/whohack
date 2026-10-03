//! Vigil core: shared domain types, configuration, the in-process event bus,
//! and the SQLite event store.
//!
//! Every other Vigil crate depends on this one; it has no OS-specific code.

pub mod bus;
pub mod config;
pub mod hex;
#[cfg(feature = "store")]
pub mod store;
pub mod time;
pub mod types;

pub use bus::EventBus;
pub use config::{Config, ConfigError};
#[cfg(feature = "store")]
pub use store::{Store, StoreError};
pub use types::*;
