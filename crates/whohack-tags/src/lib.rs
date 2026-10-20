//! Capability tagging and conservative expected-behavior profiles.
pub mod net;
pub mod profile;
pub mod sensitive;
pub mod tagger;
pub mod taxonomy;

pub use profile::{CategoryTemplate, Profile};
pub use tagger::Tagger;
