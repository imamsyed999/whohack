//! whohack typed-decision models (SPEC §12): the [`DecisionModel`] interface,
//! the out-of-process [`DecisionSidecar`], and [`MockDecisionModel`] for tests.

pub mod mock;
pub mod model;
pub mod sidecar;

pub use mock::MockDecisionModel;
pub use model::{Answer, DecisionModel, QKind, Question, answer};
pub use sidecar::{DecisionSidecar, SidecarConfig};
pub mod explain;
pub mod manifest;
pub mod profile_flow;
pub mod questions;
pub mod state;
#[cfg(windows)]
mod windows_job;
