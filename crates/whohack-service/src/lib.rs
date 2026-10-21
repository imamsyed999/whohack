//! whohack core service library: the pipeline and its stages, shared by the
//! `whohack-service` binary and integration tests.

pub mod admin;
pub mod alerts;
pub mod cli;
pub mod decisions;
mod download_view;
mod folder_scan;
pub mod integrity;
pub mod ipc_handler;
pub mod logging;
pub mod monitor;
pub mod pipeline;
pub mod replay;
pub mod service;
pub mod stages;
pub mod store_writer;
#[cfg(windows)]
pub mod winservice;
