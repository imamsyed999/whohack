//! Vigil core service library: the pipeline and its stages, shared by the
//! `vigil-service` binary and integration tests.

pub mod admin;
pub mod cli;
pub mod integrity;
pub mod ipc_handler;
pub mod logging;
pub mod monitor;
pub mod pipeline;
pub mod service;
pub mod stages;
pub mod store_writer;
#[cfg(windows)]
pub mod winservice;
