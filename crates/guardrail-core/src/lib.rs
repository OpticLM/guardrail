//! Core interfaces for the `guardrail` sandbox.
//!
//! This crate exposes a platform-agnostic API: it defines the declarative
//! policy types (e.g. [`FsAccess`], [`NetworkPolicy`]), the [`SandboxConfig`]
//! configuration, the [`SandboxCommand`] launch description, and the
//! [`Backend`] trait that platform crates (e.g. `guardrail-linux`) implement.
//! Its process handles contain small target-gated implementations, while the
//! crate itself compiles on every platform.

mod backend;
mod command;
mod config;
mod error;
mod policy;
mod process;

pub use backend::Backend;
pub use command::{SandboxCommand, StdioMode};
pub use config::{ResourceLimits, SandboxConfig};
pub use error::{Error, Result};
pub use policy::{FsAccess, NetworkPolicy, UserNamespacePolicy};
#[cfg(windows)]
pub use process::WindowsChildStdio;
pub use process::{SandboxChild, SharedSandboxChild};
