//! Core interfaces for the `guardrail` sandbox.
//!
//! This crate is platform-agnostic: it defines the declarative [`policy`]
//! types, the [`SandboxBuilder`], the built [`SandboxConfig`], and the
//! [`Backend`] trait that platform crates (e.g. `guardrail-linux`) implement.
//! It contains no OS-specific code and compiles on every platform.

mod backend;
mod builder;
mod config;
mod diagnostics;
mod error;
mod policy;
mod process;

pub use backend::Backend;
pub use builder::SandboxBuilder;
pub use config::{ResourceLimits, SandboxConfig};
pub use diagnostics::{Violation, ViolationKind};
pub use error::Error;
pub use policy::{FsAccess, IpcPolicy, NetworkPolicy};
pub use process::{SandboxChild, SharedSandboxChild};
