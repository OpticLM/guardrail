//! The crate's error type.

/// Errors returned when configuring or spawning a sandbox.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The child process could not be spawned (e.g. binary not found).
    #[error("failed to spawn sandboxed process: {0}")]
    Spawn(#[from] std::io::Error),

    /// A platform confinement stage failed. `stage` is a short machine label
    /// such as `"landlock"`, `"seccomp"`, or `"rlimit"`.
    #[error("failed to apply {stage} confinement: {source}")]
    Confinement {
        stage: &'static str,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },

    /// A requested feature is not available on this platform or kernel.
    #[error("sandbox feature unsupported here: {0}")]
    Unsupported(String),
}

impl Error {
    /// Convenience constructor for [`Error::Confinement`].
    pub fn confinement<E>(stage: &'static str, source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Error::Confinement {
            stage,
            source: Box::new(source),
        }
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
