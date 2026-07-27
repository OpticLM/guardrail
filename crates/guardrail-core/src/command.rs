//! The portable description of a child process to spawn.

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Stdio;

/// How one of the child's standard streams is connected.
///
/// The default is [`Inherit`](StdioMode::Inherit).
#[derive(Debug, Default)]
pub enum StdioMode {
    /// Share the parent's stream. On Windows, a slot the parent itself has no
    /// stream for (e.g. in a detached GUI process) falls back to the null
    /// device so the child never sees an invalid handle.
    #[default]
    Inherit,
    /// Connect the stream to the platform null device.
    Null,
    /// Connect the stream to the parent through a pipe. The parent end is
    /// available on the spawned child via [`take_stdin`], [`take_stdout`],
    /// and [`take_stderr`], or collected by [`wait_with_output`].
    ///
    /// [`take_stdin`]: crate::SandboxChild::take_stdin
    /// [`take_stdout`]: crate::SandboxChild::take_stdout
    /// [`take_stderr`]: crate::SandboxChild::take_stderr
    /// [`wait_with_output`]: crate::SandboxChild::wait_with_output
    Piped,
    /// Connect the stream to this open file (read for stdin, write for
    /// stdout/stderr — the file must have been opened accordingly).
    File(std::fs::File),
}

impl From<StdioMode> for Stdio {
    fn from(mode: StdioMode) -> Self {
        match mode {
            StdioMode::Inherit => Stdio::inherit(),
            StdioMode::Null => Stdio::null(),
            StdioMode::Piped => Stdio::piped(),
            StdioMode::File(file) => Stdio::from(file),
        }
    }
}

/// The command a [`Backend`](crate::Backend) spawns inside the sandbox.
///
/// This is guardrail's own command description rather than
/// [`std::process::Command`] because backends must be able to *read* the
/// launch configuration: Windows rebuilds process creation from scratch, and
/// stable `Command` exposes no getters for its stdio settings. It also
/// deliberately carries no environment — the child's environment is exactly
/// [`SandboxConfig::env`](crate::SandboxConfig::env), applied by the backend.
///
/// All fields are public; fill them in directly:
///
/// ```
/// use guardrail_core::{SandboxCommand, StdioMode};
///
/// let mut command = SandboxCommand::new("/usr/bin/tool");
/// command.args = vec!["--flag".into()];
/// command.stdout = StdioMode::Piped;
/// ```
#[derive(Debug, Default)]
pub struct SandboxCommand {
    /// Program to run: an absolute path, or a name resolved by the platform's
    /// usual search behavior.
    pub program: OsString,
    /// Arguments passed to the program, not including the program itself.
    pub args: Vec<OsString>,
    /// Working directory for the child; the parent's when `None`.
    pub current_dir: Option<PathBuf>,
    /// How the child's stdin is connected.
    pub stdin: StdioMode,
    /// How the child's stdout is connected.
    pub stdout: StdioMode,
    /// How the child's stderr is connected.
    pub stderr: StdioMode,
}

impl SandboxCommand {
    /// Describe `program` with no arguments, the parent's working directory,
    /// and all three standard streams inherited.
    pub fn new(program: impl Into<OsString>) -> Self {
        Self {
            program: program.into(),
            ..Self::default()
        }
    }

    /// Convert into a [`std::process::Command`] for backends that spawn
    /// through std: program, arguments, working directory, and stdio modes
    /// are applied, and the inherited environment is cleared so the backend
    /// installs exactly the configuration environment on top.
    pub fn into_std_command(self) -> std::process::Command {
        let mut command = std::process::Command::new(&self.program);
        command.args(&self.args);
        if let Some(dir) = &self.current_dir {
            command.current_dir(dir);
        }
        command.env_clear();
        command.stdin(Stdio::from(self.stdin));
        command.stdout(Stdio::from(self.stdout));
        command.stderr(Stdio::from(self.stderr));
        command
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn new_defaults_to_inherited_stdio_and_no_args() {
        let command = SandboxCommand::new("probe");
        assert_eq!(command.program, OsString::from("probe"));
        assert!(command.args.is_empty());
        assert!(command.current_dir.is_none());
        assert!(matches!(command.stdin, StdioMode::Inherit));
        assert!(matches!(command.stdout, StdioMode::Inherit));
        assert!(matches!(command.stderr, StdioMode::Inherit));
    }

    #[test]
    fn into_std_command_maps_program_args_cwd_and_scrubs_env() {
        let mut command = SandboxCommand::new("probe");
        command.args = vec!["one".into(), "two words".into()];
        command.current_dir = Some(PathBuf::from("dir"));

        let std_command = command.into_std_command();

        assert_eq!(std_command.get_program(), "probe");
        assert_eq!(
            std_command.get_args().collect::<Vec<_>>(),
            ["one", "two words"]
        );
        assert_eq!(std_command.get_current_dir(), Some(Path::new("dir")));
        assert_eq!(
            std_command.get_envs().count(),
            0,
            "the inherited environment must be cleared structurally"
        );
    }
}
