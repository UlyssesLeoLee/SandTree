//! Docker Compose v2 CLI surface (DD-PLG §6).
//!
//! This module builds argv and reports availability. It deliberately does **not**
//! spawn anything: [`ComposeCli`] is constructed with an injected runner, so
//! argv construction and the "CLI absent" degradation are both testable without
//! a Compose binary on the machine (and SandTree never bundles one).
//!
//! # Why the binary is an optional external dependency
//!
//! DD-PLG §6 is explicit that SandTree does not bundle Docker Desktop and that
//! the Compose binary's release licence must be recorded separately. Encoding
//! that as a *capability probe* rather than a build-time dependency is what keeps
//! the licensing question visible at runtime instead of resolved once by
//! whoever happens to run `cargo install`.

use std::fmt;

/// Default Compose binary name searched on `PATH`.
pub const DEFAULT_BINARY: &str = "docker";

/// Why a Compose invocation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComposeError {
    /// The Compose CLI is not present, so the operation cannot be attempted.
    ///
    /// FR-031 is a SHOULD; this is a degradation, not a defect.
    CliAbsent {
        /// Binary that was looked for.
        binary: String,
    },
    /// The Compose CLI ran but exited non-zero.
    Failed {
        /// Process exit code.
        exit_code: i32,
        /// Captured stderr, already bounded by the runner.
        stderr: String,
    },
    /// The requested operation is not one this plugin declares.
    UnsupportedOperation {
        /// The rejected verb.
        verb: String,
    },
}

impl fmt::Display for ComposeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ComposeError::CliAbsent { binary } => {
                write!(f, "the compose CLI ({binary}) is not on PATH")
            }
            ComposeError::Failed { exit_code, stderr } => {
                write!(f, "compose exited {exit_code}: {stderr}")
            }
            ComposeError::UnsupportedOperation { verb } => {
                write!(f, "compose does not declare the operation {verb:?}")
            }
        }
    }
}

impl std::error::Error for ComposeError {}

/// The Compose subcommands this plugin drives.
///
/// DD-PLG §6 names up/down/pull/restart. `start`/`stop` are included because
/// FR-031 lists them, but they are declared separately so capability reporting
/// can distinguish them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ComposeCommand {
    /// `docker compose up`.
    Up,
    /// `docker compose down`.
    Down,
    /// `docker compose pull`.
    Pull,
    /// `docker compose restart`.
    Restart,
    /// `docker compose start`.
    Start,
    /// `docker compose stop`.
    Stop,
}

impl ComposeCommand {
    /// Subcommand argument.
    pub fn as_str(self) -> &'static str {
        match self {
            ComposeCommand::Up => "up",
            ComposeCommand::Down => "down",
            ComposeCommand::Pull => "pull",
            ComposeCommand::Restart => "restart",
            ComposeCommand::Start => "start",
            ComposeCommand::Stop => "stop",
        }
    }

    /// Every command, in a stable order for capability reporting.
    pub fn all() -> &'static [ComposeCommand] {
        &[
            ComposeCommand::Up,
            ComposeCommand::Down,
            ComposeCommand::Pull,
            ComposeCommand::Restart,
            ComposeCommand::Start,
            ComposeCommand::Stop,
        ]
    }

    /// Whether this command destroys resources, and so needs force confirmation.
    ///
    /// `down` removes the project's containers, so it is destructive even though
    /// it is not literally a delete (invariant 12).
    pub fn is_destructive(self) -> bool {
        matches!(self, ComposeCommand::Down)
    }

    /// Map a SandTree [`sandtree_model::operation::OperationKind`] to a command.
    pub fn from_operation_kind(kind: sandtree_model::operation::OperationKind) -> Option<Self> {
        use sandtree_model::operation::OperationKind;
        Some(match kind {
            OperationKind::Create => ComposeCommand::Up,
            OperationKind::Destroy => ComposeCommand::Down,
            OperationKind::Pull => ComposeCommand::Pull,
            OperationKind::Restart => ComposeCommand::Restart,
            OperationKind::Start => ComposeCommand::Start,
            OperationKind::Stop => ComposeCommand::Stop,
            _ => return None,
        })
    }
}

impl fmt::Display for ComposeCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Whether the Compose CLI can be driven.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComposeAvailability {
    /// The CLI answered a version probe.
    Available {
        /// Reported version string.
        version: String,
    },
    /// The CLI is not on `PATH`.
    Absent {
        /// Binary that was looked for.
        binary: String,
    },
}

impl ComposeAvailability {
    /// Whether lifecycle operations can be attempted.
    pub fn is_available(&self) -> bool {
        matches!(self, ComposeAvailability::Available { .. })
    }

    /// Short summary for health metadata.
    pub fn summary(&self) -> String {
        match self {
            ComposeAvailability::Available { version } => format!("compose {version}"),
            ComposeAvailability::Absent { binary } => {
                format!("compose CLI {binary} not found on PATH")
            }
        }
    }
}

/// Anything that can report a Compose CLI version.
///
/// Injecting this is what lets the absence path be tested on a machine where
/// Compose happens to be installed.
pub trait ComposeRunner: Send + Sync {
    /// Probe for the CLI and its version.
    fn availability(&self) -> ComposeAvailability;

    /// Build the argv for one operation.
    ///
    /// Lives on the trait rather than being recovered by downcasting, so every
    /// runner produces a well-formed argv and the shape is testable without a
    /// process.
    fn build_argv(&self, command: ComposeCommand, project: &str, file: Option<&str>)
        -> Vec<String>;

    /// Run one composed argv and return `(exit_code, stderr)`.
    fn run(&self, argv: &[String]) -> Result<(i32, String), ComposeError>;
}

/// A runner that reports the CLI as present with a fixed version, and echoes the
/// argv it was asked to run. Used by tests and as the reference for what a real
/// runner must do.
#[derive(Debug)]
pub struct ComposeCli {
    binary: String,
    availability: ComposeAvailability,
    exit_code: i32,
    stderr: String,
    invocations: std::sync::Mutex<Vec<Vec<String>>>,
}

/// Manual `Clone`: `ComposeCli` holds a `Mutex`, which is not `Clone`.
impl Clone for ComposeCli {
    fn clone(&self) -> Self {
        Self {
            binary: self.binary.clone(),
            availability: self.availability.clone(),
            exit_code: self.exit_code,
            stderr: self.stderr.clone(),
            // A clone starts with an empty invocation log; sharing the log would
            // make two clones indistinguishable in assertions.
            invocations: std::sync::Mutex::new(Vec::new()),
        }
    }
}

impl ComposeCli {
    /// A CLI runner that is present and succeeds.
    pub fn present(version: impl Into<String>) -> Self {
        Self {
            binary: DEFAULT_BINARY.to_string(),
            availability: ComposeAvailability::Available {
                version: version.into(),
            },
            exit_code: 0,
            stderr: String::new(),
            invocations: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// A runner that reports the CLI as absent.
    pub fn absent() -> Self {
        Self {
            binary: DEFAULT_BINARY.to_string(),
            availability: ComposeAvailability::Absent {
                binary: DEFAULT_BINARY.to_string(),
            },
            exit_code: 0,
            stderr: String::new(),
            invocations: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Make `run` fail with this exit code and stderr.
    pub fn failing(mut self, exit_code: i32, stderr: impl Into<String>) -> Self {
        self.exit_code = exit_code;
        self.stderr = stderr.into();
        self
    }

    /// Override the binary name.
    pub fn with_binary(mut self, binary: impl Into<String>) -> Self {
        self.binary = binary.into();
        self
    }

    /// Probe availability without touching the filesystem.
    pub fn availability(&self) -> ComposeAvailability {
        self.availability.clone()
    }

    /// Every argv this runner was asked to execute, in order.
    pub fn invocations(&self) -> Vec<Vec<String>> {
        self.invocations
            .lock()
            .expect("compose invocation log")
            .clone()
    }

    /// Build the argv for one operation.
    ///
    /// Pure: no process is started, so this is fully testable and the argv can be
    /// asserted exactly.
    pub fn argv(&self, command: ComposeCommand, project: &str, file: Option<&str>) -> Vec<String> {
        let mut argv = vec![
            self.binary.clone(),
            "compose".to_string(),
            command.as_str().to_string(),
        ];
        if let Some(f) = file {
            argv.push("--file".to_string());
            argv.push(f.to_string());
        }
        argv.push(project.to_string());
        argv
    }
}

impl ComposeRunner for ComposeCli {
    fn availability(&self) -> ComposeAvailability {
        ComposeCli::availability(self)
    }

    fn build_argv(
        &self,
        command: ComposeCommand,
        project: &str,
        file: Option<&str>,
    ) -> Vec<String> {
        ComposeCli::argv(self, command, project, file)
    }

    fn run(&self, argv: &[String]) -> Result<(i32, String), ComposeError> {
        if !self.availability.is_available() {
            return Err(ComposeError::CliAbsent {
                binary: self.binary.clone(),
            });
        }
        self.invocations
            .lock()
            .expect("compose invocation log")
            .push(argv.to_vec());
        if self.exit_code == 0 {
            Ok((0, String::new()))
        } else {
            Ok((self.exit_code, self.stderr.clone()))
        }
    }
}

/// Convenience: probe a runner's availability.
pub fn availability(runner: &dyn ComposeRunner) -> ComposeAvailability {
    runner.availability()
}

/// Translate a non-zero exit into a [`ComposeError::Failed`].
pub fn check_exit(code: i32, stderr: &str) -> Result<(), ComposeError> {
    if code == 0 {
        Ok(())
    } else {
        Err(ComposeError::Failed {
            exit_code: code,
            stderr: stderr.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sandtree_model::error::ErrorCode;
    use sandtree_model::operation::OperationKind;

    #[test]
    fn argv_has_the_expected_shape() {
        let cli = ComposeCli::present("2.24.0");
        let argv = cli.argv(ComposeCommand::Up, "shop", None);
        assert_eq!(argv, vec!["docker", "compose", "up", "shop"]);
    }

    #[test]
    fn a_compose_file_is_included_before_the_project_name() {
        // `--file` must precede the project argument or Compose parses the
        // project as a file path.
        let cli = ComposeCli::present("2.24.0");
        let argv = cli.argv(ComposeCommand::Up, "shop", Some("compose.yaml"));
        assert_eq!(
            argv,
            vec!["docker", "compose", "up", "--file", "compose.yaml", "shop"]
        );
    }

    #[test]
    fn a_custom_binary_is_used_verbatim() {
        let cli = ComposeCli::present("2.24.0").with_binary("docker-compose");
        assert_eq!(
            cli.argv(ComposeCommand::Down, "shop", None)[0],
            "docker-compose"
        );
    }

    #[test]
    fn only_down_is_destructive() {
        assert!(ComposeCommand::Down.is_destructive());
        for c in ComposeCommand::all() {
            if *c != ComposeCommand::Down {
                assert!(
                    !c.is_destructive(),
                    "{c} should not need force confirmation"
                );
            }
        }
    }

    #[test]
    fn operation_kinds_map_to_the_expected_commands() {
        assert_eq!(
            ComposeCommand::from_operation_kind(OperationKind::Create),
            Some(ComposeCommand::Up)
        );
        assert_eq!(
            ComposeCommand::from_operation_kind(OperationKind::Destroy),
            Some(ComposeCommand::Down)
        );
        assert_eq!(
            ComposeCommand::from_operation_kind(OperationKind::Pull),
            Some(ComposeCommand::Pull)
        );
    }

    #[test]
    fn unmapped_operation_kinds_have_no_command() {
        // Observe/Logs/Exec are handled by other ports, not by the Compose CLI.
        for k in [
            OperationKind::Observe,
            OperationKind::Exec,
            OperationKind::Stats,
        ] {
            assert_eq!(
                ComposeCommand::from_operation_kind(k),
                None,
                "{k:?} should not map to a compose command"
            );
        }
    }

    #[test]
    fn an_absent_cli_is_reported_rather_than_assumed() {
        let cli = ComposeCli::absent();
        let a = availability(&cli);
        assert!(!a.is_available());
        assert!(a.summary().contains("not found"), "{}", a.summary());
    }

    #[test]
    fn a_present_cli_reports_its_version() {
        let a = availability(&ComposeCli::present("2.24.0"));
        assert!(a.is_available());
        assert_eq!(a.summary(), "compose 2.24.0");
    }

    #[test]
    fn running_with_an_absent_cli_is_an_error_not_an_empty_success() {
        let cli = ComposeCli::absent();
        let argv = cli.argv(ComposeCommand::Up, "shop", None);
        let err = cli.run(&argv).unwrap_err();
        assert!(matches!(err, ComposeError::CliAbsent { .. }));
        assert!(err.to_string().contains("not on PATH"));
    }

    #[test]
    fn running_with_a_present_cli_records_the_argv() {
        let cli = ComposeCli::present("2.24.0");
        let argv = cli.argv(ComposeCommand::Pull, "shop", None);
        assert_eq!(cli.run(&argv).unwrap().0, 0);
        assert_eq!(cli.invocations(), vec![argv]);
    }

    #[test]
    fn a_non_zero_exit_becomes_a_failed_error_carrying_stderr() {
        let cli = ComposeCli::present("2.24.0").failing(1, "no such service");
        let err = cli
            .run(&cli.argv(ComposeCommand::Up, "shop", None))
            .unwrap();
        assert_eq!(err.0, 1);
        let mapped = check_exit(err.0, &err.1).unwrap_err();
        assert!(matches!(mapped, ComposeError::Failed { exit_code: 1, .. }));
        assert!(mapped.to_string().contains("no such service"));
    }

    #[test]
    fn check_exit_accepts_zero() {
        assert!(check_exit(0, "").is_ok());
    }

    #[test]
    fn the_command_table_is_the_full_set_and_unique() {
        let names: Vec<&str> = ComposeCommand::all().iter().map(|c| c.as_str()).collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), names.len(), "duplicate command: {names:?}");
        assert_eq!(names.len(), 6);
    }

    #[test]
    fn every_command_renders_as_its_subcommand() {
        for c in ComposeCommand::all() {
            assert_eq!(c.to_string(), c.as_str());
        }
    }

    #[test]
    fn compose_error_codes_stay_on_the_stable_sandbox_registry() {
        // Nothing new is invented here: the CLI-absent case maps to the existing
        // ST-SBX-001 via the provider layer.
        assert_eq!(
            ErrorCode::SANDBOX_PROVIDER_UNAVAILABLE.as_str(),
            "ST-SBX-001"
        );
    }
}
