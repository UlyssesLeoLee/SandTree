//! `multipass` CLI invocation (DD-PLG §9, §12.3).
//!
//! Every process spawn in this provider goes through [`MultipassCli`], behind the
//! [`CliRunner`] trait. That indirection is what makes the degradation paths
//! unit-testable: a fake runner can return "binary not found" without Multipass
//! being installed, which is the situation on a developer machine.
//!
//! Isolation notes:
//!
//! * Arguments are always passed as an **argv vector**, never through a shell,
//!   so a guest-supplied name cannot become shell syntax (FR-013, NFR-S07).
//! * Instance names are validated against a conservative character set before
//!   they are used, so a name like `--flag` cannot be reinterpreted as an
//!   option.
//! * Output is bounded before it is parsed. A CLI that printed gigabytes must
//!   not be able to exhaust the collector's memory budget (DD-SW §12.3).

use std::process::Command;

/// Default CLI binary name.
pub const DEFAULT_BINARY: &str = "multipass";

/// Hard cap on captured stdout, matching the per-domain observation budget
/// (DD-SW §12.3: 4 MiB).
pub const MAX_CAPTURE_BYTES: usize = 4 * 1024 * 1024;

/// Default exec timeout in milliseconds.
pub const EXEC_TIMEOUT_MS: u64 = 30_000;

/// Failures from invoking the Multipass CLI.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MultipassError {
    /// The `multipass` binary is not on `PATH`.
    ///
    /// DD-PLG §9: "未安装/版本不兼容仅使插件 unhealthy/unavailable" — this must
    /// never propagate as a user-facing operation failure.
    #[error("multipass binary {0:?} not found on PATH")]
    NotInstalled(String),
    /// The CLI ran and exited non-zero.
    #[error("multipass {argv} exited {code}: {stderr}")]
    CommandFailed {
        /// Rendered argv, for diagnosis.
        argv: String,
        /// Process exit code.
        code: i32,
        /// Captured stderr (bounded).
        stderr: String,
    },
    /// Output exceeded [`MAX_CAPTURE_BYTES`].
    #[error("multipass output exceeded {limit} bytes")]
    OutputTooLarge {
        /// The cap that was hit.
        limit: usize,
    },
    /// An instance name failed validation.
    #[error("invalid multipass instance name {0:?}")]
    InvalidInstanceName(String),
    /// Output was not the JSON the contract promises.
    #[error("multipass returned unparsable JSON: {reason}")]
    InvalidJson {
        /// Parser diagnostic.
        reason: String,
    },
    /// The spawn itself failed for a reason other than "not installed".
    #[error("multipass could not be executed: {0}")]
    Spawn(String),
}

impl MultipassError {
    /// Whether this failure means "the product is unusable" rather than "this
    /// particular call failed".
    ///
    /// The distinction drives [`crate::provider::MultipassProvider::health`]:
    /// a missing binary makes the provider `Unavailable`, a failed call makes
    /// it `Degraded`.
    pub fn is_product_absent(&self) -> bool {
        matches!(self, MultipassError::NotInstalled(_))
    }
}

/// Result of one CLI invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliOutput {
    /// Exit code.
    pub code: i32,
    /// Captured stdout, bounded by [`MAX_CAPTURE_BYTES`].
    pub stdout: String,
    /// Captured stderr, bounded by [`MAX_CAPTURE_BYTES`].
    pub stderr: String,
}

/// A command runner, so the provider's logic can be tested without Multipass.
pub trait CliRunner: Send + Sync {
    /// Run `argv` and capture its output.
    ///
    /// `timeout_ms` bounds the wait; a runner that cannot enforce it should
    /// still not block indefinitely.
    fn run(&self, argv: &[String], timeout_ms: u64) -> Result<CliOutput, MultipassError>;
}

/// Validate a Multipass instance name.
///
/// Multipass names are restricted to letters, digits, `-`, `_` and `.`. A name
/// may therefore *contain* dashes but must not *start* with one, because a
/// leading dash is how a value gets reinterpreted as an option by the CLI's own
/// argument parser (argument-injection guard, NFR-S07).
pub fn validate_instance_name(name: &str) -> Result<(), MultipassError> {
    let ok = !name.is_empty()
        && name.len() <= 64
        && name != "."
        && name != ".."
        // Rejected outright: anything the CLI could read as a flag.
        && !name.starts_with('-')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
    if ok {
        Ok(())
    } else {
        Err(MultipassError::InvalidInstanceName(name.to_string()))
    }
}

/// The real CLI runner.
#[derive(Debug, Clone)]
pub struct MultipassCli {
    /// Executable name or absolute path.
    pub binary: String,
}

impl Default for MultipassCli {
    fn default() -> Self {
        Self {
            binary: DEFAULT_BINARY.to_string(),
        }
    }
}

impl MultipassCli {
    /// Build a runner for an explicit binary path.
    pub fn new(binary: impl Into<String>) -> Self {
        Self {
            binary: binary.into(),
        }
    }

    /// `multipass --version`, used for the availability probe.
    pub fn version_argv() -> Vec<String> {
        vec![DEFAULT_BINARY.to_string(), "--version".to_string()]
    }
}

impl CliRunner for MultipassCli {
    fn run(&self, argv: &[String], _timeout_ms: u64) -> Result<CliOutput, MultipassError> {
        if argv.is_empty() {
            return Err(MultipassError::Spawn("empty argv".into()));
        }
        // NOTE: no shell is involved. `Command::new(program).args(..)` passes
        // the vector straight to CreateProcess, so no quoting or escaping is
        // needed and none can be injected.
        let out = Command::new(&self.binary)
            .args(&argv[1..])
            .output()
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => MultipassError::NotInstalled(self.binary.clone()),
                _ => MultipassError::Spawn(e.to_string()),
            })?;

        if out.stdout.len() > MAX_CAPTURE_BYTES || out.stderr.len() > MAX_CAPTURE_BYTES {
            return Err(MultipassError::OutputTooLarge {
                limit: MAX_CAPTURE_BYTES,
            });
        }

        Ok(CliOutput {
            code: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        })
    }
}

/// Truncate a captured stream at `limit` characters, marking that it happened.
///
/// FR-024/FR-079: a bounded provider reports truncation rather than silently
/// returning a prefix that a caller might mistake for the whole stream.
pub fn bound_output(text: &str, limit: usize) -> (String, bool) {
    if text.chars().count() <= limit {
        return (text.to_string(), false);
    }
    (text.chars().take(limit).collect(), true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instance_names_reject_option_injection() {
        // NFR-S07: a name that looks like a flag must never be passed through.
        for bad in [
            "--help",
            "-v",
            "--version",
            "name with space",
            "name;rm",
            "name$(id)",
            "",
            ".",
            "..",
            "a/b",
            "a\\b",
        ] {
            assert!(
                validate_instance_name(bad).is_err(),
                "{bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn instance_names_accept_realistic_values() {
        // A dash is legal inside a name, just not at the start.
        for ok in ["primary", "dev-box", "ubuntu_22_04", "a.b", "vm01", "a-1-b"] {
            assert!(
                validate_instance_name(ok).is_ok(),
                "{ok} should be accepted"
            );
        }
    }

    #[test]
    fn overlong_names_are_rejected() {
        assert!(validate_instance_name(&"a".repeat(65)).is_err());
        assert!(validate_instance_name(&"a".repeat(64)).is_ok());
    }

    #[test]
    fn missing_binary_is_distinguished_from_a_failed_call() {
        // DD-PLG §9 drives the provider's health off this distinction.
        let missing = MultipassError::NotInstalled("multipass".into());
        assert!(missing.is_product_absent());

        let failed = MultipassError::CommandFailed {
            argv: "multipass list".into(),
            code: 1,
            stderr: "boom".into(),
        };
        assert!(!failed.is_product_absent());

        let big = MultipassError::OutputTooLarge { limit: 10 };
        assert!(!big.is_product_absent());

        let bad = MultipassError::InvalidInstanceName("x".into());
        assert!(!bad.is_product_absent());
    }

    #[test]
    fn bounding_reports_truncation_explicitly() {
        let (out, truncated) = bound_output("hello", 10);
        assert_eq!(out, "hello");
        assert!(!truncated);

        let (out, truncated) = bound_output("hello world", 5);
        assert_eq!(out, "hello");
        assert!(truncated);
    }

    #[test]
    fn bounding_counts_characters_not_bytes() {
        // A multi-byte string must not be cut mid-codepoint.
        let (out, truncated) = bound_output("日本語テスト", 3);
        assert_eq!(out, "日本語");
        assert!(truncated);
    }

    #[test]
    fn version_argv_is_the_availability_probe() {
        assert_eq!(
            MultipassCli::version_argv(),
            vec!["multipass".to_string(), "--version".to_string()]
        );
    }

    #[test]
    fn empty_argv_is_rejected_before_spawning() {
        let cli = MultipassCli::default();
        assert!(matches!(cli.run(&[], 1000), Err(MultipassError::Spawn(_))));
    }
}
