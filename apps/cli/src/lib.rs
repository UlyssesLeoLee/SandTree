//! SandTree command line interface (DD-SW §6, NFR-U02).
//!
//! The CLI is a **client**: it never opens the store, never talks to a provider
//! and never decides policy. Everything goes through the daemon over IPC. That
//! boundary is the whole point — a CLI that could shortcut the daemon would be
//! a second, unaudited path to `destroy`.
//!
//! When no daemon is reachable the CLI still works for the read-only commands
//! by running an in-process kernel, and says so. What it will not do is
//! pretend a mutation succeeded without a daemon to record it.

#![deny(missing_docs)]

use std::path::PathBuf;

use sandtree_ipc::method;
use sandtree_ipc::router::MethodRouter;
use sandtree_ipc::{Request, Response};
use serde_json::Value as Json;

/// CLI configuration.
#[derive(Debug, Clone)]
pub struct CliConfig {
    /// Data directory, used by the in-process fallback.
    pub data_dir: PathBuf,
    /// Pipe to connect to; `None` means the per-user default.
    pub pipe: Option<String>,
    /// Run against an in-process kernel instead of the daemon.
    pub local: bool,
}

impl CliConfig {
    /// Default configuration.
    pub fn new() -> Self {
        Self {
            data_dir: sandtree_daemon::default_data_dir(),
            pipe: None,
            local: false,
        }
    }
}

impl Default for CliConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// A parsed command line.
#[derive(Debug, Clone, PartialEq)]
pub enum Command {
    /// Print the resource tree.
    Tree {
        /// Restrict to one provider.
        provider: Option<String>,
        /// Restrict to one kind.
        kind: Option<String>,
    },
    /// Print one resource.
    Show {
        /// Resource id.
        resource_id: String,
    },
    /// Invoke an operation.
    Invoke {
        /// Target resource.
        resource_id: String,
        /// Operation name.
        op: String,
        /// Explicit confirmation for a destructive operation.
        force: bool,
    },
    /// Produce the redacted diagnostics bundle.
    Diagnostics,
    /// List the methods this build knows.
    Methods,
    /// Print help.
    Help,
}

impl Command {
    /// The IPC method this command maps to, if any.
    pub fn method(&self) -> Option<&'static str> {
        match self {
            Command::Tree { .. } => Some(method::RESOURCE_TREE),
            Command::Show { .. } => Some(method::RESOURCE_GET),
            Command::Invoke { .. } => Some(method::OPERATION_INVOKE),
            Command::Diagnostics => Some(method::DIAGNOSTIC_BUNDLE),
            Command::Methods => Some(method::DIAGNOSTIC_VERSION),
            Command::Help => None,
        }
    }

    /// Parameters for the mapped method.
    pub fn params(&self) -> Json {
        match self {
            Command::Tree {
                provider: p,
                kind: k,
            } => {
                let mut m = serde_json::Map::new();
                if let Some(v) = p {
                    m.insert("provider_id".into(), Json::String(v.clone()));
                }
                if let Some(v) = k {
                    m.insert("kind".into(), Json::String(v.clone()));
                }
                Json::Object(m)
            }
            Command::Show { resource_id } => serde_json::json!({"resource_id": resource_id}),
            Command::Invoke {
                resource_id,
                op,
                force,
            } => serde_json::json!({
                "resource_id": resource_id,
                "op": op,
                "args": if *force { serde_json::json!({"force": true}) } else { Json::Object(Default::default()) },
            }),
            _ => Json::Null,
        }
    }
}

/// Parse `argv` (without the program name).
pub fn parse(args: &[String]) -> Result<Command, String> {
    let Some(first) = args.first() else {
        return Ok(Command::Help);
    };
    match first.as_str() {
        "tree" | "ls" => {
            let mut provider = None;
            let mut kind = None;
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--provider" => {
                        provider = Some(
                            args.get(i + 1)
                                .cloned()
                                .ok_or_else(|| "--provider needs a value".to_string())?,
                        );
                        i += 2;
                    }
                    "--kind" => {
                        kind = Some(
                            args.get(i + 1)
                                .cloned()
                                .ok_or_else(|| "--kind needs a value".to_string())?,
                        );
                        i += 2;
                    }
                    other => return Err(format!("unknown option {other:?}")),
                }
            }
            Ok(Command::Tree { provider, kind })
        }
        "show" | "get" => {
            let id = args
                .get(1)
                .cloned()
                .ok_or_else(|| "show needs a resource id".to_string())?;
            Ok(Command::Show { resource_id: id })
        }
        "invoke" | "run" => {
            let resource_id = args
                .get(1)
                .cloned()
                .ok_or_else(|| "invoke needs a resource id".to_string())?;
            let op = args
                .get(2)
                .cloned()
                .ok_or_else(|| "invoke needs an operation name".to_string())?;
            // `--force` is a separate, visible flag on purpose: NFR-U02 requires
            // a destructive action to be confirmed explicitly, so it must not be
            // implied by position or by a default.
            let force = args.iter().skip(3).any(|a| a == "--force");
            Ok(Command::Invoke {
                resource_id,
                op,
                force,
            })
        }
        "diagnostics" | "diag" => Ok(Command::Diagnostics),
        "methods" => Ok(Command::Methods),
        "-h" | "--help" | "help" => Ok(Command::Help),
        other => Err(format!("unknown command {other:?}")),
    }
}

/// Version string the CLI reports.
///
/// NFR-U01 (the operator has to be able to tell what they are running): a
/// packaged binary whose version cannot be read is a support ticket waiting to
/// happen. `scripts/package.ps1` stamps the same number into the MSI and into
/// `VERSION.txt`, so this is also how an operator confirms the installer put
/// the build they expected on their machine.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Help text.
pub fn help() -> String {
    // `env!` expands to a literal, so `concat!` folds the version in at compile
    // time and the whole help text stays a `&str` array.
    const VERSION_LINE: &str = concat!("version ", env!("CARGO_PKG_VERSION"));
    [
        "sandtree — Sandbox & Docker control plane",
        VERSION_LINE,
        "",
        "USAGE:",
        "    sandtree tree [--provider ID] [--kind KIND]",
        "    sandtree show <resource-id>",
        "    sandtree invoke <resource-id> <op> [--force]",
        "    sandtree diagnostics",
        "    sandtree methods",
        "",
        "GLOBAL:",
        "    --local               answer from an in-process kernel, no daemon",
        "    --data-dir DIR        kernel data directory",
        "    --pipe NAME           daemon IPC pipe",
        "    --version, -V         print the version and exit",
        "",
        "NOTES:",
        "    Destructive operations require --force. The daemon refuses them",
        "    otherwise, and records an audit record either way.",
    ]
    .join("\n")
}

/// Turn a response into the text the user sees.
pub fn render(resp: &Response) -> String {
    match resp {
        Response::Ok { result, .. } => serde_json::to_string_pretty(result)
            .unwrap_or_else(|e| format!("<unrenderable result: {e}>")),
        Response::Err { error, .. } => format!("error {}: {}", error.code.as_str(), error.message),
    }
}

/// Whether a response should make the process exit non-zero.
pub fn is_failure(resp: &Response) -> bool {
    !resp.is_ok()
}

/// Build the request a command produces.
pub fn to_request(cmd: &Command) -> Option<Request> {
    cmd.method().map(|m| Request::new(m, cmd.params()))
}

/// A local in-process router, used when no daemon is reachable.
///
/// Read-only commands work against it; a mutation fails with a precise error
/// rather than running without a daemon to audit it.
///
/// The plugin lifecycle state here uses the same refusing loader the daemon
/// ships (ADR-016): the CLI has no worker transport either, and inventing a
/// second answer for the same endpoint would make "why did install fail"
/// depend on which process answered.
pub fn local_router(kernel: std::sync::Arc<sandtree_kernel::Kernel>) -> MethodRouter {
    sandtree_daemon::methods::build_router(
        kernel,
        sandtree_daemon::plugins::PluginControl::unavailable(
            std::sync::Arc::new(sandtree_plugin_host::route::RouteTable::new()),
            "the local CLI router has no plugin worker transport",
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(s: &str) -> Vec<String> {
        s.split_whitespace().map(str::to_string).collect()
    }

    #[test]
    fn no_arguments_prints_help() {
        assert_eq!(parse(&[]).unwrap(), Command::Help);
        assert_eq!(parse(&argv("--help")).unwrap(), Command::Help);
    }

    #[test]
    fn tree_parses_filters() {
        assert_eq!(
            parse(&argv("tree --provider p --kind container")).unwrap(),
            Command::Tree {
                provider: Some("p".into()),
                kind: Some("container".into()),
            }
        );
    }

    #[test]
    fn a_filter_option_without_a_value_is_an_error() {
        assert!(parse(&argv("tree --provider")).is_err());
        assert!(parse(&argv("tree --kind")).is_err());
    }

    #[test]
    fn show_requires_an_id() {
        assert!(parse(&argv("show")).is_err());
        assert_eq!(
            parse(&argv("show res-1")).unwrap(),
            Command::Show {
                resource_id: "res-1".into()
            }
        );
    }

    #[test]
    fn invoke_is_not_forced_unless_the_flag_is_present() {
        let plain = parse(&argv("invoke res-1 destroy")).unwrap();
        assert_eq!(
            plain,
            Command::Invoke {
                resource_id: "res-1".into(),
                op: "destroy".into(),
                force: false
            }
        );
        let forced = parse(&argv("invoke res-1 destroy --force")).unwrap();
        assert!(matches!(forced, Command::Invoke { force: true, .. }));
    }

    #[test]
    fn force_never_reaches_the_wire_implicitly() {
        // The flag must be the only thing that adds `force`, because the daemon
        // reads exactly this field to decide whether to run a destructive op.
        let not_forced = parse(&argv("invoke r destroy")).unwrap();
        assert!(not_forced.params()["args"].get("force").is_none());
        let forced = parse(&argv("invoke r destroy --force")).unwrap();
        assert_eq!(forced.params()["args"]["force"], Json::Bool(true));
    }

    #[test]
    fn an_unknown_command_or_option_is_rejected() {
        assert!(parse(&argv("frobnicate")).is_err());
        assert!(parse(&argv("tree --wat x")).is_err());
    }

    #[test]
    fn every_command_maps_to_a_declared_method() {
        for cmd in [
            Command::Tree {
                provider: None,
                kind: None,
            },
            Command::Show {
                resource_id: "r".into(),
            },
            Command::Invoke {
                resource_id: "r".into(),
                op: "stop".into(),
                force: false,
            },
            Command::Diagnostics,
            Command::Methods,
        ] {
            let m = cmd.method().expect("a method");
            assert!(
                sandtree_ipc::method::ALL.contains(&m),
                "{m} is not in the method registry"
            );
            assert!(to_request(&cmd).is_some());
        }
    }

    #[test]
    fn help_has_no_method() {
        assert!(Command::Help.method().is_none());
        assert!(to_request(&Command::Help).is_none());
    }

    #[test]
    fn a_failed_response_renders_the_stable_code() {
        let resp = Response::err(
            "id",
            sandtree_model::error::DomainError::new(
                sandtree_model::error::ErrorCode::POLICY_DENIED,
                "needs force",
            ),
        );
        let text = render(&resp);
        assert!(text.contains("ST-POL-001"), "{text}");
        assert!(text.contains("needs force"), "{text}");
        assert!(is_failure(&resp));
    }

    #[test]
    fn a_successful_response_renders_pretty_json() {
        let resp = Response::ok("id", serde_json::json!({"ok": 1}));
        assert_eq!(render(&resp), "{\n  \"ok\": 1\n}");
        assert!(!is_failure(&resp));
    }

    #[test]
    fn help_mentions_the_confirmation_requirement() {
        let h = help();
        assert!(h.contains("--force"), "{h}");
        assert!(h.contains("audit"), "{h}");
    }

    #[test]
    fn the_help_text_says_how_to_ask_for_the_version() {
        // A help text that omits the version flag is how `--version` ends up
        // undiscoverable: it works, and nothing says so.
        let h = help();
        assert!(
            h.contains("--version"),
            "help does not mention --version:\n{h}"
        );
        assert!(
            h.contains(version()),
            "help does not print the version it reports"
        );
    }

    #[test]
    fn the_version_is_the_workspace_version() {
        // The packaging script stamps env!("CARGO_PKG_VERSION") into the MSI
        // product version and into VERSION.txt. If this ever diverged from the
        // Cargo manifest, a package could claim a version its binary does not
        // report, and the mismatch would only surface in a bug report.
        assert_eq!(version(), env!("CARGO_PKG_VERSION"));
        assert!(
            !version().is_empty(),
            "an empty version is worse than none: it reads as 'unknown' silently"
        );
    }
}
