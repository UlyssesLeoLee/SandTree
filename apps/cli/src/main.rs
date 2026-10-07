//! CLI entry point.

use std::process::ExitCode;

use sandtree_cli::{help, is_failure, local_router, parse, render, to_request, CliConfig, Command};

fn main() -> ExitCode {
    let mut cfg = CliConfig::new();
    let mut args: Vec<String> = std::env::args().skip(1).collect();

    // Global flags come before the subcommand.
    let mut local = false;
    while let Some(first) = args.first() {
        match first.as_str() {
            // NFR-U01: an operator has to be able to tell what they are running.
            // Before this existed, `sandtree --version` answered "unknown
            // command", which is a confusing way to learn a binary exists.
            "--version" | "-V" => {
                println!("sandtree {}", sandtree_cli::version());
                return ExitCode::SUCCESS;
            }
            "--local" => {
                local = true;
                args.remove(0);
            }
            "--data-dir" => match args.get(1) {
                Some(v) => {
                    cfg.data_dir = v.into();
                    args.drain(0..2);
                }
                None => return bad("--data-dir needs a value"),
            },
            "--pipe" => match args.get(1) {
                Some(v) => {
                    cfg.pipe = Some(v.clone());
                    args.drain(0..2);
                }
                None => return bad("--pipe needs a value"),
            },
            _ => break,
        }
    }
    cfg.local = local;

    let cmd = match parse(&args) {
        Ok(c) => c,
        Err(e) => return bad(&e),
    };
    if cmd == Command::Help {
        println!("{}", help());
        return ExitCode::SUCCESS;
    }

    let Some(req) = to_request(&cmd) else {
        println!("{}", help());
        return ExitCode::SUCCESS;
    };

    let runtime = match tokio::runtime::Runtime::new() {
        Ok(r) => r,
        Err(e) => return bad(&format!("cannot start a runtime: {e}")),
    };

    let resp = runtime.block_on(async move { run(&cfg, &req).await });

    match resp {
        Ok(r) => {
            println!("{}", render(&r));
            if is_failure(&r) {
                ExitCode::FAILURE
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(f) => {
            eprintln!("sandtree: {}", f.message());
            f.exit_code()
        }
    }
}

/// Answer one request: over the pipe if a daemon is there, otherwise locally
/// for a read-only call, and never locally for a mutation.
///
/// [`Refusal`] is a separate type from a plain message because the two exit
/// differently: a usage mistake is exit 2, a refusal is exit 1, and a script
/// must be able to tell "I typed it wrong" from "it declined".
async fn run(
    cfg: &CliConfig,
    req: &sandtree_ipc::Request,
) -> Result<sandtree_ipc::Response, Failure> {
    use sandtree_ipc::method;

    if !cfg.local {
        match call_daemon(cfg, req).await {
            Ok(Some(resp)) => return Ok(resp),
            Ok(None) => {
                return Err(Failure::Usage(format!(
                    "{}: the daemon closed the connection without answering",
                    req.method
                )))
            }
            Err(reason) => {
                if !method::is_read_only(&req.method) {
                    // Refuse here rather than falling back: a mutation run by the
                    // CLI would be applied with no daemon recording it, and the
                    // operator would never find out (NFR-S03).
                    //
                    // Exit 1, not 2: this is the command failing, not the command
                    // line being wrong. A script that treats 2 as "I typed it
                    // wrong" and everything else as "it did not work" must not
                    // have to special-case a policy refusal.
                    return Err(Failure::Refused(format!(
                        "{} needs the daemon, which is not reachable ({reason}). {}",
                        req.method,
                        sandtree_cli::mutation_needs_a_daemon(&req.method).message
                    )));
                }
                eprintln!(
                    "sandtree: no daemon at {} ({reason}); answering locally",
                    endpoint(cfg)
                );
            }
        }
    } else {
        eprintln!("sandtree: --local; answering from an in-process kernel, not the daemon");
    }

    let kernel = sandtree_kernel::Kernel::bootstrap(sandtree_kernel::KernelConfig::new(
        cfg.data_dir.clone(),
    ))
    .await
    .map_err(|e| Failure::Usage(format!("{}: {}", e.code.as_str(), e.message)))?;
    Ok(local_router(std::sync::Arc::new(kernel))
        .dispatch(req)
        .await)
}

/// Why the CLI produced no answer, and how it should exit.
enum Failure {
    /// The command line or the environment made this call impossible (exit 2).
    Usage(String),
    /// The command was understood and declined (exit 1).
    Refused(String),
}

impl Failure {
    fn exit_code(&self) -> ExitCode {
        match self {
            Failure::Usage(_) => ExitCode::from(2),
            Failure::Refused(_) => ExitCode::FAILURE,
        }
    }

    fn message(&self) -> &str {
        match self {
            Failure::Usage(m) | Failure::Refused(m) => m,
        }
    }
}

/// The pipe the CLI would talk to.
fn endpoint(cfg: &CliConfig) -> String {
    cfg.pipe
        .clone()
        .unwrap_or_else(sandtree_ipc::transport::pipe_path)
}

/// One request over the pipe.
async fn call_daemon(
    cfg: &CliConfig,
    req: &sandtree_ipc::Request,
) -> Result<Option<sandtree_ipc::Response>, String> {
    let mut client = sandtree_ipc::transport::NamedPipeClient::at(endpoint(cfg));
    client.connect().await.map_err(|e| e.message)?;
    sandtree_ipc::call_once(&mut client, req)
        .await
        .map_err(|e| e.message)
}

fn bad(msg: &str) -> ExitCode {
    eprintln!("sandtree: {msg}");
    ExitCode::from(2)
}
