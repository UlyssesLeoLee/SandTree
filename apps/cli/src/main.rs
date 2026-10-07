//! CLI entry point.

use std::process::ExitCode;

use sandtree_cli::{help, is_failure, parse, render, to_request, CliConfig, Command};

fn main() -> ExitCode {
    let mut cfg = CliConfig::new();
    let mut args: Vec<String> = std::env::args().skip(1).collect();

    // Global flags come before the subcommand.
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
                cfg.local = true;
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

    let resp = runtime.block_on(async move {
        let router = sandtree_cli::local_router(std::sync::Arc::new(
            sandtree_kernel::Kernel::bootstrap(sandtree_kernel::KernelConfig::new(cfg.data_dir))
                .await
                .map_err(|e| format!("{}: {}", e.code.as_str(), e.message))?,
        ));
        Ok::<_, String>(router.dispatch(&req).await)
    });

    match resp {
        Ok(r) => {
            println!("{}", render(&r));
            if is_failure(&r) {
                ExitCode::FAILURE
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(e) => bad(&e),
    }
}

fn bad(msg: &str) -> ExitCode {
    eprintln!("sandtree: {msg}");
    ExitCode::from(2)
}
