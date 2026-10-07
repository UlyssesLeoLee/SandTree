//! Daemon entry point.
//!
//! Deliberately thin: parse flags, build the daemon, run until Ctrl-C. All the
//! behaviour lives in the library so it can be tested without a process.

use std::process::ExitCode;

use sandtree_daemon::{Daemon, DaemonConfig};

fn main() -> ExitCode {
    let mut cfg = DaemonConfig::new();
    let mut args = std::env::args().skip(1);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            // NFR-U01: the daemon's version has to be readable without
            // starting it, or "which build is on this box" needs a debugger.
            "--version" | "-V" => {
                println!("sandtree-daemon {}", env!("CARGO_PKG_VERSION"));
                return ExitCode::SUCCESS;
            }
            "--data-dir" => match args.next() {
                Some(v) => cfg.data_dir = v.into(),
                None => return fail("--data-dir needs a value"),
            },
            "--reconcile-interval-ms" => match args.next().and_then(|v| v.parse().ok()) {
                Some(v) => cfg.reconcile_interval_ms = v,
                None => return fail("--reconcile-interval-ms needs a number"),
            },
            "--stale-grace-ms" => match args.next().and_then(|v| v.parse().ok()) {
                Some(v) => cfg.stale_grace_ms = v,
                None => return fail("--stale-grace-ms needs a number"),
            },
            "--pipe" => match args.next() {
                Some(v) => cfg.pipe_path = Some(v),
                None => return fail("--pipe needs a value"),
            },
            "--check" => {
                // Startup self-check: report coverage gaps and exit without
                // entering the serve loop. Useful in CI and in a packaging
                // smoke test.
                return run_check(cfg);
            }
            "-h" | "--help" => {
                println!(
                    "sandtree-daemon [--data-dir DIR] [--pipe NAME] \
                     [--reconcile-interval-ms N] [--stale-grace-ms N] \
                     [--check] [--version]"
                );
                return ExitCode::SUCCESS;
            }
            other => return fail(&format!("unknown argument {other:?}")),
        }
    }

    let runtime = match tokio::runtime::Runtime::new() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("sandtree-daemon: cannot start a runtime: {e}");
            return ExitCode::FAILURE;
        }
    };

    runtime.block_on(async move {
        let daemon = match Daemon::start(cfg).await {
            Ok(d) => d,
            Err(e) => {
                eprintln!(
                    "sandtree-daemon: {} {}: {}",
                    e.code.as_str(),
                    e.code,
                    e.message
                );
                return ExitCode::FAILURE;
            }
        };

        let gaps = daemon.coverage_gaps();
        if !gaps.is_empty() {
            // An unroutable method is a packaging bug, not a runtime condition;
            // refuse to serve rather than answer "unknown method" later.
            eprintln!("sandtree-daemon: no handler for {gaps:?}");
            return ExitCode::FAILURE;
        }

        println!("sandtree-daemon listening on {}", daemon.pipe());
        let interval =
            std::time::Duration::from_millis(daemon.kernel().config().reconcile_interval_ms);
        loop {
            tokio::time::sleep(interval).await;
            if let Err(e) = daemon.reconcile_once().await {
                tracing::warn!(error = %e, "reconcile pass failed");
            }
        }
    })
}

fn run_check(cfg: DaemonConfig) -> ExitCode {
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("sandtree-daemon: cannot start a runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    runtime.block_on(async move {
        let daemon = match Daemon::start(cfg).await {
            Ok(d) => d,
            Err(e) => {
                eprintln!("sandtree-daemon: {}: {}", e.code.as_str(), e.message);
                return ExitCode::FAILURE;
            }
        };
        let gaps = daemon.coverage_gaps();
        println!(
            "pipe: {}\nmethods: {}\ngaps: {}",
            daemon.pipe(),
            daemon.methods().len(),
            gaps.len()
        );
        if gaps.is_empty() {
            ExitCode::SUCCESS
        } else {
            eprintln!("unrouted methods: {gaps:?}");
            ExitCode::FAILURE
        }
    })
}

fn fail(msg: &str) -> ExitCode {
    eprintln!("sandtree-daemon: {msg}");
    ExitCode::from(2)
}
