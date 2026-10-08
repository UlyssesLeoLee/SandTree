//! Daemon entry point.
//!
//! Deliberately thin: parse flags, build the daemon, run until Ctrl-C. All the
//! behaviour lives in the library so it can be tested without a process.

use std::process::ExitCode;

use sandtree_daemon::{Daemon, DaemonConfig};

fn main() -> ExitCode {
    let mut cfg = DaemonConfig::new();
    let mut args = std::env::args().skip(1);
    // Collected, not acted on: `--check` used to `return` from inside this loop,
    // which meant **every flag written after it was silently ignored**.
    // `daemon --check --pipe X` probed the default pipe, not X — and reported
    // success, so the self-check was confidently checking the wrong thing.
    let mut check = false;

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
                check = true;
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

    // Acted on only once every flag has been read, so `--check` sees the same
    // configuration a real start would.
    if check {
        return run_check(cfg);
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

        // Check the pipe is free *before* announcing readiness. Announcing first and
        // failing to listen afterwards is how this daemon spent its life: it
        // printed "listening" and then never accepted a client.
        let pipe = daemon.pipe().to_string();
        if let Err(e) = sandtree_daemon::serve::probe_pipe(&pipe).await {
            eprintln!(
                "sandtree-daemon: cannot take {}: {} — another daemon may be running",
                pipe, e.message
            );
            return ExitCode::from(3);
        }

        println!("sandtree-daemon listening on {pipe}");
        let interval =
            std::time::Duration::from_millis(daemon.kernel().config().reconcile_interval_ms);
        let mut ticker = tokio::time::interval(interval);
        // The first tick fires immediately; skip it so a fresh daemon does not
        // reconcile before it has answered anything.
        ticker.tick().await;
        // `serve_loop` keeps the pipe name claimed for as long as it runs, so
        // there is no per-connection rebinding here.
        let serving = sandtree_daemon::serve::serve_loop(
            daemon.router().clone(),
            pipe.clone(),
            std::future::pending(),
        );
        let mut serving = Box::pin(serving);
        loop {
            tokio::select! {
                result = &mut serving => {
                    // The loop only returns if `stop` resolves, which it never
                    // does here, or if the pipe could not be kept. Either way
                    // the daemon has lost its endpoint and must not keep
                    // reconciling as though it were serving.
                    tracing::error!(?result, "the IPC endpoint was lost; shutting down");
                    return ExitCode::from(3);
                }
                _ = ticker.tick() => {
                    if let Err(e) = daemon.reconcile_once().await {
                        tracing::warn!(error = %e, "reconcile pass failed");
                    }
                }
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
        // Probing the pipe is part of the self-check: "the daemon can start"
        // and "the daemon can actually listen" are different questions, and the
        // packaging smoke test is exactly where the second one should be asked.
        let probe = sandtree_daemon::serve::probe_pipe(daemon.pipe()).await;
        println!(
            "pipe: {}\nmethods: {}\ngaps: {}\npipe free: {}",
            daemon.pipe(),
            daemon.methods().len(),
            gaps.len(),
            probe.is_ok()
        );
        if let Err(e) = probe {
            // Same wording as the serve path, so "why won't it start" reads the
            // same whether the operator ran `--check` or the real thing.
            eprintln!(
                "cannot take {}: {} — another daemon may be running",
                daemon.pipe(),
                e.message
            );
            return ExitCode::from(3);
        }
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
