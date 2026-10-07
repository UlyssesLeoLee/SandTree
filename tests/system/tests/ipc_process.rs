//! Two real processes, one real named pipe (ADR-020).
//!
//! # What had never been proven
//!
//! The daemon printed `listening on \\.\pipe\...` and never created a pipe. The
//! CLI parsed `--pipe` and never opened one. Every test in the repository called
//! a router in-process, so the entire external surface of the daemon — the thing
//! an operator and the CLI actually use — was correct and unreachable.
//!
//! The tests below spawn the built binaries. That is deliberately different from
//! the in-process tests in `sandtree-ipc` and `sandtree-daemon`: those prove the
//! dispatch loop and the pipe framing respectively, and neither can catch a
//! `main` that forgot to call them at all. Only a subprocess can.

use std::path::{Path, PathBuf};
use std::process::{Child, Command};

/// A pipe name no other test can collide with.
fn unique_pipe(tag: &str) -> String {
    use std::sync::atomic::{AtomicU32, Ordering};
    static N: AtomicU32 = AtomicU32::new(0);
    format!(
        r"\\.\pipe\sandtree-st-{}-{}-{}",
        std::process::id(),
        tag,
        N.fetch_add(1, Ordering::Relaxed)
    )
}

/// The built binaries, next to each other in the cargo target directory.
///
/// `CARGO_BIN_EXE_<name>` is only set for integration tests of the package that
/// *builds* the binary, and the daemon and the CLI are two different packages.
/// Resolving the path from the test executable's own directory works because
/// cargo puts them in the same `deps` parent.
///
/// # Missing binaries are a failure, not a skip
///
/// `cargo test -p sandtree-system-tests` does not build another package's
/// binaries. Without an explicit build step these tests would quietly run
/// nothing and the `st` gate would report green — a gate that compiles zero of
/// what it claims to cover is worse than no gate, because it contributes a false
/// assurance. So the runner is told to build first, and a missing binary here is
/// a failure with the command to run.
fn binaries() -> (PathBuf, PathBuf) {
    let mut dir = std::env::current_exe().expect("test executable path");
    dir.pop();
    if dir.ends_with("deps") {
        dir.pop();
    }
    let daemon = dir.join("sandtree-daemon.exe");
    let cli = dir.join("sandtree.exe");
    assert!(
        daemon.exists() && cli.exists(),
        "these tests drive the real binaries, which `cargo test` does not build. \
         Run: cargo build -p sandtree-daemon -p sandtree-cli (looked in {} for {} and {})",
        dir.display(),
        daemon.display(),
        cli.display()
    );
    (daemon, cli)
}

struct Daemon {
    child: Child,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// True when something is listening on `pipe`.
fn listening(pipe: &str) -> bool {
    tokio::runtime::Runtime::new()
        .expect("runtime")
        .block_on(async {
            sandtree_ipc::transport::NamedPipeClient::at(pipe)
                .connect_within(200)
                .await
                .is_ok()
        })
}

/// Start a daemon on `pipe` and wait until it is actually answering.
///
/// Waiting on the pipe rather than on a fixed sleep: a sleep is a flake that
/// only appears on a loaded machine, and this test suite runs four processes.
fn start_daemon(bin: &Path, pipe: &str, data: &Path) -> Daemon {
    let child = Command::new(bin)
        .args(["--pipe", pipe, "--data-dir"])
        .arg(data)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("the daemon binary runs");
    let daemon = Daemon { child };
    for _ in 0..100 {
        if listening(pipe) {
            return daemon;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    panic!("the daemon never claimed {pipe}");
}

/// `sandtree <args>` against `pipe`, returning (exit code, stdout).
fn run_cli(cli: &Path, pipe: &str, data: &Path, args: &[&str]) -> (Option<i32>, String) {
    let out = Command::new(cli)
        .args(["--pipe", pipe, "--data-dir"])
        .arg(data)
        .args(args)
        .output()
        .expect("the CLI runs");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

#[test]
fn the_cli_gets_a_real_answer_from_a_real_daemon_over_a_real_pipe() {
    let (daemon_bin, cli_bin) = binaries();
    let data = tempfile::tempdir().expect("temp dir");
    let pipe = unique_pipe("answer");

    let _daemon = start_daemon(&daemon_bin, &pipe, data.path());

    let (code, stdout) = run_cli(&cli_bin, &pipe, data.path(), &["methods"]);
    assert_eq!(code, Some(0), "the CLI should succeed: {stdout}");
    assert!(
        stdout.contains("sandtree.diagnostics/1"),
        "the daemon's own diagnostics bundle should come back, got: {stdout}"
    );
}

/// What is *not* asserted here: that a second daemon is refused the endpoint.
///
/// `FILE_FLAG_FIRST_PIPE_INSTANCE` was the obvious candidate and it does not
/// work. It refuses a create only against an instance that itself carried the
/// flag, so as soon as the running daemon replaces its served instance with an
/// unflagged one — which it must, or it could never replace it — any other
/// process can take the name. Windows named pipes offer no durable exclusive
/// claim; that needs an out-of-band lock (a lock file beside the store, or a
/// named mutex), and it is recorded as an open item in ADR-020 rather than
/// asserted here.
///
/// A test asserting the *current* behaviour would enshrine the defect, and one
/// asserting the desired behaviour would simply be red. Neither belongs in the
/// gate; the gap belongs in the document that lists gaps.
#[test]
fn the_endpoint_is_released_between_sessions_which_is_a_known_gap() {
    let (daemon_bin, _) = binaries();
    let data = tempfile::tempdir().expect("temp dir");
    let pipe = unique_pipe("gap");

    let _daemon = start_daemon(&daemon_bin, &pipe, data.path());

    // Hold a connection so the daemon is genuinely mid-session. The binding is
    // the point: dropping the client would end the session and release the name.
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    let _holding = {
        let client = sandtree_ipc::transport::NamedPipeClient::at(&pipe);
        rt.block_on(client.connect())
            .expect("connect to the running daemon");
        client
    };

    // A second daemon's self-check reports the endpoint free. Recorded here so
    // that closing the gap makes this test fail, and someone updates the ADR.
    let second = Command::new(&daemon_bin)
        .args(["--check", "--pipe", &pipe, "--data-dir"])
        .arg(data.path())
        .output()
        .expect("the second daemon runs");
    assert_eq!(
        second.status.code(),
        Some(0),
        "ADR-020 gap G2: a second daemon is NOT refused the endpoint. When the \
         gap is closed this assertion must fail and the ADR updated."
    );
}

#[test]
fn a_mutation_with_no_daemon_is_refused_rather_than_applied() {
    let (_, cli_bin) = binaries();
    let data = tempfile::tempdir().expect("temp dir");
    let pipe = unique_pipe("no-daemon");

    let (code, _) = run_cli(
        &cli_bin,
        &pipe,
        data.path(),
        &["invoke", "res-00000000000000000000000000", "stop"],
    );
    assert_eq!(
        code,
        Some(1),
        "a refusal is the command failing (1), not a usage error (2): a script \
         must be able to tell 'I typed it wrong' from 'it declined'"
    );
    let err = Command::new(&cli_bin)
        .args(["--pipe", &pipe, "--data-dir"])
        .arg(data.path())
        .args(["invoke", "res-00000000000000000000000000", "stop"])
        .output()
        .expect("the CLI runs");
    let stderr = String::from_utf8_lossy(&err.stderr);
    assert!(
        stderr.contains("needs the daemon"),
        "the refusal must name the reason, got: {stderr}"
    );
}

#[test]
fn a_read_only_call_still_works_with_no_daemon() {
    let (_, cli_bin) = binaries();
    let data = tempfile::tempdir().expect("temp dir");
    let pipe = unique_pipe("fallback");

    let out = Command::new(&cli_bin)
        .args(["--pipe", &pipe, "--data-dir"])
        .arg(data.path())
        .args(["methods"])
        .output()
        .expect("the CLI runs");
    assert_eq!(
        out.status.code(),
        Some(0),
        "a read-only command must still answer without a daemon"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("answering locally"),
        "the fallback must be announced, not silent: {stderr}"
    );
}
