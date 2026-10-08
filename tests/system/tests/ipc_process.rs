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

/// Every flag is read before `--check` acts, whatever order they appear in.
///
/// `--check` used to `return` from inside the argument loop, so anything written
/// after it was silently dropped. The visible damage was not a crash: it
/// **checked the wrong pipe and reported success**. `daemon --check --pipe X`
/// probed the default pipe, which on a dev box is usually free — so a busy
/// endpoint looked idle, and a broken endpoint looked fine.
///
/// A self-check that quietly examines the wrong thing is worse than no
/// self-check, because it is a green light on an unexamined subject.
#[test]
fn the_self_check_honours_flags_written_after_it() {
    let (daemon_bin, _) = binaries();
    let data = tempfile::tempdir().expect("temp dir");
    let pipe = unique_pipe("order");

    // `--check` first, `--pipe` after: the order that used to lose the flag.
    let out = Command::new(&daemon_bin)
        .args(["--check", "--pipe", &pipe, "--data-dir"])
        .arg(data.path())
        .output()
        .expect("the daemon runs --check");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains(&pipe),
        "--check must report the pipe it was given, not the default: {stdout}"
    );

    // And the same in the other order, so neither ordering can drift.
    let pipe2 = unique_pipe("order2");
    let out = Command::new(&daemon_bin)
        .args(["--pipe", &pipe2, "--data-dir"])
        .arg(data.path())
        .arg("--check")
        .output()
        .expect("the daemon runs --check");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains(&pipe2),
        "--check must report the pipe it was given, not the default: {stdout}"
    );
}
///
/// This was ADR-020 open gap **G2**, and how it closed is worth recording
/// because the obvious fix was wrong. `FILE_FLAG_FIRST_PIPE_INSTANCE` is not
/// a lease: it refuses a create only against an instance that itself carried
/// the flag. The first attempt kept the name claimed by creating a
/// *replacement* instance after each client -- but the replacement must NOT
/// carry the flag (otherwise the daemon could never replace its own instance),
/// so any other process could still take the name. Measured, not assumed: that
/// version reported the endpoint free while the daemon was mid-session.
///
/// What works needs no new dependency: keep the **one flagged instance alive for
/// the whole process** and let each client connect to that same instance in
/// turn. The name is then permanently held by a flagged instance, which is
/// exactly what a second daemon's `bind_first` collides with.
/// A second daemon is refused the endpoint while the first is running (NFR-S01).
///
/// This was ADR-020 open gap **G2**, and how it closed is worth recording
/// because the diagnosis written into the ADR the first time was wrong.
///
/// `FILE_FLAG_FIRST_PIPE_INSTANCE` refuses a create only against an instance that
/// itself carried the flag. The first attempt kept the name claimed by creating a
/// *replacement* instance after each client -- but the replacement must NOT carry
/// the flag (otherwise the daemon could never replace its own instance), so the
/// name was given back to anyone who asked.
///
/// What works needs no new dependency: keep the **one flagged instance alive for
/// the whole process**, and let each client connect to that same instance in turn.
/// The name is then permanently held by a flagged instance, which is exactly what
/// a second daemon's `bind_first` collides with.
///
/// And the reason that took a detour to find: the measurement was broken. See
/// `the_self_check_honours_flags_written_after_it`.
#[test]
fn a_second_daemon_is_refused_the_endpoint() {
    let (daemon_bin, _) = binaries();
    let data = tempfile::tempdir().expect("temp dir");
    let pipe = unique_pipe("exclusive");

    let _daemon = start_daemon(&daemon_bin, &pipe, data.path());

    // Hold a connection so the daemon is genuinely mid-session: an idle daemon
    // between clients is the weaker case, and that is the one that slipped through.
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    let _holding = {
        let client = sandtree_ipc::transport::NamedPipeClient::at(&pipe);
        rt.block_on(client.connect())
            .expect("connect to the running daemon");
        client
    };

    let second = Command::new(&daemon_bin)
        .args(["--check", "--pipe", &pipe, "--data-dir"])
        .arg(data.path())
        .output()
        .expect("the second daemon runs");
    assert_ne!(
        second.status.code(),
        Some(0),
        "a second daemon must refuse the endpoint rather than share it"
    );
    let stderr = String::from_utf8_lossy(&second.stderr);
    assert!(
        stderr.contains("another daemon may be running"),
        "the refusal must say why: {stderr}"
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
