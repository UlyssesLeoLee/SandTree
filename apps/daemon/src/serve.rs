//! Actually listening on the pipe (DD-DATA §6, NFR-S03, ADR-020).
//!
//! # Why this module exists at all
//!
//! Because until now the daemon *said* it was listening and was not. `main`
//! printed `listening on \\.\pipe\...` and then went straight into a reconcile
//! sleep loop: no pipe was created, no client was ever accepted, and the
//! `MethodRouter` — with a handler for every method in `method::ALL` — could not
//! be reached from another process. Everything below this line was correct and
//! unreachable.
//!
//! # The loop
//!
//! [`serve_loop`] takes the name once, and from then on keeps it claimed: it
//! creates the next instance *before* serving the connected one, so the name is
//! never unbound between clients. See that function for why that matters.
//!
//! # The window that is *not* covered
//!
//! `serve_loop` closes the *availability* window — the name is never unbound
//! between clients, so a CLI cannot find "no daemon" while one is running.
//!
//! It does **not** close the *exclusivity* window, and this is worth being
//! precise about. `FILE_FLAG_FIRST_PIPE_INSTANCE` is not a lease: it refuses a
//! create only against an instance that itself carried the flag. Since the
//! replacements `serve_loop` creates must *not* carry it (otherwise the daemon
//! could never replace its own instance), any other process can bind the name.
//! Measured, not assumed: a second daemon's `--check` succeeds while the first
//! is mid-session.
//!
//! Closing it needs an out-of-band claim — a lock file beside the store, or a
//! named mutex. Recorded as open item **G2** in ADR-020; the process test that
//! observes it is named for the gap so that closing it turns that test red.

use std::sync::Arc;

use sandtree_ipc::router::MethodRouter;
use sandtree_ipc::serve::serve_connection;
use sandtree_ipc::transport::NamedPipeTransport;
use sandtree_model::error::DomainError;

/// Serve clients until `stop` resolves, keeping the pipe name claimed throughout.
///
/// Returns how many requests were answered in total.
///
/// # Why the next instance is created *before* the current one is served
///
/// A named-pipe instance is released when its last handle closes. So the obvious
/// loop — create, wait for a client, serve it, go round again — leaves the name
/// unbound between clients, and a second daemon can take it in exactly that
/// window. This was not theoretical: a test that started a second daemon while
/// the first was mid-session found it happily bound the same name.
///
/// The fix is tokio's own server idiom: take the connected instance, **create
/// the next one immediately**, and only then serve the connected one. The
/// previous instance drops when its session ends, but the name is already held
/// again, so it is never free.
///
/// The one instance created with `first_pipe_instance` is the startup one. That
/// flag is what makes "another daemon is already running" a loud failure instead
/// of two daemons quietly alternating clients (NFR-S01).
pub async fn serve_loop(
    router: Arc<MethodRouter>,
    path: String,
    stop: impl std::future::Future<Output = ()> + Send,
) -> Result<usize, DomainError> {
    let mut pending = NamedPipeTransport::bind_first(path.clone()).await?;
    let mut stop = std::pin::pin!(stop);
    let mut served = 0usize;
    loop {
        tokio::select! {
            biased;
            _ = &mut stop => return Ok(served),
            connected = pending.connect_client() => {
                connected?;
                // Claim the name again before serving, so it is never free.
                let next = NamedPipeTransport::bind_next(path.clone()).await?;
                let mut current = std::mem::replace(&mut pending, next);
                served += serve_connection(router.clone(), &mut current).await?;
                // `current` drops here. `pending` has been holding the name since
                // before the session started.
            }
        }
    }
}

/// Is the pipe name free right now?
///
/// # A probe, not a lease
///
/// This creates an instance and immediately drops it, so it answers "is somebody
/// listening *at this moment*" and then releases the name again. It is
/// deliberately named `probe_pipe`: an earlier version called it `claim` and
/// implied an exclusivity it does not have — and a name that promises a
/// guarantee is how the next reader comes to rely on one that is not there.
///
/// What startup actually wants is exactly this question — "is another daemon
/// already on this endpoint?" — so the honest name is also the useful one.
pub async fn probe_pipe(path: &str) -> Result<(), DomainError> {
    NamedPipeTransport::at(path).bind().await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A pipe name no other test can collide with.
    #[cfg(windows)]
    pub(crate) fn unique_pipe(tag: &str) -> String {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        format!(
            r"\\.\pipe\sandtree-d-{}-{}-{}",
            std::process::id(),
            tag,
            N.fetch_add(1, Ordering::Relaxed)
        )
    }

    #[cfg(not(windows))]
    pub(crate) fn unique_pipe(tag: &str) -> String {
        format!("sandtree-test-{tag}")
    }

    /// The claim that failed before this module existed: the daemon answers a
    /// client on a real pipe.
    ///
    /// Not over the loopback — the loopback proves the dispatch loop, and it has
    /// its own tests for that. What nothing else proved is that a *named pipe*
    /// carries a request in, gets dispatched, and carries a reply out. That is
    /// the entire external surface of the daemon.
    #[cfg(windows)]
    #[tokio::test(flavor = "multi_thread")]
    async fn the_daemon_answers_a_client_over_a_real_pipe() {
        let mut r = MethodRouter::new();
        r.register_sync(sandtree_ipc::method::DIAGNOSTIC_VERSION, |_| {
            Ok(serde_json::json!({"build": "test"}))
        });
        let router = Arc::new(r);
        let path = unique_pipe("answer");

        let path_for_task = path.clone();
        let serving = tokio::spawn(serve_loop(router, path_for_task, std::future::pending()));
        let mut client = sandtree_ipc::transport::NamedPipeClient::at(path);
        client.connect().await.expect("the daemon is listening");

        let reply = sandtree_ipc::call_once(
            &mut client,
            &sandtree_ipc::Request::new(
                sandtree_ipc::method::DIAGNOSTIC_VERSION,
                serde_json::Value::Null,
            ),
        )
        .await
        .expect("transport")
        .expect("a reply");
        assert!(reply.is_ok(), "{:?}", reply.to_json());
        assert_eq!(
            reply.to_json()["result"]["build"],
            serde_json::json!("test")
        );

        drop(client);
        serving.abort();
    }

    /// Several requests on one connection: the pipe stays up for a session, not
    /// just for one call.
    #[cfg(windows)]
    #[tokio::test(flavor = "multi_thread")]
    async fn one_connection_carries_several_requests() {
        let mut r = MethodRouter::new();
        r.register_sync(sandtree_ipc::method::DIAGNOSTIC_VERSION, |_| {
            Ok(serde_json::json!({"build": "test"}))
        });
        let router = Arc::new(r);
        let path = unique_pipe("session");

        let path_for_task = path.clone();
        let serving = tokio::spawn(serve_loop(router, path_for_task, std::future::pending()));
        let mut client = sandtree_ipc::transport::NamedPipeClient::at(path);
        client.connect().await.expect("listening");

        for _ in 0..3 {
            let reply = sandtree_ipc::call_once(
                &mut client,
                &sandtree_ipc::Request::new(
                    sandtree_ipc::method::DIAGNOSTIC_VERSION,
                    serde_json::Value::Null,
                ),
            )
            .await
            .expect("transport")
            .expect("a reply");
            assert!(reply.is_ok());
        }

        drop(client);
        serving.abort();
    }

    /// A second daemon is told no, at startup (NFR-S01).
    ///
    /// Scoped to what is actually true: while a listener holds an instance the
    /// name is unavailable. The window *between* two connections is not covered —
    /// see the module note — and is recorded as an open item rather than asserted
    /// here, because an assertion that only holds most of the time is worse than
    /// a written-down gap.
    #[cfg(windows)]
    #[tokio::test(flavor = "multi_thread")]
    async fn a_pipe_that_is_in_use_is_reported_as_taken() {
        let path = unique_pipe("taken");
        // Held alive for the whole test: a listener that is dropped releases the
        // name, which is exactly the gap the module documents.
        let listener = NamedPipeTransport::at(path.clone());
        listener
            .bind()
            .await
            .expect("the first listener takes the name");

        let err = probe_pipe(&path).await.expect_err("the name is in use");
        assert!(
            err.message.contains("cannot create named pipe"),
            "{}",
            err.message
        );
    }

    #[cfg(windows)]
    #[tokio::test(flavor = "multi_thread")]
    async fn an_unused_pipe_is_reported_as_free() {
        probe_pipe(&unique_pipe("free"))
            .await
            .expect("nothing is listening here");
    }
}
