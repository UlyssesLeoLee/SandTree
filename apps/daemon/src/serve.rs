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
//! `serve_loop` closes both windows as long as the daemon is running: the name is
//! held continuously, and it is held by an instance carrying the guard flag, so a
//! second daemon collides at `bind_first` instead of quietly alternating clients
//! (NFR-S01). What is *not* covered is the moment after `serve_loop` returns —
//! a daemon that is shutting down is no longer listening, and that is exactly
//! what `probe_pipe` reports.

use std::sync::Arc;

use sandtree_ipc::router::MethodRouter;
use sandtree_ipc::serve::serve_connection;
use sandtree_ipc::transport::NamedPipeTransport;
use sandtree_model::error::DomainError;

/// Serve clients until `stop` resolves, keeping the pipe name claimed throughout.
///
/// Returns how many requests were answered in total.
///
/// # Why one instance, kept for the whole process
///
/// A named-pipe instance is single-client and is released when its last handle
/// closes. So the obvious loop — create, wait for a client, serve it, go round
/// again — leaves the name unbound between clients, and a CLI can find "no
/// daemon" while a daemon is plainly running.
///
/// The fix also has to keep the **guard flag**, or the name is given back to
/// anyone: `FILE_FLAG_FIRST_PIPE_INSTANCE` refuses a create only against an
/// instance that itself carried the flag, and any *replacement* must leave it
/// off (otherwise the daemon could never replace its own instance). So a
/// replacement-based loop keeps the name claimed but not *exclusive*.
///
/// One instance that lives as long as the process satisfies both: it carries the
/// flag, and every client connects to it in turn, with `disconnect()` releasing
/// the client rather than the handle. A second daemon collides at `bind_first`
/// (NFR-S01).
#[cfg(windows)]
pub async fn serve_loop(
    router: Arc<MethodRouter>,
    path: String,
    stop: impl std::future::Future<Output = ()> + Send,
) -> Result<usize, DomainError> {
    // One instance, flagged, held for the whole process lifetime.
    let mut transport = NamedPipeTransport::bind_first(path).await?;
    let mut stop = std::pin::pin!(stop);
    let mut served = 0usize;
    loop {
        tokio::select! {
            biased;
            _ = &mut stop => return Ok(served),
            connected = transport.connect_client() => {
                connected?;
                served += serve_connection(router.clone(), &mut transport).await?;
                // Let the instance take the next client. Dropping it instead
                // would give up the name, which is the thing being held.
                transport.release_client().await?;
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
    /// The holder here is a plain listener that is kept alive for the test. That
    /// is the *weaker* case and it is the one worth pinning: the daemon's real
    /// hold is one flagged instance for the whole process, which
    /// `a_second_daemon_is_refused_the_endpoint` in the process test proves
    /// end to end across two real binaries.
    #[cfg(windows)]
    #[tokio::test(flavor = "multi_thread")]
    async fn a_pipe_that_is_in_use_is_reported_as_taken() {
        let path = unique_pipe("taken");
        // Held alive for the whole test: a listener that is dropped releases the
        // name, which is exactly why the hold has to outlive the sessions.
        let listener = NamedPipeTransport::at(path.clone());
        listener
            .bind()
            .await
            .expect("the first listener takes the name");

        let err = probe_pipe(&path).await.expect_err("the name is in use");
        assert!(
            err.message.contains("already taken"),
            "the refusal must say the name is taken in words rather than \
             forwarding a localised OS string, got: {}",
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
