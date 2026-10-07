//! In-memory duplex transport pair.
//!
//! # Why a crate ships a test transport
//!
//! Because the alternative is that every test of a request/response protocol
//! either needs a real named pipe (Windows-only, so the protocol's error paths
//! are untestable everywhere else) or hand-rolls its own channel pair (so each
//! test target quietly tests a different thing).
//!
//! This one is deliberately minimal and deliberately *not* clever: two mailboxes
//! and two wake-ups, no buffering, no reordering. A protocol test that passes
//! here is testing the protocol, not the channel.
//!
//! # Where it is legitimate outside tests
//!
//! Single-process embedding, where an embedder wants the real protocol and the
//! real dispatch logic without spawning a worker. That is a real use — it is how
//! `sandtree-daemon`'s in-process loader is tested — but it is *not* isolation
//! (FR-055), and the type says so in its name: `loopback`, not `local`.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use sandtree_model::error::{DomainError, ErrorCode};
use tokio::sync::mpsc;

use crate::transport::Transport;

#[derive(Debug, Default)]
struct Mailbox {
    items: Mutex<VecDeque<Vec<u8>>>,
    /// Closed by the owner. A receiver drains what is queued and only then
    /// reports end of stream, so the answer to the last request a worker ever
    /// sent is still delivered.
    closed: Mutex<bool>,
}

impl Mailbox {
    fn push(&self, bytes: Vec<u8>, wake: &mpsc::UnboundedSender<()>) {
        if self.is_closed() {
            return;
        }
        self.items.lock().unwrap().push_back(bytes);
        let _ = wake.send(());
    }

    fn close(&self, wake: &mpsc::UnboundedSender<()>) {
        if !self.is_closed() {
            *self.closed.lock().unwrap() = true;
        }
        let _ = wake.send(());
    }

    fn pop(&self) -> Option<Vec<u8>> {
        self.items.lock().unwrap().pop_front()
    }

    fn is_closed(&self) -> bool {
        *self.closed.lock().unwrap()
    }
}

fn loopback_error(msg: impl Into<String>) -> DomainError {
    DomainError::new(ErrorCode::CORE_INVALID, msg)
}

/// One end of a [`loopback_pair`].
#[derive(Debug)]
pub struct Loopback {
    /// Where my `send` goes: the other end's `recv`.
    tx: Arc<Mailbox>,
    /// Where my `recv` reads: the other end's `send`.
    rx: Arc<Mailbox>,
    /// Woken by writes to, and closes of, `rx`.
    wake: mpsc::UnboundedReceiver<()>,
    /// Used to wake the other end when `tx` or `rx` closes.
    peer_wake: mpsc::UnboundedSender<()>,
    /// Per-transport framing state.
    ///
    /// This is the whole reason this transport is worth having. `recv` returns a
    /// *decoded body*, exactly as [`crate::transport::NamedPipeTransport`] does.
    /// An earlier version returned whatever bytes were in the mailbox, framed and
    /// all — so the loopback and the pipe disagreed about what `recv` yields, and
    /// every protocol test written against it was testing a contract production
    /// does not have. A faithful fake has to pay the same cost as the real one.
    decoder: crate::framing::FrameDecoder,
}

#[async_trait::async_trait]
impl Transport for Loopback {
    async fn send(&self, bytes: &[u8]) -> Result<(), DomainError> {
        // The peer's `close` marks *my* sending mailbox closed, so this is how a
        // write after the peer went away becomes an error instead of a message
        // nobody will ever read.
        if self.tx.is_closed() {
            return Err(loopback_error(
                "loopback peer is closed; the message would go nowhere",
            ));
        }
        // Framed here, decoded there: the same work the real transport does, so
        // a frame that would be rejected on a pipe is rejected here too.
        self.tx
            .push(crate::framing::encode(bytes)?, &self.peer_wake);
        Ok(())
    }

    async fn recv(&mut self) -> Result<Option<Vec<u8>>, DomainError> {
        loop {
            if let Some(raw) = self.rx.pop() {
                self.decoder.push(&raw)?;
                if let Some(frame) = self.decoder.next_frame()? {
                    return Ok(Some(frame));
                }
                // A partial frame: keep reading rather than reporting nothing.
                continue;
            }
            if self.rx.is_closed() {
                return Ok(None);
            }
            // A closed channel also wakes the receiver, which is the wake-up we
            // want; the error itself carries no information.
            if self.wake.recv().await.is_none() {
                let last = self.rx.pop();
                match last {
                    Some(raw) => {
                        self.decoder.push(&raw)?;
                        return self.decoder.next_frame();
                    }
                    None => return Ok(None),
                }
            }
        }
    }

    async fn close(&self) {
        // Both mailboxes. Closing only the receive side would leave the peer
        // blocked in its own `recv` waiting for a message that can never come.
        self.tx.close(&self.peer_wake);
        self.rx.close(&self.peer_wake);
    }
}

impl Drop for Loopback {
    fn drop(&mut self) {
        // Not `async`, and deliberately duplicating `close` rather than calling
        // it: a Drop cannot await, and a worker task that panics must still tell
        // the peer the pipe is gone.
        self.tx.close(&self.peer_wake);
        self.rx.close(&self.peer_wake);
    }
}

/// Two connected [`Loopback`] ends.
///
/// Dropping either end ends the other: a worker task that dies must make the
/// client's next `recv` return `Ok(None)` rather than hang, or a dead worker
/// becomes a daemon that waits forever.
pub fn loopback_pair() -> (Loopback, Loopback) {
    let a_to_b = Arc::new(Mailbox::default());
    let b_to_a = Arc::new(Mailbox::default());
    let (wake_a, recv_a) = mpsc::unbounded_channel();
    let (wake_b, recv_b) = mpsc::unbounded_channel();
    (
        Loopback {
            tx: a_to_b.clone(),
            rx: b_to_a.clone(),
            wake: recv_a,
            peer_wake: wake_b,
            decoder: crate::framing::FrameDecoder::new(),
        },
        Loopback {
            tx: b_to_a,
            rx: a_to_b,
            wake: recv_b,
            peer_wake: wake_a,
            decoder: crate::framing::FrameDecoder::new(),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_sent_message_arrives_in_order() {
        let (a, mut b) = loopback_pair();
        a.send(b"one").await.unwrap();
        a.send(b"two").await.unwrap();
        assert_eq!(b.recv().await.unwrap().as_deref(), Some(&b"one"[..]));
        assert_eq!(b.recv().await.unwrap().as_deref(), Some(&b"two"[..]));
    }

    /// The contract that makes this a usable stand-in for the pipe: `recv`
    /// yields the **body**, with the length prefix stripped, exactly as
    /// `NamedPipeTransport` does.
    ///
    /// When this transport returned the raw mailbox bytes, a protocol test
    /// written against it would decode a length prefix that production has
    /// already removed — and would pass while the real one failed.
    #[tokio::test]
    async fn recv_yields_the_body_not_the_framed_bytes() {
        let (a, mut b) = loopback_pair();
        let payload = b"{\"method\":\"diagnostic.version\"}";
        a.send(payload).await.unwrap();
        let got = b.recv().await.unwrap().expect("a frame");
        assert_eq!(got, payload);
        assert_ne!(
            &got[..4],
            &crate::framing::encode(payload).unwrap()[..4],
            "the length prefix must not survive into the body"
        );
    }

    /// A length prefix the real transport would reject is rejected here too.
    #[tokio::test]
    async fn an_oversized_frame_is_refused_rather_than_buffered() {
        // Written straight into the mailbox, bypassing `send`, because that is
        // what a hostile or corrupt peer looks like from the reader's side.
        let (a, mut b) = loopback_pair();
        let mut raw = ((crate::framing::MAX_FRAME_BYTES + 1) as u32)
            .to_le_bytes()
            .to_vec();
        raw.extend_from_slice(b"payload");
        a.tx.push(raw, &b.peer_wake);
        let err = b
            .recv()
            .await
            .expect_err("must not allocate its way to death");
        assert!(
            err.message.contains("frame"),
            "the refusal must name the frame, got: {}",
            err.message
        );
    }

    #[tokio::test]
    async fn the_pair_is_duplex() {
        let (mut a, mut b) = loopback_pair();
        a.send(b"ping").await.unwrap();
        b.send(b"pong").await.unwrap();
        assert_eq!(a.recv().await.unwrap().as_deref(), Some(&b"pong"[..]));
        assert_eq!(b.recv().await.unwrap().as_deref(), Some(&b"ping"[..]));
    }

    #[tokio::test]
    async fn dropping_one_end_ends_the_other_rather_than_hanging() {
        // The failure this protects against: a dead worker task leaving the
        // daemon blocked in `recv` forever.
        let (a, mut b) = loopback_pair();
        drop(a);
        assert_eq!(
            b.recv()
                .await
                .expect("no transport error, just end of stream"),
            None
        );
    }

    #[tokio::test]
    async fn buffered_messages_survive_the_peer_closing() {
        // The last request a worker ever sent still has its answer delivered;
        // truncating it would turn a clean shutdown into a lost reply.
        let (a, mut b) = loopback_pair();
        a.send(b"final").await.unwrap();
        drop(a);
        assert_eq!(b.recv().await.unwrap().as_deref(), Some(&b"final"[..]));
        assert_eq!(b.recv().await.unwrap(), None);
    }

    #[tokio::test]
    async fn sending_after_the_peer_closed_is_an_error_not_a_silent_drop() {
        let (a, b) = loopback_pair();
        drop(b);
        assert!(a.send(b"x").await.is_err());
    }
}
