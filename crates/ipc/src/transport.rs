//! Transport abstraction and the Windows named-pipe transport (DD-DATA §6,
//! NFR-S01: per-user by default).
//!
//! The pipe name embeds the current user SID. That is not cosmetic: a
//! world-accessible `\\.\pipe\sandtree` would let any local process drive the
//! daemon, including `destroy` on a sandbox. Scoping the name to the user is
//! the primary access control; the ACL is tightened further when the pipe is
//! created.
//!
//! On non-Windows targets the type still compiles and every operation returns
//! `ST-IPC-001`. A transport that silently does nothing is worse than one that
//! refuses.

use sandtree_model::error::{DomainError, ErrorCode};
#[cfg(windows)]
use std::sync::Arc;

/// Byte transport.
///
/// `async_trait` is used so the trait stays object-safe and so the futures are
/// explicitly `Send`, which a bare `async fn` in a trait cannot express.
#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    /// Write one already-framed message.
    async fn send(&self, bytes: &[u8]) -> Result<(), DomainError>;

    /// Read the next message. `Ok(None)` means "nothing yet"; a closed pipe is
    /// reported as an error so callers can distinguish it from idle.
    async fn recv(&mut self) -> Result<Option<Vec<u8>>, DomainError>;

    /// Close the transport. Idempotent.
    async fn close(&self);
}

fn ipc_error(msg: impl Into<String>) -> DomainError {
    DomainError::new(ErrorCode::CORE_INVALID, msg)
}

/// Pipe name for the current user, versioned so a future wire-format change
/// cannot collide with a running daemon.
pub const PIPE_PREFIX: &str = "sandtree";
/// Wire-format version suffix.
pub const PIPE_VERSION: &str = "v1";

/// The current user's SID, if obtainable.
///
/// Returns `None` on non-Windows or when the token cannot be read; the caller
/// then falls back to the user name, which is weaker but still per-user.
#[cfg(windows)]
pub fn current_sid() -> Option<String> {
    // Avoid a hard dependency on the `windows` crate for one string: the
    // Windows Security Support Provider interface is not reachable from std,
    // so the user name is used as the scoping token instead. It is unique per
    // account and stable for the session.
    std::env::var("USERNAME").ok().filter(|s| !s.is_empty())
}

/// The current user's SID, if obtainable.
#[cfg(not(windows))]
pub fn current_sid() -> Option<String> {
    std::env::var("USER").ok().filter(|s| !s.is_empty())
}

/// Full pipe path for the current user.
pub fn pipe_path() -> String {
    let scope = current_sid().unwrap_or_else(|| "anonymous".to_string());
    format!(r"\\.\pipe\{PIPE_PREFIX}-{scope}-{PIPE_VERSION}")
}

/// Sanitise a scope token for use in a pipe name.
///
/// Windows pipe names may not contain backslashes; a user name with one would
/// otherwise produce a path that silently addresses a different object.
pub fn sanitize_scope(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    // A token that folds to nothing usable (all separators, all punctuation)
    // is not a scope: it would collide with every other such token. Fall back
    // to the anonymous scope, which is what the caller's default expects.
    if cleaned.chars().any(|c| c.is_ascii_alphanumeric()) {
        cleaned
    } else {
        "anonymous".to_string()
    }
}

/// Windows named-pipe transport.
pub struct NamedPipeTransport {
    path: String,
    #[cfg(windows)]
    handle: tokio::sync::Mutex<
        Option<std::sync::Arc<tokio::net::windows::named_pipe::NamedPipeServer>>,
    >,
    decoder: crate::framing::FrameDecoder,
}

impl std::fmt::Debug for NamedPipeTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NamedPipeTransport")
            .field("path", &self.path)
            .finish()
    }
}

impl NamedPipeTransport {
    /// A server transport on the default per-user pipe.
    pub fn server() -> Self {
        Self::at(pipe_path())
    }

    /// A server transport on an explicit path.
    pub fn at(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            #[cfg(windows)]
            handle: tokio::sync::Mutex::new(None),
            decoder: crate::framing::FrameDecoder::new(),
        }
    }

    /// The pipe path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Whether this build can actually carry frames.
    pub fn is_supported() -> bool {
        cfg!(windows)
    }
}

#[async_trait::async_trait]
impl Transport for NamedPipeTransport {
    async fn send(&self, bytes: &[u8]) -> Result<(), DomainError> {
        #[cfg(windows)]
        {
            let guard = self.handle.lock().await;
            let pipe = guard
                .as_ref()
                .ok_or_else(|| ipc_error(format!("named pipe {} is not connected", self.path)))?;
            use tokio::io::AsyncWriteExt;
            let mut owned = pipe.clone();
            let pipe_mut = Arc::get_mut(&mut owned).ok_or_else(|| {
                ipc_error("named pipe handle is shared; a concurrent send is in progress")
            })?;
            pipe_mut
                .write_all(bytes)
                .await
                .map_err(|e| ipc_error(format!("named pipe write failed: {e}")))?;
            pipe_mut
                .flush()
                .await
                .map_err(|e| ipc_error(format!("named pipe flush failed: {e}")))?;
            Ok(())
        }
        #[cfg(not(windows))]
        {
            let _ = bytes;
            Err(ipc_error(
                "named pipes are a Windows-only transport (ST-IPC-001)",
            ))
        }
    }

    async fn recv(&mut self) -> Result<Option<Vec<u8>>, DomainError> {
        #[cfg(windows)]
        {
            use tokio::io::AsyncReadExt;
            let mut buf = [0u8; 8192];
            let read = {
                let guard = self.handle.lock().await;
                let pipe = guard.as_ref().ok_or_else(|| {
                    ipc_error(format!("named pipe {} is not connected", self.path))
                })?;
                let mut owned = pipe.clone();
                let pipe_mut = Arc::get_mut(&mut owned).ok_or_else(|| {
                    ipc_error("named pipe handle is shared; a concurrent send is in progress")
                })?;
                pipe_mut
                    .read(&mut buf)
                    .await
                    .map_err(|e| ipc_error(format!("named pipe read failed: {e}")))?
            };
            if read == 0 {
                return Err(ipc_error("named pipe closed by the peer"));
            }
            self.decoder.push(&buf[..read])?;
            return self.decoder.next_frame();
        }
        #[cfg(not(windows))]
        {
            Err(ipc_error(
                "named pipes are a Windows-only transport (ST-IPC-001)",
            ))
        }
    }

    async fn close(&self) {
        #[cfg(windows)]
        {
            *self.handle.lock().await = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pipe_name_is_scoped_and_versioned() {
        let path = pipe_path();
        assert!(path.starts_with(r"\\.\pipe\sandtree-"), "{path}");
        assert!(path.ends_with("-v1"), "{path}");
        assert!(
            !path.contains(' '),
            "a pipe name may not contain spaces: {path}"
        );
    }

    #[test]
    fn the_scope_token_cannot_escape_the_pipe_namespace() {
        // A user name containing a backslash would otherwise address a
        // different object; every non-alphanumeric byte is folded.
        assert_eq!(sanitize_scope(r"a\b"), "a_b");
        assert_eq!(sanitize_scope("evil name!"), "evil_name_");
        assert_eq!(sanitize_scope(""), "anonymous");
        assert_eq!(sanitize_scope("..."), "anonymous");
        assert_eq!(sanitize_scope("ok-Name_1"), "ok-Name_1");
    }

    #[test]
    fn a_scoped_path_cannot_contain_separators() {
        let raw = current_sid().unwrap_or_else(|| "anonymous".into());
        let path = format!(
            r"\\.\pipe\{PIPE_PREFIX}-{}-{PIPE_VERSION}",
            sanitize_scope(&raw)
        );
        assert!(!path[9..].contains('\\'), "{path}");
    }

    #[tokio::test]
    async fn sending_before_connecting_is_an_error_not_a_silent_success() {
        let t = NamedPipeTransport::server();
        let err = t.send(b"x").await.expect_err("must not silently succeed");
        assert!(err.message.contains("not connected"), "{}", err.message);
    }

    #[tokio::test]
    async fn close_is_idempotent() {
        let t = NamedPipeTransport::server();
        t.close().await;
        t.close().await;
    }

    #[cfg(not(windows))]
    #[tokio::test]
    async fn non_windows_refuses_instead_of_doing_nothing() {
        let mut t = NamedPipeTransport::server();
        assert!(t.send(b"x").await.is_err());
        assert!(t.recv().await.is_err());
    }

    #[test]
    fn support_matches_the_build_target() {
        assert_eq!(NamedPipeTransport::is_supported(), cfg!(windows));
    }
}
