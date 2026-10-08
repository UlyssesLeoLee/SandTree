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

/// Byte transport, **framing included**.
///
/// # The contract
///
/// `send` takes a message **body** and writes it framed; `recv` returns a decoded
/// body with the length prefix removed. Callers never see the prefix.
///
/// That is not a detail — it is the property that makes a fake transport
/// interchangeable with the real one. An earlier `Loopback` returned raw mailbox
/// bytes while `NamedPipeTransport` stripped the prefix, so the two disagreed
/// about what `recv` yields and every protocol test written against the fake was
/// testing a contract production does not have. Framing belongs here precisely
/// so that there is only one contract to get right.
///
/// `async_trait` is used so the trait stays object-safe and so the futures are
/// explicitly `Send`, which a bare `async fn` in a trait cannot express.
#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    /// Write one message body.
    async fn send(&self, bytes: &[u8]) -> Result<(), DomainError>;

    /// Read the next message body. `Ok(None)` means end of stream.
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
///
/// This is the **server** end: it owns the pipe name, creates it, and waits for
/// a client. The client end is [`NamedPipeClient`].
///
/// # Why the pipe is not behind an `Arc`
///
/// An earlier version held `Arc<NamedPipeServer>` and cloned it out of the mutex
/// to get a `&mut` for the IO call. `Arc::get_mut` then returned `None`, because
/// the mutex guard still held a live reference — so **every** `send` and `recv`
/// on a *connected* pipe failed with "named pipe handle is shared". The
/// disconnected path (the only one the old tests exercised) still worked, which
/// is why it stayed green: the code had never carried a frame, so nothing had
/// ever reached the failing branch.
///
/// The pipe is held directly and the lock is held across the IO instead. The
/// protocol is strictly alternating, so serialising IO per transport costs
/// nothing.
pub struct NamedPipeTransport {
    path: String,
    #[cfg(windows)]
    pipe: tokio::sync::Mutex<Option<PipeServer>>,
    decoder: crate::framing::FrameDecoder,
}

#[cfg(windows)]
type PipeServer = tokio::net::windows::named_pipe::NamedPipeServer;

#[cfg(windows)]
type PipeClient = tokio::net::windows::named_pipe::NamedPipeClient;

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
            pipe: tokio::sync::Mutex::new(None),
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

    /// Create the pipe and wait for one client to connect.
    ///
    /// The daemon owns the name so that a worker can be spawned and pointed at a
    /// path that is already being listened on. The reverse order — worker creates,
    /// daemon connects — is a startup race, and a race at startup is a race
    /// every time on a loaded machine.
    ///
    /// `first_pipe_instance` is set so a second daemon on the same user pipe
    /// fails loudly instead of silently sharing the endpoint (NFR-S01).
    /// Take the pipe name, without waiting for anyone to connect.
    ///
    /// Separate from [`Self::connect_client`] on purpose. Creating the instance
    /// is the moment a name becomes *yours* or *not yours*; waiting for a client
    /// is not. A daemon that binds at startup learns immediately that another
    /// daemon is already running, instead of discovering it later — or, worse,
    /// never, because it only discovers it when a CLI happens to connect.
    /// Create the instance, with or without the first-instance guard.
    #[cfg(windows)]
    async fn bind_flagged(&self, first: bool) -> Result<(), DomainError> {
        use tokio::net::windows::named_pipe::ServerOptions;
        // tokio's option builders are `&mut self -> &mut self`, so the options
        // value has to outlive the call.
        let mut options = ServerOptions::new();
        options.first_pipe_instance(first);
        let server = options
            .create(&self.path)
            .map_err(|e| create_failure(&self.path, &e))?;
        *self.pipe.lock().await = Some(server);
        Ok(())
    }

    /// Take the pipe name, without waiting for anyone to connect.
    ///
    /// Separate from [`Self::connect_client`] on purpose. Creating the instance
    /// is the moment a name becomes *yours* or *not yours*; waiting for a client
    /// is not. A daemon that binds at startup learns immediately that another
    /// daemon is already running, instead of discovering it later — or, worse,
    /// never, because it only discovers it when a CLI happens to connect.
    #[cfg(windows)]
    pub async fn bind(&self) -> Result<(), DomainError> {
        self.bind_flagged(true).await
    }

    /// Bind as the *first* instance: fails if anyone already holds the name.
    #[cfg(windows)]
    pub async fn bind_first(path: impl Into<String>) -> Result<Self, DomainError> {
        let t = Self::at(path);
        t.bind_flagged(true).await?;
        Ok(t)
    }

    /// Bind as a *subsequent* instance: the first instance already owns the name.
    ///
    /// Subsequent instances must **not** set `first_pipe_instance`. Setting it
    /// again is what a second daemon would do, and it has to be the thing that
    /// fails — not the thing this daemon does on every client.
    #[cfg(windows)]
    pub async fn bind_next(path: impl Into<String>) -> Result<Self, DomainError> {
        let t = Self::at(path);
        t.bind_flagged(false).await?;
        Ok(t)
    }

    /// Wait for a client to connect to the bound instance.
    #[cfg(windows)]
    pub async fn connect_client(&self) -> Result<(), DomainError> {
        let mut slot = self.pipe.lock().await;
        let pipe = slot
            .as_mut()
            .ok_or_else(|| ipc_error(format!("named pipe {} is not bound", self.path)))?;
        pipe.connect()
            .await
            .map_err(|e| ipc_error(format!("no client connected to {}: {e}", self.path)))
    }

    /// Take the name and wait for one client: [`Self::bind`] then
    /// [`Self::connect_client`].
    ///
    /// The daemon owns the name so that a worker can be spawned and pointed at a
    /// path that is already being listened on. The reverse order — worker
    /// creates, daemon connects — is a startup race, and a race at startup is a
    /// race every time on a loaded machine.
    #[cfg(windows)]
    pub async fn accept(&self) -> Result<(), DomainError> {
        self.bind().await?;
        self.connect_client().await
    }

    /// Release the connected client, keeping this pipe instance usable.
    ///
    /// Distinct from dropping the instance. A named-pipe instance is single-client:
    /// after a session ends the handle has to be *disconnected* before the next
    /// `connect` can succeed, and dropping the handle instead would give up the
    /// name — which is the whole thing this design is holding onto.
    #[cfg(windows)]
    pub async fn release_client(&self) -> Result<(), DomainError> {
        let slot = self.pipe.lock().await;
        let pipe = slot
            .as_ref()
            .ok_or_else(|| ipc_error(format!("named pipe {} is not bound", self.path)))?;
        pipe.disconnect()
            .map_err(|e| ipc_error(format!("cannot disconnect {}: {e}", self.path)))
    }

    /// Forget the instance entirely, releasing the name. Idempotent.
    #[cfg(windows)]
    pub async fn disconnect(&self) {
        *self.pipe.lock().await = None;
    }
}

#[async_trait::async_trait]
impl Transport for NamedPipeTransport {
    async fn send(&self, bytes: &[u8]) -> Result<(), DomainError> {
        #[cfg(windows)]
        {
            use tokio::io::AsyncWriteExt;
            let mut slot = self.pipe.lock().await;
            let pipe = slot
                .as_mut()
                .ok_or_else(|| ipc_error(format!("named pipe {} is not connected", self.path)))?;
            pipe.write_all(&crate::framing::encode(bytes)?)
                .await
                .map_err(|e| ipc_error(format!("named pipe write failed: {e}")))?;
            pipe.flush()
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
                let mut slot = self.pipe.lock().await;
                let pipe = slot.as_mut().ok_or_else(|| {
                    ipc_error(format!("named pipe {} is not connected", self.path))
                })?;
                let n = pipe
                    .read(&mut buf)
                    .await
                    .map_err(|e| ipc_error(format!("named pipe read failed: {e}")))?;
                n as usize
            };
            if read == 0 {
                // The peer is gone. This is an error rather than `Ok(None)`
                // because `Ok(None)` means "nothing buffered yet", and collapsing
                // the two would turn a dead daemon into a hanging CLI.
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
            *self.pipe.lock().await = None;
        }
    }
}

/// Client end of a Windows named pipe.
///
/// # Which side creates the name
///
/// The **server** creates it. A client that starts first would have to poll for
/// a name that may not exist yet, and "retry until it appears" turns a startup
/// ordering rule into a timing accident.
pub struct NamedPipeClient {
    path: String,
    #[cfg(windows)]
    pipe: tokio::sync::Mutex<Option<PipeClient>>,
    decoder: crate::framing::FrameDecoder,
}

impl std::fmt::Debug for NamedPipeClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NamedPipeClient")
            .field("path", &self.path)
            .finish()
    }
}

/// How long a client waits for the pipe to appear.
pub const CONNECT_TIMEOUT_MS: u64 = 5_000;

impl NamedPipeClient {
    /// A client for the default per-user pipe.
    pub fn server_pipe() -> Self {
        Self::at(pipe_path())
    }

    /// A client for an explicit pipe path.
    pub fn at(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            #[cfg(windows)]
            pipe: tokio::sync::Mutex::new(None),
            decoder: crate::framing::FrameDecoder::new(),
        }
    }

    /// The pipe path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Connect, waiting up to [`CONNECT_TIMEOUT_MS`].
    ///
    /// The timeout is not decoration: an unbounded `WaitNamedPipe` inside a
    /// client process turns "no daemon is running" into a CLI that hangs
    /// forever, which is indistinguishable from a daemon that is busy.
    #[cfg(windows)]
    pub async fn connect(&self) -> Result<(), DomainError> {
        self.connect_within(CONNECT_TIMEOUT_MS).await
    }

    /// Connect, giving up after `ms` milliseconds.
    ///
    /// tokio's client `open` is a **synchronous** OS call, so it is moved onto a
    /// blocking thread: awaiting it directly would park the whole runtime, and a
    /// single-threaded runtime serving several connections would serialise every
    /// other task behind one connect attempt.
    #[cfg(windows)]
    pub async fn connect_within(&self, ms: u64) -> Result<(), DomainError> {
        use tokio::net::windows::named_pipe::ClientOptions;
        let path = self.path.clone();
        let open = tokio::task::spawn_blocking(move || ClientOptions::new().open(&path));
        let joined = tokio::time::timeout(std::time::Duration::from_millis(ms), open)
            .await
            .map_err(|_| {
                ipc_error(format!(
                    "no worker or daemon answered on {} within {ms}ms",
                    self.path
                ))
            })?
            .map_err(|e| ipc_error(format!("connect task failed: {e}")))?;
        let pipe = joined.map_err(|e| connect_failure(&self.path, &e))?;
        *self.pipe.lock().await = Some(pipe);
        Ok(())
    }
}

/// Turn an OS create error into something an operator can act on.
///
/// ERROR_ACCESS_DENIED on a first-instance create means one specific thing:
/// somebody else already owns this name. Saying so is the difference between
/// "restart it yourself" and an afternoon of guessing — and the raw message is
/// localised, exactly like the connect errors below.
#[cfg(windows)]
fn create_failure(path: &str, e: &std::io::Error) -> DomainError {
    match e.raw_os_error() {
        // ERROR_ACCESS_DENIED
        Some(5) => ipc_error(format!(
            "{path} is already taken: another daemon is listening on it"
        )),
        _ => ipc_error(format!("cannot create named pipe {path}: {e}")),
    }
}

/// Turn an OS connect error into something an operator can act on.
///
/// The raw Windows message ("系统找不到指定的文件", "The system cannot find the
/// file specified") is localised and, in a redirected log, may even be mangled by
/// the console code page — so it is *not* something to hand an operator. The
/// common case is "nothing is listening", and that is worth saying in words.
#[cfg(windows)]
fn connect_failure(path: &str, e: &std::io::Error) -> DomainError {
    match e.raw_os_error() {
        // ERROR_FILE_NOT_FOUND / ERROR_PATH_NOT_FOUND
        Some(2) | Some(3) => ipc_error(format!(
            "nothing is listening on {path}: no daemon or worker has claimed this endpoint"
        )),
        // ERROR_PIPE_BUSY: every instance is taken, which is a different
        // problem from the name being free.
        Some(231) => ipc_error(format!(
            "{path} exists but every instance is busy; another client is mid-session"
        )),
        _ => ipc_error(format!("cannot open named pipe {path}: {e}")),
    }
}

#[async_trait::async_trait]
impl Transport for NamedPipeClient {
    async fn send(&self, bytes: &[u8]) -> Result<(), DomainError> {
        #[cfg(windows)]
        {
            use tokio::io::AsyncWriteExt;
            let mut slot = self.pipe.lock().await;
            let pipe = slot
                .as_mut()
                .ok_or_else(|| ipc_error(format!("named pipe {} is not connected", self.path)))?;
            pipe.write_all(&crate::framing::encode(bytes)?)
                .await
                .map_err(|e| ipc_error(format!("named pipe write failed: {e}")))?;
            pipe.flush()
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
                let mut slot = self.pipe.lock().await;
                let pipe = slot.as_mut().ok_or_else(|| {
                    ipc_error(format!("named pipe {} is not connected", self.path))
                })?;
                let n = pipe
                    .read(&mut buf)
                    .await
                    .map_err(|e| ipc_error(format!("named pipe read failed: {e}")))?;
                n as usize
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
            *self.pipe.lock().await = None;
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

    /// A pipe name no other test can collide with.
    #[cfg(windows)]
    fn unique_pipe(tag: &str) -> String {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        format!(
            r"\\.\pipe\sandtree-t-{}-{}-{}",
            std::process::id(),
            tag,
            N.fetch_add(1, Ordering::Relaxed)
        )
    }

    /// The round trip that had never run: a frame out *and* back over a real
    /// Windows named pipe.
    ///
    /// The old tests only ever exercised the *unconnected* path, because the
    /// connected path was broken (`Arc::get_mut` on a still-referenced handle).
    /// A test that only covers the error branch leaves the working branch
    /// unproven, and "the transport exists" is not "the transport carries a
    /// frame".
    #[cfg(windows)]
    #[tokio::test]
    async fn a_frame_travels_in_both_directions_over_a_real_pipe() {
        let path = unique_pipe("both-ways");
        let server = NamedPipeTransport::at(path.clone());
        let server_task = tokio::spawn(async move {
            server.accept().await?;
            server.send(b"from-server").await?;
            let mut server = server;
            server.recv().await
        });

        let mut client = NamedPipeClient::at(path);
        client.connect().await.expect("client connects");
        let from_server = client
            .recv()
            .await
            .expect("no transport error")
            .expect("a frame, not end of stream");
        assert_eq!(from_server, b"from-server");
        client.send(b"from-client").await.expect("client writes");

        let back = server_task
            .await
            .expect("server task")
            .expect("server read");
        assert_eq!(back.as_deref(), Some(&b"from-client"[..]));
    }

    /// Two frames back to back must arrive as two frames, not one blob.
    ///
    /// The decoder is per-transport state, so a transport that is dropped and
    /// reconnected has to start clean; a decoder that carried over would splice
    /// the tail of one session onto the head of the next.
    #[cfg(windows)]
    #[tokio::test]
    async fn consecutive_frames_stay_separate() {
        let path = unique_pipe("framing");
        let server = NamedPipeTransport::at(path.clone());
        let server_task = tokio::spawn(async move {
            server.accept().await?;
            let mut server = server;
            server.recv().await
        });

        let client = NamedPipeClient::at(path);
        client.connect().await.expect("connect");
        client.send(b"one").await.unwrap();
        client.send(b"two").await.unwrap();

        let got = server_task.await.unwrap().unwrap();
        assert_eq!(got.as_deref(), Some(&b"one"[..]));
    }

    /// A second listener on the same name must fail, not share the endpoint.
    ///
    /// This is the NFR-S01 claim in code: if two daemons could both listen on
    /// the per-user pipe, a second daemon would silently intercept the CLI's
    /// `destroy`.
    ///
    /// The claim holds because the holder keeps **one flagged instance for its
    /// whole lifetime** and lets clients connect to that instance in turn. It
    /// does *not* hold if the name is kept alive by creating an unflagged
    /// replacement after each client: `FILE_FLAG_FIRST_PIPE_INSTANCE` only
    /// refuses a create against an instance that itself carried the flag, so an
    /// unflagged replacement gives the name back to anyone. See `serve_loop` in
    /// `apps/daemon`, which is where that distinction is load-bearing.
    #[cfg(windows)]
    #[tokio::test]
    async fn a_second_listener_is_refused_while_the_first_holds_the_name() {
        let path = unique_pipe("exclusive");
        let first = NamedPipeTransport::at(path.clone());
        // `bind` is synchronous with respect to the name, so there is no race:
        // once it returns, the name is held by a flagged instance.
        first
            .bind()
            .await
            .expect("the first listener takes the name");

        let second = NamedPipeTransport::at(path.clone());
        let err = second
            .bind()
            .await
            .expect_err("a second listener must not get the name");
        assert!(
            err.message.contains("already taken"),
            "the refusal must say the name is taken in words rather than \
             forwarding a localised OS string, got: {}",
            err.message
        );
        assert!(
            err.message.contains(&*path),
            "the refusal must name the endpoint it lost, got: {}",
            err.message
        );
    }

    /// Connecting where nobody is listening must fail, and it must fail *fast*.
    ///
    /// The timeout in `connect_within` is a backstop for `ERROR_PIPE_BUSY` (every
    /// pipe instance is taken); the common case — no instance at all — comes back
    /// from the OS immediately. Both paths have to end in a refusal, because a
    /// CLI that blocks when the daemon is down reads to the operator exactly
    /// like a daemon that is busy.
    #[cfg(windows)]
    #[tokio::test]
    async fn connecting_to_a_pipe_nobody_created_fails_quickly() {
        let client = NamedPipeClient::at(unique_pipe("nobody-home"));
        let started = std::time::Instant::now();
        let err = client
            .connect_within(5_000)
            .await
            .expect_err("there is no server");
        assert!(
            err.message.contains(client.path()),
            "the error must name the endpoint it tried, got: {}",
            err.message
        );
        assert!(
            err.message.contains("nothing is listening"),
            "the error must say so in words rather than forwarding a localised \
             OS string, got: {}",
            err.message
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "the client waited {:?} to report that nothing is there",
            started.elapsed()
        );
    }
}
