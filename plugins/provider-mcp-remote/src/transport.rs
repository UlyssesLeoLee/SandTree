//! HTTP transport for the MCP endpoint channel.
//!
//! MCP's streamable HTTP transport is JSON-RPC 2.0 over `POST` to a single
//! endpoint. The server may answer either `application/json` with one message,
//! or `text/event-stream` with one or more `message` frames; both are handled
//! here so the caller always ends up with parsed messages.
//!
//! # Why this crate carries its own transport
//!
//! It looks like duplication next to the git-remote provider's, and it is
//! deliberate. Each optional provider is loaded independently through the
//! plugin host, so a crate shared between two of them would quietly become
//! something every plugin deployment has to ship — the opposite of what
//! `optional/` means in the architecture (ADR-015).
//!
//! # Bounded like the git channel
//!
//! Body size, wall-clock time and status code are all bounded, because the
//! endpoint is inside the sandbox and its response is untrusted input.

use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::Request;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use tokio::time::timeout;

/// Default wall-clock budget for one call.
pub const DEFAULT_TIMEOUT_MS: u64 = 10_000;

/// MCP protocol revision this client speaks.
///
/// Sent as `MCP-Protocol-Version` so a server that supports revisions can
/// answer with one both sides understand instead of guessing.
pub const PROTOCOL_VERSION: &str = "2025-06-18";

/// Header carrying the session identifier a server may assign.
pub const SESSION_HEADER: &str = "mcp-session-id";

/// Why an MCP call failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TransportError {
    /// The endpoint URL did not parse.
    #[error("endpoint {0:?} is not a valid HTTP URI")]
    InvalidUrl(String),
    /// TLS roots could not be loaded from the host trust store.
    #[error("host trust store could not be loaded: {0}")]
    TlsRoots(String),
    /// The call did not complete inside the budget.
    #[error("call exceeded the {0}ms budget")]
    Timeout(u64),
    /// The connection or the HTTP exchange failed.
    #[error("call failed: {0}")]
    Failed(String),
    /// The server answered with a non-2xx status.
    #[error("server answered HTTP {status}")]
    StatusNotSuccess {
        /// Status code.
        status: u16,
    },
    /// The response exceeded the bound.
    #[error("response exceeded the {limit}-byte bound")]
    ResponseTooLarge {
        /// The bound applied.
        limit: usize,
    },
    /// The body was not valid UTF-8.
    #[error("response body was not valid UTF-8")]
    NotUtf8,
    /// The response was neither JSON nor an event stream.
    #[error("unsupported content type {0:?}; expected application/json or text/event-stream")]
    UnsupportedContentType(String),
}

/// One bounded HTTP response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpHttpResponse {
    /// Status code.
    pub status: u16,
    /// Normalized `Content-Type`.
    pub content_type: Option<String>,
    /// Session id the server assigned, if any.
    pub session_id: Option<String>,
    /// Decoded body.
    pub body: String,
}

/// Sends a JSON-RPC message to an MCP endpoint.
#[async_trait::async_trait]
pub trait McpTransport: Send + Sync + std::fmt::Debug {
    /// POST `body` to `url`, refusing to buffer more than `max_bytes`.
    async fn post(
        &self,
        url: &str,
        body: &str,
        session_id: Option<&str>,
        max_bytes: usize,
    ) -> Result<McpHttpResponse, TransportError>;
}

/// The production transport: hyper over a rustls-verified connector.
#[derive(Clone)]
pub struct HyperMcpTransport {
    client: Client<HttpsConnector<HttpConnector>, Full<Bytes>>,
    timeout_ms: u64,
}

impl std::fmt::Debug for HyperMcpTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HyperMcpTransport")
            .field("timeout_ms", &self.timeout_ms)
            .finish_non_exhaustive()
    }
}

impl HyperMcpTransport {
    /// Build with the default budget.
    pub fn new() -> Result<Self, TransportError> {
        Self::with_timeout_ms(DEFAULT_TIMEOUT_MS)
    }

    /// Build with an explicit budget.
    pub fn with_timeout_ms(timeout_ms: u64) -> Result<Self, TransportError> {
        let tls = hyper_rustls::HttpsConnectorBuilder::new()
            .with_native_roots()
            .map_err(|e| TransportError::TlsRoots(e.to_string()))?
            .https_or_http()
            .enable_http1()
            .build();
        Ok(Self {
            client: Client::builder(TokioExecutor::new()).build(tls),
            timeout_ms,
        })
    }
}

#[async_trait::async_trait]
impl McpTransport for HyperMcpTransport {
    async fn post(
        &self,
        url: &str,
        body: &str,
        session_id: Option<&str>,
        max_bytes: usize,
    ) -> Result<McpHttpResponse, TransportError> {
        let uri: hyper::Uri = url
            .parse()
            .map_err(|_| TransportError::InvalidUrl(url.to_string()))?;

        let mut builder = Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json")
            // MCP requires the client to accept both shapes; the server picks.
            .header("accept", "application/json, text/event-stream")
            .header("mcp-protocol-version", PROTOCOL_VERSION)
            .header(
                "user-agent",
                concat!("sandtree-mcp-remote/", env!("CARGO_PKG_VERSION")),
            );
        if let Some(sid) = session_id {
            builder = builder.header(SESSION_HEADER, sid);
        }

        let req = builder
            .body(Full::new(Bytes::from(body.to_string())))
            .map_err(|e| TransportError::Failed(e.to_string()))?;

        let fut = self.client.request(req);
        let resp = match timeout(Duration::from_millis(self.timeout_ms), fut).await {
            Ok(r) => r.map_err(|e| TransportError::Failed(e.to_string()))?,
            Err(_) => return Err(TransportError::Timeout(self.timeout_ms)),
        };

        let status = resp.status().as_u16();
        if !(200..300).contains(&status) {
            return Err(TransportError::StatusNotSuccess { status });
        }

        let header = |name: hyper::header::HeaderName| {
            resp.headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        };
        let content_type = header(hyper::header::CONTENT_TYPE)
            .map(|v| v.split(';').next().unwrap_or(&v).trim().to_string());
        let session_id = header(hyper::header::HeaderName::from_static(SESSION_HEADER));

        let collected = Limited::new(resp.into_body(), max_bytes)
            .collect()
            .await
            .map_err(|_| TransportError::ResponseTooLarge { limit: max_bytes })?
            .to_bytes();

        let body = String::from_utf8(collected.to_vec()).map_err(|_| TransportError::NotUtf8)?;
        Ok(McpHttpResponse {
            status,
            content_type,
            session_id,
            body,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::Response;
    use std::convert::Infallible;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;
    use tokio::sync::oneshot;

    struct TestServer {
        addr: std::net::SocketAddr,
        shutdown: Option<oneshot::Sender<()>>,
        handle: Option<tokio::task::JoinHandle<()>>,
        last_headers: Arc<std::sync::Mutex<Vec<(String, String)>>>,
        last_body: Arc<std::sync::Mutex<String>>,
        hits: Arc<AtomicU32>,
    }

    impl TestServer {
        async fn start<F, Fut>(handler: F) -> Self
        where
            F: Fn(String, String) -> Fut + Send + Sync + 'static,
            Fut: std::future::Future<Output = (u16, Option<String>, Option<String>, String)>
                + Send
                + 'static,
        {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let (tx, rx) = oneshot::channel::<()>();
            let hits = Arc::new(AtomicU32::new(0));
            let hits_in_closure = Arc::clone(&hits);
            let last_headers = Arc::new(std::sync::Mutex::new(Vec::new()));
            let last_body = Arc::new(std::sync::Mutex::new(String::new()));
            let headers_task = Arc::clone(&last_headers);
            let body_task = Arc::clone(&last_body);
            let handler = Arc::new(handler);

            let handle = tokio::spawn(async move {
                let make_service = Arc::new(move |req: Request<hyper::body::Incoming>| {
                    let handler = Arc::clone(&handler);
                    let headers_task = Arc::clone(&headers_task);
                    let body_task = Arc::clone(&body_task);
                    let hits = Arc::clone(&hits_in_closure);
                    async move {
                        hits.fetch_add(1, Ordering::SeqCst);
                        let mut hs: Vec<(String, String)> = req
                            .headers()
                            .iter()
                            .map(|(k, v)| {
                                (k.as_str().to_string(), v.to_str().unwrap_or("").to_string())
                            })
                            .collect();
                        hs.sort();
                        *headers_task.lock().unwrap() = hs;
                        let bytes = req
                            .into_body()
                            .collect()
                            .await
                            .map(|c| c.to_bytes())
                            .unwrap_or_default();
                        *body_task.lock().unwrap() = String::from_utf8_lossy(&bytes).to_string();

                        let (status, content_type, session, body) =
                            handler(String::new(), String::new()).await;
                        let mut b = Response::builder().status(status);
                        if let Some(ct) = content_type {
                            b = b.header("content-type", ct);
                        }
                        if let Some(s) = session {
                            b = b.header(SESSION_HEADER, s);
                        }
                        Ok::<_, Infallible>(b.body(Full::new(Bytes::from(body))).unwrap())
                    }
                });
                // `serve_connection` takes a stream, not a listener, so each
                // accepted connection is served on its own task.
                tokio::select! {
                    _ = async {
                        loop {
                            let Ok((stream, _peer)) = listener.accept().await else { break };
                            let io = hyper_util::rt::TokioIo::new(stream);
                            let make = Arc::clone(&make_service);
                            let svc = hyper::service::service_fn(move |req| (make)(req));
                            tokio::spawn(async move {
                                let _ = hyper::server::conn::http1::Builder::new()
                                    .serve_connection(io, svc).await;
                            });
                        }
                    } => {},
                    _ = rx => {}
                };
            });

            Self {
                addr,
                shutdown: Some(tx),
                handle: Some(handle),
                last_headers,
                last_body,
                hits,
            }
        }

        fn url(&self) -> String {
            format!("http://{}/mcp", self.addr)
        }

        fn header(&self, name: &str) -> Option<String> {
            self.last_headers
                .lock()
                .unwrap()
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.clone())
        }

        fn body(&self) -> String {
            self.last_body.lock().unwrap().clone()
        }

        fn hits(&self) -> u32 {
            self.hits.load(Ordering::SeqCst)
        }
    }

    impl Drop for TestServer {
        fn drop(&mut self) {
            if let Some(tx) = self.shutdown.take() {
                let _ = tx.send(());
            }
            if let Some(h) = self.handle.take() {
                h.abort();
            }
        }
    }

    const REPLY: &str = r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}"#;

    #[tokio::test]
    async fn a_json_rpc_call_travels_over_a_real_socket() {
        let server = TestServer::start(|_b, _h| async {
            (
                200,
                Some("application/json".to_string()),
                Some("sess-1".to_string()),
                REPLY.to_string(),
            )
        })
        .await;
        let t = HyperMcpTransport::new().unwrap();
        let resp = t
            .post(
                &server.url(),
                r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#,
                None,
                65536,
            )
            .await
            .unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.content_type.as_deref(), Some("application/json"));
        // The session id must reach the caller, or every follow-up call is
        // unattributable to the handshake that opened it.
        assert_eq!(resp.session_id.as_deref(), Some("sess-1"));
        assert_eq!(resp.body, REPLY);
        assert_eq!(server.hits(), 1);
    }

    #[tokio::test]
    async fn the_request_carries_the_headers_mcp_requires() {
        let server = TestServer::start(|_b, _h| async {
            (
                200,
                Some("application/json".to_string()),
                None,
                REPLY.to_string(),
            )
        })
        .await;
        let t = HyperMcpTransport::new().unwrap();
        t.post(&server.url(), "{}", Some("sess-9"), 65536)
            .await
            .unwrap();

        // Break by dropping `accept`, and a server that answers with SSE is
        // refused even though the client can read SSE.
        assert_eq!(
            server.header("accept").as_deref(),
            Some("application/json, text/event-stream")
        );
        assert_eq!(
            server.header("content-type").as_deref(),
            Some("application/json")
        );
        assert_eq!(
            server.header("mcp-protocol-version").as_deref(),
            Some(PROTOCOL_VERSION)
        );
        // The session id must be echoed back on a follow-up call.
        assert_eq!(server.header(SESSION_HEADER).as_deref(), Some("sess-9"));
        assert_eq!(server.body(), "{}");
    }

    #[tokio::test]
    async fn an_event_stream_response_is_returned_verbatim_for_the_sse_reader() {
        let server = TestServer::start(|_b, _h| async {
            (
                200,
                Some("text/event-stream; charset=utf-8".to_string()),
                None,
                "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n"
                    .to_string(),
            )
        })
        .await;
        let t = HyperMcpTransport::new().unwrap();
        let resp = t.post(&server.url(), "{}", None, 65536).await.unwrap();
        // Media type normalized so the caller compares it against a bare token.
        assert_eq!(resp.content_type.as_deref(), Some("text/event-stream"));
        assert!(resp.body.starts_with("event: message"));
    }

    #[tokio::test]
    async fn a_non_success_status_is_reported_rather_than_parsed() {
        let server = TestServer::start(|_b, _h| async {
            (
                403,
                Some("text/plain".to_string()),
                None,
                "forbidden".to_string(),
            )
        })
        .await;
        let t = HyperMcpTransport::new().unwrap();
        assert_eq!(
            t.post(&server.url(), "{}", None, 1024).await.unwrap_err(),
            TransportError::StatusNotSuccess { status: 403 }
        );
    }

    #[tokio::test]
    async fn an_oversized_body_is_cut_off_rather_than_buffered() {
        let server =
            TestServer::start(|_b, _h| async { (200, None, None, "x".repeat(50_000)) }).await;
        let t = HyperMcpTransport::new().unwrap();
        assert_eq!(
            t.post(&server.url(), "{}", None, 1024).await.unwrap_err(),
            TransportError::ResponseTooLarge { limit: 1024 }
        );
    }

    #[tokio::test]
    async fn a_slow_endpoint_times_out_instead_of_hanging_the_observation() {
        let server = TestServer::start(|_b, _h| async {
            tokio::time::sleep(Duration::from_secs(30)).await;
            (200, None, None, String::new())
        })
        .await;
        let t = HyperMcpTransport::with_timeout_ms(200).unwrap();
        assert_eq!(
            t.post(&server.url(), "{}", None, 1024).await.unwrap_err(),
            TransportError::Timeout(200)
        );
    }

    #[tokio::test]
    async fn a_bad_endpoint_url_is_refused_before_any_socket_is_opened() {
        let t = HyperMcpTransport::new().unwrap();
        assert!(matches!(
            t.post("not a url", "{}", None, 1024).await,
            Err(TransportError::InvalidUrl(_))
        ));
    }
}
