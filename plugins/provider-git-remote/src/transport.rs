//! HTTP transport for the git remote channel.
//!
//! Bounded on every axis that a hostile endpoint controls: response size,
//! wall-clock time, and status code. A sandbox publishes this endpoint, so
//! "the server sent something surprising" is an expected case, not an
//! exceptional one.
//!
//! # TLS
//!
//! `https://` is verified against the **host trust store**
//! (`rustls-native-certs`), which is what a private CA installed on the
//! operator's machine looks like. Certificate verification is never disabled;
//! there is no insecure escape hatch, because an unauthenticated fetch is
//! indistinguishable from the sandbox choosing what we see.
//!
//! `http://` is still accepted. The endpoint lives inside the sandbox network,
//! and plain HTTP there is normal — but it is still scoped by
//! `net:connect:<host:port>` and never widened (NFR-S02).

use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::Request;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use tokio::time::timeout;

/// Default wall-clock budget for one fetch.
pub const DEFAULT_TIMEOUT_MS: u64 = 10_000;

/// Why a fetch failed.
///
/// Every variant names a cause. Nothing here degrades into a generic "network
/// error", because that is indistinguishable from "the sandbox is unreachable"
/// and both mean something different to an operator (RD §9).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TransportError {
    /// The URL did not parse as an HTTP URI.
    #[error("URL {0:?} is not a valid HTTP URI")]
    InvalidUrl(String),
    /// TLS roots could not be loaded from the host trust store.
    #[error("host trust store could not be loaded: {0}")]
    TlsRoots(String),
    /// The request did not complete inside the budget.
    #[error("fetch exceeded the {0}ms budget")]
    Timeout(u64),
    /// The connection or the HTTP exchange failed.
    #[error("fetch failed: {0}")]
    Failed(String),
    /// The server answered with a non-2xx status.
    #[error("server answered HTTP {status}")]
    StatusNotSuccess {
        /// Status code.
        status: u16,
    },
    /// The response exceeded the bound and was cut off.
    #[error("response exceeded the {limit}-byte bound")]
    ResponseTooLarge {
        /// The bound that was applied.
        limit: usize,
    },
    /// The body was not valid UTF-8.
    #[error("response body was not valid UTF-8")]
    NotUtf8,
}

/// One bounded HTTP response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    /// Status code.
    pub status: u16,
    /// `Content-Type`, when the server sent one.
    pub content_type: Option<String>,
    /// Decoded body.
    pub body: String,
}

/// Fetches a URL over HTTP(S).
#[async_trait::async_trait]
pub trait RemoteTransport: Send + Sync + std::fmt::Debug {
    /// GET `url`, refusing to buffer more than `max_bytes`.
    async fn get(&self, url: &str, max_bytes: usize) -> Result<HttpResponse, TransportError>;
}

/// The production transport: hyper over a rustls-verified connector.
#[derive(Clone)]
pub struct HyperTransport {
    client: Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>,
    timeout_ms: u64,
}

impl std::fmt::Debug for HyperTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HyperTransport")
            .field("timeout_ms", &self.timeout_ms)
            .finish_non_exhaustive()
    }
}

impl HyperTransport {
    /// Build a transport with the default budget.
    pub fn new() -> Result<Self, TransportError> {
        Self::with_timeout_ms(DEFAULT_TIMEOUT_MS)
    }

    /// Build a transport with an explicit budget.
    pub fn with_timeout_ms(timeout_ms: u64) -> Result<Self, TransportError> {
        // Verification is always on. `https_or_http` only decides whether a
        // plaintext endpoint is *reachable*, never whether TLS is checked.
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

    /// Budget in milliseconds.
    pub fn timeout_ms(&self) -> u64 {
        self.timeout_ms
    }
}

#[async_trait::async_trait]
impl RemoteTransport for HyperTransport {
    async fn get(&self, url: &str, max_bytes: usize) -> Result<HttpResponse, TransportError> {
        let uri: hyper::Uri = url
            .parse()
            .map_err(|_| TransportError::InvalidUrl(url.to_string()))?;

        let req = Request::builder()
            .method("GET")
            .uri(uri)
            // git-upload-pack over smart HTTP is a plain advertisement GET.
            // Not sending `Git-Protocol` keeps the server on v0, which is the
            // only version this channel reads (see `advertisement`).
            .header(
                "User-Agent",
                concat!("sandtree-git-remote/", env!("CARGO_PKG_VERSION")),
            )
            .header("Accept", "application/x-git-upload-pack-advertisement")
            .body(Full::new(Bytes::new()))
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

        let content_type = resp
            .headers()
            .get(hyper::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.split(';').next().unwrap_or(v).trim().to_string());

        // `Limited` stops buffering at the bound instead of reading the whole
        // body and then discovering it was too large.
        let collected = Limited::new(resp.into_body(), max_bytes)
            .collect()
            .await
            .map_err(|_| TransportError::ResponseTooLarge { limit: max_bytes })?
            .to_bytes();

        let body = String::from_utf8(collected.to_vec()).map_err(|_| TransportError::NotUtf8)?;
        Ok(HttpResponse {
            status,
            content_type,
            body,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::Infallible;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;
    use tokio::sync::oneshot;

    /// A real HTTP server on loopback. Used so the transport is exercised
    /// end to end rather than against a stubbed client.
    struct TestServer {
        addr: std::net::SocketAddr,
        shutdown: Option<oneshot::Sender<()>>,
        handle: Option<tokio::task::JoinHandle<()>>,
        hits: Arc<AtomicU32>,
    }

    impl TestServer {
        /// Start a server. The handler returns `(status, headers, body)`; the
        /// header list is a Vec rather than an optional content type because the
        /// redirect test needs to set `Location`.
        async fn start<F, Fut>(handler: F) -> Self
        where
            F: Fn(String) -> Fut + Send + Sync + 'static,
            Fut:
                std::future::Future<Output = (u16, Vec<(String, String)>, String)> + Send + 'static,
        {
            let (tx, rx) = oneshot::channel::<()>();
            let hits = Arc::new(AtomicU32::new(0));
            let hits_in_closure = Arc::clone(&hits);
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let handler = Arc::new(handler);
            let make_service = Arc::new(move |req: Request<hyper::body::Incoming>| {
                let handler = Arc::clone(&handler);
                let hits = Arc::clone(&hits_in_closure);
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    let url = req.uri().to_string();
                    let (status, headers, body) = handler(url).await;
                    let mut b = Response::builder().status(status);
                    for (name, value) in headers {
                        b = b.header(name, value);
                    }
                    Ok::<_, Infallible>(b.body(Full::new(Bytes::from(body))).unwrap())
                }
            });

            let handle = tokio::spawn(async move {
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
                hits,
            }
        }

        fn url(&self, path: &str) -> String {
            format!("http://{}{}", self.addr, path)
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

    use hyper::Response;

    #[tokio::test]
    async fn a_real_server_is_fetched_over_a_real_socket() {
        let server = TestServer::start(|_url| async {
            (
                200,
                vec![(
                    "content-type".into(),
                    "application/x-git-upload-pack-advertisement".into(),
                )],
                crate::pktline::encode("# service=git-upload-pack\n").unwrap()
                    + &crate::pktline::encode_flush(),
            )
        })
        .await;
        let t = HyperTransport::new().unwrap();
        let resp = t
            .get(&server.url("/repo.git/info/refs"), 64 * 1024)
            .await
            .unwrap();
        assert_eq!(resp.status, 200);
        assert!(resp.body.starts_with("001e# service=git-upload-pack"));
        // The media type is normalized so callers compare it against a bare
        // token; break by keeping the `; charset=...` suffix and every such
        // comparison starts failing.
        assert_eq!(
            resp.content_type.as_deref(),
            Some("application/x-git-upload-pack-advertisement")
        );
        assert_eq!(server.hits(), 1);
    }

    #[tokio::test]
    async fn a_content_type_with_parameters_is_normalized() {
        let server = TestServer::start(|_url| async {
            (
                200,
                vec![(
                    "content-type".into(),
                    "application/x-git-upload-pack-advertisement; charset=utf-8".into(),
                )],
                "ok".to_string(),
            )
        })
        .await;
        let t = HyperTransport::new().unwrap();
        let resp = t.get(&server.url("/x"), 1024).await.unwrap();
        assert_eq!(
            resp.content_type.as_deref(),
            Some("application/x-git-upload-pack-advertisement")
        );
    }

    #[tokio::test]
    async fn a_redirect_is_never_followed_and_never_reaches_its_target() {
        // The SSRF test. A sandbox controls this endpoint, so a `302` pointing
        // at `169.254.169.254` (or anything else outside the granted
        // `net:connect:<host:port>` scope) is the obvious way to make the host
        // fetch something the operator never authorised.
        //
        // This asserts the property from the *outside*: the redirect target is
        // a second real server that would happily answer, and the assertion is
        // that it is never contacted. Asserting only on the returned error
        // would pass even if the client followed the redirect and then failed
        // for an unrelated reason.
        let target = TestServer::start(|_url| async {
            (
                200,
                vec![],
                crate::pktline::encode("# service=git-upload-pack\n").unwrap(),
            )
        })
        .await;
        let target_url = target.url("/stolen");

        let server = TestServer::start(move |_url| {
            let location = target_url.clone();
            async move { (302, vec![("location".into(), location)], "".to_string()) }
        })
        .await;

        let t = HyperTransport::new().unwrap();
        let result = t.get(&server.url("/repo.git/info/refs"), 64 * 1024).await;

        // No redirect is ever treated as a successful read.
        assert!(
            result.is_err(),
            "a 3xx must not be reported as a fetched advertisement: {result:?}"
        );
        assert_eq!(
            result.unwrap_err(),
            TransportError::StatusNotSuccess { status: 302 }
        );
        // And the decisive one: the redirect target was never reached.
        assert_eq!(
            target.hits(),
            0,
            "the client followed a redirect to {} -- every endpoint scope \
             in this design is bypassable by a 302",
            target.url("/stolen")
        );
    }

    #[tokio::test]
    async fn a_missing_content_type_is_reported_as_absent_not_as_empty_string() {
        let server = TestServer::start(|_url| async { (200, vec![], "ok".to_string()) }).await;
        let t = HyperTransport::new().unwrap();
        let resp = t.get(&server.url("/x"), 1024).await.unwrap();
        assert_eq!(resp.content_type, None);
    }

    #[tokio::test]
    async fn a_non_success_status_is_reported_rather_than_parsed() {
        // Break by passing the body through anyway, and a 500 page gets fed
        // to the pkt-line parser as if it were an advertisement.
        let server = TestServer::start(|_url| async { (500, vec![], "boom".to_string()) }).await;
        let t = HyperTransport::new().unwrap();
        assert_eq!(
            t.get(&server.url("/x"), 1024).await.unwrap_err(),
            TransportError::StatusNotSuccess { status: 500 }
        );
    }

    #[tokio::test]
    async fn an_oversized_body_is_cut_off_rather_than_buffered() {
        // A sandbox controls this response; without the bound one crafted
        // advertisement can allocate without limit.
        let server = TestServer::start(|_url| async { (200, vec![], "x".repeat(100_000)) }).await;
        let t = HyperTransport::new().unwrap();
        assert_eq!(
            t.get(&server.url("/x"), 1024).await.unwrap_err(),
            TransportError::ResponseTooLarge { limit: 1024 }
        );
    }

    #[tokio::test]
    async fn a_slow_server_times_out_instead_of_hanging_the_observation() {
        // Break by dropping the timeout, and one unresponsive sandbox hangs
        // the whole observation plane.
        let server = TestServer::start(|_url| async {
            tokio::time::sleep(Duration::from_secs(30)).await;
            (200, vec![], String::new())
        })
        .await;
        let t = HyperTransport::with_timeout_ms(200).unwrap();
        assert_eq!(
            t.get(&server.url("/x"), 1024).await.unwrap_err(),
            TransportError::Timeout(200)
        );
    }

    #[tokio::test]
    async fn an_unparseable_url_is_refused_before_any_socket_is_opened() {
        let t = HyperTransport::new().unwrap();
        assert!(matches!(
            t.get("not a url", 1024).await,
            Err(TransportError::InvalidUrl(_))
        ));
    }

    #[tokio::test]
    async fn a_connection_refused_is_named_as_a_failure_not_as_empty_content() {
        // Bind then drop a listener: the port is genuinely unbound, so the
        // connection is refused rather than silently dropped by the firewall.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        // The caller must see a failure, never an empty body it could mistake
        // for an empty repository.
        let t = HyperTransport::with_timeout_ms(3000).unwrap();
        match t.get(&format!("http://{addr}/x"), 1024).await {
            Err(TransportError::Failed(_)) => {}
            other => panic!("expected a named connection failure, got {other:?}"),
        }
    }
}
