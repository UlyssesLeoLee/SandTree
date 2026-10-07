//! End-to-end test: a real MCP server implementing the real conversation,
//! driven by the real transport through the real provider path.
//!
//! The server here is a genuine MCP implementation of the three messages the
//! channel speaks — `initialize`, `notifications/initialized`, `tools/list` —
//! not a canned body. It correlates on the request `id`, answers an
//! `Accept`-negotiated JSON body, and assigns a session id the client must echo
//! back. Break the correlation or the session handling and this fails.

use std::convert::Infallible;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use sandtree_model::capability::{Capability, CapabilitySet};
use sandtree_model::id::ResourceId;
use sandtree_observation_model::{
    ObservationDomain, ObservationHealth, ObservationMode, ObservationRequest, TrustLevel,
};
use sandtree_policy::acquire::{PenetrationVerdict, RefusalReason};
use sandtree_provider_mcp_remote::{McpRemoteProvider, DOMAIN};
use sandtree_sdk::ports::ObservationProvider;
use serde_json::{json, Value as Json};

struct McpServer {
    port: u16,
    hits: Arc<AtomicU32>,
    methods: Arc<std::sync::Mutex<Vec<String>>>,
    sessions_seen: Arc<std::sync::Mutex<Vec<Option<String>>>>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    handle: Option<tokio::task::JoinHandle<()>>,
}

impl McpServer {
    /// Start a server. `fail_with` makes it answer every request with that
    /// JSON-RPC error instead, so failure paths can be exercised for real.
    async fn start(fail_with: Option<(i64, String)>) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let hits = Arc::new(AtomicU32::new(0));
        let hits_in_closure = Arc::clone(&hits);
        let methods = Arc::new(std::sync::Mutex::new(Vec::new()));
        let methods_task = Arc::clone(&methods);
        let sessions = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sessions_task = Arc::clone(&sessions);
        let fail = Arc::new(fail_with);

        let make_service = Arc::new(move |req: Request<Incoming>| {
            let hits = Arc::clone(&hits_in_closure);
            let methods = Arc::clone(&methods_task);
            let sessions = Arc::clone(&sessions_task);
            let fail = Arc::clone(&fail);
            async move {
                hits.fetch_add(1, Ordering::SeqCst);
                let session = req
                    .headers()
                    .get("mcp-session-id")
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string);
                sessions.lock().unwrap().push(session);

                let bytes = req
                    .into_body()
                    .collect()
                    .await
                    .map(|c| c.to_bytes())
                    .unwrap_or_default();
                let msg: Json = serde_json::from_slice(&bytes).unwrap_or(Json::Null);
                let method = msg
                    .get("method")
                    .and_then(|m| m.as_str())
                    .unwrap_or("")
                    .to_string();
                methods.lock().unwrap().push(method.clone());
                let id = msg.get("id").and_then(|i| i.as_u64());

                // A notification carries no id and is answered 202 with no body.
                let Some(id) = id else {
                    return Ok::<_, Infallible>(
                        Response::builder()
                            .status(StatusCode::ACCEPTED)
                            .body(Full::new(Bytes::new()))
                            .unwrap(),
                    );
                };

                let body = if let Some((code, message)) = fail.as_ref() {
                    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
                        .to_string()
                } else {
                    match method.as_str() {
                        "initialize" => json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": {
                                "protocolVersion": "2025-06-18",
                                "capabilities": {"tools": {"listChanged": true}},
                                "serverInfo": {"name": "sandbox-agent", "version": "0.4.1"}
                            }
                        })
                        .to_string(),
                        "tools/list" => json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": {
                                "tools": [
                                    {"name": "zeta",  "description": "later", "inputSchema": {"type": "object"}},
                                    {"name": "alpha", "description": "first",  "inputSchema": {"type": "object"}}
                                ]
                            }
                        })
                        .to_string(),
                        other => json!({
                            "jsonrpc": "2.0", "id": id,
                            "error": {"code": -32601, "message": format!("Method not found: {other}")}
                        })
                        .to_string(),
                    }
                };

                Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header("content-type", "application/json")
                    .header("mcp-session-id", "sess-e2e-1")
                    .body(Full::new(Bytes::from(body)))
                    .unwrap())
            }
        });

        let handle = tokio::spawn(async move {
            tokio::select! {
                _ = async {
                    loop {
                        let Ok((stream, _)) = listener.accept().await else { break };
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
            port,
            hits,
            methods,
            sessions_seen: sessions,
            shutdown: Some(tx),
            handle: Some(handle),
        }
    }

    fn methods(&self) -> Vec<String> {
        self.methods.lock().unwrap().clone()
    }

    fn sessions(&self) -> Vec<Option<String>> {
        self.sessions_seen.lock().unwrap().clone()
    }

    fn hits(&self) -> u32 {
        self.hits.load(Ordering::SeqCst)
    }
}

impl Drop for McpServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(h) = self.handle.take() {
            h.abort();
        }
    }
}

fn resource() -> ResourceId {
    ResourceId::derive(&["sbx-e2e-mcp"])
}

fn request(domains: Vec<ObservationDomain>) -> ObservationRequest {
    ObservationRequest::new(resource(), domains)
}

async fn provider_for(
    server: &McpServer,
    verdict: Option<PenetrationVerdict>,
    grant: bool,
) -> Arc<McpRemoteProvider> {
    let p = McpRemoteProvider::new().expect("TLS roots must load from the host store");
    p.register_endpoint(
        resource(),
        &format!("http://127.0.0.1:{}/mcp", server.port),
        verdict.unwrap_or(PenetrationVerdict::Refused {
            domain: DOMAIN,
            reason: RefusalReason::NoHostChannel,
        }),
    )
    .await
    .unwrap();
    if grant {
        p.set_granted(CapabilitySet::from_iter_caps([Capability::parse(
            &format!("net:connect:127.0.0.1:{}", server.port),
        )
        .unwrap()]))
            .await;
    }
    p
}

#[tokio::test]
async fn a_sandbox_published_endpoint_is_called_over_http_and_read() {
    let server = McpServer::start(None).await;
    let p = provider_for(&server, None, true).await;

    let snap = p.observe(&request(vec![DOMAIN])).await.unwrap();

    assert_eq!(snap.health, ObservationHealth::Healthy);
    assert_eq!(snap.mode, ObservationMode::Probe);
    assert_eq!(snap.weakest_trust(), Some(TrustLevel::GuestProbe));
    assert!(!snap.is_security_authoritative());

    let sys = &snap.get(DOMAIN).unwrap().value;
    assert_eq!(sys["server_name"], json!("sandbox-agent"));
    assert_eq!(sys["protocol_version"], json!("2025-06-18"));
    assert_eq!(sys["tool_names"], json!(["alpha", "zeta"]));
    assert_eq!(sys["tool_count"], json!(2));

    // The conversation is the one MCP requires, in order.
    assert_eq!(
        server.methods(),
        vec![
            "initialize".to_string(),
            "notifications/initialized".to_string(),
            "tools/list".to_string()
        ]
    );
    // The session id assigned during initialize is echoed on the follow-up.
    let sessions = server.sessions();
    assert_eq!(sessions[0], None, "the handshake carries no session id yet");
    assert_eq!(
        sessions[2].as_deref(),
        Some("sess-e2e-1"),
        "tools/list must carry the session the handshake was given"
    );
}

#[tokio::test]
async fn a_server_error_is_degraded_and_never_an_empty_tool_list() {
    // Break by treating a JSON-RPC error as a successful empty result, and a
    // sandbox that refuses every call is reported as exposing zero tools.
    let server = McpServer::start(Some((-32601, "Method not found".to_string()))).await;
    let p = provider_for(&server, None, true).await;

    let snap = p.observe(&request(vec![DOMAIN])).await.unwrap();
    assert_eq!(snap.health, ObservationHealth::Degraded);
    assert!(snap.values.is_empty());
    assert!(
        snap.warnings[0].contains("Method not found"),
        "the server's own message must reach the snapshot: {:?}",
        snap.warnings
    );
}

#[tokio::test]
async fn a_penetrable_sandbox_is_never_contacted() {
    let server = McpServer::start(None).await;
    let p = provider_for(
        &server,
        Some(PenetrationVerdict::Allowed {
            domain: DOMAIN,
            mode: ObservationMode::Native,
        }),
        true,
    )
    .await;

    let snap = p.observe(&request(vec![DOMAIN])).await.unwrap();
    assert_eq!(snap.health, ObservationHealth::Unavailable);
    assert!(snap.values.is_empty());
    assert_eq!(
        server.hits(),
        0,
        "the network must not be touched when penetration was possible"
    );
}

#[tokio::test]
async fn an_endpoint_without_a_grant_is_never_contacted() {
    let server = McpServer::start(None).await;
    let p = provider_for(&server, None, false).await;

    let snap = p.observe(&request(vec![DOMAIN])).await.unwrap();
    assert_eq!(snap.health, ObservationHealth::Unavailable);
    assert_eq!(
        server.hits(),
        0,
        "denied acquisition must not open a socket"
    );
}

#[tokio::test]
async fn an_unreachable_endpoint_yields_unavailable_not_an_empty_inventory() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let p = McpRemoteProvider::new().unwrap();
    p.register_endpoint(
        resource(),
        &format!("http://127.0.0.1:{port}/mcp"),
        PenetrationVerdict::Refused {
            domain: DOMAIN,
            reason: RefusalReason::NoHostChannel,
        },
    )
    .await
    .unwrap();
    p.set_granted(CapabilitySet::from_iter_caps([Capability::parse(
        &format!("net:connect:127.0.0.1:{port}"),
    )
    .unwrap()]))
        .await;

    let snap = p.observe(&request(vec![DOMAIN])).await.unwrap();
    assert_eq!(snap.health, ObservationHealth::Degraded);
    assert!(snap.values.is_empty());
    assert!(
        sandtree_policy::TrustPolicy::new()
            .check_destructive_precondition(&snap)
            .is_err(),
        "an unreachable endpoint may never be evidence that the sandbox exposes nothing"
    );
}

#[tokio::test]
async fn no_mcp_tool_is_ever_invoked() {
    // The channel is `initialize` + `tools/list` and nothing else. Calling a
    // tool would execute sandbox-chosen code with sandbox-chosen arguments and
    // return its output as observation.
    let server = McpServer::start(None).await;
    let p = provider_for(&server, None, true).await;
    p.observe(&request(vec![DOMAIN])).await.unwrap();

    for method in server.methods() {
        assert!(
            method != "tools/call",
            "the channel must never call a tool, saw {method}"
        );
    }
}

#[tokio::test]
async fn the_evidence_hash_moves_when_the_tool_inventory_changes() {
    let first = McpServer::start(None).await;
    let p1 = provider_for(&first, None, true).await;
    let snap1 = p1.observe(&request(vec![DOMAIN])).await.unwrap();
    let hash1 = snap1.get(DOMAIN).unwrap().provenance.evidence_hash.clone();
    assert!(hash1.is_some(), "an inventory must carry an evidence hash");

    // Same server read again: stable.
    let snap1b = p1.observe(&request(vec![DOMAIN])).await.unwrap();
    assert_eq!(
        snap1b.get(DOMAIN).unwrap().provenance.evidence_hash,
        hash1,
        "an unchanged inventory must hash identically"
    );

    // A server whose tools differ must hash differently.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let make_service = {
        let make = Arc::new(move |req: Request<Incoming>| async move {
            let bytes = req
                .into_body()
                .collect()
                .await
                .map(|c| c.to_bytes())
                .unwrap_or_default();
            let msg: Json = serde_json::from_slice(&bytes).unwrap_or(Json::Null);
            let method = msg
                .get("method")
                .and_then(|m| m.as_str())
                .unwrap_or("")
                .to_string();
            let Some(id) = msg.get("id").and_then(|i| i.as_u64()) else {
                return Ok::<_, Infallible>(
                    Response::builder()
                        .status(StatusCode::ACCEPTED)
                        .body(Full::new(Bytes::new()))
                        .unwrap(),
                );
            };
            let body = match method.as_str() {
                "initialize" => json!({
                    "jsonrpc": "2.0", "id": id,
                    "result": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "sandbox-agent", "version": "0.4.1"}
                    }
                }),
                // Same name, different schema: a hash over names alone would
                // still match.
                "tools/list" => json!({
                    "jsonrpc": "2.0", "id": id,
                    "result": {"tools": [
                        {"name": "zeta",  "inputSchema": {"type": "object"}},
                        {"name": "alpha", "inputSchema": {"type": "object", "properties": {"x": {}}}}
                    ]}
                }),
                _ => json!({"jsonrpc": "2.0", "id": id, "result": {}}),
            }
            .to_string();
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/json")
                .body(Full::new(Bytes::from(body)))
                .unwrap())
        });
        make
    };
    let handle = tokio::spawn(async move {
        tokio::select! {
            _ = async {
                loop {
                    let Ok((stream, _)) = listener.accept().await else { break };
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

    let p2 = McpRemoteProvider::new().unwrap();
    p2.register_endpoint(
        resource(),
        &format!("http://127.0.0.1:{port}/mcp"),
        PenetrationVerdict::Refused {
            domain: DOMAIN,
            reason: RefusalReason::NoHostChannel,
        },
    )
    .await
    .unwrap();
    p2.set_granted(CapabilitySet::from_iter_caps([Capability::parse(
        &format!("net:connect:127.0.0.1:{port}"),
    )
    .unwrap()]))
        .await;

    let snap2 = p2.observe(&request(vec![DOMAIN])).await.unwrap();
    assert_eq!(snap2.health, ObservationHealth::Healthy);
    assert_ne!(
        snap2.get(DOMAIN).unwrap().provenance.evidence_hash,
        hash1,
        "a rewritten tool schema must change the evidence hash"
    );

    let _ = tx.send(());
    handle.abort();
}
