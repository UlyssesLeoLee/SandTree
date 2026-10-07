//! End-to-end test: a real HTTP server serving a real git ref advertisement,
//! fetched by the real transport through the real provider path.
//!
//! Everything below the policy gate is production code — `HyperTransport`,
//! the pkt-line decoder, the advertisement parser, the snapshot assembly. The
//! only thing replaced is the TLS-verified connector's *destination*, which
//! points at a loopback listener instead of a sandbox.
//!
//! This is what distinguishes "the provider compiles" from "the channel works".

use std::convert::Infallible;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use sandtree_model::capability::{Capability, CapabilitySet};
use sandtree_model::id::ResourceId;
use sandtree_observation_model::{
    ObservationDomain, ObservationHealth, ObservationMode, ObservationRequest, TrustLevel,
};
use sandtree_policy::acquire::{PenetrationVerdict, RefusalReason};
use sandtree_provider_git_remote::pktline;
use sandtree_provider_git_remote::{GitRemoteProvider, DOMAIN};
use sandtree_sdk::ports::ObservationProvider;

/// A real advertisement, byte-shaped exactly like `git-http-backend`'s.
fn advertisement() -> String {
    let mut s = pktline::encode("# service=git-upload-pack\n").unwrap();
    s.push_str(&pktline::encode_flush());
    s.push_str(
        &pktline::encode(concat!(
            "0000000000000000000000000000000000000000 HEAD\0",
            "symref=HEAD:refs/heads/main agent=git/2.45.0 object-format=sha1\n"
        ))
        .unwrap(),
    );
    s.push_str(
        &pktline::encode("a1b2c3d4e5f60718293a4b5c6d7e8f9012345678 refs/heads/main\n").unwrap(),
    );
    s.push_str(
        &pktline::encode("0f1e2d3c4b5a69788796a5b4c3d2e1f001234567 refs/heads/feature\n").unwrap(),
    );
    s.push_str(
        &pktline::encode("1122334455667788990011223344556677889900 refs/tags/v1.0\n").unwrap(),
    );
    s.push_str(
        &pktline::encode("2233445566778899001122334455667788990011 refs/tags/v1.0^{}\n").unwrap(),
    );
    s.push_str(&pktline::encode_flush());
    s
}

struct GitServer {
    port: u16,
    hits: Arc<AtomicU32>,
    seen_paths: Arc<std::sync::Mutex<Vec<String>>>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    handle: Option<tokio::task::JoinHandle<()>>,
}

impl GitServer {
    async fn start(body: String) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let hits = Arc::new(AtomicU32::new(0));
        let hits_in_closure = Arc::clone(&hits);
        let seen_paths = Arc::new(std::sync::Mutex::new(Vec::new()));
        let paths = Arc::clone(&seen_paths);
        let body = Arc::new(body);

        let make_service = Arc::new(move |req: Request<Incoming>| {
            let hits = Arc::clone(&hits_in_closure);
            let paths = Arc::clone(&paths);
            let body = Arc::clone(&body);
            async move {
                hits.fetch_add(1, Ordering::SeqCst);
                paths.lock().unwrap().push(req.uri().to_string());
                Ok::<_, Infallible>(
                    Response::builder()
                        .status(StatusCode::OK)
                        .header(
                            "content-type",
                            "application/x-git-upload-pack-advertisement",
                        )
                        .body(Full::new(Bytes::from(body.as_str().to_string())))
                        .unwrap(),
                )
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
            seen_paths,
            shutdown: Some(tx),
            handle: Some(handle),
        }
    }

    fn hits(&self) -> u32 {
        self.hits.load(Ordering::SeqCst)
    }

    fn paths(&self) -> Vec<String> {
        self.seen_paths.lock().unwrap().clone()
    }
}

impl Drop for GitServer {
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
    ResourceId::derive(&["sbx-e2e-git"])
}

fn request(domains: Vec<ObservationDomain>) -> ObservationRequest {
    ObservationRequest::new(resource(), domains)
}

/// Build a provider pointed at `server`, with the endpoint and grant in place.
async fn provider_for(server: &GitServer) -> Arc<GitRemoteProvider> {
    let p = GitRemoteProvider::new().expect("TLS roots must load from the host store");
    p.register_endpoint(
        resource(),
        &format!("http://127.0.0.1:{}/workspace.git", server.port),
        PenetrationVerdict::Refused {
            domain: DOMAIN,
            reason: RefusalReason::IsolationNotPermitted,
        },
    )
    .await
    .unwrap();
    p.set_granted(CapabilitySet::from_iter_caps([Capability::parse(
        &format!("net:connect:127.0.0.1:{}", server.port),
    )
    .unwrap()]))
        .await;
    p
}

#[tokio::test]
async fn a_sandbox_published_remote_is_fetched_over_http_and_read() {
    // The whole point of the channel, end to end over a real socket.
    let server = GitServer::start(advertisement()).await;
    let p = provider_for(&server).await;

    let snap = p.observe(&request(vec![DOMAIN])).await.unwrap();

    assert_eq!(snap.health, ObservationHealth::Healthy);
    assert_eq!(snap.mode, ObservationMode::Probe);
    // The ceiling, checked against the model rather than restated.
    assert_eq!(snap.weakest_trust(), Some(TrustLevel::GuestProbe));
    assert!(!snap.is_security_authoritative());

    let fs = &snap.get(DOMAIN).unwrap().value;
    assert_eq!(fs["head_target"], serde_json::json!("refs/heads/main"));
    assert_eq!(
        fs["branches"],
        serde_json::json!(["refs/heads/feature", "refs/heads/main"])
    );
    assert_eq!(fs["tags"], serde_json::json!(["refs/tags/v1.0"]));
    assert_eq!(
        fs["refs"][2]["object_id"],
        serde_json::json!("a1b2c3d4e5f60718293a4b5c6d7e8f9012345678")
    );
    // The evidence hash lives in the *provenance*, not in the value. Asserting
    // `fs["evidence_hash"]` here would be vacuously true forever, because that
    // key never exists in the value.
    let evidence = snap.get(DOMAIN).unwrap().provenance.evidence_hash.clone();
    assert!(
        evidence.as_deref().is_some_and(|h| h.len() == 64),
        "a real BLAKE3 hex digest must be attached, got {evidence:?}"
    );

    // Exactly one request, to the documented URL.
    assert_eq!(server.hits(), 1);
    let paths = server.paths();
    assert_eq!(paths.len(), 1);
    assert!(
        paths[0].starts_with("/workspace.git/info/refs?service=git-upload-pack"),
        "unexpected request path {}",
        paths[0]
    );
}

#[tokio::test]
async fn the_evidence_hash_is_present_and_changes_with_the_content() {
    let first = GitServer::start(advertisement()).await;
    let p1 = provider_for(&first).await;
    let snap1 = p1.observe(&request(vec![DOMAIN])).await.unwrap();
    let hash1 = snap1.get(DOMAIN).unwrap().provenance.evidence_hash.clone();
    assert!(
        hash1.is_some(),
        "an advertisement must carry an evidence hash"
    );

    // Same repository read again: the hash is stable.
    let snap1b = p1.observe(&request(vec![DOMAIN])).await.unwrap();
    assert_eq!(
        snap1b.get(DOMAIN).unwrap().provenance.evidence_hash,
        hash1,
        "an unchanged repository must hash identically"
    );

    // One rewritten branch: the hash must move. A hash that only covered HEAD
    // would still match here.
    let mut changed = advertisement();
    changed = changed.replace(
        "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678 refs/heads/main",
        "ffffffffffffffffffffffffffffffffffffffff refs/heads/main",
    );
    let second = GitServer::start(changed).await;
    let p2 = provider_for(&second).await;
    let snap2 = p2.observe(&request(vec![DOMAIN])).await.unwrap();
    assert_ne!(
        snap2.get(DOMAIN).unwrap().provenance.evidence_hash,
        hash1,
        "a rewritten branch must change the evidence hash"
    );
}

#[tokio::test]
async fn an_endpoint_that_answers_something_else_yields_degraded_not_empty() {
    // A sandbox can serve anything at all from that URL. Break by treating a
    // non-advertisement body as "no refs" and a healthy repository is reported
    // as an empty one.
    let server = GitServer::start("<html>login required</html>".to_string()).await;
    let p = provider_for(&server).await;

    let snap = p.observe(&request(vec![DOMAIN])).await.unwrap();
    assert_eq!(snap.health, ObservationHealth::Degraded);
    assert!(
        snap.values.is_empty(),
        "a protocol error must carry no values"
    );
    assert!(snap.warnings[0].contains("advertisement"));
}

#[tokio::test]
async fn a_penetrable_sandbox_is_never_contacted_even_though_the_endpoint_answers() {
    // The rule the whole channel hangs on, proven against a server that would
    // happily answer: the host must not even ask.
    let server = GitServer::start(advertisement()).await;
    let p = GitRemoteProvider::new().unwrap();
    p.register_endpoint(
        resource(),
        &format!("http://127.0.0.1:{}/workspace.git", server.port),
        PenetrationVerdict::Allowed {
            domain: DOMAIN,
            mode: ObservationMode::Exec,
        },
    )
    .await
    .unwrap();
    p.set_granted(CapabilitySet::from_iter_caps([Capability::parse(
        &format!("net:connect:127.0.0.1:{}", server.port),
    )
    .unwrap()]))
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
async fn a_connection_refused_yields_unavailable_and_never_an_empty_repository() {
    // Bind then drop, so the port is genuinely closed.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let p = GitRemoteProvider::new().unwrap();
    p.register_endpoint(
        resource(),
        &format!("http://127.0.0.1:{port}/workspace.git"),
        PenetrationVerdict::Refused {
            domain: DOMAIN,
            reason: RefusalReason::IsolationNotPermitted,
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
    assert_eq!(snap.health, ObservationHealth::Unavailable);
    assert!(snap.values.is_empty());
    assert!(
        !snap.warnings.is_empty(),
        "an unreachable endpoint must say why"
    );
    // And it can never be used as evidence that the sandbox has no branches.
    assert!(sandtree_policy::TrustPolicy::new()
        .check_destructive_precondition(&snap)
        .is_err());
}

#[tokio::test]
async fn a_second_observation_reflects_a_changed_remote() {
    // The channel is a live read, not a cached constant: a branch that appears
    // later must show up on the next observation.
    let server = GitServer::start(advertisement()).await;
    let p = provider_for(&server).await;
    let first = p.observe(&request(vec![DOMAIN])).await.unwrap();
    assert_eq!(
        first.get(DOMAIN).unwrap().value["branches"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let hash_before = first.get(DOMAIN).unwrap().provenance.evidence_hash.clone();

    let grown = advertisement()
        + &pktline::encode("3344556677889900aabbccddeeff001122334455 refs/heads/late\n").unwrap()
        + &pktline::encode_flush();
    let server2 = GitServer::start(grown).await;
    let p2 = provider_for(&server2).await;
    let snap = p2.observe(&request(vec![DOMAIN])).await.unwrap();
    let branches = snap.get(DOMAIN).unwrap().value["branches"]
        .as_array()
        .unwrap();
    assert!(
        branches.iter().any(|b| b == "refs/heads/late"),
        "a branch published later must be visible: {branches:?}"
    );
    assert_ne!(
        snap.get(DOMAIN).unwrap().provenance.evidence_hash,
        hash_before,
        "a new branch must change the evidence hash"
    );
}

#[tokio::test]
async fn the_channel_reports_its_own_capability_surface() {
    let server = GitServer::start(advertisement()).await;
    let p = provider_for(&server).await;
    let caps = p.capabilities(&resource()).await.unwrap();
    // It is a probe channel. Claiming native or exec would make the negotiator
    // select it for work it cannot do.
    assert!(!caps.supports(ObservationMode::Native));
    assert!(!caps.supports(ObservationMode::Exec));
    assert!(caps.supports(ObservationMode::Probe));
    // The channel fills `filesystem` with the ref inventory and always returns
    // `health`; it claims nothing else.
    assert_eq!(
        caps.domains_in(ObservationMode::Probe),
        &[
            DOMAIN,
            sandtree_observation_model::ObservationDomain::Health
        ]
    );
}

#[tokio::test]
async fn an_endpoint_without_a_grant_is_never_contacted() {
    // NFR-S02, enforced at the socket boundary rather than only in the returned
    // snapshot: deny-by-default has to mean no packet leaves the host.
    let server = GitServer::start(advertisement()).await;
    let p = GitRemoteProvider::new().unwrap();
    p.register_endpoint(
        resource(),
        &format!("http://127.0.0.1:{}/workspace.git", server.port),
        PenetrationVerdict::Refused {
            domain: DOMAIN,
            reason: RefusalReason::IsolationNotPermitted,
        },
    )
    .await
    .unwrap();
    // Deliberately no `net:connect` grant.

    let snap = p.observe(&request(vec![DOMAIN])).await.unwrap();
    assert_eq!(snap.health, ObservationHealth::Unavailable);
    assert!(snap.values.is_empty());
    assert_eq!(
        server.hits(),
        0,
        "denied acquisition must not open a socket"
    );
}

#[tokio::test]
async fn a_grant_for_another_endpoint_does_not_reach_this_one() {
    // A capability scope names one host:port. A grant for a different sandbox
    // must not open a socket to this one.
    let server = GitServer::start(advertisement()).await;
    let p = GitRemoteProvider::new().unwrap();
    p.register_endpoint(
        resource(),
        &format!("http://127.0.0.1:{}/workspace.git", server.port),
        PenetrationVerdict::Refused {
            domain: DOMAIN,
            reason: RefusalReason::IsolationNotPermitted,
        },
    )
    .await
    .unwrap();
    p.set_granted(CapabilitySet::from_iter_caps([Capability::parse(
        "net:connect:10.9.9.9:9418",
    )
    .unwrap()]))
        .await;

    let snap = p.observe(&request(vec![DOMAIN])).await.unwrap();
    assert_eq!(snap.health, ObservationHealth::Unavailable);
    assert_eq!(server.hits(), 0);
}
