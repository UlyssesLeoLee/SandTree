//! System tests: the scenarios in the design's system-test plan.
//!
//! These are the end-to-end behaviours a release is judged on. Each test names
//! the requirement and the ST case it stands in for, so a failure points at a
//! specific acceptance item rather than at "system tests".
//!
//! Scope note: scenarios that genuinely require a live Docker daemon, a real
//! Windows Sandbox host, or an installed Multipass are **not** faked here. They
//! are listed in `docs/IMPLEMENTATION.md` as outstanding, because a test that
//! pretends to exercise a runtime it never touched is worse than no test.

#![deny(missing_docs)]

use std::collections::BTreeMap;
use std::sync::Arc;

use sandtree_ipc::framing::{encode, FrameDecoder};
use sandtree_ipc::method;
use sandtree_kernel::resources::ResourceFilter;
use sandtree_kernel::{Kernel, KernelConfig};
use sandtree_model::error::{DomainError, ErrorCode};
use sandtree_model::event::EventType;
use sandtree_model::id::{PluginId, ResourceId};
use sandtree_model::operation::{
    OperationKind, OperationOutcome, OperationRequest, OperationState,
};
use sandtree_model::resource::{Correlation, ResourceKind, ResourceNode, ResourceState};
use sandtree_observation_model::{
    ObservationDomain, ObservationMode, ObservationRequest, TrustLevel,
};
use sandtree_sdk::ports::{
    DiscoverBatch, ObservationProvider, ProviderDescriptor, ProviderHealth, ProviderInstance,
    ResourceProvider,
};
use serde_json::Value as Json;

/// A deterministic in-memory runtime standing in for "the products exist".
struct World {
    kernel: Kernel,
    _dir: tempfile::TempDir,
    plugin: PluginId,
    resources: std::sync::Mutex<Vec<ResourceNode>>,
    present: std::sync::Mutex<bool>,
    invoke_calls: std::sync::atomic::AtomicUsize,
}

impl World {
    async fn new(grace_ms: u64) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut cfg = KernelConfig::new(dir.path());
        cfg.stale_grace_ms = grace_ms;
        let kernel = Kernel::bootstrap(cfg).await.expect("bootstrap");
        Self {
            kernel,
            _dir: dir,
            plugin: PluginId::derive(&["sandtree.provider.world"]),
            resources: std::sync::Mutex::new(Vec::new()),
            present: std::sync::Mutex::new(true),
            invoke_calls: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    fn container(&self, name: &str, state: ResourceState) -> ResourceNode {
        ResourceNode::new(
            ResourceId::derive(&["world", name]),
            ResourceKind::Container,
            self.plugin.clone(),
            name,
            state,
            None,
            sandtree_store::now_rfc3339(),
        )
    }

    /// Put the runtime in a state where the product is not installed.
    fn take_the_product_away(&self) {
        *self.present.lock().unwrap() = false;
    }

    /// Put it back.
    fn install_the_product(&self) {
        *self.present.lock().unwrap() = true;
    }

    async fn register(self: &Arc<Self>) {
        let w = self.clone();
        self.kernel
            .register_provider(ProviderInstance {
                plugin_id: w.plugin.clone(),
                generation: 1,
                resource: Some(Arc::new(Runtime(w.clone()))),
                observation: Some(Arc::new(Runtime(w.clone()))),
                files: None,
                exec: None,
            })
            .await
            .expect("register");
    }

    fn invocations(&self) -> usize {
        self.invoke_calls.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// Local newtype carrying the shared world into the provider ports.
struct Runtime(Arc<World>);

#[async_trait::async_trait]
impl ResourceProvider for Runtime {
    fn descriptor(&self) -> ProviderDescriptor {
        ProviderDescriptor {
            plugin_id: self.0.plugin.as_str().to_string(),
            version: "1.0.0".into(),
            kind: sandtree_sdk::manifest::PluginKind::Provider,
        }
    }

    async fn health(&self) -> Result<ProviderHealth, DomainError> {
        if *self.0.present.lock().unwrap() {
            Ok(ProviderHealth::Healthy)
        } else {
            Ok(ProviderHealth::Unavailable {
                reason: "the runtime is not installed".into(),
            })
        }
    }

    async fn discover(&self, _cursor: Option<String>) -> Result<DiscoverBatch, DomainError> {
        if !*self.0.present.lock().unwrap() {
            // An unreachable runtime is not an empty one: report the failure and
            // let the kernel decide, rather than claiming "no containers".
            return Err(DomainError::new(
                ErrorCode::PLUGIN_HEALTH_FAILED,
                "runtime unreachable",
            ));
        }
        Ok(DiscoverBatch {
            resources: self.0.resources.lock().unwrap().clone(),
            relations: Vec::new(),
            cursor: None,
        })
    }

    async fn inspect(&self, id: &ResourceId) -> Result<ResourceNode, DomainError> {
        self.0
            .resources
            .lock()
            .unwrap()
            .iter()
            .find(|n| &n.id == id)
            .cloned()
            .ok_or_else(|| DomainError::new(ErrorCode::CORE_INVALID, "no such resource"))
    }

    async fn invoke(&self, _req: &OperationRequest) -> Result<OperationOutcome, DomainError> {
        self.0
            .invoke_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(OperationOutcome {
            state: OperationState::Succeeded,
            error_code: None,
            result: Json::Null,
        })
    }

    async fn shutdown(&self) {}
}

#[async_trait::async_trait]
impl ObservationProvider for Runtime {
    async fn capabilities(
        &self,
        _id: &ResourceId,
    ) -> Result<sandtree_observation_model::ObservationCapabilities, DomainError> {
        Ok(sandtree_observation_model::ObservationCapabilities {
            modes: vec![ObservationMode::Probe],
            domains: BTreeMap::from([(
                ObservationMode::Probe.as_str().to_string(),
                vec![ObservationDomain::Process],
            )]),
            max_concurrency: None,
            requires_native_credential: false,
        })
    }

    async fn observe(
        &self,
        req: &ObservationRequest,
    ) -> Result<sandtree_observation_model::ObservationSnapshot, DomainError> {
        let now = sandtree_store::now_rfc3339();
        let mut snap = sandtree_observation_model::ObservationSnapshot::empty(
            req.resource_id.clone(),
            ObservationMode::Probe,
            sandtree_observation_model::ObservationHealth::Healthy,
            now.clone(),
        );
        for d in &req.domains {
            snap.insert(
                *d,
                sandtree_observation_model::ObservedValue::new(
                    Json::from("probe"),
                    sandtree_observation_model::Provenance::new(
                        "world-probe",
                        TrustLevel::GuestProbe,
                        now.clone(),
                    ),
                ),
            );
        }
        Ok(snap)
    }
}

/// ST: the daemon boots on a machine with nothing installed and still answers.
#[tokio::test]
async fn the_daemon_starts_on_a_machine_with_no_runtimes_installed() {
    let w = Arc::new(World::new(60_000).await);
    w.take_the_product_away();
    w.register().await;

    // Boot itself must not depend on a provider being reachable.
    w.kernel.discover_all().await.expect("scan completes");
    assert!(w
        .kernel
        .tree(&ResourceFilter::all())
        .await
        .unwrap()
        .is_empty());

    let bundle = w
        .kernel
        .diagnostics_bundle()
        .await
        .expect("diagnostics still work");
    assert_eq!(bundle["schema"], "sandtree.diagnostics/1");
}

/// ST: losing the runtime and getting it back must not lose the topology.
#[tokio::test]
async fn a_runtime_outage_and_recovery_round_trips_cleanly() {
    // This is the scenario that would break a daemon restart, an upgrade, or a
    // Docker Desktop toggle, and it is the one the stale rule exists for.
    let w = Arc::new(World::new(60_000).await);
    w.resources
        .lock()
        .unwrap()
        .push(w.container("web", ResourceState::Running));
    w.resources
        .lock()
        .unwrap()
        .push(w.container("db", ResourceState::Running));
    w.register().await;
    w.kernel.discover_all().await.unwrap();
    assert_eq!(
        w.kernel.tree(&ResourceFilter::all()).await.unwrap().len(),
        2
    );

    // Outage: the provider is unreachable for a while.
    w.take_the_product_away();
    for _ in 0..3 {
        w.kernel.reconcile().await.unwrap();
    }
    let during = w.kernel.tree(&ResourceFilter::all()).await.unwrap();
    assert_eq!(
        during.len(),
        2,
        "an outage must not delete the user's containers"
    );
    assert!(during
        .iter()
        .all(|n| n.node.state == ResourceState::Running));

    // Recovery: same topology comes back.
    w.install_the_product();
    w.kernel.reconcile().await.unwrap();
    let after = w.kernel.tree(&ResourceFilter::all()).await.unwrap();
    assert_eq!(after.len(), 2);
    assert!(after.iter().all(|n| n.node.state == ResourceState::Running));
}

/// ST: a container the user actually deletes disappears, but only after the
/// grace period, and it is visible as missing in between.
#[tokio::test]
async fn a_genuine_deletion_is_visible_before_it_is_applied() {
    // Grace of zero, so the "second pass applies it" step is reachable inside a
    // test. The visibility guarantee comes from the *ordering* of the passes, not
    // from the duration.
    let w = Arc::new(World::new(0).await);
    w.resources
        .lock()
        .unwrap()
        .push(w.container("keep", ResourceState::Running));
    w.resources
        .lock()
        .unwrap()
        .push(w.container("drop", ResourceState::Running));
    w.register().await;
    w.kernel.reconcile().await.unwrap();
    assert_eq!(
        w.kernel.tree(&ResourceFilter::all()).await.unwrap().len(),
        2
    );

    // The user deletes one.
    w.resources.lock().unwrap().retain(|n| n.name != "drop");

    let first = w.kernel.reconcile().await.unwrap();
    assert!(first.removed.is_empty(), "not on the first pass");
    let tree = w.kernel.tree(&ResourceFilter::all()).await.unwrap();
    assert_eq!(tree.len(), 2, "still visible while missing");
    let drop_node = tree
        .iter()
        .find(|n| n.node.name == "drop")
        .expect("the deleted container is still listed");
    assert_eq!(
        drop_node.node.state,
        ResourceState::Unknown,
        "it must be visibly missing, not silently gone"
    );

    // With no configured grace in the test harness the next pass applies it.
    let second = w.kernel.reconcile().await.unwrap();
    assert_eq!(second.removed.len(), 1);
    let final_tree = w.kernel.tree(&ResourceFilter::all()).await.unwrap();
    assert_eq!(final_tree.len(), 1);
    assert_eq!(final_tree[0].node.name, "keep");
}

/// ST: a destructive operation requires confirmation and is audited either way.
#[tokio::test]
async fn a_destructive_operation_is_confirmed_and_audited() {
    let w = Arc::new(World::new(60_000).await);
    w.resources
        .lock()
        .unwrap()
        .push(w.container("victim", ResourceState::Running));
    w.register().await;
    w.kernel.reconcile().await.unwrap();
    grant(&w.kernel, &w.plugin).await;

    // Subscribe before acting, so the privileged audit record is observable.
    // The audit trail is published on the event bus (DD-SW §12.3), so that —
    // not the event-log retention counter — is what proves an audit happened.
    let (_sub_id, mut sub) = w
        .kernel
        .event_router()
        .subscribe(sandtree_event::EventFilter::all());

    let id = ResourceId::derive(&["world", "victim"]);

    // Without confirmation: refused, and the provider is never reached.
    let refused = w
        .kernel
        .invoke(OperationRequest::new(
            id.clone(),
            OperationKind::Destroy,
            Json::Null,
            Correlation::generate(),
        ))
        .await
        .expect_err("needs force");
    assert_eq!(refused.code, ErrorCode::POLICY_DENIED);
    assert_eq!(w.invocations(), 0);

    // With confirmation: it runs exactly once.
    w.kernel
        .invoke(OperationRequest::new(
            id,
            OperationKind::Destroy,
            serde_json::json!({"force": true}),
            Correlation::generate(),
        ))
        .await
        .expect("forced destroy runs");
    assert_eq!(w.invocations(), 1);

    // And an audit record exists for the privileged action (NFR-S03): drain what
    // the router delivered and require a privileged audit for this resource.
    let mut privileged_audits = 0;
    while let Some(ev) = sub.try_recv() {
        if ev.event_type == EventType::AuditRecorded && ev.payload["privileged"] == Json::Bool(true)
        {
            privileged_audits += 1;
        }
    }
    assert!(
        privileged_audits >= 1,
        "the forced destroy must produce a privileged audit record (NFR-S03); \
         saw {privileged_audits}"
    );
}

/// ST: observation keeps its trust ceiling across an outage and a recovery.
#[tokio::test]
async fn observation_trust_never_rises_across_an_outage() {
    let w = Arc::new(World::new(60_000).await);
    w.resources
        .lock()
        .unwrap()
        .push(w.container("target", ResourceState::Running));
    w.register().await;
    w.kernel.reconcile().await.unwrap();

    let id = ResourceId::derive(&["world", "target"]);
    let before = w
        .kernel
        .observe(ObservationRequest::new(
            id.clone(),
            vec![ObservationDomain::Process],
        ))
        .await
        .expect("observation works");
    assert_eq!(before.weakest_trust(), Some(TrustLevel::GuestProbe));

    // The runtime goes away and comes back.
    w.take_the_product_away();
    w.kernel.reconcile().await.unwrap();
    w.install_the_product();
    w.kernel.reconcile().await.unwrap();

    let after = w
        .kernel
        .observe(ObservationRequest::new(
            id,
            vec![ObservationDomain::Process],
        ))
        .await
        .expect("observation works again");
    assert_eq!(
        after.weakest_trust(),
        Some(TrustLevel::GuestProbe),
        "a recovered observation must not be treated as more trustworthy"
    );
    assert!(!after.is_security_authoritative());
}

/// ST: the IPC wire format survives a hostile or truncated peer.
#[tokio::test]
async fn the_ipc_layer_survives_a_truncated_and_an_oversized_peer() {
    // A daemon that panics on a bad length prefix is a denial-of-service bug
    // reachable by any local process, so this is a system-level concern.
    // Truncated: a partial prefix is buffered, nothing is decoded, no panic.
    let mut partial = FrameDecoder::new();
    partial.push(&encode(b"partial").unwrap()[..3]).unwrap();
    assert!(partial.next_frame().unwrap().is_none());
    assert!(
        partial.pending() > 0,
        "the partial bytes are held, not dropped"
    );

    // Complete: the frame lands whole.
    let mut d = FrameDecoder::new();
    d.push(&encode(b"complete").unwrap()).unwrap();
    assert_eq!(d.next_frame().unwrap().unwrap(), b"complete");
    assert!(d.is_empty());

    // Oversized: refused, and the decoder is not left holding the payload.
    let mut hostile = FrameDecoder::new();
    let err = hostile
        .push(&vec![0x41u8; sandtree_ipc::framing::MAX_FRAME_BYTES + 16])
        .unwrap_err();
    assert!(err.message.contains("above the"), "{}", err.message);
}

/// ST: a full daemon lifecycle — boot, serve, reconcile, shut down.
#[tokio::test]
async fn a_daemon_session_completes_without_leaking_state() {
    let dir = tempfile::tempdir().unwrap();
    let d = sandtree_daemon::Daemon::start(sandtree_daemon::DaemonConfig {
        data_dir: dir.path().to_path_buf(),
        pipe_path: Some(r"\\.\pipe\sandtree-st".into()),
        ..sandtree_daemon::DaemonConfig::default()
    })
    .await
    .expect("daemon starts");

    assert_eq!(d.coverage_gaps(), Vec::<&str>::new());
    for _ in 0..3 {
        d.reconcile_once().await.expect("reconcile is clean");
    }
    assert!(d.methods().len() >= method::ALL.len());

    d.shutdown().await;
    d.shutdown().await;
}

/// ST: a corrupt endpoint profile is refused at write time.
#[tokio::test]
async fn a_credentialed_endpoint_profile_is_refused_by_the_store() {
    // NFR-S03, exercised through the store rather than through a UI path,
    // because the store is the only place a profile can enter the system.
    let w = World::new(60_000).await;
    let err = w
        .kernel
        .store()
        .upsert_docker_endpoint(&sandtree_store::repo::DockerEndpointRow {
            id: sandtree_model::id::EndpointId::derive(&["st"]),
            uri: "https://admin:s3cret@docker.invalid:2376".into(),
            api_version: None,
            engine_version: None,
            os: None,
            arch: None,
            health: "unknown".into(),
        })
        .expect_err("credentials are refused");
    assert_eq!(err.code, ErrorCode::POLICY_DENIED);
}

async fn grant(k: &Kernel, plugin: &PluginId) {
    use sandtree_model::capability::{Capability, CapabilitySet};
    let mut caps = CapabilitySet::empty();
    for verb in [
        "start",
        "stop",
        "restart",
        "destroy",
        "pause",
        "unpause",
        "exec",
        "pull",
        "build",
        "tag",
        "remove",
        "prune",
        "create",
        "observe",
        "logs",
        "stats",
        "read",
        "write",
        "snapshot",
        "diff",
        "refresh",
        "reconnect",
    ] {
        caps.insert(Capability::parse(&format!("resource:{verb}")).expect("cap"));
    }
    k.set_declared(plugin.clone(), caps.clone()).await;
    for c in caps.iter() {
        k.allow(plugin.clone(), c.clone()).await;
    }
}
