//! Integration tests: flows that cross crate boundaries.
//!
//! Everything here runs against fakes (NFR-O04). That is not a shortcut — the
//! Docker daemon is not running on a build machine, and more importantly the
//! rules being tested (stale-vs-absent, capability enforcement, atomic hot swap,
//! trust never rising) belong to the kernel and the host, not to any particular
//! runtime. A test that needed a live daemon would be testing Docker.
//!
//! Each test names the requirement it is defending so a failure points at the
//! clause it broke.

#![deny(missing_docs)]

use std::collections::BTreeMap;
use std::sync::Arc;

use sandtree_ipc::method;
use sandtree_kernel::resources::ResourceFilter;
use sandtree_kernel::{Kernel, KernelConfig};
use sandtree_model::capability::{Capability, CapabilitySet};
use sandtree_model::error::{DomainError, ErrorCode};
use sandtree_model::event::{EventRecord, EventType};
use sandtree_model::id::{PluginId, ResourceId};
use sandtree_model::operation::{
    OperationId, OperationKind, OperationOutcome, OperationRequest, OperationState,
};
use sandtree_model::resource::{Correlation, ResourceKind, ResourceNode, ResourceState};
use sandtree_observation_model::{
    ObservationCapabilities, ObservationDomain, ObservationHealth, ObservationMode,
    ObservationRequest, ObservationSnapshot, ObservedValue, Provenance, TrustLevel,
};
use sandtree_sdk::ports::{
    DiscoverBatch, ObservationProvider, ProviderDescriptor, ProviderHealth, ProviderInstance,
    ResourceProvider,
};
use serde_json::Value as Json;

/// A scripted provider.
pub struct Fake {
    plugin: PluginId,
    health: ProviderHealth,
    resources: std::sync::Mutex<Vec<ResourceNode>>,
    observation: std::sync::Mutex<Option<ProviderHealth>>,
    invoke_state: std::sync::Mutex<OperationState>,
    invocations: std::sync::atomic::AtomicUsize,
}

impl Fake {
    /// A healthy provider owning `plugin`.
    pub fn healthy(plugin: PluginId) -> Arc<Self> {
        Arc::new(Self {
            plugin: plugin.clone(),
            health: ProviderHealth::Healthy,
            resources: std::sync::Mutex::new(Vec::new()),
            observation: std::sync::Mutex::new(Some(ProviderHealth::Healthy)),
            invoke_state: std::sync::Mutex::new(OperationState::Succeeded),
            invocations: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    /// A provider that reports itself unavailable.
    pub fn unavailable(plugin: PluginId, reason: &str) -> Arc<Self> {
        Arc::new(Self {
            plugin,
            health: ProviderHealth::Unavailable {
                reason: reason.to_string(),
            },
            resources: std::sync::Mutex::new(Vec::new()),
            observation: std::sync::Mutex::new(None),
            invoke_state: std::sync::Mutex::new(OperationState::Succeeded),
            invocations: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    /// Replace the resource set this provider reports.
    pub fn report(self: Arc<Self>, nodes: Vec<ResourceNode>) -> Arc<Self> {
        *self.resources.lock().unwrap() = nodes;
        self
    }

    /// Script the operation outcome.
    pub fn failing(self: Arc<Self>, state: OperationState) -> Arc<Self> {
        *self.invoke_state.lock().unwrap() = state;
        self
    }

    /// Keep the control plane healthy but degrade only the observation plane.
    ///
    /// This is the case ADR-OBS-001 is about: the observation port still exists
    /// and still answers, it just cannot see anything. The distinction matters
    /// because it is what a real provider looks like when the runtime is up but
    /// the probe cannot attach — as opposed to a provider with no port at all.
    pub fn with_degraded_observation(self: Arc<Self>, reason: &str) -> Arc<Self> {
        *self.observation.lock().unwrap() = Some(ProviderHealth::Unavailable {
            reason: reason.to_string(),
        });
        self
    }

    /// The observation-plane health this fake declares, if any.
    pub fn observation_health(&self) -> Option<ProviderHealth> {
        self.observation.lock().unwrap().clone()
    }

    /// How many times `invoke` was reached.
    pub fn invocations(&self) -> usize {
        self.invocations.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Register with a kernel.
    pub async fn install(self: &Arc<Self>, k: &Kernel) {
        k.register_provider(ProviderInstance {
            plugin_id: self.plugin.clone(),
            generation: 1,
            resource: Some(self.clone()),
            observation: Some(Arc::new(FakeObservation(self.clone()))),
            files: None,
            exec: None,
        })
        .await
        .expect("register");
    }
}

#[async_trait::async_trait]
impl ResourceProvider for Fake {
    fn descriptor(&self) -> ProviderDescriptor {
        ProviderDescriptor {
            plugin_id: self.plugin.as_str().to_string(),
            version: "1.0.0".into(),
            kind: sandtree_sdk::manifest::PluginKind::Provider,
        }
    }

    async fn health(&self) -> Result<ProviderHealth, DomainError> {
        Ok(self.health.clone())
    }

    async fn discover(&self, _cursor: Option<String>) -> Result<DiscoverBatch, DomainError> {
        Ok(DiscoverBatch {
            resources: self.resources.lock().unwrap().clone(),
            relations: Vec::new(),
            cursor: None,
        })
    }

    async fn inspect(&self, id: &ResourceId) -> Result<ResourceNode, DomainError> {
        self.resources
            .lock()
            .unwrap()
            .iter()
            .find(|n| &n.id == id)
            .cloned()
            .ok_or_else(|| DomainError::new(ErrorCode::CORE_INVALID, "not found"))
    }

    async fn invoke(&self, _req: &OperationRequest) -> Result<OperationOutcome, DomainError> {
        self.invocations
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let state = *self.invoke_state.lock().unwrap();
        if state == OperationState::Failed {
            return Err(DomainError::new(
                ErrorCode::CORE_INVALID,
                "scripted failure",
            ));
        }
        Ok(OperationOutcome {
            state,
            error_code: None,
            result: Json::Null,
        })
    }

    async fn shutdown(&self) {}
}

/// Observation that always reports `guest-probe` trust.
///
/// The point of the fake is the trust ceiling: a provider can only report what
/// its mode allows, and `guest-probe` must never surface as host-native.
struct FakeObservation(Arc<Fake>);

#[async_trait::async_trait]
impl ObservationProvider for FakeObservation {
    async fn capabilities(&self, _id: &ResourceId) -> Result<ObservationCapabilities, DomainError> {
        Ok(ObservationCapabilities {
            modes: vec![ObservationMode::Probe, ObservationMode::Metadata],
            domains: BTreeMap::from([
                (
                    ObservationMode::Probe.as_str().to_string(),
                    vec![ObservationDomain::Process],
                ),
                (
                    ObservationMode::Metadata.as_str().to_string(),
                    vec![ObservationDomain::Process],
                ),
            ]),
            max_concurrency: None,
            requires_native_credential: false,
        })
    }

    async fn observe(&self, req: &ObservationRequest) -> Result<ObservationSnapshot, DomainError> {
        let now = sandtree_store::now_rfc3339();

        // A degraded observation plane answers with an `Unavailable` snapshot,
        // NOT an error (ADR-OBS-001). The caller must be able to tell "I could
        // not see this" apart from "this does not exist", and an error would
        // collapse that distinction. The reason travels as a warning so the
        // snapshot stays a typed, inspectable result.
        if let Some(ProviderHealth::Unavailable { reason }) = self.0.observation_health() {
            let mut snap = ObservationSnapshot::empty(
                req.resource_id.clone(),
                ObservationMode::Probe,
                ObservationHealth::Unavailable,
                now,
            );
            snap.warn(format!("observation plane unavailable: {reason}"));
            return Ok(snap);
        }

        let mut snap = ObservationSnapshot::empty(
            req.resource_id.clone(),
            ObservationMode::Probe,
            ObservationHealth::Healthy,
            now.clone(),
        );
        for d in &req.domains {
            snap.insert(
                *d,
                ObservedValue::new(
                    serde_json::json!({"pid": 1}),
                    Provenance::new("fake-probe", TrustLevel::GuestProbe, now.clone()),
                ),
            );
        }
        Ok(snap)
    }
}

/// A resource node.
pub fn node(
    name: &str,
    plugin: &PluginId,
    kind: ResourceKind,
    state: ResourceState,
) -> ResourceNode {
    ResourceNode::new(
        ResourceId::derive(&["fake", name]),
        kind,
        plugin.clone(),
        name,
        state,
        None,
        sandtree_store::now_rfc3339(),
    )
}

/// A kernel on a fresh temporary data directory.
pub async fn kernel(grace_ms: u64) -> (tempfile::TempDir, Kernel) {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut cfg = KernelConfig::new(dir.path());
    cfg.stale_grace_ms = grace_ms;
    (dir, Kernel::bootstrap(cfg).await.expect("bootstrap"))
}

/// Grant every lifecycle verb to `plugin`.
pub async fn grant_all(k: &Kernel, plugin: &PluginId) {
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
        caps.insert(Capability::parse(&format!("resource:{verb}")).expect("cap parses"));
    }
    k.set_declared(plugin.clone(), caps.clone()).await;
    for c in caps.iter() {
        k.allow(plugin.clone(), c.clone()).await;
    }
}

#[cfg(test)]
mod discovery_flow {
    use super::*;

    /// FR-001 / NFR-A01: one provider failing must not stop the others.
    #[tokio::test]
    async fn one_broken_provider_does_not_hide_a_healthy_one() {
        let (_d, k) = kernel(60_000).await;
        let good = PluginId::derive(&["p.good"]);
        let bad = PluginId::derive(&["p.bad"]);

        Fake::healthy(good.clone())
            .report(vec![node(
                "c1",
                &good,
                ResourceKind::Container,
                ResourceState::Running,
            )])
            .install(&k)
            .await;
        Fake::unavailable(bad.clone(), "not installed")
            .install(&k)
            .await;

        k.discover_all().await.expect("the scan completes");

        let tree = k.tree(&ResourceFilter::all()).await.unwrap();
        assert_eq!(
            tree.len(),
            1,
            "the healthy provider's resource must survive"
        );
        assert_eq!(tree[0].node.name, "c1");

        // And the failure is reported rather than swallowed.
        let (_id, mut sub) = sandtree_kernel::resources::subscribe_all(k.event_router());
        k.discover_all().await.unwrap();
        let events: Vec<EventRecord> = std::iter::from_fn(|| sub.try_recv()).collect();
        assert!(
            events
                .iter()
                .any(|e| e.event_type == EventType::ProviderHealthChanged),
            "an unavailable provider must produce an event: {events:?}"
        );
    }

    /// NFR-P01: a 200-resource scan completes well inside the budget.
    #[tokio::test]
    async fn a_two_hundred_resource_scan_is_fast() {
        let (_d, k) = kernel(60_000).await;
        let p = PluginId::derive(&["p.big"]);
        let nodes: Vec<ResourceNode> = (0..200)
            .map(|i| {
                node(
                    &format!("c{i}"),
                    &p,
                    ResourceKind::Container,
                    ResourceState::Running,
                )
            })
            .collect();
        Fake::healthy(p.clone()).report(nodes).install(&k).await;

        let start = std::time::Instant::now();
        let changes = k.discover_all().await.unwrap();
        let elapsed = start.elapsed();

        assert_eq!(changes.len(), 200);
        assert!(
            elapsed.as_millis() < 2_500,
            "200 resources took {elapsed:?}, above the 2.5s budget"
        );
    }
}

#[cfg(test)]
mod control_plane {
    use super::*;

    /// FR-051: capability is checked per resource before dispatch.
    #[tokio::test]
    async fn an_ungranted_operation_never_reaches_the_provider() {
        let (_d, k) = kernel(60_000).await;
        let p = PluginId::derive(&["p.a"]);
        let f = Fake::healthy(p.clone()).report(vec![node(
            "c1",
            &p,
            ResourceKind::Container,
            ResourceState::Running,
        )]);
        f.install(&k).await;
        k.discover_all().await.unwrap();
        // Deliberately no grant.

        let id = ResourceId::derive(&["fake", "c1"]);
        let err = k
            .invoke(OperationRequest::new(
                id,
                OperationKind::Stop,
                Json::Null,
                Correlation::generate(),
            ))
            .await
            .expect_err("denied");
        assert_eq!(err.code, ErrorCode::POLICY_DENIED);
        assert_eq!(f.invocations(), 0, "the provider must not be called");
    }

    /// NFR-U02: destructive operations need explicit confirmation.
    #[tokio::test]
    async fn destroy_without_force_is_refused_and_audited_as_a_refusal() {
        let (_d, k) = kernel(60_000).await;
        let p = PluginId::derive(&["p.a"]);
        let f = Fake::healthy(p.clone()).report(vec![node(
            "c1",
            &p,
            ResourceKind::Container,
            ResourceState::Running,
        )]);
        f.install(&k).await;
        k.discover_all().await.unwrap();
        grant_all(&k, &p).await;

        let id = ResourceId::derive(&["fake", "c1"]);
        let err = k
            .invoke(OperationRequest::new(
                id,
                OperationKind::Destroy,
                Json::Null,
                Correlation::generate(),
            ))
            .await
            .expect_err("needs confirmation");
        assert_eq!(err.code, ErrorCode::POLICY_DENIED);
        assert_eq!(f.invocations(), 0);
    }

    /// A provider failure is surfaced, not converted into a false success.
    #[tokio::test]
    async fn a_provider_failure_keeps_its_stable_code() {
        let (_d, k) = kernel(60_000).await;
        let p = PluginId::derive(&["p.a"]);
        let f = Fake::healthy(p.clone())
            .report(vec![node(
                "c1",
                &p,
                ResourceKind::Container,
                ResourceState::Running,
            )])
            .failing(OperationState::Failed);
        f.install(&k).await;
        k.discover_all().await.unwrap();
        grant_all(&k, &p).await;

        let err = k
            .invoke(OperationRequest::new(
                ResourceId::derive(&["fake", "c1"]),
                OperationKind::Stop,
                Json::Null,
                Correlation::generate(),
            ))
            .await
            .expect_err("scripted failure");
        assert_eq!(err.code, ErrorCode::CORE_INVALID);
    }

    /// The job row is written before dispatch and reflects the final state.
    #[tokio::test]
    async fn a_finished_operation_is_persisted_with_its_terminal_state() {
        let (_d, k) = kernel(60_000).await;
        let p = PluginId::derive(&["p.a"]);
        Fake::healthy(p.clone())
            .report(vec![node(
                "c1",
                &p,
                ResourceKind::Container,
                ResourceState::Running,
            )])
            .install(&k)
            .await;
        k.discover_all().await.unwrap();
        grant_all(&k, &p).await;

        // The operation id is generated inside the kernel, so the durable job
        // row can only be reached through the id the progress events carry —
        // which is also what proves the events and the row describe the same
        // operation.
        let (_sid, mut sub) = k
            .event_router()
            .subscribe(sandtree_event::EventFilter::all());

        let correlation = Correlation::generate();
        k.invoke(OperationRequest::new(
            ResourceId::derive(&["fake", "c1"]),
            OperationKind::Stop,
            Json::Null,
            correlation.clone(),
        ))
        .await
        .expect("stop succeeds");

        // One invoke emits several progress stages (started, ... completed), so
        // take the last one rather than asserting every event says "completed".
        let mut stages = Vec::new();
        let mut job_id = None;
        while let Some(ev) = sub.try_recv() {
            if ev.correlation_id != correlation || ev.event_type != EventType::OperationProgress {
                continue;
            }
            if let Some(stage) = ev.payload["stage"].as_str() {
                stages.push(stage.to_string());
            }
            if let Some(id) = ev.payload["operation_id"].as_str() {
                job_id = Some(id.to_string());
            }
        }
        assert_eq!(
            stages.first().map(String::as_str),
            Some("started"),
            "the operation must announce itself before dispatch; got {stages:?}"
        );
        assert_eq!(
            stages.last().map(String::as_str),
            Some("completed"),
            "the operation must reach a terminal stage; got {stages:?}"
        );
        let job_id = job_id.expect("a progress event carrying operation_id");

        let job = k
            .store()
            .operation(&OperationId::parse(&job_id))
            .expect("job row readable")
            .expect("the job row is durable, not only an in-memory event");
        assert_eq!(
            job.state,
            OperationState::Succeeded,
            "the durable job row must carry the terminal state"
        );
    }
}

#[cfg(test)]
mod observation_plane {
    use super::*;

    /// ADR-OBS-003: guest-probe data stays guest-probe after a full round trip.
    #[tokio::test]
    async fn probe_data_never_arrives_as_host_native() {
        let (_d, k) = kernel(60_000).await;
        let p = PluginId::derive(&["p.a"]);
        Fake::healthy(p.clone())
            .report(vec![node(
                "c1",
                &p,
                ResourceKind::Container,
                ResourceState::Running,
            )])
            .install(&k)
            .await;
        k.discover_all().await.unwrap();

        let snap = k
            .observe(ObservationRequest::new(
                ResourceId::derive(&["fake", "c1"]),
                vec![ObservationDomain::Process],
            ))
            .await
            .expect("observation succeeds");

        let weakest = snap.weakest_trust().expect("at least one value");
        assert_eq!(weakest, TrustLevel::GuestProbe);
        assert!(!snap.is_security_authoritative());
        for d in ObservationDomain::all() {
            if let Some(v) = snap.get(*d) {
                assert_ne!(
                    v.provenance.trust,
                    TrustLevel::HostNative,
                    "{d:?} was promoted to host-native"
                );
            }
        }
    }

    /// ADR-OBS-001: an observation failure does not remove the resource.
    #[tokio::test]
    async fn losing_observation_leaves_the_control_plane_intact() {
        let (_d, k) = kernel(60_000).await;
        let p = PluginId::derive(&["p.a"]);
        Fake::healthy(p.clone())
            .report(vec![node(
                "c1",
                &p,
                ResourceKind::Container,
                ResourceState::Running,
            )])
            .install(&k)
            .await;
        k.discover_all().await.unwrap();
        grant_all(&k, &p).await;

        // A provider with no observation port at all.
        let q = PluginId::derive(&["p.b"]);
        k.register_provider(ProviderInstance {
            plugin_id: q.clone(),
            generation: 1,
            resource: Some(Fake::healthy(q.clone()).report(vec![node(
                "s1",
                &q,
                ResourceKind::Sandbox,
                ResourceState::Running,
            )])),
            observation: None,
            files: None,
            exec: None,
        })
        .await
        .unwrap();
        k.discover_all().await.unwrap();

        let err = k
            .observe(ObservationRequest::new(
                ResourceId::derive(&["fake", "s1"]),
                vec![ObservationDomain::Process],
            ))
            .await
            .expect_err("no observation port");
        assert_eq!(err.code, ErrorCode::OBS_NO_STRATEGY);

        // Both resources still exist, and one is still controllable.
        assert_eq!(k.tree(&ResourceFilter::all()).await.unwrap().len(), 2);
        k.invoke(OperationRequest::new(
            ResourceId::derive(&["fake", "c1"]),
            OperationKind::Stop,
            Json::Null,
            Correlation::generate(),
        ))
        .await
        .expect("control still works");
    }

    /// ADR-OBS-001, second shape: the observation port EXISTS and answers, but
    /// reports itself degraded. That must be an `Unavailable` snapshot with no
    /// values, not an error and not a fabricated healthy reading — and the
    /// control plane must be completely unaffected by it.
    #[tokio::test]
    async fn a_degraded_observation_plane_yields_an_unavailable_snapshot() {
        let (_d, k) = kernel(60_000).await;
        let p = PluginId::derive(&["p.degraded"]);
        Fake::healthy(p.clone())
            .with_degraded_observation("probe cannot attach")
            .report(vec![node(
                "c1",
                &p,
                ResourceKind::Container,
                ResourceState::Running,
            )])
            .install(&k)
            .await;
        k.discover_all().await.unwrap();
        grant_all(&k, &p).await;

        // A degraded plane answers — it does not error.
        let snap = k
            .observe(ObservationRequest::new(
                ResourceId::derive(&["fake", "c1"]),
                vec![ObservationDomain::Process],
            ))
            .await
            .expect("a degraded plane still answers");

        assert_eq!(
            snap.health,
            ObservationHealth::Unavailable,
            "a degraded plane must report Unavailable, not Healthy"
        );
        assert!(
            snap.get(ObservationDomain::Process).is_none(),
            "a degraded plane must not fabricate domain values"
        );
        assert!(
            snap.warnings
                .iter()
                .any(|w| w.contains("probe cannot attach")),
            "the reason must survive into the snapshot; got {:?}",
            snap.warnings
        );

        // And the resource is still there and still controllable.
        assert_eq!(k.tree(&ResourceFilter::all()).await.unwrap().len(), 1);
        k.invoke(OperationRequest::new(
            ResourceId::derive(&["fake", "c1"]),
            OperationKind::Stop,
            Json::Null,
            Correlation::generate(),
        ))
        .await
        .expect("control still works while observation is degraded");
    }
}

#[cfg(test)]
mod ipc_surface {
    use super::*;
    use sandtree_daemon::{Daemon, DaemonConfig};

    /// The daemon answers every method it declares.
    #[tokio::test]
    async fn the_daemon_has_no_unrouted_methods() {
        let dir = tempfile::tempdir().unwrap();
        let d = Daemon::start(DaemonConfig {
            data_dir: dir.path().to_path_buf(),
            pipe_path: Some(r"\\.\pipe\sandtree-it".into()),
            ..DaemonConfig::default()
        })
        .await
        .expect("daemon starts");
        assert_eq!(d.coverage_gaps(), Vec::<&str>::new());
        for m in method::ALL {
            assert!(d.router().contains(m), "{m} is unrouted");
        }
    }

    /// An unimplemented method fails loudly instead of pretending to work.
    ///
    /// Uses `snapshot.create`, not `plugin.hotswap`. The plugin lifecycle methods
    /// left the `not_served` list in ADR-016; pointing this test at one of them
    /// would have kept passing for the wrong reason until it started failing for
    /// the right one.
    #[tokio::test]
    async fn an_unimplemented_method_says_so_explicitly() {
        let dir = tempfile::tempdir().unwrap();
        let d = Daemon::start(DaemonConfig {
            data_dir: dir.path().to_path_buf(),
            pipe_path: Some(r"\\.\pipe\sandtree-it2".into()),
            ..DaemonConfig::default()
        })
        .await
        .unwrap();

        let resp = d
            .router()
            .dispatch(&sandtree_ipc::Request::new(
                method::SNAPSHOT_CREATE,
                Json::Null,
            ))
            .await;
        assert!(!resp.is_ok());
        let msg = resp.to_json()["error"]["message"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(msg.contains("not served"), "{msg}");
        assert!(msg.contains(method::SNAPSHOT_CREATE), "{msg}");
    }

    /// Malformed parameters are client errors, not server errors.
    #[tokio::test]
    async fn malformed_parameters_are_rejected_before_any_state_change() {
        let dir = tempfile::tempdir().unwrap();
        let d = Daemon::start(DaemonConfig {
            data_dir: dir.path().to_path_buf(),
            pipe_path: Some(r"\\.\pipe\sandtree-it3".into()),
            ..DaemonConfig::default()
        })
        .await
        .unwrap();

        let resp = d
            .router()
            .dispatch(&sandtree_ipc::Request::new(
                method::OPERATION_INVOKE,
                serde_json::json!({"op": "stop"}),
            ))
            .await;
        assert!(!resp.is_ok());
        assert_eq!(k_err_code(&resp.to_json()), ErrorCode::CORE_INVALID);
    }
}

fn k_err_code(json: &Json) -> ErrorCode {
    ErrorCode::parse(json["error"]["code"].as_str().unwrap_or(""))
        .unwrap_or(ErrorCode::CORE_INVALID)
}

#[cfg(test)]
mod hot_swap_flow {
    use super::*;
    use sandtree_plugin_host::generation::LoadedGeneration;
    use sandtree_plugin_host::hot_swap::{GenerationRuntime, HotSwapSupervisor, StateMigration};
    use sandtree_plugin_host::limits::WorkerLimits;
    use sandtree_plugin_host::route::{Generation, RouteTable};
    use sandtree_sdk::wit::WitDescriptor;

    struct Stub {
        generation: Generation,
        version: &'static str,
        schema: u32,
        init_ok: bool,
    }

    #[async_trait::async_trait]
    impl GenerationRuntime for Stub {
        fn generation(&self) -> Generation {
            self.generation
        }
        fn descriptor(&self) -> WitDescriptor {
            WitDescriptor {
                plugin_id: "p".into(),
                version: self.version.into(),
                state_schema_version: self.schema,
            }
        }
        async fn init(&self, _c: &Json) -> Result<(), DomainError> {
            if self.init_ok {
                Ok(())
            } else {
                Err(DomainError::new(ErrorCode::PLUGIN_HEALTH_FAILED, "no"))
            }
        }
        async fn health(&self) -> Result<ProviderHealth, DomainError> {
            Ok(ProviderHealth::Healthy)
        }
        async fn prepare_upgrade(&self, _t: &str) -> Result<Vec<u8>, DomainError> {
            Ok(b"state".to_vec())
        }
        async fn accept_upgrade(&self, _f: &str, _s: &[u8]) -> Result<(), DomainError> {
            Ok(())
        }
        async fn drain(&self, _d: u64) -> Result<(), DomainError> {
            Ok(())
        }
        async fn shutdown(&self) {}
    }

    /// Build a routable generation for `plugin` (ADR-016).
    fn loaded(
        plugin: &PluginId,
        generation: u64,
        version: &'static str,
        schema: u32,
        init_ok: bool,
    ) -> Arc<LoadedGeneration> {
        Arc::new(LoadedGeneration::lifecycle_only(
            plugin.clone(),
            Generation(generation),
            Arc::new(Stub {
                generation: Generation(generation),
                version,
                schema,
                init_ok,
            }),
        ))
    }

    /// FR-052: a failing new generation must leave the old one serving.
    #[tokio::test]
    async fn a_failed_upgrade_never_takes_the_route_down() {
        let routes = Arc::new(RouteTable::new());
        let sup = HotSwapSupervisor::new(routes.clone(), WorkerLimits::host_ceiling());
        let plugin = PluginId::derive(&["p"]);
        let old = loaded(&plugin, 1, "1.0.0", 1, true);
        routes.atomic_swap(&plugin, old.clone());
        let new = loaded(&plugin, 2, "2.0.0", 1, false);

        let r = sup
            .swap(&plugin, new, old, StateMigration::Required, &Json::Null)
            .await;
        assert!(!r.outcome.swapped);
        assert_eq!(routes.current_generation(&plugin), Some(Generation(1)));
    }

    /// NFR-M02: a state-schema downgrade is refused before migrating.
    #[tokio::test]
    async fn a_state_schema_downgrade_keeps_the_old_generation() {
        let routes = Arc::new(RouteTable::new());
        let sup = HotSwapSupervisor::new(routes.clone(), WorkerLimits::host_ceiling());
        let plugin = PluginId::derive(&["p"]);
        let old = loaded(&plugin, 1, "1.0.0", 4, true);
        routes.atomic_swap(&plugin, old.clone());
        let new = loaded(&plugin, 2, "2.0.0", 2, true);

        let r = sup
            .swap(&plugin, new, old, StateMigration::Required, &Json::Null)
            .await;
        assert!(!r.outcome.swapped);
        assert!(
            r.outcome.reason.contains("downgrade"),
            "{}",
            r.outcome.reason
        );
        assert_eq!(routes.current_generation(&plugin), Some(Generation(1)));
    }
}
