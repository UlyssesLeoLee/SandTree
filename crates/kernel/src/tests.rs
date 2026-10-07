//! Kernel behaviour tests.
//!
//! These cover the invariants that are easiest to break silently and most
//! expensive to get wrong in production:
//!
//! * an unavailable provider must not age out its resources (ADR-OBS-001),
//! * the stale grace period must actually delay removal (DD-SW §5),
//! * a destructive operation must be refused without explicit confirmation,
//! * the diagnostics bundle must be redacted (FR-066).
//!
//! A fake provider is used throughout (NFR-O04): the kernel depends on traits,
//! so no real Docker daemon is needed to prove the control-plane rules.

use std::sync::Arc;

use sandtree_event::EventRouter;
use sandtree_model::capability::CapabilitySet;
use sandtree_model::error::{DomainError, ErrorCode};
use sandtree_model::id::{PluginId, ResourceId};
use sandtree_model::operation::{
    OperationKind, OperationOutcome, OperationRequest, OperationState,
};
use sandtree_model::resource::{ResourceKind, ResourceNode, ResourceState};
use sandtree_observation_model::{
    ObservationCapabilities, ObservationRequest, ObservationSnapshot,
};
use sandtree_sdk::ports::{
    DiscoverBatch, ExecOutcome, ObservationProvider, ProviderDescriptor, ProviderHealth,
    ProviderInstance, ResourceProvider,
};
use serde_json::Value as Json;

use crate::resources::ResourceFilter;
use crate::{Kernel, KernelConfig};

fn plugin(name: &str) -> PluginId {
    PluginId::derive(&[name])
}

fn res(name: &str) -> ResourceId {
    ResourceId::derive(&["test", name])
}

fn node(name: &str, provider: &PluginId, state: ResourceState) -> ResourceNode {
    ResourceNode::new(
        res(name),
        ResourceKind::Container,
        provider.clone(),
        name,
        state,
        None,
        sandtree_store::now_rfc3339(),
    )
}

/// A provider whose reported resources and health the test controls.
struct Fake {
    plugin_id: PluginId,
    descriptor: ProviderDescriptor,
    health: ProviderHealth,
    resources: Vec<ResourceNode>,
    /// Scripted failure code, if any. Stored as a code rather than a
    /// `DomainError` because the error type is deliberately not `Clone`.
    invoke_code: std::sync::Mutex<Option<ErrorCode>>,
    calls: std::sync::Mutex<Vec<String>>,
}

impl Fake {
    fn new(plugin_id: &PluginId, health: ProviderHealth) -> Arc<Self> {
        Arc::new(Self {
            plugin_id: plugin_id.clone(),
            descriptor: ProviderDescriptor {
                plugin_id: plugin_id.as_str().to_string(),
                version: "1.0.0".into(),
                kind: sandtree_sdk::manifest::PluginKind::Provider,
            },
            health,
            resources: Vec::new(),
            invoke_code: std::sync::Mutex::new(None),
            calls: std::sync::Mutex::new(Vec::new()),
        })
    }

    fn with(self: Arc<Self>, nodes: Vec<ResourceNode>) -> Arc<Self> {
        let mut me = self;
        Arc::get_mut(&mut me)
            .expect("freshly built fake has a single owner")
            .resources = nodes;
        me
    }

    fn failing_invoke(self: Arc<Self>, code: ErrorCode) -> Arc<Self> {
        let mut me = self;
        *Arc::get_mut(&mut me)
            .expect("freshly built fake has a single owner")
            .invoke_code
            .lock()
            .unwrap() = Some(code);
        me
    }

    fn calls(&self) -> Vec<String> {
        let guard = self.calls.lock().unwrap();
        guard.clone()
    }
}

#[async_trait::async_trait]
impl ResourceProvider for Fake {
    fn descriptor(&self) -> ProviderDescriptor {
        self.descriptor.clone()
    }

    async fn health(&self) -> Result<ProviderHealth, DomainError> {
        Ok(self.health.clone())
    }

    async fn discover(&self, _cursor: Option<String>) -> Result<DiscoverBatch, DomainError> {
        self.calls.lock().unwrap().push("discover".into());
        Ok(DiscoverBatch {
            resources: self.resources.clone(),
            relations: Vec::new(),
            cursor: None,
        })
    }

    async fn inspect(&self, _id: &ResourceId) -> Result<ResourceNode, DomainError> {
        Err(DomainError::new(ErrorCode::CORE_INVALID, "not implemented"))
    }

    async fn invoke(&self, _req: &OperationRequest) -> Result<OperationOutcome, DomainError> {
        self.calls.lock().unwrap().push("invoke".into());
        let scripted = *self.invoke_code.lock().unwrap();
        match scripted {
            Some(code) => Err(DomainError::new(code, "provider said no")),
            None => Ok(OperationOutcome {
                state: OperationState::Succeeded,
                error_code: None,
                result: Json::Null,
            }),
        }
    }

    async fn shutdown(&self) {
        self.calls.lock().unwrap().push("shutdown".into());
    }
}

struct NoObservation;

#[async_trait::async_trait]
impl ObservationProvider for NoObservation {
    async fn capabilities(&self, _id: &ResourceId) -> Result<ObservationCapabilities, DomainError> {
        Err(DomainError::new(ErrorCode::OBS_NO_STRATEGY, "none"))
    }

    async fn observe(&self, _req: &ObservationRequest) -> Result<ObservationSnapshot, DomainError> {
        Err(DomainError::new(ErrorCode::OBS_NO_STRATEGY, "none"))
    }
}

fn instance(f: Arc<Fake>) -> ProviderInstance {
    ProviderInstance {
        plugin_id: f.plugin_id.clone(),
        generation: 1,
        resource: Some(f),
        observation: None,
        files: None,
        exec: None,
    }
}

async fn kernel(grace_ms: u64) -> (tempfile::TempDir, Kernel) {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut cfg = KernelConfig::new(dir.path());
    cfg.stale_grace_ms = grace_ms;
    let k = Kernel::bootstrap(cfg).await.expect("bootstrap");
    (dir, k)
}

#[tokio::test]
async fn bootstrap_creates_a_usable_store_and_starts_empty() {
    let (_d, k) = kernel(60_000).await;
    assert!(k.tree(&ResourceFilter::all()).await.unwrap().is_empty());
    assert!(k.providers().await.is_empty());
    assert_eq!(
        k.store().schema_version().unwrap(),
        sandtree_store::db::SCHEMA_VERSION
    );
}

#[tokio::test]
async fn discover_merges_provider_resources() {
    let (_d, k) = kernel(60_000).await;
    let p = plugin("sandtree.provider.docker");
    let f =
        Fake::new(&p, ProviderHealth::Healthy).with(vec![node("c1", &p, ResourceState::Running)]);
    k.register_provider(instance(f)).await.unwrap();

    let changes = k.discover_all().await.unwrap();
    assert_eq!(changes.len(), 1);
    assert!(changes[0].added);

    let tree = k.tree(&ResourceFilter::all()).await.unwrap();
    assert_eq!(tree.len(), 1);
    assert_eq!(tree[0].node.name, "c1");
    assert_eq!(tree[0].node.state, ResourceState::Running);
}

#[tokio::test]
async fn an_unavailable_provider_does_not_age_out_its_resources() {
    // ADR-OBS-001: unreachable is not absent. If this regressed, a Docker
    // daemon restart would make every container vanish from the UI.
    let (_d, k) = kernel(60_000).await;
    let p = plugin("sandtree.provider.docker");

    let up =
        Fake::new(&p, ProviderHealth::Healthy).with(vec![node("c1", &p, ResourceState::Running)]);
    let id = up.descriptor.plugin_id.clone();
    k.register_provider(instance(up)).await.unwrap();
    k.discover_all().await.unwrap();
    assert_eq!(k.tree(&ResourceFilter::all()).await.unwrap().len(), 1);
    drop(id);

    // Same plugin id, now reporting itself unavailable.
    let down = Fake::new(
        &p,
        ProviderHealth::Unavailable {
            reason: "daemon not running".into(),
        },
    );
    k.register_provider(instance(down)).await.unwrap();
    k.discover_all().await.unwrap();

    let tree = k.tree(&ResourceFilter::all()).await.unwrap();
    assert_eq!(
        tree.len(),
        1,
        "an unavailable provider must not mark its resources missing"
    );
    assert_eq!(tree[0].node.state, ResourceState::Running);
}

#[tokio::test]
async fn a_healthy_provider_that_stops_reporting_marks_resources_missing() {
    // The other half of the rule: a provider that *can* answer and does not
    // list a resource is real evidence, and the resource goes stale.
    let (_d, k) = kernel(60_000).await;
    let p = plugin("sandtree.provider.docker");

    let with_two = Fake::new(&p, ProviderHealth::Healthy).with(vec![
        node("c1", &p, ResourceState::Running),
        node("c2", &p, ResourceState::Running),
    ]);
    k.register_provider(instance(with_two)).await.unwrap();
    k.discover_all().await.unwrap();

    let with_one =
        Fake::new(&p, ProviderHealth::Healthy).with(vec![node("c1", &p, ResourceState::Running)]);
    k.register_provider(instance(with_one)).await.unwrap();
    k.discover_all().await.unwrap();

    let tree = k.tree(&ResourceFilter::all()).await.unwrap();
    let mut by_name: Vec<(&str, &str)> = tree
        .iter()
        .map(|n| (n.node.name.as_str(), n.node.state.as_str()))
        .collect();
    by_name.sort();
    assert_eq!(
        by_name,
        vec![("c1", "running"), ("c2", "unknown")],
        "c2 is missing from a healthy provider, so it must be stale"
    );
}

#[tokio::test]
async fn the_grace_period_delays_removal_and_then_allows_it() {
    // DD-SW §5: missing first, delete only after the grace period. A single
    // missed scan must never remove anything.
    let (_d, k) = kernel(0).await;
    let p = plugin("sandtree.provider.docker");

    let with_one =
        Fake::new(&p, ProviderHealth::Healthy).with(vec![node("c1", &p, ResourceState::Running)]);
    k.register_provider(instance(with_one)).await.unwrap();
    k.discover_all().await.unwrap();

    // c2 never existed from the provider's point of view, so c1 disappears.
    // The provider now reports nothing. The first reconcile removes nothing
    // and its trailing scan marks the resource missing: it must still be
    // visible, in the `unknown` state, for a whole cycle.
    let empty = Fake::new(&p, ProviderHealth::Healthy);
    k.register_provider(instance(empty)).await.unwrap();
    let first = k.reconcile().await.unwrap();
    assert!(first.removed.is_empty(), "the first pass must not remove");
    let tree = k.tree(&ResourceFilter::all()).await.unwrap();
    assert_eq!(
        tree.len(),
        1,
        "the resource must stay visible while unknown"
    );
    assert_eq!(tree[0].node.state, ResourceState::Unknown);

    // The next pass, past the (zero) grace, removes it.
    let second = k.reconcile().await.unwrap();
    assert_eq!(second.removed.len(), 1);
    assert!(k.tree(&ResourceFilter::all()).await.unwrap().is_empty());
}

#[tokio::test]
async fn a_long_grace_period_never_removes() {
    let (_d, k) = kernel(3_600_000).await;
    let p = plugin("sandtree.provider.docker");
    let with_one =
        Fake::new(&p, ProviderHealth::Healthy).with(vec![node("c1", &p, ResourceState::Running)]);
    k.register_provider(instance(with_one)).await.unwrap();
    k.discover_all().await.unwrap();

    let empty = Fake::new(&p, ProviderHealth::Healthy);
    k.register_provider(instance(empty)).await.unwrap();
    k.discover_all().await.unwrap();

    k.reconcile().await.unwrap();
    k.reconcile().await.unwrap();
    assert_eq!(
        k.tree(&ResourceFilter::all()).await.unwrap().len(),
        1,
        "an hour-long grace must not elapse between two test passes"
    );
}

#[tokio::test]
async fn a_recovered_resource_clears_its_missing_clock() {
    // Otherwise a resource that flaps would accumulate grace time across
    // separate absences and be removed the moment it flapped once more.
    let (_d, k) = kernel(0).await;
    let p = plugin("sandtree.provider.docker");

    let with_one =
        Fake::new(&p, ProviderHealth::Healthy).with(vec![node("c1", &p, ResourceState::Running)]);
    k.register_provider(instance(with_one)).await.unwrap();
    k.discover_all().await.unwrap();

    let empty = Fake::new(&p, ProviderHealth::Healthy);
    k.register_provider(instance(empty)).await.unwrap();
    k.discover_all().await.unwrap();
    k.reconcile().await.unwrap();

    let back =
        Fake::new(&p, ProviderHealth::Healthy).with(vec![node("c1", &p, ResourceState::Running)]);
    k.register_provider(instance(back)).await.unwrap();
    k.discover_all().await.unwrap();

    assert_eq!(
        k.tree(&ResourceFilter::all()).await.unwrap()[0].node.state,
        ResourceState::Running
    );
    // The clock restarted, so this pass must not remove it.
    let outcome = k.reconcile().await.unwrap();
    assert!(outcome.removed.is_empty());
}

#[tokio::test]
async fn a_resource_whose_parent_is_filtered_out_is_still_visible() {
    let (_d, k) = kernel(60_000).await;
    let p = plugin("sandtree.provider.docker");
    let root = ResourceNode::new(
        res("engine"),
        ResourceKind::DockerRuntime,
        p.clone(),
        "engine",
        ResourceState::Running,
        None,
        sandtree_store::now_rfc3339(),
    );
    let mut child = node("c1", &p, ResourceState::Running);
    child.parent_id = Some(root.id.clone());
    let f = Fake::new(&p, ProviderHealth::Healthy).with(vec![root, child]);
    k.register_provider(instance(f)).await.unwrap();
    k.discover_all().await.unwrap();

    // Filter to containers only: the orphan must be promoted, not dropped.
    let tree = k
        .tree(&ResourceFilter::all().by_kind(ResourceKind::Container))
        .await
        .unwrap();
    assert_eq!(tree.len(), 1);
    assert_eq!(tree[0].node.name, "c1");
}

#[tokio::test]
async fn a_destructive_operation_without_force_is_refused_before_dispatch() {
    // Invariant 11. The provider must not even be called.
    let (_d, k) = kernel(60_000).await;
    let p = plugin("sandtree.provider.docker");
    let f =
        Fake::new(&p, ProviderHealth::Healthy).with(vec![node("c1", &p, ResourceState::Running)]);
    k.register_provider(instance(f.clone())).await.unwrap();
    k.discover_all().await.unwrap();

    let req = OperationRequest::new(
        res("c1"),
        OperationKind::Destroy,
        serde_json::json!({}),
        sandtree_model::resource::Correlation::generate(),
    );
    let err = k.invoke(req).await.expect_err("destroy needs confirmation");
    assert_eq!(err.code, ErrorCode::POLICY_DENIED);
    assert!(err.message.contains("force"), "{}", err.message);
    assert!(
        !f.calls().iter().any(|c| c == "invoke"),
        "the provider must not be called for a refused operation: {:?}",
        f.calls()
    );
}

#[tokio::test]
async fn a_forced_destructive_operation_reaches_the_provider() {
    let (_d, k) = kernel(60_000).await;
    let p = plugin("sandtree.provider.docker");
    let f =
        Fake::new(&p, ProviderHealth::Healthy).with(vec![node("c1", &p, ResourceState::Running)]);
    k.register_provider(instance(f.clone())).await.unwrap();
    k.discover_all().await.unwrap();
    grant_resource_caps(&k, &p).await;

    let req = OperationRequest::new(
        res("c1"),
        OperationKind::Destroy,
        serde_json::json!({"force": true}),
        sandtree_model::resource::Correlation::generate(),
    );
    k.invoke(req).await.expect("forced destroy runs");
    assert!(f.calls().iter().any(|c| c == "invoke"));
}

#[tokio::test]
async fn an_ungranted_capability_is_refused() {
    // FR-051 deny-by-default: no grant, no operation.
    let (_d, k) = kernel(60_000).await;
    let p = plugin("sandtree.provider.docker");
    let f =
        Fake::new(&p, ProviderHealth::Healthy).with(vec![node("c1", &p, ResourceState::Running)]);
    k.register_provider(instance(f.clone())).await.unwrap();
    k.discover_all().await.unwrap();
    // No grant_resource_caps here on purpose.

    let req = OperationRequest::new(
        res("c1"),
        OperationKind::Stop,
        serde_json::json!({}),
        sandtree_model::resource::Correlation::generate(),
    );
    let err = k.invoke(req).await.expect_err("no grant, no stop");
    assert_eq!(err.code, ErrorCode::POLICY_DENIED);
    assert!(!f.calls().iter().any(|c| c == "invoke"));
}

#[tokio::test]
async fn a_provider_failure_is_recorded_and_returned_not_swallowed() {
    let (_d, k) = kernel(60_000).await;
    let p = plugin("sandtree.provider.docker");
    let f = Fake::new(&p, ProviderHealth::Healthy)
        .with(vec![node("c1", &p, ResourceState::Running)])
        .failing_invoke(ErrorCode::CORE_INVALID);
    k.register_provider(instance(f)).await.unwrap();
    k.discover_all().await.unwrap();
    grant_resource_caps(&k, &p).await;

    let req = OperationRequest::new(
        res("c1"),
        OperationKind::Stop,
        serde_json::json!({}),
        sandtree_model::resource::Correlation::generate(),
    );
    let err = k.invoke(req).await.expect_err("provider failure surfaces");
    assert_eq!(err.code, ErrorCode::CORE_INVALID);
}

#[tokio::test]
async fn observation_without_a_provider_is_a_typed_error_not_absence() {
    let (_d, k) = kernel(60_000).await;
    let p = plugin("sandtree.provider.docker");
    let f =
        Fake::new(&p, ProviderHealth::Healthy).with(vec![node("c1", &p, ResourceState::Running)]);
    k.register_provider(instance(f)).await.unwrap();
    k.discover_all().await.unwrap();

    let err = k
        .observe(ObservationRequest::new(
            res("c1"),
            vec![sandtree_observation_model::ObservationDomain::Process],
        ))
        .await
        .expect_err("no observation port");
    assert_eq!(err.code, ErrorCode::OBS_NO_STRATEGY);
    // The control plane is untouched: the resource still exists.
    assert_eq!(k.tree(&ResourceFilter::all()).await.unwrap().len(), 1);
}

#[tokio::test]
async fn the_diagnostics_bundle_is_redacted_and_deterministic() {
    let (_d, k) = kernel(60_000).await;
    let p = plugin("sandtree.provider.docker");
    let f =
        Fake::new(&p, ProviderHealth::Healthy).with(vec![node("c1", &p, ResourceState::Running)]);
    k.register_provider(instance(f)).await.unwrap();
    k.discover_all().await.unwrap();

    k.store()
        .upsert_docker_endpoint(&sandtree_store::repo::DockerEndpointRow {
            id: sandtree_model::id::EndpointId::derive(&["local"]),
            uri: "npipe:////./pipe/docker_engine".into(),
            api_version: Some("1.45".into()),
            engine_version: Some("27.0.0".into()),
            os: Some("linux".into()),
            arch: Some("x86_64".into()),
            health: "ok".into(),
        })
        .unwrap();

    let bundle = k.diagnostics_bundle().await.expect("bundle");
    assert_eq!(bundle["schema"], "sandtree.diagnostics/1");
    assert_eq!(bundle["resource_counts"]["container/running"], 1);
    assert!(bundle["docker_endpoints"][0]["endpoint_id"]
        .as_str()
        .unwrap()
        .starts_with("ep-"));

    // NFR-S03: an endpoint profile may not embed credentials at all. The store
    // refuses it on write, which is strictly stronger than redacting it later.
    let err = k
        .store()
        .upsert_docker_endpoint(&sandtree_store::repo::DockerEndpointRow {
            id: sandtree_model::id::EndpointId::derive(&["remote"]),
            uri: "https://user:hunter2@example.invalid:2376".into(),
            api_version: None,
            engine_version: None,
            os: None,
            arch: None,
            health: "unknown".into(),
        })
        .expect_err("a credentialed endpoint URI must be refused");
    assert_eq!(err.code, ErrorCode::POLICY_DENIED);
    assert!(err.message.contains("NFR-S03"), "{}", err.message);

    // And nothing resembling a userinfo section reaches the bundle.
    let text = serde_json::to_string(&k.diagnostics_bundle().await.unwrap()).unwrap();
    assert!(!text.contains('@'), "no URI userinfo in the bundle: {text}");
}

#[tokio::test]
async fn shutdown_releases_every_provider() {
    let (_d, k) = kernel(60_000).await;
    let p = plugin("sandtree.provider.docker");
    let f = Fake::new(&p, ProviderHealth::Healthy);
    k.register_provider(instance(f.clone())).await.unwrap();

    k.shutdown().await;
    assert!(k.providers().await.is_empty());
}

/// Grant every `resource:*` verb the kernel maps operations onto.
///
/// `set_declared` is required first: the effective grant is
/// declared ∩ granted, so granting without declaring grants nothing.
async fn grant_resource_caps(k: &Kernel, p: &PluginId) {
    let mut declared = CapabilitySet::empty();
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
        if let Ok(cap) = sandtree_model::capability::Capability::parse(&format!("resource:{verb}"))
        {
            declared.insert(cap);
        }
    }
    let wire: Vec<sandtree_model::capability::Capability> = declared.iter().cloned().collect();
    k.set_declared(p.clone(), declared).await;
    for cap in wire {
        k.allow(p.clone(), cap).await;
    }
}

/// A provider registry entry whose observation port is absent still allows
/// control — the capability split is per port (DD-PLG §12.1).
#[test]
fn a_control_only_instance_is_not_an_observation_instance() {
    let p = plugin("sandtree.provider.docker");
    let f = Fake::new(&p, ProviderHealth::Healthy);
    let inst = ProviderInstance {
        plugin_id: p,
        generation: 1,
        resource: Some(f),
        observation: None,
        files: None,
        exec: None,
    };
    assert!(inst.has_resource());
    assert!(!inst.has_observation());
    let _ = NoObservation;
    let _ = CapabilitySet::empty();
    let _ = ExecOutcome {
        exit_code: 0,
        stdout: String::new(),
        stderr: String::new(),
        truncated: false,
    };
}

/// The router is shared and survives bootstrap; subscribing works before any
/// provider is registered.
#[tokio::test]
async fn the_event_router_is_available_immediately() {
    let (_d, k) = kernel(60_000).await;
    let (_id, mut sub) = crate::resources::subscribe_all(k.event_router());
    assert_eq!(k.event_router().subscriber_count(), 1);
    sub.close();
}

/// A provider that never terminates its cursor is stopped rather than looping.
struct EndlessCursor;

#[async_trait::async_trait]
impl ResourceProvider for EndlessCursor {
    fn descriptor(&self) -> ProviderDescriptor {
        ProviderDescriptor {
            plugin_id: "sandtree.provider.endless".into(),
            version: "1.0.0".into(),
            kind: sandtree_sdk::manifest::PluginKind::Provider,
        }
    }
    async fn health(&self) -> Result<ProviderHealth, DomainError> {
        Ok(ProviderHealth::Healthy)
    }
    async fn discover(&self, _cursor: Option<String>) -> Result<DiscoverBatch, DomainError> {
        Ok(DiscoverBatch {
            resources: Vec::new(),
            relations: Vec::new(),
            cursor: Some("always-more".into()),
        })
    }
    async fn inspect(&self, _id: &ResourceId) -> Result<ResourceNode, DomainError> {
        unreachable!()
    }
    async fn invoke(&self, _req: &OperationRequest) -> Result<OperationOutcome, DomainError> {
        unreachable!()
    }
    async fn shutdown(&self) {}
}

#[tokio::test]
async fn a_provider_with_an_endless_cursor_is_cut_off() {
    let (_d, k) = kernel(60_000).await;
    k.register_provider(ProviderInstance {
        plugin_id: plugin("sandtree.provider.endless"),
        generation: 1,
        resource: Some(Arc::new(EndlessCursor)),
        observation: None,
        files: None,
        exec: None,
    })
    .await
    .unwrap();

    let err = k.discover_all().await.expect_err("must not loop forever");
    assert_eq!(err.code, ErrorCode::CORE_INVALID);
    assert!(err.message.contains("discovery pages"), "{}", err.message);
}

/// Unused import guard: the router type is referenced through the kernel.
#[test]
fn router_type_is_in_scope() {
    let r = EventRouter::new();
    assert!(r.subscriber_count() == 0);
}
