//! IPC method surface (DD-DATA §6).
//!
//! Every handler is a thin translation from a JSON request into a kernel call.
//! Three rules hold across all of them:
//!
//! * parameters are **typed and validated** before use — a missing `resource_id`
//!   is a client error, not a `null` that propagates into the store,
//! * nothing bypasses the kernel, so policy and audit still apply, and
//! * read methods never mutate, so a client cannot turn `resource.get` into a
//!   write by changing its parameters.

use std::collections::BTreeMap;
use std::sync::Arc;

use sandtree_ipc::method;
use sandtree_ipc::router::MethodRouter;
use sandtree_ipc::Request;
use sandtree_kernel::resources::ResourceFilter;
use sandtree_kernel::Kernel;
use sandtree_model::error::{DomainError, ErrorCode};
use sandtree_model::id::{PluginId, ResourceId};
use sandtree_model::operation::{OperationKind, OperationRequest};
use sandtree_model::resource::Correlation;
use sandtree_observation_model::{ObservationDomain, ObservationRequest};
use sandtree_plugin_host::hot_swap::SwapResult;
use sandtree_plugin_host::route::HotSwapOutcome;
use serde_json::json;
use serde_json::Value as Json;

use crate::plugins::PluginControl;

/// Schema version reported by `diagnostic.version`.
pub const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

fn bad_request(msg: impl Into<String>) -> DomainError {
    DomainError::new(ErrorCode::CORE_INVALID, msg)
}

/// Required string parameter.
fn need_str(params: &Json, key: &str) -> Result<String, DomainError> {
    params
        .get(key)
        .and_then(Json::as_str)
        .map(str::to_string)
        .ok_or_else(|| {
            bad_request(format!(
                "parameter {key:?} is required and must be a string"
            ))
        })
}

/// Required resource id parameter.
fn need_resource(params: &Json) -> Result<ResourceId, DomainError> {
    let raw = need_str(params, "resource_id")?;
    ResourceId::parse(&raw).map_err(|e| bad_request(format!("resource_id {raw:?}: {e}")))
}

/// Subscription bookkeeping shared by the three event methods.
struct EventStream {
    router: Arc<sandtree_event::EventRouter>,
    subs: tokio::sync::Mutex<BTreeMap<String, sandtree_event::Subscription>>,
}

impl EventStream {
    fn new(router: Arc<sandtree_event::EventRouter>) -> Self {
        Self {
            router,
            subs: tokio::sync::Mutex::new(BTreeMap::new()),
        }
    }
}

/// A method this build knows about but does not implement.
fn not_served(method: &str) -> DomainError {
    DomainError::new(
        ErrorCode::CORE_INVALID,
        format!(
            "method {method:?} is recognised but not served by this build \
             (see docs/IMPLEMENTATION.md for the outstanding work list)"
        ),
    )
}

fn ok_json(v: Json) -> Result<Json, DomainError> {
    Ok(v)
}

/// Serialise a row for the wire, mapping the JSON error into a domain one.
fn to_json<T: serde::Serialize>(v: &T) -> Result<Json, DomainError> {
    serde_json::to_value(v).map_err(|e| bad_request(format!("cannot serialise result: {e}")))
}

/// Resolve a manifest plugin id (a reverse-domain-like name) to a `PluginId`.
///
/// Plugin ids in manifests are readable names (`sandtree.provider.docker`), not
/// the opaque `plg-…` form the wire uses elsewhere. Deriving them the same way
/// every other manifest name is derived keeps one rule across the codebase.
fn need_plugin(raw: &str) -> Result<PluginId, DomainError> {
    sandtree_sdk::manifest::validate_plugin_id(raw)
        .map_err(|e| bad_request(format!("plugin_id {raw:?}: {e}")))?;
    Ok(PluginId::derive(&[raw]))
}

/// A `HotSwapOutcome` as a wire object.
fn outcome_json(outcome: &HotSwapOutcome) -> serde_json::Map<String, Json> {
    let mut map = serde_json::Map::new();
    map.insert("swapped".into(), Json::Bool(outcome.swapped));
    map.insert(
        "generation".into(),
        outcome
            .generation
            .map(|g| Json::from(g.0))
            .unwrap_or(Json::Null),
    );
    map.insert("reason".into(), Json::String(outcome.reason.clone()));
    map
}

/// A `SwapResult` as a wire object.
///
/// The step list is included because it is the only record of *how far* a
/// refused swap got; without it an operator sees a message and has to guess
/// whether migration ran.
fn swap_to_json(result: &SwapResult) -> Json {
    let mut map = outcome_json(&result.outcome);
    map.insert(
        "steps".into(),
        Json::Array(result.trace.steps.iter().map(|s| Json::from(*s)).collect()),
    );
    map.insert("migrated".into(), Json::Bool(result.trace.migrated));
    map.insert(
        "correlation_id".into(),
        Json::String(result.correlation_id.clone()),
    );
    map.insert(
        "retired".into(),
        result
            .retired
            .as_ref()
            .map(|g| Json::from(g.generation().0))
            .unwrap_or(Json::Null),
    );
    Json::Object(map)
}

/// Build the full method router.
pub fn build_router(kernel: Arc<Kernel>, plugin_control: PluginControl) -> MethodRouter {
    let mut r = MethodRouter::new();

    // --- resource (read-only) ---
    {
        let k = kernel.clone();
        r.register_owned(method::RESOURCE_GET, move |req| {
            let k = k.clone();
            async move {
                let id = need_resource(&req.params)?;
                ok_json(to_json(&k.resources().inspect(&id).await)?)
            }
        });
    }
    {
        let k = kernel.clone();
        r.register_owned(method::RESOURCE_TREE, move |req| {
            let k = k.clone();
            async move {
                let filter = filter_from(&req.params);
                ok_json(k.resources().tree_json(&filter).await?)
            }
        });
    }
    {
        let k = kernel.clone();
        r.register_owned(method::RESOURCE_LIST, move |req| {
            let k = k.clone();
            async move {
                let provider = req
                    .params
                    .get("provider_id")
                    .and_then(Json::as_str)
                    .and_then(sandtree_model::id::PluginId::from_str_ok);
                let nodes = k.store().resources(provider.as_ref(), None)?;
                let mut out: Vec<Json> = nodes
                    .iter()
                    .filter_map(|n| serde_json::to_value(n).ok())
                    .collect();
                out.sort_by_key(|v| v["id"].as_str().unwrap_or_default().to_string());
                ok_json(Json::Array(out))
            }
        });
    }
    {
        let k = kernel.clone();
        r.register_owned(method::RESOURCE_RELATIONS, move |req| {
            let k = k.clone();
            async move {
                let id = need_resource(&req.params)?;
                let rels = k.resources().relations(&id).await?;
                ok_json(Json::Array(
                    rels.iter()
                        .filter_map(|x| serde_json::to_value(x).ok())
                        .collect(),
                ))
            }
        });
    }

    // --- operation ---
    {
        let k = kernel.clone();
        r.register_owned(method::OPERATION_INVOKE, move |req| {
            let k = k.clone();
            async move {
                let id = need_resource(&req.params)?;
                let op = need_str(&req.params, "op")?;
                let kind = OperationKind::from_wire(&op)
                    .ok_or_else(|| bad_request(format!("unknown operation {op:?}")))?;
                let args = req
                    .params
                    .get("args")
                    .cloned()
                    .unwrap_or(Json::Object(Default::default()));
                let correlation = Correlation::generate();
                let outcome = k
                    .invoke(OperationRequest::new(id, kind, args, correlation))
                    .await?;
                ok_json(to_json(&outcome)?)
            }
        });
    }
    {
        let k = kernel.clone();
        r.register_owned(method::OPERATION_STATUS, move |req| {
            let k = k.clone();
            async move {
                let raw = need_str(&req.params, "operation_id")?;
                let id = sandtree_model::operation::OperationId::parse(&raw);
                match k.store().operation(&id)? {
                    Some(row) => ok_json(to_json(&row)?),
                    None => Err(bad_request(format!("no such operation: {raw}"))),
                }
            }
        });
    }
    {
        let k = kernel.clone();
        r.register_owned(method::OPERATION_LIST, move |_| {
            let k = k.clone();
            async move {
                let jobs: Vec<Json> = k
                    .store()
                    .all_snapshots()?
                    .into_iter()
                    .filter_map(|s| serde_json::to_value(s).ok())
                    .collect();
                ok_json(Json::Array(jobs))
            }
        });
    }

    // --- docker ---
    {
        let k = kernel.clone();
        r.register_owned(method::DOCKER_ENDPOINTS, move |_| {
            let k = k.clone();
            async move {
                let eps: Vec<Json> = k
                    .store()
                    .list_docker_endpoints()?
                    .iter()
                    .filter_map(|e| serde_json::to_value(e).ok())
                    .collect();
                ok_json(Json::Array(eps))
            }
        });
    }
    {
        let k = kernel.clone();
        r.register_owned(method::DOCKER_HEALTH, move |_| {
            let k = k.clone();
            async move {
                let mut out = serde_json::Map::new();
                for p in k.providers().await {
                    out.insert(
                        p.as_str().to_string(),
                        Json::String("no provider instance registered".into()),
                    );
                }
                ok_json(Json::Object(out))
            }
        });
    }

    // --- workspace ---
    {
        let k = kernel.clone();
        r.register_owned(method::WORKSPACE_LIST, move |_| {
            let k = k.clone();
            async move {
                let mounts: Vec<Json> = k
                    .store()
                    .all_workspace_mounts()?
                    .iter()
                    .filter_map(|m| serde_json::to_value(m).ok())
                    .collect();
                ok_json(Json::Array(mounts))
            }
        });
    }

    // --- snapshot ---
    {
        let k = kernel.clone();
        r.register_owned(method::SNAPSHOT_LIST, move |_| {
            let k = k.clone();
            async move {
                let snaps: Vec<Json> = k
                    .store()
                    .all_snapshots()?
                    .iter()
                    .filter_map(|s| serde_json::to_value(s).ok())
                    .collect();
                ok_json(Json::Array(snaps))
            }
        });
    }

    {
        let k = kernel.clone();
        r.register_owned(method::SNAPSHOT_DELETE, move |req| {
            let k = k.clone();
            async move {
                let raw = need_str(&req.params, "snapshot_id")?;
                let id = sandtree_model::id::SnapshotId::parse(&raw)
                    .map_err(|e| bad_request(format!("snapshot_id {raw:?}: {e}")))?;
                let removed = k.store().delete_snapshot(&id)?;
                if removed == 0 {
                    return Err(bad_request(format!("no such snapshot: {raw}")));
                }
                ok_json(serde_json::json!({"deleted": raw}))
            }
        });
    }

    // --- plugin ---
    {
        let k = kernel.clone();
        r.register_owned(method::PLUGIN_LIST, move |_| {
            let k = k.clone();
            async move {
                let pkgs: Vec<Json> = k
                    .store()
                    .list_plugin_packages()?
                    .iter()
                    .filter_map(|p| serde_json::to_value(p).ok())
                    .collect();
                ok_json(Json::Array(pkgs))
            }
        });
    }

    // --- event stream ---
    //
    // Subscriptions live in a table owned by the router, keyed by the request
    // id that created them. Each subscription is a bounded queue owned by the
    // EventRouter, so a client that stops polling loses events rather than
    // growing the daemon.
    {
        let stream = Arc::new(EventStream::new(kernel.event_router().clone()));
        let filter = sandtree_event::EventFilter::all();

        let stream_a = stream.clone();
        r.register_owned(method::EVENT_SUBSCRIBE, move |req| {
            let stream = stream_a.clone();
            let filter = filter.clone();
            async move {
                let sid = req.id.clone();
                let (_id, sub) = stream.router.subscribe(filter);
                stream.subs.lock().await.insert(sid.clone(), sub);
                ok_json(serde_json::json!({ "subscription_id": sid }))
            }
        });

        let stream_b = stream.clone();
        r.register_owned(method::EVENT_UNSUBSCRIBE, move |req| {
            let stream = stream_b.clone();
            async move {
                let sid = need_str(&req.params, "subscription_id")?;
                let removed = stream.subs.lock().await.remove(&sid);
                ok_json(serde_json::json!({ "removed": removed.is_some() }))
            }
        });

        let stream_c = stream.clone();
        r.register_owned(method::EVENT_PULL, move |req| {
            let stream = stream_c.clone();
            async move {
                let sid = need_str(&req.params, "subscription_id")?;
                let max = req
                    .params
                    .get("max")
                    .and_then(Json::as_u64)
                    .unwrap_or(64)
                    .min(1_000) as usize;
                let mut guard = stream.subs.lock().await;
                let sub = guard
                    .get_mut(&sid)
                    .ok_or_else(|| bad_request(format!("no such subscription: {sid}")))?;
                let mut out = Vec::new();
                while out.len() < max {
                    match sub.try_recv() {
                        Some(ev) => out.push(to_json(&ev)?),
                        None => break,
                    }
                }
                let lag = sub.lag();
                ok_json(serde_json::json!({
                    "events": out,
                    "dropped": lag.dropped,
                    "lagging": !lag.is_clean(),
                }))
            }
        });
    }

    // --- plugin lifecycle ---
    //
    // These four answer for real. They used to sit in the `not_served` list
    // below, which meant the supervisor existed, was tested, and was unreachable
    // (ADR-016). Staging itself is delegated to a `PluginLoader`; the daemon
    // ships a loader that refuses, so an install without a worker transport
    // returns a typed refusal rather than a route to nothing.
    {
        let c = Arc::new(plugin_control);
        let c_install = Arc::clone(&c);
        r.register_owned(method::PLUGIN_INSTALL, move |req| {
            let c = Arc::clone(&c_install);
            async move {
                let raw = need_str(&req.params, "plugin_id")?;
                let plugin = need_plugin(&raw)?;
                let config = req
                    .params
                    .get("config")
                    .cloned()
                    .unwrap_or(Json::Object(Default::default()));
                let result = c.install(&plugin, &config).await?;
                ok_json(swap_to_json(&result))
            }
        });

        let c_swap = Arc::clone(&c);
        r.register_owned(method::PLUGIN_HOTSWAP, move |req| {
            let c = Arc::clone(&c_swap);
            async move {
                let raw = need_str(&req.params, "plugin_id")?;
                let plugin = need_plugin(&raw)?;
                let stateful = req
                    .params
                    .get("stateful")
                    .and_then(Json::as_bool)
                    .unwrap_or(false);
                let config = req
                    .params
                    .get("config")
                    .cloned()
                    .unwrap_or(Json::Object(Default::default()));
                let result = c.hotswap(&plugin, stateful, &config).await?;
                ok_json(swap_to_json(&result))
            }
        });

        let c_rollback = Arc::clone(&c);
        r.register_owned(method::PLUGIN_ROLLBACK, move |req| {
            let c = Arc::clone(&c_rollback);
            async move {
                let raw = need_str(&req.params, "plugin_id")?;
                let plugin = need_plugin(&raw)?;
                let outcome = c.rollback(&plugin).await;
                ok_json(Json::Object(outcome_json(&outcome)))
            }
        });

        let c_disable = Arc::clone(&c);
        r.register_owned(method::PLUGIN_DISABLE, move |req| {
            let c = Arc::clone(&c_disable);
            async move {
                let raw = need_str(&req.params, "plugin_id")?;
                let plugin = need_plugin(&raw)?;
                let disabled = c.disable(&plugin).await;
                ok_json(json!(
                    {
                        "plugin_id": plugin.as_str(),
                        "disabled": disabled,
                    }
                ))
            }
        });
    }

    // --- methods this build recognises but does not serve ---
    //
    // Registered explicitly so that a client gets a precise, typed answer
    // ("this build does not serve X") instead of the much less useful
    // "unknown method", which would read as a version mismatch. A method that
    // pretends to work is worse than one that refuses.
    for m in [
        method::DOCKER_EXEC,
        method::WORKSPACE_LIST_DIR,
        method::WORKSPACE_READ,
        method::WORKSPACE_WRITE,
        method::SNAPSHOT_CREATE,
        method::SNAPSHOT_RESTORE,
        method::SNAPSHOT_DIFF,
        method::PLUGIN_ENABLE,
    ] {
        let name = m;
        r.register_owned(name, move |_req| async move { Err(not_served(name)) });
    }

    // --- diagnostic ---
    {
        let k = kernel.clone();
        r.register_owned(method::DIAGNOSTIC_BUNDLE, move |_| {
            let k = k.clone();
            async move { ok_json(k.diagnostics_bundle().await?) }
        });
    }
    {
        r.register_owned(method::DIAGNOSTIC_HEALTH, |_| async move {
            ok_json(serde_json::json!({"state": "ok"}))
        });
    }
    {
        r.register_owned(method::DIAGNOSTIC_VERSION, |_| async move {
            ok_json(serde_json::json!({
                "version": SERVER_VERSION,
                "schema": "sandtree.diagnostics/1",
            }))
        });
    }

    r
}

/// Build a resource filter from request parameters.
fn filter_from(params: &Json) -> ResourceFilter {
    let mut f = ResourceFilter::all();
    if let Some(p) = params
        .get("provider_id")
        .and_then(Json::as_str)
        .and_then(sandtree_model::id::PluginId::from_str_ok)
    {
        f = f.by_provider(p);
    }
    if let Some(k) = params
        .get("kind")
        .and_then(Json::as_str)
        .and_then(resource_kind_from_wire)
    {
        f = f.by_kind(k);
    }
    f
}

fn resource_kind_from_wire(s: &str) -> Option<sandtree_model::resource::ResourceKind> {
    sandtree_model::resource::ResourceKind::all()
        .iter()
        .find(|k| k.as_str() == s)
        .copied()
}

/// Build a request for a method, used by the CLI and the integration tests.
pub fn request(method: &str, params: Json) -> Request {
    Request::new(method, params)
}

/// Observation request builder shared by the CLI and tests.
pub fn observation_request(
    resource: ResourceId,
    domains: Vec<&str>,
) -> Result<ObservationRequest, DomainError> {
    let parsed: Vec<ObservationDomain> = domains
        .iter()
        .map(|d| {
            ObservationDomain::from_wire(d)
                .ok_or_else(|| bad_request(format!("unknown observation domain {d:?}")))
        })
        .collect::<Result<_, _>>()?;
    Ok(ObservationRequest::new(resource, parsed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Daemon, DaemonConfig};
    use sandtree_kernel::KernelConfig;
    use sandtree_model::resource::ResourceKind;
    use sandtree_plugin_host::route::RouteTable;

    async fn router() -> (tempfile::TempDir, MethodRouter) {
        let dir = tempfile::tempdir().unwrap();
        let k = Kernel::bootstrap(KernelConfig::new(dir.path()))
            .await
            .unwrap();
        let r = build_router(
            Arc::new(k),
            crate::plugins::PluginControl::unavailable(Arc::new(RouteTable::new()), "test"),
        );
        (dir, r)
    }

    #[tokio::test]
    async fn every_declared_method_is_routed() {
        let (_d, r) = router().await;
        for m in method::ALL {
            assert!(r.contains(m), "{m} has no handler");
        }
    }

    #[tokio::test]
    async fn the_plugin_lifecycle_endpoints_are_reachable_not_merely_declared() {
        // The plugin lifecycle endpoints used to answer `not_served`. A handler
        // existing proves the method is routable; *calling* it proves the control
        // plane is reached. Only the second makes the mechanism reachable —
        // which is exactly what ADR-016 set out to fix.
        let (_d, r) = router().await;

        for (m, params) in [
            (
                method::PLUGIN_INSTALL,
                serde_json::json!({"plugin_id": "sandtree.provider.x"}),
            ),
            (
                method::PLUGIN_HOTSWAP,
                serde_json::json!({"plugin_id": "sandtree.provider.x"}),
            ),
            (
                method::PLUGIN_ROLLBACK,
                serde_json::json!({"plugin_id": "sandtree.provider.x"}),
            ),
            (
                method::PLUGIN_DISABLE,
                serde_json::json!({"plugin_id": "sandtree.provider.x"}),
            ),
        ] {
            let json = r.dispatch(&request(m, params)).await.to_json();
            let message = json["error"]["message"].as_str().unwrap_or_default();
            assert!(
                !message.contains("not served by this build"),
                "{m} is still a not_served stub: {message}"
            );
        }
    }

    #[tokio::test]
    async fn a_malformed_plugin_id_is_rejected_before_it_reaches_the_host() {
        // Validated against the same rule the manifest schema uses. A private
        // copy of that rule in the daemon would be free to drift from the schema
        // pattern, which is why `validate_plugin_id` is public.
        let (_d, r) = router().await;
        for bad in ["NOT-DOTTED", "sandtree.provider.x/", ""] {
            let json = r
                .dispatch(&request(
                    method::PLUGIN_INSTALL,
                    serde_json::json!({ "plugin_id": bad }),
                ))
                .await
                .to_json();
            assert!(
                json["error"]["message"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("plugin_id"),
                "{bad:?} should be rejected as a client error, got {json}"
            );
        }
    }

    #[tokio::test]
    async fn a_missing_parameter_is_a_typed_client_error() {
        let (_d, r) = router().await;
        let resp = r.dispatch(&request(method::RESOURCE_GET, Json::Null)).await;
        assert!(!resp.is_ok());
        let json = resp.to_json();
        assert!(json["error"]["message"]
            .as_str()
            .unwrap()
            .contains("resource_id"));
    }

    #[tokio::test]
    async fn a_malformed_resource_id_is_rejected_before_the_store() {
        let (_d, r) = router().await;
        let resp = r
            .dispatch(&request(
                method::RESOURCE_GET,
                serde_json::json!({"resource_id": "not-an-id"}),
            ))
            .await;
        assert!(!resp.is_ok());
    }

    #[tokio::test]
    async fn an_unknown_operation_name_is_rejected() {
        let (_d, r) = router().await;
        let resp = r
            .dispatch(&request(
                method::OPERATION_INVOKE,
                serde_json::json!({"resource_id": "res-00000000000000000000000000", "op": "levitate"}),
            ))
            .await;
        assert!(!resp.is_ok());
        assert!(resp.to_json()["error"]["message"]
            .as_str()
            .unwrap()
            .contains("levitate"));
    }

    #[tokio::test]
    async fn read_methods_answer_on_an_empty_system() {
        let (_d, r) = router().await;
        for m in [
            method::RESOURCE_TREE,
            method::RESOURCE_LIST,
            method::OPERATION_LIST,
            method::DOCKER_ENDPOINTS,
            method::WORKSPACE_LIST,
            method::SNAPSHOT_LIST,
            method::PLUGIN_LIST,
            method::DIAGNOSTIC_BUNDLE,
            method::DIAGNOSTIC_HEALTH,
            method::DIAGNOSTIC_VERSION,
        ] {
            let resp = r.dispatch(&request(m, Json::Null)).await;
            assert!(resp.is_ok(), "{m} failed: {:?}", resp.to_json());
        }
    }

    #[tokio::test]
    async fn the_version_method_reports_the_crate_version() {
        let (_d, r) = router().await;
        let resp = r
            .dispatch(&request(method::DIAGNOSTIC_VERSION, Json::Null))
            .await;
        assert_eq!(
            resp.to_json()["result"]["version"],
            Json::String(SERVER_VERSION.into())
        );
    }

    #[test]
    fn a_kind_filter_ignores_unknown_kinds_rather_than_failing() {
        let f = filter_from(&serde_json::json!({"kind": "nonsense"}));
        assert!(f.kind.is_none());
        let f = filter_from(&serde_json::json!({"kind": "container"}));
        assert_eq!(f.kind, Some(ResourceKind::Container));
    }

    #[test]
    fn observation_domains_are_validated_by_name() {
        let id = ResourceId::derive(&["x"]);
        assert!(observation_request(id.clone(), vec!["process"]).is_ok());
        let err = observation_request(id, vec!["not-a-domain"]).unwrap_err();
        assert!(err.message.contains("not-a-domain"), "{}", err.message);
    }

    #[tokio::test]
    async fn a_second_daemon_shares_no_state_with_the_first() {
        // The pipe name is configurable, so two daemons can coexist; this is
        // what makes a future in-place upgrade possible.
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let d1 = Daemon::start(DaemonConfig {
            data_dir: a.path().to_path_buf(),
            pipe_path: Some(r"\\.\pipe\sandtree-a".into()),
            ..DaemonConfig::default()
        })
        .await
        .unwrap();
        let d2 = Daemon::start(DaemonConfig {
            data_dir: b.path().to_path_buf(),
            pipe_path: Some(r"\\.\pipe\sandtree-b".into()),
            ..DaemonConfig::default()
        })
        .await
        .unwrap();
        assert_ne!(d1.pipe(), d2.pipe());
        assert_ne!(d1.kernel().store().path(), d2.kernel().store().path());
    }
}
