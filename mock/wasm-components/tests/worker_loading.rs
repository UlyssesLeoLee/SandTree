//! The worker half of the plugin path, driven over a real component.
//!
//! # Why this exists
//!
//! `tests/provider_binding.rs` proves the *host adapter* works: a component
//! binds and serves provider traffic. But a real install goes through more than
//! that — package verification, the capability intersection, the generation
//! number, the resource port being attached, and retirement. `apps/plugin-worker`
//! is where all of that lives, and until now it had only unit tests over bytes
//! that were never a component.
//!
//! So this drives the worker's own `load` over the fixture: if `Worker::load`
//! returned a generation that could not actually serve, or returned one with no
//! resource port, nothing else in the repo would say so.
//!
//! What is *not* proved here: process isolation. `Worker::load` runs the
//! component in this process, because that is what the worker is — a separate
//! process is a transport concern layered on top, and until the daemon spawns
//! one, "the worker loads a component" and "the worker is isolated" are
//! different claims and only the first one is tested.

use sandtree_model::operation::{OperationKind, OperationRequest, OperationState};
use sandtree_model::resource::{Correlation, ResourceKind, ResourceState};
use sandtree_plugin_host::hot_swap::GenerationRuntime;
use sandtree_plugin_host::route::Generation;
use sandtree_plugin_host::verify::InstallPolicy;
use sandtree_plugin_worker::{Worker, WorkerSpec};
use sandtree_sdk::ports::ProviderHealth;
use serde_json::Value as Json;

/// The same fixture the host-adapter binding test uses. There is one valid
/// component in this corpus and both tests must agree on it — two "valid"
/// fixtures would let each test pass against the other's behaviour.
const WAT: &str = include_str!("../fixtures/valid_provider_component.wat");

/// Plugin id the fixture's manifest declares.
///
/// The `PluginId` the worker derives is `PluginId::derive(&[<this>])`, not the
/// string itself — identity is derived, so the assertions below compare against
/// the derivation rather than the literal.
const MANIFEST_PLUGIN_ID: &str = "sandtree.mock.provider";

fn component_bytes() -> Vec<u8> {
    let bytes = wat::parse_str(WAT).expect("fixture parses");
    let engine = sandtree_plugin_host::engine::build_engine(
        &sandtree_plugin_host::limits::WorkerLimits::host_ceiling(),
    )
    .expect("engine");
    wasmtime::component::Component::new(&engine, &bytes[..]).expect("fixture validates");
    bytes
}

fn manifest() -> Json {
    serde_json::json!({
        "schema_version": 1,
        "plugin_id": MANIFEST_PLUGIN_ID,
        "version": "1.0.0",
        "kind": "provider",
        "component": "blake3:fixture",
        "license": "Apache-2.0",
        "capabilities": ["resource:discover", "resource:start"],
        "state_schema_version": 1,
        "hot_swap": true,
    })
}

/// A worker with a real component on disk and a policy that allows its license.
fn worker(dir: &std::path::Path) -> Worker {
    let path = dir.join("provider.wasm");
    std::fs::write(&path, component_bytes()).expect("write component");
    Worker::new(WorkerSpec::new(path, manifest(), Generation(1)))
        .with_policy(InstallPolicy::deny_all().allow_license("Apache-2.0"))
}

/// Load the fixture and return the loaded generation plus the worker.
async fn loaded(
    dir: &std::path::Path,
) -> (
    Worker,
    std::sync::Arc<sandtree_plugin_host::LoadedGeneration>,
) {
    let mut w = worker(dir);
    let g = w.load().await.expect("the worker stages a real component");
    (w, g)
}

#[tokio::test]
async fn a_worker_loads_a_real_component_and_reports_its_descriptor() {
    let dir = tempfile::tempdir().unwrap();
    let (w, g) = loaded(dir.path()).await;

    assert_eq!(w.state(), sandtree_plugin_worker::WorkerState::Ready);
    let d = GenerationRuntime::descriptor(&**g.runtime());
    assert_eq!(d.plugin_id, MANIFEST_PLUGIN_ID);
    assert_eq!(d.version, "1.0.0");
    assert_eq!(d.state_schema_version, 1);
}

#[tokio::test]
async fn the_loaded_generation_is_routable_with_a_resource_port() {
    // The point of ADR-016 for a component: staging it must produce something the
    // kernel can send provider traffic to. A generation whose ports are empty is
    // stageable, health-checkable, and useless — the exact "exists but is not
    // delivered" shape.
    let dir = tempfile::tempdir().unwrap();
    let (_w, g) = loaded(dir.path()).await;

    let port = g
        .ports()
        .resource
        .clone()
        .expect("a provider component must arrive with a resource port");
    let batch = port.discover(None).await.expect("discover over the port");
    assert_eq!(batch.resources.len(), 1);
    assert_eq!(batch.resources[0].kind, ResourceKind::Container);
    assert_eq!(batch.resources[0].state, ResourceState::Running);

    assert_eq!(
        GenerationRuntime::health(&**g.runtime())
            .await
            .expect("health"),
        ProviderHealth::Healthy
    );
}

#[tokio::test]
async fn the_resource_port_and_the_lifecycle_runtime_are_one_generation() {
    // Two different `Arc`s wrapping two different component instances would let a
    // routed request hit a generation whose lifecycle the supervisor is draining.
    // The worker must attach the port it already has, not load a second copy.
    let dir = tempfile::tempdir().unwrap();
    let (_w, g) = loaded(dir.path()).await;

    let port = g.ports().resource.clone().expect("resource port");
    let descriptor_via_port = port.descriptor();
    let descriptor_via_runtime = GenerationRuntime::descriptor(&**g.runtime());
    assert_eq!(
        descriptor_via_port.plugin_id,
        descriptor_via_runtime.plugin_id
    );
    assert_eq!(descriptor_via_port.version, descriptor_via_runtime.version);
}

#[tokio::test]
async fn the_generation_number_the_worker_was_given_is_the_one_it_reports() {
    // The route table is the authority on which generation serves; a worker that
    // invented its own number would make a swap a no-op that looks successful.
    let dir = tempfile::tempdir().unwrap();
    let (_w, g) = loaded(dir.path()).await;
    assert_eq!(g.generation(), Generation(1));
    assert_eq!(
        GenerationRuntime::generation(&**g.runtime()),
        Generation(1),
        "the lifecycle view and the route view must agree"
    );
}

#[tokio::test]
async fn initialising_then_serving_is_the_order_a_real_install_uses() {
    let dir = tempfile::tempdir().unwrap();
    let (mut w, g) = loaded(dir.path()).await;

    w.initialise(&serde_json::json!({"endpoint": "local"}))
        .await
        .expect("init");
    assert_eq!(w.state(), sandtree_plugin_worker::WorkerState::Initialised);

    let req = OperationRequest::new(
        g.ports()
            .resource
            .as_ref()
            .map(|_| sandtree_model::id::ResourceId::derive(&["mock", "container", "1"]))
            .expect("port"),
        OperationKind::Start,
        serde_json::json!({}),
        Correlation::generate(),
    );
    let outcome = g
        .ports()
        .resource
        .as_ref()
        .expect("port")
        .invoke(&req)
        .await
        .expect("invoke");
    assert_eq!(outcome.state, OperationState::Succeeded);
}

#[tokio::test]
async fn retiring_drains_and_shuts_the_generation_down() {
    // Retirement is the only thing that runs a guest's `lifecycle.shutdown`. If
    // it silently stopped, a swapped-out component would keep its WASM store
    // alive for the life of the process and no test would notice.
    let dir = tempfile::tempdir().unwrap();
    let (mut w, _g) = loaded(dir.path()).await;

    w.retire().await;

    assert_eq!(w.state(), sandtree_plugin_worker::WorkerState::Retired);
    assert!(w.loaded().is_none(), "a retired worker keeps no generation");
    assert!(w.runtime().is_none());
}

#[tokio::test]
async fn a_package_whose_license_is_refused_never_reaches_the_engine() {
    // Verification precedes loading on purpose: a package that fails the license
    // check must not be able to run a single instruction.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("provider.wasm");
    std::fs::write(&path, component_bytes()).expect("write component");

    let mut w = Worker::new(WorkerSpec::new(path, manifest(), Generation(1)))
        .with_policy(InstallPolicy::deny_all().allow_license("MIT"));

    let err = w
        .load()
        .await
        .expect_err("Apache-2.0 is not in the allow-list");
    assert_eq!(
        err.code,
        sandtree_model::error::ErrorCode::PLUGIN_MANIFEST_INVALID
    );
    assert_eq!(w.state(), sandtree_plugin_worker::WorkerState::Idle);
}
