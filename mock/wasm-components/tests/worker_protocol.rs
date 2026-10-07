//! The daemon↔worker protocol, driven end to end over a real component.
//!
//! # What this is
//!
//! `daemon_install.rs` (ADR-018) stages in the daemon process. This drives the
//! same control plane against a `WorkerServer` reached over a transport, so
//! every generation is loaded, called and retired by code that only ever sees
//! JSON. The daemon side has no wasmtime in this path at all: a `WorkerClient`
//! looks exactly like a `LoadedGeneration` from above.
//!
//! # What it is not
//!
//! Process isolation is still not here — the worker runs as a task in this
//! process over the loopback transport. Spawning a subprocess and a Windows
//! named-pipe client are the remaining pieces (ADR-019 §4). Testing the protocol
//! before testing the plumbing is deliberate: a bug found here is a bug that
//! would otherwise surface as "the daemon hangs" through two more layers.

use std::path::Path;
use std::sync::Arc;

use sandtree_daemon::packages::{DirectoryPackages, COMPONENT_FILE, MANIFEST_FILE};
use sandtree_daemon::plugins::PluginControl;
use sandtree_daemon::worker_client::RemoteLoader;
use sandtree_ipc::loopback::loopback_pair;
use sandtree_ipc::transport::Transport;
use sandtree_model::id::{PluginId, ResourceId};
use sandtree_model::operation::{OperationKind, OperationRequest};
use sandtree_model::resource::Correlation;
use sandtree_plugin_host::hot_swap::GenerationRuntime;
use sandtree_plugin_host::route::{Generation, RouteTable};
use sandtree_plugin_host::verify::InstallPolicy;
use sandtree_plugin_worker::serve::WorkerServer;
use sandtree_sdk::ports::ProviderHealth;
use serde_json::Value as Json;

const WAT: &str = include_str!("../fixtures/valid_provider_component.wat");
const PACKAGE_NAME: &str = "sandtree.mock.provider";

fn plugin() -> PluginId {
    PluginId::derive(&[PACKAGE_NAME])
}

fn component_bytes() -> Vec<u8> {
    let bytes = wat::parse_str(WAT).expect("fixture parses");
    let engine = sandtree_plugin_host::engine::build_engine(
        &sandtree_plugin_host::limits::WorkerLimits::host_ceiling(),
    )
    .expect("engine");
    wasmtime::component::Component::new(&engine, &bytes[..]).expect("fixture validates");
    bytes
}

fn install_package(root: &Path, license: &str) {
    let dir = root.join("mock-provider");
    std::fs::create_dir_all(&dir).expect("mkdir");
    std::fs::write(
        dir.join(MANIFEST_FILE),
        serde_json::to_string_pretty(&serde_json::json!({
            "schema_version": 1,
            "plugin_id": PACKAGE_NAME,
            "version": "1.0.0",
            "kind": "provider",
            "component": "blake3:fixture",
            "license": license,
            "capabilities": ["resource:discover", "resource:start"],
            "state_schema_version": 1,
            "hot_swap": true,
        }))
        .unwrap(),
    )
    .expect("manifest");
    std::fs::write(dir.join(COMPONENT_FILE), component_bytes()).expect("component");
}

/// A control plane whose loader reaches a worker over a transport.
///
/// Each generation gets its **own** pair and its own server task, which is the
/// shape the production spawner has: two generations of one plugin must not
/// share a store, and the only way to guarantee that structurally is to give
/// each one its own worker.
fn remote_control(root: &Path, license: &str) -> (Arc<RouteTable>, PluginControl) {
    let source = Arc::new(DirectoryPackages::new(root).expect("index"));
    let loader = RemoteLoader::new(
        source,
        InstallPolicy::deny_all().allow_license(license),
        sandtree_model::capability::CapabilitySet::empty(),
        sandtree_plugin_host::limits::WorkerLimits::host_ceiling(),
        move || {
            let (client, server) = loopback_pair();
            tokio::spawn(async move {
                // A worker that panics must not take the test with it; the
                // connection dropping is what the client sees.
                let mut server: Box<dyn Transport> = Box::new(server);
                let _ = WorkerServer::new().serve(&mut *server).await;
            });
            Box::new(client) as Box<dyn Transport>
        },
    );
    let routes = Arc::new(RouteTable::new());
    (
        routes.clone(),
        PluginControl::new(
            routes,
            sandtree_plugin_host::limits::WorkerLimits::host_ceiling(),
            Arc::new(loader),
        ),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn installing_over_the_protocol_routes_traffic_that_reaches_the_component() {
    let tmp = tempfile::tempdir().unwrap();
    install_package(tmp.path(), "Apache-2.0");
    let (routes, c) = remote_control(tmp.path(), "Apache-2.0");

    let r = c.install(&plugin(), &Json::Null).await.expect("install");
    assert!(r.outcome.swapped, "{:?}", r.trace.steps);

    let g = routes.current(&plugin()).expect("routed");
    assert_eq!(g.generation(), Generation(1));
    assert_eq!(
        GenerationRuntime::generation(&**g.runtime()),
        Generation(1),
        "the generation number must survive the crossing, not be re-invented locally"
    );

    let port = g.ports().resource.clone().expect("resource port");
    let batch = port.discover(None).await.expect("discover over the wire");
    assert_eq!(batch.resources.len(), 1);
    assert_eq!(batch.resources[0].name, "mock-container");

    let node = port
        .inspect(&ResourceId::derive(&["mock", "container", "1"]))
        .await
        .expect("inspect over the wire");
    assert_eq!(node.state, sandtree_model::resource::ResourceState::Running);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_lifecycle_survives_the_crossing_including_health_and_migration() {
    let tmp = tempfile::tempdir().unwrap();
    install_package(tmp.path(), "Apache-2.0");
    let (routes, c) = remote_control(tmp.path(), "Apache-2.0");
    c.install(&plugin(), &Json::Null).await.expect("install");
    let g = routes.current(&plugin()).expect("routed");

    let descriptor = GenerationRuntime::descriptor(&**g.runtime());
    assert_eq!(descriptor.plugin_id, PACKAGE_NAME);
    assert_eq!(descriptor.version, "1.0.0");
    assert_eq!(descriptor.state_schema_version, 1);

    let health = GenerationRuntime::health(&**g.runtime())
        .await
        .expect("health");
    assert_eq!(health, ProviderHealth::Healthy);

    let state = GenerationRuntime::prepare_upgrade(&**g.runtime(), "1.1.0")
        .await
        .expect("prepare-upgrade");
    assert!(state.is_empty());
    GenerationRuntime::accept_upgrade(&**g.runtime(), "1.0.0", &state)
        .await
        .expect("accept-upgrade");
    GenerationRuntime::drain(&**g.runtime(), 1_000)
        .await
        .expect("drain");
}

#[tokio::test(flavor = "multi_thread")]
async fn invoke_crosses_with_the_whole_request_intact() {
    let tmp = tempfile::tempdir().unwrap();
    install_package(tmp.path(), "Apache-2.0");
    let (routes, c) = remote_control(tmp.path(), "Apache-2.0");
    c.install(&plugin(), &Json::Null).await.expect("install");
    let g = routes.current(&plugin()).expect("routed");

    let req = OperationRequest::new(
        ResourceId::derive(&["mock", "container", "1"]),
        OperationKind::Start,
        serde_json::json!({}),
        Correlation::generate(),
    )
    .with_deadline_ms(2_000);

    let outcome = g
        .ports()
        .resource
        .clone()
        .expect("port")
        .invoke(&req)
        .await
        .expect("invoke over the wire");
    assert_eq!(
        outcome.state,
        sandtree_model::operation::OperationState::Succeeded
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_worker_refusal_keeps_its_stable_code_across_the_wire() {
    // The whole reason errors are values rather than disconnects: a host that
    // flattened "the plugin's license is not allowed" into a generic failure
    // would send an operator looking for a transport bug that does not exist.
    let tmp = tempfile::tempdir().unwrap();
    install_package(tmp.path(), "GPL-3.0-only");
    let (routes, c) = remote_control(tmp.path(), "Apache-2.0");

    let err = c
        .install(&plugin(), &Json::Null)
        .await
        .expect_err("license refused");

    assert_eq!(
        err.code,
        sandtree_model::error::ErrorCode::PLUGIN_MANIFEST_INVALID
    );
    assert!(err.message.contains("GPL-3.0-only"), "{}", err.message);
    assert!(routes.current(&plugin()).is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_swap_moves_to_a_second_worker_and_rollback_comes_back_to_the_first() {
    // Two generations, two workers, two stores. The rollback assertion is the
    // strong one: the restored generation must be the very instance that was
    // displaced, not an equal-looking re-stage.
    let tmp = tempfile::tempdir().unwrap();
    install_package(tmp.path(), "Apache-2.0");
    let (routes, c) = remote_control(tmp.path(), "Apache-2.0");

    c.install(&plugin(), &Json::Null).await.expect("gen 1");
    let first = routes.current(&plugin()).expect("gen 1");
    c.hotswap(&plugin(), true, &Json::Null)
        .await
        .expect("gen 2");
    assert_eq!(routes.current_generation(&plugin()), Some(Generation(2)));

    let port = routes
        .current(&plugin())
        .expect("gen 2")
        .ports()
        .resource
        .clone()
        .expect("port");
    assert_eq!(
        port.discover(None)
            .await
            .expect("gen 2 serves")
            .resources
            .len(),
        1,
        "the swapped-in generation must serve, not merely be routed"
    );

    c.rollback(&plugin()).await;
    assert_eq!(routes.current_generation(&plugin()), Some(Generation(1)));
    assert!(
        Arc::ptr_eq(&first, &routes.current(&plugin()).expect("restored")),
        "rollback must restore the displaced instance"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_worker_that_disappears_is_a_typed_failure_not_an_empty_result() {
    // ADR-OBS-001: a dead worker must report unavailable. Returning an empty
    // batch would tell the operator "this provider has no resources", which is
    // a different and wrong claim.
    let tmp = tempfile::tempdir().unwrap();
    install_package(tmp.path(), "Apache-2.0");
    let source = Arc::new(DirectoryPackages::new(tmp.path()).expect("index"));
    // A transport that accepts the request and then drops the connection. The
    // package on disk is valid, so the only thing that can fail here is the
    // worker -- which is the point.
    let loader = RemoteLoader::new(
        source,
        InstallPolicy::deny_all().allow_license("Apache-2.0"),
        sandtree_model::capability::CapabilitySet::empty(),
        sandtree_plugin_host::limits::WorkerLimits::host_ceiling(),
        || {
            let (client, server) = loopback_pair();
            tokio::spawn(async move {
                drop(server);
            });
            Box::new(client) as Box<dyn Transport>
        },
    );
    let routes = Arc::new(RouteTable::new());
    let c = PluginControl::new(
        routes.clone(),
        sandtree_plugin_host::limits::WorkerLimits::host_ceiling(),
        Arc::new(loader),
    );

    let err = c
        .install(&plugin(), &Json::Null)
        .await
        .expect_err("the worker vanished");
    assert_eq!(
        err.code,
        sandtree_model::error::ErrorCode::PLUGIN_HEALTH_FAILED
    );
    assert!(err.message.contains("load"), "{}", err.message);
    assert!(routes.current(&plugin()).is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_worker_already_gone_is_the_same_failure_as_one_that_dies_mid_call() {
    // The same event as the test above, reached the other way round: here the
    // peer is dropped *before* the host writes, so `send` fails instead of `recv`
    // reaching end of stream.
    //
    // It is deterministic rather than raced on purpose. The defect this pins is
    // that the two used to surface under different codes -- the transport's own
    // `CORE_INVALID` for the write failure, `PLUGIN_HEALTH_FAILED` for the end of
    // stream -- so which code the operator saw depended on a scheduling detail.
    // Asserting the raced version alone would have passed about half the time and
    // hidden it the other half.
    let tmp = tempfile::tempdir().unwrap();
    install_package(tmp.path(), "Apache-2.0");
    let source = Arc::new(DirectoryPackages::new(tmp.path()).expect("index"));
    let loader = RemoteLoader::new(
        source,
        InstallPolicy::deny_all().allow_license("Apache-2.0"),
        sandtree_model::capability::CapabilitySet::empty(),
        sandtree_plugin_host::limits::WorkerLimits::host_ceiling(),
        || {
            let (client, server) = loopback_pair();
            drop(server);
            Box::new(client) as Box<dyn Transport>
        },
    );
    let routes = Arc::new(RouteTable::new());
    let c = PluginControl::new(
        routes.clone(),
        sandtree_plugin_host::limits::WorkerLimits::host_ceiling(),
        Arc::new(loader),
    );

    let err = c
        .install(&plugin(), &Json::Null)
        .await
        .expect_err("there was never a worker to talk to");
    assert_eq!(
        err.code,
        sandtree_model::error::ErrorCode::PLUGIN_HEALTH_FAILED,
        "a worker that cannot be written to and a worker that stops answering are \
         one event and must not carry different codes"
    );
    assert!(err.message.contains("load"), "{}", err.message);
    assert!(routes.current(&plugin()).is_none());
}
