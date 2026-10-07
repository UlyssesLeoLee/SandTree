//! `plugin.install` over a real component, end to end.
//!
//! # What is being claimed
//!
//! The daemon's plugin endpoints used to answer `not_served`, and after ADR-016
//! they were wired — but with a loader that refused, which is a different way of
//! saying the same thing. Everything below this line was correct and unreachable:
//! the swap supervisor, the route table, the rollback reserve, and a component
//! that genuinely binds.
//!
//! So this drives the whole path against a real package on disk: index it,
//! verify the license, load the component, publish it atomically, route traffic
//! to it, move to a new generation, roll back, and disable. Nothing is stubbed.
//!
//! # What is still not claimed
//!
//! Process isolation (FR-055). The loader stages in this process (ADR-018), so
//! this proves *the control plane can install and serve a real component*, not
//! that a crashing worker is contained. Those are different properties and
//! conflating them is exactly the "exists but is not delivered" shape this repo
//! keeps removing.

use std::path::Path;
use std::sync::Arc;

use sandtree_daemon::loader::{DirectoryPackages, WorkerLoader, COMPONENT_FILE, MANIFEST_FILE};
use sandtree_daemon::plugins::PluginControl;
use sandtree_model::id::PluginId;
use sandtree_model::resource::{ResourceKind, ResourceState};
use sandtree_plugin_host::route::{Generation, RouteTable};
use sandtree_plugin_host::verify::InstallPolicy;
use serde_json::Value as Json;

const WAT: &str = include_str!("../fixtures/valid_provider_component.wat");

/// The reverse-domain name the fixture's manifest declares.
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

fn manifest_json() -> String {
    serde_json::to_string_pretty(&serde_json::json!({
        "schema_version": 1,
        "plugin_id": PACKAGE_NAME,
        "version": "1.0.0",
        "kind": "provider",
        "component": "blake3:fixture",
        "license": "Apache-2.0",
        "capabilities": ["resource:discover", "resource:start"],
        "state_schema_version": 1,
        "hot_swap": true,
    }))
    .expect("manifest serializes")
}

/// Drop a package into `root` under a directory an operator would choose.
fn install_package(root: &Path, license: &str) {
    let dir = root.join("mock-provider");
    std::fs::create_dir_all(&dir).expect("mkdir");
    let manifest = manifest_json().replace("Apache-2.0", license);
    std::fs::write(dir.join(MANIFEST_FILE), manifest).expect("manifest");
    std::fs::write(dir.join(COMPONENT_FILE), component_bytes()).expect("component");
}

/// A control plane whose loader really stages, with a license allow-list.
fn control(root: &Path) -> (Arc<RouteTable>, PluginControl) {
    let source = DirectoryPackages::new(root).expect("index");
    let loader = WorkerLoader::new(
        Arc::new(source),
        InstallPolicy::deny_all().allow_license("Apache-2.0"),
        sandtree_model::capability::CapabilitySet::empty(),
        sandtree_plugin_host::limits::WorkerLimits::host_ceiling(),
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

/// The node the routed generation must serve, read through its resource port.
async fn routed_node(routes: &RouteTable) -> sandtree_model::resource::ResourceNode {
    let g = routes.current(&plugin()).expect("a routed generation");
    g.ports()
        .resource
        .clone()
        .expect("a provider generation must carry a resource port")
        .inspect(&sandtree_model::id::ResourceId::derive(&[
            "mock",
            "container",
            "1",
        ]))
        .await
        .expect("inspect through the routed port")
}

#[tokio::test]
async fn installing_a_package_publishes_it_and_routes_provider_traffic_to_it() {
    let tmp = tempfile::tempdir().unwrap();
    install_package(tmp.path(), "Apache-2.0");
    let (routes, c) = control(tmp.path());

    let r = c.install(&plugin(), &Json::Null).await.expect("install");

    assert!(r.outcome.swapped, "{:?}", r.trace.steps);
    assert_eq!(routes.current_generation(&plugin()), Some(Generation(1)));

    // The point of the whole path: a routed request reaches the component.
    let node = routed_node(&routes).await;
    assert_eq!(node.kind, ResourceKind::Container);
    assert_eq!(node.state, ResourceState::Running);
    assert_eq!(node.name, "mock-container");
}

#[tokio::test]
async fn installing_the_same_plugin_twice_is_refused_and_names_hotswap() {
    let tmp = tempfile::tempdir().unwrap();
    install_package(tmp.path(), "Apache-2.0");
    let (routes, c) = control(tmp.path());
    c.install(&plugin(), &Json::Null)
        .await
        .expect("first install");

    let err = c
        .install(&plugin(), &Json::Null)
        .await
        .expect_err("already installed");

    assert_eq!(
        err.code,
        sandtree_model::error::ErrorCode::PLUGIN_HOTSWAP_REJECTED
    );
    assert!(err.message.contains("plugin.hotswap"), "{}", err.message);
    assert_eq!(
        routes.current_generation(&plugin()),
        Some(Generation(1)),
        "a refused install must leave the live generation alone"
    );
}

#[tokio::test]
async fn a_swap_stages_a_fresh_component_and_rollback_returns_to_the_first() {
    let tmp = tempfile::tempdir().unwrap();
    install_package(tmp.path(), "Apache-2.0");
    let (routes, c) = control(tmp.path());

    c.install(&plugin(), &Json::Null).await.expect("gen 1");
    let first = routes.current(&plugin()).expect("gen 1 routed");
    assert_eq!(first.generation(), Generation(1));

    c.hotswap(&plugin(), true, &Json::Null)
        .await
        .expect("gen 2")
        .outcome
        .swapped
        .then_some(())
        .expect("swap happened");
    assert_eq!(routes.current_generation(&plugin()), Some(Generation(2)));
    assert_eq!(c.rollback_target(&plugin()).await, Some(Generation(1)));

    // The swapped-in generation must also serve, not merely be routed.
    let node = routed_node(&routes).await;
    assert_eq!(node.name, "mock-container");

    let outcome = c.rollback(&plugin()).await;
    assert!(outcome.swapped, "{}", outcome.reason);
    assert_eq!(routes.current_generation(&plugin()), Some(Generation(1)));
    assert!(
        Arc::ptr_eq(&first, &routes.current(&plugin()).expect("restored")),
        "rollback must restore the very generation that was displaced, not a reloaded one"
    );
}

#[tokio::test]
async fn disabling_stops_routing_and_leaves_no_rollback_behind() {
    let tmp = tempfile::tempdir().unwrap();
    install_package(tmp.path(), "Apache-2.0");
    let (routes, c) = control(tmp.path());
    c.install(&plugin(), &Json::Null).await.expect("gen 1");
    c.hotswap(&plugin(), true, &Json::Null)
        .await
        .expect("gen 2");

    assert!(c.disable(&plugin()).await);

    assert!(routes.current(&plugin()).is_none());
    assert_eq!(c.rollback_target(&plugin()).await, None);
    assert!(!c.disable(&plugin()).await, "disabling twice is a no-op");
}

#[tokio::test]
async fn a_package_whose_license_is_refused_never_becomes_routable() {
    // The refusal has to happen before anything is published. A daemon that
    // loaded first and checked the license second would have already run guest
    // code from an unapproved package.
    let tmp = tempfile::tempdir().unwrap();
    install_package(tmp.path(), "GPL-3.0-only");
    let (routes, c) = control(tmp.path());

    let err = c
        .install(&plugin(), &Json::Null)
        .await
        .expect_err("license not allowed");

    assert_eq!(
        err.code,
        sandtree_model::error::ErrorCode::PLUGIN_MANIFEST_INVALID
    );
    assert!(err.message.contains("GPL-3.0-only"), "{}", err.message);
    assert!(routes.current(&plugin()).is_none());
    assert_eq!(c.rollback_target(&plugin()).await, None);
}

#[tokio::test]
async fn installing_a_plugin_that_is_not_on_disk_routes_nothing() {
    // The default daemon answers this with "no loader configured". With a real
    // loader the answer must be *more* specific, and the refusal must still be
    // a refusal rather than an empty success.
    let tmp = tempfile::tempdir().unwrap();
    let (routes, c) = control(tmp.path());

    let err = c
        .install(&plugin(), &Json::Null)
        .await
        .expect_err("nothing installed");

    assert!(
        err.message.contains("no package for plugin"),
        "{}",
        err.message
    );
    assert!(routes.current(&plugin()).is_none());
}
