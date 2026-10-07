//! End-to-end proof that a WASM component can actually serve provider traffic.
//!
//! # What this closes
//!
//! The host's `ResourceProvider` adapter had no test that *drove* it. Its decode
//! contract was unit-tested against strings, which proves `serde` behaves but
//! proves nothing about the guest: an adapter that never reaches wasmtime and an
//! adapter that reaches it and mis-lays the canonical ABI look identical from the
//! outside.
//!
//! So this drives the real path — compile the fixture, instantiate the
//! `provider-plugin` world, call every exported function, and assert on what
//! comes back. The adapter's propagation is covered here, or it is not covered at
//! all.
//!
//! # Why the fixture is in `mock`
//!
//! The component is a hand-written `.wat` regression input, so it belongs to the
//! mock project. The dependency direction is therefore mock -> product: this test
//! crate depends on `sandtree-plugin-host` (with `wasmtime-abi`) and the model /
//! SDK crates. No product crate depends on this one.
//!
//! # Drift
//!
//! The fixture embeds JSON literals in a WAT data segment, and a DTO that gains
//! or renames a field would silently make those literals wrong. The decode
//! assertions below would still pass if the literals were merely *consistent*,
//! so [`the_valid_fixture_matches_the_dtos_it_embeds`] re-derives the literals
//! from the product DTOs and fails if the fixture no longer carries them.

use std::sync::Arc;

use sandtree_model::capability::CapabilitySet;
use sandtree_model::id::{PluginId, ResourceId};
use sandtree_model::operation::{
    OperationKind, OperationOutcome, OperationRequest, OperationState,
};
use sandtree_model::resource::{Correlation, ResourceKind, ResourceNode, ResourceState};
use sandtree_plugin_host::engine::ComponentGeneration;
use sandtree_plugin_host::hot_swap::GenerationRuntime;
use sandtree_plugin_host::limits::WorkerLimits;
use sandtree_plugin_host::route::Generation;
use sandtree_sdk::manifest::PluginKind;
use sandtree_sdk::ports::{DiscoverBatch, ProviderHealth, ResourceProvider};

/// Compile WAT text into component **binary** bytes.
///
/// Not `Component::serialize`: that produces a native object file (it starts
/// `\x7fELF` here), and feeding it back to `Component::new` fails with
/// `input bytes aren't valid utf-8`. A host is handed binary, so the corpus must
/// produce binary.
fn compile(wat: &str) -> Vec<u8> {
    let bytes = wat::parse_str(wat).expect("fixture parses");
    let engine = sandtree_plugin_host::engine::build_engine(&LIMITS).expect("engine");
    wasmtime::component::Component::new(&engine, &bytes[..]).expect("fixture validates");
    bytes
}

/// The generated component under test.
const WAT: &str = include_str!("../fixtures/valid_provider_component.wat");

const LIMITS: WorkerLimits = WorkerLimits {
    fuel: 1_000_000,
    memory_bytes: 16 * 1024 * 1024,
    wall_clock_ms: 5_000,
    max_inflight: 1,
};

/// Identity the fixture's `descriptor` reports.
const FIXTURE_PLUGIN_ID: &str = "sandtree.mock.provider";
const FIXTURE_VERSION: &str = "1.0.0";

/// The resource id the fixture serves, derived exactly as `the_reference_node`
/// derives it.
fn fixture_resource_id() -> ResourceId {
    ResourceId::derive(&["mock", "container", "1"])
}

/// The `ResourceNode` the fixture claims to serve, built from the product DTOs
/// rather than from a hand-written literal.
fn the_reference_node() -> ResourceNode {
    ResourceNode::new(
        ResourceId::derive(&["mock", "container", "1"]),
        ResourceKind::Container,
        PluginId::derive(&["sandtree.mock.provider"]),
        "mock-container",
        ResourceState::Running,
        None,
        "2026-10-08T00:00:00Z".to_string(),
    )
    .with_capabilities(CapabilitySet::empty())
    .with_metadata(serde_json::json!({"image": "alpine:3.20"}))
}

fn the_reference_batch() -> DiscoverBatch {
    DiscoverBatch {
        resources: vec![the_reference_node()],
        relations: vec![],
        cursor: None,
    }
}

fn the_reference_outcome() -> OperationOutcome {
    OperationOutcome {
        state: OperationState::Succeeded,
        error_code: None,
        result: serde_json::json!({"message": "ok"}),
    }
}

async fn load_fixture() -> Arc<ComponentGeneration> {
    let engine = sandtree_plugin_host::engine::build_engine(&LIMITS).expect("engine");
    let bytes = compile(WAT);
    ComponentGeneration::load(
        &engine,
        &bytes,
        CapabilitySet::empty(),
        LIMITS,
        Generation(1),
        PluginKind::Provider,
    )
    .await
    .expect("fixture binds the provider-plugin world")
}

/// A guest reply the host cannot decode must be a typed failure.
///
/// ADR-OBS-001 forbids folding a broken provider into "no resources found", and
/// that is a property of the *adapter*, not of `serde`. Binding is where a
/// component that does not implement the world has to be refused: a plugin that
/// cannot serve the world must never reach the route table.
#[tokio::test]
async fn a_component_that_cannot_bind_is_rejected_before_it_serves_anything() {
    let engine = sandtree_plugin_host::engine::build_engine(&LIMITS).expect("engine");
    // Compiles as a component and exports nothing of ours.
    let bytes = wat::parse_str(
        r#"(
            component
                (core module $m (func (export "f") nop))
                (core instance $i (instantiate $m))
                (func (export "f") (canon lift (core func $i "f")))
            )"#,
    )
    .expect("parses");

    let err = ComponentGeneration::load(
        &engine,
        &bytes,
        CapabilitySet::empty(),
        LIMITS,
        Generation(1),
        PluginKind::Provider,
    )
    .await
    .expect_err("a component missing both SandTree interfaces must not load");

    let text = err.to_string();
    assert!(
        text.contains("provider-plugin"),
        "the failure must name the world that was missing, got: {text}"
    );
}

#[tokio::test]
async fn the_fixture_reports_the_descriptor_the_host_stores() {
    let g = load_fixture().await;

    let d = GenerationRuntime::descriptor(&*g);
    assert_eq!(d.plugin_id, FIXTURE_PLUGIN_ID);
    assert_eq!(d.version, FIXTURE_VERSION);
    assert_eq!(d.state_schema_version, 1);

    let pd = ResourceProvider::descriptor(&*g);
    assert_eq!(pd.plugin_id, FIXTURE_PLUGIN_ID);
    assert_eq!(pd.version, FIXTURE_VERSION);
    assert_eq!(pd.kind, PluginKind::Provider);
}

#[tokio::test]
async fn every_lifecycle_call_round_trips_through_the_canonical_abi() {
    let g = load_fixture().await;

    GenerationRuntime::init(&*g, &serde_json::json!({"endpoint": "local"}))
        .await
        .expect("init");
    assert_eq!(
        GenerationRuntime::health(&*g).await.expect("health"),
        ProviderHealth::Healthy,
        "health must be interpreted from the guest status JSON, not defaulted"
    );

    let state = GenerationRuntime::prepare_upgrade(&*g, "1.1.0")
        .await
        .expect("prepare-upgrade");
    assert!(state.is_empty(), "the fixture exports no migration state");

    GenerationRuntime::accept_upgrade(&*g, "1.0.0", &state)
        .await
        .expect("accept-upgrade");

    GenerationRuntime::drain(&*g, 1_000).await.expect("drain");

    GenerationRuntime::shutdown(&*g).await;
}

#[tokio::test]
async fn discover_returns_the_batch_the_guest_actually_embedded() {
    let g = load_fixture().await;

    let batch = ResourceProvider::discover(&*g, None)
        .await
        .expect("discover");

    assert_eq!(batch, the_reference_batch());
    assert_eq!(batch.resources.len(), 1);
    let node = &batch.resources[0];
    assert_eq!(node.id, fixture_resource_id());
    assert_eq!(node.kind, ResourceKind::Container);
    assert_eq!(node.state, ResourceState::Running);
    assert_eq!(node.name, "mock-container");
    assert_eq!(node.meta_str("image"), Some("alpine:3.20"));
}

#[tokio::test]
async fn a_discovered_page_is_followable_to_completion() {
    let g = load_fixture().await;
    let batch = ResourceProvider::discover(&*g, Some("page-2".to_string()))
        .await
        .expect("discover with a cursor still decodes");
    assert!(batch.cursor.is_none(), "the fixture reports one page");
}

#[tokio::test]
async fn inspect_returns_the_node_for_the_requested_id() {
    let g = load_fixture().await;
    let node = ResourceProvider::inspect(&*g, &fixture_resource_id())
        .await
        .expect("inspect");
    assert_eq!(node, the_reference_node());
}

#[tokio::test]
async fn invoke_returns_the_operation_outcome() {
    let g = load_fixture().await;
    let req = OperationRequest::new(
        fixture_resource_id(),
        OperationKind::Start,
        serde_json::json!({}),
        Correlation::generate(),
    );
    let outcome = ResourceProvider::invoke(&*g, &req).await.expect("invoke");
    assert_eq!(outcome, the_reference_outcome());
}

/// The fixture's literals must be exactly what the product DTOs serialize to.
///
/// This is the anti-drift assertion. Everything else here can stay green while
/// the fixture quietly stops matching the DTOs, because a stale literal is still
/// self-consistent JSON — only comparing against `serde`'s output catches it.
#[test]
fn the_valid_fixture_matches_the_dtos_it_embeds() {
    let cases: [(&str, String); 4] = [
        (
            "discover",
            serde_json::to_string(&the_reference_batch()).unwrap(),
        ),
        (
            "inspect",
            serde_json::to_string(&the_reference_node()).unwrap(),
        ),
        (
            "invoke",
            serde_json::to_string(&the_reference_outcome()).unwrap(),
        ),
        ("health", r#"{"state":"healthy"}"#.to_string()),
    ];

    for (name, json) in cases {
        // The fixture stores literals in a WAT data segment, so quotes and
        // backslashes are escaped there.
        let escaped = json.replace('\\', "\\\\").replace('"', "\\\"");
        assert!(
            WAT.contains(&escaped),
            "the `{name}` literal in valid_provider_component.wat has drifted from the \
             product DTO. Re-run mock/scripts/gen_fixtures.ps1.\n  expected: {json}"
        );
    }
}

/// Offsets in the fixture are hand-maintained by the generator, so a length slip
/// would surface as a garbled string rather than a compile error. This reads the
/// data segment lengths back out of the compiled component and checks each one
/// against the literal it is supposed to describe.
#[test]
fn the_generated_fixture_declares_one_data_segment_per_literal() {
    // Six literals: plugin id, version, health, discover, inspect, invoke.
    let segments = WAT
        .lines()
        .filter(|l| l.trim_start().starts_with("(data "))
        .count();
    assert_eq!(
        segments, 6,
        "the generator writes one data segment per served literal; a count change \
         means the fixture and gen_provider_fixture.ps1 have diverged"
    );
}
