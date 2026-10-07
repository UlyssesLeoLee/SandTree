//! UAT: the machine-checkable half of the 23 acceptance cases.
//!
//! # What this is and is not
//!
//! The design records all 23 UAT cases as `Automation = No`, and that stays
//! true: an acceptance case needs a UAT machine, a real Docker/Sandbox setup
//! and an operator who judges whether the product is understandable. None of
//! that is faked here, and no test in this file claims to have replaced it.
//!
//! What this crate does is put an automated floor under the half of each case
//! that *is* a contract rather than a judgement. Every UAT case has one:
//!
//! | case | the judgement | the contract this file checks |
//! | --- | --- | --- |
//! | UAT-001 tree | "clearly grouped" | the tree is well formed and deterministically ordered |
//! | UAT-017 dangerous actions | "impact + confirm shown" | the refusal happens and names itself |
//! | UAT-022 trust | "understandable" | trust is reported, ordered and never rises |
//! | UAT-023 degraded | "reason and fallback shown" | the plane reports the state instead of raising |
//!
//! Without that floor, a regression in any of those contracts is found by a
//! person, on a UAT machine, at the end of a release — which is the same as not
//! finding it. With it, the human is confirming behaviour, not discovering that
//! `destroy` stopped asking.
//!
//! # Why the mock crates
//!
//! The acceptance environments are exactly what is missing here: no Docker
//! daemon, no Multipass, no Windows Sandbox, no wasm32 toolchain. The mock
//! crates serve the same ports with a scripted world, so the control and
//! observation contracts are exercised for real rather than described.
//!
//! Each test names the design case it carries. `mock/scripts/case_map.csv`
//! records the same mapping, and the regression harness turns both into
//! `mock/evidence/coverage_matrix.csv` — which is where a case with no
//! automated floor becomes visible instead of quietly assumed.

#![deny(missing_docs)]

use std::collections::BTreeSet;
use std::sync::Arc;

use sandtree_mock_observation::provider::snapshot_trust;
use sandtree_mock_observation::ScriptedObservation;
use sandtree_mock_runtime::file_provider::workspace_uri;
use sandtree_mock_runtime::resource_provider::ScriptedResourceProvider;
use sandtree_mock_runtime::{discover_all, fixtures, ScriptedExecProvider, ScriptedWorld};
use sandtree_model::capability::{Capability, CapabilitySet};
use sandtree_model::error::ErrorCode;
use sandtree_model::id::{EndpointId, ResourceId, SnapshotId};
use sandtree_model::operation::{OperationKind, OperationRequest, OperationState};
use sandtree_model::resource::Correlation;
use sandtree_observation_model::{ContentHashState, FileMetadata, ObservationRequest, TrustLevel};
use sandtree_sdk::ports::{ExecProvider, ObservationProvider, ProviderHealth, ResourceProvider};
use sandtree_store::repo::{DockerEndpointRow, SnapshotManifest};
use sandtree_vfs::ReadWindow;

/// The shipped observation corpus, compiled in so a missing fixture is a build
/// failure rather than a runtime surprise on a UAT machine.
const OBSERVATION_CORPUS: &str = include_str!("../../../mock/fixtures/observation-scenarios.json");

fn docker_world() -> ScriptedWorld {
    ScriptedWorld::from_json_str(fixtures::DOCKER_WORLD).expect("the docker world loads")
}

fn port(world: ScriptedWorld) -> Arc<dyn ResourceProvider> {
    Arc::new(ScriptedResourceProvider::new(world.into_shared()))
}

fn web() -> ResourceId {
    ResourceId::derive(&["abc123def456"])
}

fn invoke(id: &ResourceId, op: OperationKind, args: serde_json::Value) -> OperationRequest {
    OperationRequest::new(id.clone(), op, args, Correlation::generate())
}

// --- UAT-001: the tree -------------------------------------------------------

/// UAT-001 — the tree an operator is shown is well formed and stable.
///
/// The judgement ("resources clearly grouped") is a human's. The contract is
/// that every resource appears exactly once, in one deterministic order, and
/// that a second scan of an unchanged world is byte-identical: a tree that
/// reshuffles between two reads is not comprehensible no matter how well the
/// grouping reads on any single one of them.
#[tokio::test]
async fn uat_001_the_tree_is_well_formed_and_deterministically_ordered() {
    let expected: Vec<ResourceId> = docker_world()
        .resources()
        .iter()
        .map(|r| r.id.clone())
        .collect();
    assert!(
        expected.len() >= 5,
        "the fixture must be big enough for ordering to mean anything, found {}",
        expected.len()
    );

    let first = discover_all(&[port(docker_world())]).await;
    let second = discover_all(&[port(docker_world())]).await;

    assert!(
        first.is_complete(),
        "a healthy world records no failure: {first:?}"
    );
    assert_eq!(
        first.resources.len(),
        expected.len(),
        "every resource in the world appears exactly once"
    );
    let seen: BTreeSet<&ResourceId> = first.resources.iter().map(|r| &r.id).collect();
    assert_eq!(
        seen.len(),
        first.resources.len(),
        "no resource appears twice"
    );
    assert_eq!(
        first.resources.iter().map(|r| &r.id).collect::<Vec<_>>(),
        expected.iter().collect::<Vec<_>>(),
        "the order is the load-time order, not an arbitrary one"
    );
    assert_eq!(
        first.to_json(),
        second.to_json(),
        "two scans of an unchanged world must agree byte for byte"
    );

    // Every node's parent, if it has one, is in the same tree: a cycle or a
    // dangling parent here is what makes a rendered tree look broken.
    for node in &first.resources {
        if let Some(parent) = &node.parent_id {
            assert!(
                first.resources.iter().any(|r| &r.id == parent),
                "{} hangs off a parent the operator cannot see",
                node.name
            );
        }
    }
}

// --- UAT-002 / UAT-005: destructive verbs ------------------------------------

/// UAT-002 / UAT-005 — a lifecycle verb runs, and the destructive one refuses
/// first. The "intuitive" and "status updates" halves are a human's.
#[tokio::test]
async fn uat_002_a_destructive_lifecycle_refuses_before_anything_else() {
    let provider = ScriptedResourceProvider::new(docker_world().into_shared());

    let refused = provider
        .invoke(&invoke(
            &web(),
            OperationKind::Destroy,
            serde_json::json!({}),
        ))
        .await
        .expect_err("destroy without force must not reach the provider");
    assert_eq!(refused.code, ErrorCode::POLICY_DENIED, "{refused}");
    assert!(
        refused.message.contains("force"),
        "the refusal must name the confirmation it wants, not just deny: {refused}"
    );

    // The same call with the confirmation is what an operator is expected to
    // be able to make, so it has to work.
    let forced = provider
        .invoke(&invoke(
            &web(),
            OperationKind::Destroy,
            serde_json::json!({"force": true}),
        ))
        .await
        .expect("a confirmed destructive call reaches the provider");
    assert_eq!(
        forced.state,
        OperationState::Succeeded,
        "a scripted destroy succeeds once it is confirmed"
    );
    assert!(
        forced.error_code.is_none(),
        "a succeeded job carries no error code, found {:?}",
        forced.error_code
    );
}

// --- UAT-003: workspace browsing --------------------------------------------

/// UAT-003 — browsing a workspace yields a canonical listing and windowed reads.
#[tokio::test]
async fn uat_003_workspace_browsing_is_canonical_and_windowed() {
    let instance = docker_world().into_shared().provider_instance();
    let files = instance.files.expect("the world serves the file port");

    let root = workspace_uri(&web(), "").expect("root uri");
    let listing = files.list(&root).await.expect("root lists");
    let names: Vec<&str> = listing.iter().map(|e| e.path.as_str()).collect();
    assert_eq!(
        names,
        vec!["build.log", "etc", "src"],
        "one level, path order"
    );
    assert!(
        listing.iter().all(|e| !e.is_dir || e.size == 0),
        "FR-077: a directory reports no size, because listing reads metadata only"
    );

    let src = workspace_uri(&web(), "src/index.html").expect("file uri");
    let body = files
        .read(
            &src,
            ReadWindow {
                offset: 0,
                length: 64,
            },
        )
        .await
        .expect("read");
    assert_eq!(body, b"<h1>hello</h1>".to_vec());

    // Reading only a window is the point: the same file through a different
    // window must not hand back the whole thing.
    let head = files
        .read(
            &src,
            ReadWindow {
                offset: 0,
                length: 4,
            },
        )
        .await
        .expect("windowed read");
    assert_eq!(head, b"<h1>".to_vec(), "the window bound is honoured");

    let tail = files
        .read(
            &src,
            ReadWindow {
                offset: 4,
                length: 64,
            },
        )
        .await
        .expect("offset read");
    assert_eq!(
        tail,
        b"hello</h1>".to_vec(),
        "an offset window starts where it says it does, not one byte earlier"
    );
    assert_eq!(
        [head.len(), tail.len()].iter().sum::<usize>(),
        body.len(),
        "the two windows tile the file exactly once, so the window is a view \
         and not a re-read of the whole object"
    );
}

// --- UAT-004: inspect --------------------------------------------------------

/// UAT-004 — inspecting a container returns the normalised fields, and an id
/// the operator cannot see is "not found" rather than a blank.
#[tokio::test]
async fn uat_004_inspect_returns_the_normalised_node_and_names_what_is_missing() {
    let provider = ScriptedResourceProvider::new(docker_world().into_shared());

    let node = provider
        .inspect(&web())
        .await
        .expect("the fixture declares this container");
    assert_eq!(node.name, "web");
    assert_eq!(
        node.id,
        web(),
        "the id the operator sees is the id used everywhere else"
    );
    assert!(
        !node.capabilities.is_empty(),
        "the node says which verbs it accepts, so the UI can hide the rest"
    );

    let ghost = provider
        .inspect(&ResourceId::derive(&["not-in-this-world"]))
        .await
        .expect_err("an undeclared resource does not exist");
    assert_eq!(
        ghost.code,
        sandtree_mock_runtime::resource_provider::NOT_FOUND_CODE,
        "absence is named with a stable code, not returned as an empty success: {ghost}"
    );
}

// --- UAT-007: bounded exec output -------------------------------------------

/// UAT-007 — a diagnostic command answers within a bound, and says it truncated.
#[tokio::test]
async fn uat_007_exec_output_is_bounded_and_the_bound_is_visible() {
    let world = ScriptedWorld::from_json_str(fixtures::LARGE_OUTPUT_WORLD)
        .expect("the large-output world loads");
    let exec = ScriptedExecProvider::new(world.into_shared());

    let out = exec
        .exec(&ResourceId::derive(&["noisy"]), &["yes".to_string()], 5_000)
        .await
        .expect("the command is scripted");

    assert!(
        out.truncated,
        "output past the cap must be reported as truncated"
    );
    assert_eq!(
        out.stdout.len(),
        sandtree_mock_runtime::MAX_CAPTURE_BYTES,
        "the cap decides the length, not the fixture"
    );
    // Without this the assertion above is vacuous: a fixture that never exceeded
    // the cap would make `truncated` false and the whole test meaningless.
    assert!(
        fixtures::LARGE_OUTPUT_WORLD.len() > sandtree_mock_runtime::MAX_CAPTURE_BYTES,
        "the fixture must really declare more than the cap allows, found {} bytes",
        fixtures::LARGE_OUTPUT_WORLD.len()
    );
}

// --- UAT-010: compose attribution -------------------------------------------

/// UAT-010 — a Compose project reads as one project with its services, and a
/// standalone container is not swept into a project it does not belong to.
#[tokio::test]
async fn uat_010_compose_attribution_is_not_invented_for_a_standalone_container() {
    let nodes = ScriptedResourceProvider::new(docker_world().into_shared())
        .discover(None)
        .await
        .expect("discovery answers")
        .resources;

    // This fixture declares no compose labels at all, so *every* container here
    // must come back unattributed. A provider that grouped by name similarity
    // would invent a project the operator never configured.
    let containers: Vec<_> = nodes
        .iter()
        .filter(|n| n.kind == sandtree_model::resource::ResourceKind::Container)
        .collect();
    assert_eq!(
        containers.len(),
        2,
        "the fixture declares two containers: web and cache"
    );
    for c in &containers {
        assert_eq!(
            c.metadata.get("com.docker.compose.project"),
            None,
            "{} has no compose project label and must not be attributed to one",
            c.name
        );
        assert_eq!(
            c.metadata.get("com.docker.compose.service"),
            None,
            "{} has no compose service label",
            c.name
        );
    }

    // And the shape that *would* carry them is present elsewhere, so the check
    // above is not passing merely because the field is never emitted.
    assert!(
        nodes
            .iter()
            .any(|n| n.metadata.get("endpoint_id").is_some()),
        "provider metadata is carried; only the absent compose keys stay absent"
    );
}

// --- UAT-011: snapshot atomicity --------------------------------------------

/// UAT-011 — a snapshot is atomic: the manifest and every object it names agree.
///
/// FR-044 requires the CAS object to be on disk before the row that references
/// it is visible. The machine-checkable half is that a visible snapshot never
/// names a digest the CAS cannot serve, and that the check has teeth: a digest
/// that was never stored must read back absent.
#[tokio::test]
async fn uat_011_a_visible_snapshot_names_only_objects_the_cas_can_serve() {
    let dir = tempfile::tempdir().expect("tempdir");
    let kernel = sandtree_kernel::Kernel::bootstrap(sandtree_kernel::KernelConfig::new(dir.path()))
        .await
        .expect("bootstrap");
    // A snapshot row carries a foreign key onto the resource it snapshotted, so
    // the resource has to exist first -- which is also the only order the
    // product can be in.
    kernel
        .register_provider(docker_world().into_shared().provider_instance())
        .await
        .expect("register");
    kernel
        .discover_all()
        .await
        .expect("discovery populates the store");
    let store = kernel.store();
    let cas = kernel.cas();

    // Objects land on disk first — the order FR-044 mandates.
    let stored = cas.put(b"snapshot payload").expect("object is stored");
    assert!(
        cas.contains(&stored).expect("contains answers"),
        "a stored object is on disk before anything references it"
    );

    let manifest = SnapshotManifest {
        id: SnapshotId::derive(&["snap", "uat-011"]),
        resource_id: web(),
        created_at: "2026-10-07T00:00:00Z".to_string(),
        manifest_hash: stored.clone(),
        entries: vec![FileMetadata {
            path: "build.log".into(),
            is_dir: false,
            size: 15,
            mtime_ns: Some(3),
            hash_state: ContentHashState::ContentCached,
            content_hash: Some(stored.clone()),
        }],
    };
    store
        .insert_snapshot(&manifest)
        .expect("the snapshot becomes visible");

    // The visible row round-trips, and every digest it names resolves.
    let listed = store
        .list_snapshots(&web())
        .expect("snapshots list")
        .into_iter()
        .find(|m| m.id == manifest.id)
        .expect("the snapshot we inserted is visible");
    assert_eq!(
        listed.manifest_hash, stored,
        "the manifest hash survived the round trip"
    );
    assert_eq!(
        listed.entries.len(),
        1,
        "exactly the entry that was written"
    );
    for entry in &listed.entries {
        let digest = entry
            .content_hash
            .as_deref()
            .expect("a ContentCached entry carries its digest");
        assert!(
            cas.contains(digest).expect("contains answers"),
            "a visible snapshot names digest {digest}, which the CAS cannot serve"
        );
        assert!(
            cas.verify(digest).expect("verify answers"),
            "digest {digest} does not verify"
        );
    }

    // The check above has teeth: an object that was never stored reads absent,
    // so "contains" is not answering true for everything.
    let never_stored = "f".repeat(64);
    assert!(
        !cas.contains(&never_stored).expect("contains answers"),
        "a digest that was never put must not resolve, or the loop above proves nothing"
    );
}

// --- UAT-015: diagnostics ----------------------------------------------------

/// UAT-015 — the diagnostic bundle is deterministic and carries no secret.
///
/// NFR-S03 has to hold at two points, and this checks both. The store refuses a
/// credential-bearing endpoint outright, and the bundle redacts one anyway --
/// because a row written by an older build, or restored from a backup, is
/// exactly the input the second check exists for.
#[tokio::test]
async fn uat_015_the_diagnostics_bundle_is_deterministic_and_secret_free() {
    let dir = tempfile::tempdir().expect("tempdir");
    let kernel = sandtree_kernel::Kernel::bootstrap(sandtree_kernel::KernelConfig::new(dir.path()))
        .await
        .expect("bootstrap");
    let store = kernel.store();

    // 1. At the source: the store will not take the credential at all.
    let refused = store
        .upsert_docker_endpoint(&DockerEndpointRow {
            id: EndpointId::derive(&["ep-uat-015"]),
            uri: "tcp://leo:hunter2@10.0.0.5:2376".to_string(),
            api_version: Some("1.45".to_string()),
            engine_version: Some("27.0.3".to_string()),
            os: Some("linux".to_string()),
            arch: Some("x86_64".to_string()),
            health: "healthy".to_string(),
        })
        .expect_err("an endpoint profile may not embed credentials");
    assert_eq!(refused.code, ErrorCode::POLICY_DENIED, "{refused}");

    // 2. Past the source: a row that got there anyway (older build, restored
    //    backup) still comes out of the bundle redacted. This is the bundle an
    //    operator pastes into a bug report, so it is the last place a password
    //    may survive.
    let smuggled = EndpointId::derive(&["ep-uat-015-legacy"]);
    store
        .write(|tx| {
            tx.execute(
                "INSERT INTO docker_endpoint(id,uri,api_version,engine_version,os,arch,health,last_seen)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                rusqlite::params![
                    smuggled.as_str(),
                    "tcp://leo:hunter2@10.0.0.5:2376",
                    "1.45",
                    "27.0.3",
                    "linux",
                    "x86_64",
                    "healthy",
                    "2026-10-07T00:00:00Z",
                ],
            )
            .map_err(sandtree_store::db::DbFailure::Sql)
        })
        .expect("the legacy row is written directly, bypassing the check");

    store
        .upsert_docker_endpoint(&DockerEndpointRow {
            id: EndpointId::derive(&["ep-uat-015-clean"]),
            uri: "tcp://10.0.0.9:2376".to_string(),
            api_version: Some("1.45".to_string()),
            engine_version: Some("27.0.3".to_string()),
            os: Some("linux".to_string()),
            arch: Some("x86_64".to_string()),
            health: "healthy".to_string(),
        })
        .expect("a clean endpoint is accepted");

    let first = kernel.diagnostics_bundle().await.expect("a bundle");
    let second = kernel.diagnostics_bundle().await.expect("a bundle");
    assert_eq!(first, second, "two bundles from one state are identical");

    let rendered = first.to_string();
    assert!(
        !rendered.contains("hunter2"),
        "a credential in an endpoint profile must never reach the bundle: {rendered}"
    );
    assert!(
        rendered.contains("[REDACTED]"),
        "the password is replaced, not the whole endpoint dropped: {rendered}"
    );
    assert!(
        rendered.contains("10.0.0.5:2376"),
        "the operator still needs the host:port to act on the report: {rendered}"
    );
    assert!(
        rendered.contains("10.0.0.9:2376"),
        "a clean endpoint appears verbatim, so redaction did not quietly drop \
         every endpoint instead: {rendered}"
    );
}

// --- UAT-017: dangerous actions are refused and audited ---------------------

/// UAT-017 — a dangerous action is refused without confirmation, and an
/// attempted one is audited under a namespaced, privileged action.
///
/// The "impact is clearly stated" half is a human's. What is machine-checkable
/// is that the confirmation gate really refuses, and that whatever the kernel
/// went on to attempt reaches the audit log with enough structure to be filed.
#[tokio::test]
async fn uat_017_a_destructive_action_is_refused_then_audited_when_attempted() {
    let dir = tempfile::tempdir().expect("tempdir");
    let kernel = sandtree_kernel::Kernel::bootstrap(sandtree_kernel::KernelConfig::new(dir.path()))
        .await
        .expect("bootstrap");

    let world = ScriptedWorld::from_json_str(fixtures::FAILING_OPERATIONS_WORLD)
        .expect("the failing-operations world loads");
    let plugin = world.plugin_id().clone();
    kernel
        .register_provider(world.into_shared().provider_instance())
        .await
        .expect("register");
    kernel
        .discover_all()
        .await
        .expect("discovery populates the store");
    // Two ceilings, both required: what the manifest declares, and what the host
    // grants. Granting without declaring leaves the operation refused at the
    // manifest check, which is the FR-061 contract rather than a test artefact.
    let destroy = CapabilitySet::parse_all(["resource:destroy"]).expect("caps parse");
    kernel.set_declared(plugin.clone(), destroy.clone()).await;
    kernel
        .allow(
            plugin,
            Capability::parse("resource:destroy").expect("capability parses"),
        )
        .await;

    // Subscribe *before* dispatching: a test that inspects the log afterwards
    // would pass even if the kernel never recorded anything.
    let (_sub_id, mut subscription) = kernel
        .event_router()
        .subscribe(sandtree_event::EventFilter::all());

    let busy = ResourceId::derive(&["busy"]);

    // 1. No confirmation: refused before anything else is even looked up.
    let unconfirmed = kernel
        .invoke(invoke(&busy, OperationKind::Destroy, serde_json::json!({})))
        .await
        .expect_err("destroy without force is refused");
    assert_eq!(unconfirmed.code, ErrorCode::POLICY_DENIED, "{unconfirmed}");
    assert!(
        unconfirmed.message.contains("force"),
        "the refusal names the confirmation it wants: {unconfirmed}"
    );

    // 2. Confirmed: this world scripts no `destroy` outcome, so the provider
    //    fails it — which is the path that must leave an audit record.
    let attempted = kernel
        .invoke(invoke(
            &busy,
            OperationKind::Destroy,
            serde_json::json!({"force": true}),
        ))
        .await
        .expect_err("this world has no scripted destroy");
    assert_ne!(
        attempted.code,
        ErrorCode::POLICY_DENIED,
        "a confirmed destroy must get past the confirmation gate: {attempted}"
    );

    let mut audited: Vec<serde_json::Value> = Vec::new();
    while let Some(event) = subscription.try_recv() {
        if let Some(action) = event.payload.get("action") {
            audited.push(event.payload.clone());
            assert_eq!(
                action.as_str(),
                Some("container.destroy"),
                "the audit action is namespaced <kind>.<verb> (NFR-S03), found {action}"
            );
        }
    }
    let destroy_audit = audited
        .iter()
        .find(|p| p.get("action").and_then(|a| a.as_str()) == Some("container.destroy"))
        .expect("the attempted destroy reached the audit log");
    assert_eq!(
        destroy_audit.get("result").and_then(|r| r.as_str()),
        Some("failed"),
        "the audit records that the attempt failed: {destroy_audit}"
    );
    assert_eq!(
        destroy_audit.get("privileged").and_then(|p| p.as_bool()),
        Some(true),
        "a container verb is privileged by namespace and must be filed as such: {destroy_audit}"
    );
    assert_eq!(
        destroy_audit.get("resource_id").and_then(|r| r.as_str()),
        Some(busy.as_str()),
        "the audit names the resource it acted on: {destroy_audit}"
    );
}

// --- UAT-018: docker endpoints ----------------------------------------------

/// UAT-018 — a Docker endpoint that is not Desktop can be addressed, and a
/// cleartext one is classified rather than silently accepted.
#[test]
fn uat_018_a_non_desktop_endpoint_is_addressable_and_classified() {
    // Named pipe and unix socket both parse, which is what "not Desktop Linux"
    // means for a Windows host.
    let pipe = sandtree_provider_docker::DockerEndpoint::parse("npipe:////./pipe/docker_engine")
        .expect("a default named pipe parses");
    assert!(pipe.uri.contains("docker_engine"));

    let socket = sandtree_provider_docker::DockerEndpoint::parse("unix:///var/run/docker.sock")
        .expect("a unix socket parses");
    assert!(socket.uri.contains("docker.sock"));

    // Cleartext TCP is refused, not quietly downgraded: the operator is told.
    let cleartext = sandtree_provider_docker::DockerEndpoint::parse("tcp://10.0.0.5:2375");
    assert!(
        cleartext.is_err(),
        "a cleartext TCP endpoint must be refused, not accepted with a warning buried in a field"
    );
}

// --- UAT-019: one method surface ---------------------------------------------

/// UAT-019 — the CLI and the daemon expose the same method set.
#[tokio::test]
async fn uat_019_cli_and_daemon_expose_the_same_method_set() {
    let dir = tempfile::tempdir().expect("tempdir");
    let kernel = Arc::new(
        sandtree_kernel::Kernel::bootstrap(sandtree_kernel::KernelConfig::new(dir.path()))
            .await
            .expect("bootstrap"),
    );
    let router = sandtree_daemon::methods::build_router(kernel);

    let routed: BTreeSet<&str> = router.methods().into_iter().collect();
    assert!(
        !routed.is_empty(),
        "the daemon must route at least one method or the check is vacuous"
    );
    let registry: BTreeSet<&str> = sandtree_ipc::method::ALL.iter().copied().collect();

    for m in &routed {
        assert!(
            sandtree_ipc::method::is_well_formed(m),
            "{m} is not a family-qualified method name; the router splits on the first dot"
        );
        assert!(
            registry.contains(m),
            "{m} is routed by the daemon but absent from the shipped registry"
        );
    }
    for m in &registry {
        assert!(
            routed.contains(m),
            "{m} is declared in the registry but the daemon never routes it, so a \
             caller would get an unknown-method error for a documented method"
        );
    }
}

// --- UAT-020: licence gate ---------------------------------------------------

/// UAT-020 — no unapproved licence reaches the plugin host.
#[test]
fn uat_020_the_plugin_host_refuses_a_licence_outside_the_allow_list() {
    use sandtree_plugin_host::verify::{verify, InstallPolicy};
    use sandtree_sdk::manifest::{PluginManifest, SUPPORTED_SCHEMA_VERSION};

    let manifest = |license: &str| {
        PluginManifest::from_json(&serde_json::json!({
            "schema_version": SUPPORTED_SCHEMA_VERSION,
            "plugin_id": "sandtree.provider.docker",
            "version": "1.0.0",
            "kind": "provider",
            "component": "blake3:abc",
            "license": license,
            "capabilities": ["resource:discover"],
            "state_schema_version": 1,
            "hot_swap": true,
        }))
        .expect("manifest parses")
    };
    let policy = InstallPolicy::deny_all().allow_license("MIT").grant(
        sandtree_model::capability::CapabilitySet::parse_all(["resource:discover"])
            .expect("caps parse"),
    );

    assert!(
        verify(&manifest("MIT"), b"", "", &policy).is_ok(),
        "an allow-listed licence is accepted"
    );
    let refused =
        verify(&manifest("GPL-3.0-only"), b"", "", &policy).expect_err("GPL is not on the list");
    assert_eq!(
        refused.code,
        ErrorCode::PLUGIN_MANIFEST_INVALID,
        "{refused}"
    );
    assert!(
        refused.message.contains("GPL-3.0-only"),
        "the refusal must name the licence that was refused, or the operator \
         cannot act on it: {refused}"
    );
}

// --- UAT-021 / 022 / 023: observation ----------------------------------------

/// UAT-021 — the same resource reports the same domain set every time.
///
/// The judgement ("understandable") is a human's. The contract underneath it is
/// stability: a panel whose domain list changes between two reads teaches the
/// operator that the numbers are unreliable.
#[tokio::test]
async fn uat_021_the_same_domain_set_is_reported_every_time() {
    let observation = ScriptedObservation::from_json(OBSERVATION_CORPUS).expect("the corpus loads");
    let ids = observation.resource_ids();
    assert!(!ids.is_empty(), "the corpus scripts no resources");
    assert!(
        ids.len() >= 8,
        "the corpus must carry a spread of worlds, found {}",
        ids.len()
    );

    for id in &ids {
        let first = observation
            .capabilities(id)
            .await
            .expect("capabilities are static and do not depend on IO");
        let second = observation
            .capabilities(id)
            .await
            .expect("capabilities are static and do not depend on IO");
        // Compared as rendered text rather than through a derived accessor: the
        // point is that *nothing* about the report moves between two reads.
        assert_eq!(
            format!("{first:?}"),
            format!("{second:?}"),
            "{id} reported two different capability sets"
        );
    }
}

/// UAT-022 — trust is reported and never rises under observation.
///
/// The ladder is written out rather than read back from the model: a test that
/// derives its expectation from the implementation cannot fail when the
/// implementation changes, which is exactly the mutation ADR-OBS-003 forbids.
#[tokio::test]
async fn uat_022_trust_is_reported_and_never_rises_under_observation() {
    // Weakest rung first. `weakest_trust()` is `reduce(at_most)` over the
    // derived `Ord`, which follows *declaration* order -- so reordering these
    // variants would silently make every snapshot look authoritative while
    // still compiling and still passing any test that only compared enum
    // values. Pinning the ladder here is what catches that.
    const LADDER: [(TrustLevel, &str); 5] = [
        (TrustLevel::Unverified, "unverified"),
        (TrustLevel::GuestProbe, "guest_probe"),
        (TrustLevel::RemoteExec, "remote_exec"),
        (TrustLevel::ProviderNative, "provider_native"),
        (TrustLevel::HostNative, "host_native"),
    ];
    for pair in LADDER.windows(2) {
        let (lower, lower_name) = pair[0];
        let (higher, higher_name) = pair[1];
        assert!(
            lower.rank() < higher.rank(),
            "{lower_name} must rank below {higher_name}: trust only ever rises \
             going up the ladder"
        );
    }
    for (level, name) in LADDER {
        assert_eq!(
            level.as_str(),
            name,
            "the wire name of a rung is part of the contract; renaming it \
             breaks every persisted snapshot and every panel that sorts by it"
        );
    }

    let observation = ScriptedObservation::from_json(OBSERVATION_CORPUS).expect("the corpus loads");

    // Every scripted resource either answers with a rung from the ladder, or
    // refuses with a typed *observation* code. Three shapes are legal and all
    // three are asserted, because "one of them happened" is the contract:
    //
    //  * data, carrying the rung the mode earned;
    //  * no data because the channel is down, carrying no rung and a stated
    //    reason -- FR-079/ADR-OBS-001. Inventing a rung for absent data is the
    //    "guess the underlying state" RD §9 forbids;
    //  * a surfaced error, because a hostile guest path is never degraded into
    //    a snapshot (NFR-S08).
    let mut saw_unavailable = false;
    let mut saw_surfaced = false;
    let mut answered = 0usize;
    for id in observation.resource_ids() {
        let snapshot = match observation
            .observe(&ObservationRequest::new(id.clone(), Vec::new()))
            .await
        {
            Ok(s) => s,
            Err(e) => {
                assert!(
                    e.code.as_str().starts_with("ST-OBS-"),
                    "{id} failed with {} ({e}); a non-observation code here \
                         means the observation plane leaked a control-plane \
                         failure (ADR-OBS-001)",
                    e.code.as_str()
                );
                saw_surfaced = true;
                continue;
            }
        };
        answered += 1;
        let health = snapshot.health;
        let warnings = format!("{:?}", snapshot.warnings);
        match snapshot_trust(&snapshot) {
            Some(trust) => {
                assert!(
                    LADDER.iter().any(|(lvl, _)| *lvl == trust),
                    "{id} reported trust {:?}, which is not a rung of the ladder",
                    trust.as_str()
                );
            }
            None => {
                assert_eq!(
                    health,
                    sandtree_observation_model::ObservationHealth::Unavailable,
                    "{id} produced data with no trust rung; a rung is missing \
                     only when there is no data, never on a healthy snapshot"
                );
                assert!(
                    warnings != "[]",
                    "{id} reports itself unavailable and must say why: {warnings}"
                );
                saw_unavailable = true;
            }
        }
    }
    assert!(
        answered >= 8,
        "the corpus must carry a spread of worlds that actually answer, got {answered}"
    );
    assert!(
        saw_unavailable,
        "the corpus must contain a down channel, or the unavailable branch \
         never ran and FR-079 is untested"
    );
    assert!(
        saw_surfaced,
        "the corpus must contain a surfaced security fault, or the refusal \
         branch never ran and NFR-S08 is untested"
    );

    // The two resources whose whole purpose is an upgrade attempt: a guest probe
    // that claims host-authoritative, and a provider that declares a ceiling
    // above what the mode allows. Neither may come back stronger than the mode
    // that produced it (ADR-OBS-003).
    for (parts, what) in [
        (
            vec!["mock", "wsb-trust-upgrade-attempt"],
            "a probe claiming host-authoritative",
        ),
        (
            vec!["mock", "wsb-ceiling-raised"],
            "a provider declaring a raised ceiling",
        ),
    ] {
        let id = ResourceId::derive(&parts);
        let snapshot = observation
            .observe(&ObservationRequest::new(id.clone(), Vec::new()))
            .await
            .unwrap_or_else(|e| panic!("{what}: observation failed: {e}"));
        assert_eq!(
            snapshot_trust(&snapshot),
            Some(TrustLevel::GuestProbe),
            "{what} must not come back stronger than guest-probe (ADR-OBS-003)"
        );
    }
}

/// UAT-023 — an unavailable provider reports the state instead of raising it.
///
/// ADR-OBS-001: an observation failure is not a resource failure. A provider
/// that is down must be describable, or the UI has to guess what it is looking
/// at -- which RD §9 forbids.
#[tokio::test]
async fn uat_023_an_unavailable_plane_reports_a_state_rather_than_raising() {
    let world = ScriptedWorld::from_json_str(fixtures::UNAVAILABLE_WORLD).expect("the world loads");
    let provider = ScriptedResourceProvider::new(world.into_shared());

    let health = provider
        .health()
        .await
        .expect("health reports a state, it does not raise");
    assert!(
        !health.control_is_available(),
        "an unavailable provider says so instead of pretending to be healthy: {health:?}"
    );
    assert_eq!(
        health.summary(),
        "unavailable",
        "the operator is told the state by name, not just that it is not healthy"
    );
    match &health {
        ProviderHealth::Unavailable { reason } => assert!(
            !reason.is_empty(),
            "an unavailable provider carries the reason, so the panel can show one"
        ),
        other => panic!("expected an Unavailable health, got {other:?}"),
    }

    // The resource is still visible even though control is refused: the UI has
    // to be able to show it greyed out with a reason, not have it vanish.
    let node = provider
        .world()
        .resources()
        .first()
        .expect("the world declares a resource")
        .clone();
    let refused = provider
        .inspect(&node.id)
        .await
        .expect_err("control is refused while unavailable");
    assert!(
        !refused.message.is_empty(),
        "the refusal names what went wrong: {refused}"
    );
}
