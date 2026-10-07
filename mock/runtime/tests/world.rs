//! World-level behaviour: validation, ordering, pagination, the four fault modes,
//! the provider-boundary refusals and exec bounds.
//!
//! Everything here goes through the public API, so these tests double as the
//! example surface another crate would use.

use sandtree_model::capability::{Capability, CapabilityNamespace};
use sandtree_model::error::ErrorCode;
use sandtree_model::id::ResourceId;
use sandtree_model::operation::{OperationKind, OperationRequest, OperationState};
use sandtree_model::resource::Correlation;
use sandtree_vfs::WorkspacePath;
use serde_json::{json, Value as Json};

use sandtree_mock_runtime::{
    fixture::FixtureError, fixtures, ScriptedWorld, DEFAULT_PROVIDER_VERSION, MAX_CAPTURE_BYTES,
};

fn world() -> ScriptedWorld {
    ScriptedWorld::from_json_str(fixtures::DOCKER_WORLD).expect("the built-in docker world loads")
}

/// `web` in [`fixtures::DOCKER_WORLD`].
fn web() -> ResourceId {
    ResourceId::derive(&["abc123def456"])
}

/// `nginx` in [`fixtures::DOCKER_WORLD`].
fn nginx() -> ResourceId {
    ResourceId::derive(&["sha256:0000beef"])
}

/// `box` in [`fixtures::ESCAPING_SYMLINK_WORLD`].
fn box_id() -> ResourceId {
    ResourceId::derive(&["box"])
}

fn req(id: &ResourceId, op: OperationKind, args: Json) -> OperationRequest {
    OperationRequest::new(id.clone(), op, args, Correlation::generate())
}

/// Load a world from a JSON snippet.
fn load(raw: &str) -> Result<ScriptedWorld, FixtureError> {
    ScriptedWorld::from_json_str(raw)
}

/// The rejection message of a load that is expected to fail.
fn rejection(raw: &str) -> String {
    match load(raw) {
        Ok(_) => panic!("this fixture must not load"),
        Err(e) => e.to_string(),
    }
}

/// A minimal world body, used as the base for the validation table below.
fn minimal(extra: &str) -> String {
    format!(
        r#"{{
            "schema": 1,
            "intent": "minimal",
            "plugin": "sandtree.provider.mock",
            "resources": [{{
                "key": "a",
                "id_parts": ["a"],
                "kind": "container",
                "name": "a",
                "state": "running",
                "last_seen": "2026-10-07T00:00:00Z"
            }}]{extra}
        }}"#
    )
}

// --- load-time validation ----------------------------------------------------

#[test]
fn an_unrecognised_schema_version_is_refused() {
    let raw = r#"{"schema": 2, "intent": "x", "plugin": "p"}"#;
    match load(raw).unwrap_err() {
        FixtureError::Invalid { field, .. } => assert_eq!(field, "schema"),
        other => panic!("expected an Invalid(schema) rejection, got {other:?}"),
    }
}

#[test]
fn an_empty_plugin_name_is_refused() {
    let raw = r#"{"schema": 1, "intent": "x", "plugin": "   "}"#;
    assert!(
        rejection(raw).contains("must not be empty"),
        "{}",
        rejection(raw)
    );
}

#[test]
fn a_repeated_key_and_a_repeated_identity_are_different_mistakes() {
    // Two resources answering to the same fixture key: one of them is unreachable.
    let dupe_key = minimal(
        r#", "resources": [{"key": "a", "id_parts": ["x"], "kind": "container",
             "name": "b", "state": "running", "last_seen": "2026-10-07T00:00:00Z"}]"#,
    );
    assert!(
        rejection(&dupe_key).contains("duplicate key"),
        "{}",
        rejection(&dupe_key)
    );

    // Two keys sharing one derived id: `inspect` would be ambiguous.
    let shared_id = minimal(
        r#", "resources": [{"key": "b", "id_parts": ["a"], "kind": "image",
             "name": "b", "state": "running", "last_seen": "2026-10-07T00:00:00Z"}]"#,
    );
    assert!(
        rejection(&shared_id).contains("shares an identity"),
        "{}",
        rejection(&shared_id)
    );
}

#[test]
fn a_dangling_parent_and_a_parent_cycle_are_both_refused() {
    let dangling = minimal(
        r#", "resources": [{"key": "b", "id_parts": ["b"], "kind": "container", "name": "b",
             "state": "running", "parent": "ghost",
             "last_seen": "2026-10-07T00:00:00Z"}]"#,
    );
    assert!(
        rejection(&dangling).contains("unknown parent key"),
        "{}",
        rejection(&dangling)
    );

    let cycle = r#"{
        "schema": 1, "intent": "cycle", "plugin": "p",
        "resources": [
          {"key":"a","id_parts":["a"],"kind":"container","name":"a","state":"running",
           "parent":"b","last_seen":"2026-10-07T00:00:00Z"},
          {"key":"b","id_parts":["b"],"kind":"container","name":"b","state":"running",
           "parent":"a","last_seen":"2026-10-07T00:00:00Z"}
        ]}"#;
    assert!(
        rejection(cycle).contains("cycle"),
        "{}",
        rejection(cycle)
    );
}

#[test]
fn relations_must_name_declared_resources() {
    let raw = minimal(
        r#", "relations": [{"from": "a", "to": "ghost", "kind": "uses-image"}]"#,
    );
    match load(&raw).unwrap_err() {
        FixtureError::Invalid { field, .. } => assert_eq!(field, "relations[].to=ghost"),
        other => panic!("expected an unknown-key rejection, got {other:?}"),
    }
}

#[test]
fn operation_outcomes_must_be_terminal_and_carry_codes_only_on_failure() {
    let pending = minimal(
        r#", "operations": [{"op": "start", "outcome": {"state": "running"}}]"#,
    );
    assert!(
        rejection(&pending).contains("not terminal"),
        "{}",
        rejection(&pending)
    );

    let failed_without_code = minimal(
        r#", "operations": [{"op": "start", "outcome": {"state": "failed"}}]"#,
    );
    assert!(
        rejection(&failed_without_code).contains("must carry a stable code"),
        "{}",
        rejection(&failed_without_code)
    );

    let success_with_code = minimal(
        r#", "operations": [{"op": "start",
             "outcome": {"state": "succeeded", "code": "ST-DKR-001"}}]"#,
    );
    assert!(
        rejection(&success_with_code).contains("must not carry code"),
        "{}",
        rejection(&success_with_code)
    );

    let neither = minimal(r#", "operations": [{"op": "start"}]"#);
    assert!(
        rejection(&neither).contains("either an outcome or an error"),
        "{}",
        rejection(&neither)
    );

    let unknown_op = minimal(
        r#", "operations": [{"op": "frobnicate", "outcome": {"state": "succeeded"}}]"#,
    );
    assert!(
        rejection(&unknown_op).contains("not an OperationKind"),
        "{}",
        rejection(&unknown_op)
    );
}

#[test]
fn error_codes_must_exist_in_the_shipped_registry() {
    let raw = minimal(
        r#", "operations": [{"op": "start",
             "error": {"code": "ST-INVENTED-999", "message": "nope"}}]"#,
    );
    assert!(
        matches!(load(&raw).unwrap_err(), FixtureError::UnknownErrorCode { .. }),
        "{}",
        rejection(&raw)
    );
}

#[test]
fn file_entries_must_declare_a_real_parent_directory() {
    let orphan = minimal(
        r#", "files": [{"root": "a", "path": "src/main.rs", "content": "x"}]"#,
    );
    assert!(
        rejection(&orphan).contains("parent directory"),
        "{}",
        rejection(&orphan)
    );

    let parent_is_a_file = minimal(
        r#", "files": [{"root": "a", "path": "src", "content": "x"},
                       {"root": "a", "path": "src/main.rs", "content": "y"}]"#,
    );
    assert!(
        rejection(&parent_is_a_file).contains("not a directory"),
        "{}",
        rejection(&parent_is_a_file)
    );

    let unknown_root = minimal(
        r#", "files": [{"root": "ghost", "path": "", "is_dir": true}]"#,
    );
    assert!(
        rejection(&unknown_root).contains("files[].root=ghost"),
        "{}",
        rejection(&unknown_root)
    );

    let traversal = minimal(
        r#", "files": [{"root": "a", "path": "", "is_dir": true},
                       {"root": "a", "path": "../outside", "content": "x"}]"#,
    );
    assert!(
        rejection(&traversal).contains("files[].path=../outside"),
        "{}",
        rejection(&traversal)
    );
}

#[test]
fn contradictory_file_declarations_are_refused() {
    let size_mismatch = minimal(
        r#", "files": [{"root": "a", "path": "", "is_dir": true},
                       {"root": "a", "path": "f", "content": "abcd", "size": 99}]"#,
    );
    assert!(
        rejection(&size_mismatch).contains("declared size 99"),
        "{}",
        rejection(&size_mismatch)
    );

    let dir_with_content = minimal(
        r#", "files": [{"root": "a", "path": "", "is_dir": true, "content": "nope"}]"#,
    );
    assert!(
        rejection(&dir_with_content).contains("a directory cannot declare content"),
        "{}",
        rejection(&dir_with_content)
    );

    let link_with_body = minimal(
        r#", "files": [{"root": "a", "path": "", "is_dir": true},
                       {"root": "a", "path": "l", "symlink_target": "t", "content": "x"}]"#,
    );
    assert!(
        rejection(&link_with_body).contains("a symlink has no content"),
        "{}",
        rejection(&link_with_body)
    );

    let duplicate_path = minimal(
        r#", "files": [{"root": "a", "path": "", "is_dir": true},
                       {"root": "a", "path": "f", "content": "x"},
                       {"root": "a", "path": "f", "content": "y"}]"#,
    );
    assert!(
        rejection(&duplicate_path).contains("duplicate path"),
        "{}",
        rejection(&duplicate_path)
    );
}

#[test]
fn an_exec_rule_must_declare_an_argv_and_a_known_resource() {
    let empty_argv = minimal(r#", "exec": [{"argv": []}]"#);
    assert!(
        rejection(&empty_argv).contains("must not be empty"),
        "{}",
        rejection(&empty_argv)
    );

    let unknown_resource = minimal(
        r#", "exec": [{"resource": "ghost", "argv": ["ls"]}]"#,
    );
    assert!(
        rejection(&unknown_resource).contains("exec[].resource=ghost"),
        "{}",
        rejection(&unknown_resource)
    );
}

// --- ordering ----------------------------------------------------------------

#[test]
fn resources_are_emitted_parent_first_with_siblings_in_derived_id_order() {
    let w = world();
    let names: Vec<&str> = w.resources().iter().map(|r| r.name.as_str()).collect();
    assert_eq!(names.len(), 5);
    assert_eq!(
        w.resources()
            .iter()
            .filter(|r| r.parent_id.is_none())
            .count(),
        1,
        "exactly one parentless resource, so the tree is connected"
    );
    assert_eq!(names[0], "docker-engine", "the root comes first");

    // Topological: no child may precede its parent.
    for node in w.resources() {
        let Some(parent) = &node.parent_id else {
            continue;
        };
        let pi = w
            .resources()
            .iter()
            .position(|r| &r.id == parent)
            .expect("the parent is in the same scan");
        let ci = w
            .resources()
            .iter()
            .position(|r| r.id == node.id)
            .expect("the node is in the same scan");
        assert!(pi < ci, "{} must follow its parent", node.name);
    }

    // Siblings are ordered by derived id, not by fixture order. The fixture
    // declares `web` before `cache`, so this also pins that the emitted order is
    // decided by the sort rather than by the input order.
    let web_node = w.node(&web()).expect("web");
    let cache = w
        .node(&ResourceId::derive(&["cache789012345"]))
        .expect("cache");
    let wi = w
        .resources()
        .iter()
        .position(|r| r.id == web_node.id)
        .expect("web");
    let ci = w
        .resources()
        .iter()
        .position(|r| r.id == cache.id)
        .expect("cache");
    assert_eq!(
        wi < ci,
        web_node.id.as_str() < cache.id.as_str(),
        "siblings must be emitted in derived-id order"
    );
}

#[test]
fn fixture_declaration_order_does_not_change_the_serialized_world() {
    let forward: Json = serde_json::from_str(fixtures::DOCKER_WORLD).expect("built-in JSON parses");

    let mut reversed = forward;
    let mut resources = reversed["resources"].as_array().expect("array").clone();
    resources.reverse();
    reversed["resources"] = Json::Array(resources);
    let mut relations = reversed["relations"].as_array().expect("array").clone();
    relations.reverse();
    reversed["relations"] = Json::Array(relations);

    let a = world();
    let b = ScriptedWorld::from_json_str(&reversed.to_string()).expect("reversed");
    assert_eq!(
        serde_json::to_string(a.resources()).unwrap(),
        serde_json::to_string(b.resources()).unwrap(),
        "resource order must not depend on the order the fixture lists them"
    );
    assert_eq!(
        serde_json::to_string(a.relations()).unwrap(),
        serde_json::to_string(b.relations()).unwrap(),
        "relation order must be fixed at load time"
    );
}

// --- pagination (FR-001, fault mode 3) ---------------------------------------

#[test]
fn pagination_delivers_every_resource_exactly_once() {
    let w = world();
    assert_eq!(w.page_size(), 3);
    assert_eq!(w.page_count(), 2);

    let first = w.page(None).expect("page 0");
    assert_eq!(first.resources.len(), 3);
    assert_eq!(first.cursor.as_deref(), Some("page:1"));

    let second = w.page(Some("page:1")).expect("page 1");
    assert_eq!(second.resources.len(), 2);
    assert_eq!(second.cursor, None);

    let mut delivered: Vec<String> = first
        .resources
        .iter()
        .chain(second.resources.iter())
        .map(|r| r.id.to_string())
        .collect();
    delivered.sort();
    let mut expected: Vec<String> = w.resources().iter().map(|r| r.id.to_string()).collect();
    expected.sort();
    assert_eq!(delivered, expected);
    assert_eq!(delivered.len(), 5, "no resource may be delivered twice");
}

#[test]
fn a_relation_rides_with_the_page_holding_its_source() {
    let w = world();
    let mut seen: Vec<String> = Vec::new();
    let mut cursor = None;
    loop {
        let page = w.page(cursor.as_deref()).expect("page");
        for rel in &page.relations {
            assert!(
                page.resources.iter().any(|r| r.id == rel.from),
                "relation {:?} arrived before its source",
                rel.kind
            );
            seen.push(rel.kind.as_str().to_string());
        }
        match page.cursor.clone() {
            Some(c) => cursor = Some(c),
            None => break,
        }
    }
    seen.sort();
    let mut expected: Vec<String> = w
        .relations()
        .iter()
        .map(|r| r.kind.as_str().to_string())
        .collect();
    expected.sort();
    assert_eq!(seen, expected, "every relation is delivered exactly once");
}

#[test]
fn a_cursor_outside_the_world_is_refused_rather_than_answered_empty() {
    let w = world();
    for bad in ["page:9", "next", "", "page:-1", "page:1x"] {
        let err = w.page(Some(bad)).unwrap_err();
        assert_eq!(err.code, ErrorCode::CORE_INVALID, "cursor {bad:?} -> {err}");
    }
}

#[test]
fn fault_mode_3_delivers_the_earlier_pages_then_fails() {
    let w = ScriptedWorld::from_json_str(fixtures::MID_PAGE_FAILURE_WORLD)
        .expect("the mid-page world loads");
    let first = w.page(None).expect("page 0 must succeed");
    assert_eq!(first.resources.len(), 2);
    assert_eq!(first.cursor.as_deref(), Some("page:1"));

    let err = w.page(Some("page:1")).unwrap_err();
    assert_eq!(err.code, ErrorCode::DOCKER_ENDPOINT_UNAVAILABLE);
    assert_eq!(
        err.detail.as_deref(),
        Some("http 500"),
        "provider detail is carried, not parsed"
    );
}

// --- fault mode 4 ------------------------------------------------------------

#[test]
fn an_unavailable_provider_reports_health_and_fails_every_other_call() {
    let w = ScriptedWorld::from_json_str(fixtures::UNAVAILABLE_WORLD).expect("world loads");
    let h = w.health_state();
    assert!(!h.control_is_available(), "{h:?}");
    let vm = ResourceId::derive(&["mock-vm"]);
    for err in [
        w.ensure_available().unwrap_err(),
        w.page(None).unwrap_err(),
        w.exec(&vm, &["ls".to_string()], 1_000).unwrap_err(),
        w.filesystem(&vm).unwrap_err(),
        w.filesystem_mut(&vm).unwrap_err(),
    ] {
        assert_eq!(
            err.code,
            ErrorCode::SANDBOX_PROVIDER_UNAVAILABLE,
            "every port must refuse: {err}"
        );
    }
}

#[test]
fn an_unavailable_provider_without_a_scripted_code_still_fails_closed() {
    let raw = minimal(r#", "health": {"state": "unavailable", "reason": "not installed"}"#);
    let w = load(&raw).expect("loads");
    let err = w.ensure_available().unwrap_err();
    assert_eq!(err.code, ErrorCode::SANDBOX_PROVIDER_UNAVAILABLE);
    assert!(err.message.contains("unavailable"), "{err}");
}

// --- fault mode 2 ------------------------------------------------------------

#[test]
fn an_undeclared_resource_is_reachable_by_no_rule_at_all() {
    let w = world();
    let ghost = ResourceId::derive(&["never-declared"]);
    assert!(w.node(&ghost).is_none(), "no node for an undeclared resource");
    assert!(
        !w.exec_rules()
            .iter()
            .any(|r| r.matches(&ghost, &["anything".to_string()])),
        "a resource-scoped rule must not answer for another resource"
    );
}

// --- the provider-boundary refusals -----------------------------------------

#[test]
fn a_destructive_operation_without_force_is_refused_at_the_provider_boundary() {
    let w = world();
    for op in [OperationKind::Destroy, OperationKind::Remove] {
        let err = w
            .invoke(&req(&web(), op, json!({})))
            .expect_err("destructive without confirmation must be refused");
        assert_eq!(err.code, ErrorCode::POLICY_DENIED, "{op:?}");
        assert!(err.message.contains("force"), "{err}");
    }
    // The confirmation is honoured, not merely accepted.
    let out = w
        .invoke(&req(&web(), OperationKind::Destroy, json!({"force": true})))
        .expect("forced destroy runs");
    assert_eq!(out.state, OperationState::Succeeded);
    assert_eq!(out.result["transition"], Json::from("destroyed"));
}

#[test]
fn a_resource_declared_capability_set_is_a_ceiling() {
    let w = world();
    // `web` declares start/stop/destroy/exec, so `pause` is outside the ceiling
    // and has no scripted rule either. The refusal code alone tells the two
    // situations apart, which is why both halves are asserted below.
    let refused = w
        .invoke(&req(&web(), OperationKind::Pause, json!({})))
        .expect_err("pause is outside web's declared capabilities");
    assert_eq!(refused.code, ErrorCode::POLICY_DENIED, "{refused}");
    assert!(refused.message.contains("resource:pause"), "{refused}");

    // Widening `args` cannot get past the ceiling either.
    let refused = w
        .invoke(&req(
            &web(),
            OperationKind::Pause,
            json!({"force": true, "capabilities": ["resource:pause"]}),
        ))
        .expect_err("arguments cannot widen the declared set");
    assert_eq!(refused.code, ErrorCode::POLICY_DENIED, "{refused}");
}

#[test]
fn an_empty_capability_list_means_no_declared_ceiling() {
    // `nginx` declares `[]`, so the ceiling check must not fire; the operation
    // then fails for the *different* reason that the fixture never scripted it.
    let w = world();
    assert!(w.node(&nginx()).expect("nginx").capabilities.is_empty());
    let err = w
        .invoke(&req(&nginx(), OperationKind::Start, json!({})))
        .expect_err("no scripted outcome");
    assert_eq!(err.code, ErrorCode::CORE_INVALID, "{err}");
    assert!(err.message.contains("no scripted outcome"), "{err}");
}

#[test]
fn an_unscripted_operation_is_an_error_rather_than_a_silent_success() {
    let w = world();
    let err = w
        .invoke(&req(&web(), OperationKind::Restart, json!({})))
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::CORE_INVALID);
    assert!(err.message.contains("restart"), "{err}");
}

#[test]
fn both_shapes_of_operation_failure_are_reproduced() {
    let w = ScriptedWorld::from_json_str(fixtures::FAILING_OPERATIONS_WORLD)
        .expect("the failing world loads");
    let busy = ResourceId::derive(&["busy"]);

    // Hard failure: the port returns Err with the scripted code.
    let err = w
        .invoke(&req(&busy, OperationKind::Start, json!({})))
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::DOCKER_CONFLICT);
    assert_eq!(err.detail.as_deref(), Some("device or resource busy"));

    // Terminal failure: the port returns Ok with a failed job.
    let out = w
        .invoke(&req(&busy, OperationKind::Stop, json!({})))
        .expect("a failed job is still an Ok outcome");
    assert_eq!(out.state, OperationState::Failed);
    assert_eq!(out.error_code, Some(ErrorCode::DOCKER_CONFLICT));
    assert_eq!(out.result["reason"], Json::from("locked"));
}

#[test]
fn invoking_on_a_resource_the_fixture_never_declared_is_not_found() {
    let w = world();
    let err = w
        .invoke(&req(
            &ResourceId::derive(&["ghost"]),
            OperationKind::Start,
            json!({}),
        ))
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::VFS_NOT_FOUND, "{err}");
}

#[test]
fn a_destructive_refusal_comes_before_the_resource_lookup() {
    // The kernel checks confirmation first, so a destroy on a ghost resource is
    // refused for the confirmation, not reported as "no such resource".
    let w = world();
    let err = w
        .invoke(&req(
            &ResourceId::derive(&["ghost"]),
            OperationKind::Destroy,
            json!({}),
        ))
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::POLICY_DENIED, "{err}");
}

// --- descriptor, identity and metadata ---------------------------------------

#[test]
fn the_descriptor_reports_the_fixture_and_a_default_version() {
    let d = world().descriptor();
    assert_eq!(d.version, "1.2.3");
    assert_eq!(d.kind, sandtree_sdk::manifest::PluginKind::Provider);
    assert!(d.plugin_id.starts_with("plg-"), "{d:?}");

    let d = load(&minimal("")).expect("loads").descriptor();
    assert_eq!(
        d.version, DEFAULT_PROVIDER_VERSION,
        "a fixture without a version still gets a stable one"
    );
}

#[test]
fn identity_is_derived_from_native_parts_not_from_the_display_name() {
    let renamed = fixtures::DOCKER_WORLD.replace("\"name\": \"web\"", "\"name\": \"renamed\"");
    let before = world();
    let after = ScriptedWorld::from_json_str(&renamed).expect("renamed world loads");
    let a = before.node(&web()).expect("web");
    let b = after.node(&web()).expect("web");

    assert_eq!(a.name, "web");
    assert_eq!(b.name, "renamed", "the rename really happened");
    assert_eq!(
        a.id, b.id,
        "identity must not move when only the display name changes"
    );
    // The id is a hash of the declared native parts, not of the fixture key.
    assert_eq!(a.id, ResourceId::derive(&["abc123def456"]));
    assert_ne!(a.id, ResourceId::derive(&["web"]));
}

#[test]
fn resource_metadata_and_capabilities_survive_loading() {
    let w = world();
    let n = w.node(&web()).expect("web");
    assert_eq!(n.capabilities.len(), 4);
    assert!(n.capabilities.allows(&Capability::global(
        CapabilityNamespace::Resource,
        "destroy"
    )));
    assert!(!n.capabilities.allows(&Capability::global(
        CapabilityNamespace::Resource,
        "pause"
    )));
    assert_eq!(n.meta_str("endpoint_id"), Some("ep-docker-engine"));
    assert_eq!(n.last_seen, "2026-10-07T00:00:00Z");
}

// --- exec (FR-013, FR-025) ---------------------------------------------------

#[test]
fn exec_rules_match_exact_argv_and_may_be_scoped_to_a_resource() {
    let w = world();
    let cache = ResourceId::derive(&["cache789012345"]);

    let out = w
        .exec(
            &web(),
            &["cat".to_string(), "/etc/hostname".to_string()],
            1_000,
        )
        .expect("scoped rule");
    assert_eq!(out.stdout, "web\n");
    assert_eq!(out.exit_code, 0);
    assert!(!out.truncated);

    // The same rule must not answer for a different resource.
    let err = w
        .exec(
            &cache,
            &["cat".to_string(), "/etc/hostname".to_string()],
            1_000,
        )
        .unwrap_err();
    assert!(err.message.contains("no scripted exec rule"), "{err}");

    // An unscoped rule answers anywhere.
    let out = w.exec(&cache, &["false".to_string()], 1_000).expect("unscoped rule");
    assert_eq!(out.exit_code, 1);
    assert_eq!(out.stderr, "scripted failure");
}

#[test]
fn exec_refuses_a_zero_budget_and_an_unscripted_command() {
    let w = world();
    let zero = w.exec(&web(), &["false".to_string()], 0).unwrap_err();
    assert_eq!(zero.code, ErrorCode::CORE_INVALID, "{zero}");
    assert!(zero.message.contains("non-zero timeout"), "{zero}");

    let unknown = w
        .exec(
            &web(),
            &["rm".to_string(), "-rf".to_string(), "/".to_string()],
            5_000,
        )
        .unwrap_err();
    assert_eq!(unknown.code, ErrorCode::CORE_INVALID);
}

#[test]
fn exec_output_is_capped_and_the_truncation_is_reported() {
    let w = ScriptedWorld::from_json_str(fixtures::LARGE_OUTPUT_WORLD).expect("world loads");
    let out = w
        .exec(&ResourceId::derive(&["noisy"]), &["yes".to_string()], 1_000)
        .expect("runs");
    assert!(
        out.truncated,
        "a stream longer than the cap must be reported as truncated"
    );
    assert_eq!(
        out.stdout.len(),
        MAX_CAPTURE_BYTES,
        "the captured stream must be exactly the cap, not the fixture's length"
    );
    assert!(out.stdout.is_char_boundary(out.stdout.len()));
    // The declared stream really is longer than the cap, so the truncation above
    // was the cap doing the work rather than the fixture being short.
    let fixture: Json = serde_json::from_str(fixtures::LARGE_OUTPUT_WORLD).expect("parses");
    let declared = fixture["exec"][0]["stdout"]
        .as_str()
        .expect("a stdout string");
    assert!(
        declared.len() > MAX_CAPTURE_BYTES,
        "fixture stream is {} bytes, cap is {MAX_CAPTURE_BYTES}",
        declared.len()
    );
}

#[test]
fn exec_can_script_a_hard_failure() {
    let raw = minimal(
        r#", "exec": [{"argv": ["boom"], "error": {"code": "ST-DKR-001", "message": "endpoint gone"}}]"#,
    );
    let w = load(&raw).expect("loads");
    let err = w
        .exec(&ResourceId::derive(&["a"]), &["boom".to_string()], 1_000)
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::DOCKER_ENDPOINT_UNAVAILABLE);
    assert_eq!(err.message, "endpoint gone");
}

// --- confinement (NFR-S05) ---------------------------------------------------

#[test]
fn a_symlink_out_of_the_workspace_root_is_refused() {
    let w = ScriptedWorld::from_json_str(fixtures::ESCAPING_SYMLINK_WORLD).expect("world loads");
    let fs = w.filesystem(&box_id()).expect("workspace");
    let path = WorkspacePath::from_relative("workspace/out").expect("canonical");
    let err = fs.resolve_confined(&path).unwrap_err();
    assert_eq!(err.code, ErrorCode::VFS_PATH_ESCAPE, "{err}");
}

#[test]
fn a_canonical_path_outside_the_served_subtree_is_still_refused() {
    // `secrets/key.pem` exists in storage and needs no `..` to reach, so only the
    // subtree check can stop it.
    let w = ScriptedWorld::from_json_str(fixtures::ESCAPING_SYMLINK_WORLD).expect("world loads");
    let fs = w.filesystem(&box_id()).expect("workspace");
    let path = WorkspacePath::from_relative("secrets/key.pem").expect("canonical");
    let err = fs.resolve_confined(&path).unwrap_err();
    assert_eq!(err.code, ErrorCode::VFS_PATH_ESCAPE, "{err}");
    assert!(err.message.contains("served subtree"), "{err}");
    // The file really is there, so the refusal is not an accident of absence.
    assert_eq!(
        fs.get("secrets/key.pem").expect("held in storage").size(),
        64
    );
}

#[test]
fn a_symlink_inside_the_subtree_resolves_to_its_target() {
    let w = ScriptedWorld::from_json_str(fixtures::ESCAPING_SYMLINK_WORLD).expect("world loads");
    let fs = w.filesystem(&box_id()).expect("workspace");
    let path = WorkspacePath::from_relative("workspace/inside").expect("canonical");
    assert_eq!(
        fs.resolve_confined(&path).expect("an in-subtree link resolves"),
        "workspace/app/ok.txt"
    );
}

#[test]
fn a_symlink_loop_is_refused_rather_than_followed_forever() {
    let raw = minimal(
        r#", "files": [{"root": "a", "path": "", "is_dir": true},
                       {"root": "a", "path": "loop", "symlink_target": "loop"},
                       {"root": "a", "path": "tail", "symlink_target": "loop"}]"#,
    );
    let w = load(&raw).expect("loads");
    let fs = w.filesystem(&ResourceId::derive(&["a"])).expect("workspace");
    let path = WorkspacePath::from_relative("tail").expect("canonical");
    let err = fs.resolve_confined(&path).unwrap_err();
    assert!(err.message.contains("symlink chain"), "{err}");
}

#[test]
fn a_read_only_ancestor_is_visible_through_the_whole_subtree() {
    let w = world();
    let fs = w.filesystem(&web()).expect("workspace");
    assert!(!fs.read_only_at("src/index.html"));
    assert!(fs.read_only_at("etc"));
    assert!(fs.read_only_at("etc/app.conf"));
}

// --- fixture corpus ----------------------------------------------------------

#[test]
fn every_built_in_world_loads_and_declares_what_it_promises() {
    let names: Vec<&str> = fixtures::all().iter().map(|(n, _)| *n).collect();
    assert!(names.len() >= 6, "the corpus must keep growing");
    for (name, json_text) in fixtures::all() {
        let w = ScriptedWorld::from_json_str(json_text)
            .unwrap_or_else(|e| panic!("built-in world {name:?} must load: {e}"));
        assert!(!w.intent().is_empty(), "{name} must state its intent");
        assert!(
            fixtures::fixture(name).is_ok(),
            "{name} must parse as a bare fixture too"
        );
    }
    let missing = fixtures::world("no-such-world").unwrap_err();
    assert!(
        matches!(missing, FixtureError::Invalid { .. }),
        "an unknown built-in name is a validation error, not a panic"
    );
}
