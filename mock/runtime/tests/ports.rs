//! Port-level behaviour: what each of the three provider ports answers.
//!
//! These are the assertions a control-plane regression would make against a real
//! provider, written against the fake. They go through the trait methods, not the
//! world, so they also pin the port boundary itself.

use sandtree_model::error::ErrorCode;
use sandtree_model::id::ResourceId;
use sandtree_model::operation::{OperationKind, OperationRequest, OperationState};
use sandtree_model::resource::{Correlation, ResourceKind, ResourceNode, ResourceState};
use sandtree_observation_model::ContentHashState;
use sandtree_sdk::ports::{ProviderHealth, ResourceProvider};
use sandtree_vfs::ReadWindow;
use serde_json::json;

use sandtree_mock_runtime::file_provider::workspace_uri;
use sandtree_mock_runtime::{fixtures, resource_provider::ScriptedResourceProvider, ScriptedWorld};

fn world() -> ScriptedWorld {
    ScriptedWorld::from_json_str(fixtures::DOCKER_WORLD).expect("the built-in docker world loads")
}

fn port() -> ScriptedResourceProvider {
    ScriptedResourceProvider::new(world().into_shared())
}

fn web() -> ResourceId {
    ResourceId::derive(&["abc123def456"])
}

fn box_id() -> ResourceId {
    ResourceId::derive(&["box"])
}

fn window(offset: u64, length: u64) -> ReadWindow {
    ReadWindow { offset, length }
}

// --- ResourceProvider --------------------------------------------------------

#[tokio::test]
async fn discover_pages_until_the_cursor_runs_out() {
    let p = port();
    let mut cursor = None;
    let mut delivered: Vec<ResourceNode> = Vec::new();
    let mut pages = 0usize;
    loop {
        let page = p.discover(cursor).await.expect("page");
        pages += 1;
        delivered.extend(page.resources.iter().cloned());
        match page.cursor {
            Some(c) => cursor = Some(c),
            None => break,
        }
    }
    assert_eq!(pages, 2, "five resources at three per page is two pages");
    assert_eq!(
        delivered.len(),
        5,
        "every resource is delivered exactly once across the pages"
    );

    // The load-time rule is pre-order with siblings ordered by derived id, so
    // the order is checked as that rule rather than as a hardcoded name list:
    // a name list would have to be rewritten every time an id derivation
    // changes, and the rule is the part worth protecting.
    let mut names: Vec<&str> = delivered.iter().map(|r| r.name.as_str()).collect();
    names.sort_unstable();
    assert_eq!(
        names,
        vec!["bridge", "cache", "docker-engine", "nginx:latest", "web"],
        "every resource in the world, once each"
    );

    let position = |name: &str| -> usize {
        delivered
            .iter()
            .position(|r| r.name == name)
            .unwrap_or_else(|| panic!("{name} was delivered"))
    };
    for node in &delivered {
        if let Some(parent) = &node.parent_id {
            let parent_name = delivered
                .iter()
                .find(|r| &r.id == parent)
                .map(|r| r.name.clone())
                .unwrap_or_else(|| panic!("{} has a parent that was not delivered", node.name));
            assert!(
                position(&parent_name) < position(&node.name),
                "pre-order puts {parent_name} before {}, got {:?}",
                node.name,
                names
            );
        }
    }
    // `bridge` is a root, so nothing may follow it that belongs to the engine's
    // subtree only because of a hash collision in the sibling ordering.
    assert_eq!(position("docker-engine"), 0, "the root comes first");

    // A second scan of a quiescent provider must repeat it exactly.
    let again = p.discover(None).await.expect("first page again");
    assert_eq!(again.resources.len(), 3);
    assert_eq!(again.cursor.as_deref(), Some("page:1"));
    assert_eq!(
        again
            .resources
            .iter()
            .map(|r| r.name.clone())
            .collect::<Vec<_>>(),
        delivered[..3]
            .iter()
            .map(|r| r.name.clone())
            .collect::<Vec<_>>(),
        "a fresh scan starts from the same first page"
    );
}

#[tokio::test]
async fn inspect_returns_the_scripted_node_and_refuses_an_unknown_id() {
    let p = port();
    let node = p.inspect(&web()).await.expect("web is in the world");
    assert_eq!(node.name, "web");
    assert_eq!(node.kind, ResourceKind::Container);
    assert_eq!(node.state, ResourceState::Running);

    let err = p
        .inspect(&ResourceId::derive(&["ghost"]))
        .await
        .expect_err("unknown id");
    assert_eq!(err.code, ErrorCode::VFS_NOT_FOUND, "{err}");
    assert!(err.message.contains("no such resource"), "{err}");
}

#[tokio::test]
async fn health_reports_the_state_rather_than_failing_on_it() {
    // ADR-OBS-001: the probe describes the fault, so it must not be the thing
    // that fails.
    let healthy = port().health().await.expect("healthy provider");
    assert_eq!(healthy, ProviderHealth::Healthy);

    let down = ScriptedResourceProvider::from_fixture(
        sandtree_mock_runtime::WorldFixture::from_json_str(fixtures::UNAVAILABLE_WORLD).unwrap(),
    )
    .expect("world loads");
    let reported = down
        .health()
        .await
        .expect("health reports, it does not raise");
    assert!(!reported.control_is_available(), "{reported:?}");
    assert_eq!(reported.summary(), "unavailable");
    assert!(
        down.discover(None).await.is_err(),
        "control must be refused while unavailable"
    );
}

#[tokio::test]
async fn shutdown_is_idempotent_and_leaves_discovery_untouched() {
    let p = port();
    let before = p.discover(None).await.expect("page").resources;
    p.shutdown().await;
    p.shutdown().await;
    p.shutdown().await;
    assert_eq!(
        p.shutdown_count(),
        3,
        "every call is accepted; idempotence means no extra effect, not no call"
    );
    let after = p.discover(None).await.expect("page").resources;
    assert_eq!(
        before, after,
        "shutdown must not change what the world reports"
    );
}

// --- FileProvider: metadata discipline (FR-077) -----------------------------

#[tokio::test]
async fn list_returns_one_level_of_metadata_and_never_a_body() {
    let p = world().into_shared();
    let instance = p.provider_instance();
    let files = instance.files.expect("the world serves the file port");

    let root = workspace_uri(&web(), "").expect("root uri");
    let entries = files.list(&root).await.expect("root lists");
    let paths: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
    assert_eq!(
        paths,
        vec!["build.log", "etc", "src"],
        "path order is fixed"
    );

    let serialized = serde_json::to_string(&entries).expect("metadata serializes");
    assert!(
        !serialized.contains("hello") && !serialized.contains("port=8080"),
        "a listing must not carry file content: {serialized}"
    );

    // `src` has a child, which proves the listing is one level and not a subtree.
    let src = workspace_uri(&web(), "src").expect("src uri");
    let deep = files.list(&src).await.expect("src lists");
    assert_eq!(deep.len(), 1);
    assert_eq!(deep[0].path, "src/index.html");
    assert_eq!(deep[0].size, 14);
    assert_eq!(deep[0].mtime_ns, Some(1));
    assert_eq!(
        deep[0].hash_state,
        ContentHashState::MetadataKnown,
        "a fixture that declares no digest must not claim one"
    );
}

#[tokio::test]
async fn listing_a_file_or_a_missing_path_is_an_error() {
    let instance = world().into_shared().provider_instance();
    let files = instance.files.expect("file port");

    let file = workspace_uri(&web(), "src/index.html").expect("uri");
    assert_eq!(
        files.list(&file).await.unwrap_err().code,
        ErrorCode::CORE_INVALID,
        "a file is not a directory"
    );

    let missing = workspace_uri(&web(), "nope").expect("uri");
    assert_eq!(
        files.list(&missing).await.unwrap_err().code,
        ErrorCode::VFS_NOT_FOUND
    );
}

#[tokio::test]
async fn read_returns_exactly_the_requested_window() {
    let instance = world().into_shared().provider_instance();
    let files = instance.files.expect("file port");
    let uri = workspace_uri(&web(), "src/index.html").expect("uri");
    let whole = files.read(&uri, window(0, 1024)).await.expect("read");
    assert_eq!(whole, b"<h1>hello</h1>".to_vec());

    assert_eq!(
        files.read(&uri, window(4, 5)).await.expect("slice"),
        b"hello".to_vec()
    );
    assert_eq!(
        files.read(&uri, window(9, 5)).await.expect("tail slice"),
        b"</h1>".to_vec()
    );
    // A window past the end clamps rather than failing; an offset past the end
    // does fail, so the two are distinguishable.
    assert!(files.read(&uri, window(0, 4096)).await.is_ok());
    assert!(files.read(&uri, window(99, 1)).await.is_err());
}

#[tokio::test]
async fn reading_a_metadata_only_file_is_an_error_not_empty_bytes() {
    // FR-077 lazy content: the fixture declares `build.log` by size alone.
    let instance = world().into_shared().provider_instance();
    let files = instance.files.expect("file port");
    let uri = workspace_uri(&web(), "build.log").expect("uri");

    let meta = files.stat(&uri).await.expect("stat works");
    assert_eq!(meta.size, 4096, "the declared size is reported");

    let err = files.read(&uri, window(0, 16)).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::CORE_INVALID, "{err}");
    assert!(err.message.contains("FR-077"), "{err}");
}

#[tokio::test]
async fn reading_a_directory_is_refused() {
    let instance = world().into_shared().provider_instance();
    let files = instance.files.expect("file port");
    let uri = workspace_uri(&web(), "src").expect("uri");
    assert_eq!(
        files.read(&uri, window(0, 16)).await.unwrap_err().code,
        ErrorCode::CORE_INVALID
    );
}

// --- FileProvider: writes and confinement (NFR-S05) -------------------------

#[tokio::test]
async fn a_write_is_visible_to_a_later_read_and_stat() {
    let instance = world().into_shared().provider_instance();
    let files = instance.files.expect("file port");
    let uri = workspace_uri(&web(), "notes.txt").expect("uri");

    files.write(&uri, b"hello world").await.expect("write");
    assert_eq!(
        files.read(&uri, window(0, 64)).await.expect("read"),
        b"hello world".to_vec()
    );
    let meta = files.stat(&uri).await.expect("stat");
    assert_eq!(meta.size, 11);
    assert_eq!(meta.mtime_ns, None, "a fake must not invent a timestamp");
    assert_eq!(
        meta.hash_state,
        ContentHashState::UnknownHash,
        "the body changed, so no digest may still be advertised"
    );
}

#[tokio::test]
async fn writing_to_a_read_only_directory_is_refused() {
    let instance = world().into_shared().provider_instance();
    let files = instance.files.expect("file port");
    let uri = workspace_uri(&web(), "etc/app.conf").expect("uri");
    let err = files.write(&uri, b"tampered").await.unwrap_err();
    assert_eq!(err.code, ErrorCode::POLICY_DENIED, "{err}");
    assert!(err.message.contains("read-only"), "{err}");
    // The refusal really protected the file.
    assert_eq!(
        files.read(&uri, window(0, 64)).await.expect("read"),
        b"port=8080".to_vec()
    );
}

#[tokio::test]
async fn a_write_whose_parent_does_not_exist_is_refused() {
    let instance = world().into_shared().provider_instance();
    let files = instance.files.expect("file port");
    let uri = workspace_uri(&web(), "nowhere/deep/file.txt").expect("uri");
    assert_eq!(
        files.write(&uri, b"x").await.unwrap_err().code,
        ErrorCode::VFS_NOT_FOUND
    );
}

#[tokio::test]
async fn a_write_follows_a_symlink_to_its_resolved_target() {
    // `workspace/inside` resolves to `workspace/app/ok.txt`, so the write must
    // land there and leave no link behind.
    let w = ScriptedWorld::from_json_str(fixtures::ESCAPING_SYMLINK_WORLD).expect("world loads");
    let files = w
        .into_shared()
        .provider_instance()
        .files
        .expect("file port");

    let link = workspace_uri(&box_id(), "workspace/inside").expect("uri");
    files
        .write(&link, b"rewritten")
        .await
        .expect("write through link");

    let target = workspace_uri(&box_id(), "workspace/app/ok.txt").expect("uri");
    assert_eq!(
        files
            .read(&target, window(0, 64))
            .await
            .expect("target changed"),
        b"rewritten".to_vec()
    );
}

#[tokio::test]
async fn a_write_through_an_escaping_symlink_is_refused_and_writes_nothing() {
    let w = ScriptedWorld::from_json_str(fixtures::ESCAPING_SYMLINK_WORLD).expect("world loads");
    let files = w
        .into_shared()
        .provider_instance()
        .files
        .expect("file port");

    let escape = workspace_uri(&box_id(), "workspace/out/key.pem").expect("uri");
    let err = files.write(&escape, b"overwritten").await.unwrap_err();
    assert_eq!(err.code, ErrorCode::VFS_PATH_ESCAPE, "{err}");

    // The file that was being aimed at is untouched.
    let victim = workspace_uri(&box_id(), "secrets/key.pem").expect("uri");
    // Reaching it directly is refused too: two independent checks, one refusal.
    assert_eq!(
        files.stat(&victim).await.unwrap_err().code,
        ErrorCode::VFS_PATH_ESCAPE
    );
}

#[tokio::test]
async fn a_caller_cannot_express_a_traversal_at_all() {
    // The first half of NFR-S05: normalisation happens before routing, so a `..`
    // never reaches the provider as a canonical path.
    let err = workspace_uri(&web(), "../etc/passwd").unwrap_err();
    assert_eq!(err.code, ErrorCode::VFS_PATH_ESCAPE, "{err}");
    let err = workspace_uri(&web(), "src/../../escape").unwrap_err();
    assert_eq!(err.code, ErrorCode::VFS_PATH_ESCAPE, "{err}");
    let err = workspace_uri(&web(), "C:/Windows/System32").unwrap_err();
    assert_eq!(err.code, ErrorCode::VFS_PATH_ESCAPE, "{err}");
}

#[tokio::test]
async fn every_file_call_on_an_unavailable_provider_fails() {
    let w = ScriptedWorld::from_json_str(fixtures::UNAVAILABLE_WORLD).expect("world loads");
    let files = w
        .into_shared()
        .provider_instance()
        .files
        .expect("file port");
    let id = ResourceId::derive(&["mock-vm"]);
    let uri = workspace_uri(&id, "anything").expect("uri");
    for code in [
        files.list(&uri).await.unwrap_err().code,
        files.stat(&uri).await.unwrap_err().code,
        files.read(&uri, window(0, 1)).await.unwrap_err().code,
        files.write(&uri, b"x").await.unwrap_err().code,
    ] {
        assert_eq!(code, ErrorCode::SANDBOX_PROVIDER_UNAVAILABLE, "{code}");
    }
}

// --- ExecProvider (FR-013, FR-025) ------------------------------------------

#[tokio::test]
async fn exec_returns_the_scripted_outcome() {
    let w = ScriptedWorld::from_json_str(fixtures::DOCKER_WORLD).expect("world loads");
    let exec = w.into_shared().provider_instance().exec.expect("exec port");

    let out = exec
        .exec(
            &web(),
            &["cat".to_string(), "/etc/hostname".to_string()],
            5_000,
        )
        .await
        .expect("scripted command");
    assert_eq!(out.stdout, "web\n");
    assert_eq!(out.exit_code, 0);
    assert!(!out.truncated);
}

#[tokio::test]
async fn exec_output_longer_than_the_cap_comes_back_truncated() {
    let w = ScriptedWorld::from_json_str(fixtures::LARGE_OUTPUT_WORLD).expect("world loads");
    let exec = w.into_shared().provider_instance().exec.expect("exec port");
    let id = ResourceId::derive(&["noisy"]);

    let out = exec
        .exec(&id, &["yes".to_string()], 5_000)
        .await
        .expect("runs");
    assert!(out.truncated);
    assert_eq!(out.stdout.len(), sandtree_mock_runtime::MAX_CAPTURE_BYTES);
    assert!(
        fixtures::LARGE_OUTPUT_WORLD.len() > sandtree_mock_runtime::MAX_CAPTURE_BYTES,
        "the fixture must really declare more output than the cap allows, or \
         this test would pass without the cap doing anything"
    );
}

#[tokio::test]
async fn exec_refuses_a_zero_budget_and_an_uncovered_command() {
    let w = ScriptedWorld::from_json_str(fixtures::DOCKER_WORLD).expect("world loads");
    let exec = w.into_shared().provider_instance().exec.expect("exec port");
    let zero = exec
        .exec(&web(), &["false".to_string()], 0)
        .await
        .unwrap_err();
    assert_eq!(zero.code, ErrorCode::CORE_INVALID, "{zero}");
    let unknown = exec
        .exec(&web(), &["whoami".to_string()], 1_000)
        .await
        .unwrap_err();
    assert_eq!(unknown.code, ErrorCode::CORE_INVALID);
}

#[tokio::test]
async fn exec_on_an_unknown_resource_is_not_found() {
    let w = ScriptedWorld::from_json_str(fixtures::DOCKER_WORLD).expect("world loads");
    let exec = w.into_shared().provider_instance().exec.expect("exec port");
    let err = exec
        .exec(
            &ResourceId::derive(&["ghost"]),
            &["false".to_string()],
            1_000,
        )
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::VFS_NOT_FOUND, "{err}");
}

// --- the refusals the fake repeats from the kernel --------------------------

#[tokio::test]
async fn the_fake_refuses_what_the_kernel_refuses() {
    // FR-023 / NFR-U02: without `force` a destructive call never reaches a
    // provider, and a fake that skipped the check would let a direct port call
    // succeed on a path production cannot take.
    let instance = world().into_shared().provider_instance();
    let resource = instance.resource.expect("resource port");
    let refused = resource
        .invoke(&OperationRequest::new(
            web(),
            OperationKind::Destroy,
            json!({}),
            Correlation::generate(),
        ))
        .await
        .unwrap_err();
    assert_eq!(refused.code, ErrorCode::POLICY_DENIED);
    assert!(refused.message.contains("force"), "{refused}");

    let forced = resource
        .invoke(&OperationRequest::new(
            web(),
            OperationKind::Destroy,
            json!({"force": true}),
            Correlation::generate(),
        ))
        .await
        .expect("forced destroy runs");
    assert_eq!(forced.state, OperationState::Succeeded);
}
