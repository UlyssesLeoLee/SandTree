//! The crate's headline property, and the fleet scan that expresses it.
//!
//! NFR-O04: for the same fixture, `discover_all` must serialize to the same
//! bytes no matter what was invoked first. That is what makes a failing
//! regression reproducible from a file name, and it is the claim these tests
//! exist to defend.

use std::sync::Arc;

use sandtree_model::error::{DomainError, ErrorCode};
use sandtree_model::id::{PluginId, ResourceId};
use sandtree_model::operation::{OperationKind, OperationRequest};
use sandtree_model::resource::{Correlation, ResourceNode};
use sandtree_sdk::ports::{
    DiscoverBatch, ProviderDescriptor, ProviderHealth, ResourceProvider,
};
use sandtree_mock_runtime::file_provider::workspace_uri;
use sandtree_mock_runtime::{
    discover_all, FailurePhase, fixtures, resource_provider::ScriptedResourceProvider,
    ScriptedWorld,
};
use serde_json::json;
use sandtree_vfs::ReadWindow;

fn world() -> ScriptedWorld {
    ScriptedWorld::from_json_str(fixtures::DOCKER_WORLD).expect("the built-in docker world loads")
}

fn as_port(w: ScriptedWorld) -> Arc<dyn ResourceProvider> {
    Arc::new(ScriptedResourceProvider::new(w.into_shared()))
}

fn web() -> ResourceId {
    ResourceId::derive(&["abc123def456"])
}

// --- determinism -------------------------------------------------------------

#[tokio::test]
async fn discover_all_is_byte_identical_no_matter_what_was_invoked_first() {
    let shared = world().into_shared();
    let instance = shared.provider_instance();
    let resource = instance.resource.expect("resource port");
    let files = instance.files.expect("file port");
    let exec = instance.exec.expect("exec port");

    let scan = |_: ()| async {
        discover_all(std::slice::from_ref(&resource)).await.to_json()
    };

    // Baseline, taken before anything else happens.
    let baseline = scan(()).await;
    assert!(!baseline.is_empty(), "the baseline scan must have content");

    // A refused operation, an accepted one, a failed one, a shutdown, a file
    // write and an exec, in that order.
    let _ = resource
        .invoke(&OperationRequest::new(
            web(),
            OperationKind::Destroy,
            json!({}),
            Correlation::generate(),
        ))
        .await;
    let _ = resource
        .invoke(&OperationRequest::new(
            web(),
            OperationKind::Start,
            json!({}),
            Correlation::generate(),
        ))
        .await;
    let _ = resource.shutdown().await;

    let writable = workspace_uri(&web(), "written.txt").expect("uri");
    files.write(&writable, b"determinism").await.expect("write");
    let _ = files.read(&writable, ReadWindow { offset: 0, length: 64 }).await;
    let _ = files.list(&workspace_uri(&web(), "").unwrap()).await;

    let _ = exec
        .exec(&web(), &["cat".to_string(), "/etc/hostname".to_string()], 5_000)
        .await;

    assert_eq!(
        baseline,
        scan(()).await,
        "the resource set must be unchanged by anything the ports did"
    );
}

#[tokio::test]
async fn two_worlds_built_from_the_same_json_agree_byte_for_byte() {
    let a = discover_all(&[as_port(world())]).await.to_json();
    let b = discover_all(&[as_port(world())]).await.to_json();
    assert_eq!(a, b, "the same fixture must always scan the same way");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_scan_is_reproducible_across_tokio_worker_threads() {
    // A fake that leaked a thread-local or a scheduling order would disagree
    // here; run the same scan from a multi-threaded runtime.
    let handles: Vec<_> = (0..4)
        .map(|_| {
            tokio::spawn(async {
                let w = ScriptedWorld::from_json_str(fixtures::DOCKER_WORLD).expect("loads");
                discover_all(&[as_port(w)]).await.to_json()
            })
        })
        .collect();
    let mut results = Vec::new();
    for h in handles {
        results.push(h.await.expect("task joined"));
    }
    assert!(
        results.windows(2).all(|w| w[0] == w[1]),
        "concurrent scans disagreed: {results:?}"
    );
}

#[tokio::test]
async fn a_fresh_scan_reproduces_the_fixture_exactly() {
    let expected: Vec<ResourceNode> = world().resources().to_vec();
    let plugin_id = world().plugin_id().clone();
    let relations = world().relations().to_vec();
    let scan = discover_all(&[as_port(world())]).await;
    assert!(scan.is_complete(), "{:?}", scan.failures);
    assert_eq!(scan.resources, expected, "every resource, in world order");
    assert_eq!(scan.relations, relations, "every relation, in world order");

    let discovery = &scan.discoveries[0];
    assert_eq!(discovery.page_count(), 2);
    assert!(discovery.completed(), "the cursor chain ran to its end");
    assert_eq!(discovery.health, ProviderHealth::Healthy);
    assert_eq!(discovery.plugin_id, plugin_id);
    assert_eq!(discovery.descriptor.version, "1.2.3");
}

// --- fault collection --------------------------------------------------------

#[tokio::test]
async fn a_provider_that_fails_mid_scan_keeps_its_earlier_pages() {
    let broken = ScriptedWorld::from_json_str(fixtures::MID_PAGE_FAILURE_WORLD)
        .expect("world loads");
    let healthy_count = world().resources().len();
    let scan = discover_all(&[as_port(broken), as_port(world())]).await;

    assert!(!scan.is_complete());
    assert_eq!(scan.failures.len(), 1);
    let f = &scan.failures[0];
    assert_eq!(f.phase, FailurePhase::Discover);
    assert_eq!(f.page, 1);
    assert_eq!(f.pages_delivered, 1, "page 0 really was delivered");
    assert_eq!(f.code, ErrorCode::DOCKER_ENDPOINT_UNAVAILABLE);

    // The healthy provider is unaffected: one dead provider does not lose the
    // scan of the others.
    assert_eq!(
        scan.resources.len(),
        2 + healthy_count,
        "the partial scan and the full one are both present"
    );
}

#[tokio::test]
async fn an_unavailable_provider_fails_every_call_but_still_reports_health() {
    let down = ScriptedWorld::from_json_str(fixtures::UNAVAILABLE_WORLD).expect("world loads");
    let scan = discover_all(&[as_port(down)]).await;

    assert_eq!(scan.failures.len(), 1);
    let f = &scan.failures[0];
    assert_eq!(f.phase, FailurePhase::Discover);
    assert_eq!(f.pages_delivered, 0);
    assert_eq!(f.code, ErrorCode::SANDBOX_PROVIDER_UNAVAILABLE);
    assert!(
        scan.resources.is_empty(),
        "an unavailable provider contributes no resources"
    );
    // The health probe succeeded, so the world is in `discoveries` too.
    assert_eq!(scan.discoveries.len(), 1);
    assert!(!scan.discoveries[0].health.control_is_available());
}

#[tokio::test]
async fn an_empty_provider_list_scans_to_nothing() {
    let first = discover_all(&[]).await;
    let second = discover_all(&[]).await;
    assert!(first.is_complete());
    assert!(first.resources.is_empty());
    assert!(first.discoveries.is_empty());
    assert_eq!(
        first.to_json(),
        second.to_json(),
        "two empty scans must agree byte for byte"
    );
}

// --- a caller-side guard, proven with a deliberately broken provider ---------

/// A provider whose cursor never advances, so a scan that trusted the cursor
/// would spin forever.
struct StuckProvider;

#[async_trait::async_trait]
impl ResourceProvider for StuckProvider {
    fn descriptor(&self) -> ProviderDescriptor {
        ProviderDescriptor {
            plugin_id: PluginId::derive(&["stuck"]).to_string(),
            version: "0.0.0-mock".into(),
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
            cursor: Some("page:1".into()),
        })
    }
    async fn inspect(&self, _id: &ResourceId) -> Result<ResourceNode, DomainError> {
        Err(DomainError::not_found("stuck provider has no resources"))
    }
    async fn invoke(&self, _req: &OperationRequest) -> Result<sandtree_model::operation::OperationOutcome, DomainError> {
        Err(DomainError::core_invalid("stuck provider runs nothing"))
    }
    async fn shutdown(&self) {}
}

#[tokio::test]
async fn a_cursor_that_does_not_advance_terminates_the_scan() {
    // Without this guard the call would not return. The test passing *is* the
    // assertion: it would hang, not fail, if the guard were removed.
    let scan = discover_all(&[Arc::new(StuckProvider) as Arc<dyn ResourceProvider>]).await;
    assert_eq!(scan.failures.len(), 1);
    let f = &scan.failures[0];
    assert_eq!(f.phase, FailurePhase::NoProgress);
    assert_eq!(f.code, ErrorCode::CORE_INVALID);
    assert!(f.message.contains("cannot advance"), "{f:?}");
}
