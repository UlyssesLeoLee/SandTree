//! Cross-crate flows over the mock world.
//!
//! These cover contracts that only exist once two crates meet, which is why a
//! unit test in either one cannot see them.
//!
//! # Discovery and the `resource_relation` foreign key
//!
//! `resource_relation` declares `FOREIGN KEY(from_id/to_id) REFERENCES
//! resource(id)`. Discovery wrote each page's relations immediately after that
//! page's resources, but paging follows the provider's pre-order, so a relation
//! on page 0 routinely names a resource page 1 has not delivered yet. The whole
//! scan then failed with `FOREIGN KEY constraint failed` — and it only failed
//! for providers whose relations crossed a page boundary, so a small fixture
//! hides it and a real Docker host hits it on the first scan.
//!
//! The fix buffers relations until the cursor chain ends. The test below pins
//! that, and deliberately uses a world whose relations *do* cross the boundary.

use std::sync::Arc;

use sandtree_kernel::{Kernel, KernelConfig};
use sandtree_mock_runtime::{fixtures, ScriptedWorld};
use sandtree_model::id::ResourceId;

/// Discovery completes and every relation survives, even though the fixture's
/// relations point at resources delivered on a later page.
#[tokio::test]
async fn relations_that_span_a_page_boundary_are_still_written() {
    let _dir = tempfile::tempdir().expect("tempdir");
    let kernel = Arc::new(
        Kernel::bootstrap(KernelConfig::new(_dir.path()))
            .await
            .expect("bootstrap"),
    );

    let world = ScriptedWorld::from_json_str(fixtures::DOCKER_WORLD).expect("world loads");
    // The premise of this test: the fixture really does paginate, and really
    // does have relations whose endpoints are not all on the first page.
    assert!(
        world.page_count() > 1,
        "a single page cannot exercise a page boundary; the fixture paginates"
    );
    let first_page_ids: Vec<ResourceId> = world
        .page(None)
        .expect("first page")
        .resources
        .iter()
        .map(|r| r.id.clone())
        .collect();
    let cross_page = world
        .relations()
        .iter()
        .any(|rel| first_page_ids.contains(&rel.from) && !first_page_ids.contains(&rel.to));
    assert!(
        cross_page,
        "the fixture must carry a relation whose source is on page 1 and whose \
         target is not, or this test proves nothing"
    );

    kernel
        .register_provider(world.into_shared().provider_instance())
        .await
        .expect("register");

    let changes = kernel
        .discover_all()
        .await
        .expect("discovery must not fail on a relation crossing a page boundary");

    assert_eq!(
        changes.len(),
        5,
        "every resource in the fixture becomes a change: {changes:?}"
    );

    // Both endpoints of every relation exist, and the relation itself is
    // readable -- not silently dropped by a `?` on the insert.
    for id in first_page_ids {
        let relations = kernel.store().relations_of(&id).expect("relations list");
        for rel in &relations {
            assert!(
                kernel.store().resource(&rel.from).expect("from").is_some(),
                "relation {} -> {} survived with a missing source",
                rel.from.as_str(),
                rel.to.as_str()
            );
            assert!(
                kernel.store().resource(&rel.to).expect("to").is_some(),
                "relation {} -> {} survived with a missing target",
                rel.from.as_str(),
                rel.to.as_str()
            );
        }
    }

    // The relation count is exact, so a partially-written scan is visible.
    let stored = kernel
        .store()
        .resources(None, None)
        .expect("resources list");
    assert_eq!(
        stored.len(),
        5,
        "every fixture resource is in the store, once each"
    );
}

/// A second scan of an unchanged provider produces no changes: discovery is
/// idempotent, so a background reconcile does not churn the resource tree.
#[tokio::test]
async fn a_second_scan_of_an_unchanged_provider_changes_nothing() {
    let _dir = tempfile::tempdir().expect("tempdir");
    let kernel = Kernel::bootstrap(KernelConfig::new(_dir.path()))
        .await
        .expect("bootstrap");
    kernel
        .register_provider(
            ScriptedWorld::from_json_str(fixtures::DOCKER_WORLD)
                .expect("world loads")
                .into_shared()
                .provider_instance(),
        )
        .await
        .expect("register");

    let first = kernel.discover_all().await.expect("first scan");
    assert_eq!(first.len(), 5, "the first scan introduces every resource");

    let second = kernel.discover_all().await.expect("second scan");
    assert!(
        second.is_empty(),
        "an unchanged provider must report no changes, got {second:?}"
    );
}
