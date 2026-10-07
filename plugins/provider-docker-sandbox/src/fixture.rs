//! The embedded fixture world (DD-PLG §8).
//!
//! DD-PLG §8 requires that when neither the host API nor the CLI is available,
//! the provider still has something to run its regression against:
//!
//! > CLI 不可用时，provider 内部 fixture regression test。
//!
//! The fixture is therefore a first-class tier, not a test-only afterthought.
//! Two rules keep it honest:
//!
//! 1. **It is labelled.** Every node it produces carries
//!    [`crate::SOURCE_FIXTURE`] in its provenance metadata, so a caller can
//!    reject fixture-derived data without inferring it from missing fields
//!    (RD §9: never let unsupported state masquerade as supported).
//! 2. **It is deterministic.** Fixed ids, fixed states, fixed ordering. Two
//!    runs must produce byte-identical batches, or the regression it exists for
//!    would not be reproducible.
//!
//! # Why ids are derived, not random
//!
//! A fixture that mints fresh ids per run cannot be diffed against a previous
//! run, which defeats the purpose. [`fixture_sandbox_id`] therefore derives ids
//! from stable names via [`sandtree_model::id::ResourceId::derive`].

use sandtree_model::id::{PluginId, ResourceId};
use sandtree_model::resource::{Relation, RelationKind, ResourceKind, ResourceNode, ResourceState};
use sandtree_sdk::ports::DiscoverBatch;
use serde_json::json;

use crate::PLUGIN_ID;

/// One sandbox in the fixture world.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixtureSandbox {
    /// Stable name; also the id seed.
    pub name: String,
    /// Lifecycle state the fixture reports.
    pub state: ResourceState,
    /// Nested runtime the sandbox owns, if any.
    pub runtime: Option<String>,
    /// Images the sandbox's containers use.
    pub images: Vec<String>,
}

/// The fixture world: a fixed list of sandboxes.
pub fn world() -> Vec<FixtureSandbox> {
    vec![
        FixtureSandbox {
            name: "sbx-fixture-basic".to_string(),
            state: ResourceState::Running,
            runtime: Some("docker-fixture".to_string()),
            images: vec!["alpine:3.20".to_string()],
        },
        FixtureSandbox {
            name: "sbx-fixture-gpu".to_string(),
            state: ResourceState::Stopped,
            runtime: None,
            images: vec!["nvidia/cuda:12.4.1-runtime".to_string()],
        },
        FixtureSandbox {
            name: "sbx-fixture-nested".to_string(),
            state: ResourceState::Running,
            runtime: Some("docker-fixture".to_string()),
            // Two images, deliberately in non-sorted order in the source so the
            // normalisation step has something to do.
            images: vec!["ubuntu:24.04".to_string(), "alpine:3.20".to_string()],
        },
    ]
}

/// Stable sandbox id for a fixture name.
pub fn fixture_sandbox_id(name: &str) -> ResourceId {
    ResourceId::derive(&["docker-sandbox", "fixture", name])
}

/// Stable id for a fixture image.
pub fn fixture_image_id(sandbox: &str, image: &str) -> ResourceId {
    ResourceId::derive(&["docker-sandbox", "fixture", sandbox, "image", image])
}

/// Stable id for a fixture nested runtime.
pub fn fixture_runtime_id(sandbox: &str, runtime: &str) -> ResourceId {
    ResourceId::derive(&["docker-sandbox", "fixture", sandbox, "runtime", runtime])
}

/// Plugin id owning fixture resources.
pub fn fixture_plugin() -> PluginId {
    PluginId::derive(&[PLUGIN_ID])
}

/// Timestamp used for every fixture node.
///
/// Fixed rather than `now()` so two runs serialise identically. Fixture data is
/// a regression artefact, so pretending it was observed at a real time would be
/// a second layer of the same dishonesty.
pub const FIXTURE_TIMESTAMP: &str = "2026-01-01T00:00:00Z";

/// Build the fixture discovery batch.
///
/// Returns a complete batch (nodes plus relations), never a partial one: a
/// half-built batch would reconcile as "some sandboxes disappeared".
pub fn fixture_batch() -> DiscoverBatch {
    let plugin = fixture_plugin();
    let mut nodes: Vec<ResourceNode> = Vec::new();
    let mut relations: Vec<Relation> = Vec::new();

    for sbx in world() {
        let sbx_id = fixture_sandbox_id(&sbx.name);

        let node = ResourceNode::new(
            sbx_id.clone(),
            ResourceKind::Sandbox,
            plugin.clone(),
            sbx.name.clone(),
            sbx.state,
            None,
            FIXTURE_TIMESTAMP.to_string(),
        )
        .with_metadata(json!({
            "provenance": crate::SOURCE_FIXTURE,
            "fixture": true,
            "tier": crate::tier::SandboxTier::Fixture.as_str(),
        }));
        nodes.push(node);

        // Images: sorted so the batch is deterministic regardless of the order
        // the fixture source happens to list them in.
        let mut images = sbx.images.clone();
        images.sort();
        for image in images {
            let img_id = fixture_image_id(&sbx.name, &image);
            nodes.push(
                ResourceNode::new(
                    img_id.clone(),
                    ResourceKind::Image,
                    plugin.clone(),
                    image.clone(),
                    ResourceState::Unknown,
                    None,
                    FIXTURE_TIMESTAMP.to_string(),
                )
                .with_metadata(json!({
                    "provenance": crate::SOURCE_FIXTURE,
                    "fixture": true,
                })),
            );
            relations.push(Relation::new(
                sbx_id.clone(),
                img_id,
                RelationKind::UsesImage,
            ));
        }

        if let Some(rt) = &sbx.runtime {
            let rt_id = fixture_runtime_id(&sbx.name, rt);
            nodes.push(
                ResourceNode::new(
                    rt_id.clone(),
                    ResourceKind::DockerRuntime,
                    plugin.clone(),
                    rt.clone(),
                    ResourceState::Running,
                    None,
                    FIXTURE_TIMESTAMP.to_string(),
                )
                .with_metadata(json!({
                    "provenance": crate::SOURCE_FIXTURE,
                    "fixture": true,
                })),
            );
            relations.push(Relation::new(
                sbx_id.clone(),
                rt_id,
                RelationKind::DockerInSandbox,
            ));
        }
    }

    // Deterministic order for the same reason: golden comparison needs it.
    nodes.sort_by(|a, b| a.id.as_str().cmp(b.id.as_str()));
    relations.sort_by(|a, b| {
        a.from
            .as_str()
            .cmp(b.from.as_str())
            .then(a.to.as_str().cmp(b.to.as_str()))
    });

    DiscoverBatch {
        resources: nodes,
        relations,
        cursor: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tier::SandboxTier;
    use serde_json::Value as Json;

    #[test]
    fn the_fixture_world_is_not_empty() {
        // An empty fixture would make the whole tier indistinguishable from
        // "nothing exists", which is exactly the confusion ADR-OBS-001 forbids.
        assert!(!world().is_empty());
        assert!(!fixture_batch().resources.is_empty());
    }

    #[test]
    fn two_runs_produce_identical_batches() {
        let a = fixture_batch();
        let b = fixture_batch();
        assert_eq!(
            a.resources, b.resources,
            "fixture discovery must be byte-identical across runs"
        );
        assert_eq!(a.relations, b.relations);
    }

    #[test]
    fn the_batch_is_already_sorted() {
        // Sortedness is asserted rather than assumed, because it is what makes
        // the determinism guarantee meaningful.
        let b = fixture_batch();
        let ids: Vec<&str> = b.resources.iter().map(|n| n.id.as_str()).collect();
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        assert_eq!(ids, sorted, "fixture nodes must be emitted in sorted order");
    }

    #[test]
    fn every_node_is_labelled_as_fixture_data() {
        // A caller must never be able to mistake fixture output for a real
        // runtime (RD §9).
        for n in fixture_batch().resources {
            assert_eq!(
                n.meta_str("provenance"),
                Some(crate::SOURCE_FIXTURE),
                "node {} is not labelled as fixture data",
                n.id
            );
            assert_eq!(n.metadata["fixture"], Json::Bool(true));
        }
    }

    #[test]
    fn sandbox_nodes_record_the_fixture_tier() {
        let b = fixture_batch();
        let sandboxes: Vec<_> = b
            .resources
            .iter()
            .filter(|n| n.kind == ResourceKind::Sandbox)
            .collect();
        assert_eq!(sandboxes.len(), world().len());
        for s in sandboxes {
            assert_eq!(s.meta_str("tier"), Some(SandboxTier::Fixture.as_str()));
        }
    }

    #[test]
    fn relations_always_resolve_to_nodes_in_the_same_batch() {
        // A relation pointing at a missing node would create a dangling edge in
        // the resource graph.
        let b = fixture_batch();
        let ids: Vec<&str> = b.resources.iter().map(|n| n.id.as_str()).collect();
        for r in &b.relations {
            assert!(
                ids.contains(&r.from.as_str()),
                "relation source {} missing from batch",
                r.from
            );
            assert!(
                ids.contains(&r.to.as_str()),
                "relation target {} missing from batch",
                r.to
            );
        }
    }

    #[test]
    fn image_relations_use_the_uses_image_edge() {
        let b = fixture_batch();
        assert!(b
            .relations
            .iter()
            .any(|r| r.kind == RelationKind::UsesImage));
    }

    #[test]
    fn nested_runtime_relations_use_the_docker_in_sandbox_edge() {
        let b = fixture_batch();
        assert!(b
            .relations
            .iter()
            .any(|r| r.kind == RelationKind::DockerInSandbox));
    }

    #[test]
    fn ids_are_stable_across_calls() {
        assert_eq!(
            fixture_sandbox_id("sbx-fixture-basic"),
            fixture_sandbox_id("sbx-fixture-basic")
        );
        assert_ne!(
            fixture_sandbox_id("sbx-fixture-basic"),
            fixture_sandbox_id("sbx-fixture-gpu")
        );
    }

    #[test]
    fn a_fixture_sandbox_without_a_runtime_emits_no_runtime_relation() {
        // The GPU fixture has no runtime; it must not gain a dangling edge.
        let b = fixture_batch();
        let gpu = fixture_sandbox_id("sbx-fixture-gpu");
        assert!(!b
            .relations
            .iter()
            .any(|r| r.from == gpu && r.kind == RelationKind::DockerInSandbox));
    }

    #[test]
    fn the_fixture_timestamp_is_fixed_not_wall_clock() {
        assert_eq!(FIXTURE_TIMESTAMP, "2026-01-01T00:00:00Z");
        for n in fixture_batch().resources {
            assert_eq!(n.last_seen, FIXTURE_TIMESTAMP);
        }
    }
}
