//! Generation route table (DD-PLG §4, FR-052, ADR-016).
//!
//! The table maps a plugin id to the **loaded generation that currently receives
//! traffic**. It stores the [`LoadedGeneration`] itself, not just its number, and
//! that is the whole point: DD-PLG §4's atomic swap has to move the route pointer
//! *and* make the new instance available, and the only way both are true
//! simultaneously is to make them one write.
//!
//! Splitting them (a `PluginId -> Generation` map plus a separate instance map)
//! leaves a window in which the route names a generation the host cannot hand out.
//! No amount of care in the supervisor closes that window, because the two writes
//! are in different maps.
//!
//! Swapping is a single [`BTreeMap::insert`] under a short write lock, so it is
//! bounded (NFR-P04 ≤ 250 ms) regardless of plugin size. Everything expensive —
//! compiling the component, `init`, health, state migration — happens before it.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use sandtree_model::id::PluginId;

use crate::generation::LoadedGeneration;

/// A routing generation number.
///
/// Generation 0 is reserved for "not staged", so a value built from `Default` is
/// visibly unrouted rather than silently generation 1.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Default,
    serde::Serialize,
    serde::Deserialize,
)]
#[serde(transparent)]
pub struct Generation(pub u64);

impl std::fmt::Display for Generation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "gen-{}", self.0)
    }
}

/// Plugin id → the generation serving it.
#[derive(Debug, Clone, Default)]
pub struct RouteTable {
    routes: Arc<RwLock<BTreeMap<PluginId, Arc<LoadedGeneration>>>>,
}

impl RouteTable {
    /// Empty routing table.
    pub fn new() -> Self {
        Self::default()
    }

    /// The generation currently serving a plugin, if any.
    ///
    /// This is the value traffic is routed through, so a caller that needs the
    /// ports takes them from here rather than from a second lookup that could
    /// observe a different generation.
    pub fn current(&self, plugin: &PluginId) -> Option<Arc<LoadedGeneration>> {
        self.routes.read().expect("route lock").get(plugin).cloned()
    }

    /// The generation *number* currently serving a plugin.
    pub fn current_generation(&self, plugin: &PluginId) -> Option<Generation> {
        self.current(plugin).map(|g| g.generation())
    }

    /// Route a plugin at `next` and return the generation it replaced.
    ///
    /// The only place traffic routing changes. One map insert under a write lock
    /// moves both the pointer and the instance, so there is no interval in which
    /// the route names a generation the host does not hold.
    pub fn atomic_swap(
        &self,
        plugin: &PluginId,
        next: Arc<LoadedGeneration>,
    ) -> Option<Arc<LoadedGeneration>> {
        debug_assert_eq!(
            plugin,
            next.plugin_id(),
            "a generation can only be routed for the plugin that owns it"
        );
        let mut routes = self.routes.write().expect("route lock");
        routes.insert(plugin.clone(), next)
    }

    /// Route several plugins at once, in a single critical section.
    ///
    /// This is what makes an App Cluster atomic (DD-PLG 核心原则
    /// "Plugin Cluster→App Cluster"). The table is guarded by one lock, so
    /// publishing N generations is one write of N entries: no caller can observe
    /// a cluster where the control plane has moved but the data plane has not.
    ///
    /// Calling [`RouteTable::atomic_swap`] N times instead would leave a window
    /// in which half the app serves traffic — the cluster is only a unit if its
    /// members become live together.
    ///
    /// Returns the generations each plugin previously served, in the same order
    /// as `batch`. Duplicate plugin ids are a caller bug: the later entry wins,
    /// so the returned vector still lines up index-for-index.
    pub fn atomic_publish(
        &self,
        batch: Vec<(PluginId, Arc<LoadedGeneration>)>,
    ) -> Vec<Option<Arc<LoadedGeneration>>> {
        for (plugin, generation) in &batch {
            debug_assert_eq!(
                plugin,
                generation.plugin_id(),
                "a generation can only be routed for the plugin that owns it"
            );
        }
        let mut routes = self.routes.write().expect("route lock");
        batch
            .into_iter()
            .map(|(plugin, generation)| routes.insert(plugin, generation))
            .collect()
    }

    /// Put a previously serving generation back.
    ///
    /// Takes the instance, not a number: a generation number alone is not enough
    /// to restore traffic, because the host would have no object to route to. The
    /// caller gets that instance back from [`crate::hot_swap::SwapResult::retired`].
    pub fn rollback(&self, plugin: &PluginId, previous: Arc<LoadedGeneration>) {
        debug_assert_eq!(plugin, previous.plugin_id());
        self.routes
            .write()
            .expect("route lock")
            .insert(plugin.clone(), previous);
    }

    /// Stop routing a plugin entirely (uninstall / retire).
    pub fn remove(&self, plugin: &PluginId) -> Option<Arc<LoadedGeneration>> {
        self.routes.write().expect("route lock").remove(plugin)
    }

    /// Full routing snapshot, deterministic order.
    pub fn snapshot(&self) -> BTreeMap<PluginId, Generation> {
        self.routes
            .read()
            .expect("route lock")
            .iter()
            .map(|(id, gen)| (id.clone(), gen.generation()))
            .collect()
    }

    /// Routed plugin ids, deterministic order.
    pub fn plugins(&self) -> Vec<PluginId> {
        self.routes
            .read()
            .expect("route lock")
            .keys()
            .cloned()
            .collect()
    }

    /// Number of routed plugins.
    pub fn len(&self) -> usize {
        self.routes.read().expect("route lock").len()
    }

    /// Whether nothing is routed.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Result of a hot swap attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HotSwapOutcome {
    /// Whether the route now points at the new generation.
    pub swapped: bool,
    /// The generation now serving traffic (old or new).
    pub generation: Option<Generation>,
    /// Human-readable reason; empty on an unqualified success.
    pub reason: String,
}

impl HotSwapOutcome {
    /// Successful swap to `generation`.
    pub fn swapped(generation: Generation) -> Self {
        Self {
            swapped: true,
            generation: Some(generation),
            reason: String::new(),
        }
    }

    /// Swap refused or reverted; `generation` is the generation still serving.
    pub fn refused(generation: Option<Generation>, reason: impl Into<String>) -> Self {
        Self {
            swapped: false,
            generation,
            reason: reason.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hot_swap::GenerationRuntime;
    use sandtree_model::error::DomainError;
    use sandtree_sdk::ports::{ProviderHealth, ProviderInstance};
    use sandtree_sdk::wit::WitDescriptor;

    struct Stub(u64);

    #[async_trait::async_trait]
    impl GenerationRuntime for Stub {
        fn generation(&self) -> Generation {
            Generation(self.0)
        }
        fn descriptor(&self) -> WitDescriptor {
            WitDescriptor {
                plugin_id: "stub".into(),
                version: "1.0.0".into(),
                state_schema_version: 1,
            }
        }
        async fn init(&self, _: &serde_json::Value) -> Result<(), DomainError> {
            Ok(())
        }
        async fn health(&self) -> Result<ProviderHealth, DomainError> {
            Ok(ProviderHealth::Healthy)
        }
        async fn prepare_upgrade(&self, _: &str) -> Result<Vec<u8>, DomainError> {
            Ok(Vec::new())
        }
        async fn accept_upgrade(&self, _: &str, _: &[u8]) -> Result<(), DomainError> {
            Ok(())
        }
        async fn drain(&self, _: u64) -> Result<(), DomainError> {
            Ok(())
        }
        async fn shutdown(&self) {}
    }

    fn pid(name: &str) -> PluginId {
        PluginId::derive(&[name])
    }

    fn gen(plugin: &PluginId, n: u64) -> Arc<LoadedGeneration> {
        Arc::new(LoadedGeneration::lifecycle_only(
            plugin.clone(),
            Generation(n),
            Arc::new(Stub(n)),
        ))
    }

    #[test]
    fn unregistered_plugin_has_no_generation() {
        let t = RouteTable::new();
        assert!(t.current(&pid("a")).is_none());
        assert!(t.is_empty());
    }

    #[test]
    fn swap_returns_the_previous_generation() {
        let t = RouteTable::new();
        let a = pid("a");
        assert!(t.atomic_swap(&a, gen(&a, 1)).is_none());
        let retired = t.atomic_swap(&a, gen(&a, 2)).unwrap();
        assert_eq!(retired.generation(), Generation(1));
        assert_eq!(t.current_generation(&a), Some(Generation(2)));
    }

    #[test]
    fn the_routed_generation_and_its_instance_are_always_the_same_value() {
        // ADR-016. Before the table held instances, these were two lookups in two
        // maps and could disagree. If `current()` ever stopped returning the
        // routed instance, this is the assertion that fails: it reads the number
        // and the ports from the same `Arc`, so a split representation shows up
        // here as a generation number that disagrees with its own instance.
        let t = RouteTable::new();
        let a = pid("a");
        let g = gen(&a, 5);
        t.atomic_swap(&a, g.clone());

        let served = t.current(&a).expect("routed");
        assert_eq!(served.generation(), t.current_generation(&a).unwrap());
        assert_eq!(served.ports().generation, served.generation().0);
        assert_eq!(served.plugin_id(), &a);
    }

    #[test]
    fn rollback_restores_the_previous_generation() {
        // AC-04: a failure after the swap must be able to put the old generation
        // back, without a reinstall — and the restored value must be the real
        // instance, not just its number.
        let t = RouteTable::new();
        let a = pid("a");
        let first = gen(&a, 1);
        t.atomic_swap(&a, first.clone());
        let retired = t.atomic_swap(&a, gen(&a, 2)).unwrap();

        t.rollback(&a, retired);

        assert_eq!(t.current_generation(&a), Some(Generation(1)));
        assert_eq!(t.current(&a).unwrap().generation(), Generation(1));
    }

    #[test]
    fn routes_are_per_plugin() {
        let t = RouteTable::new();
        let (a, b) = (pid("a"), pid("b"));
        t.atomic_swap(&a, gen(&a, 1));
        t.atomic_swap(&b, gen(&b, 7));
        assert_eq!(t.current_generation(&a), Some(Generation(1)));
        assert_eq!(t.current_generation(&b), Some(Generation(7)));
        assert_eq!(t.len(), 2);
        assert_eq!(t.plugins(), vec![a.clone(), b.clone()]);
        assert_eq!(t.snapshot().get(&a), Some(&Generation(1)));
    }

    #[test]
    fn swap_is_fast_enough_for_the_requirement() {
        // NFR-P04: the atomic route swap itself must be ≤ 250 ms. Measured over
        // many iterations so the assertion is about the operation, not noise.
        let t = RouteTable::new();
        let a = pid("a");
        let start = std::time::Instant::now();
        for i in 1..=1_000 {
            t.atomic_swap(&a, gen(&a, i));
        }
        let elapsed = start.elapsed();
        assert!(
            elapsed.as_millis() < 250,
            "1000 swaps took {elapsed:?}, far above the per-swap budget"
        );
    }

    #[test]
    fn remove_stops_routing() {
        let t = RouteTable::new();
        let a = pid("a");
        t.atomic_swap(&a, gen(&a, 1));
        assert_eq!(t.remove(&a).map(|g| g.generation()), Some(Generation(1)));
        assert!(t.current(&a).is_none());
    }

    #[test]
    fn outcome_helpers_read_correctly() {
        let ok = HotSwapOutcome::swapped(Generation(2));
        assert!(ok.swapped);
        assert!(ok.reason.is_empty());
        let bad = HotSwapOutcome::refused(Some(Generation(1)), "health probe failed");
        assert!(!bad.swapped);
        assert_eq!(bad.generation, Some(Generation(1)));
        assert_eq!(bad.reason, "health probe failed");
    }

    #[test]
    fn a_generation_can_only_be_routed_for_its_own_plugin() {
        // `atomic_swap` debug-asserts the owner matches. If the assertion were
        // removed and a caller routed plugin A's instance under plugin B, the
        // route would hand B's traffic an instance whose ports and lifecycle
        // belong to A. The assertion is the guard; this documents what it guards.
        let a = pid("a");
        let b = pid("b");
        let t = RouteTable::new();
        t.atomic_swap(&a, gen(&a, 1));
        // Routing B correctly does not disturb A.
        t.atomic_swap(&b, gen(&b, 1));
        assert_eq!(t.current_generation(&a), Some(Generation(1)));
        assert_eq!(t.current(&a).unwrap().plugin_id(), &a);
    }

    #[test]
    fn lifecycle_only_generations_route_without_any_port() {
        // A component may export the lifecycle interface and no provider port.
        // The table must still hold it — otherwise a valid package would be
        // unstaged for the sole reason that it serves nothing yet.
        let a = pid("a");
        let t = RouteTable::new();
        let g = gen(&a, 1);
        assert!(g.ports().is_empty());
        t.atomic_swap(&a, g);
        assert_eq!(t.current(&a).unwrap().ports().generation, 1);
        assert!(t.current(&a).unwrap().ports().is_empty());
    }

    #[test]
    fn the_ports_bundle_carries_no_port_when_empty() {
        // Guards the builder default: `ProviderInstance::empty` must really be
        // empty, otherwise `lifecycle_only` would advertise capabilities it does
        // not have (ADR-OBS-001: never fake a capability).
        let e = ProviderInstance::empty(pid("a"));
        assert!(e.is_empty());
        assert!(!e.has_resource());
        assert!(!e.has_observation());
    }
}
