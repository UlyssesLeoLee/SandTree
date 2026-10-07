//! Generation route table (DD-PLG §4, FR-052).
//!
//! The atomic swap is the whole point: routing decisions read one pointer, and
//! swapping it is a single write under a short lock (NFR-P04: ≤ 250 ms, and in
//! practice microseconds). Everything expensive — instantiating the new
//! component, running `init`, health checks, state migration — happens *before*
//! the swap, so a failure there never costs the caller their working plugin
//! (AC-04).

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use sandtree_model::id::PluginId;

/// A routing generation number.
///
/// Generation 0 is reserved for "not staged", so a runtime built from a
/// `Default` is visibly unrouted rather than silently generation 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Generation(pub u64);

impl std::fmt::Display for Generation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "gen-{}", self.0)
    }
}

/// Maps a plugin id to the generation that currently receives traffic.
#[derive(Debug, Clone, Default)]
pub struct RouteTable {
    routes: Arc<RwLock<BTreeMap<PluginId, Generation>>>,
}

impl RouteTable {
    /// Empty routing table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Generation currently serving a plugin, if any.
    pub fn current(&self, plugin: &PluginId) -> Option<Generation> {
        self.routes.read().expect("route lock").get(plugin).copied()
    }

    /// Point a plugin at a new generation and return the previous one.
    ///
    /// This is the only place traffic routing changes. It is a single map write
    /// under a write lock, which is why the swap itself is bounded regardless of
    /// how large the plugin is.
    pub fn atomic_swap(&self, plugin: &PluginId, next: Generation) -> Option<Generation> {
        let mut routes = self.routes.write().expect("route lock");
        routes.insert(plugin.clone(), next)
    }

    /// Restore a previous generation.
    pub fn rollback(&self, plugin: &PluginId, previous: Generation) {
        self.routes
            .write()
            .expect("route lock")
            .insert(plugin.clone(), previous);
    }

    /// Stop routing a plugin entirely (uninstall / drain finished).
    pub fn remove(&self, plugin: &PluginId) -> Option<Generation> {
        self.routes.write().expect("route lock").remove(plugin)
    }

    /// Full routing snapshot, deterministic order.
    pub fn snapshot(&self) -> BTreeMap<PluginId, Generation> {
        self.routes.read().expect("route lock").clone()
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

    fn pid(name: &str) -> PluginId {
        PluginId::derive(&[name])
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
        assert_eq!(t.atomic_swap(&pid("a"), Generation(1)), None);
        assert_eq!(t.atomic_swap(&pid("a"), Generation(2)), Some(Generation(1)));
        assert_eq!(t.current(&pid("a")), Some(Generation(2)));
    }

    #[test]
    fn rollback_restores_the_previous_generation() {
        // AC-04: a failure after the swap must be able to put the old
        // generation back, without a reinstall.
        let t = RouteTable::new();
        t.atomic_swap(&pid("a"), Generation(1));
        let previous = t.atomic_swap(&pid("a"), Generation(2)).unwrap();
        t.rollback(&pid("a"), previous);
        assert_eq!(t.current(&pid("a")), Some(Generation(1)));
    }

    #[test]
    fn routes_are_per_plugin() {
        let t = RouteTable::new();
        t.atomic_swap(&pid("a"), Generation(1));
        t.atomic_swap(&pid("b"), Generation(7));
        assert_eq!(t.current(&pid("a")), Some(Generation(1)));
        assert_eq!(t.current(&pid("b")), Some(Generation(7)));
        assert_eq!(t.len(), 2);
        let snap = t.snapshot();
        assert_eq!(snap.get(&pid("a")), Some(&Generation(1)));
    }

    #[test]
    fn swap_is_fast_enough_for_the_requirement() {
        // NFR-P04: the atomic route swap itself must be ≤ 250 ms. Measured over
        // many iterations so the assertion is about the operation, not noise.
        let t = RouteTable::new();
        let start = std::time::Instant::now();
        for i in 0..1_000 {
            t.atomic_swap(&pid("a"), Generation(i));
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
        t.atomic_swap(&pid("a"), Generation(1));
        assert_eq!(t.remove(&pid("a")), Some(Generation(1)));
        assert!(t.current(&pid("a")).is_none());
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
}
