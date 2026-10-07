//! SandTree plugin host (FR-050..055, DD-PLG).
//!
//! Responsibilities, in the order the design states them:
//!
//! * [`verify`] — decide whether a package may be staged at all, and with which
//!   capabilities. No runtime involved, so the trust decision is testable on
//!   its own.
//! * [`limits`] — the host ceiling for one plugin worker. Configuration may
//!   tighten, never loosen.
//! * [`hot_swap`] — the stage → health → migrate → atomic route swap → drain →
//!   rollback supervisor (FR-052).
//! * [`route`] — the generation route table the supervisor writes.
//! * [`engine`] — the WASM Component Model adapter, behind the `wasmtime-abi`
//!   feature, implementing [`hot_swap::GenerationRuntime`] for real components.
//!
//! ADR-002: the cross-version ABI is WIT + Component Model. Rust traits in this
//! crate are host-internal and are not an ABI; they exist so official
//! in-process providers and third-party components land on the same trait.

#![deny(missing_docs)]

pub mod hot_swap;
pub mod limits;
pub mod route;
pub mod verify;

#[cfg(feature = "wasmtime-abi")]
pub mod engine;

pub use hot_swap::{GenerationRuntime, HotSwapSupervisor, SwapResult, SwapTrace};
pub use limits::{check_against_ceiling, resolve, WorkerLimits};
pub use route::{Generation, HotSwapOutcome, RouteTable};
pub use verify::{InstallPolicy, StagedPackage};

/// Provider instances the host currently has loaded, per plugin id.
///
/// The host owns routing and lifetime; the kernel only ever sees the
/// `GenerationRuntime` trait, never a Wasmtime type (NFR-O02).
#[derive(Default)]
pub struct PluginHost {
    /// Plugin id -> loaded generation.
    loaded: std::collections::BTreeMap<
        sandtree_model::id::PluginId,
        std::sync::Arc<dyn GenerationRuntime>,
    >,
    /// Deterministic load order for enumeration.
    order: Vec<sandtree_model::id::PluginId>,
}

/// A trait object carries no `Debug`, so the host reports identity and
/// generation only — which is also all an operator needs to see.
impl std::fmt::Debug for PluginHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_map()
            .entries(
                self.order
                    .iter()
                    .filter_map(|p| self.loaded.get(p).map(|g| (p, g.generation()))),
            )
            .finish()
    }
}

impl PluginHost {
    /// Empty host.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a loaded generation.
    pub fn insert(
        &mut self,
        plugin: sandtree_model::id::PluginId,
        generation: std::sync::Arc<dyn GenerationRuntime>,
    ) {
        if self.loaded.insert(plugin.clone(), generation).is_none() {
            self.order.push(plugin);
        }
        self.order.sort();
    }

    /// Forget a plugin's generation.
    pub fn remove(
        &mut self,
        plugin: &sandtree_model::id::PluginId,
    ) -> Option<std::sync::Arc<dyn GenerationRuntime>> {
        self.order.retain(|p| p != plugin);
        self.loaded.remove(plugin)
    }

    /// Look up a loaded generation.
    pub fn get(
        &self,
        plugin: &sandtree_model::id::PluginId,
    ) -> Option<&std::sync::Arc<dyn GenerationRuntime>> {
        self.loaded.get(plugin)
    }

    /// Loaded plugins, in deterministic order.
    pub fn loaded(&self) -> &[sandtree_model::id::PluginId] {
        &self.order
    }

    /// Number of loaded plugins.
    pub fn len(&self) -> usize {
        self.loaded.len()
    }

    /// Whether nothing is loaded.
    pub fn is_empty(&self) -> bool {
        self.loaded.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hot_swap::GenerationRuntime;
    use crate::route::Generation;
    use sandtree_model::error::DomainError;
    use sandtree_model::id::PluginId;
    use sandtree_sdk::ports::ProviderHealth;
    use sandtree_sdk::wit::WitDescriptor;
    use std::sync::Arc;

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

    #[test]
    fn host_enumerates_in_deterministic_order() {
        let mut h = PluginHost::new();
        let a = PluginId::derive(&["a"]);
        let b = PluginId::derive(&["b"]);
        h.insert(b.clone(), Arc::new(Stub(2)));
        h.insert(a.clone(), Arc::new(Stub(1)));
        assert_eq!(h.loaded(), &[a.clone(), b.clone()]);
        assert_eq!(h.len(), 2);
        assert_eq!(h.get(&a).unwrap().generation(), Generation(1));
    }

    #[test]
    fn replacing_a_generation_does_not_duplicate_the_entry() {
        let mut h = PluginHost::new();
        let a = PluginId::derive(&["a"]);
        h.insert(a.clone(), Arc::new(Stub(1)));
        h.insert(a.clone(), Arc::new(Stub(2)));
        assert_eq!(h.len(), 1);
        assert_eq!(h.loaded().len(), 1);
        assert_eq!(h.get(&a).unwrap().generation(), Generation(2));
    }

    #[test]
    fn remove_drops_from_both_maps() {
        let mut h = PluginHost::new();
        let a = PluginId::derive(&["a"]);
        h.insert(a.clone(), Arc::new(Stub(1)));
        assert!(h.remove(&a).is_some());
        assert!(h.is_empty());
        assert!(h.loaded().is_empty());
    }
}
