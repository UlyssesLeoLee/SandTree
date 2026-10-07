//! One loaded generation = lifecycle control surface + the ports it serves
//! (DD-PLG §4, ADR-016).
//!
//! Before this type existed, a generation was described twice and stored twice:
//!
//! * [`crate::hot_swap::GenerationRuntime`] — the lifecycle object the supervisor
//!   drives (`init` / `health` / `prepare-upgrade` / `accept-upgrade` / `drain` /
//!   `shutdown`),
//! * [`sandtree_sdk::ports::ProviderInstance`] — the ports the kernel routes
//!   traffic to (`ResourceProvider` / `ObservationProvider` / …).
//!
//! Two descriptions of one thing means two places to get it wrong. The kernel
//! registry carried `ProviderInstance.generation`, the route table carried its own
//! `Generation`, and **nothing checked that they agreed**. A swap that moved the
//! route pointer without updating the instance map produced a route pointing at a
//! generation the host could not hand out — the exact failure the "atomic swap" in
//! DD-PLG §4 exists to prevent.
//!
//! [`LoadedGeneration`] binds the two. A generation is now one value that carries
//! both, and the route table stores that value, so swapping the route pointer and
//! making the instance available are the *same* write.

use std::sync::Arc;

use sandtree_model::id::PluginId;
use sandtree_sdk::ports::ProviderInstance;

use crate::hot_swap::GenerationRuntime;
use crate::route::Generation;

/// A generation that is loaded and ready to serve.
///
/// Construct one per generation and hand it to
/// [`crate::route::RouteTable::atomic_swap`]. The generation number is assigned
/// here, once, and the [`ProviderInstance`] handed to [`LoadedGeneration::new`] is
/// rewritten to match — so a ports bundle cannot claim to be a different
/// generation than the one the host routes to.
pub struct LoadedGeneration {
    plugin_id: PluginId,
    generation: Generation,
    runtime: Arc<dyn GenerationRuntime>,
    ports: ProviderInstance,
}

impl std::fmt::Debug for LoadedGeneration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadedGeneration")
            .field("plugin_id", &self.plugin_id)
            .field("generation", &self.generation)
            .field(
                "ports",
                &format_args!(
                    "resource={} observation={} files={} exec={}",
                    self.ports.has_resource(),
                    self.ports.has_observation(),
                    self.ports.files.is_some(),
                    self.ports.exec.is_some(),
                ),
            )
            .finish()
    }
}

impl LoadedGeneration {
    /// Bind a lifecycle object and its ports into one routable generation.
    ///
    /// `ports.generation` is **overwritten** with `generation`. The caller's
    /// value is not an input to be trusted: the host is the only authority on
    /// which generation is live (ADR-016), and a mismatch here would reintroduce
    /// the split the type exists to remove.
    pub fn new(
        plugin_id: PluginId,
        generation: Generation,
        runtime: Arc<dyn GenerationRuntime>,
        mut ports: ProviderInstance,
    ) -> Self {
        ports.plugin_id = plugin_id.clone();
        ports.generation = generation.0;
        Self {
            plugin_id,
            generation,
            runtime,
            ports,
        }
    }

    /// A generation that serves no ports, only lifecycle.
    ///
    /// Valid for a component whose WIT exports the lifecycle interface but whose
    /// provider ports are not wired yet; the supervisor can still stage, health
    /// check, migrate and retire it.
    pub fn lifecycle_only(
        plugin_id: PluginId,
        generation: Generation,
        runtime: Arc<dyn GenerationRuntime>,
    ) -> Self {
        Self::new(
            plugin_id.clone(),
            generation,
            runtime,
            ProviderInstance::empty(plugin_id),
        )
    }

    /// Owning plugin id.
    pub fn plugin_id(&self) -> &PluginId {
        &self.plugin_id
    }

    /// This generation's number.
    pub fn generation(&self) -> Generation {
        self.generation
    }

    /// The lifecycle object the supervisor drives.
    pub fn runtime(&self) -> &Arc<dyn GenerationRuntime> {
        &self.runtime
    }

    /// The ports the kernel routes to, with `generation` guaranteed to match.
    pub fn ports(&self) -> &ProviderInstance {
        &self.ports
    }

    /// A fresh [`ProviderInstance`] carrying the authoritative generation.
    ///
    /// Handed to [`sandtree_kernel::Kernel::register_provider`]. Built on demand
    /// because `ProviderInstance` is not `Clone`, and the projection into the
    /// kernel registry is what makes the two views observable for divergence
    /// testing.
    pub fn ports_for_registry(&self) -> ProviderInstance {
        let mut p = ProviderInstance::clone_ports(&self.ports);
        p.plugin_id = self.plugin_id.clone();
        p.generation = self.generation.0;
        p
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sandtree_model::error::DomainError;
    use sandtree_observation_model::ObservationCapabilities;
    use sandtree_observation_model::{ObservationRequest, ObservationSnapshot};
    use sandtree_sdk::ports::{ObservationProvider, ProviderHealth};

    struct Stub(u64);

    #[async_trait::async_trait]
    impl GenerationRuntime for Stub {
        fn generation(&self) -> Generation {
            Generation(self.0)
        }
        fn descriptor(&self) -> sandtree_sdk::wit::WitDescriptor {
            sandtree_sdk::wit::WitDescriptor {
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

    struct Obs;

    #[async_trait::async_trait]
    impl ObservationProvider for Obs {
        async fn capabilities(
            &self,
            _: &sandtree_model::id::ResourceId,
        ) -> Result<ObservationCapabilities, DomainError> {
            Ok(ObservationCapabilities::default())
        }
        async fn observe(
            &self,
            _: &ObservationRequest,
        ) -> Result<ObservationSnapshot, DomainError> {
            unreachable!("not called by these tests")
        }
    }

    fn pid() -> PluginId {
        PluginId::derive(&["sandtree.stub"])
    }

    #[test]
    fn the_ports_generation_is_rewritten_to_the_hosts_authority() {
        // The whole point of the type: a caller cannot smuggle a mismatched
        // generation number into the bundle the host will route traffic to.
        // If `new` stopped rewriting, `ports().generation` would stay 999 while
        // `generation()` said 7, and the kernel registry would advertise a
        // generation the route table never had.
        let ports = ProviderInstance {
            plugin_id: pid(),
            generation: 999,
            resource: None,
            observation: Some(Arc::new(Obs)),
            files: None,
            exec: None,
        };

        let loaded = LoadedGeneration::new(pid(), Generation(7), Arc::new(Stub(7)), ports);

        assert_eq!(loaded.generation(), Generation(7));
        assert_eq!(loaded.ports().generation, 7);
        assert!(loaded.ports().has_observation());
    }

    #[test]
    fn the_plugin_id_is_rewritten_too() {
        // Same reasoning as the generation: the host, not the caller, decides
        // which plugin a bundle belongs to. A bundle claiming another plugin's
        // id would otherwise let one plugin's install overwrite another's.
        let ports = ProviderInstance {
            plugin_id: PluginId::derive(&["someone.else"]),
            generation: 1,
            resource: None,
            observation: None,
            files: None,
            exec: None,
        };
        let loaded = LoadedGeneration::new(pid(), Generation(1), Arc::new(Stub(1)), ports);
        assert_eq!(loaded.plugin_id(), &pid());
        assert_eq!(loaded.ports().plugin_id, pid());
    }

    #[test]
    fn the_registry_projection_repeats_the_same_generation() {
        // The projection handed to the kernel must not drift from the host's
        // own view; it is rebuilt from `self`, not carried over from the input.
        let loaded = LoadedGeneration::lifecycle_only(pid(), Generation(4), Arc::new(Stub(4)));
        let projected = loaded.ports_for_registry();
        assert_eq!(projected.generation, 4);
        assert_eq!(projected.plugin_id, pid());
    }

    #[test]
    fn debug_does_not_require_the_runtime_to_be_debug() {
        // A trait object has no `Debug`; the summary must still be printable so
        // host diagnostics do not need a bespoke formatter.
        let loaded = LoadedGeneration::lifecycle_only(pid(), Generation(1), Arc::new(Stub(1)));
        let text = format!("{loaded:?}");
        assert!(text.contains("generation"), "{text}");
        assert!(text.contains("observation=false"), "{text}");
    }
}
