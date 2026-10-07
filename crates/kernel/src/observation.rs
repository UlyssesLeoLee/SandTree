//! Bridge from the provider registry to the Observation Plane service.
//!
//! `sandtree-observation-core` deliberately knows nothing about providers; it
//! takes an [`ObservationBackend`]. This adapter is the only place that knows
//! both, which keeps the dependency one-directional (NFR-O02): the kernel may
//! import both, but neither may import the other for the other's sake.
//!
//! Routing rule: a resource is observed by the plugin that *owns* it, taken from
//! the stored `ResourceNode`. There is no fallback provider — if the owner has
//! no observation port, the request fails with a typed error rather than being
//! quietly answered by a different plugin (invariant 10).

use sandtree_model::error::{DomainError, ErrorCode};
use sandtree_model::id::ResourceId;
use sandtree_observation_model::{ObservationCapabilities, ObservationPlan, ObservationSnapshot};
use sandtree_sdk::ports::ProviderRegistry;
use sandtree_store::db::Store;

/// Adapts a [`ProviderRegistry`] to the observation service's backend port.
///
/// Borrowed rather than owned: the kernel holds both behind locks, and a single
/// observation call must see one consistent view of the registry.
pub struct RegistryBackend<'a> {
    registry: &'a ProviderRegistry,
    store: &'a Store,
}

impl<'a> RegistryBackend<'a> {
    /// Build a backend over borrowed registry and store.
    pub fn new(registry: &'a ProviderRegistry, store: &'a Store) -> Self {
        Self { registry, store }
    }

    /// The observation provider that owns `id`, if any.
    fn provider_for(
        &self,
        id: &ResourceId,
    ) -> Result<&std::sync::Arc<dyn sandtree_sdk::ports::ObservationProvider>, DomainError> {
        let node = self.store.resource(id)?.ok_or_else(|| {
            DomainError::new(ErrorCode::CORE_INVALID, format!("no such resource: {id}"))
        })?;
        let instance = self.registry.get(&node.provider_id).ok_or_else(|| {
            DomainError::new(
                ErrorCode::CORE_INVALID,
                format!("no provider instance registered for {}", node.provider_id),
            )
        })?;
        instance.observation.as_ref().ok_or_else(|| {
            DomainError::new(
                ErrorCode::OBS_NO_STRATEGY,
                format!(
                    "provider {} has no observation port for {id}; \
                     the resource still exists and remains controllable",
                    node.provider_id
                ),
            )
        })
    }
}

impl sandtree_observation_core::service::ObservationBackend for RegistryBackend<'_> {
    async fn capabilities(&self, id: &ResourceId) -> Result<ObservationCapabilities, DomainError> {
        self.provider_for(id)?.capabilities(id).await
    }

    async fn collect(
        &self,
        id: &ResourceId,
        plan: &ObservationPlan,
    ) -> Result<ObservationSnapshot, DomainError> {
        // The provider port takes a request, the service hands us a negotiated
        // plan. Translate one into the other here rather than widening the
        // provider trait: the plan's mode and domains are already the
        // negotiated answer, so re-negotiating would be a second opinion.
        let request =
            sandtree_observation_model::ObservationRequest::new(id.clone(), plan.domains.clone())
                .with_deadline_ms(plan.deadline_ms)
                .with_max_age_ms(plan.max_age_ms);
        self.provider_for(id)?.observe(&request).await
    }
}
