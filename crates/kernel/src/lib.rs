//! Kernel bootstrap and composition root (DD-SW §3).
//!
//! The kernel owns the managers and the only mutable state. It depends on
//! provider **traits** (`sandtree_sdk::ports`) and never on a provider SDK
//! (NFR-O02): a Docker, Multipass or Windows Sandbox type cannot reach this
//! crate even by accident, because the dependency does not exist here.
//!
//! Control and observation stay separate all the way down. A provider that
//! cannot observe anything still controls its resources, and `observe` failing
//! never becomes "the resource does not exist" (ADR-OBS-001).

#![deny(missing_docs)]

pub mod diagnostics;
pub mod observation;
pub mod operations;
pub mod resources;

use std::path::PathBuf;
use std::sync::Arc;

use sandtree_event::EventRouter;
use sandtree_model::error::DomainError;
use sandtree_model::id::PluginId;
use sandtree_model::operation::{OperationOutcome, OperationRequest};
use sandtree_model::resource::ResourceNode;
use sandtree_observation_model::{ObservationRequest, ObservationSnapshot};
use sandtree_sdk::ports::ProviderRegistry;
use sandtree_store::db::{Store, StoreConfig};
use sandtree_store::repo::Change;
use serde_json::Value as Json;

pub use observation::RegistryBackend;
pub use operations::OperationManager;
pub use resources::{ReconcileOutcome, ResourceFilter, ResourceManager, TreeNode};

/// Kernel startup configuration.
#[derive(Debug, Clone)]
pub struct KernelConfig {
    /// Directory holding `sandtree.db` and the CAS.
    pub data_dir: PathBuf,
    /// Providers to load at bootstrap, in order.
    pub providers: Vec<PluginId>,
    /// Background reconcile interval (DD-SW §5).
    pub reconcile_interval_ms: u64,
    /// How long a resource may stay `stale` before it is tombstoned
    /// (DD-SW §5: "missing 先标 stale，超过 grace 才 delete/tombstone").
    pub stale_grace_ms: u64,
}

impl KernelConfig {
    /// A configuration rooted at `data_dir` with design default timings.
    pub fn new(data_dir: impl Into<PathBuf>) -> Self {
        Self {
            data_dir: data_dir.into(),
            providers: Vec::new(),
            reconcile_interval_ms: 15_000,
            stale_grace_ms: 60_000,
        }
    }
}

/// The SandTree kernel.
pub struct Kernel {
    store: Arc<Store>,
    cas: Arc<sandtree_store::cas::Cas>,
    events: Arc<EventRouter>,
    registry: tokio::sync::RwLock<ProviderRegistry>,
    resources: Arc<ResourceManager>,
    operations: Arc<OperationManager>,
    observation: Arc<sandtree_observation_core::ObservationService>,
    cfg: KernelConfig,
    correlation: sandtree_model::resource::Correlation,
}

impl std::fmt::Debug for Kernel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Kernel")
            .field("providers", &self.cfg.providers)
            .field("store", &self.store.path())
            .finish()
    }
}

impl Kernel {
    /// Open the store, prepare the CAS and build the managers.
    ///
    /// No provider is contacted here. A kernel that cannot reach Docker at
    /// boot is still a working kernel with an unavailable provider, not a
    /// failed startup (ADR-OBS-001).
    pub async fn bootstrap(cfg: KernelConfig) -> Result<Self, DomainError> {
        std::fs::create_dir_all(&cfg.data_dir).map_err(|e| {
            DomainError::new(
                sandtree_model::error::ErrorCode::CORE_INVALID,
                format!("cannot create data dir {}: {e}", cfg.data_dir.display()),
            )
        })?;

        let store = Arc::new(Store::open(StoreConfig {
            path: cfg.data_dir.join("sandtree.db"),
            ..StoreConfig::default()
        })?);
        store.migrate()?;
        // NFR-P01: operations left running by a crash are reconciled at boot,
        // not left dangling.
        let interrupted = store.mark_interrupted_operations()?;

        let cas = Arc::new(sandtree_store::cas::Cas::new(cfg.data_dir.join("cas"))?);

        let events = Arc::new(EventRouter::new());
        let observation = Arc::new(sandtree_observation_core::ObservationService::new());

        let resources = Arc::new(ResourceManager::new(
            store.clone(),
            cas.clone(),
            events.clone(),
            cfg.stale_grace_ms,
        ));
        let operations = Arc::new(OperationManager::new(
            store.clone(),
            events.clone(),
            sandtree_policy::PolicyEngine::new(),
        ));

        if interrupted > 0 {
            tracing::warn!(
                interrupted,
                "marked operations from a previous run as interrupted at bootstrap"
            );
        }

        Ok(Self {
            store,
            cas,
            events,
            registry: tokio::sync::RwLock::new(ProviderRegistry::new()),
            resources,
            operations,
            observation,
            cfg,
            correlation: sandtree_model::resource::Correlation::generate(),
        })
    }

    /// Configuration this kernel was built with.
    pub fn config(&self) -> &KernelConfig {
        &self.cfg
    }

    /// The persistent store.
    pub fn store(&self) -> &Arc<Store> {
        &self.store
    }

    /// The content-addressed store.
    pub fn cas(&self) -> &Arc<sandtree_store::cas::Cas> {
        &self.cas
    }

    /// The event router (DD-SW §3).
    pub fn event_router(&self) -> &Arc<EventRouter> {
        &self.events
    }

    /// The observation service (DD-SW §12.2).
    pub fn observation(&self) -> &Arc<sandtree_observation_core::ObservationService> {
        &self.observation
    }

    /// The operation manager (dangerous-op confirmation + audit live there).
    pub fn operations(&self) -> &Arc<OperationManager> {
        &self.operations
    }

    /// The resource manager.
    pub fn resources(&self) -> &Arc<ResourceManager> {
        &self.resources
    }

    /// Declare what a plugin says it can do.
    pub async fn set_declared(
        &self,
        plugin: PluginId,
        caps: sandtree_model::capability::CapabilitySet,
    ) {
        self.operations.set_declared(plugin, caps).await;
    }

    /// Grant one capability to a plugin.
    pub async fn allow(&self, plugin: PluginId, cap: sandtree_model::capability::Capability) {
        self.operations.allow(plugin, cap).await;
    }

    /// Revoke one capability from a plugin.
    pub async fn revoke(&self, plugin: &PluginId, cap: &sandtree_model::capability::Capability) {
        self.operations.revoke(plugin, cap).await;
    }

    /// Kernel-wide correlation id for one CLI/IPC session (NFR-O01).
    pub fn correlation(&self) -> &sandtree_model::resource::Correlation {
        &self.correlation
    }

    /// Register a provider instance. Replaces any existing instance for the
    /// same plugin id, which is what a hot swap produces.
    pub async fn register_provider(
        &self,
        instance: sandtree_sdk::ports::ProviderInstance,
    ) -> Result<(), DomainError> {
        self.registry.write().await.register(instance);
        Ok(())
    }

    /// Snapshot of the provider registry, deterministic order.
    pub async fn providers(&self) -> Vec<PluginId> {
        self.registry
            .read()
            .await
            .iter()
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Scan every registered provider and merge the results (NFR-A01).
    ///
    /// A provider that errors contributes an error event and nothing else; it
    /// does not abort the scan and does not mark its resources gone. That
    /// distinction is the whole reason control and observation are separate
    /// planes.
    pub async fn discover_all(&self) -> Result<Vec<Change>, DomainError> {
        self.resources
            .discover_all(&*self.registry.read().await, &self.events)
            .await
    }

    /// Remove what has been missing past the grace period, then rescan.
    ///
    /// Removal runs **before** discovery on purpose. A resource that stops
    /// being reported is marked `unknown` by this call's scan, and only a
    /// *later* call can remove it. Doing it the other way round would mark and
    /// delete in the same pass, and with a zero grace period the user would
    /// never see the `unknown` state at all.
    pub async fn reconcile(&self) -> Result<ReconcileOutcome, DomainError> {
        let mut outcome = self.resources.reconcile().await?;
        outcome.changes = self.discover_all().await?;
        Ok(outcome)
    }

    /// Invoke an operation on a resource.
    pub async fn invoke(&self, req: OperationRequest) -> Result<OperationOutcome, DomainError> {
        self.operations
            .invoke(req, &*self.registry.read().await)
            .await
    }

    /// Produce an observation snapshot.
    ///
    /// A resource with no observation provider fails with a typed error; it is
    /// never reported as "absent", and its control plane is untouched
    /// (ADR-OBS-001).
    pub async fn observe(
        &self,
        req: ObservationRequest,
    ) -> Result<ObservationSnapshot, DomainError> {
        let registry = self.registry.read().await;
        let backend = RegistryBackend::new(&registry, &self.store);
        self.observation.observe(&backend, req).await
    }

    /// Resource tree, filtered (DD-SW §4).
    pub async fn tree(&self, filter: &ResourceFilter) -> Result<Vec<TreeNode>, DomainError> {
        self.resources.tree(filter).await
    }

    /// One resource plus its relations.
    pub async fn inspect(
        &self,
        id: &sandtree_model::id::ResourceId,
    ) -> Result<ResourceNode, DomainError> {
        self.resources.inspect(id).await
    }

    /// Redacted diagnostics bundle (FR-066).
    pub async fn diagnostics_bundle(&self) -> Result<Json, DomainError> {
        diagnostics::bundle(self).await
    }

    /// Drain and shut down every provider, then flush.
    pub async fn shutdown(&self) {
        let providers: Vec<_> = {
            let mut reg = self.registry.write().await;
            let list: Vec<PluginId> = reg.iter().map(|(id, _)| id.clone()).collect();
            for id in &list {
                if let Some(inst) = reg.remove(id) {
                    drop(inst);
                }
            }
            list
        };
        for id in &providers {
            tracing::info!(plugin = %id, "provider released");
        }
    }
}

#[cfg(test)]
mod tests;
