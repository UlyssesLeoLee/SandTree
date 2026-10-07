//! A [`PluginLoader`] that stages a component **in this process** (FR-054, ADR-018).
//!
//! # What it does and does not isolate
//!
//! DD-PLG §10 and FR-055 put the worker in its own process so that a broken
//! worker takes down only itself. This loader does not deliver that, and ADR-018
//! records the deviation rather than pretending it is there.
//!
//! What *is* intact: a WASM guest remains memory-safe and capability-limited no
//! matter where its store lives. A trapping guest traps. What is lost is the
//! containment of the *host-side* worker code around it, and the OS-level
//! resource ceiling a separate process would give.
//!
//! Consequently this loader is **not** the daemon's default. The daemon still
//! ships [`crate::plugins::UnavailableLoader`], so a build that has not opted in
//! refuses rather than pretending. Turning this on is a decision, not a side
//! effect — which is why the whole module, tests included, sits behind
//! `in-process-worker`.
//!
//! The process-isolated counterpart is [`crate::worker_client::RemoteLoader`],
//! which is ungated and is the direction FR-055 actually points at.

use std::path::PathBuf;
use std::sync::Arc;

use sandtree_model::capability::CapabilitySet;
use sandtree_model::error::DomainError;
use sandtree_model::id::PluginId;
use sandtree_plugin_host::generation::LoadedGeneration;
use sandtree_plugin_host::limits::WorkerLimits;
use sandtree_plugin_host::route::Generation;
use sandtree_plugin_host::verify::InstallPolicy;
use sandtree_plugin_worker::{Worker, WorkerSpec};

use crate::packages::{DirectoryPackages, PackageSource};
use crate::plugins::PluginLoader;

/// Stages real components through [`sandtree_plugin_worker::Worker`].
pub struct WorkerLoader {
    source: Arc<dyn PackageSource>,
    policy: InstallPolicy,
    granted: CapabilitySet,
    limits: WorkerLimits,
}

impl WorkerLoader {
    /// Build a loader over `source`.
    ///
    /// `granted` is the daemon's capability ceiling; the worker's effective
    /// grant is that intersected with what the package asked for, which is the
    /// narrowing rule from NFR-S02 applied at the point of staging rather than
    /// at the point of use.
    pub fn new(
        source: Arc<dyn PackageSource>,
        policy: InstallPolicy,
        granted: CapabilitySet,
        limits: WorkerLimits,
    ) -> Self {
        Self {
            source,
            policy,
            granted,
            limits,
        }
    }

    /// A loader over a directory tree, with the host ceiling and no grant.
    ///
    /// Fails when the tree holds a package whose manifest will not parse: see
    /// [`DirectoryPackages::new`].
    pub fn over_directory(root: impl Into<PathBuf>) -> Result<Self, DomainError> {
        Ok(Self::new(
            Arc::new(DirectoryPackages::new(root)?),
            InstallPolicy::deny_all(),
            CapabilitySet::empty(),
            WorkerLimits::host_ceiling(),
        ))
    }

    /// Add an allowed license expression.
    #[must_use]
    pub fn allow_license(mut self, license: &str) -> Self {
        self.policy = self.policy.allow_license(license);
        self
    }

    /// The capability ceiling handed to every staged worker.
    pub fn granted(&self) -> &CapabilitySet {
        &self.granted
    }

    async fn stage_inner(
        &self,
        plugin: &PluginId,
        generation: Generation,
    ) -> Result<Arc<LoadedGeneration>, DomainError> {
        let spec = self.source.package(plugin)?;
        // The worker is dropped when this function returns. That is deliberate
        // and safe: `load` hands back an owned `Arc<LoadedGeneration>`, and the
        // lifecycle that matters -- drain then shutdown -- is driven through the
        // generation's runtime by the supervisor, not by the worker object.
        // Keeping the worker alive would only preserve its own state enum, which
        // nothing outside this function reads.
        let mut worker = Worker::new(WorkerSpec {
            component_path: spec.component_path,
            manifest: spec.manifest,
            generation,
            granted: self.granted.clone(),
            limits: self.limits,
        })
        .with_policy(self.policy.clone());

        worker.load().await
    }
}

impl std::fmt::Debug for WorkerLoader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WorkerLoader")
            .field("granted", &self.granted)
            .field("limits", &self.limits)
            .finish()
    }
}

#[async_trait::async_trait]
impl PluginLoader for WorkerLoader {
    async fn stage(
        &self,
        plugin: &PluginId,
        generation: Generation,
    ) -> Result<Arc<LoadedGeneration>, DomainError> {
        // Every failure below is wrapped once, here, so an operator reading a
        // stage failure always learns which plugin and which generation failed.
        // Wrapping per-failure-path is how "not installed" ends up reported
        // without a generation number while a verify error carries one.
        self.stage_inner(plugin, generation).await.map_err(|e| {
            DomainError::new(
                e.code,
                format!("plugin {plugin} generation {}: {}", generation.0, e.message),
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plugin() -> PluginId {
        PluginId::derive(&["sandtree.provider.example"])
    }

    #[tokio::test]
    async fn staging_a_plugin_with_no_package_on_disk_fails_before_any_engine_is_built() {
        let tmp = tempfile::tempdir().unwrap();
        let loader = WorkerLoader::over_directory(tmp.path())
            .expect("index")
            .allow_license("Apache-2.0");
        let err = loader
            .stage(&plugin(), Generation(1))
            .await
            .expect_err("nothing on disk");
        assert!(err.message.contains(plugin().as_str()), "{}", err.message);
        assert!(err.message.contains("generation 1"), "{}", err.message);
    }
}
