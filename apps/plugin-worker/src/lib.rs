//! Plugin worker process (DD-PLG §10, FR-055).
//!
//! A worker hosts one plugin generation in its own process. The point is blast
//! radius: a guest that traps, loops, or leaks takes down this process and
//! nothing else. The daemon treats a dead worker as a failed generation and can
//! swap in another without losing the route table, because the route lives in
//! the daemon, not here (FR-052).
//!
//! Two things are deliberately *not* here:
//!
//! * no ambient authority — the worker receives an explicit `WorkerLimits` and
//!   an explicit capability set, and nothing else, and
//! * no shared store — the worker never opens the database. A plugin that could
//!   write to the store would bypass the kernel's audit (NFR-S03).

#![deny(missing_docs)]

use std::path::PathBuf;
use std::sync::Arc;

use sandtree_model::capability::CapabilitySet;
use sandtree_model::error::{DomainError, ErrorCode};
use sandtree_plugin_host::generation::LoadedGeneration;
use sandtree_plugin_host::hot_swap::GenerationRuntime;
use sandtree_plugin_host::limits::WorkerLimits;
use sandtree_plugin_host::route::Generation;
use sandtree_plugin_host::verify::{InstallPolicy, StagedPackage};
use sandtree_sdk::manifest::PluginManifest;
use serde_json::Value as Json;

/// What a worker was asked to run.
#[derive(Debug, Clone)]
pub struct WorkerSpec {
    /// Plugin package directory or component file.
    pub component_path: PathBuf,
    /// Plugin manifest as JSON.
    pub manifest: Json,
    /// Generation this worker serves.
    pub generation: Generation,
    /// Capabilities the daemon granted.
    pub granted: CapabilitySet,
    /// Resource ceilings.
    pub limits: WorkerLimits,
}

impl WorkerSpec {
    /// Build a spec with the host ceiling and no grant.
    pub fn new(component_path: impl Into<PathBuf>, manifest: Json, generation: Generation) -> Self {
        Self {
            component_path: component_path.into(),
            manifest,
            generation,
            granted: CapabilitySet::empty(),
            limits: WorkerLimits::host_ceiling(),
        }
    }
}

/// Worker lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerState {
    /// Not started.
    Idle,
    /// Component compiled and bound.
    Ready,
    /// `init` has run.
    Initialised,
    /// Retired; the generation is no longer serving.
    Retired,
}

/// A running worker.
pub struct Worker {
    spec: WorkerSpec,
    state: WorkerState,
    /// The loaded generation, once [`Worker::load`] has succeeded.
    ///
    /// Held as a whole generation rather than a bare runtime so the value handed
    /// to the plugin host already carries its plugin id and generation number
    /// (ADR-016) — there is no point at which a caller could receive a
    /// lifecycle object and have to guess which plugin it belongs to.
    loaded: Option<Arc<LoadedGeneration>>,
    policy: InstallPolicy,
}

impl std::fmt::Debug for Worker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Worker")
            .field("state", &self.state)
            .field("generation", &self.spec.generation)
            .field("loaded", &self.loaded.is_some())
            .finish()
    }
}

impl Worker {
    /// Build a worker that has not started yet.
    pub fn new(spec: WorkerSpec) -> Self {
        Self {
            spec,
            state: WorkerState::Idle,
            loaded: None,
            policy: InstallPolicy::deny_all(),
        }
    }

    /// Set the install policy (license allow-list, component requirement).
    pub fn with_policy(mut self, policy: InstallPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Current state.
    pub fn state(&self) -> WorkerState {
        self.state
    }

    /// The staged package after verification, before any component runs.
    ///
    /// Verification is separate from loading on purpose: a package that fails
    /// the license or capability check must never reach the engine.
    pub fn verify(&self) -> Result<StagedPackage, DomainError> {
        let manifest = PluginManifest::from_json(&self.spec.manifest)?;
        let bytes = std::fs::read(&self.spec.component_path).map_err(|e| {
            DomainError::new(
                ErrorCode::PLUGIN_MANIFEST_INVALID,
                format!(
                    "cannot read component {}: {e}",
                    self.spec.component_path.display()
                ),
            )
        })?;
        let hash = blake3::hash(&bytes).to_hex().to_string();
        let mut policy = self.policy.clone();
        // A worker runs one component, so a component is always required here.
        policy.require_component = true;
        sandtree_plugin_host::verify::verify(&manifest, &bytes, &hash, &policy)
    }

    /// Load the component and mark the worker ready.
    ///
    /// Returns the loaded generation, ready to hand to
    /// [`sandtree_plugin_host::HotSwapSupervisor`]. The caller decides whether it
    /// becomes live; loading is not publishing (DD-PLG §4: everything expensive
    /// happens before the route write).
    ///
    /// Only compiled when the host was built with the `wasmtime-abi` feature;
    /// otherwise this returns a typed error instead of pretending to load.
    pub async fn load(&mut self) -> Result<Arc<LoadedGeneration>, DomainError> {
        let staged = self.verify()?;
        // The grant the worker actually runs with is the daemon's grant narrowed
        // by what the package was allowed to ask for.
        let effective = staged.granted.intersect(&self.spec.granted);
        let bytes = std::fs::read(&self.spec.component_path).map_err(|e| {
            DomainError::new(
                ErrorCode::PLUGIN_MANIFEST_INVALID,
                format!("cannot read component bytes: {e}"),
            )
        })?;

        #[cfg(feature = "wasmtime-abi")]
        {
            use sandtree_plugin_host::engine::{build_engine, ComponentGeneration};
            use sandtree_sdk::manifest::PluginKind;
            let engine = build_engine(&self.spec.limits)?;
            // The manifest is the authority on a package's role; the WIT
            // descriptor carries only identity and state schema.
            let kind = staged.manifest.kind();
            let runtime = ComponentGeneration::load(
                &engine,
                &bytes,
                effective,
                self.spec.limits,
                self.spec.generation,
                kind,
            )
            .await;
            // The engine must outlive the runtime, so it is leaked into the
            // worker's process lifetime deliberately: a generation is dropped
            // only at retirement, and the worker process is the boundary.
            std::mem::forget(engine);
            let runtime = runtime?;

            // A `provider-plugin` component exposes the resource port, so the
            // routable bundle carries it. This is what lets the kernel discover,
            // inspect and invoke a component the same way it would any other
            // provider — before ADR-016 follow-up, a component could be staged
            // and health-checked but never served a request.
            //
            // The port is the same `Arc` the runtime is, not a second instance:
            // two generations of the same component sharing a store is how a
            // swapped-out plugin keeps serving traffic.
            let ports = match kind {
                PluginKind::Provider => {
                    sandtree_sdk::ports::ProviderInstance::empty(staged.plugin_id.clone())
                        .with_resource(
                            runtime.clone() as Arc<dyn sandtree_sdk::ports::ResourceProvider>
                        )
                }
                _ => sandtree_sdk::ports::ProviderInstance::empty(staged.plugin_id.clone()),
            };
            let loaded = Arc::new(LoadedGeneration::new(
                staged.plugin_id.clone(),
                self.spec.generation,
                runtime,
                ports,
            ));
            self.loaded = Some(loaded.clone());
            self.state = WorkerState::Ready;
            Ok(loaded)
        }
        #[cfg(not(feature = "wasmtime-abi"))]
        {
            let _ = (bytes, effective);
            Err(DomainError::new(
                ErrorCode::PLUGIN_HEALTH_FAILED,
                "this worker was built without the `wasmtime-abi` feature, so it \
                 cannot load a WASM component",
            ))
        }
    }

    /// Run `init` and mark the worker initialised.
    pub async fn initialise(&mut self, config: &Json) -> Result<(), DomainError> {
        let loaded = self.loaded.as_ref().ok_or_else(|| {
            DomainError::new(ErrorCode::PLUGIN_HEALTH_FAILED, "worker is not loaded")
        })?;
        loaded.runtime().init(config).await?;
        self.state = WorkerState::Initialised;
        Ok(())
    }

    /// The loaded generation, if any.
    pub fn loaded(&self) -> Option<&Arc<LoadedGeneration>> {
        self.loaded.as_ref()
    }

    /// The lifecycle object behind the loaded generation.
    pub fn runtime(&self) -> Option<&Arc<dyn GenerationRuntime>> {
        self.loaded.as_ref().map(|g| g.runtime())
    }

    /// Drain and shut the generation down, then forget it.
    pub async fn retire(&mut self) {
        if let Some(loaded) = self.loaded.take() {
            let _ = loaded.runtime().drain(self.spec.limits.wall_clock_ms).await;
            loaded.runtime().shutdown().await;
        }
        self.state = WorkerState::Retired;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest_json() -> Json {
        serde_json::json!({
            "schema_version": 1,
            "plugin_id": "sandtree.provider.example",
            "version": "1.0.0",
            "kind": "provider",
            "component": "blake3:abc",
            "license": "Apache-2.0",
            "capabilities": ["resource:discover", "resource:start"],
            "state_schema_version": 1,
            "hot_swap": true,
        })
    }

    fn spec(dir: &std::path::Path, body: &[u8]) -> WorkerSpec {
        let path = dir.join("plugin.wasm");
        std::fs::write(&path, body).unwrap();
        WorkerSpec::new(path, manifest_json(), Generation(1))
    }

    #[test]
    fn a_worker_starts_idle() {
        let dir = tempfile::tempdir().unwrap();
        let w = Worker::new(spec(dir.path(), b"bytes"));
        assert_eq!(w.state(), WorkerState::Idle);
        assert!(w.runtime().is_none());
    }

    #[test]
    fn verification_precedes_any_component_load() {
        // A package whose license is refused must never reach the engine.
        let dir = tempfile::tempdir().unwrap();
        let w = Worker::new(spec(dir.path(), b"bytes"))
            .with_policy(InstallPolicy::deny_all().allow_license("MIT"));
        let err = w.verify().expect_err("Apache-2.0 is not in the allow-list");
        assert_eq!(err.code, ErrorCode::PLUGIN_MANIFEST_INVALID);
        assert!(err.message.contains("Apache-2.0"), "{}", err.message);
    }

    #[test]
    fn verification_requires_component_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let w = Worker::new(spec(dir.path(), b"bytes"));
        let staged = w.verify().expect("verifies");
        assert!(staged.needs_component);
        assert_eq!(staged.denied, vec!["resource:discover", "resource:start"]);
    }

    #[test]
    fn a_missing_component_file_is_a_manifest_error() {
        let s = WorkerSpec::new("/nonexistent/plugin.wasm", manifest_json(), Generation(1));
        let w = Worker::new(s);
        let err = w.verify().expect_err("no such file");
        assert_eq!(err.code, ErrorCode::PLUGIN_MANIFEST_INVALID);
        assert!(
            err.message.contains("cannot read component"),
            "{}",
            err.message
        );
    }

    #[test]
    fn a_malformed_manifest_is_rejected_before_the_file_is_read() {
        let bad = serde_json::json!({"schema_version": 1, "plugin_id": "NO-DOTS"});
        let s = WorkerSpec::new("/nonexistent/plugin.wasm", bad, Generation(1));
        let err = Worker::new(s).verify().expect_err("bad manifest");
        assert_eq!(err.code, ErrorCode::PLUGIN_MANIFEST_INVALID);
    }

    #[test]
    fn the_declared_generation_is_carried_through() {
        let dir = tempfile::tempdir().unwrap();
        let w = Worker::new(spec(dir.path(), b"bytes"));
        assert_eq!(
            w.verify().unwrap().plugin_id,
            sandtree_model::id::PluginId::derive(&["sandtree.provider.example"])
        );
    }

    #[tokio::test]
    async fn initialising_before_loading_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = Worker::new(spec(dir.path(), b"bytes"));
        let err = w.initialise(&Json::Null).await.expect_err("not loaded");
        assert!(err.message.contains("not loaded"), "{}", err.message);
    }

    #[cfg(not(feature = "wasmtime-abi"))]
    #[tokio::test]
    async fn loading_without_the_abi_feature_refuses_rather_than_faking_it() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = Worker::new(spec(dir.path(), b"\0asm\x01"));
        let err = w.load().await.expect_err("no engine in this build");
        assert!(err.message.contains("wasmtime-abi"), "{}", err.message);
        assert_eq!(w.state(), WorkerState::Idle);
    }

    #[tokio::test]
    async fn retiring_an_unloaded_worker_is_a_no_op() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = Worker::new(spec(dir.path(), b"bytes"));
        w.retire().await;
        assert_eq!(w.state(), WorkerState::Retired);
    }
}
