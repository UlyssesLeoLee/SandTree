//! Plugin lifecycle over IPC (FR-050..055, DD-PLG §4, ADR-016).
//!
//! This is the control plane's half of hot swapping. It owns the routing table,
//! drives the supervisor, and remembers what each swap displaced so
//! `plugin.rollback` can put it back. It deliberately does **not** own a WASM
//! engine: a component runs in a worker process, and putting wasmtime in the
//! daemon would collapse that boundary (FR-055).
//!
//! So staging is injected. [`PluginLoader`] is the seam; the daemon ships a
//! loader that refuses, and an embedder — or a future worker transport —
//! supplies a real one. That is a narrower claim than "install works", and it is
//! the one this code can actually back up.
//!
//! Why this module exists at all: before it, `HotSwapSupervisor` was correct,
//! tested, and unreachable — the daemon answered `not_served`, and did not even
//! depend on `sandtree-plugin-host`.

use std::collections::BTreeMap;
use std::sync::Arc;

use sandtree_model::error::{DomainError, ErrorCode};
use sandtree_model::id::PluginId;
use sandtree_plugin_host::generation::LoadedGeneration;
use sandtree_plugin_host::hot_swap::{HotSwapSupervisor, StateMigration, SwapResult};
use sandtree_plugin_host::limits::WorkerLimits;
use sandtree_plugin_host::route::{Generation, HotSwapOutcome, RouteTable};
use serde_json::Value as Json;
use tokio::sync::Mutex;

/// Stages a new generation for a plugin without publishing it.
///
/// Implementations own everything between "a package was accepted" and "a
/// generation is loaded and health-checked": verification, the engine, the
/// worker process. The control plane owns what happens after.
#[async_trait::async_trait]
pub trait PluginLoader: Send + Sync {
    /// Load generation `generation` of `plugin`.
    ///
    /// Returning `Ok` means the generation is loaded and `init`-able. It must
    /// not be routed yet — publication is the supervisor's job (DD-PLG §4).
    async fn stage(
        &self,
        plugin: &PluginId,
        generation: Generation,
    ) -> Result<Arc<LoadedGeneration>, DomainError>;
}

/// The loader the daemon uses when no worker transport is wired.
///
/// It refuses rather than pretending. A daemon that answered `plugin.install`
/// with success and routed nothing would be worse than the `not_served` it
/// replaced.
pub struct UnavailableLoader {
    reason: String,
}

impl UnavailableLoader {
    /// A loader that refuses with `reason`.
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

#[async_trait::async_trait]
impl PluginLoader for UnavailableLoader {
    async fn stage(
        &self,
        _plugin: &PluginId,
        _generation: Generation,
    ) -> Result<Arc<LoadedGeneration>, DomainError> {
        Err(DomainError::new(
            ErrorCode::PLUGIN_MANIFEST_INVALID,
            format!(
                "no plugin loader is configured in this daemon: {}",
                self.reason
            ),
        ))
    }
}

/// Control-plane plugin state.
pub struct PluginControl {
    routes: Arc<RouteTable>,
    supervisor: HotSwapSupervisor,
    loader: Arc<dyn PluginLoader>,
    limits: WorkerLimits,
    /// Displaced generations, newest first per plugin.
    ///
    /// A rollback needs the *instance*, not a number: after a swap the old
    /// generation is no longer in the route table, and routing a number would
    /// leave the plugin pointing at nothing (ADR-016). Bounded to one entry per
    /// plugin — rolling back two swaps ago is a reinstall, not a rollback.
    retired: Mutex<BTreeMap<PluginId, Arc<LoadedGeneration>>>,
}

impl PluginControl {
    /// Build control state over `routes`.
    pub fn new(
        routes: Arc<RouteTable>,
        limits: WorkerLimits,
        loader: Arc<dyn PluginLoader>,
    ) -> Self {
        let supervisor = HotSwapSupervisor::new(routes.clone(), limits);
        Self {
            routes,
            supervisor,
            loader,
            limits,
            retired: Mutex::new(BTreeMap::new()),
        }
    }

    /// Build control state with the host ceiling and a refusing loader.
    pub fn unavailable(routes: Arc<RouteTable>, reason: &str) -> Self {
        Self::new(
            routes,
            WorkerLimits::host_ceiling(),
            Arc::new(UnavailableLoader::new(reason)),
        )
    }

    /// The routing table.
    pub fn routes(&self) -> &Arc<RouteTable> {
        &self.routes
    }

    /// The next generation number for `plugin`.
    ///
    /// One past whatever is serving, so an upgrade always moves forward.
    fn next_generation(&self, plugin: &PluginId) -> Generation {
        match self.routes.current_generation(plugin) {
            Some(current) => Generation(current.0 + 1),
            None => Generation(1),
        }
    }

    /// `plugin.install` — first load of a plugin.
    ///
    /// Refuses when the plugin is already serving, and names
    /// [`PluginControl::hotswap`] instead. Silently treating a second install as
    /// an upgrade would displace the live generation without draining it, so a
    /// WASM guest's `lifecycle.shutdown` would never run and the rollback handle
    /// would be dropped on the floor. Refusing makes the misuse unreachable
    /// rather than papering over the consequences.
    pub async fn install(
        &self,
        plugin: &PluginId,
        config: &Json,
    ) -> Result<SwapResult, DomainError> {
        if self.routes.current_generation(plugin).is_some() {
            return Err(DomainError::new(
                ErrorCode::PLUGIN_HOTSWAP_REJECTED,
                format!(
                    "plugin {plugin} is already installed; use plugin.hotswap to \
                     move it to a new generation"
                ),
            ));
        }

        let generation = self.next_generation(plugin);
        let staged = self.loader.stage(plugin, generation).await?;
        Ok(self.supervisor.install(plugin, staged, config).await)
    }

    /// `plugin.hotswap` — stage the next generation and swap it in.
    ///
    /// A first install should call [`PluginControl::install`]: there is no
    /// previous generation to migrate from or drain.
    pub async fn hotswap(
        &self,
        plugin: &PluginId,
        stateful: bool,
        config: &Json,
    ) -> Result<SwapResult, DomainError> {
        let serving = self.routes.current(plugin).ok_or_else(|| {
            DomainError::new(
                ErrorCode::PLUGIN_HOTSWAP_REJECTED,
                format!(
                    "plugin {plugin} has no serving generation; use plugin.install \
                     for a first load"
                ),
            )
        })?;

        let generation = self.next_generation(plugin);
        let staged = self.loader.stage(plugin, generation).await?;
        let migration = if stateful {
            StateMigration::Required
        } else {
            StateMigration::None
        };

        let result = self
            .supervisor
            .swap(plugin, staged, serving, migration, config)
            .await;

        if result.outcome.swapped {
            if let Some(displaced) = result.retired.clone() {
                self.retired.lock().await.insert(plugin.clone(), displaced);
            }
        }
        Ok(result)
    }

    /// `plugin.rollback` — put back the generation the last swap displaced.
    pub async fn rollback(&self, plugin: &PluginId) -> HotSwapOutcome {
        let Some(previous) = self.retired.lock().await.remove(plugin) else {
            return HotSwapOutcome::refused(
                self.routes.current_generation(plugin),
                format!("no rollback is available for plugin {plugin}"),
            );
        };
        // The generation being replaced is itself displaced now, so keep it in
        // reserve: a rollback that cannot itself be rolled back is a one-way
        // door, and operators reach for it precisely when things are going
        // wrong.
        if let Some(current) = self.routes.current(plugin) {
            self.retired.lock().await.insert(plugin.clone(), current);
        }
        self.supervisor.rollback(plugin, previous)
    }

    /// `plugin.disable` — stop routing a plugin and retire its generation.
    pub async fn disable(&self, plugin: &PluginId) -> bool {
        let current = self.routes.remove(plugin);
        self.retired.lock().await.remove(plugin);
        if let Some(generation) = current {
            self.supervisor.retire(plugin, Some(generation)).await;
            true
        } else {
            false
        }
    }

    /// The generation available to roll back to, if any.
    pub async fn rollback_target(&self, plugin: &PluginId) -> Option<Generation> {
        self.retired
            .lock()
            .await
            .get(plugin)
            .map(|g| g.generation())
    }

    /// Effective worker limits.
    pub fn limits(&self) -> &WorkerLimits {
        &self.limits
    }
}

impl std::fmt::Debug for PluginControl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PluginControl")
            .field("routed", &self.routes.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sandtree_model::error::DomainError;
    use sandtree_sdk::manifest::PluginManifest;
    use sandtree_sdk::ports::{ProviderHealth, ProviderInstance};
    use sandtree_sdk::wit::WitDescriptor;

    struct Stub {
        generation: Generation,
        version: &'static str,
        schema: u32,
        init_fails: bool,
    }

    #[async_trait::async_trait]
    impl sandtree_plugin_host::hot_swap::GenerationRuntime for Stub {
        fn generation(&self) -> Generation {
            self.generation
        }
        fn descriptor(&self) -> WitDescriptor {
            WitDescriptor {
                plugin_id: "p".into(),
                version: self.version.into(),
                state_schema_version: self.schema,
            }
        }
        async fn init(&self, _: &Json) -> Result<(), DomainError> {
            if self.init_fails {
                return Err(DomainError::new(
                    ErrorCode::PLUGIN_HEALTH_FAILED,
                    "init refused",
                ));
            }
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

    struct FixedLoader {
        init_fails: bool,
    }

    #[async_trait::async_trait]
    impl PluginLoader for FixedLoader {
        async fn stage(
            &self,
            plugin: &PluginId,
            generation: Generation,
        ) -> Result<Arc<LoadedGeneration>, DomainError> {
            Ok(Arc::new(LoadedGeneration::new(
                plugin.clone(),
                generation,
                Arc::new(Stub {
                    generation,
                    version: "1.0.0",
                    schema: 1,
                    init_fails: self.init_fails,
                }),
                ProviderInstance::empty(plugin.clone()),
            )))
        }
    }

    fn plugin() -> PluginId {
        PluginId::derive(&["sandtree.provider.test"])
    }

    fn control(loader: Arc<dyn PluginLoader>) -> (Arc<RouteTable>, PluginControl) {
        let routes = Arc::new(RouteTable::new());
        let control = PluginControl::new(routes.clone(), WorkerLimits::host_ceiling(), loader);
        (routes, control)
    }

    fn loader() -> Arc<dyn PluginLoader> {
        Arc::new(FixedLoader { init_fails: false })
    }

    fn failing_loader() -> Arc<dyn PluginLoader> {
        Arc::new(FixedLoader { init_fails: true })
    }

    #[tokio::test]
    async fn installing_over_a_live_plugin_is_refused_and_names_the_right_method() {
        // The defect this guards: `supervisor.install` returns the displaced
        // generation in `SwapResult::retired`, and an install path that ignored
        // it would drop the last `Arc` of a live WASM generation — no drain, no
        // `lifecycle.shutdown`, and no rollback handle. Refusing is what keeps
        // that unreachable.
        let (routes, c) = control(loader());
        c.install(&plugin(), &Json::Null)
            .await
            .expect("first install");

        let err = c
            .install(&plugin(), &Json::Null)
            .await
            .expect_err("already installed");

        assert_eq!(err.code, ErrorCode::PLUGIN_HOTSWAP_REJECTED);
        assert!(err.message.contains("plugin.hotswap"), "{}", err.message);
        assert_eq!(
            routes.current_generation(&plugin()),
            Some(Generation(1)),
            "a refused install must not disturb the serving generation"
        );
        assert_eq!(
            c.rollback_target(&plugin()).await,
            None,
            "a refused install must not invent a rollback target"
        );
    }

    #[tokio::test]
    async fn install_stages_then_publishes() {
        let (routes, c) = control(loader());
        let r = c.install(&plugin(), &Json::Null).await.expect("staged");
        assert!(r.outcome.swapped);
        assert_eq!(routes.current_generation(&plugin()), Some(Generation(1)));
    }

    #[tokio::test]
    async fn an_install_that_cannot_stage_routes_nothing() {
        // Two different failures, deliberately kept apart. This loader *does*
        // stage a generation; that generation then refuses `init`. So the
        // supervisor returns a refusal, not an error — the refusal carries the
        // step list, which is how an operator sees that `init` is what failed.
        let (routes, c) = control(failing_loader());
        let r = c
            .install(&plugin(), &Json::Null)
            .await
            .expect("staged, then refused");
        assert!(!r.outcome.swapped);
        assert!(routes.current_generation(&plugin()).is_none());
        assert_eq!(
            r.trace.steps.last(),
            Some(&"discard-staged"),
            "the refused generation must be retired, and the trace must say so: {:?}",
            r.trace.steps
        );
    }

    #[tokio::test]
    async fn a_swap_of_an_uninstalled_plugin_is_a_client_error() {
        // `plugin.hotswap` on something that was never installed has no previous
        // generation to migrate from. Reporting a bare refusal would hide the
        // mistake; naming the right method makes it self-correcting.
        let (_, c) = control(loader());
        let err = c
            .hotswap(&plugin(), false, &Json::Null)
            .await
            .expect_err("nothing installed");
        assert_eq!(err.code, ErrorCode::PLUGIN_HOTSWAP_REJECTED);
        assert!(err.message.contains("plugin.install"), "{}", err.message);
    }

    #[tokio::test]
    async fn generations_advance_on_every_swap() {
        let (routes, c) = control(loader());
        c.install(&plugin(), &Json::Null).await.expect("staged");
        assert_eq!(routes.current_generation(&plugin()), Some(Generation(1)));

        c.hotswap(&plugin(), true, &Json::Null).await.unwrap();
        assert_eq!(routes.current_generation(&plugin()), Some(Generation(2)));

        c.hotswap(&plugin(), true, &Json::Null).await.unwrap();
        assert_eq!(routes.current_generation(&plugin()), Some(Generation(3)));
    }

    #[tokio::test]
    async fn rollback_returns_to_the_previous_generation() {
        let (routes, c) = control(loader());
        c.install(&plugin(), &Json::Null).await.expect("staged");
        c.hotswap(&plugin(), true, &Json::Null).await.unwrap();
        assert_eq!(routes.current_generation(&plugin()), Some(Generation(2)));
        assert_eq!(c.rollback_target(&plugin()).await, Some(Generation(1)));

        let outcome = c.rollback(&plugin()).await;
        assert!(outcome.swapped);
        assert_eq!(routes.current_generation(&plugin()), Some(Generation(1)));
    }

    #[tokio::test]
    async fn rollback_with_nothing_in_reserve_is_a_refusal_not_a_reinstall() {
        let (routes, c) = control(loader());
        c.install(&plugin(), &Json::Null).await.expect("staged");

        let outcome = c.rollback(&plugin()).await;

        assert!(!outcome.swapped);
        assert!(
            outcome.reason.contains("no rollback is available"),
            "{}",
            outcome.reason
        );
        assert_eq!(
            routes.current_generation(&plugin()),
            Some(Generation(1)),
            "a refusal must not disturb the serving generation"
        );
    }

    #[tokio::test]
    async fn a_rollback_can_itself_be_rolled_back() {
        // Operators reach for rollback precisely when things are going wrong.
        // A one-way door there is a bad property, so the generation a rollback
        // displaces goes back into reserve.
        let (routes, c) = control(loader());
        c.install(&plugin(), &Json::Null).await.expect("staged");
        c.hotswap(&plugin(), true, &Json::Null).await.unwrap();
        c.rollback(&plugin()).await;
        assert_eq!(routes.current_generation(&plugin()), Some(Generation(1)));

        let second = c.rollback(&plugin()).await;
        assert!(second.swapped);
        assert_eq!(routes.current_generation(&plugin()), Some(Generation(2)));
    }

    #[tokio::test]
    async fn disable_stops_routing_and_reports_whether_anything_was_live() {
        let (routes, c) = control(loader());
        c.install(&plugin(), &Json::Null).await.expect("staged");

        assert!(c.disable(&plugin()).await);
        assert!(routes.current_generation(&plugin()).is_none());
        assert!(!c.disable(&plugin()).await, "disabling twice is a no-op");
    }

    #[tokio::test]
    async fn disable_drops_the_rollback_reserve() {
        // A disabled plugin has nothing to roll back to; leaving a live
        // generation in reserve would let a rollback re-route a plugin the
        // operator just turned off.
        let (_, c) = control(loader());
        c.install(&plugin(), &Json::Null).await.expect("staged");
        c.hotswap(&plugin(), true, &Json::Null).await.unwrap();

        c.disable(&plugin()).await;

        assert_eq!(c.rollback_target(&plugin()).await, None);
    }

    #[tokio::test]
    async fn the_default_loader_refuses_rather_than_pretending() {
        // The daemon ships this loader. If it ever answered Ok, `plugin.install`
        // would report success while routing nothing — which is exactly the
        // "method that pretends to work" the not_served list was replacing.
        let routes = Arc::new(RouteTable::new());
        let c = PluginControl::unavailable(routes.clone(), "no worker transport");

        let err = c
            .install(&plugin(), &Json::Null)
            .await
            .expect_err("no loader");

        assert!(routes.is_empty());
        assert!(
            err.message.contains("no plugin loader is configured"),
            "{}",
            err.message
        );
    }

    #[tokio::test]
    async fn a_refused_swap_leaves_the_reserve_untouched() {
        // After a failed swap there is nothing new to roll back to, and the
        // reserve must still point at the generation the *last good* swap
        // displaced — otherwise a failed upgrade destroys the operator's way
        // back to the generation that was known to work.
        let routes = Arc::new(RouteTable::new());
        let good = PluginControl::new(routes.clone(), WorkerLimits::host_ceiling(), loader());
        good.install(&plugin(), &Json::Null).await.expect("staged");
        good.hotswap(&plugin(), true, &Json::Null).await.unwrap();
        assert_eq!(good.rollback_target(&plugin()).await, Some(Generation(1)));

        // Same route table, but staging can only produce a generation that
        // refuses `init`.
        let broken = PluginControl::new(
            routes.clone(),
            WorkerLimits::host_ceiling(),
            failing_loader(),
        );
        let failed = broken.hotswap(&plugin(), true, &Json::Null).await.unwrap();

        assert!(!failed.outcome.swapped);
        assert_eq!(
            routes.current_generation(&plugin()),
            Some(Generation(2)),
            "a refused swap must not move the route"
        );
        assert_eq!(
            good.rollback_target(&plugin()).await,
            Some(Generation(1)),
            "the reserve must survive a failed swap"
        );
    }

    #[test]
    fn control_is_debug_without_a_wasm_engine() {
        let (_, c) = control(loader());
        assert!(format!("{c:?}").contains("routed"));
    }

    #[test]
    fn a_plugin_manifest_is_still_the_only_way_to_name_a_package() {
        // Guards against someone inventing a looser install path later: the
        // control plane takes a `PluginId`, and producing one from a manifest is
        // the loader's job, not this module's.
        let raw = serde_json::json!({
            "schema_version": 1,
            "plugin_id": "sandtree.provider.example",
            "version": "1.0.0",
            "kind": "provider",
            "component": "blake3:abc",
            "license": "Apache-2.0",
            "capabilities": [],
        });
        let m = PluginManifest::from_json(&raw).expect("valid manifest");
        assert_eq!(m.plugin_id(), "sandtree.provider.example");
    }
}
