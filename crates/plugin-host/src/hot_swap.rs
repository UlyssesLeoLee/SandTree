//! Atomic hot swap supervisor (FR-052, FR-053, NFR-P04, NFR-M02, DD-PLG §4).
//!
//! The algorithm, verbatim from the design:
//!
//! ```text
//! package hash/schema/license policy verify
//! instantiate N+1 in staging generation
//! init + health
//! if stateful: old.prepare_upgrade -> new.accept_upgrade
//! acquire route write lock; swap generation pointer
//! new receives traffic; old drains in-flight until deadline
//! shutdown old
//! failure before swap = discard N+1
//! failure after swap during early health can swap back N
//! ```
//!
//! Everything expensive happens **before** the route write. The swap itself is
//! one map insert, which is why it is bounded (NFR-P04) regardless of plugin
//! size, and why a failure anywhere before it costs the caller nothing.

use std::sync::Arc;

use sandtree_model::error::{DomainError, ErrorCode};
use sandtree_model::id::PluginId;
use sandtree_sdk::manifest::now_rfc3339;
use sandtree_sdk::ports::ProviderHealth;
use sandtree_sdk::wit::WitDescriptor;
use serde_json::Value as Json;

use crate::limits::WorkerLimits;
use crate::route::{Generation, HotSwapOutcome, RouteTable};

/// One loaded generation, independent of how it is loaded.
///
/// A Wasmtime component and an in-process Rust provider both implement this,
/// which is what makes the supervisor testable without a WASM engine
/// (NFR-O04) while still exercising the real ordering.
#[async_trait::async_trait]
pub trait GenerationRuntime: Send + Sync {
    /// Generation number this instance serves.
    fn generation(&self) -> Generation;

    /// `lifecycle.descriptor`.
    fn descriptor(&self) -> WitDescriptor;

    /// `lifecycle.init`.
    async fn init(&self, config: &Json) -> Result<(), DomainError>;

    /// `lifecycle.health`.
    async fn health(&self) -> Result<ProviderHealth, DomainError>;

    /// `lifecycle.prepare-upgrade` — old generation serialises its state.
    async fn prepare_upgrade(&self, target_version: &str) -> Result<Vec<u8>, DomainError>;

    /// `lifecycle.accept-upgrade` — new generation takes that state.
    async fn accept_upgrade(&self, from_version: &str, state: &[u8]) -> Result<(), DomainError>;

    /// `lifecycle.drain` — let in-flight calls finish, bounded by the deadline.
    async fn drain(&self, deadline_ms: u64) -> Result<(), DomainError>;

    /// `lifecycle.shutdown`. Must be idempotent.
    async fn shutdown(&self);
}

/// Records what a swap attempt actually did, for auditing and tests.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SwapTrace {
    /// Ordered step names reached before the attempt ended.
    pub steps: Vec<&'static str>,
    /// Whether `prepare_upgrade`/`accept_upgrade` ran.
    pub migrated: bool,
    /// Whether the route pointer was moved.
    pub swapped: bool,
    /// Whether the previous generation was drained and shut down.
    pub drained: bool,
}

impl SwapTrace {
    fn step(&mut self, name: &'static str) {
        self.steps.push(name);
    }
}

/// Outcome of a full supervisor attempt.
#[derive(Debug, Clone)]
pub struct SwapResult {
    /// Whether the route now serves the new generation.
    pub outcome: HotSwapOutcome,
    /// What happened, step by step.
    pub trace: SwapTrace,
    /// Correlation id (NFR-O01).
    pub correlation_id: String,
}

/// Drives staged upgrades and the route table.
pub struct HotSwapSupervisor {
    routes: Arc<RouteTable>,
    limits: WorkerLimits,
    drain_deadline_ms: u64,
}

impl HotSwapSupervisor {
    /// Build a supervisor over a route table.
    pub fn new(routes: Arc<RouteTable>, limits: WorkerLimits) -> Self {
        Self {
            routes,
            limits,
            drain_deadline_ms: limits.wall_clock_ms,
        }
    }

    /// Override the drain deadline (DD-PLG §4: "drains in-flight until
    /// deadline").
    pub fn with_drain_deadline_ms(mut self, deadline_ms: u64) -> Self {
        self.drain_deadline_ms = deadline_ms;
        self
    }

    /// Effective worker limits.
    pub fn limits(&self) -> &WorkerLimits {
        &self.limits
    }

    /// The routing table this supervisor writes.
    pub fn routes(&self) -> &Arc<RouteTable> {
        &self.routes
    }

    /// Point a plugin at `next` without any staging, for a first install.
    ///
    /// A first install has no previous generation, so there is nothing to
    /// drain and nothing to migrate — but it still goes through `init` and
    /// `health`, because "it loaded" is not "it works".
    pub async fn install(
        &self,
        plugin: &PluginId,
        next: Arc<dyn GenerationRuntime>,
        config: &Json,
    ) -> SwapResult {
        let mut trace = SwapTrace::default();
        trace.step("stage");
        let correlation_id = sandtree_model::id::CorrelationId::generate().to_string();

        if let Err(e) = next.init(config).await {
            trace.step("init-failed");
            return SwapResult {
                outcome: HotSwapOutcome::refused(self.routes.current(plugin), e.message),
                trace,
                correlation_id,
            };
        }
        trace.step("init");

        if let Err(e) = next.health().await {
            trace.step("health-failed");
            // Nothing was routed yet, so there is no traffic to protect.
            next.shutdown().await;
            return SwapResult {
                outcome: HotSwapOutcome::refused(self.routes.current(plugin), e.message),
                trace,
                correlation_id,
            };
        }
        trace.step("health");

        trace.swapped = true;
        trace.step("route-swap");
        let generation = next.generation();
        self.routes.atomic_swap(plugin, generation);
        SwapResult {
            outcome: HotSwapOutcome::swapped(generation),
            trace,
            correlation_id,
        }
    }

    /// Stage `next` alongside `previous` and swap only if every pre-swap step
    /// succeeds.
    ///
    /// On any failure before the route write, `next` is discarded and the
    /// previous generation keeps serving traffic (AC-04).
    pub async fn swap(
        &self,
        plugin: &PluginId,
        next: Arc<dyn GenerationRuntime>,
        previous: Arc<dyn GenerationRuntime>,
        stateful: bool,
        config: &Json,
    ) -> SwapResult {
        let mut trace = SwapTrace::default();
        trace.step("stage");
        let correlation_id = sandtree_model::id::CorrelationId::generate().to_string();
        let serving = self.routes.current(plugin);

        macro_rules! discard {
            ($err:expr) => {{
                let e: DomainError = $err;
                trace.step("discard-staged");
                next.shutdown().await;
                return SwapResult {
                    outcome: HotSwapOutcome::refused(serving, e.message),
                    trace,
                    correlation_id,
                };
            }};
        }

        // --- pre-swap phase: nothing here is observable to traffic ---
        if let Err(e) = next.init(config).await {
            discard!(e);
        }
        trace.step("init");

        if let Err(e) = next.health().await {
            discard!(e);
        }
        trace.step("health");

        if stateful {
            // NFR-M02: refuse before migrating when the new generation speaks
            // an older state schema. Handing state written by a newer plugin to
            // an older reader is exactly the incompatibility that must not be
            // discovered at runtime.
            let old_schema = previous.descriptor().state_schema_version;
            let new_schema = next.descriptor().state_schema_version;
            if new_schema < old_schema {
                discard!(DomainError::new(
                    ErrorCode::PLUGIN_HOTSWAP_REJECTED,
                    format!(
                        "state schema downgrade {old_schema} -> {new_schema} is not \
                         migratable; refusing the swap and keeping the old generation"
                    ),
                ));
            }
            trace.step("schema-check");

            let target_version = next.descriptor().version.clone();
            let state = match previous.prepare_upgrade(&target_version).await {
                Ok(s) => s,
                Err(e) => discard!(e),
            };
            trace.step("prepare-upgrade");

            let from_version = previous.descriptor().version.clone();
            if let Err(e) = next.accept_upgrade(&from_version, &state).await {
                discard!(e);
            }
            trace.step("accept-upgrade");
            trace.migrated = true;
        }

        // --- the atomic part ---
        let generation = next.generation();
        let rolled = self.routes.atomic_swap(plugin, generation);
        trace.swapped = true;
        trace.step("route-swap");
        tracing::info!(
            correlation_id = %correlation_id,
            plugin = %plugin,
            from = ?rolled,
            to = %generation,
            "route swapped"
        );

        // --- post-swap: the new generation already owns traffic ---
        let drain_deadline = self.drain_deadline_ms;
        if let Err(e) = previous.drain(drain_deadline).await {
            // The new generation is live and healthy, so a drain timeout is
            // reported but does not undo the swap.
            tracing::warn!(
                correlation_id = %correlation_id,
                plugin = %plugin,
                error = %e.message,
                "previous generation drain did not finish cleanly"
            );
        }
        previous.shutdown().await;
        trace.drained = true;
        trace.step("drain");

        SwapResult {
            outcome: HotSwapOutcome::swapped(generation),
            trace,
            correlation_id,
        }
    }

    /// Restore a previous generation after a post-swap failure (DD-PLG §4:
    /// "failure after swap during early health can swap back N").
    pub fn rollback(&self, plugin: &PluginId, previous: Generation) -> HotSwapOutcome {
        self.routes.rollback(plugin, previous);
        HotSwapOutcome::swapped(previous)
    }

    /// Retire a plugin: stop routing it, then shut the generation down.
    pub async fn retire(&self, plugin: &PluginId, current: Option<Arc<dyn GenerationRuntime>>) {
        self.routes.remove(plugin);
        if let Some(rt) = current {
            let _ = rt.drain(self.drain_deadline_ms).await;
            rt.shutdown().await;
        }
    }
}

/// Wall-clock helper so callers can record attempt times without pulling in a
/// clock dependency here.
pub fn now_iso() -> String {
    now_rfc3339()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Debug, Default)]
    struct FakeRuntime {
        generation: Generation,
        version: &'static str,
        schema: u32,
        init_fails: bool,
        health_fails: bool,
        prepare_fails: bool,
        accept_fails: bool,
        drain_fails: bool,
        calls: Mutex<Vec<String>>,
        shutdown_count: Mutex<u32>,
        accepted_state: Mutex<Vec<u8>>,
        saw_config: Mutex<Option<Json>>,
    }

    impl FakeRuntime {
        fn new(generation: u64, version: &'static str, schema: u32) -> Arc<Self> {
            Arc::new(Self {
                generation: Generation(generation),
                version,
                schema,
                ..Default::default()
            })
        }

        fn record(&self, call: impl Into<String>) {
            self.calls.lock().unwrap().push(call.into());
        }

        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }

        fn shutdowns(&self) -> u32 {
            *self.shutdown_count.lock().unwrap()
        }
    }

    #[async_trait::async_trait]
    impl GenerationRuntime for FakeRuntime {
        fn generation(&self) -> Generation {
            self.generation
        }

        fn descriptor(&self) -> WitDescriptor {
            WitDescriptor {
                plugin_id: "sandtree.provider.docker".into(),
                version: self.version.into(),
                state_schema_version: self.schema,
            }
        }

        async fn init(&self, config: &Json) -> Result<(), DomainError> {
            self.record(format!("init:{}", config));
            *self.saw_config.lock().unwrap() = Some(config.clone());
            if self.init_fails {
                return Err(DomainError::new(
                    ErrorCode::PLUGIN_HEALTH_FAILED,
                    "init refused",
                ));
            }
            Ok(())
        }

        async fn health(&self) -> Result<ProviderHealth, DomainError> {
            self.record("health");
            if self.health_fails {
                return Err(DomainError::new(
                    ErrorCode::PLUGIN_HEALTH_FAILED,
                    "health refused",
                ));
            }
            Ok(ProviderHealth::Healthy)
        }

        async fn prepare_upgrade(&self, target_version: &str) -> Result<Vec<u8>, DomainError> {
            self.record(format!("prepare:{target_version}"));
            if self.prepare_fails {
                return Err(DomainError::new(
                    ErrorCode::PLUGIN_HOTSWAP_REJECTED,
                    "cannot serialise",
                ));
            }
            Ok(b"state-v1".to_vec())
        }

        async fn accept_upgrade(
            &self,
            from_version: &str,
            state: &[u8],
        ) -> Result<(), DomainError> {
            self.record(format!("accept:{from_version}"));
            if self.accept_fails {
                return Err(DomainError::new(
                    ErrorCode::PLUGIN_HOTSWAP_REJECTED,
                    "state rejected",
                ));
            }
            *self.accepted_state.lock().unwrap() = state.to_vec();
            Ok(())
        }

        async fn drain(&self, deadline_ms: u64) -> Result<(), DomainError> {
            self.record(format!("drain:{deadline_ms}"));
            if self.drain_fails {
                return Err(DomainError::new(
                    ErrorCode::PLUGIN_HEALTH_FAILED,
                    "drain timeout",
                ));
            }
            Ok(())
        }

        async fn shutdown(&self) {
            self.record("shutdown");
            *self.shutdown_count.lock().unwrap() += 1;
        }
    }

    fn pid() -> PluginId {
        PluginId::derive(&["sandtree.provider.docker"])
    }

    fn sup() -> (Arc<RouteTable>, HotSwapSupervisor) {
        let routes = Arc::new(RouteTable::new());
        let s = HotSwapSupervisor::new(routes.clone(), WorkerLimits::host_ceiling())
            .with_drain_deadline_ms(5_000);
        (routes, s)
    }

    /// A staging generation that fails at `kind`. `prepare` is intentionally
    /// absent: `prepare-upgrade` is an old-generation call, so a test that
    /// wants it to fail must build the *old* runtime itself.
    fn make_failing(generation: u64, kind: &str) -> Arc<FakeRuntime> {
        Arc::new(FakeRuntime {
            generation: Generation(generation),
            version: "2.0.0",
            schema: 2,
            init_fails: kind == "init",
            health_fails: kind == "health",
            accept_fails: kind == "accept",
            ..Default::default()
        })
    }

    #[tokio::test]
    async fn happy_path_follows_the_design_order() {
        let (routes, s) = sup();
        let old = FakeRuntime::new(1, "1.0.0", 1);
        let new = FakeRuntime::new(2, "2.0.0", 2);
        routes.atomic_swap(&pid(), old.generation());

        let r = s
            .swap(
                &pid(),
                new.clone(),
                old.clone(),
                true,
                &serde_json::json!({"k": 1}),
            )
            .await;

        assert!(r.outcome.swapped);
        assert_eq!(r.outcome.generation, Some(Generation(2)));
        assert_eq!(routes.current(&pid()), Some(Generation(2)));
        assert_eq!(
            r.trace.steps,
            vec![
                "stage",
                "init",
                "health",
                "schema-check",
                "prepare-upgrade",
                "accept-upgrade",
                "route-swap",
                "drain"
            ]
        );
        // init saw the config, migration carried state, old was retired.
        assert_eq!(
            new.saw_config.lock().unwrap().as_ref().unwrap()["k"],
            serde_json::json!(1)
        );
        assert_eq!(&*new.accepted_state.lock().unwrap(), b"state-v1");
        assert_eq!(old.shutdowns(), 1);
        assert!(r.trace.migrated && r.trace.swapped && r.trace.drained);
        assert!(!r.correlation_id.is_empty());
    }

    #[tokio::test]
    async fn stateless_swap_never_migrates() {
        let (routes, s) = sup();
        let old = FakeRuntime::new(1, "1.0.0", 1);
        let new = FakeRuntime::new(2, "2.0.0", 2);
        routes.atomic_swap(&pid(), old.generation());

        let r = s
            .swap(&pid(), new.clone(), old.clone(), false, &Json::Null)
            .await;

        assert!(r.outcome.swapped);
        assert!(!r.trace.migrated);
        assert!(!r.trace.steps.contains(&"prepare-upgrade"));
        assert!(!r.trace.steps.contains(&"accept-upgrade"));
        assert_eq!(new.calls(), vec!["init:null", "health"]);
    }

    #[tokio::test]
    async fn init_failure_keeps_the_old_generation_serving() {
        let (routes, s) = sup();
        let old = FakeRuntime::new(1, "1.0.0", 1);
        let new = make_failing(2, "init");
        routes.atomic_swap(&pid(), old.generation());

        let r = s
            .swap(&pid(), new.clone(), old.clone(), true, &Json::Null)
            .await;

        assert!(!r.outcome.swapped);
        assert_eq!(r.outcome.generation, Some(Generation(1)));
        assert_eq!(routes.current(&pid()), Some(Generation(1)));
        // The staged generation is discarded, never left half-alive.
        assert_eq!(new.shutdowns(), 1);
        assert!(!r.trace.swapped);
        // The old generation was not touched at all.
        assert_eq!(old.shutdowns(), 0);
    }

    #[tokio::test]
    async fn health_failure_keeps_the_old_generation_serving() {
        let (routes, s) = sup();
        let old = FakeRuntime::new(1, "1.0.0", 1);
        let new = make_failing(2, "health");
        routes.atomic_swap(&pid(), old.generation());

        let r = s
            .swap(&pid(), new.clone(), old.clone(), true, &Json::Null)
            .await;

        assert!(!r.outcome.swapped);
        assert_eq!(routes.current(&pid()), Some(Generation(1)));
        assert_eq!(new.shutdowns(), 1);
        assert!(r.trace.steps.contains(&"discard-staged"));
    }

    #[tokio::test]
    async fn prepare_failure_never_reaches_accept_or_the_route() {
        // `prepare-upgrade` runs on the OLD generation (it is the old plugin
        // serialising its state), so a failure there must abandon the staging
        // generation before `accept-upgrade` is ever asked to read state.
        let (routes, s) = sup();
        let old = Arc::new(FakeRuntime {
            generation: Generation(1),
            version: "1.0.0",
            schema: 1,
            prepare_fails: true,
            ..Default::default()
        });
        let new = FakeRuntime::new(2, "2.0.0", 2);
        routes.atomic_swap(&pid(), old.generation());

        let r = s
            .swap(&pid(), new.clone(), old.clone(), true, &Json::Null)
            .await;

        assert!(!r.outcome.swapped, "swap must be refused");
        assert_eq!(routes.current(&pid()), Some(Generation(1)));
        assert_eq!(
            old.calls(),
            vec!["prepare:2.0.0".to_string()],
            "the old generation tried and failed to serialise"
        );
        assert_eq!(
            new.calls(),
            vec!["init:null", "health", "shutdown"],
            "the staging generation must never have seen accept-upgrade"
        );
        assert_eq!(old.shutdowns(), 0, "the serving generation is untouched");
    }

    #[tokio::test]
    async fn accept_failure_keeps_the_old_generation_serving() {
        let (routes, s) = sup();
        let old = FakeRuntime::new(1, "1.0.0", 1);
        let new = make_failing(2, "accept");
        routes.atomic_swap(&pid(), old.generation());

        let r = s
            .swap(&pid(), new.clone(), old.clone(), true, &Json::Null)
            .await;

        assert!(!r.outcome.swapped);
        assert_eq!(routes.current(&pid()), Some(Generation(1)));
        assert_eq!(new.shutdowns(), 1);
        assert!(
            r.outcome.reason.contains("state rejected"),
            "{}",
            r.outcome.reason
        );
    }

    #[tokio::test]
    async fn state_schema_downgrade_is_refused_before_any_migration() {
        // NFR-M02: an incompatible migration target must be refused, keeping
        // the old generation, and the refusal must cost nothing.
        let (routes, s) = sup();
        let old = FakeRuntime::new(1, "1.0.0", 5);
        let new = FakeRuntime::new(2, "2.0.0", 3);
        routes.atomic_swap(&pid(), old.generation());

        let r = s
            .swap(&pid(), new.clone(), old.clone(), true, &Json::Null)
            .await;

        assert!(!r.outcome.swapped);
        assert_eq!(r.outcome.generation, Some(Generation(1)));
        assert_eq!(routes.current(&pid()), Some(Generation(1)));
        assert!(
            r.outcome.reason.contains("state schema downgrade"),
            "{}",
            r.outcome.reason
        );
        // Neither migration call ran: `prepare-upgrade` belongs to the old
        // generation, and the refusal happened before it was asked to.
        assert_eq!(new.calls(), vec!["init:null", "health", "shutdown"]);
        assert_eq!(old.calls(), Vec::<String>::new());
        assert_eq!(new.shutdowns(), 1);
    }

    #[tokio::test]
    async fn equal_state_schema_is_accepted() {
        let (routes, s) = sup();
        let old = FakeRuntime::new(1, "1.0.0", 2);
        let new = FakeRuntime::new(2, "2.0.0", 2);
        routes.atomic_swap(&pid(), old.generation());

        let r = s
            .swap(&pid(), new.clone(), old.clone(), true, &Json::Null)
            .await;
        assert!(r.outcome.swapped);
    }

    #[tokio::test]
    async fn rollback_after_swap_restores_the_previous_generation() {
        // DD-PLG §4: "failure after swap during early health can swap back N".
        let (routes, s) = sup();
        let old = FakeRuntime::new(1, "1.0.0", 1);
        let new = FakeRuntime::new(2, "2.0.0", 2);
        routes.atomic_swap(&pid(), old.generation());

        s.swap(&pid(), new.clone(), old.clone(), false, &Json::Null)
            .await;
        assert_eq!(routes.current(&pid()), Some(Generation(2)));

        s.rollback(&pid(), Generation(1));
        assert_eq!(routes.current(&pid()), Some(Generation(1)));
    }

    #[tokio::test]
    async fn drain_timeout_does_not_undo_a_healthy_swap() {
        // The new generation is already serving; reverting because the *old*
        // one would not drain would drop traffic on the floor.
        let (routes, s) = sup();
        let old = FakeRuntime::new(1, "1.0.0", 1);
        let mut new = FakeRuntime::new(2, "2.0.0", 2);
        Arc::get_mut(&mut new).unwrap().drain_fails = true;
        routes.atomic_swap(&pid(), old.generation());

        let r = s
            .swap(&pid(), new.clone(), old.clone(), false, &Json::Null)
            .await;
        assert!(r.outcome.swapped);
        assert_eq!(routes.current(&pid()), Some(Generation(2)));
        // The old generation is still shut down, so it does not linger.
        assert_eq!(old.shutdowns(), 1);
    }

    #[tokio::test]
    async fn install_runs_init_and_health_before_routing() {
        let (routes, s) = sup();
        let new = FakeRuntime::new(1, "1.0.0", 1);

        let r = s.install(&pid(), new.clone(), &Json::Null).await;
        assert!(r.outcome.swapped);
        assert_eq!(routes.current(&pid()), Some(Generation(1)));
        assert_eq!(new.calls(), vec!["init:null", "health"]);
    }

    #[tokio::test]
    async fn install_of_an_unhealthy_provider_routes_nothing() {
        let (routes, s) = sup();
        let new = make_failing(1, "health");

        let r = s.install(&pid(), new.clone(), &Json::Null).await;
        assert!(!r.outcome.swapped);
        assert!(routes.current(&pid()).is_none());
        assert_eq!(new.shutdowns(), 1);
    }

    #[tokio::test]
    async fn retire_stops_routing_and_shuts_down() {
        let (routes, s) = sup();
        let rt = FakeRuntime::new(1, "1.0.0", 1);
        routes.atomic_swap(&pid(), rt.generation());

        s.retire(&pid(), Some(rt.clone())).await;
        assert!(routes.current(&pid()).is_none());
        assert_eq!(rt.shutdowns(), 1);
    }
}
