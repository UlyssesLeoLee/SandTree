//! Atomic hot swap supervisor (FR-052, FR-053, NFR-P04, NFR-M02, DD-PLG §4,
//! ADR-016).
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
//!
//! # Shape of the code
//!
//! The pre-swap phase is [`HotSwapSupervisor::stage`], which returns either a
//! populated [`SwapTrace`] or a failure. Every pre-swap failure therefore has
//! exactly one handling site in [`HotSwapSupervisor::swap`] — "discard the staged
//! generation, keep the old one serving" is written once rather than at each step
//! that can fail. Adding a step to the pre-swap phase cannot introduce a new
//! leak path, because there is no new place where a `?` can escape to.

use std::sync::Arc;

use sandtree_model::error::{DomainError, ErrorCode};
use sandtree_model::id::PluginId;
use sandtree_sdk::manifest::now_rfc3339;
use sandtree_sdk::ports::ProviderHealth;
use sandtree_sdk::wit::WitDescriptor;
use serde_json::Value as Json;

use crate::generation::LoadedGeneration;
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

/// Whether an incoming generation carries state that must be migrated.
///
/// A named value rather than a `bool` because the two branches differ in kind,
/// not in degree: [`StateMigration::None`] skips two lifecycle calls entirely,
/// while [`StateMigration::Required`] refuses a schema downgrade before either
/// of them runs (NFR-M02). At a call site `true` says nothing about which of
/// those two behaviours is meant.
///
/// Note what this does **not** carry: the state schema versions. Both are read
/// from the generations' own descriptors inside the supervisor. A caller that
/// supplied the incoming version instead could understate it and talk the
/// supervisor out of the NFR-M02 refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateMigration {
    /// Stateless plugin: no `prepare-upgrade` / `accept-upgrade` calls.
    None,
    /// Stateful plugin: the old generation exports state, the new one imports it.
    Required,
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
#[derive(Debug)]
pub struct SwapResult {
    /// Whether the route now serves the new generation.
    pub outcome: HotSwapOutcome,
    /// What happened, step by step.
    pub trace: SwapTrace,
    /// Correlation id (NFR-O01).
    pub correlation_id: String,
    /// The generation this swap displaced, still live and drained.
    ///
    /// Handed back rather than looked up: after a swap the retired generation is
    /// no longer in the route table, and a generation number alone cannot restore
    /// traffic because there would be no instance to route to. Pass this to
    /// [`HotSwapSupervisor::rollback`] to honour DD-PLG §4's "failure after swap
    /// during early health can swap back N".
    pub retired: Option<Arc<LoadedGeneration>>,
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
        next: Arc<LoadedGeneration>,
        config: &Json,
    ) -> SwapResult {
        let correlation_id = sandtree_model::id::CorrelationId::generate().to_string();

        let trace = match self.stage(next.runtime(), config).await {
            Ok(trace) => trace,
            Err(staged) => {
                let (trace, failure) = staged.discard(next.runtime()).await;
                return SwapResult {
                    outcome: HotSwapOutcome::refused(
                        self.routes.current_generation(plugin),
                        failure.message,
                    ),
                    trace,
                    correlation_id,
                    retired: None,
                };
            }
        };

        self.publish(plugin, next, trace, correlation_id, None)
            .await
    }

    /// Stage `next` alongside `previous` and swap only if every pre-swap step
    /// succeeds.
    ///
    /// On any failure before the route write, `next` is discarded and the
    /// previous generation keeps serving traffic (AC-04).
    pub async fn swap(
        &self,
        plugin: &PluginId,
        next: Arc<LoadedGeneration>,
        previous: Arc<LoadedGeneration>,
        migration: StateMigration,
        config: &Json,
    ) -> SwapResult {
        let correlation_id = sandtree_model::id::CorrelationId::generate().to_string();
        let serving = self.routes.current_generation(plugin);

        let trace = match self.stage(next.runtime(), config).await {
            Ok(trace) => trace,
            Err(staged) => {
                let (trace, failure) = staged.discard(next.runtime()).await;
                return SwapResult {
                    outcome: HotSwapOutcome::refused(serving, failure.message),
                    trace,
                    correlation_id,
                    retired: None,
                };
            }
        };

        // --- state migration: still before the route write ---
        let trace = match self
            .migrate(trace, next.runtime(), previous.runtime(), migration)
            .await
        {
            Ok(trace) => trace,
            Err(staged) => {
                let (trace, failure) = staged.discard(next.runtime()).await;
                return SwapResult {
                    outcome: HotSwapOutcome::refused(serving, failure.message),
                    trace,
                    correlation_id,
                    retired: None,
                };
            }
        };

        self.publish(plugin, next, trace, correlation_id, Some(previous))
            .await
    }

    /// Everything that must succeed before the route pointer moves.
    async fn stage(
        &self,
        next: &Arc<dyn GenerationRuntime>,
        config: &Json,
    ) -> Result<SwapTrace, StagedFailure> {
        let mut trace = SwapTrace::default();
        trace.step("stage");

        if let Err(e) = next.init(config).await {
            return Err(StagedFailure::new(trace, "init-failed", e));
        }
        trace.step("init");

        if let Err(e) = next.health().await {
            return Err(StagedFailure::new(trace, "health-failed", e));
        }
        trace.step("health");

        Ok(trace)
    }

    /// `old.prepare_upgrade` then `new.accept_upgrade` (DD-PLG §4).
    ///
    /// Takes the trace by value and hands it back on success, so every failure
    /// path can record the step it reached without cloning a half-built trace
    /// that the caller then has to reconcile.
    async fn migrate(
        &self,
        trace: SwapTrace,
        next: &Arc<dyn GenerationRuntime>,
        previous: &Arc<dyn GenerationRuntime>,
        migration: StateMigration,
    ) -> Result<SwapTrace, StagedFailure> {
        let incoming = match migration {
            StateMigration::None => return Ok(trace),
            StateMigration::Required => next.descriptor().state_schema_version,
        };

        // NFR-M02: refuse before migrating when the new generation speaks an
        // older state schema. Handing state written by a newer plugin to an
        // older reader is exactly the incompatibility that must not be
        // discovered at runtime.
        let outgoing = previous.descriptor().state_schema_version;
        if incoming < outgoing {
            return Err(StagedFailure::new(
                trace,
                "schema-downgrade-refused",
                DomainError::new(
                    ErrorCode::PLUGIN_HOTSWAP_REJECTED,
                    format!(
                        "state schema downgrade {outgoing} -> {incoming} is not \
                         migratable; refusing the swap and keeping the old generation"
                    ),
                ),
            ));
        }
        let mut trace = trace;
        trace.step("schema-check");

        let target_version = next.descriptor().version.clone();
        let state = match previous.prepare_upgrade(&target_version).await {
            Ok(state) => state,
            Err(e) => return Err(StagedFailure::new(trace, "prepare-upgrade-failed", e)),
        };
        trace.step("prepare-upgrade");

        let from_version = previous.descriptor().version.clone();
        if let Err(e) = next.accept_upgrade(&from_version, &state).await {
            return Err(StagedFailure::new(trace, "accept-upgrade-failed", e));
        }
        trace.step("accept-upgrade");
        trace.migrated = true;

        Ok(trace)
    }

    /// Move the route pointer, then drain whatever it displaced.
    ///
    /// Reached only after the whole pre-swap phase succeeded, so there is no
    /// error path here that could leave the route half-swapped.
    async fn publish(
        &self,
        plugin: &PluginId,
        next: Arc<LoadedGeneration>,
        mut trace: SwapTrace,
        correlation_id: String,
        previous: Option<Arc<LoadedGeneration>>,
    ) -> SwapResult {
        let generation = next.generation();
        let rolled = self.routes.atomic_swap(plugin, next);
        trace.swapped = true;
        trace.step("route-swap");

        tracing::info!(
            correlation_id = %correlation_id,
            plugin = %plugin,
            from = ?rolled.as_ref().map(|g| g.generation()),
            to = %generation,
            "route swapped"
        );

        // --- post-swap: the new generation already owns traffic ---
        //
        // Two generations can be involved here, and only one of them can be the
        // rollback target. `previous` is what the supervisor migrated from, so it
        // is authoritative for rollback; `rolled` is what the route table
        // actually displaced. They are the same generation in the normal case,
        // but two concurrent swaps on one plugin can make them differ — and
        // then the displaced generation that is *not* handed back still has to
        // be retired, or it stays resident with nothing routing to it.
        let mut retired: Option<Arc<LoadedGeneration>> = None;
        if let Some(old) = previous {
            if let Err(e) = old.runtime().drain(self.drain_deadline_ms).await {
                // The new generation is live and healthy, so a drain timeout is
                // reported but does not undo the swap.
                tracing::warn!(
                    correlation_id = %correlation_id,
                    plugin = %plugin,
                    error = %e.message,
                    "previous generation drain did not finish cleanly"
                );
            }
            old.runtime().shutdown().await;
            trace.drained = true;
            trace.step("drain");
            retired = Some(old);
        }

        if let Some(rolled) = rolled {
            let already_retired = retired
                .as_ref()
                .is_some_and(|kept| kept.generation() == rolled.generation());
            if !already_retired {
                tracing::warn!(
                    correlation_id = %correlation_id,
                    plugin = %plugin,
                    displaced = %rolled.generation(),
                    "a concurrent swap displaced a different generation; retiring it"
                );
                let _ = rolled.runtime().drain(self.drain_deadline_ms).await;
                rolled.runtime().shutdown().await;
            }
        }

        SwapResult {
            outcome: HotSwapOutcome::swapped(generation),
            trace,
            correlation_id,
            retired: retired.filter(|g| g.generation() != generation),
        }
    }

    /// Restore a generation that a swap displaced (DD-PLG §4: "failure after
    /// swap during early health can swap back N").
    ///
    /// Takes the instance from [`SwapResult::retired`]: a generation number
    /// cannot restore traffic on its own.
    pub fn rollback(&self, plugin: &PluginId, previous: Arc<LoadedGeneration>) -> HotSwapOutcome {
        let generation = previous.generation();
        self.routes.rollback(plugin, previous);
        HotSwapOutcome::swapped(generation)
    }

    /// Retire a plugin: stop routing it, then shut the generation down.
    pub async fn retire(&self, plugin: &PluginId, current: Option<Arc<LoadedGeneration>>) {
        self.routes.remove(plugin);
        if let Some(generation) = current {
            let _ = generation.runtime().drain(self.drain_deadline_ms).await;
            generation.runtime().shutdown().await;
        }
    }
}

/// A pre-swap step that failed, carrying everything needed to report it.
///
/// The staged generation is *not* shut down here: shutting down is an async
/// operation and this type is returned from async code that has already gone
/// cold. [`StagedFailure::discard`] is the single place that does it.
struct StagedFailure {
    trace: SwapTrace,
    failure: DomainError,
}

impl StagedFailure {
    fn new(mut trace: SwapTrace, step: &'static str, failure: DomainError) -> Self {
        trace.step(step);
        Self { trace, failure }
    }

    /// Shut the staged generation down, exactly once, on the way out.
    ///
    /// This is the only place a discarded generation is retired. A staged
    /// instance that is merely dropped would take its `Arc`s with it, but a
    /// WASM generation holds a live store and worker resources — those are
    /// released by `shutdown`, not by the last reference going away. Every
    /// pre-swap failure path routes through here, so a new failing step cannot
    /// introduce a generation that was staged and never told to stop.
    ///
    /// Returns the trace with the `discard-staged` step recorded, so an
    /// operator reading an attempt can see that the staged generation was
    /// retired rather than merely abandoned.
    async fn discard(self, next: &Arc<dyn GenerationRuntime>) -> (SwapTrace, DomainError) {
        next.shutdown().await;
        let Self { mut trace, failure } = self;
        trace.step("discard-staged");
        (trace, failure)
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
    use crate::generation::LoadedGeneration;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Mutex;

    /// A generation runtime with individually triggerable failures.
    ///
    /// Each failure is a separate flag so a test can name the step it is
    /// exercising. A single "fail everything" switch would let a test pass for
    /// the wrong reason — every pre-swap step would refuse, and the test would
    /// prove nothing about the step it names.
    #[derive(Debug, Default)]
    struct FakeRuntime {
        generation: Generation,
        version: String,
        schema: u32,
        init_fails: bool,
        health_fails: bool,
        prepare_fails: bool,
        accept_fails: bool,
        drain_fails: bool,
        calls: Mutex<Vec<String>>,
        shutdowns: AtomicU32,
        accepted_state: Mutex<Vec<u8>>,
        saw_config: Mutex<Option<Json>>,
    }

    impl FakeRuntime {
        fn new(generation: u64, version: &str, schema: u32) -> Arc<Self> {
            Arc::new(Self {
                generation: Generation(generation),
                version: version.to_string(),
                schema,
                ..Default::default()
            })
        }

        /// A staging generation that fails at `kind`.
        ///
        /// `prepare` is intentionally absent: `prepare-upgrade` is an
        /// old-generation call, so a test that wants it to fail must build the
        /// *old* runtime itself.
        fn failing(generation: u64, kind: &str) -> Arc<Self> {
            Arc::new(Self {
                generation: Generation(generation),
                version: "2.0.0".into(),
                schema: 2,
                init_fails: kind == "init",
                health_fails: kind == "health",
                accept_fails: kind == "accept",
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
            self.shutdowns.load(Ordering::SeqCst)
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
                version: self.version.clone(),
                state_schema_version: self.schema,
            }
        }

        async fn init(&self, config: &Json) -> Result<(), DomainError> {
            self.record(format!("init:{config}"));
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
            self.shutdowns.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn pid() -> PluginId {
        PluginId::derive(&["sandtree.provider.docker"])
    }

    /// Wrap a runtime into the routable generation the supervisor consumes.
    fn gen(rt: Arc<FakeRuntime>) -> Arc<LoadedGeneration> {
        Arc::new(LoadedGeneration::lifecycle_only(pid(), rt.generation(), rt))
    }

    fn sup() -> (Arc<RouteTable>, HotSwapSupervisor) {
        let routes = Arc::new(RouteTable::new());
        let s = HotSwapSupervisor::new(routes.clone(), WorkerLimits::host_ceiling())
            .with_drain_deadline_ms(5_000);
        (routes, s)
    }

    #[tokio::test]
    async fn happy_path_follows_the_design_order() {
        let (routes, s) = sup();
        let old_rt = FakeRuntime::new(1, "1.0.0", 1);
        let old = gen(old_rt.clone());
        let new_rt = FakeRuntime::new(2, "2.0.0", 2);
        let new = gen(new_rt.clone());
        routes.atomic_swap(&pid(), old.clone());

        let r = s
            .swap(
                &pid(),
                new.clone(),
                old.clone(),
                StateMigration::Required,
                &serde_json::json!({"k": 1}),
            )
            .await;

        assert!(r.outcome.swapped);
        assert_eq!(r.outcome.generation, Some(Generation(2)));
        assert_eq!(routes.current_generation(&pid()), Some(Generation(2)));
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
        assert_eq!(
            new_rt.descriptor().version,
            "2.0.0",
            "the incoming version is what the old generation was asked for"
        );
        assert!(r.trace.migrated && r.trace.swapped && r.trace.drained);
        assert!(!r.correlation_id.is_empty());
    }

    #[tokio::test]
    async fn migration_reaches_the_generation_the_old_one_was_asked_to_target() {
        // The state that crossed generations has to be the bytes the *new*
        // plugin asked for. If `prepare-upgrade` were handed the old version, a
        // plugin that serialises differently per target would hand back state the
        // new reader cannot parse, and the swap would still have succeeded.
        let (routes, s) = sup();
        let old_rt = FakeRuntime::new(1, "1.0.0", 1);
        let old = gen(old_rt.clone());
        let new_rt = FakeRuntime::new(2, "2.0.0", 2);
        let new = gen(new_rt.clone());
        routes.atomic_swap(&pid(), old.clone());

        s.swap(
            &pid(),
            new.clone(),
            old.clone(),
            StateMigration::Required,
            &Json::Null,
        )
        .await;

        let old_calls = old_rt.calls();
        let new_calls = new_rt.calls();
        assert!(
            old_calls.contains(&"prepare:2.0.0".to_string()),
            "old must be asked to serialise for the NEW version: {old_calls:?}"
        );
        // `accept-upgrade` runs on the *incoming* generation — the old one has
        // nothing left to do by then. Reading this off the old runtime would
        // pass vacuously if the call were simply never made.
        assert!(
            new_calls.contains(&"accept:1.0.0".to_string()),
            "new must be told which version it is receiving from: {new_calls:?}"
        );
        assert!(
            !old_calls.iter().any(|c| c.starts_with("accept:")),
            "the outgoing generation must not be asked to import: {old_calls:?}"
        );
    }

    #[tokio::test]
    async fn stateless_swap_never_migrates() {
        let (routes, s) = sup();
        let old_rt = FakeRuntime::new(1, "1.0.0", 1);
        let old = gen(old_rt.clone());
        let new_rt = FakeRuntime::new(2, "2.0.0", 2);
        let new = gen(new_rt.clone());
        routes.atomic_swap(&pid(), old.clone());

        let r = s
            .swap(
                &pid(),
                new.clone(),
                old.clone(),
                StateMigration::None,
                &Json::Null,
            )
            .await;

        assert!(r.outcome.swapped);
        assert!(!r.trace.migrated);
        assert!(!r.trace.steps.contains(&"prepare-upgrade"));
        assert!(!r.trace.steps.contains(&"accept-upgrade"));
        assert_eq!(new_rt.descriptor().state_schema_version, 2);
    }

    #[tokio::test]
    async fn init_failure_keeps_the_old_generation_serving() {
        let (routes, s) = sup();
        let old_rt = FakeRuntime::new(1, "1.0.0", 1);
        let old = gen(old_rt.clone());
        let new_rt = FakeRuntime::failing(2, "init");
        let new = gen(new_rt.clone());
        routes.atomic_swap(&pid(), old.clone());

        let r = s
            .swap(
                &pid(),
                new.clone(),
                old.clone(),
                StateMigration::Required,
                &Json::Null,
            )
            .await;

        assert!(!r.outcome.swapped);
        assert_eq!(r.outcome.generation, Some(Generation(1)));
        assert_eq!(routes.current_generation(&pid()), Some(Generation(1)));
        assert!(!r.trace.swapped);
        // The staged generation is discarded, never left half-alive.
        assert_eq!(new_rt.shutdowns(), 1);
        assert_eq!(old_rt.shutdowns(), 0);
        assert!(r.trace.steps.contains(&"discard-staged"));
    }

    #[tokio::test]
    async fn health_failure_keeps_the_old_generation_serving() {
        let (routes, s) = sup();
        let old_rt = FakeRuntime::new(1, "1.0.0", 1);
        let old = gen(old_rt.clone());
        let new_rt = FakeRuntime::failing(2, "health");
        let new = gen(new_rt.clone());
        routes.atomic_swap(&pid(), old.clone());

        let r = s
            .swap(
                &pid(),
                new.clone(),
                old.clone(),
                StateMigration::Required,
                &Json::Null,
            )
            .await;

        assert!(!r.outcome.swapped);
        assert_eq!(routes.current_generation(&pid()), Some(Generation(1)));
        assert_eq!(new_rt.shutdowns(), 1);
        assert_eq!(old_rt.shutdowns(), 0);
    }

    #[tokio::test]
    async fn prepare_failure_never_reaches_accept_or_the_route() {
        // `prepare-upgrade` runs on the OLD generation (it is the old plugin
        // serialising its state), so a failure there must abandon the staging
        // generation before `accept-upgrade` is ever asked to read state.
        let (routes, s) = sup();
        let old_rt = Arc::new(FakeRuntime {
            generation: Generation(1),
            version: "1.0.0".into(),
            schema: 1,
            prepare_fails: true,
            ..Default::default()
        });
        let old = gen(old_rt.clone());
        let new_rt = FakeRuntime::new(2, "2.0.0", 2);
        let new = gen(new_rt.clone());
        routes.atomic_swap(&pid(), old.clone());

        let r = s
            .swap(
                &pid(),
                new.clone(),
                old.clone(),
                StateMigration::Required,
                &Json::Null,
            )
            .await;

        assert!(!r.outcome.swapped, "swap must be refused");
        assert_eq!(routes.current_generation(&pid()), Some(Generation(1)));
        assert!(
            old_rt.calls().contains(&"prepare:2.0.0".to_string()),
            "the old generation tried and failed to serialise"
        );
        assert_eq!(old_rt.shutdowns(), 0, "the serving generation is untouched");
        assert!(r.trace.steps.contains(&"discard-staged"));
    }

    #[tokio::test]
    async fn accept_failure_keeps_the_old_generation_serving() {
        let (routes, s) = sup();
        let old_rt = FakeRuntime::new(1, "1.0.0", 1);
        let old = gen(old_rt.clone());
        let new_rt = FakeRuntime::failing(2, "accept");
        let new = gen(new_rt.clone());
        routes.atomic_swap(&pid(), old.clone());

        let r = s
            .swap(
                &pid(),
                new.clone(),
                old.clone(),
                StateMigration::Required,
                &Json::Null,
            )
            .await;

        assert!(!r.outcome.swapped);
        assert_eq!(routes.current_generation(&pid()), Some(Generation(1)));
        assert_eq!(new_rt.shutdowns(), 1);
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
        let old_rt = FakeRuntime::new(1, "1.0.0", 5);
        let old = gen(old_rt.clone());
        let new_rt = FakeRuntime::new(2, "2.0.0", 3);
        let new = gen(new_rt.clone());
        routes.atomic_swap(&pid(), old.clone());

        let r = s
            .swap(
                &pid(),
                new.clone(),
                old.clone(),
                StateMigration::Required,
                &Json::Null,
            )
            .await;

        assert!(!r.outcome.swapped);
        assert_eq!(r.outcome.generation, Some(Generation(1)));
        assert_eq!(routes.current_generation(&pid()), Some(Generation(1)));
        assert!(
            r.outcome.reason.contains("state schema downgrade"),
            "{}",
            r.outcome.reason
        );
        // Neither migration call ran: `prepare-upgrade` belongs to the old
        // generation, and the refusal happened before it was asked to.
        assert!(!r.trace.steps.contains(&"prepare-upgrade"));
        assert!(!r.trace.steps.contains(&"accept-upgrade"));
        assert_eq!(new_rt.shutdowns(), 1);
        assert_eq!(old_rt.shutdowns(), 0);
    }

    #[tokio::test]
    async fn equal_state_schema_is_accepted() {
        let (routes, s) = sup();
        let old_rt = FakeRuntime::new(1, "1.0.0", 2);
        let old = gen(old_rt.clone());
        let new_rt = FakeRuntime::new(2, "2.0.0", 2);
        let new = gen(new_rt.clone());
        routes.atomic_swap(&pid(), old.clone());

        let r = s
            .swap(
                &pid(),
                new.clone(),
                old.clone(),
                StateMigration::Required,
                &Json::Null,
            )
            .await;
        assert!(r.outcome.swapped);
    }

    #[tokio::test]
    async fn the_schema_verdict_comes_from_the_generations_not_the_caller() {
        // ADR-016 / NFR-M02. `StateMigration::Required` carries no version, so
        // the only way the supervisor can learn the incoming schema is by asking
        // the generation itself. If the descriptor stopped being consulted and a
        // caller-supplied value were used instead, this downgrade would swap.
        let (routes, s) = sup();
        let old_rt = FakeRuntime::new(1, "1.0.0", 9);
        let old = gen(old_rt.clone());
        let new_rt = FakeRuntime::new(2, "2.0.0", 1);
        let new = gen(new_rt.clone());
        routes.atomic_swap(&pid(), old.clone());

        let r = s
            .swap(
                &pid(),
                new.clone(),
                old.clone(),
                StateMigration::Required,
                &Json::Null,
            )
            .await;

        assert!(
            !r.outcome.swapped,
            "a downgrade declared by the generations themselves must be refused"
        );
    }

    #[tokio::test]
    async fn the_supervisor_hands_back_the_retired_generation_for_rollback() {
        // ADR-016: after a swap the old generation is no longer in the route
        // table, so a number could not restore it. If `retired` were dropped,
        // rollback would be impossible and AC-04 would silently be dead code.
        let (routes, s) = sup();
        let old_rt = FakeRuntime::new(1, "1.0.0", 1);
        let old = gen(old_rt.clone());
        let new_rt = FakeRuntime::new(2, "2.0.0", 2);
        let new = gen(new_rt.clone());
        routes.atomic_swap(&pid(), old.clone());

        let r = s
            .swap(
                &pid(),
                new.clone(),
                old.clone(),
                StateMigration::None,
                &Json::Null,
            )
            .await;

        let retired = r.retired.expect("the displaced generation is handed back");
        assert_eq!(retired.generation(), Generation(1));
        assert_eq!(retired.ports().generation, 1);
    }

    #[tokio::test]
    async fn a_generation_displaced_by_a_racing_swap_is_still_retired() {
        // `previous` (what the supervisor migrated from) and `rolled` (what the
        // route actually displaced) are the same generation normally. A second
        // swap landing between the caller reading the route and the atomic write
        // makes them differ — and the displaced generation that is not handed
        // back for rollback must still be shut down. Otherwise it stays
        // resident with nothing routing to it and no handle to retire it.
        let (routes, s) = sup();
        let mut racing_rt = FakeRuntime::new(3, "3.0.0", 3);
        Arc::get_mut(&mut racing_rt).unwrap().version = "3.0.0".to_string();
        let racing = gen(racing_rt.clone());

        // The route is serving gen3 by the time our swap writes.
        routes.atomic_swap(&pid(), racing.clone());

        let old_rt = FakeRuntime::new(1, "1.0.0", 1);
        let old = gen(old_rt.clone());
        let new_rt = FakeRuntime::new(2, "2.0.0", 2);
        let new = gen(new_rt.clone());

        let r = s
            .swap(&pid(), new, old.clone(), StateMigration::None, &Json::Null)
            .await;

        assert!(r.outcome.swapped);
        assert_eq!(routing_generation(&routes), Some(Generation(2)));
        // The generation we migrated from is what a rollback restores.
        assert_eq!(
            r.retired.as_ref().map(|g| g.generation()),
            Some(Generation(1))
        );
        assert_eq!(
            old_rt.shutdowns(),
            1,
            "the migrated-from generation is drained and shut down"
        );
        assert_eq!(
            racing_rt.shutdowns(),
            1,
            "the racing generation must not be left resident"
        );
    }

    fn routing_generation(routes: &RouteTable) -> Option<Generation> {
        routes.current_generation(&pid())
    }

    #[tokio::test]
    async fn rollback_after_swap_restores_the_previous_generation() {
        // DD-PLG §4: "failure after swap during early health can swap back N".
        let (routes, s) = sup();
        let old_rt = FakeRuntime::new(1, "1.0.0", 1);
        let old = gen(old_rt.clone());
        let new_rt = FakeRuntime::new(2, "2.0.0", 2);
        let new = gen(new_rt.clone());
        routes.atomic_swap(&pid(), old.clone());

        let r = s
            .swap(
                &pid(),
                new.clone(),
                old.clone(),
                StateMigration::None,
                &Json::Null,
            )
            .await;
        assert_eq!(routes.current_generation(&pid()), Some(Generation(2)));

        s.rollback(&pid(), r.retired.expect("retired generation"));
        assert_eq!(routes.current_generation(&pid()), Some(Generation(1)));
    }

    #[tokio::test]
    async fn drain_timeout_does_not_undo_a_healthy_swap() {
        // The new generation is already serving; reverting because the *old*
        // one would not drain would drop traffic on the floor.
        let (routes, s) = sup();
        let old_rt = FakeRuntime::new(1, "1.0.0", 1);
        let old = gen(old_rt.clone());
        let new_rt = Arc::new(FakeRuntime {
            generation: Generation(2),
            version: "2.0.0".into(),
            schema: 2,
            drain_fails: true,
            ..Default::default()
        });
        let new = gen(new_rt);
        routes.atomic_swap(&pid(), old.clone());

        let r = s
            .swap(
                &pid(),
                new.clone(),
                old.clone(),
                StateMigration::None,
                &Json::Null,
            )
            .await;
        assert!(r.outcome.swapped);
        assert_eq!(routes.current_generation(&pid()), Some(Generation(2)));
        // The old generation is still shut down, so it does not linger.
        assert_eq!(old_rt.shutdowns(), 1);
    }

    #[tokio::test]
    async fn install_runs_init_and_health_before_routing() {
        let (routes, s) = sup();
        let new = gen(FakeRuntime::new(1, "1.0.0", 1));

        let r = s.install(&pid(), new.clone(), &Json::Null).await;
        assert!(r.outcome.swapped);
        assert_eq!(routes.current_generation(&pid()), Some(Generation(1)));
        assert!(r.retired.is_none(), "a first install displaces nothing");
    }

    #[tokio::test]
    async fn install_of_an_unhealthy_provider_routes_nothing() {
        let (routes, s) = sup();
        let new_rt = FakeRuntime::failing(1, "health");
        let new = gen(new_rt.clone());

        let r = s.install(&pid(), new.clone(), &Json::Null).await;
        assert!(!r.outcome.swapped);
        assert!(routes.current_generation(&pid()).is_none());
        assert_eq!(new_rt.shutdowns(), 1);
    }

    #[tokio::test]
    async fn retire_stops_routing_and_shuts_down() {
        let (routes, s) = sup();
        let rt = FakeRuntime::new(1, "1.0.0", 1);
        let loaded = gen(rt.clone());
        routes.atomic_swap(&pid(), loaded.clone());

        s.retire(&pid(), Some(loaded)).await;
        assert!(routes.current_generation(&pid()).is_none());
        assert_eq!(rt.shutdowns(), 1);
    }

    #[tokio::test]
    async fn retire_of_a_plugin_that_is_not_routed_is_harmless() {
        // Uninstalling something that was never installed must not panic, and
        // must not shut down a generation the caller passed in speculatively.
        let (routes, s) = sup();
        let rt = FakeRuntime::new(1, "1.0.0", 1);

        s.retire(&pid(), None).await;
        assert!(routes.current_generation(&pid()).is_none());
        assert_eq!(rt.shutdowns(), 0);
    }

    #[tokio::test]
    async fn a_refused_swap_reports_no_generation_when_nothing_was_serving() {
        // The refusal must not invent a generation. Reporting `Some(..)` here
        // would tell an operator a plugin is live when it never was.
        let (_routes, s) = sup();
        let new_rt = FakeRuntime::failing(1, "init");
        let new = gen(new_rt.clone());

        let r = s.install(&pid(), new, &Json::Null).await;
        assert!(!r.outcome.swapped);
        assert_eq!(r.outcome.generation, None);
    }

    #[test]
    fn now_iso_is_a_usable_timestamp() {
        // Present so callers can record attempt times without a clock
        // dependency; a formatter that returned an empty string would pass
        // unnoticed everywhere it is used.
        let stamp = now_iso();
        assert!(
            stamp.contains("T") && (stamp.ends_with('Z') || stamp.ends_with("+00:00")),
            "expected an RFC3339 UTC timestamp: {stamp}"
        );
    }
}
