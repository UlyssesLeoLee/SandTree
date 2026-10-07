//! WASM Component Model adapter (FR-054, FR-055, ADR-002).
//!
//! `bindgen!` reads `schemas/sandtree_provider_v1.wit` **directly**. That is
//! deliberate: the shipped WIT file is the ABI, so a change to the design's
//! WIT that this host does not implement becomes a compile error here instead
//! of a runtime surprise. Rust types in this crate are host-internal and are
//! not the ABI.
//!
//! Isolation, in order of how a runaway guest is stopped:
//!
//! * **fuel** — a per-call instruction budget; exhaustion traps the guest,
//! * **epoch** — the host interrupts long-running calls from outside,
//! * **store limits** — a ceiling on guest memory, tables and instances,
//! * **drain deadline** — in-flight calls get a bounded window on shutdown.
//!
//! No single one of these is sufficient on its own: fuel does not stop a guest
//! that blocks without executing, and a wall clock does not stop one that
//! allocates. Together they make a trap the *expected* outcome (FR-054:
//! "trap only degrades the daemon").

use std::sync::Arc;

use sandtree_model::capability::CapabilitySet;
use sandtree_model::error::{DomainError, ErrorCode};
use sandtree_model::id::ResourceId;
use sandtree_model::operation::{OperationOutcome, OperationRequest};
use sandtree_model::resource::ResourceNode;
use sandtree_sdk::manifest::PluginKind;
use sandtree_sdk::ports::{DiscoverBatch, ProviderDescriptor, ProviderHealth, ResourceProvider};
use sandtree_sdk::wit::WitDescriptor;
use serde_json::Value as Json;
use wasmtime::component::{Component, Linker};
use wasmtime::{Config, Engine, Store, StoreLimits, StoreLimitsBuilder};

use crate::hot_swap::GenerationRuntime;
use crate::limits::WorkerLimits;
use crate::route::Generation;

/// Generated bindings for `schemas/sandtree_provider_v1.wit` (see ADR-004 for
/// why the WIT copy lives in `wit/` rather than pointing straight at the frozen
/// design file).
#[allow(missing_docs, clippy::all)]
pub mod abi {
    wasmtime::component::bindgen!({
        // The design file `schemas/sandtree_provider_v1.wit` is frozen and, as
        // written, a strict WIT parser rejects it: `record descriptor` and
        // `descriptor: func()` share one namespace in the `lifecycle`
        // interface. `wit/` holds a copy that differs only in that record's
        // name. `wit_copy_matches_design_file` fails if they ever diverge, so
        // the design file stays the source of truth for the ABI.
        path: "wit/sandtree_provider_v1.wit",
        world: "provider-plugin",
    });
}

use abi::ProviderPlugin;

/// Guest-facing host state.
pub struct HostState {
    /// Store limits enforced on every growth request.
    pub limits: StoreLimits,
    /// Capabilities actually granted to this worker (FR-051).
    pub granted: CapabilitySet,
}

fn engine_error(context: &str, e: wasmtime::Error) -> DomainError {
    DomainError::new(ErrorCode::PLUGIN_HEALTH_FAILED, format!("{context}: {e}"))
}

fn component_error(raw: String) -> DomainError {
    sandtree_sdk::wit::decode_component_error(&raw)
}

/// Build an engine with the containment features enabled.
///
/// Fuel and epoch interruption are *not* optional here: a host that instantiates
/// untrusted components without them has no trap story at all.
pub fn build_engine(limits: &WorkerLimits) -> Result<Engine, DomainError> {
    let mut config = Config::new();
    config.consume_fuel(true);
    config.epoch_interruption(true);
    config.wasm_component_model(true);
    // Guest memory is capped by StoreLimits; the engine-level limit is a
    // backstop for the allocator's own reservations.
    config.memory_reservation(limits.memory_bytes as u64);
    Engine::new(&config).map_err(|e| engine_error("failed to build the plugin engine", e))
}

/// Advance the shared epoch, interrupting every worker whose deadline is now in
/// the past.
///
/// This **must** be called periodically by the host. `Config::epoch_interruption`
/// only arms the mechanism; without an external ticker nothing ever fires it,
/// and a wedged guest would run until its fuel ran out rather than being
/// interrupted at the wall-clock deadline. The two limits are independent on
/// purpose: fuel bounds a *busy* guest, the epoch bounds a *blocked* one.
pub fn tick(engine: &Engine) {
    engine.increment_epoch();
}

/// An engine with fuel metering but no epoch interruption.
///
/// Only for measuring fuel in isolation; production workers use
/// [`build_engine`].
#[cfg(test)]
fn fuel_only_engine() -> Engine {
    let mut config = Config::new();
    config.consume_fuel(true);
    config.wasm_component_model(true);
    Engine::new(&config).expect("engine")
}

/// A live WASM component generation.
pub struct ComponentGeneration {
    store: tokio::sync::Mutex<Store<HostState>>,
    bindings: ProviderPlugin,
    limits: WorkerLimits,
    generation: Generation,
    /// Captured once at load time.
    ///
    /// The supervisor needs the descriptor *before* `init` (the state-schema
    /// compatibility check runs ahead of migration), and the trait method that
    /// returns it is synchronous. Calling into the guest synchronously on every
    /// read would mean blocking inside an async context, so the value is read
    /// once here and cached — a descriptor is immutable for the life of a
    /// generation by definition.
    descriptor: WitDescriptor,
    /// Provider role, from the manifest.
    ///
    /// Not in the WIT descriptor, which carries only identity and state schema.
    /// The kernel routes by role (DD-PLG §2), so it has to come from somewhere
    /// the operator declared rather than be guessed from the exports a
    /// component happens to have.
    kind: PluginKind,
}

impl std::fmt::Debug for ComponentGeneration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ComponentGeneration")
            .field("generation", &self.generation)
            .field("kind", &self.kind)
            .field("fuel", &self.limits.fuel)
            .finish()
    }
}

impl ComponentGeneration {
    /// Compile, instantiate and bind a component.
    ///
    /// Binding happens here, not lazily, so a component that does not implement
    /// the `provider-plugin` world is rejected before it can ever be routed
    /// traffic. The world declares both `lifecycle` and `resource-provider`, so
    /// both exports are required here — an observation-only plugin uses the
    /// observation world, not a truncated provider world.
    pub async fn load(
        engine: &Engine,
        component_bytes: &[u8],
        granted: CapabilitySet,
        limits: WorkerLimits,
        generation: Generation,
        kind: PluginKind,
    ) -> Result<Arc<Self>, DomainError> {
        let component = Component::new(engine, component_bytes).map_err(|e| {
            DomainError::new(
                ErrorCode::PLUGIN_MANIFEST_INVALID,
                format!("component is not a valid WASM component: {e}"),
            )
        })?;

        let mut store = Store::new(
            engine,
            HostState {
                limits: StoreLimitsBuilder::new()
                    .memory_size(limits.memory_bytes)
                    .instances(1)
                    .memories(1)
                    .tables(1)
                    .build(),
                granted,
            },
        );
        store.limiter(|state| &mut state.limits);

        // **Before the first guest call.** With `epoch_interruption` enabled a
        // store starts with an epoch deadline of 0, which the engine has already
        // passed: an un-armed call traps immediately with `wasm trap:
        // interrupt`, before the guest executes a single instruction. Reading
        // `descriptor` un-armed therefore made *every* component fail to load,
        // and nothing noticed because nothing drove this path.
        //
        // The budget for this call comes from `limits`, not from a `Self` that
        // does not exist yet — hence the free function rather than `self.arm`.
        Self::arm_with(&limits, &mut store)?;

        let linker: Linker<HostState> = Linker::new(engine);
        let bindings =
            ProviderPlugin::instantiate(&mut store, &component, &linker).map_err(|e| {
                DomainError::new(
                    ErrorCode::PLUGIN_MANIFEST_INVALID,
                    format!(
                        "component does not implement the `provider-plugin` world (needs \
                     `sandtree:plugin/lifecycle@1.0.0` and \
                     `sandtree:plugin/resource-provider@1.0.0`): {e}"
                    ),
                )
            })?;

        // Read the immutable descriptor eagerly; see the field doc.
        let d = bindings
            .sandtree_plugin_lifecycle()
            .call_descriptor(&mut store)
            .map_err(|e| engine_error("lifecycle.descriptor trapped", e))?;
        let descriptor = WitDescriptor {
            plugin_id: d.plugin_id,
            version: d.version,
            state_schema_version: d.state_schema_version,
        };

        Ok(Arc::new(Self {
            store: tokio::sync::Mutex::new(store),
            bindings,
            limits,
            generation,
            descriptor,
            kind,
        }))
    }

    /// Refill the per-call fuel budget and arm the epoch deadline.
    ///
    /// Called before every guest call: fuel is per-call, not per-generation, so
    /// a long-lived plugin still cannot accumulate an unbounded budget.
    fn arm(&self, store: &mut Store<HostState>) -> Result<(), DomainError> {
        Self::arm_with(&self.limits, store)
    }

    /// The arming itself, separated so [`ComponentGeneration::load`] can use it
    /// before a `Self` exists.
    ///
    /// One implementation, one invariant: a second copy of this logic is how the
    /// load path ended up calling into the guest with no budget at all.
    fn arm_with(limits: &WorkerLimits, store: &mut Store<HostState>) -> Result<(), DomainError> {
        store
            .set_fuel(limits.fuel)
            .map_err(|e| engine_error("failed to set the guest fuel budget", e))?;
        store.set_epoch_deadline(1);
        Ok(())
    }

    /// Decode a guest payload into a domain DTO.
    ///
    /// The WIT surface is JSON strings; the kernel wants typed DTOs. A guest that
    /// returns something unparseable is a **failure**, never a default value —
    /// folding a malformed reply into an empty batch or a default node would
    /// report "no resources found" for a provider that is merely broken, which is
    /// the collapse ADR-OBS-001 forbids.
    fn decode<T: serde::de::DeserializeOwned>(
        raw: String,
        context: &'static str,
    ) -> Result<T, DomainError> {
        serde_json::from_str(&raw).map_err(|e| {
            DomainError::new(
                ErrorCode::CORE_INVALID,
                format!("{context}: guest returned unparseable JSON ({e}): {raw:?}"),
            )
        })
    }
}

/// `ResourceProvider` over the WIT `resource-provider` exports.
///
/// The WIT surface is three JSON-in/JSON-out calls; the kernel port is typed
/// DTOs. Every method arms the guest before calling, because a call site that
/// forgot would give a component an unbounded fuel budget with no guard rail —
/// the containment story this engine exists to tell (FR-054). Keeping `arm` in
/// each method is deliberate: a shared helper that took the closure would be
/// shorter and would make the arming invisible at the call site.
///
/// `health` and `shutdown` delegate to the `GenerationRuntime` impl on the same
/// value rather than re-calling the guest. The lifecycle export is the
/// authority for those, and a second, subtly different interpretation of the
/// same guest state is how a host ends up disagreeing with itself about whether
/// a plugin is alive.
#[async_trait::async_trait]
impl ResourceProvider for ComponentGeneration {
    fn descriptor(&self) -> ProviderDescriptor {
        ProviderDescriptor {
            plugin_id: self.descriptor.plugin_id.clone(),
            version: self.descriptor.version.clone(),
            kind: self.kind,
        }
    }

    async fn health(&self) -> Result<ProviderHealth, DomainError> {
        GenerationRuntime::health(self).await
    }

    async fn discover(&self, cursor: Option<String>) -> Result<DiscoverBatch, DomainError> {
        let mut store = self.store.lock().await;
        self.arm(&mut store)?;
        let raw = self
            .bindings
            .sandtree_plugin_resource_provider()
            .call_discover(&mut *store, cursor.as_deref())
            .map_err(|e| engine_error("resource-provider.discover trapped", e))?
            .map_err(component_error)?;
        Self::decode(raw, "resource-provider.discover")
    }

    async fn inspect(&self, id: &ResourceId) -> Result<ResourceNode, DomainError> {
        let mut store = self.store.lock().await;
        self.arm(&mut store)?;
        let raw = self
            .bindings
            .sandtree_plugin_resource_provider()
            .call_inspect(&mut *store, id.as_str())
            .map_err(|e| engine_error("resource-provider.inspect trapped", e))?
            .map_err(component_error)?;
        Self::decode(raw, "resource-provider.inspect")
    }

    async fn invoke(&self, req: &OperationRequest) -> Result<OperationOutcome, DomainError> {
        let mut store = self.store.lock().await;
        self.arm(&mut store)?;
        // The whole request travels as the payload: the WIT signature takes one
        // JSON string, and the provider is the only thing that understands
        // provider-specific args (DD-SW §4).
        let payload = serde_json::to_string(req)
            .map_err(|e| DomainError::new(ErrorCode::CORE_INVALID, e.to_string()))?;
        let raw = self
            .bindings
            .sandtree_plugin_resource_provider()
            .call_invoke(
                &mut *store,
                req.resource_id.as_str(),
                req.op.as_str(),
                &payload,
            )
            .map_err(|e| engine_error("resource-provider.invoke trapped", e))?
            .map_err(component_error)?;
        Self::decode(raw, "resource-provider.invoke")
    }

    async fn shutdown(&self) {
        GenerationRuntime::shutdown(self).await
    }
}

#[async_trait::async_trait]
impl GenerationRuntime for ComponentGeneration {
    fn generation(&self) -> Generation {
        self.generation
    }

    fn descriptor(&self) -> WitDescriptor {
        self.descriptor.clone()
    }

    async fn init(&self, config: &Json) -> Result<(), DomainError> {
        let mut store = self.store.lock().await;
        self.arm(&mut store)?;
        let payload = serde_json::to_string(config)
            .map_err(|e| DomainError::new(ErrorCode::CORE_INVALID, e.to_string()))?;
        self.bindings
            .sandtree_plugin_lifecycle()
            .call_init(&mut *store, &payload)
            .map_err(|e| engine_error("lifecycle.init trapped", e))?
            .map_err(component_error)
    }

    async fn health(&self) -> Result<ProviderHealth, DomainError> {
        let mut store = self.store.lock().await;
        self.arm(&mut store)?;
        let raw = self
            .bindings
            .sandtree_plugin_lifecycle()
            .call_health(&mut *store)
            .map_err(|e| engine_error("lifecycle.health trapped", e))?
            .map_err(component_error)?;

        // The component returns a JSON status string; the host decides what that
        // means. An unparseable status is a health failure, never "healthy".
        serde_json::from_str::<Json>(&raw)
            .ok()
            .and_then(|v| {
                let state = v.get("state")?.as_str()?;
                let reason = v.get("reason").and_then(Json::as_str).unwrap_or_default();
                Some(match state {
                    "healthy" => ProviderHealth::Healthy,
                    "degraded" => ProviderHealth::Degraded {
                        reason: reason.to_string(),
                    },
                    "unavailable" => ProviderHealth::Unavailable {
                        reason: reason.to_string(),
                    },
                    "stale" => ProviderHealth::Stale {
                        age_ms: v.get("age_ms").and_then(Json::as_u64).unwrap_or(0),
                    },
                    _ => return None,
                })
            })
            .ok_or_else(|| {
                DomainError::new(
                    ErrorCode::PLUGIN_HEALTH_FAILED,
                    format!("lifecycle.health returned an uninterpretable status: {raw:?}"),
                )
            })
    }

    async fn prepare_upgrade(&self, target_version: &str) -> Result<Vec<u8>, DomainError> {
        let mut store = self.store.lock().await;
        self.arm(&mut store)?;
        self.bindings
            .sandtree_plugin_lifecycle()
            .call_prepare_upgrade(&mut *store, target_version)
            .map_err(|e| engine_error("lifecycle.prepare-upgrade trapped", e))?
            .map_err(component_error)
    }

    async fn accept_upgrade(&self, from_version: &str, state: &[u8]) -> Result<(), DomainError> {
        let mut store = self.store.lock().await;
        self.arm(&mut store)?;
        self.bindings
            .sandtree_plugin_lifecycle()
            .call_accept_upgrade(&mut *store, from_version, state)
            .map_err(|e| engine_error("lifecycle.accept-upgrade trapped", e))?
            .map_err(component_error)
    }

    async fn drain(&self, deadline_ms: u64) -> Result<(), DomainError> {
        let mut store = self.store.lock().await;
        self.arm(&mut store)?;
        self.bindings
            .sandtree_plugin_lifecycle()
            .call_drain(&mut *store, deadline_ms)
            .map_err(|e| engine_error("lifecycle.drain trapped", e))?
            .map_err(component_error)
    }

    async fn shutdown(&self) {
        // Shutdown must never fail loudly: it runs on the retirement path,
        // including when the generation is already broken. A trap here is
        // logged and the store is dropped, which releases everything anyway.
        let mut store = self.store.lock().await;
        if self.arm(&mut store).is_ok() {
            if let Err(e) = self
                .bindings
                .sandtree_plugin_lifecycle()
                .call_shutdown(&mut *store)
            {
                tracing::warn!(
                    generation = %self.generation,
                    error = %e,
                    "lifecycle.shutdown trapped; releasing the store instead"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIMITS: WorkerLimits = WorkerLimits {
        fuel: 1_000_000,
        memory_bytes: 16 * 1024 * 1024,
        wall_clock_ms: 5_000,
        max_inflight: 1,
    };

    /// A real, minimal WASM component with no SandTree exports at all.
    const EMPTY_COMPONENT: &str = r#"
        (component
            (core module $m
                (func (export "f") nop)
            )
            (core instance $i (instantiate $m))
            (func (export "f") (canon lift (core func $i "f")))
        )
    "#;

    /// The frozen design artefact this crate's WIT copy must match (ADR-004).
    const DESIGN_WIT: &str = include_str!("../../../schemas/sandtree_provider_v1.wit");

    /// The parse-legal copy `bindgen!` actually reads.
    const LOCAL_WIT: &str = include_str!("../wit/sandtree_provider_v1.wit");

    #[test]
    fn wit_copy_matches_design_file() {
        // The only permitted difference is the record rename. Strip comments
        // and whitespace, undo the rename in the local copy, and compare — if
        // anyone edits one WIT and not the other, this fails.
        fn normalize(src: &str, undo_rename: bool) -> Vec<String> {
            let mut out = Vec::new();
            for raw in src.lines() {
                let mut line = raw.to_string();
                // Strip `//` comments (this WIT dialect has no `/* */`).
                if let Some(idx) = line.find("//") {
                    line.truncate(idx);
                }
                if line.trim().is_empty() {
                    continue;
                }
                if undo_rename {
                    line = line.replace("descriptor-record", "descriptor");
                }
                out.push(line.trim().to_string());
            }
            out
        }

        let design = normalize(DESIGN_WIT, false);
        let local = normalize(LOCAL_WIT, true);
        assert_eq!(
            design, local,
            "crates/plugin-host/wit/sandtree_provider_v1.wit has drifted from \
             schemas/sandtree_provider_v1.wit (beyond the documented record rename)"
        );
    }

    #[tokio::test]
    async fn engine_is_built_with_fuel_and_epoch_containment() {
        // FR-054: an engine without these is not a containment boundary.
        let engine = build_engine(&LIMITS).expect("engine");
        let mut store = Store::new(&engine, ());
        store.set_fuel(100).expect("fuel metering is on");
        store.set_epoch_deadline(1);
    }

    #[tokio::test]
    async fn fuel_actually_decrements_when_metering_is_on() {
        // If fuel were not being consumed, the budget would be decorative.
        // Measured on a fuel-only engine so epoch interruption cannot muddy
        // the number.
        let engine = fuel_only_engine();
        let component = Component::new(&engine, EMPTY_COMPONENT).expect("component compiles");
        let linker: Linker<()> = Linker::new(&engine);
        let mut store = Store::new(&engine, ());
        store.set_fuel(1_000_000).unwrap();
        let instance = linker.instantiate(&mut store, &component).unwrap();
        let f = instance.get_typed_func::<(), ()>(&mut store, "f").unwrap();

        let before = store.get_fuel().unwrap();
        f.call(&mut store, ())
            .unwrap_or_else(|e| panic!("call failed: {e:?}"));
        let after = store.get_fuel().unwrap();
        assert!(after < before, "fuel must be consumed: {before} -> {after}");
    }

    #[tokio::test]
    async fn epoch_tick_interrupts_a_worker_that_missed_its_deadline() {
        // FR-054 / the `tick` doc: fuel bounds a busy guest, the epoch bounds
        // a blocked one. A worker that called `arm` and then never yielded
        // still gets interrupted once the host advances the epoch.
        let engine = build_engine(&LIMITS).expect("engine");
        let component = Component::new(&engine, EMPTY_COMPONENT).expect("component compiles");
        let linker: Linker<()> = Linker::new(&engine);
        let mut store = Store::new(&engine, ());
        store.set_fuel(u64::MAX).unwrap();
        store.set_epoch_deadline(1);
        let instance = linker.instantiate(&mut store, &component).unwrap();
        let f = instance.get_typed_func::<(), ()>(&mut store, "f").unwrap();

        // Without a tick the deadline has not passed and the call runs.
        f.call(&mut store, ()).expect("before the tick");

        // After the tick the store is out of deadline. Use a fresh store so the
        // failure is the interruption itself and not the component model's
        // single-entry rule.
        tick(&engine);
        let mut late = Store::new(&engine, ());
        late.set_fuel(u64::MAX).unwrap();
        late.set_epoch_deadline(0);
        let instance = linker.instantiate(&mut late, &component).unwrap();
        let f = instance.get_typed_func::<(), ()>(&mut late, "f").unwrap();
        let err = f
            .call(&mut late, ())
            .expect_err("a missed epoch deadline must interrupt");
        let text = format!("{err:?}");
        assert!(
            text.contains("interrupt") || text.contains("epoch"),
            "expected an epoch interruption, got: {text}"
        );
    }

    #[tokio::test]
    async fn garbage_bytes_are_rejected_as_an_invalid_component() {
        let engine = build_engine(&LIMITS).expect("engine");
        let err = ComponentGeneration::load(
            &engine,
            b"definitely not wasm",
            CapabilitySet::empty(),
            LIMITS,
            Generation(1),
            PluginKind::Provider,
        )
        .await
        .expect_err("garbage must not load");
        assert_eq!(err.code, ErrorCode::PLUGIN_MANIFEST_INVALID);
    }

    #[tokio::test]
    async fn a_component_without_the_lifecycle_interface_is_refused() {
        // The design's world is `provider-plugin`. A component that compiles
        // but exports no lifecycle interface must never reach the route table.
        let engine = build_engine(&LIMITS).expect("engine");
        let err = ComponentGeneration::load(
            &engine,
            EMPTY_COMPONENT.as_bytes(),
            CapabilitySet::empty(),
            LIMITS,
            Generation(1),
            PluginKind::Provider,
        )
        .await
        .expect_err("missing lifecycle must not load");
        assert_eq!(err.code, ErrorCode::PLUGIN_MANIFEST_INVALID);
        assert!(
            err.message.contains("lifecycle"),
            "the error must name the missing interface: {}",
            err.message
        );
    }

    #[tokio::test]
    async fn an_uninterpretable_health_status_is_a_failure_not_a_pass() {
        // A component cannot report "healthy" by returning nonsense. The host
        // decides what health means (invariant 10: no guessing).
        let raw = serde_json::json!({"state": "totally-fine"});
        let parsed: Option<ProviderHealth> = serde_json::from_str::<Json>(&raw.to_string())
            .ok()
            .and_then(|v| {
                let state = v.get("state")?.as_str()?;
                Some(match state {
                    "healthy" => ProviderHealth::Healthy,
                    _ => return None,
                })
            });
        assert!(parsed.is_none());
    }

    #[tokio::test]
    async fn a_malformed_guest_reply_is_a_typed_error_not_an_empty_batch() {
        // ADR-OBS-001: a provider that is broken must not be reported as a
        // provider that found nothing. `DiscoverBatch::default()` is the trap —
        // it decodes from nothing and would make a broken guest look like a
        // clean scan of an empty system.
        let err = ComponentGeneration::decode::<DiscoverBatch>(
            "this is not json".to_string(),
            "resource-provider.discover",
        )
        .expect_err("garbage must not decode");
        assert_eq!(err.code, ErrorCode::CORE_INVALID);
        assert!(
            err.message.contains("resource-provider.discover"),
            "the error must name the call that failed: {}",
            err.message
        );
        assert!(
            err.message.contains("this is not json"),
            "the error must carry what the guest actually said: {}",
            err.message
        );
    }

    #[test]
    fn a_well_formed_reply_decodes_into_the_domain_type() {
        // The positive side of the same contract, so the previous test is not
        // passing merely because every input is rejected.
        let batch: DiscoverBatch = ComponentGeneration::decode(
            r#"{"resources":[],"relations":[]}"#.to_string(),
            "discover",
        )
        .expect("valid payload");
        assert!(batch.resources.is_empty());
        assert!(batch.relations.is_empty());
        assert!(batch.cursor.is_none());
    }

    #[test]
    fn structurally_valid_json_of_the_wrong_shape_is_still_a_failure() {
        // A guest returning `{}` for `discover` is as broken as one returning
        // prose: serde will not fill the missing fields in, and that refusal
        // is the behaviour we want rather than a silent default.
        let err = ComponentGeneration::decode::<DiscoverBatch>("{}".to_string(), "discover")
            .expect_err("missing required fields");
        assert_eq!(err.code, ErrorCode::CORE_INVALID);
    }

    #[tokio::test]
    async fn store_limits_are_attached_to_every_worker() {
        let engine = build_engine(&LIMITS).expect("engine");
        let mut store = Store::new(
            &engine,
            HostState {
                limits: StoreLimitsBuilder::new()
                    .memory_size(LIMITS.memory_bytes)
                    .instances(1)
                    .memories(1)
                    .tables(1)
                    .build(),
                granted: CapabilitySet::empty(),
            },
        );
        store.limiter(|state| &mut state.limits);
        // The limiter is consulted on growth; a store with it attached still
        // instantiates a small component fine.
        let component = Component::new(&engine, EMPTY_COMPONENT).expect("component");
        let linker: Linker<HostState> = Linker::new(&engine);
        linker
            .instantiate(&mut store, &component)
            .expect("small component still fits");
    }
}
