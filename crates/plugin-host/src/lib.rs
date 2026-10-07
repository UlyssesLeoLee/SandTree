//! SandTree plugin host (FR-050..055, DD-PLG, ADR-016).
//!
//! Responsibilities, in the order the design states them:
//!
//! * [`verify`] — decide whether a package may be staged at all, and with which
//!   capabilities. No runtime involved, so the trust decision is testable on its
//!   own.
//! * [`limits`] — the host ceiling for one plugin worker. Configuration may
//!   tighten, never loosen.
//! * [`generation`] — one loaded generation: lifecycle control plus the ports it
//!   serves. This is the unit the route table holds.
//! * [`route`] — the generation route table. **The single authority** on which
//!   generation serves which plugin.
//! * [`hot_swap`] — the stage → health → migrate → atomic route swap → drain →
//!   rollback supervisor (FR-052).
//! * [`engine`] — the WASM Component Model adapter, behind the `wasmtime-abi`
//!   feature, implementing [`hot_swap::GenerationRuntime`] for real components.
//! * [`cluster`] — App Cluster assembly: stage every plugin in an app manifest
//!   as one generation, publish together or not at all (DD-PLG 核心原则
//!   "Plugin Cluster→App Cluster").
//!
//! ADR-002: the cross-version ABI is WIT + Component Model. Rust traits in this
//! crate are host-internal and are not an ABI; they exist so official
//! in-process providers and third-party components land on the same trait.
//!
//! ADR-016: a generation used to be described by two types and stored in two
//! places. There is now exactly one ([`generation::LoadedGeneration`]) and
//! exactly one owner ([`route::RouteTable`]). A kernel
//! [`sandtree_sdk::ports::ProviderRegistry`] is a *projection* of the route
//! table, produced by `LoadedGeneration::ports_for_registry`, and is not allowed
//! to disagree with it.

#![deny(missing_docs)]

pub mod cluster;
pub mod generation;
pub mod hot_swap;
pub mod limits;
pub mod route;
pub mod verify;

#[cfg(feature = "wasmtime-abi")]
pub mod engine;

pub use cluster::{ClusterInstall, ClusterPlan, ClusterPlanner};
pub use generation::LoadedGeneration;
pub use hot_swap::{GenerationRuntime, HotSwapSupervisor, StateMigration, SwapResult, SwapTrace};
pub use limits::{check_against_ceiling, resolve, WorkerLimits};
pub use route::{Generation, HotSwapOutcome, RouteTable};
pub use verify::{InstallPolicy, StagedPackage};
