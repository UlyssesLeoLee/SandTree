//! SandTree mock runtime (mock project, lane A).
//!
//! A **scripted world**: a declarative JSON description of resources,
//! relations, pagination cursors and per-operation outcomes, exposed through the
//! three control-plane provider ports of [`sandtree_sdk::ports`] —
//! [`ResourceProvider`], [`FileProvider`] and [`ExecProvider`].
//!
//! # Why this exists
//!
//! The repository contained two hand-rolled provider fakes — `Fake` in
//! `tests/integration` (~700 lines) and `World`/`Runtime` in `tests/system`
//! (~500 lines) — which duplicated each other, were not exported, and had
//! drifted. This crate is the single replacement: one world description, three
//! ports, four fault modes.
//!
//! # Determinism (the property the whole thing exists for)
//!
//! * no wall clock: every timestamp comes from the fixture, never from
//!   [`sandtree_sdk::manifest::now_rfc3339`] and never from the system;
//! * no randomness: identities are [`sandtree_model::id::ResourceId::derive`]d
//!   from fixture-declared parts, never generated;
//! * no environment probing: a world reads exactly the JSON it was given;
//! * no mutation of the resource set: invoking an operation changes nothing
//!   about what discovery reports, so `discover_all` is byte-identical for the
//!   same fixture no matter what was invoked before it;
//! * collections are ordered at load time, so serialization order is fixed
//!   even when the fixture lists its resources in a different order.
//!
//! # Fault injection
//!
//! Four faults are first-class in the fixture schema rather than bolted on:
//!
//! 1. a scripted operation that fails (or that fails hard with a stable code);
//! 2. a resource that does not exist (`inspect` on an unknown id);
//! 3. an error partway through pagination (`discover_fault.fail_from_page`);
//! 4. a provider that is entirely unavailable (`health.state = "unavailable"`).
//!
//! # Which rules the fake enforces
//!
//! The kernel already refuses a destructive operation without `force: true` and
//! already checks the host grant (FR-051 / NFR-S02). The fake **repeats both
//! refusals** at the provider boundary: duplicating a refusal is fail-closed,
//! while skipping it would let a test that calls a provider directly succeed on
//! a path production can never take.

#![deny(missing_docs)]

pub mod exec_provider;
pub mod file_provider;
pub mod fixture;
pub mod fixtures;
pub mod fleet;
pub mod resource_provider;
pub mod world;

pub use exec_provider::ScriptedExecProvider;
pub use file_provider::ScriptedFileProvider;
pub use fixture::{
    DiscoverFault, ExecSpec, FileSpec, FixtureError, OperationOutcomeSpec, OperationSpec,
    RelationSpec, ResourceSpec, ScriptedError, WorldFixture, FIXTURE_SCHEMA,
};
pub use fleet::{discover_all, ProviderDiscovery, ProviderFailure};
pub use resource_provider::ScriptedResourceProvider;
pub use world::ScriptedWorld;