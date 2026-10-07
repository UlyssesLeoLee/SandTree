//! SandTree mock Observation Plane (mock project **Lane B**).
//!
//! A scripted [`ObservationProvider`] for regression tests that must not depend
//! on a real runtime. Windows Sandbox cannot be driven on a build machine,
//! Multipass is not installed, and Docker daemon state is not the test's to
//! control — which leaves the two highest-risk design invariants with no
//! coverage at all. This crate provides both, deterministically.
//!
//! # What is defended here
//!
//! | invariant | where |
//! | --- | --- |
//! | **ADR-OBS-001** — control and observation are separate planes; a failed observation is a state, not an error, and never means "absent" | [`provider::ScriptedObservation`], [`fault::FaultDisposition`] |
//! | **ADR-OBS-003** — trust is never raised; `guest_probe` stays `guest_probe` | [`trust`] |
//! | **FR-075 / FR-079** — a failure yields a typed result rather than an error | [`fault`] |
//! | **NFR-O01 / NFR-O02** — no provider SDK, no runtime binding, no guesswork | crate dependencies |
//! | **NFR-S06 / S07 / S08** — isolation is not tradeable; a guest path is not a host path | [`fault::ObservationFault::GuestPathEscape`] |
//!
//! # Quick start
//!
//! ```
//! use sandtree_mock_observation::{ObservationFixture, ResourceObservation, ScriptedObservation};
//! use sandtree_observation_model::{ObservationDomain, ObservationMode, TrustLevel};
//! use sandtree_sdk::ports::ObservationProvider;
//! use serde_json::json;
//!
//! # async fn demo() {
//! let world = ObservationFixture::new("mock-probe").with_resource(
//!     ResourceObservation::new(&["mock", "sandbox-1"])
//!         .with_modes(&[ObservationMode::Probe, ObservationMode::Metadata])
//!         .with_value(ObservationDomain::System, json!({"os": "windows"}))
//!         .with_trust(TrustLevel::GuestProbe),
//! );
//! let provider = ScriptedObservation::new(world);
//! let id = sandtree_model::id::ResourceId::derive(&["mock", "sandbox-1"]);
//! let snap = provider
//!     .observe(&sandtree_observation_model::ObservationRequest::new(
//!         id.clone(),
//!         vec![ObservationDomain::System],
//!     ))
//!     .await
//!     .expect("typed result, never a bare error");
//!
//! assert_eq!(snap.health, sandtree_observation_model::ObservationHealth::Healthy);
//! // ADR-OBS-003: guest-reported data never surfaces as host-native.
//! assert_eq!(snap.weakest_trust(), Some(TrustLevel::GuestProbe));
//! // ADR-OBS-001: observing does not create or destroy the resource.
//! assert!(provider.has_resource(&id));
//! # }
//! ```
//!
//! # Determinism
//!
//! No wall clock, no randomness, no environment probing. Every timestamp, age
//! and payload comes from the fixture, so the same fixture yields byte-identical
//! snapshots on every run — which is what makes "this snapshot must never say
//! host-native" a checkable assertion rather than a flaky one.
//!
//! Every collection that reaches serialization is ordered: values live in
//! `BTreeMap`, served domains are sorted before insertion, and capabilities
//! follow [`provider::MODE_PRIORITY`].
//!
//! # Relationship to the rest of the mock project
//!
//! Lane A (`mock/runtime`) scripts the control plane and Lane C
//! (`mock/wasm-components`) the plugin ABI. This crate is deliberately
//! independent of both: it needs no scripted `ResourceNode` and no component,
//! so a kernel test can mount it alone. Mock crates are never depended on by
//! product code — only by `tests/*` and `apps/*` as dev-dependencies.

#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

pub mod fault;
pub mod fixture;
pub mod provider;
pub mod trust;

pub use fault::{FaultDisposition, ObservationFault};
pub use fixture::{FixtureError, ObservationFixture, ResourceObservation, FIXTURE_SCHEMA};
pub use provider::{effective_health, select_mode, ScriptedObservation, MODE_PRIORITY};
pub use trust::{is_permitted, mode_trust_ceiling, resolve_trust, TrustDecision};