//! SandTree mock Lane C — hand-written WASM component fixtures.
//!
//! # Why this crate exists
//!
//! `sandtree-plugin-host` loads plugins through the WASM Component Model
//! (ADR-002, FR-054): it compiles the component bytes, instantiates the
//! `provider-plugin` world, and refuses anything that does not export
//! `sandtree:plugin/lifecycle@1.0.0` **and**
//! `sandtree:plugin/resource-provider@1.0.0`.
//!
//! The positive half of that path — "a well-formed provider component actually
//! loads, reports its descriptor, and answers `health`" — needs real `.wasm`
//! bytes. Producing those normally means cross-compiling a guest with
//! `cargo build --target wasm32-wasip2`.
//!
//! # The blocker (why the fixtures are WAT text)
//!
//! This machine has no `rustup` shim, so `rustup target add wasm32-wasip2`
//! cannot run and the target's `core`/`std` are not installed. **No guest crate
//! can be cross-compiled here**, and no prebuilt provider `.wasm` is vendored in
//! the repository. A test that asserts "the happy path loads" therefore has
//! nothing to load.
//!
//! The fix is to keep the *component* as WebAssembly text (`.wat`) and hand it
//! straight to the engine. Wasmtime's text-format parser lives in the
//! host-target `wasmtime` crate and needs no guest toolchain, so a component
//! written by hand in `.wat` exercises exactly the same compile → instantiate →
//! link path as a cross-compiled one. What the fixtures do **not** replace is
//! guest *source*: there is no Rust here that would be compiled away. Every
//! fixture is a complete, self-contained component.
//!
//! # What this crate does not do
//!
//! It does not re-test the host. `crates/plugin-host` owns the policy; these
//! fixtures are the inputs a host-side test drives, and [`manifest`] declares
//! for each one what the host is expected to do with it.
//!
//! [`manifest`]: crate::manifest
//!
//! # ADR-004
//!
//! The frozen design WIT (`schemas/sandtree_provider_v1.wit`) is not strictly
//! parseable — `record descriptor` and `descriptor: func()` collide in one
//! namespace — so `crates/plugin-host/wit/` holds a renamed copy. The fixtures
//! are built against the same package identity the host binds, and the
//! equivalence of the two WIT files is re-checked from this side in
//! `wit_equivalence`.
//!
//! # Scope
//!
//! Mock-only. `crates/*` must never depend on this crate (see `mock/README.md`).

#![deny(missing_docs)]

pub mod fixtures;
pub mod manifest;
pub mod wit_equivalence;

/// Corpus tests that need no WASM engine.
///
/// `#[cfg(test)]` rather than a public module: these assertions are about this
/// crate's own fixtures, so shipping them in the library's API would expose
/// test scaffolding to callers and leave their imports unused in a non-test
/// build.
#[cfg(test)]
mod tests;

/// Live-engine validation of the corpus (default-OFF `engine` feature).
#[cfg(feature = "engine")]
pub mod engine;

pub use fixtures::{Expectation, Fixture};
