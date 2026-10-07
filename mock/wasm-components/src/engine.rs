//! Live-engine validation of the fixture corpus (feature `engine`).
//!
//! Everything in this module is behind the default-OFF `engine` feature
//! because it pulls in a host-target wasmtime. The fixtures themselves need no
//! engine to exist or to be read; an engine is only needed to answer "is this
//! actually a component, and are its exports what the manifest says".
//!
//! # Why the engine is optional
//!
//! The crate's whole purpose is to be usable where no guest toolchain exists.
//! Making wasmtime mandatory would trade a missing `wasm32-wasip2` target for a
//! 200-crate host dependency in every mock test that touches this crate. Keeping
//! it optional means the default `cargo test` runs on a machine that cannot
//! build a component at all, and the engine checks are opted into where
//! validation matters.
//!
//! # A default-OFF module that nothing ran
//!
//! While this module was still blocked (see below) it was red, and the default
//! `cargo test --workspace` did not run it — so seven tests had been failing
//! silently for as long as they existed, and nothing in the gate list would have
//! said so. The block is resolved; `mock/scripts/run_regression.ps1` now runs
//! this feature explicitly so the module cannot rot unnoticed again. The lesson
//! is recorded rather than just fixed: **a test module behind a flag that no gate
//! enables is not a test**, whatever its green-on-paper status.
//!
//! # The block that was resolved, and how
//!
//! Every fixture used to fail with
//!
//! ```text
//! failed to parse WebAssembly module
//!   instance not valid to be used as export
//! ```
//!
//! The cause was **not** what this file previously claimed. The old diagnosis —
//! "an exported function may only use named value types, and exporting
//! `descriptor-record` produces a freshly aliased type identity" — was a guess,
//! and it had already sent one fix in the wrong direction (`(alias outer ...)`,
//! which does not parse in a component type position at all, `outer` being a
//! *core* alias kind).
//!
//! Bisection with real per-signature probes (`mock/scripts/gen_fixtures.ps1`
//! writes the components; the encoder's verdict identified each shape) settled
//! all three causes at once:
//!
//! 1. **An interface instance must export every type its own signatures use.**
//!    That single line is what makes the instance valid as an export.
//! 2. **The return-area pointer is the core function's `i32` result, never an
//!    extra parameter.** `canon lift` has the guest allocate the area and return
//!    its address; `canon lower` has the host pass it. Adding a trailing retptr
//!    parameter fails with `lowered parameter types [...] do not match parameter
//!    types [...]`.
//! 3. **A unit ok-payload does not make a `result` cheap.** `result<_, string>`
//!    is `[disc, err_ptr, err_len]` — three i32 — and still needs an area.
//!
//! Rule 2 in particular is the kind of thing that is easy to get backwards from
//! memory, and getting it backwards costs a full round of edits per function.
//!
//! # What this proves, and what it does not
//!
//! It proves the `.wat` text parses, validates and encodes into the component
//! binary a host loads. Binding and serving traffic is proved one level up, in
//! `tests/provider_binding.rs`, which drives `ComponentGeneration` over the same
//! fixture — an adapter that never reaches a guest looks exactly like one that
//! reaches it and mis-lays the ABI, so only a test that actually calls
//! distinguishes them.

#![cfg(feature = "engine")]

use wasmtime::component::Component;
use wasmtime::{Config, Engine};

/// Build an engine that accepts component text.
///
/// The component model is enabled explicitly rather than relying on the
/// default, so this module keeps working if wasmtime ever flips it.
fn engine() -> Result<Engine, String> {
    let mut config = Config::new();
    config.wasm_component_model(true);
    Engine::new(&config).map_err(|e| format!("engine: {e:?}"))
}

/// Compile WAT text into **component binary** bytes.
///
/// This is what a host loads, and it is deliberately *not*
/// [`wasmtime::component::Component::serialize`]: `serialize` produces a native
/// object file for `deserialize`-based AOT loading, and on this machine those
/// bytes begin `\x7fELF`. Handing them back to `Component::new` fails with
/// `input bytes aren't valid utf-8`, which reads like a text-parsing problem and
/// is not one. The encoding step is therefore `wat::parse_str`, and the result
/// is validated by a real engine before being returned — a `parse_str` success
/// only means the text parsed, not that the component is well formed.
pub fn compile(wat: &str) -> Result<Vec<u8>, String> {
    let bytes = wat::parse_str(wat).map_err(|e| format!("{e:?}"))?;
    let engine = engine()?;
    Component::new(&engine, &bytes[..]).map_err(|e| format!("{e:?}"))?;
    Ok(bytes)
}

/// The top-level export names of a compiled component, sorted.
///
/// Sorted so a comparison against [`Fixture::expected_exports`] is order
/// independent — the Component Model does not promise an export order and a
/// test that depended on one would be testing wasmtime, not the fixture.
pub fn top_level_exports(wat: &str) -> Result<Vec<String>, String> {
    let engine = engine()?;
    let component = Component::new(&engine, wat).map_err(|e| format!("{e:?}"))?;
    let mut names: Vec<String> = component
        .component_type()
        .exports(&engine)
        .map(|(name, _)| name.to_string())
        .collect();
    names.sort();
    Ok(names)
}

/// The import names of a compiled component, sorted.
///
/// A mock fixture must import nothing: an import is the host having to supply
/// something, and there is no host in a regression corpus.
pub fn imports(wat: &str) -> Result<Vec<String>, String> {
    let engine = engine()?;
    let component = Component::new(&engine, wat).map_err(|e| format!("{e:?}"))?;
    let mut names: Vec<String> = component
        .component_type()
        .imports(&engine)
        .map(|(name, _)| name.to_string())
        .collect();
    names.sort();
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{Expectation, Fixture};

    /// Every fixture compiles.
    ///
    /// There is no longer a blocked one: `the_valid_fixture_compiles` is the
    /// assertion that used to be inverted, and keeping the whole set here means
    /// a regression in any of them — not just the accept fixture — is caught by
    /// the gate.
    #[test]
    fn every_fixture_is_a_real_component() {
        for f in Fixture::ALL {
            compile(f.wat()).unwrap_or_else(|e| panic!("{f} does not compile: {e}"));
        }
    }

    /// The accept path is no longer hypothetical.
    ///
    /// This is the assertion that replaces `the_valid_fixture_is_blocked_on_the_named_type_export_rule`.
    /// It is here, and not only in the binding test, because a fixture that
    /// compiles is a precondition for every host-side test in the repo — if the
    /// corpus stops compiling, those tests should say so for the reason the
    /// corpus broke rather than for some downstream symptom.
    #[test]
    fn the_valid_fixture_compiles() {
        let bytes =
            compile(Fixture::ValidProviderComponent.wat()).expect("the accept fixture compiles");
        assert_eq!(
            &bytes[..8.min(bytes.len())],
            b"\0asm\x0d\x00\x01\x00",
            "compiled fixture is not a component binary"
        );
    }

    #[test]
    fn compiled_exports_are_exactly_what_the_manifest_claims() {
        for f in Fixture::ALL {
            let actual = top_level_exports(f.wat()).expect("compiles");
            let mut expected: Vec<String> =
                f.expected_exports().iter().map(|s| s.to_string()).collect();
            expected.sort();
            assert_eq!(actual, expected, "export set of {f}");
        }
    }

    #[test]
    fn no_fixture_imports_anything_from_the_host() {
        for f in Fixture::ALL {
            let imported = imports(f.wat()).expect("compiles");
            assert!(
                imported.is_empty(),
                "{f} must import nothing, imports: {imported:?}"
            );
        }
    }

    #[test]
    fn compiled_bytes_round_trip_through_the_binary_format() {
        // `Component::new` takes text; a host loads binary. Proving the bytes
        // encode back to the same exports is what makes `compile()` usable as a
        // fixture source for a real install test.
        for f in Fixture::ALL {
            let bytes = compile(f.wat()).expect("compiles");
            assert_eq!(&bytes[..4], b"\0asm", "{} is not a wasm module", f);
            let engine = engine().unwrap();
            let recompiled =
                Component::new(&engine, &bytes[..]).unwrap_or_else(|e| panic!("{f}: {e}"));
            assert_eq!(
                recompiled.component_type().exports(&engine).count(),
                f.expected_exports().len(),
                "binary round trip lost exports for {f}"
            );
        }
    }

    #[test]
    fn no_fixture_is_marked_blocked_any_more() {
        // `blocked` existed to record why the accept fixture could not compile.
        // Now that it compiles, leaving the field set would have a host-side test
        // refusing to expect an accept for a component that binds.
        let m = crate::manifest::manifest();
        for f in Fixture::ALL {
            let e = m.entry(f).expect("entry");
            assert!(
                e.blocked.is_none(),
                "manifest still blocks {f}: {:?}",
                e.blocked
            );
        }
    }

    #[test]
    fn every_reject_fixture_really_is_rejected_before_binding() {
        // Every fixture now compiles, so the reject split is carried entirely
        // by the export names a host derives a package from. That is the check
        // `verify_component_package` performs, asserted against the real
        // compiled export list rather than against the fixture's own claims.
        for f in Fixture::ALL
            .into_iter()
            .filter(|f| f.expectation().is_reject())
        {
            let Expectation::Reject { code, at, .. } = f.expectation() else {
                panic!("{f} is not a reject fixture");
            };
            assert_eq!(code, "ST-PLG-001", "{f}");
            let exports = top_level_exports(f.wat()).expect("compiles");
            let abi_exports: Vec<&String> = exports
                .iter()
                .filter(|e| e.contains("/lifecycle@") || e.contains("/resource-provider@"))
                .collect();
            match at {
                "verify_component_package" => {
                    assert!(
                        !abi_exports.is_empty(),
                        "{f} exports no interface at all, so no package could be derived"
                    );
                    for name in &abi_exports {
                        let pkg = crate::fixtures::package_of(name).expect("interface name");
                        match f {
                            Fixture::WrongPackageName => assert_eq!(
                                pkg, "evil:plugin@1.0.0",
                                "{f} export {name} does not carry the foreign namespace"
                            ),
                            Fixture::InterfaceVersionMismatch => assert_eq!(
                                pkg, "sandtree:plugin@2.0.0",
                                "{f} export {name} does not carry world 2.0.0"
                            ),
                            _ => {}
                        }
                    }
                }
                "ProviderPlugin::instantiate" => {
                    // The world is unmet, so the interface set is what is wrong.
                    match f {
                        Fixture::MissingRequiredExport => assert!(
                            !exports
                                .iter()
                                .any(|e| e.contains("/resource-provider@1.0.0")),
                            "{f} must not export resource-provider@1.0.0"
                        ),
                        Fixture::NoSandTreeExports => assert!(
                            !abi_exports.iter().any(|e| e.starts_with("sandtree:")),
                            "{f} must export no sandtree: interface"
                        ),
                        _ => {}
                    }
                }
                other => panic!("{f} names an unknown rejecting check: {other}"),
            }
        }
    }
}
