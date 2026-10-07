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
//! # Known state of the corpus
//!
//! Three of the four ABI-shaped fixtures compile as real components. The valid
//! one does **not**: wasmtime rejects it with `instance not valid to be used as
//! export`, because a Component Model component may only export a function
//! whose value types are *named*, and exporting `descriptor-record` produces a
//! freshly aliased type identity that `lifecycle.descriptor` does not reference.
//! Getting that right needs an `(alias outer ...)` re-reference of the
//! exported type, which is not something to guess at in hand-written WAT.
//!
//! That failure is pinned by
//! [`tests::the_valid_fixture_is_blocked_on_the_named_type_export_rule`] rather
//! than skipped, so it cannot turn into a silent regression and cannot be
//! mistaken for a passing accept path.
//!
//! # What this proves, and what it does not
//!
//! It proves the `.wat` text parses, validates and encodes. It does **not**
//! prove the host binds them: binding needs `sandtree-plugin-host`'s
//! `wasmtime-abi` feature, which is off by default and belongs to another
//! crate.

#![cfg(feature = "engine")]

use crate::fixtures::Fixture;
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

/// Compile WAT text into binary component bytes.
///
/// This is the same entry point a host uses, minus the staging policy: hand it
/// the result and it is exactly what a cross-compiled `.wasm` would have been.
/// Returns the error text rather than a `wasmtime::Error` so callers do not
/// need the engine feature in their own signatures.
pub fn compile(wat: &str) -> Result<Vec<u8>, String> {
    let engine = engine()?;
    Component::new(&engine, wat)
        .map_err(|e| format!("{e:?}"))?
        .serialize()
        .map_err(|e| format!("{e:?}"))
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

    /// Fixtures that are expected to compile today. See the module docs for why
    /// the valid one is not in this list.
    fn compiling_fixtures() -> Vec<Fixture> {
        Fixture::ALL
            .into_iter()
            .filter(|f| !matches!(f, Fixture::ValidProviderComponent))
            .collect()
    }

    #[test]
    fn the_three_abideviation_fixtures_are_real_components() {
        for f in compiling_fixtures() {
            compile(f.wat()).unwrap_or_else(|e| panic!("{f} does not compile: {e}"));
        }
    }

    #[test]
    fn compiled_exports_are_exactly_what_the_manifest_claims() {
        for f in compiling_fixtures() {
            let actual = top_level_exports(f.wat()).expect("compiles");
            let mut expected: Vec<String> =
                f.expected_exports().iter().map(|s| s.to_string()).collect();
            expected.sort();
            assert_eq!(actual, expected, "export set of {f}");
        }
    }

    #[test]
    fn no_fixture_imports_anything_from_the_host() {
        for f in compiling_fixtures() {
            let imported = imports(f.wat()).expect("compiles");
            assert!(
                imported.is_empty(),
                "{f} must import nothing, imports: {imported:?}"
            );
        }
    }

    #[test]
    fn compiled_bytes_round_trip_through_the_binary_format() {
        // `Component::new` takes text; a host loads binary. Proving the text
        // encodes to bytes that encode back to the same exports is what makes
        // `compile()` usable as a fixture source for a real install test.
        for f in compiling_fixtures() {
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
    fn the_valid_fixture_is_blocked_on_the_named_type_export_rule() {
        // Pinned, not skipped. If this ever starts compiling, the corpus gained
        // a real accept path and this test must be updated to say so.
        let err = compile(Fixture::ValidProviderComponent.wat())
            .expect_err("still expected to be blocked");
        assert!(
            err.contains("not valid to be used as export"),
            "expected the named-type export failure, got: {err}"
        );
        // The manifest must say so too, so a host-side test cannot be driven
        // into an accept expectation that cannot hold.
        let m = crate::manifest::manifest();
        let e = m.entry(Fixture::ValidProviderComponent).expect("entry");
        assert!(
            e.blocked.is_some(),
            "MANIFEST.json must record why the valid fixture does not compile"
        );
    }

    #[test]
    fn the_manifest_marks_exactly_the_blocked_fixture() {
        let m = crate::manifest::manifest();
        for f in Fixture::ALL {
            let e = m.entry(f).expect("entry");
            assert_eq!(
                e.blocked.is_some(),
                matches!(f, Fixture::ValidProviderComponent),
                "manifest `blocked` disagrees with reality for {}",
                f.name()
            );
        }
    }

    #[test]
    fn every_reject_fixture_that_compiles_really_is_rejected_before_binding() {
        // A fixture that compiles but exports a bad namespace/version is the
        // case `verify_component_package` exists for, so assert the derivation
        // the host performs on the real compiled export list.
        for f in compiling_fixtures() {
            let Expectation::Reject { code, .. } = f.expectation() else {
                panic!("{f} is not a reject fixture");
            };
            assert_eq!(code, "ST-PLG-001", "{f}");
            let exports = top_level_exports(f.wat()).expect("compiles");
            let abi_exports: Vec<&String> = exports
                .iter()
                .filter(|e| e.contains("/lifecycle@") || e.contains("/resource-provider@"))
                .collect();
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
    }
}
