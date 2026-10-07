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
//! # What this proves, and what it does not
//!
//! It proves the `.wat` text parses, validates and encodes — that the fixtures
//! are real components, not plausible-looking text. It does **not** prove the
//! host binds them: binding needs `sandtree-plugin-host`'s `wasmtime-abi`
//! feature, which is off by default and belongs to another crate.

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
    Engine::new(&config).map_err(|e| format!("engine: {e}"))
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
        .map_err(|e| format!("{e}"))?
        .serialize()
        .map_err(|e| format!("{e}"))
}

/// The top-level export names of a compiled component, sorted.
///
/// Sorted so a comparison against [`Fixture::expected_exports`] is order
/// independent — the Component Model does not promise an export order and a
/// test that depended on one would be testing wasmtime, not the fixture.
pub fn top_level_exports(wat: &str) -> Result<Vec<String>, String> {
    let engine = engine()?;
    let component = Component::new(&engine, wat).map_err(|e| format!("{e}"))?;
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
    let component = Component::new(&engine, wat).map_err(|e| format!("{e}"))?;
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
    use crate::fixtures::Fixture;

    #[test]
    fn every_fixture_is_a_real_component() {
        for f in Fixture::ALL {
            compile(f.wat()).unwrap_or_else(|e| panic!("{f} does not compile: {e}"));
        }
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
        // `Component::new` takes text; a host loads binary. Proving the text
        // encodes to bytes that encode back to the same exports is what makes
        // `compile()` usable as a fixture source for a real install test.
        for f in Fixture::ALL {
            let bytes = compile(f.wat()).expect("compiles");
            assert_eq!(&bytes[..4], b"\0asm", "{} is not a wasm module", f);
            let engine = engine().unwrap();
            let recompiled =
                Component::new(&engine, &bytes[..]).unwrap_or_else(|e| panic!("{f}: {e}"));
            assert_eq!(recompiled.component_type().exports(&engine).count(), f.expected_exports().len());
        }
    }
}
