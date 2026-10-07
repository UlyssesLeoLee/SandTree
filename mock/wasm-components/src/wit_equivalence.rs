//! ADR-004, re-checked from the fixture side.
//!
//! The frozen design WIT `schemas/sandtree_provider_v1.wit` declares both
//! `record descriptor` and `descriptor: func()`, which share one namespace in
//! the `lifecycle` interface and are therefore rejected by a strict parser. The
//! repo's answer is a renamed parse-legal copy under
//! `crates/plugin-host/wit/`, kept honest by `wit_copy_matches_design_file`
//! inside `crates/plugin-host`.
//!
//! That test lives in the crate that consumes the copy. This module is the
//! independent second opinion from the crate that *produces* components against
//! it: if the two WIT files ever drift beyond the documented rename, the
//! fixtures in this crate stop describing the ABI the host actually binds, and
//! that is a silent, expensive failure — every fixture would still compile and
//! every rejection would still pass while testing the wrong interface.
//!
//! Two properties are checked:
//!
//! 1. **Equivalence** — the local copy equals the design file modulo the record
//!    rename, comments and whitespace.
//! 2. **Conformance** — the interface names and function names this corpus
//!    builds against are exactly the ones the design WIT declares, so a fixture
//!    cannot quietly export a function the world does not have.
//!
//! Both WIT files are read-only to this lane; the comparison is `include_str!`
//! only, nothing is written back.

/// The frozen design artefact. Read-only (ADR-004, `mock/README.md` §4).
pub const DESIGN_WIT: &str = include_str!("../../../schemas/sandtree_provider_v1.wit");

/// The parse-legal copy `wasmtime::component::bindgen!` actually reads.
pub const LOCAL_WIT: &str =
    include_str!("../../../crates/plugin-host/wit/sandtree_provider_v1.wit");

/// The name ADR-004 renames `descriptor` to.
pub const RENAMED_RECORD: &str = "descriptor-record";

/// Strip comments and blank lines, optionally undoing the ADR-004 rename.
///
/// Same normalisation the host's own `wit_copy_matches_design_file` uses; kept
/// independent rather than shared because the two crates must not depend on
/// each other.
fn normalize(src: &str, undo_rename: bool) -> Vec<String> {
    src.lines()
        .map(|raw| {
            let mut line = raw.to_string();
            // This WIT dialect has no block comments.
            if let Some(idx) = line.find("//") {
                line.truncate(idx);
            }
            if undo_rename {
                line = line.replace(RENAMED_RECORD, "descriptor");
            }
            line.trim().to_string()
        })
        .filter(|line| !line.is_empty())
        .collect()
}

/// Whether the two WIT files agree modulo the documented rename.
pub fn wit_copy_matches_design() -> bool {
    normalize(DESIGN_WIT, false) == normalize(LOCAL_WIT, true)
}

/// The package declaration line of a WIT source.
///
/// The trailing `;` is WIT statement syntax, not part of the identity, so it is
/// trimmed here. Leaving it on made this disagree with the fixture side, which
/// derives the same string from an interface export name and has no terminator
/// to strip — and a disagreement between the two is indistinguishable from a
/// fixture that drifted onto a different package.
#[cfg(test)]
fn package_of(src: &str) -> Option<String> {
    normalize(src, false).into_iter().find_map(|l| {
        l.strip_prefix("package ")
            .map(|p| p.trim().trim_end_matches(';').trim().to_string())
    })
}

/// The function names declared by one named WIT interface.
#[cfg(test)]
fn interface_functions(src: &str, interface: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut inside = false;
    for line in normalize(src, false) {
        if line.starts_with("interface ") {
            inside = line == format!("interface {interface} {{");
            continue;
        }
        if line == "}" {
            inside = false;
            continue;
        }
        if !inside {
            continue;
        }
        // `name: func(...) -> ...;`. The `record` line in the same interface
        // ends with `}` rather than `;`, so it is skipped by design: it is a
        // type, not a function.
        if let Some(rest) = line.strip_suffix(';') {
            if let Some((name, _sig)) = rest.split_once(": func") {
                out.push(name.trim().to_string());
            }
        }
    }
    out
}

/// The interface names and world of a WIT source, for conformance checking.
#[cfg(test)]
fn interfaces_of(src: &str) -> Vec<String> {
    normalize(src, false)
        .into_iter()
        .filter_map(|l| {
            l.strip_prefix("interface ")
                .map(|r| r.trim_end_matches(" {").to_string())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{Fixture, LIFECYCLE_INTERFACE_1, RESOURCE_PROVIDER_INTERFACE_1};

    /// Every WIT function this crate's fixtures lift, per interface.
    ///
    /// Hand-written here rather than parsed out of the `.wat` files on purpose:
    /// this is the corpus's *claim* about the ABI, and it is what gets compared
    /// against the design WIT. Deriving it from the fixtures would make the
    /// comparison circular.
    const CORPUS_LIFECYCLE: &[&str] = &[
        "descriptor",
        "init",
        "health",
        "prepare-upgrade",
        "accept-upgrade",
        "drain",
        "shutdown",
    ];
    const CORPUS_RESOURCE_PROVIDER: &[&str] = &["discover", "inspect", "invoke"];

    #[test]
    fn wit_copy_matches_design_file_modulo_the_rename() {
        // ADR-004: this is the property that keeps the fixtures describing the
        // ABI the host binds. If it breaks, every fixture in this crate is
        // testing the wrong interface.
        assert_eq!(
            normalize(DESIGN_WIT, false),
            normalize(LOCAL_WIT, true),
            "crates/plugin-host/wit/sandtree_provider_v1.wit has drifted from \
             schemas/sandtree_provider_v1.wit beyond the documented record rename"
        );
        assert!(
            wit_copy_matches_design(),
            "wit_copy_matches_design() disagrees with the direct comparison"
        );
    }

    #[test]
    fn the_rename_is_the_only_difference_and_it_is_real() {
        // Guards against the equivalence check passing vacuously: if the local
        // copy did *not* contain the rename, the comparison above would be
        // comparing the design file to itself and proving nothing.
        assert!(
            LOCAL_WIT.contains(RENAMED_RECORD),
            "the local WIT copy must carry the ADR-004 rename"
        );
        assert!(
            DESIGN_WIT.contains("record descriptor {") && !DESIGN_WIT.contains(RENAMED_RECORD),
            "the frozen design WIT must still carry the colliding name"
        );
        assert_ne!(normalize(DESIGN_WIT, false), normalize(LOCAL_WIT, false));
    }

    #[test]
    fn both_wit_files_declare_the_package_the_fixtures_use() {
        let design = package_of(DESIGN_WIT).expect("design WIT declares a package");
        let local = package_of(LOCAL_WIT).expect("local WIT declares a package");
        assert_eq!(design, "sandtree:plugin@1.0.0");
        assert_eq!(design, local);
        // And the fixtures agree with the WIT about what they declare.
        assert_eq!(
            Fixture::ValidProviderComponent.declared_package(),
            Some(design.as_str())
        );
    }

    #[test]
    fn the_corpus_implements_exactly_the_declared_world() {
        // If the design WIT grew or lost a function, this must fail: the
        // fixtures would no longer cover the world, and a host-side test would
        // pass without exercising the new function.
        let design_interfaces = interfaces_of(DESIGN_WIT);
        assert_eq!(
            design_interfaces,
            vec!["lifecycle".to_string(), "resource-provider".to_string()]
        );

        let lifecycle = interface_functions(DESIGN_WIT, "lifecycle");
        assert_eq!(lifecycle, CORPUS_LIFECYCLE.to_vec());

        let resource = interface_functions(DESIGN_WIT, "resource-provider");
        assert_eq!(resource, CORPUS_RESOURCE_PROVIDER.to_vec());

        // The local copy must declare the same functions.
        assert_eq!(
            interface_functions(LOCAL_WIT, "lifecycle"),
            CORPUS_LIFECYCLE.to_vec()
        );
        assert_eq!(
            interface_functions(LOCAL_WIT, "resource-provider"),
            CORPUS_RESOURCE_PROVIDER.to_vec()
        );
    }

    #[test]
    fn the_interface_export_names_match_the_wit_identity() {
        // `sandtree:plugin/lifecycle@1.0.0` is `package` + `/interface@version`.
        let package = package_of(DESIGN_WIT).unwrap();
        let (ns_name, version) = package.split_once('@').unwrap();
        assert_eq!(
            crate::fixtures::package_of(LIFECYCLE_INTERFACE_1).as_deref(),
            Some(package.as_str())
        );
        assert_eq!(
            crate::fixtures::package_of(RESOURCE_PROVIDER_INTERFACE_1).as_deref(),
            Some(package.as_str())
        );
        assert!(LIFECYCLE_INTERFACE_1.starts_with(&format!("{ns_name}/lifecycle@{version}")));
        assert!(RESOURCE_PROVIDER_INTERFACE_1
            .starts_with(&format!("{ns_name}/resource-provider@{version}")));
    }
}
