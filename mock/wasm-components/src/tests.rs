//! Corpus tests that need no WASM engine.
//!
//! Everything asserted here is checked against the *files*, not against a
//! compiler, so it runs on a machine that cannot build a component at all —
//! which is the whole reason this crate exists. The engine-dependent checks
//! live in [`crate::engine`] behind the default-OFF `engine` feature.
//!
//! # What is deliberately not asserted here
//!
//! Nothing checks that a `.wat` file parses, that its exports are what the
//! manifest says, or that its function bodies behave. Those need wasmtime, and
//! a test that pretended otherwise would be exactly the always-true assertion
//! this repo removed from `tests/integration` and `tests/system`.

use crate::fixtures::{package_of, Expectation, Fixture};
use crate::manifest::{self, Outcome};

/// Significant lines of a WAT fixture: comments and blank lines removed.
///
/// Works on the text, so it is independent of the engine. Line endings are not
/// significant (a Windows checkout is CRLF, a Linux one is LF), so every line is
/// trimmed before comparison.
fn significant_lines(src: &str) -> Vec<String> {
    src.lines()
        .map(|l| {
            let l = match l.find(";;") {
                Some(i) => &l[..i],
                None => l,
            };
            l.trim().to_string()
        })
        .filter(|l| !l.is_empty())
        .collect()
}

/// The line changes a derived fixture must differ from the valid one by.
///
/// A pair is (line in the valid fixture, line in the derived one); an empty
/// second element means the line was removed. More than one pair is normal: a
/// component declaring a foreign package exports *both* of its interfaces under
/// it, and a world-version mismatch is wrong for both too, so a single-pair
/// description would have forced the fixtures to be wrong instead of the test.
fn expected_deviations(fixture: Fixture) -> Option<Vec<(&'static str, &'static str)>> {
    match fixture {
        // Namespace and version are the *only* intended differences.
        Fixture::WrongPackageName => Some(vec![
            (
                r#"(export "sandtree:plugin/lifecycle@1.0.0" (instance $lifecycle))"#,
                r#"(export "evil:plugin/lifecycle@1.0.0" (instance $lifecycle))"#,
            ),
            (
                r#"(export "sandtree:plugin/resource-provider@1.0.0" (instance $resource_provider))"#,
                r#"(export "evil:plugin/resource-provider@1.0.0" (instance $resource_provider))"#,
            ),
        ]),
        Fixture::InterfaceVersionMismatch => Some(vec![
            (
                r#"(export "sandtree:plugin/lifecycle@1.0.0" (instance $lifecycle))"#,
                r#"(export "sandtree:plugin/lifecycle@2.0.0" (instance $lifecycle))"#,
            ),
            (
                r#"(export "sandtree:plugin/resource-provider@1.0.0" (instance $resource_provider))"#,
                r#"(export "sandtree:plugin/resource-provider@2.0.0" (instance $resource_provider))"#,
            ),
        ]),
        // Only the export is removed; the instance is still defined.
        Fixture::MissingRequiredExport => Some(vec![(
            r#"(export "sandtree:plugin/resource-provider@1.0.0" (instance $resource_provider))"#,
            "",
        )]),
        _ => None,
    }
}

#[test]
fn manifest_export_lists_match_the_code() {
    // `exports` was data nothing read. An entry sat there listing eight names
    // for the valid fixture -- the two interfaces plus six type names that live
    // inside the instances, not at component scope -- and no test noticed,
    // because "top-level exports" was only ever checked in the engine module,
    // which compares `Fixture::expected_exports()` and never the manifest.
    // Two copies of one fact with no assertion between them is how that happens.
    let m = manifest::manifest();
    for f in Fixture::ALL {
        let e = m.entry(f).expect("entry");
        let mut from_manifest = e.exports.clone();
        let mut from_code: Vec<String> =
            f.expected_exports().iter().map(|s| s.to_string()).collect();
        from_manifest.sort();
        from_code.sort();
        assert_eq!(
            from_manifest, from_code,
            "entry {} lists different exports than the fixture declares",
            e.id
        );
    }
}

#[test]
fn every_fixture_has_a_manifest_entry_and_the_reverse() {
    let m = manifest::manifest();
    assert_eq!(
        m.fixtures.len(),
        Fixture::ALL.len(),
        "manifest and fixture enum disagree on how many fixtures there are"
    );
    for f in Fixture::ALL {
        assert!(m.entry(f).is_some(), "manifest has no entry for {f}");
    }
    for e in &m.fixtures {
        assert!(
            manifest::fixture_named(&e.id).is_some(),
            "manifest lists {:?}, which is not a known fixture id",
            e.id
        );
    }
    // No duplicate ids.
    let mut ids: Vec<&str> = m.fixtures.iter().map(|e| e.id.as_str()).collect();
    ids.sort_unstable();
    let before = ids.len();
    ids.dedup();
    assert_eq!(before, ids.len(), "manifest has duplicate fixture ids");
}

#[test]
fn manifest_paths_and_constants_resolve() {
    let m = manifest::manifest();
    for e in &m.fixtures {
        let f = manifest::fixture_named(&e.id).expect("known id");
        assert_eq!(e.file, f.file(), "manifest path for {} is stale", e.id);
        assert_eq!(
            e.r#const,
            manifest::const_name(f),
            "constant name for {}",
            e.id
        );
        let text = manifest::const_named(&e.r#const).unwrap_or_else(|| {
            panic!(
                "manifest names a constant that does not exist: {}",
                e.r#const
            )
        });
        // The constant must be the file's text, not a second copy that can rot.
        assert_eq!(
            text,
            f.wat(),
            "constant {} does not carry {}'s text",
            e.r#const,
            e.id
        );
    }
}

#[test]
fn manifest_and_code_agree_on_every_outcome() {
    let m = manifest::manifest();
    for f in Fixture::ALL {
        let e = m.entry(f).expect("entry");
        let from_code = f.expectation();
        match (from_code, m.expected_rejection(e)) {
            (Expectation::Accept, None) => {}
            (Expectation::Reject { code, at, .. }, Some((mcode, mat))) => {
                assert_eq!(code, mcode, "{}: expected code drifted", e.id);
                assert_eq!(at, mat, "{}: rejecting check drifted", e.id);
            }
            (from_code, from_manifest) => panic!(
                "{}: fixture expects {from_code:?} but the manifest says {from_manifest:?}",
                e.id
            ),
        }
        if let Expectation::Reject { code, at, .. } = from_code {
            assert_eq!(e.expected_code.as_deref(), Some(code), "entry {}", e.id);
            assert_eq!(e.rejected_at.as_deref(), Some(at), "entry {}", e.id);
            assert!(
                !code.is_empty() && !at.is_empty(),
                "entry {} must name a stable code and a check",
                e.id
            );
        } else {
            assert_eq!(e.expected_outcome, Outcome::Accept);
            assert!(e.expected_code.is_none() && e.rejected_at.is_none());
        }
        assert_eq!(e.intent, f.intent(), "entry {} intent drifted", e.id);
        assert_eq!(
            e.declared_package.as_deref(),
            f.declared_package(),
            "entry {} declared_package drifted",
            e.id
        );
    }
}

#[test]
fn only_the_valid_fixture_is_expected_to_load() {
    // Exactly one accept. If a second fixture ever flips to accept, a host-side
    // test would stop checking that the reject path rejects.
    let accepting: Vec<&Fixture> = Fixture::ALL
        .iter()
        .filter(|f| !f.expectation().is_reject())
        .collect();
    assert_eq!(
        accepting,
        vec![&Fixture::ValidProviderComponent],
        "more than one fixture is expected to load"
    );
    assert!(Fixture::ValidProviderComponent
        .expectation()
        .code()
        .is_none());
}

#[test]
fn every_expected_code_exists_in_the_shipped_error_registry() {
    // Every code a fixture expects must be a code the repo ships, or a host
    // test asserting on it would be asserting on a string nothing produces.
    // The manifest is not consulted here: `manifest_and_code_agree_on_every_outcome`
    // already proves the manifest says the same thing.
    let registry = include_str!("../../../schemas/error_codes.csv");
    for f in Fixture::ALL {
        let Some(code) = f.expectation().code() else {
            continue;
        };
        assert!(
            registry.lines().any(|l| l.starts_with(code)),
            "{} expects {code}, which is not in schemas/error_codes.csv",
            f.name()
        );
    }
}

#[test]
fn every_reject_fixture_reports_a_distinct_cause() {
    // The *reason* must be distinct, not the (code, check) pair. There are only
    // two host checks that can refuse a component, and four fixtures spread
    // across them on purpose: two cases through one check is a check being
    // tested twice, not one case being tested twice. The `why` is what
    // distinguishes them, so that is what has to be unique.
    let mut causes: Vec<(String, String, String)> = Fixture::ALL
        .iter()
        .filter_map(|f| match f.expectation() {
            Expectation::Reject { code, at, why } => {
                Some((code.to_string(), at.to_string(), why.to_string()))
            }
            Expectation::Accept => None,
        })
        .collect();
    let total = causes.len();
    assert!(total >= 2, "a corpus of one reject fixture proves nothing");
    causes.sort();
    causes.dedup();
    assert_eq!(causes.len(), total, "two fixtures share a rejection cause");

    // One check must report exactly one code. If `verify_component_package`
    // produced two different codes for two fixtures, a host test asserting on
    // the code could not tell which rule fired. Sharing a single code *across*
    // checks is correct and expected: all four are "this component is refused".
    let mut pairs: Vec<(String, String)> = Fixture::ALL
        .iter()
        .filter_map(|f| match f.expectation() {
            Expectation::Reject { code, at, .. } => Some((at.to_string(), code.to_string())),
            Expectation::Accept => None,
        })
        .collect();
    pairs.sort();
    let mut per_check: Vec<(String, String)> = Vec::new();
    for (at, code) in pairs {
        match per_check.iter_mut().find(|(seen, _)| *seen == at) {
            Some((_, seen_code)) => assert_eq!(
                *seen_code, code,
                "check {at} reports two different codes; a host test asserting \
                 on the code could not tell which rule fired"
            ),
            None => per_check.push((at, code)),
        }
    }
    assert_eq!(
        per_check.len(),
        2,
        "the corpus should exercise both host checks that can refuse a component"
    );
}

#[test]
fn derived_fixtures_differ_from_the_valid_one_only_where_intended() {
    // This is what makes a rejection attributable. If the wrong-package fixture
    // also had a broken body, a host test rejecting it would prove nothing
    // about the namespace check.
    let valid = significant_lines(Fixture::ValidProviderComponent.wat());
    for f in Fixture::ALL.into_iter().filter(|f| f.is_derived()) {
        let deviations = expected_deviations(f).expect("derived fixture");
        let other = significant_lines(f.wat());

        let mut valid_only: Vec<String> = valid
            .iter()
            .filter(|l| !other.contains(l))
            .cloned()
            .collect();
        let mut other_only: Vec<String> = other
            .iter()
            .filter(|l| !valid.contains(l))
            .cloned()
            .collect();
        valid_only.sort();
        other_only.sort();

        let mut expected_removed: Vec<String> = deviations
            .iter()
            .map(|(from, _)| (*from).to_string())
            .collect();
        let mut expected_added: Vec<String> = deviations
            .iter()
            .filter(|(_, to)| !to.is_empty())
            .map(|(_, to)| (*to).to_string())
            .collect();
        expected_removed.sort();
        expected_added.sort();

        assert_eq!(
            valid_only, expected_removed,
            "{f}: lines present in the valid fixture that this one should have kept"
        );
        assert_eq!(
            other_only, expected_added,
            "{f}: lines changed beyond the declared deviation"
        );
    }
}

#[test]
fn no_sandtree_exports_fixture_is_a_standalone_component() {
    // It is deliberately not a copy of the valid one, so it is checked on its
    // own terms: it must declare no package and export nothing SandTree-shaped.
    let f = Fixture::NoSandTreeExports;
    assert_eq!(f.declared_package(), None);
    assert_eq!(f.expected_exports(), &["ping"]);
    let text = f.wat();
    assert!(
        !text.contains("sandtree:plugin"),
        "the no-sandtree-exports fixture must not mention the SandTree ABI"
    );
    assert!(text.contains("(component"));
}

#[test]
fn interface_names_derive_back_to_the_declared_package() {
    // The fixtures' whole reject/accept split is decided by the package string
    // a host derives from an export name, so that derivation has to be right.
    assert_eq!(
        package_of("sandtree:plugin/lifecycle@1.0.0").as_deref(),
        Some("sandtree:plugin@1.0.0")
    );
    assert_eq!(
        package_of("evil:plugin/resource-provider@1.0.0").as_deref(),
        Some("evil:plugin@1.0.0")
    );
    // Not an interface export name at all: no package can be derived, and a
    // caller must not be handed a half-built string.
    assert_eq!(package_of("ping"), None);
    assert_eq!(package_of("sandtree:plugin/lifecycle"), None);
    assert_eq!(package_of("sandtree:plugin/lifecycle@"), None);
    assert_eq!(package_of(""), None);

    // And each fixture's declared package must equal what its own exports imply.
    for f in Fixture::ALL {
        let derived = f
            .expected_exports()
            .iter()
            .filter_map(|e| package_of(e))
            .next();
        match f.declared_package() {
            None => assert_eq!(
                derived,
                None,
                "{} claims no package but derives one",
                f.name()
            ),
            Some(p) => assert_eq!(
                derived.as_deref(),
                Some(p),
                "{} derives a different package",
                f.name()
            ),
        }
    }
}

#[test]
fn the_valid_fixture_exports_both_required_interfaces() {
    let v = Fixture::ValidProviderComponent;
    assert!(v
        .expected_exports()
        .contains(&crate::fixtures::LIFECYCLE_INTERFACE_1));
    assert!(v
        .expected_exports()
        .contains(&crate::fixtures::RESOURCE_PROVIDER_INTERFACE_1));
    assert!(v.wat().contains(crate::fixtures::LIFECYCLE_INTERFACE_1));
    assert!(v
        .wat()
        .contains(crate::fixtures::RESOURCE_PROVIDER_INTERFACE_1));
}

#[test]
fn reject_fixtures_drop_exactly_the_interface_they_are_about() {
    // Each reject fixture must fail for its stated reason, so the interface it
    // is "about" has to be the one it breaks.
    assert!(
        !Fixture::MissingRequiredExport
            .expected_exports()
            .contains(&crate::fixtures::RESOURCE_PROVIDER_INTERFACE_1),
        "missing-required-export must not export resource-provider"
    );
    assert!(
        Fixture::MissingRequiredExport
            .expected_exports()
            .contains(&crate::fixtures::LIFECYCLE_INTERFACE_1),
        "missing-required-export must still export lifecycle"
    );
    // A foreign package: every export moves, and the declared package is not
    // the accepted one. Nothing may be left behind under `sandtree:`, or the
    // fixture would be exercising a mixed-namespace component instead.
    let wrong = Fixture::WrongPackageName;
    assert!(wrong.declared_package().is_some());
    assert!(
        wrong
            .expected_exports()
            .iter()
            .all(|e| e.starts_with("evil:")),
        "wrong-package-name must export everything under the foreign namespace"
    );
    assert!(
        wrong
            .expected_exports()
            .iter()
            .all(|e| !e.starts_with("sandtree:")),
        "wrong-package-name must not also export under the accepted namespace"
    );

    // A version mismatch keeps the accepted namespace — that is the whole point
    // of the fixture — and differs only in a major the host does not support.
    // Asserting "nothing under sandtree:plugin" here would reject the only
    // fixture that can tell a bad version apart from a bad package.
    let supported = manifest::manifest().abi.supported_world_majors;
    let mism = Fixture::InterfaceVersionMismatch;
    assert!(mism.declared_package().is_some());
    for e in mism.expected_exports() {
        assert!(
            e.starts_with("sandtree:"),
            "{e} must keep the accepted namespace; a foreign one belongs to the other fixture"
        );
        let major: u64 = e
            .rsplit('@')
            .next()
            .unwrap_or_default()
            .split('.')
            .next()
            .unwrap_or_default()
            .parse()
            .unwrap_or_else(|_| panic!("{e} has no parseable major version"));
        assert!(
            !supported.contains(&major),
            "{e} is major {major}, which the host accepts"
        );
    }
}

#[test]
fn fixture_names_and_files_are_unique() {
    let mut names: Vec<&str> = Fixture::ALL.iter().map(|f| f.name()).collect();
    names.sort_unstable();
    let n = names.len();
    names.dedup();
    assert_eq!(n, names.len(), "duplicate fixture names");

    let mut files: Vec<&str> = Fixture::ALL.iter().map(|f| f.file()).collect();
    files.sort_unstable();
    let n = files.len();
    files.dedup();
    assert_eq!(n, files.len(), "duplicate fixture files");

    // Every fixture must end up with a readable, non-trivial source.
    for f in Fixture::ALL {
        assert!(
            f.wat().contains("(component"),
            "{} does not look like a component",
            f.name()
        );
        assert!(
            f.wat().lines().count() > 5,
            "{} is suspiciously short",
            f.name()
        );
    }
}
