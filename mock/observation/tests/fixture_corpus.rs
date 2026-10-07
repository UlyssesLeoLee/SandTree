//! The shipped fixture corpus as a test asset.
//!
//! Two things are checked here that no in-memory fixture can check:
//!
//! 1. **the files exist, parse and validate** — a fixture that only exists in a
//!    unit test cannot be reused by `tests/integration` when the two fakes are
//!    consolidated (the whole point of the mock project);
//! 2. **they carry no host path and no credential** (NFR-S03, NFR-S06,
//!    NFR-S08). A fixture naming `C:\Users\...` or embedding a token would make
//!    the corpus machine-specific and unsafe to share, and a reviewer would have
//!    no way to tell by eye across a large corpus.

mod common;

use common::{forbidden_markers, loaded_fixtures, CREDENTIAL_MARKERS, HOST_PATH_MARKERS};
use sandtree_observation_model::{ObservationHealth, ObservationMode, TrustLevel};

/// The corpus is non-empty and every file in it loads and validates.
#[test]
fn every_shipped_fixture_loads_and_validates() {
    let files = common::fixture_files();
    assert!(
        !files.is_empty(),
        "the corpus is a deliverable; found {} files",
        files.len()
    );

    let fixtures = loaded_fixtures();
    assert_eq!(fixtures.len(), files.len(), "every file must load");
    for (stem, fixture) in &fixtures {
        fixture
            .validate()
            .unwrap_or_else(|e| panic!("{stem} must validate: {e}"));
        assert!(!fixture.is_empty(), "{stem} scripts no resources");
        assert_eq!(fixture.schema, sandtree_mock_observation::FIXTURE_SCHEMA);
        assert!(!fixture.source().trim().is_empty(), "{stem} has no source");
    }

    let total: usize = fixtures.iter().map(|(_, f)| f.len()).sum();
    assert!(
        total >= 8,
        "the corpus must carry a spread of worlds, found {total}"
    );
}

/// Every resource in the corpus is scriptable in every mode the design defines,
/// and the corpus names each of them at least once.
#[test]
fn the_corpus_covers_every_mode_health_and_trust_rung() {
    let fixtures = loaded_fixtures();
    let mut modes: Vec<&str> = Vec::new();
    let mut healths: Vec<&str> = Vec::new();
    let mut trusts: Vec<&str> = Vec::new();

    for (_, fixture) in &fixtures {
        for resource in fixture.resources() {
            for mode in resource.modes() {
                modes.push(mode.as_str());
            }
            healths.push(resource.health().as_str());
            trusts.push(resource.trust().as_str());
            // Ids are derived, so a resource name collision would silently
            // replace one world with another.
            assert!(
                !resource.resource_parts().is_empty(),
                "a resource must name itself"
            );
        }
    }

    for mode in [
        ObservationMode::Native,
        ObservationMode::Exec,
        ObservationMode::Probe,
        ObservationMode::Metadata,
    ] {
        assert!(
            modes.contains(&mode.as_str()),
            "no fixture uses mode {}; corpus has {modes:?}",
            mode.as_str()
        );
    }
    for health in [
        ObservationHealth::Healthy,
        ObservationHealth::Degraded,
        ObservationHealth::Stale,
    ] {
        assert!(
            healths.contains(&health.as_str()),
            "no fixture declares health {}; corpus has {healths:?}",
            health.as_str()
        );
    }
    // `Unavailable` is deliberately absent from that list: in a fixture it is
    // always the *result* of a fault, never a declared state, because "the
    // channel is down" and "here is data anyway" contradict each other. The
    // resulting snapshots are asserted in `faults.rs`.
    assert!(
        !healths.contains(&ObservationHealth::Unavailable.as_str()),
        "a fixture must not declare an unavailable channel while serving data: {healths:?}"
    );
    // Corpus worlds must exercise at least the guest-probe rung, since that is
    // the one ADR-OBS-003 is about.
    assert!(
        trusts.contains(&TrustLevel::GuestProbe.as_str()),
        "no fixture reports guest_probe; corpus has {trusts:?}"
    );
}

/// NFR-S03 / NFR-S06 / NFR-S08: no host path, no credential-shaped string.
#[test]
fn no_fixture_carries_a_host_path_or_a_credential() {
    let files = common::fixture_files();
    let mut scanned = 0usize;

    for path in &files {
        let text = std::fs::read_to_string(path).expect("fixture is readable");
        let findings = forbidden_markers(&text);
        assert!(
            findings.is_empty(),
            "{} must not contain {:?}",
            path.file_name().and_then(|n| n.to_str()).unwrap_or("?"),
            findings
        );
        scanned += 1;
    }
    assert_eq!(scanned, files.len(), "every fixture must be scanned");
    assert!(scanned >= 1, "the scan must have read something");
}

/// The scanner itself must still detect. Without this, the check above would
/// pass on a scanner that silently matches nothing — the same failure mode the
/// repo found in three removed "assertions" that verified nothing.
#[test]
fn the_hygiene_scanner_detects_what_it_claims_to() {
    // One violation per marker class, so a scanner that only looks at one of
    // them fails here. Each marker is written in the exact form the scanner
    // looks for: an earlier version of this test asserted `token=` while the
    // sample only contained the JSON form `"token":`, so the assertion failed
    // for a reason that had nothing to do with the scanner.
    let dirty = r#"{"path":"C:\\Users\\alice\\notes.txt","api_key":"k-1"} env_token=abc123"#;
    let findings = forbidden_markers(dirty);
    for expected in [":\\", "token=", "api_key"] {
        assert!(
            findings.contains(&expected.to_string()),
            "scanner missed {expected:?}: {findings:?}"
        );
    }

    // ...and a clean fixture-shaped document trips nothing, including one that
    // legitimately talks about a missing credential and a guest path escape.
    let clean = r#"{
        "reason": "instance key is not present in the credential store",
        "path": "../outside/taken.txt",
        "entries": ["workspace/src/main.rs", "workspace/README.md"]
    }"#;
    assert_eq!(
        forbidden_markers(clean),
        Vec::<String>::new(),
        "prose about an absent credential and a relative guest path is allowed"
    );

    // The marker lists are not empty, so the assertions above mean something.
    assert_eq!(CREDENTIAL_MARKERS.len(), 14);
    assert_eq!(HOST_PATH_MARKERS.len(), 6);
}

/// A relative traversal is the *subject* of the escape fixture, not a violation:
/// the corpus deliberately ships one so the refusal path has data to refuse.
#[test]
fn the_corpus_ships_exactly_one_path_escape_fixture() {
    let escapes: Vec<String> = loaded_fixtures()
        .into_iter()
        .flat_map(|(_, fixture)| {
            fixture
                .resources()
                .filter(|r| {
                    matches!(
                        r.fault(),
                        Some(sandtree_mock_observation::ObservationFault::GuestPathEscape { .. })
                    )
                })
                .map(|r| r.id().as_str().to_string())
                .collect::<Vec<String>>()
        })
        .collect();
    assert_eq!(
        escapes.len(),
        1,
        "exactly one world must exercise the path-escape refusal: {escapes:?}"
    );
}
