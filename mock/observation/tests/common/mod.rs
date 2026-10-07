//! Shared helpers for the Lane B integration tests.
//!
//! Kept in one place so the corpus assertions in different test files cannot
//! drift apart: they all load the same files through the same loader.
//!
//! `#![allow(dead_code)]`: each test binary compiles this module separately and
//! uses a different subset of it, so unused helpers here are expected rather
//! than a mistake.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

use sandtree_mock_observation::{ObservationFixture, ScriptedObservation};

/// `mock/fixtures`, found relative to this crate's manifest.
///
/// `CARGO_MANIFEST_DIR` is fixed at compile time, so the path is deterministic
/// and independent of the working directory a test is run from.
pub fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("mock/observation has a parent directory")
        .join("fixtures")
}

/// Every shipped `observation-*.json` fixture, sorted by file name.
pub fn fixture_files() -> Vec<PathBuf> {
    let dir = fixtures_dir();
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()))
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|path| {
            path.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with("observation-") && n.ends_with(".json"))
                .unwrap_or(false)
        })
        .collect();
    files.sort();
    assert!(
        !files.is_empty(),
        "no observation-*.json found in {}; the corpus is part of the deliverable",
        dir.display()
    );
    files
}

/// Every shipped fixture, as `(file stem, parsed fixture)`, sorted by file name.
pub fn loaded_fixtures() -> Vec<(String, ObservationFixture)> {
    fixture_files()
        .into_iter()
        .map(|path| {
            let stem = path
                .file_stem()
                .and_then(|s| s.to_str())
                .expect("fixture file name")
                .to_string();
            let fixture = ObservationFixture::from_path(&path)
                .unwrap_or_else(|e| panic!("{} must load and validate: {e}", path.display()));
            (stem, fixture)
        })
        .collect()
}

/// A provider built from one shipped fixture file.
pub fn provider_from(stem: &str) -> ScriptedObservation {
    let path = fixtures_dir().join(format!("{stem}.json"));
    ScriptedObservation::from_path(&path)
        .unwrap_or_else(|e| panic!("{} must load: {e}", path.display()))
}

/// The scenario corpus, the fixture file that carries the named worlds.
pub const SCENARIOS: &str = "observation-scenarios";

/// A fixture resource id from its name parts.
pub fn id(parts: &[&str]) -> sandtree_model::id::ResourceId {
    sandtree_model::id::ResourceId::derive(parts)
}

/// A resource id for one of the scripted scenario worlds.
pub fn scenario_id(name: &str) -> sandtree_model::id::ResourceId {
    id(&["mock", name])
}

/// Strings that must never appear in a fixture payload (NFR-S03, NFR-S08).
///
/// Naming an *absent* credential is allowed — `credential_denied` faults have to
/// say what is missing — so the ban is on credential-shaped values, not on the
/// word.
pub const CREDENTIAL_MARKERS: [&str; 14] = [
    "password",
    "passwd",
    "secret",
    "api_key",
    "apikey",
    "private_key",
    "authorization:",
    "bearer ",
    "token=",
    // JSON-key shapes, which is how a credential would actually appear in a
    // fixture file rather than on a command line.
    "\"token\":",
    "\"password\":",
    "access_token",
    "refresh_token",
    "-----begin",
];

/// Host-path shapes a fixture must not contain.
///
/// Guest payloads carry *relative* paths only; a host-root or drive-qualified
/// path in a fixture would let a test assert against the build machine's
/// filesystem instead of the scripted world (NFR-S06, NFR-S08).
pub const HOST_PATH_MARKERS: [&str; 6] = [":\\", ":/", "\\\\", "/root/", "/home/", "program files"];

/// Every forbidden marker found in `text`, lower-cased.
///
/// Returned rather than asserted on so the caller decides whether a finding is
/// fatal, which also lets the tests prove the scanner itself still detects.
pub fn forbidden_markers(text: &str) -> Vec<String> {
    let lowered = text.to_ascii_lowercase();
    CREDENTIAL_MARKERS
        .iter()
        .chain(HOST_PATH_MARKERS.iter())
        .filter(|marker| lowered.contains(**marker))
        .map(|marker| marker.to_string())
        .collect()
}
