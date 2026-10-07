//! `MANIFEST.json` — the table a host-side test drives.
//!
//! The manifest is deliberately *data*, not code: it names each fixture, the
//! outcome the plugin host must produce for it, and — where the fixture is a
//! deliberate deviation from the valid one — the single change that makes it
//! deviate. Nothing in the crate reads it to decide behaviour, so it cannot
//! silently disagree with reality; [`tests`] exists to prove it does not.
//!
//! # Why it is checked against the Rust enum
//!
//! [`crate::fixtures::Fixture`] carries the same intent in code. Two copies of
//! the same fact is exactly how a fixture corpus rots: a file gets renamed, the
//! Rust constant follows, and the manifest keeps pointing at the old path —
//! with nothing failing. So the manifest is cross-checked against both, in
//! both directions: every `Fixture` must appear, every manifest entry must
//! resolve to a `Fixture`, and the outcomes must agree.

use serde::Deserialize;

use crate::fixtures::{Expectation, Fixture};

/// The manifest as committed.
pub const MANIFEST_JSON: &str = include_str!("../MANIFEST.json");

/// ABI identity this corpus is written against.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Abi {
    /// The WIT package a provider component declares.
    pub package: String,
    /// The `lifecycle` interface export name.
    pub lifecycle_interface: String,
    /// The `resource-provider` interface export name.
    pub resource_provider_interface: String,
    /// World major versions this host accepts.
    pub supported_world_majors: Vec<u64>,
}

/// What the host must do with a fixture.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Outcome {
    /// Load it.
    Accept,
    /// Refuse it with this stable code from `schemas/error_codes.csv`.
    Reject {
        /// Stable error code.
        code: String,
        /// The check that must produce it.
        at: String,
    },
}

/// One manifest entry.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Entry {
    /// Matches [`Fixture::name`].
    pub id: String,
    /// Path relative to this crate's root.
    pub file: String,
    /// Name of the Rust constant holding the same text.
    pub r#const: String,
    /// The single change that makes this fixture deviate, if any.
    pub deviation: Option<String>,
    /// What this fixture exists to prove.
    pub intent: String,
    /// The package the component declares; `null` when it declares none.
    pub declared_package: Option<String>,
    /// Top-level export names.
    pub exports: Vec<String>,
    /// Required outcome.
    pub expected_outcome: Outcome,
    /// Stable error code for a reject, `null` for accept.
    #[serde(default)]
    pub expected_code: Option<String>,
    /// The check that must reject, `null` for accept.
    #[serde(default)]
    pub rejected_at: Option<String>,
    /// Set when the fixture cannot yet be compiled by a real engine, with why.
    #[serde(default)]
    pub blocked: Option<String>,
}

/// The whole manifest.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Manifest {
    /// Manifest format identifier.
    pub schema: String,
    /// ABI identity.
    pub abi: Abi,
    /// Prose notes.
    #[serde(default)]
    pub note: Vec<String>,
    /// One entry per fixture.
    pub fixtures: Vec<Entry>,
}

impl Manifest {
    /// The entry for a fixture, if the manifest lists it.
    pub fn entry(&self, fixture: Fixture) -> Option<&Entry> {
        self.fixtures.iter().find(|e| e.id == fixture.name())
    }

    /// The outcome the manifest requires, mapped onto [`Expectation`].
    ///
    /// This is the cross-check that matters: if `Fixture::expectation` and the
    /// manifest ever disagree, the two are describing different worlds and a
    /// host test driven by one would be asserting the wrong thing.
    pub fn expectation_of(&self, entry: &Entry) -> Expectation {
        match &entry.expected_outcome {
            Outcome::Accept => Expectation::Accept,
            Outcome::Reject { code, at } => Expectation::Reject {
                code,
                at,
                why: "",
            },
        }
    }
}

/// Parse [`MANIFEST_JSON`].
///
/// Panics on malformed JSON: the manifest is compiled into the crate, so a
/// syntax error is a build-time authoring mistake, not a runtime condition a
/// caller could handle.
pub fn manifest() -> Manifest {
    serde_json::from_str(MANIFEST_JSON).expect("MANIFEST.json parses")
}

/// The Rust constant a manifest entry names, resolved by name.
///
/// Written as a match over the known constant names rather than a lookup table
/// so that renaming a constant in [`crate::fixtures`] is a compile error here
/// instead of a silent mismatch discovered at test time.
pub const fn const_named(name: &str) -> Option<&'static str> {
    match name.as_bytes() {
        b"VALID_PROVIDER_COMPONENT_WAT" => Some(crate::fixtures::VALID_PROVIDER_COMPONENT_WAT),
        b"WRONG_PACKAGE_NAME_WAT" => Some(crate::fixtures::WRONG_PACKAGE_NAME_WAT),
        b"MISSING_REQUIRED_EXPORT_WAT" => Some(crate::fixtures::MISSING_REQUIRED_EXPORT_WAT),
        b"INTERFACE_VERSION_MISMATCH_WAT" => {
            Some(crate::fixtures::INTERFACE_VERSION_MISMATCH_WAT)
        }
        b"NO_SANDTREE_EXPORTS_WAT" => Some(crate::fixtures::NO_SANDTREE_EXPORTS_WAT),
        _ => None,
    }
}

/// Name of the Rust constant holding a fixture's text.
pub const fn const_name(fixture: Fixture) -> &'static str {
    match fixture {
        Fixture::ValidProviderComponent => "VALID_PROVIDER_COMPONENT_WAT",
        Fixture::WrongPackageName => "WRONG_PACKAGE_NAME_WAT",
        Fixture::MissingRequiredExport => "MISSING_REQUIRED_EXPORT_WAT",
        Fixture::InterfaceVersionMismatch => "INTERFACE_VERSION_MISMATCH_WAT",
        Fixture::NoSandTreeExports => "NO_SANDTREE_EXPORTS_WAT",
    }
}

/// Look a fixture up by manifest id.
pub fn fixture_named(id: &str) -> Option<Fixture> {
    Fixture::ALL.into_iter().find(|f| f.name() == id)
}
