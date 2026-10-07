//! Declarative JSON schema of a world fixture.
//!
//! Everything a [`super::ScriptedWorld`] can do is described here, in data. A
//! fixture is a plain serde value: no code, no closures, no clock. That is what
//! makes a failing control-plane regression reproducible from a file name.
//!
//! Enum spellings are accepted in both their wire form (`docker-runtime`,
//! `uses-image`) and their serde form (`docker_runtime`, `uses_image`), because
//! both appear in the shipped contracts and a fixture author should not have to
//! guess which one a field wants.
//!
//! Validation is strict on purpose: an ambiguous or self-contradicting fixture is
//! rejected at load time instead of producing a world whose behaviour depends on
//! which half of the contradiction was read first.

use std::collections::BTreeMap;
use std::path::Path;

use sandtree_model::error::{DomainError, ErrorCode};
use sandtree_model::operation::{OperationKind, OperationState};
use sandtree_model::resource::{RelationKind, ResourceKind, ResourceState};
use sandtree_sdk::manifest::PluginKind;
use sandtree_sdk::ports::ProviderHealth;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value as Json;

/// Fixture schema version understood by this crate.
///
/// A fixture declaring any other version is refused rather than
/// best-effort parsed: silently ignoring an unknown key is how a fake starts
/// lying about what it covers.
pub const FIXTURE_SCHEMA: u32 = 1;

/// Why a fixture could not be turned into a world.
#[derive(Debug, thiserror::Error)]
pub enum FixtureError {
    /// The fixture file could not be read.
    #[error("cannot read fixture {path}: {source}")]
    Io {
        /// Path as given by the caller.
        path: String,
        /// Underlying I/O failure.
        source: std::io::Error,
    },
    /// The fixture is not valid JSON, or a field has the wrong shape.
    #[error("fixture is not valid JSON: {0}")]
    Json(String),
    /// The fixture parsed but describes an impossible world.
    #[error("fixture field {field}: {reason}")]
    Invalid {
        /// Dotted path of the offending field, e.g. `resources[2].parent`.
        field: String,
        /// Why it is impossible.
        reason: String,
    },
    /// A declared error code is not in `schemas/error_codes.csv`.
    ///
    /// A fixture that invents `ST-FAKE-001` would make every assertion against
    /// it vacuous, because nothing outside this crate could ever produce it.
    #[error("error code {code:?} is not in the shipped error-code registry")]
    UnknownErrorCode {
        /// The offending code text.
        code: String,
    },
}

/// A complete world description.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorldFixture {
    /// Must equal [`FIXTURE_SCHEMA`].
    pub schema: u32,
    /// Human-readable statement of what this world is for.
    ///
    /// Mirrored in `mock/runtime/MANIFEST.json`; keeping it in the fixture means
    /// a copied fixture carries its own explanation.
    pub intent: String,
    /// Reverse-domain plugin name, e.g. `sandtree.provider.docker.mock`.
    ///
    /// The [`sandtree_model::id::PluginId`] is *derived* from this string, so the
    /// same name always yields the same identity.
    pub plugin: String,
    /// SemVer reported by [`sandtree_sdk::ports::ProviderDescriptor`].
    #[serde(default)]
    pub version: Option<String>,
    /// Provider role. Defaults to `Provider`.
    #[serde(default)]
    pub kind: Option<PluginKind>,
    /// Declared health. Defaults to `Healthy`.
    #[serde(default)]
    pub health: Option<ProviderHealth>,
    /// Code returned by every port call while `health` is `Unavailable`.
    #[serde(default)]
    pub unavailable_error: Option<ScriptedError>,
    /// Resources per discovery page. Defaults to all resources in one page.
    #[serde(default)]
    pub page_size: Option<usize>,
    /// The resources this world contains.
    #[serde(default)]
    pub resources: Vec<ResourceSpec>,
    /// Typed edges between them.
    #[serde(default)]
    pub relations: Vec<RelationSpec>,
    /// Fault injected into the middle of pagination.
    #[serde(default)]
    pub discover_fault: Option<DiscoverFault>,
    /// Per-operation scripted results, keyed by [`OperationKind::as_str`].
    #[serde(default)]
    pub operations: Vec<OperationSpec>,
    /// Files and directories inside resource workspaces.
    #[serde(default)]
    pub files: Vec<FileSpec>,
    /// Scripted command results.
    #[serde(default)]
    pub exec: Vec<ExecSpec>,
}

/// One resource in the world.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResourceSpec {
    /// Fixture-local handle, unique within the fixture.
    ///
    /// Stable across edits to the fixture, so relations, parents, VFS roots and
    /// exec rules all reference a key instead of a hashed id. This is also why
    /// the world does not need a clock to be diffable.
    pub key: String,
    /// Parts hashed into the resource identity.
    ///
    /// Mirrors `ResourceId::derive(endpoint_id + provider_native_id)`
    /// (DD-PLG §5): identity comes from provider-native state, never from the
    /// display name, so renaming a resource in the fixture does not change its id.
    pub id_parts: Vec<String>,
    /// Normalized kind.
    #[serde(deserialize_with = "de_resource_kind")]
    pub kind: ResourceKind,
    /// Display name. Never part of identity.
    pub name: String,
    /// Normalized state.
    #[serde(deserialize_with = "de_resource_state")]
    pub state: ResourceState,
    /// Key of the tree parent, if any.
    #[serde(default)]
    pub parent: Option<String>,
    /// Capabilities this resource declares (FR-061).
    ///
    /// An empty list means "no ceiling declared"; a non-empty list is a hard
    /// ceiling, exactly as the kernel treats it.
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Provider-specific non-secret metadata.
    #[serde(default)]
    pub metadata: BTreeMap<String, Json>,
    /// Fixed RFC3339 timestamp reported as `last_seen`.
    ///
    /// Required, and never defaulted: a fake that filled this in from the system
    /// clock would make every serialized snapshot differ between runs.
    pub last_seen: String,
    /// Subtree inside this resource that the VFS is allowed to serve.
    ///
    /// `None` means the whole resource root. Anything else confines every file
    /// operation to that subtree, which is how the escape-refusal path gets
    /// exercised without a real mount.
    #[serde(default)]
    pub vfs_root: Option<String>,
}

/// One typed edge between two resources (FR-004).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RelationSpec {
    /// Source resource key.
    pub from: String,
    /// Target resource key.
    pub to: String,
    /// Edge kind.
    #[serde(deserialize_with = "de_relation_kind")]
    pub kind: RelationKind,
    /// Non-secret edge metadata.
    #[serde(default)]
    pub metadata: BTreeMap<String, Json>,
}

/// A failure the provider returns verbatim.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScriptedError {
    /// Code from `schemas/error_codes.csv`.
    pub code: String,
    /// Human-facing message. Must not contain secrets (NFR-S03).
    pub message: String,
    /// Provider raw detail, carried but never parsed.
    #[serde(default)]
    pub detail: Option<String>,
}

impl ScriptedError {
    /// The validated stable code.
    pub fn error_code(&self) -> ErrorCode {
        // Validated at load time; `parse` cannot fail here.
        ErrorCode::parse(&self.code).unwrap_or(ErrorCode::CORE_INVALID)
    }

    /// Render as a [`DomainError`] for crossing a port boundary.
    pub fn to_domain_error(&self) -> DomainError {
        let mut err = DomainError::new(self.error_code(), self.message.clone());
        if let Some(detail) = &self.detail {
            err = err.with_detail(detail.clone());
        }
        err
    }
}

/// An error injected partway through pagination (fault mode 3).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DiscoverFault {
    /// Zero-based page index from which discovery starts failing.
    ///
    /// Pages below it succeed, so a test can assert that pages 0..N were
    /// delivered *before* the failure — the shape of a scan that dies halfway.
    pub fail_from_page: usize,
    /// The failure to return.
    pub error: ScriptedError,
}

/// A scripted result for one operation kind.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OperationSpec {
    /// [`OperationKind::as_str`], e.g. `start`.
    pub op: String,
    /// Terminal outcome to return.
    #[serde(default)]
    pub outcome: Option<OperationOutcomeSpec>,
    /// Hard failure to return instead of an outcome.
    #[serde(default)]
    pub error: Option<ScriptedError>,
}

/// Terminal outcome for a scripted operation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OperationOutcomeSpec {
    /// Job state.
    #[serde(deserialize_with = "de_operation_state")]
    pub state: OperationState,
    /// Stable code, required when `state` is `Failed`.
    #[serde(default)]
    pub code: Option<String>,
    /// Result payload (non-secret).
    #[serde(default)]
    pub result: Option<Json>,
}

/// One entry inside a resource workspace.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileSpec {
    /// Key of the resource owning this entry.
    pub root: String,
    /// Canonical path relative to the resource root.
    pub path: String,
    /// Whether this entry is a directory.
    #[serde(default)]
    pub is_dir: bool,
    /// File content, served only through `read`.
    ///
    /// Absent means the file exists with metadata but no body in the fixture:
    /// the lazy-content shape from FR-077.
    #[serde(default)]
    pub content: Option<String>,
    /// Size to report when there is no `content` to measure.
    #[serde(default)]
    pub size: Option<u64>,
    /// Modification time in nanoseconds since the Unix epoch.
    #[serde(default)]
    pub mtime_ns: Option<i128>,
    /// BLAKE3 digest, when one is already known.
    ///
    /// Declared, never computed: `list`/`stat` must not hash (FR-077).
    #[serde(default)]
    pub content_hash: Option<String>,
    /// Symlink target, stored raw so a fixture can express an escape.
    ///
    /// Raw on purpose: a target containing `..` is the thing under test, and
    /// normalizing it at load time would delete the scenario.
    #[serde(default)]
    pub symlink_target: Option<String>,
    /// Whether writes are refused for this entry and its children.
    #[serde(default)]
    pub read_only: bool,
}

/// One scripted command result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExecSpec {
    /// Resource key the rule applies to; `None` matches any resource.
    #[serde(default)]
    pub resource: Option<String>,
    /// Exact argv to match.
    pub argv: Vec<String>,
    /// Exit code. Defaults to `0`.
    #[serde(default)]
    pub exit_code: Option<i32>,
    /// Captured stdout.
    #[serde(default)]
    pub stdout: Option<String>,
    /// Captured stderr.
    #[serde(default)]
    pub stderr: Option<String>,
    /// Whether output was truncated at the provider cap.
    #[serde(default)]
    pub truncated: Option<bool>,
    /// Hard failure instead of an outcome.
    #[serde(default)]
    pub error: Option<ScriptedError>,
}

/// Wire spellings accepted for [`ResourceKind`].
const RESOURCE_KINDS: &[&str] = &[
    "host",
    "sandbox",
    "docker-runtime",
    "container",
    "image",
    "volume",
    "network",
    "compose-project",
    "compose-service",
    "workspace",
];

/// Wire spellings accepted for [`ResourceState`].
const RESOURCE_STATES: &[&str] = &[
    "unknown",
    "creating",
    "running",
    "stopped",
    "paused",
    "exited",
    "degraded",
    "destroying",
    "destroyed",
    "tombstoned",
];

/// Wire spellings accepted for [`OperationState`].
const OPERATION_STATES: &[&str] = &[
    "pending",
    "running",
    "succeeded",
    "failed",
    "cancelled",
    "interrupted",
];

/// Wire spellings accepted for [`RelationKind`].
const RELATION_KINDS: &[&str] = &[
    "uses-image",
    "mounts",
    "attached-network",
    "member-of-compose",
    "workspace-mount",
    "docker-in-sandbox",
];

/// Accept `docker-runtime` and `docker_runtime` alike.
fn de_resource_kind<'de, D: Deserializer<'de>>(d: D) -> Result<ResourceKind, D::Error> {
    let raw = String::deserialize(d)?;
    let wire = RESOURCE_KINDS
        .iter()
        .copied()
        .find(|k| accepted(&raw, k))
        .ok_or_else(|| serde::de::Error::custom(format!("unknown resource kind {raw:?}")))?;
    ResourceKind::all()
        .iter()
        .copied()
        .find(|c| c.as_str() == wire)
        .ok_or_else(|| serde::de::Error::custom(format!("kind {wire:?} has no enum variant")))
}

/// Accept both spellings of a wire name.
fn accepted(raw: &str, wire: &str) -> bool {
    raw == wire || raw == wire.replace('-', "_")
}

fn de_resource_state<'de, D: Deserializer<'de>>(d: D) -> Result<ResourceState, D::Error> {
    let raw = String::deserialize(d)?;
    RESOURCE_STATES
        .iter()
        .find(|s| **s == raw)
        .map(|s| ResourceState::from_wire(s))
        .ok_or_else(|| serde::de::Error::custom(format!("unknown resource state {raw:?}")))
}

fn de_operation_state<'de, D: Deserializer<'de>>(d: D) -> Result<OperationState, D::Error> {
    let raw = String::deserialize(d)?;
    OPERATION_STATES
        .iter()
        .find(|s| **s == raw)
        .map(|s| OperationState::from_wire(s))
        .ok_or_else(|| serde::de::Error::custom(format!("unknown operation state {raw:?}")))
}

fn de_relation_kind<'de, D: Deserializer<'de>>(d: D) -> Result<RelationKind, D::Error> {
    let raw = String::deserialize(d)?;
    let wire = RELATION_KINDS
        .iter()
        .copied()
        .find(|k| accepted(&raw, k))
        .ok_or_else(|| serde::de::Error::custom(format!("unknown relation kind {raw:?}")))?;
    RelationKind::from_wire(wire)
        .ok_or_else(|| serde::de::Error::custom(format!("relation kind {wire:?} has no variant")))
}

impl WorldFixture {
    /// Parse a fixture from JSON text.
    ///
    /// Structural validation (JSON shape) happens here; semantic validation
    /// (dangling parent keys, size contradictions, …) happens when the fixture
    /// is turned into a [`super::ScriptedWorld`].
    pub fn from_json_str(raw: &str) -> Result<Self, FixtureError> {
        serde_json::from_str(raw).map_err(|e| FixtureError::Json(e.to_string()))
    }

    /// Read and parse a fixture file.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, FixtureError> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path).map_err(|source| FixtureError::Io {
            path: path.display().to_string(),
            source,
        })?;
        Self::from_json_str(&text)
    }
}

impl ResourceSpec {
    /// The capability this resource declares for `op`, in wire form.
    ///
    /// The kernel builds `resource:<verb>` globally for every lifecycle verb
    /// (DD-SW §11), so a fixture declares `resource:start`, not `start`.
    pub fn capability_for(op: OperationKind) -> String {
        format!("resource:{}", op.as_str())
    }
}

/// Parse and validate the operation kind named by a fixture field.
pub fn parse_operation_kind(op: &str) -> Result<OperationKind, FixtureError> {
    OperationKind::from_wire(op).ok_or_else(|| FixtureError::Invalid {
        field: format!("operations[].op={op}"),
        reason: "not an OperationKind wire name".into(),
    })
}

/// Parse and validate one scripted error code.
pub fn parse_error_code(code: &str) -> Result<ErrorCode, FixtureError> {
    ErrorCode::parse(code).ok_or_else(|| FixtureError::UnknownErrorCode {
        code: code.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enum_fields_accept_both_wire_spellings() {
        // The fixture author must not have to guess whether a field wants the
        // hyphenated wire name or the serde name.
        let a: ResourceSpec = serde_json::from_str(
            r#"{"key":"k","id_parts":["a"],"kind":"docker-runtime","name":"d",
                "state":"running","last_seen":"2026-10-07T00:00:00Z"}"#,
        )
        .expect("hyphen form");
        assert_eq!(a.kind, ResourceKind::DockerRuntime);

        let b: ResourceSpec = serde_json::from_str(
            r#"{"key":"k","id_parts":["a"],"kind":"docker_runtime","name":"d",
                "state":"running","last_seen":"2026-10-07T00:00:00Z"}"#,
        )
        .expect("underscore form");
        assert_eq!(b.kind, ResourceKind::DockerRuntime);
        assert_eq!(a.kind, b.kind);
    }

    #[test]
    fn relation_kind_accepts_hyphen_form_and_rejects_rubbish() {
        let rel: RelationSpec =
            serde_json::from_str(r#"{"from":"a","to":"b","kind":"uses-image"}"#)
                .expect("hyphen form");
        assert_eq!(rel.kind, RelationKind::UsesImage);
        let bad =
            serde_json::from_str::<RelationSpec>(r#"{"from":"a","to":"b","kind":"uses_image"}"#)
                .unwrap_err();
        assert!(bad.to_string().contains("unknown relation kind"), "{bad}");
    }

    #[test]
    fn unknown_enum_values_are_rejected_not_defaulted() {
        // ResourceState::from_wire maps anything unknown to `Unknown`; a fixture
        // that typo'd a state would otherwise silently become `unknown`.
        let err = serde_json::from_str::<ResourceSpec>(
            r#"{"key":"k","id_parts":["a"],"kind":"container","name":"c",
                "state":"runing","last_seen":"2026-10-07T00:00:00Z"}"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown resource state"), "{err}");
    }

    #[test]
    fn fixture_round_trips_through_json() {
        let raw = r#"{
            "schema": 1,
            "intent": "round trip",
            "plugin": "sandtree.provider.mock",
            "resources": [{
                "key": "c1",
                "id_parts": ["ep", "c1"],
                "kind": "container",
                "name": "web",
                "state": "running",
                "capabilities": ["resource:start"],
                "metadata": {"endpoint_id": "ep-abc"},
                "last_seen": "2026-10-07T00:00:00Z"
            }],
            "relations": [{"from": "c1", "to": "c1", "kind": "mounts"}]
        }"#;
        let f = WorldFixture::from_json_str(raw).expect("parse");
        let text = serde_json::to_string(&f).expect("serialize");
        let again = WorldFixture::from_json_str(&text).expect("reparse");
        assert_eq!(f, again);
        assert_eq!(
            f.resources[0].capabilities,
            vec!["resource:start".to_string()]
        );
        assert_eq!(f.resources[0].metadata["endpoint_id"], Json::from("ep-abc"));
    }

    #[test]
    fn missing_file_is_reported_as_io_error() {
        let err = WorldFixture::from_path("definitely/not/here.json").unwrap_err();
        assert!(matches!(err, FixtureError::Io { .. }), "{err}");
    }

    #[test]
    fn error_codes_must_come_from_the_shipped_registry() {
        assert!(parse_error_code("ST-DKR-001").is_ok());
        let err = parse_error_code("ST-FAKE-001").unwrap_err();
        assert!(
            matches!(err, FixtureError::UnknownErrorCode { .. }),
            "{err}"
        );
    }

    #[test]
    fn operation_kinds_must_be_real() {
        assert_eq!(parse_operation_kind("start").unwrap(), OperationKind::Start);
        assert!(parse_operation_kind("frobnicate").is_err());
        assert_eq!(
            ResourceSpec::capability_for(OperationKind::Destroy),
            "resource:destroy"
        );
    }
}
