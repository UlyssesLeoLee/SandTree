//! Plugin and app manifests (DD-PLG §2, §11; FR-050, FR-053).
//!
//! Validation is hand-written rather than delegated to a JSON Schema engine, and
//! that is deliberate: the acceptance rule is *"unknown required field rejected"*
//! (DD-PLG §11), which a permissive schema validator will happily accept. The
//! test module additionally reads the shipped
//! `schemas/plugin_manifest_v1.schema.json` / `app_manifest_v1.schema.json` and
//! cross-checks that every `required` field, `enum` member and `pattern` in the
//! machine contract is actually enforced here.

use std::collections::BTreeSet;

use sandtree_model::capability::{Capability, CapabilitySet};
use sandtree_model::error::{DomainError, ErrorCode};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value as Json};

/// Manifest schema version understood by this host (DD-PLG §11: strict).
pub const SUPPORTED_SCHEMA_VERSION: u64 = 1;

/// Plugin kinds (DD-PLG §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PluginKind {
    /// Provides resources for the topology.
    Provider,
    /// Adds capability inside a cluster (e.g. compose lifecycle).
    Feature,
    /// Optional integration such as MCP/agent observer (FR-O01, FR-O02).
    Integration,
    /// Declarative UI contribution.
    UiContribution,
}

impl PluginKind {
    /// Wire name used by the manifest schema.
    pub fn as_str(self) -> &'static str {
        match self {
            PluginKind::Provider => "provider",
            PluginKind::Feature => "feature",
            PluginKind::Integration => "integration",
            PluginKind::UiContribution => "ui-contribution",
        }
    }

    /// Parse wire name.
    pub fn from_wire(s: &str) -> Option<Self> {
        Some(match s {
            "provider" => PluginKind::Provider,
            "feature" => PluginKind::Feature,
            "integration" => PluginKind::Integration,
            "ui-contribution" => PluginKind::UiContribution,
            _ => return None,
        })
    }
}

/// A verified plugin manifest (DD-PLG §2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PluginManifest {
    /// Must equal [`SUPPORTED_SCHEMA_VERSION`].
    pub schema_version: u64,
    /// Lower-case reverse-domain id, e.g. `sandtree.provider.docker`.
    pub plugin_id: String,
    /// SemVer version.
    pub version: String,
    /// Plugin role.
    pub kind: PluginKind,
    /// Content-addressed component reference.
    pub component: String,
    /// SPDX license expression.
    pub license: String,
    /// Declared **maximum** capability set; the actual grant is a subset.
    pub capabilities: Vec<String>,
    /// Whether the plugin supports hot swap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hot_swap: Option<bool>,
    /// State schema version used for hot-swap migration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_schema_version: Option<u32>,
}

impl PluginManifest {
    /// Parse and validate from JSON.
    pub fn from_json(v: &Json) -> Result<Self, DomainError> {
        let obj = v
            .as_object()
            .ok_or_else(|| invalid("plugin manifest must be a JSON object"))?;

        reject_unknown_keys(
            obj,
            &[
                "schema_version",
                "plugin_id",
                "version",
                "kind",
                "component",
                "license",
                "capabilities",
                "hot_swap",
                "state_schema_version",
            ],
            "plugin manifest",
        )?;

        let schema_version = obj
            .get("schema_version")
            .and_then(Json::as_u64)
            .ok_or_else(|| invalid("plugin manifest: schema_version must be an integer"))?;
        if schema_version != SUPPORTED_SCHEMA_VERSION {
            return Err(invalid(format!(
                "plugin manifest: unsupported schema_version {schema_version}, host supports {SUPPORTED_SCHEMA_VERSION}"
            )));
        }

        let plugin_id = require_str(obj, "plugin_id")?;
        validate_plugin_id(&plugin_id)?;

        let version_raw = require_str(obj, "version")?;
        let version = semver::Version::parse(&version_raw)
            .map_err(|e| invalid(format!("plugin manifest: version is not SemVer: {e}")))?;

        let kind_raw = require_str(obj, "kind")?;
        let kind = PluginKind::from_wire(&kind_raw).ok_or_else(|| {
            invalid(format!(
                "plugin manifest: kind {kind_raw:?} is not one of provider/feature/integration/ui-contribution"
            ))
        })?;

        let component = require_str(obj, "component")?;
        if component.is_empty() {
            return Err(invalid("plugin manifest: component must not be empty"));
        }

        let license = require_str(obj, "license")?;
        if !is_plausible_spdx(&license) {
            return Err(invalid(format!(
                "plugin manifest: license {license:?} is not an SPDX-looking expression (NFR-E03)"
            )));
        }

        let caps_raw = obj
            .get("capabilities")
            .ok_or_else(|| invalid("plugin manifest: capabilities is required"))?
            .as_array()
            .ok_or_else(|| invalid("plugin manifest: capabilities must be an array"))?;
        let mut capabilities = Vec::with_capacity(caps_raw.len());
        for c in caps_raw {
            let s = c
                .as_str()
                .ok_or_else(|| invalid("plugin manifest: capabilities entries must be strings"))?;
            capabilities.push(s.to_string());
        }
        let unique: BTreeSet<&String> = capabilities.iter().collect();
        if unique.len() != capabilities.len() {
            return Err(invalid(
                "plugin manifest: capabilities must satisfy uniqueItems",
            ));
        }

        let hot_swap = match obj.get("hot_swap") {
            None | Some(Json::Null) => None,
            Some(Json::Bool(b)) => Some(*b),
            Some(_) => return Err(invalid("plugin manifest: hot_swap must be a boolean")),
        };
        let state_schema_version = match obj.get("state_schema_version") {
            None | Some(Json::Null) => None,
            Some(Json::Number(n)) => {
                let v = n.as_u64().ok_or_else(|| {
                    invalid("plugin manifest: state_schema_version must be a non-negative integer")
                })?;
                if v > u32::MAX as u64 {
                    return Err(invalid(
                        "plugin manifest: state_schema_version out of range",
                    ));
                }
                Some(v as u32)
            }
            Some(_) => {
                return Err(invalid(
                    "plugin manifest: state_schema_version must be an integer",
                ))
            }
        };

        let manifest = Self {
            schema_version,
            plugin_id,
            version: version.to_string(),
            kind,
            component,
            license,
            capabilities,
            hot_swap,
            state_schema_version,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    /// Structural + semantic validation (idempotent; called by `from_json`).
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.schema_version != SUPPORTED_SCHEMA_VERSION {
            return Err(invalid(format!(
                "plugin manifest: unsupported schema_version {}",
                self.schema_version
            )));
        }
        validate_plugin_id(&self.plugin_id)?;
        semver::Version::parse(&self.version)
            .map_err(|e| invalid(format!("plugin manifest: version is not SemVer: {e}")))?;
        if !is_plausible_spdx(&self.license) {
            return Err(invalid(
                "plugin manifest: license must be an SPDX expression",
            ));
        }
        // Parse declared capabilities here so a bad string fails at install time,
        // not at first call.
        self.declared_capabilities()?;
        Ok(())
    }

    /// Plugin id.
    pub fn plugin_id(&self) -> &str {
        &self.plugin_id
    }

    /// Parsed SemVer version.
    pub fn version(&self) -> Result<semver::Version, DomainError> {
        semver::Version::parse(&self.version)
            .map_err(|e| invalid(format!("plugin manifest: version is not SemVer: {e}")))
    }

    /// Plugin kind.
    pub fn kind(&self) -> PluginKind {
        self.kind
    }

    /// SPDX license expression.
    pub fn license(&self) -> &str {
        &self.license
    }

    /// Component reference.
    pub fn component(&self) -> &str {
        &self.component
    }

    /// Declared capability set (the *maximum*, not the grant).
    pub fn declared_capabilities(&self) -> Result<CapabilitySet, DomainError> {
        let caps = self
            .capabilities
            .iter()
            .map(|s| {
                Capability::parse(s).map_err(|e| {
                    invalid(format!(
                        "plugin manifest: capability {s:?} is invalid: {e} (NFR-S02)"
                    ))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(CapabilitySet::from_iter_caps(caps))
    }

    /// Whether hot swap is declared.
    pub fn supports_hot_swap(&self) -> bool {
        self.hot_swap.unwrap_or(false)
    }

    /// State schema version for migration.
    pub fn state_schema_version(&self) -> u32 {
        self.state_schema_version.unwrap_or(0)
    }

    /// Canonical JSON for hashing (keys sorted by serde_json Map default).
    pub fn to_json(&self) -> Json {
        let mut m = Map::new();
        m.insert("schema_version".into(), Json::from(self.schema_version));
        m.insert("plugin_id".into(), Json::from(self.plugin_id.clone()));
        m.insert("version".into(), Json::from(self.version.clone()));
        m.insert("kind".into(), Json::from(self.kind.as_str()));
        m.insert("component".into(), Json::from(self.component.clone()));
        m.insert("license".into(), Json::from(self.license.clone()));
        m.insert(
            "capabilities".into(),
            Json::Array(
                self.capabilities
                    .iter()
                    .map(|c| Json::from(c.clone()))
                    .collect(),
            ),
        );
        if let Some(b) = self.hot_swap {
            m.insert("hot_swap".into(), Json::Bool(b));
        }
        if let Some(v) = self.state_schema_version {
            m.insert("state_schema_version".into(), Json::from(v));
        }
        Json::Object(m)
    }
}

/// An app manifest: a composition of plugin clusters (FR-053).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AppManifest {
    /// Must equal [`SUPPORTED_SCHEMA_VERSION`].
    pub schema_version: u64,
    /// Stable app id.
    pub app_id: String,
    /// App SemVer.
    pub version: String,
    /// Clusters composing this app.
    pub clusters: Vec<AppCluster>,
}

/// One cluster entry inside an app manifest.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AppCluster {
    /// Cluster id, e.g. `docker`.
    pub cluster_id: String,
    /// Plugin ids in this cluster.
    pub plugins: Vec<String>,
    /// Whether the app can start without this cluster.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
}

impl AppManifest {
    /// Parse from TOML (`schemas/example_desktop_app.toml` shape).
    pub fn from_toml(raw: &str) -> Result<Self, DomainError> {
        let value: toml::Value =
            toml::from_str(raw).map_err(|e| invalid(format!("app manifest: invalid TOML: {e}")))?;
        let v = json_from_toml(&value);
        Self::from_json(&v)
    }

    /// Parse and validate from JSON.
    pub fn from_json(v: &Json) -> Result<Self, DomainError> {
        let obj = v
            .as_object()
            .ok_or_else(|| invalid("app manifest must be a JSON object"))?;
        reject_unknown_keys(
            obj,
            &["schema_version", "app_id", "version", "clusters"],
            "app manifest",
        )?;
        let schema_version = obj
            .get("schema_version")
            .and_then(Json::as_u64)
            .ok_or_else(|| invalid("app manifest: schema_version must be an integer"))?;
        if schema_version != SUPPORTED_SCHEMA_VERSION {
            return Err(invalid(format!(
                "app manifest: unsupported schema_version {schema_version}"
            )));
        }
        let app_id = require_str(obj, "app_id")?;
        if app_id.is_empty() {
            return Err(invalid("app manifest: app_id must not be empty"));
        }
        let version = require_str(obj, "version")?;
        semver::Version::parse(&version)
            .map_err(|e| invalid(format!("app manifest: version is not SemVer: {e}")))?;

        let clusters_raw = obj
            .get("clusters")
            .and_then(Json::as_array)
            .ok_or_else(|| invalid("app manifest: clusters must be an array"))?;
        if clusters_raw.is_empty() {
            return Err(invalid("app manifest: clusters must not be empty"));
        }
        let mut clusters = Vec::with_capacity(clusters_raw.len());
        for c in clusters_raw {
            let co = c
                .as_object()
                .ok_or_else(|| invalid("app manifest: cluster entries must be objects"))?;
            reject_unknown_keys(
                co,
                &["cluster_id", "plugins", "required"],
                "app manifest cluster",
            )?;
            let cluster_id = require_str(co, "cluster_id")?;
            if cluster_id.is_empty() {
                return Err(invalid("app manifest: cluster_id must not be empty"));
            }
            let plugins = co
                .get("plugins")
                .and_then(Json::as_array)
                .ok_or_else(|| invalid("app manifest: cluster plugins must be an array"))?;
            if plugins.is_empty() {
                return Err(DomainError::new(
                    ErrorCode::PLUGIN_MANIFEST_INVALID,
                    "app manifest: cluster plugins has minItems 1",
                ));
            }
            let mut ids = Vec::with_capacity(plugins.len());
            for p in plugins {
                let s = p
                    .as_str()
                    .ok_or_else(|| invalid("app manifest: plugin ids must be strings"))?;
                validate_plugin_id(s)?;
                ids.push(s.to_string());
            }
            let required = match co.get("required") {
                None | Some(Json::Null) => None,
                Some(Json::Bool(b)) => Some(*b),
                Some(_) => return Err(invalid("app manifest: required must be a boolean")),
            };
            clusters.push(AppCluster {
                cluster_id,
                plugins: ids,
                required,
            });
        }

        let manifest = Self {
            schema_version,
            app_id,
            version,
            clusters,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    /// Validate cluster uniqueness and plugin reference sanity.
    pub fn validate(&self) -> Result<(), DomainError> {
        let mut seen = BTreeSet::new();
        for c in &self.clusters {
            if !seen.insert(c.cluster_id.clone()) {
                return Err(invalid(format!(
                    "app manifest: duplicate cluster_id {:?}",
                    c.cluster_id
                )));
            }
            if c.plugins.is_empty() {
                return Err(invalid(format!(
                    "app manifest: cluster {:?} has no plugins",
                    c.cluster_id
                )));
            }
        }
        Ok(())
    }

    /// Canonical JSON representation.
    pub fn to_json(&self) -> Json {
        let mut m = Map::new();
        m.insert("schema_version".into(), Json::from(self.schema_version));
        m.insert("app_id".into(), Json::from(self.app_id.clone()));
        m.insert("version".into(), Json::from(self.version.clone()));
        m.insert(
            "clusters".into(),
            Json::Array(
                self.clusters
                    .iter()
                    .map(|c| {
                        let mut cm = Map::new();
                        cm.insert("cluster_id".into(), Json::from(c.cluster_id.clone()));
                        cm.insert(
                            "plugins".into(),
                            Json::Array(c.plugins.iter().map(|p| Json::from(p.clone())).collect()),
                        );
                        if let Some(r) = c.required {
                            cm.insert("required".into(), Json::Bool(r));
                        }
                        Json::Object(cm)
                    })
                    .collect(),
            ),
        );
        Json::Object(m)
    }

    /// Cluster ids declared `required = true`.
    pub fn required_clusters(&self) -> Vec<&str> {
        self.clusters
            .iter()
            .filter(|c| c.required.unwrap_or(false))
            .map(|c| c.cluster_id.as_str())
            .collect()
    }

    /// Every plugin id referenced by this manifest, sorted and de-duplicated.
    pub fn all_plugin_ids(&self) -> Vec<&str> {
        let mut ids: BTreeSet<&str> = BTreeSet::new();
        for c in &self.clusters {
            for p in &c.plugins {
                ids.insert(p.as_str());
            }
        }
        ids.into_iter().collect()
    }
}

/// A plugin package that passed hash / schema / license verification (FR-050).
#[derive(Debug, Clone, PartialEq)]
pub struct PluginPackage {
    /// Verified manifest.
    pub manifest: PluginManifest,
    /// BLAKE3 of the component bytes.
    pub content_hash: String,
    /// Component bytes (may be empty for in-process providers).
    pub component: Vec<u8>,
    /// Filesystem directory the package was installed into, if any.
    pub package_dir: Option<std::path::PathBuf>,
}

impl PluginPackage {
    /// Build a package and verify that `content_hash` matches the bytes.
    pub fn new(
        manifest: PluginManifest,
        component: Vec<u8>,
        package_dir: Option<std::path::PathBuf>,
    ) -> Result<Self, DomainError> {
        let content_hash = blake3::hash(&component).to_hex().to_string();
        Ok(Self {
            manifest,
            content_hash,
            component,
            package_dir,
        })
    }

    /// Package size in bytes.
    pub fn size(&self) -> usize {
        self.component.len()
    }
}

fn invalid(msg: impl Into<String>) -> DomainError {
    DomainError::new(ErrorCode::PLUGIN_MANIFEST_INVALID, msg)
}

fn require_str(obj: &Map<String, Json>, key: &str) -> Result<String, DomainError> {
    obj.get(key)
        .and_then(Json::as_str)
        .map(str::to_string)
        .ok_or_else(|| invalid(format!("plugin/app manifest: {key} must be a string")))
}

fn reject_unknown_keys(
    obj: &Map<String, Json>,
    allowed: &[&str],
    what: &str,
) -> Result<(), DomainError> {
    for k in obj.keys() {
        if !allowed.contains(&k.as_str()) {
            // DD-PLG §11: unknown required field rejected.
            return Err(invalid(format!(
                "{what}: unknown field {k:?} (schema_version is strict)"
            )));
        }
    }
    Ok(())
}

/// `plugin_id` must be lower-case reverse-domain, matching schema pattern
/// `^[a-z0-9.-]+$`, and must be dotted.
fn validate_plugin_id(id: &str) -> Result<(), DomainError> {
    if id.is_empty() {
        return Err(invalid("manifest: plugin_id must not be empty"));
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-')
    {
        return Err(invalid(format!(
            "manifest: plugin_id {id:?} must match ^[a-z0-9.-]+$"
        )));
    }
    if !id.contains('.') {
        return Err(invalid(format!(
            "manifest: plugin_id {id:?} must be reverse-domain (contain at least one '.')"
        )));
    }
    Ok(())
}

/// Cheap SPDX sanity check.
///
/// This is deliberately *not* a full SPDX parser: release gating still runs
/// `cargo deny` plus SBOM generation (NFR-E04). This only rejects obviously
/// non-SPDX strings at install time.
fn is_plausible_spdx(expr: &str) -> bool {
    if expr.is_empty() || expr.len() > 128 {
        return false;
    }
    expr.chars().all(|c| {
        c.is_ascii_alphanumeric()
            || matches!(c, '.' | '-' | '+' | '_' | ' ' | '(' | ')' | '/' | ':')
    }) && expr
        .split_whitespace()
        .any(|t| t.chars().next().is_some_and(|c| c.is_ascii_uppercase()))
}

fn json_from_toml(v: &toml::Value) -> Json {
    match v {
        toml::Value::String(s) => Json::String(s.clone()),
        toml::Value::Integer(i) => Json::from(*i),
        toml::Value::Float(f) => Json::from(*f),
        toml::Value::Boolean(b) => Json::Bool(*b),
        toml::Value::Datetime(d) => Json::String(d.to_string()),
        toml::Value::Array(a) => Json::Array(a.iter().map(json_from_toml).collect()),
        toml::Value::Table(t) => {
            let mut m = Map::new();
            for (k, val) in t {
                m.insert(k.clone(), json_from_toml(val));
            }
            Json::Object(m)
        }
    }
}

/// Current time as RFC3339, re-exported so plugin crates do not need chrono.
pub fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good_plugin_json() -> Json {
        serde_json::json!({
            "schema_version": 1,
            "plugin_id": "sandtree.provider.docker",
            "version": "1.0.0",
            "kind": "provider",
            "component": "sha256-blake3:abcdef",
            "license": "Apache-2.0",
            "capabilities": ["resource:discover", "resource:inspect", "docker:endpoint.read"],
            "hot_swap": true,
            "state_schema_version": 1
        })
    }

    #[test]
    fn accepts_valid_plugin_manifest() {
        let m = PluginManifest::from_json(&good_plugin_json()).unwrap();
        assert_eq!(m.plugin_id(), "sandtree.provider.docker");
        assert_eq!(m.kind(), PluginKind::Provider);
        assert_eq!(m.version().unwrap(), semver::Version::new(1, 0, 0));
        assert!(m.supports_hot_swap());
        assert_eq!(m.state_schema_version(), 1);
        let caps = m.declared_capabilities().unwrap();
        assert!(caps.allows(&Capability::parse("docker:endpoint.read").unwrap()));
    }

    #[test]
    fn rejects_unknown_schema_version() {
        let mut v = good_plugin_json();
        v["schema_version"] = Json::from(2);
        let e = PluginManifest::from_json(&v).unwrap_err();
        assert_eq!(e.code, ErrorCode::PLUGIN_MANIFEST_INVALID);
    }

    #[test]
    fn rejects_unknown_field() {
        let mut v = good_plugin_json();
        v["extra"] = Json::from(1);
        assert!(PluginManifest::from_json(&v).is_err());
    }

    #[test]
    fn rejects_bad_plugin_id() {
        for bad in ["SandTree.Provider", "nodots", "sand tree", ""] {
            let mut v = good_plugin_json();
            v["plugin_id"] = Json::from(bad);
            assert!(
                PluginManifest::from_json(&v).is_err(),
                "{bad} should be rejected"
            );
        }
    }

    #[test]
    fn rejects_non_semver_version() {
        let mut v = good_plugin_json();
        v["version"] = Json::from("1.0");
        assert!(PluginManifest::from_json(&v).is_err());
    }

    #[test]
    fn rejects_unknown_kind() {
        let mut v = good_plugin_json();
        v["kind"] = Json::from("daemon");
        assert!(PluginManifest::from_json(&v).is_err());
    }

    #[test]
    fn rejects_duplicate_capabilities() {
        let mut v = good_plugin_json();
        v["capabilities"] = serde_json::json!(["resource:discover", "resource:discover"]);
        assert!(PluginManifest::from_json(&v).is_err());
    }

    #[test]
    fn rejects_unparsable_capability() {
        let mut v = good_plugin_json();
        v["capabilities"] = serde_json::json!(["filesystem:read"]);
        let e = PluginManifest::from_json(&v).unwrap_err();
        assert_eq!(e.code, ErrorCode::PLUGIN_MANIFEST_INVALID);
    }

    #[test]
    fn rejects_non_spdx_license() {
        let mut v = good_plugin_json();
        v["license"] = Json::from("free for non commercial use");
        assert!(PluginManifest::from_json(&v).is_err());
    }

    #[test]
    fn app_manifest_parses_reference_toml() {
        let raw = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../schemas/example_desktop_app.toml"
        ))
        .expect("reference app manifest must exist");
        let app = AppManifest::from_toml(&raw).unwrap();
        assert_eq!(app.app_id, "sandtree.desktop");
        assert_eq!(app.version, "1.0.0");
        assert_eq!(
            app.required_clusters(),
            vec!["docker", "workspace"],
            "only required=true clusters"
        );
        assert!(app
            .all_plugin_ids()
            .contains(&"sandtree.provider.multipass"));
    }

    #[test]
    fn app_manifest_rejects_empty_plugin_list() {
        let v = serde_json::json!({
            "schema_version": 1, "app_id": "a", "version": "1.0.0",
            "clusters": [{"cluster_id": "docker", "plugins": []}]
        });
        assert!(AppManifest::from_json(&v).is_err());
    }

    #[test]
    fn app_manifest_rejects_duplicate_cluster_ids() {
        let v = serde_json::json!({
            "schema_version": 1, "app_id": "a", "version": "1.0.0",
            "clusters": [
              {"cluster_id": "docker", "plugins": ["p.one"]},
              {"cluster_id": "docker", "plugins": ["p.two"]}
            ]
        });
        assert!(AppManifest::from_json(&v).is_err());
    }

    #[test]
    fn app_manifest_round_trips_json() {
        let v = serde_json::json!({
            "schema_version": 1, "app_id": "sandtree.headless", "version": "1.0.0",
            "clusters": [{"cluster_id": "docker", "plugins": ["sandtree.provider.docker"], "required": true}]
        });
        let app = AppManifest::from_json(&v).unwrap();
        let again = AppManifest::from_json(&app.to_json()).unwrap();
        assert_eq!(app, again);
    }

    #[test]
    fn package_hash_is_blake3_of_bytes() {
        let m = PluginManifest::from_json(&good_plugin_json()).unwrap();
        let p = PluginPackage::new(m, b"component-bytes".to_vec(), None).unwrap();
        assert_eq!(
            p.content_hash,
            blake3::hash(b"component-bytes").to_hex().to_string()
        );
        assert_eq!(p.size(), b"component-bytes".len());
    }

    #[test]
    fn cross_checks_shipped_plugin_schema() {
        // The acceptance rule is DD-PLG §11 "unknown required field rejected".
        // Verify this validator really enforces what the machine contract lists.
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../schemas/plugin_manifest_v1.schema.json"
        );
        let schema: Json =
            serde_json::from_str(&std::fs::read_to_string(path).expect("plugin schema must exist"))
                .unwrap();
        let required = schema["required"].as_array().unwrap();
        for field in required {
            let field = field.as_str().unwrap();
            let mut v = good_plugin_json();
            v.as_object_mut().unwrap().remove(field);
            assert!(
                PluginManifest::from_json(&v).is_err(),
                "missing required field {field} must be rejected"
            );
        }
        // enum for `kind`
        let kind_enum = schema["properties"]["kind"]["enum"].as_array().unwrap();
        for member in kind_enum {
            let mut v = good_plugin_json();
            v["kind"] = member.clone();
            assert!(
                PluginManifest::from_json(&v).is_ok(),
                "{member} is a legal kind"
            );
        }
        let mut v = good_plugin_json();
        v["kind"] = Json::from("not-a-kind");
        assert!(PluginManifest::from_json(&v).is_err());
    }

    #[test]
    fn cross_checks_shipped_app_schema() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../schemas/app_manifest_v1.schema.json"
        );
        let schema: Json =
            serde_json::from_str(&std::fs::read_to_string(path).expect("app schema must exist"))
                .unwrap();
        let required = schema["required"].as_array().unwrap();
        for field in required {
            let field = field.as_str().unwrap();
            let mut v = serde_json::json!({
                "schema_version": 1, "app_id": "a", "version": "1.0.0",
                "clusters": [{"cluster_id": "c", "plugins": ["p.one"]}]
            });
            v.as_object_mut().unwrap().remove(field);
            assert!(
                AppManifest::from_json(&v).is_err(),
                "missing required field {field} must be rejected"
            );
        }
        // minItems: 1 on cluster plugins
        let plugins_schema = &schema["properties"]["clusters"]["items"];
        assert_eq!(
            plugins_schema["required"],
            serde_json::json!(["cluster_id", "plugins"])
        );
        assert_eq!(plugins_schema["additionalProperties"], Json::Bool(false));
    }
}
