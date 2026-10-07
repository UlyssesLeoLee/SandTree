//! WIT-facing message types.
//!
//! The **public** plugin ABI is `schemas/sandtree_provider_v1.wit` +
//! `schemas/sandtree_observation_v1.wit`. Rust structs are *not* that ABI
//! (ADR-002). These types exist so that `plugin-host` can serialize across the
//! component boundary without inventing a second vocabulary, and so contract
//! tests can assert the two stay in sync.
//!
//! Every payload is a JSON string in WIT. Here they are typed, and the
//! conversion is explicit.

use sandtree_model::error::{DomainError, ErrorCode};
use sandtree_model::id::ResourceId;
use serde::{Deserialize, Serialize};
use serde_json::Value as Json;

/// WIT world/package identity implemented by this host.
pub const PROVIDER_PACKAGE: &str = "sandtree:plugin@1.0.0";
/// Observation package identity.
pub const OBSERVATION_PACKAGE: &str = "sandtree:observation@1.0.0";

/// Host major versions accepted in parallel (DD-PLG §11).
pub const SUPPORTED_WORLD_MAJORS: &[u64] = &[1];

/// `lifecycle.descriptor` record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitDescriptor {
    /// `plugin-id`
    pub plugin_id: String,
    /// `version`
    pub version: String,
    /// `state-schema-version`
    pub state_schema_version: u32,
}

/// `lifecycle.init` payload.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct WitInitConfig {
    /// `config-json`
    pub config: Json,
}

/// `resource-provider.discover` result.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct WitDiscoverResult {
    /// Opaque JSON payload from the component.
    pub json: Json,
    /// Optional continuation cursor.
    pub cursor: Option<String>,
}

/// Parse a WIT package string into `(namespace, name, version)`.
///
/// The namespace matters: `other:plugin@1.0.0` has the right interface name and
/// version but is a *different* ABI, and accepting it would let a component
/// declare an interface the host does not implement.
pub fn parse_package(s: &str) -> Option<(&str, &str, &str)> {
    let (body, version) = s.split_once('@')?;
    let (namespace, name) = body.split_once(':')?;
    if namespace.is_empty() || name.is_empty() || version.is_empty() {
        return None;
    }
    Some((namespace, name, version))
}

/// Major version of a WIT package version string.
pub fn major(version: &str) -> Option<u64> {
    version.split('.').next()?.parse().ok()
}

/// Whether this host accepts a component built against `package_version`.
pub fn accepts_world(package_version: &str) -> bool {
    match major(package_version) {
        Some(m) => SUPPORTED_WORLD_MAJORS.contains(&m),
        None => false,
    }
}

/// Validate a component's declared package against this host.
pub fn verify_component_package(package: &str) -> Result<(), DomainError> {
    let Some((namespace, name, version)) = parse_package(package) else {
        return Err(DomainError::new(
            ErrorCode::PLUGIN_MANIFEST_INVALID,
            format!("component package {package:?} is not `ns:name@version`"),
        ));
    };
    if namespace != "sandtree" {
        return Err(DomainError::new(
            ErrorCode::PLUGIN_MANIFEST_INVALID,
            format!("component namespace {namespace:?} is not `sandtree`"),
        ));
    }
    if name != "plugin" {
        return Err(DomainError::new(
            ErrorCode::PLUGIN_MANIFEST_INVALID,
            format!("component exports package {name:?}, expected `plugin`"),
        ));
    }
    if !accepts_world(version) {
        return Err(DomainError::new(
            ErrorCode::PLUGIN_MANIFEST_INVALID,
            format!("unsupported WIT world major {version}"),
        ));
    }
    Ok(())
}

/// Encode a WIT error string into a domain error, defaulting to `ST-PLG-002`
/// when the component did not supply a known code.
///
/// A component that returns an unknown code must not be able to invent a new
/// stable code: only codes in the shipped registry are accepted.
pub fn decode_component_error(raw: &str) -> DomainError {
    if let Some(code) = ErrorCode::parse(raw) {
        return DomainError::new(code, "plugin reported an error");
    }
    DomainError::new(ErrorCode::PLUGIN_HEALTH_FAILED, raw.to_string())
}

/// Build the resource id a component-observed file path must be normalized into.
pub fn stfs_resource_id(provider: &str, native: &str) -> ResourceId {
    ResourceId::derive(&[provider, native])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_accepts_known_world() {
        assert_eq!(
            parse_package(PROVIDER_PACKAGE),
            Some(("sandtree", "plugin", "1.0.0"))
        );
        assert!(accepts_world("1.0.0"));
        assert!(accepts_world("1.9.3"));
        assert!(!accepts_world("2.0.0"));
        assert!(!accepts_world("garbage"));
    }

    #[test]
    fn rejects_component_from_wrong_package() {
        assert!(verify_component_package(PROVIDER_PACKAGE).is_ok());
        assert!(verify_component_package(OBSERVATION_PACKAGE).is_err());
        assert!(verify_component_package("nonsense").is_err());
        assert!(verify_component_package("other:plugin@1.0.0").is_err());
    }

    #[test]
    fn unknown_component_error_cannot_invent_a_code() {
        let e = decode_component_error("ST-CORE-001");
        assert_eq!(e.code, ErrorCode::CORE_INVALID);
        let e2 = decode_component_error("totally-made-up");
        assert_eq!(e2.code, ErrorCode::PLUGIN_HEALTH_FAILED);
        assert_eq!(e2.message, "totally-made-up");
    }

    #[test]
    fn stfs_id_is_derived_from_provider_and_native_id() {
        let a = stfs_resource_id("sandtree.provider.docker", "abc123");
        let b = stfs_resource_id("sandtree.provider.docker", "abc123");
        let c = stfs_resource_id("sandtree.provider.docker-sandbox", "abc123");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
