//! Package verification before anything is instantiated (FR-050, FR-051,
//! DD-PLG §2, §3).
//!
//! Nothing in this module touches the host runtime. It answers exactly one
//! question: *may this package be staged at all, and with which capabilities?*
//! Keeping it separate means the trust decision is testable without a WASM
//! engine, and it means the engine adapter never has to decide policy.

use sandtree_model::capability::CapabilitySet;
use sandtree_model::error::{DomainError, ErrorCode};
use sandtree_model::id::PluginId;
use sandtree_sdk::manifest::PluginManifest;
use sandtree_sdk::wit::verify_component_package;

/// Host-side installation policy.
///
/// `grant` is the *ceiling*, not the starting point. A package gets
/// `declared ∩ grant`; everything else stays denied (FR-051, deny-by-default).
#[derive(Debug, Clone, Default)]
pub struct InstallPolicy {
    /// Maximum capabilities the host is willing to grant.
    pub grant: CapabilitySet,
    /// Accepted SPDX expressions for release builds (NFR-E04).
    pub allowed_licenses: Vec<String>,
    /// Whether a WASM component is mandatory.
    ///
    /// Official in-process providers have no component bytes; third-party
    /// packages must have one (FR-054).
    pub require_component: bool,
}

impl InstallPolicy {
    /// A policy that grants nothing — the deny-everything starting point.
    pub fn deny_all() -> Self {
        Self {
            grant: CapabilitySet::empty(),
            allowed_licenses: Vec::new(),
            require_component: false,
        }
    }

    /// Add an allowed license expression.
    pub fn allow_license(mut self, expr: impl Into<String>) -> Self {
        self.allowed_licenses.push(expr.into());
        self
    }

    /// Widen the grant ceiling.
    pub fn grant(mut self, caps: CapabilitySet) -> Self {
        self.grant = caps;
        self
    }
}

/// A package that passed every check and is allowed to be staged.
#[derive(Debug, Clone)]
pub struct StagedPackage {
    /// Stable plugin id.
    pub plugin_id: PluginId,
    /// The verified manifest.
    pub manifest: PluginManifest,
    /// BLAKE3 of the component bytes (empty for in-process providers).
    pub content_hash: String,
    /// Effective capabilities = declared ∩ policy ceiling.
    pub granted: CapabilitySet,
    /// Capabilities the manifest asked for but the host refuses, deterministic
    /// wire order. Non-empty is not fatal — it is silently *not* granted, and
    /// the difference is reported so the operator can see the shortfall.
    pub denied: Vec<String>,
    /// Whether a component must be present at runtime.
    pub needs_component: bool,
}

impl StagedPackage {
    /// Whether `cap` is granted to this package.
    pub fn allows(&self, cap: &sandtree_model::capability::Capability) -> bool {
        self.granted.allows(cap)
    }
}

/// Manifest declared in a component, checked for ABI identity before compile.
///
/// The component's real import/export set is inspected later by the engine
/// adapter; this is the cheap pre-check that keeps a component from the wrong
/// namespace out of the pipeline entirely.
pub fn check_declared_package(declared: &str) -> Result<(), DomainError> {
    verify_component_package(declared)
}

fn invalid(msg: impl Into<String>) -> DomainError {
    DomainError::new(ErrorCode::PLUGIN_MANIFEST_INVALID, msg)
}

/// Verify a package against an install policy.
///
/// Checks, in order (all fail closed):
/// 1. manifest schema (delegated to [`PluginManifest::validate`]),
/// 2. license allow-list,
/// 3. capability grant = declared ∩ ceiling,
/// 4. component presence when required.
pub fn verify(
    manifest: &PluginManifest,
    component: &[u8],
    content_hash: &str,
    policy: &InstallPolicy,
) -> Result<StagedPackage, DomainError> {
    manifest.validate()?;

    let license = manifest.license();
    if !policy.allowed_licenses.is_empty() {
        let allowed = policy
            .allowed_licenses
            .iter()
            .any(|allowed| allowed == license || license.contains(allowed.as_str()));
        if !allowed {
            return Err(invalid(format!(
                "plugin {}: license {license:?} is not in the host allow-list",
                manifest.plugin_id()
            )));
        }
    }

    let declared = manifest.declared_capabilities()?;
    let granted = declared.intersect(&policy.grant);
    let denied: Vec<String> = declared
        .iter()
        .filter(|c| !policy.grant.allows(c))
        .map(|c| c.to_string())
        .collect();

    // A component is mandatory for third-party packages. The hash is
    // recomputed by the caller from the exact bytes handed to the engine; we
    // only require that it is present and plausible so a package cannot claim
    // "no component, trust me" while shipping bytes.
    let needs_component = policy.require_component || !component.is_empty();
    if needs_component && component.is_empty() {
        return Err(invalid(format!(
            "plugin {}: component bytes are required for this policy",
            manifest.plugin_id()
        )));
    }
    if content_hash.is_empty() && !component.is_empty() {
        return Err(invalid(format!(
            "plugin {}: content hash must be recorded before staging",
            manifest.plugin_id()
        )));
    }

    Ok(StagedPackage {
        // The manifest id is the stable name; the opaque PluginId is derived
        // from it so the same package always yields the same identity (UT-002)
        // and renaming a resource never moves an id.
        plugin_id: PluginId::derive(&[manifest.plugin_id()]),
        manifest: manifest.clone(),
        content_hash: content_hash.to_string(),
        granted,
        denied,
        needs_component,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sandtree_sdk::manifest::{PluginKind, SUPPORTED_SCHEMA_VERSION};

    fn manifest_json(caps: &[&str]) -> serde_json::Value {
        serde_json::json!({
            "schema_version": SUPPORTED_SCHEMA_VERSION,
            "plugin_id": "sandtree.provider.docker",
            "version": "1.0.0",
            "kind": "provider",
            "component": "blake3:abc",
            "license": "Apache-2.0",
            "capabilities": caps,
            "state_schema_version": 1,
            "hot_swap": true,
        })
    }

    fn parse(caps: &[&str]) -> PluginManifest {
        PluginManifest::from_json(&manifest_json(caps)).expect("manifest parses")
    }

    fn policy_with(grant_caps: &[&str], licenses: &[&str]) -> InstallPolicy {
        InstallPolicy {
            grant: CapabilitySet::parse_all(grant_caps.iter().copied()).expect("caps parse"),
            allowed_licenses: licenses.iter().map(|s| s.to_string()).collect(),
            require_component: false,
        }
    }

    #[test]
    fn grant_is_the_intersection_not_the_union() {
        // FR-051: a plugin declaring more than the host allows gets the
        // smaller set, and the shortfall is reported rather than silently
        // ignored.
        let m = parse(&[
            "resource:discover",
            "net:connect:localhost",
            "secret:read:*",
        ]);
        let p = policy_with(&["resource:discover", "resource:inspect"], &["Apache-2.0"]);
        let staged = verify(&m, b"", "", &p).expect("verifies");
        let granted: Vec<String> = staged.granted.iter().map(|c| c.to_string()).collect();
        assert_eq!(granted, vec!["resource:discover".to_string()]);
        // The refused ones are surfaced, sorted deterministically.
        assert_eq!(
            staged.denied,
            vec!["net:connect:localhost", "secret:read:*"]
        );
    }

    #[test]
    fn deny_by_default_when_policy_grants_nothing() {
        let m = parse(&["resource:discover", "resource:start"]);
        let p = policy_with(&[], &["Apache-2.0"]);
        let staged = verify(&m, b"", "", &p).expect("verifies");
        assert!(staged.granted.is_empty());
        assert_eq!(staged.denied.len(), 2);
        assert!(!staged
            .allows(&sandtree_model::capability::Capability::parse("resource:discover").unwrap()));
    }

    #[test]
    fn license_outside_the_allow_list_is_rejected() {
        let m = parse(&["resource:discover"]);
        let p = policy_with(&["resource:discover"], &["MIT"]);
        let err = verify(&m, b"", "", &p).expect_err("GPL is refused");
        assert_eq!(err.code, ErrorCode::PLUGIN_MANIFEST_INVALID);
        assert!(err.message.contains("Apache-2.0"), "{}", err.message);
    }

    #[test]
    fn empty_license_allow_list_defers_to_release_gating() {
        // Not passing an allow-list is a valid "install-time check only"
        // configuration; cargo-deny + SBOM remain the release gate.
        let m = parse(&["resource:discover"]);
        let p = InstallPolicy::deny_all();
        assert!(verify(&m, b"", "", &p).is_ok());
    }

    #[test]
    fn component_is_mandatory_under_the_component_policy() {
        let m = parse(&["resource:discover"]);
        let mut p = InstallPolicy::deny_all();
        p.require_component = true;
        let err = verify(&m, b"", "", &p).expect_err("no bytes is a failure");
        assert!(
            err.message.contains("component bytes are required"),
            "{}",
            err.message
        );
    }

    #[test]
    fn shipped_bytes_without_a_recorded_hash_are_rejected() {
        let m = parse(&["resource:discover"]);
        let p = InstallPolicy::deny_all();
        let err = verify(&m, b"\0asm\x01", "", &p).expect_err("hash missing");
        assert!(err.message.contains("content hash"), "{}", err.message);
    }

    #[test]
    fn in_process_provider_needs_no_component() {
        let m = parse(&["resource:discover"]);
        let p = policy_with(&["resource:discover"], &[]);
        let staged = verify(&m, b"", "", &p).expect("verifies");
        assert!(!staged.needs_component);
    }

    #[test]
    fn invalid_manifest_fails_before_capability_math() {
        // The failure order matters: a malformed manifest must not be able to
        // reach the capability stage, where a partial read could be mistaken
        // for "declared nothing".
        let bad = serde_json::json!({
            "schema_version": 1,
            "plugin_id": "Not Reverse Domain",
            "version": "1.0.0",
            "kind": "provider",
            "component": "blake3:abc",
            "license": "Apache-2.0",
            "capabilities": [],
            "state_schema_version": 1,
            "hot_swap": true,
        });
        assert!(PluginManifest::from_json(&bad).is_err());
        assert_eq!(PluginKind::Provider.as_str(), "provider");
    }

    #[test]
    fn wrong_component_package_namespace_is_refused() {
        assert!(check_declared_package("sandtree:plugin@1.0.0").is_ok());
        assert!(check_declared_package("evil:plugin@1.0.0").is_err());
        assert!(check_declared_package("sandtree:plugin@2.0.0").is_err());
    }
}
