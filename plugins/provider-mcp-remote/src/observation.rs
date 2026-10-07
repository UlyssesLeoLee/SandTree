//! Snapshot assembly for the MCP endpoint channel (ADR-015).
//!
//! # Mode and trust
//!
//! Negotiated as [`ObservationMode::Probe`], at the same
//! [`TrustLevel::GuestProbe`] ceiling as the git channel. The endpoint is
//! inside the sandbox and answers whatever the sandbox decides to answer, so
//! nothing here may satisfy a security precondition (ADR-OBS-003).
//!
//! # What is recorded
//!
//! The `initialize` handshake result (protocol version, server identity,
//! advertised capabilities) and the tool inventory from `tools/list`. That is
//! the sandbox describing **its own exposed surface** — which is exactly the
//! thing a host cannot determine any other way when it is not allowed to
//! penetrate.
//!
//! # Integrity, not authenticity
//!
//! The payload's BLAKE3 hash goes into `Provenance::evidence_hash` so the same
//! tool inventory can be re-verified later. A sandbox can present a perfectly
//! valid hash for a tool list it invented, so the trust level does not move
//! (ADR-OBS-003).
//!
//! # Degradation is never absence
//!
//! A server that errors, times out or answers in an unexpected shape yields a
//! snapshot whose `health` says so. None of them produces an empty `Healthy`
//! snapshot — "the endpoint exposes no tools" and "the endpoint could not be
//! reached" are different facts (ADR-OBS-001).

use std::collections::BTreeMap;

use sandtree_model::id::ResourceId;
use sandtree_observation_model::{
    ObservationCapabilities, ObservationDomain, ObservationHealth, ObservationMode,
    ObservationSnapshot, ObservedValue, Provenance, TrustLevel,
};
use serde_json::{Map, Value as Json};

use crate::url::McpEndpointUrl;
use sandtree_policy::acquire::AcquisitionPermit;

/// Domain this channel fills. The MCP handshake describes what the sandbox
/// *is* and what it exposes, which is what `system` means in DD-OBS §5.
pub const DOMAIN: ObservationDomain = ObservationDomain::System;

/// Channel status, always returned alongside (DD-OBS §5, Health domain).
pub const HEALTH_DOMAIN: ObservationDomain = ObservationDomain::Health;

/// What the `initialize` handshake reported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpHandshake {
    /// Protocol revision the server agreed on.
    pub protocol_version: String,
    /// Server name from `serverInfo`.
    pub server_name: String,
    /// Server version from `serverInfo`.
    pub server_version: String,
    /// Capability keys the server advertised, sorted.
    pub capabilities: BTreeMap<String, Json>,
    /// Session id the server assigned, if any.
    pub session_id: Option<String>,
}

impl McpHandshake {
    /// Read a handshake out of an `initialize` result.
    ///
    /// Missing `serverInfo` or `protocolVersion` is an error rather than a
    /// default: guessing a version would put a fabricated number into a field
    /// an operator may act on (RD §9).
    pub fn from_result(result: &Json, session_id: Option<String>) -> Option<Self> {
        let protocol_version = result.get("protocolVersion")?.as_str()?.to_string();
        let info = result.get("serverInfo")?;
        let server_name = info.get("name")?.as_str()?.to_string();
        let server_version = info
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();

        let mut capabilities = BTreeMap::new();
        if let Some(Json::Object(map)) = result.get("capabilities") {
            for (k, v) in map {
                capabilities.insert(k.clone(), v.clone());
            }
        }

        Some(Self {
            protocol_version,
            server_name,
            server_version,
            capabilities,
            session_id,
        })
    }

    /// Whether the server advertised the `tools` capability.
    pub fn has_tools(&self) -> bool {
        self.capabilities.contains_key("tools")
    }
}

/// Read the tool inventory out of a `tools/list` result.
///
/// Tools are sorted by name so two servers exposing the same set produce the
/// same bytes (CONTRACTS §6).
pub fn parse_tool_list(result: &Json) -> Option<Vec<Json>> {
    let arr = result.get("tools")?.as_array()?;
    let mut tools: Vec<Json> = arr.clone();
    tools.sort_by_key(|t| {
        t.get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("")
            .to_string()
    });
    Some(tools)
}

/// Declared capabilities.
///
/// `probe` plus the metadata floor only: claiming `exec` or `native` would make
/// the negotiator select this provider for work it cannot do (DD-OBS §4).
pub fn mcp_capabilities() -> ObservationCapabilities {
    let mut domains = BTreeMap::new();
    domains.insert(
        ObservationMode::Probe.as_str().to_string(),
        vec![DOMAIN, HEALTH_DOMAIN],
    );
    domains.insert(
        ObservationMode::Metadata.as_str().to_string(),
        vec![ObservationDomain::System],
    );
    ObservationCapabilities {
        modes: vec![ObservationMode::Probe, ObservationMode::Metadata],
        domains,
        max_concurrency: None,
        requires_native_credential: false,
    }
}

/// Assemble the snapshot from a completed handshake and tool listing.
pub fn snapshot_from_session(
    resource_id: ResourceId,
    url: &McpEndpointUrl,
    permit: &AcquisitionPermit,
    handshake: &McpHandshake,
    tools: &[Json],
    observed_at: &str,
    partial: bool,
) -> ObservationSnapshot {
    let mut snap = ObservationSnapshot::empty(
        resource_id,
        ObservationMode::Probe,
        ObservationHealth::Healthy,
        observed_at.to_string(),
    );
    snap.collector_version = Some(format!(
        "sandtree-mcp-remote/{} (mcp {})",
        crate::PROVIDER_VERSION,
        handshake.protocol_version
    ));

    let tool_names: Vec<Json> = tools
        .iter()
        .filter_map(|t| t.get("name").and_then(|n| n.as_str()))
        .map(Json::from)
        .collect();

    let mut caps = Map::new();
    for (k, v) in &handshake.capabilities {
        caps.insert(k.clone(), v.clone());
    }

    let mut sys = Map::new();
    sys.insert("endpoint".to_string(), Json::String(url.endpoint_scope()));
    sys.insert("path".to_string(), Json::String(url.path().to_string()));
    sys.insert(
        "protocol_version".to_string(),
        Json::String(handshake.protocol_version.clone()),
    );
    sys.insert(
        "server_name".to_string(),
        Json::String(handshake.server_name.clone()),
    );
    sys.insert(
        "server_version".to_string(),
        Json::String(handshake.server_version.clone()),
    );
    sys.insert("capabilities".to_string(), Json::Object(caps));
    sys.insert("tool_count".to_string(), Json::from(tools.len()));
    sys.insert("tools".to_string(), Json::Array(tools.to_vec()));
    sys.insert("tool_names".to_string(), Json::Array(tool_names));

    snap.insert(
        DOMAIN,
        ObservedValue::new(
            Json::Object(sys),
            Provenance::new(
                crate::SOURCE_MCP_ENDPOINT,
                permit.trust_ceiling(),
                observed_at,
            )
            .with_evidence_hash(evidence_hash(handshake, tools))
            .partial(partial),
        ),
    );

    let mut health = Map::new();
    health.insert(
        "channel".to_string(),
        Json::String("mcp_endpoint".to_string()),
    );
    health.insert(
        "session_id_present".to_string(),
        Json::Bool(handshake.session_id.is_some()),
    );
    health.insert(
        "refusal_reason".to_string(),
        Json::String(format!("{:?}", permit.refusal_reason())),
    );
    snap.insert(
        HEALTH_DOMAIN,
        ObservedValue::new(
            Json::Object(health),
            Provenance::new(
                crate::SOURCE_MCP_ENDPOINT,
                permit.trust_ceiling(),
                observed_at,
            ),
        ),
    );

    snap
}

/// Hash over the whole observed payload.
///
/// The tool *schema* is included, not just the names: a sandbox could keep the
/// names identical and change what a tool does, and a hash that only covered
/// names would still verify.
fn evidence_hash(handshake: &McpHandshake, tools: &[Json]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(handshake.protocol_version.as_bytes());
    hasher.update(b"\0");
    hasher.update(handshake.server_name.as_bytes());
    hasher.update(b"\0");
    hasher.update(handshake.server_version.as_bytes());
    for (k, v) in &handshake.capabilities {
        hasher.update(b"cap:");
        hasher.update(k.as_bytes());
        hasher.update(b"=");
        hasher.update(v.to_string().as_bytes());
    }
    for t in tools {
        hasher.update(b"tool:");
        hasher.update(t.to_string().as_bytes());
    }
    hasher.finalize().to_hex().to_string()
}

/// The channel could not be used at all.
///
/// No values: this is what makes "we could not look" visibly different from
/// "there is nothing there" (ADR-OBS-001).
pub fn unavailable_snapshot(
    resource_id: ResourceId,
    reason: impl Into<String>,
    observed_at: &str,
) -> ObservationSnapshot {
    let mut snap = ObservationSnapshot::empty(
        resource_id,
        ObservationMode::Probe,
        ObservationHealth::Unavailable,
        observed_at.to_string(),
    );
    snap.warn(reason);
    snap
}

/// The channel answered but cannot answer this question.
pub fn degraded_snapshot(
    resource_id: ResourceId,
    reason: impl Into<String>,
    observed_at: &str,
) -> ObservationSnapshot {
    let mut snap = ObservationSnapshot::empty(
        resource_id,
        ObservationMode::Probe,
        ObservationHealth::Degraded,
        observed_at.to_string(),
    );
    snap.warn(reason);
    snap
}

/// The trust ceiling this module stamps on everything it produces.
pub const fn trust_ceiling() -> TrustLevel {
    sandtree_policy::acquire::NETWORK_TRUST_CEILING
}

#[cfg(test)]
mod tests {
    use super::*;
    use sandtree_model::capability::{Capability, CapabilitySet};
    use sandtree_policy::acquire::{
        AcquisitionChannel, AcquisitionPolicy, AcquisitionRequest, PenetrationVerdict,
        RefusalReason,
    };

    fn res() -> ResourceId {
        ResourceId::derive(&["sbx-mcp"])
    }

    fn permit() -> AcquisitionPermit {
        let req = AcquisitionRequest::new(
            res(),
            DOMAIN,
            AcquisitionChannel::McpEndpoint,
            "10.0.0.7:9443",
        );
        AcquisitionPolicy::new()
            .authorize(
                &CapabilitySet::from_iter_caps([
                    Capability::parse("net:connect:10.0.0.7:9443").unwrap()
                ]),
                &PenetrationVerdict::Refused {
                    domain: DOMAIN,
                    reason: RefusalReason::NoHostChannel,
                },
                &req,
            )
            .unwrap()
    }

    fn handshake() -> McpHandshake {
        McpHandshake::from_result(
            &serde_json::json!({
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {"listChanged": true}},
                "serverInfo": {"name": "sandbox-agent", "version": "0.4.1"}
            }),
            Some("sess-7".to_string()),
        )
        .unwrap()
    }

    fn tools() -> Vec<Json> {
        parse_tool_list(&serde_json::json!({
            "tools": [
                {"name": "zeta", "description": "later", "inputSchema": {"type": "object"}},
                {"name": "alpha", "description": "first", "inputSchema": {"type": "object"}}
            ]
        }))
        .unwrap()
    }

    fn url() -> McpEndpointUrl {
        McpEndpointUrl::parse("https://10.0.0.7:9443/mcp").unwrap()
    }

    #[test]
    fn the_snapshot_is_probe_mode_at_the_guest_probe_ceiling() {
        // Break by stamping ProviderNative: the snapshot then starts
        // satisfying destructive preconditions this channel can never support.
        let snap = snapshot_from_session(
            res(),
            &url(),
            &permit(),
            &handshake(),
            &tools(),
            "2026-10-07T00:00:00Z",
            false,
        );
        assert_eq!(snap.mode, ObservationMode::Probe);
        assert_eq!(snap.health, ObservationHealth::Healthy);
        assert_eq!(snap.weakest_trust(), Some(TrustLevel::GuestProbe));
        assert!(!snap.is_security_authoritative());
    }

    #[test]
    fn the_exposed_surface_reaches_the_snapshot_in_canonical_order() {
        // Break by preserving server order, and two servers exposing the same
        // tools produce two different snapshot byte streams.
        let snap = snapshot_from_session(
            res(),
            &url(),
            &permit(),
            &handshake(),
            &tools(),
            "2026-10-07T00:00:00Z",
            false,
        );
        let sys = &snap.get(DOMAIN).unwrap().value;
        assert_eq!(sys["server_name"], serde_json::json!("sandbox-agent"));
        assert_eq!(sys["protocol_version"], serde_json::json!("2025-06-18"));
        assert_eq!(sys["tool_names"], serde_json::json!(["alpha", "zeta"]));
        assert_eq!(sys["tool_count"], Json::from(2));
        assert!(sys["capabilities"]["tools"].is_object());
    }

    #[test]
    fn the_evidence_hash_changes_when_a_tool_schema_changes() {
        // The names stay identical; only the schema differs. A hash covering
        // names alone would still match, which is the bug this guards.
        let mut changed = tools();
        changed[0]["inputSchema"] = serde_json::json!({"type": "object", "properties": {"x": {}}});
        assert_ne!(
            evidence_hash(&handshake(), &tools()),
            evidence_hash(&handshake(), &changed),
            "a rewritten tool schema must change the evidence hash"
        );
    }

    #[test]
    fn a_handshake_missing_required_fields_is_refused_not_defaulted() {
        // RD §9: filling in a plausible server name would be inventing state.
        for bad in [
            serde_json::json!({"capabilities": {}, "serverInfo": {"name": "s", "version": "1"}}),
            serde_json::json!({"protocolVersion": "2025-06-18", "serverInfo": {"version": "1"}}),
            serde_json::json!({"protocolVersion": "2025-06-18", "capabilities": {}}),
        ] {
            assert!(
                McpHandshake::from_result(&bad, None).is_none(),
                "{bad} must not produce a handshake"
            );
        }
    }

    #[test]
    fn a_tool_list_that_is_not_a_list_is_refused() {
        assert!(parse_tool_list(&serde_json::json!({"tools": {}})).is_none());
        assert!(parse_tool_list(&serde_json::json!({})).is_none());
    }

    #[test]
    fn a_server_with_no_tools_is_reported_as_zero_not_as_a_failure() {
        // The distinction the module exists to preserve: an empty tool list is a
        // successful read of a sandbox that exposes nothing.
        let snap = snapshot_from_session(
            res(),
            &url(),
            &permit(),
            &handshake(),
            &[],
            "2026-10-07T00:00:00Z",
            false,
        );
        assert_eq!(snap.health, ObservationHealth::Healthy);
        assert_eq!(snap.get(DOMAIN).unwrap().value["tool_count"], Json::from(0));
    }

    #[test]
    fn an_unavailable_channel_carries_no_values_and_fails_the_policy_gate() {
        // ADR-OBS-001.
        let snap = unavailable_snapshot(res(), "endpoint refused", "2026-10-07T00:00:00Z");
        assert_eq!(snap.health, ObservationHealth::Unavailable);
        assert!(snap.values.is_empty());
        assert!(sandtree_policy::TrustPolicy::new()
            .check_destructive_precondition(&snap)
            .is_err());
    }

    #[test]
    fn the_declared_capabilities_do_not_claim_native_or_exec() {
        let caps = mcp_capabilities();
        assert!(!caps.supports(ObservationMode::Native));
        assert!(!caps.supports(ObservationMode::Exec));
        assert!(caps.supports(ObservationMode::Probe));
    }

    #[test]
    fn the_snapshot_is_byte_stable_for_the_same_session() {
        let a = snapshot_from_session(
            res(),
            &url(),
            &permit(),
            &handshake(),
            &tools(),
            "2026-10-07T00:00:00Z",
            false,
        );
        let b = snapshot_from_session(
            res(),
            &url(),
            &permit(),
            &handshake(),
            &tools(),
            "2026-10-07T00:00:00Z",
            false,
        );
        assert_eq!(
            serde_json::to_string(&a).unwrap(),
            serde_json::to_string(&b).unwrap()
        );
    }
}
