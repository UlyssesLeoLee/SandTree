//! Mode C Probe observation for Windows Sandbox (DD-PLG §12.4; FR-070, FR-079;
//! NFR-S07).
//!
//! Every value this module produces carries [`TrustLevel::GuestProbe`]. That is
//! the whole point: Windows Sandbox shares nothing with the host, so the host
//! cannot see inside it, and a probe is a program running inside the guest. A
//! payload whose BLAKE3 hash verifies is still `guest_probe`, because the guest
//! can produce a valid hash for a false claim (ADR-OBS-003).
//!
//! Consequently a probe snapshot is **never** security authoritative, and the
//! tests below assert exactly that.

use std::collections::BTreeMap;

use sandtree_model::id::ResourceId;
use sandtree_observation_model::{
    ObservationCapabilities, ObservationDomain, ObservationHealth, ObservationMode,
    ObservationSnapshot, ObservedValue, Provenance, TrustLevel,
};
use serde_json::Value as Json;

use crate::envelope::ProbeEnvelope;
use crate::SOURCE_PROBE;

/// Max envelopes merged into one snapshot, oldest-first wins per domain.
///
/// Bounds work done from guest-controlled input (DD-SW §12.3).
pub const MAX_ENVELOPES_PER_SESSION: usize = 32;

/// Declared capabilities for a Windows Sandbox instance.
///
/// Mode C Probe can return `system`, `process`, `filesystem` and `network`.
/// `docker` is only claimed when the guest reports a nested Engine, because a
/// probe that cannot see one must not advertise it (FR-078, RD §9).
pub fn sandbox_capabilities(has_nested_docker: bool) -> ObservationCapabilities {
    let mut probe_domains = vec![
        ObservationDomain::Filesystem,
        ObservationDomain::Network,
        ObservationDomain::Process,
        ObservationDomain::System,
    ];
    if has_nested_docker {
        probe_domains.push(ObservationDomain::Docker);
    }
    probe_domains.sort();

    let mut domains = BTreeMap::new();
    domains.insert(ObservationMode::Probe.as_str().to_string(), probe_domains);
    // DD-PLG §12.5 Mode D: metadata-only is always available, so the UI keeps
    // Control operations even when the probe is dead (FR-079).
    domains.insert(
        ObservationMode::Metadata.as_str().to_string(),
        vec![ObservationDomain::System],
    );

    ObservationCapabilities {
        modes: vec![ObservationMode::Probe, ObservationMode::Metadata],
        domains,
        max_concurrency: Some(2),
        requires_native_credential: false,
    }
}

/// Map an envelope domain name onto the shared vocabulary.
fn to_obs_domain(name: &str) -> Option<ObservationDomain> {
    ObservationDomain::from_wire(name)
}

/// Merge validated envelopes into a snapshot.
///
/// `envelopes` must already have passed [`crate::envelope::validate_envelope`];
/// this function only assembles. Later envelopes win per domain, and a domain
/// that appeared only in an older envelope is still surfaced.
pub fn snapshot_from_envelopes(
    resource_id: ResourceId,
    envelopes: &[ProbeEnvelope],
    requested: &[ObservationDomain],
    observed_at: &str,
) -> ObservationSnapshot {
    let mut snap = ObservationSnapshot::empty(
        resource_id,
        ObservationMode::Probe,
        ObservationHealth::Healthy,
        observed_at.to_string(),
    );
    if let Some(last) = envelopes.last() {
        snap.collector_version = Some(format!("probe/{}", last.sequence));
    }

    // CONTRACTS §6: iterate the sorted domain map so insertion order is stable.
    let mut merged: BTreeMap<String, Json> = BTreeMap::new();
    for env in envelopes.iter() {
        for (name, value) in &env.domains {
            merged.insert(name.clone(), value.clone());
        }
    }

    for (name, value) in merged {
        let Some(domain) = to_obs_domain(&name) else {
            // An unknown domain name is dropped rather than surfaced as-is.
            continue;
        };
        snap.insert(
            domain,
            ObservedValue::new(
                value,
                // Guest-reported, no matter how well-formed the envelope was.
                Provenance::new(SOURCE_PROBE, TrustLevel::GuestProbe, observed_at),
            ),
        );
    }

    for missing in snap.missing_domains(requested) {
        snap.warn(format!("domain {missing} was not reported by the probe"));
    }

    // Health domain is always emitted so the UI has a channel status.
    snap.insert(
        ObservationDomain::Health,
        ObservedValue::new(
            serde_json::json!({
                "status": if envelopes.is_empty() { "no-envelope" } else { "ok" },
                "envelopes_merged": envelopes.len(),
                "sequence": envelopes.last().map(|e| e.sequence),
            }),
            Provenance::new(SOURCE_PROBE, TrustLevel::GuestProbe, observed_at)
                .partial(envelopes.is_empty()),
        ),
    );

    let complete = requested.is_empty() || snap.covers_all(requested);
    snap.health = if envelopes.is_empty() {
        ObservationHealth::Unavailable
    } else if complete && snap.warnings.is_empty() {
        ObservationHealth::Healthy
    } else {
        ObservationHealth::Degraded
    };
    snap
}

/// The degraded snapshot for a sandbox whose probe never reported (FR-079).
///
/// The sandbox still exists; only its telemetry channel is down. `mode` records
/// what was expected.
pub fn unavailable_snapshot(
    resource_id: ResourceId,
    reason: impl Into<String>,
    observed_at: impl Into<String>,
) -> ObservationSnapshot {
    let reason = reason.into();
    let observed_at = observed_at.into();
    let mut snap = ObservationSnapshot::empty(
        resource_id,
        ObservationMode::Probe,
        ObservationHealth::Unavailable,
        observed_at,
    );
    snap.warn(reason);
    snap
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn rid() -> ResourceId {
        ResourceId::derive(&["windows-sandbox", "demo"])
    }

    fn env(sequence: u64, domains: serde_json::Map<String, Json>) -> ProbeEnvelope {
        ProbeEnvelope {
            schema: crate::envelope::ENVELOPE_SCHEMA.to_string(),
            sandbox_id: rid().as_str().to_string(),
            nonce: "n1".to_string(),
            sequence,
            observed_at: "2026-10-07T00:00:00Z".to_string(),
            payload_hash: String::new(),
            domains: domains.into_iter().collect(),
        }
    }

    #[test]
    fn capabilities_claim_probe_and_metadata_floor() {
        let caps = sandbox_capabilities(false);
        assert!(caps.supports(ObservationMode::Probe));
        assert!(caps.supports(ObservationMode::Metadata));
        assert!(!caps.supports(ObservationMode::Exec));
        let probe = caps.domains_in(ObservationMode::Probe);
        assert!(probe.contains(&ObservationDomain::System));
        assert!(probe.contains(&ObservationDomain::Filesystem));
        // Without a nested Engine, docker is not advertised.
        assert!(!probe.contains(&ObservationDomain::Docker));
    }

    #[test]
    fn nested_docker_is_advertised_only_when_the_guest_reports_one() {
        let caps = sandbox_capabilities(true);
        assert!(caps
            .domains_in(ObservationMode::Probe)
            .contains(&ObservationDomain::Docker));
    }

    #[test]
    fn probe_data_is_guest_probe_and_never_security_authoritative() {
        // ADR-OBS-003: this is the single most important assertion in the crate.
        let e = env(
            1,
            [("system".to_string(), json!({"os": "windows"}))]
                .into_iter()
                .collect(),
        );
        let snap = snapshot_from_envelopes(
            rid(),
            &[e],
            &[ObservationDomain::System],
            "2026-10-07T00:00:00Z",
        );
        let v = snap.get(ObservationDomain::System).unwrap();
        assert_eq!(v.provenance.trust, TrustLevel::GuestProbe);
        assert!(!v.provenance.trust.is_security_authoritative());
        // Every value in the snapshot, health included, is guest-probe.
        assert_eq!(snap.weakest_trust(), Some(TrustLevel::GuestProbe));
        assert!(!snap.is_security_authoritative());
    }

    #[test]
    fn a_full_envelope_set_yields_a_healthy_snapshot() {
        let e = env(
            3,
            [
                ("system".to_string(), json!({"os": "windows"})),
                ("process".to_string(), json!([{"pid": 1}])),
                ("filesystem".to_string(), json!({"entries": []})),
                ("network".to_string(), json!({"listeners": []})),
            ]
            .into_iter()
            .collect(),
        );
        let snap = snapshot_from_envelopes(
            rid(),
            &[e],
            &[
                ObservationDomain::System,
                ObservationDomain::Process,
                ObservationDomain::Filesystem,
                ObservationDomain::Network,
            ],
            "2026-10-07T00:00:00Z",
        );
        assert_eq!(snap.health, ObservationHealth::Healthy);
        assert_eq!(snap.mode, ObservationMode::Probe);
        assert_eq!(snap.collector_version.as_deref(), Some("probe/3"));
        assert!(snap.warnings.is_empty());
    }

    #[test]
    fn a_missing_domain_degrades_rather_than_failing() {
        let e = env(1, [("system".to_string(), json!({}))].into_iter().collect());
        let snap = snapshot_from_envelopes(
            rid(),
            &[e],
            &[ObservationDomain::System, ObservationDomain::Process],
            "2026-10-07T00:00:00Z",
        );
        assert_eq!(snap.health, ObservationHealth::Degraded);
        assert!(snap.warnings.iter().any(|w| w.contains("process")));
        assert!(snap.missing_domains(&[ObservationDomain::Process]) == vec!["process"]);
    }

    #[test]
    fn no_envelope_is_unavailable_not_an_error() {
        let snap = snapshot_from_envelopes(
            rid(),
            &[],
            &[ObservationDomain::System],
            "2026-10-07T00:00:00Z",
        );
        assert_eq!(snap.health, ObservationHealth::Unavailable);
        assert_eq!(snap.resource_id, rid());
        // Health is still present so the UI can render the channel state.
        assert!(snap.get(ObservationDomain::Health).unwrap().is_partial());
        assert!(snap.get(ObservationDomain::System).is_none());
    }

    #[test]
    fn later_envelopes_win_per_domain() {
        let first = env(
            1,
            [("system".to_string(), json!({"uptime_s": 10}))]
                .into_iter()
                .collect(),
        );
        let second = env(
            2,
            [("system".to_string(), json!({"uptime_s": 20}))]
                .into_iter()
                .collect(),
        );
        let snap = snapshot_from_envelopes(rid(), &[first, second], &[], "2026-10-07T00:00:00Z");
        assert_eq!(
            snap.get(ObservationDomain::System).unwrap().value["uptime_s"],
            20
        );
    }

    #[test]
    fn unknown_domain_names_are_dropped() {
        let e = env(
            1,
            [
                ("system".to_string(), json!({})),
                ("telepathy".to_string(), json!({"ok": true})),
            ]
            .into_iter()
            .collect(),
        );
        let snap = snapshot_from_envelopes(rid(), &[e], &[], "2026-10-07T00:00:00Z");
        // Only the two known domains are present (system + always-on health).
        assert_eq!(snap.values.len(), 2);
        assert!(snap.values.contains_key("system"));
        assert!(snap.values.contains_key("health"));
    }

    #[test]
    fn snapshot_values_are_sorted_for_byte_stability() {
        let e = env(
            1,
            [
                ("system".to_string(), json!({})),
                ("process".to_string(), json!({})),
                ("network".to_string(), json!({})),
            ]
            .into_iter()
            .collect(),
        );
        let snap = snapshot_from_envelopes(rid(), &[e], &[], "2026-10-07T00:00:00Z");
        let keys: Vec<&str> = snap.values.keys().map(String::as_str).collect();
        assert_eq!(keys, vec!["health", "network", "process", "system"]);
    }

    #[test]
    fn unavailable_snapshot_records_the_reason() {
        let snap = unavailable_snapshot(rid(), "probe never started", "2026-10-07T00:00:00Z");
        assert_eq!(snap.health, ObservationHealth::Unavailable);
        assert_eq!(snap.mode, ObservationMode::Probe);
        assert_eq!(snap.warnings, vec!["probe never started".to_string()]);
        assert!(snap.values.is_empty());
    }
}
