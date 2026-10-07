//! Mode B Exec observation for Multipass (DD-PLG §12.3; FR-070, FR-079;
//! NFR-S08).
//!
//! Multipass exposes guest state only by running a command, so this provider
//! negotiates [`ObservationMode::Exec`] and labels everything it produces
//! [`TrustLevel::RemoteExec`]. It never claims `HostNative`: the host cannot see
//! inside a VM, and pretending otherwise would let policy satisfy a security
//! precondition from data the host never observed (ADR-OBS-003).

use sandtree_model::id::ResourceId;
use sandtree_observation_model::{
    ObservationCapabilities, ObservationDomain, ObservationHealth, ObservationMode,
    ObservationSnapshot, ObservedValue, Provenance, TrustLevel,
};
use serde_json::{Map, Value as Json};

use crate::parse::{CollectorDomain, CollectorReport};
use crate::SOURCE_MULTIPASS_EXEC;

/// Declared observation capabilities for a Multipass instance.
///
/// Mode B Exec can collect `system`, `process`, `filesystem` and `network`
/// through the collector. `docker` is *not* claimed here: nested Docker
/// inventory inside a Multipass instance would need a second hop, and claiming
/// it here would make the negotiator select a collection this provider does not
/// actually perform (DD-OBS §4).
pub fn multipass_capabilities() -> ObservationCapabilities {
    let exec_domains = vec![
        ObservationDomain::Filesystem,
        ObservationDomain::Network,
        ObservationDomain::Process,
        ObservationDomain::System,
    ];
    let mut domains = std::collections::BTreeMap::new();
    domains.insert(
        ObservationMode::Exec.as_str().to_string(),
        exec_domains.clone(),
    );
    // DD-PLG §12.5 Mode D: metadata-only is always the floor.
    domains.insert(
        ObservationMode::Metadata.as_str().to_string(),
        vec![ObservationDomain::System],
    );

    ObservationCapabilities {
        modes: vec![ObservationMode::Exec, ObservationMode::Metadata],
        domains,
        max_concurrency: None,
        requires_native_credential: false,
    }
}

/// Build the `system` domain from a collector's system payload.
///
/// Trust is fixed to `RemoteExec`: the value was produced by a command the host
/// ran inside the guest, and no amount of payload integrity checking changes
/// that (ADR-OBS-003).
pub fn system_domain_from_collector(
    payload: &Json,
    observed_at: &str,
    partial: bool,
) -> ObservedValue {
    // Only an object payload is meaningful; anything else is dropped rather
    // than coerced (RD §9).
    let value = match payload {
        Json::Object(_) => payload.clone(),
        _ => Json::Object(Map::new()),
    };
    ObservedValue::new(
        value,
        Provenance::new(SOURCE_MULTIPASS_EXEC, TrustLevel::RemoteExec, observed_at)
            .partial(partial),
    )
}

/// Assemble a snapshot from a parsed [`CollectorReport`].
///
/// `requested` drives completeness. A domain the collector marked partial is
/// inserted with `partial = true` so the UI can show it as incomplete rather
/// than either hiding it or presenting it as whole (DD-PLG §12.3).
pub fn snapshot_from_report(
    resource_id: ResourceId,
    report: &CollectorReport,
    requested: &[CollectorDomain],
    observed_at: &str,
) -> ObservationSnapshot {
    let mut snap = ObservationSnapshot::empty(
        resource_id,
        ObservationMode::Exec,
        ObservationHealth::Healthy,
        observed_at.to_string(),
    );
    snap.collector_version = Some("sandtree-collector/1".to_string());

    for (name, payload) in &report.domains {
        let Some(domain) = CollectorDomain::from_wire(name) else {
            continue;
        };
        let is_partial = report.partial.iter().any(|p| p == name);
        let value = match domain {
            CollectorDomain::System
            | CollectorDomain::Process
            | CollectorDomain::Filesystem
            | CollectorDomain::Network => ObservedValue::new(
                payload.clone(),
                Provenance::new(SOURCE_MULTIPASS_EXEC, TrustLevel::RemoteExec, observed_at)
                    .partial(is_partial),
            ),
            // Health is provider-reported about the collection itself, so it is
            // still `remote_exec` — it came back over the same guest command.
            CollectorDomain::Health => ObservedValue::new(
                payload.clone(),
                Provenance::new(SOURCE_MULTIPASS_EXEC, TrustLevel::RemoteExec, observed_at)
                    .partial(is_partial),
            ),
            // Nested docker is not claimed; if it ever appears it is surfaced
            // verbatim rather than re-interpreted.
            CollectorDomain::Docker => ObservedValue::new(
                payload.clone(),
                Provenance::new(SOURCE_MULTIPASS_EXEC, TrustLevel::RemoteExec, observed_at)
                    .partial(true),
            ),
        };
        snap.insert(to_obs_domain(domain), value);
    }

    for name in &report.partial {
        snap.warn(format!("domain {name} is partial"));
    }
    for e in &report.errors {
        snap.warn(e.clone());
    }
    for missing in snap.missing_domains(
        &requested
            .iter()
            .map(|d| to_obs_domain(*d))
            .collect::<Vec<_>>(),
    ) {
        snap.warn(format!("domain {missing} not collected"));
    }

    let complete = requested.is_empty()
        || snap.covers_all(
            &requested
                .iter()
                .map(|d| to_obs_domain(*d))
                .collect::<Vec<_>>(),
        );
    snap.health = if report.partial.is_empty() && report.errors.is_empty() && complete {
        ObservationHealth::Healthy
    } else if snap.values.is_empty() {
        ObservationHealth::Unavailable
    } else {
        ObservationHealth::Degraded
    };
    snap
}

/// Map the provider's domain enum onto the shared vocabulary.
fn to_obs_domain(d: CollectorDomain) -> ObservationDomain {
    match d {
        CollectorDomain::System => ObservationDomain::System,
        CollectorDomain::Process => ObservationDomain::Process,
        CollectorDomain::Filesystem => ObservationDomain::Filesystem,
        CollectorDomain::Network => ObservationDomain::Network,
        CollectorDomain::Docker => ObservationDomain::Docker,
        CollectorDomain::Health => ObservationDomain::Health,
    }
}

/// Produce the degraded snapshot for an unavailable Multipass (FR-079).
///
/// The instance is still running (or still exists) — only the observation
/// channel failed. `mode` records what was attempted.
pub fn unavailable_snapshot(
    resource_id: ResourceId,
    reason: impl Into<String>,
    observed_at: impl Into<String>,
) -> ObservationSnapshot {
    let reason = reason.into();
    let observed_at = observed_at.into();
    let mut snap = ObservationSnapshot::empty(
        resource_id,
        ObservationMode::Exec,
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
        ResourceId::derive(&["multipass", "primary"])
    }

    #[test]
    fn capabilities_claim_exec_but_not_probe_or_nested_docker() {
        let caps = multipass_capabilities();
        assert!(caps.supports(ObservationMode::Exec));
        assert!(caps.supports(ObservationMode::Metadata));
        assert!(!caps.supports(ObservationMode::Probe));
        let exec = caps.domains_in(ObservationMode::Exec);
        assert!(exec.contains(&ObservationDomain::System));
        assert!(exec.contains(&ObservationDomain::Process));
        assert!(exec.contains(&ObservationDomain::Filesystem));
        assert!(exec.contains(&ObservationDomain::Network));
        // FR-078 nested inventory is the sandbox provider's job.
        assert!(!exec.contains(&ObservationDomain::Docker));
    }

    #[test]
    fn exec_data_is_never_host_native() {
        // ADR-OBS-003: the host cannot see inside a VM.
        let v =
            system_domain_from_collector(&json!({"os": "ubuntu"}), "2026-10-07T00:00:00Z", false);
        assert_eq!(v.provenance.trust, TrustLevel::RemoteExec);
        assert!(!v.provenance.trust.is_security_authoritative());
    }

    #[test]
    fn a_non_object_payload_is_not_coerced() {
        // RD §9: a scalar is not a system description.
        let v = system_domain_from_collector(&json!("ubuntu"), "2026-10-07T00:00:00Z", false);
        assert_eq!(v.value, json!({}));
    }

    #[test]
    fn complete_report_yields_a_healthy_snapshot() {
        let report = CollectorReport {
            domains: [
                ("system".to_string(), json!({"os": "ubuntu"})),
                ("process".to_string(), json!([{"pid": 1}])),
            ]
            .into_iter()
            .collect(),
            partial: vec![],
            errors: vec![],
        };
        let snap = snapshot_from_report(
            rid(),
            &report,
            &[CollectorDomain::System, CollectorDomain::Process],
            "2026-10-07T00:00:00Z",
        );
        assert_eq!(snap.health, ObservationHealth::Healthy);
        assert_eq!(snap.mode, ObservationMode::Exec);
        assert!(snap.covers_all(&[ObservationDomain::System, ObservationDomain::Process]));
        assert_eq!(
            snap.collector_version.as_deref(),
            Some("sandtree-collector/1")
        );
        // No remote-exec data may satisfy a security precondition.
        assert!(!snap.is_security_authoritative());
    }

    #[test]
    fn partial_domain_is_present_and_flagged_not_hidden() {
        let report = CollectorReport {
            domains: [("system".to_string(), json!({"os": "ubuntu"}))]
                .into_iter()
                .collect(),
            partial: vec!["network".to_string()],
            errors: vec!["network: timeout".to_string()],
        };
        let snap = snapshot_from_report(
            rid(),
            &report,
            &[CollectorDomain::System, CollectorDomain::Network],
            "2026-10-07T00:00:00Z",
        );
        assert_eq!(snap.health, ObservationHealth::Degraded);
        // network is absent because the collector never produced it, and the
        // snapshot says so rather than implying it was empty.
        assert!(snap.get(ObservationDomain::Network).is_none());
        assert!(snap.warnings.iter().any(|w| w.contains("network")));
        assert!(snap.missing_domains(&[ObservationDomain::Network]) == vec!["network"]);
    }

    #[test]
    fn an_empty_report_is_unavailable_rather_than_healthy() {
        // FR-079: a collection that returned nothing is not a healthy empty
        // reading of the guest.
        let report = CollectorReport::default();
        let snap = snapshot_from_report(
            rid(),
            &report,
            &[CollectorDomain::System],
            "2026-10-07T00:00:00Z",
        );
        assert_eq!(snap.health, ObservationHealth::Unavailable);
        assert!(snap.values.is_empty());
        assert!(!snap.is_security_authoritative());
    }

    #[test]
    fn unavailable_snapshot_preserves_the_resource_and_says_why() {
        let snap = unavailable_snapshot(rid(), "multipass not installed", "2026-10-07T00:00:00Z");
        assert_eq!(snap.resource_id, rid());
        assert_eq!(snap.health, ObservationHealth::Unavailable);
        assert_eq!(snap.mode, ObservationMode::Exec);
        assert!(snap.values.is_empty());
        assert_eq!(snap.warnings, vec!["multipass not installed".to_string()]);
    }

    #[test]
    fn unknown_domains_in_a_report_are_ignored() {
        let report = CollectorReport {
            domains: [("telepathy".to_string(), json!({"ok": true}))]
                .into_iter()
                .collect(),
            partial: vec![],
            errors: vec![],
        };
        let snap = snapshot_from_report(rid(), &report, &[], "2026-10-07T00:00:00Z");
        assert_eq!(snap.values.len(), 0);
    }

    #[test]
    fn nested_docker_payload_is_surfaced_but_marked_partial() {
        // If a collector ever reports nested Docker, it is passed through with
        // the weakest honest trust and flagged, never promoted.
        let report = CollectorReport {
            domains: [("docker".to_string(), json!({"containers": 2}))]
                .into_iter()
                .collect(),
            partial: vec![],
            errors: vec![],
        };
        let snap = snapshot_from_report(rid(), &report, &[], "2026-10-07T00:00:00Z");
        let v = snap.get(ObservationDomain::Docker).unwrap();
        assert!(v.is_partial());
        assert_eq!(v.provenance.trust, TrustLevel::RemoteExec);
    }

    #[test]
    fn snapshot_values_are_sorted_for_byte_stability() {
        let report = CollectorReport {
            domains: [
                ("system".to_string(), json!({})),
                ("health".to_string(), json!({})),
                ("process".to_string(), json!({})),
            ]
            .into_iter()
            .collect(),
            partial: vec![],
            errors: vec![],
        };
        let snap = snapshot_from_report(rid(), &report, &[], "2026-10-07T00:00:00Z");
        let keys: Vec<&str> = snap.values.keys().map(String::as_str).collect();
        assert_eq!(keys, vec!["health", "process", "system"]);
    }
}
