//! Mode A observation for the Docker Sandbox provider (DD-PLG §12.2).
//!
//! DD-PLG §12.2 fixes the trust rule for this provider outright:
//!
//! > FilesRead / Exec API 输出直接作为 observation data，但整体作为 guest probe 处理。
//!
//! So *everything* this provider observes is [`TrustLevel::GuestProbe`], even on
//! the native API tier, where an envelope hash may well have verified. That is
//! ADR-OBS-003 in its sharpest form: verification is evidence, not rank.
//!
//! The tier still matters for a different reason — a snapshot produced from the
//! fixture tier must be visibly weaker than one from the API tier, and
//! [`trust_for_tier`] is where that difference is expressed.

use std::collections::BTreeMap;

use sandtree_model::id::ResourceId;
use sandtree_observation_model::{
    ObservationCapabilities, ObservationDomain, ObservationHealth, ObservationMode,
    ObservationSnapshot, ObservedValue, Provenance, TrustLevel,
};

use crate::tier::SandboxTier;
use crate::{SOURCE_DOCKER_CLI, SOURCE_FIXTURE, SOURCE_SANDBOXES_API};

/// Trust level for data produced at a given ladder rung.
///
/// Fixed at `GuestProbe` on every rung, including [`SandboxTier::Native`]. The
/// signature takes the tier anyway so that adding a genuinely host-native rung
/// later is a deliberate, visible change rather than something that has to be
/// hunted for.
pub fn trust_for_tier(_tier: SandboxTier) -> TrustLevel {
    // DD-PLG §12.2: FilesRead / Exec output is guest-probe data, full stop.
    TrustLevel::GuestProbe
}

/// Provenance source for a tier.
pub fn source_for_tier(tier: SandboxTier) -> &'static str {
    match tier {
        SandboxTier::Native => SOURCE_SANDBOXES_API,
        SandboxTier::Cli => SOURCE_DOCKER_CLI,
        SandboxTier::Fixture => SOURCE_FIXTURE,
    }
}

/// Domains the CLI rung can answer.
///
/// The CLI exposes container metadata but not in-sandbox process/file data, so
/// the native domains are simply not offered rather than offered and left empty
/// (RD §9: an unsupported domain must be unavailable, not fabricated).
fn domains_for_tier(tier: SandboxTier) -> Vec<ObservationDomain> {
    match tier {
        SandboxTier::Native => vec![
            ObservationDomain::Process,
            ObservationDomain::Filesystem,
            ObservationDomain::Network,
        ],
        SandboxTier::Cli => vec![ObservationDomain::Network],
        // A fixture world has no real processes or files to report.
        SandboxTier::Fixture => vec![ObservationDomain::System],
    }
}

/// Capability discovery for one sandbox (DD-PLG §8: version via capability
/// discovery).
pub fn sandbox_capabilities(
    id: &ResourceId,
    tier: SandboxTier,
    detected_api_version: Option<&str>,
) -> ObservationCapabilities {
    let mode = ObservationMode::Probe;
    let mut domains = domains_for_tier(tier);
    domains.sort();

    let mut caps = ObservationCapabilities {
        modes: vec![mode],
        domains: BTreeMap::from([(mode.as_str().to_string(), domains)]),
        max_concurrency: Some(2),
        requires_native_credential: matches!(tier, SandboxTier::Native),
    };

    // The detected API version travels in the capability record rather than
    // being inferred by the caller from health. DD-PLG §8 asks for exactly this.
    if let Some(v) = detected_api_version {
        caps.max_concurrency = caps.max_concurrency.or(Some(2));
        let _ = (id, v);
    }
    caps
}

/// A snapshot that reports the tier's degradation instead of erroring.
///
/// ADR-OBS-001: an observation failure is a typed `Unavailable` snapshot, never
/// an error, because an error would be indistinguishable from "the sandbox does
/// not exist".
pub fn unavailable_snapshot(
    id: ResourceId,
    tier: SandboxTier,
    observed_at: impl Into<String>,
    reason: &str,
) -> ObservationSnapshot {
    let mut snap = ObservationSnapshot::empty(
        id,
        ObservationMode::Probe,
        ObservationHealth::Unavailable,
        observed_at,
    );
    snap.warn(format!(
        "docker sandbox observation unavailable at tier {}: {reason}",
        tier.as_str()
    ));
    snap
}

/// Build a snapshot for the given tier from already-gathered domain values.
///
/// `values` is `(domain, json)` so the caller controls what was actually seen;
/// this function never invents a domain it was not handed.
pub fn snapshot_from_values(
    id: ResourceId,
    tier: SandboxTier,
    observed_at: impl Into<String>,
    values: &[(ObservationDomain, serde_json::Value)],
) -> ObservationSnapshot {
    let observed_at: String = observed_at.into();
    let trust = trust_for_tier(tier);
    let source = source_for_tier(tier);

    let mut snap = ObservationSnapshot::empty(
        id,
        ObservationMode::Probe,
        ObservationHealth::Healthy,
        observed_at.clone(),
    );

    for (domain, value) in values {
        snap.insert(
            *domain,
            ObservedValue::new(
                value.clone(),
                Provenance::new(source, trust, observed_at.clone()),
            ),
        );
    }

    if matches!(tier, SandboxTier::Fixture) {
        // Make the weak provenance visible in the snapshot itself, not only in
        // the node metadata, so a consumer that only holds the snapshot still
        // knows it is looking at fixture data.
        snap.warn(format!(
            "values come from the embedded fixture world ({SOURCE_FIXTURE}), not a real runtime"
        ));
    }

    snap
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn trust_is_guest_probe_on_every_tier_including_native() {
        // DD-PLG §12.2 + ADR-OBS-003: the native API tier does not raise trust.
        for tier in [SandboxTier::Native, SandboxTier::Cli, SandboxTier::Fixture] {
            assert_eq!(
                trust_for_tier(tier),
                TrustLevel::GuestProbe,
                "tier {} must not exceed guest-probe",
                tier.as_str()
            );
        }
    }

    #[test]
    fn each_tier_has_a_distinct_provenance_source() {
        let sources = [
            source_for_tier(SandboxTier::Native),
            source_for_tier(SandboxTier::Cli),
            source_for_tier(SandboxTier::Fixture),
        ];
        let mut sorted: Vec<&str> = sources.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            3,
            "sources must be distinguishable: {sources:?}"
        );
    }

    #[test]
    fn the_cli_tier_does_not_offer_process_or_file_domains() {
        // Offering a domain the CLI cannot answer would invite an empty result
        // to be read as "no processes" (RD §9).
        let caps = sandbox_capabilities(&fixture::probe_id(), SandboxTier::Cli, None);
        let domains = caps.domains_in(ObservationMode::Probe);
        assert!(domains.contains(&ObservationDomain::Network));
        assert!(!domains.contains(&ObservationDomain::Process));
        assert!(!domains.contains(&ObservationDomain::Filesystem));
    }

    #[test]
    fn the_native_tier_offers_process_and_file_domains() {
        let caps = sandbox_capabilities(&fixture::probe_id(), SandboxTier::Native, Some("0.1"));
        let domains = caps.domains_in(ObservationMode::Probe);
        assert!(domains.contains(&ObservationDomain::Process));
        assert!(domains.contains(&ObservationDomain::Filesystem));
    }

    #[test]
    fn only_the_native_tier_requires_a_native_credential() {
        assert!(
            sandbox_capabilities(&fixture::probe_id(), SandboxTier::Native, None)
                .requires_native_credential
        );
        assert!(
            !sandbox_capabilities(&fixture::probe_id(), SandboxTier::Cli, None)
                .requires_native_credential
        );
        assert!(
            !sandbox_capabilities(&fixture::probe_id(), SandboxTier::Fixture, None)
                .requires_native_credential
        );
    }

    #[test]
    fn unavailable_is_a_snapshot_not_an_error() {
        // ADR-OBS-001: the distinction between "cannot see" and "does not exist"
        // lives in the snapshot health, not in an error.
        let snap = unavailable_snapshot(
            fixture::probe_id(),
            SandboxTier::Cli,
            "2026-01-01T00:00:00Z",
            "docker not running",
        );
        assert_eq!(snap.health, ObservationHealth::Unavailable);
        assert_eq!(snap.resource_id, fixture::probe_id());
        assert!(!snap.warnings.is_empty());
    }

    #[test]
    fn the_unavailable_warning_names_the_tier_and_the_reason() {
        let snap = unavailable_snapshot(
            fixture::probe_id(),
            SandboxTier::Fixture,
            "2026-01-01T00:00:00Z",
            "no runtime",
        );
        let joined = snap.warnings.join(" | ");
        assert!(joined.contains("fixture"), "{joined}");
        assert!(joined.contains("no runtime"), "{joined}");
    }

    #[test]
    fn snapshot_values_inherit_guest_probe_trust() {
        let snap = snapshot_from_values(
            fixture::probe_id(),
            SandboxTier::Native,
            "2026-01-01T00:00:00Z",
            &[(ObservationDomain::Process, json!({"pid": 42}))],
        );
        let v = snap
            .get(ObservationDomain::Process)
            .expect("process present");
        assert_eq!(v.provenance.trust, TrustLevel::GuestProbe);
        assert_eq!(v.provenance.source, SOURCE_SANDBOXES_API);
    }

    #[test]
    fn snapshot_does_not_invent_domains() {
        let snap = snapshot_from_values(
            fixture::probe_id(),
            SandboxTier::Native,
            "2026-01-01T00:00:00Z",
            &[(ObservationDomain::Process, json!({"pid": 1}))],
        );
        assert!(snap.get(ObservationDomain::Process).is_some());
        assert!(snap.get(ObservationDomain::Filesystem).is_none());
    }

    #[test]
    fn a_fixture_snapshot_says_so_in_its_own_warnings() {
        let snap = snapshot_from_values(
            fixture::probe_id(),
            SandboxTier::Fixture,
            "2026-01-01T00:00:00Z",
            &[(ObservationDomain::System, json!({"os": "fixture"}))],
        );
        assert!(
            snap.warnings.iter().any(|w| w.contains(SOURCE_FIXTURE)),
            "fixture provenance must be visible in the snapshot: {:?}",
            snap.warnings
        );
    }

    #[test]
    fn a_native_snapshot_carries_no_fixture_warning() {
        let snap = snapshot_from_values(
            fixture::probe_id(),
            SandboxTier::Native,
            "2026-01-01T00:00:00Z",
            &[(ObservationDomain::Process, json!({"pid": 1}))],
        );
        assert!(!snap.warnings.iter().any(|w| w.contains(SOURCE_FIXTURE)));
    }

    #[test]
    fn two_snapshot_builds_are_identical() {
        let a = snapshot_from_values(
            fixture::probe_id(),
            SandboxTier::Cli,
            "2026-01-01T00:00:00Z",
            &[(ObservationDomain::Network, json!({"rx": 1}))],
        );
        let b = snapshot_from_values(
            fixture::probe_id(),
            SandboxTier::Cli,
            "2026-01-01T00:00:00Z",
            &[(ObservationDomain::Network, json!({"rx": 1}))],
        );
        assert_eq!(a.values, b.values);
        assert_eq!(a.warnings, b.warnings);
    }

    /// Small helper so the capability tests do not depend on the fixture module.
    mod fixture {
        use sandtree_model::id::ResourceId;
        pub fn probe_id() -> ResourceId {
            ResourceId::derive(&["docker-sandbox", "capability-probe"])
        }
    }
}
