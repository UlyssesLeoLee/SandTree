//! Observation trust gates (DD-SECOPS §11.1, DD-OBS §6, ADR-OBS-001/003).
//!
//! This is the module that stops a sandbox from lying its way into a
//! destructive action. Two independent rules:
//!
//! 1. A guest probe is never authoritative, **even when its hash verifies**.
//!    A guest that can produce a valid BLAKE3 digest can produce a valid digest
//!    for a false claim, so the digest proves integrity of the message, not
//!    truth of the content.
//! 2. Stale data may not gate a destructive precondition — "the container is
//!    stopped" must be checked against something current.

use sandtree_model::error::{DomainError, ErrorCode};
use sandtree_observation_model::{
    ObservationDomain, ObservationHealth, ObservationSnapshot, TrustLevel,
};

use crate::audit::now_ms;

/// Minimum trust required for a destructive precondition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustPolicy {
    /// Weakest trust level accepted as proof for destructive actions.
    pub min_trust_for_destructive: TrustLevel,
    /// Treat snapshots older than this as stale regardless of domain defaults.
    pub absolute_max_age_ms: Option<u64>,
}

impl Default for TrustPolicy {
    fn default() -> Self {
        Self {
            // DD-SECOPS §11.1: security decisions prefer HostNative/ProviderNative.
            min_trust_for_destructive: TrustLevel::HostNative,
            absolute_max_age_ms: None,
        }
    }
}

impl TrustPolicy {
    /// Strict default policy.
    pub fn new() -> Self {
        Self::default()
    }

    /// Policy accepting any trust level (used by read-only inspection paths).
    pub fn permissive() -> Self {
        Self {
            min_trust_for_destructive: TrustLevel::Unverified,
            absolute_max_age_ms: None,
        }
    }

    /// Whether a snapshot may be used as evidence for a destructive action.
    pub fn check_destructive_precondition(
        &self,
        snap: &ObservationSnapshot,
    ) -> Result<(), DomainError> {
        // An empty snapshot is "we cannot see inside", which is never evidence
        // that a resource is absent or idle (ADR-OBS-001).
        if snap.values.is_empty() {
            if snap.health != ObservationHealth::Healthy {
                return Err(DomainError::new(
                    ErrorCode::OBS_NO_STRATEGY,
                    format!(
                        "observation for {} is {} with no values; an unobservable resource is not evidence of absence",
                        snap.resource_id, snap.health.as_str()
                    ),
                ));
            }
            return Err(DomainError::new(
                ErrorCode::OBS_NO_STRATEGY,
                "snapshot carries no values and cannot gate a destructive action",
            ));
        }

        if snap.health == ObservationHealth::Stale {
            return Err(DomainError::new(
                ErrorCode::OBS_STALE,
                "observation is stale and must not gate a destructive action",
            ));
        }

        // Lower `TrustLevel` means *more* authoritative, so the test is `<=`,
        // not `>=`. Getting this backwards silently turns the gate off.
        match snap.weakest_trust() {
            Some(t) if t <= self.min_trust_for_destructive => {}
            Some(t) => {
                return Err(DomainError::new(
                    ErrorCode::OBS_TRUST_BELOW_THRESHOLD,
                    format!(
                        "weakest observation trust {} is below the required {}",
                        t.as_str(),
                        self.min_trust_for_destructive.as_str()
                    ),
                ))
            }
            None => {
                return Err(DomainError::new(
                    ErrorCode::OBS_TRUST_BELOW_THRESHOLD,
                    "snapshot carries no provenance",
                ))
            }
        }

        Ok(())
    }

    /// Whether a snapshot is fresh enough per domain.
    pub fn check_staleness(
        &self,
        snap: &ObservationSnapshot,
        now_ms: u64,
    ) -> Result<(), DomainError> {
        for (key, value) in &snap.values {
            let Some(domain) = ObservationDomain::from_wire(key) else {
                continue;
            };
            let limit = self
                .absolute_max_age_ms
                .unwrap_or_else(|| domain.default_max_age_ms());
            let age =
                now_ms.saturating_sub(parse_observed_at_ms(value.provenance.observed_at.as_str()));
            if age > limit {
                return Err(DomainError::new(
                    ErrorCode::OBS_STALE,
                    format!("domain {key} is {age}ms old, exceeding the {limit}ms policy"),
                ));
            }
        }
        Ok(())
    }

    /// Convenience: freshness check against the current wall clock.
    pub fn check_freshness_now(&self, snap: &ObservationSnapshot) -> Result<(), DomainError> {
        self.check_staleness(snap, now_ms())
    }
}

/// Parse an RFC3339 timestamp into epoch milliseconds.
///
/// Deliberately minimal and deliberately *fail-closed*: an unparsable timestamp
/// yields `0`, which makes the value look maximally old and therefore fails the
/// freshness check. Guessing "now" would silently pass a stale snapshot.
fn parse_observed_at_ms(s: &str) -> u64 {
    // `YYYY-MM-DDTHH:MM:SS` prefix is enough; fractional seconds and zone are
    // irrelevant for an age comparison and parsing them adds failure modes.
    let b = s.as_bytes();
    if b.len() < 19 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' {
        return 0;
    }
    let num = |a: usize, z: usize| -> Option<i64> { s.get(a..z)?.parse().ok() };
    let (Some(y), Some(mo), Some(d), Some(h), Some(mi), Some(sec)) = (
        num(0, 4),
        num(5, 7),
        num(8, 10),
        num(11, 13),
        num(14, 16),
        num(17, 19),
    ) else {
        return 0;
    };
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || sec > 60 {
        return 0;
    }
    let days = days_from_civil(y, mo as u32, d as u32);
    let secs = days * 86_400 + h * 3600 + mi * 60 + sec;
    if secs < 0 {
        return 0;
    }
    (secs as u64) * 1000
}

fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let mp = if m > 2 { m - 3 } else { m + 9 } as u64;
    let doy = (153 * mp + 2) / 5 + d as u64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe as i64 - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;
    use sandtree_model::id::ResourceId;
    use sandtree_observation_model::{ObservationMode, ObservedValue, Provenance};

    fn snap_with(trust: TrustLevel, evidence: bool) -> ObservationSnapshot {
        let mut s = ObservationSnapshot::empty(
            ResourceId::derive(&["res"]),
            ObservationMode::Native,
            ObservationHealth::Healthy,
            iso_now(),
        );
        let mut p = Provenance::new("test", trust, iso_now());
        if evidence {
            p = p.with_evidence(b"payload");
        }
        s.insert(
            ObservationDomain::System,
            ObservedValue::new(serde_json::json!({"state": "stopped"}), p),
        );
        s
    }

    fn iso_now() -> String {
        // Same formatter the audit module uses, so tests do not need chrono.
        crate::now_rfc3339_for_tests()
    }

    #[test]
    fn host_native_passes_the_destructive_gate() {
        let s = snap_with(TrustLevel::HostNative, false);
        assert!(TrustPolicy::new()
            .check_destructive_precondition(&s)
            .is_ok());
    }

    #[test]
    fn guest_probe_never_passes_even_with_a_verified_hash() {
        // ADR-OBS-003: a valid digest proves message integrity, not truth.
        let s = snap_with(TrustLevel::GuestProbe, true);
        let err = TrustPolicy::new()
            .check_destructive_precondition(&s)
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::OBS_TRUST_BELOW_THRESHOLD);
        assert!(s.values["system"].provenance.evidence_hash.is_some());
    }

    #[test]
    fn remote_exec_is_below_the_default_threshold() {
        let s = snap_with(TrustLevel::RemoteExec, true);
        let err = TrustPolicy::new()
            .check_destructive_precondition(&s)
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::OBS_TRUST_BELOW_THRESHOLD);
    }

    #[test]
    fn stale_snapshot_is_rejected_before_trust_is_even_considered() {
        let mut s = snap_with(TrustLevel::HostNative, false);
        s.health = ObservationHealth::Stale;
        let err = TrustPolicy::new()
            .check_destructive_precondition(&s)
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::OBS_STALE);
    }

    #[test]
    fn unavailable_snapshot_is_not_evidence_of_absence() {
        // ADR-OBS-001
        let s = ObservationSnapshot::empty(
            ResourceId::derive(&["res"]),
            sandtree_observation_model::ObservationMode::Metadata,
            ObservationHealth::Unavailable,
            iso_now(),
        );
        let err = TrustPolicy::new()
            .check_destructive_precondition(&s)
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::OBS_NO_STRATEGY);
    }

    #[test]
    fn permissive_policy_still_requires_provenance() {
        let s = snap_with(TrustLevel::Unverified, false);
        assert!(TrustPolicy::permissive()
            .check_destructive_precondition(&s)
            .is_ok());
    }

    #[test]
    fn freshness_uses_per_domain_limits() {
        let s = snap_with(TrustLevel::HostNative, false);
        let now = now_ms();
        assert!(TrustPolicy::new().check_staleness(&s, now).is_ok());
        // system default max age is 60s; go past it.
        assert_eq!(
            TrustPolicy::new()
                .check_staleness(&s, now + 61_000)
                .unwrap_err()
                .code,
            ErrorCode::OBS_STALE
        );
    }

    #[test]
    fn unparsable_timestamp_is_treated_as_oldest_possible() {
        // Fail closed: a broken timestamp must never read as "fresh".
        assert_eq!(parse_observed_at_ms("not-a-date"), 0);
        assert_eq!(parse_observed_at_ms(""), 0);
        assert!(parse_observed_at_ms("1970-01-01T00:00:00Z") < 1_000);
    }

    #[test]
    fn timestamp_parsing_is_correct() {
        assert_eq!(parse_observed_at_ms("1970-01-01T00:00:00Z"), 0);
        assert_eq!(
            parse_observed_at_ms("2023-11-14T22:13:20Z"),
            1_700_000_000_000
        );
    }
}
