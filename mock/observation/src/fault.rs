//! Fault injection for the mock observation plane.
//!
//! The Observation Plane's failure modes cannot be produced on demand from a
//! real runtime: Windows Sandbox cannot be driven in CI, Multipass is not
//! installed on a build machine, and Docker daemon state is not the test's to
//! control. They are scripted here instead.
//!
//! # Which faults become snapshots and which become errors
//!
//! **ADR-OBS-001 / FR-079 — an observation failure is a typed result, not an
//! error.** A sandbox whose probe cannot attach still exists and is still
//! controllable, so the observation port must *answer*; returning `Err` would
//! collapse "I could not see this" into "this is not there".
//!
//! The design carves out exactly two exceptions, and the mock mirrors them
//! because they are not optional: a malformed or hostile envelope must surface
//! so it can be audited, and must never be degraded away silently (DD-OBS §12,
//! NFR-S08). [`FaultDisposition`] is that decision, encoded as data rather than
//! spread across match arms.
//!
//! | fault | code | default disposition |
//! | --- | --- | --- |
//! | [`ObservationFault::DeadlineExceeded`] | `ST-OBS-002` | `Unavailable` snapshot |
//! | [`ObservationFault::ProbeBootstrapFailed`] | `ST-OBS-004` | `Unavailable` snapshot |
//! | [`ObservationFault::CredentialDenied`] | `ST-OBS-006` | `Unavailable` snapshot |
//! | [`ObservationFault::NestedDockerUnavailable`] | `ST-OBS-010` | `Degraded` snapshot |
//! | [`ObservationFault::PartialCoverage`] | — | `Degraded` snapshot |
//! | [`ObservationFault::InvalidEnvelope`] | `ST-OBS-005` | surfaced error |
//! | [`ObservationFault::GuestPathEscape`] | `ST-OBS-008` | surfaced error |

use sandtree_model::error::{DomainError, ErrorCode};
use sandtree_observation_model::ObservationDomain;
use serde::{Deserialize, Serialize};

/// How a fault is reported to the caller (ADR-OBS-001, DD-OBS §12).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FaultDisposition {
    /// Answer with an `Unavailable` snapshot carrying a warning.
    ///
    /// The channel is down. The resource is untouched and no domain value is
    /// fabricated.
    UnavailableSnapshot,
    /// Answer with a `Degraded` snapshot carrying a warning.
    ///
    /// Some domains are still valid, so the snapshot keeps the values it did
    /// get; "partial" is never encoded as "absent" (DD-OBS §2).
    DegradedSnapshot,
    /// Return the typed error instead of a snapshot.
    ///
    /// Reserved for protocol and security violations, which must reach the
    /// audit log rather than being degraded away.
    SurfaceError,
}

/// A scripted observation failure.
///
/// Deserialized from fixtures with an internally tagged `kind` field, e.g.
/// `{"kind": "probe_bootstrap_failed", "reason": "bridge handshake refused"}`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ObservationFault {
    /// The collector did not answer inside its deadline (`ST-OBS-002`).
    DeadlineExceeded {
        /// Why the deadline was not met.
        reason: String,
        /// The deadline that was exceeded, in milliseconds.
        deadline_ms: u64,
    },
    /// A probe envelope failed host-side validation (`ST-OBS-005`).
    ///
    /// Always surfaced, never degraded: an envelope that does not validate may
    /// be a replay, a foreign session, or a tampered payload.
    InvalidEnvelope {
        /// Which validation rule rejected it.
        reason: String,
    },
    /// A guest-reported path escaped the guest root (`ST-OBS-008`).
    ///
    /// Always surfaced and audited (NFR-S08): a guest path is never resolved
    /// against the host filesystem.
    GuestPathEscape {
        /// The offending guest path, exactly as the guest reported it.
        path: String,
    },
    /// The disposable probe could not be bootstrapped (`ST-OBS-004`).
    ProbeBootstrapFailed {
        /// Why bootstrap failed.
        reason: String,
    },
    /// The provider-native credential is missing or denied (`ST-OBS-006`).
    CredentialDenied {
        /// Why the credential was refused. Never contains the credential.
        reason: String,
    },
    /// A nested engine inside the guest is unreachable (`ST-OBS-010`).
    ///
    /// Only the `docker` domain is affected; the sandbox itself is observable.
    NestedDockerUnavailable {
        /// Why the nested endpoint could not be reached.
        reason: String,
    },
    /// The collector answered, but some requested domains are missing.
    PartialCoverage {
        /// Domains that produced no value, sorted by the fixture author.
        missing_domains: Vec<ObservationDomain>,
    },
}

impl ObservationFault {
    /// Stable error code for this fault.
    ///
    /// [`ObservationFault::PartialCoverage`] has none: missing domains are a
    /// coverage fact, not an error, and inventing a code for it would give a
    /// UI something to branch on that the registry does not define.
    pub fn code(&self) -> Option<ErrorCode> {
        match self {
            ObservationFault::DeadlineExceeded { .. } => Some(ErrorCode::OBS_DEADLINE_EXCEEDED),
            ObservationFault::InvalidEnvelope { .. } => Some(ErrorCode::OBS_ENVELOPE_INVALID),
            ObservationFault::GuestPathEscape { .. } => Some(ErrorCode::OBS_GUEST_PATH_ESCAPE),
            ObservationFault::ProbeBootstrapFailed { .. } => Some(ErrorCode::OBS_PROBE_BOOTSTRAP),
            ObservationFault::CredentialDenied { .. } => Some(ErrorCode::OBS_CREDENTIAL_DENIED),
            ObservationFault::NestedDockerUnavailable { .. } => {
                Some(ErrorCode::OBS_NESTED_DOCKER_UNAVAILABLE)
            }
            ObservationFault::PartialCoverage { .. } => None,
        }
    }

    /// Whether retrying the same request could succeed.
    pub fn is_retryable(&self) -> bool {
        match self.code() {
            Some(code) => code.is_retryable(),
            // Missing domains come back on the next collection window.
            None => true,
        }
    }

    /// The disposition required by the design, before any fixture override.
    pub fn default_disposition(&self) -> FaultDisposition {
        match self {
            // NFR-S08 / DD-OBS §12: protocol and security violations surface.
            ObservationFault::InvalidEnvelope { .. } | ObservationFault::GuestPathEscape { .. } => {
                FaultDisposition::SurfaceError
            }
            // Some values are still valid, so the snapshot survives.
            ObservationFault::PartialCoverage { .. }
            | ObservationFault::NestedDockerUnavailable { .. } => {
                FaultDisposition::DegradedSnapshot
            }
            // The channel is gone but the resource is not (FR-079).
            ObservationFault::DeadlineExceeded { .. }
            | ObservationFault::ProbeBootstrapFailed { .. }
            | ObservationFault::CredentialDenied { .. } => FaultDisposition::UnavailableSnapshot,
        }
    }

    /// Stable warning text recorded on a snapshot that absorbs this fault.
    ///
    /// Always starts with the error code, because UI and test code branch on
    /// codes rather than on prose (DD-SW §10).
    pub fn warning(&self) -> String {
        match self {
            ObservationFault::DeadlineExceeded {
                reason,
                deadline_ms,
            } => format!(
                "{} observation deadline exceeded after {deadline_ms}ms: {reason}",
                ErrorCode::OBS_DEADLINE_EXCEEDED
            ),
            ObservationFault::InvalidEnvelope { reason } => format!(
                "{} probe envelope rejected: {reason}",
                ErrorCode::OBS_ENVELOPE_INVALID
            ),
            ObservationFault::GuestPathEscape { path } => format!(
                "{} guest-reported path refused: {path}",
                ErrorCode::OBS_GUEST_PATH_ESCAPE
            ),
            ObservationFault::ProbeBootstrapFailed { reason } => format!(
                "{} probe bootstrap failed: {reason}",
                ErrorCode::OBS_PROBE_BOOTSTRAP
            ),
            ObservationFault::CredentialDenied { reason } => format!(
                "{} provider credential denied: {reason}",
                ErrorCode::OBS_CREDENTIAL_DENIED
            ),
            ObservationFault::NestedDockerUnavailable { reason } => format!(
                "{} nested engine unreachable: {reason}",
                ErrorCode::OBS_NESTED_DOCKER_UNAVAILABLE
            ),
            ObservationFault::PartialCoverage { missing_domains } => {
                let names: Vec<&str> = missing_domains.iter().map(|d| d.as_str()).collect();
                format!(
                    "domains not reported by the collector: {}",
                    names.join(", ")
                )
            }
        }
    }

    /// The typed error a surfaced fault carries.
    ///
    /// Provider-supplied detail goes into `detail`, never into `message`
    /// (DD-DATA §8): the message is what a UI renders.
    pub fn to_domain_error(&self) -> DomainError {
        let code = self.code().unwrap_or(ErrorCode::OBS_NO_STRATEGY);
        let message = match self {
            ObservationFault::DeadlineExceeded { .. } => "observation deadline exceeded",
            ObservationFault::InvalidEnvelope { .. } => "probe envelope rejected",
            ObservationFault::GuestPathEscape { .. } => "guest-reported path refused",
            ObservationFault::ProbeBootstrapFailed { .. } => "probe bootstrap failed",
            ObservationFault::CredentialDenied { .. } => "provider credential denied",
            ObservationFault::NestedDockerUnavailable { .. } => "nested engine unreachable",
            ObservationFault::PartialCoverage { .. } => "collector reported partial coverage",
        };
        DomainError::new(code, message).with_detail(self.warning())
    }

    /// Domains this fault removes from an otherwise complete snapshot.
    ///
    /// Only faults that actually withhold domains appear here; a bootstrap
    /// failure withholds *all* of them, which the provider expresses by using
    /// [`FaultDisposition::UnavailableSnapshot`] instead of consulting this.
    pub fn withheld_domains(&self) -> &[ObservationDomain] {
        match self {
            ObservationFault::PartialCoverage { missing_domains } => missing_domains,
            _ => &[],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The disposition split must match `observation-core`'s degradability rule:
    /// only the envelope and path-escape codes may surface.
    #[test]
    fn only_protocol_and_security_faults_surface() {
        let faults = all_faults();
        let surfacing: Vec<String> = faults
            .iter()
            .filter(|f| f.default_disposition() == FaultDisposition::SurfaceError)
            .map(|f| f.warning())
            .collect();
        assert_eq!(surfacing.len(), 2, "expected exactly two surfacing faults");
        assert!(surfacing[0].starts_with("ST-OBS-005"), "{surfacing:?}");
        assert!(surfacing[1].starts_with("ST-OBS-008"), "{surfacing:?}");
        for f in &faults {
            if f.default_disposition() == FaultDisposition::SurfaceError {
                continue;
            }
            assert!(
                f.code().map(|c| c.as_str()) != Some("ST-OBS-005"),
                "{f:?} must not degrade an envelope violation"
            );
            assert!(
                f.code().map(|c| c.as_str()) != Some("ST-OBS-008"),
                "{f:?} must not degrade a path escape"
            );
        }
    }

    /// Every code emitted here exists in the shipped registry, so a test can
    /// never assert on an invented `ST-OBS-xxx`.
    #[test]
    fn codes_come_from_the_registry_and_match_the_table() {
        let expected = [
            (
                ObservationFault::DeadlineExceeded {
                    reason: "collector did not answer".into(),
                    deadline_ms: 2_000,
                },
                "ST-OBS-002",
                true,
            ),
            (
                ObservationFault::InvalidEnvelope {
                    reason: "sequence regression".into(),
                },
                "ST-OBS-005",
                false,
            ),
            (
                ObservationFault::GuestPathEscape {
                    path: "../outside".into(),
                },
                "ST-OBS-008",
                false,
            ),
            (
                ObservationFault::ProbeBootstrapFailed {
                    reason: "bridge refused".into(),
                },
                "ST-OBS-004",
                true,
            ),
            (
                ObservationFault::CredentialDenied {
                    reason: "no credential".into(),
                },
                "ST-OBS-006",
                // The CSV marks ST-OBS-006 `maybe`, and `is_retryable` is a
                // strict yes-set, so a denied credential is *not* reported as
                // retryable. Asserted here so a change to that mapping is a
                // deliberate, visible edit rather than a silent behaviour drift.
                false,
            ),
            (
                ObservationFault::NestedDockerUnavailable {
                    reason: "pipe closed".into(),
                },
                "ST-OBS-010",
                true,
            ),
        ];
        for (fault, code, retryable) in expected {
            let got = fault.code().expect("registry code");
            assert_eq!(got.as_str(), code);
            assert_eq!(
                ErrorCode::parse(code),
                Some(got),
                "{code} must be parseable from the shipped registry"
            );
            assert_eq!(fault.is_retryable(), retryable, "{code} retry flag");
        }
        // Partial coverage is a coverage fact, not a coded error.
        let partial = ObservationFault::PartialCoverage {
            missing_domains: vec![ObservationDomain::Process],
        };
        assert_eq!(partial.code(), None);
        assert!(partial.is_retryable());
    }

    /// Warnings lead with the code so callers can branch on them (DD-SW §10).
    #[test]
    fn warnings_lead_with_the_stable_code() {
        let fault = ObservationFault::DeadlineExceeded {
            reason: "no answer".into(),
            deadline_ms: 2_000,
        };
        let w = fault.warning();
        assert!(w.starts_with("ST-OBS-002 "), "{w}");
        assert!(w.contains("2000ms"), "{w}");
        assert!(w.contains("no answer"), "{w}");

        let partial = ObservationFault::PartialCoverage {
            missing_domains: vec![ObservationDomain::Network, ObservationDomain::Process],
        };
        assert_eq!(
            partial.warning(),
            "domains not reported by the collector: network, process"
        );
    }

    /// A surfaced error keeps provider detail out of the user-facing message.
    #[test]
    fn surfaced_errors_keep_detail_out_of_the_message() {
        let err = ObservationFault::InvalidEnvelope {
            reason: "nonce belongs to another session".into(),
        }
        .to_domain_error();
        assert_eq!(err.code, ErrorCode::OBS_ENVELOPE_INVALID);
        assert_eq!(err.message, "probe envelope rejected");
        assert!(!err.message.contains("nonce"));
        assert!(err
            .detail
            .as_ref()
            .expect("detail carries the raw reason")
            .contains("nonce belongs to another session"));
    }

    /// Withheld domains are only reported by the coverage fault.
    #[test]
    fn only_partial_coverage_withholds_specific_domains() {
        let partial = ObservationFault::PartialCoverage {
            missing_domains: vec![ObservationDomain::Filesystem],
        };
        assert_eq!(partial.withheld_domains(), &[ObservationDomain::Filesystem]);
        for fault in all_faults() {
            if matches!(fault, ObservationFault::PartialCoverage { .. }) {
                continue;
            }
            assert!(
                fault.withheld_domains().is_empty(),
                "{fault:?} must withhold nothing specific"
            );
        }
    }

    /// Every fault the crate ships, in a stable order.
    fn all_faults() -> Vec<ObservationFault> {
        vec![
            ObservationFault::DeadlineExceeded {
                reason: "collector did not answer".into(),
                deadline_ms: 2_000,
            },
            ObservationFault::InvalidEnvelope {
                reason: "sequence regression".into(),
            },
            ObservationFault::GuestPathEscape {
                path: "../outside".into(),
            },
            ObservationFault::ProbeBootstrapFailed {
                reason: "bridge handshake refused".into(),
            },
            ObservationFault::CredentialDenied {
                reason: "credential store empty".into(),
            },
            ObservationFault::NestedDockerUnavailable {
                reason: "nested pipe closed".into(),
            },
            ObservationFault::PartialCoverage {
                missing_domains: vec![ObservationDomain::Process],
            },
        ]
    }
}
