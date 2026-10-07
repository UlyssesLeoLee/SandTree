//! The degradation ladder (DD-PLG §8).
//!
//! DD-PLG §8 fixes both the tiers and their order:
//!
//! > 主机 API 不可用时只降级 CLI；CLI 不可用时，provider 内部 fixture regression test。
//!
//! The ladder is a value, not a side effect: [`SandboxTier`] records which rung
//! was reached so health, capability discovery and observation provenance can all
//! report the truth instead of each re-deriving it.

use crate::SUPPORTED_API_VERSIONS;

/// Which rung of the degradation ladder answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SandboxTier {
    /// Neither API nor CLI is reachable; the embedded fixture answers.
    ///
    /// This is still a *usable* provider for regression purposes, which is why
    /// it is a tier rather than an error (DD-PLG §8).
    Fixture,
    /// The experimental Docker Sandboxes API answered.
    Native,
    /// Only the Docker CLI answered; observation is metadata-only.
    Cli,
}

impl SandboxTier {
    /// Wire name for events, metadata and the diagnostics bundle.
    pub fn as_str(self) -> &'static str {
        match self {
            SandboxTier::Fixture => "fixture",
            SandboxTier::Native => "native",
            SandboxTier::Cli => "cli",
        }
    }

    /// Whether lifecycle control works from this tier.
    ///
    /// The fixture tier deliberately reports `false`: a fixture world is not a
    /// real runtime, so claiming control is available would let a caller try to
    /// start something that cannot start (RD §9).
    pub fn control_is_available(self) -> bool {
        !matches!(self, SandboxTier::Fixture)
    }

    /// Whether this tier can produce real observation data.
    pub fn observation_is_real(self) -> bool {
        matches!(self, SandboxTier::Native | SandboxTier::Cli)
    }
}

/// What the API probe concluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiSupport {
    /// Detected API version, when the endpoint answered at all.
    pub detected_version: Option<String>,
    /// Whether that version is one this provider understands.
    pub supported: bool,
}

impl ApiSupport {
    /// The experimental API answered and its version is supported.
    pub fn supported(version: impl Into<String>) -> Self {
        Self {
            detected_version: Some(version.into()),
            supported: true,
        }
    }

    /// The API answered but with a version outside [`SUPPORTED_API_VERSIONS`].
    ///
    /// This is reported rather than hidden: an unsupported version must be
    /// visible as metadata so an operator can tell it apart from an absent API.
    pub fn unsupported(version: impl Into<String>) -> Self {
        Self {
            detected_version: Some(version.into()),
            supported: false,
        }
    }

    /// The API did not answer at all.
    pub fn absent() -> Self {
        Self {
            detected_version: None,
            supported: false,
        }
    }

    /// Whether the API rung should be used.
    pub fn usable(&self) -> bool {
        self.supported
    }
}

/// Outcome of probing the ladder, rung by rung.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeOutcome {
    /// Rung reached.
    pub tier: SandboxTier,
    /// API probe result, retained even when the ladder fell past it.
    pub api: ApiSupport,
    /// Whether the Docker CLI answered.
    pub cli_available: bool,
    /// Human-readable reason for the tier reached.
    pub reason: String,
}

impl ProbeOutcome {
    /// Choose a tier from an API probe and a CLI probe, in the order DD-PLG §8
    /// mandates.
    ///
    /// The ordering is the whole point of this function, so it is expressed once
    /// here rather than being re-implemented at each call site.
    pub fn resolve(api: ApiSupport, cli_available: bool) -> Self {
        if api.usable() {
            return Self {
                tier: SandboxTier::Native,
                reason: format!(
                    "docker sandboxes API {} is supported",
                    api.detected_version.as_deref().unwrap_or("?")
                ),
                api,
                cli_available,
            };
        }
        if cli_available {
            let reason = match &api.detected_version {
                Some(v) => format!(
                    "docker sandboxes API {v} is not in the supported set; \
                     falling back to CLI"
                ),
                None => "docker sandboxes API is not available; falling back to CLI".to_string(),
            };
            return Self {
                tier: SandboxTier::Cli,
                reason,
                api,
                cli_available,
            };
        }
        let reason = match &api.detected_version {
            Some(v) => format!(
                "docker sandboxes API {v} is unsupported and the docker CLI is \
                 absent; serving the embedded fixture world"
            ),
            None => "docker sandboxes API is absent and the docker CLI is absent; \
                 serving the embedded fixture world"
                .to_string(),
        };
        Self {
            tier: SandboxTier::Fixture,
            reason,
            api,
            cli_available,
        }
    }

    /// Health implied by the tier reached.
    pub fn health(&self) -> sandtree_sdk::ports::ProviderHealth {
        use sandtree_sdk::ports::ProviderHealth;
        match self.tier {
            // Fully native.
            SandboxTier::Native => ProviderHealth::Healthy,
            // Control works but observation is metadata-only: degraded, NOT
            // unavailable, because control is still available (ADR-OBS-001).
            SandboxTier::Cli => ProviderHealth::Degraded {
                reason: self.reason.clone(),
            },
            // No real runtime at all. Reporting `Unavailable` here is what keeps
            // the kernel from deleting anything on our account; the fixture still
            // answers `discover`, so reconcile sees resources rather than an error.
            SandboxTier::Fixture => ProviderHealth::Unavailable {
                reason: self.reason.clone(),
            },
        }
    }
}

/// Whether a detected API version string is one this provider understands.
pub fn is_supported_version(version: &str) -> bool {
    SUPPORTED_API_VERSIONS.contains(&version)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sandtree_sdk::ports::ProviderHealth;

    #[test]
    fn native_wins_when_the_api_is_supported() {
        let o = ProbeOutcome::resolve(ApiSupport::supported("0.1"), true);
        assert_eq!(o.tier, SandboxTier::Native);
        assert_eq!(o.health(), ProviderHealth::Healthy);
    }

    #[test]
    fn an_unsupported_api_version_falls_to_the_cli() {
        let o = ProbeOutcome::resolve(ApiSupport::unsupported("9.9"), true);
        assert_eq!(o.tier, SandboxTier::Cli);
        assert!(
            o.reason.contains("9.9"),
            "reason must name the version: {o:?}"
        );
        // Degraded, not unavailable: control still works via the CLI.
        assert!(matches!(o.health(), ProviderHealth::Degraded { .. }));
    }

    #[test]
    fn an_absent_api_falls_to_the_cli() {
        let o = ProbeOutcome::resolve(ApiSupport::absent(), true);
        assert_eq!(o.tier, SandboxTier::Cli);
    }

    #[test]
    fn no_api_and_no_cli_reaches_the_fixture_tier() {
        let o = ProbeOutcome::resolve(ApiSupport::absent(), false);
        assert_eq!(o.tier, SandboxTier::Fixture);
        assert!(matches!(o.health(), ProviderHealth::Unavailable { .. }));
    }

    #[test]
    fn an_unsupported_version_without_a_cli_also_reaches_the_fixture() {
        // Both failure modes must land in the same place, or "unsupported" and
        // "absent" would need separate handling downstream.
        let o = ProbeOutcome::resolve(ApiSupport::unsupported("9.9"), false);
        assert_eq!(o.tier, SandboxTier::Fixture);
    }

    #[test]
    fn the_fixture_tier_never_claims_control_is_available() {
        // A fixture world cannot really start or stop anything.
        assert!(!SandboxTier::Fixture.control_is_available());
        assert!(SandboxTier::Native.control_is_available());
        assert!(SandboxTier::Cli.control_is_available());
    }

    #[test]
    fn the_fixture_tier_never_claims_real_observation() {
        assert!(!SandboxTier::Fixture.observation_is_real());
        assert!(SandboxTier::Native.observation_is_real());
        // CLI gives metadata about a real sandbox, so it is real, just thinner.
        assert!(SandboxTier::Cli.observation_is_real());
    }

    #[test]
    fn degraded_health_keeps_control_available() {
        // ADR-OBS-001: an unusable observation channel must not disable control.
        let o = ProbeOutcome::resolve(ApiSupport::absent(), true);
        assert!(o.health().control_is_available());
    }

    #[test]
    fn version_support_follows_the_declared_list() {
        assert!(is_supported_version("0.1"));
        assert!(is_supported_version("0.2"));
        assert!(!is_supported_version("0.3"));
        assert!(!is_supported_version(""));
    }

    #[test]
    fn an_absent_api_reports_no_detected_version() {
        let a = ApiSupport::absent();
        assert_eq!(a.detected_version, None);
        assert!(!a.usable());
    }

    #[test]
    fn every_tier_has_a_distinct_wire_name() {
        let names = [
            SandboxTier::Fixture.as_str(),
            SandboxTier::Native.as_str(),
            SandboxTier::Cli.as_str(),
        ];
        let mut sorted: Vec<&str> = names.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            3,
            "tier wire names must be distinct: {names:?}"
        );
    }
}
