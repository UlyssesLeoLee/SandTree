//! Observation strategy negotiation (DD-OBS §4, FR-071).
//!
//! The selection order is fixed by the design: `Native → Exec → Probe →
//! Metadata`. Two properties matter more than the order itself:
//!
//! * **A plan must be explainable.** Every [`ObservationPlan`] carries the
//!   fallback chain and the reason each step was chosen, because "why can I not
//!   see inside this sandbox" is the single most common operator question.
//! * **The kernel never overrides the provider.** If a provider refuses a mode,
//!   negotiation continues down the chain; it does not decide that the refusal
//!   was wrong.

use sandtree_model::error::{DomainError, ErrorCode};
use sandtree_observation_model::{
    FallbackStep, ObservationCapabilities, ObservationDomain, ObservationMode, ObservationPlan,
};

/// Negotiates an observation mode for a resource.
#[derive(Debug, Clone, Default)]
pub struct StrategyNegotiator {
    /// Modes the kernel is permitted to use at all.
    ///
    /// A deployment that forbids guest probes sets this to
    /// `[Native, Exec, Metadata]` (NFR-S06), and negotiation then simply never
    /// proposes `Probe`.
    allowed_modes: Vec<ObservationMode>,
}

impl StrategyNegotiator {
    /// Negotiator allowing every mode.
    pub fn new() -> Self {
        Self {
            allowed_modes: vec![
                ObservationMode::Native,
                ObservationMode::Exec,
                ObservationMode::Probe,
                ObservationMode::Metadata,
            ],
        }
    }

    /// Restrict the permitted modes, preserving negotiation order.
    pub fn restricted(modes: Vec<ObservationMode>) -> Self {
        let mut allowed = modes;
        allowed.sort_unstable();
        allowed.dedup();
        Self {
            allowed_modes: allowed,
        }
    }

    /// Modes this negotiator may use.
    pub fn allowed_modes(&self) -> &[ObservationMode] {
        &self.allowed_modes
    }

    /// Choose a mode and build a plan.
    ///
    /// `requested` empty means "whatever the provider offers". The chosen mode
    /// is the first one that is both permitted here and supported by the
    /// provider *and* can serve at least one requested domain.
    pub fn negotiate(
        &self,
        caps: &ObservationCapabilities,
        requested: &[ObservationDomain],
    ) -> Result<ObservationPlan, DomainError> {
        if caps.modes.is_empty() {
            return Err(DomainError::new(
                ErrorCode::OBS_NO_STRATEGY,
                "provider reports no observation modes",
            ));
        }

        let wanted: Vec<ObservationDomain> = if requested.is_empty() {
            ObservationDomain::all().to_vec()
        } else {
            requested.to_vec()
        };

        let mut rejected: Vec<FallbackStep> = Vec::new();
        for mode in &self.allowed_modes {
            if !caps.supports(*mode) {
                rejected.push(FallbackStep::new(
                    *mode,
                    format!("provider does not offer {}", mode.as_str()),
                ));
                continue;
            }
            let declared = caps.domains_in(*mode);
            // A provider that declares no domain map at all is a
            // metadata-only provider (DD-PLG §12.5): it is still a usable
            // terminal mode, not a rejection.
            let usable: Vec<ObservationDomain> = wanted
                .iter()
                .copied()
                .filter(|d| declared.contains(d))
                .collect();
            if !declared.is_empty() && usable.is_empty() && !wanted.is_empty() {
                rejected.push(FallbackStep::new(
                    *mode,
                    format!("{} cannot serve the requested domains", mode.as_str()),
                ));
                continue;
            }
            // The plan carries the *requested* set, not just what the provider
            // could answer, so a coverage gap shows up as degraded rather than
            // being silently dropped from the plan.
            return Ok(ObservationPlan {
                mode: *mode,
                domains: wanted.clone(),
                deadline_ms: wanted
                    .iter()
                    .map(|d| d.default_deadline_ms())
                    .max()
                    .unwrap_or(2_000),
                max_age_ms: wanted
                    .iter()
                    .map(|d| d.default_max_age_ms())
                    .min()
                    .unwrap_or(5_000),
                collector_version: None,
                fallback_chain: rejected,
            });
        }

        // Metadata-only is the terminal state of the design, not a failure: a
        // provider that cannot see inside still yields a usable snapshot
        // (DD-PLG §12.5). Reaching here means even that is unavailable.
        Err(DomainError::new(
            ErrorCode::OBS_NO_STRATEGY,
            format!(
                "no permitted mode can serve the requested domains; tried {}",
                rejected
                    .iter()
                    .map(|f| format!("{} ({})", f.mode.as_str(), f.reason))
                    .collect::<Vec<_>>()
                    .join("; ")
            ),
        ))
    }

    /// Build the fallback plan for a mode that failed at run time.
    ///
    /// Used by the degradation path (FR-079, NFR-A04): when `Native` fails the
    /// provider retries with the next mode instead of the whole observation
    /// failing.
    pub fn fallback_plan(
        &self,
        caps: &ObservationCapabilities,
        from: ObservationMode,
        reason: &str,
    ) -> Option<ObservationPlan> {
        let mut chain = vec![FallbackStep::new(from, reason)];
        for mode in &self.allowed_modes {
            if *mode <= from {
                continue;
            }
            if !caps.supports(*mode) {
                chain.push(FallbackStep::new(
                    *mode,
                    format!("provider does not offer {}", mode.as_str()),
                ));
                continue;
            }
            let domains = caps.domains_in(*mode).to_vec();
            return Some(ObservationPlan {
                mode: *mode,
                domains: if domains.is_empty() {
                    ObservationDomain::all().to_vec()
                } else {
                    domains
                },
                deadline_ms: 2_000,
                max_age_ms: 5_000,
                collector_version: None,
                fallback_chain: chain,
            });
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn caps(modes: &[(ObservationMode, &[ObservationDomain])]) -> ObservationCapabilities {
        let mut c = ObservationCapabilities::default();
        for (m, d) in modes {
            c.modes.push(*m);
            c.domains.insert(m.as_str().to_string(), d.to_vec());
        }
        c
    }

    #[test]
    fn native_wins_when_offered() {
        let n = StrategyNegotiator::new();
        let c = caps(&[
            (ObservationMode::Native, &[ObservationDomain::Filesystem]),
            (ObservationMode::Probe, &[ObservationDomain::Filesystem]),
        ]);
        let plan = n.negotiate(&c, &[ObservationDomain::Filesystem]).unwrap();
        assert_eq!(plan.mode, ObservationMode::Native);
        assert_eq!(plan.domains, vec![ObservationDomain::Filesystem]);
    }

    #[test]
    fn probe_is_used_when_native_is_absent() {
        let n = StrategyNegotiator::new();
        let c = caps(&[
            (ObservationMode::Probe, &[ObservationDomain::Process]),
            (ObservationMode::Metadata, &[ObservationDomain::Health]),
        ]);
        let plan = n.negotiate(&c, &[ObservationDomain::Process]).unwrap();
        assert_eq!(plan.mode, ObservationMode::Probe);
    }

    #[test]
    fn fallback_chain_explains_every_rejected_mode() {
        let n = StrategyNegotiator::new();
        let c = caps(&[(ObservationMode::Metadata, &[ObservationDomain::Health])]);
        let plan = n.negotiate(&c, &[ObservationDomain::Health]).unwrap();
        assert_eq!(plan.mode, ObservationMode::Metadata);
        assert_eq!(plan.fallback_chain.len(), 3);
        assert!(plan
            .fallback_chain
            .iter()
            .all(|f| f.reason.contains("does not offer")));
    }

    #[test]
    fn kernel_policy_can_forbid_probe() {
        // NFR-S06: no guest injection.
        let n = StrategyNegotiator::restricted(vec![
            ObservationMode::Native,
            ObservationMode::Exec,
            ObservationMode::Metadata,
        ]);
        let c = caps(&[
            (ObservationMode::Probe, &[ObservationDomain::Health]),
            (ObservationMode::Metadata, &[ObservationDomain::Health]),
        ]);
        let plan = n.negotiate(&c, &[ObservationDomain::Health]).unwrap();
        assert_eq!(plan.mode, ObservationMode::Metadata);
        assert!(
            !n.allowed_modes().contains(&ObservationMode::Probe),
            "a forbidden mode must never appear in the negotiation order"
        );
        assert!(
            !plan
                .fallback_chain
                .iter()
                .any(|f| f.mode == ObservationMode::Probe),
            "a forbidden mode must not even be attempted"
        );
    }

    #[test]
    fn empty_request_means_every_domain() {
        let n = StrategyNegotiator::new();
        let c = caps(&[(ObservationMode::Native, &[])]);
        let plan = n.negotiate(&c, &[]).unwrap();
        assert_eq!(plan.mode, ObservationMode::Native);
        assert_eq!(plan.domains.len(), ObservationDomain::all().len());
    }

    #[test]
    fn plan_carries_requested_domains_so_gaps_are_visible() {
        let n = StrategyNegotiator::new();
        let c = caps(&[(ObservationMode::Native, &[ObservationDomain::System])]);
        let plan = n
            .negotiate(
                &c,
                &[ObservationDomain::System, ObservationDomain::Filesystem],
            )
            .unwrap();
        assert_eq!(
            plan.domains.len(),
            2,
            "the missing domain stays in the plan"
        );
    }

    #[test]
    fn no_modes_at_all_is_a_typed_error() {
        let n = StrategyNegotiator::new();
        let c = ObservationCapabilities::default();
        let err = n.negotiate(&c, &[ObservationDomain::System]).unwrap_err();
        assert_eq!(err.code, ErrorCode::OBS_NO_STRATEGY);
        assert!(
            !err.is_retryable(),
            "ST-OBS-001 is retry=no in schemas/observation_error_codes.csv"
        );
    }

    #[test]
    fn fallback_plan_moves_down_the_chain() {
        let n = StrategyNegotiator::new();
        let c = caps(&[
            (ObservationMode::Exec, &[ObservationDomain::System]),
            (ObservationMode::Metadata, &[ObservationDomain::Health]),
        ]);
        let p = n
            .fallback_plan(&c, ObservationMode::Native, "credential denied")
            .expect("exec is available");
        assert_eq!(p.mode, ObservationMode::Exec);
        assert_eq!(p.fallback_chain[0].reason, "credential denied");
        // Already at the bottom: no further fallback.
        assert!(n
            .fallback_plan(&c, ObservationMode::Metadata, "tried")
            .is_none());
    }

    #[test]
    fn limits_come_from_the_requested_domains() {
        let n = StrategyNegotiator::new();
        let c = caps(&[(
            ObservationMode::Native,
            &[ObservationDomain::System, ObservationDomain::Filesystem],
        )]);
        let plan = n
            .negotiate(
                &c,
                &[ObservationDomain::System, ObservationDomain::Filesystem],
            )
            .unwrap();
        assert_eq!(plan.deadline_ms, 10_000, "slowest domain wins the deadline");
        assert_eq!(plan.max_age_ms, 10_000, "fastest domain wins max-age");
    }

    #[test]
    fn caps_with_no_declared_domains_fall_back_to_all() {
        let c = ObservationCapabilities {
            modes: vec![ObservationMode::Metadata],
            domains: std::collections::BTreeMap::new(),
            max_concurrency: None,
            requires_native_credential: false,
        };
        let n = StrategyNegotiator::new();
        let plan = n.negotiate(&c, &[]).unwrap();
        assert_eq!(plan.mode, ObservationMode::Metadata);
        assert_eq!(plan.domains.len(), ObservationDomain::all().len());
        let _ = BTreeMap::<String, u8>::new();
    }
}
