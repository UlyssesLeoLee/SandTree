//! Trust ceiling arithmetic for the mock observation plane.
//!
//! **ADR-OBS-003 / NFR-O01 — trust is never raised.** Everything here exists so
//! that a fixture which *asks* for a stronger trust level than its mode can
//! justify is refused rather than obeyed, and so that the refusal is visible in
//! the snapshot instead of being a silent clamp.
//!
//! # The ordinal trap
//!
//! [`TrustLevel`] is declared strongest-first for display, so its derived
//! [`Ord`] runs **opposite** to trust strength:
//!
//! ```text
//! HostNative < ProviderNative < RemoteExec < GuestProbe < Unverified   (derived Ord)
//! rank:       4            3              2           1          0
//! ```
//!
//! Comparing with `>` or calling [`Ord::max`] on the enum therefore *lowers*
//! trust while reading as if it raised it. Every comparison in this module goes
//! through [`TrustLevel::rank`] instead, and the crate's tests pin that down by
//! asserting the derived order and the rank order disagree.
//!
//! # Mode ceilings
//!
//! Each observation mode can only justify the trust rung its data source
//! actually earns (DD-OBS §4, §6, and `schemas/observation_provider_matrix.csv`):
//!
//! | mode | ceiling | why |
//! | --- | --- | --- |
//! | `native` | `provider_native` | an authenticated provider/runtime API |
//! | `exec` | `remote_exec` | output of a host-initiated guest command |
//! | `probe` | `guest_probe` | a program running inside the guest |
//! | `metadata` | `host_native` | only host-visible state exists |
//!
//! A fixture may declare a ceiling *below* the mode's default (an `exec`
//! provider that cannot bind a command to a session reports `guest_probe`).
//! It may never declare one above it.

use sandtree_observation_model::{ObservationMode, TrustLevel};

/// The strongest trust level an observation mode may report (ADR-OBS-003).
///
/// This is the whole mode → trust mapping; there is no second source for it in
/// the crate, so a provider cannot pick a different table by accident.
pub fn mode_trust_ceiling(mode: ObservationMode) -> TrustLevel {
    match mode {
        // A supported read API on the provider or runtime. Authenticated, but
        // not the host OS itself (DD-OBS §6 "provider_native").
        ObservationMode::Native => TrustLevel::ProviderNative,
        // A bounded guest command: real data, bound to a session, not host state.
        ObservationMode::Exec => TrustLevel::RemoteExec,
        // A probe inside the guest. Never security authoritative, ever.
        ObservationMode::Probe => TrustLevel::GuestProbe,
        // Metadata mode can only report what the host already sees about the
        // resource, which is precisely what `host_native` means.
        ObservationMode::Metadata => TrustLevel::HostNative,
    }
}

/// Outcome of resolving one requested trust level against a mode's ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustDecision {
    /// The trust level the fixture asked for.
    pub requested: TrustLevel,
    /// The ceiling actually applied, after any fixture override was lowered.
    pub ceiling: TrustLevel,
    /// The trust level that will be written into the provenance.
    pub effective: TrustLevel,
    /// Whether an upgrade was refused, i.e. `requested.rank() > ceiling.rank()`.
    pub refused_upgrade: bool,
    /// Whether the fixture declared a ceiling above the mode's own ceiling.
    pub refused_ceiling: bool,
}

/// Resolve a requested trust level against a mode's ceiling.
///
/// `declared_ceiling` is the fixture's optional override. It is combined with
/// the mode default using [`TrustLevel::at_most`], so an override can only
/// lower the ceiling — a fixture cannot talk its way into a stronger level by
/// declaring one. A refused override is reported in
/// [`TrustDecision::refused_ceiling`] rather than dropped silently.
///
/// The result is always `effective == requested.at_most(ceiling)`, and
/// `effective.rank() <= ceiling.rank()` holds for every input, including the
/// "fixture asks for `host_native` over a probe" case that the invariant is
/// about.
pub fn resolve_trust(
    mode: ObservationMode,
    declared_ceiling: Option<TrustLevel>,
    requested: TrustLevel,
) -> TrustDecision {
    // NFR-O01: an override narrows, it never widens. `at_most` is the only
    // merge used anywhere in this crate.
    let mode_ceiling = mode_trust_ceiling(mode);
    let ceiling = match declared_ceiling {
        Some(declared) => declared.at_most(mode_ceiling),
        None => mode_ceiling,
    };
    let effective = requested.at_most(ceiling);
    TrustDecision {
        requested,
        ceiling,
        effective,
        refused_upgrade: requested.rank() > ceiling.rank(),
        refused_ceiling: declared_ceiling
            .map(|d| d.rank() > mode_ceiling.rank())
            .unwrap_or(false),
    }
}

/// Warning text recorded on a snapshot whose trust upgrade was refused.
///
/// Exposed so the provider and the tests assert on one string instead of
/// re-deriving the phrasing at each site.
pub fn refusal_warning(mode: ObservationMode, decision: &TrustDecision) -> String {
    format!(
        "trust upgrade refused (ADR-OBS-003): mode {} requested {} but its ceiling is {}; reporting {}",
        mode.as_str(),
        decision.requested.as_str(),
        decision.ceiling.as_str(),
        decision.effective.as_str()
    )
}

/// Warning text recorded when a fixture declares a ceiling above its mode's.
///
/// Separate from [`refusal_warning`]: here the claim *about the ceiling* was
/// refused while the reported value may still be acceptable, and someone
/// debugging a fixture needs to see which of the two happened.
pub fn ceiling_refusal_warning(mode: ObservationMode, decision: &TrustDecision) -> String {
    format!(
        "declared trust ceiling refused (ADR-OBS-003): mode {} cannot exceed {}; using {}",
        mode.as_str(),
        mode_trust_ceiling(mode).as_str(),
        decision.ceiling.as_str()
    )
}

/// Whether a trust level is permitted for a mode without resolving anything.
///
/// Equivalent to `resolve_trust(..).refused_upgrade` inverted, kept as a named
/// predicate because tests assert against it far more often than against the
/// whole decision struct.
pub fn is_permitted(mode: ObservationMode, trust: TrustLevel) -> bool {
    trust.rank() <= mode_trust_ceiling(mode).rank()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The derived `Ord` and the trust strength must stay opposite. If this ever
    /// fails, every `>` comparison written against `TrustLevel` in this crate is
    /// now a trust *downgrade* and the ceilings below need re-derivation.
    #[test]
    fn derived_ord_is_the_inverse_of_rank() {
        assert!(TrustLevel::HostNative < TrustLevel::GuestProbe);
        assert!(TrustLevel::GuestProbe.rank() < TrustLevel::HostNative.rank());
        assert!(
            TrustLevel::HostNative.rank() > TrustLevel::Unverified.rank(),
            "rank 0 is untrusted and must sort below host-native"
        );
    }

    /// Each mode's ceiling, spelled out so a change to the table is visible.
    #[test]
    fn mode_ceilings_match_the_design_table() {
        assert_eq!(
            mode_trust_ceiling(ObservationMode::Native),
            TrustLevel::ProviderNative
        );
        assert_eq!(
            mode_trust_ceiling(ObservationMode::Exec),
            TrustLevel::RemoteExec
        );
        assert_eq!(
            mode_trust_ceiling(ObservationMode::Probe),
            TrustLevel::GuestProbe
        );
        assert_eq!(
            mode_trust_ceiling(ObservationMode::Metadata),
            TrustLevel::HostNative
        );
    }

    /// The headline invariant: `guest_probe` cannot become `host_native`.
    #[test]
    fn guest_probe_is_never_promoted_by_resolution() {
        let d = resolve_trust(ObservationMode::Probe, None, TrustLevel::HostNative);
        assert_eq!(d.requested, TrustLevel::HostNative);
        assert_eq!(d.ceiling, TrustLevel::GuestProbe);
        assert_eq!(d.effective, TrustLevel::GuestProbe);
        assert!(d.refused_upgrade);
        assert!(!is_permitted(ObservationMode::Probe, TrustLevel::HostNative));
        assert!(!is_permitted(ObservationMode::Probe, TrustLevel::RemoteExec));
        assert!(is_permitted(ObservationMode::Probe, TrustLevel::GuestProbe));
    }

    /// A fixture-declared ceiling may lower the ceiling but never raise it.
    #[test]
    fn a_declared_ceiling_can_only_narrow() {
        let raised = resolve_trust(
            ObservationMode::Probe,
            Some(TrustLevel::HostNative),
            TrustLevel::HostNative,
        );
        assert_eq!(
            raised.ceiling,
            TrustLevel::GuestProbe,
            "a fixture must not raise the mode ceiling"
        );
        assert!(raised.refused_upgrade);
        assert!(raised.refused_ceiling);

        let lowered = resolve_trust(
            ObservationMode::Native,
            Some(TrustLevel::Unverified),
            TrustLevel::ProviderNative,
        );
        assert_eq!(lowered.ceiling, TrustLevel::Unverified);
        assert_eq!(lowered.effective, TrustLevel::Unverified);
        assert!(lowered.refused_upgrade);
        assert!(
            !lowered.refused_ceiling,
            "narrowing the ceiling is a legal request"
        );
    }

    /// A ceiling the mode already implies is neither a narrowing nor a refusal.
    #[test]
    fn an_implied_ceiling_is_neither_refusal_nor_downgrade() {
        let d = resolve_trust(
            ObservationMode::Probe,
            Some(TrustLevel::GuestProbe),
            TrustLevel::GuestProbe,
        );
        assert!(!d.refused_ceiling);
        assert!(!d.refused_upgrade);
        assert_eq!(d.effective, TrustLevel::GuestProbe);
    }

    /// A request at or below the ceiling passes through untouched.
    #[test]
    fn a_permitted_request_is_left_alone() {
        for (mode, trust) in [
            (ObservationMode::Metadata, TrustLevel::HostNative),
            (ObservationMode::Native, TrustLevel::ProviderNative),
            (ObservationMode::Exec, TrustLevel::RemoteExec),
            (ObservationMode::Probe, TrustLevel::GuestProbe),
            (ObservationMode::Probe, TrustLevel::Unverified),
            (ObservationMode::Metadata, TrustLevel::GuestProbe),
        ] {
            let d = resolve_trust(mode, None, trust);
            assert_eq!(d.effective, trust, "{mode:?} should accept {trust:?}");
            assert!(!d.refused_upgrade, "{mode:?} refused {trust:?}");
        }
    }

    /// The ceiling bound holds for every mode × trust pair, not just the probe
    /// case the invariant is named after.
    #[test]
    fn the_ceiling_bound_holds_for_every_pair() {
        for mode in [
            ObservationMode::Native,
            ObservationMode::Exec,
            ObservationMode::Probe,
            ObservationMode::Metadata,
        ] {
            for trust in [
                TrustLevel::HostNative,
                TrustLevel::ProviderNative,
                TrustLevel::RemoteExec,
                TrustLevel::GuestProbe,
                TrustLevel::Unverified,
            ] {
                let d = resolve_trust(mode, None, trust);
                assert!(
                    d.effective.rank() <= d.ceiling.rank(),
                    "{mode:?} emitted {:?} above ceiling {:?}",
                    d.effective,
                    d.ceiling
                );
                assert_eq!(
                    d.refused_upgrade,
                    trust.rank() > mode_trust_ceiling(mode).rank(),
                    "refusal flag disagrees with the ceiling for {mode:?}/{trust:?}"
                );
            }
        }
    }

    /// The warning names both sides of the refusal so a UI can show the gap.
    #[test]
    fn refusal_warning_names_requested_and_effective() {
        let d = resolve_trust(ObservationMode::Probe, None, TrustLevel::HostNative);
        let w = refusal_warning(ObservationMode::Probe, &d);
        assert!(w.contains("host_native"), "{w}");
        assert!(w.contains("guest_probe"), "{w}");
        assert!(w.contains("probe"), "{w}");
        assert!(!w.contains("provider_native"), "{w}");

        let c = ceiling_refusal_warning(ObservationMode::Probe, &d);
        assert!(c.contains("cannot exceed guest_probe"), "{c}");
        assert!(c.contains("using guest_probe"), "{c}");
        assert!(c.contains("probe"), "{c}");
        assert!(
            !c.contains("requested"),
            "a ceiling refusal must not claim a value was requested: {c}"
        );
    }
}