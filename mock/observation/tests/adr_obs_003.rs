//! ADR-OBS-003: trust is never raised.
//!
//! The rule is small enough to state in one sentence — a value's trust may never
//! exceed what its observation mode can justify — and easy to break in one
//! place: a merge that picks the stronger of two levels, or a code path that
//! reads the enum's derived `Ord` instead of [`TrustLevel::rank`].
//!
//! So this file does not spot-check. It walks **every** mode × trust × health
//! combination (4 × 5 × 4 = 80 worlds), asserts the ceiling holds for each, and
//! then asserts the three specific attacks on it: a fixture that demands
//! `host_native`, a fixture that declares a ceiling above its mode's, and a
//! payload whose BLAKE3 evidence hash verifies.

mod common;

use common::{provider_from, scenario_id, SCENARIOS};
use sandtree_mock_observation::{
    mode_trust_ceiling, ObservationFault, ObservationFixture, ResourceObservation,
    ScriptedObservation,
};
use sandtree_observation_model::{
    ObservationDomain, ObservationHealth, ObservationMode, ObservationRequest, ObservationSnapshot,
    TrustLevel,
};
use sandtree_sdk::ports::ObservationProvider;
use serde_json::json;

/// Every mode, trust level and health the design defines.
const MODES: [ObservationMode; 4] = [
    ObservationMode::Native,
    ObservationMode::Exec,
    ObservationMode::Probe,
    ObservationMode::Metadata,
];
const TRUSTS: [TrustLevel; 5] = [
    TrustLevel::HostNative,
    TrustLevel::ProviderNative,
    TrustLevel::RemoteExec,
    TrustLevel::GuestProbe,
    TrustLevel::Unverified,
];
const HEALTHS: [ObservationHealth; 4] = [
    ObservationHealth::Healthy,
    ObservationHealth::Degraded,
    ObservationHealth::Unavailable,
    ObservationHealth::Stale,
];

/// One single-mode resource with complete coverage, for the exhaustive walk.
fn world(
    mode: ObservationMode,
    trust: TrustLevel,
    health: ObservationHealth,
) -> ResourceObservation {
    ResourceObservation::new(&["mock", "matrix"])
        .with_modes(&[mode])
        .with_domains(&[ObservationDomain::System, ObservationDomain::Health])
        .with_value(ObservationDomain::System, json!({"os": "windows"}))
        .with_trust(trust)
        .with_health(health)
        // A stale snapshot must declare an age, or the fixture is invalid.
        .with_freshness_ms(if health == ObservationHealth::Stale {
            120_000
        } else {
            0
        })
}

/// Observe a world, requesting exactly the domains that world declares.
///
/// Both the id and the domain set come from the world rather than from a
/// hard-coded constant, so a test cannot silently observe a resource the
/// fixture never declared — which would otherwise look like a trust assertion
/// that passed for the wrong reason.
fn observe(world: ResourceObservation) -> ObservationSnapshot {
    let id = world.id();
    let domains = world.domains().to_vec();
    let provider =
        ScriptedObservation::new(ObservationFixture::new("mock-matrix").with_resource(world));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime
        .block_on(provider.observe(&ObservationRequest::new(id, domains)))
        .expect("a scripted world without a security fault always answers")
}

/// The headline invariant, over all 80 combinations.
///
/// For every mode, every requested trust and every declared health, the emitted
/// trust is at or below the mode's ceiling — never above, whatever the fixture
/// asked for.
#[test]
fn no_mode_trust_health_combination_can_exceed_its_ceiling() {
    let mut checked = 0usize;
    for mode in MODES {
        let ceiling = mode_trust_ceiling(mode);
        for trust in TRUSTS {
            for health in HEALTHS {
                let snap = observe(world(mode, trust, health));
                let weakest = snap
                    .weakest_trust()
                    .unwrap_or_else(|| panic!("{mode:?}/{trust:?}/{health:?} produced no value"));
                assert!(
                    weakest.rank() <= ceiling.rank(),
                    "{mode:?} ceiling is {} but {trust:?} was reported as {weakest:?}",
                    ceiling.as_str()
                );
                for domain in ObservationDomain::all() {
                    if let Some(value) = snap.get(*domain) {
                        assert!(
                            value.provenance.trust.rank() <= ceiling.rank(),
                            "{mode:?}/{trust:?}/{health:?}: domain {domain:?} carries {:?} above ceiling {:?}",
                            value.provenance.trust,
                            ceiling
                        );
                    }
                }
                checked += 1;
            }
        }
    }
    assert_eq!(
        checked, 80,
        "every mode x trust x health pair must be walked"
    );
}

/// The refusal is visible, not silent: a fixture that asked for more than the
/// mode allows produces a snapshot *and* a warning naming both sides.
#[test]
fn a_refused_upgrade_is_reported_on_the_snapshot() {
    let snap = observe(world(
        ObservationMode::Probe,
        TrustLevel::HostNative,
        ObservationHealth::Healthy,
    ));

    assert_eq!(
        snap.weakest_trust(),
        Some(TrustLevel::GuestProbe),
        "a probe must report guest-probe even when the fixture demands host-native"
    );
    let refusal = snap
        .warnings
        .iter()
        .find(|w| w.contains("trust upgrade refused"))
        .expect("the refusal must be reported");
    assert!(
        refusal.contains("host_native") && refusal.contains("guest_probe"),
        "the warning must name both sides: {refusal}"
    );
    assert!(
        !snap.is_security_authoritative(),
        "guest-probe is never security authoritative"
    );
}

/// A fixture-declared ceiling above the mode's is ignored, and said so.
#[tokio::test]
async fn a_declared_ceiling_above_the_mode_ceiling_is_refused() {
    let provider = provider_from(SCENARIOS);
    let snap = provider
        .observe(&ObservationRequest::new(
            scenario_id("wsb-ceiling-raised"),
            vec![ObservationDomain::System],
        ))
        .await
        .expect("answers");

    assert_eq!(snap.mode, ObservationMode::Probe);
    assert_eq!(
        snap.weakest_trust(),
        Some(TrustLevel::GuestProbe),
        "the mode's ceiling, not the fixture's claim, decides"
    );
    assert!(
        snap.warnings
            .iter()
            .any(|w| w.contains("declared trust ceiling refused")),
        "a refused ceiling must be visible: {:?}",
        snap.warnings
    );
    assert!(
        snap.warnings
            .iter()
            .all(|w| !w.contains("trust upgrade refused")),
        "the value itself was legitimate, so only the ceiling claim is refused: {:?}",
        snap.warnings
    );
}

/// ADR-OBS-003's sharpest case: the payload's hash verifies, and the trust is
/// still `guest_probe`, because the guest produced the bytes.
#[test]
fn a_verified_evidence_hash_does_not_promote_guest_probe() {
    let snap = observe(
        world(
            ObservationMode::Probe,
            TrustLevel::GuestProbe,
            ObservationHealth::Healthy,
        )
        .evidence(true),
    );
    let value = snap.get(ObservationDomain::System).expect("system value");
    assert_eq!(value.provenance.trust, TrustLevel::GuestProbe);
    assert!(
        value.provenance.evidence_hash.is_some(),
        "the hash must actually be attached, or this test proves nothing"
    );
    assert!(
        !value.provenance.trust.is_security_authoritative(),
        "ADR-OBS-003: a verified guest payload is still not authoritative"
    );
    assert!(!snap.is_security_authoritative());
}

/// Metadata mode is the one mode whose ceiling is `host_native`, so it is the
/// only place a `host_native` value is legitimate. Everything below it must
/// still come out weaker.
#[test]
fn only_metadata_mode_may_report_host_native() {
    for mode in MODES {
        let snap = observe(world(
            mode,
            TrustLevel::HostNative,
            ObservationHealth::Healthy,
        ));
        let emitted = snap.weakest_trust().expect("a value");
        if mode == ObservationMode::Metadata {
            assert_eq!(emitted, TrustLevel::HostNative);
        } else {
            assert!(
                emitted != TrustLevel::HostNative,
                "{mode:?} must not report host-native, got {emitted:?}"
            );
        }
    }
}

/// The corpus exercises the attack fixtures end to end: the one that demands
/// `host_native`, and the one whose probe reports host-shaped state.
#[tokio::test]
async fn the_corpus_attack_fixtures_stay_below_their_ceiling() {
    let provider = provider_from(SCENARIOS);

    let attempt = provider
        .observe(&ObservationRequest::new(
            scenario_id("wsb-trust-upgrade-attempt"),
            vec![ObservationDomain::System],
        ))
        .await
        .expect("answers");
    assert_eq!(attempt.mode, ObservationMode::Probe);
    assert_eq!(attempt.weakest_trust(), Some(TrustLevel::GuestProbe));
    assert!(
        attempt
            .warnings
            .iter()
            .any(|w| w.contains("trust upgrade refused")),
        "the refusal must be visible: {:?}",
        attempt.warnings
    );
    // The hash is present and the trust still did not move.
    let system = attempt.get(ObservationDomain::System).expect("system");
    assert!(system.provenance.evidence_hash.is_some());
    assert_eq!(system.provenance.trust, TrustLevel::GuestProbe);

    let raised = provider
        .observe(&ObservationRequest::new(
            scenario_id("wsb-ceiling-raised"),
            vec![ObservationDomain::System],
        ))
        .await
        .expect("answers");
    assert!(
        raised
            .warnings
            .iter()
            .any(|w| w.contains("declared trust ceiling refused")),
        "raising a ceiling must be refused out loud: {:?}",
        raised.warnings
    );
    assert_eq!(raised.weakest_trust(), Some(TrustLevel::GuestProbe));
}

/// Whatever else happens, a probe-sourced snapshot is never authoritative. This
/// walks the whole corpus so a future fixture cannot introduce one.
#[tokio::test]
async fn no_probe_snapshot_in_the_corpus_is_security_authoritative() {
    let provider = provider_from(SCENARIOS);
    let mut checked = 0usize;
    for id in provider.resource_ids() {
        for domain in ObservationDomain::all() {
            let snap = match provider
                .observe(&ObservationRequest::new(id.clone(), vec![*domain]))
                .await
            {
                Ok(s) => s,
                // Surfaced security faults are audited, not returned.
                Err(_) => continue,
            };
            checked += 1;
            if snap.mode == ObservationMode::Probe {
                assert!(
                    !snap.is_security_authoritative(),
                    "{} reported an authoritative probe snapshot: {:?}",
                    id.as_str(),
                    snap.values
                );
            }
        }
    }
    assert!(
        checked >= 10,
        "the corpus walk must cover real work: {checked}"
    );
}

/// A degraded channel may withhold a value, but it must never restate the
/// withheld trust as if it had been observed.
#[test]
fn a_degraded_snapshot_does_not_invent_a_trust_claim() {
    let snap = observe(world(
        ObservationMode::Probe,
        TrustLevel::HostNative,
        ObservationHealth::Unavailable,
    ));
    assert_eq!(snap.health, ObservationHealth::Unavailable);
    // Unavailable-at-full-coverage keeps the fixture's declared state, but any
    // value that does exist must still respect the ceiling.
    for domain in ObservationDomain::all() {
        if let Some(value) = snap.get(*domain) {
            assert_ne!(
                value.provenance.trust,
                TrustLevel::HostNative,
                "{domain:?} leaked host-native trust through a degraded snapshot"
            );
        }
    }
}

/// A fault never becomes a path for raising trust: even when a fixture pairs a
/// bootstrap failure with a `host_native` claim, nothing is emitted.
#[test]
fn a_fault_does_not_open_a_trust_side_channel() {
    let world = ResourceObservation::new(&["mock", "fault-trust"])
        .with_modes(&[ObservationMode::Probe])
        .with_domains(&[ObservationDomain::System])
        .with_value(ObservationDomain::System, json!({"os": "windows"}))
        .with_trust(TrustLevel::HostNative)
        .evidence(true)
        .with_fault(ObservationFault::ProbeBootstrapFailed {
            reason: "bridge refused".into(),
        });
    let snap = observe(world);
    assert_eq!(snap.health, ObservationHealth::Unavailable);
    assert_eq!(
        snap.weakest_trust(),
        None,
        "a down channel reports no trust, so there is nothing to escalate"
    );
}
