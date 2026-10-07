//! ADR-OBS-001: control and observation are separate planes.
//!
//! The invariant has three parts, and this file defends each one:
//!
//! 1. an observation failure is a **typed result**, not an error (FR-079);
//! 2. it never becomes "the resource does not exist", and the scripted world
//!    is unchanged afterwards;
//! 3. it never disables the control plane's view of the resource — the
//!    capabilities it reports stay exactly as they were.
//!
//! The one deliberate exception is asserted too: a rejected envelope and an
//! escaping guest path must *surface* (DD-OBS §12, NFR-S08), so the "never an
//! error" rule cannot be satisfied by swallowing hostile input.

mod common;

use common::{id, provider_from, scenario_id, SCENARIOS};
use sandtree_mock_observation::{
    FaultDisposition, ObservationFault, ObservationFixture, ResourceObservation,
    ScriptedObservation,
};
use sandtree_model::error::ErrorCode;
use sandtree_observation_model::{
    ObservationCapabilities, ObservationDomain, ObservationHealth, ObservationMode,
    ObservationRequest, ObservationSnapshot,
};
use sandtree_sdk::ports::ObservationProvider;
use serde_json::json;

/// The shape `tests/integration`'s `with_degraded_observation` already asserts,
/// reproduced against the mock and extended with the parts the integration test
/// cannot reach: a typed code, a deterministic warning, and a world that did not
/// change.
#[tokio::test]
async fn a_degraded_observation_plane_yields_an_unavailable_snapshot() {
    let provider = provider_from(SCENARIOS);
    let id = scenario_id("wsb-probe-dead");
    let snap = provider
        .observe(&ObservationRequest::new(
            id.clone(),
            vec![ObservationDomain::System],
        ))
        .await
        .expect("a degraded plane still answers");

    assert_eq!(
        snap.health,
        ObservationHealth::Unavailable,
        "a degraded plane must report Unavailable, not Healthy"
    );
    assert!(
        snap.values.is_empty(),
        "a degraded plane must not fabricate domain values: {:?}",
        snap.values
    );
    assert!(
        snap.warnings.iter().any(|w| w.contains("ST-OBS-004")),
        "the reason must survive into the snapshot: {:?}",
        snap.warnings
    );
    assert!(
        snap.warnings
            .iter()
            .any(|w| w.contains("bridge handshake refused")),
        "the fixture reason must survive verbatim: {:?}",
        snap.warnings
    );
    assert_eq!(
        snap.resource_id, id,
        "the snapshot names the resource asked for"
    );
    assert!(
        snap.weakest_trust().is_none(),
        "no value means no trust claim at all"
    );
}

/// The failure must not un-create the resource: the scripted world is the
/// control plane's view, and observing does not edit it.
#[tokio::test]
async fn an_observation_failure_never_removes_the_resource() {
    let provider = provider_from(SCENARIOS);
    let before = provider.resource_ids();
    let id = scenario_id("wsb-probe-dead");

    for _ in 0..3 {
        let snap = provider
            .observe(&ObservationRequest::new(
                id.clone(),
                vec![ObservationDomain::System],
            ))
            .await
            .expect("still answers");
        assert_eq!(snap.health, ObservationHealth::Unavailable);
    }

    assert!(
        provider.has_resource(&id),
        "the resource must still be scripted"
    );
    assert_eq!(
        provider.resource_ids(),
        before,
        "three failed observations must not change the world"
    );
    assert!(
        provider
            .capabilities(&id)
            .await
            .expect("capabilities still answer")
            .supports(ObservationMode::Probe),
        "the port still exists after a failed collection"
    );
}

/// Every fault the design treats as degradable must come back as a snapshot.
/// The codes are checked too, so a fault cannot silently change shape.
#[tokio::test]
async fn every_degradable_fault_yields_a_snapshot_rather_than_an_error() {
    let cases: Vec<(&str, ObservationFault, ObservationHealth, &str)> = vec![
        (
            "deadline",
            ObservationFault::DeadlineExceeded {
                reason: "collector did not answer".into(),
                deadline_ms: 2_000,
            },
            ObservationHealth::Unavailable,
            "ST-OBS-002",
        ),
        (
            "bootstrap",
            ObservationFault::ProbeBootstrapFailed {
                reason: "bridge handshake refused".into(),
            },
            ObservationHealth::Unavailable,
            "ST-OBS-004",
        ),
        (
            "credential",
            ObservationFault::CredentialDenied {
                reason: "no credential in the store".into(),
            },
            ObservationHealth::Unavailable,
            "ST-OBS-006",
        ),
        (
            "partial",
            ObservationFault::PartialCoverage {
                missing_domains: vec![ObservationDomain::Filesystem],
            },
            ObservationHealth::Degraded,
            "filesystem",
        ),
        (
            "nested-docker",
            ObservationFault::NestedDockerUnavailable {
                reason: "nested engine pipe closed".into(),
            },
            ObservationHealth::Degraded,
            "ST-OBS-010",
        ),
    ];

    for (name, fault, expected_health, expected_marker) in cases {
        let resource = ResourceObservation::new(&["mock", name])
            .with_modes(&[ObservationMode::Probe])
            .with_domains(&[
                ObservationDomain::System,
                ObservationDomain::Filesystem,
                ObservationDomain::Docker,
            ])
            .with_value(ObservationDomain::System, json!({"os": "windows"}))
            .with_value(ObservationDomain::Filesystem, json!({"entries": []}))
            .with_value(ObservationDomain::Docker, json!({"containers": []}))
            .with_trust(sandtree_observation_model::TrustLevel::GuestProbe)
            .with_fault(fault);
        let provider =
            ScriptedObservation::new(ObservationFixture::new("mock-probe").with_resource(resource));
        let snap = provider
            .observe(&ObservationRequest::new(
                id(&["mock", name]),
                vec![
                    ObservationDomain::System,
                    ObservationDomain::Filesystem,
                    ObservationDomain::Docker,
                ],
            ))
            .await
            .unwrap_or_else(|e| panic!("{name} must degrade, not error: {e}"));

        assert_eq!(snap.health, expected_health, "{name} health");
        assert!(
            snap.warnings.iter().any(|w| w.contains(expected_marker)),
            "{name} warning must mention {expected_marker}: {:?}",
            snap.warnings
        );
        assert_eq!(
            provider.observe_calls(),
            1,
            "{name} must be collected, not cached around"
        );
    }
}

/// The two faults that must never be degraded away keep their codes, and the
/// resource stays in the world even then.
#[tokio::test]
async fn protocol_and_security_faults_surface_and_are_auditable() {
    let cases: Vec<(&str, ObservationFault, ErrorCode)> = vec![
        (
            "envelope",
            ObservationFault::InvalidEnvelope {
                reason: "sequence 4 is not greater than the session sequence 7".into(),
            },
            ErrorCode::OBS_ENVELOPE_INVALID,
        ),
        (
            "escape",
            ObservationFault::GuestPathEscape {
                path: "../outside/taken.txt".into(),
            },
            ErrorCode::OBS_GUEST_PATH_ESCAPE,
        ),
    ];

    for (name, fault, code) in cases {
        let resource = ResourceObservation::new(&["mock", name])
            .with_modes(&[ObservationMode::Probe])
            .with_domains(&[ObservationDomain::System])
            .with_value(ObservationDomain::System, json!({"os": "windows"}))
            .with_trust(sandtree_observation_model::TrustLevel::GuestProbe)
            .with_fault(fault);
        let provider =
            ScriptedObservation::new(ObservationFixture::new("mock-probe").with_resource(resource));
        let id = id(&["mock", name]);

        // Three attempts, three surfaced errors: a hostile payload must never be
        // quietly converted into "nothing to report".
        for _ in 0..3 {
            let err = provider
                .observe(&ObservationRequest::new(
                    id.clone(),
                    vec![ObservationDomain::System],
                ))
                .await
                .expect_err("must surface");
            assert_eq!(err.code, code, "{name} code");
            assert!(
                err.detail.is_some(),
                "{name} must carry provider detail for the audit log"
            );
        }
        assert!(
            provider.has_resource(&id),
            "{name}: a surfaced violation does not delete the resource either"
        );
    }
}

/// Partial coverage keeps what arrived. "Degraded" must not degrade into
/// "absent" (DD-OBS §2) and must not over-claim either.
#[tokio::test]
async fn partial_coverage_keeps_the_domains_that_did_arrive() {
    let provider = provider_from(SCENARIOS);
    let id = scenario_id("wsb-partial");
    let requested = vec![ObservationDomain::System, ObservationDomain::Process];
    let snap = provider
        .observe(&ObservationRequest::new(id.clone(), requested.clone()))
        .await
        .expect("partial coverage is a state, not an error");

    assert_eq!(snap.health, ObservationHealth::Degraded);
    assert!(
        snap.get(ObservationDomain::System).is_some(),
        "the domain that answered must survive"
    );
    assert_eq!(
        snap.missing_domains(&requested),
        vec!["process"],
        "the withheld domain is named, not silently dropped"
    );
    assert!(
        !snap.covers_all(&requested),
        "the snapshot must not claim full coverage"
    );
    assert!(
        snap.warnings.iter().any(|w| w.contains("process")),
        "warnings: {:?}",
        snap.warnings
    );
}

/// FR-079 also requires metadata-only to stay available while a richer mode is
/// down: the control surface must keep something to show.
#[tokio::test]
async fn the_metadata_floor_stays_available_while_the_rich_mode_is_down() {
    let provider = provider_from(SCENARIOS);
    let id = scenario_id("wsb-probe-dead");
    let caps: ObservationCapabilities = provider.capabilities(&id).await.expect("capabilities");

    assert_eq!(
        caps.modes,
        vec![ObservationMode::Probe, ObservationMode::Metadata],
        "a dead probe must not delete the metadata floor from the caps"
    );
    assert!(caps.supports(ObservationMode::Metadata));

    // The rich mode yields Unavailable...
    let probe = provider
        .observe(&ObservationRequest::new(
            id.clone(),
            vec![ObservationDomain::System],
        ))
        .await
        .expect("probe answers with a snapshot");
    assert_eq!(probe.health, ObservationHealth::Unavailable);

    // ...and the control plane still has a working observation surface.
    assert!(provider.has_resource(&id));
}

/// A fixture may deliberately override the disposition so callers can be tested
/// against the error branch of a transient fault. This is a test affordance; the
/// design default for a bootstrap failure stays a snapshot (see the table in
/// `fault.rs`).
#[tokio::test]
async fn a_disposition_override_can_force_the_error_branch() {
    let resource = ResourceObservation::new(&["mock", "forced"])
        .with_modes(&[ObservationMode::Probe])
        .with_domains(&[ObservationDomain::System])
        .with_value(ObservationDomain::System, json!({"os": "windows"}))
        .with_fault(ObservationFault::ProbeBootstrapFailed {
            reason: "bridge refused".into(),
        })
        .with_disposition(FaultDisposition::SurfaceError);
    let provider =
        ScriptedObservation::new(ObservationFixture::new("mock-probe").with_resource(resource));

    let err = provider
        .observe(&ObservationRequest::new(
            id(&["mock", "forced"]),
            vec![ObservationDomain::System],
        ))
        .await
        .expect_err("the override must surface the fault");
    assert_eq!(err.code, ErrorCode::OBS_PROBE_BOOTSTRAP);
}

/// A channel may report trouble without a coverage gap — a sub-collector
/// unhappy, but every requested domain answered. That is still `Degraded`, and
/// it must not be laundered into `Healthy` by the coverage rule alone.
#[tokio::test]
async fn a_declared_degraded_channel_stays_degraded_with_complete_coverage() {
    let provider = provider_from(SCENARIOS);
    let id = scenario_id("wsb-subcollector-degraded");
    let requested = vec![ObservationDomain::System];
    let snap = provider
        .observe(&ObservationRequest::new(id, requested.clone()))
        .await
        .expect("answers");

    assert!(
        snap.covers_all(&requested),
        "this world answers everything it was asked: {:?}",
        snap.values
    );
    assert!(
        snap.get(ObservationDomain::System).is_some(),
        "and it must say so with a real value"
    );
    assert_eq!(
        snap.health,
        ObservationHealth::Degraded,
        "a provider reporting trouble must not be reported as healthy"
    );
    assert!(
        !snap.is_partial(),
        "no value is partial here; the channel itself is unhappy"
    );
}

/// The nested-engine world declares itself degraded *and* marks the docker
/// domain partial: the declared state and the coverage rule agree.
#[tokio::test]
async fn a_declared_and_derived_degradation_agree() {
    let provider = provider_from(SCENARIOS);
    let snap = provider
        .observe(&ObservationRequest::new(
            scenario_id("docker-nested-down"),
            vec![ObservationDomain::System, ObservationDomain::Docker],
        ))
        .await
        .expect("answers");
    assert_eq!(snap.health, ObservationHealth::Degraded);
    assert!(snap
        .get(ObservationDomain::Docker)
        .expect("docker present")
        .is_partial());
}

/// A missing observation mode is a typed `ST-OBS-001`, not a panic and not a
/// fabricated empty snapshot.
#[tokio::test]
async fn a_request_no_mode_can_serve_is_a_typed_no_strategy_error() {
    let resource = ResourceObservation::new(&["mock", "docker-only"])
        .with_modes(&[ObservationMode::Native])
        .with_domains(&[ObservationDomain::System, ObservationDomain::Docker])
        .with_value(ObservationDomain::System, json!({"os": "linux"}))
        .with_value(ObservationDomain::Docker, json!({"containers": []}));
    let provider =
        ScriptedObservation::new(ObservationFixture::new("mock-native").with_resource(resource));

    let err = provider
        .observe(&ObservationRequest::new(
            id(&["mock", "docker-only"]),
            vec![ObservationDomain::Filesystem],
        ))
        .await
        .expect_err("no mode serves filesystem");
    assert_eq!(err.code, ErrorCode::OBS_NO_STRATEGY);
    assert!(err.message.contains("no mode that can serve"));
}

/// An unscripted resource is a mock bookkeeping fact. The message has to say so,
/// because a caller that read it as "the resource does not exist" would be
/// deriving absence from observation — exactly what ADR-OBS-001 forbids.
#[tokio::test]
async fn an_unscripted_resource_does_not_claim_the_resource_is_absent() {
    let provider = provider_from(SCENARIOS);
    let err = provider
        .observe(&ObservationRequest::new(
            scenario_id("never-scripted"),
            vec![ObservationDomain::System],
        ))
        .await
        .expect_err("not scripted");

    assert_eq!(err.code, ErrorCode::OBS_NO_STRATEGY);
    for phrase in ["not scripted", "makes no claim about the host"] {
        assert!(
            err.message.contains(phrase),
            "message must say {phrase:?}: {}",
            err.message
        );
    }
    for absent in ["does not exist", "no such resource", "not found"] {
        assert!(
            !err.message.contains(absent),
            "message must not read as an absence claim: {}",
            err.message
        );
    }
}

/// The trust of an unavailable snapshot is unstated, not "unverified": no value
/// was reported, so there is nothing to trust. A fixture that would otherwise
/// claim `host_native` must not leak that claim into a dead snapshot.
#[tokio::test]
async fn a_dead_channel_reports_no_trust_at_all() {
    let snap: ObservationSnapshot = provider_from(SCENARIOS)
        .observe(&ObservationRequest::new(
            scenario_id("wsb-probe-dead"),
            vec![ObservationDomain::System],
        ))
        .await
        .expect("answers");
    assert_eq!(snap.weakest_trust(), None);
    assert!(!snap.is_security_authoritative());
    assert!(
        !snap.is_security_authoritative(),
        "no values can never be security authoritative"
    );
}
