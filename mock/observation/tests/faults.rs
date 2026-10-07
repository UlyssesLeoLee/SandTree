//! Every fault mode, on its own terms.
//!
//! `adr_obs_001.rs` argues that degradable faults stay snapshots. This file
//! pins down each fault's *observable* contract: the code it carries, whether it
//! is retryable per the shipped registry, what it leaves in the snapshot, and
//! which domains survive.

mod common;

use common::{id, provider_from, scenario_id, SCENARIOS};
use sandtree_mock_observation::{
    FaultDisposition, ObservationFault, ObservationFixture, ResourceObservation,
    ScriptedObservation,
};
use sandtree_model::error::ErrorCode;
use sandtree_observation_model::{
    ObservationDomain, ObservationHealth, ObservationMode, ObservationRequest, TrustLevel,
};
use sandtree_sdk::ports::ObservationProvider;
use serde_json::json;

fn world(name: &str, fault: ObservationFault) -> ScriptedObservation {
    ScriptedObservation::new(
        ObservationFixture::new("mock-probe").with_resource(
            ResourceObservation::new(&["mock", name])
                .with_modes(&[ObservationMode::Probe])
                .with_domains(&[
                    ObservationDomain::System,
                    ObservationDomain::Process,
                    ObservationDomain::Filesystem,
                    ObservationDomain::Docker,
                ])
                .with_value(ObservationDomain::System, json!({"os": "windows"}))
                .with_value(ObservationDomain::Process, json!({"pids": [1]}))
                .with_value(
                    ObservationDomain::Filesystem,
                    json!({"entries": ["workspace/a.txt"]}),
                )
                .with_value(ObservationDomain::Docker, json!({"containers": []}))
                .with_trust(TrustLevel::GuestProbe)
                .with_fault(fault),
        ),
    )
}

fn all() -> Vec<ObservationDomain> {
    vec![
        ObservationDomain::System,
        ObservationDomain::Process,
        ObservationDomain::Filesystem,
        ObservationDomain::Docker,
    ]
}

/// A collector that overruns its deadline: `ST-OBS-002`, retryable, and — the
/// point of FR-079 — a snapshot saying so rather than an error.
#[tokio::test]
async fn deadline_exceeded_is_a_retryable_unavailable_snapshot() {
    let fault = ObservationFault::DeadlineExceeded {
        reason: "collector did not answer the process query".into(),
        deadline_ms: 2_000,
    };
    assert_eq!(fault.code(), Some(ErrorCode::OBS_DEADLINE_EXCEEDED));
    assert!(
        fault.is_retryable(),
        "ST-OBS-002 is retryable per the registry"
    );

    let snap = world("deadline", fault)
        .observe(&ObservationRequest::new(id(&["mock", "deadline"]), all()))
        .await
        .expect("a deadline is a state, not an error");

    assert_eq!(snap.health, ObservationHealth::Unavailable);
    assert!(snap.values.is_empty(), "no partial guesses after a timeout");
    let warning = &snap.warnings[0];
    assert!(warning.starts_with("ST-OBS-002"), "{warning}");
    assert!(
        warning.contains("2000ms"),
        "the budget must be reported: {warning}"
    );
    assert!(warning.contains("did not answer"), "{warning}");
    assert_eq!(
        snap.resource_id,
        id(&["mock", "deadline"]),
        "the snapshot still names the resource"
    );
}

/// A rejected envelope surfaces with its reason in `detail` and a clean
/// `message` (DD-DATA §8: the message is what a UI renders).
#[tokio::test]
async fn an_invalid_envelope_surfaces_with_audit_detail() {
    let provider = world(
        "envelope",
        ObservationFault::InvalidEnvelope {
            reason: "nonce belongs to another session".into(),
        },
    );
    let err = provider
        .observe(&ObservationRequest::new(id(&["mock", "envelope"]), all()))
        .await
        .expect_err("must surface");

    assert_eq!(err.code, ErrorCode::OBS_ENVELOPE_INVALID);
    assert_eq!(err.code.as_str(), "ST-OBS-005");
    assert!(!err.is_retryable(), "ST-OBS-005 is not retryable");
    assert_eq!(err.message, "probe envelope rejected");
    assert_eq!(
        err.detail.as_deref(),
        Some("ST-OBS-005 probe envelope rejected: nonce belongs to another session")
    );
    assert!(provider.has_resource(&id(&["mock", "envelope"])));
}

/// NFR-S08: a guest-reported path that escapes the root is refused, and the
/// refusal names the offending path so it can be audited.
#[tokio::test]
async fn a_guest_path_escape_is_refused_and_named() {
    let fault = ObservationFault::GuestPathEscape {
        path: "../outside/taken.txt".into(),
    };
    assert_eq!(fault.code(), Some(ErrorCode::OBS_GUEST_PATH_ESCAPE));
    assert!(!fault.is_retryable());

    let err = world("escape", fault)
        .observe(&ObservationRequest::new(id(&["mock", "escape"]), all()))
        .await
        .expect_err("must surface");
    assert_eq!(err.code, ErrorCode::OBS_GUEST_PATH_ESCAPE);
    assert_eq!(err.message, "guest-reported path refused");
    assert!(
        err.detail
            .as_deref()
            .unwrap_or_default()
            .contains("../outside/taken.txt"),
        "the audit trail needs the path: {:?}",
        err.detail
    );
}

/// A probe that never bootstrapped: the channel is down, and the health domain
/// carries no value at all.
#[tokio::test]
async fn a_probe_bootstrap_failure_reports_the_channel_down() {
    let fault = ObservationFault::ProbeBootstrapFailed {
        reason: "bridge handshake refused: no telemetry channel".into(),
    };
    assert_eq!(fault.code(), Some(ErrorCode::OBS_PROBE_BOOTSTRAP));
    assert!(fault.is_retryable());

    let snap = world("bootstrap", fault)
        .observe(&ObservationRequest::new(id(&["mock", "bootstrap"]), all()))
        .await
        .expect("answers");
    assert_eq!(snap.health, ObservationHealth::Unavailable);
    assert!(snap.get(ObservationDomain::Health).is_none());
    assert!(snap
        .warnings
        .iter()
        .any(|w| w.contains("no telemetry channel")));
}

/// A denied credential is declared up front in the capabilities, so a UI can
/// prompt instead of collecting and failing (ST-OBS-006).
#[tokio::test]
async fn a_denied_credential_is_declared_in_the_capabilities() {
    let provider = world(
        "credential",
        ObservationFault::CredentialDenied {
            reason: "instance key is not in the credential store".into(),
        },
    );
    let id = id(&["mock", "credential"]);

    let caps = provider.capabilities(&id).await.expect("capabilities");
    assert!(
        caps.requires_native_credential,
        "a provider that needs a credential must say so"
    );
    assert!(
        caps.supports(ObservationMode::Probe),
        "the mode is still advertised; only the credential is missing"
    );

    let snap = provider
        .observe(&ObservationRequest::new(id, all()))
        .await
        .expect("answers");
    assert_eq!(snap.health, ObservationHealth::Unavailable);
    assert!(snap.warnings.iter().any(|w| w.starts_with("ST-OBS-006")));
    // The fixture hygiene rule: the reason names the absence, never a value.
    assert!(!snap.warnings.iter().any(|w| w.contains("PRIVATE KEY")));
}

/// Missing domains are a coverage fact with no error code.
#[tokio::test]
async fn partial_coverage_has_no_error_code_and_keeps_the_rest() {
    let fault = ObservationFault::PartialCoverage {
        missing_domains: vec![ObservationDomain::Process, ObservationDomain::Docker],
    };
    assert_eq!(fault.code(), None, "coverage gaps are not coded errors");

    let snap = world("partial", fault)
        .observe(&ObservationRequest::new(id(&["mock", "partial"]), all()))
        .await
        .expect("answers");

    assert_eq!(snap.health, ObservationHealth::Degraded);
    assert_eq!(
        snap.missing_domains(&all()),
        vec!["process", "docker"],
        "both withheld domains are named"
    );
    assert_eq!(snap.values.len(), 2, "system and filesystem survive");
    assert!(snap
        .warnings
        .iter()
        .any(|w| w == "domains not reported by the collector: process, docker"));
}

/// A nested engine that is unreachable leaves the docker domain present and
/// **partial**: "the child is degraded" must not read as "no engine".
#[tokio::test]
async fn a_nested_engine_outage_marks_docker_partial_not_absent() {
    let fault = ObservationFault::NestedDockerUnavailable {
        reason: "nested engine pipe closed after bootstrap".into(),
    };
    assert_eq!(fault.code(), Some(ErrorCode::OBS_NESTED_DOCKER_UNAVAILABLE));
    assert!(fault.is_retryable());

    let snap = world("nested", fault)
        .observe(&ObservationRequest::new(id(&["mock", "nested"]), all()))
        .await
        .expect("answers");

    assert_eq!(snap.health, ObservationHealth::Degraded);
    let docker = snap
        .get(ObservationDomain::Docker)
        .expect("docker is present");
    assert!(
        docker.is_partial(),
        "the docker domain must be partial, not missing"
    );
    assert_eq!(
        docker.value,
        json!({"containers": []}),
        "the scripted payload must survive; only its completeness changes"
    );
    assert!(
        snap.get(ObservationDomain::System)
            .map(|v| !v.is_partial())
            .unwrap_or(false),
        "the other domains must stay complete"
    );
    assert!(snap.warnings.iter().any(|w| w.contains("ST-OBS-010")));
    assert!(snap
        .warnings
        .iter()
        .any(|w| w.contains("domain docker is partial")));
    assert!(
        !snap.missing_domains(&all()).contains(&"docker"),
        "a partial domain is not a missing domain"
    );
}

/// The corpus covers every fault kind the crate defines, so a new fault cannot
/// be added without a fixture to drive it.
#[tokio::test]
async fn the_corpus_exercises_every_fault_kind() {
    let kinds: Vec<String> = common::loaded_fixtures()
        .into_iter()
        .flat_map(|(_, fixture)| {
            fixture
                .resources()
                .filter_map(|r| r.fault().map(kind_of))
                .collect::<Vec<_>>()
        })
        .collect();
    let mut unique = kinds.clone();
    unique.sort();
    unique.dedup();

    for expected in [
        "deadline_exceeded",
        "invalid_envelope",
        "guest_path_escape",
        "probe_bootstrap_failed",
        "credential_denied",
        "nested_docker_unavailable",
        "partial_coverage",
    ] {
        assert!(
            unique.contains(&expected.to_string()),
            "no fixture drives {expected}; corpus has {unique:?}"
        );
    }
    assert_eq!(
        unique.len(),
        7,
        "every fault kind must be driven exactly once in the corpus"
    );
}

/// Serialise the `kind` tag so the corpus check uses the wire form.
fn kind_of(fault: &ObservationFault) -> String {
    serde_json::to_value(fault).expect("fault serializes")["kind"]
        .as_str()
        .expect("internally tagged")
        .to_string()
}

/// A disposition override is honoured in both directions, and the default is
/// always the design's. Documented in `fault.rs`; this pins the behaviour.
#[tokio::test]
async fn disposition_overrides_are_honoured_in_both_directions() {
    let forced_surface = world(
        "forced-surface",
        ObservationFault::CredentialDenied {
            reason: "no credential".into(),
        },
    );
    let snap = forced_surface
        .observe(&ObservationRequest::new(
            id(&["mock", "forced-surface"]),
            all(),
        ))
        .await
        .expect("default disposition degrades");
    assert_eq!(snap.health, ObservationHealth::Unavailable);

    let overridden = ScriptedObservation::new(
        ObservationFixture::new("mock-probe").with_resource(
            ResourceObservation::new(&["mock", "forced-error"])
                .with_modes(&[ObservationMode::Probe])
                .with_domains(&[ObservationDomain::System])
                .with_value(ObservationDomain::System, json!({"os": "windows"}))
                .with_trust(TrustLevel::GuestProbe)
                .with_fault(ObservationFault::CredentialDenied {
                    reason: "no credential".into(),
                })
                .with_disposition(FaultDisposition::SurfaceError),
        ),
    );
    let err = overridden
        .observe(&ObservationRequest::new(
            id(&["mock", "forced-error"]),
            all(),
        ))
        .await
        .expect_err("the override must surface");
    assert_eq!(err.code, ErrorCode::OBS_CREDENTIAL_DENIED);
}

/// The corpus expectations, spelled out per scripted world, so a fixture edit
/// that changes a documented behaviour breaks a test rather than drifting.
#[tokio::test]
async fn the_scenario_corpus_matches_its_documented_behaviour() {
    let provider = provider_from(SCENARIOS);

    let healthy = provider
        .observe(&ObservationRequest::new(
            scenario_id("wsb-healthy"),
            vec![ObservationDomain::System, ObservationDomain::Health],
        ))
        .await
        .expect("observes");
    assert_eq!(healthy.health, ObservationHealth::Healthy);
    assert!(healthy.warnings.is_empty(), "{:?}", healthy.warnings);
    assert!(healthy
        .get(ObservationDomain::System)
        .expect("system")
        .provenance
        .evidence_hash
        .is_some());

    let stale = provider
        .observe(&ObservationRequest::new(
            scenario_id("wsb-stale"),
            vec![ObservationDomain::System, ObservationDomain::Health],
        ))
        .await
        .expect("observes");
    assert_eq!(stale.health, ObservationHealth::Stale);
    assert_eq!(stale.mode, ObservationMode::Metadata);
    assert!(
        stale.warnings.iter().any(|w| w.contains("300000ms")),
        "the age must be reported: {:?}",
        stale.warnings
    );
    assert_eq!(
        stale.get(ObservationDomain::System).expect("system").value["uptime_s"],
        900
    );

    let rejected = provider
        .observe(&ObservationRequest::new(
            scenario_id("wsb-envelope-rejected"),
            vec![ObservationDomain::System],
        ))
        .await
        .expect_err("surfaces");
    assert_eq!(rejected.code, ErrorCode::OBS_ENVELOPE_INVALID);
    assert!(rejected
        .detail
        .as_deref()
        .unwrap_or_default()
        .contains("sequence 4"));

    let escape = provider
        .observe(&ObservationRequest::new(
            scenario_id("wsb-path-escape"),
            vec![ObservationDomain::Filesystem],
        ))
        .await
        .expect_err("surfaces");
    assert_eq!(escape.code, ErrorCode::OBS_GUEST_PATH_ESCAPE);

    let partial = provider
        .observe(&ObservationRequest::new(
            scenario_id("wsb-partial"),
            vec![ObservationDomain::System, ObservationDomain::Process],
        ))
        .await
        .expect("observes");
    assert_eq!(partial.health, ObservationHealth::Degraded);
    assert_eq!(
        partial.missing_domains(&[
            ObservationDomain::System,
            ObservationDomain::Process,
            ObservationDomain::Filesystem
        ]),
        vec!["process", "filesystem"]
    );

    let deadline = provider
        .observe(&ObservationRequest::new(
            scenario_id("multipass-deadline"),
            vec![ObservationDomain::System],
        ))
        .await
        .expect("observes");
    assert_eq!(deadline.health, ObservationHealth::Unavailable);
    assert!(deadline.warnings.iter().any(|w| w.contains("2000ms")));

    let nested = provider
        .observe(&ObservationRequest::new(
            scenario_id("docker-nested-down"),
            vec![ObservationDomain::System, ObservationDomain::Docker],
        ))
        .await
        .expect("observes");
    assert_eq!(nested.mode, ObservationMode::Native);
    assert_eq!(nested.health, ObservationHealth::Degraded);
    assert!(nested
        .get(ObservationDomain::Docker)
        .expect("docker present")
        .is_partial());
    assert_eq!(
        nested.weakest_trust(),
        Some(TrustLevel::ProviderNative),
        "a native-mode provider may report provider_native"
    );
    assert!(nested.is_security_authoritative());
}
