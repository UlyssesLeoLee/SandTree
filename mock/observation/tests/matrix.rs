//! Determinism, ordering and the shape of what crosses the port.
//!
//! A mock whose output moves between runs is worse than no mock: a flaky test
//! teaches the team to re-run failures instead of reading them. Everything here
//! is about the output being *byte-stable* and about nothing vendor-shaped
//! leaking into the observation plane (NFR-O02, NFR-O04).

mod common;

use common::{provider_from, scenario_id, SCENARIOS};
use sandtree_mock_observation::{
    ObservationFixture, ResourceObservation, ScriptedObservation, MODE_PRIORITY,
};
use sandtree_observation_model::{
    ObservationCapabilities, ObservationDomain, ObservationHealth, ObservationMode,
    ObservationRequest, ObservationSnapshot, TrustLevel,
};
use sandtree_sdk::ports::ObservationProvider;
use serde_json::{json, Value as Json};

fn world() -> ResourceObservation {
    ResourceObservation::new(&["mock", "determinism"])
        .with_modes(&[ObservationMode::Probe, ObservationMode::Metadata])
        .with_domains(&[
            ObservationDomain::System,
            ObservationDomain::Process,
            ObservationDomain::Filesystem,
            ObservationDomain::Network,
            ObservationDomain::Health,
        ])
        .with_value(
            ObservationDomain::System,
            json!({"os": "windows", "uptime_s": 5}),
        )
        .with_value(ObservationDomain::Process, json!({"pids": [1, 2, 3]}))
        .with_value(
            ObservationDomain::Filesystem,
            json!({"entries": ["workspace/a.txt", "workspace/b.txt"]}),
        )
        .with_value(ObservationDomain::Network, json!({"listeners": [80, 443]}))
        .with_trust(TrustLevel::GuestProbe)
        .with_collector_version("probe/7")
        .evidence(true)
}

fn all_domains() -> Vec<ObservationDomain> {
    ObservationDomain::all().to_vec()
}

/// Two providers built from the same fixture must serialise identically.
#[tokio::test]
async fn the_same_fixture_yields_identical_snapshots() {
    let first =
        ScriptedObservation::new(ObservationFixture::new("mock-probe").with_resource(world()));
    let second =
        ScriptedObservation::new(ObservationFixture::new("mock-probe").with_resource(world()));

    let req = ObservationRequest::new(
        sandtree_model::id::ResourceId::derive(&["mock", "determinism"]),
        all_domains(),
    );
    let a = first.observe(&req).await.expect("observes");
    let b = second.observe(&req).await.expect("observes");

    assert_eq!(
        serde_json::to_string(&a).expect("serialize"),
        serde_json::to_string(&b).expect("serialize"),
        "two providers over one fixture must produce identical bytes"
    );
}

/// Repeated observation of the same resource must not drift either — no clock,
/// no counter in the output.
#[tokio::test]
async fn repeated_observation_is_stable() {
    let provider =
        ScriptedObservation::new(ObservationFixture::new("mock-probe").with_resource(world()));
    let req = ObservationRequest::new(
        sandtree_model::id::ResourceId::derive(&["mock", "determinism"]),
        all_domains(),
    );

    let mut rendered: Vec<String> = Vec::new();
    for _ in 0..5 {
        let snap = provider.observe(&req).await.expect("observes");
        assert_eq!(
            snap.observed_at, "2026-10-07T00:00:00Z",
            "the mock must report the fixture timestamp, not the wall clock"
        );
        rendered.push(serde_json::to_string(&snap).expect("serialize"));
    }
    let first = rendered[0].clone();
    for (i, later) in rendered.iter().enumerate() {
        assert_eq!(*later, first, "run {i} drifted from run 0");
    }
    assert_eq!(provider.observe_calls(), 5);
}

/// The same request must produce the same health every time, including the
/// degraded and stale axes.
#[tokio::test]
async fn health_is_a_function_of_the_fixture_not_of_call_order() {
    let degraded = ResourceObservation::new(&["mock", "deg"])
        .with_modes(&[ObservationMode::Native])
        .with_domains(&[ObservationDomain::System])
        .with_value(ObservationDomain::System, json!({"os": "linux"}))
        .with_trust(TrustLevel::ProviderNative);
    let provider =
        ScriptedObservation::new(ObservationFixture::new("mock-native").with_resource(degraded));
    let req = ObservationRequest::new(
        sandtree_model::id::ResourceId::derive(&["mock", "deg"]),
        vec![ObservationDomain::System],
    );

    let first = provider.observe(&req).await.expect("observes");
    assert_eq!(first.health, ObservationHealth::Healthy);
    let second = provider.observe(&req).await.expect("observes again");
    assert_eq!(
        second, first,
        "a second call must not cache-drift the answer"
    );
}

/// Domain values serialise in sorted key order, so a diff between two runs is
/// readable.
#[tokio::test]
async fn values_serialise_in_sorted_domain_order() {
    let provider =
        ScriptedObservation::new(ObservationFixture::new("mock-probe").with_resource(world()));
    let snap = provider
        .observe(&ObservationRequest::new(
            sandtree_model::id::ResourceId::derive(&["mock", "determinism"]),
            // Request in reverse order on purpose: the output must not depend
            // on the order the caller asked in.
            vec![
                ObservationDomain::Network,
                ObservationDomain::Filesystem,
                ObservationDomain::Process,
                ObservationDomain::System,
                ObservationDomain::Health,
            ],
        ))
        .await
        .expect("observes");

    let keys: Vec<String> = serde_json::to_value(&snap).expect("serialize")["values"]
        .as_object()
        .expect("values is an object")
        .keys()
        .cloned()
        .collect();
    let mut sorted = keys.clone();
    sorted.sort();
    assert_eq!(keys, sorted, "values must serialise sorted: {keys:?}");
    assert_eq!(
        keys,
        vec!["filesystem", "health", "network", "process", "system"],
        "every requested domain must be present, health included"
    );
}

/// The synthesised health domain reports the mode, the deadline and what was
/// actually served — so a deadline test has something to assert on.
#[tokio::test]
async fn the_health_domain_reports_mode_deadline_and_served_domains() {
    let provider =
        ScriptedObservation::new(ObservationFixture::new("mock-probe").with_resource(world()));
    let snap = provider
        .observe(
            &ObservationRequest::new(
                sandtree_model::id::ResourceId::derive(&["mock", "determinism"]),
                vec![ObservationDomain::System, ObservationDomain::Health],
            )
            .with_deadline_ms(1_500),
        )
        .await
        .expect("observes");

    let health = snap.get(ObservationDomain::Health).expect("health domain");
    assert_eq!(health.value["mode"], "probe");
    assert_eq!(health.value["deadline_ms"], 1_500);
    assert_eq!(health.value["collector"], "mock-probe");
    assert_eq!(health.value["served"], json!(["system", "health"]));
    assert_eq!(health.value["requested"], json!(["system", "health"]));
    assert!(
        !health.is_partial(),
        "a complete collection is not a partial health report"
    );
}

/// With no explicit deadline the provider falls back to the design's per-domain
/// budgets, and says which number it used.
#[tokio::test]
async fn a_missing_deadline_falls_back_to_the_domain_budget() {
    let provider =
        ScriptedObservation::new(ObservationFixture::new("mock-probe").with_resource(world()));
    let snap = provider
        .observe(&ObservationRequest::new(
            sandtree_model::id::ResourceId::derive(&["mock", "determinism"]),
            vec![ObservationDomain::System, ObservationDomain::Health],
        ))
        .await
        .expect("observes");

    let expected = ObservationDomain::System
        .default_deadline_ms()
        .max(ObservationDomain::Health.default_deadline_ms());
    assert_eq!(
        snap.get(ObservationDomain::Health).expect("health").value["deadline_ms"],
        expected
    );
    assert_eq!(expected, 2_000, "DD-SW 12.3 budget for these domains");
}

/// Capabilities list modes in negotiation order and never advertise a mode the
/// fixture did not declare (RD §9: no speculation).
#[tokio::test]
async fn capabilities_are_ordered_and_never_speculate() {
    let provider = provider_from(SCENARIOS);
    let caps: ObservationCapabilities = provider
        .capabilities(&scenario_id("wsb-healthy"))
        .await
        .expect("capabilities");

    assert_eq!(
        caps.modes,
        vec![ObservationMode::Probe, ObservationMode::Metadata]
    );
    assert!(
        MODE_PRIORITY
            .iter()
            .filter(|m| caps.modes.contains(m))
            .copied()
            .collect::<Vec<_>>()
            == caps.modes,
        "caps must follow MODE_PRIORITY"
    );
    for mode in &caps.modes {
        let declared = provider
            .fixture()
            .resource(&scenario_id("wsb-healthy"))
            .expect("scripted")
            .domains_in(*mode);
        assert_eq!(
            caps.domains_in(*mode),
            declared.as_slice(),
            "caps must not invent domains for {mode:?}"
        );
    }
    assert!(!caps.supports(ObservationMode::Native));
    assert!(!caps.supports(ObservationMode::Exec));
    assert!(!caps.requires_native_credential);
    assert_eq!(caps.max_concurrency, None);
}

/// NFR-O02: what crosses the port is a domain DTO, not a vendor type. The
/// serialised snapshot must have exactly the fields the machine schema declares
/// — no extra vendor keys, no missing ones.
#[tokio::test]
async fn a_snapshot_carries_only_the_declared_dto_fields() {
    let provider = provider_from(SCENARIOS);
    let snap = provider
        .observe(&ObservationRequest::new(
            scenario_id("wsb-healthy"),
            vec![ObservationDomain::System],
        ))
        .await
        .expect("observes");

    let json: Json = serde_json::to_value(&snap).expect("serialize");
    let mut keys: Vec<&str> = json
        .as_object()
        .expect("object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec![
            "collector_version",
            "health",
            "mode",
            "observed_at",
            "resource_id",
            "values",
            "warnings",
        ],
        "the observation plane must not leak extra fields"
    );

    // Provenance carries the provenance fields and nothing else.
    let provenance = json["values"]["system"]["provenance"].clone();
    let mut pkeys: Vec<&str> = provenance
        .as_object()
        .expect("provenance object")
        .keys()
        .map(String::as_str)
        .collect();
    pkeys.sort_unstable();
    assert_eq!(
        pkeys,
        vec![
            "evidence_hash",
            "freshness_ms",
            "observed_at",
            "partial",
            "source",
            "trust"
        ]
    );
    assert_eq!(provenance["source"], "mock-probe");
    assert_eq!(provenance["trust"], "guest_probe");
    assert_eq!(provenance["partial"], false);
    assert_eq!(provenance["freshness_ms"], 0);
}

/// A snapshot round-trips through the wire form, so a fixture-authored world can
/// be persisted and replayed.
#[tokio::test]
async fn a_snapshot_round_trips_through_json() {
    let provider = provider_from(SCENARIOS);
    // Exactly the domains this world declares. Asking for all six would leave
    // `docker` missing, and a missing domain is correctly Degraded — which would
    // make this a test of coverage arithmetic rather than of round-tripping.
    let declared = vec![
        ObservationDomain::System,
        ObservationDomain::Process,
        ObservationDomain::Filesystem,
        ObservationDomain::Network,
        ObservationDomain::Health,
    ];
    let snap = provider
        .observe(&ObservationRequest::new(scenario_id("wsb-healthy"), declared))
        .await
        .expect("observes");

    let encoded = serde_json::to_string(&snap).expect("serialize");
    let decoded: ObservationSnapshot = serde_json::from_str(&encoded).expect("deserialize");
    assert_eq!(decoded, snap);
    assert_eq!(decoded.collector_version.as_deref(), Some("probe/1"));
    assert_eq!(decoded.health, ObservationHealth::Healthy);
    assert!(decoded.warnings.is_empty(), "{:?}", decoded.warnings);
    assert_eq!(decoded.values.len(), 5, "four scripted domains plus health");
    assert_eq!(
        decoded
            .get(ObservationDomain::Network)
            .expect("network")
            .value["listeners"],
        json!([80, 443]),
        "the payload must survive the round trip verbatim"
    );
}

/// Asking for a domain the world cannot serve is Degraded, never Healthy and
/// never an error: a coverage gap is reported as a state (DD-OBS §2).
#[tokio::test]
async fn an_unservable_requested_domain_degrades_the_snapshot() {
    let provider = provider_from(SCENARIOS);
    let snap = provider
        .observe(&ObservationRequest::new(
            scenario_id("wsb-healthy"),
            all_domains(),
        ))
        .await
        .expect("observes");

    assert_eq!(snap.health, ObservationHealth::Degraded);
    assert_eq!(snap.missing_domains(&all_domains()), vec!["docker"]);
    assert!(snap
        .warnings
        .iter()
        .any(|w| w.contains("domain docker was not reported")));
    assert!(snap.get(ObservationDomain::Docker).is_none());
}

/// Warnings are de-duplicated and stable, so a caller can compare them.
#[tokio::test]
async fn warnings_are_deduplicated_and_stable() {
    let provider = ScriptedObservation::new(ObservationFixture::new("mock-probe").with_resource(
        world().with_fault(
            sandtree_mock_observation::ObservationFault::PartialCoverage {
                missing_domains: vec![ObservationDomain::Process, ObservationDomain::Process],
            },
        ),
    ));
    let snap = provider
        .observe(&ObservationRequest::new(
            sandtree_model::id::ResourceId::derive(&["mock", "determinism"]),
            all_domains(),
        ))
        .await
        .expect("observes");

    assert_eq!(
        snap.health,
        ObservationHealth::Degraded,
        "withholding a domain must never look healthy"
    );
    let mut sorted = snap.warnings.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(
        sorted.len(),
        snap.warnings.len(),
        "warnings must be de-duplicated: {:?}",
        snap.warnings
    );
    assert!(
        snap.warnings.iter().any(|w| w.contains("process")),
        "the withheld domain must be named: {:?}",
        snap.warnings
    );
}

/// Every scripted world in the shipped corpus observes deterministically. This
/// is the broadest regression guard in the crate: one loop over every fixture,
/// every domain.
#[tokio::test]
async fn the_whole_corpus_observes_deterministically() {
    for (stem, fixture) in common::loaded_fixtures() {
        let provider = ScriptedObservation::new(fixture);
        for id in provider.resource_ids() {
            for domain in ObservationDomain::all() {
                let req = ObservationRequest::new(id.clone(), vec![*domain]);
                let first = match provider.observe(&req).await {
                    Ok(s) => serde_json::to_string(&s).expect("serialize"),
                    Err(e) => format!("ERR {} {}", e.code, e.message),
                };
                let second = match provider.observe(&req).await {
                    Ok(s) => serde_json::to_string(&s).expect("serialize"),
                    Err(e) => format!("ERR {} {}", e.code, e.message),
                };
                assert_eq!(
                    first,
                    second,
                    "{stem}: observing {} twice must produce identical bytes",
                    id.as_str()
                );
            }
        }
    }
}
