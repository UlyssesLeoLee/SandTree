//! `ScriptedObservation` — the mock Observation Plane provider.
//!
//! This is the lane's product: a deterministic [`ObservationProvider`] that can
//! stand in for Windows Sandbox, Multipass or a Docker endpoint on a machine
//! that has none of them, and that can be pushed into every failure mode on
//! demand.
//!
//! # What it does not do
//!
//! * **No clock, no randomness, no environment probing** (NFR-O04). Timestamps,
//!   ages and payloads come from the fixture. The same fixture produces
//!   byte-identical snapshots on every run and every machine.
//! * **No provider SDK, no runtime binding** (NFR-O02). The crate depends only
//!   on `sandtree-model`, `sandtree-observation-model` and `sandtree-sdk`, so a
//!   kernel test can mount it without dragging in `bollard`, `wasmtime` or
//!   `rusqlite`.
//! * **No negotiation.** The kernel has already negotiated a mode by the time
//!   this port is called, but [`ObservationRequest`] carries no mode field, so
//!   [`select_mode`] re-derives one with the design's priority order. The rule
//!   is deliberately the same one the negotiator uses — first mode that can
//!   serve at least one requested domain — so a snapshot's mode is explainable
//!   from the caps alone.
//!
//! # The two invariants this crate exists to defend
//!
//! * **ADR-OBS-001** — an observation failure yields an `Unavailable` snapshot
//!   with a warning, never an `Err`, and never removes the resource from the
//!   scripted world. Only a malformed envelope or an escaping guest path
//!   surfaces as an error, because those must be audited (DD-OBS §12, NFR-S08).
//! * **ADR-OBS-003** — trust is clamped to the mode's ceiling, so `guest_probe`
//!   never becomes `host_native` even when a fixture asks for it and even when
//!   the payload carries a verifying evidence hash. See [`crate::trust`].

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use sandtree_model::error::{DomainError, ErrorCode};
use sandtree_model::id::ResourceId;
use sandtree_observation_model::{
    ObservationCapabilities, ObservationDomain, ObservationHealth, ObservationMode,
    ObservationRequest, ObservationSnapshot, ObservedValue, Provenance, TrustLevel,
};
use sandtree_sdk::ports::ObservationProvider;
use serde_json::Value as Json;

use crate::fault::{FaultDisposition, ObservationFault};
use crate::fixture::{FixtureError, ObservationFixture, ResourceObservation};
use crate::trust::{ceiling_refusal_warning, refusal_warning, resolve_trust};

/// Negotiation priority order (DD-OBS §4): least invasive first.
///
/// Explicitly ordered rather than relying on the enum's derived `Ord`, so the
/// mock states the rule it follows instead of inheriting one.
pub const MODE_PRIORITY: [ObservationMode; 4] = [
    ObservationMode::Native,
    ObservationMode::Exec,
    ObservationMode::Probe,
    ObservationMode::Metadata,
];

/// Pick the observation mode for a request.
///
/// Mirrors [`StrategyNegotiator`][negotiator]: the first declared mode in
/// [`MODE_PRIORITY`] that can serve at least one requested domain. Returns
/// `None` when no declared mode can serve any of them, which the provider turns
/// into `ST-OBS-001`.
///
/// [negotiator]: sandtree_observation_core::strategy::StrategyNegotiator
pub fn select_mode(
    resource: &ResourceObservation,
    requested: &[ObservationDomain],
) -> Option<ObservationMode> {
    let wanted: Vec<ObservationDomain> = if requested.is_empty() {
        ObservationDomain::all().to_vec()
    } else {
        requested.to_vec()
    };
    MODE_PRIORITY.iter().copied().find(|mode| {
        if !resource.modes().contains(mode) {
            return false;
        }
        let declared = resource.domains_in(*mode);
        wanted.iter().any(|d| declared.contains(d))
    })
}

/// Derive snapshot health from the channel state, the declared state and the
/// domains that actually arrived.
///
/// Ordering matters and is deliberate:
///
/// 1. a channel that is down is `Unavailable`, whatever the fixture declared;
/// 2. `stale` is its own axis (DD-OBS §13) and survives a coverage gap, which
///    is reported as a warning instead;
/// 3. nothing at all is `Unavailable` — not `Healthy`, because reporting no
///    data as healthy is the one thing a snapshot must never do;
/// 4. a coverage gap or a partial value is `Degraded` — never `Healthy`;
/// 5. otherwise the fixture's declared channel state has the last word, so a
///    sub-collector that reports trouble without missing a domain still shows
///    up as `Degraded`.
pub fn effective_health(
    declared: ObservationHealth,
    requested: &[ObservationDomain],
    present: usize,
    any_partial: bool,
    channel_down: bool,
) -> ObservationHealth {
    if channel_down {
        return ObservationHealth::Unavailable;
    }
    if declared == ObservationHealth::Stale {
        return ObservationHealth::Stale;
    }
    if present == 0 {
        return ObservationHealth::Unavailable;
    }
    if present < requested.len() || any_partial {
        return ObservationHealth::Degraded;
    }
    declared
}

/// A scripted observation provider over one fixture.
///
/// Cloning shares the fixture and the counters, so a test can mount the same
/// world under several plugin ids without re-parsing it.
#[derive(Debug, Clone)]
pub struct ScriptedObservation {
    fixture: Arc<ObservationFixture>,
    observe_calls: Arc<AtomicUsize>,
    capability_calls: Arc<AtomicUsize>,
}

impl ScriptedObservation {
    /// Wrap an already-validated fixture.
    pub fn new(fixture: ObservationFixture) -> Self {
        Self {
            fixture: Arc::new(fixture),
            observe_calls: Arc::new(AtomicUsize::new(0)),
            capability_calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Parse and validate a fixture from JSON.
    pub fn from_json(text: &str) -> Result<Self, FixtureError> {
        Ok(Self::new(ObservationFixture::from_json(text)?))
    }

    /// Read, parse and validate a fixture from disk.
    pub fn from_path(path: &std::path::Path) -> Result<Self, FixtureError> {
        Ok(Self::new(ObservationFixture::from_path(path)?))
    }

    /// The scripted world behind this provider.
    pub fn fixture(&self) -> &ObservationFixture {
        &self.fixture
    }

    /// Scripted identities, sorted.
    pub fn resource_ids(&self) -> Vec<ResourceId> {
        self.fixture.resource_ids()
    }

    /// Whether the resource is part of the scripted world.
    ///
    /// The point of the accessor is ADR-OBS-001: this stays `true` after an
    /// observation failure, because failing to see a resource never un-creates
    /// it.
    pub fn has_resource(&self, id: &ResourceId) -> bool {
        self.fixture.resource(id).is_some()
    }

    /// How many times `observe` was reached.
    pub fn observe_calls(&self) -> usize {
        self.observe_calls.load(Ordering::SeqCst)
    }

    /// How many times `capabilities` was reached.
    pub fn capability_calls(&self) -> usize {
        self.capability_calls.load(Ordering::SeqCst)
    }

    /// Look up a scripted resource.
    fn resource_for(&self, id: &ResourceId) -> Result<&ResourceObservation, DomainError> {
        self.fixture.resource(id).ok_or_else(|| {
            // Not scripted is a mock bookkeeping fact, not a claim about the
            // host: the message says so, so nobody can read "not in the
            // fixture" as "not present" (ADR-OBS-001).
            DomainError::new(
                ErrorCode::OBS_NO_STRATEGY,
                format!(
                    "resource {id} is not scripted in this mock fixture; \
                     the mock does not model it and makes no claim about the host"
                ),
            )
        })
    }

    /// The capabilities a scripted resource reports (DD-OBS §12.1).
    fn capabilities_for(&self, resource: &ResourceObservation) -> ObservationCapabilities {
        let mut modes: Vec<ObservationMode> = MODE_PRIORITY
            .iter()
            .copied()
            .filter(|m| resource.modes().contains(m))
            .collect();
        modes.dedup();

        let mut domains: BTreeMap<String, Vec<ObservationDomain>> = BTreeMap::new();
        for mode in &modes {
            let mut list = resource.domains_in(*mode);
            list.sort_unstable();
            list.dedup();
            domains.insert(mode.as_str().to_string(), list);
        }

        ObservationCapabilities {
            modes,
            domains,
            max_concurrency: None,
            // A provider whose credential is denied still says so up front, so
            // a UI can prompt instead of collecting and failing (ST-OBS-006).
            requires_native_credential: matches!(
                resource.fault(),
                Some(ObservationFault::CredentialDenied { .. })
            ),
        }
    }

    /// Assemble one snapshot for a request. See [`ObservationProvider::observe`].
    fn snapshot_for(
        &self,
        resource: &ResourceObservation,
        id: &ResourceId,
        req: &ObservationRequest,
    ) -> Result<ObservationSnapshot, DomainError> {
        // NFR-O01: the resource never changes because observation did.
        let requested: Vec<ObservationDomain> = if req.domains.is_empty() {
            ObservationDomain::all().to_vec()
        } else {
            req.domains.clone()
        };

        let Some(mode) = select_mode(resource, &requested) else {
            return Err(DomainError::new(
                ErrorCode::OBS_NO_STRATEGY,
                format!(
                    "resource {id} offers no mode that can serve the requested domains"
                ),
            ));
        };

        // The deadline the request carried, or the tightest default for the
        // requested set. Recorded in the snapshot so a deadline test asserts on
        // the number the provider actually used.
        let deadline_ms = req.deadline_ms.unwrap_or_else(|| {
            requested
                .iter()
                .map(|d| d.default_deadline_ms())
                .max()
                .unwrap_or(2_000)
        });

        let fault = resource.fault();
        let disposition = resource.disposition();

        // DD-OBS §12 / NFR-S08: a protocol or security violation surfaces. It is
        // never degraded into a snapshot, because a swallowed hostile envelope
        // is worse than a visible failure.
        if fault.is_some() && disposition == Some(FaultDisposition::SurfaceError) {
            let fault = fault.expect("fault present when disposition is SurfaceError");
            return Err(fault.to_domain_error());
        }

        let trust = resolve_trust(mode, resource.declared_ceiling(), resource.trust());
        let mut snapshot = ObservationSnapshot::empty(
            id.clone(),
            mode,
            ObservationHealth::Healthy,
            resource.observed_at().to_string(),
        );
        snapshot.collector_version = resource.collector_version().map(str::to_string);

        // FR-079 / ADR-OBS-001: the channel is down, the resource is not.
        if disposition == Some(FaultDisposition::UnavailableSnapshot) {
            let warning = fault
                .map(|f| f.warning())
                .unwrap_or_else(|| "observation channel is down".to_string());
            snapshot.health = ObservationHealth::Unavailable;
            snapshot.warn(warning);
            return Ok(snapshot);
        }

        let declared_domains = resource.domains_in(mode);
        let withheld: Vec<ObservationDomain> = fault
            .map(|f| f.withheld_domains().to_vec())
            .unwrap_or_default();

        // CONTRACTS §6 / NFR-O01: iterate a sorted list so insertion order, and
        // therefore the serialized snapshot, is stable.
        let mut served: Vec<ObservationDomain> = requested
            .iter()
            .copied()
            .filter(|d| declared_domains.contains(d))
            .filter(|d| !withheld.contains(d))
            .collect();
        served.sort_unstable();
        served.dedup();

        // A nested engine that is unreachable leaves the docker domain present
        // but partial: "the child is degraded" must not read as "no engine".
        let docker_degraded = matches!(
            fault,
            Some(ObservationFault::NestedDockerUnavailable { .. })
        );

        let mut partial_domains: Vec<&'static str> = Vec::new();
        for domain in &served {
            // The health domain is synthesised by the provider, not scripted:
            // it reports the mode, the deadline and the warnings of this very
            // collection (DD-OBS §5).
            let (payload, partial) = if *domain == ObservationDomain::Health {
                (self.health_payload(mode, deadline_ms, &requested, &served), false)
            } else {
                match resource.value_for(*domain) {
                    Some(value) => (
                        value.clone(),
                        *domain == ObservationDomain::Docker && docker_degraded,
                    ),
                    None => continue,
                }
            };
            let mut provenance = Provenance::new(
                self.fixture.source(),
                trust.effective,
                resource.observed_at(),
            )
            .with_freshness_ms(resource.freshness_ms())
            .partial(partial);
            if resource.attaches_evidence() {
                // ADR-OBS-003: the hash travels with the value; the trust rung
                // does not move, because the reporter produced the bytes.
                provenance = provenance.with_evidence(
                    &serde_json::to_vec(&payload).unwrap_or_default(),
                );
            }
            if partial {
                partial_domains.push(domain.as_str());
            }
            snapshot.insert(*domain, ObservedValue::new(payload, provenance));
        }

        let channel_down = false;
        let present = snapshot.values.len();
        let any_partial = !partial_domains.is_empty();
        snapshot.health = effective_health(
            resource.health(),
            &requested,
            present,
            any_partial,
            channel_down,
        );

        // A trust upgrade the fixture attempted is reported, not hidden: an
        // operator must be able to see that a value arrived weaker than the
        // provider claimed.
        if trust.refused_upgrade {
            snapshot.warn(refusal_warning(mode, &trust));
        }
        if trust.refused_ceiling {
            snapshot.warn(ceiling_refusal_warning(mode, &trust));
        }
        if let Some(fault) = fault {
            if disposition == Some(FaultDisposition::DegradedSnapshot) {
                snapshot.warn(fault.warning());
            }
        }
        if docker_degraded {
            snapshot.warn(format!(
                "domain {} is partial: nested engine unreachable",
                ObservationDomain::Docker.as_str()
            ));
        }
        for missing in snapshot.missing_domains(&requested) {
            snapshot.warn(format!("domain {missing} was not reported"));
        }
        if snapshot.health == ObservationHealth::Stale {
            snapshot.warn(format!(
                "snapshot age {}ms exceeds the freshness policy",
                resource.freshness_ms()
            ));
            if present < requested.len() || any_partial {
                snapshot.warn("stale snapshot is also missing requested domains");
            }
        }

        Ok(snapshot)
    }

    /// The synthesised `health` domain payload.
    fn health_payload(
        &self,
        mode: ObservationMode,
        deadline_ms: u64,
        requested: &[ObservationDomain],
        served: &[ObservationDomain],
    ) -> Json {
        let names: Vec<&str> = served.iter().map(|d| d.as_str()).collect();
        let mut payload = serde_json::json!({
            "mode": mode.as_str(),
            "deadline_ms": deadline_ms,
            "collector": self.fixture.source(),
            "requested": requested.iter().map(|d| d.as_str()).collect::<Vec<_>>(),
            "served": names,
        });
        // Keep the object shape fixed so a byte-comparison of two runs is
        // meaningful rather than dependent on insertion order.
        if let Json::Object(map) = &mut payload {
            map.sort_keys();
        }
        payload
    }
}

#[async_trait::async_trait]
impl ObservationProvider for ScriptedObservation {
    async fn capabilities(
        &self,
        id: &ResourceId,
    ) -> Result<ObservationCapabilities, DomainError> {
        self.capability_calls.fetch_add(1, Ordering::SeqCst);
        let resource = self.resource_for(id)?;
        Ok(self.capabilities_for(resource))
    }

    /// Produce one snapshot for `req`.
    ///
    /// Returns `Ok` for every fault the design considers degradable, including
    /// a dead observation channel; returns `Err` only for a rejected envelope or
    /// an escaping guest path. The resource is never removed from the scripted
    /// world either way (ADR-OBS-001).
    async fn observe(
        &self,
        req: &ObservationRequest,
    ) -> Result<ObservationSnapshot, DomainError> {
        self.observe_calls.fetch_add(1, Ordering::SeqCst);
        let resource = self.resource_for(&req.resource_id)?;
        self.snapshot_for(resource, &req.resource_id, req)
    }
}

/// Trust level a snapshot actually carries, for tests that assert on outcomes
/// rather than on provenance directly.
///
/// Returns `None` for a snapshot with no values, which is what a down channel
/// produces.
pub fn snapshot_trust(snapshot: &ObservationSnapshot) -> Option<TrustLevel> {
    snapshot.weakest_trust()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn probe_resource() -> ResourceObservation {
        ResourceObservation::new(&["mock", "wsb"])
            .with_modes(&[ObservationMode::Probe, ObservationMode::Metadata])
            .with_domains(&[ObservationDomain::Filesystem, ObservationDomain::Process, ObservationDomain::System])
            .with_value(
                ObservationDomain::System,
                json!({"os": "windows", "arch": "x86_64"}),
            )
            .with_value(ObservationDomain::Process, json!({"count": 2}))
            .with_value(
                ObservationDomain::Filesystem,
                json!({"entries": ["workspace/src/main.rs"]}),
            )
            .with_trust(TrustLevel::GuestProbe)
    }

    fn provider() -> ScriptedObservation {
        ScriptedObservation::new(
            ObservationFixture::new("mock-probe").with_resource(probe_resource()),
        )
    }

    fn request(domains: &[ObservationDomain]) -> ObservationRequest {
        ObservationRequest::new(ResourceId::derive(&["mock", "wsb"]), domains.to_vec())
    }

    #[tokio::test]
    async fn picks_the_least_invasive_mode_that_can_serve_the_request() {
        let p = provider();
        let caps = p.capabilities(&ResourceId::derive(&["mock", "wsb"])).await.unwrap();
        assert_eq!(
            caps.modes,
            vec![ObservationMode::Probe, ObservationMode::Metadata],
            "caps must be listed in negotiation order"
        );

        let snap = p.observe(&request(&[ObservationDomain::System])).await.unwrap();
        assert_eq!(snap.mode, ObservationMode::Probe);
        assert_eq!(snap.health, ObservationHealth::Healthy);
        assert_eq!(snap.values.len(), 1);
        assert_eq!(snap.weakest_trust(), Some(TrustLevel::GuestProbe));
    }

    #[tokio::test]
    async fn an_unscripted_resource_is_a_mock_fact_not_a_host_claim() {
        let p = provider();
        let err = p
            .observe(&ObservationRequest::new(
                ResourceId::derive(&["mock", "absent"]),
                vec![ObservationDomain::System],
            ))
            .await
            .expect_err("not scripted");
        assert_eq!(err.code, ErrorCode::OBS_NO_STRATEGY);
        assert!(err.message.contains("not scripted"));
        assert!(err.message.contains("makes no claim about the host"));
    }

    #[test]
    fn select_mode_follows_the_priority_order() {
        let r = probe_resource();
        assert_eq!(
            select_mode(&r, &[ObservationDomain::System]),
            Some(ObservationMode::Probe)
        );
        // A domain only metadata can serve pushes negotiation down the chain.
        let restricted = ResourceObservation::new(&["mock", "x"])
            .with_modes(&[ObservationMode::Probe, ObservationMode::Metadata])
            .with_domains(&[ObservationDomain::Filesystem, ObservationDomain::System])
            .with_value(ObservationDomain::Filesystem, json!({}))
            .with_value(ObservationDomain::System, json!({}))
            .with_mode_domains(ObservationMode::Probe, &[ObservationDomain::Filesystem])
            .with_mode_domains(ObservationMode::Metadata, &[ObservationDomain::System]);
        assert_eq!(
            select_mode(&restricted, &[ObservationDomain::System]),
            Some(ObservationMode::Metadata)
        );
        assert_eq!(select_mode(&r, &[ObservationDomain::Docker]), None);
    }

    /// Health derivation, case by case. The order of the rules is the contract.
    #[test]
    fn health_follows_coverage_then_the_declared_state() {
        let two = [ObservationDomain::System, ObservationDomain::Process];
        // Channel down wins over anything declared.
        assert_eq!(
            effective_health(ObservationHealth::Healthy, &two, 2, false, true),
            ObservationHealth::Unavailable
        );
        // Stale is its own axis.
        assert_eq!(
            effective_health(ObservationHealth::Stale, &two, 1, false, false),
            ObservationHealth::Stale
        );
        // Nothing at all is unavailable, never healthy.
        assert_eq!(
            effective_health(ObservationHealth::Healthy, &two, 0, false, false),
            ObservationHealth::Unavailable
        );
        // A coverage gap is degraded.
        assert_eq!(
            effective_health(ObservationHealth::Healthy, &two, 1, false, false),
            ObservationHealth::Degraded
        );
        // A partial value is degraded even at full coverage.
        assert_eq!(
            effective_health(ObservationHealth::Healthy, &two, 2, true, false),
            ObservationHealth::Degraded
        );
        // Complete coverage takes the declared state's word.
        assert_eq!(
            effective_health(ObservationHealth::Healthy, &two, 2, false, false),
            ObservationHealth::Healthy
        );
        assert_eq!(
            effective_health(ObservationHealth::Degraded, &two, 2, false, false),
            ObservationHealth::Degraded
        );
    }

    #[tokio::test]
    async fn capabilities_declare_a_native_credential_requirement() {
        let p = ScriptedObservation::new(
            ObservationFixture::new("mock-native").with_resource(
                probe_resource()
                    .with_modes(&[ObservationMode::Native, ObservationMode::Metadata])
                    .with_trust(TrustLevel::ProviderNative)
                    .with_fault(ObservationFault::CredentialDenied {
                        reason: "credential store empty".into(),
                    }),
            ),
        );
        let caps = p.capabilities(&ResourceId::derive(&["mock", "wsb"])).await.unwrap();
        assert!(caps.requires_native_credential);
        assert!(caps.supports(ObservationMode::Native));
        assert!(!caps.supports(ObservationMode::Exec));
        assert_eq!(p.capability_calls(), 1);
    }
}