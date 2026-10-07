//! Composed observation service (DD-SW §3 `ObservationService` wiring).
//!
//! The order here is the whole design of the Observation Plane:
//!
//! 1. ask the provider what it can do (`capabilities`);
//! 2. negotiate a mode and a domain set (`StrategyNegotiator`);
//! 3. answer from cache when fresh, **reporting the age**;
//! 4. otherwise collect under a deadline, with per-domain limits;
//! 5. normalize into a snapshot whose health follows *coverage*;
//! 6. cache what was collected.
//!
//! Failure at any step produces a degraded snapshot rather than an error, with
//! the exception of protocol and security violations (FR-079, ADR-OBS-001).

use std::sync::Arc;

use sandtree_model::error::{DomainError, ErrorCode};
use sandtree_model::id::ResourceId;
use sandtree_observation_model::{
    ObservationCapabilities, ObservationDomain, ObservationHealth, ObservationMode,
    ObservationPlan, ObservationRequest, ObservationSnapshot, ObservedValue,
};
use serde_json::Value as Json;

use crate::cache::ObservationCache;
use crate::limits::{clamp_json, domain_health, ObservationLimits};
use crate::scheduler::Scheduler;
use crate::strategy::StrategyNegotiator;

/// The provider-facing observation port.
///
/// Declared here (not in the SDK) so `observation-core` has no dependency on the
/// plugin ABI: the kernel wires an adapter, and unit tests supply a fake.
pub trait ObservationBackend: Send + Sync {
    /// Modes and domains available for one resource.
    fn capabilities(
        &self,
        id: &ResourceId,
    ) -> impl std::future::Future<Output = Result<ObservationCapabilities, DomainError>> + Send;

    /// Collect one domain set under a plan.
    fn collect(
        &self,
        id: &ResourceId,
        plan: &ObservationPlan,
    ) -> impl std::future::Future<Output = Result<ObservationSnapshot, DomainError>> + Send;
}

/// Composed observation service.
pub struct ObservationService {
    negotiator: StrategyNegotiator,
    scheduler: Scheduler,
    cache: Arc<std::sync::Mutex<ObservationCache>>,
    limits: ObservationLimits,
}

impl std::fmt::Debug for ObservationService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ObservationService")
            .field("limits", &self.limits)
            .finish()
    }
}

impl ObservationService {
    /// Build with the default limits and an unrestricted negotiator.
    pub fn new() -> Self {
        Self {
            negotiator: StrategyNegotiator::new(),
            scheduler: Scheduler::new(ObservationLimits::default()),
            cache: Arc::new(std::sync::Mutex::new(ObservationCache::new())),
            limits: ObservationLimits::default(),
        }
    }

    /// Build with explicit limits and negotiator.
    pub fn with(negotiator: StrategyNegotiator, limits: ObservationLimits) -> Self {
        Self {
            negotiator,
            scheduler: Scheduler::new(limits),
            cache: Arc::new(std::sync::Mutex::new(ObservationCache::new())),
            limits,
        }
    }

    /// The negotiator in use.
    pub fn negotiator(&self) -> &StrategyNegotiator {
        &self.negotiator
    }

    /// The scheduler in use.
    pub fn scheduler(&self) -> &Scheduler {
        &self.scheduler
    }

    /// Drop cached data for a resource (provider event / manual refresh).
    pub fn invalidate(&self, id: &ResourceId) {
        if let Ok(mut c) = self.cache.lock() {
            c.invalidate(id, None);
        }
        self.scheduler.invalidate(id.as_str());
    }

    /// Number of cached domain entries.
    pub fn cache_len(&self) -> usize {
        self.cache.lock().map(|c| c.len()).unwrap_or(0)
    }

    /// Observe a resource.
    pub async fn observe<B: ObservationBackend>(
        &self,
        backend: &B,
        req: ObservationRequest,
    ) -> Result<ObservationSnapshot, DomainError> {
        let caps = backend.capabilities(&req.resource_id).await?;
        let plan = self.negotiator.negotiate(&caps, &req.domains)?;

        // A forced request must also clear the scheduler's coalescing slot,
        // otherwise "manual refresh" silently returns the coalesced value from
        // the burst that is still registered.
        if req.force {
            self.scheduler.invalidate(req.resource_id.as_str());
        }

        // Cache hit: return with its real age, never as if freshly collected.
        if !req.force {
            if let Ok(cache) = self.cache.lock() {
                let mut collected: Vec<(ObservationDomain, ObservedValue)> = Vec::new();
                let mut all_fresh = !plan.domains.is_empty();
                let mut age_ms = 0u64;
                for d in &plan.domains {
                    match cache.get(&req.resource_id, *d, plan.mode.as_str()) {
                        Some(hit) => {
                            age_ms = age_ms.max(hit.age_ms);
                            if !hit.is_fresh(req.max_age_ms.unwrap_or(plan.max_age_ms)) {
                                all_fresh = false;
                            }
                            collected.push((
                                *d,
                                hit.snapshot.get(*d).cloned().unwrap_or_else(|| {
                                    ObservedValue::new(
                                        Json::Null,
                                        sandtree_observation_model::Provenance::new(
                                            "cache",
                                            sandtree_observation_model::TrustLevel::Unverified,
                                            "1970-01-01T00:00:00Z",
                                        ),
                                    )
                                }),
                            ));
                        }
                        None => {
                            all_fresh = false;
                            break;
                        }
                    }
                }
                if all_fresh && !collected.is_empty() {
                    let mut snap = ObservationSnapshot::empty(
                        req.resource_id.clone(),
                        plan.mode,
                        ObservationHealth::Healthy,
                        now_iso(age_ms),
                    );
                    for (d, v) in collected {
                        snap.insert(d, v);
                    }
                    snap.warn(format!("served from cache, age {age_ms}ms"));
                    return Ok(snap);
                }
            }
        }

        // Collect, normalizing every domain payload to the limits.
        let mut request = req.clone();
        if request.max_age_ms.is_none() {
            request.max_age_ms = Some(plan.max_age_ms);
        }
        if request.deadline_ms.is_none() {
            request.deadline_ms = Some(plan.deadline_ms);
        }
        let resource_id = request.resource_id.clone();
        let plan_for_collect = plan.clone();
        let collected = self
            .scheduler
            .observe(request, move |r| {
                let id = r.resource_id.clone();
                let plan = plan_for_collect.clone();
                async move { backend.collect(&id, &plan).await }
            })
            .await;

        let mut snapshot = match collected {
            Ok(s) => s,
            // Degradation: observation failed but the resource still exists.
            Err(e) if is_degradable(&e) => {
                let mut degraded = ObservationSnapshot::empty(
                    resource_id.clone(),
                    plan.mode,
                    ObservationHealth::Unavailable,
                    crate::cache::now_rfc3339(),
                );
                degraded.warn(format!(
                    "observation degraded: {} {}",
                    e.code.as_str(),
                    e.message
                ));
                degraded
            }
            Err(e) => return Err(e),
        };

        let mut rejections: Vec<String> = Vec::new();
        for (key, value) in snapshot.values.iter_mut() {
            let domain_limits = ObservationDomain::from_wire(key)
                .map(|d| ObservationLimits::for_domain(d).tightened_by(self.limits))
                .unwrap_or(self.limits);
            match clamp_json(&value.value, &domain_limits) {
                Ok(clamped) => value.value = clamped,
                Err(e) => {
                    value.provenance.partial = true;
                    rejections.push(format!("domain {key} rejected: {}", e.code.as_str()));
                    value.value = Json::Null;
                }
            }
        }
        for message in rejections {
            snapshot.warn(message);
        }

        snapshot.health = domain_health(&snapshot.values, &plan.domains);
        if snapshot.mode == ObservationMode::Metadata
            && snapshot.health == ObservationHealth::Healthy
        {
            snapshot.warn("metadata-only: internal state is not observable");
        }

        if let Ok(mut cache) = self.cache.lock() {
            for d in &plan.domains {
                if snapshot.get(*d).is_some() {
                    cache.put(&resource_id, *d, plan.mode.as_str(), &snapshot);
                }
            }
        }
        Ok(snapshot)
    }
}

impl Default for ObservationService {
    fn default() -> Self {
        Self::new()
    }
}

/// Whether an error should degrade instead of propagate.
///
/// Protocol and security failures are *not* degradable: a malformed or hostile
/// envelope must surface, be audited, and must never be silently swallowed
/// (DD-OBS §12).
fn is_degradable(e: &DomainError) -> bool {
    !matches!(
        e.code,
        ErrorCode::OBS_ENVELOPE_INVALID | ErrorCode::OBS_GUEST_PATH_ESCAPE
    )
}

fn now_iso(age_ms: u64) -> String {
    let now = crate::cache::now_ms().saturating_sub(age_ms);
    let secs = (now / 1000) as i64;
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        sod / 3600,
        (sod % 3600) / 60,
        sod % 60
    )
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sandtree_observation_model::{ObservationMode, Provenance, TrustLevel};
    use std::collections::BTreeMap;

    struct FakeBackend {
        caps: ObservationCapabilities,
        calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        fail_with: Option<DomainError>,
    }

    impl FakeBackend {
        fn new(modes: &[(ObservationMode, &[ObservationDomain])]) -> Self {
            let mut caps = ObservationCapabilities::default();
            for (m, d) in modes {
                caps.modes.push(*m);
                caps.domains.insert(m.as_str().to_string(), d.to_vec());
            }
            Self {
                caps,
                calls: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                fail_with: None,
            }
        }
    }

    impl ObservationBackend for FakeBackend {
        async fn capabilities(
            &self,
            _id: &ResourceId,
        ) -> Result<ObservationCapabilities, DomainError> {
            Ok(self.caps.clone())
        }

        async fn collect(
            &self,
            id: &ResourceId,
            plan: &ObservationPlan,
        ) -> Result<ObservationSnapshot, DomainError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if let Some(e) = &self.fail_with {
                return Err(clone_domain_error(e));
            }
            let mut snap = ObservationSnapshot::empty(
                id.clone(),
                plan.mode,
                ObservationHealth::Healthy,
                "2026-10-07T00:00:00Z",
            );
            let mut values = BTreeMap::new();
            let declared = self.caps.domains_in(plan.mode);
            let serve: Vec<&ObservationDomain> = if declared.is_empty() {
                plan.domains.iter().collect()
            } else {
                plan.domains
                    .iter()
                    .filter(|d| declared.contains(d))
                    .collect()
            };
            for d in serve {
                values.insert(
                    d.as_str().to_string(),
                    ObservedValue::new(
                        serde_json::json!({ "domain": d.as_str() }),
                        Provenance::new("fake", TrustLevel::ProviderNative, "2026-10-07T00:00:00Z"),
                    ),
                );
            }
            snap.values = values;
            Ok(snap)
        }
    }

    /// `DomainError` is not `Clone`; rebuild one for the fake backend.
    fn clone_domain_error(e: &DomainError) -> DomainError {
        DomainError::new(e.code, e.message.clone())
            .with_detail(e.detail.clone().unwrap_or_default())
    }

    fn rid() -> ResourceId {
        ResourceId::derive(&["res"])
    }

    fn req() -> ObservationRequest {
        ObservationRequest::new(rid(), vec![ObservationDomain::System])
    }

    #[tokio::test]
    async fn collects_then_serves_from_cache() {
        let svc = ObservationService::new();
        let b = FakeBackend::new(&[(ObservationMode::Native, &[ObservationDomain::System])]);
        let first = svc.observe(&b, req()).await.unwrap();
        assert_eq!(first.mode, ObservationMode::Native);
        assert_eq!(first.health, ObservationHealth::Healthy);
        assert_eq!(b.calls.load(std::sync::atomic::Ordering::SeqCst), 1);

        let second = svc.observe(&b, req()).await.unwrap();
        assert_eq!(
            b.calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "a fresh cache entry must not hit the provider"
        );
        assert!(second.warnings.iter().any(|w| w.contains("cache")));
    }

    #[tokio::test]
    async fn forced_request_bypasses_the_cache() {
        let svc = ObservationService::new();
        let b = FakeBackend::new(&[(ObservationMode::Native, &[ObservationDomain::System])]);
        svc.observe(&b, req()).await.unwrap();
        svc.observe(&b, req().forced()).await.unwrap();
        assert_eq!(b.calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn collection_failure_degrades_instead_of_erroring() {
        // FR-079 / ADR-OBS-001: an unobservable sandbox is not an error.
        let svc = ObservationService::new();
        let mut b = FakeBackend::new(&[(ObservationMode::Exec, &[ObservationDomain::System])]);
        b.fail_with = Some(DomainError::new(
            ErrorCode::OBS_DEADLINE_EXCEEDED,
            "collector timed out",
        ));
        let snap = svc.observe(&b, req()).await.unwrap();
        assert_eq!(snap.health, ObservationHealth::Unavailable);
        assert!(snap.warnings.iter().any(|w| w.contains("ST-OBS-002")));
    }

    #[tokio::test]
    async fn security_violations_are_never_swallowed() {
        // A hostile envelope must surface, not degrade quietly.
        let svc = ObservationService::new();
        let mut b = FakeBackend::new(&[(ObservationMode::Probe, &[ObservationDomain::System])]);
        b.fail_with = Some(DomainError::new(
            ErrorCode::OBS_ENVELOPE_INVALID,
            "sequence regression",
        ));
        let err = svc.observe(&b, req()).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::OBS_ENVELOPE_INVALID);
    }

    #[tokio::test]
    async fn partial_coverage_marks_the_snapshot_degraded() {
        let svc = ObservationService::new();
        // The provider can only answer `system` although two domains were asked.
        let b = FakeBackend::new(&[(ObservationMode::Native, &[ObservationDomain::System])]);
        let r = ObservationRequest::new(
            rid(),
            vec![ObservationDomain::System, ObservationDomain::Filesystem],
        );
        let snap = svc.observe(&b, r).await.unwrap();
        assert_eq!(snap.health, ObservationHealth::Degraded);
    }

    #[tokio::test]
    async fn metadata_only_is_flagged_in_the_snapshot() {
        let svc = ObservationService::new();
        let b = FakeBackend::new(&[(ObservationMode::Metadata, &[ObservationDomain::Health])]);
        let snap = svc
            .observe(
                &b,
                ObservationRequest::new(rid(), vec![ObservationDomain::Health]),
            )
            .await
            .unwrap();
        assert_eq!(snap.mode, ObservationMode::Metadata);
        assert!(snap.warnings.iter().any(|w| w.contains("metadata-only")));
    }

    #[tokio::test]
    async fn oversized_domain_payload_is_marked_partial() {
        let svc = ObservationService::with(
            StrategyNegotiator::new(),
            ObservationLimits {
                max_domain_bytes: 16,
                ..ObservationLimits::default()
            },
        );
        let b = FakeBackend::new(&[(ObservationMode::Native, &[ObservationDomain::System])]);
        let snap = svc.observe(&b, req()).await.unwrap();
        let v = snap.get(ObservationDomain::System).unwrap();
        assert!(v.is_partial());
        assert_eq!(v.value, Json::Null);
        assert!(snap.warnings.iter().any(|w| w.contains("ST-OBS-007")));
    }

    #[tokio::test]
    async fn invalidation_forces_the_next_request_to_collect() {
        let svc = ObservationService::new();
        let b = FakeBackend::new(&[(ObservationMode::Native, &[ObservationDomain::System])]);
        svc.observe(&b, req()).await.unwrap();
        svc.invalidate(&rid());
        svc.observe(&b, req()).await.unwrap();
        assert_eq!(b.calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    }
}
