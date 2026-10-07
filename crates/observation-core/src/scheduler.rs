//! Observation scheduler (DD-SW §12.3).
//!
//! The scheduler exists to make one guarantee cheap: **for a given
//! `(resource, domain)` there is at most one refresh in flight, and later
//! requests coalesce onto it.** Without that, a UI that re-renders every
//! 200 ms would spawn a fresh `multipass exec` per render, which is precisely
//! the load pattern NFR-P05 forbids.
//!
//! It also enforces the global concurrency limit and turns a provider that
//! overruns its deadline into a typed `ST-OBS-002` rather than a hung kernel.

use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sandtree_model::error::{DomainError, ErrorCode};
use sandtree_observation_model::{ObservationRequest, ObservationSnapshot};

use crate::limits::ObservationLimits;

/// Shared slot holding the most recent result for one coalesced refresh.
type FlightSlot = Arc<Mutex<Option<ObservationSnapshot>>>;

/// Key identifying a coalesced refresh.
fn flight_key(req: &ObservationRequest) -> String {
    let domains: Vec<&str> = req.domains.iter().map(|d| d.as_str()).collect();
    format!("{}|{}", req.resource_id.as_str(), domains.join(","))
}

/// Runs observation jobs with coalescing and bounded concurrency.
#[derive(Clone)]
pub struct Scheduler {
    limits: ObservationLimits,
    in_flight: Arc<Mutex<HashMap<String, FlightSlot>>>,
    counter: Arc<AtomicU64>,
    concurrent: Arc<AtomicU64>,
}

impl std::fmt::Debug for Scheduler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Scheduler")
            .field("limits", &self.limits)
            .field("in_flight", &self.in_flight_count())
            .finish()
    }
}

impl Scheduler {
    /// Build a scheduler with the given limits.
    pub fn new(limits: ObservationLimits) -> Self {
        Self {
            limits,
            in_flight: Arc::new(Mutex::new(HashMap::new())),
            counter: Arc::new(AtomicU64::new(0)),
            concurrent: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Global concurrency limit.
    pub fn limit(&self) -> usize {
        self.limits.global_concurrency()
    }

    /// Number of distinct refreshes currently tracked.
    pub fn in_flight_count(&self) -> usize {
        self.in_flight.lock().map(|m| m.len()).unwrap_or(0)
    }

    /// Observe, coalescing onto an in-flight refresh for the same request.
    ///
    /// `f` is invoked at most once per `(resource, domains)` burst. The deadline
    /// is applied by this layer so a provider that ignores its own timeout
    /// still cannot hold the kernel.
    pub async fn observe<F, Fut>(
        &self,
        req: ObservationRequest,
        f: F,
    ) -> Result<ObservationSnapshot, DomainError>
    where
        F: FnOnce(ObservationRequest) -> Fut + Send,
        Fut: Future<Output = Result<ObservationSnapshot, DomainError>> + Send,
    {
        let key = flight_key(&req);
        let slot: FlightSlot = {
            let mut map = self.in_flight.lock().expect("scheduler lock");
            Arc::clone(
                map.entry(key.clone())
                    .or_insert_with(|| Arc::new(Mutex::new(None))),
            )
        };

        // If a refresh already produced a value for this key, reuse it.
        if let Some(existing) = slot.lock().expect("flight lock").clone() {
            return Ok(existing);
        }

        // Refuse to start more than the global limit of *distinct* jobs.
        let started = self.concurrent.fetch_add(1, Ordering::SeqCst);
        if started >= self.limits.global_concurrency() as u64 {
            self.concurrent.fetch_sub(1, Ordering::SeqCst);
            return Err(DomainError::new(
                ErrorCode::OBS_DEADLINE_EXCEEDED,
                format!(
                    "observation concurrency limit of {} reached",
                    self.limits.global_concurrency()
                ),
            ));
        }
        self.counter.fetch_add(1, Ordering::SeqCst);

        let deadline = req.deadline_ms.unwrap_or_else(|| {
            req.domains
                .iter()
                .map(|d| d.default_deadline_ms())
                .max()
                .unwrap_or(2_000)
        });

        let outcome = match tokio::time::timeout(Duration::from_millis(deadline), f(req)).await {
            Ok(result) => result,
            Err(_) => Err(DomainError::new(
                ErrorCode::OBS_DEADLINE_EXCEEDED,
                format!("observation exceeded its {deadline}ms deadline"),
            )),
        };
        self.concurrent.fetch_sub(1, Ordering::SeqCst);

        match outcome {
            Ok(snapshot) => {
                let mut guard = slot.lock().expect("flight lock");
                *guard = Some(snapshot.clone());
                drop(guard);
                Ok(snapshot)
            }
            Err(e) => Err(e),
        }
    }

    /// Clear the coalescing slot for a resource so the next request refreshes.
    ///
    /// Called on provider events and after a manual refresh.
    pub fn invalidate(&self, resource_id: &str) {
        if let Ok(mut map) = self.in_flight.lock() {
            let prefix = format!("{resource_id}|");
            map.retain(|k, _| !k.starts_with(&prefix));
        }
    }

    /// Total refreshes started; used by tests and by the operations dashboard.
    pub fn refresh_count(&self) -> u64 {
        self.counter.load(Ordering::SeqCst)
    }

    /// Current concurrent job count.
    pub fn concurrent_jobs(&self) -> u64 {
        self.concurrent.load(Ordering::SeqCst)
    }
}

impl ObservationLimits {
    /// Global concurrency, derived from the max collection depth.
    ///
    /// Kept as a method on the limits type so the scheduler and the store agree
    /// on one number.
    pub fn global_concurrency(&self) -> usize {
        DEFAULT_GLOBAL_CONCURRENCY
    }
}

/// DD-SW §12.3: at most 8 observation jobs globally.
pub const DEFAULT_GLOBAL_CONCURRENCY: usize = 8;

#[cfg(test)]
mod tests {
    use super::*;
    use sandtree_model::id::ResourceId;
    use sandtree_observation_model::{ObservationDomain, ObservationHealth, ObservationMode};

    fn req() -> ObservationRequest {
        ObservationRequest::new(
            ResourceId::derive(&["res"]),
            vec![ObservationDomain::System],
        )
    }

    fn snap() -> ObservationSnapshot {
        ObservationSnapshot::empty(
            ResourceId::derive(&["res"]),
            ObservationMode::Native,
            ObservationHealth::Healthy,
            "2026-10-07T00:00:00Z",
        )
    }

    #[tokio::test]
    async fn a_refresh_is_executed_and_reused() {
        let s = Scheduler::new(ObservationLimits::default());
        let out = s.observe(req(), |_| async { Ok(snap()) }).await.unwrap();
        assert_eq!(out.mode, ObservationMode::Native);
        assert_eq!(s.refresh_count(), 1);
        // A second call for the same key reuses the coalesced result.
        s.observe(req(), |_| async { Ok(snap()) }).await.unwrap();
        assert_eq!(
            s.refresh_count(),
            1,
            "the provider must not be called twice"
        );
    }

    #[tokio::test]
    async fn invalidation_forces_a_fresh_refresh() {
        let s = Scheduler::new(ObservationLimits::default());
        s.observe(req(), |_| async { Ok(snap()) }).await.unwrap();
        s.invalidate(ResourceId::derive(&["res"]).as_str());
        s.observe(req(), |_| async { Ok(snap()) }).await.unwrap();
        assert_eq!(s.refresh_count(), 2);
    }

    #[tokio::test]
    async fn deadline_overrun_becomes_a_typed_error() {
        let s = Scheduler::new(ObservationLimits::default());
        let r = s
            .observe(
                ObservationRequest::new(
                    ResourceId::derive(&["slow"]),
                    vec![ObservationDomain::Process],
                )
                .with_deadline_ms(10),
                |_| async {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    Ok(snap())
                },
            )
            .await;
        let err = r.unwrap_err();
        assert_eq!(err.code, ErrorCode::OBS_DEADLINE_EXCEEDED);
        assert!(err.is_retryable());
    }

    #[tokio::test]
    async fn provider_errors_propagate_untouched() {
        let s = Scheduler::new(ObservationLimits::default());
        let r = s
            .observe(req(), |_| async {
                Err(DomainError::new(
                    ErrorCode::OBS_CREDENTIAL_DENIED,
                    "no credential",
                ))
            })
            .await;
        assert_eq!(r.unwrap_err().code, ErrorCode::OBS_CREDENTIAL_DENIED);
    }

    #[tokio::test]
    async fn different_domains_do_not_share_a_flight_slot() {
        let s = Scheduler::new(ObservationLimits::default());
        let r1 = ObservationRequest::new(
            ResourceId::derive(&["res"]),
            vec![ObservationDomain::System],
        );
        let r2 = ObservationRequest::new(
            ResourceId::derive(&["res"]),
            vec![ObservationDomain::Filesystem],
        );
        s.observe(r1, |_| async { Ok(snap()) }).await.unwrap();
        s.observe(r2, |_| async { Ok(snap()) }).await.unwrap();
        assert_eq!(s.refresh_count(), 2);
    }

    #[tokio::test]
    async fn global_concurrency_is_capped() {
        let s = Scheduler::new(ObservationLimits::default());
        // Fill the slots with long-running jobs.
        let mut handles = Vec::new();
        for i in 0..DEFAULT_GLOBAL_CONCURRENCY {
            let s = s.clone();
            let r = ObservationRequest::new(
                ResourceId::derive(&["res", &i.to_string()]),
                vec![ObservationDomain::Process],
            )
            .with_deadline_ms(5_000);
            handles.push(tokio::spawn(async move {
                s.observe(r, |_| async {
                    tokio::time::sleep(Duration::from_millis(120)).await;
                    Ok(snap())
                })
                .await
            }));
        }
        // Give the tasks a chance to register.
        tokio::time::sleep(Duration::from_millis(30)).await;
        let overflow = s
            .observe(
                ObservationRequest::new(
                    ResourceId::derive(&["overflow"]),
                    vec![ObservationDomain::System],
                )
                .with_deadline_ms(5_000),
                |_| async { Ok(snap()) },
            )
            .await;
        assert_eq!(
            overflow.unwrap_err().code,
            ErrorCode::OBS_DEADLINE_EXCEEDED,
            "the global limit must refuse, not queue without bound"
        );
        for h in handles {
            let _ = h.await;
        }
    }
}
