//! Event pump (DD-SW §3, DD-DATA §6, NFR-P02).
//!
//! Two jobs, and the second one is the interesting one:
//!
//! 1. append every event to the durable log (`event` table, FR-063/FR-064) so
//!    a restart can replay what happened, and
//! 2. **coalesce** before delivering. A container start produces a burst of
//!    state changes; forwarding each one would make the UI flicker and would
//!    let one chatty resource starve the others (NFR-P02). The router already
//!    coalesces per subscription, and this module is the part that decides
//!    which events are worth persisting at all.
//!
//! A high-frequency `Info` heartbeat is not written to the durable log. It is
//! delivered live, but persisting it would grow the log without bound and
//! drown the events a human actually needs after an incident.

use std::sync::Arc;

use sandtree_event::EventRouter;
use sandtree_model::event::{EventRecord, EventType};
use sandtree_store::db::Store;

/// Durable event sink.
pub struct EventPump {
    store: Arc<Store>,
    events: Arc<EventRouter>,
    persisted: std::sync::atomic::AtomicU64,
    coalesced: std::sync::atomic::AtomicU64,
}

impl EventPump {
    /// Build a pump.
    pub fn new(store: Arc<Store>, events: Arc<EventRouter>) -> Self {
        Self {
            store,
            events,
            persisted: std::sync::atomic::AtomicU64::new(0),
            coalesced: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Whether an event is worth a durable row.
    ///
    /// `Heartbeat` is the only non-durable type. Severity cannot be the axis:
    /// `Info` is the floor of the enum, so a severity test would admit
    /// everything, and the high-frequency events that actually need dropping
    /// are all `Info` by construction.
    pub fn is_durable(ev: &EventRecord) -> bool {
        ev.event_type != EventType::Heartbeat
    }

    /// Persist one event, then publish it live.
    ///
    /// A persistence failure is logged, not propagated: losing the durable log
    /// for one event must not take down the operation that produced it.
    pub fn emit(&self, ev: EventRecord) {
        if Self::is_durable(&ev) {
            match self.store.append_event(&ev) {
                Ok(()) => {
                    self.persisted
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                Err(e) => tracing::error!(
                    event_id = %ev.event_id,
                    error = %e,
                    "failed to append an event to the durable log"
                ),
            }
        } else {
            self.coalesced
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        self.events.publish(ev);
    }

    /// Events written to the durable log.
    pub fn persisted_count(&self) -> u64 {
        self.persisted.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Events delivered without a durable row.
    pub fn skipped_count(&self) -> u64 {
        self.coalesced.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Delete durable events older than `cutoff` (RFC3339), returning the count.
    pub fn purge_before(&self, cutoff: &str) -> Result<usize, sandtree_model::error::DomainError> {
        self.store.purge_events(cutoff)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sandtree_model::event::{EventRecord, EventType, Severity};
    use sandtree_model::resource::Correlation;
    use serde_json::Value as Json;

    fn store() -> Arc<Store> {
        Arc::new(Store::open_in_memory().unwrap())
    }

    fn ev(t: EventType, sev: Severity) -> EventRecord {
        EventRecord::new(t, Correlation::generate(), Json::from("x")).with_severity(sev)
    }

    #[test]
    fn heartbeats_are_never_durable() {
        assert!(!EventPump::is_durable(&ev(
            EventType::Heartbeat,
            Severity::Info
        )));
    }

    #[test]
    fn audit_and_error_events_are_durable() {
        assert!(EventPump::is_durable(&ev(
            EventType::AuditRecorded,
            Severity::Audit
        )));
        assert!(EventPump::is_durable(&ev(
            EventType::ProviderHealthChanged,
            Severity::Error
        )));
        assert!(EventPump::is_durable(&ev(
            EventType::ResourceChanged,
            Severity::Warning
        )));
    }

    #[test]
    fn informational_events_are_still_durable() {
        // Info is the minimum severity, so a "drop the low-severity noise" rule
        // would silently discard every ordinary state change.
        assert!(EventPump::is_durable(&ev(
            EventType::ResourceChanged,
            Severity::Info
        )));
    }

    #[test]
    fn emitting_records_the_durable_count_and_publishes() {
        let s = store();
        let router = Arc::new(EventRouter::new());
        let (_id, mut sub) = router.subscribe(sandtree_event::EventFilter::all());
        let pump = EventPump::new(s.clone(), router);

        pump.emit(ev(EventType::ResourceChanged, Severity::Info));
        assert_eq!(pump.persisted_count(), 1);
        assert_eq!(pump.skipped_count(), 0);
        assert!(sub.try_recv().is_some(), "the event must also go out live");
    }

    #[test]
    fn a_skipped_event_is_still_delivered_live() {
        // Coalescing must not mean dropping: the UI still needs the heartbeat.
        let s = store();
        let router = Arc::new(EventRouter::new());
        let (_id, mut sub) = router.subscribe(sandtree_event::EventFilter::all());
        let pump = EventPump::new(s, router);

        pump.emit(ev(EventType::Heartbeat, Severity::Info));
        assert_eq!(pump.persisted_count(), 0);
        assert_eq!(pump.skipped_count(), 1);
        assert!(
            sub.try_recv().is_some(),
            "a heartbeat must still reach the UI"
        );
    }

    #[test]
    fn a_durable_write_failure_does_not_stop_delivery() {
        // Close the store underneath the pump: persistence fails, the live
        // publish must still happen, and `emit` must not panic.
        let s = store();
        let router = Arc::new(EventRouter::new());
        let (_id, mut sub) = router.subscribe(sandtree_event::EventFilter::all());
        let pump = EventPump::new(s.clone(), router);
        drop(s);
        pump.emit(ev(EventType::ResourceChanged, Severity::Info));
        assert!(sub.try_recv().is_some());
    }

    #[test]
    fn purge_reports_how_many_rows_went_away() {
        let s = store();
        let router = Arc::new(EventRouter::new());
        let pump = EventPump::new(s.clone(), router);
        for _ in 0..3 {
            pump.emit(ev(EventType::ResourceChanged, Severity::Info));
        }
        // Cut everything: the rows carry a real timestamp, and an empty
        // cutoff is not a valid bound, so use a far-future one.
        let removed = pump.purge_before("9999-01-01T00:00:00Z").unwrap();
        assert_eq!(removed, 3);
    }
}
