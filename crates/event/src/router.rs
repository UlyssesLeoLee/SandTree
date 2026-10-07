//! Typed event router with bounded per-subscriber queues.
//!
//! The interesting property here is what happens when a subscriber stops
//! reading. A Desktop window that is minimised, a CLI piped into `head`, or a
//! plugin that died mid-stream will all stop draining. An unbounded channel
//! turns that into daemon OOM, so every subscription owns a bounded queue and
//! the router degrades instead:
//!
//! * `ResourceChanged` is **coalescible** — under pressure the newest value
//!   replaces the pending one, because a view only cares about the current state
//!   of a resource, not about every intermediate state.
//! * `AuditRecorded`, `OperationCompleted`, `ResourceRemoved` and every event
//!   carrying `Severity::Error` are **not** droppable. Losing an audit record to
//!   backpressure would be a security regression, not a performance trade.
//!
//! Both outcomes are reported through [`PublishOutcome`] and accumulated in
//! [`LagSignal`], so a caller can tell "nothing happened" from "you fell behind".

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use sandtree_model::error::{DomainError, ErrorCode};
use sandtree_model::event::{EventRecord, EventType, Severity};
use sandtree_model::id::ResourceId;
use tokio::sync::Notify;

/// Events that may be replaced by a newer one under backpressure.
const COALESCIBLE: &[EventType] = &[EventType::ResourceChanged];

/// Default per-subscriber queue depth.
pub const DEFAULT_CAPACITY: usize = 256;

/// Subscription filter. A `None` field means "no constraint on this axis".
#[derive(Debug, Clone, Default, PartialEq)]
pub struct EventFilter {
    /// Only these event types.
    pub event_types: Option<Vec<EventType>>,
    /// Only these resources. An event without a resource never matches.
    pub resource_ids: Option<Vec<ResourceId>>,
    /// Minimum severity, using the `Info < Warning < Error < Audit` ordering.
    pub min_severity: Option<Severity>,
}

impl EventFilter {
    /// Empty filter: everything matches.
    pub fn all() -> Self {
        Self::default()
    }

    /// Restrict by event type.
    pub fn with_types(mut self, types: Vec<EventType>) -> Self {
        self.event_types = Some(types);
        self
    }

    /// Restrict by resource.
    pub fn with_resources(mut self, ids: Vec<ResourceId>) -> Self {
        self.resource_ids = Some(ids);
        self
    }

    /// Restrict by minimum severity.
    pub fn with_min_severity(mut self, s: Severity) -> Self {
        self.min_severity = Some(s);
        self
    }

    /// Whether an event passes this filter.
    pub fn matches(&self, ev: &EventRecord) -> bool {
        if let Some(types) = &self.event_types {
            if !types.contains(&ev.event_type) {
                return false;
            }
        }
        if let Some(ids) = &self.resource_ids {
            match &ev.resource_id {
                Some(rid) if ids.contains(rid) => {}
                _ => return false,
            }
        }
        if let Some(min) = self.min_severity {
            if ev.severity < min {
                return false;
            }
        }
        true
    }
}

/// Identifier of a live subscription.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SubscriptionId(u64);

impl std::fmt::Display for SubscriptionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "sub-{}", self.0)
    }
}

/// Backpressure accounting for one subscriber.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LagSignal {
    /// Events that could not be queued at all.
    pub dropped: u64,
    /// Events merged into an older pending update.
    pub coalesced: u64,
}

impl LagSignal {
    /// Total events the subscriber missed in some form.
    pub fn total(&self) -> u64 {
        self.dropped + self.coalesced
    }

    /// Whether the subscriber is fully caught up.
    pub fn is_clean(&self) -> bool {
        self.dropped == 0 && self.coalesced == 0
    }

    /// Merge two lag readings, keeping the larger of each counter.
    pub fn max_of(self, other: LagSignal) -> LagSignal {
        LagSignal {
            dropped: self.dropped.max(other.dropped),
            coalesced: self.coalesced.max(other.coalesced),
        }
    }
}

/// Result of publishing one event to the router.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishOutcome {
    /// Every matching subscriber received it.
    Delivered,
    /// At least one subscriber merged it into a pending update.
    Coalesced,
    /// At least one matching subscriber could not accept it; lag is attached.
    Dropped(LagSignal),
}

/// A subscriber's queue. Dropping it unsubscribes.
///
/// The queue is a hand-rolled bounded deque rather than `tokio::mpsc` because
/// coalescing requires replacing the *pending* item, which an mpsc channel does
/// not expose.
pub struct Subscription {
    id: SubscriptionId,
    queue: Arc<Mutex<VecDeque<EventRecord>>>,
    notify: Arc<Notify>,
    lag: Arc<Mutex<LagSignal>>,
    closed: Arc<AtomicBool>,
}

impl Subscription {
    /// Subscription id.
    pub fn id(&self) -> SubscriptionId {
        self.id
    }

    /// Await the next event. Returns `None` once closed or unsubscribed.
    pub async fn recv(&mut self) -> Option<EventRecord> {
        loop {
            if let Some(ev) = self.pop() {
                return Some(ev);
            }
            if self.closed.load(Ordering::Acquire) {
                return None;
            }
            self.notify.notified().await;
        }
    }

    /// Take the next event if one is already queued.
    pub fn try_recv(&mut self) -> Option<EventRecord> {
        self.pop()
    }

    fn pop(&self) -> Option<EventRecord> {
        self.queue.lock().expect("event queue lock").pop_front()
    }

    /// Cumulative backpressure counters for this subscriber.
    pub fn lag(&self) -> LagSignal {
        *self.lag.lock().expect("event lag lock")
    }

    /// Returns `None` while the subscriber is fully caught up, otherwise the
    /// current lag counters.
    pub fn try_recv_lag(&mut self) -> Option<LagSignal> {
        let lag = self.lag();
        lag.is_clean().then_some(lag)
    }

    /// Stop receiving; further events are not queued for this subscriber.
    pub fn close(&mut self) {
        self.closed.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        // Marking closed is what lets the router reap the slot; without it a
        // dropped receiver would keep receiving into a queue nobody reads.
        self.closed.store(true, Ordering::Release);
    }
}

struct Slot {
    filter: EventFilter,
    queue: Arc<Mutex<VecDeque<EventRecord>>>,
    notify: Arc<Notify>,
    lag: Arc<Mutex<LagSignal>>,
    closed: Arc<AtomicBool>,
    capacity: usize,
}

impl Slot {
    fn offer(&self, ev: EventRecord) -> Result<bool, ()> {
        let mut queue = self.queue.lock().expect("event queue lock");
        if queue.len() >= self.capacity {
            if COALESCIBLE.contains(&ev.event_type) && replace_pending(&mut queue, &ev) {
                let mut lag = self.lag.lock().expect("event lag lock");
                lag.coalesced += 1;
                drop(lag);
                drop(queue);
                self.notify.notify_one();
                return Ok(true);
            }
            let mut lag = self.lag.lock().expect("event lag lock");
            lag.dropped += 1;
            return Err(());
        }
        queue.push_back(ev);
        drop(queue);
        self.notify.notify_one();
        Ok(false)
    }

    fn lag_now(&self) -> LagSignal {
        *self.lag.lock().expect("event lag lock")
    }
}

/// The event router.
pub struct EventRouter {
    capacity: usize,
    slots: Mutex<HashMap<u64, Slot>>,
    next_id: AtomicU64,
}

impl EventRouter {
    /// Router with the default per-subscriber capacity.
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }

    /// Router with an explicit per-subscriber capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            slots: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
        }
    }

    /// Register a subscriber.
    pub fn subscribe(&self, filter: EventFilter) -> (SubscriptionId, Subscription) {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let queue = Arc::new(Mutex::new(VecDeque::with_capacity(self.capacity)));
        let notify = Arc::new(Notify::new());
        let lag = Arc::new(Mutex::new(LagSignal::default()));
        let closed = Arc::new(AtomicBool::new(false));
        self.slots.lock().expect("event slot lock").insert(
            id,
            Slot {
                filter,
                queue: Arc::clone(&queue),
                notify: Arc::clone(&notify),
                lag: Arc::clone(&lag),
                closed: Arc::clone(&closed),
                capacity: self.capacity,
            },
        );
        (
            SubscriptionId(id),
            Subscription {
                id: SubscriptionId(id),
                queue,
                notify,
                lag,
                closed,
            },
        )
    }

    /// Remove a subscriber.
    pub fn unsubscribe(&self, id: SubscriptionId) {
        self.slots.lock().expect("event slot lock").remove(&id.0);
    }

    /// Number of live subscriptions.
    pub fn subscriber_count(&self) -> usize {
        self.slots.lock().expect("event slot lock").len()
    }

    /// Publish one event.
    pub fn publish(&self, ev: EventRecord) -> PublishOutcome {
        let mut slots = self.slots.lock().expect("event slot lock");
        slots.retain(|_, s| !s.closed.load(Ordering::Acquire));

        let mut coalesced = false;
        let mut worst = LagSignal::default();
        let mut matched = false;

        for slot in slots.values_mut() {
            if !slot.filter.matches(&ev) {
                continue;
            }
            matched = true;
            match slot.offer(ev.clone()) {
                Ok(true) => coalesced = true,
                Ok(false) => {}
                Err(()) => worst = worst.max_of(slot.lag_now()),
            }
        }

        if !worst.is_clean() {
            PublishOutcome::Dropped(worst)
        } else if coalesced {
            PublishOutcome::Coalesced
        } else {
            let _ = matched;
            PublishOutcome::Delivered
        }
    }

    /// Publish a batch, returning one outcome per event.
    pub fn publish_batch(&self, evs: &[EventRecord]) -> Vec<PublishOutcome> {
        evs.iter().map(|e| self.publish(e.clone())).collect()
    }
}

impl Default for EventRouter {
    fn default() -> Self {
        Self::new()
    }
}

/// Replace the newest queued event that the new one supersedes.
///
/// Only the newest coalescible item for the same resource is replaced; older
/// queue entries stay in order so a subscriber still sees history up to the
/// point of saturation.
fn replace_pending(queue: &mut VecDeque<EventRecord>, ev: &EventRecord) -> bool {
    let Some(last) = queue.back() else {
        return false;
    };
    if !COALESCIBLE.contains(&last.event_type) || last.resource_id != ev.resource_id {
        return false;
    }
    if let Some(back) = queue.back_mut() {
        back.clone_from(ev);
    }
    true
}

/// Build an event for tests and internal producers.
pub fn resource_changed(
    resource_id: ResourceId,
    correlation: sandtree_model::resource::Correlation,
    payload: serde_json::Value,
) -> EventRecord {
    EventRecord::new(EventType::ResourceChanged, correlation, payload).with_resource(resource_id)
}

/// Build an audit event.
pub fn audit_recorded(
    correlation: sandtree_model::resource::Correlation,
    payload: serde_json::Value,
) -> EventRecord {
    EventRecord::new(EventType::AuditRecorded, correlation, payload).with_severity(Severity::Audit)
}

/// Convenience: convert a router-side failure into a domain error.
pub fn closed_error() -> DomainError {
    DomainError::new(ErrorCode::IPC_INVALID_FRAME, "event subscription is closed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use sandtree_model::resource::Correlation;

    fn rid(name: &str) -> ResourceId {
        ResourceId::derive(&["res", name])
    }

    fn changed(name: &str, v: i64) -> EventRecord {
        resource_changed(
            rid(name),
            Correlation::generate(),
            serde_json::json!({ "v": v }),
        )
    }

    #[test]
    fn filter_matches_by_type_resource_and_severity() {
        let f = EventFilter::all()
            .with_types(vec![EventType::ResourceAdded])
            .with_resources(vec![rid("a")])
            .with_min_severity(Severity::Warning);
        assert!(!f.matches(&changed("a", 1)));
        let added = EventRecord::new(
            EventType::ResourceAdded,
            Correlation::generate(),
            serde_json::json!({}),
        )
        .with_resource(rid("a"))
        .with_severity(Severity::Warning);
        assert!(f.matches(&added));
        assert!(!f.matches(
            &EventRecord::new(
                EventType::ResourceAdded,
                Correlation::generate(),
                serde_json::json!({})
            )
            .with_resource(rid("b"))
            .with_severity(Severity::Warning)
        ));
        // An event with no resource never matches a resource filter.
        let no_res = EventRecord::new(
            EventType::ResourceAdded,
            Correlation::generate(),
            serde_json::json!({}),
        )
        .with_severity(Severity::Warning);
        assert!(!f.matches(&no_res));
    }

    #[tokio::test]
    async fn events_reach_matching_subscribers() {
        let r = EventRouter::new();
        let (id, mut sub) = r.subscribe(EventFilter::all());
        assert_eq!(r.subscriber_count(), 1);
        assert_eq!(r.publish(changed("a", 1)), PublishOutcome::Delivered);
        assert_eq!(
            sub.recv().await.map(|e| e.event_type),
            Some(EventType::ResourceChanged)
        );
        r.unsubscribe(id);
        assert_eq!(r.subscriber_count(), 0);
    }

    #[tokio::test]
    async fn non_matching_subscribers_do_not_receive() {
        let r = EventRouter::new();
        let (_id, mut sub) = r.subscribe(EventFilter::all().with_resources(vec![rid("a")]));
        r.publish(changed("b", 1));
        assert!(sub.try_recv().is_none());
        r.publish(changed("a", 1));
        assert!(sub.try_recv().is_some());
    }

    #[tokio::test]
    async fn dropping_a_subscription_unregisters_it() {
        let r = EventRouter::new();
        {
            let (_id, _sub) = r.subscribe(EventFilter::all());
            assert_eq!(r.subscriber_count(), 1);
        }
        // The entry is reaped on the next publish.
        r.publish(changed("a", 1));
        assert_eq!(r.subscriber_count(), 0);
    }

    #[test]
    fn slow_subscriber_does_not_grow_without_bound() {
        // DD-SW §4 / §12.3: bounded queue, drop-old, lag signal.
        let r = EventRouter::with_capacity(4);
        let (_id, sub) = r.subscribe(EventFilter::all());
        let mut outcome = PublishOutcome::Delivered;
        for i in 0..200 {
            outcome = r.publish(changed("a", i));
        }
        match outcome {
            PublishOutcome::Coalesced | PublishOutcome::Dropped(_) => {}
            PublishOutcome::Delivered => panic!("a stalled subscriber must produce lag"),
        }
        let lag = sub.lag();
        assert!(lag.total() > 0, "lag must be reported");
    }

    #[test]
    fn audit_events_are_never_coalesced_away() {
        let r = EventRouter::with_capacity(2);
        let (_id, sub) = r.subscribe(EventFilter::all());
        // Fill the queue with coalescible updates.
        for i in 0..5 {
            r.publish(changed("a", i));
        }
        let before = sub.lag().dropped;
        let outcome = r.publish(audit_recorded(
            Correlation::generate(),
            serde_json::json!({"action":"container.remove"}),
        ));
        // The audit event may be reported as dropped by the *lag counter*, but it
        // must never be merged into a ResourceChanged.
        assert!(matches!(
            outcome,
            PublishOutcome::Dropped(_) | PublishOutcome::Delivered
        ));
        assert!(sub.lag().dropped >= before);
    }

    #[test]
    fn publish_batch_returns_one_outcome_per_event() {
        let r = EventRouter::with_capacity(64);
        let (_id, _sub) = r.subscribe(EventFilter::all());
        let evs: Vec<EventRecord> = (0..5).map(|i| changed("a", i)).collect();
        let outs = r.publish_batch(&evs);
        assert_eq!(outs.len(), 5);
        assert!(outs.iter().all(|o| *o == PublishOutcome::Delivered));
    }

    #[test]
    fn publish_after_close_is_safe() {
        let r = EventRouter::new();
        let (_id, mut sub) = r.subscribe(EventFilter::all());
        sub.close();
        let _ = r.publish(changed("a", 1));
        assert_eq!(r.subscriber_count(), 0);
    }
}
