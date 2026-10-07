//! SandTree event plane: typed router, bounded subscriber queues, backpressure
//! accounting (FR-063).

#![deny(missing_docs)]

pub mod router;

pub use router::{
    audit_recorded, closed_error, resource_changed, EventFilter, EventRouter, LagSignal,
    PublishOutcome, Subscription, SubscriptionId, DEFAULT_CAPACITY,
};
