//! SandTree observation core: strategy negotiation, refresh coalescing,
//! freshness cache and bounded payload normalization (FR-070..FR-080;
//! DD-OBS §4, §13; DD-SW §12.3).
//!
//! No provider SDK may be referenced here (NFR-O02). The crate decides *how* to
//! observe and what the result may claim; providers decide *what* they can read.

#![deny(missing_docs)]

pub mod cache;
pub mod limits;
pub mod scheduler;
pub mod service;
pub mod strategy;

pub use cache::{now_ms, now_rfc3339, CachedSnapshot, ObservationCache};
pub use limits::{
    clamp_json, domain_health, ObservationLimits, DEFAULT_MAX_COLLECTION_LEN,
    DEFAULT_MAX_DOMAIN_BYTES, DEFAULT_MAX_JSON_DEPTH, DEFAULT_MAX_STRING_LEN,
};
pub use scheduler::{Scheduler, DEFAULT_GLOBAL_CONCURRENCY};
pub use service::ObservationService;
pub use strategy::StrategyNegotiator;
