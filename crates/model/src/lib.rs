//! SandTree domain model.
//!
//! This crate is the only vocabulary shared by the kernel, plugins, IPC and the
//! UI. It intentionally has **no** dependency on any provider SDK, on SQLite,
//! on Wasmtime or on the filesystem: NFR-O02 requires the kernel to speak only
//! in domain DTOs, and that rule is enforced by this crate's dependency list
//! rather than by review comments.

#![deny(missing_docs)]

pub mod capability;
pub mod error;
pub mod event;
pub mod id;
pub mod operation;
pub mod resource;

pub use capability::{Capability, CapabilityNamespace, CapabilityParseError, CapabilitySet};
pub use error::{DomainError, ErrorCode};
pub use event::{EventRecord, EventType, Severity};
pub use id::{
    AppId, CorrelationId, EndpointId, Generation, IdError, PluginId, ResourceId, SessionId,
    SnapshotId,
};
pub use operation::{
    OperationId, OperationKind, OperationOutcome, OperationProgress, OperationRequest,
    OperationState,
};
pub use resource::{
    Correlation, Relation, RelationKind, ResourceKind, ResourceNode, ResourceState, Timestamp,
};

/// Convenience alias for a JSON object payload crossing a boundary.
pub type Metadata = serde_json::Value;
