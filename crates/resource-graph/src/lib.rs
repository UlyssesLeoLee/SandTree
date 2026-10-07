//! SandTree unified resource topology: in-memory tree + relation indexes and
//! the stale → tombstone reconcile lifecycle (FR-002, FR-003, FR-004).

#![deny(missing_docs)]

pub mod graph;

pub use graph::{
    now_ms, now_rfc3339, Change, ChangeKind, Metadata, ResourceFilter, ResourceGraph, TreeNode,
};
