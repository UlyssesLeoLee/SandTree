//! Operation model (DD-SW §6; `operation_job` table).
//!
//! Every mutation or long-running read creates an operation job before the
//! provider call is dispatched, so a crashed daemon leaves a recoverable
//! `interrupted` record rather than a silent no-op (NFR-A03).

use serde::{Deserialize, Serialize};
use serde_json::Value as Json;

use crate::id::ResourceId;
use crate::resource::Correlation;

/// Lifecycle of an operation job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationState {
    /// Accepted, not yet dispatched.
    Pending,
    /// Dispatched to a provider.
    Running,
    /// Succeeded; the target resource is reconciled afterwards.
    Succeeded,
    /// Failed with a stable error code.
    Failed,
    /// Cancelled by client or daemon shutdown.
    Cancelled,
    /// Daemon died while the job was running (recovery path, NFR-A03).
    Interrupted,
}

impl OperationState {
    /// Wire name stored in `operation_job.state`.
    pub fn as_str(self) -> &'static str {
        match self {
            OperationState::Pending => "pending",
            OperationState::Running => "running",
            OperationState::Succeeded => "succeeded",
            OperationState::Failed => "failed",
            OperationState::Cancelled => "cancelled",
            OperationState::Interrupted => "interrupted",
        }
    }

    /// Parse a DB state string.
    pub fn from_wire(s: &str) -> Self {
        match s {
            "running" => OperationState::Running,
            "succeeded" => OperationState::Succeeded,
            "failed" => OperationState::Failed,
            "cancelled" => OperationState::Cancelled,
            "interrupted" => OperationState::Interrupted,
            _ => OperationState::Pending,
        }
    }

    /// Terminal states accept no further transitions.
    pub fn is_terminal(self) -> bool {
        !matches!(self, OperationState::Pending | OperationState::Running)
    }
}

/// Operation identifier (`operation_job.id`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OperationId(String);

impl OperationId {
    /// Fresh random operation id.
    pub fn generate() -> Self {
        let seed = crate::id::CorrelationId::generate();
        Self(seed.into_string())
    }

    /// Borrow the raw id.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Parse from wire form.
    pub fn parse(raw: &str) -> Self {
        Self(raw.to_string())
    }
}

/// Operation kinds accepted by the operation manager.
///
/// This is deliberately not a free-form string: the kernel validates the kind
/// before policy evaluation so a typo cannot reach a provider (ST-CORE-001).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    /// Bring a resource up (FR-011, FR-023).
    Start,
    /// Bring a resource down without destroying it (FR-011, FR-023).
    Stop,
    /// Stop then start, preserving identity.
    Restart,
    /// Irreversible teardown; requires confirmation (NFR-U02).
    Destroy,
    /// Suspend a container (FR-023).
    Pause,
    /// Resume a paused container.
    Unpause,
    /// Run a command inside a running resource (FR-013, FR-025).
    Exec,
    /// Fetch an image from a registry (FR-026).
    Pull,
    /// Build an image from a context (FR-026, SHOULD).
    Build,
    /// Add a repository tag to an image.
    Tag,
    /// Delete a resource; `force` defaults to false (FR-023).
    Remove,
    /// Bulk removal of unreferenced resources; requires strong confirmation (FR-027).
    Prune,
    /// Create a resource.
    Create,
    /// Produce an observation snapshot (FR-070).
    Observe,
    /// Stream container/sandbox logs (FR-024).
    Logs,
    /// Stream resource statistics (FR-029).
    Stats,
    /// Read file content through the VFS (FR-014).
    Read,
    /// Write file content through the VFS, policy-gated (FR-015).
    Write,
    /// Create a logical snapshot (FR-016, FR-044).
    Snapshot,
    /// Diff two snapshots or a file (FR-043).
    Diff,
    /// Re-run discovery for a subtree (FR-001).
    Refresh,
    /// Re-establish a broken provider connection (FR-029 backoff/reconcile).
    Reconnect,
}

impl OperationKind {
    /// Wire name used by IPC `operation.invoke`.
    pub fn as_str(self) -> &'static str {
        match self {
            OperationKind::Start => "start",
            OperationKind::Stop => "stop",
            OperationKind::Restart => "restart",
            OperationKind::Destroy => "destroy",
            OperationKind::Pause => "pause",
            OperationKind::Unpause => "unpause",
            OperationKind::Exec => "exec",
            OperationKind::Pull => "pull",
            OperationKind::Build => "build",
            OperationKind::Tag => "tag",
            OperationKind::Remove => "remove",
            OperationKind::Prune => "prune",
            OperationKind::Create => "create",
            OperationKind::Observe => "observe",
            OperationKind::Logs => "logs",
            OperationKind::Stats => "stats",
            OperationKind::Read => "read",
            OperationKind::Write => "write",
            OperationKind::Snapshot => "snapshot",
            OperationKind::Diff => "diff",
            OperationKind::Refresh => "refresh",
            OperationKind::Reconnect => "reconnect",
        }
    }

    /// Parse from wire form.
    pub fn from_wire(s: &str) -> Option<Self> {
        Some(match s {
            "start" => OperationKind::Start,
            "stop" => OperationKind::Stop,
            "restart" => OperationKind::Restart,
            "destroy" => OperationKind::Destroy,
            "pause" => OperationKind::Pause,
            "unpause" => OperationKind::Unpause,
            "exec" => OperationKind::Exec,
            "pull" => OperationKind::Pull,
            "build" => OperationKind::Build,
            "tag" => OperationKind::Tag,
            "remove" => OperationKind::Remove,
            "prune" => OperationKind::Prune,
            "create" => OperationKind::Create,
            "observe" => OperationKind::Observe,
            "logs" => OperationKind::Logs,
            "stats" => OperationKind::Stats,
            "read" => OperationKind::Read,
            "write" => OperationKind::Write,
            "snapshot" => OperationKind::Snapshot,
            "diff" => OperationKind::Diff,
            "refresh" => OperationKind::Refresh,
            "reconnect" => OperationKind::Reconnect,
            _ => return None,
        })
    }

    /// Operations that are destructive and therefore require explicit
    /// confirmation and audit (NFR-U02, FR-064).
    pub fn is_destructive(self) -> bool {
        matches!(
            self,
            OperationKind::Destroy | OperationKind::Remove | OperationKind::Prune
        )
    }

    /// Operations that must never be issued with `force` by default (FR-023).
    pub fn defaults_to_non_forced(self) -> bool {
        matches!(self, OperationKind::Remove | OperationKind::Destroy)
    }
}

/// A request to mutate or observe a resource.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OperationRequest {
    /// Target resource.
    pub resource_id: ResourceId,
    /// What to do.
    pub op: OperationKind,
    /// Operation arguments; provider-specific keys stay inside the provider.
    #[serde(default)]
    pub args: Json,
    /// Cross-plane correlation id.
    pub correlation_id: Correlation,
    /// Wall-clock deadline in milliseconds since the Unix epoch.
    ///
    /// Provider adapters must honour this; observation adds its own per-domain
    /// budget on top (DD-OBS §12.3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deadline_ms: Option<u64>,
}

impl OperationRequest {
    /// Construct without a deadline.
    pub fn new(
        resource_id: ResourceId,
        op: OperationKind,
        args: Json,
        correlation_id: Correlation,
    ) -> Self {
        Self {
            resource_id,
            op,
            args,
            correlation_id,
            deadline_ms: None,
        }
    }

    /// Set the deadline.
    pub fn with_deadline_ms(mut self, ms: u64) -> Self {
        self.deadline_ms = Some(ms);
        self
    }
}

/// Progress notification emitted while an operation runs (FR-063).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OperationProgress {
    /// Operation id.
    pub operation_id: OperationId,
    /// Fraction complete in `0.0..=1.0`, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fraction: Option<f32>,
    /// Human-readable step.
    pub message: String,
    /// Free-form non-secret detail.
    #[serde(default, skip_serializing_if = "Json::is_null")]
    pub detail: Json,
}

/// Terminal result of an operation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OperationOutcome {
    /// Job state.
    pub state: OperationState,
    /// Stable error code when failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<crate::error::ErrorCode>,
    /// Provider result payload (non-secret).
    #[serde(default, skip_serializing_if = "Json::is_null")]
    pub result: Json,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorCode;

    #[test]
    fn kind_wire_round_trip() {
        let all = [
            OperationKind::Start,
            OperationKind::Stop,
            OperationKind::Restart,
            OperationKind::Destroy,
            OperationKind::Pause,
            OperationKind::Unpause,
            OperationKind::Exec,
            OperationKind::Pull,
            OperationKind::Build,
            OperationKind::Tag,
            OperationKind::Remove,
            OperationKind::Prune,
            OperationKind::Create,
            OperationKind::Observe,
            OperationKind::Logs,
            OperationKind::Stats,
            OperationKind::Read,
            OperationKind::Write,
            OperationKind::Snapshot,
            OperationKind::Diff,
            OperationKind::Refresh,
            OperationKind::Reconnect,
        ];
        for k in all {
            assert_eq!(OperationKind::from_wire(k.as_str()), Some(k));
        }
        assert_eq!(OperationKind::from_wire("nope"), None);
    }

    #[test]
    fn destructive_kinds_are_flagged() {
        assert!(OperationKind::Destroy.is_destructive());
        assert!(OperationKind::Remove.is_destructive());
        assert!(OperationKind::Prune.is_destructive());
        assert!(!OperationKind::Stop.is_destructive());
    }

    #[test]
    fn terminal_states_close_the_job() {
        assert!(OperationState::Succeeded.is_terminal());
        assert!(OperationState::Failed.is_terminal());
        assert!(!OperationState::Running.is_terminal());
        assert!(!OperationState::Pending.is_terminal());
    }

    #[test]
    fn operation_state_wire_round_trip() {
        for s in [
            OperationState::Pending,
            OperationState::Running,
            OperationState::Succeeded,
            OperationState::Failed,
            OperationState::Cancelled,
            OperationState::Interrupted,
        ] {
            assert_eq!(OperationState::from_wire(s.as_str()), s);
        }
    }

    #[test]
    fn outcome_serializes_error_code() {
        let o = OperationOutcome {
            state: OperationState::Failed,
            error_code: Some(ErrorCode::POLICY_DENIED),
            result: Json::Null,
        };
        let json = serde_json::to_string(&o).unwrap();
        assert!(json.contains("ST-POL-001"));
        assert!(serde_json::from_str::<OperationOutcome>(&json).is_ok());
    }
}
