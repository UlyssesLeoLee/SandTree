//! Event envelope (DD-DATA §7, FR-063).
//!
//! Events are part of the data contract, not log output: subscribers
//! (Desktop/CLI) consume them to keep views in sync, and every event carries a
//! correlation id so a UI action can be traced back to an operation job.

use serde::{Deserialize, Serialize};
use serde_json::Value as Json;

use crate::id::ResourceId;
use crate::resource::{Correlation, Timestamp};

/// Severity of an event.
///
/// Ordering is meaningful: `Info < Warning < Error < Audit`, so a subscriber can
/// ask for "at least this important" with a single comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Informational.
    Info,
    /// Something degraded but usable.
    Warning,
    /// Failure.
    Error,
    /// Audit record for a privileged action (FR-064).
    Audit,
}

impl Severity {
    /// Wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Warning => "warning",
            Severity::Error => "error",
            Severity::Audit => "audit",
        }
    }
}

/// Typed event names (DD-DATA §7).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EventType {
    /// A resource appeared in the graph.
    ResourceAdded,
    /// A resource field changed.
    ResourceChanged,
    /// A resource was removed or tombstoned.
    ResourceRemoved,
    /// Provider health transition.
    ProviderHealthChanged,
    /// Operation progress tick.
    OperationProgress,
    /// Operation reached a terminal state.
    OperationCompleted,
    /// Plugin routing generation changed (hot swap, FR-052).
    PluginGenerationChanged,
    /// Audit record appended (FR-064).
    AuditRecorded,
    /// An observation snapshot was produced or refreshed (FR-075).
    ObservationSnapshot,
    /// Event-log subscription lifecycle (FR-063).
    Heartbeat,
}

impl EventType {
    /// Wire name.
    pub fn as_str(&self) -> &'static str {
        match self {
            EventType::ResourceAdded => "ResourceAdded",
            EventType::ResourceChanged => "ResourceChanged",
            EventType::ResourceRemoved => "ResourceRemoved",
            EventType::ProviderHealthChanged => "ProviderHealthChanged",
            EventType::OperationProgress => "OperationProgress",
            EventType::OperationCompleted => "OperationCompleted",
            EventType::PluginGenerationChanged => "PluginGenerationChanged",
            EventType::AuditRecorded => "AuditRecorded",
            EventType::ObservationSnapshot => "ObservationSnapshot",
            EventType::Heartbeat => "Heartbeat",
        }
    }
}

/// The event envelope delivered to subscribers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EventRecord {
    /// Unique event id.
    pub event_id: String,
    /// Typed name.
    pub event_type: EventType,
    /// Emission timestamp (RFC3339).
    pub ts: Timestamp,
    /// Subject resource, when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_id: Option<ResourceId>,
    /// Owning provider, when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_id: Option<String>,
    /// Owning plugin, when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plugin_id: Option<String>,
    /// Correlation back to the originating request.
    pub correlation_id: Correlation,
    /// Severity.
    pub severity: Severity,
    /// Non-secret payload.
    pub payload: Json,
}

impl EventRecord {
    /// Construct an event with a fresh id and the current time.
    pub fn new(event_type: EventType, correlation_id: Correlation, payload: Json) -> Self {
        Self {
            event_id: uuid::Uuid::new_v4().to_string(),
            event_type,
            ts: chrono::Utc::now().to_rfc3339(),
            resource_id: None,
            provider_id: None,
            plugin_id: None,
            correlation_id,
            severity: Severity::Info,
            payload,
        }
    }

    /// Attach the subject resource.
    pub fn with_resource(mut self, id: ResourceId) -> Self {
        self.resource_id = Some(id);
        self
    }

    /// Attach the provider.
    pub fn with_provider(mut self, id: impl Into<String>) -> Self {
        self.provider_id = Some(id.into());
        self
    }

    /// Attach the plugin.
    pub fn with_plugin(mut self, id: impl Into<String>) -> Self {
        self.plugin_id = Some(id.into());
        self
    }

    /// Set severity.
    pub fn with_severity(mut self, sev: Severity) -> Self {
        self.severity = sev;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_carries_correlation_and_resource() {
        let c = Correlation::generate();
        let rid = ResourceId::derive(&["x"]);
        let ev = EventRecord::new(
            EventType::ResourceAdded,
            c.clone(),
            serde_json::json!({"name":"web"}),
        )
        .with_resource(rid.clone())
        .with_severity(Severity::Info);
        let v = serde_json::to_value(&ev).unwrap();
        assert_eq!(v["correlation_id"], c.id().as_str());
        assert_eq!(v["resource_id"], rid.as_str());
        assert_eq!(v["event_type"], "ResourceAdded");
        assert_eq!(v["severity"], "info");
    }

    #[test]
    fn event_without_resource_omits_field() {
        let ev = EventRecord::new(EventType::Heartbeat, Correlation::generate(), Json::Null);
        let v = serde_json::to_value(&ev).unwrap();
        assert!(v.get("resource_id").is_none());
    }

    #[test]
    fn all_event_types_have_names() {
        let types = [
            EventType::ResourceAdded,
            EventType::ResourceChanged,
            EventType::ResourceRemoved,
            EventType::ProviderHealthChanged,
            EventType::OperationProgress,
            EventType::OperationCompleted,
            EventType::PluginGenerationChanged,
            EventType::AuditRecorded,
            EventType::ObservationSnapshot,
            EventType::Heartbeat,
        ];
        for t in types {
            assert!(!t.as_str().is_empty());
        }
    }
}
