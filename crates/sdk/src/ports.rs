//! Provider ports: the traits every provider implements (DD-SW §11 test seam,
//! DD-PLG §12.1 capability split).
//!
//! The kernel depends on these traits only. A provider may be
//!
//! * an in-process Rust crate implementing them directly (official providers), or
//! * a WASM component loaded through `plugin-host`, which adapts the WIT ABI to
//!   exactly these traits.
//!
//! Because both shapes land on the same traits, the kernel has no way to tell
//! them apart, which is what keeps NFR-O02 true: no provider SDK type can reach
//! kernel code even by accident.

use std::collections::BTreeMap;

use sandtree_model::error::DomainError;
use sandtree_model::id::{PluginId, ResourceId};
use sandtree_model::operation::{OperationOutcome, OperationRequest};
use sandtree_model::resource::{Relation, ResourceNode};
use sandtree_observation_model::{
    FileMetadata, ObservationCapabilities, ObservationRequest, ObservationSnapshot,
};
use sandtree_vfs::{ReadWindow, WorkspaceUri};
use serde::{Deserialize, Serialize};
use serde_json::Value as Json;

use crate::manifest::PluginKind;

/// Static provider identity (DD-PLG §1 `descriptor`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderDescriptor {
    /// Plugin id.
    pub plugin_id: String,
    /// SemVer string.
    pub version: String,
    /// Provider role.
    pub kind: PluginKind,
}

/// Health of a provider instance (DD-OBS §12.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ProviderHealth {
    /// Fully functional.
    Healthy,
    /// Usable but partially degraded (e.g. observation channel down).
    Degraded {
        /// Why it is degraded.
        reason: String,
    },
    /// Not usable at all (missing external product, denied credential).
    Unavailable {
        /// Why it is unavailable.
        reason: String,
    },
    /// Data is older than the freshness policy.
    Stale {
        /// Age in milliseconds.
        age_ms: u64,
    },
}

impl ProviderHealth {
    /// Whether lifecycle control still works.
    ///
    /// ADR-OBS-001: an unusable observation channel must not disable control.
    pub fn control_is_available(&self) -> bool {
        !matches!(self, ProviderHealth::Unavailable { .. })
    }

    /// Wire summary used in events and the UI.
    pub fn summary(&self) -> &'static str {
        match self {
            ProviderHealth::Healthy => "healthy",
            ProviderHealth::Degraded { .. } => "degraded",
            ProviderHealth::Unavailable { .. } => "unavailable",
            ProviderHealth::Stale { .. } => "stale",
        }
    }
}

/// One discovery page (DD-PLG §1 `discover`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DiscoverBatch {
    /// Provider-owned resources, already normalized to domain DTOs.
    pub resources: Vec<ResourceNode>,
    /// Typed relations discovered alongside the resources.
    pub relations: Vec<Relation>,
    /// Opaque cursor for the next page; `None` means the scan is complete.
    pub cursor: Option<String>,
}

/// Result of a guest command (DD-PLG §9).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExecOutcome {
    /// Process exit code.
    pub exit_code: i32,
    /// Captured stdout (already bounded/truncated by the provider).
    pub stdout: String,
    /// Captured stderr.
    pub stderr: String,
    /// Whether output was truncated at the configured cap.
    pub truncated: bool,
}

/// Resource lifecycle + invocation port.
#[async_trait::async_trait]
pub trait ResourceProvider: Send + Sync {
    /// Static identity.
    fn descriptor(&self) -> ProviderDescriptor;

    /// Current health.
    async fn health(&self) -> Result<ProviderHealth, DomainError>;

    /// Discover one page of resources.
    async fn discover(&self, cursor: Option<String>) -> Result<DiscoverBatch, DomainError>;

    /// Inspect one resource.
    async fn inspect(&self, id: &ResourceId) -> Result<ResourceNode, DomainError>;

    /// Invoke a lifecycle/IO operation.
    async fn invoke(&self, req: &OperationRequest) -> Result<OperationOutcome, DomainError>;

    /// Release external handles. Must be idempotent.
    async fn shutdown(&self);
}

/// Observation Plane port (DD-SW §12.2).
#[async_trait::async_trait]
pub trait ObservationProvider: Send + Sync {
    /// Modes and domains available for one resource.
    async fn capabilities(&self, id: &ResourceId) -> Result<ObservationCapabilities, DomainError>;

    /// Produce a snapshot.
    async fn observe(&self, req: &ObservationRequest) -> Result<ObservationSnapshot, DomainError>;
}

/// Workspace file port (DD-PLG §12.1 `FileProvider`).
#[async_trait::async_trait]
pub trait FileProvider: Send + Sync {
    /// List one directory level. Directory enumeration returns metadata only
    /// (FR-077): no file content is read here.
    async fn list(&self, uri: &WorkspaceUri) -> Result<Vec<FileMetadata>, DomainError>;

    /// Stat one path.
    async fn stat(&self, uri: &WorkspaceUri) -> Result<FileMetadata, DomainError>;

    /// Read a byte window.
    async fn read(&self, uri: &WorkspaceUri, window: ReadWindow) -> Result<Vec<u8>, DomainError>;

    /// Write file content.
    ///
    /// Implementations must canonicalize the target (symlink / reparse check)
    /// **after** the host already normalized the URI, because either check alone
    /// is bypassable (NFR-S05).
    async fn write(&self, uri: &WorkspaceUri, bytes: &[u8]) -> Result<(), DomainError>;
}

/// Command execution port (DD-PLG §12.1 `ExecProvider`).
#[async_trait::async_trait]
pub trait ExecProvider: Send + Sync {
    /// Run a command with an explicit timeout.
    async fn exec(
        &self,
        id: &ResourceId,
        argv: &[String],
        timeout_ms: u64,
    ) -> Result<ExecOutcome, DomainError>;
}

/// A provider instance registered with the kernel.
pub struct ProviderInstance {
    /// Owning plugin id.
    pub plugin_id: PluginId,
    /// Active generation.
    pub generation: u64,
    /// Lifecycle port, when the provider has one.
    pub resource: Option<std::sync::Arc<dyn ResourceProvider>>,
    /// Observation port, when the provider has one.
    pub observation: Option<std::sync::Arc<dyn ObservationProvider>>,
    /// File port, when the provider has one.
    pub files: Option<std::sync::Arc<dyn FileProvider>>,
    /// Exec port, when the provider has one.
    pub exec: Option<std::sync::Arc<dyn ExecProvider>>,
}

impl ProviderInstance {
    /// Whether this instance can service resource lifecycle calls.
    pub fn has_resource(&self) -> bool {
        self.resource.is_some()
    }

    /// Whether this instance can produce observation snapshots.
    pub fn has_observation(&self) -> bool {
        self.observation.is_some()
    }
}

/// A registry of provider instances, keyed by plugin id.
///
/// The registry is intentionally dumb: routing by capability lives in the
/// kernel, so a provider that only implements observation can be registered
/// without pretending to own lifecycle (DD-PLG §12.1).
#[derive(Default)]
pub struct ProviderRegistry {
    instances: BTreeMap<PluginId, ProviderInstance>,
}

impl ProviderRegistry {
    /// Empty registry.
    pub fn new() -> Self {
        Self {
            instances: BTreeMap::new(),
        }
    }

    /// Register (or replace) an instance.
    pub fn register(&mut self, instance: ProviderInstance) {
        self.instances.insert(instance.plugin_id.clone(), instance);
    }

    /// Remove an instance.
    pub fn remove(&mut self, plugin_id: &PluginId) -> Option<ProviderInstance> {
        self.instances.remove(plugin_id)
    }

    /// Look up an instance.
    pub fn get(&self, plugin_id: &PluginId) -> Option<&ProviderInstance> {
        self.instances.get(plugin_id)
    }

    /// Iterate instances in deterministic plugin-id order.
    pub fn iter(&self) -> impl Iterator<Item = (&PluginId, &ProviderInstance)> {
        self.instances.iter()
    }

    /// Number of registered instances.
    pub fn len(&self) -> usize {
        self.instances.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.instances.is_empty()
    }

    /// Instances implementing the resource port.
    pub fn resource_providers(&self) -> Vec<(PluginId, std::sync::Arc<dyn ResourceProvider>)> {
        self.instances
            .iter()
            .filter_map(|(id, inst)| inst.resource.clone().map(|p| (id.clone(), p)))
            .collect()
    }

    /// Instances implementing the observation port.
    pub fn observation_providers(
        &self,
    ) -> Vec<(PluginId, std::sync::Arc<dyn ObservationProvider>)> {
        self.instances
            .iter()
            .filter_map(|(id, inst)| inst.observation.clone().map(|p| (id.clone(), p)))
            .collect()
    }
}

/// Helper: build an empty domain map. Used by providers that produce partial
/// snapshots and want type inference.
pub fn empty_values() -> BTreeMap<String, sandtree_observation_model::ObservedValue> {
    BTreeMap::new()
}

/// Helper: wrap a JSON value as an observation payload with no provenance.
///
/// Providers must set provenance explicitly; this helper exists so that a
/// missing-provenance bug shows up as `unverified` rather than as absent data.
pub fn unverified_value(v: Json) -> sandtree_observation_model::ObservedValue {
    sandtree_observation_model::ObservedValue::new(
        v,
        sandtree_observation_model::Provenance::new(
            "unknown",
            sandtree_observation_model::TrustLevel::Unverified,
            crate::manifest::now_rfc3339(),
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use sandtree_observation_model::TrustLevel;

    #[test]
    fn health_control_availability_follows_observation_independence() {
        // ADR-OBS-001: unavailable observation must not disable control.
        assert!(ProviderHealth::Healthy.control_is_available());
        assert!(ProviderHealth::Degraded {
            reason: "probe down".into()
        }
        .control_is_available());
        assert!(ProviderHealth::Stale { age_ms: 10_000 }.control_is_available());
        assert!(!ProviderHealth::Unavailable {
            reason: "multipass not installed".into()
        }
        .control_is_available());
    }

    #[test]
    fn registry_keeps_deterministic_order_and_capability_separation() {
        let mut reg = ProviderRegistry::new();
        let a = PluginId::derive(&["a"]);
        let b = PluginId::derive(&["b"]);
        reg.register(ProviderInstance {
            plugin_id: b.clone(),
            generation: 1,
            resource: None,
            observation: None,
            files: None,
            exec: None,
        });
        reg.register(ProviderInstance {
            plugin_id: a.clone(),
            generation: 2,
            resource: None,
            observation: None,
            files: None,
            exec: None,
        });
        let ids: Vec<&PluginId> = reg.iter().map(|(id, _)| id).collect();
        assert_eq!(ids.len(), 2);
        assert_eq!(reg.get(&a).unwrap().generation, 2);
        assert!(reg.get(&a).unwrap().resource.is_none());
        assert!(reg.resource_providers().is_empty());
        assert_eq!(reg.remove(&b).map(|i| i.plugin_id), Some(b));
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn unverified_helper_is_the_weakest_trust() {
        let v = unverified_value(serde_json::json!({"a": 1}));
        assert_eq!(v.provenance.trust, TrustLevel::Unverified);
        assert!(!v.provenance.trust.is_security_authoritative());
    }
}
