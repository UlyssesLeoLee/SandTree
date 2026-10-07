//! Resource node / kind / state / relation model (DD-SW §2, BD §4).

use serde::{Deserialize, Serialize};
use serde_json::Value as Json;

use crate::capability::CapabilitySet;
use crate::id::{CorrelationId, EndpointId, PluginId, ResourceId};

/// RFC3339 timestamp, the only timestamp form crossing a boundary
/// (`schemas/observation_snapshot_v1.schema.json` uses `date-time`).
pub type Timestamp = String;

/// Resource kinds in the unified topology (BD §4).
///
/// Ordering is meaningful: it is the primary sort key for the topology view, so
/// that `Host → Sandbox/DockerRuntime → Container …` renders consistently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    /// The local host; root of the primary tree.
    Host,
    /// An isolation environment: Windows Sandbox / Docker Sandbox / Multipass instance.
    Sandbox,
    /// A Docker Engine / Moby-compatible endpoint, including one nested inside a sandbox
    /// (FR-078 Docker-in-Sandbox).
    DockerRuntime,
    /// A Docker container.
    Container,
    /// A Docker image.
    Image,
    /// A Docker volume.
    Volume,
    /// A Docker network.
    Network,
    /// A Compose project (FR-030).
    ComposeProject,
    /// A Compose service inside a project (FR-032).
    ComposeService,
    /// A workspace / VFS root inside a sandbox or container (FR-014).
    Workspace,
}

impl ResourceKind {
    /// Wire name used in DB rows and IPC payloads.
    pub fn as_str(self) -> &'static str {
        match self {
            ResourceKind::Host => "host",
            ResourceKind::Sandbox => "sandbox",
            ResourceKind::DockerRuntime => "docker-runtime",
            ResourceKind::Container => "container",
            ResourceKind::Image => "image",
            ResourceKind::Volume => "volume",
            ResourceKind::Network => "network",
            ResourceKind::ComposeProject => "compose-project",
            ResourceKind::ComposeService => "compose-service",
            ResourceKind::Workspace => "workspace",
        }
    }

    /// Every kind, used by tests and by provider capability tables.
    pub fn all() -> &'static [ResourceKind] {
        &[
            ResourceKind::Host,
            ResourceKind::Sandbox,
            ResourceKind::DockerRuntime,
            ResourceKind::Container,
            ResourceKind::Image,
            ResourceKind::Volume,
            ResourceKind::Network,
            ResourceKind::ComposeProject,
            ResourceKind::ComposeService,
            ResourceKind::Workspace,
        ]
    }
}

/// Normalized resource state (BD §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceState {
    /// Provider has not reported the resource this discovery round.
    ///
    /// Reconcile marks missing resources stale first and only tombstones them after
    /// the grace period (DD-SW §5). Absence is therefore never immediate removal.
    Unknown,
    /// Being created.
    Creating,
    /// Running / active.
    Running,
    /// Stopped but the resource still exists.
    Stopped,
    /// Paused (container semantics).
    Paused,
    /// Exited (container semantics).
    Exited,
    /// Degraded: exists, control works, observation is partial (FR-079).
    Degraded,
    /// Being destroyed.
    Destroying,
    /// Destroyed / removed.
    Destroyed,
    /// Tombstoned after exceeding the reconcile grace period.
    Tombstoned,
}

impl ResourceState {
    /// Wire name used in DB rows.
    pub fn as_str(self) -> &'static str {
        match self {
            ResourceState::Unknown => "unknown",
            ResourceState::Creating => "creating",
            ResourceState::Running => "running",
            ResourceState::Stopped => "stopped",
            ResourceState::Paused => "paused",
            ResourceState::Exited => "exited",
            ResourceState::Degraded => "degraded",
            ResourceState::Destroying => "destroying",
            ResourceState::Destroyed => "destroyed",
            ResourceState::Tombstoned => "tombstoned",
        }
    }

    /// Terminal states are never returned by discovery.
    pub fn is_terminal(self) -> bool {
        matches!(self, ResourceState::Destroyed | ResourceState::Tombstoned)
    }

    /// Parse a DB/IPC state string.
    pub fn from_wire(s: &str) -> Self {
        match s {
            "creating" => ResourceState::Creating,
            "running" => ResourceState::Running,
            "stopped" => ResourceState::Stopped,
            "paused" => ResourceState::Paused,
            "exited" => ResourceState::Exited,
            "degraded" => ResourceState::Degraded,
            "destroying" => ResourceState::Destroying,
            "destroyed" => ResourceState::Destroyed,
            "tombstoned" => ResourceState::Tombstoned,
            _ => ResourceState::Unknown,
        }
    }
}

/// The unified resource node (DD-SW §2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResourceNode {
    /// Stable opaque identity.
    pub id: ResourceId,
    /// Normalized kind.
    pub kind: ResourceKind,
    /// Owning provider plugin.
    pub provider_id: PluginId,
    /// Display name. Never part of identity.
    pub name: String,
    /// Normalized state.
    pub state: ResourceState,
    /// Primary tree parent. `None` only for the host root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<ResourceId>,
    /// Operations the provider declares as available (FR-061).
    ///
    /// UI must not show an action whose capability is absent, and policy must
    /// refuse it even if the UI is bypassed (FR-061, NFR-U02).
    pub capabilities: CapabilitySet,
    /// Provider-specific non-secret metadata.
    #[serde(default)]
    pub metadata: Json,
    /// Last time this provider confirmed the resource (RD §9: no guessing).
    pub last_seen: Timestamp,
}

impl ResourceNode {
    /// Minimal constructor used by discovery adapters.
    pub fn new(
        id: ResourceId,
        kind: ResourceKind,
        provider_id: PluginId,
        name: impl Into<String>,
        state: ResourceState,
        parent_id: Option<ResourceId>,
        last_seen: Timestamp,
    ) -> Self {
        Self {
            id,
            kind,
            provider_id,
            name: name.into(),
            state,
            parent_id,
            capabilities: CapabilitySet::empty(),
            metadata: Json::Object(Default::default()),
            last_seen,
        }
    }

    /// Builder for capabilities.
    pub fn with_capabilities(mut self, caps: CapabilitySet) -> Self {
        self.capabilities = caps;
        self
    }

    /// Builder for provider metadata.
    pub fn with_metadata(mut self, metadata: Json) -> Self {
        self.metadata = metadata;
        self
    }

    /// Read a single metadata key without leaking provider SDK types into the kernel.
    pub fn meta_str(&self, key: &str) -> Option<&str> {
        self.metadata.get(key).and_then(Json::as_str)
    }

    /// Docker endpoint identity, when this resource belongs to one.
    ///
    /// Docker resource ids are derived from `endpoint_id + native_id` (DD-PLG §5),
    /// so the endpoint must be recoverable from metadata for nested topologies.
    pub fn endpoint_id(&self) -> Option<EndpointId> {
        self.meta_str("endpoint_id")
            .and_then(EndpointId::from_str_ok)
    }
}

/// Typed non-tree relations (FR-004, BD §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RelationKind {
    /// container → image (`uses-image`).
    UsesImage,
    /// container → volume (`mounts`).
    Mounts,
    /// container → network (`attached-network`).
    AttachedNetwork,
    /// container → compose project (`member-of-compose`).
    MemberOfCompose,
    /// host ↔ sandbox ↔ container mount/bind source (`workspace-mount`).
    WorkspaceMount,
    /// sandbox → nested docker runtime (`docker-in-sandbox`, FR-078).
    DockerInSandbox,
}

impl RelationKind {
    /// Wire name stored in `resource_relation.kind`.
    pub fn as_str(self) -> &'static str {
        match self {
            RelationKind::UsesImage => "uses-image",
            RelationKind::Mounts => "mounts",
            RelationKind::AttachedNetwork => "attached-network",
            RelationKind::MemberOfCompose => "member-of-compose",
            RelationKind::WorkspaceMount => "workspace-mount",
            RelationKind::DockerInSandbox => "docker-in-sandbox",
        }
    }

    /// Parse a DB relation kind string.
    pub fn from_wire(s: &str) -> Option<Self> {
        Some(match s {
            "uses-image" => RelationKind::UsesImage,
            "mounts" => RelationKind::Mounts,
            "attached-network" => RelationKind::AttachedNetwork,
            "member-of-compose" => RelationKind::MemberOfCompose,
            "workspace-mount" => RelationKind::WorkspaceMount,
            "docker-in-sandbox" => RelationKind::DockerInSandbox,
            _ => return None,
        })
    }
}

/// A typed edge between two resources (DD-SW §2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Relation {
    /// Source resource.
    pub from: ResourceId,
    /// Target resource.
    pub to: ResourceId,
    /// Edge kind.
    pub kind: RelationKind,
    /// Non-secret edge metadata.
    #[serde(default)]
    pub metadata: Json,
}

impl Relation {
    /// Construct a relation with empty metadata.
    pub fn new(from: ResourceId, to: ResourceId, kind: RelationKind) -> Self {
        Self {
            from,
            to,
            kind,
            metadata: Json::Object(Default::default()),
        }
    }
}

/// Correlation carrier for operations and events (FR-063).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Correlation(#[serde(with = "correlation_repr")] CorrelationId);

mod correlation_repr {
    use super::CorrelationId;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(id: &CorrelationId, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(id.as_str())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<CorrelationId, D::Error> {
        let raw = String::deserialize(d)?;
        CorrelationId::parse(&raw).map_err(serde::de::Error::custom)
    }
}

impl Correlation {
    /// Fresh correlation id for a new request.
    pub fn generate() -> Self {
        Self(CorrelationId::generate())
    }

    /// Borrow the inner id.
    pub fn id(&self) -> &CorrelationId {
        &self.0
    }

    /// Parse from wire form.
    pub fn parse(raw: &str) -> Option<Self> {
        CorrelationId::parse(raw).ok().map(Self)
    }
}

impl std::fmt::Display for Correlation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_node_round_trips() {
        // UT-001 ResourceNode serialize/deserialize
        let node = ResourceNode::new(
            ResourceId::derive(&["ep", "c1"]),
            ResourceKind::Container,
            PluginId::derive(&["sandtree.provider.docker"]),
            "web",
            ResourceState::Running,
            None,
            "2026-10-07T00:00:00Z".into(),
        )
        .with_capabilities(CapabilitySet::empty());
        let json = serde_json::to_string(&node).unwrap();
        let back: ResourceNode = serde_json::from_str(&json).unwrap();
        assert_eq!(node, back);
    }

    #[test]
    fn state_wire_names_are_stable() {
        for kind in ResourceKind::all() {
            assert!(!kind.as_str().is_empty());
        }
        assert_eq!(ResourceState::from_wire("running"), ResourceState::Running);
        assert_eq!(ResourceState::from_wire("nonsense"), ResourceState::Unknown);
    }

    #[test]
    fn relation_kind_wire_round_trip() {
        for s in [
            "uses-image",
            "mounts",
            "attached-network",
            "member-of-compose",
            "workspace-mount",
            "docker-in-sandbox",
        ] {
            assert_eq!(RelationKind::from_wire(s).unwrap().as_str(), s);
        }
    }

    #[test]
    fn endpoint_id_recovered_from_metadata() {
        let ep = EndpointId::derive(&["npipe:////./pipe/docker_engine"]);
        let node = ResourceNode::new(
            ResourceId::derive(&["x"]),
            ResourceKind::DockerRuntime,
            PluginId::derive(&["p"]),
            "docker",
            ResourceState::Running,
            None,
            "2026-10-07T00:00:00Z".into(),
        )
        .with_metadata(serde_json::json!({ "endpoint_id": ep.as_str() }));
        assert_eq!(node.endpoint_id().as_ref(), Some(&ep));
    }

    #[test]
    fn correlation_serializes_as_plain_string() {
        let c = Correlation::generate();
        let json = serde_json::to_string(&c).unwrap();
        assert_eq!(json, format!("\"{}\"", c.id().as_str()));
        assert_eq!(serde_json::from_str::<Correlation>(&json).unwrap(), c);
    }
}
