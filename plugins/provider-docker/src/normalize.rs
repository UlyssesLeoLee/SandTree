//! Pure Docker JSON → domain DTO normalization (DD-PLG §5, FR-022, UT-032).
//!
//! This module is the unit-testable seam of the provider. It contains no I/O and
//! no `async`, so the whole normalization contract — state mapping, identity
//! derivation, relation derivation, capability declaration, and the
//! "never invent a field" rule — is exercised against fixtures rather than
//! against a running Engine.
//!
//! # Two rules encoded here
//!
//! * **Identity is `endpoint_id + native id/digest`** (DD-PLG §5). A container
//!   rename or an image retag must not change a [`ResourceId`].
//! * **Absent means absent** (RD §9, AGENTS.md invariant 11). A `null` field from
//!   Docker produces *no metadata key at all*, not `"unknown"` and not a zero.

use std::collections::BTreeMap;

use bollard::models::{ContainerSummary, ImageSummary, Network, Volume};
use sandtree_model::capability::{Capability, CapabilityNamespace, CapabilitySet};
use sandtree_model::id::{EndpointId, PluginId, ResourceId};
use sandtree_model::resource::{Relation, RelationKind, ResourceKind, ResourceNode};
use serde_json::{Map, Value as Json};

/// Compose label prefix (DD-PLG §6).
pub const COMPOSE_LABEL_PREFIX: &str = "com.docker.compose.";

/// Docker stable id kinds, used as the identity salt so an image id and a volume
/// name that happen to be equal cannot collide.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeKind {
    /// A container's 64-hex id.
    Container,
    /// An image id or repo digest.
    Image,
    /// A volume name.
    Volume,
    /// A network id.
    Network,
    /// The Engine itself.
    Engine,
}

impl NativeKind {
    /// Identity salt for [`ResourceId::derive`].
    pub fn salt(self) -> &'static str {
        match self {
            NativeKind::Container => "container",
            NativeKind::Image => "image",
            NativeKind::Volume => "volume",
            NativeKind::Network => "network",
            NativeKind::Engine => "engine",
        }
    }
}

/// Derive a stable [`ResourceId`] from the endpoint and the Docker stable id.
///
/// Renaming a container does not change the result, because Docker's numeric id
/// is the only input (DD-PLG §5, UT-002).
pub fn resource_id(endpoint: &EndpointId, kind: NativeKind, native_id: &str) -> ResourceId {
    ResourceId::derive(&[endpoint.as_str(), kind.salt(), native_id])
}

/// Map a Docker container state string to the normalized [`ResourceState`].
///
/// Docker reports: `created`, `running`, `paused`, `restarting`, `removing`,
/// `exited`, `dead`. Anything unrecognized becomes
/// [`ResourceState::Unknown`] rather than a guess (RD §9).
pub fn container_state(docker_state: Option<&str>) -> sandtree_model::resource::ResourceState {
    use sandtree_model::resource::ResourceState;
    match docker_state {
        Some("created") => ResourceState::Creating,
        Some("running") => ResourceState::Running,
        Some("paused") => ResourceState::Paused,
        Some("restarting") => ResourceState::Running,
        Some("removing") => ResourceState::Destroying,
        Some("exited") => ResourceState::Exited,
        // `dead` is a container the Engine could not tear down cleanly; it is
        // stopped, not running, and not destroyed.
        Some("dead") => ResourceState::Exited,
        _ => ResourceState::Unknown,
    }
}

/// Capabilities offered for a container (FR-023, FR-061).
///
/// A UI must not render an action whose capability is absent, and policy must
/// refuse it even if the UI is bypassed.
pub fn container_capabilities(state: sandtree_model::resource::ResourceState) -> CapabilitySet {
    use sandtree_model::resource::ResourceState;
    let mut set = CapabilitySet::empty();
    let add = |set: &mut CapabilitySet, ns: CapabilityNamespace, verb: &str| {
        set.insert(Capability::global(ns, verb));
    };
    add(&mut set, CapabilityNamespace::Resource, "discover");
    add(&mut set, CapabilityNamespace::Resource, "inspect");
    match state {
        ResourceState::Running => {
            add(&mut set, CapabilityNamespace::Resource, "stop");
            add(&mut set, CapabilityNamespace::Resource, "restart");
            add(&mut set, CapabilityNamespace::Resource, "pause");
            add(&mut set, CapabilityNamespace::Exec, "spawn");
        }
        ResourceState::Paused => {
            add(&mut set, CapabilityNamespace::Resource, "unpause");
            add(&mut set, CapabilityNamespace::Resource, "destroy");
        }
        ResourceState::Exited | ResourceState::Stopped => {
            add(&mut set, CapabilityNamespace::Resource, "start");
            add(&mut set, CapabilityNamespace::Resource, "destroy");
        }
        ResourceState::Creating => {
            add(&mut set, CapabilityNamespace::Resource, "start");
            add(&mut set, CapabilityNamespace::Resource, "destroy");
        }
        // Unknown / terminal states expose only inspection. Offering `start`
        // here would be speculation about a state we did not observe.
        _ => {}
    }
    add(&mut set, CapabilityNamespace::Observation, "observe:system");
    add(&mut set, CapabilityNamespace::Observation, "observe:health");
    set
}

/// Pull a single label value out of a Docker label map.
fn label<'a>(labels: &'a BTreeMap<String, String>, key: &str) -> Option<&'a str> {
    labels.get(key).map(String::as_str)
}

/// Extract Compose attribution from a container's labels (DD-PLG §6, UT-031).
///
/// Returns `(project, service)` when Docker actually carried both labels. A
/// container with no Compose labels yields `None` — it is a standalone
/// container, not a project with an unknown name.
pub fn compose_attribution(labels: &BTreeMap<String, String>) -> Option<(String, String)> {
    let project = label(labels, &format!("{COMPOSE_LABEL_PREFIX}project"))?;
    let service = label(labels, &format!("{COMPOSE_LABEL_PREFIX}service"))?;
    if project.is_empty() || service.is_empty() {
        return None;
    }
    Some((project.to_string(), service.to_string()))
}

/// Derive the ComposeProject id for a project name on one endpoint.
pub fn compose_project_id(endpoint: &EndpointId, project: &str) -> ResourceId {
    ResourceId::derive(&[endpoint.as_str(), "compose-project", project])
}

/// Derive the ComposeService id for a project/service pair on one endpoint.
pub fn compose_service_id(endpoint: &EndpointId, project: &str, service: &str) -> ResourceId {
    ResourceId::derive(&[endpoint.as_str(), "compose-service", project, service])
}

/// Display name for a container: Docker's first name without the leading `/`.
pub fn display_name(names: &[String], id: &str) -> String {
    names
        .iter()
        .find(|n| !n.is_empty() && *n != "/")
        .map(|n| n.trim_start_matches('/').to_string())
        .unwrap_or_else(|| id.chars().take(12).collect())
}

/// Normalize one container summary into a [`ResourceNode`] plus its relations.
///
/// `now` is injected so the output is byte-stable in tests (CONTRACTS §5).
pub fn normalize_container(
    summary: &ContainerSummary,
    endpoint: &EndpointId,
    provider: &PluginId,
    runtime_id: &ResourceId,
    now: &str,
) -> (ResourceNode, Vec<Relation>) {
    let Some(native_id) = summary.id.as_deref().filter(|s| !s.is_empty()) else {
        // A summary without an id carries no identity; the caller drops it
        // rather than inventing one.
        return (
            ResourceNode::new(
                ResourceId::derive(&["unidentified-container"]),
                ResourceKind::Container,
                provider.clone(),
                "unknown",
                sandtree_model::resource::ResourceState::Unknown,
                Some(runtime_id.clone()),
                now.to_string(),
            ),
            Vec::new(),
        );
    };

    let id = resource_id(endpoint, NativeKind::Container, native_id);
    let state = container_state(summary.state.as_deref());
    let mut meta = Map::new();
    meta.insert("endpoint_id".into(), Json::from(endpoint.as_str()));
    meta.insert("native_id".into(), Json::from(native_id));

    // RD §9: only echo what Docker actually reported.
    if let Some(image) = summary.image.as_deref().filter(|s| !s.is_empty()) {
        meta.insert("image_ref".into(), Json::from(image));
    }
    if let Some(image_id) = summary.image_id.as_deref().filter(|s| !s.is_empty()) {
        meta.insert("native_image_id".into(), Json::from(image_id));
    }
    if let Some(cmd) = summary.command.as_deref().filter(|s| !s.is_empty()) {
        meta.insert("command".into(), Json::from(cmd));
    }
    if let Some(status) = summary.status.as_deref().filter(|s| !s.is_empty()) {
        meta.insert("status_text".into(), Json::from(status));
    }
    if let Some(created) = summary.created {
        meta.insert("created_unix".into(), Json::from(created));
    }
    if let Some(mode) = summary
        .host_config
        .as_ref()
        .and_then(|h| h.network_mode.as_deref())
        .filter(|s| !s.is_empty())
    {
        meta.insert("network_mode".into(), Json::from(mode));
    }

    let labels: BTreeMap<String, String> = summary
        .labels
        .clone()
        .unwrap_or_default()
        .into_iter()
        .collect();

    let mut relations = Vec::new();

    // uses-image: keyed on the immutable image id when Docker gave one, because
    // the human-readable reference may have been retagged.
    if let Some(image_id) = summary.image_id.as_deref().filter(|s| !s.is_empty()) {
        let img = resource_id(endpoint, NativeKind::Image, image_id);
        relations.push(Relation::new(id.clone(), img, RelationKind::UsesImage));
    }

    // attached-network: sorted for deterministic serialization (CONTRACTS §6).
    if let Some(networks) = summary
        .network_settings
        .as_ref()
        .and_then(|s| s.networks.as_ref())
    {
        let mut names: Vec<&String> = networks.keys().collect();
        names.sort();
        for n in names {
            relations.push(Relation::new(
                id.clone(),
                resource_id(endpoint, NativeKind::Network, n),
                RelationKind::AttachedNetwork,
            ));
        }
    }

    // mounts: only named volumes become `mounts` edges. Bind mounts point at host
    // paths and are host-side workspace concerns (NFR-S06), so they are recorded
    // as metadata rather than as edges to invented volume resources.
    if let Some(mounts) = summary.mounts.as_ref() {
        let mut named: Vec<&str> = mounts
            .iter()
            .filter(|m| {
                m.typ == Some(bollard::models::MountPointTypeEnum::VOLUME)
                    && m.name.as_deref().is_some_and(|n| !n.is_empty())
            })
            .filter_map(|m| m.name.as_deref())
            .collect();
        named.sort_unstable();
        named.dedup();
        for name in named {
            relations.push(Relation::new(
                id.clone(),
                resource_id(endpoint, NativeKind::Volume, name),
                RelationKind::Mounts,
            ));
        }
        let bind_sources: Vec<String> = mounts
            .iter()
            .filter(|m| m.typ == Some(bollard::models::MountPointTypeEnum::BIND))
            .filter_map(|m| m.source.clone())
            .collect();
        if !bind_sources.is_empty() {
            meta.insert("bind_mount_sources".into(), Json::from(bind_sources));
        }
    }

    // member-of-compose.
    if let Some((project, _service)) = compose_attribution(&labels) {
        relations.push(Relation::new(
            id.clone(),
            compose_project_id(endpoint, &project),
            RelationKind::MemberOfCompose,
        ));
        meta.insert(
            "compose_project".into(),
            Json::from(compose_project_id(endpoint, &project).as_str().to_string()),
        );
        meta.insert("compose_project_name".into(), Json::from(project));
    }

    let node = ResourceNode::new(
        id,
        ResourceKind::Container,
        provider.clone(),
        display_name(&summary.names.clone().unwrap_or_default(), native_id),
        state,
        Some(runtime_id.clone()),
        now.to_string(),
    )
    .with_capabilities(container_capabilities(state))
    .with_metadata(Json::Object(meta));

    (node, relations)
}

/// Normalize one image summary.
///
/// Identity prefers the repo digest when Docker reported one, falling back to
/// the image id (DD-PLG §5: "Image → digest/id").
pub fn normalize_image(
    summary: &ImageSummary,
    endpoint: &EndpointId,
    provider: &PluginId,
    runtime_id: &ResourceId,
    now: &str,
) -> (ResourceNode, Vec<Relation>) {
    let digest = summary
        .repo_digests
        .iter()
        .filter(|d| !d.is_empty())
        .min()
        .cloned();
    let native_identity = digest.clone().unwrap_or_else(|| summary.id.clone());
    let id = resource_id(endpoint, NativeKind::Image, &native_identity);

    let mut meta = Map::new();
    meta.insert("endpoint_id".into(), Json::from(endpoint.as_str()));
    meta.insert("native_id".into(), Json::from(summary.id.clone()));
    if let Some(d) = digest {
        meta.insert("repo_digest".into(), Json::from(d));
    }
    if !summary.repo_tags.is_empty() {
        let mut tags = summary.repo_tags.clone();
        tags.sort();
        meta.insert("repo_tags".into(), Json::from(tags));
    }
    meta.insert("created_unix".into(), Json::from(summary.created));
    meta.insert("size_bytes".into(), Json::from(summary.size));

    // An image has no runtime state of its own. Reporting `Unknown` is honest;
    // `Running` would be fabrication (RD §9).
    let node = ResourceNode::new(
        id,
        ResourceKind::Image,
        provider.clone(),
        image_display_name(summary),
        sandtree_model::resource::ResourceState::Unknown,
        Some(runtime_id.clone()),
        now.to_string(),
    )
    .with_capabilities(image_capabilities())
    .with_metadata(Json::Object(meta));

    (node, Vec::new())
}

/// Display name for an image: first repo tag, else a short id.
fn image_display_name(summary: &ImageSummary) -> String {
    summary
        .repo_tags
        .iter()
        .filter(|t| !t.is_empty() && *t != "<none>:<none>")
        .min()
        .cloned()
        .unwrap_or_else(|| summary.id.chars().take(12).collect())
}

/// Capabilities offered for an image (FR-026, FR-061).
pub fn image_capabilities() -> CapabilitySet {
    CapabilitySet::from_iter_caps([
        Capability::global(CapabilityNamespace::Resource, "discover"),
        Capability::global(CapabilityNamespace::Resource, "inspect"),
        Capability::global(CapabilityNamespace::Resource, "destroy"),
    ])
}

/// Normalize one volume.
///
/// Volume identity is `name + endpoint`, because Docker volume names are only
/// unique within an Engine (DD-PLG §5).
pub fn normalize_volume(
    volume: &Volume,
    endpoint: &EndpointId,
    provider: &PluginId,
    runtime_id: &ResourceId,
    now: &str,
) -> (ResourceNode, Vec<Relation>) {
    let id = resource_id(endpoint, NativeKind::Volume, &volume.name);
    let mut meta = Map::new();
    meta.insert("endpoint_id".into(), Json::from(endpoint.as_str()));
    meta.insert("native_id".into(), Json::from(volume.name.clone()));
    if !volume.driver.is_empty() {
        meta.insert("driver".into(), Json::from(volume.driver.clone()));
    }
    if !volume.mountpoint.is_empty() {
        meta.insert("mountpoint".into(), Json::from(volume.mountpoint.clone()));
    }
    // `labels` is an empty map rather than Option in the stub: an empty map means
    // Docker reported no labels, so no metadata key is emitted.
    if !volume.labels.is_empty() {
        let mut m = Map::new();
        for (k, v) in volume.labels.iter() {
            m.insert(k.clone(), Json::from(v.clone()));
        }
        meta.insert("labels".into(), Json::Object(m));
    }

    let node = ResourceNode::new(
        id,
        ResourceKind::Volume,
        provider.clone(),
        volume.name.clone(),
        sandtree_model::resource::ResourceState::Unknown,
        Some(runtime_id.clone()),
        now.to_string(),
    )
    .with_capabilities(volume_capabilities())
    .with_metadata(Json::Object(meta));

    (node, Vec::new())
}

/// Capabilities offered for a volume (FR-061).
pub fn volume_capabilities() -> CapabilitySet {
    CapabilitySet::from_iter_caps([
        Capability::global(CapabilityNamespace::Resource, "discover"),
        Capability::global(CapabilityNamespace::Resource, "inspect"),
        Capability::global(CapabilityNamespace::Resource, "destroy"),
    ])
}

/// Normalize one network.
pub fn normalize_network(
    network: &Network,
    endpoint: &EndpointId,
    provider: &PluginId,
    runtime_id: &ResourceId,
    now: &str,
) -> (ResourceNode, Vec<Relation>) {
    let Some(native_id) = network
        .id
        .as_deref()
        .filter(|s| !s.is_empty())
        .or(network.name.as_deref())
    else {
        return (
            ResourceNode::new(
                ResourceId::derive(&["unidentified-network"]),
                ResourceKind::Network,
                provider.clone(),
                "unknown",
                sandtree_model::resource::ResourceState::Unknown,
                Some(runtime_id.clone()),
                now.to_string(),
            ),
            Vec::new(),
        );
    };

    let id = resource_id(endpoint, NativeKind::Network, native_id);
    let mut meta = Map::new();
    meta.insert("endpoint_id".into(), Json::from(endpoint.as_str()));
    meta.insert("native_id".into(), Json::from(native_id));
    if let Some(driver) = network.driver.as_deref().filter(|d| !d.is_empty()) {
        meta.insert("driver".into(), Json::from(driver));
    }
    if let Some(scope) = network.scope.as_deref().filter(|s| !s.is_empty()) {
        meta.insert("scope".into(), Json::from(scope));
    }

    let node = ResourceNode::new(
        id,
        ResourceKind::Network,
        provider.clone(),
        network
            .name
            .clone()
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| native_id.chars().take(12).collect()),
        sandtree_model::resource::ResourceState::Unknown,
        Some(runtime_id.clone()),
        now.to_string(),
    )
    .with_capabilities(volume_capabilities())
    .with_metadata(Json::Object(meta));

    (node, Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sandtree_model::resource::ResourceState;
    use serde_json::json;
    use std::collections::BTreeSet;

    const NOW: &str = "2026-10-07T00:00:00Z";

    fn ep() -> EndpointId {
        EndpointId::derive(&["npipe:////./pipe/docker_engine"])
    }

    fn plugin() -> PluginId {
        PluginId::derive(&["sandtree.provider.docker"])
    }

    fn runtime() -> ResourceId {
        resource_id(&ep(), NativeKind::Engine, "engine")
    }

    fn container_summary(json: Json) -> ContainerSummary {
        serde_json::from_value(json).expect("fixture must deserialize")
    }

    fn base_container() -> Json {
        serde_json::json!({
            "Id": "9f1c2b3a4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8",
            "Names": ["/web"],
            "Image": "nginx:1.27",
            "ImageID": "sha256:aaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999",
            "Command": "nginx -g daemon off;",
            "Created": 1750000000,
            "State": "running",
            "Status": "Up 3 hours",
            "Labels": {},
            "Ports": [],
            "Mounts": []
        })
    }

    #[test]
    fn container_state_mapping_covers_docker_vocabulary() {
        // RD §9: unknown input must not be invented into a confident state.
        assert_eq!(container_state(Some("created")), ResourceState::Creating);
        assert_eq!(container_state(Some("running")), ResourceState::Running);
        assert_eq!(container_state(Some("paused")), ResourceState::Paused);
        assert_eq!(container_state(Some("exited")), ResourceState::Exited);
        assert_eq!(container_state(Some("dead")), ResourceState::Exited);
        assert_eq!(container_state(Some("removing")), ResourceState::Destroying);
        assert_eq!(
            container_state(Some("weird-new-state")),
            ResourceState::Unknown
        );
        assert_eq!(container_state(None), ResourceState::Unknown);
    }

    #[test]
    fn identity_survives_a_container_rename() {
        // DD-PLG §5: "name 变化不改变 identity".
        let mut before = base_container();
        before["Names"] = json!(["/web"]);
        let mut after = base_container();
        after["Names"] = json!(["/frontend"]);
        let (a, _) = normalize_container(
            &container_summary(before),
            &ep(),
            &plugin(),
            &runtime(),
            NOW,
        );
        let (b, _) =
            normalize_container(&container_summary(after), &ep(), &plugin(), &runtime(), NOW);
        assert_eq!(a.id, b.id);
        assert_eq!(a.name, "web");
        assert_eq!(b.name, "frontend");
    }

    #[test]
    fn same_container_id_on_two_endpoints_stays_distinct() {
        // FR-078 / DD-PLG §5: endpoint is part of identity.
        let summary = container_summary(base_container());
        let other_ep = EndpointId::derive(&["tcp://sandbox.internal:2376"]);
        let (a, _) = normalize_container(&summary, &ep(), &plugin(), &runtime(), NOW);
        let (b, _) = normalize_container(&summary, &other_ep, &plugin(), &runtime(), NOW);
        assert_ne!(a.id, b.id);
        assert_eq!(a.endpoint_id(), Some(ep()));
    }

    #[test]
    fn container_normalization_emits_expected_fields_and_relations() {
        // UT-032: Docker JSON -> ResourceNode with expected fields + relations.
        let mut fixture = base_container();
        fixture["Labels"] =
            json!({ "com.docker.compose.project": "shop", "com.docker.compose.service": "web" });
        fixture["NetworkSettings"] = json!({ "Networks": { "bridge": {}, "shop_default": {} } });
        let (node, rels) = normalize_container(
            &container_summary(fixture),
            &ep(),
            &plugin(),
            &runtime(),
            NOW,
        );

        assert_eq!(node.kind, ResourceKind::Container);
        assert_eq!(node.state, ResourceState::Running);
        assert_eq!(node.parent_id, Some(runtime()));
        assert_eq!(node.provider_id, plugin());
        assert_eq!(node.last_seen, NOW);

        assert_eq!(node.meta_str("image_ref"), Some("nginx:1.27"));
        assert_eq!(node.meta_str("status_text"), Some("Up 3 hours"));
        assert_eq!(node.meta_str("compose_project_name"), Some("shop"));
        // Round-trip identity is recoverable from metadata (DD-PLG §5).
        assert!(node.meta_str("endpoint_id").is_some());
        assert!(node.meta_str("native_id").unwrap().starts_with("9f1c"));

        let mut kinds: Vec<RelationKind> = rels.iter().map(|r| r.kind).collect();
        kinds.sort();
        // Sorted by the `RelationKind` discriminant order, not alphabetically.
        assert_eq!(
            kinds,
            vec![
                RelationKind::UsesImage,
                RelationKind::AttachedNetwork,
                RelationKind::AttachedNetwork,
                RelationKind::MemberOfCompose
            ]
        );
        // All edges originate at the container.
        assert!(rels.iter().all(|r| r.from == node.id));
    }

    #[test]
    fn named_volume_mounts_become_edges_and_bind_mounts_become_metadata() {
        // UT-034 / FR-041: a container mount becomes a `mounts` relation. Only
        // *named* volumes do, because a named volume is a resource this
        // provider already reports and therefore a target the edge can point
        // at honestly; a bind mount names a host path, which is a workspace
        // concern (NFR-S06) and not a volume resource. Turning a bind mount
        // into an edge would invent a resource the operator never created.
        let mut fixture = base_container();
        fixture["Mounts"] = json!([
            { "Type": "volume", "Name": "pgdata",   "Source": "/var/lib/docker/volumes/pgdata/_data", "Destination": "/var/lib/postgresql/data", "RW": true },
            { "Type": "volume", "Name": "cache",    "Source": "/var/lib/docker/volumes/cache/_data",  "Destination": "/var/cache",               "RW": true },
            { "Type": "bind",   "Name": "",         "Source": "E:/work/src",                          "Destination": "/src",                     "RW": false },
            { "Type": "tmpfs",  "Name": "",         "Source": "",                                    "Destination": "/tmp",                     "RW": false }
        ]);
        let (node, rels) = normalize_container(
            &container_summary(fixture),
            &ep(),
            &plugin(),
            &runtime(),
            NOW,
        );

        let mut mounted: Vec<RelationKind> = rels.iter().map(|r| r.kind).collect();
        mounted.sort();
        mounted.dedup();
        assert_eq!(
            mounted,
            vec![RelationKind::UsesImage, RelationKind::Mounts,],
            "only the named volume produces an extra edge; bind and tmpfs do not \
             (sorted by discriminant, so UsesImage precedes Mounts)"
        );

        let edges: Vec<&Relation> = rels
            .iter()
            .filter(|r| r.kind == RelationKind::Mounts)
            .collect();
        assert_eq!(edges.len(), 2, "one edge per named volume: {edges:?}");
        // Volume identity is name + endpoint (DD-PLG §5), so two containers on
        // two endpoints do not collide on a shared name.
        for edge in &edges {
            assert_eq!(
                edge.from, node.id,
                "every mount edge originates at the container"
            );
        }
        let expected: BTreeSet<ResourceId> = ["pgdata", "cache"]
            .iter()
            .map(|name| resource_id(&ep(), NativeKind::Volume, name))
            .collect();
        let actual: BTreeSet<ResourceId> = edges.iter().map(|e| e.to.clone()).collect();
        assert_eq!(
            actual, expected,
            "the edge targets are exactly the two named volumes, derived the \
             same way `normalize_volume` derives them"
        );
        let targets: Vec<ResourceId> = edges.iter().map(|e| e.to.clone()).collect();
        // Order follows the sorted *volume names*, not the sorted resource ids:
        // `pgdata` and `cache` hash to unrelated ids, so "sorted by id" would
        // only be true by accident. Asserting the name order is what actually
        // pins the determinism guarantee (CONTRACTS §6).
        let name_order: Vec<ResourceId> = ["cache", "pgdata"]
            .iter()
            .map(|name| resource_id(&ep(), NativeKind::Volume, name))
            .collect();
        assert_eq!(
            targets, name_order,
            "volume edges are emitted in sorted volume-name order; a reordering \
             here would make the edge list unstable across runs"
        );

        // The bind source is recorded, not modelled as a volume.
        let binds = node
            .metadata
            .get("bind_mount_sources")
            .and_then(|v| v.as_array())
            .expect("bind sources are recorded as metadata");
        assert_eq!(
            binds.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>(),
            vec!["E:/work/src"],
            "exactly the bind mount's source, and nothing invented: {binds:?}"
        );
        assert!(
            rels.iter()
                .all(|r| r.kind != RelationKind::Mounts || !r.to.as_str().contains("E:")),
            "a host path must never become a resource id"
        );
    }

    #[test]
    fn relations_are_deterministically_ordered() {
        // CONTRACTS §6: collection order must be stable for golden tests. The
        // guarantee is that repeated normalization yields the same sequence —
        // edges are sorted by *network name*, so the derived resource ids are
        // stable but are not themselves in ascending order.
        let mut fixture = base_container();
        fixture["NetworkSettings"] = json!({ "Networks": { "zzz": {}, "aaa": {}, "mmm": {} } });
        let summary = container_summary(fixture);
        let (_, first) = normalize_container(&summary, &ep(), &plugin(), &runtime(), NOW);
        let (_, second) = normalize_container(&summary, &ep(), &plugin(), &runtime(), NOW);
        assert_eq!(first, second);

        // The source map's insertion order must not change the result.
        let mut reordered = base_container();
        reordered["NetworkSettings"] = json!({ "Networks": { "mmm": {}, "zzz": {}, "aaa": {} } });
        let (_, other) = normalize_container(
            &container_summary(reordered),
            &ep(),
            &plugin(),
            &runtime(),
            NOW,
        );
        assert_eq!(first, other);

        // Edges follow the sorted network names themselves.
        let attached: Vec<ResourceId> = first
            .iter()
            .filter(|r| r.kind == RelationKind::AttachedNetwork)
            .map(|r| r.to.clone())
            .collect();
        let expected: Vec<ResourceId> = ["aaa", "mmm", "zzz"]
            .iter()
            .map(|n| resource_id(&ep(), NativeKind::Network, n))
            .collect();
        assert_eq!(attached, expected);
    }

    #[test]
    fn absent_fields_produce_no_metadata_key() {
        // RD §9 / AGENTS.md invariant 11: never fabricate.
        let mut fixture = base_container();
        fixture["Status"] = Json::Null;
        fixture["Command"] = Json::Null;
        fixture["NetworkSettings"] = Json::Null;
        let (node, _) = normalize_container(
            &container_summary(fixture),
            &ep(),
            &plugin(),
            &runtime(),
            NOW,
        );
        assert!(node.meta_str("status_text").is_none());
        assert!(node.meta_str("command").is_none());
        assert!(node.meta_str("network_mode").is_none());
        // Required identity fields are still present.
        assert!(node.meta_str("native_id").is_some());
    }

    #[test]
    fn capabilities_track_state_and_never_expose_unavailable_actions() {
        // FR-023 / FR-061: no action may be offered that the state cannot serve.
        let running = container_capabilities(ResourceState::Running);
        assert!(running.allows(&Capability::parse("resource:stop").unwrap()));
        assert!(running.allows(&Capability::parse("resource:pause").unwrap()));
        assert!(running.allows(&Capability::parse("exec:spawn").unwrap()));
        assert!(!running.allows(&Capability::parse("resource:start").unwrap()));

        let exited = container_capabilities(ResourceState::Exited);
        assert!(exited.allows(&Capability::parse("resource:start").unwrap()));
        assert!(exited.allows(&Capability::parse("resource:destroy").unwrap()));
        assert!(!exited.allows(&Capability::parse("resource:pause").unwrap()));

        // Unknown state: inspection only. Guessing `start` here would be
        // speculation about an unobserved state.
        let unknown = container_capabilities(ResourceState::Unknown);
        assert!(unknown.allows(&Capability::parse("resource:inspect").unwrap()));
        assert!(!unknown.allows(&Capability::parse("resource:start").unwrap()));
        assert!(!unknown.allows(&Capability::parse("resource:destroy").unwrap()));
    }

    #[test]
    fn compose_attribution_requires_both_labels() {
        let full: BTreeMap<String, String> = [
            ("com.docker.compose.project".to_string(), "shop".to_string()),
            ("com.docker.compose.service".to_string(), "web".to_string()),
        ]
        .into_iter()
        .collect();
        assert_eq!(
            compose_attribution(&full),
            Some(("shop".to_string(), "web".to_string()))
        );

        let partial: BTreeMap<String, String> =
            [("com.docker.compose.project".to_string(), "shop".to_string())]
                .into_iter()
                .collect();
        assert_eq!(compose_attribution(&partial), None);

        assert_eq!(compose_attribution(&BTreeMap::new()), None);

        // Empty values are not a project name.
        let empty: BTreeMap<String, String> = [
            ("com.docker.compose.project".to_string(), String::new()),
            ("com.docker.compose.service".to_string(), String::new()),
        ]
        .into_iter()
        .collect();
        assert_eq!(compose_attribution(&empty), None);
    }

    #[test]
    fn standalone_container_gets_no_compose_relation() {
        let (node, rels) = normalize_container(
            &container_summary(base_container()),
            &ep(),
            &plugin(),
            &runtime(),
            NOW,
        );
        assert!(!rels.iter().any(|r| r.kind == RelationKind::MemberOfCompose));
        assert!(node.meta_str("compose_project").is_none());
    }

    #[test]
    fn compose_ids_are_stable_and_project_scoped() {
        let a = compose_project_id(&ep(), "shop");
        assert_eq!(a, compose_project_id(&ep(), "shop"));
        assert_ne!(a, compose_project_id(&ep(), "blog"));

        let s1 = compose_service_id(&ep(), "shop", "web");
        assert_eq!(s1, compose_service_id(&ep(), "shop", "web"));
        assert_ne!(s1, compose_service_id(&ep(), "shop", "api"));
        // A service id must not collide with the project id of the same name.
        assert_ne!(s1, compose_project_id(&ep(), "web"));
    }

    #[test]
    fn image_prefers_digest_for_identity() {
        // ImageSummary's non-Option fields are all required by the schema, so a
        // realistic fixture must carry them (`Containers` in particular).
        let with_digest: ImageSummary = serde_json::from_value(serde_json::json!({
            "Id": "sha256:imageid",
            "ParentId": "",
            "RepoTags": ["nginx:latest"],
            "RepoDigests": ["nginx@sha256:1111", "nginx@sha256:0000"],
            "Created": 1750000000,
            "Size": 1234,
            "SharedSize": 0,
            "Containers": 1,
            "Labels": {}
        }))
        .unwrap();
        let (node, _) = normalize_image(&with_digest, &ep(), &plugin(), &runtime(), NOW);
        // The lexicographically smallest digest is chosen, deterministically.
        assert_eq!(node.meta_str("repo_digest"), Some("nginx@sha256:0000"));
        assert_eq!(node.name, "nginx:latest");

        // Retagging must not change identity while the digest holds.
        let mut retagged = with_digest.clone();
        retagged.repo_tags = vec!["nginx:1.27".to_string()];
        let (node2, _) = normalize_image(&retagged, &ep(), &plugin(), &runtime(), NOW);
        assert_eq!(node.id, node2.id);
        assert_eq!(node2.name, "nginx:1.27");
    }

    #[test]
    fn image_without_digest_falls_back_to_id_and_is_not_running() {
        let img: ImageSummary = serde_json::from_value(serde_json::json!({
            "Id": "sha256:onlyid",
            "ParentId": "",
            "RepoTags": ["<none>:<none>"],
            "RepoDigests": [],
            "Created": 1750000000,
            "Size": 10,
            "SharedSize": 0,
            "Containers": -1,
            "Labels": {}
        }))
        .unwrap();
        let (node, _) = normalize_image(&img, &ep(), &plugin(), &runtime(), NOW);
        assert!(node.meta_str("repo_digest").is_none());
        assert_eq!(node.name, "sha256:onlyi");
        // An image is not a running thing; `Running` would be fabrication.
        assert_eq!(node.state, ResourceState::Unknown);
        assert!(node
            .capabilities
            .allows(&Capability::parse("resource:destroy").unwrap()));
    }

    #[test]
    fn volume_identity_is_name_plus_endpoint() {
        let vol: Volume = serde_json::from_value(serde_json::json!({
            "Name": "shop_data",
            "Driver": "local",
            "Mountpoint": "/var/lib/docker/volumes/shop_data/_data",
            "Labels": {"env": "dev"},
            "Options": {},
            "Scope": "local"
        }))
        .unwrap();
        let (node, rels) = normalize_volume(&vol, &ep(), &plugin(), &runtime(), NOW);
        assert_eq!(node.kind, ResourceKind::Volume);
        assert_eq!(node.name, "shop_data");
        assert_eq!(node.meta_str("driver"), Some("local"));
        assert!(rels.is_empty());

        let other = EndpointId::derive(&["https://sandbox.internal:2376"]);
        let (b, _) = normalize_volume(&vol, &other, &plugin(), &runtime(), NOW);
        assert_ne!(a_id(&node), b.id);
    }

    fn a_id(n: &ResourceNode) -> ResourceId {
        n.id.clone()
    }

    #[test]
    fn network_falls_back_to_name_when_id_is_absent() {
        let net: Network = serde_json::from_value(serde_json::json!({
            "Name": "bridge",
            "Driver": "bridge",
            "Scope": "local",
            "Id": null
        }))
        .unwrap();
        let (node, _) = normalize_network(&net, &ep(), &plugin(), &runtime(), NOW);
        assert_eq!(node.name, "bridge");
        assert_eq!(node.meta_str("native_id"), Some("bridge"));
        assert_eq!(node.meta_str("driver"), Some("bridge"));
        assert_eq!(node.kind, ResourceKind::Network);
    }

    #[test]
    fn network_without_id_or_name_is_not_given_a_fabricated_identity() {
        let net: Network =
            serde_json::from_value(serde_json::json!({ "Name": null, "Id": null })).unwrap();
        let (node, rels) = normalize_network(&net, &ep(), &plugin(), &runtime(), NOW);
        assert!(rels.is_empty());
        assert_eq!(node.name, "unknown");
        assert_eq!(node.state, ResourceState::Unknown);
        assert!(node.meta_str("native_id").is_none());
    }
}
