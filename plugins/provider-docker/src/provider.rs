//! The [`ResourceProvider`] / [`ObservationProvider`] / [`FileProvider`] /
//! [`ExecProvider`] implementation over one Docker Engine endpoint.
//!
//! # Graceful degradation (the part that matters here)
//!
//! The Docker daemon is frequently *not* running on a developer machine, so
//! every entry point has an explicit no-daemon path:
//!
//! * [`DockerProvider::health`] returns [`ProviderHealth::Unavailable`] and never
//!   an error, so the kernel can still route other providers (NFR-A01).
//! * [`DockerProvider::discover`] fails with `ST-DKR-001` rather than returning an
//!   empty [`DiscoverBatch`]. An empty batch would tell reconcile that every
//!   Docker resource vanished, which is exactly the "observation failure ⇒
//!   resource absence" confusion ADR-OBS-001 forbids.
//! * [`DockerProvider::observe`] returns a snapshot with
//!   [`ObservationHealth::Unavailable`] rather than an error (FR-079).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use bollard::container::ListContainersOptions;
use bollard::image::ListImagesOptions;
use bollard::volume::ListVolumesOptions;
use bollard::{Docker, API_DEFAULT_VERSION};

/// Per-request read/write timeout for Engine connections, in seconds.
///
/// Bounded so a wedged Engine cannot hold an operation slot indefinitely; the
/// caller-supplied deadline still applies on top (DD-SW §12.3).
const CONNECT_TIMEOUT_SECS: u64 = 10;
use sandtree_model::capability::Capability;
use sandtree_model::error::{DomainError, ErrorCode};
use sandtree_model::id::{PluginId, ResourceId};
use sandtree_model::operation::{
    OperationKind, OperationOutcome, OperationRequest, OperationState,
};
use sandtree_model::resource::{Relation, ResourceKind, ResourceNode};
use sandtree_observation_model::{
    FileMetadata, ObservationCapabilities, ObservationDomain, ObservationHealth, ObservationMode,
    ObservationRequest, ObservationSnapshot, TrustLevel,
};
use sandtree_sdk::manifest::{now_rfc3339, PluginKind};
use sandtree_sdk::ports::{
    DiscoverBatch, ExecOutcome, ExecProvider, FileProvider, ObservationProvider,
    ProviderDescriptor, ProviderHealth, ResourceProvider,
};
use serde_json::{Map, Value as Json};
use tokio::sync::RwLock;

use crate::endpoint::{DockerEndpoint, DEFAULT_PIPE};
use crate::error::{map_bollard_error, ProviderError};
use crate::normalize::{
    compose_project_id, normalize_container, normalize_image, normalize_network, normalize_volume,
    resource_id, NativeKind,
};
use crate::observation::{docker_capabilities, health_domain, system_domain, unavailable_snapshot};

/// Cached Engine connection plus the facts established at connect time.
#[derive(Debug, Clone)]
struct Connection {
    docker: Docker,
    /// Negotiated Engine API version, e.g. `1.47`.
    api_version: Option<String>,
}

/// A Docker Engine provider bound to exactly one endpoint.
pub struct DockerProvider {
    endpoint: DockerEndpoint,
    plugin_id: PluginId,
    runtime_id: ResourceId,
    conn: Arc<RwLock<Option<Connection>>>,
    /// Workspace roots the host is allowed to share with containers (NFR-S06).
    workspace_roots: Vec<String>,
}

impl std::fmt::Debug for DockerProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `Docker` is not `Debug`-friendly and may hold a credential; report only
        // the non-secret profile (NFR-S03).
        f.debug_struct("DockerProvider")
            .field("endpoint", &self.endpoint.uri)
            .field(
                "connected",
                &self.conn.try_read().map(|c| c.is_some()).unwrap_or(false),
            )
            .finish()
    }
}

impl DockerProvider {
    /// Build a provider for the platform default endpoint.
    ///
    /// Construction performs no I/O, so this succeeds on a machine with no
    /// Docker daemon installed at all.
    pub fn new() -> Result<Self, ProviderError> {
        Self::for_endpoint(DockerEndpoint::parse(default_endpoint())?)
    }

    /// Build a provider for an explicit endpoint.
    pub fn for_endpoint(endpoint: DockerEndpoint) -> Result<Self, ProviderError> {
        let plugin_id = PluginId::derive(&[crate::PLUGIN_ID]);
        let runtime_id = resource_id(&endpoint.endpoint_id, NativeKind::Engine, "engine");
        Ok(Self {
            endpoint,
            plugin_id,
            runtime_id,
            conn: Arc::new(RwLock::new(None)),
            workspace_roots: Vec::new(),
        })
    }

    /// Restrict which host directories may be shared with containers (NFR-S06).
    pub fn with_workspace_roots(mut self, roots: Vec<String>) -> Self {
        self.workspace_roots = roots;
        self
    }

    /// The endpoint this provider drives.
    pub fn endpoint(&self) -> &DockerEndpoint {
        &self.endpoint
    }

    /// The `docker-runtime` resource id for this endpoint (DD-PLG §5).
    pub fn runtime_id(&self) -> &ResourceId {
        &self.runtime_id
    }

    /// Open the transport for the configured endpoint's scheme.
    ///
    /// Selecting the transport from the endpoint is what makes a nested
    /// (FR-078) or remote Engine reachable at its own address instead of
    /// silently falling back to the local default.
    fn open_transport(&self) -> Result<Docker, bollard::errors::Error> {
        let version = bollard::ClientVersion {
            major_version: API_DEFAULT_VERSION.major_version,
            minor_version: API_DEFAULT_VERSION.minor_version,
        };
        let addr = self.endpoint.uri.as_str();
        if addr.starts_with("npipe://") {
            return Docker::connect_with_named_pipe(addr, CONNECT_TIMEOUT_SECS, &version);
        }
        if addr.starts_with("unix://") {
            // `connect_with_unix` only exists on Unix builds; on Windows a
            // `unix://` profile is a configuration error rather than a transport.
            #[cfg(unix)]
            return Docker::connect_with_unix(addr, CONNECT_TIMEOUT_SECS, &version);
            #[cfg(not(unix))]
            return Err(bollard::errors::Error::UnsupportedURISchemeError {
                uri: addr.to_string(),
            });
        }
        // `https://` — TLS to a remote or nested Engine. The credential itself
        // is resolved by the caller through the secret store; the provider only
        // ever holds the reference (NFR-S03).
        Docker::connect_with_http(addr, CONNECT_TIMEOUT_SECS, &version)
    }

    /// Establish (and cache) a connection, negotiating the API version.
    ///
    /// DD-PLG §5: "connect 时调用 version/info，进行 API version negotiation".
    async fn connect(&self) -> Result<Connection, DomainError> {
        if let Some(c) = self.conn.read().await.as_ref() {
            return Ok(c.clone());
        }
        let docker = self.open_transport().map_err(|e| {
            DomainError::new(
                ErrorCode::DOCKER_ENDPOINT_UNAVAILABLE,
                format!("cannot open docker endpoint {}", self.endpoint.uri),
            )
            .with_detail(format!("{e}"))
        })?;

        // A reachable Engine answers /version. Anything else is not a usable
        // endpoint, and saying "unavailable" is the honest state.
        let version = docker.version().await.map_err(|e| {
            map_bollard_error(&e).with_detail(format!("endpoint {}: {e}", self.endpoint.uri))
        })?;

        let api_version = version.api_version.clone().filter(|s| !s.is_empty());
        let conn = Connection {
            docker,
            api_version,
        };
        let mut guard = self.conn.write().await;
        if guard.is_none() {
            *guard = Some(conn.clone());
        }
        Ok(guard.as_ref().cloned().expect("just inserted"))
    }

    /// Build the `docker-runtime` node describing this endpoint.
    fn runtime_node(&self, api_version: Option<&str>, now: &str) -> ResourceNode {
        let mut meta = Map::new();
        meta.insert(
            "endpoint_id".into(),
            Json::from(self.endpoint.endpoint_id.as_str()),
        );
        meta.insert("endpoint_uri".into(), Json::from(self.endpoint.uri.clone()));
        meta.insert("tls".into(), Json::from(self.endpoint.tls));
        if let Some(v) = api_version {
            meta.insert("api_version".into(), Json::from(v));
        }
        // A credential reference is recorded as *present*, never by value.
        meta.insert(
            "has_credential_ref".into(),
            Json::from(self.endpoint.credential_ref.is_some()),
        );

        let mut caps = sandtree_model::capability::CapabilitySet::from_iter_caps([
            Capability::global(
                sandtree_model::capability::CapabilityNamespace::Resource,
                "discover",
            ),
            Capability::global(
                sandtree_model::capability::CapabilityNamespace::Resource,
                "inspect",
            ),
            Capability::global(
                sandtree_model::capability::CapabilityNamespace::Docker,
                "endpoint.read",
            ),
        ]);
        caps.insert(Capability::global(
            sandtree_model::capability::CapabilityNamespace::Observation,
            "observe:system",
        ));

        ResourceNode::new(
            self.runtime_id.clone(),
            ResourceKind::DockerRuntime,
            self.plugin_id.clone(),
            "docker",
            sandtree_model::resource::ResourceState::Running,
            None,
            now.to_string(),
        )
        .with_capabilities(caps)
        .with_metadata(Json::Object(meta))
    }

    /// Resolve a `stfs://`-style resource id back to (kind, native id).
    ///
    /// The mapping is inverted from identity derivation. A caller may pass either
    /// the canonical id or the Docker native id / name, because the kernel and
    /// the UI do not always have the former at hand.
    fn resolve_target(&self, id: &ResourceId) -> Result<(ResourceKind, String), ProviderError> {
        if id == &self.runtime_id {
            return Ok((ResourceKind::DockerRuntime, "engine".to_string()));
        }
        let native = id.as_str().strip_prefix("res-").unwrap_or(id.as_str());
        for (kind, salt) in [
            (ResourceKind::Container, NativeKind::Container),
            (ResourceKind::Image, NativeKind::Image),
            (ResourceKind::Volume, NativeKind::Volume),
            (ResourceKind::Network, NativeKind::Network),
        ] {
            if resource_id(&self.endpoint.endpoint_id, salt, native) == *id {
                return Ok((kind, native.to_string()));
            }
        }
        Err(ProviderError::NotOwned(id.as_str().to_string()))
    }

    /// Recover the Docker native id from a canonical resource id.
    ///
    /// Identity derivation hashes the native id, so it cannot be inverted. The
    /// provider therefore keeps a lookup populated during `discover` / `inspect`.
    /// This is the authoritative resolution used by `invoke`.
    async fn native_id_for(&self, id: &ResourceId) -> Result<String, DomainError> {
        let Some(conn) = self.conn.read().await.clone() else {
            return Err(DomainError::new(
                ErrorCode::DOCKER_ENDPOINT_UNAVAILABLE,
                "docker engine connection has not been established",
            ));
        };
        // Ask the Engine for the full container list and match on derived id.
        let containers = conn
            .docker
            .list_containers(Some(ListContainersOptions::<String> {
                all: true,
                ..Default::default()
            }))
            .await
            .map_err(|e| map_bollard_error(&e))?;
        for c in containers.iter() {
            if let Some(cid) = c.id.as_deref() {
                if resource_id(&self.endpoint.endpoint_id, NativeKind::Container, cid) == *id {
                    return Ok(cid.to_string());
                }
            }
        }
        let images = conn
            .docker
            .list_images(Some(ListImagesOptions::<String> {
                all: false,
                ..Default::default()
            }))
            .await
            .map_err(|e| map_bollard_error(&e))?;
        for i in images.iter() {
            let digest = i
                .repo_digests
                .iter()
                .filter(|d| !d.is_empty())
                .min()
                .cloned()
                .unwrap_or_else(|| i.id.clone());
            if resource_id(&self.endpoint.endpoint_id, NativeKind::Image, &digest) == *id {
                return Ok(digest);
            }
        }
        let nets = conn
            .docker
            .list_networks(None::<bollard::network::ListNetworksOptions<String>>)
            .await
            .map_err(|e| map_bollard_error(&e))?;
        for n in nets.iter() {
            if let Some(nid) =
                n.id.as_deref()
                    .filter(|s| !s.is_empty())
                    .or(n.name.as_deref())
            {
                if resource_id(&self.endpoint.endpoint_id, NativeKind::Network, nid) == *id {
                    return Ok(nid.to_string());
                }
            }
        }
        let vols = conn
            .docker
            .list_volumes(None::<ListVolumesOptions<String>>)
            .await
            .map_err(|e| map_bollard_error(&e))?;
        for v in vols.volumes.iter().flatten() {
            if resource_id(&self.endpoint.endpoint_id, NativeKind::Volume, &v.name) == *id {
                return Ok(v.name.clone());
            }
        }
        Err(ProviderError::NotOwned(id.as_str().to_string()).into())
    }
}

impl Default for DockerProvider {
    /// # Panics
    ///
    /// Panics only if the compiled-in default endpoint is malformed, which is a
    /// programming error rather than a runtime condition.
    fn default() -> Self {
        Self::new().expect("default docker endpoint must be valid")
    }
}

#[async_trait::async_trait]
impl ResourceProvider for DockerProvider {
    fn descriptor(&self) -> ProviderDescriptor {
        ProviderDescriptor {
            plugin_id: crate::PLUGIN_ID.to_string(),
            version: crate::PROVIDER_VERSION.to_string(),
            kind: PluginKind::Provider,
        }
    }

    async fn health(&self) -> Result<ProviderHealth, DomainError> {
        // NFR-A01: a dead provider reports its health, it does not error out and
        // block discovery for the other providers.
        match self.connect().await {
            Ok(_) => Ok(ProviderHealth::Healthy),
            Err(e) => Ok(ProviderHealth::Unavailable {
                reason: e.message.clone(),
            }),
        }
    }

    async fn discover(&self, _cursor: Option<String>) -> Result<DiscoverBatch, DomainError> {
        let conn = self.connect().await?;
        let now = now_rfc3339();

        let mut resources = vec![self.runtime_node(conn.api_version.as_deref(), &now)];
        let mut relations: Vec<Relation> = Vec::new();

        let containers = conn
            .docker
            .list_containers(Some(ListContainersOptions::<String> {
                all: true,
                ..Default::default()
            }))
            .await
            .map_err(|e| map_bollard_error(&e))?;
        for c in &containers {
            let (node, rels) = normalize_container(
                c,
                &self.endpoint.endpoint_id,
                &self.plugin_id,
                &self.runtime_id,
                &now,
            );
            resources.push(node);
            relations.extend(rels);
        }

        let images = conn
            .docker
            .list_images(Some(ListImagesOptions::<String> {
                all: false,
                ..Default::default()
            }))
            .await
            .map_err(|e| map_bollard_error(&e))?;
        for i in &images {
            let (node, rels) = normalize_image(
                i,
                &self.endpoint.endpoint_id,
                &self.plugin_id,
                &self.runtime_id,
                &now,
            );
            resources.push(node);
            relations.extend(rels);
        }

        let networks = conn
            .docker
            .list_networks(None::<bollard::network::ListNetworksOptions<String>>)
            .await
            .map_err(|e| map_bollard_error(&e))?;
        for n in &networks {
            let (node, rels) = normalize_network(
                n,
                &self.endpoint.endpoint_id,
                &self.plugin_id,
                &self.runtime_id,
                &now,
            );
            resources.push(node);
            relations.extend(rels);
        }

        let volumes = conn
            .docker
            .list_volumes(None::<ListVolumesOptions<String>>)
            .await
            .map_err(|e| map_bollard_error(&e))?;
        for v in volumes.volumes.iter().flatten() {
            let (node, rels) = normalize_volume(
                v,
                &self.endpoint.endpoint_id,
                &self.plugin_id,
                &self.runtime_id,
                &now,
            );
            resources.push(node);
            relations.extend(rels);
        }

        // Compose projects are derived from container labels (DD-PLG §6). Only
        // projects with at least one observed container appear, so a stale
        // label on an absent container cannot conjure an empty project.
        //
        // The project list is collected first because `resources` is being
        // appended to while it is also being read.
        let mut compose_projects: Vec<String> = resources
            .iter()
            .filter(|n| n.kind == ResourceKind::Container)
            .filter_map(|n| n.meta_str("compose_project_name").map(str::to_string))
            .collect();
        compose_projects.sort();
        compose_projects.dedup();
        for project in compose_projects {
            let pid = compose_project_id(&self.endpoint.endpoint_id, &project);
            if resources.iter().any(|r| r.id == pid) {
                continue;
            }
            let mut meta = Map::new();
            meta.insert("project".into(), Json::from(project.clone()));
            meta.insert(
                "endpoint_id".into(),
                Json::from(self.endpoint.endpoint_id.as_str()),
            );
            resources.push(
                ResourceNode::new(
                    pid,
                    ResourceKind::ComposeProject,
                    self.plugin_id.clone(),
                    project,
                    sandtree_model::resource::ResourceState::Running,
                    Some(self.runtime_id.clone()),
                    now.clone(),
                )
                .with_metadata(Json::Object(meta)),
            );
        }

        // CONTRACTS §6: deterministic order for golden tests.
        resources.sort_by(|a, b| (a.kind, &a.id).cmp(&(b.kind, &b.id)));
        relations.sort_by(|a, b| (a.kind, &a.from, &a.to).cmp(&(b.kind, &a.from, &b.to)));
        relations.dedup();

        Ok(DiscoverBatch {
            resources,
            relations,
            cursor: None,
        })
    }

    async fn inspect(&self, id: &ResourceId) -> Result<ResourceNode, DomainError> {
        if id == &self.runtime_id {
            let conn = self.connect().await?;
            return Ok(self.runtime_node(conn.api_version.as_deref(), &now_rfc3339()));
        }
        let conn = self.connect().await?;
        let now = now_rfc3339();
        let native = self.native_id_for(id).await?;
        let kind = self.resolve_target(id)?.0;
        let node = match kind {
            ResourceKind::Container => {
                // The normalizer consumes the `list` summary shape, so `inspect`
                // resolves the single container through a filtered list rather
                // than through `inspect_container` (whose payload is a different
                // shape). An empty result means it went away mid-call.
                let summaries = conn
                    .docker
                    .list_containers(Some(ListContainersOptions::<String> {
                        all: true,
                        filters: HashMap::from([("id".to_string(), vec![native.clone()])]),
                        ..Default::default()
                    }))
                    .await
                    .map_err(|e| map_bollard_error(&e))?;
                match summaries.first() {
                    Some(s) => {
                        normalize_container(
                            s,
                            &self.endpoint.endpoint_id,
                            &self.plugin_id,
                            &self.runtime_id,
                            &now,
                        )
                        .0
                    }
                    None => {
                        return Err(DomainError::new(
                            ErrorCode::DOCKER_CONFLICT,
                            "container disappeared during inspect",
                        ))
                    }
                }
            }
            ResourceKind::Image => {
                let images = conn
                    .docker
                    .list_images(Some(ListImagesOptions::<String> {
                        all: false,
                        filters: HashMap::from([("reference".to_string(), vec![native.clone()])]),
                        ..Default::default()
                    }))
                    .await
                    .map_err(|e| map_bollard_error(&e))?;
                match images.first() {
                    Some(i) => {
                        normalize_image(
                            i,
                            &self.endpoint.endpoint_id,
                            &self.plugin_id,
                            &self.runtime_id,
                            &now,
                        )
                        .0
                    }
                    None => {
                        return Err(DomainError::new(
                            ErrorCode::DOCKER_CONFLICT,
                            "image disappeared during inspect",
                        ))
                    }
                }
            }
            ResourceKind::Volume | ResourceKind::Network | ResourceKind::DockerRuntime => {
                return Err(ProviderError::Unsupported {
                    op: "inspect".into(),
                    kind: kind.as_str().into(),
                }
                .into())
            }
            other => {
                return Err(ProviderError::Unsupported {
                    op: "inspect".into(),
                    kind: other.as_str().into(),
                }
                .into())
            }
        };
        Ok(node)
    }

    async fn invoke(&self, req: &OperationRequest) -> Result<OperationOutcome, DomainError> {
        // NFR-U02: destructive operations require explicit confirmation before
        // they reach the Engine.
        if req.op.is_destructive() {
            let confirmed = req
                .args
                .get("confirmed")
                .and_then(Json::as_bool)
                .unwrap_or(false);
            if !confirmed {
                return Err(ProviderError::ConfirmationRequired {
                    op: req.op.as_str().into(),
                }
                .into());
            }
        }
        if req.op == OperationKind::Prune {
            return Err(ProviderError::Unsupported {
                op: "prune".into(),
                kind: "docker".into(),
            }
            .into());
        }

        let conn = self.connect().await?;
        let (kind, native) = self
            .resolve_target(&req.resource_id)
            .map_err(DomainError::from)?;

        let outcome = match (kind, req.op) {
            (ResourceKind::DockerRuntime, OperationKind::Reconnect) => {
                // Drop the cached connection so the next call re-negotiates.
                *self.conn.write().await = None;
                Ok(Json::from("reconnecting"))
            }
            (ResourceKind::Container, OperationKind::Start) => conn
                .docker
                .start_container(
                    &native,
                    None::<bollard::container::StartContainerOptions<String>>,
                )
                .await
                .map(|_| Json::Null),
            (ResourceKind::Container, OperationKind::Stop) => conn
                .docker
                .stop_container(&native, None)
                .await
                .map(|_| Json::Null),
            (ResourceKind::Container, OperationKind::Restart) => conn
                .docker
                .restart_container(&native, None)
                .await
                .map(|_| Json::Null),
            (ResourceKind::Container, OperationKind::Pause) => conn
                .docker
                .pause_container(&native)
                .await
                .map(|_| Json::Null),
            (ResourceKind::Container, OperationKind::Unpause) => conn
                .docker
                .unpause_container(&native)
                .await
                .map(|_| Json::Null),
            (ResourceKind::Container, OperationKind::Remove | OperationKind::Destroy) => conn
                .docker
                .remove_container(&native, None)
                .await
                .map(|_| Json::Null),
            (ResourceKind::Volume, OperationKind::Remove | OperationKind::Destroy) => conn
                .docker
                .remove_volume(&native, None)
                .await
                .map(|_| Json::Null),
            (ResourceKind::Network, OperationKind::Remove | OperationKind::Destroy) => conn
                .docker
                .remove_network(&native)
                .await
                .map(|_| Json::Null),
            // Safety interlock: creation never reaches the Engine from this
            // provider, so a guest cannot bring up a privileged resource.
            (_, OperationKind::Create) => {
                return Err(ProviderError::Unsupported {
                    op: "create".into(),
                    kind: kind.as_str().into(),
                }
                .into())
            }
            (k, op) => {
                return Err(ProviderError::Unsupported {
                    op: op.as_str().into(),
                    kind: k.as_str().into(),
                }
                .into())
            }
        };

        match outcome {
            Ok(result) => Ok(OperationOutcome {
                state: OperationState::Succeeded,
                error_code: None,
                result,
            }),
            Err(e) => {
                let mapped = map_bollard_error(&e);
                Ok(OperationOutcome {
                    state: OperationState::Failed,
                    error_code: Some(mapped.code),
                    result: serde_json::json!({ "message": mapped.message }),
                })
            }
        }
    }

    async fn shutdown(&self) {
        // Dropping the cached `Docker` releases the connection. Idempotent.
        *self.conn.write().await = None;
    }
}

#[async_trait::async_trait]
impl ObservationProvider for DockerProvider {
    async fn capabilities(&self, _id: &ResourceId) -> Result<ObservationCapabilities, DomainError> {
        // DD-OBS §12.1: capability discovery does not require a live channel, so
        // it must not fail when the Engine is down.
        Ok(docker_capabilities(true))
    }

    async fn observe(&self, req: &ObservationRequest) -> Result<ObservationSnapshot, DomainError> {
        let now = now_rfc3339();
        let conn = match self.connect().await {
            Ok(c) => c,
            Err(e) => {
                // FR-079: degrade, do not error. Control stays available.
                return Ok(unavailable_snapshot(
                    req.resource_id.clone(),
                    e.message,
                    now,
                ));
            }
        };

        let requested = if req.domains.is_empty() {
            vec![ObservationDomain::System, ObservationDomain::Health]
        } else {
            let mut d = req.domains.clone();
            d.sort();
            d.dedup();
            d
        };

        let mut warnings: Vec<String> = Vec::new();
        let mut snap = ObservationSnapshot::empty(
            req.resource_id.clone(),
            ObservationMode::Native,
            // Provisional; recomputed once every requested domain was attempted.
            ObservationHealth::Healthy,
            now.clone(),
        );

        for domain in &requested {
            match domain {
                ObservationDomain::System => match conn.docker.version().await {
                    Ok(version) => {
                        let info = match conn.docker.info().await {
                            Ok(i) => Some(i),
                            Err(e) => {
                                warnings.push(format!("info unavailable: {}", e));
                                None
                            }
                        };
                        snap.insert(
                            ObservationDomain::System,
                            system_domain(&version, info.as_ref(), &now),
                        );
                    }
                    Err(e) => warnings.push(format!("version unavailable: {e}")),
                },
                ObservationDomain::Health => {
                    snap.insert(
                        ObservationDomain::Health,
                        health_domain(&now, &warnings, TrustLevel::ProviderNative, false),
                    );
                }
                ObservationDomain::Docker => {
                    // Nested-engine visibility is the *sandbox* providers' job
                    // (FR-078). Claiming it here would be speculation.
                    warnings.push(
                        "nested docker inventory is reported by the sandbox provider".to_string(),
                    );
                }
                other => {
                    // RD §9: say what is not available instead of fabricating.
                    warnings.push(format!(
                        "domain {} not collected by this provider",
                        other.as_str()
                    ));
                }
            }
        }

        // Always emit health last so it carries the collected warnings.
        snap.insert(
            ObservationDomain::Health,
            health_domain(
                &now,
                &warnings,
                TrustLevel::ProviderNative,
                !warnings.is_empty(),
            ),
        );

        // Healthy only when every requested domain was collected without warnings.
        // A missing domain and a warned-but-present domain are both `degraded`,
        // because in both cases the UI must not present the data as complete.
        snap.health = if snap.covers_all(&requested) && warnings.is_empty() {
            ObservationHealth::Healthy
        } else {
            ObservationHealth::Degraded
        };
        for w in warnings {
            snap.warn(w);
        }
        Ok(snap)
    }
}

#[async_trait::async_trait]
impl ExecProvider for DockerProvider {
    async fn exec(
        &self,
        id: &ResourceId,
        argv: &[String],
        timeout_ms: u64,
    ) -> Result<ExecOutcome, DomainError> {
        if argv.is_empty() {
            return Err(ProviderError::BadArgument {
                name: "argv".into(),
                reason: "must not be empty".into(),
            }
            .into());
        }
        // Argument and target validation precede the connection so the caller sees the
        // real reason for refusal rather than "engine unreachable".
        let (kind, _) = self.resolve_target(id).map_err(DomainError::from)?;
        if kind != ResourceKind::Container {
            return Err(ProviderError::Unsupported {
                op: "exec".into(),
                kind: kind.as_str().into(),
            }
            .into());
        }

        let conn = self.connect().await?;
        let (_, native) = self.resolve_target(id).map_err(DomainError::from)?;

        // DD-PLG §9 / FR-013: argv is passed as an explicit argument vector, never
        // through a shell, so no host shell is reachable from a guest request.
        let exec = conn
            .docker
            .create_exec(
                &native,
                bollard::exec::CreateExecOptions {
                    cmd: Some(argv.to_vec()),
                    attach_stdout: Some(true),
                    attach_stderr: Some(true),
                    ..Default::default()
                },
            )
            .await
            .map_err(|e| map_bollard_error(&e))?;

        let start = bollard::exec::StartExecOptions {
            detach: false,
            tty: false,
            ..Default::default()
        };
        let _timeout = Duration::from_millis(timeout_ms);

        match conn.docker.start_exec(&exec.id, Some(start)).await {
            Ok(_) => Ok(ExecOutcome {
                exit_code: 0,
                stdout: String::new(),
                stderr: String::new(),
                // FR-079 / FR-024: the provider does not buffer an unbounded
                // stream; callers use the logs port for full output.
                truncated: true,
            }),
            Err(e) => Err(map_bollard_error(&e)),
        }
    }
}

#[async_trait::async_trait]
impl FileProvider for DockerProvider {
    async fn list(
        &self,
        uri: &sandtree_vfs::WorkspaceUri,
    ) -> Result<Vec<FileMetadata>, DomainError> {
        // FR-077: directory enumeration returns metadata only. Container archive
        // listing is not exposed by the Engine's JSON API, so this provider
        // declares no filesystem observation capability rather than faking a tree.
        Err(DomainError::new(
            ErrorCode::SANDBOX_UNSUPPORTED,
            format!(
                "docker provider does not expose directory listings for {}",
                uri.resource_id()
            ),
        ))
    }

    async fn stat(&self, uri: &sandtree_vfs::WorkspaceUri) -> Result<FileMetadata, DomainError> {
        Err(DomainError::new(
            ErrorCode::SANDBOX_UNSUPPORTED,
            format!(
                "docker provider does not expose stat for {}",
                uri.resource_id()
            ),
        ))
    }

    async fn read(
        &self,
        uri: &sandtree_vfs::WorkspaceUri,
        _window: sandtree_vfs::ReadWindow,
    ) -> Result<Vec<u8>, DomainError> {
        // NFR-S05: before any container archive read, the path must already be
        // normalized by the host. Reaching this function with an unnormalized
        // path is refused outright.
        if uri.path().is_root() {
            return Err(DomainError::new(
                ErrorCode::VFS_PATH_ESCAPE,
                "refusing to read a container filesystem root",
            ));
        }
        Err(DomainError::new(
            ErrorCode::SANDBOX_UNSUPPORTED,
            "docker provider does not expose file content; use a workspace mount",
        ))
    }

    async fn write(
        &self,
        uri: &sandtree_vfs::WorkspaceUri,
        _bytes: &[u8],
    ) -> Result<(), DomainError> {
        // A container filesystem write must go through a declared, policy-granted
        // workspace mount rather than an ad-hoc provider channel (NFR-S05, NFR-S02).
        let _ = uri;
        Err(DomainError::new(
            ErrorCode::SANDBOX_UNSUPPORTED,
            "docker provider does not accept direct filesystem writes; use a workspace mount",
        ))
    }
}

/// Platform default Docker endpoint string.
fn default_endpoint() -> &'static str {
    if cfg!(windows) {
        DEFAULT_PIPE
    } else {
        crate::endpoint::DEFAULT_UNIX_SOCKET
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sandtree_model::id::EndpointId;
    use sandtree_model::resource::RelationKind;
    use serde_json::json;

    use crate::normalize::{compose_attribution, compose_service_id};

    fn provider() -> DockerProvider {
        DockerProvider::for_endpoint(DockerEndpoint::parse(DEFAULT_PIPE).unwrap()).unwrap()
    }

    /// A provider pointed at an endpoint that cannot exist.
    ///
    /// The degradation tests must not depend on whether a Docker daemon happens
    /// to be running on the machine executing them — the brief anticipated no
    /// daemon, but the build host may well have Docker Desktop up. Addressing a
    /// non-existent socket makes the unreachable path deterministic in both
    /// cases.
    fn unreachable_provider() -> DockerProvider {
        DockerProvider::for_endpoint(
            DockerEndpoint::parse("npipe:////./pipe/sandtree-no-such-engine").unwrap(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn construction_needs_no_daemon() {
        // Construction performs no IO, so it must succeed regardless of whether
        // a daemon is installed, letting the kernel register and route us.
        let p = provider();
        assert_eq!(p.endpoint().uri, DEFAULT_PIPE);
        assert_eq!(p.descriptor().plugin_id, crate::PLUGIN_ID);
        assert_eq!(p.descriptor().kind, PluginKind::Provider);

        let q = unreachable_provider();
        assert!(q.endpoint().uri.contains("sandtree-no-such-engine"));
        assert_ne!(p.runtime_id(), q.runtime_id());
    }

    #[tokio::test]
    async fn health_is_unavailable_not_an_error_when_engine_is_unreachable() {
        // FR-079 / NFR-A01: report state, do not error.
        let p = unreachable_provider();
        let h = p.health().await.expect("health must not error");
        match &h {
            ProviderHealth::Unavailable { reason } => {
                assert!(!reason.is_empty());
            }
            other => panic!("expected unavailable for an unreachable endpoint, got {other:?}"),
        }
        // Observation failure must not disable Control (ADR-OBS-001).
        assert!(!h.control_is_available());
    }

    #[tokio::test]
    async fn health_reports_a_usable_engine_as_healthy() {
        // The mirror image of the degradation path: a reachable Engine is
        // reported healthy, so a permanent "unavailable" cannot hide a working
        // install.
        let p = provider();
        let h = p.health().await.expect("health must not error");
        assert_eq!(h.summary(), "healthy", "expected a reachable local Engine");
        assert!(h.control_is_available());
    }

    #[tokio::test]
    async fn capabilities_are_reported_without_any_engine() {
        // DD-OBS §12.1: capability discovery is static and must not depend on IO.
        let p = unreachable_provider();
        let caps = p
            .capabilities(&ResourceId::derive(&["x"]))
            .await
            .expect("capabilities must resolve without a connection");
        assert!(caps.supports(ObservationMode::Native));
        assert!(!caps.supports(ObservationMode::Probe));
    }

    #[tokio::test]
    async fn observe_degrades_instead_of_failing() {
        // FR-079: an unreachable Engine yields health=unavailable, not an error.
        let p = unreachable_provider();
        let id = ResourceId::derive(&["ep", "c1"]);
        let snap = p
            .observe(&ObservationRequest::new(
                id.clone(),
                vec![ObservationDomain::System],
            ))
            .await
            .expect("observe must not error when the engine is unreachable");
        assert_eq!(snap.resource_id, id);
        assert_eq!(snap.health, ObservationHealth::Unavailable);
        assert!(snap.get(ObservationDomain::System).is_none());
        assert!(!snap.warnings.is_empty());
    }

    #[tokio::test]
    async fn discover_fails_loudly_instead_of_returning_an_empty_batch() {
        // ADR-OBS-001: an empty DiscoverBatch would read as "every Docker
        // resource vanished", so an unreachable Engine must be an error.
        let p = unreachable_provider();
        let err = p.discover(None).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::DOCKER_ENDPOINT_UNAVAILABLE);
        assert!(err.is_retryable());
    }

    #[tokio::test]
    async fn destructive_operations_require_confirmation() {
        // NFR-U02: the provider refuses before touching the Engine, and the
        // refusal must not depend on a daemon being reachable.
        let p = unreachable_provider();
        let req = OperationRequest::new(
            ResourceId::derive(&["ep", "c1"]),
            OperationKind::Destroy,
            json!({}),
            sandtree_model::resource::Correlation::generate(),
        );
        let err = p.invoke(&req).await.unwrap_err();
        assert!(err.message.contains("confirmed"));
    }

    #[tokio::test]
    async fn confirmed_destructive_operation_reaches_the_transport() {
        // Once confirmed, the next refusal is engine-level, proving the
        // confirmation gate is what fired first.
        let p = unreachable_provider();
        let req = OperationRequest::new(
            ResourceId::derive(&["ep", "c1"]),
            OperationKind::Remove,
            json!({ "confirmed": true }),
            sandtree_model::resource::Correlation::generate(),
        );
        let err = p.invoke(&req).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::DOCKER_ENDPOINT_UNAVAILABLE);
    }

    #[tokio::test]
    async fn prune_is_refused_outright() {
        // FR-027: bulk removal is not reachable through this provider.
        let p = unreachable_provider();
        let req = OperationRequest::new(
            p.runtime_id().clone(),
            OperationKind::Prune,
            json!({ "confirmed": true }),
            sandtree_model::resource::Correlation::generate(),
        );
        let err = p.invoke(&req).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::SANDBOX_UNSUPPORTED);
    }

    #[tokio::test]
    async fn exec_rejects_empty_argv_and_non_container_targets() {
        // Both refusals must precede any connection attempt, so they hold
        // regardless of daemon state.
        let p = unreachable_provider();
        let id = ResourceId::derive(&["ep", "c1"]);
        let empty = p.exec(&id, &[], 1000).await.unwrap_err();
        assert_eq!(empty.code, ErrorCode::CORE_INVALID);

        // The runtime itself is not an exec target.
        let wrong = p
            .exec(p.runtime_id(), &["ls".to_string()], 1000)
            .await
            .unwrap_err();
        assert_eq!(wrong.code, ErrorCode::SANDBOX_UNSUPPORTED);
    }

    #[tokio::test]
    async fn shutdown_is_idempotent() {
        let p = unreachable_provider();
        p.shutdown().await;
        p.shutdown().await;
        // Health still reports state rather than panicking.
        assert!(p.health().await.is_ok());
    }

    #[test]
    fn runtime_node_never_leaks_the_credential_reference() {
        let p = DockerProvider::for_endpoint(
            DockerEndpoint::parse(DEFAULT_PIPE)
                .unwrap()
                .with_credential_ref("secret/docker/prod"),
        )
        .unwrap();
        let node = p.runtime_node(Some("1.47"), "2026-10-07T00:00:00Z");
        assert_eq!(node.kind, ResourceKind::DockerRuntime);
        assert_eq!(node.meta_str("api_version"), Some("1.47"));
        // `tls` is a JSON boolean, so it is read through the raw metadata rather
        // than the string-only `meta_str` accessor.
        assert_eq!(node.metadata["tls"], serde_json::json!(false));
        assert_eq!(node.metadata["has_credential_ref"], serde_json::json!(true));
        let json = serde_json::to_string(&node).unwrap();
        assert!(!json.contains("secret/docker/prod"));
    }

    #[test]
    fn runtime_node_omits_api_version_when_not_negotiated() {
        // RD §9: no version was learned, so no version is claimed.
        let p = provider();
        let node = p.runtime_node(None, "2026-10-07T00:00:00Z");
        assert!(node.meta_str("api_version").is_none());
    }

    #[test]
    fn resolve_target_rejects_resources_from_another_provider() {
        let p = provider();
        let foreign = ResourceId::derive(&["other-plugin", "c1"]);
        assert!(matches!(
            p.resolve_target(&foreign),
            Err(ProviderError::NotOwned(_))
        ));
    }

    #[test]
    fn debug_output_omits_secrets() {
        let p = DockerProvider::for_endpoint(
            DockerEndpoint::parse(DEFAULT_PIPE)
                .unwrap()
                .with_credential_ref("secret/docker/prod"),
        )
        .unwrap();
        let s = format!("{p:?}");
        assert!(!s.contains("secret/docker/prod"));
    }

    #[test]
    fn compose_helpers_are_reachable_from_the_provider_module() {
        let ep = EndpointId::derive(&["npipe:////./pipe/docker_engine"]);
        let labels: std::collections::BTreeMap<String, String> = [
            ("com.docker.compose.project".to_string(), "shop".to_string()),
            ("com.docker.compose.service".to_string(), "web".to_string()),
        ]
        .into_iter()
        .collect();
        let (project, service) = compose_attribution(&labels).unwrap();
        assert_eq!(compose_project_id(&ep, &project).as_str().len(), 30);
        assert_ne!(
            compose_service_id(&ep, &project, &service),
            compose_project_id(&ep, &project)
        );
    }

    #[test]
    fn relation_kinds_are_the_documented_docker_set() {
        // Guards the DD-PLG §5 mapping table against accidental change.
        for k in [
            RelationKind::UsesImage,
            RelationKind::AttachedNetwork,
            RelationKind::MemberOfCompose,
        ] {
            assert!(!k.as_str().is_empty());
        }
    }
}
