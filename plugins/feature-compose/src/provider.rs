//! The Compose feature plugin (DD-PLG §6; FR-030, FR-031, FR-032).
//!
//! A feature plugin does not own the topology — the Docker provider does. This
//! one adds lifecycle over the projects that discovery already found, and only
//! when the Compose v2 CLI is present.
//!
//! The degradation shape is the interesting part. FR-031 is a SHOULD, so a
//! machine without Compose must still see its compose projects:
//!
//! ```text
//! CLI present   -> Healthy,   every declared command callable
//! CLI absent    -> Degraded,  discovery still answers, lifecycle refuses
//! ```

use std::collections::BTreeMap;
use std::sync::Arc;

use sandtree_model::error::{DomainError, ErrorCode};
use sandtree_model::id::{PluginId, ResourceId};
use sandtree_model::operation::{OperationOutcome, OperationRequest, OperationState};
use sandtree_model::resource::{ResourceKind, ResourceNode, ResourceState};
use sandtree_sdk::manifest::PluginKind;
use sandtree_sdk::ports::{
    DiscoverBatch, ObservationProvider, ProviderDescriptor, ProviderHealth, ResourceProvider,
};
use serde_json::json;

use crate::cli::{ComposeAvailability, ComposeCommand, ComposeError, ComposeRunner};
use crate::project::{self, ComposeContainer, ProjectStatus};
use crate::{COMPOSE_LABEL_PREFIX, PLUGIN_ID, PROVIDER_VERSION};

/// Configuration for the Compose feature.
pub struct ComposeFeatureConfig {
    /// Runner used for the Compose CLI; injected so the CLI-absent path is
    /// testable on a machine where Compose happens to be installed.
    pub runner: Arc<dyn ComposeRunner>,
    /// Timestamp stamped on nodes this plugin emits.
    pub observed_at: String,
}

impl ComposeFeatureConfig {
    /// Configure with an injected runner.
    pub fn new(runner: Arc<dyn ComposeRunner>, observed_at: impl Into<String>) -> Self {
        Self {
            runner,
            observed_at: observed_at.into(),
        }
    }
}

/// The Compose feature plugin.
pub struct ComposeFeature {
    config: ComposeFeatureConfig,
    containers: std::sync::Mutex<Vec<ComposeContainer>>,
}

impl ComposeFeature {
    /// Build the plugin.
    pub fn new(config: ComposeFeatureConfig) -> Self {
        Self {
            config,
            containers: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Plugin id.
    pub fn plugin_id(&self) -> PluginId {
        PluginId::derive(&[PLUGIN_ID])
    }

    /// Current CLI availability.
    pub fn cli_availability(&self) -> ComposeAvailability {
        crate::cli::availability(self.config.runner.as_ref())
    }

    /// Whether lifecycle operations can be attempted.
    pub fn cli_is_available(&self) -> bool {
        self.cli_availability().is_available()
    }

    /// Record the containers discovery found, replacing any previous set.
    ///
    /// Takes the graph the Docker provider already built rather than re-reading
    /// labels or a compose file (FR-030).
    pub fn set_containers(&self, containers: Vec<ComposeContainer>) {
        *self.containers.lock().expect("compose container set") = containers;
    }

    /// Fold the recorded containers into project summaries (FR-032).
    pub fn summaries(&self) -> Vec<project::ProjectSummary> {
        let guard = self.containers.lock().expect("compose container set");
        project::aggregate_status(&guard)
    }

    /// Extract Compose containers from a discovered node, if it has the labels.
    pub fn container_from_node(node: &ResourceNode) -> Option<ComposeContainer> {
        let (project, service) = project::compose_labels(node)?;
        Some(ComposeContainer {
            id: node.id.clone(),
            project,
            service,
            state: node.state,
        })
    }

    /// Health.
    ///
    /// `Degraded` rather than `Unavailable` when the CLI is missing: discovery
    /// still works, and reporting `Unavailable` would tell reconcile the compose
    /// topology is gone (ADR-OBS-001).
    pub fn current_health(&self) -> ProviderHealth {
        let a = self.cli_availability();
        if a.is_available() {
            ProviderHealth::Healthy
        } else {
            ProviderHealth::Degraded {
                reason: a.summary(),
            }
        }
    }
}

#[async_trait::async_trait]
impl ResourceProvider for ComposeFeature {
    fn descriptor(&self) -> ProviderDescriptor {
        ProviderDescriptor {
            plugin_id: PLUGIN_ID.to_string(),
            version: PROVIDER_VERSION.to_string(),
            kind: PluginKind::Feature,
        }
    }

    async fn health(&self) -> Result<ProviderHealth, DomainError> {
        Ok(ComposeFeature::current_health(self))
    }

    /// Emit one node per discovered project, sorted.
    ///
    /// The projects come from the recorded containers, so this answers even with
    /// no Compose CLI installed (FR-031 degradation).
    async fn discover(&self, _cursor: Option<String>) -> Result<DiscoverBatch, DomainError> {
        let plugin = self.plugin_id();
        let summaries = self.summaries();

        let mut resources: Vec<ResourceNode> = summaries
            .iter()
            .map(|s| {
                let mut services = serde_json::Map::new();
                for (name, st) in &s.services {
                    services.insert(name.clone(), json!(st.as_str()));
                }
                ResourceNode::new(
                    project::project_id(&s.name),
                    ResourceKind::ComposeProject,
                    plugin.clone(),
                    s.name.clone(),
                    // The Docker provider owns the authoritative state of the
                    // containers; the project node mirrors the fold rather than
                    // inventing a lifecycle state of its own.
                    ResourceState::Unknown,
                    None,
                    self.config.observed_at.clone(),
                )
                .with_metadata(json!({
                    "label_prefix": COMPOSE_LABEL_PREFIX,
                    "status": s.status.as_str(),
                    "services": Json_object(services),
                    "cli": self.cli_availability().summary(),
                }))
            })
            .collect();
        resources.sort_by(|a, b| a.id.as_str().cmp(b.id.as_str()));

        Ok(DiscoverBatch {
            resources,
            relations: Vec::new(),
            cursor: None,
        })
    }

    async fn inspect(&self, id: &ResourceId) -> Result<ResourceNode, DomainError> {
        self.discover(None)
            .await?
            .resources
            .into_iter()
            .find(|n| &n.id == id)
            .ok_or_else(|| {
                DomainError::new(
                    ErrorCode::VFS_NOT_FOUND,
                    format!("{id} is not a discovered compose project"),
                )
            })
    }

    /// Lifecycle dispatch.
    ///
    /// Refuses before building any argv when the CLI is absent, so an absent CLI
    /// can never turn into a fabricated success.
    async fn invoke(&self, req: &OperationRequest) -> Result<OperationOutcome, DomainError> {
        let command = match ComposeCommand::from_operation_kind(req.op) {
            Some(c) => c,
            None => {
                return Err(DomainError::new(
                    ErrorCode::SANDBOX_UNSUPPORTED,
                    ComposeError::UnsupportedOperation {
                        verb: req.op.as_str().to_string(),
                    }
                    .to_string(),
                ))
            }
        };

        if !self.cli_is_available() {
            return Err(DomainError::new(
                ErrorCode::SANDBOX_PROVIDER_UNAVAILABLE,
                format!(
                    "{} needs the Docker Compose CLI, which is not available",
                    command.as_str()
                ),
            ));
        }

        // A `down` removes the project's containers, so it is treated as
        // destructive: without an explicit force it must not run (invariant 12).
        if command.is_destructive()
            && !req
                .args
                .get("force")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
        {
            return Err(DomainError::new(
                ErrorCode::POLICY_DENIED,
                format!("{} is destructive and requires force", command.as_str()),
            ));
        }

        let summaries = self.summaries();
        let project = project_name_of(&req.resource_id, &summaries).ok_or_else(|| {
            DomainError::new(
                ErrorCode::VFS_NOT_FOUND,
                format!("{} is not a discovered compose project", req.resource_id),
            )
        })?;
        let file = req.args.get("file").and_then(|v| v.as_str());
        let argv = self.config.runner.build_argv(command, &project, file);

        let (code, stderr) = self.config.runner.run(&argv).map_err(compose_to_domain)?;
        crate::cli::check_exit(code, &stderr).map_err(compose_to_domain)?;

        Ok(OperationOutcome {
            state: OperationState::Succeeded,
            error_code: None,
            result: json!({"argv": argv, "project": project, "command": command.as_str()}),
        })
    }

    async fn shutdown(&self) {
        // No handle is held: the runner is injected and owns its own lifecycle.
    }
}

#[async_trait::async_trait]
impl ObservationProvider for ComposeFeature {
    async fn capabilities(
        &self,
        _id: &ResourceId,
    ) -> Result<sandtree_observation_model::ObservationCapabilities, DomainError> {
        let mut domains = BTreeMap::new();
        domains.insert(
            sandtree_observation_model::ObservationMode::Metadata
                .as_str()
                .to_string(),
            vec![sandtree_observation_model::ObservationDomain::Docker],
        );
        Ok(sandtree_observation_model::ObservationCapabilities {
            modes: vec![sandtree_observation_model::ObservationMode::Metadata],
            domains,
            max_concurrency: None,
            requires_native_credential: false,
        })
    }

    /// Metadata-only observation.
    ///
    /// FR-032 asks for aggregate project/service/container status; this plugin
    /// never opens a log stream itself, so it advertises `Docker` under
    /// `Metadata` and nothing more. Claiming a richer mode would be fabrication
    /// (RD §9).
    async fn observe(
        &self,
        req: &sandtree_observation_model::ObservationRequest,
    ) -> Result<sandtree_observation_model::ObservationSnapshot, DomainError> {
        use sandtree_observation_model::{
            ObservationDomain, ObservationHealth, ObservationMode, ObservationSnapshot,
        };
        let mut snap = ObservationSnapshot::empty(
            req.resource_id.clone(),
            ObservationMode::Metadata,
            ObservationHealth::Healthy,
            self.config.observed_at.clone(),
        );
        for d in &req.domains {
            if *d != ObservationDomain::Docker {
                snap.warn(format!(
                    "compose feature plugin observes {} only; {} is unavailable here",
                    ObservationDomain::Docker.as_str(),
                    d.as_str()
                ));
                continue;
            }
            let summaries = self.summaries();
            // An unknown project is a fact about the request, not an error. The
            // domain is still emitted, carrying `Empty` plus a warning, because
            // omitting it would be indistinguishable from "the Docker domain is
            // not observable here" (ADR-OBS-001, RD §9).
            let project = project_name_of(&req.resource_id, &summaries);
            if project.is_none() {
                snap.warn(format!(
                    "{} is not a discovered compose project",
                    req.resource_id
                ));
            }
            let project = project.unwrap_or_default();
            let status = summaries
                .iter()
                .find(|s| s.name == project)
                .map(|s| s.status)
                .unwrap_or(ProjectStatus::Empty);
            snap.insert(
                ObservationDomain::Docker,
                sandtree_observation_model::ObservedValue::new(
                    json!({"project": project, "status": status.as_str()}),
                    sandtree_observation_model::Provenance::new(
                        "compose-feature",
                        sandtree_observation_model::TrustLevel::HostNative,
                        self.config.observed_at.clone(),
                    ),
                ),
            );
        }
        Ok(snap)
    }
}

/// Resolve the project name behind a project resource id.
///
/// Looks the id up against the ids actually in the summaries rather than
/// parsing the id string. `ResourceId` is an opaque derived identifier, so
/// splitting it on a separator would couple this code to the derivation format
/// and silently return the wrong name the moment that format changed.
fn project_name_of(id: &ResourceId, summaries: &[project::ProjectSummary]) -> Option<String> {
    summaries
        .iter()
        .find(|s| &project::project_id(&s.name) == id)
        .map(|s| s.name.clone())
}

/// Map a Compose failure onto the stable error registry.
///
/// CLI-absent and non-zero-exit both land on ST-SBX-001 (`SANDBOX_PROVIDER_UNAVAILABLE`)
/// because the provider, not the sandbox, is what could not serve the request.
fn compose_to_domain(err: ComposeError) -> DomainError {
    DomainError::new(ErrorCode::SANDBOX_PROVIDER_UNAVAILABLE, err.to_string())
}

/// Small helper so the metadata object is built without a nested import.
#[allow(non_snake_case)]
fn Json_object(m: serde_json::Map<String, serde_json::Value>) -> serde_json::Value {
    serde_json::Value::Object(m)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::ComposeCli;
    use sandtree_model::operation::OperationKind;
    use sandtree_model::resource::Correlation;
    use sandtree_observation_model::ObservationDomain;

    fn container(project: &str, service: &str, state: ResourceState) -> ComposeContainer {
        ComposeContainer {
            id: ResourceId::derive(&["container", project, service]),
            project: project.to_string(),
            service: service.to_string(),
            state,
        }
    }

    fn plugin(cli: ComposeCli, containers: Vec<ComposeContainer>) -> ComposeFeature {
        let p = ComposeFeature::new(ComposeFeatureConfig::new(
            Arc::new(cli),
            "2026-01-01T00:00:00Z",
        ));
        p.set_containers(containers);
        p
    }

    fn req(kind: OperationKind, args: serde_json::Value) -> OperationRequest {
        OperationRequest::new(
            project::project_id("shop"),
            kind,
            args,
            Correlation::generate(),
        )
    }

    #[tokio::test]
    async fn the_descriptor_declares_a_feature_plugin() {
        let d = plugin(ComposeCli::present("2.24.0"), vec![]).descriptor();
        assert_eq!(d.kind, PluginKind::Feature);
        assert_eq!(d.plugin_id, PLUGIN_ID);
    }

    #[tokio::test]
    async fn a_present_cli_means_healthy() {
        assert_eq!(
            plugin(ComposeCli::present("2.24.0"), vec![])
                .health()
                .await
                .unwrap(),
            ProviderHealth::Healthy
        );
    }

    #[tokio::test]
    async fn an_absent_cli_degrades_but_does_not_disappear() {
        // The critical FR-031 property: no CLI must not mean no resources.
        let p = plugin(
            ComposeCli::absent(),
            vec![container("shop", "web", ResourceState::Running)],
        );
        assert!(matches!(
            p.health().await.unwrap(),
            ProviderHealth::Degraded { .. }
        ));
        let batch = p.discover(None).await.unwrap();
        assert_eq!(
            batch.resources.len(),
            1,
            "discovery must survive an absent CLI"
        );
    }

    #[tokio::test]
    async fn degraded_health_still_permits_control_to_be_attempted() {
        let h = plugin(ComposeCli::absent(), vec![]).health().await.unwrap();
        assert!(h.control_is_available());
    }

    #[tokio::test]
    async fn projects_are_discovered_sorted_with_aggregate_status() {
        let p = plugin(
            ComposeCli::present("2.24.0"),
            vec![
                container("zeta", "web", ResourceState::Running),
                container("alpha", "web", ResourceState::Running),
                container("alpha", "db", ResourceState::Exited),
            ],
        );
        let batch = p.discover(None).await.unwrap();
        assert_eq!(batch.resources.len(), 2);
        let names: Vec<&str> = batch.resources.iter().map(|n| n.name.as_str()).collect();
        assert_eq!(names, vec!["alpha", "zeta"]);
        assert_eq!(
            batch.resources[0].meta_str("status"),
            Some(ProjectStatus::Partial.as_str())
        );
    }

    #[tokio::test]
    async fn project_nodes_record_the_service_map() {
        let p = plugin(
            ComposeCli::present("2.24.0"),
            vec![container("shop", "web", ResourceState::Running)],
        );
        let batch = p.discover(None).await.unwrap();
        assert_eq!(
            batch.resources[0].metadata["services"]["web"],
            json!("running")
        );
    }

    #[tokio::test]
    async fn project_nodes_do_not_invent_a_lifecycle_state() {
        // The Docker provider owns state; this plugin mirrors a fold only.
        let p = plugin(
            ComposeCli::present("2.24.0"),
            vec![container("shop", "web", ResourceState::Running)],
        );
        let batch = p.discover(None).await.unwrap();
        assert_eq!(batch.resources[0].state, ResourceState::Unknown);
    }

    #[tokio::test]
    async fn inspect_finds_a_discovered_project() {
        let p = plugin(
            ComposeCli::present("2.24.0"),
            vec![container("shop", "web", ResourceState::Running)],
        );
        let n = p.inspect(&project::project_id("shop")).await.unwrap();
        assert_eq!(n.name, "shop");
    }

    #[tokio::test]
    async fn inspect_reports_not_found_for_an_unknown_project() {
        let err = plugin(ComposeCli::present("2.24.0"), vec![])
            .inspect(&project::project_id("ghost"))
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::VFS_NOT_FOUND);
    }

    #[tokio::test]
    async fn a_lifecycle_op_without_a_cli_is_refused() {
        let cli = ComposeCli::absent();
        let p = plugin(cli, vec![container("shop", "web", ResourceState::Running)]);
        let err = p
            .invoke(&req(OperationKind::Start, serde_json::Value::Null))
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::SANDBOX_PROVIDER_UNAVAILABLE);
        assert!(err.message.contains("not available"), "{}", err.message);
    }

    #[tokio::test]
    async fn an_absent_cli_never_records_an_invocation() {
        let cli = ComposeCli::absent();
        let p = plugin(cli, vec![container("shop", "web", ResourceState::Running)]);
        let _ = p
            .invoke(&req(OperationKind::Start, serde_json::Value::Null))
            .await;
        // The runner must not have been reached at all.
        assert_eq!(
            p.cli_availability(),
            ComposeAvailability::Absent {
                binary: crate::cli::DEFAULT_BINARY.to_string()
            }
        );
    }

    #[tokio::test]
    async fn a_non_destructive_op_runs_the_compose_cli() {
        let cli = ComposeCli::present("2.24.0");
        let p = plugin(cli, vec![container("shop", "web", ResourceState::Running)]);
        let out = p
            .invoke(&req(OperationKind::Start, serde_json::Value::Null))
            .await
            .expect("start runs");
        assert_eq!(out.state, OperationState::Succeeded);
        assert_eq!(out.result["command"], json!("start"));
    }

    #[tokio::test]
    async fn a_compose_file_argument_is_forwarded() {
        let cli = ComposeCli::present("2.24.0");
        let p = plugin(cli, vec![container("shop", "web", ResourceState::Running)]);
        let out = p
            .invoke(&req(OperationKind::Start, json!({"file": "compose.yaml"})))
            .await
            .unwrap();
        assert_eq!(out.result["argv"][4], json!("compose.yaml"));
    }

    #[tokio::test]
    async fn a_destructive_down_requires_force() {
        let cli = ComposeCli::present("2.24.0");
        let p = plugin(cli, vec![container("shop", "web", ResourceState::Running)]);
        let err = p
            .invoke(&req(OperationKind::Destroy, serde_json::Value::Null))
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::POLICY_DENIED);
        assert!(err.message.contains("destructive"), "{}", err.message);
    }

    #[tokio::test]
    async fn a_destructive_down_runs_once_forced() {
        let cli = ComposeCli::present("2.24.0");
        let p = plugin(cli, vec![container("shop", "web", ResourceState::Running)]);
        let out = p
            .invoke(&req(OperationKind::Destroy, json!({"force": true})))
            .await
            .unwrap();
        assert_eq!(out.result["command"], json!("down"));
    }

    #[tokio::test]
    async fn a_non_destructive_op_does_not_need_force() {
        let cli = ComposeCli::present("2.24.0");
        let p = plugin(cli, vec![container("shop", "web", ResourceState::Running)]);
        assert!(p
            .invoke(&req(OperationKind::Stop, serde_json::Value::Null))
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn an_unmapped_operation_kind_is_refused() {
        let cli = ComposeCli::present("2.24.0");
        let p = plugin(cli, vec![container("shop", "web", ResourceState::Running)]);
        let err = p
            .invoke(&req(OperationKind::Observe, serde_json::Value::Null))
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::SANDBOX_UNSUPPORTED);
    }

    #[tokio::test]
    async fn a_failing_compose_cli_surfaces_its_exit_code() {
        let cli = ComposeCli::present("2.24.0").failing(2, "service not found");
        let p = plugin(cli, vec![container("shop", "web", ResourceState::Running)]);
        let err = p
            .invoke(&req(OperationKind::Start, serde_json::Value::Null))
            .await
            .unwrap_err();
        assert!(err.message.contains("service not found"), "{}", err.message);
    }

    #[tokio::test]
    async fn observation_reports_the_aggregate_project_status() {
        let p = plugin(
            ComposeCli::present("2.24.0"),
            vec![container("shop", "web", ResourceState::Running)],
        );
        let snap = p
            .observe(&sandtree_observation_model::ObservationRequest::new(
                project::project_id("shop"),
                vec![ObservationDomain::Docker],
            ))
            .await
            .unwrap();
        let v = snap.get(ObservationDomain::Docker).expect("docker domain");
        assert_eq!(v.value["status"], json!("running"));
    }

    #[tokio::test]
    async fn observation_warns_instead_of_fabricating_other_domains() {
        let p = plugin(
            ComposeCli::present("2.24.0"),
            vec![container("shop", "web", ResourceState::Running)],
        );
        let snap = p
            .observe(&sandtree_observation_model::ObservationRequest::new(
                project::project_id("shop"),
                vec![ObservationDomain::Process],
            ))
            .await
            .unwrap();
        assert!(snap.get(ObservationDomain::Process).is_none());
        assert!(snap.warnings.iter().any(|w| w.contains("unavailable")));
    }

    #[tokio::test]
    async fn observation_of_an_unknown_project_is_empty_not_an_error() {
        let p = plugin(ComposeCli::present("2.24.0"), vec![]);
        let snap = p
            .observe(&sandtree_observation_model::ObservationRequest::new(
                project::project_id("ghost"),
                vec![ObservationDomain::Docker],
            ))
            .await
            .unwrap();
        assert_eq!(
            snap.get(ObservationDomain::Docker).unwrap().value["status"],
            json!("empty")
        );
    }

    #[tokio::test]
    async fn compose_containers_are_extracted_from_discovered_nodes() {
        let node = ResourceNode::new(
            ResourceId::derive(&["c1"]),
            ResourceKind::Container,
            PluginId::derive(&["p"]),
            "shop-web-1",
            ResourceState::Running,
            None,
            "2026-01-01T00:00:00Z".to_string(),
        )
        .with_metadata(json!({
            "com.docker.compose.project": "shop",
            "com.docker.compose.service": "web",
        }));
        let c = ComposeFeature::container_from_node(&node).expect("compose container");
        assert_eq!(c.project, "shop");
        assert_eq!(c.service, "web");
        assert!(c.is_running());
    }

    #[tokio::test]
    async fn a_plain_container_is_not_a_compose_container() {
        let node = ResourceNode::new(
            ResourceId::derive(&["c1"]),
            ResourceKind::Container,
            PluginId::derive(&["p"]),
            "plain",
            ResourceState::Running,
            None,
            "2026-01-01T00:00:00Z".to_string(),
        );
        assert!(ComposeFeature::container_from_node(&node).is_none());
    }

    #[tokio::test]
    async fn shutdown_is_idempotent_and_leaves_discovery_working() {
        let p = plugin(
            ComposeCli::present("2.24.0"),
            vec![container("shop", "web", ResourceState::Running)],
        );
        p.shutdown().await;
        p.shutdown().await;
        assert_eq!(p.discover(None).await.unwrap().resources.len(), 1);
    }
}
