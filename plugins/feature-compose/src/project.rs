//! Project and service aggregation (DD-PLG §6, FR-030, FR-032).
//!
//! FR-030 requires discovery through Docker labels and metadata, explicitly
//! *without* reading a compose file. FR-032 requires project/service/container
//! aggregate status without converting service containers into new resources.
//!
//! So this module does one thing: fold the already-discovered containers of a
//! project into a summary. It never reads YAML, never shells out, and never
//! invents a container.
//!
//! # Aggregate status rule
//!
//! A project's status is the **worst** of its services, with the one exception
//! that "no services" is [`ProjectStatus::Empty`] rather than
//! [`ProjectStatus::Stopped`] — a project that was never started is a different
//! fact from one that was stopped.

use std::collections::BTreeMap;

use sandtree_model::id::ResourceId;
use sandtree_model::resource::{ResourceNode, ResourceState};

/// Status of a single service, folded from its containers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ServiceStatus {
    /// No containers reported for this service.
    Empty,
    /// Every container is running.
    Running,
    /// At least one container is running and at least one is not.
    Partial,
    /// Containers exist but none is running.
    Stopped,
}

impl ServiceStatus {
    /// Wire name for the inspector.
    pub fn as_str(self) -> &'static str {
        match self {
            ServiceStatus::Empty => "empty",
            ServiceStatus::Running => "running",
            ServiceStatus::Partial => "partial",
            ServiceStatus::Stopped => "stopped",
        }
    }
}

/// Status of a whole project, folded from its services.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProjectStatus {
    /// The project has no services at all.
    Empty,
    /// Every service is running.
    Running,
    /// A mix of running and not-running.
    Partial,
    /// Services exist but none is running.
    Stopped,
}

impl ProjectStatus {
    /// Wire name for the inspector.
    pub fn as_str(self) -> &'static str {
        match self {
            ProjectStatus::Empty => "empty",
            ProjectStatus::Running => "running",
            ProjectStatus::Partial => "partial",
            ProjectStatus::Stopped => "stopped",
        }
    }

    /// Fold a set of service statuses.
    ///
    /// Empty in, `Empty` out; otherwise `Partial` whenever the members disagree,
    /// and only a unanimous `Stopped` is reported as `Stopped`.
    ///
    /// Counting only the running members would be wrong: a project whose only
    /// service is half-up is *partial*, not stopped, and collapsing the two would
    /// tell an operator to start a project that is already partly running.
    pub fn fold(statuses: &[ServiceStatus]) -> Self {
        if statuses.is_empty() {
            return ProjectStatus::Empty;
        }
        // A single mixed service makes the whole project mixed, whether or not
        // other services are up.
        if statuses.contains(&ServiceStatus::Partial) {
            return ProjectStatus::Partial;
        }
        let running = statuses
            .iter()
            .filter(|s| **s == ServiceStatus::Running)
            .count();
        if running == statuses.len() {
            return ProjectStatus::Running;
        }
        if running == 0 {
            // Nothing is running and nothing is mixed: genuinely stopped.
            return ProjectStatus::Stopped;
        }
        ProjectStatus::Partial
    }
}

/// One container as this module needs it: the two label values plus its state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComposeContainer {
    /// Resource id, carried through to the summary.
    pub id: ResourceId,
    /// `com.docker.compose.project`.
    pub project: String,
    /// `com.docker.compose.service`.
    pub service: String,
    /// Lifecycle state.
    pub state: ResourceState,
}

impl ComposeContainer {
    /// Whether this container's state counts as running.
    ///
    /// `Running` and `Creating` both mean "up or becoming up"; `Paused` and
    /// `Exited` do not.
    pub fn is_running(&self) -> bool {
        matches!(self.state, ResourceState::Running | ResourceState::Creating)
    }
}

/// Aggregated view of one Compose project.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectSummary {
    /// Project name.
    pub name: String,
    /// Folded project status.
    pub status: ProjectStatus,
    /// Per-service status, sorted by service name.
    pub services: BTreeMap<String, ServiceStatus>,
    /// Container ids per service, sorted.
    pub containers: BTreeMap<String, Vec<ResourceId>>,
}

/// Stable resource id for a Compose project.
pub fn project_id(project: &str) -> ResourceId {
    ResourceId::derive(&["compose", "project", project])
}

/// Stable resource id for a service inside a project.
pub fn service_id(project: &str, service: &str) -> ResourceId {
    ResourceId::derive(&["compose", "project", project, "service", service])
}

/// Fold containers into one summary per project.
///
/// Deterministic: projects and services come out in sorted order because
/// `BTreeMap` and the returned vectors are both sorted by name.
pub fn aggregate_status(containers: &[ComposeContainer]) -> Vec<ProjectSummary> {
    let mut by_project: BTreeMap<String, Vec<&ComposeContainer>> = BTreeMap::new();
    for c in containers {
        by_project.entry(c.project.clone()).or_default().push(c);
    }

    by_project
        .into_iter()
        .map(|(name, group)| {
            let mut per_service: BTreeMap<String, ServiceStatus> = BTreeMap::new();
            let mut containers: BTreeMap<String, Vec<ResourceId>> = BTreeMap::new();

            for c in group {
                let running = c.is_running();
                let entry = per_service
                    .entry(c.service.clone())
                    .or_insert(ServiceStatus::Empty);
                *entry = match (*entry, running) {
                    // Nothing seen yet in this service.
                    (ServiceStatus::Empty, false) => ServiceStatus::Stopped,
                    (ServiceStatus::Empty, true) => ServiceStatus::Running,
                    // Already saw a stopped replica, now a running one: mixed.
                    (ServiceStatus::Stopped, true) => ServiceStatus::Partial,
                    (ServiceStatus::Stopped, false) => ServiceStatus::Stopped,
                    (ServiceStatus::Running, true) => ServiceStatus::Running,
                    (ServiceStatus::Running, false) => ServiceStatus::Partial,
                    // Once mixed, mixed is absorbing.
                    (ServiceStatus::Partial, _) => ServiceStatus::Partial,
                };
                containers
                    .entry(c.service.clone())
                    .or_default()
                    .push(c.id.clone());
            }

            for ids in containers.values_mut() {
                ids.sort_by(|a, b| a.as_str().cmp(b.as_str()));
            }

            let statuses: Vec<ServiceStatus> = per_service.values().copied().collect();
            ProjectSummary {
                status: ProjectStatus::fold(&statuses),
                name,
                services: per_service,
                containers,
            }
        })
        .collect()
}

/// Whether a discovered [`ResourceNode`] carries Compose labels.
///
/// This is the FR-030 entry point: it answers "is this node part of a compose
/// project?" purely from labels, with no compose file involved.
pub fn compose_labels(node: &ResourceNode) -> Option<(String, String)> {
    let get = |k: &str| {
        node.metadata
            .get(k)
            .and_then(|v| v.as_str())
            .map(str::to_string)
    };
    let project = get("com.docker.compose.project")?;
    let service = get("com.docker.compose.service")?;
    if project.is_empty() || service.is_empty() {
        return None;
    }
    Some((project, service))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(project: &str, service: &str, state: ResourceState) -> ComposeContainer {
        ComposeContainer {
            id: ResourceId::derive(&["container", project, service]),
            project: project.to_string(),
            service: service.to_string(),
            state,
        }
    }

    #[test]
    fn an_empty_input_aggregates_to_nothing() {
        assert!(aggregate_status(&[]).is_empty());
    }

    #[test]
    fn a_single_running_container_makes_the_project_running() {
        let s = aggregate_status(&[c("shop", "web", ResourceState::Running)]);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].status, ProjectStatus::Running);
        assert_eq!(s[0].services["web"], ServiceStatus::Running);
    }

    #[test]
    fn a_mixed_project_is_partial() {
        let s = aggregate_status(&[
            c("shop", "web", ResourceState::Running),
            c("shop", "db", ResourceState::Exited),
        ]);
        assert_eq!(s[0].status, ProjectStatus::Partial);
        assert_eq!(s[0].services["web"], ServiceStatus::Running);
        assert_eq!(s[0].services["db"], ServiceStatus::Stopped);
    }

    #[test]
    fn a_fully_stopped_project_is_stopped_not_empty() {
        let s = aggregate_status(&[c("shop", "web", ResourceState::Exited)]);
        assert_eq!(s[0].status, ProjectStatus::Stopped);
    }

    #[test]
    fn an_empty_service_list_folds_to_empty() {
        // "never started" and "stopped" are different facts.
        assert_eq!(ProjectStatus::fold(&[]), ProjectStatus::Empty);
        assert_ne!(ProjectStatus::Empty, ProjectStatus::Stopped);
    }

    #[test]
    fn creating_counts_as_running() {
        assert!(c("shop", "web", ResourceState::Creating).is_running());
    }

    #[test]
    fn paused_and_exited_do_not_count_as_running() {
        assert!(!c("shop", "web", ResourceState::Paused).is_running());
        assert!(!c("shop", "web", ResourceState::Exited).is_running());
        assert!(!c("shop", "web", ResourceState::Stopped).is_running());
        assert!(!c("shop", "web", ResourceState::Unknown).is_running());
    }

    #[test]
    fn replicas_of_one_service_fold_to_running() {
        let s = aggregate_status(&[
            c("shop", "web", ResourceState::Running),
            c("shop", "web", ResourceState::Running),
        ]);
        assert_eq!(s[0].services["web"], ServiceStatus::Running);
        assert_eq!(s[0].containers["web"].len(), 2);
    }

    #[test]
    fn a_service_with_one_running_and_one_stopped_replica_is_partial() {
        let s = aggregate_status(&[
            c("shop", "web", ResourceState::Running),
            c("shop", "web", ResourceState::Exited),
        ]);
        assert_eq!(s[0].services["web"], ServiceStatus::Partial);
        assert_eq!(s[0].status, ProjectStatus::Partial);
    }

    #[test]
    fn projects_come_back_in_sorted_order() {
        let s = aggregate_status(&[
            c("zeta", "web", ResourceState::Running),
            c("alpha", "web", ResourceState::Running),
            c("mid", "web", ResourceState::Running),
        ]);
        let names: Vec<&str> = s.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["alpha", "mid", "zeta"]);
    }

    #[test]
    fn services_come_back_in_sorted_order() {
        let s = aggregate_status(&[
            c("shop", "web", ResourceState::Running),
            c("shop", "api", ResourceState::Running),
            c("shop", "db", ResourceState::Running),
        ]);
        let names: Vec<&str> = s[0].services.keys().map(String::as_str).collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted);
    }

    #[test]
    fn container_ids_within_a_service_are_sorted() {
        let mut a = c("shop", "web", ResourceState::Running);
        let mut b = c("shop", "web", ResourceState::Running);
        a.id = ResourceId::derive(&["zzz"]);
        b.id = ResourceId::derive(&["aaa"]);
        let s = aggregate_status(&[a, b]);
        let ids: Vec<&str> = s[0].containers["web"].iter().map(|i| i.as_str()).collect();
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        assert_eq!(ids, sorted);
    }

    #[test]
    fn aggregation_is_deterministic_across_input_orderings() {
        let a = vec![
            c("shop", "web", ResourceState::Running),
            c("shop", "db", ResourceState::Exited),
        ];
        let mut b = a.clone();
        b.reverse();
        assert_eq!(aggregate_status(&a), aggregate_status(&b));
    }

    #[test]
    fn ids_are_stable_and_distinct() {
        assert_eq!(project_id("shop"), project_id("shop"));
        assert_ne!(project_id("shop"), project_id("other"));
        assert_ne!(service_id("shop", "web"), service_id("shop", "db"));
        assert_ne!(project_id("shop"), service_id("shop", "shop"));
    }

    #[test]
    fn compose_labels_are_read_from_metadata_alone() {
        // FR-030: discovery is label/metadata driven, no compose file.
        let mut node = ResourceNode::new(
            ResourceId::derive(&["c1"]),
            sandtree_model::resource::ResourceKind::Container,
            sandtree_model::id::PluginId::derive(&["p"]),
            "shop-web-1",
            ResourceState::Running,
            None,
            "2026-01-01T00:00:00Z".to_string(),
        )
        .with_metadata(serde_json::json!({
            "com.docker.compose.project": "shop",
            "com.docker.compose.service": "web",
        }));
        assert_eq!(
            compose_labels(&node),
            Some(("shop".to_string(), "web".to_string()))
        );

        // An empty label value is not a usable grouping key.
        node = node.with_metadata(serde_json::json!({
            "com.docker.compose.project": "",
            "com.docker.compose.service": "web",
        }));
        assert_eq!(compose_labels(&node), None);
    }

    #[test]
    fn a_node_without_compose_labels_is_not_compose() {
        let node = ResourceNode::new(
            ResourceId::derive(&["c1"]),
            sandtree_model::resource::ResourceKind::Container,
            sandtree_model::id::PluginId::derive(&["p"]),
            "plain",
            ResourceState::Running,
            None,
            "2026-01-01T00:00:00Z".to_string(),
        );
        assert_eq!(compose_labels(&node), None);
    }

    #[test]
    fn a_project_label_without_a_service_label_is_rejected() {
        // Half a grouping key would create a phantom service.
        let node = ResourceNode::new(
            ResourceId::derive(&["c1"]),
            sandtree_model::resource::ResourceKind::Container,
            sandtree_model::id::PluginId::derive(&["p"]),
            "shop-web-1",
            ResourceState::Running,
            None,
            "2026-01-01T00:00:00Z".to_string(),
        )
        .with_metadata(serde_json::json!({"com.docker.compose.project": "shop"}));
        assert_eq!(compose_labels(&node), None);
    }

    #[test]
    fn a_project_whose_only_service_is_partial_is_partial_not_stopped() {
        // Counting only running members would report this as Stopped and invite
        // an operator to "start" a project that is already half up.
        assert_eq!(
            ProjectStatus::fold(&[ServiceStatus::Partial]),
            ProjectStatus::Partial
        );
    }

    #[test]
    fn a_unanimously_stopped_project_is_stopped() {
        assert_eq!(
            ProjectStatus::fold(&[ServiceStatus::Stopped, ServiceStatus::Stopped]),
            ProjectStatus::Stopped
        );
    }

    #[test]
    fn a_unanimously_running_project_is_running() {
        assert_eq!(
            ProjectStatus::fold(&[ServiceStatus::Running, ServiceStatus::Running]),
            ProjectStatus::Running
        );
    }

    #[test]
    fn status_wire_names_are_distinct() {
        let names = [
            ProjectStatus::Empty.as_str(),
            ProjectStatus::Running.as_str(),
            ProjectStatus::Partial.as_str(),
            ProjectStatus::Stopped.as_str(),
        ];
        let mut sorted: Vec<&str> = names.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), 4);
    }
}
