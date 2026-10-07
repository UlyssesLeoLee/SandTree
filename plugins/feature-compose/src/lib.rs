//! Compose Feature plugin (DD-PLG §6; FR-030, FR-031, FR-032).
//!
//! DD-PLG §6 assigns this crate a narrow, specific job:
//!
//! > 应用 discovery 使用 Docker labels `com.docker.compose.*`；
//! > 如 Docker Compose v2 CLI 可用则作为 Feature Plugin 提供 up/down/pull/restart；
//! > capability 声明后可执行。SandTree 不捆绑 Docker Desktop，
//! > Compose binary 是可选依赖并需单独记录 release-license 约束。
//!
//! Three consequences shape the whole crate:
//!
//! 1. **Discovery is not ours.** The Docker provider already groups containers
//!    into projects and services from `com.docker.compose.*` labels
//!    (`plugins/provider-docker/src/normalize.rs`). This crate consumes that
//!    grouping; it does not re-parse labels and it never reads a compose file
//!    (FR-030 explicitly does not require the file).
//! 2. **Lifecycle is optional, and its absence is a first-class state.** When the
//!    Compose v2 CLI is missing, [`ComposeCli::availability`] reports it and the
//!    plugin degrades rather than disappearing: FR-031 is a SHOULD, so discovery
//!    must keep working with no CLI at all.
//! 3. **We do not ship the binary.** Nothing here bundles Docker Desktop or the
//!    Compose binary; [`ComposeCli::availability`] exists precisely so the
//!    licensing of that external binary stays an explicit, recorded dependency
//!    rather than an implicit bundling decision.
//!
//! # Structure
//!
//! | module | role |
//! | --- | --- |
//! | [`cli`] | argv construction + availability probing; the only place that would spawn |
//! | [`project`] | project/service aggregation from an already-discovered graph (FR-032) |
//! | [`provider`] | the feature plugin's capability surface and lifecycle dispatch |
//!
//! # Invariants
//!
//! * **No CLI ≠ no resources.** With the CLI absent, `discover` still returns the
//!   projects and services the Docker provider found. Returning empty would tell
//!   reconcile the compose topology vanished (ADR-OBS-001).
//! * **Lifecycle is capability-gated.** `invoke` refuses anything the plugin did
//!   not declare, before any argv is built (invariant 6, NFR-S02).

#![deny(missing_docs)]

pub mod cli;
pub mod project;
pub mod provider;

pub use cli::{
    availability, ComposeAvailability, ComposeCli, ComposeCommand, ComposeError, DEFAULT_BINARY,
};
pub use project::{
    aggregate_status, project_id, service_id, ProjectStatus, ProjectSummary, ServiceStatus,
};
pub use provider::{ComposeFeature, ComposeFeatureConfig};

/// Reverse-domain plugin id for this feature (DD-PLG §2).
pub const PLUGIN_ID: &str = "sandtree.feature.compose";

/// Version reported through [`sandtree_sdk::ports::ProviderDescriptor`].
pub const PROVIDER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Docker Compose label prefix used for discovery (DD-PLG §6).
pub const COMPOSE_LABEL_PREFIX: &str = "com.docker.compose.";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plugin_id_is_the_reverse_domain_design_specifies() {
        // DD-PLG §2 fixes the id; a change would silently orphan persisted rows.
        assert_eq!(PLUGIN_ID, "sandtree.feature.compose");
    }

    #[test]
    fn the_compose_label_prefix_matches_the_docker_provider() {
        // The Docker provider groups by this prefix in
        // plugins/provider-docker/src/normalize.rs. If either side drifts, compose
        // discovery silently stops matching, so the constant is asserted here.
        assert_eq!(COMPOSE_LABEL_PREFIX, "com.docker.compose.");
    }

    #[test]
    fn provider_version_is_the_crate_version() {
        assert_eq!(PROVIDER_VERSION, env!("CARGO_PKG_VERSION"));
    }
}
