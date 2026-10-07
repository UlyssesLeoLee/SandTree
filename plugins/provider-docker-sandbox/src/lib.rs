//! Docker Sandbox provider (DD-PLG §8, §12.2; FR-011, FR-013, FR-070, FR-079).
//!
//! DD-PLG §8 is unusually explicit about what this crate is allowed to be:
//!
//! > 实现只有适配器契约，真正的实现/宿主 SDK 不放在 Core；
//! > 主机 API 不可用时只降级 CLI；CLI 不可用时，provider 内部 fixture regression test；
//! > provider 版本通过 capability discovery 上报。
//!
//! That yields a three-tier degradation ladder, and the order matters:
//!
//! ```text
//! tier 1  Docker "sandboxes" experimental API   -> native, best data
//! tier 2  Docker CLI                            -> degraded, metadata only
//! tier 3  embedded fixture                      -> still discoverable, test-only
//! ```
//!
//! # Structure
//!
//! | module | role |
//! | --- | --- |
//! | [`tier`] | the degradation ladder and its probe order |
//! | [`fixture`] | embedded fixture world + the CLI-absence regression path |
//! | [`observation`] | Mode A snapshot assembly and trust |
//! | [`provider`] | SDK port implementations and health |
//!
//! # The invariants this crate exists to protect
//!
//! * **Absent product ≠ absent resources.** With no API and no CLI the provider
//!   still serves [`provider::DockerSandboxProvider::discover`] from its embedded
//!   fixture, because returning an empty [`sandtree_sdk::ports::DiscoverBatch`]
//!   would tell reconcile that every sandbox vanished (ADR-OBS-001).
//! * **Trust never rises.** Everything reaching this provider came out of a
//!   sandbox: `FilesRead` / `Exec` are guest-probe data and are capped at
//!   [`sandtree_observation_model::TrustLevel::GuestProbe`] no matter how the
//!   envelope verified (ADR-OBS-003).
//! * **Version is reported, not guessed.** [`provider::DockerSandboxProvider::descriptor`]
//!   carries the provider version, and [`observation`] surfaces the *detected API*
//!   version separately so an unsupported API is visible as `unavailable`
//!   metadata rather than silently producing empty snapshots (RD §9).

#![deny(missing_docs)]

pub mod fixture;
pub mod observation;
pub mod provider;
pub mod tier;

pub use observation::{sandbox_capabilities, snapshot_from_values, unavailable_snapshot};
pub use provider::{DockerSandboxConfig, DockerSandboxProvider};
pub use tier::{is_supported_version, ApiSupport, ProbeOutcome, SandboxTier};

/// Reverse-domain plugin id for this provider (DD-PLG §2).
pub const PLUGIN_ID: &str = "sandtree.provider.docker-sandbox";

/// Version reported through [`sandtree_sdk::ports::ProviderDescriptor`].
pub const PROVIDER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Provenance source for data read through the experimental API.
pub const SOURCE_SANDBOXES_API: &str = "docker-sandboxes-api";

/// Provenance source for data read through the Docker CLI.
pub const SOURCE_DOCKER_CLI: &str = "docker-cli";

/// Provenance source for the embedded fixture world.
///
/// A fixture is *not* evidence about a real runtime, so callers must be able to
/// tell it apart. The constant exists so that check is a string comparison
/// rather than an inference from the absence of data.
pub const SOURCE_FIXTURE: &str = "docker-sandbox-fixture";

/// Docker Compose / Docker Sandboxes API versions this provider understands.
///
/// DD-PLG §8 requires the version to be surfaced through capability discovery
/// rather than assumed; an API outside this list degrades to the next tier.
pub const SUPPORTED_API_VERSIONS: &[&str] = &["0.1", "0.2"];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plugin_id_is_the_reverse_domain_design_specifies() {
        // DD-PLG §2 fixes the id; changing it silently breaks persisted
        // plugin_package rows, so it is asserted rather than documented.
        assert_eq!(PLUGIN_ID, "sandtree.provider.docker-sandbox");
    }

    #[test]
    fn fixture_provenance_is_distinguishable_from_real_provenance() {
        // A caller must be able to reject fixture-derived data without having to
        // infer it from missing fields.
        assert_ne!(SOURCE_FIXTURE, SOURCE_SANDBOXES_API);
        assert_ne!(SOURCE_FIXTURE, SOURCE_DOCKER_CLI);
    }

    #[test]
    fn supported_api_versions_are_sorted_and_unique() {
        // Deterministic ordering is a repo-wide rule and this list drives
        // capability discovery output.
        let mut sorted: Vec<&str> = SUPPORTED_API_VERSIONS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), SUPPORTED_API_VERSIONS.len());
        assert_eq!(sorted, SUPPORTED_API_VERSIONS.to_vec());
    }

    #[test]
    fn provider_version_is_the_crate_version() {
        assert_eq!(PROVIDER_VERSION, env!("CARGO_PKG_VERSION"));
    }
}
