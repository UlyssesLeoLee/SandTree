//! Multipass provider (DD-PLG §9, §12.3; FR-011, FR-013, FR-070, FR-079).
//!
//! There is no Multipass client crate, so this provider drives the `multipass`
//! CLI through `std::process::Command`. That is a deliberate consequence of
//! DD-PLG §9 ("multipass list/info --format json discovery"), not a shortcut:
//! CLI output is parsed **here**, inside the plugin, and only domain DTOs cross
//! the boundary (NFR-O02).
//!
//! # Structure
//!
//! | module | role |
//! | --- | --- |
//! | [`cli`] | argv construction and process execution — the only place that spawns |
//! | [`parse`] | pure `multipass` JSON / collector-output → DTO normalization |
//! | [`observation`] | Mode B Exec snapshot assembly and trust |
//! | [`provider`] | the SDK port implementations and health |
//!
//! # The two invariants this crate exists to protect
//!
//! * **Absent product ≠ absent resources.** When `multipass` is not installed,
//!   [`ProviderHealth::Unavailable`] is returned and `discover` fails with
//!   `ST-SBX-001`. It never returns an empty [`DiscoverBatch`], because that
//!   would tell reconcile that every instance vanished (ADR-OBS-001).
//! * **Trust never rises.** Everything observed through `multipass exec` is
//!   [`TrustLevel::RemoteExec`] at best. A verified payload does not promote it
//!   (ADR-OBS-003).

#![deny(missing_docs)]

pub mod cli;
pub mod observation;
pub mod parse;
pub mod provider;

pub use cli::{CliRunner, MultipassCli, MultipassError, DEFAULT_BINARY, EXEC_TIMEOUT_MS};
pub use observation::{multipass_capabilities, system_domain_from_collector, unavailable_snapshot};
pub use parse::{
    instance_id, multipass_state, normalize_instance, CollectorDomain, CollectorReport,
};
pub use provider::MultipassProvider;

/// Reverse-domain plugin id for this provider (DD-PLG §2).
pub const PLUGIN_ID: &str = "sandtree.provider.multipass";

/// Version reported through [`sandtree_sdk::ports::ProviderDescriptor`].
pub const PROVIDER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Provenance source for data read through `multipass exec`.
pub const SOURCE_MULTIPASS_EXEC: &str = "multipass-exec";
