//! SandTree plugin SDK: manifests, provider ports, WIT message contracts.
//!
//! The public plugin ABI is WASM Component Model + WIT (ADR-002). This crate
//! carries the Rust-side vocabulary: manifest types, the capability-split ports
//! the kernel depends on, and the message shapes used at the component
//! boundary. Rust traits here are **kernel-internal** and are explicitly not a
//! cross-version ABI.

#![deny(missing_docs)]

pub mod manifest;
pub mod ports;
pub mod wit;

pub use manifest::{
    now_rfc3339, AppCluster, AppManifest, PluginKind, PluginManifest, PluginPackage,
    SUPPORTED_SCHEMA_VERSION,
};
pub use ports::{
    DiscoverBatch, ExecOutcome, ExecProvider, FileProvider, ObservationProvider,
    ProviderDescriptor, ProviderHealth, ProviderInstance, ProviderRegistry, ResourceProvider,
};
pub use wit::{
    decode_component_error, parse_package, verify_component_package, WitDescriptor,
    WitDiscoverResult, OBSERVATION_PACKAGE, PROVIDER_PACKAGE, SUPPORTED_WORLD_MAJORS,
};

/// Installed plugin identity as stored in `plugin_instance`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginInstanceId {
    /// Stable instance id (`instance_id` column).
    pub instance_id: String,
    /// Owning plugin id.
    pub plugin_id: String,
    /// Active generation number.
    pub generation: u64,
}
