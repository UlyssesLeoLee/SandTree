//! Docker Engine provider (DD-PLG §5, §12.2; FR-020..FR-027, FR-070, FR-077, FR-078).
//!
//! Implements the four SDK ports over a Bollard connection to one Docker Engine
//! endpoint:
//!
//! | port | source | trust |
//! | --- | --- | --- |
//! | [`ResourceProvider`] | Engine `/containers`, `/images`, `/volumes`, `/networks` | — |
//! | [`ObservationProvider`] | Engine `/version`, `/info`, `/stats`, `/top` | `provider_native` |
//! | [`FileProvider`] | container archive endpoints | — |
//! | [`ExecProvider`] | container exec endpoints | — |
//!
//! # Invariants this crate must not violate
//!
//! * **NFR-O02** — vendor types stop at this boundary. Every function that
//!   crosses into the kernel returns a `sandtree-model` DTO. [`normalize`] never
//!   exposes a `bollard::models::*` type.
//! * **ADR-OBS-001 / FR-079** — an unreachable Engine makes the provider
//!   [`ProviderHealth::Unavailable`]; it never yields an empty resource list that
//!   the kernel would read as "these resources are gone".
//! * **RD §9 / NFR-S04** — fields the Engine did not report are omitted from
//!   metadata rather than defaulted. [`normalize`] only emits a key when Docker
//!   actually sent it.
//! * **DD-PLG §5** — identity is `blake3(endpoint_id + native id/digest)`, so a
//!   rename does not change a [`ResourceId`].
//!
//! # Isolation
//!
//! This provider runs on the **host** and talks to the host Engine. It never
//! mounts or proxies the host Docker socket into a guest (NFR-S06); doing so is
//! [`crate::host_policy`]'s explicit refusal, not an omission.

#![deny(missing_docs)]

pub mod endpoint;
pub mod error;
pub mod host_policy;
pub mod normalize;
pub mod observation;
pub mod provider;

pub use endpoint::{DockerEndpoint, EndpointParseError, DEFAULT_PIPE, DEFAULT_UNIX_SOCKET};
pub use error::{map_bollard_error, ProviderError};
pub use normalize::{
    container_state, normalize_container, normalize_image, normalize_network, normalize_volume,
};
pub use observation::{docker_capabilities, health_domain, system_domain};
pub use provider::DockerProvider;

/// Reverse-domain plugin id for this provider (DD-PLG §2).
pub const PLUGIN_ID: &str = "sandtree.provider.docker";

/// Version reported through [`sandtree_sdk::ports::ProviderDescriptor`].
pub const PROVIDER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Provenance source string for Engine-API observations.
pub const SOURCE_DOCKER_API: &str = "docker-engine-api";
