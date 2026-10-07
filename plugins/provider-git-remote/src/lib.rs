//! Git-remote provider: obtains sandbox-internal state over HTTP for content
//! that must **not** be reached by penetrating the guest (ADR-015).
//!
//! # Why this provider exists
//!
//! Some sandbox content cannot be observed from the host: the runtime has no
//! read API, no exec channel exists, and getting at it another way would mean
//! exposing the host Docker socket, a full-disk writable mapping or a host
//! admin token — all forbidden by NFR-S06/S07. For that content the sandbox
//! may instead **publish** a git remote and let the host fetch it.
//!
//! # The channel
//!
//! One request: `GET <repo>/info/refs?service=git-upload-pack`, which returns
//! git's **ref advertisement** — every ref with its content-addressed object
//! ID. That is enough to learn the shape of the sandbox's workspace (branches,
//! tags, HEAD, commit identity) without reading a single file out of the guest.
//!
//! # What this provider will not do
//!
//! * **Fetch objects or file content.** Only the advertisement is read. A
//!   channel that could pull arbitrary blobs out of the sandbox would be a
//!   second, ungoverned file-exfiltration path (NFR-S05 spirit).
//! * **Speak git protocol v2.** The client does not request it, and a v2
//!   answer is reported as unsupported rather than as an empty repository.
//! * **Speak any other scheme.** `git://`, `ssh://`, `file://` and `ext::` are
//!   refused at parse time — see [`url`].
//! * **Claim discovery.** Only [`ObservationProvider`] is implemented, so a
//!   channel outage can never be mistaken for resources having disappeared
//!   (ADR-OBS-001).
//!
//! # Trust
//!
//! Everything this provider produces is
//! [`TrustLevel::GuestProbe`](sandtree_observation_model::TrustLevel::GuestProbe),
//! fixed by [`sandtree_policy::acquire`]. The object IDs are recorded as
//! `evidence_hash`: that is **integrity**, not authenticity — a sandbox can
//! publish a valid object ID for a repository it made up — so the trust level
//! never rises (ADR-OBS-003).
//!
//! # Admission
//!
//! The channel only runs when [`sandtree_policy::acquire::AcquisitionPolicy`]
//! admits it, which means penetrating the same resource and domain was
//! **refused**. When the host can already read inside safely, this channel is
//! refused — otherwise a sandbox could decline a direct read and have the
//! weaker, sandbox-controlled answer delivered instead. The grant defaults to
//! absent, so a provider that was never configured observes nothing.

#![deny(missing_docs)]

pub mod advertisement;
pub mod observation;
pub mod pktline;
pub mod provider;
pub mod transport;
pub mod url;

pub use advertisement::{
    parse_advertisement, AdvertisementError, GitRef, ObjectFormat, RefAdvertisement, MAX_REFS,
};
pub use observation::{
    git_remote_capabilities, snapshot_from_advertisement, unavailable_snapshot, DOMAIN,
};
pub use pktline::{decode_all, PktLine, PktLineError};
pub use provider::{declared_capabilities, GitRemoteProvider};
pub use transport::{HttpResponse, RemoteTransport, TransportError};
pub use url::{GitRemoteUrl, RemoteScheme, RemoteUrlError};

/// Reverse-domain plugin id for this provider (DD-PLG §2).
pub const PLUGIN_ID: &str = "sandtree.provider.git-remote";

/// Version reported through [`sandtree_sdk::ports::ProviderDescriptor`].
pub const PROVIDER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Provenance source for every value this channel produces.
pub const SOURCE_GIT_REMOTE: &str = "git-remote-acquire";
