//! MCP endpoint provider: obtains sandbox-internal state over HTTP for content
//! that must **not** be reached by penetrating the guest (ADR-015).
//!
//! # Why this provider exists
//!
//! A sandbox may hold information the host cannot read without trading away
//! isolation — no read API, no exec channel, and reaching it another way would
//! mean exposing the host Docker socket, a full-disk writable mapping or a host
//! admin token (NFR-S06/S07, not negotiable). For that information the sandbox
//! can instead **publish** an MCP endpoint and let the host call it.
//!
//! MCP is the right shape for this: it is an ordinary, well-specified,
//! agent-facing protocol, so a sandbox that already speaks it can expose its
//! own view of itself without inventing anything.
//!
//! # What this provider does, and does not do
//!
//! It performs exactly one exchange: `initialize` → `notifications/initialized`
//! → `tools/list`. That yields the protocol revision, the server identity, the
//! advertised capabilities and the tool inventory — the sandbox's own account
//! of its exposed surface.
//!
//! It deliberately **never calls a tool**. Calling one executes
//! sandbox-chosen code with sandbox-chosen arguments and returns its output as
//! observation. That makes the observed able to act on the observer through a
//! path whose side effects nothing in the observation plane can reason about,
//! and it is exactly the shape of the guest-probe bootstrap that NFR-S06
//! keeps read-only for a living reason.
//!
//! # Trust
//!
//! Everything here is
//! [`TrustLevel::GuestProbe`](sandtree_observation_model::TrustLevel::GuestProbe),
//! fixed by [`sandtree_policy::acquire`]. The payload's BLAKE3 hash goes into
//! `evidence_hash`: **integrity**, not authenticity — a sandbox can present a
//! valid hash for an inventory it invented — so the level never rises
//! (ADR-OBS-003).
//!
//! # Admission
//!
//! The channel runs only when [`sandtree_policy::acquire::AcquisitionPolicy`]
//! admits it, which means penetrating the same resource and domain was
//! **refused**. When the host can already read inside safely, the network
//! channel is refused — otherwise a sandbox could decline a direct read and get
//! the weaker, sandbox-controlled answer delivered instead. The capability
//! grant defaults to absent, so an unconfigured provider observes nothing.
//!
//! # Relationship to `FR-O02`
//!
//! The design baseline's `FR-O02` MCP adapter is the **opposite** direction:
//! SandTree exposing its own operations to a compatible agent. This crate is
//! SandTree *consuming* an endpoint a sandbox publishes. The two share no code
//! and no protocol surface; see ADR-015.

#![deny(missing_docs)]

pub mod jsonrpc;
pub mod observation;
pub mod provider;
pub mod transport;
pub mod url;

pub use jsonrpc::{parse_response, ProtocolError, Request, Response};
pub use observation::{
    mcp_capabilities, parse_tool_list, snapshot_from_session, unavailable_snapshot, McpHandshake,
    DOMAIN,
};
pub use provider::{declared_capabilities, McpRemoteProvider};
pub use transport::{HyperMcpTransport, McpHttpResponse, McpTransport, TransportError};
pub use url::{EndpointScheme, EndpointUrlError, McpEndpointUrl};

/// Reverse-domain plugin id for this provider (DD-PLG §2).
pub const PLUGIN_ID: &str = "sandtree.provider.mcp-remote";

/// Version reported through [`sandtree_sdk::ports::ProviderDescriptor`].
pub const PROVIDER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Provenance source for every value this channel produces.
pub const SOURCE_MCP_ENDPOINT: &str = "mcp-endpoint-acquire";
