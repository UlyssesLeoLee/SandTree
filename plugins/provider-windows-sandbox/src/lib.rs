//! Windows Sandbox provider (DD-PLG §7, §12.4; FR-011, FR-014, FR-070,
//! FR-079; NFR-S06, NFR-S07, NFR-S08).
//!
//! Windows Sandbox offers no process I/O through `wsb exec`, so rich telemetry
//! requires a **probe**: a disposable binary mapped read-only into the guest that
//! writes bounded JSON envelopes to a dedicated outbox for the host to consume
//! (`schemas/windows_probe_protocol_v1.md`).
//!
//! # Structure
//!
//! | module | role |
//! | --- | --- |
//! | [`definition`] | `.wsb` XML → `ResourceNode`; the mapped-folder allow-list |
//! | [`envelope`] | probe envelope parsing and **host-side validation** |
//! | [`observation`] | Mode C Probe snapshot assembly and trust |
//! | [`provider`] | the SDK port implementations |
//!
//! # The three invariants this crate exists to enforce
//!
//! 1. **Trust never rises** (AGENTS.md invariant 3, ADR-OBS-003). Every value
//!    that came out of a probe is [`TrustLevel::GuestProbe`]. Envelope
//!    validation decides whether the payload is *accepted*, never whether it
//!    becomes *more trustworthy*: a verified BLAKE3 hash over guest-produced
//!    bytes proves integrity, not truth.
//! 2. **Read-only bootstrap** (invariant 4, NFR-S07). [`definition`] is the only
//!    place mapped folders are interpreted, and a writable mapping of anything
//!    other than the dedicated outbox is refused.
//! 3. **No general shell** (NFR-S07). The probe has a fixed domain vocabulary
//!    ([`CollectorDomain`]-equivalent) and this provider never forwards a
//!    host-supplied command into a guest.
//!
//! # Deviation from DD-PLG §7
//!
//! DD-PLG §7 says `LogonCommand` starts a `sandtree-bridge` binary. No such
//! binary is in this repository (the probe lives in `apps/probe-windows`, owned
//! elsewhere), so this provider treats the **envelope protocol** as the
//! contract: it discovers `.wsb` definitions and validates consumed envelopes,
//! and does not itself generate bridge configuration. See
//! [`definition::bridge_command`].

#![deny(missing_docs)]

pub mod definition;
pub mod envelope;
pub mod observation;
pub mod provider;

pub use definition::{
    bridge_command, parse_wsb, WsbDefinition, WsbParseError, DEFAULT_OUTBOX_DIR, FORBIDDEN_MAPPINGS,
};
pub use envelope::{
    validate_envelope, EnvelopeError, EnvelopeLimits, ProbeEnvelope, ENVELOPE_SCHEMA,
};
pub use observation::{
    sandbox_capabilities, snapshot_from_envelopes, unavailable_snapshot, MAX_ENVELOPES_PER_SESSION,
};
pub use provider::WindowsSandboxProvider;

/// Reverse-domain plugin id for this provider (DD-PLG §2).
pub const PLUGIN_ID: &str = "sandtree.provider.windows-sandbox";

/// Version reported through [`sandtree_sdk::ports::ProviderDescriptor`].
pub const PROVIDER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Provenance source for probe-reported data (DD-OBS §6).
pub const SOURCE_PROBE: &str = "windows-sandbox-probe";
