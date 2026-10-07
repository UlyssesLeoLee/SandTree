//! Observation Plane domain DTO (DD-OBS §5–§6, DD-SW §12.2).
//!
//! Machine contract: `schemas/observation_snapshot_v1.schema.json`,
//! `schemas/sandtree_observation_v1.wit`, `schemas/observation_error_codes.csv`.
//!
//! Two invariants are encoded in the types themselves rather than in comments:
//!
//! * **Trust never escalates** (ADR-OBS-003). [`TrustLevel::at_most`] is the only
//!   way the kernel may combine sources, and [`Provenance::with_evidence`] keeps
//!   the reported trust even when a hash verifies.
//! * **No false certainty** (DD-OBS §2). Every value carries provenance with
//!   freshness and a `partial` flag; snapshots carry health independently of
//!   mode, so "partial" is never encoded as "absent".

use std::collections::BTreeMap;

use sandtree_model::id::ResourceId;
use serde::{Deserialize, Serialize};
use serde_json::Value as Json;

/// Observation mode, in negotiation priority order (DD-OBS §4).
///
/// Declaration order is significant: `Native < Exec < Probe < Metadata` in terms
/// of invasiveness, and the negotiation loop walks this order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationMode {
    /// Provider/Runtime offers a supported read API. Authoritative, least invasive.
    Native,
    /// Host can run a guest command and read its stdout (bounded collector).
    Exec,
    /// No reliable I/O; a disposable probe is bootstrapped.
    Probe,
    /// Only host-visible state.
    Metadata,
}

impl ObservationMode {
    /// Wire name (matches JSON schema + WIT).
    pub fn as_str(self) -> &'static str {
        match self {
            ObservationMode::Native => "native",
            ObservationMode::Exec => "exec",
            ObservationMode::Probe => "probe",
            ObservationMode::Metadata => "metadata",
        }
    }

    /// Parse wire form.
    pub fn from_wire(s: &str) -> Option<Self> {
        Some(match s {
            "native" => ObservationMode::Native,
            "exec" => ObservationMode::Exec,
            "probe" => ObservationMode::Probe,
            "metadata" => ObservationMode::Metadata,
            _ => return None,
        })
    }

    /// Less invasive modes sort first. `Metadata` is always last.
    pub fn is_less_invasive_than(self, other: ObservationMode) -> bool {
        self < other
    }

    /// Metadata mode can never claim rich observation.
    pub fn is_rich(self) -> bool {
        matches!(
            self,
            ObservationMode::Native | ObservationMode::Exec | ObservationMode::Probe
        )
    }
}

/// Provenance trust ladder (DD-OBS §6).
///
/// Ordering is by authority: lower is more trustworthy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustLevel {
    /// Directly visible to the host OS / hypervisor. Usable for security preconditions.
    HostNative,
    /// From an authenticated provider/runtime API. Usually usable.
    ProviderNative,
    /// Result of a host-initiated guest command. Must be bound to resource identity.
    RemoteExec,
    /// Reported by a probe inside the guest. Never usable for security preconditions.
    GuestProbe,
    /// Imported, stale, or not bindable to a session.
    Unverified,
}

impl TrustLevel {
    /// Wire name (JSON schema uses snake_case; WIT uses kebab-ish `host-native`).
    pub fn as_str(self) -> &'static str {
        match self {
            TrustLevel::HostNative => "host_native",
            TrustLevel::ProviderNative => "provider_native",
            TrustLevel::RemoteExec => "remote_exec",
            TrustLevel::GuestProbe => "guest_probe",
            TrustLevel::Unverified => "unverified",
        }
    }

    /// WIT variant name.
    pub fn wit_name(self) -> &'static str {
        match self {
            TrustLevel::HostNative => "host-native",
            TrustLevel::ProviderNative => "provider-native",
            TrustLevel::RemoteExec => "remote-exec",
            TrustLevel::GuestProbe => "guest-probe",
            TrustLevel::Unverified => "unverified",
        }
    }

    /// Parse wire form.
    pub fn from_wire(s: &str) -> Option<Self> {
        Some(match s {
            "host_native" => TrustLevel::HostNative,
            "provider_native" => TrustLevel::ProviderNative,
            "remote_exec" => TrustLevel::RemoteExec,
            "guest_probe" => TrustLevel::GuestProbe,
            "unverified" => TrustLevel::Unverified,
            _ => return None,
        })
    }

    /// The least trustworthy of two levels.
    ///
    /// This is the only legal way to merge trust when a snapshot is assembled
    /// from several sources; a guest probe can never be promoted by combination.
    /// Trust strength, `0` (untrusted) upward.
    ///
    /// The enum's declaration order is the *display* order the design uses
    /// (strongest first), so the derived `Ord` runs the opposite way from
    /// "more trust". Anything that reasons about trust must use this rank, never
    /// `>` or `max()` on the enum itself.
    pub fn rank(self) -> u8 {
        match self {
            TrustLevel::Unverified => 0,
            TrustLevel::GuestProbe => 1,
            TrustLevel::RemoteExec => 2,
            TrustLevel::ProviderNative => 3,
            TrustLevel::HostNative => 4,
        }
    }

    /// The weaker of two levels (ADR-OBS-003: trust is never raised).
    pub fn at_most(self, other: TrustLevel) -> TrustLevel {
        if self.rank() <= other.rank() {
            self
        } else {
            other
        }
    }

    /// Whether this level may satisfy a security precondition (DD-OBS §6, DD-SECOPS §11.1).
    pub fn is_security_authoritative(self) -> bool {
        matches!(self, TrustLevel::HostNative | TrustLevel::ProviderNative)
    }
}

/// Observation health, independent of mode (DD-OBS §12).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationHealth {
    /// Complete for the requested domains.
    Healthy,
    /// Some domains missing or failed; other domains valid.
    Degraded,
    /// Observation channel is down; control still works (FR-079).
    Unavailable,
    /// Data exists but exceeds the freshness policy (DD-OBS §13).
    Stale,
}

impl ObservationHealth {
    /// Wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            ObservationHealth::Healthy => "healthy",
            ObservationHealth::Degraded => "degraded",
            ObservationHealth::Unavailable => "unavailable",
            ObservationHealth::Stale => "stale",
        }
    }

    /// Parse wire form.
    pub fn from_wire(s: &str) -> Option<Self> {
        Some(match s {
            "healthy" => ObservationHealth::Healthy,
            "degraded" => ObservationHealth::Degraded,
            "unavailable" => ObservationHealth::Unavailable,
            "stale" => ObservationHealth::Stale,
            _ => return None,
        })
    }
}

/// Observation domains (DD-OBS §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationDomain {
    /// os/arch/hostname/uptime/cpu/memory — small, always complete.
    System,
    /// pid/ppid/name/cpu/memory/cwd — paginated, short cache.
    Process,
    /// path/type/size/mtime/hash_state — metadata only, lazy content.
    Filesystem,
    /// interfaces/listeners/connections summary.
    Network,
    /// nested engine info / containers / images / volumes / networks.
    Docker,
    /// mode/errors/warnings/collector version — always returned.
    Health,
}

impl ObservationDomain {
    /// Wire name (also the snapshot `values` key).
    pub fn as_str(self) -> &'static str {
        match self {
            ObservationDomain::System => "system",
            ObservationDomain::Process => "process",
            ObservationDomain::Filesystem => "filesystem",
            ObservationDomain::Network => "network",
            ObservationDomain::Docker => "docker",
            ObservationDomain::Health => "health",
        }
    }

    /// Parse wire form.
    pub fn from_wire(s: &str) -> Option<Self> {
        Some(match s {
            "system" => ObservationDomain::System,
            "process" => ObservationDomain::Process,
            "filesystem" => ObservationDomain::Filesystem,
            "network" => ObservationDomain::Network,
            "docker" => ObservationDomain::Docker,
            "health" => ObservationDomain::Health,
            _ => return None,
        })
    }

    /// All domains.
    pub fn all() -> &'static [ObservationDomain] {
        &[
            ObservationDomain::System,
            ObservationDomain::Process,
            ObservationDomain::Filesystem,
            ObservationDomain::Network,
            ObservationDomain::Docker,
            ObservationDomain::Health,
        ]
    }

    /// Default cache max-age in milliseconds (DD-OBS §13).
    pub fn default_max_age_ms(self) -> u64 {
        match self {
            ObservationDomain::System => 60_000,
            ObservationDomain::Process => 5_000,
            ObservationDomain::Network => 5_000,
            ObservationDomain::Filesystem => 10_000,
            ObservationDomain::Docker => 5_000,
            ObservationDomain::Health => 5_000,
        }
    }

    /// Default collection deadline in milliseconds (DD-SW §12.3).
    pub fn default_deadline_ms(self) -> u64 {
        match self {
            ObservationDomain::System => 2_000,
            ObservationDomain::Health => 2_000,
            ObservationDomain::Process => 5_000,
            ObservationDomain::Network => 5_000,
            ObservationDomain::Filesystem => 10_000,
            ObservationDomain::Docker => 10_000,
        }
    }
}

/// Where a value came from and how much to trust it (DD-OBS §6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    /// Source identifier, e.g. `multipass-exec` or `docker-sandbox-api`.
    pub source: String,
    /// Trust level.
    pub trust: TrustLevel,
    /// Observation timestamp (RFC3339).
    pub observed_at: String,
    /// Age at the time the snapshot was assembled.
    #[serde(default)]
    pub freshness_ms: u64,
    /// BLAKE3 evidence hash of the payload, when one exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_hash: Option<String>,
    /// Whether this value is incomplete.
    #[serde(default)]
    pub partial: bool,
}

impl Provenance {
    /// Fresh provenance with no evidence yet.
    pub fn new(
        source: impl Into<String>,
        trust: TrustLevel,
        observed_at: impl Into<String>,
    ) -> Self {
        Self {
            source: source.into(),
            trust,
            observed_at: observed_at.into(),
            freshness_ms: 0,
            evidence_hash: None,
            partial: false,
        }
    }

    /// Attach the BLAKE3 evidence hash of the payload.
    ///
    /// Trust is intentionally **not** raised here: ADR-OBS-003 states that a
    /// verified guest payload is still `guest_probe`, because the guest can
    /// simply produce a valid hash for a false claim.
    pub fn with_evidence(mut self, payload: &[u8]) -> Self {
        self.evidence_hash = Some(blake3::hash(payload).to_hex().to_string());
        self
    }

    /// Attach an explicit evidence hash.
    pub fn with_evidence_hash(mut self, hash: impl Into<String>) -> Self {
        self.evidence_hash = Some(hash.into());
        self
    }

    /// Mark partial.
    pub fn partial(mut self, partial: bool) -> Self {
        self.partial = partial;
        self
    }

    /// Set freshness age.
    pub fn with_freshness_ms(mut self, ms: u64) -> Self {
        self.freshness_ms = ms;
        self
    }
}

/// A single observed value plus its provenance.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ObservedValue {
    /// The value. Domain-specific JSON; never a provider SDK type.
    pub value: Json,
    /// How much to trust it.
    pub provenance: Provenance,
}

impl ObservedValue {
    /// Construct a value with provenance.
    pub fn new(value: Json, provenance: Provenance) -> Self {
        Self { value, provenance }
    }

    /// Whether the value is partial.
    pub fn is_partial(&self) -> bool {
        self.provenance.partial
    }

    /// Whether the value is trustworthy enough for a security precondition.
    pub fn is_security_authoritative(&self) -> bool {
        self.provenance.trust.is_security_authoritative()
    }
}

/// The unified observation output (DD-OBS §5).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ObservationSnapshot {
    /// Observed resource.
    pub resource_id: ResourceId,
    /// Snapshot time (RFC3339).
    pub observed_at: String,
    /// Mode actually used.
    pub mode: ObservationMode,
    /// Health of the observation channel.
    pub health: ObservationHealth,
    /// Collector/probe version, when the mode used one.
    #[serde(default)]
    pub collector_version: Option<String>,
    /// Domain → value map. Sorted keys keep snapshots byte-stable.
    #[serde(default)]
    pub values: BTreeMap<String, ObservedValue>,
    /// Non-fatal problems: missing domains, degraded sub-collectors.
    #[serde(default)]
    pub warnings: Vec<String>,
}

impl ObservationSnapshot {
    /// An empty snapshot in the given mode. Used by the degradation path so a
    /// failure still produces a typed result instead of an error (FR-079).
    pub fn empty(
        resource_id: ResourceId,
        mode: ObservationMode,
        health: ObservationHealth,
        observed_at: impl Into<String>,
    ) -> Self {
        Self {
            resource_id,
            observed_at: observed_at.into(),
            mode,
            health,
            collector_version: None,
            values: BTreeMap::new(),
            warnings: Vec::new(),
        }
    }

    /// Insert or replace a domain value.
    pub fn insert(&mut self, domain: ObservationDomain, value: ObservedValue) {
        self.values.insert(domain.as_str().to_string(), value);
    }

    /// Read a domain value.
    pub fn get(&self, domain: ObservationDomain) -> Option<&ObservedValue> {
        self.values.get(domain.as_str())
    }

    /// Missing requested domains, sorted.
    pub fn missing_domains(&self, requested: &[ObservationDomain]) -> Vec<&'static str> {
        requested
            .iter()
            .filter(|d| !self.values.contains_key(d.as_str()))
            .map(|d| d.as_str())
            .collect()
    }

    /// Whether every requested domain is present in this snapshot.
    pub fn covers_all(&self, requested: &[ObservationDomain]) -> bool {
        requested
            .iter()
            .all(|d| self.values.contains_key(d.as_str()))
    }

    /// Add a warning, de-duplicated.
    pub fn warn(&mut self, message: impl Into<String>) {
        let msg = message.into();
        if !self.warnings.contains(&msg) {
            self.warnings.push(msg);
        }
    }

    /// Whether any value is partial.
    pub fn is_partial(&self) -> bool {
        self.values.values().any(|v| v.is_partial())
    }

    /// Least trustworthy level present in the snapshot.
    ///
    /// Used when policy asks "how much do we trust this snapshot overall".
    pub fn weakest_trust(&self) -> Option<TrustLevel> {
        self.values
            .values()
            .map(|v| v.provenance.trust)
            .reduce(|a, b| a.at_most(b))
    }

    /// Whether every present value is security-authoritative.
    pub fn is_security_authoritative(&self) -> bool {
        self.weakest_trust()
            .map(TrustLevel::is_security_authoritative)
            .unwrap_or(false)
    }
}

/// The negotiated plan produced by strategy selection (DD-OBS §4).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ObservationPlan {
    /// Selected mode.
    pub mode: ObservationMode,
    /// Domains to collect in this plan.
    pub domains: Vec<ObservationDomain>,
    /// Per-run deadline.
    pub deadline_ms: u64,
    /// Maximum accepted age for a cache hit.
    pub max_age_ms: u64,
    /// Collector or probe version required by the provider, if any.
    #[serde(default)]
    pub collector_version: Option<String>,
    /// Fallback chain if this mode fails: `(mode, reason)`.
    #[serde(default)]
    pub fallback_chain: Vec<FallbackStep>,
}

/// One entry of the fallback chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FallbackStep {
    /// Mode to try next.
    pub mode: ObservationMode,
    /// Why the previous mode was abandoned.
    pub reason: String,
}

impl FallbackStep {
    /// Construct a fallback step.
    pub fn new(mode: ObservationMode, reason: impl Into<String>) -> Self {
        Self {
            mode,
            reason: reason.into(),
        }
    }
}

/// The kernel-side observation request (DD-SW §12.2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ObservationRequest {
    /// Target resource.
    pub resource_id: ResourceId,
    /// Requested domains; empty means "the provider's default set".
    #[serde(default)]
    pub domains: Vec<ObservationDomain>,
    /// Cache max-age.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_age_ms: Option<u64>,
    /// Hard deadline.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deadline_ms: Option<u64>,
    /// Bypass cache even when fresh (manual refresh).
    #[serde(default)]
    pub force: bool,
}

impl ObservationRequest {
    /// Construct with a domain set.
    pub fn new(resource_id: ResourceId, domains: Vec<ObservationDomain>) -> Self {
        Self {
            resource_id,
            domains,
            max_age_ms: None,
            deadline_ms: None,
            force: false,
        }
    }

    /// Set the cache max-age.
    pub fn with_max_age_ms(mut self, ms: u64) -> Self {
        self.max_age_ms = Some(ms);
        self
    }

    /// Set the hard deadline.
    pub fn with_deadline_ms(mut self, ms: u64) -> Self {
        self.deadline_ms = Some(ms);
        self
    }

    /// Force refresh, ignoring a fresh cache entry.
    pub fn forced(mut self) -> Self {
        self.force = true;
        self
    }
}

/// What a provider can do for one resource (DD-OBS §12.1).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservationCapabilities {
    /// Modes the provider supports, best first.
    pub modes: Vec<ObservationMode>,
    /// Domains obtainable per mode.
    pub domains: BTreeMap<String, Vec<ObservationDomain>>,
    /// Lower global concurrency limit the provider wants, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_concurrency: Option<u32>,
    /// Native credentials required (never the credential itself).
    #[serde(default)]
    pub requires_native_credential: bool,
}

impl ObservationCapabilities {
    /// Whether the provider supports a mode.
    pub fn supports(&self, mode: ObservationMode) -> bool {
        self.modes.contains(&mode)
    }

    /// Domains supported in a mode.
    pub fn domains_in(&self, mode: ObservationMode) -> &[ObservationDomain] {
        self.domains
            .get(mode.as_str())
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }
}

/// File content observation state (DD-OBS §10).
///
/// Hashing is triggered only on mtime/size change, snapshot, diff, or explicit
/// request — never by walking a tree (FR-077, ADR-OBS-005).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentHashState {
    /// Not hashed and not even indexed.
    UnknownHash,
    /// path/size/mtime known, no hash yet.
    MetadataKnown,
    /// BLAKE3 known.
    HashKnown,
    /// Content is stored in CAS.
    ContentCached,
}

impl ContentHashState {
    /// Wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            ContentHashState::UnknownHash => "unknown_hash",
            ContentHashState::MetadataKnown => "metadata_known",
            ContentHashState::HashKnown => "hash_known",
            ContentHashState::ContentCached => "content_cached",
        }
    }

    /// Whether a hash is available.
    pub fn has_hash(self) -> bool {
        matches!(
            self,
            ContentHashState::HashKnown | ContentHashState::ContentCached
        )
    }
}

/// File metadata entry produced by filesystem observation (metadata only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileMetadata {
    /// Path relative to the workspace root, `/`-separated.
    pub path: String,
    /// Whether this entry is a directory.
    pub is_dir: bool,
    /// Size in bytes (`0` for directories).
    pub size: u64,
    /// Modification time in nanoseconds since the Unix epoch, if available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtime_ns: Option<i128>,
    /// Hash availability.
    pub hash_state: ContentHashState,
    /// BLAKE3 digest when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rid() -> ResourceId {
        ResourceId::derive(&["res"])
    }

    #[test]
    fn mode_negotiation_order_is_native_exec_probe_metadata() {
        let mut modes = vec![
            ObservationMode::Metadata,
            ObservationMode::Probe,
            ObservationMode::Native,
            ObservationMode::Exec,
        ];
        modes.sort();
        assert_eq!(
            modes,
            vec![
                ObservationMode::Native,
                ObservationMode::Exec,
                ObservationMode::Probe,
                ObservationMode::Metadata
            ]
        );
    }

    #[test]
    fn wire_names_match_json_schema_and_wit() {
        for m in [
            ObservationMode::Native,
            ObservationMode::Exec,
            ObservationMode::Probe,
            ObservationMode::Metadata,
        ] {
            assert_eq!(ObservationMode::from_wire(m.as_str()), Some(m));
        }
        for t in [
            TrustLevel::HostNative,
            TrustLevel::ProviderNative,
            TrustLevel::RemoteExec,
            TrustLevel::GuestProbe,
            TrustLevel::Unverified,
        ] {
            assert_eq!(TrustLevel::from_wire(t.as_str()), Some(t));
        }
        for h in [
            ObservationHealth::Healthy,
            ObservationHealth::Degraded,
            ObservationHealth::Unavailable,
            ObservationHealth::Stale,
        ] {
            assert_eq!(ObservationHealth::from_wire(h.as_str()), Some(h));
        }
    }

    #[test]
    fn trust_ladder_orders_host_above_guest() {
        assert!(TrustLevel::HostNative < TrustLevel::ProviderNative);
        assert!(TrustLevel::ProviderNative < TrustLevel::RemoteExec);
        assert!(TrustLevel::RemoteExec < TrustLevel::GuestProbe);
        assert!(TrustLevel::GuestProbe < TrustLevel::Unverified);
    }

    #[test]
    fn trust_never_escalates_when_merged() {
        // ADR-OBS-003
        assert_eq!(
            TrustLevel::GuestProbe.at_most(TrustLevel::HostNative),
            TrustLevel::GuestProbe
        );
        assert_eq!(
            TrustLevel::ProviderNative.at_most(TrustLevel::RemoteExec),
            TrustLevel::RemoteExec
        );
    }

    #[test]
    fn evidence_does_not_promote_guest_trust() {
        let p = Provenance::new("probe", TrustLevel::GuestProbe, "2026-10-07T00:00:00Z")
            .with_evidence(b"payload");
        assert_eq!(p.trust, TrustLevel::GuestProbe);
        assert!(p.evidence_hash.is_some());
        assert!(!p.trust.is_security_authoritative());
    }

    #[test]
    fn snapshot_reports_missing_and_partial_domains() {
        let mut snap = ObservationSnapshot::empty(
            rid(),
            ObservationMode::Exec,
            ObservationHealth::Degraded,
            "2026-10-07T00:00:00Z",
        );
        snap.insert(
            ObservationDomain::System,
            ObservedValue::new(
                Json::Null,
                Provenance::new(
                    "multipass-exec",
                    TrustLevel::RemoteExec,
                    "2026-10-07T00:00:00Z",
                ),
            ),
        );
        let requested = vec![
            ObservationDomain::System,
            ObservationDomain::Process,
            ObservationDomain::Filesystem,
        ];
        assert_eq!(
            snap.missing_domains(&requested),
            vec!["process", "filesystem"]
        );
        assert!(!snap.is_partial());
        assert_eq!(snap.weakest_trust(), Some(TrustLevel::RemoteExec));
        assert!(!snap.is_security_authoritative());
    }

    #[test]
    fn snapshot_with_guest_probe_is_not_authoritative() {
        let mut snap = ObservationSnapshot::empty(
            rid(),
            ObservationMode::Probe,
            ObservationHealth::Healthy,
            "2026-10-07T00:00:00Z",
        );
        snap.insert(
            ObservationDomain::System,
            ObservedValue::new(
                serde_json::json!({"os":"windows"}),
                Provenance::new("probe", TrustLevel::GuestProbe, "2026-10-07T00:00:00Z"),
            ),
        );
        assert!(!snap.is_security_authoritative());
        assert_eq!(snap.weakest_trust(), Some(TrustLevel::GuestProbe));
    }

    #[test]
    fn empty_snapshot_represents_failure_without_error() {
        // FR-079 / ADR-OBS-001: unavailable observation is a state, not an error.
        let snap = ObservationSnapshot::empty(
            rid(),
            ObservationMode::Metadata,
            ObservationHealth::Unavailable,
            "2026-10-07T00:00:00Z",
        );
        assert!(snap.values.is_empty());
        assert_eq!(snap.health, ObservationHealth::Unavailable);
        let json = serde_json::to_value(&snap).unwrap();
        assert_eq!(json["health"], "unavailable");
        assert_eq!(json["mode"], "metadata");
    }

    #[test]
    fn snapshot_values_are_sorted_for_byte_stability() {
        let mut snap = ObservationSnapshot::empty(
            rid(),
            ObservationMode::Native,
            ObservationHealth::Healthy,
            "2026-10-07T00:00:00Z",
        );
        let p = Provenance::new("api", TrustLevel::ProviderNative, "2026-10-07T00:00:00Z");
        for d in [
            ObservationDomain::System,
            ObservationDomain::Health,
            ObservationDomain::Process,
        ] {
            snap.insert(d, ObservedValue::new(Json::Null, p.clone()));
        }
        let keys: Vec<&str> = snap.values.keys().map(String::as_str).collect();
        assert_eq!(keys, vec!["health", "process", "system"]);
    }

    #[test]
    fn freshness_defaults_match_design_table() {
        // DD-OBS §13
        assert_eq!(ObservationDomain::System.default_max_age_ms(), 60_000);
        assert_eq!(ObservationDomain::Process.default_max_age_ms(), 5_000);
        assert_eq!(ObservationDomain::Network.default_max_age_ms(), 5_000);
        assert_eq!(ObservationDomain::Filesystem.default_max_age_ms(), 10_000);
        // DD-SW §12.3
        assert_eq!(ObservationDomain::System.default_deadline_ms(), 2_000);
        assert_eq!(ObservationDomain::Process.default_deadline_ms(), 5_000);
        assert_eq!(ObservationDomain::Filesystem.default_deadline_ms(), 10_000);
    }

    #[test]
    fn hash_state_ladder() {
        assert!(!ContentHashState::UnknownHash.has_hash());
        assert!(!ContentHashState::MetadataKnown.has_hash());
        assert!(ContentHashState::HashKnown.has_hash());
        assert!(ContentHashState::ContentCached.has_hash());
    }

    #[test]
    fn capabilities_report_domains_per_mode() {
        let mut domains = std::collections::BTreeMap::new();
        domains.insert(
            "native".to_string(),
            vec![ObservationDomain::Filesystem, ObservationDomain::Process],
        );
        let caps = ObservationCapabilities {
            modes: vec![ObservationMode::Native, ObservationMode::Metadata],
            domains,
            max_concurrency: None,
            requires_native_credential: false,
        };
        assert!(caps.supports(ObservationMode::Native));
        assert!(!caps.supports(ObservationMode::Exec));
        assert_eq!(caps.domains_in(ObservationMode::Native).len(), 2);
        assert!(caps.domains_in(ObservationMode::Metadata).is_empty());
    }
}
