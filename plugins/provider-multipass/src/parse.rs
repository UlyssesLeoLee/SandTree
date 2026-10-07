//! Pure `multipass` JSON → domain DTO normalization (DD-PLG §9, FR-011, UT-032
//! shape, NFR-O02).
//!
//! No I/O and no `async`: everything here is a function from already-captured
//! bytes to a domain DTO, so the whole parsing contract is exercised against
//! recorded fixtures rather than against an installed Multipass.
//!
//! # Rules encoded here
//!
//! * **Identity** is `ResourceId::derive(["multipass", instance_name])`. A
//!   rename therefore *is* a new instance, which is correct for Multipass
//!   (unlike Docker, there is no immutable numeric id).
//! * **Absent fields produce no metadata key.** Multipass omits `ipv4` for a
//!   stopped instance; that yields no `ipv4` key rather than an empty list
//!   (RD §9, AGENTS.md invariant 11).
//! * **Unknown instance states are not guessed.** A state string this crate does
//!   not know maps to [`ResourceState::Unknown`], never to `Stopped`.

use std::collections::BTreeMap;

use sandtree_model::capability::{Capability, CapabilityNamespace, CapabilitySet};
use sandtree_model::id::{PluginId, ResourceId};
use sandtree_model::resource::{ResourceKind, ResourceNode, ResourceState};
use serde::Deserialize;
use serde_json::{Map, Value as Json};

/// Identity salt so Multipass ids cannot collide with another provider's.
const PROVIDER_SALT: &str = "sandtree.provider.multipass";

/// One entry of `multipass list --format json`.
#[derive(Debug, Clone, Deserialize)]
pub struct MultipassListEntry {
    /// Instance name.
    pub name: String,
    /// Reported state, e.g. `Running`, `Stopped`, `Started`.
    #[serde(default)]
    pub state: Option<String>,
    /// IPv4 addresses; absent for a stopped instance.
    #[serde(default)]
    pub ipv4: Option<Vec<String>>,
    /// IPv6 addresses.
    #[serde(default)]
    pub ipv6: Option<Vec<String>>,
    /// Guest release, e.g. `22.04`.
    #[serde(default)]
    pub release: Option<String>,
    /// Image backing the instance.
    #[serde(default)]
    pub image: Option<String>,
    /// Instance description / notes.
    #[serde(default)]
    pub description: Option<String>,
}

/// Map a Multipass state string to the normalized [`ResourceState`].
///
/// Multipass documents `Running`, `Stopped`, `Started`, `Restarting`,
/// `Suspended`, `Deleted`. Anything else becomes `Unknown`.
pub fn multipass_state(raw: Option<&str>) -> ResourceState {
    match raw {
        Some("Running") => ResourceState::Running,
        // `Started` is Multipass's transitional "booting" state.
        Some("Started") => ResourceState::Creating,
        Some("Stopped") => ResourceState::Stopped,
        Some("Suspended") => ResourceState::Paused,
        Some("Deleted") => ResourceState::Destroyed,
        Some("Restarting") => ResourceState::Running,
        _ => ResourceState::Unknown,
    }
}

/// Derive the stable instance id.
pub fn instance_id(name: &str) -> ResourceId {
    ResourceId::derive(&[PROVIDER_SALT, name])
}

/// Capabilities for an instance in a given state (FR-011, FR-061).
pub fn instance_capabilities(state: ResourceState) -> CapabilitySet {
    let mut set = CapabilitySet::from_iter_caps([
        Capability::global(CapabilityNamespace::Resource, "discover"),
        Capability::global(CapabilityNamespace::Resource, "inspect"),
    ]);
    match state {
        ResourceState::Running => {
            set.insert(Capability::global(CapabilityNamespace::Resource, "stop"));
            set.insert(Capability::global(CapabilityNamespace::Resource, "restart"));
            set.insert(Capability::global(CapabilityNamespace::Resource, "destroy"));
            // FR-013: exec is only meaningful in a running instance.
            set.insert(Capability::global(CapabilityNamespace::Exec, "spawn"));
        }
        ResourceState::Creating | ResourceState::Stopped => {
            set.insert(Capability::global(CapabilityNamespace::Resource, "start"));
            set.insert(Capability::global(CapabilityNamespace::Resource, "destroy"));
        }
        _ => {}
    }
    set.insert(Capability::global(
        CapabilityNamespace::Observation,
        "observe:system",
    ));
    set
}

/// Normalize one instance from `multipass list`.
pub fn normalize_instance(
    entry: &MultipassListEntry,
    provider: &PluginId,
    host_id: &ResourceId,
    now: &str,
) -> ResourceNode {
    let state = multipass_state(entry.state.as_deref());
    let mut meta = Map::new();
    meta.insert("instance_name".into(), Json::from(entry.name.clone()));

    // RD §9: emit a key only when Multipass reported the value.
    if let Some(ipv4) = non_empty(entry.ipv4.as_deref()) {
        meta.insert("ipv4".into(), Json::from(ipv4));
    }
    if let Some(ipv6) = non_empty(entry.ipv6.as_deref()) {
        meta.insert("ipv6".into(), Json::from(ipv6));
    }
    if let Some(release) = entry.release.as_deref().filter(|s| !s.is_empty()) {
        meta.insert("release".into(), Json::from(release));
    }
    if let Some(image) = entry.image.as_deref().filter(|s| !s.is_empty()) {
        meta.insert("image".into(), Json::from(image));
    }
    if let Some(desc) = entry.description.as_deref().filter(|s| !s.is_empty()) {
        meta.insert("description".into(), Json::from(desc));
    }
    if let Some(state_text) = entry.state.as_deref().filter(|s| !s.is_empty()) {
        meta.insert("state_text".into(), Json::from(state_text));
    }

    ResourceNode::new(
        instance_id(&entry.name),
        ResourceKind::Sandbox,
        provider.clone(),
        entry.name.clone(),
        state,
        Some(host_id.clone()),
        now.to_string(),
    )
    .with_capabilities(instance_capabilities(state))
    .with_metadata(Json::Object(meta))
}

/// Return a sorted copy when the list is non-empty, else `None`.
fn non_empty(list: Option<&[String]>) -> Option<Vec<String>> {
    let items = list?;
    if items.is_empty() {
        return None;
    }
    let mut v = items.to_vec();
    // CONTRACTS §6: deterministic ordering for golden tests.
    v.sort();
    Some(v)
}

/// Parse `multipass list --format json` into entries.
///
/// Multipass emits `[]` when no instances exist, which is a legitimate empty
/// result — distinct from the provider being unable to ask.
pub fn parse_list(stdout: &str) -> Result<Vec<MultipassListEntry>, String> {
    let parsed: Vec<MultipassListEntry> =
        serde_json::from_str(stdout).map_err(|e| e.to_string())?;
    // Stable order regardless of CLI output order.
    let mut entries = parsed;
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(entries)
}

/// Which observation domain a collector payload carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CollectorDomain {
    /// os/arch/hostname/uptime/cpu/memory.
    System,
    /// pid/ppid/name/cpu/memory.
    Process,
    /// Guest filesystem metadata (paths, types, sizes).
    Filesystem,
    /// Interfaces/listeners.
    Network,
    /// Nested Docker inventory.
    Docker,
    /// Collector self-report.
    Health,
}

impl CollectorDomain {
    /// Wire name, matching `sandtree_observation_model::ObservationDomain`.
    pub fn as_str(self) -> &'static str {
        match self {
            CollectorDomain::System => "system",
            CollectorDomain::Process => "process",
            CollectorDomain::Filesystem => "filesystem",
            CollectorDomain::Network => "network",
            CollectorDomain::Docker => "docker",
            CollectorDomain::Health => "health",
        }
    }

    /// Parse the wire name.
    pub fn from_wire(s: &str) -> Option<Self> {
        Some(match s {
            "system" => CollectorDomain::System,
            "process" => CollectorDomain::Process,
            "filesystem" => CollectorDomain::Filesystem,
            "network" => CollectorDomain::Network,
            "docker" => CollectorDomain::Docker,
            "health" => CollectorDomain::Health,
            _ => return None,
        })
    }
}

/// One collector invocation's parsed output.
///
/// DD-PLG §12.3: "命令失败只将对应 domain 标为 partial" — a per-domain failure
/// is recorded as partial, not as a whole-snapshot failure.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CollectorReport {
    /// Successfully parsed domain payloads, keyed by wire name.
    pub domains: BTreeMap<String, Json>,
    /// Domains the collector attempted but could not produce.
    pub partial: Vec<String>,
    /// Collector-reported errors, de-duplicated and sorted.
    pub errors: Vec<String>,
}

impl CollectorReport {
    /// Whether every requested domain was collected.
    pub fn is_complete(&self, requested: &[CollectorDomain]) -> bool {
        self.partial.is_empty()
            && requested
                .iter()
                .all(|d| self.domains.contains_key(d.as_str()))
    }
}

/// Parse `sandtree-collector --json <domains>` stdout.
///
/// The contract is a single JSON object:
///
/// ```json
/// {"domains": {"system": {...}}, "partial": ["network"], "errors": ["..."]}
/// ```
pub fn parse_collector_output(stdout: &str) -> Result<CollectorReport, String> {
    let raw: Json = serde_json::from_str(stdout).map_err(|e| e.to_string())?;
    let obj = raw
        .as_object()
        .ok_or_else(|| "collector output must be a JSON object".to_string())?;

    // An unknown top-level key means the collector is a version this provider
    // does not understand; silently ignoring it would risk mis-reading the
    // payload (DD-PLG §12.3 field allow-list).
    for key in obj.keys() {
        if !matches!(key.as_str(), "domains" | "partial" | "errors") {
            return Err(format!("unexpected collector key {key:?}"));
        }
    }

    let mut domains = BTreeMap::new();
    if let Some(d) = obj.get("domains").and_then(Json::as_object) {
        for (k, v) in d {
            // An unrecognised domain name is dropped rather than passed through.
            if CollectorDomain::from_wire(k).is_some() {
                domains.insert(k.clone(), v.clone());
            }
        }
    }

    let partial = string_list(obj.get("partial"));
    let mut errors = string_list(obj.get("errors"));
    errors.sort();
    errors.dedup();

    Ok(CollectorReport {
        domains,
        partial,
        errors,
    })
}

/// Read a JSON array of strings, ignoring non-string or non-array values.
fn string_list(v: Option<&Json>) -> Vec<String> {
    v.and_then(Json::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Json::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Build the argv for a collector run (DD-PLG §12.3).
///
/// ```text
/// multipass exec <instance> -- sandtree-collector --json <domains>
/// ```
///
/// `--` terminates Multipass's own option parsing so a collector flag cannot be
/// mistaken for a `multipass exec` flag.
pub fn collector_argv(instance: &str, domains: &[CollectorDomain]) -> Vec<String> {
    let mut names: Vec<&str> = domains.iter().map(|d| d.as_str()).collect();
    names.sort();
    names.dedup();
    let mut argv = vec![
        "multipass".to_string(),
        "exec".to_string(),
        instance.to_string(),
        "--".to_string(),
        "sandtree-collector".to_string(),
        "--json".to_string(),
        names.join(","),
    ];
    argv.shrink_to_fit();
    argv
}

/// Build the argv for a guest command (FR-013).
pub fn exec_argv(instance: &str, argv: &[String]) -> Vec<String> {
    let mut out = vec![
        "multipass".to_string(),
        "exec".to_string(),
        instance.to_string(),
        "--".to_string(),
    ];
    out.extend(argv.iter().cloned());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const NOW: &str = "2026-10-07T00:00:00Z";

    fn plugin() -> PluginId {
        PluginId::derive(&["sandtree.provider.multipass"])
    }

    fn host() -> ResourceId {
        ResourceId::derive(&["host"])
    }

    fn list_json() -> &'static str {
        r#"[
          {"name":"primary","state":"Running","ipv4":["10.0.0.5"],"release":"22.04","image":"Ubuntu 22.04 LTS amd64"},
          {"name":"dev-box","state":"Stopped","release":"24.04","image":"Ubuntu 24.04 LTS amd64"}
        ]"#
    }

    #[test]
    fn parses_and_sorts_list_entries() {
        let entries = parse_list(list_json()).unwrap();
        assert_eq!(entries.len(), 2);
        // Sorted by name regardless of the CLI's order.
        assert_eq!(entries[0].name, "dev-box");
        assert_eq!(entries[1].name, "primary");
    }

    #[test]
    fn empty_list_is_a_valid_empty_result() {
        // An empty array means "no instances", which is different from "could
        // not ask". The provider distinguishes the two before calling this.
        assert!(parse_list("[]").unwrap().is_empty());
    }

    #[test]
    fn malformed_list_json_is_rejected() {
        assert!(parse_list("not json").is_err());
        assert!(parse_list("{}").is_err());
        // A list entry missing its name is not usable.
        assert!(parse_list(r#"[{"state":"Running"}]"#).is_err());
    }

    #[test]
    fn state_mapping_is_exhaustive_over_documented_values() {
        assert_eq!(multipass_state(Some("Running")), ResourceState::Running);
        assert_eq!(multipass_state(Some("Started")), ResourceState::Creating);
        assert_eq!(multipass_state(Some("Stopped")), ResourceState::Stopped);
        assert_eq!(multipass_state(Some("Suspended")), ResourceState::Paused);
        assert_eq!(multipass_state(Some("Deleted")), ResourceState::Destroyed);
        // RD §9: an unknown state is not guessed into "stopped".
        assert_eq!(
            multipass_state(Some("Frobnicating")),
            ResourceState::Unknown
        );
        assert_eq!(multipass_state(None), ResourceState::Unknown);
    }

    #[test]
    fn stopped_instance_has_no_ip_metadata_key() {
        let entries = parse_list(list_json()).unwrap();
        let node = normalize_instance(&entries[0], &plugin(), &host(), NOW);
        assert_eq!(node.name, "dev-box");
        assert_eq!(node.state, ResourceState::Stopped);
        // Multipass omitted ipv4 for the stopped instance.
        assert!(node.meta_str("ipv4").is_none());
        assert!(node.meta_str("release").is_some());
        assert_eq!(node.meta_str("release"), Some("24.04"));
    }

    #[test]
    fn running_instance_normalizes_expected_fields() {
        let entries = parse_list(list_json()).unwrap();
        let node = normalize_instance(&entries[1], &plugin(), &host(), NOW);
        assert_eq!(node.kind, ResourceKind::Sandbox);
        assert_eq!(node.state, ResourceState::Running);
        assert_eq!(node.parent_id, Some(host()));
        assert_eq!(node.meta_str("instance_name"), Some("primary"));
        assert_eq!(node.meta_str("state_text"), Some("Running"));
        // `ipv4` is a JSON array, so it is read through the raw metadata rather
        // than the string-only `meta_str` accessor.
        assert_eq!(node.metadata["ipv4"], json!(["10.0.0.5"]));
        assert_eq!(node.last_seen, NOW);
    }

    #[test]
    fn empty_ip_list_produces_no_key() {
        // An empty array is still "no addresses"; emitting `[]` would suggest
        // the provider measured and found nothing.
        let entry: MultipassListEntry =
            serde_json::from_str(r#"{"name":"primary","state":"Running","ipv4":[],"ipv6":[]}"#)
                .unwrap();
        let node = normalize_instance(&entry, &plugin(), &host(), NOW);
        assert!(node.meta_str("ipv4").is_none());
        assert!(node.meta_str("ipv6").is_none());
    }

    #[test]
    fn instance_id_is_stable_and_name_scoped() {
        assert_eq!(instance_id("primary"), instance_id("primary"));
        assert_ne!(instance_id("primary"), instance_id("dev-box"));
        // Multipass ids must not collide with another provider's ids derived
        // from the same name.
        assert_ne!(
            instance_id("primary"),
            ResourceId::derive(&["sandtree.provider.docker", "primary"])
        );
    }

    #[test]
    fn capabilities_track_instance_state() {
        let running = instance_capabilities(ResourceState::Running);
        assert!(running.allows(&Capability::parse("resource:stop").unwrap()));
        assert!(running.allows(&Capability::parse("exec:spawn").unwrap()));
        assert!(!running.allows(&Capability::parse("resource:start").unwrap()));

        let stopped = instance_capabilities(ResourceState::Stopped);
        assert!(stopped.allows(&Capability::parse("resource:start").unwrap()));
        assert!(!stopped.allows(&Capability::parse("exec:spawn").unwrap()));

        // Unknown state: inspect only, no guessed lifecycle.
        let unknown = instance_capabilities(ResourceState::Unknown);
        assert!(unknown.allows(&Capability::parse("resource:inspect").unwrap()));
        assert!(!unknown.allows(&Capability::parse("resource:start").unwrap()));
        assert!(!unknown.allows(&Capability::parse("resource:stop").unwrap()));
    }

    #[test]
    fn parses_a_complete_collector_report() {
        let out =
            r#"{"domains":{"system":{"os":"ubuntu","arch":"amd64"}},"partial":[],"errors":[]}"#;
        let r = parse_collector_output(out).unwrap();
        assert!(r.partial.is_empty());
        assert!(r.errors.is_empty());
        assert_eq!(r.domains["system"]["os"], "ubuntu");
        assert!(r.is_complete(&[CollectorDomain::System]));
    }

    #[test]
    fn partial_collector_output_keeps_good_domains() {
        // DD-PLG §12.3: a failing sub-collector marks that domain partial; the
        // others stay usable.
        let out = r#"{"domains":{"system":{"os":"ubuntu"}},"partial":["network"],"errors":["network: timeout"]}"#;
        let r = parse_collector_output(out).unwrap();
        assert_eq!(r.partial, vec!["network"]);
        assert_eq!(r.errors, vec!["network: timeout"]);
        assert!(r.domains.contains_key("system"));
        assert!(!r.is_complete(&[CollectorDomain::System, CollectorDomain::Network]));
        // The system domain itself was collected cleanly.
        assert!(r.domains.contains_key("system"));
    }

    #[test]
    fn unknown_collector_keys_and_domains_are_rejected_or_dropped() {
        // An unknown top-level key means a collector version we do not
        // understand; guessing would be worse than failing.
        assert!(parse_collector_output(r#"{"domains":{},"surprise":1}"#).is_err());
        // An unknown *domain* is dropped, since it cannot be mapped to the
        // Observation Plane vocabulary.
        let r = parse_collector_output(r#"{"domains":{"system":{},"telepathy":{}}}"#).unwrap();
        assert!(r.domains.contains_key("system"));
        assert!(!r.domains.contains_key("telepathy"));
    }

    #[test]
    fn non_array_fields_are_ignored_rather_than_crashing() {
        let r = parse_collector_output(r#"{"domains":{},"partial":"network","errors":7}"#).unwrap();
        assert!(r.partial.is_empty());
        assert!(r.errors.is_empty());
    }

    #[test]
    fn errors_are_sorted_and_deduped_for_stable_output() {
        let r = parse_collector_output(r#"{"domains":{},"partial":[],"errors":["b","a","b","a"]}"#)
            .unwrap();
        assert_eq!(r.errors, vec!["a", "b"]);
    }

    #[test]
    fn collector_argv_uses_option_terminator_and_sorted_domains() {
        let argv = collector_argv(
            "primary",
            &[CollectorDomain::Network, CollectorDomain::System],
        );
        assert_eq!(
            argv,
            vec![
                "multipass",
                "exec",
                "primary",
                "--",
                "sandtree-collector",
                "--json",
                "network,system"
            ]
        );
        // `--` must appear so a collector flag is never a multipass flag.
        assert_eq!(argv.iter().position(|a| a == "--"), Some(3));
    }

    #[test]
    fn exec_argv_preserves_the_caller_vector_exactly() {
        // FR-013: argv is passed through verbatim, never via a shell.
        let argv = exec_argv("primary", &["ls".into(), "-la".into(), "/tmp".into()]);
        assert_eq!(
            argv,
            vec!["multipass", "exec", "primary", "--", "ls", "-la", "/tmp"]
        );
    }

    #[test]
    fn exec_argv_does_not_interpret_metacharacters() {
        // No shell is involved, so these are literal arguments.
        let argv = exec_argv("primary", &["echo $(id)".into(), "; rm -rf /".into()]);
        assert_eq!(argv[4], "echo $(id)");
        assert_eq!(argv[5], "; rm -rf /");
    }

    #[test]
    fn collector_domain_wire_round_trip() {
        for d in [
            CollectorDomain::System,
            CollectorDomain::Process,
            CollectorDomain::Filesystem,
            CollectorDomain::Network,
            CollectorDomain::Docker,
            CollectorDomain::Health,
        ] {
            assert_eq!(CollectorDomain::from_wire(d.as_str()), Some(d));
        }
        assert_eq!(CollectorDomain::from_wire("nope"), None);
    }
}
