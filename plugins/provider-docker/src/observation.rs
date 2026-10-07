//! Docker Engine observation (DD-PLG §12, §12.5; FR-070, FR-077, FR-079).
//!
//! Docker Engine is the *authoritative* source for its own resources, so this
//! provider always negotiates [`ObservationMode::Native`] with
//! [`TrustLevel::ProviderNative`]. There is no probe, no exec fallback and no
//! guest agent: if the Engine API cannot answer, the snapshot says so.
//!
//! Degradation follows FR-079 exactly: a failed collection produces a snapshot
//! with [`ObservationHealth::Unavailable`] plus a warning, **not** an error and
//! **not** an empty-looking healthy result.

use bollard::models::{SystemInfo, SystemVersionPlatform};
use bollard::system::Version;
use sandtree_observation_model::{
    ObservationCapabilities, ObservationDomain, ObservationHealth, ObservationMode,
    ObservationSnapshot, ObservedValue, Provenance, TrustLevel,
};
use serde_json::{Map, Value as Json};

/// Provenance source for Engine-API data (DD-OBS §6).
pub const SOURCE: &str = crate::SOURCE_DOCKER_API;

/// Build the capability declaration for a Docker-backed resource.
///
/// Docker answers `system`, `docker` and `health` natively. `process` and
/// `filesystem` need a guest-side channel (exec or probe), which this provider
/// deliberately does not claim — over-claiming would make the negotiator pick a
/// mode that cannot complete (DD-OBS §4).
pub fn docker_capabilities(resource_is_container: bool) -> ObservationCapabilities {
    let mut domains = std::collections::BTreeMap::new();
    let mut native = vec![ObservationDomain::System, ObservationDomain::Health];
    if resource_is_container {
        // `/stats` and `/top` are per-container Engine endpoints.
        native.push(ObservationDomain::Process);
    }
    native.sort();
    domains.insert(ObservationMode::Native.as_str().to_string(), native.clone());

    let mut modes = vec![ObservationMode::Native];
    // DD-PLG §12.5 Mode D: metadata-only always remains as the floor, so a
    // broken Engine still leaves Control usable (FR-079).
    modes.push(ObservationMode::Metadata);
    let mut metadata = vec![ObservationDomain::Health];
    if resource_is_container {
        metadata.push(ObservationDomain::System);
    }
    metadata.sort();
    domains.insert(ObservationMode::Metadata.as_str().to_string(), metadata);

    ObservationCapabilities {
        modes,
        domains,
        max_concurrency: None,
        requires_native_credential: false,
    }
}

/// Build the `system` domain from `/version` and `/info`.
///
/// Trust is `provider_native`: this is the Engine's own API, not a guess.
/// Fields Docker did not send are omitted (RD §9).
///
/// The domain describes the Engine rather than one resource, so the payload is
/// a pure function of the two API responses and carries no per-resource fields.
pub fn system_domain(
    version: &Version,
    info: Option<&SystemInfo>,
    observed_at: &str,
) -> ObservedValue {
    let mut m = Map::new();
    let mut put = |k: &str, v: Json| {
        m.insert(k.to_string(), v);
    };

    put("api_version", opt_str(version.api_version.as_deref()));
    put("engine_version", opt_str(version.version.as_deref()));
    put(
        "min_api_version",
        opt_str(version.min_api_version.as_deref()),
    );
    put("os", opt_str(version.os.as_deref()));
    put("arch", opt_str(version.arch.as_deref()));
    put("kernel_version", opt_str(version.kernel_version.as_deref()));
    put("go_version", opt_str(version.go_version.as_deref()));
    put("git_commit", opt_str(version.git_commit.as_deref()));
    put(
        "experimental",
        version.experimental.map_or(Json::Null, Json::from),
    );

    if let Some(platform) = version.platform.as_ref().and_then(platform_name) {
        put("platform_name", Json::from(platform));
    }
    if let Some(info) = info {
        put("containers", opt_i64(info.containers));
        put("containers_running", opt_i64(info.containers_running));
        put("containers_paused", opt_i64(info.containers_paused));
        put("containers_stopped", opt_i64(info.containers_stopped));
        put("images", opt_i64(info.images));
        put("driver", opt_str(info.driver.as_deref()));
        put("server_version", opt_str(info.server_version.as_deref()));
        put(
            "operating_system",
            opt_str(info.operating_system.as_deref()),
        );
        put("ncpu", opt_i64(info.ncpu));
        put("mem_total", opt_i64(info.mem_total));
    }

    // Drop every key whose value is null: an unreported field is absent, not null.
    m.retain(|_, v| !v.is_null());

    ObservedValue::new(
        Json::Object(m),
        Provenance::new(SOURCE, TrustLevel::ProviderNative, observed_at),
    )
}

/// Build the `health` domain, which is always present even when nothing else is.
///
/// DD-OBS §5: "health — always returned". It carries no measured values, only
/// Build the `health` domain, which is always present even when nothing else is.
///
/// DD-OBS §5: "health — always returned". It carries no measured values, only
/// the mode/errors the collector wants to surface. It is deliberately a pure
/// function of its arguments so it can be emitted on any path, including the
/// degraded one.
///
/// `trust` is explicit rather than fixed because the two call sites differ: when
/// the Engine answered, the health report is `provider_native`; when the Engine
/// could not be reached, no Engine response backs the claim at all, so it is
/// `unverified`. Claiming Engine trust for a failure report would let policy
/// treat a failed collection as an authoritative observation.
pub fn health_domain(
    observed_at: &str,
    warnings: &[String],
    trust: TrustLevel,
    partial: bool,
) -> ObservedValue {
    let mut m = Map::new();
    m.insert("mode".into(), Json::from(ObservationMode::Native.as_str()));
    m.insert(
        "status".into(),
        Json::from(if trust == TrustLevel::Unverified {
            "unavailable"
        } else {
            "ok"
        }),
    );
    if !warnings.is_empty() {
        let mut sorted: Vec<&String> = warnings.iter().collect();
        sorted.sort();
        sorted.dedup();
        m.insert(
            "errors".into(),
            Json::from(sorted.iter().map(|s| s.as_str()).collect::<Vec<_>>()),
        );
    }
    ObservedValue::new(
        Json::Object(m),
        Provenance::new(SOURCE, trust, observed_at).partial(partial),
    )
}

/// Produce the degraded snapshot for an unreachable Engine (FR-079).
///
/// The resource keeps existing in the graph; only its observation channel is
/// unavailable. `mode` stays `native` because that is what was attempted, and
/// `health` is `Unavailable` so the UI can say "control works, telemetry does
/// not" (ADR-OBS-001).
pub fn unavailable_snapshot(
    resource_id: sandtree_model::id::ResourceId,
    reason: impl Into<String>,
    observed_at: impl Into<String>,
) -> ObservationSnapshot {
    let reason = reason.into();
    let observed_at = observed_at.into();
    let mut snap = ObservationSnapshot::empty(
        resource_id,
        ObservationMode::Native,
        ObservationHealth::Unavailable,
        observed_at.clone(),
    );
    // health is still emitted so callers always have the domain present.
    snap.insert(
        ObservationDomain::Health,
        health_domain(&observed_at, &[], TrustLevel::Unverified, true),
    );
    snap.warn(reason);
    snap
}

fn opt_str(v: Option<&str>) -> Json {
    match v {
        Some(s) if !s.is_empty() => Json::from(s),
        _ => Json::Null,
    }
}

/// Optional integer, rendered as JSON null when the Engine omitted it.
///
/// The caller drops null values afterwards (RD §9), so an unreported counter
/// leaves no key at all rather than a fabricated zero.
fn opt_i64(v: Option<i64>) -> Json {
    v.map_or(Json::Null, Json::from)
}

fn platform_name(p: &SystemVersionPlatform) -> Option<String> {
    // `name` is a plain `String` in this bollard version, not an `Option`.
    (!p.name.is_empty()).then(|| p.name.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rid() -> sandtree_model::id::ResourceId {
        sandtree_model::id::ResourceId::derive(&["ep", "c1"])
    }

    fn version() -> Version {
        serde_json::from_value(serde_json::json!({
            "Platform": { "Name": "Docker Engine - Community" },
            "Version": "27.3.1",
            "ApiVersion": "1.47",
            "MinAPIVersion": "1.24",
            "GitCommit": "cecb303",
            "GoVersion": "go1.22.7",
            "Os": "linux",
            "Arch": "amd64",
            "KernelVersion": "5.15.0",
            "Experimental": false
        }))
        .unwrap()
    }

    #[test]
    fn engine_data_is_provider_native_not_host_native() {
        // The Engine API is authoritative for Docker resources (DD-PLG §12.2),
        // but it is not host-visible state, so it must not claim HostNative.
        let v = system_domain(&version(), None, "2026-10-07T00:00:00Z");
        assert_eq!(v.provenance.trust, TrustLevel::ProviderNative);
        // Host visibility is a strictly stronger trust than the Engine API offers.
        assert_ne!(v.provenance.trust, TrustLevel::HostNative);
    }

    #[test]
    fn system_domain_reports_only_what_the_engine_sent() {
        let v = system_domain(&version(), None, "2026-10-07T00:00:00Z");
        let obj = v.value.as_object().unwrap();
        assert_eq!(obj["engine_version"], "27.3.1");
        assert_eq!(obj["api_version"], "1.47");
        assert_eq!(obj["min_api_version"], "1.24");
        assert_eq!(obj["platform_name"], "Docker Engine - Community");
        assert_eq!(obj["os"], "linux");
        assert_eq!(obj["arch"], "amd64");
        // `info` was not supplied, so no /info keys may appear at all.
        assert!(!obj.contains_key("containers"));
        assert!(!obj.contains_key("ncpu"));
        // No null-valued keys: absence is absence.
        assert!(obj.values().all(|v| !v.is_null()));
    }

    #[test]
    fn system_domain_merges_info_when_available() {
        let info: SystemInfo = serde_json::from_value(serde_json::json!({
            "ID": "ENGINE",
            "Containers": 7,
            "ContainersRunning": 2,
            "Images": 11,
            "Driver": "overlay2",
            "NCPU": 8,
            "MemTotal": 16 * 1024 * 1024
        }))
        .unwrap();
        let v = system_domain(&version(), Some(&info), "2026-10-07T00:00:00Z");
        let obj = v.value.as_object().unwrap();
        assert_eq!(obj["containers"], 7);
        assert_eq!(obj["containers_running"], 2);
        assert_eq!(obj["driver"], "overlay2");
        assert_eq!(obj["ncpu"], 8);
    }

    #[test]
    fn capabilities_do_not_over_claim_guest_only_domains() {
        // Over-claiming process/filesystem would make the negotiator choose a
        // mode this provider cannot actually run.
        let caps = docker_capabilities(true);
        assert!(caps.supports(ObservationMode::Native));
        assert!(caps.supports(ObservationMode::Metadata));
        assert!(!caps.supports(ObservationMode::Probe));
        assert!(!caps.supports(ObservationMode::Exec));

        let native = caps.domains_in(ObservationMode::Native);
        assert!(native.contains(&ObservationDomain::System));
        assert!(native.contains(&ObservationDomain::Health));
        assert!(native.contains(&ObservationDomain::Process));
        // Filesystem needs a guest channel; not claimed.
        assert!(!native.contains(&ObservationDomain::Filesystem));
    }

    #[test]
    fn non_container_does_not_claim_process_observation() {
        let caps = docker_capabilities(false);
        assert!(!caps
            .domains_in(ObservationMode::Native)
            .contains(&ObservationDomain::Process));
    }

    #[test]
    fn unavailable_snapshot_is_a_state_not_an_error() {
        // FR-079 / ADR-OBS-001: observation failure must not be an error and
        // must not imply the resource is gone.
        let snap = unavailable_snapshot(rid(), "engine unreachable", "2026-10-07T00:00:00Z");
        assert_eq!(snap.health, ObservationHealth::Unavailable);
        assert_eq!(snap.resource_id, rid());
        assert!(snap.warnings.contains(&"engine unreachable".to_string()));
        // health domain is still present so the UI has something to render.
        assert!(snap.get(ObservationDomain::Health).is_some());
        assert!(snap.get(ObservationDomain::Health).unwrap().is_partial());
        // Nothing was invented.
        assert!(snap.get(ObservationDomain::System).is_none());
        // Nothing measured, so nothing is security-authoritative.
        assert!(!snap
            .get(ObservationDomain::Health)
            .unwrap()
            .is_security_authoritative());
        assert!(!snap.is_security_authoritative());
    }

    #[test]
    fn health_domain_sorts_and_dedups_warnings() {
        let v = health_domain(
            "2026-10-07T00:00:00Z",
            &["b".to_string(), "a".to_string(), "b".to_string()],
            TrustLevel::ProviderNative,
            false,
        );
        assert_eq!(v.value["status"], "ok");
        assert_eq!(v.value["errors"], serde_json::json!(["a", "b"]));
        assert!(!v.is_partial());
    }
}
