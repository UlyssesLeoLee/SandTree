//! Redacted diagnostics bundle (FR-066, NFR-S03).
//!
//! The bundle is what a user attaches to a bug report, so it is built under the
//! assumption that **everything** in it will be shown to someone. Secrets are
//! removed by key and by value shape *before* anything is serialised, and the
//! redaction runs over the final assembled document rather than over each part
//! separately — a secret that only appears after two fields are joined would
//! otherwise slip through.

use sandtree_model::error::DomainError;
use sandtree_model::resource::{ResourceKind, ResourceState};
use sandtree_policy::redact::Redactor;
use serde_json::Value as Json;

use crate::resources::ResourceFilter;
use crate::Kernel;

/// What the bundle contains.
#[derive(Debug, Clone, PartialEq)]
pub struct DiagnosticsBundle {
    /// Redacted JSON document.
    pub json: Json,
}

/// Assemble and redact the bundle.
pub async fn bundle(kernel: &Kernel) -> Result<Json, DomainError> {
    let store = kernel.store();
    let providers = kernel.providers().await;

    let resources = store.resources(None, None)?;
    let mut counts: std::collections::BTreeMap<String, u64> = Default::default();
    for n in &resources {
        *counts
            .entry(format!("{}/{}", n.kind.as_str(), n.state.as_str()))
            .or_insert(0) += 1;
    }

    let mut endpoints = Vec::new();
    for e in store.list_docker_endpoints()? {
        endpoints.push(serde_json::json!({
            "endpoint_id": e.id.as_str(),
            "uri": strip_userinfo(&e.uri),
            "api_version": e.api_version,
            "engine_version": e.engine_version,
            "os": e.os,
            "arch": e.arch,
            "health": e.health,
        }));
    }

    let raw = serde_json::json!({
        "schema": "sandtree.diagnostics/1",
        "kernel": {
            "data_dir": kernel.config().data_dir.display().to_string(),
            "reconcile_interval_ms": kernel.config().reconcile_interval_ms,
            "stale_grace_ms": kernel.config().stale_grace_ms,
            "store": store.path().display().to_string(),
            "schema_version": store.schema_version()?,
        },
        "providers": providers.iter().map(|p| p.as_str()).collect::<Vec<_>>(),
        "resource_counts": counts,
        "resource_kinds": kinds(),
        "resource_states": states(),
        "docker_endpoints": endpoints,
        "tree": kernel
            .resources()
            .tree_json(&ResourceFilter::all())
            .await
            .unwrap_or(Json::Array(Vec::new())),
    });

    // Redact the assembled document, not the parts.
    Redactor::new().redact_value(&raw).map_err(|e| {
        DomainError::new(
            sandtree_model::error::ErrorCode::CORE_INVALID,
            format!("diagnostics bundle could not be redacted: {e}"),
        )
    })
}

/// Remove `user:password@` from a URI before it reaches the bundle.
///
/// The redactor works on keys, and `uri` is not a secret key, so an endpoint
/// profile with embedded credentials would pass straight through. NFR-S03
/// forbids credentials in endpoint profiles; this makes that hold for the one
/// field where they are realistically embedded.
fn strip_userinfo(uri: &str) -> String {
    let Some(scheme_end) = uri.find("://") else {
        return uri.to_string();
    };
    let rest = &uri[scheme_end + 3..];
    let authority_end = rest.find('/').unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(authority_end);
    let Some(at) = authority.rfind('@') else {
        return uri.to_string();
    };
    let userinfo = &authority[..at];
    let user = userinfo.split(':').next().unwrap_or("");
    format!(
        "{}://{user}:[REDACTED]@{}{tail}",
        &uri[..scheme_end],
        &authority[at + 1..]
    )
}

/// Every resource kind the model defines, so a report always shows which kinds
/// exist even when the current install uses none of them.
fn kinds() -> Json {
    Json::Array(
        ResourceKind::all()
            .iter()
            .map(|k| Json::String(k.as_str().to_string()))
            .collect(),
    )
}

/// States the model defines.
pub fn states() -> Json {
    Json::Array(
        [
            ResourceState::Unknown,
            ResourceState::Creating,
            ResourceState::Running,
            ResourceState::Stopped,
            ResourceState::Paused,
            ResourceState::Exited,
            ResourceState::Degraded,
            ResourceState::Destroying,
            ResourceState::Destroyed,
            ResourceState::Tombstoned,
        ]
        .iter()
        .map(|s| Json::String(s.as_str().to_string()))
        .collect(),
    )
}
