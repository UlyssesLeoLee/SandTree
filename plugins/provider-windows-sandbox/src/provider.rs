//! SDK port implementation for Windows Sandbox (DD-PLG §7, §12.1; §12.4).
//!
//! # Capability separation
//!
//! This crate implements [`ResourceProvider`] and [`ObservationProvider`].
//! It deliberately does **not** implement [`ExecProvider`]: Windows Sandbox has
//! no reliable guest command channel (`wsb exec` returns no process I/O,
//! DD-PLG §12.4), and a probe is a fixed-capability program rather than a shell
//! (NFR-S07). Implementing the port would advertise an escape hatch that does not
//! exist.
//!
//! It also does not implement [`FileProvider`]. Guest file access goes through
//! probe-reported metadata and an explicitly mapped folder; presenting an
//! `stfs://` tree over it would imply a stable mount that Windows Sandbox does
//! not provide.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use sandtree_model::error::{DomainError, ErrorCode};
use sandtree_model::id::{PluginId, ResourceId};
use sandtree_model::operation::{OperationKind, OperationOutcome, OperationRequest};
use sandtree_model::resource::{Relation, RelationKind, ResourceNode};
use sandtree_observation_model::{
    ObservationCapabilities, ObservationRequest, ObservationSnapshot,
};
use sandtree_sdk::manifest::{now_rfc3339, PluginKind};
use sandtree_sdk::ports::{
    DiscoverBatch, ObservationProvider, ProviderDescriptor, ProviderHealth, ResourceProvider,
};
use tokio::sync::RwLock;

use crate::definition::{
    definition_name_from_path, is_within, normalize_definition, parse_wsb, sandbox_id,
    WsbParseError,
};
use crate::envelope::{
    parse_envelope, validate_envelope, EnvelopeError, EnvelopeLimits, ProbeEnvelope, SessionBinding,
};
use crate::observation::{sandbox_capabilities, snapshot_from_envelopes, unavailable_snapshot};

/// Configuration for a provider instance.
#[derive(Debug, Clone)]
pub struct WindowsSandboxConfig {
    /// Directory scanned for SandTree-managed `.wsb` definitions.
    pub definitions_dir: PathBuf,
    /// Dedicated telemetry outbox. The only host path a guest may write.
    pub outbox_dir: PathBuf,
    /// Nonce agreed at bridge handshake for the current session.
    pub session_nonce: String,
    /// Envelope validation budgets.
    pub limits: EnvelopeLimits,
}

impl WindowsSandboxConfig {
    /// Build a configuration with default budgets.
    pub fn new(
        definitions_dir: impl Into<PathBuf>,
        outbox_dir: impl Into<PathBuf>,
        session_nonce: impl Into<String>,
    ) -> Self {
        Self {
            definitions_dir: definitions_dir.into(),
            outbox_dir: outbox_dir.into(),
            session_nonce: session_nonce.into(),
            limits: EnvelopeLimits::default(),
        }
    }
}

/// Windows Sandbox provider.
pub struct WindowsSandboxProvider {
    config: WindowsSandboxConfig,
    plugin_id: PluginId,
    host_id: ResourceId,
    /// Highest accepted sequence per sandbox, for replay rejection.
    sequences: RwLock<std::collections::BTreeMap<String, u64>>,
}

impl std::fmt::Debug for WindowsSandboxProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The nonce is a session secret; never print it.
        f.debug_struct("WindowsSandboxProvider")
            .field("definitions_dir", &self.config.definitions_dir)
            .field("outbox_dir", &self.config.outbox_dir)
            .finish()
    }
}

impl WindowsSandboxProvider {
    /// Build a provider.
    pub fn new(config: WindowsSandboxConfig) -> Arc<Self> {
        Arc::new(Self {
            config,
            plugin_id: PluginId::derive(&[crate::PLUGIN_ID]),
            host_id: ResourceId::derive(&["host", "local"]),
            sequences: RwLock::new(std::collections::BTreeMap::new()),
        })
    }

    /// Whether the definitions directory exists.
    ///
    /// A missing directory is a legitimate "no sandboxes configured" state, not
    /// an error, so it is reported rather than raised.
    pub async fn definitions_present(&self) -> bool {
        tokio::fs::try_exists(&self.config.definitions_dir)
            .await
            .unwrap_or(false)
    }

    /// List `.wsb` files in the managed definitions directory, sorted.
    pub async fn list_definition_files(&self) -> Vec<PathBuf> {
        let mut entries: Vec<PathBuf> =
            match tokio::fs::read_dir(&self.config.definitions_dir).await {
                Ok(mut rd) => {
                    let mut v = Vec::new();
                    while let Ok(Some(e)) = rd.next_entry().await {
                        let p = e.path();
                        if p.extension().and_then(|s| s.to_str()) == Some("wsb") {
                            v.push(p);
                        }
                    }
                    v
                }
                Err(_) => Vec::new(),
            };
        // CONTRACTS §6: deterministic order.
        entries.sort();
        entries
    }

    /// Load and validate one envelope from the outbox.
    ///
    /// The file name must be `<something>.json`; `.part` files are the probe's
    /// in-progress writes and are skipped rather than read (the protocol writes
    /// `<uuid>.part` then renames).
    pub async fn load_envelope(&self, path: &Path) -> Result<ProbeEnvelope, DomainError> {
        // NFR-S08: containment is re-checked at read time, not just when the
        // name was produced.
        if !is_within(&self.config.outbox_dir, path) {
            return Err(DomainError::new(
                ErrorCode::OBS_GUEST_PATH_ESCAPE,
                "outbox file path escapes the telemetry outbox",
            ));
        }
        let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if !name.ends_with(".json") {
            // A `.part` file is mid-write; the caller skips it silently.
            return Err(DomainError::new(
                ErrorCode::OBS_ENVELOPE_INVALID,
                format!("outbox entry {name:?} is not a completed envelope"),
            ));
        }
        let bytes = tokio::fs::read(path).await.map_err(|e| {
            DomainError::new(
                ErrorCode::OBS_ENVELOPE_INVALID,
                format!("outbox entry {name:?} could not be read"),
            )
            .with_detail(e.to_string())
        })?;
        parse_envelope(&bytes).map_err(map_envelope_error)
    }

    /// Validate an envelope and advance the sequence high-water mark.
    pub async fn accept_envelope(
        &self,
        sandbox: &str,
        env: &ProbeEnvelope,
        now_ms: u64,
    ) -> Result<(), DomainError> {
        let last = self.sequences.read().await.get(sandbox).copied();
        let binding = SessionBinding {
            expected_nonce: self.config.session_nonce.clone(),
            last_sequence: last,
        };
        let accepted = validate_envelope(env, &binding, now_ms, &self.config.limits)
            .map_err(map_envelope_error)?;
        self.sequences
            .write()
            .await
            .insert(sandbox.to_string(), accepted.0);
        Ok(())
    }
}

/// Map an [`EnvelopeError`] onto its stable `ST-OBS-*` code.
fn map_envelope_error(e: EnvelopeError) -> DomainError {
    use crate::envelope::EnvelopeError as E;
    let code = match &e {
        E::TooLarge { .. } | E::StructureTooLarge { .. } => ErrorCode::OBS_OUTPUT_TOO_LARGE,
        E::BadTimestamp(_) | E::TimestampSkew { .. } => ErrorCode::OBS_STALE,
        E::PathEscape(_) => ErrorCode::OBS_GUEST_PATH_ESCAPE,
        E::Malformed(_)
        | E::Schema(_)
        | E::NonceMismatch
        | E::SequenceNotIncreasing { .. }
        | E::HashMismatch => ErrorCode::OBS_ENVELOPE_INVALID,
    };
    DomainError::new(code, e.to_string())
}

#[async_trait::async_trait]
impl ResourceProvider for WindowsSandboxProvider {
    fn descriptor(&self) -> ProviderDescriptor {
        ProviderDescriptor {
            plugin_id: crate::PLUGIN_ID.to_string(),
            version: crate::PROVIDER_VERSION.to_string(),
            kind: PluginKind::Provider,
        }
    }

    async fn health(&self) -> Result<ProviderHealth, DomainError> {
        // NFR-A01: report state, never block the other providers.
        if !self.definitions_present().await {
            return Ok(ProviderHealth::Unavailable {
                reason: format!(
                    "definitions directory {} does not exist",
                    self.config.definitions_dir.display()
                ),
            });
        }
        Ok(ProviderHealth::Degraded {
            // DD-PLG §12.4: without a probe the sandbox exists but rich telemetry
            // does not. Saying so up front stops the UI from claiming otherwise.
            reason: "no probe session has reported telemetry yet".to_string(),
        })
    }

    async fn discover(&self, _cursor: Option<String>) -> Result<DiscoverBatch, DomainError> {
        if !self.definitions_present().await {
            // Not an error: "no sandboxes configured" is a state. Returning an
            // empty batch here would be the same as claiming every previously
            // discovered sandbox vanished (ADR-OBS-001), so the caller is told
            // explicitly instead.
            return Err(DomainError::new(
                ErrorCode::SANDBOX_PROVIDER_UNAVAILABLE,
                format!(
                    "definitions directory {} does not exist",
                    self.config.definitions_dir.display()
                ),
            ));
        }

        let outbox = self.config.outbox_dir.to_string_lossy().to_string();
        let now = now_rfc3339();
        let mut resources = Vec::new();
        for path in self.list_definition_files().await {
            let Some(name) = definition_name_from_path(&path) else {
                continue;
            };
            let bytes = match tokio::fs::read_to_string(&path).await {
                Ok(b) => b,
                Err(_) => {
                    tracing::warn!(path = %path.display(), "wsb definition could not be read");
                    continue;
                }
            };
            let def = match parse_wsb(&bytes, &outbox) {
                Ok(d) => d,
                Err(e @ WsbParseError::ForbiddenMapping { .. }) => {
                    // A definition that violates the isolation policy is
                    // refused loudly rather than loaded with the mapping
                    // stripped, because silently dropping it would leave the
                    // user believing the sandbox shares what it does not.
                    return Err(DomainError::new(
                        ErrorCode::SANDBOX_UNSUPPORTED,
                        format!("definition {name} requests a forbidden mapped folder"),
                    )
                    .with_detail(e.to_string()));
                }
                Err(e) => {
                    tracing::warn!(definition = %name, error = %e, "wsb definition could not be parsed");
                    continue;
                }
            };
            // RD §9: a `.wsb` is a recipe. The host-visible sandbox table is
            // what reports running state, and this provider has no such table on
            // a machine without an active sandbox, so the honest state is
            // `Unknown` — not `Running`.
            resources.push(normalize_definition(
                &name,
                &def,
                sandtree_model::resource::ResourceState::Unknown,
                &self.plugin_id,
                &self.host_id,
                &now,
            ));
        }

        resources.sort_by(|a, b| a.id.cmp(&b.id));
        let relations: Vec<Relation> = resources
            .iter()
            .map(|n| {
                Relation::new(
                    self.host_id.clone(),
                    n.id.clone(),
                    RelationKind::WorkspaceMount,
                )
            })
            .collect();

        Ok(DiscoverBatch {
            resources,
            relations,
            cursor: None,
        })
    }

    async fn inspect(&self, id: &ResourceId) -> Result<ResourceNode, DomainError> {
        let batch = self.discover(None).await?;
        batch
            .resources
            .into_iter()
            .find(|n| n.id == *id)
            .ok_or_else(|| {
                DomainError::new(
                    ErrorCode::CORE_INVALID,
                    format!("no windows sandbox definition has id {id}"),
                )
            })
    }

    async fn invoke(&self, req: &OperationRequest) -> Result<OperationOutcome, DomainError> {
        // NFR-U02: destructive operations need explicit confirmation.
        if req.op.is_destructive() {
            let confirmed = req
                .args
                .get("confirmed")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            if !confirmed {
                return Err(DomainError::new(
                    ErrorCode::CORE_INVALID,
                    format!(
                        "{} is destructive and requires confirmed=true",
                        req.op.as_str()
                    ),
                ));
            }
        }

        // Starting or stopping a Windows Sandbox is driven by the host product
        // (`WindowsSandbox.exe`), which this provider invokes through the
        // operation manager rather than reimplementing here. Refusing the
        // unsupported kinds keeps the surface honest.
        match req.op {
            OperationKind::Start | OperationKind::Stop | OperationKind::Destroy => {
                Err(DomainError::new(
                    ErrorCode::SANDBOX_UNSUPPORTED,
                    format!(
                        "windows sandbox lifecycle {} is not driven by this provider; \
                         it is delegated to the host sandbox product",
                        req.op.as_str()
                    ),
                ))
            }
            other => Err(DomainError::new(
                ErrorCode::SANDBOX_UNSUPPORTED,
                format!(
                    "{} is not supported by the windows sandbox provider",
                    other.as_str()
                ),
            )),
        }
    }

    async fn shutdown(&self) {
        // Forget the replay window; a new session starts from a fresh nonce.
        self.sequences.write().await.clear();
    }
}

#[async_trait::async_trait]
impl ObservationProvider for WindowsSandboxProvider {
    async fn capabilities(&self, _id: &ResourceId) -> Result<ObservationCapabilities, DomainError> {
        // DD-OBS §12.1: static, and independent of whether a probe is running.
        Ok(sandbox_capabilities(false))
    }

    async fn observe(&self, req: &ObservationRequest) -> Result<ObservationSnapshot, DomainError> {
        let now = now_rfc3339();
        let now_ms = chrono::Utc::now().timestamp().max(0) as u64 * 1000;

        // Consume completed envelopes, skipping in-progress `.part` writes.
        let sandbox = req.resource_id.as_str().to_string();
        let mut accepted: Vec<ProbeEnvelope> = Vec::new();
        for path in self.list_outbox_files().await {
            let env = match self.load_envelope(&path).await {
                Ok(e) => e,
                // A `.part` file is expected mid-write and is not an error.
                Err(e) if e.code == ErrorCode::OBS_ENVELOPE_INVALID => continue,
                Err(e) => return Err(e),
            };
            if self.accept_envelope(&sandbox, &env, now_ms).await.is_ok() {
                accepted.push(env);
            }
            if accepted.len() >= crate::observation::MAX_ENVELOPES_PER_SESSION {
                break;
            }
        }

        if accepted.is_empty() {
            // FR-079: the sandbox still exists; only telemetry is missing.
            return Ok(unavailable_snapshot(
                req.resource_id.clone(),
                "no valid probe envelope was available",
                now,
            ));
        }

        Ok(snapshot_from_envelopes(
            req.resource_id.clone(),
            &accepted,
            &req.domains,
            &now,
        ))
    }
}

impl WindowsSandboxProvider {
    /// Completed envelope files in the outbox, sorted; `.part` excluded.
    pub async fn list_outbox_files(&self) -> Vec<PathBuf> {
        let mut entries: Vec<PathBuf> = match tokio::fs::read_dir(&self.config.outbox_dir).await {
            Ok(mut rd) => {
                let mut v = Vec::new();
                while let Ok(Some(e)) = rd.next_entry().await {
                    let p = e.path();
                    if p.extension().and_then(|s| s.to_str()) == Some("json") {
                        v.push(p);
                    }
                }
                v
            }
            Err(_) => Vec::new(),
        };
        entries.sort();
        entries
    }

    /// The sandbox id for a definition name.
    pub fn sandbox_id_for(&self, name: &str) -> ResourceId {
        sandbox_id(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now_ms() -> u64 {
        chrono::Utc::now().timestamp().max(0) as u64 * 1000
    }

    fn provider() -> (Arc<WindowsSandboxProvider>, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let defs = tmp.path().join("defs");
        let outbox = tmp.path().join("probe-outbox");
        std::fs::create_dir_all(&defs).unwrap();
        std::fs::create_dir_all(&outbox).unwrap();
        let p = WindowsSandboxProvider::new(WindowsSandboxConfig::new(&defs, &outbox, "nonce-1"));
        (p, tmp)
    }

    /// A provider whose definitions/outbox directories were never created, so
    /// every directory read must degrade instead of failing the caller.
    fn provider_without_dirs() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    fn good_envelope(nonce: &str, sequence: u64) -> ProbeEnvelope {
        use std::collections::BTreeMap;
        let domains: BTreeMap<String, serde_json::Value> =
            [("system".to_string(), serde_json::json!({"os": "windows"}))]
                .into_iter()
                .collect();
        crate::envelope::ProbeEnvelope {
            schema: crate::envelope::ENVELOPE_SCHEMA.to_string(),
            sandbox_id: "res-demo".to_string(),
            nonce: nonce.to_string(),
            sequence,
            observed_at: chrono::Utc::now().to_rfc3339(),
            payload_hash: {
                // Hash the same canonical form the validator recomputes.
                let sorted: Vec<(&String, &serde_json::Value)> = domains.iter().collect();
                let encoded = serde_json::to_string(&sorted).unwrap();
                blake3::hash(encoded.as_bytes()).to_hex().to_string()
            },
            domains,
        }
    }

    #[test]
    fn debug_output_never_prints_the_session_nonce() {
        let tmp = tempfile::tempdir().unwrap();
        let p = WindowsSandboxProvider::new(WindowsSandboxConfig::new(
            tmp.path(),
            tmp.path(),
            "super-secret-nonce",
        ));
        assert!(!format!("{p:?}").contains("super-secret-nonce"));
    }

    #[tokio::test]
    async fn health_is_unavailable_when_definitions_are_absent() {
        let tmp = provider_without_dirs();
        let p = WindowsSandboxProvider::new(WindowsSandboxConfig::new(
            tmp.path().join("missing"),
            tmp.path().join("outbox"),
            "n1",
        ));
        let h = p.health().await.unwrap();
        assert_eq!(h.summary(), "unavailable");
        assert!(!h.control_is_available());
    }

    #[tokio::test]
    async fn health_is_degraded_before_any_probe_reports() {
        // DD-PLG §12.4: the sandbox is controllable even with no telemetry.
        let (p, _tmp) = provider();
        let h = p.health().await.unwrap();
        assert_eq!(h.summary(), "degraded");
        assert!(h.control_is_available());
    }

    #[tokio::test]
    async fn discover_reports_definitions_with_host_observed_state() {
        let (p, tmp) = provider();
        std::fs::write(
            tmp.path().join("defs").join("demo.wsb"),
            r#"<Configuration>
                 <Networking>Default</Networking>
                 <MappedFolder HostFolder="C:\ws" SandboxFolder="C:\ws" ReadOnly="true"/>
               </Configuration>"#,
        )
        .unwrap();
        let batch = p.discover(None).await.unwrap();
        assert_eq!(batch.resources.len(), 1);
        let n = &batch.resources[0];
        assert_eq!(n.name, "demo");
        assert_eq!(n.kind, sandtree_model::resource::ResourceKind::Sandbox);
        // A .wsb is a recipe, not a report: state must not be claimed Running.
        assert_eq!(n.state, sandtree_model::resource::ResourceState::Unknown);
        assert_eq!(n.meta_str("networking"), Some("Default"));
        assert_eq!(batch.relations.len(), 1);
    }

    #[tokio::test]
    async fn discover_fails_when_the_definitions_directory_is_missing() {
        let tmp = provider_without_dirs();
        let p = WindowsSandboxProvider::new(WindowsSandboxConfig::new(
            tmp.path().join("missing"),
            tmp.path().join("outbox"),
            "n1",
        ));
        // Not an empty batch: an empty batch would read as "all sandboxes gone".
        let err = p.discover(None).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::SANDBOX_PROVIDER_UNAVAILABLE);
    }

    #[tokio::test]
    async fn a_definition_with_a_forbidden_mapping_is_refused_loudly() {
        let (p, tmp) = provider();
        std::fs::write(
            tmp.path().join("defs").join("bad.wsb"),
            r#"<Configuration><MappedFolder HostFolder="/var/run/docker.sock" SandboxFolder="C:\d" ReadOnly="true"/></Configuration>"#,
        )
        .unwrap();
        let err = p.discover(None).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::SANDBOX_UNSUPPORTED);
    }

    #[tokio::test]
    async fn a_malformed_definition_is_skipped_not_fatal() {
        let (p, tmp) = provider();
        std::fs::write(tmp.path().join("defs").join("broken.wsb"), "<not-xml").unwrap();
        std::fs::write(
            tmp.path().join("defs").join("good.wsb"),
            "<Configuration><Networking>Default</Networking></Configuration>",
        )
        .unwrap();
        let batch = p.discover(None).await.unwrap();
        assert_eq!(batch.resources.len(), 1);
        assert_eq!(batch.resources[0].name, "good");
    }

    #[tokio::test]
    async fn lifecycle_is_delegated_and_refused_here() {
        let (p, _tmp) = provider();
        let req = OperationRequest::new(
            p.sandbox_id_for("demo"),
            OperationKind::Start,
            serde_json::json!({}),
            sandtree_model::resource::Correlation::generate(),
        );
        let err = p.invoke(&req).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::SANDBOX_UNSUPPORTED);
    }

    #[tokio::test]
    async fn destructive_lifecycle_requires_confirmation_first() {
        let (p, _tmp) = provider();
        let req = OperationRequest::new(
            p.sandbox_id_for("demo"),
            OperationKind::Destroy,
            serde_json::json!({}),
            sandtree_model::resource::Correlation::generate(),
        );
        let err = p.invoke(&req).await.unwrap_err();
        assert!(err.message.contains("confirmed"));
    }

    #[tokio::test]
    async fn capabilities_are_available_without_a_running_probe() {
        let (p, _tmp) = provider();
        let caps = p.capabilities(&ResourceId::derive(&["x"])).await.unwrap();
        assert!(caps.supports(sandtree_observation_model::ObservationMode::Probe));
    }

    #[tokio::test]
    async fn observe_degrades_when_no_envelope_is_present() {
        let (p, _tmp) = provider();
        let snap = p
            .observe(&ObservationRequest::new(
                ResourceId::derive(&["x"]),
                vec![sandtree_observation_model::ObservationDomain::System],
            ))
            .await
            .unwrap();
        assert_eq!(
            snap.health,
            sandtree_observation_model::ObservationHealth::Unavailable
        );
    }

    #[tokio::test]
    async fn observe_merges_a_valid_envelope_as_guest_probe() {
        let (p, tmp) = provider();
        let env = good_envelope("nonce-1", 1);
        std::fs::write(
            tmp.path().join("probe-outbox").join("a.json"),
            serde_json::to_vec(&env).unwrap(),
        )
        .unwrap();

        let snap = p
            .observe(&ObservationRequest::new(
                ResourceId::derive(&["res-demo"]),
                vec![sandtree_observation_model::ObservationDomain::System],
            ))
            .await
            .unwrap();
        assert_eq!(
            snap.health,
            sandtree_observation_model::ObservationHealth::Healthy
        );
        let v = snap
            .get(sandtree_observation_model::ObservationDomain::System)
            .unwrap();
        assert_eq!(
            v.provenance.trust,
            sandtree_observation_model::TrustLevel::GuestProbe
        );
        // Guest probe data must never satisfy a security precondition.
        assert!(!snap.is_security_authoritative());
    }

    #[tokio::test]
    async fn a_foreign_nonce_envelope_is_not_consumed() {
        let (p, tmp) = provider();
        let env = good_envelope("some-other-session", 1);
        std::fs::write(
            tmp.path().join("probe-outbox").join("a.json"),
            serde_json::to_vec(&env).unwrap(),
        )
        .unwrap();
        let snap = p
            .observe(&ObservationRequest::new(
                ResourceId::derive(&["res-demo"]),
                vec![],
            ))
            .await
            .unwrap();
        assert_eq!(
            snap.health,
            sandtree_observation_model::ObservationHealth::Unavailable
        );
    }

    #[tokio::test]
    async fn part_files_are_skipped_as_in_progress() {
        let (p, tmp) = provider();
        std::fs::write(
            tmp.path().join("probe-outbox").join("a.part"),
            b"{\"half\":",
        )
        .unwrap();
        assert!(p.list_outbox_files().await.is_empty());
    }

    #[tokio::test]
    async fn outbox_containment_is_enforced_on_read() {
        let (p, _tmp) = provider();
        let outside = std::env::temp_dir().join("sandtree-outside.json");
        std::fs::write(&outside, b"{}").unwrap();
        let err = p.load_envelope(&outside).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::OBS_GUEST_PATH_ESCAPE);
        let _ = std::fs::remove_file(&outside);
    }

    #[tokio::test]
    async fn envelope_validation_advances_the_replay_window() {
        let (p, _tmp) = provider();
        assert!(p
            .accept_envelope("s", &good_envelope("nonce-1", 5), now_ms())
            .await
            .is_ok());
        // Replaying sequence 5 is refused.
        assert!(p
            .accept_envelope("s", &good_envelope("nonce-1", 5), now_ms())
            .await
            .is_err());
        // A newer one is accepted.
        assert!(p
            .accept_envelope("s", &good_envelope("nonce-1", 6), now_ms())
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn shutdown_clears_the_replay_window_and_is_idempotent() {
        let (p, _tmp) = provider();
        p.accept_envelope("s", &good_envelope("nonce-1", 9), now_ms())
            .await
            .unwrap();
        p.shutdown().await;
        p.shutdown().await;
        // After a new session the same sequence is acceptable again.
        assert!(p
            .accept_envelope("s", &good_envelope("nonce-1", 1), now_ms())
            .await
            .is_ok());
    }
}
