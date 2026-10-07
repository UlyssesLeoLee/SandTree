//! SDK port implementation for Multipass (DD-PLG §9, §12.1).
//!
//! # Capability separation
//!
//! DD-PLG §12.1: one plugin may implement any combination of the four ports.
//! This crate implements [`ResourceProvider`], [`ObservationProvider`] and
//! [`ExecProvider`]. It deliberately does **not** implement [`FileProvider`]:
//! guest file access goes through `multipass transfer`, which is a copy
//! operation rather than a mountable VFS root, and claiming the port would let a
//! caller assume a stable `stfs://` tree that does not exist.

use std::sync::Arc;

use sandtree_model::capability::Capability;
use sandtree_model::error::{DomainError, ErrorCode};
use sandtree_model::id::{PluginId, ResourceId};
use sandtree_model::operation::{
    OperationKind, OperationOutcome, OperationRequest, OperationState,
};
use sandtree_model::resource::{Relation, RelationKind, ResourceKind, ResourceNode};
use sandtree_observation_model::{
    ObservationCapabilities, ObservationRequest, ObservationSnapshot,
};
use sandtree_sdk::manifest::{now_rfc3339, PluginKind};
use sandtree_sdk::ports::{
    DiscoverBatch, ExecOutcome, ExecProvider, ObservationProvider, ProviderDescriptor,
    ProviderHealth, ResourceProvider,
};
use tokio::sync::RwLock;
use tracing::warn;

use crate::cli::{
    bound_output, validate_instance_name, CliOutput, CliRunner, MultipassCli, MultipassError,
    EXEC_TIMEOUT_MS,
};
use crate::observation::{multipass_capabilities, snapshot_from_report, unavailable_snapshot};
use crate::parse::{
    collector_argv, exec_argv, instance_id, normalize_instance, parse_collector_output, parse_list,
    CollectorDomain,
};

/// Max captured stdout for a guest command, in characters.
const EXEC_OUTPUT_LIMIT: usize = 64 * 1024;

/// Cached availability probe result.
#[derive(Debug, Clone)]
struct Availability {
    /// Whether `multipass --version` succeeded.
    present: bool,
    /// Version string, when reported.
    version: Option<String>,
}

/// Multipass provider over the `multipass` CLI.
pub struct MultipassProvider {
    plugin_id: PluginId,
    host_id: ResourceId,
    cli: Arc<dyn CliRunner>,
    availability: RwLock<Option<Availability>>,
}

impl std::fmt::Debug for MultipassProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MultipassProvider")
            .field("plugin_id", &self.plugin_id)
            .finish()
    }
}

impl MultipassProvider {
    /// Build a provider driving the `multipass` binary on `PATH`.
    pub fn new() -> Arc<Self> {
        Self::with_runner(Arc::new(MultipassCli::default()))
    }

    /// Build a provider with an injected CLI runner.
    pub fn with_runner(cli: Arc<dyn CliRunner>) -> Arc<Self> {
        Arc::new(Self {
            plugin_id: PluginId::derive(&[crate::PLUGIN_ID]),
            host_id: ResourceId::derive(&["host", "local"]),
            cli,
            availability: RwLock::new(None),
        })
    }

    /// Run a CLI invocation and require success, mapping failures to domain errors.
    async fn run_ok(&self, argv: &[String]) -> Result<CliOutput, DomainError> {
        let out = self
            .cli
            .run(argv, EXEC_TIMEOUT_MS)
            .await_map_cli_error(argv)?;
        if out.code != 0 {
            let (stderr, truncated) = bound_output(&out.stderr, 4096);
            return Err(DomainError::new(
                ErrorCode::SANDBOX_PROVIDER_UNAVAILABLE,
                format!(
                    "multipass {} failed with exit code {}",
                    argv.join(" "),
                    out.code
                ),
            )
            .with_detail(if truncated {
                format!("{stderr} [truncated]")
            } else {
                stderr
            }));
        }
        Ok(out)
    }

    /// Probe whether the product is installed, caching the answer.
    async fn availability(&self) -> Availability {
        if let Some(a) = self.availability.read().await.as_ref() {
            return a.clone();
        }
        let probed = match self.cli.run(&MultipassCli::version_argv(), EXEC_TIMEOUT_MS) {
            Ok(out) if out.code == 0 => Availability {
                present: true,
                version: Some(out.stdout.trim().to_string()),
            },
            Ok(_) | Err(_) => Availability {
                present: false,
                version: None,
            },
        };
        let mut guard = self.availability.write().await;
        if guard.is_none() {
            *guard = Some(probed.clone());
        }
        guard.clone().unwrap_or(probed)
    }

    /// Require an installed product, else return the standard unavailable error.
    ///
    /// DD-PLG §9: a missing or incompatible install makes the plugin
    /// unhealthy/unavailable, never a hard user-facing failure.
    async fn require_product(&self) -> Result<(), DomainError> {
        if self.availability().await.present {
            Ok(())
        } else {
            Err(DomainError::new(
                ErrorCode::SANDBOX_PROVIDER_UNAVAILABLE,
                "multipass is not installed or not runnable on PATH",
            ))
        }
    }

    /// Recover an instance name from a resource id.
    ///
    /// Identity is derived from the name, so the reverse mapping is kept as a
    /// table populated during discovery. Lookups fall back to the discovery
    /// round that `inspect` triggers.
    async fn name_for(&self, id: &ResourceId) -> Option<String> {
        match self.list_instances().await {
            Ok(entries) => entries
                .into_iter()
                .find(|e| instance_id(&e.name) == *id)
                .map(|e| e.name),
            Err(_) => None,
        }
    }

    async fn list_instances(&self) -> Result<Vec<crate::parse::MultipassListEntry>, DomainError> {
        let argv = vec![
            "multipass".to_string(),
            "list".to_string(),
            "--format".to_string(),
            "json".to_string(),
        ];
        let out = self.run_ok(&argv).await?;
        parse_list(&out.stdout).map_err(|reason| {
            DomainError::new(
                ErrorCode::SANDBOX_PROVIDER_UNAVAILABLE,
                "multipass list output was not valid JSON",
            )
            .with_detail(reason)
        })
    }
}

/// Map a [`MultipassError`] onto a [`DomainError`].
trait MapCliError {
    fn await_map_cli_error(self, argv: &[String]) -> Result<CliOutput, DomainError>;
}

impl MapCliError for Result<CliOutput, MultipassError> {
    fn await_map_cli_error(self, argv: &[String]) -> Result<CliOutput, DomainError> {
        self.map_err(|e| {
            let (code, message) = if e.is_product_absent() {
                (
                    ErrorCode::SANDBOX_PROVIDER_UNAVAILABLE,
                    "multipass is not installed or not runnable on PATH".to_string(),
                )
            } else {
                (
                    ErrorCode::SANDBOX_PROVIDER_UNAVAILABLE,
                    format!("multipass {} could not be executed", argv.join(" ")),
                )
            };
            DomainError::new(code, message).with_detail(e.to_string())
        })
    }
}

#[async_trait::async_trait]
impl ResourceProvider for MultipassProvider {
    fn descriptor(&self) -> ProviderDescriptor {
        ProviderDescriptor {
            plugin_id: crate::PLUGIN_ID.to_string(),
            version: crate::PROVIDER_VERSION.to_string(),
            kind: PluginKind::Provider,
        }
    }

    async fn health(&self) -> Result<ProviderHealth, DomainError> {
        // NFR-A01: state is reported, not thrown.
        let a = self.availability().await;
        if !a.present {
            return Ok(ProviderHealth::Unavailable {
                reason: "multipass is not installed or not runnable on PATH".to_string(),
            });
        }
        // DD-PLG §9: a version is what makes an *incompatible* install
        // diagnosable, so its absence is reported rather than treated as fine.
        match a.version.as_deref().filter(|v| !v.is_empty()) {
            Some(_) => Ok(ProviderHealth::Healthy),
            None => Ok(ProviderHealth::Degraded {
                reason: "multipass did not report a version".to_string(),
            }),
        }
    }

    async fn discover(&self, _cursor: Option<String>) -> Result<DiscoverBatch, DomainError> {
        self.require_product().await?;
        let entries = self.list_instances().await?;
        let now = now_rfc3339();
        let mut resources: Vec<ResourceNode> = entries
            .iter()
            .map(|e| normalize_instance(e, &self.plugin_id, &self.host_id, &now))
            .collect();

        // CONTRACTS §6: deterministic order.
        resources.sort_by(|a, b| a.id.cmp(&b.id));

        // Instances are sandbox children of the local host.
        let relations: Vec<Relation> = resources
            .iter()
            .filter(|n| n.kind == ResourceKind::Sandbox)
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
        self.require_product().await?;
        let entries = self.list_instances().await?;
        let now = now_rfc3339();
        entries
            .iter()
            .find(|e| instance_id(&e.name) == *id)
            .map(|e| normalize_instance(e, &self.plugin_id, &self.host_id, &now))
            .ok_or_else(|| {
                DomainError::new(
                    ErrorCode::CORE_INVALID,
                    format!("no multipass instance has id {id}"),
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

        self.require_product().await?;
        let Some(name) = self.name_for(&req.resource_id).await else {
            return Err(DomainError::new(
                ErrorCode::CORE_INVALID,
                format!("no multipass instance has id {}", req.resource_id),
            ));
        };
        validate_instance_name(&name).map_err(|e| {
            DomainError::new(ErrorCode::CORE_INVALID, "instance name is not usable")
                .with_detail(e.to_string())
        })?;

        let argv = match req.op {
            OperationKind::Start => vec!["multipass", "start", &name],
            OperationKind::Stop => vec!["multipass", "stop", &name],
            OperationKind::Restart => vec!["multipass", "restart", &name],
            OperationKind::Destroy => vec!["multipass", "delete", &name],
            // NFR-U02 already gated destroy/remove; prune is refused outright.
            OperationKind::Prune | OperationKind::Remove => {
                return Err(DomainError::new(
                    ErrorCode::SANDBOX_UNSUPPORTED,
                    "bulk instance removal is not reachable through this provider",
                ))
            }
            other => {
                return Err(DomainError::new(
                    ErrorCode::SANDBOX_UNSUPPORTED,
                    format!(
                        "{} is not supported by the multipass provider",
                        other.as_str()
                    ),
                ))
            }
        };
        let argv: Vec<String> = argv.into_iter().map(str::to_string).collect();

        match self.run_ok(&argv).await {
            Ok(_) => Ok(OperationOutcome {
                state: OperationState::Succeeded,
                error_code: None,
                result: serde_json::json!({ "instance": name }),
            }),
            Err(e) => Ok(OperationOutcome {
                state: OperationState::Failed,
                error_code: Some(e.code),
                result: serde_json::json!({ "message": e.message }),
            }),
        }
    }

    async fn shutdown(&self) {
        // Nothing to release: each call is a short-lived process.
        *self.availability.write().await = None;
    }
}

#[async_trait::async_trait]
impl ObservationProvider for MultipassProvider {
    async fn capabilities(&self, _id: &ResourceId) -> Result<ObservationCapabilities, DomainError> {
        // DD-OBS §12.1: capability discovery is static and never requires the
        // product to be installed.
        Ok(multipass_capabilities())
    }

    async fn observe(&self, req: &ObservationRequest) -> Result<ObservationSnapshot, DomainError> {
        let now = now_rfc3339();
        let Some(name) = self.name_for(&req.resource_id).await else {
            return Ok(unavailable_snapshot(
                req.resource_id.clone(),
                "instance could not be resolved for observation",
                now,
            ));
        };
        if validate_instance_name(&name).is_err() {
            return Ok(unavailable_snapshot(
                req.resource_id.clone(),
                "instance name is not usable for exec",
                now,
            ));
        }

        let requested: Vec<CollectorDomain> = if req.domains.is_empty() {
            vec![CollectorDomain::System]
        } else {
            let mut d: Vec<CollectorDomain> = req
                .domains
                .iter()
                .filter_map(|d| CollectorDomain::from_wire(d.as_str()))
                .collect();
            d.sort();
            d.dedup();
            d
        };

        let argv = collector_argv(&name, &requested);
        let out = match self.cli.run(&argv, EXEC_TIMEOUT_MS) {
            Ok(o) if o.code == 0 => o,
            Ok(o) => {
                // DD-PLG §12.3: a failed command degrades the snapshot rather
                // than destroying the instance's record.
                warn!(exit = o.code, "multipass collector failed");
                return Ok(unavailable_snapshot(
                    req.resource_id.clone(),
                    format!("collector exited with code {}", o.code),
                    now,
                ));
            }
            Err(e) => {
                return Ok(unavailable_snapshot(
                    req.resource_id.clone(),
                    e.to_string(),
                    now,
                ))
            }
        };

        // Bound the payload before parsing (DD-SW §12.3).
        let (stdout, truncated) = bound_output(&out.stdout, crate::cli::MAX_CAPTURE_BYTES);
        let parsed = parse_collector_output(&stdout);
        let mut report = match parsed {
            Ok(r) => r,
            Err(reason) => {
                return Ok(unavailable_snapshot(
                    req.resource_id.clone(),
                    format!("collector output was not usable: {reason}"),
                    now,
                ))
            }
        };
        if truncated {
            report
                .errors
                .push("collector output was truncated at the capture limit".to_string());
            report.partial.push(requested[0].as_str().to_string());
        }

        Ok(snapshot_from_report(
            req.resource_id.clone(),
            &report,
            &requested,
            &now,
        ))
    }
}

#[async_trait::async_trait]
impl ExecProvider for MultipassProvider {
    async fn exec(
        &self,
        id: &ResourceId,
        argv: &[String],
        _timeout_ms: u64,
    ) -> Result<ExecOutcome, DomainError> {
        if argv.is_empty() {
            return Err(DomainError::new(
                ErrorCode::CORE_INVALID,
                "exec requires a non-empty argument vector",
            ));
        }
        self.require_product().await?;
        let Some(name) = self.name_for(id).await else {
            return Err(DomainError::new(
                ErrorCode::CORE_INVALID,
                format!("no multipass instance has id {id}"),
            ));
        };
        validate_instance_name(&name).map_err(|e| {
            DomainError::new(ErrorCode::CORE_INVALID, "instance name is not usable")
                .with_detail(e.to_string())
        })?;

        let full = exec_argv(&name, argv);
        let out = self
            .cli
            .run(&full, EXEC_TIMEOUT_MS)
            .await_map_cli_error(&full)?;
        let (stdout, t_out) = bound_output(&out.stdout, EXEC_OUTPUT_LIMIT);
        let (stderr, t_err) = bound_output(&out.stderr, EXEC_OUTPUT_LIMIT);
        Ok(ExecOutcome {
            exit_code: out.code,
            stdout,
            stderr,
            // FR-024: truncation is reported, never silently applied.
            truncated: t_out || t_err,
        })
    }
}

/// The `multipass` CLI does not expose a `suspend` verb name this provider
/// maps from; keep the mapping explicit so an unknown kind cannot be guessed.
///
/// FR-061 helper kept public so the capability table and this match can be
/// diffed by a reviewer.
pub fn supported_lifecycle_kinds() -> &'static [OperationKind] {
    &[
        OperationKind::Start,
        OperationKind::Stop,
        OperationKind::Restart,
        OperationKind::Destroy,
    ]
}

/// Capability name helper for the observation namespace, used in manifests.
pub fn observation_capability_names() -> Vec<String> {
    multipass_capabilities()
        .modes
        .iter()
        .map(|m| format!("observation:observe:{}", m.as_str()))
        .collect()
}

/// Kept so the capability vocabulary used by this provider is referenced from
/// one place (FR-051, NFR-S02).
pub fn declared_capabilities() -> Vec<Capability> {
    vec![
        Capability::global(
            sandtree_model::capability::CapabilityNamespace::Resource,
            "discover",
        ),
        Capability::global(
            sandtree_model::capability::CapabilityNamespace::Resource,
            "inspect",
        ),
        Capability::global(
            sandtree_model::capability::CapabilityNamespace::Resource,
            "start",
        ),
        Capability::global(
            sandtree_model::capability::CapabilityNamespace::Resource,
            "stop",
        ),
        Capability::global(
            sandtree_model::capability::CapabilityNamespace::Resource,
            "restart",
        ),
        Capability::global(
            sandtree_model::capability::CapabilityNamespace::Resource,
            "destroy",
        ),
        Capability::global(
            sandtree_model::capability::CapabilityNamespace::Exec,
            "spawn",
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::MultipassError;
    use sandtree_observation_model::{ObservationDomain, ObservationHealth};
    use serde_json::json;
    use std::sync::Mutex;

    /// Scriptable fake CLI so the provider can be tested without Multipass.
    #[derive(Default)]
    struct FakeCli {
        calls: Mutex<Vec<Vec<String>>>,
        version: Option<String>,
        list: String,
        list_code: i32,
        collector: String,
        collector_code: i32,
        exec_stdout: String,
        exec_code: i32,
    }

    impl FakeCli {
        fn absent() -> Arc<Self> {
            Arc::new(Self {
                version: None,
                list_code: 1,
                collector_code: 1,
                exec_code: 1,
                ..Default::default()
            })
        }

        fn with_instances() -> Arc<Self> {
            Arc::new(Self {
                version: Some("1.15.0".into()),
                list: r#"[
                    {"name":"primary","state":"Running","ipv4":["10.0.0.5"],"release":"22.04"},
                    {"name":"dev-box","state":"Stopped","release":"24.04"}
                ]"#
                .into(),
                collector: r#"{"domains":{"system":{"os":"ubuntu"}},"partial":[],"errors":[]}"#
                    .into(),
                exec_stdout: "hello\n".into(),
                ..Default::default()
            })
        }

        fn calls(&self) -> Vec<Vec<String>> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl CliRunner for FakeCli {
        fn run(&self, argv: &[String], _t: u64) -> Result<CliOutput, MultipassError> {
            self.calls.lock().unwrap().push(argv.to_vec());
            if argv.iter().any(|a| a == "--version") {
                return match &self.version {
                    Some(v) => Ok(CliOutput {
                        code: 0,
                        stdout: v.clone(),
                        stderr: String::new(),
                    }),
                    None => Err(MultipassError::NotInstalled("multipass".into())),
                };
            }
            if argv.contains(&"list".to_string()) {
                return Ok(CliOutput {
                    code: self.list_code,
                    stdout: self.list.clone(),
                    stderr: String::new(),
                });
            }
            if argv.iter().any(|a| a == "sandtree-collector") {
                return Ok(CliOutput {
                    code: self.collector_code,
                    stdout: self.collector.clone(),
                    stderr: String::new(),
                });
            }
            Ok(CliOutput {
                code: self.exec_code,
                stdout: self.exec_stdout.clone(),
                stderr: String::new(),
            })
        }
    }

    fn rid(name: &str) -> ResourceId {
        instance_id(name)
    }

    #[tokio::test]
    async fn health_is_unavailable_when_the_binary_is_absent() {
        // DD-PLG §9: a missing install makes the plugin unavailable, and that
        // is reported as state rather than raised as an error.
        let p = MultipassProvider::with_runner(FakeCli::absent());
        let h = p.health().await.unwrap();
        match h {
            ProviderHealth::Unavailable { ref reason } => assert!(reason.contains("not installed")),
            other => panic!("expected unavailable, got {other:?}"),
        }
        assert!(!h.control_is_available());
    }

    #[tokio::test]
    async fn health_is_healthy_when_the_binary_answers() {
        let p = MultipassProvider::with_runner(FakeCli::with_instances());
        assert_eq!(p.health().await.unwrap().summary(), "healthy");
    }

    #[tokio::test]
    async fn availability_is_probed_once_and_cached() {
        let fake = FakeCli::with_instances();
        let p = MultipassProvider::with_runner(fake.clone());
        p.health().await.unwrap();
        p.health().await.unwrap();
        let version_probes = fake
            .calls()
            .iter()
            .filter(|c| c.iter().any(|a| a == "--version"))
            .count();
        assert_eq!(version_probes, 1, "the version probe must be cached");
    }

    #[tokio::test]
    async fn discover_fails_instead_of_returning_an_empty_batch() {
        // ADR-OBS-001: an empty batch would read as "every instance vanished".
        let p = MultipassProvider::with_runner(FakeCli::absent());
        let err = p.discover(None).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::SANDBOX_PROVIDER_UNAVAILABLE);
    }

    #[tokio::test]
    async fn discover_normalizes_instances_deterministically() {
        let p = MultipassProvider::with_runner(FakeCli::with_instances());
        let batch = p.discover(None).await.unwrap();
        assert_eq!(batch.resources.len(), 2);
        let names: Vec<&str> = batch.resources.iter().map(|r| r.name.as_str()).collect();
        // Sorted by derived id, which is stable across runs.
        assert_eq!(names.len(), 2);
        let ids: Vec<&str> = batch.resources.iter().map(|r| r.id.as_str()).collect();
        let sorted = {
            let mut s = ids.clone();
            s.sort();
            s
        };
        assert_eq!(ids, sorted);
        assert!(ids.contains(&rid("primary").as_str()));
        assert!(ids.contains(&rid("dev-box").as_str()));
        // Instances hang off the local host.
        assert!(batch
            .relations
            .iter()
            .all(|r| r.kind == RelationKind::WorkspaceMount));
    }

    #[tokio::test]
    async fn inspect_resolves_by_resource_id() {
        let p = MultipassProvider::with_runner(FakeCli::with_instances());
        let node = p.inspect(&rid("primary")).await.unwrap();
        assert_eq!(node.name, "primary");
        assert_eq!(node.meta_str("release"), Some("22.04"));

        let missing = p.inspect(&rid("nope")).await.unwrap_err();
        assert_eq!(missing.code, ErrorCode::CORE_INVALID);
    }

    #[tokio::test]
    async fn destructive_operations_require_confirmation_before_any_cli_call() {
        let fake = FakeCli::with_instances();
        let p = MultipassProvider::with_runner(fake.clone());
        let req = OperationRequest::new(
            rid("primary"),
            OperationKind::Destroy,
            json!({}),
            sandtree_model::resource::Correlation::generate(),
        );
        let err = p.invoke(&req).await.unwrap_err();
        assert!(err.message.contains("confirmed"));
        // The confirmation gate fires before any process is spawned.
        assert!(fake
            .calls()
            .iter()
            .all(|c| !c.iter().any(|a| a == "delete")));
    }

    #[tokio::test]
    async fn confirmed_lifecycle_issues_the_expected_verb() {
        let fake = FakeCli::with_instances();
        let p = MultipassProvider::with_runner(fake.clone());
        let req = OperationRequest::new(
            rid("primary"),
            OperationKind::Stop,
            json!({ "confirmed": true }),
            sandtree_model::resource::Correlation::generate(),
        );
        let out = p.invoke(&req).await.unwrap();
        assert_eq!(out.state, OperationState::Succeeded);
        let calls = fake.calls();
        assert!(calls
            .iter()
            .any(|c| c == &vec!["multipass".to_string(), "stop".into(), "primary".into()]));
    }

    #[tokio::test]
    async fn unsupported_operation_is_refused() {
        let p = MultipassProvider::with_runner(FakeCli::with_instances());
        let req = OperationRequest::new(
            rid("primary"),
            OperationKind::Pull,
            json!({}),
            sandtree_model::resource::Correlation::generate(),
        );
        let err = p.invoke(&req).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::SANDBOX_UNSUPPORTED);
    }

    #[tokio::test]
    async fn capabilities_are_available_without_the_product() {
        let p = MultipassProvider::with_runner(FakeCli::absent());
        let caps = p.capabilities(&rid("primary")).await.unwrap();
        assert!(caps.supports(sandtree_observation_model::ObservationMode::Exec));
    }

    #[tokio::test]
    async fn observe_degrades_when_the_product_is_absent() {
        // FR-079: unavailable observation is a state, not an error.
        let p = MultipassProvider::with_runner(FakeCli::absent());
        let snap = p
            .observe(&ObservationRequest::new(
                rid("primary"),
                vec![ObservationDomain::System],
            ))
            .await
            .unwrap();
        assert_eq!(snap.health, ObservationHealth::Unavailable);
        assert!(snap.get(ObservationDomain::System).is_none());
        assert!(!snap.warnings.is_empty());
        // Remote-exec data must never be security authoritative.
        assert!(!snap.is_security_authoritative());
    }

    #[tokio::test]
    async fn observe_collects_the_system_domain_via_exec() {
        let p = MultipassProvider::with_runner(FakeCli::with_instances());
        let snap = p
            .observe(&ObservationRequest::new(
                rid("primary"),
                vec![ObservationDomain::System],
            ))
            .await
            .unwrap();
        assert_eq!(snap.health, ObservationHealth::Healthy);
        let v = snap.get(ObservationDomain::System).unwrap();
        assert_eq!(v.value["os"], "ubuntu");
        assert_eq!(
            v.provenance.trust,
            sandtree_observation_model::TrustLevel::RemoteExec
        );
    }

    #[tokio::test]
    async fn observe_degrades_when_the_collector_exits_non_zero() {
        let fake = Arc::new(FakeCli {
            version: Some("1.15.0".into()),
            list: r#"[{"name":"primary","state":"Running"}]"#.into(),
            collector_code: 3,
            ..Default::default()
        });
        let p = MultipassProvider::with_runner(fake);
        let snap = p
            .observe(&ObservationRequest::new(
                rid("primary"),
                vec![ObservationDomain::System],
            ))
            .await
            .unwrap();
        assert_eq!(snap.health, ObservationHealth::Unavailable);
        assert!(snap
            .warnings
            .iter()
            .any(|w| w.contains("exited with code 3")));
    }

    #[tokio::test]
    async fn exec_passes_argv_verbatim_and_reports_the_exit_code() {
        let fake = FakeCli::with_instances();
        let p = MultipassProvider::with_runner(fake.clone());
        let out = p
            .exec(&rid("primary"), &["echo".into(), "hi there".into()], 1000)
            .await
            .unwrap();
        assert_eq!(out.exit_code, 0);
        assert_eq!(out.stdout, "hello\n");
        assert!(!out.truncated);

        let calls = fake.calls();
        assert!(calls.iter().any(|c| c
            == &vec![
                "multipass".to_string(),
                "exec".into(),
                "primary".into(),
                "--".into(),
                "echo".into(),
                "hi there".into()
            ]));
    }

    #[tokio::test]
    async fn exec_rejects_an_empty_argv() {
        let p = MultipassProvider::with_runner(FakeCli::with_instances());
        let err = p.exec(&rid("primary"), &[], 1000).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::CORE_INVALID);
    }

    #[tokio::test]
    async fn exec_fails_cleanly_when_the_product_is_absent() {
        let p = MultipassProvider::with_runner(FakeCli::absent());
        let err = p
            .exec(&rid("primary"), &["ls".into()], 1000)
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::SANDBOX_PROVIDER_UNAVAILABLE);
    }

    #[tokio::test]
    async fn shutdown_is_idempotent() {
        let p = MultipassProvider::with_runner(FakeCli::with_instances());
        p.shutdown().await;
        p.shutdown().await;
        assert!(p.health().await.is_ok());
    }

    #[test]
    fn declared_capabilities_are_deny_by_default_shaped() {
        // NFR-S02: the provider declares what it may do; the host grants a subset.
        let caps = declared_capabilities();
        assert!(!caps.is_empty());
        assert!(caps.iter().any(|c| c.to_string() == "exec:spawn"));
    }

    #[test]
    fn lifecycle_verbs_match_the_cli_mapping() {
        let kinds = supported_lifecycle_kinds();
        let names: Vec<&str> = kinds.iter().map(|k| k.as_str()).collect();
        assert_eq!(names, vec!["start", "stop", "restart", "destroy"]);
    }
}
