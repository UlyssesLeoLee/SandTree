//! Operation dispatch: capability enforcement, destructive-op confirmation and
//! audit (FR-023, FR-027, FR-051, NFR-S03, NFR-O01).
//!
//! Two rules decide whether an operation runs at all, and both are enforced here
//! rather than in the UI or in the provider:
//!
//! 1. the plugin must hold the capability the operation needs, scoped to the
//!    target resource (deny-by-default, FR-051), and
//! 2. an operation the design marks as requiring confirmation is refused before
//!    dispatch unless the request carries `force: true` (invariant 11).
//!
//! The job row is written *before* dispatch so a daemon crash mid-operation is
//! reconcilable at the next boot (NFR-P01).

use std::sync::Arc;

use sandtree_event::EventRouter;
use sandtree_model::capability::{Capability, CapabilityNamespace, CapabilitySet};
use sandtree_model::error::{DomainError, ErrorCode};
use sandtree_model::event::{EventRecord, EventType};
use sandtree_model::operation::{
    OperationId, OperationKind, OperationOutcome, OperationRequest, OperationState,
};
use sandtree_model::resource::Correlation;
use sandtree_policy::audit::AuditRecord;
use sandtree_policy::engine::{GrantContext, PolicyEngine};
use sandtree_sdk::ports::ProviderRegistry;
use sandtree_store::db::Store;
use serde_json::Value as Json;

/// Build an `OperationProgress` event (NFR-O01: correlation + result + stage).
fn progress_event(job: &OperationId, correlation: &Correlation, stage: &str) -> EventRecord {
    EventRecord::new(
        EventType::OperationProgress,
        correlation.clone(),
        serde_json::json!({"operation_id": job.as_str(), "stage": stage}),
    )
}

/// Owns operation lifecycle.
pub struct OperationManager {
    store: Arc<Store>,
    events: Arc<EventRouter>,
    /// Grants change as plugins install, are revoked, and are hot-swapped, so
    /// the engine sits behind a lock rather than being frozen at bootstrap.
    /// A *missing* entry is always a denial, so an empty engine is safe.
    policy: tokio::sync::RwLock<PolicyEngine>,
}

impl OperationManager {
    /// Build a manager over an open store.
    pub fn new(store: Arc<Store>, events: Arc<EventRouter>, policy: PolicyEngine) -> Self {
        Self {
            store,
            events,
            policy: tokio::sync::RwLock::new(policy),
        }
    }

    /// Declare what a plugin says it can do (FR-050: declared maximum).
    pub async fn set_declared(&self, plugin: sandtree_model::id::PluginId, caps: CapabilitySet) {
        self.policy.write().await.set_declared(plugin, caps);
    }

    /// Grant one capability to a plugin (FR-051: still deny-by-default).
    pub async fn allow(&self, plugin: sandtree_model::id::PluginId, cap: Capability) {
        self.policy.write().await.allow(plugin, cap);
    }

    /// Revoke one capability.
    pub async fn revoke(&self, plugin: &sandtree_model::id::PluginId, cap: &Capability) {
        self.policy.write().await.revoke(plugin, cap);
    }

    /// Every current grant, for diagnostics and tests.
    pub async fn grants(&self) -> Vec<(sandtree_model::id::PluginId, Capability, bool)> {
        self.policy
            .read()
            .await
            .dump()
            .into_iter()
            .map(|(p, c, d)| (p, c, d.is_allowed()))
            .collect()
    }

    /// The capability an operation requires.
    ///
    /// Lifecycle verbs map onto the `resource` namespace; everything else
    /// (pull, build, logs, stats, read, write, …) maps onto its own verb, so a
    /// grant can be as narrow as `resource:destroy` on one sandbox.
    fn required_capability(op: OperationKind) -> Capability {
        let verb = match op {
            OperationKind::Start => "start",
            OperationKind::Stop => "stop",
            OperationKind::Restart => "restart",
            OperationKind::Destroy => "destroy",
            OperationKind::Pause => "pause",
            OperationKind::Unpause => "unpause",
            OperationKind::Exec => "exec",
            OperationKind::Pull => "pull",
            OperationKind::Build => "build",
            OperationKind::Tag => "tag",
            OperationKind::Remove => "remove",
            OperationKind::Prune => "prune",
            OperationKind::Create => "create",
            OperationKind::Observe => "observe",
            OperationKind::Logs => "logs",
            OperationKind::Stats => "stats",
            OperationKind::Read => "read",
            OperationKind::Write => "write",
            OperationKind::Snapshot => "snapshot",
            OperationKind::Diff => "diff",
            OperationKind::Refresh => "refresh",
            OperationKind::Reconnect => "reconnect",
        };
        Capability::global(CapabilityNamespace::Resource, verb)
    }

    /// Whether the request carries an explicit confirmation.
    fn is_forced(req: &OperationRequest) -> bool {
        req.args
            .get("force")
            .and_then(Json::as_bool)
            .unwrap_or(false)
    }

    /// Decide whether an operation may proceed, without running it.
    pub async fn precheck(
        &self,
        req: &OperationRequest,
        registry: &ProviderRegistry,
    ) -> Result<(), DomainError> {
        // Confirmation comes first: refusing a destructive call is the whole
        // point, and it must not depend on the store being reachable.
        if req.op.defaults_to_non_forced() && !Self::is_forced(req) {
            return Err(DomainError::new(
                ErrorCode::POLICY_DENIED,
                format!(
                    "{} is destructive and requires an explicit `force: true` confirmation",
                    req.op.as_str()
                ),
            ));
        }

        let node = self.store.resource(&req.resource_id)?.ok_or_else(|| {
            DomainError::new(
                ErrorCode::CORE_INVALID,
                format!("no such resource: {}", req.resource_id),
            )
        })?;

        let provider_id = node.provider_id.clone();
        let Some(instance) = registry.get(&provider_id) else {
            return Err(DomainError::new(
                ErrorCode::CORE_INVALID,
                format!("no provider instance registered for {provider_id}"),
            ));
        };
        if instance.resource.is_none() {
            return Err(DomainError::new(
                ErrorCode::POLICY_DENIED,
                format!("provider {provider_id} does not implement the resource port"),
            ));
        }

        let required = Self::required_capability(req.op);

        // Host grant, scoped to the exact resource.
        let ctx = GrantContext::plugin(provider_id.clone()).with_resource(req.resource_id.clone());
        self.policy.read().await.require(&ctx, &required)?;

        // The resource's own declared capability set is a second ceiling: a
        // caller cannot widen what the provider said the resource supports
        // (FR-061), even with a broad host grant.
        if !node.capabilities.is_empty() && !node.capabilities.allows(&required) {
            return Err(DomainError::new(
                ErrorCode::POLICY_DENIED,
                format!(
                    "resource {} does not declare the {} capability",
                    req.resource_id, required
                ),
            ));
        }

        Ok(())
    }

    /// Run an operation end to end.
    pub async fn invoke(
        &self,
        req: OperationRequest,
        registry: &ProviderRegistry,
    ) -> Result<OperationOutcome, DomainError> {
        self.precheck(&req, registry).await?;

        let node = self
            .store
            .resource(&req.resource_id)?
            .expect("precheck verified the resource exists");
        let provider_id = node.provider_id.clone();
        let provider = registry
            .get(&provider_id)
            .and_then(|i| i.resource.clone())
            .expect("precheck verified the provider is present");

        let job = OperationId::generate();
        let started = sandtree_policy::audit::now_ms();

        self.store.insert_operation(&job, &req)?;
        self.events
            .publish(progress_event(&job, &req.correlation_id, "started"));

        let outcome = match provider.invoke(&req).await {
            Ok(o) => {
                self.store
                    .transition_operation(&job, o.state, o.error_code, &o.result)?;
                o
            }
            Err(e) => {
                self.store.transition_operation(
                    &job,
                    OperationState::Failed,
                    Some(e.code),
                    &serde_json::json!({"message": e.message}),
                )?;
                self.audit(
                    &req,
                    &provider_id,
                    node.kind,
                    false,
                    started,
                    e.code.as_str(),
                );
                self.events
                    .publish(progress_event(&job, &req.correlation_id, "failed"));
                return Err(e);
            }
        };

        let ok = outcome.state != OperationState::Failed;
        let detail = outcome
            .error_code
            .map(|c| c.as_str().to_string())
            .unwrap_or_else(|| outcome.state.as_str().to_string());
        self.audit(&req, &provider_id, node.kind, ok, started, &detail);
        self.events
            .publish(progress_event(&job, &req.correlation_id, "completed"));
        Ok(outcome)
    }

    /// Write the audit event. Privileged operations are always audited
    /// (NFR-S03); the record is redacted by the policy crate before it is built.
    fn audit(
        &self,
        req: &OperationRequest,
        provider_id: &sandtree_model::id::PluginId,
        kind: sandtree_model::resource::ResourceKind,
        success: bool,
        started_ms: u64,
        detail: &str,
    ) {
        // The audit action must be namespaced `<kind>.<verb>` (NFR-S03).
        // `AuditRecord::is_privileged()` keys off that namespace, and a bare verb
        // like "destroy" is never privileged by that definition -- so recording
        // the bare verb silently marked every destructive action unprivileged.
        let action = format!("{}.{}", kind.as_str(), req.op.as_str());

        let record = if success {
            AuditRecord::success(
                provider_id.as_str(),
                action.clone(),
                req.resource_id.clone(),
                req.correlation_id.clone(),
                &req.args,
            )
        } else {
            AuditRecord::failure(
                provider_id.as_str(),
                action.clone(),
                req.resource_id.clone(),
                req.correlation_id.clone(),
                &req.args,
                ErrorCode::parse(detail).unwrap_or(ErrorCode::CORE_INVALID),
            )
        };
        self.events.publish(sandtree_event::audit_recorded(
            req.correlation_id.clone(),
            serde_json::json!({
                // The namespaced action, matching the record itself, so the
                // event and the audit record cannot disagree about what ran.
                "action": action,
                "resource_id": req.resource_id.as_str(),
                "provider_id": provider_id.as_str(),
                "privileged": record.is_privileged(),
                "duration_ms": sandtree_policy::audit::now_ms().saturating_sub(started_ms),
                "result": if success { "succeeded" } else { "failed" },
                "detail": detail,
            }),
        ));
    }

    /// Correlation id for a fresh operation.
    pub fn correlation_for() -> Correlation {
        Correlation::generate()
    }
}
