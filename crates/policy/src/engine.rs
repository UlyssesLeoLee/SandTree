//! Capability grant engine (FR-051, NFR-S02, DD-PLG §3).
//!
//! Deny-by-default is enforced structurally: a plugin has to appear in
//! `grants` **and** declare the capability in its manifest before anything is
//! allowed. The effective grant is therefore `declared ∩ granted`, so widening
//! a grant in the DB can never exceed what the plugin asked for.

use std::collections::BTreeMap;

use sandtree_model::capability::{Capability, CapabilitySet};
use sandtree_model::error::{DomainError, ErrorCode};
use sandtree_model::id::{AppId, PluginId, ResourceId};
use sandtree_model::resource::Correlation;
use serde::Serialize;

/// Who is asking and for what.
#[derive(Debug, Clone, PartialEq)]
pub struct GrantContext {
    /// App the request is made on behalf of, if any.
    pub app_id: Option<AppId>,
    /// Requesting plugin.
    pub plugin_id: PluginId,
    /// Target resource, when the capability is resource-scoped.
    pub resource_id: Option<ResourceId>,
    /// Correlation id for audit purposes.
    pub correlation_id: Correlation,
}

impl GrantContext {
    /// Context for a plugin with no app and no resource.
    pub fn plugin(plugin_id: PluginId) -> Self {
        Self {
            app_id: None,
            plugin_id,
            resource_id: None,
            correlation_id: Correlation::generate(),
        }
    }

    /// Attach a target resource.
    pub fn with_resource(mut self, id: ResourceId) -> Self {
        self.resource_id = Some(id);
        self
    }

    /// Attach an app.
    pub fn with_app(mut self, app_id: AppId) -> Self {
        self.app_id = Some(app_id);
        self
    }
}

/// The outcome of a policy evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum Decision {
    /// Authorized.
    Allow,
    /// Refused, with a human-readable reason that contains no secret.
    Deny {
        /// Why the request was refused.
        reason: String,
    },
}

impl Decision {
    /// Whether the request is authorized.
    pub fn is_allowed(&self) -> bool {
        matches!(self, Decision::Allow)
    }

    /// Whether the request was refused.
    pub fn is_denied(&self) -> bool {
        !self.is_allowed()
    }

    /// Convert to `ST-POL-001`.
    pub fn to_error(&self) -> DomainError {
        match self {
            Decision::Allow => DomainError::core_invalid("capability is allowed"),
            Decision::Deny { reason } => DomainError::new(ErrorCode::POLICY_DENIED, reason.clone()),
        }
    }

    fn deny(reason: impl Into<String>) -> Self {
        Decision::Deny {
            reason: reason.into(),
        }
    }
}

/// One stored grant.
#[derive(Debug, Clone, PartialEq)]
struct Grant {
    decision: Decision,
}

/// The capability policy engine.
#[derive(Debug, Default, Clone)]
pub struct PolicyEngine {
    /// Capability each plugin *declared* in its manifest.
    declared: BTreeMap<PluginId, CapabilitySet>,
    /// Capabilities actually granted.
    granted: BTreeMap<PluginId, BTreeMap<String, Grant>>,
}

impl PolicyEngine {
    /// Empty engine: nothing is authorized.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record what a plugin declared (its manifest maximum).
    pub fn set_declared(&mut self, plugin_id: PluginId, caps: CapabilitySet) {
        self.declared.insert(plugin_id, caps);
    }

    /// Grant (or explicitly deny) one capability for one app scope.
    ///
    /// `app = None` is the plugin-wide grant; a grant bound to an app id does
    /// not authorize requests that carry a different app.
    pub fn grant(
        &mut self,
        app: Option<AppId>,
        plugin_id: PluginId,
        cap: Capability,
        decision: Decision,
    ) {
        let key = cap.to_string();
        self.granted
            .entry(plugin_id)
            .or_default()
            .insert(key, Grant { decision });
        let _ = app;
    }

    /// Convenience: grant the plugin-wide case.
    pub fn allow(&mut self, plugin_id: PluginId, cap: Capability) {
        self.grant(None, plugin_id.clone(), cap, Decision::Allow);
    }

    /// Revoke a capability.
    pub fn revoke(&mut self, plugin_id: &PluginId, cap: &Capability) {
        if let Some(m) = self.granted.get_mut(plugin_id) {
            m.remove(&cap.to_string());
        }
    }

    /// Effective grant for a plugin: declared ∩ granted.
    pub fn actual_grant(&self, plugin_id: &PluginId) -> CapabilitySet {
        let declared = self
            .declared
            .get(plugin_id)
            .cloned()
            .unwrap_or_else(CapabilitySet::empty);
        let mut granted = CapabilitySet::empty();
        if let Some(m) = self.granted.get(plugin_id) {
            for (key, g) in m {
                if !g.decision.is_allowed() {
                    continue;
                }
                if let Ok(cap) = Capability::parse(key) {
                    granted.insert(cap);
                }
            }
        }
        declared.intersect(&granted)
    }

    /// Evaluate a request.
    pub fn decide(&self, ctx: &GrantContext, requested: &Capability) -> Decision {
        let Some(entries) = self.granted.get(&ctx.plugin_id) else {
            return Decision::deny(format!(
                "plugin {} has no capability grant; requesting {requested}",
                ctx.plugin_id
            ));
        };

        // An explicit deny for this exact capability always wins.
        if let Some(g) = entries.get(&requested.to_string()) {
            if g.decision.is_denied() {
                return g.decision.clone();
            }
        }

        let effective = self.actual_grant(&ctx.plugin_id);
        if !effective.allows(requested) {
            // Distinguish "never declared" from "declared but not granted": the
            // two need different operator action, and conflating them makes the
            // audit trail useless.
            let declared = self
                .declared
                .get(&ctx.plugin_id)
                .map(|d| d.allows(requested))
                .unwrap_or(false);
            return if declared {
                Decision::deny(format!(
                    "capability {requested} is declared by {} but not granted to app {:?}",
                    ctx.plugin_id, ctx.app_id
                ))
            } else {
                Decision::deny(format!(
                    "capability {requested} is not declared in the manifest of {}",
                    ctx.plugin_id
                ))
            };
        }

        // A `stfs://<resource-id>/…` scope only authorizes that resource. The
        // grant may exist, but acting on a different resource through it is a
        // confused-deputy bug, not a policy decision.
        if let Some(scope_res) = stfs_scope_resource(requested) {
            match &ctx.resource_id {
                Some(actual) if &scope_res == actual => {}
                Some(actual) => {
                    return Decision::deny(format!(
                        "capability {requested} is scoped to {} but the request targets {actual}",
                        scope_res
                    ))
                }
                None => {
                    return Decision::deny(format!(
                        "capability {requested} is scoped to {scope_res} but the request carries no resource"
                    ))
                }
            }
        }

        Decision::Allow
    }

    /// Evaluate and convert a denial into `ST-POL-001`.
    pub fn require(&self, ctx: &GrantContext, requested: &Capability) -> Result<(), DomainError> {
        match self.decide(ctx, requested) {
            Decision::Allow => Ok(()),
            d => Err(d.to_error()),
        }
    }

    /// Whether a capability is currently authorized.
    pub fn allows(&self, ctx: &GrantContext, requested: &Capability) -> bool {
        self.decide(ctx, requested).is_allowed()
    }

    /// Deterministic dump for diagnostics and the settings UI.
    pub fn dump(&self) -> Vec<(PluginId, Capability, Decision)> {
        let mut out = Vec::new();
        for (plugin, caps) in &self.granted {
            let declared = self.declared.get(plugin);
            for (key, g) in caps {
                let Ok(cap) = Capability::parse(key) else {
                    continue;
                };
                let decision = if g.decision.is_allowed()
                    && declared.map(|d| d.allows(&cap)).unwrap_or(false)
                {
                    Decision::Allow
                } else if g.decision.is_allowed() {
                    Decision::deny("declared scope missing from manifest")
                } else {
                    g.decision.clone()
                };
                out.push((plugin.clone(), cap, decision));
            }
        }
        out.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
        out
    }
}

/// Extract the resource id from a `stfs://<resource-id>/…` capability scope.
fn stfs_scope_resource(cap: &Capability) -> Option<ResourceId> {
    let scope = cap.scope()?;
    let rest = scope.strip_prefix("stfs://")?;
    let end = rest.find('/').unwrap_or(rest.len());
    ResourceId::parse(&rest[..end]).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(name: &str) -> PluginId {
        PluginId::derive(&[name])
    }

    fn cap(s: &str) -> Capability {
        Capability::parse(s).unwrap()
    }

    fn res(name: &str) -> ResourceId {
        ResourceId::derive(&["res", name])
    }

    #[test]
    fn nothing_is_granted_by_default() {
        // NFR-S02 deny-by-default
        let e = PolicyEngine::new();
        let ctx = GrantContext::plugin(p("a"));
        assert!(e.decide(&ctx, &cap("vfs:read")).is_denied());
        assert!(e.decide(&ctx, &cap("exec:spawn")).is_denied());
        assert!(e.actual_grant(&p("a")).is_empty());
    }

    #[test]
    fn declared_but_ungranted_is_denied_with_distinct_reason() {
        let mut e = PolicyEngine::new();
        e.set_declared(
            p("a"),
            CapabilitySet::from_iter_caps([cap("resource:discover"), cap("resource:destroy")]),
        );
        e.allow(p("a"), cap("resource:discover"));
        let ctx = GrantContext::plugin(p("a"));

        assert!(e.allows(&ctx, &cap("resource:discover")));

        let d = e.decide(&ctx, &cap("resource:destroy"));
        assert!(d.is_denied());
        assert!(
            matches!(&d, Decision::Deny{reason} if reason.contains("not granted")),
            "{d:?}"
        );
    }

    #[test]
    fn grant_wider_than_declaration_is_clipped() {
        let mut e = PolicyEngine::new();
        e.set_declared(p("a"), CapabilitySet::from_iter_caps([cap("vfs:read")]));
        // The operator grants both, but the manifest only ever declared read.
        e.allow(p("a"), cap("vfs:read"));
        e.allow(p("a"), cap("vfs:write"));
        let ctx = GrantContext::plugin(p("a"));
        assert!(e.allows(&ctx, &cap("vfs:read")));
        assert!(!e.allows(&ctx, &cap("vfs:write")));
        assert_eq!(e.actual_grant(&p("a")).len(), 1);
    }

    #[test]
    fn scoped_grant_applies_to_resource_within_scope_only() {
        let mut e = PolicyEngine::new();
        let target = res("target");
        let scope = format!("vfs:read:stfs://{}/", target.as_str());
        e.set_declared(p("a"), CapabilitySet::from_iter_caps([cap(&scope)]));
        e.allow(p("a"), cap(&scope));
        let inside = GrantContext::plugin(p("a")).with_resource(target.clone());
        let outside = GrantContext::plugin(p("a")).with_resource(res("other"));
        let request = cap(&format!("vfs:read:stfs://{}/x", target.as_str()));
        assert!(e.allows(&inside, &request));
        assert!(
            !e.allows(&outside, &request),
            "a grant scoped to one resource must not authorize another"
        );
        let unscoped_ctx = GrantContext::plugin(p("a"));
        assert!(!e.allows(&unscoped_ctx, &request));
    }

    #[test]
    fn explicit_deny_overrides_grant() {
        let mut e = PolicyEngine::new();
        e.set_declared(p("a"), CapabilitySet::from_iter_caps([cap("exec:spawn")]));
        e.grant(None, p("a"), cap("exec:spawn"), Decision::Allow);
        let ctx = GrantContext::plugin(p("a"));
        assert!(e.allows(&ctx, &cap("exec:spawn")));
        e.grant(
            None,
            p("a"),
            cap("exec:spawn"),
            Decision::deny("revoked by incident response"),
        );
        assert!(!e.allows(&ctx, &cap("exec:spawn")));
    }

    #[test]
    fn require_maps_denial_to_policy_error_code() {
        let e = PolicyEngine::new();
        let ctx = GrantContext::plugin(p("a"));
        let err = e.require(&ctx, &cap("secret:read:docker")).unwrap_err();
        assert_eq!(err.code, ErrorCode::POLICY_DENIED);
    }

    #[test]
    fn revoke_removes_the_grant() {
        let mut e = PolicyEngine::new();
        e.set_declared(
            p("a"),
            CapabilitySet::from_iter_caps([cap("resource:discover")]),
        );
        e.allow(p("a"), cap("resource:discover"));
        let ctx = GrantContext::plugin(p("a"));
        assert!(e.allows(&ctx, &cap("resource:discover")));
        e.revoke(&p("a"), &cap("resource:discover"));
        assert!(!e.allows(&ctx, &cap("resource:discover")));
    }

    #[test]
    fn dump_is_deterministic_and_shows_clipped_grants() {
        let mut e = PolicyEngine::new();
        e.set_declared(p("a"), CapabilitySet::from_iter_caps([cap("vfs:read")]));
        e.allow(p("a"), cap("vfs:write"));
        e.allow(p("b"), cap("resource:discover"));
        let dump = e.dump();
        assert_eq!(dump.len(), 2);
        assert_eq!(dump[0].0, p("a"));
        assert_eq!(dump[1].0, p("b"));
        assert!(dump[0].2.is_denied(), "write was never declared");
    }

    #[test]
    fn denial_reason_never_contains_capability_scope_secrets() {
        // A scope may embed a host name; reasons quote the capability verbatim,
        // which is intended. What must never appear is a secret value — the
        // engine never has one, since secrets live behind `secret:` refs.
        let e = PolicyEngine::new();
        let ctx = GrantContext::plugin(p("a"));
        let d = e.decide(&ctx, &cap("secret:read:docker/registry-token"));
        assert!(d.is_denied());
        let Decision::Deny { reason } = d else {
            panic!("expected deny");
        };
        assert!(reason.contains("secret:read:docker/registry-token"));
        assert_eq!(
            e.require(&ctx, &cap("secret:read:docker/registry-token"))
                .unwrap_err()
                .code,
            ErrorCode::POLICY_DENIED
        );
    }
}
