//! SDK port implementation for the git-remote channel (ADR-015).
//!
//! # Default deny
//!
//! Three things must be present before a single byte leaves the host: an
//! [`AcquisitionPolicy`] permit, a registered [`PenetrationVerdict`] for the
//! exact (resource, domain) pair, and a granted `net:connect` capability for
//! the endpoint. All three are **absent by default**, so a freshly constructed
//! provider observes nothing. A missing verdict is a refusal, not a "go
//! ahead" (NFR-S02).
//!
//! # This provider implements one port
//!
//! Only [`ObservationProvider`]. It does **not** implement [`ResourceProvider`]:
//! the git advertisement says nothing about which containers or VMs exist, and
//! claiming `discover` would let reconcile conclude that everything vanished
//! whenever this channel is down (ADR-OBS-001).

use std::collections::BTreeMap;
use std::sync::Arc;

use sandtree_model::capability::{Capability, CapabilitySet};
use sandtree_model::error::{DomainError, ErrorCode};
use sandtree_model::id::{PluginId, ResourceId};
use sandtree_observation_model::{
    ObservationCapabilities, ObservationRequest, ObservationSnapshot,
};
use sandtree_policy::acquire::{
    AcquisitionChannel, AcquisitionPolicy, AcquisitionRequest, PenetrationVerdict,
};
use sandtree_sdk::manifest::{now_rfc3339, PluginKind};
use sandtree_sdk::ports::{ObservationProvider, ProviderDescriptor};
use tokio::sync::RwLock;
use tracing::warn;

use crate::advertisement::{parse_advertisement, RefAdvertisement};
use crate::observation::{
    degraded_snapshot, git_remote_capabilities, snapshot_from_advertisement, unavailable_snapshot,
    DOMAIN,
};
use crate::transport::{RemoteTransport, TransportError, DEFAULT_TIMEOUT_MS};
use crate::url::{GitRemoteUrl, RemoteUrlError};

/// Largest advertisement body accepted, in bytes.
///
/// A sandbox serves this endpoint, so the response is untrusted input. The
/// bound is well above any realistic ref count (see `MAX_REFS`) and below what
/// would matter to the process.
pub const MAX_ADVERTISEMENT_BYTES: usize = 4 * 1024 * 1024;

/// Per-resource configuration the operator must supply explicitly.
#[derive(Debug, Clone, PartialEq, Eq)]
struct EndpointConfig {
    url: GitRemoteUrl,
    verdict: PenetrationVerdict,
}

/// The git-remote observation provider.
pub struct GitRemoteProvider {
    plugin_id: PluginId,
    transport: Arc<dyn RemoteTransport>,
    policy: AcquisitionPolicy,
    endpoints: RwLock<BTreeMap<ResourceId, EndpointConfig>>,
    granted: RwLock<CapabilitySet>,
    max_body: usize,
}

impl std::fmt::Debug for GitRemoteProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GitRemoteProvider")
            .field("plugin_id", &self.plugin_id)
            .finish_non_exhaustive()
    }
}

impl GitRemoteProvider {
    /// Build a provider with the production transport and no grants.
    pub fn new() -> Result<Arc<Self>, TransportError> {
        Ok(Self::with_transport(Arc::new(
            crate::transport::HyperTransport::with_timeout_ms(DEFAULT_TIMEOUT_MS)?,
        )))
    }

    /// Build a provider with an injected transport.
    pub fn with_transport(transport: Arc<dyn RemoteTransport>) -> Arc<Self> {
        Arc::new(Self {
            plugin_id: PluginId::derive(&[crate::PLUGIN_ID]),
            transport,
            policy: AcquisitionPolicy::new(),
            endpoints: RwLock::new(BTreeMap::new()),
            granted: RwLock::new(CapabilitySet::empty()),
            max_body: MAX_ADVERTISEMENT_BYTES,
        })
    }

    /// Register the remote a sandbox publishes, plus the verdict explaining why
    /// penetrating it was refused.
    ///
    /// Both halves are required at registration time on purpose: an endpoint
    /// without a reason would be exactly the "more convenient channel" the
    /// admission rule exists to refuse.
    pub async fn register_endpoint(
        &self,
        resource_id: ResourceId,
        url: &str,
        verdict: PenetrationVerdict,
    ) -> Result<(), RemoteUrlError> {
        let parsed = GitRemoteUrl::parse(url)?;
        self.endpoints.write().await.insert(
            resource_id,
            EndpointConfig {
                url: parsed,
                verdict,
            },
        );
        Ok(())
    }

    /// Replace the granted capability set (NFR-S02).
    pub async fn set_granted(&self, granted: CapabilitySet) {
        *self.granted.write().await = granted;
    }

    /// Endpoint scope a resource would need a grant for.
    ///
    /// Exposed so an operator-facing surface can show the exact capability
    /// before asking for it, rather than making them guess `host:port`.
    pub async fn required_scope(&self, resource_id: &ResourceId) -> Option<String> {
        self.endpoints
            .read()
            .await
            .get(resource_id)
            .map(|c| c.url.endpoint_scope())
    }

    /// Fetch and parse the advertisement for a resource.
    ///
    /// Separated from [`ObservationProvider::observe`] so the end-to-end tests
    /// can drive the real transport and the real parser while the policy gate
    /// stays in one place.
    pub async fn fetch_advertisement(
        &self,
        resource_id: &ResourceId,
    ) -> Result<RefAdvertisement, TransportError> {
        let cfg = self.endpoints.read().await.get(resource_id).cloned();
        let Some(cfg) = cfg else {
            // No endpoint is not an error state of the network; it is a
            // configuration gap, reported as such by the caller.
            return Err(TransportError::Failed(
                "no git remote is registered".to_string(),
            ));
        };
        let url = cfg.url.info_refs_url();
        let resp = self.transport.get(&url, self.max_body).await?;
        parse_advertisement(&resp.body).map_err(|e| {
            // An advertisement we could not read is a transport-level failure
            // for the caller, never an empty ref list.
            TransportError::Failed(e.to_string())
        })
    }

    /// Which parser/transport error this is, for the snapshot health decision.
    pub(crate) fn classify(e: &TransportError) -> ObservationFailure {
        match e {
            TransportError::Timeout(_) => ObservationFailure::Unavailable,
            TransportError::Failed(_) => ObservationFailure::Unavailable,
            TransportError::StatusNotSuccess { status } if *status == 404 => {
                ObservationFailure::Degraded
            }
            TransportError::StatusNotSuccess { .. } => ObservationFailure::Unavailable,
            _ => ObservationFailure::Unavailable,
        }
    }
}

/// How a channel failure should be reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ObservationFailure {
    /// The channel is down; nothing was learned.
    Unavailable,
    /// The channel answered but cannot answer *this* question.
    Degraded,
}

#[async_trait::async_trait]
impl ObservationProvider for GitRemoteProvider {
    async fn capabilities(&self, _id: &ResourceId) -> Result<ObservationCapabilities, DomainError> {
        // DD-OBS §12.1: static, and independent of whether anything is reachable.
        Ok(git_remote_capabilities())
    }

    async fn observe(&self, req: &ObservationRequest) -> Result<ObservationSnapshot, DomainError> {
        let now = now_rfc3339();

        let cfg = self.endpoints.read().await.get(&req.resource_id).cloned();
        let Some(cfg) = cfg else {
            return Ok(unavailable_snapshot(
                req.resource_id.clone(),
                "no git remote is registered for this resource",
                &now,
            ));
        };

        // The gate. Everything before this point is local; nothing above this
        // point has touched the network.
        let request = AcquisitionRequest::new(
            req.resource_id.clone(),
            DOMAIN,
            AcquisitionChannel::GitRemote,
            cfg.url.endpoint_scope(),
        );
        let granted = self.granted.read().await.clone();
        let permit = match self
            .policy
            .authorize_or_error(&granted, &cfg.verdict, &request)
        {
            Ok(p) => p,
            Err(e) => {
                // A refused channel is `Unavailable`, never an empty Healthy
                // snapshot: policy said no, which is not the same as the
                // sandbox having no branches (ADR-OBS-001).
                warn!(reason = %e.detail.unwrap_or_default(), "git-remote acquisition refused");
                return Ok(unavailable_snapshot(
                    req.resource_id.clone(),
                    e.message,
                    &now,
                ));
            }
        };

        let url = cfg.url.info_refs_url();
        // Defence in depth, immediately before the socket: the permit must
        // still cover the request the fetch is about to make. `authorize`
        // already checked these fields, so this can only fire if something
        // rebuilt the request between the gate and here — which is exactly the
        // moment a permit would otherwise authorize a different endpoint than
        // the one that was judged.
        if !permit.covers(&request) {
            return Ok(unavailable_snapshot(
                req.resource_id.clone(),
                "acquisition permit does not cover this request",
                &now,
            ));
        }

        let resp = match self.transport.get(&url, self.max_body).await {
            Ok(r) => r,
            Err(e) => {
                let snap = match Self::classify(&e) {
                    ObservationFailure::Unavailable => {
                        unavailable_snapshot(req.resource_id.clone(), e.to_string(), &now)
                    }
                    ObservationFailure::Degraded => {
                        degraded_snapshot(req.resource_id.clone(), e.to_string(), &now)
                    }
                };
                return Ok(snap);
            }
        };

        let adv = match parse_advertisement(&resp.body) {
            Ok(a) => a,
            Err(e) => {
                // Protocol v2 lands here. It is an unsupported exchange, and
                // reporting it as "no refs" would be a false finding.
                return Ok(degraded_snapshot(
                    req.resource_id.clone(),
                    format!("git advertisement could not be read: {e}"),
                    &now,
                ));
            }
        };

        // Whatever the caller asked for beyond this channel's one domain is
        // reported as partial rather than quietly omitted.
        let partial = !req.domains.is_empty()
            && !req
                .domains
                .iter()
                .all(|d| *d == DOMAIN || *d == crate::observation::HEALTH_DOMAIN);

        Ok(snapshot_from_advertisement(
            req.resource_id.clone(),
            &cfg.url,
            &permit,
            &adv,
            &now,
            partial,
        ))
    }
}

/// Static identity of this provider, for the plugin host's manifest check.
///
/// Not a trait method: `ObservationProvider` has no `descriptor`, and adding a
/// port method to the SDK for one provider would widen the ABI for all of them.
pub fn descriptor() -> ProviderDescriptor {
    ProviderDescriptor {
        plugin_id: crate::PLUGIN_ID.to_string(),
        version: crate::PROVIDER_VERSION.to_string(),
        kind: PluginKind::Provider,
    }
}

/// Capabilities this provider declares in its manifest (FR-051, NFR-S02).
///
/// `net:connect` is declared **without a scope**: the host grants the exact
/// `host:port` at runtime, per endpoint, so one plugin registration can serve
/// several sandboxes without widening any of them.
pub fn declared_capabilities() -> Vec<Capability> {
    use sandtree_model::capability::CapabilityNamespace;
    vec![
        Capability::global(CapabilityNamespace::Observation, "observe:probe"),
        Capability::global(CapabilityNamespace::Observation, "observe:metadata"),
        Capability::global(CapabilityNamespace::Net, "connect"),
    ]
}

/// Map a policy refusal onto the error a caller sees when it insists on a result.
pub fn refusal_error(reason: &str) -> DomainError {
    DomainError::new(ErrorCode::POLICY_DENIED, reason.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::advertisement::ObjectFormat;
    use sandtree_model::capability::CapabilityNamespace;
    use sandtree_observation_model::{ObservationDomain, ObservationHealth, ObservationMode};
    use sandtree_policy::acquire::RefusalReason;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// A realistic advertisement, assembled with the encoder so the packet
    /// lengths cannot drift from the payloads.
    fn advertisement() -> String {
        let mut s = crate::pktline::encode("# service=git-upload-pack\n").unwrap();
        s.push_str(&crate::pktline::encode_flush());
        s.push_str(
            &crate::pktline::encode(concat!(
                "0000000000000000000000000000000000000000 HEAD\0",
                "symref=HEAD:refs/heads/main agent=git/2.45.0 object-format=sha1\n"
            ))
            .unwrap(),
        );
        s.push_str(
            &crate::pktline::encode("a1b2c3d4e5f60718293a4b5c6d7e8f9012345678 refs/heads/main\n")
                .unwrap(),
        );
        s.push_str(&crate::pktline::encode_flush());
        s
    }

    fn res() -> ResourceId {
        ResourceId::derive(&["sbx-e2e"])
    }

    fn refused() -> PenetrationVerdict {
        PenetrationVerdict::Refused {
            domain: DOMAIN,
            reason: RefusalReason::IsolationNotPermitted,
        }
    }

    /// A transport that answers from a fixed body and counts the calls, so a
    /// test can assert the network was *not* touched.
    #[derive(Debug)]
    struct ScriptedTransport {
        body: String,
        hits: AtomicU32,
    }

    impl ScriptedTransport {
        fn new(body: &str) -> Arc<Self> {
            Arc::new(Self {
                body: body.to_string(),
                hits: AtomicU32::new(0),
            })
        }
        fn hits(&self) -> u32 {
            self.hits.load(Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl RemoteTransport for ScriptedTransport {
        async fn get(
            &self,
            _url: &str,
            _max_bytes: usize,
        ) -> Result<crate::transport::HttpResponse, TransportError> {
            self.hits.fetch_add(1, Ordering::SeqCst);
            Ok(crate::transport::HttpResponse {
                status: 200,
                content_type: Some("application/x-git-upload-pack-advertisement".to_string()),
                body: self.body.clone(),
            })
        }
    }

    async fn configured(transport: Arc<dyn RemoteTransport>) -> Arc<GitRemoteProvider> {
        let p = GitRemoteProvider::with_transport(transport);
        p.register_endpoint(res(), "https://10.0.0.5:9418/workspace.git", refused())
            .await
            .unwrap();
        p.set_granted(CapabilitySet::from_iter_caps([Capability::parse(
            "net:connect:10.0.0.5:9418",
        )
        .unwrap()]))
            .await;
        p
    }

    fn observation_request(domains: Vec<ObservationDomain>) -> ObservationRequest {
        ObservationRequest::new(res(), domains)
    }

    #[tokio::test]
    async fn a_permitted_fetch_produces_a_guest_probe_snapshot() {
        let p = configured(ScriptedTransport::new(&advertisement())).await;
        let snap = p.observe(&observation_request(vec![DOMAIN])).await.unwrap();

        assert_eq!(snap.mode, ObservationMode::Probe);
        assert_eq!(snap.health, ObservationHealth::Healthy);
        assert_eq!(
            snap.weakest_trust(),
            Some(sandtree_observation_model::TrustLevel::GuestProbe)
        );
        let fs = &snap.get(DOMAIN).unwrap().value;
        assert_eq!(fs["branches"], serde_json::json!(["refs/heads/main"]));
        assert_eq!(fs["head_target"], serde_json::json!("refs/heads/main"));
        assert!(fs["object_format"] == serde_json::json!(ObjectFormat::Sha1.as_str()));
    }

    #[tokio::test]
    async fn an_unregistered_resource_never_reaches_the_network() {
        // Break by fetching before looking up the config, and an unconfigured
        // sandbox still produces a network request.
        let transport = ScriptedTransport::new(&advertisement());
        let p =
            GitRemoteProvider::with_transport(Arc::clone(&transport) as Arc<dyn RemoteTransport>);
        p.set_granted(CapabilitySet::from_iter_caps([Capability::parse(
            "net:connect:10.0.0.5:9418",
        )
        .unwrap()]))
            .await;

        let snap = p.observe(&observation_request(vec![DOMAIN])).await.unwrap();
        assert_eq!(snap.health, ObservationHealth::Unavailable);
        assert!(snap.values.is_empty());
        assert_eq!(
            transport.hits(),
            0,
            "no request may be made without an endpoint"
        );
    }

    #[tokio::test]
    async fn a_missing_capability_grant_never_reaches_the_network() {
        // NFR-S02 deny-by-default, enforced at the socket boundary rather than
        // only in the returned snapshot.
        let transport = ScriptedTransport::new(&advertisement());
        let p =
            GitRemoteProvider::with_transport(Arc::clone(&transport) as Arc<dyn RemoteTransport>);
        p.register_endpoint(res(), "https://10.0.0.5:9418/workspace.git", refused())
            .await
            .unwrap();
        // No grant at all.

        let snap = p.observe(&observation_request(vec![DOMAIN])).await.unwrap();
        assert_eq!(snap.health, ObservationHealth::Unavailable);
        assert!(
            snap.values.is_empty(),
            "a refused channel carries no values"
        );
        assert_eq!(
            transport.hits(),
            0,
            "denied acquisition must not open a socket"
        );
    }

    #[tokio::test]
    async fn a_penetrable_resource_never_reaches_the_network() {
        // The core rule, end to end: a sandbox that could be read directly
        // must not get to answer over its own channel instead.
        let transport = ScriptedTransport::new(&advertisement());
        let p =
            GitRemoteProvider::with_transport(Arc::clone(&transport) as Arc<dyn RemoteTransport>);
        p.register_endpoint(
            res(),
            "https://10.0.0.5:9418/workspace.git",
            PenetrationVerdict::Allowed {
                domain: DOMAIN,
                mode: ObservationMode::Exec,
            },
        )
        .await
        .unwrap();
        p.set_granted(CapabilitySet::from_iter_caps([Capability::parse(
            "net:connect:10.0.0.5:9418",
        )
        .unwrap()]))
            .await;

        let snap = p.observe(&observation_request(vec![DOMAIN])).await.unwrap();
        assert_eq!(snap.health, ObservationHealth::Unavailable);
        assert!(snap.values.is_empty());
        assert_eq!(transport.hits(), 0);
        assert!(
            snap.warnings[0].contains("penetration"),
            "the warning must name the rule, got {:?}",
            snap.warnings
        );
    }

    #[tokio::test]
    async fn a_malformed_advertisement_is_degraded_not_empty() {
        // Break by swallowing the parse error, and a protocol-v2 server is
        // reported as an empty repository.
        let p = configured(ScriptedTransport::new("0003")).await;
        let snap = p.observe(&observation_request(vec![DOMAIN])).await.unwrap();
        assert_eq!(snap.health, ObservationHealth::Degraded);
        assert!(
            snap.values.is_empty(),
            "a protocol error must not yield an empty-looking Healthy snapshot"
        );
        assert!(snap.warnings[0].contains("advertisement"));
    }

    #[tokio::test]
    async fn domains_this_channel_cannot_answer_are_marked_partial() {
        let p = configured(ScriptedTransport::new(&advertisement())).await;
        let snap = p
            .observe(&observation_request(vec![
                DOMAIN,
                ObservationDomain::Process,
            ]))
            .await
            .unwrap();
        assert_eq!(snap.health, ObservationHealth::Healthy);
        assert!(
            snap.get(DOMAIN).unwrap().is_partial(),
            "a request this channel cannot fully answer must be partial"
        );
        assert_eq!(
            snap.missing_domains(&[DOMAIN, ObservationDomain::Process]),
            vec!["process"],
            "the missing domain must be named rather than hidden"
        );
    }

    #[tokio::test]
    async fn the_declared_capability_set_is_unscoped_and_denies_by_default() {
        let caps = declared_capabilities();
        assert!(caps
            .iter()
            .any(|c| c.namespace() == CapabilityNamespace::Net));
        // No declared capability may carry an endpoint scope: the host grants
        // `net:connect:<host:port>` per endpoint at runtime.
        for c in &caps {
            assert_eq!(
                c.scope(),
                None,
                "declared capability {c} must not pin a scope"
            );
        }
    }

    #[tokio::test]
    async fn the_operator_can_see_the_exact_scope_before_granting_it() {
        let p = configured(ScriptedTransport::new(&advertisement())).await;
        assert_eq!(
            p.required_scope(&res()).await.as_deref(),
            Some("10.0.0.5:9418")
        );
        assert!(p
            .required_scope(&ResourceId::derive(&["other"]))
            .await
            .is_none());
    }
}
