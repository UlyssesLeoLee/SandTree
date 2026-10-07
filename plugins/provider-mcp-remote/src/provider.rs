//! SDK port implementation for the MCP endpoint channel (ADR-015).
//!
//! # Default deny
//!
//! An endpoint registration alone is not enough. The request is refused unless
//! all three hold, and all three are **absent by default**:
//!
//! 1. an [`AcquisitionPolicy`] permit — penetrating this resource and domain
//!    was refused,
//! 2. a granted `net:connect:<host:port>` capability for the endpoint
//!    (NFR-S02), and
//! 3. a registered [`PenetrationVerdict`] for the exact domain asked for.
//!
//! A missing verdict is a refusal, never a "go ahead".
//!
//! # The exchange
//!
//! `initialize` → `tools/list`. `initialize` establishes the protocol revision
//! and the session id that every later call must echo; `tools/list` returns the
//! inventory. The `notifications/initialized` notification is sent between them
//! because a conforming server waits for it.
//!
//! Nothing here calls an MCP **tool**. Calling one would execute
//! sandbox-chosen code with sandbox-chosen arguments and report the result as
//! observation — a channel for the observed to act on the observer, and one
//! whose side effects nothing in the observation plane could reason about.
//! The list is the whole channel (ADR-015).
//!
//! # One port only
//!
//! Only [`ObservationProvider`], so a channel outage can never be mistaken for
//! resources disappearing (ADR-OBS-001).

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use sandtree_model::capability::{Capability, CapabilityNamespace, CapabilitySet};
use sandtree_model::error::DomainError;
use sandtree_model::id::{PluginId, ResourceId};
use sandtree_observation_model::{
    ObservationCapabilities, ObservationRequest, ObservationSnapshot,
};
use sandtree_policy::acquire::{
    AcquisitionChannel, AcquisitionPolicy, AcquisitionRequest, PenetrationVerdict,
};
use sandtree_sdk::manifest::{now_rfc3339, PluginKind};
use sandtree_sdk::ports::{ObservationProvider, ProviderDescriptor};
use serde_json::{json, Value as Json};
use tokio::sync::RwLock;
use tracing::warn;

use crate::jsonrpc::{self, ProtocolError, Request};
use crate::observation::{
    degraded_snapshot, mcp_capabilities, parse_tool_list, snapshot_from_session,
    unavailable_snapshot, McpHandshake, DOMAIN,
};
use crate::transport::{
    HyperMcpTransport, McpTransport, TransportError, DEFAULT_TIMEOUT_MS, PROTOCOL_VERSION,
};
use crate::url::{EndpointUrlError, McpEndpointUrl};

/// Largest response body accepted, in bytes.
///
/// The endpoint is inside the sandbox, so the response is untrusted input.
pub const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

/// The client identity sent in `initialize`.
pub const CLIENT_NAME: &str = "sandtree-mcp-remote";

/// Why one MCP call failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CallError {
    /// The HTTP exchange failed.
    #[error("{0}")]
    Transport(#[from] TransportError),
    /// The response was not a valid JSON-RPC message.
    #[error("{0}")]
    Protocol(#[from] ProtocolError),
    /// The request could not be serialized.
    #[error("request could not be serialized: {0}")]
    Encode(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EndpointConfig {
    url: McpEndpointUrl,
    verdict: PenetrationVerdict,
}

/// The MCP endpoint observation provider.
pub struct McpRemoteProvider {
    plugin_id: PluginId,
    transport: Arc<dyn McpTransport>,
    policy: AcquisitionPolicy,
    endpoints: RwLock<BTreeMap<ResourceId, EndpointConfig>>,
    granted: RwLock<CapabilitySet>,
    next_id: AtomicU64,
    max_body: usize,
}

impl std::fmt::Debug for McpRemoteProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("McpRemoteProvider")
            .field("plugin_id", &self.plugin_id)
            .finish_non_exhaustive()
    }
}

impl McpRemoteProvider {
    /// Build a provider with the production transport and no grants.
    pub fn new() -> Result<Arc<Self>, TransportError> {
        Ok(Self::with_transport(Arc::new(
            HyperMcpTransport::with_timeout_ms(DEFAULT_TIMEOUT_MS)?,
        )))
    }

    /// Build a provider with an injected transport.
    pub fn with_transport(transport: Arc<dyn McpTransport>) -> Arc<Self> {
        Arc::new(Self {
            plugin_id: PluginId::derive(&[crate::PLUGIN_ID]),
            transport,
            policy: AcquisitionPolicy::new(),
            endpoints: RwLock::new(BTreeMap::new()),
            granted: RwLock::new(CapabilitySet::empty()),
            next_id: AtomicU64::new(1),
            max_body: MAX_RESPONSE_BYTES,
        })
    }

    /// Register an endpoint plus the verdict explaining why penetrating it was
    /// refused. Both halves are required together.
    pub async fn register_endpoint(
        &self,
        resource_id: ResourceId,
        url: &str,
        verdict: PenetrationVerdict,
    ) -> Result<(), EndpointUrlError> {
        let parsed = McpEndpointUrl::parse(url)?;
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
    pub async fn required_scope(&self, resource_id: &ResourceId) -> Option<String> {
        self.endpoints
            .read()
            .await
            .get(resource_id)
            .map(|c| c.url.endpoint_scope())
    }

    /// Next correlation id.
    fn next_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::SeqCst)
    }

    /// Send one request and return the correlated, validated response, together
    /// with any session id the server assigned in the response headers.
    ///
    /// The session id is returned rather than kept internally because MCP
    /// requires every call after the handshake to echo it — dropping it makes
    /// the later calls unattributable to the session that opened them, which is
    /// invisible on a server that tolerates it and fatal on one that does not.
    ///
    /// Both MCP response shapes are handled here: a single JSON body, and an
    /// SSE stream whose first matching `message` frame is used. Anything else
    /// is refused by name rather than guessed at.
    #[allow(clippy::type_complexity)]
    async fn call(
        &self,
        url: &str,
        request: &Request,
        session_id: Option<&str>,
    ) -> Result<(jsonrpc::Response, Option<String>), CallError> {
        let body = request
            .to_json()
            .map_err(|e| CallError::Encode(e.to_string()))?;
        let resp = self
            .transport
            .post(url, &body, session_id, self.max_body)
            .await?;
        let returned_session = resp.session_id.clone();

        let parsed = match resp.content_type.as_deref() {
            Some("text/event-stream") => {
                let frames = jsonrpc::extract_sse_data(&resp.body);
                let Some(frame) = frames.into_iter().find(|f| frame_matches_id(f, request.id))
                else {
                    return Err(ProtocolError::NoMessageFrame.into());
                };
                jsonrpc::parse_response(&frame, request.id)?
            }
            Some("application/json") | None => jsonrpc::parse_response(&resp.body, request.id)?,
            Some(other) => {
                return Err(TransportError::UnsupportedContentType(other.to_string()).into())
            }
        };
        Ok((parsed, returned_session))
    }

    /// Fire-and-forget a notification.
    ///
    /// A notification carries no id, so a 202 with an empty body is success.
    /// Any other status is a failure — silently ignoring it would hide a server
    /// that rejected the handshake.
    async fn notify(
        &self,
        url: &str,
        body: &str,
        session_id: Option<&str>,
    ) -> Result<(), CallError> {
        self.transport
            .post(url, body, session_id, self.max_body)
            .await
            .map(|_| ())
            .map_err(CallError::from)
    }

    /// Run the full handshake and list the tools.
    ///
    /// Separated from [`ObservationProvider::observe`] so tests can drive the
    /// real transport and the real parser while the policy gate stays in one
    /// place.
    pub async fn probe(
        &self,
        url: &McpEndpointUrl,
    ) -> Result<(McpHandshake, Vec<Json>), CallError> {
        let id = self.next_id();
        let init = Request::new(id, "initialize").with_params(json!({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": CLIENT_NAME, "version": crate::PROVIDER_VERSION},
        }));
        let (init_resp, session_id) = self.call(&url.url(), &init, None).await?;
        let Some(handshake) =
            McpHandshake::from_result(init_resp.result.as_ref().unwrap_or(&Json::Null), session_id)
        else {
            return Err(ProtocolError::NeitherResultNorError.into());
        };

        self.notify(
            &url.url(),
            &json!({"jsonrpc": jsonrpc::JSONRPC_VERSION, "method": "notifications/initialized"})
                .to_string(),
            handshake.session_id.as_deref(),
        )
        .await?;

        // A server that never advertised `tools` is answered honestly with an
        // empty inventory rather than a failed call.
        if !handshake.has_tools() {
            return Ok((handshake, Vec::new()));
        }

        let tools_id = self.next_id();
        let (tools_resp, tools_session) = self
            .call(
                &url.url(),
                &Request::new(tools_id, "tools/list"),
                handshake.session_id.as_deref(),
            )
            .await?;
        // A server may assign the session on any response, not only the first.
        // Adopt a newly seen id so a server that assigns late still gets it
        // echoed on the next call.
        let mut handshake = handshake;
        if handshake.session_id.is_none() {
            handshake.session_id = tools_session;
        }
        let tools = parse_tool_list(tools_resp.result.as_ref().unwrap_or(&Json::Null)).ok_or(
            ProtocolError::Rpc {
                code: jsonrpc::codes::INVALID_PARAMS,
                message: "tools/list result had no tools array".to_string(),
            },
        )?;
        Ok((handshake, tools))
    }
}

/// Whether an SSE frame looks like the response to `id`.
///
/// Checked without full parsing so a stream carrying several messages can skip
/// the ones belonging to other calls.
fn frame_matches_id(frame: &str, id: u64) -> bool {
    serde_json::from_str::<Json>(frame)
        .ok()
        .and_then(|v| v.get("id").and_then(|i| i.as_u64()))
        .map(|got| got == id)
        .unwrap_or(false)
}

#[async_trait::async_trait]
impl ObservationProvider for McpRemoteProvider {
    async fn capabilities(&self, _id: &ResourceId) -> Result<ObservationCapabilities, DomainError> {
        // DD-OBS §12.1: static and independent of reachability.
        Ok(mcp_capabilities())
    }

    async fn observe(&self, req: &ObservationRequest) -> Result<ObservationSnapshot, DomainError> {
        let now = now_rfc3339();

        let cfg = self.endpoints.read().await.get(&req.resource_id).cloned();
        let Some(cfg) = cfg else {
            return Ok(unavailable_snapshot(
                req.resource_id.clone(),
                "no MCP endpoint is registered for this resource",
                &now,
            ));
        };

        // The gate. Everything before this point is local; nothing above it has
        // touched the network.
        let request = AcquisitionRequest::new(
            req.resource_id.clone(),
            DOMAIN,
            AcquisitionChannel::McpEndpoint,
            cfg.url.endpoint_scope(),
        );
        let granted = self.granted.read().await.clone();
        let permit = match self
            .policy
            .authorize_or_error(&granted, &cfg.verdict, &request)
        {
            Ok(p) => p,
            Err(e) => {
                warn!(reason = %e.detail.unwrap_or_default(), "mcp acquisition refused");
                return Ok(unavailable_snapshot(
                    req.resource_id.clone(),
                    e.message,
                    &now,
                ));
            }
        };

        // Binding, not a live defence. `authorize` already checked the resource,
        // domain, channel and endpoint, and nothing between here and the socket
        // can change them -- so today this cannot fire. It is here because the
        // permit is the only thing that carries those four fields across the
        // gate, and a refactor that rebuilt the request would otherwise call
        // somewhere the gate never judged. Stated plainly so nobody mistakes it
        // for an active control that is being exercised.
        if !permit.covers(&request) {
            return Ok(unavailable_snapshot(
                req.resource_id.clone(),
                "acquisition permit does not cover this request",
                &now,
            ));
        }

        let (handshake, tools) = match self.probe(&cfg.url).await {
            Ok(v) => v,
            Err(e) => {
                // A refused or broken call is never an empty tool list.
                return Ok(degraded_snapshot(
                    req.resource_id.clone(),
                    format!("mcp endpoint could not be read: {e}"),
                    &now,
                ));
            }
        };

        let partial = !req.domains.is_empty()
            && !req
                .domains
                .iter()
                .all(|d| *d == DOMAIN || *d == crate::observation::HEALTH_DOMAIN);

        Ok(snapshot_from_session(
            req.resource_id.clone(),
            &cfg.url,
            &permit,
            &handshake,
            &tools,
            &now,
            partial,
        ))
    }
}

/// Static identity of this provider, for the plugin host's manifest check.
pub fn descriptor() -> ProviderDescriptor {
    ProviderDescriptor {
        plugin_id: crate::PLUGIN_ID.to_string(),
        version: crate::PROVIDER_VERSION.to_string(),
        kind: PluginKind::Provider,
    }
}

/// Capabilities this provider declares in its manifest (FR-051, NFR-S02).
///
/// `net:connect` is declared without a scope: the host grants the exact
/// `host:port` at runtime, per endpoint.
pub fn declared_capabilities() -> Vec<Capability> {
    vec![
        Capability::global(CapabilityNamespace::Observation, "observe:probe"),
        Capability::global(CapabilityNamespace::Observation, "observe:metadata"),
        Capability::global(CapabilityNamespace::Net, "connect"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use sandtree_model::capability::Capability;
    use sandtree_observation_model::{ObservationDomain, ObservationHealth, ObservationMode};
    use sandtree_policy::acquire::RefusalReason;
    use serde_json::json;
    use std::sync::Mutex;

    fn res() -> ResourceId {
        ResourceId::derive(&["sbx-mcp-e2e"])
    }

    fn refused() -> PenetrationVerdict {
        PenetrationVerdict::Refused {
            domain: DOMAIN,
            reason: RefusalReason::NoHostChannel,
        }
    }

    /// A transport that replays a scripted list of replies and records every
    /// request body, so tests can assert the wire conversation as well as the
    /// socket count.
    #[derive(Debug, Default)]
    struct ScriptedTransport {
        replies: Mutex<Vec<Result<crate::transport::McpHttpResponse, String>>>,
        calls: Mutex<Vec<String>>,
    }

    impl ScriptedTransport {
        fn with(replies: Vec<Result<crate::transport::McpHttpResponse, String>>) -> Arc<Self> {
            Arc::new(Self {
                replies: Mutex::new(replies),
                calls: Mutex::new(Vec::new()),
            })
        }

        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
    }

    fn json_reply(id: u64, result: Json) -> Result<crate::transport::McpHttpResponse, String> {
        Ok(crate::transport::McpHttpResponse {
            status: 200,
            content_type: Some("application/json".to_string()),
            session_id: Some("sess-1".to_string()),
            body: json!({"jsonrpc": "2.0", "id": id, "result": result}).to_string(),
        })
    }

    fn accepted() -> Result<crate::transport::McpHttpResponse, String> {
        Ok(crate::transport::McpHttpResponse {
            status: 202,
            content_type: None,
            session_id: None,
            body: String::new(),
        })
    }

    #[async_trait::async_trait]
    impl McpTransport for ScriptedTransport {
        async fn post(
            &self,
            _url: &str,
            body: &str,
            _session_id: Option<&str>,
            _max_bytes: usize,
        ) -> Result<crate::transport::McpHttpResponse, TransportError> {
            let mut calls = self.calls.lock().unwrap();
            calls.push(body.to_string());
            let mut replies = self.replies.lock().unwrap();
            if replies.is_empty() {
                return Err(TransportError::Failed("script exhausted".to_string()));
            }
            match replies.remove(0) {
                Ok(r) => Ok(r),
                Err(msg) => Err(TransportError::Failed(msg)),
            }
        }
    }

    fn init_result() -> Json {
        json!({
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "sandbox-agent", "version": "0.4.1"}
        })
    }

    fn tools_result() -> Json {
        json!({"tools": [{"name": "alpha", "inputSchema": {"type": "object"}}]})
    }

    async fn configured(transport: Arc<ScriptedTransport>) -> Arc<McpRemoteProvider> {
        let p = McpRemoteProvider::with_transport(transport as Arc<dyn McpTransport>);
        p.register_endpoint(res(), "https://10.0.0.7:9443/mcp", refused())
            .await
            .unwrap();
        p.set_granted(CapabilitySet::from_iter_caps([Capability::parse(
            "net:connect:10.0.0.7:9443",
        )
        .unwrap()]))
            .await;
        p
    }

    fn observation_request(domains: Vec<ObservationDomain>) -> ObservationRequest {
        ObservationRequest::new(res(), domains)
    }

    #[tokio::test]
    async fn a_permitted_endpoint_yields_a_guest_probe_snapshot() {
        // The full conversation: initialize, notifications/initialized,
        // tools/list — in that order.
        let transport = ScriptedTransport::with(vec![
            json_reply(1, init_result()),
            accepted(),
            json_reply(2, tools_result()),
        ]);
        let p = configured(Arc::clone(&transport)).await;

        let snap = p.observe(&observation_request(vec![DOMAIN])).await.unwrap();
        assert_eq!(snap.mode, ObservationMode::Probe);
        assert_eq!(snap.health, ObservationHealth::Healthy);
        assert_eq!(
            snap.weakest_trust(),
            Some(sandtree_observation_model::TrustLevel::GuestProbe)
        );

        let sys = &snap.get(DOMAIN).unwrap().value;
        assert_eq!(sys["server_name"], json!("sandbox-agent"));
        assert_eq!(sys["tool_names"], json!(["alpha"]));

        let calls = transport.calls();
        assert_eq!(calls.len(), 3, "initialize, notification, tools/list");
        assert!(calls[0].contains("\"initialize\""));
        assert!(calls[1].contains("notifications/initialized"));
        assert!(calls[2].contains("\"tools/list\""));
    }

    #[tokio::test]
    async fn correlation_ids_are_unique_and_echoed_back() {
        // Break by reusing one id, and the response validation can no longer
        // tell two calls apart.
        let transport = ScriptedTransport::with(vec![
            json_reply(1, init_result()),
            accepted(),
            json_reply(2, tools_result()),
        ]);
        let p = configured(Arc::clone(&transport)).await;
        p.observe(&observation_request(vec![DOMAIN])).await.unwrap();
        let calls = transport.calls();
        assert!(calls[0].contains("\"id\":1"));
        assert!(calls[2].contains("\"id\":2"));
        assert_ne!(calls[0], calls[2]);
    }

    #[tokio::test]
    async fn an_ungranted_endpoint_never_reaches_the_network() {
        let transport = ScriptedTransport::with(vec![]);
        let p = McpRemoteProvider::with_transport(Arc::clone(&transport) as Arc<dyn McpTransport>);
        p.register_endpoint(res(), "https://10.0.0.7:9443/mcp", refused())
            .await
            .unwrap();
        // No grant.

        let snap = p.observe(&observation_request(vec![DOMAIN])).await.unwrap();
        assert_eq!(snap.health, ObservationHealth::Unavailable);
        assert!(snap.values.is_empty());
        assert!(
            transport.calls().is_empty(),
            "denied acquisition must not open a socket"
        );
    }

    #[tokio::test]
    async fn a_penetrable_resource_never_reaches_the_network() {
        let transport = ScriptedTransport::with(vec![]);
        let p = McpRemoteProvider::with_transport(Arc::clone(&transport) as Arc<dyn McpTransport>);
        p.register_endpoint(
            res(),
            "https://10.0.0.7:9443/mcp",
            PenetrationVerdict::Allowed {
                domain: DOMAIN,
                mode: ObservationMode::Native,
            },
        )
        .await
        .unwrap();
        p.set_granted(CapabilitySet::from_iter_caps([Capability::parse(
            "net:connect:10.0.0.7:9443",
        )
        .unwrap()]))
            .await;

        let snap = p.observe(&observation_request(vec![DOMAIN])).await.unwrap();
        assert_eq!(snap.health, ObservationHealth::Unavailable);
        assert!(snap.values.is_empty());
        assert!(transport.calls().is_empty());
    }

    #[tokio::test]
    async fn a_server_error_is_degraded_not_an_empty_tool_list() {
        // Break by swallowing the JSON-RPC error, and a server that refuses
        // every call is reported as a sandbox exposing zero tools.
        let transport = ScriptedTransport::with(vec![Ok(crate::transport::McpHttpResponse {
            status: 200,
            content_type: Some("application/json".to_string()),
            session_id: None,
            body: json!({
                "jsonrpc": "2.0", "id": 1,
                "error": {"code": -32601, "message": "Method not found"}
            })
            .to_string(),
        })]);
        let p = configured(transport).await;

        let snap = p.observe(&observation_request(vec![DOMAIN])).await.unwrap();
        assert_eq!(snap.health, ObservationHealth::Degraded);
        assert!(snap.values.is_empty());
        assert!(snap.warnings[0].contains("Method not found"));
    }

    #[tokio::test]
    async fn a_server_without_the_tools_capability_yields_an_empty_list_not_a_failure() {
        // A sandbox that exposes nothing is a finding; a sandbox that cannot be
        // reached is not.
        let transport = ScriptedTransport::with(vec![
            json_reply(
                1,
                json!({
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "serverInfo": {"name": "bare", "version": "0.1.0"}
                }),
            ),
            accepted(),
        ]);
        let p = configured(transport).await;

        let snap = p.observe(&observation_request(vec![DOMAIN])).await.unwrap();
        assert_eq!(snap.health, ObservationHealth::Healthy);
        assert_eq!(snap.get(DOMAIN).unwrap().value["tool_count"], json!(0));
    }

    #[tokio::test]
    async fn an_event_stream_reply_is_read_and_correlated() {
        // The other shape a conforming server may use.
        let transport = ScriptedTransport::with(vec![
            Ok(crate::transport::McpHttpResponse {
                status: 200,
                content_type: Some("text/event-stream".to_string()),
                session_id: Some("sess-s".to_string()),
                body: concat!(
                    ": keep-alive\n\n",
                    "event: message\n",
                    "data: {\"jsonrpc\":\"2.0\",\"id\":99,\"result\":{\"stale\":true}}\n\n",
                    "event: message\n",
                    "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":",
                )
                .to_string()
                    + &init_result().to_string()
                    + "}\n\n",
            }),
            accepted(),
            json_reply(2, tools_result()),
        ]);
        let p = configured(transport).await;

        let snap = p.observe(&observation_request(vec![DOMAIN])).await.unwrap();
        assert_eq!(snap.health, ObservationHealth::Healthy);
        assert_eq!(
            snap.get(DOMAIN).unwrap().value["server_name"],
            json!("sandbox-agent")
        );
    }

    #[tokio::test]
    async fn a_stream_with_no_matching_frame_is_a_failure_not_an_empty_result() {
        let transport = ScriptedTransport::with(vec![Ok(crate::transport::McpHttpResponse {
            status: 200,
            content_type: Some("text/event-stream".to_string()),
            session_id: None,
            body: ": keep-alive\n\n: ping\n\n".to_string(),
        })]);
        let p = configured(transport).await;
        let snap = p.observe(&observation_request(vec![DOMAIN])).await.unwrap();
        assert_eq!(snap.health, ObservationHealth::Degraded);
        assert!(snap.warnings[0].contains("message frame"));
    }

    #[tokio::test]
    async fn an_unexpected_content_type_is_refused_by_name() {
        let transport = ScriptedTransport::with(vec![Ok(crate::transport::McpHttpResponse {
            status: 200,
            content_type: Some("text/html".to_string()),
            session_id: None,
            body: "<html>nope</html>".to_string(),
        })]);
        let p = configured(transport).await;
        let snap = p.observe(&observation_request(vec![DOMAIN])).await.unwrap();
        assert_eq!(snap.health, ObservationHealth::Degraded);
        assert!(snap.warnings[0].contains("text/html"));
    }

    #[tokio::test]
    async fn domains_this_channel_cannot_answer_are_marked_partial() {
        let transport = ScriptedTransport::with(vec![
            json_reply(1, init_result()),
            accepted(),
            json_reply(2, tools_result()),
        ]);
        let p = configured(transport).await;
        let snap = p
            .observe(&observation_request(vec![
                DOMAIN,
                ObservationDomain::Network,
            ]))
            .await
            .unwrap();
        assert!(snap.get(DOMAIN).unwrap().is_partial());
        assert_eq!(
            snap.missing_domains(&[DOMAIN, ObservationDomain::Network]),
            vec!["network"]
        );
    }

    #[tokio::test]
    async fn the_declared_capabilities_are_unscoped() {
        for c in declared_capabilities() {
            assert_eq!(
                c.scope(),
                None,
                "declared capability {c} must not pin a scope"
            );
        }
        assert!(declared_capabilities()
            .iter()
            .any(|c| c.namespace() == CapabilityNamespace::Net));
    }

    #[tokio::test]
    async fn the_operator_can_see_the_exact_scope_before_granting_it() {
        let transport = ScriptedTransport::with(vec![]);
        let p = configured(transport).await;
        assert_eq!(
            p.required_scope(&res()).await.as_deref(),
            Some("10.0.0.7:9443")
        );
    }
}
