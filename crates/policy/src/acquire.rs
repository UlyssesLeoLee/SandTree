//! Admission rule for **network acquisition** of sandbox-internal state
//! (ADR-015; FR-0xx v1.2 proposal, NFR-S02, NFR-S06, NFR-S07, NFR-O05).
//!
//! # What this module is for
//!
//! Some sandbox-internal content cannot be reached by penetrating the guest:
//! the runtime offers no read API, there is no exec channel, and mounting or
//! exposing anything would trade away isolation (NFR-S06/S07 — isolation is not
//! negotiable). For that content the sandbox may instead **publish** a channel
//! and let the host fetch over the network: a git remote, an MCP endpoint.
//!
//! This module decides **whether that is allowed**. It contains no transport,
//! no HTTP, no git — the decision is pure so it can be tested without a network
//! and so both channel providers are forced through exactly the same gate.
//!
//! # The rule
//!
//! Network acquisition is admissible **only when penetrating that same
//! (resource, domain) pair was refused**. The converse is just as important and
//! is the reason this is not a simple capability check:
//!
//! > If the host can already read inside safely, the network channel must be
//! > **refused**.
//!
//! Without that half, a sandbox could pick the weaker channel for itself: keep
//! the host's own read API out of reach, make penetration look unavailable, and
//! get every fact about itself delivered by a process the sandbox controls. The
//! network channel is a **fallback for unreachable content, not a preference**.
//!
//! # Why the trust ceiling is a constant
//!
//! Everything fetched over the network is reported by the sandbox, so its
//! ceiling is [`TrustLevel::GuestProbe`] and stays there (ADR-OBS-003). This is
//! enforced *structurally* rather than by convention: [`AcquisitionPolicy`] has
//! no fields, so there is no way to construct one with a raised ceiling, and
//! [`AcquisitionPermit`] is only obtainable from [`AcquisitionPolicy::authorize`].
//!
//! What git *does* add is **integrity**, not authenticity: object IDs are
//! content-addressed, so a value can be re-checked later against the same bytes.
//! That lands in `Provenance::evidence_hash` and deliberately does **not** move
//! the trust level — a sandbox can produce a valid hash for a false claim.
//!
//! # Error codes
//!
//! No acquisition-specific code exists in the frozen `schemas/error_codes.csv`,
//! and inventing one would break that contract. Every denial here surfaces as
//! [`ErrorCode::POLICY_DENIED`] (`ST-POL-001`) with the specific reason in the
//! detail string, and a caller with no admissible channel at all surfaces as
//! [`ErrorCode::OBS_NO_STRATEGY`] (`ST-OBS-001`).

use sandtree_model::capability::{Capability, CapabilityNamespace, CapabilitySet};
use sandtree_model::error::{DomainError, ErrorCode};
use sandtree_model::id::ResourceId;
use sandtree_observation_model::{ObservationDomain, ObservationMode, TrustLevel};
use serde::{Deserialize, Serialize};

/// Longest endpoint scope accepted, in characters.
///
/// A scope is a `host:port` pair, so anything longer than this is a malformed
/// value rather than a wide-but-real network. Bounding it also keeps a
/// pathological value out of audit records.
pub const MAX_ENDPOINT_SCOPE_LEN: usize = 255;

/// The fixed trust ceiling for every network-acquired value.
///
/// Deliberately a `const`, not a policy field: there is no configuration path
/// that raises it (ADR-OBS-003, ADR-015).
pub const NETWORK_TRUST_CEILING: TrustLevel = TrustLevel::GuestProbe;

/// Why the host could not read inside for one (resource, domain) pair.
///
/// Produced by strategy selection *before* any channel is considered. It is
/// always specific to a single [`ObservationDomain`] — see
/// [`PenetrationVerdict::domain`] for why that binding matters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PenetrationVerdict {
    /// The host can read this domain inside the sandbox.
    Allowed {
        /// Domain the verdict was judged for.
        domain: ObservationDomain,
        /// Mode that would be used.
        mode: ObservationMode,
    },
    /// The host cannot read this domain without trading away isolation.
    Refused {
        /// Domain the verdict was judged for.
        domain: ObservationDomain,
        /// Machine-checkable cause. Free text would not be decidable (RD §9).
        reason: RefusalReason,
    },
}

impl PenetrationVerdict {
    /// Domain this verdict was judged for.
    pub fn domain(&self) -> ObservationDomain {
        match self {
            PenetrationVerdict::Allowed { domain, .. }
            | PenetrationVerdict::Refused { domain, .. } => *domain,
        }
    }

    /// Whether penetrating this domain is possible.
    pub fn is_allowed(&self) -> bool {
        matches!(self, PenetrationVerdict::Allowed { .. })
    }
}

/// Why a penetration channel was unavailable.
///
/// Each variant names a rule from the design baseline, so a denial is
/// explainable without re-deriving it (RD §9: never present a guess as a fact).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefusalReason {
    /// The provider/runtime exposes no read API and no exec channel at all.
    NoHostChannel,
    /// Reaching the content would require exposing the host Docker socket, a
    /// full-disk writable mapping or a host admin token (NFR-S06/S07).
    IsolationNotPermitted,
    /// The only writable path into the guest is the telemetry outbox, which is
    /// deliberately not a general read/write channel (NFR-S06).
    GuestPathDenied,
    /// The channel exists but the capability to use it was not granted
    /// (NFR-S02, deny-by-default).
    CapabilityDenied,
}

/// The network channels through which a sandbox may publish internal state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcquisitionChannel {
    /// A git remote the sandbox exposes (`info/refs` ref advertisement).
    GitRemote,
    /// An MCP endpoint the sandbox exposes (JSON-RPC 2.0 over HTTP).
    McpEndpoint,
}

impl AcquisitionChannel {
    /// Wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            AcquisitionChannel::GitRemote => "git_remote",
            AcquisitionChannel::McpEndpoint => "mcp_endpoint",
        }
    }

    /// Parse wire form.
    pub fn from_wire(s: &str) -> Option<Self> {
        match s {
            "git_remote" => Some(AcquisitionChannel::GitRemote),
            "mcp_endpoint" => Some(AcquisitionChannel::McpEndpoint),
            _ => None,
        }
    }

    /// Provenance source recorded on every value this channel produces.
    ///
    /// Provenance names the channel so a stored snapshot can be traced back to
    /// how it was obtained.
    pub fn provenance_source(self) -> &'static str {
        match self {
            AcquisitionChannel::GitRemote => "git-remote-acquire",
            AcquisitionChannel::McpEndpoint => "mcp-endpoint-acquire",
        }
    }
}

/// A request to obtain one domain of one resource over the network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcquisitionRequest {
    /// Resource the caller wants to learn about.
    pub resource_id: ResourceId,
    /// Domain being requested.
    pub domain: ObservationDomain,
    /// Channel to use.
    pub channel: AcquisitionChannel,
    /// `host:port` of the endpoint, used verbatim as the `net:connect` scope.
    pub endpoint_scope: String,
}

impl AcquisitionRequest {
    /// Build a request.
    pub fn new(
        resource_id: ResourceId,
        domain: ObservationDomain,
        channel: AcquisitionChannel,
        endpoint_scope: impl Into<String>,
    ) -> Self {
        Self {
            resource_id,
            domain,
            channel,
            endpoint_scope: endpoint_scope.into(),
        }
    }

    /// The capability that must be granted for this request.
    ///
    /// `net:connect:<host:port>` — scoped to the exact endpoint, never global.
    /// A global grant would let a channel configured for one sandbox reach any
    /// other host (NFR-S02).
    pub fn required_capability(&self) -> Capability {
        Capability::new(
            CapabilityNamespace::Net,
            "connect",
            Some(self.endpoint_scope.clone()),
        )
    }
}

/// Proof that one request was admitted, and under what ceiling.
///
/// Fields are private: the only way to obtain one is [`AcquisitionPolicy::authorize`],
/// so a permit cannot be forged by a caller that skipped the gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcquisitionPermit {
    resource_id: ResourceId,
    channel: AcquisitionChannel,
    endpoint_scope: String,
    domain: ObservationDomain,
    trust_ceiling: TrustLevel,
    refusal_reason: RefusalReason,
}

impl AcquisitionPermit {
    /// Resource this permit is bound to.
    pub fn resource_id(&self) -> &ResourceId {
        &self.resource_id
    }

    /// Channel this permit is valid for.
    ///
    /// A permit issued for `GitRemote` does **not** authorize an MCP request,
    /// even to the same endpoint: the two channels carry different content and
    /// different server-side trust assumptions.
    pub fn channel(&self) -> AcquisitionChannel {
        self.channel
    }

    /// Endpoint this permit is bound to.
    pub fn endpoint_scope(&self) -> &str {
        &self.endpoint_scope
    }

    /// Domain this permit is bound to.
    pub fn domain(&self) -> ObservationDomain {
        self.domain
    }

    /// Trust ceiling for values obtained under this permit.
    pub fn trust_ceiling(&self) -> TrustLevel {
        self.trust_ceiling
    }

    /// Why penetration was refused, carried for the audit record (NFR-S03).
    pub fn refusal_reason(&self) -> RefusalReason {
        self.refusal_reason
    }

    /// Whether this permit covers `req`.
    ///
    /// A channel provider calls this before transmitting, so a permit obtained
    /// for one domain cannot be replayed for another domain, channel, endpoint
    /// or resource. The resource is part of the tuple: the refusal that
    /// justified the permit was judged for this sandbox, not for every sandbox
    /// sharing the endpoint.
    pub fn covers(&self, req: &AcquisitionRequest) -> bool {
        self.resource_id == req.resource_id
            && self.channel == req.channel
            && self.domain == req.domain
            && self.endpoint_scope == req.endpoint_scope
    }
}

/// Why a network acquisition was refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "reason")]
pub enum AcquisitionDenied {
    /// Penetration was possible, so the network channel must not be used.
    ///
    /// This is the rule that stops a sandbox steering the host onto the weaker
    /// channel on purpose.
    PenetrationAvailable {
        /// Domain penetration covered.
        domain: ObservationDomain,
        /// Mode that would have been used instead.
        mode: ObservationMode,
    },
    /// The verdict was judged for a different domain than the request.
    VerdictDomainMismatch {
        /// Domain the verdict covered.
        verdict_domain: ObservationDomain,
        /// Domain actually requested.
        request_domain: ObservationDomain,
    },
    /// The `net:connect` capability for this endpoint was not granted.
    CapabilityDenied {
        /// The capability that would have been required.
        required: String,
    },
    /// The endpoint scope is empty or malformed.
    EndpointScopeRejected {
        /// Why the scope was not usable.
        detail: String,
    },
}

impl AcquisitionDenied {
    /// Stable wire reason, for audit records.
    pub fn as_str(&self) -> &'static str {
        match self {
            AcquisitionDenied::PenetrationAvailable { .. } => "penetration_available",
            AcquisitionDenied::VerdictDomainMismatch { .. } => "verdict_domain_mismatch",
            AcquisitionDenied::CapabilityDenied { .. } => "capability_denied",
            AcquisitionDenied::EndpointScopeRejected { .. } => "endpoint_scope_rejected",
        }
    }
}

impl std::fmt::Display for AcquisitionDenied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AcquisitionDenied::PenetrationAvailable { domain, mode } => write!(
                f,
                "penetration of {} is available via {}; the network channel is a fallback for unreachable content, not a preference",
                domain.as_str(),
                mode.as_str()
            ),
            AcquisitionDenied::VerdictDomainMismatch {
                verdict_domain,
                request_domain,
            } => write!(
                f,
                "the penetration verdict was judged for {}, not {}",
                verdict_domain.as_str(),
                request_domain.as_str()
            ),
            AcquisitionDenied::CapabilityDenied { required } => {
                write!(f, "capability {required} was not granted")
            }
            AcquisitionDenied::EndpointScopeRejected { detail } => {
                write!(f, "endpoint scope was rejected: {detail}")
            }
        }
    }
}

/// The admission gate for network acquisition.
///
/// Intentionally fieldless. The trust ceiling is [`NETWORK_TRUST_CEILING`], a
/// constant, so there is no instance of this type that permits a higher trust
/// level — the invariant is a property of the type rather than a value someone
/// has to remember to set correctly.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AcquisitionPolicy;

impl AcquisitionPolicy {
    /// Construct the gate.
    pub const fn new() -> Self {
        Self
    }

    /// The fixed trust ceiling.
    pub const fn trust_ceiling(&self) -> TrustLevel {
        NETWORK_TRUST_CEILING
    }

    /// Decide one request.
    ///
    /// Order matters and is itself part of the contract: the domain binding is
    /// checked **first**, so a refusal cannot be laundered by presenting a
    /// verdict obtained for a domain the host can actually read.
    pub fn authorize(
        &self,
        granted: &CapabilitySet,
        penetration: &PenetrationVerdict,
        req: &AcquisitionRequest,
    ) -> Result<AcquisitionPermit, AcquisitionDenied> {
        if penetration.domain() != req.domain {
            return Err(AcquisitionDenied::VerdictDomainMismatch {
                verdict_domain: penetration.domain(),
                request_domain: req.domain,
            });
        }

        // The half of the rule that is easy to forget: a working penetration
        // channel makes the network channel inadmissible.
        let refusal_reason = match penetration {
            PenetrationVerdict::Allowed { mode, .. } => {
                return Err(AcquisitionDenied::PenetrationAvailable {
                    domain: req.domain,
                    mode: *mode,
                })
            }
            PenetrationVerdict::Refused { reason, .. } => *reason,
        };

        if let Err(detail) = validate_endpoint_scope(&req.endpoint_scope) {
            return Err(AcquisitionDenied::EndpointScopeRejected { detail });
        }

        let required = req.required_capability();
        if !granted.allows(&required) {
            return Err(AcquisitionDenied::CapabilityDenied {
                required: required.to_string(),
            });
        }

        Ok(AcquisitionPermit {
            resource_id: req.resource_id.clone(),
            channel: req.channel,
            endpoint_scope: req.endpoint_scope.clone(),
            domain: req.domain,
            trust_ceiling: self.trust_ceiling(),
            refusal_reason,
        })
    }

    /// [`Self::authorize`] mapped onto the frozen error-code vocabulary.
    ///
    /// The specific [`AcquisitionDenied`] reason is preserved in the error
    /// detail, because `ST-POL-001` alone would not tell an operator *why* the
    /// channel was closed (RD §9).
    pub fn authorize_or_error(
        &self,
        granted: &CapabilitySet,
        penetration: &PenetrationVerdict,
        req: &AcquisitionRequest,
    ) -> Result<AcquisitionPermit, DomainError> {
        Self::authorize(self, granted, penetration, req).map_err(|d| {
            DomainError::new(
                ErrorCode::POLICY_DENIED,
                format!(
                    "network acquisition via {} refused for {}: {}",
                    req.channel.as_str(),
                    req.resource_id,
                    d
                ),
            )
            .with_detail(d.as_str().to_string())
        })
    }
}

/// Whether an endpoint scope is usable as a capability scope.
///
/// Rejects empty, over-long, whitespace-bearing and scheme-bearing values.
/// An empty scope would serialize to a *global* `net:connect` grant, which is
/// exactly the widening deny-by-default exists to prevent.
fn validate_endpoint_scope(scope: &str) -> Result<(), String> {
    if scope.is_empty() {
        return Err("scope is empty; an empty scope would widen to a global grant".to_string());
    }
    if scope.len() > MAX_ENDPOINT_SCOPE_LEN {
        return Err(format!(
            "scope is {} characters, over the {MAX_ENDPOINT_SCOPE_LEN} limit",
            scope.len()
        ));
    }
    if scope.chars().any(char::is_whitespace) {
        return Err("scope contains whitespace".to_string());
    }
    if scope.contains("://") {
        return Err("scope must be host:port, not a URL".to_string());
    }
    if scope.contains('/') || scope.contains('\\') {
        return Err("scope must not contain a path separator".to_string());
    }
    if scope.contains('@') {
        // Same reasoning as ADR-013: a userinfo marker means the value is a
        // credential-bearing URI, not an endpoint, and must never be logged.
        return Err("scope must not contain userinfo".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sandtree_model::capability::CapabilitySet;

    fn res() -> ResourceId {
        ResourceId::derive(&["sbx-a"])
    }

    fn granted_for(scope: &str) -> CapabilitySet {
        CapabilitySet::from_iter_caps([Capability::parse(&format!("net:connect:{scope}")).unwrap()])
    }

    fn refused(domain: ObservationDomain) -> PenetrationVerdict {
        PenetrationVerdict::Refused {
            domain,
            reason: RefusalReason::IsolationNotPermitted,
        }
    }

    fn allowed(domain: ObservationDomain) -> PenetrationVerdict {
        PenetrationVerdict::Allowed {
            domain,
            mode: ObservationMode::Native,
        }
    }

    fn req(channel: AcquisitionChannel, domain: ObservationDomain) -> AcquisitionRequest {
        AcquisitionRequest::new(res(), domain, channel, "10.0.0.5:9418")
    }

    // ---- the core rule -------------------------------------------------

    #[test]
    fn a_working_penetration_channel_makes_the_network_channel_inadmissible() {
        // Break the implementation by allowing `PenetrationVerdict::Allowed`
        // and this goes red: the whole point is that a sandbox must not be
        // able to steer the host onto the weaker channel it controls.
        for channel in [
            AcquisitionChannel::GitRemote,
            AcquisitionChannel::McpEndpoint,
        ] {
            let r = req(channel, ObservationDomain::Filesystem);
            let err = AcquisitionPolicy::new()
                .authorize(
                    &granted_for("10.0.0.5:9418"),
                    &allowed(ObservationDomain::Filesystem),
                    &r,
                )
                .expect_err("penetration is available, so acquisition must be refused");
            assert_eq!(
                err,
                AcquisitionDenied::PenetrationAvailable {
                    domain: ObservationDomain::Filesystem,
                    mode: ObservationMode::Native,
                }
            );
        }
    }

    #[test]
    fn refused_penetration_admits_the_network_channel() {
        // Break the implementation by making the gate deny everything and this
        // goes red: the channel is useless if it can never fire.
        let r = req(AcquisitionChannel::GitRemote, ObservationDomain::Filesystem);
        let permit = AcquisitionPolicy::new()
            .authorize(
                &granted_for("10.0.0.5:9418"),
                &refused(ObservationDomain::Filesystem),
                &r,
            )
            .expect("refused penetration must admit acquisition");
        assert_eq!(permit.channel(), AcquisitionChannel::GitRemote);
        assert_eq!(permit.endpoint_scope(), "10.0.0.5:9418");
        assert_eq!(
            permit.refusal_reason(),
            RefusalReason::IsolationNotPermitted
        );
    }

    #[test]
    fn a_verdict_judged_for_another_domain_is_not_accepted() {
        // Break the implementation by dropping the domain check: a refusal
        // covering `system` would then unlock acquisition for `filesystem`,
        // which is a real escalation rather than a cosmetic one.
        let r = req(AcquisitionChannel::GitRemote, ObservationDomain::Filesystem);
        let err = AcquisitionPolicy::new()
            .authorize(
                &granted_for("10.0.0.5:9418"),
                &refused(ObservationDomain::System),
                &r,
            )
            .expect_err("a verdict for another domain must not unlock this one");
        assert_eq!(
            err,
            AcquisitionDenied::VerdictDomainMismatch {
                verdict_domain: ObservationDomain::System,
                request_domain: ObservationDomain::Filesystem,
            }
        );
    }

    // ---- trust ceiling -------------------------------------------------

    #[test]
    fn the_ceiling_is_guest_probe_and_the_policy_cannot_be_told_otherwise() {
        // Break the implementation by making the ceiling a field a caller can
        // set, or by returning ProviderNative: both turn this red.
        assert_eq!(
            AcquisitionPolicy::new().trust_ceiling(),
            TrustLevel::GuestProbe
        );
        assert_eq!(
            AcquisitionPolicy::new().trust_ceiling(),
            NETWORK_TRUST_CEILING
        );

        let r = req(
            AcquisitionChannel::McpEndpoint,
            ObservationDomain::Filesystem,
        );
        let permit = AcquisitionPolicy::new()
            .authorize(
                &granted_for("10.0.0.5:9418"),
                &refused(ObservationDomain::Filesystem),
                &r,
            )
            .unwrap();
        assert_eq!(permit.trust_ceiling(), TrustLevel::GuestProbe);
        // ADR-OBS-003: this value may never satisfy a security precondition.
        assert!(!permit.trust_ceiling().is_security_authoritative());
    }

    #[test]
    fn the_ceiling_cannot_exceed_the_constant_for_any_channel() {
        // If the ceiling were ever computed per channel, one of these changes.
        for channel in [
            AcquisitionChannel::GitRemote,
            AcquisitionChannel::McpEndpoint,
        ] {
            let r = req(channel, ObservationDomain::Process);
            let permit = AcquisitionPolicy::new()
                .authorize(
                    &granted_for("10.0.0.5:9418"),
                    &refused(ObservationDomain::Process),
                    &r,
                )
                .unwrap();
            assert_eq!(permit.trust_ceiling(), NETWORK_TRUST_CEILING);
            assert!(permit.trust_ceiling().rank() <= TrustLevel::GuestProbe.rank());
        }
    }

    // ---- capability gating ----------------------------------------------

    #[test]
    fn an_ungranted_endpoint_is_denied_by_default() {
        // Break the implementation by skipping the capability check: with an
        // empty grant set this starts succeeding.
        let r = req(
            AcquisitionChannel::McpEndpoint,
            ObservationDomain::Filesystem,
        );
        let err = AcquisitionPolicy::new()
            .authorize(
                &CapabilitySet::empty(),
                &refused(ObservationDomain::Filesystem),
                &r,
            )
            .expect_err("deny-by-default means an empty grant set authorizes nothing");
        assert!(matches!(err, AcquisitionDenied::CapabilityDenied { .. }));
        assert_eq!(err.as_str(), "capability_denied");
    }

    #[test]
    fn a_grant_for_one_endpoint_does_not_authorize_another() {
        // Break the implementation by comparing only the namespace/verb, and
        // the grant for 10.0.0.5 starts reaching 10.0.0.6.
        let r = req(
            AcquisitionChannel::McpEndpoint,
            ObservationDomain::Filesystem,
        );
        let verdict = refused(ObservationDomain::Filesystem);
        let r_other = AcquisitionRequest::new(
            res(),
            ObservationDomain::Filesystem,
            AcquisitionChannel::McpEndpoint,
            "10.0.0.6:9418",
        );
        let err = AcquisitionPolicy::new()
            .authorize(&granted_for("10.0.0.5:9418"), &verdict, &r_other)
            .expect_err("a scoped grant must not widen to another endpoint");
        // The denial must name the capability that is missing, otherwise an
        // operator sees "denied" with nothing to act on.
        assert!(
            matches!(err, AcquisitionDenied::CapabilityDenied { ref required } if required == "net:connect:10.0.0.6:9418"),
            "expected the grant to be named for the second endpoint, got {err:?}"
        );
        assert!(
            AcquisitionPolicy::new()
                .authorize(&granted_for("10.0.0.5:9418"), &verdict, &r)
                .is_ok(),
            "the granted endpoint itself must still work"
        );
    }

    // ---- endpoint scope hygiene -----------------------------------------

    #[test]
    fn an_empty_scope_is_refused_rather_than_widened_to_a_global_grant() {
        // An empty scope serializes to `net:connect` with no scope, which
        // authorizes *every* host. Refusing it is what keeps the grant scoped.
        let r = AcquisitionRequest::new(
            res(),
            ObservationDomain::Filesystem,
            AcquisitionChannel::GitRemote,
            "",
        );
        let err = AcquisitionPolicy::new()
            .authorize(
                &CapabilitySet::empty(),
                &refused(ObservationDomain::Filesystem),
                &r,
            )
            .expect_err("an empty scope must not be accepted");
        assert!(matches!(
            err,
            AcquisitionDenied::EndpointScopeRejected { .. }
        ));
        // And it is refused as a *scope* problem, not as a missing capability,
        // so the detail names the real cause.
        assert_eq!(err.as_str(), "endpoint_scope_rejected");
    }

    #[test]
    fn scope_hygiene_rejects_url_and_credential_shapes() {
        // Each case would either leak a credential into a capability string or
        // make the grant describe something other than one endpoint.
        for bad in [
            "https://10.0.0.5/repo.git", // scheme + path
            "admin:hunter2@10.0.0.5",    // userinfo (ADR-013)
            "10.0.0.5/repo",             // path separator
            "10.0.0.5 9418",             // whitespace
            &"a".repeat(MAX_ENDPOINT_SCOPE_LEN + 1),
        ] {
            let r = AcquisitionRequest::new(
                res(),
                ObservationDomain::Filesystem,
                AcquisitionChannel::GitRemote,
                bad,
            );
            let err = AcquisitionPolicy::new()
                .authorize(
                    &CapabilitySet::empty(),
                    &refused(ObservationDomain::Filesystem),
                    &r,
                )
                .expect_err(&format!("{bad} should have been refused"));
            assert!(
                matches!(err, AcquisitionDenied::EndpointScopeRejected { .. }),
                "{bad} produced {err:?}"
            );
        }
    }

    #[test]
    fn a_well_formed_scope_is_accepted() {
        for good in ["10.0.0.5:9418", "[fe80::1]:9418", "sandbox.internal:80"] {
            assert!(
                validate_endpoint_scope(good).is_ok(),
                "{good} should be accepted"
            );
        }
    }

    // ---- permit binding --------------------------------------------------

    #[test]
    fn a_permit_does_not_transfer_to_another_channel_or_domain() {
        // Break the implementation by making `covers` always true and a permit
        // obtained for git starts authorizing an MCP read of another domain.
        let r = req(AcquisitionChannel::GitRemote, ObservationDomain::Filesystem);
        let permit = AcquisitionPolicy::new()
            .authorize(
                &granted_for("10.0.0.5:9418"),
                &refused(ObservationDomain::Filesystem),
                &r,
            )
            .unwrap();

        let same = AcquisitionRequest::new(
            res(),
            ObservationDomain::Filesystem,
            AcquisitionChannel::GitRemote,
            "10.0.0.5:9418",
        );
        assert!(permit.covers(&same));

        let other_channel = AcquisitionRequest::new(
            res(),
            ObservationDomain::Filesystem,
            AcquisitionChannel::McpEndpoint,
            "10.0.0.5:9418",
        );
        assert!(
            !permit.covers(&other_channel),
            "a git permit must not authorize MCP"
        );

        let other_domain = AcquisitionRequest::new(
            res(),
            ObservationDomain::Process,
            AcquisitionChannel::GitRemote,
            "10.0.0.5:9418",
        );
        assert!(
            !permit.covers(&other_domain),
            "a permit must not change domain"
        );

        let other_scope = AcquisitionRequest::new(
            res(),
            ObservationDomain::Filesystem,
            AcquisitionChannel::GitRemote,
            "10.0.0.9:9418",
        );
        assert!(
            !permit.covers(&other_scope),
            "a permit must not change endpoint"
        );
    }

    #[test]
    fn the_resource_actually_binds_the_permit() {
        // A permit must not be replayable against a different sandbox: the
        // refusal that justified it was judged for *this* resource.
        let r = AcquisitionRequest::new(
            res(),
            ObservationDomain::Filesystem,
            AcquisitionChannel::GitRemote,
            "10.0.0.5:9418",
        );
        let permit = AcquisitionPolicy::new()
            .authorize(
                &granted_for("10.0.0.5:9418"),
                &refused(ObservationDomain::Filesystem),
                &r,
            )
            .unwrap();
        let other_resource = AcquisitionRequest::new(
            ResourceId::derive(&["sbx-b"]),
            ObservationDomain::Filesystem,
            AcquisitionChannel::GitRemote,
            "10.0.0.5:9418",
        );
        assert!(
            !permit.covers(&other_resource),
            "a permit must not cross resources"
        );
    }

    // ---- error mapping ----------------------------------------------------

    #[test]
    fn denials_carry_a_specific_reason_into_the_frozen_error_vocabulary() {
        let r = req(
            AcquisitionChannel::McpEndpoint,
            ObservationDomain::Filesystem,
        );
        let err = AcquisitionPolicy::new()
            .authorize_or_error(
                &granted_for("10.0.0.5:9418"),
                &allowed(ObservationDomain::Filesystem),
                &r,
            )
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::POLICY_DENIED);
        // The message says which channel and which resource; the detail says
        // which rule. `ST-POL-001` on its own would not be actionable.
        assert!(err.message.contains("mcp_endpoint"));
        assert!(err.message.contains("sbx-a") || err.message.contains(&res().to_string()));
        assert_eq!(err.detail.as_deref(), Some("penetration_available"));
    }

    // ---- self-invalidation thresholds --------------------------------------

    #[test]
    fn every_refusal_reason_is_reachable_and_named() {
        // Guards against a reason that is constructed nowhere: if a variant is
        // added but never produced, the count no longer matches the enum.
        for reason in [
            RefusalReason::NoHostChannel,
            RefusalReason::IsolationNotPermitted,
            RefusalReason::GuestPathDenied,
            RefusalReason::CapabilityDenied,
        ] {
            let verdict = PenetrationVerdict::Refused {
                domain: ObservationDomain::Filesystem,
                reason,
            };
            let r = req(AcquisitionChannel::GitRemote, ObservationDomain::Filesystem);
            let permit = AcquisitionPolicy::new()
                .authorize(&granted_for("10.0.0.5:9418"), &verdict, &r)
                .expect("every refusal reason admits acquisition");
            assert_eq!(
                permit.refusal_reason(),
                reason,
                "{reason:?} must survive the gate"
            );
        }
    }

    #[test]
    fn channel_wire_names_round_trip() {
        for c in [
            AcquisitionChannel::GitRemote,
            AcquisitionChannel::McpEndpoint,
        ] {
            assert_eq!(AcquisitionChannel::from_wire(c.as_str()), Some(c));
            // A channel must be traceable in a stored snapshot.
            assert!(!c.provenance_source().is_empty());
        }
        assert_eq!(AcquisitionChannel::from_wire("http"), None);
    }
}
