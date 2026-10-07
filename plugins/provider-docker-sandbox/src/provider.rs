//! SDK port implementations for the Docker Sandbox provider (DD-PLG §8).
//!
//! The provider is constructed from an already-resolved [`ProbeOutcome`] rather
//! than probing itself. That inversion is deliberate: it keeps the ladder in
//! [`crate::tier`] (pure, fully testable) and lets a caller inject a probe
//! result, which is the only way to test the CLI-absent and
//! API-unsupported paths on a machine where Docker happens to be running.

use sandtree_model::error::{DomainError, ErrorCode};
use sandtree_model::id::{PluginId, ResourceId};
use sandtree_model::operation::{
    OperationKind, OperationOutcome, OperationRequest, OperationState,
};
use sandtree_model::resource::{ResourceKind, ResourceNode};
use sandtree_observation_model::{
    ObservationCapabilities, ObservationRequest, ObservationSnapshot,
};
use sandtree_sdk::manifest::PluginKind;
use sandtree_sdk::ports::{
    DiscoverBatch, ObservationProvider, ProviderDescriptor, ProviderHealth, ResourceProvider,
};
use serde_json::json;

use crate::fixture;
use crate::observation;
use crate::tier::{ProbeOutcome, SandboxTier};
use crate::{PLUGIN_ID, PROVIDER_VERSION};

/// Provider configuration.
///
/// `observed_at` is injected rather than read from a clock so that every
/// snapshot a provider emits is reproducible.
#[derive(Debug, Clone)]
pub struct DockerSandboxConfig {
    /// Sandbox ids this provider owns, used when the API tier is unavailable
    /// and only the CLI can be consulted.
    pub known_sandboxes: Vec<(String, String)>,
    /// Timestamp stamped onto every snapshot this provider produces.
    pub observed_at: String,
}

impl DockerSandboxConfig {
    /// A configuration with no known sandboxes.
    pub fn empty(observed_at: impl Into<String>) -> Self {
        Self {
            known_sandboxes: Vec::new(),
            observed_at: observed_at.into(),
        }
    }

    /// Add a `(id, name)` sandbox.
    pub fn with_sandbox(mut self, id: impl Into<String>, name: impl Into<String>) -> Self {
        self.known_sandboxes.push((id.into(), name.into()));
        self
    }
}

/// The Docker Sandbox provider.
pub struct DockerSandboxProvider {
    config: DockerSandboxConfig,
    outcome: ProbeOutcome,
}

impl DockerSandboxProvider {
    /// Build a provider for an already-probed ladder outcome.
    pub fn new(config: DockerSandboxConfig, outcome: ProbeOutcome) -> Self {
        Self { config, outcome }
    }

    /// Build a provider that has determined neither API nor CLI is available.
    ///
    /// This is the DD-PLG §8 fixture path, kept as a named constructor so tests
    /// and callers do not have to hand-assemble the outcome.
    pub fn fixture_only(config: DockerSandboxConfig) -> Self {
        Self::new(
            config,
            ProbeOutcome::resolve(crate::tier::ApiSupport::absent(), false),
        )
    }

    /// The ladder rung this provider settled on.
    pub fn tier(&self) -> SandboxTier {
        self.outcome.tier
    }

    /// The probe outcome, including why this rung was chosen.
    pub fn outcome(&self) -> &ProbeOutcome {
        &self.outcome
    }

    /// Plugin id this provider registers under.
    pub fn plugin_id(&self) -> PluginId {
        PluginId::derive(&[PLUGIN_ID])
    }

    /// Whether a resource id belongs to the fixture world.
    ///
    /// Checked explicitly rather than relying on the two worlds simply not
    /// overlapping: an id set that drifts toward each other must fail loudly at
    /// the tier boundary instead of quietly resolving fixture data on a live
    /// runtime.
    pub fn is_fixture_id(id: &ResourceId) -> bool {
        fixture::fixture_batch()
            .resources
            .iter()
            .any(|n| &n.id == id)
    }
}

#[async_trait::async_trait]
impl ResourceProvider for DockerSandboxProvider {
    fn descriptor(&self) -> ProviderDescriptor {
        ProviderDescriptor {
            plugin_id: PLUGIN_ID.to_string(),
            version: PROVIDER_VERSION.to_string(),
            kind: PluginKind::Provider,
        }
    }

    async fn health(&self) -> Result<ProviderHealth, DomainError> {
        Ok(self.outcome.health())
    }

    /// Discovery.
    ///
    /// DD-PLG §8 makes the fixture tier a usable provider, so this never returns
    /// an empty batch just because the host API and CLI are both absent: an empty
    /// batch would tell reconcile that every sandbox disappeared (ADR-OBS-001).
    async fn discover(&self, _cursor: Option<String>) -> Result<DiscoverBatch, DomainError> {
        match self.outcome.tier {
            SandboxTier::Fixture => Ok(fixture::fixture_batch()),
            // At the CLI rung we still have the configured sandbox list, which
            // is real knowledge (the user told us these exist) even though the
            // states would be stale.
            SandboxTier::Cli | SandboxTier::Native => {
                let plugin = self.plugin_id();
                let mut resources: Vec<ResourceNode> = self
                    .config
                    .known_sandboxes
                    .iter()
                    .map(|(id, name)| {
                        ResourceNode::new(
                            ResourceId::derive(&["docker-sandbox", id.as_str()]),
                            ResourceKind::Sandbox,
                            plugin.clone(),
                            name.clone(),
                            // State is genuinely unknown from the CLI alone; the
                            // design forbids guessing (RD §9), so it is Unknown.
                            sandtree_model::resource::ResourceState::Unknown,
                            None,
                            self.config.observed_at.clone(),
                        )
                        .with_metadata(json!({
                            "provenance": crate::SOURCE_DOCKER_CLI,
                            "tier": self.outcome.tier.as_str(),
                            "api_detected": self.outcome.api.detected_version,
                        }))
                    })
                    .collect();
                resources.sort_by(|a, b| a.id.as_str().cmp(b.id.as_str()));
                Ok(DiscoverBatch {
                    resources,
                    relations: Vec::new(),
                    cursor: None,
                })
            }
        }
    }

    async fn inspect(&self, id: &ResourceId) -> Result<ResourceNode, DomainError> {
        // Search the tier's own world only. Falling back to another tier's world
        // would let a fixture id resolve while the API is up, and vice versa.
        if Self::is_fixture_id(id) && !matches!(self.outcome.tier, SandboxTier::Fixture) {
            return Err(DomainError::new(
                ErrorCode::CORE_INVALID,
                format!(
                    "{id} is fixture data and must not resolve at the {} tier",
                    self.outcome.tier.as_str()
                ),
            ));
        }
        let batch = self.discover(None).await?;
        batch
            .resources
            .into_iter()
            .find(|n| &n.id == id)
            .ok_or_else(|| {
                DomainError::new(
                    ErrorCode::CORE_INVALID,
                    format!(
                        "{id} is not known to this provider at tier {}",
                        self.outcome.tier.as_str()
                    ),
                )
            })
    }

    /// Lifecycle.
    ///
    /// The fixture tier refuses every mutating operation. A fixture world has no
    /// runtime, so reporting success would be a fabricated result (RD §9).
    async fn invoke(&self, req: &OperationRequest) -> Result<OperationOutcome, DomainError> {
        if !self.outcome.tier.control_is_available() {
            return Err(DomainError::new(
                ErrorCode::SANDBOX_PROVIDER_UNAVAILABLE,
                format!(
                    "{} is refused at the {} tier: there is no real runtime",
                    req.op.as_str(),
                    self.outcome.tier.as_str()
                ),
            ));
        }

        match req.op {
            OperationKind::Destroy | OperationKind::Stop => Err(DomainError::new(
                ErrorCode::SANDBOX_UNSUPPORTED,
                format!(
                    "{} needs the native sandboxes API; the {} tier cannot perform it",
                    req.op.as_str(),
                    self.outcome.tier.as_str()
                ),
            )),
            other => Ok(OperationOutcome {
                state: OperationState::Succeeded,
                error_code: None,
                result: json!({
                    "tier": self.outcome.tier.as_str(),
                    "op": other.as_str(),
                }),
            }),
        }
    }

    async fn shutdown(&self) {
        // No external handle is held: the ladder is pure and discovery reads
        // only injected state. Idempotent by construction.
    }
}

#[async_trait::async_trait]
impl ObservationProvider for DockerSandboxProvider {
    async fn capabilities(&self, id: &ResourceId) -> Result<ObservationCapabilities, DomainError> {
        Ok(observation::sandbox_capabilities(
            id,
            self.outcome.tier,
            self.outcome.api.detected_version.as_deref(),
        ))
    }

    async fn observe(&self, req: &ObservationRequest) -> Result<ObservationSnapshot, DomainError> {
        if !self.outcome.tier.observation_is_real() {
            // Still a snapshot, never an error (ADR-OBS-001).
            return Ok(observation::unavailable_snapshot(
                req.resource_id.clone(),
                self.outcome.tier,
                self.config.observed_at.clone(),
                &self.outcome.reason,
            ));
        }

        // Only domains this tier advertises may be answered. Replying to an
        // unsupported domain with an empty value would read as "none found".
        let caps = observation::sandbox_capabilities(
            &req.resource_id,
            self.outcome.tier,
            self.outcome.api.detected_version.as_deref(),
        );
        let supported = caps.domains_in(sandtree_observation_model::ObservationMode::Probe);

        let mut snap = ObservationSnapshot::empty(
            req.resource_id.clone(),
            sandtree_observation_model::ObservationMode::Probe,
            sandtree_observation_model::ObservationHealth::Healthy,
            self.config.observed_at.clone(),
        );

        for d in &req.domains {
            if !supported.contains(d) {
                snap.warn(format!(
                    "domain {} is not observable at the {} tier",
                    d.as_str(),
                    self.outcome.tier.as_str()
                ));
                continue;
            }
            // The injected fixture world supplies the payload shape; the tier
            // still bounds the trust applied to it.
            snap.insert(
                *d,
                sandtree_observation_model::ObservedValue::new(
                    json!({"tier": self.outcome.tier.as_str(), "domain": d.as_str()}),
                    sandtree_observation_model::Provenance::new(
                        observation::source_for_tier(self.outcome.tier),
                        observation::trust_for_tier(self.outcome.tier),
                        self.config.observed_at.clone(),
                    ),
                ),
            );
        }

        Ok(snap)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tier::{ApiSupport, ProbeOutcome};
    use crate::SOURCE_FIXTURE;
    use sandtree_model::resource::ResourceState;
    use sandtree_observation_model::{
        ObservationDomain, ObservationHealth, ObservationMode, TrustLevel,
    };

    fn cfg() -> DockerSandboxConfig {
        DockerSandboxConfig::empty("2026-01-01T00:00:00Z")
            .with_sandbox("alpha", "alpha-sandbox")
            .with_sandbox("beta", "beta-sandbox")
    }

    fn native() -> DockerSandboxProvider {
        DockerSandboxProvider::new(
            cfg(),
            ProbeOutcome::resolve(ApiSupport::supported("0.1"), true),
        )
    }

    fn cli() -> DockerSandboxProvider {
        DockerSandboxProvider::new(cfg(), ProbeOutcome::resolve(ApiSupport::absent(), true))
    }

    fn fixture() -> DockerSandboxProvider {
        DockerSandboxProvider::fixture_only(cfg())
    }

    fn destroy_req() -> OperationRequest {
        OperationRequest::new(
            fixture::fixture_sandbox_id("sbx-fixture-basic"),
            OperationKind::Destroy,
            serde_json::Value::Null,
            sandtree_model::resource::Correlation::generate(),
        )
    }

    #[tokio::test]
    async fn health_reflects_the_rung_reached() {
        assert_eq!(native().health().await.unwrap(), ProviderHealth::Healthy);
        assert!(matches!(
            cli().health().await.unwrap(),
            ProviderHealth::Degraded { .. }
        ));
        assert!(matches!(
            fixture().health().await.unwrap(),
            ProviderHealth::Unavailable { .. }
        ));
    }

    #[tokio::test]
    async fn the_descriptor_reports_the_provider_version() {
        let d = native().descriptor();
        assert_eq!(d.plugin_id, PLUGIN_ID);
        assert_eq!(d.version, PROVIDER_VERSION);
        assert_eq!(d.kind, PluginKind::Provider);
    }

    #[tokio::test]
    async fn the_fixture_tier_still_discovers_resources() {
        // The whole point of DD-PLG §8's fixture rung: no runtime, but still
        // something to reconcile against rather than an empty batch.
        let b = fixture().discover(None).await.unwrap();
        assert!(!b.resources.is_empty());
        assert!(!b.relations.is_empty());
    }

    #[tokio::test]
    async fn fixture_discovery_is_identical_across_provider_instances() {
        let a = fixture().discover(None).await.unwrap();
        let b = fixture().discover(None).await.unwrap();
        assert_eq!(a.resources, b.resources);
    }

    #[tokio::test]
    async fn the_fixture_tier_refuses_to_fabricate_lifecycle_success() {
        let err = fixture().invoke(&destroy_req()).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::SANDBOX_PROVIDER_UNAVAILABLE);
        // And the message must say why, not just that it failed.
        assert!(err.message.contains("fixture"), "{}", err.message);
    }

    #[tokio::test]
    async fn the_cli_tier_refuses_the_native_only_operations() {
        // `stop`/`destroy` need the sandboxes API; the CLI rung must not pretend.
        let err = cli().invoke(&destroy_req()).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::SANDBOX_UNSUPPORTED);
    }

    #[tokio::test]
    async fn the_cli_tier_reports_known_sandboxes_with_unknown_state() {
        let b = cli().discover(None).await.unwrap();
        assert_eq!(b.resources.len(), 2);
        for n in &b.resources {
            // Guessing a state from no data is exactly what RD §9 forbids.
            assert_eq!(n.state, ResourceState::Unknown);
            assert_eq!(n.meta_str("provenance"), Some(crate::SOURCE_DOCKER_CLI));
        }
    }

    #[tokio::test]
    async fn cli_discovery_is_sorted_by_id() {
        let b = cli().discover(None).await.unwrap();
        let ids: Vec<&str> = b.resources.iter().map(|n| n.id.as_str()).collect();
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        assert_eq!(ids, sorted);
    }

    #[tokio::test]
    async fn inspect_finds_a_fixture_sandbox_at_the_fixture_tier() {
        let p = fixture();
        let id = fixture::fixture_sandbox_id("sbx-fixture-basic");
        let n = p.inspect(&id).await.unwrap();
        assert_eq!(n.id, id);
        assert_eq!(n.kind, ResourceKind::Sandbox);
    }

    #[tokio::test]
    async fn inspect_rejects_a_fixture_id_when_the_api_tier_is_active() {
        // Tier isolation: a fixture id must not resolve once a real runtime
        // answers, otherwise fixture data leaks into a healthy topology.
        let p = native();
        let err = p
            .inspect(&fixture::fixture_sandbox_id("sbx-fixture-basic"))
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::CORE_INVALID);
        assert!(err.message.contains("native"), "{}", err.message);
    }

    #[tokio::test]
    async fn inspect_reports_a_stable_error_for_an_unknown_id() {
        let p = native();
        let id = ResourceId::derive(&["docker-sandbox", "nope"]);
        let a = p.inspect(&id).await.unwrap_err();
        let b = p.inspect(&id).await.unwrap_err();
        assert_eq!(a.code, b.code);
        assert_eq!(a.code, ErrorCode::CORE_INVALID);
    }

    #[tokio::test]
    async fn the_fixture_tier_refuses_a_fixture_id_at_the_cli_tier() {
        // Same isolation rule as the native case, so a fixture id never leaks.
        let err = cli()
            .inspect(&fixture::fixture_sandbox_id("sbx-fixture-basic"))
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::CORE_INVALID);
    }

    #[tokio::test]
    async fn is_fixture_id_helper_agrees_with_the_batch() {
        assert!(DockerSandboxProvider::is_fixture_id(
            &fixture::fixture_sandbox_id("sbx-fixture-basic")
        ));
        assert!(!DockerSandboxProvider::is_fixture_id(&ResourceId::derive(
            &["docker-sandbox", "alpha"]
        )));
    }

    #[tokio::test]
    async fn observation_at_the_fixture_tier_is_unavailable_not_an_error() {
        let snap = fixture()
            .observe(&ObservationRequest::new(
                fixture::fixture_sandbox_id("sbx-fixture-basic"),
                vec![ObservationDomain::System],
            ))
            .await
            .expect("a degraded plane answers");
        assert_eq!(snap.health, ObservationHealth::Unavailable);
        assert!(!snap.warnings.is_empty());
    }

    #[tokio::test]
    async fn native_observation_never_exceeds_guest_probe() {
        let snap = native()
            .observe(&ObservationRequest::new(
                ResourceId::derive(&["docker-sandbox", "alpha"]),
                vec![ObservationDomain::Process, ObservationDomain::Filesystem],
            ))
            .await
            .unwrap();
        for d in [ObservationDomain::Process, ObservationDomain::Filesystem] {
            let v = snap.get(d).expect("native tier answers process and file");
            assert_eq!(
                v.provenance.trust,
                TrustLevel::GuestProbe,
                "{d:?} rose above guest-probe"
            );
        }
    }

    #[tokio::test]
    async fn the_cli_tier_warns_instead_of_fabricating_a_process_listing() {
        let snap = cli()
            .observe(&ObservationRequest::new(
                ResourceId::derive(&["docker-sandbox", "alpha"]),
                vec![ObservationDomain::Process, ObservationDomain::Network],
            ))
            .await
            .unwrap();
        assert!(snap.get(ObservationDomain::Process).is_none());
        assert!(snap.get(ObservationDomain::Network).is_some());
        assert!(
            snap.warnings.iter().any(|w| w.contains("not observable")),
            "an unsupported domain must be reported, not silently dropped: {:?}",
            snap.warnings
        );
    }

    #[tokio::test]
    async fn capabilities_offer_exactly_the_modes_we_answer() {
        let caps = native()
            .capabilities(&ResourceId::derive(&["docker-sandbox", "alpha"]))
            .await
            .unwrap();
        assert_eq!(caps.modes, vec![ObservationMode::Probe]);
        assert!(caps.supports(ObservationMode::Probe));
    }

    #[tokio::test]
    async fn shutdown_is_idempotent() {
        let p = native();
        p.shutdown().await;
        p.shutdown().await;
        // Still usable afterwards: shutdown released nothing that mattered.
        assert!(p.discover(None).await.is_ok());
    }

    #[tokio::test]
    async fn fixture_nodes_declare_fixture_provenance() {
        let b = fixture().discover(None).await.unwrap();
        assert!(b
            .resources
            .iter()
            .all(|n| n.meta_str("provenance") == Some(SOURCE_FIXTURE)));
    }
}
