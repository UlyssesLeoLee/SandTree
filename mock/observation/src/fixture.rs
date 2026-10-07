//! Declarative fixture format for the mock observation plane.
//!
//! A fixture is a small, hand-auditable JSON document that describes one
//! scripted world: which resources exist, what each can observe, how much the
//! data is trusted, and which fault it runs into. Nothing in it is looked up at
//! runtime — no wall clock, no randomness, no environment probing (NFR-O04), so
//! the same fixture yields byte-identical snapshots on every run.
//!
//! # Why validation is strict
//!
//! A fixture is test *input*, and a malformed one would turn a real defect into
//! a confusing assertion failure three layers away. Every rule below is checked
//! at load time by [`ObservationFixture::validate`]:
//!
//! 1. the `schema` tag must be this crate's version;
//! 2. every resource must declare at least one mode;
//! 3. the domain list must be sorted and free of duplicates;
//! 4. every declared domain must have a value, unless the resource's fault
//!    withholds it — coverage gaps are scripted with
//!    [`ObservationFault::PartialCoverage`], never by omission;
//! 5. a per-mode domain restriction must be a subset of the global list;
//! 6. `observed_at` must parse as RFC3339, and a resource that declares itself
//!    `stale` must declare a non-zero age.
//!
//! # Fixture hygiene
//!
//! No fixture may name a real host path or a credential. Guest payloads use
//! relative paths only, and credential faults describe *the absence* of a
//! credential, never its value (NFR-S03, NFR-S08). `tests/fixture_corpus.rs`
//! enforces this by scanning every shipped fixture.

use std::collections::BTreeMap;
use std::path::Path;

use sandtree_model::id::ResourceId;
use sandtree_observation_model::{
    ObservationDomain, ObservationHealth, ObservationMode, TrustLevel,
};
use serde::{Deserialize, Serialize};
use serde_json::Value as Json;

use crate::fault::{FaultDisposition, ObservationFault};

/// Fixture schema tag this crate understands.
pub const FIXTURE_SCHEMA: &str = "sandtree.mock.observation.v1";

/// Errors produced while loading or validating a fixture.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FixtureError {
    /// The document is not valid JSON, or its shape is wrong.
    #[error("fixture is not valid JSON: {0}")]
    Malformed(String),
    /// The `schema` tag is not [`FIXTURE_SCHEMA`].
    #[error("fixture schema {found:?} is not {expected:?}")]
    SchemaMismatch {
        /// Tag found in the document.
        found: String,
        /// Tag this crate requires.
        expected: String,
    },
    /// Two resources declare the same identity.
    #[error("fixture declares resource {id} twice")]
    DuplicateResource {
        /// The repeated identity.
        id: String,
    },
    /// A resource declares no observation mode.
    #[error("resource {id} declares no observation mode")]
    NoModes {
        /// The offending resource.
        id: String,
    },
    /// A resource declares no domains.
    #[error("resource {id} declares no observation domain")]
    NoDomains {
        /// The offending resource.
        id: String,
    },
    /// A domain list is unsorted or contains duplicates.
    #[error("resource {id} domain list for mode {mode} must be sorted and duplicate-free")]
    UnsortedDomains {
        /// The offending resource.
        id: String,
        /// The mode whose list is wrong.
        mode: String,
    },
    /// A declared domain has no value and no fault withholding it.
    #[error("resource {id} declares domain {domain} but supplies no value for it")]
    MissingValue {
        /// The offending resource.
        id: String,
        /// The domain with no value.
        domain: String,
    },
    /// A per-mode domain list names a domain the resource does not declare.
    #[error("resource {id} restricts mode {mode} to {domain}, which it does not declare")]
    RestrictionOutsideDeclaration {
        /// The offending resource.
        id: String,
        /// The mode carrying the restriction.
        mode: String,
        /// The offending domain.
        domain: String,
    },
    /// `observed_at` is not RFC3339.
    #[error("resource {id} has observed_at {value:?}, which is not RFC3339")]
    BadTimestamp {
        /// The offending resource.
        id: String,
        /// The rejected timestamp.
        value: String,
    },
    /// A resource declares itself stale without declaring an age.
    #[error("resource {id} declares health stale with freshness_ms 0")]
    StaleWithoutAge {
        /// The offending resource.
        id: String,
    },
    /// The fixture has no provenance source, so values could not be labelled.
    #[error("fixture source must not be empty")]
    EmptySource,
    /// The file could not be read.
    #[error("fixture file {path} could not be read: {reason}")]
    Io {
        /// Path as given.
        path: String,
        /// Underlying reason.
        reason: String,
    },
}

/// One scripted resource and everything observation may say about it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResourceObservation {
    /// Identity parts, fed to [`ResourceId::derive`].
    #[serde(rename = "resource")]
    resource_parts: Vec<String>,
    /// Modes this resource supports, best (least invasive) first.
    #[serde(default = "default_modes")]
    modes: Vec<ObservationMode>,
    /// Domains this resource can report, sorted.
    #[serde(default)]
    domains: Vec<ObservationDomain>,
    /// Per-mode restriction, keyed by [`ObservationMode::as_str`].
    #[serde(default)]
    mode_domains: BTreeMap<String, Vec<ObservationDomain>>,
    /// Domain payload, keyed by [`ObservationDomain::as_str`].
    #[serde(default)]
    values: BTreeMap<String, Json>,
    /// Trust the fixture claims for this resource's values.
    #[serde(default = "default_trust")]
    trust: TrustLevel,
    /// Optional fixture ceiling; may only *lower* the mode ceiling.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    declared_ceiling: Option<TrustLevel>,
    /// Channel state the fixture asserts.
    #[serde(default = "default_health")]
    health: ObservationHealth,
    /// Fault this resource runs into, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    fault: Option<ObservationFault>,
    /// Overrides [`ObservationFault::default_disposition`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    disposition: Option<FaultDisposition>,
    /// Attach a BLAKE3 evidence hash to every value (never raises trust).
    #[serde(default)]
    attach_evidence: bool,
    /// Observation timestamp; RFC3339, never "now".
    #[serde(default = "default_observed_at")]
    observed_at: String,
    /// Age reported in provenance.
    #[serde(default)]
    freshness_ms: u64,
    /// Collector/probe version, when the mode used one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    collector_version: Option<String>,
}

fn default_modes() -> Vec<ObservationMode> {
    vec![ObservationMode::Metadata]
}

fn default_trust() -> TrustLevel {
    TrustLevel::HostNative
}

fn default_health() -> ObservationHealth {
    ObservationHealth::Healthy
}

fn default_observed_at() -> String {
    DEFAULT_OBSERVED_AT.to_string()
}

/// Fixed timestamp every fixture uses unless it declares its own.
///
/// A constant, not a clock read: mock snapshots must be byte-identical across
/// runs and machines (NFR-O04).
pub const DEFAULT_OBSERVED_AT: &str = "2026-10-07T00:00:00Z";

impl Default for ResourceObservation {
    fn default() -> Self {
        Self {
            resource_parts: Vec::new(),
            modes: default_modes(),
            domains: vec![ObservationDomain::System],
            mode_domains: BTreeMap::new(),
            values: BTreeMap::from([(
                ObservationDomain::System.as_str().to_string(),
                Json::Null,
            )]),
            trust: default_trust(),
            declared_ceiling: None,
            health: default_health(),
            fault: None,
            disposition: None,
            attach_evidence: false,
            observed_at: default_observed_at(),
            freshness_ms: 0,
            collector_version: None,
        }
    }
}

impl ResourceObservation {
    /// A resource with the smallest honest default: metadata mode, one `system`
    /// domain, `host_native` trust, healthy.
    ///
    /// The defaults deliberately sit *at* the mode ceiling rather than above
    /// it, so a builder that forgets to declare trust still produces a valid
    /// fixture.
    pub fn new(resource_parts: &[&str]) -> Self {
        Self {
            resource_parts: resource_parts.iter().map(|s| s.to_string()).collect(),
            ..Self::default()
        }
    }

    /// Replace the supported modes (order is preserved as written).
    pub fn with_modes(self, modes: &[ObservationMode]) -> Self {
        Self {
            modes: modes.to_vec(),
            ..self
        }
    }

    /// Add one supported mode.
    pub fn mode(self, mode: ObservationMode) -> Self {
        let mut modes = self.modes;
        if !modes.contains(&mode) {
            modes.push(mode);
        }
        Self { modes, ..self }
    }

    /// Declare the domains this resource can report.
    pub fn with_domains(self, domains: &[ObservationDomain]) -> Self {
        Self {
            domains: domains.to_vec(),
            ..self
        }
    }

    /// Supply the payload for one domain.
    ///
    /// The domain is added to the global list, so the builder cannot produce a
    /// value for an undeclared domain by accident.
    pub fn with_value(mut self, domain: ObservationDomain, value: Json) -> Self {
        if !self.domains.contains(&domain) {
            self.domains.push(domain);
        }
        self.values.insert(domain.as_str().to_string(), value);
        self
    }

    /// Restrict one mode to a subset of the declared domains.
    pub fn with_mode_domains(self, mode: ObservationMode, domains: &[ObservationDomain]) -> Self {
        let mut mode_domains = self.mode_domains;
        mode_domains.insert(mode.as_str().to_string(), domains.to_vec());
        Self {
            mode_domains,
            ..self
        }
    }

    /// Declare the trust this resource's values claim.
    pub fn with_trust(self, trust: TrustLevel) -> Self {
        Self {
            trust,
            ..self
        }
    }

    /// Declare a ceiling that may only lower the mode ceiling.
    pub fn with_declared_ceiling(self, ceiling: TrustLevel) -> Self {
        Self {
            declared_ceiling: Some(ceiling),
            ..self
        }
    }

    /// Declare the channel state.
    pub fn with_health(self, health: ObservationHealth) -> Self {
        Self {
            health,
            ..self
        }
    }

    /// Script a fault.
    pub fn with_fault(self, fault: ObservationFault) -> Self {
        Self {
            fault: Some(fault),
            ..self
        }
    }

    /// Override the fault's default disposition.
    pub fn with_disposition(self, disposition: FaultDisposition) -> Self {
        Self {
            disposition: Some(disposition),
            ..self
        }
    }

    /// Attach a BLAKE3 evidence hash to every value.
    ///
    /// Exists to prove that a verified payload does not raise trust
    /// (ADR-OBS-003): the hash travels, the rung does not move.
    pub fn evidence(self, attach: bool) -> Self {
        Self {
            attach_evidence: attach,
            ..self
        }
    }

    /// Set the observation timestamp.
    pub fn with_observed_at(self, observed_at: impl Into<String>) -> Self {
        Self {
            observed_at: observed_at.into(),
            ..self
        }
    }

    /// Set the age reported in provenance.
    pub fn with_freshness_ms(self, freshness_ms: u64) -> Self {
        Self {
            freshness_ms,
            ..self
        }
    }

    /// Set the collector/probe version.
    pub fn with_collector_version(self, version: impl Into<String>) -> Self {
        Self {
            collector_version: Some(version.into()),
            ..self
        }
    }

    /// This resource's derived identity.
    pub fn id(&self) -> ResourceId {
        let parts: Vec<&str> = self.resource_parts.iter().map(String::as_str).collect();
        ResourceId::derive(&parts)
    }

    /// Identity parts as written in the fixture.
    pub fn resource_parts(&self) -> &[String] {
        &self.resource_parts
    }

    /// Supported modes, in fixture order.
    pub fn modes(&self) -> &[ObservationMode] {
        &self.modes
    }

    /// Declared domains.
    pub fn domains(&self) -> &[ObservationDomain] {
        &self.domains
    }

    /// Domains obtainable in one mode: the restriction if declared, else all.
    pub fn domains_in(&self, mode: ObservationMode) -> Vec<ObservationDomain> {
        match self.mode_domains.get(mode.as_str()) {
            Some(list) => list.clone(),
            None => self.domains.clone(),
        }
    }

    /// Payload for one domain.
    pub fn value_for(&self, domain: ObservationDomain) -> Option<&Json> {
        self.values.get(domain.as_str())
    }

    /// Trust the fixture claims.
    pub fn trust(&self) -> TrustLevel {
        self.trust
    }

    /// Fixture-declared ceiling override, if any.
    pub fn declared_ceiling(&self) -> Option<TrustLevel> {
        self.declared_ceiling
    }

    /// Declared channel state.
    pub fn health(&self) -> ObservationHealth {
        self.health
    }

    /// The scripted fault, if any.
    pub fn fault(&self) -> Option<&ObservationFault> {
        self.fault.as_ref()
    }

    /// The effective disposition for this resource's fault.
    pub fn disposition(&self) -> Option<FaultDisposition> {
        match (&self.fault, self.disposition) {
            (None, _) => None,
            (Some(_), Some(d)) => Some(d),
            (Some(fault), None) => Some(fault.default_disposition()),
        }
    }

    /// Whether values carry an evidence hash.
    pub fn attaches_evidence(&self) -> bool {
        self.attach_evidence
    }

    /// The fixture's timestamp.
    pub fn observed_at(&self) -> &str {
        &self.observed_at
    }

    /// The fixture's declared age.
    pub fn freshness_ms(&self) -> u64 {
        self.freshness_ms
    }

    /// The fixture's collector/probe version, if any.
    pub fn collector_version(&self) -> Option<&str> {
        self.collector_version.as_deref()
    }

    /// Check every fixture rule for this resource.
    pub fn validate(&self) -> Result<(), FixtureError> {
        let id = self.id().as_str().to_string();

        if self.modes.is_empty() {
            return Err(FixtureError::NoModes { id });
        }
        if self.domains.is_empty() {
            return Err(FixtureError::NoDomains { id });
        }
        for mode in &self.modes {
            let list = self.domains_in(*mode);
            if !is_sorted_and_unique(&list) {
                return Err(FixtureError::UnsortedDomains {
                    id,
                    mode: mode.as_str().to_string(),
                });
            }
        }
        // Coverage gaps must be declared as a fault, never as a silent hole.
        // `health` is exempt: the provider synthesises it for every collection,
        // so a fixture value for it would be dead weight (DD-OBS §5).
        let withheld: Vec<&str> = self
            .fault
            .as_ref()
            .map(|f| f.withheld_domains().iter().map(|d| d.as_str()).collect())
            .unwrap_or_default();
        for domain in &self.domains {
            if *domain == ObservationDomain::Health {
                continue;
            }
            if !self.values.contains_key(domain.as_str()) && !withheld.contains(&domain.as_str()) {
                return Err(FixtureError::MissingValue {
                    id,
                    domain: domain.as_str().to_string(),
                });
            }
        }
        for mode in &self.modes {
            for domain in self.domains_in(*mode) {
                if !self.domains.contains(&domain) {
                    return Err(FixtureError::RestrictionOutsideDeclaration {
                        id,
                        mode: mode.as_str().to_string(),
                        domain: domain.as_str().to_string(),
                    });
                }
            }
        }
        if chrono::DateTime::parse_from_rfc3339(&self.observed_at).is_err() {
            return Err(FixtureError::BadTimestamp {
                id,
                value: self.observed_at.clone(),
            });
        }
        if self.health == ObservationHealth::Stale && self.freshness_ms == 0 {
            return Err(FixtureError::StaleWithoutAge { id });
        }
        Ok(())
    }
}

/// Whether a domain list is sorted and free of duplicates.
fn is_sorted_and_unique(list: &[ObservationDomain]) -> bool {
    list.windows(2).all(|w| w[0] < w[1])
}

/// A complete scripted observation world.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ObservationFixture {
    /// Schema tag; must equal [`FIXTURE_SCHEMA`].
    pub schema: String,
    /// Provenance source recorded on every value, e.g. `mock-probe`.
    pub source: String,
    /// Scripted resources, keyed by derived identity so iteration is sorted.
    #[serde(default)]
    resources: BTreeMap<String, ResourceObservation>,
}

impl ObservationFixture {
    /// An empty fixture carrying a provenance source.
    pub fn new(source: impl Into<String>) -> Self {
        Self {
            schema: FIXTURE_SCHEMA.to_string(),
            source: source.into(),
            resources: BTreeMap::new(),
        }
    }

    /// Add a resource, replacing any resource with the same identity.
    pub fn with_resource(mut self, resource: ResourceObservation) -> Self {
        self.resources
            .insert(resource.id().as_str().to_string(), resource);
        self
    }

    /// Parse and validate a fixture from JSON.
    pub fn from_json(text: &str) -> Result<Self, FixtureError> {
        let fixture: Self = serde_json::from_str(text)
            .map_err(|e| FixtureError::Malformed(e.to_string()))?;
        fixture.validate()?;
        Ok(fixture)
    }

    /// Read, parse and validate a fixture from disk.
    pub fn from_path(path: &Path) -> Result<Self, FixtureError> {
        let text = std::fs::read_to_string(path).map_err(|e| FixtureError::Io {
            path: path.display().to_string(),
            reason: e.to_string(),
        })?;
        Self::from_json(&text)
    }

    /// The provenance source recorded on every value.
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Look up one resource.
    pub fn resource(&self, id: &ResourceId) -> Option<&ResourceObservation> {
        self.resources.get(id.as_str())
    }

    /// Scripted identities, sorted.
    pub fn resource_ids(&self) -> Vec<ResourceId> {
        self.resources
            .values()
            .map(ResourceObservation::id)
            .collect()
    }

    /// Every scripted resource, in identity order.
    pub fn resources(&self) -> impl Iterator<Item = &ResourceObservation> {
        self.resources.values()
    }

    /// Number of scripted resources.
    pub fn len(&self) -> usize {
        self.resources.len()
    }

    /// Whether no resource is scripted.
    pub fn is_empty(&self) -> bool {
        self.resources.is_empty()
    }

    /// Check every fixture rule.
    pub fn validate(&self) -> Result<(), FixtureError> {
        if self.schema != FIXTURE_SCHEMA {
            return Err(FixtureError::SchemaMismatch {
                found: self.schema.clone(),
                expected: FIXTURE_SCHEMA.to_string(),
            });
        }
        if self.source.trim().is_empty() {
            return Err(FixtureError::EmptySource);
        }
        for resource in self.resources.values() {
            resource.validate()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn resource() -> ResourceObservation {
        ResourceObservation::new(&["mock", "unit"])
            .mode(ObservationMode::Probe)
            .with_domains(&[ObservationDomain::System, ObservationDomain::Process])
            .with_value(ObservationDomain::System, json!({"os": "windows"}))
            .with_value(ObservationDomain::Process, json!({"pids": [1]}))
            .with_trust(TrustLevel::GuestProbe)
    }

    #[test]
    fn a_default_resource_is_valid_and_metadata_only() {
        let r = ResourceObservation::new(&["mock", "unit"]);
        r.validate().expect("defaults validate");
        assert_eq!(r.modes(), &[ObservationMode::Metadata]);
        assert_eq!(r.trust(), TrustLevel::HostNative);
        assert_eq!(r.domains(), &[ObservationDomain::System]);
        assert_eq!(
            r.value_for(ObservationDomain::System),
            Some(&Json::Null)
        );
    }

    #[test]
    fn identity_is_derived_from_the_parts() {
        let a = ResourceObservation::new(&["mock", "unit"]).id();
        let b = ResourceObservation::new(&["mock", "unit"]).id();
        let c = ResourceObservation::new(&["mock", "other"]).id();
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn values_must_exist_for_every_declared_domain() {
        let r = ResourceObservation::new(&["mock", "unit"])
            .with_domains(&[ObservationDomain::System, ObservationDomain::Network]);
        assert_eq!(
            r.validate(),
            Err(FixtureError::MissingValue {
                id: r.id().as_str().to_string(),
                domain: "network".to_string(),
            })
        );
    }

    #[test]
    fn a_partial_coverage_fault_may_withhold_a_domain() {
        let r = ResourceObservation::new(&["mock", "unit"])
            .with_domains(&[ObservationDomain::System, ObservationDomain::Network])
            .with_fault(ObservationFault::PartialCoverage {
                missing_domains: vec![ObservationDomain::Network],
            });
        r.validate().expect("the withheld domain is accounted for");
        assert_eq!(
            r.fault().map(|f| f.withheld_domains().to_vec()),
            Some(vec![ObservationDomain::Network])
        );
    }

    #[test]
    fn a_stale_resource_must_declare_an_age() {
        let r = resource().with_health(ObservationHealth::Stale);
        assert_eq!(
            r.validate(),
            Err(FixtureError::StaleWithoutAge {
                id: r.id().as_str().to_string()
            })
        );
        resource()
            .with_health(ObservationHealth::Stale)
            .with_freshness_ms(90_000)
            .validate()
            .expect("a stale resource with an age is valid");
    }

    #[test]
    fn an_unparsable_timestamp_is_refused() {
        let r = resource().with_observed_at("last tuesday");
        assert!(matches!(r.validate(), Err(FixtureError::BadTimestamp { .. })));
    }

    #[test]
    fn a_mode_restriction_must_be_a_subset() {
        let r = resource().with_mode_domains(ObservationMode::Probe, &[ObservationDomain::Network]);
        assert_eq!(
            r.validate(),
            Err(FixtureError::RestrictionOutsideDeclaration {
                id: r.id().as_str().to_string(),
                mode: "probe".to_string(),
                domain: "network".to_string(),
            })
        );
    }

    #[test]
    fn an_unsorted_domain_list_is_refused() {
        // Sorted means `ObservationDomain` declaration order
        // (system, process, filesystem, network, docker, health) — the same
        // order `provider::select_mode` and the snapshot builder use, not
        // alphabetical. So `filesystem` after `system` is correct and
        // `filesystem` before it is the violation.
        let sorted = ResourceObservation::new(&["mock", "unit"])
            .with_domains(&[ObservationDomain::System, ObservationDomain::Filesystem])
            .with_value(ObservationDomain::System, json!({}))
            .with_value(ObservationDomain::Filesystem, json!({}));
        sorted
            .validate()
            .expect("declaration order is the sorted order");
        assert!(sorted.domains()[0] < sorted.domains()[1]);

        let unsorted = ResourceObservation::new(&["mock", "unit"])
            .with_domains(&[ObservationDomain::Filesystem, ObservationDomain::System])
            .with_value(ObservationDomain::System, json!({}))
            .with_value(ObservationDomain::Filesystem, json!({}));
        assert_eq!(
            unsorted.validate(),
            Err(FixtureError::UnsortedDomains {
                id: unsorted.id().as_str().to_string(),
                mode: "metadata".to_string(),
            })
        );
    }

    #[test]
    fn a_resource_without_modes_is_refused() {
        let r = resource().with_modes(&[]);
        assert_eq!(
            r.validate(),
            Err(FixtureError::NoModes {
                id: r.id().as_str().to_string()
            })
        );
    }

    #[test]
    fn a_wrong_schema_tag_is_refused() {
        let text = json!({
            "schema": "sandtree.mock.observation.v99",
            "source": "mock",
            "resources": {}
        })
        .to_string();
        assert_eq!(
            ObservationFixture::from_json(&text),
            Err(FixtureError::SchemaMismatch {
                found: "sandtree.mock.observation.v99".to_string(),
                expected: FIXTURE_SCHEMA.to_string(),
            })
        );
    }

    #[test]
    fn malformed_json_is_reported_as_such() {
        assert!(matches!(
            ObservationFixture::from_json("{not json"),
            Err(FixtureError::Malformed(_))
        ));
    }

    #[test]
    fn an_empty_source_is_refused() {
        let f = ObservationFixture::from_json(&json!({
            "schema": FIXTURE_SCHEMA,
            "source": "   ",
            "resources": {}
        })
        .to_string());
        assert_eq!(f, Err(FixtureError::EmptySource));
    }

    #[test]
    fn a_fixture_round_trips_through_json_unchanged() {
        let fixture = ObservationFixture::new("mock-probe").with_resource(
            resource().evidence(true).with_collector_version("probe/1"),
        );
        let text = serde_json::to_string_pretty(&fixture).expect("serialize");
        let parsed = ObservationFixture::from_json(&text).expect("parse");
        assert_eq!(parsed, fixture);
    }

    #[test]
    fn resource_ids_are_sorted_and_deduplicated() {
        let fixture = ObservationFixture::new("mock")
            .with_resource(ResourceObservation::new(&["mock", "zeta"]))
            .with_resource(ResourceObservation::new(&["mock", "alpha"]))
            .with_resource(ResourceObservation::new(&["mock", "alpha"]));
        assert_eq!(fixture.len(), 2);
        let ids: Vec<String> = fixture
            .resource_ids()
            .iter()
            .map(|i| i.as_str().to_string())
            .collect();
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(ids, sorted);
        assert_eq!(fixture.len(), 2);
    }

    #[test]
    fn disposition_defaults_to_the_fault_policy() {
        let r = resource().with_fault(ObservationFault::ProbeBootstrapFailed {
            reason: "no bridge".into(),
        });
        assert_eq!(
            r.disposition(),
            Some(FaultDisposition::UnavailableSnapshot)
        );
        let surfaced = resource().with_fault(ObservationFault::InvalidEnvelope {
            reason: "schema".into(),
        });
        assert_eq!(surfaced.disposition(), Some(FaultDisposition::SurfaceError));
        assert_eq!(
            surfaced.with_disposition(FaultDisposition::UnavailableSnapshot).disposition(),
            Some(FaultDisposition::UnavailableSnapshot)
        );
        assert_eq!(resource().disposition(), None);
    }
}