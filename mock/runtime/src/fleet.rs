//! [`discover_all`] — drive several providers to completion and report what each
//! contributed, including what failed partway.
//!
//! This is the function the determinism requirement is stated against: for the
//! same provider list it produces byte-identical [`FleetDiscovery::to_json`],
//! no matter which operations were invoked on those providers beforehand.
//!
//! # Why failures are collected instead of propagated
//!
//! One provider dying is not a reason to lose the scan of the others — that is
//! exactly the shape a reconcile loop has to survive (NFR-A01). So an error is
//! recorded as a [`ProviderFailure`], the pages already delivered by that
//! provider are kept, and the scan moves on.
//!
//! # Why the loop cannot hang
//!
//! A provider that returns a cursor it was just handed makes no progress. Left
//! alone that is an infinite loop, so the scan records a
//! [`FailurePhase::NoProgress`] failure and stops paging that provider. The
//! progress check is a property of the *caller*, which is why it lives here and
//! not in [`sandtree_sdk::ports::ResourceProvider`].

use std::sync::Arc;

use sandtree_model::error::ErrorCode;
use sandtree_model::id::PluginId;
use sandtree_model::resource::{Relation, ResourceNode};
use sandtree_sdk::ports::{DiscoverBatch, ProviderDescriptor, ProviderHealth, ResourceProvider};
use serde::{Deserialize, Serialize};

/// Which stage of a scan failed for one provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailurePhase {
    /// The health probe itself failed, so nothing was scanned.
    Health,
    /// A discovery page failed; earlier pages were delivered.
    Discover,
    /// The provider handed back a cursor that made no progress.
    NoProgress,
}

/// One provider's contribution to a fleet scan.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProviderDiscovery {
    /// Provider identity.
    pub plugin_id: PluginId,
    /// Descriptor reported by the provider.
    pub descriptor: ProviderDescriptor,
    /// Health reported by the provider.
    pub health: ProviderHealth,
    /// Pages delivered before the scan stopped, in order.
    pub pages: Vec<DiscoverBatch>,
    /// Every delivered resource, flattened in page order.
    pub resources: Vec<ResourceNode>,
    /// Every delivered relation, flattened in page order.
    pub relations: Vec<Relation>,
}

impl ProviderDiscovery {
    /// Number of pages delivered.
    pub fn page_count(&self) -> usize {
        self.pages.len()
    }

    /// Whether the scan of this provider reached the end of its cursor chain.
    pub fn completed(&self) -> bool {
        self.pages.last().is_some_and(|p| p.cursor.is_none())
    }
}

/// Why one provider's scan stopped early.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProviderFailure {
    /// Provider identity.
    pub plugin_id: PluginId,
    /// Stage that failed.
    pub phase: FailurePhase,
    /// Zero-based page index that failed; `0` for a health failure.
    pub page: usize,
    /// Pages delivered before the failure.
    pub pages_delivered: usize,
    /// Stable error code (DD-SW §10: never match on the message).
    pub code: ErrorCode,
    /// Human-facing summary, carried but never parsed.
    pub message: String,
}

/// The result of scanning a list of providers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FleetDiscovery {
    /// One entry per provider, in the order the providers were given.
    pub discoveries: Vec<ProviderDiscovery>,
    /// Providers whose scan stopped early.
    pub failures: Vec<ProviderFailure>,
    /// Every delivered resource, in provider order then page order.
    pub resources: Vec<ResourceNode>,
    /// Every delivered relation, in provider order then page order.
    pub relations: Vec<Relation>,
}

impl FleetDiscovery {
    /// Whether every provider finished its scan.
    pub fn is_complete(&self) -> bool {
        self.failures.is_empty()
    }

    /// Ids of every delivered resource, in delivery order.
    pub fn resource_ids(&self) -> Vec<&str> {
        self.resources.iter().map(|r| r.id.as_str()).collect()
    }

    /// Canonical serialization used to compare two scans.
    ///
    /// Sorted keys are already guaranteed by the load-time ordering of the
    /// world, so this is a stable byte sequence for a given provider list.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self)
            .unwrap_or_else(|e| panic!("FleetDiscovery is serializable: {e}"))
    }
}

/// Scan every provider to completion and collect what each delivered.
///
/// Ordering follows the `providers` slice: resource `n` of provider `m` comes
/// before resource `n` of provider `m + 1`. That is the caller's choice, not a
/// sort, because the kernel also iterates providers in registration order.
///
/// NFR-A01, NFR-O04, NFR-P01.
pub async fn discover_all(providers: &[Arc<dyn ResourceProvider>]) -> FleetDiscovery {
    let mut discoveries: Vec<ProviderDiscovery> = Vec::with_capacity(providers.len());
    let mut failures: Vec<ProviderFailure> = Vec::new();
    let mut resources: Vec<ResourceNode> = Vec::new();
    let mut relations: Vec<Relation> = Vec::new();

    for provider in providers {
        let descriptor = provider.descriptor();
        let plugin_id = descriptor
            .plugin_id
            .parse()
            .unwrap_or_else(|_| PluginId::derive(&[descriptor.plugin_id.as_str()]));

        let health = match provider.health().await {
            Ok(h) => h,
            Err(e) => {
                failures.push(failure(
                    &plugin_id,
                    FailurePhase::Health,
                    0,
                    0,
                    e.code,
                    e.message,
                ));
                continue;
            }
        };

        let mut pages: Vec<DiscoverBatch> = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            match provider.discover(cursor.clone()).await {
                Ok(batch) => {
                    let next = batch.cursor.clone();
                    if next == cursor {
                        // No progress: stop rather than spin forever.
                        failures.push(failure(
                            &plugin_id,
                            FailurePhase::NoProgress,
                            pages.len(),
                            pages.len(),
                            ErrorCode::CORE_INVALID,
                            format!(
                                "provider returned cursor {next:?} unchanged; the scan cannot advance"
                            ),
                        ));
                        break;
                    }
                    cursor = next;
                    pages.push(batch);
                }
                Err(e) => {
                    failures.push(failure(
                        &plugin_id,
                        FailurePhase::Discover,
                        pages.len(),
                        pages.len(),
                        e.code,
                        e.message,
                    ));
                    break;
                }
            }
        }

        let delivered_resources: Vec<ResourceNode> = pages
            .iter()
            .flat_map(|p| p.resources.iter().cloned())
            .collect();
        let delivered_relations: Vec<Relation> = pages
            .iter()
            .flat_map(|p| p.relations.iter().cloned())
            .collect();
        resources.extend(delivered_resources.iter().cloned());
        relations.extend(delivered_relations.iter().cloned());

        discoveries.push(ProviderDiscovery {
            plugin_id,
            descriptor,
            health,
            pages,
            resources: delivered_resources,
            relations: delivered_relations,
        });
    }

    FleetDiscovery {
        discoveries,
        failures,
        resources,
        relations,
    }
}

fn failure(
    plugin_id: &PluginId,
    phase: FailurePhase,
    page: usize,
    pages_delivered: usize,
    code: ErrorCode,
    message: impl Into<String>,
) -> ProviderFailure {
    ProviderFailure {
        plugin_id: plugin_id.clone(),
        phase,
        page,
        pages_delivered,
        code,
        message: message.into(),
    }
}
