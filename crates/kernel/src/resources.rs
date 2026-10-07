//! Resource discovery, reconciliation and the resource tree (DD-SW §4, §5).
//!
//! The stale rule is the important part. A resource a provider stops reporting
//! is **not** deleted: the store marks it `unknown` (the design's "stale"), and
//! only past the grace period is it removed. A Docker daemon that is briefly
//! unreachable must not look like "the user deleted every container".
//!
//! The second rule is stronger still: a provider that is *unavailable* does not
//! age out its resources at all. Unreachable is not the same as absent
//! (ADR-OBS-001), and conflating them would make a daemon restart look like
//! mass deletion.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use sandtree_event::{EventFilter, EventRouter};
use sandtree_model::error::{DomainError, ErrorCode};
use sandtree_model::event::{EventRecord, EventType};
use sandtree_model::id::{PluginId, ResourceId};
use sandtree_model::resource::{Correlation, Relation, ResourceKind, ResourceNode, ResourceState};
use sandtree_sdk::ports::{ProviderHealth, ProviderRegistry};
use sandtree_store::cas::Cas;
use sandtree_store::db::Store;
use sandtree_store::repo::Change;
use serde_json::Value as Json;

/// Hard cap on discovery pages per provider, so a provider whose cursor never
/// terminates fails loudly instead of looping forever.
const MAX_DISCOVERY_PAGES: usize = 1_000;

/// Resource tree filter.
#[derive(Debug, Clone, Default)]
pub struct ResourceFilter {
    /// Restrict to one owning provider.
    pub provider: Option<PluginId>,
    /// Restrict to one kind.
    pub kind: Option<ResourceKind>,
    /// Restrict to one state.
    pub state: Option<ResourceState>,
    /// Include removed resources (they are hard-deleted, so this is rarely true).
    pub include_removed: bool,
}

impl ResourceFilter {
    /// No filtering.
    pub fn all() -> Self {
        Self::default()
    }

    /// Filter by owning provider.
    pub fn by_provider(mut self, provider: PluginId) -> Self {
        self.provider = Some(provider);
        self
    }

    /// Filter by kind.
    pub fn by_kind(mut self, kind: ResourceKind) -> Self {
        self.kind = Some(kind);
        self
    }

    fn matches(&self, node: &ResourceNode) -> bool {
        if let Some(p) = &self.provider {
            if &node.provider_id != p {
                return false;
            }
        }
        if let Some(k) = self.kind {
            if node.kind != k {
                return false;
            }
        }
        if let Some(s) = self.state {
            if node.state != s {
                return false;
            }
        }
        let _ = self.include_removed;
        true
    }
}

/// One node of the resource tree.
#[derive(Debug, Clone, PartialEq)]
pub struct TreeNode {
    /// The resource.
    pub node: ResourceNode,
    /// Children, sorted by id for deterministic output.
    pub children: Vec<TreeNode>,
}

/// What a reconcile pass did.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ReconcileOutcome {
    /// Changes produced by discovery.
    pub changes: Vec<Change>,
    /// Resources removed after exceeding the grace period, sorted.
    pub removed: Vec<ResourceId>,
}

/// Owns the resource view: discovery, reconciliation, tree and inspect.
pub struct ResourceManager {
    store: Arc<Store>,
    cas: Arc<Cas>,
    events: Arc<EventRouter>,
    stale_grace_ms: u64,
    /// When each resource was first seen missing, `ResourceId -> epoch millis`.
    stale_since: tokio::sync::Mutex<BTreeMap<ResourceId, u64>>,
}

impl ResourceManager {
    /// Build a manager over an open store.
    pub fn new(
        store: Arc<Store>,
        cas: Arc<Cas>,
        events: Arc<EventRouter>,
        stale_grace_ms: u64,
    ) -> Self {
        Self {
            store,
            cas,
            events,
            stale_grace_ms,
            stale_since: tokio::sync::Mutex::new(BTreeMap::new()),
        }
    }

    /// The CAS, for workspace and snapshot writers.
    pub fn cas(&self) -> &Arc<Cas> {
        &self.cas
    }

    /// Grace period after which a missing resource is removed.
    pub fn stale_grace_ms(&self) -> u64 {
        self.stale_grace_ms
    }

    /// Build a `provider.health` event.
    fn provider_event(
        plugin: &PluginId,
        health: &ProviderHealth,
        detail: impl Into<String>,
    ) -> EventRecord {
        EventRecord::new(
            EventType::ProviderHealthChanged,
            Correlation::generate(),
            serde_json::json!({
                "provider_id": plugin.as_str(),
                "state": health.summary(),
                "control_available": health.control_is_available(),
                "detail": detail.into(),
            }),
        )
        .with_provider(plugin.as_str())
    }

    /// Scan every registered resource provider and merge the results (NFR-A01).
    ///
    /// Only providers that actually answered a discovery page may age their
    /// resources out. A provider that reported `Unavailable`, or whose
    /// `health` call failed, contributes an event and nothing else.
    pub async fn discover_all(
        &self,
        registry: &ProviderRegistry,
        events: &EventRouter,
    ) -> Result<Vec<Change>, DomainError> {
        let mut all = Vec::new();
        // plugin -> every id the provider actually returned this round.
        // This must come from the provider, not from the database: reading
        // the database back would list every known resource as "seen" and
        // nothing would ever go stale.
        let mut seen_this_round: BTreeMap<PluginId, Vec<ResourceId>> = BTreeMap::new();

        for (plugin, provider) in registry.resource_providers() {
            match provider.health().await {
                Ok(health @ ProviderHealth::Unavailable { .. }) => {
                    events.publish(Self::provider_event(
                        &plugin,
                        &health,
                        "provider reported itself unavailable",
                    ));
                    continue;
                }
                Ok(_) => {}
                Err(e) => {
                    events.publish(Self::provider_event(
                        &plugin,
                        &ProviderHealth::Unavailable {
                            reason: e.message.clone(),
                        },
                        "health check failed",
                    ));
                    continue;
                }
            }

            let mut seen: Vec<ResourceId> = Vec::new();
            let mut cursor: Option<String> = None;
            let mut pages = 0usize;
            loop {
                pages += 1;
                if pages > MAX_DISCOVERY_PAGES {
                    return Err(DomainError::new(
                        ErrorCode::CORE_INVALID,
                        format!(
                            "provider {plugin} produced more than {MAX_DISCOVERY_PAGES} \
                             discovery pages; refusing to loop"
                        ),
                    ));
                }
                let batch = match provider.discover(cursor.clone()).await {
                    Ok(b) => b,
                    Err(e) => {
                        events.publish(Self::provider_event(
                            &plugin,
                            &ProviderHealth::Degraded {
                                reason: e.message.clone(),
                            },
                            "discovery failed",
                        ));
                        break;
                    }
                };
                seen.extend(batch.resources.iter().map(|n| n.id.clone()));
                all.extend(self.store.upsert_resources(&batch.resources)?);
                self.store.upsert_relations(&batch.relations)?;
                match batch.cursor {
                    Some(next) if !next.is_empty() => cursor = Some(next),
                    _ => {
                        // The round completed, so this provider answered.
                        seen.sort();
                        seen.dedup();
                        for id in &seen {
                            self.note_recovered(id).await;
                        }
                        seen_this_round.insert(plugin.clone(), seen);
                        break;
                    }
                }
            }
        }

        for (plugin, seen) in &seen_this_round {
            self.store.mark_resources_stale(plugin, seen)?;
        }

        Ok(all)
    }

    /// Remove resources that have been missing past the grace period.
    ///
    /// The clock starts on the **first** pass that did not see a resource, so a
    /// single missed scan can never remove anything.
    pub async fn reconcile(&self) -> Result<ReconcileOutcome, DomainError> {
        let now = sandtree_policy::audit::now_ms();
        let missing = self.store.resources(None, Some(ResourceState::Unknown))?;
        let mut removed = Vec::new();
        let mut since = self.stale_since.lock().await;

        for node in missing {
            if node.state.is_terminal() {
                since.remove(&node.id);
                continue;
            }
            let first_seen = *since.entry(node.id.clone()).or_insert(now);
            if now.saturating_sub(first_seen) < self.stale_grace_ms {
                continue;
            }
            self.events.publish(
                sandtree_event::resource_changed(
                    node.id.clone(),
                    Correlation::generate(),
                    serde_json::json!({"reason": "missing past the stale grace period"}),
                )
                .with_severity(sandtree_model::event::Severity::Warning),
            );
            self.store.delete_resource(&node.id)?;
            since.remove(&node.id);
            removed.push(node.id);
        }
        removed.sort();
        Ok(ReconcileOutcome {
            changes: Vec::new(),
            removed,
        })
    }

    /// Forget the missing-since clock for a resource that came back.
    pub async fn note_recovered(&self, id: &ResourceId) {
        self.stale_since.lock().await.remove(id);
    }

    /// Build the resource tree.
    ///
    /// A node whose parent is filtered out is promoted to a root rather than
    /// dropped: a container whose Docker endpoint is unavailable must still be
    /// visible somewhere.
    pub async fn tree(&self, filter: &ResourceFilter) -> Result<Vec<TreeNode>, DomainError> {
        let all = self.store.resources(filter.provider.as_ref(), None)?;
        let kept: Vec<ResourceNode> = all.into_iter().filter(|n| filter.matches(n)).collect();
        let ids: BTreeSet<ResourceId> = kept.iter().map(|n| n.id.clone()).collect();

        let mut children: BTreeMap<Option<ResourceId>, Vec<ResourceNode>> = BTreeMap::new();
        for node in kept {
            let parent = node.parent_id.clone().filter(|p| ids.contains(p));
            children.entry(parent).or_default().push(node);
        }

        fn build(
            parent: Option<ResourceId>,
            children: &BTreeMap<Option<ResourceId>, Vec<ResourceNode>>,
        ) -> Vec<TreeNode> {
            let mut out = Vec::new();
            if let Some(nodes) = children.get(&parent) {
                let mut sorted = nodes.clone();
                sorted.sort_by(|a, b| a.id.cmp(&b.id));
                for node in sorted {
                    out.push(TreeNode {
                        children: build(Some(node.id.clone()), children),
                        node,
                    });
                }
            }
            out
        }

        Ok(build(None, &children))
    }

    /// One resource.
    pub async fn inspect(&self, id: &ResourceId) -> Result<ResourceNode, DomainError> {
        self.store.resource(id)?.ok_or_else(|| {
            DomainError::new(ErrorCode::CORE_INVALID, format!("no such resource: {id}"))
        })
    }

    /// Relations touching a resource, deterministic order.
    pub async fn relations(&self, id: &ResourceId) -> Result<Vec<Relation>, DomainError> {
        self.store.relations_of(id)
    }

    /// Deterministic JSON view of the tree, for IPC and diagnostics.
    pub async fn tree_json(&self, filter: &ResourceFilter) -> Result<Json, DomainError> {
        fn to_json(node: &TreeNode) -> Json {
            serde_json::json!({
                "id": node.node.id.as_str(),
                "kind": node.node.kind.as_str(),
                "provider_id": node.node.provider_id.as_str(),
                "name": node.node.name,
                "state": node.node.state.as_str(),
                "children": node.children.iter().map(to_json).collect::<Vec<Json>>(),
            })
        }
        Ok(Json::Array(
            self.tree(filter).await?.iter().map(to_json).collect(),
        ))
    }
}

/// Subscribe to everything the kernel publishes.
pub fn subscribe_all(
    events: &EventRouter,
) -> (sandtree_event::SubscriptionId, sandtree_event::Subscription) {
    events.subscribe(EventFilter::all())
}
