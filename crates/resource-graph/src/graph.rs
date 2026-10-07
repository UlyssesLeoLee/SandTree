//! Unified resource topology.
//!
//! Two things here are load-bearing and easy to get wrong:
//!
//! 1. **`last_seen` alone is not a change.** A provider that re-reports an
//!    identical resource every discovery round would otherwise flood the event
//!    stream and defeat NFR-P02 (event → UI update ≤ 1s). Only a real field
//!    change emits [`ChangeKind::Changed`].
//! 2. **Absence is not deletion.** A resource missing from one discovery round
//!    becomes [`ResourceState::Unknown`], and only crosses
//!    [`ResourceState::Tombstoned`] after the grace period (DD-SW §5). This is
//!    also why [`ResourceGraph::mark_missing`] is scoped to one provider: a
//!    provider that fails to answer must not delete another provider's
//!    resources.

use std::collections::{BTreeMap, BTreeSet};

use sandtree_model::id::{PluginId, ResourceId};
use sandtree_model::resource::{Relation, ResourceKind, ResourceNode, ResourceState};
use serde::Serialize;
use serde_json::Value as Json;

/// Filter over the topology (FR-003).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ResourceFilter {
    /// Keep only these providers.
    pub provider_ids: Option<Vec<PluginId>>,
    /// Keep only these kinds.
    pub kinds: Option<Vec<ResourceKind>>,
    /// Keep only these states.
    pub states: Option<Vec<ResourceState>>,
    /// Restrict to the subtree rooted at this resource.
    pub root: Option<ResourceId>,
}

impl ResourceFilter {
    /// No filtering.
    pub fn all() -> Self {
        Self::default()
    }

    /// Restrict to one provider.
    pub fn with_provider(mut self, p: PluginId) -> Self {
        self.provider_ids = Some(vec![p]);
        self
    }

    /// Restrict to one kind.
    pub fn with_kind(mut self, k: ResourceKind) -> Self {
        self.kinds = Some(vec![k]);
        self
    }

    /// Restrict to one subtree root.
    pub fn with_root(mut self, r: ResourceId) -> Self {
        self.root = Some(r);
        self
    }

    /// Whether a node itself passes the non-tree criteria.
    pub fn accepts(&self, node: &ResourceNode) -> bool {
        if let Some(p) = &self.provider_ids {
            if !p.contains(&node.provider_id) {
                return false;
            }
        }
        if let Some(k) = &self.kinds {
            if !k.contains(&node.kind) {
                return false;
            }
        }
        if let Some(s) = &self.states {
            if !s.contains(&node.state) {
                return false;
            }
        }
        true
    }
}

/// A node in the rendered topology tree.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TreeNode {
    /// The resource.
    pub resource: ResourceNode,
    /// Descendants, sorted by (kind, name, id).
    pub children: Vec<TreeNode>,
}

impl TreeNode {
    /// Depth-first flatten of this subtree, self first.
    pub fn flatten(&self) -> Vec<&ResourceNode> {
        let mut out = vec![&self.resource];
        for c in &self.children {
            out.extend(c.flatten());
        }
        out
    }

    /// Number of resources in this subtree.
    pub fn len(&self) -> usize {
        1 + self.children.iter().map(TreeNode::len).sum::<usize>()
    }

    /// Whether the subtree has no children.
    pub fn is_empty(&self) -> bool {
        self.children.is_empty()
    }
}

/// What happened to a resource during a reconcile pass.
///
/// Ordering mirrors the lifecycle so that sorting a batch of changes produces a
/// sensible replay order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    /// Newly discovered.
    Added,
    /// A field other than `last_seen` changed.
    Changed,
    /// Provider stopped reporting it, but within the grace period.
    Stale,
    /// Tombstoned after the grace period.
    Removed,
}

/// One change emitted by a reconcile pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Change {
    /// What happened.
    pub kind: ChangeKind,
    /// Which resource.
    pub id: ResourceId,
}

/// In-memory topology.
#[derive(Debug, Default, Clone)]
pub struct ResourceGraph {
    nodes: BTreeMap<ResourceId, ResourceNode>,
    children: BTreeMap<Option<ResourceId>, BTreeSet<ResourceId>>,
    relations: BTreeMap<ResourceId, Vec<Relation>>,
}

impl ResourceGraph {
    /// Empty graph.
    pub fn new() -> Self {
        Self::default()
    }

    /// Upsert a discovery batch.
    ///
    /// Duplicate ids inside one batch collapse: the last definition wins and at
    /// most one [`Change`] is emitted. Changes are returned in input order, so
    /// the caller can emit events that preserve provider ordering.
    pub fn upsert_batch(&mut self, nodes: &[ResourceNode]) -> Vec<Change> {
        let mut deduped: Vec<&ResourceNode> = Vec::with_capacity(nodes.len());
        for node in nodes {
            if let Some(pos) = deduped.iter().position(|n| n.id == node.id) {
                deduped[pos] = node;
            } else {
                deduped.push(node);
            }
        }

        let mut changes = Vec::with_capacity(deduped.len());
        for node in deduped {
            let previous = self.nodes.get(&node.id).cloned();
            let new_parent = node.parent_id.clone();

            match previous {
                None => {
                    changes.push(Change {
                        kind: ChangeKind::Added,
                        id: node.id.clone(),
                    });
                    self.index_parent(node.id.clone(), None, new_parent);
                    self.nodes.insert(node.id.clone(), node.clone());
                }
                Some(existing) => {
                    if existing.parent_id != new_parent {
                        self.index_parent(node.id.clone(), existing.parent_id.clone(), new_parent);
                    }
                    if materially_changed(&existing, node) {
                        changes.push(Change {
                            kind: ChangeKind::Changed,
                            id: node.id.clone(),
                        });
                    }
                    self.nodes.insert(node.id.clone(), node.clone());
                }
            }
        }
        changes
    }

    fn index_parent(
        &mut self,
        id: ResourceId,
        old_parent: Option<ResourceId>,
        new_parent: Option<ResourceId>,
    ) {
        if old_parent == new_parent {
            return;
        }
        self.children.get_mut(&old_parent).map(|s| s.remove(&id));
        self.children.entry(new_parent).or_default().insert(id);
    }

    /// Insert or replace typed relations, de-duplicated on `(from, to, kind)`.
    pub fn upsert_relations(&mut self, rels: &[Relation]) {
        for rel in rels {
            let entry = self.relations.entry(rel.from.clone()).or_default();
            match entry
                .iter_mut()
                .find(|r| r.to == rel.to && r.kind == rel.kind)
            {
                Some(existing) => *existing = rel.clone(),
                None => entry.push(rel.clone()),
            }
            // Make the edge discoverable from the other end too.
            let back = self.relations.entry(rel.to.clone()).or_default();
            match back
                .iter_mut()
                .find(|r| r.to == rel.from && r.kind == rel.kind)
            {
                Some(existing) => *existing = rel.clone(),
                None => back.push(Relation {
                    from: rel.to.clone(),
                    to: rel.from.clone(),
                    kind: rel.kind,
                    metadata: rel.metadata.clone(),
                }),
            }
        }
        for list in self.relations.values_mut() {
            list.sort_by(|a, b| (&a.kind, &a.to).cmp(&(&b.kind, &b.to)));
            list.dedup_by(|a, b| a.kind == b.kind && a.to == b.to);
        }
    }

    /// Fetch one node.
    pub fn get(&self, id: &ResourceId) -> Option<&ResourceNode> {
        self.nodes.get(id)
    }

    /// Direct children, sorted by (kind, name, id).
    pub fn children(&self, id: &ResourceId) -> Vec<&ResourceNode> {
        let mut out: Vec<&ResourceNode> = self
            .children
            .get(&Some(id.clone()))
            .map(|s| s.iter().filter_map(|c| self.nodes.get(c)).collect())
            .unwrap_or_default();
        sort_nodes(&mut out);
        out
    }

    /// All relations touching a resource, sorted by (kind, from, to).
    pub fn relations_of(&self, id: &ResourceId) -> Vec<&Relation> {
        self.relations
            .get(id)
            .map(Vec::as_slice)
            .unwrap_or(&[])
            .iter()
            .collect()
    }

    /// Nodes matching the filter, sorted by (kind, provider, name, id).
    pub fn list(&self, filter: &ResourceFilter) -> Vec<ResourceNode> {
        let mut out: Vec<ResourceNode> = self
            .nodes
            .values()
            .filter(|n| filter.accepts(n))
            .cloned()
            .collect();
        sort_owned(&mut out);
        out
    }

    /// Render the tree for the default topology view (NFR-U01).
    ///
    /// A node is rendered when it itself passes the filter. Children of a
    /// filtered-out node are **not** hoisted: hiding a runtime should not make
    /// its containers appear to be direct children of the host.
    ///
    /// Cycles (corrupt provider data) truncate rather than recursing forever.
    pub fn tree(&self, filter: &ResourceFilter) -> Vec<TreeNode> {
        let roots: Vec<&ResourceNode> = match &filter.root {
            Some(r) => self.nodes.get(r).into_iter().collect(),
            None => self
                .nodes
                .values()
                .filter(|n| n.parent_id.is_none())
                .collect(),
        };
        let mut ordered: Vec<&ResourceNode> =
            roots.into_iter().filter(|n| filter.accepts(n)).collect();
        sort_nodes(&mut ordered);
        let mut visited = BTreeSet::new();
        ordered
            .into_iter()
            .map(|n| self.build(n, filter, &mut visited))
            .collect()
    }

    fn build(
        &self,
        node: &ResourceNode,
        filter: &ResourceFilter,
        visited: &mut BTreeSet<ResourceId>,
    ) -> TreeNode {
        visited.insert(node.id.clone());
        let mut children = Vec::new();
        for child in self.children(&node.id) {
            if visited.contains(&child.id) || !filter.accepts(child) {
                continue;
            }
            children.push(self.build(child, filter, visited));
        }
        TreeNode {
            resource: node.clone(),
            children,
        }
    }

    /// Mark the provider's unseen resources.
    ///
    /// Within `grace_ms` a resource becomes [`ResourceState::Unknown`] and
    /// reports [`ChangeKind::Stale`]; past the grace it becomes
    /// [`ResourceState::Tombstoned`] and reports [`ChangeKind::Removed`].
    pub fn mark_missing(
        &mut self,
        provider: &PluginId,
        seen: &[ResourceId],
        grace_ms: u64,
        now_ms: u64,
    ) -> Vec<Change> {
        let seen: BTreeSet<&ResourceId> = seen.iter().collect();
        let candidates: Vec<ResourceId> = self
            .nodes
            .values()
            .filter(|n| &n.provider_id == provider && !seen.contains(&n.id))
            .map(|n| n.id.clone())
            .collect();

        let mut changes = Vec::new();
        for id in candidates {
            let Some(node) = self.nodes.get_mut(&id) else {
                continue;
            };
            let age = now_ms.saturating_sub(parse_ts_ms(&node.last_seen));
            if node.state == ResourceState::Tombstoned {
                continue;
            }
            if age >= grace_ms {
                node.state = ResourceState::Tombstoned;
                changes.push(Change {
                    kind: ChangeKind::Removed,
                    id,
                });
            } else if node.state != ResourceState::Unknown {
                node.state = ResourceState::Unknown;
                changes.push(Change {
                    kind: ChangeKind::Stale,
                    id,
                });
            }
        }
        changes.sort_by(|a, b| (&a.kind, &a.id).cmp(&(&b.kind, &b.id)));
        changes
    }

    /// Remove a resource and every edge touching it.
    pub fn remove(&mut self, id: &ResourceId) -> Option<ResourceNode> {
        let node = self.nodes.remove(id)?;
        if let Some(set) = self.children.get_mut(&node.parent_id) {
            set.remove(id);
        }
        for kids in self.children.values_mut() {
            kids.remove(id);
        }
        self.relations.remove(id);
        for list in self.relations.values_mut() {
            list.retain(|r| &r.from != id && &r.to != id);
        }
        Some(node)
    }

    /// Number of nodes.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Whether the graph is empty.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
}

/// Whether anything other than `last_seen` differs.
fn materially_changed(a: &ResourceNode, b: &ResourceNode) -> bool {
    let mut lhs = a.clone();
    let mut rhs = b.clone();
    lhs.last_seen = String::new();
    rhs.last_seen = String::new();
    lhs != rhs
}

fn sort_nodes(v: &mut [&ResourceNode]) {
    v.sort_by(|a, b| (a.kind, &a.name, &a.id).cmp(&(b.kind, &b.name, &b.id)));
}

fn sort_owned(v: &mut [ResourceNode]) {
    v.sort_by(|a, b| {
        (a.kind, &a.provider_id, &a.name, &a.id).cmp(&(b.kind, &b.provider_id, &b.name, &b.id))
    });
}

/// Parse an RFC3339 timestamp into epoch milliseconds; unparsable input reads as
/// epoch (i.e. maximally old), which fails the grace test safely.
fn parse_ts_ms(s: &str) -> u64 {
    let b = s.as_bytes();
    if b.len() < 19 {
        return 0;
    }
    let num = |a: usize, z: usize| -> Option<i64> { s.get(a..z)?.parse().ok() };
    let (Some(y), Some(mo), Some(d), Some(h), Some(mi), Some(sec)) = (
        num(0, 4),
        num(5, 7),
        num(8, 10),
        num(11, 13),
        num(14, 16),
        num(17, 19),
    ) else {
        return 0;
    };
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || sec > 60 {
        return 0;
    }
    let y = if mo <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let mp = if mo > 2 { mo - 3 } else { mo + 9 } as u64;
    let doy = (153 * mp + 2) / 5 + d as u64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe as i64 - 719_468;
    let secs = days * 86_400 + h * 3600 + mi * 60 + sec;
    if secs < 0 {
        return 0;
    }
    (secs as u64) * 1000
}

/// Wall-clock milliseconds; shared by tests and by the kernel's clock port.
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Current time as RFC3339 UTC.
pub fn now_rfc3339() -> String {
    let ms = now_ms() as i64;
    let secs = ms.div_euclid(1000);
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        sod / 3600,
        (sod % 3600) / 60,
        sod % 60
    )
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// JSON metadata used to carry provider-specific payloads.
pub type Metadata = Json;

#[cfg(test)]
mod tests {
    use sandtree_model::resource::RelationKind;

    use super::*;

    fn plugin(name: &str) -> PluginId {
        PluginId::derive(&[name])
    }

    fn node(
        provider: &PluginId,
        kind: ResourceKind,
        name: &str,
        parent: Option<ResourceId>,
        state: ResourceState,
        last_seen: &str,
    ) -> ResourceNode {
        ResourceNode::new(
            ResourceId::derive(&[provider.as_str(), name]),
            kind,
            provider.clone(),
            name,
            state,
            parent,
            last_seen.to_string(),
        )
    }

    fn host(provider: &PluginId) -> ResourceNode {
        node(
            provider,
            ResourceKind::Host,
            "host",
            None,
            ResourceState::Running,
            "2026-10-07T00:00:00Z",
        )
    }

    #[test]
    fn first_batch_emits_added_once_per_id() {
        let mut g = ResourceGraph::new();
        let p = plugin("docker");
        let h = host(&p);
        let c = node(
            &p,
            ResourceKind::Container,
            "web",
            Some(h.id.clone()),
            ResourceState::Running,
            "2026-10-07T00:00:00Z",
        );
        let changes = g.upsert_batch(&[h.clone(), c.clone(), c.clone()]);
        assert_eq!(changes.len(), 2);
        assert!(changes.iter().all(|c| c.kind == ChangeKind::Added));
        assert_eq!(g.len(), 2);
    }

    #[test]
    fn last_seen_alone_is_not_a_change() {
        // NFR-P02: a stable resource must not re-emit on every round.
        let mut g = ResourceGraph::new();
        let p = plugin("docker");
        let h = host(&p);
        g.upsert_batch(std::slice::from_ref(&h));
        let later = node(
            &p,
            ResourceKind::Host,
            "host",
            None,
            ResourceState::Running,
            "2026-10-07T00:05:00Z",
        );
        assert!(g.upsert_batch(&[later]).is_empty());
    }

    #[test]
    fn real_field_change_emits_changed() {
        let mut g = ResourceGraph::new();
        let p = plugin("docker");
        let h = host(&p);
        g.upsert_batch(&[h]);
        let stopped = node(
            &p,
            ResourceKind::Host,
            "host",
            None,
            ResourceState::Stopped,
            "2026-10-07T00:05:00Z",
        );
        let changes = g.upsert_batch(&[stopped]);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].kind, ChangeKind::Changed);
    }

    #[test]
    fn tree_is_ordered_and_filtered_by_node_not_hoisted() {
        let mut g = ResourceGraph::new();
        let p = plugin("docker");
        let h = host(&p);
        let c = node(
            &p,
            ResourceKind::Container,
            "web",
            Some(h.id.clone()),
            ResourceState::Running,
            "2026-10-07T00:00:00Z",
        );
        g.upsert_batch(&[h.clone(), c.clone()]);

        let tree = g.tree(&ResourceFilter::all());
        assert_eq!(tree.len(), 1);
        assert_eq!(tree[0].len(), 2);
        assert_eq!(tree[0].flatten().len(), 2);

        // Filtering out the host does not hoist the container to a root.
        let filtered = g.tree(&ResourceFilter::all().with_kind(ResourceKind::Container));
        assert!(filtered.is_empty());
        // …but list() still finds it.
        assert_eq!(
            g.list(&ResourceFilter::all().with_kind(ResourceKind::Container))
                .len(),
            1
        );
    }

    #[test]
    fn cycles_do_not_recurse_forever() {
        let mut g = ResourceGraph::new();
        let p = plugin("docker");
        let a = ResourceId::derive(&["a"]);
        let b = ResourceId::derive(&["b"]);
        g.upsert_batch(&[
            node(
                &p,
                ResourceKind::Sandbox,
                "a",
                Some(b.clone()),
                ResourceState::Running,
                "2026-10-07T00:00:00Z",
            ),
            node(
                &p,
                ResourceKind::Sandbox,
                "b",
                Some(a.clone()),
                ResourceState::Running,
                "2026-10-07T00:00:00Z",
            ),
        ]);
        // Neither has a parent of None, so nothing renders as a root.
        assert!(g.tree(&ResourceFilter::all()).is_empty());
        // Both are still listable.
        assert_eq!(g.list(&ResourceFilter::all()).len(), 2);
    }

    #[test]
    fn orphan_nodes_are_listable_but_unrendered() {
        let mut g = ResourceGraph::new();
        let p = plugin("docker");
        let ghost = ResourceId::derive(&["ghost"]);
        g.upsert_batch(&[node(
            &p,
            ResourceKind::Container,
            "orphan",
            Some(ghost),
            ResourceState::Running,
            "2026-10-07T00:00:00Z",
        )]);
        assert_eq!(g.list(&ResourceFilter::all()).len(), 1);
        assert!(g.tree(&ResourceFilter::all()).is_empty());
    }

    #[test]
    fn relations_are_deduplicated_and_bidirectional() {
        let mut g = ResourceGraph::new();
        let a = ResourceId::derive(&["a"]);
        let b = ResourceId::derive(&["b"]);
        let rel = Relation::new(a.clone(), b.clone(), RelationKind::UsesImage);
        g.upsert_relations(&[rel.clone(), rel.clone()]);
        assert_eq!(g.relations_of(&a).len(), 1);
        assert_eq!(g.relations_of(&b).len(), 1);
        assert_eq!(g.relations_of(&a)[0].kind, RelationKind::UsesImage);
    }

    #[test]
    fn removing_a_node_drops_its_edges() {
        let mut g = ResourceGraph::new();
        let p = plugin("docker");
        let h = host(&p);
        let c = node(
            &p,
            ResourceKind::Container,
            "web",
            Some(h.id.clone()),
            ResourceState::Running,
            "2026-10-07T00:00:00Z",
        );
        g.upsert_batch(&[h.clone(), c.clone()]);
        g.upsert_relations(&[Relation::new(
            c.id.clone(),
            h.id.clone(),
            RelationKind::WorkspaceMount,
        )]);
        assert_eq!(g.relations_of(&h.id).len(), 1);
        g.remove(&c.id);
        assert!(g.relations_of(&h.id).is_empty());
        assert!(g.children(&h.id).is_empty());
    }

    #[test]
    fn missing_resource_is_staled_before_being_tombstoned() {
        // DD-SW §5 step 4, and the reason ADR-OBS-001 needs no exception here.
        let mut g = ResourceGraph::new();
        let p = plugin("docker");
        let base = parse_ts_ms("2026-10-07T00:00:00Z");
        g.upsert_batch(&[node(
            &p,
            ResourceKind::Container,
            "web",
            None,
            ResourceState::Running,
            "2026-10-07T00:00:00Z",
        )]);

        // Within the grace period: stale, not removed.
        let changes = g.mark_missing(&p, &[], 60_000, base + 1_000);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].kind, ChangeKind::Stale);
        assert_eq!(
            g.list(&ResourceFilter::all())[0].state,
            ResourceState::Unknown
        );

        // Past the grace period: tombstoned.
        let changes = g.mark_missing(&p, &[], 60_000, base + 120_000);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].kind, ChangeKind::Removed);
        assert_eq!(
            g.list(&ResourceFilter::all())[0].state,
            ResourceState::Tombstoned
        );

        // Idempotent once tombstoned.
        assert!(g.mark_missing(&p, &[], 60_000, base + 200_000).is_empty());
    }

    #[test]
    fn a_resource_seen_again_within_grace_stays_alive() {
        let mut g = ResourceGraph::new();
        let p = plugin("docker");
        let base = parse_ts_ms("2026-10-07T00:00:00Z");
        let c = node(
            &p,
            ResourceKind::Container,
            "web",
            None,
            ResourceState::Running,
            "2026-10-07T00:00:00Z",
        );
        g.upsert_batch(std::slice::from_ref(&c));
        g.mark_missing(&p, &[], 60_000, base + 1_000);
        // Provider reports it again. `Unknown → Running` is a real state change,
        // so the UI must be told: a resource that went stale and came back is not
        // the same observation as one that never went stale.
        let changes = g.upsert_batch(&[node(
            &p,
            ResourceKind::Container,
            "web",
            None,
            ResourceState::Running,
            "2026-10-07T00:00:01Z",
        )]);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].kind, ChangeKind::Changed);
        assert_eq!(
            g.list(&ResourceFilter::all())[0].state,
            ResourceState::Running
        );
    }

    #[test]
    fn mark_missing_is_scoped_to_one_provider() {
        // A provider that fails must not delete another provider's resources.
        let mut g = ResourceGraph::new();
        let a = plugin("docker");
        let b = plugin("multipass");
        let base = parse_ts_ms("2026-10-07T00:00:00Z");
        g.upsert_batch(&[
            node(
                &a,
                ResourceKind::Container,
                "web",
                None,
                ResourceState::Running,
                "2026-10-07T00:00:00Z",
            ),
            node(
                &b,
                ResourceKind::Sandbox,
                "mp",
                None,
                ResourceState::Running,
                "2026-10-07T00:00:00Z",
            ),
        ]);
        let changes = g.mark_missing(&a, &[], 1_000, base + 10_000);
        assert_eq!(changes.len(), 1);
        let states: Vec<ResourceState> = g
            .list(&ResourceFilter::all())
            .iter()
            .map(|n| n.state)
            .collect();
        assert!(states.contains(&ResourceState::Tombstoned));
        assert!(
            states.contains(&ResourceState::Running),
            "other provider untouched"
        );
    }

    #[test]
    fn children_are_deterministically_ordered() {
        let mut g = ResourceGraph::new();
        let p = plugin("docker");
        let h = host(&p);
        let mut batch = vec![h.clone()];
        for (name, kind) in [
            ("z", ResourceKind::Volume),
            ("a", ResourceKind::Container),
            ("m", ResourceKind::Network),
        ] {
            batch.push(node(
                &p,
                kind,
                name,
                Some(h.id.clone()),
                ResourceState::Running,
                "2026-10-07T00:00:00Z",
            ));
        }
        g.upsert_batch(&batch);
        let kids: Vec<&str> = g.children(&h.id).iter().map(|n| n.name.as_str()).collect();
        // Ordered by (kind, name, id): Container < Volume < Network, so names
        // alone do not determine the order.
        assert_eq!(
            kids,
            vec!["a", "z", "m"],
            "ordered by kind, then name, then id"
        );
    }

    #[test]
    fn timestamp_parsing_is_fail_closed() {
        assert_eq!(parse_ts_ms("garbage"), 0);
        assert_eq!(parse_ts_ms("1970-01-01T00:00:00Z"), 0);
        assert_eq!(parse_ts_ms("2023-11-14T22:13:20Z"), 1_700_000_000_000);
    }
}
