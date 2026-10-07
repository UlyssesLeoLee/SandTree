//! Resource and relation persistence.
//!
//! Implemented directly on `Store` so the kernel gets one concrete persistence
//! seam it can also fake in unit tests.
//!
//! Note on capabilities: `schemas/001_init.sql` has no `capabilities` column, and
//! the design baseline is read-only. The capability set therefore round-trips
//! inside `metadata_json` under a reserved key, which keeps the approved DDL
//! untouched while still letting `ResourceNode` come back complete.

use rusqlite::params;
use sandtree_model::capability::CapabilitySet;
use sandtree_model::error::{DomainError, ErrorCode};
use sandtree_model::id::{PluginId, ResourceId};
use sandtree_model::resource::{Relation, RelationKind, ResourceNode, ResourceState};

use crate::db::{DbFailure, Store};
use crate::repo::{row_to_node, Change, ResourceRow};

/// Metadata key holding the serialized capability set.
const CAPS_KEY: &str = "_sandtree_capabilities";

impl Store {
    /// Upsert a discovery batch in one transaction (DD-DATA §2).
    ///
    /// Returns one [`Change`] per resource that was genuinely added or changed.
    /// A resource whose only difference is `last_seen` produces none, so a
    /// steady-state reconcile does not flood the event stream (NFR-P02).
    pub fn upsert_resources(&self, nodes: &[ResourceNode]) -> Result<Vec<Change>, DomainError> {
        self.write(|tx| {
            let mut changes = Vec::new();
            for node in nodes {
                let existing: Option<(String, String, Option<String>, String)> = tx
                    .query_row(
                        "SELECT name, state, parent_id, metadata_json FROM resource WHERE id = ?1",
                        [node.id.as_str()],
                        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                    )
                    .ok();

                let added = existing.is_none();
                let differs = match &existing {
                    None => true,
                    Some((name, state, parent, metadata)) => {
                        name != &node.name
                            || state != node.state.as_str()
                            || parent.as_deref() != node.parent_id.as_ref().map(ResourceId::as_str)
                            || metadata != &encode_metadata(node)
                    }
                };

                tx.execute(
                    "INSERT INTO resource(id, provider_id, kind, name, state, parent_id, metadata_json, last_seen)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                     ON CONFLICT(id) DO UPDATE SET
                        provider_id = excluded.provider_id,
                        kind = excluded.kind,
                        name = excluded.name,
                        state = excluded.state,
                        parent_id = excluded.parent_id,
                        metadata_json = excluded.metadata_json,
                        last_seen = excluded.last_seen",
                    params![
                        node.id.as_str(),
                        node.provider_id.as_str(),
                        crate::repo::kind_wire(node.kind),
                        node.name,
                        node.state.as_str(),
                        node.parent_id.as_ref().map(ResourceId::as_str),
                        encode_metadata(node),
                        node.last_seen,
                    ],
                )
                .map_err(DbFailure::from)?;

                if added {
                    changes.push(Change {
                        added: true,
                        id: node.id.clone(),
                    });
                } else if differs {
                    changes.push(Change {
                        added: false,
                        id: node.id.clone(),
                    });
                }
            }
            Ok(changes)
        })
    }

    /// Replace typed relations for a batch in one transaction.
    pub fn upsert_relations(&self, rels: &[Relation]) -> Result<(), DomainError> {
        self.write(|tx| {
            for r in rels {
                tx.execute(
                    "INSERT INTO resource_relation(from_id, to_id, kind, metadata_json)
                     VALUES (?1, ?2, ?3, ?4)
                     ON CONFLICT(from_id, to_id, kind) DO UPDATE SET metadata_json = excluded.metadata_json",
                    params![
                        r.from.as_str(),
                        r.to.as_str(),
                        r.kind.as_str(),
                        r.metadata.to_string(),
                    ],
                )
                .map_err(DbFailure::from)?;
            }
            Ok(())
        })
    }

    /// Read one resource row.
    pub fn resource(&self, id: &ResourceId) -> Result<Option<ResourceNode>, DomainError> {
        self.read(|c| {
            let row = c
                .query_row(
                    "SELECT id, provider_id, kind, name, state, parent_id, metadata_json, last_seen
                       FROM resource WHERE id = ?1",
                    [id.as_str()],
                    |r| {
                        Ok((
                            r.get::<_, String>(0)?,
                            r.get::<_, String>(1)?,
                            r.get::<_, String>(2)?,
                            r.get::<_, String>(3)?,
                            r.get::<_, String>(4)?,
                            r.get::<_, Option<String>>(5)?,
                            r.get::<_, String>(6)?,
                            r.get::<_, String>(7)?,
                        ))
                    },
                )
                .ok();
            match row {
                None => Ok(None),
                Some(args) => Ok(Some(row_to_node(ResourceRow {
                    id: args.0,
                    provider_id: args.1,
                    kind: args.2,
                    name: args.3,
                    state: args.4,
                    parent_id: args.5,
                    metadata_json: args.6,
                    last_seen: args.7,
                })?)),
            }
        })
    }

    /// List resources with optional provider/state filters, ordered by (kind, name, id).
    pub fn resources(
        &self,
        provider: Option<&PluginId>,
        state: Option<ResourceState>,
    ) -> Result<Vec<ResourceNode>, DomainError> {
        self.read(|c| {
            let mut stmt = c
                .prepare(
                    "SELECT id, provider_id, kind, name, state, parent_id, metadata_json, last_seen
                       FROM resource
                      WHERE (?1 IS NULL OR provider_id = ?1)
                        AND (?2 IS NULL OR state = ?2)
                      ORDER BY kind, name, id",
                )
                .map_err(DbFailure::from)?;
            let rows = stmt
                .query_map(
                    params![
                        provider.map(PluginId::as_str),
                        state.map(ResourceState::as_str)
                    ],
                    |r| {
                        Ok((
                            r.get::<_, String>(0)?,
                            r.get::<_, String>(1)?,
                            r.get::<_, String>(2)?,
                            r.get::<_, String>(3)?,
                            r.get::<_, String>(4)?,
                            r.get::<_, Option<String>>(5)?,
                            r.get::<_, String>(6)?,
                            r.get::<_, String>(7)?,
                        ))
                    },
                )
                .map_err(DbFailure::from)?;
            let mut out = Vec::new();
            for row in rows {
                let args = row.map_err(DbFailure::from)?;
                out.push(row_to_node(ResourceRow {
                    id: args.0,
                    provider_id: args.1,
                    kind: args.2,
                    name: args.3,
                    state: args.4,
                    parent_id: args.5,
                    metadata_json: args.6,
                    last_seen: args.7,
                })?);
            }
            Ok(out)
        })
    }

    /// Relations touching a resource, ordered by (kind, from, to).
    pub fn relations_of(&self, id: &ResourceId) -> Result<Vec<Relation>, DomainError> {
        self.read(|c| {
            let mut stmt = c
                .prepare(
                    "SELECT from_id, to_id, kind, metadata_json FROM resource_relation
                      WHERE from_id = ?1 OR to_id = ?1
                      ORDER BY kind, from_id, to_id",
                )
                .map_err(DbFailure::from)?;
            let rows = stmt
                .query_map([id.as_str()], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                    ))
                })
                .map_err(DbFailure::from)?;
            let mut out = Vec::new();
            for row in rows {
                let (from, to, kind, meta) = row.map_err(DbFailure::from)?;
                let Some(kind) = RelationKind::from_wire(&kind) else {
                    continue;
                };
                out.push(Relation {
                    from: ResourceId::parse(&from)
                        .map_err(|e| corrupt("relation from_id", &e.to_string()))?,
                    to: ResourceId::parse(&to)
                        .map_err(|e| corrupt("relation to_id", &e.to_string()))?,
                    kind,
                    metadata: serde_json::from_str(&meta).unwrap_or_default(),
                });
            }
            Ok(out)
        })
    }

    /// Mark a provider's unseen resources `unknown`.
    ///
    /// Tombstoning deliberately does **not** happen here: the grace-period
    /// decision belongs to the in-memory graph, and writing `tombstoned` straight
    /// to SQL would let one missed round delete durable state (DD-SW §5).
    pub fn mark_resources_stale(
        &self,
        provider: &PluginId,
        seen: &[ResourceId],
    ) -> Result<usize, DomainError> {
        let ids: Vec<String> = seen.iter().map(|i| i.as_str().to_string()).collect();
        self.write(|tx| {
            let mut stmt = tx
                .prepare(
                    "SELECT id FROM resource
                      WHERE provider_id = ?1
                        AND state NOT IN ('unknown','destroyed','tombstoned')",
                )
                .map_err(DbFailure::from)?;
            let mut rows = stmt
                .query_map([provider.as_str()], |r| r.get::<_, String>(0))
                .map_err(DbFailure::from)?;
            let mut unseen = Vec::new();
            for row in rows.by_ref() {
                let id = row.map_err(DbFailure::from)?;
                if !ids.contains(&id) {
                    unseen.push(id);
                }
            }
            drop(rows);
            drop(stmt);
            let mut n = 0usize;
            for id in unseen {
                n += tx
                    .execute("UPDATE resource SET state = 'unknown' WHERE id = ?1", [id])
                    .map_err(DbFailure::from)?;
            }
            Ok(n)
        })
    }

    /// Delete a resource row and its relations.
    pub fn delete_resource(&self, id: &ResourceId) -> Result<(), DomainError> {
        self.write(|tx| {
            tx.execute(
                "DELETE FROM resource_relation WHERE from_id = ?1 OR to_id = ?1",
                [id.as_str()],
            )
            .map_err(DbFailure::from)?;
            tx.execute("DELETE FROM resource WHERE id = ?1", [id.as_str()])
                .map_err(DbFailure::from)?;
            Ok(())
        })
    }
}

/// Encode a node's metadata plus its capability set.
fn encode_metadata(node: &ResourceNode) -> String {
    let mut value = node.metadata.clone();
    if !node.capabilities.is_empty() {
        if let Some(map) = value.as_object_mut() {
            map.insert(
                CAPS_KEY.to_string(),
                serde_json::Value::Array(
                    node.capabilities
                        .to_wire_vec()
                        .into_iter()
                        .map(serde_json::Value::String)
                        .collect(),
                ),
            );
        }
    }
    value.to_string()
}

/// Decode the capability set previously stored under [`CAPS_KEY`].
pub fn decode_capabilities(metadata: &serde_json::Value) -> CapabilitySet {
    let Some(raw) = metadata.get(CAPS_KEY).and_then(|v| v.as_array()) else {
        return CapabilitySet::empty();
    };
    let wires: Vec<&str> = raw.iter().filter_map(|v| v.as_str()).collect();
    CapabilitySet::parse_all(wires).unwrap_or_else(|_| CapabilitySet::empty())
}

fn corrupt(what: &str, detail: &str) -> DomainError {
    DomainError::new(
        ErrorCode::STORE_TRANSACTION_FAILED,
        format!("corrupt {what} in stored row"),
    )
    .with_detail(detail.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sandtree_model::capability::Capability;
    use sandtree_model::resource::ResourceKind;

    fn p(name: &str) -> PluginId {
        PluginId::derive(&[name])
    }

    fn node(name: &str, parent: Option<ResourceId>) -> ResourceNode {
        ResourceNode::new(
            ResourceId::derive(&["docker", name]),
            ResourceKind::Container,
            p("docker"),
            name,
            ResourceState::Running,
            parent,
            "2026-10-07T00:00:00Z".to_string(),
        )
    }

    #[test]
    fn upsert_reports_added_then_changed_then_quiet() {
        let s = Store::open_in_memory().unwrap();
        let n = node("web", None);
        let changes = s.upsert_resources(std::slice::from_ref(&n)).unwrap();
        assert_eq!(changes.len(), 1);
        assert!(changes[0].added);

        // Only last_seen moves: no change.
        let mut later = n.clone();
        later.last_seen = "2026-10-07T00:05:00Z".into();
        assert!(s.upsert_resources(&[later]).unwrap().is_empty());

        // Real field change: reported.
        let mut stopped = n.clone();
        stopped.state = ResourceState::Stopped;
        let changes = s.upsert_resources(&[stopped]).unwrap();
        assert_eq!(changes.len(), 1);
        assert!(!changes[0].added);
    }

    #[test]
    fn resource_round_trips_with_capabilities_and_metadata() {
        let s = Store::open_in_memory().unwrap();
        let caps = CapabilitySet::from_iter_caps([
            Capability::parse("resource:discover").unwrap(),
            Capability::parse("vfs:write").unwrap(),
        ]);
        let n = node("web", None)
            .with_capabilities(caps)
            .with_metadata(serde_json::json!({"image": "nginx:1.27"}));
        s.upsert_resources(std::slice::from_ref(&n)).unwrap();
        let back = s.resource(&n.id).unwrap().expect("row exists");
        assert_eq!(back.id, n.id);
        assert_eq!(back.name, "web");
        assert_eq!(back.metadata["image"], serde_json::json!("nginx:1.27"));
        let restored = decode_capabilities(&back.metadata);
        assert!(restored.allows(&Capability::parse("resource:discover").unwrap()));
        assert!(restored.allows(&Capability::parse("vfs:write").unwrap()));
    }

    #[test]
    fn relations_round_trip_and_filter_by_endpoint() {
        let s = Store::open_in_memory().unwrap();
        let a = node("web", None);
        let b = node("img", None);
        s.upsert_resources(&[a.clone(), b.clone()]).unwrap();
        s.upsert_relations(&[
            Relation::new(a.id.clone(), b.id.clone(), RelationKind::UsesImage),
            Relation::new(a.id.clone(), b.id.clone(), RelationKind::UsesImage),
        ])
        .unwrap();
        let rels = s.relations_of(&a.id).unwrap();
        assert_eq!(rels.len(), 1, "duplicate relation collapses");
        assert_eq!(rels[0].kind, RelationKind::UsesImage);
        assert_eq!(s.relations_of(&b.id).unwrap().len(), 1);
    }

    #[test]
    fn listing_filters_by_provider_and_state() {
        let s = Store::open_in_memory().unwrap();
        let other = ResourceNode::new(
            ResourceId::derive(&["mp", "vm"]),
            ResourceKind::Sandbox,
            p("multipass"),
            "vm",
            ResourceState::Running,
            None,
            "2026-10-07T00:00:00Z".to_string(),
        );
        let running = node("web", None);
        let mut stopped = node("db", None);
        stopped.state = ResourceState::Stopped;
        s.upsert_resources(&[running.clone(), stopped.clone(), other.clone()])
            .unwrap();

        assert_eq!(s.resources(None, None).unwrap().len(), 3);
        assert_eq!(s.resources(Some(&p("docker")), None).unwrap().len(), 2);
        assert_eq!(
            s.resources(Some(&p("docker")), Some(ResourceState::Stopped))
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn stale_marking_touches_only_unseen_resources() {
        let s = Store::open_in_memory().unwrap();
        let seen = node("web", None);
        let unseen = node("db", None);
        let other = ResourceNode::new(
            ResourceId::derive(&["mp", "vm"]),
            ResourceKind::Sandbox,
            p("multipass"),
            "vm",
            ResourceState::Running,
            None,
            "2026-10-07T00:00:00Z".to_string(),
        );
        s.upsert_resources(&[seen.clone(), unseen.clone(), other.clone()])
            .unwrap();
        let n = s
            .mark_resources_stale(&p("docker"), std::slice::from_ref(&seen.id))
            .unwrap();
        assert_eq!(n, 1);
        assert_eq!(
            s.resource(&seen.id).unwrap().unwrap().state,
            ResourceState::Running
        );
        assert_eq!(
            s.resource(&unseen.id).unwrap().unwrap().state,
            ResourceState::Unknown
        );
        assert_eq!(
            s.resource(&other.id).unwrap().unwrap().state,
            ResourceState::Running,
            "another provider must be untouched"
        );
    }

    #[test]
    fn stale_marking_never_tombstones() {
        // A missed discovery round must not be able to destroy durable state.
        let s = Store::open_in_memory().unwrap();
        let n = node("web", None);
        s.upsert_resources(std::slice::from_ref(&n)).unwrap();
        s.mark_resources_stale(&p("docker"), &[]).unwrap();
        s.mark_resources_stale(&p("docker"), &[]).unwrap();
        assert_eq!(
            s.resource(&n.id).unwrap().unwrap().state,
            ResourceState::Unknown
        );
    }

    #[test]
    fn delete_removes_relations_too() {
        let s = Store::open_in_memory().unwrap();
        let a = node("web", None);
        let b = node("img", None);
        s.upsert_resources(&[a.clone(), b.clone()]).unwrap();
        s.upsert_relations(&[Relation::new(
            a.id.clone(),
            b.id.clone(),
            RelationKind::UsesImage,
        )])
        .unwrap();
        s.delete_resource(&a.id).unwrap();
        assert!(s.resource(&a.id).unwrap().is_none());
        assert!(s.relations_of(&b.id).unwrap().is_empty());
    }
}
