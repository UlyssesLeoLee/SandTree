//! Mount registry (FR-041; `workspace_mount` table).

use std::collections::BTreeMap;

use sandtree_model::id::ResourceId;
use serde::{Deserialize, Serialize};

use crate::uri::WorkspaceUri;

/// Whether a mount permits writes (BD §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MountMode {
    /// Read-only mapping.
    ReadOnly,
    /// Read-write mapping.
    ReadWrite,
}

impl MountMode {
    /// Whether writes are permitted through this mount.
    pub fn allows_write(self) -> bool {
        matches!(self, MountMode::ReadWrite)
    }

    /// Parse wire form.
    pub fn from_wire(s: &str) -> Option<Self> {
        match s {
            "ro" | "read_only" | "readonly" => Some(MountMode::ReadOnly),
            "rw" | "read_write" | "readwrite" => Some(MountMode::ReadWrite),
            _ => None,
        }
    }
}

/// One host ↔ sandbox ↔ container mount record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MountRecord {
    /// Stable record id (`workspace_mount.id`).
    pub id: String,
    /// Resource the mount belongs to.
    pub resource_id: ResourceId,
    /// Optional host-side source URI; `None` for guest-only volumes.
    pub source_uri: Option<String>,
    /// Canonical target inside the resource, `stfs://…` or a provider path.
    pub target_uri: String,
    /// Access mode.
    pub mode: MountMode,
}

impl MountRecord {
    /// Build a read-write record.
    pub fn new(
        id: impl Into<String>,
        resource_id: ResourceId,
        source_uri: Option<String>,
        target_uri: impl Into<String>,
        mode: MountMode,
    ) -> Self {
        Self {
            id: id.into(),
            resource_id,
            source_uri,
            target_uri: target_uri.into(),
            mode,
        }
    }
}

/// In-memory mount registry.
///
/// Lookups are by canonical `stfs` target prefix, longest-prefix-wins, which is
/// what lets a nested read-only mount shadow a broader read-write one.
#[derive(Debug, Default, Clone)]
pub struct MountRegistry {
    records: BTreeMap<String, MountRecord>,
}

impl MountRegistry {
    /// Empty registry.
    pub fn new() -> Self {
        Self {
            records: BTreeMap::new(),
        }
    }

    /// Insert or replace a record. A duplicate id is an invariant violation.
    pub fn insert(&mut self, record: MountRecord) -> Result<(), MountError> {
        if record.id.trim().is_empty() {
            return Err(MountError::EmptyId);
        }
        self.records.insert(record.id.clone(), record);
        Ok(())
    }

    /// Remove by id.
    pub fn remove(&mut self, id: &str) -> Option<MountRecord> {
        self.records.remove(id)
    }

    /// Fetch by id.
    pub fn get(&self, id: &str) -> Option<&MountRecord> {
        self.records.get(id)
    }

    /// All records for one resource, sorted by target.
    pub fn targets_for(&self, resource_id: &ResourceId) -> Vec<&MountRecord> {
        let mut v: Vec<&MountRecord> = self
            .records
            .values()
            .filter(|r| &r.resource_id == resource_id)
            .collect();
        v.sort_by(|a, b| (&a.target_uri, &a.id).cmp(&(&b.target_uri, &b.id)));
        v
    }

    /// All records, sorted by target then id.
    pub fn list(&self) -> Vec<&MountRecord> {
        let mut v: Vec<&MountRecord> = self.records.values().collect();
        v.sort_by(|a, b| (&a.target_uri, &a.id).cmp(&(&b.target_uri, &b.id)));
        v
    }

    /// Longest-prefix mount covering a URI, if any.
    ///
    /// The target is matched on `stfs` segment boundaries so that a mount of
    /// `stfs://res/ws` does not cover `stfs://res/ws-private`.
    pub fn resolve(&self, uri: &WorkspaceUri) -> Option<&MountRecord> {
        let needle = uri.to_uri_string();
        let mut best: Option<&MountRecord> = None;
        for rec in self.records.values() {
            let target = &rec.target_uri;
            if needle == *target
                || needle.starts_with(&format!("{}/", target.trim_end_matches('/')))
            {
                let better = match best {
                    None => true,
                    Some(cur) => target.len() > cur.target_uri.len(),
                };
                if better {
                    best = Some(rec);
                }
            }
        }
        best
    }

    /// Whether a write through `uri` is permitted by the resolved mount.
    ///
    /// With no mount at all the answer is `false`: an unmounted path is not a
    /// licence to mutate.
    pub fn allows_write(&self, uri: &WorkspaceUri) -> bool {
        self.resolve(uri)
            .map(|m| m.mode.allows_write())
            .unwrap_or(false)
    }

    /// Number of records.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

/// Mount registry errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MountError {
    /// Record id was blank.
    #[error("mount record id must not be empty")]
    EmptyId,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rid(name: &str) -> ResourceId {
        ResourceId::derive(&["mount-test", name])
    }

    fn root_of(res: &ResourceId) -> String {
        WorkspaceUri::root(res.clone()).to_uri_string()
    }

    fn uri(res: &ResourceId, path: &str) -> WorkspaceUri {
        let mut u = WorkspaceUri::root(res.clone());
        for seg in path.split('/').filter(|s| !s.is_empty()) {
            u = u.child(seg).unwrap();
        }
        u
    }

    #[test]
    fn insert_get_remove() {
        let mut reg = MountRegistry::new();
        let r = MountRecord::new("m1", rid("a"), None, "stfs://res/ws", MountMode::ReadOnly);
        assert!(reg.insert(r).is_ok());
        assert_eq!(reg.len(), 1);
        assert!(reg.get("m1").is_some());
        assert!(reg.remove("m1").is_some());
        assert!(reg.is_empty());
    }

    #[test]
    fn rejects_empty_id() {
        let mut reg = MountRegistry::new();
        let r = MountRecord::new("  ", rid("a"), None, "stfs://res/ws", MountMode::ReadOnly);
        assert_eq!(reg.insert(r).unwrap_err(), MountError::EmptyId);
    }

    #[test]
    fn resolve_prefers_longest_prefix() {
        let res = rid("a");
        let mut reg = MountRegistry::new();
        reg.insert(MountRecord::new(
            "outer",
            res.clone(),
            None,
            root_of(&res),
            MountMode::ReadWrite,
        ))
        .unwrap();
        reg.insert(MountRecord::new(
            "inner",
            res.clone(),
            None,
            format!("{}/src", root_of(&res)),
            MountMode::ReadOnly,
        ))
        .unwrap();
        let deep = uri(&res, "src");
        assert_eq!(reg.resolve(&deep).unwrap().id, "inner");
        assert!(
            !reg.allows_write(&deep),
            "read-only shadow must deny writes"
        );
        let other = WorkspaceUri::root(res.clone());
        // Root target is shorter, so it wins for an unrelated path.
        assert!(reg.resolve(&other).is_some());
    }

    #[test]
    fn unmounted_path_denies_write() {
        // An unmounted path is not a licence to mutate: only paths actually
        // covered by a read-write mount may be written through.
        let mut reg = MountRegistry::new();
        let res = rid("a");
        reg.insert(MountRecord::new(
            "m",
            res.clone(),
            None,
            format!("{}/inside", root_of(&res)),
            MountMode::ReadWrite,
        ))
        .unwrap();
        assert!(!reg.allows_write(&uri(&res, "elsewhere")));
        assert!(reg.allows_write(&uri(&res, "inside")));
        assert!(reg.allows_write(&uri(&res, "inside/deeper/file.txt")));
    }

    #[test]
    fn listing_is_deterministic() {
        let mut reg = MountRegistry::new();
        let res = rid("a");
        for (id, target) in [("z", "b"), ("a", "c"), ("m", "a")] {
            reg.insert(MountRecord::new(
                id,
                res.clone(),
                None,
                target,
                MountMode::ReadOnly,
            ))
            .unwrap();
        }
        let order: Vec<&str> = reg.list().iter().map(|r| r.id.as_str()).collect();
        assert_eq!(order, vec!["m", "z", "a"], "sorted by target then id");
    }

    #[test]
    fn mount_mode_wire_round_trip() {
        assert_eq!(MountMode::from_wire("ro"), Some(MountMode::ReadOnly));
        assert_eq!(MountMode::from_wire("rw"), Some(MountMode::ReadWrite));
        assert_eq!(MountMode::from_wire("bogus"), None);
    }
}
