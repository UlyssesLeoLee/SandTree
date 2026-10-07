//! Typed repositories over the Core store (DD-DATA §2, §6).
//!
//! The transaction boundaries here are the design's, not an implementation
//! detail (DD-DATA §2):
//!
//! * discovery batch — resource + relation upsert + stale marks in **one** write
//!   transaction, so a partially applied discovery can never leave the graph
//!   describing a state the provider never reported;
//! * operation start — the job row is inserted **before** provider dispatch;
//! * snapshot — entries are inserted only after the CAS objects exist.

use rusqlite::{params, Connection, OptionalExtension};
use sandtree_model::capability::Capability;
use sandtree_model::error::{DomainError, ErrorCode};
use sandtree_model::id::{EndpointId, PluginId, ResourceId, SnapshotId};
use sandtree_model::operation::{OperationId, OperationRequest, OperationState};
use sandtree_model::resource::{ResourceNode, ResourceState};
use sandtree_observation_model::FileMetadata;
use serde_json::Value as Json;

use crate::db::{DbFailure, Store};

/// A stored operation job row.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct OperationJobRecord {
    /// Job id.
    pub id: String,
    /// Target resource, when the job targets one.
    pub resource_id: Option<ResourceId>,
    /// Operation name.
    pub operation: String,
    /// Current state.
    pub state: OperationState,
    /// Correlation id text.
    pub correlation_id: String,
    /// Stable error code when failed.
    pub error_code: Option<ErrorCode>,
    /// Provider result payload.
    pub result: Json,
    /// Request timestamp.
    pub requested_at: String,
    /// Completion timestamp.
    pub finished_at: Option<String>,
}

/// A snapshot manifest plus its entries.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SnapshotManifest {
    /// Snapshot id.
    pub id: SnapshotId,
    /// Snapshotted resource.
    pub resource_id: ResourceId,
    /// Creation time.
    pub created_at: String,
    /// BLAKE3 over the canonical entry listing.
    pub manifest_hash: String,
    /// File entries.
    pub entries: Vec<FileMetadata>,
}

/// Plugin package row.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PluginPackageRow {
    /// Plugin id.
    pub plugin_id: String,
    /// Version.
    pub version: String,
    /// Content hash.
    pub content_hash: String,
    /// SPDX license expression.
    pub license_expr: String,
    /// Whether the package is enabled.
    pub enabled: bool,
}

/// A capability grant to persist (`plugin_grant`).
#[derive(Debug, Clone, PartialEq)]
pub struct CapabilityGrant {
    /// App the grant belongs to.
    pub app_id: String,
    /// Plugin the grant is for.
    pub plugin_id: String,
    /// Capability being granted or denied.
    pub capability: Capability,
    /// Resource scope the grant applies to.
    pub resource_scope: String,
    /// `allow` / `deny`.
    pub decision: String,
}

/// A plugin instance row (`plugin_instance`).
#[derive(Debug, Clone, PartialEq)]
pub struct PluginInstanceRow {
    /// Instance id.
    pub instance_id: String,
    /// Owning plugin.
    pub plugin_id: PluginId,
    /// Package version.
    pub version: String,
    /// Cluster the instance serves.
    pub cluster_id: String,
    /// Active generation.
    pub generation: u64,
    /// Lifecycle state.
    pub state: String,
    /// Health summary.
    pub health: String,
}

/// One stored capability grant.
#[derive(Debug, Clone, PartialEq)]
pub struct GrantRow {
    /// App the grant belongs to.
    pub app_id: String,
    /// Plugin id.
    pub plugin_id: String,
    /// Capability string.
    pub capability: String,
    /// Resource scope.
    pub resource_scope: String,
    /// `allow` / `deny`.
    pub decision: String,
}

/// Docker endpoint row with credentials already reduced to a reference.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct DockerEndpointRow {
    /// Endpoint id.
    pub id: EndpointId,
    /// Endpoint URI (credentials must not be embedded; NFR-S03).
    pub uri: String,
    /// Negotiated API version.
    pub api_version: Option<String>,
    /// Engine version.
    pub engine_version: Option<String>,
    /// Host OS.
    pub os: Option<String>,
    /// Host architecture.
    pub arch: Option<String>,
    /// Health summary.
    pub health: String,
}

/// Workspace mount row.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct WorkspaceMountRow {
    /// Mount id.
    pub id: String,
    /// Owning resource.
    pub resource_id: ResourceId,
    /// Host-side source, when any.
    pub source_uri: Option<String>,
    /// Target inside the resource.
    pub target_uri: String,
    /// `ro` / `rw`.
    pub mode: String,
}

/// Convert a rusqlite error.
fn corrupt_row(what: &str) -> DomainError {
    DomainError::new(
        ErrorCode::STORE_TRANSACTION_FAILED,
        format!("corrupt {what} in stored row"),
    )
}

pub(crate) fn db_err(e: rusqlite::Error) -> DomainError {
    DomainError::new(
        ErrorCode::STORE_TRANSACTION_FAILED,
        "sqlite operation failed",
    )
    .with_detail(e.to_string())
}

/// Resource persistence.
pub trait ResourceRepo {
    /// Upsert a discovery batch atomically.
    fn upsert_batch(&self, nodes: &[ResourceNode]) -> Result<Vec<Change>, DomainError>;
    /// Fetch one resource.
    fn get(&self, id: &ResourceId) -> Result<Option<ResourceNode>, DomainError>;
    /// List resources with an optional provider/kind/state filter.
    fn list(
        &self,
        provider: Option<&PluginId>,
        state: Option<ResourceState>,
    ) -> Result<Vec<ResourceNode>, DomainError>;
    /// Delete a resource row.
    fn delete(&self, id: &ResourceId) -> Result<(), DomainError>;
    /// Mark a provider's unseen resources as unknown (reconcile, step 4).
    fn mark_stale(&self, provider: &PluginId, seen: &[ResourceId]) -> Result<usize, DomainError>;
}

/// One change produced by a repository upsert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    /// `added` / `changed`.
    pub added: bool,
    /// Resource id.
    pub id: ResourceId,
}

impl Store {
    /// Insert the job row before dispatching to a provider (DD-DATA §2).
    pub fn insert_operation(
        &self,
        id: &OperationId,
        req: &OperationRequest,
    ) -> Result<(), DomainError> {
        self.write(|tx| {
            tx.execute(
                "INSERT INTO operation_job(id, resource_id, operation, state, requested_at, correlation_id)
                 VALUES (?1, ?2, ?3, 'pending', ?4, ?5)",
                params![
                    id.as_str(),
                    req.resource_id.as_str(),
                    req.op.as_str(),
                    crate::now_rfc3339(),
                    req.correlation_id.id().as_str(),
                ],
            )
            .map_err(db_err)?;
            Ok(())
        })
    }

    /// Move a job to a terminal state.
    pub fn transition_operation(
        &self,
        id: &OperationId,
        state: OperationState,
        error_code: Option<ErrorCode>,
        result: &Json,
    ) -> Result<(), DomainError> {
        self.write(|tx| {
            tx.execute(
                "UPDATE operation_job
                    SET state = ?2, error_code = ?3, result_json = ?4, finished_at = ?5
                  WHERE id = ?1",
                params![
                    id.as_str(),
                    state.as_str(),
                    error_code.map(ErrorCode::as_str),
                    result.to_string(),
                    crate::now_rfc3339(),
                ],
            )
            .map_err(db_err)?;
            Ok(())
        })
    }

    /// Read one job.
    pub fn operation(&self, id: &OperationId) -> Result<Option<OperationJobRecord>, DomainError> {
        self.read(|c| read_operation(c, id.as_str()).map_err(DbFailure::from))
    }

    /// Append an event to the durable log (FR-063, FR-064).
    pub fn append_event(&self, ev: &sandtree_model::event::EventRecord) -> Result<(), DomainError> {
        self.write(|tx| {
            tx.execute(
                "INSERT INTO event_log(resource_id, event_type, correlation_id, payload_json, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    ev.resource_id.as_ref().map(ResourceId::as_str),
                    ev.event_type.as_str(),
                    ev.correlation_id.id().as_str(),
                    ev.payload.to_string(),
                    ev.ts,
                ],
            )
            .map_err(db_err)?;
            Ok(())
        })
    }

    /// Apply retention to the event log (DD-DATA §9: 30 days by default).
    pub fn purge_events(&self, older_than: &str) -> Result<usize, DomainError> {
        self.write(|tx| {
            let n = tx
                .execute("DELETE FROM event_log WHERE created_at < ?1", [older_than])
                .map_err(db_err)?;
            Ok(n)
        })
    }

    /// Commit a snapshot manifest and its entries (DD-DATA §2).
    ///
    /// Callers must have stored the CAS objects first; this transaction is the
    /// moment the snapshot becomes visible.
    pub fn insert_snapshot(&self, manifest: &SnapshotManifest) -> Result<(), DomainError> {
        self.write(|tx| {
            tx.execute(
                "INSERT INTO snapshot(id, resource_id, created_at, manifest_hash, metadata_json)
                 VALUES (?1, ?2, ?3, ?4, '{}')",
                params![
                    manifest.id.as_str(),
                    manifest.resource_id.as_str(),
                    manifest.created_at,
                    manifest.manifest_hash,
                ],
            )
            .map_err(db_err)?;
            for e in &manifest.entries {
                tx.execute(
                    "INSERT INTO snapshot_entry(snapshot_id, uri, content_hash, size, mtime_ns)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        manifest.id.as_str(),
                        e.path,
                        e.content_hash,
                        e.size as i64,
                        e.mtime_ns.map(|v| v as i64),
                    ],
                )
                .map_err(db_err)?;
            }
            Ok(())
        })
    }

    /// Snapshots for a resource, newest first.
    pub fn list_snapshots(
        &self,
        resource: &ResourceId,
    ) -> Result<Vec<SnapshotManifest>, DomainError> {
        self.read(|c| {
            let mut stmt = c
                .prepare(
                    "SELECT id, created_at, manifest_hash FROM snapshot
                      WHERE resource_id = ?1 ORDER BY created_at DESC, id DESC",
                )
                .map_err(db_err)?;
            let rows = stmt
                .query_map([resource.as_str()], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                })
                .map_err(db_err)?;
            let mut out = Vec::new();
            for r in rows {
                let (id, created_at, manifest_hash) = r.map_err(db_err)?;
                let sid = SnapshotId::from_digest(&id).map_err(|e| {
                    DomainError::new(ErrorCode::STORE_TRANSACTION_FAILED, "corrupt snapshot id")
                        .with_detail(e.to_string())
                })?;
                let entries = read_snapshot_entries(c, &sid)?;
                out.push(SnapshotManifest {
                    id: sid,
                    resource_id: resource.clone(),
                    created_at,
                    manifest_hash,
                    entries,
                });
            }
            Ok(out)
        })
    }

    /// Delete a snapshot and its entries.
    /// Delete a snapshot and its entries in one transaction.
    ///
    /// Returns the number of manifest rows removed, so a caller can tell an
    /// absent snapshot from a deleted one instead of reporting success for
    /// both.
    pub fn delete_snapshot(&self, id: &SnapshotId) -> Result<usize, DomainError> {
        self.write(|tx| {
            tx.execute(
                "DELETE FROM snapshot_entry WHERE snapshot_id = ?1",
                [id.as_str()],
            )
            .map_err(db_err)?;
            let n = tx
                .execute("DELETE FROM snapshot WHERE id = ?1", [id.as_str()])
                .map_err(db_err)?;
            Ok(n)
        })
    }

    /// Insert a verified plugin package (DD-DATA §2: only after verification).
    pub fn upsert_plugin_package(
        &self,
        row: &PluginPackageRow,
        manifest_json: &str,
    ) -> Result<(), DomainError> {
        self.write(|tx| {
            tx.execute(
                "INSERT INTO plugin_package(plugin_id, version, content_hash, manifest_json, license_expr, installed_at, enabled)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(plugin_id, version) DO UPDATE SET
                     content_hash = excluded.content_hash,
                     manifest_json = excluded.manifest_json,
                     license_expr = excluded.license_expr,
                     enabled = excluded.enabled",
                params![
                    row.plugin_id,
                    row.version,
                    row.content_hash,
                    manifest_json,
                    row.license_expr,
                    crate::now_rfc3339(),
                    i64::from(row.enabled),
                ],
            )
            .map_err(db_err)?;
            Ok(())
        })
    }

    /// Record the active generation of a plugin instance (FR-052).
    pub fn upsert_plugin_instance(&self, row: &PluginInstanceRow) -> Result<(), DomainError> {
        let PluginInstanceRow {
            instance_id,
            plugin_id,
            version,
            cluster_id,
            generation,
            state,
            health,
        } = row;
        self.write(|tx| {
            tx.execute(
                "INSERT INTO plugin_instance(instance_id, plugin_id, version, cluster_id, generation, state, health, started_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(instance_id) DO UPDATE SET
                     generation = excluded.generation,
                     state = excluded.state,
                     health = excluded.health",
                params![
                    instance_id,
                    plugin_id.as_str(),
                    version,
                    cluster_id,
                    *generation as i64,
                    state,
                    health,
                    crate::now_rfc3339(),
                ],
            )
            .map_err(db_err)?;
            Ok(())
        })
    }

    /// List installed packages in deterministic order.
    pub fn list_plugin_packages(&self) -> Result<Vec<PluginPackageRow>, DomainError> {
        self.read(|c| {
            let mut stmt = c
                .prepare(
                    "SELECT plugin_id, version, content_hash, license_expr, enabled
                       FROM plugin_package ORDER BY plugin_id, version",
                )
                .map_err(db_err)?;
            let rows = stmt
                .query_map([], |row| {
                    Ok(PluginPackageRow {
                        plugin_id: row.get(0)?,
                        version: row.get(1)?,
                        content_hash: row.get(2)?,
                        license_expr: row.get(3)?,
                        enabled: row.get::<_, i64>(4)? != 0,
                    })
                })
                .map_err(db_err)?;
            rows.collect::<Result<Vec<_>, rusqlite::Error>>()
                .map_err(DbFailure::from)
        })
    }

    /// Store a capability grant (FR-051).
    pub fn upsert_grant(&self, grant: &CapabilityGrant) -> Result<(), DomainError> {
        let CapabilityGrant {
            app_id,
            plugin_id,
            capability,
            resource_scope,
            decision,
        } = grant;
        self.write(|tx| {
            tx.execute(
                "INSERT INTO plugin_grant(app_id, plugin_id, capability, resource_scope, decision, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(app_id, plugin_id, capability, resource_scope)
                 DO UPDATE SET decision = excluded.decision, updated_at = excluded.updated_at",
                params![
                    app_id,
                    plugin_id,
                    capability.to_string(),
                    resource_scope,
                    decision,
                    crate::now_rfc3339(),
                ],
            )
            .map_err(db_err)?;
            Ok(())
        })
    }

    /// Read all grants for an app, ordered for deterministic policy loading.
    pub fn list_grants(&self, app_id: &str) -> Result<Vec<GrantRow>, DomainError> {
        self.read(|c| {
            let mut stmt = c
                .prepare(
                    "SELECT app_id, plugin_id, capability, resource_scope, decision
                       FROM plugin_grant WHERE app_id = ?1
                      ORDER BY plugin_id, capability, resource_scope",
                )
                .map_err(db_err)?;
            let rows = stmt
                .query_map([app_id], |row| {
                    Ok(GrantRow {
                        app_id: row.get(0)?,
                        plugin_id: row.get(1)?,
                        capability: row.get(2)?,
                        resource_scope: row.get(3)?,
                        decision: row.get(4)?,
                    })
                })
                .map_err(db_err)?;
            rows.collect::<Result<Vec<_>, rusqlite::Error>>()
                .map_err(DbFailure::from)
        })
    }

    /// Record an immutable app generation and activate it atomically (FR-053).
    pub fn insert_app_generation(
        &self,
        app_id: &str,
        generation: u64,
        manifest_hash: &str,
        manifest_json: &str,
    ) -> Result<(), DomainError> {
        self.write(|tx| {
            tx.execute(
                "INSERT INTO app_generation(app_id, generation, manifest_hash, manifest_json, state, created_at, activated_at)
                 VALUES (?1, ?2, ?3, ?4, 'active', ?5, ?5)",
                params![
                    app_id,
                    generation as i64,
                    manifest_hash,
                    manifest_json,
                    crate::now_rfc3339(),
                ],
            )
            .map_err(db_err)?;
            tx.execute(
                "UPDATE app_generation SET state = 'superseded'
                  WHERE app_id = ?1 AND generation <> ?2 AND state = 'active'",
                params![app_id, generation as i64],
            )
            .map_err(db_err)?;
            Ok(())
        })
    }

    /// Upsert a Docker endpoint profile. The URI must not embed credentials.
    ///
    /// NFR-S03. A URI authority is `<userinfo@>host[:port]`, so a credential is
    /// present exactly when the authority contains `@`. The previous check
    /// treated any `:` before the first `@` as a credential, which cannot
    /// distinguish `user:password@host` from `host:2376` — so it refused
    /// **every** TCP endpoint, including the remote-engine case UAT-018 exists
    /// to cover. The split tests the host part against credentials, not the
    /// port separator.
    pub fn upsert_docker_endpoint(&self, row: &DockerEndpointRow) -> Result<(), DomainError> {
        let authority = row
            .uri
            .split_once("://")
            .map(|(_, rest)| rest.split('/').next().unwrap_or(""))
            .unwrap_or("");
        if authority.contains('@') {
            return Err(DomainError::new(
                ErrorCode::POLICY_DENIED,
                format!(
                    "docker endpoint URI must not embed credentials (NFR-S03): {}",
                    row.uri
                ),
            ));
        }
        self.write(|tx| {
            tx.execute(
                "INSERT INTO docker_endpoint(id, uri, api_version, engine_version, os, arch, health, last_seen)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(id) DO UPDATE SET
                     uri = excluded.uri,
                     api_version = excluded.api_version,
                     engine_version = excluded.engine_version,
                     os = excluded.os,
                     arch = excluded.arch,
                     health = excluded.health,
                     last_seen = excluded.last_seen",
                params![
                    row.id.as_str(),
                    row.uri,
                    row.api_version,
                    row.engine_version,
                    row.os,
                    row.arch,
                    row.health,
                    crate::now_rfc3339(),
                ],
            )
            .map_err(db_err)?;
            Ok(())
        })
    }

    /// Read all Docker endpoints.
    pub fn list_docker_endpoints(&self) -> Result<Vec<DockerEndpointRow>, DomainError> {
        self.read(|c| {
            type Raw = (
                String,
                String,
                Option<String>,
                Option<String>,
                Option<String>,
                Option<String>,
                String,
            );
            let mut stmt = c
                .prepare(
                    "SELECT id, uri, api_version, engine_version, os, arch, health
                       FROM docker_endpoint ORDER BY id",
                )
                .map_err(DbFailure::from)?;
            let rows = stmt
                .query_map([], |row| {
                    let raw: Raw = (
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                    );
                    Ok(raw)
                })
                .map_err(DbFailure::from)?;
            let mut out = Vec::new();
            for r in rows {
                let (id, uri, api_version, engine_version, os, arch, health) =
                    r.map_err(DbFailure::from)?;
                let parsed = EndpointId::from_str_ok(&id)
                    .ok_or_else(|| DbFailure::Domain(corrupt_row("docker_endpoint.id")))?;
                out.push(DockerEndpointRow {
                    id: parsed,
                    uri,
                    api_version,
                    engine_version,
                    os,
                    arch,
                    health,
                });
            }
            Ok(out)
        })
    }

    /// Upsert a workspace mount (FR-041).
    pub fn upsert_workspace_mount(&self, row: &WorkspaceMountRow) -> Result<(), DomainError> {
        self.write(|tx| {
            tx.execute(
                "INSERT INTO workspace_mount(id, resource_id, source_uri, target_uri, mode, metadata_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, '{}')
                 ON CONFLICT(id) DO UPDATE SET
                     source_uri = excluded.source_uri,
                     target_uri = excluded.target_uri,
                     mode = excluded.mode",
                params![
                    row.id,
                    row.resource_id.as_str(),
                    row.source_uri,
                    row.target_uri,
                    row.mode,
                ],
            )
            .map_err(db_err)?;
            Ok(())
        })
    }

    /// Read mounts for a resource.
    /// Every snapshot, newest first.
    ///
    /// Distinct from [`Store::list_snapshots`], which is scoped to one
    /// resource. The IPC surface needs the global list, and making callers
    /// invent a sentinel resource id to get it would put a fake id into
    /// queries.
    pub fn all_snapshots(&self) -> Result<Vec<SnapshotManifest>, DomainError> {
        self.read(|c| {
            let mut stmt = c
                .prepare(
                    "SELECT id, resource_id, created_at, manifest_hash FROM snapshot
                      ORDER BY created_at DESC, id DESC",
                )
                .map_err(db_err)?;
            let rows = stmt
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                })
                .map_err(db_err)?;
            let mut out = Vec::new();
            for r in rows {
                let (id, resource_id, created_at, manifest_hash) = r.map_err(db_err)?;
                let parsed_id = SnapshotId::parse(&id)
                    .map_err(|e| corrupt_row(&format!("snapshot id {id:?}: {e:?}")))?;
                let parsed_resource = ResourceId::parse(&resource_id)
                    .map_err(|e| corrupt_row(&format!("snapshot {id}: {e:?}")))?;
                out.push(SnapshotManifest {
                    id: parsed_id,
                    resource_id: parsed_resource,
                    created_at,
                    manifest_hash,
                    // Entry listing is loaded on demand; the list view does not
                    // need it and loading it here would be O(entries) per row.
                    entries: Vec::new(),
                });
            }
            Ok(out)
        })
    }

    /// Every workspace mount, in `target_uri, id` order.
    pub fn all_workspace_mounts(&self) -> Result<Vec<WorkspaceMountRow>, DomainError> {
        self.read(|c| {
            let mut stmt = c
                .prepare(
                    "SELECT id, resource_id, source_uri, target_uri, mode
                       FROM workspace_mount ORDER BY target_uri, id",
                )
                .map_err(db_err)?;
            let rows = stmt
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                })
                .map_err(db_err)?;
            let mut out = Vec::new();
            for r in rows {
                let (id, resource_id, source_uri, target_uri, mode) = r.map_err(db_err)?;
                let parsed_resource = ResourceId::parse(&resource_id)
                    .map_err(|e| corrupt_row(&format!("workspace mount {id}: {e:?}")))?;
                out.push(WorkspaceMountRow {
                    id,
                    resource_id: parsed_resource,
                    source_uri,
                    target_uri,
                    mode,
                });
            }
            Ok(out)
        })
    }

    /// Mounts for one resource, in `target_uri, id` order.
    pub fn list_workspace_mounts(
        &self,
        resource: &ResourceId,
    ) -> Result<Vec<WorkspaceMountRow>, DomainError> {
        self.read(|c| {
            let mut stmt = c
                .prepare(
                    "SELECT id, resource_id, source_uri, target_uri, mode
                       FROM workspace_mount WHERE resource_id = ?1 ORDER BY target_uri, id",
                )
                .map_err(db_err)?;
            let rows = stmt
                .query_map([resource.as_str()], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                })
                .map_err(DbFailure::from)?;
            let mut out = Vec::new();
            for r in rows {
                let (id, rid, source_uri, target_uri, mode) = r.map_err(DbFailure::from)?;
                let resource_id = ResourceId::parse(&rid).map_err(|e| {
                    DbFailure::Domain(
                        corrupt_row("workspace_mount.resource_id").with_detail(e.to_string()),
                    )
                })?;
                out.push(WorkspaceMountRow {
                    id,
                    resource_id,
                    source_uri,
                    target_uri,
                    mode,
                });
            }
            Ok(out)
        })
    }

    /// Every content hash referenced by any snapshot entry (GC mark phase).
    pub fn referenced_hashes(&self) -> Result<std::collections::BTreeSet<String>, DomainError> {
        self.read(|c| {
            let mut stmt = c
                .prepare("SELECT content_hash FROM snapshot_entry WHERE content_hash IS NOT NULL")
                .map_err(db_err)?;
            let rows = stmt
                .query_map([], |row| row.get::<_, String>(0))
                .map_err(db_err)?;
            let mut set = std::collections::BTreeSet::new();
            for r in rows {
                set.insert(r.map_err(db_err)?);
            }
            Ok(set)
        })
    }
}

fn read_operation(c: &Connection, id: &str) -> Result<Option<OperationJobRecord>, DomainError> {
    let row = c
        .query_row(
            "SELECT id, resource_id, operation, state, correlation_id, error_code, result_json, requested_at, finished_at
               FROM operation_job WHERE id = ?1",
            [id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, Option<String>>(8)?,
                ))
            },
        )
        .optional()
        .map_err(db_err)?;
    Ok(row.map(
        |(
            id,
            resource_id,
            operation,
            state,
            correlation_id,
            error_code,
            result_json,
            requested_at,
            finished_at,
        )| {
            OperationJobRecord {
                id,
                resource_id: resource_id.and_then(|r| ResourceId::parse(&r).ok()),
                operation,
                state: OperationState::from_wire(&state),
                correlation_id,
                error_code: error_code.as_deref().and_then(ErrorCode::parse),
                result: result_json
                    .and_then(|s| serde_json::from_str(&s).ok())
                    .unwrap_or(Json::Null),
                requested_at,
                finished_at,
            }
        },
    ))
}

fn read_snapshot_entries(
    c: &Connection,
    id: &SnapshotId,
) -> Result<Vec<FileMetadata>, DomainError> {
    let mut stmt = c
        .prepare(
            "SELECT uri, content_hash, size, mtime_ns FROM snapshot_entry
              WHERE snapshot_id = ?1 ORDER BY uri",
        )
        .map_err(db_err)?;
    let rows = stmt
        .query_map([id.as_str()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Option<i64>>(3)?,
            ))
        })
        .map_err(db_err)?;
    let mut out = Vec::new();
    for r in rows {
        let (uri, hash, size, mtime) = r.map_err(db_err)?;
        let state = if hash.is_some() {
            sandtree_observation_model::ContentHashState::ContentCached
        } else {
            sandtree_observation_model::ContentHashState::MetadataKnown
        };
        out.push(FileMetadata {
            path: uri,
            is_dir: false,
            size: size.max(0) as u64,
            mtime_ns: mtime.map(i128::from),
            hash_state: state,
            content_hash: hash,
        });
    }
    Ok(out)
}

/// Raw columns of a `resource` row, before id/kind parsing.
#[derive(Debug, Clone)]
pub struct ResourceRow {
    /// Primary key.
    pub id: String,
    /// Owning provider.
    pub provider_id: String,
    /// Kind wire name.
    pub kind: String,
    /// Display name.
    pub name: String,
    /// State wire name.
    pub state: String,
    /// Parent id, when attached.
    pub parent_id: Option<String>,
    /// Metadata JSON.
    pub metadata_json: String,
    /// Last-seen timestamp.
    pub last_seen: String,
}

/// Convert a resource row into a node.
pub(crate) fn row_to_node(row: ResourceRow) -> Result<ResourceNode, DomainError> {
    let ResourceRow {
        id,
        provider_id,
        kind,
        name,
        state,
        parent_id,
        metadata_json,
        last_seen,
    } = row;
    let corrupt = |what: &str| {
        DomainError::new(
            ErrorCode::STORE_TRANSACTION_FAILED,
            format!("corrupt {what} in resource row"),
        )
    };
    Ok(ResourceNode {
        id: ResourceId::parse(&id).map_err(|e| corrupt(&format!("id ({e})")))?,
        kind: parse_kind(&kind).ok_or_else(|| corrupt(&format!("kind {kind:?}")))?,
        provider_id: PluginId::parse(&provider_id)
            .map_err(|e| corrupt(&format!("provider_id ({e})")))?,
        name,
        state: ResourceState::from_wire(&state),
        parent_id: parent_id
            .as_deref()
            .map(ResourceId::parse)
            .transpose()
            .map_err(|e| corrupt(&format!("parent_id ({e})")))?,
        capabilities: Default::default(),
        metadata: serde_json::from_str(&metadata_json).unwrap_or(Json::Object(Default::default())),
        last_seen,
    })
}

fn parse_kind(s: &str) -> Option<sandtree_model::resource::ResourceKind> {
    use sandtree_model::resource::ResourceKind as K;
    Some(match s {
        "host" => K::Host,
        "sandbox" => K::Sandbox,
        "docker-runtime" => K::DockerRuntime,
        "container" => K::Container,
        "image" => K::Image,
        "volume" => K::Volume,
        "network" => K::Network,
        "compose-project" => K::ComposeProject,
        "compose-service" => K::ComposeService,
        "workspace" => K::Workspace,
        _ => return None,
    })
}

/// Wire name for a resource kind.
pub fn kind_wire(kind: sandtree_model::resource::ResourceKind) -> &'static str {
    kind.as_str()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sandtree_model::capability::Capability;
    use sandtree_model::resource::Correlation;
    use sandtree_model::resource::ResourceKind;
    use sandtree_observation_model::ContentHashState;

    #[test]
    fn operation_job_is_recorded_before_dispatch() {
        let s = Store::open_in_memory().unwrap();
        let id = OperationId::parse("op-1");
        let req = OperationRequest::new(
            ResourceId::derive(&["c"]),
            sandtree_model::operation::OperationKind::Start,
            Json::Null,
            Correlation::generate(),
        );
        s.insert_operation(&id, &req).unwrap();
        let job = s.operation(&id).unwrap().expect("job exists");
        assert_eq!(job.state, OperationState::Pending);
        s.transition_operation(
            &id,
            OperationState::Succeeded,
            None,
            &serde_json::json!({"started": true}),
        )
        .unwrap();
        let job = s.operation(&id).unwrap().unwrap();
        assert_eq!(job.state, OperationState::Succeeded);
        assert_eq!(job.result["started"], Json::Bool(true));
    }

    #[test]
    fn failed_operation_keeps_the_stable_code() {
        let s = Store::open_in_memory().unwrap();
        let id = OperationId::parse("op-2");
        let req = OperationRequest::new(
            ResourceId::derive(&["c"]),
            sandtree_model::operation::OperationKind::Destroy,
            Json::Null,
            Correlation::generate(),
        );
        s.insert_operation(&id, &req).unwrap();
        s.transition_operation(
            &id,
            OperationState::Failed,
            Some(ErrorCode::POLICY_DENIED),
            &Json::Null,
        )
        .unwrap();
        let job = s.operation(&id).unwrap().unwrap();
        assert_eq!(job.error_code, Some(ErrorCode::POLICY_DENIED));
    }

    #[test]
    fn snapshot_manifest_round_trips() {
        let s = Store::open_in_memory().unwrap();
        let res = ResourceId::derive(&["ws"]);
        s.upsert_resources(&[ResourceNode::new(
            res.clone(),
            ResourceKind::Workspace,
            PluginId::derive(&["vfs"]),
            "ws",
            ResourceState::Running,
            None,
            crate::now_rfc3339(),
        )])
        .unwrap();
        let man = SnapshotManifest {
            id: SnapshotId::derive(&["snap", "1"]),
            resource_id: res.clone(),
            created_at: crate::now_rfc3339(),
            manifest_hash: "a".repeat(64),
            entries: vec![
                FileMetadata {
                    path: "a.txt".into(),
                    is_dir: false,
                    size: 3,
                    mtime_ns: Some(1),
                    hash_state: ContentHashState::ContentCached,
                    content_hash: Some("b".repeat(64)),
                },
                FileMetadata {
                    path: "b.txt".into(),
                    is_dir: false,
                    size: 0,
                    mtime_ns: None,
                    hash_state: ContentHashState::MetadataKnown,
                    content_hash: None,
                },
            ],
        };
        s.insert_snapshot(&man).unwrap();
        let list = s.list_snapshots(&res).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].entries.len(), 2);
        assert_eq!(
            list[0].entries[0].path, "a.txt",
            "entries are ordered by uri"
        );
        assert_eq!(
            s.referenced_hashes().unwrap().len(),
            1,
            "only hashed entries feed the GC mark set"
        );
        s.delete_snapshot(&man.id).unwrap();
        assert!(s.list_snapshots(&res).unwrap().is_empty());
        assert!(s.referenced_hashes().unwrap().is_empty());
    }

    fn grant(plugin_id: &str, capability: &Capability) -> CapabilityGrant {
        CapabilityGrant {
            app_id: "app".into(),
            plugin_id: plugin_id.into(),
            capability: capability.clone(),
            resource_scope: String::new(),
            decision: "allow".into(),
        }
    }

    #[test]
    fn grants_are_stored_and_ordered() {
        let s = Store::open_in_memory().unwrap();
        let c1 = Capability::parse("vfs:read").unwrap();
        let c2 = Capability::parse("exec:spawn").unwrap();
        s.upsert_grant(&grant("sandtree.provider.docker", &c2))
            .unwrap();
        s.upsert_grant(&grant("sandtree.provider.docker", &c1))
            .unwrap();
        let rows = s.list_grants("app").unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].capability, "exec:spawn", "ordered by capability");
    }

    #[test]
    fn plugin_package_upsert_replaces_instead_of_conflicting() {
        let s = Store::open_in_memory().unwrap();
        let row = PluginPackageRow {
            plugin_id: "sandtree.provider.docker".into(),
            version: "1.0.0".into(),
            content_hash: "h1".into(),
            license_expr: "Apache-2.0".into(),
            enabled: true,
        };
        s.upsert_plugin_package(&row, "{}").unwrap();
        let mut row2 = row.clone();
        row2.content_hash = "h2".into();
        s.upsert_plugin_package(&row2, "{\"a\":1}").unwrap();
        let all = s.list_plugin_packages().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].content_hash, "h2");
    }

    #[test]
    fn docker_endpoint_rejects_embedded_credentials() {
        // NFR-S03 / DD-SECOPS §3: only references are stored.
        let s = Store::open_in_memory().unwrap();
        let bad = DockerEndpointRow {
            id: EndpointId::derive(&["x"]),
            uri: "tcp://admin:hunter2@10.0.0.1:2375".into(),
            api_version: None,
            engine_version: None,
            os: None,
            arch: None,
            health: "unknown".into(),
        };
        let err = s.upsert_docker_endpoint(&bad).unwrap_err();
        assert_eq!(err.code, ErrorCode::POLICY_DENIED);
    }

    #[test]
    fn a_tcp_port_is_not_mistaken_for_a_credential() {
        // NFR-S03, and the other half of the same rule. The previous check
        // rejected any authority containing ':', which cannot tell
        // `user:password@host` from `host:2376` -- so it refused every TCP
        // endpoint, and with them the entire remote-engine story (UAT-018). A
        // guard that blocks the legitimate case is not a guard.
        let s = Store::open_in_memory().unwrap();
        for (i, uri) in [
            "tcp://10.0.0.5:2375",
            "tcp://docker.internal:2376",
            "npipe:////./pipe/docker_engine",
            "unix:///var/run/docker.sock",
        ]
        .into_iter()
        .enumerate()
        {
            s.upsert_docker_endpoint(&DockerEndpointRow {
                id: EndpointId::derive(&["ok", &i.to_string()]),
                uri: uri.into(),
                api_version: None,
                engine_version: None,
                os: None,
                arch: None,
                health: "unknown".into(),
            })
            .unwrap_or_else(|e| panic!("{uri} carries no credential and must be storable: {e}"));
        }
        assert_eq!(s.list_docker_endpoints().unwrap().len(), 4);

        // A bare username is still userinfo, so it is still refused: an `@`
        // anywhere in the authority means the URI is carrying an identity.
        for uri in [
            "tcp://admin:hunter2@10.0.0.1:2375",
            "tcp://admin@10.0.0.1:2375",
            "https://user:pw@registry.example.com/v2",
        ] {
            let err = s
                .upsert_docker_endpoint(&DockerEndpointRow {
                    id: EndpointId::derive(&["bad", uri]),
                    uri: uri.into(),
                    api_version: None,
                    engine_version: None,
                    os: None,
                    arch: None,
                    health: "unknown".into(),
                })
                .unwrap_err();
            assert_eq!(err.code, ErrorCode::POLICY_DENIED, "{uri}");
            assert!(
                err.message.contains("NFR-S03"),
                "the refusal cites the rule it enforces, so an operator can act \
                 on it without reading the source: {err}"
            );
        }
    }

    #[test]
    fn docker_endpoint_round_trips() {
        let s = Store::open_in_memory().unwrap();
        let row = DockerEndpointRow {
            id: EndpointId::derive(&["npipe"]),
            uri: "npipe:////./pipe/docker_engine".into(),
            api_version: Some("1.47".into()),
            engine_version: Some("27.0.0".into()),
            os: Some("linux".into()),
            arch: Some("x86_64".into()),
            health: "healthy".into(),
        };
        s.upsert_docker_endpoint(&row).unwrap();
        let all = s.list_docker_endpoints().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].id, row.id);
        assert_eq!(all[0].api_version.as_deref(), Some("1.47"));
    }

    #[test]
    fn app_generations_are_immutable_and_single_active() {
        let s = Store::open_in_memory().unwrap();
        s.insert_app_generation("sandtree.desktop", 1, "h1", "{}")
            .unwrap();
        s.insert_app_generation("sandtree.desktop", 2, "h2", "{}")
            .unwrap();
        let gen: i64 = s
            .read(|c| Ok(c.query_row("SELECT count(*) FROM app_generation WHERE app_id='sandtree.desktop' AND state='active'", [], |r| r.get(0))?))
            .unwrap();
        assert_eq!(gen, 1, "only the newest generation stays active");
        let total: i64 = s
            .read(|c| {
                Ok(c.query_row(
                    "SELECT count(*) FROM app_generation WHERE app_id='sandtree.desktop'",
                    [],
                    |r| r.get(0),
                )?)
            })
            .unwrap();
        assert_eq!(total, 2, "older generations are retained, not deleted");
    }

    #[test]
    fn workspace_mount_round_trips() {
        let s = Store::open_in_memory().unwrap();
        let res = ResourceId::derive(&["c"]);
        s.upsert_resources(&[ResourceNode::new(
            res.clone(),
            ResourceKind::Container,
            PluginId::derive(&["docker"]),
            "c",
            ResourceState::Running,
            None,
            crate::now_rfc3339(),
        )])
        .unwrap();
        s.upsert_workspace_mount(&WorkspaceMountRow {
            id: "m1".into(),
            resource_id: res.clone(),
            source_uri: Some("C:\\src".into()),
            target_uri: "/app".into(),
            mode: "ro".into(),
        })
        .unwrap();
        let rows = s.list_workspace_mounts(&res).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].mode, "ro");
    }

    #[test]
    fn resource_row_conversion_rejects_corrupt_ids() {
        let e = row_to_node(ResourceRow {
            id: "not-an-id".into(),
            provider_id: "plg-00000000000000000000".into(),
            kind: "container".into(),
            name: "x".into(),
            state: "running".into(),
            parent_id: None,
            metadata_json: "{}".into(),
            last_seen: "t".into(),
        })
        .unwrap_err();
        assert_eq!(e.code, ErrorCode::STORE_TRANSACTION_FAILED);
    }

    #[test]
    fn events_are_appended_and_purged_by_age() {
        use sandtree_model::event::{EventRecord, EventType, Severity};
        let s = Store::open_in_memory().unwrap();
        let mut ev = EventRecord::new(
            EventType::ResourceAdded,
            Correlation::generate(),
            Json::Null,
        )
        .with_severity(Severity::Info);
        ev.ts = "2026-01-01T00:00:00Z".into();
        s.append_event(&ev).unwrap();
        ev.event_type = EventType::ResourceChanged;
        ev.ts = "2026-12-31T00:00:00Z".into();
        s.append_event(&ev).unwrap();
        assert_eq!(s.purge_events("2026-06-01T00:00:00Z").unwrap(), 1);
        let n: i64 = s
            .read(|c| Ok(c.query_row("SELECT count(*) FROM event_log", [], |r| r.get(0))?))
            .unwrap();
        assert_eq!(n, 1);
    }
}
