//! SQLite metadata store (DD-DATA §1–§2, §9–§10; `schemas/001_init.sql`).
//!
//! Connection policy follows the design baseline: WAL, `foreign_keys=ON`,
//! `busy_timeout=5s`, **one** dedicated writer and up to four readers. SQLite
//! serialises writers anyway; pretending otherwise with a pool only moves the
//! contention into `SQLITE_BUSY` errors.
//!
//! Migrations are numbered one-way and recorded in both `PRAGMA user_version` and
//! a `schema_version` table, so a mismatch is detectable rather than guessed at.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use rusqlite::Connection;
use sandtree_model::error::{DomainError, ErrorCode};

/// Store configuration.
#[derive(Debug, Clone)]
pub struct StoreConfig {
    /// Database file path, or `:memory:`.
    pub path: PathBuf,
    /// Maximum concurrent reader connections.
    pub max_read_conns: usize,
    /// `busy_timeout` in milliseconds.
    pub busy_timeout_ms: u64,
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from(":memory:"),
            max_read_conns: 4,
            busy_timeout_ms: 5_000,
        }
    }
}

/// Current schema version. Bump together with a new migration file.
pub const SCHEMA_VERSION: i64 = 1;

/// The DDL shipped as `schemas/001_init.sql`.
pub const INIT_SQL: &str = include_str!("../../../schemas/001_init.sql");

/// SQLite-backed metadata store.
pub struct Store {
    writer: Arc<Mutex<Connection>>,
    readers: Arc<Vec<Mutex<Connection>>>,
    path: PathBuf,
}

impl Store {
    /// Open (and migrate) a store.
    pub fn open(cfg: StoreConfig) -> Result<Self, DomainError> {
        if cfg.path != *":memory:" {
            if let Some(dir) = cfg.path.parent() {
                std::fs::create_dir_all(dir).map_err(io_err)?;
            }
        }
        let writer = Connection::open(&cfg.path).map_err(db_err)?;
        Self::configure(&writer, cfg.busy_timeout_ms)?;
        let store = Self {
            writer: Arc::new(Mutex::new(writer)),
            readers: Arc::new(Vec::new()),
            path: cfg.path.clone(),
        };
        store.migrate()?;

        // Read connections are separate files; an in-memory database would give
        // each connection its own empty database, so readers are only created
        // for file-backed stores.
        if cfg.path != *":memory:" {
            let mut readers = Vec::with_capacity(cfg.max_read_conns.max(1));
            for _ in 0..cfg.max_read_conns.max(1) {
                let conn = Connection::open(&cfg.path).map_err(db_err)?;
                Self::configure(&conn, cfg.busy_timeout_ms)?;
                readers.push(Mutex::new(conn));
            }
            // Readers were created against the pre-migration file in the worst
            // case; re-running migrate-per-connection is unnecessary because
            // WAL readers observe committed schema.
            return Ok(Self {
                writer: store.writer,
                readers: Arc::new(readers),
                path: store.path,
            });
        }
        Ok(store)
    }

    /// In-memory store for tests.
    pub fn open_in_memory() -> Result<Self, DomainError> {
        Self::open(StoreConfig::default())
    }

    fn configure(conn: &Connection, busy_timeout_ms: u64) -> Result<(), DomainError> {
        let in_memory = conn.path().map(|p| p == ":memory:").unwrap_or(false);
        if !in_memory {
            conn.pragma_update(None, "journal_mode", "WAL")
                .map_err(db_err)?;
        }
        conn.pragma_update(None, "foreign_keys", "ON")
            .map_err(db_err)?;
        conn.busy_timeout(std::time::Duration::from_millis(busy_timeout_ms))
            .map_err(db_err)?;
        Ok(())
    }

    /// Database file path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Apply pending migrations inside a transaction.
    pub fn migrate(&self) -> Result<(), DomainError> {
        let mut conn = self.writer.lock().expect("writer lock");
        let current: i64 = conn
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .map_err(db_err)?;
        if current > SCHEMA_VERSION {
            return Err(DomainError::new(
                ErrorCode::STORE_TRANSACTION_FAILED,
                format!(
                    "database schema version {current} is newer than this binary supports ({SCHEMA_VERSION})"
                ),
            ));
        }
        if current == SCHEMA_VERSION {
            return Ok(());
        }
        let tx = conn.transaction().map_err(db_err)?;
        tx.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_version(
                version INTEGER NOT NULL,
                applied_at TEXT NOT NULL
            );",
        )
        .map_err(db_err)?;
        tx.execute_batch(INIT_SQL).map_err(db_err)?;
        tx.execute(
            "INSERT INTO schema_version(version, applied_at) VALUES (?1, ?2)",
            rusqlite::params![SCHEMA_VERSION, crate::now_rfc3339()],
        )
        .map_err(db_err)?;
        tx.pragma_update(None, "user_version", SCHEMA_VERSION)
            .map_err(db_err)?;
        tx.commit().map_err(db_err)?;
        Ok(())
    }

    /// Run `PRAGMA integrity_check`.
    pub fn integrity_check(&self) -> Result<bool, DomainError> {
        let conn = self.writer.lock().expect("writer lock");
        let result: String = conn
            .query_row("PRAGMA integrity_check", [], |r| r.get(0))
            .map_err(db_err)?;
        Ok(result.eq_ignore_ascii_case("ok"))
    }

    /// Mark jobs left running by a crashed daemon as interrupted (NFR-A03).
    pub fn mark_interrupted_operations(&self) -> Result<usize, DomainError> {
        let conn = self.writer.lock().expect("writer lock");
        let n = conn
            .execute(
                "UPDATE operation_job
                    SET state = 'interrupted', finished_at = ?1, error_code = ?2
                  WHERE state IN ('pending', 'running')",
                rusqlite::params![
                    crate::now_rfc3339(),
                    ErrorCode::STORE_TRANSACTION_FAILED.as_str()
                ],
            )
            .map_err(db_err)?;
        Ok(n)
    }

    /// Current schema version recorded in the file.
    pub fn schema_version(&self) -> Result<i64, DomainError> {
        let conn = self.writer.lock().expect("writer lock");
        conn.pragma_query_value(None, "user_version", |r| r.get(0))
            .map_err(db_err)
    }

    /// Run a closure with the single writer connection inside a transaction.
    pub fn write<T, F>(&self, f: F) -> Result<T, DomainError>
    where
        F: FnOnce(&rusqlite::Transaction) -> Result<T, DbFailure>,
    {
        let mut conn = self.writer.lock().expect("writer lock");
        let tx = conn.transaction().map_err(DbFailure::from)?;
        let out = f(&tx).map_err(DbFailure::into_domain)?;
        tx.commit().map_err(DbFailure::from)?;
        Ok(out)
    }

    /// Run a read-only closure on a reader connection.
    ///
    /// Falls back to the writer connection when no readers exist (in-memory
    /// store), because that is the only place the data lives.
    pub fn read<T, F>(&self, f: F) -> Result<T, DomainError>
    where
        F: FnOnce(&Connection) -> Result<T, DbFailure>,
    {
        if let Some(reader) = self.readers.first() {
            let guard = reader.lock().expect("reader lock");
            return f(&guard).map_err(DbFailure::into_domain);
        }
        let conn = self.writer.lock().expect("writer lock");
        f(&conn).map_err(DbFailure::into_domain)
    }
}

/// Internal error carrier so `?` works uniformly inside repository closures.
///
/// `DomainError` and `rusqlite::Error` are both foreign types here, so
/// `From<rusqlite::Error> for DomainError` cannot be implemented; this local
/// enum is the conversion seam.
#[derive(Debug)]
pub enum DbFailure {
    /// Raw SQLite failure.
    Sql(rusqlite::Error),
    /// A domain failure raised by repository logic.
    Domain(DomainError),
}

impl From<rusqlite::Error> for DbFailure {
    fn from(e: rusqlite::Error) -> Self {
        DbFailure::Sql(e)
    }
}

impl From<DomainError> for DbFailure {
    fn from(e: DomainError) -> Self {
        DbFailure::Domain(e)
    }
}

impl From<DbFailure> for DomainError {
    fn from(f: DbFailure) -> Self {
        f.into_domain()
    }
}

impl DbFailure {
    /// Convert to the public error type.
    pub fn into_domain(self) -> DomainError {
        match self {
            DbFailure::Sql(e) => db_err(e),
            DbFailure::Domain(e) => e,
        }
    }
}

fn db_err(e: rusqlite::Error) -> DomainError {
    DomainError::new(
        ErrorCode::STORE_TRANSACTION_FAILED,
        "sqlite transaction failed",
    )
    .with_detail(e.to_string())
}

fn io_err(e: std::io::Error) -> DomainError {
    DomainError::new(
        ErrorCode::STORE_TRANSACTION_FAILED,
        "cannot prepare database directory",
    )
    .with_detail(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_in_memory_applies_the_schema() {
        let s = Store::open_in_memory().unwrap();
        assert_eq!(s.schema_version().unwrap(), SCHEMA_VERSION);
        assert!(s.integrity_check().unwrap());
    }

    #[test]
    fn every_design_table_exists() {
        let s = Store::open_in_memory().unwrap();
        s.read(|c| {
            for table in [
                "resource",
                "resource_relation",
                "plugin_package",
                "plugin_instance",
                "app_generation",
                "plugin_grant",
                "docker_endpoint",
                "workspace_mount",
                "snapshot",
                "snapshot_entry",
                "event_log",
                "operation_job",
                "schema_version",
            ] {
                let found: i64 = c.query_row(
                    "SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?1",
                    [table],
                    |r| r.get(0),
                )?;
                assert_eq!(found, 1, "table {table} is missing from the DDL");
            }
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn design_indexes_exist() {
        let s = Store::open_in_memory().unwrap();
        s.read(|c| {
            for index in ["idx_resource_provider_kind", "idx_event_time_resource"] {
                let found: i64 = c.query_row(
                    "SELECT count(*) FROM sqlite_master WHERE type='index' AND name=?1",
                    [index],
                    |r| r.get(0),
                )?;
                assert_eq!(found, 1, "index {index} is missing");
            }
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn foreign_keys_are_enforced() {
        let s = Store::open_in_memory().unwrap();
        let err = s
            .write(|tx| {
                tx.execute(
                    "INSERT INTO resource_relation(from_id,to_id,kind) VALUES ('a','b','uses-image')",
                    [],
                )?;
                Ok(())
            })
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::STORE_TRANSACTION_FAILED);
    }

    #[test]
    fn interrupted_operations_are_recovered_on_startup() {
        // NFR-A03: a crashed daemon must not leave jobs silently pending.
        let s = Store::open_in_memory().unwrap();
        s.write(|tx| {
            tx.execute(
                "INSERT INTO operation_job(id, operation, state, requested_at, correlation_id)
                 VALUES ('j1','container.start','running','2026-10-07T00:00:00Z','cor-1')",
                [],
            )?;
            tx.execute(
                "INSERT INTO operation_job(id, operation, state, requested_at, correlation_id)
                 VALUES ('j2','container.stop','succeeded','2026-10-07T00:00:00Z','cor-2')",
                [],
            )?;
            Ok(())
        })
        .unwrap();
        assert_eq!(s.mark_interrupted_operations().unwrap(), 1);
        s.read(|c| {
            let state: String =
                c.query_row("SELECT state FROM operation_job WHERE id='j1'", [], |r| {
                    r.get(0)
                })?;
            assert_eq!(state, "interrupted");
            let state: String =
                c.query_row("SELECT state FROM operation_job WHERE id='j2'", [], |r| {
                    r.get(0)
                })?;
            assert_eq!(state, "succeeded", "terminal jobs are untouched");
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn transaction_rolls_back_on_error() {
        let s = Store::open_in_memory().unwrap();
        let err = s
            .write(|tx| {
                tx.execute(
                    "INSERT INTO resource(id,provider_id,kind,name,state,last_seen)
                     VALUES ('res-1','p','host','h','running','t')",
                    [],
                )?;
                // Force a failure after a successful statement.
                tx.execute("INSERT INTO nonexistent(x) VALUES (1)", [])?;
                Ok(())
            })
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::STORE_TRANSACTION_FAILED);
        s.read(|c| {
            let n: i64 = c.query_row("SELECT count(*) FROM resource", [], |r| r.get(0))?;
            assert_eq!(n, 0, "a failed transaction must leave nothing behind");
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn migrate_is_idempotent() {
        let s = Store::open_in_memory().unwrap();
        s.migrate().unwrap();
        s.migrate().unwrap();
        assert_eq!(s.schema_version().unwrap(), SCHEMA_VERSION);
    }

    #[test]
    fn a_newer_database_is_refused_rather_than_downgraded() {
        // DD-DATA §10: never silently migrate backwards.
        let s = Store::open_in_memory().unwrap();
        {
            let conn = s.writer.lock().unwrap();
            conn.pragma_update(None, "user_version", SCHEMA_VERSION + 1)
                .unwrap();
        }
        assert!(s.migrate().is_err());
    }

    #[test]
    fn file_backed_store_opens_readers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("sandtree.db");
        let s = Store::open(StoreConfig {
            path: path.clone(),
            max_read_conns: 2,
            busy_timeout_ms: 1_000,
        })
        .unwrap();
        assert!(path.exists(), "parent directories are created");
        assert_eq!(s.readers.len(), 2);
        // Data written through the writer is visible to a reader.
        s.write(|tx| {
            tx.execute(
                "INSERT INTO resource(id,provider_id,kind,name,state,last_seen)
                 VALUES ('res-1','p','host','h','running','t')",
                [],
            )?;
            Ok(())
        })
        .unwrap();
        let n = s
            .read(|c| Ok(c.query_row("SELECT count(*) FROM resource", [], |r| r.get::<_, i64>(0))?))
            .unwrap();
        assert_eq!(n, 1);
    }
}
