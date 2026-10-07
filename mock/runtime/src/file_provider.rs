//! [`ScriptedFileProvider`] — the [`FileProvider`] port over a scripted
//! in-memory filesystem.
//!
//! # What this port is really testing
//!
//! Two independent checks, because either one alone is bypassable (NFR-S05):
//!
//! 1. the caller normalizes the path before routing (the `WorkspaceUri` it
//!    hands us is already canonical);
//! 2. **this port canonicalizes again after resolution** — following symlinks
//!    is what turns a perfectly canonical `stfs://…/link` into a path outside
//!    the workspace, and that is only visible here.
//!
//! So the port does not trust the caller's normalisation: every entry point
//! re-derives the resolved location through
//! [`WorkspaceFs::resolve_confined`].
//!
//! # Content discipline
//!
//! [`FileProvider::list`] and [`FileProvider::stat`] return [`FileMetadata`],
//! which has no content field at all — FR-077 is therefore enforced by the type,
//! not by remembering to strip a field. Only [`FileProvider::read`] returns
//! bytes.
//!
//! [`FileProvider`]: sandtree_sdk::ports::FileProvider
//! [`WorkspaceFs::resolve_confined`]: crate::world::WorkspaceFs::resolve_confined

use std::sync::Arc;

use sandtree_model::error::DomainError;
use sandtree_model::id::ResourceId;
use sandtree_observation_model::FileMetadata;
use sandtree_sdk::ports::FileProvider;
use sandtree_vfs::{
    plan_read, ReadWindow, WorkspacePath, WorkspaceUri, DEFAULT_MAX_SINGLE_FILE,
    DEFAULT_MAX_TOTAL_BYTES,
};

use crate::fixture::FixtureError;
use crate::world::ScriptedWorld;

/// A [`FileProvider`] serving one world's scripted workspaces.
#[derive(Debug)]
pub struct ScriptedFileProvider {
    world: Arc<ScriptedWorld>,
}

impl ScriptedFileProvider {
    /// Serve an already-loaded world.
    pub fn new(world: Arc<ScriptedWorld>) -> Self {
        Self { world }
    }

    /// Load a fixture and serve it.
    pub fn from_fixture(fixture: crate::fixture::WorldFixture) -> Result<Self, FixtureError> {
        Ok(Self::new(Arc::new(ScriptedWorld::load(fixture)?)))
    }

    /// The world behind this port.
    pub fn world(&self) -> &Arc<ScriptedWorld> {
        &self.world
    }
}

#[async_trait::async_trait]
impl FileProvider for ScriptedFileProvider {
    // FR-077: one directory level, metadata only. The returned type carries no
    // content field, so no listing can leak a body even by accident.
    async fn list(&self, uri: &WorkspaceUri) -> Result<Vec<FileMetadata>, DomainError> {
        let fs = self.world.filesystem(uri.resource_id())?;
        let canonical = fs.resolve_confined(uri.path())?;
        let entry = fs.get(&canonical).ok_or_else(|| not_found(uri))?;
        if !entry.is_dir {
            return Err(DomainError::core_invalid(format!(
                "{} is not a directory",
                uri.to_uri_string()
            )));
        }
        Ok(fs
            .children(&canonical)
            .into_iter()
            .map(|e| e.metadata())
            .collect())
    }

    async fn stat(&self, uri: &WorkspaceUri) -> Result<FileMetadata, DomainError> {
        let fs = self.world.filesystem(uri.resource_id())?;
        let canonical = fs.resolve_confined(uri.path())?;
        let entry = fs.get(&canonical).ok_or_else(|| not_found(uri))?;
        Ok(entry.metadata())
    }

    // FR-014: reads are windowed. Planning goes through the same
    // `sandtree_vfs::plan_read` production uses, so the mock cannot accept a
    // window the real VFS would reject.
    async fn read(&self, uri: &WorkspaceUri, window: ReadWindow) -> Result<Vec<u8>, DomainError> {
        let fs = self.world.filesystem(uri.resource_id())?;
        let canonical = fs.resolve_confined(uri.path())?;
        let entry = fs.get(&canonical).ok_or_else(|| not_found(uri))?;
        if entry.is_dir {
            return Err(DomainError::core_invalid(format!(
                "{} is a directory, not a file",
                uri.to_uri_string()
            )));
        }
        let body = entry.body().ok_or_else(|| {
            DomainError::core_invalid(format!(
                "{} has metadata only; the fixture declares no content for it (FR-077 lazy content)",
                uri.to_uri_string()
            ))
        })?;

        let planned = plan_read(
            window.offset,
            Some(window.length),
            body.len() as u64,
            DEFAULT_MAX_SINGLE_FILE,
            DEFAULT_MAX_TOTAL_BYTES,
        )
        .map_err(|e| e.to_domain_error())?;

        let start = (planned.offset as usize).min(body.len());
        let end = (planned.end() as usize).min(body.len());
        Ok(body[start..end].to_vec())
    }

    // NFR-S05: the provider canonicalizes after the host normalized, and a
    // write is refused rather than redirected when the target is read-only —
    // an unmounted or read-only path is not a licence to mutate.
    async fn write(&self, uri: &WorkspaceUri, bytes: &[u8]) -> Result<(), DomainError> {
        let mut fs = self.world.filesystem_mut(uri.resource_id())?;
        let canonical = fs.resolve_confined(uri.path())?;

        if let Some(existing) = fs.get(&canonical) {
            if existing.is_dir {
                return Err(DomainError::core_invalid(format!(
                    "{} is a directory",
                    uri.to_uri_string()
                )));
            }
        } else if let Some(parent) = parent_of(&canonical) {
            match fs.get(parent) {
                Some(p) if p.is_dir => {}
                Some(_) => {
                    return Err(DomainError::core_invalid(format!(
                        "{parent:?} is not a directory"
                    )))
                }
                None => {
                    return Err(DomainError::not_found(format!(
                        "parent directory {parent:?} does not exist"
                    )))
                }
            }
        }

        if fs.read_only_at(&canonical) {
            return Err(DomainError::policy_denied(format!(
                "{} is read-only",
                uri.to_uri_string()
            )));
        }

        fs.install(canonical, bytes.to_vec());
        Ok(())
    }
}

fn parent_of(canonical: &str) -> Option<&str> {
    canonical.rsplit_once('/').map(|(p, _)| p)
}

fn not_found(uri: &WorkspaceUri) -> DomainError {
    DomainError::not_found(format!("no such path: {}", uri.to_uri_string()))
}

/// Build a canonical URI for a scripted workspace path. Test convenience.
///
/// The path is validated exactly as a production caller would validate it, so a
/// helper cannot smuggle in a traversal a real caller could not express.
pub fn workspace_uri(resource: &ResourceId, path: &str) -> Result<WorkspaceUri, DomainError> {
    let canonical = WorkspacePath::from_relative(path).map_err(|e| e.to_domain_error())?;
    Ok(WorkspaceUri::new(resource.clone(), canonical))
}
