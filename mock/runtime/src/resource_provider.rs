//! [`ScriptedResourceProvider`] — the [`ResourceProvider`] port over a world.
//!
//! Everything interesting lives in [`ScriptedWorld`]; this module is the thin
//! port that exposes it. Keeping the logic in the world is what lets the file
//! and exec ports enforce the *same* unavailability and not-found rules — a
//! fake whose three ports disagreed about what "unavailable" means would let a
//! test pass against one port and fail against another.
//!
//! [`ResourceProvider`]: sandtree_sdk::ports::ResourceProvider

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use sandtree_model::error::{DomainError, ErrorCode};
use sandtree_model::id::ResourceId;
use sandtree_model::operation::{OperationOutcome, OperationRequest};
use sandtree_model::resource::ResourceNode;
use sandtree_sdk::ports::{DiscoverBatch, ProviderDescriptor, ProviderHealth, ResourceProvider};

use crate::fixture::FixtureError;
use crate::world::ScriptedWorld;

/// A [`ResourceProvider`] whose every answer comes from a [`ScriptedWorld`].
///
/// FR-001, FR-023, FR-027, FR-051, FR-061, NFR-O04, NFR-P01, NFR-S02, NFR-U02.
#[derive(Debug)]
pub struct ScriptedResourceProvider {
    world: Arc<ScriptedWorld>,
    shutdown_calls: AtomicU64,
}

impl ScriptedResourceProvider {
    /// Serve an already-loaded world.
    pub fn new(world: Arc<ScriptedWorld>) -> Self {
        Self {
            world,
            shutdown_calls: AtomicU64::new(0),
        }
    }

    /// Load a fixture and serve it.
    pub fn from_fixture(fixture: crate::fixture::WorldFixture) -> Result<Self, FixtureError> {
        Ok(Self::new(Arc::new(ScriptedWorld::load(fixture)?)))
    }

    /// The world behind this port.
    pub fn world(&self) -> &Arc<ScriptedWorld> {
        &self.world
    }

    /// How many times [`ResourceProvider::shutdown`] has been called.
    ///
    /// Observable so a test can prove idempotence instead of assuming it.
    pub fn shutdown_count(&self) -> u64 {
        self.shutdown_calls.load(Ordering::Relaxed)
    }
}

// NFR-P01: the fake creates no job rows, so "the job row is written before
// dispatch" is the kernel's invariant to check, not this fake's. What the fake
// owes instead is the observable order of its own refusals, which is why the
// destructive-op check stays ahead of the resource lookup.
#[async_trait::async_trait]
impl ResourceProvider for ScriptedResourceProvider {
    fn descriptor(&self) -> ProviderDescriptor {
        self.world.descriptor()
    }

    // ADR-OBS-001: `health` reports the state instead of raising it. A provider
    // that answered "unavailable" with an error would make the health probe
    // indistinguishable from the failure it is describing.
    async fn health(&self) -> Result<ProviderHealth, DomainError> {
        Ok(self.world.health_state())
    }

    async fn discover(&self, cursor: Option<String>) -> Result<DiscoverBatch, DomainError> {
        self.world.page(cursor.as_deref())
    }

    // Fault mode 2: a resource the fixture never declared does not exist, and
    // says so with `ST-VFS-002` rather than a success-shaped placeholder.
    async fn inspect(&self, id: &ResourceId) -> Result<ResourceNode, DomainError> {
        self.world.ensure_available()?;
        self.world
            .node(id)
            .cloned()
            .ok_or_else(|| DomainError::not_found(format!("no such resource: {id}")))
    }

    async fn invoke(&self, req: &OperationRequest) -> Result<OperationOutcome, DomainError> {
        self.world.invoke(req)
    }

    // Idempotent by contract, and deliberately free of side effects: a scripted
    // world holds no external handle to release, and flipping a flag here that
    // changed what `discover` reports would break the determinism invariant.
    async fn shutdown(&self) {
        self.shutdown_calls.fetch_add(1, Ordering::Relaxed);
    }
}

/// The code a fake reports when a caller asks for a resource it never declared.
///
/// Exposed so tests can assert on the refusal instead of on a message string
/// (DD-SW §10: UI logic must never match on provider text).
pub const NOT_FOUND_CODE: ErrorCode = ErrorCode::VFS_NOT_FOUND;
