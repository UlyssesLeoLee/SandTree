//! [`ScriptedExecProvider`] — the [`ExecProvider`] port over a scripted command
//! table.
//!
//! Rules match on the exact argv a fixture declares, optionally scoped to one
//! resource, and the first matching rule in declaration order wins. A command
//! with no rule is an error rather than an empty success: a fake that "succeeds"
//! anything it was not told about turns every assertion against it into a
//! statement about the fixture author's memory.
//!
//! Output is bounded at [`MAX_CAPTURE_BYTES`] per stream (DD-SW §12.3), which is
//! the same budget the observation plane uses, so a fixture cannot make the
//! fake look like a provider that streams without limit.
//!
//! [`ExecProvider`]: sandtree_sdk::ports::ExecProvider

use std::sync::Arc;

use sandtree_model::error::DomainError;
use sandtree_model::id::ResourceId;
use sandtree_sdk::ports::{ExecOutcome, ExecProvider};

use crate::fixture::{FixtureError, WorldFixture};
use crate::world::ScriptedWorld;

/// An [`ExecProvider`] answering from a scripted command table.
#[derive(Debug)]
pub struct ScriptedExecProvider {
    world: Arc<ScriptedWorld>,
}

impl ScriptedExecProvider {
    /// Serve an already-loaded world.
    pub fn new(world: Arc<ScriptedWorld>) -> Self {
        Self { world }
    }

    /// Load a fixture and serve it.
    pub fn from_fixture(fixture: WorldFixture) -> Result<Self, FixtureError> {
        Ok(Self::new(Arc::new(ScriptedWorld::load(fixture)?)))
    }

    /// The world behind this port.
    pub fn world(&self) -> &Arc<ScriptedWorld> {
        &self.world
    }

    /// Whether any scripted rule answers `argv` on `id`.
    ///
    /// Lets a caller check coverage before dispatching, instead of discovering
    /// a missing rule from the error message.
    pub fn has_rule(&self, id: &ResourceId, argv: &[String]) -> bool {
        self.world.exec_rules().iter().any(|r| r.matches(id, argv))
    }
}

#[async_trait::async_trait]
impl ExecProvider for ScriptedExecProvider {
    // FR-013, FR-025: the timeout is a budget the provider must be given. A
    // scripted command does not block, so the budget is validated rather than
    // waited on — and a zero budget is refused instead of reported as success.
    async fn exec(
        &self,
        id: &ResourceId,
        argv: &[String],
        timeout_ms: u64,
    ) -> Result<ExecOutcome, DomainError> {
        self.world.exec(id, argv, timeout_ms)
    }
}
