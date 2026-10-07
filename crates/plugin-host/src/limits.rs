//! Worker resource limits (FR-054 trap containment, FR-055 worker isolation,
//! NFR-P03 scale).
//!
//! The host owns a hard ceiling. Configuration may *tighten* a limit but never
//! loosen it, because a limit that a plugin package can raise by itself is not
//! a containment boundary at all. That asymmetry is the entire point of this
//! module, so it is enforced in one place and tested from both sides.

use sandtree_model::error::{DomainError, ErrorCode};

/// Resource ceiling for one plugin worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkerLimits {
    /// Wasmtime fuel budget for a single call. Exhaustion traps the guest
    /// instead of letting it spin (FR-054).
    pub fuel: u64,
    /// Maximum linear memory bytes for the guest.
    pub memory_bytes: usize,
    /// Wall-clock ceiling for a single call, enforced by the host (the guest
    /// cannot be trusted to honour it).
    pub wall_clock_ms: u64,
    /// Maximum concurrently in-flight calls for this worker.
    pub max_inflight: usize,
}

impl WorkerLimits {
    /// Host ceiling. Chosen so that 10 concurrent providers (NFR-P03) cannot
    /// each claim a machine's worth of memory.
    pub const fn host_ceiling() -> Self {
        Self {
            fuel: 50_000_000,
            memory_bytes: 256 * 1024 * 1024,
            wall_clock_ms: 30_000,
            max_inflight: 4,
        }
    }

    /// Whether every field of `self` is at or below `ceiling`.
    pub fn within(&self, ceiling: &Self) -> bool {
        self.fuel <= ceiling.fuel
            && self.memory_bytes <= ceiling.memory_bytes
            && self.wall_clock_ms <= ceiling.wall_clock_ms
            && self.max_inflight <= ceiling.max_inflight
    }

    /// The tighter of two limit sets, field by field.
    ///
    /// Used when merging a package's declared limits with the host ceiling, so
    /// "combine" can never produce a value looser than either input.
    pub fn tightened(&self, other: &Self) -> Self {
        Self {
            fuel: self.fuel.min(other.fuel),
            memory_bytes: self.memory_bytes.min(other.memory_bytes),
            wall_clock_ms: self.wall_clock_ms.min(other.wall_clock_ms),
            max_inflight: self.max_inflight.min(other.max_inflight),
        }
    }
}

impl Default for WorkerLimits {
    fn default() -> Self {
        Self::host_ceiling()
    }
}

fn denied(msg: impl Into<String>) -> DomainError {
    DomainError::new(ErrorCode::POLICY_DENIED, msg)
}

/// Check a configured limit set against the host ceiling.
///
/// A violation is `ST-POL-001` (policy denied), not a manifest error: the
/// request is well-formed, it is simply not permitted.
pub fn check_against_ceiling(
    requested: &WorkerLimits,
    ceiling: &WorkerLimits,
) -> Result<(), DomainError> {
    if !requested.within(ceiling) {
        return Err(denied(format!(
            "plugin worker limits exceed the host ceiling: requested \
             (fuel={}, memory={}B, wall={}ms, inflight={}) vs ceiling \
             (fuel={}, memory={}B, wall={}ms, inflight={})",
            requested.fuel,
            requested.memory_bytes,
            requested.wall_clock_ms,
            requested.max_inflight,
            ceiling.fuel,
            ceiling.memory_bytes,
            ceiling.wall_clock_ms,
            ceiling.max_inflight,
        )));
    }
    Ok(())
}

/// Resolve the effective limits for a worker.
///
/// Configuration wins where it is *stricter*; the ceiling wins everywhere
/// else. This never fails, and it is the only place effective limits are
/// computed.
pub fn resolve(configured: Option<WorkerLimits>, ceiling: WorkerLimits) -> WorkerLimits {
    match configured {
        Some(c) => c.tightened(&ceiling),
        None => ceiling,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_ceiling_is_accepted_by_itself() {
        assert!(check_against_ceiling(
            &WorkerLimits::host_ceiling(),
            &WorkerLimits::host_ceiling()
        )
        .is_ok());
    }

    #[test]
    fn any_loosened_field_is_refused() {
        let ceiling = WorkerLimits::host_ceiling();
        for field in 0..4 {
            let mut bad = WorkerLimits::host_ceiling();
            match field {
                0 => bad.fuel = ceiling.fuel + 1,
                1 => bad.memory_bytes = ceiling.memory_bytes + 1,
                2 => bad.wall_clock_ms = ceiling.wall_clock_ms + 1,
                _ => bad.max_inflight = ceiling.max_inflight + 1,
            };
            let err = check_against_ceiling(&bad, &ceiling).expect_err("loosening refused");
            assert_eq!(err.code, ErrorCode::POLICY_DENIED);
        }
    }

    #[test]
    fn tightening_a_limit_is_allowed() {
        let ceiling = WorkerLimits::host_ceiling();
        let mut strict = ceiling;
        strict.fuel = 1_000;
        strict.wall_clock_ms = 250;
        assert!(check_against_ceiling(&strict, &ceiling).is_ok());
        // And the effective value really is the strict one.
        assert_eq!(resolve(Some(strict), ceiling), strict);
    }

    #[test]
    fn resolve_can_never_produce_a_value_looser_than_the_ceiling() {
        // Even bypassing `check_against_ceiling`, `resolve` is safe: an
        // over-large configured value gets clamped instead of honoured.
        let ceiling = WorkerLimits::host_ceiling();
        let greedy = WorkerLimits {
            fuel: u64::MAX,
            memory_bytes: usize::MAX,
            wall_clock_ms: u64::MAX,
            max_inflight: usize::MAX,
        };
        let effective = resolve(Some(greedy), ceiling);
        assert_eq!(effective, ceiling);
    }

    #[test]
    fn resolve_takes_the_tighter_of_each_field_independently() {
        let ceiling = WorkerLimits::host_ceiling();
        let configured = WorkerLimits {
            fuel: 1_000,              // stricter
            memory_bytes: usize::MAX, // looser -> clamped
            wall_clock_ms: 5_000,     // stricter
            max_inflight: 1,          // stricter
        };
        let effective = resolve(Some(configured), ceiling);
        assert_eq!(effective.fuel, 1_000);
        assert_eq!(effective.memory_bytes, ceiling.memory_bytes);
        assert_eq!(effective.wall_clock_ms, 5_000);
        assert_eq!(effective.max_inflight, 1);
    }

    #[test]
    fn no_configuration_means_the_ceiling() {
        assert_eq!(
            resolve(None, WorkerLimits::host_ceiling()),
            WorkerLimits::host_ceiling()
        );
    }
}
