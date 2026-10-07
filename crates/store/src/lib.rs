//! SandTree core store: SQLite metadata, repositories, BLAKE3 CAS, migrations
//! and retention (DD-DATA §1–§3, §9–§10).

#![deny(missing_docs)]

pub mod cas;
pub mod db;
pub mod repo;
pub mod resources;

pub use cas::Cas;
pub use db::{Store, StoreConfig, SCHEMA_VERSION};
pub use repo::{
    CapabilityGrant, Change, DockerEndpointRow, GrantRow, OperationJobRecord, PluginInstanceRow,
    PluginPackageRow, ResourceRow, SnapshotManifest, WorkspaceMountRow,
};
pub use resources::decode_capabilities;

use chrono_free::now_rfc3339 as inner_now_rfc3339;

/// Current UTC time in RFC3339, the only timestamp form written to the store
/// (`schemas/observation_snapshot_v1.schema.json` uses `date-time`).
pub fn now_rfc3339() -> String {
    inner_now_rfc3339()
}

/// Minimal RFC3339 formatter, kept local so the store has no date-crate
/// dependency and the audit log and the store cannot disagree about "now".
mod chrono_free {
    /// Current time as `YYYY-MM-DDTHH:MM:SSZ`.
    pub fn now_rfc3339() -> String {
        let ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
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
}
