//! SandTree policy: capability decisions, secret redaction, audit records and
//! observation trust gates (FR-051, FR-064; NFR-S02, NFR-S03, NFR-O05).

#![deny(missing_docs)]

pub mod acquire;
pub mod audit;
pub mod engine;
pub mod redact;
pub mod trust;

pub use acquire::{
    AcquisitionChannel, AcquisitionDenied, AcquisitionPermit, AcquisitionPolicy,
    AcquisitionRequest, PenetrationVerdict, RefusalReason, NETWORK_TRUST_CEILING,
};
pub use audit::{now_ms, AuditRecord};
pub use engine::{Decision, GrantContext, PolicyEngine};
pub use redact::{RedactError, Redactor, REDACTED, SECRET_KEY_TOKENS};
pub use trust::TrustPolicy;

/// Test-only RFC3339 helper shared with the trust tests.
#[doc(hidden)]
pub fn now_rfc3339_for_tests() -> String {
    let ms = now_ms();
    let secs = (ms / 1000) as i64;
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
