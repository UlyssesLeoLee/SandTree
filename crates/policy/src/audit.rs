//! Audit records (FR-064, DD-SECOPS §7).

use sandtree_model::error::ErrorCode;
use sandtree_model::id::ResourceId;
use sandtree_model::resource::Correlation;
use serde::Serialize;
use serde_json::Value as Json;

use crate::redact::Redactor;

/// One audit entry.
///
/// Parameters are stored already redacted. The audit log is written to disk and
/// exported in diagnostics bundles, so redaction must happen *before* the record
/// is constructed rather than when it is displayed.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AuditRecord {
    /// RFC3339 timestamp.
    pub ts: String,
    /// Actor: current OS user / session.
    pub actor: String,
    /// Action name, e.g. `container.remove`.
    pub action: String,
    /// Target resource, when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_id: Option<ResourceId>,
    /// Correlation id tying the record to the operation.
    pub correlation_id: Correlation,
    /// Redacted parameter summary.
    pub params: Json,
    /// Result summary, e.g. `succeeded` / `failed`.
    pub result: String,
    /// Stable error code on failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<ErrorCode>,
}

impl AuditRecord {
    /// Build a record, redacting `params` and any textual field.
    ///
    /// `result` is redacted too: provider error strings frequently embed the
    /// command line that produced them, and a command line can carry a password
    /// (`psql "postgres://user:pw@host/db"`).
    pub fn new(
        actor: impl Into<String>,
        action: impl Into<String>,
        resource_id: Option<ResourceId>,
        correlation_id: Correlation,
        params: &Json,
        result: impl Into<String>,
        error_code: Option<ErrorCode>,
    ) -> Self {
        let r = Redactor::new();
        let params = r
            .redact_value(params)
            .unwrap_or(Json::String("[REDACTED]".into()));
        let result = r.redact_text(&result.into());
        Self {
            ts: chrono_stub::now_rfc3339(),
            actor: actor.into(),
            action: action.into(),
            resource_id,
            correlation_id,
            params,
            result,
            error_code,
        }
    }

    /// Succeeded audit record.
    pub fn success(
        actor: impl Into<String>,
        action: impl Into<String>,
        resource_id: ResourceId,
        correlation_id: Correlation,
        params: &Json,
    ) -> Self {
        Self::new(
            actor,
            action,
            Some(resource_id),
            correlation_id,
            params,
            "succeeded",
            None,
        )
    }

    /// Failed audit record.
    pub fn failure(
        actor: impl Into<String>,
        action: impl Into<String>,
        resource_id: ResourceId,
        correlation_id: Correlation,
        params: &Json,
        error: ErrorCode,
    ) -> Self {
        Self::new(
            actor,
            action,
            Some(resource_id),
            correlation_id,
            params,
            "failed",
            Some(error),
        )
    }

    /// Whether this record describes a privileged action.
    pub fn is_privileged(&self) -> bool {
        matches!(
            self.action.split('.').next(),
            Some("container")
                | Some("sandbox")
                | Some("volume")
                | Some("network")
                | Some("plugin")
                | Some("workspace")
        )
    }
}

/// Tiny time helper so this crate does not need a chrono dependency.
mod chrono_stub {
    /// Current UTC time in RFC3339.
    pub fn now_rfc3339() -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        format_epoch_millis(now.as_millis() as i64)
    }

    /// Format epoch milliseconds as RFC3339 UTC without pulling in a date crate.
    ///
    /// Implemented with the civil-from-days algorithm so the audit trail has a
    /// real timestamp rather than a monotonic counter.
    pub fn format_epoch_millis(ms: i64) -> String {
        let secs = ms.div_euclid(1000);
        let millis = ms.rem_euclid(1000);
        let days = secs.div_euclid(86_400);
        let sod = secs.rem_euclid(86_400);
        let (y, m, d) = civil_from_days(days);
        format!(
            "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{millis:03}Z",
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

/// Milliseconds since the Unix epoch. Shared by the trust policy and audit log.
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_formats_as_rfc3339() {
        assert_eq!(
            chrono_stub::format_epoch_millis(0),
            "1970-01-01T00:00:00.000Z"
        );
        assert_eq!(
            chrono_stub::format_epoch_millis(1_700_000_000_123),
            "2023-11-14T22:13:20.123Z"
        );
    }

    #[test]
    fn success_record_is_redacted() {
        let rid = ResourceId::derive(&["c1"]);
        let rec = AuditRecord::success(
            "leo19",
            "container.remove",
            rid.clone(),
            Correlation::generate(),
            &serde_json::json!({ "force": true, "password": "hunter2" }),
        );
        let text = serde_json::to_string(&rec).unwrap();
        assert!(!text.contains("hunter2"), "{text}");
        assert!(text.contains("\"force\":true"));
        assert_eq!(rec.result, "succeeded");
        assert!(rec.error_code.is_none());
    }

    #[test]
    fn failure_record_carries_error_code() {
        let rid = ResourceId::derive(&["c1"]);
        let rec = AuditRecord::failure(
            "leo19",
            "volume.remove",
            rid,
            Correlation::generate(),
            &serde_json::json!({}),
            ErrorCode::POLICY_DENIED,
        );
        assert_eq!(rec.error_code, Some(ErrorCode::POLICY_DENIED));
        assert_eq!(rec.result, "failed");
        assert!(rec.is_privileged());
    }

    #[test]
    fn result_text_is_redacted_because_it_can_carry_a_command_line() {
        let rid = ResourceId::derive(&["c1"]);
        let rec = AuditRecord::new(
            "leo19",
            "container.exec",
            Some(rid),
            Correlation::generate(),
            &Json::Null,
            "psql postgres://app:hunter2@db:5432/x failed",
            Some(ErrorCode::CORE_INVALID),
        );
        assert!(!rec.result.contains("hunter2"), "{}", rec.result);
    }

    #[test]
    fn now_ms_is_plausible() {
        let ms = now_ms();
        assert!(ms > 1_700_000_000_000, "clock looks wrong: {ms}");
    }
}
