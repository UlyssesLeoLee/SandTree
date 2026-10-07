//! Payload normalization and bounded parsing (DD-OBS §14, NFR-S08).
//!
//! Guest and probe payloads are attacker-controlled input. Every collection that
//! crosses the observation boundary is therefore clamped before it reaches the
//! store, the cache or the UI:
//!
//! * JSON nesting depth, so a deeply nested document cannot exhaust the stack;
//! * collection length, so an array of a million entries cannot exhaust memory;
//! * string length, so a single 100 MB "path" cannot either;
//! * per-domain byte budget, so one noisy collector cannot starve the others.

use sandtree_model::error::{DomainError, ErrorCode};
use sandtree_observation_model::{ObservationDomain, ObservationHealth, ObservedValue};
use serde_json::Value as Json;
use std::collections::BTreeMap;

/// Default per-domain payload cap (4 MiB) — DD-SW §12.3.
pub const DEFAULT_MAX_DOMAIN_BYTES: usize = 4 * 1024 * 1024;
/// Default JSON nesting depth cap.
pub const DEFAULT_MAX_JSON_DEPTH: usize = 32;
/// Default maximum entries per array/object.
pub const DEFAULT_MAX_COLLECTION_LEN: usize = 10_000;
/// Default maximum string length.
pub const DEFAULT_MAX_STRING_LEN: usize = 64 * 1024;

/// Hard limits applied to observation payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObservationLimits {
    /// Maximum serialized bytes for one domain.
    pub max_domain_bytes: usize,
    /// Maximum JSON nesting depth.
    pub max_json_depth: usize,
    /// Maximum entries per array or object.
    pub max_collection_len: usize,
    /// Maximum characters in a single string.
    pub max_string_len: usize,
}

impl Default for ObservationLimits {
    fn default() -> Self {
        Self {
            max_domain_bytes: DEFAULT_MAX_DOMAIN_BYTES,
            max_json_depth: DEFAULT_MAX_JSON_DEPTH,
            max_collection_len: DEFAULT_MAX_COLLECTION_LEN,
            max_string_len: DEFAULT_MAX_STRING_LEN,
        }
    }
}

impl ObservationLimits {
    /// Strict limits for untrusted guest input.
    pub fn strict() -> Self {
        Self {
            max_domain_bytes: 512 * 1024,
            max_json_depth: 8,
            max_collection_len: 512,
            max_string_len: 4 * 1024,
        }
    }

    /// Return the stricter of this limit set and `other` field by field.
    ///
    /// A deployment-wide limit must be able to tighten a per-domain one without
    /// ever being able to loosen it.
    pub fn tightened_by(self, other: ObservationLimits) -> ObservationLimits {
        ObservationLimits {
            max_domain_bytes: self.max_domain_bytes.min(other.max_domain_bytes),
            max_json_depth: self.max_json_depth.min(other.max_json_depth),
            max_collection_len: self.max_collection_len.min(other.max_collection_len),
            max_string_len: self.max_string_len.min(other.max_string_len),
        }
    }

    /// Limits implied by a deadline-bearing request.
    pub fn for_domain(domain: ObservationDomain) -> Self {
        let base = Self::default();
        match domain {
            // Process lists are the classic unbounded collection.
            ObservationDomain::Process => Self {
                max_collection_len: 2_000,
                max_string_len: 512,
                ..base
            },
            ObservationDomain::Filesystem => Self {
                max_collection_len: 50_000,
                ..base
            },
            _ => base,
        }
    }
}

/// Clamp a JSON payload to the limits.
///
/// Returns `ST-OBS-007` when a single domain exceeds its byte budget, and
/// truncates in place for the bounded structural limits.
pub fn clamp_json(value: &Json, limits: &ObservationLimits) -> Result<Json, DomainError> {
    let clamped = clamp_value(value, 0, limits, &mut 0usize)?;
    let size = clamped.to_string().len();
    if size > limits.max_domain_bytes {
        return Err(DomainError::new(
            ErrorCode::OBS_OUTPUT_TOO_LARGE,
            format!(
                "observation payload is {size} bytes, exceeding the {} byte limit",
                limits.max_domain_bytes
            ),
        ));
    }
    Ok(clamped)
}

fn clamp_value(
    value: &Json,
    depth: usize,
    limits: &ObservationLimits,
    budget: &mut usize,
) -> Result<Json, DomainError> {
    if depth > limits.max_json_depth {
        return Err(DomainError::new(
            ErrorCode::OBS_ENVELOPE_INVALID,
            format!(
                "payload nesting depth exceeds {} (NFR-S08)",
                limits.max_json_depth
            ),
        ));
    }
    *budget = budget.saturating_add(1);
    Ok(match value {
        Json::String(s) => {
            if s.chars().count() > limits.max_string_len {
                let truncated: String = s.chars().take(limits.max_string_len).collect();
                Json::String(truncated)
            } else {
                value.clone()
            }
        }
        Json::Array(items) => {
            let mut out = Vec::with_capacity(items.len().min(limits.max_collection_len));
            for item in items.iter().take(limits.max_collection_len) {
                out.push(clamp_value(item, depth + 1, limits, budget)?);
            }
            Json::Array(out)
        }
        Json::Object(map) => {
            let mut out = serde_json::Map::with_capacity(map.len().min(limits.max_collection_len));
            for (k, v) in map.iter().take(limits.max_collection_len) {
                out.insert(k.clone(), clamp_value(v, depth + 1, limits, budget)?);
            }
            Json::Object(out)
        }
        other => other.clone(),
    })
}

/// Derive snapshot health from the domains that actually arrived.
///
/// Health is computed from *coverage*, not from the mode: a Native snapshot that
/// only answered two of six requested domains is degraded, while a Metadata
/// snapshot that answered every domain it was asked for is healthy.
pub fn domain_health(
    values: &BTreeMap<String, ObservedValue>,
    requested: &[ObservationDomain],
) -> ObservationHealth {
    if requested.is_empty() {
        return if values.is_empty() {
            ObservationHealth::Unavailable
        } else {
            ObservationHealth::Healthy
        };
    }
    let present = requested
        .iter()
        .filter(|d| values.contains_key(d.as_str()))
        .count();
    if present == requested.len() && !values.values().any(ObservedValue::is_partial) {
        ObservationHealth::Healthy
    } else if present == 0 {
        ObservationHealth::Unavailable
    } else {
        ObservationHealth::Degraded
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn plain_payload_passes_through() {
        let v = json!({"os": "windows", "cores": 8});
        let out = clamp_json(&v, &ObservationLimits::default()).unwrap();
        assert_eq!(out, v);
    }

    #[test]
    fn oversized_string_is_truncated() {
        let v = json!({"path": "x".repeat(10_000)});
        let out = clamp_json(&v, &ObservationLimits::strict()).unwrap();
        assert_eq!(out["path"].as_str().unwrap().chars().count(), 4096);
    }

    #[test]
    fn oversized_collection_is_truncated() {
        let items: Vec<u32> = (0..10_000).collect();
        let v = json!({ "procs": items });
        let out = clamp_json(&v, &ObservationLimits::strict()).unwrap();
        assert_eq!(out["procs"].as_array().unwrap().len(), 512);
    }

    #[test]
    fn deep_nesting_is_rejected_not_truncated() {
        // Truncating depth silently would produce a payload that parses but
        // means something else, so depth overflow is an error.
        let mut v = json!("leaf");
        for _ in 0..32 {
            v = json!({ "n": v });
        }
        let err = clamp_json(&v, &ObservationLimits::strict()).unwrap_err();
        assert_eq!(err.code, ErrorCode::OBS_ENVELOPE_INVALID);
    }

    #[test]
    fn oversized_domain_is_a_typed_error() {
        // The byte budget is checked *after* structural clamping, so the
        // payload has to exceed the cap without having been truncated first.
        let v = json!({"blob": "x".repeat(2_000_000)});
        let err = clamp_json(
            &v,
            &ObservationLimits {
                max_domain_bytes: 64 * 1024,
                max_string_len: 4 * 1024 * 1024,
                ..ObservationLimits::default()
            },
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::OBS_OUTPUT_TOO_LARGE);
        assert!(!err.is_retryable(), "retrying the same payload cannot help");
    }

    #[test]
    fn health_reflects_coverage_not_mode() {
        let mut values = BTreeMap::new();
        let requested = vec![ObservationDomain::System, ObservationDomain::Process];
        assert_eq!(
            domain_health(&values, &requested),
            ObservationHealth::Unavailable
        );

        values.insert(
            "system".to_string(),
            ObservedValue::new(Json::Null, provenance()),
        );
        assert_eq!(
            domain_health(&values, &requested),
            ObservationHealth::Degraded
        );

        values.insert(
            "process".to_string(),
            ObservedValue::new(Json::Null, provenance()),
        );
        assert_eq!(
            domain_health(&values, &requested),
            ObservationHealth::Healthy
        );
    }

    #[test]
    fn partial_values_make_a_fully_covered_snapshot_degraded() {
        let mut values = BTreeMap::new();
        for d in ["system", "process"] {
            values.insert(
                d.to_string(),
                ObservedValue::new(Json::Null, provenance().partial(true)),
            );
        }
        assert_eq!(
            domain_health(
                &values,
                &[ObservationDomain::System, ObservationDomain::Process]
            ),
            ObservationHealth::Degraded
        );
    }

    #[test]
    fn per_domain_limits_differ_for_process_lists() {
        assert!(
            ObservationLimits::for_domain(ObservationDomain::Process).max_collection_len
                < ObservationLimits::for_domain(ObservationDomain::System).max_collection_len
        );
    }

    fn provenance() -> sandtree_observation_model::Provenance {
        sandtree_observation_model::Provenance::new(
            "test",
            sandtree_observation_model::TrustLevel::ProviderNative,
            "2026-10-07T00:00:00Z",
        )
    }
}
