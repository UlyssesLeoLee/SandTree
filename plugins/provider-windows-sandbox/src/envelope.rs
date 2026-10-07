//! Probe envelope parsing and host-side validation
//! (`schemas/windows_probe_protocol_v1.md`; DD-PLG §12.4; NFR-S07, NFR-S08).
//!
//! A probe inside Windows Sandbox writes one JSON file per snapshot, named
//! `<uuid>.json`, produced atomically as `<uuid>.part` then renamed. The host
//! must validate **before** trusting any of it:
//!
//! | check | error code | why |
//! | --- | --- | --- |
//! | file name / size limits | `ST-OBS-007` | bound resource use |
//! | schema version | `ST-OBS-005` | the payload shape must be understood |
//! | nonce / session binding | `ST-OBS-005` | reject a stale or foreign outbox |
//! | monotonically increasing sequence | `ST-OBS-005` | reject replay |
//! | timestamp skew / max age | `ST-OBS-003` | reject a stale replay |
//! | BLAKE3 payload hash | `ST-OBS-005` | integrity of the bytes |
//! | JSON depth / array size | `ST-OBS-007` | bound parsing |
//! | traversal in paths | `ST-OBS-008` | a guest path is not a host path |
//!
//! # What validation does *not* do
//!
//! It never raises trust. A payload whose hash verifies is still
//! [`TrustLevel::GuestProbe`] (ADR-OBS-003): the guest produced the bytes, so a
//! valid hash proves only that they arrived intact, not that they are true.
//! [`validate_envelope`] therefore returns the envelope for the caller to label,
//! rather than returning a trust level it could inflate.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value as Json;

/// Envelope schema version this provider understands (DD-PLG §11).
pub const ENVELOPE_SCHEMA: &str = "sandtree.probe.v1";

/// One probe snapshot as written to the outbox.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProbeEnvelope {
    /// Schema tag; must equal [`ENVELOPE_SCHEMA`].
    pub schema: String,
    /// Sandbox this envelope belongs to.
    pub sandbox_id: String,
    /// Session nonce agreed during the bridge handshake.
    pub nonce: String,
    /// Per-session monotonic sequence number.
    pub sequence: u64,
    /// RFC3339 observation timestamp.
    pub observed_at: String,
    /// Domain payloads, keyed by wire name.
    pub domains: BTreeMap<String, Json>,
    /// BLAKE3 hash over the canonical `domains` encoding.
    pub payload_hash: String,
}

/// Why an envelope was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EnvelopeError {
    /// The file was not the JSON envelope shape.
    #[error("envelope is not valid JSON: {0}")]
    Malformed(String),
    /// The schema tag was not recognized.
    #[error("unsupported envelope schema {0:?}")]
    Schema(String),
    /// The nonce did not match the session's expected nonce.
    #[error("envelope nonce does not match the session")]
    NonceMismatch,
    /// The sequence did not advance past the session's high-water mark.
    #[error("envelope sequence {got} is not greater than the session sequence {expected}")]
    SequenceNotIncreasing {
        /// Sequence carried by the envelope.
        got: u64,
        /// Highest accepted sequence so far.
        expected: u64,
    },
    /// The payload exceeded the size cap.
    #[error("envelope payload is {actual} bytes, over the {limit} byte limit")]
    TooLarge {
        /// Observed size.
        actual: usize,
        /// The cap.
        limit: usize,
    },
    /// The BLAKE3 hash did not match.
    #[error("envelope payload hash does not match its domains")]
    HashMismatch,
    /// The timestamp was unparsable.
    #[error("envelope observed_at {0:?} is not RFC3339")]
    BadTimestamp(String),
    /// The timestamp was too far from `now`.
    #[error("envelope timestamp skew {skew_ms} ms exceeds the {limit_ms} ms allowance")]
    TimestampSkew {
        /// Signed skew, positive meaning the future.
        skew_ms: i64,
        /// The allowed window.
        limit_ms: i64,
    },
    /// A path in the payload escaped its root.
    #[error("envelope path {0:?} escapes its configured root")]
    PathEscape(String),
    /// The JSON exceeded the configured depth / breadth limits.
    #[error("envelope {what} exceeds the limit of {limit}")]
    StructureTooLarge {
        /// What was measured (`depth`, `collection`).
        what: &'static str,
        /// The cap.
        limit: usize,
    },
}

/// Bounds applied to an envelope before it is accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnvelopeLimits {
    /// Max serialized `domains` size in bytes.
    pub max_payload_bytes: usize,
    /// Max JSON nesting depth.
    pub max_depth: usize,
    /// Max entries in any array / object.
    pub max_collection: usize,
    /// Max string length in bytes.
    pub max_string: usize,
    /// Max absolute timestamp skew, in milliseconds.
    pub max_skew_ms: i64,
}

impl Default for EnvelopeLimits {
    /// DD-SW §12.3 budgets, with a freshness window matching DD-OBS §13.
    fn default() -> Self {
        Self {
            max_payload_bytes: 4 * 1024 * 1024,
            max_depth: 32,
            max_collection: 10_000,
            max_string: 64 * 1024,
            max_skew_ms: 60_000,
        }
    }
}

/// Session state a new envelope is validated against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionBinding {
    /// The nonce the probe agreed to at handshake time.
    pub expected_nonce: String,
    /// Highest sequence accepted so far for this session.
    pub last_sequence: Option<u64>,
}

/// The high-water mark after accepting an envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcceptedSequence(pub u64);

/// Parse an envelope from raw bytes without validating it.
///
/// Useful for reporting *why* a file was rejected; callers should follow with
/// [`validate_envelope`] before using anything.
pub fn parse_envelope(bytes: &[u8]) -> Result<ProbeEnvelope, EnvelopeError> {
    serde_json::from_slice(bytes).map_err(|e| EnvelopeError::Malformed(e.to_string()))
}

/// Validate an envelope against its session binding.
///
/// On success the caller receives the envelope and the new sequence high-water
/// mark. **Trust is unchanged by validation**: see the module docs.
pub fn validate_envelope(
    env: &ProbeEnvelope,
    session: &SessionBinding,
    now_ms: u64,
    limits: &EnvelopeLimits,
) -> Result<AcceptedSequence, EnvelopeError> {
    // 1. Schema.
    if env.schema != ENVELOPE_SCHEMA {
        return Err(EnvelopeError::Schema(env.schema.clone()));
    }

    // 2. Session binding. A file from another session, or a replayed outbox,
    //    is refused before anything in it is read.
    if env.nonce != session.expected_nonce {
        return Err(EnvelopeError::NonceMismatch);
    }

    // 3. Monotonic sequence — the anti-replay check.
    if let Some(last) = session.last_sequence {
        if env.sequence <= last {
            return Err(EnvelopeError::SequenceNotIncreasing {
                got: env.sequence,
                expected: last,
            });
        }
    }

    // 4. Timestamp sanity and skew.
    let observed_ms = parse_rfc3339_ms(&env.observed_at)
        .ok_or_else(|| EnvelopeError::BadTimestamp(env.observed_at.clone()))?;
    // `observed_ms` and `now_ms` are both epoch milliseconds (u64), so the skew
    // is computed as a signed difference: a guest clock ahead of ours must give a
    // positive skew, not wrap around at zero.
    let skew = observed_ms as i64 - now_ms as i64;
    if skew.abs() > limits.max_skew_ms {
        return Err(EnvelopeError::TimestampSkew {
            skew_ms: skew,
            limit_ms: limits.max_skew_ms,
        });
    }

    // 5. Size and structure budgets.
    let encoded = canonical_domains(&env.domains);
    if encoded.len() > limits.max_payload_bytes {
        return Err(EnvelopeError::TooLarge {
            actual: encoded.len(),
            limit: limits.max_payload_bytes,
        });
    }
    // Budget the payload as the domain values themselves rather than
    // re-encoding them, so the structure walk sees the guest-controlled shape.
    check_structure(
        &Json::Object(
            env.domains
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        ),
        limits,
        0,
    )?;

    // 6. Integrity of the payload bytes.
    let expected = blake3::hash(encoded.as_bytes()).to_hex().to_string();
    if expected != env.payload_hash {
        return Err(EnvelopeError::HashMismatch);
    }

    // 7. Guest-reported paths must not escape their root (NFR-S08).
    if let Some(bad) = find_escaping_path(&env.domains) {
        return Err(EnvelopeError::PathEscape(bad));
    }

    Ok(AcceptedSequence(env.sequence))
}

/// Canonical encoding of the `domains` map: sorted keys, compact form.
///
/// `serde_json::Map` preserves insertion order, so sorting here is what makes
/// the hash reproducible on both sides (CONTRACTS §6).
fn canonical_domains(domains: &BTreeMap<String, Json>) -> String {
    // `domains` is already a BTreeMap, so its iteration order is the sorted key
    // order on both sides; the explicit ordered vector just pins the encoded
    // shape so a future container swap cannot silently change the hash input.
    let ordered: Vec<(&String, &Json)> = domains.iter().collect();
    serde_json::to_string(&ordered).unwrap_or_default()
}

/// Enforce depth, breadth and string budgets.
fn check_structure(
    value: &Json,
    limits: &EnvelopeLimits,
    depth: usize,
) -> Result<(), EnvelopeError> {
    if depth > limits.max_depth {
        return Err(EnvelopeError::StructureTooLarge {
            what: "depth",
            limit: limits.max_depth,
        });
    }
    match value {
        Json::Array(items) => {
            if items.len() > limits.max_collection {
                return Err(EnvelopeError::StructureTooLarge {
                    what: "collection",
                    limit: limits.max_collection,
                });
            }
            for item in items {
                check_structure(item, limits, depth + 1)?;
            }
        }
        Json::Object(map) => {
            if map.len() > limits.max_collection {
                return Err(EnvelopeError::StructureTooLarge {
                    what: "collection",
                    limit: limits.max_collection,
                });
            }
            for v in map.values() {
                check_structure(v, limits, depth + 1)?;
            }
        }
        Json::String(s) if s.len() > limits.max_string => {
            return Err(EnvelopeError::StructureTooLarge {
                what: "string",
                limit: limits.max_string,
            })
        }
        _ => {}
    }
    Ok(())
}

/// Find a guest-reported path that escapes its root.
///
/// NFR-S08: a guest-reported path must never become a host path. Traversal,
/// home expansion, UNC and host-root absolute forms are refused outright rather
/// than resolved; see [`has_traversal`] for the exact rule and for why a
/// drive-qualified guest path is accepted.
fn find_escaping_path(domains: &BTreeMap<String, Json>) -> Option<String> {
    fn walk(v: &Json, out: &mut Option<String>) {
        if out.is_some() {
            return;
        }
        match v {
            Json::Array(items) => {
                for i in items {
                    walk(i, out);
                }
            }
            Json::Object(map) => {
                for (k, val) in map {
                    if is_path_key(k) {
                        if let Some(p) = val.as_str() {
                            if has_traversal(p) {
                                *out = Some(p.to_string());
                                return;
                            }
                        }
                    }
                    walk(val, out);
                }
            }
            _ => {}
        }
    }
    let mut found = None;
    for v in domains.values() {
        walk(v, &mut found);
        if found.is_some() {
            break;
        }
    }
    found
}

/// Whether a key names a filesystem path.
///
/// Matching on the whole key rather than exact equality keeps coverage for
/// composite names like `full_path` / `source_path`, which a guest is free to
/// use and which would otherwise bypass the traversal check entirely.
fn is_path_key(k: &str) -> bool {
    let l = k.to_ascii_lowercase();
    l == "path" || l == "source" || l.ends_with("path") || l.contains("_path")
}

/// Whether a guest path escapes its root.
///
/// NFR-S08. Refused outright, without trying to normalise and re-check:
///
/// * `..`      -- traversal out of the guest root
/// * `~`       -- home-directory expansion
/// * `\\host\`  -- UNC, i.e. a path that genuinely reaches outside the guest
/// * `/...`    -- host-root absolute
///
/// A **drive-qualified** path such as `C:\ws\src\main.rs` is deliberately
/// accepted. That is the guest's own view of a mapped volume, and the envelope
/// carries it as an observation string only: the host resolves guest paths to
/// host paths exclusively through the `.wsb` mapped-folder table, which enforces
/// that writable mappings land in the outbox and nowhere else. Refusing drive
/// letters here would reject every legitimate Windows Sandbox guest payload
/// while adding no protection the mapping layer does not already provide.
fn has_traversal(p: &str) -> bool {
    let unified = p.replace('\\', "/");
    if unified.starts_with("//") {
        return true; // UNC: \\server\share
    }
    if unified.starts_with('/') {
        return true; // host-root absolute
    }
    unified.split('/').any(|seg| seg == ".." || seg == "~")
}

/// Parse an RFC3339 timestamp to milliseconds since the Unix epoch.
fn parse_rfc3339_ms(raw: &str) -> Option<u64> {
    // Kept dependency-free and strict: the probe contract says RFC3339, and a
    // lenient parser here would accept timestamps the guest should not produce.
    chrono::DateTime::parse_from_rfc3339(raw)
        .ok()
        .map(|dt| dt.timestamp().max(0) as u64 * 1000 + dt.timestamp_subsec_millis() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn limits() -> EnvelopeLimits {
        EnvelopeLimits::default()
    }

    /// Build a correctly-hashed envelope for the given domains.
    fn envelope(
        nonce: &str,
        sequence: u64,
        observed_at: &str,
        domains: BTreeMap<String, Json>,
    ) -> ProbeEnvelope {
        let encoded = canonical_domains(&domains);
        ProbeEnvelope {
            schema: ENVELOPE_SCHEMA.to_string(),
            sandbox_id: "res-demo".to_string(),
            nonce: nonce.to_string(),
            sequence,
            observed_at: observed_at.to_string(),
            payload_hash: blake3::hash(encoded.as_bytes()).to_hex().to_string(),
            domains,
        }
    }

    fn system_domains() -> BTreeMap<String, Json> {
        [(
            "system".to_string(),
            json!({"os": "windows", "arch": "x86_64"}),
        )]
        .into_iter()
        .collect()
    }

    fn session(nonce: &str, last: Option<u64>) -> SessionBinding {
        SessionBinding {
            expected_nonce: nonce.to_string(),
            last_sequence: last,
        }
    }

    fn now_ms() -> u64 {
        // 2026-10-07T00:00:00Z
        1_768_000_000_000
    }

    /// RFC3339 timestamp `offset_secs` away from `now_ms()`, for skew tests.
    fn rfc3339_offset(offset_secs: i64) -> String {
        chrono::DateTime::<chrono::Utc>::from_timestamp(now_ms() as i64 / 1000 + offset_secs, 0)
            .unwrap()
            .to_rfc3339()
    }

    fn now_rfc3339() -> String {
        rfc3339_offset(0)
    }

    #[test]
    fn a_well_formed_envelope_is_accepted() {
        let env = envelope("n1", 1, &now_rfc3339(), system_domains());
        let got = validate_envelope(&env, &session("n1", None), now_ms(), &limits()).unwrap();
        assert_eq!(got, AcceptedSequence(1));
    }

    #[test]
    fn an_unknown_schema_is_refused() {
        let mut env = envelope("n1", 1, &now_rfc3339(), system_domains());
        env.schema = "sandtree.probe.v99".into();
        assert_eq!(
            validate_envelope(&env, &session("n1", None), now_ms(), &limits()),
            Err(EnvelopeError::Schema("sandtree.probe.v99".into()))
        );
    }

    #[test]
    fn a_foreign_nonce_is_refused() {
        // The anti-cross-session check: a file copied from another sandbox's
        // outbox must never be consumed.
        let env = envelope("other", 1, &now_rfc3339(), system_domains());
        assert_eq!(
            validate_envelope(&env, &session("n1", None), now_ms(), &limits()),
            Err(EnvelopeError::NonceMismatch)
        );
    }

    #[test]
    fn a_replayed_or_out_of_order_sequence_is_refused() {
        let env = envelope("n1", 5, &now_rfc3339(), system_domains());
        assert_eq!(
            validate_envelope(&env, &session("n1", Some(5)), now_ms(), &limits()),
            Err(EnvelopeError::SequenceNotIncreasing {
                got: 5,
                expected: 5
            })
        );
        let older = envelope("n1", 4, &now_rfc3339(), system_domains());
        assert!(matches!(
            validate_envelope(&older, &session("n1", Some(5)), now_ms(), &limits()),
            Err(EnvelopeError::SequenceNotIncreasing { .. })
        ));
        // A strictly greater sequence is accepted.
        let newer = envelope("n1", 6, &now_rfc3339(), system_domains());
        assert_eq!(
            validate_envelope(&newer, &session("n1", Some(5)), now_ms(), &limits()),
            Ok(AcceptedSequence(6))
        );
    }

    #[test]
    fn a_tampered_payload_fails_the_hash_check() {
        let mut env = envelope("n1", 1, &now_rfc3339(), system_domains());
        // Simulate a guest rewriting a claimed value after hashing.
        env.domains
            .insert("system".to_string(), json!({"os": "linux"}));
        assert_eq!(
            validate_envelope(&env, &session("n1", None), now_ms(), &limits()),
            Err(EnvelopeError::HashMismatch)
        );
    }

    #[test]
    fn a_mismatched_or_empty_hash_is_refused() {
        let mut env = envelope("n1", 1, &now_rfc3339(), system_domains());
        env.payload_hash = String::new();
        assert_eq!(
            validate_envelope(&env, &session("n1", None), now_ms(), &limits()),
            Err(EnvelopeError::HashMismatch)
        );
    }

    #[test]
    fn a_stale_or_future_timestamp_is_refused() {
        let old = envelope("n1", 1, &rfc3339_offset(-3600), system_domains());
        assert!(matches!(
            validate_envelope(&old, &session("n1", None), now_ms(), &limits()),
            Err(EnvelopeError::TimestampSkew { .. })
        ));

        let future = envelope("n1", 1, &rfc3339_offset(3600), system_domains());
        assert!(matches!(
            validate_envelope(&future, &session("n1", None), now_ms(), &limits()),
            Err(EnvelopeError::TimestampSkew { .. })
        ));
    }

    #[test]
    fn an_unparsable_timestamp_is_refused() {
        let env = envelope("n1", 1, "yesterday", system_domains());
        assert_eq!(
            validate_envelope(&env, &session("n1", None), now_ms(), &limits()),
            Err(EnvelopeError::BadTimestamp("yesterday".into()))
        );
    }

    #[test]
    fn an_oversized_payload_is_refused() {
        let big = "x".repeat(2048);
        let domains: BTreeMap<String, Json> = [("system".to_string(), json!({"blob": big}))]
            .into_iter()
            .collect();
        let env = envelope("n1", 1, &now_rfc3339(), domains);
        let tight = EnvelopeLimits {
            max_payload_bytes: 256,
            ..limits()
        };
        assert!(matches!(
            validate_envelope(&env, &session("n1", None), now_ms(), &tight),
            Err(EnvelopeError::TooLarge { limit: 256, .. })
        ));
    }

    #[test]
    fn excessive_nesting_is_refused() {
        // Build a deeply nested value.
        let mut deep = json!({"leaf": 1});
        for _ in 0..64 {
            deep = json!({ "n": deep });
        }
        let domains: BTreeMap<String, Json> = [("system".to_string(), deep)].into_iter().collect();
        let env = envelope("n1", 1, &now_rfc3339(), domains);
        let tight = EnvelopeLimits {
            max_depth: 8,
            ..limits()
        };
        assert_eq!(
            validate_envelope(&env, &session("n1", None), now_ms(), &tight),
            Err(EnvelopeError::StructureTooLarge {
                what: "depth",
                limit: 8
            })
        );
    }

    #[test]
    fn an_oversized_collection_is_refused() {
        let items: Vec<Json> = (0..50).map(|i| json!(i)).collect();
        let domains: BTreeMap<String, Json> = [("process".to_string(), json!(items))]
            .into_iter()
            .collect();
        let env = envelope("n1", 1, &now_rfc3339(), domains);
        let tight = EnvelopeLimits {
            max_collection: 10,
            ..limits()
        };
        assert!(matches!(
            validate_envelope(&env, &session("n1", None), now_ms(), &tight),
            Err(EnvelopeError::StructureTooLarge {
                what: "collection",
                ..
            })
        ));
    }

    #[test]
    fn a_guest_path_that_escapes_its_root_is_refused() {
        // NFR-S08: a guest-reported path must never become a host path.
        let domains: BTreeMap<String, Json> = [(
            "filesystem".to_string(),
            json!({"entries": [{"path": "C:\\ws\\..\\Windows"}]}),
        )]
        .into_iter()
        .collect();
        let env = envelope("n1", 1, &now_rfc3339(), domains);
        assert!(matches!(
            validate_envelope(&env, &session("n1", None), now_ms(), &limits()),
            Err(EnvelopeError::PathEscape(_))
        ));
    }

    #[test]
    fn an_ordinary_guest_path_is_accepted() {
        let domains: BTreeMap<String, Json> = [(
            "filesystem".to_string(),
            json!({"entries": [{"path": "C:\\ws\\src\\main.rs"}, {"path": "C:\\ws\\README.md"}]}),
        )]
        .into_iter()
        .collect();
        let env = envelope("n1", 1, &now_rfc3339(), domains);
        assert_eq!(
            validate_envelope(&env, &session("n1", None), now_ms(), &limits()),
            Ok(AcceptedSequence(1))
        );
    }

    #[test]
    fn unc_and_host_root_absolute_paths_are_refused() {
        // The traversal check must not be narrowed so far that a genuinely
        // host-reachable path slips through (NFR-S08).
        for hostile in [
            "\\\\build-host\\share\\payload.dll",
            "\\\\?\\C:\\Windows\\System32\\drivers",
            "/etc/shadow",
        ] {
            let domains: BTreeMap<String, Json> = [(
                "filesystem".to_string(),
                json!({"entries": [{"path": hostile}]}),
            )]
            .into_iter()
            .collect();
            let env = envelope("n1", 1, &now_rfc3339(), domains);
            assert!(
                matches!(
                    validate_envelope(&env, &session("n1", None), now_ms(), &limits()),
                    Err(EnvelopeError::PathEscape(_))
                ),
                "hostile path {hostile:?} was accepted"
            );
        }
    }

    #[test]
    fn a_home_expansion_path_is_refused() {
        let domains: BTreeMap<String, Json> = [(
            "filesystem".to_string(),
            json!({"entries": [{"path": "~/secret"}]}),
        )]
        .into_iter()
        .collect();
        let env = envelope("n1", 1, &now_rfc3339(), domains);
        assert!(matches!(
            validate_envelope(&env, &session("n1", None), now_ms(), &limits()),
            Err(EnvelopeError::PathEscape(_))
        ));
    }

    #[test]
    fn a_composite_path_key_is_still_checked() {
        // `full_path` is not literally "path"; a key match on equality alone would
        // let a guest route the same payload through an unchecked key.
        let domains: BTreeMap<String, Json> = [(
            "filesystem".to_string(),
            json!({"entries": [{"full_path": "C:\\ws\\..\\Windows"}]}),
        )]
        .into_iter()
        .collect();
        let env = envelope("n1", 1, &now_rfc3339(), domains);
        assert!(matches!(
            validate_envelope(&env, &session("n1", None), now_ms(), &limits()),
            Err(EnvelopeError::PathEscape(_))
        ));
    }

    #[test]
    fn canonical_domains_are_order_independent() {
        // The hash must not depend on the order keys happened to be inserted,
        // otherwise the probe and host would disagree on a valid payload.
        let a: BTreeMap<String, Json> = [
            ("system".to_string(), json!({"a": 1})),
            ("process".to_string(), json!({"b": 2})),
        ]
        .into_iter()
        .collect();
        let b: BTreeMap<String, Json> = [
            ("process".to_string(), json!({"b": 2})),
            ("system".to_string(), json!({"a": 1})),
        ]
        .into_iter()
        .collect();
        assert_eq!(canonical_domains(&a), canonical_domains(&b));
        // ...and both validate against the same hash.
        let ea = envelope("n1", 1, &now_rfc3339(), a);
        let eb = envelope("n1", 1, &now_rfc3339(), b);
        assert_eq!(ea.payload_hash, eb.payload_hash);
    }

    #[test]
    fn malformed_bytes_are_reported_not_panicked() {
        assert!(matches!(
            parse_envelope(b"not json"),
            Err(EnvelopeError::Malformed(_))
        ));
        // Valid JSON of the wrong shape.
        assert!(matches!(
            parse_envelope(b"{}"),
            Err(EnvelopeError::Malformed(_))
        ));
    }

    #[test]
    fn envelope_round_trips_through_json() {
        let env = envelope("n1", 1, &now_rfc3339(), system_domains());
        let bytes = serde_json::to_vec(&env).unwrap();
        assert_eq!(parse_envelope(&bytes).unwrap(), env);
    }

    #[test]
    fn validation_order_puts_binding_before_content() {
        // A file that is both foreign and malformed must be rejected as
        // foreign, so a probe cannot use error messages to probe the session.
        let mut env = envelope("other", 1, "not-a-date", system_domains());
        env.payload_hash = "wrong".into();
        assert_eq!(
            validate_envelope(&env, &session("n1", None), now_ms(), &limits()),
            Err(EnvelopeError::NonceMismatch)
        );
    }
}
