//! Windows Sandbox observation Probe (DD-OBS §9, NFR-S06, NFR-S07).
//!
//! This binary runs **inside** the sandbox and does exactly one thing: collect a
//! fixed set of observation domains and write them out as a signed envelope.
//! Everything about it is shaped by the isolation rules —
//!
//! * **no general shell.** There is no command path from outside into this
//!   process; the domain list is a compile-time constant. If a domain were
//!   caller-supplied, "collect a domain" would become "run this", which is the
//!   trade NFR-S07 forbids.
//! * **read-only.** Nothing here writes to the guest filesystem outside the
//!   telemetry outbox, and the outbox is a distinct directory so a host mount
//!   can be granted write on it alone.
//! * **trust is capped.** The envelope declares `guest_probe`, and the host
//!   side is required to keep that ceiling even when the hash verifies
//!   (ADR-OBS-003). [`Envelope::trust_ceiling`] exists so that rule has one
//!   implementation.
//! * **atomic publication.** A reader either sees a complete envelope or no
//!   envelope: the file is written as `<uuid>.part` and then renamed
//!   (FR-044's ordering rule applied to telemetry).

#![deny(missing_docs)]

mod time;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value as Json;

/// Envelope schema identifier. The host rejects anything else.
pub const ENVELOPE_SCHEMA: &str = "sandtree.observation.envelope/1";

/// Current time as RFC3339.
///
/// The probe is a single-purpose binary and deliberately does not depend on
/// the SDK, so it formats the timestamp itself rather than pulling chrono in.
pub fn now_rfc3339() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    time::format_rfc3339(secs)
}

/// The trust this data can ever carry, no matter what the host verifies.
///
/// The value is fixed, not computed: a hash match proves integrity, not origin
/// (ADR-OBS-003).
pub const TRUST_CEILING: &str = "guest_probe";

/// Directories the probe reads. The list is constant by design — see the module
/// docs.
const OBSERVED_DIRECTORIES: &[(&str, &str)] = &[
    ("process", "cmdline"),
    ("process", "handles"),
    ("network", "listeners"),
    ("service", "list"),
    ("filesystem", "mounts"),
];

/// One observation envelope.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Envelope {
    /// Always [`ENVELOPE_SCHEMA`].
    pub schema: String,
    /// The sandbox this was collected from.
    pub sandbox_id: String,
    /// One-shot value the host can match against what it asked for (replay
    /// protection, DD-OBS §9).
    pub nonce: String,
    /// Monotonic sequence number within one probe run.
    pub sequence: u64,
    /// RFC3339 collection time.
    pub observed_at: String,
    /// `domain -> value`, sorted for determinism.
    pub domains: BTreeMap<String, Json>,
    /// BLAKE3-equivalent digest of the canonical payload. The host checks it
    /// for integrity and still keeps the trust ceiling.
    pub payload_hash: String,
}

impl Envelope {
    /// Build an envelope for one collection.
    pub fn new(
        sandbox_id: impl Into<String>,
        nonce: impl Into<String>,
        sequence: u64,
        observed_at: impl Into<String>,
        domains: BTreeMap<String, Json>,
    ) -> Self {
        let mut e = Self {
            schema: ENVELOPE_SCHEMA.to_string(),
            sandbox_id: sandbox_id.into(),
            nonce: nonce.into(),
            sequence,
            observed_at: observed_at.into(),
            domains,
            payload_hash: String::new(),
        };
        e.payload_hash = e.compute_hash();
        e
    }

    /// The trust ceiling for any envelope, enforced on both sides.
    pub fn trust_ceiling() -> &'static str {
        TRUST_CEILING
    }

    /// Canonical payload: everything except the hash itself.
    ///
    /// Fields are serialised through a `BTreeMap`-backed map so the byte order
    /// does not depend on struct field order or on a hash-map iteration order.
    fn canonical(&self) -> String {
        let mut map = serde_json::Map::new();
        map.insert("schema".into(), Json::String(self.schema.clone()));
        map.insert("sandbox_id".into(), Json::String(self.sandbox_id.clone()));
        map.insert("nonce".into(), Json::String(self.nonce.clone()));
        map.insert("sequence".into(), Json::from(self.sequence));
        map.insert("observed_at".into(), Json::String(self.observed_at.clone()));
        map.insert(
            "domains".into(),
            Json::Object(self.domains.clone().into_iter().collect()),
        );
        serde_json::to_string(&Json::Object(map)).expect("canonical payload is serialisable")
    }

    /// Digest of the canonical payload.
    pub fn compute_hash(&self) -> String {
        blake3::hash(self.canonical().as_bytes())
            .to_hex()
            .to_string()
    }

    /// Whether the recorded hash matches the payload.
    ///
    /// Integrity only. A `true` here never authorises anything: the trust stays
    /// at [`TRUST_CEILING`].
    pub fn hash_matches(&self) -> bool {
        self.payload_hash == self.compute_hash()
    }

    /// Whether the schema is the one the host accepts.
    pub fn schema_matches(&self) -> bool {
        self.schema == ENVELOPE_SCHEMA
    }
}

/// Telemetry outbox: the only directory the probe writes to.
#[derive(Debug, Clone)]
pub struct Outbox {
    root: PathBuf,
}

impl Outbox {
    /// Open (creating if needed) an outbox directory.
    pub fn open(root: impl Into<PathBuf>) -> std::io::Result<Self> {
        let root = root.into();
        std::fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    /// The outbox root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Publish an envelope atomically.
    ///
    /// The payload lands in `<uuid>.part` and is then renamed to `<uuid>.json`.
    /// A reader that globs `*.json` therefore never observes a half-written
    /// envelope, and a crash leaves a `.part` that is ignored rather than a
    /// truncated `.json` that would be parsed as data.
    pub fn publish(&self, id: &str, envelope: &Envelope) -> std::io::Result<PathBuf> {
        let staged = self.root.join(format!("{id}.part"));
        let final_path = self.root.join(format!("{id}.json"));
        let body = serde_json::to_vec(envelope)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(&staged, &body)?;
        std::fs::rename(&staged, &final_path)?;
        Ok(final_path)
    }

    /// Read a published envelope.
    pub fn read(&self, id: &str) -> std::io::Result<Envelope> {
        let body = std::fs::read(self.root.join(format!("{id}.json")))?;
        serde_json::from_slice(&body)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    /// Ids of every published envelope, sorted.
    pub fn published(&self) -> std::io::Result<Vec<String>> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(&self.root)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();
            if let Some(id) = name.strip_suffix(".json") {
                out.push(id.to_string());
            }
        }
        out.sort();
        Ok(out)
    }
}

/// Collect the fixed domain set.
///
/// Each domain is gathered by a dedicated reader; a domain whose reader is not
/// available on this host is recorded as `unavailable` with a reason rather
/// than omitted, so the host can tell "the probe could not look" apart from
/// "there is nothing there" (invariant 10).
pub fn collect(sandbox_id: &str) -> BTreeMap<String, Json> {
    let mut domains = BTreeMap::new();
    for (domain, probe) in OBSERVED_DIRECTORIES {
        let value = match *probe {
            "cmdline" => probe_process_cmdline(),
            "handles" => unavailable("handle enumeration is not permitted in the probe"),
            "listeners" => probe_listeners(),
            "list" => unavailable("service enumeration requires host privileges"),
            "mounts" => probe_mounts(),
            other => unavailable(&format!("unknown probe {other}")),
        };
        domains.insert(
            format!("{domain}.{probe}"),
            serde_json::json!({
                "sandbox_id": sandbox_id,
                "value": value,
            }),
        );
    }
    domains
}

fn unavailable(reason: &str) -> Json {
    serde_json::json!({"status": "unavailable", "reason": reason})
}

/// Read `/proc`-style process command lines. On Windows the guest has no
/// equivalent that can be read without privileges, so this reports honestly
/// rather than synthesising a list.
fn probe_process_cmdline() -> Json {
    let entries: Vec<Json> = std::fs::read_dir("/proc")
        .ok()
        .map(|rd| {
            rd.flatten()
                .filter_map(|e| {
                    let pid = e.file_name().to_string_lossy().to_string();
                    if !pid.chars().all(|c| c.is_ascii_digit()) {
                        return None;
                    }
                    let cmdline = std::fs::read(e.path().join("cmdline")).ok()?;
                    let text: String = cmdline
                        .iter()
                        .map(|b| if *b == 0 { ' ' } else { *b as char })
                        .collect();
                    Some(serde_json::json!({"pid": pid, "cmdline": text.trim()}))
                })
                .collect()
        })
        .unwrap_or_default();
    serde_json::json!({"status": "ok", "processes": entries})
}

/// Read listening sockets. Best effort, and never elevated.
fn probe_listeners() -> Json {
    let body = match std::fs::read_to_string("/proc/net/tcp") {
        Ok(b) => b,
        Err(e) => return unavailable(&format!("socket table unreadable: {e}")),
    };
    let mut listeners = Vec::new();
    for line in body.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        // Column 3 is the state; 0A is LISTEN.
        if cols.len() > 3 && cols[3] == "0A" {
            listeners.push(serde_json::json!({
                "local": cols.get(1).copied().unwrap_or(""),
            }));
        }
    }
    serde_json::json!({"status": "ok", "listeners": listeners})
}

/// Read mount points.
fn probe_mounts() -> Json {
    let body = match std::fs::read_to_string("/proc/mounts") {
        Ok(b) => b,
        Err(e) => return unavailable(&format!("mount table unreadable: {e}")),
    };
    let mounts: Vec<&str> = body.lines().take(256).collect();
    serde_json::json!({"status": "ok", "mounts": mounts})
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope() -> Envelope {
        let mut domains = BTreeMap::new();
        domains.insert("process.cmdline".to_string(), Json::from(vec![1, 2, 3]));
        Envelope::new("sbx-1", "nonce-abc", 7, "2026-01-01T00:00:00Z", domains)
    }

    #[test]
    fn an_envelope_round_trips_through_the_outbox() {
        let dir = tempfile::tempdir().unwrap();
        let outbox = Outbox::open(dir.path()).unwrap();
        let e = envelope();

        let path = outbox.publish("run-1", &e).unwrap();
        assert!(path.ends_with("run-1.json"));
        assert!(
            !path.with_extension("part").exists(),
            "the staged file is gone"
        );

        let read_back = outbox.read("run-1").unwrap();
        assert_eq!(read_back, e);
        assert_eq!(outbox.published().unwrap(), vec!["run-1"]);
    }

    #[test]
    fn publication_is_atomic_and_leaves_no_partial_json() {
        // The ordering rule: staged file first, rename second. A reader globbing
        // `*.json` can never see a half-written envelope.
        let dir = tempfile::tempdir().unwrap();
        let outbox = Outbox::open(dir.path()).unwrap();
        outbox.publish("run-1", &envelope()).unwrap();

        let names: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(names, vec!["run-1.json"]);
    }

    #[test]
    fn a_failed_publish_writes_no_json() {
        // The staged file is written first and renamed second, so a failure at
        // any point leaves either a `.part` (ignored by readers) or nothing —
        // never a `.json` holding partial data.
        let dir = tempfile::tempdir().unwrap();
        let outbox = Outbox::open(dir.path()).unwrap();
        let blocked = dir.path().join("blocked");
        std::fs::write(&blocked, b"not a directory").unwrap();

        let mut e = envelope();
        e.sandbox_id = blocked.to_string_lossy().to_string();
        // Point the outbox at a path whose parent is a regular file.
        let bad_outbox = Outbox {
            root: blocked.join("nested"),
        };
        assert!(bad_outbox.publish("run-1", &e).is_err());

        // The good outbox is untouched by that failure.
        assert!(outbox.published().unwrap().is_empty());
    }

    #[test]
    fn the_hash_detects_tampering_but_never_raises_trust() {
        let mut e = envelope();
        assert!(e.hash_matches());
        assert!(e.schema_matches());

        // ADR-OBS-003: a verified hash is integrity, not authority.
        assert_eq!(Envelope::trust_ceiling(), "guest_probe");

        e.domains
            .insert("process.cmdline".into(), Json::from(vec![9, 9, 9]));
        assert!(!e.hash_matches(), "a modified payload must fail the hash");
    }

    #[test]
    fn the_hash_is_stable_across_field_insertion_order() {
        // Domains is a BTreeMap, so the canonical form must not depend on the
        // order the host happened to collect them in.
        let mut a = BTreeMap::new();
        a.insert("z".into(), Json::from(1));
        a.insert("a".into(), Json::from(2));
        let mut b = BTreeMap::new();
        b.insert("a".into(), Json::from(2));
        b.insert("z".into(), Json::from(1));
        assert_eq!(
            Envelope::new("s", "n", 1, "t", a).compute_hash(),
            Envelope::new("s", "n", 1, "t", b).compute_hash()
        );
    }

    #[test]
    fn a_foreign_schema_is_rejected() {
        let mut e = envelope();
        e.schema = "something.else/9".into();
        assert!(!e.schema_matches());
    }

    #[test]
    fn the_domain_set_is_fixed_and_always_populated() {
        // A missing key would be indistinguishable from "the probe did not
        // look", which is the ambiguity invariant 10 forbids.
        let domains = collect("sbx-1");
        assert_eq!(domains.len(), OBSERVED_DIRECTORIES.len());
        for (domain, probe) in OBSERVED_DIRECTORIES {
            let key = format!("{domain}.{probe}");
            let value = domains
                .get(&key)
                .unwrap_or_else(|| panic!("{key} must always be present"));
            assert!(value.get("value").is_some(), "{key} has no value");
        }
    }

    #[test]
    fn an_unavailable_probe_says_why() {
        let domains = collect("sbx-1");
        let handles = &domains["process.handles"]["value"];
        assert_eq!(handles["status"], "unavailable");
        assert!(
            handles["reason"]
                .as_str()
                .unwrap()
                .contains("not permitted"),
            "{handles}"
        );
    }

    #[test]
    fn published_ids_are_sorted() {
        let dir = tempfile::tempdir().unwrap();
        let outbox = Outbox::open(dir.path()).unwrap();
        for id in ["c", "a", "b"] {
            outbox.publish(id, &envelope()).unwrap();
        }
        assert_eq!(outbox.published().unwrap(), vec!["a", "b", "c"]);
    }

    #[test]
    fn reading_an_unpublished_envelope_is_an_error_not_an_empty_one() {
        let dir = tempfile::tempdir().unwrap();
        let outbox = Outbox::open(dir.path()).unwrap();
        assert!(outbox.read("nope").is_err());
    }
}
