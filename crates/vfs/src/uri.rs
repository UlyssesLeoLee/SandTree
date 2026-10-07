//! Canonical `stfs://` URI (`schemas/workspace_uri_v1.md`, DD-DATA §4).
//!
//! Canonical form: `stfs://<resource-id>/<absolute-within-root-path>`.
//!
//! Parsing order matters and is part of the contract: percent-decoding happens
//! **before** normalization, so `%2e%2e` becomes `..` and is then rejected. A
//! parser that normalized first would accept `a/%2e%2e/b` and then either fail
//! late or produce a path the caller never intended.

use sandtree_model::id::ResourceId;
use serde::{Deserialize, Serialize};

use crate::error::UriError;
use crate::path::WorkspacePath;

/// URI scheme prefix.
pub const SCHEME: &str = "stfs://";

/// A canonical workspace URI.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct WorkspaceUri {
    resource_id: ResourceId,
    path: WorkspacePath,
}

impl WorkspaceUri {
    /// The workspace root of a resource.
    pub fn root(resource_id: ResourceId) -> Self {
        Self {
            resource_id,
            path: WorkspacePath::root(),
        }
    }

    /// Build from an already-validated path.
    pub fn new(resource_id: ResourceId, path: WorkspacePath) -> Self {
        Self { resource_id, path }
    }

    /// Parse a canonical URI.
    ///
    /// `stfs://res-<hex>` is the root. Everything after the resource-id segment
    /// is the relative path.
    pub fn parse(raw: &str) -> Result<Self, UriError> {
        let Some(body) = raw.strip_prefix(SCHEME) else {
            if raw.contains("://") {
                let scheme = raw.split("://").next().unwrap_or("");
                return Err(UriError::UnknownScheme(scheme.to_string()));
            }
            return Err(UriError::MissingScheme);
        };

        // Split resource-id from path on the first '/'. The resource id is a
        // fixed-width token, so this is unambiguous.
        let (id_raw, path_raw) = match body.find('/') {
            Some(idx) => (&body[..idx], &body[idx + 1..]),
            None => (body, ""),
        };

        let resource_id = ResourceId::parse(id_raw)
            .map_err(|_| UriError::InvalidResourceId(id_raw.to_string()))?;

        // Decode first, normalize second — see module docs.
        let decoded = percent_decode(path_raw)?;
        let path = WorkspacePath::from_relative(&decoded)?;

        Ok(Self { resource_id, path })
    }

    /// Target resource.
    pub fn resource_id(&self) -> &ResourceId {
        &self.resource_id
    }

    /// Normalized path within the resource.
    pub fn path(&self) -> &WorkspacePath {
        &self.path
    }

    /// Append a single child name.
    pub fn child(&self, name: &str) -> Result<Self, UriError> {
        Ok(Self {
            resource_id: self.resource_id.clone(),
            path: self.path.join(name)?,
        })
    }

    /// Canonical textual form, ready to persist in the index or a snapshot.
    pub fn to_uri_string(&self) -> String {
        let mut out = String::with_capacity(SCHEME.len() + 32);
        out.push_str(SCHEME);
        out.push_str(self.resource_id.as_str());
        let p = self.path.as_str();
        if !p.is_empty() {
            out.push('/');
            out.push_str(&percent_encode_path(p));
        }
        out
    }

    /// Diagnostics-safe rendering: the resource id is truncated.
    ///
    /// Used in error messages and logs so a full topology identifier is not
    /// splattered through the daemon log (DD-SECOPS §9).
    pub fn redacted(&self) -> String {
        let id = self.resource_id.as_str();
        let head: String = id.chars().take(10).collect();
        format!("{}{}…/{}", SCHEME, head, self.path.as_str())
    }
}

impl std::fmt::Display for WorkspaceUri {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_uri_string())
    }
}

impl Serialize for WorkspaceUri {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_uri_string())
    }
}

impl<'de> Deserialize<'de> for WorkspaceUri {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        WorkspaceUri::parse(&raw).map_err(serde::de::Error::custom)
    }
}

/// Strict percent-decoding.
///
/// Rejects `%zz`, a truncated `%A`, and any decoded NUL. Malformed input is an
/// error rather than a literal, so downstream normalization always sees the
/// real bytes.
pub fn percent_decode(raw: &str) -> Result<String, UriError> {
    if !raw.contains('%') {
        return Ok(raw.to_string());
    }
    let bytes = raw.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err(UriError::BadPercentEncoding(raw.to_string()));
            }
            let hi = hex_val(bytes[i + 1])
                .ok_or_else(|| UriError::BadPercentEncoding(raw.to_string()))?;
            let lo = hex_val(bytes[i + 2])
                .ok_or_else(|| UriError::BadPercentEncoding(raw.to_string()))?;
            let decoded = (hi << 4) | lo;
            if decoded == 0 {
                return Err(UriError::IllegalCharacter("\\u{0}".into()));
            }
            out.push(decoded);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out)
        .map_err(|_| UriError::IllegalCharacter("non-UTF-8 percent escape".into()))
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Percent-encode only what would break the canonical grammar.
fn percent_encode_path(p: &str) -> String {
    let mut out = String::with_capacity(p.len());
    for b in p.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' => {
                out.push(b as char)
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rid() -> ResourceId {
        ResourceId::derive(&["host", "workspace"])
    }

    /// Fixed-width resource id used by the literal-URI tests.
    const ID: &str = "res-0123456789abcdef0123456789";

    #[test]
    fn root_uri_round_trips() {
        let u = WorkspaceUri::root(rid());
        let s = u.to_uri_string();
        assert!(s.starts_with("stfs://res-"));
        assert_eq!(WorkspaceUri::parse(&s).unwrap(), u);
    }

    #[test]
    fn nested_uri_round_trips() {
        let u = WorkspaceUri::root(rid())
            .child("src")
            .unwrap()
            .child("main.rs")
            .unwrap();
        let s = u.to_uri_string();
        assert!(s.ends_with("/src/main.rs"), "{s}");
        assert_eq!(WorkspaceUri::parse(&s).unwrap(), u);
    }

    #[test]
    fn idempotent_parse_of_canonical_form() {
        let u = WorkspaceUri::parse(&format!("stfs://{ID}/a/b.txt")).unwrap();
        let once = u.to_uri_string();
        let twice = WorkspaceUri::parse(&once).unwrap().to_uri_string();
        assert_eq!(once, twice);
    }

    #[test]
    fn rejects_missing_and_wrong_scheme() {
        assert!(matches!(
            WorkspaceUri::parse("/plain/path").unwrap_err(),
            UriError::MissingScheme
        ));
        assert!(matches!(
            WorkspaceUri::parse("docker://abc/x").unwrap_err(),
            UriError::UnknownScheme(_)
        ));
    }

    #[test]
    fn rejects_invalid_resource_id() {
        let e = WorkspaceUri::parse("stfs://not-a-resource/x").unwrap_err();
        assert!(matches!(e, UriError::InvalidResourceId(_)));
    }

    #[test]
    fn percent_decoded_traversal_is_rejected() {
        // `%2e%2e` decodes to `..` and must be caught by normalization.
        let e = WorkspaceUri::parse(&format!("stfs://{ID}/a/%2e%2e/b")).unwrap_err();
        assert!(matches!(e, UriError::TraversalDenied { .. }), "{e:?}");
    }

    #[test]
    fn percent_encoded_separator_is_still_a_separator() {
        let u = WorkspaceUri::parse(&format!("stfs://{ID}/a%2Fb")).unwrap();
        assert_eq!(
            u.path().as_str(),
            "a/b",
            "decoded %2F must act as a separator"
        );
        let v = WorkspaceUri::parse(&format!("stfs://{ID}/a%2F%2e%2e%2Fb")).unwrap_err();
        assert!(matches!(v, UriError::TraversalDenied { .. }));
    }

    #[test]
    fn rejects_malformed_percent_escapes() {
        for raw in ["%zz", "%A", "%"] {
            let e = percent_decode(raw).unwrap_err();
            assert!(
                matches!(e, UriError::BadPercentEncoding(_)),
                "{raw} -> {e:?}"
            );
        }
        assert!(matches!(
            percent_decode("a%00b").unwrap_err(),
            UriError::IllegalCharacter(_)
        ));
    }

    #[test]
    fn canonical_form_percent_encodes_odd_characters() {
        let u = WorkspaceUri::parse(&format!("stfs://{ID}/a%20b")).unwrap();
        assert_eq!(u.path().as_str(), "a b");
        let s = u.to_uri_string();
        assert!(s.ends_with("/a%20b"), "{s}");
        assert_eq!(WorkspaceUri::parse(&s).unwrap(), u);
    }

    #[test]
    fn child_applies_same_validation() {
        let u = WorkspaceUri::root(rid());
        assert!(u.child("..").is_err());
        assert!(u.child("a/b").is_err());
        assert!(u.child("ok").is_ok());
    }

    #[test]
    fn redacted_does_not_leak_full_resource_id() {
        let u = WorkspaceUri::root(rid()).child("secret-dir").unwrap();
        let r = u.redacted();
        assert!(!r.contains(rid().as_str()), "full id must not appear: {r}");
        assert!(r.starts_with("stfs://res-"));
        assert!(r.contains("secret-dir"), "path is not a secret");
    }

    #[test]
    fn serde_round_trips_as_string_and_rejects_traversal() {
        let u = WorkspaceUri::root(rid()).child("x").unwrap();
        let j = serde_json::to_string(&u).unwrap();
        assert!(j.starts_with("\"stfs://"));
        assert_eq!(serde_json::from_str::<WorkspaceUri>(&j).unwrap(), u);
        assert!(serde_json::from_str::<WorkspaceUri>(&format!("\"stfs://{ID}/../x\"")).is_err());
    }
}
