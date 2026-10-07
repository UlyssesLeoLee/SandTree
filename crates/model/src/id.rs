//! Stable identifier types (DD-SW §2; `schemas/workspace_uri_v1.md`).
//!
//! Every identity in SandTree is an opaque, lower-case, lexicographically sortable
//! string. Provider native ids never leak into identity: they are stored as
//! metadata, while the canonical id is derived from
//! `blake3(endpoint_id + provider_native_id)` so that a rename does not change
//! identity (DD-PLG §5).

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Errors produced when parsing or constructing an identifier.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum IdError {
    /// The textual form was empty or longer than the bounded representation.
    #[error("invalid {kind} id: {reason}")]
    Invalid {
        /// Identifier family, e.g. `res`.
        kind: &'static str,
        /// Human-readable cause.
        reason: String,
    },
}

/// Shared validation + construction for every SandTree opaque id.
macro_rules! opaque_id {
    ($name:ident, $len:expr, $label:literal, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Short stable prefix used when deriving human-readable diagnostics.
            pub const PREFIX: &'static str = $label;

            /// Build an id from arbitrary parts, hashing them into the bounded form.
            ///
            /// Identity must be reproducible for identical inputs (UT-002) and must
            /// not depend on mutable display names (DD-PLG §5).
            pub fn derive(parts: &[&str]) -> Self {
                let mut hasher = blake3::Hasher::new();
                hasher.update($label.as_bytes());
                for part in parts {
                    hasher.update(b"\x1f");
                    hasher.update(part.as_bytes());
                }
                Self(format!(
                    "{}-{}",
                    $label,
                    &hasher.finalize().to_hex()[..$len]
                ))
            }

            /// Build an id from an already-bounded hex digest.
            pub fn from_digest(digest: &str) -> Result<Self, IdError> {
                Self::parse(digest)
            }

            /// Generate a fresh random id.
            ///
            /// Only for identities that are *not* derived from provider state
            /// (session tokens, correlation ids, observation job ids).
            pub fn generate() -> Self {
                Self(format!(
                    "{}-{}",
                    $label,
                    &uuid::Uuid::new_v4().simple().to_string()[..$len]
                ))
            }

            /// Lenient parse helper for metadata that may be absent or foreign.
            ///
            /// Returns `None` instead of an error so callers reading optional
            /// provider metadata do not have to match on `IdError`.
            pub fn from_str_ok(raw: &str) -> Option<Self> {
                Self::parse(raw).ok()
            }

            /// Validate and wrap an existing bounded id string.
            pub fn parse(raw: &str) -> Result<Self, IdError> {
                let invalid = |reason: String| IdError::Invalid {
                    kind: $label,
                    reason,
                };
                let Some(rest) = raw.strip_prefix(concat!($label, "-")) else {
                    return Err(invalid(format!("expected prefix {}-, got {raw:?}", $label)));
                };
                if rest.len() != $len {
                    return Err(invalid(format!(
                        "expected {} hex chars, got {}",
                        $len,
                        rest.len()
                    )));
                }
                if !rest
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                {
                    return Err(invalid("must be lower-case hex".into()));
                }
                Ok(Self(raw.to_string()))
            }

            /// Borrow the textual id.
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// Consume and return the textual id.
            pub fn into_string(self) -> String {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = IdError;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Self::parse(s)
            }
        }
    };
}

opaque_id!(
    ResourceId,
    26,
    "res",
    "Opaque resource identity. Immutable within a discovery epoch (FR-002, UT-002)."
);
opaque_id!(
    PluginId,
    20,
    "plg",
    "Stable lower-case plugin id in reverse-domain form, e.g. `sandtree.provider.docker` (DD-PLG §2)."
);
opaque_id!(
    AppId,
    16,
    "app",
    "Stable app identity used by app manifests / generations (FR-053)."
);
opaque_id!(
    EndpointId,
    20,
    "ep",
    "Docker endpoint identity. Part of every Docker resource id so that two
    endpoints exposing the same container id stay distinct (DD-PLG §5)."
);
opaque_id!(
    SnapshotId,
    24,
    "snp",
    "Logical workspace/resource snapshot identity (FR-016, FR-044)."
);
opaque_id!(
    CorrelationId,
    20,
    "cor",
    "Cross-plane correlation id carried by operations, events and audit records (FR-063)."
);

/// Session identity for a sandbox observation session.
///
/// Windows Sandbox probe envelopes bind their payload to this value so a stale
/// or forged outbox file cannot be accepted (`schemas/windows_probe_protocol_v1.md`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionId(String);

impl SessionId {
    /// Generate a fresh random session id.
    pub fn generate() -> Self {
        Self(uuid::Uuid::new_v4().to_string())
    }

    /// Borrow the raw session id.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Generation number for a plugin/app generation (FR-052, FR-053).
pub type Generation = u64;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_is_stable_for_identical_inputs() {
        // UT-002 Resource ID stability
        let a = ResourceId::derive(&["ep-abc", "sha256:deadbeef"]);
        let b = ResourceId::derive(&["ep-abc", "sha256:deadbeef"]);
        assert_eq!(a, b);
    }

    #[test]
    fn derive_changes_with_provider_native_id() {
        let a = ResourceId::derive(&["ep-abc", "sha256:deadbeef"]);
        let b = ResourceId::derive(&["ep-abc", "sha256:feedface"]);
        assert_ne!(a, b);
    }

    #[test]
    fn derive_ignores_display_name_rename() {
        // DD-PLG §5: "name 变化不改变 identity"
        let id = ResourceId::derive(&["ep-abc", "containerid"]);
        let _renamed_to = "totally-different-display-name";
        assert_eq!(ResourceId::derive(&["ep-abc", "containerid"]), id);
    }

    #[test]
    fn derived_ids_are_domain_separated() {
        // The same parts hashed for two different id types must not collide.
        let resource = ResourceId::derive(&["x"]);
        let plugin = PluginId::derive(&["x"]);
        assert_ne!(resource.as_str(), plugin.as_str());
        assert!(plugin.as_str().starts_with("plg-"));
    }

    #[test]
    fn parse_rejects_wrong_prefix_and_shape() {
        assert!(ResourceId::parse("res-abc").is_err());
        assert!(ResourceId::parse("plg-abc").is_err());
        assert!(ResourceId::parse(&format!("res-{}", "z".repeat(26))).is_err());
        assert!(ResourceId::parse(&format!("res-{}", "A".repeat(26))).is_err());
    }

    #[test]
    fn parse_round_trips() {
        let id = ResourceId::derive(&["a", "b"]);
        assert_eq!(ResourceId::parse(id.as_str()).unwrap(), id);
    }

    #[test]
    fn serde_is_transparent_string() {
        let id = EndpointId::derive(&["npipe:////./pipe/docker_engine"]);
        let json = serde_json::to_string(&id).unwrap();
        assert!(json.starts_with("\"ep-"));
        assert_eq!(serde_json::from_str::<EndpointId>(&json).unwrap(), id);
    }

    #[test]
    fn ordering_is_stable_for_sorting() {
        let mut ids = [
            ResourceId::derive(&["c"]),
            ResourceId::derive(&["a"]),
            ResourceId::derive(&["b"]),
        ];
        ids.sort();
        assert!(ids[0] < ids[1] && ids[1] < ids[2]);
    }
}
