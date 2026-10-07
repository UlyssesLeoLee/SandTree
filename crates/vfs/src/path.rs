//! Canonical workspace path.
//!
//! A `WorkspacePath` is always relative, always `/`-separated, and never
//! contains `.`, `..`, empty segments or a host-specific prefix
//! (`schemas/workspace_uri_v1.md`).
//!
//! The type is deliberately unforgiving: `a/../b` is **rejected**, not silently
//! folded into `b`. Folding would make a traversal attempt look like a
//! legitimate request in the audit log, which is exactly the ambiguity NFR-S05
//! exists to remove.

use serde::{Deserialize, Serialize};

use crate::error::UriError;

/// Maximum number of path segments.
pub const MAX_SEGMENTS: usize = 256;
/// Maximum length of the whole relative path in bytes.
pub const MAX_PATH_BYTES: usize = 64 * 1024;
/// Maximum length of a single segment in bytes.
pub const MAX_SEGMENT_BYTES: usize = 4 * 1024;

/// A normalized, root-relative workspace path.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct WorkspacePath {
    segments: Vec<String>,
    text: String,
}

impl WorkspacePath {
    /// The workspace root (empty relative path).
    pub fn root() -> Self {
        Self::build(Vec::new())
    }

    /// Build from segments, keeping the rendered form in sync.
    fn build(segments: Vec<String>) -> Self {
        let mut text = String::new();
        for (i, s) in segments.iter().enumerate() {
            if i > 0 {
                text.push('/');
            }
            text.push_str(s);
        }
        Self { segments, text }
    }

    /// Normalize a relative path, rejecting anything that could escape the root.
    ///
    /// Accepted: `""`, `"."`, `"a"`, `"a/b"`, `"a/./b"`, `"a/"`.
    /// Rejected: `..` in any position, absolute paths (POSIX or Windows),
    /// backslashes, interior empty segments (`a//b`), NUL, oversized input.
    pub fn from_relative(raw: &str) -> Result<Self, UriError> {
        if raw.len() > MAX_PATH_BYTES {
            return Err(UriError::TooLong(raw.len()));
        }
        if raw.contains('\0') {
            return Err(UriError::IllegalCharacter("\\u{0}".to_string()));
        }
        // Absolute-host detection runs before the backslash rule: a Windows
        // drive or UNC path must be reported as a host path, not as "illegal
        // backslash", or the error code would say the wrong thing.
        if is_absolute(raw) {
            return Err(UriError::AbsoluteHostPathDenied(raw.to_string()));
        }
        if raw.contains('\\') {
            // The canonical form is `/`-only; a backslash is either a Windows
            // separator smuggled in or a deliberate parser-differential attempt.
            return Err(UriError::IllegalCharacter("\\".to_string()));
        }
        if raw.is_empty() {
            return Ok(Self::root());
        }

        let mut segments: Vec<String> = Vec::new();
        for part in raw.split('/') {
            match part {
                "" => {
                    // A single trailing slash is normal; interior empties are not.
                    if raw.ends_with('/') {
                        continue;
                    }
                    return Err(UriError::EmptySegment);
                }
                "." => continue,
                ".." => {
                    return Err(UriError::TraversalDenied {
                        offending: "..".into(),
                    })
                }
                other => {
                    if other.len() > MAX_SEGMENT_BYTES {
                        return Err(UriError::TooLong(other.len()));
                    }
                    segments.push(other.to_string());
                }
            }
            if segments.len() > MAX_SEGMENTS {
                return Err(UriError::TooLong(segments.len()));
            }
        }
        Ok(Self::build(segments))
    }

    /// Whether this is the workspace root.
    pub fn is_root(&self) -> bool {
        self.segments.is_empty()
    }

    /// Path segments, in order.
    pub fn segments(&self) -> &[String] {
        &self.segments
    }

    /// Canonical relative form (`a/b/c`, empty for root).
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Append one child name, applying the same validation as `from_relative`.
    pub fn join(&self, child: &str) -> Result<WorkspacePath, UriError> {
        if child.contains('/') || child.contains('\\') || child.contains('\0') {
            return Err(UriError::IllegalCharacter(child.to_string()));
        }
        if child.is_empty() || child == "." || child == ".." {
            return Err(UriError::IllegalCharacter(child.to_string()));
        }
        if child.len() > MAX_SEGMENT_BYTES {
            return Err(UriError::TooLong(child.len()));
        }
        if self.segments.len() + 1 > MAX_SEGMENTS {
            return Err(UriError::TooLong(self.segments.len() + 1));
        }
        let mut segments = self.segments.clone();
        segments.push(child.to_string());
        Ok(Self::build(segments))
    }

    /// Parent path, or `None` at the root.
    pub fn parent(&self) -> Option<WorkspacePath> {
        if self.segments.is_empty() {
            return None;
        }
        let mut segments = self.segments.clone();
        segments.pop();
        Some(Self::build(segments))
    }

    /// Last segment.
    pub fn file_name(&self) -> Option<&str> {
        self.segments.last().map(String::as_str)
    }

    /// Depth below the root.
    pub fn depth(&self) -> usize {
        self.segments.len()
    }

    /// Whether `self` is `other` or lives under it.
    pub fn starts_with(&self, other: &WorkspacePath) -> bool {
        if other.segments.len() > self.segments.len() {
            return false;
        }
        self.segments[..other.segments.len()] == other.segments[..]
    }
}

impl std::fmt::Display for WorkspacePath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for WorkspacePath {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for WorkspacePath {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = <String as Deserialize>::deserialize(d)?;
        WorkspacePath::from_relative(&raw).map_err(serde::de::Error::custom)
    }
}

fn is_absolute(raw: &str) -> bool {
    raw.starts_with('/') || raw.starts_with('\\') || looks_like_drive_prefix(raw)
}

fn looks_like_drive_prefix(raw: &str) -> bool {
    let b = raw.as_bytes();
    b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':'
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_canonical_and_dotted_forms() {
        for raw in ["", ".", "a", "a/b/c", "a/./b", "a/"] {
            assert!(
                WorkspacePath::from_relative(raw).is_ok(),
                "{raw:?} must parse"
            );
        }
        assert_eq!(
            WorkspacePath::from_relative("a/./b").unwrap().as_str(),
            "a/b"
        );
        assert_eq!(WorkspacePath::from_relative("a/").unwrap().as_str(), "a");
        assert_eq!(WorkspacePath::from_relative(".").unwrap().as_str(), "");
        assert!(WorkspacePath::from_relative("").unwrap().is_root());
    }

    #[test]
    fn rejects_every_traversal_form() {
        for raw in [
            "..",
            "../a",
            "a/../b",
            "a/..",
            "../",
            "a/b/../../c",
            "..\\a",
        ] {
            let err = WorkspacePath::from_relative(raw).unwrap_err();
            assert!(
                matches!(
                    err,
                    UriError::TraversalDenied { .. } | UriError::IllegalCharacter(_)
                ),
                "{raw:?} produced {err:?}"
            );
        }
    }

    #[test]
    fn rejects_absolute_host_paths() {
        for raw in [
            "/a",
            "/",
            "C:\\a",
            "C:/a",
            "\\\\server\\share",
            "//host/share",
        ] {
            let err = WorkspacePath::from_relative(raw).unwrap_err();
            assert!(
                matches!(err, UriError::AbsoluteHostPathDenied(_)),
                "{raw:?} produced {err:?}"
            );
        }
    }

    #[test]
    fn rejects_backslash_and_interior_empty_segment() {
        assert!(matches!(
            WorkspacePath::from_relative("a\\b").unwrap_err(),
            UriError::IllegalCharacter(_)
        ));
        assert!(matches!(
            WorkspacePath::from_relative("a//b").unwrap_err(),
            UriError::EmptySegment
        ));
        assert!(WorkspacePath::from_relative("a/b/").is_ok());
    }

    #[test]
    fn rejects_nul_and_oversized() {
        assert!(WorkspacePath::from_relative("a\0b").is_err());
        let big = "x".repeat(MAX_SEGMENT_BYTES + 1);
        assert!(WorkspacePath::from_relative(&big).is_err());
        let deep = (0..MAX_SEGMENTS + 2)
            .map(|i| format!("s{i}"))
            .collect::<Vec<_>>()
            .join("/");
        assert!(WorkspacePath::from_relative(&deep).is_err());
    }

    #[test]
    fn join_and_parent_round_trip() {
        let p = WorkspacePath::from_relative("a/b/c").unwrap();
        assert_eq!(p.parent().unwrap().as_str(), "a/b");
        assert_eq!(p.parent().unwrap().parent().unwrap().as_str(), "a");
        assert!(WorkspacePath::from_relative("a")
            .unwrap()
            .parent()
            .unwrap()
            .is_root());
        assert!(WorkspacePath::root().parent().is_none());
        assert_eq!(p.file_name(), Some("c"));
        assert_eq!(p.depth(), 3);
        assert_eq!(p.join("d").unwrap().as_str(), "a/b/c/d");
    }

    #[test]
    fn join_rejects_traversal_names() {
        let p = WorkspacePath::from_relative("a").unwrap();
        for bad in ["..", ".", "", "b/c", "b\\c"] {
            assert!(p.join(bad).is_err(), "{bad:?} must be rejected by join");
        }
    }

    #[test]
    fn starts_with_uses_segment_boundary() {
        let a = WorkspacePath::from_relative("a/b").unwrap();
        let b = WorkspacePath::from_relative("a").unwrap();
        let ab = WorkspacePath::from_relative("ab").unwrap();
        assert!(a.starts_with(&b));
        assert!(b.starts_with(&WorkspacePath::root()));
        assert!(!b.starts_with(&a));
        assert!(!ab.starts_with(&b), "'ab' must not be under 'a'");
    }

    #[test]
    fn serde_round_trips_as_string() {
        let p = WorkspacePath::from_relative("a/b").unwrap();
        let j = serde_json::to_string(&p).unwrap();
        assert_eq!(j, "\"a/b\"");
        assert_eq!(serde_json::from_str::<WorkspacePath>(&j).unwrap(), p);
        assert!(serde_json::from_str::<WorkspacePath>("\"../x\"").is_err());
    }
}
