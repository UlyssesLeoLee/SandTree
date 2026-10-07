//! Provider-side confinement helpers (NFR-S05, NFR-S08, DD-SECOPS §5).
//!
//! Two checks exist and neither replaces the other:
//!
//! 1. **Normalize before routing** — `to_relative` turns whatever the provider
//!    returned into a canonical `stfs` relative path. A guest-reported path can
//!    therefore never become a host path (NFR-S08).
//! 2. **Canonicalize before mutation** — `confine` / `is_within` re-check the
//!    final resolved location. Symlink or reparse-point targets are only visible
//!    after resolution, so this second pass is the one that actually stops a
//!    junction pointing outside the root.

use crate::error::UriError;

/// Join a validated relative path onto a root, rejecting escapes.
///
/// `relative` must already be canonical (no `..`); if it is not, this returns
/// `TraversalDenied` rather than cleaning it, so callers cannot accidentally
/// rely on silent folding.
pub fn confine(root: &str, relative: &str) -> Result<String, UriError> {
    let clean = crate::path::WorkspacePath::from_relative(relative)?;
    if root.is_empty() {
        return Err(UriError::AbsoluteHostPathDenied("<empty root>".into()));
    }
    let base = normalize_root(root);
    let joined = if clean.is_root() {
        base.clone()
    } else {
        format!("{}/{}", base.trim_end_matches('/'), clean.as_str())
    };
    if is_within(&base, &joined) {
        Ok(joined)
    } else {
        Err(UriError::TraversalDenied {
            offending: relative.to_string(),
        })
    }
}

/// Component-boundary containment check.
///
/// A plain `starts_with` on the string would accept `C:\root-evil` as being
/// inside `C:\root`; comparing components after normalization does not.
pub fn is_within(root: &str, candidate: &str) -> bool {
    let base = normalize_root(root);
    let cand = normalize_path(candidate);
    if cand == base {
        return true;
    }
    cand.starts_with(&format!("{}/", base.trim_end_matches('/')))
}

/// Convert a provider-reported absolute path into a canonical relative path.
///
/// Returns `TraversalDenied` when the reported path lies outside `root`, which
/// is the NFR-S08 guard against trusting guest-reported paths.
pub fn to_relative(root: &str, candidate: &str) -> Result<String, UriError> {
    let base = normalize_root(root);
    let cand = normalize_path(candidate);
    if cand == base {
        return Ok(String::new());
    }
    let prefix = format!("{}/", base.trim_end_matches('/'));
    let Some(rest) = cand.strip_prefix(&prefix) else {
        return Err(UriError::TraversalDenied {
            offending: candidate.to_string(),
        });
    };
    // `normalize_root` lowercases; restore nothing — comparison is
    // case-insensitive on Windows, and the relative remainder keeps the
    // provider's casing so lookups still match the provider's own listings.
    crate::path::WorkspacePath::from_relative(rest).map(|p| p.as_str().to_string())
}

/// Strip trailing separators and unify to `/`; lowercase on Windows.
fn normalize_root(root: &str) -> String {
    let mut r = root.replace('\\', "/");
    while r.len() > 1 && r.ends_with('/') {
        r.pop();
    }
    if r.is_empty() {
        r.push('/');
    }
    if cfg!(windows) {
        r = r.to_lowercase();
    }
    r
}

fn normalize_path(p: &str) -> String {
    let mut s = p.replace('\\', "/");
    while s.len() > 1 && s.ends_with('/') {
        s.pop();
    }
    if cfg!(windows) {
        s = s.to_lowercase();
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confine_joins_within_root() {
        let r = confine("/ws/root", "a/b").unwrap();
        assert_eq!(r, "/ws/root/a/b");
    }

    #[test]
    fn confine_rejects_traversal_relative() {
        assert!(matches!(
            confine("/ws/root", "../escape").unwrap_err(),
            UriError::TraversalDenied { .. }
        ));
        assert!(matches!(
            confine("/ws/root", "a/../../escape").unwrap_err(),
            UriError::TraversalDenied { .. }
        ));
    }

    #[test]
    fn confine_root_returns_root() {
        assert_eq!(confine("/ws/root", "").unwrap(), "/ws/root");
        assert_eq!(confine("/ws/root", ".").unwrap(), "/ws/root");
    }

    #[test]
    fn is_within_uses_component_boundary() {
        assert!(is_within("/ws/root", "/ws/root"));
        assert!(is_within("/ws/root", "/ws/root/a/b"));
        assert!(!is_within("/ws/root", "/ws/root-evil/x"));
        assert!(!is_within("/ws/root", "/ws"));
        assert!(!is_within("/ws/root", "/other/root/a"));
    }

    #[test]
    fn to_relative_strips_root_and_rejects_outside() {
        assert_eq!(to_relative("/ws/root", "/ws/root").unwrap(), "");
        assert_eq!(
            to_relative("/ws/root", "/ws/root/src/main.rs").unwrap(),
            "src/main.rs"
        );
        assert!(matches!(
            to_relative("/ws/root", "/etc/passwd").unwrap_err(),
            UriError::TraversalDenied { .. }
        ));
        assert!(matches!(
            to_relative("/ws/root", "/ws/root-evil/x").unwrap_err(),
            UriError::TraversalDenied { .. }
        ));
    }

    #[test]
    fn guest_reported_traversal_cannot_become_relative_path() {
        // NFR-S08: a guest path that escapes must never become a host path.
        let r = to_relative("/ws", "/ws/../../etc/shadow");
        assert!(r.is_err());
    }
}
