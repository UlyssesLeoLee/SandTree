//! URI errors, mapped to stable SandTree codes.

use sandtree_model::error::ErrorCode;

/// Failure modes of URI parsing, path normalization and confinement.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UriError {
    /// No `stfs://` scheme present.
    #[error("missing stfs:// scheme")]
    MissingScheme,
    /// A different scheme was used (e.g. `docker://`, which is UI-only).
    #[error("unsupported scheme {0:?}; canonical form is stfs://")]
    UnknownScheme(String),
    /// The resource-id segment is not a valid `ResourceId`.
    #[error("invalid resource id segment {0:?}")]
    InvalidResourceId(String),
    /// A `..` component was present. This is an attempted escape, never a
    /// legitimate relative path (NFR-S05).
    #[error("path traversal rejected at {offending:?}")]
    TraversalDenied {
        /// The offending component.
        offending: String,
    },
    /// An absolute host path reached the canonical layer.
    #[error("host absolute path must not enter the canonical VFS: {0:?}")]
    AbsoluteHostPathDenied(String),
    /// Malformed percent escape.
    #[error("bad percent encoding in {0:?}")]
    BadPercentEncoding(String),
    /// Interior empty segment (`a//b`).
    #[error("empty path segment")]
    EmptySegment,
    /// A character that has no place in a canonical path.
    #[error("illegal character in path segment: {0:?}")]
    IllegalCharacter(String),
    /// Input exceeded a documented bound.
    #[error("path exceeds the {0} byte limit")]
    TooLong(usize),
}

impl UriError {
    /// Stable SandTree error code.
    ///
    /// Everything that represents an escape attempt collapses to
    /// `ST-VFS-001`; the rest are `ST-CORE-001` because they indicate a caller
    /// bug rather than a security event.
    pub fn code(&self) -> ErrorCode {
        match self {
            UriError::TraversalDenied { .. } | UriError::AbsoluteHostPathDenied(_) => {
                ErrorCode::VFS_PATH_ESCAPE
            }
            UriError::MissingScheme
            | UriError::UnknownScheme(_)
            | UriError::IllegalCharacter(_)
            | UriError::EmptySegment
            | UriError::TooLong(_)
            | UriError::BadPercentEncoding(_) => ErrorCode::CORE_INVALID,
            UriError::InvalidResourceId(_) => ErrorCode::CORE_INVALID,
        }
    }

    /// Whether this error denotes a containment failure.
    pub fn is_escape_attempt(&self) -> bool {
        matches!(self.code(), ErrorCode::VFS_PATH_ESCAPE)
    }

    /// Render as a `DomainError` for crossing a process boundary.
    pub fn to_domain_error(&self) -> sandtree_model::error::DomainError {
        sandtree_model::error::DomainError::new(self.code(), self.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_attempts_map_to_vfs_path_escape() {
        assert_eq!(
            UriError::TraversalDenied {
                offending: "..".into()
            }
            .code(),
            ErrorCode::VFS_PATH_ESCAPE
        );
        assert_eq!(
            UriError::AbsoluteHostPathDenied("C:\\x".into()).code(),
            ErrorCode::VFS_PATH_ESCAPE
        );
        assert!(UriError::TraversalDenied {
            offending: "..".into()
        }
        .is_escape_attempt());
        assert!(!UriError::EmptySegment.is_escape_attempt());
    }

    #[test]
    fn other_errors_map_to_core_invalid() {
        for e in [
            UriError::MissingScheme,
            UriError::UnknownScheme("docker".into()),
            UriError::EmptySegment,
            UriError::TooLong(1),
            UriError::BadPercentEncoding("%zz".into()),
            UriError::InvalidResourceId("x".into()),
        ] {
            assert_eq!(e.code(), ErrorCode::CORE_INVALID, "{e:?}");
        }
    }

    #[test]
    fn renders_domain_error_with_code() {
        let d = UriError::TraversalDenied {
            offending: "..".into(),
        }
        .to_domain_error();
        assert_eq!(d.code, ErrorCode::VFS_PATH_ESCAPE);
    }
}
