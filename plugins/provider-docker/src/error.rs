//! Provider-local error type and vendor-error mapping (NFR-O02, DD-DATA §8).
//!
//! Rule: **every** failure that crosses the plugin boundary becomes a
//! [`DomainError`] carrying a stable `ST-*` code. The Bollard error string may
//! only appear in `detail`, never in `message`, because UI and kernel branch on
//! the code (DD-SW §10).

use sandtree_model::error::{DomainError, ErrorCode};

/// Failures this provider produces itself (before any vendor call).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProviderError {
    /// The endpoint string did not validate.
    #[error("invalid docker endpoint: {0}")]
    Endpoint(#[from] crate::endpoint::EndpointParseError),
    /// The requested resource id is not a Docker resource of this endpoint.
    #[error("resource {0} is not owned by the docker provider")]
    NotOwned(String),
    /// The operation kind is not supported for this resource kind.
    #[error("operation {op} is not supported for a docker {kind}")]
    Unsupported {
        /// Operation kind name.
        op: String,
        /// Resource kind name.
        kind: String,
    },
    /// An operation argument was missing or the wrong shape.
    #[error("invalid argument {name:?}: {reason}")]
    BadArgument {
        /// Argument name.
        name: String,
        /// Why it was rejected.
        reason: String,
    },
    /// Confirmation was required for a destructive operation (NFR-U02).
    #[error("{op} is destructive and requires confirmed=true")]
    ConfirmationRequired {
        /// Operation kind name.
        op: String,
    },
    /// The Engine connection could not be established.
    #[error("docker engine at {endpoint} is unavailable: {reason}")]
    EngineUnavailable {
        /// Endpoint string.
        endpoint: String,
        /// Non-secret reason.
        reason: String,
    },
}

impl ProviderError {
    /// Map to the stable domain error code for this failure.
    pub fn code(&self) -> ErrorCode {
        match self {
            ProviderError::Endpoint(_) => ErrorCode::DOCKER_ENDPOINT_UNAVAILABLE,
            ProviderError::NotOwned(_) => ErrorCode::CORE_INVALID,
            ProviderError::Unsupported { .. } => ErrorCode::SANDBOX_UNSUPPORTED,
            ProviderError::BadArgument { .. } => ErrorCode::CORE_INVALID,
            ProviderError::ConfirmationRequired { .. } => ErrorCode::CORE_INVALID,
            ProviderError::EngineUnavailable { .. } => ErrorCode::DOCKER_ENDPOINT_UNAVAILABLE,
        }
    }
}

impl From<ProviderError> for DomainError {
    fn from(e: ProviderError) -> Self {
        let code = e.code();
        DomainError::new(code, e.to_string()).with_detail(format!("{e:?}"))
    }
}

/// Translate a Bollard error into a [`DomainError`] with a stable code.
///
/// The mapping is deliberately coarse: the kernel must be able to decide
/// retry-vs-give-up without parsing Docker strings (DD-DATA §8).
pub fn map_bollard_error(err: &bollard::errors::Error) -> DomainError {
    let (code, message) = match err {
        // Connection refused / pipe missing / timed out: retryable endpoint problem.
        bollard::errors::Error::IOError { .. } => (
            ErrorCode::DOCKER_ENDPOINT_UNAVAILABLE,
            "docker engine is not reachable",
        ),
        bollard::errors::Error::DockerResponseServerError {
            status_code,
            message: raw_message,
        } => {
            // 404 -> the object is genuinely absent (ST-VFS-002 is for VFS paths,
            // so a Docker-level absence is ST-DKR-003 with the status in detail).
            // 409 -> conflict / still in use. 4xx otherwise -> client-side refusal.
            let code = match *status_code {
                404 => ErrorCode::DOCKER_CONFLICT,
                409 => ErrorCode::DOCKER_CONFLICT,
                400..=499 => ErrorCode::CORE_INVALID,
                500..=599 => ErrorCode::DOCKER_ENDPOINT_UNAVAILABLE,
                _ => ErrorCode::DOCKER_API_INCOMPATIBLE,
            };
            let message = format!("docker engine rejected the request ({status_code})");
            return DomainError::new(code, message)
                .with_detail(message_redacted(raw_message, *status_code));
        }
        // Version negotiation / unsupported API surface.
        bollard::errors::Error::APIVersionParseError { .. }
        | bollard::errors::Error::StrParseError { .. } => (
            ErrorCode::DOCKER_API_INCOMPATIBLE,
            "docker api version is not compatible with this provider",
        ),
        // Anything else (decode, stream, url) is treated as a transport fault.
        _ => (
            ErrorCode::DOCKER_ENDPOINT_UNAVAILABLE,
            "docker engine request failed",
        ),
    };
    DomainError::new(code, message).with_detail(format!("{err}"))
}

/// Keep the engine's own text out of the user-facing message (NFR-S03).
///
/// The raw Engine message is genuinely useful for diagnosis, so it is retained
/// in `detail` only, where the UI must not parse it.
fn message_redacted(message: &str, status_code: u16) -> String {
    format!("{message}: status {status_code}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn io_error_maps_to_retryable_endpoint_code() {
        let e = bollard::errors::Error::IOError {
            err: std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused"),
        };
        let d = map_bollard_error(&e);
        assert_eq!(d.code, ErrorCode::DOCKER_ENDPOINT_UNAVAILABLE);
        assert!(d.is_retryable());
        assert!(d.detail.is_some());
    }

    #[test]
    fn server_404_maps_to_conflict_and_keeps_raw_text_in_detail() {
        let e = bollard::errors::Error::DockerResponseServerError {
            status_code: 404,
            message: "No such container: web".into(),
        };
        let d = map_bollard_error(&e);
        assert_eq!(d.code, ErrorCode::DOCKER_CONFLICT);
        // The vendor text must not leak into the branchable message.
        assert!(!d.message.contains("No such container"));
        assert!(d.detail.as_deref().unwrap().contains("No such container"));
    }

    #[test]
    fn server_409_maps_to_conflict() {
        let e = bollard::errors::Error::DockerResponseServerError {
            status_code: 409,
            message: "container is running".into(),
        };
        assert_eq!(map_bollard_error(&e).code, ErrorCode::DOCKER_CONFLICT);
    }

    #[test]
    fn server_4xx_and_5xx_split_into_client_and_transport() {
        let bad = bollard::errors::Error::DockerResponseServerError {
            status_code: 400,
            message: "bad parameter".into(),
        };
        assert_eq!(map_bollard_error(&bad).code, ErrorCode::CORE_INVALID);
        assert!(!map_bollard_error(&bad).is_retryable());

        let boom = bollard::errors::Error::DockerResponseServerError {
            status_code: 503,
            message: "unavailable".into(),
        };
        let d = map_bollard_error(&boom);
        assert_eq!(d.code, ErrorCode::DOCKER_ENDPOINT_UNAVAILABLE);
        assert!(d.is_retryable());
    }

    #[test]
    fn provider_errors_carry_stable_codes() {
        use crate::endpoint::EndpointParseError;
        assert_eq!(
            ProviderError::Endpoint(EndpointParseError::Empty).code(),
            ErrorCode::DOCKER_ENDPOINT_UNAVAILABLE
        );
        assert_eq!(
            ProviderError::Unsupported {
                op: "destroy".into(),
                kind: "image".into()
            }
            .code(),
            ErrorCode::SANDBOX_UNSUPPORTED
        );
        assert_eq!(
            ProviderError::ConfirmationRequired { op: "prune".into() }.code(),
            ErrorCode::CORE_INVALID
        );
        let d: DomainError = ProviderError::NotOwned("res-x".into()).into();
        assert_eq!(d.code, ErrorCode::CORE_INVALID);
        assert!(d.detail.is_some());
    }
}
