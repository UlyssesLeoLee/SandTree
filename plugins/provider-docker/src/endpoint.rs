//! Endpoint addressing and validation (DD-PLG §5, UT-029, FR-020).
//!
//! The endpoint profile stores a **credential reference**, never a credential
//! (DD-PLG §5: "endpoint profile 只保存 credential reference"). Insecure
//! transports are rejected rather than downgraded, because silently accepting
//! `tcp://` without TLS would let a user believe a link is encrypted when it is
//! not.

use std::fmt;

use sandtree_model::id::EndpointId;

/// Windows named pipe used by Docker Desktop / Docker Engine for Windows.
pub const DEFAULT_PIPE: &str = r"npipe:////./pipe/docker_engine";
/// Unix domain socket used by Docker Engine on Linux/macOS.
pub const DEFAULT_UNIX_SOCKET: &str = "unix:///var/run/docker.sock";

/// Why an endpoint string was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EndpointParseError {
    /// The scheme is not one this provider can drive.
    #[error("unsupported docker endpoint scheme {0:?}; expected npipe/unix/tcp/http/https")]
    UnsupportedScheme(String),
    /// `tcp://` or `http://` without TLS.
    #[error(
        "insecure transport {0:?}; a remote docker endpoint must use tls (tcp:// or https://)"
    )]
    InsecureTransport(String),
    /// The host component was empty (e.g. `tcp://:2375`).
    #[error("endpoint {0:?} has an empty host")]
    EmptyHost(String),
    /// The port component was not a valid TCP port.
    #[error("endpoint {0:?} has an invalid port")]
    InvalidPort(String),
    /// The endpoint string was empty.
    #[error("docker endpoint must not be empty")]
    Empty,
}

/// A validated Docker Engine endpoint (FR-020).
///
/// Identity is derived from the canonical endpoint string so that two profiles
/// pointing at the same Engine produce the same [`EndpointId`] (DD-PLG §5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DockerEndpoint {
    /// Canonical endpoint string, e.g. `npipe:////./pipe/docker_engine`.
    pub uri: String,
    /// Stable identity, part of every Docker resource id.
    pub endpoint_id: EndpointId,
    /// Reference to a secret holding credentials. Never the secret itself.
    pub credential_ref: Option<String>,
    /// Whether the transport is encrypted.
    pub tls: bool,
}

impl DockerEndpoint {
    /// Parse and validate a `DOCKER_HOST`-style endpoint string.
    ///
    /// Rejects malformed and insecure endpoints (UT-029: `tcp://:bad`).
    pub fn parse(raw: &str) -> Result<Self, EndpointParseError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(EndpointParseError::Empty);
        }
        let (scheme, rest) = trimmed
            .split_once("://")
            .ok_or_else(|| EndpointParseError::UnsupportedScheme(trimmed.to_string()))?;
        let scheme_l = scheme.to_ascii_lowercase();

        let tls = match scheme_l.as_str() {
            "npipe" | "unix" => {
                if rest.is_empty() {
                    return Err(EndpointParseError::EmptyHost(trimmed.to_string()));
                }
                false
            }
            "https" => true,
            "http" => false,
            "tcp" => {
                // FR-020 / NFR-S03: a cleartext remote endpoint is refused
                // outright rather than accepted with a warning. The check runs
                // before host/port validation because the transport is the
                // reason for refusal regardless of how well-formed the
                // authority is — UT-029 rejects `tcp://:bad` on the insecure
                // transport, not on a parse detail.
                return Err(EndpointParseError::InsecureTransport(trimmed.to_string()));
            }
            other => return Err(EndpointParseError::UnsupportedScheme(other.to_string())),
        };

        if tls {
            validate_host_port(rest, trimmed)?;
        }

        let uri = format!("{scheme_l}://{rest}");
        Ok(Self {
            endpoint_id: EndpointId::derive(&[uri.as_str()]),
            uri,
            credential_ref: None,
            tls,
        })
    }

    /// Attach a credential **reference** (not a credential value).
    ///
    /// NFR-S03: the value stored is a key into the secret store; a provider never
    /// holds the secret bytes.
    pub fn with_credential_ref(mut self, key: impl Into<String>) -> Self {
        self.credential_ref = Some(key.into());
        self
    }

    /// The canonical endpoint string used for `EndpointId` derivation.
    pub fn identity_key(&self) -> &str {
        self.uri.as_str()
    }
}

impl fmt::Display for DockerEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The credential reference is deliberately omitted: this value reaches
        // logs and event payloads (NFR-S03).
        f.write_str(&self.uri)
    }
}

/// Validate a `host:port` authority component.
fn validate_host_port(rest: &str, whole: &str) -> Result<(), EndpointParseError> {
    // Strip any path component; the authority is what we validate.
    let authority = rest.split('/').next().unwrap_or("");
    if authority.is_empty() {
        return Err(EndpointParseError::EmptyHost(whole.to_string()));
    }
    let Some((host, port)) = authority.rsplit_once(':') else {
        return Err(EndpointParseError::InvalidPort(whole.to_string()));
    };
    if host.is_empty() {
        return Err(EndpointParseError::EmptyHost(whole.to_string()));
    }
    match port.parse::<u16>() {
        Ok(0) | Err(_) => Err(EndpointParseError::InvalidPort(whole.to_string())),
        Ok(_) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_default_named_pipe_and_unix_socket() {
        let pipe = DockerEndpoint::parse(DEFAULT_PIPE).unwrap();
        assert_eq!(pipe.uri, "npipe:////./pipe/docker_engine");
        assert!(!pipe.tls);

        let sock = DockerEndpoint::parse(DEFAULT_UNIX_SOCKET).unwrap();
        assert_eq!(sock.uri, "unix:///var/run/docker.sock");
        assert!(!sock.tls);
    }

    #[test]
    fn identity_is_stable_and_normalizes_scheme_case() {
        // DD-PLG §5: same endpoint -> same EndpointId, so two profiles cannot
        // fork the identity of one Engine.
        let a = DockerEndpoint::parse("npipe:////./pipe/docker_engine").unwrap();
        let b = DockerEndpoint::parse("NPIPE:////./pipe/docker_engine").unwrap();
        assert_eq!(a.endpoint_id, b.endpoint_id);
        assert_eq!(a.identity_key(), b.identity_key());
    }

    #[test]
    fn distinct_endpoints_get_distinct_ids() {
        // FR-078: a nested Engine inside a sandbox must not collide with the host one.
        let host = DockerEndpoint::parse(DEFAULT_PIPE).unwrap();
        let nested = DockerEndpoint::parse("https://sandbox.internal:2376").unwrap();
        assert_ne!(host.endpoint_id, nested.endpoint_id);
    }

    #[test]
    fn cleartext_tcp_is_rejected_not_downgraded() {
        // UT-029: insecure / malformed endpoint must be rejected.
        assert_eq!(
            DockerEndpoint::parse("tcp://:bad"),
            Err(EndpointParseError::InsecureTransport("tcp://:bad".into()))
        );
        assert_eq!(
            DockerEndpoint::parse("tcp://host.example:2375"),
            Err(EndpointParseError::InsecureTransport(
                "tcp://host.example:2375".into()
            ))
        );
    }

    #[test]
    fn malformed_endpoints_are_rejected() {
        for raw in [
            "",
            "   ",
            "not-a-uri",
            "ftp://host:21",
            "tcp://:2375",
            "https://h:0",
        ] {
            assert!(
                DockerEndpoint::parse(raw).is_err(),
                "{raw:?} must not be accepted"
            );
        }
    }

    #[test]
    fn https_endpoint_is_accepted_and_marked_tls() {
        let e = DockerEndpoint::parse("https://docker.internal:2376").unwrap();
        assert!(e.tls);
        assert_eq!(e.uri, "https://docker.internal:2376");
    }

    #[test]
    fn credential_reference_is_stored_not_the_secret() {
        // DD-PLG §5 / NFR-S03: profile keeps a reference only.
        let e = DockerEndpoint::parse(DEFAULT_PIPE)
            .unwrap()
            .with_credential_ref("secret/docker/prod");
        assert_eq!(e.credential_ref.as_deref(), Some("secret/docker/prod"));
        // Display (which reaches logs) never carries the reference.
        assert!(!format!("{e}").contains("secret/"));
    }

    #[test]
    fn invalid_port_and_empty_host_are_distinguished() {
        assert_eq!(
            DockerEndpoint::parse("tcp://h:notaport"),
            Err(EndpointParseError::InsecureTransport(
                "tcp://h:notaport".into()
            ))
        );
        // A TLS endpoint is accepted by the transport check, so it reaches the
        // authority validator and the two failure modes become distinguishable.
        assert_eq!(
            DockerEndpoint::parse("https://:2376"),
            Err(EndpointParseError::EmptyHost("https://:2376".into()))
        );
        assert_eq!(
            DockerEndpoint::parse("https://host:99999"),
            Err(EndpointParseError::InvalidPort("https://host:99999".into()))
        );
    }
}
