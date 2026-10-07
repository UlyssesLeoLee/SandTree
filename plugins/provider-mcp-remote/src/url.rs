//! Validation for the MCP endpoint a sandbox publishes.
//!
//! Same threat model as the git remote's URL: the endpoint comes out of the
//! sandbox being observed, so it is attacker-influenced input. Everything that
//! would let a hostile endpoint widen the request is closed before a socket is
//! opened.
//!
//! Refused: userinfo (a credential must never reach a capability scope, an
//! audit record or a log line — ADR-013), query and fragment (this channel
//! appends nothing, so a caller-supplied one only ever describes a *different*
//! request than the capability was granted for), `..` path segments, control
//! characters, and every scheme other than `http`/`https`.

/// Schemes this provider will speak.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointScheme {
    /// Plain HTTP.
    Http,
    /// HTTP over TLS.
    Https,
}

impl EndpointScheme {
    /// Scheme token as it appears in a URL.
    pub fn as_str(self) -> &'static str {
        match self {
            EndpointScheme::Http => "http",
            EndpointScheme::Https => "https",
        }
    }

    /// Default port when the URL omits one.
    pub fn default_port(self) -> u16 {
        match self {
            EndpointScheme::Http => 80,
            EndpointScheme::Https => 443,
        }
    }

    /// Parse a scheme token.
    pub fn from_wire(s: &str) -> Option<Self> {
        match s {
            "http" => Some(EndpointScheme::Http),
            "https" => Some(EndpointScheme::Https),
            _ => None,
        }
    }
}

/// Why an endpoint URL was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EndpointUrlError {
    /// No `scheme://` prefix.
    #[error("endpoint must be absolute and start with a scheme")]
    NotAbsolute,
    /// A scheme outside the allow-list.
    #[error("scheme {0:?} is not one of http, https")]
    UnsupportedScheme(String),
    /// The authority carried userinfo.
    #[error("endpoint must not embed credentials")]
    CredentialsInUrl,
    /// No host in the authority.
    #[error("endpoint has no host")]
    MissingHost,
    /// The port was not a number in range.
    #[error("port {0:?} is not valid")]
    InvalidPort(String),
    /// A `..` path segment.
    #[error("endpoint path must not contain a .. segment")]
    PathEscapes,
    /// A control character in the path.
    #[error("endpoint path contains a control character")]
    PathControlCharacter,
    /// A query string was supplied.
    #[error("endpoint must not carry a query string")]
    QueryNotAllowed,
    /// A fragment was supplied.
    #[error("endpoint must not carry a fragment")]
    FragmentNotAllowed,
}

/// A validated MCP endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpEndpointUrl {
    scheme: EndpointScheme,
    host: String,
    port: u16,
    path: String,
}

impl McpEndpointUrl {
    /// Validate and split an endpoint URL.
    pub fn parse(raw: &str) -> Result<Self, EndpointUrlError> {
        let raw = raw.trim();
        let Some((scheme_tok, rest)) = raw.split_once("://") else {
            return Err(EndpointUrlError::NotAbsolute);
        };
        let scheme = EndpointScheme::from_wire(scheme_tok)
            .ok_or_else(|| EndpointUrlError::UnsupportedScheme(scheme_tok.to_string()))?;

        let (authority, path_and_rest) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, ""),
        };
        if authority.contains('@') {
            return Err(EndpointUrlError::CredentialsInUrl);
        }
        if authority.is_empty() {
            return Err(EndpointUrlError::MissingHost);
        }

        let (host, port) = split_host_port(authority, scheme.default_port())?;

        if path_and_rest.contains('?') {
            return Err(EndpointUrlError::QueryNotAllowed);
        }
        if path_and_rest.contains('#') {
            return Err(EndpointUrlError::FragmentNotAllowed);
        }
        let path = path_and_rest;
        if path.chars().any(|c| c.is_control()) {
            return Err(EndpointUrlError::PathControlCharacter);
        }
        if path.split('/').any(|s| s == "..") {
            return Err(EndpointUrlError::PathEscapes);
        }
        if path.is_empty() {
            return Err(EndpointUrlError::MissingHost);
        }

        Ok(Self {
            scheme,
            host,
            port,
            path: path.to_string(),
        })
    }

    /// Scheme.
    pub fn scheme(&self) -> EndpointScheme {
        self.scheme
    }

    /// Host, without brackets.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Port.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Path, always starting with `/`.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// `host:port`, used verbatim as the `net:connect` capability scope.
    pub fn endpoint_scope(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    /// The full URL this transport posts to.
    pub fn url(&self) -> String {
        format!(
            "{}://{}:{}{}",
            self.scheme.as_str(),
            self.host,
            self.port,
            self.path
        )
    }
}

fn split_host_port(authority: &str, default_port: u16) -> Result<(String, u16), EndpointUrlError> {
    if let Some(stripped) = authority.strip_prefix('[') {
        let Some(close) = stripped.find(']') else {
            return Err(EndpointUrlError::MissingHost);
        };
        let host = format!("[{}]", &stripped[..close]);
        let after = &stripped[close + 1..];
        if after.is_empty() {
            return Ok((host, default_port));
        }
        let Some(port_tok) = after.strip_prefix(':') else {
            return Err(EndpointUrlError::InvalidPort(after.to_string()));
        };
        return Ok((host, parse_port(port_tok)?));
    }
    match authority.rsplit_once(':') {
        Some((host, port_tok)) if !host.is_empty() => Ok((host.to_string(), parse_port(port_tok)?)),
        Some((_, port_tok)) => Err(EndpointUrlError::InvalidPort(port_tok.to_string())),
        None => Ok((authority.to_string(), default_port)),
    }
}

fn parse_port(tok: &str) -> Result<u16, EndpointUrlError> {
    tok.parse::<u16>()
        .ok()
        .filter(|p| *p > 0)
        .ok_or_else(|| EndpointUrlError::InvalidPort(tok.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plain_endpoint_parses_and_yields_its_capability_scope() {
        let u = McpEndpointUrl::parse("https://sandbox.internal:9443/mcp").unwrap();
        assert_eq!(u.scheme(), EndpointScheme::Https);
        assert_eq!(u.host(), "sandbox.internal");
        assert_eq!(u.port(), 9443);
        assert_eq!(u.path(), "/mcp");
        assert_eq!(u.endpoint_scope(), "sandbox.internal:9443");
        assert_eq!(u.url(), "https://sandbox.internal:9443/mcp");
    }

    #[test]
    fn an_omitted_port_still_yields_an_explicit_scope() {
        assert_eq!(
            McpEndpointUrl::parse("http://10.0.0.7/mcp")
                .unwrap()
                .endpoint_scope(),
            "10.0.0.7:80"
        );
    }

    #[test]
    fn credentials_are_refused() {
        // ADR-013: a credential must never reach a capability scope, an audit
        // record or a log line.
        assert_eq!(
            McpEndpointUrl::parse("https://u:p@sandbox.internal/mcp").unwrap_err(),
            EndpointUrlError::CredentialsInUrl
        );
    }

    #[test]
    fn only_http_and_https_are_accepted() {
        for raw in [
            "file:///etc/passwd",
            "ws://sandbox.internal/mcp",
            "stdio:///run/mcp.sock",
            "mcp+inproc://x",
            "sandbox.internal/mcp",
        ] {
            assert!(
                matches!(
                    McpEndpointUrl::parse(raw),
                    Err(EndpointUrlError::NotAbsolute)
                        | Err(EndpointUrlError::UnsupportedScheme(_))
                ),
                "{raw} must be refused"
            );
        }
    }

    #[test]
    fn query_fragment_and_traversal_are_refused() {
        assert_eq!(
            McpEndpointUrl::parse("https://h/mcp?x=1").unwrap_err(),
            EndpointUrlError::QueryNotAllowed
        );
        assert_eq!(
            McpEndpointUrl::parse("https://h/mcp#f").unwrap_err(),
            EndpointUrlError::FragmentNotAllowed
        );
        assert_eq!(
            McpEndpointUrl::parse("https://h/a/../mcp").unwrap_err(),
            EndpointUrlError::PathEscapes
        );
    }

    #[test]
    fn a_host_with_no_path_is_refused() {
        // MCP streamable HTTP posts to one endpoint path; a bare host would
        // silently mean `/`, which is a different request.
        assert_eq!(
            McpEndpointUrl::parse("https://sandbox.internal").unwrap_err(),
            EndpointUrlError::MissingHost
        );
    }

    #[test]
    fn an_ipv6_literal_and_an_invalid_port_are_handled() {
        assert_eq!(
            McpEndpointUrl::parse("http://[fe80::1]:9443/mcp")
                .unwrap()
                .endpoint_scope(),
            "[fe80::1]:9443"
        );
        assert!(matches!(
            McpEndpointUrl::parse("https://h:abc/mcp"),
            Err(EndpointUrlError::InvalidPort(_))
        ));
        assert!(matches!(
            McpEndpointUrl::parse("https://h:0/mcp"),
            Err(EndpointUrlError::InvalidPort(_))
        ));
    }

    #[test]
    fn the_emitted_scope_survives_the_policy_gate_hygiene_rules() {
        // Self-invalidation: if either module tightens its rules, this fails
        // rather than every endpoint being refused at the last moment.
        let scope = McpEndpointUrl::parse("https://[fe80::1]:9443/mcp")
            .unwrap()
            .endpoint_scope();
        assert!(!scope.is_empty());
        assert!(!scope.contains('@'));
        assert!(!scope.contains('/'));
        assert!(!scope.contains("://"));
        assert!(!scope.chars().any(char::is_whitespace));
        assert!(scope.len() <= sandtree_policy::acquire::MAX_ENDPOINT_SCOPE_LEN);
    }
}
