//! Validation for the git remote URL a sandbox publishes.
//!
//! The URL is **attacker-influenced input**: it comes out of the sandbox we are
//! trying to observe. Everything a hostile sandbox could gain by shaping it is
//! closed here, before any socket is opened.
//!
//! # What is refused, and why
//!
//! | refused | reason |
//! | --- | --- |
//! | userinfo (`https://u:p@host/repo`) | the URL would carry a credential into a capability scope, an audit record and a log line (same reasoning as ADR-013) |
//! | `file://`, `git://`, `ssh://`, `ext::`, `--upload-pack=` | schemes that reach outside the endpoint the capability scope names; `ext::` and `--upload-pack=` are remote-command execution by another name |
//! | `..` path segments | the effective path could leave the scope the operator granted |
//! | a non-`refs/` ref filter in the query | the advertisement path must not become a generic fetch primitive |
//!
//! # Parse, never guess
//!
//! Every failure is a named reason (RD §9). Nothing here falls back to a
//! "best effort" interpretation of a malformed URL, because a guessed host is
//! a request to a host nobody authorized.

/// Schemes this provider will speak.
///
/// `http`/`https` only: both are covered by the `net:connect:<host:port>`
/// capability, which is the only thing that makes a network fetch admissible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteScheme {
    /// Plain HTTP.
    Http,
    /// HTTP over TLS.
    Https,
}

impl RemoteScheme {
    /// Scheme token as it appears in a URL.
    pub fn as_str(self) -> &'static str {
        match self {
            RemoteScheme::Http => "http",
            RemoteScheme::Https => "https",
        }
    }

    /// Default port when the URL omits one.
    pub fn default_port(self) -> u16 {
        match self {
            RemoteScheme::Http => 80,
            RemoteScheme::Https => 443,
        }
    }

    /// Parse a scheme token.
    pub fn from_wire(s: &str) -> Option<Self> {
        match s {
            "http" => Some(RemoteScheme::Http),
            "https" => Some(RemoteScheme::Https),
            _ => None,
        }
    }
}

/// Why a remote URL was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RemoteUrlError {
    /// The URL is not absolute, or has no `scheme://` prefix at all.
    #[error("remote URL must be absolute and start with a scheme")]
    NotAbsolute,
    /// A scheme outside the allow-list. The offending token is named so the
    /// operator sees what was attempted.
    #[error("scheme {0:?} is not one of http, https")]
    UnsupportedScheme(String),
    /// The authority carried userinfo.
    #[error("remote URL must not embed credentials")]
    CredentialsInUrl,
    /// The authority had no host.
    #[error("remote URL has no host")]
    MissingHost,
    /// The port was not a number in range.
    #[error("port {0:?} is not valid")]
    InvalidPort(String),
    /// The path escaped its root via `..`.
    #[error("remote path must not contain a .. segment")]
    PathEscapes,
    /// The path contained a control character.
    #[error("remote path contains a control character")]
    PathControlCharacter,
    /// The path contained whitespace.
    ///
    /// A space does not survive URL construction intact — it turns one request
    /// into two tokens, and `--upload-pack=…` smuggling rides on exactly that.
    /// Refusing it here names the cause instead of leaving a downstream parser
    /// to fail on something unrelated.
    #[error("remote path contains whitespace")]
    PathWhitespace,
    /// A query string was supplied; this provider only ever appends its own.
    #[error("remote URL must not carry a query string")]
    QueryNotAllowed,
    /// A fragment was supplied.
    #[error("remote URL must not carry a fragment")]
    FragmentNotAllowed,
}

/// A validated git remote URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitRemoteUrl {
    scheme: RemoteScheme,
    host: String,
    port: u16,
    path: String,
}

impl GitRemoteUrl {
    /// Validate and split a remote URL.
    pub fn parse(raw: &str) -> Result<Self, RemoteUrlError> {
        let raw = raw.trim();
        let Some((scheme_tok, rest)) = raw.split_once("://") else {
            return Err(RemoteUrlError::NotAbsolute);
        };
        let scheme = RemoteScheme::from_wire(scheme_tok)
            .ok_or_else(|| RemoteUrlError::UnsupportedScheme(scheme_tok.to_string()))?;

        // Split authority from path before looking for userinfo: the path is
        // allowed to contain `@`, only the authority is not.
        let (authority, path_and_rest) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, ""),
        };
        if authority.contains('@') {
            return Err(RemoteUrlError::CredentialsInUrl);
        }
        if authority.contains('?') || authority.contains('#') {
            return Err(RemoteUrlError::QueryNotAllowed);
        }
        if authority.is_empty() {
            return Err(RemoteUrlError::MissingHost);
        }

        let (host, port) = split_host_port(authority, scheme.default_port())?;

        // `path_and_rest` still has to be split off any query/fragment.
        let path = match path_and_rest.find(['?', '#']) {
            Some(i) => &path_and_rest[..i],
            None => path_and_rest,
        };
        if path_and_rest.contains('?') {
            return Err(RemoteUrlError::QueryNotAllowed);
        }
        if path_and_rest.contains('#') {
            return Err(RemoteUrlError::FragmentNotAllowed);
        }
        if path.chars().any(|c| c.is_control()) {
            return Err(RemoteUrlError::PathControlCharacter);
        }
        if path.chars().any(char::is_whitespace) {
            return Err(RemoteUrlError::PathWhitespace);
        }
        for segment in path.split('/') {
            if segment == ".." {
                return Err(RemoteUrlError::PathEscapes);
            }
        }
        if path.is_empty() {
            return Err(RemoteUrlError::MissingHost);
        }

        Ok(Self {
            scheme,
            host,
            port,
            path: path.to_string(),
        })
    }

    /// Scheme.
    pub fn scheme(&self) -> RemoteScheme {
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

    /// Repository path, always starting with `/`.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// `host:port`, the exact string used as the `net:connect` capability scope.
    ///
    /// The port is **always** present, even when the URL omitted it, so that
    /// `http://h/repo` and `http://h:80/repo` produce the same scope instead of
    /// one granting a scope no operator wrote down.
    pub fn endpoint_scope(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    /// The `info/refs` URL that returns the ref advertisement.
    pub fn info_refs_url(&self) -> String {
        format!(
            "{}://{}:{}{}/info/refs?service=git-upload-pack",
            self.scheme.as_str(),
            self.host,
            self.port,
            self.path
        )
    }
}

fn split_host_port(authority: &str, default_port: u16) -> Result<(String, u16), RemoteUrlError> {
    // An IPv6 literal keeps its brackets, so the port separator is the last
    // colon that is not inside them.
    if let Some(stripped) = authority.strip_prefix('[') {
        let Some(close) = stripped.find(']') else {
            return Err(RemoteUrlError::MissingHost);
        };
        let host = format!("[{}]", &stripped[..close]);
        let after = &stripped[close + 1..];
        if after.is_empty() {
            return Ok((host, default_port));
        }
        let Some(port_tok) = after.strip_prefix(':') else {
            return Err(RemoteUrlError::InvalidPort(after.to_string()));
        };
        return Ok((host, parse_port(port_tok)?));
    }

    match authority.rsplit_once(':') {
        Some((host, port_tok)) if !host.is_empty() => Ok((host.to_string(), parse_port(port_tok)?)),
        Some((_, _)) => Err(RemoteUrlError::MissingHost),
        None => Ok((authority.to_string(), default_port)),
    }
}

fn parse_port(tok: &str) -> Result<u16, RemoteUrlError> {
    tok.parse::<u16>()
        .ok()
        .filter(|p| *p > 0)
        .ok_or_else(|| RemoteUrlError::InvalidPort(tok.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plain_https_remote_parses_and_yields_its_capability_scope() {
        let u = GitRemoteUrl::parse("https://sandbox.internal/workspace.git").unwrap();
        assert_eq!(u.scheme(), RemoteScheme::Https);
        assert_eq!(u.host(), "sandbox.internal");
        assert_eq!(u.port(), 443);
        assert_eq!(u.path(), "/workspace.git");
        // The scope the policy gate checks against.
        assert_eq!(u.endpoint_scope(), "sandbox.internal:443");
        assert_eq!(
            u.info_refs_url(),
            "https://sandbox.internal:443/workspace.git/info/refs?service=git-upload-pack"
        );
    }

    #[test]
    fn an_omitted_port_still_yields_an_explicit_scope() {
        // Break by leaving the default port out of the scope, and
        // `http://h/repo` stops matching the `net:connect:h:80` grant an
        // operator actually wrote.
        let u = GitRemoteUrl::parse("http://10.0.0.5/repo.git").unwrap();
        assert_eq!(u.endpoint_scope(), "10.0.0.5:80");
    }

    #[test]
    fn an_explicit_port_is_preserved() {
        assert_eq!(
            GitRemoteUrl::parse("http://10.0.0.5:9418/repo.git")
                .unwrap()
                .endpoint_scope(),
            "10.0.0.5:9418"
        );
    }

    #[test]
    fn credentials_in_the_url_are_refused() {
        // Break by accepting userinfo, and the credential reaches a capability
        // scope, an audit record and a log line (ADR-013).
        for raw in [
            "https://admin:hunter2@sandbox.internal/repo.git",
            "https://admin@sandbox.internal/repo.git",
            "http://:pw@10.0.0.5/repo.git",
        ] {
            assert_eq!(
                GitRemoteUrl::parse(raw).unwrap_err(),
                RemoteUrlError::CredentialsInUrl,
                "{raw} must be refused"
            );
        }
    }

    #[test]
    fn only_http_and_https_are_accepted() {
        // Each refused scheme is a way to reach outside the endpoint the
        // capability scope names.
        for raw in [
            "file:///etc/passwd",
            "git://10.0.0.5/repo.git",
            "ssh://10.0.0.5/repo.git",
            "ext::sh -c whoami",
            "/plain/path",
            "repo.git",
        ] {
            assert!(
                matches!(
                    GitRemoteUrl::parse(raw),
                    Err(RemoteUrlError::NotAbsolute) | Err(RemoteUrlError::UnsupportedScheme(_))
                ),
                "{raw} must be refused"
            );
        }
    }

    #[test]
    fn a_remote_command_smuggled_after_the_path_is_refused() {
        // `git clone` treats everything after the path as an option, so a path
        // carrying `--upload-pack=` would be remote command execution wearing a
        // URL. The space is what makes it smuggle, and the space is refused.
        assert_eq!(
            GitRemoteUrl::parse("https://10.0.0.5/repo.git --upload-pack=touch /tmp/pwn")
                .unwrap_err(),
            RemoteUrlError::PathWhitespace
        );
        assert_eq!(
            GitRemoteUrl::parse("https://10.0.0.5/repo.git\u{0}--upload-pack=x").unwrap_err(),
            RemoteUrlError::PathControlCharacter
        );
    }

    #[test]
    fn a_traversal_segment_is_refused() {
        // Break by normalizing instead of refusing, and the effective path can
        // leave the repository the operator granted.
        for raw in [
            "https://h/other/../repo.git",
            "https://h/../../etc/passwd",
            "https://h/repo.git/..",
        ] {
            assert_eq!(
                GitRemoteUrl::parse(raw).unwrap_err(),
                RemoteUrlError::PathEscapes,
                "{raw} must be refused"
            );
        }
    }

    #[test]
    fn a_query_or_fragment_is_refused() {
        // This provider appends its own `service=` query. A caller-supplied one
        // would turn `info/refs` into a different request than the one the
        // capability was granted for.
        assert_eq!(
            GitRemoteUrl::parse("https://h/r.git?x=1").unwrap_err(),
            RemoteUrlError::QueryNotAllowed
        );
        assert_eq!(
            GitRemoteUrl::parse("https://h/r.git#frag").unwrap_err(),
            RemoteUrlError::FragmentNotAllowed
        );
    }

    #[test]
    fn a_bare_host_with_no_path_is_refused() {
        assert_eq!(
            GitRemoteUrl::parse("https://sandbox.internal").unwrap_err(),
            RemoteUrlError::MissingHost
        );
        assert_eq!(
            GitRemoteUrl::parse("https:///repo.git").unwrap_err(),
            RemoteUrlError::MissingHost
        );
    }

    #[test]
    fn an_ipv6_literal_keeps_its_brackets_and_parses_the_port() {
        let u = GitRemoteUrl::parse("http://[fe80::1]:9418/repo.git").unwrap();
        assert_eq!(u.host(), "[fe80::1]");
        assert_eq!(u.port(), 9418);
        assert_eq!(u.endpoint_scope(), "[fe80::1]:9418");

        let no_port = GitRemoteUrl::parse("http://[fe80::1]/repo.git").unwrap();
        assert_eq!(no_port.endpoint_scope(), "[fe80::1]:80");
    }

    #[test]
    fn an_invalid_port_is_refused_rather_than_defaulted() {
        // Break by falling back to the default port, and a typo'd port silently
        // turns into a request to a different endpoint.
        for raw in [
            "https://h:0/r.git",
            "https://h:99999/r.git",
            "https://h:abc/r.git",
        ] {
            assert!(matches!(
                GitRemoteUrl::parse(raw),
                Err(RemoteUrlError::InvalidPort(_))
            ));
        }
    }

    #[test]
    fn a_control_character_in_the_path_is_refused() {
        assert_eq!(
            GitRemoteUrl::parse("https://h/repo\r\nX-Injected: 1.git").unwrap_err(),
            RemoteUrlError::PathControlCharacter
        );
    }

    #[test]
    fn whitespace_in_the_path_is_refused() {
        // A path with a space lets `--upload-pack=…` ride along as what looks
        // like a second token. Break by allowing spaces and this becomes a
        // remote-command smuggling primitive again.
        assert_eq!(
            GitRemoteUrl::parse("https://10.0.0.5/my repo.git").unwrap_err(),
            RemoteUrlError::PathWhitespace
        );
    }

    #[test]
    fn the_endpoint_scope_survives_the_policy_gate_hygiene_rules() {
        // The scope this module emits must itself pass `acquire`'s scope check,
        // otherwise every remote URL would be refused at the last moment.
        // Self-invalidation: if either module tightens its rules, this fails.
        let u = GitRemoteUrl::parse("https://[fe80::1]:9418/repo.git").unwrap();
        let scope = u.endpoint_scope();
        assert!(!scope.is_empty());
        assert!(!scope.contains('@'));
        assert!(!scope.contains('/'));
        assert!(!scope.contains("://"));
        assert!(!scope.chars().any(char::is_whitespace));
        assert!(scope.len() <= sandtree_policy::acquire::MAX_ENDPOINT_SCOPE_LEN);
    }
}
