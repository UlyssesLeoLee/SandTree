//! Secret redaction (NFR-S03, NFR-S06, DD-SECOPS §6, §9).
//!
//! Two independent layers, because either one alone leaks:
//!
//! * **Key-based** — any JSON object key whose name looks secret has its value
//!   replaced, no matter how deeply nested.
//! * **Value-shaped** — free text (log lines, provider error strings) is scanned
//!   for credential *shapes*: bearer headers, `key=value` secrets, URL userinfo
//!   and PEM private keys.
//!
//! Both are bounded: a deeply nested or very wide document is rejected instead of
//! being recursed into (NFR-S08).

use serde_json::{Map, Value as Json};

/// Key fragments that mark a value as secret (case-insensitive substring match).
pub const SECRET_KEY_TOKENS: &[&str] = &[
    "token",
    "password",
    "passwd",
    "secret",
    "apikey",
    "api_key",
    "api-key",
    "authorization",
    "auth",
    "credential",
    "private_key",
    "privatekey",
    "private-key",
    "cookie",
    "session",
    "passphrase",
    "client_secret",
];

/// Replacement written in place of a secret.
pub const REDACTED: &str = "[REDACTED]";

/// Maximum nesting depth accepted while redacting.
pub const MAX_DEPTH: usize = 64;
/// Maximum number of nodes visited while redacting.
pub const MAX_NODES: usize = 100_000;

/// Bounded secret redactor.
#[derive(Debug, Clone, Copy, Default)]
pub struct Redactor;

impl Redactor {
    /// Default redactor.
    pub fn new() -> Self {
        Self
    }

    /// Whether a key name marks its value as secret.
    ///
    /// Matching is case-insensitive and substring-based so that
    /// `DockerPassword`, `refresh_token` and `X-Api-Key` are all caught.
    pub fn is_secret_key(key: &str) -> bool {
        let lower = key.to_ascii_lowercase();
        SECRET_KEY_TOKENS.iter().any(|t| lower.contains(t))
    }

    /// Redact a JSON document, recursively.
    ///
    /// Returns an error when the document exceeds the depth or node budget, so
    /// a JSON bomb cannot turn logging into a denial of service.
    pub fn redact_value(&self, v: &Json) -> Result<Json, RedactError> {
        let mut budget = MAX_NODES;
        self.walk(v, 0, &mut budget)
    }

    fn walk(&self, v: &Json, depth: usize, budget: &mut usize) -> Result<Json, RedactError> {
        if depth > MAX_DEPTH {
            return Err(RedactError::TooDeep { depth });
        }
        *budget = budget.saturating_sub(1);
        if *budget == 0 {
            return Err(RedactError::TooManyNodes);
        }
        Ok(match v {
            Json::Object(map) => {
                let mut out = Map::with_capacity(map.len());
                for (k, val) in map {
                    if Self::is_secret_key(k) {
                        out.insert(k.clone(), Json::String(REDACTED.to_string()));
                    } else {
                        out.insert(k.clone(), self.walk(val, depth + 1, budget)?);
                    }
                }
                Json::Object(out)
            }
            Json::Array(items) => {
                let mut out = Vec::with_capacity(items.len());
                for it in items {
                    out.push(self.walk(it, depth + 1, budget)?);
                }
                Json::Array(out)
            }
            Json::String(s) => Json::String(self.redact_text(s)),
            other => other.clone(),
        })
    }

    /// Redact credential shapes inside free text.
    ///
    /// Applied to log messages, provider error detail and any string that may
    /// carry a token. Deliberately conservative: false positives only cost
    /// diagnostics clarity, false negatives leak credentials.
    pub fn redact_text(&self, s: &str) -> String {
        let mut out = s.to_string();
        out = replace_bearer(&out);
        out = redact_key_value(&out);
        out = redact_url_userinfo(&out);
        out = redact_pem(&out);
        out
    }
}

/// Redaction failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RedactError {
    /// Document nested deeper than [`MAX_DEPTH`].
    #[error("json nesting depth {depth} exceeds the redaction limit")]
    TooDeep {
        /// Observed depth.
        depth: usize,
    },
    /// Document contained more nodes than [`MAX_NODES`].
    #[error("json node count exceeds the redaction limit")]
    TooManyNodes,
}

fn replace_bearer(s: &str) -> String {
    let lower = s.to_ascii_lowercase();
    let Some(pos) = lower.find("bearer ") else {
        return s.to_string();
    };
    let start = pos + "bearer ".len();
    let end = s[start..]
        .find(|c: char| c.is_whitespace() || c == '"' || c == '\'')
        .map(|i| start + i)
        .unwrap_or(s.len());
    format!("{}{}{}", &s[..start], REDACTED, &s[end..])
}

/// Redact `password=…`, `token: …`, `api_key=…` style assignments.
fn redact_key_value(s: &str) -> String {
    const KEYS: &[&str] = &[
        "password",
        "passwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "authorization",
    ];
    let mut out = String::with_capacity(s.len());
    let lower = s.to_ascii_lowercase();
    let mut i = 0usize;
    while i < s.len() {
        let rest = &lower[i..];
        let mut found: Option<usize> = None;
        for k in KEYS {
            if !rest.starts_with(k) {
                continue;
            }
            let mut j = i + k.len();
            // Allow a closing quote between key and separator (JSON member).
            if j < s.len() && s.as_bytes()[j] == b'"' {
                j += 1;
            }
            while j < s.len() && s.as_bytes()[j] == b' ' {
                j += 1;
            }
            if j < s.len() && (s.as_bytes()[j] == b'=' || s.as_bytes()[j] == b':') {
                found = Some(j);
                break;
            }
        }
        let Some(mut j) = found else {
            let ch = next_char(s, i);
            out.push_str(&ch);
            i += ch.len();
            continue;
        };

        // Copy the key and its separator verbatim, then skip the separators.
        out.push_str(&s[i..j]);
        while j < s.len() && matches!(s.as_bytes()[j], b' ' | b'=' | b':') {
            j += 1;
        }
        // A JSON member looks like `"token":"value"`: after the key there is a
        // closing quote before the separator, so skip it before looking for `=`.
        if j < s.len() && s.as_bytes()[j] == b'"' {
            j += 1;
            while j < s.len() && matches!(s.as_bytes()[j], b' ' | b'=' | b':') {
                j += 1;
            }
        }
        let value_start = j;

        if j < s.len() && (s.as_bytes()[j] == b'"' || s.as_bytes()[j] == b'\'') {
            let quote = s.as_bytes()[j] as char;
            let quoted_start = j + 1;
            let rel_end = s[quoted_start..]
                .find(quote)
                .unwrap_or(s.len() - quoted_start);
            let value_end = quoted_start + rel_end;
            out.push(quote);
            out.push_str(REDACTED);
            out.push(quote);
            i = (value_end + 1).min(s.len());
        } else {
            let rel_end = s[value_start..]
                .find(|c: char| c.is_whitespace() || matches!(c, ',' | ';' | ')' | '}'))
                .unwrap_or(s.len() - value_start);
            let value_end = value_start + rel_end;
            out.push_str(REDACTED);
            i = value_end;
        }
    }
    out
}

fn next_char(s: &str, i: usize) -> String {
    s[i..].chars().next().map(String::from).unwrap_or_default()
}

/// Redact `scheme://user:password@host` userinfo.
fn redact_url_userinfo(s: &str) -> String {
    let Some(scheme_end) = s.find("://") else {
        return s.to_string();
    };
    let after = scheme_end + 3;
    let Some(at_rel) = s[after..].find('@') else {
        return s.to_string();
    };
    let at = after + at_rel;
    // Only treat it as userinfo when the authority starts before the '@'.
    let userinfo = &s[after..at];
    if userinfo.is_empty() || !userinfo.contains(':') {
        return s.to_string();
    }
    format!("{}[REDACTED]{}", &s[..after], &s[at..])
}

/// Mask everything between a PEM header and footer.
fn redact_pem(s: &str) -> String {
    const BEGIN: &str = "-----BEGIN";
    if !s.contains(BEGIN) {
        return s.to_string();
    }
    let Some(start) = s.find(BEGIN) else {
        return s.to_string();
    };
    let end = s[start..]
        .find("-----END")
        .map(|i| start + i)
        .map(|i| s[i..].find("-----").map(|k| i + k + 5).unwrap_or(s.len()))
        .unwrap_or(s.len());
    format!("{}{}{}", &s[..start], REDACTED, &s[end..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_key_detection_is_broad() {
        for k in [
            "token",
            "refresh_token",
            "DockerPassword",
            "X-Api-Key",
            "api_key",
            "client_secret",
            "private_key",
            "Authorization",
            "COOKIE",
            "SESSION_ID",
        ] {
            assert!(Redactor::is_secret_key(k), "{k} must be treated as secret");
        }
        for k in ["username", "path", "image", "container_id", "count"] {
            assert!(!Redactor::is_secret_key(k), "{k} must not be redacted");
        }
    }

    #[test]
    fn nested_secret_values_are_replaced_not_leaked() {
        let r = Redactor::new();
        let doc = serde_json::json!({
            "name": "web",
            "env": { "DOCKER_PASSWORD": "hunter2", "PORT": "8080" },
            "meta": { "token": "abc123def", "user": "bob" }
        });
        let out = r.redact_value(&doc).unwrap();
        let text = out.to_string();
        assert!(!text.contains("hunter2"), "{text}");
        assert!(!text.contains("abc123def"), "{text}");
        assert!(text.contains("bob"), "non-secret fields survive: {text}");
        assert_eq!(out["env"]["PORT"], "8080");
    }

    #[test]
    fn arrays_are_walked() {
        let r = Redactor::new();
        let doc = serde_json::json!([{"token": "s3cr3t"}, {"safe": "ok"}]);
        let out = r.redact_value(&doc).unwrap();
        assert!(!out.to_string().contains("s3cr3t"));
    }

    #[test]
    fn deep_nesting_is_rejected_instead_of_overflowing() {
        let r = Redactor::new();
        let mut v = Json::String("leaf".into());
        for _ in 0..(MAX_DEPTH + 10) {
            v = serde_json::json!({ "n": v });
        }
        assert!(matches!(
            r.redact_value(&v),
            Err(RedactError::TooDeep { .. })
        ));
    }

    #[test]
    fn wide_documents_are_bounded() {
        let r = Redactor::new();
        let big: Vec<Json> = (0..(MAX_NODES + 10))
            .map(|i| serde_json::json!({ "i": i }))
            .collect();
        assert_eq!(
            r.redact_value(&Json::Array(big)),
            Err(RedactError::TooManyNodes)
        );
    }

    #[test]
    fn bearer_headers_are_masked() {
        let r = Redactor::new();
        let out = r.redact_text("Authorization: Bearer eyJhbGciOi.J9.sig end");
        assert!(!out.contains("eyJhbGciOi"), "{out}");
        assert!(out.contains(REDACTED));
        assert!(out.ends_with(" end"), "{out}");
    }

    #[test]
    fn url_userinfo_is_masked() {
        let r = Redactor::new();
        let out = r.redact_text("connecting to tcp://admin:sup3rsecret@registry.local:2376");
        assert!(!out.contains("sup3rsecret"), "{out}");
        assert!(
            out.contains("registry.local:2376"),
            "host must stay readable"
        );
    }

    #[test]
    fn key_value_secrets_are_masked() {
        let r = Redactor::new();
        for input in [
            "login password=hunter2 ok",
            "password: hunter2",
            "{\"token\":\"abc123\"}",
            "api_key=sk-live-1234 trailing",
        ] {
            let out = r.redact_text(input);
            assert!(
                !out.contains("hunter2")
                    && !out.contains("abc123")
                    && !out.contains("sk-live-1234"),
                "{input} -> {out}"
            );
        }
    }

    #[test]
    fn pem_private_keys_are_removed() {
        let r = Redactor::new();
        let input =
            "before\n-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----\nafter";
        let out = r.redact_text(input);
        assert!(!out.contains("MIIabc"), "{out}");
        assert!(out.contains(REDACTED));
    }

    #[test]
    fn harmless_text_is_untouched() {
        let r = Redactor::new();
        let input = "container web-1 exited with code 0 after 12s";
        assert_eq!(r.redact_text(input), input);
    }
}
