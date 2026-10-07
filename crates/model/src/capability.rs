//! Capability model (DD-PLG §3, FR-051, NFR-S02).
//!
//! Capabilities are deny-by-default. A plugin declares its *maximum* in its
//! manifest; the actual grant the host enforces is a subset, scoped by
//! namespace and resource.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

/// Capability namespaces (DD-PLG §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityNamespace {
    /// `discover` / `inspect` / `start` / `stop` / `destroy`.
    Resource,
    /// `endpoint.read` / `container.mutate` / `image.pull`.
    Docker,
    /// `read` / `write` / `remove` on `stfs://` roots.
    Vfs,
    /// `spawn` / `attach`.
    Exec,
    /// `connect:<host/port scope>`.
    Net,
    /// `read:<key namespace>`.
    Secret,
    /// `observe:<domain>` — Observation Plane specific (FR-070, NFR-S02).
    Observation,
}

impl CapabilityNamespace {
    /// Wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            CapabilityNamespace::Resource => "resource",
            CapabilityNamespace::Docker => "docker",
            CapabilityNamespace::Vfs => "vfs",
            CapabilityNamespace::Exec => "exec",
            CapabilityNamespace::Net => "net",
            CapabilityNamespace::Secret => "secret",
            CapabilityNamespace::Observation => "observation",
        }
    }

    /// Parse a namespace string.
    pub fn from_wire(s: &str) -> Option<Self> {
        Some(match s {
            "resource" => CapabilityNamespace::Resource,
            "docker" => CapabilityNamespace::Docker,
            "vfs" => CapabilityNamespace::Vfs,
            "exec" => CapabilityNamespace::Exec,
            "net" => CapabilityNamespace::Net,
            "secret" => CapabilityNamespace::Secret,
            "observation" => CapabilityNamespace::Observation,
            _ => return None,
        })
    }
}

/// A single capability, optionally scoped.
///
/// `docker:container.mutate`, `net:connect:10.0.0.0/8:443`,
/// `vfs:read:stfs://res-…/`.
///
/// The scope is always the part after the first `:` inside the namespace. A
/// namespace without a scope (`vfs:read`) is *global* and therefore requires an
/// explicit grant — never implied by a scoped grant.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Capability {
    namespace: CapabilityNamespace,
    verb: String,
    scope: Option<String>,
}

impl Capability {
    /// Build a capability with an optional scope.
    pub fn new(
        namespace: CapabilityNamespace,
        verb: impl Into<String>,
        scope: Option<String>,
    ) -> Self {
        Self {
            namespace,
            verb: verb.into(),
            scope,
        }
    }

    /// Build an unscoped capability.
    pub fn global(namespace: CapabilityNamespace, verb: impl Into<String>) -> Self {
        Self::new(namespace, verb, None)
    }

    /// Parse the `namespace[:verb][:scope]` capability form.
    ///
    /// Scopes may themselves contain `:` (e.g. `connect:host:443`), so only the
    /// first two separators are structural.
    pub fn parse(raw: &str) -> Result<Self, CapabilityParseError> {
        let mut it = raw.splitn(3, ':');
        let ns = it
            .next()
            .and_then(CapabilityNamespace::from_wire)
            .ok_or_else(|| CapabilityParseError::UnknownNamespace(raw.to_string()))?;
        let verb = it
            .next()
            .filter(|v| !v.is_empty())
            .ok_or_else(|| CapabilityParseError::MissingVerb(raw.to_string()))?;
        let scope = it.next().filter(|s| !s.is_empty()).map(str::to_string);
        Ok(Self {
            namespace: ns,
            verb: verb.to_string(),
            scope,
        })
    }

    /// Namespace part.
    pub fn namespace(&self) -> CapabilityNamespace {
        self.namespace
    }

    /// Verb part.
    pub fn verb(&self) -> &str {
        &self.verb
    }

    /// Scope part, if any.
    pub fn scope(&self) -> Option<&str> {
        self.scope.as_deref()
    }

    /// True when this capability authorizes `requested`.
    ///
    /// Grant matching rules:
    /// 1. namespace and verb must be equal;
    /// 2. a scoped grant only authorizes scopes that start with the granted
    ///    prefix on a path-component boundary, so `stfs://r/workspace` does not
    ///    authorize `stfs://r/workspaces-private`;
    /// 3. an unscoped grant authorizes any scope in its namespace.
    pub fn authorizes(&self, requested: &Capability) -> bool {
        if self.namespace != requested.namespace || self.verb != requested.verb {
            return false;
        }
        match (&self.scope, requested.scope.as_deref()) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(granted), Some(want)) => scope_covers(granted, want),
        }
    }
}

fn scope_covers(granted: &str, want: &str) -> bool {
    if granted == want {
        return true;
    }
    if granted.ends_with(':') {
        return want.starts_with(granted);
    }
    if let Some(prefix) = granted.strip_suffix('/') {
        return want.starts_with(prefix);
    }
    // Host/port and other dotted scopes: allow prefix match on a separator
    // boundary so `10.0.0.0/8` does not silently widen.
    want.strip_prefix(granted)
        .map(|rest| rest.starts_with(['/', ':', '.']))
        .unwrap_or(false)
}

/// Capability parse failure.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CapabilityParseError {
    /// Namespace token is not one of the seven known namespaces.
    #[error("unknown capability namespace in {0:?}")]
    UnknownNamespace(String),
    /// No verb after the namespace.
    #[error("capability missing verb in {0:?}")]
    MissingVerb(String),
}

/// An immutable, ordered set of capabilities.
///
/// Ordering gives deterministic grant comparison and deterministic IPC output,
/// which keeps hash-based tests and golden files stable.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CapabilitySet(BTreeSet<Capability>);

impl CapabilitySet {
    /// The empty set — the default grant is always empty (NFR-S02).
    pub fn empty() -> Self {
        Self(BTreeSet::new())
    }

    /// Build from an iterator.
    pub fn from_iter_caps<I: IntoIterator<Item = Capability>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }

    /// Parse from wire strings.
    pub fn parse_all<'a, I: IntoIterator<Item = &'a str>>(
        iter: I,
    ) -> Result<Self, CapabilityParseError> {
        iter.into_iter()
            .map(Capability::parse)
            .collect::<Result<BTreeSet<_>, _>>()
            .map(CapabilitySet)
    }

    /// Insert one capability.
    pub fn insert(&mut self, cap: Capability) {
        self.0.insert(cap);
    }

    /// Number of capabilities.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True when no capability is granted.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Exact membership test. Use [`CapabilitySet::allows`] for authorization.
    pub fn contains(&self, cap: &Capability) -> bool {
        self.0.contains(cap)
    }

    /// Whether this set authorizes a requested capability.
    pub fn allows(&self, requested: &Capability) -> bool {
        self.0.iter().any(|g| g.authorizes(requested))
    }

    /// Iterate in deterministic order.
    pub fn iter(&self) -> impl Iterator<Item = &Capability> {
        self.0.iter()
    }

    /// Union of two sets (used when a grant is widened).
    pub fn union(&self, other: &CapabilitySet) -> CapabilitySet {
        let mut out = self.clone();
        for cap in other.iter() {
            out.insert(cap.clone());
        }
        out
    }

    /// Intersection of two sets (used when computing actual = declared ∩ granted).
    pub fn intersect(&self, other: &CapabilitySet) -> CapabilitySet {
        CapabilitySet(
            self.0
                .intersection(&other.0)
                .cloned()
                .collect::<BTreeSet<_>>(),
        )
    }

    /// Wire strings, sorted.
    pub fn to_wire_vec(&self) -> Vec<String> {
        self.0.iter().map(|c| c.to_string()).collect()
    }
}

impl std::fmt::Display for Capability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.namespace.as_str())?;
        f.write_str(":")?;
        f.write_str(&self.verb)?;
        if let Some(scope) = &self.scope {
            f.write_str(":")?;
            f.write_str(scope)?;
        }
        Ok(())
    }
}

impl TryFrom<String> for Capability {
    type Error = CapabilityParseError;
    fn try_from(raw: String) -> Result<Self, Self::Error> {
        Capability::parse(&raw)
    }
}

impl From<Capability> for String {
    fn from(c: Capability) -> Self {
        c.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cap(s: &str) -> Capability {
        Capability::parse(s).unwrap()
    }

    #[test]
    fn empty_set_denies_everything() {
        let set = CapabilitySet::empty();
        assert!(set.is_empty());
        assert!(!set.allows(&cap("vfs:read")));
        assert!(!set.allows(&cap("exec:spawn")));
    }

    #[test]
    fn parse_all_namespaces() {
        for s in [
            "resource:discover",
            "docker:endpoint.read",
            "vfs:read",
            "exec:spawn",
            "net:connect:host:443",
            "secret:read:docker",
            "observation:observe:process",
        ] {
            assert!(Capability::parse(s).is_ok(), "{s} should parse");
        }
    }

    #[test]
    fn unknown_namespace_is_rejected() {
        assert!(Capability::parse("filesystem:read").is_err());
        assert!(Capability::parse("vfs").is_err());
    }

    #[test]
    fn scope_does_not_cross_component_boundary() {
        let grant = cap("vfs:read:stfs://res-a/workspace");
        assert!(grant.authorizes(&cap("vfs:read:stfs://res-a/workspace/src")));
        assert!(!grant.authorizes(&cap("vfs:read:stfs://res-a/workspaces-private")));
    }

    #[test]
    fn unscoped_grant_covers_any_scope() {
        let grant = cap("vfs:read");
        assert!(grant.authorizes(&cap("vfs:read:anything")));
    }

    #[test]
    fn scoped_grant_never_covers_unscoped_request() {
        let grant = cap("net:connect:example.internal:443");
        assert!(!grant.authorizes(&cap("net:connect")));
    }

    #[test]
    fn set_allows_uses_any_grant() {
        let set =
            CapabilitySet::from_iter_caps([cap("resource:discover"), cap("vfs:read:stfs://res-a")]);
        assert!(set.allows(&cap("vfs:read:stfs://res-a/x")));
        assert!(!set.allows(&cap("vfs:write:stfs://res-a/x")));
        assert!(!set.allows(&cap("exec:spawn")));
    }

    #[test]
    fn intersection_computes_actual_grant() {
        let declared = CapabilitySet::from_iter_caps([
            cap("resource:discover"),
            cap("resource:destroy"),
            cap("vfs:read:stfs://res-a"),
        ]);
        let granted =
            CapabilitySet::from_iter_caps([cap("resource:discover"), cap("vfs:read:stfs://res-b")]);
        let actual = declared.intersect(&granted);
        assert!(actual.allows(&cap("resource:discover")));
        assert!(!actual.allows(&cap("resource:destroy")));
        assert!(!actual.allows(&cap("vfs:read:stfs://res-a")));
    }

    #[test]
    fn wire_form_is_sorted_and_round_trips() {
        let set = CapabilitySet::from_iter_caps([
            cap("vfs:write"),
            cap("resource:discover"),
            cap("vfs:read"),
        ]);
        let wire = set.to_wire_vec();
        assert_eq!(wire, vec!["resource:discover", "vfs:read", "vfs:write"]);
        let json = serde_json::to_string(&set).unwrap();
        assert_eq!(serde_json::from_str::<CapabilitySet>(&json).unwrap(), set);
    }
}
