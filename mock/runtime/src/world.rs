//! [`ScriptedWorld`] — the validated in-memory state every fake port reads from.
//!
//! A world is built once, from a [`WorldFixture`], and is then immutable apart
//! from file writes. Nothing here consults a clock, a random source or the
//! environment, and no operation mutates the resource set, so the same fixture
//! always yields the same scan (NFR-O04).
//!
//! # Load-time ordering
//!
//! Ordering is decided once, here, so a fixture author may list resources in
//! whatever order reads best and still get a byte-identical scan:
//!
//! * resources come out in **pre-order over the tree** — parents before
//!   children, siblings ordered by their derived id;
//! * relations come out ordered by `(from, kind, to)`;
//! * workspace entries live in a [`BTreeMap`], so `list` is always
//!   path-ordered.
//!
//! # The four fault modes
//!
//! | Mode | Fixture field | Entry point | Behaviour |
//! | --- | --- | --- | --- |
//! | 1. scripted operation failure | `operations[].error` | [`ScriptedWorld::invoke`] | `Err(code)` |
//! | 2. unknown resource | *(absence is the script)* | [`ScriptedWorld::node`] callers | `ST-VFS-002` |
//! | 3. mid-pagination failure | `discover_fault.fail_from_page` | [`ScriptedWorld::page`] | earlier pages delivered, then `Err` |
//! | 4. provider unavailable | `health.state = "unavailable"` | every entry point | `Err(unavailable_error)` |
//!
//! Mode 2 is a mode rather than a field because a resource that is not in the
//! fixture *is* a resource that does not exist; there is nothing to declare.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::Path;
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

use sandtree_model::capability::{Capability, CapabilityNamespace, CapabilitySet};
use sandtree_model::error::{DomainError, ErrorCode};
use sandtree_model::id::{PluginId, ResourceId};
use sandtree_model::operation::{OperationOutcome, OperationRequest, OperationState};
use sandtree_model::resource::{Relation, ResourceNode};
use sandtree_observation_model::{ContentHashState, FileMetadata};
use sandtree_sdk::manifest::PluginKind;
use sandtree_sdk::ports::{
    DiscoverBatch, ExecOutcome, ProviderDescriptor, ProviderHealth, ProviderInstance,
};
use sandtree_vfs::WorkspacePath;
use serde_json::Value as Json;

use crate::exec_provider::ScriptedExecProvider;
use crate::file_provider::ScriptedFileProvider;
use crate::fixture::{
    parse_error_code, parse_operation_kind, DiscoverFault, ExecSpec, FileSpec, FixtureError,
    OperationSpec, ResourceSpec, ScriptedError, WorldFixture, FIXTURE_SCHEMA,
};
use crate::resource_provider::ScriptedResourceProvider;

/// Version reported by [`ProviderDescriptor`] when the fixture omits one.
pub const DEFAULT_PROVIDER_VERSION: &str = "0.0.0-mock";

/// Generation number used by [`ScriptedWorld::provider_instance`].
///
/// Constant because a fake that allocated a counter here would make two runs of
/// the same regression produce different registry dumps.
pub const MOCK_GENERATION: u64 = 1;

/// Prefix of every discovery cursor this crate hands out.
pub const CURSOR_PREFIX: &str = "page:";

/// Maximum bytes captured per exec stream before truncation (DD-SW §12.3).
pub const MAX_CAPTURE_BYTES: usize = 4096;

/// Maximum symlink hops resolved for one path before the request is refused.
///
/// A cycle of symlinks would otherwise loop forever; the bound is part of the
/// contract rather than an implementation detail so a fixture can rely on it.
pub const MAX_SYMLINK_HOPS: usize = 8;

/// One entry in a scripted in-memory filesystem (FR-077).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    /// Canonical relative path; `""` is the workspace root itself.
    pub path: String,
    /// Whether the entry is a directory.
    pub is_dir: bool,
    /// Body declared in the fixture.
    ///
    /// Absent means "metadata known, body not fetched" — the lazy-content shape
    /// FR-077 requires, so a directory listing never needs it.
    pub content: Option<String>,
    /// Body installed by a [`ScriptedFileProvider::write`] call.
    ///
    /// Kept apart from `content` because `write` takes arbitrary bytes while a
    /// fixture is UTF-8 text. The two are mutually exclusive by construction:
    /// [`FileEntry::body`] prefers `written_bytes` whenever it is present, so a
    /// write can never be silently mangled by a lossy text conversion.
    pub written_bytes: Option<Vec<u8>>,
    /// Size to report when there is no body to measure.
    pub declared_size: Option<u64>,
    /// Modification time in nanoseconds since the Unix epoch.
    pub mtime_ns: Option<i128>,
    /// BLAKE3 digest, declared by the fixture and never computed.
    pub content_hash: Option<String>,
    /// Raw symlink target, stored unresolved.
    ///
    /// Raw on purpose: a target containing `..` is the scenario under test, and
    /// normalizing it at load time would delete it.
    pub symlink_target: Option<String>,
    /// Whether writes are refused for this entry and its children.
    pub read_only: bool,
}

impl FileEntry {
    /// Metadata view of this entry.
    ///
    /// Carries no content field at all, which is why FR-077 cannot be violated
    /// by accident on this path.
    pub fn metadata(&self) -> FileMetadata {
        FileMetadata {
            path: self.path.clone(),
            is_dir: self.is_dir,
            size: self.size(),
            mtime_ns: self.mtime_ns,
            hash_state: self.hash_state(),
            content_hash: self.content_hash.clone(),
        }
    }

    /// Effective size in bytes; directories are always zero.
    pub fn size(&self) -> u64 {
        if self.is_dir {
            return 0;
        }
        match self.body() {
            Some(b) => b.len() as u64,
            None => self.declared_size.unwrap_or(0),
        }
    }

    /// Hash availability.
    ///
    /// Never upgraded to [`ContentHashState::HashKnown`] from a body: hashing
    /// here would be exactly the work FR-077 forbids during enumeration.
    pub fn hash_state(&self) -> ContentHashState {
        if self.content_hash.is_some() {
            ContentHashState::HashKnown
        } else if self.is_dir || self.declared_size.is_some() || self.content.is_some() {
            ContentHashState::MetadataKnown
        } else {
            ContentHashState::UnknownHash
        }
    }

    /// Body bytes, if the fixture or a write supplied any.
    pub fn body(&self) -> Option<Cow<'_, [u8]>> {
        match &self.written_bytes {
            Some(b) => Some(Cow::Borrowed(b.as_slice())),
            None => self.content.as_deref().map(|c| Cow::Borrowed(c.as_bytes())),
        }
    }

    /// Parent path of this entry, or `None` at the workspace root.
    pub fn parent_path(&self) -> Option<&str> {
        if self.path.is_empty() {
            None
        } else {
            self.path.rsplit_once('/').map(|(p, _)| p)
        }
    }
}

/// Scripted filesystem of one resource workspace (NFR-S05).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WorkspaceFs {
    entries: BTreeMap<String, FileEntry>,
    root_subtree: String,
}

impl WorkspaceFs {
    /// Ordered entries, keyed by canonical relative path.
    pub fn entries(&self) -> &BTreeMap<String, FileEntry> {
        &self.entries
    }

    /// Subtree the VFS is allowed to serve; empty means the whole resource root.
    pub fn root_subtree(&self) -> &str {
        &self.root_subtree
    }

    /// Look up an entry by already-resolved canonical path.
    pub fn get(&self, canonical: &str) -> Option<&FileEntry> {
        self.entries.get(canonical)
    }

    /// Direct children of a directory, in path order.
    ///
    /// A root entry's [`FileEntry::parent_path`] is `None`, not `Some("")`, so
    /// the root directory is matched explicitly. Without this, listing a
    /// workspace root returns nothing at all while listing `src` works — the
    /// asymmetry that makes an empty root listing look like an empty workspace.
    pub fn children(&self, dir: &str) -> Vec<&FileEntry> {
        self.entries
            .values()
            .filter(|e| e.parent_path().unwrap_or("") == dir)
            .collect()
    }

    /// Resolve and confine a caller-supplied path (NFR-S05).
    ///
    /// Two independent checks live here, and neither replaces the other:
    ///
    /// 1. **symlink / reparse resolution** ([`WorkspaceFs::resolve`]) — the
    ///    caller's [`WorkspacePath`] is canonical but says nothing about what a
    ///    link inside the workspace points at, and a link pointing outside is
    ///    only visible after resolution;
    /// 2. **subtree confinement** ([`WorkspaceFs::require_within`]) — the
    ///    resolved location must sit inside the resource's served subtree.
    ///
    /// Every file-port entry point goes through this method, so no port can
    /// reach a path that skips either check.
    pub fn resolve_confined(&self, path: &WorkspacePath) -> Result<String, DomainError> {
        let canonical = self.resolve(path)?;
        self.require_within(&canonical)?;
        Ok(canonical)
    }

    /// Install a body at an already-resolved, already-confined path.
    ///
    /// The pre-write hash is dropped rather than recomputed: this crate never
    /// hashes, and a stale-but-present digest would be worse than none.
    pub fn install(&mut self, canonical: String, bytes: Vec<u8>) {
        match self.entries.get_mut(&canonical) {
            Some(entry) => {
                entry.is_dir = false;
                entry.content = None;
                entry.written_bytes = Some(bytes);
                entry.declared_size = None;
                entry.content_hash = None;
                entry.symlink_target = None;
            }
            None => {
                self.entries.insert(
                    canonical.clone(),
                    FileEntry {
                        path: canonical,
                        is_dir: false,
                        content: None,
                        written_bytes: Some(bytes),
                        declared_size: None,
                        // No clock anywhere in this crate: a write must not
                        // invent a timestamp, because a fake that stamped
                        // `SystemTime::now()` would make two runs of the same
                        // regression disagree on the recorded mtime.
                        mtime_ns: None,
                        content_hash: None,
                        symlink_target: None,
                        read_only: false,
                    },
                );
            }
        }
    }

    /// Follow symlinks component by component, refusing anything that leaves the
    /// workspace root.
    fn resolve(&self, path: &WorkspacePath) -> Result<String, DomainError> {
        let mut resolved: Vec<String> = Vec::new();
        let mut hops = 0usize;

        for seg in path.segments() {
            let mut pending: VecDeque<String> = VecDeque::from([seg.clone()]);
            while let Some(next) = pending.pop_front() {
                let prefix = join_segments(&resolved, &next);
                let target = self
                    .entries
                    .get(&prefix)
                    .and_then(|e| e.symlink_target.clone());
                match target {
                    // Not a link (or not there at all): place it and move on.
                    None => resolved.push(next),
                    Some(target) => {
                        hops += 1;
                        if hops > MAX_SYMLINK_HOPS {
                            return Err(DomainError::core_invalid(format!(
                                "symlink chain at {prefix:?} exceeds {MAX_SYMLINK_HOPS} hops"
                            )));
                        }
                        let expanded = fold_target(&resolved, &target)?;
                        for seg in expanded.into_iter().rev() {
                            pending.push_front(seg);
                        }
                    }
                }
            }
        }
        Ok(join_segments(&resolved, ""))
    }

    /// Refuse a canonical path outside the served subtree (NFR-S05).
    fn require_within(&self, canonical: &str) -> Result<(), DomainError> {
        if self.root_subtree.is_empty() {
            return Ok(());
        }
        let want = segments_of(&self.root_subtree);
        let got = segments_of(canonical);
        if got.len() < want.len() || got[..want.len()] != want[..] {
            return Err(DomainError::path_escape(format!(
                "{canonical:?} is outside the served subtree {:?}",
                self.root_subtree
            )));
        }
        Ok(())
    }

    /// Whether this entry, or any directory above it, is marked read-only.
    pub fn read_only_at(&self, canonical: &str) -> bool {
        let segs = segments_of(canonical);
        (0..=segs.len())
            .map(|depth| segs[..depth].join("/"))
            .filter_map(|prefix| self.entries.get(&prefix))
            .any(|e| e.read_only)
    }
}

/// One scripted command result, bound to a resource when the fixture scopes it.
#[derive(Debug, Clone, PartialEq)]
pub struct ExecRule {
    /// Resource the rule is bound to; `None` matches any resource.
    pub resource: Option<ResourceId>,
    /// Exact argv the rule matches.
    pub argv: Vec<String>,
    /// The scripted result.
    pub spec: ExecSpec,
}

impl ExecRule {
    /// Whether this rule answers `argv` on `id`.
    pub fn matches(&self, id: &ResourceId, argv: &[String]) -> bool {
        self.resource.as_ref().is_none_or(|r| r == id) && self.argv == argv
    }
}

/// A validated world. Build one with [`ScriptedWorld::load`].
#[derive(Debug)]
pub struct ScriptedWorld {
    intent: String,
    plugin_id: PluginId,
    descriptor: ProviderDescriptor,
    health: ProviderHealth,
    unavailable_error: Option<ScriptedError>,
    page_size: usize,
    resources: Vec<ResourceNode>,
    index: BTreeMap<ResourceId, usize>,
    relations: Vec<Relation>,
    discover_fault: Option<DiscoverFault>,
    operations: BTreeMap<String, OperationSpec>,
    files: BTreeMap<ResourceId, RwLock<WorkspaceFs>>,
    exec_rules: Vec<ExecRule>,
}

impl ScriptedWorld {
    /// Validate a fixture and build the world it describes.
    ///
    /// Semantic validation lives here rather than in [`WorldFixture`] because it
    /// needs cross-references: a dangling parent key, a relation naming an
    /// unknown resource, a file outside the served subtree.
    pub fn load(fixture: WorldFixture) -> Result<Self, FixtureError> {
        // FR-001: the scan is driven from the resource set, so an unrecognised
        // schema version means this code cannot say what the fixture asks for.
        if fixture.schema != FIXTURE_SCHEMA {
            return Err(FixtureError::Invalid {
                field: "schema".into(),
                reason: format!("expected schema {FIXTURE_SCHEMA}, got {}", fixture.schema),
            });
        }
        if fixture.plugin.trim().is_empty() {
            return Err(FixtureError::Invalid {
                field: "plugin".into(),
                reason: "must not be empty".into(),
            });
        }
        if fixture
            .version
            .as_deref()
            .is_some_and(|v| v.trim().is_empty())
        {
            return Err(FixtureError::Invalid {
                field: "version".into(),
                reason: "must not be blank when present".into(),
            });
        }

        let plugin_id = PluginId::derive(&[fixture.plugin.as_str()]);
        let descriptor = ProviderDescriptor {
            plugin_id: plugin_id.to_string(),
            version: fixture
                .version
                .clone()
                .unwrap_or_else(|| DEFAULT_PROVIDER_VERSION.to_string()),
            kind: fixture.kind.unwrap_or(PluginKind::Provider),
        };
        let health = fixture.health.clone().unwrap_or(ProviderHealth::Healthy);
        if let Some(err) = &fixture.unavailable_error {
            parse_error_code(&err.code)?;
        }
        if let Some(fault) = &fixture.discover_fault {
            parse_error_code(&fault.error.code)?;
        }

        // Fixture-local key -> derived identity. Everything else in the fixture
        // addresses resources by key, so this map is the single place where a
        // reference is resolved.
        let key_to_id = Self::derive_keys(&fixture)?;
        let subtrees = Self::canonicalize_subtrees(&fixture)?;

        let (resources, index) = Self::build_resources(&fixture, &plugin_id)?;
        let relations = Self::build_relations(&fixture, &key_to_id)?;
        let operations = Self::build_operations(&fixture)?;
        let files = Self::build_files(&fixture, &key_to_id, &subtrees)?;
        let exec_rules = Self::build_exec(&fixture, &key_to_id)?;

        // One page holds the whole world unless the fixture asks otherwise;
        // `max(1)` keeps the page-count arithmetic free of a zero page size.
        let page_size = fixture.page_size.unwrap_or_else(|| resources.len().max(1));

        Ok(Self {
            intent: fixture.intent,
            plugin_id,
            descriptor,
            health,
            unavailable_error: fixture.unavailable_error,
            page_size,
            resources,
            index,
            relations,
            discover_fault: fixture.discover_fault,
            operations,
            files,
            exec_rules,
        })
    }

    /// Parse JSON text and build the world it describes.
    pub fn from_json_str(raw: &str) -> Result<Self, FixtureError> {
        Self::load(WorldFixture::from_json_str(raw)?)
    }

    /// Read a fixture file and build the world it describes.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, FixtureError> {
        Self::load(WorldFixture::from_path(path)?)
    }

    /// Share one world between all three ports.
    pub fn into_shared(self) -> Arc<Self> {
        Arc::new(self)
    }

    /// The fixture's stated purpose.
    pub fn intent(&self) -> &str {
        &self.intent
    }

    /// Derived plugin identity of this world.
    pub fn plugin_id(&self) -> &PluginId {
        &self.plugin_id
    }

    /// Static provider identity.
    pub fn descriptor(&self) -> ProviderDescriptor {
        self.descriptor.clone()
    }

    /// Declared health, independent of whether any call has been made.
    pub fn health_state(&self) -> ProviderHealth {
        self.health.clone()
    }

    /// Resources in deterministic pre-order.
    pub fn resources(&self) -> &[ResourceNode] {
        &self.resources
    }

    /// Relations in deterministic `(from, kind, to)` order.
    pub fn relations(&self) -> &[Relation] {
        &self.relations
    }

    /// Resources per discovery page.
    pub fn page_size(&self) -> usize {
        self.page_size
    }

    /// Number of discovery pages this world produces.
    pub fn page_count(&self) -> usize {
        self.resources.len().div_ceil(self.page_size)
    }

    /// One resource by id.
    pub fn node(&self, id: &ResourceId) -> Option<&ResourceNode> {
        self.index.get(id).map(|i| &self.resources[*i])
    }

    /// Scripted operation results, keyed by [OperationKind::as_str].
    pub fn operations(&self) -> &BTreeMap<String, OperationSpec> {
        &self.operations
    }

    /// Scripted command rules, in fixture declaration order.
    pub fn exec_rules(&self) -> &[ExecRule] {
        &self.exec_rules
    }

    /// Guard against calls on a world whose provider is unavailable (fault 4).
    pub fn ensure_available(&self) -> Result<(), DomainError> {
        if self.health.control_is_available() {
            return Ok(());
        }
        match &self.unavailable_error {
            Some(err) => Err(err.to_domain_error()),
            None => Err(DomainError::new(
                ErrorCode::SANDBOX_PROVIDER_UNAVAILABLE,
                format!(
                    "provider {} is unavailable ({})",
                    self.plugin_id,
                    self.health.summary()
                ),
            )),
        }
    }

    /// One discovery page (FR-001, fault mode 3).
    ///
    /// `cursor` is `None` for the first page and otherwise the opaque token a
    /// previous page returned. A relation rides along with the page holding its
    /// `from` resource, so an edge can never appear before its source.
    pub fn page(&self, cursor: Option<&str>) -> Result<DiscoverBatch, DomainError> {
        self.ensure_available()?;
        let index = parse_cursor(cursor)?;
        let pages = self.page_count();
        // Reject a cursor outside the world rather than answering it with an
        // empty page: an empty page reads as "the scan finished", which would
        // silently truncate a resource set.
        if (pages == 0 && index != 0) || (pages > 0 && index >= pages) {
            return Err(invalid_cursor(cursor));
        }

        if let Some(fault) = &self.discover_fault {
            if index >= fault.fail_from_page {
                return Err(fault.error.to_domain_error());
            }
        }

        let start = index * self.page_size;
        let end = (start + self.page_size).min(self.resources.len());
        let resources: Vec<ResourceNode> = self.resources[start..end].to_vec();

        let ids: BTreeSet<&str> = resources.iter().map(|r| r.id.as_str()).collect();
        let relations: Vec<Relation> = self
            .relations
            .iter()
            .filter(|r| ids.contains(r.from.as_str()))
            .cloned()
            .collect();

        let cursor = if end < self.resources.len() {
            Some(format!("{CURSOR_PREFIX}{}", index + 1))
        } else {
            None
        };
        Ok(DiscoverBatch {
            resources,
            relations,
            cursor,
        })
    }

    /// Invoke a scripted lifecycle operation.
    ///
    /// The destructive-op confirmation and the capability ceiling are **repeated
    /// here on purpose** (FR-023, FR-027, FR-051, NFR-S02, NFR-U02): the kernel
    /// refuses both before dispatch, and a fake that skipped them would let a
    /// test calling the port directly succeed on a path production can never
    /// take. Duplicating a refusal is fail-closed; skipping one is not.
    pub fn invoke(&self, req: &OperationRequest) -> Result<OperationOutcome, DomainError> {
        self.ensure_available()?;

        // Confirmation first, in the same order the kernel uses it: refusing a
        // destructive call must not depend on anything else being reachable.
        if req.op.defaults_to_non_forced() && !is_forced(req) {
            return Err(DomainError::policy_denied(format!(
                "{} is destructive and requires an explicit `force: true` confirmation",
                req.op.as_str()
            )));
        }

        let node = self
            .node(&req.resource_id)
            .ok_or_else(|| not_found(&req.resource_id))?;

        // The resource's declared capability set is a ceiling (FR-061): an
        // empty set means "no ceiling declared", a non-empty one is binding.
        if !node.capabilities.is_empty() {
            let required = Capability::global(CapabilityNamespace::Resource, req.op.as_str());
            if !node.capabilities.allows(&required) {
                return Err(DomainError::policy_denied(format!(
                    "resource {} does not declare the {required} capability",
                    node.name
                )));
            }
        }

        let spec = self.operations.get(req.op.as_str()).ok_or_else(|| {
            DomainError::core_invalid(format!(
                "no scripted outcome for operation {:?} on resource {}; add it to `operations`",
                req.op.as_str(),
                node.name
            ))
        })?;

        if let Some(err) = &spec.error {
            return Err(err.to_domain_error());
        }
        let outcome = spec.outcome.as_ref().ok_or_else(|| {
            DomainError::core_invalid(format!(
                "operation {:?} declares neither an outcome nor an error",
                req.op.as_str()
            ))
        })?;
        Ok(OperationOutcome {
            state: outcome.state,
            // Validated at load time; a failure outcome always carries a code.
            error_code: outcome.code.as_deref().and_then(ErrorCode::parse),
            result: outcome.result.clone().unwrap_or(Json::Null),
        })
    }

    /// Run one scripted command (FR-013, FR-025).
    ///
    /// `timeout_ms` is a budget, not a delay: a scripted world never blocks, so
    /// a zero budget is refused rather than reported as success — a provider
    /// that "succeeds" a command it had no time to run would make every
    /// deadline assertion vacuous.
    pub fn exec(
        &self,
        id: &ResourceId,
        argv: &[String],
        timeout_ms: u64,
    ) -> Result<ExecOutcome, DomainError> {
        self.ensure_available()?;
        let node = self.node(id).ok_or_else(|| not_found(id))?;
        if timeout_ms == 0 {
            return Err(DomainError::core_invalid(
                "exec requires a non-zero timeout budget",
            ));
        }

        let rule = self
            .exec_rules
            .iter()
            .find(|r| r.matches(id, argv))
            .ok_or_else(|| {
                DomainError::core_invalid(format!(
                    "no scripted exec rule for argv {argv:?} on resource {}",
                    node.name
                ))
            })?;

        if let Some(err) = &rule.spec.error {
            return Err(err.to_domain_error());
        }

        let (stdout, out_truncated) =
            bound_output(rule.spec.stdout.as_deref().unwrap_or(""), MAX_CAPTURE_BYTES);
        let (stderr, err_truncated) =
            bound_output(rule.spec.stderr.as_deref().unwrap_or(""), MAX_CAPTURE_BYTES);
        // A fixture may declare truncation itself; the provider cap can also
        // truncate independently. Either way the flag must come out true.
        let truncated = out_truncated || err_truncated || rule.spec.truncated.unwrap_or(false);

        Ok(ExecOutcome {
            exit_code: rule.spec.exit_code.unwrap_or(0),
            stdout,
            stderr,
            truncated,
        })
    }

    /// Read guard over one resource workspace (fault 4 and mode 2 both apply).
    pub fn filesystem(
        &self,
        id: &ResourceId,
    ) -> Result<RwLockReadGuard<'_, WorkspaceFs>, DomainError> {
        self.ensure_available()?;
        self.node(id).ok_or_else(|| not_found(id))?;
        self.files
            .get(id)
            .ok_or_else(|| not_found(id))?
            .read()
            .map_err(|_| poisoned("filesystem"))
    }

    /// Write guard over one resource workspace, for [`ScriptedFileProvider::write`].
    ///
    /// Public so the file port can mutate the shared world. The mutation is
    /// confined to file content, never to the resource set, so the scan stays
    /// byte-identical whatever a test writes.
    pub fn filesystem_mut(
        &self,
        id: &ResourceId,
    ) -> Result<RwLockWriteGuard<'_, WorkspaceFs>, DomainError> {
        self.ensure_available()?;
        self.node(id).ok_or_else(|| not_found(id))?;
        self.files
            .get(id)
            .ok_or_else(|| not_found(id))?
            .write()
            .map_err(|_| poisoned("filesystem"))
    }

    /// Build a [`ProviderInstance`] serving all three control-plane ports.
    ///
    /// `observation` stays `None`: this crate has no observation plane, and
    /// pretending otherwise would let a caller register a fake that could never
    /// produce a snapshot (ADR-OBS-001).
    pub fn provider_instance(self: &Arc<Self>) -> ProviderInstance {
        ProviderInstance {
            plugin_id: self.plugin_id.clone(),
            generation: MOCK_GENERATION,
            resource: Some(Arc::new(ScriptedResourceProvider::new(self.clone()))),
            observation: None,
            files: Some(Arc::new(ScriptedFileProvider::new(self.clone()))),
            exec: Some(Arc::new(ScriptedExecProvider::new(self.clone()))),
        }
    }

    // --- load-time construction ------------------------------------------------

    // FR-001: identity is derived from provider-native parts, so two fixtures
    // naming the same provider-native resource agree on its id, and renaming a
    // resource in the fixture does not change it.
    fn derive_keys(fixture: &WorldFixture) -> Result<BTreeMap<String, ResourceId>, FixtureError> {
        let mut keys: BTreeMap<String, ResourceId> = BTreeMap::new();
        for spec in &fixture.resources {
            if spec.key.trim().is_empty() {
                return Err(FixtureError::Invalid {
                    field: "resources[].key".into(),
                    reason: "must not be empty".into(),
                });
            }
            if spec.id_parts.is_empty() {
                return Err(FixtureError::Invalid {
                    field: format!("resources[{}].id_parts", spec.key),
                    reason: "must not be empty; identity is derived from these parts".into(),
                });
            }
            let id = ResourceId::derive(&parts_of(spec));
            if keys.insert(spec.key.clone(), id.clone()).is_some() {
                return Err(FixtureError::Invalid {
                    field: format!("resources[].key={}", spec.key),
                    reason: "duplicate key".into(),
                });
            }
        }
        // Two keys pointing at one identity would make `inspect` ambiguous.
        let mut seen: BTreeMap<ResourceId, String> = BTreeMap::new();
        for (key, id) in &keys {
            if let Some(other) = seen.insert(id.clone(), key.clone()) {
                return Err(FixtureError::Invalid {
                    field: format!("resources[].key={key}"),
                    reason: format!("shares an identity with key {other:?}"),
                });
            }
        }
        Ok(keys)
    }

    fn canonicalize_subtrees(
        fixture: &WorldFixture,
    ) -> Result<BTreeMap<String, String>, FixtureError> {
        let mut out = BTreeMap::new();
        for spec in &fixture.resources {
            let canonical = match &spec.vfs_root {
                Some(raw) => WorkspacePath::from_relative(raw)
                    .map_err(|e| FixtureError::Invalid {
                        field: format!("resources[{}].vfs_root", spec.key),
                        reason: e.to_string(),
                    })?
                    .as_str()
                    .to_string(),
                None => String::new(),
            };
            out.insert(spec.key.clone(), canonical);
        }
        Ok(out)
    }

    fn build_resources(
        fixture: &WorldFixture,
        plugin_id: &PluginId,
    ) -> Result<(Vec<ResourceNode>, BTreeMap<ResourceId, usize>), FixtureError> {
        let mut nodes: BTreeMap<&str, ResourceNode> = BTreeMap::new();
        for spec in &fixture.resources {
            let id = ResourceId::derive(&parts_of(spec));
            let capabilities = CapabilitySet::parse_all(
                spec.capabilities.iter().map(String::as_str),
            )
            .map_err(|e| FixtureError::Invalid {
                field: format!("resources[{}].capabilities", spec.key),
                reason: e.to_string(),
            })?;
            nodes.insert(
                spec.key.as_str(),
                ResourceNode {
                    id,
                    kind: spec.kind,
                    provider_id: plugin_id.clone(),
                    name: spec.name.clone(),
                    state: spec.state,
                    parent_id: None,
                    capabilities,
                    metadata: Json::Object(spec.metadata.clone().into_iter().collect()),
                    last_seen: spec.last_seen.clone(),
                },
            );
        }

        // Wire parents, refusing dangling keys and cycles: a cycle would make
        // the pre-order emission below recurse forever.
        let parent_of: BTreeMap<&str, &str> = fixture
            .resources
            .iter()
            .filter_map(|s| s.parent.as_deref().map(|p| (s.key.as_str(), p)))
            .collect();
        for spec in &fixture.resources {
            let Some(parent_key) = spec.parent.as_deref() else {
                continue;
            };
            let parent_id = nodes.get(parent_key).map(|p| p.id.clone()).ok_or_else(|| {
                FixtureError::Invalid {
                    field: format!("resources[{}].parent", spec.key),
                    reason: format!("unknown parent key {parent_key:?}"),
                }
            })?;
            let child = nodes
                .get_mut(spec.key.as_str())
                .ok_or_else(|| FixtureError::Invalid {
                    field: format!("resources[{}]", spec.key),
                    reason: "key vanished during load".into(),
                })?;
            child.parent_id = Some(parent_id);

            let mut seen: BTreeSet<&str> = BTreeSet::from([parent_key, spec.key.as_str()]);
            let mut cursor = parent_key;
            while let Some(next_key) = parent_of.get(cursor).copied() {
                if !seen.insert(next_key) {
                    return Err(FixtureError::Invalid {
                        field: format!("resources[{}].parent", spec.key),
                        reason: format!(
                            "parent chain of {:?} forms a cycle at {next_key:?}",
                            spec.key
                        ),
                    });
                }
                cursor = next_key;
            }
        }

        // Pre-order over the tree: parents before children, siblings by id.
        // Ordering here is what makes the serialization order of a scan fixed
        // regardless of how the fixture listed its resources.
        let by_key: BTreeMap<&str, &ResourceSpec> = fixture
            .resources
            .iter()
            .map(|s| (s.key.as_str(), s))
            .collect();
        let mut roots: Vec<&str> = fixture
            .resources
            .iter()
            .filter(|s| s.parent.is_none())
            .map(|s| s.key.as_str())
            .collect();
        roots.sort_by(|a, b| nodes[a].id.as_str().cmp(nodes[b].id.as_str()));
        let mut ordered: Vec<ResourceNode> = Vec::with_capacity(nodes.len());
        for root in roots {
            Self::emit_subtree(root, &by_key, &nodes, &mut ordered);
        }
        if ordered.len() != nodes.len() {
            return Err(FixtureError::Invalid {
                field: "resources[].parent".into(),
                reason: "some resources are unreachable from a parentless root".into(),
            });
        }

        let mut index = BTreeMap::new();
        for (i, node) in ordered.iter().enumerate() {
            index.insert(node.id.clone(), i);
        }
        Ok((ordered, index))
    }

    fn emit_subtree(
        key: &str,
        by_key: &BTreeMap<&str, &ResourceSpec>,
        nodes: &BTreeMap<&str, ResourceNode>,
        out: &mut Vec<ResourceNode>,
    ) {
        if let Some(node) = nodes.get(key) {
            out.push(node.clone());
        }
        let mut children: Vec<&str> = by_key
            .iter()
            .filter(|(_, s)| s.parent.as_deref() == Some(key))
            .map(|(k, _)| *k)
            .collect();
        children.sort_by(|a, b| nodes[a].id.as_str().cmp(nodes[b].id.as_str()));
        for child in children {
            Self::emit_subtree(child, by_key, nodes, out);
        }
    }

    // FR-004: relations are typed edges between derived identities; a relation
    // naming a resource the fixture never declared would be unresolvable
    // outside this crate, so it is refused here rather than at scan time.
    fn build_relations(
        fixture: &WorldFixture,
        keys: &BTreeMap<String, ResourceId>,
    ) -> Result<Vec<Relation>, FixtureError> {
        let mut relations = Vec::with_capacity(fixture.relations.len());
        for rel in &fixture.relations {
            let from = lookup_key(keys, &rel.from, "relations[].from")?;
            let to = lookup_key(keys, &rel.to, "relations[].to")?;
            relations.push(Relation {
                from,
                to,
                kind: rel.kind,
                metadata: Json::Object(rel.metadata.clone().into_iter().collect()),
            });
        }
        relations.sort_by(|a, b| {
            a.from
                .as_str()
                .cmp(b.from.as_str())
                .then_with(|| a.kind.as_str().cmp(b.kind.as_str()))
                .then_with(|| a.to.as_str().cmp(b.to.as_str()))
        });
        Ok(relations)
    }

    // Keyed by the operation *wire name* rather than by `OperationKind`: the
    // enum has no `Ord`, and a `BTreeMap<String, _>` also gives a fixed
    // iteration order for the same determinism reason the rest of the world
    // orders itself at load time.
    fn build_operations(
        fixture: &WorldFixture,
    ) -> Result<BTreeMap<String, OperationSpec>, FixtureError> {
        let mut ops: BTreeMap<String, OperationSpec> = BTreeMap::new();
        for spec in &fixture.operations {
            parse_operation_kind(&spec.op)?;
            if let Some(err) = &spec.error {
                parse_error_code(&err.code)?;
            }
            if let Some(outcome) = &spec.outcome {
                if !outcome.state.is_terminal() {
                    return Err(FixtureError::Invalid {
                        field: format!("operations[{}].outcome.state", spec.op),
                        reason: format!(
                            "{:?} is not terminal; `invoke` returns a finished job",
                            outcome.state
                        ),
                    });
                }
                // A code belongs on a failure and nowhere else: `Succeeded` with
                // an error code would be a job the UI has to guess about
                // (DD-SW §10 — never infer state from text).
                match (outcome.state, outcome.code.as_deref()) {
                    (OperationState::Failed, None) => {
                        return Err(FixtureError::Invalid {
                            field: format!("operations[{}].outcome.code", spec.op),
                            reason: "a failed outcome must carry a stable code".into(),
                        })
                    }
                    (OperationState::Failed, Some(code)) => {
                        parse_error_code(code)?;
                    }
                    (_, Some(code)) => {
                        return Err(FixtureError::Invalid {
                            field: format!("operations[{}].outcome.code", spec.op),
                            reason: format!(
                                "{:?} is not a failure, so it must not carry code {code:?}",
                                outcome.state
                            ),
                        })
                    }
                    (_, None) => {}
                }
            }
            if spec.outcome.is_none() && spec.error.is_none() {
                return Err(FixtureError::Invalid {
                    field: format!("operations[{}]", spec.op),
                    reason: "must declare either an outcome or an error".into(),
                });
            }
            if ops.insert(spec.op.clone(), spec.clone()).is_some() {
                return Err(FixtureError::Invalid {
                    field: format!("operations[].op={}", spec.op),
                    reason: "duplicate operation rule".into(),
                });
            }
        }
        Ok(ops)
    }

    // FR-077 + NFR-S05: file entries are declared, not discovered, and every one
    // must name a real parent inside the same workspace. Whether an entry is
    // *reachable* is decided at request time by [`WorkspaceFs::require_within`],
    // not here: storage may legitimately hold material outside the served
    // subtree, and that is what makes the runtime confinement check testable.
    fn build_files(
        fixture: &WorldFixture,
        keys: &BTreeMap<String, ResourceId>,
        subtrees: &BTreeMap<String, String>,
    ) -> Result<BTreeMap<ResourceId, RwLock<WorkspaceFs>>, FixtureError> {
        let mut files: BTreeMap<ResourceId, RwLock<WorkspaceFs>> = fixture
            .resources
            .iter()
            .map(|spec| {
                (
                    ResourceId::derive(&parts_of(spec)),
                    RwLock::new(WorkspaceFs {
                        entries: BTreeMap::new(),
                        root_subtree: subtrees.get(&spec.key).cloned().unwrap_or_else(String::new),
                    }),
                )
            })
            .collect();

        for spec in &fixture.files {
            let id = lookup_key(keys, &spec.root, "files[].root")?;
            let entry = build_file_entry(spec)?;
            let fs = files.get_mut(&id).ok_or_else(|| FixtureError::Invalid {
                field: format!("files[].root={}", spec.root),
                reason: "resource is not part of the world".into(),
            })?;
            let mut fs = fs.write().map_err(|_| poisoned_load())?;

            if fs.entries.contains_key(&entry.path) {
                return Err(FixtureError::Invalid {
                    field: format!("files[].path={}", entry.path),
                    reason: format!("duplicate path in root {:?}", spec.root),
                });
            }
            // An entry outside the served subtree is *allowed*: the storage can
            // hold material the port must not reach. That is the shape a real
            // workspace mount has, and it is the only way a test can prove the
            // confinement check is load-bearing — a refusal against a path that
            // holds nothing would also pass if the check were deleted.
            fs.entries.insert(entry.path.clone(), entry);
        }

        for fs in files.values() {
            let fs = fs.read().map_err(|_| poisoned_load())?;
            Self::require_explicit_parents(&fs)?;
        }
        Ok(files)
    }

    // A lazy fake that invented parent directories would make `list` results
    // depend on which files a fixture happened to declare, so parents are
    // explicit.
    fn require_explicit_parents(fs: &WorkspaceFs) -> Result<(), FixtureError> {
        for entry in fs.entries.values() {
            let Some(parent) = entry.parent_path() else {
                continue;
            };
            match fs.entries.get(parent) {
                Some(p) if p.is_dir => {}
                Some(_) => {
                    return Err(FixtureError::Invalid {
                        field: format!("files[].path={}", entry.path),
                        reason: format!("parent {parent:?} is a file, not a directory"),
                    })
                }
                None => {
                    return Err(FixtureError::Invalid {
                        field: format!("files[].path={}", entry.path),
                        reason: format!("parent directory {parent:?} is not declared"),
                    })
                }
            }
        }
        Ok(())
    }

    fn build_exec(
        fixture: &WorldFixture,
        keys: &BTreeMap<String, ResourceId>,
    ) -> Result<Vec<ExecRule>, FixtureError> {
        let mut rules = Vec::with_capacity(fixture.exec.len());
        for spec in &fixture.exec {
            if spec.argv.is_empty() {
                return Err(FixtureError::Invalid {
                    field: "exec[].argv".into(),
                    reason: "must not be empty; rules match argv exactly".into(),
                });
            }
            if let Some(err) = &spec.error {
                parse_error_code(&err.code)?;
            }
            let resource = match &spec.resource {
                Some(key) => Some(lookup_key(keys, key, "exec[].resource")?),
                None => None,
            };
            rules.push(ExecRule {
                resource,
                argv: spec.argv.clone(),
                spec: spec.clone(),
            });
        }
        Ok(rules)
    }
}

// --- load-time helpers ------------------------------------------------------

fn parts_of(spec: &ResourceSpec) -> Vec<&str> {
    spec.id_parts.iter().map(String::as_str).collect()
}

fn lookup_key(
    keys: &BTreeMap<String, ResourceId>,
    key: &str,
    field: &str,
) -> Result<ResourceId, FixtureError> {
    keys.get(key).cloned().ok_or_else(|| FixtureError::Invalid {
        field: format!("{field}={key}"),
        reason: "unknown resource key".into(),
    })
}

/// Convert one declared file into an entry, refusing self-contradictions.
fn build_file_entry(spec: &FileSpec) -> Result<FileEntry, FixtureError> {
    let path = WorkspacePath::from_relative(&spec.path)
        .map_err(|e| FixtureError::Invalid {
            field: format!("files[].path={}", spec.path),
            reason: e.to_string(),
        })?
        .as_str()
        .to_string();

    if path.is_empty() && !spec.is_dir {
        return Err(FixtureError::Invalid {
            field: "files[].path".into(),
            reason: "the workspace root must be declared as a directory".into(),
        });
    }
    if spec.is_dir && spec.content.is_some() {
        return Err(FixtureError::Invalid {
            field: format!("files[].path={path}"),
            reason: "a directory cannot declare content".into(),
        });
    }
    if spec.is_dir && spec.size.unwrap_or(0) != 0 {
        return Err(FixtureError::Invalid {
            field: format!("files[].path={path}"),
            reason: "a directory reports size 0".into(),
        });
    }
    if spec.symlink_target.is_some() && spec.content.is_some() {
        return Err(FixtureError::Invalid {
            field: format!("files[].path={path}"),
            reason: "a symlink has no content of its own".into(),
        });
    }
    if let (Some(content), Some(size)) = (&spec.content, spec.size) {
        if size != content.len() as u64 {
            return Err(FixtureError::Invalid {
                field: format!("files[].path={path}"),
                reason: format!(
                    "declared size {size} but content is {} bytes",
                    content.len()
                ),
            });
        }
    }
    if spec.symlink_target.as_deref().is_some_and(str::is_empty) {
        return Err(FixtureError::Invalid {
            field: format!("files[].path={path}"),
            reason: "symlink_target must not be empty".into(),
        });
    }

    Ok(FileEntry {
        path,
        is_dir: spec.is_dir,
        content: spec.content.clone(),
        written_bytes: None,
        declared_size: spec.size,
        mtime_ns: spec.mtime_ns,
        content_hash: spec.content_hash.clone(),
        symlink_target: spec.symlink_target.clone(),
        read_only: spec.read_only,
    })
}

/// Whether a request carries an explicit destructive-op confirmation (FR-023).
fn is_forced(req: &OperationRequest) -> bool {
    req.args
        .get("force")
        .and_then(Json::as_bool)
        .unwrap_or(false)
}

fn join_segments(parts: &[String], extra: &str) -> String {
    let mut s = parts.join("/");
    if !extra.is_empty() {
        if !s.is_empty() {
            s.push('/');
        }
        s.push_str(extra);
    }
    s
}

fn segments_of(path: &str) -> Vec<&str> {
    path.split('/').filter(|s| !s.is_empty()).collect()
}

/// Resolve a raw symlink target against the link's directory (NFR-S05).
///
/// Folding happens *here*, in the provider, because a target is only knowable
/// after resolution — the caller's normalisation never saw it. `\` counts as a
/// separator too: a link authored on Windows may use it, and folding it is the
/// conservative choice.
fn fold_target(base: &[String], target: &str) -> Result<Vec<String>, DomainError> {
    if target.starts_with('/') || target.starts_with('\\') || looks_like_drive(target) {
        return Err(DomainError::path_escape(format!(
            "symlink target {target:?} is a host-absolute path"
        )));
    }
    let mut out: Vec<String> = base.to_vec();
    for part in target.split(['/', '\\']) {
        match part {
            "" | "." => continue,
            ".." => {
                if out.pop().is_none() {
                    return Err(DomainError::path_escape(format!(
                        "symlink target {target:?} escapes the workspace root"
                    )));
                }
            }
            other => out.push(other.to_string()),
        }
    }
    Ok(out)
}

fn looks_like_drive(raw: &str) -> bool {
    let b = raw.as_bytes();
    b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':'
}

fn parse_cursor(cursor: Option<&str>) -> Result<usize, DomainError> {
    let Some(raw) = cursor else {
        return Ok(0);
    };
    let Some(rest) = raw.strip_prefix(CURSOR_PREFIX) else {
        return Err(invalid_cursor(cursor));
    };
    rest.parse::<usize>().map_err(|_| invalid_cursor(cursor))
}

fn invalid_cursor(cursor: Option<&str>) -> DomainError {
    DomainError::core_invalid(format!(
        "invalid discovery cursor {cursor:?}; expected {CURSOR_PREFIX}<page> from a previous page"
    ))
}

fn not_found(id: &ResourceId) -> DomainError {
    DomainError::not_found(format!("no such resource: {id}"))
}

fn poisoned(what: &str) -> DomainError {
    DomainError::core_invalid(format!("scripted {what} lock is poisoned"))
}

fn poisoned_load() -> FixtureError {
    FixtureError::Invalid {
        field: "files".into(),
        reason: "the scripted filesystem lock is poisoned".into(),
    }
}

/// Truncate a captured stream at a byte budget without splitting a character.
fn bound_output(s: &str, cap: usize) -> (String, bool) {
    if s.len() <= cap {
        return (s.to_string(), false);
    }
    let mut end = cap;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    (s[..end].to_string(), true)
}
