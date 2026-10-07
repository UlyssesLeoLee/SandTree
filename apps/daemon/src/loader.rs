//! A [`PluginLoader`] that actually stages a component (FR-054, FR-055, ADR-018).
//!
//! # Why this is a separate module
//!
//! [`crate::plugins::PluginControl`] owns the control plane: routing, the swap
//! supervisor, the rollback reserve. It deliberately owns no engine. This module
//! owns the other half — turning a plugin id into a loaded generation — behind
//! the same [`PluginLoader`] seam, so swapping in a different loader is a
//! constructor argument and not a rewrite.
//!
//! # What it does and does not isolate
//!
//! It runs the worker **in this process**. DD-PLG §10 and FR-055 put the worker
//! in its own process so that a broken worker takes down only itself; this
//! loader does not deliver that, and ADR-018 records the deviation rather than
//! pretending it is there.
//!
//! What *is* intact: a WASM guest remains memory-safe and capability-limited no
//! matter where its store lives. A trapping guest traps. What is lost is the
//! containment of the *host-side* worker code around it, and the OS-level
//! resource ceiling a separate process would give.
//!
//! Consequently this loader is **not** the daemon's default. The daemon still
//! ships [`crate::plugins::UnavailableLoader`], so a build that has not opted in
//! refuses rather than pretending. Turning this on is a decision, not a
//! side effect.
//!
//! # Why a [`PackageSource`]
//!
//! [`PluginLoader::stage`] receives a plugin id and a generation number, and
//! nothing else — correctly, because the control plane has no business knowing
//! where bytes live. So the mapping from id to package is a separate, injectable
//! concern. Anything that can answer "what are this plugin's bytes" works:
//! a directory on disk, a manifest registry, a test fixture.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use sandtree_model::capability::CapabilitySet;
use sandtree_model::error::{DomainError, ErrorCode};
use sandtree_model::id::PluginId;
use sandtree_plugin_host::generation::LoadedGeneration;
use sandtree_plugin_host::limits::WorkerLimits;
use sandtree_plugin_host::route::Generation;
use sandtree_plugin_host::verify::InstallPolicy;
use sandtree_plugin_worker::{Worker, WorkerSpec};
use serde_json::Value as Json;

use crate::plugins::PluginLoader;

/// File name of the manifest inside a package directory.
pub const MANIFEST_FILE: &str = "plugin.json";

/// File name of the component inside a package directory.
pub const COMPONENT_FILE: &str = "component.wasm";

/// One plugin's installable bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageSpec {
    /// Component file to load.
    pub component_path: PathBuf,
    /// The plugin manifest, as JSON.
    pub manifest: Json,
}

/// Resolves a plugin id to its installable bytes.
pub trait PackageSource: Send + Sync {
    /// The package for `plugin`, or an error naming what is missing.
    fn package(&self, plugin: &PluginId) -> Result<PackageSpec, DomainError>;
}

/// Packages laid out on disk as `<root>/<anything>/{plugin.json,component.wasm}`.
///
/// The directory name is deliberately **not** the identity. A plugin's identity
/// is `PluginId::derive(&[<manifest plugin_id>])`, which is an opaque `plg-<hex>`
/// — usable as a map key, useless as something an operator types. So the tree is
/// indexed by parsing each `plugin.json` and deriving the id from it, which also
/// means the layout is "drop a package directory in", not "create a directory
/// whose name matches a hash you would have to compute".
///
/// The index is built once, at construction, and a manifest that will not parse
/// fails there rather than on the first install: a broken package on disk is a
/// deployment problem, and finding out at startup beats finding out when an
/// operator happens to install that plugin.
#[derive(Debug)]
pub struct DirectoryPackages {
    root: PathBuf,
    index: BTreeMap<PluginId, PathBuf>,
}

impl DirectoryPackages {
    /// Index every `plugin.json` under `root`.
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, DomainError> {
        let root = root.into();
        let mut index = BTreeMap::new();
        if root.is_dir() {
            for entry in walkdir::WalkDir::new(&root)
                .into_iter()
                .filter_map(std::result::Result::ok)
            {
                if !entry.file_type().is_file() || entry.file_name() != MANIFEST_FILE {
                    continue;
                }
                let dir = entry.path().parent().unwrap_or(&root).to_path_buf();
                let path = entry.path().to_path_buf();
                let id = plugin_id_at(&path)?;
                // A duplicate is a deployment error, not a merge: two packages
                // claiming one identity makes "which one do I install" a
                // coin flip.
                if let Some(existing) = index.insert(id.clone(), dir.clone()) {
                    return Err(DomainError::new(
                        ErrorCode::PLUGIN_MANIFEST_INVALID,
                        format!(
                            "plugin {id} is declared twice: {} and {}",
                            existing.display(),
                            dir.display()
                        ),
                    ));
                }
            }
        }
        Ok(Self { root, index })
    }

    /// The package root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Directory a plugin's package lives in, if it is installed.
    pub fn dir_for(&self, plugin: &PluginId) -> Option<&Path> {
        self.index.get(plugin).map(PathBuf::as_path)
    }

    /// Every installed plugin id, sorted.
    pub fn installed(&self) -> impl Iterator<Item = &PluginId> {
        self.index.keys()
    }
}

/// Read a `plugin.json` and derive the plugin id it declares.
fn plugin_id_at(path: &Path) -> Result<PluginId, DomainError> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        DomainError::new(
            ErrorCode::PLUGIN_MANIFEST_INVALID,
            format!("cannot read {}: {e}", path.display()),
        )
    })?;
    let manifest: Json = serde_json::from_str(&text).map_err(|e| {
        DomainError::new(
            ErrorCode::PLUGIN_MANIFEST_INVALID,
            format!("{} is not valid JSON: {e}", path.display()),
        )
    })?;
    let name = manifest
        .get("plugin_id")
        .and_then(Json::as_str)
        .ok_or_else(|| {
            DomainError::new(
                ErrorCode::PLUGIN_MANIFEST_INVALID,
                format!("{} has no `plugin_id` string", path.display()),
            )
        })?;
    Ok(PluginId::derive(&[name]))
}

fn missing(what: &str, path: &Path) -> DomainError {
    DomainError::new(
        ErrorCode::PLUGIN_MANIFEST_INVALID,
        format!("{what} is missing at {}", path.display()),
    )
}

impl PackageSource for DirectoryPackages {
    fn package(&self, plugin: &PluginId) -> Result<PackageSpec, DomainError> {
        let dir = self.dir_for(plugin).ok_or_else(|| {
            DomainError::new(
                ErrorCode::PLUGIN_MANIFEST_INVALID,
                format!(
                    "no package for plugin {plugin} under {}; installed: {:?}",
                    self.root.display(),
                    self.installed()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                ),
            )
        })?;
        let component_path = dir.join(COMPONENT_FILE);
        if !component_path.is_file() {
            return Err(missing("plugin component", &component_path));
        }
        let manifest: Json = serde_json::from_str(
            &std::fs::read_to_string(dir.join(MANIFEST_FILE)).map_err(|e| {
                DomainError::new(
                    ErrorCode::PLUGIN_MANIFEST_INVALID,
                    format!("cannot read the manifest in {}: {e}", dir.display()),
                )
            })?,
        )
        .map_err(|e| {
            DomainError::new(
                ErrorCode::PLUGIN_MANIFEST_INVALID,
                format!("the manifest in {} is not valid JSON: {e}", dir.display()),
            )
        })?;
        Ok(PackageSpec {
            component_path,
            manifest,
        })
    }
}

/// Stages real components through [`sandtree_plugin_worker::Worker`].
pub struct WorkerLoader {
    source: Arc<dyn PackageSource>,
    policy: InstallPolicy,
    granted: CapabilitySet,
    limits: WorkerLimits,
}

impl WorkerLoader {
    /// Build a loader over `source`.
    ///
    /// `granted` is the daemon's capability ceiling; the worker's effective
    /// grant is that intersected with what the package asked for, which is the
    /// narrowing rule from NFR-S02 applied at the point of staging rather than
    /// at the point of use.
    pub fn new(
        source: Arc<dyn PackageSource>,
        policy: InstallPolicy,
        granted: CapabilitySet,
        limits: WorkerLimits,
    ) -> Self {
        Self {
            source,
            policy,
            granted,
            limits,
        }
    }

    /// A loader over a directory tree, with the host ceiling and no grant.
    ///
    /// Fails when the tree holds a package whose manifest will not parse: see
    /// [`DirectoryPackages::new`].
    pub fn over_directory(root: impl Into<PathBuf>) -> Result<Self, DomainError> {
        Ok(Self::new(
            Arc::new(DirectoryPackages::new(root)?),
            InstallPolicy::deny_all(),
            CapabilitySet::empty(),
            WorkerLimits::host_ceiling(),
        ))
    }

    /// Add an allowed license expression.
    #[must_use]
    pub fn allow_license(mut self, license: &str) -> Self {
        self.policy = self.policy.allow_license(license);
        self
    }

    /// The capability ceiling handed to every staged worker.
    pub fn granted(&self) -> &CapabilitySet {
        &self.granted
    }
}

impl std::fmt::Debug for WorkerLoader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WorkerLoader")
            .field("granted", &self.granted)
            .field("limits", &self.limits)
            .finish()
    }
}

#[async_trait::async_trait]
impl PluginLoader for WorkerLoader {
    async fn stage(
        &self,
        plugin: &PluginId,
        generation: Generation,
    ) -> Result<Arc<LoadedGeneration>, DomainError> {
        // Every failure below is wrapped once, here, so an operator reading a
        // stage failure always learns which plugin and which generation failed.
        // Wrapping per-failure-path is how "not installed" ends up reported
        // without a generation number while a verify error carries one.
        self.stage_inner(plugin, generation).await.map_err(|e| {
            DomainError::new(
                e.code,
                format!("plugin {plugin} generation {}: {}", generation.0, e.message),
            )
        })
    }
}

impl WorkerLoader {
    async fn stage_inner(
        &self,
        plugin: &PluginId,
        generation: Generation,
    ) -> Result<Arc<LoadedGeneration>, DomainError> {
        let spec = self.source.package(plugin)?;
        // The worker is dropped when this function returns. That is deliberate
        // and safe: `load` hands back an owned `Arc<LoadedGeneration>`, and the
        // lifecycle that matters -- drain then shutdown -- is driven through the
        // generation's runtime by the supervisor, not by the worker object.
        // Keeping the worker alive would only preserve its own state enum, which
        // nothing outside this function reads.
        let mut worker = Worker::new(WorkerSpec {
            component_path: spec.component_path,
            manifest: spec.manifest,
            generation,
            granted: self.granted.clone(),
            limits: self.limits,
        })
        .with_policy(self.policy.clone());

        worker.load().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plugin() -> PluginId {
        PluginId::derive(&["sandtree.provider.example"])
    }

    /// Drop a package directory into `root`, named the way an operator would.
    fn write_package(root: &Path, dir: &str, manifest: &str, component: &[u8]) -> PathBuf {
        let d = root.join(dir);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join(MANIFEST_FILE), manifest).unwrap();
        std::fs::write(d.join(COMPONENT_FILE), component).unwrap();
        d
    }

    fn manifest_json() -> String {
        r#"{"plugin_id":"sandtree.provider.example"}"#.to_string()
    }

    #[test]
    fn the_directory_name_is_not_the_identity() {
        // The whole reason this source indexes instead of path-building: a
        // plugin's id is `plg-<hex>`, and requiring the operator to create a
        // directory with that name would make every install a hash lookup.
        let tmp = tempfile::tempdir().unwrap();
        write_package(tmp.path(), "provider-example", &manifest_json(), b"bytes");

        let src = DirectoryPackages::new(tmp.path()).expect("index");
        assert_eq!(
            src.dir_for(&plugin()).map(|p| p.to_path_buf()),
            Some(tmp.path().join("provider-example"))
        );
    }

    #[test]
    fn a_well_formed_package_resolves_to_its_manifest_and_component() {
        let tmp = tempfile::tempdir().unwrap();
        let d = write_package(tmp.path(), "provider-example", &manifest_json(), b"bytes");
        let src = DirectoryPackages::new(tmp.path()).expect("index");

        let spec = src.package(&plugin()).expect("package");
        assert_eq!(spec.component_path, d.join(COMPONENT_FILE));
        assert_eq!(
            spec.manifest["plugin_id"],
            serde_json::json!("sandtree.provider.example")
        );
    }

    #[test]
    fn asking_for_an_absent_plugin_lists_what_is_installed() {
        // "not found" with no context is the error that sends an operator
        // grepping the filesystem.
        let tmp = tempfile::tempdir().unwrap();
        write_package(tmp.path(), "provider-example", &manifest_json(), b"bytes");
        let src = DirectoryPackages::new(tmp.path()).expect("index");

        let other = PluginId::derive(&["sandtree.provider.absent"]);
        let err = src.package(&other).expect_err("not installed");
        assert!(err.message.contains(other.as_str()), "{}", err.message);
        assert!(
            err.message.contains(plugin().as_str()),
            "the error should say what *is* installed: {}",
            err.message
        );
    }

    #[test]
    fn a_component_missing_from_an_otherwise_valid_package_is_reported_separately() {
        // Two different mistakes — no package at all, versus a package whose
        // component was never copied — must not collapse into one message.
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path().join("provider-example");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join(MANIFEST_FILE), manifest_json()).unwrap();
        let src = DirectoryPackages::new(tmp.path()).expect("index");

        let err = src.package(&plugin()).expect_err("component absent");
        assert!(err.message.contains(COMPONENT_FILE), "{}", err.message);
    }

    #[test]
    fn a_manifest_that_is_not_json_fails_at_index_time() {
        let tmp = tempfile::tempdir().unwrap();
        write_package(tmp.path(), "provider-example", "{not json", b"bytes");
        let err = DirectoryPackages::new(tmp.path()).expect_err("malformed manifest");
        assert!(err.message.contains("not valid JSON"), "{}", err.message);
    }

    #[test]
    fn two_packages_claiming_one_identity_are_a_deployment_error() {
        // Merging them would make "which one do I install" a coin flip.
        let tmp = tempfile::tempdir().unwrap();
        write_package(tmp.path(), "a", &manifest_json(), b"one");
        write_package(tmp.path(), "b", &manifest_json(), b"two");
        let err = DirectoryPackages::new(tmp.path()).expect_err("duplicate");
        assert!(err.message.contains("declared twice"), "{}", err.message);
    }

    #[test]
    fn an_empty_or_absent_root_is_not_an_error() {
        // A daemon that starts before any plugin is installed must not fail to
        // boot; it just has nothing to offer.
        let tmp = tempfile::tempdir().unwrap();
        let src = DirectoryPackages::new(tmp.path()).expect("index");
        assert_eq!(src.installed().count(), 0);
        assert!(src.package(&plugin()).is_err());
    }

    #[tokio::test]
    async fn staging_a_plugin_with_no_package_on_disk_fails_before_any_engine_is_built() {
        let tmp = tempfile::tempdir().unwrap();
        let loader = WorkerLoader::over_directory(tmp.path())
            .expect("index")
            .allow_license("Apache-2.0");
        let err = loader
            .stage(&plugin(), Generation(1))
            .await
            .expect_err("nothing on disk");
        assert!(err.message.contains(plugin().as_str()), "{}", err.message);
        assert!(err.message.contains("generation 1"), "{}", err.message);
    }
}
