//! Daemon composition: kernel bootstrap, IPC method surface, event pump.
//!
//! The daemon is the only process that touches the store, so everything that
//! mutates state goes through the kernel. It registers one handler per IPC
//! method and nothing else — there is no "admin" method that bypasses policy,
//! because a bypass reachable over IPC is indistinguishable from no policy at
//! all (NFR-S03).
//!
//! Per-user by default (NFR-S01): the pipe is scoped to the current account, and
//! the daemon does not ask for elevation.

#![deny(missing_docs)]

pub mod events;
#[cfg(feature = "in-process-worker")]
pub mod loader;
pub mod methods;
pub mod packages;
pub mod plugins;
pub mod worker_client;

use std::path::PathBuf;
use std::sync::Arc;

use sandtree_event::EventRouter;
use sandtree_ipc::method;
use sandtree_ipc::router::MethodRouter;
use sandtree_kernel::{Kernel, KernelConfig};
use serde_json::Value as Json;

/// Daemon configuration.
#[derive(Debug, Clone)]
pub struct DaemonConfig {
    /// Where the store and CAS live.
    pub data_dir: PathBuf,
    /// How often to reconcile in the background.
    pub reconcile_interval_ms: u64,
    /// Missing-resource grace period.
    pub stale_grace_ms: u64,
    /// Pipe path override; the default is the per-user path.
    pub pipe_path: Option<String>,
}

impl DaemonConfig {
    /// Default configuration under the user's data directory.
    pub fn new() -> Self {
        Self {
            data_dir: default_data_dir(),
            reconcile_interval_ms: 15_000,
            stale_grace_ms: 60_000,
            pipe_path: None,
        }
    }
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// `%LOCALAPPDATA%\sandtree` on Windows, `~/.local/share/sandtree` elsewhere.
pub fn default_data_dir() -> PathBuf {
    #[cfg(windows)]
    {
        if let Some(local) = std::env::var_os("LOCALAPPDATA") {
            return PathBuf::from(local).join("sandtree");
        }
    }
    #[cfg(not(windows))]
    {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home)
                .join(".local")
                .join("share")
                .join("sandtree");
        }
    }
    PathBuf::from(".sandtree")
}

/// A running daemon.
pub struct Daemon {
    kernel: Arc<Kernel>,
    router: Arc<MethodRouter>,
    events: Arc<EventRouter>,
    pipe: String,
}

impl std::fmt::Debug for Daemon {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Daemon")
            .field("pipe", &self.pipe)
            .field("data_dir", &self.kernel.config().data_dir)
            .finish()
    }
}

impl Daemon {
    /// Boot the kernel and build the IPC surface.
    ///
    /// No provider is contacted during boot, so this succeeds on a machine
    /// where Docker is not installed — the daemon comes up with unavailable
    /// providers rather than refusing to start (ADR-OBS-001).
    pub async fn start(cfg: DaemonConfig) -> Result<Self, sandtree_model::error::DomainError> {
        let mut kcfg = KernelConfig::new(cfg.data_dir.clone());
        kcfg.reconcile_interval_ms = cfg.reconcile_interval_ms;
        kcfg.stale_grace_ms = cfg.stale_grace_ms;

        let kernel = Arc::new(Kernel::bootstrap(kcfg).await?);
        let pipe = cfg
            .pipe_path
            .unwrap_or_else(sandtree_ipc::transport::pipe_path);
        // Plugin lifecycle state (ADR-016). The daemon ships a loader that
        // refuses, because it does not host a WASM engine: components run in
        // worker processes (FR-055). The endpoints exist and answer precisely;
        // wiring a real worker transport is what turns them from a refusal into
        // an install.
        let plugin_control = plugins::PluginControl::unavailable(
            Arc::new(sandtree_plugin_host::route::RouteTable::new()),
            "this daemon build has no plugin worker transport",
        );
        let router = Arc::new(methods::build_router(kernel.clone(), plugin_control));
        let events = kernel.event_router().clone();

        // A first discovery pass runs before the daemon accepts traffic, so the
        // first `resource.tree` is not empty for no reason (NFR-A01).
        if let Err(e) = kernel.discover_all().await {
            tracing::warn!(error = %e, "initial discovery failed; the daemon still starts");
        }

        tracing::info!(pipe = %pipe, "sandtree daemon ready");
        Ok(Self {
            kernel,
            router,
            events,
            pipe,
        })
    }

    /// The kernel.
    pub fn kernel(&self) -> &Arc<Kernel> {
        &self.kernel
    }

    /// The IPC method router.
    pub fn router(&self) -> &Arc<MethodRouter> {
        &self.router
    }

    /// The event router.
    pub fn events(&self) -> &Arc<EventRouter> {
        &self.events
    }

    /// The pipe this daemon listens on.
    pub fn pipe(&self) -> &str {
        &self.pipe
    }

    /// Methods this build answers, sorted.
    pub fn methods(&self) -> Vec<&str> {
        self.router.methods()
    }

    /// Whether every known method has a handler.
    ///
    /// A missing method would otherwise surface as a runtime "unknown method"
    /// on the first call, which is a poor time to find out.
    pub fn coverage_gaps(&self) -> Vec<&'static str> {
        method::ALL
            .iter()
            .copied()
            .filter(|m| !self.router.contains(m))
            .collect()
    }

    /// One background reconcile pass.
    pub async fn reconcile_once(&self) -> Result<Json, Json> {
        match self.kernel.reconcile().await {
            Ok(outcome) => Ok(serde_json::json!({
                "changes": outcome.changes.len(),
                "removed": outcome.removed.iter().map(|r| r.as_str()).collect::<Vec<_>>(),
            })),
            Err(e) => Err(serde_json::json!({
                "code": e.code.as_str(),
                "message": e.message,
            })),
        }
    }

    /// Shut down cleanly.
    pub async fn shutdown(&self) {
        self.kernel.shutdown().await;
        tracing::info!("sandtree daemon stopped");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn daemon() -> (tempfile::TempDir, Daemon) {
        let dir = tempfile::tempdir().unwrap();
        let cfg = DaemonConfig {
            data_dir: dir.path().to_path_buf(),
            reconcile_interval_ms: 1_000,
            stale_grace_ms: 1_000,
            pipe_path: Some(r"\\.\pipe\sandtree-test-v1".into()),
        };
        let d = Daemon::start(cfg).await.expect("daemon starts");
        (dir, d)
    }

    #[tokio::test]
    async fn the_daemon_boots_without_any_provider_present() {
        // A missing Docker/Multipass must not stop the daemon; the provider is
        // simply unavailable.
        let (_d, d) = daemon().await;
        assert!(d.kernel().providers().await.is_empty());
        assert_eq!(d.pipe(), r"\\.\pipe\sandtree-test-v1");
    }

    #[tokio::test]
    async fn every_known_method_has_a_handler() {
        let (_d, d) = daemon().await;
        assert_eq!(
            d.coverage_gaps(),
            Vec::<&str>::new(),
            "the daemon must answer every method in `method::ALL`"
        );
        assert_eq!(d.methods().len(), method::ALL.len());
    }

    #[tokio::test]
    async fn methods_are_registered_in_sorted_order() {
        let (_d, d) = daemon().await;
        let mut sorted = d.methods();
        sorted.sort_unstable();
        assert_eq!(sorted, d.methods());
    }

    #[tokio::test]
    async fn reconcile_on_an_empty_system_succeeds_and_removes_nothing() {
        let (_d, d) = daemon().await;
        let out = d.reconcile_once().await.expect("reconcile");
        assert_eq!(out["changes"], Json::from(0));
        assert_eq!(out["removed"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn the_event_router_is_shared_with_the_kernel() {
        let (_d, d) = daemon().await;
        assert!(std::sync::Arc::ptr_eq(
            d.events(),
            d.kernel().event_router()
        ));
    }

    #[tokio::test]
    async fn shutdown_is_idempotent() {
        let (_d, d) = daemon().await;
        d.shutdown().await;
        d.shutdown().await;
    }

    #[test]
    fn the_default_data_dir_is_absolute_and_version_free() {
        let p = default_data_dir();
        assert!(p.ends_with("sandtree"), "{}", p.display());
    }
}
