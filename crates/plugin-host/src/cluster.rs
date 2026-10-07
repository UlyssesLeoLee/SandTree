//! App Cluster assembly (DD-PLG 核心原则 "Plugin Cluster→App Cluster", FR-053,
//! ADR-016).
//!
//! An app manifest is a list of clusters, each naming the plugins that make it
//! up. Before this module the manifest parsed and validated, and then nothing
//! read `clusters` — the composition was a document, not a behaviour.
//!
//! The rule the design states is atomic: an app's clusters go live together or
//! not at all. That is stronger than it sounds, because an app is usually a
//! control plane plus the things it controls. Publishing them one at a time
//! leaves a window where the new control plane is live but the old data plane
//! still is — an app that half-upgraded is worse than one that did not upgrade,
//! because it looks like it worked.
//!
//! So assembly runs in three phases with no partial state:
//!
//! 1. [`ClusterPlanner::plan`] — resolve the manifest into a deterministic,
//!    de-duplicated list of plugin slots. No I/O, so a malformed app fails here.
//! 2. stage — load, `init` and health-check every plugin. A **required** slot
//!    that fails takes the whole install down; an **optional** slot that fails is
//!    dropped, which is what `required = false` means in the manifest.
//! 3. publish — one [`RouteTable::atomic_publish`] moves the whole app at once,
//!    then whatever it displaced is drained and shut down.
//!
//! Phase 2 is deliberately not "publish each plugin as it succeeds". That would
//! be simpler and would violate the atomicity the design asks for.

use std::collections::BTreeSet;
use std::sync::Arc;

use sandtree_model::error::{DomainError, ErrorCode};
use sandtree_model::id::PluginId;
use sandtree_sdk::manifest::AppManifest;

use crate::generation::LoadedGeneration;
use crate::route::{Generation, RouteTable};

fn invalid(msg: impl Into<String>) -> DomainError {
    DomainError::new(ErrorCode::PLUGIN_MANIFEST_INVALID, msg)
}

/// One plugin's slot in a cluster plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterEntry {
    /// Plugin this slot serves.
    pub plugin: PluginId,
    /// Plugin id exactly as written in the manifest, for diagnostics.
    pub declared_as: String,
    /// Cluster that owns the slot.
    pub cluster_id: String,
    /// Whether the app refuses to start without this plugin.
    pub required: bool,
}

/// A resolved app manifest: the exact set of plugin slots to stage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterPlan {
    /// App id from the manifest.
    pub app_id: String,
    /// Slots, in deterministic order (cluster id, then declared plugin order).
    pub entries: Vec<ClusterEntry>,
}

impl ClusterPlan {
    /// Plugin ids in the plan, deterministic order.
    pub fn plugins(&self) -> Vec<&PluginId> {
        self.entries.iter().map(|e| &e.plugin).collect()
    }

    /// How many slots the app needs.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the plan is empty (a manifest cannot produce one).
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether any slot is mandatory.
    pub fn has_required(&self) -> bool {
        self.entries.iter().any(|e| e.required)
    }
}

/// Resolves app manifests into cluster plans.
#[derive(Debug, Clone, Copy, Default)]
pub struct ClusterPlanner;

impl ClusterPlanner {
    /// Resolve an app manifest into a deterministic plan.
    ///
    /// Two properties matter and are tested separately:
    ///
    /// * **Determinism** — the same manifest always yields the same order, so a
    ///   staged app is reproducible and a diff between two runs is meaningful.
    /// * **No silent duplicates** — a plugin listed in two clusters is kept once.
    ///   Staging it twice would create two generations of one plugin, and the
    ///   second route write would displace the first with no warning.
    pub fn plan(manifest: &AppManifest) -> Result<ClusterPlan, DomainError> {
        // Sorted so plan order follows cluster id rather than manifest order.
        let mut clusters: Vec<_> = manifest.clusters.iter().collect();
        clusters.sort_by(|a, b| a.cluster_id.cmp(&b.cluster_id));

        let mut seen: BTreeSet<&str> = BTreeSet::new();
        let mut entries: Vec<ClusterEntry> = Vec::new();

        for cluster in clusters {
            // `required` absent means the app cannot start without it. Defaulting
            // the other way would let an app come up missing the very cluster its
            // author never annotated.
            let required = cluster.required.unwrap_or(true);
            for declared in &cluster.plugins {
                if !seen.insert(declared.as_str()) {
                    continue;
                }
                entries.push(ClusterEntry {
                    plugin: PluginId::derive(&[declared.as_str()]),
                    declared_as: declared.clone(),
                    cluster_id: cluster.cluster_id.clone(),
                    required,
                });
            }
        }

        if entries.is_empty() {
            return Err(invalid(format!(
                "app {}: manifest resolves to zero plugins",
                manifest.app_id
            )));
        }

        Ok(ClusterPlan {
            app_id: manifest.app_id.clone(),
            entries,
        })
    }

    /// The generation number an app install starts at.
    ///
    /// One number for the whole app, not one per plugin: an app is a single
    /// composition, and "which version of the app is running" has to be
    /// answerable without walking every plugin id.
    pub fn first_generation() -> Generation {
        Generation(1)
    }
}

/// A slot that could not be staged and was dropped because it was optional.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedSlot {
    /// Plugin that did not stage.
    pub plugin: PluginId,
    /// Plugin id as written in the manifest.
    pub declared_as: String,
    /// Why staging failed.
    pub reason: String,
}

/// What a cluster install actually did.
#[derive(Debug)]
pub struct ClusterInstall {
    /// Slots published, in plan order.
    pub published: Vec<PluginId>,
    /// Optional slots dropped, because their cluster was not required.
    pub skipped: Vec<SkippedSlot>,
    /// Generation the app was published at.
    pub generation: Generation,
    /// Generations this publish displaced, already drained and shut down.
    pub displaced: Vec<PluginId>,
}

/// Stages every plugin in a plan and publishes the app in one critical section.
///
/// `stage` is supplied by the caller because loading a plugin is the host's job
/// (it owns the engine and the install policy). This module decides *whether* to
/// publish, never *how* to load — which keeps the atomicity rule testable
/// without a WASM engine, and keeps the engine out of a module that only reasons
/// about composition.
pub struct ClusterInstaller {
    routes: Arc<RouteTable>,
    /// Deadline handed to a displaced generation's `drain`.
    drain_deadline_ms: u64,
}

impl ClusterInstaller {
    /// Build an installer writing to `routes`, using the host ceiling drain.
    pub fn new(routes: Arc<RouteTable>) -> Self {
        Self {
            routes,
            drain_deadline_ms: crate::limits::WorkerLimits::host_ceiling().wall_clock_ms,
        }
    }

    /// Override the drain deadline for displaced generations.
    pub fn with_drain_deadline_ms(mut self, deadline_ms: u64) -> Self {
        self.drain_deadline_ms = deadline_ms;
        self
    }

    /// Stage every plugin, then publish the app together.
    ///
    /// `stage` receives a [`ClusterEntry`] **by value** and returns the loaded
    /// generation. By-value rather than by-reference so the future a caller
    /// returns does not borrow from the plan; a closure that captured
    /// `&ClusterEntry` would pin the plan's lifetime to the returned future for
    /// no benefit, since an entry is two `String`s and a bool.
    pub async fn install<F, Fut>(
        &self,
        plan: &ClusterPlan,
        mut stage: F,
    ) -> Result<ClusterInstall, DomainError>
    where
        F: FnMut(ClusterEntry) -> Fut,
        Fut: std::future::Future<Output = Result<Arc<LoadedGeneration>, DomainError>>,
    {
        let generation = ClusterPlanner::first_generation();
        let mut staged: Vec<(PluginId, Arc<LoadedGeneration>)> = Vec::new();
        let mut skipped: Vec<SkippedSlot> = Vec::new();

        for entry in &plan.entries {
            let entry = entry.clone();
            match stage(entry.clone()).await {
                Ok(loaded) => staged.push((entry.plugin.clone(), loaded)),
                Err(e) if entry.required => {
                    // A required slot takes the whole app down. Everything staged
                    // so far has to be told to stop: a WASM generation holds a
                    // live store until `shutdown`, and dropping the last `Arc` is
                    // not the same thing.
                    let loaded: Vec<_> = staged.iter().map(|(_, g)| g.clone()).collect();
                    abort(&loaded, self.drain_deadline_ms).await;
                    return Err(DomainError::new(
                        e.code,
                        format!(
                            "app {}: required cluster {:?} could not stage plugin {}: {}",
                            plan.app_id, entry.cluster_id, entry.declared_as, e.message
                        ),
                    ));
                }
                Err(e) => {
                    // `required = false` is the manifest author saying the app can
                    // come up without this. Dropping it is the documented
                    // behaviour, not a silent partial failure.
                    skipped.push(SkippedSlot {
                        plugin: entry.plugin.clone(),
                        declared_as: entry.declared_as.clone(),
                        reason: e.message,
                    });
                }
            }
        }

        if staged.is_empty() {
            return Err(invalid(format!(
                "app {}: every plugin slot was dropped, nothing to publish",
                plan.app_id
            )));
        }

        Ok(self.publish_batch(staged, skipped, generation).await)
    }

    /// Publish an app whose slots are already loaded.
    ///
    /// Splits [`ClusterInstaller::install`] so a caller that already holds the
    /// generations — a test, or a host that staged them earlier — does not have
    /// to wrap them in a closure that ignores its input.
    pub async fn publish(
        &self,
        plan: &ClusterPlan,
        staged: Vec<Arc<LoadedGeneration>>,
    ) -> Result<ClusterInstall, DomainError> {
        if staged.len() != plan.len() {
            // Nothing was published, so shut the staged generations back down
            // rather than leaving live workers with no route to them.
            abort(&staged, self.drain_deadline_ms).await;
            return Err(invalid(format!(
                "app {}: {} generations staged for {} plan slots",
                plan.app_id,
                staged.len(),
                plan.len()
            )));
        }

        let batch: Vec<(PluginId, Arc<LoadedGeneration>)> = plan
            .entries
            .iter()
            .zip(staged)
            .map(|(entry, loaded)| (entry.plugin.clone(), loaded))
            .collect();

        Ok(self
            .publish_batch(batch, Vec::new(), ClusterPlanner::first_generation())
            .await)
    }

    /// One lock, one write, whole app; then retire what it displaced.
    async fn publish_batch(
        &self,
        batch: Vec<(PluginId, Arc<LoadedGeneration>)>,
        skipped: Vec<SkippedSlot>,
        generation: Generation,
    ) -> ClusterInstall {
        // `published` and the result of `atomic_publish` are index-aligned:
        // `atomic_publish` returns one slot per entry, in batch order.
        let published: Vec<PluginId> = batch.iter().map(|(p, _)| p.clone()).collect();
        let displaced = self.routes.atomic_publish(batch);

        // The route already points at the new app, so retiring the old one
        // cannot strand traffic — and leaving it running would keep a whole
        // previous generation of the app resident forever.
        let mut displaced_ids = Vec::new();
        for (plugin, old) in published.iter().zip(displaced) {
            let Some(old) = old else { continue };
            let _ = old.runtime().drain(self.drain_deadline_ms).await;
            old.runtime().shutdown().await;
            displaced_ids.push(plugin.clone());
        }

        ClusterInstall {
            published,
            skipped,
            generation,
            displaced: displaced_ids,
        }
    }
}

/// Shut every staged generation down, ignoring failures.
///
/// Best-effort by design: this runs on a path that is already refusing, and one
/// generation that will not shut down must not prevent the others from being
/// told to stop.
async fn abort(staged: &[Arc<LoadedGeneration>], deadline_ms: u64) {
    for generation in staged {
        let _ = generation.runtime().drain(deadline_ms).await;
        generation.runtime().shutdown().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hot_swap::GenerationRuntime;
    use sandtree_model::error::DomainError;
    use sandtree_sdk::ports::{ProviderHealth, ProviderInstance};
    use sandtree_sdk::wit::WitDescriptor;
    use serde_json::Value as Json;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// Counts this generation's own `shutdown` calls.
    ///
    /// Per-instance rather than a `static`: tests run concurrently, so a
    /// process-global counter makes one test's shutdowns show up in another's
    /// assertion, and the failures look like lifecycle bugs that are not there.
    #[derive(Debug, Default)]
    struct Shutdowns(AtomicU32);

    impl Shutdowns {
        fn take(&self) -> u32 {
            self.0.swap(0, Ordering::SeqCst)
        }
    }

    struct Stub {
        generation: u64,
        shutdowns: Arc<Shutdowns>,
    }

    #[async_trait::async_trait]
    impl GenerationRuntime for Stub {
        fn generation(&self) -> Generation {
            Generation(self.generation)
        }
        fn descriptor(&self) -> WitDescriptor {
            WitDescriptor {
                plugin_id: "stub".into(),
                version: "1.0.0".into(),
                state_schema_version: 1,
            }
        }
        async fn init(&self, _: &Json) -> Result<(), DomainError> {
            Ok(())
        }
        async fn health(&self) -> Result<ProviderHealth, DomainError> {
            Ok(ProviderHealth::Healthy)
        }
        async fn prepare_upgrade(&self, _: &str) -> Result<Vec<u8>, DomainError> {
            Ok(Vec::new())
        }
        async fn accept_upgrade(&self, _: &str, _: &[u8]) -> Result<(), DomainError> {
            Ok(())
        }
        async fn drain(&self, _: u64) -> Result<(), DomainError> {
            Ok(())
        }
        async fn shutdown(&self) {
            self.shutdowns.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn manifest(clusters: &str) -> AppManifest {
        AppManifest::from_toml(&format!(
            "schema_version = 1\napp_id = \"test.app\"\nversion = \"1.0.0\"\n{clusters}"
        ))
        .expect("valid app manifest")
    }

    /// A routable generation plus the per-generation counter a test asserts on.
    fn loaded(plugin: &PluginId, n: u64) -> (Arc<LoadedGeneration>, Arc<Shutdowns>) {
        let shutdowns = Arc::new(Shutdowns::default());
        let generation = Arc::new(LoadedGeneration::new(
            plugin.clone(),
            Generation(n),
            Arc::new(Stub {
                generation: n,
                shutdowns: shutdowns.clone(),
            }),
            ProviderInstance::empty(plugin.clone()),
        ));
        (generation, shutdowns)
    }

    /// A generation whose `shutdown` lands in a caller-supplied counter.
    fn counted(plugin: &PluginId, n: u64, shutdowns: Arc<Shutdowns>) -> Arc<LoadedGeneration> {
        Arc::new(LoadedGeneration::new(
            plugin.clone(),
            Generation(n),
            Arc::new(Stub {
                generation: n,
                shutdowns,
            }),
            ProviderInstance::empty(plugin.clone()),
        ))
    }

    #[test]
    fn plan_order_is_deterministic_regardless_of_manifest_order() {
        // Determinism is the property: if two runs of the same manifest could
        // produce different orders, a staged app would not be reproducible and a
        // diff between two deployments would be unreadable.
        let a = ClusterPlanner::plan(&manifest(
            "[[clusters]]\ncluster_id = \"zeta\"\nplugins = [\"p.z\"]\n[[clusters]]\ncluster_id = \"alpha\"\nplugins = [\"p.a\"]\n",
        ))
        .unwrap();
        let b = ClusterPlanner::plan(&manifest(
            "[[clusters]]\ncluster_id = \"alpha\"\nplugins = [\"p.a\"]\n[[clusters]]\ncluster_id = \"zeta\"\nplugins = [\"p.z\"]\n",
        ))
        .unwrap();
        assert_eq!(a, b, "manifest order must not change the plan");
        assert_eq!(
            a.entries
                .iter()
                .map(|e| e.cluster_id.as_str())
                .collect::<Vec<_>>(),
            vec!["alpha", "zeta"]
        );
    }

    #[test]
    fn a_plugin_in_two_clusters_is_staged_once() {
        // Staging it twice would create two generations of one plugin, and the
        // second route write would displace the first with nothing to show for
        // it. The plan keeps the first occurrence.
        let plan = ClusterPlanner::plan(&manifest(
            "[[clusters]]\ncluster_id = \"a\"\nplugins = [\"p.one\", \"p.shared\"]\n[[clusters]]\ncluster_id = \"b\"\nplugins = [\"p.shared\"]\n",
        ))
        .unwrap();
        assert_eq!(plan.len(), 2);
        assert_eq!(plan.entries[1].declared_as, "p.shared");
        assert_eq!(plan.entries[1].cluster_id, "a");
    }

    #[test]
    fn an_unannotated_cluster_is_required() {
        // Defaulting the other way would let an app come up silently missing the
        // cluster its author never annotated.
        let plan = ClusterPlanner::plan(&manifest(
            "[[clusters]]\ncluster_id = \"a\"\nplugins = [\"p.one\"]\n",
        ))
        .unwrap();
        assert!(plan.entries[0].required);
        assert!(plan.has_required());
    }

    #[tokio::test]
    async fn a_failed_required_slot_publishes_nothing() {
        // The core atomicity property. `p.two` cannot be staged, so `p.one` —
        // which staged fine — must not be routed either.
        let plan = ClusterPlanner::plan(&manifest(
            "[[clusters]]\ncluster_id = \"a\"\nplugins = [\"p.one\", \"p.two\"]\n",
        ))
        .unwrap();
        let routes = Arc::new(RouteTable::new());
        let installer = ClusterInstaller::new(routes.clone());
        let staged_ok = Arc::new(Shutdowns::default());
        let counter = Arc::clone(&staged_ok);

        let result = installer
            .install(&plan, move |entry| {
                let counts = Arc::clone(&counter);
                async move {
                    if entry.declared_as == "p.two" {
                        Err(DomainError::new(
                            ErrorCode::PLUGIN_HEALTH_FAILED,
                            "engine unreachable",
                        ))
                    } else {
                        Ok(counted(&entry.plugin, 1, counts))
                    }
                }
            })
            .await;

        assert!(result.is_err());
        assert!(
            routes.is_empty(),
            "a partially staged app must not be routed at all"
        );
        // `p.one` staged successfully and must still be retired, or it stays
        // resident as a worker nothing can reach.
        assert_eq!(
            staged_ok.take(),
            1,
            "the successfully staged generation must be shut down on abort"
        );
    }

    #[tokio::test]
    async fn a_failed_optional_slot_is_dropped_not_fatal() {
        // `required = false` is the manifest author saying the app can come up
        // without this cluster. The refusal is reported, not swallowed.
        let plan = ClusterPlanner::plan(&manifest(
            "[[clusters]]\ncluster_id = \"core\"\nplugins = [\"p.core\"]\n[[clusters]]\ncluster_id = \"extras\"\nplugins = [\"p.optional\"]\nrequired = false\n",
        ))
        .unwrap();
        assert!(!plan.entries[1].required);

        let routes = Arc::new(RouteTable::new());
        let installer = ClusterInstaller::new(routes.clone());

        let install = installer
            .install(&plan, |entry| async move {
                if entry.declared_as == "p.optional" {
                    Err(DomainError::new(
                        ErrorCode::PLUGIN_HEALTH_FAILED,
                        "docker daemon absent",
                    ))
                } else {
                    Ok(loaded(&entry.plugin, 1).0)
                }
            })
            .await
            .expect("the required slot staged, so the app installs");

        assert_eq!(install.published.len(), 1);
        assert_eq!(install.published[0], plan.entries[0].plugin);
        assert_eq!(install.skipped.len(), 1);
        assert_eq!(install.skipped[0].declared_as, "p.optional");
        assert!(
            install.skipped[0].reason.contains("docker daemon absent"),
            "the operator must be told why: {:?}",
            install.skipped[0]
        );
    }

    #[tokio::test]
    async fn an_app_where_every_slot_is_optional_and_all_fail_is_refused() {
        // Dropping everything is not "coming up without the extras" — it is an
        // app with no plugins, which would look healthy and do nothing.
        let plan = ClusterPlanner::plan(&manifest(
            "[[clusters]]\ncluster_id = \"extras\"\nplugins = [\"p.a\", \"p.b\"]\nrequired = false\n",
        ))
        .unwrap();
        let routes = Arc::new(RouteTable::new());
        let installer = ClusterInstaller::new(routes.clone());

        let result = installer
            .install(&plan, |_entry| async {
                Err::<Arc<LoadedGeneration>, _>(DomainError::new(
                    ErrorCode::PLUGIN_HEALTH_FAILED,
                    "no",
                ))
            })
            .await;

        assert!(result.is_err());
        assert!(routes.is_empty());
    }

    #[tokio::test]
    async fn a_complete_app_is_published_together() {
        let plan = ClusterPlanner::plan(&manifest(
            "[[clusters]]\ncluster_id = \"a\"\nplugins = [\"p.one\", \"p.two\"]\n",
        ))
        .unwrap();
        let routes = Arc::new(RouteTable::new());
        let installer = ClusterInstaller::new(routes.clone());

        let install = installer
            .install(&plan, |entry| async move { Ok(loaded(&entry.plugin, 1).0) })
            .await
            .expect("every slot staged");

        assert_eq!(install.published.len(), 2);
        assert!(install.skipped.is_empty());
        assert!(install.displaced.is_empty());
        assert_eq!(routes.len(), 2);
        for entry in &plan.entries {
            assert_eq!(
                routes.current_generation(&entry.plugin),
                Some(Generation(1)),
                "{} should be serving",
                entry.declared_as
            );
        }
    }

    #[tokio::test]
    async fn the_whole_app_shares_one_generation_number() {
        // "Which version of the app is running" has to be answerable without
        // walking every plugin id, so the app is one generation.
        let plan = ClusterPlanner::plan(&manifest(
            "[[clusters]]\ncluster_id = \"a\"\nplugins = [\"p.one\", \"p.two\"]\n",
        ))
        .unwrap();
        let routes = Arc::new(RouteTable::new());
        let installer = ClusterInstaller::new(routes.clone());
        installer
            .install(&plan, |entry| async move { Ok(loaded(&entry.plugin, 1).0) })
            .await
            .unwrap();

        let numbers: Vec<_> = plan
            .entries
            .iter()
            .filter_map(|e| routes.current_generation(&e.plugin))
            .collect();
        assert_eq!(numbers.len(), 2);
        assert!(numbers.windows(2).all(|w| w[0] == w[1]));
    }

    #[tokio::test]
    async fn reinstalling_retires_the_generation_it_displaced() {
        // A previous generation left resident keeps a whole copy of the old app
        // alive with nothing routing to it.
        let plan = ClusterPlanner::plan(&manifest(
            "[[clusters]]\ncluster_id = \"a\"\nplugins = [\"p.one\", \"p.two\"]\n",
        ))
        .unwrap();
        let routes = Arc::new(RouteTable::new());
        let installer = ClusterInstaller::new(routes.clone());

        // Both first-install generations share one counter: the point is that
        // *each* displaced generation is retired, and a shared counter proves it
        // by summing. Building a second set of generations just to read their
        // counters would assert about objects that were never installed.
        let first_installs = Arc::new(Shutdowns::default());
        let counter = Arc::clone(&first_installs);
        installer
            .install(&plan, move |entry| {
                let counts = Arc::clone(&counter);
                async move { Ok(counted(&entry.plugin, 1, counts)) }
            })
            .await
            .unwrap();
        assert_eq!(first_installs.take(), 0, "nothing retired on first install");

        let second = installer
            .install(&plan, |entry| async move { Ok(loaded(&entry.plugin, 2).0) })
            .await
            .unwrap();

        assert_eq!(second.displaced.len(), 2);
        assert_eq!(
            first_installs.take(),
            2,
            "both displaced generations must be shut down"
        );
        for entry in &plan.entries {
            assert_eq!(
                routes.current_generation(&entry.plugin),
                Some(Generation(2))
            );
        }
    }

    #[tokio::test]
    async fn publishing_the_wrong_number_of_generations_is_refused() {
        // Guard against a caller whose closure silently staged fewer plugins
        // than the plan promised: the app would otherwise go live with a hole in
        // it, which is exactly what the plan exists to prevent.
        let plan = ClusterPlanner::plan(&manifest(
            "[[clusters]]\ncluster_id = \"a\"\nplugins = [\"p.one\", \"p.two\"]\n",
        ))
        .unwrap();
        let routes = Arc::new(RouteTable::new());
        let installer = ClusterInstaller::new(routes.clone());
        let (stray, stray_counts) = loaded(&plan.entries[0].plugin, 1);

        let result = installer.publish(&plan, vec![stray]).await;

        assert!(result.is_err());
        assert!(routes.is_empty());
        assert_eq!(
            stray_counts.take(),
            1,
            "the stray generation must be retired"
        );
    }

    #[test]
    fn an_app_that_resolves_to_no_plugins_is_refused() {
        // Defensive: `AppManifest::from_json` already rejects an empty
        // `plugins` array, so reaching here means the two drifted apart.
        let m = AppManifest {
            schema_version: 1,
            app_id: "test.app".into(),
            version: "1.0.0".into(),
            clusters: vec![],
        };
        assert!(ClusterPlanner::plan(&m).is_err());
    }

    #[test]
    fn plan_helpers_agree_with_the_entries() {
        let plan = ClusterPlanner::plan(&manifest(
            "[[clusters]]\ncluster_id = \"a\"\nplugins = [\"p.one\"]\n",
        ))
        .unwrap();
        assert_eq!(plan.plugins(), vec![&plan.entries[0].plugin]);
        assert!(!plan.is_empty());
    }

    #[test]
    fn skipped_slots_report_the_manifest_name_not_only_the_hash() {
        // `PluginId` is a hash; an operator reading a skip needs to see what
        // they wrote in the manifest.
        let skipped = SkippedSlot {
            plugin: PluginId::derive(&["p.optional"]),
            declared_as: "p.optional".into(),
            reason: "boom".into(),
        };
        assert_eq!(skipped.declared_as, "p.optional");
        assert!(format!("{skipped:?}").contains("p.optional"));
    }
}
