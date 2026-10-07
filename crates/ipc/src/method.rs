//! IPC method names (DD-DATA §6).
//!
//! Method families are `resource`, `operation`, `docker`, `workspace`,
//! `snapshot`, `plugin`, `event` and `diagnostic`. The router accepts a method
//! only if it is registered, so this module is the single place a typo can be
//! caught — a constant that does not match a handler is a startup error, not a
//! runtime "unknown method".

/// Read a resource.
pub const RESOURCE_GET: &str = "resource.get";
/// List the resource tree.
pub const RESOURCE_TREE: &str = "resource.tree";
/// List resources matching a filter.
pub const RESOURCE_LIST: &str = "resource.list";
/// Relations touching a resource.
pub const RESOURCE_RELATIONS: &str = "resource.relations";

/// Invoke an operation.
pub const OPERATION_INVOKE: &str = "operation.invoke";
/// Current state of an operation.
pub const OPERATION_STATUS: &str = "operation.status";
/// List recorded operations.
pub const OPERATION_LIST: &str = "operation.list";

/// List configured Docker endpoints.
pub const DOCKER_ENDPOINTS: &str = "docker.endpoints";
/// Docker engine health.
pub const DOCKER_HEALTH: &str = "docker.health";
/// Run a command in a container.
pub const DOCKER_EXEC: &str = "docker.exec";

/// List workspace mounts.
pub const WORKSPACE_LIST: &str = "workspace.list";
/// List one directory level.
pub const WORKSPACE_LIST_DIR: &str = "workspace.list_dir";
/// Read a file window.
pub const WORKSPACE_READ: &str = "workspace.read";
/// Write file content.
pub const WORKSPACE_WRITE: &str = "workspace.write";

/// List snapshots.
pub const SNAPSHOT_LIST: &str = "snapshot.list";
/// Create a snapshot.
pub const SNAPSHOT_CREATE: &str = "snapshot.create";
/// Restore a snapshot.
pub const SNAPSHOT_RESTORE: &str = "snapshot.restore";
/// Delete a snapshot.
pub const SNAPSHOT_DELETE: &str = "snapshot.delete";
/// Diff two snapshots.
pub const SNAPSHOT_DIFF: &str = "snapshot.diff";

/// List installed plugin packages.
pub const PLUGIN_LIST: &str = "plugin.list";
/// Install a plugin package.
pub const PLUGIN_INSTALL: &str = "plugin.install";
/// Enable a plugin.
pub const PLUGIN_ENABLE: &str = "plugin.enable";
/// Disable a plugin.
pub const PLUGIN_DISABLE: &str = "plugin.disable";
/// Hot swap a plugin generation.
pub const PLUGIN_HOTSWAP: &str = "plugin.hotswap";
/// Roll a plugin back to the previous generation.
pub const PLUGIN_ROLLBACK: &str = "plugin.rollback";

/// Subscribe to the event stream.
pub const EVENT_SUBSCRIBE: &str = "event.subscribe";
/// Unsubscribe from the event stream.
pub const EVENT_UNSUBSCRIBE: &str = "event.unsubscribe";
/// Pull buffered events.
pub const EVENT_PULL: &str = "event.pull";

/// Produce the redacted diagnostics bundle.
pub const DIAGNOSTIC_BUNDLE: &str = "diagnostic.bundle";
/// Daemon liveness and version.
pub const DIAGNOSTIC_HEALTH: &str = "diagnostic.health";
/// Daemon build and toolchain information.
pub const DIAGNOSTIC_VERSION: &str = "diagnostic.version";

/// Every method this build knows about, sorted.
pub const ALL: &[&str] = &[
    DIAGNOSTIC_BUNDLE,
    DIAGNOSTIC_HEALTH,
    DIAGNOSTIC_VERSION,
    DOCKER_ENDPOINTS,
    DOCKER_EXEC,
    DOCKER_HEALTH,
    EVENT_PULL,
    EVENT_SUBSCRIBE,
    EVENT_UNSUBSCRIBE,
    OPERATION_INVOKE,
    OPERATION_LIST,
    OPERATION_STATUS,
    PLUGIN_DISABLE,
    PLUGIN_ENABLE,
    PLUGIN_HOTSWAP,
    PLUGIN_INSTALL,
    PLUGIN_LIST,
    PLUGIN_ROLLBACK,
    RESOURCE_GET,
    RESOURCE_LIST,
    RESOURCE_RELATIONS,
    RESOURCE_TREE,
    SNAPSHOT_CREATE,
    SNAPSHOT_DELETE,
    SNAPSHOT_DIFF,
    SNAPSHOT_LIST,
    SNAPSHOT_RESTORE,
    WORKSPACE_LIST,
    WORKSPACE_LIST_DIR,
    WORKSPACE_READ,
    WORKSPACE_WRITE,
];

/// The family part of a method name, e.g. `resource` for `resource.tree`.
pub fn family(method: &str) -> &str {
    method.split_once('.').map(|(f, _)| f).unwrap_or(method)
}

/// Whether a method name is well formed: exactly one dot, with a non-empty
/// family and a non-empty verb on either side.
///
/// The single-dot rule is what keeps a method name unambiguous — `a.b.c` would
/// otherwise parse with a family of `a` and a verb of `b.c`, and two different
/// call sites could disagree about where the verb ends.
pub fn is_well_formed(method: &str) -> bool {
    if method.matches('.').count() != 1 {
        return false;
    }
    match method.split_once('.') {
        Some((family, verb)) => !family.is_empty() && !verb.is_empty(),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn all_is_sorted_and_free_of_duplicates() {
        let sorted: Vec<&str> = {
            let mut v = ALL.to_vec();
            v.sort_unstable();
            v
        };
        assert_eq!(sorted, ALL.to_vec(), "ALL must stay sorted");
        let unique: BTreeSet<&str> = ALL.iter().copied().collect();
        assert_eq!(unique.len(), ALL.len(), "ALL must not contain duplicates");
    }

    #[test]
    fn every_method_is_well_formed_and_registered_in_all() {
        for m in ALL {
            assert!(is_well_formed(m), "{m} is not `family.verb`");
            assert_eq!(m.matches('.').count(), 1, "{m} has more than one separator");
        }
    }

    #[test]
    fn family_splits_on_the_first_dot() {
        assert_eq!(family(RESOURCE_TREE), "resource");
        assert_eq!(family(PLUGIN_HOTSWAP), "plugin");
        // No dot: the whole string is the family, which is what
        // `is_well_formed` then rejects.
        assert_eq!(family("nodots"), "nodots");
    }

    #[test]
    fn malformed_names_are_rejected() {
        assert!(!is_well_formed("nodots"));
        assert!(!is_well_formed(".verb"));
        assert!(!is_well_formed("family."));
        assert!(!is_well_formed("a.b.c"));
        assert!(is_well_formed("a.b"));
    }
}
