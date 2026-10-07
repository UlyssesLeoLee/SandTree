//! Built-in worlds, ready to load without touching the filesystem.
//!
//! Four fixtures, one per thing a control-plane regression most often needs:
//! a working provider, a provider that is entirely unavailable, a scan that
//! dies halfway, and a provider whose operations fail.
//!
//! They are `const` strings rather than files on disk so that
//! `ScriptedWorld::from_json_str` can load them from anywhere — including from
//! a test in another crate — with no path resolution and no environment
//! dependence (NFR-O04).
//!
//! Every world uses the same fixed timestamp, `2026-10-07T00:00:00Z`. A fixture
//! that stamped a real clock here would defeat the whole crate.
//!
//! Containment note: no world below carries a host path, a credential or a
//! secret. Symlink targets are relative and point at paths *inside* the served
//! subtree — except the deliberate escape in [`ESCAPING_SYMLINK_WORLD`], which
//! is a relative `..` chain, not a host location.

use crate::fixture::{FixtureError, WorldFixture};
use crate::world::ScriptedWorld;

/// A healthy Docker-shaped world with pagination, files and exec rules.
///
/// Five resources across two pages, so a scan that stops after the first page is
/// detectable. The container workspace carries a content file, a metadata-only
/// file (the FR-077 lazy-content shape) and a read-only directory.
pub const DOCKER_WORLD: &str = r#"
{
  "schema": 1,
  "intent": "healthy docker provider: paginated discovery, scripted ops, files and exec",
  "plugin": "sandtree.provider.docker.mock",
  "version": "1.2.3",
  "kind": "provider",
  "page_size": 3,
  "resources": [
    {
      "key": "engine",
      "id_parts": ["npipe:////./pipe/docker_engine"],
      "kind": "docker-runtime",
      "name": "docker-engine",
      "state": "running",
      "capabilities": ["resource:start", "resource:stop", "resource:restart"],
      "metadata": {"endpoint_id": "ep-docker-engine"},
      "last_seen": "2026-10-07T00:00:00Z"
    },
    {
      "key": "net",
      "id_parts": ["bridge"],
      "kind": "network",
      "name": "bridge",
      "state": "running",
      "last_seen": "2026-10-07T00:00:00Z"
    },
    {
      "key": "web",
      "id_parts": ["abc123def456"],
      "kind": "container",
      "name": "web",
      "state": "running",
      "parent": "engine",
      "capabilities": ["resource:start", "resource:stop", "resource:destroy", "resource:exec"],
      "metadata": {"endpoint_id": "ep-docker-engine"},
      "last_seen": "2026-10-07T00:00:00Z"
    },
    {
      "key": "cache",
      "id_parts": ["cache789012345"],
      "kind": "container",
      "name": "cache",
      "state": "exited",
      "parent": "engine",
      "capabilities": ["resource:start", "resource:stop"],
      "metadata": {"endpoint_id": "ep-docker-engine"},
      "last_seen": "2026-10-07T00:00:00Z"
    },
    {
      "key": "nginx",
      "id_parts": ["sha256:0000beef"],
      "kind": "image",
      "name": "nginx:latest",
      "state": "running",
      "parent": "engine",
      "capabilities": [],
      "last_seen": "2026-10-07T00:00:00Z"
    }
  ],
  "relations": [
    {"from": "web", "to": "nginx", "kind": "uses-image"},
    {"from": "web", "to": "net", "kind": "attached-network"},
    {"from": "cache", "to": "nginx", "kind": "uses-image"}
  ],
  "operations": [
    {"op": "start", "outcome": {"state": "succeeded", "result": {"transition": "started"}}},
    {"op": "stop", "outcome": {"state": "succeeded", "result": {"transition": "stopped"}}},
    {"op": "destroy", "outcome": {"state": "succeeded", "result": {"transition": "destroyed"}}}
  ],
  "files": [
    {"root": "web", "path": "", "is_dir": true},
    {"root": "web", "path": "src", "is_dir": true},
    {"root": "web", "path": "src/index.html", "content": "<h1>hello</h1>", "mtime_ns": 1},
    {"root": "web", "path": "etc", "is_dir": true, "read_only": true},
    {"root": "web", "path": "etc/app.conf", "content": "port=8080", "size": 10, "mtime_ns": 2},
    {"root": "web", "path": "build.log", "size": 4096, "mtime_ns": 3}
  ],
  "exec": [
    {
      "resource": "web",
      "argv": ["cat", "/etc/hostname"],
      "exit_code": 0,
      "stdout": "web\n",
      "stderr": ""
    },
    {
      "argv": ["false"],
      "exit_code": 1,
      "stderr": "scripted failure"
    }
  ]
}
"#;

/// A provider that is entirely unavailable (fault mode 4).
///
/// Every port call must fail; `health` must still *report* the state rather than
/// raise it (ADR-OBS-001).
pub const UNAVAILABLE_WORLD: &str = r#"
{
  "schema": 1,
  "intent": "fault mode 4: the provider is unavailable, so every port call fails",
  "plugin": "sandtree.provider.sandbox.mock",
  "health": {"state": "unavailable", "reason": "multipass is not installed on this host"},
  "unavailable_error": {
    "code": "ST-SBX-001",
    "message": "sandbox provider unavailable: multipass is not installed on this host"
  },
  "resources": [
    {
      "key": "vm",
      "id_parts": ["mock-vm"],
      "kind": "sandbox",
      "name": "win-sandbox-1",
      "state": "unknown",
      "last_seen": "2026-10-07T00:00:00Z"
    }
  ]
}
"#;

/// A scan that dies partway through pagination (fault mode 3).
///
/// Page 0 succeeds, page 1 fails, so a test can assert that the *first* page was
/// really delivered before the failure rather than the whole scan vanishing.
pub const MID_PAGE_FAILURE_WORLD: &str = r#"
{
  "schema": 1,
  "intent": "fault mode 3: discovery succeeds for the first page and then fails",
  "plugin": "sandtree.provider.docker.mock",
  "page_size": 2,
  "unavailable_error": {"code": "ST-DKR-001", "message": "docker endpoint unavailable"},
  "resources": [
    {
      "key": "a",
      "id_parts": ["a"],
      "kind": "container",
      "name": "a",
      "state": "running",
      "last_seen": "2026-10-07T00:00:00Z"
    },
    {
      "key": "b",
      "id_parts": ["b"],
      "kind": "container",
      "name": "b",
      "state": "running",
      "last_seen": "2026-10-07T00:00:00Z"
    },
    {
      "key": "c",
      "id_parts": ["c"],
      "kind": "container",
      "name": "c",
      "state": "running",
      "last_seen": "2026-10-07T00:00:00Z"
    },
    {
      "key": "d",
      "id_parts": ["d"],
      "kind": "container",
      "name": "d",
      "state": "running",
      "last_seen": "2026-10-07T00:00:00Z"
    }
  ],
  "discover_fault": {
    "fail_from_page": 1,
    "error": {"code": "ST-DKR-001", "message": "docker endpoint went away mid-scan", "detail": "http 500"}
  }
}
"#;

/// Operations that fail two different ways (fault mode 1).
///
/// `start` fails hard with a code; `stop` returns a *terminal job* that failed.
/// A test asserting on `Err` and a test asserting on
/// `OperationOutcome::Failed` therefore cover both shapes.
pub const FAILING_OPERATIONS_WORLD: &str = r#"
{
  "schema": 1,
  "intent": "fault mode 1: one operation fails hard, another fails as a terminal job",
  "plugin": "sandtree.provider.docker.mock",
  "resources": [
    {
      "key": "busy",
      "id_parts": ["busy"],
      "kind": "container",
      "name": "busy",
      "state": "running",
      "capabilities": ["resource:start", "resource:stop", "resource:destroy"],
      "last_seen": "2026-10-07T00:00:00Z"
    },
    {
      "key": "locked",
      "id_parts": ["locked"],
      "kind": "volume",
      "name": "locked",
      "state": "running",
      "capabilities": [],
      "last_seen": "2026-10-07T00:00:00Z"
    }
  ],
  "operations": [
    {
      "op": "start",
      "error": {"code": "ST-DKR-003", "message": "container busy", "detail": "device or resource busy"}
    },
    {"op": "stop", "outcome": {"state": "failed", "code": "ST-DKR-003", "result": {"reason": "locked"}}}
  ]
}
"#;

/// A workspace served under a subtree, with a symlink that escapes it.
///
/// The symlink is a relative `..` chain — the shape a real mount escape takes —
/// so the provider's own post-resolution check is what has to stop it
/// (NFR-S05).
pub const ESCAPING_SYMLINK_WORLD: &str = r#"
{
  "schema": 1,
  "intent": "NFR-S05: a symlink and a subtree boundary that must both refuse an escape",
  "plugin": "sandtree.provider.docker.mock",
  "resources": [
    {
      "key": "box",
      "id_parts": ["box"],
      "kind": "container",
      "name": "box",
      "state": "running",
      "vfs_root": "workspace",
      "last_seen": "2026-10-07T00:00:00Z"
    }
  ],
  "files": [
    {"root": "box", "path": "workspace", "is_dir": true},
    {"root": "box", "path": "workspace/app", "is_dir": true},
    {"root": "box", "path": "workspace/app/ok.txt", "content": "inside", "mtime_ns": 1},
    {"root": "box", "path": "workspace/out", "symlink_target": "../../secrets", "mtime_ns": 2},
    {"root": "box", "path": "secrets", "is_dir": true},
    {"root": "box", "path": "secrets/key.pem", "size": 64, "mtime_ns": 3}
  ]
}
"#;

/// A command whose output is longer than the capture cap.
///
/// Used to prove the cap is enforced by the provider rather than asserted by the
/// fixture.
pub const LARGE_OUTPUT_WORLD: &str = r#"
{
  "schema": 1,
  "intent": "exec output exceeding the capture cap must come back truncated",
  "plugin": "sandtree.provider.docker.mock",
  "resources": [
    {
      "key": "noisy",
      "id_parts": ["noisy"],
      "kind": "container",
      "name": "noisy",
      "state": "running",
      "last_seen": "2026-10-07T00:00:00Z"
    }
  ],
  "exec": [
    {
      "resource": "noisy",
      "argv": ["yes"],
      "exit_code": 0,
      "stdout": "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
      "stderr": ""
    }
  ]
}
"#;

/// Every built-in world, as `(name, json)` pairs.
///
/// Used by [`crate`]'s own tests to prove none of them regressed into something
/// unloadable.
pub fn all() -> Vec<(&'static str, &'static str)> {
    vec![
        ("docker-world", DOCKER_WORLD),
        ("unavailable-world", UNAVAILABLE_WORLD),
        ("mid-page-failure-world", MID_PAGE_FAILURE_WORLD),
        ("failing-operations-world", FAILING_OPERATIONS_WORLD),
        ("escaping-symlink-world", ESCAPING_SYMLINK_WORLD),
        ("large-output-world", LARGE_OUTPUT_WORLD),
    ]
}

/// Load one of the built-in worlds by name.
pub fn world(name: &str) -> Result<ScriptedWorld, FixtureError> {
    let json = all()
        .into_iter()
        .find(|(n, _)| *n == name)
        .map(|(_, json)| json)
        .ok_or_else(|| FixtureError::Invalid {
            field: "name".into(),
            reason: format!(
                "unknown built-in world {name:?}; known: {:?}",
                all().iter().map(|(n, _)| *n).collect::<Vec<_>>()
            ),
        })?;
    ScriptedWorld::from_json_str(json)
}

/// Parse a built-in fixture without building a world.
///
/// Exposed so a fixture can be validated by the same rules a file would face.
pub fn fixture(name: &str) -> Result<WorldFixture, FixtureError> {
    WorldFixture::from_json_str(
        all()
            .into_iter()
            .find(|(n, _)| *n == name)
            .map(|(_, json)| json)
            .ok_or_else(|| FixtureError::Invalid {
                field: "name".into(),
                reason: format!("unknown built-in world {name:?}"),
            })?,
    )
}
