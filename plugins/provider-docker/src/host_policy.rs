//! Host-side isolation guards for the Docker provider (NFR-S06, NFR-S07).
//!
//! AGENTS.md invariant 4 ("isolation is not tradeable") forbids buying
//! observation or convenience with a host Docker socket exposure, a full-disk
//! writable mapping, or a host administrator token. A provider is exactly where
//! that mistake would be tempting — it is the code that *has* the privileged
//! handle — so the refusals live here as named, tested functions rather than as
//! review comments.
//!
//! None of these functions needs a Docker connection, which is why they are
//! unit-testable on a machine with no daemon running.

/// Why a bind request was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IsolationViolation {
    /// The requested bind source is the host Docker socket.
    #[error("binding the host docker socket into a guest is forbidden (NFR-S06)")]
    HostDockerSocket,
    /// The requested bind source is a drive root, i.e. effectively full-disk.
    #[error("binding a drive root is forbidden (NFR-S06): {0}")]
    DriveRoot(String),
    /// The requested bind source is outside the allow-listed workspace roots.
    #[error("bind source {0} is outside the configured workspace roots")]
    OutsideWorkspace(String),
    /// A guest-facing call asked for host-namespace networking.
    #[error("joining the host network namespace is forbidden (NFR-S07)")]
    HostNetworkNamespace,
    /// A privileged (administrator) container was requested.
    #[error("privileged / host-administrator containers are forbidden (NFR-S06)")]
    PrivilegedContainer,
}

/// Path fragments that indicate a Docker socket.
const SOCKET_MARKERS: &[&str] = &[
    "docker_engine",
    "docker.sock",
    "docker.sock.raw",
    "containers/docker",
    "/var/run/docker",
];

/// Decide whether a bind-mount source may be exposed to a guest.
///
/// `workspace_roots` is the set of host directories SandTree was configured to
/// share. Anything outside it, any drive root, and any Docker socket is refused
/// (NFR-S06, NFR-S08).
pub fn authorize_bind_source(
    source: &str,
    workspace_roots: &[String],
) -> Result<(), IsolationViolation> {
    let normalized = source.replace('\\', "/").to_lowercase();

    if SOCKET_MARKERS.iter().any(|m| normalized.contains(m)) {
        return Err(IsolationViolation::HostDockerSocket);
    }

    // `C:/`, `C:`, `//host/share/` — a drive root is full-disk access in
    // everything but name. The test is whether *every* path segment is either
    // empty or a bare drive letter; `C:/workspaces/demo` has a real segment and
    // is an ordinary shareable subdirectory.
    let without_scheme = normalized
        .strip_prefix("//")
        .map(|rest| rest.to_string())
        .unwrap_or_else(|| normalized.clone());
    let segments: Vec<&str> = without_scheme
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();
    let is_drive_root = !segments.is_empty()
        && segments.iter().all(|seg| {
            let seg = seg.strip_suffix(':').unwrap_or(seg);
            seg.len() == 1 && seg.as_bytes()[0].is_ascii_lowercase()
        });
    if is_drive_root {
        return Err(IsolationViolation::DriveRoot(source.to_string()));
    }

    // A drive root is never a valid workspace root, so a misconfigured root list
    // cannot silently widen the allow-list to the whole volume (NFR-S06).
    let within_roots = workspace_roots.iter().any(|root| {
        let r = root.replace('\\', "/").trim_end_matches('/').to_lowercase();
        if is_drive_root_path(&r) {
            return false;
        }
        normalized == r || normalized.starts_with(&format!("{r}/"))
    });
    if within_roots {
        Ok(())
    } else {
        Err(IsolationViolation::OutsideWorkspace(source.to_string()))
    }
}

/// Whether a normalized path is exactly a drive root (`c:` or `c:/`).
fn is_drive_root_path(normalized: &str) -> bool {
    let seg = normalized.trim_end_matches('/');
    let seg = seg.strip_suffix(':').unwrap_or(seg);
    seg.len() == 1 && seg.as_bytes()[0].is_ascii_lowercase()
}

/// Refuse guest containers that would join the host network namespace.
///
/// `--network=host` is Docker's own escape hatch and would let a guest reach
/// host-only services (NFR-S07).
pub fn authorize_network_mode(mode: &str) -> Result<(), IsolationViolation> {
    let m = mode.trim().to_ascii_lowercase();
    if m == "host" {
        return Err(IsolationViolation::HostNetworkNamespace);
    }
    Ok(())
}

/// Refuse privileged / administrator-equivalent container requests (NFR-S06).
pub fn authorize_privilege(privileged: bool) -> Result<(), IsolationViolation> {
    if privileged {
        return Err(IsolationViolation::PrivilegedContainer);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roots() -> Vec<String> {
        vec![
            "C:/SandTree/workspaces".to_string(),
            "D:/shared".to_string(),
        ]
    }

    #[test]
    fn host_docker_socket_is_never_shareable() {
        // NFR-S06: this is the single most important refusal in the file.
        for src in [
            "npipe:////./pipe/docker_engine",
            "\\\\.\\pipe\\docker_engine",
            "/var/run/docker.sock",
            "/run/docker.sock.raw",
        ] {
            assert_eq!(
                authorize_bind_source(src, &roots()),
                Err(IsolationViolation::HostDockerSocket),
                "{src} must be refused"
            );
        }
    }

    #[test]
    fn drive_roots_are_refused_even_if_listed_as_a_root() {
        // Listing `C:/` as a workspace root must not become full-disk access.
        for src in ["C:/", "c:/", "C:", "c:"] {
            assert_eq!(
                authorize_bind_source(src, &["C:/".to_string()]),
                Err(IsolationViolation::DriveRoot(src.into())),
                "{src} must be refused as a drive root"
            );
        }

        // A subdirectory of a drive is not itself a drive root; it falls through
        // to the workspace-allow-list check.
        assert!(matches!(
            authorize_bind_source("C:/Windows", &["C:/".to_string()]),
            Err(IsolationViolation::OutsideWorkspace(_))
        ));
    }

    #[test]
    fn configured_workspace_roots_are_allowed() {
        assert!(authorize_bind_source("C:/SandTree/workspaces/demo", &roots()).is_ok());
        assert!(authorize_bind_source("c:\\sandtree\\workspaces\\demo", &roots()).is_ok());
        assert!(authorize_bind_source("D:/shared", &roots()).is_ok());
    }

    #[test]
    fn sibling_prefix_paths_are_not_inside_a_root() {
        // `workspaces-private` must not pass as `workspaces` (same component-boundary
        // rule the VFS crate applies).
        assert!(matches!(
            authorize_bind_source("C:/SandTree/workspaces-private/x", &roots()),
            Err(IsolationViolation::OutsideWorkspace(_))
        ));
        assert!(matches!(
            authorize_bind_source("C:/Windows/System32", &roots()),
            Err(IsolationViolation::OutsideWorkspace(_))
        ));
    }

    #[test]
    fn host_network_namespace_is_refused() {
        assert_eq!(
            authorize_network_mode("host"),
            Err(IsolationViolation::HostNetworkNamespace)
        );
        for ok in ["bridge", "none", "my-net", ""] {
            assert!(authorize_network_mode(ok).is_ok());
        }
    }

    #[test]
    fn privileged_containers_are_refused() {
        assert_eq!(
            authorize_privilege(true),
            Err(IsolationViolation::PrivilegedContainer)
        );
        assert!(authorize_privilege(false).is_ok());
    }
}
