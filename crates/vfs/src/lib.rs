//! SandTree VFS: canonical `stfs://` addressing, path confinement, mount model
//! and read quotas (FR-014, FR-015, FR-040, FR-041; NFR-S05).
//!
//! This crate is pure logic by design: no filesystem access, no async runtime, no
//! provider types. Everything here is a *precondition* that must hold before a
//! provider is asked to touch anything. The second half of the containment
//! guarantee (canonicalization after symlink/reparse resolution) can only happen
//! inside the provider, which is why [`FileProvider::write`] in the SDK demands
//! it explicitly.

#![deny(missing_docs)]

pub mod confinement;
pub mod error;
pub mod mount;
pub mod path;
pub mod read;
pub mod uri;

pub use error::UriError;
pub use mount::{MountError, MountMode, MountRecord, MountRegistry};
pub use path::{WorkspacePath, MAX_PATH_BYTES, MAX_SEGMENTS, MAX_SEGMENT_BYTES};
pub use read::{plan_read, ReadWindow, DEFAULT_MAX_SINGLE_FILE, DEFAULT_MAX_TOTAL_BYTES};
pub use uri::{percent_decode, WorkspaceUri, SCHEME};

/// Sanity test of the crate's own invariants; runs under `cargo test`.
#[cfg(test)]
mod integration_smoke {
    use super::*;

    #[test]
    fn parse_reserialize_resolve_flow() {
        let res = sandtree_model::id::ResourceId::derive(&["smoke"]);
        let uri = WorkspaceUri::parse(&format!("{SCHEME}{}/src/main.rs", res.as_str())).unwrap();
        let mut reg = MountRegistry::new();
        let root = format!("{SCHEME}{}", res.as_str());
        reg.insert(MountRecord::new(
            "root",
            res.clone(),
            None,
            root.clone(),
            MountMode::ReadOnly,
        ))
        .unwrap();
        assert!(reg.resolve(&uri).is_some());
        assert!(!reg.allows_write(&uri));
        assert_eq!(WorkspaceUri::parse(&uri.to_uri_string()).unwrap(), uri);
    }
}
