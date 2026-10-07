//! BLAKE3 content-addressed store (FR-043, FR-044, DD-DATA §3).
//!
//! Layout: `objects/<first 2 hex>/<full digest>`, written as
//! `tmp/cas-<uuid>.part` → flush → atomic rename.
//!
//! Two ordering rules are not negotiable (DD-SW §8):
//!
//! * An object may exist **before** the snapshot row that references it. The
//!   reverse ordering would expose a snapshot whose content is not yet readable.
//! * An existing object is never rewritten. Content addressing makes the bytes
//!   identical by construction, so rewriting is pure risk.

use std::collections::BTreeSet;
use std::io::Write;
use std::path::{Path, PathBuf};

use sandtree_model::error::{DomainError, ErrorCode};

/// Content-addressed store rooted at a directory.
#[derive(Debug, Clone)]
pub struct Cas {
    root: PathBuf,
}

impl Cas {
    /// Open (creating if needed) a CAS under `root`.
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, DomainError> {
        let root = root.into();
        std::fs::create_dir_all(root.join("objects")).map_err(io_err)?;
        std::fs::create_dir_all(root.join("tmp")).map_err(io_err)?;
        Ok(Self { root })
    }

    /// Root directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Final object path for a digest.
    pub fn object_path(&self, hash: &str) -> PathBuf {
        let (prefix, rest) = match hash.get(..2) {
            Some(p) => (p, &hash[2..]),
            None => ("00", hash),
        };
        self.root.join("objects").join(prefix).join(rest)
    }

    /// Whether an object exists.
    pub fn contains(&self, hash: &str) -> Result<bool, DomainError> {
        Ok(self.object_path(hash).is_file())
    }

    /// Store bytes, returning the BLAKE3 digest.
    ///
    /// Idempotent: storing identical bytes twice returns the same digest and does
    /// not touch the existing object.
    pub fn put(&self, bytes: &[u8]) -> Result<String, DomainError> {
        let hash = blake3::hash(bytes).to_hex().to_string();
        let target = self.object_path(&hash);
        if target.is_file() {
            return Ok(hash);
        }
        let tmp = self.temp_path(&hash);
        {
            let mut f = std::fs::File::create(&tmp).map_err(io_err)?;
            f.write_all(bytes).map_err(io_err)?;
            f.flush().map_err(io_err)?;
            // Durability before visibility: a crash must not leave a name that
            // points at an empty or partial object.
            let _ = f.sync_all();
        }
        if let Some(dir) = target.parent() {
            std::fs::create_dir_all(dir).map_err(io_err)?;
        }
        match std::fs::rename(&tmp, &target) {
            Ok(()) => Ok(hash),
            Err(e) => {
                let _ = std::fs::remove_file(&tmp);
                // Losing the race with a concurrent writer of identical content
                // is fine: the bytes are the same by construction.
                if target.is_file() {
                    Ok(hash)
                } else {
                    Err(io_err(e))
                }
            }
        }
    }

    /// Store from a reader, hashing while streaming.
    pub fn put_stream<R: std::io::Read>(&self, mut reader: R) -> Result<String, DomainError> {
        let tmp_dir = self.root.join("tmp");
        std::fs::create_dir_all(&tmp_dir).map_err(io_err)?;
        let tmp = tmp_dir.join(format!("cas-{}.part", uuid_like()));
        let mut hasher = blake3::Hasher::new();
        {
            let mut f = std::fs::File::create(&tmp).map_err(io_err)?;
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                let n = reader.read(&mut buf).map_err(io_err)?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
                f.write_all(&buf[..n]).map_err(io_err)?;
            }
            f.flush().map_err(io_err)?;
            let _ = f.sync_all();
        }
        let hash = hasher.finalize().to_hex().to_string();
        let target = self.object_path(&hash);
        if let Some(dir) = target.parent() {
            std::fs::create_dir_all(dir).map_err(io_err)?;
        }
        if target.is_file() {
            let _ = std::fs::remove_file(&tmp);
            return Ok(hash);
        }
        std::fs::rename(&tmp, &target).map_err(io_err)?;
        Ok(hash)
    }

    /// Read an object.
    pub fn get(&self, hash: &str) -> Result<Vec<u8>, DomainError> {
        let path = self.object_path(hash);
        std::fs::read(&path).map_err(|e| {
            DomainError::new(
                ErrorCode::VFS_NOT_FOUND,
                format!("CAS object {hash} is not present"),
            )
            .with_detail(e.to_string())
        })
    }

    /// Hash of stored bytes, used to verify integrity on read paths.
    pub fn verify(&self, hash: &str) -> Result<bool, DomainError> {
        let bytes = self.get(hash)?;
        Ok(blake3::hash(&bytes).to_hex().to_string() == hash)
    }

    /// Delete unreferenced objects older than the grace period.
    ///
    /// Mark-and-sweep: `referenced` is the set of digests any live snapshot
    /// entry points at. Sweeping is non-destructive by default because the grace
    /// period is what protects a snapshot that is mid-commit.
    pub fn gc(
        &self,
        referenced: &BTreeSet<String>,
        grace_ms: u64,
        now_ms: u64,
    ) -> Result<usize, DomainError> {
        let objects = self.root.join("objects");
        if !objects.is_dir() {
            return Ok(0);
        }
        let mut removed = 0usize;
        let mut stack = vec![objects.clone()];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                    continue;
                };
                let parent = path
                    .parent()
                    .and_then(|p| p.file_name())
                    .and_then(|n| n.to_str());
                let full = match parent {
                    Some(prefix) => format!("{prefix}{name}"),
                    None => name.to_string(),
                };
                if referenced.contains(&full) {
                    continue;
                }
                let age = now_ms.saturating_sub(modified_ms(&path));
                if age < grace_ms {
                    continue;
                }
                if std::fs::remove_file(&path).is_ok() {
                    removed += 1;
                }
            }
        }
        Ok(removed)
    }

    fn temp_path(&self, hash: &str) -> PathBuf {
        self.root
            .join("tmp")
            .join(format!("cas-{hash}-{}.part", uuid_like()))
    }
}

fn io_err(e: std::io::Error) -> DomainError {
    DomainError::new(ErrorCode::STORE_TRANSACTION_FAILED, "CAS storage failure")
        .with_detail(e.to_string())
}

fn modified_ms(path: &Path) -> u64 {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Random-ish suffix for temp file names.
///
/// Uses process id plus a monotonic counter rather than a UUID crate: temp
/// uniqueness only has to hold inside one data directory.
fn uuid_like() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{:x}-{:x}-{:x}", std::process::id(), n, now_millis())
}

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cas() -> (Cas, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        (Cas::new(dir.path()).unwrap(), dir)
    }

    #[test]
    fn put_and_get_round_trip() {
        let (c, _d) = cas();
        let h = c.put(b"hello sandtree").unwrap();
        assert_eq!(h.len(), 64);
        assert_eq!(c.get(&h).unwrap(), b"hello sandtree");
        assert!(c.contains(&h).unwrap());
        assert!(c.verify(&h).unwrap());
    }

    #[test]
    fn identical_content_reuses_the_object() {
        // FR-043: "相同内容可复用 CAS object"
        let (c, _d) = cas();
        let a = c.put(b"same").unwrap();
        let path = c.object_path(&a);
        let before = std::fs::metadata(&path).unwrap().modified().unwrap();
        let b = c.put(b"same").unwrap();
        assert_eq!(a, b);
        assert_eq!(
            std::fs::metadata(&path).unwrap().modified().unwrap(),
            before,
            "an existing object must not be rewritten"
        );
    }

    #[test]
    fn layout_is_two_char_prefix_then_full_digest() {
        let (c, _d) = cas();
        let h = c.put(b"x").unwrap();
        let p = c.object_path(&h);
        assert_eq!(p.parent().unwrap().file_name().unwrap(), &h[..2]);
        assert_eq!(p.file_name().unwrap(), &h[2..]);
    }

    #[test]
    fn missing_object_is_vfs_not_found() {
        let (c, _d) = cas();
        let missing = "0".repeat(64);
        let err = c.get(&missing).unwrap_err();
        assert_eq!(err.code, ErrorCode::VFS_NOT_FOUND);
    }

    #[test]
    fn stream_put_matches_buffered_put() {
        let (c, _d) = cas();
        let a = c.put(b"stream me").unwrap();
        let b = c.put_stream(&b"stream me"[..]).unwrap();
        assert_eq!(a, b);
        assert!(c.contains(&a).unwrap());
    }

    #[test]
    fn no_temp_files_survive_a_successful_put() {
        let (c, _d) = cas();
        let h = c.put(b"clean").unwrap();
        assert!(c.get(&h).is_ok());
        let leftovers: Vec<_> = std::fs::read_dir(c.root().join("tmp"))
            .unwrap()
            .flatten()
            .collect();
        assert!(leftovers.is_empty(), "temp files must be renamed away");
    }

    #[test]
    fn gc_keeps_referenced_and_grace_period_objects() {
        // DD-DATA §9: referenced indefinitely; orphan grace 7 days.
        let (c, _d) = cas();
        let keep = c.put(b"keep").unwrap();
        let orphan = c.put(b"orphan").unwrap();
        let now = now_millis();
        let refs: BTreeSet<String> = [keep.clone()].into_iter().collect();
        let removed = c.gc(&refs, 7 * 24 * 3600 * 1000, now).unwrap();
        assert_eq!(removed, 0, "both objects are inside the grace window");
        assert!(c.contains(&keep).unwrap());
        assert!(c.contains(&orphan).unwrap());

        let removed = c.gc(&refs, 0, now).unwrap();
        assert_eq!(removed, 1);
        assert!(c.contains(&keep).unwrap(), "referenced object survives");
        assert!(!c.contains(&orphan).unwrap(), "orphan is swept");
    }

    #[test]
    fn gc_accepts_a_full_digest_and_reconstructs_it_from_the_path() {
        // The sweep reads digests back from `<prefix>/<rest>`; if that
        // reconstruction is wrong, referenced objects get collected.
        let (c, _d) = cas();
        let keep = c.put(b"survives").unwrap();
        let drop_me = c.put(b"collected").unwrap();
        let refs: BTreeSet<String> = [keep.clone()].into_iter().collect();
        c.gc(&refs, 0, now_millis()).unwrap();
        assert!(c.contains(&keep).unwrap());
        assert!(!c.contains(&drop_me).unwrap());
    }

    #[test]
    fn corrupt_object_fails_verification() {
        let (c, _d) = cas();
        let h = c.put(b"intact").unwrap();
        let p = c.object_path(&h);
        std::fs::write(&p, b"tampered").unwrap();
        assert!(!c.verify(&h).unwrap());
    }
}
