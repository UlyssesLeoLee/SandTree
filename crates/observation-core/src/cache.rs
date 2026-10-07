//! Freshness cache (DD-OBS §13, FR-080, NFR-P06).
//!
//! The rule the design states and this cache implements: *stale data may be
//! displayed but must never masquerade as fresh*. So a cache hit always carries
//! its age, and the caller decides. There is no API here that silently returns a
//! value of unknown age.

use std::collections::HashMap;

use sandtree_model::id::ResourceId;
use sandtree_observation_model::{ObservationDomain, ObservationHealth, ObservationSnapshot};

/// Milliseconds since the Unix epoch.
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Current UTC time as RFC3339, the timestamp form used by every observation
/// value.
pub fn now_rfc3339() -> String {
    let secs = (now_ms() / 1000) as i64;
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        sod / 3600,
        (sod % 3600) / 60,
        sod % 60
    )
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// A cached snapshot plus the time it was stored.
#[derive(Debug, Clone, PartialEq)]
pub struct CachedSnapshot {
    /// The snapshot itself.
    pub snapshot: ObservationSnapshot,
    /// When it entered the cache.
    pub stored_at_ms: u64,
    /// Age at read time.
    pub age_ms: u64,
}

impl CachedSnapshot {
    /// Whether the entry is younger than `max_age_ms`.
    pub fn is_fresh(&self, max_age_ms: u64) -> bool {
        self.age_ms <= max_age_ms
    }

    /// A copy whose health reflects staleness.
    ///
    /// Returning the original value with `Healthy` attached after it expired
    /// would be the exact failure mode NFR-O05 warns about, so the health is
    /// downgraded on the way out.
    pub fn with_freshness(&self) -> ObservationSnapshot {
        let mut snap = self.snapshot.clone();
        let domain_max = ObservationDomain::all()
            .iter()
            .map(|d| d.default_max_age_ms())
            .max()
            .unwrap_or(60_000);
        if self.age_ms > domain_max {
            snap.health = ObservationHealth::Stale;
            snap.warn(format!(
                "cached snapshot is {}ms old (policy {}ms)",
                self.age_ms, domain_max
            ));
        }
        snap
    }
}

/// In-memory observation cache keyed by `(resource, domain, profile)`.
#[derive(Debug, Default)]
pub struct ObservationCache {
    entries: HashMap<(ResourceId, String, String), CachedSnapshot>,
}

impl ObservationCache {
    /// Empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Look up a cached snapshot, stamping the current age.
    pub fn get(
        &self,
        id: &ResourceId,
        domain: ObservationDomain,
        profile: &str,
    ) -> Option<CachedSnapshot> {
        let key = (id.clone(), domain.as_str().to_string(), profile.to_string());
        let entry = self.entries.get(&key)?;
        let stored_at_ms = entry.stored_at_ms;
        Some(CachedSnapshot {
            snapshot: entry.snapshot.clone(),
            stored_at_ms,
            age_ms: now_ms().saturating_sub(stored_at_ms),
        })
    }

    /// Store one domain of a snapshot.
    ///
    /// The cache is per-domain so that a slow `filesystem` walk does not delay
    /// the `system` domain, and so a provider event can invalidate exactly the
    /// domain it affected.
    pub fn put(
        &mut self,
        id: &ResourceId,
        domain: ObservationDomain,
        profile: &str,
        snapshot: &ObservationSnapshot,
    ) {
        let key = (id.clone(), domain.as_str().to_string(), profile.to_string());
        self.entries.insert(
            key,
            CachedSnapshot {
                snapshot: snapshot.clone(),
                stored_at_ms: now_ms(),
                age_ms: 0,
            },
        );
    }

    /// Drop cached domains for a resource; `None` clears every domain.
    ///
    /// Called when a provider event says the resource changed.
    pub fn invalidate(&mut self, id: &ResourceId, domain: Option<ObservationDomain>) {
        match domain {
            Some(d) => {
                self.entries
                    .retain(|(rid, dom, _), _| !(rid == id && dom == d.as_str()));
            }
            None => self.entries.retain(|(rid, _, _), _| rid != id),
        }
    }

    /// Number of cached domain entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Drop entries older than `max_age_ms`, returning how many were removed.
    pub fn evict_expired(&mut self, max_age_ms: u64) -> usize {
        let now = now_ms();
        let before = self.entries.len();
        self.entries
            .retain(|_, v| now.saturating_sub(v.stored_at_ms) <= max_age_ms);
        before - self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rid() -> ResourceId {
        ResourceId::derive(&["res"])
    }

    fn snap() -> ObservationSnapshot {
        ObservationSnapshot::empty(
            rid(),
            sandtree_observation_model::ObservationMode::Native,
            ObservationHealth::Healthy,
            "2026-10-07T00:00:00Z",
        )
    }

    #[test]
    fn store_and_retrieve_carries_age() {
        let mut c = ObservationCache::new();
        c.put(&rid(), ObservationDomain::System, "default", &snap());
        let hit = c.get(&rid(), ObservationDomain::System, "default").unwrap();
        assert!(hit.age_ms < 1_000, "fresh entry has a small age");
        assert!(hit.is_fresh(5_000));
    }

    #[test]
    fn profiles_are_separated() {
        let mut c = ObservationCache::new();
        c.put(&rid(), ObservationDomain::System, "default", &snap());
        assert!(c.get(&rid(), ObservationDomain::System, "fast").is_none());
    }

    #[test]
    fn domains_are_stored_independently() {
        let mut c = ObservationCache::new();
        c.put(&rid(), ObservationDomain::System, "p", &snap());
        c.put(&rid(), ObservationDomain::Filesystem, "p", &snap());
        assert_eq!(c.len(), 2);
        c.invalidate(&rid(), Some(ObservationDomain::System));
        assert_eq!(c.len(), 1);
        assert!(c.get(&rid(), ObservationDomain::Filesystem, "p").is_some());
    }

    #[test]
    fn invalidating_a_resource_clears_every_domain() {
        let mut c = ObservationCache::new();
        for d in ObservationDomain::all() {
            c.put(&rid(), *d, "p", &snap());
        }
        c.invalidate(&rid(), None);
        assert!(c.is_empty());
    }

    #[test]
    fn invalidation_is_scoped_to_one_resource() {
        let other = ResourceId::derive(&["other"]);
        let mut c = ObservationCache::new();
        c.put(&rid(), ObservationDomain::System, "p", &snap());
        c.put(&other, ObservationDomain::System, "p", &snap());
        c.invalidate(&rid(), None);
        assert_eq!(c.len(), 1);
        assert!(c.get(&other, ObservationDomain::System, "p").is_some());
    }

    #[test]
    fn expired_entry_is_downgraded_not_returned_as_healthy() {
        let mut c = ObservationCache::new();
        c.put(&rid(), ObservationDomain::System, "p", &snap());
        // Force an old entry.
        let key = (rid(), "system".to_string(), "p".to_string());
        if let Some(v) = c.entries.get_mut(&key) {
            v.stored_at_ms = now_ms().saturating_sub(120_000);
        }
        let hit = c.get(&rid(), ObservationDomain::System, "p").unwrap();
        assert!(!hit.is_fresh(60_000));
        let downgraded = hit.with_freshness();
        assert_eq!(downgraded.health, ObservationHealth::Stale);
        assert!(!downgraded.warnings.is_empty());
    }

    #[test]
    fn eviction_removes_only_expired_entries() {
        let mut c = ObservationCache::new();
        c.put(&rid(), ObservationDomain::System, "p", &snap());
        let key = (rid(), "system".to_string(), "p".to_string());
        if let Some(v) = c.entries.get_mut(&key) {
            v.stored_at_ms = now_ms().saturating_sub(120_000);
        }
        c.put(&rid(), ObservationDomain::Health, "p", &snap());
        assert_eq!(c.evict_expired(60_000), 1);
        assert_eq!(c.len(), 1);
        assert!(c.get(&rid(), ObservationDomain::Health, "p").is_some());
    }
}
