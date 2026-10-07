//! Snapshot assembly for the git-remote channel (ADR-015).
//!
//! # Mode and trust
//!
//! The channel is negotiated as [`ObservationMode::Probe`]: like a guest probe,
//! it learns what the sandbox is willing to publish rather than what the host
//! can see, and it runs after `Native` and `Exec` have been found unavailable.
//!
//! Everything it produces is [`TrustLevel::GuestProbe`], fixed. The content-
//! addressed object IDs are recorded in `Provenance::evidence_hash`, which
//! gives **integrity** — the same bytes hash the same way later — and nothing
//! more. A sandbox can publish a valid object ID for a repository it invented,
//! so the level does not move (ADR-OBS-003).
//!
//! # Degradation is never absence
//!
//! Every failure path returns a typed snapshot whose `health` says what
//! happened. None of them returns an empty `Healthy` snapshot, because
//! "the channel failed" and "the sandbox has nothing" are different facts and
//! collapsing them is how a broken channel turns into a false finding
//! (ADR-OBS-001).

use std::collections::BTreeMap;

use sandtree_model::id::ResourceId;
use sandtree_observation_model::{
    ObservationCapabilities, ObservationDomain, ObservationHealth, ObservationMode,
    ObservationSnapshot, ObservedValue, Provenance, TrustLevel,
};
use serde_json::{Map, Value as Json};

use crate::advertisement::RefAdvertisement;
use crate::url::GitRemoteUrl;
use sandtree_policy::acquire::AcquisitionPermit;

/// Domain this channel fills. A git advertisement describes the sandbox's
/// workspace tree state, which is what `filesystem` means in DD-OBS §5.
pub const DOMAIN: ObservationDomain = ObservationDomain::Filesystem;

/// Value reported for `health` alongside the ref inventory.
pub const HEALTH_DOMAIN: ObservationDomain = ObservationDomain::Health;

/// Declared capabilities.
///
/// Only `probe` and the metadata floor are claimed. Claiming `native` or `exec`
/// would make the negotiator select this provider for work it cannot do
/// (DD-OBS §4).
pub fn git_remote_capabilities() -> ObservationCapabilities {
    let mut domains = BTreeMap::new();
    domains.insert(
        ObservationMode::Probe.as_str().to_string(),
        vec![DOMAIN, HEALTH_DOMAIN],
    );
    domains.insert(
        ObservationMode::Metadata.as_str().to_string(),
        vec![ObservationDomain::System],
    );
    ObservationCapabilities {
        modes: vec![ObservationMode::Probe, ObservationMode::Metadata],
        domains,
        max_concurrency: None,
        requires_native_credential: false,
    }
}

/// Build the snapshot from a successfully parsed advertisement.
///
/// `partial` is set when the advertisement could be read but does not cover
/// what was asked for — for example when only the filesystem domain was
/// collected and `health` was not. A partial value is shown as incomplete
/// rather than hidden or presented as whole (DD-PLG §12.3).
pub fn snapshot_from_advertisement(
    resource_id: ResourceId,
    url: &GitRemoteUrl,
    permit: &AcquisitionPermit,
    adv: &RefAdvertisement,
    observed_at: &str,
    partial: bool,
) -> ObservationSnapshot {
    let mut snap = ObservationSnapshot::empty(
        resource_id,
        ObservationMode::Probe,
        ObservationHealth::Healthy,
        observed_at.to_string(),
    );
    snap.collector_version = Some(format!(
        "sandtree-git-remote/{} (git {})",
        crate::PROVIDER_VERSION,
        adv.object_format.as_str()
    ));

    let mut refs_json = Vec::with_capacity(adv.refs.len());
    for r in &adv.refs {
        refs_json.push(serde_json::json!({
            "name": r.name,
            "object_id": r.object_id,
            "peeled": r.peeled,
            "unborn": r.is_unborn(),
        }));
    }

    let mut fs = Map::new();
    fs.insert("remote".to_string(), Json::String(url.path().to_string()));
    fs.insert("endpoint".to_string(), Json::String(url.endpoint_scope()));
    fs.insert(
        "object_format".to_string(),
        Json::String(adv.object_format.as_str().to_string()),
    );
    fs.insert("ref_count".to_string(), Json::from(adv.refs.len()));
    fs.insert("refs".to_string(), Json::Array(refs_json));
    fs.insert(
        "branches".to_string(),
        Json::Array(adv.branches().into_iter().map(Json::from).collect()),
    );
    fs.insert(
        "tags".to_string(),
        Json::Array(adv.tags().into_iter().map(Json::from).collect()),
    );
    match &adv.head_target {
        Some(t) => {
            fs.insert("head_target".to_string(), Json::String(t.clone()));
        }
        None => {
            // RD §9: absent is reported as absent, not as an empty string.
            fs.insert("head_target".to_string(), Json::Null);
        }
    }
    // A repository with no commits is a fact about the repository; a failed
    // fetch is a fact about the channel. Both are stated explicitly so they
    // cannot be read as each other.
    fs.insert(
        "empty_repository".to_string(),
        Json::Bool(adv.is_empty_repository()),
    );

    let evidence = evidence_hash(adv);
    snap.insert(
        DOMAIN,
        ObservedValue::new(
            Json::Object(fs),
            Provenance::new(
                crate::SOURCE_GIT_REMOTE,
                permit.trust_ceiling(),
                observed_at,
            )
            .with_evidence_hash(evidence)
            .partial(partial),
        ),
    );

    let mut health = Map::new();
    health.insert(
        "channel".to_string(),
        Json::String("git_remote".to_string()),
    );
    health.insert(
        "agent".to_string(),
        Json::String(adv.agent.clone().unwrap_or_default()),
    );
    health.insert(
        "refusal_reason".to_string(),
        Json::String(format!("{:?}", permit.refusal_reason())),
    );
    snap.insert(
        HEALTH_DOMAIN,
        ObservedValue::new(
            Json::Object(health),
            Provenance::new(
                crate::SOURCE_GIT_REMOTE,
                permit.trust_ceiling(),
                observed_at,
            ),
        ),
    );

    snap
}

/// A stable hash over the whole advertisement.
///
/// Binding **all** refs — not just `HEAD` — is deliberate: a snapshot whose
/// evidence hash only covers one ref would still verify while the sandbox
/// changed every other branch underneath it.
fn evidence_hash(adv: &RefAdvertisement) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(adv.object_format.as_str().as_bytes());
    for r in &adv.refs {
        hasher.update(r.name.as_bytes());
        hasher.update(b"\0");
        hasher.update(r.object_id.as_bytes());
        hasher.update(b"\0");
        hasher.update(&[r.peeled as u8]);
        hasher.update(b"\n");
    }
    if let Some(head) = &adv.head_target {
        hasher.update(b"HEAD->");
        hasher.update(head.as_bytes());
    }
    hasher.finalize().to_hex().to_string()
}

/// Snapshot for a channel that could not be used at all.
///
/// `Unavailable` health, no values. This is what makes "we could not look"
/// visibly different from "there is nothing there" (ADR-OBS-001).
pub fn unavailable_snapshot(
    resource_id: ResourceId,
    reason: impl Into<String>,
    observed_at: &str,
) -> ObservationSnapshot {
    let mut snap = ObservationSnapshot::empty(
        resource_id,
        ObservationMode::Probe,
        ObservationHealth::Unavailable,
        observed_at.to_string(),
    );
    snap.warn(reason);
    snap
}

/// Snapshot for a channel that worked but could not answer this question.
pub fn degraded_snapshot(
    resource_id: ResourceId,
    reason: impl Into<String>,
    observed_at: &str,
) -> ObservationSnapshot {
    let mut snap = ObservationSnapshot::empty(
        resource_id,
        ObservationMode::Probe,
        ObservationHealth::Degraded,
        observed_at.to_string(),
    );
    snap.warn(reason);
    snap
}

/// The trust ceiling this module stamps on everything it produces.
///
/// Exposed so the provider's own tests can assert it without duplicating the
/// constant, and so a future change to the ceiling has one place to change.
pub const fn trust_ceiling() -> TrustLevel {
    sandtree_policy::acquire::NETWORK_TRUST_CEILING
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::advertisement::parse_advertisement;
    use crate::pktline;
    use sandtree_policy::acquire::{
        AcquisitionChannel, AcquisitionPolicy, AcquisitionRequest, PenetrationVerdict,
        RefusalReason,
    };

    fn res() -> ResourceId {
        ResourceId::derive(&["sbx-git"])
    }

    fn permit() -> AcquisitionPermit {
        let req = AcquisitionRequest::new(
            res(),
            DOMAIN,
            AcquisitionChannel::GitRemote,
            "10.0.0.5:9418",
        );
        AcquisitionPolicy::new()
            .authorize(
                &sandtree_model::capability::CapabilitySet::from_iter_caps([
                    sandtree_model::capability::Capability::parse("net:connect:10.0.0.5:9418")
                        .unwrap(),
                ]),
                &PenetrationVerdict::Refused {
                    domain: DOMAIN,
                    reason: RefusalReason::IsolationNotPermitted,
                },
                &req,
            )
            .unwrap()
    }

    fn advertisement() -> RefAdvertisement {
        let mut s = String::new();
        s.push_str(&pktline::encode("# service=git-upload-pack\n").unwrap());
        s.push_str(pktline::encode_flush().as_str());
        s.push_str(
            &pktline::encode(concat!(
                "0000000000000000000000000000000000000000 HEAD\0",
                "symref=HEAD:refs/heads/main agent=git/2.45.0 object-format=sha1\n"
            ))
            .unwrap(),
        );
        s.push_str(
            &pktline::encode("a1b2c3d4e5f60718293a4b5c6d7e8f9012345678 refs/heads/main\n").unwrap(),
        );
        s.push_str(
            &pktline::encode("1122334455667788990011223344556677889900 refs/tags/v1.0\n").unwrap(),
        );
        s.push_str(pktline::encode_flush().as_str());
        parse_advertisement(&s).unwrap()
    }

    fn url() -> GitRemoteUrl {
        GitRemoteUrl::parse("https://10.0.0.5:9418/workspace.git").unwrap()
    }

    #[test]
    fn the_snapshot_is_probe_mode_at_the_guest_probe_ceiling() {
        // Break by stamping ProviderNative: the snapshot then starts
        // satisfying destructive preconditions that this channel can never
        // legitimately support.
        let snap = snapshot_from_advertisement(
            res(),
            &url(),
            &permit(),
            &advertisement(),
            "2026-10-07T00:00:00Z",
            false,
        );
        assert_eq!(snap.mode, ObservationMode::Probe);
        assert_eq!(snap.health, ObservationHealth::Healthy);
        assert_eq!(snap.weakest_trust(), Some(TrustLevel::GuestProbe));
        assert!(!snap.is_security_authoritative());
        let v = snap.get(DOMAIN).unwrap();
        assert_eq!(v.provenance.trust, trust_ceiling());
    }

    #[test]
    fn the_content_addressed_ids_reach_the_snapshot() {
        // Break by dropping object ids from the payload, and the whole point of
        // choosing git over an opaque endpoint is lost.
        let snap = snapshot_from_advertisement(
            res(),
            &url(),
            &permit(),
            &advertisement(),
            "2026-10-07T00:00:00Z",
            false,
        );
        let fs = &snap.get(DOMAIN).unwrap().value;
        // HEAD + refs/heads/main + refs/tags/v1.0
        assert_eq!(fs["ref_count"], Json::from(3));
        assert_eq!(fs["branches"], serde_json::json!(["refs/heads/main"]));
        assert_eq!(fs["tags"], serde_json::json!(["refs/tags/v1.0"]));
        assert_eq!(fs["head_target"], serde_json::json!("refs/heads/main"));
        assert_eq!(fs["empty_repository"], Json::Bool(false));
        assert_eq!(
            fs["refs"][1]["object_id"],
            serde_json::json!("a1b2c3d4e5f60718293a4b5c6d7e8f9012345678")
        );
    }

    #[test]
    fn the_evidence_hash_changes_when_any_ref_changes() {
        // Break by hashing only HEAD, and a snapshot whose evidence hash still
        // matches while the sandbox rewrote every branch.
        let a = evidence_hash(&advertisement());
        assert_eq!(a, evidence_hash(&advertisement()), "same input, same hash");

        let mut s = String::new();
        s.push_str(&pktline::encode("# service=git-upload-pack\n").unwrap());
        s.push_str(pktline::encode_flush().as_str());
        s.push_str(
            &pktline::encode(concat!(
                "0000000000000000000000000000000000000000 HEAD\0",
                "symref=HEAD:refs/heads/main object-format=sha1\n"
            ))
            .unwrap(),
        );
        s.push_str(
            &pktline::encode("ffffffffffffffffffffffffffffffffffffffff refs/heads/main\n").unwrap(),
        );
        s.push_str(pktline::encode_flush().as_str());
        let mutated = parse_advertisement(&s).unwrap();
        assert_ne!(
            a,
            evidence_hash(&mutated),
            "a rewritten branch must change the evidence hash"
        );
    }

    #[test]
    fn an_unavailable_channel_carries_no_values() {
        // ADR-OBS-001: this is the snapshot that must never be mistaken for
        // "the sandbox has no branches".
        let snap = unavailable_snapshot(
            res(),
            "endpoint refused the connection",
            "2026-10-07T00:00:00Z",
        );
        assert_eq!(snap.health, ObservationHealth::Unavailable);
        assert!(
            snap.values.is_empty(),
            "an unavailable channel has no values"
        );
        assert_eq!(snap.warnings.len(), 1);
        // And policy must refuse it as evidence of absence.
        assert!(sandtree_policy::TrustPolicy::new()
            .check_destructive_precondition(&snap)
            .is_err());
    }

    #[test]
    fn a_degraded_channel_is_distinguishable_from_an_unavailable_one() {
        let d = degraded_snapshot(res(), "no HEAD symref advertised", "2026-10-07T00:00:00Z");
        assert_eq!(d.health, ObservationHealth::Degraded);
        assert_ne!(d.health, ObservationHealth::Unavailable);
    }

    #[test]
    fn the_declared_capabilities_do_not_claim_native_or_exec() {
        // Break by adding Exec, and the negotiator starts selecting this
        // provider for guest commands it cannot run (DD-OBS §4).
        let caps = git_remote_capabilities();
        assert!(!caps.supports(ObservationMode::Native));
        assert!(!caps.supports(ObservationMode::Exec));
        assert!(caps.supports(ObservationMode::Probe));
        assert!(caps.supports(ObservationMode::Metadata));
        assert_eq!(
            caps.domains_in(ObservationMode::Probe),
            &[DOMAIN, HEALTH_DOMAIN]
        );
    }

    #[test]
    fn a_repository_with_no_commits_is_reported_as_empty_not_as_unavailable() {
        // The distinction the whole module exists to preserve.
        let mut s = String::new();
        s.push_str(&pktline::encode("# service=git-upload-pack\n").unwrap());
        s.push_str(pktline::encode_flush().as_str());
        s.push_str(
            &pktline::encode(concat!(
                "0000000000000000000000000000000000000000 HEAD\0",
                "symref=HEAD:refs/heads/main object-format=sha1\n"
            ))
            .unwrap(),
        );
        s.push_str(pktline::encode_flush().as_str());
        let adv = parse_advertisement(&s).unwrap();
        let snap = snapshot_from_advertisement(
            res(),
            &url(),
            &permit(),
            &adv,
            "2026-10-07T00:00:00Z",
            false,
        );
        // A successful read of an empty repository: healthy, and explicitly empty.
        assert_eq!(snap.health, ObservationHealth::Healthy);
        assert_eq!(
            snap.get(DOMAIN).unwrap().value["empty_repository"],
            Json::Bool(true)
        );
    }

    #[test]
    fn an_absent_head_target_is_null_not_an_empty_string() {
        // RD §9: guessing a default branch name would be inventing state.
        let mut s = String::new();
        s.push_str(&pktline::encode("# service=git-upload-pack\n").unwrap());
        s.push_str(pktline::encode_flush().as_str());
        s.push_str(
            &pktline::encode("a1b2c3d4e5f60718293a4b5c6d7e8f9012345678 refs/heads/main\n").unwrap(),
        );
        s.push_str(pktline::encode_flush().as_str());
        let adv = parse_advertisement(&s).unwrap();
        let snap = snapshot_from_advertisement(
            res(),
            &url(),
            &permit(),
            &adv,
            "2026-10-07T00:00:00Z",
            false,
        );
        assert_eq!(snap.get(DOMAIN).unwrap().value["head_target"], Json::Null);
    }

    #[test]
    fn the_snapshot_is_byte_stable_for_the_same_advertisement() {
        // Two runs must produce identical JSON or every hash-based comparison
        // downstream becomes flaky.
        let a = snapshot_from_advertisement(
            res(),
            &url(),
            &permit(),
            &advertisement(),
            "2026-10-07T00:00:00Z",
            false,
        );
        let b = snapshot_from_advertisement(
            res(),
            &url(),
            &permit(),
            &advertisement(),
            "2026-10-07T00:00:00Z",
            false,
        );
        assert_eq!(
            serde_json::to_string(&a).unwrap(),
            serde_json::to_string(&b).unwrap()
        );
    }
}
