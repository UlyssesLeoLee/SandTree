//! Parsing the git **ref advertisement** returned by
//! `GET <repo>/info/refs?service=git-upload-pack`.
//!
//! # What this yields, and why it is enough
//!
//! The advertisement carries every ref the sandbox's repository publishes,
//! each with its **content-addressed object ID**. That object ID is the point
//! of the whole channel: it is verifiable against the same bytes later, so it
//! becomes `Provenance::evidence_hash`. It is *not* authenticity — a sandbox
//! can produce a valid ID for a false claim — so it never raises trust
//! (ADR-OBS-003, ADR-015).
//!
//! # Protocol version
//!
//! git's protocol v2 pushes a `version 2` capability announcement instead of
//! the ref list and requires a follow-up `POST /git-upload-pack`. This provider
//! deliberately does **not** send `Git-Protocol: version=2`, so a conforming
//! server answers with the v0 advertisement, which is all this channel needs.
//! If a server answers v2 anyway, that is reported as
//! [`AdvertisementError::ProtocolVersion2Unsupported`] — never as "zero refs",
//! because an empty repository and an unsupported protocol must never look the
//! same (ADR-OBS-001).

use crate::pktline::{self, PktLine, PktLineError};

/// Upper bound on refs accepted from one advertisement.
///
/// A sandbox controls this response. Without a bound, one crafted advertisement
/// could allocate without limit (DD-SW §12.3 bounds every untrusted payload).
pub const MAX_REFS: usize = 8192;

/// Object ID width advertised by the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectFormat {
    /// Git's original 40-hex SHA-1 object IDs.
    Sha1,
    /// 64-hex SHA-256 object IDs.
    Sha256,
}

impl ObjectFormat {
    /// Hex width of an object ID in this format.
    pub fn hex_len(self) -> usize {
        match self {
            ObjectFormat::Sha1 => 40,
            ObjectFormat::Sha256 => 64,
        }
    }

    /// Wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            ObjectFormat::Sha1 => "sha1",
            ObjectFormat::Sha256 => "sha256",
        }
    }
}

/// One advertised ref.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct GitRef {
    /// Full ref name, or `HEAD`.
    pub name: String,
    /// Hex object ID. All-zero for an unborn symref target.
    pub object_id: String,
    /// True for a `^{}` peeled tag entry.
    pub peeled: bool,
}

impl GitRef {
    /// Whether the object ID is the all-zero placeholder git uses for a
    /// symref that does not resolve yet.
    pub fn is_unborn(&self) -> bool {
        self.object_id.chars().all(|c| c == '0') && !self.object_id.is_empty()
    }
}

/// A parsed ref advertisement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefAdvertisement {
    /// Refs, sorted by name so snapshots stay byte-stable (CONTRACTS §6).
    pub refs: Vec<GitRef>,
    /// Where `HEAD` points, when the server said so via `symref=`.
    pub head_target: Option<String>,
    /// Server `agent=` string, kept for diagnostics only.
    pub agent: Option<String>,
    /// Object ID width the server uses.
    pub object_format: ObjectFormat,
    /// Raw capability tokens the server advertised.
    pub capabilities: Vec<String>,
}

impl RefAdvertisement {
    /// Whether this is a repository with no commits yet.
    ///
    /// Distinct from "we could not read the advertisement": that is an error,
    /// never an empty list. Confusing the two would let a transport failure
    /// masquerade as a finding (ADR-OBS-001).
    pub fn is_empty_repository(&self) -> bool {
        // The `!is_empty()` term is load-bearing. `all` over an empty iterator
        // is vacuously true, so without it this predicate would report "an
        // empty repository" for a value carrying no information at all -- and
        // `RefAdvertisement`'s fields are public, so it can be built by hand.
        // `parse_advertisement` rejects a zero-ref advertisement, which closes
        // the main path; this closes the rest.
        !self.refs.is_empty() && self.refs.iter().all(|r| r.is_unborn() || r.name == "HEAD")
    }

    /// Look up one ref by exact name.
    pub fn ref_named(&self, name: &str) -> Option<&GitRef> {
        self.refs.iter().find(|r| r.name == name)
    }

    /// Ref names under `refs/heads/`, sorted.
    pub fn branches(&self) -> Vec<&str> {
        self.refs
            .iter()
            .filter(|r| r.name.starts_with("refs/heads/"))
            .map(|r| r.name.as_str())
            .collect()
    }

    /// Ref names under `refs/tags/`, excluding peeled `^{}` entries.
    pub fn tags(&self) -> Vec<&str> {
        self.refs
            .iter()
            .filter(|r| r.name.starts_with("refs/tags/") && !r.peeled)
            .map(|r| r.name.as_str())
            .collect()
    }
}

/// Why an advertisement could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AdvertisementError {
    /// The pkt-line framing was invalid.
    #[error("advertisement framing is invalid: {0}")]
    Framing(#[from] PktLineError),
    /// The first packet was not the expected service announcement.
    #[error("expected a '# service=git-upload-pack' line, got {0:?}")]
    WrongService(String),
    /// No service announcement at all.
    #[error("advertisement carried no service announcement")]
    MissingServiceLine,
    /// The server answered with protocol v2, which this channel does not speak.
    #[error("server answered with git protocol v2; this channel requests v0")]
    ProtocolVersion2Unsupported,
    /// The advertisement carried no refs at all.
    ///
    /// A real repository — empty or not — always advertises at least `HEAD`. A
    /// response with the service line and nothing else is a truncated reply or
    /// an endpoint that is not a git server, and reporting it as "an empty
    /// repository" would turn a broken channel into a finding (ADR-OBS-001).
    #[error("advertisement carried no refs; that is not what an empty repository sends")]
    NoRefs,
    /// A ref line did not have the `<oid> SP <name>` shape.
    #[error("malformed ref line: {0:?}")]
    MalformedRefLine(String),
    /// The object ID was not hex of the advertised width.
    #[error("ref {name:?} carried an invalid object id {value:?}")]
    InvalidObjectId {
        /// Ref the ID belongs to.
        name: String,
        /// The offending value.
        value: String,
    },
    /// A ref name that is neither `HEAD` nor under `refs/`.
    #[error("unexpected ref name {0:?}")]
    UnexpectedRefName(String),
    /// More refs than [`MAX_REFS`].
    #[error("advertisement carried more than {MAX_REFS} refs")]
    RefLimitExceeded,
}

/// Parse a complete `info/refs` response body.
pub fn parse_advertisement(body: &str) -> Result<RefAdvertisement, AdvertisementError> {
    let packets = pktline::decode_all(body)?;

    // The service line is the first data packet; protocol v2 replaces it with
    // `version 2`, which is a different exchange we deliberately do not run.
    let first = packets
        .iter()
        .find_map(|p| match p {
            PktLine::Data(d) => Some(d.as_str()),
            _ => None,
        })
        .ok_or(AdvertisementError::MissingServiceLine)?;

    if first.starts_with("version 2") {
        return Err(AdvertisementError::ProtocolVersion2Unsupported);
    }
    let service = first
        .strip_prefix("# service=")
        .ok_or_else(|| AdvertisementError::WrongService(first.to_string()))?;
    if service.trim() != "git-upload-pack" {
        return Err(AdvertisementError::WrongService(first.to_string()));
    }

    let mut refs: Vec<GitRef> = Vec::new();
    let mut capabilities: Vec<String> = Vec::new();
    let mut head_target: Option<String> = None;
    let mut agent: Option<String> = None;
    let mut object_format = ObjectFormat::Sha1;

    for pkt in &packets {
        let PktLine::Data(line) = pkt else { continue };
        if line.starts_with('#') {
            continue;
        }
        let line = line.trim_end_matches('\n');
        if line.is_empty() {
            continue;
        }

        // A `ref: <target>` line declares a symref without an object ID.
        if let Some(target) = line.strip_prefix("ref: ") {
            head_target = Some(target.trim().to_string());
            continue;
        }

        let (oid, rest) = line
            .split_once(' ')
            .ok_or_else(|| AdvertisementError::MalformedRefLine(line.to_string()))?;

        // Capabilities ride on the first ref line, after a NUL.
        let (name, cap_text) = match rest.split_once('\0') {
            Some((n, c)) => (n, Some(c)),
            None => (rest, None),
        };

        if let Some(caps) = cap_text {
            capabilities = caps
                .split_whitespace()
                .map(str::to_string)
                .collect::<Vec<_>>();
            for cap in &capabilities {
                if let Some(v) = cap.strip_prefix("object-format=") {
                    object_format = match v {
                        "sha256" => ObjectFormat::Sha256,
                        _ => ObjectFormat::Sha1,
                    };
                }
                if let Some(v) = cap.strip_prefix("agent=") {
                    agent = Some(v.to_string());
                }
                if let Some(v) = cap.strip_prefix("symref=HEAD:") {
                    head_target = Some(v.to_string());
                }
            }
        }

        let expected = object_format.hex_len();
        if oid.len() != expected || !oid.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(AdvertisementError::InvalidObjectId {
                name: name.to_string(),
                value: oid.to_string(),
            });
        }
        if name != "HEAD" && !name.starts_with("refs/") {
            return Err(AdvertisementError::UnexpectedRefName(name.to_string()));
        }

        let peeled = name.ends_with("^{}");
        refs.push(GitRef {
            name: name.to_string(),
            object_id: oid.to_ascii_lowercase(),
            peeled,
        });

        if refs.len() > MAX_REFS {
            return Err(AdvertisementError::RefLimitExceeded);
        }
    }

    // CONTRACTS §6: deterministic order, independent of server ordering.
    refs.sort_by(|a, b| (a.name.as_str(), a.peeled).cmp(&(b.name.as_str(), b.peeled)));

    // Checked after sorting so the guard cannot be reordered past it by a later
    // refactor, and before any caller can ask `is_empty_repository()` -- on an
    // empty `refs` that predicate is vacuously true, which is exactly how a
    // truncated response would masquerade as an empty repository.
    if refs.is_empty() {
        return Err(AdvertisementError::NoRefs);
    }

    Ok(RefAdvertisement {
        refs,
        head_target,
        agent,
        object_format,
        capabilities,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A realistic advertisement, byte-for-byte the shape git-http-backend
    /// returns: service line, flush, a capabilities-bearing first ref, then
    /// plain refs, a peeled tag, and a closing flush.
    fn realistic() -> String {
        let mut s = String::new();
        s.push_str(&pktline::encode("# service=git-upload-pack\n").unwrap());
        s.push_str(pktline::encode_flush().as_str());
        s.push_str(
            &pktline::encode(concat!(
                "0000000000000000000000000000000000000000 HEAD\0",
                "symref=HEAD:refs/heads/main agent=git/2.45.0 object-format=sha1 ofs-delta\n"
            ))
            .unwrap(),
        );
        s.push_str(
            &pktline::encode("a1b2c3d4e5f60718293a4b5c6d7e8f9012345678 refs/heads/main\n").unwrap(),
        );
        s.push_str(
            &pktline::encode("0f1e2d3c4b5a69788796a5b4c3d2e1f001234567 refs/heads/dev\n").unwrap(),
        );
        s.push_str(
            &pktline::encode("1122334455667788990011223344556677889900 refs/tags/v1.0\n").unwrap(),
        );
        s.push_str(
            &pktline::encode("2233445566778899001122334455667788990011 refs/tags/v1.0^{}\n")
                .unwrap(),
        );
        s.push_str(pktline::encode_flush().as_str());
        s
    }

    #[test]
    fn a_real_advertisement_yields_every_ref() {
        // Break by dropping the service-line skip and the first "ref" becomes
        // the service banner, so nothing parses.
        let adv = parse_advertisement(&realistic()).unwrap();
        assert_eq!(
            adv.refs.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(),
            vec![
                "HEAD",
                "refs/heads/dev",
                "refs/heads/main",
                "refs/tags/v1.0",
                "refs/tags/v1.0^{}",
            ]
        );
        assert_eq!(adv.branches(), vec!["refs/heads/dev", "refs/heads/main"]);
        assert_eq!(adv.tags(), vec!["refs/tags/v1.0"]);
        assert_eq!(adv.head_target.as_deref(), Some("refs/heads/main"));
        assert_eq!(adv.agent.as_deref(), Some("git/2.45.0"));
        assert_eq!(adv.object_format, ObjectFormat::Sha1);
        assert!(!adv.is_empty_repository());
    }

    #[test]
    fn the_object_id_is_the_content_addressed_value_we_carry_as_evidence() {
        // Break by dropping or rewriting the id, and the evidence hash recorded
        // on the snapshot no longer matches the repository.
        let adv = parse_advertisement(&realistic()).unwrap();
        let main = adv.ref_named("refs/heads/main").unwrap();
        assert_eq!(main.object_id, "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678");
        assert!(!main.is_unborn());
        assert!(adv.ref_named("HEAD").unwrap().is_unborn());
    }

    #[test]
    fn the_ref_order_does_not_depend_on_server_order() {
        // Break by preserving server order, and two servers advertising the
        // same repository produce two different snapshot byte streams.
        let a = parse_advertisement(&realistic()).unwrap();
        let reversed = {
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
                &pktline::encode("2233445566778899001122334455667788990011 refs/tags/v1.0^{}\n")
                    .unwrap(),
            );
            s.push_str(
                &pktline::encode("1122334455667788990011223344556677889900 refs/tags/v1.0\n")
                    .unwrap(),
            );
            s.push_str(
                &pktline::encode("a1b2c3d4e5f60718293a4b5c6d7e8f9012345678 refs/heads/main\n")
                    .unwrap(),
            );
            s.push_str(
                &pktline::encode("0f1e2d3c4b5a69788796a5b4c3d2e1f001234567 refs/heads/dev\n")
                    .unwrap(),
            );
            s.push_str(pktline::encode_flush().as_str());
            s
        };
        let b = parse_advertisement(&reversed).unwrap();
        assert_eq!(
            a.refs, b.refs,
            "ref order must be canonical, not server order"
        );
    }

    #[test]
    fn protocol_v2_is_reported_as_unsupported_not_as_an_empty_repository() {
        // This is the ADR-OBS-001 case that matters most here: a v2 answer has
        // no ref list at all, so treating it as "no refs" would report an empty
        // repository for a perfectly healthy one.
        let body = {
            let mut s = String::new();
            s.push_str(&pktline::encode("version 2\n").unwrap());
            s.push_str(pktline::encode_flush().as_str());
            s
        };
        assert_eq!(
            parse_advertisement(&body).unwrap_err(),
            AdvertisementError::ProtocolVersion2Unsupported
        );
    }

    #[test]
    fn a_genuinely_empty_repository_is_distinguishable_from_a_failure() {
        // git advertises only an unborn HEAD for a repository with no commits.
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
        assert!(adv.is_empty_repository());
        assert_eq!(adv.head_target.as_deref(), Some("refs/heads/main"));
        // And it is a *successful* read, so its health may be Healthy.
        assert!(!adv.refs.is_empty());
    }

    #[test]
    fn sha256_object_ids_are_recognised() {
        // Break by hardcoding the sha1 width, and a sha256 repository's every
        // ref is rejected as invalid.
        let oid = "ab".repeat(32);
        let mut s = String::new();
        s.push_str(&pktline::encode("# service=git-upload-pack\n").unwrap());
        s.push_str(pktline::encode_flush().as_str());
        s.push_str(
            &pktline::encode(&format!("{oid} refs/heads/main\0object-format=sha256\n")).unwrap(),
        );
        s.push_str(pktline::encode_flush().as_str());
        let adv = parse_advertisement(&s).unwrap();
        assert_eq!(adv.object_format, ObjectFormat::Sha256);
        assert_eq!(adv.ref_named("refs/heads/main").unwrap().object_id, oid);
    }

    #[test]
    fn a_bad_object_id_is_refused_rather_than_stored() {
        // Break by accepting any hex string, and a truncated or padded id ends
        // up in `evidence_hash` looking like a real object reference.
        for oid in ["zzzz", "a1b2", &"a".repeat(41), ""] {
            let mut s = String::new();
            s.push_str(&pktline::encode("# service=git-upload-pack\n").unwrap());
            s.push_str(pktline::encode_flush().as_str());
            s.push_str(&pktline::encode(&format!("{oid} refs/heads/main\n")).unwrap());
            s.push_str(pktline::encode_flush().as_str());
            assert!(
                matches!(
                    parse_advertisement(&s),
                    Err(AdvertisementError::InvalidObjectId { .. })
                ),
                "object id {oid:?} must be refused"
            );
        }
    }

    #[test]
    fn a_ref_name_outside_head_and_refs_is_refused() {
        // A sandbox controls the names too; anything else is not a ref and
        // must not reach a snapshot field.
        let mut s = String::new();
        s.push_str(&pktline::encode("# service=git-upload-pack\n").unwrap());
        s.push_str(pktline::encode_flush().as_str());
        s.push_str(&pktline::encode("a1b2c3d4e5f60718293a4b5c6d7e8f9012345678 sneaky\n").unwrap());
        s.push_str(pktline::encode_flush().as_str());
        assert_eq!(
            parse_advertisement(&s).unwrap_err(),
            AdvertisementError::UnexpectedRefName("sneaky".to_string())
        );
    }

    #[test]
    fn a_zero_ref_response_is_refused_rather_than_reported_as_an_empty_repository() {
        // The failure this prevents: `is_empty_repository()` is `all(...)`, and
        // `all` on an empty list is vacuously true. So without this guard a
        // truncated reply -- service line, flush, nothing else -- would produce
        // a Healthy snapshot saying `empty_repository: true` about a sandbox
        // that may well have hundreds of branches.
        let mut s = String::new();
        s.push_str(&pktline::encode("# service=git-upload-pack\n").unwrap());
        s.push_str(pktline::encode_flush().as_str());

        assert_eq!(
            parse_advertisement(&s).unwrap_err(),
            AdvertisementError::NoRefs
        );

        // And the contrast that makes the distinction real: a genuine empty
        // repository *does* send an unborn HEAD, and parses successfully.
        let mut real = String::new();
        real.push_str(&pktline::encode("# service=git-upload-pack\n").unwrap());
        real.push_str(pktline::encode_flush().as_str());
        real.push_str(
            &pktline::encode(concat!(
                "0000000000000000000000000000000000000000 HEAD\0",
                "symref=HEAD:refs/heads/main object-format=sha1\n"
            ))
            .unwrap(),
        );
        real.push_str(pktline::encode_flush().as_str());
        let adv = parse_advertisement(&real).unwrap();
        assert!(adv.is_empty_repository());
        assert_eq!(adv.refs.len(), 1);
    }

    #[test]
    fn a_wrong_service_banner_is_refused() {
        // Break by ignoring the banner, and a download-pack response is parsed
        // as if it were the ref list we asked for.
        let mut s = String::new();
        s.push_str(&pktline::encode("# service=git-receive-pack\n").unwrap());
        s.push_str(pktline::encode_flush().as_str());
        assert!(matches!(
            parse_advertisement(&s),
            Err(AdvertisementError::WrongService(_))
        ));
    }

    #[test]
    fn malformed_framing_is_an_error_not_an_empty_list() {
        // The invalid sentinel, an empty body and a truncated packet must all
        // fail loudly.
        assert!(matches!(
            parse_advertisement("0003"),
            Err(AdvertisementError::Framing(PktLineError::InvalidSentinel))
        ));
        assert_eq!(
            parse_advertisement("").unwrap_err(),
            AdvertisementError::MissingServiceLine
        );
        assert!(matches!(
            parse_advertisement("003fdeadbeef refs/heads/ma"),
            Err(AdvertisementError::Framing(_))
        ));
    }

    #[test]
    fn a_ref_flood_is_refused_before_it_can_allocate_without_limit() {
        // Break by removing the bound and one crafted advertisement allocates
        // one GitRef per line.
        let mut s = String::new();
        s.push_str(&pktline::encode("# service=git-upload-pack\n").unwrap());
        s.push_str(pktline::encode_flush().as_str());
        for i in 0..=MAX_REFS {
            s.push_str(
                &pktline::encode(&format!(
                    "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678 refs/heads/b{i}\n"
                ))
                .unwrap(),
            );
        }
        s.push_str(pktline::encode_flush().as_str());
        assert_eq!(
            parse_advertisement(&s).unwrap_err(),
            AdvertisementError::RefLimitExceeded
        );
    }
}
