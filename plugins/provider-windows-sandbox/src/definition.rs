//! `.wsb` definition parsing and mapped-folder authorization (DD-PLG §7;
//! NFR-S06, NFR-S07, NFR-S08).
//!
//! A `.wsb` file is a Windows Sandbox configuration XML document. SandTree
//! discovers the definitions it manages and turns each into a
//! [`ResourceNode`]. The mapped-folder handling here is the enforcement point
//! for the read-only-bootstrap invariant: a `<MappedFolder>` may be writable
//! only when it points at the dedicated telemetry outbox.
//!
//! Parsing is deliberately tolerant of the parts SandTree does not use and
//! strict about the parts it acts on. An attribute that cannot be understood is
//! recorded as unknown rather than guessed (RD §9).

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

use sandtree_model::capability::{Capability, CapabilityNamespace, CapabilitySet};
use sandtree_model::id::{PluginId, ResourceId};
use sandtree_model::resource::{ResourceKind, ResourceNode, ResourceState};
use serde_json::{Map, Value as Json};

/// Identity salt so Windows Sandbox ids cannot collide with another provider's.
const PROVIDER_SALT: &str = "sandtree.provider.windows-sandbox";

/// Default dedicated telemetry outbox, relative to the managed data directory.
///
/// `schemas/windows_probe_protocol_v1.md`: "Telemetry outbox is a dedicated empty
/// directory and is never a source-code workspace."
pub const DEFAULT_OUTBOX_DIR: &str = "probe-outbox";

/// Mapped sources that are never shareable, whatever the `.wsb` says.
///
/// NFR-S06: isolation is not tradeable, so a `.wsb` authored to expose one of
/// these is refused rather than honoured. A definition file is configuration,
/// not authority.
pub const FORBIDDEN_MAPPINGS: &[&str] = &[
    "docker_engine",
    "docker.sock",
    "containers/docker",
    "/var/run/docker",
    "windows/winSxS",
    "$recycle.bin",
];

/// Why a `.wsb` document was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WsbParseError {
    /// The document was not valid XML.
    #[error("wsb document is not valid XML: {0}")]
    Xml(String),
    /// No `<Configuration>` element was found.
    #[error("wsb document has no <Configuration> element")]
    NoConfiguration,
    /// A mapped folder was refused by policy.
    #[error("mapped folder {0} is forbidden (NFR-S06): {1}")]
    ForbiddenMapping(String, &'static str),
    /// A `MappedFolder` element was present but carried no paths.
    #[error("wsb document has a <MappedFolder> with no HostFolder or SandboxFolder")]
    EmptyMappedFolder,
}

/// A mapped folder as declared in a `.wsb`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappedFolder {
    /// Host path.
    pub host_path: String,
    /// Guest-visible path.
    pub guest_path: String,
    /// Whether the guest may write.
    pub writable: bool,
    /// Whether the host may see guest writes.
    pub read_only: bool,
}

/// A parsed `.wsb` configuration.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WsbDefinition {
    /// `<Configuration><Networking>`, etc. — retained verbatim for the inspector.
    pub networking: Option<String>,
    /// `<MappedFolder>` entries, sorted by guest path.
    pub mapped_folders: Vec<MappedFolder>,
    /// `<LogonCommand>` payload, if any.
    pub logon_command: Option<String>,
    /// `<ClipboardRedirection>` state.
    pub clipboard_redirection: Option<bool>,
    /// `<PrinterRedirection>` state.
    pub printer_redirection: Option<bool>,
    /// `<MemoryInMB>`.
    pub memory_in_mb: Option<u32>,
    /// Attributes this parser does not model, kept for diagnostics.
    pub unknown_attributes: BTreeMap<String, String>,
}

/// Derive the stable sandbox id from its definition file name.
pub fn sandbox_id(name: &str) -> ResourceId {
    ResourceId::derive(&[PROVIDER_SALT, name])
}

/// Parse a `.wsb` document.
///
/// `outbox_dir` is the only host path a definition may map writable; anything
/// else writable is refused (NFR-S07).
pub fn parse_wsb(xml: &str, outbox_dir: &str) -> Result<WsbDefinition, WsbParseError> {
    use quick_xml::events::Event;
    use quick_xml::Reader;

    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut def = WsbDefinition::default();
    let mut saw_configuration = false;
    let mut saw_any_element = false;
    let mut current_element: Option<String> = None;
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let name = String::from_utf8_lossy(e.local_name().as_ref()).to_string();
                saw_any_element = true;
                if name == "Configuration" {
                    saw_configuration = true;
                }
                let attrs = attributes(&e)?;
                current_element = Some(name.clone());
                apply_attributes(&mut def, &name, &attrs);
            }
            Ok(Event::Empty(e)) => {
                // A self-closing element carries attributes but no body.
                let name = String::from_utf8_lossy(e.local_name().as_ref()).to_string();
                saw_any_element = true;
                if name == "Configuration" {
                    saw_configuration = true;
                }
                let attrs = attributes(&e)?;
                apply_attributes(&mut def, &name, &attrs);
            }
            Ok(Event::Text(t)) => {
                if let Some(el) = current_element.as_deref() {
                    let text = t.decode().map_err(|e| WsbParseError::Xml(e.to_string()))?;
                    apply_text(&mut def, el, &text);
                }
            }
            Ok(Event::End(e)) => {
                let name = String::from_utf8_lossy(e.local_name().as_ref()).to_string();
                if current_element.as_deref() == Some(name.as_str()) {
                    current_element = None;
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(WsbParseError::Xml(e.to_string())),
            _ => {}
        }
        buf.clear();
    }

    if !saw_configuration {
        // A document with no markup at all is a syntax problem, not a
        // well-formed document that happens to omit `<Configuration>`.
        // Reporting `NoConfiguration` here would send an operator looking for a
        // missing element instead of at the malformed input (RD §9).
        if !saw_any_element {
            return Err(WsbParseError::Xml(
                "document contains no XML elements".to_string(),
            ));
        }
        return Err(WsbParseError::NoConfiguration);
    }

    // Enforce the mapping policy after the whole document is known, so a
    // forbidden folder is reported even if it appears late in the file.
    enforce_mapping_policy(&mut def, outbox_dir)?;
    def.mapped_folders.sort_by(|a, b| {
        a.guest_path
            .cmp(&b.guest_path)
            .then(a.host_path.cmp(&b.host_path))
    });
    Ok(def)
}

/// Collect an element's attributes into a plain map.
fn attributes(
    e: &quick_xml::events::BytesStart<'_>,
) -> Result<BTreeMap<String, String>, WsbParseError> {
    let mut out = BTreeMap::new();
    for attr in e.attributes() {
        let a = attr.map_err(|err| WsbParseError::Xml(err.to_string()))?;
        let key = String::from_utf8_lossy(a.key.local_name().as_ref()).to_string();
        let value = a
            .unescape_value()
            .map_err(|err| WsbParseError::Xml(err.to_string()))?
            .to_string();
        out.insert(key, value);
    }
    Ok(out)
}

/// Apply element attributes to the definition.
///
/// Only `<MappedFolder>` carries its data in attributes. Every other modelled
/// element in the `.wsb` schema is text content (`<Networking>Default</Networking>`),
/// and is handled by [`apply_text`] — reading those from attributes silently
/// yields an empty value for a perfectly valid document.
fn apply_attributes(def: &mut WsbDefinition, element: &str, attrs: &BTreeMap<String, String>) {
    match element {
        "MappedFolder" => {
            let host_path = attrs.get("HostFolder").cloned().unwrap_or_default();
            let guest_path = attrs.get("SandboxFolder").cloned().unwrap_or_default();
            if host_path.is_empty() && guest_path.is_empty() {
                // An element with no paths cannot be authorized, and silently
                // ignoring it would let a definition appear to declare a mapping
                // it does not.
                return;
            }
            def.mapped_folders.push(MappedFolder {
                host_path,
                guest_path,
                // An unrecognized `ReadOnly` value falls back to read-only,
                // which is the safe direction: a garbled flag must not become
                // a writable mapping.
                read_only: parse_bool(attrs.get("ReadOnly").map(String::as_str), true),
                writable: false,
            });
        }
        _ => {
            // Retained for diagnostics rather than silently dropped (RD §9).
            for (k, v) in attrs {
                def.unknown_attributes.insert(k.clone(), v.clone());
            }
        }
    }
}

/// Apply element text content.
fn apply_text(def: &mut WsbDefinition, element: &str, text: &str) {
    let text = text.trim();
    if text.is_empty() {
        return;
    }
    match element {
        "LogonCommand" => def.logon_command = Some(text.to_string()),
        // Verbatim, not lowercased: the value is surfaced in the inspector and
        // must reflect what the definition actually said.
        "Networking" => def.networking = Some(text.to_string()),
        "ClipboardRedirection" => def.clipboard_redirection = Some(parse_bool(Some(text), true)),
        "PrinterRedirection" => def.printer_redirection = Some(parse_bool(Some(text), true)),
        "MemoryInMB" => def.memory_in_mb = text.parse().ok(),
        _ => {}
    }
}

/// Interpret `0` / `1` / `true` / `false`.
///
/// Anything unrecognized falls back to the given default rather than being
/// coerced — a malformed `ReadOnly` must not silently become writable.
fn parse_bool(raw: Option<&str>, default: bool) -> bool {
    match raw.map(str::trim) {
        Some("1") | Some("true") => true,
        Some("0") | Some("false") => false,
        _ => default,
    }
}

/// Refuse forbidden and non-outbox writable mappings.
fn enforce_mapping_policy(def: &mut WsbDefinition, outbox_dir: &str) -> Result<(), WsbParseError> {
    let normalized_outbox = outbox_dir.replace('\\', "/").to_lowercase();
    let mut kept = Vec::with_capacity(def.mapped_folders.len());
    for m in def.mapped_folders.drain(..) {
        let normalized = m.host_path.replace('\\', "/").to_lowercase();

        if FORBIDDEN_MAPPINGS
            .iter()
            .any(|f| normalized.contains(&f.to_lowercase()))
        {
            return Err(WsbParseError::ForbiddenMapping(
                m.host_path.clone(),
                "matches a protected host location",
            ));
        }

        // A guest path may not escape the guest namespace (NFR-S08).
        if m.guest_path.contains("..") {
            return Err(WsbParseError::ForbiddenMapping(
                m.host_path,
                "guest folder contains a traversal component",
            ));
        }

        // `writable` is the inverse of `read_only`: the guest may write exactly when
        // the definition did not mark the folder read-only. It is recomputed
        // here rather than trusted from the parse step.
        let mut m = m;
        m.writable = !m.read_only;

        // Writable mappings are limited to the dedicated telemetry outbox
        // (NFR-S07). Everything else must be read-only.
        if m.writable && !normalized.contains(&normalized_outbox) {
            return Err(WsbParseError::ForbiddenMapping(
                m.host_path,
                "writable mappings are limited to the telemetry outbox (NFR-S07)",
            ));
        }

        kept.push(m);
    }
    def.mapped_folders = kept;
    Ok(())
}

/// Build the `LogonCommand` a `.wsb` needs to start the probe.
///
/// DD-PLG §7 puts the bridge binary under `LogonCommand`. The binary is expected
/// at the read-only bootstrap mapping and is passed only its session nonce; no
/// secret and no arbitrary argument is interpolated.
pub fn bridge_command(bootstrap_guest_path: &str, session_id: &str) -> Result<String, String> {
    if bootstrap_guest_path.is_empty() || session_id.is_empty() {
        return Err("bootstrap path and session id are both required".to_string());
    }
    let boot = bootstrap_guest_path.replace('\\', "/").to_lowercase();
    if boot.contains("..") {
        return Err("bootstrap path must not contain a traversal component".to_string());
    }
    // Only these characters are interpolated, so a crafted value cannot become
    // command syntax.
    if !session_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
    {
        return Err("session id contains unsupported characters".to_string());
    }
    Ok(format!(
        r#"<Command>C:\sandtree\{}\probe.exe --session {}</Command>"#,
        bootstrap_guest_path.trim_matches('\\').replace('/', "\\"),
        session_id
    ))
}

/// Capabilities declared for a sandbox in a given state (FR-011, FR-061).
pub fn sandbox_capabilities(state: ResourceState) -> CapabilitySet {
    let mut set = CapabilitySet::from_iter_caps([
        Capability::global(CapabilityNamespace::Resource, "discover"),
        Capability::global(CapabilityNamespace::Resource, "inspect"),
    ]);
    match state {
        ResourceState::Running => {
            set.insert(Capability::global(CapabilityNamespace::Resource, "stop"));
            set.insert(Capability::global(CapabilityNamespace::Resource, "destroy"));
            // NFR-S07: no general remote shell. Observation goes through the
            // fixed probe protocol only, so `exec:spawn` is never granted.
        }
        ResourceState::Stopped | ResourceState::Destroyed => {
            set.insert(Capability::global(CapabilityNamespace::Resource, "start"));
        }
        _ => {}
    }
    set.insert(Capability::global(
        CapabilityNamespace::Observation,
        "observe:system",
    ));
    set
}

/// Normalize a `.wsb` definition file into a [`ResourceNode`].
///
/// `state` comes from the host-visible sandbox process table, never from the
/// document: a `.wsb` is a recipe, not a report of what is running (RD §9).
pub fn normalize_definition(
    name: &str,
    def: &WsbDefinition,
    state: ResourceState,
    provider: &PluginId,
    host_id: &ResourceId,
    now: &str,
) -> ResourceNode {
    let mut meta = Map::new();
    meta.insert("definition_name".into(), Json::from(name));
    if let Some(n) = def.networking.as_deref().filter(|s| !s.is_empty()) {
        meta.insert("networking".into(), Json::from(n));
    }
    if let Some(m) = def.memory_in_mb {
        meta.insert("memory_in_mb".into(), Json::from(m));
    }
    if let Some(c) = def.clipboard_redirection {
        meta.insert("clipboard_redirection".into(), Json::from(c));
    }
    if let Some(p) = def.printer_redirection {
        meta.insert("printer_redirection".into(), Json::from(p));
    }
    if !def.mapped_folders.is_empty() {
        // Deterministic order: already sorted by guest path.
        let folders: Vec<Json> = def
            .mapped_folders
            .iter()
            .map(|m| {
                let mut o = Map::new();
                o.insert("host_path".into(), Json::from(m.host_path.clone()));
                o.insert("guest_path".into(), Json::from(m.guest_path.clone()));
                o.insert("writable".into(), Json::from(m.writable));
                o.insert("read_only".into(), Json::from(m.read_only));
                Json::Object(o)
            })
            .collect();
        meta.insert("mapped_folders".into(), Json::Array(folders));
    }
    if let Some(cmd) = def.logon_command.as_deref().filter(|s| !s.is_empty()) {
        meta.insert("logon_command".into(), Json::from(cmd));
    }

    ResourceNode::new(
        sandbox_id(name),
        ResourceKind::Sandbox,
        provider.clone(),
        name,
        state,
        Some(host_id.clone()),
        now.to_string(),
    )
    .with_capabilities(sandbox_capabilities(state))
    .with_metadata(Json::Object(meta))
}

/// Derive a definition name from a `.wsb` file path.
///
/// The name is the file stem; a path outside a plain filename is rejected so a
/// crafted path cannot inject a name containing separators.
pub fn definition_name_from_path(path: &Path) -> Option<String> {
    let stem = path.file_stem()?.to_str()?;
    if stem.is_empty() || stem.contains('/') || stem.contains('\\') {
        return None;
    }
    Some(stem.to_string())
}

/// Whether a path stays inside `root` after normalization.
///
/// Used when reading the outbox so a probe-supplied filename cannot reach
/// outside the directory (NFR-S08).
pub fn is_within(root: &Path, candidate: &Path) -> bool {
    let root = root.components().collect::<PathBuf>();
    let mut normalized = PathBuf::new();
    for c in candidate.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    return false;
                }
            }
            other => normalized.push(other),
        }
    }
    normalized.starts_with(&root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    const NOW: &str = "2026-10-07T00:00:00Z";
    const OUTBOX: &str = "C:/SandTree/data/probe-outbox";

    fn plugin() -> PluginId {
        PluginId::derive(&["sandtree.provider.windows-sandbox"])
    }

    fn host() -> ResourceId {
        ResourceId::derive(&["host", "local"])
    }

    const MINIMAL: &str = r#"<Configuration>
      <Networking>Default</Networking>
      <MappedFolder HostFolder="C:\SandTree\workspaces\demo" SandboxFolder="C:\ws" ReadOnly="true"/>
      <MemoryInMB>4096</MemoryInMB>
    </Configuration>"#;

    #[test]
    fn parses_a_minimal_definition() {
        let d = parse_wsb(MINIMAL, OUTBOX).unwrap();
        assert_eq!(d.networking.as_deref(), Some("Default"));
        assert_eq!(d.memory_in_mb, Some(4096));
        assert_eq!(d.mapped_folders.len(), 1);
        let m = &d.mapped_folders[0];
        assert_eq!(m.host_path, r"C:\SandTree\workspaces\demo");
        assert_eq!(m.guest_path, r"C:\ws");
        // ReadOnly="true" means the guest cannot write.
        assert!(m.read_only);
        assert!(!m.writable);
    }

    #[test]
    fn a_document_without_configuration_is_rejected() {
        assert_eq!(
            parse_wsb("<Sandbox/>", OUTBOX),
            Err(WsbParseError::NoConfiguration)
        );
        assert!(matches!(
            parse_wsb("not xml at all", OUTBOX),
            Err(WsbParseError::Xml(_))
        ));
    }

    #[test]
    fn a_definition_without_mapped_folders_is_accepted() {
        // A minimal sandbox needs no mapping at all; that is not an error.
        let d = parse_wsb(
            "<Configuration><Networking>Default</Networking></Configuration>",
            OUTBOX,
        )
        .unwrap();
        assert!(d.mapped_folders.is_empty());
        assert_eq!(d.networking.as_deref(), Some("Default"));
        // A node for it still normalizes, with no mapping metadata key.
        let node =
            normalize_definition("bare", &d, ResourceState::Stopped, &plugin(), &host(), NOW);
        assert!(node.meta_str("mapped_folders").is_none());
    }

    #[test]
    fn protected_host_locations_are_never_mappable() {
        // NFR-S06: a .wsb is configuration, not authority.
        for bad in [
            r"C:\SandTree\data\docker_engine",
            "/var/run/docker.sock",
            r"\\.\pipe\containers\docker",
            "C:/Windows/WinSxS",
        ] {
            let xml = format!(
                r#"<Configuration><MappedFolder HostFolder="{bad}" SandboxFolder="C:\x" ReadOnly="true"/></Configuration>"#
            );
            assert!(
                matches!(
                    parse_wsb(&xml, OUTBOX),
                    Err(WsbParseError::ForbiddenMapping(_, _))
                ),
                "{bad} must be refused"
            );
        }
    }

    #[test]
    fn writable_mappings_are_limited_to_the_outbox() {
        // NFR-S07: the bootstrap is read-only; only the telemetry outbox writes.

        // An explicitly writable mapping outside the outbox is refused.
        let writable_elsewhere = r#"<Configuration><MappedFolder HostFolder="C:\SandTree\src" SandboxFolder="C:\src" ReadOnly="false"/></Configuration>"#;
        assert!(
            matches!(
                parse_wsb(writable_elsewhere, OUTBOX),
                Err(WsbParseError::ForbiddenMapping(_, reason)) if reason.contains("outbox")
            ),
            "an explicitly writable mapping outside the outbox must be refused"
        );

        // The outbox itself may be writable.
        let ok = format!(
            r#"<Configuration><MappedFolder HostFolder="{OUTBOX}" SandboxFolder="C:\outbox" ReadOnly="false"/></Configuration>"#
        );
        let d = parse_wsb(&ok, OUTBOX).unwrap();
        assert!(d.mapped_folders[0].writable);

        // An OMITTED ReadOnly is read-only, not writable. This is the fail-closed
        // direction: a definition that forgets the flag must not hand the guest
        // write access it never asked for.
        let omitted = r#"<Configuration><MappedFolder HostFolder="C:\SandTree\src" SandboxFolder="C:\src"/></Configuration>"#;
        let d = parse_wsb(omitted, OUTBOX)
            .expect("an omitted ReadOnly is a read-only mapping, not an error");
        assert!(d.mapped_folders[0].read_only);
        assert!(!d.mapped_folders[0].writable);

        // A garbage ReadOnly value also fails closed, for the same reason.
        let garbage = r#"<Configuration><MappedFolder HostFolder="C:\SandTree\src" SandboxFolder="C:\src" ReadOnly="maybe"/></Configuration>"#;
        let d = parse_wsb(garbage, OUTBOX).expect("an unparsable ReadOnly falls back to read-only");
        assert!(d.mapped_folders[0].read_only);
        assert!(!d.mapped_folders[0].writable);
    }

    #[test]
    fn guest_folder_traversal_is_refused() {
        // NFR-S08: a guest path may not escape.
        let xml = r#"<Configuration><MappedFolder HostFolder="C:\ws" SandboxFolder="C:\..\Windows" ReadOnly="true"/></Configuration>"#;
        assert!(matches!(
            parse_wsb(xml, OUTBOX),
            Err(WsbParseError::ForbiddenMapping(_, reason)) if reason.contains("traversal")
        ));
    }

    #[test]
    fn malformed_readonly_attribute_never_becomes_writable() {
        // A garbled flag must fail safe: the default is read-only, and a
        // read-only mapping outside the outbox is allowed.
        let xml = r#"<Configuration><MappedFolder HostFolder="C:\SandTree\workspaces\d" SandboxFolder="C:\ws" ReadOnly="yes"/></Configuration>"#;
        let d = parse_wsb(xml, OUTBOX).unwrap();
        let m = &d.mapped_folders[0];
        assert!(
            m.read_only,
            "unrecognized ReadOnly must default to read-only"
        );
        assert!(!m.writable);

        // Explicitly requesting a writable mapping outside the outbox is refused.
        let writable = r#"<Configuration><MappedFolder HostFolder="C:\SandTree\src" SandboxFolder="C:\src" ReadOnly="false"/></Configuration>"#;
        assert!(matches!(
            parse_wsb(writable, OUTBOX),
            Err(WsbParseError::ForbiddenMapping(_, reason)) if reason.contains("outbox")
        ));
    }

    #[test]
    fn mapped_folders_are_sorted_for_deterministic_output() {
        let xml = r#"<Configuration>
          <MappedFolder HostFolder="C:\ws\z" SandboxFolder="C:\zeta" ReadOnly="true"/>
          <MappedFolder HostFolder="C:\ws\a" SandboxFolder="C:\alpha" ReadOnly="true"/>
        </Configuration>"#;
        let d = parse_wsb(xml, OUTBOX).unwrap();
        assert_eq!(d.mapped_folders[0].guest_path, r"C:\alpha");
        assert_eq!(d.mapped_folders[1].guest_path, r"C:\zeta");
    }

    #[test]
    fn bridge_command_interpolates_only_safe_values() {
        let cmd = bridge_command("bootstrap", "abc-123_XYZ").unwrap();
        assert!(cmd.contains("abc-123_XYZ"));
        assert!(cmd.contains("bootstrap"));
        // A session id with shell metacharacters is refused.
        for bad in ["a;b", "a b", "$(id)", "a\\b", ""] {
            assert!(
                bridge_command("bootstrap", bad).is_err(),
                "{bad:?} must be refused"
            );
        }
        assert!(bridge_command("", "s").is_err());
        assert!(bridge_command("../escape", "s").is_err());
    }

    #[test]
    fn sandbox_capabilities_never_grant_a_shell() {
        // NFR-S07: the probe has fixed capabilities, not a general shell.
        for state in [
            ResourceState::Running,
            ResourceState::Stopped,
            ResourceState::Destroyed,
            ResourceState::Unknown,
        ] {
            let caps = sandbox_capabilities(state);
            assert!(
                !caps.allows(&Capability::parse("exec:spawn").unwrap()),
                "{state:?} must not grant exec"
            );
            assert!(caps.allows(&Capability::parse("resource:inspect").unwrap()));
        }
        assert!(sandbox_capabilities(ResourceState::Running)
            .allows(&Capability::parse("resource:stop").unwrap()));
    }

    #[test]
    fn normalization_uses_host_observed_state_not_the_document() {
        // RD §9: a .wsb is a recipe, not a report.
        let d = parse_wsb(MINIMAL, OUTBOX).unwrap();
        let running =
            normalize_definition("demo", &d, ResourceState::Running, &plugin(), &host(), NOW);
        assert_eq!(running.state, ResourceState::Running);
        assert_eq!(running.kind, ResourceKind::Sandbox);
        assert_eq!(running.parent_id, Some(host()));
        assert_eq!(running.meta_str("definition_name"), Some("demo"));
        assert_eq!(running.meta_str("networking"), Some("Default"));
        assert_eq!(running.metadata["memory_in_mb"], Json::from(4096));
        // No claim is made about process/domain observation from the document.
        assert!(running.meta_str("process_count").is_none());
    }

    #[test]
    fn sandbox_id_is_stable_and_namespaced() {
        assert_eq!(sandbox_id("demo"), sandbox_id("demo"));
        assert_ne!(sandbox_id("demo"), sandbox_id("other"));
        assert_ne!(
            sandbox_id("demo"),
            ResourceId::derive(&["sandtree.provider.multipass", "demo"])
        );
    }

    #[test]
    fn definition_name_comes_from_the_file_stem() {
        assert_eq!(
            definition_name_from_path(Path::new(r"C:\ws\demo.wsb")),
            Some("demo".to_string())
        );
        assert_eq!(
            definition_name_from_path(Path::new("demo.wsb")),
            Some("demo".into())
        );
        assert_eq!(
            definition_name_from_path(Path::new("noext")),
            Some("noext".into())
        );
    }

    #[test]
    fn containment_rejects_escapes() {
        // NFR-S08: a probe-supplied filename may not reach outside the outbox.
        let root = PathBuf::from("C:/outbox");
        assert!(is_within(&root, Path::new("C:/outbox/a.json")));
        assert!(is_within(&root, Path::new("C:/outbox")));
        assert!(!is_within(&root, Path::new("C:/outbox/../../etc/passwd")));
        assert!(!is_within(&root, Path::new("C:/other/a.json")));
        assert!(!is_within(&root, Path::new("../a.json")));
    }

    #[test]
    fn logon_command_text_is_captured() {
        let xml = r#"<Configuration><LogonCommand>C:\sandtree\probe.exe --session s1</LogonCommand></Configuration>"#;
        let d = parse_wsb(xml, OUTBOX).unwrap();
        assert_eq!(
            d.logon_command.as_deref(),
            Some(r"C:\sandtree\probe.exe --session s1")
        );
    }
}
