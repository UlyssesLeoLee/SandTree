//! Repository-level invariants that no single crate can enforce.
//!
//! # Why this file exists
//!
//! `AGENTS.md` states hard invariants about the *shape of the repository*, not
//! about the behaviour of any one crate:
//!
//! 1. the microkernel must not depend on a provider SDK (NFR-O02);
//! 2. `crates/*` must not depend on the mock crates (ADR-010);
//! 3. the default implementation must stay Rust-first (NFR-O03).
//!
//! A unit test inside `crates/kernel` cannot see any of them — by the time it
//! runs, the dependency already exists. So they are asserted here, against the
//! manifests themselves, where a violation is visible.
//!
//! # The self-invalidation rule
//!
//! Every check below counts what it scanned and fails when the count is zero.
//! A manifest scanner pointed at the wrong path returns no findings and looks
//! exactly like a clean result; "no violations found" and "nothing was looked
//! at" are the same output, and only the second one is useless. The thresholds
//! are the difference, so they are asserted rather than assumed.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("tests/contract is two levels below the workspace root")
        .to_path_buf()
}

/// Dependency names declared in one of a manifest's dependency tables.
///
/// Reads the `[dependencies]`, `[dev-dependencies]` and `[build-dependencies]`
/// tables and returns the declared keys. Deliberately a text scan rather than a
/// TOML parse: a vendored `toml` parser would be a new dependency in the one
/// package whose job is to have as few as possible, and the shapes involved are
/// a flat `key = ...` list.
fn declared_dependencies(manifest: &Path) -> BTreeSet<String> {
    let text = std::fs::read_to_string(manifest)
        .unwrap_or_else(|e| panic!("{} must be readable: {e}", manifest.display()));
    let mut found = BTreeSet::new();
    let mut in_table = false;
    for raw in text.lines() {
        let line = raw.trim();
        if line.starts_with('[') {
            in_table = matches!(
                line.trim_start_matches('[').trim_end_matches(']'),
                "dependencies" | "dev-dependencies" | "build-dependencies"
            );
            continue;
        }
        if !in_table || line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, _)) = line.split_once('=') {
            let name = key.trim().trim_matches('"');
            if !name.is_empty() {
                found.insert(name.to_string());
            }
        }
    }
    found
}

// --- UT-042: the kernel closure has no provider SDK -------------------------

/// NFR-O02: the microkernel closure must not name a provider SDK.
///
/// This is a direct-dependency check. A transitive one needs `cargo metadata`
/// and a resolver walk, which would make the contract test depend on the very
/// toolchain it is supposed to police; the direct form is what a contributor
/// actually types, and it is the form `AGENTS.md` names.
#[test]
fn the_microkernel_crates_declare_no_provider_sdk() {
    const FORBIDDEN: [&str; 5] = ["bollard", "wasmtime", "rusqlite", "shiplift", "windows"];
    // `crates/store` is deliberately absent: it owns `sandtree.db` and the CAS,
    // so rusqlite is its job. What matters is that the three crates below do
    // not reach a provider SDK by any route.
    const KERNEL_CRATES: [&str; 3] = ["kernel", "model", "resource-graph"];

    let root = repo_root();
    let mut scanned_deps = 0usize;

    for crate_name in KERNEL_CRATES {
        let manifest = root.join("crates").join(crate_name).join("Cargo.toml");
        assert!(
            manifest.is_file(),
            "{} must exist; if it was renamed, this rule is no longer checking \
             the crate it was written for: {}",
            crate_name,
            manifest.display()
        );
        let deps = declared_dependencies(&manifest);
        scanned_deps += deps.len();

        for bad in FORBIDDEN {
            assert!(
                !deps.contains(bad),
                "NFR-O02: crates/{crate_name} must not depend on `{bad}`. The \
                 kernel crosses the plugin boundary through domain DTOs or WIT \
                 only, so a provider SDK type cannot appear in its signature."
            );
        }
    }

    // Self-invalidation: three manifests with zero dependencies between them is
    // a parser that stopped finding `[dependencies]`, not a clean tree.
    assert!(
        scanned_deps > 10,
        "scanned {scanned_deps} dependency keys across {KERNEL_CRATES:?}; a \
         scanner that finds nothing reports the same 'clean' as a real pass"
    );
}

/// The same rule stated from the other side: the three crates must not reach a
/// provider crate *of this workspace* either. A workspace-internal path
/// dependency would carry the same SDK transitively.
#[test]
fn the_microkernel_crates_reach_no_provider_crate() {
    let root = repo_root();
    let manifest = root.join("crates").join("kernel").join("Cargo.toml");
    let deps = declared_dependencies(&manifest);

    let provider_crates = provider_crate_names(&root);

    assert!(
        !deps.is_empty(),
        "crates/kernel declares dependencies; an empty set means the manifest \
         could not be read"
    );
    for dep in &deps {
        assert!(
            !provider_crates.contains(dep.as_str()),
            "NFR-O02: crates/kernel must not depend on `{dep}` -- that is the \
             provider boundary the microkernel exists to hide"
        );
    }
}

/// Every provider crate in the workspace, **discovered** from `plugins/`.
///
/// This used to be a hand-written list of four names. That list was correct
/// until a fifth provider was added and nothing noticed: the rule kept
/// reporting a clean tree while `crates/kernel` could have reached the new
/// provider and this test would still have passed. The failure mode of a
/// hand-written input set is that it is indistinguishable from a clean result.
///
/// So the set is derived from the tree, and the caller asserts a floor on how
/// many were found — a walk that finds nothing must be loud.
///
/// The map is keyed by **package name** and valued by the crate's source
/// directory. The two differ (`sandtree-provider-git-remote` lives in
/// `plugins/provider-git-remote`), and a rule that joins a package name onto
/// `plugins/` reports "path not found" for a plugin that is present and
/// working — a false alarm dressed as a real failure.
fn provider_crate_sources(root: &Path) -> BTreeMap<String, PathBuf> {
    let mut found = BTreeMap::new();
    let plugins = root.join("plugins");
    for entry in std::fs::read_dir(&plugins).unwrap_or_else(|e| panic!("plugins/ is readable: {e}"))
    {
        let dir = entry.expect("dir entry").path();
        if !dir.is_dir() {
            continue;
        }
        let manifest = dir.join("Cargo.toml");
        if manifest.is_file() {
            if let Some(name) = package_name(&manifest) {
                found.insert(name, dir.join("src"));
            }
        }
    }
    assert!(
        found.len() >= 6,
        "only {} provider crates were discovered under plugins/ ({}); a walk \
         that finds nothing reports the same 'clean' as a real pass",
        found.len(),
        found.keys().cloned().collect::<Vec<_>>().join(", ")
    );
    found
}

/// Package names of every provider crate in the workspace.
fn provider_crate_names(root: &Path) -> BTreeSet<String> {
    provider_crate_sources(root).into_keys().collect()
}

/// The `name = "..."` in a manifest's `[package]` table.
fn package_name(manifest: &Path) -> Option<String> {
    let text = std::fs::read_to_string(manifest).ok()?;
    let mut in_package = false;
    for raw in text.lines() {
        let line = raw.trim();
        if line.starts_with('[') {
            in_package = line.trim_start_matches('[').trim_end_matches(']') == "package";
            continue;
        }
        if !in_package {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            if key.trim() == "name" {
                return Some(value.trim().trim_matches('"').to_string());
            }
        }
    }
    None
}

/// ADR-010: mock crates are test assets. `tests/*` may use them; `crates/*`
/// may not, or the fake becomes part of the product and starts deciding what
/// the product believes.
#[test]
fn only_test_targets_depend_on_the_mock_crates() {
    let root = repo_root();
    let mock_crates: BTreeSet<&str> = [
        "sandtree-mock-runtime",
        "sandtree-mock-observation",
        "sandtree-mock-wasm-components",
    ]
    .into_iter()
    .collect();

    let mut crates_checked = 0usize;
    for entry in std::fs::read_dir(root.join("crates")).expect("crates/ is readable") {
        let dir = entry.expect("dir entry").path();
        if !dir.is_dir() {
            continue;
        }
        let manifest = dir.join("Cargo.toml");
        if !manifest.is_file() {
            continue;
        }
        crates_checked += 1;
        let deps = declared_dependencies(&manifest);
        for dep in &deps {
            assert!(
                !mock_crates.contains(dep.as_str()),
                "ADR-010: {} must not depend on `{dep}`. Mock crates exist so \
                 tests can run with no Docker daemon, Multipass or Windows \
                 Sandbox; a product crate depending on one means a regression \
                 run and a production build disagree about what is real.",
                manifest.display()
            );
        }
    }
    assert!(
        crates_checked >= 10,
        "only {crates_checked} crate manifests were scanned; a walk that finds \
         nothing looks exactly like a workspace with no violations"
    );
}

// --- UT-043: the Rust-first baseline ---------------------------------------

/// NFR-O03: every MUST row in `schemas/technology_baseline.csv` is Rust or
/// Rust-facing, and anything that is not declares itself external.
///
/// "Rust-facing" is the design's own phrase for a technology the Rust
/// ecosystem owns or speaks to. The external escape hatch exists because two
/// MUST rows name runtimes this project deliberately does not redistribute --
/// Docker Engine and Compose -- and a rule that could not express that would
/// force a false exception instead of an honest stance.
#[test]
fn every_must_row_in_the_technology_baseline_is_rust_facing() {
    const RUST_FACING: [&str; 16] = [
        "rust",
        "tokio",
        "serde",
        "serde_json",
        "wasmtime",
        "component model",
        "wit",
        "rusqlite",
        "sqlite",
        "tauri",
        "bollard",
        "redb",
        "blake3",
        "tracing",
        "clap",
        "cargo-deny",
    ];
    const EXTERNAL_MARKERS: [&str; 3] = ["external", "not redistributed", "if installed"];

    let csv = repo_root().join("schemas").join("technology_baseline.csv");
    // The file ships with a UTF-8 BOM. Reading it as plain UTF-8 leaves the BOM
    // glued to the first header cell, so `Layer` never matches and every
    // downstream lookup is off by one column -- the classic way a data-driven
    // check passes by reading nothing.
    let text = std::fs::read_to_string(&csv)
        .unwrap_or_else(|e| panic!("{} must be readable: {e}", csv.display()))
        .trim_start_matches('\u{feff}')
        .to_string();

    let mut must_rows: Vec<(String, String, String)> = Vec::new(); // (layer, technology, stance)

    for (i, raw) in text.lines().enumerate() {
        // The License column contains commas inside quotes, so the split is
        // bounded to the leading columns: everything after the stance start is
        // not needed to make the decision.
        if i == 0 {
            let header: Vec<String> = raw.split(',').map(|s| s.trim().to_string()).collect();
            assert_eq!(
                header.first().map(String::as_str),
                Some("Layer"),
                "the baseline's first column must stay `Layer`, got {header:?}"
            );
            continue;
        }
        if raw.trim().is_empty() {
            continue;
        }
        let mut cols = raw.splitn(4, ',');
        let layer = cols.next().unwrap_or_default().trim().to_string();
        let technology = cols.next().unwrap_or_default().trim().to_string();
        let stance_and_rest = cols.next().unwrap_or_default();
        let rest = cols.next().unwrap_or_default();
        let stance = format!("{stance_and_rest} {rest}");

        if stance.to_uppercase().contains("MUST") || raw.to_uppercase().contains("MUST") {
            must_rows.push((layer, technology, stance));
        }
    }

    assert!(
        must_rows.len() >= 6,
        "the baseline declares {} MUST rows; a reformat that yields fewer makes \
         this rule check almost nothing",
        must_rows.len()
    );

    for (layer, technology, stance) in &must_rows {
        let lowered = technology.to_lowercase();
        let rust_facing = RUST_FACING.iter().any(|r| lowered.contains(r));
        let external = EXTERNAL_MARKERS
            .iter()
            .any(|m| stance.to_lowercase().contains(m));

        assert!(
            rust_facing || external,
            "NFR-O03: the MUST row for `{layer}` / `{technology}` is neither \
             Rust-facing nor declared external (stance: `{stance}`). Every \
             exception needs a written ADR; a silent one is not an exception."
        );
    }

    // The Rust-first claim itself, not just the rows around it.
    let language = must_rows
        .iter()
        .find(|(layer, ..)| layer == "Language")
        .expect("the baseline has a Language row");
    assert!(
        language.1.to_lowercase().contains("rust"),
        "the language baseline must still name Rust, got `{}`",
        language.1
    );
}

/// Every relation kind the model declares has a wire name the DDL can store,
/// and the two sides agree. A new `RelationKind` added to the model without a
/// matching DDL column value would otherwise only fail on a real scan.
#[test]
fn relation_kinds_are_all_representable_in_the_frozen_model() {
    use sandtree_model::resource::RelationKind;

    const ALL: [RelationKind; 6] = [
        RelationKind::UsesImage,
        RelationKind::Mounts,
        RelationKind::AttachedNetwork,
        RelationKind::MemberOfCompose,
        RelationKind::WorkspaceMount,
        RelationKind::DockerInSandbox,
    ];
    let mut names: Vec<&str> = ALL.iter().map(|k| k.as_str()).collect();
    let sorted = {
        let mut s = names.clone();
        s.sort_unstable();
        s.dedup();
        s
    };
    assert_eq!(
        names.len(),
        sorted.len(),
        "two relation kinds share a wire name, so one would overwrite the other \
         in `resource_relation`"
    );
    names.sort_unstable();
    assert_eq!(names, sorted, "wire names are snake_case and stable");
}

// --- UT-044: the network-acquisition gate is not bypassable -----------------

/// ADR-015: both network channels must go through `sandtree-policy`'s admission
/// gate, and neither may stamp a trust ceiling of its own.
///
/// The per-crate tests in `crates/policy` prove the *rule* is correct. They
/// cannot prove the rule is *reached*: a provider that skips `authorize` and
/// fetches anyway compiles fine, passes its own tests, and violates the whole
/// design. That is a repository-shaped fact, so it is asserted here.
///
/// Discovered from `plugins/`, not hand-listed: a gate that only checks the two
/// providers it was written for reports a clean tree the moment a third channel
/// appears.
#[test]
fn every_network_channel_plugin_goes_through_the_acquisition_gate() {
    /// Plugins that open a network connection. Matched by name, and asserted
    /// below that at least this many were found.
    const NETWORK_PLUGINS: [&str; 2] = [
        "sandtree-provider-git-remote",
        "sandtree-provider-mcp-remote",
    ];

    let root = repo_root();
    let sources = provider_crate_sources(&root);

    let mut checked = 0usize;
    for name in NETWORK_PLUGINS {
        let src = sources
            .get(name)
            .unwrap_or_else(|| {
                panic!(
                    "{name} is named as a network channel but was not found \
                     under plugins/. Either it was renamed or moved, and this \
                     rule is no longer checking what it was written for."
                )
            })
            .clone();

        let mut gated = false;
        let mut files = 0usize;
        for entry in std::fs::read_dir(&src).unwrap_or_else(|e| panic!("{src:?}: {e}")) {
            let path = entry.expect("dir entry").path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            files += 1;
            let text = std::fs::read_to_string(&path).unwrap_or_default();
            if text.contains("acquire::AcquisitionPolicy") || text.contains("authorize_or_error") {
                gated = true;
            }
        }
        assert!(
            files > 0,
            "no .rs files were scanned under {}",
            src.display()
        );
        checked += 1;
        assert!(
            gated,
            "ADR-015/NFR-S02: {name} opens a network connection but \
             nothing in it calls `sandtree_policy::acquire`. The admission \
             rule -- network acquisition only when penetrating the same \
             resource and domain was refused -- is the security property of the \
             whole channel; a plugin that does not route through it can fetch \
             from a sandbox that the host can already read directly."
        );
    }
    assert!(checked >= 2, "only {checked} network channels were checked");
}

/// ADR-OBS-003 as a repository fact: `GuestProbe` is the ceiling for anything
/// obtained over the network, and the ceiling is defined in exactly one place.
///
/// The interesting failure is not "someone wrote the wrong constant" -- the
/// per-crate tests catch that. It is someone adding a second definition of the
/// ceiling in a plugin, which then drifts from the policy crate and quietly
/// raises trust for one channel only.
#[test]
fn the_network_trust_ceiling_is_defined_in_exactly_one_place() {
    let root = repo_root();
    let policy = root
        .join("crates")
        .join("policy")
        .join("src")
        .join("acquire.rs");
    let policy_text = std::fs::read_to_string(&policy).unwrap_or_default();

    assert!(
        policy_text.contains("pub const NETWORK_TRUST_CEILING"),
        "the ceiling constant must live in crates/policy/src/acquire.rs; if it \
         moved, this rule is checking the wrong file"
    );

    // Where a network channel is allowed to live.
    let sources = provider_crate_sources(&root);
    let mut scanned = 0usize;
    for name in [
        "sandtree-provider-git-remote",
        "sandtree-provider-mcp-remote",
    ] {
        let src = sources
            .get(name)
            .unwrap_or_else(|| panic!("{name} is not present under plugins/"))
            .clone();
        for entry in std::fs::read_dir(&src).unwrap_or_else(|e| panic!("{src:?}: {e}")) {
            let path = entry.expect("dir entry").path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).unwrap_or_default();
            scanned += 1;
            // The ceiling may be *referenced*, never re-declared.
            assert!(
                !text.contains("const NETWORK_TRUST_CEILING"),
                "{} re-declares the network trust ceiling. It must reference \
                 `sandtree_policy::acquire::NETWORK_TRUST_CEILING`; a second \
                 definition can drift from the policy crate and raise trust for \
                 one channel only.",
                path.display()
            );
        }
    }
    assert!(
        scanned >= 10,
        "only {scanned} provider source files were scanned; a walk that finds \
         nothing reports the same 'clean' as a real pass"
    );
}
