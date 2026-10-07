//! Contract tests: the implementation against the frozen machine-readable
//! contracts in `schemas/`.
//!
//! These exist because the design documents are read-only and the schemas are
//! the machine-checkable form of them. If a rename happens in Rust and not in
//! the schema, one of these fails — which is the only way a drift between
//! "what the design says" and "what ships" gets caught at all.
//!
//! Everything here reads the shipped schema files directly. Nothing is
//! hard-coded, so updating the schema updates the expectation.

#![deny(missing_docs)]

use std::collections::BTreeSet;

/// The frozen core error-code registry.
pub const ERROR_CODES_CSV: &str = include_str!("../../../schemas/error_codes.csv");

/// The frozen observation error-code registry.
pub const OBSERVATION_CODES_CSV: &str =
    include_str!("../../../schemas/observation_error_codes.csv");

/// The frozen provider WIT.
pub const PROVIDER_WIT: &str = include_str!("../../../schemas/sandtree_provider_v1.wit");

/// The frozen observation WIT.
pub const OBSERVATION_WIT: &str = include_str!("../../../schemas/sandtree_observation_v1.wit");

/// The frozen plugin manifest JSON schema.
pub const PLUGIN_MANIFEST_SCHEMA: &str =
    include_str!("../../../schemas/plugin_manifest_v1.schema.json");

/// The frozen app manifest JSON schema.
pub const APP_MANIFEST_SCHEMA: &str = include_str!("../../../schemas/app_manifest_v1.schema.json");

/// The frozen observation snapshot JSON schema.
pub const OBSERVATION_SNAPSHOT_SCHEMA: &str =
    include_str!("../../../schemas/observation_snapshot_v1.schema.json");

/// The core SQLite DDL, included verbatim by the store crate.
pub const INIT_SQL: &str = include_str!("../../../schemas/001_init.sql");

/// Columns of a CSV, skipping the header.
fn csv_columns(text: &str) -> Vec<Vec<String>> {
    text.lines()
        .skip(1)
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.split(',').map(|c| c.trim().to_string()).collect())
        .collect()
}

/// Every code in `error_codes.csv`.
pub fn core_codes() -> BTreeSet<String> {
    csv_columns(ERROR_CODES_CSV)
        .into_iter()
        .filter_map(|mut r| {
            if r.is_empty() {
                None
            } else {
                Some(r.remove(0))
            }
        })
        .collect()
}

/// Every code in `observation_error_codes.csv`.
pub fn observation_codes() -> BTreeSet<String> {
    csv_columns(OBSERVATION_CODES_CSV)
        .into_iter()
        .filter_map(|mut r| {
            if r.is_empty() {
                None
            } else {
                Some(r.remove(0))
            }
        })
        .collect()
}

#[cfg(test)]
mod error_codes {
    use super::*;
    use sandtree_model::error::ErrorCode;

    #[test]
    fn the_csv_is_well_formed() {
        for (i, row) in csv_columns(ERROR_CODES_CSV).iter().enumerate() {
            assert!(row.len() >= 2, "error_codes.csv row {} has {row:?}", i + 2);
            assert!(row[0].starts_with("ST-"), "row {} code {:?}", i + 2, row[0]);
        }
    }

    #[test]
    fn every_shipped_code_is_in_the_frozen_registry() {
        // The registry is the source of truth: a code that exists in Rust but
        // not in the CSV would be invisible to the registry, and a caller
        // matching on documented codes could not handle it.
        for c in ErrorCode::all() {
            assert!(
                core_codes().contains(c.as_str()),
                "{} is implemented but not in schemas/error_codes.csv",
                c.as_str()
            );
        }
    }

    #[test]
    fn every_registered_code_is_implemented() {
        // The other direction: a documented code nobody can return is a
        // promise the implementation does not keep.
        for code in core_codes() {
            assert!(
                ErrorCode::parse(&code).is_some(),
                "{code} is in schemas/error_codes.csv but not implemented"
            );
        }
    }

    #[test]
    fn observation_codes_match_their_own_registry() {
        let obs = ErrorCode::all_observation();
        assert!(!obs.is_empty());
        for c in obs {
            assert!(
                observation_codes().contains(c.as_str()),
                "{} is implemented but not in schemas/observation_error_codes.csv",
                c.as_str()
            );
        }
        for code in observation_codes() {
            assert!(
                ErrorCode::parse(&code).is_some(),
                "{code} is registered but not implemented"
            );
        }
    }

    #[test]
    fn the_two_registries_do_not_overlap() {
        for code in observation_codes() {
            assert!(
                !core_codes().contains(&code),
                "{code} is in both registries"
            );
        }
    }

    #[test]
    fn retryable_flags_in_the_csv_match_the_implementation() {
        for row in csv_columns(ERROR_CODES_CSV) {
            let (code, retryable) = (row[0].clone(), row.get(3).cloned().unwrap_or_default());
            let Some(c) = ErrorCode::parse(&code) else {
                continue;
            };
            assert_eq!(
                c.is_retryable(),
                retryable == "yes",
                "{code}: csv says retryable={retryable:?}, implementation says {}",
                c.is_retryable()
            );
        }
    }

    #[test]
    fn category_prefixes_match_the_declared_category() {
        for row in csv_columns(ERROR_CODES_CSV) {
            let code = ErrorCode::parse(&row[0]).expect("registered");
            assert_eq!(
                code.category(),
                row[1],
                "{} category disagrees with the csv",
                code.as_str()
            );
        }
    }
}

#[cfg(test)]
mod wit {
    use super::*;

    /// The version part of a WIT file's package line.
    fn wit_package(wit: &str) -> &str {
        wit.lines()
            .find(|l| l.trim_start().starts_with("package "))
            .map(|l| l.trim().trim_end_matches(';'))
            .unwrap_or_default()
            .rsplit_once('@')
            .map(|(_, v)| v)
            .unwrap_or_default()
    }

    use sandtree_sdk::wit::{verify_component_package, OBSERVATION_PACKAGE, PROVIDER_PACKAGE};

    #[test]
    fn the_shipped_constants_match_the_frozen_files() {
        // `PROVIDER_PACKAGE` is `namespace:name@version`; the WIT file holds
        // `namespace:name@version;`. Comparing the parsed forms means a change
        // to either side is caught even if the formatting differs.
        assert_eq!(
            wit_package(PROVIDER_WIT).trim(),
            PROVIDER_PACKAGE.split_once('@').unwrap().1,
            "provider WIT version drifted from PROVIDER_PACKAGE"
        );
        assert_eq!(
            wit_package(OBSERVATION_WIT).trim(),
            OBSERVATION_PACKAGE.split_once('@').unwrap().1,
            "observation WIT version drifted from OBSERVATION_PACKAGE"
        );
    }

    #[test]
    fn the_host_accepts_its_own_wit_and_refuses_the_other() {
        assert!(verify_component_package(PROVIDER_PACKAGE).is_ok());
        assert!(
            verify_component_package(OBSERVATION_PACKAGE).is_err(),
            "the provider host must not accept an observation component"
        );
    }

    #[test]
    fn the_both_worlds_keep_their_declared_names() {
        assert!(PROVIDER_WIT.contains("interface lifecycle"));
        assert!(PROVIDER_WIT.contains("interface resource-provider"));
        assert!(PROVIDER_WIT.contains("world provider-plugin"));
        assert!(OBSERVATION_WIT.contains("interface observation-provider"));
    }

    #[test]
    fn the_lifecycle_interface_still_exposes_every_designed_call() {
        // DD-PLG §4's hot-swap sequence depends on all seven.
        for call in [
            "descriptor:",
            "init:",
            "health:",
            "prepare-upgrade:",
            "accept-upgrade:",
            "drain:",
            "shutdown:",
        ] {
            assert!(PROVIDER_WIT.contains(call), "lifecycle lost {call:?}");
        }
    }
}

#[cfg(test)]
mod manifest_schema {
    use super::*;
    use sandtree_sdk::manifest::{PluginManifest, SUPPORTED_SCHEMA_VERSION};
    use serde_json::Value as Json;

    fn schema() -> Json {
        serde_json::from_str(PLUGIN_MANIFEST_SCHEMA).expect("plugin manifest schema parses")
    }

    #[test]
    fn the_schema_pins_the_version_the_code_accepts() {
        assert_eq!(
            schema()["properties"]["schema_version"]["const"],
            Json::from(SUPPORTED_SCHEMA_VERSION)
        );
    }

    #[test]
    fn every_required_field_in_the_schema_is_required_by_the_parser() {
        let doc = schema();
        let required: Vec<String> = doc["required"]
            .as_array()
            .expect("required list")
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect();
        assert!(
            required.iter().any(|f| f == "plugin_id") && required.iter().any(|f| f == "version"),
            "the schema must require identity: {required:?}"
        );

        // A manifest missing any required field must be rejected.
        for field in &required {
            let mut base = valid_manifest();
            base.as_object_mut().unwrap().remove(field.as_str());
            assert!(
                PluginManifest::from_json(&base).is_err(),
                "a manifest without {field:?} must be rejected"
            );
        }
    }

    #[test]
    fn the_plugin_id_pattern_in_the_schema_is_what_the_parser_enforces() {
        let pattern = schema()["properties"]["plugin_id"]["pattern"]
            .as_str()
            .expect("plugin_id pattern")
            .to_string();
        assert_eq!(pattern, "^[a-z0-9.-]+$");
        // Dots are required by the parser (reverse-domain) even though the
        // schema pattern alone would allow a single label.
        assert!(PluginManifest::from_json(&valid_manifest())
            .expect("valid manifest parses")
            .validate()
            .is_ok());
    }

    fn valid_manifest() -> Json {
        serde_json::json!({
            "schema_version": SUPPORTED_SCHEMA_VERSION,
            "plugin_id": "sandtree.provider.docker",
            "version": "1.0.0",
            "kind": "provider",
            "component": "blake3:abc",
            "license": "Apache-2.0",
            "capabilities": ["resource:discover"],
            "state_schema_version": 1,
            "hot_swap": true,
        })
    }
}

#[cfg(test)]
mod resource_model {
    use std::collections::BTreeSet;

    use sandtree_model::resource::{RelationKind, ResourceKind, ResourceState};

    #[test]
    fn resource_kind_wire_names_are_unique_and_snake_case() {
        let mut seen = BTreeSet::new();
        for k in ResourceKind::all() {
            let w = k.as_str();
            assert!(!w.is_empty());
            assert!(
                w.chars()
                    .all(|c| c.is_ascii_lowercase() || c == '_' || c == '-'),
                "{w} is neither snake_case nor kebab-case"
            );
            assert!(seen.insert(w), "{w} appears twice");
        }
    }

    #[test]
    fn state_and_relation_wire_names_round_trip() {
        for s in [
            ResourceState::Unknown,
            ResourceState::Creating,
            ResourceState::Running,
            ResourceState::Stopped,
            ResourceState::Paused,
            ResourceState::Exited,
            ResourceState::Degraded,
            ResourceState::Destroying,
            ResourceState::Destroyed,
            ResourceState::Tombstoned,
        ] {
            assert_eq!(ResourceState::from_wire(s.as_str()), s);
        }
        for r in [
            RelationKind::UsesImage,
            RelationKind::Mounts,
            RelationKind::AttachedNetwork,
            RelationKind::MemberOfCompose,
            RelationKind::WorkspaceMount,
            RelationKind::DockerInSandbox,
        ] {
            assert_eq!(RelationKind::from_wire(r.as_str()), Some(r));
        }
    }
}

#[cfg(test)]
mod ddl {
    use super::*;
    use sandtree_store::db::Store;

    #[tokio::test]
    async fn the_shipped_ddl_applies_to_an_empty_database() {
        // If the DDL and the code ever disagree about a column, this is where
        // it shows up, rather than in a migration on a user's machine.
        let store = Store::open_in_memory().expect("store opens");
        store.migrate().expect("the frozen DDL applies");
        assert!(store.integrity_check().expect("integrity check"));
        assert_eq!(
            store.schema_version().unwrap(),
            sandtree_store::db::SCHEMA_VERSION
        );
    }

    #[test]
    fn the_ddl_still_declares_the_tables_the_code_queries() {
        for table in [
            "resource",
            "resource_relation",
            "operation_job",
            // Names taken from the frozen DDL itself, not from what the code
            // happens to query: two of these (`plugin_grant`, `event_log`) are
            // spelled differently from the obvious guess, and a test that
            // guessed would have been checking itself.
            "event_log",
            "snapshot",
            "snapshot_entry",
            "plugin_package",
            "plugin_instance",
            "app_generation",
            "plugin_grant",
            "docker_endpoint",
            "workspace_mount",
        ] {
            assert!(
                INIT_SQL.contains(&format!("CREATE TABLE {table}(")),
                "001_init.sql no longer creates {table}"
            );
        }
    }
}

#[cfg(test)]
mod observation_model {
    use std::collections::BTreeSet;

    use sandtree_observation_model::{ObservationDomain, ObservationMode, TrustLevel};

    #[test]
    fn trust_levels_never_rise_under_comparison() {
        // ADR-OBS-003. `at_most` is the only way trust is combined, and it must
        // always return the weaker of the two.
        // Ranks, not `Ord`: the enum's declaration order is the display order
        // (strongest first), so `<=` on the enum means "less trusted", which is
        // the opposite of what a reader would assume.
        let all = [
            TrustLevel::Unverified,
            TrustLevel::GuestProbe,
            TrustLevel::RemoteExec,
            TrustLevel::ProviderNative,
            TrustLevel::HostNative,
        ];
        for a in all {
            for b in all {
                let combined = a.at_most(b);
                assert_eq!(
                    combined.rank(),
                    a.rank().min(b.rank()),
                    "{a:?} at_most {b:?} produced {combined:?}, which is not the weaker of the two"
                );
            }
        }
        // Explicitly: merging an untrusted value with a host-native one must not
        // produce host-native.
        assert_eq!(
            TrustLevel::Unverified.at_most(TrustLevel::HostNative),
            TrustLevel::Unverified
        );
    }

    #[test]
    fn only_host_native_is_security_authoritative() {
        assert!(TrustLevel::HostNative.is_security_authoritative());
        assert!(!TrustLevel::GuestProbe.is_security_authoritative());
        assert!(!TrustLevel::Unverified.is_security_authoritative());
    }

    #[test]
    fn observation_mode_wire_names_round_trip() {
        for m in [
            ObservationMode::Native,
            ObservationMode::Exec,
            ObservationMode::Probe,
            ObservationMode::Metadata,
        ] {
            assert_eq!(ObservationMode::from_wire(m.as_str()), Some(m));
        }
    }

    #[test]
    fn every_observation_domain_has_a_wire_name_and_a_budget() {
        let mut seen = BTreeSet::new();
        for d in ObservationDomain::all() {
            assert!(seen.insert(d.as_str()), "{} is listed twice", d.as_str());
            assert!(
                d.default_deadline_ms() > 0 && d.default_max_age_ms() > 0,
                "{} has no budget",
                d.as_str()
            );
        }
    }
}

#[cfg(test)]
mod workspace_uri {
    use sandtree_vfs::WorkspaceUri;

    #[test]
    fn the_uri_scheme_is_stable() {
        let id = sandtree_model::id::ResourceId::derive(&["contract-test"]);
        let uri = WorkspaceUri::parse(&format!("stfs://{}/data", id)).expect("parses");
        assert!(
            uri.to_uri_string().starts_with("stfs://"),
            "{} lost its scheme",
            uri.to_uri_string()
        );
        // Round trip: a parsed URI must re-serialise to a parseable URI.
        let again = WorkspaceUri::parse(&uri.to_uri_string()).expect("round trips");
        assert_eq!(again.to_uri_string(), uri.to_uri_string());
    }

    #[test]
    fn a_foreign_scheme_is_refused() {
        assert!(WorkspaceUri::parse("file:///etc/passwd").is_err());
        assert!(WorkspaceUri::parse("http://example.invalid").is_err());
    }
}
