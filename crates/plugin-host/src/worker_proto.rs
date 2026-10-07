//! The daemon ↔ plugin-worker wire protocol (FR-055, DD-PLG §10, ADR-019).
//!
//! # Why this lives in `plugin-host`
//!
//! It is the contract between the two halves of the plugin path, and both halves
//! already depend on this crate. Putting it anywhere else means one of them
//! grows a dependency on the other, and an app depending on an app is exactly
//! the coupling the seam was meant to avoid.
//!
//! # Shape
//!
//! One request, one response, strictly alternating on one channel. There is no
//! correlation id, and that is a deliberate consequence of the channel: a second
//! request cannot be in flight until the first response is written, because the
//! client serialises on the connection. Adding an id would be adding a mechanism
//! to solve a problem this design does not have — and the moment a second request
//! *is* allowed in flight, the id becomes mandatory, so
//! [`super::worker_proto`] is where that change has to be made, visibly.
//!
//! Bodies are JSON. That is not laziness: the guest ABI is already
//! JSON-over-WIT, and a second wire format between the same two peers would be a
//! third thing to keep in step.
//!
//! # Errors are values, not transport failures
//!
//! A plugin that refuses a `drain`, or a component that traps, produces an
//! [`Response::Err`] carrying the stable error code. Losing the pipe produces an
//! `Err` from the transport instead. Collapsing the two would make "the plugin
//! said no" indistinguishable from "the worker died", and those need different
//! operator responses.

use std::path::PathBuf;

use sandtree_model::capability::CapabilitySet;
use sandtree_model::error::{DomainError, ErrorCode};
use sandtree_model::id::PluginId;
use sandtree_sdk::wit::WitDescriptor;
use serde::{Deserialize, Serialize};
use serde_json::Value as Json;

use crate::limits::WorkerLimits;
use crate::route::Generation;

/// Protocol version, carried in every request.
///
/// A worker from an older build must fail loudly rather than interpret a request
/// under today's rules: the alternative is a silent semantic mismatch, which is
/// the kind of bug that only shows up as wrong data much later.
pub const PROTOCOL_VERSION: u32 = 1;

/// What a worker is asked to load.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoadSpec {
    /// Protocol version this peer speaks.
    pub version: u32,
    /// Component file to load.
    pub component_path: PathBuf,
    /// The plugin manifest, as JSON.
    pub manifest: Json,
    /// Generation the worker must serve.
    pub generation: Generation,
    /// Capability ceiling the host granted.
    pub granted: CapabilitySet,
    /// Resource ceilings.
    pub limits: WorkerLimits,
    /// Licenses the host will accept for this package.
    pub allowed_licenses: Vec<String>,
}

impl LoadSpec {
    /// A spec for `generation` over `component_path`.
    pub fn new(component_path: PathBuf, manifest: Json, generation: Generation) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            component_path,
            manifest,
            generation,
            granted: CapabilitySet::empty(),
            limits: WorkerLimits::host_ceiling(),
            allowed_licenses: Vec::new(),
        }
    }
}

/// One request from the host to a worker.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", content = "args", rename_all = "kebab-case")]
pub enum Request {
    /// Compile, bind and `init`-able a component. Answered with
    /// [`Response::Loaded`].
    Load(LoadSpec),
    /// Run the guest's `lifecycle.init`.
    Init(Json),
    /// Read health.
    Health,
    /// Ask the outgoing generation for migration state.
    PrepareUpgrade(String),
    /// Hand migration state to the incoming generation.
    AcceptUpgrade {
        /// Version being upgraded from.
        from_version: String,
        /// Migration blob from `prepare-upgrade`.
        state: Vec<u8>,
    },
    /// Stop accepting new work, bounded by `deadline_ms`.
    Drain(u64),
    /// Shut the guest down. Not acknowledged; the worker may exit first.
    Shutdown,
    /// One page of discovery.
    Discover(Option<String>),
    /// Read one resource.
    Inspect(String),
    /// Run a guest command.
    Invoke {
        /// Target resource id.
        resource_id: String,
        /// Operation name.
        operation: String,
        /// The whole request, as JSON.
        payload_json: String,
    },
}

impl Request {
    /// Stable name, for logs and for the error messages a caller sees.
    pub fn op(&self) -> &'static str {
        match self {
            Request::Load(_) => "load",
            Request::Init(_) => "init",
            Request::Health => "health",
            Request::PrepareUpgrade(_) => "prepare-upgrade",
            Request::AcceptUpgrade { .. } => "accept-upgrade",
            Request::Drain(_) => "drain",
            Request::Shutdown => "shutdown",
            Request::Discover(_) => "discover",
            Request::Inspect(_) => "inspect",
            Request::Invoke { .. } => "invoke",
        }
    }
}

/// A worker that finished loading.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Loaded {
    /// The identity the worker derived from the manifest.
    pub plugin_id: PluginId,
    /// Generation the worker is serving.
    pub generation: Generation,
    /// What the guest's `lifecycle.descriptor` said.
    pub descriptor: WitDescriptor,
}

/// One response from a worker to the host.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum Response {
    /// The call succeeded; `body` carries whatever the op returns.
    Ok {
        /// Result payload, op-specific.
        body: Json,
    },
    /// The call failed, and the failure is the guest's or the worker's answer.
    Err {
        /// Stable code from `schemas/error_codes.csv`.
        code: String,
        /// Human-readable cause.
        message: String,
    },
}

impl Response {
    /// A successful response carrying `body`.
    pub fn ok(body: Json) -> Self {
        Response::Ok { body }
    }

    /// A failure response carrying a [`DomainError`].
    pub fn err(e: &DomainError) -> Self {
        Response::Err {
            code: e.code.as_str().to_string(),
            message: e.message.clone(),
        }
    }

    /// Convert back into a `Result`, restoring the stable code.
    ///
    /// An unparseable code is not silently dropped: it becomes
    /// `ST-PLG-002` (`PLUGIN_HEALTH_FAILED`) with the original text kept in the
    /// message, because "some code we do not recognise" still has to reach the
    /// operator intact.
    pub fn into_result(self) -> Result<Json, DomainError> {
        match self {
            Response::Ok { body } => Ok(body),
            Response::Err { code, message } => match ErrorCode::parse(&code) {
                Some(c) => Err(DomainError::new(c, message)),
                None => Err(DomainError::new(
                    ErrorCode::PLUGIN_HEALTH_FAILED,
                    format!("worker returned unknown error code {code:?}: {message}"),
                )),
            },
        }
    }
}

/// Serialise a request into one message body.
pub fn encode_request(r: &Request) -> Result<Vec<u8>, DomainError> {
    serde_json::to_vec(r).map_err(|e| protocol_error("request", e))
}

/// Parse one message body into a request.
pub fn decode_request(b: &[u8]) -> Result<Request, DomainError> {
    serde_json::from_slice(b).map_err(|e| protocol_error("request", e))
}

/// Serialise a response into one message body.
pub fn encode_response(r: &Response) -> Result<Vec<u8>, DomainError> {
    serde_json::to_vec(r).map_err(|e| protocol_error("response", e))
}

/// Parse one message body into a response.
pub fn decode_response(b: &[u8]) -> Result<Response, DomainError> {
    serde_json::from_slice(b).map_err(|e| protocol_error("response", e))
}

fn protocol_error(what: &'static str, e: serde_json::Error) -> DomainError {
    DomainError::new(
        ErrorCode::CORE_INVALID,
        format!("plugin worker protocol: malformed {what}: {e}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn spec() -> LoadSpec {
        LoadSpec::new(
            PathBuf::from("/plugins/demo/component.wasm"),
            json!({"plugin_id": "sandtree.provider.demo"}),
            Generation(3),
        )
    }

    /// Every request must survive the wire unchanged.
    ///
    /// A request variant the codec silently drops is a capability the daemon
    /// thinks it has: the call is sent, the worker answers something else, and
    /// nothing complains until the values are wrong.
    #[test]
    fn every_request_round_trips() {
        let all = vec![
            Request::Load(spec()),
            Request::Init(json!({"endpoint": "local"})),
            Request::Health,
            Request::PrepareUpgrade("1.1.0".into()),
            Request::AcceptUpgrade {
                from_version: "1.0.0".into(),
                state: vec![1, 2, 3],
            },
            Request::Drain(1_500),
            Request::Shutdown,
            Request::Discover(None),
            Request::Discover(Some("page-2".into())),
            Request::Inspect("res-abc".into()),
            Request::Invoke {
                resource_id: "res-abc".into(),
                operation: "start".into(),
                payload_json: "{}".into(),
            },
        ];
        for r in all {
            let bytes = encode_request(&r).expect("encode");
            assert_eq!(decode_request(&bytes).expect("decode"), r, "{r:?}");
        }
    }

    /// The op tag is what a human reads in a log, so two ops must never share it.
    #[test]
    fn op_names_are_unique() {
        let all = vec![
            Request::Load(spec()),
            Request::Init(Json::Null),
            Request::Health,
            Request::PrepareUpgrade(String::new()),
            Request::AcceptUpgrade {
                from_version: String::new(),
                state: Vec::new(),
            },
            Request::Drain(0),
            Request::Shutdown,
            Request::Discover(None),
            Request::Inspect(String::new()),
            Request::Invoke {
                resource_id: String::new(),
                operation: String::new(),
                payload_json: String::new(),
            },
        ];
        let mut names: Vec<&str> = all.iter().map(Request::op).collect();
        let before = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), before, "two ops share a name");
    }

    #[test]
    fn responses_round_trip_and_keep_the_stable_code() {
        let ok = Response::ok(json!({"state": "healthy"}));
        assert_eq!(decode_response(&encode_response(&ok).unwrap()).unwrap(), ok);

        let original = DomainError::new(ErrorCode::PLUGIN_HEALTH_FAILED, "guest trapped");
        let wire = decode_response(&encode_response(&Response::err(&original)).unwrap()).unwrap();
        let back = wire.into_result().expect_err("still a failure");
        // The whole point of carrying the code: a host that maps a guest failure
        // onto its own generic code has thrown away the distinction an operator
        // needs between "the plugin said no" and "the transport broke".
        assert_eq!(back.code, ErrorCode::PLUGIN_HEALTH_FAILED);
        assert_eq!(back.message, "guest trapped");
    }

    #[test]
    fn an_unknown_error_code_survives_rather_than_becoming_success() {
        // A code this build does not know must not be dropped. Silently
        // defaulting it to `ok` would be the worst possible reading of a
        // failure.
        let wire = Response::Err {
            code: "ST-PLG-999".into(),
            message: "from a newer worker".into(),
        };
        let back = wire.into_result().expect_err("a failure stays a failure");
        assert_eq!(back.code, ErrorCode::PLUGIN_HEALTH_FAILED);
        assert!(
            back.message.contains("ST-PLG-999"),
            "the original code must survive into the message: {}",
            back.message
        );
    }

    #[test]
    fn malformed_input_is_an_error_not_a_default() {
        for bad in [
            &b"{"[..],
            &b"not json"[..],
            &b"{}"[..],
            &b"{\"op\":\"teleport\"}"[..],
            &b"{\"op\":\"drain\"}"[..],
            &b"{\"op\":\"health\",\"args\":[]}"[..],
        ] {
            let err = decode_request(bad).expect_err("must refuse");
            assert_eq!(
                err.code,
                ErrorCode::CORE_INVALID,
                "{:?}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn a_response_and_a_request_are_not_interchangeable() {
        // They are different shapes; a server that mis-reads one as the other
        // must produce an error rather than a plausible-looking value.
        let req = encode_request(&Request::Health).unwrap();
        assert!(decode_response(&req).is_err());
        let resp = encode_response(&Response::ok(Json::Null)).unwrap();
        assert!(decode_request(&resp).is_err());
    }

    #[test]
    fn the_load_spec_carries_the_host_ceilings_rather_than_letting_the_worker_choose() {
        // A worker that picked its own fuel budget would not be bounded by
        // anything the host decided.
        let mut s = spec();
        assert_eq!(s.version, PROTOCOL_VERSION);
        assert_eq!(s.limits, WorkerLimits::host_ceiling());
        s.limits.fuel = 1_000;
        let back: LoadSpec = decode_request(&encode_request(&Request::Load(s.clone())).unwrap())
            .map(|r| match r {
                Request::Load(x) => x,
                _ => unreachable!(),
            })
            .unwrap();
        assert_eq!(back, s);
    }
}
