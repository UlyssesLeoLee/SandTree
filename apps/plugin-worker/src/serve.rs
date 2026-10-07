//! Serving the daemon ↔ worker protocol (FR-055, DD-PLG §10, ADR-019).
//!
//! # Transport-agnostic on purpose
//!
//! [`serve`] takes a `dyn Transport`, not a named pipe. That is what makes the
//! worker half testable without a subprocess: the same dispatch code runs over
//! the loopback pair in the tests, so a protocol change is verified in the
//! normal `cargo test` run instead of only in a Windows-only integration test.
//!
//! # Failures are answers, not disconnects
//!
//! Every refusal — an op before `load`, a guest that traps, a manifest that will
//! not parse — is sent back as a [`Response::Err`] carrying the stable code, and
//! the connection stays open. Only the transport breaking ends the session,
//! because "the plugin said no" and "the worker died" need different operator
//! responses and must not arrive as the same event.

use sandtree_ipc::transport::Transport;
use sandtree_model::error::{DomainError, ErrorCode};
use sandtree_model::operation::{OperationOutcome, OperationRequest};
use sandtree_model::resource::ResourceNode;
use sandtree_plugin_host::hot_swap::GenerationRuntime;
use sandtree_plugin_host::limits::WorkerLimits;
use sandtree_plugin_host::verify::InstallPolicy;
use sandtree_plugin_host::worker_proto::{
    decode_request, encode_response, LoadSpec, Loaded, Request, Response, PROTOCOL_VERSION,
};
use sandtree_sdk::ports::{DiscoverBatch, ProviderHealth, ResourceProvider};
use serde_json::Value as Json;

use crate::{Worker, WorkerSpec};

/// A worker serving one generation over a transport.
pub struct WorkerServer {
    worker: Worker,
    loaded: Option<Loaded>,
    /// Set by a `shutdown` request, so `serve` returns instead of waiting for a
    /// peer that may never disconnect.
    stop: bool,
}

impl std::fmt::Debug for WorkerServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WorkerServer")
            .field("loaded", &self.loaded.is_some())
            .finish()
    }
}

impl Default for WorkerServer {
    fn default() -> Self {
        Self::new()
    }
}

fn not_loaded(op: &str) -> DomainError {
    DomainError::new(
        ErrorCode::PLUGIN_MANIFEST_INVALID,
        format!("worker received `{op}` before a successful load"),
    )
}

fn encode_error(op: &str, e: &DomainError) -> Vec<u8> {
    // Encoding a response can only fail if the error message is unserialisable,
    // which a `String` cannot be. The fallback is still a valid response, so the
    // peer never sees a decode failure it cannot interpret.
    encode_response(&Response::err(e)).unwrap_or_else(|_| {
        format!(
            r#"{{"status":"err","code":"{}","message":"worker could not encode its {op} reply: {}"}}"#,
            ErrorCode::CORE_INVALID.as_str(),
            e.message
        )
        .into_bytes()
    })
}

impl WorkerServer {
    /// A server with nothing loaded.
    pub fn new() -> Self {
        Self {
            worker: Worker::new(WorkerSpec::new(
                std::path::PathBuf::new(),
                Json::Null,
                Default::default(),
            )),
            loaded: None,
            stop: false,
        }
    }

    /// What a successful load reported, if any.
    pub fn loaded(&self) -> Option<&Loaded> {
        self.loaded.as_ref()
    }

    /// Handle exactly one request: read, dispatch, write.
    ///
    /// Returns `false` when the peer closed the connection, which is the only
    /// thing that ends a session.
    pub async fn handle(&mut self, t: &mut dyn Transport) -> Result<bool, DomainError> {
        let Some(bytes) = t.recv().await? else {
            return Ok(false);
        };
        let response = match decode_request(&bytes) {
            // A body that will not parse gets an answer, not a disconnect: the
            // peer can then report it as a plugin failure rather than an opaque
            // transport error.
            Err(e) => encode_error("?", &e),
            Ok(request) => {
                let op = request.op();
                match self.dispatch(request).await {
                    Ok(body) => encode_response(&Response::Ok { body }).unwrap_or_else(|_| {
                        encode_error(
                            op,
                            &DomainError::new(
                                ErrorCode::CORE_INVALID,
                                format!("worker could not encode its {op} reply"),
                            ),
                        )
                    }),
                    Err(e) => encode_error(op, &e),
                }
            }
        };
        t.send(&response).await?;
        Ok(true)
    }

    /// Serve until the peer disconnects or asks to shut down.
    pub async fn serve(mut self, t: &mut dyn Transport) -> Result<(), DomainError> {
        loop {
            if !self.handle(t).await? {
                return Ok(());
            }
            if self.stop {
                return Ok(());
            }
        }
    }

    async fn dispatch(&mut self, request: Request) -> Result<Json, DomainError> {
        match request {
            Request::Load(spec) => self.load(spec).await,
            Request::Init(cfg) => {
                self.runtime()?.init(&cfg).await?;
                Ok(Json::Null)
            }
            Request::Health => {
                let h: ProviderHealth = self.runtime()?.health().await?;
                to_json(&h)
            }
            Request::PrepareUpgrade(target) => {
                let state = self.runtime()?.prepare_upgrade(&target).await?;
                to_json(&state)
            }
            Request::AcceptUpgrade {
                from_version,
                state,
            } => {
                self.runtime()?
                    .accept_upgrade(&from_version, &state)
                    .await?;
                Ok(Json::Null)
            }
            Request::Drain(deadline_ms) => {
                self.runtime()?.drain(deadline_ms).await?;
                Ok(Json::Null)
            }
            Request::Shutdown => {
                // Answer first: a worker that exits before the reply is written
                // turns a clean shutdown into a transport error on the host.
                self.worker.retire().await;
                self.loaded = None;
                self.stop = true;
                Ok(Json::Null)
            }
            Request::Discover(cursor) => {
                let batch: DiscoverBatch = self.resource()?.discover(cursor).await?;
                to_json(&batch)
            }
            Request::Inspect(resource_id) => {
                let id = parse_resource_id(&resource_id)?;
                let node: ResourceNode = self.resource()?.inspect(&id).await?;
                to_json(&node)
            }
            Request::Invoke {
                resource_id,
                operation,
                payload_json,
            } => {
                let payload: Json = serde_json::from_str(&payload_json).map_err(|e| {
                    DomainError::new(
                        ErrorCode::CORE_INVALID,
                        format!("worker received an unparseable invoke payload: {e}"),
                    )
                })?;
                let correlation = payload
                    .get("correlation_id")
                    .and_then(Json::as_str)
                    .and_then(sandtree_model::resource::Correlation::parse)
                    .unwrap_or_else(sandtree_model::resource::Correlation::generate);
                let mut req = OperationRequest::new(
                    parse_resource_id(&resource_id)?,
                    parse_operation(&operation)?,
                    payload.get("args").cloned().unwrap_or(Json::Null),
                    correlation,
                );
                if let Some(deadline) = payload.get("deadline_ms").and_then(Json::as_u64) {
                    req = req.with_deadline_ms(deadline);
                }
                let outcome: OperationOutcome = self.resource()?.invoke(&req).await?;
                to_json(&outcome)
            }
        }
    }

    async fn load(&mut self, spec: LoadSpec) -> Result<Json, DomainError> {
        if spec.version != PROTOCOL_VERSION {
            return Err(DomainError::new(
                ErrorCode::PLUGIN_MANIFEST_INVALID,
                format!(
                    "worker speaks plugin protocol v{} but the host sent v{}",
                    PROTOCOL_VERSION, spec.version
                ),
            ));
        }
        // The host owns the ceilings; taking them from the request rather than
        // from a local default is the whole point of sending them.
        let limits: WorkerLimits = spec.limits;
        let mut policy = InstallPolicy::deny_all();
        for license in &spec.allowed_licenses {
            policy = policy.allow_license(license);
        }
        policy.require_component = true;

        let mut worker = Worker::new(WorkerSpec {
            component_path: spec.component_path,
            manifest: spec.manifest,
            generation: spec.generation,
            granted: spec.granted,
            limits,
        })
        .with_policy(policy);

        let loaded = worker.load().await?;
        let generation = loaded.generation();
        let plugin_id = loaded.plugin_id().clone();
        let descriptor =
            sandtree_plugin_host::hot_swap::GenerationRuntime::descriptor(&**loaded.runtime());

        self.loaded = Some(Loaded {
            plugin_id,
            generation,
            descriptor,
        });
        self.worker = worker;
        to_json(self.loaded.as_ref().expect("just set"))
    }

    fn runtime(&self) -> Result<&dyn GenerationRuntime, DomainError> {
        self.worker
            .runtime()
            .map(|r| r.as_ref())
            .ok_or_else(|| not_loaded("a lifecycle call"))
    }

    fn resource(&self) -> Result<std::sync::Arc<dyn ResourceProvider>, DomainError> {
        self.worker
            .loaded()
            .and_then(|g| g.ports().resource.clone())
            .ok_or_else(|| {
                DomainError::new(
                    ErrorCode::PLUGIN_HEALTH_FAILED,
                    "the loaded generation carries no resource port, so it cannot \
                     serve provider traffic",
                )
            })
    }
}

fn to_json<T: serde::Serialize>(v: &T) -> Result<Json, DomainError> {
    serde_json::to_value(v).map_err(|e| {
        DomainError::new(
            ErrorCode::CORE_INVALID,
            format!("worker could not serialise its reply: {e}"),
        )
    })
}

fn parse_resource_id(raw: &str) -> Result<sandtree_model::id::ResourceId, DomainError> {
    sandtree_model::id::ResourceId::parse(raw).map_err(|e| {
        DomainError::new(
            ErrorCode::CORE_INVALID,
            format!("worker received an invalid resource id {raw:?}: {e:?}"),
        )
    })
}

fn parse_operation(raw: &str) -> Result<sandtree_model::operation::OperationKind, DomainError> {
    sandtree_model::operation::OperationKind::from_wire(raw).ok_or_else(|| {
        DomainError::new(
            ErrorCode::CORE_INVALID,
            format!("worker received an unknown operation {raw:?}"),
        )
    })
}
