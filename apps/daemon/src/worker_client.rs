//! The host side of the worker protocol (FR-055, ADR-019).
//!
//! # What this turns into
//!
//! [`WorkerClient`] *is* a generation, as far as the rest of the control plane
//! is concerned: it implements [`GenerationRuntime`] and [`ResourceProvider`],
//! and every call is forwarded to a worker over a transport. Nothing above this
//! layer knows or cares whether the guest is in this process or another one,
//! which is the point of the [`crate::plugins::PluginLoader`] seam.
//!
//! # One call at a time
//!
//! The connection is behind a mutex and requests strictly alternate. That is
//! not a performance choice: the protocol has no correlation id because there is
//! never more than one outstanding request. If a future change allows
//! concurrent calls, it must add ids *and* tests that a reordered pair of
//! replies is detected — otherwise two answers arrive attributed to the wrong
//! calls, and nothing fails.
//!
//! # A dead worker is a typed failure
//!
//! If the transport breaks mid-call, the caller gets a `DomainError` naming the
//! op, not a hang and not a default value. A generation whose worker died must
//! report "unavailable" (ADR-OBS-001), never "no resources".

use std::sync::Arc;

use sandtree_ipc::transport::Transport;
use sandtree_model::capability::CapabilitySet;
use sandtree_model::error::{DomainError, ErrorCode};
use sandtree_model::id::ResourceId;
use sandtree_model::operation::{OperationOutcome, OperationRequest};
use sandtree_model::resource::ResourceNode;
use sandtree_plugin_host::generation::LoadedGeneration;
use sandtree_plugin_host::hot_swap::GenerationRuntime;
use sandtree_plugin_host::route::Generation;
use sandtree_plugin_host::verify::InstallPolicy;
use sandtree_plugin_host::worker_proto::{
    decode_response, encode_request, LoadSpec, Loaded, Request,
};
use sandtree_sdk::manifest::PluginKind;
use sandtree_sdk::ports::{DiscoverBatch, ProviderDescriptor, ProviderHealth, ResourceProvider};
use sandtree_sdk::wit::WitDescriptor;
use serde_json::Value as Json;
use tokio::sync::Mutex;

use crate::packages::PackageSource;
use crate::plugins::PluginLoader;

/// A connection to one worker.
pub struct WorkerClient {
    transport: Arc<Mutex<Box<dyn Transport>>>,
    loaded: Loaded,
    kind: PluginKind,
}

impl std::fmt::Debug for WorkerClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WorkerClient")
            .field("plugin_id", &self.loaded.plugin_id)
            .field("generation", &self.loaded.generation)
            .finish()
    }
}

fn transport_error(op: &str, e: &DomainError) -> DomainError {
    // Every transport-level failure collapses to one code on purpose.
    //
    // Preserving whatever code the transport implementation happened to use
    // makes the host's answer depend on *when* the peer died: a `send` into a
    // closed mailbox fails with `CORE_INVALID`, while a `recv` that reaches end of
    // stream says `PLUGIN_HEALTH_FAILED`. That is one event — the worker is gone —
    // surfacing under two codes, and it would send an operator hunting for a
    // malformed request instead of a dead worker. The original code is kept in the
    // text, so the detail survives without becoming the classification.
    //
    // `PLUGIN_HEALTH_FAILED` is retryable, which is what the swap supervisor needs
    // in order to route around a generation whose worker disappeared.
    DomainError::new(
        ErrorCode::PLUGIN_HEALTH_FAILED,
        format!(
            "worker transport failed during `{op}` [{}]: {}",
            e.code.as_str(),
            e.message
        ),
    )
}

impl WorkerClient {
    /// Send one request and read its reply.
    async fn call(&self, request: Request) -> Result<Json, DomainError> {
        let op = request.op();
        let mut guard = self.transport.lock().await;
        let bytes = encode_request(&request)?;
        guard
            .send(&bytes)
            .await
            .map_err(|e| transport_error(op, &e))?;
        let Some(reply) = guard.recv().await.map_err(|e| transport_error(op, &e))? else {
            // End of stream: the worker exited without answering. Reported as
            // unavailable rather than as an empty result, because "the worker
            // died" and "the plugin has nothing" must not look alike.
            return Err(DomainError::new(
                ErrorCode::PLUGIN_HEALTH_FAILED,
                format!("worker closed the connection during `{op}` without replying"),
            ));
        };
        decode_response(&reply)
            .map_err(|e| transport_error(op, &e))?
            .into_result()
    }

    /// Load a component over `transport` and return the client for it.
    pub async fn load(
        transport: Box<dyn Transport>,
        mut spec: LoadSpec,
        allowed_licenses: Vec<String>,
        kind: PluginKind,
    ) -> Result<Arc<Self>, DomainError> {
        spec.allowed_licenses = allowed_licenses;
        let connection = Arc::new(Mutex::new(transport));

        // The load request is sent before a client exists, because the client is
        // built *from* the reply. Rather than a placeholder with an empty
        // descriptor — which would be observable if anything read it early —
        // the exchange is done here.
        let op = Request::Load(spec.clone()).op();
        let mut guard = connection.lock().await;
        guard
            .send(&encode_request(&Request::Load(spec))?)
            .await
            .map_err(|e| transport_error(op, &e))?;
        let Some(reply) = guard.recv().await.map_err(|e| transport_error(op, &e))? else {
            return Err(DomainError::new(
                ErrorCode::PLUGIN_HEALTH_FAILED,
                "worker closed the connection during `load` without replying",
            ));
        };
        drop(guard);
        let body = decode_response(&reply)
            .map_err(|e| transport_error(op, &e))?
            .into_result()?;
        let loaded: Loaded = serde_json::from_value(body).map_err(|e| {
            DomainError::new(
                ErrorCode::PLUGIN_HEALTH_FAILED,
                format!("worker sent an unreadable load result: {e}"),
            )
        })?;
        Ok(Arc::new(Self {
            transport: connection,
            loaded,
            kind,
        }))
    }

    /// The identity the worker's guest reported.
    pub fn loaded(&self) -> &Loaded {
        &self.loaded
    }

    /// Close the connection.
    pub async fn close(&self) {
        if let Ok(guard) = self.transport.try_lock() {
            guard.close().await;
        }
    }
}

#[async_trait::async_trait]
impl GenerationRuntime for WorkerClient {
    fn generation(&self) -> Generation {
        self.loaded.generation
    }

    fn descriptor(&self) -> WitDescriptor {
        self.loaded.descriptor.clone()
    }

    async fn init(&self, config: &Json) -> Result<(), DomainError> {
        self.call(Request::Init(config.clone())).await.map(|_| ())
    }

    async fn health(&self) -> Result<ProviderHealth, DomainError> {
        let body = self.call(Request::Health).await?;
        serde_json::from_value(body).map_err(|e| {
            DomainError::new(
                ErrorCode::PLUGIN_HEALTH_FAILED,
                format!("worker sent an unreadable health status: {e}"),
            )
        })
    }

    async fn prepare_upgrade(&self, target_version: &str) -> Result<Vec<u8>, DomainError> {
        let body = self
            .call(Request::PrepareUpgrade(target_version.to_string()))
            .await?;
        serde_json::from_value(body).map_err(|e| {
            DomainError::new(
                ErrorCode::PLUGIN_HEALTH_FAILED,
                format!("worker sent unreadable migration state: {e}"),
            )
        })
    }

    async fn accept_upgrade(&self, from_version: &str, state: &[u8]) -> Result<(), DomainError> {
        self.call(Request::AcceptUpgrade {
            from_version: from_version.to_string(),
            state: state.to_vec(),
        })
        .await
        .map(|_| ())
    }

    async fn drain(&self, deadline_ms: u64) -> Result<(), DomainError> {
        self.call(Request::Drain(deadline_ms)).await.map(|_| ())
    }

    async fn shutdown(&self) {
        // Shutdown never fails loudly: it runs on the retirement path, including
        // for a generation whose worker has already died. The guest is expected
        // to be gone either way.
        let _ = self.call(Request::Shutdown).await;
        self.close().await;
    }
}

#[async_trait::async_trait]
impl ResourceProvider for WorkerClient {
    fn descriptor(&self) -> ProviderDescriptor {
        ProviderDescriptor {
            plugin_id: self.loaded.plugin_id.as_str().to_string(),
            version: self.loaded.descriptor.version.clone(),
            kind: self.kind,
        }
    }

    async fn health(&self) -> Result<ProviderHealth, DomainError> {
        GenerationRuntime::health(self).await
    }

    async fn discover(&self, cursor: Option<String>) -> Result<DiscoverBatch, DomainError> {
        let body = self.call(Request::Discover(cursor)).await?;
        {
            let raw = body.clone();
            serde_json::from_value(body).map_err(|e| decode_failure("discover", e, &raw))
        }
    }

    async fn inspect(&self, id: &ResourceId) -> Result<ResourceNode, DomainError> {
        let body = self.call(Request::Inspect(id.as_str().to_string())).await?;
        {
            let raw = body.clone();
            serde_json::from_value(body).map_err(|e| decode_failure("inspect", e, &raw))
        }
    }

    async fn invoke(&self, req: &OperationRequest) -> Result<OperationOutcome, DomainError> {
        // The whole request travels as the payload, exactly as it does over the
        // WIT boundary: the provider is the only thing that understands
        // provider-specific args (DD-SW §4).
        let payload = serde_json::to_value(req)
            .map_err(|e| DomainError::new(ErrorCode::CORE_INVALID, e.to_string()))?;
        let body = self
            .call(Request::Invoke {
                resource_id: req.resource_id.as_str().to_string(),
                operation: req.op.as_str().to_string(),
                payload_json: payload.to_string(),
            })
            .await?;
        {
            let raw = body.clone();
            serde_json::from_value(body).map_err(|e| decode_failure("invoke", e, &raw))
        }
    }

    async fn shutdown(&self) {
        GenerationRuntime::shutdown(self).await
    }
}

fn decode_failure(op: &str, e: serde_json::Error, body: &Json) -> DomainError {
    // A worker that answers with something unparseable is a failure, never an
    // empty result. Folding it into a default would report "no resources" for a
    // provider that is merely broken — the collapse ADR-OBS-001 forbids.
    DomainError::new(
        ErrorCode::CORE_INVALID,
        format!("worker `{op}` returned unparseable JSON ({e}): {body}"),
    )
}

/// Stages generations by loading them into a worker over `transport`.
///
/// `spawn` is called per generation: each one gets its own worker, which is what
/// makes "two generations of the same plugin do not share a store" a structural
/// property rather than something to remember.
pub struct RemoteLoader<S, F> {
    source: Arc<S>,
    policy: InstallPolicy,
    granted: CapabilitySet,
    limits: sandtree_plugin_host::limits::WorkerLimits,
    spawn: F,
}

impl<S, F> std::fmt::Debug for RemoteLoader<S, F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteLoader")
            .field("granted", &self.granted)
            .finish()
    }
}

impl<S, F> RemoteLoader<S, F>
where
    S: PackageSource + 'static,
    F: Fn() -> Box<dyn Transport> + Send + Sync + 'static,
{
    /// Build a loader that obtains a fresh connection per generation from
    /// `spawn`.
    pub fn new(
        source: Arc<S>,
        policy: InstallPolicy,
        granted: CapabilitySet,
        limits: sandtree_plugin_host::limits::WorkerLimits,
        spawn: F,
    ) -> Self {
        Self {
            source,
            policy,
            granted,
            limits,
            spawn,
        }
    }
}

#[async_trait::async_trait]
impl<S, F> PluginLoader for RemoteLoader<S, F>
where
    S: PackageSource + 'static,
    F: Fn() -> Box<dyn Transport> + Send + Sync + 'static,
{
    async fn stage(
        &self,
        plugin: &sandtree_model::id::PluginId,
        generation: Generation,
    ) -> Result<Arc<LoadedGeneration>, DomainError> {
        let spec = self.source.package(plugin)?;
        let manifest =
            sandtree_sdk::manifest::PluginManifest::from_json(&spec.manifest).map_err(|e| {
                DomainError::new(
                    ErrorCode::PLUGIN_MANIFEST_INVALID,
                    format!("plugin {plugin}: {}", e.message),
                )
            })?;
        let kind = manifest.kind();
        let load = LoadSpec {
            allowed_licenses: Vec::new(),
            ..LoadSpec::new(spec.component_path, spec.manifest, generation)
        };
        let load = LoadSpec {
            granted: self.granted.clone(),
            limits: self.limits,
            ..load
        };

        let client = WorkerClient::load(
            (self.spawn)(),
            load,
            self.policy.allowed_licenses.clone(),
            kind,
        )
        .await?;

        let plugin_id = client.loaded().plugin_id.clone();
        let ports = match kind {
            PluginKind::Provider => {
                let resource: Arc<dyn ResourceProvider> = client.clone();
                sandtree_sdk::ports::ProviderInstance::empty(plugin_id.clone())
                    .with_resource(resource)
            }
            _ => sandtree_sdk::ports::ProviderInstance::empty(plugin_id.clone()),
        };
        let runtime: Arc<dyn GenerationRuntime> = client;
        let loaded = Arc::new(LoadedGeneration::new(plugin_id, generation, runtime, ports));
        Ok(loaded)
    }
}
