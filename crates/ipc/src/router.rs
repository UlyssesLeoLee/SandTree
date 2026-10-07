//! Method routing (DD-DATA §6).
//!
//! The router owns a name → handler map and nothing else. Two rules matter:
//!
//! * an unknown method is a typed error carrying the method name, never a
//!   silent no-op, and
//! * dispatch is deterministic — iterating registered methods is sorted, so a
//!   "what does this daemon support?" query has a stable answer.

use std::collections::BTreeMap;
use std::sync::Arc;

use sandtree_model::error::{DomainError, ErrorCode};
use serde_json::Value as Json;

use crate::Request;

/// A method result.
///
/// `PartialEq` is written out because `DomainError` is deliberately not
/// `Clone`, and deriving it would force that.
#[derive(Debug)]
pub enum Response {
    /// Success.
    Ok {
        /// Echoed request id.
        id: String,
        /// Result payload.
        result: Json,
    },
    /// Failure.
    Err {
        /// Echoed request id.
        id: String,
        /// The domain error, with a stable code.
        error: DomainError,
    },
}

impl PartialEq for Response {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Response::Ok { id: a, result: ra }, Response::Ok { id: b, result: rb }) => {
                a == b && ra == rb
            }
            (Response::Err { id: a, error: ea }, Response::Err { id: b, error: eb }) => {
                a == b && ea.code == eb.code && ea.message == eb.message
            }
            _ => false,
        }
    }
}

impl Response {
    /// Build a success.
    pub fn ok(id: impl Into<String>, result: Json) -> Self {
        Response::Ok {
            id: id.into(),
            result,
        }
    }

    /// Build a failure.
    pub fn err(id: impl Into<String>, error: DomainError) -> Self {
        Response::Err {
            id: id.into(),
            error,
        }
    }

    /// Whether this is a success.
    pub fn is_ok(&self) -> bool {
        matches!(self, Response::Ok { .. })
    }

    /// Wire form.
    pub fn to_json(&self) -> Json {
        match self {
            Response::Ok { id, result } => serde_json::json!({
                "id": id,
                "ok": true,
                "result": result,
            }),
            Response::Err { id, error } => serde_json::json!({
                "id": id,
                "ok": false,
                "error": {
                    "code": error.code.as_str(),
                    "message": error.message,
                    "detail": error.detail,
                },
            }),
        }
    }
}

/// A method implementation.
pub type Handler = Arc<
    dyn Fn(&Request) -> futures::future::BoxFuture<'static, Result<Json, DomainError>>
        + Send
        + Sync,
>;

/// Name → handler map.
#[derive(Default, Clone)]
pub struct MethodRouter {
    handlers: BTreeMap<String, Handler>,
}

impl std::fmt::Debug for MethodRouter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MethodRouter")
            .field("methods", &self.handlers.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl MethodRouter {
    /// Empty router.
    pub fn new() -> Self {
        Self {
            handlers: BTreeMap::new(),
        }
    }

    /// Register a handler. Registering the same name twice replaces it, which
    /// is what a plugin reload needs.
    pub fn register(&mut self, method: &str, handler: Handler) {
        self.handlers.insert(method.to_string(), handler);
    }

    /// Register a synchronous handler.
    ///
    /// The handler runs eagerly and its owned result is moved into the future,
    /// so no borrow of the request escapes into the boxed future — which is why
    /// this can be a plain `Fn` over a `BoxFuture<'static, _>`.
    pub fn register_sync<F>(&mut self, method: &str, f: F)
    where
        F: Fn(&Request) -> Result<Json, DomainError> + Send + Sync + 'static,
    {
        let f = Arc::new(f);
        self.register(
            method,
            Arc::new(move |req| {
                let out = f(req);
                Box::pin(async move { out }) as futures::future::BoxFuture<'static, _>
            }),
        );
    }

    /// Register an asynchronous handler that takes the request by value.
    ///
    /// Taking it by value is what lets the future be `'static`: a handler that
    /// borrowed the request would have to return a future tied to that borrow,
    /// which a boxed `'static` future cannot express.
    pub fn register_owned<F, Fut>(&mut self, method: &str, f: F)
    where
        F: Fn(Request) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<Json, DomainError>> + Send + 'static,
    {
        self.register(method, Arc::new(move |req| Box::pin(f(req.clone()))));
    }

    /// Whether a method is registered.
    pub fn contains(&self, method: &str) -> bool {
        self.handlers.contains_key(method)
    }

    /// Registered method names, sorted.
    pub fn methods(&self) -> Vec<&str> {
        self.handlers.keys().map(String::as_str).collect()
    }

    /// Number of registered methods.
    pub fn len(&self) -> usize {
        self.handlers.len()
    }

    /// Whether nothing is registered.
    pub fn is_empty(&self) -> bool {
        self.handlers.is_empty()
    }

    /// Dispatch one request.
    pub async fn dispatch(&self, req: &Request) -> Response {
        let Some(handler) = self.handlers.get(&req.method) else {
            return Response::err(
                req.id.clone(),
                DomainError::new(
                    ErrorCode::CORE_INVALID,
                    format!("unknown method {:?}", req.method),
                ),
            );
        };
        match handler(req).await {
            Ok(result) => Response::ok(req.id.clone(), result),
            Err(e) => Response::err(req.id.clone(), e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::method;

    fn ok_handler() -> Handler {
        Arc::new(
            |_req| -> futures::future::BoxFuture<'static, Result<Json, DomainError>> {
                Box::pin(async { Ok(Json::from(1u32)) })
            },
        )
    }

    #[tokio::test]
    async fn dispatch_calls_the_registered_handler() {
        let mut r = MethodRouter::new();
        r.register(method::RESOURCE_TREE, ok_handler());
        let resp = r
            .dispatch(&Request::new(method::RESOURCE_TREE, Json::Null))
            .await;
        assert!(resp.is_ok());
        assert_eq!(resp.to_json()["result"], Json::from(1u32));
    }

    #[tokio::test]
    async fn an_unknown_method_is_a_typed_error_naming_it() {
        let r = MethodRouter::new();
        let resp = r.dispatch(&Request::new("nope.nope", Json::Null)).await;
        assert!(!resp.is_ok());
        let json = resp.to_json();
        assert_eq!(json["ok"], Json::Bool(false));
        assert_eq!(json["error"]["code"], ErrorCode::CORE_INVALID.as_str());
        assert!(
            json["error"]["message"]
                .as_str()
                .unwrap()
                .contains("nope.nope"),
            "the error must name the method"
        );
    }

    #[tokio::test]
    async fn the_request_id_is_echoed_on_both_paths() {
        let mut r = MethodRouter::new();
        r.register(method::RESOURCE_TREE, ok_handler());
        let req = Request::new(method::RESOURCE_TREE, Json::Null);
        let ok = r.dispatch(&req).await.to_json();
        assert_eq!(ok["id"], Json::String(req.id.clone()));
        let bad = r.dispatch(&Request::new("a.b", Json::Null)).await.to_json();
        assert!(bad["id"].as_str().is_some());
    }

    #[tokio::test]
    async fn a_handler_error_becomes_a_failed_response() {
        let mut r = MethodRouter::new();
        r.register_sync(method::OPERATION_INVOKE, |_| {
            Err(DomainError::new(ErrorCode::POLICY_DENIED, "nope"))
        });
        let resp = r
            .dispatch(&Request::new(method::OPERATION_INVOKE, Json::Null))
            .await;
        assert!(!resp.is_ok());
        assert_eq!(
            resp.to_json()["error"]["code"],
            ErrorCode::POLICY_DENIED.as_str()
        );
    }

    #[test]
    fn methods_are_listed_in_sorted_order() {
        let mut r = MethodRouter::new();
        for m in [
            method::SNAPSHOT_LIST,
            method::RESOURCE_TREE,
            method::PLUGIN_LIST,
        ] {
            r.register(m, ok_handler());
        }
        assert_eq!(
            r.methods(),
            vec![
                method::PLUGIN_LIST,
                method::RESOURCE_TREE,
                method::SNAPSHOT_LIST
            ]
        );
    }

    #[tokio::test]
    async fn re_registering_replaces_the_handler() {
        let mut r = MethodRouter::new();
        r.register(method::RESOURCE_TREE, ok_handler());
        r.register_sync(method::RESOURCE_TREE, |_| Ok(Json::from("replaced")));
        assert_eq!(r.len(), 1);
        let resp = r
            .dispatch(&Request::new(method::RESOURCE_TREE, Json::Null))
            .await;
        assert_eq!(resp.to_json()["result"], Json::String("replaced".into()));
    }

    #[test]
    fn contains_reflects_registration() {
        let mut r = MethodRouter::new();
        assert!(!r.contains(method::RESOURCE_TREE));
        assert!(r.is_empty());
        r.register(method::RESOURCE_TREE, ok_handler());
        assert!(r.contains(method::RESOURCE_TREE));
        assert!(!r.is_empty());
    }
}
