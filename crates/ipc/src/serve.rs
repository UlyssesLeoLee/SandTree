//! Serving IPC requests over any [`Transport`] (DD-DATA §6, NFR-S03).
//!
//! # Why this is separate from the transport
//!
//! The daemon's whole external surface is "decode a request, dispatch it, write
//! a reply". None of that needs a pipe. Putting it here means the loop is tested
//! over [`crate::loopback::loopback_pair`] — in the normal `cargo test` run, on
//! every platform — instead of only inside a Windows-only integration test that
//! nobody runs on a clean checkout.
//!
//! The transport then has exactly one job left: carry bytes.
//!
//! # One request, one reply, in order
//!
//! There is no correlation id on this path. The connection serialises requests,
//! so a reply is always for the request just sent; adding concurrency later
//! would make an id mandatory *and* would need a test that a reordered pair of
//! replies is detected, or two answers get attributed to the wrong calls and
//! nothing fails.
//!
//! # A malformed request is an answer, not a dropped connection
//!
//! A frame that will not decode still gets a typed error reply. Dropping the
//! connection instead would make a version mismatch look identical to a daemon
//! that crashed, and those two send an operator to completely different places.

use std::sync::Arc;

use sandtree_model::error::{DomainError, ErrorCode};
use serde_json::Value as Json;

use crate::router::{MethodRouter, Response};
use crate::transport::Transport;
use crate::Request;

/// Decode a wire request.
///
/// A request with no `id` is still accepted, with an empty id, because the id is
/// only used to correlate the reply — refusing the call over a missing echo id
/// would turn a cosmetic gap into a hard failure.
pub fn decode_request(body: &Json) -> Result<Request, DomainError> {
    let malformed = |what: &str| {
        DomainError::new(
            ErrorCode::CORE_INVALID,
            format!("malformed IPC request: {what}"),
        )
    };
    let method = body
        .get("method")
        .and_then(Json::as_str)
        .ok_or_else(|| malformed("no `method` string"))?;
    Ok(Request {
        id: body
            .get("id")
            .and_then(Json::as_str)
            .unwrap_or_default()
            .to_string(),
        method: method.to_string(),
        params: body.get("params").cloned().unwrap_or(Json::Null),
        correlation_id: body
            .get("correlation_id")
            .and_then(Json::as_str)
            .unwrap_or_default()
            .to_string(),
    })
}

/// Wire form of a request.
pub fn encode_request(req: &Request) -> Result<Json, DomainError> {
    Ok(serde_json::json!({
        "id": req.id,
        "method": req.method,
        "params": req.params,
        "correlation_id": req.correlation_id,
    }))
}

/// Serve requests on `t` until the peer goes away.
///
/// Returns how many requests were answered. A transport error is returned as an
/// error; the peer disconnecting is not, because a client hanging up after its
/// last request is normal and not worth an alarm.
pub async fn serve_connection(
    router: Arc<MethodRouter>,
    t: &mut dyn Transport,
) -> Result<usize, DomainError> {
    let mut served = 0usize;
    loop {
        let frame = match t.recv().await {
            Ok(Some(bytes)) => bytes,
            Ok(None) => return Ok(served),
            Err(e) => {
                // A pipe closed by the peer ends the session quietly. Anything
                // else is a real transport problem worth reporting.
                if e.message.contains("closed by the peer")
                    || e.message.contains("closed the connection")
                {
                    return Ok(served);
                }
                return Err(e);
            }
        };
        let reply = match serde_json::from_slice::<Json>(&frame) {
            Ok(body) => match decode_request(&body) {
                Ok(req) => router.dispatch(&req).await,
                Err(e) => Response::err(String::new(), e),
            },
            Err(e) => Response::err(
                String::new(),
                DomainError::new(
                    ErrorCode::CORE_INVALID,
                    format!("request frame is not JSON: {e}"),
                ),
            ),
        };
        t.send(reply.to_json().to_string().as_bytes()).await?;
        served += 1;
    }
}

/// Send one request and read its reply.
///
/// Returns `None` when the peer closed the connection without answering, which
/// is a different event from a refusal and must not be flattened into one.
pub async fn call_once(
    t: &mut dyn Transport,
    req: &Request,
) -> Result<Option<Response>, DomainError> {
    t.send(encode_request(req)?.to_string().as_bytes()).await?;
    let Some(reply) = t.recv().await? else {
        return Ok(None);
    };
    let body: Json = serde_json::from_slice(&reply).map_err(|e| {
        DomainError::new(
            ErrorCode::CORE_INVALID,
            format!("reply frame is not JSON: {e}"),
        )
    })?;
    Ok(Some(decode_response(&body)))
}

/// Decode a wire reply.
///
/// Only the observable parts are reconstructed: the daemon's `DomainError` is
/// not `Clone`, and the client never dispatches on it, it only reports it.
pub fn decode_response(body: &Json) -> Response {
    let id = body.get("id").and_then(Json::as_str).unwrap_or_default();
    if body.get("ok").and_then(Json::as_bool) == Some(true) {
        return Response::ok(id, body.get("result").cloned().unwrap_or(Json::Null));
    }
    let error = body.get("error");
    Response::err(
        id,
        DomainError::new(
            error
                .and_then(|e| e.get("code"))
                .and_then(Json::as_str)
                .and_then(ErrorCode::parse)
                .unwrap_or(ErrorCode::CORE_INVALID),
            error
                .and_then(|e| e.get("message"))
                .and_then(Json::as_str)
                .unwrap_or("the daemon reported a failure with no message")
                .to_string(),
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loopback::loopback_pair;
    use crate::method;

    fn router() -> Arc<MethodRouter> {
        let mut r = MethodRouter::new();
        r.register_sync(method::DIAGNOSTIC_VERSION, |_| Ok(Json::from("v1.1.0")));
        r.register_sync(method::RESOURCE_GET, |req| {
            req.params
                .get("resource_id")
                .cloned()
                .ok_or_else(|| DomainError::new(ErrorCode::CORE_INVALID, "no resource_id"))
        });
        Arc::new(r)
    }

    /// Run the server half on its own task and hand back the client half.
    ///
    /// The server end has to be *moved* into the task rather than borrowed: a
    /// future holding a borrow of a local cannot be `'static`, which is what
    /// `tokio::spawn` requires. Every test below wants the same shape, so it is
    /// written once.
    fn spawn_server(
        r: Arc<MethodRouter>,
    ) -> (
        crate::loopback::Loopback,
        tokio::task::JoinHandle<Result<usize, DomainError>>,
    ) {
        let (client, server) = loopback_pair();
        let task = tokio::spawn(async move {
            let mut server = server;
            serve_connection(r, &mut server).await
        });
        (client, task)
    }

    /// End to end over a transport, in one process: this is the loop the daemon
    /// runs for every client, exercised without a pipe so it is checked on every
    /// platform.
    #[tokio::test]
    async fn a_request_goes_out_over_the_wire_and_the_reply_comes_back() {
        let (mut client, serving) = spawn_server(router());

        let req = Request::new(method::DIAGNOSTIC_VERSION, Json::Null);
        let reply = call_once(&mut client, &req)
            .await
            .expect("transport")
            .expect("a reply");
        assert!(reply.is_ok());
        assert_eq!(reply.to_json()["result"], Json::from("v1.1.0"));

        drop(client);
        let served = serving.await.expect("server task").expect("serve");
        assert_eq!(served, 1, "exactly one request should have been answered");
    }

    #[tokio::test]
    async fn the_reply_echoes_the_request_id() {
        let (mut client, serving) = spawn_server(router());

        let mut req = Request::new(method::DIAGNOSTIC_VERSION, Json::Null);
        req.id = "req-42".into();
        let reply = call_once(&mut client, &req).await.unwrap().unwrap();
        assert_eq!(reply.to_json()["id"], Json::from("req-42"));

        drop(client);
        let _ = serving.await;
    }

    /// An unknown method is a typed error naming the method, not a dropped
    /// connection — otherwise "wrong version of the CLI" looks like "daemon
    /// crashed", and those send an operator to opposite places.
    #[tokio::test]
    async fn an_unknown_method_is_answered_not_dropped() {
        let (mut client, serving) = spawn_server(router());

        let mut req = Request::new("resource.teleport", Json::Null);
        req.id = "x".into();
        let reply = call_once(&mut client, &req).await.unwrap().unwrap();
        assert!(!reply.is_ok());
        assert!(
            reply.to_json()["error"]["message"]
                .as_str()
                .unwrap()
                .contains("resource.teleport"),
            "{}",
            reply.to_json()
        );

        drop(client);
        let _ = serving.await;
    }

    /// A frame that is not JSON at all still gets a reply.
    #[tokio::test]
    async fn garbage_on_the_wire_is_an_answer_not_a_disconnect() {
        let (mut client, serving) = spawn_server(router());

        client.send(b"this is not json").await.expect("send");
        let reply = client.recv().await.expect("recv").expect("a frame");
        let body: Json = serde_json::from_slice(&reply).expect("json reply");
        assert_eq!(body["ok"], Json::from(false));
        assert!(body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("not JSON"));

        drop(client);
        let _ = serving.await;
    }

    /// Several requests on one connection, answered in order.
    #[tokio::test]
    async fn a_connection_serves_a_sequence_and_reports_how_many() {
        let (mut client, serving) = spawn_server(router());

        for i in 0..3 {
            let req = Request::new(method::RESOURCE_GET, serde_json::json!({"resource_id": i}));
            let reply = call_once(&mut client, &req).await.unwrap().unwrap();
            assert_eq!(reply.to_json()["result"], serde_json::json!(i));
        }

        drop(client);
        assert_eq!(serving.await.unwrap().unwrap(), 3);
    }

    /// A handler that refuses comes back as a failure with its stable code, so
    /// the client can tell "the daemon said no" from "the daemon is gone".
    #[tokio::test]
    async fn a_handler_failure_keeps_its_code_across_the_wire() {
        let (mut client, serving) = spawn_server(router());

        let reply = call_once(&mut client, &Request::new(method::RESOURCE_GET, Json::Null))
            .await
            .unwrap()
            .unwrap();
        assert!(!reply.is_ok());
        assert_eq!(reply.to_json()["error"]["code"], Json::from("ST-CORE-001"));

        drop(client);
        let _ = serving.await;
    }

    /// The peer hanging up without sending anything is a normal end of session,
    /// not an error the daemon has to log as a failure.
    #[tokio::test]
    async fn a_client_that_hangs_up_immediately_is_not_a_serve_error() {
        // The client is dropped *before* serving, or `recv` would correctly wait
        // forever for a peer that is still there and has said nothing.
        let (client, mut server) = loopback_pair();
        drop(client);
        let served = serve_connection(router(), &mut server).await;
        assert_eq!(served.expect("no error"), 0);
    }
}
