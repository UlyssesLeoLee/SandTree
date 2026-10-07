//! JSON-RPC 2.0 message handling for the MCP channel.
//!
//! MCP's streamable HTTP transport *is* JSON-RPC 2.0 over HTTP POST, so this is
//! the whole protocol surface the channel needs. The server is inside the
//! sandbox and is therefore untrusted, so every field is validated rather than
//! assumed:
//!
//! * `jsonrpc` must be exactly `"2.0"` — not `"2"`, and not absent.
//! * A response's `id` must match the request that produced it. A mismatch means
//!   the answer is about something else, and accepting it would attribute one
//!   sandbox's data to another.
//! * A response must carry **exactly one** of `result` / `error`. Neither means
//!   the exchange did not complete; both means the server is confused.
//! * An `error` is surfaced as an error, never coerced into an empty result.
//!
//! The last point is the one that matters most here: an error response and a
//! response with empty data look identical to a caller that ignores the
//! distinction, and that is how a broken channel turns into a false finding
//! (ADR-OBS-001).

use serde::{Deserialize, Serialize};
use serde_json::Value as Json;

/// The only version string JSON-RPC 2.0 defines.
pub const JSONRPC_VERSION: &str = "2.0";

/// Standard JSON-RPC error codes.
pub mod codes {
    /// Invalid JSON was received.
    pub const PARSE_ERROR: i64 = -32700;
    /// The payload was not a valid request object.
    pub const INVALID_REQUEST: i64 = -32600;
    /// The method does not exist.
    pub const METHOD_NOT_FOUND: i64 = -32601;
    /// The method's parameters are invalid.
    pub const INVALID_PARAMS: i64 = -32602;
    /// Internal server error.
    pub const INTERNAL_ERROR: i64 = -32603;
}

/// A request this client sends.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Request {
    /// Always [`JSONRPC_VERSION`].
    pub jsonrpc: String,
    /// Correlation id. Monotonic per client instance.
    pub id: u64,
    /// Method name.
    pub method: String,
    /// Method parameters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Json>,
}

impl Request {
    /// Build a request with no parameters.
    pub fn new(id: u64, method: impl Into<String>) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            id,
            method: method.into(),
            params: None,
        }
    }

    /// Attach parameters.
    pub fn with_params(mut self, params: Json) -> Self {
        self.params = Some(params);
        self
    }

    /// Serialize to the wire.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

/// A server-reported error.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RpcError {
    /// JSON-RPC error code.
    pub code: i64,
    /// Short message.
    pub message: String,
    /// Optional detail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Json>,
}

/// A response this client reads.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Response {
    /// Always [`JSONRPC_VERSION`].
    pub jsonrpc: String,
    /// Correlation id, echoed.
    #[serde(default)]
    pub id: Option<Json>,
    /// Success payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Json>,
    /// Error payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
}

/// Why a response could not be accepted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProtocolError {
    /// The body was not valid JSON.
    #[error("response body was not valid JSON")]
    NotJson,
    /// `jsonrpc` was missing or not `"2.0"`.
    #[error("jsonrpc version must be \"2.0\", got {0:?}")]
    BadVersion(String),
    /// The response had no `id`, so it cannot be correlated.
    #[error("response carried no id")]
    MissingId,
    /// The response `id` did not match the request.
    #[error("response id did not match the request")]
    IdMismatch,
    /// The response carried neither `result` nor `error`.
    #[error("response carried neither result nor error")]
    NeitherResultNorError,
    /// The response carried both.
    #[error("response carried both result and error")]
    BothResultAndError,
    /// The server reported an error.
    #[error("server reported error {code}: {message}")]
    Rpc {
        /// JSON-RPC error code.
        code: i64,
        /// Server message.
        message: String,
    },
    /// An SSE response contained no message frame.
    #[error("event stream carried no message frame")]
    NoMessageFrame,
}

/// Parse and validate a response against the id that was sent.
///
/// `expected_id` correlation is not optional: without it a server could answer
/// an earlier request and the caller would record it against this one.
pub fn parse_response(body: &str, expected_id: u64) -> Result<Response, ProtocolError> {
    let value: Json = serde_json::from_str(body).map_err(|_| ProtocolError::NotJson)?;
    parse_response_value(value, expected_id)
}

/// [`parse_response`] over an already-parsed [`Json`].
pub fn parse_response_value(value: Json, expected_id: u64) -> Result<Response, ProtocolError> {
    let obj = value.as_object().ok_or(ProtocolError::NotJson)?;

    match obj.get("jsonrpc") {
        Some(Json::String(v)) if v == JSONRPC_VERSION => {}
        Some(other) => {
            return Err(ProtocolError::BadVersion(
                other.as_str().unwrap_or("<non-string>").to_string(),
            ))
        }
        None => return Err(ProtocolError::BadVersion("<absent>".to_string())),
    }

    let id = obj.get("id").ok_or(ProtocolError::MissingId)?;
    let id_num = match id {
        Json::Number(n) => n.as_u64(),
        // A string id is legal JSON-RPC, but this client only ever sends
        // numeric ids, so a string id is a mismatch rather than a match.
        _ => None,
    };
    if id_num != Some(expected_id) {
        return Err(ProtocolError::IdMismatch);
    }

    let has_result = obj.contains_key("result");
    let has_error = obj.contains_key("error");
    match (has_result, has_error) {
        (true, true) => return Err(ProtocolError::BothResultAndError),
        (false, false) => return Err(ProtocolError::NeitherResultNorError),
        _ => {}
    }

    let resp: Response = serde_json::from_value(value).map_err(|_| ProtocolError::NotJson)?;

    // An error is an error. It is not coerced into an empty result, because
    // that is exactly how "the call failed" turns into "the sandbox has no
    // tools" downstream.
    if let Some(e) = &resp.error {
        return Err(ProtocolError::Rpc {
            code: e.code,
            message: e.message.clone(),
        });
    }

    Ok(resp)
}

/// Extract the `data` payloads from a `text/event-stream` body.
///
/// Per the MCP streamable transport the server may answer with SSE. Frames
/// look like:
///
/// ```text
/// : keep-alive
/// event: message
/// data: {"jsonrpc":"2.0","id":1,"result":{...}}
/// ```
///
/// `:` lines are comments and ignored. Multiple `data:` lines in one frame are
/// joined with `\n`, as the SSE grammar requires.
pub fn extract_sse_data(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current: Option<Vec<String>> = None;

    for line in body.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.is_empty() {
            // Blank line dispatches the frame.
            if let Some(parts) = current.take() {
                out.push(parts.join("\n"));
            }
            continue;
        }
        if line.starts_with(':') {
            continue;
        }
        let Some((field, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.strip_prefix(' ').unwrap_or(value);
        if field == "data" {
            current.get_or_insert_with(Vec::new).push(value.to_string());
        }
        // `event`, `id` and `retry` do not affect the message body here.
    }
    if let Some(parts) = current {
        out.push(parts.join("\n"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_body(id: u64) -> String {
        format!(r#"{{"jsonrpc":"2.0","id":{id},"result":{{"tools":[]}}}}"#)
    }

    #[test]
    fn a_matching_success_response_is_accepted() {
        let r = parse_response(&ok_body(1), 1).unwrap();
        assert_eq!(r.id, Some(Json::from(1u64)));
        assert_eq!(r.result.unwrap()["tools"], serde_json::json!([]));
        assert!(r.error.is_none());
    }

    #[test]
    fn a_response_for_a_different_request_is_refused() {
        // Break by dropping the id correlation, and a server answering request
        // 1 with data from request 2 gets recorded against the wrong call.
        assert_eq!(
            parse_response(&ok_body(2), 1).unwrap_err(),
            ProtocolError::IdMismatch
        );
        assert_eq!(
            parse_response(r#"{"jsonrpc":"2.0","id":"1","result":{}}"#, 1).unwrap_err(),
            ProtocolError::IdMismatch,
            "a string id does not match the numeric id that was sent"
        );
        assert_eq!(
            parse_response(r#"{"jsonrpc":"2.0","result":{}}"#, 1).unwrap_err(),
            ProtocolError::MissingId
        );
    }

    #[test]
    fn a_non_2_0_version_is_refused() {
        // Break by accepting "2" or a missing field, and a non-JSON-RPC
        // response shape starts being treated as a valid answer.
        for body in [
            r#"{"jsonrpc":"2","id":1,"result":{}}"#,
            r#"{"id":1,"result":{}}"#,
        ] {
            assert!(matches!(
                parse_response(body, 1),
                Err(ProtocolError::BadVersion(_))
            ));
        }
    }

    #[test]
    fn an_error_response_is_never_coerced_into_an_empty_result() {
        // The distinction that stops a failing channel from reading as
        // "the sandbox exposes nothing" (ADR-OBS-001).
        let body =
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found"}}"#;
        let err = parse_response(body, 1).unwrap_err();
        assert_eq!(
            err,
            ProtocolError::Rpc {
                code: codes::METHOD_NOT_FOUND,
                message: "Method not found".to_string()
            }
        );
    }

    #[test]
    fn a_response_with_both_or_neither_is_refused() {
        assert_eq!(
            parse_response(
                r#"{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":1,"message":"x"}}"#,
                1
            )
            .unwrap_err(),
            ProtocolError::BothResultAndError
        );
        assert_eq!(
            parse_response(r#"{"jsonrpc":"2.0","id":1}"#, 1).unwrap_err(),
            ProtocolError::NeitherResultNorError
        );
    }

    #[test]
    fn a_non_json_body_is_refused() {
        assert_eq!(
            parse_response("<html>404</html>", 1).unwrap_err(),
            ProtocolError::NotJson
        );
        assert_eq!(parse_response("", 1).unwrap_err(), ProtocolError::NotJson);
        assert_eq!(
            parse_response("[1,2,3]", 1).unwrap_err(),
            ProtocolError::NotJson
        );
    }

    #[test]
    fn requests_serialize_with_the_version_and_id() {
        let r = Request::new(7, "initialize").with_params(serde_json::json!({"a": 1}));
        let s = r.to_json().unwrap();
        assert!(s.contains(r#""jsonrpc":"2.0""#));
        assert!(s.contains(r#""id":7"#));
        assert!(s.contains(r#""method":"initialize""#));
        // Round-trip keeps the correlation id the response will be checked against.
        let back: Request = serde_json::from_str(&s).unwrap();
        assert_eq!(back.id, 7);
    }

    #[test]
    fn sse_frames_yield_their_data_payloads() {
        let body = concat!(
            ": keep-alive\n",
            "\n",
            "event: message\n",
            "data: {\"jsonrpc\":\"2.0\",\"id\":1,\n",
            "data: \"result\":{\"ok\":true}}\n",
            "\n",
        );
        let frames = extract_sse_data(body);
        // Two `data:` lines are one frame, joined with a newline.
        assert_eq!(frames.len(), 1);
        let resp = parse_response(&frames[0], 1).unwrap();
        assert_eq!(resp.result.unwrap()["ok"], Json::Bool(true));
    }

    #[test]
    fn a_stream_with_several_messages_yields_every_one() {
        let body = concat!(
            "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n",
            "data: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{}}\n\n",
        );
        let frames = extract_sse_data(body);
        assert_eq!(frames.len(), 2);
        assert!(parse_response(&frames[0], 1).is_ok());
        assert!(parse_response(&frames[1], 2).is_ok());
    }

    #[test]
    fn a_comment_only_stream_yields_no_message_frame() {
        // Break by returning the keep-alive comments as data, and a stream
        // with nothing in it produces a bogus "empty" response.
        assert!(extract_sse_data(": ping\n\n: pong\n\n").is_empty());
    }

    #[test]
    fn an_unterminated_final_frame_is_still_captured() {
        // A stream that ends without the final blank line is common enough
        // that dropping the last message would silently lose data.
        let frames = extract_sse_data("data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}");
        assert_eq!(frames.len(), 1);
    }

    #[test]
    fn crlf_framing_is_accepted() {
        // Break by not stripping `\r`, and every frame parsed from a CRLF
        // server carries a trailing carriage return into the JSON.
        let frames = extract_sse_data("event: message\r\ndata: {\"a\":1}\r\n\r\n");
        assert_eq!(frames, vec!["{\"a\":1}".to_string()]);
    }
}
