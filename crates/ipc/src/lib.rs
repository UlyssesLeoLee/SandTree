//! IPC framing, method routing and transport (DD-DATA §5, §6).
//!
//! Wire format is deliberately boring: a little-endian `u32` length followed by
//! the body. The only interesting rules are the two failure modes —
//!
//! * a length above [`MAX_FRAME_BYTES`] is refused **before** a single byte is
//!   buffered, so a hostile or buggy peer cannot make the daemon allocate its
//!   way to death, and
//! * a decode never trusts the declared length to be the length it got, because
//!   a short read is a normal event on a pipe, not an error to panic on.
//!
//! Windows named pipes are the supported transport. On other platforms the
//! type still compiles and every method returns `ST-IPC-001` rather than
//! silently doing nothing, so a misconfigured build fails loudly.

#![deny(missing_docs)]

pub mod framing;
pub mod method;
pub mod router;
pub mod transport;

pub use framing::{
    decode, decode_exact, encode, peek_len, FrameDecoder, LEN_PREFIX_BYTES, MAX_FRAME_BYTES,
};
pub use method::*;
pub use router::{Handler, MethodRouter, Response};
pub use transport::{NamedPipeTransport, Transport};

use serde_json::Value as Json;

/// A request frame.
#[derive(Debug, Clone, PartialEq)]
pub struct Request {
    /// Request id echoed in the response.
    pub id: String,
    /// Method name, e.g. `resource.list`.
    pub method: String,
    /// Method parameters.
    pub params: Json,
    /// Cross-plane correlation id (NFR-O01).
    pub correlation_id: String,
}

impl Request {
    /// Build a request with a fresh id and correlation id.
    pub fn new(method: impl Into<String>, params: Json) -> Self {
        Self {
            id: sandtree_model::id::CorrelationId::generate().to_string(),
            method: method.into(),
            params,
            correlation_id: sandtree_model::id::CorrelationId::generate().to_string(),
        }
    }
}

/// An event frame pushed from daemon to client.
#[derive(Debug, Clone, PartialEq)]
pub struct EventFrame {
    /// The event payload.
    pub event: Json,
}

impl EventFrame {
    /// Wrap an event payload.
    pub fn new(event: Json) -> Self {
        Self { event }
    }
}
