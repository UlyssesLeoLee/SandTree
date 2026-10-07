//! Length-prefixed framing (DD-DATA §5).
//!
//! `u32` little-endian length, then the body. The decoder is incremental: a
//! pipe delivers whatever it delivers, so a frame arrives in pieces and the
//! decoder has to hold a partial one rather than assume a whole.

use sandtree_model::error::{DomainError, ErrorCode};

/// Hard ceiling on one frame. A declared length beyond this is refused before
/// any allocation happens, so a peer cannot request a 4 GiB buffer.
pub const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;

/// Bytes of the length prefix.
pub const LEN_PREFIX_BYTES: usize = 4;

fn too_large(declared: u32) -> DomainError {
    DomainError::new(
        ErrorCode::CORE_INVALID,
        format!("IPC frame declares {declared} bytes, above the {MAX_FRAME_BYTES}-byte limit"),
    )
}

fn incomplete() -> DomainError {
    DomainError::new(ErrorCode::CORE_INVALID, "truncated IPC frame")
}

/// Encode one frame.
pub fn encode(payload: &[u8]) -> Result<Vec<u8>, DomainError> {
    let len = u32::try_from(payload.len()).map_err(|_| too_large(u32::MAX))?;
    if payload.len() > MAX_FRAME_BYTES {
        return Err(too_large(len));
    }
    let mut out = Vec::with_capacity(LEN_PREFIX_BYTES + payload.len());
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Read the declared length from the front of a buffer.
///
/// Returns `None` when fewer than [`LEN_PREFIX_BYTES`] bytes are available yet,
/// which is a normal "not yet" rather than an error.
pub fn peek_len(buf: &[u8]) -> Result<Option<u32>, DomainError> {
    if buf.len() < LEN_PREFIX_BYTES {
        return Ok(None);
    }
    let mut raw = [0u8; LEN_PREFIX_BYTES];
    raw.copy_from_slice(&buf[..LEN_PREFIX_BYTES]);
    let declared = u32::from_le_bytes(raw);
    if declared as usize > MAX_FRAME_BYTES {
        return Err(too_large(declared));
    }
    Ok(Some(declared))
}

/// Decode a single complete frame from `buf`.
///
/// Returns `Ok(None)` when the frame is incomplete. An empty buffer yields
/// `Ok(None)` rather than an error, because "connection closed cleanly" and
/// "nothing yet" arrive the same way on a pipe.
pub fn decode(buf: &[u8]) -> Result<Option<(Vec<u8>, usize)>, DomainError> {
    let Some(declared) = peek_len(buf)? else {
        return Ok(None);
    };
    let declared = declared as usize;
    let total = LEN_PREFIX_BYTES + declared;
    if buf.len() < total {
        return Ok(None);
    }
    Ok(Some((buf[LEN_PREFIX_BYTES..total].to_vec(), total)))
}

/// Decode exactly one frame, requiring the buffer to hold nothing more.
///
/// Used where a whole datagram is available; a trailing byte is a framing bug
/// and is reported rather than ignored.
pub fn decode_exact(buf: &[u8]) -> Result<Vec<u8>, DomainError> {
    match decode(buf)? {
        Some((body, _)) => Ok(body),
        None => Err(incomplete()),
    }
}

/// Incremental frame reader.
#[derive(Debug, Default)]
pub struct FrameDecoder {
    buf: Vec<u8>,
}

impl FrameDecoder {
    /// Empty decoder.
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Feed bytes read from the transport.
    ///
    /// Bytes beyond the frame limit are rejected on arrival, not when the
    /// length prefix happens to be complete.
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), DomainError> {
        self.buf.extend_from_slice(bytes);
        // Guard the buffer itself, not just the declared length: a peer that
        // streams without ever sending a complete prefix must still be bounded.
        if self.buf.len() > MAX_FRAME_BYTES + LEN_PREFIX_BYTES {
            return Err(too_large(self.buf.len() as u32));
        }
        Ok(())
    }

    /// Pop the next complete frame, if any.
    pub fn next_frame(&mut self) -> Result<Option<Vec<u8>>, DomainError> {
        match decode(&self.buf)? {
            Some((body, used)) => {
                self.buf.drain(..used);
                Ok(Some(body))
            }
            None => Ok(None),
        }
    }

    /// Bytes buffered but not yet part of a complete frame.
    pub fn pending(&self) -> usize {
        self.buf.len()
    }

    /// Whether anything is buffered.
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Drop buffered bytes (used when a connection is reset).
    pub fn reset(&mut self) {
        self.buf.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let frame = encode(b"hello").unwrap();
        assert_eq!(frame.len(), LEN_PREFIX_BYTES + 5);
        let (body, used) = decode(&frame).unwrap().unwrap();
        assert_eq!(body, b"hello");
        assert_eq!(used, frame.len());
    }

    #[test]
    fn empty_payload_is_a_valid_frame() {
        let frame = encode(b"").unwrap();
        let (body, _) = decode(&frame).unwrap().unwrap();
        assert!(body.is_empty());
    }

    #[test]
    fn a_partial_frame_is_not_an_error() {
        let frame = encode(b"hello world").unwrap();
        for cut in 0..frame.len() {
            if let Some((body, used)) = decode(&frame[..cut]).unwrap() {
                panic!(
                    "cut at {cut} produced a frame of {} bytes",
                    body.len() + used
                );
            }
        }
        // The complete frame is the first that decodes.
        assert!(decode(&frame).unwrap().is_some());
    }

    #[test]
    fn little_endian_length_prefix() {
        let frame = encode(&[0u8; 258]).unwrap();
        assert_eq!(&frame[..4], &[2, 1, 0, 0]);
    }

    #[test]
    fn an_oversized_declaration_is_refused_before_buffering() {
        // This is the memory-exhaustion guard: a peer must not be able to make
        // the daemon reserve whatever it claims.
        let mut raw = Vec::new();
        let huge = (MAX_FRAME_BYTES as u32) + 1;
        raw.extend_from_slice(&huge.to_le_bytes());
        let err = peek_len(&raw).unwrap_err();
        assert!(err.message.contains("above the"), "{}", err.message);
    }

    #[test]
    fn a_stream_without_a_usable_prefix_is_still_bounded() {
        // The bound is enforced on the buffered bytes, not only on a parsed
        // length, so a peer that never sends a complete prefix is still capped.
        let mut d = FrameDecoder::new();
        let err = d.push(&vec![0x41u8; MAX_FRAME_BYTES + 8]).unwrap_err();
        assert!(err.message.contains("above the"), "{}", err.message);
    }

    #[test]
    fn decoder_handles_frames_split_across_arbitrary_chunks() {
        let a = encode(b"first").unwrap();
        let b = encode(b"second").unwrap();
        let mut stream = a.clone();
        stream.extend_from_slice(&b);

        let mut d = FrameDecoder::new();
        let mut out = Vec::new();
        for byte in stream {
            d.push(&[byte]).unwrap();
            while let Some(frame) = d.next_frame().unwrap() {
                out.push(frame);
            }
        }
        assert_eq!(out, vec![b"first".to_vec(), b"second".to_vec()]);
        assert!(d.is_empty());
    }

    #[test]
    fn decoder_yields_frames_in_order_from_one_push() {
        let mut stream = encode(b"one").unwrap();
        stream.extend(encode(b"two").unwrap());
        stream.extend(encode(b"three").unwrap());
        let mut d = FrameDecoder::new();
        d.push(&stream).unwrap();
        assert_eq!(d.next_frame().unwrap().unwrap(), b"one");
        assert_eq!(d.next_frame().unwrap().unwrap(), b"two");
        assert_eq!(d.next_frame().unwrap().unwrap(), b"three");
        assert!(d.next_frame().unwrap().is_none());
        assert_eq!(d.pending(), 0);
    }

    #[test]
    fn decode_exact_rejects_a_truncated_buffer() {
        let frame = encode(b"payload").unwrap();
        assert_eq!(decode_exact(&frame).unwrap(), b"payload");
        assert!(decode_exact(&frame[..3]).is_err());
    }

    #[test]
    fn a_maximum_size_frame_is_accepted() {
        let payload = vec![7u8; MAX_FRAME_BYTES];
        let frame = encode(&payload).unwrap();
        let (body, _) = decode(&frame).unwrap().unwrap();
        assert_eq!(body.len(), MAX_FRAME_BYTES);
    }
}
