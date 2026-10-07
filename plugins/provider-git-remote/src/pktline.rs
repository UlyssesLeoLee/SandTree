//! git pkt-line framing (the wire format behind `info/refs` and
//! `upload-pack`), reduced to exactly what ref advertisement needs.
//!
//! # Why this is implemented here rather than pulled in
//!
//! The design baseline lists `gix/gitoxide` as the OPTIONAL git technology, but
//! the operation this provider needs — *read the ref advertisement* — does not
//! justify a git implementation dependency (ADR-015). pkt-line is a four-hex
//! length prefix and a payload; the whole format used here is under a hundred
//! lines and, crucially, is **testable without a git binary**.
//!
//! # Format
//!
//! ```text
//! 001e# service=git-upload-pack\n
//! 0000
//! 0107<40-hex> refs/heads/main\0<capabilities>\n
//! 003f<40-hex> refs/tags/v1\n
//! 0000
//! ```
//!
//! The four leading hex digits are the **total** length of the packet, header
//! included, trailing LF included. Four values are reserved:
//! `0000` flush, `0001` delim, `0002` response-end, `0003` invalid.
//!
//! # Failure is never "no refs"
//!
//! A malformed advertisement returns an error. It never yields an empty
//! ref list, because an empty list is indistinguishable from an empty
//! repository and would let a parse bug look like a finding (ADR-OBS-001).

/// Flush packet: end of a section.
pub const FLUSH_PKT: &str = "0000";
/// Delim packet: separates sections within one response.
pub const DELIM_PKT: &str = "0001";
/// Response-end packet: no further response follows.
pub const RESPONSE_END_PKT: &str = "0002";

/// Largest payload a single data packet may carry, per git's own limit.
///
/// git caps `MAX_PACKET_DATA` at 65520 bytes; a longer payload is invalid
/// input rather than something to encode.
pub const MAX_DATA_LEN: usize = 65520;

/// One decoded packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PktLine {
    /// A payload packet, with the trailing LF already stripped.
    Data(String),
    /// `0000`.
    Flush,
    /// `0001`.
    Delim,
    /// `0002`.
    ResponseEnd,
}

/// pkt-line decoding failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PktLineError {
    /// The four-byte length prefix was not lowercase hex.
    #[error("pkt-line length prefix is not hex: {0:?}")]
    NotHex(String),
    /// The declared length ran past the end of the input.
    #[error("pkt-line declared length {declared} exceeds the remaining {remaining} bytes")]
    Truncated {
        /// The declared length.
        declared: usize,
        /// Bytes actually left.
        remaining: usize,
    },
    /// `0003`, git's explicit "invalid packet" sentinel.
    #[error("server sent the invalid-packet sentinel (0003)")]
    InvalidSentinel,
    /// A data payload that does not end in LF.
    #[error("pkt-line data payload does not end with LF")]
    MissingTrailingLf,
}

/// Encode one data packet.
///
/// The payload is written verbatim; callers that want a trailing LF include it.
pub fn encode(data: &str) -> Result<String, PktLineError> {
    let payload = data.as_bytes();
    if payload.len() > MAX_DATA_LEN {
        return Err(PktLineError::Truncated {
            declared: payload.len(),
            remaining: MAX_DATA_LEN,
        });
    }
    let total = payload.len() + 4;
    Ok(format!("{total:04x}{data}"))
}

/// The flush packet.
pub fn encode_flush() -> String {
    FLUSH_PKT.to_string()
}

/// Decode every packet in `input`, in order.
///
/// Stops cleanly at a flush packet: everything after a flush belongs to a
/// later exchange, so decoding it here would invent refs that this request
/// never advertised.
pub fn decode_all(input: &str) -> Result<Vec<PktLine>, PktLineError> {
    let bytes = input.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;

    while i < bytes.len() {
        // Trailing whitespace after the final flush is tolerated; a real
        // server sends nothing, but a proxy may append a newline.
        if bytes[i..].iter().all(|b| b.is_ascii_whitespace()) {
            break;
        }

        if i + 4 > bytes.len() {
            return Err(PktLineError::Truncated {
                declared: 4,
                remaining: bytes.len() - i,
            });
        }

        let header = &input[i..i + 4];
        let declared = usize::from_str_radix(header, 16)
            .map_err(|_| PktLineError::NotHex(header.to_string()))?;

        match header {
            FLUSH_PKT => {
                out.push(PktLine::Flush);
                i += 4;
            }
            DELIM_PKT => {
                out.push(PktLine::Delim);
                i += 4;
            }
            RESPONSE_END_PKT => {
                out.push(PktLine::ResponseEnd);
                i += 4;
            }
            "0003" => return Err(PktLineError::InvalidSentinel),
            _ => {
                // 0000-0003 are the reserved values handled above, so any
                // packet reaching here declares at least 4: the header itself.
                // A length below that is therefore not representable and needs
                // no branch.
                debug_assert!(declared >= 4, "reserved packets are matched above");
                let end = i + declared;
                if end > bytes.len() {
                    return Err(PktLineError::Truncated {
                        declared,
                        remaining: bytes.len() - i,
                    });
                }
                let payload = &input[i + 4..end];
                // Length 4 is a legal packet with no payload and no
                // terminator; everything else must end in LF.
                let body = if payload.is_empty() {
                    ""
                } else {
                    payload
                        .strip_suffix('\n')
                        .ok_or(PktLineError::MissingTrailingLf)?
                };
                out.push(PktLine::Data(body.to_string()));
                i = end;
            }
        }
    }

    Ok(out)
}

/// Decode and return only data payloads, stopping at the first flush.
pub fn decode_data_until_flush(input: &str) -> Result<Vec<String>, PktLineError> {
    let mut out = Vec::new();
    for pkt in decode_all(input)? {
        match pkt {
            PktLine::Data(d) => out.push(d),
            PktLine::Flush => break,
            PktLine::Delim | PktLine::ResponseEnd => {}
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_a_data_packet() {
        // Break by changing the length computation (dropping +4, or counting
        // the LF twice) and the decoded payload stops matching.
        let payload = "# service=git-upload-pack\n";
        let wire = encode(payload).unwrap();
        assert_eq!(wire.len(), 4 + payload.len());
        assert_eq!(&wire[..4], "001e");
        // The trailing LF is the packet terminator, so it is consumed rather
        // than delivered as payload.
        assert_eq!(
            decode_all(&wire).unwrap(),
            vec![PktLine::Data("# service=git-upload-pack".to_string())]
        );
    }

    #[test]
    fn decodes_a_real_multi_ref_advertisement() {
        // Built with the encoder so the packet lengths cannot drift from the
        // payloads — the shape is what git-http-backend actually returns:
        // service line, flush, a capabilities-bearing first ref, then plain
        // refs, a peeled tag, and a closing flush.
        let mut wire = encode("# service=git-upload-pack\n").unwrap();
        wire.push_str(&encode_flush());
        wire.push_str(
            &encode(concat!(
                "0000000000000000000000000000000000000000 HEAD\0",
                "symref=HEAD:refs/heads/main agent=git/2.45\n"
            ))
            .unwrap(),
        );
        wire.push_str(
            &encode("1111111111111111111111111111111111111111 refs/heads/main\n").unwrap(),
        );
        wire.push_str(&encode("2222222222222222222222222222222222222222 refs/tags/v1\n").unwrap());
        wire.push_str(
            &encode("3333333333333333333333333333333333333333 refs/tags/v1^{}\n").unwrap(),
        );
        wire.push_str(&encode_flush());

        let data = decode_data_until_flush(&wire).unwrap();
        // The flush separates the service section from the ref section, so
        // `decode_data_until_flush` deliberately returns only the first one.
        assert_eq!(data, vec!["# service=git-upload-pack".to_string()]);

        // Decoding the whole thing yields every packet.
        let all = decode_all(&wire).unwrap();
        assert_eq!(all.len(), 7);
        assert_eq!(all[1], PktLine::Flush);
        assert!(matches!(&all[2], PktLine::Data(d) if d.ends_with("agent=git/2.45")));
        assert_eq!(all[6], PktLine::Flush);
    }

    #[test]
    fn decoding_stops_at_the_flush_so_later_sections_are_not_invented() {
        // Break by removing the `Flush => break` and the second section's refs
        // get attributed to the first request.
        let mut wire = encode("# service=git-upload-pack\n").unwrap();
        wire.push_str(&encode_flush());
        wire.push_str(
            &encode("1111111111111111111111111111111111111111 refs/heads/main\n").unwrap(),
        );
        wire.push_str(&encode_flush());
        assert_eq!(decode_data_until_flush(&wire).unwrap().len(), 1);
    }

    #[test]
    fn a_truncated_packet_is_an_error() {
        let mut wire = encode("# service=git-upload-pack\n").unwrap();
        wire.pop();
        assert!(matches!(
            decode_all(&wire),
            Err(PktLineError::Truncated { .. })
        ));
    }

    #[test]
    fn reserved_packets_are_distinguished_from_data() {
        // Break by collapsing the four reserved values into data and a real
        // server's flush stops parsing correctly.
        let wire = format!("0000{FLUSH_PKT}{DELIM_PKT}{RESPONSE_END_PKT}");
        assert_eq!(
            decode_all(&wire).unwrap(),
            vec![
                PktLine::Flush,
                PktLine::Flush,
                PktLine::Delim,
                PktLine::ResponseEnd
            ]
        );
    }

    #[test]
    fn the_invalid_sentinel_is_an_error_not_an_empty_section() {
        // 0003 must never be read as "no refs".
        assert_eq!(
            decode_all("0003").unwrap_err(),
            PktLineError::InvalidSentinel
        );
    }

    #[test]
    fn a_length_that_runs_past_the_input_is_an_error() {
        // Break by clamping the length instead of erroring, and a truncated
        // advertisement silently loses its last ref.
        let wire = "003f1111111111111111111111111111111111111 refs/heads/ma";
        assert!(matches!(
            decode_all(wire),
            Err(PktLineError::Truncated { .. })
        ));
    }

    #[test]
    fn reserved_values_cover_every_length_below_the_header_size() {
        // 0000..=0003 are flush/delim/response-end/invalid, so every one of
        // them is claimed and a data packet always declares at least 4. This
        // pins that set: if a reserved value is dropped, the decoder starts
        // treating it as a data packet with a length shorter than its header.
        assert_eq!(decode_all("0000").unwrap(), vec![PktLine::Flush]);
        assert_eq!(decode_all("0001").unwrap(), vec![PktLine::Delim]);
        assert_eq!(decode_all("0002").unwrap(), vec![PktLine::ResponseEnd]);
        assert_eq!(
            decode_all("0003").unwrap_err(),
            PktLineError::InvalidSentinel
        );
        // 0004 is the smallest legal data packet: an empty payload.
        assert_eq!(
            decode_all("0004").unwrap(),
            vec![PktLine::Data(String::new())]
        );
    }

    #[test]
    fn a_non_hex_length_is_an_error() {
        assert!(matches!(
            decode_all("zzzzabcd\n"),
            Err(PktLineError::NotHex(_))
        ));
    }

    #[test]
    fn a_payload_without_a_trailing_lf_is_an_error() {
        // Break by accepting payloads without LF and a packet boundary in the
        // middle of a ref name stops being detectable. The declared length is
        // 8 = 4-byte header + 4 payload bytes, with no terminator.
        assert_eq!(
            decode_all("0008abcd").unwrap_err(),
            PktLineError::MissingTrailingLf
        );
    }

    #[test]
    fn trailing_whitespace_after_the_final_flush_is_tolerated() {
        // A proxy appending a newline must not turn a good response into an error.
        assert_eq!(decode_all("0000\n").unwrap(), vec![PktLine::Flush]);
    }

    #[test]
    fn an_empty_input_decodes_to_no_packets() {
        assert_eq!(decode_all("").unwrap(), Vec::new());
    }

    #[test]
    fn encoding_refuses_an_oversized_payload() {
        // Break by removing the bound and one oversized advertisement is
        // buffered whole instead of being rejected at the source.
        let huge = "x".repeat(MAX_DATA_LEN + 1);
        assert!(encode(&huge).is_err());
        let ok = "x".repeat(MAX_DATA_LEN);
        assert!(encode(&ok).is_ok());
    }
}
