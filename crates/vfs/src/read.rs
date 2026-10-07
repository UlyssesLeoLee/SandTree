//! Read window planning (DD-SW §7: reads support offset/length; large files are
//! never fully buffered by default).

use crate::error::UriError;

/// A byte range to read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadWindow {
    /// Start offset in bytes.
    pub offset: u64,
    /// Number of bytes to read.
    pub length: u64,
}

impl ReadWindow {
    /// End offset (exclusive) after clamping.
    pub fn end(&self) -> u64 {
        self.offset.saturating_add(self.length)
    }
}

/// Default per-file read cap (4 MiB) — matches the observation per-domain cap so
/// file reads and collector output share one budget (DD-SW §12.3).
pub const DEFAULT_MAX_SINGLE_FILE: u64 = 4 * 1024 * 1024;
/// Default per-request total cap.
pub const DEFAULT_MAX_TOTAL_BYTES: u64 = 8 * 1024 * 1024;

/// Plan a read, clamped by the caller's quotas.
///
/// `length = None` means "to end of file", which is then clamped by
/// `max_total_bytes`. A request that exceeds `max_single_file` is rejected
/// outright rather than silently truncated: silently returning half a file is
/// how a diff silently compares different content.
pub fn plan_read(
    offset: u64,
    length: Option<u64>,
    file_size: u64,
    max_single_file: u64,
    max_total_bytes: u64,
) -> Result<ReadWindow, UriError> {
    if offset > file_size {
        return Err(UriError::TooLong(offset as usize));
    }
    if file_size > max_single_file {
        return Err(UriError::TooLong(file_size as usize));
    }
    let remaining = file_size - offset;
    let requested = length.unwrap_or(remaining);
    let clamped = requested.min(remaining).min(max_total_bytes);
    if clamped == 0 && remaining > 0 {
        return Err(UriError::TooLong(0));
    }
    Ok(ReadWindow {
        offset,
        length: clamped,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const M: u64 = DEFAULT_MAX_SINGLE_FILE;
    const T: u64 = DEFAULT_MAX_TOTAL_BYTES;

    #[test]
    fn explicit_length_within_bounds() {
        let w = plan_read(0, Some(10), 100, M, T).unwrap();
        assert_eq!(
            w,
            ReadWindow {
                offset: 0,
                length: 10
            }
        );
        assert_eq!(w.end(), 10);
    }

    #[test]
    fn length_none_reads_to_end() {
        let w = plan_read(10, None, 100, M, T).unwrap();
        assert_eq!(
            w,
            ReadWindow {
                offset: 10,
                length: 90
            }
        );
    }

    #[test]
    fn length_is_clamped_to_file_end() {
        let w = plan_read(0, Some(500), 100, M, T).unwrap();
        assert_eq!(w.length, 100);
    }

    #[test]
    fn offset_beyond_eof_is_rejected() {
        assert!(plan_read(101, Some(1), 100, M, T).is_err());
        assert!(plan_read(100, Some(1), 100, M, T).is_ok());
    }

    #[test]
    fn oversized_file_is_rejected_not_truncated() {
        let e = plan_read(0, Some(1), M + 1, M, T).unwrap_err();
        assert!(matches!(e, UriError::TooLong(_)));
    }

    #[test]
    fn total_budget_clamps_an_otherwise_valid_read() {
        let w = plan_read(0, None, M, M, 1024).unwrap();
        assert_eq!(w.length, 1024);
    }

    #[test]
    fn empty_file_yields_empty_window() {
        let w = plan_read(0, Some(10), 0, M, T).unwrap();
        assert_eq!(w.length, 0);
    }
}
