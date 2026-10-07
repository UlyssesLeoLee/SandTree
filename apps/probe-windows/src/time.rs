//! Minimal UTC timestamp formatting.
//!
//! The probe is a single-purpose binary that ships into a sandbox, so it avoids
//! pulling a date-time crate in for one formatted string. The algorithm is
//! Howard Hinnant's `civil_from_days`, the same one the rest of the workspace
//! uses, so probe output is byte-comparable with host output.

/// Format epoch seconds as RFC3339.
pub fn format_rfc3339(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        sod / 3600,
        (sod % 3600) / 60,
        sod % 60
    )
}

/// Days since the Unix epoch to a civil `(year, month, day)`.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_instants_format_correctly() {
        assert_eq!(format_rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_rfc3339(1), "1970-01-01T00:00:01Z");
        assert_eq!(format_rfc3339(86_399), "1970-01-01T23:59:59Z");
        assert_eq!(format_rfc3339(86_400), "1970-01-02T00:00:00Z");
    }

    #[test]
    fn leap_days_are_handled() {
        // 2000-02-29 (a leap year) and 2001-03-01 (the day after a common
        // February) bracket the rule.
        assert_eq!(format_rfc3339(951_782_400), "2000-02-29T00:00:00Z");
        // 2001-01-01 is 978_307_200; 2001 is not a leap year, so 59 days later
        // is 1 March.
        assert_eq!(format_rfc3339(978_307_200), "2001-01-01T00:00:00Z");
        assert_eq!(
            format_rfc3339(978_307_200 + 59 * 86_400),
            "2001-03-01T00:00:00Z"
        );
    }

    #[test]
    fn pre_epoch_instants_stay_valid() {
        // Negative seconds must not wrap; a signed envelope from a guest with a
        // skewed clock is still parseable.
        assert_eq!(format_rfc3339(-1), "1969-12-31T23:59:59Z");
    }
}
