//! Timestamps: RFC 3339, UTC, millisecond precision.

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// Now, e.g. `2026-09-27T21:00:00.123Z`.
pub fn now() -> String {
    format(OffsetDateTime::now_utc())
}

/// A Unix time in milliseconds as RFC 3339.
pub fn from_unix_ms(ms: u64) -> String {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(ms) * 1_000_000)
        .map(format)
        .unwrap_or_else(|_| ms.to_string())
}

fn format(at: OffsetDateTime) -> String {
    let at = at
        .replace_nanosecond(at.millisecond() as u32 * 1_000_000)
        .unwrap_or(at);
    at.format(&Rfc3339).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    #[test]
    fn unix_ms_formats_as_utc() {
        assert_eq!(
            super::from_unix_ms(1_700_000_000_000),
            "2023-11-14T22:13:20Z"
        );
        assert_eq!(
            super::from_unix_ms(1_700_000_000_123),
            "2023-11-14T22:13:20.123Z"
        );
    }
}
