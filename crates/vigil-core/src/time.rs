//! Timestamp convention.
//!
//! Every `i64` timestamp in Vigil (`Event::ts`, `ProcessInfo::start_time`,
//! `FileInfo::first_seen`, store columns) is **milliseconds since the Unix
//! epoch, UTC**.

use std::time::{SystemTime, UNIX_EPOCH};

pub const MS_PER_SEC: i64 = 1_000;
pub const MS_PER_HOUR: i64 = 60 * 60 * MS_PER_SEC;
pub const MS_PER_DAY: i64 = 24 * MS_PER_HOUR;

/// Current wall-clock time in Unix milliseconds.
///
/// A clock set before 1970 yields 0 rather than panicking.
pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn now_is_after_2024() {
        // 2024-01-01T00:00:00Z
        assert!(now_ms() > 1_704_067_200_000);
    }

    #[test]
    fn constants_are_consistent() {
        assert_eq!(MS_PER_DAY, 86_400_000);
        assert_eq!(MS_PER_HOUR * 24, MS_PER_DAY);
    }
}
