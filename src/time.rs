//! Times as the files hold them: Windows FILETIMEs (UTC, 100 ns) in detection history files, and
//! the protection logs' text times: UTC (`Z` or an offset), or a clock whose zone the line doesn't
//! say.

use std::fmt::{self, Write};

/// 100 ns ticks per second.
const TICKS_PER_SECOND: i64 = 10_000_000;
/// Days from 0001-01-01 (proleptic Gregorian) to 1601-01-01.
const DAYS_TO_1601: i64 = 584_388;
/// The last FILETIME of 9999-12-31, as .NET and Eric Zimmerman's tools allow.
const MAX_FILETIME: u64 = 2_650_467_743_999_999_999;

/// How precisely a time was written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Precision {
    /// Whole seconds.
    Second,
    /// Milliseconds.
    Millisecond,
    /// 100 ns (a FILETIME).
    Tick,
}

/// A point in time: 100 ns ticks since 1601-01-01 (a FILETIME's scale), and whether it is UTC or
/// a clock whose zone isn't known.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Time {
    ticks: i64,
    utc: bool,
    precision: Precision,
}

impl Time {
    /// A FILETIME (UTC); `None` for 0 and for values past 9999-12-31.
    #[must_use]
    pub fn from_filetime(value: u64) -> Option<Self> {
        (value != 0 && value <= MAX_FILETIME).then_some(Self {
            ticks: value as i64,
            utc: true,
            precision: Precision::Tick,
        })
    }

    /// A calendar time, UTC or in a zone not known, to the precision given.
    pub(crate) fn from_parts(
        date: (i64, u32, u32),
        clock: (u32, u32, u32),
        ticks: i64,
        utc: bool,
        precision: Precision,
    ) -> Option<Self> {
        let (year, month, day) = date;
        let (hour, minute, second) = clock;
        if !(1601..=9999).contains(&year)
            || !(1..=12).contains(&month)
            || day == 0
            || day > days_in_month(year, month)
            || hour > 23
            || minute > 59
            || second > 59
            || !(0..TICKS_PER_SECOND).contains(&ticks)
        {
            return None;
        }
        let days = days_from_civil(year, month, day) - DAYS_TO_1601;
        let seconds = days * 86_400 + i64::from(hour) * 3600 + i64::from(minute) * 60;
        Some(Self {
            ticks: (seconds + i64::from(second)) * TICKS_PER_SECOND + ticks,
            utc,
            precision,
        })
    }

    /// The same time moved by `minutes` (a UTC offset taken off).
    pub(crate) fn shifted(self, minutes: i64) -> Option<Self> {
        let ticks = self
            .ticks
            .checked_add(minutes.checked_mul(60 * TICKS_PER_SECOND)?)?;
        (ticks >= 0).then_some(Self { ticks, ..self })
    }

    /// The same clock reading, as UTC.
    pub(crate) fn as_utc(self) -> Self {
        Self { utc: true, ..self }
    }

    /// 100 ns ticks since 1601-01-01 (as a FILETIME), whatever the zone.
    #[must_use]
    pub fn filetime(self) -> u64 {
        self.ticks as u64
    }

    /// Whether it is UTC (else a clock whose zone isn't known).
    #[must_use]
    pub fn is_utc(self) -> bool {
        self.utc
    }

    /// How precisely it was written.
    #[must_use]
    pub fn precision(self) -> Precision {
        self.precision
    }

    /// Seconds since 1970-01-01 and the nanoseconds after them.
    #[must_use]
    pub fn unix(self) -> (i64, u32) {
        let since_1970 = self.ticks - 116_444_736_000_000_000;
        (
            since_1970.div_euclid(TICKS_PER_SECOND),
            (since_1970.rem_euclid(TICKS_PER_SECOND) * 100) as u32,
        )
    }

    /// ISO 8601 to its precision: `2021-07-22T15:38:04.557Z`; without the `Z` when the zone isn't
    /// known.
    #[must_use]
    pub fn to_iso8601(self) -> String {
        let seconds = self.ticks.div_euclid(TICKS_PER_SECOND);
        let fraction = self.ticks.rem_euclid(TICKS_PER_SECOND);
        let (year, month, day) = civil_from_days(seconds.div_euclid(86_400) + DAYS_TO_1601);
        let rest = seconds.rem_euclid(86_400);
        let mut text = format!(
            "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}",
            rest / 3600,
            rest % 3600 / 60,
            rest % 60
        );
        match self.precision {
            Precision::Second => {}
            Precision::Millisecond => {
                let _ = write!(text, ".{:03}", fraction / 10_000);
            }
            Precision::Tick => {
                let _ = write!(text, ".{fraction:07}");
            }
        }
        if self.utc {
            text.push('Z');
        }
        text
    }
}

impl fmt::Display for Time {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_iso8601())
    }
}

fn is_leap(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        2 if is_leap(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days from 0001-01-01 (Howard Hinnant's algorithm, from 0000-03-01).
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let m = i64::from(month);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 306
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 306;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + i64::from(month <= 2), month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filetimes_read_as_utc() {
        let t = Time::from_filetime(133_825_563_062_208_881).unwrap();
        assert_eq!(t.to_iso8601(), "2025-01-28T16:45:06.2208881Z");
        assert_eq!(t.unix(), (1_738_082_706, 220_888_100));
        assert_eq!(Time::from_filetime(0), None);
        assert_eq!(Time::from_filetime(u64::MAX), None);
        assert_eq!(
            Time::from_filetime(MAX_FILETIME).unwrap().to_iso8601(),
            "9999-12-31T23:59:59.9999999Z"
        );
    }

    #[test]
    fn calendar_times_round_trip() {
        for (date, clock) in [
            ((1601, 1, 1), (0, 0, 0)),
            ((2000, 2, 29), (12, 0, 1)),
            ((2024, 12, 31), (23, 59, 59)),
        ] {
            let t = Time::from_parts(date, clock, 5_570_000, true, Precision::Millisecond).unwrap();
            let text = t.to_iso8601();
            assert_eq!(&text[text.len() - 5..], ".557Z", "{text}");
            assert!(text.starts_with(&format!("{:04}-{:02}-{:02}", date.0, date.1, date.2)));
        }
        assert!(Time::from_parts((2023, 2, 29), (0, 0, 0), 0, true, Precision::Second).is_none());
        let local = Time::from_parts((2023, 1, 2), (3, 4, 5), 0, false, Precision::Second).unwrap();
        assert_eq!(local.to_iso8601(), "2023-01-02T03:04:05");
        assert_eq!(
            local.shifted(-90).unwrap().as_utc().to_iso8601(),
            "2023-01-02T01:34:05Z"
        );
    }
}
