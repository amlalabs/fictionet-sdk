//! Simulation instants and durations in microseconds.

use core::ops;

/// A representation of an absolute time value.
///
/// The `Instant` type is a wrapper around a `i64` value that
/// represents a number of microseconds, monotonically increasing
/// since an arbitrary moment in time, such as system startup.
///
/// * A value of `0` is inherently arbitrary.
/// * A value less than `0` indicates a time before the starting
///   point.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Instant {
    micros: i64,
}

impl Instant {
    pub(crate) const ZERO: Instant = Instant { micros: 0 };

    /// Create a new `Instant` from a number of microseconds.
    pub fn from_micros<T: Into<i64>>(micros: T) -> Instant {
        Instant {
            micros: micros.into(),
        }
    }

    /// Create a new `Instant` from a number of milliseconds.
    pub fn from_millis<T: Into<i64>>(millis: T) -> Instant {
        Instant {
            micros: millis.into() * 1000,
        }
    }

    /// Create a new `Instant` from a number of seconds.
    pub(crate) fn from_secs<T: Into<i64>>(secs: T) -> Instant {
        Instant {
            micros: secs.into() * 1000000,
        }
    }

    /// The total number of microseconds since the clock origin.
    pub const fn total_micros(&self) -> i64 {
        self.micros
    }
}

impl ops::Add<Duration> for Instant {
    type Output = Instant;

    fn add(self, rhs: Duration) -> Instant {
        Instant::from_micros(self.micros + rhs.total_micros() as i64)
    }
}

impl ops::Sub<Duration> for Instant {
    type Output = Instant;

    fn sub(self, rhs: Duration) -> Instant {
        Instant::from_micros(self.micros - rhs.total_micros() as i64)
    }
}

impl ops::Sub<Instant> for Instant {
    type Output = Duration;

    fn sub(self, rhs: Instant) -> Duration {
        Duration::from_micros(self.micros.abs_diff(rhs.micros))
    }
}

/// A relative amount of time.
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Duration {
    micros: u64,
}

impl Duration {
    /// Create a new `Duration` from a number of microseconds.
    pub(crate) const fn from_micros(micros: u64) -> Duration {
        Duration { micros }
    }

    /// Create a new `Duration` from a number of milliseconds.
    pub const fn from_millis(millis: u64) -> Duration {
        Duration {
            micros: millis * 1000,
        }
    }

    /// Create a new `Duration` from a number of seconds.
    pub const fn from_secs(secs: u64) -> Duration {
        Duration {
            micros: secs * 1000000,
        }
    }

    /// The total number of milliseconds in this `Duration`.
    pub(crate) const fn total_millis(&self) -> u64 {
        self.micros / 1000
    }

    /// The total number of microseconds in this `Duration`.
    const fn total_micros(&self) -> u64 {
        self.micros
    }
}

impl ops::Add<Duration> for Duration {
    type Output = Duration;

    fn add(self, rhs: Duration) -> Duration {
        Duration::from_micros(self.micros + rhs.total_micros())
    }
}

impl ops::AddAssign<Duration> for Duration {
    fn add_assign(&mut self, rhs: Duration) {
        self.micros += rhs.total_micros();
    }
}

impl ops::Sub<Duration> for Duration {
    type Output = Duration;

    fn sub(self, rhs: Duration) -> Duration {
        Duration::from_micros(
            self.micros
                .checked_sub(rhs.total_micros())
                .expect("overflow when subtracting durations"),
        )
    }
}

impl ops::SubAssign<Duration> for Duration {
    fn sub_assign(&mut self, rhs: Duration) {
        self.micros = self
            .micros
            .checked_sub(rhs.total_micros())
            .expect("overflow when subtracting durations");
    }
}

impl ops::Mul<u32> for Duration {
    type Output = Duration;

    fn mul(self, rhs: u32) -> Duration {
        Duration::from_micros(self.micros * rhs as u64)
    }
}

impl ops::MulAssign<u32> for Duration {
    fn mul_assign(&mut self, rhs: u32) {
        self.micros *= rhs as u64;
    }
}

impl ops::Div<u32> for Duration {
    type Output = Duration;

    fn div(self, rhs: u32) -> Duration {
        Duration::from_micros(self.micros / rhs as u64)
    }
}

impl ops::DivAssign<u32> for Duration {
    fn div_assign(&mut self, rhs: u32) {
        self.micros /= rhs as u64;
    }
}

impl From<::core::time::Duration> for Duration {
    fn from(other: ::core::time::Duration) -> Duration {
        Duration::from_micros(other.as_secs() * 1000000 + other.subsec_micros() as u64)
    }
}

impl From<Duration> for ::core::time::Duration {
    fn from(val: Duration) -> Self {
        ::core::time::Duration::from_micros(val.total_micros())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_instant_difference_across_signed_range() {
        let first = Instant::from_micros(i64::MIN);
        let last = Instant::from_micros(i64::MAX);
        assert_eq!(last - first, Duration::from_micros(u64::MAX));
        assert_eq!(first - last, Duration::from_micros(u64::MAX));
    }

    #[test]
    fn test_instant_ops() {
        assert_eq!(
            Instant::from_millis(4) + Duration::from_millis(6),
            Instant::from_millis(10)
        );
        assert_eq!(
            Instant::from_millis(7) - Duration::from_millis(5),
            Instant::from_millis(2)
        );
    }

    #[test]
    fn test_duration_ops() {
        assert_eq!(
            Duration::from_millis(40) + Duration::from_millis(2),
            Duration::from_millis(42)
        );
        assert_eq!(
            Duration::from_millis(555) - Duration::from_millis(42),
            Duration::from_millis(513)
        );
        assert_eq!(Duration::from_millis(13) * 22, Duration::from_millis(286));
        assert_eq!(Duration::from_millis(53) / 4, Duration::from_micros(13250));
    }

    #[test]
    fn test_duration_assign_ops() {
        let mut duration = Duration::from_millis(4735);
        duration += Duration::from_millis(1733);
        assert_eq!(duration, Duration::from_millis(6468));
        duration -= Duration::from_millis(1234);
        assert_eq!(duration, Duration::from_millis(5234));
        duration *= 4;
        assert_eq!(duration, Duration::from_millis(20936));
        duration /= 5;
        assert_eq!(duration, Duration::from_micros(4187200));
    }

    #[test]
    #[should_panic(expected = "overflow when subtracting durations")]
    fn test_sub_from_zero_overflow() {
        let _ = Duration::from_millis(0) - Duration::from_millis(1);
    }

    #[test]
    #[should_panic(expected = "attempt to divide by zero")]
    fn test_div_by_zero() {
        let _ = Duration::from_millis(4) / 0;
    }

    #[test]
    fn test_duration_getters() {
        let instant = Duration::from_millis(4934);
        assert_eq!(instant.total_millis(), 4934);
    }

    #[test]
    fn test_duration_conversions() {
        let mut std_duration = ::core::time::Duration::from_millis(4934);
        let duration: Duration = std_duration.into();
        assert_eq!(duration, Duration::from_millis(4934));
        assert_eq!(Duration::from(std_duration), Duration::from_millis(4934));

        std_duration = duration.into();
        assert_eq!(std_duration, ::core::time::Duration::from_millis(4934));
    }
}
