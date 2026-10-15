//! Passive mechanics for caller-driven protocol sessions: ordered actions
//! and a clock advanced by the caller.
//!
//! The sessions of [`fix`](super::fix), [`soupbintcp`](super::soupbintcp),
//! [`moldudp64`](super::moldudp64), [`ouch`](super::ouch) and
//! [`cboe_boe`](super::cboe_boe) return a `Vec` of [`Action`]s from each call.
//! This module does no I/O, reads no clock and runs no timers.

/// A session's ordered output. Send messages before acting on later events.
///
/// ```
/// use fictionet::stdlib::session::Action;
///
/// let actions = [Action::Send(vec![1, 2]), Action::Event("ready")];
/// assert_eq!(actions[0].clone(), Action::Send(vec![1, 2]));
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action<W, E> {
    /// A message for the caller to send.
    Send(W),
    /// A notification for the caller.
    Event(E),
}

/// A fault in caller-supplied session time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The supplied time is earlier than the clock's current time.
    Time,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Time => f.write_str("time went backwards"),
        }
    }
}

impl core::error::Error for Error {}

/// A passive clock with start, receive and send marks.
///
/// All timestamps are caller-supplied milliseconds on one monotonic timeline.
/// Equal timestamps are allowed. The full `u64` range is accepted; time must
/// not wrap. Marks use the current time, and elapsed queries subtract a mark
/// from that time with saturating arithmetic.
///
/// This clock reads no system clock and schedules no work. The caller chooses
/// when to mark activity, which limits to compare against elapsed time, and
/// what to do at a deadline. Copies advance independently.
///
/// ```
/// use fictionet::stdlib::session::Clock;
///
/// let mut clock = Clock::new(100);
/// clock.advance(150)?;
/// clock.mark_sent();
/// clock.advance(200)?;
/// assert_eq!(clock.elapsed_ms(), 100);
/// assert_eq!(clock.sent_elapsed_ms(), 50);
/// assert_eq!(clock.received_elapsed_ms(), 100);
/// # Ok::<(), fictionet::stdlib::session::Error>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Clock {
    now: u64,
    since: u64,
    received: u64,
    sent: u64,
}

impl Clock {
    /// Starts a clock with all three marks at `now_ms`.
    pub fn new(now_ms: u64) -> Self {
        Self {
            now: now_ms,
            since: now_ms,
            received: now_ms,
            sent: now_ms,
        }
    }

    /// Advances the current time without changing any marks.
    /// Returns [`Error::Time`] without changing the clock if time goes backwards.
    pub fn advance(&mut self, now_ms: u64) -> Result<(), Error> {
        if now_ms < self.now {
            return Err(Error::Time);
        }
        self.now = now_ms;
        Ok(())
    }

    /// Resets the start mark to the current time, leaving activity marks alone.
    pub fn mark_start(&mut self) {
        self.since = self.now;
    }

    /// Marks a received message at the current time.
    pub fn mark_received(&mut self) {
        self.received = self.now;
    }

    /// Marks a sent message at the current time.
    pub fn mark_sent(&mut self) {
        self.sent = self.now;
    }

    /// Milliseconds since creation or the last [`Self::mark_start`].
    pub fn elapsed_ms(&self) -> u64 {
        self.now.saturating_sub(self.since)
    }

    /// Milliseconds since creation or the last [`Self::mark_received`].
    pub fn received_elapsed_ms(&self) -> u64 {
        self.now.saturating_sub(self.received)
    }

    /// Milliseconds since creation or the last [`Self::mark_sent`].
    pub fn sent_elapsed_ms(&self) -> u64 {
        self.now.saturating_sub(self.sent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marks_are_independent() {
        let mut clock = Clock::new(100);
        assert_eq!(clock.elapsed_ms(), 0);
        assert_eq!(clock.received_elapsed_ms(), 0);
        assert_eq!(clock.sent_elapsed_ms(), 0);
        clock.advance(120).unwrap();
        clock.mark_sent();
        clock.advance(130).unwrap();
        clock.mark_received();
        clock.advance(140).unwrap();
        clock.mark_start();
        clock.advance(150).unwrap();
        assert_eq!(clock.elapsed_ms(), 10);
        assert_eq!(clock.received_elapsed_ms(), 20);
        assert_eq!(clock.sent_elapsed_ms(), 30);
    }

    #[test]
    fn backwards_time_leaves_clock_unchanged() {
        let mut clock = Clock::new(100);
        clock.advance(120).unwrap();
        clock.mark_received();
        let before = clock;
        assert_eq!(clock.advance(119), Err(Error::Time));
        assert_eq!(clock, before);
        clock.advance(120).unwrap();
        assert_eq!(clock, before);
        clock.advance(121).unwrap();
        assert_eq!(clock.received_elapsed_ms(), 1);
        assert_eq!(before.received_elapsed_ms(), 0);
    }

    #[test]
    fn full_timestamp_range_does_not_wrap() {
        let mut clock = Clock::new(0);
        clock.advance(u64::MAX).unwrap();
        assert_eq!(clock.elapsed_ms(), u64::MAX);
        assert_eq!(clock.received_elapsed_ms(), u64::MAX);
        assert_eq!(clock.sent_elapsed_ms(), u64::MAX);
        clock.mark_start();
        clock.mark_received();
        clock.mark_sent();
        assert_eq!(clock.elapsed_ms(), 0);
        assert_eq!(clock.received_elapsed_ms(), 0);
        assert_eq!(clock.sent_elapsed_ms(), 0);
        let before = clock;
        assert_eq!(clock.advance(0), Err(Error::Time));
        assert_eq!(clock, before);
    }
}
