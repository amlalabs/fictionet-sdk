use crate::time::Instant;

use super::RttEstimator;

pub(super) mod no_control;

pub(super) mod reno;

pub(super) trait Controller {
    /// Returns the number of bytes that can be sent.
    fn window(&self) -> usize;

    /// Set the remote window size.
    fn set_remote_window(&mut self, _remote_window: usize) {}

    fn on_ack(&mut self, _now: Instant, _len: usize, _in_flight: usize, _rtt: &RttEstimator) {}

    /// Fired on each duplicate ack received, after `on_loss` has been called.
    fn on_dup_ack(&mut self, _now: Instant, _len: usize, _in_flight: usize) {}

    /// Fired on a retransmission timeout.
    fn on_rto(&mut self, _now: Instant, _in_flight: usize) {}

    /// Fired after an inferred loss via three duplicate acks.
    fn on_loss(&mut self, _now: Instant, _in_flight: usize) {}

    fn pre_transmit(&mut self, _now: Instant) {}

    fn post_transmit(&mut self, _now: Instant, _len: usize) {}

    /// Set the maximum segment size.
    fn set_mss(&mut self, _mss: usize) {}
}

#[derive(Debug)]
pub(super) enum AnyController {
    None(no_control::NoControl),

    Reno(reno::Reno),
}

impl AnyController {
    /// Create the Reno congestion controller used by Fictionet.
    #[inline]
    pub fn new() -> Self {
        AnyController::Reno(reno::Reno::new())
    }

    #[inline]
    pub fn inner_mut(&mut self) -> &mut dyn Controller {
        match self {
            AnyController::None(n) => n,

            AnyController::Reno(r) => r,
        }
    }

    #[inline]
    pub fn inner(&self) -> &dyn Controller {
        match self {
            AnyController::None(n) => n,

            AnyController::Reno(r) => r,
        }
    }
}
