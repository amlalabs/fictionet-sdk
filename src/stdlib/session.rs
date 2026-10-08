//! What caller-driven protocol sessions hand back: messages to send and
//! events to act on, in order.
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
