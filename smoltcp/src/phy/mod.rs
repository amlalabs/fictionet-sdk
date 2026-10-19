//! In-memory IP devices and their packet tokens.

use crate::time::Instant;

/// Limits of an IP packet device.
#[derive(Debug, Clone, Default)]
pub struct DeviceCapabilities {
    /// Maximum size of an emitted IP packet, including its header.
    pub max_transmission_unit: usize,
}

/// An interface for sending and receiving raw network frames.
///
/// The interface is based on _tokens_, which are types that allow to receive/transmit a
/// single packet. The `receive` and `transmit` functions only construct such tokens, the
/// real sending/receiving operation are performed when the tokens are consumed.
pub trait Device {
    type RxToken<'a>: RxToken
    where
        Self: 'a;
    type TxToken<'a>: TxToken
    where
        Self: 'a;

    /// Construct a token pair consisting of one receive token and one transmit token.
    ///
    /// The transmit token allows an immediate TCP reply.
    ///
    /// The timestamp must be a number of milliseconds, monotonically increasing since an
    /// arbitrary moment in time, such as system startup.
    fn receive(&mut self, timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)>;

    /// Construct a transmit token.
    ///
    /// The timestamp must be a number of milliseconds, monotonically increasing since an
    /// arbitrary moment in time, such as system startup.
    fn transmit(&mut self, timestamp: Instant) -> Option<Self::TxToken<'_>>;

    /// Get a description of device capabilities.
    fn capabilities(&self) -> DeviceCapabilities;
}

/// A token to receive a single network packet.
pub trait RxToken {
    /// Consumes the token to receive a single network packet.
    ///
    /// This method receives a packet and then calls the given closure `f` with the raw
    /// packet bytes as argument.
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R;
}

/// A token to transmit a single network packet.
pub trait TxToken {
    /// Consumes the token to send a single network packet.
    ///
    /// This method constructs a transmit buffer of size `len` and calls the passed
    /// closure `f` with a mutable reference to that buffer. The closure should construct
    /// a valid network packet (e.g. an IP packet) in the buffer. When the closure
    /// returns, the transmit buffer is sent out.
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R;
}
