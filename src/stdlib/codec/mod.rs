//! Bounded byte decoders, wire values, and the driver that runs them.
//! [`Reader`] checks byte reads and keeps its position on truncation.
//!
//! A [`Decode`] reads a slice and returns a [`Step`]. It owns state, but
//! never keeps unread input. [`Stream`] owns that input in one [`Buffer`].
//! [`pump`] accepts chunks and reports the accepted count. [`finish`] marks EOF.
//! After `End`, use [`Stream::swap`] and push the unaccepted slice to it.
//! Buffered unread bytes are kept for the new decoder. Direct [`Stream::push`]
//! takes and drops new bytes after EOF or completion.
//! Errors are returned once and kept by [`Stream::failed`]. Driving a stream
//! requires a cloneable error so both the caller and stream can own it.
//!
//! [`Wire`] reads one complete value and writes it without changing its
//! meaning. [`Map`] interprets each item, [`Assemble`] joins fragments, and
//! [`Pipe`] feeds selected outer payloads into an inner decoder. [`Lines`]
//! and [`Collect`] cover lines and values that end at EOF. [`Frames<T>`]
//! frames values through their [`Prefixed`] parser and protocol limits. [`Spans`] records
//! bounded provenance; [`Demux`] shares a budget across keyed streams.
//!
//! This module uses only `core` and `alloc`. No function here performs
//! I/O, reads a clock, or uses global state. The driver that runs a
//! decoder over a connection is [`serve`](super::serve), outside this
//! module. [`Interceptor`], [`Recorder`], and [`Faults`] operate on any
//! decoder's items and original bytes.
//!
//! ```
//! use fictionet::stdlib::codec::{Decode, Step, Stream, pump, finish};
//! use core::convert::Infallible;
//!
//! struct Bytes;
//! impl Decode for Bytes {
//!     type Item = u8;
//!     type Error = Infallible;
//!     const NAME: &'static str = "bytes";
//!     fn capacity(&self) -> usize { 8 }
//!     fn decode(&mut self, input: &[u8], _: bool) -> Result<Step<u8>, Infallible> {
//!         Ok(match input.first() {
//!             Some(b) => Step::Item(*b, 1),
//!             None => Step::Need,
//!         })
//!     }
//! }
//! let mut stream = Stream::new(Bytes);
//! let mut items = Vec::new();
//! pump(&mut stream, b"hello", |b| items.push(b))?;
//! finish(&mut stream, |b| items.push(b))?;
//! assert_eq!(items, b"hello");
//! assert!(stream.is_done());
//! # Ok::<(), fictionet::stdlib::codec::Fail<Infallible>>(())
//! ```
//!
//! A two-layer pipe can join payloads across outer item boundaries:
//!
//! ```
//! use fictionet::stdlib::codec::{Carry, Collect, Ending, Layered, Lines, Pipe,
//!     Stream, Wire, finish, pump};
//! use core::convert::Infallible;
//!
//! #[derive(Debug, PartialEq)]
//! struct Body(Vec<u8>);
//! impl Wire for Body {
//!     type ParseError = Infallible;
//!     type WriteError = Infallible;
//!     fn parse(b: &[u8]) -> Result<Self, Infallible> { Ok(Self(b.to_vec())) }
//!     fn write(&self, out: &mut Vec<u8>) -> Result<(), Infallible> {
//!         out.extend_from_slice(&self.0);
//!         Ok(())
//!     }
//! }
//! let pipe = Pipe::new(Lines::new(8, Ending::LfOrCrlf), Collect::<Body>::new(16),
//!     |line| match line { Ok(b) => Carry::Bytes(b), err => Carry::Through(err) });
//! let mut stream = Stream::new(pipe);
//! let mut items = Vec::new();
//! pump(&mut stream, b"hel\nlo\n", |item| items.push(item))?;
//! finish(&mut stream, |item| items.push(item))?;
//! assert_eq!(items, vec![Layered::Inner(Body(b"hello".to_vec()))]);
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```
//!
//! # Errors and names in a codec module
//!
//! Every protocol module in [`stdlib`](super) follows these rules, and a
//! copy you own reads best if it keeps them.
//!
//! - **E1.** A module has one `pub enum Error`. It is the `ParseError` and
//!   `WriteError` of each [`Wire`] type, the [`Decode::Error`] of each
//!   decoder, and the `E` in an `Item = Result<T, E>`. Its variants name
//!   the clause of the specification. A writer that cannot fail uses
//!   [`Infallible`](core::convert::Infallible). An item fault that must
//!   carry more than the reason, such as the header a reply needs, is a
//!   struct named for the fault that holds the module's `Error`
//!   (`fix::FieldFault`, `diameter::AvpFault`).
//! - **E2.** A decoder that yields `Result<Unit, Error>`, so a bad unit
//!   does not end the stream, reports the fault that does end it as
//!   `FrameError`, its `Decode::Error`. A module without that split has
//!   no `FrameError`.
//! - **E3.** An error the peer sends is a wire value and keeps the
//!   protocol's word: `modbus::Exception`, `grpc::Status`,
//!   `kerberos::KrbError`. E1 does not count it.
//! - **E4.** No `DecodeError`, `EncodeError`, `ParseError`, `WireError`,
//!   `<Unit>ParseError`, `<Unit>Error`, `<Module>Error`, `Malformed` or
//!   `Unwritable`.
//! - **E5.** The wrappers are this module's: [`Fail`], [`PumpError`],
//!   [`CollectError`], [`AssembleError`], [`PipeError`], [`LineError`],
//!   [`InterceptError`], [`RewriteError`] and [`FaultError`]. A protocol
//!   module adds none. An error that wraps another returns it from
//!   [`source`](core::error::Error::source), and its `Display` says only its own
//!   context, never the inner error's text, so
//!   [`ErrorChain`](crate::ErrorChain) shows each message once.
//! - **N1.** A decoder that only frames a [`Wire`] value is [`Frames<T>`],
//!   with [`Prefixed`] implemented on `T`. Other [`Decode`] types are the
//!   plural of their item. A `Result<T, E>` item counts
//!   as `T`. A raw-bytes item takes the protocol's word for its unit. A
//!   decoder that yields one message head and then ends is `Head`.
//! - **N2.** A [`Wire`] type takes the specification's word for its unit,
//!   with no module prefix: `rtp::Packet`, not `rtp::RtpPacket`. Names the
//!   specification gives (`LdapResult`) stay, and so do prefixed names
//!   whose bare form clashes with the prelude (`CoapOption`).
//! - **N3.** With one decoder for each direction, the items carry the side
//!   and the decoders follow N1 (`ClientMessage`, `ClientMessages`). When
//!   both directions yield the same item, one decoder has a constructor
//!   for each side (`Frames::client_side()`).
//! - **N4.** A state machine for one side of a protocol is `Client` or
//!   `Server`, one that plays either side is `Session`, and its progress
//!   enum is `Phase`. `Connection` names only the byte-stream trait. A
//!   session fed bytes uses [`Stream`]'s verbs (`push`, `next`, `end`); one
//!   fed messages uses `receive`, `send` and `tick`.
//! - **N5.** A [`Service`](super::serve::Service) is named for what it
//!   serves, with no suffix. Its associated types are `Decoder` and
//!   `State`.
//! - **N6.** [`Present`](crate::observe::Present) is implemented on the
//!   decoder it presents.

extern crate alloc;

use alloc::vec::Vec;

pub mod ascii;
pub mod base64;
pub mod civil;
pub mod crc32c;
pub mod field;
pub mod leb128;
pub mod head_body;
mod buffer;
mod combinators;
pub mod contract;
mod demux;
mod faults;
mod frames;
mod interceptor;
mod lcg;
mod work;
mod pipe;
mod reader;
mod layout;
pub use crate::layout;
mod recorder;
mod stream;
pub mod test_support;

pub use buffer::Buffer;
pub use combinators::{
    Assemble, AssembleError, Assembled, Collect, CollectError, Ending, Fragment, LineError, Lines,
    Map,
};
pub use demux::Demux;
pub use frames::{Frames, Prefixed};
pub use faults::{ByteFault, FaultDelay, FaultError, Faults, ItemFault, Rule, Trigger};
pub use interceptor::{
    InterceptError, Interceptor, Rewrite, RewriteError, SkipPolicy, append_bounded, write_bounded,
};
pub use lcg::Lcg;
pub use work::Work;
pub use pipe::{Carry, DEFAULT_SPANS, Layered, Pipe, PipeError, Span, Spans};
pub use reader::{Reader, Trailing, Truncated, be16, be24, be32, be64, le16, le24, le32, le64};
pub use recorder::{Direction, Record, RecordKind, Recorder};
pub use stream::{Fail, PumpError, Stream, StreamEvent, finish, pump, try_pump};

/// A refused codec operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// A charge exceeds the finite work allowance.
    Work {
        /// The allowance's name.
        name: &'static str,
        /// The maximum work allowed.
        limit: usize,
        /// Work already charged.
        used: usize,
        /// The refused charge, saturated on product overflow.
        charge: usize,
    },
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Work { name, limit, used, charge } =>
                write!(f, "{name}: work charge {charge} exceeds allowance {limit} with {used} used"),
        }
    }
}
impl core::error::Error for Error {}

/// The result of one call to [`Decode::decode`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step<T> {
    /// One item and the number of input bytes consumed from the start.
    /// A zero count releases an item from previously held state.
    Item(T, usize),
    /// Bytes belonging to no item. Zero counts must make finite state progress.
    Skip(usize),
    /// More input is needed. No bytes were consumed.
    Need,
    /// No more items. The unread suffix belongs to the next decoder.
    End,
}

/// A decoder that borrows all unread input for each call.
///
/// Counts must not exceed the input length. `Need` must not grow held
/// state or change later results. Chunk boundaries must not change items.
/// At capacity, a call must progress or fail. After a call, the capacity
/// must be at least the length of the input that call read, consumed bytes
/// included. So a decoder lowers its capacity only on a call whose input
/// fits the new value. Zero-byte steps must finish
/// work bounded by held state within each `next` call. Composite steps can
/// move or expand that state. Each step need not reduce [`held`](Self::held).
/// EOF must terminate. An error is terminal. Driving a stream requires
/// `Self::Error: Clone`. Modes change only between items.
/// See [`contract`] for executable checks.
pub trait Decode {
    /// An owned decoded unit. Recoverable unit errors belong here.
    type Item;
    /// A fault that ends framing of this stream. It owns its details, so
    /// a wrapper can return it from [`source`](core::error::Error::source).
    type Error: core::error::Error + 'static;
    /// A short name for logs and observation layers.
    const NAME: &'static str;
    /// The most unread bytes needed to make progress or report an error.
    /// This must fit within [`Buffer::MAX_LIMIT`]. After each call it must
    /// be at least the length of the input that call read.
    fn capacity(&self) -> usize;
    /// Reads the stable unread suffix. `eof` means no more bytes will arrive.
    fn decode(&mut self, input: &[u8], eof: bool) -> Result<Step<Self::Item>, Self::Error>;
    /// Bytes held outside the input buffer, under the decoder's named limit.
    fn held(&self) -> usize {
        0
    }
    /// Applies `f` to each item without changing framing.
    fn map<U, F: FnMut(Self::Item) -> U>(self, f: F) -> Map<Self, F>
    where
        Self: Sized,
    {
        Map::new(self, f)
    }
}

/// A complete wire value with an exact parser and a strict writer.
///
/// Implementations must bound values by named limits. Successful writes
/// must parse as the same value. An unsuccessful write must leave the
/// destination unchanged. Context-dependent formats use ordinary functions.
pub trait Wire: Sized {
    /// Why a complete byte slice is not a value. Owned, like
    /// [`Decode::Error`].
    type ParseError: core::error::Error + 'static;
    /// Why a value cannot be represented on the wire. Owned, like
    /// [`Decode::Error`].
    type WriteError: core::error::Error + 'static;
    /// Reads all bytes. Trailing bytes are an error.
    fn parse(b: &[u8]) -> Result<Self, Self::ParseError>;
    /// Appends the value's bytes, leaving `out` unchanged on error.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Self::WriteError>;
    /// Writes into a new vector, bounded by this type's named limits.
    fn to_bytes(&self) -> Result<Vec<u8>, Self::WriteError> {
        let mut out = Vec::new();
        self.write(&mut out)?;
        Ok(out)
    }
}

/// Rounds a byte length up to a multiple of four; `len` must be at most `usize::MAX - 3`.
#[inline]
pub fn pad_to_4(len: usize) -> usize {
    (len + 3) & !3
}

#[cfg(test)]
mod tests;
