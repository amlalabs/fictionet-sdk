//! Bounded byte decoders, wire values, and the driver that runs them.
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
//! and [`Collect`] cover lines and values that end at EOF. [`Spans`] records
//! bounded provenance; [`Demux`] shares a budget across keyed streams.
//!
//! To customize a protocol, copy its module file into your crate and edit it.
//! Keep its `fictionet::stdlib::...` imports. Its [`Decode`] and [`Wire`]
//! implementations work with the same [`Stream`] and combinators.
//!
//! This module uses only `core` and `alloc`. The planned async `serve`
//! adapter lives in stdlib next to [`tcp`](super::tcp), outside this module.
//! No function here performs I/O, reads a clock, or uses global state.
//! [`Interceptor`], [`Recorder`], and [`Faults`] operate on any decoder's
//! items and original bytes. Length prefixes are planned.
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

extern crate alloc;

use alloc::vec::Vec;
use core::error::Error;

mod buffer;
mod combinators;
pub mod contract;
mod demux;
/// Seeded byte and item fault plans with delay markers.
pub mod faults;
/// Exact-byte forwarding and caller-directed replacement.
pub mod interceptor;
/// Small deterministic generator shared by tools and tests.
pub mod lcg;
mod pipe;
/// Bounded transcripts of driver events in both directions.
pub mod recorder;
mod stream;
pub mod test_support;

pub use buffer::Buffer;
pub use combinators::{
    Assemble, AssembleError, Assembled, Collect, CollectError, Ending, Fragment, LineError, Lines,
    Map,
};
pub use demux::Demux;
pub use faults::{ByteFault, FaultAction, Faults, ItemFault, Rule, Trigger};
pub use interceptor::{InterceptError, Interceptor, Rewrite, RewriteError};
pub use lcg::Lcg;
pub use pipe::{Carry, DEFAULT_SPANS, Layered, Pipe, PipeError, Span, Spans};
pub use recorder::{Direction, Record, RecordKind, Recorder};
pub use stream::{Fail, PumpError, Stream, StreamEvent, finish, pump, try_pump};

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
/// At capacity, a call must progress or fail. Zero-byte steps must finish
/// work bounded by held state within each `next` call. Composite steps can
/// move or expand that state. Each step need not reduce [`held`](Self::held).
/// EOF must terminate. An error is terminal. Driving a stream requires
/// `Self::Error: Clone`. Modes change only between items.
/// See [`contract`] for executable checks.
pub trait Decode {
    /// An owned decoded unit. Recoverable unit errors belong here.
    type Item;
    /// A fault that ends framing of this stream.
    type Error: Error;
    /// A short name for logs and observation layers.
    const NAME: &'static str;
    /// The most unread bytes needed to make progress or report an error.
    /// This must fit within [`Buffer::MAX_LIMIT`].
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
    /// Why a complete byte slice is not a value.
    type ParseError: Error;
    /// Why a value cannot be represented on the wire.
    type WriteError: Error;
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

#[cfg(test)]
mod tests;
