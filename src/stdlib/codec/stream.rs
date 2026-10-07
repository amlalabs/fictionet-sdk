use super::{Buffer, Decode, Step};
use core::{error::Error, fmt, ops::Range};

/// Why a stream stopped.
///
/// [`Stuck`](Self::Stuck) is a bug in the decoder. [`Refused`](Self::Refused)
/// is the owner's limit, reached by a decoder that kept its contract.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fail<E> {
    /// A terminal decoder error. [`source`](Error::source) returns it.
    Protocol(E),
    /// EOF left a partial unit in the input buffer.
    Truncated {
        /// Unread input bytes.
        unread: usize,
    },
    /// The decoder broke the [`Decode`] contract: it consumed more than its
    /// input, grew held state across [`Step::Need`], returned `Need` at
    /// capacity, or did not finish its zero-byte steps.
    Stuck {
        /// Unread input bytes at failure.
        unread: usize,
        /// The decoder's stated capacity.
        capacity: usize,
    },
    /// The owner refused more input: a buffer limit, an allocation failure,
    /// a datagram larger than the buffer, or a [`Demux`](super::Demux)
    /// shared budget.
    Refused {
        /// Unread input bytes at failure.
        unread: usize,
        /// The limit that refused the input: the buffer's, or the shared
        /// budget of a `Demux`.
        limit: usize,
    },
}
impl<E: fmt::Display> fmt::Display for Fail<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(_) => f.write_str("the decoder failed"),
            Self::Truncated { unread } => write!(f, "input ended with {unread} unread bytes"),
            Self::Stuck { unread, capacity } => write!(
                f,
                "decoder stuck with {unread} unread bytes (capacity {capacity})"
            ),
            Self::Refused { unread, limit } => write!(
                f,
                "input refused with {unread} unread bytes (limit {limit})"
            ),
        }
    }
}
impl<E: Error + 'static> Error for Fail<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Protocol(e) => Some(e),
            Self::Truncated { .. } | Self::Stuck { .. } | Self::Refused { .. } => None,
        }
    }
}

/// A borrowed observation made before the driver releases bytes.
/// Ranges use this stream's offsets and saturate at `u64::MAX`.
/// Inner items released from held state have empty bytes and ranges.
#[derive(Debug)]
pub enum StreamEvent<'a, T, E> {
    /// A decoded item and exactly the bytes consumed by its step.
    Item {
        /// The decoded value, including recoverable errors represented as items.
        item: &'a T,
        /// Original consumed bytes. These have not been re-encoded.
        bytes: &'a [u8],
        /// Consumed stream coordinates.
        range: Range<u64>,
    },
    /// Bytes consumed without an item. Zero-byte transitions are included.
    Skipped {
        /// Original skipped bytes.
        bytes: &'a [u8],
        /// Skipped stream coordinates.
        range: Range<u64>,
    },
    /// Clean completion, including EOF with no unread bytes.
    Ended {
        /// First unread byte. Any remaining suffix belongs to a handoff.
        offset: u64,
    },
    /// A terminal failure. Reported once, just like the returned error.
    Failed {
        /// The error retained by the stream.
        error: &'a Fail<E>,
        /// The unread bytes at failure. They remain available for handoff.
        bytes: &'a [u8],
        /// Coordinates of those unread bytes.
        range: Range<u64>,
    },
}

/// One decoder and its bounded input buffer.
///
/// A terminal error is returned once. Later calls return no items and
/// [`failed`](Self::failed) retains the error. Driving methods require
/// `D::Error: Clone` to keep an owned copy without changing [`Fail`].
pub struct Stream<D: Decode> {
    pub(super) buf: Buffer,
    pub(super) dec: D,
    pub(super) eof: bool,
    done: bool,
    failed: Option<Fail<D::Error>>,
}
impl<D: Decode> Stream<D> {
    /// Creates a buffer limited to `dec.capacity()`.
    pub fn new(dec: D) -> Self {
        Self::with_buffer(dec, 0)
    }
    /// Creates a buffer at least as large as `dec.capacity()`, up to
    /// [`Buffer::MAX_LIMIT`]. Extra room allows read-ahead for this decoder.
    /// [`swap`](Self::swap) resets the limit to the next decoder's capacity.
    pub fn with_buffer(dec: D, limit: usize) -> Self {
        Self {
            buf: Buffer::new(limit.max(dec.capacity())),
            dec,
            eof: false,
            done: false,
            failed: None,
        }
    }
    /// Adds what fits. After EOF or completion, takes and drops new bytes.
    /// Already buffered bytes remain available for handoff.
    #[must_use = "bytes past the returned count were not taken"]
    pub fn push(&mut self, bytes: &[u8]) -> usize {
        if self.done || self.eof {
            return bytes.len();
        }
        self.sync_limit();
        self.buf.push(bytes)
    }
    /// Offers direct read space. Empty after EOF or completion.
    pub fn spare(&mut self) -> &mut [u8] {
        if self.done || self.eof {
            &mut []
        } else {
            self.sync_limit();
            self.buf.spare()
        }
    }
    /// Commits at most the last spare offer. Does nothing after EOF or
    /// completion. Excess counts are clamped.
    pub fn commit(&mut self, n: usize) {
        if self.done || self.eof {
            return;
        }
        self.buf.commit(n);
    }
    /// Marks EOF. Buffered input is still decoded on subsequent calls.
    pub fn end(&mut self) {
        self.eof = true;
    }
    /// The unread suffix, including bytes left for a handoff.
    pub fn unread(&self) -> &[u8] {
        self.buf.unread()
    }
    /// The offset of the first unread byte, saturating at `u64::MAX`.
    pub fn offset(&self) -> u64 {
        self.buf.offset()
    }
    /// Unread bytes in the driver's buffer.
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }
    /// The buffer's limit for new input: at least the decoder's capacity.
    pub fn limit(&self) -> usize {
        self.buf.limit()
    }
    /// Bytes of state retained by the decoder, excluding the input buffer.
    pub fn held(&self) -> usize {
        self.dec.held()
    }
    /// Whether decoding has completed or failed.
    pub fn is_done(&self) -> bool {
        self.done
    }
    /// The retained terminal error, if one occurred.
    pub fn failed(&self) -> Option<&Fail<D::Error>> {
        self.failed.as_ref()
    }
    /// Access to mode changes between items. A raised capacity raises the
    /// buffer limit before the next push, spare offer, or decode.
    pub fn decoder(&mut self) -> &mut D {
        &mut self.dec
    }
    /// Raises the buffer limit to the decoder's capacity. Never lowers it.
    /// The buffer clamps to [`Buffer::MAX_LIMIT`] and allocates on demand.
    fn sync_limit(&mut self) {
        let cap = self.dec.capacity();
        if cap > self.buf.limit() {
            self.buf.set_limit(cap);
        }
    }
    /// Hands the same unread bytes and offset to a new decoder. Preserves
    /// EOF and clears terminal status. The new capacity becomes the buffer
    /// limit. A larger unread suffix is kept and drains before more input fits.
    pub fn swap<E: Decode>(mut self, next: E) -> Stream<E> {
        self.buf.set_limit(next.capacity());
        Stream {
            buf: self.buf,
            dec: next,
            eof: self.eof,
            done: false,
            failed: None,
        }
    }
    /// Returns the buffer and decoder for transfer outside the codec layer.
    pub fn into_parts(self) -> (Buffer, D) {
        (self.buf, self.dec)
    }
    pub(super) fn stuck(&self) -> Fail<D::Error> {
        Fail::Stuck {
            unread: self.buf.len(),
            capacity: self.dec.capacity(),
        }
    }
    pub(super) fn refused(&self) -> Fail<D::Error> {
        Fail::Refused {
            unread: self.buf.len(),
            limit: self.buf.limit(),
        }
    }
}
impl<D: Decode> Stream<D>
where
    D::Error: Clone,
{
    pub(super) fn fail<R>(&mut self, fail: Fail<D::Error>) -> Option<Result<R, Fail<D::Error>>> {
        self.done = true;
        self.failed = Some(fail.clone());
        Some(Err(fail))
    }
    /// Takes one item. `None` means input is needed or the stream is done.
    /// A terminal error is returned only once.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Option<Result<D::Item, Fail<D::Error>>> {
        self.with_next(|item, _, _| item)
    }
    /// Takes one item and the range consumed by that step. Items released
    /// from held state have an empty range in this stream's coordinates.
    #[allow(clippy::type_complexity)]
    pub fn next_span(&mut self) -> Option<Result<(D::Item, Range<u64>), Fail<D::Error>>> {
        self.with_next(|item, _, range| (item, range))
    }
    /// Calls `f` once with an item, its exact consumed bytes, and its range,
    /// before consuming those bytes. Skips advance the range without
    /// calling `f`. For inner items of a pipe use its provenance spans.
    pub fn with_next<R>(
        &mut self,
        f: impl FnOnce(D::Item, &[u8], Range<u64>) -> R,
    ) -> Option<Result<R, Fail<D::Error>>> {
        self.with_next_observed(f, |_| {})
    }
    /// Like [`with_next`](Self::with_next), with borrowed observations of
    /// items, skips, clean completion, and failure. Observations occur in
    /// decoding order, before consuming bytes and before calling `f`.
    /// Completion and failure are each observed only on their first call.
    /// Waiting for input emits nothing and copies no bytes.
    pub fn with_next_observed<R>(
        &mut self,
        f: impl FnOnce(D::Item, &[u8], Range<u64>) -> R,
        mut observe: impl FnMut(StreamEvent<'_, D::Item, D::Error>),
    ) -> Option<Result<R, Fail<D::Error>>> {
        if self.done {
            return None;
        }
        self.sync_limit();
        let mut zero_budget = None;
        loop {
            let before = self.dec.held();
            let step = match self.dec.decode(self.buf.unread(), self.eof) {
                Ok(step) => step,
                Err(e) => return self.fail_observed(Fail::Protocol(e), &mut observe),
            };
            match &step {
                Step::Item(_, n) | Step::Skip(n) => {
                    if *n > self.buf.len() {
                        return self.fail_observed(self.stuck(), &mut observe);
                    }
                    if matches!(step, Step::Skip(0)) {
                        // Items return to the caller and need no loop allowance.
                        // A composite may move or expand state before releasing it.
                        // Allow one transition even when there are no held bytes.
                        let (budget, high) =
                            zero_budget.get_or_insert((before.saturating_add(1), before));
                        let after = self.dec.held();
                        // Credit each held byte once, even if state oscillates.
                        *budget = budget.saturating_add(after.saturating_sub(*high));
                        *high = (*high).max(after);
                        let Some(left) = budget.checked_sub(1) else {
                            return self.fail_observed(self.stuck(), &mut observe);
                        };
                        *budget = left;
                    } else {
                        zero_budget = None;
                    }
                }
                Step::Need if self.dec.held() > before => {
                    return self.fail_observed(self.stuck(), &mut observe);
                }
                _ => {}
            }
            match step {
                Step::Item(item, n) => {
                    let start = self.buf.offset();
                    let end = start.saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
                    observe(StreamEvent::Item {
                        item: &item,
                        bytes: self.buf.unread().get(..n).unwrap_or_default(),
                        range: start..end,
                    });
                    let result = f(
                        item,
                        self.buf.unread().get(..n).unwrap_or_default(),
                        start..end,
                    );
                    self.buf.consume(n);
                    return Some(Ok(result));
                }
                Step::Skip(n) => {
                    let start = self.buf.offset();
                    observe(StreamEvent::Skipped {
                        bytes: self.buf.unread().get(..n).unwrap_or_default(),
                        range: start..start.saturating_add(u64::try_from(n).unwrap_or(u64::MAX)),
                    });
                    self.buf.consume(n);
                }
                Step::Need => {
                    if self.eof {
                        if self.buf.is_empty() {
                            self.done = true;
                            observe(StreamEvent::Ended {
                                offset: self.offset(),
                            });
                            return None;
                        }
                        return self.fail_observed(
                            Fail::Truncated {
                                unread: self.buf.len(),
                            },
                            &mut observe,
                        );
                    }
                    if self.buf.len() >= self.dec.capacity() || self.buf.room() == 0 {
                        return self.fail_observed(self.stuck(), &mut observe);
                    }
                    return None;
                }
                Step::End => {
                    self.done = true;
                    observe(StreamEvent::Ended {
                        offset: self.offset(),
                    });
                    return None;
                }
            }
        }
    }
    fn fail_observed<R>(
        &mut self,
        fail: Fail<D::Error>,
        observe: &mut impl FnMut(StreamEvent<'_, D::Item, D::Error>),
    ) -> Option<Result<R, Fail<D::Error>>> {
        let start = self.offset();
        observe(StreamEvent::Failed {
            error: &fail,
            bytes: self.unread(),
            range: start..start.saturating_add(u64::try_from(self.buffered()).unwrap_or(u64::MAX)),
        });
        self.fail(fail)
    }
}

/// A decoder failure or a handler refusal while pumping.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PumpError<E, H> {
    /// The stream failed and retained this error.
    Decode(Fail<E>),
    /// The handler refused an item. That item has already been consumed.
    Handler(H),
}
impl<E: fmt::Display, H: fmt::Display> fmt::Display for PumpError<E, H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(_) => f.write_str("decoding failed"),
            Self::Handler(_) => f.write_str("the item handler failed"),
        }
    }
}
impl<E: Error + 'static, H: Error + 'static> Error for PumpError<E, H> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Decode(e) => Some(e),
            Self::Handler(e) => Some(e),
        }
    }
}

/// Feeds bytes and returns the number accepted from this slice.
/// Stops at EOF or completion. After `End`, swap decoders and push
/// `bytes[taken..]` to the new stream. Buffered unread bytes survive the swap.
/// On error, use `offset() + buffered()` before and after to count acceptance.
pub fn pump<D: Decode>(
    s: &mut Stream<D>,
    bytes: &[u8],
    mut on: impl FnMut(D::Item),
) -> Result<usize, Fail<D::Error>>
where
    D::Error: Clone,
{
    match try_pump(s, bytes, |item| {
        on(item);
        Ok::<(), core::convert::Infallible>(())
    }) {
        Ok(n) => Ok(n),
        Err(PumpError::Decode(e)) => Err(e),
        Err(PumpError::Handler(e)) => match e {},
    }
}

/// Feeds bytes until drained, ended, or refused by `on`.
/// Returns the number accepted. No bytes are pushed after EOF or completion.
/// On an error, the increase in `offset() + buffered()` gives the accepted
/// count. Keep the remaining slice for retry or handoff. A handler error
/// consumes its item. Accepted unread bytes remain in the stream.
pub fn try_pump<D: Decode, H>(
    s: &mut Stream<D>,
    mut bytes: &[u8],
    mut on: impl FnMut(D::Item) -> Result<(), H>,
) -> Result<usize, PumpError<D::Error, H>>
where
    D::Error: Clone,
{
    let mut taken = 0;
    loop {
        if s.is_done() {
            return Ok(taken);
        }
        let before_offset = s.offset();
        let before_held = s.held();
        let n = if s.eof { 0 } else { s.push(bytes) };
        taken += n;
        bytes = bytes.get(n..).unwrap_or_default();
        while let Some(result) = s.next() {
            on(result.map_err(PumpError::Decode)?).map_err(PumpError::Handler)?;
        }
        if bytes.is_empty() || s.is_done() || s.eof {
            return Ok(taken);
        }
        if n == 0 && s.offset() == before_offset && s.held() >= before_held {
            // A decoder at capacity has already failed as Stuck, so the
            // buffer refused room it had: the allocation failed.
            let fail = s.refused();
            s.done = true;
            s.failed = Some(fail.clone());
            return Err(PumpError::Decode(fail));
        }
    }
}

/// Marks EOF and delivers all remaining items. Later calls are inert.
pub fn finish<D: Decode>(
    s: &mut Stream<D>,
    mut on: impl FnMut(D::Item),
) -> Result<(), Fail<D::Error>>
where
    D::Error: Clone,
{
    s.end();
    while let Some(result) = s.next() {
        on(result?);
    }
    Ok(())
}
