use super::{Buffer, Decode, Step};
use core::{error::Error, fmt, ops::Range};

/// Why a stream stopped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fail<E> {
    /// A terminal decoder error.
    Protocol(E),
    /// EOF left a partial unit in the input buffer.
    Truncated {
        /// Unread input bytes.
        unread: usize,
    },
    /// A decoder broke its progress or accounting contract.
    /// Also covers refused buffer input, including allocation failure,
    /// and a [`Demux`](super::Demux) shared budget excess.
    Stuck {
        /// Unread input bytes at failure.
        unread: usize,
        /// The decoder's stated capacity.
        capacity: usize,
    },
}
impl<E: fmt::Display> fmt::Display for Fail<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(e) => write!(f, "decoder error: {e}"),
            Self::Truncated { unread } => write!(f, "input ended with {unread} unread bytes"),
            Self::Stuck { unread, capacity } => write!(
                f,
                "decoder stuck with {unread} unread bytes (capacity {capacity})"
            ),
        }
    }
}
impl<E: Error> Error for Fail<E> {}

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
        if self.done {
            return None;
        }
        self.sync_limit();
        let mut zero_budget = None;
        loop {
            let before = self.dec.held();
            let step = match self.dec.decode(self.buf.unread(), self.eof) {
                Ok(step) => step,
                Err(e) => return self.fail(Fail::Protocol(e)),
            };
            match &step {
                Step::Item(_, n) | Step::Skip(n) => {
                    if *n > self.buf.len() {
                        return self.fail(self.stuck());
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
                            return self.fail(self.stuck());
                        };
                        *budget = left;
                    } else {
                        zero_budget = None;
                    }
                }
                Step::Need if self.dec.held() > before => return self.fail(self.stuck()),
                _ => {}
            }
            match step {
                Step::Item(item, n) => {
                    let start = self.buf.offset();
                    let end = start.saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
                    let result = f(
                        item,
                        self.buf.unread().get(..n).unwrap_or_default(),
                        start..end,
                    );
                    self.buf.consume(n);
                    return Some(Ok(result));
                }
                Step::Skip(n) => self.buf.consume(n),
                Step::Need => {
                    if self.eof {
                        if self.buf.is_empty() {
                            self.done = true;
                            return None;
                        }
                        return self.fail(Fail::Truncated {
                            unread: self.buf.len(),
                        });
                    }
                    if self.buf.len() >= self.dec.capacity() || self.buf.room() == 0 {
                        return self.fail(self.stuck());
                    }
                    return None;
                }
                Step::End => {
                    self.done = true;
                    return None;
                }
            }
        }
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
            Self::Decode(e) => e.fmt(f),
            Self::Handler(e) => write!(f, "item handler: {e}"),
        }
    }
}
impl<E: Error, H: Error> Error for PumpError<E, H> {}

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
            let fail = s.stuck();
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
