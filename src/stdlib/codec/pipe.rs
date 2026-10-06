use super::{
    Buffer, Decode, Fail, Step, Stream,
    alloc::{collections::VecDeque, vec::Vec},
};
use core::{error::Error, fmt, ops::Range};

/// Default number of provenance spans retained by a [`Pipe`].
pub const DEFAULT_SPANS: usize = 256;

/// Byte coordinates in an inner stream and its parent stream.
/// The mapping is coarse: the inner bytes came from somewhere in the
/// outer range, which covers the whole outer unit that carried them,
/// framing and earlier fragments included. Equal lengths do not mean a
/// byte-for-byte copy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Span {
    /// Bytes in the inner stream.
    pub inner: Range<u64>,
    /// Corresponding bytes in the outer stream.
    pub outer: Range<u64>,
    /// Whether these ranges contain identical bytes in the same order.
    pub exact: bool,
}
/// A bounded ring of provenance spans. Offsets saturate at `u64::MAX`.
#[derive(Clone, Debug)]
pub struct Spans {
    ring: VecDeque<Span>,
    keep: usize,
    inner_at: u64,
    outer_at: u64,
}
impl Spans {
    /// Retains at most `keep` spans, evicting oldest first. Zero disables
    /// retention. The count is clamped to a representable allocation size.
    pub fn new(keep: usize) -> Self {
        Self {
            ring: VecDeque::new(),
            keep: keep.min((isize::MAX as usize) / core::mem::size_of::<Span>()),
            inner_at: 0,
            outer_at: 0,
        }
    }
    /// Records the next outer unit and the inner bytes it carries.
    /// The unit starts at the current outer offset, so outer bytes not yet
    /// recorded (earlier fragments of an assembled message) belong to it.
    /// Zero inner length only advances the outer offset.
    pub fn push(&mut self, outer_len: usize, inner_len: usize) {
        self.record(outer_len, inner_len, false);
    }
    /// Records unchanged bytes in both streams. Call `skip` first for an
    /// outer header. Unlike `push`, this permits partial byte placement.
    pub fn push_exact(&mut self, len: usize) {
        self.record(len, len, true);
    }
    fn record(&mut self, outer_len: usize, inner_len: usize, exact: bool) {
        let outer_end = self
            .outer_at
            .saturating_add(u64::try_from(outer_len).unwrap_or(u64::MAX));
        let inner_end = self
            .inner_at
            .saturating_add(u64::try_from(inner_len).unwrap_or(u64::MAX));
        if inner_len != 0 && self.keep != 0 {
            if self.ring.len() == self.keep {
                self.ring.pop_front();
            }
            let target = self.ring.capacity().saturating_mul(2).max(1).min(self.keep);
            if self.ring.len() < self.ring.capacity()
                || self
                    .ring
                    .try_reserve_exact(target.saturating_sub(self.ring.len()))
                    .is_ok()
            {
                self.ring.push_back(Span {
                    inner: self.inner_at..inner_end,
                    outer: self.outer_at..outer_end,
                    exact,
                });
            }
        }
        self.inner_at = inner_end;
        self.outer_at = outer_end;
    }
    /// Advances past an outer unit that carries no inner bytes.
    pub fn skip(&mut self, outer_len: usize) {
        self.push(outer_len, 0);
    }
    /// Retained mappings, oldest first.
    pub fn iter(&self) -> impl DoubleEndedIterator<Item = &Span> {
        self.ring.iter()
    }
    /// The number of retained spans.
    pub fn len(&self) -> usize {
        self.ring.len()
    }
    /// Whether no spans are retained.
    pub fn is_empty(&self) -> bool {
        self.ring.is_empty()
    }
    /// The next inner byte offset.
    pub fn inner_offset(&self) -> u64 {
        self.inner_at
    }
    /// The next outer byte offset.
    pub fn outer_offset(&self) -> u64 {
        self.outer_at
    }
    /// Resolves any nonempty range covered by exact, contiguous spans.
    /// Coarse mappings, gaps, evicted spans, and overflow return `None`.
    pub fn locate_exact(&self, range: Range<u64>) -> Option<Range<u64>> {
        if range.start >= range.end { return None; }
        let mut at = range.start;
        let mut result: Option<Range<u64>> = None;
        for span in &self.ring {
            if span.inner.end <= at { continue; }
            if !span.exact || span.inner.start > at { return None; }
            let start = span.outer.start.checked_add(at.checked_sub(span.inner.start)?)?;
            let end = span.outer.start.checked_add(range.end.min(span.inner.end).checked_sub(span.inner.start)?)?;
            if end > span.outer.end { return None; }
            match &mut result {
                Some(r) if r.end == start => r.end = end,
                None => result = Some(start..end),
                _ => return None,
            }
            at = range.end.min(span.inner.end);
            if at == range.end { return result; }
        }
        None
    }
    /// Resolves a nonempty range that covers whole spans with contiguous
    /// outer ranges, giving the union of those outer ranges. A partial
    /// span, an evicted span, or a gap in either coordinate returns `None`.
    pub fn locate(&self, range: Range<u64>) -> Option<Range<u64>> {
        if range.start >= range.end {
            return None;
        }
        let mut at = range.start;
        let mut result: Option<Range<u64>> = None;
        for span in &self.ring {
            if span.inner.end <= at {
                continue;
            }
            if span.inner.start > at {
                return None;
            }
            if span.inner.start != at || span.inner.end > range.end {
                return None;
            }
            match &mut result {
                Some(r) if r.end == span.outer.start => r.end = span.outer.end,
                None => result = Some(span.outer.clone()),
                _ => return None,
            }
            at = span.inner.end;
            if at == range.end {
                return result;
            }
        }
        None
    }
}

/// How an outer item contributes to a pipe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Carry<T> {
    /// Bytes of a continuous inner stream.
    Bytes(Vec<u8>),
    /// An outer control item to deliver unchanged.
    Through(T),
    /// An outer item to discard.
    Drop,
}
/// An item from either layer of a pipe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Layered<O, I> {
    /// An outer control item.
    Outer(O),
    /// An inner decoded item.
    Inner(I),
}
/// Why a pipe failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PipeError<OE, IE> {
    /// The outer framing failed.
    Outer(OE),
    /// The inner decoder or driver failed.
    Inner(Fail<IE>),
    /// The mapping closure produced more payload than its configured bound.
    PayloadTooLong {
        /// Maximum bytes staged from one outer item.
        limit: usize,
    },
}
impl<OE: fmt::Display, IE: fmt::Display> fmt::Display for PipeError<OE, IE> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Outer(e) => write!(f, "outer decoder: {e}"),
            Self::Inner(e) => write!(f, "inner stream: {e}"),
            Self::PayloadTooLong { limit } => write!(f, "payload exceeds {limit} bytes"),
        }
    }
}
impl<OE: Error, IE: Error> Error for PipeError<OE, IE> {}
/// Feeds selected outer payloads into one continuous inner stream.
/// Inner items can cross payload boundaries. A staged payload is fully
/// admitted before another outer item is decoded. The inner stream sees
/// EOF only after the outer stream and its final payload are drained.
/// An early inner `End` ends the pipe. The outer unread suffix stays in
/// the driver. Inner unread bytes and unpushed payload stay in the pipe.
///
/// [`new`](Self::new) limits each payload to `outer.capacity()`.
/// Use [`with_limits`](Self::with_limits) for larger payloads, including
/// messages from an [`Assemble`](super::Assemble) outer or an expanding map.
pub struct Pipe<O: Decode, I: Decode, F> {
    outer: O,
    inner: Stream<I>,
    pick: F,
    pending: Vec<u8>,
    pushed: usize,
    outer_ended: bool,
    inner_ready: bool,
    spans: Spans,
    // Outer bytes skipped since the last outer item; they belong to the next.
    unit: usize,
    payload_limit: usize,
}
impl<O: Decode, I: Decode, F> Pipe<O, I, F> {
    /// Uses `outer.capacity()` as the staged payload limit and
    /// [`DEFAULT_SPANS`] as the provenance limit. Use [`with_limits`](Self::with_limits)
    /// when a mapped payload can be larger than one outer input unit.
    pub fn new(outer: O, inner: I, pick: F) -> Self {
        let limit = outer.capacity();
        Self::with_limits(outer, inner, pick, limit, DEFAULT_SPANS)
    }
    /// Sets the maximum staged payload bytes and retained span count.
    /// Payload limits are clamped to [`Buffer::MAX_LIMIT`]. Each decoder
    /// remains responsible for its own held-state limit.
    pub fn with_limits(
        outer: O,
        inner: I,
        pick: F,
        payload_limit: usize,
        keep_spans: usize,
    ) -> Self {
        Self {
            outer,
            inner: Stream::new(inner),
            pick,
            pending: Vec::new(),
            pushed: 0,
            outer_ended: false,
            inner_ready: true,
            spans: Spans::new(keep_spans),
            unit: 0,
            payload_limit: payload_limit.min(Buffer::MAX_LIMIT),
        }
    }
    /// Coarse whole-unit provenance, relative to the pipe's first byte.
    /// A unit is every outer byte since the previous outer item, so an
    /// assembled message spans all its fragments. Through and dropped items
    /// advance outer offsets. Skipped bytes are counted with the next item.
    pub fn spans(&self) -> &Spans {
        &self.spans
    }
    /// Access to the inner decoder between items.
    pub fn inner(&mut self) -> &mut I {
        self.inner_ready = true;
        self.inner.decoder()
    }
    /// Staged payload bytes not yet accepted by the inner stream.
    pub fn pending(&self) -> &[u8] {
        self.pending.get(self.pushed..).unwrap_or_default()
    }
    /// Returns both layers and the unpushed payload for handoff.
    pub fn into_parts(mut self) -> (O, Stream<I>, Vec<u8>) {
        self.pending.drain(..self.pushed);
        (self.outer, self.inner, self.pending)
    }
    /// The inner stream, including its unread suffix after an early end.
    pub fn inner_stream(&self) -> &Stream<I> {
        &self.inner
    }
    // Ends the current outer unit with an item of `n` bytes; returns its length.
    fn take_unit(&mut self, n: usize) -> usize {
        core::mem::take(&mut self.unit).saturating_add(n)
    }
}
impl<O: Decode, I: Decode, F: FnMut(O::Item) -> Carry<O::Item>> Decode for Pipe<O, I, F>
where
    I::Error: Clone,
{
    type Item = Layered<O::Item, I::Item>;
    type Error = PipeError<O::Error, I::Error>;
    const NAME: &'static str = O::NAME;
    fn capacity(&self) -> usize {
        self.outer.capacity()
    }
    fn held(&self) -> usize {
        self.pending
            .len()
            .saturating_sub(self.pushed)
            .saturating_add(self.inner.buffered())
            .saturating_add(self.inner.held())
            .saturating_add(self.outer.held())
    }
    fn decode(&mut self, input: &[u8], eof: bool) -> Result<Step<Self::Item>, Self::Error> {
        let entry_held = self.held();
        loop {
            if self.inner.is_done() {
                return Ok(Step::End);
            }
            let remaining = self.pending.get(self.pushed..).unwrap_or_default();
            let n = self.inner.push(remaining);
            if n != 0 {
                self.inner_ready = true;
            }
            self.pushed = self.pushed.saturating_add(n);
            if self.pushed >= self.pending.len() {
                self.pending.clear();
                self.pushed = 0;
            }
            if self.outer_ended && self.pending.is_empty() && !self.inner.eof {
                self.inner.end();
                self.inner_ready = true;
            }
            let before = self.inner.buffered().saturating_add(self.inner.held());
            let offset = self.inner.offset();
            if self.inner_ready {
                if let Some(result) = self.inner.next() {
                    return result
                        .map(|item| Step::Item(Layered::Inner(item), 0))
                        .map_err(PipeError::Inner);
                }
                // A waiting decoder needs new bytes, EOF, or a mode change.
                self.inner_ready = false;
            }
            if self.inner.is_done() {
                return Ok(Step::End);
            }
            if self.pending.is_empty() {
                break;
            }
            let after = self.inner.buffered().saturating_add(self.inner.held());
            if n == 0 && self.inner.offset() == offset && after >= before {
                return Err(PipeError::Inner(self.inner.stuck()));
            }
        }
        if self.outer_ended {
            return Ok(Step::End);
        }
        let mut empty_budget = self.outer.held().saturating_add(1);
        loop {
            let before = self.outer.held();
            let step = match self.outer.decode(input, eof).map_err(PipeError::Outer)? {
                Step::Item(item, n) => Ok(match (self.pick)(item) {
                    Carry::Through(item) => {
                        let unit = self.take_unit(n);
                        self.spans.skip(unit);
                        Step::Item(Layered::Outer(item), n)
                    }
                    Carry::Drop => {
                        let unit = self.take_unit(n);
                        self.spans.skip(unit);
                        Step::Skip(n)
                    }
                    Carry::Bytes(bytes) => {
                        if bytes.len() > self.payload_limit {
                            return Err(PipeError::PayloadTooLong {
                                limit: self.payload_limit,
                            });
                        }
                        let unit = self.take_unit(n);
                        self.spans.push(unit, bytes.len());
                        self.pending = bytes;
                        Step::Skip(n)
                    }
                }),
                Step::Skip(n) => {
                    self.unit = self.unit.saturating_add(n);
                    Ok(Step::Skip(n))
                }
                Step::Need if !(eof && input.is_empty()) => Ok(Step::Need),
                Step::Need | Step::End => {
                    let unit = self.take_unit(0);
                    self.spans.skip(unit);
                    self.outer_ended = true;
                    self.inner.end();
                    self.inner_ready = true;
                    // Finish the inner stream after the last outer payload.
                    match self.inner.next() {
                        Some(result) => result
                            .map(|item| Step::Item(Layered::Inner(item), 0))
                            .map_err(PipeError::Inner),
                        None => Ok(Step::End),
                    }
                }
            }?;
            // Empty transitions add no work for the inner stream. Finish them
            // here so nesting does not multiply zero-byte skips. Yield when
            // the outer state budget runs out so the driver can check progress.
            if matches!(step, Step::Skip(0))
                && self.pending.is_empty()
                && self.outer.held() <= before
                && empty_budget != 0
            {
                empty_budget -= 1;
                continue;
            }
            // Inner progress may expand state before the outer needs input.
            // Report that work without growing held state across Need.
            return Ok(if matches!(step, Step::Need) && self.held() > entry_held {
                Step::Skip(0)
            } else {
                step
            });
        }
    }
}
