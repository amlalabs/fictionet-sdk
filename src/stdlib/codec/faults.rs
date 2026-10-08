#[cfg(test)]
use fictionet::stdlib::codec::Frames;
extern crate alloc;

use alloc::{collections::BinaryHeap, vec::Vec};
use core::{cmp::Ordering, convert::Infallible, error::Error, fmt, ops::Range, time::Duration};
use fictionet::stdlib::codec::{
    Buffer, Decode, Interceptor, Lcg, PumpError, Rewrite, RewriteError, SkipPolicy, Stream,
    StreamEvent, Wire, append_bounded, write_bounded,
};

/// When a rule applies. Call numbers start at one in each fault domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Trigger {
    /// Every call that reaches this rule.
    Always,
    /// Exactly this call number. Zero never matches.
    At(u64),
    /// From the nth call onward. Zero includes every call.
    After(u64),
    /// Calls from `start` through `end`, inclusive. Reversed bounds never match.
    Window {
        /// First matching call.
        start: u64,
        /// Last matching call.
        end: u64,
    },
    /// Every nth call. Zero never matches.
    Every(u64),
    /// Draw below `out_of` and match when below `take`.
    /// Zero `out_of` never matches; `take >= out_of` always matches.
    /// Draws combine two 31-bit LCG outputs before modulo reduction.
    /// All u32 denominators are supported, with a small modulo bias.
    Chance {
        /// Number of matching outcomes.
        take: u32,
        /// Number of possible outcomes.
        out_of: u32,
    },
}

/// A rule in an ordered plan. Only the first matching rule is applied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule<F> {
    /// Selection condition.
    pub when: Trigger,
    /// Action when this rule matches.
    pub fault: F,
}

/// An edit to a caller-defined byte chunk before it is pushed to a stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ByteFault {
    /// Request a delay before these unchanged bytes.
    Delay(Duration),
    /// Discard a range, or the whole chunk when `None`.
    /// Endpoints are clamped to the chunk. A reversed range is empty.
    Drop(Option<Range<usize>>),
    /// Repeat a range in place, or the whole chunk when `None`.
    /// Endpoints are clamped. A reversed range is empty.
    Repeat {
        /// Selected bytes, or the entire chunk.
        range: Option<Range<usize>>,
        /// Total copies, including the original. Zero removes the range.
        copies: usize,
    },
    /// Deliver the prefix, then wait before delivering the suffix.
    Split {
        /// Split offset, clamped to the input length. Either half may be empty.
        at: usize,
        /// Delay between the two pushes.
        delay: Duration,
    },
    /// Retain at most this many bytes from the beginning of the chunk.
    Truncate(usize),
    /// XOR one byte. Empty input and an out-of-range fixed offset are inert.
    Corrupt {
        /// Byte index, or `None` to draw an index from the seeded LCG.
        offset: Option<usize>,
        /// Bits to flip. Zero leaves the byte unchanged.
        xor: u8,
    },
    /// Substitute these exact bytes without protocol validation.
    Replace(Vec<u8>),
}

/// An item edit, with optional delay, or a bounded reorder operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ItemFault<T> {
    /// Apply an interceptor decision after an optional delay.
    Action {
        /// A marker for the world. This code never sleeps or reads a clock.
        delay: Option<Duration>,
        /// Forward, drop, repeat, replace values, or supply framed raw bytes.
        rewrite: Rewrite<T>,
    },
    /// Retain exact raw bytes until `window` later successful item calls.
    /// The current item's output precedes any held items released by it.
    /// Zero forwards immediately. [`Faults::flush`] releases any remainder.
    Hold {
        /// Number of later items to wait for, including dropped or held items.
        window: u64,
    },
}

/// A delay before an offset in the destination vector passed to a fault.
/// Send or push the appended prefix up to `at`, wait, then send the suffix.
/// Keep this boundary even when the duration is zero or a half is empty.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FaultDelay {
    /// Absolute offset in that output vector, including its existing prefix.
    pub at: usize,
    /// How long the world should wait before delivering the suffix.
    pub duration: Duration,
}

/// Why an item fault or a held-item flush could not complete.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FaultError<E> {
    /// Output, held bytes, or a replacement writer exceeded a bound or failed.
    Rewrite(RewriteError<E>),
    /// The held-item count would exceed its configured bound.
    HeldLimit {
        /// Maximum held item count.
        limit: usize,
    },
}
impl<E: fmt::Display> fmt::Display for FaultError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rewrite(_) => f.write_str("the fault plan's rewrite failed"),
            Self::HeldLimit { limit } => write!(f, "fault plan exceeds {limit} held items"),
        }
    }
}
impl<E: Error + 'static> Error for FaultError<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Rewrite(e) => Some(e),
            Self::HeldLimit { .. } => None,
        }
    }
}
impl<E> From<RewriteError<E>> for FaultError<E> {
    fn from(error: RewriteError<E>) -> Self {
        Self::Rewrite(error)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Held {
    due: u128,
    seq: u64,
    bytes: Vec<u8>,
}
impl Ord for Held {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse order makes the earliest due call and sequence the root.
        (other.due, other.seq).cmp(&(self.due, self.seq))
    }
}
impl PartialOrd for Held {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Deterministic byte and item fault plans with an explicit seed.
///
/// Plans are borrowed per call and remain owned and bounded by world code.
/// Byte and item calls have independent counters and share one LCG. The
/// same seed, plans, and call sequence give the same decisions and bytes.
/// Counters stop matching after `u64::MAX` calls instead of wrapping.
/// Rules are checked in order; random draws occur only for reached rules
/// and selected random corruption offsets. Each item call shares one
/// counter regardless of the selected plan. Per-operation counters belong
/// in world code, with an aggregate bound on any per-key Faults instances.
///
/// Byte rules apply to each supplied chunk before [`Stream::push`](fictionet::stdlib::codec::Stream::push).
/// Chunk boundaries are part of that input. Use [`next_with_observed`](Self::next_with_observed)
/// with [`Recorder::observer`](fictionet::stdlib::codec::Recorder::observer) to
/// record and fault in one pass through the Interceptor. Skips are forwarded
/// even when an item is held. Item rules run once per item,
/// independent of push sizes. Apply them to outer frames when holding a
/// Pipe's inner item would retain no raw bytes. Use caller-owned framing
/// for inner replacements. Honor returned delay offsets when sending output.
///
/// ```
/// use fictionet::stdlib::{codec::{Direction, Faults, ItemFault, Recorder, Rule, Stream, Trigger, write_bounded}, json};
/// let mut faults = Faults::new(7, 1024, 8);
/// let mut log = Recorder::new(16, 1024);
/// let mut stream = Stream::new(json::Values::new());
/// let plan = [Rule { when: Trigger::At(1), fault: ItemFault::<json::Value>::Hold { window: 1 } }];
/// let input = b"1 2\n";
/// assert_eq!(stream.push(input), input.len());
/// stream.end();
/// let mut output = Vec::new();
/// while let Some(result) = faults.next_with_observed(&mut stream, &mut output, &plan,
///     write_bounded, log.observer(0, Direction::ClientToServer)) {
///     result?;
/// }
/// faults.flush(&mut output)?;
/// assert_eq!(output, b" 21\n"); // skipped separators survive the deliberate reorder
/// assert_eq!(log.retained_bytes(), input.len());
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
#[derive(Clone, Debug)]
pub struct Faults {
    rng: Lcg,
    byte_at: Option<u64>,
    item_at: Option<u64>,
    output: Interceptor,
    held: BinaryHeap<Held>,
    completed: u128,
    held_bytes: usize,
    max_held: usize,
}
impl Faults {
    /// Starts both counters at one. `max_output` bounds each destination
    /// vector and, separately, all held raw bytes. It is clamped as in
    /// [`Interceptor::new`]. `max_held` bounds queue entries, including empty
    /// items, and is clamped to a representable allocation size.
    /// With Forward skips, the stream's buffered bytes must fit `max_output`:
    /// push at most [`room`](Self::room) bytes before each call.
    pub fn new(seed: u64, max_output: usize, max_held: usize) -> Self {
        Self {
            rng: Lcg::new(seed),
            byte_at: Some(1),
            item_at: Some(1),
            output: Interceptor::new(max_output),
            held: BinaryHeap::new(),
            completed: 0,
            held_bytes: 0,
            max_held: max_held.min((isize::MAX as usize) / core::mem::size_of::<Held>()),
        }
    }

    /// Number of items waiting for later calls or a flush.
    pub fn held_count(&self) -> usize {
        self.held.len()
    }

    /// Total raw bytes retained by held items.
    pub fn held_bytes(&self) -> usize {
        self.held_bytes
    }

    /// How many bytes to push to `stream` before the next item call, as in
    /// [`Interceptor::room`] with this plan's output limit and skip policy.
    pub fn room<D: Decode>(&self, stream: &Stream<D>, out: &[u8]) -> usize {
        self.output.room(stream, out)
    }

    /// Edits one input chunk. Returns a delay at the appended start or at
    /// a split boundary. An error restores `out`, but advances the counter
    /// and random draws. Retrying is a new plan call. No match copies input.
    pub fn bytes(
        &mut self,
        plan: &[Rule<ByteFault>],
        input: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<Option<FaultDelay>, RewriteError<Infallible>> {
        let call = self.byte_at;
        self.byte_at = call.and_then(|n| n.checked_add(1));
        let fault = plan
            .iter()
            .find(|rule| self.matches(rule.when, call))
            .map(|rule| &rule.fault);
        let start = out.len();
        let result = (|| {
            let mut marker = None;
            match fault {
                None | Some(ByteFault::Delay(_)) | Some(ByteFault::Split { .. }) => {
                    self.output.append(input, 1, out)?;
                    marker = match fault {
                        Some(ByteFault::Delay(duration)) => Some(FaultDelay {
                            at: start,
                            duration: *duration,
                        }),
                        Some(ByteFault::Split { at, delay }) => Some(FaultDelay {
                            // The append checked that start + input.len() fits.
                            at: out.len() - (input.len() - (*at).min(input.len())),
                            duration: *delay,
                        }),
                        _ => None,
                    };
                }
                Some(ByteFault::Drop(range)) | Some(ByteFault::Repeat { range, .. }) => {
                    let (begin, end) = range.as_ref().map_or((0, input.len()), |r| {
                        let begin = r.start.min(input.len());
                        (begin, r.end.min(input.len()).max(begin))
                    });
                    let copies = match fault {
                        Some(ByteFault::Repeat { copies, .. }) => *copies,
                        _ => 0,
                    };
                    self.output.append(&input[..begin], 1, out)?;
                    self.output.append(&input[begin..end], copies, out)?;
                    self.output.append(&input[end..], 1, out)?;
                }
                Some(ByteFault::Truncate(len)) => {
                    self.output
                        .append(&input[..(*len).min(input.len())], 1, out)?
                }
                Some(ByteFault::Replace(bytes)) => self.output.append(bytes, 1, out)?,
                Some(ByteFault::Corrupt { offset, xor }) => {
                    self.output.append(input, 1, out)?;
                    let at = offset.unwrap_or_else(|| self.rng.index(input.len()));
                    if let Some(byte) = out[start..].get_mut(at) {
                        *byte ^= xor;
                    }
                }
            }
            Ok(marker)
        })();
        if result.is_err() {
            out.truncate(start);
        }
        result
    }

    /// Sets the shared Interceptor's skip policy. Forward is the default.
    /// Drop is for caller-owned framing of inner items, such as a Pipe.
    pub fn with_skips(mut self, skips: SkipPolicy) -> Self {
        self.output = self.output.with_skips(skips);
        self
    }

    /// Drives one item through the Interceptor with the supplied plan.
    /// Skips are forwarded by default, including on Hold. No item means no
    /// plan call, though skips may be appended. See [`next_with_observed`](Self::next_with_observed)
    /// for transaction and observer behavior.
    #[allow(clippy::type_complexity)]
    pub fn next<D: Decode>(
        &mut self,
        stream: &mut Stream<D>,
        out: &mut Vec<u8>,
        plan: &[Rule<ItemFault<D::Item>>],
    ) -> Option<
        Result<Option<FaultDelay>, PumpError<D::Error, FaultError<<D::Item as Wire>::WriteError>>>,
    >
    where
        D::Error: Clone,
        D::Item: Wire,
    {
        self.next_with_observed(stream, out, plan, write_bounded, |_| {})
    }

    /// Drives one item with caller-owned replacement framing. The writer
    /// receives the remaining output budget as in [`Interceptor::apply_with`].
    #[allow(clippy::type_complexity)]
    pub fn next_with<D: Decode, T, E>(
        &mut self,
        stream: &mut Stream<D>,
        out: &mut Vec<u8>,
        plan: &[Rule<ItemFault<T>>],
        write: impl FnMut(&T, &mut Buffer) -> Result<(), RewriteError<E>>,
    ) -> Option<Result<Option<FaultDelay>, PumpError<D::Error, FaultError<E>>>>
    where
        D::Error: Clone,
    {
        self.next_with_observed(stream, out, plan, write, |_| {})
    }

    /// Drives, faults, and observes one pass using the Interceptor's skip
    /// handling, output bound, and per-item transaction. Observations contain
    /// original bytes before any fault. Pass a [`Recorder::observer`](fictionet::stdlib::codec::Recorder::observer)
    /// to retain them by stream key and direction.
    ///
    /// A handler failure rolls back this call's output, including its skips.
    /// A decode failure keeps consumed skips and is returned once. Reserving
    /// room for skips can fail before decoding, leaving input untouched.
    /// More buffered input than `max_output` is [`RewriteError::Capacity`],
    /// which draining cannot fix. Keep pushes within [`room`](Self::room).
    /// Hold commits only if the whole item action succeeds. Delay offsets
    /// include any forwarded skips. EOF does not flush holds automatically;
    /// call [`flush`](Self::flush) after honoring the last delay marker.
    #[allow(clippy::type_complexity)]
    pub fn next_with_observed<D: Decode, T, E>(
        &mut self,
        stream: &mut Stream<D>,
        out: &mut Vec<u8>,
        plan: &[Rule<ItemFault<T>>],
        write: impl FnMut(&T, &mut Buffer) -> Result<(), RewriteError<E>>,
        observe: impl FnMut(StreamEvent<'_, D::Item, D::Error>),
    ) -> Option<Result<Option<FaultDelay>, PumpError<D::Error, FaultError<E>>>>
    where
        D::Error: Clone,
    {
        let output = self.output;
        output.with_next_observed::<D, _, _, E>(
            stream,
            out,
            |_, raw, _, out| self.item_with(plan, raw, out, write),
            observe,
        )
    }

    /// Applies one item's plan using its replacement type's Wire writer.
    /// No match forwards raw bytes. The plan is borrowed without cloning.
    /// This operates on one supplied item, without stream skips. For a stream,
    /// use [`next`](Self::next). See [`item_with`](Self::item_with) for errors.
    pub fn item<T: Wire>(
        &mut self,
        plan: &[Rule<ItemFault<T>>],
        raw: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<Option<FaultDelay>, FaultError<T::WriteError>> {
        self.item_with(plan, raw, out, write_bounded)
    }

    /// Applies a plan with caller-owned replacement framing, then releases
    /// due held items by (due call, insertion order). Longer windows do not
    /// block later entries. Writers follow [`Interceptor::apply_with`].
    /// Holds use absolute successful call numbers in a heap. Each call
    /// examines only the earliest entry and any entries it releases.
    /// The queue is bounded by count and total raw bytes. A new hold must
    /// fit before due entries are released. An error restores output and
    /// leaves the queue and its windows unchanged. Counters and random
    /// draws advance on errors. Each successful call advances old windows.
    pub fn item_with<T, E>(
        &mut self,
        plan: &[Rule<ItemFault<T>>],
        raw: &[u8],
        out: &mut Vec<u8>,
        mut write: impl FnMut(&T, &mut Buffer) -> Result<(), RewriteError<E>>,
    ) -> Result<Option<FaultDelay>, FaultError<E>> {
        let call = self.item_at;
        self.item_at = call.and_then(|n| n.checked_add(1));
        let fault = plan
            .iter()
            .find(|rule| self.matches(rule.when, call))
            .map(|rule| &rule.fault);
        let start = out.len();
        let mut pending = None;
        let mut released = Vec::new();
        // Plans stop selecting holds after u64::MAX attempts. u128 keeps
        // every such due call representable, including u64::MAX windows.
        let completed = self.completed.saturating_add(1);
        let result = (|| {
            let mut marker = None;
            match fault {
                Some(ItemFault::Hold { window }) if *window != 0 => {
                    if self.held.len() >= self.max_held {
                        return Err(FaultError::HeldLimit {
                            limit: self.max_held,
                        });
                    }
                    let mut bytes = Vec::new();
                    let limit = self.output.limit();
                    if raw.len() > limit.saturating_sub(self.held_bytes) {
                        return Err(RewriteError::TooLong { limit }.into());
                    }
                    append_bounded(raw, 1, &mut bytes, limit)?;
                    if self.held.len() == self.held.capacity() {
                        let target = self
                            .held
                            .capacity()
                            .saturating_mul(2)
                            .max(1)
                            .min(self.max_held);
                        self.held
                            .try_reserve_exact(target.saturating_sub(self.held.len()))
                            .map_err(|_| RewriteError::Allocation)?;
                    }
                    pending = Some(Held {
                        bytes,
                        due: completed.saturating_add(u128::from(*window)),
                        seq: call.unwrap_or(u64::MAX),
                    });
                }
                Some(ItemFault::Action { delay, rewrite }) => {
                    self.output.apply_with(raw, rewrite, out, &mut write)?;
                    marker = delay.map(|duration| FaultDelay {
                        at: start,
                        duration,
                    });
                }
                _ => self.output.append(raw, 1, out)?,
            }
            // Check the output bound even for a hold with no released bytes.
            self.output.append(&[], 1, out)?;
            while self.held.peek().is_some_and(|entry| entry.due <= completed) {
                if released.len() == released.capacity() {
                    // Keep this small reservation local. Recorder owns a deque;
                    // this temporary vector and the held heap have separate bounds.
                    let target = released
                        .capacity()
                        .saturating_mul(2)
                        .max(1)
                        .min(self.max_held);
                    released
                        .try_reserve_exact(target.saturating_sub(released.len()))
                        .map_err(|_| RewriteError::Allocation)?;
                }
                if let Some(entry) = self.held.peek() {
                    self.output.append(&entry.bytes, 1, out)?;
                }
                if let Some(entry) = self.held.pop() {
                    released.push(entry);
                }
            }
            Ok(marker)
        })();
        if result.is_err() {
            out.truncate(start);
            // Pop preserves heap capacity, so restoring these cannot allocate.
            for entry in released {
                self.held.push(entry);
            }
            return result;
        }
        self.completed = completed;
        for entry in released {
            self.held_bytes = self.held_bytes.saturating_sub(entry.bytes.len());
        }
        if let Some(entry) = pending {
            // The reservation and append above checked both bounds.
            self.held_bytes = self.held_bytes.saturating_add(entry.bytes.len());
            self.held.push(entry);
        }
        result
    }

    /// Releases all held raw bytes in due order, breaking ties by insertion.
    /// This adds no delay or plan call. Reserves for all held bytes first.
    /// An error leaves output and queue unchanged, so the caller can drain
    /// output and retry. Empty flushes also check the destination limit.
    pub fn flush(&mut self, out: &mut Vec<u8>) -> Result<(), RewriteError<Infallible>> {
        let limit = self.output.limit();
        let size = out
            .len()
            .checked_add(self.held_bytes)
            .filter(|size| *size <= limit)
            .ok_or(RewriteError::TooLong { limit })?;
        if size > out.capacity() {
            out.try_reserve_exact(size.saturating_sub(out.len()))
                .map_err(|_| RewriteError::Allocation)?;
        }
        while let Some(entry) = self.held.pop() {
            out.extend_from_slice(&entry.bytes);
        }
        self.held_bytes = 0;
        Ok(())
    }

    fn matches(&mut self, trigger: Trigger, call: Option<u64>) -> bool {
        let Some(call) = call else { return false };
        match trigger {
            Trigger::Always => true,
            Trigger::At(n) => n != 0 && call == n,
            Trigger::After(n) => call >= n,
            Trigger::Window { start, end } => call >= start && call <= end,
            Trigger::Every(n) => n != 0 && call.is_multiple_of(n),
            Trigger::Chance { take, out_of } => {
                out_of != 0
                    && (take >= out_of || {
                        let draw = (self.rng.next() << 31) | self.rng.next();
                        draw % u64::from(out_of) < u64::from(take)
                    })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::{test_support, modbus};

    fn rule<T>(fault: ItemFault<T>) -> [Rule<ItemFault<T>>; 1] {
        [Rule {
            when: Trigger::Always,
            fault,
        }]
    }

    #[test]
    fn many_distant_holds_do_not_walk_the_queue_per_call() {
        let count = 40_000;
        let mut faults = Faults::new(0, 0, count);
        let plan = rule(ItemFault::<modbus::Frame>::Hold { window: u64::MAX });
        let mut out = Vec::new();
        for _ in 0..count {
            faults.item(&plan, b"", &mut out).unwrap();
        }
        assert_eq!(faults.held_count(), count);
        assert_eq!(faults.held_bytes(), 0);
        assert_eq!(faults.held.peek().unwrap().due, u128::from(u64::MAX) + 1);
        faults.flush(&mut out).unwrap();
        assert_eq!(faults.held_count(), 0);
    }

    #[test]
    fn due_entries_restore_after_partial_release_failure() {
        let mut faults = Faults::new(0, 3, 4);
        let mut out = Vec::new();
        faults
            .item(
                &rule(ItemFault::<modbus::Frame>::Hold { window: 2 }),
                b"a",
                &mut out,
            )
            .unwrap();
        faults
            .item(
                &rule(ItemFault::<modbus::Frame>::Hold { window: 1 }),
                b"bb",
                &mut out,
            )
            .unwrap();
        assert!(faults.item::<modbus::Frame>(&[], b"c", &mut out).is_err());
        assert_eq!(faults.held_count(), 2);
        assert_eq!(faults.held_bytes(), 3);
        assert!(out.is_empty());
        faults.item::<modbus::Frame>(&[], b"", &mut out).unwrap();
        assert_eq!(out, b"abb");
        assert_eq!(faults.held_count(), 0);
    }

    #[test]
    fn output_limit_below_buffered_input_is_a_capacity_error_and_room_avoids_it() {
        let frame = [0, 1, 0, 0, 0, 6, 1, 3, 0, 0, 0, 1];
        let input = frame.repeat(4);
        let plan = rule(ItemFault::<modbus::Frame>::Action {
            delay: None,
            rewrite: Rewrite::Drop,
        });
        let mut faults = Faults::new(0, 16, 4);
        let mut stream = Stream::new(Frames::<modbus::Frame>::new());
        assert_eq!(stream.push(&input), input.len());
        let mut out = Vec::new();
        assert!(matches!(
            faults.next(&mut stream, &mut out, &plan),
            Some(Err(PumpError::Handler(FaultError::Rewrite(
                RewriteError::Capacity {
                    buffered: 48,
                    limit: 16
                }
            ))))
        ));

        let mut stream = Stream::new(Frames::<modbus::Frame>::new());
        let mut accepted = 0;
        let mut items = 0;
        while accepted < input.len() {
            let room = faults.room(&stream, &out);
            assert!(room > 0);
            accepted += stream.push(&input[accepted..input.len().min(accepted + room)]);
            while let Some(result) = faults.next(&mut stream, &mut out, &plan) {
                result.unwrap();
                items += 1;
            }
            out.clear();
        }
        assert_eq!(items, 4);
    }

    #[test]
    fn held_byte_error_reports_configured_limit() {
        let mut faults = Faults::new(0, 4, 4);
        let plan = rule(ItemFault::<modbus::Frame>::Hold { window: 2 });
        let mut out = Vec::new();
        faults.item(&plan, b"abc", &mut out).unwrap();
        assert_eq!(
            faults.item(&plan, b"de", &mut out),
            Err(FaultError::Rewrite(RewriteError::TooLong { limit: 4 }))
        );
        assert_eq!(faults.held_bytes(), 3);
        assert!(out.is_empty());
    }

    #[test]
    fn all_byte_faults_preserve_prefix_and_mark_boundaries() {
        let delay = Duration::from_millis(3);
        let cases = [
            (ByteFault::Delay(delay), b"abc".as_slice(), Some(1)),
            (ByteFault::Drop(None), b"", None),
            (ByteFault::Drop(Some(1..2)), b"ac", None),
            (
                ByteFault::Repeat {
                    range: None,
                    copies: 2,
                },
                b"abcabc",
                None,
            ),
            (
                ByteFault::Repeat {
                    range: Some(1..2),
                    copies: 3,
                },
                b"abbbc",
                None,
            ),
            (
                ByteFault::Repeat {
                    range: Some(1..2),
                    copies: 0,
                },
                b"ac",
                None,
            ),
            (ByteFault::Split { at: 1, delay }, b"abc", Some(2)),
            (
                ByteFault::Split {
                    at: usize::MAX,
                    delay,
                },
                b"abc",
                Some(4),
            ),
            (ByteFault::Truncate(2), b"ab", None),
            (
                ByteFault::Corrupt {
                    offset: Some(1),
                    xor: 1,
                },
                b"acc",
                None,
            ),
            (ByteFault::Replace(b"z".to_vec()), b"z", None),
            (ByteFault::Drop(Some(usize::MAX..usize::MAX)), b"abc", None),
        ];
        let mut faults = Faults::new(7, 16, 2);
        for (fault, expected, at) in cases {
            let mut out = vec![42];
            let marker = faults
                .bytes(
                    &[Rule {
                        when: Trigger::Always,
                        fault,
                    }],
                    b"abc",
                    &mut out,
                )
                .unwrap();
            assert_eq!(out[0], 42);
            assert_eq!(&out[1..], expected);
            assert_eq!(
                marker,
                at.map(|at| FaultDelay {
                    at,
                    duration: delay
                })
            );
        }
        let plan = [Rule {
            when: Trigger::Always,
            fault: ByteFault::Repeat {
                range: None,
                copies: usize::MAX,
            },
        }];
        let mut out = vec![42];
        assert!(faults.bytes(&plan, b"abc", &mut out).is_err());
        assert_eq!(out, [42]);
        faults.bytes(&plan, b"", &mut out).unwrap();
        // Prefix and range fit, but the trailing bytes exceed the limit.
        let mut faults = Faults::new(0, 4, 0);
        let plan = [Rule {
            when: Trigger::Always,
            fault: ByteFault::Repeat {
                range: Some(0..1),
                copies: 2,
            },
        }];
        assert!(faults.bytes(&plan, b"abc", &mut out).is_err());
        assert_eq!(out, [42]);
    }

    #[test]
    fn holds_obey_windows_flush_and_both_queue_bounds() {
        let mut faults = Faults::new(0, 4, 2);
        let hold = rule(ItemFault::<modbus::Frame>::Hold { window: 2 });
        let mut out = Vec::new();
        faults.item(&hold, b"a", &mut out).unwrap();
        faults.item(&hold, b"b", &mut out).unwrap();
        assert_eq!((faults.held_count(), faults.held_bytes()), (2, 2));
        assert_eq!(
            faults.item(&hold, b"", &mut out),
            Err(FaultError::HeldLimit { limit: 2 })
        );
        faults.item::<modbus::Frame>(&[], b"c", &mut out).unwrap();
        assert_eq!(out, b"ca");
        faults.flush(&mut out).unwrap();
        assert_eq!(out, b"cab");
        faults.flush(&mut out).unwrap();
        assert_eq!((faults.held_count(), faults.held_bytes()), (0, 0));
        faults.item(&hold, b"abcd", &mut Vec::new()).unwrap();
        assert!(faults.item(&hold, b"e", &mut Vec::new()).is_err());
        assert_eq!(faults.held_bytes(), 4);
        assert!(faults.flush(&mut out).is_err());
        assert_eq!(out, b"cab");
        assert_eq!(faults.held_bytes(), 4);
        out.clear();
        faults.flush(&mut out).unwrap();
        assert_eq!(out, b"abcd");
        out.clear();
        faults
            .item(
                &rule(ItemFault::<modbus::Frame>::Hold { window: 0 }),
                b"z",
                &mut out,
            )
            .unwrap();
        assert_eq!(out, b"z");
        assert_eq!(faults.held_count(), 0);
        let mut faults = Faults::new(0, 0, 1);
        faults.item(&hold, b"", &mut Vec::new()).unwrap();
        assert!(faults.item(&hold, b"", &mut Vec::new()).is_err());
        faults.flush(&mut Vec::new()).unwrap();
    }

    #[test]
    fn due_release_failure_preserves_queue_and_output() {
        let mut faults = Faults::new(0, 3, 2);
        let hold = rule(ItemFault::<modbus::Frame>::Hold { window: 1 });
        let mut out = vec![42];
        faults.item(&hold, b"ab", &mut out).unwrap();
        assert!(faults.item::<modbus::Frame>(&[], b"c", &mut out).is_err());
        assert_eq!(out, [42]);
        assert_eq!(faults.held_count(), 1);
        out.clear();
        faults.item::<modbus::Frame>(&[], b"c", &mut out).unwrap();
        assert_eq!(out, b"cab");
    }

    #[test]
    fn shorter_windows_release_without_waiting_for_older_holds() {
        let mut faults = Faults::new(0, 16, 4);
        let mut out = Vec::new();
        faults
            .item(
                &rule(ItemFault::<modbus::Frame>::Hold { window: u64::MAX }),
                b"a",
                &mut out,
            )
            .unwrap();
        faults
            .item(
                &rule(ItemFault::<modbus::Frame>::Hold { window: 1 }),
                b"b",
                &mut out,
            )
            .unwrap();
        faults
            .item(
                &rule(ItemFault::<modbus::Frame>::Action {
                    delay: None,
                    rewrite: Rewrite::Drop,
                }),
                b"c",
                &mut out,
            )
            .unwrap();
        assert_eq!(out, b"b");
        faults.flush(&mut out).unwrap();
        assert_eq!(out, b"ba");
    }

    #[test]
    fn actions_combine_delay_with_raw_and_strict_replacements() {
        let mut faults = Faults::new(0, 64, 2);
        let duration = Duration::from_millis(1);
        let delay = Some(duration);
        let mut out = vec![42];
        let frame = modbus::Frame {
            transaction: 1,
            unit: 1,
            pdu: vec![3],
        };
        let plan = rule(ItemFault::Action {
            delay,
            rewrite: Rewrite::Replace(vec![frame.clone()]),
        });
        assert_eq!(
            faults.item(&plan, b"original", &mut out).unwrap(),
            Some(FaultDelay { at: 1, duration })
        );
        assert_eq!(
            test_support::decode_all(Frames::<modbus::Frame>::new, &out[1..]).0,
            core::slice::from_ref(&frame)
        );
        let before = out.clone();
        let invalid = modbus::Frame {
            pdu: vec![],
            ..frame
        };
        assert!(
            faults
                .item(
                    &rule(ItemFault::Action {
                        delay,
                        rewrite: Rewrite::Replace(vec![invalid])
                    }),
                    b"",
                    &mut out
                )
                .is_err()
        );
        assert_eq!(out, before);
        let raw = rule(ItemFault::<modbus::Frame>::Action {
            delay,
            rewrite: Rewrite::Raw(b"raw".to_vec()),
        });
        let start = out.len();
        assert_eq!(faults.item(&raw, b"", &mut out).unwrap().unwrap().at, start);
        assert_eq!(&out[start..], b"raw");
    }

    #[test]
    fn triggers_cover_windows_wide_chance_and_counter_exhaustion() {
        let mut faults = Faults::new(27, 16, 0);
        assert!(!faults.matches(Trigger::After(2), Some(1)));
        assert!(faults.matches(Trigger::After(2), Some(2)));
        assert!(faults.matches(Trigger::After(2), Some(3)));
        for (call, expected) in [(1, false), (2, true), (3, true), (4, false)] {
            assert_eq!(
                faults.matches(Trigger::Window { start: 2, end: 3 }, Some(call)),
                expected
            );
        }
        assert!(!faults.matches(Trigger::Window { start: 3, end: 2 }, Some(3)));
        assert!(!faults.matches(Trigger::Every(0), Some(1)));
        assert!(!faults.matches(Trigger::At(0), Some(1)));
        assert!(!faults.matches(
            Trigger::Chance {
                take: u32::MAX,
                out_of: 0
            },
            Some(1)
        ));
        let draw = |seed| {
            let mut faults = Faults::new(seed, 16, 0);
            (0..1000)
                .map(|_| {
                    faults.matches(
                        Trigger::Chance {
                            take: 1 << 31,
                            out_of: u32::MAX,
                        },
                        Some(1),
                    )
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(draw(27), draw(27));
        assert_ne!(draw(27), draw(28));
        let hits = draw(27).into_iter().filter(|hit| *hit).count();
        assert!((400..600).contains(&hits), "{hits}");
        faults.item_at = Some(u64::MAX);
        let plan = rule(ItemFault::<modbus::Frame>::Action {
            delay: None,
            rewrite: Rewrite::Drop,
        });
        let mut out = Vec::new();
        faults.item(&plan, b"a", &mut out).unwrap();
        faults.item(&plan, b"b", &mut out).unwrap();
        assert_eq!(out, b"b");
    }
}
