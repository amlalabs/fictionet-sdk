extern crate alloc;

use alloc::vec::Vec;
use core::{error::Error, fmt, ops::Range};
use fictionet::stdlib::codec::{Buffer, Decode, Fail, PumpError, Stream, StreamEvent, Wire};

/// A policy decision for one item's consumed bytes.
/// [`Drop`](Self::Drop) is the canonical empty decision. Empty Replace and
/// Repeat(0) are equivalent so callers can pass computed lists and counts
/// without a separate branch. Raw and Repeat support byte fault plans.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Rewrite<T> {
    /// Copy the original bytes without calling a writer.
    Forward,
    /// Emit no bytes.
    Drop,
    /// Write these values in order. An empty list drops the item.
    Replace(Vec<T>),
    /// Substitute caller-framed bytes without validation.
    Raw(Vec<u8>),
    /// Emit the original bytes this many times, including the first copy.
    /// Zero drops the item. This never re-encodes the value.
    Repeat(usize),
}

/// Why an interception or rewrite could not complete.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RewriteError<E> {
    /// A replacement writer refused a value.
    Write(E),
    /// The resulting destination would exceed its configured byte limit.
    TooLong {
        /// Maximum total destination length, including its existing prefix.
        limit: usize,
    },
    /// Storage could not be reserved.
    Allocation,
}
impl<E: fmt::Display> fmt::Display for RewriteError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Write(e) => write!(f, "replacement writer: {e}"),
            Self::TooLong { limit } => write!(f, "replacement exceeds {limit} output bytes"),
            Self::Allocation => f.write_str("replacement allocation failed"),
        }
    }
}
impl<E: Error> Error for RewriteError<E> {}

/// A stream failure or a refused replacement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InterceptError<D, W> {
    /// The stream's terminal error. The stream retains it too.
    Decode(Fail<D>),
    /// Storage or a replacement was refused. Only this item call was rolled back.
    Rewrite(RewriteError<W>),
}
impl<D: fmt::Display, W: fmt::Display> fmt::Display for InterceptError<D, W> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(e) => e.fmt(f),
            Self::Rewrite(e) => e.fmt(f),
        }
    }
}
impl<D: Error, W: Error> Error for InterceptError<D, W> {}

/// How bytes consumed without an item reach the output.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SkipPolicy {
    /// Preserve every skipped byte, including padding and refused lines.
    #[default]
    Forward,
    /// Discard skipped bytes. The caller owns the resulting framing.
    Drop,
}

/// Forwards or rewrites one direction of a byte stream without I/O.
///
/// Use two instances and two streams for a bidirectional proxy. The world
/// owns input, output, mode changes, and EOF. Call [`next`](Self::next)
/// after pushing bytes, and again after [`Stream::end`]. Each call handles
/// at most one item. Skipped bytes are forwarded by default.
/// A [`Demux`](fictionet::stdlib::codec::Demux) exposes its keyed streams
/// through `get_mut`; direct driving must respect its shared byte budget.
///
/// Forwarding preserves all consumed bytes, including a Pipe's outer
/// payloads. Its inner items usually consume zero outer bytes. Rewriting
/// those items requires caller-owned framing through [`next_with`](Self::next_with)
/// and an explicit skip policy. No inner-to-outer framing is inferred here.
///
/// ```
/// use fictionet::stdlib::{codec::{Interceptor, Rewrite, Stream}, modbus};
/// let mut stream = Stream::new(modbus::Frames);
/// let proxy = Interceptor::new(1024);
/// let input = [0, 1, 0, 0, 0, 2, 1, 3];
/// let mut out = Vec::new();
/// assert_eq!(proxy.intercept(&mut stream, &input, &mut out, |_, _, _| Rewrite::Forward).map_err(|(_, error)| error)?, input.len());
/// assert_eq!(out, input);
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
#[derive(Clone, Copy, Debug)]
pub struct Interceptor {
    limit: usize,
    skips: SkipPolicy,
}
impl Interceptor {
    /// Bounds the total length of each supplied output vector. Clamps to
    /// [`Buffer::MAX_LIMIT`]. Drain or clear output between calls as needed.
    /// No output queue is retained by this type.
    pub fn new(limit: usize) -> Self {
        Self {
            limit: limit.min(Buffer::MAX_LIMIT),
            skips: SkipPolicy::Forward,
        }
    }

    /// Sets how skipped bytes reach output. The default is Forward.
    pub fn with_skips(mut self, skips: SkipPolicy) -> Self {
        self.skips = skips;
        self
    }

    /// Maximum destination length accepted by this interceptor.
    pub fn limit(&self) -> usize {
        self.limit
    }

    /// Takes one item and applies the policy to its original bytes.
    /// Uses the decoded type's Wire writer. For mapped or layered items,
    /// use [`next_with`](Self::next_with) with caller-owned framing.
    /// `None` means input is needed or the stream has ended. Skipped bytes
    /// may still have been appended. Decode errors
    /// are returned once. A write error consumes its item; unread input
    /// remains available. Rewrite errors roll back this call's output.
    /// Decode errors keep consumed skips; unread bytes remain in the stream.
    #[allow(clippy::type_complexity)]
    pub fn next<D: Decode>(
        &self,
        stream: &mut Stream<D>,
        out: &mut Vec<u8>,
        policy: impl FnOnce(&D::Item, &[u8], Range<u64>) -> Rewrite<D::Item>,
    ) -> Option<Result<(), InterceptError<D::Error, <D::Item as Wire>::WriteError>>>
    where
        D::Error: Clone,
        D::Item: Wire,
    {
        self.next_observed(stream, out, policy, |_| {})
    }

    /// Takes one item and observes the same decoding pass. Record original
    /// bytes with [`Recorder::observer`](fictionet::stdlib::codec::Recorder::observer).
    /// Observations precede rewriting and include skips, failure, and end.
    /// Error and skip handling follow [`next`](Self::next).
    #[allow(clippy::type_complexity)]
    pub fn next_observed<D: Decode>(
        &self,
        stream: &mut Stream<D>,
        out: &mut Vec<u8>,
        policy: impl FnOnce(&D::Item, &[u8], Range<u64>) -> Rewrite<D::Item>,
        observe: impl FnMut(StreamEvent<'_, D::Item, D::Error>),
    ) -> Option<Result<(), InterceptError<D::Error, <D::Item as Wire>::WriteError>>>
    where
        D::Error: Clone,
        D::Item: Wire,
    {
        self.next_with_observed(stream, out, policy, write_bounded, observe)
    }

    /// Takes one item using caller-owned framing for replacements.
    /// Skips and the item share one output transaction and one byte limit.
    /// Rewrite errors roll back this call. Decode errors keep consumed skips.
    /// Consumed input is not restored. Skip-only calls may append bytes and
    /// return `None`. The writer follows [`apply_with`](Self::apply_with).
    #[allow(clippy::type_complexity)]
    pub fn next_with<D: Decode, T, E>(
        &self,
        stream: &mut Stream<D>,
        out: &mut Vec<u8>,
        policy: impl FnOnce(&D::Item, &[u8], Range<u64>) -> Rewrite<T>,
        write: impl FnMut(&T, &mut Buffer) -> Result<(), RewriteError<E>>,
    ) -> Option<Result<(), InterceptError<D::Error, E>>>
    where
        D::Error: Clone,
    {
        self.next_with_observed(stream, out, policy, write, |_| {})
    }

    /// Rewrites with caller-owned framing and observes the same pass.
    /// Uses the skip and transaction rules of [`next_with`](Self::next_with).
    #[allow(clippy::type_complexity)]
    pub fn next_with_observed<D: Decode, T, E>(
        &self,
        stream: &mut Stream<D>,
        out: &mut Vec<u8>,
        policy: impl FnOnce(&D::Item, &[u8], Range<u64>) -> Rewrite<T>,
        mut write: impl FnMut(&T, &mut Buffer) -> Result<(), RewriteError<E>>,
        observe: impl FnMut(StreamEvent<'_, D::Item, D::Error>),
    ) -> Option<Result<(), InterceptError<D::Error, E>>>
    where
        D::Error: Clone,
    {
        self.with_next_observed::<D, _, _, E>(
            stream,
            out,
            |item, bytes, range, out| {
                self.apply_with(bytes, &policy(item, bytes, range), out, &mut write)
            },
            observe,
        )
        .map(|r| {
            r.map_err(|e| match e {
                PumpError::Decode(e) => InterceptError::Decode(e),
                PumpError::Handler(e) => InterceptError::Rewrite(e),
            })
        })
    }

    /// Runs an item action inside the shared output transaction. Fault plans
    /// use this entry point to hold or delay items while forwarding skips.
    /// The action must bound its writes and commit its state only on success.
    /// A handler error restores this call's output prefix. A decode failure
    /// keeps consumed skips and is returned once. Observations precede actions.
    ///
    /// With Forward skips, reserves room for all buffered input before driving.
    /// A reservation failure leaves the stream untouched, so no later item or
    /// decode failure is consumed. This may require draining output even when
    /// the action would drop an item. Drop skips only checks the existing prefix.
    /// `E` converts storage errors with writer error type `W`.
    pub fn with_next_observed<D: Decode, R, E, W>(
        &self,
        stream: &mut Stream<D>,
        out: &mut Vec<u8>,
        action: impl FnOnce(&D::Item, &[u8], Range<u64>, &mut Vec<u8>) -> Result<R, E>,
        mut observe: impl FnMut(StreamEvent<'_, D::Item, D::Error>),
    ) -> Option<Result<R, PumpError<D::Error, E>>>
    where
        D::Error: Clone,
        E: From<RewriteError<W>>,
    {
        if stream.is_done() {
            return None;
        }
        let reserve = if self.skips == SkipPolicy::Forward {
            stream.buffered()
        } else {
            0
        };
        if let Err(error) = reserve_output::<W>(out, reserve, self.limit) {
            return Some(Err(PumpError::Handler(error.into())));
        }
        let start = out.len();
        let mut action = Some(action);
        let mut applied = None;
        let result = stream.with_next_observed(
            |_, _, _| (),
            |event| {
                match &event {
                    StreamEvent::Skipped { bytes, .. } if self.skips == SkipPolicy::Forward => {
                        // Every skip comes from the buffer reserved above. There
                        // is no writer or other output mutation before the item.
                        out.extend_from_slice(bytes);
                    }
                    _ => {}
                }
                // Observe the original item before applying its action.
                match event {
                    StreamEvent::Item { item, bytes, range } => {
                        observe(StreamEvent::Item {
                            item,
                            bytes,
                            range: range.clone(),
                        });
                        if let Some(action) = action.take() {
                            applied = Some(action(item, bytes, range, out));
                        }
                    }
                    event => observe(event),
                }
            },
        );
        match result {
            Some(Err(error)) => Some(Err(PumpError::Decode(error))),
            _ => applied.map(|result| {
                result.map_err(|error| {
                    out.truncate(start);
                    PumpError::Handler(error)
                })
            }),
        }
    }

    /// Pushes and drains input, using the decoded type's Wire writer.
    /// Returns the number of bytes accepted. A clean handoff can leave a
    /// suffix unaccepted or unread in the stream. After EOF, no new bytes
    /// are accepted. Call with empty input
    /// after [`Stream::end`] to drain EOF items and trailing skips.
    /// Each item has its own output transaction. Errors return the accepted
    /// byte count and keep earlier items' output. A decode failure also keeps
    /// consumed skips. A rewrite error rolls back only its item call.
    #[allow(clippy::type_complexity)]
    pub fn intercept<D: Decode>(
        &self,
        stream: &mut Stream<D>,
        bytes: &[u8],
        out: &mut Vec<u8>,
        policy: impl FnMut(&D::Item, &[u8], Range<u64>) -> Rewrite<D::Item>,
    ) -> Result<
        usize,
        (
            usize,
            InterceptError<D::Error, <D::Item as Wire>::WriteError>,
        ),
    >
    where
        D::Item: Wire,
        D::Error: Clone,
    {
        self.intercept_with(stream, bytes, out, policy, write_bounded)
    }

    /// Pushes and drains input with caller-owned replacement framing.
    /// This also supports mapped items and combinators without Wire impls.
    /// Acceptance, EOF, and rollback follow [`intercept`](Self::intercept).
    pub fn intercept_with<D: Decode, T, E>(
        &self,
        stream: &mut Stream<D>,
        mut bytes: &[u8],
        out: &mut Vec<u8>,
        mut policy: impl FnMut(&D::Item, &[u8], Range<u64>) -> Rewrite<T>,
        mut write: impl FnMut(&T, &mut Buffer) -> Result<(), RewriteError<E>>,
    ) -> Result<usize, (usize, InterceptError<D::Error, E>)>
    where
        D::Error: Clone,
    {
        let length = bytes.len();
        loop {
            // Drain first so EOF and handoff leave new input unaccepted.
            while let Some(result) = self.next_with(stream, out, &mut policy, &mut write) {
                if let Err(error) = result {
                    return Err((length - bytes.len(), error));
                }
            }
            if bytes.is_empty() || stream.is_done() {
                return Ok(length - bytes.len());
            }
            let taken = stream.push(bytes);
            if taken == 0 {
                // A live, drained stream has room. A refused push means
                // its buffer could not reserve storage. Do not retry here.
                return Err((
                    length - bytes.len(),
                    InterceptError::Rewrite(RewriteError::Allocation),
                ));
            }
            bytes = &bytes[taken..];
        }
    }

    /// Applies a decision to exact bytes supplied by the driver.
    /// Each replacement uses [`Wire::write`]. All replacements for this
    /// item succeed together or leave `out` unchanged. Scratch storage
    /// holds one encoded replacement at a time, under that Wire type's
    /// named limit. The destination stays under this interceptor's limit.
    pub fn apply<T: Wire>(
        &self,
        raw: &[u8],
        rewrite: Rewrite<T>,
        out: &mut Vec<u8>,
    ) -> Result<(), RewriteError<T::WriteError>> {
        self.apply_with(raw, &rewrite, out, write_bounded)
    }

    /// Applies a decision with caller-owned framing for replacements.
    /// The writer receives an empty [`Buffer`] limited to the remaining output
    /// budget per value. Check every `push` count and encode a complete valid
    /// outer unit on success. Scratch length is checked after every write
    /// before copying or calling the writer again. Use [`write_bounded`] to
    /// adapt a Wire value; its temporary encoding uses that type's named limit.
    /// Use this for line endings or context-dependent Pipe framing.
    /// A writer failure or output limit error rolls back the entire call.
    /// Forward, Drop, Raw, and Repeat never call the writer.
    pub fn apply_with<T, E>(
        &self,
        raw: &[u8],
        rewrite: &Rewrite<T>,
        out: &mut Vec<u8>,
        mut write: impl FnMut(&T, &mut Buffer) -> Result<(), RewriteError<E>>,
    ) -> Result<(), RewriteError<E>> {
        let start = out.len();
        let result = (|| {
            if start > self.limit {
                return Err(RewriteError::TooLong { limit: self.limit });
            }
            match rewrite {
                Rewrite::Forward => self.append(raw, 1, out),
                Rewrite::Drop => Ok(()),
                Rewrite::Raw(bytes) => self.append(bytes, 1, out),
                Rewrite::Repeat(copies) => self.append(raw, *copies, out),
                Rewrite::Replace(items) => {
                    for item in items {
                        let remaining = self.limit - out.len();
                        let mut scratch = Buffer::new(remaining);
                        write(item, &mut scratch).map_err(|error| match error {
                            RewriteError::TooLong { .. } => {
                                RewriteError::TooLong { limit: self.limit }
                            }
                            error => error,
                        })?;
                        if scratch.len() > remaining {
                            return Err(RewriteError::TooLong { limit: self.limit });
                        }
                        self.append(scratch.unread(), 1, out)?;
                    }
                    Ok(())
                }
            }
        })();
        if result.is_err() {
            out.truncate(start);
        }
        result
    }

    /// Appends exact bytes a bounded number of times. Shared by fault
    /// plans and rewrites. Checks size and reserves before changing output.
    /// An error leaves output unchanged. Empty input takes constant time.
    pub fn append<E>(
        &self,
        bytes: &[u8],
        copies: usize,
        out: &mut Vec<u8>,
    ) -> Result<(), RewriteError<E>> {
        append_bounded(bytes, copies, out, self.limit)
    }
}

/// Writes a Wire value to a bounded replacement buffer. The temporary
/// encoding uses the Wire type's named limit. Its full length is checked
/// before copying into `out`. Errors leave the unread output unchanged.
/// Use this with [`Interceptor::apply_with`] or fault replacement writers.
pub fn write_bounded<T: Wire>(
    item: &T,
    out: &mut Buffer,
) -> Result<(), RewriteError<T::WriteError>> {
    let mut bytes = Vec::new();
    item.write(&mut bytes).map_err(RewriteError::Write)?;
    if bytes.len() > out.room() {
        return Err(RewriteError::TooLong { limit: out.limit() });
    }
    if out.push(&bytes) != bytes.len() {
        return Err(RewriteError::Allocation);
    }
    Ok(())
}

/// Appends exact bytes under a total destination limit, clamped to
/// [`Buffer::MAX_LIMIT`]. Shared by interceptors and held fault items.
/// Checks multiplication and reserves before writing. Errors leave output
/// unchanged. Empty input takes constant time even for very large counts.
pub fn append_bounded<E>(
    bytes: &[u8],
    copies: usize,
    out: &mut Vec<u8>,
    limit: usize,
) -> Result<(), RewriteError<E>> {
    let limit = limit.min(Buffer::MAX_LIMIT);
    let added = bytes
        .len()
        .checked_mul(copies)
        .ok_or(RewriteError::TooLong { limit })?;
    reserve_output(out, added, limit)?;
    if added != 0 {
        for _ in 0..copies {
            out.extend_from_slice(bytes);
        }
    }
    Ok(())
}

fn reserve_output<E>(out: &mut Vec<u8>, added: usize, limit: usize) -> Result<(), RewriteError<E>> {
    let size = out
        .len()
        .checked_add(added)
        .filter(|size| *size <= limit)
        .ok_or(RewriteError::TooLong { limit })?;
    if size > out.capacity() {
        let target = size.max(out.capacity().saturating_mul(2)).min(limit);
        out.try_reserve_exact(target.saturating_sub(out.len()))
            .map_err(|_| RewriteError::Allocation)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::{codec::test_support::decode_all, json, modbus};

    #[test]
    fn replacement_writer_gets_remaining_budget_and_stops_on_excess() {
        let proxy = Interceptor::new(4);
        let mut out = vec![42];
        let mut budgets = Vec::new();
        let error = proxy
            .apply_with(
                b"",
                &Rewrite::Replace(vec![2, 2, 0]),
                &mut out,
                |length, scratch| {
                    budgets.push(scratch.limit());
                    let bytes = vec![1; *length];
                    let taken = scratch.push(&bytes);
                    assert!(scratch.len() <= scratch.limit());
                    if taken != bytes.len() {
                        return Err(RewriteError::TooLong {
                            limit: scratch.limit(),
                        });
                    }
                    Ok::<_, RewriteError<core::convert::Infallible>>(())
                },
            )
            .unwrap_err();
        assert_eq!(error, RewriteError::TooLong { limit: 4 });
        assert_eq!(budgets, [3, 1]);
        assert_eq!(out, [42]);
    }

    #[test]
    fn two_directions_and_noncanonical_forwarding() {
        let proxies = [Interceptor::new(128), Interceptor::new(128)];
        let mut streams = [
            Stream::new(json::Values::new()),
            Stream::new(json::Values::new()),
        ];
        let request = b"{\"x\": \"\\u0061\"}";
        let reply = b"{\"ok\" : true}";
        for (i, input) in [request.as_slice(), reply.as_slice()]
            .into_iter()
            .enumerate()
        {
            let mut out = Vec::new();
            for byte in input {
                assert_eq!(streams[i].push(core::slice::from_ref(byte)), 1);
                while let Some(r) = proxies[i].next(&mut streams[i], &mut out, |_, _, _| {
                    Rewrite::<json::Value>::Forward
                }) {
                    r.unwrap();
                }
            }
            assert_eq!(out, input);
        }
    }

    #[test]
    fn replacement_batch_rolls_back_and_preserves_write_error() {
        let good = modbus::Frame {
            transaction: 1,
            unit: 1,
            pdu: vec![3],
        };
        let bad = modbus::Frame {
            pdu: vec![],
            ..good.clone()
        };
        let mut out = vec![42];
        let proxy = Interceptor::new(128);
        assert_eq!(
            proxy.apply(b"", Rewrite::Replace(vec![good.clone(), bad]), &mut out),
            Err(RewriteError::Write(modbus::EncodeError::EmptyPdu))
        );
        assert_eq!(out, [42]);
        assert_eq!(
            Interceptor::new(9).apply(
                b"",
                Rewrite::Replace(vec![good.clone(), good.clone()]),
                &mut out
            ),
            Err(RewriteError::TooLong { limit: 9 })
        );
        assert_eq!(out, [42]);
        out.clear();
        proxy
            .apply(b"", Rewrite::Replace(vec![good.clone()]), &mut out)
            .unwrap();
        assert_eq!(decode_all(|| modbus::Frames, &out).0, [good]);
    }

    #[test]
    fn limits_extreme_counts_and_decode_errors() {
        let proxy = Interceptor::new(8);
        let mut out = vec![7];
        assert!(
            proxy
                .apply::<json::Value>(b"xx", Rewrite::Repeat(usize::MAX), &mut out)
                .is_err()
        );
        proxy
            .apply::<json::Value>(b"", Rewrite::Repeat(usize::MAX), &mut out)
            .unwrap();
        assert_eq!(out, [7]);
        let mut stream = Stream::new(modbus::Frames);
        assert_eq!(stream.push(&[0, 0, 0, 1, 0, 2]), 6);
        assert!(matches!(
            proxy.next(&mut stream, &mut out, |_, _, _| {
                Rewrite::<modbus::Frame>::Forward
            }),
            Some(Err(InterceptError::Decode(Fail::Protocol(
                modbus::FrameError::Protocol(1)
            ))))
        ));
        assert_eq!(out, [7]);
        assert!(
            proxy
                .next(&mut stream, &mut out, |_, _, _| {
                    Rewrite::<modbus::Frame>::Forward
                })
                .is_none()
        );
    }
}
