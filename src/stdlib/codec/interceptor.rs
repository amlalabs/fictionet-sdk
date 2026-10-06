extern crate alloc;

use alloc::vec::Vec;
use core::{error::Error, fmt, ops::Range};
use fictionet::stdlib::codec::{Buffer, Decode, Fail, Stream, Wire};

/// A policy decision for one item's consumed bytes.
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

/// Why one replacement could not be written.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RewriteError<E> {
    /// A replacement writer refused a value.
    Write(E),
    /// The resulting destination would exceed its configured byte limit.
    TooLong {
        /// Maximum total destination length, including its existing prefix.
        limit: usize,
    },
    /// Storage for the output could not be reserved.
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
    /// The item was consumed, but its replacement appended nothing.
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

/// Forwards or rewrites one direction of a byte stream without I/O.
///
/// Use two instances and two streams for a bidirectional proxy. The world
/// owns input, output, mode changes, and EOF. Call [`next`](Self::next)
/// after pushing bytes, and again after [`Stream::end`]. Each call handles
/// at most one item. Skips emit no output. Use a recorder to retain skips.
/// A [`Demux`](fictionet::stdlib::codec::Demux) exposes its keyed streams
/// through `get_mut`; direct driving must respect its shared byte budget.
///
/// Forwarding copies only the bytes reported by [`Stream::with_next`].
/// A Pipe's inner items usually consume zero outer bytes. Forwarding such
/// an item emits nothing. Rewriting it requires the caller to frame it in
/// the outer protocol with [`apply_with`](Self::apply_with). A transparent
/// proxy should intercept the outer framing before feeding its payloads
/// into a Pipe. No inner-to-outer framing is inferred here.
///
/// ```
/// use fictionet::stdlib::{codec::{Interceptor, Rewrite, Stream}, modbus};
/// let mut stream = Stream::new(modbus::Frames);
/// let proxy = Interceptor::new(1024);
/// let input = [0, 1, 0, 0, 0, 2, 1, 3];
/// assert_eq!(stream.push(&input), input.len());
/// let mut out = Vec::new();
/// proxy.next(&mut stream, &mut out, |_, _, _| Rewrite::<modbus::Frame>::Forward)
///     .unwrap()?;
/// assert_eq!(out, input);
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
#[derive(Clone, Copy, Debug)]
pub struct Interceptor {
    limit: usize,
}
impl Interceptor {
    /// Bounds the total length of each supplied output vector. Clamps to
    /// [`Buffer::MAX_LIMIT`]. Drain or clear output between calls as needed.
    /// No output queue is retained by this type.
    pub fn new(limit: usize) -> Self {
        Self {
            limit: limit.min(Buffer::MAX_LIMIT),
        }
    }

    /// Maximum destination length accepted by this interceptor.
    pub fn limit(&self) -> usize {
        self.limit
    }

    /// Takes one item and applies the policy to its original bytes.
    /// Replacement values can differ from the decoder's item type, so
    /// mapped results and Pipe items need no `Wire` implementation.
    /// `None` means input is needed or the stream has ended. Decode errors
    /// are returned once. A write error consumes its item; unread input
    /// remains available. Every error leaves `out` unchanged for this call.
    #[allow(clippy::type_complexity)]
    pub fn next<D: Decode, T: Wire>(
        &self,
        stream: &mut Stream<D>,
        out: &mut Vec<u8>,
        policy: impl FnOnce(&D::Item, &[u8], Range<u64>) -> Rewrite<T>,
    ) -> Option<Result<(), InterceptError<D::Error, T::WriteError>>>
    where
        D::Error: Clone,
    {
        stream
            .with_next(|item, raw, range| self.apply(raw, policy(&item, raw, range), out))
            .map(|r| {
                r.map_err(InterceptError::Decode)?
                    .map_err(InterceptError::Rewrite)
            })
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
        self.apply_with(raw, rewrite, out, T::write)
    }

    /// Applies a decision with caller-owned framing for replacements.
    /// The writer receives an empty scratch vector per value. It must
    /// bound that vector and encode a complete valid outer unit on success.
    /// Use this for line endings or context-dependent Pipe framing.
    /// A writer failure or output limit error rolls back the entire call.
    /// Forward, Drop, Raw, and Repeat never call the writer.
    pub fn apply_with<T, E>(
        &self,
        raw: &[u8],
        rewrite: Rewrite<T>,
        out: &mut Vec<u8>,
        mut write: impl FnMut(&T, &mut Vec<u8>) -> Result<(), E>,
    ) -> Result<(), RewriteError<E>> {
        let start = out.len();
        let result = (|| {
            if start > self.limit {
                return Err(RewriteError::TooLong { limit: self.limit });
            }
            match rewrite {
                Rewrite::Forward => self.append(raw, 1, out),
                Rewrite::Drop => Ok(()),
                Rewrite::Raw(bytes) => self.append(&bytes, 1, out),
                Rewrite::Repeat(copies) => self.append(raw, copies, out),
                Rewrite::Replace(items) => {
                    let mut scratch = Vec::new();
                    for item in items {
                        scratch.clear();
                        write(&item, &mut scratch).map_err(RewriteError::Write)?;
                        self.append(&scratch, 1, out)?;
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

    fn append<E>(
        &self,
        bytes: &[u8],
        copies: usize,
        out: &mut Vec<u8>,
    ) -> Result<(), RewriteError<E>> {
        let added = bytes
            .len()
            .checked_mul(copies)
            .filter(|n| *n <= self.limit.saturating_sub(out.len()))
            .ok_or(RewriteError::TooLong { limit: self.limit })?;
        if added == 0 {
            return Ok(());
        }
        let size = out
            .len()
            .checked_add(added)
            .ok_or(RewriteError::TooLong { limit: self.limit })?;
        if size > out.capacity() {
            let target = size.max(out.capacity().saturating_mul(2)).min(self.limit);
            out.try_reserve_exact(target.saturating_sub(out.len()))
                .map_err(|_| RewriteError::Allocation)?;
        }
        for _ in 0..copies {
            out.extend_from_slice(bytes);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::{codec::test_support::decode_all, json, modbus};

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
