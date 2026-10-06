extern crate alloc;

use alloc::{collections::VecDeque, vec::Vec};
use core::ops::Range;
use fictionet::stdlib::codec::{Buffer, Decode, Fail, Stream, StreamEvent};

/// Direction of bytes relative to the client endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// A request or other bytes sent by the client.
    ClientToServer,
    /// A response or other bytes sent by the server.
    ServerToClient,
}

/// What a retained transcript entry describes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecordKind<T, E> {
    /// An owned copy of a decoded item.
    Item(T),
    /// Nonempty bytes consumed without an item. Zero-byte skips are omitted.
    Skipped,
    /// Clean completion. The entry has an empty byte range.
    Ended,
    /// A terminal failure. The full range identifies unread bytes at failure.
    Failed(Fail<E>),
}

/// One observation in decoding order, with its original wire bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record<T, E> {
    /// Caller-assigned stream key. Together with direction, it identifies offsets.
    pub tag: u64,
    /// Endpoint direction. Each direction has its own stream offsets.
    pub direction: Direction,
    /// Consumed bytes for items and skips; unread bytes for failures.
    /// Offsets saturate at `u64::MAX`, as they do in [`Stream`].
    pub range: Range<u64>,
    /// Whether the byte budget kept only a prefix of the observed bytes.
    pub truncated: bool,
    /// Retained prefix of exact driver bytes. Never reconstructed with a writer.
    pub bytes: Vec<u8>,
    /// Item, skip, end, or failure details.
    pub kind: RecordKind<T, E>,
}

/// A transcript bounded by entry count and retained wire bytes.
///
/// Entries are evicted oldest first to fit both limits. Bytes larger than
/// the budget are truncated; the kind and full range survive, including
/// for skips and terminal failures. Storage is reserved before eviction.
/// Allocation refusal drops only the incoming entry. [`dropped`](Self::dropped)
/// counts all lost entries, including evictions, and saturates at `u64::MAX`.
/// A zero entry limit disables retention. A zero byte limit keeps entry
/// metadata with empty bytes and marks nonempty observations truncated.
///
/// The byte limit counts `Record::bytes`, not storage inside cloned items
/// or errors. Those keep their decoder's named limits; the entry limit
/// bounds how many such values are held. Allocator overhead is separate.
/// Use one recorder for all Demux keys and directions under one budget.
/// Assign each stream a numeric tag with [`observer`](Self::observer).
/// Untagged calls use zero. The recorder does not infer stream identity.
///
/// ```
/// use fictionet::stdlib::{codec::{Direction, Interceptor, Recorder, Rewrite, Stream}, modbus};
/// let mut stream = Stream::new(modbus::Frames);
/// let mut log = Recorder::new(16, 1024);
/// let proxy = Interceptor::new(1024);
/// let input = [0, 1, 0, 0, 0, 2, 1, 3];
/// let mut out = Vec::new();
/// assert_eq!(stream.push(&input), input.len());
/// stream.end();
/// while let Some(result) = proxy.next_observed(&mut stream, &mut out,
///     |_, _, _| Rewrite::Forward, log.observer(7, Direction::ClientToServer)) {
///     result?;
/// }
/// assert_eq!(out, input);
/// assert_eq!(log.len(), 2); // item, then end
/// assert_eq!(log.iter().next().unwrap().bytes, input);
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
#[derive(Clone, Debug)]
pub struct Recorder<T, E> {
    entries: VecDeque<Record<T, E>>,
    max_entries: usize,
    max_bytes: usize,
    retained: usize,
    dropped: u64,
}
impl<T, E> Recorder<T, E> {
    /// Sets both bounds. Entry count is clamped to a representable
    /// allocation size. Wire bytes are clamped to [`Buffer::MAX_LIMIT`].
    /// Storage is allocated only when an entry is retained.
    pub fn new(max_entries: usize, max_bytes: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            max_entries: max_entries
                .min((isize::MAX as usize) / core::mem::size_of::<Record<T, E>>().max(1)),
            max_bytes: max_bytes.min(Buffer::MAX_LIMIT),
            retained: 0,
            dropped: 0,
        }
    }

    /// Retained entries, oldest first.
    pub fn iter(&self) -> impl DoubleEndedIterator<Item = &Record<T, E>> {
        self.entries.iter()
    }

    /// Number of retained entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the transcript retains no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Total retained original wire bytes.
    pub fn retained_bytes(&self) -> usize {
        self.retained
    }

    /// Maximum number of retained entries.
    pub fn max_entries(&self) -> usize {
        self.max_entries
    }

    /// Maximum retained original wire bytes.
    pub fn max_bytes(&self) -> usize {
        self.max_bytes
    }

    /// Entries lost to bounds or allocation refusal, including evictions.
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Transfers the oldest entry to the caller without counting it as lost.
    pub fn pop_front(&mut self) -> Option<Record<T, E>> {
        let entry = self.entries.pop_front()?;
        self.retained = self.retained.saturating_sub(entry.bytes.len());
        Some(entry)
    }
}
impl<T: Clone, E: Clone> Recorder<T, E> {
    /// Copies a driver observation with tag zero. Returns whether retained.
    /// Byte truncation preserves the full range and kind under the budget.
    pub fn observe(&mut self, direction: Direction, event: StreamEvent<'_, T, E>) -> bool {
        self.observe_tagged(0, direction, event)
    }

    /// Copies an observation with a caller-assigned stream key. Count and
    /// byte limits are shared across all tags and directions. Empty skips
    /// are ignored without eviction or incrementing the dropped count.
    pub fn observe_tagged(
        &mut self,
        tag: u64,
        direction: Direction,
        event: StreamEvent<'_, T, E>,
    ) -> bool {
        if matches!(event, StreamEvent::Skipped { bytes: [], .. }) {
            return false;
        }
        let (bytes, range) = match &event {
            StreamEvent::Item { bytes, range, .. }
            | StreamEvent::Skipped { bytes, range }
            | StreamEvent::Failed { bytes, range, .. } => (*bytes, range.clone()),
            StreamEvent::Ended { offset } => (&[][..], *offset..*offset),
        };
        if self.max_entries == 0 {
            self.dropped = self.dropped.saturating_add(1);
            return false;
        }
        let keep = bytes.len().min(self.max_bytes);
        let mut owned = Vec::new();
        // Keep deque growth local for copy-and-own. Faults uses a heap
        // and a temporary vector with their own reservation bounds.
        let target = self
            .entries
            .capacity()
            .saturating_mul(2)
            .max(1)
            .min(self.max_entries);
        if owned.try_reserve_exact(keep).is_err()
            || (self.entries.len() == self.entries.capacity()
                && self.entries.len() < self.max_entries
                && self
                    .entries
                    .try_reserve_exact(target.saturating_sub(self.entries.len()))
                    .is_err())
        {
            self.dropped = self.dropped.saturating_add(1);
            return false;
        }
        owned.extend_from_slice(&bytes[..keep]);
        let kind = match event {
            StreamEvent::Item { item, .. } => RecordKind::Item(item.clone()),
            StreamEvent::Skipped { .. } => RecordKind::Skipped,
            StreamEvent::Ended { .. } => RecordKind::Ended,
            StreamEvent::Failed { error, .. } => RecordKind::Failed(error.clone()),
        };
        while self.entries.len() >= self.max_entries
            || keep > self.max_bytes.saturating_sub(self.retained)
        {
            if self.pop_front().is_none() {
                break;
            }
            self.dropped = self.dropped.saturating_add(1);
        }
        self.retained = self.retained.saturating_add(owned.len());
        self.entries.push_back(Record {
            tag,
            direction,
            truncated: keep < bytes.len(),
            range,
            bytes: owned,
            kind,
        });
        true
    }

    /// Returns an observer for a keyed stream direction. Pass it to
    /// [`Interceptor::next_observed`](fictionet::stdlib::codec::Interceptor::next_observed)
    /// or [`Faults::next_with_observed`](fictionet::stdlib::codec::Faults::next_with_observed)
    /// to record and rewrite in one pass, including skipped bytes.
    pub fn observer(
        &mut self,
        tag: u64,
        direction: Direction,
    ) -> impl FnMut(StreamEvent<'_, T, E>) + '_ {
        move |event| {
            self.observe_tagged(tag, direction, event);
        }
    }

    /// Drives one item while recording every skip and terminal event along
    /// the way. The callback receives the owned item and its borrowed bytes
    /// after recording. For recording with rewrites or faults, pass
    /// [`observer`](Self::observer) to `Interceptor::next_with_observed` or
    /// `Faults::next_with_observed`. Those forward skips in the same pass.
    /// Waiting for input allocates and copies nothing.
    pub fn with_next<D: Decode<Item = T, Error = E>, R>(
        &mut self,
        direction: Direction,
        stream: &mut Stream<D>,
        f: impl FnOnce(T, &[u8], Range<u64>) -> R,
    ) -> Option<Result<R, Fail<E>>> {
        self.with_next_tagged(0, direction, stream, f)
    }

    /// Drives and records one keyed stream. Use one recorder across every
    /// Demux key to keep an aggregate transcript bound. Offsets are local
    /// to the supplied stream; the key and direction label them.
    pub fn with_next_tagged<D: Decode<Item = T, Error = E>, R>(
        &mut self,
        tag: u64,
        direction: Direction,
        stream: &mut Stream<D>,
        f: impl FnOnce(T, &[u8], Range<u64>) -> R,
    ) -> Option<Result<R, Fail<E>>> {
        stream.with_next_observed(f, |event| {
            self.observe_tagged(tag, direction, event);
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::{
        codec::{Ending, Lines},
        json, modbus,
    };

    #[test]
    fn empty_skips_do_not_evict_real_entries() {
        let mut log = Recorder::<(), core::convert::Infallible>::new(1, 4);
        assert!(log.observe(
            Direction::ClientToServer,
            StreamEvent::Skipped {
                bytes: b"data",
                range: 0..4
            }
        ));
        for _ in 0..1000 {
            assert!(!log.observe(
                Direction::ClientToServer,
                StreamEvent::Skipped {
                    bytes: b"",
                    range: 4..4
                }
            ));
        }
        assert_eq!(log.len(), 1);
        assert_eq!(log.dropped(), 0);
        assert_eq!(log.iter().next().unwrap().bytes, b"data");
    }

    #[test]
    fn bounds_drop_oldest_and_truncate_oversized_incoming() {
        let mut log = Recorder::<u8, core::convert::Infallible>::new(2, 3);
        for i in 0..3u8 {
            assert!(log.observe(
                Direction::ClientToServer,
                StreamEvent::Item {
                    item: &i,
                    bytes: &[i],
                    range: u64::from(i)..u64::from(i) + 1,
                }
            ));
        }
        assert_eq!(log.len(), 2);
        assert_eq!(log.dropped(), 1);
        assert!(log.observe(
            Direction::ServerToClient,
            StreamEvent::Skipped {
                bytes: b"long",
                range: 0..4
            }
        ));
        assert_eq!(log.dropped(), 3);
        let entry = log.iter().next().unwrap();
        assert_eq!(entry.bytes, b"lon");
        assert_eq!(entry.range, 0..4);
        assert!(entry.truncated);
        assert!(log.observe(
            Direction::ServerToClient,
            StreamEvent::Skipped {
                bytes: b"abc",
                range: 0..3
            }
        ));
        assert_eq!(log.len(), 1);
        assert_eq!(log.retained_bytes(), 3);
        assert_eq!(log.dropped(), 4);
        log.pop_front();
        assert!(log.is_empty());
        assert_eq!(log.retained_bytes(), 0);
    }

    #[test]
    fn skips_and_end_have_exact_bytes_and_offsets() {
        let mut stream = Stream::new(Lines::new(1, Ending::LfOrCrlf));
        let mut log = Recorder::new(32, 32);
        for byte in b"abcdef\nx\n" {
            assert_eq!(stream.push(&[*byte]), 1);
            while let Some(r) = log.with_next(Direction::ClientToServer, &mut stream, |_, _, _| ())
            {
                r.unwrap();
            }
        }
        stream.end();
        for _ in 0..2 {
            assert!(
                log.with_next(Direction::ClientToServer, &mut stream, |_, _, _| ())
                    .is_none()
            );
        }
        let bytes: Vec<_> = log.iter().flat_map(|r| r.bytes.iter().copied()).collect();
        assert_eq!(bytes, b"abcdef\nx\n");
        assert!(
            log.iter()
                .any(|r| r.kind == RecordKind::Skipped && r.bytes == b"d")
        );
        assert_eq!(log.iter().last().unwrap().range, 9..9);
        assert_eq!(
            log.iter().filter(|r| r.kind == RecordKind::Ended).count(),
            1
        );
    }

    #[test]
    fn failures_are_recorded_once_with_unread_bytes() {
        let mut stream = Stream::new(modbus::Frames);
        let mut log = Recorder::new(4, 16);
        assert_eq!(stream.push(b"abc"), 3);
        stream.end();
        assert!(
            log.with_next(Direction::ServerToClient, &mut stream, |_, _, _| ())
                .unwrap()
                .is_err()
        );
        assert!(
            log.with_next(Direction::ServerToClient, &mut stream, |_, _, _| ())
                .is_none()
        );
        let entry = log.iter().next().unwrap();
        assert_eq!(
            entry.kind,
            RecordKind::Failed(Fail::Truncated { unread: 3 })
        );
        assert_eq!(entry.bytes, b"abc");
        assert_eq!(entry.range, 0..3);
    }

    #[test]
    fn zero_limits_and_idle_calls() {
        let mut stream = Stream::new(json::Values::new());
        let mut log = Recorder::new(0, 0);
        assert!(
            log.with_next(Direction::ClientToServer, &mut stream, |_, _, _| ())
                .is_none()
        );
        assert_eq!(log.dropped(), 0);
        stream.end();
        log.with_next(Direction::ClientToServer, &mut stream, |_, _, _| ());
        assert_eq!(log.dropped(), 1);
        let mut log = Recorder::<(), core::convert::Infallible>::new(1, 0);
        assert!(log.observe(Direction::ClientToServer, StreamEvent::Ended { offset: 0 }));
        assert_eq!(log.retained_bytes(), 0);
        assert_eq!(log.len(), 1);
    }
}
