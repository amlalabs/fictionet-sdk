//! `Stream`, `pump` and `finish` over the real `Frames` decoder and over
//! decoders whose every step is chosen by the solver.
//!
//! The first harness is the framing theorem: items framed through any
//! chunking are exactly the values written, with nothing lost, duplicated
//! or reordered, and a trailing partial frame is reported as truncation.
//! The second is the regression for the stale buffer limit: a decoder that
//! raises its capacity on a zero-byte skip must not be reported stuck. The
//! third checks the stream's own safety against any decoder behaviour, and
//! the fourth that a decoder keeping the documented contract is never
//! reported stuck.

extern crate alloc;

use super::bytes;
use alloc::vec::Vec;
use core::{convert::Infallible, fmt};
use fictionet::stdlib::codec::{Decode, Fail, Frames, Prefixed, Step, Stream, Wire, finish, pump};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Bad;
impl fmt::Display for Bad {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("bad")
    }
}
impl core::error::Error for Bad {}

/// One length byte and at most three payload bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Blob(Vec<u8>);
const MAX_BLOB: usize = 3;
impl Wire for Blob {
    type ParseError = Bad;
    type WriteError = Bad;
    fn parse(b: &[u8]) -> Result<Self, Bad> {
        match Self::parse_prefix(b, &())? {
            Some((blob, used)) if used == b.len() => Ok(blob),
            _ => Err(Bad),
        }
    }
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Bad> {
        if self.0.len() > MAX_BLOB {
            return Err(Bad);
        }
        out.push(self.0.len() as u8);
        out.extend_from_slice(&self.0);
        Ok(())
    }
}
impl Prefixed for Blob {
    type Item = Blob;
    type Error = Bad;
    type Limit = ();
    const NAME: &'static str = "blob";
    fn default_limit() -> Self::Limit {}
    fn capacity(_: &Self::Limit) -> usize {
        1 + MAX_BLOB
    }
    fn parse_prefix(input: &[u8], _: &Self::Limit) -> Result<Option<(Blob, usize)>, Bad> {
        let Some(&n) = input.first() else {
            return Ok(None);
        };
        let n = usize::from(n);
        if n > MAX_BLOB {
            return Err(Bad);
        }
        Ok(input.get(1..1 + n).map(|p| (Blob(p.to_vec()), 1 + n)))
    }
}

/// Pushes `wire` through `stream` in chunks the solver chooses, returning
/// the items; every chunk must be taken whole.
fn pump_in_chunks<D: Decode>(stream: &mut Stream<D>, wire: &[u8]) -> Vec<D::Item>
where
    D::Error: Clone + fmt::Debug,
{
    let mut items = Vec::new();
    let mut fed = 0;
    while fed < wire.len() {
        let chunk: usize = kani::any();
        kani::assume(chunk >= 1 && chunk <= wire.len() - fed);
        let taken = pump(stream, &wire[fed..fed + chunk], |item| items.push(item)).unwrap();
        assert_eq!(taken, chunk);
        fed += chunk;
    }
    items
}

#[kani::proof]
#[kani::unwind(12)]
fn frames_through_any_chunking_lose_or_duplicate_nothing() {
    let (a, alen) = bytes::<2>();
    let (b, blen) = bytes::<2>();
    let blobs = [Blob(a[..alen].to_vec()), Blob(b[..blen].to_vec())];
    let mut wire = Vec::new();
    for blob in &blobs {
        blob.write(&mut wire).unwrap();
    }
    let partial: bool = kani::any();
    if partial {
        wire.push(2);
        wire.push(kani::any());
    }
    let mut stream = Stream::new(Frames::<Blob>::new());
    let mut items = pump_in_chunks(&mut stream, &wire);
    let ended = finish(&mut stream, |item| items.push(item));
    assert_eq!(items, blobs);
    if partial {
        assert_eq!(ended, Err(Fail::Truncated { unread: 2 }));
        assert_eq!(stream.unread(), &wire[wire.len() - 2..]);
    } else {
        assert_eq!(ended, Ok(()));
        assert!(stream.is_done());
        assert!(stream.unread().is_empty());
    }
    assert_eq!(stream.offset(), (wire.len() - stream.unread().len()) as u64);
}

/// Reads the first byte as the width of every record, including that byte,
/// and raises its capacity to that width without consuming anything.
struct Widening {
    width: usize,
}
impl Decode for Widening {
    type Item = Vec<u8>;
    type Error = Infallible;
    const NAME: &'static str = "widening";
    fn capacity(&self) -> usize {
        self.width
    }
    fn decode(&mut self, input: &[u8], _: bool) -> Result<Step<Vec<u8>>, Infallible> {
        if self.width == 1 {
            let Some(&first) = input.first() else {
                return Ok(Step::Need);
            };
            self.width = usize::from(first.clamp(2, 4));
            return Ok(Step::Skip(0));
        }
        Ok(match input.get(..self.width) {
            Some(record) => Step::Item(record.to_vec(), self.width),
            None => Step::Need,
        })
    }
}

#[kani::proof]
#[kani::unwind(10)]
fn a_skip_that_raises_capacity_is_not_stuck() {
    let (data, len) = bytes::<5>();
    kani::assume(len >= 1);
    let data = &data[..len];
    let width = usize::from(data[0].clamp(2, 4));
    let mut stream = Stream::new(Widening { width: 1 });
    let mut items = pump_in_chunks(&mut stream, data);
    let ended = finish(&mut stream, |item| items.push(item));
    assert_eq!(items.len(), len / width);
    for (i, item) in items.iter().enumerate() {
        assert_eq!(item, &data[i * width..(i + 1) * width]);
    }
    let rest = len % width;
    if rest == 0 {
        assert_eq!(ended, Ok(()));
    } else {
        assert_eq!(ended, Err(Fail::Truncated { unread: rest }));
    }
    assert_eq!(stream.offset(), (len - rest) as u64);
}

/// A decoder whose every answer the solver chooses. `honest` restricts the
/// choices to the `Decode` contract; without it anything goes.
struct Chaos {
    held: usize,
    capacity: usize,
    /// Zero-byte skips still allowed in this `next` call, under the contract:
    /// one more than the most bytes held during the run.
    zero_steps: usize,
    high: usize,
    honest: bool,
}
const MAX_HELD: usize = 2;
const MAX_CAPACITY: usize = 4;
impl Chaos {
    fn new(honest: bool) -> Self {
        let held: usize = kani::any();
        kani::assume(held <= MAX_HELD);
        let capacity: usize = kani::any();
        kani::assume((1..=MAX_CAPACITY).contains(&capacity));
        Self {
            held,
            capacity,
            zero_steps: held + 1,
            high: held,
            honest,
        }
    }
    fn begin_call(&mut self) {
        self.zero_steps = self.held + 1;
        self.high = self.held;
    }
}
impl Decode for Chaos {
    type Item = usize;
    type Error = Bad;
    const NAME: &'static str = "chaos";
    fn capacity(&self) -> usize {
        self.capacity
    }
    fn held(&self) -> usize {
        self.held
    }
    fn decode(&mut self, input: &[u8], eof: bool) -> Result<Step<usize>, Bad> {
        let before = self.held;
        let held: usize = kani::any();
        kani::assume(held <= MAX_HELD);
        let capacity: usize = kani::any();
        kani::assume((1..=MAX_CAPACITY).contains(&capacity));
        let choice: u8 = kani::any();
        let n: usize = kani::any();
        kani::assume(n <= MAX_CAPACITY + 1);
        let step = match choice % 5 {
            0 => Step::Item(n, n),
            1 => Step::Skip(n),
            2 => Step::Need,
            3 => Step::End,
            _ => return Err(Bad),
        };
        if self.honest {
            match &step {
                Step::Item(_, n) | Step::Skip(n) => {
                    kani::assume(*n <= input.len());
                    kani::assume(capacity >= input.len());
                    if *n == 0 && matches!(step, Step::Skip(_)) {
                        // Each byte newly held during the run earns one more step.
                        if held > self.high {
                            self.zero_steps += held - self.high;
                            self.high = held;
                        }
                        kani::assume(self.zero_steps > 0);
                        self.zero_steps -= 1;
                    } else {
                        self.zero_steps = held + 1;
                        self.high = held;
                    }
                }
                Step::Need => {
                    kani::assume(held <= before);
                    kani::assume(input.len() < capacity);
                    let _ = eof;
                }
                Step::End => {}
            }
        }
        self.held = held;
        self.capacity = capacity;
        Ok(step)
    }
}

#[kani::proof]
#[kani::unwind(14)]
fn the_stream_is_safe_against_any_decoder() {
    let (data, len) = bytes::<4>();
    let data = &data[..len];
    let mut stream = Stream::new(Chaos::new(false));
    let mut accepted = 0usize;
    let mut failed = false;
    for _ in 0..3 {
        let push: bool = kani::any();
        if push {
            let at: usize = kani::any();
            kani::assume(at <= len);
            let n = stream.push(&data[at..]);
            assert!(n <= len - at);
            if !stream.is_done() && !stream.is_eof() {
                accepted += n;
                assert!(stream.buffered() <= stream.limit());
            }
        }
        if kani::any() {
            stream.end();
        }
        let before = stream.offset();
        let unread_before = stream.unread().to_vec();
        let result = stream.with_next(|item, raw, range| (item, raw.to_vec(), range));
        match result {
            Some(Ok((_, raw, range))) => {
                assert!(!failed);
                assert_eq!(range.start, before);
                assert_eq!(range.end - range.start, raw.len() as u64);
                assert_eq!(raw, unread_before[..raw.len()]);
                assert_eq!(stream.offset(), range.end);
            }
            Some(Err(fail)) => {
                assert!(!failed);
                failed = true;
                assert!(stream.is_done());
                assert_eq!(stream.failed(), Some(&fail));
                if let Fail::Truncated { unread } = fail {
                    assert!(stream.is_eof());
                    assert_eq!(unread, stream.buffered());
                    assert!(unread > 0);
                }
            }
            None => {}
        }
        assert!(stream.offset() >= before);
        assert_eq!(stream.offset() as usize + stream.buffered(), accepted);
        if failed {
            assert!(stream.is_done());
            assert!(stream.next().is_none());
        }
    }
}

#[kani::proof]
#[kani::unwind(14)]
fn an_honest_decoder_is_never_stuck() {
    let (data, len) = bytes::<4>();
    let data = &data[..len];
    let mut stream = Stream::new(Chaos::new(true));
    for _ in 0..3 {
        if kani::any() {
            let at: usize = kani::any();
            kani::assume(at <= len);
            let _ = stream.push(&data[at..]);
        }
        if kani::any() {
            stream.end();
        }
        stream.decoder().begin_call();
        if let Some(Err(fail)) = stream.next() {
            assert!(!matches!(fail, Fail::Stuck { .. }));
        }
    }
}
