use super::*;
use alloc::{rc::Rc, vec, vec::Vec};
use core::{cell::Cell, convert::Infallible, fmt};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct TestError;
impl fmt::Display for TestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("test error")
    }
}
impl core::error::Error for TestError {}

// Length byte plus at most seven bytes; 0x80 skips, 0xff hands off.
#[derive(Default)]
struct Frames;
impl Decode for Frames {
    type Item = Vec<u8>;
    type Error = TestError;
    const NAME: &'static str = "test frames";
    fn capacity(&self) -> usize {
        8
    }
    fn decode(&mut self, input: &[u8], _: bool) -> Result<Step<Vec<u8>>, TestError> {
        let Some(&first) = input.first() else {
            return Ok(Step::Need);
        };
        match first {
            0xff => Ok(Step::End),
            0x80 => Ok(Step::Skip(1)),
            0..=7 => {
                let n = usize::from(first).saturating_add(1);
                Ok(match input.get(1..n) {
                    Some(b) => Step::Item(b.to_vec(), n),
                    None => Step::Need,
                })
            }
            _ => Err(TestError),
        }
    }
}
struct Pairs;
impl Decode for Pairs {
    type Item = Vec<u8>;
    type Error = TestError;
    const NAME: &'static str = "pairs";
    fn capacity(&self) -> usize {
        2
    }
    fn decode(&mut self, input: &[u8], _: bool) -> Result<Step<Vec<u8>>, TestError> {
        Ok(match input.get(..2) {
            Some(b) => Step::Item(b.to_vec(), 2),
            None => Step::Need,
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Blob(Vec<u8>);
impl Wire for Blob {
    type ParseError = TestError;
    type WriteError = TestError;
    fn parse(b: &[u8]) -> Result<Self, TestError> {
        if b.len() > 64 || b.contains(&0xff) {
            Err(TestError)
        } else {
            Ok(Self(b.to_vec()))
        }
    }
    fn write(&self, out: &mut Vec<u8>) -> Result<(), TestError> {
        Self::parse(&self.0)?;
        out.extend_from_slice(&self.0);
        Ok(())
    }
}
#[derive(Clone)]
pub(super) enum Fault {
    Need,
    Error,
    End,
    Count,
    ZeroItem,
    ZeroSkip,
    Grow(usize),
    Drain(usize, bool),
    ShrinkCapacity,
}
impl Decode for Fault {
    type Item = ();
    type Error = TestError;
    const NAME: &'static str = "fault";
    fn capacity(&self) -> usize {
        if matches!(self, Self::ShrinkCapacity) {
            0
        } else {
            4
        }
    }
    fn held(&self) -> usize {
        match self {
            Self::Grow(n) | Self::Drain(n, _) => *n,
            _ => 0,
        }
    }
    fn decode(&mut self, _: &[u8], _: bool) -> Result<Step<()>, TestError> {
        match self {
            Self::Need | Self::ShrinkCapacity => Ok(Step::Need),
            Self::Error => Err(TestError),
            Self::End => Ok(Step::End),
            Self::Count => Ok(Step::Item((), usize::MAX)),
            Self::ZeroItem => Ok(Step::Item((), 0)),
            Self::ZeroSkip => Ok(Step::Skip(0)),
            Self::Grow(n) => {
                *n = n.saturating_add(1);
                Ok(Step::Need)
            }
            Self::Drain(n, item) if *n > 0 => {
                *n -= 1;
                Ok(if *item {
                    Step::Item((), 0)
                } else {
                    Step::Skip(0)
                })
            }
            Self::Drain(_, _) => Ok(Step::End),
        }
    }
}

#[test]
fn buffer_empty_full_and_clamped_counts() {
    let mut b = Buffer::new(4);
    assert_eq!((b.len(), b.room(), b.offset(), b.allocated()), (0, 4, 0, 0));
    b.commit(usize::MAX);
    b.consume(usize::MAX);
    assert_eq!(b.offset(), 0);
    assert_eq!(b.push(b"abcdef"), 4);
    assert_eq!(b.unread(), b"abcd");
    assert_eq!(b.push(b"x"), 0);
    assert!(b.spare().is_empty());
    b.consume(2);
    assert_eq!((b.len(), b.room(), b.offset()), (2, 2, 2));
    assert_eq!(b.push(b"ef"), 2);
    assert_eq!(b.unread(), b"cdef");
    b.consume(usize::MAX);
    assert!(b.is_empty());
    assert_eq!(b.offset(), 6);
    let mut zero = Buffer::new(0);
    assert_eq!(zero.push(b"a"), 0);
    assert!(zero.spare().is_empty());
    assert_eq!(Buffer::new(usize::MAX).limit(), Buffer::MAX_LIMIT);
}
#[test]
fn buffer_spare_commit_and_invalidation() {
    let mut b = Buffer::new(4);
    b.spare().copy_from_slice(b"abcd");
    assert!(b.is_empty());
    b.commit(2);
    assert_eq!(b.unread(), b"ab");
    b.commit(2);
    assert_eq!(b.unread(), b"ab");
    b.spare().copy_from_slice(b"cd");
    b.commit(usize::MAX);
    assert_eq!(b.unread(), b"abcd");
    b.consume(3);
    b.spare().copy_from_slice(b"efg");
    assert_eq!(b.push(b"h"), 1);
    b.commit(2);
    assert_eq!(b.unread(), b"dh");
    let _ = b.spare();
    b.consume(0);
    b.commit(2);
    assert_eq!(b.unread(), b"dh");
}
#[test]
fn buffer_compaction_is_amortized_at_full_capacity() {
    let mut b = Buffer::new(127);
    assert_eq!(b.push(&[0; 127]), 127);
    for i in 0..20_000 {
        b.consume(1);
        assert_eq!(b.push(&[(i % 256) as u8]), 1);
        assert_eq!(b.len(), 127);
        assert!(b.allocated() <= 254);
        assert!(b.moved <= i + 1);
    }
    assert_eq!(b.offset(), 20_000);
    assert!(b.moved > 0);
}
#[test]
fn buffer_random_operations_match_a_queue() {
    let mut rng = fictionet::stdlib::codec::Lcg::new(72);
    let mut b = Buffer::new(31);
    let mut expected = alloc::collections::VecDeque::new();
    let mut consumed = 0;
    for _ in 0..4000 {
        if rng.below(2) == 0 {
            let mut bytes = [0; 19];
            rng.fill(&mut bytes);
            let n = b.push(&bytes);
            expected.extend(bytes.iter().take(n));
        } else {
            let n = (rng.below(35) as usize).min(expected.len());
            b.consume(n);
            consumed += n as u64;
            expected.drain(..n);
        }
        assert_eq!(b.unread(), expected.make_contiguous());
        assert_eq!(b.offset(), consumed);
        assert!(b.allocated() <= 62);
    }
}
#[test]
fn driver_need_item_skip_spans_and_raw_bytes() {
    let mut s = Stream::new(Frames);
    assert!(s.next().is_none());
    assert_eq!(s.push(&[0x80, 2, b'a']), 3);
    assert!(s.next().is_none());
    assert_eq!(s.offset(), 1);
    assert_eq!(s.push(b"b"), 1);
    assert_eq!(
        s.with_next(|item, raw, span| (item, raw.to_vec(), span)),
        Some(Ok((b"ab".to_vec(), vec![2, b'a', b'b'], 1..4)))
    );
    assert_eq!(s.buffered(), 0);
    assert_eq!(s.held(), 0);
    assert!(!s.is_done());
    s.end();
    assert!(s.next_span().is_none());
    assert!(s.is_done());
}
#[test]
fn driver_end_and_handoff_preserve_bytes_and_eof() {
    let mut s = Stream::with_buffer(Frames, 16);
    assert_eq!(s.push(&[1, b'a', 0xff, b'z']), 4);
    assert_eq!(s.next_span(), Some(Ok((vec![b'a'], 0..2))));
    assert!(s.next().is_none());
    assert!(s.is_done());
    assert_eq!(s.unread(), &[0xff, b'z']);
    assert_eq!(s.push(b"discard"), 7);
    s.end();
    let mut next = s.swap(Pairs);
    assert_eq!(next.next_span(), Some(Ok((vec![0xff, b'z'], 2..4))));
    assert!(next.next().is_none());
    assert!(next.is_done());
    let (buf, _) = next.into_parts();
    assert_eq!(buf.limit(), 2);
}
#[test]
fn driver_error_once_and_swap_after_error() {
    let mut s = Stream::new(Frames);
    assert_eq!(s.push(&[0xfe, 1]), 2);
    assert_eq!(s.next(), Some(Err(Fail::Protocol(TestError))));
    assert_eq!(s.failed(), Some(&Fail::Protocol(TestError)));
    assert!(s.next().is_none());
    assert_eq!(s.push(b"dropped"), 7);
    assert!(s.spare().is_empty());
    s.commit(usize::MAX);
    assert_eq!(s.unread(), &[0xfe, 1]);
    let mut s = s.swap(Pairs);
    assert_eq!(s.next(), Some(Ok(vec![0xfe, 1])));
}
#[test]
fn driver_spare_end_and_buffer_growth_for_handoff() {
    let mut s = Stream::new(Pairs);
    s.spare().copy_from_slice(b"ab");
    s.commit(1);
    s.end();
    assert!(s.spare().is_empty());
    s.commit(3);
    assert_eq!(s.push(b"after eof"), 9);
    assert_eq!(s.next(), Some(Err(Fail::Truncated { unread: 1 })));
    let s = s.swap(Frames);
    let (b, _) = s.into_parts();
    assert_eq!(b.limit(), 8);
    assert_eq!(b.unread(), b"a");
}
#[test]
fn driver_stuck_overcount_and_growing_need_are_terminal() {
    for fault in [Fault::Need, Fault::Count, Fault::ZeroSkip, Fault::Grow(0)] {
        let mut s = Stream::new(fault);
        assert_eq!(s.push(b"abcd"), 4);
        assert!(matches!(s.next(), Some(Err(Fail::Stuck { .. }))));
        assert!(s.next().is_none());
        assert!(s.is_done());
    }
    let mut s = Stream::new(Fault::ShrinkCapacity);
    assert!(matches!(
        s.next(),
        Some(Err(Fail::Stuck { capacity: 0, .. }))
    ));
}
#[test]
fn driver_allows_state_bounded_zero_steps_per_next() {
    for item in [false, true] {
        let mut s = Stream::new(Fault::Drain(3, item));
        let mut count = 0;
        while let Some(r) = s.next() {
            r.unwrap();
            count += 1;
        }
        assert_eq!(count, if item { 3 } else { 0 });
        assert!(s.is_done());
        let mut s = Stream::new(Fault::Drain(70_000, item));
        let mut errors = 0;
        while let Some(r) = s.next() {
            if r.is_err() {
                errors += 1;
            }
        }
        assert_eq!(errors, 0);
        assert!(s.failed().is_none());
    }
}
#[test]
fn pump_drains_multiple_buffers_and_prefilled_input() {
    let mut s = Stream::new(Pairs);
    assert_eq!(s.push(b"ab"), 2);
    let mut items = Vec::new();
    pump(&mut s, b"cdefgh", |it| items.push(it)).unwrap();
    assert_eq!(items, vec![b"ab", b"cd", b"ef", b"gh"]);
    finish(&mut s, |_| panic!()).unwrap();
    pump(&mut s, b"ignored", |_| panic!()).unwrap();
    finish(&mut s, |_| panic!()).unwrap();
}
#[test]
fn pump_need_skip_end_and_error_paths() {
    let mut s = Stream::new(Frames);
    pump(&mut s, &[2, b'a'], |_| panic!()).unwrap();
    let mut got = Vec::new();
    pump(&mut s, &[b'b', 0x80, 0xff], |it| got.push(it)).unwrap();
    assert_eq!(got, vec![b"ab"]);
    assert!(s.is_done());
    for fault in [Fault::Error, Fault::Need, Fault::ZeroSkip] {
        let mut s = Stream::new(fault);
        assert!(pump(&mut s, b"abcd", |_| panic!()).is_err());
        pump(&mut s, b"again", |_| panic!()).unwrap();
    }
}
#[test]
fn try_pump_handler_refusal_keeps_accepted_suffix() {
    let mut s = Stream::new(Frames);
    assert_eq!(
        try_pump(&mut s, &[1, b'a', 1, b'b'], |_| Err("stop")),
        Err(PumpError::Handler("stop"))
    );
    assert!(!s.is_done());
    assert_eq!(s.next(), Some(Ok(vec![b'b'])));
    assert!(s.failed().is_none());
}
#[test]
fn try_pump_need_skip_end_and_errors() {
    let mut s = Stream::new(Frames);
    try_pump(&mut s, &[2], |_| Ok::<_, TestError>(())).unwrap();
    try_pump(
        &mut s,
        &[b'a', b'b', 0x80, 0xff],
        |_| Ok::<_, TestError>(()),
    )
    .unwrap();
    assert!(s.is_done());
    try_pump(&mut s, &[0xfe], |_| Err(TestError)).unwrap();
    let mut s = Stream::new(Fault::Error);
    assert_eq!(
        try_pump(&mut s, &[], |_| Ok::<_, TestError>(())),
        Err(PumpError::Decode(Fail::Protocol(TestError)))
    );
    try_pump(&mut s, b"x", |_| Err(TestError)).unwrap();
    let mut s = Stream::new(Fault::ZeroSkip);
    assert!(matches!(
        try_pump(&mut s, &[], |_| Ok::<_, TestError>(())),
        Err(PumpError::Decode(Fail::Stuck { .. }))
    ));
}
#[test]
fn finish_empty_truncated_item_skip_end_error_and_stuck() {
    let mut s = Stream::new(Frames);
    finish(&mut s, |_| panic!()).unwrap();
    let mut s = Stream::new(Frames);
    assert_eq!(s.push(&[0x80, 1, b'a']), 3);
    let mut got = Vec::new();
    finish(&mut s, |it| got.push(it)).unwrap();
    assert_eq!(got, vec![b"a"]);
    let mut s = Stream::new(Frames);
    assert_eq!(s.push(&[2, b'a']), 2);
    assert_eq!(
        finish(&mut s, |_| panic!()),
        Err(Fail::Truncated { unread: 2 })
    );
    finish(&mut s, |_| panic!()).unwrap();
    for fault in [Fault::End, Fault::Error, Fault::ZeroSkip] {
        let is_end = matches!(fault, Fault::End);
        let mut s = Stream::new(fault);
        assert_eq!(finish(&mut s, |_| panic!()).is_ok(), is_end);
        assert!(s.is_done());
        finish(&mut s, |_| panic!()).unwrap();
    }
}
#[test]
fn mode_changes_happen_between_items() {
    struct Mode(u8);
    impl Decode for Mode {
        type Item = u8;
        type Error = Infallible;
        const NAME: &'static str = "mode";
        fn capacity(&self) -> usize {
            2
        }
        fn decode(&mut self, b: &[u8], _: bool) -> Result<Step<u8>, Infallible> {
            Ok(if b.is_empty() {
                Step::Need
            } else {
                Step::Item(self.0, 1)
            })
        }
    }
    let mut s = Stream::new(Mode(1));
    assert_eq!(s.push(b"ab"), 2);
    assert_eq!(s.next(), Some(Ok(1)));
    s.decoder().0 = 2;
    assert_eq!(s.next(), Some(Ok(2)));
}
#[test]
fn map_forwards_every_step_error_capacity_and_held() {
    let mut s = Stream::new(Frames.map(|b| b.len()));
    assert!(s.next().is_none());
    assert_eq!(s.push(&[0x80, 1, b'a', 0xff]), 4);
    assert_eq!(s.next(), Some(Ok(1)));
    assert!(s.next().is_none());
    let mut mapped = Fault::Error.map(|_| 1);
    assert_eq!(mapped.decode(&[], false), Err(TestError));
    let mut mapped = Map::new(Fault::Drain(3, true), |_: ()| 1);
    assert_eq!((mapped.capacity(), mapped.held()), (4, 3));
    *mapped.inner() = Fault::End;
    assert_eq!(mapped.decode(&[], false), Ok(Step::End));
}
#[test]
fn collect_empty_full_limit_parse_error_and_single_item() {
    for bytes in [&b""[..], b"abc"] {
        let mut s = Stream::new(Collect::<Blob>::new(3));
        assert_eq!(s.held(), 0);
        pump(&mut s, bytes, |_| panic!()).unwrap();
        let mut items = Vec::new();
        finish(&mut s, |it| items.push(it)).unwrap();
        assert_eq!(items, vec![Blob(bytes.to_vec())]);
        assert_eq!(s.held(), 0);
        finish(&mut s, |_| panic!()).unwrap();
        contract::check_decode(|| Collect::<Blob>::new(3), bytes);
    }
    let mut s = Stream::new(Collect::<Blob>::new(3));
    assert_eq!(
        pump(&mut s, b"abcd", |_| panic!()),
        Err(Fail::Protocol(CollectError::TooLong { limit: 3 }))
    );
    let mut s = Stream::new(Collect::<Blob>::new(0));
    assert_eq!(
        pump(&mut s, b"a", |_| panic!()),
        Err(Fail::Protocol(CollectError::TooLong { limit: 0 }))
    );
    let mut s = Stream::new(Collect::<Blob>::new(3));
    assert_eq!(s.push(&[0xff]), 1);
    assert_eq!(
        finish(&mut s, |_| panic!()),
        Err(Fail::Protocol(CollectError::Parse(TestError)))
    );
    assert_eq!(
        Collect::<Blob>::new(usize::MAX).capacity(),
        Buffer::MAX_LIMIT
    );
}
fn read_lines(data: &[u8], max: usize, ending: Ending) -> Vec<Result<Vec<u8>, LineError>> {
    let mut s = Stream::new(Lines::new(max, ending));
    let mut items = Vec::new();
    pump(&mut s, data, |it| items.push(it)).unwrap();
    finish(&mut s, |it| items.push(it)).unwrap();
    items
}
#[test]
fn lines_crlf_policy_limits_and_partial_eof() {
    assert_eq!(
        read_lines(b"ab\r\nc\n\r\nlast", 4, Ending::Crlf),
        vec![
            Ok(b"ab".to_vec()),
            Err(LineError::BareLf),
            Ok(vec![]),
            Err(LineError::Unterminated)
        ]
    );
    assert_eq!(
        read_lines(b"ab\nc\r\n", 2, Ending::LfOrCrlf),
        vec![Ok(b"ab".to_vec()), Ok(b"c".to_vec())]
    );
    assert_eq!(
        read_lines(b"\n\r\nx\n", 0, Ending::LfOrCrlf),
        vec![Ok(vec![]), Ok(vec![]), Err(LineError::TooLong { max: 0 })]
    );
    assert_eq!(
        read_lines(b"abcdef\nxy\n", 2, Ending::LfOrCrlf),
        vec![Err(LineError::TooLong { max: 2 }), Ok(b"xy".to_vec())]
    );
    assert_eq!(
        read_lines(b"abcdef", 2, Ending::LfOrCrlf),
        vec![Err(LineError::TooLong { max: 2 })]
    );
    assert!(read_lines(b"", 2, Ending::Crlf).is_empty());
    assert_eq!(
        Lines::new(usize::MAX, Ending::Crlf).capacity(),
        Buffer::MAX_LIMIT
    );
}
#[test]
fn lines_partition_invariance_and_scan_cursor() {
    for ending in [Ending::Crlf, Ending::LfOrCrlf, Ending::LfOrCrOrCrlf] {
        for data in [
            &b"abc\r\nx\n\n123456789\r\nok\r\npartial"[..],
            b"abcd\n",
            b"abcd\r\n",
        ] {
            contract::check_decode(|| Lines::new(3, ending), data);
        }
    }
    let mut lines = Lines::new(4096, Ending::Crlf);
    let data = vec![b'x'; 4096];
    for n in 0..=data.len() {
        assert_eq!(lines.decode(data.get(..n).unwrap(), false), Ok(Step::Need));
    }
    // A reused cursor still recognizes CRLF split across calls.
    let mut s = Stream::new(Lines::new(3, Ending::Crlf));
    assert_eq!(s.push(b"abc\r"), 4);
    assert!(s.next().is_none());
    assert_eq!(s.push(b"\n"), 1);
    assert_eq!(s.next(), Some(Ok(Ok(b"abc".to_vec()))));
}
#[test]
fn lines_cr_lf_and_crlf() {
    let ending = Ending::LfOrCrOrCrlf;
    assert_eq!(
        read_lines(b"a\rb\nc\r\n\r\n\rx\r", 1, ending),
        vec![
            Ok(b"a".to_vec()),
            Ok(b"b".to_vec()),
            Ok(b"c".to_vec()),
            Ok(vec![]),
            Ok(vec![]),
            Ok(b"x".to_vec())
        ]
    );
    for max in 0..=4 {
        for data in [
            &b"ab\r\nx\ry\n\r\r\nlast"[..],
            b"abcd\r\nx\r",
            b"abcd\r",
            b"abcdef\r\n\rx\n",
            b"a\r\r\nb\r\nc\n",
            b"\r",
            b"\r\n",
        ] {
            contract::check_decode(|| Lines::new(max, ending), data);
        }
    }
    assert_eq!(
        read_lines(b"abcdef\r\nx\r", 1, ending),
        vec![Err(LineError::TooLong { max: 1 }), Ok(b"x".to_vec())]
    );
    let mut stream = Stream::new(Lines::new(3, ending));
    // A final CR ends the line at once. A split LF is skipped later.
    assert_eq!(stream.push(b"abc\r"), 4);
    assert_eq!(stream.next(), Some(Ok(Ok(b"abc".to_vec()))));
    assert_eq!(stream.offset(), 4);
    assert_eq!(stream.push(b"\n"), 1);
    assert!(stream.next().is_none());
    assert_eq!(stream.offset(), 5);
    assert_eq!(stream.push(b"x\r"), 2);
    assert_eq!(stream.next(), Some(Ok(Ok(b"x".to_vec()))));
    assert_eq!(stream.push(b"\r"), 1);
    assert_eq!(stream.next(), Some(Ok(Ok(vec![]))));
    stream.end();
    assert!(stream.next().is_none());
    // An overlong line ending in a final CR is refused without waiting,
    // and the LF after it is still one terminator with the CR.
    let mut stream = Stream::new(Lines::new(1, ending));
    assert_eq!(stream.push(b"ab\r"), 3);
    assert_eq!(stream.next(), Some(Ok(Err(LineError::TooLong { max: 1 }))));
    assert_eq!(stream.push(b"\nx\n"), 3);
    assert_eq!(stream.next(), Some(Ok(Ok(b"x".to_vec()))));
    assert!(stream.next().is_none());
}
fn fragments(item: Vec<u8>) -> Fragment<Vec<u8>> {
    match item.first() {
        Some(0) => Fragment::Part {
            data: item.get(1..).unwrap_or_default().to_vec(),
            last: false,
        },
        Some(1) => Fragment::Part {
            data: item.get(1..).unwrap_or_default().to_vec(),
            last: true,
        },
        _ => Fragment::Whole(item),
    }
}
#[test]
fn assemble_fragments_with_interleaved_control() {
    let data = [3, 0, b'a', b'b', 1, 2, 2, 1, b'c'];
    let mut s = Stream::new(Assemble::new(Frames, 4, fragments));
    let mut items = Vec::new();
    pump(&mut s, &data, |it| items.push(it)).unwrap();
    finish(&mut s, |_| panic!()).unwrap();
    assert_eq!(
        items,
        vec![
            Assembled::Whole(vec![2]),
            Assembled::Message(b"abc".to_vec())
        ]
    );
    assert_eq!(s.held(), 0);
    contract::check_decode(|| Assemble::new(Frames, 4, fragments), &data);
}
#[test]
fn assemble_limit_incomplete_empty_and_inner_error() {
    for data in [&[1, 0][..], &[2, 0, b'a']] {
        let mut s = Stream::new(Assemble::new(Frames, 4, fragments));
        pump(&mut s, data, |_| panic!()).unwrap();
        assert_eq!(s.held(), data.len() - 2);
        assert_eq!(
            finish(&mut s, |_| panic!()),
            Err(Fail::Protocol(AssembleError::Incomplete {
                held: data.len() - 2
            }))
        );
    }
    let mut s = Stream::new(Assemble::new(Frames, 1, fragments));
    assert_eq!(
        pump(&mut s, &[3, 1, b'a', b'b'], |_| panic!()),
        Err(Fail::Protocol(AssembleError::TooLong { limit: 1 }))
    );
    let mut s = Stream::new(Assemble::new(Frames, 1, fragments));
    assert_eq!(
        pump(&mut s, &[0xfe], |_| panic!()),
        Err(Fail::Protocol(AssembleError::Inner(TestError)))
    );
    let mut s = Stream::new(Assemble::new(Frames, 1, fragments));
    assert_eq!(
        pump(&mut s, &[1, 0, 0xff], |_| panic!()),
        Err(Fail::Protocol(AssembleError::Incomplete { held: 0 }))
    );
    let mut s = Stream::new(Assemble::new(Frames, 0, fragments));
    let mut got = Vec::new();
    pump(&mut s, &[1, 1], |it| got.push(it)).unwrap();
    assert_eq!(got, vec![Assembled::Message(vec![])]);
}
fn carry(item: Vec<u8>) -> Carry<Vec<u8>> {
    match item.first() {
        Some(0xf0) => Carry::Through(item),
        Some(0xf1) => Carry::Drop,
        _ => Carry::Bytes(item),
    }
}
#[test]
fn pipe_two_layers_cross_payloads_and_match_separate_decoding() {
    let data = [
        1, b'a', 3, b'b', b'c', b'd', 1, 0xf0, 0x80, 1, 0xf1, 2, b'e', b'f',
    ];
    let mut s = Stream::new(Pipe::new(Frames, Pairs, carry));
    let mut items = Vec::new();
    pump(&mut s, &data, |it| items.push(it)).unwrap();
    finish(&mut s, |it| items.push(it)).unwrap();
    assert_eq!(
        items,
        vec![
            Layered::Inner(b"ab".to_vec()),
            Layered::Inner(b"cd".to_vec()),
            Layered::Outer(vec![0xf0]),
            Layered::Inner(b"ef".to_vec())
        ]
    );
    let mut outer = Stream::new(Frames);
    let mut bytes = Vec::new();
    pump(&mut outer, &data, |item| {
        if let Carry::Bytes(b) = carry(item) {
            bytes.extend_from_slice(&b)
        }
    })
    .unwrap();
    let mut inner = Stream::new(Pairs);
    let mut separate = Vec::new();
    pump(&mut inner, &bytes, |item| separate.push(item)).unwrap();
    finish(&mut inner, |_| panic!()).unwrap();
    let combined: Vec<_> = items
        .into_iter()
        .filter_map(|it| match it {
            Layered::Inner(i) => Some(i),
            _ => None,
        })
        .collect();
    assert_eq!(combined, separate);
    assert_eq!(s.decoder().spans().outer_offset(), data.len() as u64);
    assert_eq!(s.decoder().spans().iter().last().unwrap().outer, 11..14);
    contract::check_stack(|| Pipe::new(Frames, Pairs, carry), &data);
}
#[test]
fn pipe_pending_larger_than_inner_buffer_is_not_overwritten() {
    let data = [7, 1, 2, 3, 4, 5, 6, 7, 1, 8];
    let mut s = Stream::new(Pipe::new(Frames, Pairs, carry));
    let mut items = Vec::new();
    pump(&mut s, &data, |it| items.push(it)).unwrap();
    finish(&mut s, |_| panic!()).unwrap();
    assert_eq!(
        items,
        vec![
            Layered::Inner(vec![1, 2]),
            Layered::Inner(vec![3, 4]),
            Layered::Inner(vec![5, 6]),
            Layered::Inner(vec![7, 8])
        ]
    );
    contract::check_stack(|| Pipe::new(Frames, Pairs, carry), &data);
}
#[test]
fn pipe_eof_collect_empty_and_nonempty() {
    for data in [&[][..], &[2, b'a', b'b', 1, b'c']] {
        let mut s = Stream::new(Pipe::new(Frames, Collect::<Blob>::new(8), carry));
        pump(&mut s, data, |_| panic!()).unwrap();
        let mut items = Vec::new();
        finish(&mut s, |it| items.push(it)).unwrap();
        assert_eq!(
            items,
            vec![Layered::Inner(Blob(if data.is_empty() {
                vec![]
            } else {
                b"abc".to_vec()
            }))]
        );
        contract::check_stack(|| Pipe::new(Frames, Collect::<Blob>::new(8), carry), data);
    }
}
#[test]
fn pipe_outer_end_inner_errors_and_payload_limit() {
    let mut s = Stream::new(Pipe::new(Frames, Pairs, carry));
    assert_eq!(
        pump(&mut s, &[1, b'a', 0xff], |_| panic!()),
        Err(Fail::Protocol(PipeError::Inner(Fail::Truncated {
            unread: 1
        })))
    );
    let mut s = Stream::new(Pipe::new(Frames, Pairs, carry));
    assert_eq!(
        pump(&mut s, &[0xfe], |_| panic!()),
        Err(Fail::Protocol(PipeError::Outer(TestError)))
    );
    let mut s = Stream::new(Pipe::new(Frames, Frames, carry));
    assert_eq!(
        pump(&mut s, &[1, 0xfe], |_| panic!()),
        Err(Fail::Protocol(PipeError::Inner(Fail::Protocol(TestError))))
    );
    let mut s = Stream::new(Pipe::with_limits(Frames, Pairs, carry, 1, 0));
    assert_eq!(
        pump(&mut s, &[2, b'a', b'b'], |_| panic!()),
        Err(Fail::Protocol(PipeError::PayloadTooLong { limit: 1 }))
    );
    let mut s = Stream::new(Pipe::new(Frames, Pairs, carry));
    assert_eq!(s.push(&[0xff]), 1);
    assert!(s.next().is_none());
    assert!(s.is_done());
    assert_eq!(s.unread(), &[0xff]);
}
#[test]
fn pipe_inner_skips_and_early_end() {
    let mut s = Stream::new(Pipe::new(Frames, Frames, carry));
    pump(&mut s, &[4, 0x80, 0x80, 0xff, 0], |_| panic!()).unwrap();
    finish(&mut s, |_| panic!()).unwrap();
    assert!(s.decoder().inner_stream().is_done());
    assert_eq!(s.decoder().inner_stream().unread(), &[0xff, 0]);
    let mut s = Stream::new(Pipe::new(Frames, Fault::Need, carry));
    assert!(matches!(
        pump(&mut s, &[4, 1, 2, 3, 4], |_| panic!()),
        Err(Fail::Protocol(PipeError::Inner(Fail::Stuck { .. })))
    ));
}
#[test]
fn spans_coarse_gaps_eviction_and_zero_retention() {
    let mut spans = Spans::new(3);
    spans.push(3, 3);
    spans.push(2, 2);
    // Equal lengths are still coarse: only whole spans resolve.
    assert_eq!(spans.locate(1..4), None);
    assert_eq!(spans.locate(0..3), Some(0..3));
    assert_eq!(spans.locate(0..5), Some(0..5));
    spans.skip(2);
    spans.push(3, 3);
    assert_eq!(spans.locate(4..7), None);
    assert_eq!(spans.locate(5..7), None);
    assert_eq!(spans.locate(5..8), Some(7..10));
    assert_eq!(spans.locate(3..8), None);
    spans.push(5, 2);
    assert_eq!(spans.len(), 3);
    assert_eq!(spans.locate(0..1), None);
    assert_eq!(spans.locate(8..10), Some(10..15));
    assert_eq!(spans.locate(5..10), Some(7..15));
    assert_eq!(spans.locate(8..9), None);
    assert_eq!(spans.locate(8..8), None);
    let mut disabled = Spans::new(0);
    disabled.push(5, 3);
    assert!(disabled.is_empty());
    assert_eq!((disabled.inner_offset(), disabled.outer_offset()), (3, 5));
    let mut overflow = Spans::new(1);
    overflow.push(usize::MAX, usize::MAX);
    overflow.push(usize::MAX, usize::MAX);
    assert!(overflow.outer_offset() > 0);
}
#[test]
fn demux_accepts_a_local_borrowing_factory() {
    let count = std::rc::Rc::new(core::cell::Cell::new(0));
    let mut d = Demux::new(2, 4, |_: &u8| {
        count.set(count.get() + 1);
        Pairs
    });
    assert_eq!(d.push(&1, b"ab"), 2);
    assert_eq!(d.next(), Some((1, Ok(b"ab".to_vec()))));
    assert_eq!(count.get(), 1);
}

#[test]
fn demux_limits_order_eof_remove_and_held_budget() {
    let mut d = Demux::new(2, 4, |_: &u8| Pairs);
    assert!(d.is_empty());
    assert_eq!(d.push(&2, b"ab"), 2);
    assert_eq!(d.push(&1, b"cd"), 2);
    assert_eq!(d.push(&3, b"ef"), 0);
    assert_eq!(d.push(&1, b"x"), 0);
    assert_eq!(d.total(), 4);
    assert_eq!(d.next(), Some((1, Ok(b"cd".to_vec()))));
    assert_eq!(d.next(), Some((2, Ok(b"ab".to_vec()))));
    assert_eq!(d.total(), 0);
    d.end(&1);
    d.end(&99);
    assert!(d.next().is_none());
    assert!(d.get_mut(&1).unwrap().is_done());
    assert_eq!(d.push(&1, b"discard"), 7);
    assert!(d.remove(&1).is_some());
    assert_eq!(d.len(), 1);
    assert_eq!(d.push(&3, b"x"), 1);
    d.end(&3);
    assert_eq!(d.next(), Some((3, Err(Fail::Truncated { unread: 1 }))));
    assert!(d.next().is_none());
    let mut d = Demux::new(2, 1, |_: &u8| Collect::<Blob>::new(8));
    assert_eq!(d.push(&1, b"a"), 1);
    assert_eq!(d.total(), 1);
    assert_eq!(d.push(&2, b""), 0);
    assert_eq!(d.len(), 2);
    d.end(&1);
    assert_eq!(d.next(), Some((1, Ok(Blob(b"a".to_vec())))));
}
#[test]
fn demux_refuses_initial_state_and_delivers_item_before_budget_error() {
    let mut d = Demux::new(1, 0, |_: &u8| Fault::Drain(1, true));
    assert_eq!(d.push(&1, b""), 0);
    assert!(d.is_empty());
    struct Inflate(usize);
    impl Decode for Inflate {
        type Item = ();
        type Error = TestError;
        const NAME: &'static str = "inflate";
        fn capacity(&self) -> usize {
            1
        }
        fn held(&self) -> usize {
            self.0
        }
        fn decode(&mut self, b: &[u8], _: bool) -> Result<Step<()>, TestError> {
            if b.is_empty() {
                return Ok(Step::Need);
            }
            self.0 = 8;
            Ok(Step::Item((), 1))
        }
    }
    let mut d = Demux::new(1, 2, |_: &u8| Inflate(0));
    assert_eq!(d.push(&1, b"a"), 1);
    assert_eq!(d.next(), Some((1, Ok(()))));
    assert_eq!(d.total(), 0);
    assert!(matches!(
        d.next(),
        Some((1, Err(Fail::Refused { limit: 2, .. })))
    ));
    assert!(d.next().is_none());
    assert_eq!(d.len(), 1);
    assert_eq!(d.push(&1, b"closed"), 6);
    assert!(d.next().is_none());
    assert!(d.remove(&1).is_none());
    assert!(d.is_empty());
}

#[test]
fn harness_accepts_correct_decoders_on_valid_and_invalid_inputs() {
    for data in [&b""[..], &[0x80, 1, 4, 2, 5, 6, 0xff], &[2, 1], &[0xfe]] {
        contract::check_decode(|| Frames, data);
    }
    for data in [&b""[..], b"a", b"ab", b"abcdefghijklmnop"] {
        contract::check_decode(|| Pairs, data);
        contract::check_decode_with_held_limit(|| Collect::<Blob>::new(8), data, 1);
    }
    let mut rng = fictionet::stdlib::codec::Lcg::new(42);
    for _ in 0..100 {
        let mut bytes = [0; 32];
        rng.fill(&mut bytes);
        contract::check_decode(|| Frames, &bytes);
        contract::check_decode(|| Lines::new(7, Ending::Crlf), &bytes);
    }
}
#[test]
#[should_panic(expected = "chunking changed decoding")]
fn harness_catches_chunking_dependent_output() {
    struct Chunks;
    impl Decode for Chunks {
        type Item = Vec<u8>;
        type Error = TestError;
        const NAME: &'static str = "chunks";
        fn capacity(&self) -> usize {
            16
        }
        fn decode(&mut self, b: &[u8], _: bool) -> Result<Step<Vec<u8>>, TestError> {
            Ok(if b.is_empty() {
                Step::Need
            } else {
                Step::Item(b.to_vec(), b.len())
            })
        }
    }
    contract::check_decode(|| Chunks, b"abcdef");
}
#[test]
#[should_panic(expected = "buffered exceeds capacity")]
fn harness_catches_capacity_shrinking_below_buffered() {
    struct Shrink(usize);
    impl Decode for Shrink {
        type Item = ();
        type Error = TestError;
        const NAME: &'static str = "shrink";
        fn capacity(&self) -> usize {
            self.0
        }
        fn decode(&mut self, _: &[u8], _: bool) -> Result<Step<()>, TestError> {
            self.0 = 0;
            Ok(Step::End)
        }
    }
    contract::check_decode(|| Shrink(8), b"abc");
}
#[test]
#[should_panic(expected = "Need at capacity")]
fn harness_catches_stuck() {
    contract::check_decode(|| Fault::Need, b"abcd");
}
#[test]
#[should_panic(expected = "consumed count exceeds input")]
fn harness_catches_consumed_miscount() {
    contract::check_decode(|| Fault::Count, b"a");
}
#[test]
#[should_panic(expected = "held grew across Need")]
fn harness_catches_held_growth_across_need() {
    contract::check_decode(|| Fault::Grow(0), b"a");
}
#[test]
#[should_panic(expected = "harness item limit exceeded")]
fn harness_catches_endless_zero_items() {
    contract::check_decode(|| Fault::ZeroItem, b"");
}
#[test]
#[should_panic(expected = "driver reported Stuck")]
fn harness_catches_endless_zero_skips() {
    contract::check_decode(|| Fault::ZeroSkip, b"");
}
#[test]
fn harness_accepts_many_zero_steps_across_returned_items() {
    contract::check_decode(|| Fault::Drain(70_000, true), b"");
}
#[test]
fn harness_accepts_state_bounded_zero_steps_inside_one_next() {
    contract::check_decode(|| Fault::Drain(70_000, false), b"");
}
#[test]
#[should_panic(expected = "driver reported Stuck")]
fn harness_catches_not_finishing_after_end() {
    struct Forever;
    impl Decode for Forever {
        type Item = ();
        type Error = TestError;
        const NAME: &'static str = "forever";
        fn capacity(&self) -> usize {
            4
        }
        fn decode(&mut self, _: &[u8], eof: bool) -> Result<Step<()>, TestError> {
            Ok(if eof { Step::Skip(0) } else { Step::Need })
        }
    }
    contract::check_decode(|| Forever, b"");
}
#[test]
#[should_panic(expected = "held exceeds named limit")]
fn harness_catches_named_held_limit() {
    contract::check_decode_with_held_limit(|| Fault::Drain(5, true), b"", 4);
}
#[test]
fn harness_never_calls_decoder_after_error_or_end() {
    struct Once {
        calls: Rc<Cell<usize>>,
        error: bool,
    }
    impl Decode for Once {
        type Item = ();
        type Error = TestError;
        const NAME: &'static str = "once";
        fn capacity(&self) -> usize {
            4
        }
        fn decode(&mut self, _: &[u8], _: bool) -> Result<Step<()>, TestError> {
            assert_eq!(self.calls.get(), 0, "called after terminal result");
            self.calls.set(1);
            if self.error {
                Err(TestError)
            } else {
                Ok(Step::End)
            }
        }
    }
    for error in [false, true] {
        contract::check_decode(
            || Once {
                calls: Rc::new(Cell::new(0)),
                error,
            },
            b"abcd",
        );
    }
}
#[derive(Debug, PartialEq)]
struct BadWire<const KIND: u8>(u8);
impl<const KIND: u8> Wire for BadWire<KIND> {
    type ParseError = TestError;
    type WriteError = TestError;
    fn parse(b: &[u8]) -> Result<Self, TestError> {
        match b {
            [b] if *b != 0xff => Ok(Self(*b)),
            _ => Err(TestError),
        }
    }
    fn write(&self, out: &mut Vec<u8>) -> Result<(), TestError> {
        match KIND {
            0 => out.push(0xff),                   // rejected output
            1 => out.push(self.0.wrapping_add(1)), // different value
            2 => {
                out.push(0);
                return Err(TestError);
            } // failed transaction
            3 => return Err(TestError),            // parsed values must write
            _ => out.push(self.0),
        }
        Ok(())
    }
}
#[test]
#[should_panic(expected = "writer output does not parse")]
fn harness_catches_wire_output_rejected_by_parser() {
    contract::check_wire::<BadWire<0>>(&[1]);
}
#[test]
#[should_panic(expected = "wire round trip changed value")]
fn harness_catches_wire_roundtrip_mismatch() {
    contract::check_wire::<BadWire<1>>(&[1]);
}
#[test]
#[should_panic(expected = "writer changed destination on error")]
fn harness_catches_nontransactional_write() {
    contract::check_wire_value(&BadWire::<2>(1));
}
#[test]
#[should_panic(expected = "parsed value does not write")]
fn harness_catches_refusal_of_parsed_value() {
    contract::check_wire::<BadWire<3>>(&[1]);
}
#[test]
fn wire_harness_accepts_valid_and_refused_values() {
    contract::check_wire::<Blob>(b"abc");
    contract::check_wire::<Blob>(&[0xff]);
    contract::check_wire_value(&Blob(vec![0xff]));
    contract::check_wire_value(&Blob(vec![0; 65]));
    contract::check_wire::<BadWire<4>>(&[1]);
}
#[test]
fn test_support_reproducible_rng_and_chunks() {
    let mut rng = fictionet::stdlib::codec::Lcg::new(0);
    assert_eq!(rng.next(), 1442695040888963407 >> 33);
    assert_eq!(rng.below(0), 0);
    let data = b"abcdefghi";
    assert_eq!(
        test_support::chunks(data, &[0, 2, 3]).collect::<Vec<_>>(),
        vec![&b"a"[..], b"bc", b"def", b"g", b"hi"]
    );
    assert_eq!(
        test_support::chunks(data, &[]).collect::<Vec<_>>(),
        vec![&data[..]]
    );
    assert!(test_support::chunks(b"", &[1]).next().is_none());
    let mut a = fictionet::stdlib::codec::Lcg::new(7);
    let mut b = fictionet::stdlib::codec::Lcg::new(7);
    assert_eq!(
        test_support::random_chunks(data, &mut a, 3).collect::<Vec<_>>(),
        test_support::random_chunks(data, &mut b, 3).collect::<Vec<_>>()
    );
    assert_eq!(
        test_support::random_chunks(data, &mut a, 0).count(),
        data.len()
    );
}
#[test]
fn test_support_index_and_generators() {
    let mut rng = fictionet::stdlib::codec::Lcg::new(11);
    assert_eq!(rng.index(0), 0);
    let mut seen = [false; 5];
    for _ in 0..200 {
        let i = rng.index(5);
        assert!(i < 5);
        seen[i] = true;
    }
    assert_eq!(seen, [true; 5]);
    let flips: Vec<bool> = (0..64).map(|_| rng.coin()).collect();
    assert!(flips.contains(&true) && flips.contains(&false));
    assert!(rng.bytes(0).is_empty());
    assert!(rng.text(0).is_empty());
    let mut lengths = Vec::new();
    for _ in 0..200 {
        let b = rng.bytes(9);
        assert!(b.len() <= 9);
        lengths.push(b.len());
        let t = rng.text(9);
        assert!(t.len() <= 9);
        assert!(t.bytes().all(|c| (b' '..=b'~').contains(&c)));
    }
    assert!(lengths.contains(&0) && lengths.contains(&9));
    let mut a = fictionet::stdlib::codec::Lcg::new(5);
    let mut b = fictionet::stdlib::codec::Lcg::new(5);
    assert_eq!(a.bytes(32), b.bytes(32));
    assert_eq!(a.text(32), b.text(32));
}
#[test]
fn test_support_mutate_is_bounded_and_reproducible() {
    let mut rng = fictionet::stdlib::codec::Lcg::new(3);
    let mut empty = Vec::new();
    test_support::mutate(&mut rng, &mut empty);
    assert_eq!(empty.len(), 1);
    let (mut shorter, mut same, mut one, mut more) = (false, false, false, false);
    for _ in 0..2000 {
        let mut data = rng.bytes(40);
        let original = data.clone();
        test_support::mutate(&mut rng, &mut data);
        let (before, after) = (original.len(), data.len());
        assert!(after <= before + test_support::MUTATE_GROWTH);
        if after < before {
            shorter = true;
            assert_eq!(data[..], original[..after]);
        } else if after == before {
            same = true;
            // Setting a byte or flipping a bit changes at most one byte.
            let changed = data.iter().zip(&original).filter(|(x, y)| x != y).count();
            assert!(changed <= 1);
        } else if after == before + 1 {
            one = true;
        } else {
            more = true;
        }
    }
    assert!(shorter && same && one && more);
    let (mut a, mut b) = (
        fictionet::stdlib::codec::Lcg::new(9),
        fictionet::stdlib::codec::Lcg::new(9),
    );
    let (mut x, mut y) = (b"abcdef".to_vec(), b"abcdef".to_vec());
    for _ in 0..50 {
        test_support::mutate(&mut a, &mut x);
        test_support::mutate(&mut b, &mut y);
    }
    assert_eq!(x, y);
    assert!(x.len() <= 6 + 50 * test_support::MUTATE_GROWTH);
}
#[test]
fn test_support_mutate_duplicates_a_slice() {
    // Growth beyond one byte only comes from copying an existing slice.
    let mut rng = fictionet::stdlib::codec::Lcg::new(1);
    for _ in 0..500 {
        let original = b"0123456789".to_vec();
        let mut data = original.clone();
        test_support::mutate(&mut rng, &mut data);
        let n = data.len().saturating_sub(original.len());
        if n > 1 {
            let at = (0..=original.len())
                .find(|&at| data[..at] == original[..at] && data[at + n..] == original[at..])
                .expect("copy inserted at one position");
            let copy = &data[at..at + n];
            assert!(original.windows(n).any(|w| w == copy));
        }
    }
}
#[test]
fn test_support_decode_all() {
    let (items, failure) = test_support::decode_all(|| Frames, &[2, b'a', b'b', 0x80, 0]);
    assert_eq!(items, vec![b"ab".to_vec(), Vec::new()]);
    assert_eq!(failure, None);
    let (items, failure) = test_support::decode_all(|| Frames, &[1, b'a', 3, b'b']);
    assert_eq!(items, vec![b"a".to_vec()]);
    assert_eq!(failure, Some(Fail::Truncated { unread: 2 }));
    let (items, failure) = test_support::decode_all(|| Frames, &[0, 0x40, 0]);
    assert_eq!(items, vec![Vec::new()]);
    assert_eq!(failure, Some(Fail::Protocol(TestError)));
    // Bytes after End are left undecoded.
    let (items, failure) = test_support::decode_all(|| Frames, &[0, 0xff, 0x40]);
    assert_eq!(items, vec![Vec::new()]);
    assert_eq!(failure, None);
    let (items, failure) = test_support::decode_all(|| Frames, b"");
    assert!(items.is_empty());
    assert_eq!(failure, None);
}
#[test]
fn contract_alloc_limit_accepts_bounded_buffer() {
    let data = [7, 1, 2, 3, 4, 5, 6, 7, 2, b'a', b'b', 0x80, 0];
    contract::check_decode_with_alloc_limit(|| Frames, &data, 16);
    let mut rng = fictionet::stdlib::codec::Lcg::new(8);
    for _ in 0..20 {
        let mut bytes = data.to_vec();
        test_support::mutate(&mut rng, &mut bytes);
        contract::check_decode_with_alloc_limit(|| Frames, &bytes, 16);
    }
}
#[test]
#[should_panic(expected = "buffer allocation exceeds limit")]
fn contract_alloc_limit_rejects_large_buffer() {
    contract::check_decode_with_alloc_limit(|| Frames, &[7, 1, 2, 3, 4, 5, 6, 7], 4);
}
#[test]
fn wrappers_chain_to_their_source_and_display_only_their_own_context() {
    use alloc::string::ToString;
    use core::error::Error as _;
    fn chained(e: &dyn core::error::Error) -> bool {
        e.source()
            .is_some_and(|s| s.is::<TestError>() || chained(s))
    }
    let fail = Fail::Protocol(TestError);
    assert!(fail.source().is_some_and(|s| s.is::<TestError>()));
    assert!(chained(&CollectError::Parse(TestError)));
    assert!(chained(&AssembleError::Inner(TestError)));
    assert!(chained(&PipeError::<_, TestError>::Outer(TestError)));
    assert!(chained(&PipeError::<TestError, _>::Inner(fail.clone())));
    assert!(chained(&PumpError::<_, TestError>::Decode(fail.clone())));
    assert!(chained(&PumpError::<TestError, _>::Handler(TestError)));
    assert!(chained(&RewriteError::Write(TestError)));
    assert!(chained(&FaultError::Rewrite(RewriteError::Write(
        TestError
    ))));
    assert!(chained(&InterceptError::<_, TestError>::Decode(
        fail.clone()
    )));
    assert!(chained(&InterceptError::<TestError, _>::Rewrite(
        RewriteError::Write(TestError)
    )));
    assert!(!fail.to_string().contains(&TestError.to_string()));
    for verdict in [
        Fail::<TestError>::Truncated { unread: 2 },
        Fail::Stuck {
            unread: 3,
            capacity: 3,
        },
        Fail::Refused {
            unread: 3,
            limit: 3,
        },
    ] {
        assert!(verdict.source().is_none());
        assert!(!verdict.to_string().is_empty());
    }
    assert!(LineError::BareLf.source().is_none());
}

#[test]
fn buffer_spare_one_byte_reads_reuse_initialized_storage() {
    let mut b = Buffer::new(1024);
    for _ in 0..1024 {
        *b.spare().first_mut().unwrap() = b'a';
        b.commit(1);
    }
    assert_eq!(b.initialized, 1024);
    for _ in 0..10_000 {
        b.consume(1);
        *b.spare().first_mut().unwrap() = b'b';
        b.commit(1);
    }
    assert!(b.initialized <= 2048);
    assert!(b.moved <= 10_000);
}

#[test]
fn eof_allows_persistent_tables_in_held_state() {
    struct Table;
    impl Decode for Table {
        type Item = ();
        type Error = TestError;
        const NAME: &'static str = "table";
        fn capacity(&self) -> usize {
            8
        }
        fn held(&self) -> usize {
            32
        }
        fn decode(&mut self, _: &[u8], _: bool) -> Result<Step<()>, TestError> {
            Ok(Step::Need)
        }
    }
    let mut stream = Stream::new(Table);
    finish(&mut stream, |_| panic!()).unwrap();
    assert_eq!(stream.held(), 32);
    assert!(stream.failed().is_none());
    contract::check_decode_with_held_limit(|| Table, b"", 32);
}

#[test]
fn pipe_random_payload_partitions_preserve_inner_stream() {
    let mut rng = fictionet::stdlib::codec::Lcg::new(93);
    for _ in 0..32 {
        let mut input = Vec::new();
        for _ in 0..16 {
            let n = rng.below(8) as usize;
            input.push(n as u8);
            let mut payload = [0; 7];
            rng.fill(&mut payload);
            input.extend_from_slice(payload.get(..n).unwrap());
        }
        contract::check_stack(|| Pipe::new(Frames, Pairs, carry), &input);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Body(Vec<u8>);
impl Wire for Body {
    type ParseError = Infallible;
    type WriteError = Infallible;
    fn parse(b: &[u8]) -> Result<Self, Infallible> {
        Ok(Self(b.to_vec()))
    }
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Infallible> {
        out.extend_from_slice(&self.0);
        Ok(())
    }
}
struct Bytes;
impl Decode for Bytes {
    type Item = u8;
    type Error = Infallible;
    const NAME: &'static str = "bytes";
    fn capacity(&self) -> usize {
        2
    }
    fn decode(&mut self, b: &[u8], _: bool) -> Result<Step<u8>, Infallible> {
        Ok(match b.first() {
            Some(b) => Step::Item(*b, 1),
            None => Step::Need,
        })
    }
}

#[test]
fn regression_large_payload_zero_items() {
    let input = vec![b'\n'; 70_000];
    let mut s = Stream::new(Pipe::new(
        Collect::<Body>::new(1 << 20),
        Lines::new(8, Ending::LfOrCrlf),
        |b: Body| Carry::Bytes(b.0),
    ));
    let mut count = 0;
    pump(&mut s, &input, |_| count += 1).unwrap();
    finish(&mut s, |_| count += 1).unwrap();
    assert_eq!(count, input.len());
    contract::check_stack(
        || {
            Pipe::new(
                Collect::<Body>::new(1 << 20),
                Lines::new(8, Ending::LfOrCrlf),
                |b: Body| Carry::Bytes(b.0),
            )
        },
        &input,
    );
}

#[test]
fn regression_assemble_pipe_zero_fragments() {
    fn make() -> impl Decode<Item = Assembled<()>, Error: Clone + PartialEq + fmt::Debug> {
        Assemble::new(
            Pipe::new(Frames, Lines::new(8, Ending::LfOrCrlf), Carry::Bytes),
            64,
            |item: Layered<Vec<u8>, Result<Vec<u8>, LineError>>| match item {
                Layered::Inner(Ok(line)) => Fragment::Part {
                    last: line.is_empty(),
                    data: line,
                },
                _ => Fragment::Whole(()),
            },
        )
    }
    let data = [2, b'a', b'\n', 1, b'\n'];
    let mut s = Stream::new(make());
    let mut items = Vec::new();
    pump(&mut s, &data, |item| items.push(item)).unwrap();
    finish(&mut s, |_| panic!()).unwrap();
    assert_eq!(items, vec![Assembled::Message(b"a".to_vec())]);
    contract::check_stack(make, &data);
}

#[test]
fn regression_nested_expanding_pipe() {
    fn make() -> impl Decode<Item: PartialEq + fmt::Debug, Error: Clone + PartialEq + fmt::Debug> {
        Pipe::new(
            Frames,
            Pipe::with_limits(
                Frames,
                Bytes,
                |b: Vec<u8>| Carry::Bytes(b.repeat(4)),
                1024,
                16,
            ),
            Carry::Bytes,
        )
    }
    let data = [5, 4, b'a', b'b', b'c', b'd'];
    let mut s = Stream::new(make());
    let mut count = 0;
    pump(&mut s, &data, |_| count += 1).unwrap();
    finish(&mut s, |_| count += 1).unwrap();
    assert_eq!(count, 16);
    contract::check_stack(make, &data);
}

#[test]
fn regression_pump_handoff_large_chunk() {
    let mut data = vec![1, b'h', 0xff];
    data.extend(0..20);
    let mut s = Stream::new(Frames);
    let taken = pump(&mut s, &data, |_| {}).unwrap();
    assert_eq!(taken, 8);
    assert_eq!(pump(&mut s, &data[taken..], |_| panic!()), Ok(0));
    let mut s = s.swap(Collect::<Body>::new(64));
    assert_eq!(
        pump(&mut s, &data[taken..], |_| panic!()),
        Ok(data.len() - taken)
    );
    let mut body = Vec::new();
    finish(&mut s, |b| body = b.0).unwrap();
    assert_eq!(body, data[2..]);
}

#[test]
fn regression_pipe_end_leaves_outer_suffix() {
    for data in [vec![1, 0xff, 2, b'x', b'y'], vec![2, 0xff, 9, 3, 1, 2, 3]] {
        let used = 1 + data[0] as usize;
        let mut s = Stream::new(Pipe::new(Frames, Frames, Carry::Bytes));
        pump(&mut s, &data, |_| panic!()).unwrap();
        assert!(s.is_done());
        assert_eq!(s.unread(), &data[used..]);
        assert_eq!(s.decoder().inner_stream().unread(), &data[1..used]);
    }
}

#[test]
fn regression_pipe_end_with_unpushed_payload() {
    struct UntilZero;
    impl Decode for UntilZero {
        type Item = u8;
        type Error = Infallible;
        const NAME: &'static str = "until zero";
        fn capacity(&self) -> usize {
            2
        }
        fn decode(&mut self, b: &[u8], _: bool) -> Result<Step<u8>, Infallible> {
            Ok(match b.first() {
                Some(0) => Step::End,
                Some(b) => Step::Item(*b, 1),
                None => Step::Need,
            })
        }
    }
    let mut s = Stream::new(Pipe::new(Frames, UntilZero, Carry::Bytes));
    pump(&mut s, &[6, 1, 0, 9, 9, 9, 9], |_| {}).unwrap();
    assert!(s.is_done());
    assert_eq!(s.decoder().inner_stream().unread(), &[0, 9]);
    assert_eq!(s.held(), 5);
    assert_eq!(s.decoder().pending(), &[9, 9, 9]);
    let (_, pipe) = s.into_parts();
    let (_, inner, pending) = pipe.into_parts();
    assert_eq!([inner.unread(), &pending].concat(), &[0, 9, 9, 9, 9]);
}

#[test]
fn regression_demux_visits_only_ready_streams() {
    use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
    struct Counted {
        calls: Arc<AtomicUsize>,
        held_calls: Arc<AtomicUsize>,
    }
    impl Decode for Counted {
        type Item = u8;
        type Error = Infallible;
        const NAME: &'static str = "counted";
        fn capacity(&self) -> usize {
            2
        }
        fn held(&self) -> usize {
            self.held_calls.fetch_add(1, Ordering::Relaxed);
            0
        }
        fn decode(&mut self, b: &[u8], eof: bool) -> Result<Step<u8>, Infallible> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Bytes.decode(b, eof)
        }
    }
    let calls = Arc::new(AtomicUsize::new(0));
    let held_calls = Arc::new(AtomicUsize::new(0));
    let counters = (calls.clone(), held_calls.clone());
    let mut d = Demux::new(4096, 8192, move |_: &usize| Counted {
        calls: counters.0.clone(),
        held_calls: counters.1.clone(),
    });
    for key in 0..4096 {
        assert_eq!(d.push(&key, b""), 0);
    }
    assert!(d.next().is_none());
    calls.store(0, Ordering::Relaxed);
    held_calls.store(0, Ordering::Relaxed);
    for key in (0..4096).cycle().take(8192) {
        assert_eq!(d.push(&key, b"a"), 1);
        assert_eq!(d.next(), Some((key, Ok(b'a'))));
        assert!(d.next().is_none());
        assert_eq!(d.total(), 0);
    }
    assert!(calls.load(Ordering::Relaxed) <= 8192 * 2, "{} decode calls", calls.load(Ordering::Relaxed));
    assert!(
        held_calls.load(Ordering::Relaxed) <= 8192 * 12,
        "{} held calls",
        held_calls.load(Ordering::Relaxed)
    );
}

#[test]
fn try_pump_handoff_and_handler_error_counts() {
    let mut data = vec![1, b'h', 0xff];
    data.extend(0..20);
    let mut s = Stream::new(Frames);
    let taken = try_pump(&mut s, &data, |_| Ok::<_, TestError>(())).unwrap();
    assert_eq!(taken, 8);
    assert_eq!(try_pump(&mut s, &data[taken..], |_| Err(TestError)), Ok(0));
    let mut s = s.swap(Collect::<Body>::new(64));
    assert_eq!(
        try_pump(&mut s, &data[taken..], |_| Ok::<_, TestError>(())),
        Ok(15)
    );
    finish(&mut s, |body| assert_eq!(body.0, data[2..])).unwrap();

    let mut s = Stream::new(Frames);
    let data = [1, b'a'].repeat(10);
    let accepted_before = s.offset() + s.buffered() as u64;
    assert_eq!(
        try_pump(&mut s, &data, |_| Err(TestError)),
        Err(PumpError::Handler(TestError))
    );
    let taken = (s.offset() + s.buffered() as u64 - accepted_before) as usize;
    assert_eq!(taken, 8);
    let mut items = 0;
    assert_eq!(pump(&mut s, &data[taken..], |_| items += 1), Ok(12));
    finish(&mut s, |_| items += 1).unwrap();
    assert_eq!(items, 9);
    assert_eq!(s.offset(), data.len() as u64);
}

#[test]
fn pump_after_eof_keeps_unaccepted_input() {
    let mut s = Stream::new(Collect::<Body>::new(64));
    assert_eq!(s.push(b"body"), 4);
    s.end();
    assert_eq!(pump(&mut s, b"tail", |b| assert_eq!(b.0, b"body")), Ok(0));
    assert_eq!(s.offset(), 4);
}

#[test]
fn swap_lowers_limit_without_losing_oversized_suffix() {
    let mut s = Stream::with_buffer(Frames, 64);
    let data = [0xff; 32];
    assert_eq!(s.push(&data), data.len());
    assert!(s.next().is_none());
    let mut s = s.swap(Bytes);
    assert_eq!(s.unread(), data);
    assert_eq!(s.push(b"x"), 0);
    let mut count = 0;
    while let Some(item) = s.next() {
        assert_eq!(item, Ok(0xff));
        count += 1;
    }
    assert_eq!(count, data.len());
    assert_eq!(s.push(b"abc"), 2);
    assert_eq!(s.into_parts().0.limit(), 2);
}

#[test]
fn spare_caps_initial_offer_for_large_capacity() {
    let mut b = Buffer::new(16 << 20);
    let offer = b.spare();
    assert_eq!(offer.len(), 64 << 10);
    offer[..10].copy_from_slice(b"small body");
    b.commit(10);
    assert_eq!(b.unread(), b"small body");
    assert_eq!(b.initialized, 64 << 10);
}

#[test]
fn demux_preserves_protocol_error_on_budget_overflow() {
    struct ErrorGrowth(usize);
    impl Decode for ErrorGrowth {
        type Item = ();
        type Error = TestError;
        const NAME: &'static str = "error growth";
        fn capacity(&self) -> usize {
            1
        }
        fn held(&self) -> usize {
            self.0
        }
        fn decode(&mut self, _: &[u8], _: bool) -> Result<Step<()>, TestError> {
            self.0 = 8;
            Err(TestError)
        }
    }
    let mut d = Demux::new(2, 2, |_: &u8| ErrorGrowth(0));
    assert_eq!(d.push(&1, b"a"), 1);
    assert_eq!(d.next(), Some((1, Err(Fail::Protocol(TestError)))));
    assert_eq!(d.total(), 0);
    assert!(d.next().is_none());
}

#[test]
fn demux_mutable_access_updates_only_its_stream() {
    let mut d = Demux::new(2, 4, |_: &u8| Collect::<Body>::new(64));
    assert_eq!(d.push(&1, b"a"), 1);
    assert_eq!(d.push(&2, b"b"), 1);
    assert!(d.next().is_none());
    assert_eq!(d.get_mut(&2).unwrap().push(b"c"), 1);
    assert_eq!(d.total(), 3);
    assert!(d.next().is_none());
    d.get_mut(&2).unwrap().end();
    assert_eq!(d.next(), Some((2, Ok(Body(b"bc".to_vec())))));
    assert_eq!(d.total(), 1);
    assert_eq!(d.remove(&1).unwrap().unread(), b"a");
    assert_eq!(d.total(), 0);

    let mut d = Demux::new(2, 4, |_: &u8| Collect::<Body>::new(64));
    assert_eq!(d.push(&1, b"a"), 1);
    assert_eq!(d.push(&2, b"b"), 1);
    assert_eq!(d.get_mut(&2).unwrap().push(b"excess"), 6);
    assert_eq!(d.total(), 8);
    assert!(matches!(
        d.next(),
        Some((2, Err(Fail::Refused { limit: 4, .. })))
    ));
    assert_eq!(d.total(), 1);
    d.end(&1);
    assert_eq!(d.next(), Some((1, Ok(Body(b"a".to_vec())))));
}

#[test]
fn demux_rotates_ready_keys() {
    let mut d = Demux::new(2, 4, |_: &u8| Bytes);
    assert_eq!(d.push(&1, b"ab"), 2);
    assert_eq!(d.push(&2, b"cd"), 2);
    assert_eq!(d.next(), Some((1, Ok(b'a'))));
    assert_eq!(d.next(), Some((2, Ok(b'c'))));
    assert_eq!(d.next(), Some((1, Ok(b'b'))));
    assert_eq!(d.next(), Some((2, Ok(b'd'))));
    assert!(d.next().is_none());
    assert!(d.next().is_none());
}

#[test]
fn assemble_identity_payload_moves_held_bytes_without_shrinking() {
    let mut data = vec![b'a'; 1024];
    data.push(0);
    let mut s = Stream::new(Assemble::new(
        Pipe::new(Collect::<Body>::new(2048), Bytes, |b: Body| {
            Carry::Bytes(b.0)
        }),
        2048,
        |item: Layered<Body, u8>| -> Fragment<()> {
            match item {
                Layered::Inner(b) => Fragment::Part {
                    data: vec![b],
                    last: b == 0,
                },
                _ => Fragment::Whole(()),
            }
        },
    ));
    pump(&mut s, &data, |_| panic!()).unwrap();
    finish(&mut s, |item| {
        assert_eq!(item, Assembled::Message(data.clone()))
    })
    .unwrap();
}

#[test]
fn empty_collectors_can_form_complete_or_incomplete_assemblies() {
    for last in [false, true] {
        let mut s = Stream::new(Assemble::new(
            Pipe::new(
                Collect::<Body>::new(0),
                Collect::<Body>::new(0),
                |b: Body| Carry::Bytes(b.0),
            ),
            0,
            move |_: Layered<Body, Body>| -> Fragment<()> { Fragment::Part { data: vec![], last } },
        ));
        let mut items = Vec::new();
        let result = finish(&mut s, |item| items.push(item));
        if last {
            result.unwrap();
            assert_eq!(items, vec![Assembled::Message(vec![])]);
        } else {
            assert_eq!(
                result,
                Err(Fail::Protocol(AssembleError::Incomplete { held: 0 }))
            );
            assert!(items.is_empty());
        }
    }
}

#[derive(Default)]
struct Expand {
    bytes: Vec<u8>,
}
impl Decode for Expand {
    type Item = usize;
    type Error = TestError;
    const NAME: &'static str = "expand";
    fn capacity(&self) -> usize {
        4
    }
    fn held(&self) -> usize {
        self.bytes.len()
    }
    fn decode(&mut self, input: &[u8], _: bool) -> Result<Step<usize>, TestError> {
        const LIMIT: usize = 64;
        Ok(match input.first() {
            Some(b'!') => {
                let n = self.bytes.len();
                self.bytes.clear();
                Step::Item(n, 1)
            }
            Some(&b) => {
                if self.bytes.len() > LIMIT - 2 {
                    return Err(TestError);
                }
                self.bytes.extend_from_slice(&[b, b]);
                Step::Skip(1)
            }
            None => Step::Need,
        })
    }
}

#[test]
fn regression_lines_expanding_pipe_bytewise() {
    contract::check_decode_with_held_limit(Expand::default, b"abcd!", 64);
    let make = || {
        Pipe::new(
            Lines::new(16, Ending::LfOrCrlf),
            Expand::default(),
            |line| match line {
                Ok(bytes) => Carry::Bytes(bytes),
                err => Carry::Through(err),
            },
        )
    };
    let data = b"ab\ncd\n!\n";
    for size in [data.len(), 1] {
        let mut s = Stream::new(make());
        let mut items = Vec::new();
        for chunk in data.chunks(size) {
            assert_eq!(
                pump(&mut s, chunk, |item| items.push(item)),
                Ok(chunk.len())
            );
        }
        finish(&mut s, |item| items.push(item)).unwrap();
        assert_eq!(items, vec![Layered::Inner(8)]);
        assert_eq!(s.offset(), data.len() as u64);
        assert_eq!(s.held(), 0);
    }
    contract::check_stack(make, data);
}

#[test]
fn regression_pipe_over_expanding_assemble() {
    let make = || {
        Pipe::new(
            Frames,
            Assemble::new(Frames, 64, |f: Vec<u8>| Fragment::<()>::Part {
                last: f.is_empty(),
                data: f.repeat(4),
            }),
            Carry::Bytes,
        )
    };
    let mut s = Stream::new(make());
    let mut items = Vec::new();
    assert_eq!(pump(&mut s, &[3, 2, b'a', b'b'], |i| items.push(i)), Ok(4));
    assert!(items.is_empty());
    assert_eq!(s.held(), 8);
    assert_eq!(pump(&mut s, &[1, 0], |i| items.push(i)), Ok(2));
    finish(&mut s, |i| items.push(i)).unwrap();
    assert_eq!(
        items,
        vec![Layered::Inner(Assembled::Message(b"abababab".to_vec()))]
    );
    contract::check_stack(make, &[3, 2, b'a', b'b', 1, 0]);
}

fn expanding_frame_pipe()
-> impl Decode<Item = Layered<Vec<u8>, Layered<Vec<u8>, Vec<u8>>>, Error: Clone + PartialEq + fmt::Debug>
{
    Pipe::new(
        Frames,
        Pipe::with_limits(
            Frames,
            Frames,
            |b: Vec<u8>| Carry::Bytes(if b == [1] { vec![3, 0, 0] } else { vec![0] }),
            64,
            16,
        ),
        Carry::Bytes,
    )
}

#[test]
fn regression_nested_expanding_pipe_waits_for_payload() {
    let data = [2, 1, 1, 2, 1, 2];
    for size in [data.len(), 3, 1] {
        let mut s = Stream::new(expanding_frame_pipe());
        let mut items = Vec::new();
        for chunk in data.chunks(size) {
            assert_eq!(pump(&mut s, chunk, |i| items.push(i)), Ok(chunk.len()));
        }
        finish(&mut s, |i| items.push(i)).unwrap();
        assert_eq!(items, vec![Layered::Inner(Layered::Inner(vec![0, 0, 0]))]);
        assert_eq!(s.offset(), data.len() as u64);
    }
}

#[test]
fn regression_nested_expanding_pipe_contract() {
    contract::check_stack(expanding_frame_pipe, &[2, 1, 1, 2, 1, 2]);
}

#[test]
fn regression_nested_expanding_pipe_into_collect() {
    let make = || {
        Pipe::new(
            Frames,
            Pipe::with_limits(
                Frames,
                Collect::<Body>::new(64),
                |b: Vec<u8>| Carry::Bytes(b.repeat(4)),
                1024,
                16,
            ),
            Carry::Bytes,
        )
    };
    let mut s = Stream::new(make());
    let mut items = Vec::new();
    assert_eq!(pump(&mut s, &[2, 1, b'a'], |i| items.push(i)), Ok(3));
    assert!(items.is_empty());
    finish(&mut s, |i| items.push(i)).unwrap();
    assert_eq!(
        items,
        vec![Layered::Inner(Layered::Inner(Body(b"aaaa".to_vec())))]
    );
    contract::check_stack(make, &[2, 1, b'a']);
}

#[derive(Default)]
struct Table {
    bytes: usize,
}
impl Decode for Table {
    type Item = u8;
    type Error = TestError;
    const NAME: &'static str = "table";
    fn capacity(&self) -> usize {
        4
    }
    fn held(&self) -> usize {
        self.bytes
    }
    fn decode(&mut self, input: &[u8], _: bool) -> Result<Step<u8>, TestError> {
        const LIMIT: usize = 64;
        Ok(match input.first() {
            Some(b't') => {
                self.bytes = self.bytes.saturating_add(4).min(LIMIT);
                Step::Skip(1)
            }
            Some(&b) => {
                self.bytes = 0;
                Step::Item(b, 1)
            }
            None => Step::Need,
        })
    }
}

#[test]
fn regression_pipe_over_growing_table() {
    contract::check_decode_with_held_limit(Table::default, b"ttxtq", 64);
    let make = || Pipe::new(Frames, Table::default(), Carry::Bytes);
    let mut s = Stream::new(make());
    assert_eq!(
        pump(&mut s, &[1, b't'], |_| panic!("unexpected item")),
        Ok(2)
    );
    assert_eq!(s.held(), 4);
    let mut items = Vec::new();
    assert_eq!(pump(&mut s, &[1, b'x'], |i| items.push(i)), Ok(2));
    finish(&mut s, |i| items.push(i)).unwrap();
    assert_eq!(items, vec![Layered::Inner(b'x')]);
    contract::check_stack(make, &[1, b't', 1, b'x']);
}

#[test]
fn regression_pipe_over_growing_table_contract() {
    contract::check_stack(
        || Pipe::new(Frames, Table::default(), carry),
        &[
            2, 0, 116, 187, 6, 116, 116, 227, 67, 19, 116, 63, 251, 0, 202,
        ],
    );
}

#[derive(Default)]
struct Oscillating {
    held: usize,
    calls: usize,
}
impl Decode for Oscillating {
    type Item = ();
    type Error = TestError;
    const NAME: &'static str = "oscillating";
    fn capacity(&self) -> usize {
        4
    }
    fn held(&self) -> usize {
        self.held
    }
    fn decode(&mut self, _: &[u8], _: bool) -> Result<Step<()>, TestError> {
        self.calls += 1;
        assert!(self.calls <= 100, "zero-step call guard reached");
        self.held = 3 - self.held;
        Ok(Step::Skip(0))
    }
}

#[test]
fn regression_oscillating_zero_skips_terminate() {
    let mut s = Stream::new(Oscillating::default());
    assert_eq!(s.push(b"a"), 1);
    let failure = Fail::Stuck {
        unread: 1,
        capacity: 4,
    };
    assert_eq!(s.next(), Some(Err(failure.clone())));
    assert_eq!(s.failed(), Some(&failure));
    assert!(s.is_done());
    assert_eq!(s.unread(), b"a");
    assert_eq!(s.offset(), 0);
    let calls = s.decoder().calls;
    assert!(calls < 100);
    assert_eq!(s.next(), None);
    assert_eq!(s.decoder().calls, calls);
}

#[test]
#[should_panic(expected = "driver reported Stuck")]
fn regression_harness_rejects_oscillating_zero_skips() {
    contract::check_decode(Oscillating::default, b"a");
}

#[test]
fn demux_push_after_end_matches_stream_with_any_budget() {
    for budget in [2, 3, 8] {
        let mut d = Demux::new(2, budget, |_: &u8| Collect::<Body>::new(8));
        assert_eq!(d.push(&1, b"ab"), 2);
        d.end(&1);
        assert_eq!(d.push(&1, b"cdef"), 4);
        assert_eq!(d.total(), 2);
        assert_eq!(d.next(), Some((1, Ok(Body(b"ab".to_vec())))));
        assert_eq!(d.next(), None);
        assert_eq!(d.total(), 0);
    }
}

struct Counting<D> {
    inner: D,
    calls: Rc<Cell<usize>>,
}
impl<D: Decode> Decode for Counting<D> {
    type Item = D::Item;
    type Error = D::Error;
    const NAME: &'static str = D::NAME;
    fn capacity(&self) -> usize {
        self.inner.capacity()
    }
    fn held(&self) -> usize {
        self.inner.held()
    }
    fn decode(&mut self, input: &[u8], eof: bool) -> Result<Step<Self::Item>, Self::Error> {
        self.calls.set(self.calls.get() + 1);
        self.inner.decode(input, eof)
    }
}

#[test]
fn pipe_waiting_inner_runs_only_after_changes() {
    let calls = Rc::new(Cell::new(0));
    let mut s = Stream::new(Pipe::new(
        Lines::new(1 << 16, Ending::LfOrCrlf),
        Counting {
            inner: Lines::new(1 << 16, Ending::LfOrCrlf),
            calls: calls.clone(),
        },
        |line: Result<Vec<u8>, LineError>| Carry::Bytes(line.unwrap()),
    ));
    pump(&mut s, b"a\n", |_| panic!("unexpected item")).unwrap();
    let waiting_calls = calls.get();
    for b in vec![b'b'; 50_000] {
        pump(&mut s, &[b], |_| panic!("unexpected item")).unwrap();
    }
    assert_eq!(calls.get(), waiting_calls);
    pump(&mut s, b"\n", |_| panic!("unexpected item")).unwrap();
    assert_eq!(calls.get(), waiting_calls + 1);
    let mut items = Vec::new();
    finish(&mut s, |i| items.push(i)).unwrap();
    assert_eq!(items, vec![Layered::Inner(Err(LineError::Unterminated))]);
}

#[test]
fn pipe_inner_mode_change_resumes_waiting_decoder() {
    struct Mode(bool);
    impl Decode for Mode {
        type Item = Vec<u8>;
        type Error = Infallible;
        const NAME: &'static str = "mode";
        fn capacity(&self) -> usize {
            8
        }
        fn decode(&mut self, b: &[u8], _: bool) -> Result<Step<Vec<u8>>, Infallible> {
            Ok(if self.0 && !b.is_empty() {
                Step::Item(b.to_vec(), b.len())
            } else {
                Step::Need
            })
        }
    }
    let mut s = Stream::new(Pipe::new(Frames, Mode(false), Carry::Bytes));
    pump(&mut s, &[1, b'a'], |_| panic!("unexpected item")).unwrap();
    s.decoder().inner().0 = true;
    assert_eq!(s.next(), Some(Ok(Layered::Inner(vec![b'a']))));
    finish(&mut s, |_| panic!("unexpected item")).unwrap();
}

// Header mode: capacity 4, one-byte items. Body mode: capacity 10, one 10-byte item.
struct HeaderBody(bool);
impl Decode for HeaderBody {
    type Item = Vec<u8>;
    type Error = TestError;
    const NAME: &'static str = "header body";
    fn capacity(&self) -> usize {
        if self.0 { 10 } else { 4 }
    }
    fn decode(&mut self, input: &[u8], _: bool) -> Result<Step<Vec<u8>>, TestError> {
        let n = if self.0 { 10 } else { 1 };
        Ok(match input.get(..n) {
            Some(b) => Step::Item(b.to_vec(), n),
            None => Step::Need,
        })
    }
}
#[test]
fn regression_buffer_limit_follows_raised_capacity() {
    let mut s = Stream::new(HeaderBody(false));
    let mut items = Vec::new();
    assert_eq!(pump(&mut s, &[1], |i| items.push(i)), Ok(1));
    s.decoder().0 = true;
    assert_eq!(pump(&mut s, &[7; 10], |i| items.push(i)), Ok(10));
    assert_eq!(items, vec![vec![1], vec![7; 10]]);
    finish(&mut s, |_| panic!("unexpected item")).unwrap();

    // Direct reads see the raised limit too.
    let mut s = Stream::new(HeaderBody(false));
    assert_eq!(s.push(&[1]), 1);
    assert_eq!(s.next(), Some(Ok(vec![1])));
    s.decoder().0 = true;
    assert_eq!(s.spare().len(), 10);
}
#[test]
fn regression_pipe_inner_limit_follows_raised_capacity() {
    let mut s = Stream::new(Pipe::new(Frames, HeaderBody(false), Carry::Bytes));
    let mut items = Vec::new();
    assert_eq!(pump(&mut s, &[1, 0], |i| items.push(i)), Ok(2));
    s.decoder().inner().0 = true;
    let mut data = vec![7];
    data.extend_from_slice(&[7; 7]);
    data.push(3);
    data.extend_from_slice(&[7; 3]);
    assert_eq!(pump(&mut s, &data, |i| items.push(i)), Ok(data.len()));
    finish(&mut s, |_| panic!("unexpected item")).unwrap();
    assert_eq!(
        items,
        vec![Layered::Inner(vec![0]), Layered::Inner(vec![7; 10])]
    );
}
#[test]
fn regression_pipe_spans_cover_assembled_message() {
    let mut s = Stream::new(Pipe::with_limits(
        Assemble::new(Frames, 64, fragments),
        Pairs,
        |item: Assembled<Vec<u8>>| match item {
            Assembled::Message(bytes) => Carry::Bytes(bytes),
            Assembled::Whole(item) => Carry::Through(Assembled::Whole(item)),
        },
        64,
        16,
    ));
    let mut items = Vec::new();
    let data = [3, 0, b'a', b'b', 3, 1, b'c', b'd'];
    assert_eq!(pump(&mut s, &data, |i| items.push(i)), Ok(8));
    finish(&mut s, |_| panic!("unexpected item")).unwrap();
    assert_eq!(
        items,
        vec![
            Layered::Inner(b"ab".to_vec()),
            Layered::Inner(b"cd".to_vec())
        ]
    );
    let spans = s.decoder().spans();
    assert_eq!(
        spans.iter().cloned().collect::<Vec<_>>(),
        vec![Span {
            exact: false,
            inner: 0..4,
            outer: 0..8
        }]
    );
    assert_eq!(spans.locate(0..1), None);
    assert_eq!(spans.locate(0..4), Some(0..8));
}

#[test]
fn pad_to_four_edges() {
    for (n, want) in [(0, 0), (1, 4), (3, 4), (4, 4), (5, 8), (usize::MAX - 3, usize::MAX - 3)] {
        assert_eq!(super::pad_to_4(n), want);
    }
}
