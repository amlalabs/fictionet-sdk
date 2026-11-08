//! Kani proofs over `BodyEvents`, the HTTP/1 body framing the server,
//! the capture parser and the WARC reader share (`BodyEvents::decode`,
//! `Reader::begin`, `Reader::body`, `Reader::chunk_step`, `chunk_framing`,
//! `chunk_size`, `chunk_size_skipping_extensions` and `number` in
//! `src/stdlib/protocols/http1.rs`). Compiled only under `cargo kani`, as a
//! child module of `protocols::http1`, so every harness calls the real
//! decoder.
//!
//! The proofs are per step: from each state the decoder can be in, one call
//! on any input does what the RFC 9112 grammar says for that state, and
//! gives the same result however its input was split. A body is a run of
//! such steps from the state `begin` sets, so the framing of a whole body
//! follows by induction on the steps. Whole-body harnesses, which unroll
//! several calls with the state symbolic between them, do not fit in the
//! 10 GiB the machine allows.
//!
//! `verification/http/README.md` lists what each harness proves, its
//! bound and the mutation that shows it can fail.

use super::*;
/// A symbolic byte string of at most `N` bytes.
fn input<const N: usize>() -> ([u8; N], usize) {
    let bytes: [u8; N] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= N);
    (bytes, len)
}

fn is_hex(b: u8) -> bool {
    b.is_ascii_hexdigit()
}

/// The value of a non-empty string of hex digits, if it fits in a `u64`:
/// leading zeros dropped, then at most 16 digits.
fn spec_hex(digits: &[u8]) -> Option<u64> {
    if digits.is_empty() || !digits.iter().copied().all(is_hex) {
        return None;
    }
    let first = digits
        .iter()
        .position(|b| *b != b'0')
        .unwrap_or(digits.len());
    let significant = &digits[first..];
    if significant.len() > 16 {
        return None;
    }
    let mut value = 0u64;
    for b in significant {
        let digit = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            _ => b - b'A' + 10,
        };
        value = (value << 4) | u64::from(digit);
    }
    Some(value)
}

/// Bytes allowed in a chunk extension: tab, and visible ASCII or above.
fn spec_field_byte(b: u8) -> bool {
    b == b'\t' || (b >= 0x20 && b != 0x7f)
}

fn spec_trim(mut b: &[u8]) -> &[u8] {
    while let [b' ' | b'\t', rest @ ..] = b {
        b = rest;
    }
    while let [rest @ .., b' ' | b'\t'] = b {
        b = rest;
    }
    b
}

/// The decoder's state as a comparable value: its kind and its count.
fn kind(state: State) -> (u8, u64) {
    match state {
        State::Head => (0, 0),
        State::Length(n) => (1, n),
        State::Size => (2, 0),
        State::Data(n) => (3, n),
        State::DataEnd => (4, 0),
        State::Trailers => (5, 0),
        State::Close => (6, 0),
        State::Done => (7, 0),
        State::Boundary => (8, 0),
        State::End => (9, 0),
    }
}

/// What one step of the grammar does with the input in front of it.
#[derive(Debug, PartialEq, Eq)]
enum Expect {
    /// More input is needed; nothing changes.
    Need,
    /// A refusal.
    Fail,
    /// Consume this many bytes and move to this state.
    Skip(usize, (u8, u64)),
    /// A block of this many bytes, then this state.
    Block(usize, (u8, u64)),
    /// `Done`, then this state.
    Done((u8, u64)),
    /// The end of this decoder.
    End,
}

/// The line at the front of `input` under `Lines` with content limit
/// `max` and CRLF endings: `Ok(Some((content, used)))`, `Ok(None)` when
/// more input could still end it, `Err(())` when it is refused (too long,
/// or a bare LF).
fn spec_front_line(input: &[u8], max: usize) -> Result<Option<(&[u8], usize)>, ()> {
    let window = &input[..input.len().min(max + 2)];
    match window.iter().position(|b| *b == b'\n') {
        Some(i) if i >= 1 && input[i - 1] == b'\r' && i - 1 <= max => {
            Ok(Some((&input[..i - 1], i + 1)))
        }
        Some(_) => Err(()),
        None if input.len() >= max + 2 => Err(()),
        None => Ok(None),
    }
}

/// A decoder's configuration and state for one step: any line, head,
/// field and block limits within small bounds, and any head and field
/// counts so far within them.
#[derive(Clone, Copy)]
struct Setup {
    extras: bool,
    state: State,
    limits: Limits,
    scanned: usize,
    count: usize,
}

impl Setup {
    fn any(extras: bool, state: State) -> Setup {
        let header_line: usize = kani::any();
        kani::assume(header_line <= 3);
        let head: usize = kani::any();
        kani::assume(head <= 6);
        let headers: usize = kani::any();
        kani::assume(headers <= 2);
        let block: usize = kani::any();
        kani::assume(block >= 1 && block <= 3);
        let scanned: usize = kani::any();
        let count: usize = kani::any();
        kani::assume(scanned <= head && count <= headers);
        // The decoder never holds a count of zero: `begin` makes an empty
        // length `Done`, and a chunk's last byte moves it to `DataEnd`.
        kani::assume(!matches!(state, State::Length(0) | State::Data(0)));
        Setup {
            extras,
            state,
            limits: Limits {
                header_line,
                headers,
                head,
                body_chunk: block,
                ..Limits::default()
            },
            scanned,
            count,
        }
    }

    /// A decoder built the public way, then put in this state.
    fn decoder(&self) -> BodyEvents {
        let mut decoder = BodyEvents::with_limits(Framing::Chunked, self.limits);
        if self.extras {
            decoder = decoder.skip_chunk_extras();
        }
        decoder.core.state = self.state;
        decoder.core.scanned = self.scanned;
        decoder.core.count = self.count;
        decoder
    }
}

/// What one call of the real decoder did, and the state it left. A block
/// is exactly the bytes it consumed; `Done` consumes nothing.
fn outcome(decoder: &mut BodyEvents, input: &[u8], eof: bool) -> Expect {
    match decoder.decode(input, eof) {
        Ok(Step::Need) => Expect::Need,
        Ok(Step::End) => Expect::End,
        Err(_) => Expect::Fail,
        Ok(Step::Skip(used)) => Expect::Skip(used, kind(decoder.core.state)),
        Ok(Step::Item(Event::Body(data), used)) => {
            assert!(data.len() == used);
            assert!(data == input[..used]);
            Expect::Block(used, kind(decoder.core.state))
        }
        Ok(Step::Item(Event::Done, used)) => {
            assert!(used == 0);
            Expect::Done(kind(decoder.core.state))
        }
        Ok(Step::Item(Event::Head(never), _)) => match never {},
    }
}

/// One step gives the same result at every split of its input: a call on
/// the bytes up to any cut either asks for more, and the call on all of
/// them (after it, with whatever `Lines` remembered of the scan) gives what
/// one call on all of them gives, or it already gives that same result,
/// consuming the same bytes and leaving the same state. With `Need`
/// changing no state, this extends step by step to any number of cuts.
fn one_step_is_independent_of_the_split(extras: bool, state: State) {
    let setup = Setup::any(extras, state);
    let (bytes, len) = input::<6>();
    let input = &bytes[..len];
    let eof: bool = kani::any();
    let cut: usize = kani::any();
    kani::assume(cut <= len);
    let direct = outcome(&mut setup.decoder(), input, eof);
    let mut parts = setup.decoder();
    let first = outcome(&mut parts, &input[..cut], false);
    let later = if first == Expect::Need {
        outcome(&mut parts, input, eof)
    } else {
        first
    };
    assert!(later == direct);
    kani::cover!(
        cut < len && direct != Expect::Need,
        "a split before the result"
    );
}

/// One step from every body state, against the grammar written out
/// independently: for every state (any count, so lengths and chunk sizes
/// near `u64::MAX` are in), both chunk modes, any line, head and block
/// limits within small bounds, every input of up to 6 bytes and with or
/// without the end of input. A size line is read exactly when it is a
/// complete valid line and sets the chunk size it says; data goes up in
/// blocks of exactly `min(left, block)` bytes and the count drops by that;
/// a chunk's CRLF and an empty trailer section are required byte for byte;
/// trailer lines (when skipped) are bounded by the head and field limits;
/// no step consumes past its input; and the decoder never asks for more
/// input while it holds its capacity, so the stream's buffer never needs
/// to grow past that capacity.
fn one_step_follows_the_grammar(extras: bool, state: State) {
    let setup = Setup::any(extras, state);
    let Limits {
        header_line,
        headers,
        head,
        body_chunk: block,
        ..
    } = setup.limits;
    let (scanned, count) = (setup.scanned, setup.count);
    let mut decoder = setup.decoder();
    let capacity = decoder.capacity();
    let line_max = if extras { header_line } else { MAX_CHUNK_LINE };
    let (bytes, len) = input::<6>();
    let input = &bytes[..len];
    let eof: bool = kani::any();

    let take = |left: u64| -> usize { left.min(block as u64) as usize };
    let mut expect = match state {
        State::Length(left) | State::Data(left) => {
            let size = take(left);
            if len < size {
                Expect::Need
            } else {
                let rest = left - size as u64;
                let next = match (state, rest) {
                    (State::Length(_), 0) => kind(State::Done),
                    (State::Length(_), r) => kind(State::Length(r)),
                    (_, 0) => kind(State::DataEnd),
                    (_, r) => kind(State::Data(r)),
                };
                Expect::Block(size, next)
            }
        }
        State::Size => match spec_front_line(input, line_max) {
            Err(()) => Expect::Fail,
            Ok(None) => Expect::Need,
            Ok(Some((line, used))) => {
                let size = if extras {
                    let semi = line.iter().position(|b| *b == b';').unwrap_or(line.len());
                    if line[semi..].iter().copied().all(spec_field_byte) {
                        spec_hex(spec_trim(&line[..semi]))
                    } else {
                        None
                    }
                } else {
                    spec_hex(line)
                };
                match size {
                    None => Expect::Fail,
                    Some(0) => Expect::Skip(used, kind(State::Trailers)),
                    Some(size) => Expect::Skip(used, kind(State::Data(size))),
                }
            }
        },
        State::DataEnd => match input {
            [] | [b'\r'] => Expect::Need,
            [b'\r', b'\n', ..] => Expect::Skip(2, kind(State::Size)),
            _ => Expect::Fail,
        },
        State::Trailers if !extras => match input {
            [] | [b'\r'] => Expect::Need,
            [b'\r', b'\n', ..] => Expect::Skip(2, kind(State::Done)),
            _ => Expect::Fail,
        },
        State::Trailers => match spec_front_line(input, line_max) {
            Err(()) => Expect::Fail,
            Ok(None) => Expect::Need,
            Ok(Some((line, used))) => {
                if scanned + used > head {
                    Expect::Fail
                } else if line.is_empty() {
                    Expect::Skip(used, kind(State::Done))
                } else if !header_line_ok(line) || count + 1 > headers {
                    Expect::Fail
                } else {
                    Expect::Skip(used, kind(State::Trailers))
                }
            }
        },
        State::Close => {
            let size = len.min(block);
            if size == block || (eof && size != 0) {
                Expect::Block(size, kind(State::Close))
            } else if eof {
                Expect::Done(kind(State::End))
            } else {
                Expect::Need
            }
        }
        State::Done => Expect::Done(kind(State::Boundary)),
        // A body read on its own ends after it: `begin(framing, true)`.
        State::Boundary | State::End => Expect::End,
        State::Head => unreachable!(),
    };
    // At the end of input with nothing buffered, a body that is not
    // finished is a failure (`Reader::body`).
    if expect == Expect::Need && eof && len == 0 {
        expect = Expect::Fail;
    }

    let got = outcome(&mut decoder, input, eof);
    assert!(got == expect);
    // Which outcomes the harness reaches: none of the asserts above holds
    // only because its case never happens.
    kani::cover!(matches!(got, Expect::Need), "waits for input");
    kani::cover!(matches!(got, Expect::Fail), "refuses");
    kani::cover!(matches!(got, Expect::Skip(..)), "consumes framing");
    kani::cover!(matches!(got, Expect::Block(..)), "yields a block");
    kani::cover!(matches!(got, Expect::Done(_)), "yields Done");
    kani::cover!(matches!(got, Expect::End), "ends");
    if got == Expect::Need {
        assert!(kind(decoder.core.state) == kind(state));
        if !eof {
            assert!(len < capacity);
        }
    }
    assert!(decoder.capacity() == capacity);
}

// One harness per state and mode: with the state and the mode fixed, CBMC
// leaves out the other arms of `Reader::body`, and each formula fits in
// memory.

/// Inside a Content-Length body, at any count.
#[kani::proof]
#[kani::stub(core::slice::memchr::memchr, find_byte)]
#[kani::unwind(8)]
fn length_steps_follow_the_grammar() {
    one_step_follows_the_grammar(false, State::Length(kani::any()));
}

/// Inside a chunk's data, at any count.
#[kani::proof]
#[kani::stub(core::slice::memchr::memchr, find_byte)]
#[kani::unwind(8)]
fn data_steps_follow_the_grammar() {
    one_step_follows_the_grammar(false, State::Data(kani::any()));
}

/// A body that ends with the connection.
#[kani::proof]
#[kani::stub(core::slice::memchr::memchr, find_byte)]
#[kani::unwind(8)]
fn close_steps_follow_the_grammar() {
    one_step_follows_the_grammar(false, State::Close);
}

/// The steps after a body: `Done`, then the end.
#[kani::proof]
#[kani::stub(core::slice::memchr::memchr, find_byte)]
#[kani::unwind(8)]
fn steps_after_a_body_follow_the_grammar() {
    one_step_follows_the_grammar(false, State::Done);
    one_step_follows_the_grammar(false, State::Boundary);
    one_step_follows_the_grammar(false, State::End);
}

/// The first index of `x` in `text`, byte by byte: what `memchr` returns.
/// Every harness here stubs `core::slice::memchr::memchr` with it: CBMC
/// cannot rule out memchr's word-at-a-time path for long slices at a
/// symbolic length, and with it the formulas do not fit in memory.
fn find_byte(x: u8, text: &[u8]) -> Option<usize> {
    let mut i = 0;
    while i < text.len() {
        if text[i] == x {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// A chunk-size line, strict.
#[kani::proof]
#[kani::stub(core::slice::memchr::memchr, find_byte)]
#[kani::unwind(8)]
fn strict_size_steps_follow_the_grammar() {
    one_step_follows_the_grammar(false, State::Size);
}

/// A chunk-size line, skipping whitespace and extensions.
#[kani::proof]
#[kani::stub(core::slice::memchr::memchr, find_byte)]
#[kani::unwind(8)]
fn lenient_size_steps_follow_the_grammar() {
    one_step_follows_the_grammar(true, State::Size);
}

/// The CRLF after a chunk's data, strict.
#[kani::proof]
#[kani::stub(core::slice::memchr::memchr, find_byte)]
#[kani::unwind(8)]
fn strict_data_end_steps_follow_the_grammar() {
    one_step_follows_the_grammar(false, State::DataEnd);
}

/// The CRLF after a chunk's data, skipping extras.
#[kani::proof]
#[kani::stub(core::slice::memchr::memchr, find_byte)]
#[kani::unwind(8)]
fn lenient_data_end_steps_follow_the_grammar() {
    one_step_follows_the_grammar(true, State::DataEnd);
}

/// The empty trailer section, strict.
#[kani::proof]
#[kani::stub(core::slice::memchr::memchr, find_byte)]
#[kani::unwind(8)]
fn strict_trailer_steps_follow_the_grammar() {
    one_step_follows_the_grammar(false, State::Trailers);
}

/// A trailer line, skipped.
#[kani::proof]
#[kani::stub(core::slice::memchr::memchr, find_byte)]
#[kani::unwind(18)]
fn lenient_trailer_steps_follow_the_grammar() {
    one_step_follows_the_grammar(true, State::Trailers);
}

// The same states again, each split at any cut.

#[kani::proof]
#[kani::stub(core::slice::memchr::memchr, find_byte)]
#[kani::unwind(8)]
fn length_steps_are_independent_of_the_split() {
    one_step_is_independent_of_the_split(false, State::Length(kani::any()));
}

#[kani::proof]
#[kani::stub(core::slice::memchr::memchr, find_byte)]
#[kani::unwind(8)]
fn data_steps_are_independent_of_the_split() {
    one_step_is_independent_of_the_split(false, State::Data(kani::any()));
}

#[kani::proof]
#[kani::stub(core::slice::memchr::memchr, find_byte)]
#[kani::unwind(8)]
fn close_steps_are_independent_of_the_split() {
    one_step_is_independent_of_the_split(false, State::Close);
}

#[kani::proof]
#[kani::stub(core::slice::memchr::memchr, find_byte)]
#[kani::unwind(8)]
fn steps_after_a_body_are_independent_of_the_split() {
    one_step_is_independent_of_the_split(false, State::Done);
    one_step_is_independent_of_the_split(false, State::Boundary);
    one_step_is_independent_of_the_split(false, State::End);
}

#[kani::proof]
#[kani::stub(core::slice::memchr::memchr, find_byte)]
#[kani::unwind(8)]
fn strict_size_steps_are_independent_of_the_split() {
    one_step_is_independent_of_the_split(false, State::Size);
}

#[kani::proof]
#[kani::stub(core::slice::memchr::memchr, find_byte)]
#[kani::unwind(8)]
fn data_end_steps_are_independent_of_the_split() {
    one_step_is_independent_of_the_split(kani::any(), State::DataEnd);
}

#[kani::proof]
#[kani::stub(core::slice::memchr::memchr, find_byte)]
#[kani::unwind(8)]
fn strict_trailer_steps_are_independent_of_the_split() {
    one_step_is_independent_of_the_split(false, State::Trailers);
}

/// `chunk_size` and `chunk_size_skipping_extensions` on any line of up to
/// 20 bytes: a value exactly when the grammar gives one, and that value;
/// never an overflow or a panic.
#[kani::proof]
#[kani::stub(core::slice::memchr::memchr, find_byte)]
#[kani::unwind(22)]
fn chunk_size_is_the_hex_value_or_refused() {
    let (bytes, len) = input::<20>();
    let line = &bytes[..len];
    let strict = chunk_size(line).ok();
    assert!(strict == spec_hex(line));
    let skipping = chunk_size_skipping_extensions(line).ok();
    let semi = line.iter().position(|b| *b == b';').unwrap_or(len);
    let expected = if line[semi..].iter().copied().all(spec_field_byte) {
        spec_hex(spec_trim(&line[..semi]))
    } else {
        None
    };
    assert!(skipping == expected);
}
