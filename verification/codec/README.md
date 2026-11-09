# Codec layer verification

This directory checks `src/stdlib/codec/`, the bounded decoders, byte
buffer and stream driver every protocol module is built from, in two ways:

| Part | What it is | Where |
|---|---|---|
| Kani | Bounded proofs over the production Rust: no panics, round trips, and framing that loses and duplicates nothing, for every input up to a bound | [`kani/`](kani/) |
| TLA+ | A model of `Demux`'s shared budget, checked with TLC, with three ablations that must fail | [`tla/`](tla/) |

[`VERIFICATION.md`](VERIFICATION.md) beside this file reports the results
of the pass that added this directory, the two bugs it found, and their
fixes.

## Kani

The harnesses are included from `src/stdlib/codec/mod.rs` under
`cfg(kani)`, so they call the real functions, not copies. Every symbolic
input is bounded by a constant named in its file; every loop is unwound
to a bound that Kani checks with an unwinding assertion, so a proof also
says the code terminates within that bound. None of them stubs a function.
Run one harness, or the 36 in this directory (a bare `cargo kani -p
fictionet` also runs every other area's harnesses, whose controls fail by
design):

```sh
cargo kani -p fictionet --lib --harness every_u64_roundtrips_in_its_shortest_form
cargo kani -p fictionet --lib --harness stdlib::codec::proofs
```

A harness holds about 8 GiB at most; the stream and buffer harnesses are
the heaviest. Run them one at a time if memory is short.

| File | Code | Proves |
|---|---|---|
| `reader.rs` | `Reader`, `be16`..`le64` | Every fixed-width read consumes exactly its width and returns those bytes, or fails and leaves the position; length-prefixed reads consume a complete prefix first; `tlv_u16_be` is all or nothing; `nul_bytes` stops at the first NUL; the free offset readers agree with the cursor |
| `leb128.rs` | `encode_with`, `decode_with`, zigzag | Every `u64` encodes to its shortest form and decodes back; decoding keeps both bounds on any input; zigzag is a bijection on each width |
| `base64.rs` | `encode_with`, `decoded`, `is_valid` | Every input round-trips under every padding policy; a canonical text re-encodes to itself; the policies nest |
| `ber.rs` | `write_base128`, `read_base128`, `read_length` | Every `u128` round-trips minimally; a value read is the only encoding of itself; a length prefix agrees with its octets under every policy |
| `crc.rs` | `crc32`, `crc32c` | The tables agree with the bit-at-a-time definition of each polynomial; CRC-32C composes across any split |
| `frames.rs` | `signed_frame_prefix` | Every input is exactly one of a complete frame, a request for more, or a refusal known from the header |
| `bounded.rs` | `reserve_bytes`, `append_bounded` | A refusal leaves the vector unchanged; a success stays within the limit and appends exactly the copies asked for |
| `buffer.rs` | `Buffer`, `write_bounded` | For any sequence of pushes, direct reads, consumes, shrinks and limit changes the unread bytes are the accepted bytes not yet consumed, the offset counts consumed bytes, new input never passes the limit, and storage stays within twice the largest limit; a bounded write is all or nothing |
| `dot_body.rs` | `encoded_len`, `write`, `Accumulator` | The count matches the bytes written; the stuffed lines fed back give the body; the accumulator never holds more than its limit |
| `head_body.rs` | `head_size`, `write_headers`, `Scanner`, `content_length` | The size counts exactly what is written; scanning a head never panics, ends only at a blank line within the limits, and gives the same answer whole or in two parts; no length is found without a length header |
| `stream.rs` | `Stream`, `pump`, `finish`, `Frames` | Values framed through any chunking are exactly the values written, with a trailing partial frame reported as truncation; a decoder that raises its capacity on a zero-byte skip is not reported stuck; the stream's byte accounting and terminal behaviour hold against a decoder whose every step the solver chooses; a decoder that keeps the `Decode` contract is never reported stuck |

The bounds are small: input strings of two to ten bytes (three for the
CRCs, six for most readers, eight for base64 text and the signed frame
header, ten for LEB128 and the eight-byte readers), every `u64` for LEB128
and every `u128` for base 128, two framed values plus an optional partial
frame, three driver steps, three buffer operations. Within them the proofs
are exhaustive. They do not cover `Pipe` and `Spans` (`pipe.rs`),
`Assemble`, `Lines`, `Collect` and `Map` (`combinators.rs`), which have
their own tests in `src/stdlib/codec/tests.rs`, nor `write_checked`
(`checked.rs`), nor `Demux`, which the TLA+ model covers.

The last `stream.rs` harness, `an_honest_decoder_is_never_stuck`, gives
the solver the `Decode` contract as the harness's `Chaos` decoder states
it: counts within the input, a capacity at least the input read, no held
growth across `Need`, `Need` only while the input is shorter than the
capacity *after* the call, and the zero-byte skip allowance `Stream`
itself uses. That last rule is the stream's own judgement restated, so the
harness checks that `Stream` applies its documented rule, not that the
rule is right. The `Need` rule lets a decoder raise its capacity on the
call that returns `Need`; `Stream::with_next` judges that call against the
buffer limit set from the capacity before it (`buf.room() == 0`,
stream.rs:318) and reports `Stuck` when the buffer was full at the old
capacity. By reading, the harness should fail on that case (a decoder of
capacity 1 given one byte, answering `Need` with capacity 2); the pass
below recorded it as passed, and this audit could not run Kani to settle
it. See `VERIFICATION.md`.

## TLA+

[`tla/Demux.tla`](tla/Demux.tla) models the shared budget of
`Demux` (`src/stdlib/codec/demux.rs`): the cached `total` of every live
stream's input allocation and decoder-held bytes, kept across
`push_with_budget` (`push` is the same call with an unbounded growth),
`next`, `end`, `remove`, `get_mut` and `shrink`. Streams are abstract;
what a decoder does on `next` is nondeterministic. Each action names the
method it stands for; `Mutate` is the caller's change to a stream it
reached through `get_mut`.

| Property | States |
|---|---|
| `Charged`: when no stream is out through `get_mut`, `total` is the sum over live streams | The cached charge is exact |
| `BudgetKept`: with nothing out and no excess pending, `total` is within the budget | The budget holds through every owner operation |
| `ExcessLive`: an excess always names a live stream | It can be released |
| `PendingVisited`: an error waiting behind a delivered item sits on a closed key in the ready set | It will be delivered |
| `ReadyHasEntry`: ready keys have entries, and entries never exceed the stream limit | |
| `ExcessReleasedFirst` (action): the first visit after an excess releases that stream and no other | |

Run with TLC:

```sh
cd verification/codec/tla
java -Xmx6g -cp ~/.cache/adorably-fv/tla2tools.jar tlc2.TLC -workers auto -config Demux_base.cfg Demux.tla
```

`Demux_base.cfg` has three keys, two stream slots, a budget of three
bytes and streams of at most two allocated and two held bytes. It passes
every property: 1,246,857 states generated, 29,167 distinct, depth 11
(the pass wrote 13; the run on main at e2858ccc4 and a one-worker rerun
in this audit both report 11), empty queue. Each `Demux_without_*.cfg`
switches one rule off and must violate `BudgetKept`:

| Config | Rule off | Shortest violation |
|---|---|---|
| `Demux_without_chargeopenheld` | the factory's initial held bytes are not checked against the room | depth 3 |
| `Demux_without_chargeexcess` | an over-budget direct change is not charged to its stream | depth 5 |
| `Demux_without_blamegrower` | the excess is charged to whichever stream is settled while the total is over budget, as the code did before its fix | depth 7 |

The model allows one unsettled excess at a time, which is the case the
owner recovers from; two streams grown over the budget before a visit is
outside the caller's contract and outside the model. Allocator overhead,
provenance spans and the rotation order of the ready set (`cursor`,
demux.rs:207-217; the model picks any ready key) are not modelled. The
model has no EOF flag: after `End(k)` a `Push(k)` may still grow the
allocation, where `Stream::push_with_budget` (stream.rs:101-103) takes and
drops the bytes; and `Mutate` changes only `alloc` and `held`, where a
caller holding the `&mut Stream` from `get_mut` may also call `next` or
`end`. Both let the model do more than the code, never less, so no
property can pass on a behaviour the code has and the model lacks. The
code's saturating arithmetic is plain arithmetic in the model.
