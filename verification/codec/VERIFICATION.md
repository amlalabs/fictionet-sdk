# Codec layer verification

This pass checks `src/stdlib/codec/` on branch `fv-codec`, off `8ccf47fae`:
`stream.rs`, `buffer.rs`, `frames.rs`, `reader.rs`, `bounded.rs`,
`leb128.rs`, `base64.rs`, `ber.rs`, `demux.rs`, `head_body.rs`,
`dot_body.rs`, `crc32.rs` and `crc32c.rs` (`checked.rs`, which the pass
listed, has no harness: `write_checked` is not covered). The model is in
`verification/codec/`: Kani harnesses over the production Rust and a TLA+
model of `Demux`. It found two bugs, both confirmed by a failing unit test
before the fix and fixed at the root. `verification/codec/README.md` says
how to run everything.

The fixes landed on `main` as `12136eb84` (stream) and `37f37db9e`
(demux); the `fv-codec` commits named below are their originals and are
not in `main`'s history. A drift audit at `e2858ccc4` (2026-11-09) read
every model element and harness against the code at that revision: the
model matches `demux.rs` as it is today, and no harness calls a copy. Its
corrections are marked "audit" below.

## What was modeled and checked

### Kani, over the production code

The harnesses in `verification/codec/kani/` are included from
`src/stdlib/codec/mod.rs` under `cfg(kani)` and call the real functions.
The pass reported every harness passed, with its unwinding assertions, so
each loop is proved to end within its bound. The pass's write-up left its
results table as a placeholder (`KANI_TABLE`) and recorded no check counts
or times; the audit filled the table from the harness files. The rerun on
`main` at `e2858ccc4` (`check-all`, 2026-11-09) reached seven of these
harnesses before it was stopped, all `SUCCESSFUL`: the three `base64`, the
three `ber` and `bounded::appended_copies_are_all_or_nothing`. The other
29 have not been rerun since the pass.

| Harness | Code | Bound |
|---|---|---|
| `reader::take_skip_rest_and_finish` | `Reader::skip`, `take`, `rest`, `finish`, `peek_u8`, `remaining`, `is_empty` | 6 bytes, any skip and take |
| `reader::{one,two,three,four,eight}_byte_reads` | `Reader::u8`, `i8`, `u16_be`..`i64_le`, `u24_be`, `u24_le` | 10 bytes, any start |
| `reader::float_reads_carry_every_bit_pattern` | `Reader::f64_be`, `f64_le` | 10 bytes |
| `reader::offset_readers_agree_with_the_cursor` | `be16`..`le64` against `Reader` | 10 bytes, any offset, overflow included |
| `reader::length_prefixed_reads_consume_a_complete_prefix` | `length_prefixed_u8`, `length_prefixed_u16_be`, `tlv_u16_be` | 6 bytes |
| `reader::nul_terminated_reads_stop_at_the_first_nul` | `nul_bytes` | 6 bytes |
| `leb128::every_u64_roundtrips_in_its_shortest_form` | `encode_with`, `decode_with` | every `u64` |
| `leb128::decoding_keeps_both_bounds_on_every_input` | `decode_with` | 10 bytes, any byte and value bound |
| `leb128::zigzag_is_a_bijection` | `zigzag_encode32`, `zigzag_decode32`, `zigzag_encode64`, `zigzag_decode64` | every value |
| `base64::every_input_roundtrips_under_every_policy` | `encode_with`, `is_valid`, `decoded`, `digit` | 5 data bytes, three policies |
| `base64::canonical_text_reencodes_to_itself` | `decoded`, `encode_with` | 8 text bytes |
| `base64::the_policies_nest_and_validation_is_total` | `is_valid` | 8 text bytes |
| `ber::every_u128_roundtrips_minimally` | `write_base128`, `read_base128` | every `u128` value and limit |
| `ber::a_value_read_is_the_only_encoding_of_itself` | `read_base128`, `write_base128` | 6 bytes, any limit |
| `ber::length_prefixes_agree_with_their_octets` | `read_length` | 6 bytes, any policy |
| `crc::crc32_matches_the_ieee_definition` | `crc32` | 3 bytes |
| `crc::crc32c_matches_the_castagnoli_definition_and_composes` | `crc32c::checksum`, `update` | 3 bytes, any split |
| `frames::signed_frame_prefix_partitions_every_input` | `signed_frame_prefix` | 8 bytes, any limit |
| `bounded::reservations_keep_the_limit_and_the_contents` | `reserve_bytes` | 4 bytes, any count, limit at most 8 |
| `bounded::appended_copies_are_all_or_nothing` | `append_bounded` | 2-byte pattern and prefix, any copies, limit at most 8 |
| `buffer::the_buffer_is_a_bounded_byte_queue` | `Buffer::push_with_budget`, `consume`, `spare`, `commit`, `shrink`, `set_limit` and the readers | 3 operations, pushes of at most 3 bytes, limits at most 4 |
| `buffer::commit_without_an_offer_adds_nothing` | `Buffer::spare`, `commit`, `push`, `consume`, `set_limit` | 3 bytes, limit at most 4 |
| `buffer::bounded_writes_are_all_or_nothing` | `write_bounded` | 3 bytes each, limit at most 4 |
| `dot_body::stuffing_counts_exactly_and_roundtrips_through_the_accumulator` | `encoded_len`, `write`, `Accumulator::push`, `held` | body of at most 5 bytes, limit 8 |
| `dot_body::the_accumulator_holds_at_most_its_limit` | `Accumulator::push`, `held` | 3 lines of at most 3 bytes, limit at most 8 |
| `head_body::head_size_counts_exactly_what_is_written` | `head_size`, `write_headers`, `Header::new` | start line at most 3, at most 2 headers of 2-byte ASCII names and values, any limits |
| `head_body::scanning_a_head_is_bounded_and_independent_of_chunking` | `Scanner::new`, `scan_head`, `is_start` | 6 bytes, line limit at most 4, head limit at most 6, both ending modes, every split |
| `head_body::content_length_finds_no_length_without_a_length_header` | `content_length` | two lines of at most 4 bytes |
| `stream::frames_through_any_chunking_lose_or_duplicate_nothing` | `Stream::new`, `pump`, `finish`, `Frames<Blob>` (the harness's `Prefixed`) | two blobs of at most 2 bytes, an optional partial frame, any chunking |
| `stream::a_skip_that_raises_capacity_is_not_stuck` | `Stream`, `pump`, `finish` with the harness's `Widening` decoder | at most 5 bytes, widths 2 to 4 |
| `stream::the_stream_is_safe_against_any_decoder` | `Stream::push`, `end`, `with_next`, `next` with `Chaos` choosing every step | at most 4 bytes, 3 steps, held at most 2, capacity 1 to 4 |
| `stream::an_honest_decoder_is_never_stuck` | `Stream::push`, `end`, `next` with `Chaos` under the contract | the same |

Bounds (audit): byte strings of two to ten bytes (three for the CRCs,
six for most readers, eight for base64 text and the signed frame header,
ten for LEB128 and the eight-byte readers), every `u64` for LEB128 and
every `u128` for base-128, two framed values plus an optional partial
frame, three driver steps for the chaos decoders, three buffer operations
of up to three bytes under a limit of four.

The `Decode` contract is given to the solver in `stream.rs`'s `Chaos`
decoder: counts within the input, the capacity at least the input read,
no growth of held state across `Need`, no `Need` at capacity, and a run
of zero-byte skips bounded by one more than the most bytes held during it,
as `Stream`'s documentation states. A decoder that keeps it is never
reported `Stuck`. Audit: the contract's `Need` rule in `Chaos` is "the
input is shorter than the capacity after the call", which lets a decoder
raise its capacity on the call that answers `Need`; `Stream::with_next`
judges that `Need` against the buffer limit it set from the capacity
before the call (`self.buf.room() == 0`, stream.rs:318), so a decoder of
capacity 1 that is given one byte and answers `Need` with capacity 2 is
reported `Stuck` while the harness counts it honest. By reading, the
harness should fail there. Whether the stream or the contract statement
is right is for the owner: the `decoder()` doc (stream.rs:181) promises a
raised capacity takes effect before the next decode, and the fix below
made that true for `Skip(0)` but not for `Need`. The audit could not run
Kani; this needs a run of `an_honest_decoder_is_never_stuck`. Without the contract the same decoder, choosing every
step freely, cannot make the stream consume bytes it does not have, report
a span that does not match the bytes handed to the caller, lose or invent
bytes in `offset() + buffered()`, or yield anything after a terminal error.

### TLC, on the Demux budget

`verification/codec/tla/Demux.tla` models the cached charge
`Demux::total` keeps for every live stream's input allocation and
decoder-held bytes across `push_with_budget`, `end`, `remove`, `get_mut`,
`shrink` and one iteration of `next`. Three keys, two stream slots, a
budget of three bytes, streams of at most two allocated and two held
bytes. Each action names the method it stands for.

| Config | Result |
|---|---|
| `Demux_base` | All five invariants and the action property pass: 1,246,857 states generated, 29,167 distinct, depth 11 (audit: the pass wrote 13; the `check-all` run on `main` and a one-worker rerun both report 11), empty queue |
| `Demux_without_chargeopenheld` | `BudgetKept` violated at depth 3, as expected: the factory's held bytes pass the room check |
| `Demux_without_chargeexcess` | `BudgetKept` violated at depth 5, as expected: an over-budget direct change is not charged |
| `Demux_without_blamegrower` | `BudgetKept` violated at depth 7, as expected: this is the code before bug 2's fix |

## Bugs found and fixed

### 1. `Stream` reported a decoder stuck after it raised its capacity on a skip

`Stream::with_next` raised the buffer limit to the decoder's capacity once,
before its loop. A decoder that read the width of its records from the
first byte, raised its capacity to that width and returned `Step::Skip(0)`
was decoded again inside the loop with the old limit. It asked for more
bytes; the stream saw `room() == 0` and reported `Fail::Stuck`, although
the buffer held fewer bytes than the new capacity. The decoder kept every
rule of the `Decode` contract, and the `decoder()` documentation promised
that a raised capacity raises the limit before the next decode.

Reproduction: `regression_skip_that_raises_capacity_is_not_stuck` in
`src/stdlib/codec/tests.rs`. Before the fix it failed with
`Err(Stuck { unread: 1, capacity: 3 })` where `Ok(6)` was expected.

Fix (`12136eb84` on `main`; `e09efa687` on `fv-codec`): the limit follows
the capacity at the top of every loop iteration in `with_next`
(stream.rs:257-259), so each decode and each full-buffer judgement sees
the capacity as it was before that decode. The Kani harness
`a_skip_that_raises_capacity_is_not_stuck` proves the fixed path for every
record width and input up to five bytes.

### 2. `Demux` charged an excess to the wrong stream

`Demux::total` settles the stream that last escaped through `get_mut`. If
the total was then over the budget it charged the excess to that stream,
whether or not that stream had changed. After one stream grew over the
budget through `get_mut`, any `get_mut` or `remove` on another stream
moved the blame to that other stream; `remove` then cleared it. The next
`next()` found the total over budget with no excess recorded and refused
the first ready stream, an innocent one, while the stream that grew kept
its bytes.

TLC found the trace first (`Demux_base` with the old rule, now kept as
`Demux_without_blamegrower`). Reproduction:
`regression_demux_charges_the_excess_to_the_stream_that_grew` in
`src/stdlib/codec/tests.rs`. Before the fix it failed with
`Some((1, Err(Refused { unread: 1, limit: 4 })))` where stream 3 with its
seven bytes was expected.

Fix (`37f37db9e` on `main`; `d7cbe5bea` on `fv-codec`): `total()`
charges the excess to the settled stream only when that stream's own
charge grew (`after > before`, demux.rs:165). A stream that changed
nothing, or shrank, leaves the blame where it was.

## What the model leaves out

- The Kani proofs are bounded; inputs longer than the bounds are not
  covered, and allocation failure is not modeled (Kani's allocator does not
  fail, so the `Allocation` branches are only shown to leave data intact).
- `Pipe`, `Assemble`, `Lines`, `Collect` and `Map` are outside the pass;
  their tests stay in `src/stdlib/codec/tests.rs`.
- The TLA+ model allows one unsettled over-budget change at a time, which
  is the case `Demux` recovers from. Two streams grown over the budget
  before a visit is outside the caller's contract (`get_mut`: direct
  changes must preserve the shared budget) and outside the model. The
  ready set's rotation order, allocator overhead and provenance spans are
  not modeled. The model has no EOF flag and its `Mutate` moves only the
  escaped stream's bytes, not its `done` state, so it allows a `Push`
  after `End` to grow the allocation and a `Visit` of a stream the caller
  finished through `get_mut` to yield items; the code does neither, so
  the model explores more than the code, never less (audit).
- `Scanner::scan_head` differs between its two line-ending modes on a
  leading blank line: with CRLF required it passes over one leading CRLF,
  with LF accepted it returns the blank line as a complete head. Both
  callers, RTSP and SIP, skip keep-alive line endings before the scanner,
  so no caller sees the difference; it is noted here, not changed.
- `Demux`'s unit tests, not the model, cover what the real `Stream` and
  decoders do inside one of its streams.
