# Codec layer verification

This pass checks `src/stdlib/codec/` on branch `fv-codec`, off `8ccf47fae`:
`stream.rs`, `buffer.rs`, `frames.rs`, `reader.rs`, `bounded.rs`,
`checked.rs`, `leb128.rs`, `base64.rs`, `ber.rs`, `demux.rs`,
`head_body.rs`, `dot_body.rs`, `crc32.rs` and `crc32c.rs`. The model is in
`verification/codec/`: Kani harnesses over the production Rust and a TLA+
model of `Demux`. It found two bugs, both confirmed by a failing unit test
before the fix and fixed at the root. `verification/codec/README.md` says
how to run everything.

## What was modeled and checked

### Kani, over the production code

The harnesses in `verification/codec/kani/` are included from
`src/stdlib/codec/mod.rs` under `cfg(kani)` and call the real functions.
Every harness passed. The checks column is CBMC's count for the harness;
every harness also passed its unwinding assertions, so each loop is proved
to end within its bound.

KANI_TABLE

Bounds: byte strings of four to ten bytes (six for most readers, eight for
base64 text and the signed frame header, ten for LEB128 and the eight-byte
readers), every `u64` for LEB128 and every `u128` for base-128, two framed
values plus an optional partial frame, three driver steps for the chaos
decoders, three buffer operations of up to three bytes under a limit of
four.

The `Decode` contract is given to the solver in `stream.rs`'s `Chaos`
decoder: counts within the input, the capacity at least the input read,
no growth of held state across `Need`, no `Need` at capacity, and a run
of zero-byte skips bounded by one more than the most bytes held during it,
as `Stream`'s documentation states. A decoder that keeps it is never
reported `Stuck`. Without the contract the same decoder, choosing every
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
| `Demux_base` | All five invariants and the action property pass: 1,246,857 states generated, 29,167 distinct, depth 13, empty queue |
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

Fix (`e09efa687`): the limit follows the capacity at the top of every loop
iteration in `with_next`, so each decode and each full-buffer judgement
sees the current capacity. The Kani harness
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

Fix (`d7cbe5bea`): `total()` charges the excess to the settled stream only
when that stream's own charge grew. A stream that changed nothing, or
shrank, leaves the blame where it was.

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
  not modeled.
- `Scanner::scan_head` differs between its two line-ending modes on a
  leading blank line: with CRLF required it passes over one leading CRLF,
  with LF accepted it returns the blank line as a complete head. Both
  callers, RTSP and SIP, skip keep-alive line endings before the scanner,
  so no caller sees the difference; it is noted here, not changed.
- `Demux`'s unit tests, not the model, cover what the real `Stream` and
  decoders do inside one of its streams.
