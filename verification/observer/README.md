# The passive TCP observer

The observer ([`observer.rs`](../../src/stdlib/network/observer.rs), with
each direction's reassembly in
[`observer/flow.rs`](../../src/stdlib/network/observer/flow.rs)) takes
captured IP packets and offers one `ObservedStream` child per TCP
connection. Two checks cover it:

- [`Observer.tla`](Observer.tla) is one connection as the observer follows
  it: both directions' reassembly as `Flow` does it, and what goes up to the
  child as `Observer` queues it, under loss, repeats, reordering, overlap,
  resets, eviction, replacement by a new SYN, a child closed from above, and
  the capture's end.
- [`kani/Flow.rs`](kani/Flow.rs) runs the real `Flow::push` and
  `Flow::finish` on symbolic captures, for what the model leaves out: the
  wire's 32-bit sequence wrap and the byte values themselves.

## What the observer must do, and where it is checked

| Rule | TLA+ | Kani |
| --- | --- | --- |
| It never sends: no write, no ACK | `NeverSends` | the types: `ObservedStream`'s command is `Infallible`, `TcpObserver`'s control port is `Top`, and `Observer::take_command` always returns `None` |
| Every byte of a direction appears exactly once, in data or inside an explicit gap | `Contiguous` | `observed_bytes_come_once_in_order`: each step starts where the last ended, and each byte is the one the sender sent at that position |
| A FIN ends the direction only once every byte before it came up | `FinIsReached` | the same harness: the FIN step comes only at the position after the last byte |
| Termination is typed and reported once per direction, and last | `EndOnce`, `ClosedAfterEnds`, `EventuallyClosed` | the same harness: nothing follows the FIN |
| A capture cut short ends incomplete: never `Fin`, and `Truncated` whenever bytes are known to be missing | `FinIsReached`, `CutShortIncomplete` | the same harness: `finish` never gives a FIN, a FIN seen but not reached leaves the direction holed, and bytes the capture carried that never came up leave it holed, which `Observer::finish` turns into `Truncated` |

`Termination` is a closed enum (`Fin`, `Reset`, `Truncated`, `Evicted`,
`Replaced`, `Finalized`), and only `Fin` is clean.

## Observer.tla

Positions are a direction's unwrapped sequence positions: 0 to N-1 for the
sender's bytes and N for its FIN. The capture may lose, repeat, reorder and
overlap segments, carry a RST, or end. The observer may evict the
connection (`make_room`, `let_go` for the connection bound) or replace it
on a new SYN, and the layer above may close the child. The header of
`Observer.tla` maps each action to its function and its lines at
`f0dceb76f`; every one of those lines still holds at `e2858ccc4` (the
two later commits that touch the observer, `2de017e3a` and `3d4e3df9d`,
moved none of them, and the profiling pass merged at `e2858ccc4` changed
no observer file: `take_event` still serves `opened` first and then its
`ready` children in turn, and `make_room` still evicts the child with the
most waiting).

`CutShortIncomplete` judges an end by what the capture showed, not by what
the flow kept: the history variable `carried` is the end of the furthest
payload the capture carried, and an end is known to be missing bytes when
`carried` is past the position or a FIN seen is. Before `6521cb8c2` the
model marked an end holed exactly when `Flow::holed` was true, so the
property held by definition.

Every property has a configuration that weakens one rule and must fail on
it:

| Control | What it changes | Fails on |
| --- | --- | --- |
| `Observer_without_passive` | the observer acknowledges what it put in order, as an endpoint's stream adapter would | `NeverSends` |
| `Observer_without_trimdelivered` | `push` delivers an in-order segment whole, without skipping bytes already delivered | `Contiguous` |
| `Observer_without_fininorder` | a FIN ends its direction when it is seen, ahead of a hole | `FinIsReached` |
| `Observer_without_endonlyopen` | `let_go` ends a direction that already ended | `EndOnce` |
| `Observer_without_holestruncate` | `finish` says `Finalized` even with bytes known to be missing | `CutShortIncomplete` |
| `Observer_without_droppedholes` | with holding off, a segment dropped ahead of a hole leaves no trace, as before `f0dceb76f` | `CutShortIncomplete` |
| `Observer_without_replacedholes` | a shorter segment replaces a held one and its tail leaves no trace, as before `f0dceb76f` | `CutShortIncomplete` |
| `Observer_without_evictends` | `make_room` drops what waits and closes the child with no end in its place | `ClosedAfterEnds` |
| `Observer_without_finishcloses` | `finish` ends every direction but never closes the child | `EventuallyClosed` |

TLC 2.19, `-workers 2`. The passing configurations finish with an empty
queue. The counts of a failing run depend on the order TLC explores in.

| Config | Generated | Distinct | Result |
| --- | ---: | ---: | --- |
| `Observer_base` (three bytes each way, one segment held, payloads up to two bytes) | 6,031,762 | 296,466 | every property holds, depth 19 |
| `Observer_unbuffered` (the same with holding off) | 7,975,125 | 382,228 | every property holds |
| `Observer_wide` (four bytes each way, two segments held; invariants only) | 260,694,429 | 10,473,745 | every invariant holds, depth 25, 8 minutes |
| `Observer_without_passive` | 127 | 76 | `NeverSends` |
| `Observer_without_trimdelivered` | 6,499 | 1,618 | `Contiguous`: two overlapping segments |
| `Observer_without_fininorder` | 905 | 352 | `FinIsReached`: a FIN ahead of a hole |
| `Observer_without_endonlyopen` | 394,060 | 33,791 | `EndOnce`: an end, then eviction |
| `Observer_without_holestruncate` | 189,225 | 17,674 | `CutShortIncomplete` |
| `Observer_without_droppedholes` | 4,208 | 736 | `CutShortIncomplete`: one segment dropped ahead of the hole, then the capture ends |
| `Observer_without_replacedholes` | 466,169 | 32,165 | `CutShortIncomplete`: two bytes held, a one-byte segment at their place, the hole filled, the capture ends |
| `Observer_without_evictends` | 2,579 | 548 | `ClosedAfterEnds` |
| `Observer_without_finishcloses` | 202,558 | 19,172 | `EventuallyClosed` |

`Observer_wide` checks invariants only: with `EventuallyClosed` TLC had not
finished after half an hour. `Observer_base` checks it. Only
`Observer_wide` and `Observer_without_replacedholes` hold two segments, the
least a replacement needs, since the code refuses a new held segment once
the bound is reached, even at the place of a held one.

What the model leaves out: the 32-bit wrap and byte values (the Kani
harnesses take them), the byte bound `Limits::buffered` (it acts as the
segment bound does), credit (the child takes events in order when it
likes), and which side opened. One connection at a time; the connection
bound appears as eviction. Two smaller differences from the code: `gap`
in `flow.rs` joins a gap to the one just before it, while the model's
`DrainFirst` appends a marker's gap unjoined, so the child may see two
adjacent gap events where the code sends one (`Contiguous` holds either
way); and `make_room` in the code also acts on a child whose connection
was already let go, replacing its pending ends with `Evicted` ones, where
the model's `MakeRoom` stops once the connection is detached.

## kani/Flow.rs

The sender sends two symbolic bytes after its SYN, then its FIN, from a
symbolic initial sequence number, so the capture may cross the top of the
sequence space anywhere. The capture is two segments, each a symbolic slice
of what was sent, perhaps with the FIN, in any order. Then the capture
ends. The harness checks every step `push` and `finish` give up against
what the sender sent. Two `kani::cover!` statements show it reaches a
capture across the wrap and an end before bytes the capture carried.

The flow holds nothing out of order (`Limits::segments` zero). With a
segment held, CBMC's symbolic execution of `BTreeMap` ran out of its 10 GB
cap even with the held segment's place fixed, so holding is left to
`Observer.tla` and to the randomized test
`random_segments_keep_the_stream_rules`. The harness gives `push` and
`finish` a `Vec` with room for every step: a `Vec` that grows under CBMC
splits every later read over its old and new allocations, and that took
more than 10 GB on its own.

Each control changes one thing as a layer without that rule would, and
must fail on the assertion its comment names:

Kani 0.68, CBMC 6.11, unwinding assertions on, each harness alone under a
10 GB cap, about two and a half minutes each:

| Harness | Checks | Result |
| --- | ---: | --- |
| `observed_bytes_come_once_in_order` | 3,354 | none fails (174 unreachable); both covers reached |
| `observed_bytes_without_trim`: bytes already delivered come up again | 3,354 | fails only "each step starts where the last one ended" |
| `observed_bytes_without_fin_in_order`: a FIN ends the direction when seen | 3,354 | fails only "the FIN comes after every position before it" |
| `observed_bytes_without_wrap`: sequence numbers stop at the top of the space | 3,354 | fails "each byte is the one the sender sent there", and three checks that follow from bytes put in the wrong place |
| `observed_bytes_without_holes_truncate`: the end ignores what is missing | 3,354 | fails only "bytes the capture carried that never came up end Truncated" |

Run on the code before `f0dceb76f`, the first harness fails only "bytes
the capture carried that never came up end Truncated".

## What it found

Two bugs, both fixed in `f0dceb76f` in `observer/flow.rs`, each with a
test in `observer/tests.rs` that failed before the fix. In both, the flow
threw away bytes the capture carried, and the capture's end said
`Finalized`, which promises no known hole:

- With out-of-order holding off (`Limits::segments` zero), a segment
  ahead of a hole was dropped with no marker for its place. Found by the
  stronger `CutShortIncomplete` with `Limits::segments` zero, and by the
  Kani harness. Test:
  `a_capture_that_ends_past_unmarked_dropped_bytes_is_truncated`.
- A shorter segment at the place of a held one replaces it, and the held
  one's tail went with it. Found by the stronger `CutShortIncomplete` in
  `Observer_wide`. Test:
  `a_capture_that_ends_past_a_replaced_tail_is_truncated`.

`Flow::dropped_to` now keeps the end of the furthest bytes dropped either
way, and `Flow::holed` counts them until the position passes them. Nothing
changes while the capture runs.

## Running

TLC, from this directory, with the JDK and `tla2tools.jar` of
`~/.cache/adorably-fv`:

```sh
java -Xmx2g -cp ~/.cache/adorably-fv/tla2tools.jar tlc2.TLC -workers 2 \
  -metadir "$STATES/Observer_base" -config Observer_base.cfg Observer.tla
```

Each control's first line, `\* expect violation: <Property>`, names the
property it must violate.

Kani, from the root of the repository, one harness at a time:

```sh
cargo kani -p fictionet --lib --exact \
  --harness stdlib::network::observer::flow::proofs::observed_bytes_come_once_in_order
```

The tests, which include a randomized check of the stream rules
(`random_segments_keep_the_stream_rules`):

```sh
cargo test -p fictionet --lib -- network::observer::
```
