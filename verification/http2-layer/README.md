# HTTP/2 as a layer

The HTTP/2 server is a layer now: `Http2` (`src/stdlib/web/httpd/http2.rs`)
has a byte stream below and one `HttpExchange` child per stream above,
which `Children` (`src/stdlib/layer/children.rs`) runs; `Respond`
(`http2/respond.rs`) answers a stream with a handler, and `Grpc`
(`http2/grpc.rs`) carries gRPC calls on one. HTTP/2 starts either from the
client's preface, which `Detect` (`detect.rs`) tells from HTTP/1, or from an
HTTP/1 `Upgrade: h2c` that `Http1` (`native.rs`) answers with 101 and hands
on through `Switch`.

This directory checks that composition: four TLA+ models of the protocol
state machines and the composition, and Kani proofs of the arithmetic and
the byte scan the models take as given. Each model's header names the
source lines it follows, at commit 733f6c2c2 on `comp/v-http2` (the code
after the fixes below). On 2026-11-09 they were checked against
e2858ccc4: the `http2.rs`, `detect.rs`, `respond.rs` and `native.rs`
lines still hold, and the `children.rs` and `switch.rs` lines in the
headers were brought up to date. Each property has a configuration that breaks one
rule of the code and must violate that property; each counterexample was
read to check that it fails for the stated reason.

`verification/http` has the earlier models of the HTTP/2 server
(`Streams.tla`, `Flow.tla`) from before it was a layer. Their exchange takes
each body byte as it comes, so the stream children, their credit and the
handoffs are not in them. They are left as they are.

## Running

TLC 2.19 on JDK 21; Kani 0.68.0 with CBMC 6.11.0. From
`verification/http2-layer/tla`, one configuration at a time, with state
directories off `/tmp`:

```sh
states=${STATES:?a directory for TLC states, not under /tmp}
systemd-run --user --scope -q -p MemoryMax=8G -p MemorySwapMax=0 \
  ~/.cache/adorably-fv/jdk/bin/java -Djava.io.tmpdir=$states -XX:+UseParallelGC -Xmx6g \
  -cp ~/.cache/adorably-fv/tla2tools.jar tlc2.TLC -workers 4 \
  -metadir $states/Flow_base -config Flow_base.cfg Flow.tla
```

Every `*_base.cfg` must pass; every `*_without_<flag>.cfg` must report the
violation its first comment line names. `CHECK_DEADLOCK FALSE` is set
everywhere: a finished run has nothing left to do.

The Kani harnesses are compiled into `http2.rs` (`kani/flow.rs`) and
`detect.rs` (`kani/detect.rs`) under `cfg(kani)` and call the production
functions:

```sh
systemd-run --user --scope -q -p MemoryMax=12G -p MemorySwapMax=0 env CARGO_BUILD_JOBS=6 \
  cargo kani -p fictionet \
  --harness credit_back_tops_the_window_up_to_the_room \
  --harness a_frame_fits_both_windows_and_the_frame_size \
  --harness window_updates_add_exactly_or_refuse_past_the_maximum \
  --harness initial_window_changes_move_windows_exactly \
  --harness body_credit_tops_up_to_send_credit \
  --harness scan_takes_each_byte_once_and_chooses_at_the_first_difference
```

The regression tests for the bugs below:

```sh
cargo test -p fictionet --lib -- httpd::http2::tests
cargo test -p fictionet --test it -- an_upgrading_body_larger_than_the_streams_window
```

## Flow.tla: flow control across the layer and its children

The receive side: `on_data` debits both windows and `tell`s the child;
`forward` moves events up within the child's credit, splitting a body piece
larger than that credit; bytes waiting for credit are `Stream::held`, or
`Stream::outside` for the body an `Upgrade: h2c` request brought over
HTTP/1. `Children` gives each child its window and grants credit back as
the child reads. `release`, once a batch is over, returns credit by
WINDOW_UPDATE: on the connection for bytes it no longer holds, on a stream
for what its child can take once the child has read all it was given. A
release is due after input, after a child's grant, and after a stream with
held bytes ends. The send side: `admit` grants a child `SEND_CREDIT`,
`on_child` takes body pieces within it, `send_one` frames within both send
windows and the frame size, `grant` tops the child up, and WINDOW_UPDATE
and SETTINGS_INITIAL_WINDOW_SIZE refill the windows with their 2^31 - 1
checks. Bytes are units and windows hold a few.

| Property | States |
| --- | --- |
| `ReleasedOnlyFreed` | the client never holds credit for a byte the connection still holds, on the connection or a stream; `held` matches the pending queues |
| `NothingHeld` | with each child's credit a whole window, as `Responder` composes it, the connection never holds a request byte for a child |
| `SendWindowsBounded` | no send window passes 2^31 - 1 |
| `ServerSpendsWithinWindows` | no DATA frame goes past either send window |
| `ChildWithinGrant` | the connection holds at most `SEND_CREDIT` of a response it has not framed |
| `CreditAgrees` | the connection and `Children` agree on a child's body credit, so a child within its credit is never reset |
| `BodyReachesChild` (liveness) | every request body byte, h2c body included, reaches a child that reads |
| `RequestsEnd` (liveness) | the client gets to send every body whose child reads, whatever other children do, once it stops moving its initial window |
| `ResponsesEnd` (liveness) | every response goes out whole, under a client that grants credit when a response waits for it |

| Config | Setting | Result |
| --- | --- | --- |
| `Flow_base` | streams 1 (h2c, a 3-unit body over a 2-unit child credit) and 3 (a 5-unit body), windows of 2, `SEND_CREDIT` 2, 3-unit responses | passes: 3,188,421 states generated, 816,304 distinct, depth 46, 5 min 50 s |
| `Flow_stalled_base` | the h2c child never reads a 4-unit body | passes: 109,536 generated, 32,910 distinct, depth 29 |
| `Flow_sibling_base` | stream 1's child never reads; stream 3's does | passes: 486,880 generated, 136,142 distinct, depth 34 |
| `Flow_reset_base` | three streams with half-window child credit; two never read and are reset by the client in the end | passes: 728,686 generated, 176,031 distinct, depth 28 |
| `Flow_without_splittocredit` | `forward` moves whole events only | violates `BodyReachesChild` (14 states): the h2c body waits in `pending` forever |
| `Flow_without_heldonlywindowed` | the h2c body counts as held | violates `RequestsEnd` (12 states): `held` 2 on stream 1, both connection windows 0, stream 3 stuck |
| `Flow_without_followchild` | a stream's credit returns once its bytes go up, read or not | violates `RequestsEnd` (10 states): the stalled stream holds the connection's whole window |
| `Flow_without_followchild_held` | as above | violates `NothingHeld` (5 states) |
| `Flow_without_releaseoncredit` | a child's grant makes no release due | violates `RequestsEnd` (9 states): stream 3's child caught up, its window stays 0 |
| `Flow_without_releaseonend` | a stream ending with held bytes makes no release due | violates `RequestsEnd` (21 states): streams 1 and 3 reset, the connection window stays 0 |
| `Flow_without_countheld` | `release` ignores held bytes | violates `ReleasedOnlyFreed` (4 states) |
| `Flow_without_checkoverflow` | no 2^31 - 1 checks | violates `SendWindowsBounded` (4 states) |
| `Flow_without_spendwithinwindows` | `send_one` ignores the windows | violates `ServerSpendsWithinWindows` (6 states) |
| `Flow_without_countoutbytes` | `grant` ignores queued bytes | violates `ChildWithinGrant` (6 states) |
| `Flow_without_recordgrant` | `grant` does not add to `Stream::granted` | violates `CreditAgrees` (5 states) |

The state counts in parentheses, here and in the tables below, are the
lengths of TLC's traces in the run of 2026-11-09 on main (two workers),
the initial state included; a liveness trace includes the loop it ends in.
They vary by one to three states between runs: a rerun the same day gave
13 for `splittocredit`, 10 for `releaseoncredit`, 11 for `endonwritten`,
7 for `takedeciding`, 8 for `handfirst`, 19 for `blockwhenfull` and 8 for
`cancelwork`.

## Lifecycle.tla: streams, children, RST_STREAM and GOAWAY

A new stream above `last_stream` opens a child, or is refused with
RST_STREAM at the stream limit or while draining. The child (`Respond`)
answers once the request ends or its body deadline fires, possibly through
work the runtime polls, and its head, body and end go down to `on_child`.
A stream ends when its END_STREAM is written (with a NO_ERROR reset if the
request is still open), when either side resets it, when `Children` refuses
its child, or when the connection closes; `end_stream` frees its slot and
sends the child `Closed`, on which `Children` drops it with its timers and
cancels its work. GOAWAY comes from the client or from `graceful_shutdown`
(2^31 - 1 and a PING, then the last stream once the PING returns).

| Property | States |
| --- | --- |
| `LegalTransitions` (action) | each stream moves only along RFC 9113 section 5.1: idle, open, half closed, closed, never back |
| `NoStreamPastGoaway` | no stream opens above the last stream of a GOAWAY the server sent |
| `GoawayNeverGrows` | each GOAWAY's last stream is at most the one before |
| `NoFrameAfterReset` | nothing but RST_STREAM is queued for a stream once either side reset it |
| `ChildRetiresWithStream` | a child lives only while its stream does, or until the `Closed` on its way |
| `NoWorkAfterRetire`, `NoTimerAfterRetire` | a retired child has no work running and no timer armed |
| `SlotsMatchStreams` | the slots hold exactly the live streams' children |
| `InFlightFinish` | a drain lets the streams in flight finish or be reset; it never closes the connection under one |
| `StreamsEnd` (liveness) | every stream ends, or the connection does |
| `DrainingCloses` (liveness) | a draining connection closes |

| Config | Result |
| --- | --- |
| `Lifecycle_base` (streams 1, 3 and 5, two at once, four client frames; `Children` may refuse stream 1's child) | passes: 14,376,013 states generated, 4,011,621 distinct, depth 43, 12 min |
| `Lifecycle_without_recordlast` (`on_headers` does not record a new stream as `last_stream`) | violates `LegalTransitions` (11 states): stream 1 answered and closed, then opened again |
| `Lifecycle_without_refusewhendraining` (new streams taken while draining) | violates `NoStreamPastGoaway` (4 states) |
| `Lifecycle_without_mingoaway` (`goaway` sends `last_stream` as it is now) | violates `GoawayNeverGrows` (5 states): a refused stream raised `last_stream` after the GOAWAY |
| `Lifecycle_without_waitforstreams` (a drain closes at once) | violates `InFlightFinish` (4 states) |
| `Lifecycle_without_endonclientreset` (the RST_STREAM arm keeps the stream) | violates `NoFrameAfterReset` (7 states): the child's head is framed after the client's reset |
| `Lifecycle_without_removeslot` (`end_stream` keeps the slot) | violates `SlotsMatchStreams` (3 states) |
| `Lifecycle_without_childrenretire` (`Children` hands `Closed` on as any event) | violates `ChildRetiresWithStream` (5 states) |
| `Lifecycle_without_cancelwork` (`Children` drops a child without cancelling its work) | violates `NoWorkAfterRetire` (7 states): the handler's work runs on after the reset |
| `Lifecycle_without_endonwritten` (`written` does not end a stream) | violates `StreamsEnd` (13 states): stream 3's END_STREAM is out and the stream stays open, holding the drain up |

## Settings.tla: SETTINGS and their acknowledgment

The server's SETTINGS go out when the connection opens, with the
acknowledgment deadline; the client's first frame must be SETTINGS without
ACK; each client SETTINGS is applied value by value, then acknowledged; an
initial window that takes a stream past 2^31 - 1 fails the connection. After
`Upgrade: h2c` the HTTP2-Settings values apply before stream 1 opens. Only
SETTINGS_INITIAL_WINDOW_SIZE is modeled, the one value whose application can
fail.

| Property | States |
| --- | --- |
| `AckEach` | on an open connection, every client SETTINGS got one ACK |
| `AckOnlyApplied` | no ACK goes out for SETTINGS whose values were not all applied (RFC 9113 section 6.5.3) |
| `UnexpectedAckFails` | an ACK when none is awaited fails the connection |
| `NoTimeoutAfterAck` | SETTINGS_TIMEOUT only while the ACK is awaited |
| `FirstFrameSettings` | nothing before the client's first SETTINGS is acted on |
| `UnackedTimesOut` (liveness) | a client that never acknowledges loses the connection |

| Config | Result |
| --- | --- |
| `Settings_base` (prior knowledge, seven client frames) | passes: 751 states generated, 377 distinct, depth 9 |
| `Settings_h2c_base` (after `Upgrade: h2c`) | passes: 864 generated, 449 distinct, depth 9 |
| `Settings_without_checkfirst` | violates `FirstFrameSettings` (2 states) |
| `Settings_without_checkawaiting` | violates `UnexpectedAckFails` (4 states) |
| `Settings_without_cleardeadline` | violates `NoTimeoutAfterAck` (4 states) |
| `Settings_without_armdeadline` | violates `UnackedTimesOut` (9 states) |
| `Settings_without_ackafterapply` (the code before 733f6c2c2) | violates `AckOnlyApplied` (5 states) |
| `Settings_without_ackevery` | violates `AckEach` (3 states) |

## H2cSwitch.tla: the bytes across the switch to HTTP/2

`Switch<Detect, Versions>` reads the first bytes until they tell the preface
from HTTP/1, then hands them and everything after to `Http2` or to
`Switch<Http1, Upgraded>`; after the 101 to `Upgrade: h2c`, `Http1::hand_on`
hands the bytes past the request, then the client's end, to the upgraded
`Http2`. Bytes are tokens, each its own position; the preface is two
tokens; the client sends chunks of one or two, then its end; the transport
offers each delivery again until it is taken.

| Property | States |
| --- | --- |
| `H2GetsTheRest` | HTTP/2 reads the bytes it should (all of them with prior knowledge, those after the request after h2c), each once, in order, from the first |
| `H2EndLast` | the client's end reaches HTTP/2 only after every byte did |
| `H1GetsTheInput` | with HTTP/1 chosen, HTTP/1 reads the input from its first byte, each once, in order |
| `H2GetsAll`, `H1GetsAll` (liveness) | every byte, and the end, reach the version chosen |

| Config | Result |
| --- | --- |
| `H2cSwitch_h2c_base` (h2c, more bytes than HTTP/1's buffer holds) | passes: 142 states generated, 72 distinct, depth 18 |
| `H2cSwitch_h2c_roomy_base` (h2c, the client's end before the 101 is written) | passes: 193 generated, 101 distinct, depth 17 |
| `H2cSwitch_pk_base` (prior knowledge) | passes: 50 generated, 31 distinct, depth 13 |
| `H2cSwitch_h1_base` (bytes leave the preface at the second) | passes: 38 generated, 25 distinct, depth 12 |
| `H2cSwitch_without_takedeciding` | violates `H2GetsTheRest` (9 states): the last preface byte read twice |
| `H2cSwitch_without_takedeciding_h1` | violates `H1GetsTheInput` (7 states): the differing byte read twice |
| `H2cSwitch_without_handfirst` | violates `H2GetsTheRest` (7 states) |
| `H2cSwitch_without_leftoversfirst` | violates `H2GetsTheRest` (6 states): a newer byte passes the preface |
| `H2cSwitch_without_keepunread` | violates `H2GetsTheRest` (11 states) |
| `H2cSwitch_without_blockwhenfull` | violates `H2GetsAll` (20 states): a chunk dropped while switching |
| `H2cSwitch_without_endafterdata` | violates `H2EndLast` (15 states) |

## Kani

`kani/flow.rs` proves the functions `release`, `send_one`, the WINDOW_UPDATE
arm, `peer_setting` and `grant` call, over their whole input types unless a
harness says otherwise, with Kani's overflow checks on every operation.
`kani/detect.rs` proves `scan`, the loop `Detect::on_event` reads the first
bytes with.

| Harness | Proves | Time |
| --- | --- | --- |
| `credit_back_tops_the_window_up_to_the_room` | for a window from 0 to 65,535 and any room up to a window, the credit tops the window up to exactly the room once that adds at least half of what the client has left, else none; never past the room or 65,535 | 0.12 s |
| `a_frame_fits_both_windows_and_the_frame_size` | a frame is the least of the piece, both windows (negative as none) and the frame size, and leaves neither window below zero | 0.15 s |
| `window_updates_add_exactly_or_refuse_past_the_maximum` | a WINDOW_UPDATE adds exactly its increment or is refused exactly past 2^31 - 1; an increment the parser never passes (2^31 or more) is refused, not wrapped | 0.04 s |
| `initial_window_changes_move_windows_exactly` | an initial window change moves a stream's window by exactly the change and is refused only past 2^31 - 1, never for going low, for any window at least `old - (2^31 - 1)` (the server spends a window only while it is positive) | 0.09 s |
| `body_credit_tops_up_to_send_credit` | a child's body credit tops granted plus queued bytes up to exactly `SEND_CREDIT` | 0.03 s |
| `scan_takes_each_byte_once_and_chooses_at_the_first_difference` | from each of the 24 points inside the preface and for any chunk of up to four bytes: a prefix is taken, each byte once and in order; no choice means all taken and still a proper prefix; HTTP/2 exactly at the whole preface; HTTP/1 exactly at the first differing byte, which is taken; the covers reach all three | 419 s |

Each reports `VERIFICATION:- SUCCESSFUL`. Each was also run once against a
broken copy of its function (`kani/` at the commit above, every harness in
one run), and each failed for that break:

| Broken function | Harness | Failed check |
| --- | --- | --- |
| `credit_back` returns up to a whole window, ignoring the room (a stream's credit before c21694faf) | `credit_back_tops_the_window_up_to_the_room` | `i64::from(back) == short` |
| `sendable` drops the stream window | `a_frame_fits_both_windows_and_the_frame_size` | `n <= ... stream_room` |
| `grown` casts the increment `as i32` (the code before 733f6c2c2) | `window_updates_add_exactly_or_refuse_past_the_maximum` | `increment <= MAX` |
| `shifted` adds the new window, then takes off the old | `initial_window_changes_move_windows_exactly` | `moved > MAX` (a spurious refusal) |
| `more_credit` ignores queued bytes | `body_credit_tops_up_to_send_credit` | `sum + more == SEND_CREDIT` |
| `scan` reads the differing byte into `first` but does not count it | `scan_takes_each_byte_once_and_chooses_at_the_first_difference` | `first.len() == read + taken` |

With a symbolic count of preface bytes already read, the `scan` harness ran
out of 12 GiB; it runs each of the 24 counts in turn instead.

## The bugs, fixed

Each has a test that failed before its fix and passes after.

1. **An h2c body larger than the child's credit never reached the
   child.** `forward` moved only whole events, and the body an `Upgrade:
   h2c` request brought is one piece, larger than the 65,535 units a
   `Respond` child is given: stream 1 waited until its body deadline and
   answered 408. `forward` now splits a body piece to the credit (commit
   96c6c6c5e). Test: `an_upgrading_body_larger_than_the_streams_window_reaches_the_handler`
   in `tests/it/http2_server/layers.rs` (before: no answer on stream 1).
   Model: `Flow_without_splittocredit`.
2. **The h2c body held back every other stream's connection credit.** It
   came outside the receive windows but counted in `Stream::held`, which
   `release` keeps back from the connection's credit; a child that read it
   slowly kept the client from sending on any stream. It is now
   `Stream::outside` (96c6c6c5e). Test:
   `a_stalled_upgrade_body_holds_back_only_its_own_stream` (before: no
   connection WINDOW_UPDATE after a full window on stream 3). Model:
   `Flow_without_heldonlywindowed`.
3. **Credit a child freed after its batch never returned.** A release
   was due only after new input, so credit for bytes a child took or read
   after the batch that brought them stayed with the server while the
   client, out of window, could send nothing. A child's grant now makes a
   release due (96c6c6c5e, c21694faf). Test:
   `credit_returns_once_a_slow_child_reads`. Model:
   `Flow_without_releaseoncredit`.
4. **Credit for bytes dropped with a stream never returned.** A stream
   that ended (here, reset by the client) with held bytes left them
   counted against the connection until new input came. `end_stream` now
   makes a release due (96c6c6c5e). Test:
   `credit_held_for_a_stream_that_ends_returns` (before: no connection
   WINDOW_UPDATE after the reset). Model: `Flow_without_releaseonend`.
5. **One child that stopped reading stopped every stream.** A stream's
   credit came back as soon as its bytes went up to the child, read or
   not, so a stalled child took one window into its inbox, then the
   connection held the next for it, which was the connection's whole
   window. A stream's credit now returns once its child has read all it
   was given, up to what the child can take (c21694faf); the connection
   never holds a request byte for a `Respond` child (`NothingHeld`). Test:
   `a_child_that_stops_reading_stops_only_its_own_stream` (before: the
   connection window was 0 once the client sent all stream 1's credit).
   Model: `Flow_without_followchild`.
6. **SETTINGS were acknowledged before they were applied.** An initial
   window that took a stream past 2^31 - 1 went out as an ACK followed by
   GOAWAY with FLOW_CONTROL_ERROR. The ACK now follows the values, as RFC
   9113 section 6.5.3 says (733f6c2c2). Test:
   `settings_that_fail_are_not_acknowledged`. Model:
   `Settings_without_ackafterapply`.

The flow-control arithmetic moved into small functions (`credit_back`,
`sendable`, `grown`, `shifted`, `more_credit`) and `Detect`'s loop into
`scan` so the Kani harnesses call the code the layer runs. `grown` takes
the increment with `i32::try_from` where the code cast it `as i32`; the
parser masks the increment to 31 bits, so the cast never wrapped in
practice.

## What the models leave out

- HPACK, CONTINUATION, PRIORITY, padding, PUSH_PROMISE, PING other than
  the shutdown PING, trailers as distinct from an end, and the frame
  decoder's own checks (frame sizes, zero increments, SETTINGS values),
  which are in `protocols/http2.rs` and its tests.
- Budgets and over-budget closing, the error-reset and pending-reset
  limits, the reset list's one-second expiry and its bound of 50
  (`Lifecycle.tla` ignores a reset stream's late frames for the whole run),
  `UP_LIMIT`, `OUT_LIMIT` and `FRAMES`, and the order frames of different
  streams take on the wire.
- `Flow.tla` has two or three streams, windows of a few units, and
  children that read all they hold at once; `send_one` takes from a
  stream's queued bytes as one run. `Lifecycle.tla` has three streams, two
  at once, four client frames, and one body piece per response. It arms
  the body deadline on every `opened`, while `Respond::new` arms none for
  a request that arrived complete, so the model allows a 408 the code
  cannot give (more behaviors, none hidden); `Respond` sends head, body
  and end as one step, while `Children` takes one command per visit, so
  in the code commands of different streams interleave; the client's end
  of input (`peer_ended`, `advance` http2.rs:1557-1562), the 431 and
  PROTOCOL_ERROR refusals in `on_headers` (head limits, a bad request, a
  bad content-length) and the pending-reset count are not in it.
  `Settings.tla` models only the initial window. `H2cSwitch.tla` has a
  two-token preface and messages of three to five tokens, and treats an
  HTTP/1 request as one token (the HTTP/1 pipeline is `Pipeline.tla` in
  `verification/http`).
- The Kani proofs cover the arithmetic and the byte scan, not `Http2` as
  a whole: its state lives in maps, queues and charged chunks behind an
  `Env`, which the TLA+ models take on instead.
- `Children`'s own guarantees (slots, generations, credit and inbox
  bounds, urgent completion, work cancellation) are `verification/layer`;
  here they are assumed as `Children` states them.

`Http2::on_command` returns `Admit::Closed(command)` after closing begins,
so the caller retains ownership of rejected output. `Lifecycle` models
commands only while the connection is open and does not distinguish the
admission return variants. The Rust regression offers commands in both
closing and closed phases and checks ownership is returned intact.

The unchanged `Lifecycle` baseline was rerun on November 9, 2026 and passed all
configured invariants and liveness properties with 4,011,621 distinct states.

## RFC 9113: flow control, SETTINGS and the end of a connection

The models above follow the code. These follow the RFC: two spec modules
written from the text of RFC 9113, and three models of the code that
INSTANCE them and check that the code refines them. `RfcFlow.tla` holds
the rules of flow control and SETTINGS for one direction of DATA (sections
3.4, 5.1, 5.4.1, 6.5, 6.9, 6.9.1 and 6.9.2); `RfcGoaway.tla` the rules for
an endpoint that ends a connection (sections 4.1, 5.4.1, 6.8 and 7). Each
rule is a property of its own, so a control names the one rule it breaks.

The code models are `Http2Rfc.tla` (the server layer `Http2`, both
directions: the client's DATA against the server's receive windows and the
credit it returns, and the server's DATA within the client's windows),
`SessionRfc.tla` (the sans-I/O `Session` in `protocols/http2.rs`, which had
no model), and `Http2Refusal.tla` (how `Http2` ends a connection it
refuses). Every step of a code model carries the frame it read or wrote
and what it did about it, and maps its state onto the spec's: the windows,
which streams may still send, the initial window in force, the SETTINGS
awaiting an ACK, and the frames queued. Each header names the source lines
it follows, at the commit that adds this section on `comp/fv-h2-flow`.

`Max` stands for 2^31 - 1 and every window, value and increment is a small
integer near it: `Max` 4, initial windows of 2, increments that land on
`Max` exactly and one past it, SETTINGS values that move a window below
zero, to `Max`, and past it. The rules only compare windows with `Max`
and add or subtract, so they mean the same at full scale; the Kani proofs
(here and in `kani/flow.rs`) show the Rust arithmetic is exact over the
whole range.

`Session` reads one direction, from a sender A to a receiver B, and is
given B's SETTINGS and WINDOW_UPDATE from the other direction. A applies a
SETTINGS frame as it reads it, but DATA A sent before then may still use
the larger window of an earlier value. So `Session` keeps two windows in
one: the most A may send, which counts from the largest initial window A
has not acknowledged away (`BoundCovers`), and A's own, which counts from
the one announced last and is what an overflow is judged on.

| Property | RFC 9113 | Rule |
| --- | --- | --- |
| `DataDebits` | 6.9, 6.9.1 | every DATA frame, padding and pad length byte included, counts against the connection window unless it ends the connection; one accepted counts against its stream too |
| `ConnExcess` | 6.9.1 | DATA past the connection window is a connection FLOW_CONTROL_ERROR |
| `NoFalseFlowError` | 6.9.1 | DATA within both windows is never refused for flow control |
| `StreamExcessRefused` | 6.9.1 | DATA past a stream's window is refused (a MAY; `Http2` does it with RST_STREAM) |
| `GrantWithinMax` | 6.9, 6.9.1 | credit written is never 0 and never takes a window past 2^31 - 1 |
| `BoundCovers` | 6.5.3, 6.9.2 | the window DATA is judged by covers every window the sender may still hold |
| `SendWithinWindows` | 4.2, 6.9.1 | DATA goes out within both windows and the frame size, on a stream that may send, and only while its window is positive |
| `WindowUpdateZero` | 6.9 | an increment of 0 is a connection error on stream 0, a stream error on a stream |
| `WindowUpdateIdle` | 5.1 | WINDOW_UPDATE on an idle stream is a connection error |
| `ConnWindowUpdate` | 6.9.1 | the connection window grows by the increment; past 2^31 - 1 the connection fails |
| `StreamWindowUpdate` | 6.9, 6.9.1 | a stream's window grows by the increment; past 2^31 - 1 the stream, not the connection, ends with RST_STREAM FLOW_CONTROL_ERROR; on a stream that can send no more it is no error |
| `SettingsApplied` | 6.5.2, 6.5.3, 6.9.2 | values apply in order; a value no endpoint may announce, or an initial window that takes a stream that may still send past 2^31 - 1, fails the connection; otherwise every such stream moves by the change, below zero included, the connection window does not move, and unknown identifiers change nothing |
| `SettingsAcked` | 6.5.3 | the ACK goes out once every value is applied, and only then |
| `SettingsFrame` | 6.5 | SETTINGS on a stream is a PROTOCOL_ERROR; a length not a multiple of 6, or an ACK with a payload, a FRAME_SIZE_ERROR |
| `AckHandling` | 6.5.3 | an awaited ACK settles the oldest SETTINGS; an unexpected one may be ignored or fail the connection |
| `FirstFrameData`, `FirstFrameUpdate` | 3.4 | nothing before the client's first SETTINGS is acted on |
| `ConnErrorGoaway` | 5.4.1 | a connection error is answered with GOAWAY carrying its code |
| `TerminalLast` | 5.4.1 | no frame follows the GOAWAY that ends a connection for an error |
| `RefusalSaysGoaway` | 5.4.1, 7 | a connection that ends for an error sends GOAWAY; load refused is ENHANCE_YOUR_CALM |
| `WholeFrames` | 4.1 | frames go out whole: GOAWAY never lands inside a DATA frame queued as header and payload |
| `LastNeverGrows` | 6.8 | each GOAWAY's last stream is at most the one before |
| `LastCoversActed` | 6.8 | the last stream of the final GOAWAY covers every stream acted on, and not one whose header block was never read whole |
| `NoStreamCarriedOn`, `NothingAfterEnd` | 6.8 | a connection that ends leaves no stream open in it and acts on no stream after |
| `GoawayFits` | (the code's promise) | the GOAWAY of a refusal always has the place and the bytes kept for it |

TLC reports the properties under their instance: `In!` (client to server)
and `Out!` (server to client) in `Http2Rfc`, `R!` in the other two.

| Config | Result |
| --- | --- |
| `Http2Rfc_base` (streams 1 and 3; up to five client frames; DATA of 0 to 2 bytes, unpadded or padded with 0 or 1 byte; increments 0, 1, 2 and 4; nine SETTINGS frames; a 2-unit response) | passes: 36,726,903 states generated, 6,368,221 distinct, depth 20, 5 min 49 s; every action taken |
| `SessionRfc_base` (streams 1 and 3; six steps of A's frames and B's routed ones; seven SETTINGS frames, one of 4 then 1) | passes: 5,574,033 generated, 917,670 distinct, depth 7, 1 min 3 s |
| `Http2Refusal_base` (streams 1 and 3; a budget of 4 units, `sent` keeping 2 places; six steps) | passes: 467,169 generated, 278,264 distinct, depth 27, 9 s |
| `Http2Rfc_without_skipended` (the code before this branch) | violates `SettingsApplied` (7 states): stream 1's END_STREAM framed with its window at 3, SETTINGS [1, 4] takes it to 5 and fails the connection |
| `Http2Rfc_without_shiftstreams` | violates `SettingsApplied` (4 states) |
| `Http2Rfc_without_countpadding` | violates `DataDebits` (4 states): a DATA frame of its pad length byte alone costs nothing |
| `Http2Rfc_without_checkconn` | violates `ConnExcess` (3 states) |
| `Http2Rfc_without_checkstream` | violates `StreamExcessRefused` (6 states) |
| `Http2Rfc_without_recvown` (DATA judged by the stream's send window) | violates `NoFalseFlowError` (5 states): after SETTINGS of 0, a byte within the receive window resets the stream |
| `Http2Rfc_without_positivecredit` (`credit_back` without its `back > 0`) | violates `GrantWithinMax` (5 states): WINDOW_UPDATE with an increment of 0 |
| `Http2Rfc_without_takeack` | violates `AckHandling` (3 states) |
| `Http2Rfc_without_checkfirst` | violates `FirstFrameData` (2 states) |
| `Http2Rfc_without_checkfirst_update` | violates `FirstFrameUpdate` (2 states) |
| `Http2Rfc_without_framecap` | violates `SendWithinWindows` (5 states): 2 bytes in a frame of 1 |
| `Http2Rfc_without_sendcheck` | violates `SendWithinWindows` (6 states): DATA on a window of 0 after SETTINGS of 0, which leaves it at -1 |
| `Http2Rfc_without_zeroreset` | violates `WindowUpdateZero` (4 states) |
| `Http2Rfc_without_checkidle` | violates `WindowUpdateIdle` (3 states) |
| `Http2Rfc_without_checkconnoverflow` | violates `ConnWindowUpdate` (3 states) |
| `Http2Rfc_without_checkoverflow` | violates `StreamWindowUpdate` (4 states): 2 + 4 taken as 6 |
| `Http2Rfc_without_ackafterapply` (the code before 733f6c2c2) | violates `SettingsAcked` (5 states) |
| `Http2Rfc_without_refusebadsettings` | violates `SettingsFrame` (3 states) |
| `Http2Rfc_without_sendgoaway` | violates `ConnErrorGoaway` (2 states) |
| `SessionRfc_without_streamoverflow` (the code before this branch) | violates `StreamWindowUpdate` (3 states): stream credit past 2^31 - 1 stops the direction |
| `SessionRfc_without_latestcredit` (the code before this branch) | violates `StreamWindowUpdate` (4 states): after B announces 0, unacknowledged, credit of 3 is refused though A's window goes from 0 to 3 |
| `SessionRfc_without_latestinitial` (the code before this branch) | violates `SettingsApplied` (5 states): after that credit, an empty SETTINGS stops the direction |
| `SessionRfc_without_skipclosed` (the code before this branch) | violates `SettingsApplied` (5 states): stream 1, ended at 3, fails SETTINGS [4, 1] |
| `SessionRfc_without_streamerrors` (the code before this branch) | violates `WindowUpdateZero` (3 states) |
| `SessionRfc_without_envelope` | violates `BoundCovers` (3 states) |
| `SessionRfc_without_dataenvelope` | violates `NoFalseFlowError` (4 states): after B announces 0, unacknowledged, a byte A may still send stops the direction |
| `SessionRfc_without_countpadding` | violates `DataDebits` (3 states) |
| `SessionRfc_without_checkconn` | violates `ConnExcess` (3 states) |
| `SessionRfc_without_checkconncredit` | violates `ConnWindowUpdate` (2 states) |
| `SessionRfc_without_ackfront` | violates `AckHandling` (5 states) |
| `Http2Refusal_without_guard` (the code before this branch) | violates `TerminalLast` (4 states): the shutdown's GOAWAY runs past the budget, `over_budget` queues GOAWAY ENHANCE_YOUR_CALM, and the shutdown's PING follows it |
| `Http2Refusal_without_reserve` | violates `GoawayFits` (3 states) |
| `Http2Refusal_without_keeppayload` | violates `WholeFrames` (5 states): GOAWAY between a DATA header the transport took and its payload |
| `Http2Refusal_without_minlast` | violates `LastNeverGrows` (4 states): a stream refused while draining raises `last_stream` past the GOAWAY before |
| `Http2Refusal_without_lastwords` | violates `RefusalSaysGoaway` (3 states) |
| `Http2Refusal_without_lastonread` | violates `LastCoversActed` (3 states): a header block cut off before its CONTINUATION is reported as maybe processed |
| `Http2Refusal_without_endall` | violates `NoStreamCarriedOn` (3 states) |
| `Http2Refusal_without_stopreading` | violates `NothingAfterEnd` (4 states) |

The state counts in parentheses are trace lengths in the runs of
2026-11-10, the initial state included. Each trace was read: each fails
for the reason in its config's first line.

### Kani: `Session`'s window arithmetic

`kani/session.rs` is compiled into `protocols/http2.rs` under `cfg(kani)`
and calls `credited` and `initial_fits`, the functions `Session` judges
credit and initial windows with. The inputs are a credit (granted less
sent), the largest unacknowledged initial window and the last announced,
over their whole ranges.

| Harness | Proves | Time |
| --- | --- | --- |
| `credit_counts_from_the_initial_window_announced_last` | credit of 1 to 2^31 - 1 is granted exactly when A's window stays within 2^31 - 1, and then the window grows by exactly the increment; covers A at exactly 2^31 - 1, one past it, and credit granted while the larger window passes 2^31 - 1 | 0.26 s |
| `initial_windows_fail_exactly_past_the_maximum` | a SETTINGS frame whose initial windows reach at most `most` fails exactly when `most` plus the credit passes 2^31 - 1, whatever window it counts from | 0.10 s |

Each reports `VERIFICATION:- SUCCESSFUL`, and each failed when its
function was put back to the arithmetic before this branch (judging on the
larger window). At 3db7a847e, `cargo kani -p fictionet` does not compile:
`verification/tls/kani/LayerProof.rs` and `verification/layer/kani/mod.rs`
no longer match the code (58 errors). These harnesses were run with those
two `cfg(kani)` modules switched off locally; that change is not
committed.

### The departures, fixed

Each has a test that failed before its fix and passes after.

7. **The shutdown's PING followed the GOAWAY that ended the connection.**
   When graceful shutdown's first GOAWAY ran past the budget,
   `over_budget` queued GOAWAY ENHANCE_YOUR_CALM and closed, and `advance`
   then queued the PING behind it. `push_piece` now queues nothing once
   the connection is closing. Test:
   `a_refusal_during_graceful_shutdown_writes_nothing_after_its_goaway`
   (before: the output ended with the PING). Model:
   `Http2Refusal_without_guard`.
8. **An ended response failed the connection on an initial window
   change.** `peer_setting` moved every stream it knew, including one
   whose END_STREAM was framed but not yet written; with its window at
   2^31 - 1, a larger initial window failed the whole connection with
   FLOW_CONTROL_ERROR. Section 6.9.2 moves only streams that may still
   send. Test: `an_initial_window_change_leaves_ended_responses_alone`
   (before: GOAWAY FLOW_CONTROL_ERROR, no ACK). Model:
   `Http2Rfc_without_skipended`.
9. **`Session` stopped on stream errors.** Its `step` returned every
   decoder refusal as its error, so WINDOW_UPDATE with an increment of 0
   on a stream stopped the direction. A stream-scope refusal is now
   `Event::StreamError`. Test: `a_zero_increment_on_a_stream_is_a_stream_error`.
   Model: `SessionRfc_without_streamerrors`.
10. **`Session` answered stream credit past 2^31 - 1 as a connection
    error.** Section 6.9.1 ends the stream. `peer_window_update` now
    returns `Credit`, and `Credit::StreamOverflow` leaves the window as it
    was. Test: `a_stream_window_overflow_ends_only_the_stream`. Model:
    `SessionRfc_without_streamoverflow`.
11. **`Session` judged overflow on the wrong window.** It judged credit and
    initial windows on the most A may send, not A's own window: with a
    smaller initial window announced and not acknowledged, credit that
    keeps A within 2^31 - 1 was refused, and after such credit even an
    empty SETTINGS stopped the direction. Test:
    `overflow_counts_from_the_initial_window_announced_last`. Models:
    `SessionRfc_without_latestcredit`, `SessionRfc_without_latestinitial`.
12. **`Session` moved ended streams on an initial window change.** One at
    2^31 - 1 stopped the direction. Test:
    `an_initial_window_change_leaves_ended_streams_alone`. Model:
    `SessionRfc_without_skipclosed`.

The tests are in `httpd::http2::tests` and `protocols::http2::tests`.

### Kept on purpose

- `Http2` ends without GOAWAY when the connection's storage does not fit
  its budget at open: nothing is queued and the GOAWAY cannot be paid
  for. Section 5.4.1 says SHOULD.
- `Http2` treats an unexpected SETTINGS ACK as a connection
  PROTOCOL_ERROR. RFC 9113 does not define it.
- A SETTINGS value no endpoint may announce is refused by the decoder,
  before the values ahead of it are applied. The connection fails either
  way and nothing is acknowledged.
- `Http2` resets a stream for DATA past its window; `Session` stops the
  direction with FLOW_CONTROL_ERROR. Section 6.9.1 allows both.
- `Session`'s window for DATA counts from the largest initial window in an
  unacknowledged SETTINGS frame, values in the middle of a frame included,
  so it can take DATA past any window A held. Refusing that DATA is a MAY.
- `Http2` enforces its own SETTINGS_MAX_CONCURRENT_STREAMS before the
  client acknowledges it, with RST_STREAM REFUSED_STREAM, which the client
  may retry (section 5.1.2).
- `Http2` ignores a zero increment on a stream that is closed, and resets
  with FLOW_CONTROL_ERROR a stream whose END_STREAM is framed when credit
  takes its window past 2^31 - 1. Neither is a connection error.

### What these models leave out

- `Http2Rfc` and `SessionRfc` model SETTINGS_INITIAL_WINDOW_SIZE,
  SETTINGS_MAX_FRAME_SIZE (in `Http2Rfc`), ENABLE_PUSH and unknown
  identifiers; HEADER_TABLE_SIZE is `hpack-grpc`. SETTINGS_TIMEOUT and the
  h2c HTTP2-Settings are `Settings.tla`.
- Stream states (RST_STREAM, reset streams' late frames, the reset list's
  expiry, even streams, PRIORITY, CONTINUATION order) are `Lifecycle.tla`
  and the sibling stream models. `Session` streams are never retired or
  reset by the peer here, and A sends nothing on a stream it ended.
- The children and their credit are `Flow.tla`: here each child reads all
  it holds at once and its credit is a whole window.
- Frames in flight between the endpoints: each model's peer acts on the
  latest state, which `Session`'s two windows cover for DATA.
- `Http2Refusal` counts the budget in units, a DATA payload costs none,
  and every other allocation is `Squeeze` and `Elsewhere`; the order of
  frames of different streams is not modeled.

### After `comp/buf-h2` merges

That branch reworks framing and HPACK. The spec modules follow the RFC and
stay as they are. Check again:

- every source line range in the headers of `Http2Rfc.tla`,
  `SessionRfc.tla` and `Http2Refusal.tla`;
- the decoder's `setting_valid`, the zero increment refusal and the
  scopes `Inputs::decode` gives them, which the models take as given;
- how `Http2` queues output: `push_piece`'s check of the phase, the two
  places it reserves, `LAST_WORDS`, `finish`'s push into the kept place,
  and `over_budget` keeping the payload of a DATA header the transport
  took; `Http2Refusal`'s pieces assume a largest DATA frame is a header
  piece and a payload piece;
- `on_data`'s count of a padded frame (`data.len() + padding.len() + 1`);
- `peer_setting`'s skip of streams whose reply is `Reply::Ended`;
- `Session::step`'s stream-scope refusal arm and its `blocks.pending`
  check, and `kani/session.rs`'s `#[path]` from `protocols/http2.rs`;
- then rerun the three base configs, every control, both Kani harnesses,
  and the six tests above.
