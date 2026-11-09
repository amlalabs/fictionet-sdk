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
