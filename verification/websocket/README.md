# WebSocket verification

Three kinds of checks cover the WebSocket codec in
`src/stdlib/protocols/websocket.rs`. Kani harnesses in `kani/frames.rs` run
the production parser and writer on every input up to a fixed size. A unit
test runs the whole decoder on every stream of up to three frames and
compares it with a receiver written from the RFC. TLA+ models in `tla/`
follow the receive state over time and the echo servers that run the codec
after the HTTP/1 switch, and both refine `tla/Rfc6455.tla`, a spec of one
endpoint written from the RFC text. The codec buffer proofs and the HTTP
pipeline handoff proofs are in `../codec/README.md` and `../http/README.md`.
The wire rules are those of
[RFC 6455 sections 5–7](https://www.rfc-editor.org/rfc/rfc6455.html#section-5).

Every property has a control: a configuration or harness that removes one
check and must then fail on the property it names. A control counts only
when it fails an assertion or invariant, not on parsing, unwinding or
memory.

## Kani on the production code

`kani/frames.rs` is included by `protocols/websocket.rs` under `cfg(kani)`.
Line numbers are in `protocols/websocket.rs`.

| Harness | Source | Inputs and property |
|---|---|---|
| `websocket_headers_follow_wire_grammar` | `Header::parse`:386, `Frames::header`:845 | Every byte string of 0 to 14 bytes. Reserved bits and opcodes are refused. Control frames must be final with at most 125 bytes. Lengths use the 7, 16 or 64-bit form, each only when the shorter form cannot hold it, with the high bit clear and at most `MAX_PAYLOAD`. A short header waits. A frame from a client must be masked and a frame from a server must not be. |
| `websocket_writer_uses_minimal_length` | `write_header`:777 | Every length from 0 to `MAX_PAYLOAD` (16 MiB), both FIN values, any mask. The writer uses the shortest length form, and the parser reads back the same length, FIN and key. |
| `websocket_mask_is_involution_and_composes` | `apply_mask`:517 | Eight arbitrary bytes, any key, any offset (including wrapping), every split. Each byte is XORed with the RFC's key byte, masking twice restores the input, and masking in two pieces equals masking at once. |
| `websocket_small_frames_{write,read}_{masked,unmasked}_{zero..four}` | `write_frame`:749, `Header::parse_exact`:454, `Frame::from_header`:499 | Binary payloads of 0 to 4 arbitrary bytes, any FIN, any key, in twenty harnesses. The writer produces the frame built byte by byte in the harness, and reading that frame gives back the payload, FIN and key. |
| `websocket_exact_frame_boundaries` | `Header::parse_exact`:454, `Header::payload`:469 | Every input of up to 18 bytes. Exact parsing refuses a truncated frame and a frame followed by more bytes, and the payload is exactly the declared bytes after the header. |
| `websocket_close_codes_follow_wire_ranges` | `Close::parse`:559, `Close` writer | All 65,536 codes. Parsing and writing accept exactly 1000–1003, 1007–1014 and 3000–4999. |
| `websocket_close_payload_validates_reason` | `parse_close`:544 | Every close payload of up to 6 bytes. Empty means no code, one byte is refused, and otherwise the code must be in range and the reason valid UTF-8, kept unchanged. |
| `websocket_fragments_follow_message_order` | `Messages::check_header`:960 | Every two-byte header, with and without a message in progress. A continuation is refused outside a message, a new text or binary frame is refused inside one, and control frames pass in both states. |
| `websocket_text_across_fragment_boundary` | `validate_text`:1050, called from `Messages::decode`:995 | Every four-byte message split at every point. Text is accepted exactly when the whole message is valid UTF-8, even when a character spans the split, and the checked prefix never passes the bytes held. |
| `websocket_message_limit_precedes_payload_copy` | `Messages::check_header`:960 | Bytes held and limit from 0 to 3, next frame length 0 to 125. `check_header` refuses, with `TooBig`, a frame whose length plus the bytes held passes the limit. The harness calls `check_header` alone: that `decode` calls it (line 1000) before `Frames::decode` copies the payload (1001, `Frame::from_header` at 877) is read from the code, not proved, and `check_header` takes `&self`, so the held bytes cannot change in it. |
| `websocket_writer_rules_{continuation,text,binary,ping,pong}`, `websocket_writer_rules_close_{zero..three}` | `write_frame`:749, `Header::parse_exact`:454, `Frame::from_header`:499 | Every opcode the writer takes (the `Opcode` type has no reserved values), with two arbitrary payload bytes; Close with 0 to 3; any FIN, any mask. The writer refuses exactly a non-final control frame (5.5) and a Close body of one byte, with a code that may not be sent, or with a reason that is not UTF-8 (5.5.1, 7.4), and leaves the output empty then. An accepted frame has its reserved bits clear (5.2), the FIN, opcode and mask bit asked for, and reads back as the same frame. |
| `websocket_writer_bounds_control_payload_{ping,pong,close_126}` | `write_frame`:749 | Ping and Pong of 125 and 126 bytes and Close of 126 bytes, any FIN. The writer accepts exactly a final control frame of at most 125 bytes (5.5). |
| `websocket_fragments_follow_rfc_*` (nine harnesses) | `Message::to_frames`:666 | Empty text and binary, three-byte Ping and Pong, and an empty Close, with any fragment size from 0 to 4; three arbitrary binary bytes with fragment sizes 1, 2 and 3; and "€" (three bytes) split one byte per frame, so text splits inside a character (5.6). A control message is one final frame (5.5). Otherwise the first frame carries the message's opcode, the rest are continuations, only the last is final, each holds at most the fragment size and is empty only when it is the only frame, the payloads joined are the message (5.4), and the writer accepts every frame. |

`write_header`, `write_frame`, `Header::parse_exact`, `Header::payload`,
`Messages::check_header` and `validate_text` are blocks moved out of
`Frame::write`, `Frame::parse` and `Messages::decode` unchanged, so the
harnesses can call them without building multi-megabyte payloads or whole
decoders. The callers run the same checks in the same order as before.

The new writer and fragment harnesses fix the opcode or message kind per
harness, and the payload length per harness where frames split. With the
opcode left symbolic, CBMC ran out of memory under the 8 GiB cap even on
an empty payload.

Results (Kani 0.68 with CBMC 6.11, one harness at a time under an 8 GiB
cap, run on 2026-11-10): all 50 harnesses pass. CBMC times: the writer
rules up to 48 s each, `websocket_fragments_follow_rfc_text_split_character`
117 s, `websocket_fragments_follow_rfc_binary_three_by_one`
88 s, `websocket_text_across_fragment_boundary` 46 s,
`websocket_close_payload_validates_reason` 37 s,
`websocket_headers_follow_wire_grammar` 12 s, and under 5 s for the rest.
On main at this run, two other areas' Kani files do not compile
(`verification/tls/kani/LayerProof.rs` and `verification/layer/kani/mod.rs`),
so their `cfg(kani)` includes were turned off locally for this run and not
committed.

Each control is a harness named `websocket_control_without_*`. It stubs one
production function and runs the same property on a concrete input that
shows the fault. All 22 fail on the assertion listed.

| Control | Change | Failed assertion |
|---|---|---|
| `control_rules` | every opcode counts as data | a non-final Ping is not refused (`got.is_err()`) |
| `control_size` | the same, with a final Ping of 126 bytes | an oversized Ping is not refused (`got.is_err()`) |
| `mask_direction` | `Frames::header` skips the mask check | a frame from the wrong side is accepted |
| `masking` | masking leaves bytes unchanged | a byte differs from the RFC XOR |
| `mask_involution` | XOR replaced by addition | masking twice does not restore the input |
| `mask_offset` | the key restarts at each piece | split masking differs from whole masking |
| `exact_end` | exact parsing accepts trailing bytes | `exact == Err(Error::Trailing)` |
| `payload_start` | the payload includes the header | `payload.len() == header.len` |
| `unmasking` | `Frame::from_header` copies without unmasking | decoded payload differs |
| `frame_masking` | the writer does not mask | written frame differs from the expected bytes |
| `minimal_length` | the writer always uses the 64-bit form | the parser refuses the written header |
| `extended_length` | the writer cuts lengths to 7 bits | `header.len == len` |
| `close_utf8` | close reasons decoded lossily | an invalid reason is accepted |
| `close_ranges` | every close code is allowed | code 1005 is accepted |
| `fragment_order` | `check_header` without the order check | a final continuation with no message is accepted |
| `held_charge` | held bytes counted as zero | an over-limit frame is not refused |
| `utf8_carry` | each fragment validated alone | `€a` split after the first byte of `€` is refused |
| `writer_control_rules` | every opcode counts as data | the writer accepts a non-final Ping (`result.is_ok() == ...`) |
| `writer_reserved_bits` | the writer sets RSV2 | `out[0] & 0x70 == 0` |
| `writer_control_size` | every opcode counts as data | the writer accepts a 126-byte Ping |
| `fragment_fin` | `to_frames` marks every fragment final | `f.fin == (i + 1 == frames.len())` |
| `control_unsplit` | `to_frames` splits control messages too | `frames.len() == 1` for a two-byte Ping |

Run one harness or control:

```sh
systemd-run --user --scope -q --slice=fictionet-work.slice -p MemoryMax=10G -p MemorySwapMax=0 \
  env CARGO_BUILD_JOBS=4 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  cargo kani -p fictionet --lib -Z stubbing --output-format terse \
  --harness websocket_headers_follow_wire_grammar
```

`--harness websocket_` runs all of them; add `-j 1` to keep one at a time.
The controls fail by design, so that command exits non-zero.

The line numbers in both tables were checked on 2026-11-10 and hold.

## The decoder against the RFC, exhaustively

`decoder_follows_rfc_on_every_short_stream`, a unit test in
`websocket.rs`, runs the whole decoder (`Messages` through
`codec::Stream`) on every stream of up to three unmasked frames. It covers
all 16 opcodes, both FIN values, and payloads that are empty, ASCII, either
half of "é" (so text splits inside a character) and a byte that is never
UTF-8. Streams of up to two frames also take three Close bodies: a
sendable code, a code that may not be sent, and a sendable code with a
reason that is not UTF-8. That is about 4.1 million streams.

The test compares the messages and how the stream ends (Close, failure,
EOF inside a message, EOF between messages) with `rfc_receive`, a receiver
written in the test from RFC 6455: 5.2 (reserved opcodes), 5.4 (fragment
order, control frames between fragments, the message is its fragments
joined), 5.5 (control frames are final), 5.5.1 and 7.4 (Close bodies), and
5.6 and 8.1 (text is UTF-8, and a prefix no later bytes can make valid
fails at once). This covers what the Kani harnesses leave out: the parts
of `Messages::decode` composed, on every short input. A Kani version of
the same check ran out of memory: three symbolic opcodes are far past the
one that already did.

Each control changes one rule in `websocket.rs`, runs the test, and puts
the file back. All 8 make the test fail; the first stream it names is
listed.

| Control | Change | First failing stream |
|---|---|---|
| `order_continuation` | a continuation with no message is accepted (line 966) | a lone non-final continuation |
| `order_new_message` | a new data frame inside a message is accepted (968) | two non-final text frames |
| `control_final` | non-final control frames are accepted (396) | non-final text, then a non-final Close |
| `reserved_opcode` | opcode 3 is read as binary (179) | final text, then a frame with opcode 3 |
| `ping_drops_message` | a Ping ends the message in progress (1011) | non-final text, then a Ping |
| `close_body` | Close bodies are not checked (881, 1014) | non-final text, then a 1-byte Close |
| `utf8_fail_fast` | invalid text fails only at the last fragment (1054) | non-final text, then a continuation holding `0xa9` |
| `stop_after_close` | decoding goes on after a Close (871, 997) | a Close, then a continuation |

## TLA+: the receive state

`tla/Messages.tla` follows `Messages::check_header` and `Messages::decode`
(lines 960–1047). The model header maps each step to its source lines. It
takes four complete frames, each data, continuation, Ping, Pong or Close,
final or not, with length 0, 1, 2, 125 or 126, against a message limit of 2.
Text and binary are one kind here; UTF-8 and wire bytes are left to Kani. A
failed decode ends the stream. EOF and input chunking are outside the model.

`charged` is the sum `check_header` compares with `limit` (lines 972–976),
the decoder's own arithmetic: `layer::Budget` does not appear in
`websocket.rs`, and nothing under `src/` drives `Messages` (its users are
the tests and the doc examples). The check runs before the copy, but the
copy allocates the frame's payload (`Frame::from_header`, line 877) and
then appends it to the partial message (line 1027), so a message briefly
costs its held bytes plus twice the frame.

The model refuses a Close with a 1-byte body, as `Frames::decode` does
through `parse_close` (line 881). Before 2026-11-10 the model accepted it,
a gap the RFC refinement below found; codes and reasons stay with Kani.
`ChargeControl` is a control flag only: the code never charges control
frames against the limit (lines 854 and 972), and every config here sets
it to `FALSE` except the refinement control that sets it to `TRUE`.

`Messages_base.cfg`: no error, 7,101 states generated, 801 distinct, depth 5.
Counterexample lengths below are TLC's trace lengths, the initial state
included, from the run of 2026-11-10. With two workers TLC does not always
report the shortest trace.

| Invariant | Meaning | Control | Counterexample |
|---|---|---|---|
| `ContinuationOrder` | continuation only inside a message, data only outside | `without_order` | a new data frame inside a message, 3 states |
| `ControlAtomic` | accepted control frames are final, at most 125 bytes | `without_control` | a non-final Ping, 2 states |
| `ChargedBeforeGrowth` | the message size is checked against the limit before the copy | `without_charge` | data over the limit, 2 states |
| `ControlPreservesPartial` | Ping and Pong between fragments keep the message in progress | `without_preserve` | a Ping drops the message, 3 states |
| `ReceiveEndsAtClose` | nothing is accepted after a Close | `without_stop` | data after Close, 4 states |
| `OneReceivedClose` | at most one Close is delivered | `without_close_once` | a second Close, 3 states |

## TLA+: the close handshake through the HTTP switch

The HTTP server does not own a WebSocket session. `Http1::hand_on`
(`web/httpd/native.rs`:793) passes unread bytes and EOF to the upgrade
handler, which runs on the raw connection. `Messages` only receives, and
`Message::to_frame` and `Frame::write` keep no state, so each handler sends
its own Close and stops writing after it.

`tla/Echo.tla` follows the two echo handlers the tests install:
`EchoSocket` in `tests/support/response.rs` (used by
`websockets_work_through_sites` in `tests/it/web/http_serving.rs`) and
`echo` in `tests/it/features.rs` (used by
`websocket_continuation_exchanges_messages_through_server`). Both answer
Ping with Pong, ignore Pong, echo a Close and return. Text messages are one
event. Four incoming messages cover a repeated Close, Close after text and
text after Close. Writes are assumed to succeed and to be weakly fair.
Returning is a step of its own after the Close write: when the handler
returns, the server drops the connection, which closes TCP from the
server's side. Until 2026-11-10 the model wrote the Close and returned in
one step, which the RFC refinement cannot map, since sending a Close and
closing TCP are two events there. `read` and `echoed` are history
variables for that mapping and never constrain a step.

`Echo_base.cfg`: no error, 21 states, depth 10.

| Property | Meaning | Control | Counterexample |
|---|---|---|---|
| `CloseIsAnswered` | a received Close is answered | `without_reply` | the handler returns without replying, 7 states then stuttering |
| `OneCloseEachWay` | at most one Close is sent | `without_close_once` | two Close replies, 5 states |
| `NoDataAfterClose` | no text follows the Close reply | `without_stop` | text after the Close reply, 7 states |

The last two controls turn off both the decoder's stop after Close and the
handler's return after replying; either one alone keeps these handlers
correct.

Run a configuration from the repository root:

```sh
systemd-run --user --scope -q --slice=fictionet-work.slice -p MemoryMax=10G -p MemorySwapMax=0 \
  ~/.cache/adorably-fv/jdk/bin/java -Xmx2g \
  -cp ~/.cache/adorably-fv/tla2tools.jar tlc2.TLC -workers 2 \
  -metadir /home/souvik/Projects/amlalabs/.fictionet-comp-work/tlc-vws-messages \
  -config verification/websocket/tla/Messages_base.cfg \
  verification/websocket/tla/Messages.tla
```

## TLA+: refinement of RFC 6455

`tla/Rfc6455.tla` is one endpoint after the opening handshake, written
from the RFC text and not from the code. Its header quotes the sentence
behind each rule. Frames are abstract: data (text and binary as one
class), continuation, Ping, Pong or Close, with FIN and a payload length.
The endpoint receives frames and sends data and Close frames. Its state
(`State`) is OPEN, then CLOSING once a Close is sent or received (7.1.3),
then CLOSED once TCP is closed (7.1.4).

| Rule | RFC | What it says |
|---|---|---|
| `FragmentOrder` | 5.4 | a delivered continuation is inside a message; a delivered new data frame is outside one |
| `ControlFrames` | 5.5 | a delivered control frame is final and carries at most 125 bytes |
| `CloseBody` | 5.5.1 | a delivered Close has no body or at least the 2-byte code |
| `ControlInsideMessage` | 5.4 | a Ping or Pong between fragments leaves the message in progress |
| `ValidControlAccepted` | 5.4, 5.5 | a valid control frame is never the reason to fail; only data may be refused for size (10.4) |
| `DiscardAfterClose` | 1.4 | after a Close is received, later frames are discarded |
| `NoDataAfterClose` | 5.5.1 | no data frame after sending a Close |
| `OneClose` | 5.5.1, 7.1.5 | at most one Close is sent |
| `TcpClosedAfterHandshake` | 5.5.1, 7.1.7 | the endpoint closes TCP only after both Closes, or when it fails the connection |
| `CloseAnswered` | 5.5.1 | a received Close is eventually answered with a Close, unless the peer drops the connection |
| `ServerClosesTcp` | 5.5.1, 7.1.1 | once both Closes are exchanged, the server eventually closes TCP itself |

Two readings of the RFC are choices made here. 7.3 says an endpoint
starts a closure with the closing handshake; the spec reads that as "the
endpoint closes TCP only after the handshake or when it fails the
connection". 1.4 is non-normative; the spec takes its "discards any
further data" as the rule for frames after a received Close, which is what
the decoder does. The TCP close duty of 5.5.1 is the server's, so the spec
is an endpoint in the server role.

`Rfc6455Check.cfg` checks that every rule, `FailCloses` (7.1.7) and
`StateOrder` (OPEN, CLOSING, CLOSED in that order) follow from the spec
itself, so no rule can fail under a mapping for a reason the spec allows.
Payload lengths 0, 1, 125 and 126, at most 3 frames received and 1 data
frame sent: no error, 32,693 states generated, 3,348 distinct, depth 7.

`tla/MessagesRfc.tla` and `tla/EchoRfc.tla` instance the spec with a
refinement mapping and check `R!Safety` (`Init /\ [][Next]_vars` of the
spec) and the rules. Lengths map to `Nat`, so the spec does not limit
them.

- `Messages` maps each receive step to one spec receive step. An accepted
  frame is delivered. A frame refused only because a Close came first is
  discarded (the decoder returns End at line 998). Any other refused frame
  fails the connection. The decoder never sends and owns no TCP
  connection, so the send rules are not checked here.
- `Echo` maps a text read to a delivered final data frame, a Close read to
  a delivered Close, a text write to a data frame sent, the Close write to
  the Close sent and the return to the server closing TCP. The handlers
  never fail the connection, and the peer never drops it.

The bounds are those of `Messages_base.cfg` and `Echo_base.cfg`: four
frames for `Messages`, four messages for `Echo`.

| Config | Properties | Result |
|---|---|---|
| `MessagesRfc_base` | `R!Safety` and the six receive rules | no error, 7,101 states generated, 801 distinct, depth 5 |
| `EchoRfc_base` | `R!Safety`, `DiscardAfterClose`, `NoDataAfterClose`, `OneClose`, `TcpClosedAfterHandshake`, `CloseAnswered`, `ServerClosesTcp` | no error, 21 states, depth 10 |

Each control names one rule. A matrix run checked every control against
every property of its base, one property at a time. The last column lists
what else each control breaks.

| Control | Change | Fails | Counterexample | Also fails |
|---|---|---|---|---|
| `MessagesRfc_without_order` | no order check | `FragmentOrder` | a continuation with no message, 2 states | `R!Safety` only |
| `MessagesRfc_without_control` | no control frame check | `ControlFrames` | a non-final Ping delivered, 3 states | `R!Safety` only |
| `MessagesRfc_without_close_body` | 1-byte Close body accepted | `CloseBody` | a 1-byte Close delivered, 2 states | `R!Safety` only |
| `MessagesRfc_without_preserve` | Ping and Pong drop the message | `ControlInsideMessage` | a Ping drops the message, 3 states | `R!Safety` only |
| `MessagesRfc_with_control_charge` | control frames charged against the limit | `ValidControlAccepted` | a 125-byte Ping refused, 3 states | `R!Safety` only |
| `MessagesRfc_without_stop` | frames accepted after a Close | `DiscardAfterClose` | a frame delivered after a Close, 3 states | `R!Safety` only |
| `EchoRfc_without_stop` | neither the decoder nor the handler stops after a Close | `NoDataAfterClose` | text echoed after the Close reply, 5 states | `R!Safety`, `DiscardAfterClose`, `OneClose`, `ServerClosesTcp` |
| `EchoRfc_without_close_once` | the same | `OneClose` | a second Close reply, 5 states | `R!Safety`, `DiscardAfterClose`, `NoDataAfterClose`, `ServerClosesTcp` |
| `EchoRfc_without_reply` | the handler returns on a Close without replying | `TcpClosedAfterHandshake` | TCP closed with no Close sent, 5 states | `R!Safety`, `CloseAnswered` |
| `EchoRfc_lazy_reply` | no fairness on the Close write | `CloseAnswered` | the reply never comes, 2 states then stuttering | nothing else |
| `EchoRfc_lazy_return` | no fairness on the return: the server waits for the client to close TCP | `ServerClosesTcp` | the server never closes TCP, 3 states then stuttering | nothing else |

The overlaps in the Echo rows are not separable in this model. An echo
handler sends data only in answer to data, so data after its Close needs a
frame read after the Close, which already breaks `DiscardAfterClose`; the
same holds for a second Close. A handler that keeps reading after its
reply also never returns, which breaks `ServerClosesTcp`. Returning
without a reply closes TCP early and leaves the Close unanswered: two
rules of 5.5.1 at once.

Both models refine the spec with no change to the code. The two model
changes above (the 1-byte Close body in `Messages`, the separate return
step in `Echo`) were gaps in the models, not departures in the code.

## Bugs found

Both were in the test echo servers, not in the codec.

- `EchoSocket` returned on any message other than text. A Ping or Pong
  between fragments ended the session in the middle of a message, and a
  Close got no reply. It now answers Ping with Pong, ignores Pong, and
  echoes Close before returning. `websockets_work_through_sites` sends
  non-final text, Ping, an unsolicited Pong and the final continuation
  together, and requires the Pong and the whole echoed text. It then sends
  Close, a second Close and text in one write, and requires exactly one
  unmasked Close with code 1000 and then EOF. Before the fix the reply was
  empty.
- The `echo` handler in `features.rs` sent Ping and Pong back unchanged and
  kept reading after echoing Close. It now handles them the same way.
  `websocket_continuation_exchanges_messages_through_server` sends text,
  Ping and an unsolicited Pong with the upgrade request, so they cross the
  switch as unread bytes, and requires the echo and the Pong. After a
  Close it requires one unmasked Close with code 1000 and then EOF.

## Departures from RFC 6455

None of these checks found a bug in the codec. These departures are
deliberate and left as they are:

- A receiver refuses a length in a longer form than it needs. Section 5.2
  puts the shortest form on the sender ("the minimal number of bytes MUST
  be used"); it does not tell a receiver to refuse. Refusing is stricter.
- A frame or message over 16 MiB is refused with 1009. Section 10.4 lets
  an endpoint set such limits.
- Codes 1016 to 2999 are refused in a Close. Section 7.4.2 reserves them
  for the protocol and its extensions; none is defined.
- The codec has no session. Answering Ping with Pong (5.5.2), replying to
  a Close and closing TCP (5.5.1) belong to the code that runs it; the
  module docs say so. The TLA+ refinement checks them for the two test
  echo handlers only.
- Both test echo handlers return without a Close frame when decoding
  fails, and `EchoSocket` also returns on a binary message. Section 7.1.7
  says an endpoint SHOULD send a Close with a status code before it drops
  the connection, and `Error::close_code` gives that code. Both are test
  handlers, not the codec, and `Echo.tla` has no binary or error event.

## Limits

These checks cover inputs up to the sizes in the tables, streams of up to
three frames in the decoder test, and four-frame histories in the models,
not every possible session. The UTF-8 checks use Rust's own validator as
the definition of valid text. Allocation failure, allocator spare capacity
and total process memory are outside them; the message limit bounds
payload bytes before each copy.

Not covered:

- A 125-byte Close in the writer: its 123-byte reason runs CBMC out of
  memory. Ping and Pong at 125 bytes and Close at 126 are covered.
- Symbolic text in the fragment harnesses, and "€" at fragment sizes other
  than 1: both run CBMC out of memory. Text is split as bytes, like
  binary, which is covered with arbitrary bytes.
- Masked frames in the decoder test and the fragment harnesses. Masking is
  proved on its own by the mask and small-frame harnesses.
- Pong payloads matching their Ping (5.5.3), and the client side of the
  close handshake (a client waits for the server to close TCP, 7.1.1).
  `Rfc6455.tla` is a server endpoint.
- The opening handshake (section 4) is not part of these checks.
