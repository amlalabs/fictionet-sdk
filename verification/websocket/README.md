# WebSocket verification

The Kani harnesses call the production codec. The TLA+ models cover the
receive state over time and the test server that uses the codec after the
HTTP/1 switch. They complement the codec buffer proofs and HTTP pipeline
handoff proofs described in `../codec/README.md` and `../http/README.md`.
The wire rules follow [RFC 6455 sections 5–8](https://www.rfc-editor.org/rfc/rfc6455.html#section-5).

## Receive state

`tla/Messages.tla` follows `Messages::decode`, `Frames::decode` and
`Header::parse` in `src/stdlib/protocols/websocket.rs`; its header maps the
checks to source lines. It checks four complete-frame steps, a two-byte
message limit, all FIN values, data/continuation/ping/pong/close, and lengths
0, 1, 2, 125 and 126. Data represents both text and binary; UTF-8 and wire
bytes belong to the Kani harnesses, not this abstraction. `charged` records
the aggregate before the payload copy, including final frames that release
the message in the same call. The independently configurable frame limit
is assumed large enough to admit these lengths (`Messages::from_frames`).
Errors terminate the stream. EOF, allocation failure, input chunking and
the allocator's spare capacity are outside this model.

TLC 2.19 on the cached JDK 21 checked `Messages_base.cfg`: 7,551 states
generated, 801 distinct, depth 5, all six invariants passed. Every property
has a checked negative configuration:

| Configuration suffix | Property | Counterexample |
|---|---|---|
| `without_order` | `ContinuationOrder` | continuation without a partial, depth 2 |
| `without_control` | `ControlAtomic` | non-final ping, depth 2 |
| `without_charge` | `ChargedBeforeGrowth` | data exceeds the message limit before copying, depth 2 |
| `without_preserve` | `ControlPreservesPartial` | ping discards an unfinished empty message, depth 3 |
| `without_stop` | `ReceiveEndsAtClose` | data accepted after close, depth 3 |
| `without_close_once` | `OneReceivedClose` | second close delivered, depth 3 |

The state-space bounds are not an unbounded proof. In particular, the
presence of an empty partial matters independently of its byte count.

## Close handshake through the HTTP switch

The HTTP server does not own a WebSocket session: `Http1::hand_on`
(`src/stdlib/web/httpd/native.rs:793`) passes unread bytes and EOF to the
successor; the tunnel runs the caller's `UpgradeHandler` on a raw
connection. `Messages` only receives, and `Message::to_frame` and
`Frame::write` are stateless writers. Applications must remember their own
outgoing close and stop writing data. These APIs alone cannot guarantee
one close in each direction or prevent application writes after close.

`tla/Echo.tla` follows the concrete `EchoSocket` handler in
`tests/support/response.rs`, used by `websockets_work_through_sites` in
`tests/it/web/http_serving.rs`, and the local `echo` handler in
`tests/it/features.rs:249`, exercised by
`websocket_continuation_exchanges_messages_through_server` at line 243.
Both handlers write a close reply before returning, answer Ping with Pong,
and ignore unsolicited Pong. Text requests and replies are abstracted to
one event; payload differences between the two echoes are outside the model.
A close is echoed once and the handler returns. Four incoming
messages are enough to explore repeated close, close after text, and text
after close. All payload validation belongs to `Messages`. Successful
writes are weakly fair: a broken connection cannot promise a close reply.

`Echo_base.cfg` passed: 17 generated and distinct states, depth 9.
`OneCloseEachWay` checks at most one sent reply; the receive model separately
checks at most one delivered close. `NoDataAfterClose` checks that no text
reply follows the close reply, and `CloseIsAnswered` checks eventual reply
under the stated write assumption.

| Configuration suffix | Property | Counterexample |
|---|---|---|
| `without_reply` | `CloseIsAnswered` | receives close and ends without replying; terminal stuttering |
| `without_close_once` | `OneCloseEachWay` | two close replies, depth 5 |
| `without_stop` | `NoDataAfterClose` | text reply after close reply, depth 5 |

The latter two controls disable both the decoder's terminal-close check
and the handler's return after sending close; either stop suffices for
this handler. This is a paired ablation, not evidence that removing only
one of those checks breaks the current handler.

The old test server also returned on Ping and Pong, ending a fragmented
text message prematurely. The integration regression now sends non-final
text, Ping, unsolicited Pong, and final continuation together. It requires
a Pong with the ping payload and the completed text echo before testing
close. The handler replies to Ping and ignores Pong; these operations
preserve the close state and are abstracted as stuttering in `Echo.tla`.

The old test server returned on every non-text message, including Close.
The missing-reply configuration models that path. The regression sends a
masked close, a second close and text together after a successful text
echo, then requires exactly one unmasked close and EOF from the real
server. This is a correction to a test service, not a new production
WebSocket session API. Production callers remain responsible for their
own close handshake.

The feature-test echo also needed its control-message and termination
handling corrected. Its regression sends a text frame, Ping, and unsolicited
Pong together with the HTTP upgrade request, exercising preservation of
unread bytes at the switch. It requires the text echo and a Pong carrying
the Ping payload. After sending a masked close with code 1000, it reads to
EOF and requires exactly `[0x88, 0x02, 0x03, 0xe8]` on the wire. This detects
an unsolicited Pong reply, a missing or repeated close reply, or a handler
that keeps the connection open after replying. The close projection in
`Echo.tla` covers this handler too; the wire-level response checks belong
to the Rust regression. The model's missing-reply control specifically
represents the old support handler's early return, rather than claiming
that both handlers had the same previous implementation.

Run the models from the repository root, choosing another configuration
from the same directory for each control (controls must fail the named
property, not parsing or state-space construction):

```sh
systemd-run --user --scope -q --slice=fictionet-work.slice -p MemoryMax=10G -p MemorySwapMax=0 \
  ~/.cache/adorably-fv/jdk/bin/java -Xmx2g \
  -cp ~/.cache/adorably-fv/tla2tools.jar tlc2.TLC -workers 2 \
  -metadir /home/souvik/Projects/amlalabs/.fictionet-comp-work/tlc-vws-messages \
  -config verification/websocket/tla/Messages_base.cfg \
  verification/websocket/tla/Messages.tla
systemd-run --user --scope -q --slice=fictionet-work.slice -p MemoryMax=10G -p MemorySwapMax=0 \
  ~/.cache/adorably-fv/jdk/bin/java -Xmx2g \
  -cp ~/.cache/adorably-fv/tla2tools.jar tlc2.TLC -workers 2 \
  -metadir /home/souvik/Projects/amlalabs/.fictionet-comp-work/tlc-vws-echo \
  -config verification/websocket/tla/Echo_base.cfg \
  verification/websocket/tla/Echo.tla
```

## Production Rust bounds

`kani/frames.rs` is included by `protocols/websocket.rs` only under
`cfg(kani)`. The production source mapping (after extracting the unchanged
header-writing block) is:

| Harness | Production source | Domain and assertion |
|---|---|---|
| `websocket_headers_follow_wire_grammar` | `Header::parse`:386 and `Frames::header`:845 | every byte string of length 0 through 14; reserved bits/opcodes, control FIN/125-byte bound, 7/16/64-bit lengths, minimal form, high bit, payload cap, incomplete headers, both mask directions |
| `websocket_writer_uses_minimal_length` | `Frame::write`:744, `write_header`:777 | every length 0 through 16 MiB, both FIN values, arbitrary optional mask; shortest header round-trips with exact length and key |
| `websocket_mask_is_involution_and_composes` | `apply_mask`:517 | eight arbitrary bytes, arbitrary key and machine-width offset, every split; RFC XOR value, involution and split composition, including wrapping offsets |
| `websocket_small_frames_{read,write}_*` | `write_frame`:749, `Header::parse_exact`:454, `Frame::from_header`:499 | binary payloads 0 through 4 bytes, arbitrary FIN and optional key; twenty read/write length/mask partitions cover the same domain. The writer must match an independent stack wire image and parsing that image through `Header::parse_exact` and `Frame::from_header` must reconstruct the frame |
| `websocket_exact_frame_boundaries` | `Header::parse_exact`:454 and `Header::payload`:469 | arbitrary inputs through eighteen bytes; the separately verified header parser determines the declared end, exact parsing rejects truncation and trailing bytes, and the borrowed payload excludes the header |
| `websocket_close_codes_follow_wire_ranges` | `Close::parse`:559, `Close::write`:579 | all 65,536 codes; acceptance and writing agree with permitted ranges |
| `websocket_close_payload_validates_reason` | `parse_close`:544 and `Close::parse`:559 | every payload through six bytes; empty/one-byte handling, code ranges, UTF-8 reason validity and preservation |
| `websocket_text_across_fragment_boundary` | `validate_text`:1050, called by `Messages::decode`:1033 | all four-byte messages, every initial/final fragment boundary; the production incremental validator accepts exactly whole-message UTF-8 and never advances its checked prefix beyond retained bytes |
| `websocket_message_limit_precedes_payload_copy` | `Messages::check_header`:960, called before copying at `Messages::decode`:1000 | every held/limit pair 0 through 3 and next length 0 through 125; an excessive aggregate fails from the header alone and leaves retained bytes unchanged |

All 28 positive Kani harnesses passed. All 16 mutation controls failed their
stated semantic assertions; resource failures are excluded from these
counts. The twenty small-frame partitions ran serially with `-j 1`.

The writer's header extraction contains the same instructions previously
in `Frame::write`; it permits checking the full length domain without
allocating a symbolic multi-megabyte payload. Payload copying and
unmasking are bounded separately through `Frame::from_header`. The read
proof composes the production header parser and payload constructor; it
does not call the `Frame::parse` wrapper, whose additional close-payload
validation is outside this binary-frame domain. The wrapper harness and
its fixed unmasking control exhausted 10 GiB even in isolation. Existing
Rust `length_forms_are_minimal`
tests also exercise real payloads across 125/126 and 65535/65536.

Controls are persistent Kani harnesses named `websocket_control_without_*`.
Each calls the same property with one stubbed implementation. The UTF-8,
involution and offset controls use concrete counterexample inputs; positive
proof domains stay symbolic. Held-charge, close-range and unmasking controls
also use concrete witnesses through the same property helpers, as does the
full-frame masking control. They are expected failures, so do not interpret an unfiltered `cargo kani` exit
status as the baseline result.

| Control suffix | Mutation | Expected failed assertion |
|---|---|---|
| `control_rules` | every opcode is treated as non-control | a non-final Ping is accepted |
| `control_size` | the same mutation with a final Ping declaring 126 bytes | an oversized control is accepted |
| `mask_direction` | `Frames::header` delegates directly to `Header::parse` | a frame is accepted from the wrong side |
| `masking` | masking leaves bytes unchanged | wire bytes differ from the RFC XOR rule |
| `mask_involution` | replace XOR with byte addition | a second mask does not restore the original bytes |
| `mask_offset` | restart the key at each split | split masking differs from masking the whole payload |
| `exact_end` | exact parsing accepts trailing bytes | trailing input is accepted |
| `payload_start` | the payload includes the header | payload length differs from the declared length |
| `unmasking` | `Frame::from_header` copies without unmasking | decoded payload differs from the frame |
| `frame_masking` | writer masking leaves bytes unchanged | written frame differs from the independent wire image |
| `minimal_length` | writer always emits the eight-byte length form | parser rejects the nonminimal header even though the numeric length is preserved |
| `close_utf8` | close reasons use lossy UTF-8 conversion | invalid reason bytes are accepted |
| `close_ranges` | every close code is sendable | reserved close accepted |
| `held_charge` | retained message length is omitted | excessive aggregate is not refused from its header |
| `utf8_carry` | each fragment is validated independently | the same property rejects `€a` split after the first byte of `€` |
| `extended_length` | writer truncates every length to seven bits | encoded header loses the declared length |

The pre-copy header guards were also extracted unchanged into
`Messages::check_header`, which takes `&self` and cannot grow its retained
payload. Production `decode` calls it with `?` before `Frames::decode`
copies a payload. The limit proof checks this guard component directly;
the original whole-decoder harness reached the 12 GiB cap.

The incremental UTF-8 block was extracted unchanged from `Messages::decode`
so the proof exercises that state update without duplicating frame parsing
or allocating temporary wire buffers. The UTF-8 harness is a component
proof, not an end-to-end proof of two complete frame decode calls.

UTF-8 validity uses Rust's standard validator as its specification; this
checks its incremental use, not the standard library's UTF-8 algorithm.
The close-reason proof checks the production close parser against that
validator for reasons up to four bytes; the separate code-range harness
has empty reasons. Allocation failure and allocator spare capacity
are not proved. The aggregate bound concerns payload lengths before copies,
not accounting for vector capacity or total process memory. These finite
harnesses and models do not prove all possible session histories.

Run an individual property or control with the same memory cap as the
other verification work:

```sh
systemd-run --user --scope -q --slice=fictionet-work.slice -p MemoryMax=10G -p MemorySwapMax=0 \
  env CARGO_TARGET_DIR=/home/souvik/Projects/amlalabs/.fictionet-comp-work/target-vws \
  CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_BUILD_JOBS=4 \
  cargo kani -p fictionet -Z stubbing --output-format terse \
  --harness websocket_headers_follow_wire_grammar
```

## Rust validation

The close-handshake regression failed before the fix with an empty reply
instead of `[136, 2, 3, 232]`, then passed after the fix. The protocol suite with `--features tokio` passed all 3,259 tests, including
HTTP/1 and WebSocket tests. All 14 matching `native` tests and the
`websockets_work_through_sites` integration test also passed. `cargo clippy -p fictionet --features tokio --lib --tests -- -D warnings`,
`cargo fmt --all -- --check`, and `cargo doc -p fictionet --features tokio
--no-deps` passed. `cargo bench -p fictionet --profile dev --bench decoders
-- 'http1_requests|websocket_frames' --sample-count 2 --sample-size 1` ran
both decoder benchmarks successfully; this is a smoke check, not a release
performance comparison.
