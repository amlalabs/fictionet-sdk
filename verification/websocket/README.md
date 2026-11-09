# WebSocket verification

Two kinds of checks cover the WebSocket codec in
`src/stdlib/protocols/websocket.rs`. Kani harnesses in `kani/frames.rs` run
the production parser and writer on every input up to a fixed size. TLA+
models in `tla/` follow the receive state over time and the echo servers that
run the codec after the HTTP/1 switch. The codec buffer proofs and the HTTP
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

`write_header`, `write_frame`, `Header::parse_exact`, `Header::payload`,
`Messages::check_header` and `validate_text` are blocks moved out of
`Frame::write`, `Frame::parse` and `Messages::decode` unchanged, so the
harnesses can call them without building multi-megabyte payloads or whole
decoders. The callers run the same checks in the same order as before.

Results (Kani with CBMC 6.11, one harness at a time under a 10 GiB cap): all
29 harnesses pass. The slowest are `websocket_text_across_fragment_boundary`
(47 s) and `websocket_close_payload_validates_reason` (30 s); the rest take
under 5 s each.

Each control is a harness named `websocket_control_without_*`. It stubs one
production function and runs the same property on a concrete input that
shows the fault. All 17 fail on the assertion listed.

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

Run one harness or control:

```sh
systemd-run --user --scope -q --slice=fictionet-work.slice -p MemoryMax=10G -p MemorySwapMax=0 \
  env CARGO_BUILD_JOBS=4 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  cargo kani -p fictionet --lib -Z stubbing --output-format terse \
  --harness websocket_headers_follow_wire_grammar
```

`--harness websocket_` runs all of them; add `-j 1` to keep one at a time.
The controls fail by design, so that command exits non-zero.

The line numbers in both tables were checked against e2858ccc4 on
2026-11-09 and hold. The Kani results were not rerun then.

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

`Messages_base.cfg`: no error, 7,551 states generated, 801 distinct, depth 5.
Counterexample lengths below are TLC's trace lengths, the initial state
included, from the run of 2026-11-09 at e2858ccc4.

| Invariant | Meaning | Control | Counterexample |
|---|---|---|---|
| `ContinuationOrder` | continuation only inside a message, data only outside | `without_order` | a continuation with no message, 2 states |
| `ControlAtomic` | accepted control frames are final, at most 125 bytes | `without_control` | a non-final Ping, 2 states |
| `ChargedBeforeGrowth` | the message size is checked against the limit before the copy | `without_charge` | data over the limit, 2 states |
| `ControlPreservesPartial` | Ping and Pong between fragments keep the message in progress | `without_preserve` | a Ping drops the message, 3 states |
| `ReceiveEndsAtClose` | nothing is accepted after a Close | `without_stop` | data after Close, 4 states |
| `OneReceivedClose` | at most one Close is delivered | `without_close_once` | a second Close, 4 states |

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

`Echo_base.cfg`: no error, 17 states, depth 9.

| Property | Meaning | Control | Counterexample |
|---|---|---|---|
| `CloseIsAnswered` | a received Close is answered | `without_reply` | the handler returns without replying, 3 states then stuttering |
| `OneCloseEachWay` | at most one Close is sent | `without_close_once` | two Close replies, 5 states |
| `NoDataAfterClose` | no text follows the Close reply | `without_stop` | text after the Close reply, 5 states |

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

## Limits

These checks cover inputs up to the sizes in the tables and four-frame
histories in the models, not every possible session. The UTF-8 checks use
Rust's own validator as the definition of valid text. Allocation failure,
allocator spare capacity and total process memory are outside them; the
message limit bounds payload bytes before each copy.
