# HTTP message framing: verification notes

Area: `src/stdlib/web/httpd.rs` and `src/stdlib/web/httpd/` (HTTP/1 in
`native.rs`, HTTP/2 in `http2.rs`, the shared response policy in
`response.rs`), the HTTP/1 framing rules in `src/stdlib/protocols/http1.rs`,
HTTP/2 stream states and flow control, the HTTP/1 layer (`Http1`) with its
handoff through `Switch` to `stack::Tunnel`, and the HTTP/1 body framing
(`http1::BodyEvents`) shared by serving, capture and the WARC reader. The
models, how to run them and the full results are in
[verification/http/README.md](README.md).

## What was modeled and checked

| Model | Of | Checker | Result |
|---|---|---|---|
| `verification/http/lean/Http/Framing.lean` | `ResponsePolicy::new`, `native::encode` and `Http1::start`, `http1::response_framing`, `Sending::poll_next` | Lean 4 (`lake build`, axiom audit) | 20 theorems proved for every status class, method, body hint and supplied length: never both length fields, HTTP/1.0 never chunked and closes on an unknown length, no length on 1xx or 204, no framing on a 2xx to CONNECT, HEAD's length is GET's, the reader finds the body the server wrote, HTTP/2 END_STREAM and `content-length` agree with the DATA. Only `propext`, `Quot.sound` and `Classical.choice` appear. |
| `verification/http/lean/Http/Request.lean` | `http1::fields` and `request_framing` | Lean 4 | 12 theorems: RFC 9112 sections 6.1 and 6.3 for requests (both fields refused, HTTP/1.0 `Transfer-Encoding` refused, `chunked` not final refused, no `chunked` refused, unsupported coding is a 501, equal `Content-Length` values accepted, differing or invalid ones refused, no fields means no body). |
| `verification/http/tla/Streams.tla` | `Http2::headers`, `headers_on`, `data`, RST_STREAM handling, `cancel`, `write_reset`, `on_timer`, `on_done`, `Sending::poll_next` | TLC 2.19 | Base: 210,019 states generated, 13,277 distinct, depth 14; six invariants and six properties hold, including the liveness `ResponsesEnd`. Four ablations each violate the one property named for them. |
| `verification/http/tla/Flow.tla` | The receive side of `Http2::data`, `Accept` with `release_window`, the send side of `Sending::poll_next`, the WINDOW_UPDATE and SETTINGS_INITIAL_WINDOW_SIZE arms of `Http2::frame` | TLC 2.19 | Base: 4,581,219 states generated, 1,145,490 distinct, depth 22; four invariants and four properties hold, including the liveness `NoLostWake`, `ResponsesEnd` and `RequestsEnd`. Eight ablations each violate the one property named for them. |
| `tests/it/httpd.rs::http1_framing_follows_the_rfcs_for_every_case`, `tests/it/http2_server.rs::http2_framing_follows_the_rfcs_for_every_case` | The server itself, over the Lean domain | `cargo test` | Pass. Every method, status class, supplied length and body kind (and both HTTP/1 request versions) satisfies the rules the theorems state, on the bytes and frames the server writes. |
| `verification/http/tla/Pipeline.tla` | `Http1::on_event`, `advance`, `read`, `dispatch`, `fail`, `on_done`, `respond`, `start`, `piece`, `finish`, `hand_on`, `close`, `take_command`, `handover`; `Switch::on_event` and `advance`; `Tunnel::on_event` | TLC 2.19 | Base: 1,493,826 states generated, 660,798 distinct, depth 41; six invariants and the liveness `TunnelGetsAll` hold: one request in flight, the next read only after the last response is written, the handover only with nothing of HTTP left to write, the bytes after the request reach the tunnel first, in order, once and all, the end last, and no request after a 101. Nine ablations each violate the one property named for them; one of them is the code before the fix below. |
| `verification/http/kani/body.rs` | `BodyEvents::decode` (`Reader::body`, `chunk_step`, `chunk_framing`, `chunk_size`, `chunk_size_skipping_extensions`, `number`) | Kani 0.68.0 | 18 harnesses verified: one step from every state, in both chunk modes, does what an independent statement of the RFC 9112 grammar says, never waits while it holds its capacity, and (for every state but the lenient size and trailer lines) gives the same result at every split; chunk-size parsing gives the hex value exactly when it fits in a `u64`, without overflow. Five mutations of `http1.rs` each fail the harness run against them. |
| `verification/http/tla/Tunnel.tla` | `Tunnel::on_event`, `take_command`, `TunnelConn::poll_read` and `poll_write` with the budget's charges | TLC 2.19 | Base: 30,275 states generated, 5,644 distinct, depth 15: the code's writes stay within the room and are charged exactly, and input stays under the room plus one chunk. Three ablations each violate their property; two configs find the code does not keep its doc's 64 KiB inbound bound, and that an empty chunk from below reads as end of input. Kani could not run on this code (a compiler panic on `Region`, and 10 GiB). |
| `native.rs::tests::a_101_without_an_upgrade_handler_closes` | `Http1` over the layer harness | `cargo test` | Fails before the fix (a 101, then a second response), passes after. The `httpd`, `serve_limits` and `services` integration tests (119) and the `httpd::native` and `layer` library tests pass. |

The existing `httpd` library tests and the `httpd` and `http2_server`
integration test modules pass; `cargo fmt` and `cargo clippy -- -D warnings`
are clean on the library and the `it` tests.

## On the merged foundation

`comp/v-http1` was merged into `comp/foundation` (commit `61ef74c2f`) and
every TLA+ config and Kani harness here was rerun at code revision
`6aa68ae5f`. Since `Pipeline.tla` and `Tunnel.tla` were written,
`native.rs` changed only in its imports and in the bare-101 close below,
and the tunnel moved from `layer/tunnel.rs` to
`services/stack/tunnel.rs`, unchanged but for its imports; the line
numbers in the models and the README are the merged ones. The bare-101
test now runs its work with `Harness::with_worker(Polling::new())`, the
foundation's way, and passes.

| Config | Generated | Distinct | Result |
| --- | ---: | ---: | --- |
| `Streams_base.cfg` | 210,019 | 13,277 | every property holds |
| `Streams_without_checkbelowlast.cfg` | 436 | 117 | `ClosedHeadersEndConnection` violated |
| `Streams_without_halfclosedisstreamerror.cfg` | 148 | 50 | `NoBodyAfterEnd` violated |
| `Streams_without_ignoreafterreset.cfg` | 114 | 43 | `LateFramesIgnored` violated |
| `Streams_without_refuseoverlimit.cfg` | 312 | 87 | `Concurrency` violated |
| `Flow_base.cfg` | 4,581,219 | 1,145,490 | every property holds |
| `Flow_without_checkconnectionwindow.cfg` | 661 | 349 | `OverflowRejected` violated |
| `Flow_without_checkstreamwindow.cfg` | 39,116 | 13,799 | `OverflowRejected` violated |
| `Flow_without_countpadding.cfg` | 73 | 52 | `CreditMatchesWindow` violated |
| `Flow_without_releasecredit.cfg` | 558,533 | 169,566 | `RequestsEnd` violated |
| `Flow_without_spendwithinwindows.cfg` | 7,433 | 3,076 | `ServerSpendsWithinWindows` violated |
| `Flow_without_wakeonconnectionupdate.cfg` | 4,872,579 | 1,230,106 | `NoLostWake` violated |
| `Flow_without_wakeonsettings.cfg` | 276,877 | 87,180 | `NoLostWake` violated |
| `Flow_without_wakeonstreamupdate.cfg` | 264,463 | 81,949 | `NoLostWake` violated |
| `Pipeline_base.cfg` | 1,493,826 | 660,798 | every property holds |
| `Pipeline_without_waitwritten.cfg` | 255,903 | 107,199 | `ReadAfterWritten` violated |
| `Pipeline_without_readonlyinreading.cfg` | 23,315 | 17,661 | `OneInFlight` violated |
| `Pipeline_without_keepunread.cfg` | 578,355 | 258,971 | `TunnelGetsTheRest` violated |
| `Pipeline_without_leftoverinswitching.cfg` | 806,714 | 365,039 | `TunnelGetsTheRest` violated |
| `Pipeline_without_endlast.cfg` | 1,236,442 | 549,135 | `TunnelEndsLast` violated |
| `Pipeline_without_handoverafterwritten.cfg` | 106,739 | 51,707 | `HandoverAfterWritten` violated |
| `Pipeline_without_leftoverfirst.cfg` | 578,723 | 258,776 | `TunnelGetsTheRest` violated |
| `Pipeline_without_feedleftovers.cfg` | 1,471,808 | 648,360 | `TunnelGetsAll` violated |
| `Pipeline_without_closeafterbare101.cfg` | 391,817 | 172,027 | `NoHttpAfter101` violated |

| `Tunnel_base.cfg` | 30,275 | 5,644 | every invariant holds |
| `Tunnel_without_checkroom.cfg` | 26 | 23 | `OutboundWithinRoom` violated |
| `Tunnel_without_chargewrites.cfg` | 22 | 19 | `ChargesMatch` violated |
| `Tunnel_without_admitbelowroom.cfg` | 33 | 27 | `InboundBelowRoomAndAChunk` violated |
| `Tunnel_doc_room.cfg` | 70 | 46 | `InboundWithinRoom` violated: the finding below |
| `Tunnel_empty_chunks.cfg` | 59 | 52 | `NoEofWhileOpen` violated: the finding below |

The foundation readiness pass reran the base configuration and all nine
mutations after bounding post-framing input admission to the remaining
stream capacity. The base checked 1,493,826 generated and 660,798 distinct
states, including `AfterLen <= StreamCap`; all nine mutations violated
the same named properties listed above. These runs used the cached JDK,
`-Xmx6g`, a systemd 8 GiB memory limit, and state directories on the home
volume. The model abstracts allocation: production reserves decoded-head
storage and wire output before growth, and copied handover bytes carry a
separate reservation until the old input buffer is released. Allocation
refusal follows `Abort`; the state counts do not prove heap bounds.


Each was run with `-workers 4 -Xmx6g` under an 8 GB memory cap; where
several workers race to a violation the counts differ a little from the
branch's.

The 18 body-framing harnesses of `kani/body.rs` were rerun in one
`cargo kani -p fictionet -Z stubbing --harness stdlib::protocols::http1::proofs`
under a 12 GB memory cap and all verified, with 533 to 1,661 checks each,
in 0.7 s to 459 s (`chunk_size_is_the_hex_value_or_refused` the longest).
The Lean proofs (`lake build` in `verification/http/lean`) build: the
bare-101 close sets the request's close decision, which `Framing.lean`
already takes as any value, so its theorems cover it.

## Bugs

### A 101 without an UpgradeHandler kept the connection reading HTTP

A handler that answered an upgrade request with a 101 but no
`UpgradeHandler` left `Http1` with no successor, and a keep-alive request
sent `finish` back to `Reading`: the server wrote `101 Switching Protocols`
with `Connection: upgrade`, then read the client's next bytes as a new
request and answered it. RFC 9110 section 15.2.2 says the connection
switches right after the 101. `Pipeline_without_closeafterbare101.cfg`
violates `NoHttpAfter101` (client tokens `U, P, P, C`: the second request is
read after the 101, 391,698 states, depth 9).

Reproduction: `a_101_without_an_upgrade_handler_closes` in
`src/stdlib/web/httpd/native.rs` sends an upgrade request and a second
request to a handler that answers with a bare 101. Before the fix it failed
with the 101 followed by a second `HTTP/1.1` response on the same
connection.

Fix: `Http1::start` closes the connection after a 101 that carries no
`UpgradeHandler` (native.rs:577-581). After it the test passes and
`Pipeline_base.cfg`, which checks `NoHttpAfter101`, passes. The rule
predates B2: the server before the layer had the same one. Commit
b69a3806f: "Model the HTTP/1 pipeline and handoff; close after a bare 101".

### A 2xx to CONNECT over HTTP/2 carried a length and a body

`Sending` in `src/stdlib/web/httpd/http2.rs` carried `head_only: bool` and
rebuilt `Asked` from it as `Head` or `Body`. A CONNECT request therefore
took the `Body` path, and a 2xx answer carried `content-length` and the
handler's body as DATA frames. RFC 9110 section 9.3.6 forbids
`Content-Length` and `Transfer-Encoding` there, and the HTTP/1 backend
already answered with a bare head through the same policy (`Asked::Tunnel`).

Reproduction: `connect_success_has_no_length_and_ends_the_stream` in
`tests/it/http2_server.rs` sends `:method CONNECT`, `:authority a.test:443`
over the HTTP/2 harness to a handler that answers 200 with the body
`tunnel`. Before the fix it failed: the HEADERS block decoded to
`:status 200` and `content-length: 6`, without END_STREAM, followed by a
DATA frame with `tunnel` and an empty DATA frame with END_STREAM. The Lean
theorem `connect_leaked_length_before_fix` states the same behaviour of
the pre-fix mapping.

Fix: `Sending` carries `wants: Asked`, set in `Http2::dispatch` from
`Asked::of(request.method())`, and `Sending::poll_next` passes it to
`ResponsePolicy::new`; the `bool` and the rebuilt `Asked` are gone. After
the fix the test passes, the HTTP/2 table test passes for CONNECT, and the
Lean theorem `connect_success_has_no_length_h2` is the fixed behaviour.
Commit 70ed52764: "Answer a CONNECT over HTTP/2 with a bare head".

## Found in the tunnel, not changed

From `Tunnel.tla` and the code; Kani could not run on `tunnel.rs`, so these
are left to the owner (README, "Findings in the tunnel").

- An empty `Data` chunk at the front of the tunnel's input makes
  `TunnelConn::poll_read` return `Ok(0)`, end of input, while the stream is
  open (`Tunnel_empty_chunks.cfg`, 4 steps). No producer in this tree sends
  an empty chunk today; `Http1::on_event` already drops them, and the same
  check in `Tunnel::on_event` would close it.
- The tunnel takes a chunk whole while it holds less than 64 KiB, so it can
  hold up to 64 KiB less one byte plus the largest chunk from below, not the
  "at most 64 KiB" its doc says (`Tunnel_doc_room.cfg`), and it charges
  nothing for those bytes.

## Judged correct, not changed

- HTTP/2 keeps a valid handler-supplied `content-length` on a 304, where
  HTTP/1 strips it. Both are allowed (RFC 9110 section 15.4.5 lets a 304
  carry the representation's length); the HTTP/2 choice is documented in
  `Sending::poll_next` and proved as `not_modified_keeps_supplied_length`.
- A HEAD handler that supplies a `Content-Length` is believed even when it
  also returns a body of another length: a handler that drops the HEAD body
  is the documented way to name the GET length, and the server cannot tell
  a dropped body from a wrong length. `head_keeps_supplied_length` states
  it; the table tests compare HEAD with GET only when the handler supplies
  no length.
- `Connection: close` on a 2xx to CONNECT over HTTP/1 (no further requests
  can follow a tunnel) and PROTOCOL_ERROR rather than STREAM_CLOSED for
  frames on closed streams (RFC 9113 section 5.1 allows either).
- HTTP/1 pipelining cannot interleave a `100 Continue` or an `on_fail` 400
  into a streaming response: the serve driver's ordered work blocks reads,
  timers and wakes until the response drains.

## What the models leave out

HPACK, CONTINUATION, PRIORITY, PUSH_PROMISE, trailers, GOAWAY draining,
PING and the SETTINGS acknowledgment; the wire parser's own validation of
SETTINGS values, zero window increments and frame sizes (in
`protocols/http2.rs`); body size limits, the connection budget, the head and
body timeouts, the error-reset limit and TLS; WINDOW_UPDATE on a closed
stream. The flow-control liveness properties assume a client that
eventually settles on one SETTINGS_INITIAL_WINDOW_SIZE, since one that
keeps moving it can hold every response back by design.

`Pipeline.tla` treats a request as one token and the conditions of
deadlines, the budget and failed work as one `Abort` that may close the
connection at any point; resets from below and the tunnel's output are left
out. The Kani body proofs are per step on inputs of up to six bytes, with
whole bodies following by induction on the steps; the lenient size and
trailer lines are not proved split-independent, and the strict 128-byte
chunk-line limit is not reached. `Tunnel.tla` is a model of `tunnel.rs`,
not a proof over it. The README lists each gap.
