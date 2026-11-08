# HTTP message framing: verification notes

Area: `src/stdlib/web/httpd.rs` and `src/stdlib/web/httpd/` (HTTP/1 in
`native.rs`, HTTP/2 in `http2.rs`, the shared response policy in
`response.rs`), the HTTP/1 framing rules in `src/stdlib/protocols/http1.rs`,
and HTTP/2 stream states and flow control. The models, how to run them and
the full results are in [verification/http/README.md](README.md).

## What was modeled and checked

| Model | Of | Checker | Result |
|---|---|---|---|
| `verification/http/lean/Http/Framing.lean` | `ResponsePolicy::new`, `native::encode` and `Http1::start`, `http1::response_framing`, `Sending::poll_next` | Lean 4 (`lake build`, axiom audit) | 20 theorems proved for every status class, method, body hint and supplied length: never both length fields, HTTP/1.0 never chunked and closes on an unknown length, no length on 1xx or 204, no framing on a 2xx to CONNECT, HEAD's length is GET's, the reader finds the body the server wrote, HTTP/2 END_STREAM and `content-length` agree with the DATA. Only `propext`, `Quot.sound` and `Classical.choice` appear. |
| `verification/http/lean/Http/Request.lean` | `http1::fields` and `request_framing` | Lean 4 | 12 theorems: RFC 9112 sections 6.1 and 6.3 for requests (both fields refused, HTTP/1.0 `Transfer-Encoding` refused, `chunked` not final refused, no `chunked` refused, unsupported coding is a 501, equal `Content-Length` values accepted, differing or invalid ones refused, no fields means no body). |
| `verification/http/tla/Streams.tla` | `Http2::headers`, `headers_on`, `data`, RST_STREAM handling, `cancel`, `write_reset`, `on_timer`, `on_done`, `Sending::poll_next` | TLC 2.19 | Base: 210,019 states generated, 13,277 distinct, depth 14; six invariants and six properties hold, including the liveness `ResponsesEnd`. Four ablations each violate the one property named for them. |
| `verification/http/tla/Flow.tla` | The receive side of `Http2::data`, `Accept` with `release_window`, the send side of `Sending::poll_next`, the WINDOW_UPDATE and SETTINGS_INITIAL_WINDOW_SIZE arms of `Http2::frame` | TLC 2.19 | Base: 4,581,219 states generated, 1,145,490 distinct, depth 22; four invariants and four properties hold, including the liveness `NoLostWake`, `ResponsesEnd` and `RequestsEnd`. Eight ablations each violate the one property named for them. |
| `tests/it/httpd.rs::http1_framing_follows_the_rfcs_for_every_case`, `tests/it/http2_server.rs::http2_framing_follows_the_rfcs_for_every_case` | The server itself, over the Lean domain | `cargo test` | Pass. Every method, status class, supplied length and body kind (and both HTTP/1 request versions) satisfies the rules the theorems state, on the bytes and frames the server writes. |

The existing `httpd` library tests and the `httpd` and `http2_server`
integration test modules pass; `cargo fmt` and `cargo clippy -- -D warnings`
are clean on the library and the `it` tests.

## Bugs

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
body timeouts, the error-reset limit and TLS; HTTP/1 request pipelining and
the 101 that hands the connection on; WINDOW_UPDATE on a closed stream. The
flow-control liveness properties assume a client that eventually settles
on one SETTINGS_INITIAL_WINDOW_SIZE, since one that keeps moving it can hold
every response back by design. No Kani harnesses: the crate's dependency
graph does not build under the memory cap this machine allows.
