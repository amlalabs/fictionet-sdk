# HTTP framing verification

The HTTP server in `src/stdlib/web/httpd.rs` and `src/stdlib/web/httpd/`
answers over HTTP/1 (`native.rs`) and HTTP/2 (`http2.rs`) from one response
policy (`response.rs`). This directory models that policy and both wire
framings in Lean, the HTTP/1 request framing rules in Lean, and the HTTP/2
stream states and flow control in TLA+. Two table tests run the Lean
framing domain through the real server and check the same rules on the
bytes it writes.

```sh
# Lean: the theorems, then the axiom audit (only propext, Quot.sound and
# Classical.choice may appear).
cd verification/http/lean && lake build && lake env lean Http/Axioms.lean

# TLC: a configuration of a model. Each *_base.cfg must pass; each
# *_without_<flag>.cfg must violate the one property it names.
cd verification/http/tla
java -XX:+UseParallelGC -Xmx6g -cp /home/souvik/.cache/adorably-fv/tla2tools.jar \
  tlc2.TLC -workers 3 -config Streams_base.cfg Streams.tla
java -XX:+UseParallelGC -Xmx6g -cp /home/souvik/.cache/adorably-fv/tla2tools.jar \
  tlc2.TLC -workers 3 -config Flow_base.cfg Flow.tla

# Rust: the table tests and the regression for the bug the model found.
cargo test -p fictionet --test it -- framing_follows connect_success
```

Lean 4 v4.35.0 with no Mathlib; TLC 2.19 on JDK 21.

## Lean: the response policy and both framings

`lean/Http/Framing.lean` defines the server's decisions as functions and
proves the RFC rules about them.

| Lean | Rust | Rule |
|---|---|---|
| `policy` | `ResponsePolicy::new` in `response.rs` | `bodiless` and the length for a status, an `Asked` (`Body`, `Head`, `Tunnel`), a body length hint and a handler-supplied `Content-Length` |
| `encode1` | `native::encode` and `Http1::start` | HTTP/1 head: `Content-Length`, `Transfer-Encoding: chunked` for an unknown length on HTTP/1.1, `Connection: close` for one on HTTP/1.0 |
| `readerFraming`, `readerClose` | `http1::response_framing` in `protocols/http1.rs` | The reader's body boundary for a head and the request method (RFC 9112 section 6.3) |
| `headers2`, `contentLength2` | `Sending::poll_next` in `http2.rs` | HTTP/2 HEADERS: `content-length` and END_STREAM |
| `askedBeforeFix` | the `head_only: bool` that `Sending` carried before the fix | The negative control: the mapping that lost CONNECT |

Theorems, each over every status class, method, hint and supplied length:

- `reader_agrees`, `reader_close_agrees`: the HTTP/1 reader finds exactly
  the body the server wrote, and expects a close exactly when the server
  closes, for every response but the 101 that hands the connection on.
- `never_both`: no head carries both `Content-Length` and
  `Transfer-Encoding` (RFC 9112 section 6.1).
- `http10_never_chunked`, `http10_unknown_length_closes`: an HTTP/1.0
  response is never chunked and an unknown length closes the connection.
- `no_length_on_informational_or_204`, `no_length_on_informational_or_204_h2`:
  no length on 1xx or 204 (RFC 9110 section 8.6).
- `connect_success_has_no_framing`, `connect_success_has_no_length_h2`: a 2xx
  to CONNECT has no `Content-Length` or `Transfer-Encoding` (RFC 9110
  section 9.3.6) and ends its HTTP/2 stream on the HEADERS frame.
- `head_length_is_get_length`, `head_length_is_get_length_h2`,
  `head_keeps_supplied_length`: HEAD gets GET's length when the handler
  supplies none, and the handler's own when it does (RFC 9110 section 9.3.2).
- `end_stream_means_no_data`, `length_matches_data`, `bodiless_ends_stream`:
  HTTP/2 DATA follows HEADERS only without END_STREAM, `content-length`
  matches the DATA, and every bodiless response ends on HEADERS (RFC 9113
  sections 8.1 and 8.1.1).
- `not_modified_keeps_supplied_length`: HTTP/2 keeps a valid handler length
  on 304.
- `connect_leaked_length_before_fix`: with `askedBeforeFix`, a 2xx to CONNECT
  with a four-byte body carries `content-length: 4`, no END_STREAM and four
  DATA bytes. This is the bug below, stated in the model.

`lean/Http/Request.lean` defines `requestFraming`, the `fields` and
`request_framing` functions of `protocols/http1.rs` over a request head's
`Transfer-Encoding` codings and `Content-Length` values, with `Reject` as
`http1::Error` and `Reject.status` as the 400 or 501 `Http1::on_fail`
answers. Theorems: `both_fields_refused`, `http10_transfer_encoding_refused`,
`chunked_not_final_refused`, `no_chunked_refused`, `empty_codings_refused`,
`chunked_alone_is_chunked`, `unsupported_coding_refused` (a 501),
`same_lengths_accepted`, `differing_lengths_refused`,
`invalid_length_refused`, `invalid_length_after_same_refused` and
`no_fields_no_body`: RFC 9112 sections 6.1 and 6.3.

`lake build` is clean with no `sorry`; `Http/Axioms.lean` prints the axioms
of every theorem above.

## TLA+: HTTP/2 stream states

`tla/Streams.tla` is `Http2::headers`, `headers_on`, `data`, the RST_STREAM
arm of `Http2::frame`, `cancel`, `write_reset`, `on_timer` (reset expiry and
the body deadline), `on_done` and `Sending::poll_next`, over a few client
stream identifiers, with the stream limit, the reset list and response body
sizes as constants. Flags turn parts of the code off:
`IgnoreAfterReset`, `RefuseOverLimit`, `HalfClosedIsStreamError`,
`CheckBelowLast`.

Invariants: `TypeOK`, `Concurrency` (never more live streams than the
limit), `IgnoredBounded` (the reset list stays within `ResetMax`),
`UsedBelowLast`, `AnsweredOnce`, `NoBodyAfterEnd` (no request body is taken
after END_STREAM). Properties: `HalfClosedFramesAreStreamErrors`,
`IdleFramesEndConnection`, `ClosedHeadersEndConnection`,
`LateFramesIgnored`, `EndStreamClosesStream` (RFC 9113 sections 5.1 and
5.1.1) and the liveness `ResponsesEnd` under weak fairness of each stream's
response.

Results with `Ids = {1, 3, 5}`, `MaxStreams = 2`, `ResetMax = 1`,
`Responses = {0, 1}`: `Streams_base.cfg` passes, 210,019 states generated,
13,277 distinct, depth 14. Each ablation violates its property:
`without_ignoreafterreset` violates `LateFramesIgnored`,
`without_refuseoverlimit` violates `Concurrency`,
`without_halfclosedisstreamerror` violates `NoBodyAfterEnd`,
`without_checkbelowlast` violates `ClosedHeadersEndConnection`.

## TLA+: HTTP/2 flow control

`tla/Flow.tla` is the receive side of `Http2::data` (the connection window
first, then the stream's, padding and its length byte included), `Accept`
with `release_window` (credit returns by WINDOW_UPDATE once the client used
at least half of what it has left), the send side of `Sending::poll_next`
(the least of the body left, both windows and the frame size; a stored waker
when that is zero), and the WINDOW_UPDATE and SETTINGS_INITIAL_WINDOW_SIZE
arms of `Http2::frame` with their 2^31 - 1 checks and wakes. Bytes are
units; the windows hold a few units. The client is any client: it may send
beyond its credit, update any window at any time and move its initial window
up and down. Flags: `CountPadding`, `CheckConnectionWindow`,
`CheckStreamWindow`, `ReleaseCredit`, `SpendWithinWindows`,
`WakeOnConnectionUpdate`, `WakeOnStreamUpdate`, `WakeOnSettings`.

Invariants: `ServerSpendsWithinWindows`, `SendWindowsBounded`,
`ReceiveWindowsNonNegative`, `CreditMatchesWindow` (the server's receive
accounting equals the client's). Properties: `OverflowRejected` (DATA beyond
the connection window ends the connection, beyond a stream window resets the
stream; RFC 9113 section 6.9.1), and the liveness `NoLostWake`,
`ResponsesEnd` and `RequestsEnd` under fairness of the server's responses
and credit returns and of a client that sends the body it declared and
grants credit when the server runs out. A client that keeps moving its
initial window can hold every response back, so the liveness properties
assume the client settles on one (`<>[][~SettingsChange]_vars`).

Results with `Ids = {1, 3}`, `RecvWindow = 5`, `SendWindow = 1`,
`MaxWindow = 2`, `Frame = 1`, `Responses = {0, 1}`, `Requests = {0, 1, 2}`,
`Initials = {0, 1}`, `Extras = {0, 4}`: `Flow_base.cfg` passes, 4,581,219
states generated, 1,145,490 distinct, depth 22, 1 min 40 s with three
workers. Each ablation violates its property: `without_countpadding` violates
`CreditMatchesWindow`, `without_checkconnectionwindow` and
`without_checkstreamwindow` violate `OverflowRejected`,
`without_releasecredit` violates `RequestsEnd`, `without_spendwithinwindows`
violates `ServerSpendsWithinWindows`, and `without_wakeonconnectionupdate`,
`without_wakeonstreamupdate` and `without_wakeonsettings` violate
`NoLostWake`.

## Rust

`tests/it/httpd.rs::http1_framing_follows_the_rfcs_for_every_case` and
`tests/it/http2_server.rs::http2_framing_follows_the_rfcs_for_every_case`
run the Lean domain through the server: every request method (GET, HEAD,
CONNECT), response status class (103, 200, 204, 304, 404), supplied
`Content-Length` (none, valid, invalid) and body (held in full, or streamed
without a length), and for HTTP/1 both request versions. They check the
rules above on the frames and bytes the server writes, and that the HTTP/1
reply reads back under its request's method as the body the handler wrote.

## The bug

`Sending` in `http2.rs` carried `head_only: bool` and rebuilt `Asked` from it
as `Head` or `Body`, so a 2xx response to CONNECT over HTTP/2 took the `Body`
path: it carried `content-length` and sent the handler's body as DATA, where
native HTTP/1 answered with a bare head (RFC 9110 section 9.3.6). The Lean
theorem `connect_leaked_length_before_fix` states the pre-fix behaviour; the
test `connect_success_has_no_length_and_ends_the_stream` in
`tests/it/http2_server.rs` failed against it with a HEADERS block of
`:status 200`, `content-length: 6` and two DATA frames. The fix carries
`Asked` through `Sending` (`wants: Asked`, from `Asked::of(request.method())`
in `dispatch`), so both backends ask the one policy the same question.

## What the models leave out

- HPACK, CONTINUATION, PRIORITY, PUSH_PROMISE, trailers, GOAWAY draining and
  PING. The wire parser's own checks (SETTINGS values, zero increments,
  frame sizes) are in `protocols/http2.rs` and its tests, not here.
- Body size limits, the connection budget, the head and body timeouts, the
  error-reset limit and TLS.
- HTTP/1 request pipelining and the 101 that hands the connection on.
- WINDOW_UPDATE on a closed stream (ignored by the server, not modeled) and
  the SETTINGS acknowledgment.
- Kani harnesses: the crate's dependency graph does not build under the
  memory cap the verification machine allows, so no Kani proofs are included.
