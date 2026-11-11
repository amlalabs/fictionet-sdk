# HTTP framing verification

The HTTP server in `src/stdlib/web/httpd.rs` and `src/stdlib/web/httpd/`
answers over HTTP/1 (`native.rs`) and HTTP/2 (`http2.rs`) from one response
policy (`response.rs`). This directory models that policy and both wire
framings in Lean, the HTTP/1 request framing rules in Lean, the HTTP/2
stream states and flow control in TLA+, the HTTP/1 layer's pipeline and its
handoff to a tunnel in TLA+, and the HTTP/1 body framing (`http1::BodyEvents`)
with Kani. Two table tests run the Lean framing domain through the real
server and check the same rules on the bytes it writes.

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
java -XX:+UseParallelGC -Xmx6g -cp /home/souvik/.cache/adorably-fv/tla2tools.jar \
  tlc2.TLC -workers 4 -config Pipeline_base.cfg Pipeline.tla

# Kani: one harness at a time (each holds up to 10 GiB). The harnesses
# stub `memchr` (see below), so stubbing must be on.
cargo kani -p fictionet -Z stubbing --harness length_steps_follow_the_grammar

# Rust: the table tests and the regressions for the bugs the models found.
cargo test -p fictionet --test it -- framing_follows connect_success
cargo test -p fictionet --lib -- a_101_without_an_upgrade_handler_closes

# Resource properties (see "Resource properties" below).
cargo xtask http-verify resources   # the counted Kani harnesses and the TLC configs
cargo xtask http-verify diff        # the vectors, each request vector also served and costed
cargo test -p fictionet --test it http_resources
```

Lean 4 v4.35.0 with no Mathlib; TLC 2.19 on JDK 21; Kani 0.68.0 with
CBMC 6.11.0.

## Lean: the response policy and both framings

`lean/Http/Framing.lean` defines the server's decisions as functions and
proves the RFC rules about them.

| Lean | Rust | Rule |
|---|---|---|
| `policy` | `ResponsePolicy::new` in `response.rs` | `bodiless` and the length for a status, an `Asked` (`Body`, `Head`, `Tunnel`), a body length hint and a handler-supplied `Content-Length` |
| `encode1` | `native::encode` and `Http1::start` | HTTP/1 head: `Content-Length`, `Transfer-Encoding: chunked` for an unknown length on HTTP/1.1, `Connection: close` for one on HTTP/1.0 |
| `readerFraming`, `readerClose` | `http1::response_framing` in `protocols/http1.rs` | The reader's body boundary for a head and the request method (RFC 9112 section 6.3) |
| `headers2`, `contentLength2` | `Respond`'s `start` in `http2/respond.rs` (once `Sending::poll_next` in `http2.rs`) | HTTP/2 HEADERS: `content-length` and END_STREAM |
| `askedBeforeFix` | the `head_only: bool` that `Sending` carried before the fix | The negative control: the mapping that lost CONNECT |

Theorems, each over every status class, method, hint and supplied length:

- `reader_agrees`, `reader_close_agrees`: the HTTP/1 reader finds exactly
  the body the server wrote, and expects a close exactly when the server
  closes, for every response but the 101 that hands the connection on.
- `reader_no_body_is_bodiless`, `http11_body_is_delimited`: the reader
  expects no body exactly when the policy is bodiless, and on HTTP/1.1 a
  body is always delimited by a length or by chunks, never by the close.
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
`no_fields_no_body`: RFC 9112 sections 6.1 and 6.3. It is tied to the
decoder two ways (next section): `RequestTie.wire_framing_is_request`
proves that for every head the byte-level decoder model accepts,
`requestFraming` of that head's codings and lengths is the decoder's
framing, and `framing.json` holds heads written from `requestFraming`'s
inputs with its verdicts, which `tests/http1_vectors.rs` replays against
`RequestEvents`.

`lake build` is clean with no `sorry`; `Http/Axioms.lean` prints the axioms
of every theorem above.

## Lean: the HTTP/1 decoders against RFC 9112

This part proves that request smuggling between the server and any front
end that follows RFC 9112 is impossible for every request the server
accepts, and ties the proof to the Rust code with reference vectors, in the
DNS and MPTCP pattern.

```sh
cargo xtask http-verify lean      # lake build, then the axiom audit
cargo xtask http-verify diff 1    # vectors of seed 1, replayed against Rust
cargo xtask http-verify all       # lean, then diff for seeds 1 to 8
```

### The decoders, byte by byte, and the vectors

`lean/Http/Wire.lean` writes `http1::RequestEvents` (the strict decoder
`web/httpd/native.rs` runs on every connection) and `http1::ResponseEvents`
as executable functions over bytes. Each definition names the function of
`protocols/http1.rs` it follows: `codec::Lines` with CRLF endings,
`Reader::head` with all four head limits, `split_head`, `header_parts`,
`request_line`, `status_line`, `validate_target` with `core::net`'s IPv6
parser, `validate_host`, `fields` (one walk with named steps:
`clStep`, `teStep`, `connStep`, `fieldStep`), `request_framing`,
`response_framing`, `head_size`, `Reader::begin`, `Reader::body` with its
block size, and the strict `chunk_framing`. `request1` and `response1` read
one message from the start of the bytes they are given, and `requests` and
`responses` run them one after another as `Stream` does, so a theorem about
one message holds for every message of a pipeline.

`lean/Gen.lean` (`lake exe gen <dir> <seed>`) writes three files:

| File | Expected values from | Inputs |
| --- | --- | --- |
| `requests.json` | `Wire.requests` | 66 fixed inputs (the smuggling shapes of RFC 9112 section 11.2 and each rule's edge), then 6,000 random ones: one to three requests, each with at most one fault in a chosen part (method, target, version, separators, Host, lengths, codings, a chunk size, a chunk end, the last chunk, a trailer, a field line, `Connection`), leading empty lines, small limits, then sometimes cut short or given one wrong byte; with and without the end of input |
| `responses.json` | `Wire.responses` | 24 fixed inputs, then 4,000 random pipelines of responses to queued HEAD, CONNECT and other methods, with the same kinds of faults and close-delimited bodies |
| `framing.json` | `Request.lean`'s `requestFraming` | 4,000 heads written from its abstract inputs (version, codings, `Content-Length` elements, split over one or two fields with empty elements), with the body its framing gives |

`tests/http1_vectors.rs` replays each `requests` and `responses` vector
twice, with the whole input pushed at once and in random pieces, and
compares every event (head with method, target, version, status and end
offset; body block; `Done` with its offset) and how the stream stops
(waiting at an offset, ended at an offset, `Truncated`, or the
`http1::Error`). A `framing` vector must give `requestFraming`'s refusal
reason, or one message with the body it predicts.

`cargo xtask http-verify all` on 2026-11-10: `lake build` passes and the
43 theorems `Http/Axioms.lean` prints rest on `propext`, `Quot.sound` and
`Classical.choice` at most; for each of seeds 1 to 8, 6,066 request,
4,024 response and 4,000 framing vectors, 0 disagree (112,720 in all, each
request and response vector replayed twice).

The first run of `framing.json` found a disagreement in the generator, not
the decoder: it wrote empty `Content-Length` list elements that the
abstract input did not have. `Request.lean` reads an empty element as an
invalid one, so the generator no longer writes them there.

A model with DEL taken as a field byte (one rule changed in `fieldByte`)
makes 118 of seed 1's vectors disagree (15 requests, 103 responses): the
replay notices a one-rule change.

### The RFC as a family of recipients

`lean/Http/Rfc9112.lean` is written from the RFC text, not the code: lines
(section 2.2), field lines (5.1) and obs-fold (5.2), the request line (3),
`Transfer-Encoding` (6.1, 7) and `Content-Length` (RFC 9110 section 8.6),
the body length algorithm (6.3, for requests and for responses), and
chunked bodies (7.1, with extensions and trailers). Where the RFC lets a
recipient choose, `Rfc.Choices` has a field, so `Rfc.request c` is one
recipient for each choice of tolerances:

| Field | RFC text |
| --- | --- |
| `lfAlone` | 2.2: a recipient MAY recognize a single LF as a line terminator |
| `bareCrAsSp` | 2.2: a bare CR is invalid, or replaced with SP |
| `consumeWsLines` | 2.2: a whitespace-led line after the start line is refused, or consumed |
| `unfold` | 5.2: an obs-fold is refused, or replaced with SP |
| `emptyLines` | 2.2: SHOULD ignore at least one empty line before the request line |
| `wordsAnyWs` | 3: MAY parse the request line on whitespace-delimited words |
| `teOverridesCl` | 6.1, 6.3 item 3: both fields: refuse, or let `Transfer-Encoding` win |
| `clList` | RFC 9110 8.6: a repeated equal value is refused, or read as one |

Chunk extensions are not read at all (a recipient MUST ignore unknown
ones) and trailer fields are discarded (7.1.2), which only lets the family
accept more.

### What is proved

Every theorem is over all inputs of any length, with no bound. `lake build`
checks them and `Http/Axioms.lean` shows each rests on `propext`,
`Quot.sound` and `Classical.choice` at most.

| Theorem | File | Says |
| --- | --- | --- |
| `request_agrees` | `Body.lean` | For any input and any message `Wire.request1` reads to `Done` at offset `d`: every recipient `c` reads it with the same head end, method, framing, body bytes and `rest = input.drop d`, or refuses it; and it refuses it only if `c.emptyLines` is below 8 or `c.clList` is off. This is the no-smuggling theorem (RFC 9112 sections 2.2, 3, 5, 6.1, 6.3, 7.1, 11.2). |
| `request_accepted` | `Body.lean` | Every recipient that skips eight empty lines and reads a repeated `Content-Length` (whatever its other tolerances) accepts the message with those boundaries, so the agreement is not empty. |
| `head_agrees` | `Smuggling.lean` | The head part: the same head end, method and framing, for any accepted head. |
| `framing_agrees` | `Smuggling.lean` | For any field list `fields` and `request_framing` accept, every recipient's section 6.3 algorithm gives the same framing (items 3 to 7). |
| `runBody_spec`, `begin_spec` | `Body.lean` | From every decoder state, a body the decoder finishes is what every recipient reads: a length (6.3 item 6), chunks (7.1, the data of each chunk exactly, then the last chunk and the empty trailer section), or the rest of the stream (item 8). |
| `wire_framing_is_request` | `RequestTie.lean` | `Request.lean`'s `requestFraming` of an accepted head's codings and lengths is the decoder's framing. |
| `response_framing_agrees` | `Responses.lean` | For any response field list `fields` accepts, `response_framing` gives every recipient's framing: no body after HEAD, 1xx, 204, 304 or a 2xx to CONNECT (items 1, 2), chunked only when chunked is the final coding and the close otherwise (item 4), the length (6), the close (8). |
| `te_and_cl_splits_the_family`, `bare_lf_splits_the_family`, `obs_fold_splits_the_family` | `Controls.lean` | On `Transfer-Encoding` with `Content-Length`, a bare LF, and an obs-fold, two recipients the RFC allows read the message differently. |
| `te_and_cl_refused`, `bare_lf_refused`, `obs_fold_refused` | `Controls.lean` | The decoder refuses each of those inputs. A decoder that accepted one would contradict `request_agrees`. |

The lemmas behind them: `Lines.lean` (what `readHead` ends: lines with CR
LF and no LF inside, then an empty line; what `splitHead` reads from them),
`Fields.lean` (the walk of `fields` projected onto the length and the
coding state, and what it accepted), `Smuggling.lean` (an accepted field
line or request line has no CR, LF or leading whitespace, and every
recipient reads the same name, value, method and version from it; the
RFC's character classes equal the decoder's).

### Where the server departs from the RFC

None of these lets two parsers disagree on a request the server accepts;
each makes the server refuse something the RFC lets it accept. They are
reported, not changed:

- Chunk extensions are refused (`Error::ChunkExtension`, a 400), where
  section 7.1.1 says a recipient MUST ignore unrecognized ones. The module
  documentation says so; `ResponseEvents::skip_chunk_extras` is the
  lenient mode for clients.
- A non-empty trailer section is refused (`Error::Trailers`), where 7.1.2
  lets a recipient discard trailer fields.
- HTTP/1.x with a minor version other than 0 or 1 is refused
  (`Error::Version`, a 400), where section 2.3 says a recipient SHOULD
  read a higher minor version as the highest it implements.
- A response whose codings do not end in `chunked`, or name `chunked`
  twice, is refused by `ResponseEvents` (`Error::ChunkedNotLast`), where
  6.3 item 4 reads it to the close.
- A request line splits at single spaces only (section 3 allows any
  whitespace, as a MAY); obs-fold, bare CR, whitespace-led lines,
  `Transfer-Encoding` with `Content-Length`, and HTTP/1.0 with
  `Transfer-Encoding` are refused, each one of the options the RFC gives.
- The server does accept a repeated equal `Content-Length` (`1, 1`, or two
  fields with `1`), which RFC 9110 section 8.6 allows. A front end that
  uses its option to refuse it refuses the request; it cannot read other
  boundaries (`request_agrees`).

Every refusal answers 400 (501 for an unsupported coding) and closes the
connection (`Http1::fail`), so no byte after a refused head is read as a
request.

### What these proofs leave out

- `Wire.lean` is a model of the Rust code. The vectors tie it on 14,090
  inputs per seed, in random pieces as well as whole; the proofs are about
  the model.
- The decoder model reads its whole input at once. Splitting the input is
  covered by the replay in pieces and, per step, by the Kani harnesses
  `*_are_independent_of_the_split` below.
- The head limits refuse only; the theorems hold for any limits.
  `validate_target` and the IPv6 parser are in the model for the vectors
  and refuse only; no theorem is about them.
- Responses are proved at the level of the framing decision; a response
  head's bytes and a recipient's reading of them are covered by the
  vectors, not by a theorem. `runBody_spec` is shared by both decoders.
- The lenient decoders (`skip_chunk_extras`, `parse_lenient`, the capture
  parser) and the whole-message decoders (`Requests`, `Responses`) are not
  modeled.
- What the server does after a refusal (the 400, the close) is in
  `native.rs` and its tests; `Pipeline.tla` treats a failure as `Abort`.

### After the `comp/buf-h1` merge

That branch changes how a request head is held. The RFC behaviour modeled
here does not depend on it, but these must be checked again: that
`Wire.splitHead`, `headerParts`, `requestLine` and `requestHead` still
follow `split_head`, `header_parts`/`header_spans`, `request_line`,
`request_syntax` and `request_info`, in the same order of checks (the order
decides which error the vectors expect); that `fields` still walks the
fields once in order with the same steps; that `tests/http1_vectors.rs`
still compiles against `RequestHead::method`, `target`, `version` and
`RequestError::reason`; then `cargo xtask http-verify all`.

## TLA+: HTTP/2 stream states

`tla/Streams.tla` is the HTTP/2 connection layer's `Http2::on_headers`,
`headers_on`, `admit`, `on_data`, the RST_STREAM arm of `Http2::on_frame`,
`end_stream`, `write_reset`, `on_timer` (reset expiry), `response_head`,
`send_one` and `written` (the stream ends once its END_STREAM is written),
with the exchange child's `Respond` (`dispatch`, the body deadline in
`Respond::on_timer`, and `respond`) as atomic steps between them, over a few
client stream identifiers, with the stream limit, the reset list and
response body sizes as constants. Flags turn parts of the code off:
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

`tla/Flow.tla` is the receive side of `Http2::on_data` (the connection
window first, then the stream's, padding and its length byte included),
`Http2::release` once a batch of input is read (credit returns by
WINDOW_UPDATE once the client used at least half of what it has left), the
send side of `Http2::send_one` (the least of the body left, both windows and
the frame size; a wait for a retry when that is zero), and the WINDOW_UPDATE
and SETTINGS_INITIAL_WINDOW_SIZE arms of `Http2::on_frame` with their
2^31 - 1 checks. The `Wake*` flags are the retry: `Http2::advance` tries
every stream's `send_one` again after each batch of frames it reads, so all
three are on in the code. The layer keeps no per-stream waiting state
(`Http2::send`, http2.rs:1220-1244, tries every stream on every
`advance`), so the three flags are one rule in the code and each
`without_wakeon*` config removes a part of it that is not a separate line
of code. This model was written for the serving engine before the layer
foundation; checked against the layer `Http2` at e2858ccc4 on 2026-11-09,
`on_data` (770-830), `release` (1071-1103), `send_one` (1248-1310) and the
WINDOW_UPDATE and SETTINGS arms (914-932, 833-850) still do what its
actions say. The finer model of today's `Http2`, with the children, their
credit and `Stream::held`, is `verification/http2-layer/tla/Flow.tla`;
what this one keeps that it lacks is padding, the over-credit client and
the receive-window accounting (`CreditMatchesWindow`). The model's exchange takes each body unit as it
comes, as `Respond` does, so the bytes `release` holds back for a child
that has not granted credit (`Stream::held`) are zero in it. Bytes are
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

## TLA+: the HTTP/1 pipeline and the handoff to a tunnel

`tla/Pipeline.tla` is `Http1` (`web/httpd/native.rs`) inside
`Switch<Http1, Tunnel>` (`layer/switch.rs`), with the `Tunnel`
(`services/stack/tunnel.rs`) it switches to. The successor is now
`Upgraded`, a `Side<Tunnel, Http2Server>`: an `Upgrade: h2c` request that
`Http1::h2c` accepts is answered by the service's own 101, which sets the
successor in `dispatch` and then takes the same `start`, `finish`,
`hand_on` and `handover` path as the model's `U` token, so the model does
not tell the two successors apart. The header of the file maps each action
to its functions with line numbers (checked again at e2858ccc4 on
2026-11-09; `native.rs` has changed much since the model was written at
50b69c60d, and every rule was found again in it):
`on_event` for data, the end and
`Written`; `advance` with `read`, `dispatch` and `fail`; `on_done`;
`respond`, `start`, `piece`, `finish` and `hand_on`; `close` and
`over_budget`; `take_command`; `handover`; `Switch::on_event` and
`Switch::advance`; `Tunnel::on_event` and `TunnelConn::poll_read`.

The client sends `L` tokens chosen at the start from `P` (a keep-alive
request), `Q` (a request with `Connection: close`), `C` (CONNECT), `U` (an
upgrade request) and `X` (bytes that are not HTTP), in chunks of one or two
tokens, then ends. A token is its index, so a lost, repeated or reordered
byte shows. The request decoder's buffer holds `StreamCap` tokens (pushes
past it are partial or blocked, as `Stream::push` is), and the tunnel takes
a chunk whole while it holds fewer than `TunnelRoom`. The handler answers
each request with any response its kind allows: a head with or without a
body piece, at once or later (`Reply::Later`), and for `U` and `C` a 101 or
2xx with an `UpgradeHandler`, without one, or a plain answer. A deadline,
the budget or a failed work may close the connection at any point
(`Abort`). The transport takes and writes each command when it likes.

| Property | States |
|---|---|
| `OneInFlight` | at most one request read and not yet answered |
| `ReadAfterWritten` | a request is read only once every byte of the response before it has been written (`Written`), not only handed below |
| `HandoverAfterWritten` | the handover happens only with nothing of HTTP left to write: no response byte can follow it |
| `TunnelGetsTheRest` | the tunnel's input is the tokens after the handed-over request, from the first, in order, each once |
| `TunnelEndsLast` | the client's end reaches the tunnel only after every token did |
| `NoHttpAfter101` | after a 101 is queued, no further request is read |
| `TunnelGetsAll` (liveness) | every token after the request reaches the tunnel, under fairness of everything that moves bytes (not of `Abort`) |

Results with `L = 4`, `StreamCap = 2`, `TunnelRoom = 1`, chunks of 1 or 2
tokens and responses of one or two pieces: `Pipeline_base.cfg` passes,
1,493,826 states generated, 660,798 distinct, depth 41, 15 s with four
workers. Each flag is a rule of the code; each `Pipeline_without_<flag>.cfg`
turns one off and violates the property it names:

| Config | The rule turned off | Violates | States to the violation |
|---|---|---|---|
| `without_waitwritten` | `all_written` waits for `Written` (native.rs:339-341) | `ReadAfterWritten` | 255,857 generated, depth 8 |
| `without_readonlyinreading` | `advance` reads only in `Reading` (native.rs:1071) | `OneInFlight` | 23,412, depth 5 |
| `without_keepunread` | `hand_on` passes the unread bytes (native.rs:795-802) | `TunnelGetsTheRest` | 578,788, depth 11 |
| `without_leftoverinswitching` | data while `Switching` joins the leftovers (native.rs:911-923) | `TunnelGetsTheRest` | 806,786, depth 13 |
| `without_endlast` | `hand_on` puts the client's end last (native.rs:816-818) | `TunnelEndsLast` | 1,236,115, depth 19 |
| `without_handoverafterwritten` | `handover` only once `Switching` (native.rs:1111-1113) | `HandoverAfterWritten` | 106,530, depth 6 |
| `without_leftoverfirst` | `Switch` blocks new input behind leftovers (switch.rs:190) | `TunnelGetsTheRest` | 578,870, depth 11 |
| `without_feedleftovers` | `Switch::advance` feeds a leftover (switch.rs:271-276) | `TunnelGetsAll` | 1,471,808 generated, the whole graph |
| `without_closeafterbare101` | a 101 without an `UpgradeHandler` closes (native.rs:702-706) | `NoHttpAfter101` | 391,698, depth 9 |

The last is the code before commit b69a3806f: see the bugs below. The
states generated to a violation vary by a few hundred between runs (the
workers race to it); the run of 2026-11-09 on main found the same
violations at the same depths.

The model's `after` (bytes behind a request whose decoder has finished,
bounded by `StreamCap`) is never filled: `sdone` is set only together
with `Close` or the 400 path, which leave `Reading` and `Answering`, and
the `after` branch of `HttpData` needs both, so `AfterLen <= StreamCap`
holds vacuously. The code is the same: `Http1::read` (native.rs:374-386)
is the only caller of `Stream::next`, and it closes as soon as the decoder
is done, so `on_event`'s `after` buffer (native.rs:924-948) is not reached
either. Bytes behind a CONNECT or a `Connection: close` request wait in
the decoder's own buffer in both.

## Kani: HTTP/1 body framing

`kani/body.rs` is compiled into `protocols/http1.rs` under `cfg(kani)` and
calls the real decoder: `BodyEvents::decode`, which is `Reader::body`,
`Reader::chunk_step`, `chunk_framing`, `chunk_size`,
`chunk_size_skipping_extensions` and `number`, the body framing that
`RequestEvents` and `ResponseEvents` (serving), the capture parser
(`dissect/protocols/http1.rs`) and the WARC reader (`extras/src/warc.rs`)
share. The serving decoders reach the same `Reader::body` after a head;
the capture parser and the WARC reader use `BodyEvents` itself in the
lenient mode (`skip_chunk_extras`).

The proofs are per step. From each state the decoder can be in, a harness
sets up a decoder through the public constructors, puts it in that state
with any count (so lengths and chunk sizes up to `u64::MAX` are in), and
calls `decode` once. A body is a run of such steps from the state `begin`
sets for its framing, so a property that holds for every step from every
state holds for the whole body by induction on the steps. Whole-body
harnesses, which unroll several calls with the state symbolic between
them, did not fit in 10 GiB at any input length that reaches a chunk.

`one_step_follows_the_grammar` writes the grammar out independently
(`spec_front_line`, `spec_hex`, `spec_trim`, `spec_field_byte`; the
lenient trailer line uses the crate's `header_line_ok` as the definition of
a field line) and checks, for any line, head, field and block limits up to
3, 6, 2 and 3, any head and field counts so far, every input of up to six
bytes, with and without the end of input:

- a size line is consumed exactly when it is a complete CRLF line within
  the line limit whose size is valid hex, with no extension in strict
  mode, or with whitespace around the size and an extension of field bytes
  in lenient mode, and the next state holds that size (or is the trailers
  for 0); a bare LF, an overlong line or a bad size is refused;
- inside a length or a chunk, a block of exactly `min(left, block)` bytes
  goes up once that many are there, its bytes are the input's, and the
  count drops by exactly that, to `Done` or the chunk's CRLF at zero;
- a chunk's CRLF and the strict empty trailer section are required byte
  for byte; a lenient trailer line passes the head limit, the field limit
  and the field syntax, or is refused;
- a close-delimited body goes up in full blocks, then the rest and `Done`
  at the end of input; after a body come `Done` and the end;
- no step consumes more than its input; `Need` changes no state; the end
  of input with nothing buffered in an unfinished body is a failure;
- the decoder never answers `Need` while it holds its capacity, so the
  stream's buffer, whose limit is that capacity, never has to grow past
  it (the bounded-buffer rule `Stream` reports as `Fail::Stuck`).

`one_step_is_independent_of_the_split` checks that a call on the bytes up
to any cut either asks for more, after which the call on all of them gives
what one call on all of them gives (with whatever `Lines` remembered of
its scan), or already gives that same result. With `Need` changing no
state, this extends to any number of cuts.

| Harness | State, mode | Verification time | Outcomes reached (`kani::cover!`) |
|---|---|---|---|
| `length_steps_follow_the_grammar` | `Length(n)`, any `n` | 1.4 s | waits, refuses (empty at the end), yields a block |
| `data_steps_follow_the_grammar` | `Data(n)`, any `n` | 1.3 s | waits, refuses, yields a block |
| `close_steps_follow_the_grammar` | `Close` | 1.3 s | waits, yields a block, yields `Done` |
| `steps_after_a_body_follow_the_grammar` | `Done`, `Boundary`, `End` | 0.8 s | yields `Done`, ends |
| `strict_size_steps_follow_the_grammar` | `Size`, strict | 14.6 s | waits, refuses, consumes the line |
| `lenient_size_steps_follow_the_grammar` | `Size`, lenient | 37.6 s | waits, refuses, consumes the line |
| `strict_data_end_steps_follow_the_grammar` | `DataEnd`, strict | 1.5 s | waits, refuses, consumes the CRLF |
| `lenient_data_end_steps_follow_the_grammar` | `DataEnd`, lenient | 1.2 s | waits, refuses, consumes the CRLF |
| `strict_trailer_steps_follow_the_grammar` | `Trailers`, strict | 1.5 s | waits, refuses, consumes the CRLF |
| `lenient_trailer_steps_follow_the_grammar` | `Trailers`, lenient | 56.1 s | waits, refuses, consumes a line |
| `length_steps_are_independent_of_the_split` | `Length(n)` | 7.7 s | a cut before the result |
| `data_steps_are_independent_of_the_split` | `Data(n)` | 8.9 s | a cut before the result |
| `close_steps_are_independent_of_the_split` | `Close` | 3.3 s | a cut before the result |
| `steps_after_a_body_are_independent_of_the_split` | `Done`, `Boundary`, `End` | 1.0 s | a cut before the result |
| `strict_size_steps_are_independent_of_the_split` | `Size`, strict | 30.1 s | a cut before the result |
| `data_end_steps_are_independent_of_the_split` | `DataEnd`, both modes | 81.4 s | a cut before the result |
| `strict_trailer_steps_are_independent_of_the_split` | `Trailers`, strict | 6.7 s | a cut before the result |
| `chunk_size_is_the_hex_value_or_refused` | `chunk_size`, `chunk_size_skipping_extensions` on any line of up to 20 bytes | 443 s | |

Each harness reports `VERIFICATION:- SUCCESSFUL` with every unwinding
assertion holding; the times are CBMC's, with compilation about 20 s more.
The covers a state cannot reach (a block from a size line, say) are
`UNSATISFIABLE`, as they should be. The last harness proves the size
parsers return a value exactly when the input is non-empty hex whose value
fits in a `u64` (leading zeros allowed), and that value, with Kani's
overflow checks on every operation: chunk-size arithmetic cannot overflow.

Every harness stubs `core::slice::memchr::memchr` with `find_byte`, a
byte-by-byte search with the same result: CBMC cannot rule out memchr's
word-at-a-time path at a symbolic length, and with it the formulas do not
fit in memory. Each harness was also run against a broken copy of one rule
in `http1.rs` (the edit, the harness, the result):

| Broken rule (`http1.rs` at 50b69c60d) | Harness | Result |
|---|---|---|
| `chunk_framing` accepts any byte after the CR of a chunk's CRLF (line 1598, `if false && *second != b'\n'`) | `strict_data_end_steps_follow_the_grammar` | fails: `got == expect` |
| a lenient trailer line ignores the head limit (line 1542, `if false && self.scanned > self.limits.head`) | `lenient_trailer_steps_follow_the_grammar` | fails: `got == expect` |
| a length's block ignores the block size (line 1471, `.min(self.limits.body_chunk)` removed) | `length_steps_follow_the_grammar` | fails: `got == expect` |
| a close-delimited body sends whatever it has (line 1487, `if n != 0`) | `close_steps_are_independent_of_the_split` | fails: `later == direct` |
| `number` wraps instead of refusing on overflow (line 1637, `Some(n.wrapping_mul(..))`) | `chunk_size_is_the_hex_value_or_refused` | fails: `strict == spec_hex(line)` and `skipping == expected` |

## TLA+: the tunnel's room and charges

`tla/Tunnel.tla` is `Tunnel::on_event`, `take_command`, and the
`TunnelConn` reads and writes the code gets (`services/stack/tunnel.rs`), with the
budget's `charge` and a charge's drop, in units with `Room` for the 64 KiB
`ROOM`. Kani could not check this code: every harness that calls
`TunnelConn`'s `poll_read` or `poll_write` needs a `Cx`, and building one
reaches `Region`, on which Kani 0.68's compiler panics
(`kani-compiler/src/intrinsics.rs:243`, as `verification/runtime` records);
the one harness that needs no `Cx`, the start of the code only once the
budget is known, ran out of 10 GiB in CBMC (the boxed takeover, its future
and `std::sync::Mutex`).

| Property | States |
|---|---|
| `OutboundWithinRoom` | the code's writes waiting below never pass the room |
| `ChargesMatch` | the budget's count is exactly the bytes waiting and the bytes the layer below took and still holds |
| `InboundBelowRoomAndAChunk` | what came from below and was not read stays under the room plus one chunk |
| `NoEofWhileOpen` | a read returns end of input (`Ok(0)` to a buffer with room) only after the stream ended |

With `Room = 2`, `Limit = 3`, chunks from below of 1 or 3 units, writes of
1 or 3, reads of 1 or 2 and three of each: `Tunnel_base.cfg` passes,
30,275 states generated, 5,644 distinct, depth 15. Each ablation violates
its property: `without_checkroom` (a write takes `min(room, len)`,
tunnel.rs:304-309) violates `OutboundWithinRoom`; `without_chargewrites`
(the charge before the queue, tunnel.rs:310-323) violates `ChargesMatch`;
`without_admitbelowroom` (`Blocked` at the room, tunnel.rs:154-156)
violates `InboundBelowRoomAndAChunk`. Since the model was written,
`tunnel.rs` moved to `services/stack` and gained `released`,
`is_terminal` and a `Successor` impl; its room, charge and read paths are
as they were (checked at e2858ccc4 on 2026-11-09).

Two configs check the code against what it promises and find it does not
keep it; both are findings below. `Tunnel_doc_room.cfg` checks the doc
comment's "each way holds at most 64 KiB" (`InboundWithinRoom`) and
violates it in 6 steps: a chunk that arrives below the room is taken whole.
`Tunnel_empty_chunks.cfg` lets a chunk from below be empty and violates
`NoEofWhileOpen` in 4 steps: an empty chunk at the front makes `poll_read`
return `Ok(0)`, end of input, to a stream that has not ended. The base
config sends no empty chunks because no producer in this tree does:
`Http1::on_event` takes an empty chunk and drops it (native.rs:908-910),
the stack runner turns a zero-byte read into `Ended` (stack/live.rs:207) and
`Harness::push` skips empty input (harness.rs:128-132).

## Rust

`tests/it/httpd.rs::http1_framing_follows_the_rfcs_for_every_case` and
`tests/it/http2_server.rs::http2_framing_follows_the_rfcs_for_every_case`
run the Lean domain through the server: every request method (GET, HEAD,
CONNECT), response status class (103, 200, 204, 304, 404), supplied
`Content-Length` (none, valid, invalid) and body (held in full, or streamed
without a length), and for HTTP/1 both request versions. They check the
rules above on the frames and bytes the server writes, and that the HTTP/1
reply reads back under its request's method as the body the handler wrote.

`src/stdlib/web/httpd/native.rs::tests::a_101_without_an_upgrade_handler_closes`
is the regression for the 101 bug below.

## The bugs

### A 101 without an UpgradeHandler kept reading HTTP

`Pipeline_without_closeafterbare101.cfg` (the code at 50b69c60d) violates
`NoHttpAfter101`: with the client's tokens `U, P, P, C`, the handler answers
the upgrade request with a 101 that carries no `UpgradeHandler`; `start`
sets no successor, the request kept the connection alive, so `finish` went
back to `Reading` and the next request was read and answered on a
connection whose 101 had said HTTP was over. RFC 9110 section 15.2.2 says
the server switches immediately after the 101's empty line. A client that
believed the 101 sends WebSocket frames, which the server then read as HTTP
and answered with a 400. The test `a_101_without_an_upgrade_handler_closes`
sends an upgrade request and a second request to a handler that answers
with a bare 101; before the fix the output was the 101 (with `Connection:
upgrade`) followed by a second response. A 2xx to CONNECT without a handler
was already safe: CONNECT never keeps the connection alive. The fix
(commit b69a3806f, `Http1::start`): a 101 with nothing to take the
connection over closes it after the head. The behaviour predates B2: the
code before the layer had the same rule.

### The HTTP/2 CONNECT length

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

## Findings in the tunnel, not changed

Both come from `Tunnel.tla`, a model, and from reading `tunnel.rs`; Kani
could not run on the code, so they are reported for the owner rather than
fixed here.

- **An empty chunk from below reads as end of input.** `TunnelConn::poll_read`
  (tunnel.rs:266-276) copies `min(chunk.len(), buf.len())` bytes from the
  first chunk and pops it when it is empty, so an empty `Data` chunk at the
  front returns `Ok(0)` to a read with room, which every `Connection` user
  takes as the peer's end, while the stream is still open
  (`Tunnel_empty_chunks.cfg`). `ByteStream` says chunk boundaries mean
  nothing, so an empty chunk is allowed; no producer in this tree sends one
  (see above), so it cannot happen today. The smallest fix is the one
  `Http1::on_event` already has: take an empty chunk and drop it in
  `Tunnel::on_event`.
- **The inbound room is a soft limit.** `Tunnel::on_event` takes a chunk
  whole whenever it holds less than `ROOM` (tunnel.rs:150-159), so it can
  hold up to `ROOM - 1` plus the largest chunk from below, not the "at most
  64 KiB" its doc comment says (`Tunnel_doc_room.cfg`). The tunnel charges
  nothing for what it holds from below: a chunk carries whatever charge its
  producer gave it; the stack runner's carry the charge of the bytes read
  (stack/live.rs:208-215). Taking a prefix up to the room and answering
  `Admit::Partial` would make the doc true.

## What the models leave out

- HPACK, CONTINUATION, PRIORITY, PUSH_PROMISE, trailers, GOAWAY draining and
  PING. The wire parser's own checks (SETTINGS values, zero increments,
  frame sizes) are in `protocols/http2.rs` and its tests, not here.
- Body size limits, the connection budget, the head and body timeouts, the
  error-reset limit and TLS.
- WINDOW_UPDATE on a closed stream (ignored by the server, not modeled) and
  the SETTINGS acknowledgment.
- `Pipeline.tla` treats a request as one token: the head, body, 100-continue
  and the decoder's failures inside a request are the Lean request framing
  and the Kani body proofs, not this model. Timers, the budget and failed
  work appear only as `Abort`, which may close the connection at any point;
  their exact conditions are not modeled. Resets from below, `Report`s,
  `Delivery` observations and the tunnel's own output are left out. Four
  client tokens, a two-token decoder buffer and a one-token tunnel room.
- The Kani body proofs are per step with inputs of up to six bytes (four
  hex digits of chunk size), limits of up to three bytes per line, six per
  head and two fields; whole bodies follow by induction on the steps, which
  is an argument, not a harness. The lenient size line and the lenient
  trailer line are not proved split-independent (those two harnesses did
  not fit in 10 GiB); the strict ones are, and the line reader (`Lines`) is
  the same. The strict 128-byte chunk-line limit is not reached (the
  lenient mode's limit, the header line limit, is, up to three). `Stream`
  itself and the capture parser's and the WARC reader's handling of what
  `BodyEvents` returns are not covered. The serving decoder's head parsing
  is checked on small inputs in the next section.
- `Tunnel.tla` is a model of `tunnel.rs`, not a proof over the code (see
  above): wakers, the takeover's start and drop, `poll_gone` and the stack's
  `Written` events are left out.

## Kani: request smuggling boundaries

`kani/smuggling.rs` checks that every request head is framed one way RFC
9112 allows, or refused, and that the server and the response reader agree
on where a message ends ([RFC 9112 sections 5–7](https://www.rfc-editor.org/rfc/rfc9112.html#section-5)).
It adds to `Request.lean` (the field policy in the abstract), `kani/body.rs`
(chunk sizes, overflow, extensions and trailers, step by step) and
`Pipeline.tla` (requests as tokens and the handoff to a tunnel).

The serving decoder refuses ambiguous framing rather than repairing it: a
request with both Content-Length and Transfer-Encoding, Content-Length
values that disagree, any coding other than one final `chunked`, chunk
extensions, non-empty trailers, obs-fold and bare CR or LF are all
refused. `web/httpd/native.rs`:202 builds the `RequestEvents` that run
these checks.

The harnesses call these functions in `protocols/http1.rs`:

| Function | Line |
|---|---|
| `RequestEvents::scan_request` | 857 |
| `Reader::head`, `Reader::begin` | 1391, 1432 |
| `scan_fields`, `valid_field_value` | 1676, 1727 |
| `content_length`, `check_framing_fields` | 1731, 1742 |
| `transfer_encoding`, `complete_transfer` | 1749, 1771 |
| `request_framing`, `response_framing` | 1778, 1791 |
| `header_parts` | 1830 |

`scan_fields`, `content_length`, `check_framing_fields`,
`transfer_encoding`, `complete_transfer` and `header_parts` are blocks moved
out of `fields` and `header_line` unchanged, in the same order, over
borrowed names and values. The harnesses call them on stack arrays, which
keeps the solver within the memory cap. Routing a field to its check by
name, and the copy into an owned `Header`, stay outside the proofs; the
server test below covers them.

| Harness | Inputs and property |
|---|---|
| `content_lengths_separate_have_one_value`, `content_lengths_joined_have_one_value` | Two arbitrary three-byte values, as two fields or one comma-joined field, including commas, controls, signs and whitespace. The request is accepted exactly when every list member is a decimal number and all are equal; it then has that length, and a 200 response with the same fields has the same length. |
| `transfer_fields_{chunked,gzip,gzip_then_chunked,chunked_then_gzip,repeated_chunked,empty,empty_elements,parameters}` | Eight codings, each with all sixteen combinations of HTTP/1.0 or 1.1, one field or split across two, and no Content-Length or one before or after. Only a final `chunked` on HTTP/1.1 with no Content-Length is accepted, and a 200 response with the same fields is chunked too. |
| `transfer_values_follow_bounded_grammar` | Every Transfer-Encoding value of 0 to 8 bytes. Accepted exactly when it is `chunked` in any case, with at most one empty list element before or after (the only accepted forms that fit in 8 bytes). |
| `strict_head_fields_{empty_name,one_byte_name,two_byte_name,three_byte_name,without_colon}` | Every four-byte field line, split by the position of its first colon. Accepted exactly when a non-empty token comes before the colon and only field bytes after it. This includes obs-fold (a leading space), space before the colon, bare CR and LF, and every non-ASCII byte. |
| `head_boundaries_length_{zero..ten}` | Every input of 0 to 10 bytes, cut at every point, with 8-byte line limits. `Reader::head` waits, refuses, or ends the head at the first empty CRLF line after the start line, and gives the same answer whether the input arrives whole or in two pieces. |
| `pipeline_boundary_{empty_body,one_byte,two_bytes,three_bytes}` | A head with a length field of 0 to 3, that many arbitrary body bytes, then a second head. The production `Reader` finds the first head, `content_length` and `request_framing` set the body, the reader yields exactly those bytes, ends the message without consuming more, and finds the end of the second head where it is. |
| `token_character_matches_production` | All 256 bytes: the loop-free token predicate `token_char`, used in place of `ascii::is_tchar` by the harnesses above, equals the production one. |

Results (Kani with CBMC 6.11, one harness at a time under a 10 GiB cap): all
32 harnesses pass. The slowest are `head_boundaries_length_ten` (201 s),
`head_boundaries_length_nine` (179 s), `head_boundaries_length_seven`
(153 s), `content_lengths_separate_have_one_value` (132 s) and
`transfer_values_follow_bounded_grammar` (117 s).

Two first versions did not fit in 10 GiB and were changed. The pipeline
harness with full request lines (`POST / HTTP/1.1`, `Host`,
`Content-Length`) was killed by the out-of-memory killer at 10 GiB after
11 minutes for three body bytes, and reached 10 GiB after 10 minutes for
one. It now uses one-letter start lines and a one-letter field name, which
the reader treats exactly as it treats full ones, and each case takes 3 s.
The transfer harness with its four flags symbolic reached 10 GiB on the
parameterized coding; it now checks the sixteen flag combinations one after
another, and each coding takes under 20 s.

Each control stubs one function and runs the same property on a concrete
input that shows the fault.

| Control | Change | Witness and failed assertion |
|---|---|---|
| `content_lengths_control_truncated_number` | `number` reads only the first digit | fields `100` and `101` read as equal; `result.is_err()` fails |
| `content_lengths_joined_control_truncated_number` | the same | `100,101` in one field; `result.is_err()` fails |
| `transfer_fields_control_conflicting_fields` | `check_framing_fields` accepts both fields | `chunked` with Content-Length is accepted |
| `transfer_fields_control_old_version` | `transfer_encoding` skips the HTTP/1.0 check | `chunked` on HTTP/1.0 is accepted |
| `transfer_fields_control_unsupported_coding` | `request_framing` skips the unsupported-coding check | `gzip, chunked` is accepted |
| `transfer_fields_control_missing_final_chunked` | `request_framing` frames any coding as chunked | `gzip` is accepted |
| `transfer_fields_control_repeated_chunked` | `transfer_encoding` allows a coding after `chunked` | `chunked` in two fields is accepted |
| `transfer_fields_control_nonfinal_chunked` | both of the last two changes | `chunked` then `gzip` is accepted |
| `transfer_values_control_missing_final_chunked` | `request_framing` frames any coding as chunked | `gzip` is accepted |
| `strict_head_fields_control_allow_controls` | `field_byte` accepts every byte | `X:<CR>x` is accepted |
| `head_boundaries_control_bare_lf` | `Reader::head` also ends lines at a bare LF | `X<LF><LF>` ends a head; `got == expected` fails |
| `pipeline_control_ignore_length` | `request_framing` ignores Content-Length | the body byte is read as the next request |
| `token_character_control_allow_invalid` | `ascii::is_tchar` accepts every byte | `is_tchar(byte) == token_char(byte)` fails |

The last two transfer controls change two checks at once because either
check alone refuses those inputs.

`find_byte` replaces `memchr` with a plain search, as in the body
harnesses. Unwinding assertions stay on in every harness.

Run one harness or control:

```sh
systemd-run --user --scope -q --slice=fictionet-work.slice -p MemoryMax=10G -p MemorySwapMax=0 \
  env CARGO_BUILD_JOBS=4 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  cargo kani -p fictionet --lib -Z stubbing --output-format terse \
  --harness content_lengths_separate_have_one_value
```

`--harness smuggling_proofs:: -j 1` runs all of them one at a time; the
controls fail by design, so that command exits non-zero.

On November 10, 2026 (`comp/fv-fixup`, after the buffers round gave
`Reader::body` its `partial` argument, passed as `false`), each of the 45
ran alone under a 14 GiB scope: the 32 proofs pass and the 13 controls
fail, each on the assertion its row above names.

### The server test

`ambiguous_framing_never_dispatches_a_pipelined_request` in
`web/httpd/native.rs` sends sixteen POST requests to the real server, each
followed by `GET /admin`, cut at every byte. Equal duplicate lengths
(`1` twice, `1, 1`) and plain chunking dispatch both requests. Content-Length
with Transfer-Encoding in either order, unequal lengths, unsupported or
non-final codings, an overflowing chunk size, a chunk extension, a
trailer, obs-fold, a bare LF and a bare CR never dispatch `/admin`. Every
response is read back with `http1::Responses`: two for an accepted pair,
one for a refused one.

### What these checks leave out

Decimal lengths beyond three digits, field lines beyond four bytes, heads
beyond ten bytes, and pipelines beyond two requests and three body bytes.
The ten-byte heads do not reach the head-size or header-count limits. The
response comparison covers 200 responses with declared framing; HEAD,
CONNECT, statuses without a body and responses with no framing follow
other rules, covered by the response proofs above. The lenient decoder
used for captures is not used by the server and is not checked here.

## Resource properties

The method is in `verification/README.md`, "Resource properties". The
area has all three layers, over the three places that join a unit that
arrives in pieces (an HTTP/1 head, an HTTP/2 header block, the request
body `Respond` collects) and the storage a response and received DATA
hold within HTTP/2's flow-control windows and the per-stream send
deadline.

```sh
cargo xtask http-verify resources   # the Kani harnesses and the TLC configs below
cargo xtask http-verify diff        # the vectors; every request vector also served and costed
cargo test -p fictionet --test it http_resources
```

**What is charged.** Every block an HTTP/1 head is joined in is charged
to the connection's budget before it is allocated: a pool slot, a block
of its own (`Chunk::block`), or the largest block the budget has room for
(`Budget::charge_within`); the first delivery is taken as it came and
charged its capacity (`Chunk::repay`). An HTTP/2 header block split
across frames or pieces is kept in `ChargedSegments`
(`HeaderBlocks::join`) and decoded across them where they lie
(`hpack::Block`). `Respond` keeps a body in `ChargedSegments` too
(`collect_into`): one segment of exactly its `content-length` when that
is known, taken with its first bytes. A response body goes down in
chunks its child charged, within the credit the connection gives
(`SEND_CREDIT`, `more_credit`); received DATA is held within the receive
window the connection advertised.

**The growth rule.** An HTTP/1 head replaces full storage with storage
twice what it holds, up to the head limit, and when the budget has no
room for that, with the largest it has room for, if that holds what is
needed. HTTP/2 storage never moves: a piece fills the room in the last
segment, and the rest takes one new segment, charged before it is
allocated, of the rest or an eighth of what is held if that is more,
between 256 bytes and 16 KiB, never past the limit, and down to the rest
or 256 bytes when the budget has no room for more. A body of known
length never grows. A head or header block the budget has no room for
waits for memory; a body ends with `503`. A handler reads a body in full
as one chunk, so a body of unknown length kept in more than one segment
is copied once, when it is handed on, into a chunk of its length charged
first (`Body::from_segments`), or ends with `503` if there is no room.

### TLA+

`tla/Assembly.tla` is one unit kept from pieces, threaded through a
store (`resources/tla/Resources.tla`) in the code's order. Moving
storage charges the new block, allocates it, copies what is held, frees
the old block and gives its charge back; segmented storage
(`Segmented`) charges and allocates one more segment and copies nothing.
A unit of `UnitLimit`, or of a length known from its first piece
(`Known`), comes in pieces of `PieceSizes`; a body of unknown length in
more than one segment is copied whole once when it is handed on
(`JoinWhole`). The rest of the budget (another of the client's
connections) takes and frees room between units, and within one when
`BudgetMovesInUnit`. `copied` counts the bytes moves and joins copy into
fresh storage. Invariants: `AssemblyPaid` (no moment held more than was
reserved then), `AssemblyWithinLimit`, `AssemblyTracks`, `LinearCopy`
(`copied <= CopyPer * received`), with `CopyPer` 1 for segments (the one
join), 2 for doubling the capacity (the capacities moved out of form a
doubling series under twice the last, which the unit passed) and 3 for
doubling what is held, as HTTP/1 does (each copy is more than twice the
one two moves before), and `HeldBound`
(`Share * peak <= HeldShares * input + Share * HeldFixed`, the most held
at any moment against the unit's size: its known length, or what
arrived). For a header block the bound is the block, a share of it and
the floor; for a body of known length, its length; for a body of
unknown length, the body twice, for the join, and a share.

`tla/SendHold.tla` is two streams' responses and the connection's
received DATA: the child's chunks queue within its credit, frames go
within both send windows, the client grants or withholds window at any
time, a clock ticks only while no stalled stream's deadline has passed
(as `Http2::deadline` and the runner fire it), and a stream whose queue
waited `WriteTimeout` with a closed window is reset. Invariants:
`QueuePaid`, `QueueWithinCredit` (granted and queued at most
`SendCredit`), `ReceivePaid`, `ReceiveWithinWindow` (what is held and
what the client may still send at most the window), `QueuesTrack`,
`ReceiveTracks`, and `HoldBounded` (a stalled queue waited at most
`WriteTimeout`).

| Config | Result |
| --- | --- |
| `Assembly_head_base` | passes: `RequestStream::push`, `UnitLimit` 12, pieces of 1 to 3, budget 24 |
| `Assembly_head_long_base` | passes: the same a byte a delivery, `UnitLimit` 24, budget 48 |
| `Assembly_block_base` | passes: `HeaderBlocks::join` in segments, a floor of 2, `HeldBound` of the block, a share and the floor |
| `Assembly_block_budgetmoves_base` | passes: the same with the rest of the budget moving before every piece |
| `Assembly_body_base` | passes: `collect_into` of unknown length, a refusal ending the body, the join when handed on, `HeldBound` of twice the body and a share |
| `Assembly_body_length_base` | passes: `collect_into` of known length, `HeldBound` of the length |
| `Assembly_block_moving` | violates `HeldBound`: header blocks in `ChargedBytes`, doubling, each move charged whole (the storage before this round) |
| `Assembly_body_moving` | violates `HeldBound`: a body of known length doubling in `ChargedBytes`, past its length |
| `Assembly_head_without_double` | violates `LinearCopy`: the head assembly before 3271cfe52 |
| `Assembly_head_without_largestwhenrefused` | violates `LinearCopy`: the head assembly at 3271cfe52, a block of exactly the need when doubling does not fit |
| `Assembly_head_without_chargefirst` | violates `AssemblyPaid`: a block allocated before it is charged |
| `Assembly_body_without_double` | violates `LinearCopy`: `Respond::collect` before bf20d67f4 |
| `Assembly_block_without_chargewhole` | violates `AssemblyPaid`: `ChargedBytes` growth before 84530d0d5 |
| `Assembly_body_without_chargewhole` | violates `AssemblyPaid`: the same for the body |
| `Assembly_head_budgetmoves` | violates `LinearCopy`, reported: a budget that frees room before each piece |
| `SendHold_base`, `SendHold_receive_base` | pass, depth 23 |
| `SendHold_without_stalldeadline` | violates `HoldBounded`: no reset on the stall timer |
| `SendHold_without_topupcredit` | violates `QueueWithinCredit`: credit per frame sent, not topped up to `SEND_CREDIT` |
| `SendHold_without_returncreditwhenfreed` | violates `ReceiveWithinWindow`: WINDOW_UPDATE for DATA still held |

Each config ran in under 20 seconds on November 11, 2026 (TLC 2.19,
two workers); the passing ones generated 18,081 to 355,892 states.

`Resources.tla`'s `Paid` used to compare a step's peak with the
reservation it ended with. A move releases the old block's charge at its
end, so a paid move failed it; `Paid` now records each moment's
shortfall in `Grow` and `Release`. `HpackSync`'s five resource configs
give their stated results with it, with the state counts of before.

### Kani

`kani/collect.rs`, compiled into `respond.rs`, runs `collect_into` on a
body of two one-byte pieces, with every allocation counted: of unknown
length under a roomy budget and under one of exactly what it asks for
(`UNKNOWN`: the least segment and the first places), and of known length
under one of its length and a place (`KNOWN`), where a growth that moved
would need the old allocation beside the new. The pieces are written
out, not looped, so the unwinding bound stays at 3, which the budget's
own loops need. `kani/resources.rs`, compiled into
`http1.rs`, runs the production `RequestStream::push` on a head of ten
pieces of 64 bytes, with pools of 4- and 8-byte slots and a 1 KiB head
limit, under a roomy budget and one of 350 or 500 bytes, where doubling
is refused past 128 or 256 bytes. All run with `-Z restrict-vtable`: a
block dropped gives its charge back through the budget's wakers.

| Harness | Bound | Result, November 10, 2026 |
| --- | --- | --- |
| `a_backing_is_within_its_constant` | a one-byte chunk asks for at most its byte and `BACKING` (128) | passes, 0.1 s |
| `the_counter_sees_every_allocation` | the counter's own check | passes, 20.8 s |
| `a_collected_body_moves_nothing` | every piece is taken; the body asks for at most `UNKNOWN`, on a roomy budget | does not fit: CBMC killed at 14 GiB in the solver after 36 s of symbolic execution (two pieces), 72 s (three) |
| `a_collected_body_stays_within_its_charge` | on a budget of `UNKNOWN`, every piece is taken, the most live at once is at most what was live before and `UNKNOWN`, and the body asks for at most `UNKNOWN` | does not fit: killed at 14 GiB after 122 s of symbolic execution (three pieces); with eight, 745 s |
| `a_body_of_known_length_is_reserved_once` | on a budget of `KNOWN`, every piece is taken, the most live at once is at most what was live before and `KNOWN`, and the body asks for at most `KNOWN` | does not fit: killed at 14 GiB after 147 s of symbolic execution (two pieces), 522 s (three) |
| `a_head_in_pieces_within_a_roomy_budget_copies_linearly` | the most live at once is at most what was live once the stream was made, the budget's limit, three backings and a piece; the pushes ask for at most `JOIN_PER` times the bytes taken, both slots and `HEAD_BLOCKS` (8) backings | not finished: still in CBMC's symbolic execution after an hour, at 9.7 GiB |
| `a_head_in_pieces_within_a_tight_budget_copies_linearly` | the same | not run: it is the roomy harness with a choice of two budgets |

`cargo xtask http-verify resources` runs the two that pass. The body
harnesses stay in the file. The one they replace,
`a_collected_body_copies_linearly`, ran `collect_into` on `ChargedBytes`
in 258.4 s with eight pieces; each call now also charges and grows the
segments' places in a `ChargedVec`, and the formula no longer fits at
two. The bounds they state are held instead by
`a_body_of_known_length_is_reserved_once` (`respond.rs`), the
`ChargedSegments` tests in `charged.rs`, `Assembly.tla` and
`a_body_in_many_data_frames_is_collected_linearly`. The head
harnesses stay in the file. Their first version, twenty 3-byte pieces
looped with an unwinding bound of 22, ran out of 14 GiB; ten pieces
written out did not finish in an hour. Each push charges and releases the
budget, takes from its pools and drops a block, which the HPACK harnesses
never do. The head assembly's bounds are held by the replay and the test
instead.

`JOIN_PER` is 4: the blocks a unit moves through form a doubling series
under twice the last, the last is under twice the unit, and a block the
budget had no room to double moves at most once more, to the largest
that fits, also under twice the unit. `HEAD_BLOCKS` is 8: the first
delivery, both pool slots, the doubling blocks up to the limit, and one
more.

Before this round, a mutation of `collect_into` growing to exactly its
length and the piece, as `Respond::collect` did before bf20d67f4, failed
`a_collected_body_copies_linearly` in 100.5 s. The moving storage's
controls are now `Assembly_block_moving` and `Assembly_body_moving`.

### The replay

`tests/http1_vectors.rs` serves every request vector with the HTTP/1
server (`Http1` on a `Driver`, answering an empty 200), cut in the random
pieces the differential replay uses, as one costed step
(`resources/cost.rs`). The deliveries are made in the step, as the
transport makes them. The budget is the pools' slots and four times the
input. The bounds, with their constants in the test:

- **Within the charge**: the most bytes live at once is at most the
  budget's limit, plus the layer's own state (`LAYER`, 1 KiB), its
  opening (`OPENING`: the pools' state, the rejected-request record, the
  dates and the small pool's first slot), a backing for each of eight
  chunks live at once, and the delivery in hand.
- **Linear copying**: the bytes asked for are at most 5 times the input
  (the joins' `JOIN_PER` and the deliveries' own bytes), plus a backing a
  delivery, the layer and its opening, both head pools' slots (a head may
  be joined in each however short it is), and for each message three
  small slots (its field block, a copy of a head refused for its `Host`,
  the answer's head) and 1 KiB for the answer's body, fields and record.

`heads_a_byte_a_delivery` serves a head of 63,276 bytes, near the 64 KiB
limit, a byte a delivery, within a roomy budget and one that leaves it no
room to double past 32 KiB.

`cargo xtask http-verify diff` over seeds 1 to 8 on November 10, 2026:
every seed passes, 6,066 request cases each, none disagreeing, every
served case within its bounds. The closest a case came to its charge was
12,296 of 25,362 bytes; to its linear bound, 12,818 to 25,360 bytes
against 30,042 to 46,841. The heads came to 99,961 of 103,105 bytes
charged (the tight budget) and 6,320,262 of 8,445,148 asked.

| Mutation, in a scratch copy | Failed check |
| --- | --- |
| `RequestStream::push` before 3271cfe52 | `heads, roomy budget`: 1,877,416,964 bytes asked for 63,276 of input, against 8,445,148; `a_head_trickled_into_a_tight_budget_is_copied_linearly`: 367,825,573 against 145,956 |
| `RequestStream::push` at 3271cfe52 (a block of exactly the need when doubling does not fit) | `heads, tight budget`: 260,172,451 against 8,445,148; the test: 297,014,677 against 182,948 |

### The bugs, fixed

Both in bf20d67f4, each with a test in `tests/it/http_resources.rs` on
the counting allocator that fails before its fix:

- **A tight head copied itself once a byte.** When the budget had no room
  to double a head's block, `RequestStream::push` took one of exactly
  what the delivery needed, full again at the next delivery. A 58 KB head
  sent a byte a delivery, with another connection leaving it 96 KiB,
  asked for 297 MB to join 41 KB
  (`a_head_trickled_into_a_tight_budget_is_copied_linearly`). It now
  takes the largest block that fits.
- **`Respond` grew a body a piece at a time.** `Respond::collect` grew
  the body to exactly its length on every DATA frame: 20,000 one-byte
  frames asked for 202 MB
  (`a_body_in_many_data_frames_is_collected_linearly`). `collect_into`
  now doubles. The room it holds ahead turned a 413 near a tight budget
  into a 503 while the answer was made
  (`serve_limits::http2_has_the_limits_budget_and_seed_of_http1`); a body
  not received whole is now dropped before its answer is made.

`tests/http1_vectors.rs` had not compiled since the buffers round
replaced `http1::RequestHead` with `web::Head`; it now uses `Head`.

### Reported, not fixed

`ChargedBytes` growth, reported here first, held the old and new
allocations at once with only the new charged. The layer area fixed it
at the root (84530d0d5): a growth charges the old allocation with the
new while the bytes move. `Assembly_block_without_chargewhole` and
`Assembly_body_without_chargewhole` are controls of the growth before
that. The memory of the move is real, and three `serve_limits` HTTP/2
tests sized to the old rule failed on it, so HTTP/2 storage no longer
moves: header blocks and bodies are kept in `ChargedSegments`, a body of
known length is reserved once, and the blocks are decoded across the
segments. `Assembly_block_moving` and `Assembly_body_moving` are the
moving storage, held to the bound the segments keep.

- **A budget that moves with the pieces.** With the largest-that-fits
  rule, a client whose other connections free a little room before each
  piece makes each HTTP/1 head block one piece larger
  (`Assembly_head_budgetmoves`). With the budget as it stands, a head
  moves at most once more. HTTP/2 storage does not move, so it does not
  copy more (`Assembly_block_budgetmoves_base`).
- **A body of unknown length is copied once when it is handed on.** A
  handler reads a body in full as one chunk, so an HTTP/2 body without
  `content-length` kept in more than one segment is copied into a chunk
  of its length when it is handed on, and for that moment the budget
  holds the body twice (`Assembly_body_base`'s `HeldShares`).

### What these checks leave out

HTTP/2 has no vectors, so its storage and holds are checked by the
models, the Kani harnesses on `collect_into` and the tests, not by a
costed replay. The Kani harnesses do not reach `HeaderBlocks::join`
(its storage is `ChargedSegments`, which the layer's tests check, and
`hpack_vectors` decodes every block in pieces) or the send queue, which
`SendHold.tla` models. The model leaves out the places of segments, a
fixed size each, which the Kani harnesses and
`a_body_in_many_data_frames_is_collected_linearly` count. The send deadline is checked in the model and by
`a_response_held_back_by_the_clients_window_is_reset_after_the_write_timeout`.
The replay serves with a handler that allocates nothing; handlers' own
storage is outside the connection's accounting.
