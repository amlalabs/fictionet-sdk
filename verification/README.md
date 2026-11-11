# Verification

Formal models and proofs of the Fictionet SDK, one folder per area. Each
folder's README says what its models cover, what they leave out, what they
found, and the counts of its last run; a VERIFICATION.md, where there is
one, keeps the longer account. This page is the index: for every area, what
is proved, how the proof is tied to the Rust, how to run it again, and what
is known not to be covered.

Three kinds of artifact appear:

- **TLA+** (`tla/*.tla`, checked with TLC): a hand-written model of a part
  of the code, with `*_base.cfg` configs of the code as it is, which must
  pass, and `*_without_<flag>.cfg` controls that break one part and name
  the one property TLC must then violate. A control that fails for another
  reason, or a base that passes vacuously, is a bug in the model. Every
  model header names the source lines it describes; those were checked
  against the tree at `e2858ccc4` on 2026-11-09.
- **Kani** (`kani/*.rs`): bounded proofs compiled into the production
  module under `cfg(kani)` with `#[path]` or `include!`, so they call the
  production functions. Where a harness stubs something (memchr in the
  HTTP harnesses, a few WebSocket helpers), its README says so.
- **Lean 4** (`lean/`): proofs about a protocol's wire format or algorithm,
  with `Gen.lean` reference vectors that a Rust test replays against the
  implementation.

Run TLC as `java -Xmx2g -cp tla2tools.jar tlc2.TLC -workers 2 -metadir <dir
outside the tree> -config <cfg> <module>.tla` from the model's folder;
Cargo and Kani under a memory cap (`systemd-run --user --scope -p
MemoryMax=10G`), with `CARGO_TARGET_DIR` outside the tree.

## Areas

| Area | Proves | Tied to the code by | Rerun |
| --- | --- | --- | --- |
| [`layer`](layer/README.md) | `Chain`, `Switch` and `Driver` route every byte once and in order (`Route.tla`); `Children` keep stale ids, credit and control progress right (`Children.tla`); `Slots`, `Budget`, `Timers`, `WorkOwner` in Kani | the real routing code's steps are replayed against `Route.tla` (`RouteTrace.tla`, `src/stdlib/layer/route_trace.rs`); Kani harnesses with no stubs | `cargo xtask layer-verify trace`; TLC per config; `cargo kani -p fictionet --harness <name>` |
| [`buf`](buf/README.md) | a `Chunk`'s cursor, pieces and headroom; a pooled backing is paid by one budget at every instant and goes back only from its last piece; a `Packet`'s checksum flags clear on any byte change; all in Kani | harnesses compiled into `buf/src/lib.rs` and `src/packet.rs`, no stubs; not yet run | `cargo kani -p fictionet-buf --harness <name>`; `cargo kani -p fictionet --harness checksum_flags_clear_on_any_byte_change` |
| [`layer-runtime`](layer-runtime/README.md) | the stream and datagram runners that run layer stacks on live sockets (`StreamRunner.tla`, `DatagramRunner.tla`) and `Framed` | models named to `services/stack/live.rs` and `layer/framed.rs` | TLC per config |
| [`runtime`](runtime/README.md) | the runtime's state machines: executor, job context, regions, timers and the lab clock | each locked section of `src/run.rs`, `src/cx/*.rs` and `src/timer.rs` is one step; `JobContext.tla` was brought to the code (the cancellation guards it never had are gone) | TLC per config |
| [`lifecycle`](lifecycle/README.md) | one TCP connection's life, from handshake to retirement (`Conn.tla`) | model named to `tcp/engine.rs` and the handles in `tcp.rs` | TLC per config |
| [`tls`](tls/README.md) | the server TLS layer under `Driver` and `Harness` (`Layer.tla`), write cancellation in the live connection (`Write.tla`); the layer's write accounting in Kani; the provider draws entropy only from what it was given | models named to `services/tls/layer.rs` and `stack/open.rs`; Kani on the production layer | TLC per config; `cargo kani` |
| [`tls-rfc`](tls-rfc/README.md) | the vendored rustls against RFC 8446 and RFC 5246/7627: the server handshake (`Handshake.tla`, refined by `ServerHs.tla`), the record layer with the budget's refusals (`Record.tla`, refined by `RecordCode.tla`): plaintext only after authentication, no nonce used twice, no gap on the wire, key update order, refusals change nothing; Lean: record checks before decryption and nonce use (16 theorems, standard axioms only) | `hs_trace.rs` handshakes and `record_trace.rs` schedules replayed by `HandshakeTrace.tla` and `RecordTrace.tla`; `Gen.lean` vectors replayed by `record_vectors` and `nonce_vectors` in rustls's tests | `cargo xtask tls-verify handshake-trace`, `record-trace`, `lean`, `vectors`; TLC per config |
| [`tls-contract`](tls-contract/README.md) | what a replacement TLS must keep: ordered owned plaintext, sticky failure, stable negotiated metadata; STARTTLS (`Starttls.tla`); encrypted DNS request order | models follow the named Rust transitions; two `EncryptedDns_*_request_order` configs are documented expected failures | TLC per config |
| [`ssh-layer`](ssh-layer/README.md) | the transport/authentication boundary, ordered key changes, completion ownership, channel lifecycle and the honeypot policy; conformance with RFC 4253 (ordering, NEWKEYS per direction, rekeys with data in flight, wrapping sequence numbers, strict KEX), RFC 8308 EXT_INFO, RFC 4252 (pipelined requests, no service before success) and RFC 4254 (open replies and reason codes, EOF and CLOSE, requests, windows), and no stall under the half-window adjustment policy against russh's bounded queues (`Transport.tla`, `Auth.tla`, `Close.tla`, `Window.tla`, `Adjust.tla`); window lemmas in Lean | `Transport.tla` traces replayed on the production transport with real crypto (`protocols/ssh/transport/replay.rs`); `Adjust.tla` searched exhaustively on the production `Channel`; other models named in their headers to `services/ssh`; Kani on the production arithmetic in `ssh.rs` | TLC per config; `cargo kani`; `lean lean/Adjust.lean` |
| [`http`](http/README.md) | HTTP/1 pipelining and the switch to a tunnel (`Pipeline.tla`), HTTP/2 flow control and stream states (`Flow.tla`, `Streams.tla`), the tunnel's room and charges (`Tunnel.tla`); framing in Lean; no request smuggling between the HTTP/1 decoder and any RFC 9112 recipient (`request_agrees`, Lean); body decoding and request smuggling in Kani | `Gen.lean` vectors replayed by `tests/http1_vectors.rs` against `RequestEvents` and `ResponseEvents`, and `Request.lean` tied by `wire_framing_is_request` and `framing.json`; models named to `web/httpd/native.rs`, `http2.rs`, `stack/tunnel.rs`; Kani on the production decoder and `Reader` (memchr stubbed) | `cargo xtask http-verify lean` and `diff`; TLC per config; `cargo kani` |
| [`http2-layer`](http2-layer/README.md) | the layer `Http2`: flow control with children (`Flow.tla`), stream and connection lifecycle (`Lifecycle.tla`), SETTINGS (`Settings.tla`), the h2c switch (`H2cSwitch.tla`); RFC 9113 specs written from the text (`StreamRules.tla`, `RfcFlow.tla`, `RfcGoaway.tla`) that `Http2` and `Session` refine (`H2Streams`, `SessionStreams`, `Http2Rfc`, `SessionRfc`, `Http2Refusal`); window arithmetic, `Session`'s windows, frame refusals and the preface scan in Kani | models named to `http2.rs`, `protocols/http2.rs`, `children.rs`, `switch.rs`, `detect.rs`; Kani on the production helpers | TLC per config; `cargo kani` |
| [`hpack-grpc`](hpack-grpc/README.md) | Lean: RFC 7541 integers, Huffman with its padding and EOS rules, the dynamic table, size updates, and encoder-decoder round trips (34 theorems, standard axioms only); TLA+: encoder and decoder table sizes stay in step through SETTINGS and size updates (`HpackSync.tla`); resources: neither table holds more than its charge at any moment, in TLA+, in counted Kani harnesses on the production insertion, and on every replayed block, whose copying stays linear | `Gen.lean` vectors replayed by `tests/hpack_vectors.rs`; `cargo xtask hpack-verify lean|vectors|diff`; model named to `hpack.rs` and `http2.rs` | `cargo xtask hpack-verify lean`, `diff` and `resources`; TLC per config |
| [`websocket`](websocket/README.md) | message assembly, control frames and close (`Messages.tla`, `Echo.tla`); frame parsing and writing in Kani (29 harnesses) | models named to `websocket.rs`; Kani on the production functions with the stubs its README lists | TLC per config; `cargo kani` |
| [`codec`](codec/README.md) | the stream demultiplexer (`Demux.tla`); the codec stream, buffers and limits in Kani (36 harnesses) | model named to `codec/demux.rs`; Kani through the public API, no stubs | TLC; `cargo kani` |
| [`dissector`](dissector/README.md) | traffic dissection: stream reassembly with gaps (`Stream.tla`), HTTP/1 pairing (`Pairing.tla`), HPACK and TLS dissection | models named to `dissect/`; Kani on the production code | TLC per config; `cargo kani` |
| [`dns`](dns/README.md) | Lean: the wire format, request checks, TCP framing, size limits, the answer algorithm, signature windows in serial arithmetic, key tags, the negative cache with the NXDOMAIN cut, and QNAME minimisation (86 headline theorems, standard axioms only); TLA+: exchanges, resolution (bailiwick, work bounds, negative caching, spoofing), DNSSEC validation | `Gen.lean` vectors replayed by `tests/dns_vectors.rs`; `cargo xtask dns-verify lean|vectors|diff`; models named to the resolver's functions; one control per property | `cargo xtask dns-verify lean` and `diff`; TLC per config |
| [`mptcp`](mptcp/README.md) | Lean: options, sequence mapping, crypto and IPv4 handling (42 theorems); TLA+: the join handshake, data mapping, the listener's backlog with cookies, the honeypot's observation | `Gen.lean` vectors replayed by `tests/mptcp_vectors.rs`; `cargo xtask mptcp-verify lean|diff`; models named to `extras/src/linux/mptcp.rs`, `tcp/engine.rs`, `demos/honeypot` | `cargo xtask mptcp-verify lean` and `diff`; TLC per config |
| [`tcp-layer`](tcp-layer/README.md) | the TCP layer's handshakes, accept, close and orphan handling over smoltcp (`Layer.tla`) | model named to `tcp/engine.rs`; SYN cookies are left to `mptcp/tla/Listener.tla` | TLC per config |
| [`tcp-rfc`](tcp-rfc/README.md) | the smoltcp socket refines RFC 9293 segment arrival with RFC 5961 (`Rfc9293.tla`, `Engine.tla`), with eight named departures; Lean: the arrival rules over the full 32-bit space | `Engine.tla` named to `process`; logs of the real socket replayed against `Rfc9293.tla` (`RfcTrace.tla`, `smoltcp/src/socket/tcp/rfc_trace.rs`); `Gen.lean` vectors replayed through `process` (`rfc_vectors.rs`) | `cargo xtask tcp-rfc-verify trace`, `lean`, `diff`; TLC per config |
| [`tcp-port-zero`](tcp-port-zero/README.md) | smoltcp's socket with source port zero (`Socket.tla`), port allocation and preparation (`Binding.tla`); the wire and socket in Kani | models named to the vendored smoltcp, `engine.rs`, `hosts.rs`; Kani included in smoltcp's tests | TLC per config; `cargo kani` |
| [`tcp-store`](tcp-store/README.md) | the TCP socket's receive and send stores of retained chunks: what they hold, the window, acknowledgements, and pieces within one chunk | none; harnesses call the stores in `smoltcp/src/socket/tcp/{rx,tx}.rs` | `cargo kani -p smoltcp` |
| [`observer`](observer/README.md) | the passive observer delivers each byte once and in order with holes marked (`Observer.tla`); the same for `Flow` in Kani | model named to `observer/flow.rs`, `observer.rs`; Kani on the production `Flow` | TLC per config; `cargo kani` |
| [`quic`](quic/README.md) | handshake amplification allowance, datagram completion ordering and progress, typed directional cancellation, connection-layer send ownership, application datagram wire admission and retirement, and stream final-size validation; partial transport coverage | Kani on production helpers and carriers; TLA+ refinement and negative controls; datagram-layer regressions with adverse delivery and independent quiche peers | See the area README; whole-engine resource bounds, HTTP/3 and full transport verification remain incomplete |
| [`packet-udp`](packet-udp/README.md) | TLA+: IP reassembly with the overlap kill, expiry and the cap (`Reassembly.tla`) and the IP layer's slots (`Dispatch.tla`), each checked to refine a spec written from the RFCs (`RfcReassembly.tla`, `RfcIpInput.tla`); UDP sockets and their queues (`UdpSockets.tla`); the trusted-checksum flag, ready for the core `Packet` (`TrustedChecksum.tla`). Lean ([lean/](packet-udp/lean/README.md)): the RFC 1071 checksum and the RFC 1624 hop update, IPv4 header checks, UDP, reassembly (any order and copies give the original; overlaps kill; limits; Time Exceeded on timeout), IPv6 extension headers, and the ICMP and ICMPv6 the engine sends (81 headline theorems, standard axioms only). Headers and checksums in Kani | `Gen.lean` vectors replayed by `tests/ip_vectors.rs`; `cargo xtask ip-verify lean|vectors|diff|all`; models named to `network/ip.rs`, `packet.rs`, `udp/sockets.rs`; Kani on the production parsers | `cargo xtask ip-verify all`; TLC per config; `cargo kani` |
| [`world-layers`](world-layers/README.md) | per-peer admission with holds and releases (`Admission.tla`), staging a machine's ports (`Staging.tla`); packet dispatch in Kani | models named to `world/net/hosts.rs`, `tcp.rs`, `children.rs` | TLC per config; `cargo kani` |
| [`world-net`](world-net/README.md) | attachments and routes (`Attachments.tla`), the port table (`Ports.tla`), the routing table (`Table.tla`), cables (`Cable.tla`); prefixes in Kani | models named to `world/net/attachments.rs`, `network/route.rs`, `cable.rs` | TLC per config; `cargo kani` |

## Resource properties

The models above check what a protocol does. Resource properties check
what a step costs: that storage grows only after it is paid for, and that
the bytes a step copies stay linear in its input. A step can be RFC-correct
and still break them. The HPACK decoder copied an entry's name and value,
up to 64 KiB each, before it evicted, outside its charge, even for an entry
larger than the table. Joining a TLS handshake message was quadratic and
uncapped, and so was HTTP/1 head assembly.

The shared pieces are in [`resources/`](resources). An area adds all three
layers:

1. **TLA+: storage is reserved before it grows.** A step in TLA+ is
   atomic, so an entry added and the old ones dropped in one step look
   the same as the reverse order. `resources/tla/Resources.tla` makes the
   transient visible. A model keeps a store `[held, peak, reserved]` for
   each part of the code that holds storage. Each step starts with
   `Begin`. The model threads the store through every allocation and
   free with `Grow` and `Shrink`, in the code's order, and through every
   charge with `Reserve`, `ReserveTo` and `Release`. Then it checks three
   invariants. `Paid`: no moment held more than was reserved. `WithinLimit`:
   the reservation stays within the budget's limit. `Tracks`: the store
   holds what the model's state says, which catches a step that forgot to
   thread it. Add `EXTENDS Resources`, and give TLC
   `-DTLA-Library=<repository>/verification/resources/tla`. Give the
   resource configs a control that does the old order and must violate
   `Paid`.
2. **Kani: production code allocates no more than its charge.** Kani
   ignores `#[global_allocator]`, so `resources/kani/counting.rs` stubs
   the standard library's allocation functions with ones that count. To
   use it, include the file at the crate root as `counting` (see its
   header). Write each harness as `counted_proof! { ... }` instead of
   `#[kani::proof]`, and run it with `cargo kani -Z stubbing -Z c-ffi -Z mem-predicates`.
   Inside the harness, build the state inside `measure` so that the
   counter sees all of it. Take the charge the code pays (the area's
   `most_held()`, or whatever the code charges), then run one step on any
   input of up to N bytes. Then state two bounds as inequalities. The
   step's `Cost.peak` is at most the charge. The bytes the step asked for
   (read `so_far()` before and after) are at most `per × input + fixed`.
   Name `per` and `fixed`, and say where each comes from. Never assert an
   exact count. The harness `the_counter_sees_every_allocation` fails if a
   toolchain routes allocations around the stubs. Make every allocation
   size and every collection length a constant on its path: use a choice
   among a few fixed shapes, and a concrete loop over counts. Leave the
   state undropped at the end (`mem::forget`). With symbolic sizes or
   counts, or with the drop glue, the HPACK harnesses ran CBMC out of
   16 GiB. A harness that still does not fit can be split into one per
   count.
3. **Replays: every step of a trace or vector run is costed.**
   `resources/alloc.rs` is the counting global allocator. It is the one
   `tests/it` uses, now shared. `resources/cost.rs` is the recorder.
   Include both with `#[path]` in the replay's test binary, and run each
   step through `Costs::step(input, charge, linear, ...)`. The step fails
   if the bytes live at once (counted from the session's start) pass the
   charge, or if the bytes asked for pass the `Linear` bound. Build what
   the session replays inside its steps. Make what the caller pays for
   before the step, such as the budget or a block sized to its bound.
   `Costs::held_charge` keeps a charge the way a holder keeps one that it
   never gives back. Each test prints a `cost:` line per kind, and the
   area's `diff` command reports it.

Bytes copied are measured as bytes asked of the allocator. Every copy
into fresh storage is asked for first, so a step that copies all it holds
on each delivery breaks a linear bound once the input is long enough. A
copy into storage the step already holds is not counted. Where that
matters (a pool that recycles blocks), state the bound on what the pool
is charged instead.

Show that each layer catches the bug it is for. In a scratch commit,
restore the old code and confirm the Kani bound and the replay fail. For
the TLA+ model, the control config does the same. Record all of it in the
area's README. A bound that fails on the current code is a finding: report
it and fix the code. Never loosen the bound until it passes.

Wire the layers into the area's verify command with `xtask/src/resources.rs`.
`resources::kani` runs the named harnesses with the counting stubs.
`resources::tlc` runs the named configs and checks each against its first
line (`\* Must pass` or `\* Must violate <invariant>`). HPACK's is
`cargo xtask hpack-verify resources`. Its replay costs run in
`hpack-verify diff`.

## What the models found in the code

Each area's README lists its own findings with the commits that fixed
them. The audit of 2026-11-09 found and fixed two:

- `Switch` held a write completion behind the leftovers of the layer it
  replaced, so a successor that waits for its writes before it reads (the
  HTTP/2 layer at its output bound) never read them: an h2c upgrade with
  pipelined requests whose responses passed 64 KiB hung. Fixed by
  `Port::urgent`, asked alike by `Chain`, `Children` and `Switch`, with a
  test in `switch.rs` (`layer/VERIFICATION.md`).
- The TCP listener let the connections waiting for accept pass the backlog
  when SYN cookies were in use: a kept handshake's ACK completed unchecked
  while a cookie's was refused. `ingress` now drops it, as Linux does, and
  the handshake sends its SYN-ACK again (`mptcp/tla/Listener.tla`,
  `tcp-layer/README.md`).

The RFC 9293 pass of 2026-11-10 (`tcp-rfc/README.md`) found six bugs in
the smoltcp socket, each fixed with a test: an ACK half the sequence space
from SND.UNA was taken as new, which stalled a connection and, on a socket
closed in SYN-RECEIVED, panicked the stack; a retransmitted bare FIN went
unanswered behind the challenge-ACK rate limit; SYN-SENT dropped a bad ACK
with PSH or FIN without a RST; text held past the peer's FIN was read
before the end of the stream; a second FIN dropped the ACK beside it; and
TIME-WAIT left a closed window's segment unanswered.

The TLS audit of 2026-11-10 (`tls-rfc`) found and fixed, in the vendored
rustls, each with a test that fails before: a record lost after
encryption that left the connection sending after the hole, and a record
under new keys sent without the KeyUpdate before it (both needing an
encrypter that over-allocates); record sizes and alerts that departed
from RFC 8446 §5 and RFC 5246 §6.2 (unprotected records up to 2^14 + 2047,
oversize TLS 1.3 records decrypted, a legal 2^14 + 2048 TLS 1.2 record
refused, decode_error where record_overflow or unexpected_message is
named); and EndOfEarlyData taken without ending its record, so a Finished
in the same record went under the early keys (RFC 8446 §5.1, upstream
too). Departures left as they are, and what to re-check after the move to
rustls's unbuffered API, are in its README.

And two found by reading a model's abstractions or a harness against the
code: an NXDOMAIN's copy under the type it answered outlived the entry
under ANY when a later NXDOMAIN of another type replaced that entry with a
shorter one, so data at the name no longer ended it (fixed in
`Cache::exists`, with a test in `tests/it/dns/cache.rs`); and
`Stream::with_next` judged a `Need` against the buffer's room before the
limit followed a capacity the decoder had just raised, so such a decoder
was reported `Stuck` (fixed, with a test in `codec/tests.rs`; the Kani
harness `an_honest_decoder_is_never_stuck` covers it).

The RFC 9113 models of 2026-11-10 (`http2-layer/README.md`) found and
fixed eleven departures, each with a test that failed before its fix. In
`Http2`: the reset list forgot a stream a second after its reset, so late
trailers ended the connection; a full reset list remembered no new reset;
a reset of a stream already closed was remembered, so HEADERS on a
skipped stream was ignored; RST_STREAM followed a 431 on a closed stream;
a refusal during graceful shutdown queued the shutdown's PING after the
final GOAWAY; and an ended response still moved with an initial window
change, so a window at 2^31 - 1 failed the connection. In `Session`: a
client PUSH_PROMISE was refused only at the end of its block, or not at
all on a reset stream; a stream window overflow and a zero increment on a
stream stopped the direction instead of ending the stream; overflow was
judged against the wrong initial window while a smaller one waited for
its ACK; and ended streams moved with an initial window change. The HPACK
Lean model found no departure.

The HPACK resource properties of 2026-11-10 (`hpack-grpc/README.md`)
found three more ways a table held more than its charge for a moment,
all now fixed:

- `Encoder::write_block` still copied an entry and then evicted, the
  decoder's bug that d914d14e9 fixed. It now does as the decoder does,
  with a test that fails before the fix.
- `Table::index` copied a literal or static name before the eviction
  that made room. Only a name the dynamic table holds has to be read
  first, and sharing it allocates nothing. Any other name is now copied
  after the eviction.
- `DynamicTable::most_held` left out the moment the entry slots double,
  when the old and the new are both allocated. It now counts that moment.
  The server's charge at 4096, 12,288 bytes, is unchanged: the most slots
  that can double there are 64, and three times 64 is within the 256
  already counted.

Two are reported, not fixed. `Table::most_held()` understates a table's
storage once its limit has fallen, because the entry slots it grew stay
allocated. The server charges once at open and never lowers its own limit,
so it is not affected.

The other one came from porting `tests/hpack_vectors.rs` to the current
`decode_block`. The test had not built since the buffers round
(3d5e185a5). A block with two faults now reports a
different one than the Lean model does. Since that round,
`Representations` borrows strings without decoding them, so a truncated
value, a bad index or an owed size reduction is reported before an
invalid Huffman name. The model decodes as it parses and reports the
Huffman error first. Both end the connection with `COMPRESSION_ERROR`;
only `hpack::Error`'s kind differs. Seeds 4, 6, 7 and 8 of `hpack-verify
diff` fail on it until the model or the code takes the other's order.

## Known gaps

- **Reported, not fixed.** From the models and their audit, each with its
  scenario in the area's README or VERIFICATION: `offer` in `tcp/engine.rs`
  returns at `UP_ROOM` and a second ready connection with accept credit
  waits for the next `completed`, `housekeeping` or `Accept`; the
  default-route fallback (`on_unreachable`) is not restored once an
  internet sandbox was attached and detached (`world-net`); a host placed
  at an address an outside peer was using keeps that peer's connections
  through the route alive at detach (`world-net`); HTTP/1 dissection skips every later head after a gap inside a
  body instead of resyncing at the next request line (`dissector`);
  application packets from an SSH client past 128 or 256 KiB between the
  server's rekey KEXINIT and the client's fail the connection, and an
  unknown SSH channel type is refused with reason 1 rather than 3
  (`ssh-layer`); `native.rs`'s `after` buffer is dead code. (HEADERS on a
  stream the client itself reset ends the connection; RFC 9113 allows that,
  and the stream error once listed here is RFC 7540's rule, `http2-layer`.)
- **`cargo kani -p fictionet` does not compile** at 3db7a847e:
  `verification/tls/kani/LayerProof.rs` and `verification/layer/kani/mod.rs`
  no longer match the code. The HTTP/2 harnesses were run with those two
  modules switched off locally. At d56ff61aa, after the buffers round,
  four modules fail to compile: `layer/kani/mod.rs`,
  `layer-runtime/kani/mod.rs` (`framed.rs`),
  `world-layers/kani/dispatch.rs` and `http/kani/smuggling.rs`. The HPACK
  resource harnesses were run in a scratch copy with those four switched
  off. Until they are brought up to date, `cargo xtask hpack-verify
  resources` fails at its Kani step.
- **Kani in the audited areas was read, not rerun**, except where an
  area's README gives a date for its last run.
- **`cargo kani` on the library does not compile at `3db7a847e`.** Two
  areas' harnesses no longer match their code:
  `layer/kani/mod.rs` compares `Refusals`, which has no `PartialEq`, and
  `tls/kani/LayerProof.rs` uses `TlsLayer` fields that are gone. The
  packet-udp reruns of 2026-11-10 switched those two modules off in a
  scratch copy; nothing in the tree was changed for it.
- **The trace check covers data only.** `RouteTrace.tla` replays bytes
  through `Chain`, `Switch` and `Driver`; the urgent path (`Written`,
  `Reset`), ends of input, timers and work are checked by `Route_urgent`
  and the unit tests, not by replay. Besides it, `ssh-layer`'s
  `Transport.tla` traces are replayed on the production SSH transport and
  `tls-rfc` has trace checks (handshakes and record-layer schedules of the
  vendored rustls); Lean vectors tie DNS, MPTCP, HPACK, the HTTP/1
  decoders, the TLS record checks, and the IP, UDP and ICMP code; the
  TLA+ models elsewhere are hand-written descriptions checked by reading.
- **Property-based tests of the tricky parts were not written in this
  pass**: byte-stream splits and coalescing through each layer and
  `Chain`, `Switch` handoff of unread bytes under random chunking,
  `Children` isolation, ready lists, the deadline heap and credit under
  random schedules, budgets charged before growth, TCP and the observer
  under loss, reordering, duplication and overlap, IP reassembly per
  scope, TLS records at every boundary, HTTP/1 framing, HTTP/2 flow control
  and HPACK tables, WebSocket fragmentation, DNS message parsing and
  compression pointers, SSH channel windows. The existing unit tests cover
  fixed cases of each; `src/stdlib/layer/tests.rs` has the seeded
  `cuts`/`segmentations` style to build on.
- **Four must-pass configs are documented expected failures**:
  `tls-contract/EncryptedDns_dot_request_order`, `_doh2_request_order`,
  `http/Tunnel_doc_room` and `http/Tunnel_empty_chunks`; their READMEs say
  why.
- The abstractions each model makes, and which real behaviors they could
  hide, are listed under "What the model leaves out" in every README.
