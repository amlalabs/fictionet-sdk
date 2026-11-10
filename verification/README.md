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
| [`layer`](layer/README.md) | `Chain`, `Switch` and `Driver` route every byte once and in order (`Route.tla`); `Children` keep stale ids, credit and control progress right (`Children.tla`); `Slots`, `Budget`, `Timers`, `Chunk`, `WorkOwner` in Kani | the real routing code's steps are replayed against `Route.tla` (`RouteTrace.tla`, `src/stdlib/layer/route_trace.rs`); sixteen Kani harnesses, no stubs | `cargo xtask layer-verify trace`; TLC per config; `cargo kani -p fictionet --harness <name>` |
| [`layer-runtime`](layer-runtime/README.md) | the stream and datagram runners that run layer stacks on live sockets (`StreamRunner.tla`, `DatagramRunner.tla`) and `Framed` | models named to `services/stack/live.rs` and `layer/framed.rs` | TLC per config |
| [`runtime`](runtime/README.md) | the runtime's state machines: executor, job context, regions, timers and the lab clock | each locked section of `src/run.rs`, `src/cx/*.rs` and `src/timer.rs` is one step; `JobContext.tla` was brought to the code (the cancellation guards it never had are gone) | TLC per config |
| [`lifecycle`](lifecycle/README.md) | one TCP connection's life, from handshake to retirement (`Conn.tla`) | model named to `tcp/engine.rs` and the handles in `tcp.rs` | TLC per config |
| [`tls`](tls/README.md) | the server TLS layer under `Driver` and `Harness` (`Layer.tla`), write cancellation in the live connection (`Write.tla`); the layer's write accounting in Kani; the provider draws entropy only from what it was given | models named to `services/tls/layer.rs` and `stack/open.rs`; Kani on the production layer | TLC per config; `cargo kani` |
| [`tls-rfc`](tls-rfc/README.md) | the vendored rustls against RFC 8446 and RFC 5246/7627: the server handshake (`Handshake.tla`, refined by `ServerHs.tla`), the record layer with the budget's refusals (`Record.tla`, refined by `RecordCode.tla`): plaintext only after authentication, no nonce used twice, no gap on the wire, key update order, refusals change nothing; Lean: record checks before decryption and nonce use (16 theorems, standard axioms only) | `hs_trace.rs` handshakes and `record_trace.rs` schedules replayed by `HandshakeTrace.tla` and `RecordTrace.tla`; `Gen.lean` vectors replayed by `record_vectors` and `nonce_vectors` in rustls's tests | `cargo xtask tls-verify handshake-trace`, `record-trace`, `lean`, `vectors`; TLC per config |
| [`tls-contract`](tls-contract/README.md) | what a replacement TLS must keep: ordered owned plaintext, sticky failure, stable negotiated metadata; STARTTLS (`Starttls.tla`); encrypted DNS request order | models follow the named Rust transitions; two `EncryptedDns_*_request_order` configs are documented expected failures | TLC per config |
| [`ssh-layer`](ssh-layer/README.md) | the transport/authentication boundary, ordered key changes, completion ownership, channel lifecycle and the honeypot policy | models named in their headers to `services/ssh`; Kani on the production arithmetic in `ssh.rs` | TLC per config; `cargo kani` |
| [`http`](http/README.md) | HTTP/1 pipelining and the switch to a tunnel (`Pipeline.tla`), HTTP/2 flow control and stream states (`Flow.tla`, `Streams.tla`), the tunnel's room and charges (`Tunnel.tla`); framing in Lean; body decoding and request smuggling in Kani | models named to `web/httpd/native.rs`, `http2.rs`, `stack/tunnel.rs`; Kani on the production decoder and `Reader` (memchr stubbed); the Lean `Request.lean` rules have no Rust tie | TLC per config; `cargo kani`; `lake build` in `http/lean` |
| [`http2-layer`](http2-layer/README.md) | the layer `Http2`: flow control with children (`Flow.tla`), stream and connection lifecycle (`Lifecycle.tla`), SETTINGS (`Settings.tla`), the h2c switch (`H2cSwitch.tla`); window arithmetic and the preface scan in Kani | models named to `http2.rs`, `children.rs`, `switch.rs`, `detect.rs`; Kani on the production helpers | TLC per config; `cargo kani` |
| [`hpack-grpc`](hpack-grpc/README.md) | encoder and decoder table sizes stay in step through SETTINGS and size updates (`HpackSync.tla`), for the default encoder and the server's `Encoder::new(0)` | model named to `hpack.rs` and `http2.rs` | TLC per config |
| [`websocket`](websocket/README.md) | message assembly, control frames and close (`Messages.tla`, `Echo.tla`); frame parsing and writing in Kani (29 harnesses) | models named to `websocket.rs`; Kani on the production functions with the stubs its README lists | TLC per config; `cargo kani` |
| [`codec`](codec/README.md) | the stream demultiplexer (`Demux.tla`); the codec stream, buffers and limits in Kani (36 harnesses) | model named to `codec/demux.rs`; Kani through the public API, no stubs | TLC; `cargo kani` |
| [`dissector`](dissector/README.md) | traffic dissection: stream reassembly with gaps (`Stream.tla`), HTTP/1 pairing (`Pairing.tla`), HPACK and TLS dissection | models named to `dissect/`; Kani on the production code | TLC per config; `cargo kani` |
| [`dns`](dns/README.md) | Lean: the wire format and the answer algorithm (62 theorems, standard axioms only); TLA+: exchanges, resolution (bailiwick, work bounds, negative caching, spoofing), DNSSEC validation | `Gen.lean` vectors replayed by `tests/dns_vectors.rs`; `cargo xtask dns-verify lean|vectors|diff`; models named to the resolver's functions; one control per property | `cargo xtask dns-verify lean` and `diff`; TLC per config |
| [`mptcp`](mptcp/README.md) | Lean: options, sequence mapping, crypto and IPv4 handling (42 theorems); TLA+: the join handshake, data mapping, the listener's backlog with cookies, the honeypot's observation | `Gen.lean` vectors replayed by `tests/mptcp_vectors.rs`; `cargo xtask mptcp-verify lean|diff`; models named to `extras/src/linux/mptcp.rs`, `tcp/engine.rs`, `demos/honeypot` | `cargo xtask mptcp-verify lean` and `diff`; TLC per config |
| [`tcp-layer`](tcp-layer/README.md) | the TCP layer's handshakes, accept, close and orphan handling over smoltcp (`Layer.tla`) | model named to `tcp/engine.rs`; SYN cookies are left to `mptcp/tla/Listener.tla` | TLC per config |
| [`tcp-port-zero`](tcp-port-zero/README.md) | smoltcp's socket with source port zero (`Socket.tla`), port allocation and preparation (`Binding.tla`); the wire and socket in Kani | models named to the vendored smoltcp, `engine.rs`, `hosts.rs`; Kani included in smoltcp's tests | TLC per config; `cargo kani` |
| [`observer`](observer/README.md) | the passive observer delivers each byte once and in order with holes marked (`Observer.tla`); the same for `Flow` in Kani | model named to `observer/flow.rs`, `observer.rs`; Kani on the production `Flow` | TLC per config; `cargo kani` |
| [`packet-udp`](packet-udp/README.md) | IP reassembly per scope with the overlap kill, expiry and the cap (`Reassembly.tla`), the IP layer's slots (`Dispatch.tla`), UDP sockets and their queues (`UdpSockets.tla`); headers and checksums in Kani | models named to `network/ip.rs`, `packet.rs`, `udp/sockets.rs`; Kani on the production parsers | TLC per config; `cargo kani` |
| [`world-layers`](world-layers/README.md) | per-peer admission with holds and releases (`Admission.tla`), staging a machine's ports (`Staging.tla`); packet dispatch in Kani | models named to `world/net/hosts.rs`, `tcp.rs`, `children.rs` | TLC per config; `cargo kani` |
| [`world-net`](world-net/README.md) | attachments and routes (`Attachments.tla`), the port table (`Ports.tla`), the routing table (`Table.tla`), cables (`Cable.tla`); prefixes in Kani | models named to `world/net/attachments.rs`, `network/route.rs`, `cable.rs` | TLC per config; `cargo kani` |

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

## Known gaps

- **Reported, not fixed.** From the models and their audit, each with its
  scenario in the area's README or VERIFICATION: `offer` in `tcp/engine.rs`
  returns at `UP_ROOM` and a second ready connection with accept credit
  waits for the next `completed`, `housekeeping` or `Accept`; the
  default-route fallback (`on_unreachable`) is not restored once an
  internet sandbox was attached and detached (`world-net`); a host placed
  at an address an outside peer was using keeps that peer's connections
  through the route alive at detach (`world-net`); HTTP/1 dissection skips every later head after a gap inside a
  body instead of resyncing at the next request line (`dissector`); HEADERS
  on a stream the client itself reset is a connection error where RFC 9113
  asks for a stream error (`http`); `native.rs`'s `after` buffer is dead
  code.
- **Kani in the audited areas was read, not rerun**, except where an
  area's README gives a date for its last run.
- **The trace check covers data only.** `RouteTrace.tla` replays bytes
  through `Chain`, `Switch` and `Driver`; the urgent path (`Written`,
  `Reset`), ends of input, timers and work are checked by `Route_urgent`
  and the unit tests, not by replay. Besides it, only `tls-rfc` has
  trace checks (handshakes and record-layer schedules of the vendored
  rustls), and Lean vectors tie DNS, MPTCP and the TLS record checks; the
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
