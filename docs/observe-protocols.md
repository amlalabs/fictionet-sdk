# Add an observe protocol

Implement `fictionet::stdlib::codec::Decode` and `fictionet::observe::Present`
on your decoder. You can copy a protocol file from `src/stdlib/protocols/`
into your crate and edit it, or write a decoder from scratch. `Present::summary`
describes one item. `Present::fields` adds fields to a `Layer`, with ranges
relative to the item's raw bytes. `Layer::note` adds text without a range.
The `Present` rustdoc includes a complete decoder and registration example.

Use [`Registry`](../src/observe/registry.rs) to register a name, a matcher,
and a factory for the two direction decoders. Its contract covers defaults,
selection precedence, TCP prefix limits, UDP handling and explicit choice.
Built-ins use the same registration methods.

`Registry::names()` lists the registered names in registration order, oldest
first. Each name appears once. Replacing a name moves it to the end.
`Registry::default()` includes built-ins with the `observe` feature and is
empty without it. Matchers, factories and presenters live in `src/observe/`.

Each built-in adapter owns its matcher, factory, and input read-ahead.
Use `Http1::register`, `Dns::register`, `Dhcp::register`, or
`ModbusSession::register` from `observe::protocols`,
`observe::http2::Capture::register`, or `observe::tls::TlsSession::register`
to add just that protocol. These methods use the built-in name and replace
any earlier registration with that name. The default composition in
`src/observe/app.rs` registers HTTP/1, HTTP/2, TLS, Modbus, DHCP, then DNS.
Later registrations take precedence, so port-based DNS and Modbus matching
still win over HTTP prefixes. HTTP/2 waits for a partial preface on TCP.

HTTP/2 registration takes a `CaptureBudget`. The default composition creates
one budget for all its connections and registry clones, including TLS
plaintext. Keep that budget outside the per-connection factory:

```rust
use fictionet::observe::{Registry, http2, protocols::Http1, tls::TlsSession};

let mut registry = Registry::new();
Http1::register(&mut registry);
let budget = http2::CaptureBudget::default();
http2::Capture::register(&mut registry, &budget);
TlsSession::register(&mut registry);
```

For a pcap reader or live capture, create `Dissector::with_registry(registry)`
and call `decode(packet, keys)` in capture order. `packet` is a raw IPv4 or
IPv6 packet. A reader for Ethernet captures must first extract the IP
payload. Supply TLS key log entries when decryption is wanted, or `&[]`.
The returned `Decoded` exposes layers, fields, tags, and summaries.
`write_layers` and `write_buffers` use the dashboard's JSON format.

For a running world, call `fcx.observe_protocols(registry)` before observers
start watching links. New watches use that registry. The existing
`fictionet observe` command and dashboard then show the custom protocol
without binary changes. Watches already running retain their registry and
connection state.

Packet streams distinguish three kinds of missing data. `skipped` counts
packets omitted by sampling since the previous tap copy. The additive
`evicted` field counts copies evicted before decoding, since the previous
decoded row. The tap keeps at most 4,096 copies and 8 MiB. If it loses every
copy, the next decoded row carries that loss. Counts of sampled packets
carried by evicted copies are unavailable. Packet `seq` values still number
decoded rows; detail requests use the same numbers.

Decoded history keeps at most 4,096 rows and 32 MiB. When a subscriber asks
for rows that have expired, the stream sends
`{"event":"packet_gap","data":{"after":7,"next":12,"missed":4}}`
before sending the remaining rows. Here rows 8 through 11 were lost to that
subscriber. This also applies to a new subscription with `after:0`.
If no rows remain, `next` is the next row number to be assigned. The cursor
advances past the gap so it is reported only once. Merged dashboard streams
include the source `link` in gap data.

The drawer shows sampling, capture eviction and subscriber overruns
separately. Capture and overrun totals survive browser queue trimming and
pause. Reconnecting reloads history and resets all three totals. These are
reported counts, not complete traffic totals: expired rows may have carried
earlier sampling or capture loss. Capture downloads contain retained packets;
the new loss metadata is carried by the JSON stream, not the pcapng file.

These fields and events are additive changes to observer API version 1.
Rust public paths and signatures are unchanged. Clients should accept unknown
fields and events. When reading older streams, a missing `evicted` means zero.

Capture downloads include the deduplicated TLS secrets from the link watch
and the current world ring. Each keeps at most 20,000 secrets. A quiet watch
can retain secrets after the world ring rotates. Retention is best effort:
secrets evicted from both caches are unavailable even if their packets remain.
The `keylog` operation returns only the current world ring.

`Observed<D>` drives ordered bytes directly. Its [placement contract](../src/observe/present.rs)
covers exact spans, hop limits, live updates, resets and reassembly buffers.
For a removed outer header, record `Spans::skip`, then record its unchanged
payload with `Spans::push_exact`. Follow the documented order when recording
payload spans and calling `data` or `reset`.

[`Conversation`](../src/observe/conversation.rs) supplies the TCP selection
and flush driver, including ordered input, gaps, waiting status and ALPN.

TLS and Modbus sessions use `Registry::register_protocol` when
shared state requires the `Protocol` interface. The session factory receives
the active registry. TLS clones it for plaintext selection with the outer
ports. ALPN hints select `http2` for `h2` or `http1` for `http/1.1` only when
that name is registered. Other cases use the registry matchers, including
across split plaintext prefixes. Eight unmatched bytes permanently reject
plaintext selection in both directions, as in the outer conversation.
Selection is not retried at each record. User replacements apply inside TLS
too. HTTP/1 capture reads each head with `stdlib::http1`'s lenient reader
(`RequestHead::parse_lenient`), which checks syntax but not the framing
rules an endpoint applies, and frames bodies itself. Chunked bodies end after
the empty line that terminates all trailers. Trailer bytes do not enter the
body preview, and the next message starts after that empty line. Incomplete
trailer sections retain incremental scan progress within the capture buffer
limit. Chunk sizes must be nonempty hexadecimal values that fit in `u64`;
surrounding spaces and tabs and `;extensions` are tolerated. An invalid or
overflowing size produces a `malformed` HTTP item with the raw size line
(lossy UTF-8 with controls escaped) and the body preview collected so far.
The decoder then skips bytes until close because framing has been lost.
Framing for DNS, DHCP, Modbus, HTTP/1, HTTP/2, and TLS uses `Stream`
and `Present`.

You can copy and edit an adapter, then call its `register` method to use its
matcher and factory. Keep any helpers it depends on. To change selection
without editing an adapter, use `Registry::register`, `register_with_buffer`,
or `register_protocol` directly.

`Display::from_packet` builds an item from a relative layer, summary, and
tags. `Decoded::level` and `Decoded::cap_info` expose the summary
policy. The adapter and registry require cloneable decoder errors so `Stream`
can retain a terminal error while reporting it once.

HTTP/2's `Capture::register` uses `register_with_buffer` with
`observe::http2::CAPTURE_READ_AHEAD`. Copy `src/observe/http2.rs` to
customize presentation; it uses only public SDK APIs. It reads frames with
`stdlib::http2::Inputs::for_observation` and header blocks with
`stdlib::http2::HeaderBlocks::for_observation`, the same frame parser and
header assembly that strict `Frames` and `Session` use, which notes what
it cannot read instead of failing. Strict `Frames` and `Session` check
RFC 9113 framing and directional state. Announce a request's opening HEADERS
to the response direction's `Session::peer_open` before routing WINDOW_UPDATE.
The direction that reads a PUSH_PROMISE registers its promised stream. This
retains stream credit received before response headers, within `Limits::streams`.
Registration does not allow DATA before that direction's final headers.
`Session::peer_settings` and `Session::peer_window_update` apply control frames
from the other direction.
Ended streams keep their metadata until `retire`. Retirement keeps a watermark
for each stream parity; untracked IDs at or below it cannot reopen. Register
openings in stream ID order so lower active streams remain tracked. `lost`
clears state and stops decoding because a TCP gap does not identify the next
frame boundary.

`http2::BlockRead::diagnostics` replaces the public `notes` field. This is a
source-breaking API change. Match `http2::BlockDiagnostic` variants instead
of field labels or sentences. They report continuation state, promised stream
IDs, interruptions, invalid fragments, and byte limits. Strict assembly also
reports continuation and promised-stream facts. `observe::http2::Capture`
renders the labels and sentences, in the same order as before. Wire acceptance,
capture recovery, and displayed diagnostics are unchanged.

Capture policy keeps complete frames already present in bounded read-ahead.
An incomplete oversized frame becomes a header-only item, followed by `Skip`
for its payload. Header blocks share the stdlib HPACK decoder. Recognized
gRPC calls use `codec::Frames<grpc::Message>` through `codec::Demux`, with an 8 MiB aggregate
DATA budget shared by every connection from the built-in registry and its
clones, including nested TLS streams, through `Capture::pair_in`.
Message layers point at payload bytes when one
contiguous range is available; otherwise they use a reassembly buffer.
To show a copied `src/stdlib/protocols/grpc.rs` in HTTP/2 display, also copy
`src/observe/http2.rs` and change its `grpc` import to the copied module.
