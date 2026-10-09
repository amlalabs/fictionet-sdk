# Add an observe protocol

Implement `fictionet::stdlib::codec::Decode` and `fictionet::observe::Present`
on your decoder. You can copy a protocol file from `src/stdlib/` into your
crate and edit it, or write a decoder from scratch. `Present::summary`
describes one item. `Present::fields` adds fields to a `Layer`, with ranges
relative to the item's raw bytes. `Layer::note` adds text without a range.
The `Present` rustdoc includes a complete decoder and registration example.

Use [`Registry`](../src/observe/registry.rs) to register a name, a matcher,
and a factory for the two direction decoders. Its contract covers defaults,
selection precedence, TCP prefix limits, UDP handling and explicit choice.
Built-ins use the same registration methods.

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
rules an endpoint applies, and frames bodies itself. Framing for DNS, DHCP,
Modbus, HTTP/1, HTTP/2, and TLS uses `Stream` and `Present`.

These files can be copied into another crate and edited:

- `src/observe/protocols.rs`: capture decoders and presenters, including
  `ModbusSession`. Register that session through `register_protocol` to stop
  both directions after a framing error, as the built-in does. The file uses
  public observe and stdlib APIs, plus `hickory-proto`.
- `src/observe/http2.rs`: the HTTP/2 and gRPC presenter, `Capture`, with
  `CaptureBudget`. It uses public observe and stdlib APIs. Register it
  through `register_with_buffer`, as below.
- `src/observe/tls.rs`: `TlsSession`, its key schedule, handshake parsing,
  and record presentation. It uses public observe APIs and `ring`. Register
  it through `register_protocol`, passing the supplied registry to `new`.
- `src/observe/conversation.rs`: the public prefix selection driver.

`Display::from_packet` builds an item from a relative layer, summary, and
tags. `Decoded::level` and `Decoded::cap_info` expose the summary
policy. The adapter and registry require cloneable decoder errors so `Stream`
can retain a terminal error while reporting it once.

HTTP/2 uses `observe::http2::Capture` through `register_with_buffer`, with
`observe::http2::CAPTURE_READ_AHEAD`. Copy `src/observe/http2.rs` to
customize presentation; it uses only public SDK APIs. It reads frames with
`stdlib::http2::Inputs::for_observation` and header blocks with
`stdlib::http2::HeaderBlocks::for_observation`, the same frame parser and
header assembly that strict `Frames` and `Session` use, which notes what
it cannot read instead of failing. Strict `Frames` and `Session` check
RFC 9113 framing and directional state. `Session::peer_settings` and
`Session::peer_window_update` apply control frames from the other direction. `lost`
clears state and stops decoding because a TCP gap does not identify the next
frame boundary.

Capture policy keeps complete frames already present in bounded read-ahead.
An incomplete oversized frame becomes a header-only item, followed by `Skip`
for its payload. Header blocks share the stdlib HPACK decoder. Recognized
gRPC calls use `codec::Frames<grpc::Message>` through `codec::Demux`, with an 8 MiB aggregate
DATA budget shared by every connection from the built-in registry and its
clones, including nested TLS streams, through `Capture::pair_in`.
Message layers point at payload bytes when one
contiguous range is available; otherwise they use a reassembly buffer.
To show a copied `src/stdlib/grpc.rs` in HTTP/2 display, also copy
`src/observe/http2.rs` and change its `grpc` import to the copied module.
