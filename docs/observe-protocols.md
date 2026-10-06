# Add an observe protocol

Implement `fictionet::stdlib::codec::Decode` and `fictionet::observe::Present`
on your decoder. You can copy a protocol file from `src/stdlib/` into your
crate and edit it, or write a decoder from scratch. `Present::summary`
describes one item. `Present::fields` adds fields to a `Layer`, with ranges
relative to the item's raw bytes. `Layer::note` adds text without a range.
The `Present` rustdoc includes a complete decoder and registration example.

Start with `Registry::default()` to keep the built-ins, or `Registry::new()`
for an empty registry. `register` takes a name, a matcher, and a factory for
the two direction decoders. Match `Selection::ports`, `Selection::first`,
`Selection::transport`, and `Selection::alpn` for decrypted TLS. Return
`Match::More` to wait for more TCP prefix bytes, up to 64 bytes. UDP treats `More` as `No`. Later registrations
take precedence. `choose(transport, name)` selects a registration explicitly
for that transport. `automatic(transport)` restores its matchers. Built-ins
use these same methods.

For a pcap reader or live capture, create `Dissector::with_registry(registry)`
and call `decode(packet, keys)` in capture order. `packet` is a raw IPv4 or
IPv6 packet. A reader for Ethernet captures must first extract the IP
payload. Supply TLS key log entries when decryption is wanted, or `&[]`.
The returned `Decoded` exposes layers, fields, tags, and summaries.
`write_layers` and `write_buffers` use the dashboard's JSON format.

For a running world, call `cx.observe_protocols(registry)` before observers
start watching links. New watches use that registry. The existing
`fictionet observe` command and dashboard then show the custom protocol
without binary changes. Watches already running retain their registry and
connection state.

`Observed<D>` drives ordered bytes through the same adapter directly.
Its `Placement` follows exact `Spans` from inner bytes to packet bytes.
Record a removed outer header with `Spans::skip`, then record its unchanged
payload with `Spans::push_exact`. Add hops from the innermost stream outward.
Update a live hop with `Placement::hop_mut`. Record the current payload
before the first `data` call. `Observed::reset` keeps the hops and starts at
the innermost hop's next byte offset; reset before recording new payloads.
A coarse span, an expired mapping, a gap, or a message crossing packets
creates a separate byte buffer. Fields always index the bytes shown.

TLS session processing and HTTP/2 use `Registry::register_protocol` when
shared state requires the `Protocol` interface. The session factory receives
the active registry. TLS clones it for plaintext selection with the outer
ports. ALPN hints select `http2` for `h2` or `http1` for `http/1.1` only when
that name is registered. Other cases use the registry matchers, including
across split plaintext prefixes. User replacements apply inside TLS too.
HTTP/1 capture parsing remains in observe until a stdlib HTTP/1 module is available. Framing for
DNS, DHCP, Modbus, HTTP/1, and TLS uses `Stream` and `Present`.

The capture presenters in `src/observe/protocols.rs` can also be copied into
another crate. They use public observe and stdlib APIs, plus `hickory-proto`
and `httparse`. `Display::from_packet` builds an item from a relative layer,
summary, and tags. `Decoded::level` and `Decoded::cap_info` expose the summary
policy. The adapter and registry require cloneable decoder errors so `Stream`
can retain a terminal error while reporting it once.
