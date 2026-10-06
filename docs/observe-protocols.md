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
and `Selection::transport`. Return `Match::More` to wait for more prefix
bytes, up to 64 bytes. Later registrations take precedence. `choose(name)`
selects a registration explicitly. Built-ins use these same methods.

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
A coarse span, an expired mapping, a gap, or a message crossing packets
creates a separate byte buffer. Fields always index the bytes shown.

TLS session processing and HTTP/2 use `Registry::register_protocol` when
shared state requires the `Protocol` interface. HTTP/1 capture parsing
remains in observe until a stdlib HTTP/1 module is available. Framing for
DNS, DHCP, Modbus, HTTP/1, and TLS uses `Stream` and `Present`.
