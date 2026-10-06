# Fuzzing Fictionet

The agent in the sandbox is the one adversary in Fictionet's trust model.
Every byte it sends reaches world-side code. The targets here feed the
parsers and state machines on that path. A panic, a hang or memory that
grows without end in one of them is a denial of service against the
world.

The targets use [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) and
libFuzzer, and need a nightly toolchain:

```sh
cargo install cargo-fuzz
cargo +nightly fuzz list
```

## The targets

| Target | What it feeds | Code it reaches |
|---|---|---|
| `relay` | relay messages | `relay::decode` |
| `packets` | whole packets | `ip::split_protocols`'s sorting, `icmp::echo_reply`, `dhcp::Message::parse` |
| `ip_reassembly` | IPv4 and IPv6 fragments, with timing | fragment reassembly in `ip::split_protocols` |
| `stack` | packets, with checksums made right or not | a machine: `split_protocols`, `tcp::endpoint`, `udp::endpoint`, ping replies, over IPv4 and IPv6 |
| `tcp` | TCP segments and the world's own calls, structured | `tcp::endpoint`: smoltcp's state machine and the stdlib's code around it |
| `tls` | the client's bytes | `tls::server` (the ClientHello and SNI), `ClientHello::finish`, `TlsConnection` |
| `dns` | DNS messages | hickory-proto's parser, and attach's resolver reading an answer |
| `web` | packets, DNS queries, DHCP messages, TCP segments | `web::Sites`: the filter, DHCP, DNS over UDP and TCP, routing, the machines |
| `web_http` | HTTP/1.1 and HTTP/2 bytes, plain or over TLS | `web::Sites` serving HTTP through hyper and h2 |
| `proxy_http` | a request head | the HTTP proxy door of `fictionet attach`: CONNECT and absolute URIs, `Proxy-Authorization` |
| `proxy_socks5` | a SOCKS5 client's bytes | the SOCKS5 door: greeting, login and request |
| `modbus` | TCP bytes, standalone PDUs, and constructed frames, requests, and responses | `modbus`: stream chunking and EOF, MBAP and PDU limits, exception replies, value round trips, and transactional frame writes |
| `dnp3` | arbitrary and constructed CRC-protected frames; checks chunking, CRCs, transport reassembly, application fragments and write rollback | `stdlib::dnp3`: framing, transport reassembly and application headers |
| `iec104` | arbitrary APDUs and constructed frames/ASDUs; checks chunking, sequence ranges, both object address layouts and write rollback | `stdlib::iec104`: I/S/U frames and sequential or explicit object addresses |
| `rdp` | bounded arbitrary transport and plaintext bytes plus constructed values; checks chunking, TPKT/COTP composition, GCC/MCS fields, body limits and write rollback | `stdlib::rdp`: codec contracts, X.224, GCC and MCS |
| `smtp` | command and reply streams, DATA bodies, and constructed values | `stdlib::smtp`: commands, multiline replies, dot-stuffing and bounded decoders |
| `amqp` | bytes and constructed values, checked with codec contracts | `stdlib::amqp`: AMQP 0-9-1 |
| `asn1` | BER/DER elements and writer scripts; checks framing, value readers, DER copies, bounds, and transactional writes | `stdlib::asn1`: ASN.1 BER and DER |
| `pop3` | commands, replies, AUTH lines, expectations, and listings | `stdlib::pop3`: strict wire values and bounded codec contracts |
| `bacnet` | arbitrary bytes, and its decoder fed whole and in pieces | `stdlib::bacnet`: BACnet/IP |
| `cotp` | TPKT streams, standalone TPDUs, and input bytes segmented as messages | `cotp`: chunking and EOF, bounded message assembly, class 0 negotiation, error replies, strict TPDU writes, and segmentation round trips |
| `dhcpv6` | bytes and constructed values, checked with codec contracts | `stdlib::dhcpv6`: DHCPv6 |
| `enip` | arbitrary packet streams and CIP bodies plus constructed packets; checks chunking, packet policy, nested body round trips and write rollback | `stdlib::enip`: EtherNet/IP and CIP |
| `coap` | datagrams, TCP streams, and constructed values, checked with codec contracts | `stdlib::coap`: CoAP and block transfers |
| `fastcgi` | arbitrary bytes and constructed values | `stdlib::fastcgi`: exact wire values, request and response state, and bounded codec contracts |
| `bgp` | arbitrary bytes and constructed values | `stdlib::bgp`: exact frames, session context, UPDATE handling, and bounded codec contracts |
| `ftp` | control streams, address tokens, and constructed commands and replies | `stdlib::ftp`: strict wire values and bounded codec contracts |
| `geneve` | datagrams and constructed headers; bounded collection and wire contracts | `stdlib::geneve`: Geneve |
| `git_protocol` | arbitrary bytes and typed values; wire, chunking, EOF, and allocation contracts | `stdlib::git_protocol`: The Git wire protocol |
| `grpc` | Framed messages with input-selected limits, constructed payloads, header values, and zero-separated header blocks | `grpc`: chunking and EOF, message limits and transactional writes, compression flags, request and rejection round trips, trailers, timeouts, and paths |
| `imap` | commands, responses, literals, raw lines, and refusal decisions | `stdlib::imap`: strict wire values and bounded codec contracts |
| `imf` | headers and structured field values | `stdlib::imf`: `Head`, named wire types, and bounded-allocation codec contracts |
| `json` | wire values and streams checked with bounded codec contracts | `stdlib::json`: JSON |
| `kafka` | arbitrary bytes and constructed values | `stdlib::kafka`: exact wire values, versioned messages, and bounded codec contracts |
| `kerberos` | DER/BER messages, TCP records, and METHOD-DATA; checks record bounds, request-body slices, round trips, and write refusal | `stdlib::kerberos`: Kerberos V5 |
| `ldap` | BER messages, CLDAP datagrams, filters, and DN text; checks stream limits, text round trips, and constructed search writes | `stdlib::ldap`: LDAP |
| `ipp` | heads, documents, and attribute values | `stdlib::ipp`: `Head`, `Header`, `Message`, and bounded-allocation codec contracts |
| `gre` | GRE and PPTP packets; exact payload boundaries and wire contracts | `stdlib::gre`: GRE |
| `igmp` | messages and checksum-corrected inputs; bounded collection and wire contracts | `stdlib::igmp`: IGMP |
| `ipsec` | ESP, AH, NAT-T, and plaintext values; bounded collection and wire contracts | `stdlib::ipsec`: IPsec |
| `memcache` | text streams, binary packets, UDP datagrams, and constructed values | `stdlib::memcache`: strict wire values and bounded codec contracts |
| `mime_multipart` | wire values and streams checked with bounded codec contracts | `stdlib::mime_multipart`: MIME multipart bodies |
| `mongodb` | arbitrary bytes and typed values; wire, chunking, EOF, and allocation contracts | `stdlib::mongodb`: MongoDB |
| `mqtt` | bytes and constructed values, checked with codec contracts | `stdlib::mqtt`: MQTT 3.1.1 |
| `mysql` | arbitrary bytes and typed values; wire, chunking, EOF, and allocation contracts | `stdlib::mysql`: MySQL |
| `http3` | bounded frame and stream contracts, field validation, connection routing, and QPACK pause/resume | `stdlib::http3`: HTTP/3 |
| `nbns` | arbitrary bytes, and its decoder fed whole and in pieces | `stdlib::nbns`: NetBIOS Name Service |
| `nfs` | Procedure-selected NFS and MOUNT arguments and results, RPC streams, and constructed handles and names | `nfs`: argument and result round trips, handle and name limits, failure replies, RPC framing and EOF, and envelope writes |
| `ntp` | arbitrary bytes, and its decoder fed whole and in pieces | `stdlib::ntp`: NTP |
| `ocsp` | DER requests and responses, GET paths, and constructed values; checks framing, nonce bounds, signed slices, and round trips | `stdlib::ocsp`: OCSP |
| `onc_rpc` | TCP record bytes, UDP messages, AUTH_SYS bodies, and XDR arrays | `onc_rpc`: chunking and EOF, record and assembly bounds, fragmented record round trips, exact RPC writes, authentication, and array allocation limits |
| `opcua` | arbitrary chunks under selected limits and constructed chunks; checks assembly bounds, sequence rules, binary values, reserved-type reads and write rollback | `stdlib::opcua`: OPC UA over TCP |
| `portmap` | Arguments and results for every procedure and version, RPC streams, universal addresses, and constructed values | `portmap`: version refusal, XDR round trips, string and list limits, address conversion, RPC framing and EOF, and reply writes |
| `postgres` | startup, authentication, and typed messages | `stdlib::postgres`: frontend and backend decoders, wire types, and bounded-allocation codec contracts |
| `protobuf` | wire values and streams checked with bounded codec contracts | `stdlib::protobuf`: Protocol Buffers |
| `proxy_protocol` | exact wire values, header handoff and bounded codec contracts | `stdlib::proxy_protocol`: The PROXY protocol |
| `qpack` | wire values, bounded instruction contracts, tables, blocked sections, and acknowledgments | `stdlib::qpack`: QPACK, the header compression of HTTP/3 |
| `quic` | datagram and payload wire contracts, every short-header ID length, and reassembly | `stdlib::quic`: QUIC |
| `resp` | arbitrary bytes, bounded stream contracts, and strict value and command writers | `stdlib::resp`: RESP, the Redis protocol |
| `rfb` | exact wire values, session modes and bounded codec contracts | `stdlib::rfb`: RFB, the remote framebuffer protocol behind VNC |
| `rtp` | datagrams, RFC 4571 streams, strict values, and codec contracts | `stdlib::rtp`: RTP and multiplexed RTCP |
| `rtsp` | message streams, interleaved frames, header values, and constructed messages | `stdlib::rtsp`: strict wire values and bounded codec contracts |
| `sdp` | arbitrary bodies, bounded EOF decoding, strict writing, and typed attributes | `stdlib::sdp`: SDP |
| `sftp` | arbitrary bytes and typed values; wire, chunking, EOF, and allocation contracts | `stdlib::sftp`: SFTP version 3 |
| `sip` | message streams, UDP datagrams, header values, and constructed values | `stdlib::sip`: strict wire values and bounded codec contracts |
| `snmp` | BER messages, object identifiers, strict values, and codec contracts | `stdlib::snmp`: SNMP v1 and v2c |
| `socks` | exact wire values, session modes and bounded codec contracts | `stdlib::socks`: SOCKS4, SOCKS4a and SOCKS5 |
| `spnego` | Bare and GSS-wrapped tokens plus constructed wrappers; checks framing, mechanism rules, round trips, and write refusal | `stdlib::spnego`: SPNEGO |
| `ssh` | version lines, cleartext packets, messages, and codec contracts | `stdlib::ssh`: The SSH transport layer before encryption |
| `stun` | TCP streams, UDP datagrams, standalone attributes, and constructed messages | `stun`: chunking and EOF, exact raw frame spans, strict attribute writes, canonical padding and fingerprints, Binding replies, and transaction IDs |
| `syslog` | bytes and constructed values, checked with codec contracts | `stdlib::syslog`: Syslog |
| `tds` | arbitrary bytes and typed values; wire, chunking, EOF, and allocation contracts | `stdlib::tds`: SQL Server TDS |
| `telnet` | events, binary mode changes, strict writers, and bounded codec contracts | `stdlib::telnet`: Telnet |
| `openvpn` | wrapped control packets, TCP envelopes, and codec contracts | `stdlib::openvpn`: plain, tls-auth, and tls-crypt layouts |
| `rtcp` | control datagrams, compound rules, strict values, and codec contracts | `stdlib::rtcp`: reports, feedback, and XR blocks |
| `tftp` | arbitrary bytes, and its decoder fed whole and in pieces | `stdlib::tftp`: TFTP |
| `tpkt` | TCP bytes with limits selected from the input, plus constructed headers, packets, and COTP messages | `tpkt` and `cotp::over_tpkt`: chunking and EOF, exact headers and packets, size limits, TPDU round trips, and segmented message assembly |
| `thrift` | arbitrary bytes and constructed values | `stdlib::thrift`: framed and unframed messages, typed values, and bounded codec contracts |
| `urlencoded_form` | wire values and streams checked with bounded codec contracts | `stdlib::urlencoded_form`: application/x-www-form-urlencoded |
| `ospf` | packets and LSAs; contextual parsing and bounded payload contracts | `stdlib::ospf`: OSPFv2 and OSPFv3 |
| `pim` | messages and checksum-corrected inputs; contextual parsing and bounded payload contracts | `stdlib::pim`: PIMv2 |
| `rip` | RIP and RIPng routes and authentication; bounded collection and wire contracts | `stdlib::rip`: RIP |
| `vrrp` | advertisements, checksum oracles, and constructed values; bounded payload contracts | `stdlib::vrrp`: VRRP |
| `vxlan` | arbitrary bytes, and its decoder fed whole and in pieces | `stdlib::vxlan`: VXLAN and VXLAN-GPE |
| `websocket` | frames, messages, close payloads, handshake fields, and bounded codec contracts | `stdlib::websocket`: WebSocket (RFC 6455) |
| `x509` | DER certificates, CRLs, extensions, and PEM bundles; checks signed-byte preservation, text framing, limits, and constructed writes | `stdlib::x509`: X.509 certificates and CRLs |
| `xml` | wire values and streams checked with bounded codec contracts | `stdlib::xml`: XML 1.0 |
| `zabbix` | arbitrary bytes and constructed values | `stdlib::zabbix`: exact headers, packets, JSON messages, and bounded codec contracts |
| `wake_on_lan` | arbitrary payloads, bounded EOF decoding, exact packet writing, and password checks | `stdlib::wake_on_lan`: Wake-on-LAN |
| `whois` | query streams, EOF responses, fields, and constructed values | `stdlib::whois`: strict wire values and bounded codec contracts |

The proxy targets compile the `fictionet` binary's proxy modules from
their source files (`src/proxy.rs` here), because a binary's modules
cannot be imported. Code that the targets need from inside the SDK is in
`fictionet::fuzzing`, which exists only when `cargo fuzz` builds with
`--cfg fuzzing`.

Some paths are reached only in part:

- `tls` cannot finish a handshake, since the fuzzer cannot compute the
  client's Finished. `web_http` finishes real handshakes with a rustls
  client and then sends the fuzzer's bytes as plaintext, so encrypted
  records that are themselves malformed are not fuzzed after the
  handshake.
- The proxy targets fuzz the doors' parsers and the SOCKS5 handshake, not
  accepting clients, forwarding or the tunnel's pump.
- Under `cfg(fuzzing)`, smoltcp accepts every IPv4 and TCP checksum. A
  crash the `tcp` or `stack` target finds with a bad checksum must be
  checked again without it.

## Running a target

```sh
cargo +nightly fuzz run -O -a tcp fuzz/corpus/tcp -- -max_total_time=600
```

`-O` builds with optimizations, and `-a` keeps debug assertions and
overflow checks on, as in a debug build of a world. Runs read and add to
`fuzz/corpus/<target>`. A crash is saved in `fuzz/artifacts/<target>/`.
To run one input again, or to shrink it:

```sh
cargo +nightly fuzz run -O -a tcp fuzz/artifacts/tcp/crash-...
cargo +nightly fuzz tmin -O -a tcp fuzz/artifacts/tcp/crash-...
```

On a system whose default target is not `x86_64-unknown-linux-gnu`, add
`--target x86_64-unknown-linux-gnu`: the sanitizer does not work with
musl's static libc.

The `tcp` target never sleeps by default, which keeps it fast. To reach
the timers too (delayed ACKs, TIME-WAIT), let each input sleep up to some
milliseconds in all:

```sh
FICTIONET_FUZZ_SLEEP_MS=30 cargo +nightly fuzz run -O -a tcp fuzz/corpus/tcp
```

The corpora here are small seeds. Shrink a corpus before you commit it:

```sh
cargo +nightly fuzz cmin -O -a tcp fuzz/corpus/tcp
```

Each bug a target found has a regression test in the SDK's own tests, so
`cargo test` keeps it fixed without a fuzzer.

## Resource limits

Memory and fairness under a flood are a test, not a fuzz target:
`tests/flood.rs` floods `web::Sites` from one sandbox with made-up names,
fragments, SYNs and held connections, checks the limits, and checks that
the process grows by less than 200 MiB and that another sandbox is still
served.

The `dnp3`, `iec104`, `enip`, `opcua`, and `rdp` targets drive `Frames`
through `codec::Stream` and `codec::contract`. OPC UA also checks `Messages`
with its assembly limit. Typed values use `Wire` writer contracts.
RDP uses `DataBlocks` for bounded GCC block sequences.
The module docs describe the APIs:
[DNP3](../src/stdlib/dnp3.rs), [IEC 104](../src/stdlib/iec104.rs),
[EtherNet/IP](../src/stdlib/enip.rs), [OPC UA](../src/stdlib/opcua.rs), and
[RDP](../src/stdlib/rdp.rs). The shared [codec docs](../src/stdlib/codec/mod.rs)
cover `pump`, `finish`, stream errors, and unread bytes.
