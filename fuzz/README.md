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
| `modbus` | a Modbus/TCP byte stream, whole and a byte at a time | `modbus::Decoder`, `Frame`, `Request` and `Response`, reading and writing |
| `dnp3` | arbitrary and constructed link frames, CRC blocks and transport segments | `stdlib::dnp3`: framing, transport reassembly and application headers |
| `iec104` | APDU streams, ASDU headers and information object layouts | `stdlib::iec104`: I/S/U frames and sequential or explicit object addresses |
| `smtp` | command and reply streams, DATA bodies, and constructed values | `stdlib::smtp`: commands, multiline replies, dot-stuffing and bounded decoders |
| `amqp` | arbitrary bytes, and its decoder fed whole and in pieces | `stdlib::amqp`: AMQP 0-9-1 |
| `asn1` | arbitrary bytes, and its decoder fed whole and in pieces | `stdlib::asn1`: ASN.1 BER and DER |
| `bacnet` | arbitrary bytes, and its decoder fed whole and in pieces | `stdlib::bacnet`: BACnet/IP |
| `cotp` | arbitrary bytes, and its decoder fed whole and in pieces | `stdlib::cotp`: TPKT and COTP |
| `dhcpv6` | arbitrary bytes, and its decoder fed whole and in pieces | `stdlib::dhcpv6`: DHCPv6 |
| `enip` | arbitrary bytes, and its decoder fed whole and in pieces | `stdlib::enip`: EtherNet/IP and CIP |
| `fastcgi` | arbitrary bytes, and its decoder fed whole and in pieces | `stdlib::fastcgi`: FastCGI |
| `ftp` | arbitrary bytes, and its decoder fed whole and in pieces | `stdlib::ftp`: FTP |
| `geneve` | arbitrary bytes, and its decoder fed whole and in pieces | `stdlib::geneve`: Geneve |
| `git_protocol` | arbitrary bytes, and its decoder fed whole and in pieces | `stdlib::git_protocol`: The Git wire protocol |
| `grpc` | arbitrary bytes, and its decoder fed whole and in pieces | `stdlib::grpc`: gRPC |
| `imap` | arbitrary bytes, and its decoder fed whole and in pieces | `stdlib::imap`: IMAP |
| `imf` | arbitrary bytes, and its decoder fed whole and in pieces | `stdlib::imf`: Internet Message Format headers |
| `json` | arbitrary bytes, and its decoder fed whole and in pieces | `stdlib::json`: JSON |
| `kafka` | arbitrary bytes, and its decoder fed whole and in pieces | `stdlib::kafka`: Apache Kafka |
| `kerberos` | arbitrary bytes, and its decoder fed whole and in pieces | `stdlib::kerberos`: Kerberos V5 |
| `ldap` | arbitrary bytes, and its decoder fed whole and in pieces | `stdlib::ldap`: LDAP |
| `memcache` | arbitrary bytes, and its decoder fed whole and in pieces | `stdlib::memcache`: memcached |
| `mime_multipart` | arbitrary bytes, and its decoder fed whole and in pieces | `stdlib::mime_multipart`: MIME multipart bodies |
| `mongodb` | arbitrary bytes, and its decoder fed whole and in pieces | `stdlib::mongodb`: MongoDB |
| `mqtt` | arbitrary bytes, and its decoder fed whole and in pieces | `stdlib::mqtt`: MQTT 3.1.1 |
| `mysql` | arbitrary bytes, and its decoder fed whole and in pieces | `stdlib::mysql`: MySQL |
| `nbns` | arbitrary bytes, and its decoder fed whole and in pieces | `stdlib::nbns`: NetBIOS Name Service |
| `nfs` | arbitrary bytes, and its decoder fed whole and in pieces | `stdlib::nfs`: NFS version 3 and MOUNT version 3 |
| `ntp` | arbitrary bytes, and its decoder fed whole and in pieces | `stdlib::ntp`: NTP |
| `ocsp` | arbitrary bytes, and its decoder fed whole and in pieces | `stdlib::ocsp`: OCSP |
| `onc_rpc` | arbitrary bytes, and its decoder fed whole and in pieces | `stdlib::onc_rpc`: ONC RPC and XDR |
| `opcua` | arbitrary bytes, and its decoder fed whole and in pieces | `stdlib::opcua`: OPC UA over TCP |
| `postgres` | arbitrary bytes, and its decoder fed whole and in pieces | `stdlib::postgres`: PostgreSQL |
| `protobuf` | arbitrary bytes, and its decoder fed whole and in pieces | `stdlib::protobuf`: Protocol Buffers |
| `proxy_protocol` | exact wire values, header handoff and bounded codec contracts | `stdlib::proxy_protocol`: The PROXY protocol |
| `qpack` | arbitrary bytes, and its decoder fed whole and in pieces | `stdlib::qpack`: QPACK, the header compression of HTTP/3 |
| `quic` | arbitrary bytes, and its decoder fed whole and in pieces | `stdlib::quic`: QUIC |
| `resp` | arbitrary bytes, and its decoder fed whole and in pieces | `stdlib::resp`: RESP, the Redis protocol |
| `rfb` | exact wire values, session modes and bounded codec contracts | `stdlib::rfb`: RFB, the remote framebuffer protocol behind VNC |
| `rtp` | arbitrary bytes, and its decoder fed whole and in pieces | `stdlib::rtp`: RTP and RTCP |
| `rtsp` | arbitrary bytes, and its decoder fed whole and in pieces | `stdlib::rtsp`: RTSP |
| `sdp` | arbitrary bytes, and its decoder fed whole and in pieces | `stdlib::sdp`: SDP |
| `sftp` | arbitrary bytes, and its decoder fed whole and in pieces | `stdlib::sftp`: SFTP version 3 |
| `sip` | arbitrary bytes, and its decoder fed whole and in pieces | `stdlib::sip`: SIP |
| `snmp` | arbitrary bytes, and its decoder fed whole and in pieces | `stdlib::snmp`: SNMP v1 and v2c |
| `socks` | exact wire values, session modes and bounded codec contracts | `stdlib::socks`: SOCKS4, SOCKS4a and SOCKS5 |
| `spnego` | arbitrary bytes, and its decoder fed whole and in pieces | `stdlib::spnego`: SPNEGO |
| `ssh` | arbitrary bytes, and its decoder fed whole and in pieces | `stdlib::ssh`: The SSH transport layer before encryption |
| `stun` | arbitrary bytes, and its decoder fed whole and in pieces | `stdlib::stun`: STUN |
| `syslog` | arbitrary bytes, and its decoder fed whole and in pieces | `stdlib::syslog`: Syslog |
| `telnet` | arbitrary bytes, and its decoder fed whole and in pieces | `stdlib::telnet`: Telnet |
| `tftp` | arbitrary bytes, and its decoder fed whole and in pieces | `stdlib::tftp`: TFTP |
| `urlencoded_form` | arbitrary bytes, and its decoder fed whole and in pieces | `stdlib::urlencoded_form`: application/x-www-form-urlencoded |
| `vxlan` | arbitrary bytes, and its decoder fed whole and in pieces | `stdlib::vxlan`: VXLAN and VXLAN-GPE |
| `websocket` | arbitrary bytes, and its decoder fed whole and in pieces | `stdlib::websocket`: WebSocket (RFC 6455) |
| `x509` | arbitrary bytes, and its decoder fed whole and in pieces | `stdlib::x509`: X.509 certificates and CRLs |
| `xml` | arbitrary bytes, and its decoder fed whole and in pieces | `stdlib::xml`: XML 1.0 |

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
