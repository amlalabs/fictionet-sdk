//! The standard library: everything in Fictionet that knows about
//! networking.
//!
//! The core of Fictionet only moves packets between [`Interface`](fictionet::Interface)s. It
//! never reads them. This module adds everything that does: IP addresses,
//! routing, TCP and UDP, TLS, DNS, services, and the protocols they
//! speak. Read it once you have a world running and want to give the
//! sandbox something to talk to. [The catalog](#the-catalog) at the end
//! lists every protocol module and what each can do.
//!
//! [`httpd`]: https://docs.rs/fictionet/latest/fictionet/stdlib/httpd/index.html
//!
//! [`web`]: https://docs.rs/fictionet/latest/fictionet/stdlib/web/index.html
//!
//! # What you build with it
//!
//! A world is a network of small pieces joined by interfaces. The pieces
//! you use most are:
//!
//! - **Machines.** A machine is one IP address on the simulated network. You
//!   build one from an interface: [`ip::split_protocols`] splits its packets
//!   by protocol, and [`tcp::endpoint`] and [`udp::endpoint`] give the TCP
//!   and UDP parts listeners, connections and sockets.
//! - **Routes.** [`route::router`] forwards packets between routes by
//!   destination address. [`route::lan`] joins machines on one IP subnet,
//!   floods broadcast and multicast traffic to its members, and hands
//!   packets for other subnets to a gateway.
//! - **Links.** [`delay`] and [`bottleneck`] sit on an interface and change
//!   how its packets travel, as a slow or distant link would. [`filter`]
//!   shows each packet to your code, which can drop it.
//! - **Protocols.** Each protocol is a module written with no I/O: types
//!   for its messages and a framer for its byte stream, built on the tools
//!   in [`codec`]. [Protocols](#protocols) explains the shape they share.
//! - **Services.** A [`serve::Service`] is the server side of one protocol
//!   for one connection, written with no I/O. [`serve::connection`] and
//!   [`serve::listen`] run it over a connection or a listener. HTTP is one
//!   ([`httpd`](https://docs.rs/fictionet/latest/fictionet/stdlib/httpd/index.html)). Every service records what it sees as
//!   [events](fictionet::events) in the run's one log.
//! - **Networks.** [`net::Net`] builds all of the above for you: the
//!   sandboxes' subnet, DNS, addresses, a router, one machine per address,
//!   and each host's services. [`web::Sites`](https://docs.rs/fictionet/latest/fictionet/stdlib/web/struct.Sites.html) is a preset on it for a world
//!   of websites. Start there.
//!
//! Every piece is ordinary code built from the same public items, so you
//! can wire a network by hand when `Net` does not fit. To put a link in
//! front of every sandbox, wrap the sandboxes with
//! [`Attachments::map`](fictionet::Attachments::map). The
//! [recipes](fictionet::recipes) show both ways, with commands to run.
//!
//! # Three kinds of functions
//!
//! Every function in the stdlib is one of three kinds. The kind tells you
//! whether it takes a [`Cx`](fictionet::Cx), whether you `.await` it, and whether anything
//! keeps running after it returns.
//!
//! **Functions that start a task.** These take a [`&Cx`](fictionet::Cx) and one or more
//! [`Interface`](fictionet::Interface)s. They start a background task that keeps moving packets,
//! and return immediately, usually with new interfaces or a handle. You do
//! not `.await` them. The task belongs to the caller's
//! [region](fictionet::Cx#regions), so it stops when the region is cancelled. It also
//! stops when it has nothing left to do, which depends on the function:
//!
//! - [`delay`], [`bottleneck`] and [`filter`] stop when either of their
//!   interfaces closes.
//! - The splits in [`ip`] stop when the interface they split closes, or when
//!   all of the interfaces they returned have closed.
//! - [`route::router`] stops when the last of its interfaces has closed and
//!   no [`Router`](route::Router) handle is left to add more.
//! - [`route::lan`] stops when its members and gateway have all closed and
//!   no [`Lan`](route::Lan) handle is left to add more.
//! - [`tcp::endpoint`] and [`udp::endpoint`] stop when their interface
//!   closes.
//!
//! [`net::Net::start`] and [`web::Sites::start`](https://docs.rs/fictionet/latest/fictionet/stdlib/web/struct.Sites.html#method.start) start many tasks: one for
//! each part of the network they build. Each task yields after at most 64
//! packets in a row, so a busy interface cannot starve the rest of the run
//! (see [`Cx::yield_now`](fictionet::Cx::yield_now)).
//!
//! | Function | Takes | Gives back |
//! |---|---|---|
//! | [`delay`] | an interface | the same packets, later |
//! | [`bottleneck`] | an interface | the same packets, at most a given rate, with a queue that drops when full |
//! | [`filter`] | an interface, and a callback | the packets the callback keeps |
//! | [`ip::split_versions`] | an interface | IPv4, IPv6 and other packets, split apart |
//! | [`ip::split_protocols`] | an interface | TCP, UDP, ICMP and other packets, split apart |
//! | [`route::router`] | many interfaces with prefixes | a handle for adding routes later; it forwards between them |
//! | [`route::lan`] | one IP subnet | a handle for adding members and a gateway; it forwards unicast and floods broadcast and multicast |
//! | [`tcp::endpoint`] | TCP packets and an address | listeners and connections |
//! | [`udp::endpoint`] | UDP packets and an address | sockets |
//! | [`net::Net::start`] | the attachments, and the hosts with their services | nothing: it builds DNS, routing, machines and every service |
//! | [`web::Sites::start`](https://docs.rs/fictionet/latest/fictionet/stdlib/web/struct.Sites.html#method.start) | the attachments, and a callback that gives the site for a hostname | nothing: it builds DNS, routing, machines, TLS and HTTP |
//! | [`serve::listen`] | a listener, and a function that makes a service | the accepting task |
//!
//! **Functions you await.** These are `async`. They take `&Cx`, as every
//! wait in Fictionet does, and run inside the task that awaits them. They
//! start no task of their own. When the caller's region is cancelled, they
//! return early with `Err`: [`Cancelled`](fictionet::Cancelled), or their error
//! type's `Cancelled` variant, such as [`ConnError::Cancelled`]. Examples are
//! [`tls::server`], [`tcp::Listener::accept`] and [`ConnectionExt::read`].
//!
//! **Plain functions.** These read or build values. They never wait, take
//! no context, and start nothing. Examples are [`icmp::echo_reply`], parsing
//! a [`Prefix`](route::Prefix), and everything in [`dns`]. A builder such as
//! [`tls::config_builder`] takes a `Cx` only to read its clock and random
//! numbers. It never waits and starts nothing either.
//!
//! # A small example
//!
//! This world gives the sandbox named `agent` a 50 ms link, and puts one
//! machine at `10.0.0.1` behind it that accepts TCP connections on port 80.
//! First, `get` waits for the sandbox to attach. The next three calls start
//! tasks and return immediately. Then `accept` waits for each connection.
//!
//! ```
//! use fictionet::{Attachments, Cx, Result, stdlib, time::ms};
//! use fictionet::stdlib::{ip, tcp};
//!
//! async fn world(fcx: Cx, mut attachments: Attachments) -> Result {
//!     let agent = attachments.get(&fcx, "agent").await?;
//!     let link = stdlib::delay(&fcx, ms(50), agent);
//!     let (tcp, _udp, _icmp, _other) = ip::split_protocols(&fcx, link);
//!     let machine = tcp::endpoint(&fcx, tcp, "10.0.0.1".parse()?);
//!     let mut listener = machine.listen(80)?;
//!     while let Ok(conn) = listener.accept(&fcx).await {
//!         // serve `conn`, usually in a task of its own
//!         drop(conn);
//!     }
//!     Ok(())
//! }
//! ```
//!
//! The sandbox here talks to one machine directly, with no router. Every
//! packet it sends goes to that machine, which drops any packet not
//! addressed to `10.0.0.1`. A real world puts a [`route::router`] between
//! them, as [`route`] shows.
//!
//! # Protocols
//!
//! Every protocol module has the same shape, and none of them does I/O.
//! A message type implements [`codec::Wire`]: `parse` reads one complete
//! value from a slice, and `write` appends the value's bytes. A framer
//! implements [`codec::Decode`]: it is given the unread bytes of a stream
//! and cuts out the next item, such as a frame or a command, and keeps no
//! input of its own. [`codec::Stream`] owns the input and drives a framer,
//! so the same framer serves a live connection, a unit test, a fuzz target
//! and a packet capture. Some modules add a state machine for one side of
//! a conversation (a session, an exchange, an order book), driven by the
//! caller the same way: items in, bytes and events out.
//!
//! Three layers put a protocol on the network. A [`serve::Service`] joins
//! a framer to a server's replies and the facts it records, and
//! [`serve::connection`] runs it over a connection. A [`net::Host`] puts the
//! service on a port of a machine with a name and an address. To show a
//! protocol's items in the dashboard and in captures, implement
//! [`Present`](fictionet::observe::Present) for its framer and add it to the
//! observe [`Registry`](fictionet::observe::Registry). The guide
//! `docs/observe-protocols.md` in the repository walks through it.
//!
//! ## Changing a protocol by copying it
//!
//! Every file in `src/stdlib/` uses only public `fictionet::` items. The crate
//! root's `extern crate self as fictionet` makes those imports work here and
//! in your crate. Copy a file, edit it, and use it through the public traits.
//! `tests/copy_and_own` compiles the files in a separate crate. Optional
//! code uses the SDK's feature-selection macros, so a copied file needs
//! no matching Cargo features in the consuming crate.
//!
//! For a Modbus gateway that accepts a nonzero protocol identifier, copy
//! `src/stdlib/modbus.rs` into your crate and remove the two protocol-identifier
//! checks in `Frame::parse_prefix`. Implement a [`serve::Service`] whose decoder
//! is `codec::Frames<modbus::Frame>` from that copy, and install it with
//! [`net::Host::tcp`]. Fault plans and transcripts use the same service driver.
//! Register a presenter using the copied parser in the dashboard's
//! [`Registry`](fictionet::observe::Registry), then call
//! [`Cx::observe_protocols`](fictionet::Cx::observe_protocols) before observing.
//! `examples/custom_protocol` runs this gateway on a [`net::Net`] and reads a
//! register using a request with a nonzero protocol identifier.
//!
//! A module can also be generated from a schema; see
//! [code generation](https://github.com/amlalabs/fictionet-sdk/blob/main/docs/codegen.md).
//!
//! # The catalog
//!
//! One row per module. The columns:
//!
//! - **Wire**: message types that implement [`codec::Wire`].
//! - **Decode**: [`codec::Frames<T>`] for a [`codec::Prefixed`] wire value,
//!   or a protocol decoder such as `Messages` or `Commands` that implements
//!   [`codec::Decode`] and keeps state or yields a different item.
//! - **State**: a caller-driven state machine for one side of a
//!   conversation, by name.
//! - **Service**: a type that implements [`serve::Service`], ready for a
//!   [`net::Host`] port.
//! - **Observe**: how the dashboard and captures show the protocol.
//!   `built in` means the default observe registry decodes it, with a
//!   presenter in [`observe`](fictionet::observe). Presenters live there, not
//!   in the protocol's module, so a copied module carries no observe code.
//! - **Fuzz**: the module has a fuzz target in `fuzz/`. CI builds every
//!   target on pushes and pull requests. Nightly and manual runs also run
//!   each target for 60 seconds.
//! - **Copy**: `tests/copy_and_own` compiles the file as a module of a
//!   separate crate, as a user's copy would be.
//!
//! `tests/stdlib_catalog.rs` checks every column against the code, so the
//! table cannot drift. A new module gets a row here and its own module
//! docs, and nothing on this page or the crate root.
//!
//! | Module | What it is | Wire | Decode | State | Service | Observe | Fuzz | Copy |
//! |---|---|---|---|---|---|---|---|---|
//! | [`amqp`] | AMQP 0-9-1 frames, methods, field tables and content headers. | yes | yes |  |  |  | yes | yes |
//! | [`asn1`] | ASN.1 BER and DER tags, lengths and values, the base of LDAP, SNMP, Kerberos and X.509. | yes | yes |  |  |  | yes | yes |
//! | [`bacnet`] | BACnet/IP: BVLC messages, NPDUs, APDUs and application-tagged values. | yes | yes |  |  |  | yes | yes |
//! | [`bgp`] | BGP-4 messages from OPEN to ROUTE-REFRESH, with path attributes and prefixes. | yes | yes |  |  |  | yes | yes |
//! | [`ca`] | Seeded certificate authorities and server leaves for simulated TLS sites. |  |  |  |  |  |  | yes |
//! | [`cboe_boe`] | Cboe Binary Order Entry: every session and order message, a member's and an exchange's session, and an order tracker. | yes | yes | `Client`, `Server`, `Exchange` |  |  | yes | yes |
//! | [`cboe_pitch`] | Cboe Multicast PITCH: sequenced units, every message, a gap detector per unit and a bounded order book. | yes | yes | `GapDetector`, `Book` |  |  | yes | yes |
//! | [`cme_mdp3`] | CME MDP 3.0 market data: generated messages for SBE schema 1 version 13 (20230411), plus packet framing. | yes | yes |  |  |  | yes | yes |
//! | [`coap`] | CoAP messages over UDP and frames over TCP, with block-wise reassembly. | yes | yes |  |  |  | yes | yes |
//! | [`codec`] | The tools every protocol is built on, none of them doing I/O: `Decode`, `Wire`, `Stream`, combinators, a recorder and fault injection. | yes | yes |  |  |  | yes | yes |
//! | [`cotp`] | ISO transport on TCP: TPKT and COTP packets, with segment reassembly. | yes |  |  |  |  | yes | yes |
//! | [`dcerpc`] | DCE/RPC over connections: bind, request and response PDUs, with fragment reassembly. | yes | yes |  |  |  | yes | yes |
//! | [`dhcp`] | DHCP messages, used by `Net` and by the DHCP server attach runs for a VM. | yes |  |  |  | built in | yes | yes |
//! | [`dhcpv6`] | DHCPv6 client, server and relay messages and their options. | yes | yes |  |  |  | yes | yes |
//! | [`diameter`] | Diameter messages and AVPs. | yes | yes |  |  |  | yes | yes |
//! | [`dnp3`] | DNP3 link frames, transport segments and application headers. | yes | yes |  |  |  | yes | yes |
//! | [`dns`] | DNS messages: the `hickory-proto` crate, re-exported. `Net` runs the server. |  |  |  |  | built in | yes | yes |
//! | [`dtls`] | DTLS records and handshake messages, with fragment reassembly and no cryptography. | yes |  |  |  |  | yes | yes |
//! | [`enip`] | EtherNet/IP and CIP: the encapsulation layer, the common packet format and message router messages. | yes | yes |  |  |  | yes | yes |
//! | [`fast`] | FAST 1.1, the compression of FIX market data: templates, dictionaries, a decoder and an encoder. | yes | yes |  |  |  | yes | yes |
//! | [`fastcgi`] | FastCGI records, name-value pairs and whole requests and responses, with request bookkeeping for both sides. | yes | yes | `Client`, `Server` |  |  | yes | yes |
//! | [`fix`] | FIX tag=value messages, repeating groups and a caller-driven session for either side. | yes | yes | `Session` |  |  | yes | yes |
//! | [`ftp`] | FTP control connection: commands, replies and features. | yes | yes |  |  |  | yes | yes |
//! | [`geneve`] | Geneve tunnel headers and their options. | yes |  |  |  |  | yes | yes |
//! | [`git_protocol`] | The Git wire protocol: pkt-lines, requests, ref advertisements, negotiation and side-band demultiplexing. | yes | yes |  |  |  | yes | yes |
//! | [`gre`] | GRE headers, PPTP's included. | yes |  |  |  |  | yes | yes |
//! | [`grpc`] | gRPC over HTTP/2: message framing, status codes, timeouts and the header rules a server follows. | yes | yes |  |  |  | yes | yes |
//! | [`hpack`] | HPACK header compression for HTTP/2: fields, blocks, the dynamic table and an encoder. | yes |  |  |  |  | yes | yes |
//! | [`http1`] | HTTP/1.0 and 1.1 wire messages and stream framing, with no non-empty trailers, chunk extensions, or Upgrade negotiation. | yes | yes |  |  | built in | yes | yes |
//! | [`http2`] | HTTP/2 frames, directional state and capture decoding. Live serving uses hyper in `httpd`. | yes | yes | `Session` |  | built in | yes | yes |
//! | [`http3`] | HTTP/3 frames, field sections and caller-driven stream state, with no QUIC transport or HTTP service. | yes | yes | `Session` |  |  | yes | yes |
//! | [`httpd`] | HTTP serving: the `Http1` service, hyper for HTTP/2 and Upgrade, handlers, tower integration, and virtual hosts. |  |  |  | `Http1` |  |  | yes |
//! | [`huffman`] | The RFC 7541 Huffman code that HPACK and QPACK share. | yes |  |  |  |  | yes | yes |
//! | [`icmp`] | ICMP echo replies and error messages, for machines built by hand. |  |  |  |  |  |  | yes |
//! | [`iec104`] | IEC 60870-5-104 APDUs and ASDU headers. | yes | yes |  |  |  | yes | yes |
//! | [`igmp`] | IGMP membership queries and reports, versions 1 to 3. | yes |  |  |  |  | yes | yes |
//! | [`ike`] | IKEv2 message structure and payloads, with no cryptography. | yes |  |  |  |  | yes | yes |
//! | [`imap`] | IMAP commands and responses. | yes | yes |  |  |  | yes | yes |
//! | [`imf`] | Internet Message Format mail headers: fields, addresses, dates, message IDs and encoded words. | yes | yes |  |  |  | yes | yes |
//! | [`ip`] | IP headers read, checked and built, checksums, fragment reassembly, and sorting packets by version and protocol. |  |  |  |  |  | yes | yes |
//! | [`ipp`] | IPP, the Internet Printing Protocol: requests, responses and their attribute groups. | yes | yes |  |  |  | yes | yes |
//! | [`ipsec`] | IPsec ESP and AH wire headers, with no cryptography or security association state. | yes |  |  |  |  | yes | yes |
//! | [`itch`] | Nasdaq TotalView-ITCH 5.0: every message, a framer and a bounded order book. | yes | yes | `Book` |  |  | yes | yes |
//! | [`json`] | JSON text to a tree of values and back, under limits. | yes | yes |  |  |  | yes | yes |
//! | [`json_schema`] | Checked JSON schemas: compile one, validate values against it, and generate values from it. |  |  |  |  |  | yes | yes |
//! | [`jsonrpc`] | JSON-RPC 2.0 requests, notifications, responses and batches, over lines or HTTP bodies. | yes | yes |  |  |  | yes | yes |
//! | [`kafka`] | Apache Kafka frames, headers, and the ApiVersions and Metadata messages. | yes | yes |  |  |  | yes | yes |
//! | [`kerberos`] | Kerberos V5 messages between a client, a KDC and a service, with no cryptography. | yes | yes |  |  |  | yes | yes |
//! | [`l2tp`] | L2TP headers, control messages and AVPs, versions 2 and 3. | yes |  |  |  |  | yes | yes |
//! | [`ldap`] | LDAP wire messages, search filters and distinguished names, with no session or service. | yes | yes |  |  |  | yes | yes |
//! | [`memcache`] | memcached's text and binary protocols and UDP frames. | yes | yes |  |  |  | yes | yes |
//! | [`mime_multipart`] | MIME multipart bodies, split into parts and written back. | yes | yes |  |  |  | yes | yes |
//! | [`modbus`] | Modbus/TCP frames, requests and responses. The `custom_protocol` example copies it. | yes | yes |  |  | built in | yes | yes |
//! | [`moldudp64`] | MoldUDP64 packets and message blocks, a receiver with gap recovery and a retransmission server. | yes | yes | `Receiver`, `Retransmitter` |  |  | yes | yes |
//! | [`mongodb`] | MongoDB BSON documents and wire protocol messages. | yes | yes |  |  |  | yes | yes |
//! | [`mqtt`] | MQTT 3.1.1 control packets and topic matching. | yes | yes |  |  |  | yes | yes |
//! | [`mysql`] | The MySQL client/server protocol: packets, the handshake, commands and result sets. | yes | yes | `ResultReader` |  |  | yes | yes |
//! | [`nbdgm`] | NetBIOS Datagram Service packets, with fragment reassembly and `nbns` name encoding. | yes |  |  |  |  | yes | yes |
//! | [`nbns`] | NetBIOS Name Service queries, registrations and node status, with reply helpers. | yes |  |  |  |  | yes | yes |
//! | [`nbss`] | NetBIOS Session Service packets, using `nbns` name encoding. | yes | yes |  |  |  | yes | yes |
//! | [`net`] | A network of hosts and services in a few lines: the sandboxes' subnet, DHCP, DNS, a router, machines, LANs and each host's services. |  |  |  |  |  |  | yes |
//! | [`nfs`] | NFS version 3 and MOUNT version 3: the arguments and results of every procedure, over `onc_rpc`. |  |  |  |  |  | yes | yes |
//! | [`ntlmssp`] | NTLM NEGOTIATE, CHALLENGE and AUTHENTICATE wire messages, with no cryptography or authentication session. | yes |  |  |  |  | yes | yes |
//! | [`ntp`] | NTP time packets, with a server reply helper. | yes |  |  |  |  | yes | yes |
//! | [`ocsp`] | OCSP certificate status wire requests and responses, with no signing or signature verification. | yes | yes |  |  |  | yes | yes |
//! | [`onc_rpc`] | ONC RPC calls and replies, XDR reading and writing, and TCP record marking. | yes | yes |  |  |  | yes | yes |
//! | [`opcua`] | OPC UA binary transport, built-in types and open/close secure channel bodies for policy None, with no cryptography or session. | yes | yes |  |  |  | yes | yes |
//! | [`openvpn`] | OpenVPN control and data wire packets over UDP and TCP, with no cryptography or tunnel session. | yes | yes |  |  |  | yes | yes |
//! | [`ospf`] | OSPFv2 and OSPFv3 packets and LSAs. | yes |  |  |  |  | yes | yes |
//! | [`ouch`] | Nasdaq OUCH 5.0 order entry messages and an exchange-side state machine that tracks open orders. | yes |  | `Exchange` |  |  | yes | yes |
//! | [`pcp`] | PCP and NAT-PMP port mapping requests and responses, and the version negotiation between them. | yes |  |  |  |  | yes | yes |
//! | [`pim`] | PIM version 2 multicast routing messages. |  |  |  |  |  | yes | yes |
//! | [`pop3`] | POP3 commands and replies. | yes | yes |  |  |  | yes | yes |
//! | [`portmap`] | Portmapper version 2 and rpcbind versions 3 and 4 requests and results, and universal addresses. |  |  |  |  |  | yes | yes |
//! | [`ports`] | Ready-slot polling for packet interfaces. |  |  |  |  |  |  | yes |
//! | [`postgres`] | The PostgreSQL protocol, version 3: frontend and backend messages, from startup to query results. | yes | yes |  |  |  | yes | yes |
//! | [`prefix_int`] | RFC 7541 prefix integers, shared by HPACK and QPACK. | yes |  |  |  |  |  | yes |
//! | [`protobuf`] | The Protocol Buffers wire format, read and written without a schema. | yes | yes |  |  |  | yes | yes |
//! | [`proxy_protocol`] | The PROXY protocol header a proxy puts in front of a TCP connection, versions 1 and 2. | yes | yes |  |  |  | yes | yes |
//! | [`qpack`] | QPACK, HTTP/3's header compression: field sections and the encoder and decoder streams. | yes | yes |  |  |  | yes | yes |
//! | [`quic`] | QUIC packets and frames, with no cryptography. | yes |  |  |  |  | yes | yes |
//! | [`radius`] | RADIUS wire packets and attributes, with the standard attribute dictionary and no cryptography. | yes | yes |  |  |  | yes | yes |
//! | [`rdp`] | RDP connection sequence messages from MS-RDPBCGR. | yes | yes |  |  |  | yes | yes |
//! | [`resp`] | RESP, the Redis protocol, versions 2 and 3: values and commands. | yes | yes |  |  |  | yes | yes |
//! | [`rfb`] | RFB, the protocol behind VNC: the handshake and messages, and a session for either side. | yes | yes | `Client`, `Server` |  |  | yes | yes |
//! | [`rip`] | RIP and RIPng routing messages. | yes |  |  |  |  | yes | yes |
//! | [`route`] | Forwarding packets between interfaces by destination: the router and the LAN. |  |  |  |  |  |  | yes |
//! | [`rtcp`] | RTCP control packets, compound packets and feedback messages. | yes | yes |  |  |  | yes | yes |
//! | [`rtp`] | RTP media packets and their header extensions, told apart from RTCP. | yes |  |  |  |  | yes | yes |
//! | [`rtsp`] | RTSP messages and interleaved data, with transport and range headers. | yes | yes |  |  |  | yes | yes |
//! | [`sandbox`] | Client machines with DNS, TLS, and HTTP requests for lab tests. |  |  |  |  |  |  | yes |
//! | [`sbe`] | FIX Simple Binary Encoding 1.0 at run time: load a schema's XML, then read and write its messages. | yes | yes |  |  |  | yes | yes |
//! | [`sdp`] | SDP session descriptions, with ICE candidates and RTP maps. | yes | yes |  |  |  | yes | yes |
//! | [`serve`] | Services: the `Service` trait, the driver that runs one over a connection or a UDP socket, `listen`, a test harness, transcripts and fault plans. |  |  |  |  |  | yes | yes |
//! | [`session`] | Passive mechanics shared by caller-driven protocol sessions. |  |  |  |  |  |  | yes |
//! | [`sftp`] | SFTP version 3 packets, requests and responses. | yes | yes |  |  |  | yes | yes |
//! | [`sip`] | SIP messages, URIs and the headers a proxy reads. | yes | yes |  |  |  | yes | yes |
//! | [`smb2`] | SMB2 and SMB3 wire messages and compound chains, with no session, service, signing, encryption, or decompression. | yes | yes |  |  |  | yes | yes |
//! | [`smtp`] | SMTP commands, replies and DATA, with a server-side decoder that switches between them. | yes | yes |  |  |  | yes | yes |
//! | [`snmp`] | SNMP v1 and v2c messages, PDUs and OIDs, using `asn1` integer and length helpers. | yes | yes |  |  |  | yes | yes |
//! | [`socks`] | SOCKS4, SOCKS4a and SOCKS5 handshake messages and the UDP request header. | yes | yes |  |  |  | yes | yes |
//! | [`soupbintcp`] | SoupBinTCP 3.0 packets, a framer, and client and server sessions. | yes | yes | `Client`, `Server` |  |  | yes | yes |
//! | [`spnego`] | SPNEGO negotiation tokens, as HTTP Negotiate, SMB and LDAP carry them. | yes | yes |  |  |  | yes | yes |
//! | [`sse`] | Server-sent events: raw lines or dispatched events from a streaming response body, and events written back. | yes | yes |  |  |  | yes | yes |
//! | [`ssh`] | The SSH transport layer before encryption: version exchange, binary packets and the first messages. | yes | yes |  |  |  | yes | yes |
//! | [`stun`] | STUN messages and attributes, with a binding reply helper. | yes | yes |  |  |  | yes | yes |
//! | [`syslog`] | Syslog messages in the RFC 5424 and RFC 3164 formats, and RFC 6587 stream framing. | yes | yes |  |  |  | yes | yes |
//! | [`tcp`] | TCP listeners and connections for a machine on the simulated network, on smoltcp. |  |  |  |  |  | yes | yes |
//! | [`tcp_reassembly`] | TCP capture reassembly for observers: ordered bytes, gaps and end signals. |  |  |  |  |  | yes | yes |
//! | [`tds`] | TDS, the SQL Server protocol: packets, logins, SQL batches and response tokens. | yes | yes | `TokenReader` |  |  | yes | yes |
//! | [`telnet`] | Telnet data and commands, option negotiation, terminal type and window size. | yes | yes | `Negotiation` |  |  | yes | yes |
//! | [`test_support`] | Shared test data, timing and contract checks. |  | yes |  |  |  |  | yes |
//! | [`tftp`] | TFTP packets, option negotiation, and one read transfer served. | yes | yes | `ReadTransfer` |  |  | yes | yes |
//! | [`thrift`] | Apache Thrift messages and values in the binary and compact protocols, and the framed transport. | yes | yes |  |  |  | yes | yes |
//! | [`tls`] | The server side of a TLS connection, played by the world with rustls. The world picks the certificate after the client hello. |  |  |  |  | built in | yes | yes |
//! | [`tpkt`] | TPKT packets, the carrier of ISO transport on TCP. | yes | yes |  |  |  | yes | yes |
//! | [`udp`] | UDP sockets for a machine on the simulated network. |  |  |  |  |  |  | yes |
//! | [`urlencoded_form`] | application/x-www-form-urlencoded form bodies and query strings. | yes | yes |  |  |  | yes | yes |
//! | [`vrrp`] | VRRP virtual router advertisements, versions 2 and 3. |  |  |  |  |  | yes | yes |
//! | [`vxlan`] | VXLAN and VXLAN-GPE headers. | yes |  |  |  |  | yes | yes |
//! | [`wake_on_lan`] | Wake-on-LAN magic packets. | yes | yes |  |  |  | yes | yes |
//! | [`web`] | Websites by hostname: `Sites`, a preset on `Net` that builds DNS, addresses, TLS and HTTP around one callback. |  |  |  |  |  | yes | yes |
//! | [`websocket`] | WebSocket: the opening handshake, frames and messages. | yes | yes |  |  |  | yes | yes |
//! | [`whois`] | WHOIS queries and responses, with referrals. | yes | yes |  |  |  | yes | yes |
//! | [`wireguard`] | WireGuard's four message types, with no cryptography. | yes |  |  |  |  | yes | yes |
//! | [`x509`] | X.509 certificates and CRLs with PEM reading and writing, with no signing, signature verification, or trust-path validation. | yes | yes |  |  |  | yes | yes |
//! | [`xml`] | XML 1.0: a nonvalidating UTF-8 pull parser and writer, with DTD attribute defaults but no declared entity expansion. | yes | yes |  |  |  | yes | yes |
//! | [`zabbix`] | The Zabbix protocol: packets and the JSON messages of agents, senders and servers. | yes | yes |  |  |  | yes | yes |

pub mod amqp;
pub mod asn1;
pub mod bacnet;
pub mod bgp;
pub mod ca;
pub mod cboe_boe;
pub mod cboe_pitch;
mod connection;
// These docs live here, not in cme_mdp3.rs, because regenerating that file
// (BLESS_CODEGEN=1) rewrites its header.
/// CME Group MDP 3.0 market data: every message of CME's public SBE
/// schema, plus UDP packets and message framing.
///
/// The message types are generated by `fictionet-codegen sbe` from
/// `data/cme/templates_FixBinary.xml` (`mktdata`, schema id 1, version
/// 13). [`Message`](cme_mdp3::Message) reads and writes one SBE message:
/// the eight-byte message header, the template's root block, its
/// repeating groups, and its variable data. Readers skip the extra bytes
/// of longer blocks from newer senders and refuse acting versions below
/// 13. Constants, such as a price's exponent, are associated constants.
///
/// There is no feed session, recovery engine, order book, `Service` or
/// live transport. The generated part is checked against the generator in CI.
/// A copy in your crate has no such check. See
/// [code generation](https://github.com/amlalabs/fictionet-sdk/blob/main/docs/codegen.md)
/// for the generation and checking steps.
///
/// The packet layer is written by hand at the end of the file.
/// [`Packet`](cme_mdp3::Packet) is one UDP datagram: the binary packet
/// header (`MsgSeqNum` and `SendingTime`), then messages, each after a
/// two-byte `MsgSize` that counts itself. [`Messages`](cme_mdp3::Messages)
/// reads the same size-prefixed messages from a byte stream. It yields a
/// message it refuses as an `Err` item and reads on from the next size.
///
/// ```
/// use fictionet::stdlib::cme_mdp3::{AdminHeartbeat12, Message, Packet, PacketHeader};
/// use fictionet::stdlib::codec::Wire;
///
/// let packet = Packet {
///     header: PacketHeader { sequence: 1, sending_time: 1_700_000_000_000_000_000 },
///     messages: vec![Message::AdminHeartbeat12(AdminHeartbeat12 {})],
/// };
/// let bytes = packet.to_bytes()?;
/// assert_eq!(bytes.len(), 12 + 2 + 8);
/// assert_eq!(Packet::parse(&bytes)?, packet);
/// # Ok::<(), fictionet::stdlib::cme_mdp3::Error>(())
/// ```
pub mod cme_mdp3;
pub mod coap;
pub mod codec;
pub mod cotp;
pub mod dcerpc;
pub mod dhcp;
pub mod dhcpv6;
pub mod diameter;
pub mod dnp3;
pub mod dns;
pub mod dtls;
pub mod enip;
pub mod fast;
pub mod fastcgi;
pub mod fix;
pub mod ftp;
pub mod geneve;
pub mod git_protocol;
pub mod gre;
pub mod grpc;
pub mod hpack;
pub mod http1;
pub mod http2;
pub mod http3;
fictionet::cfg_std! { pub mod httpd; }
pub mod huffman;
pub mod icmp;
pub mod iec104;
pub mod igmp;
pub mod ike;
pub mod imap;
pub mod imf;
pub mod ip;
pub mod ipp;
pub mod ipsec;
pub mod itch;
pub mod json;
pub mod json_schema;
pub mod jsonrpc;
pub mod kafka;
pub mod kerberos;
pub mod l2tp;
pub mod ldap;
pub mod memcache;
pub mod mime_multipart;
pub mod modbus;
pub mod moldudp64;
pub mod mongodb;
pub mod mqtt;
pub mod mysql;
pub mod nbdgm;
pub mod nbns;
pub mod nbss;
pub mod net;
pub mod nfs;
pub mod ntlmssp;
pub mod ntp;
pub mod ocsp;
pub mod onc_rpc;
pub mod opcua;
pub mod openvpn;
pub mod ospf;
pub mod ouch;
pub mod pcp;
pub mod pim;
pub mod pop3;
pub mod portmap;
pub mod ports;
pub mod postgres;
pub mod prefix_int;
pub mod protobuf;
pub mod proxy_protocol;
pub mod qpack;
pub mod quic;
pub mod radius;
pub mod rdp;
pub mod resp;
pub mod rfb;
pub mod rip;
pub mod route;
pub mod rtcp;
pub mod rtp;
pub mod rtsp;
pub mod sandbox;
pub mod sbe;
pub mod sdp;
pub mod serve;
pub mod session;
pub mod sftp;
pub mod sip;
pub mod smb2;
pub mod smtp;
pub mod snmp;
pub mod socks;
pub mod soupbintcp;
pub mod spnego;
pub mod sse;
pub mod ssh;
pub mod stun;
pub mod syslog;
pub mod tcp;
pub mod tcp_reassembly;
pub mod tds;
pub mod telnet;
pub mod test_support;
pub mod tftp;
pub mod thrift;
pub mod tls;
pub mod tpkt;
pub mod udp;
pub mod urlencoded_form;
pub mod vrrp;
pub mod vxlan;
pub mod wake_on_lan;
fictionet::cfg_std! { pub mod web; }
pub mod websocket;
pub mod whois;
pub mod wireguard;
pub mod x509;
pub mod xml;
pub mod zabbix;

pub use connection::{Accept, Accepted, ConnError, Connection, ConnectionExt, DatagramSocket};

mod link;
pub use link::{Direction, bottleneck, delay, filter};
