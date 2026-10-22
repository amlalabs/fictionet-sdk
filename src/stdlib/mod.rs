//! The standard library: everything in Fictionet that knows about
//! networking.
//!
//! The core of Fictionet only moves packets between [`Interface`](fictionet::Interface)s. It
//! never reads them. This module adds everything that does: IP addresses,
//! routing, TCP and UDP, TLS, DNS, services, and the protocols they
//! speak. Read it once you have a world running and want to give the
//! sandbox something to talk to. [The module table](#modules) at the end
//! lists the modules and their uses.
//!
//! # What you build with it
//!
//! A world is a network of small pieces joined by interfaces. The pieces
//! you use most are:
//!
//! - **Machines.** A machine is one IP address on the simulated network. You
//!   build one from an interface:
//!   [`ip::split_protocols`](network::ip::split_protocols) splits its packets
//!   by protocol, and [`tcp::endpoint`](network::tcp::endpoint) and
//!   [`udp::endpoint`](network::udp::endpoint) give the TCP and UDP parts
//!   listeners, connections and sockets.
//! - **Routes.** [`route::router`](network::route::router) forwards packets
//!   between routes by destination address. [`route::lan`](network::route::lan)
//!   joins machines on one IP subnet, floods broadcast and multicast traffic to
//!   its members, and hands packets for other subnets to a gateway.
//! - **Links.** [`delay`](network::delay) and
//!   [`bottleneck`](network::bottleneck) sit on an interface and change how its
//!   packets travel, as a slow or distant link would.
//!   [`filter`](network::filter) shows each packet to your code, which can drop
//!   it.
//! - **Protocols.** Each protocol is a module written with no I/O: types
//!   for its messages and a framer for its byte stream, built on the tools
//!   in [`codec`]. [Protocols](#protocols) explains the shape they share.
//! - **Services.** A [`serve::Service`](services::serve::Service) is the server
//!   side of one protocol for one connection, written with no I/O.
//!   [`serve::connection`](services::serve::connection) and
//!   [`serve::listen`](services::serve::listen) run it over a connection or a
//!   listener. HTTP is one ([`httpd`](web::httpd)). Services emit
//!   [events](fictionet::events) to optional observers installed by the integrator.
//! - **Networks.** [`net::Net`](world::net::Net) builds all of the above for
//!   you: the sandboxes' subnet, DNS, addresses, a router, one machine per
//!   address, and each host's services. [`web::Sites`] is a preset on it for a
//!   world of websites. Start there.
//!
//! Every piece is ordinary code built from the same public items, so you
//! can wire a network by hand when `Net` does not fit. To put a link in
//! front of every sandbox, wrap the sandboxes with
//! [`Attachments::map`](fictionet::Attachments::map).
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
//! - [`delay`](network::delay), [`bottleneck`](network::bottleneck) and
//!   [`filter`](network::filter) stop when either of their interfaces closes.
//! - The splits in [`ip`](network::ip) stop when the interface they split
//!   closes, or when all of the interfaces they returned have closed.
//! - [`route::router`](network::route::router) stops when the last of its
//!   interfaces has closed and no [`Router`](network::route::Router) handle is
//!   left to add more.
//! - [`route::lan`](network::route::lan) stops when its members and gateway
//!   have all closed and no [`Lan`](network::route::Lan) handle is left to add
//!   more.
//! - [`tcp::endpoint`](network::tcp::endpoint) and
//!   [`udp::endpoint`](network::udp::endpoint) stop when their interface
//!   closes.
//!
//! [`net::Net::start`](world::net::Net::start) and [`web::Sites::start`] start
//! many tasks: one for each part of the network they build. Each task yields
//! after at most 64 packets in a row, so a busy interface cannot starve the
//! rest of the run (see [`Cx::yield_now`](fictionet::Cx::yield_now)).
//!
//! | Function | Takes | Gives back |
//! |---|---|---|
//! | [`delay`](network::delay) | an interface | the same packets, later |
//! | [`bottleneck`](network::bottleneck) | an interface | the same packets, at most a given rate, with a queue that drops when full |
//! | [`filter`](network::filter) | an interface, and a callback | the packets the callback keeps |
//! | [`ip::split_versions`](network::ip::split_versions) | an interface | IPv4, IPv6 and other packets, split apart |
//! | [`ip::split_protocols`](network::ip::split_protocols) | an interface | TCP, UDP, ICMP and other packets, split apart |
//! | [`route::router`](network::route::router) | many interfaces with prefixes | a handle for adding routes later; it forwards between them |
//! | [`route::lan`](network::route::lan) | one IP subnet | a handle for adding members and a gateway; it forwards unicast and floods broadcast and multicast |
//! | [`tcp::endpoint`](network::tcp::endpoint) | TCP packets and an address | listeners and connections |
//! | [`udp::endpoint`](network::udp::endpoint) | UDP packets and an address | sockets |
//! | [`net::Net::start`](world::net::Net::start) | the attachments, and the hosts with their services | nothing: it builds DNS, routing, machines and every service |
//! | [`web::Sites::start`] | the attachments, and a callback that gives the site for a hostname | nothing: it builds DNS, routing, machines, TLS and HTTP |
//! | [`serve::listen`](services::serve::listen) | a listener, and a function that makes a service | the accepting task |
//!
//! **Functions you await.** These are `async`. They take `&Cx`, as every wait
//! in Fictionet does, and run inside the task that awaits them. They start no
//! task of their own. When the caller's region is cancelled, they return early
//! with `Err`: [`Cancelled`](fictionet::Cancelled), or their error type's
//! `Cancelled` variant, such as
//! [`ConnError::Cancelled`](network::ConnError::Cancelled). Examples are
//! [`tls::server`](services::tls::server),
//! [`tcp::Listener::accept`](network::tcp::Listener::accept) and
//! [`ConnectionExt::read`](network::ConnectionExt::read).
//!
//! **Plain functions.** These read or build values. They never wait, take no
//! context, and start nothing. Examples are
//! [`icmp::echo_reply`](network::icmp::echo_reply), parsing a
//! [`Prefix`](network::route::Prefix), and everything in
//! [`dns`](protocols::dns). A builder such as
//! [`tls::config_builder`](services::tls::config_builder) takes a `Cx` only to
//! read its clock and random numbers. It never waits and starts nothing either.
//!
//! # A small example
//!
//! This world gives the sandbox named `agent` a 50 ms link, and puts one
//! machine at `10.0.0.1` behind it that accepts TCP connections on port 80.
//! First, `get` waits for the sandbox to attach. The next three calls start
//! tasks and return immediately. Then `accept` waits for each connection.
//!
//! ```
//! use fictionet::{Attachments, Cx, Result, time::ms};
//! use fictionet::stdlib::network::{self, ip, tcp};
//!
//! async fn world(fcx: Cx, mut attachments: Attachments) -> Result {
//!     let agent = attachments.get(&fcx, "agent").await?;
//!     let link = network::delay(&fcx, ms(50), agent);
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
//! The sandbox here talks to one machine directly, with no router. Every packet
//! it sends goes to that machine, which drops any packet not addressed to
//! `10.0.0.1`. A real world puts a [`route::router`](network::route::router)
//! between them, as [`route`](network::route) shows.
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
//! Three layers put a protocol on the network. A
//! [`serve::Service`](services::serve::Service) joins a framer to a server's
//! replies and the facts it records, and
//! [`serve::connection`](services::serve::connection) runs it over a
//! connection. A [`net::Host`](world::net::Host) puts the service on a port of
//! a machine with a name and an address. Capture presentation belongs to
//! [Fictionet Observe](../../fictionet_observe/index.html). Its `Present`
//! adapters use these codecs, and its `Registry` selects adapters for traffic.
//! Wire parsing, serving and capture presentation are
//! separate responsibilities. A codec does not imply a live server or a
//! built-in capture presenter. See the codec's [serving and capture
//! boundaries](codec#serving-and-capture-boundaries) for runtime support and
//! observation policies.
//!
//! ## Adding a protocol
//!
//! Follow the codec's [errors and names](codec#errors-and-names-in-a-codec-module).
//! A new protocol needs these entries:
//!
//! 1. Add `src/stdlib/protocols/<name>.rs`. Document
//!    the supported wire format, limits and caller responsibilities, with
//!    runnable doctests. Implement [`codec::Wire`] for complete values and
//!    [`codec::Prefixed`] or [`codec::Decode`] where stream framing is needed.
//!    Check decoder contracts with [`test_support::contract`]. A large
//!    protocol may be a directory whose `mod.rs` declares private child
//!    modules and re-exports their items, as `protocols/smb2/` does.
//! 2. Declare it with `pub mod` in `src/stdlib/protocols/mod.rs`, and add a
//!    one-line description to the [module table](#protocol-modules).
//! 3. Add `fuzz/fuzz_targets/<name>.rs` and a `[[bin]]` entry in `fuzz/Cargo.toml`.
//!
//! A service and a presenter are optional additions. A service owns replies,
//! connection state and events; install it on a [`net::Host`](world::net::Host)
//! port. Capture adapters and their registration belong to the companion.
//! Set `fictionet_observe::DashboardOptions::protocols` before installing the
//! observer to use a custom `Registry`. See the
//! [companion's protocol guide](../../fictionet_observe/index.html#user-protocols).
//!
//! ## Changing a protocol by copying it
//!
//! Copy the code you want to change into your crate and use it through the
//! SDK's public traits. Keep the helpers and shared types it depends on.
//! Crate-private helpers and shared types are fine; individual files need
//! not compile on their own.
//!
//! For a Modbus gateway that accepts a nonzero protocol identifier, copy
//! `src/stdlib/protocols/modbus.rs` into your crate and remove the two
//! protocol-identifier checks in `Frame::parse_prefix`. Implement a
//! [`serve::Service`](services::serve::Service) whose decoder is
//! `codec::Frames<modbus::Frame>` from that copy, and install it with
//! [`net::Host::tcp`](world::net::Host::tcp). Fault plans and transcripts use
//! the same service driver. A companion `Present` adapter can use the copied
//! parser. Register it in `fictionet_observe::Registry` and set
//! `fictionet_observe::DashboardOptions::protocols` before installing the observer.
//!
//! A module can also be generated from a schema; see
//! [code generation](https://github.com/amlalabs/fictionet-sdk/blob/main/docs/codegen.md).
//!
//! # Modules
//!
//! The stdlib's folders are its layers, and each layer is a module:
//!
//! | Module | Description |
//! | --- | --- |
//! | [`codec`] | Wire traits, streaming decoders, combinators, recording and faults. |
//! | [`network`] | IP packets, routing, links, TCP and UDP. |
//! | [`protocols`] | Message types and framers for each protocol, with no I/O. |
//! | [`services`] | Service drivers, TLS servers and certificate authorities. |
//! | [`test_support`] | Test data, scripted decoders and behavior assertions. |
//! | [`web`] | Websites by hostname, and HTTP serving. |
//! | [`world`] | Networks of hosts, and simulated clients. |
//!
//! ## Network modules
//!
//! | Module | Description |
//! | --- | --- |
//! | [`network::ethernet`] | Ethernet frames to IP packets and back for a VM's network card, with ARP, neighbor discovery and the frame stream. |
//! | [`network::icmp`] | ICMP echo replies and error messages. |
//! | [`network::ip`] | IP packets, checksums, fragment reassembly and protocol splitting. |
//! | [`network::ports`] | Ready-slot polling for packet interfaces. |
//! | [`network::route`] | Packet routing and LAN forwarding. |
//! | [`network::tcp`] | Simulated TCP listeners and connections using smoltcp. |
//! | [`network::udp`] | UDP sockets, datagram parsing and encoding. |
//!
//! [`network`] itself holds the links ([`delay`](network::delay),
//! [`bottleneck`](network::bottleneck) and [`filter`](network::filter)) and the
//! [`Connection`](network::Connection) traits that TCP, TLS and HTTP share.
//!
//! ## Protocol modules
//!
//! | Module | Description |
//! | --- | --- |
//! | [`protocols::amqp`] | AMQP 0-9-1 frames, methods, field tables and content headers. |
//! | [`protocols::asn1`] | ASN.1 BER and DER tags, lengths and values. |
//! | [`protocols::bacnet`] | BACnet/IP messages and application values. |
//! | [`protocols::bgp`] | BGP-4 messages, path attributes and prefixes. |
//! | [`protocols::book_levels`] | Quantity and order-count aggregates for an order book. |
//! | [`protocols::cboe_boe`] | Cboe Binary Order Entry messages, sessions and order tracking. |
//! | [`protocols::cboe_pitch`] | Cboe Multicast PITCH messages, gap detection and order books. |
//! | [`protocols::cme_mdp3`] | CME MDP 3.0 market data messages and packet framing. |
//! | [`protocols::coap`] | CoAP messages, stream framing and block reassembly. |
//! | [`protocols::cotp`] | ISO transport packets and segment reassembly over TCP. |
//! | [`protocols::dcerpc`] | DCE/RPC connection messages and fragment reassembly. |
//! | [`protocols::dhcp`] | DHCP messages used by networks and VM attachment. |
//! | [`protocols::dhcpv6`] | DHCPv6 client, server and relay messages. |
//! | [`protocols::diameter`] | Diameter messages and attribute-value pairs. |
//! | [`protocols::dnp3`] | DNP3 link frames, transport segments and application headers. |
//! | [`protocols::dns`] | DNS messages from the re-exported `hickory-proto` crate. |
//! | [`protocols::dtls`] | DTLS records and handshake reassembly without cryptography. |
//! | [`protocols::enip`] | EtherNet/IP encapsulation and CIP messages. |
//! | [`protocols::fast`] | FAST 1.1 templates, dictionaries, encoding and decoding. |
//! | [`protocols::fastcgi`] | FastCGI records, requests, responses and session bookkeeping. |
//! | [`protocols::fix`] | FIX messages, repeating groups and sessions. |
//! | [`protocols::ftp`] | FTP control commands, replies and features. |
//! | [`protocols::geneve`] | Geneve tunnel headers and options. |
//! | [`protocols::git_protocol`] | Git wire messages, negotiation and side-band streams. |
//! | [`protocols::gre`] | GRE and PPTP tunnel headers. |
//! | [`protocols::grpc`] | gRPC message framing, status codes, timeouts and headers. |
//! | [`protocols::hpack`] | HTTP/2 header compression. |
//! | [`protocols::http1`] | HTTP/1.0 and HTTP/1.1 wire messages and stream framing. |
//! | [`protocols::http2`] | HTTP/2 frames, directional state and capture decoding. |
//! | [`protocols::http3`] | HTTP/3 frames, headers and stream state without QUIC transport. |
//! | [`protocols::huffman`] | The Huffman code shared by HPACK and QPACK. |
//! | [`protocols::iec104`] | IEC 60870-5-104 APDUs and ASDU headers. |
//! | [`protocols::igmp`] | IGMP membership queries and reports. |
//! | [`protocols::ike`] | IKEv2 messages and payloads without cryptography. |
//! | [`protocols::imap`] | IMAP commands and responses. |
//! | [`protocols::imf`] | Internet mail headers, addresses, dates and encoded words. |
//! | [`protocols::ipp`] | Internet Printing Protocol requests, responses and attributes. |
//! | [`protocols::ipsec`] | IPsec ESP and AH headers without cryptography. |
//! | [`protocols::itch`] | Nasdaq TotalView-ITCH messages, framing and order books. |
//! | [`protocols::json`] | Bounded JSON parsing and writing. |
//! | [`protocols::json_schema`] | JSON schema compilation, validation and value generation. |
//! | [`protocols::jsonrpc`] | JSON-RPC requests, notifications, responses and batches. |
//! | [`protocols::kafka`] | Kafka framing, headers, ApiVersions and Metadata messages. |
//! | [`protocols::kerberos`] | Kerberos V5 wire messages without cryptography. |
//! | [`protocols::l2tp`] | L2TP headers, control messages and attributes. |
//! | [`protocols::ldap`] | LDAP messages, search filters and distinguished names. |
//! | [`protocols::memcache`] | Memcached text and binary messages and UDP framing. |
//! | [`protocols::mime_multipart`] | MIME multipart body parsing and writing. |
//! | [`protocols::modbus`] | Modbus/TCP frames, requests and responses. |
//! | [`protocols::moldudp64`] | MoldUDP64 packets, gap recovery and retransmission. |
//! | [`protocols::mongodb`] | MongoDB BSON documents and wire messages. |
//! | [`protocols::mqtt`] | MQTT 3.1.1 packets and topic matching. |
//! | [`protocols::mysql`] | MySQL packets, handshakes, commands and result sets. |
//! | [`protocols::nbdgm`] | NetBIOS datagrams and fragment reassembly. |
//! | [`protocols::nbns`] | NetBIOS name queries, registration and node status. |
//! | [`protocols::nbss`] | NetBIOS Session Service packets. |
//! | [`protocols::netbios`] | Shared NetBIOS name encoding and display. |
//! | [`protocols::nfs`] | NFS version 3 and MOUNT procedure arguments and results. |
//! | [`protocols::ntlmssp`] | NTLM negotiation and authentication messages without cryptography. |
//! | [`protocols::ntp`] | NTP time packets and reply helpers. |
//! | [`protocols::ocsp`] | Certificate status requests and responses without signing. |
//! | [`protocols::onc_rpc`] | ONC RPC calls, replies, XDR values and TCP record framing. |
//! | [`protocols::opcua`] | OPC UA binary transport and types without cryptography. |
//! | [`protocols::openvpn`] | OpenVPN wire packets without cryptography or tunnel sessions. |
//! | [`protocols::ospf`] | OSPFv2 and OSPFv3 packets and link-state advertisements. |
//! | [`protocols::ouch`] | Nasdaq OUCH order entry messages and exchange state. |
//! | [`protocols::pcp`] | PCP and NAT-PMP port mapping and version negotiation. |
//! | [`protocols::pim`] | PIM version 2 multicast routing messages. |
//! | [`protocols::pop3`] | POP3 commands and replies. |
//! | [`protocols::portmap`] | Portmapper and rpcbind messages and universal addresses. |
//! | [`protocols::postgres`] | PostgreSQL startup, query and result messages. |
//! | [`protocols::prefix_int`] | Prefix integers shared by HPACK and QPACK. |
//! | [`protocols::protobuf`] | Protocol Buffers wire values without a schema. |
//! | [`protocols::proxy_protocol`] | PROXY protocol headers, versions 1 and 2. |
//! | [`protocols::qpack`] | HTTP/3 header compression and encoder and decoder streams. |
//! | [`protocols::quic`] | QUIC packets and frames without cryptography. |
//! | [`protocols::radius`] | RADIUS packets and attributes without cryptography. |
//! | [`protocols::rdp`] | RDP connection sequence messages. |
//! | [`protocols::resp`] | Redis RESP values and commands, versions 2 and 3. |
//! | [`protocols::rfb`] | VNC handshakes, messages and sessions. |
//! | [`protocols::rip`] | RIP and RIPng routing messages. |
//! | [`protocols::rtcp`] | RTCP control packets and feedback. |
//! | [`protocols::rtp`] | RTP media packets and header extensions. |
//! | [`protocols::rtsp`] | RTSP messages, interleaved data and headers. |
//! | [`protocols::sbe`] | Runtime encoding and decoding from FIX SBE schemas. |
//! | [`protocols::sdp`] | SDP descriptions, ICE candidates and RTP maps. |
//! | [`protocols::session`] | Shared mechanics for caller-driven protocol sessions. |
//! | [`protocols::sftp`] | SFTP version 3 packets, requests and responses. |
//! | [`protocols::sip`] | SIP messages, URIs and proxy headers. |
//! | [`protocols::smb2`] | SMB2 and SMB3 wire messages without sessions or cryptography. |
//! | [`protocols::smtp`] | SMTP commands, replies and DATA decoding. |
//! | [`protocols::snmp`] | SNMP v1 and v2c messages, PDUs and OIDs. |
//! | [`protocols::socks`] | SOCKS handshakes and UDP request headers. |
//! | [`protocols::soupbintcp`] | SoupBinTCP packets, framing and client and server sessions. |
//! | [`protocols::spnego`] | SPNEGO negotiation tokens. |
//! | [`protocols::sse`] | Server-sent event lines, events and encoding. |
//! | [`protocols::ssh`] | SSH version exchange and transport packets before encryption. |
//! | [`protocols::stun`] | STUN messages, attributes and binding replies. |
//! | [`protocols::syslog`] | Syslog messages and stream framing. |
//! | [`protocols::tcp_reassembly`] | TCP capture reassembly, gaps and end signals. |
//! | [`protocols::tds`] | SQL Server packets, logins, batches and response tokens. |
//! | [`protocols::telnet`] | Telnet data, commands and option negotiation. |
//! | [`protocols::tftp`] | TFTP packets, options and read transfers. |
//! | [`protocols::thrift`] | Thrift binary and compact messages and framed transport. |
//! | [`protocols::tpkt`] | TPKT framing for ISO transport over TCP. |
//! | [`protocols::urlencoded_form`] | URL-encoded form bodies and query strings. |
//! | [`protocols::vrrp`] | VRRP virtual router advertisements. |
//! | [`protocols::vxlan`] | VXLAN and VXLAN-GPE headers. |
//! | [`protocols::wake_on_lan`] | Wake-on-LAN magic packets. |
//! | [`protocols::websocket`] | WebSocket handshakes, frames and messages. |
//! | [`protocols::whois`] | WHOIS queries, responses and referrals. |
//! | [`protocols::wireguard`] | WireGuard wire messages without cryptography. |
//! | [`protocols::x509`] | X.509 certificates, CRLs and PEM encoding without verification. |
//! | [`protocols::xml`] | XML parsing and writing without declared entity expansion. |
//! | [`protocols::zabbix`] | Zabbix packets and agent, sender and server messages. |
//!
//! ## Service modules
//!
//! | Module | Description |
//! | --- | --- |
//! | [`services::ca`] | Seeded certificate authorities and server certificates. |
//! | [`services::serve`] | Service drivers, listeners, transcripts and fault plans. |
//! | [`services::tls`] | Simulated TLS servers using rustls. |
//!
//! ## Web modules
//!
//! | Module | Description |
//! | --- | --- |
//! | [`web`] | Websites by hostname with DNS, TLS and HTTP. |
//! | [`web::httpd`] | HTTP serving, upgrades, handlers and virtual hosts. |
//!
//! ## World modules
//!
//! | Module | Description |
//! | --- | --- |
//! | [`world::net`] | Networks of hosts, DNS names, addresses, routes and services. |
//! | [`world::sandbox`] | Simulated clients with DNS, TLS and HTTP requests. |

pub mod codec;
pub mod network;
pub mod protocols;
pub mod services;
pub mod test_support;
fictionet::cfg_std! { pub mod web; }
pub mod world;
