<!-- Generated from catalog/stdlib.rs. Update with BLESS_STDLIB_CATALOG=1 cargo nextest run --locked --test stdlib_catalog. -->

| Module | What it is | Wire | Decode | State | Service | Observe | Fuzz | Copy |
|---|---|---|---|---|---|---|---|---|
| [`amqp`] | AMQP 0-9-1 frames, methods, field tables and content headers. | yes | yes |  |  |  | yes | yes |
| [`asn1`] | ASN.1 BER and DER tags, lengths and values, the base of LDAP, SNMP, Kerberos and X.509. | yes | yes |  |  |  | yes | yes |
| [`bacnet`] | BACnet/IP: BVLC messages, NPDUs, APDUs and application-tagged values. | yes | yes |  |  |  | yes | yes |
| [`bgp`] | BGP-4 messages from OPEN to ROUTE-REFRESH, with path attributes and prefixes. | yes | yes |  |  |  | yes | yes |
| [`book_levels`] | Ordered quantity and order-count aggregates for one side of an order book. |  |  |  |  |  |  | yes |
| [`ca`] | Seeded certificate authorities and server leaves for simulated TLS sites. |  |  |  |  |  |  | yes |
| [`cboe_boe`] | Cboe Binary Order Entry: every session and order message, a member's and an exchange's session, and an order tracker. | yes | yes | `Client`, `Server`, `Exchange` |  |  | yes | yes |
| [`cboe_pitch`] | Cboe Multicast PITCH: sequenced units, every message, a gap detector per unit and a bounded order book. | yes | yes | `GapDetector`, `Book` |  |  | yes | yes |
| [`cme_mdp3`] | CME MDP 3.0 market data: generated messages for SBE schema 1 version 13 (20230411), plus packet framing. | yes | yes |  |  |  | yes | yes |
| [`coap`] | CoAP messages over UDP and frames over TCP, with block-wise reassembly. | yes | yes |  |  |  | yes | yes |
| [`codec`] | The tools every protocol is built on, none of them doing I/O: `Decode`, `Wire`, `Stream`, combinators, a recorder and fault injection. | yes | yes |  |  |  | yes | yes |
| [`cotp`] | ISO transport on TCP: TPKT and COTP packets, with segment reassembly. | yes | yes |  |  |  | yes | yes |
| [`dcerpc`] | DCE/RPC over connections: bind, request and response PDUs, with fragment reassembly. | yes | yes |  |  |  | yes | yes |
| [`dhcp`] | DHCP messages, used by `Net` and by the DHCP server attach runs for a VM. | yes |  |  |  | built in | yes | yes |
| [`dhcpv6`] | DHCPv6 client, server and relay messages and their options. | yes | yes |  |  |  | yes | yes |
| [`diameter`] | Diameter messages and AVPs. | yes | yes |  |  |  | yes | yes |
| [`dnp3`] | DNP3 link frames, transport segments and application headers. | yes | yes |  |  |  | yes | yes |
| [`dns`] | DNS messages: the `hickory-proto` crate, re-exported. `Net` runs the server. |  |  |  |  | built in | yes | yes |
| [`dtls`] | DTLS records and handshake messages, with fragment reassembly and no cryptography. | yes |  |  |  |  | yes | yes |
| [`enip`] | EtherNet/IP and CIP: the encapsulation layer, the common packet format and message router messages. | yes | yes |  |  |  | yes | yes |
| [`fast`] | FAST 1.1, the compression of FIX market data: templates, dictionaries, a decoder and an encoder. | yes | yes |  |  |  | yes | yes |
| [`fastcgi`] | FastCGI records, name-value pairs and whole requests and responses, with request bookkeeping for both sides. | yes | yes | `Client`, `Server` |  |  | yes | yes |
| [`fix`] | FIX tag=value messages, repeating groups and a caller-driven session for either side. | yes | yes | `Session` |  |  | yes | yes |
| [`ftp`] | FTP control connection: commands, replies and features. | yes | yes |  |  |  | yes | yes |
| [`geneve`] | Geneve tunnel headers and their options. | yes |  |  |  |  | yes | yes |
| [`git_protocol`] | The Git wire protocol: pkt-lines, requests, ref advertisements, negotiation and side-band demultiplexing. | yes | yes |  |  |  | yes | yes |
| [`gre`] | GRE headers, PPTP's included. | yes |  |  |  |  | yes | yes |
| [`grpc`] | gRPC over HTTP/2: message framing, status codes, timeouts and the header rules a server follows. | yes | yes |  |  |  | yes | yes |
| [`hpack`] | HPACK header compression for HTTP/2: fields, blocks, the dynamic table and an encoder. | yes |  |  |  |  | yes | yes |
| [`http1`] | HTTP/1.0 and 1.1 wire messages and stream framing, with no non-empty trailers, chunk extensions, or Upgrade negotiation. | yes | yes |  |  | built in | yes | yes |
| [`http2`] | HTTP/2 frames, directional state and capture decoding. Live serving uses hyper in `httpd`. | yes | yes | `Session` |  | built in | yes | yes |
| [`http3`] | HTTP/3 frames, field sections and caller-driven stream state, with no QUIC transport or HTTP service. | yes | yes | `Session` |  |  | yes | yes |
| [`httpd`] | HTTP serving: `Http1`, upgrade continuations, hyper for HTTP/2 and axum upgrades, handlers, tower integration, and virtual hosts. |  |  |  | `Http1` |  |  | yes |
| [`huffman`] | The RFC 7541 Huffman code that HPACK and QPACK share. | yes |  |  |  |  | yes | yes |
| [`icmp`] | ICMP echo replies and error messages, for machines built by hand. |  |  |  |  |  |  | yes |
| [`iec104`] | IEC 60870-5-104 APDUs and ASDU headers. | yes | yes |  |  |  | yes | yes |
| [`igmp`] | IGMP membership queries and reports, versions 1 to 3. | yes |  |  |  |  | yes | yes |
| [`ike`] | IKEv2 message structure and payloads, with no cryptography. | yes |  |  |  |  | yes | yes |
| [`imap`] | IMAP commands and responses. | yes | yes |  |  |  | yes | yes |
| [`imf`] | Internet Message Format mail headers: fields, addresses, dates, message IDs and encoded words. | yes | yes |  |  |  | yes | yes |
| [`ip`] | IP headers read, checked and built, checksums, fragment reassembly, and sorting packets by version and protocol. |  |  |  |  |  | yes | yes |
| [`ipp`] | IPP, the Internet Printing Protocol: requests, responses and their attribute groups. | yes | yes |  |  |  | yes | yes |
| [`ipsec`] | IPsec ESP and AH wire headers, with no cryptography or security association state. | yes |  |  |  |  | yes | yes |
| [`itch`] | Nasdaq TotalView-ITCH 5.0: every message, a framer and a bounded order book. | yes | yes | `Book` |  |  | yes | yes |
| [`json`] | JSON text to a tree of values and back, under limits. | yes | yes |  |  |  | yes | yes |
| [`json_schema`] | Checked JSON schemas: compile one, validate values against it, and generate values from it. |  |  |  |  |  | yes | yes |
| [`jsonrpc`] | JSON-RPC 2.0 requests, notifications, responses and batches, over lines or HTTP bodies. | yes | yes |  |  |  | yes | yes |
| [`kafka`] | Apache Kafka frames, headers, and the ApiVersions and Metadata messages. | yes | yes |  |  |  | yes | yes |
| [`kerberos`] | Kerberos V5 messages between a client, a KDC and a service, with no cryptography. | yes | yes |  |  |  | yes | yes |
| [`l2tp`] | L2TP headers, control messages and AVPs, versions 2 and 3. | yes |  |  |  |  | yes | yes |
| [`ldap`] | LDAP wire messages, search filters and distinguished names, with no session or service. | yes | yes |  |  |  | yes | yes |
| [`memcache`] | memcached's text and binary protocols and UDP frames. | yes | yes |  |  |  | yes | yes |
| [`mime_multipart`] | MIME multipart bodies, split into parts and written back. | yes | yes |  |  |  | yes | yes |
| [`modbus`] | Modbus/TCP frames, requests and responses. The `custom_protocol` example copies it. | yes | yes |  |  | built in | yes | yes |
| [`moldudp64`] | MoldUDP64 packets and message blocks, a receiver with gap recovery and a retransmission server. | yes | yes | `Receiver`, `Retransmitter` |  |  | yes | yes |
| [`mongodb`] | MongoDB BSON documents and wire protocol messages. | yes | yes |  |  |  | yes | yes |
| [`mqtt`] | MQTT 3.1.1 control packets and topic matching. | yes | yes |  |  |  | yes | yes |
| [`mysql`] | The MySQL client/server protocol: packets, the handshake, commands and result sets. | yes | yes | `ResultReader` |  |  | yes | yes |
| [`nbdgm`] | NetBIOS Datagram Service packets, with fragment reassembly and `netbios` name encoding. | yes |  |  |  |  | yes | yes |
| [`nbns`] | NetBIOS Name Service queries, registrations and node status, with reply helpers. | yes |  |  |  |  | yes | yes |
| [`nbss`] | NetBIOS Session Service packets, using `netbios` name encoding. | yes | yes |  |  |  | yes | yes |
| [`net`] | A network of hosts and services in a few lines: the sandboxes' subnet, DHCP, DNS, a router, machines, LANs and each host's services. |  |  |  |  |  |  | yes |
| [`netbios`] | NetBIOS name construction, display, and uncompressed reading and writing shared by NBNS, NBDGM and NBSS. |  |  |  |  |  | yes | yes |
| [`nfs`] | NFS version 3 and MOUNT version 3: the arguments and results of every procedure, over `onc_rpc`. |  |  |  |  |  | yes | yes |
| [`ntlmssp`] | NTLM NEGOTIATE, CHALLENGE and AUTHENTICATE wire messages, with no cryptography or authentication session. | yes |  |  |  |  | yes | yes |
| [`ntp`] | NTP time packets, with a server reply helper. | yes |  |  |  |  | yes | yes |
| [`ocsp`] | OCSP certificate status wire requests and responses, with no signing or signature verification. | yes | yes |  |  |  | yes | yes |
| [`onc_rpc`] | ONC RPC calls and replies, XDR reading and writing, and TCP record marking. | yes | yes |  |  |  | yes | yes |
| [`opcua`] | OPC UA binary transport, built-in types and open/close secure channel bodies for policy None, with no cryptography or session. | yes | yes |  |  |  | yes | yes |
| [`openvpn`] | OpenVPN control and data wire packets over UDP and TCP, with no cryptography or tunnel session. | yes | yes |  |  |  | yes | yes |
| [`ospf`] | OSPFv2 and OSPFv3 packets and LSAs. | yes |  |  |  |  | yes | yes |
| [`ouch`] | Nasdaq OUCH 5.0 order entry messages and an exchange-side state machine that tracks open orders. | yes |  | `Exchange` |  |  | yes | yes |
| [`pcp`] | PCP and NAT-PMP port mapping requests and responses, and the version negotiation between them. | yes |  |  |  |  | yes | yes |
| [`pim`] | PIM version 2 multicast routing messages. |  |  |  |  |  | yes | yes |
| [`pop3`] | POP3 commands and replies. | yes | yes |  |  |  | yes | yes |
| [`portmap`] | Portmapper version 2 and rpcbind versions 3 and 4 requests and results, and universal addresses. |  |  |  |  |  | yes | yes |
| [`ports`] | Ready-slot polling for packet interfaces. |  |  |  |  |  |  | yes |
| [`postgres`] | The PostgreSQL protocol, version 3: frontend and backend messages, from startup to query results. | yes | yes |  |  |  | yes | yes |
| [`prefix_int`] | RFC 7541 prefix integers, shared by HPACK and QPACK. | yes |  |  |  |  |  | yes |
| [`protobuf`] | The Protocol Buffers wire format, read and written without a schema. | yes | yes |  |  |  | yes | yes |
| [`proxy_protocol`] | The PROXY protocol header a proxy puts in front of a TCP connection, versions 1 and 2. | yes | yes |  |  |  | yes | yes |
| [`qpack`] | QPACK, HTTP/3's header compression: field sections and the encoder and decoder streams. | yes | yes |  |  |  | yes | yes |
| [`quic`] | QUIC packets and frames, with no cryptography. | yes |  |  |  |  | yes | yes |
| [`radius`] | RADIUS wire packets and attributes, with the standard attribute dictionary and no cryptography. | yes | yes |  |  |  | yes | yes |
| [`rdp`] | RDP connection sequence messages from MS-RDPBCGR. | yes | yes |  |  |  | yes | yes |
| [`resp`] | RESP, the Redis protocol, versions 2 and 3: values and commands. | yes | yes |  |  |  | yes | yes |
| [`rfb`] | RFB, the protocol behind VNC: the handshake and messages, and a session for either side. | yes | yes | `Client`, `Server` |  |  | yes | yes |
| [`rip`] | RIP and RIPng routing messages. | yes |  |  |  |  | yes | yes |
| [`route`] | Forwarding packets between interfaces by destination: the router and the LAN. |  |  |  |  |  |  | yes |
| [`rtcp`] | RTCP control packets, compound packets and feedback messages. | yes | yes |  |  |  | yes | yes |
| [`rtp`] | RTP media packets and their header extensions, told apart from RTCP. | yes |  |  |  |  | yes | yes |
| [`rtsp`] | RTSP messages and interleaved data, with transport and range headers. | yes | yes |  |  |  | yes | yes |
| [`sandbox`] | Client machines with DNS, TLS, and HTTP requests for lab tests. |  |  |  |  |  |  | yes |
| [`sbe`] | FIX Simple Binary Encoding 1.0 at run time: load a schema's XML, then read and write its messages. | yes | yes |  |  |  | yes | yes |
| [`sdp`] | SDP session descriptions, with ICE candidates and RTP maps. | yes | yes |  |  |  | yes | yes |
| [`serve`] | Services: the `Service` trait, the driver that runs one over a connection or a UDP socket, `listen`, a test harness, transcripts and fault plans. |  |  |  |  |  | yes | yes |
| [`session`] | Passive mechanics shared by caller-driven protocol sessions. |  |  |  |  |  |  | yes |
| [`sftp`] | SFTP version 3 packets, requests and responses. | yes | yes |  |  |  | yes | yes |
| [`sip`] | SIP messages, URIs and the headers a proxy reads. | yes | yes |  |  |  | yes | yes |
| [`smb2`] | SMB2 and SMB3 wire messages and compound chains, with no session, service, signing, encryption, or decompression. | yes | yes |  |  |  | yes | yes |
| [`smtp`] | SMTP commands, replies and DATA, with a server-side decoder that switches between them. | yes | yes |  |  |  | yes | yes |
| [`snmp`] | SNMP v1 and v2c messages, PDUs and OIDs, using `asn1` integer and length helpers. | yes | yes |  |  |  | yes | yes |
| [`socks`] | SOCKS4, SOCKS4a and SOCKS5 handshake messages and the UDP request header. | yes | yes |  |  |  | yes | yes |
| [`soupbintcp`] | SoupBinTCP 3.0 packets, a framer, and client and server sessions. | yes | yes | `Client`, `Server` |  |  | yes | yes |
| [`spnego`] | SPNEGO negotiation tokens, as HTTP Negotiate, SMB and LDAP carry them. | yes | yes |  |  |  | yes | yes |
| [`sse`] | Server-sent events: raw lines or dispatched events from a streaming response body, and events written back. | yes | yes |  |  |  | yes | yes |
| [`ssh`] | The SSH transport layer before encryption: version exchange, binary packets and the first messages. | yes | yes |  |  |  | yes | yes |
| [`stun`] | STUN messages and attributes, with a binding reply helper. | yes | yes |  |  |  | yes | yes |
| [`syslog`] | Syslog messages in the RFC 5424 and RFC 3164 formats, and RFC 6587 stream framing. | yes | yes |  |  |  | yes | yes |
| [`tcp`] | TCP listeners and connections for a machine on the simulated network, on smoltcp. |  |  |  |  |  | yes | yes |
| [`tcp_reassembly`] | TCP capture reassembly for observers: ordered bytes, gaps and end signals. |  |  |  |  |  | yes | yes |
| [`tds`] | TDS, the SQL Server protocol: packets, logins, SQL batches and response tokens. | yes | yes | `TokenReader` |  |  | yes | yes |
| [`telnet`] | Telnet data and commands, option negotiation, terminal type and window size. | yes | yes | `Negotiation` |  |  | yes | yes |
| [`test_support`] | Shared test data, scripted decoders, timing and contract checks. |  | yes |  |  |  |  | yes |
| [`tftp`] | TFTP packets, option negotiation, and one read transfer served. | yes | yes | `ReadTransfer` |  |  | yes | yes |
| [`thrift`] | Apache Thrift messages and values in the binary and compact protocols, and the framed transport. | yes | yes |  |  |  | yes | yes |
| [`tls`] | The server side of a TLS connection, played by the world with rustls. The world picks the certificate after the client hello. |  |  |  |  | built in | yes | yes |
| [`tpkt`] | TPKT packets, the carrier of ISO transport on TCP. | yes | yes |  |  |  | yes | yes |
| [`udp`] | UDP sockets, borrowed datagram parsing and checked encoding. |  |  |  |  |  |  | yes |
| [`urlencoded_form`] | application/x-www-form-urlencoded form bodies and query strings. | yes | yes |  |  |  | yes | yes |
| [`vrrp`] | VRRP virtual router advertisements, versions 2 and 3. |  |  |  |  |  | yes | yes |
| [`vxlan`] | VXLAN and VXLAN-GPE headers. | yes |  |  |  |  | yes | yes |
| [`wake_on_lan`] | Wake-on-LAN magic packets. | yes | yes |  |  |  | yes | yes |
| [`web`] | Websites by hostname: `Sites`, a preset on `Net` that builds DNS, addresses, TLS and HTTP around one callback. |  |  |  |  |  | yes | yes |
| [`websocket`] | WebSocket: the opening handshake, frames and messages. | yes | yes |  |  |  | yes | yes |
| [`whois`] | WHOIS queries and responses, with referrals. | yes | yes |  |  |  | yes | yes |
| [`wireguard`] | WireGuard's four message types, with no cryptography. | yes |  |  |  |  | yes | yes |
| [`x509`] | X.509 certificates and CRLs with PEM reading and writing, with no signing, signature verification, or trust-path validation. | yes | yes |  |  |  | yes | yes |
| [`xml`] | XML 1.0: a nonvalidating UTF-8 pull parser and writer, with DTD attribute defaults but no declared entity expansion. | yes | yes |  |  |  | yes | yes |
| [`zabbix`] | The Zabbix protocol: packets and the JSON messages of agents, senders and servers. | yes | yes |  |  |  | yes | yes |
