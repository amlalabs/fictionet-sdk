//! Canonical stdlib catalog metadata. Keep records in module-name order.
//!
//! `tests/stdlib_catalog.rs` checks these claims against independent source
//! inventories. Set `BLESS_STDLIB_CATALOG=1` when running that test to update
//! `src/stdlib/catalog.md`, the public module declarations in
//! `src/stdlib/mod.rs`, the module declarations of the copy-and-own fixture in
//! `tests/copy_and_own/modules.rs`, the `[[bin]]` records in `fuzz/Cargo.toml`
//! and the list of fuzz targets without a module in `fuzz/README.md`. Private
//! stdlib modules, the fixture's compile probes and fuzz target sources remain
//! handwritten.

/// One public stdlib module and its documented capabilities.
#[derive(Clone, Copy, Debug)]
pub struct Module {
    /// The public name under `fictionet::stdlib`.
    pub module: &'static str,
    /// Whether rustdoc exposes the module and can link to it.
    pub linked: bool,
    /// A one-line description of the module.
    pub what: &'static str,
    /// The module provides public `Wire` implementations.
    pub wire: bool,
    /// The module provides a public decoder or `Prefixed` value.
    pub decode: bool,
    /// Public types that hold caller-driven conversation state.
    pub state: &'static [&'static str],
    /// Public types that implement `serve::Service`.
    pub service: &'static [&'static str],
    /// The default observe registry includes this module's protocol.
    pub observe: bool,
    /// At least one record in [`FUZZ_TARGETS`] names this module as its owner.
    pub fuzz: bool,
    /// The copy-and-own fixture compiles this module's implementation.
    pub copy: bool,
    /// The fixture copies the module's files one by one, as [`COPY_PARTS`]
    /// records, instead of through its entry file.
    pub copy_parts: bool,
    /// The entry file under `src/stdlib/`, when it is not `<module>.rs`.
    pub file: Option<&'static str>,
    /// A Markdown file under `src/stdlib/` included as the module's docs.
    pub docs: Option<&'static str>,
    /// The feature-selection macro around the module's declarations.
    pub gate: Gate,
}

/// The SDK feature-selection macro a module declaration sits in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gate {
    /// No macro: the module is always compiled.
    Always,
    /// `fictionet::cfg_std!`.
    Std,
    /// `fictionet::cfg_observe!`.
    Observe,
}

impl Module {
    const fn new(module: &'static str, what: &'static str) -> Self {
        Self {
            module,
            linked: true,
            what,
            wire: false,
            decode: false,
            state: &[],
            service: &[],
            observe: false,
            fuzz: false,
            copy: false,
            copy_parts: false,
            file: None,
            docs: None,
            gate: Gate::Always,
        }
    }
}

// Omitted capabilities are absent; all modules are linked unless hidden.
macro_rules! catalog {
    ($($module:ident: $what:literal; $($field:ident: $value:expr),*;)*) => {
        /// Every public stdlib module, in alphabetical order.
        pub const MODULES: &[Module] = &[
            $(Module {
                $($field: $value,)*
                ..Module::new(stringify!($module), $what)
            },)*
        ];
    };
}

catalog! {
    amqp: "AMQP 0-9-1 frames, methods, field tables and content headers.";
        wire: true, decode: true, fuzz: true, copy: true;
    asn1: "ASN.1 BER and DER tags, lengths and values, the base of LDAP, SNMP, Kerberos and X.509.";
        wire: true, decode: true, fuzz: true, copy: true;
    bacnet: "BACnet/IP: BVLC messages, NPDUs, APDUs and application-tagged values.";
        wire: true, decode: true, fuzz: true, copy: true;
    bgp: "BGP-4 messages from OPEN to ROUTE-REFRESH, with path attributes and prefixes.";
        wire: true, decode: true, fuzz: true, copy: true;
    book_levels: "Ordered quantity and order-count aggregates for one side of an order book.";
        copy: true;
    ca: "Seeded certificate authorities and server leaves for simulated TLS sites.";
        copy: true;
    cboe_boe: "Cboe Binary Order Entry: every session and order message, a member's and an exchange's session, and an order tracker.";
        wire: true, decode: true, state: &["Client", "Server", "Exchange"], fuzz: true, copy: true;
    cboe_pitch: "Cboe Multicast PITCH: sequenced units, every message, a gap detector per unit and a bounded order book.";
        wire: true, decode: true, state: &["GapDetector", "Book"], fuzz: true, copy: true;
    cme_mdp3: "CME MDP 3.0 market data: generated messages for SBE schema 1 version 13 (20230411), plus packet framing.";
        wire: true, decode: true, fuzz: true, copy: true,
        file: Some("cme_mdp3/mod.rs"), docs: Some("cme_mdp3/docs.md");
    coap: "CoAP messages over UDP and frames over TCP, with block-wise reassembly.";
        wire: true, decode: true, fuzz: true, copy: true;
    codec: "The tools every protocol is built on, none of them doing I/O: `Decode`, `Wire`, `Stream`, combinators, a recorder and fault injection.";
        wire: true, decode: true, fuzz: true, copy: true, copy_parts: true;
    cotp: "ISO transport on TCP: TPKT and COTP packets, with segment reassembly.";
        wire: true, decode: true, fuzz: true, copy: true;
    dcerpc: "DCE/RPC over connections: bind, request and response PDUs, with fragment reassembly.";
        wire: true, decode: true, fuzz: true, copy: true;
    dhcp: "DHCP messages, used by `Net` and by the DHCP server attach runs for a VM.";
        wire: true, observe: true, fuzz: true, copy: true;
    dhcpv6: "DHCPv6 client, server and relay messages and their options.";
        wire: true, decode: true, fuzz: true, copy: true;
    diameter: "Diameter messages and AVPs.";
        wire: true, decode: true, fuzz: true, copy: true;
    dnp3: "DNP3 link frames, transport segments and application headers.";
        wire: true, decode: true, fuzz: true, copy: true;
    dns: "DNS messages: the `hickory-proto` crate, re-exported. `Net` runs the server.";
        observe: true, fuzz: true, copy: true;
    dtls: "DTLS records and handshake messages, with fragment reassembly and no cryptography.";
        wire: true, fuzz: true, copy: true;
    enip: "EtherNet/IP and CIP: the encapsulation layer, the common packet format and message router messages.";
        wire: true, decode: true, fuzz: true, copy: true;
    fast: "FAST 1.1, the compression of FIX market data: templates, dictionaries, a decoder and an encoder.";
        wire: true, decode: true, fuzz: true, copy: true;
    fastcgi: "FastCGI records, name-value pairs and whole requests and responses, with request bookkeeping for both sides.";
        wire: true, decode: true, state: &["Client", "Server"], fuzz: true, copy: true;
    fix: "FIX tag=value messages, repeating groups and a caller-driven session for either side.";
        wire: true, decode: true, state: &["Session"], fuzz: true, copy: true;
    ftp: "FTP control connection: commands, replies and features.";
        wire: true, decode: true, fuzz: true, copy: true;
    geneve: "Geneve tunnel headers and their options.";
        wire: true, fuzz: true, copy: true;
    git_protocol: "The Git wire protocol: pkt-lines, requests, ref advertisements, negotiation and side-band demultiplexing.";
        wire: true, decode: true, fuzz: true, copy: true;
    gre: "GRE headers, PPTP's included.";
        wire: true, fuzz: true, copy: true;
    grpc: "gRPC over HTTP/2: message framing, status codes, timeouts and the header rules a server follows.";
        wire: true, decode: true, fuzz: true, copy: true;
    hpack: "HPACK header compression for HTTP/2: fields, blocks, the dynamic table and an encoder.";
        wire: true, fuzz: true, copy: true;
    http1: "HTTP/1.0 and 1.1 wire messages and stream framing, with no non-empty trailers, chunk extensions, or Upgrade negotiation.";
        wire: true, decode: true, observe: true, fuzz: true, copy: true;
    http2: "HTTP/2 frames, directional state and capture decoding. Live serving uses hyper in `httpd`.";
        wire: true, decode: true, state: &["Session"], observe: true, fuzz: true, copy: true;
    http3: "HTTP/3 frames, field sections and caller-driven stream state, with no QUIC transport or HTTP service.";
        wire: true, decode: true, state: &["Session"], fuzz: true, copy: true;
    httpd: "HTTP serving: `Http1`, upgrade continuations, hyper for HTTP/2 and axum upgrades, handlers, tower integration, and virtual hosts.";
        service: &["Http1"], copy: true, gate: Gate::Std;
    huffman: "The RFC 7541 Huffman code that HPACK and QPACK share.";
        wire: true, fuzz: true, copy: true;
    icmp: "ICMP echo replies and error messages, for machines built by hand.";
        copy: true;
    iec104: "IEC 60870-5-104 APDUs and ASDU headers.";
        wire: true, decode: true, fuzz: true, copy: true;
    igmp: "IGMP membership queries and reports, versions 1 to 3.";
        wire: true, fuzz: true, copy: true;
    ike: "IKEv2 message structure and payloads, with no cryptography.";
        wire: true, fuzz: true, copy: true;
    imap: "IMAP commands and responses.";
        wire: true, decode: true, fuzz: true, copy: true;
    imf: "Internet Message Format mail headers: fields, addresses, dates, message IDs and encoded words.";
        wire: true, decode: true, fuzz: true, copy: true;
    ip: "IP headers read, checked and built, checksums, fragment reassembly, and sorting packets by version and protocol.";
        fuzz: true, copy: true;
    ipp: "IPP, the Internet Printing Protocol: requests, responses and their attribute groups.";
        wire: true, decode: true, fuzz: true, copy: true;
    ipsec: "IPsec ESP and AH wire headers, with no cryptography or security association state.";
        wire: true, fuzz: true, copy: true;
    itch: "Nasdaq TotalView-ITCH 5.0: every message, a framer and a bounded order book.";
        wire: true, decode: true, state: &["Book"], fuzz: true, copy: true;
    json: "JSON text to a tree of values and back, under limits.";
        wire: true, decode: true, fuzz: true, copy: true;
    json_schema: "Checked JSON schemas: compile one, validate values against it, and generate values from it.";
        fuzz: true, copy: true;
    jsonrpc: "JSON-RPC 2.0 requests, notifications, responses and batches, over lines or HTTP bodies.";
        wire: true, decode: true, fuzz: true, copy: true;
    kafka: "Apache Kafka frames, headers, and the ApiVersions and Metadata messages.";
        wire: true, decode: true, fuzz: true, copy: true;
    kerberos: "Kerberos V5 messages between a client, a KDC and a service, with no cryptography.";
        wire: true, decode: true, fuzz: true, copy: true;
    l2tp: "L2TP headers, control messages and AVPs, versions 2 and 3.";
        wire: true, fuzz: true, copy: true;
    ldap: "LDAP wire messages, search filters and distinguished names, with no session or service.";
        wire: true, decode: true, fuzz: true, copy: true;
    memcache: "memcached's text and binary protocols and UDP frames.";
        wire: true, decode: true, fuzz: true, copy: true;
    mime_multipart: "MIME multipart bodies, split into parts and written back.";
        wire: true, decode: true, fuzz: true, copy: true;
    modbus: "Modbus/TCP frames, requests and responses. The `custom_protocol` example copies it.";
        wire: true, decode: true, observe: true, fuzz: true, copy: true;
    moldudp64: "MoldUDP64 packets and message blocks, a receiver with gap recovery and a retransmission server.";
        wire: true, decode: true, state: &["Receiver", "Retransmitter"], fuzz: true, copy: true;
    mongodb: "MongoDB BSON documents and wire protocol messages.";
        wire: true, decode: true, fuzz: true, copy: true;
    mqtt: "MQTT 3.1.1 control packets and topic matching.";
        wire: true, decode: true, fuzz: true, copy: true;
    mysql: "The MySQL client/server protocol: packets, the handshake, commands and result sets.";
        wire: true, decode: true, state: &["ResultReader"], fuzz: true, copy: true;
    nbdgm: "NetBIOS Datagram Service packets, with fragment reassembly and `netbios` name encoding.";
        wire: true, fuzz: true, copy: true;
    nbns: "NetBIOS Name Service queries, registrations and node status, with reply helpers.";
        wire: true, fuzz: true, copy: true;
    nbss: "NetBIOS Session Service packets, using `netbios` name encoding.";
        wire: true, decode: true, fuzz: true, copy: true;
    net: "A network of hosts and services in a few lines: the sandboxes' subnet, DHCP, DNS, a router, machines, LANs and each host's services.";
        copy: true;
    netbios: "NetBIOS name construction, display, and uncompressed reading and writing shared by NBNS, NBDGM and NBSS.";
        fuzz: true, copy: true;
    nfs: "NFS version 3 and MOUNT version 3: the arguments and results of every procedure, over `onc_rpc`.";
        fuzz: true, copy: true;
    ntlmssp: "NTLM NEGOTIATE, CHALLENGE and AUTHENTICATE wire messages, with no cryptography or authentication session.";
        wire: true, fuzz: true, copy: true;
    ntp: "NTP time packets, with a server reply helper.";
        wire: true, fuzz: true, copy: true;
    ocsp: "OCSP certificate status wire requests and responses, with no signing or signature verification.";
        wire: true, decode: true, fuzz: true, copy: true;
    onc_rpc: "ONC RPC calls and replies, XDR reading and writing, and TCP record marking.";
        wire: true, decode: true, fuzz: true, copy: true;
    opcua: "OPC UA binary transport, built-in types and open/close secure channel bodies for policy None, with no cryptography or session.";
        wire: true, decode: true, fuzz: true, copy: true;
    openvpn: "OpenVPN control and data wire packets over UDP and TCP, with no cryptography or tunnel session.";
        wire: true, decode: true, fuzz: true, copy: true;
    ospf: "OSPFv2 and OSPFv3 packets and LSAs.";
        wire: true, fuzz: true, copy: true;
    ouch: "Nasdaq OUCH 5.0 order entry messages and an exchange-side state machine that tracks open orders.";
        wire: true, state: &["Exchange"], fuzz: true, copy: true;
    pcp: "PCP and NAT-PMP port mapping requests and responses, and the version negotiation between them.";
        wire: true, fuzz: true, copy: true;
    pim: "PIM version 2 multicast routing messages.";
        fuzz: true, copy: true;
    pop3: "POP3 commands and replies.";
        wire: true, decode: true, fuzz: true, copy: true;
    portmap: "Portmapper version 2 and rpcbind versions 3 and 4 requests and results, and universal addresses.";
        fuzz: true, copy: true;
    ports: "Ready-slot polling for packet interfaces.";
        copy: true;
    postgres: "The PostgreSQL protocol, version 3: frontend and backend messages, from startup to query results.";
        wire: true, decode: true, fuzz: true, copy: true;
    prefix_int: "RFC 7541 prefix integers, shared by HPACK and QPACK.";
        wire: true, copy: true;
    protobuf: "The Protocol Buffers wire format, read and written without a schema.";
        wire: true, decode: true, fuzz: true, copy: true;
    proxy_protocol: "The PROXY protocol header a proxy puts in front of a TCP connection, versions 1 and 2.";
        wire: true, decode: true, fuzz: true, copy: true;
    qpack: "QPACK, HTTP/3's header compression: field sections and the encoder and decoder streams.";
        wire: true, decode: true, fuzz: true, copy: true;
    quic: "QUIC packets and frames, with no cryptography.";
        wire: true, fuzz: true, copy: true;
    radius: "RADIUS wire packets and attributes, with the standard attribute dictionary and no cryptography.";
        wire: true, decode: true, fuzz: true, copy: true;
    rdp: "RDP connection sequence messages from MS-RDPBCGR.";
        wire: true, decode: true, fuzz: true, copy: true;
    resp: "RESP, the Redis protocol, versions 2 and 3: values and commands.";
        wire: true, decode: true, fuzz: true, copy: true;
    rfb: "RFB, the protocol behind VNC: the handshake and messages, and a session for either side.";
        wire: true, decode: true, state: &["Client", "Server"], fuzz: true, copy: true;
    rip: "RIP and RIPng routing messages.";
        wire: true, fuzz: true, copy: true;
    route: "Forwarding packets between interfaces by destination: the router and the LAN.";
        copy: true;
    rtcp: "RTCP control packets, compound packets and feedback messages.";
        wire: true, decode: true, fuzz: true, copy: true;
    rtp: "RTP media packets and their header extensions, told apart from RTCP.";
        wire: true, fuzz: true, copy: true;
    rtsp: "RTSP messages and interleaved data, with transport and range headers.";
        wire: true, decode: true, fuzz: true, copy: true;
    sandbox: "Client machines with DNS, TLS, and HTTP requests for lab tests.";
        copy: true;
    sbe: "FIX Simple Binary Encoding 1.0 at run time: load a schema's XML, then read and write its messages.";
        wire: true, decode: true, fuzz: true, copy: true;
    sdp: "SDP session descriptions, with ICE candidates and RTP maps.";
        wire: true, decode: true, fuzz: true, copy: true;
    serve: "Services: the `Service` trait, the driver that runs one over a connection or a UDP socket, `listen`, a test harness, transcripts and fault plans.";
        fuzz: true, copy: true;
    session: "Passive mechanics shared by caller-driven protocol sessions.";
        copy: true;
    sftp: "SFTP version 3 packets, requests and responses.";
        wire: true, decode: true, fuzz: true, copy: true;
    sip: "SIP messages, URIs and the headers a proxy reads.";
        wire: true, decode: true, fuzz: true, copy: true;
    smb2: "SMB2 and SMB3 wire messages and compound chains, with no session, service, signing, encryption, or decompression.";
        wire: true, decode: true, fuzz: true, copy: true;
    smtp: "SMTP commands, replies and DATA, with a server-side decoder that switches between them.";
        wire: true, decode: true, fuzz: true, copy: true;
    snmp: "SNMP v1 and v2c messages, PDUs and OIDs, using `asn1` integer and length helpers.";
        wire: true, decode: true, fuzz: true, copy: true;
    socks: "SOCKS4, SOCKS4a and SOCKS5 handshake messages and the UDP request header.";
        wire: true, decode: true, fuzz: true, copy: true;
    soupbintcp: "SoupBinTCP 3.0 packets, a framer, and client and server sessions.";
        wire: true, decode: true, state: &["Client", "Server"], fuzz: true, copy: true;
    spnego: "SPNEGO negotiation tokens, as HTTP Negotiate, SMB and LDAP carry them.";
        wire: true, decode: true, fuzz: true, copy: true;
    sse: "Server-sent events: raw lines or dispatched events from a streaming response body, and events written back.";
        wire: true, decode: true, fuzz: true, copy: true;
    ssh: "The SSH transport layer before encryption: version exchange, binary packets and the first messages.";
        wire: true, decode: true, fuzz: true, copy: true;
    stun: "STUN messages and attributes, with a binding reply helper.";
        wire: true, decode: true, fuzz: true, copy: true;
    syslog: "Syslog messages in the RFC 5424 and RFC 3164 formats, and RFC 6587 stream framing.";
        wire: true, decode: true, fuzz: true, copy: true;
    tcp: "TCP listeners and connections for a machine on the simulated network, on smoltcp.";
        fuzz: true, copy: true;
    tcp_reassembly: "TCP capture reassembly for observers: ordered bytes, gaps and end signals.";
        fuzz: true, copy: true;
    tds: "TDS, the SQL Server protocol: packets, logins, SQL batches and response tokens.";
        wire: true, decode: true, state: &["TokenReader"], fuzz: true, copy: true;
    telnet: "Telnet data and commands, option negotiation, terminal type and window size.";
        wire: true, decode: true, state: &["Negotiation"], fuzz: true, copy: true;
    test_support: "Shared test data, scripted decoders, timing and contract checks.";
        decode: true, copy: true, file: Some("test_support/mod.rs");
    tftp: "TFTP packets, option negotiation, and one read transfer served.";
        wire: true, decode: true, state: &["ReadTransfer"], fuzz: true, copy: true;
    thrift: "Apache Thrift messages and values in the binary and compact protocols, and the framed transport.";
        wire: true, decode: true, fuzz: true, copy: true;
    tls: "The server side of a TLS connection, played by the world with rustls. The world picks the certificate after the client hello.";
        observe: true, fuzz: true, copy: true;
    tpkt: "TPKT packets, the carrier of ISO transport on TCP.";
        wire: true, decode: true, fuzz: true, copy: true;
    udp: "UDP sockets, borrowed datagram parsing and checked encoding.";
        copy: true;
    urlencoded_form: "application/x-www-form-urlencoded form bodies and query strings.";
        wire: true, decode: true, fuzz: true, copy: true;
    vrrp: "VRRP virtual router advertisements, versions 2 and 3.";
        fuzz: true, copy: true;
    vxlan: "VXLAN and VXLAN-GPE headers.";
        wire: true, fuzz: true, copy: true;
    wake_on_lan: "Wake-on-LAN magic packets.";
        wire: true, decode: true, fuzz: true, copy: true;
    web: "Websites by hostname: `Sites`, a preset on `Net` that builds DNS, addresses, TLS and HTTP around one callback.";
        fuzz: true, copy: true, gate: Gate::Std;
    websocket: "WebSocket: the opening handshake, frames and messages.";
        wire: true, decode: true, fuzz: true, copy: true;
    whois: "WHOIS queries and responses, with referrals.";
        wire: true, decode: true, fuzz: true, copy: true;
    wireguard: "WireGuard's four message types, with no cryptography.";
        wire: true, fuzz: true, copy: true;
    x509: "X.509 certificates and CRLs with PEM reading and writing, with no signing, signature verification, or trust-path validation.";
        wire: true, decode: true, fuzz: true, copy: true;
    xml: "XML 1.0: a nonvalidating UTF-8 pull parser and writer, with DTD attribute defaults but no declared entity expansion.";
        wire: true, decode: true, fuzz: true, copy: true;
    zabbix: "The Zabbix protocol: packets and the JSON messages of agents, senders and servers.";
        wire: true, decode: true, fuzz: true, copy: true;
}

/// A file the copy-and-own fixture compiles as a module of its own, beside
/// the catalog modules it copies through their entry files: a private stdlib
/// module, one file of a module with `copy_parts`, or observe and generated
/// code from outside `src/stdlib/`.
#[derive(Clone, Copy, Debug)]
pub struct CopyPart {
    /// The module name in the fixture.
    pub name: &'static str,
    /// The file, relative to the repository root.
    pub file: &'static str,
    /// The fixture declares the module `pub`.
    pub public: bool,
    /// The feature-selection macro around the declaration.
    pub gate: Gate,
}

impl CopyPart {
    const fn new(name: &'static str, file: &'static str) -> Self {
        Self {
            name,
            file,
            public: true,
            gate: Gate::Always,
        }
    }
}

// Parts are public and always compiled unless a field says otherwise.
macro_rules! copy_parts {
    ($($name:ident: $file:literal $(, $field:ident: $value:expr)*;)*) => {
        /// Every copy part, in name order.
        pub const COPY_PARTS: &[CopyPart] = &[
            $(CopyPart {
                $($field: $value,)*
                ..CopyPart::new(stringify!($name), $file)
            },)*
        ];
    };
}

copy_parts! {
    ascii: "src/stdlib/codec/ascii.rs";
    base64: "src/stdlib/codec/base64.rs";
    ber: "src/stdlib/codec/ber.rs";
    bounded: "src/stdlib/codec/bounded.rs";
    buffer: "src/stdlib/codec/buffer.rs";
    checked: "src/stdlib/codec/checked.rs";
    civil: "src/stdlib/codec/civil.rs";
    combinators: "src/stdlib/codec/combinators.rs";
    connection: "src/stdlib/connection.rs";
    crc32: "src/stdlib/codec/crc32.rs";
    crc32c: "src/stdlib/codec/crc32c.rs";
    declarations: "src/stdlib/codec/declarations.rs";
    demux: "src/stdlib/codec/demux.rs";
    dot_body: "src/stdlib/codec/dot_body.rs";
    faults: "src/stdlib/codec/faults.rs";
    field: "src/stdlib/codec/field.rs";
    frames: "src/stdlib/codec/frames.rs";
    generated: "src/stdlib/codec/generated.rs";
    generated_recursive: "codegen/tests/golden/recursive.rs";
    head_body: "src/stdlib/codec/head_body.rs";
    interceptor: "src/stdlib/codec/interceptor.rs";
    json_syntax: "src/stdlib/codec/json_syntax.rs";
    layout: "src/stdlib/codec/layout.rs";
    lcg: "src/stdlib/codec/lcg.rs";
    leb128: "src/stdlib/codec/leb128.rs";
    link: "src/stdlib/link.rs";
    observe_conversation: "src/observe/conversation.rs", gate: Gate::Observe;
    observe_http2: "src/observe/http2.rs", gate: Gate::Observe;
    observe_protocols: "src/observe/protocols.rs", gate: Gate::Observe;
    observe_tls: "src/observe/tls.rs", gate: Gate::Observe;
    pipe: "src/stdlib/codec/pipe.rs";
    reader: "src/stdlib/codec/reader.rs";
    recorder: "src/stdlib/codec/recorder.rs";
    stream: "src/stdlib/codec/stream.rs";
    tls_output: "src/stdlib/tls/output.rs", public: false;
    work: "src/stdlib/codec/work.rs";
}

/// The owner of a fuzz target.
#[derive(Clone, Copy, Debug)]
pub enum FuzzOwner {
    /// The public stdlib module the target fuzzes.
    Module(&'static str),
    /// The target fuzzes no single stdlib module. The text says what it
    /// checks, as a sentence without its subject, for `fuzz/README.md`.
    Unowned(&'static str),
}

/// One cargo-fuzz target: a `[[bin]]` in `fuzz/Cargo.toml` built from
/// `fuzz/fuzz_targets/<name>.rs`.
#[derive(Clone, Copy, Debug)]
pub struct FuzzTarget {
    /// The binary name, which is also the source file stem.
    pub name: &'static str,
    /// The module the target belongs to, or what it checks if none.
    pub owner: FuzzOwner,
}

// `target: module;` names the owning stdlib module. `target: "checks ...";`
// describes a target that fuzzes no single stdlib module.
macro_rules! fuzz_owner {
    ($module:ident) => {
        FuzzOwner::Module(stringify!($module))
    };
    ($what:literal) => {
        FuzzOwner::Unowned($what)
    };
}

macro_rules! fuzz_targets {
    ($($name:ident: $owner:tt;)*) => {
        /// Every fuzz target, in `fuzz/Cargo.toml` order. Add new targets at the
        /// end. The `[[bin]]` records and the README list of targets without a
        /// module are generated from these records.
        pub const FUZZ_TARGETS: &[FuzzTarget] = &[
            $(FuzzTarget {
                name: stringify!($name),
                owner: fuzz_owner!($owner),
            },)*
        ];
    };
}

fuzz_targets! {
    codec_tools: codec;
    json_schema: json_schema;
    sse_lines: sse;
    sse_events: sse;
    sbe: sbe;
    relay: "checks relay message decoding and encoding.";
    tcp_reassembly: tcp_reassembly;
    packets: "checks IP protocol sorting, ICMP echo replies and DHCP messages.";
    ip_reassembly: ip;
    dns: dns;
    proxy_http: "checks HTTP proxy request heads, authentication and response heads.";
    proxy_socks5: "checks SOCKS5 greetings, authentication and requests across chunk boundaries.";
    tls: tls;
    stack: "feeds IPv4 and IPv6 packets to TCP, UDP and ICMP endpoints.";
    tcp: tcp;
    web: web;
    web_http: web;
    modbus: modbus;
    mqtt: mqtt;
    ntp: ntp;
    resp: resp;
    tftp: tftp;
    websocket: websocket;
    syslog: syslog;
    snmp: snmp;
    postgres: postgres;
    stun: stun;
    bacnet: bacnet;
    asn1: asn1;
    ssh: ssh;
    dhcpv6: dhcpv6;
    netbios: netbios;
    nbns: nbns;
    mysql: mysql;
    ftp: ftp;
    imap: imap;
    protobuf: protobuf;
    quic: quic;
    grpc: grpc;
    mime_multipart: mime_multipart;
    json: json;
    urlencoded_form: urlencoded_form;
    xml: xml;
    imf: imf;
    onc_rpc: onc_rpc;
    sip: sip;
    sdp: sdp;
    rtp: rtp;
    mongodb: mongodb;
    kafka: kafka;
    proxy_protocol: proxy_protocol;
    amqp: amqp;
    enip: enip;
    opcua: opcua;
    rfb: rfb;
    git_protocol: git_protocol;
    telnet: telnet;
    memcache: memcache;
    fastcgi: fastcgi;
    nfs: nfs;
    qpack: qpack;
    sftp: sftp;
    socks: socks;
    rtsp: rtsp;
    cotp: cotp;
    vxlan: vxlan;
    geneve: geneve;
    ldap: ldap;
    x509: x509;
    ocsp: ocsp;
    kerberos: kerberos;
    spnego: spnego;
    bgp: bgp;
    tds: tds;
    thrift: thrift;
    ipp: ipp;
    zabbix: zabbix;
    l2tp: l2tp;
    gre: gre;
    igmp: igmp;
    coap: coap;
    pop3: pop3;
    nbss: nbss;
    nbdgm: nbdgm;
    vrrp: vrrp;
    pcp: pcp;
    dtls: dtls;
    wireguard: wireguard;
    radius: radius;
    diameter: diameter;
    ike: ike;
    ipsec: ipsec;
    openvpn: openvpn;
    ospf: ospf;
    rip: rip;
    pim: pim;
    smb2: smb2;
    ntlmssp: ntlmssp;
    dcerpc: dcerpc;
    tpkt: tpkt;
    whois: whois;
    rtcp: rtcp;
    portmap: portmap;
    wake_on_lan: wake_on_lan;
    smtp: smtp;
    dnp3: dnp3;
    iec104: iec104;
    http3: http3;
    rdp: rdp;
    hpack: hpack;
    soupbintcp: soupbintcp;
    observe_modbus: modbus;
    huffman: huffman;
    observe_dns: dns;
    observe_dhcp: dhcp;
    observe_http1: http1;
    observe_tls: tls;
    http1_request_events: http1;
    http2: http2;
    http1_response_events: http1;
    jsonrpc_lines: jsonrpc;
    http1_requests: http1;
    jsonrpc_body: jsonrpc;
    http1_responses: http1;
    codegen_ir: "checks generated recursive values and stream frames.";
    serve_http1: serve;
    fix: fix;
    observe_http2: http2;
    fast: fast;
    cme_mdp3: cme_mdp3;
    moldudp64: moldudp64;
    itch: itch;
    ouch: ouch;
    cboe_pitch: cboe_pitch;
    cboe_boe: cboe_boe;
}
