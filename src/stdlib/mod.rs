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
//!   ([`httpd`]). Every service records what it sees as
//!   [events](fictionet::events) in the run's one log.
//! - **Networks.** [`net::Net`] builds all of the above for you: the
//!   sandboxes' subnet, DNS, addresses, a router, one machine per address,
//!   and each host's services. [`web::Sites`] is a preset on it for a world
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
//! [`net::Net::start`] and [`web::Sites::start`] start many tasks: one for
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
//! | [`web::Sites::start`] | the attachments, and a callback that gives the site for a hostname | nothing: it builds DNS, routing, machines, TLS and HTTP |
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
//! [Add an observe protocol](https://github.com/amlalabs/fictionet-sdk/blob/main/docs/observe-protocols.md)
//! walks through it. Wire parsing, serving and capture presentation are
//! separate responsibilities. A catalog entry in **Wire** or **Decode**
//! does not promise a live server or a built-in capture presenter. See the
//! codec's [serving and capture boundaries](codec#serving-and-capture-boundaries)
//! for runtime support and observation policies.
//!
//! ## Adding a protocol
//!
//! Follow [CONTRIBUTING.md](https://github.com/amlalabs/fictionet-sdk/blob/main/CONTRIBUTING.md#adding-a-protocol-module)
//! and the codec's [errors and names](codec#errors-and-names-in-a-codec-module).
//! A new protocol needs these entries:
//!
//! 1. Add `src/stdlib/<name>.rs`, using public `fictionet::` items. Document
//!    the supported wire format, limits and caller responsibilities, with
//!    runnable doctests. Implement [`codec::Wire`] for complete values and
//!    [`codec::Prefixed`] or [`codec::Decode`] where stream framing is needed.
//!    Check decoder contracts with [`test_support::contract`].
//! 2. Add a record to `catalog/stdlib.rs` for [the catalog](#the-catalog).
//!    List only capabilities the module implements. Regenerate the table with
//!    `BLESS_STDLIB_CATALOG=1 cargo nextest run --locked --test stdlib_catalog`.
//!    The same command writes the module's `pub mod` declaration here and its
//!    `#[path]` entry in `tests/copy_and_own/modules.rs`, which checks that
//!    the source compiles in a consumer crate using public APIs. The record's
//!    `file` and `gate` fields give another entry file and a feature gate.
//!    Keep protocol-specific descriptions in that record and the module docs,
//!    without adding a front-page paragraph.
//! 3. Add `fuzz/fuzz_targets/<name>.rs`, a fuzz target record naming the
//!    module in `catalog/stdlib.rs`, and `fuzz/corpus/<name>/` with seed
//!    inputs. The bless command above writes its `[[bin]]` entry in
//!    `fuzz/Cargo.toml`. `fuzz/check-targets.sh` checks the source, bin and
//!    corpus inventory.
//!
//! A service and a presenter are optional additions. A service owns replies,
//! connection state and events; install it on a [`net::Host`] port. A capture
//! adapter belongs in `src/observe/`, implements
//! [`Present`](fictionet::observe::Present) on its decoder, and keeps observe
//! dependencies out of the protocol file. For a built-in presenter, declare
//! the adapter in the observe module. Put its matcher, factory and input
//! read-ahead in the adapter's `register` method. Call that method from
//! `src/observe/app.rs`. That file sets the default registration order and
//! creates the shared HTTP/2 `CaptureBudget`. For a local copy, install a custom
//! [`Registry`](fictionet::observe::Registry) with
//! [`Cx::observe_protocols`](fictionet::Cx::observe_protocols) before watches
//! start, as the observe guide shows.
//!
//! `tests/stdlib_catalog.rs` derives inventories from the source files and
//! declarations, the observe app registrations, the fuzz manifest and the
//! copy fixture. It checks the catalog against those owners; editing a row
//! alone does not register a codec, a server or a presenter.
//!
//! The [CI workflow](https://github.com/amlalabs/fictionet-sdk/blob/main/.github/workflows/ci.yml)
//! is the authority for the five feature combinations: default,
//! `--no-default-features`, `--all-features`,
//! `--no-default-features --features std,observe`, and
//! `--no-default-features --features tokio`. It checks the fuzz bins and
//! helper tests on pinned stable with `RUSTFLAGS="--cfg fuzzing"`. The fuzz
//! job checks the inventory and sweep script, then builds all targets with
//! `cargo +nightly fuzz build -O -a`. Scheduled and manual runs also execute
//! every target for 60 seconds. See that workflow for the exact commands.
//!
//! ## Changing a protocol by copying it
//!
//! Every file in `src/stdlib/` uses only public `fictionet::` items. The crate
//! root's `extern crate self as fictionet` makes those imports work here and
//! in your crate. Copy a file, edit it, and use it through the public traits.
//! `tests/copy_and_own` compiles the files in a separate crate. Optional
//! code uses the SDK's feature-selection macros, so a copied file needs
//! no matching Cargo features in the consuming crate.
//! Copy `net.rs` together with the `net/` directory, keeping the relative
//! paths. The entry file declares its private address-management, host
//! installation, attachment lifecycle, and DNS service modules.
//! It also needs `world/names.rs`, keeping that relative path.
//! Copy `httpd.rs` together with the `httpd/` directory, keeping the relative
//! paths. The entry file declares its private body, handler, site, and response modules,
//! and one module per serving engine: native HTTP/1 in `httpd/http1.rs`, and
//! hyper's HTTP/2 and upgrades in `httpd/hyper.rs` with the `tokio` feature.
//! Copy `tls.rs` together with the `tls/` directory, keeping the relative
//! paths. The entry file declares its private run-aware crypto provider.
//! Copy `sandbox.rs` together with `tls/output.rs`, keeping that relative
//! path. For either copy, declare `#[path = "tls/output.rs"] mod tls_output;`
//! next to the copied module. Both adapters use this private output helper.
//! Copy the `cme_mdp3/` directory, keeping the relative paths. Its entry
//! file, `mod.rs`, declares the private packet framing module.
//! Copy the `smb2/` directory the same way. Its `mod.rs` declares the
//! private module of negotiate, create and error contexts.
//! Copy the `json_schema/` directory the same way. Its `mod.rs` declares
//! the private modules of string format checks and examples, and of exact
//! decimal arithmetic.
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
//! `tests/stdlib_catalog.rs` checks the table against source declarations and
//! the copy, fuzz and observe inventories. A listed capability must have a
//! matching declaration of a kind the test recognizes; see that test's docs.
//! The check is textual and does not prove every Rust trait implementation.
//! The metadata lives in `catalog/stdlib.rs`. This table is generated from it;
//! the test rejects drift unless `BLESS_STDLIB_CATALOG` is set to update it.
//! A new module gets a record there and its own module docs.
//! Do not add other prose about the module to this page or the crate root.
//! See [Adding a protocol](#adding-a-protocol) for the registration checklist.
//!
#![doc = include_str!("catalog.md")]

// Generated from catalog/stdlib.rs. Update with BLESS_STDLIB_CATALOG=1 cargo nextest run --locked --test stdlib_catalog.
pub mod amqp;
pub mod asn1;
pub mod bacnet;
pub mod bgp;
pub mod book_levels;
pub mod ca;
pub mod cboe_boe;
pub mod cboe_pitch;
#[doc = include_str!("cme_mdp3/docs.md")]
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
pub mod netbios;
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
// End of the generated module declarations.

mod connection;
pub use connection::{Accept, Accepted, ConnError, Connection, ConnectionExt, DatagramSocket};

#[path = "tls/output.rs"]
mod tls_output;

mod link;
pub use link::{Direction, bottleneck, delay, filter};
