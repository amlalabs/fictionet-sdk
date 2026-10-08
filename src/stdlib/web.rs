//! Websites by hostname: a whole network of sites in a few lines.
//!
//! Start here when the world you want is a set of websites, real or made
//! up, for an agent to browse. [`Sites`] takes a callback that decides, for
//! each hostname, whether a site exists and what it is. It builds the whole
//! network around the answers: DNS, addresses, a router, one machine per
//! address, TLS, and HTTP. You write only the sites.
//!
//! `Sites` is a preset on [`net::Net`](fictionet::stdlib::net::Net): each site
//! is a [`Host`] with a DNS name per site and a [`Website`] on ports 80
//! and 443, made when its name is first looked up. HTTP is [`httpd`], a
//! service like any other. A world that needs other services next to its
//! websites builds on `Net` directly.
//!
//! In this world, two sites are served by the world's own axum routers.
//! `en.wikipedia.org` has the IPv4 and IPv6 addresses it has on the real
//! internet. `api.stripe.com` serves a bad certificate one time in ten.
//! `github.com` and every name under it pass through to the real GitHub.
//! Every other name does not exist. The certificates come from the world's
//! own certificate authority (CA), loaded from the world's arguments. The
//! world function gets its context ([`Cx`]) and its sandboxes
//! ([`Attachments`]), as [A world in code](crate#a-world-in-code) explains:
//!
//! ```
//! # use std::net::{Ipv4Addr, Ipv6Addr};
//! # use std::sync::Arc;
//! # use fictionet::{Attachments, Cx, Result, stdlib::web};
//! # use rustls::ServerConfig;
//! # struct Certs { wikipedia: Arc<ServerConfig>, stripe: Arc<ServerConfig>, bad: Arc<ServerConfig>, github: Arc<ServerConfig> }
//! # fn my_certs(_args: &[String]) -> Result<Certs> { unimplemented!() }
//! async fn world(fcx: Cx, attachments: Attachments, args: Vec<String>) -> Result {
//! #   let wiki: axum::Router = axum::Router::new();
//! #   let fake_stripe: axum::Router = axum::Router::new();
//!     // Yours: an Arc<ServerConfig> per certificate, each issued by the world's CA.
//!     let certs = my_certs(&args)?;
//!
//!     web::Sites::new(move |host: &str| match host {
//!         "en.wikipedia.org" | "www.wikipedia.org" => Some(
//!             web::Site::new(wiki.clone())
//!                 .at(Ipv4Addr::new(185, 15, 59, 224))
//!                 .at("2a02:ec80:300:ed1a::1".parse::<Ipv6Addr>().unwrap())
//!                 .tls({ let c = certs.wikipedia.clone(); move |_| c.clone() }),
//!         ),
//!         "api.stripe.com" => Some(
//!             web::Site::new(fake_stripe.clone()) // an axum::Router
//!                 .tls({
//!                     let (real, fake) = (certs.stripe.clone(), certs.bad.clone());
//!                     move |fcx| if fcx.random_f64() < 0.1 { fake.clone() } else { real.clone() }
//!                 }),
//!         ),
//! #       #[cfg(feature = "tokio")]
//!         h if h == "github.com" || h.ends_with(".github.com") => Some(
//!             web::Site::new(web::proxy()) // the real site, over the world's own network
//!                 .tls({ let c = certs.github.clone(); move |_| c.clone() }), // github.com and *.github.com
//!         ),
//!         _ => None, // NXDOMAIN: the world stays closed
//!     })
//!     .serve(&fcx, attachments)?;
//!     Ok(()) // the sites keep running after the world returns
//! }
//! ```
//!
//! For HTTPS to work, the sandbox must trust the world's CA, and each site
//! must have a certificate for its names. [`Site::tls`] gives a site its
//! certificate. A site without `tls` serves plain HTTP only. Port 443 is
//! closed at its address, unless another site there has `tls`: then a TLS
//! handshake for its name is rejected.
//!
//! # The callback
//!
//! The callback runs the first time a hostname is looked up in DNS.
//!
//! - `Some(site)`: the site gets an address, a machine and a route, and DNS
//!   answers with that address.
//! - `None`: DNS answers NXDOMAIN.
//!
//! A site exists only once its name has been looked up. Connecting straight
//! to an IP address, without a lookup, works only if a site already lives
//! there. A TCP connection names only an address and a port, so a world
//! cannot learn the hostname before it must accept or refuse the
//! connection. An address with no site gets an ICMP "host unreachable"
//! reply. On a machine that exists, a TLS handshake or request for a name
//! that has no site at that address is rejected with `unrecognized_name`
//! or answered with `421 Misdirected Request` (unless a site there is the
//! [`default_host`](Site::default_host), which answers such requests). The
//! callback is not run for names seen there.
//!
//! The answer is kept for the whole run. The callback runs once per name, so
//! a site keeps its state between requests, and the agent always sees the
//! same address for a name. A site that should change over time does so
//! inside its handler.
//!
//! The agent chooses which names to look up, so two limits keep a flood of
//! made-up names from growing the world's memory without end:
//!
//! - **Names turned down.** 100,000 names the callback turned down (`None`)
//!   are remembered, which costs about 35 MB at most. Past that, a name
//!   turned down is not kept, and looking it up again runs the callback
//!   again.
//! - **Sites.** 20,000 names may have a site, unless the world sets
//!   another limit with [`Sites::max_sites`]. This matters for a callback
//!   that opens a whole domain, such as every name under `github.com`: each
//!   such name the agent tries gets a site, and a machine (about 11 KiB) for
//!   each of its addresses, so the default limit holds them to about
//!   430 MiB. Past the limit, a new name that the callback
//!   gives a site is answered with SERVFAIL, and its site is dropped before
//!   it gets an address or a machine. The name is not kept, so looking it
//!   up again runs the callback again.
//!
//! To see which names the agent tried, watch the `dns.query` events (see
//! [Events](#events)).
//!
//! # Handlers
//!
//! [`Site::new`] takes any [`tower_service::Service`] that takes an
//! `http::Request<web::Body>` and returns an `http::Response`. An
//! `axum::Router` is one. So is a plain async function wrapped in
//! `tower::service_fn`. So is `web::proxy()` (feature `tokio`, on by
//! default), which forwards to the real site. [`Site::handler`] takes an
//! [`httpd::Handler`] instead, such as an
//! [`httpd::Router`], whose handlers get plain
//! byte bodies and no runtime. A request's body is read whole before the
//! handler is called, up to 64 MiB; past that the answer is `413`.
//!
//! # Passing a site through to the real one
//!
//! A site whose handler is `web::proxy()`, such as `github.com` above, shows
//! the agent the real site's pages. Each request then travels over two
//! separate connections:
//!
//! 1. **From the sandbox to the world.** The agent's TLS connection ends at
//!    the world. The world finishes the handshake with the certificate from
//!    the site's [`tls`](Site::tls) config: one for `github.com`, issued by
//!    the world's CA. The sandbox must trust that CA, as it must for any
//!    site in the world. The agent sees the world's certificate, never
//!    GitHub's.
//! 2. **From the world to the real site.** For each request, the world
//!    process makes a new HTTPS request through its operating system's
//!    network, as any program on the host would. It resolves the name with
//!    the host's DNS, sends the name as its TLS SNI, and checks the real
//!    certificate against the Mozilla root store (`webpki-roots`). It
//!    offers HTTP/2 and HTTP/1.1, and uses whichever the real site picks.
//!    The scheme, host and port come from the [`Target`] of the agent's
//!    request, and the path and query from its URI. The `Host` header is
//!    set to that host. Hop-by-hop headers (`Connection`, `Keep-Alive`,
//!    `Transfer-Encoding` and the like) are dropped both ways. Every other
//!    header, and the body, passes through unchanged.
//!
//! The certificate for `github.com` lists `github.com` and `*.github.com`
//! as its names, so it covers `api.github.com` too. A name two levels
//! deeper, such as `a.b.github.com`, needs a certificate of its own.
//!
//! The site's `http.request` events show the request the agent sent and
//! the answer it got. If the real site cannot be reached, the agent gets
//! `502 Bad Gateway`.
//!
//! # What `serve` builds
//!
#![doc = include_str!("../../docs/diagrams/sites-network.svg")]
//!
//! - **The sandboxes' side.** Every sandbox that attaches, now or later,
//!   joins the same two subnets: `10.0.0.0/24` for IPv4, with the gateway
//!   and the DNS server at `10.0.0.1`, and `2001:db8::/64` for IPv6, with
//!   the gateway and the DNS server at `2001:db8::1`.
//!   [`subnet`](Sites::subnet) changes either one. A DHCP server hands out
//!   IPv4 addresses to sandboxes that ask for one, such as a test, or a VM
//!   attached with `fictionet attach --type tap` and no IPv4 address flags,
//!   whose DHCP then goes to the world (see
//!   [The VM's addresses](fictionet::attaching#the-vms-addresses)). Attach sets a `tun` sandbox's
//!   addresses itself, from `--ip-addr` and `--ip-addr-v6`, and runs no
//!   DHCP client. A sandbox with a fixed address is known by the source
//!   address of its first packet. Either way, the router gets a `/32` or
//!   `/128` route for each address through
//!   [`Router::add`](fictionet::stdlib::route::Router::add), and loses it when
//!   the sandbox detaches.
//! - **Each sandbox owns one address of each family, and only those.** The
//!   agent is the adversary and can send any packet it likes, so addresses
//!   are bound to attachments, not trusted from packets. The rules below
//!   are for IPv4. IPv6 follows the same rules, without DHCP: see
//!   [IPv6](#ipv6).
//!   - DHCP leases are keyed by attachment, not by the MAC address or client
//!     ID in the request, which the agent controls. An attachment holds at
//!     most one lease. Asking again returns the same address. A request for
//!     a specific address is granted only if that address is free.
//!   - DHCP from `0.0.0.0` to the DHCP server is always accepted, before and
//!     after binding, since a client that restarts sends from `0.0.0.0`
//!     again.
//!   - An address offered by DHCP is held for that attachment, and bound
//!     only when the server acknowledges it. A static address is bound from
//!     the first packet that is not DHCP, only if it is inside the subnet,
//!     not the gateway, and not held or bound for another attachment.
//!     Otherwise the packet is dropped and the attachment stays unbound.
//!   - After binding, every other packet from that attachment must carry
//!     its address as the source. Others are dropped. A sandbox cannot take
//!     another's route, because [`Router::add`](fictionet::stdlib::route::Router::add)
//!     is only called for a newly bound, free address.
//!   - The binding ends when the sandbox detaches, and the address becomes
//!     free again. Its TCP connections to the sites and the gateway are
//!     reset first, so data still on its way to it, such as the rest of a
//!     download, never reaches the next sandbox to take the address.
//! - **Sandboxes cannot reach each other.** Each sandbox's packets pass
//!   through a small filter task before the router. It drops any packet
//!   addressed to the sandboxes' subnet other than the gateway. There is no
//!   option to turn this off: two agents in separate eval samples must not
//!   see each other. A world that wants sandboxes on one shared network wires it
//!   by hand with [`router`](fictionet::stdlib::route::router).
//! - **Fragments are put back together in each sandbox's filter.** Each
//!   fragment must pass the checks above on its own. The filter then holds
//!   it until its packet is whole, and sends the router only whole packets,
//!   with the rules and limits of
//!   [`split_protocols`](fictionet::stdlib::ip::split_protocols): overlapping
//!   fragments drop the packet, unfinished packets are dropped after 30
//!   seconds (IPv4) or 60 seconds (IPv6), and at most 4 MiB of fragments
//!   wait in each filter. A filter's fragments end with it, so a fragment a
//!   sandbox sent before it detached can never complete a packet for the
//!   next sandbox to take its address.
//! - **DNS** at the gateway, at both of its addresses. It answers A and
//!   AAAA records for sites, NODATA for other record types of their names,
//!   and NXDOMAIN for names the callback turned down.
//! - **Addresses.** Every site has an IPv4 and an IPv6 address, unless it
//!   is made [`ipv4_only`](Site::ipv4_only) or
//!   [`ipv6_only`](Site::ipv6_only). A site with [`at`](Site::at) uses the
//!   addresses given there. For a family without one, it gets a free
//!   address from a range set aside for testing: `198.18.0.0/15` for IPv4,
//!   `2001:2::/48` for IPv6. Sites with the same address share one
//!   machine.
//! - **A router** with one route per machine, added as sites appear. A
//!   packet for any other address gets an ICMP "host unreachable" reply, or
//!   an ICMPv6 "address unreachable" reply, so a client fails immediately
//!   with "No route to host" instead of waiting for a timeout.
//! - **Ports 80 and 443.** Ports belong to an address, not a site, because
//!   a TCP connection names only an address and port until the client sends
//!   a hostname. Port 80 is open on every machine. Port 443 is open on a
//!   machine if any site at its address has [`tls`](Site::tls), and refuses
//!   connections otherwise. Once the client names a host:
//!   - a site with `tls`: served over HTTPS on 443. On port 80 it answers
//!     with a 301 redirect to https, unless it also has
//!     [`plain_http`](Site::plain_http): then its handler answers on port
//!     80 too.
//!   - a site without `tls`: served over plain HTTP on 80. A TLS handshake
//!     for its name on 443 is rejected with `unrecognized_name`.
//! - **HTTP/1.0, HTTP/1.1 and HTTP/2** on every connection: HTTP/1 with
//!   [`httpd::Http1`], HTTP/2 with hyper for
//!   now. Over TLS, the
//!   version is agreed in the handshake (ALPN): `serve` sets the ALPN list
//!   of each config to `h2` and `http/1.1`, so a browser gets HTTP/2 and
//!   `curl` gets what it asks for. Without TLS, the version is read from the
//!   first bytes the client sends. HTTP/2 streams run as tasks in the
//!   connection's [region](fictionet::Cx#regions).
//! - **Routing by host.** Each request goes to the site for its host: the
//!   authority of its URI if it has one (the `:authority` in HTTP/2, or an
//!   absolute URI in HTTP/1.1), else its `Host` header. A host with no site
//!   at the address gets `421 Misdirected Request`, unless a site there is
//!   the [`default_host`](Site::default_host).
//! - **A [`Target`] on every request.** Before calling a handler, `serve`
//!   puts a `Target` in the request's extensions. Its scheme and port come
//!   from the connection, not from headers: TLS or not, and the port the
//!   connection arrived on. Its host comes from the request, the same
//!   authority or `Host` header that chose the site. Its SNI comes from the
//!   TLS client hello. Handlers read it with
//!   `request.extensions().get::<web::Target>()`, or with axum's
//!   `Extension` extractor.
//!
//! How one sandbox's IPv4 address is bound, as its filter sees it:
//!
#![doc = include_str!("../../docs/diagrams/sites-binding.svg")]
//!
//! # IPv6
//!
//! The network `Sites` builds is dual-stack, as most of the real internet
//! is. A sandbox attached with IPv6 reaches every site over either family.
//! These are its attach flags ([Addresses](fictionet::attaching#addresses)
//! explains each one):
//!
//! ```text
//! fictionet attach --world unix:/run/fictionet/world.sock --name agent --type tun \
//!     --ip-addr 10.0.0.2/24 --gateway 10.0.0.1 --dns 10.0.0.1 \
//!     --ip-addr-v6 2001:db8::2/64 --gateway-v6 2001:db8::1 --dns-v6 2001:db8::1
//! ```
//!
//! A client that looks up a name gets both an A and an AAAA record.
//! glibc's `getaddrinfo` puts the IPv6 address first, so most clients try
//! IPv6 first. Clients that implement Happy Eyeballs (RFC 8305), such as
//! curl, fall back to IPv4 if IPv6 fails or is slow.
//!
//! Why these prefixes:
//!
//! - **The sandboxes' subnet, `2001:db8::/64`,** is the documentation
//!   prefix, so it never collides with a real network. It is not a unique
//!   local (`fd00::/8`) prefix on purpose. Clients sort addresses by the
//!   rules of RFC 6724, and with a unique local source address they prefer
//!   IPv4 for every site with a global address. With a global-looking
//!   source address, they prefer IPv6, as on a real dual-stack network.
//! - **Sites' automatic addresses, `2001:2::/48`,** come from the range
//!   set aside for benchmarking (RFC 5180), as `198.18.0.0/15` is for IPv4.
//!
//! How IPv6 works here:
//!
//! - **Addresses are static.** `Sites` runs no DHCPv6 and sends no router
//!   advertisements. A sandbox's IPv6 address is bound by its first packet
//!   from an address inside the subnet, other than the subnet's first
//!   address and the gateway. After that, the rules are the same as for
//!   IPv4: other sources are dropped, and the address is free again when
//!   the sandbox detaches. A sandbox gets one `net.bound` event for each
//!   family.
//! - **The kernel's own packets do no harm.** A Linux sandbox sends router
//!   solicitations and multicast listener reports from its link-local
//!   address as soon as `tun0` comes up. Packets to multicast addresses are
//!   dropped before binding, so they never bind the wrong address.
//! - **No neighbor resolution is needed.** A `tun` device carries IP
//!   packets with no link layer, so the sandbox's kernel sends to the
//!   gateway directly, without asking for its hardware address. A VM
//!   attached with `tap` does ask, and attach answers it on the VM's link
//!   (see [`lowering`](fictionet::lowering#tap-ethernet-frames-with-the-ethernet-taken-off)).
//!   `Sites` sends no router advertisements, so such a VM gets its IPv6
//!   address from attach's `--ip-addr-v6`, or sets one itself.
//! - **Fallback is quick.** A site made [`ipv4_only`](Site::ipv4_only) gets
//!   NODATA for AAAA, so clients go straight to IPv4. One made
//!   [`ipv6_only`](Site::ipv6_only) gets NODATA for A. An address with no
//!   site gets "address unreachable" immediately. A sandbox attached without
//!   IPv6 has no IPv6 route, so its connections to an IPv6 address fail
//!   immediately and the client moves on to IPv4.
//! - **No MTU limit inside the world.** Packets cross the world as whole
//!   packets, and TCP sizes its segments from the sandbox's own MSS, so
//!   `Sites` never needs to send "packet too big".
//! - **Extension headers are checked as a host checks them.** The gateway
//!   and every machine check Hop-by-Hop Options, Routing and Destination
//!   Options headers as RFC 8200 asks, and take out the ones that pass, so
//!   TCP, UDP and ICMPv6 behind them work as they would without them. Each
//!   fragment's headers are checked as it arrives. A
//!   packet that fails is dropped, and answered with ICMPv6 "parameter
//!   problem" where the RFC asks for one, such as for a Routing header with
//!   segments left: the machines here forward no source-routed packets.
//!   Only the gateway and the machines answer that way. A packet to an
//!   address no machine has gets "address unreachable", whatever its
//!   headers say.
//!   [`split_protocols`](fictionet::stdlib::ip::split_protocols) lists the
//!   rules.
//! - **UDP always has a checksum.** A UDP datagram over IPv6 whose checksum
//!   field is zero is dropped, as RFC 8200 requires. Over IPv4, zero means
//!   the sender left the checksum out, and the datagram is accepted.
//!
//! [`Sites::ipv4_only`] turns IPv6 off for a world that models an IPv4-only
//! network. Sandboxes for such a world attach with `--no-ip-addr-v6
//! --no-gateway-v6 --no-dns-v6`.
//!
//! # Events
//!
//! Much of what the agent does never reaches a handler. `Sites` answers DNS,
//! rejects TLS handshakes, sends redirects and `421`s, and drops packets on
//! its own. `Sites` records all of it in the run's
//! [events](fictionet::events), one event for each of these, in the shape
//! every service uses:
//!
//! - `net.attached`, `net.bound` (field `by_dhcp`, `addr`) and
//!   `net.detached`: a sandbox attaches, gets an address, or detaches;
//! - `dns.query`: every DNS message, over UDP or TCP, with its answer:
//!   fields `tcp`, `name`, `qtype`, `answer` (`addr`, `nodata`, `nxdomain`,
//!   `error` or `none`), `addr` and `rcode`;
//! - `tls.handshake`: every TLS handshake on port 443, with `addr`, `sni`
//!   and `outcome` (`accepted` with `alpn`, `rejected`, `alert` with
//!   `alert` (name) and `alert_code` (number), `failed` with `detail`,
//!   `closed`, `timed_out`, `detached`
//!   or `cancelled`);
//! - `http.request`: every HTTP request, with who answered it (`answer`:
//!   `handler`, `error`, `redirect`, `misdirected`, `no_host` or
//!   `cancelled`), its status, and how much of the body was sent, also
//!   when the client gave up before the answer
//!   ([`httpd`](fictionet::stdlib::httpd#events) lists the fields);
//! - `http.error`: every connection on port 80 or 443 that ended in an HTTP
//!   error (`cause`: `protocol`, `timeout` or `transport`);
//! - `net.blocked`: the packets `Sites` itself drops or refuses, with
//!   `why` (see [`BlockedWhy`](fictionet::stdlib::net::BlockedWhy)),
//!   `protocol`, `src`, `dst`, `dst_port` and `count`. These are
//!   [repeats](fictionet::events#repeats): a scan or a flood is counted, not
//!   kept packet by packet.
//!
//! Every event names the sandbox it came from; events about a connection
//! carry its number, from 1, on both ports. A connection's `tls.handshake`
//! comes before its requests. An event is made when the thing it reports
//! ends, so HTTP/2 requests on one connection can end in any order; the
//! `started` field gives when each arrived.
//!
//! One HTTPS request to a site with [`tls`](Site::tls), from its lookup to
//! its events:
//!
#![doc = include_str!("../../docs/diagrams/sites-request.svg")]
//!
//! Callbacks set with [`EventLog::subscribe`](fictionet::events::EventLog::subscribe)
//! run inside the task that recorded the event. Every task of a world runs
//! on one thread, so a slow callback slows the whole world. Hand the event
//! to a channel that never waits, and do the work elsewhere, or write the
//! events to a file with
//! [`EventLog::to_file`](fictionet::events::EventLog::to_file), which does that
//! for you:
//!
//! ```
//! # use fictionet::{Attachments, Cx, Result, stdlib::web};
//! # fn site_for(_host: &str) -> Option<web::Site> { None }
//! # fn world(fcx: Cx, attachments: Attachments) -> Result {
//! let events = fcx.events();
//! events.to_file("/var/lib/fictionet/events.jsonl")?;
//! web::Sites::new(site_for).serve(&fcx, attachments)?;
//! // At the end of the sample: events.lost() must be zero.
//! # Ok(())
//! # }
//! ```
//!
//! A handler can add its own fields to its request's event. It puts
//! [`Fields`](fictionet::events::Fields) in the extensions of the
//! response it returns. Response extensions are never sent to the agent.
//! The FakeWiki eval in `examples/fakewiki` puts the kind and stance of
//! each page there, so one log line holds what the agent asked for and what
//! it was shown.
//!
//! Events do not hold packets or bodies. A world that wants every packet
//! puts a [`filter`](fictionet::stdlib::filter) between each sandbox and
//! `Sites`, as [Changing the network around the
//! sites](#changing-the-network-around-the-sites) shows. The
//! [packet capture recipe](fictionet::recipes#packet-capture) writes them all
//! to a pcap file.
//!
//! # Details
//!
//! - **Names.** The callback gets each name in lowercase, without the
//!   trailing dot. Lookups of `Example.COM.` and `example.com` are the same
//!   lookup. Answers have a TTL of 60 seconds.
//! - **Automatic addresses** are handed out in order from `198.18.0.1` and
//!   `2001:2::1`. Addresses inside the sandboxes' subnets are skipped, so a
//!   subnet such as `198.18.0.0/24` works too. A subnet that covers all of
//!   `198.18.0.0/15` or `2001:2::/48` leaves no automatic addresses of that
//!   family: sites without [`at`](Site::at) then have only the other
//!   family, and a site with neither gets NXDOMAIN.
//! - **Machines** answer pings, refuse TCP on ports other than 80 and 443
//!   with a RST, and answer UDP with ICMP "port unreachable", over both
//!   families. The gateway answers pings, and DNS on UDP and TCP port 53.
//! - **TLS without a name.** A handshake with no SNI, as from a client that
//!   connected to a bare IPv4 or IPv6 address, is rejected with
//!   `unrecognized_name`. Clients never send an IP address as the SNI, so
//!   certificates for IP addresses are never used.
//! - **Limits per sandbox.** A sandbox may have 256 connections open at
//!   the same time to one machine (both ports together), and 256 to the gateway's
//!   DNS over TCP at each of its addresses. A machine has one address, so
//!   a dual-stack site is two machines, and a sandbox may have 256 open to
//!   each. A connection counts until it has finished closing, so
//!   one that the server closed but the sandbox never closed on its side
//!   still counts, for up to a minute. Past that, a new connection is reset
//!   as soon as it is accepted. Every open connection costs a machine a
//!   little on every packet, and machines are shared, so one sandbox must
//!   not slow a site down for the others.
//! - **Queues.** Each link inside the network, from a sandbox to the
//!   router and from the router to a machine, holds at most 4 MiB of
//!   packets each way, counting 64 bytes more for each packet. Past that,
//!   packets are dropped, as on a congested link, and TCP sends them
//!   again. Sandboxes that together send faster than the router forwards
//!   lose packets instead of growing the world's memory.
//! - **Timeouts.** A client has 10 seconds from connecting to finish its
//!   TLS handshake, or on port 80 to send the first bytes of its request.
//!   An HTTP/1.1 connection is closed when a request's headers take more
//!   than 30 seconds to arrive, which includes waiting between requests. A
//!   DNS-over-TCP connection is closed after 10 seconds with no query.
//! - **Lengths.** A response body whose length is known, such as a `String`
//!   or an `http_body_util::Full`, is sent with `content-length`, as real
//!   servers send it. A body of unknown length is sent chunked on HTTP/1.1.
//! - **HEAD.** The answer to a `HEAD` request has the headers a `GET` would
//!   get and no body, on HTTP/1.1 and HTTP/2. A body of known length keeps
//!   its length as `content-length`. Handlers need not handle `HEAD`
//!   themselves.
//! - **No host.** A request with no `Host` header and no authority gets
//!   `400 Bad Request`.
//! - **Half-close.** An HTTP/1 client that shuts down its side of the
//!   connection after its request (as `nc -N` and many HTTP/1.0 scripts
//!   do) still gets the response.
//! - **Handler errors.** A handler that returns an error gets the client a
//!   `500 Internal Server Error`. `proxy()` errors, where the real site
//!   could not be reached, give `502 Bad Gateway`.
//! - **DHCP.** Leases last an hour, with renewal after 30 minutes. The
//!   answer carries the subnet mask, and the gateway as router and DNS
//!   server. Renewals are answered as long as the sandbox stays attached.
//!   RELEASE and DECLINE change nothing: the address stays bound until the
//!   sandbox detaches. INFORM from a sandbox's own address is answered with
//!   the settings, also when it is the sandbox's first packet. An INFORM
//!   does not bind the address. Replies go to the client's address if it
//!   has one, else to `255.255.255.255`. The subnet's network and broadcast addresses are
//!   never bound.
//!
//! # Changing the network around the sites
//!
//! `serve` takes the world's [`Attachments`], so it serves every sandbox
//! that attaches. To change the path between the sandboxes and the sites,
//! wrap each sandbox before `serve` sees it, with
//! [`Attachments::map`](fictionet::Attachments::map). Here every sandbox gets a
//! 200 ms delay each way, in front of everything `Sites` builds:
//!
//! ```
//! # use fictionet::{Attachments, Cx, Result, stdlib::{self, web}, time::ms};
//! # fn site_for(_host: &str) -> Option<web::Site> { None }
//! # fn world(fcx: Cx, attachments: Attachments) -> Result {
//! let far = attachments.map(&fcx, |fcx, sandbox| stdlib::delay(fcx, ms(200), sandbox));
//! web::Sites::new(site_for).serve(&fcx, far)?;
//! # Ok(())
//! # }
//! ```
//!
//! `Sites` sees each sandbox through its delay, under the same name, and
//! binds its addresses and reports its events as usual. The same works with
//! [`bottleneck`](fictionet::stdlib::bottleneck) for a slow link, and with
//! [`filter`](fictionet::stdlib::filter) to watch or drop packets. The
//! [recipes](fictionet::recipes) run each of these, with a route that changes
//! mid-run, and show what the sandbox sees.
//!
//! Every part of `Sites` is built from public stdlib items, so a world can
//! also write any part itself. [`Sites::into_net`] gives the
//! [`Net`] before it starts, to add hosts with
//! other services next to the websites. To change how `Sites` turns a site
//! into a host, copy this file into your crate and edit
//! [`Site::into_host`]. The copy compiles there as it is, with the same
//! `fictionet::` imports, and the fixture in `tests/copy_and_own` checks
//! that it does. What the network does around the hosts, such as how
//! addresses are bound or how DNS answers, is
//! [`net`](fictionet::stdlib::net)'s, and a copy of that file changes it.


use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use http::{Request, Response};

pub use fictionet::stdlib::httpd::{Body, Target};
use fictionet::stdlib::httpd::{self, Handler, Website};
use fictionet::stdlib::net::{Host, Net};
use fictionet::stdlib::route::Prefix;
use fictionet::stdlib::tls::ServerConfig;
use fictionet::{Attachments, Cx, Error};

/// Websites by hostname, and the network around them. See the
/// [module docs](self).
pub struct Sites {
    site_for: Arc<SiteFor>,
    subnet: Prefix,
    subnet_v6: Prefix,
    ipv6: bool,
    max_sites: usize,
    date: Option<std::time::SystemTime>,
}

/// The callback given to [`Sites::new`].
type SiteFor = dyn Fn(&str) -> Option<Site> + Send + Sync;

impl Sites {
    /// Sites decided by `site_for`, which gets a hostname and returns the
    /// site for it, or `None` if it does not exist. It runs once per name.
    ///
    /// The name is in lowercase, without a trailing dot: `en.wikipedia.org`.
    ///
    /// `site_for` must return quickly and must not block. It runs inside the
    /// DNS task, and every sandbox's lookups wait while it runs. It decides.
    /// It does not fetch. Slow work belongs in the site's handler.
    pub fn new<F>(site_for: F) -> Sites
    where
        F: Fn(&str) -> Option<Site> + Send + Sync + 'static,
    {
        Sites {
            site_for: Arc::new(site_for),
            subnet: Prefix { addr: Ipv4Addr::new(10, 0, 0, 0).into(), len: 24 },
            subnet_v6: Prefix { addr: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0).into(), len: 64 },
            ipv6: true,
            max_sites: fictionet::stdlib::net::MAX_HOSTS,
            date: None,
        }
    }

    /// Sets the world's date and time at the start of the run. Every site
    /// then sends a `Date` header: this date plus the run's clock. Without
    /// it, responses have no `Date` header; the host's clock is never used.
    /// See [`httpd`'s Dates](fictionet::stdlib::httpd#dates).
    pub fn date(self, start: std::time::SystemTime) -> Sites {
        Sites { date: Some(start), ..self }
    }

    /// Sets the sandboxes' IPv4 or IPv6 subnet, whichever `subnet` is. The
    /// gateway and DNS server take the address after the subnet's own
    /// address, such as `10.0.0.1` in `10.0.0.0/24` or `2001:db8::1` in
    /// `2001:db8::/64`. The IPv4 subnet defaults to `10.0.0.0/24`, and the
    /// IPv6 subnet to `2001:db8::/64`.
    /// To set both, call it twice.
    ///
    /// An IPv4 subnet must have a length from 8 to 30. An IPv6 subnet must
    /// have a length from 8 to 126, and lie inside the global unicast
    /// range `2000::/3` or the unique local range `fc00::/7`. Otherwise
    /// [`serve`](Sites::serve) fails.
    pub fn subnet(self, subnet: Prefix) -> Sites {
        match subnet.addr {
            IpAddr::V4(_) => Sites { subnet, ..self },
            IpAddr::V6(_) => Sites { subnet_v6: subnet, ..self },
        }
    }

    /// Turns IPv6 off for the whole network. Sites then have only IPv4
    /// addresses, DNS answers AAAA queries with NODATA, and every IPv6
    /// packet from a sandbox is dropped, with a `net.blocked` event whose
    /// `why` is `Ipv6`.
    ///
    /// Without this, the network is dual-stack: see [IPv6](self#ipv6).
    pub fn ipv4_only(self) -> Sites {
        Sites { ipv6: false, ..self }
    }

    /// Sets how many names may have a site. The default is 20,000.
    ///
    /// Each name the callback gives a site is kept for the whole run, with
    /// its machines. At the limit, a new name still runs the callback. If it
    /// returns a site, that site is dropped before it gets an address or a
    /// machine, DNS answers SERVFAIL, and the `dns.query` event says
    /// `error` with `rcode` 2. The name is not kept, so looking it up again
    /// runs the callback again.
    pub fn max_sites(self, max_sites: usize) -> Sites {
        Sites { max_sites, ..self }
    }

    /// The network these sites run on, before it starts: to add hosts
    /// with other services next to the websites.
    pub fn into_net(self) -> Net {
        let site_for = self.site_for;
        let date = self.date;
        let mut net = Net::new()
            .group("web::Sites")
            .subnet(self.subnet)
            .subnet(self.subnet_v6)
            .max_hosts(self.max_sites)
            .resolve(move |name| {
                site_for(name).map(|mut site| {
                    if let Some(date) = date {
                        site.website = site.website.date(date);
                    }
                    site.into_host(name)
                })
            });
        if !self.ipv6 {
            net = net.ipv4_only();
        }
        net
    }

    /// Builds the network and starts it. Every sandbox in `attachments`,
    /// including ones that attach later, is connected to the sites.
    ///
    /// Returns immediately. The network runs in background tasks in `fcx`'s
    /// [region](fictionet::Cx#regions), and keeps running after the world
    /// returns, until that region is cancelled.
    ///
    /// Fails only if a [`subnet`](Sites::subnet) is not one it can use.
    pub fn serve(self, fcx: &Cx, attachments: Attachments) -> Result<(), Error> {
        self.into_net().serve(fcx, attachments)
    }
}

/// One website: a handler, and optionally an address and TLS.
pub struct Site {
    website: Website,
    at: Option<Ipv4Addr>,
    at_v6: Option<Ipv6Addr>,
    family: Family,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Family {
    Both,
    V4,
    V6,
}

impl Site {
    /// A site served by `service`, a tower service such as an
    /// `axum::Router`. See [Handlers](self#handlers).
    pub fn new<S, B>(service: S) -> Site
    where
        S: tower_service::Service<Request<Body>, Response = Response<B>> + Clone + Send + 'static,
        S::Future: Send + 'static,
        S::Error: Into<Error>,
        B: http_body::Body + Send + 'static,
        B::Data: Send,
        B::Error: Into<Error>,
    {
        Site::handler(httpd::tower(service))
    }

    /// A site served by an [`httpd::Handler`], such as an
    /// [`httpd::Router`].
    pub fn handler(handler: impl Handler) -> Site {
        Site { website: Website::new(handler), at: None, at_v6: None, family: Family::Both }
    }

    /// Serves the site at `addr`, for example the address it has on the
    /// real internet. `addr` may be an [`Ipv4Addr`], an [`Ipv6Addr`] or an
    /// [`IpAddr`], and sets the site's address of that family. A site that
    /// has both A and AAAA records on the real internet takes both
    /// addresses, with two calls:
    ///
    /// ```
    /// # use std::net::{Ipv4Addr, Ipv6Addr};
    /// # use fictionet::stdlib::web;
    /// # let wiki: axum::Router = axum::Router::new();
    /// let site = web::Site::new(wiki)
    ///     .at(Ipv4Addr::new(185, 15, 59, 224))
    ///     .at("2a02:ec80:300:ed1a::1".parse::<Ipv6Addr>().unwrap());
    /// # drop(site);
    /// ```
    ///
    /// A family without `at` gets a free address from that family's pool:
    /// `198.18.0.0/15` for IPv4, `2001:2::/48` for IPv6. An address given
    /// for a family the site does not have (see
    /// [`ipv4_only`](Site::ipv4_only)) is not used.
    ///
    /// The address must not be inside the sandboxes' subnet, and must be
    /// one a host can have: not unspecified, broadcast, multicast or
    /// loopback. An IPv6 address must also not be link-local (`fe80::/10`)
    /// or IPv4-mapped. If it is not, the site is not served and the name
    /// gets NXDOMAIN. IPv4 link-local addresses are allowed, so a world can
    /// serve a site at `169.254.169.254`.
    pub fn at(self, addr: impl Into<IpAddr>) -> Site {
        match addr.into() {
            IpAddr::V4(a) => Site { at: Some(a), ..self },
            IpAddr::V6(a) => Site { at_v6: Some(a), ..self },
        }
    }

    /// Gives the site only an IPv4 address. DNS answers AAAA queries for
    /// its name with NODATA, so clients connect over IPv4.
    pub fn ipv4_only(self) -> Site {
        Site { family: Family::V4, ..self }
    }

    /// Gives the site only an IPv6 address. DNS answers A queries for its
    /// name with NODATA, so a sandbox without IPv6 cannot reach it. On a
    /// network with IPv6 turned off ([`Sites::ipv4_only`]) the site has
    /// no address at all, and its name gets NXDOMAIN.
    pub fn ipv6_only(self) -> Site {
        Site { family: Family::V6, ..self }
    }

    /// Serves the site over HTTPS. `config_for` runs on every handshake and
    /// returns the TLS config to use, so it can choose differently each time,
    /// with randomness from `fcx`. To use one config every time, return a
    /// clone of it.
    ///
    /// `serve` replaces the ALPN list of the returned config with `h2` and
    /// `http/1.1`, so the config does not need one.
    pub fn tls<F>(self, config_for: F) -> Site
    where
        F: Fn(&Cx) -> Arc<ServerConfig> + Send + Sync + 'static,
    {
        Site { website: self.website.tls(config_for), ..self }
    }

    /// Serves a site with [`tls`](Site::tls) over plain HTTP on port 80
    /// as well. Its handler answers those requests, instead of the 301
    /// redirect to https that a TLS site gets by default.
    ///
    /// This is a site that never moved to HTTPS, or a machine that answers
    /// in plain text where the real site would redirect, as an attacker
    /// that strips TLS does. The handler tells the two kinds of request
    /// apart by [`Target::scheme`].
    pub fn plain_http(self) -> Site {
        Site { website: self.website.plain_http(), ..self }
    }

    /// Makes the site the default one at its address: it answers requests
    /// whose host names no site there, as a web server's default virtual
    /// host does. A client that types the address instead of a name
    /// (`http://203.0.113.10/`) reaches it, and so does any `Host` header.
    /// Without this, such requests get `421 Misdirected Request`.
    ///
    /// The request's [`Target`] keeps the host the client named. The rest
    /// is as for any request to the site: over plain HTTP, a site with
    /// [`tls`](Site::tls) redirects to https (to the host the client
    /// named) unless it has [`plain_http`](Site::plain_http). A TLS
    /// handshake still needs an SNI that names a site at the address.
    ///
    /// The first default site that appears at an address keeps the role.
    pub fn default_host(self) -> Site {
        Site { website: self.website.default_host(), ..self }
    }

    /// The site as a host of a [`Net`], named `name`.
    pub fn into_host(self, name: &str) -> Host {
        let mut host = self.website.served_by(Host::new(name).dns_name(name));
        if let Some(a) = self.at {
            host = host.at(a);
        }
        if let Some(a) = self.at_v6 {
            host = host.at(a);
        }
        match self.family {
            Family::Both => host,
            Family::V4 => host.ipv4_only(),
            Family::V6 => host.ipv6_only(),
        }
    }
}

/// A handler that forwards each request to the real site, over the world's
/// own network. Needs the `tokio` feature (on by default), and a tokio
/// runtime polling the world.
///
/// It needs no arguments: it forwards to the [`Target`] that [`Sites`] puts
/// on every request, so the scheme, host and port come from the connection
/// the agent made, not from headers. The path and query come from the
/// request. The world process makes a new, separate request there through
/// its operating system's network, resolving the name with its own DNS, and
/// returns the answer to the agent.
///
/// The agent never touches the real internet: its connection ends at the
/// world. Over HTTPS the agent sees the world's certificate, from
/// [`Site::tls`], and the real certificate stays between the world and the
/// real site.
///
/// Only names the callback hands to `proxy()` are forwarded, so the world
/// stays closed unless it opens a name on purpose. To change some responses
/// and pass the rest through, wrap it in tower or axum middleware.
///
/// The world checks the real site's certificate against the Mozilla root
/// store (`webpki-roots`). Hop-by-hop headers (`Connection`, `Keep-Alive`,
/// `Transfer-Encoding` and the like) are not passed on in either direction,
/// so it carries no protocol upgrades: a WebSocket handshake reaches the
/// real site as a plain `GET`. A world that wants WebSockets serves them
/// itself, with a handler on the site (see [`httpd`'s upgrades](fictionet::stdlib::httpd)).
/// If the real site cannot be reached, the agent gets `502 Bad Gateway`.
#[cfg(feature = "tokio")]
#[cfg_attr(docsrs, doc(cfg(feature = "tokio")))]
pub fn proxy() -> Proxy {
    Proxy { client: Arc::new(proxy_client()) }
}

/// The handler made by [`proxy`].
#[cfg(feature = "tokio")]
#[cfg_attr(docsrs, doc(cfg(feature = "tokio")))]
#[derive(Clone)]
pub struct Proxy {
    client: Arc<ProxyClient>,
}

#[cfg(feature = "tokio")]
impl tower_service::Service<Request<Body>> for Proxy {
    type Response = Response<hyper::body::Incoming>;
    type Error = Error;
    type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<Body>) -> Self::Future {
        Box::pin(forward(self.client.clone(), request))
    }
}

#[cfg(feature = "tokio")]
type ProxyClient = hyper_util::client::legacy::Client<
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    Body,
>;

#[cfg(feature = "tokio")]
fn proxy_client() -> ProxyClient {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_provider_and_webpki_roots(provider)
        .expect("ring supports the default TLS versions")
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .build();
    hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new()).build(connector)
}

/// Headers that belong to one connection and are not passed on (RFC 9110,
/// section 7.6.1).
#[cfg(feature = "tokio")]
const HOP_BY_HOP: [&str; 8] =
    ["connection", "keep-alive", "proxy-connection", "transfer-encoding", "te", "trailer", "upgrade", "proxy-authorization"];

#[cfg(feature = "tokio")]
fn strip_hop_by_hop(headers: &mut http::HeaderMap) {
    let named: Vec<String> = headers
        .get_all(http::header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(',').map(|s| s.trim().to_ascii_lowercase()))
        .collect();
    for name in HOP_BY_HOP.iter().copied().chain(named.iter().map(String::as_str)) {
        headers.remove(name);
    }
}

/// Forwards one request to its [`Target`] over the world's own network.
#[cfg(feature = "tokio")]
async fn forward(client: Arc<ProxyClient>, request: Request<Body>) -> Result<Response<hyper::body::Incoming>, Error> {
    use http::uri::Scheme;
    let target = request
        .extensions()
        .get::<Target>()
        .cloned()
        .ok_or_else(|| fictionet::Error::msg("web::proxy() serves only requests that web::Sites routed: there is no web::Target"))?;
    let (mut parts, body) = request.into_parts();
    let default_port = (target.scheme == Scheme::HTTP && target.port == 80) || (target.scheme == Scheme::HTTPS && target.port == 443);
    let authority = if default_port { target.host.clone() } else { format!("{}:{}", target.host, target.port) };
    let path = parts.uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    parts.uri = format!("{}://{}{}", target.scheme, authority, path).parse()?;
    parts.version = http::Version::HTTP_11;
    parts.extensions = http::Extensions::new();
    strip_hop_by_hop(&mut parts.headers);
    parts.headers.insert(http::header::HOST, authority.parse()?);
    let mut response = client
        .request(Request::from_parts(parts, body))
        .await
        .map_err(|e| httpd::BadGateway(format!("{}: {e}", target.host)))?;
    strip_hop_by_hop(response.headers_mut());
    Ok(response)
}
