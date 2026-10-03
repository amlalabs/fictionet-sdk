//! Websites by hostname: a whole network of sites in a few lines.
//!
//! Start here when the world you want is a set of websites, real or made
//! up, for an agent to browse. [`Sites`] takes a callback that decides, for
//! each hostname, whether a site exists and what it is. It builds the whole
//! network around the answers: DNS, addresses, a router, one machine per
//! address, TLS, and HTTP. You write only the sites.
//!
//! `Sites` is plain stdlib code, built from the same public pieces a world
//! could use by hand: [`ip`](crate::stdlib::ip),
//! [`route`](crate::stdlib::route), [`tcp`](crate::stdlib::tcp),
//! [`udp`](crate::stdlib::udp), [`dns`](crate::stdlib::dns) and
//! [`tls`](crate::stdlib::tls).
//!
//! In this world, two sites are served by the world's own axum routers.
//! `en.wikipedia.org` has the IPv4 and IPv6 addresses it has on the real
//! internet. `api.stripe.com` serves a bad certificate one time in ten.
//! `github.com` and every name under it pass through to the real GitHub.
//! Every other name does not exist. The certificates come from the world's
//! own certificate authority (CA), loaded from the world's arguments. The
//! world function gets its context ([`Cx`](crate::Cx)) and its sandboxes
//! ([`Attachments`](crate::Attachments)), as
//! [A world in code](crate#a-world-in-code) explains:
//!
//! ```
//! # use std::net::{Ipv4Addr, Ipv6Addr};
//! # use std::sync::Arc;
//! # use fictionet::{Attachments, Cx, Result, stdlib::web};
//! # use rustls::ServerConfig;
//! # struct Certs { wikipedia: Arc<ServerConfig>, stripe: Arc<ServerConfig>, bad: Arc<ServerConfig>, github: Arc<ServerConfig> }
//! # fn my_certs(_args: &[String]) -> Result<Certs> { unimplemented!() }
//! async fn world(cx: Cx, attachments: Attachments, args: Vec<String>) -> Result {
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
//!                     move |cx| if cx.random_f64() < 0.1 { fake.clone() } else { real.clone() }
//!                 }),
//!         ),
//! #       #[cfg(feature = "tokio")]
//!         h if h == "github.com" || h.ends_with(".github.com") => Some(
//!             web::Site::new(web::proxy()) // the real site, over the world's own network
//!                 .tls({ let c = certs.github.clone(); move |_| c.clone() }), // github.com and *.github.com
//!         ),
//!         _ => None, // NXDOMAIN: the world stays closed
//!     })
//!     .serve(&cx, attachments)?;
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
//! To see which names the agent tried, watch the [`Dns`] events (see
//! [Events](#events)).
//!
//! # Handlers
//!
//! A handler is any [`tower_service::Service`] that takes an
//! `http::Request` and returns an `http::Response`. An `axum::Router` is
//! one. So is a plain async function wrapped in `tower::service_fn`. So is
//! `web::proxy()` (feature `tokio`, on by default), which forwards to the
//! real site.
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
//! The site's [`Http`] events show the request the agent sent and the
//! answer it got. If the real site cannot be reached, the agent gets
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
//!   [The VM's addresses](crate::attaching#the-vms-addresses)). Attach sets a `tun` sandbox's
//!   addresses itself, from `--ip-addr` and `--ip-addr-v6`, and runs no
//!   DHCP client. A sandbox with a fixed address is known by the source
//!   address of its first packet. Either way, the router gets a `/32` or
//!   `/128` route for each address through
//!   [`Router::add`](crate::stdlib::route::Router::add), and loses it when
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
//!     another's route, because [`Router::add`](crate::stdlib::route::Router::add)
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
//!   by hand with [`router`](crate::stdlib::route::router).
//! - **Fragments are put back together in each sandbox's filter.** Each
//!   fragment must pass the checks above on its own. The filter then holds
//!   it until its packet is whole, and sends the router only whole packets,
//!   with the rules and limits of
//!   [`split_protocols`](crate::stdlib::ip::split_protocols): overlapping
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
//! - **HTTP/1.1 and HTTP/2** with hyper on every connection. Over TLS, the
//!   version is agreed in the handshake (ALPN): `serve` sets the ALPN list
//!   of each config to `h2` and `http/1.1`, so a browser gets HTTP/2 and
//!   `curl` gets what it asks for. Without TLS, the version is read from the
//!   first bytes the client sends. HTTP/2 streams run as tasks in the
//!   connection's [region](crate::Cx#regions).
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
//! These are its attach flags ([Addresses](crate::attaching#addresses)
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
//!   the sandbox detaches. A sandbox gets one [`Bound`](Event::Bound) event
//!   for each family.
//! - **The kernel's own packets do no harm.** A Linux sandbox sends router
//!   solicitations and multicast listener reports from its link-local
//!   address as soon as `tun0` comes up. Packets to multicast addresses are
//!   dropped before binding, so they never bind the wrong address.
//! - **No neighbor resolution is needed.** A `tun` device carries IP
//!   packets with no link layer, so the sandbox's kernel sends to the
//!   gateway directly, without asking for its hardware address. A VM
//!   attached with `tap` does ask, and attach answers it on the VM's link
//!   (see [`lowering`](crate::lowering#tap-ethernet-frames-with-the-ethernet-taken-off)).
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
//!   [`split_protocols`](crate::stdlib::ip::split_protocols) lists the
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
//! its own. A world that wants to know all of it sets a callback with
//! [`on_event`](Sites::on_event), and `Sites` calls it with an [`Event`] for
//! each of these:
//!
//! - a sandbox attaches, gets its address, or detaches;
//! - every DNS message the server gets, over UDP or TCP, with its answer;
//! - every TLS handshake on port 443, with its SNI and how it ended;
//! - every HTTP request hyper hands to `Sites`, with who answered it, its
//!   status and how much of the body was sent, also when the client gave up
//!   before the answer;
//! - every connection on port 80 or 443 that ended in an HTTP error;
//! - every packet `Sites` itself drops or refuses, and why.
//!
//! What the layers below `Sites` drop on their own is not reported. See
//! [`Http`] and [`Blocked`] for which.
//!
//! One HTTPS request to a site with [`tls`](Site::tls), from its lookup to
//! its events:
//!
#![doc = include_str!("../../docs/diagrams/sites-request.svg")]
//!
//! The callback is a plain function, not an async one. It runs inside the
//! task that made the event, in the order `Sites` makes the events. Every
//! task of a world runs on one thread, so a slow callback slows the whole
//! world, for every sandbox, and the agent could time the delay. It must
//! return quickly and must not block. Even a write to a buffered file can
//! block when the buffer fills. Hand the event on instead, to a channel
//! that never waits, and do the work elsewhere. [`Event`] is `Clone` for
//! this:
//!
//! ```
//! # use std::sync::Arc;
//! # use std::sync::atomic::{AtomicU64, Ordering};
//! # use fictionet::{Attachments, Cx, Result, stdlib::web};
//! # fn store(_: Option<http::StatusCode>, _: &http::Uri, _: Option<&str>) {}
//! # fn site_for(_host: &str) -> Option<web::Site> { None }
//! # fn world(cx: Cx, attachments: Attachments) -> Result {
//! #[derive(Clone)]
//! struct Page { stance: &'static str } // a handler's own field
//!
//! let (tx, rx) = std::sync::mpsc::sync_channel::<web::Event>(100_000);
//! let lost = Arc::new(AtomicU64::new(0));
//! std::thread::spawn(move || {
//!     for event in rx {
//!         if let web::Event::Http(http) = &event {
//!             let stance = http.extensions.get::<Page>().map(|p| p.stance);
//!             store(http.status, &http.uri, stance); // slow: a file, a database
//!         }
//!     }
//! });
//! let counter = lost.clone();
//! web::Sites::new(site_for)
//!     .on_event(move |_cx, event| {
//!         if tx.try_send(event.clone()).is_err() {
//!             counter.fetch_add(1, Ordering::Relaxed); // full: count it, never wait
//!         }
//!     })
//!     .serve(&cx, attachments)?;
//! # Ok(())
//! # }
//! ```
//!
//! An eval that needs every event checks the count of lost events at the
//! end, and throws the sample away if it is not zero.
//!
//! A handler can add its own fields to its request's event. It puts them in
//! the extensions of the response it returns, and they arrive in
//! [`Http::extensions`]. Response extensions are never sent to the agent.
//! Read them by type, with `get`, as above: the `Debug` output of
//! `http::Extensions` shows only the types, not the values. The FakeWiki
//! eval in `examples/fakewiki` puts
//! the kind and stance of each page there, so one log line holds what the
//! agent asked for and what it was shown.
//!
//! Events do not hold packets or bodies. A world that wants every packet
//! puts a [`filter`](crate::stdlib::filter) between each sandbox and
//! `Sites`, as [Changing the network around the
//! sites](#changing-the-network-around-the-sites) shows. The
//! [packet capture recipe](crate::recipes#packet-capture) writes them all
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
//! [`Attachments::map`](crate::Attachments::map). Here every sandbox gets a
//! 200 ms delay each way, in front of everything `Sites` builds:
//!
//! ```
//! # use fictionet::{Attachments, Cx, Result, stdlib::{self, web}, time::ms};
//! # fn site_for(_host: &str) -> Option<web::Site> { None }
//! # fn world(cx: Cx, attachments: Attachments) -> Result {
//! let far = attachments.map(&cx, |cx, sandbox| stdlib::delay(cx, ms(200), sandbox));
//! web::Sites::new(site_for).serve(&cx, far)?;
//! # Ok(())
//! # }
//! ```
//!
//! `Sites` sees each sandbox through its delay, under the same name, and
//! binds its addresses and reports its events as usual. The same works with
//! [`bottleneck`](crate::stdlib::bottleneck) for a slow link, and with
//! [`filter`](crate::stdlib::filter) to watch or drop packets. The
//! [recipes](crate::recipes) run each of these, with a route that changes
//! mid-run, and show what the sandbox sees.
//!
//! Every part of `Sites` is built from public stdlib items, so a world can
//! also write any part itself. To change something inside the network,
//! such as how addresses are bound or how DNS answers, copy the code of
//! `serve` and change that part.

use std::future::{Future, poll_fn};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use bytes::{Buf, Bytes};
use http::{Request, Response};
use http_body_util::BodyExt;
use http_body_util::combinators::UnsyncBoxBody;
use hyper::body::Incoming;
use tower_service::Service;

use crate::stdlib::route::Prefix;
use crate::stdlib::tls::ServerConfig;
use crate::time::Instant;
use crate::{Attachments, Cx, Error};

mod http_serve;
mod names;
mod net;

/// Websites by hostname, and the network around them. See the
/// [module docs](self).
pub struct Sites {
    site_for: Arc<SiteFor>,
    subnet: Prefix,
    subnet_v6: Prefix,
    ipv6: bool,
    max_sites: usize,
    on_event: Option<Arc<OnEvent>>,
}

/// The callback given to [`Sites::on_event`].
type OnEvent = dyn Fn(&Cx, &Event) + Send + Sync;

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
            max_sites: net::MAX_SITES,
            on_event: None,
        }
    }

    /// Calls `on_event` with an [`Event`] for everything `Sites` does. See
    /// [Events](self#events).
    ///
    /// `on_event` gets the context of the task that made the event, for
    /// [`Cx::now`] and the like. It must return quickly and must not block.
    /// Calling `on_event` again replaces the earlier callback.
    pub fn on_event<F>(self, on_event: F) -> Sites
    where
        F: Fn(&Cx, &Event) + Send + Sync + 'static,
    {
        Sites { on_event: Some(Arc::new(on_event)), ..self }
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
    /// packet from a sandbox is dropped, with a [`Blocked`] event that
    /// says [`BlockedWhy::Ipv6`].
    ///
    /// Without this, the network is dual-stack: see [IPv6](self#ipv6).
    pub fn ipv4_only(self) -> Sites {
        Sites { ipv6: false, ..self }
    }

    /// Sets how many names may have a site. The default is 20,000.
    ///
    /// Each name the callback gives a site is kept for the whole run, with
    /// its machines: one for each address it has, unless it shares an
    /// address with another site. A callback that opens a whole domain lets
    /// the agent make a new site with every new name it looks up, so this
    /// keeps the world's memory and tasks bounded. At the limit, a new name
    /// still runs the callback. If it returns a site, that site is dropped
    /// before it gets an address or a machine, DNS answers SERVFAIL, and the
    /// [`Dns`] event says [`DnsAnswer::Error`]`(2)`. The name is not kept,
    /// so looking it up again runs the callback again. Names that already
    /// have a site, and names the callback turns down, are answered as
    /// before.
    pub fn max_sites(self, max_sites: usize) -> Sites {
        Sites { max_sites, ..self }
    }

    /// Builds the network and starts it. Every sandbox in `attachments`,
    /// including ones that attach later, is connected to the sites.
    ///
    /// Returns immediately. The network runs in background tasks in `cx`'s
    /// [region](crate::Cx#regions), and keeps running after the world
    /// returns, until that region is cancelled.
    ///
    /// Fails only if a [`subnet`](Sites::subnet) is not one it can use.
    pub fn serve(self, cx: &Cx, attachments: Attachments) -> Result<(), Error> {
        let subnet_v6 = self.ipv6.then_some(self.subnet_v6);
        net::serve(cx, self.site_for, self.subnet, subnet_v6, self.max_sites, self.on_event, attachments)
    }
}

/// One website: a handler, and optionally an address and TLS.
pub struct Site {
    handler: Handler,
    at: Option<Ipv4Addr>,
    at_v6: Option<Ipv6Addr>,
    family: Family,
    tls: Option<Arc<SiteTls>>,
    plain_http: bool,
    default_host: bool,
}

/// The body of every response `serve` sends.
type Body = UnsyncBoxBody<Bytes, Error>;

/// What a request turns into.
type Reply = Pin<Box<dyn Future<Output = Result<Response<Body>, Error>> + Send>>;

/// A site's handler, with its types erased.
type Handler = Arc<dyn Fn(Request<Incoming>) -> Reply + Send + Sync>;

impl Site {
    /// A site served by `handler`. See [Handlers](self#handlers).
    pub fn new<S, B>(handler: S) -> Site
    where
        S: Service<Request<Incoming>, Response = Response<B>> + Clone + Send + 'static,
        S::Future: Send + 'static,
        S::Error: Into<Error>,
        B: http_body::Body + Send + 'static,
        B::Data: Send,
        B::Error: Into<Error>,
    {
        // Each request gets its own clone, as tower expects. The mutex only
        // guards the clone, so the handler need not be Sync.
        let handler = Mutex::new(handler);
        let handler: Handler = Arc::new(move |request| {
            let mut service = handler.lock().unwrap_or_else(|e| e.into_inner()).clone();
            Box::pin(async move {
                poll_fn(|task| service.poll_ready(task)).await.map_err(|e| -> Error { e.into() })?;
                let response = service.call(request).await.map_err(|e| -> Error { e.into() })?;
                Ok(response.map(|body| IntoBytes(Box::pin(body)).boxed_unsync()))
            })
        });
        Site { handler, at: None, at_v6: None, family: Family::Both, tls: None, plain_http: false, default_host: false }
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
    /// its name with NODATA, so clients connect over IPv4. Use it for a
    /// site that has no IPv6 on the real internet, or to see how an agent
    /// copes with one.
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
    /// with randomness from `cx`. To use one config every time, return a
    /// clone of it.
    ///
    /// `serve` replaces the ALPN list of the returned config with `h2` and
    /// `http/1.1`, so the config does not need one.
    pub fn tls<F>(self, config_for: F) -> Site
    where
        F: Fn(&Cx) -> Arc<ServerConfig> + Send + Sync + 'static,
    {
        Site { tls: Some(Arc::new(SiteTls { config_for: Box::new(config_for), last: Mutex::new(None) })), ..self }
    }

    /// Serves a site with [`tls`](Site::tls) over plain HTTP on port 80
    /// as well. Its handler answers those requests, instead of the 301
    /// redirect to https that a TLS site gets by default.
    ///
    /// This is a site that never moved to HTTPS, or a machine that answers
    /// in plain text where the real site would redirect, as an attacker
    /// that strips TLS does. The handler tells the two kinds of request
    /// apart by [`Target::scheme`]. Their events are [`Http`] events with
    /// [`HttpAnswer::Handler`] either way.
    ///
    /// A site without `tls` is served over plain HTTP already, so this
    /// changes nothing for it.
    pub fn plain_http(self) -> Site {
        Site { plain_http: true, ..self }
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
        Site { default_host: true, ..self }
    }
}

/// Which address families a site has. The last of [`Site::ipv4_only`] and
/// [`Site::ipv6_only`] wins.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Family {
    Both,
    V4,
    V6,
}

/// A handler's body, with its data as `Bytes` and its errors as [`Error`].
/// It passes on the body's size hint, so hyper sends a `content-length`
/// for a body whose length is known, as a real server would, instead of
/// chunked encoding.
struct IntoBytes<B>(Pin<Box<B>>);

impl<B> http_body::Body for IntoBytes<B>
where
    B: http_body::Body,
    B::Error: Into<Error>,
{
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        task: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Bytes>, Error>>> {
        self.0.as_mut().poll_frame(task).map(|frame| {
            frame.map(|r| {
                r.map(|f| f.map_data(|mut data| data.copy_to_bytes(data.remaining()))).map_err(|e| e.into())
            })
        })
    }

    fn is_end_stream(&self) -> bool {
        self.0.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.0.size_hint()
    }
}

/// A site's TLS: the world's callback, and the last config it returned
/// with the ALPN list set, so a world that returns the same config every
/// time does not pay for a copy on every handshake.
struct SiteTls {
    config_for: ConfigFor,
    last: Mutex<Option<(Arc<ServerConfig>, Arc<ServerConfig>)>>,
}

/// The callback given to [`Site::tls`].
type ConfigFor = Box<dyn Fn(&Cx) -> Arc<ServerConfig> + Send + Sync>;

impl SiteTls {
    /// The config for one handshake, with ALPN set to `h2` and `http/1.1`.
    fn config(&self, cx: &Cx) -> Arc<ServerConfig> {
        let given = (self.config_for)(cx);
        let mut last = self.last.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((from, with_alpn)) = &*last && Arc::ptr_eq(from, &given) {
            return with_alpn.clone();
        }
        let mut config = (*given).clone();
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let config = Arc::new(config);
        *last = Some((given, config.clone()));
        config
    }
}

/// Where a request arrived: the scheme and port from the connection, the
/// host from the request.
///
/// `serve` puts one in the extensions of every request before calling the
/// handler. Extensions are a typed map inside an `http::Request` that code
/// in the same process can read and write. They are never sent over the
/// network.
///
/// The scheme, port and SNI come from the connection, not from headers the
/// agent wrote: the scheme from whether the connection used TLS, the port
/// from the port it arrived on. An HTTP/1.1 request line usually carries
/// only a path, so the scheme is not in the request at all. The host is the
/// one the request named, which the agent wrote. `Sites` routed the request
/// by it only because a site with that name is at this address.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Target {
    /// `http` or `https`.
    pub scheme: http::uri::Scheme,
    /// The hostname the request was routed by, such as `github.com`: the
    /// authority of its URI if it has one, else its `Host` header, in
    /// lowercase, without a port or a trailing dot.
    pub host: String,
    /// The port the connection arrived on, such as 443.
    pub port: u16,
    /// The name the client sent in its TLS handshake (SNI), in lowercase,
    /// without a trailing dot. `None` without TLS.
    ///
    /// It is always the name of a TLS site at this address, but it need not
    /// be `host`. A client may send several hosts' requests over one
    /// connection when their sites share an address and a certificate, as
    /// browsers do with HTTP/2.
    pub sni: Option<String>,
}

/// Something [`Sites`] did, given to the callback set with
/// [`Sites::on_event`].
///
/// Each event names the sandbox it came from. Events come in the order
/// `Sites` makes them. For one sandbox:
///
/// - `Attached` comes before any other event of it.
/// - A connection's `Tls` event comes before its `Http` and `HttpError`
///   events.
/// - Events that end something begun before a detach, such as a request,
///   a handshake or a DNS query over TCP, may come after its `Detached`.
///   [`Sandbox::id`] tells them apart from a later sandbox with the same
///   name and address.
///
/// One possible order of the events of one sandbox:
///
/// ```text
/// Attached → Blocked → Bound → Dns → Tls → Http → Http → Detached → Http
/// ↑                                  └─ connection 3 ┘              ↑
/// first, always                                   connection 3 too: a request
///                                                 begun before the detach,
///                                                 ends as HttpAnswer::Cancelled
/// ```
///
/// An event is made when the thing it reports ends. HTTP/2 requests on one
/// connection run side by side and can end in any order. [`Http::started`]
/// gives when each one arrived.
// The variants differ in size, and events are not stored in bulk, so they
// are not boxed.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum Event {
    /// A sandbox attached. It has no address yet.
    #[non_exhaustive]
    Attached {
        /// The sandbox.
        sandbox: Sandbox,
    },
    /// One of a sandbox's addresses was bound: when DHCP acknowledged an
    /// IPv4 address (`by_dhcp`), or by the first packet from a static
    /// address. A dual-stack sandbox gets one `Bound` for each family. The
    /// new address is in `sandbox.addr` or `sandbox.addr_v6`.
    #[non_exhaustive]
    Bound {
        /// The sandbox, with its new address.
        sandbox: Sandbox,
        /// Whether DHCP gave the address.
        by_dhcp: bool,
    },
    /// A sandbox detached. Its connections were reset, and its address is
    /// free again.
    #[non_exhaustive]
    Detached {
        /// The sandbox.
        sandbox: Sandbox,
    },
    /// A DNS message, and its answer.
    Dns(Dns),
    /// A TLS handshake on port 443, from the TCP connection to its end.
    Tls(Tls),
    /// An HTTP request, when it has ended.
    Http(Http),
    /// A connection on port 80 or 443 that ended in an HTTP error.
    HttpError(HttpError),
    /// A packet from a sandbox that `Sites` dropped or refused.
    Blocked(Blocked),
}

/// The sandbox an event came from.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Sandbox {
    /// The attachment, numbered from 1 in the order sandboxes attached to
    /// this `Sites`. A name and an address can be used again after a
    /// sandbox detaches. The id is never used again.
    pub id: u64,
    /// Its attachment's name, from [`Attachment::name`](crate::Attachment::name).
    pub name: Arc<str>,
    /// Its IPv4 address, once bound.
    pub addr: Option<Ipv4Addr>,
    /// Its IPv6 address, once bound.
    ///
    /// Events about a connection or a query carry the sandbox as it was
    /// when the connection or query arrived. Its address in the family
    /// the connection used is always set.
    pub addr_v6: Option<Ipv6Addr>,
}

/// A DNS message to the gateway, and how `Sites` answered it.
///
/// Every message is one event: a UDP datagram, or one whole message over
/// TCP. A name looked up twice makes two events, though the site callback
/// runs only the first time. A TCP connection that closes in the middle of
/// a message makes no event for it.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Dns {
    /// The sandbox that sent it.
    pub sandbox: Sandbox,
    /// Whether the message came over TCP, rather than UDP.
    pub tcp: bool,
    /// The name asked for, in lowercase, without a trailing dot. `None` if
    /// the message could not be read, or did not hold exactly one question.
    pub name: Option<String>,
    /// The DNS query type asked for: 1 for A, 28 for AAAA, and so on.
    /// `None` when `name` is.
    pub qtype: Option<u16>,
    /// What `Sites` answered. It says nothing about whether the answer
    /// reached the sandbox.
    pub answer: DnsAnswer,
}

/// What `Sites` answered to a DNS message.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DnsAnswer {
    /// An A record (for an IPv4 address) or an AAAA record (for an IPv6
    /// address) with this address.
    Addr(IpAddr),
    /// The name exists, but has no record of the type asked for.
    NoData,
    /// The name does not exist.
    NxDomain,
    /// An error with this response code: 1 (FORMERR) for a message that
    /// could not be read or did not hold exactly one question, 2 (SERVFAIL)
    /// for a new name the callback gave a site when the world already had
    /// [`Sites::max_sites`] sites, 4 (NOTIMP) for an opcode other than
    /// QUERY.
    Error(u16),
    /// No answer: the message was too broken to answer, or was not a query.
    None,
}

/// A TLS handshake on port 443, from the moment the TCP connection is
/// accepted to the end of the handshake.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Tls {
    /// The sandbox that sent it.
    pub sandbox: Sandbox,
    /// The connection, numbered from 1 for each `Sites`, on both ports.
    /// The `Http` and `HttpError` events of this connection carry the same
    /// number.
    pub conn: u64,
    /// The address of the machine the client connected to.
    pub addr: IpAddr,
    /// The name the client sent (SNI), in lowercase, without a trailing
    /// dot. `None` if it sent none, or if no SNI could be read from what it
    /// sent.
    pub sni: Option<String>,
    /// How the handshake ended.
    pub outcome: TlsOutcome,
}

/// How a TLS handshake ended.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum TlsOutcome {
    /// The handshake finished, with this protocol agreed by ALPN, such as
    /// `h2`.
    Accepted {
        /// The protocol agreed by ALPN. `None` if none was.
        alpn: Option<Vec<u8>>,
    },
    /// `Sites` refused it with `unrecognized_name`: no SNI, or no TLS site
    /// with that name at this address.
    Rejected,
    /// The client sent this TLS alert, such as 48 (`unknown_ca`) when it
    /// does not trust the world's certificate.
    Alert(u8),
    /// The bytes were not TLS, or broke the protocol. The text says how. It
    /// is for people, and may change.
    Failed(String),
    /// The client closed the connection before the handshake finished.
    Closed,
    /// The handshake did not finish within 10 seconds of the connection
    /// being accepted.
    TimedOut,
    /// `Sites` ended the connection first: the sandbox detached, or the
    /// world stopped.
    Aborted,
}

/// An HTTP request that hyper read and handed to `Sites`, and how it ended.
///
/// Every such request is exactly one event: those a handler answered,
/// those `Sites` answered itself, and those whose client gave up before
/// there was an answer.
///
/// Requests the HTTP layers refuse before handing them on make no `Http`
/// event. HTTP/1.1 bytes hyper cannot parse end the connection, with an
/// [`HttpError`] event. HTTP/2 streams the protocol layer resets as
/// malformed, such as one whose length does not match its
/// `content-length`, or whose headers are too large, are not reported.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Http {
    /// The sandbox that sent it.
    pub sandbox: Sandbox,
    /// The connection, as in [`Tls::conn`].
    pub conn: u64,
    /// The machine's address and port the connection arrived on.
    pub local: SocketAddr,
    /// `http` or `https`.
    pub scheme: http::uri::Scheme,
    /// The connection's SNI, as in [`Target::sni`]. `None` without TLS.
    pub sni: Option<String>,
    /// The host the request named, found as [`Target::host`] is, even when
    /// no site has it. `None` when it named none.
    pub host: Option<String>,
    /// When `Sites` got the request, from [`Cx::now`]. The callback's own
    /// `cx.now()` gives when it ended.
    pub started: Instant,
    /// The method, URI, version and headers, as hyper parsed them from the
    /// client's request. The URI is usually only a path and query. Header
    /// names are in lowercase. HTTP/2's pseudo-headers are in `method` and
    /// `uri`, not in `headers`.
    pub method: http::Method,
    /// The URI, as above.
    pub uri: http::Uri,
    /// The HTTP version, as above.
    pub version: http::Version,
    /// The headers, as above.
    pub headers: http::HeaderMap,
    /// Who answered the request.
    pub answer: HttpAnswer,
    /// The status of the response. `None` when there was no response
    /// ([`HttpAnswer::Cancelled`]).
    pub status: Option<http::StatusCode>,
    /// How many bytes of the response body were handed to the connection,
    /// which takes more only as it makes room. This is what the world sent,
    /// not what the agent read: when the client goes away early, the last
    /// of these may not have reached it.
    pub sent: u64,
    /// Whether the end of the body was handed to the connection. `false`
    /// if the client went away, or the body failed, before its end, and
    /// when there was no response. A response with no body, such as one to
    /// `HEAD`, is complete when it is sent.
    pub complete: bool,
    /// The extensions of the response the handler returned, which are
    /// never sent to the agent. Empty when no handler answered. Read them
    /// by type, with `get`: their `Debug` output shows only the types.
    pub extensions: http::Extensions,
}

/// Who answered an HTTP request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum HttpAnswer {
    /// The site's handler.
    Handler,
    /// `Sites`, because the handler failed: `500`, or `502` when `proxy()`
    /// (feature `tokio`) could not reach the real site.
    Error,
    /// `Sites`, with a `301` redirect from http to https.
    Redirect,
    /// `Sites`, with `421`: no site with that host at this address and no
    /// [default site](Site::default_host), or no TLS for the site on a TLS
    /// connection.
    Misdirected,
    /// `Sites`, with `400`: the request named no host.
    NoHost,
    /// No response. The client reset the stream or the connection, closed
    /// an HTTP/2 connection, or the sandbox detached, before the handler
    /// returned, and the handler's future was dropped.
    ///
    /// An HTTP/1.1 client that only closes its side of the connection
    /// while the handler works is taken to be half-closing (see
    /// Half-close under Details): the handler goes on, and the request
    /// ends with its answer.
    Cancelled,
}

/// A connection on port 80 or 443 that ended in an HTTP error.
///
/// A connection that ends cleanly makes no `HttpError` event, with or
/// without requests. Neither does the 30-second limit on HTTP/1.1 headers,
/// which also ends connections left idle between requests, nor the client
/// closing or resetting the connection: requests it cut off end as
/// [`Http`] events with [`HttpAnswer::Cancelled`]. On port 443, a
/// handshake that fails is a [`Tls`] event, not an `HttpError`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct HttpError {
    /// The sandbox that sent it.
    pub sandbox: Sandbox,
    /// The connection, as in [`Tls::conn`].
    pub conn: u64,
    /// The machine's address and port the connection arrived on.
    pub local: SocketAddr,
    /// The kind of error.
    pub cause: HttpErrorCause,
    /// What went wrong, in words. The text is for people, and may change.
    pub detail: String,
}

/// Why a connection ended in an HTTP error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum HttpErrorCause {
    /// The client's bytes were not HTTP, or broke the protocol.
    Protocol,
    /// On port 80, the client sent no bytes within 10 seconds of
    /// connecting.
    Timeout,
    /// The TLS layer under HTTP failed after the handshake, such as on a
    /// record that would not decrypt.
    Transport,
}

/// A packet from a sandbox that `Sites` itself dropped or refused, for one
/// of the reasons in [`BlockedWhy`].
///
/// Packets the layers below `Sites` drop on their own are not reported:
/// UDP or TCP with a bad checksum, UDP for a full socket queue, TCP
/// connection attempts past the backlog for one client, IP fragments that
/// overlap or never complete, IPv6 extension headers that a host must
/// refuse, DHCP messages that cannot be read, and IP protocols other than
/// TCP, UDP and ICMP sent to a machine. Each fragment is checked against
/// the sandbox's address and the other sandboxes' subnet on its own, and
/// reported if it fails. [`BlockedWhy::NoRoute`] and
/// [`BlockedWhy::ClosedPort`] are about where a packet goes, so a packet
/// that arrives in fragments makes them once, when it is whole.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Blocked {
    /// The sandbox that sent it.
    pub sandbox: Sandbox,
    /// Why it was blocked.
    pub why: BlockedWhy,
    /// The IP protocol: 6 for TCP, 17 for UDP, 1 for ICMP, 58 for ICMPv6. `None` if the
    /// packet is not IP.
    pub protocol: Option<u8>,
    /// The source address. `None` if the packet is not IP.
    pub src: Option<std::net::IpAddr>,
    /// The destination address. `None` if the packet is not IP.
    pub dst: Option<std::net::IpAddr>,
    /// The TCP or UDP destination port.
    pub dst_port: Option<u16>,
}

/// Why `Sites` dropped or refused a packet.
///
/// Every blocked packet is one event: a client that retries, or scans
/// 65,535 ports, makes one event per packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum BlockedWhy {
    /// Its source was not the sandbox's address, or the static address it
    /// tried to bind was not free. Dropped.
    NotItsAddress,
    /// It was for another sandbox's subnet address. Dropped.
    OtherSandbox,
    /// It was for a broadcast, multicast or unspecified address, and was
    /// not DHCP. Dropped. This includes the IPv6 router solicitations and
    /// multicast listener reports a Linux sandbox sends on its own.
    Broadcast,
    /// It was IPv6, on a network with IPv6 turned off
    /// ([`Sites::ipv4_only`]). Dropped.
    Ipv6,
    /// It was not an IP packet, or its IPv4 or IPv6 header was broken.
    /// Dropped.
    Malformed,
    /// No machine has its destination address. Answered with ICMP "host
    /// unreachable", or ICMPv6 "address unreachable", except for packets
    /// that must get no ICMP error, such as ICMP errors themselves.
    NoRoute,
    /// Its destination port is not served: TCP is answered with a RST, UDP
    /// with ICMP "port unreachable". A RST sent to a closed port gets no
    /// answer and makes no event.
    ClosedPort,
    /// A new TCP connection past the sandbox's limit per machine. Reset.
    TooManyConnections,
}

/// Runs hyper's background work, such as HTTP/2 streams, as tasks in a
/// region, with [`Cx::spawn`]. Private until a world needs its own hyper
/// server.
#[derive(Clone)]
struct Executor {
    cx: Cx,
}

impl Executor {
    fn new(cx: &Cx) -> Executor {
        Executor { cx: cx.clone() }
    }
}

impl<F> hyper::rt::Executor<F> for Executor
where
    F: Future<Output = ()> + Send + 'static,
{
    fn execute(&self, work: F) {
        // A stream's handler may wait on something outside the world, so the
        // task also ends when the world stops.
        self.cx.spawn(move |cx| async move {
            let mut work = std::pin::pin!(work);
            let mut stopping = std::pin::pin!(cx.cancelled());
            poll_fn(|task| {
                if work.as_mut().poll(task).is_ready() || stopping.as_mut().poll(task).is_ready() {
                    return std::task::Poll::Ready(());
                }
                std::task::Poll::Pending
            })
            .await;
            Ok(())
        });
    }
}

/// The error a handler returns when the site behind it could not be
/// reached. `serve` answers it with `502 Bad Gateway` instead of `500`.
#[derive(Debug)]
struct BadGateway(String);

impl std::fmt::Display for BadGateway {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "bad gateway: {}", self.0)
    }
}

impl std::error::Error for BadGateway {}

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
/// `Transfer-Encoding` and the like) are not passed on in either direction.
/// If the real site cannot be reached, the agent gets `502 Bad Gateway`.
#[cfg(feature = "tokio")]
#[cfg_attr(docsrs, doc(cfg(feature = "tokio")))]
pub fn proxy() -> Proxy {
    Proxy { client: Arc::new(http_serve::proxy_client()) }
}

/// The handler made by [`proxy`].
#[cfg(feature = "tokio")]
#[cfg_attr(docsrs, doc(cfg(feature = "tokio")))]
#[derive(Clone)]
pub struct Proxy {
    client: Arc<http_serve::ProxyClient>,
}

#[cfg(feature = "tokio")]
impl Service<Request<Incoming>> for Proxy {
    type Response = Response<Incoming>;
    type Error = Error;
    type Future = std::pin::Pin<Box<dyn Future<Output = Result<Response<Incoming>, Error>> + Send>>;

    fn poll_ready(&mut self, _task: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<Incoming>) -> Self::Future {
        Box::pin(http_serve::forward(self.client.clone(), request))
    }
}
