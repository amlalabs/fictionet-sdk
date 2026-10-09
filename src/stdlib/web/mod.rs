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
//! and 443, made when its name is first looked up. HTTP is [`httpd`](https://docs.rs/fictionet/latest/fictionet/stdlib/httpd/index.html), a
//! service like any other. A world that needs other services next to its
//! websites builds on `Net` directly.
//!
//! In this world, two sites are served by the world's own axum routers.
//! `en.wikipedia.org` has the IPv4 and IPv6 addresses it has on the real
//! internet. `api.stripe.com` serves a bad certificate one time in ten.
//! `github.com` and every name under it pass through to the real GitHub.
//! Every other name does not exist. The certificates come from the world's
//! own certificate authority (CA). The world function gets its context
//! ([`Cx`]) and its sandboxes
//! ([`Attachments`]), as [A world in code](crate#a-world-in-code) explains:
//!
#![doc = fictionet::cfg_web_proxy!(doc r####"
```
# use std::net::{Ipv4Addr, Ipv6Addr};
# use std::sync::Arc;
# use fictionet::{Attachments, Cx, Result, stdlib::web};
# use rustls::ServerConfig;
# struct Certs { wikipedia: Arc<ServerConfig>, stripe: Arc<ServerConfig>, bad: Arc<ServerConfig>, github: Arc<ServerConfig> }
# fn my_certs() -> Result<Certs> { unimplemented!() }
async fn world(fcx: Cx, attachments: Attachments) -> Result {
#   let wiki: axum::Router = axum::Router::new();
#   let fake_stripe: axum::Router = axum::Router::new();
    // Yours: an Arc<ServerConfig> per certificate, each issued by the world's CA.
    let certs = my_certs()?;

    let upstream = web::proxy(&fcx)?;
    web::Sites::new(move |host: &str| match host {
        "en.wikipedia.org" | "www.wikipedia.org" => Some(
            web::Site::new(wiki.clone())
                .at(Ipv4Addr::new(185, 15, 59, 224))
                .at("2a02:ec80:300:ed1a::1".parse::<Ipv6Addr>().unwrap())
                .tls({ let c = certs.wikipedia.clone(); move |_| c.clone() }),
        ),
        "api.stripe.com" => Some(
            web::Site::new(fake_stripe.clone()) // an axum::Router
                .tls({
                    let (real, fake) = (certs.stripe.clone(), certs.bad.clone());
                    move |fcx| if fcx.random_f64() < 0.1 { fake.clone() } else { real.clone() }
                }),
        ),
        h if h == "github.com" || h.ends_with(".github.com") => Some(
            web::Site::new(upstream.clone()) // the real site, over the world's own network
                .tls({ let c = certs.github.clone(); move |_| c.clone() }), // github.com and *.github.com
        ),
        _ => None, // NXDOMAIN: the world stays closed
    })
    .start(&fcx, attachments)?;
    Ok(()) // the sites keep running after the world returns
}
```
"####)]
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
//! `tower::service_fn`. So is `web::proxy(&fcx)?` (feature `web-proxy`, off by
//! default), which forwards to the real site. [`Site::handler`] takes an
//! [`httpd::Handler`](https://docs.rs/fictionet/latest/fictionet/stdlib/httpd/trait.Handler.html) instead, such as an
//! [`httpd::Router`](https://docs.rs/fictionet/latest/fictionet/stdlib/httpd/struct.Router.html), whose handlers get plain
//! byte bodies and no runtime. A request's body is read whole before the
//! handler is called, up to 64 MiB; past that the answer is `413`.
//!
//! # Passing a site through to the real one
//!
//! A site whose handler is `web::proxy(&fcx)?`, such as `github.com` above, shows
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
//! # What `start` builds
//!
#![doc = include_str!("../../../docs/diagrams/sites-network.svg")]
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
//!   [`httpd::Http1`](https://docs.rs/fictionet/latest/fictionet/stdlib/httpd/struct.Http1.html), HTTP/2 with hyper and the `tokio` feature. Over TLS, the
//!   version is agreed in the handshake (ALPN): `start` sets the ALPN list
//!   of each config to `http/1.1` and, with `tokio`, `h2`. Without TLS,
//!   the version is read from the
//!   first bytes the client sends. HTTP/2 streams run as tasks in the
//!   connection's [region](fictionet::Cx#regions).
//! - **Routing by host.** Each request goes to the site for its host: the
//!   authority of its URI if it has one (the `:authority` in HTTP/2, or an
//!   absolute URI in HTTP/1.1), else its `Host` header. A host with no site
//!   at the address gets `421 Misdirected Request`, unless a site there is
//!   the [`default_host`](Site::default_host).
//! - **A [`Target`] on every request.** Before calling a handler, `start`
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
#![doc = include_str!("../../../docs/diagrams/sites-binding.svg")]
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
//!   ([`httpd`](https://docs.rs/fictionet/latest/fictionet/stdlib/httpd/index.html#events) lists the fields);
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
#![doc = include_str!("../../../docs/diagrams/sites-request.svg")]
//!
//! Callbacks set with [`EventLog::subscribe`](fictionet::events::EventLog::subscribe)
//! run inside the task that recorded the event. Every task of a world runs
//! on one thread, so a slow callback slows the whole world. Hand the event
//! to a channel that never waits, and do the work elsewhere, or write the
//! events to a file with
//! [`EventLog::to_file`](fictionet::events::EventLog::to_file), which does that
//! for you:
//!
#![doc = fictionet::cfg_std!(doc r####"
```
# use fictionet::{Attachments, Cx, Result, stdlib::web};
# fn site_for(_host: &str) -> Option<web::Site> { None }
# async fn world(fcx: Cx, attachments: Attachments) -> Result {
let events = fcx.events();
events.to_file("/var/lib/fictionet/events.jsonl")?;
web::Sites::new(site_for).start(&fcx, attachments)?;
// At the end of the sample: events.lost() must be zero.
# Ok(())
# }
```
"####)]
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
//!   `500 Internal Server Error`. `proxy(&fcx)` errors, where the real site
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
//! `start` takes the world's [`Attachments`], so it serves every sandbox
//! that attaches. To change the path between the sandboxes and the sites,
//! wrap each sandbox before `start` sees it, with
//! [`Attachments::map`](fictionet::Attachments::map). Here every sandbox gets a
//! 200 ms delay each way, in front of everything `Sites` builds:
//!
#![doc = fictionet::cfg_std!(doc r####"
```
# use fictionet::{Attachments, Cx, Result, stdlib::{self, web}, time::ms};
# fn site_for(_host: &str) -> Option<web::Site> { None }
# async fn world(fcx: Cx, attachments: Attachments) -> Result {
let far = attachments.map(&fcx, |fcx, sandbox| stdlib::delay(fcx, ms(200), sandbox));
web::Sites::new(site_for).start(&fcx, far)?;
# Ok(())
# }
```
"####)]
//!
//! `Sites` sees each sandbox through its delay, under the same name, and
//! binds its addresses and reports its events as usual. The same works with
//! [`bottleneck`](fictionet::stdlib::bottleneck) for a slow link, and with
//! [`filter`](fictionet::stdlib::filter) to watch or drop packets. The
//! [recipes](fictionet::recipes) run each of these, with a route that changes
//! mid-run, and show what the sandbox sees.
//!
//! [`Sites::into_net`] gives the [`Net`] before it starts, to add hosts with
//! other services next to the websites. [`Site::into_host`] turns a site into
//! a host; [`net`](fictionet::stdlib::net) binds addresses and answers DNS.
//! To change those parts, see
//! [Changing a protocol by copying it](fictionet::stdlib#changing-a-protocol-by-copying-it).

#[allow(unused_imports)]
use fictionet::stdlib::httpd;
#[allow(unused_imports)]
use fictionet::stdlib::httpd::Website;
#[allow(unused_imports)]
use fictionet::stdlib::net::{Host, Net};
#[allow(unused_imports)]
use fictionet::{Attachments, Cx};

mod sites;
pub use sites::*;

fictionet::cfg_web_proxy! {
mod proxy;
pub use proxy::{Forward, Proxy, forward, proxy};
}
