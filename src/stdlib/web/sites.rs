use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use http::{Request, Response};

use fictionet::stdlib::httpd::{self, Handler, Website};
pub use fictionet::stdlib::httpd::{Body, Target};
use fictionet::stdlib::net::{Host, Net};
use fictionet::stdlib::route::Prefix;
use fictionet::stdlib::tls::ServerConfig;
use fictionet::{Attachments, Cx, Error};

/// Websites by hostname, and the network around them. See the
/// [module docs](fictionet::stdlib::web).
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
            subnet: Prefix {
                addr: Ipv4Addr::new(10, 0, 0, 0).into(),
                len: 24,
            },
            subnet_v6: Prefix {
                addr: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0).into(),
                len: 64,
            },
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
        Sites {
            date: Some(start),
            ..self
        }
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
    /// [`start`](Sites::start) fails.
    pub fn subnet(self, subnet: Prefix) -> Sites {
        match subnet.addr {
            IpAddr::V4(_) => Sites { subnet, ..self },
            IpAddr::V6(_) => Sites {
                subnet_v6: subnet,
                ..self
            },
        }
    }

    /// Turns IPv6 off for the whole network. Sites then have only IPv4
    /// addresses, DNS answers AAAA queries with NODATA, and every IPv6
    /// packet from a sandbox is dropped, with a `net.blocked` event whose
    /// `why` is `Ipv6`.
    ///
    /// Without this, the network is dual-stack: see [IPv6](fictionet::stdlib::web#ipv6).
    pub fn ipv4_only(self) -> Sites {
        Sites {
            ipv6: false,
            ..self
        }
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
                        site = site.date(date);
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
    pub fn start(self, fcx: &Cx, attachments: Attachments) -> Result<(), Error> {
        self.into_net().start(fcx, attachments)
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
    /// `axum::Router`. See [Handlers](fictionet::stdlib::web#handlers).
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

    /// A site served by an [`httpd::Handler`](https://docs.rs/fictionet/latest/fictionet/stdlib/httpd/trait.Handler.html), such as an
    /// [`httpd::Router`](https://docs.rs/fictionet/latest/fictionet/stdlib/httpd/struct.Router.html).
    pub fn handler(handler: impl Handler) -> Site {
        Site {
            website: Website::new(handler),
            at: None,
            at_v6: None,
            family: Family::Both,
        }
    }

    /// Sets the site's date at the start of the run. Responses send this
    /// date plus elapsed run time in their `Date` header.
    pub fn date(self, start: std::time::SystemTime) -> Site {
        Site {
            website: self.website.date(start),
            ..self
        }
    }

    /// Serves the site at `addr`, for example the address it has on the
    /// real internet. `addr` may be an [`Ipv4Addr`], an [`Ipv6Addr`] or an
    /// [`IpAddr`], and sets the site's address of that family. A site that
    /// has both A and AAAA records on the real internet takes both
    /// addresses, with two calls:
    ///
    #[doc = fictionet::cfg_std!(doc r####"
```
# use std::net::{Ipv4Addr, Ipv6Addr};
# use fictionet::stdlib::web;
# let wiki: axum::Router = axum::Router::new();
let site = web::Site::new(wiki)
    .at(Ipv4Addr::new(185, 15, 59, 224))
    .at("2a02:ec80:300:ed1a::1".parse::<Ipv6Addr>().unwrap());
# drop(site);
```
"####)]
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
            IpAddr::V4(a) => Site {
                at: Some(a),
                ..self
            },
            IpAddr::V6(a) => Site {
                at_v6: Some(a),
                ..self
            },
        }
    }

    /// Gives the site only an IPv4 address. DNS answers AAAA queries for
    /// its name with NODATA, so clients connect over IPv4.
    pub fn ipv4_only(self) -> Site {
        Site {
            family: Family::V4,
            ..self
        }
    }

    /// Gives the site only an IPv6 address. DNS answers A queries for its
    /// name with NODATA, so a sandbox without IPv6 cannot reach it. On a
    /// network with IPv6 turned off ([`Sites::ipv4_only`]) the site has
    /// no address at all, and its name gets NXDOMAIN.
    pub fn ipv6_only(self) -> Site {
        Site {
            family: Family::V6,
            ..self
        }
    }

    /// Serves the site over HTTPS. `config_for` runs on every handshake and
    /// returns the TLS config to use, so it can choose differently each time,
    /// with randomness from `fcx`. To use one config every time, return a
    /// clone of it.
    ///
    /// `start` replaces the ALPN list with `http/1.1` and, when the
    /// `tokio` feature is enabled, `h2`, so the config does not need one.
    pub fn tls<F>(self, config_for: F) -> Site
    where
        F: Fn(&Cx) -> Arc<ServerConfig> + Send + Sync + 'static,
    {
        Site {
            website: self.website.tls(config_for),
            ..self
        }
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
        Site {
            website: self.website.plain_http(),
            ..self
        }
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
        Site {
            website: self.website.default_host(),
            ..self
        }
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
