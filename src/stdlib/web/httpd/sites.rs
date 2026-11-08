use std::any::Any;
use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use http::header::{HOST, LOCATION};
use http::uri::{Authority, Scheme};
use http::{Request, StatusCode};

use fictionet::Cx;
use fictionet::stdlib::services::serve::ConnInfo;
use fictionet::stdlib::services::stack::Boxed;
use fictionet::stdlib::services::tls::ServerConfig;
use fictionet::stdlib::world::net::{
    Arrival, ConfigFor, ConfigFuture, Host, Opening, PortServer, PreparedShare, Sni,
};

use super::{
    Body, Exchange, Handler, HttpOptions, Limits, Reply, http1_for, http2_for, serve_connection,
    text,
};

pub use fictionet::stdlib::world::net::normalize;

/// Where a request arrived: the scheme and port from the connection, the
/// host from the request. [`VirtualHosts`] puts one in the extensions of
/// every request it hands on; handlers read it with
/// `request.extensions().get::<Target>()`, or axum's `Extension`.
///
/// The scheme, port and SNI come from the connection, not from headers the
/// client wrote. The host is the one the request named, even when routing
/// used the default site. [`routing`](Self::routing) says how it matched.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Target {
    /// `http` or `https`.
    pub scheme: Scheme,
    /// The host the request was routed by, in lowercase, without a port or
    /// a trailing dot.
    pub host: String,
    /// The port the connection arrived on.
    pub port: u16,
    /// The name the client sent in its TLS hello. `None` without TLS.
    pub sni: Option<String>,
    /// Whether the requested host matched a registered site or used the default.
    pub routing: Routing,
}

/// How [`VirtualHosts`] selected a request's handler.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Routing {
    /// The requested host matched a registered name after normalization.
    Exact,
    /// No registered name matched; the default site supplied the handler.
    Fallback,
}

// ---------------------------------------------------------------------------
// Virtual hosts

/// A response selected by virtual-host routing before reaching a site's handler.
/// Present in that response's extensions; absent for a handler's own answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answer {
    /// The request did not name a host.
    NoHost,
    /// The requested site is not served on this connection.
    Misdirected,
    /// The site requires HTTPS.
    Redirect,
}

/// One site of [`VirtualHosts`].
#[derive(Clone)]
pub struct VHost {
    /// Its handler.
    pub handler: Arc<dyn Handler>,
    /// It is served over HTTPS. Plain HTTP requests for it get a `301`
    /// redirect to https, unless `plain_http`.
    pub https: bool,
    /// Its handler answers plain HTTP too, even with `https`.
    pub plain_http: bool,
}

impl VHost {
    /// A site with `handler`, plain HTTP only.
    pub fn new(handler: impl Handler) -> VHost {
        VHost {
            handler: Arc::new(handler),
            https: false,
            plain_http: false,
        }
    }
}

/// Picks a site by the request's host, as a web server with several sites
/// at one address does.
///
/// - A request with no host gets `400 Bad Request`.
/// - A host with no site, and no default site, gets `421 Misdirected
///   Request`. So does a site without `https`, asked for over TLS.
/// - A site with `https` asked for over plain HTTP gets a `301` to the same
///   path at `https://host`, unless it has `plain_http`.
/// - Every other request goes to the site's handler, with a [`Target`] in
///   its extensions. Its [`Target::routing`] distinguishes a registered
///   host from a default-site fallback.
///
/// Its own answers carry an [`Answer`] in their response extensions.
#[derive(Clone, Default)]
pub struct VirtualHosts {
    inner: Arc<VInner>,
}

#[derive(Default)]
struct VInner {
    hosts: RwLock<HashMap<String, VHost>>,
    default: RwLock<Option<VHost>>,
}

impl VirtualHosts {
    /// No sites.
    pub fn new() -> VirtualHosts {
        VirtualHosts::default()
    }

    /// Adds `site` under `name` (lowercase, without a trailing dot),
    /// replacing one there.
    pub fn insert(&self, name: &str, site: VHost) {
        self.inner
            .hosts
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(normalize(name), site);
    }

    /// Makes `site` the default, for hosts no site has. The first default
    /// set keeps the role.
    /// Requests routed this way keep their requested host and carry
    /// [`Routing::Fallback`] in their [`Target`].
    pub fn set_default(&self, site: VHost) {
        self.inner
            .default
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .get_or_insert(site);
    }

    /// The site named `name`.
    pub fn get(&self, name: &str) -> Option<VHost> {
        self.inner
            .hosts
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(name)
            .cloned()
    }

    /// Whether a site named `name` is served over HTTPS here.
    pub fn has_https(&self, name: &str) -> bool {
        self.get(name).is_some_and(|s| s.https)
    }

    fn site_or_default(&self, host: &str) -> Option<(VHost, Routing)> {
        self.get(host)
            .map(|site| (site, Routing::Exact))
            .or_else(|| {
                self.inner
                    .default
                    .read()
                    .unwrap_or_else(|e| e.into_inner())
                    .clone()
                    .map(|site| (site, Routing::Fallback))
            })
    }
}

impl Handler for VirtualHosts {
    fn call(&self, mut request: Request<Body>, ex: &mut Exchange<'_>) -> Reply {
        let Some(host) = request_host(&request) else {
            return Reply::Now(no_host());
        };
        let misdirected = || {
            let mut response = text(
                StatusCode::MISDIRECTED_REQUEST,
                "This server does not serve that host.\n",
            );
            response.extensions_mut().insert(Answer::Misdirected);
            Reply::Now(response)
        };
        let Some((site, routing)) = self.site_or_default(&host) else {
            return misdirected();
        };

        let tls = ex.conn().tls;
        match (tls, site.https) {
            (true, false) => misdirected(),
            (false, true) if !site.plain_http => {
                let path = request
                    .uri()
                    .path_and_query()
                    .map(|p| p.as_str())
                    .unwrap_or("/");
                let location = format!("https://{host}{path}");
                let mut response = text(
                    StatusCode::MOVED_PERMANENTLY,
                    &format!("Moved to {location}\n"),
                );
                if let Ok(value) = location.parse() {
                    response.headers_mut().insert(LOCATION, value);
                }
                response.extensions_mut().insert(Answer::Redirect);
                Reply::Now(response)
            }
            _ => {
                let conn = ex.conn();
                let target = Target {
                    scheme: if tls { Scheme::HTTPS } else { Scheme::HTTP },
                    host,
                    port: conn.local.map_or(0, |a| a.port()),
                    sni: conn.sni.as_deref().map(str::to_owned),
                    routing,
                };
                request.extensions_mut().insert(target);
                site.handler.call(request, ex)
            }
        }
    }
}

/// The answer to a request that names no host: `400`, with `answer`
/// [`Answer::NoHost`] in its extensions. [`VirtualHosts`] gives it, and [`Http1`](super::Http1)
/// gives it to an HTTP/1.1 request without `Host` before any handler.
pub(super) fn no_host() -> http::Response<Body> {
    let mut response = text(StatusCode::BAD_REQUEST, "The request names no host.\n");
    response.extensions_mut().insert(Answer::NoHost);
    response
}

/// The host a request is for: the authority of its URI (HTTP/2's
/// `:authority`, or an absolute URI in HTTP/1.1), else its `Host` header.
/// Lowercase, without the port or a trailing dot.
pub fn request_host<B>(request: &Request<B>) -> Option<String> {
    let host = match request.uri().authority() {
        Some(a) => a.host().to_owned(),
        None => {
            let value = request.headers().get(HOST)?.to_str().ok()?;
            value.parse::<Authority>().ok()?.host().to_owned()
        }
    };
    let host = normalize(&host);
    (!host.is_empty()).then_some(host)
}

// ---------------------------------------------------------------------------
// HTTP on a network

/// HTTP on one port of a [`Net`](fictionet::stdlib::world::net::Net) host: an
/// [`PortServer`] that serves the host's site for each of its DNS names.
///
/// Every host at one address that serves HTTP on a port shares that port:
/// the first host's `Server` takes in the others' sites as
/// [`VirtualHosts`], and each request goes to the site its host names.
/// Names and defaults belong to the local address and port where `Net`
/// installed them. Sharing one address does not add sites at another.
/// Over TLS, ALPN offers `h2` and `http/1.1` with `std` alone.
///
/// ```
/// # use fictionet::stdlib::{web::httpd, world::net::Host};
/// let page = httpd::tower(axum::Router::new().route("/", axum::routing::get(|| async { "hello\n" })));
/// let host = Host::new("www").dns_name("www.corp.test").port_server(80, httpd::Server::new(page));
/// # drop(host);
/// ```
#[derive(Clone)]
pub struct Server {
    observe: Option<super::Observe>,
    vhost: VHost,
    default_host: bool,
    limits: Limits,
    date: Option<SystemTime>,
    vhosts: Arc<RwLock<HashMap<SocketAddr, VirtualHosts>>>,
    tls: Option<ConfigFor>,
}

impl Server {
    /// A site served by `handler`, over plain HTTP.
    pub fn new(handler: impl Handler) -> Server {
        Server::shared(Arc::new(handler))
    }

    /// The same, from a shared handler.
    pub fn shared(handler: Arc<dyn Handler>) -> Server {
        Server {
            observe: None,
            vhost: VHost {
                handler,
                https: false,
                plain_http: false,
            },
            default_host: false,
            limits: Limits::default(),
            date: None,
            vhosts: Arc::default(),
            tls: None,
        }
    }

    /// The site is served over HTTPS: on a TLS port it answers, and on a
    /// plain port its requests get a `301` to https, unless
    /// [`plain_http`](Self::plain_http).
    /// This sets routing policy without installing TLS.
    /// Use [`tls_with`](Self::tls_with) to select a config and
    /// [`served_by`](Self::served_by) to install ports 80 and 443.
    pub fn https(mut self) -> Server {
        self.vhost.https = true;
        self
    }

    /// With [`https`](Self::https), answers plain HTTP too, with no
    /// redirect.
    pub fn plain_http(mut self) -> Server {
        self.vhost.plain_http = true;
        self
    }

    /// Answers requests at its address whose host names no site there.
    /// The first default site at each local address and port keeps the role.
    /// These requests keep their requested host in [`Target`] and carry
    /// [`Routing::Fallback`]. Handlers that forward dynamically should
    /// check [`Target::routing`].
    pub fn default_host(mut self) -> Server {
        self.default_host = true;
        self
    }

    /// Observes response delivery on this port. Sites sharing the port use
    /// the first server's callback, as they do its limits and date.
    pub fn observe(mut self, observe: super::Observe) -> Self {
        self.observe = Some(observe);
        self
    }

    /// Sets the limits and timers.
    pub fn limits(mut self, limits: Limits) -> Server {
        self.limits = limits;
        self
    }

    /// Sends `Date` headers: `start` is the world's date and time at the
    /// start of the run. See [Dates](super#dates). Sites that share a port
    /// use the first one's.
    pub fn date(mut self, start: SystemTime) -> Server {
        self.date = Some(start);
        self
    }

    /// Serves HTTPS on 443 with a config selected for each handshake.
    /// Port 80 redirects to HTTPS unless [`plain_http`](Self::plain_http) was selected.
    pub fn tls_with(
        self,
        config_for: impl Fn(&Cx) -> Arc<ServerConfig> + Send + Sync + 'static,
    ) -> Server {
        self.tls_when(move |fcx| std::future::ready(config_for(fcx)))
    }

    /// [`tls_with`](Self::tls_with) with a config that may take time to
    /// select: each handshake waits for its own, up to its deadline, while
    /// the world goes on.
    pub fn tls_when<F>(mut self, config_for: impl Fn(&Cx) -> F + Send + Sync + 'static) -> Server
    where
        F: Future<Output = Arc<ServerConfig>> + Send + 'static,
    {
        self.vhost.https = true;
        self.tls = Some(Arc::new(move |fcx| {
            Box::pin(config_for(fcx)) as ConfigFuture
        }));
        self
    }

    /// Installs this site on ports 80 and, with TLS, 443.
    /// TLS uses the host's names for SNI; without TLS only port 80 opens.
    /// Each installed port has a fresh virtual-host table, including
    /// when this builder was cloned.
    pub fn served_by(mut self, host: Host) -> Host {
        self.vhosts = Arc::default();
        let secure = self.tls.take().map(|config| {
            let mut server = self.clone();
            server.vhosts = Arc::default();
            server.vhost.plain_http = false;
            (config, server)
        });
        let host = host.port_server(80, self);
        match secure {
            None => host,
            Some((config, server)) => {
                host.tls_accept_when(443, Sni::Names, move |fcx| config(fcx), server)
            }
        }
    }
}

impl Server {
    /// The sites of the address `info` arrived at, as one handler.
    fn handler_for(&self, info: &ConnInfo) -> Arc<dyn Handler> {
        let vhosts = info.local.and_then(|local| {
            self.vhosts
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .get(&local)
                .cloned()
        });
        Arc::new(vhosts.unwrap_or_default())
    }
}

impl PortServer for Server {
    fn serve(&self, fcx: Cx, arrival: Arrival) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let handler = self.handler_for(&arrival.info);
        let opts = HttpOptions {
            observe: self.observe.clone().or(arrival.http_observe.clone()),
            limits: self.limits,
            first_bytes: (!arrival.info.tls).then_some(arrival.limits.handshake),
            budget: arrival.budget,
            date: self.date,
        };
        let (conn, info) = (arrival.conn, arrival.info);
        Box::pin(async move {
            let _ = serve_connection(&fcx, conn, info, handler, &opts).await;
        })
    }

    /// HTTP/2 when TLS agreed on `h2`, else HTTP/1, in the same stack as
    /// TLS. The network's
    /// [`write_timeout`](fictionet::stdlib::world::net::Limits::write_timeout)
    /// gives up on a client that stops reading.
    fn over_tls(&self, _fcx: &Cx, opening: &Opening) -> Option<Boxed> {
        let opts = HttpOptions {
            observe: self.observe.clone().or(opening.http_observe.clone()),
            limits: self.limits,
            first_bytes: None,
            budget: opening.budget.clone(),
            date: self.date,
        };
        let handler = self.handler_for(&opening.info);
        Some(if opening.info.alpn.as_deref() == Some(b"h2".as_slice()) {
            Boxed::new(http2_for(handler, &opts, &opening.info))
        } else {
            Boxed::new(http1_for(handler, &opts, &opening.info).upgradable())
        })
    }

    fn alpn(&self) -> Vec<Vec<u8>> {
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    }

    fn prepare_share(
        &self,
        local: SocketAddr,
        names: &[String],
        other: &Arc<dyn PortServer>,
    ) -> Option<PreparedShare> {
        let other: &dyn Any = &**other;
        let site = other.downcast_ref::<Server>()?;
        let (vhost, default_host) = (site.vhost.clone(), site.default_host);
        let names = names.to_vec();
        let endpoints = self.vhosts.clone();
        Some(PreparedShare::new(move || {
            let mut endpoints = endpoints.write().unwrap_or_else(|e| e.into_inner());
            let vhosts = endpoints.entry(local).or_default();
            for name in names {
                vhosts.insert(&name, vhost.clone());
            }
            if default_host {
                vhosts.set_default(vhost);
            }
        }))
    }
}
