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
use fictionet::stdlib::net::{Arrival, ConfigFor, Host, PortServer, PreparedShare, Sni};
use fictionet::stdlib::tls::ServerConfig;

use super::response::answered;
use super::{
    Body, Exchange, Handler, HttpOptions, Limits, Observer, Reply, serve_connection, text,
};

pub use fictionet::stdlib::net::normalize;

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
/// Its own answers put `answer` in the request's event: `no_host`,
/// `misdirected` or `redirect`.
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
    fictionet::cfg_tokio! {
    fn hyper_upgrade(&self, request: &Request<Body>) -> bool {
        request_host(request).and_then(|host| self.site_or_default(&host))
            .is_some_and(|(site, _)| site.handler.hyper_upgrade(request))
    }
    }

    fn call(&self, mut request: Request<Body>, ex: &mut Exchange<'_>) -> Reply {
        let Some(host) = request_host(&request) else {
            return Reply::Now(no_host());
        };
        let misdirected = || {
            Reply::Now(answered(
                text(
                    StatusCode::MISDIRECTED_REQUEST,
                    "This server does not serve that host.\n",
                ),
                "misdirected",
            ))
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
                Reply::Now(answered(response, "redirect"))
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
/// `no_host` in its event. [`VirtualHosts`] gives it, and [`Http1`](super::Http1)
/// gives it to an HTTP/1.1 request without `Host` before any handler.
pub(super) fn no_host() -> http::Response<Body> {
    answered(
        text(StatusCode::BAD_REQUEST, "The request names no host.\n"),
        "no_host",
    )
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

/// HTTP on one port of a [`Net`](fictionet::stdlib::net::Net) host: an
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
/// # use fictionet::stdlib::{httpd, net::Host};
/// let page = httpd::Router::new().get("/", |_, _| http::Response::new("hello\n".into()));
/// let host = Host::new("www").dns_name("www.corp.test").port_server(80, httpd::Server::new(page));
/// # drop(host);
/// ```
#[derive(Clone)]
pub struct Server {
    vhost: VHost,
    default_host: bool,
    limits: Limits,
    date: Option<SystemTime>,
    observe: Option<Arc<dyn Observer>>,
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
            vhost: VHost {
                handler,
                https: false,
                plain_http: false,
            },
            default_host: false,
            limits: Limits::default(),
            date: None,
            observe: None,
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

    /// Observes requests before virtual hosting and admission. Sites sharing
    /// an endpoint use the first server's observer, as they do its date.
    pub fn observe(mut self, observer: Arc<dyn Observer>) -> Server {
        self.observe = Some(observer);
        self
    }

    /// Serves HTTPS on 443 with a config selected for each handshake.
    /// Port 80 redirects to HTTPS unless [`plain_http`](Self::plain_http) was selected.
    pub fn tls_with(
        mut self,
        config_for: impl Fn(&Cx) -> Arc<ServerConfig> + Send + Sync + 'static,
    ) -> Server {
        self.vhost.https = true;
        self.tls = Some(Arc::new(config_for));
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
                host.tls_accept(443, Sni::Names, move |fcx| config(fcx), server)
            }
        }
    }
}

impl PortServer for Server {
    fn serve(&self, fcx: Cx, arrival: Arrival) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let vhosts = arrival.info.local.and_then(|local| {
            self.vhosts
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .get(&local)
                .cloned()
        });
        let handler: Arc<dyn Handler> = Arc::new(vhosts.unwrap_or_default());
        let opts = HttpOptions {
            limits: self.limits,
            first_bytes: (!arrival.info.tls).then_some(arrival.handshake),
            budget: arrival.budget,
            date: self.date,
            observe: self.observe.clone(),
        };
        let (conn, info) = (arrival.conn, arrival.info);
        Box::pin(async move {
            let _ = serve_connection(&fcx, conn, info, handler, &opts).await;
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
