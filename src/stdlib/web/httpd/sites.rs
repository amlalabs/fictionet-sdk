use std::any::Any;
use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use crate::stdlib::web::Request;
use http::StatusCode;

use fictionet::Cx;
use fictionet::stdlib::network::ConnInfo;
use fictionet::stdlib::services::stack::Boxed;
use fictionet::stdlib::services::tls::{self, CertifiedKey};
use fictionet::stdlib::world::net::{
    Arrival, CertificateFor, CertificateFuture, Host, Opening, PortServer, PortStack,
    PreparedShare, Sni,
};

use super::{Exchange, Handler, HttpOptions, Limits, Reply, http_for, serve_connection, text};

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
/// Present in that response's `answer` field; absent for a handler's own answer.
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
/// - Every other request goes to the site's handler, with a typed [`Site`](crate::stdlib::web::Site).
///   Its [`routing`](crate::stdlib::web::Site::routing) distinguishes a registered
///   host from a default-site fallback.
///
/// Its own answers carry an [`Answer`] in their response metadata.
#[derive(Clone, Default)]
pub struct VirtualHosts {
    inner: Arc<VInner>,
}

#[derive(Default)]
struct VInner {
    hosts: RwLock<Vec<(Arc<str>, VHost)>>,
    default: RwLock<Option<VHost>>,
}

impl VirtualHosts {
    /// No sites.
    pub fn new() -> VirtualHosts {
        VirtualHosts::default()
    }

    /// Adds `site` under `name`, ignoring ASCII case and trailing dots,
    /// replacing one there.
    pub fn insert(&self, name: &str, site: VHost) {
        let mut hosts = self.inner.hosts.write().unwrap_or_else(|e| e.into_inner());
        let name = name.trim_end_matches('.');
        if let Some((_, old)) = hosts.iter_mut().find(|(n, _)| n.eq_ignore_ascii_case(name)) {
            *old = site;
        } else {
            hosts.push((Arc::from(name), site));
        }
    }

    /// Makes `site` the default, for hosts no site has. The first default
    /// set keeps the role.
    /// Requests routed this way keep their requested host and carry
    /// [`Routing::Fallback`] in their [`Site`](crate::stdlib::web::Site).
    pub fn set_default(&self, site: VHost) {
        self.inner
            .default
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .get_or_insert(site);
    }

    /// The site named `name`.
    pub fn get(&self, name: &[u8]) -> Option<VHost> {
        self.inner
            .hosts
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .find(|(n, _)| n.as_bytes().eq_ignore_ascii_case(name))
            .map(|(_, site)| site.clone())
    }

    /// Whether a site named `name` is served over HTTPS here.
    pub fn has_https(&self, name: &str) -> bool {
        self.get(name.as_bytes()).is_some_and(|s| s.https)
    }

    fn site_or_default(&self, host: &[u8]) -> Option<(Option<Arc<str>>, VHost, Routing)> {
        self.inner
            .hosts
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .find(|(name, _)| name.as_bytes().eq_ignore_ascii_case(host))
            .map(|(name, site)| (Some(name.clone()), site.clone(), Routing::Exact))
            .or_else(|| {
                self.inner
                    .default
                    .read()
                    .unwrap_or_else(|e| e.into_inner())
                    .clone()
                    .map(|site| (None, site, Routing::Fallback))
            })
    }
}

impl Handler for VirtualHosts {
    fn call(&self, mut request: Request, ex: &mut Exchange<'_>) -> Reply {
        let Some(host) = request.head.host() else {
            return Reply::Now(no_host(ex.responses()));
        };
        let misdirected = || {
            let mut response = text(
                ex.responses(),
                StatusCode::MISDIRECTED_REQUEST,
                "This server does not serve that host.\n",
            );
            response.answer = Some(Answer::Misdirected);
            Reply::Now(response)
        };
        let Some((name, site, routing)) = self.site_or_default(host) else {
            return misdirected();
        };

        let tls = ex.conn().tls;
        match (tls, site.https) {
            (true, false) => misdirected(),
            (false, true) if !site.plain_http => {
                let path = request.head.path_and_query();
                let host = std::str::from_utf8(host).expect("validated host");
                let slash = if path.starts_with('?') { "/" } else { "" };
                let location = format!("https://{host}{slash}{path}");
                let mut response = text(
                    ex.responses(),
                    StatusCode::MOVED_PERMANENTLY,
                    &format!("Moved to {location}\n"),
                );
                response.fields = crate::stdlib::web::Fields::new([
                    ("content-type", "text/plain; charset=utf-8"),
                    ("location", location.as_str()),
                ]);
                response.answer = Some(Answer::Redirect);
                Reply::Now(response)
            }
            _ => {
                request.site.name = name.unwrap_or_else(|| {
                    Arc::from(std::str::from_utf8(host).expect("validated host"))
                });
                request.site.routing = routing;
                site.handler.call(request, ex)
            }
        }
    }
}

/// The answer to a request that names no host: `400`, with `answer`
/// [`Answer::NoHost`] in its `answer` field. [`VirtualHosts`] gives it, and [`Http1`](super::Http1)
/// gives it to an HTTP/1.1 request without `Host` before any handler.
pub(super) fn no_host(storage: &super::Responses) -> crate::stdlib::web::Response {
    let mut response = text(
        storage,
        StatusCode::BAD_REQUEST,
        "The request names no host.\n",
    );
    response.answer = Some(Answer::NoHost);
    response
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
/// The default stack is `Chain<TlsLayer, Later<Boxed>>`; its application
/// is [`Http`](super::Http), from [`http_for`]. HTTP/2 in turn composes
/// `Chain<Http2, Children<Respond, Top, Opening>>`. Replace the TLS factory
/// with [`tls_layer`](Self::tls_layer), or negotiated applications with
/// [`applications`](Self::applications).
///
/// ```
/// # use fictionet::stdlib::{web::httpd, world::net::Host};
/// let page = fictionet_extras::httpd::tower(axum::Router::new().route("/", axum::routing::get(|| async { "hello\n" })));
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
    tls: Option<CertificateFor>,
    tls_layer: tls::Factory,
    application: ApplicationFor,
    protocols: Vec<Vec<u8>>,
}

type ApplicationFor =
    Arc<dyn Fn(&Cx, &Opening, Arc<dyn Handler>, &HttpOptions) -> Boxed + Send + Sync>;

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
            tls_layer: tls::Factory::default(),
            application: Arc::new(|cx, opening, handler, opts| {
                Boxed::new(http_for(handler, opts, &opening.info, cx.now()))
            }),
            protocols: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
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
    /// These requests keep their requested host in [`Site`](crate::stdlib::web::Site) and carry
    /// [`Routing::Fallback`]. Handlers that forward dynamically should
    /// check [`Site::routing`](crate::stdlib::web::Site::routing).
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

    pub(crate) fn inherit_observer(&mut self, observe: &Option<super::Observe>) {
        if self.observe.is_none() {
            self.observe = observe.clone();
        }
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

    /// Replaces TLS for this listener. The first TLS site installed at an
    /// address and port selects the factory for every site sharing it;
    /// later sites still select their own certificates and applications.
    /// The default is `Chain<TlsLayer, Later<Boxed>>` through `Secure`.
    /// The application box contains [`Http`](super::Http), from [`http_for`];
    /// HTTP/2 is `Chain<Http2, Children<Respond, Top, Opening>>`.
    pub fn tls_layer(mut self, factory: tls::Factory) -> Self {
        self.tls_layer = factory;
        self
    }

    /// Selects an application from `opening.info.alpn`, advertising
    /// `protocols` in the handshake. The factory receives the routed site
    /// handler, connection budget, limits and runtime context. Use
    /// [`http_for`] for the standard HTTP/1 and HTTP/2 choices, or return
    /// another byte-stream application for another negotiated protocol.
    /// Each TLS site selects its own protocols and application, even when
    /// it shares routing, limits and the response observer with other sites.
    /// The default is [`http_for`]; HTTP/2 composes its multiplexed
    /// streams with `Children` and the request handler.
    pub fn applications(
        mut self,
        protocols: Vec<Vec<u8>>,
        make: impl Fn(&Cx, &Opening, Arc<dyn Handler>, &HttpOptions) -> Boxed + Send + Sync + 'static,
    ) -> Self {
        self.protocols = protocols;
        self.application = Arc::new(make);
        self
    }

    /// Serves HTTPS on 443 with a certificate selected for each handshake.
    /// Port 80 redirects to HTTPS unless [`plain_http`](Self::plain_http) was selected.
    pub fn tls_with(
        self,
        certificate_for: impl Fn(&Cx) -> Arc<CertifiedKey> + Send + Sync + 'static,
    ) -> Server {
        self.tls_when(move |fcx| std::future::ready(certificate_for(fcx)))
    }

    /// [`tls_with`](Self::tls_with) with a certificate that may take time to
    /// select: each handshake waits for its own, up to its deadline, while
    /// the world goes on.
    pub fn tls_when<F>(
        mut self,
        certificate_for: impl Fn(&Cx) -> F + Send + Sync + 'static,
    ) -> Server
    where
        F: Future<Output = Arc<CertifiedKey>> + Send + 'static,
    {
        self.vhost.https = true;
        self.tls = Some(Arc::new(move |fcx| {
            Box::pin(certificate_for(fcx)) as CertificateFuture
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
    fn serve_connection(
        &self,
        fcx: Cx,
        arrival: Arrival,
    ) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let handler = self.handler_for(&arrival.info);
        let opts = HttpOptions {
            observe: self.observe.clone(),
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

    /// The configured application, by default HTTP/2 when TLS agreed on
    /// `h2`, else HTTP/1, in the same stack as TLS. The network's
    /// [`write_timeout`](fictionet::stdlib::world::net::Limits::write_timeout)
    /// gives up on a client that stops reading.
    fn stack(&self, fcx: &Cx, opening: &Opening) -> PortStack {
        let opts = HttpOptions {
            observe: self.observe.clone(),
            limits: self.limits,
            first_bytes: (!opening.info.tls).then_some(opening.limits.handshake),
            budget: opening.budget.clone(),
            date: self.date,
        };
        let handler = self.handler_for(&opening.info);
        PortStack::Stack((self.application)(fcx, opening, handler, &opts))
    }

    fn tls_factory(&self) -> tls::Factory {
        self.tls_layer.clone()
    }

    fn alpn(&self) -> Vec<Vec<u8>> {
        self.protocols.clone()
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
        let mut application = self.clone();
        application.application = site.application.clone();
        application.protocols = site.protocols.clone();
        Some(
            PreparedShare::new(move || {
                let mut endpoints = endpoints.write().unwrap_or_else(|e| e.into_inner());
                let vhosts = endpoints.entry(local).or_default();
                for name in names {
                    vhosts.insert(&name, vhost.clone());
                }
                if default_host {
                    vhosts.set_default(vhost);
                }
            })
            .tls_server(Arc::new(application)),
        )
    }
}
