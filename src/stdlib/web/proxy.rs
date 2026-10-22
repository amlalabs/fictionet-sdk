//! Forwarding HTTP requests to real sites.

use fictionet::stdlib::web::httpd::{self, Body, Handler, Routing, Target};
use fictionet::{Cx, Error};
use http::{Request, Response};
use std::sync::Arc;

/// A transport supplied by the host application. The core performs no host I/O.
pub trait Upstream: Send + Sync + 'static {
    /// Sends a request whose URI contains the selected origin.
    fn request(self: Arc<Self>, request: Request<Body>) -> UpstreamFuture;
}

/// One upstream request and its streaming response.
pub type UpstreamFuture =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response<Body>, Error>> + Send>>;

/// A handler that forwards each request to the real site, over the world's
/// own network. Needs the `web-proxy` feature.
/// The supplied transport owns DNS, sockets, TLS and connection pooling.
/// `fictionet_host::Client` supplies the host HTTP/1.1 transport.
///
/// The proxy forwards to the [`Target`] that [`Sites`](fictionet::stdlib::web::Sites)
/// puts on each request. The scheme and port come from the agent's connection;
/// the host comes from the authority or `Host` header. The path and query come
/// from the request.
///
/// The agent never touches the real internet: its connection ends at the
/// world. Over HTTPS the agent sees the world's certificate, from
/// [`Site::tls`](fictionet::stdlib::web::Site::tls), and the real certificate stays between the world and the
/// real site.
///
/// Only names the callback hands to `proxy(&fcx, client)` are forwarded, so the world
/// stays closed unless it opens a name on purpose. To change some responses
/// and pass the rest through, wrap it in tower or axum middleware.
/// A target must have [`Routing::Exact`]. Requests routed through a
/// default host get `421 Misdirected Request` before any upstream I/O.
/// Their request events carry `answer: misdirected`.
/// Use [`forward`] for a catch-all that forwards to one fixed origin.
///
/// The transport must verify upstream certificates. Hop-by-hop headers (`Connection`, `Keep-Alive`,
/// `Transfer-Encoding` and the like) are not passed on in either direction,
/// so it carries no protocol upgrades: a WebSocket handshake reaches the
/// real site as a plain `GET`. A world that wants WebSockets serves them
/// itself, with a handler on the site (see [`httpd`'s upgrades](fictionet::stdlib::web::httpd)).
/// If the real site cannot be reached, the agent gets `502 Bad Gateway`.
/// Every request it sends upstream, answered or not, has a `forwarded`
/// field in its `http.request` event: the origin it went to, such as
/// `https://github.com`.
pub fn proxy(_fcx: &Cx, client: Arc<dyn Upstream>) -> Result<Proxy, Error> {
    Ok(Proxy { client })
}

/// The handler made by [`proxy`].
/// Its tower response body is [`Body`], for both upstream responses and
/// local routing rejections.
#[derive(Clone)]
pub struct Proxy {
    client: Arc<dyn Upstream>,
}

impl tower_service::Service<Request<Body>> for Proxy {
    type Response = Response<Body>;
    type Error = Error;
    type Future =
        std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Error>> + Send>>;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<Body>) -> Self::Future {
        Box::pin(send_upstream(self.client.clone(), request))
    }
}

/// Headers that belong to one connection and are not passed on (RFC 9110,
/// section 7.6.1).
const HOP_BY_HOP: [&str; 8] = [
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "te",
    "trailer",
    "upgrade",
    "proxy-authorization",
];

fn strip_hop_by_hop(headers: &mut http::HeaderMap) {
    let named: Vec<String> = headers
        .get_all(http::header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(',').map(|s| s.trim().to_ascii_lowercase()))
        .collect();
    for name in HOP_BY_HOP
        .iter()
        .copied()
        .chain(named.iter().map(String::as_str))
    {
        headers.remove(name);
    }
}

/// Forwards one request to its [`Target`] over the world's own network.
async fn send_upstream(
    client: Arc<dyn Upstream>,
    request: Request<Body>,
) -> Result<Response<Body>, Error> {
    use http::uri::Scheme;
    let target = request
        .extensions()
        .get::<Target>()
        .cloned()
        .ok_or_else(|| {
            fictionet::Error::msg(
                "web::proxy serves only requests that web::Sites routed: there is no web::Target",
            )
        })?;
    if target.routing != Routing::Exact {
        let mut response = httpd::text(
            http::StatusCode::MISDIRECTED_REQUEST,
            "This proxy does not serve unregistered hosts.\n",
        );
        response
            .extensions_mut()
            .insert(fictionet::events::Fields::new().with("answer", "misdirected"));
        return Ok(response);
    }
    let default_port = (target.scheme == Scheme::HTTP && target.port == 80)
        || (target.scheme == Scheme::HTTPS && target.port == 443);
    let authority = if default_port {
        target.host.clone()
    } else {
        format!("{}:{}", target.host, target.port)
    };
    let origin = format!("{}://{}", target.scheme, authority);
    dispatch(
        client,
        request,
        |path| Ok(format!("{origin}{path}").parse()?),
        Host::Replace(&authority),
        &origin,
        Some(&target.host),
    )
    .await
}

/// What [`dispatch`] does with the request's `Host` header.
enum Host<'a> {
    /// Keeps the agent's `Host` header.
    Preserve,
    /// Replaces it with this authority.
    Replace(&'a str),
}

/// Sends one request upstream. `destination` makes the upstream URI from
/// the request's path and query. A failed request is answered `502 Bad
/// Gateway`, prefixed with `error_context` when there is one. Before sending, the
/// request records a `forwarded` event field naming `origin`, so the
/// request's event says it left the world.
async fn dispatch(
    client: Arc<dyn Upstream>,
    request: Request<Body>,
    destination: impl FnOnce(&str) -> Result<http::Uri, Error>,
    host: Host<'_>,
    origin: &str,
    error_context: Option<&str>,
) -> Result<Response<Body>, Error> {
    let (mut parts, body) = request.into_parts();
    parts.uri = destination(
        parts
            .uri
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or("/"),
    )?;
    parts.version = http::Version::HTTP_11;
    if let Some(fields) = parts.extensions.get::<httpd::RequestFields>() {
        fields.record_fields(fictionet::events::Fields::new().with("forwarded", origin));
    }
    parts.extensions.clear();
    strip_hop_by_hop(&mut parts.headers);
    if let Host::Replace(authority) = host {
        parts.headers.insert(http::header::HOST, authority.parse()?);
    }
    let request = Request::from_parts(parts, body);
    let mut response = client.request(request).await.map_err(|error| {
        httpd::BadGateway(match error_context {
            Some(context) => format!("{context}: {error}"),
            None => error.to_string(),
        })
    })?;
    strip_hop_by_hop(response.headers_mut());
    response
        .extensions_mut()
        .insert(fictionet::events::Fields::new().with("forwarded", origin));
    Ok(response)
}

/// Forwards requests to a fixed HTTP or HTTPS origin through the world's
/// network. Paths, queries, bodies, and the original `Host` header are
/// preserved. Connection-specific headers are removed in both directions.
/// `upstream` must have an `http` or `https` scheme and an authority. Its
/// path is ignored.
/// The origin does not depend on [`Target`], so default-host requests can
/// be forwarded here even when their routing is [`Routing::Fallback`].
/// This handler requires real host I/O and works with any executor.
/// It uses the supplied transport, and its
/// requests' events carry the same `forwarded` field.
/// Returns an error for an
/// upstream without such a scheme or without an authority.
pub fn forward(_fcx: &Cx, upstream: http::Uri, client: Arc<dyn Upstream>) -> Result<Forward, Error> {
    use http::uri::Scheme;
    let parts = upstream.into_parts();
    match (parts.scheme, parts.authority) {
        (Some(scheme), Some(authority)) if scheme == Scheme::HTTP || scheme == Scheme::HTTPS => {
            Ok(Forward {
                scheme,
                authority,
                client,
            })
        }
        _ => Err(Error::msg(
            "web::forward needs an upstream with an http or https scheme and an authority",
        )),
    }
}

/// A handler that forwards to one fixed origin.
/// Its tower response body is [`Body`], streaming the upstream response.
#[derive(Clone)]
pub struct Forward {
    scheme: http::uri::Scheme,
    authority: http::uri::Authority,
    client: Arc<dyn Upstream>,
}

impl Handler for Forward {
    fn call(&self, request: Request<Body>, ex: &mut httpd::Exchange<'_>) -> httpd::Reply {
        httpd::tower(self.clone()).call(request, ex)
    }
}

impl tower_service::Service<Request<Body>> for Forward {
    type Response = Response<Body>;
    type Error = Error;
    type Future =
        std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<Body>) -> Self::Future {
        let client = self.client.clone();
        let scheme = self.scheme.clone();
        let authority = self.authority.clone();
        Box::pin(async move {
            let origin = format!("{scheme}://{authority}");
            dispatch(
                client,
                request,
                move |path| {
                    Ok(http::Uri::builder()
                        .scheme(scheme)
                        .authority(authority)
                        .path_and_query(path)
                        .build()?)
                },
                Host::Preserve,
                &origin,
                None,
            )
            .await
        })
    }
}
