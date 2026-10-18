//! Forwarding HTTP requests to real sites.

use fictionet::stdlib::httpd::{self, Body, Handler, Routing, Target};
use fictionet::{Cx, Error};
use http::{Request, Response};
use std::sync::Arc;

#[path = "upstream.rs"]
mod upstream;
use upstream::Client as ProxyClient;

/// A handler that forwards each request to the real site, over the world's
/// own network. Needs the `web-proxy` feature, which enables `std`.
/// Host helper threads handle DNS, sockets and TLS, waking the world when
/// data is ready. Works with [`fictionet::block_on`] or another executor.
/// Upstream connections use HTTP/1.1 and are reused after complete bodies.
/// Connecting, with the name lookup and the TLS handshake, has thirty
/// seconds. After that a response may take as long as the site does. At
/// most 64 requests are upstream at once, and later ones wait their turn.
///
/// It needs no arguments: it forwards to the [`Target`] that [`Sites`](fictionet::stdlib::web::Sites) puts
/// on every request. The scheme and port come from the connection the
/// agent made; the host comes from the request's authority or `Host` header.
/// The path and query come from the request. The world process makes a new,
/// separate request there through its operating system's network, resolving
/// the name with its own DNS, and returns the answer to the agent.
///
/// The agent never touches the real internet: its connection ends at the
/// world. Over HTTPS the agent sees the world's certificate, from
/// [`Site::tls`](fictionet::stdlib::web::Site::tls), and the real certificate stays between the world and the
/// real site.
///
/// Only names the callback hands to `proxy(&fcx)` are forwarded, so the world
/// stays closed unless it opens a name on purpose. To change some responses
/// and pass the rest through, wrap it in tower or axum middleware.
/// A target must have [`Routing::Exact`]. Requests routed through a
/// default host get `421 Misdirected Request` before any upstream I/O.
/// Their request events carry `answer: misdirected`.
/// Use [`forward`] for a catch-all that forwards to one fixed origin.
///
/// The world checks the real site's certificate against the Mozilla root
/// store (`webpki-roots`). Hop-by-hop headers (`Connection`, `Keep-Alive`,
/// `Transfer-Encoding` and the like) are not passed on in either direction,
/// so it carries no protocol upgrades: a WebSocket handshake reaches the
/// real site as a plain `GET`. A world that wants WebSockets serves them
/// itself, with a handler on the site (see [`httpd`'s upgrades](fictionet::stdlib::httpd)).
/// If the real site cannot be reached, the agent gets `502 Bad Gateway`.
/// Returns an error in a lab before constructing a client.
pub fn proxy(fcx: &Cx) -> Result<Proxy, Error> {
    fcx.require_real_io()?;
    Ok(Proxy {
        client: Arc::new(ProxyClient::new()),
    })
}

/// The handler made by [`proxy`].
/// Its tower response body is [`Body`], for both upstream responses and
/// local routing rejections.
#[derive(Clone)]
pub struct Proxy {
    client: Arc<ProxyClient>,
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
    client: Arc<ProxyClient>,
    request: Request<Body>,
) -> Result<Response<Body>, Error> {
    use http::uri::Scheme;
    let target = request
        .extensions()
        .get::<Target>()
        .cloned()
        .ok_or_else(|| {
            fictionet::Error::msg(
                "web::proxy(&fcx) serves only requests that web::Sites routed: there is no web::Target",
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
    dispatch(
        client,
        request,
        |path| Ok(format!("{}://{}{}", target.scheme, authority, path).parse()?),
        Host::Replace(&authority),
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
/// the request's path and query. A failed request becomes a
/// [`httpd::BadGateway`], prefixed with `error_context` when there is one.
async fn dispatch(
    client: Arc<ProxyClient>,
    request: Request<Body>,
    destination: impl FnOnce(&str) -> Result<http::Uri, Error>,
    host: Host<'_>,
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
    parts.extensions = http::Extensions::new();
    strip_hop_by_hop(&mut parts.headers);
    if let Host::Replace(authority) = host {
        parts.headers.insert(http::header::HOST, authority.parse()?);
    }
    let mut response = client
        .request(Request::from_parts(parts, body))
        .await
        .map_err(|e| {
            httpd::BadGateway(match error_context {
                Some(context) => format!("{context}: {e}"),
                None => e.to_string(),
            })
        })?;
    strip_hop_by_hop(response.headers_mut());
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
/// It uses the same HTTP/1.1 transport and limits as [`proxy`].
/// Returns an error in a lab before constructing a client, and for an
/// upstream without such a scheme or without an authority.
pub fn forward(fcx: &Cx, upstream: http::Uri) -> Result<Forward, Error> {
    use http::uri::Scheme;
    fcx.require_real_io()?;
    let parts = upstream.into_parts();
    match (parts.scheme, parts.authority) {
        (Some(scheme), Some(authority)) if scheme == Scheme::HTTP || scheme == Scheme::HTTPS => {
            Ok(Forward {
                scheme,
                authority,
                client: Arc::new(ProxyClient::new()),
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
    client: Arc<ProxyClient>,
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
        Box::pin(dispatch(
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
            None,
        ))
    }
}
