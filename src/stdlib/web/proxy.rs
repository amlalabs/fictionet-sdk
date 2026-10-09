//! Forwarding HTTP requests to real sites.

use fictionet::stdlib::httpd::{self, Body, Handler, Target};
use fictionet::{Cx, Error};
use http::{Request, Response};
use std::sync::Arc;

/// A handler that forwards each request to the real site, over the world's
/// own network. Needs the `web-proxy` feature and a tokio
/// runtime polling the world.
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
        client: Arc::new(proxy_client()),
    })
}

/// The handler made by [`proxy`].
#[derive(Clone)]
pub struct Proxy {
    client: Arc<ProxyClient>,
}

impl tower_service::Service<Request<Body>> for Proxy {
    type Response = Response<hyper::body::Incoming>;
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

type ProxyClient = hyper_util::client::legacy::Client<
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    Body,
>;

fn proxy_client() -> ProxyClient {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_provider_and_webpki_roots(provider)
        .expect("ring supports the default TLS versions")
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .build();
    hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
        .build(connector)
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
) -> Result<Response<hyper::body::Incoming>, Error> {
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
    let (mut parts, body) = request.into_parts();
    let default_port = (target.scheme == Scheme::HTTP && target.port == 80)
        || (target.scheme == Scheme::HTTPS && target.port == 443);
    let authority = if default_port {
        target.host.clone()
    } else {
        format!("{}:{}", target.host, target.port)
    };
    let path = parts
        .uri
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/");
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

/// Forwards requests to a fixed HTTP or HTTPS origin through the world's
/// network. Paths, queries, bodies, and the original `Host` header are
/// preserved. Connection-specific headers are removed in both directions.
/// The upstream must contain a scheme and authority. Its path is ignored.
/// This handler requires a tokio runtime and real host I/O.
pub fn forward(upstream: http::Uri) -> Forward {
    Forward {
        upstream,
        client: Arc::new(proxy_client()),
    }
}

/// A handler that forwards to one fixed origin.
#[derive(Clone)]
pub struct Forward {
    upstream: http::Uri,
    client: Arc<ProxyClient>,
}

impl Handler for Forward {
    fn call(&self, request: Request<Body>, ex: &mut httpd::Exchange<'_>) -> httpd::Reply {
        httpd::tower(self.clone()).call(request, ex)
    }
}

impl tower_service::Service<Request<Body>> for Forward {
    type Response = Response<hyper::body::Incoming>;
    type Error = Error;
    type Future =
        std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<Body>) -> Self::Future {
        let client = self.client.clone();
        let upstream = self.upstream.clone();
        Box::pin(async move {
            let (mut parts, body) = request.into_parts();
            parts.uri = http::Uri::builder()
                .scheme(
                    upstream
                        .scheme()
                        .cloned()
                        .ok_or_else(|| Error::msg("upstream has no scheme"))?,
                )
                .authority(
                    upstream
                        .authority()
                        .cloned()
                        .ok_or_else(|| Error::msg("upstream has no authority"))?,
                )
                .path_and_query(
                    parts
                        .uri
                        .path_and_query()
                        .map(|p| p.as_str())
                        .unwrap_or("/"),
                )
                .build()?;
            parts.version = http::Version::HTTP_11;
            parts.extensions = http::Extensions::new();
            strip_hop_by_hop(&mut parts.headers);
            let mut response = client
                .request(Request::from_parts(parts, body))
                .await
                .map_err(|e| httpd::BadGateway(e.to_string()))?;
            strip_hop_by_hop(response.headers_mut());
            Ok(response)
        })
    }
}
