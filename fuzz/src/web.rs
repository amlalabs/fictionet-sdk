//! A `web::Sites` world for the web fuzz targets, and a client side to
//! reach it with.

use std::net::Ipv4Addr;
use std::sync::Arc;

use bytes::Bytes;
use fictionet::stdlib::web::Response;
use rustls::pki_types::CertificateDer;

use fictionet::stdlib::{services::tls, web};
use fictionet::{Attacher, Cx, attachments};

/// Where the fixed-address sites are.
pub const SITE_ADDR: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 10);
pub const DEFAULT_ADDR: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 40);
/// The names the world serves. `*.wild.test` is any name under it.
pub const NAMES: [&str; 8] = [
    "plain.test",
    "tls.test",
    "both.test",
    "broken.test",
    "default.test",
    "other.test",
    "x.wild.test",
    "nxdomain.test",
];

/// A site that reads the request body (up to 1 MiB) and answers with its
/// size, the method, the path and the version.
#[derive(Clone)]
struct Echo;

impl web::httpd::Handler for Echo {
    fn call(&self, request: web::Request, _: &mut web::httpd::Exchange<'_>) -> web::httpd::Reply {
        web::httpd::Reply::Later(Box::new(move |_| {
            Box::pin(async move {
                let parts = request.head.to_http()?;
                let mut body = request.body;
                let mut n: i64 = 0;
                while let Some(piece) = std::future::poll_fn(|cx| body.poll_next(cx)).await {
                    match piece {
                        Ok(piece) if n + piece.len() as i64 <= 1 << 20 => n += piece.len() as i64,
                        _ => {
                            n = -1;
                            break;
                        }
                    }
                }
                let text = format!("{} {} {:?} {n}\n", parts.method, parts.uri, parts.version);
                let big = parts.uri.path() == "/big";
                let body = if big {
                    Bytes::from(vec![b'x'; 256 * 1024])
                } else {
                    Bytes::from(text)
                };
                Ok(Response::new(web::Body::from(body)))
            })
        }))
    }
}

/// A site whose handler fails.
#[derive(Clone)]
struct Broken;

impl web::httpd::Handler for Broken {
    fn call(&self, _: web::Request, _: &mut web::httpd::Exchange<'_>) -> web::httpd::Reply {
        web::httpd::Reply::Later(Box::new(|_| {
            Box::pin(async { Err(std::io::Error::other("broken on purpose").into()) })
        }))
    }
}

/// Starts the sites, with events on, and returns the attacher.
pub fn serve(fcx: &Cx, cert: &fictionet::stdlib::services::ca::Leaf) -> Attacher {
    let config = Arc::new(tls::CertifiedKey {
        chain: cert.chain.clone(),
        key: cert.key.clone_key(),
    });
    let sites = web::Sites::new(
        fictionet::stdlib::world::net::Pools {
            v4: Some("104.18.0.0/15".parse().unwrap()),
            v6: Some("2606:4700:100::/48".parse().unwrap()),
        },
        move |host| {
            let c = config.clone();
            match host {
                "plain.test" => Some(web::SiteConfig::handler(Echo)),
                "tls.test" => Some(web::SiteConfig::handler(Echo).at(SITE_ADDR).tls(c)),
                "both.test" => Some(
                    web::SiteConfig::handler(Echo)
                        .at(SITE_ADDR)
                        .tls(c)
                        .plain_http(),
                ),
                "broken.test" => Some(web::SiteConfig::handler(Broken).at(SITE_ADDR)),
                "default.test" => Some(
                    web::SiteConfig::handler(Echo)
                        .at(DEFAULT_ADDR)
                        .default_host(),
                ),
                "other.test" => Some(web::SiteConfig::handler(Echo).at(DEFAULT_ADDR)),
                h if h.ends_with(".wild.test") => Some(web::SiteConfig::handler(Echo)),
                _ => None,
            }
        },
    );
    let (attacher, attachments) = attachments();
    sites.start(fcx, attachments).unwrap();
    attacher
}

/// A sandbox's side, made of stdlib parts: its TCP and UDP endpoints at
/// `addr`, on an attachment named `name`.
pub struct Client {
    pub tcp: fictionet::stdlib::network::tcp::Endpoint,
    pub udp: fictionet::stdlib::network::udp::Endpoint,
    _icmp: fictionet::End,
}

impl Client {
    pub fn new(fcx: &Cx, attacher: &Attacher, name: &str, addr: Ipv4Addr) -> Client {
        use fictionet::stdlib::network::{ip, tcp, udp};
        let end = attacher.attach(name).unwrap();
        let (t, u, icmp, _other) = ip::split_protocols(fcx, end);
        Client {
            tcp: tcp::endpoint(fcx, t, addr.into()),
            udp: udp::endpoint(fcx, u, addr.into()),
            _icmp: icmp,
        }
    }

    /// Looks `name` up at the gateway. `None` if there is no address.
    pub async fn lookup(&self, fcx: &Cx, name: &str) -> Option<Ipv4Addr> {
        use fictionet::stdlib::protocols::dns::op::{Message, Query};
        use fictionet::stdlib::protocols::dns::rr::{Name, RData, RecordType};
        let mut socket = self.udp.bind(5353).ok()?;
        let mut m = Message::query();
        m.metadata.id = 7;
        m.add_query(Query::query(
            Name::from_ascii(format!("{name}.")).ok()?,
            RecordType::A,
        ));
        socket.send_to(&m.to_vec().ok()?, "10.0.0.1:53".parse().unwrap());
        let (reply, _) = socket.recv(fcx).await.ok()?;
        let reply = Message::from_vec(&reply).ok()?;
        reply.answers.iter().find_map(|r| match &r.data {
            RData::A(a) => Some(a.0),
            _ => None,
        })
    }
}

/// Accepts any server certificate: the fuzz targets test the server.
#[derive(Debug)]
pub struct AnyCert;

impl rustls::client::danger::ServerCertVerifier for AnyCert {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// A TLS client config that trusts any certificate, with these ALPN
/// protocols.
pub fn client_config(alpn: &[&[u8]]) -> Arc<rustls::ClientConfig> {
    let mut c = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(AnyCert))
    .with_no_client_auth();
    c.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Arc::new(c)
}
