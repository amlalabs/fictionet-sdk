//! A `web::Sites` world for the web fuzz targets, and a client side to
//! reach it with.

use std::convert::Infallible;
use std::future::Future;
use std::net::Ipv4Addr;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use std::time::{Duration, UNIX_EPOCH};

use bytes::Bytes;
use http::{Request, Response};
use http_body_util::{BodyExt, Full, Limited};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use fictionet::stdlib::{tls, web};
use fictionet::{Attacher, Cx, attachments};

/// Where the fixed-address sites are.
pub const SITE_ADDR: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 10);
pub const DEFAULT_ADDR: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 40);
/// The names the world serves. `*.wild.test` is any name under it.
pub const NAMES: [&str; 8] =
    ["plain.test", "tls.test", "both.test", "broken.test", "default.test", "other.test", "x.wild.test", "nxdomain.test"];

/// The certificate for the TLS sites, and its key.
pub fn cert() -> &'static (Vec<u8>, Vec<u8>) {
    static CERT: OnceLock<(Vec<u8>, Vec<u8>)> = OnceLock::new();
    CERT.get_or_init(|| {
        let c = rcgen::generate_simple_self_signed(vec!["tls.test".to_owned(), "both.test".to_owned()]).unwrap();
        (c.cert.der().to_vec(), c.key_pair.serialize_der())
    })
}

/// A site that reads the request body (up to 1 MiB) and answers with its
/// size, the method, the path and the version.
#[derive(Clone)]
struct Echo;

impl tower_service::Service<Request<fictionet::stdlib::web::Body>> for Echo {
    type Response = Response<Full<Bytes>>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<fictionet::stdlib::web::Body>) -> Self::Future {
        Box::pin(async move {
            let (parts, body) = request.into_parts();
            let n = match Limited::new(body, 1 << 20).collect().await {
                Ok(b) => b.to_bytes().len() as i64,
                Err(_) => -1,
            };
            let text = format!("{} {} {:?} {n}\n", parts.method, parts.uri, parts.version);
            let big = parts.uri.path() == "/big";
            let body = if big { Bytes::from(vec![b'x'; 256 * 1024]) } else { Bytes::from(text) };
            Ok(Response::new(Full::new(body)))
        })
    }
}

/// A site whose handler fails.
#[derive(Clone)]
struct Broken;

impl tower_service::Service<Request<fictionet::stdlib::web::Body>> for Broken {
    type Response = Response<Full<Bytes>>;
    type Error = std::io::Error;
    type Future = std::future::Ready<Result<Self::Response, std::io::Error>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _: Request<fictionet::stdlib::web::Body>) -> Self::Future {
        std::future::ready(Err(std::io::Error::other("broken on purpose")))
    }
}

/// Starts the sites, with events on, and returns the attacher.
pub fn serve(cx: &Cx) -> Attacher {
    let (der, key) = cert();
    let config = Arc::new(
        tls::config_builder(cx, UNIX_EPOCH + Duration::from_secs(1_800_000_000), rustls::crypto::ring::default_provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![CertificateDer::from(der.clone())], PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.clone())))
            .unwrap(),
    );
    let sites = web::Sites::new(move |host| {
        let c = config.clone();
        match host {
            "plain.test" => Some(web::Site::new(Echo)),
            "tls.test" => Some(web::Site::new(Echo).at(SITE_ADDR).tls(move |_| c.clone())),
            "both.test" => Some(web::Site::new(Echo).at(SITE_ADDR).tls(move |_| c.clone()).plain_http()),
            "broken.test" => Some(web::Site::new(Broken).at(SITE_ADDR)),
            "default.test" => Some(web::Site::new(Echo).at(DEFAULT_ADDR).default_host()),
            "other.test" => Some(web::Site::new(Echo).at(DEFAULT_ADDR)),
            h if h.ends_with(".wild.test") => Some(web::Site::new(Echo)),
            _ => None,
        }
    })
    .journal({
        // Format each entry, as a world that logs them would.
        let journal = fictionet::stdlib::journal::Journal::new();
        journal.subscribe(|e| {
            let _ = format!("{e:?}");
            let _ = fictionet::stdlib::codec::Wire::to_bytes(&e.to_json());
        });
        journal
    });
    let (attacher, attachments) = attachments();
    sites.serve(cx, attachments).unwrap();
    attacher
}

/// A sandbox's side, made of stdlib parts: its TCP and UDP endpoints at
/// `addr`, on an attachment named `name`.
pub struct Client {
    pub tcp: fictionet::stdlib::tcp::Endpoint,
    pub udp: fictionet::stdlib::udp::Endpoint,
    _icmp: fictionet::End,
}

impl Client {
    pub fn new(cx: &Cx, attacher: &Attacher, name: &str, addr: Ipv4Addr) -> Client {
        use fictionet::stdlib::{ip, tcp, udp};
        let end = attacher.attach(name).unwrap();
        let (t, u, icmp, _other) = ip::split_protocols(cx, end);
        Client { tcp: tcp::endpoint(cx, t, addr.into()), udp: udp::endpoint(cx, u, addr.into()), _icmp: icmp }
    }

    /// Looks `name` up at the gateway. `None` if there is no address.
    pub async fn lookup(&self, cx: &Cx, name: &str) -> Option<Ipv4Addr> {
        use fictionet::stdlib::dns::op::{Message, Query};
        use fictionet::stdlib::dns::rr::{Name, RData, RecordType};
        let mut socket = self.udp.bind(5353).ok()?;
        let mut m = Message::query();
        m.metadata.id = 7;
        m.add_query(Query::query(Name::from_ascii(format!("{name}.")).ok()?, RecordType::A));
        socket.send_to(&m.to_vec().ok()?, "10.0.0.1:53".parse().unwrap());
        let (reply, _) = socket.recv(cx).await.ok()?;
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
        rustls::crypto::ring::default_provider().signature_verification_algorithms.supported_schemes()
    }
}

/// A TLS client config that trusts any certificate, with these ALPN
/// protocols.
pub fn client_config(alpn: &[&[u8]]) -> Arc<rustls::ClientConfig> {
    let mut c = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyCert))
        .with_no_client_auth();
    c.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Arc::new(c)
}
