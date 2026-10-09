//! A small world of websites, written with `web::Sites`.
//!
//! ```text
//! cargo run --features tokio --example web_world -- /run/fictionet/world.sock /run/fictionet/ca.pem
//! ```
//!
//! It makes a certificate authority for the world when it starts and
//! writes its certificate to the second path, so the sandbox can trust it
//! (`curl --cacert`). Then it serves:
//!
//! The network is dual-stack: every site has an IPv4 and an IPv6 address,
//! except the two that test one family.
//!
//! - `example.test` and `www.example.test`: an axum app over HTTPS. `/`
//!   answers with the request's [`web::Target`] and HTTP version, `/count`
//!   with how many times it was asked. Port 80 redirects to https.
//!   Both live at 203.0.113.10 and 2001:db8:113::10.
//! - `shared.test`: a plain HTTP site at the same addresses, with no TLS.
//! - `plain.test`: a plain HTTP site with addresses of its own, from
//!   `198.18.0.0/15` and `2001:2::/48`, with no TLS, so its port 443 is
//!   closed. Every path answers with the request's target.
//! - `v4only.test` and `v6only.test`: the same app over HTTPS, with only
//!   an IPv4 or only an IPv6 address. DNS answers the other record type
//!   with NODATA.
//! - every other name: NXDOMAIN.
//!
//! The sites record every DNS query, TLS handshake and HTTP request as an
//! event (`dns.query`, `tls.handshake`, `http.request`). Watch them, and the
//! whole world, with `fictionet dashboard --world unix:<socket>`: see
//! [`fictionet::observe`].
//!
//! The web test adds bulk transfers and a proxy in `tests/web_fixture`.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use axum::Extension;
use axum::routing::get;
use fictionet::Result;
use fictionet::stdlib::tls;
use fictionet::stdlib::web;
use http::Version;
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

/// The addresses `example.test`, `www.example.test` and `shared.test`
/// share.
pub const SHARED: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 10);
const SHARED6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0x113, 0, 0, 0, 0, 0x10);

fn main() -> Result {
    run(start)
}

/// Starts a world on the socket and writes its CA certificate.
pub fn run(
    start: fn(
        &fictionet::Cx,
        Vec<rustls::pki_types::CertificateDer<'static>>,
        PrivateKeyDer<'static>,
        fictionet::Attachments,
    ) -> Result,
) -> Result {
    let args: Vec<String> = std::env::args().collect();
    let path = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| "/run/fictionet/world.sock".into());
    let ca_path = args
        .get(2)
        .cloned()
        .unwrap_or_else(|| "/run/fictionet/ca.pem".into());

    // The world's CA and one certificate for its HTTPS names.
    let mut ca = CertificateParams::new(Vec::<String>::new())?;
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    // Python 3.13 and later check certificates strictly: a CA must say
    // what its key is for, and a leaf must name the key that signed it.
    ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca.distinguished_name
        .push(rcgen::DnType::CommonName, "web_world CA");
    let ca_key = KeyPair::generate()?;
    let ca = ca.self_signed(&ca_key)?;
    let names = [
        "example.test",
        "www.example.test",
        "v4only.test",
        "v6only.test",
    ];
    let mut leaf = CertificateParams::new(names.map(str::to_owned).to_vec())?;
    leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    // Python 3.13 and later refuse a leaf without an authority key identifier.
    leaf.use_authority_key_identifier_extension = true;
    let leaf_key = KeyPair::generate()?;
    let leaf = leaf.signed_by(&leaf_key, &ca, &ca_key)?;
    std::fs::write(&ca_path, ca.pem())?;
    let chain = vec![leaf.der().clone()];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));

    let (attacher, attachments) = fictionet::attachments();
    let _listening = fictionet::listen(
        fictionet::WorldSocket::UnixSocket(path.clone().into()),
        attacher,
    )?;
    println!("listening on {path}, CA in {ca_path}");

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(fictionet::run(
        fictionet::Seed::random(),
        move |fcx| async move { start(&fcx, chain, key, attachments) },
    ))
}

/// Builds the world's sites on `attachments`, with `chain` and `key` for
/// every HTTPS name.
fn start(
    fcx: &fictionet::Cx,
    chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    attachments: fictionet::Attachments,
) -> Result {
    web::Sites::new(sites(fcx, chain, key, app(), plain())?).start(fcx, attachments)
}

/// The HTTPS app, shared by all four HTTPS names.
pub fn app() -> axum::Router {
    let count = Arc::new(AtomicU64::new(0));
    axum::Router::new()
        .route(
            "/",
            get(
                |Extension(t): Extension<web::Target>, version: Version| async move {
                    format!(
                        "hello from {} {} {} over {:?}\n",
                        t.scheme, t.host, t.port, version
                    )
                },
            ),
        )
        .route(
            "/count",
            get(move || {
                let n = count.fetch_add(1, Ordering::SeqCst) + 1;
                async move { format!("{n}\n") }
            }),
        )
}

/// The plain HTTP app, shared by both HTTP names.
pub fn plain() -> axum::Router {
    axum::Router::new().fallback(|Extension(t): Extension<web::Target>| async move {
        format!("plain site {} {} {}\n", t.scheme, t.host, t.port)
    })
}

/// Resolves the world's names to sites with the given apps.
pub fn sites(
    fcx: &fictionet::Cx,
    chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    app: axum::Router,
    plain: axum::Router,
) -> Result<impl Fn(&str) -> Option<web::Site> + Send + Sync + 'static> {
    let config = Arc::new(
        tls::config_builder(fcx, SystemTime::now())
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(chain, key)?,
    );
    Ok(move |host: &str| {
        println!("lookup {host}");
        match host {
            "example.test" | "www.example.test" => {
                Some(web::Site::new(app.clone()).at(SHARED).at(SHARED6).tls({
                    let c = config.clone();
                    move |_| c.clone()
                }))
            }
            "v4only.test" => Some(web::Site::new(app.clone()).ipv4_only().tls({
                let c = config.clone();
                move |_| c.clone()
            })),
            "v6only.test" => Some(web::Site::new(app.clone()).ipv6_only().tls({
                let c = config.clone();
                move |_| c.clone()
            })),
            "shared.test" => Some(web::Site::new(plain.clone()).at(SHARED).at(SHARED6)),
            "plain.test" => Some(web::Site::new(plain.clone())),
            _ => None,
        }
    })
}
