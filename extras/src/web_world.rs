//! The sites and startup of the quick-start world. The web test's fixture,
//! `tests/web_fixture`, serves it with routes of its own added.
//!
//! `run` takes the attachment socket, CA output and optional observation
//! socket after the executable name. The third path installs a collector
//! and serves its handle with `fictionet_observe::serve`:
//!
//! ```sh
//! cargo run -p fictionet --features web-proxy,tokio --example web_fixture -- /run/fictionet/world.sock /run/fictionet/ca.pem /run/fictionet/observation.sock
//! fictionet observe --observation unix:/run/fictionet/observation.sock watch
//! ```
//!
//! Run the watch command in another terminal. See `fictionet_observe` for
//! the shell commands and capture limits.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use axum::Extension;
use axum::routing::get;
use fictionet::Result;
use fictionet::stdlib::protocols::x509;
use fictionet::stdlib::services::{ca, tls};
use fictionet::stdlib::web;
use http::Version;
use rustls::pki_types::PrivateKeyDer;

/// The addresses `example.test`, `www.example.test` and `shared.test`
/// share.
pub const SHARED: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 10);
const SHARED6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0x113, 0, 0, 0, 0, 0x10);

/// Starts a world on the socket and writes its CA certificate.
pub fn run(
    args: &[String],
    start: fn(
        &fictionet::Cx,
        Vec<rustls::pki_types::CertificateDer<'static>>,
        PrivateKeyDer<'static>,
        fictionet::Attachments,
    ) -> Result,
) -> Result {
    let path = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| "/run/fictionet/world.sock".into());
    let ca_path = args
        .get(2)
        .cloned()
        .unwrap_or_else(|| "/run/fictionet/ca.pem".into());

    let (options, _observation) = fictionet_observe::serve_observation(
        fictionet::RunOptions::new(fictionet::Seed::random()),
        args.get(3).map(Into::into),
        None,
    )?;
    let (_listening, attachments) =
        fictionet::Listening::bind(fictionet::WorldSocket::UnixSocket(path.clone().into()))?;
    println!("listening on {path}, CA in {ca_path}");

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(fictionet::run(options, move |fcx| async move {
        let (ca, leaf) = certificates(&fcx)?;
        std::fs::write(&ca_path, ca.cert_pem())?;
        start(&fcx, leaf.chain, leaf.key, attachments)
    }))
}

/// The world's certificate authority, and the certificate it issues for
/// every HTTPS name.
pub fn certificates(fcx: &fictionet::Cx) -> Result<(ca::Ca, ca::Leaf)> {
    let ca = ca::Ca::new(fcx, "web_world CA")?;
    let leaf = ca.issue(
        fcx,
        &[
            "example.test",
            "www.example.test",
            "v4only.test",
            "v6only.test",
        ],
        x509::Validity {
            not_before: x509::Time::from_unix(946684800).unwrap(),
            not_after: x509::Time::from_unix(4102444800).unwrap(),
        },
    )?;
    Ok((ca, leaf))
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
            "example.test" | "www.example.test" => Some(
                web::Site::new(app.clone())
                    .at(SHARED)
                    .at(SHARED6)
                    .tls(config.clone()),
            ),
            "v4only.test" => Some(web::Site::new(app.clone()).ipv4_only().tls(config.clone())),
            "v6only.test" => Some(web::Site::new(app.clone()).ipv6_only().tls(config.clone())),
            "shared.test" => Some(web::Site::new(plain.clone()).at(SHARED).at(SHARED6)),
            "plain.test" => Some(web::Site::new(plain.clone())),
            _ => None,
        }
    })
}
