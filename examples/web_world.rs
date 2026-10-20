//! A small world of websites, written with `web::Sites`.
//!
//! ```text
//! cargo run --example web_world -- /run/fictionet/world.sock /run/fictionet/ca.pem /run/fictionet/observation.sock
//! ```
//!
//! It makes a certificate authority for the world when it starts and
//! writes its certificate to the second path, so the sandbox can trust it
//! (`curl --cacert`). An optional third path opens a Unix observation socket.
//! Then it serves:
//!
//! The network is dual-stack: every site has an IPv4 and an IPv6 address,
//! except the two that test one family.
//!
//! - `example.test` and `www.example.test`: an axum app over HTTPS. `/`
//!   answers with the request's [`web::Target`] and HTTP version, `/count`
//!   with how many times it was asked. `/challenge` returns a 32-byte nonce,
//!   hex-encoded with a trailing newline. It is drawn once at startup from
//!   the world's seeded random stream and stays fixed for that world.
//!   Port 80 redirects to https.
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
//! The sites emit `dns.query`, `tls.handshake` and `http.request` events.
//! The optional third path installs a collector and serves its handle.
//! Watch it from another terminal:
//!
//! ```sh
//! fictionet observe --observation unix:/run/fictionet/observation.sock watch
//! ```
//!
//! For the shell commands and capture limits, see [`fictionet_observe`].
//!
//! The sites themselves are in `example_common::web_world`, which the web
//! test's fixture in `tests/web_fixture` shares to add bulk transfers and a
//! proxy.

use axum::routing::get;
use example_common::web_world::{app, plain, run, sites};
use fictionet::Result;
use fictionet::stdlib::web;
use rustls::pki_types::PrivateKeyDer;

fn main() -> Result {
    run(&std::env::args().collect::<Vec<_>>(), start)
}

/// Builds the world's sites on `attachments`, with `chain` and `key` for
/// every HTTPS name.
fn start(
    fcx: &fictionet::Cx,
    chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    attachments: fictionet::Attachments,
) -> Result {
    let mut nonce = [0u8; 32];
    fcx.fill_random(&mut nonce);
    let challenge = nonce.iter().map(|b| format!("{b:02x}")).collect::<String>() + "\n";
    let app = app().route(
        "/challenge",
        get(move || {
            let challenge = challenge.clone();
            async move { challenge }
        }),
    );
    web::Sites::new(sites(fcx, chain, key, app, plain())?).start(fcx, attachments)
}
