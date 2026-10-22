//! The web fixture for real proxy and upload requests.
use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post};
use fictionet_extras::web_world;
use fictionet::Result;
use fictionet::stdlib::web;
use rustls::pki_types::PrivateKeyDer;
pub fn world(
    fcx: &fictionet::Cx,
    chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    attachments: fictionet::Attachments,
) -> Result {
    let app = web_world::app()
        .route("/big", get(|| async { vec![b'x'; 16 << 20] }))
        .route("/4mb", get(|| async { vec![b'x'; 4 << 20] }))
        .route("/upload", post(upload).layer(DefaultBodyLimit::disable()));
    let plain = web_world::plain()
        .route("/mb", get(|| async { vec![b'x'; 1 << 20] }))
        .route("/big", get(|| async { vec![b'x'; 16 << 20] }))
        .route("/upload", post(upload).layer(DefaultBodyLimit::disable()));
    let sites = web_world::sites(fcx, chain, key, app, plain)?;
    let upstream = web::proxy(fcx, std::sync::Arc::new(fictionet_host::Client::new()))?;
    web::Sites::new(move |host: &str| {
        if host == "upstream" {
            println!("lookup {host}");
            Some(web::Site::new(upstream.clone()))
        } else {
            sites(host)
        }
    })
    .start(fcx, attachments)
}

/// Reads a request body to its end and answers with its length, for
/// measuring uploads.
async fn upload(body: axum::body::Body) -> String {
    use http_body_util::BodyExt;
    let mut body = body;
    let mut n = 0usize;
    while let Some(frame) = body.frame().await {
        match frame {
            Ok(f) => n += f.data_ref().map_or(0, |d| d.len()),
            Err(e) => return format!("error after {n} bytes: {e}\n"),
        }
    }
    format!("{n}\n")
}
