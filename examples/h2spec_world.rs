//! The world `cargo xtask h2spec` runs the h2spec conformance suite
//! against: the stdlib's native HTTP/2 server on one host, reached from two
//! ports on 127.0.0.1. One is an `httpd::Server` behind TLS, which picks
//! HTTP/2 by ALPN. The other speaks HTTP/2 alone over plain TCP (h2c with
//! prior knowledge). A port that also speaks HTTP/1.1 takes bytes without
//! HTTP/2's preface for an HTTP/1.1 request, and h2spec checks that an
//! HTTP/2 server refuses them.
//!
//! ```text
//! cargo run --example h2spec_world
//! ```
//!
//! It prints `tls <port>` and `h2c <port>`, then serves until its standard
//! input closes. Each connection to either port becomes a TCP connection
//! from a sandbox in the world to the site, so every byte crosses the
//! world's network. GET and POST on `/` answer with a short body.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use fictionet::InterfaceExt;
use fictionet::stdlib::net::{Net, Sni};
use fictionet::stdlib::tcp;
use fictionet::stdlib::x509::{Time, Validity};
use fictionet::stdlib::{ca::Ca, httpd, sandbox};
use fictionet::tokio::ConnectionTokioExt;

const SITE: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 1);
const BODY: &[u8] = b"hello from the native HTTP/2 server\n";

fn main() -> fictionet::Result {
    let tls = std::net::TcpListener::bind("127.0.0.1:0")?;
    let h2c = std::net::TcpListener::bind("127.0.0.1:0")?;
    println!("tls {}", tls.local_addr()?.port());
    println!("h2c {}", h2c.local_addr()?.port());
    let (stop, mut stopped) = fictionet::pair();
    std::thread::spawn(move || {
        // Whoever started the world stops it by closing our standard input.
        let _ = std::io::copy(&mut std::io::stdin(), &mut std::io::sink());
        drop(stop);
    });
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(fictionet::run(
        fictionet::Seed::random(),
        move |fcx| async move {
            let ca = Ca::new(&fcx, "h2spec CA")?;
            let leaf = ca.issue(
                &fcx,
                &["localhost"],
                Validity {
                    not_before: Time::from_unix(946_684_800)?,
                    not_after: Time::from_unix(4_102_444_800)?,
                },
            )?;
            let start = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
            let config = leaf.server_config(&fcx, start)?;
            let answer =
                |_: &mut httpd::Exchange<'_>, _| http::Response::new(Bytes::from_static(BODY));
            let handler: Arc<dyn httpd::Handler> =
                Arc::new(httpd::Router::new().get("/", answer).post("/", answer));
            let server = httpd::Server::shared(handler.clone()).default_host();
            let (attacher, attachments) = fictionet::attachments();
            Net::new()
                .ipv4_only()
                .host("site", |host| {
                    host.at(SITE)
                        .tls_accept(443, Sni::Any, move |_| config.clone(), server)
                        .tcp(80, Arc::new(()), move || {
                            httpd::Http2::with(handler.clone(), httpd::Limits::default())
                        })
                })
                .start(&fcx, attachments)?;
            let machine =
                sandbox::machine(&fcx, attacher.attach("h2spec")?, Ipv4Addr::new(10, 0, 0, 2));
            for (listener, port) in [(tls, 443), (h2c, 80)] {
                bridge(&fcx, listener, machine.tcp.clone(), port)?;
            }
            let _ = stopped.recv(&fcx).await;
            fcx.cancel();
            Ok(())
        },
    ))
}

/// Copies each connection to `listener` to and from a new connection
/// from the sandbox to the site's `port`.
fn bridge(
    fcx: &fictionet::Cx,
    listener: std::net::TcpListener,
    tcp: tcp::Endpoint,
    port: u16,
) -> fictionet::Result {
    listener.set_nonblocking(true)?;
    let listener = tokio::net::TcpListener::from_std(listener)?;
    fcx.spawn(move |fcx| async move {
        while let Ok(accepted) = fcx.race(None, listener.accept()).await {
            let (mut host, _) = accepted?;
            let tcp = tcp.clone();
            fcx.spawn(move |fcx| async move {
                match tcp.connect(&fcx, SocketAddr::new(SITE.into(), port)).await {
                    Ok(conn) => {
                        let mut world = conn.into_tokio(&fcx);
                        let _ = tokio::io::copy_bidirectional(&mut host, &mut world).await;
                    }
                    Err(error) => eprintln!("connecting to the site's port {port}: {error}"),
                }
                Ok(())
            });
        }
        Ok(())
    });
    Ok(())
}
