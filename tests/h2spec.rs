//! The h2spec conformance suite against the stdlib's native HTTP/2 server.
//!
//! ```text
//! cargo test --features web-proxy,tokio --test h2spec
//! ```
//!
//! The world is one host running the native server, reached from two ports
//! on 127.0.0.1. One is an `httpd::Server` behind TLS, which picks HTTP/2 by
//! ALPN. The other speaks HTTP/2 alone over plain TCP (h2c with prior
//! knowledge). Each connection to either port becomes a TCP connection from
//! a sandbox in the world to the site, so every byte crosses the world's
//! network. h2spec runs in strict mode over both, and the test fails on any
//! failed or skipped case.
//!
//! The test downloads h2spec v2.6.0 (Linux on x86_64 only) into Cargo's
//! test temporary directory once and checks its sha256.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use fictionet::InterfaceExt;
use fictionet::stdlib::network::tcp;
use fictionet::stdlib::protocols::x509::{Time, Validity};
use fictionet::stdlib::world::net::{Net, Sni};
use fictionet::stdlib::{services::ca::Ca, web::httpd};
use fictionet::tokio::ConnectionTokioExt;
use fictionet_test_support::sandbox;

const VERSION: &str = "v2.6.0";
const ARCHIVE: &str = "h2spec_linux_amd64.tar.gz";
const SHA256: &str = "157ee0de702e01ad40e752dbf074b366027e550c8e7504f9450da2809e279318";

const SITE: Ipv4Addr = Ipv4Addr::new(104, 18, 0, 1);
const BODY: &[u8] = b"hello from the native HTTP/2 server\n";

#[test]
fn h2spec_strict() {
    let h2spec = fetch();
    let tls = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let h2c = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let tls_port = tls.local_addr().unwrap().port();
    let h2c_port = h2c.local_addr().unwrap().port();
    let (stop, stopped) = fictionet::pair();
    let world = std::thread::spawn(move || serve(tls, h2c, stopped));

    let mut failures = Vec::new();
    for (name, port, flags) in [
        ("TLS", tls_port, &["--tls", "--insecure"][..]),
        ("h2c", h2c_port, &[]),
    ] {
        let output = Command::new(&h2spec)
            .args(flags)
            .args(["--strict", "--host", "127.0.0.1", "--port"])
            .arg(port.to_string())
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&output.stdout);
        println!("h2spec {VERSION} over {name}\n{text}");
        // A skipped case means the world's answer was too short to test with.
        match summary(&text) {
            Some((_, _, 0, 0)) if output.status.success() => {}
            Some((tests, passed, skipped, failed)) => failures.push(format!(
                "{name}: {tests} tests, {passed} passed, {skipped} skipped, {failed} failed"
            )),
            None => failures.push(format!(
                "{name}: h2spec printed no summary and exited with {}",
                output.status
            )),
        }
    }

    drop(stop);
    world.join().unwrap().unwrap();
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// The last "N tests, N passed, N skipped, N failed" line h2spec printed.
fn summary(text: &str) -> Option<(u64, u64, u64, u64)> {
    text.lines().rev().find_map(|line| {
        let mut numbers = line
            .split(", ")
            .map(|part| part.trim().split_once(' '))
            .map(|part| part.and_then(|(n, _)| n.parse().ok()));
        let parsed = (
            numbers.next()??,
            numbers.next()??,
            numbers.next()??,
            numbers.next()??,
        );
        (line.contains(" tests, ") && line.trim_end().ends_with(" failed")).then_some(parsed)
    })
}

/// Downloads h2spec once and returns the binary's path.
fn fetch() -> PathBuf {
    assert!(
        cfg!(target_os = "linux") && cfg!(target_arch = "x86_64"),
        "h2spec {VERSION} is published for Linux on x86_64 only"
    );
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("h2spec-{VERSION}"));
    let binary = dir.join("h2spec");
    if binary.is_file() {
        return binary;
    }
    std::fs::create_dir_all(&dir).unwrap();
    let archive = dir.join(ARCHIVE);
    let url = format!("https://github.com/summerwind/h2spec/releases/download/{VERSION}/{ARCHIVE}");
    run(Command::new("curl")
        .args(["-fsSL", "-o"])
        .arg(&archive)
        .arg(url));
    let sum = run(Command::new("sha256sum").arg(&archive));
    assert_eq!(sum.split_whitespace().next(), Some(SHA256), "h2spec sha256");
    run(Command::new("tar")
        .args(["-xzf"])
        .arg(&archive)
        .arg("-C")
        .arg(&dir)
        .arg("h2spec"));
    binary
}

fn run(command: &mut Command) -> String {
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{command:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

/// Runs the world until `stopped` closes.
fn serve(
    tls: std::net::TcpListener,
    h2c: std::net::TcpListener,
    mut stopped: fictionet::End,
) -> fictionet::Result {
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
            let handler: Arc<dyn httpd::Handler> = Arc::new({
                let route_0 = answer;
                let route_1 = answer;
                fictionet_test_support::handler(move |ex, request| {
                    if request.uri().path() == "/"
                        && (request.method() == http::Method::GET
                            || request.method() == http::Method::HEAD)
                    {
                        return route_0(ex, request);
                    }
                    if request.uri().path() == "/" && (request.method() == http::Method::POST) {
                        return route_1(ex, request);
                    }
                    if (request.uri().path() == "/") || (request.uri().path() == "/") {
                        return http::Response::builder()
                            .status(405)
                            .body(bytes::Bytes::new())
                            .unwrap();
                    }
                    http::Response::builder()
                        .status(404)
                        .body(bytes::Bytes::new())
                        .unwrap()
                })
            });
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
