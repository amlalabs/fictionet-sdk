//! End to end, in one process: two machines joined by a router, each built
//! from stdlib parts. The server is `split_protocols` + `tcp::endpoint` +
//! `tls::server`. The client is `split_protocols` + `tcp::endpoint` + a
//! rustls client. Every byte crosses as IP packets through both splits, the
//! router and a delayed link.

#[path = "common/certs.rs"]
mod certs;
mod common;
#[path = "common/done.rs"]
mod done;
#[path = "common/world.rs"]
mod world;

use certs::certs;
use world::real_world as world;

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime};

use fictionet::prelude::*;
use fictionet::stdlib::tls::{self, ServerConfig};
use fictionet::stdlib::{delay, ip, route, tcp};
use fictionet::{Cx, Interface, Packet, RecvError, pair};
use rustls::ClientConfig;

// ---------------------------------------------------------------------------
// Shared rustls client and payload pattern.

#[path = "common/rustls_client.rs"]
mod rustls_client;
type Client<C> = rustls_client::Client<C, false>;

#[path = "common/pattern.rs"]
mod payload;
use payload::pattern;

// ---------------------------------------------------------------------------
// The test.

const NAME: &str = "wiki.test";
const UP: usize = 1024 * 1024;
const DOWN: usize = 2 * 1024 * 1024;

/// One machine: its cable split by protocol, and a TCP endpoint on the TCP
/// end. Pings and UDP are left unanswered.
fn machine(fcx: &Cx, cable: impl Interface, addr: IpAddr) -> tcp::Endpoint {
    let (tcp, _udp, _icmp, _other) = ip::split_protocols(fcx, cable);
    tcp::endpoint(fcx, tcp, addr)
}

fn https_through_a_router(
    server_addr: &str,
    client_addr: &str,
    server_prefix: &str,
    client_prefix: &str,
) {
    let server_ip: IpAddr = server_addr.parse().unwrap();
    let client_ip: IpAddr = client_addr.parse().unwrap();
    let server_prefix: route::Prefix = server_prefix.parse().unwrap();
    let client_prefix: route::Prefix = client_prefix.parse().unwrap();
    world(Duration::from_secs(60), move |fcx| async move {
        let certs = certs(&fcx, &[NAME]);

        // Two cables into the router. The client's link has 5 ms of delay
        // each way.
        let (router_to_server, server_cable) = pair();
        let (router_to_client, client_cable) = pair();
        let client_cable = delay(&fcx, Duration::from_millis(5), client_cable);
        let _router = route::router(
            &fcx,
            vec![
                (
                    server_prefix,
                    Box::new(router_to_server) as Box<dyn Interface>,
                ),
                (client_prefix, Box::new(router_to_client)),
            ],
        );
        let server = machine(&fcx, server_cable, server_ip);
        let client = machine(&fcx, client_cable, client_ip);

        let mut config = tls::config_builder(&fcx, SystemTime::now())
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(certs.chain, certs.key)?;
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let config: Arc<ServerConfig> = Arc::new(config);

        let mut listener = server.listen(443)?;
        let served = fcx.spawn(move |fcx| async move {
            let conn = listener.accept(&fcx).await?;
            assert_eq!(conn.peer_addr().ip(), client_ip);
            let hello = tls::server(&fcx, conn).await?;
            assert_eq!(hello.server_name(), Some(NAME));
            let mut conn = hello.finish(&fcx, config).await?;
            assert_eq!(conn.alpn(), Some(&b"http/1.1"[..]));
            assert_eq!(conn.inner().local_addr(), SocketAddr::new(server_ip, 443));
            // Read the whole upload, up to the client's close_notify.
            let mut got = Vec::new();
            let mut buf = vec![0; 64 * 1024];
            loop {
                let n = conn.read(&fcx, &mut buf).await?;
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&buf[..n]);
            }
            assert!(
                got == pattern(UP, 1),
                "the upload arrived changed ({} bytes)",
                got.len()
            );
            conn.write_all(&fcx, &pattern(DOWN, 2)).await?;
            conn.shutdown(&fcx).await?;
            Ok(())
        });

        let mut client_config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()?
                .with_root_certificates(certs.roots)
                .with_no_client_auth();
        client_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let conn = client
            .connect(&fcx, SocketAddr::new(server_ip, 443))
            .await?;
        assert_eq!(conn.local_addr().ip(), client_ip);
        let mut tls = Client::connect(&fcx, conn, Arc::new(client_config), NAME).await?;
        assert_eq!(tls.tls.alpn_protocol(), Some(&b"http/1.1"[..]));
        tls.write_all(&fcx, &pattern(UP, 1)).await?;
        tls.close(&fcx).await?;
        let mut got = Vec::new();
        let mut buf = vec![0; 64 * 1024];
        loop {
            let n = tls.read(&fcx, &mut buf).await?;
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        assert!(
            got == pattern(DOWN, 2),
            "the download arrived changed ({} bytes)",
            got.len()
        );
        served.join(&fcx).await?;
        Ok(())
    });
}

#[test]
fn https_through_a_router_v4() {
    https_through_a_router("10.0.0.1", "10.0.0.2", "10.0.0.1/32", "10.0.0.0/24");
}

#[test]
fn https_through_a_router_v6() {
    https_through_a_router("fd00::1", "fd00::2", "fd00::1/128", "fd00::/64");
}

// ---------------------------------------------------------------------------
// ACK pacing.

/// Counts the TCP segments that cross a cable, by direction, and whether
/// they carry data.
struct Count<I> {
    inner: I,
    counts: Arc<Mutex<[usize; 4]>>,
}

fn carries_data(p: &[u8]) -> bool {
    let ihl = ((p[0] & 0x0f) as usize) * 4;
    let total = u16::from_be_bytes([p[2], p[3]]) as usize;
    total > ihl + ((p[ihl + 12] >> 4) as usize) * 4
}

impl<I: Interface> Interface for Count<I> {
    fn poll_recv(&mut self, fcx: &Cx, cx: &mut Context<'_>) -> Poll<Result<Packet, RecvError>> {
        let r = self.inner.poll_recv(fcx, cx);
        if let Poll::Ready(Ok(p)) = &r {
            self.counts.lock().unwrap()[carries_data(&p.0) as usize] += 1;
        }
        r
    }

    fn send(&mut self, p: Packet) {
        self.counts.lock().unwrap()[2 + carries_data(&p.0) as usize] += 1;
        self.inner.send(p)
    }
}

/// A receiver that gets a window of data in one go still ACKs about every
/// second segment, as a kernel does. One ACK per window would make the
/// sender's slow start grow by one segment per round trip, which made a
/// 2 MiB transfer over a 2 ms round trip take 50 round trips.
#[test]
fn a_receiver_acks_every_second_segment() {
    let counts = Arc::new(Mutex::new([0usize; 4]));
    let seen = counts.clone();
    world(Duration::from_secs(60), move |fcx| async move {
        let (a, b) = pair();
        let b = delay(&fcx, Duration::from_millis(5), b);
        let b = Count {
            inner: b,
            counts: seen,
        };
        let sender = tcp::endpoint(&fcx, a, "10.0.0.1".parse().unwrap());
        let receiver = tcp::endpoint(&fcx, b, "10.0.0.2".parse().unwrap());
        let mut listener = sender.listen(80)?;
        let sent = fcx.spawn(move |fcx| async move {
            let mut conn = listener.accept(&fcx).await?;
            conn.write_all(&fcx, &pattern(DOWN, 3)).await?;
            conn.shutdown(&fcx).await?;
            let mut buf = [0; 1];
            let _ = conn.read(&fcx, &mut buf).await;
            Ok(())
        });
        let mut conn = receiver
            .connect(&fcx, "10.0.0.1:80".parse().unwrap())
            .await?;
        let mut got = 0;
        let mut buf = vec![0; 64 * 1024];
        loop {
            let n = conn.read(&fcx, &mut buf).await?;
            if n == 0 {
                break;
            }
            got += n;
        }
        assert_eq!(got, DOWN);
        drop(conn);
        sent.join(&fcx).await?;
        Ok(())
    });
    // [received without data, received with data, sent without, sent with]
    let [_, data_in, acks_out, _] = *counts.lock().unwrap();
    assert!(data_in > 1000, "{data_in} data segments");
    assert!(
        acks_out * 3 >= data_in,
        "{acks_out} ACKs for {data_in} data segments"
    );
}
