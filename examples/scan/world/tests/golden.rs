//! What a scanner sees of the world, compared with a report recorded
//! before the world moved onto the service layer
//! (`examples/scan/world/tests/golden.txt`): which hosts answer pings, which ports
//! are open or closed, and what each open port says. A host that does
//! not answer is "down" whether its pings vanish or come back
//! unreachable, as nmap reports both.
//!
//! `SCAN_GOLDEN_WRITE=1 cargo test -p scan-world` records it again.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::mpsc;

use fictionet::prelude::*;
use fictionet::stdlib::network::{ConnError, ip, tcp};
use fictionet::time::{Duration, ms};
use fictionet::{Cx, End, Interface, Packet};

const SCANNER: Ipv4Addr = Ipv4Addr::new(10, 0, 9, 2);

fn ping(dst: Ipv4Addr, seq: u16) -> Packet {
    let mut icmp = vec![8, 0, 0, 0, 0x51, 0x52];
    icmp.extend_from_slice(&seq.to_be_bytes());
    let c = ip::checksum(&icmp);
    icmp[2..4].copy_from_slice(&c.to_be_bytes());
    let mut p = vec![0x45, 0, 0, 0, 0, 1, 0, 0, 64, 1, 0, 0];
    p[2..4].copy_from_slice(&((20 + icmp.len()) as u16).to_be_bytes());
    p.extend_from_slice(&SCANNER.octets());
    p.extend_from_slice(&dst.octets());
    ip::set_header_checksum(&mut p);
    p.extend_from_slice(&icmp);
    Packet(p)
}

async fn within<T>(fcx: &Cx, d: Duration, fut: impl std::future::Future<Output = T>) -> Option<T> {
    let mut fut = std::pin::pin!(fut);
    let mut sleep = std::pin::pin!(fcx.sleep(d));
    std::future::poll_fn(|cx| {
        if let std::task::Poll::Ready(v) = fut.as_mut().poll(cx) {
            return std::task::Poll::Ready(Some(v));
        }
        if sleep.as_mut().poll(cx).is_ready() {
            return std::task::Poll::Ready(None);
        }
        std::task::Poll::Pending
    })
    .await
}

/// The real container, played by the test: OpenSSH and nginx.
fn container(fcx: &Cx, end: End) {
    let addr: IpAddr = Ipv4Addr::new(10, 0, 0, 50).into();
    let (t, _u, mut icmp, _o) = ip::split_protocols(fcx, end);
    let tcp = tcp::endpoint(fcx, t, addr);
    fcx.spawn(move |fcx| async move {
        while let Ok(p) = icmp.recv(&fcx).await {
            if let Some(r) = fictionet::stdlib::network::icmp::echo_reply(&p, addr) {
                icmp.send(r);
            }
        }
        Ok(())
    });
    for (port, reply) in [
        (22u16, &b"SSH-2.0-OpenSSH_9.9\r\n"[..]),
        (
            80,
            &b"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                [..],
        ),
    ] {
        let mut listener = tcp.listen(port).unwrap();
        fcx.spawn(move |fcx| async move {
            while let Ok(mut conn) = listener.accept(&fcx).await {
                if port == 80 {
                    let mut buf = [0u8; 512];
                    let _ = conn.read(&fcx, &mut buf).await;
                }
                let _ = conn.write_all(&fcx, reply).await;
                let _ = conn.shutdown(&fcx).await;
            }
            Ok(())
        });
    }
    std::mem::forget(tcp);
}

async fn report(fcx: &Cx, attacher: &fictionet::Attacher) -> Vec<String> {
    let end = attacher.attach("scanner").unwrap();
    let (t, _u, mut icmp, _o) = ip::split_protocols(fcx, end);
    let tcp = tcp::endpoint(fcx, t, SCANNER.into());
    let hosts: Vec<Ipv4Addr> = [10u8, 11, 12, 13, 14, 20, 50, 99]
        .iter()
        .map(|h| Ipv4Addr::new(10, 0, 0, *h))
        .collect();
    let mut lines = Vec::new();
    // Pings, all at once.
    for (i, h) in hosts.iter().enumerate() {
        icmp.send(ping(*h, i as u16));
    }
    let mut up = std::collections::BTreeSet::new();
    while let Some(Ok(p)) = within(fcx, ms(1000), icmp.recv(fcx)).await {
        let b = &p.0;
        if b.len() >= 28 && b[20] == 0 {
            up.insert(Ipv4Addr::new(b[12], b[13], b[14], b[15]));
        }
    }
    for h in &hosts {
        lines.push(format!(
            "ping {h} {}",
            if up.contains(h) { "up" } else { "down" }
        ));
    }
    for h in &hosts {
        for port in [21u16, 22, 25, 80, 110, 143, 443, 631, 3306] {
            let to = SocketAddr::new((*h).into(), port);
            let state = match within(fcx, ms(800), tcp.connect(fcx, to)).await {
                Some(Ok(mut conn)) => {
                    if matches!(port, 80 | 631) {
                        conn.write_all(fcx, b"GET / HTTP/1.0\r\n\r\n")
                            .await
                            .unwrap();
                    }
                    let mut got = Vec::new();
                    let mut buf = [0u8; 4096];
                    while let Some(Ok(n)) = within(fcx, ms(500), conn.read(fcx, &mut buf)).await {
                        if n == 0 {
                            break;
                        }
                        got.extend_from_slice(&buf[..n]);
                    }
                    format!("open {:?}", String::from_utf8_lossy(&got))
                }
                Some(Err(ConnError::Refused)) => "closed".to_owned(),
                _ => "no answer".to_owned(),
            };
            lines.push(format!("tcp {to} {state}"));
        }
    }
    lines
}

#[test]
fn the_scan_report_is_the_recorded_one() {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let result = fictionet::block_on(fictionet::run(
            fictionet::RunOptions::new(fictionet::Seed::random()),
            move |fcx| async move {
                let (attacher, attachments) = fictionet::attachments();
                fcx.spawn(move |fcx| scan_world::world(fcx, attachments));
                container(&fcx, attacher.attach(scan_world::SERVER).unwrap());
                let lines = report(&fcx, &attacher).await;
                let _ = tx.send(lines);
                fcx.cancel();
                Ok(())
            },
        ));
        let _ = result;
    });
    let got = rx
        .recv_timeout(std::time::Duration::from_secs(120))
        .expect("the scan finished");
    let file = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/golden.txt");
    let got = got.join("\n") + "\n";
    if std::env::var_os("SCAN_GOLDEN_WRITE").is_some() {
        std::fs::write(file, &got).unwrap();
        return;
    }
    assert_eq!(got, std::fs::read_to_string(file).unwrap());
}
