//! A small office subnet for a port scanner: four simulated machines and
//! one real container, on a [`Net`].
//!
//! ```text
//! cargo run --example scan -- /run/fictionet/world.sock
//! ```
//!
//! The world waits for two sandboxes:
//!
//! - `container`, a real container at 10.0.0.50 with whatever services it
//!   runs (nginx and OpenSSH in `examples/scan/compose.yaml`), wired with
//!   [`Net::route`] as a trusted host of the office subnet.
//! - `scanner`, the agent, at 10.0.9.2 in the sandboxes' subnet of the
//!   `Net`, so that a scan of 10.0.0.0/24 does not find the scanner itself.
//!
//! The simulated machines are [`Host`]s. Each open port runs a small
//! [`Service`]: one sends a banner when a client connects, the other answers
//! each HTTP request with a page, so `nmap -sV` can name them. A port with no
//! service answers a SYN with a RST, so a scanner reports it closed rather
//! than filtered; an address with no host answers "host unreachable".
//!
//! The dashboard shows the network as one group, "simulated hosts", with one group
//! per machine inside it, and the two sandboxes in groups of their own.
//! `examples/scan/README.md` runs it all under Docker Compose with nmap.

use std::convert::Infallible;
use std::net::Ipv4Addr;
use std::sync::Arc;

use fictionet::stdlib::codec::{Collect, Wire};
use fictionet::stdlib::net::{Host, Net};
use fictionet::stdlib::route::Prefix;
use fictionet::stdlib::serve::{Driver, Flow, Service};
use fictionet::stdlib::{ftp, httpd, imap, pop3, smtp, ssh};
use fictionet::time::{Duration, ms};
use fictionet::{Attachments, Cx, Result};

/// What answers on an open port.
#[derive(Clone, Copy)]
enum Kind {
    /// Sends this line when a client connects, then waits for it to leave.
    Ssh,
    Smtp,
    Pop3,
    Imap,
    Ftp,
    /// Answers each HTTP request with a page and a server name.
    Http {
        server: &'static str,
        title: &'static str,
    },
}

/// A simulated machine: its name, last address byte, and open ports.
struct Machine {
    name: &'static str,
    host: u8,
    ports: &'static [(u16, Kind)],
}

const OPENSSH: Kind = Kind::Ssh;

const MACHINES: &[Machine] = &[
    Machine {
        name: "www",
        host: 10,
        ports: &[
            (22, OPENSSH),
            (
                80,
                Kind::Http {
                    server: "Apache/2.4.62 (Debian)",
                    title: "Intranet",
                },
            ),
        ],
    },
    Machine {
        name: "mail",
        host: 11,
        ports: &[(25, Kind::Smtp), (110, Kind::Pop3), (143, Kind::Imap)],
    },
    Machine {
        name: "files",
        host: 12,
        ports: &[(21, Kind::Ftp), (22, OPENSSH)],
    },
    Machine {
        name: "printer",
        host: 13,
        ports: &[
            (
                80,
                Kind::Http {
                    server: "lighttpd/1.4.69 (Linux)",
                    title: "LaserJet M507",
                },
            ),
            (
                631,
                Kind::Http {
                    server: "CUPS/2.4 IPP/2.1",
                    title: "Home - CUPS 2.4.2",
                },
            ),
        ],
    },
];

/// The office subnet, with the simulated machines and the container.
const SUBNET: [u8; 3] = [10, 0, 0];
/// The real container's address.
const CONTAINER: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 50);
/// The scanner's subnet: the sandboxes' subnet of the `Net`.
const SCANNER_NET: &str = "10.0.9.0/24";

fn main() -> Result {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/run/fictionet/world.sock".into());
    let (attacher, attachments) = fictionet::attachments();
    let _listening = fictionet::listen(
        fictionet::WorldSocket::UnixSocket(path.clone().into()),
        attacher,
    )?;
    println!("listening on {path}");
    fictionet::block_on(fictionet::run(fictionet::Seed::random(), move |fcx| {
        world(fcx, attachments)
    }))
}

async fn world(fcx: Cx, attachments: Attachments) -> Result {
    let mut net = Net::new()
        .group("simulated hosts")
        .subnet(SCANNER_NET.parse()?)
        .ipv4_only();
    for m in MACHINES {
        let mut host = Host::new(m.name).at(Ipv4Addr::new(SUBNET[0], SUBNET[1], SUBNET[2], m.host));
        for &(port, kind) in m.ports {
            host = match kind {
                Kind::Http { server, title } => host.tcp(port, Arc::new(()), move || {
                    httpd::Http1::new(Page { server, title })
                }),
                Kind::Ssh => host.tcp(port, Arc::new(()), || Ssh),
                _ => host.tcp(port, Arc::new(()), move || Banner(kind)),
            };
        }
        net = net.add_host(host);
    }
    // Each sandbox goes through a short delay started in its own group, so
    // the group holds the task that reads the sandbox, and the sandbox with
    // it.
    let delayed = attachments.map(&fcx, |fcx, sandbox| {
        let (group, by): (&str, Duration) = match sandbox.name() {
            "container" => ("real container", ms(1)),
            _ => ("scanner", ms(2)),
        };
        println!("attached {}", sandbox.name());
        fictionet::stdlib::delay(&fcx.group(group), by, sandbox)
    });
    net.route(
        "container",
        Prefix {
            addr: CONTAINER.into(),
            len: 32,
        },
    )
    .start(&fcx, delayed)?;
    Ok(())
}

struct Page {
    server: &'static str,
    title: &'static str,
}

impl httpd::Handler for Page {
    fn call(&self, _: http::Request<httpd::Body>, _: &mut httpd::Exchange<'_>) -> httpd::Reply {
        let title = self.title;
        let body = format!(
            "<!doctype html><html><head><title>{title}</title></head><body><h1>{title}</h1></body></html>\n"
        );
        httpd::Reply::Now(
            http::Response::builder()
                .header("server", self.server)
                .header("content-type", "text/html; charset=utf-8")
                .header("connection", "close")
                .body(httpd::Body::from(body))
                .expect("valid page headers"),
        )
    }
}

struct Banner(Kind);

impl Service for Banner {
    type Decoder = Collect<Vec<u8>, true>;
    type State = ();
    type Error = Infallible;

    fn decoder(&self) -> Self::Decoder {
        Collect::bytes(16 << 10)
    }

    fn on_open(
        &mut self,
        _: &(),
        driver: &mut Driver<'_, Self::Decoder>,
    ) -> std::result::Result<Flow, Infallible> {
        let out = driver.reply();
        match self.0 {
            Kind::Smtp => smtp::Reply::new(220, "mail.corp.test ESMTP Postfix (Debian/GNU)").write(out).expect("valid SMTP greeting"),
            Kind::Pop3 => pop3::Reply::ok("Dovecot ready.").write(out).expect("valid POP3 greeting"),
            Kind::Imap => imap::Response::Status {
                tag: None, status: imap::Status::Ok,
                code: Some("CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+ STARTTLS AUTH=PLAIN".into()),
                text: "Dovecot ready.".into(),
            }.write(out).expect("valid IMAP greeting"),
            Kind::Ftp => ftp::Reply::new(ftp::ReplyCode::new(220).unwrap(), "(vsFTPd 3.0.3)").write(out).expect("valid FTP greeting"),
            _ => unreachable!("a mail or FTP banner"),
        }
        Ok(Flow::Continue)
    }

    fn on_item(
        &mut self,
        _: Vec<u8>,
        _: &(),
        _: &mut Driver<'_, Self::Decoder>,
    ) -> std::result::Result<Flow, Infallible> {
        Ok(Flow::Close)
    }
}

struct Ssh;

impl Service for Ssh {
    type Decoder = ssh::Events;
    type State = ();
    type Error = ssh::Error;

    fn decoder(&self) -> Self::Decoder {
        ssh::Events::new()
    }

    fn on_open(
        &mut self,
        _: &(),
        driver: &mut Driver<'_, Self::Decoder>,
    ) -> std::result::Result<Flow, ssh::Error> {
        ssh::Identification::new("2.0", "OpenSSH_9.2p1", Some("Debian-2+deb12u3"))?
            .write(driver.reply())?;
        Ok(Flow::Continue)
    }

    fn on_item(
        &mut self,
        item: ssh::Event,
        _: &(),
        driver: &mut Driver<'_, Self::Decoder>,
    ) -> std::result::Result<Flow, ssh::Error> {
        match item {
            ssh::Event::Version(_) => {
                let mut cookie = [0; 16];
                cookie[..8].copy_from_slice(&driver.random_u64().to_be_bytes());
                cookie[8..].copy_from_slice(&driver.random_u64().to_be_bytes());
                let kex = ssh::Message::KexInit(ssh::KexInit {
                    cookie,
                    kex_algorithms: vec!["curve25519-sha256".into()],
                    server_host_key_algorithms: vec!["ssh-ed25519".into()],
                    encryption_client_to_server: vec!["aes128-ctr".into()],
                    encryption_server_to_client: vec!["aes128-ctr".into()],
                    mac_client_to_server: vec!["hmac-sha2-256".into()],
                    mac_server_to_client: vec!["hmac-sha2-256".into()],
                    compression_client_to_server: vec!["none".into()],
                    compression_server_to_client: vec!["none".into()],
                    languages_client_to_server: vec![],
                    languages_server_to_client: vec![],
                    first_kex_packet_follows: false,
                    reserved: 0,
                });
                ssh::Packet::from_message(&kex)?.write(driver.reply())?;
            }
            ssh::Event::Packet { .. } => {
                ssh::Packet::from_message(&ssh::Message::Disconnect {
                    reason: ssh::DisconnectReason::KeyExchangeFailed,
                    description: "Key exchange is unavailable".into(),
                    language: String::new(),
                })?
                .write(driver.reply())?;
                return Ok(Flow::Close);
            }
            _ => {}
        }
        Ok(Flow::Continue)
    }
}

#[cfg(test)]
mod tests {
    //! What a scanner sees of the world, compared with a report recorded
    //! before the world moved onto the service layer
    //! (`examples/scan/golden.txt`): which hosts answer pings, which ports
    //! are open or closed, and what each open port says. A host that does
    //! not answer is "down" whether its pings vanish or come back
    //! unreachable, as nmap reports both.
    //!
    //! `SCAN_GOLDEN_WRITE=1 cargo test --example scan` records it again.

    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::mpsc;

    use fictionet::prelude::*;
    use fictionet::stdlib::{ConnError, ip, tcp};
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

    async fn within<T>(
        fcx: &Cx,
        d: Duration,
        fut: impl std::future::Future<Output = T>,
    ) -> Option<T> {
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
                if let Some(r) = fictionet::stdlib::icmp::echo_reply(&p, addr) {
                    icmp.send(r);
                }
            }
            Ok(())
        });
        for (port, reply) in [(22u16, &b"SSH-2.0-OpenSSH_9.9\r\n"[..]), (80, &b"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"[..])] {
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
                        while let Some(Ok(n)) = within(fcx, ms(500), conn.read(fcx, &mut buf)).await
                        {
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
    fn ssh_identification_is_followed_by_kexinit_and_disconnect() {
        use fictionet::stdlib::{codec::Wire, serve::Harness, ssh};
        let mut h = Harness::new(fictionet::Seed::from_u64(42), super::Ssh, ());
        assert_eq!(
            h.open().unwrap(),
            b"SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3\r\n"
        );
        let reply = h.push(b"SSH-2.0-test_client\r\n").unwrap();
        let packet = ssh::Packet::parse(&reply).unwrap();
        let ssh::Message::KexInit(kex) = ssh::Message::parse(&packet.payload).unwrap() else {
            panic!("expected KEXINIT");
        };
        assert_eq!(kex.kex_algorithms, ["curve25519-sha256"]);
        assert_ne!(kex.cookie, [0; 16]);
        let client = ssh::Packet::from_message(&ssh::Message::KexInit(kex))
            .unwrap()
            .to_bytes()
            .unwrap();
        let reply = h.push(&client).unwrap();
        let packet = ssh::Packet::parse(&reply).unwrap();
        assert!(matches!(
            ssh::Message::parse(&packet.payload).unwrap(),
            ssh::Message::Disconnect {
                reason: ssh::DisconnectReason::KeyExchangeFailed,
                ..
            }
        ));
        assert!(h.push(&client).is_err());
    }

    #[test]
    fn the_scan_report_is_the_recorded_one() {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let result = fictionet::block_on(fictionet::run(
                fictionet::Seed::random(),
                move |fcx| async move {
                    let (attacher, attachments) = fictionet::attachments();
                    fcx.spawn(move |fcx| super::world(fcx, attachments));
                    container(&fcx, attacher.attach("container").unwrap());
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
        let file = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/scan/golden.txt");
        let got = got.join("\n") + "\n";
        if std::env::var_os("SCAN_GOLDEN_WRITE").is_some() {
            std::fs::write(file, &got).unwrap();
            return;
        }
        assert_eq!(got, std::fs::read_to_string(file).unwrap());
    }
}
