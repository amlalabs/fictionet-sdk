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

use fictionet::stdlib::codec::{Decode, Step};
use fictionet::stdlib::net::{Host, Net};
use fictionet::stdlib::route::Prefix;
use fictionet::stdlib::serve::{Driver, Flow, Service};
use fictionet::time::{Duration, ms};
use fictionet::{Attachments, Cx, Result};

/// What answers on an open port.
#[derive(Clone, Copy)]
enum Kind {
    /// Sends this line when a client connects, then waits for it to leave.
    Banner(&'static str),
    /// Answers every HTTP request with a small page. `status` is the start
    /// of the response, such as `HTTP/1.1 200 OK`, and `server` the server
    /// it names.
    Http {
        status: &'static str,
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

const OPENSSH: Kind = Kind::Banner("SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3\r\n");

const MACHINES: &[Machine] = &[
    Machine {
        name: "www",
        host: 10,
        ports: &[
            (22, OPENSSH),
            (
                80,
                Kind::Http {
                    status: "HTTP/1.1 200 OK",
                    server: "Apache/2.4.62 (Debian)",
                    title: "Intranet",
                },
            ),
        ],
    },
    Machine {
        name: "mail",
        host: 11,
        ports: &[
            (
                25,
                Kind::Banner("220 mail.corp.test ESMTP Postfix (Debian/GNU)\r\n"),
            ),
            (110, Kind::Banner("+OK Dovecot ready.\r\n")),
            (
                143,
                Kind::Banner(
                    "* OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+ STARTTLS AUTH=PLAIN] Dovecot ready.\r\n",
                ),
            ),
        ],
    },
    Machine {
        name: "files",
        host: 12,
        ports: &[(21, Kind::Banner("220 (vsFTPd 3.0.3)\r\n")), (22, OPENSSH)],
    },
    Machine {
        name: "printer",
        host: 13,
        ports: &[
            (
                80,
                Kind::Http {
                    status: "HTTP/1.0 200 OK",
                    server: "lighttpd/1.4.69 (Linux)",
                    title: "LaserJet M507",
                },
            ),
            (
                631,
                Kind::Http {
                    status: "HTTP/1.0 200 OK",
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
    fictionet::block_on(fictionet::run(move |fcx| world(fcx, attachments)))
}

async fn world(fcx: Cx, attachments: Attachments) -> Result {
    let mut net = Net::new()
        .group("simulated hosts")
        .subnet(SCANNER_NET.parse()?)
        .ipv4_only();
    for m in MACHINES {
        let mut host = Host::new(m.name).at(Ipv4Addr::new(SUBNET[0], SUBNET[1], SUBNET[2], m.host));
        for &(port, kind) in m.ports {
            host = host.tcp(port, Arc::new(()), move || Port { kind, request: 0 });
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
    .serve(&fcx, delayed)?;
    Ok(())
}

/// One open port: a banner, or a page for each request.
struct Port {
    kind: Kind,
    /// Bytes of the request so far, for an HTTP port.
    request: usize,
}

/// The most of a request a page port reads before it answers anyway.
const REQUEST_LIMIT: usize = 16 << 10;

/// Reads a request up to the end of its head, or [`REQUEST_LIMIT`] bytes,
/// whichever comes first; and for a banner port, takes and ignores
/// everything.
struct Head {
    ignore: bool,
}

impl Decode for Head {
    type Item = ();
    type Error = Infallible;
    const NAME: &'static str = "scan request";

    fn capacity(&self) -> usize {
        REQUEST_LIMIT + 4
    }

    fn decode(&mut self, input: &[u8], _eof: bool) -> std::result::Result<Step<()>, Infallible> {
        if input.is_empty() {
            return Ok(Step::Need);
        }
        if self.ignore {
            return Ok(Step::Skip(input.len()));
        }
        if let Some(at) = input.windows(4).position(|w| w == b"\r\n\r\n") {
            return Ok(Step::Item((), at + 4));
        }
        if input.len() > REQUEST_LIMIT {
            return Ok(Step::Item((), input.len()));
        }
        Ok(Step::Need)
    }
}

impl Service for Port {
    type Decoder = Head;
    type State = ();
    type Error = Infallible;

    fn decoder(&self) -> Head {
        Head {
            ignore: matches!(self.kind, Kind::Banner(_)),
        }
    }

    fn on_open(
        &mut self,
        _: &(),
        driver: &mut Driver<'_>,
    ) -> std::result::Result<Flow, Infallible> {
        if let Kind::Banner(line) = self.kind {
            driver.reply().extend_from_slice(line.as_bytes());
        }
        Ok(Flow::Continue)
    }

    fn on_item(
        &mut self,
        _: (),
        _: &(),
        driver: &mut Driver<'_>,
    ) -> std::result::Result<Flow, Infallible> {
        let Kind::Http {
            status,
            server,
            title,
        } = self.kind
        else {
            return Ok(Flow::Continue);
        };
        self.request += 1;
        let body = format!(
            "<!doctype html><html><head><title>{title}</title></head><body><h1>{title}</h1></body></html>\n"
        );
        let head = format!(
            "{status}\r\nServer: {server}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        driver.reply().extend_from_slice(head.as_bytes());
        driver.reply().extend_from_slice(body.as_bytes());
        Ok(Flow::Close)
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
    fn the_scan_report_is_the_recorded_one() {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let result = fictionet::block_on(fictionet::run(move |fcx| async move {
                let (attacher, attachments) = fictionet::attachments();
                fcx.spawn(move |fcx| super::world(fcx, attachments));
                container(&fcx, attacher.attach("container").unwrap());
                let lines = report(&fcx, &attacher).await;
                let _ = tx.send(lines);
                fcx.cancel();
                Ok(())
            }));
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
