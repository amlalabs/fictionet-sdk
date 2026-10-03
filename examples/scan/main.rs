//! A small office subnet for a port scanner: four simulated machines and
//! one real container, behind one router.
//!
//! ```text
//! cargo run --example scan -- /run/fictionet/world.sock
//! ```
//!
//! The world waits for two sandboxes:
//!
//! - `container`, a real container at 10.0.0.50 with whatever services it
//!   runs (nginx and OpenSSH in `examples/scan/compose.yaml`).
//! - `scanner`, the agent, at 10.0.9.2 in a subnet of its own, so that a
//!   scan of 10.0.0.0/24 does not find the scanner itself.
//!
//! The simulated machines are built from the stdlib. Each has a
//! [`tcp::endpoint`] with listeners on its open ports, a [`udp::endpoint`]
//! with none, and answers pings. A port with no listener answers a SYN with
//! a RST, so a scanner reports it closed rather than filtered. Each open
//! port sends a banner, or answers HTTP, so `nmap -sV` can name it.
//!
//! The parts are [groups](fictionet::Cx#groups), so the dashboard shows
//! "scanner", "real container" and "simulated hosts", with one group per
//! machine inside the last. `examples/scan/README.md` runs it all under
//! Docker Compose with nmap.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use fictionet::prelude::*;
use fictionet::stdlib::route::{self, Prefix};
use fictionet::stdlib::{ConnError, icmp, ip, tcp, udp};
use fictionet::time::{Duration, ms};
use fictionet::{Attachments, Cx, End, Interface, Result, pair};

/// What answers on an open port.
#[derive(Clone, Copy)]
enum Service {
    /// Sends this line when a client connects, then waits for it to leave.
    Banner(&'static str),
    /// Answers every HTTP request with a small page. `status` is the start
    /// of the response, such as `HTTP/1.1 200 OK`, and `server` the server
    /// it names.
    Http { status: &'static str, server: &'static str, title: &'static str },
}

/// A simulated machine: its name, last address byte, and open ports.
struct Machine {
    name: &'static str,
    host: u8,
    ports: &'static [(u16, Service)],
}

const OPENSSH: Service = Service::Banner("SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3\r\n");

const MACHINES: &[Machine] = &[
    Machine {
        name: "www",
        host: 10,
        ports: &[
            (22, OPENSSH),
            (80, Service::Http { status: "HTTP/1.1 200 OK", server: "Apache/2.4.62 (Debian)", title: "Intranet" }),
        ],
    },
    Machine {
        name: "mail",
        host: 11,
        ports: &[
            (25, Service::Banner("220 mail.corp.test ESMTP Postfix (Debian/GNU)\r\n")),
            (110, Service::Banner("+OK Dovecot ready.\r\n")),
            (143, Service::Banner("* OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+ STARTTLS AUTH=PLAIN] Dovecot ready.\r\n")),
        ],
    },
    Machine {
        name: "files",
        host: 12,
        ports: &[(21, Service::Banner("220 (vsFTPd 3.0.3)\r\n")), (22, OPENSSH)],
    },
    Machine {
        name: "printer",
        host: 13,
        ports: &[
            (80, Service::Http { status: "HTTP/1.0 200 OK", server: "lighttpd/1.4.69 (Linux)", title: "LaserJet M507" }),
            (631, Service::Http { status: "HTTP/1.0 200 OK", server: "CUPS/2.4 IPP/2.1", title: "Home - CUPS 2.4.2" }),
        ],
    },
];

/// The office subnet, with the simulated machines and the container.
const SUBNET: [u8; 3] = [10, 0, 0];
/// The real container's address.
const CONTAINER: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 50);
/// The scanner's subnet.
const SCANNER_NET: &str = "10.0.9.0/24";

fn main() -> Result {
    let path = std::env::args().nth(1).unwrap_or_else(|| "/run/fictionet/world.sock".into());
    let (attacher, attachments) = fictionet::attachments();
    let _listening = fictionet::listen(fictionet::WorldSocket::UnixSocket(path.clone().into()), attacher)?;
    println!("listening on {path}");
    fictionet::block_on(fictionet::run(move |cx| world(cx, attachments)))
}

async fn world(cx: Cx, mut attachments: Attachments) -> Result {
    let router = route::router(&cx, Vec::new());
    let hosts = cx.group("simulated hosts");
    for m in MACHINES {
        let addr = Ipv4Addr::new(SUBNET[0], SUBNET[1], SUBNET[2], m.host);
        let (router_side, machine_side) = pair();
        router.add(Prefix { addr: addr.into(), len: 32 }, Box::new(router_side));
        machine(&hosts.group(format!("{} {addr}", m.name)), machine_side, addr.into(), m.ports)?;
    }
    // Each sandbox goes through a short delay started in its own group, so
    // the group holds the task that reads the sandbox, and the sandbox with
    // it. Sandboxes that come back after detaching are wired again.
    while let Some(sandbox) = attachments.next(&cx).await {
        let (prefix, group, by): (Prefix, _, Duration) = match sandbox.name() {
            "container" => (Prefix { addr: CONTAINER.into(), len: 32 }, cx.group("real container"), ms(1)),
            "scanner" => (SCANNER_NET.parse()?, cx.group("scanner"), ms(2)),
            other => {
                println!("turned away {other}: this world wires only container and scanner");
                continue;
            }
        };
        println!("attached {}", sandbox.name());
        router.add(prefix, Box::new(fictionet::stdlib::delay(&group, by, sandbox)));
    }
    Ok(())
}

/// Starts one simulated machine at `addr` on `side`, all of it in `cx`'s
/// group.
fn machine(cx: &Cx, side: End, addr: IpAddr, ports: &'static [(u16, Service)]) -> Result {
    let (tcp, udp, icmp, _other) = ip::split_protocols(cx, side);
    let tcp = tcp::endpoint(cx, tcp, addr);
    // No UDP ports are open: every datagram gets "port unreachable".
    let _udp = udp::endpoint(cx, udp, addr);
    cx.spawn(move |cx| pings(cx, icmp, addr));
    for &(port, service) in ports {
        let listener = tcp.listen(port)?;
        cx.spawn(move |cx| accept(cx, listener, service));
    }
    // The endpoint lives on in its task; the listeners keep it reachable.
    drop(tcp);
    Ok(())
}

/// Answers pings to `addr`.
async fn pings(cx: Cx, mut icmp: End, addr: IpAddr) -> Result {
    while let Ok(packet) = icmp.recv(&cx).await {
        if let Some(reply) = icmp::echo_reply(&packet, addr) {
            icmp.send(reply);
        }
    }
    Ok(())
}

/// Connections one port serves at once. The agent could otherwise keep
/// thousands open, each with its task and buffers. Past this, a new
/// connection is closed as soon as it is accepted.
const CONNECTIONS: usize = 64;

/// Accepts connections on one port, and serves each in a task of its own.
async fn accept(cx: Cx, mut listener: tcp::Listener, service: Service) -> Result {
    let open = Arc::new(AtomicUsize::new(0));
    while let Ok(conn) = listener.accept(&cx).await {
        if open.load(Ordering::Relaxed) >= CONNECTIONS {
            drop(conn);
            continue;
        }
        open.fetch_add(1, Ordering::Relaxed);
        let open = open.clone();
        cx.spawn(move |cx| async move {
            // A client that resets or vanishes is no error.
            let _ = serve(&cx, conn, service).await;
            open.fetch_sub(1, Ordering::Relaxed);
            Ok(())
        });
    }
    Ok(())
}

/// How long a connection may stay quiet before the machine closes it.
const IDLE: Duration = Duration::from_secs(10);

async fn serve(cx: &Cx, mut conn: tcp::TcpConnection, service: Service) -> std::result::Result<(), ConnError> {
    let mut buf = vec![0u8; 4096];
    match service {
        Service::Banner(line) => {
            conn.write_all(cx, line.as_bytes()).await?;
            // Read and ignore what the client says until it leaves or goes
            // quiet.
            while let Some(Ok(n)) = timeout(cx, conn.read(cx, &mut buf)).await {
                if n == 0 {
                    break;
                }
            }
        }
        Service::Http { status, server, title } => {
            let mut request = Vec::new();
            loop {
                let Some(read) = timeout(cx, conn.read(cx, &mut buf)).await else { break };
                let n = read?;
                if n == 0 {
                    break;
                }
                request.extend_from_slice(&buf[..n]);
                if request.windows(4).any(|w| w == b"\r\n\r\n") || request.len() > 16 << 10 {
                    let body = format!("<!doctype html><html><head><title>{title}</title></head><body><h1>{title}</h1></body></html>\n");
                    let head = format!(
                        "{status}\r\nServer: {server}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    conn.write_all(cx, head.as_bytes()).await?;
                    conn.write_all(cx, body.as_bytes()).await?;
                    break;
                }
            }
        }
    }
    conn.shutdown(cx).await
}

/// `work`, or `None` if it takes longer than [`IDLE`].
async fn timeout<T>(cx: &Cx, work: impl std::future::Future<Output = T>) -> Option<T> {
    let mut work = std::pin::pin!(work);
    let sleep = cx.sleep(IDLE);
    let mut sleep = std::pin::pin!(sleep);
    std::future::poll_fn(|task| {
        if let std::task::Poll::Ready(v) = work.as_mut().poll(task) {
            return std::task::Poll::Ready(Some(v));
        }
        if sleep.as_mut().poll(task).is_ready() {
            return std::task::Poll::Ready(None);
        }
        std::task::Poll::Pending
    })
    .await
}
