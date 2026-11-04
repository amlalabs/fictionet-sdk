//! A honeypot for CVE-2026-98432: a world that looks like a Linux server
//! with an MPTCP listener, and logs everyone who tries it.
//!
//! IPv4 option-bearing SYNs and their retransmissions are logged separately
//! from MP_CAPABLE offers that close or expire without sending data. These
//! are observations of traffic shape, not proof of exploitation.
//!
//! The world is one host at a public IPv4 address ([`Config::address`]),
//! and at a public IPv6 address too when it has one
//! ([`Config::address_v6`]), with MPTCP listeners on its open ports: SSH
//! with an OpenSSH identification line and HTTP with nginx's default page
//! ([`services`]). Both addresses serve the same ports. A SYN with
//! MP_CAPABLE gets an RFC 8684 SYN-ACK with MP_CAPABLE and a key, its data
//! then carries DSS, and an MP_JOIN is answered, taken or refused as Linux
//! answers, takes and refuses it ([`mptcp`]). The internet reaches the
//! host through an attachment called [`INTERNET`], which carries both
//! families and is routed at [`Config::internet`] with `Net::route`, and
//! reaches nothing else: its packets for any other address are logged and
//! dropped. Sandboxes attached under any other name join the network as
//! usual, and reach the host through its router.
//!
//! Every packet that crosses any attachment, both ways, goes to a pcapng
//! file, and a typed [`Observation`](observe::Observation) per SYN,
//! payload, answer and burst goes to a JSON-lines log ([`observe`]). The
//! observer sees each packet before the world's TCP does, once it is
//! whole: the relay puts fragments together and the world gets the
//! packet it made. Neither file can stop the world: what one cannot take
//! is counted, and the log says so once it can.
//!
//! Nothing here is a real kernel, and nothing runs what a client sends.
//! The packets come from the internet, so the world treats every byte as
//! hostile: each reader checks lengths, and the state kept per source or
//! connection is removed when that source or connection is gone.
//!
//! | Module | Contents |
//! | --- | --- |
//! | [`config`] | The command line and the world's settings |
//! | [`mptcp`] | How the listener answers MP_CAPABLE and MP_JOIN |
//! | [`services`] | SSH and HTTP once a connection is open |
//! | [`observe`] | The packet log and the observations |

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::task::Poll;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fictionet::stdlib::network::ip::{self, Intake, Reassembly};
use fictionet::stdlib::network::ports::{Event, Ports};
use fictionet::stdlib::world::net::{Host, Net};
use fictionet::sync::Mutex;
use fictionet::time::Instant;
use fictionet::{Attachment, Attachments, Cx, End, Interface};

pub mod config;
pub mod mptcp;
pub mod observe;
pub mod services;

#[cfg(all(feature = "raw-virtio", target_os = "linux"))]
pub mod raw;
#[cfg(all(feature = "raw-virtio", target_os = "linux"))]
pub use raw::start_raw;

pub use config::{Args, Config, Port, Service};
use mptcp::{Listener, Tokens};
use observe::{Direction, Observer, Sinks};

/// The wall clock: the time the run's clock reads zero, so that run times
/// become Unix times.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Clock {
    epoch: SystemTime,
}

impl Clock {
    /// A clock for a run that starts now.
    pub fn starting_now() -> Clock {
        Clock {
            epoch: SystemTime::now(),
        }
    }

    /// A clock for a run that started `secs` after the Unix epoch.
    pub fn at_unix_secs(secs: u64) -> Clock {
        Clock {
            epoch: UNIX_EPOCH + Duration::from_secs(secs),
        }
    }

    /// `at` in microseconds since the Unix epoch.
    pub fn micros(&self, at: Instant) -> u64 {
        self.since_epoch(at).as_micros() as u64
    }

    /// `at` in whole seconds since the Unix epoch.
    pub fn unix_secs(&self, at: Instant) -> u64 {
        self.since_epoch(at).as_secs()
    }

    fn since_epoch(&self, at: Instant) -> Duration {
        (self.epoch + at.since_start())
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
    }
}

/// The network before it starts: the server with its ports, and the route
/// the internet comes in by.
pub fn network(fcx: &Cx, config: &Config, clock: Clock, tokens: &Arc<Tokens>) -> Net {
    let mut server = Host::new("server")
        .at(config.address)
        .tcp_options(fictionet_extras::linux::tcp());
    server = match config.address_v6 {
        Some(address_v6) => server.at(address_v6),
        None => server.ipv4_only(),
    };
    for port in &config.ports {
        server = match port.service {
            Service::Ssh => server.port_server(
                port.number,
                Listener::new(fcx, clock, tokens.clone(), port.number, services::Ssh),
            ),
            Service::Http => server.port_server(
                port.number,
                Listener::new(
                    fcx,
                    clock,
                    tokens.clone(),
                    port.number,
                    services::Http { clock },
                ),
            ),
        };
    }
    let net = Net::new()
        .add_host(server)
        .route(INTERNET, config.internet.ipv4);
    match config.address_v6 {
        Some(_) => net.route(INTERNET6, config.internet.ipv6),
        None => net,
    }
}

/// The name of the attachment the internet comes in by, with IPv4 and
/// IPv6 alike.
pub const INTERNET: &str = "internet";

/// The name of the internet's IPv6 route inside the world. A network
/// route carries one prefix, so the relay for [`INTERNET`] passes IPv4 to
/// the route called `internet` and IPv6 to this one. A sandbox that comes
/// with this name is cut off.
const INTERNET6: &str = "internet6";

/// A running honeypot, for looking at what it holds.
#[derive(Clone)]
pub struct Honeypot {
    tokens: Arc<Tokens>,
    observer: Arc<Mutex<Observer>>,
}

impl Honeypot {
    /// How many open connections negotiated MPTCP.
    pub fn mptcp_connections(&self) -> usize {
        self.tokens.len()
    }

    /// How many source addresses the observer holds burst state for.
    pub fn sources(&self) -> usize {
        self.observer.lock().sources()
    }
}

/// Starts the honeypot in `fcx`: the network, and a relay for every
/// sandbox in `attachments` that writes what crosses it to `sinks`.
/// Returns once the network is up, or fails if `config` cannot be served
/// or the pcapng header cannot be written.
pub fn start(
    fcx: &Cx,
    config: &Config,
    clock: Clock,
    sinks: Sinks,
    mut attachments: Attachments,
) -> fictionet::Result<Honeypot> {
    let tokens = Arc::new(Tokens::default());
    let observer = Observer::new(sinks, clock, config.burst, tokens.clone())?;
    let observer = Arc::new(Mutex::new(observer));
    let honeypot = Honeypot {
        tokens: tokens.clone(),
        observer: observer.clone(),
    };
    let (attacher, inner) = fictionet::attachments();
    network(fcx, config, clock, &tokens).start(fcx, inner)?;
    let expiring = observer.clone();
    fcx.spawn(move |fcx| async move {
        let mut timer = fictionet::Timer::new(&fcx);
        loop {
            std::future::poll_fn(|cx| {
                let deadline = expiring.lock().expiry(cx);
                timer.poll_until(cx, deadline)
            })
            .await?;
            expiring.lock().expire(fcx.now());
        }
    });
    let (address, address_v6) = (config.address, config.address_v6);
    fcx.spawn(move |fcx| async move {
        loop {
            let sandbox = attachments.next(&fcx).await?;
            if sandbox.name() == INTERNET6 {
                continue;
            }
            // A name still held by a relay that has not seen its sandbox
            // go yet is refused, and the new sandbox is cut off.
            let Ok(end) = attacher.attach(sandbox.name()) else {
                continue;
            };
            let (ends, route) = match (sandbox.name() == INTERNET, address_v6) {
                (false, _) => (vec![end], Route::All),
                (true, None) => (vec![end], Route::Server(address, None)),
                (true, Some(address_v6)) => match attacher.attach(INTERNET6) {
                    Ok(end6) => (vec![end, end6], Route::Server(address, Some(address_v6))),
                    Err(_) => continue,
                },
            };
            let observer = observer.clone();
            fcx.spawn(move |fcx| relay(fcx, sandbox, ends, route, observer));
        }
    });
    Ok(honeypot)
}

/// Which of the network's attachments a packet from a sandbox goes on
/// by. The relay's port 0 is the sandbox, and its network attachments are
/// ports 1 and on.
enum Route {
    /// A sandbox's own attachment: port 1, whatever the destination.
    All,
    /// The internet's routes, one per family: port 1 for the server's IPv4
    /// address, port 2 for its IPv6 address, and none for any other
    /// destination. The internet reaches the server and nothing else in
    /// the world.
    Server(Ipv4Addr, Option<Ipv6Addr>),
}

impl Route {
    fn port(&self, packet: &[u8]) -> Option<usize> {
        match (self, ip::destination(packet)) {
            (Route::All, _) => Some(1),
            (Route::Server(address, _), Some(IpAddr::V4(dst))) if dst == *address => Some(1),
            (Route::Server(_, Some(address_v6)), Some(IpAddr::V6(dst))) if dst == *address_v6 => {
                Some(2)
            }
            (Route::Server(..), _) => None,
        }
    }
}

/// Passes packets between a sandbox and the network, writing each one
/// first. A packet from the sandbox goes on by `ends` as `route` says:
/// for the internet, only when it is for one of the server's addresses.
/// Ends when either side closes. A write that fails does not end it: the
/// observer counts what was lost ([`observe`]).
///
/// Every packet goes to the packet log as it crossed. Fragments from the
/// sandbox that go on are put back together here, as a host puts them
/// together ([`Reassembly`]: at most 4 MiB waiting, for at most 30 seconds
/// for IPv4 and 60 for IPv6), and the world gets the whole packet. So the
/// observer logs each packet once it is whole, as the world gets it.
/// Fragments for addresses the world never sees are not put together, and
/// cannot crowd out those it does: they are in the packet log only. A
/// whole packet for such an address is logged, and dropped here.
async fn relay(
    fcx: Cx,
    sandbox: Attachment,
    ends: Vec<End>,
    route: Route,
    observer: Arc<Mutex<Observer>>,
) -> fictionet::Result {
    let name: Arc<str> = sandbox.name().into();
    let mut interfaces = vec![Box::new(sandbox) as Box<dyn Interface>];
    interfaces.extend(
        ends.into_iter()
            .map(|end| Box::new(end) as Box<dyn Interface>),
    );
    let mut ports = Ports::new(interfaces);
    let mut reassembly = Reassembly::default();
    loop {
        let deadline = reassembly.next_expiry();
        match ports.next(&fcx, deadline, |_| Poll::Pending).await? {
            Event::Packet(0, packet) => {
                let mut observer = observer.lock();
                observer.crossed(&name, Direction::In, &packet.0, fcx.now());
                let port = route.port(&packet.0);
                let goes_on = port.is_some();
                let fragment = ip::Header::parse_truncated(&packet.0)
                    .is_some_and(|h| h.fragment.is_some_and(|f| !f.is_atomic()));
                if fragment && !goes_on {
                    continue;
                }
                // A packet refused for its IPv6 extension headers goes on
                // as it is, so the world refuses it and answers as a host
                // does.
                let packet = match reassembly.push(packet, fcx.now()) {
                    Intake::Whole(packet) | Intake::Refused { packet, .. } => packet,
                    Intake::Waiting => continue,
                };
                observer.whole(&name, Direction::In, &packet.0, fcx.now());
                if let Some(port) = port {
                    ports.send(port, packet);
                }
            }
            Event::Packet(_, packet) => {
                let mut observer = observer.lock();
                observer.crossed(&name, Direction::Out, &packet.0, fcx.now());
                observer.whole(&name, Direction::Out, &packet.0, fcx.now());
                ports.send(0, packet);
            }
            Event::Timer => reassembly.expire(fcx.now()),
            Event::Extra => {}
            Event::Closed(_) => return Ok(()),
        }
    }
}
