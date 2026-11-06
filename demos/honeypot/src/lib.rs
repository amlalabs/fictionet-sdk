//! A honeypot for CVE-2026-98432: a world that looks like a Linux server
//! with an MPTCP listener, and logs everyone who tries it.
//!
//! IPv4 option-bearing SYNs and their retransmissions are logged separately
//! from MP_CAPABLE offers that close or expire without sending data. These
//! are observations of traffic shape, not proof of exploitation.
//!
//! The world is one host at a public IPv4 address ([`Config::address`]),
//! and at a public IPv6 address too when it has one
//! ([`Config::address_v6`]), with ordinary OpenSSH on port 22 and Caddy's
//! packaged HTTP site on port 80 ([`ssh`], [`services`]). The explicit nginx profile
//! uses ordinary TCP for HTTP. Both addresses serve the same ports. On a
//! Caddy port, a SYN with MP_CAPABLE gets an RFC 8684 SYN-ACK with a key, its data
//! then carries DSS, and an MP_JOIN is answered, taken or refused as Linux
//! answers, takes and refuses it ([`fictionet_extras::linux::mptcp`]). The internet reaches the
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
//! | [`fictionet_extras::linux::mptcp`] | How the listener answers MP_CAPABLE and MP_JOIN |
//! | [`services`] | HTTP once a connection is open |
//! | [`ssh`] | SSH authentication, fake prompt and command hangup |
//! | [`observe`] | The packet log and the observations |

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::task::Poll;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fictionet::stdlib::network::ip::{self, Intake, Reassembly};
use fictionet::stdlib::network::ports::{Event, Ports};
use fictionet::stdlib::world::net::{Host, Net, Pools};
use fictionet::sync::Mutex;
use fictionet::time::Instant;
use fictionet::{Attachment, Attachments, Cx, End, Interface};

pub mod config;
pub mod observe;
pub mod services;
pub mod ssh;

#[cfg(all(feature = "raw-virtio", target_os = "linux"))]
pub mod raw;
#[cfg(all(feature = "raw-virtio", target_os = "linux"))]
pub use raw::start_raw;

pub use config::{Args, Config, HttpProfile, Port, Service};
use fictionet_extras::linux::mptcp::{Listener, Tokens};
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
pub fn network(
    fcx: &Cx,
    config: &Config,
    clock: Clock,
    tokens: &Arc<Tokens>,
    observer: Arc<Mutex<Observer>>,
) -> Net {
    let mut server = Host::new("server")
        .at(config.address)
        .tcp_options(fictionet_extras::linux::tcp())
        .icmp_options(fictionet_extras::linux::icmp(fcx));
    server = match config.address_v6 {
        Some(address_v6) => server.at(address_v6),
        None => server.ipv4_only(),
    };
    for port in &config.ports {
        let timestamp = {
            let fcx = fcx.clone();
            move || ((clock.micros(fcx.now()) / 1000) % 86_400_000) as u32
        };
        server = match port.service {
            Service::Ssh => server.port_server(
                port.number,
                fictionet_extras::linux::with_ipv4_options(
                    ssh::server(fcx, config.ssh_auth.clone(), observer.clone()),
                    timestamp,
                ),
            ),
            Service::Http if config.http_profile == HttpProfile::Caddy => server.port_server(
                port.number,
                Listener::new(
                    fcx,
                    timestamp,
                    tokens.clone(),
                    port.number,
                    services::Http {
                        clock,
                        profile: config.http_profile,
                    },
                ),
            ),
            Service::Http => server.port_server(
                port.number,
                fictionet_extras::linux::with_ipv4_options(
                    services::Http {
                        clock,
                        profile: config.http_profile,
                    },
                    timestamp,
                ),
            ),
        };
    }
    let net = Net::new(Pools::NONE)
        .egress(fictionet_extras::network::corporate_egress)
        .add_host(server)
        .route(INTERNET, config.internet.ipv4);
    match config.address_v6 {
        Some(_) => net.route(INTERNET, config.internet.ipv6),
        None => net,
    }
}

/// The name of the attachment the internet comes in by, with IPv4 and
/// IPv6 alike.
pub const INTERNET: &str = "internet";

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
    network(fcx, config, clock, &tokens, observer.clone()).start(fcx, inner)?;
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
            // A name still held by a relay that has not seen its sandbox
            // go yet is refused, and the new sandbox is cut off.
            let Ok(end) = attacher.attach(sandbox.name()) else {
                continue;
            };
            let route = if sandbox.name() == INTERNET {
                Route::Server(address, address_v6)
            } else {
                Route::All
            };
            let observer = observer.clone();
            fcx.spawn(move |fcx| relay(fcx, sandbox, end, route, observer));
        }
    });
    Ok(honeypot)
}

/// Which packets from a sandbox go on into the world.
enum Route {
    /// A sandbox's own: every packet, whatever the destination.
    All,
    /// The internet's: only packets for the server's IPv4 address, or its
    /// IPv6 address when it has one. The internet reaches the server and
    /// nothing else in the world.
    Server(Ipv4Addr, Option<Ipv6Addr>),
}

impl Route {
    fn goes_on(&self, packet: &[u8]) -> bool {
        match (self, ip::destination(packet)) {
            (Route::All, _) => true,
            (Route::Server(address, _), Some(IpAddr::V4(dst))) => dst == *address,
            (Route::Server(_, address_v6), Some(IpAddr::V6(dst))) => *address_v6 == Some(dst),
            (Route::Server(..), None) => false,
        }
    }
}

/// The relay's port for the sandbox.
const SANDBOX: usize = 0;
/// The relay's port for the network.
const NETWORK: usize = 1;

/// Passes packets between a sandbox and the network, writing each one
/// first. A packet from the sandbox goes on by `end` as `route` says:
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
    end: End,
    route: Route,
    observer: Arc<Mutex<Observer>>,
) -> fictionet::Result {
    let name: Arc<str> = sandbox.name().into();
    let mut ports = Ports::new(vec![
        Box::new(sandbox) as Box<dyn Interface>,
        Box::new(end) as Box<dyn Interface>,
    ]);
    let mut reassembly = Reassembly::default();
    loop {
        let deadline = reassembly.next_expiry();
        match ports.next(&fcx, deadline, |_| Poll::Pending).await? {
            Event::Packet(SANDBOX, packet) => {
                let mut observer = observer.lock();
                observer.crossed(&name, Direction::In, &packet.0, fcx.now());
                let goes_on = route.goes_on(&packet.0);
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
                if goes_on {
                    ports.send(NETWORK, packet);
                }
            }
            Event::Packet(_, packet) => {
                let mut observer = observer.lock();
                observer.crossed(&name, Direction::Out, &packet.0, fcx.now());
                observer.whole(&name, Direction::Out, &packet.0, fcx.now());
                ports.send(SANDBOX, packet);
            }
            Event::Timer => reassembly.expire(fcx.now()),
            Event::Extra => {}
            Event::Closed(_) => return Ok(()),
        }
    }
}
