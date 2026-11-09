#![deny(unsafe_code)]

//! A shared Linux honeypot with MPTCP, SSH, and literal port-zero observations.
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
//! packet it made. Port-zero facts instead describe original ingress packets.
//! The executable supplies bounded asynchronous evidence sinks; rejected
//! records are counted without waiting for storage.
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

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::task::Poll;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fictionet::stdlib::network::ip::{self, Intake, Reassembly};
use fictionet::stdlib::network::ports::{Event, Ports};
use fictionet::stdlib::services::stack::Counted;
use fictionet::stdlib::world::net::{Arrival, Host, Net, NetHandle, Pools, PortServer, Program};
use fictionet::sync::Mutex;
use fictionet::time::Instant;
use fictionet::{Attachment, Attachments, Cx, End, Interface};

pub mod config;
pub mod evidence;
pub mod observe;
pub mod services;
pub mod ssh;

#[cfg(all(feature = "raw-ethernet", not(target_arch = "wasm32")))]
pub mod raw;
#[cfg(all(feature = "raw-ethernet", not(target_arch = "wasm32")))]
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
        .icmp_options(fictionet_extras::linux::icmp(fcx))
        .udp_settings(fictionet_extras::linux::udp());
    server = match config.address_v6 {
        Some(address_v6) => server.at(address_v6),
        None => server.ipv4_only(),
    };
    let connections = Arc::new(AtomicUsize::new(0));
    for port in &config.ports {
        let timestamp = {
            let fcx = fcx.clone();
            move || ((clock.micros(fcx.now()) / 1000) % 86_400_000) as u32
        };
        let inner: Box<dyn PortServer> = match port.service {
            Service::Ssh => Box::new(fictionet_extras::linux::with_ipv4_options(
                ssh::server(
                    fcx,
                    config.ssh_auth.clone(),
                    config.ssh_host_key,
                    observer.clone(),
                ),
                timestamp,
            )),
            Service::Http if config.http_profile == HttpProfile::Caddy => Box::new(Listener::new(
                fcx,
                timestamp,
                tokens.clone(),
                port.number,
                services::Http {
                    clock,
                    profile: config.http_profile,
                },
            )),
            Service::Http => Box::new(fictionet_extras::linux::with_ipv4_options(
                services::Http {
                    clock,
                    profile: config.http_profile,
                },
                timestamp,
            )),
        };
        server = server.port_server(
            port.number,
            Bounded {
                inner,
                connections: connections.clone(),
                observer: observer.clone(),
            },
        );
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

/// Maximum accepted sockets shared by all honeypot services and address families.
pub const CONNECTION_LIMIT: usize = 256;

struct Bounded {
    inner: Box<dyn PortServer>,
    connections: Arc<AtomicUsize>,
    observer: Arc<Mutex<Observer>>,
}

impl PortServer for Bounded {
    fn serve(&self, fcx: Cx, arrival: Arrival) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let Some(guard) = Counted::enter(&self.connections, CONNECTION_LIMIT) else {
            self.observer.lock().connection_limit(fcx.now());
            arrival.socket.reset();
            return Box::pin(async {});
        };
        arrival.socket.hold_until_gone(Box::new(guard));
        self.inner.serve(fcx, arrival)
    }

    fn backlog(&self) -> Option<usize> {
        self.inner.backlog()
    }
    fn alpn(&self) -> Vec<Vec<u8>> {
        self.inner.alpn()
    }
    fn answer(&self) -> Option<Box<dyn fictionet::stdlib::network::tcp::Answer>> {
        self.inner.answer()
    }
}

/// The name of the attachment the internet comes in by, with IPv4 and
/// IPv6 alike.
pub const INTERNET: &str = "internet";

/// A running honeypot, its observations, and trusted machine programs.
#[derive(Clone)]
pub struct Honeypot {
    network: NetHandle,
    address: Ipv4Addr,
    address_v6: Option<Ipv6Addr>,
    observer: Arc<Mutex<Observer>>,
}

impl Honeypot {
    /// Runs trusted application code on the existing honeypot machines.
    ///
    /// Its TCP and UDP endpoints share the server's addresses and ports.
    /// Initiated packets leave through the same routed attachment as replies;
    /// this does not open host operating system sockets. With IPv6 configured,
    /// the program runs once per address family. Errors fail the world region.
    pub fn program(&self, program: impl Program) -> fictionet::Result {
        let host = Host::new("server").at(self.address).program(program);
        let host = match self.address_v6 {
            Some(address) => host.at(address),
            None => host.ipv4_only(),
        };
        self.network.add_host(host)?;
        Ok(())
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
    let mut observer = Observer::new(sinks, clock, config.burst, tokens.clone())?;
    observer.restricted_evidence(config.restricted_evidence);
    let observer = Arc::new(Mutex::new(observer));
    let network = network(fcx, config, clock, &tokens, observer.clone());
    let honeypot = Honeypot {
        network: network.handle(),
        address: config.address,
        address_v6: config.address_v6,
        observer: observer.clone(),
    };
    let (attacher, inner) = fictionet::attachments();
    network.start(fcx, inner)?;
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
                let reassembled = fragment
                    && ip::Header::parse_truncated(&packet.0)
                        .is_some_and(|header| header.fragment.is_none());
                if reassembled {
                    observer.reassembled(&name, Direction::In, &packet.0, fcx.now());
                } else {
                    observer.whole(&name, Direction::In, &packet.0, fcx.now());
                }
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
