//! What the honeypot serves and where it writes, from the command line.
//!
//! ```text
//! honeypot [--world unix:PATH] [--log PATH] [--pcap PATH]
//!          [--address IPV4] [--address-v6 IPV6] [--internet PREFIX]...
//!          [--gateway IPV4] [--gateway-v6 IPV6]
//!          [--ssh PORT]... [--http PORT]... [--http-profile caddy|nginx]
//!          [--burst-window-ms MS] [--burst-syns N]
//! ```
//!
//! With no `--ssh` or `--http`, the server has SSH on 22 and HTTP on 80.
//! With no `--address-v6`, it has IPv4 only.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::time::Duration;

use fictionet::WorldSocket;
use fictionet::stdlib::network::ethernet::host::Ipv6Gateway;
use fictionet::stdlib::network::route::Prefix;

/// The server's IPv4 address when none is given: in TEST-NET-3
/// ([RFC 5737](https://www.rfc-editor.org/rfc/rfc5737)).
pub const DEFAULT_ADDRESS: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 10);

/// The world: the server, the route the internet comes in by, and what
/// counts as a burst.
///
/// The server always has an IPv4 address, because the flaw the honeypot
/// is built for is in Linux's IPv4 connection setup. Its IPv6 address is
/// optional, as many servers have none. When it has one, it serves the
/// same ports and logs the same observations on both addresses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// The server's public IPv4 address.
    pub address: Ipv4Addr,
    /// The server's public IPv6 address, or `None` for a server with IPv4
    /// only.
    pub address_v6: Option<Ipv6Addr>,
    /// The addresses the `internet` attachment carries.
    pub internet: Internet,
    /// The IPv4 default gateway of the raw Ethernet adapter
    /// ([`start_raw`](crate::start_raw)): the router every IPv4 packet goes
    /// to.
    pub gateway: Ipv4Addr,
    /// Where the raw Ethernet adapter's IPv6 default gateway comes from: an
    /// address, such as `fe80::1` on Hetzner, or the router advertisements
    /// on the link, as on AWS and Google Cloud. Unused without
    /// [`address_v6`](Config::address_v6).
    pub gateway_v6: Ipv6Gateway,
    /// The server's open TCP ports.
    pub ports: Vec<Port>,
    /// The HTTP server persona. Caddy accepts MPTCP; nginx uses ordinary TCP.
    pub http_profile: HttpProfile,
    /// When SYNs from one source count as a burst.
    pub burst: Burst,
}

/// The addresses the internet comes in from, one prefix per family. The
/// internet may send from any address in them that the network does not
/// have elsewhere.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Internet {
    /// The IPv4 prefix, `0.0.0.0/0` by default.
    pub ipv4: Prefix,
    /// The IPv6 prefix, `::/0` by default. Used only when the server has an
    /// IPv6 address.
    pub ipv6: Prefix,
}

impl Default for Internet {
    fn default() -> Internet {
        Internet {
            ipv4: Prefix {
                addr: Ipv4Addr::UNSPECIFIED.into(),
                len: 0,
            },
            ipv6: Prefix {
                addr: Ipv6Addr::UNSPECIFIED.into(),
                len: 0,
            },
        }
    }
}

impl Internet {
    /// Sets the prefix of `prefix`'s family.
    pub fn set(&mut self, prefix: Prefix) {
        match prefix.addr {
            IpAddr::V4(_) => self.ipv4 = prefix,
            IpAddr::V6(_) => self.ipv6 = prefix,
        }
    }
}

/// One open port and what answers on it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Port {
    /// The TCP port.
    pub number: u16,
    /// What it serves.
    pub service: Service,
}

/// What a port serves once a connection is open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Service {
    /// An OpenSSH server's identification line.
    Ssh,
    /// The configured HTTP profile's default page.
    Http,
}

/// The packaged HTTP server whose behavior is exposed to clients.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum HttpProfile {
    /// Official Caddy with its packaged site and default MPTCP listener.
    #[default]
    Caddy,
    /// Ubuntu nginx with its packaged site and ordinary TCP listener.
    Nginx,
}

/// When SYNs from one source address count as a burst: at least `syns`
/// of one kind within `window` of each other.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Burst {
    /// How close together the SYNs are.
    pub window: Duration,
    /// How many make a burst.
    pub syns: usize,
}

impl Default for Burst {
    fn default() -> Burst {
        Burst {
            window: Duration::from_millis(100),
            syns: 8,
        }
    }
}

impl Default for Config {
    fn default() -> Config {
        Config {
            address: DEFAULT_ADDRESS,
            address_v6: None,
            gateway: Ipv4Addr::new(203, 0, 113, 1),
            gateway_v6: Ipv6Gateway::FromRouterAdvertisements,
            internet: Internet::default(),
            ports: vec![
                Port {
                    number: 22,
                    service: Service::Ssh,
                },
                Port {
                    number: 80,
                    service: Service::Http,
                },
            ],
            burst: Burst::default(),
            http_profile: HttpProfile::default(),
        }
    }
}

/// The command line: the world, the socket it listens on, and its two
/// output files.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Args {
    /// Where `fictionet attach` connects.
    pub world: WorldSocket,
    /// The observations, one JSON object per line.
    pub log: PathBuf,
    /// Every packet, as pcapng.
    pub pcap: PathBuf,
    /// The world.
    pub config: Config,
}

/// Why the command line could not be read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ArgsError {
    /// An argument that is no flag here.
    Unknown(String),
    /// A flag with no value after it.
    Missing(Flag),
    /// A flag whose value does not parse.
    Bad {
        /// The flag.
        flag: Flag,
        /// What followed it.
        value: String,
    },
}

impl std::fmt::Display for ArgsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ArgsError::Unknown(arg) => write!(f, "unknown argument {arg:?}"),
            ArgsError::Missing(flag) => write!(f, "{} needs a value", flag.name()),
            ArgsError::Bad { flag, value } => write!(f, "{}: cannot use {value:?}", flag.name()),
        }
    }
}

impl std::error::Error for ArgsError {}

/// A flag of the command line. Each takes a value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flag {
    /// `--world`: [`Args::world`].
    World,
    /// `--log`: [`Args::log`].
    Log,
    /// `--pcap`: [`Args::pcap`].
    Pcap,
    /// `--address`: [`Config::address`].
    Address,
    /// `--address-v6`: [`Config::address_v6`].
    AddressV6,
    /// `--internet`: the prefix of its family in [`Config::internet`].
    Internet,
    /// `--gateway`: [`Config::gateway`].
    Gateway,
    /// `--gateway-v6`: a configured [`Config::gateway_v6`]. Without it, the
    /// gateway is learned from router advertisements.
    GatewayV6,
    /// `--ssh`: a port with [`Service::Ssh`].
    Ssh,
    /// `--http`: a port with [`Service::Http`].
    Http,
    /// `--http-profile`: [`Config::http_profile`].
    HttpProfile,
    /// `--burst-window-ms`: [`Burst::window`].
    BurstWindowMs,
    /// `--burst-syns`: [`Burst::syns`].
    BurstSyns,
}

impl Flag {
    /// Every flag.
    pub const ALL: [Flag; 13] = [
        Flag::World,
        Flag::Log,
        Flag::Pcap,
        Flag::Address,
        Flag::AddressV6,
        Flag::Internet,
        Flag::Gateway,
        Flag::GatewayV6,
        Flag::Ssh,
        Flag::Http,
        Flag::HttpProfile,
        Flag::BurstWindowMs,
        Flag::BurstSyns,
    ];

    /// The flag as written.
    pub fn name(self) -> &'static str {
        match self {
            Flag::World => "--world",
            Flag::Log => "--log",
            Flag::Pcap => "--pcap",
            Flag::Address => "--address",
            Flag::AddressV6 => "--address-v6",
            Flag::Internet => "--internet",
            Flag::Gateway => "--gateway",
            Flag::GatewayV6 => "--gateway-v6",
            Flag::Ssh => "--ssh",
            Flag::Http => "--http",
            Flag::HttpProfile => "--http-profile",
            Flag::BurstWindowMs => "--burst-window-ms",
            Flag::BurstSyns => "--burst-syns",
        }
    }

    /// The flag written as `arg`.
    pub fn parse(arg: &str) -> Option<Flag> {
        Flag::ALL.into_iter().find(|flag| flag.name() == arg)
    }
}

impl Args {
    /// Reads the arguments after the program name.
    pub fn parse(args: impl IntoIterator<Item = String>) -> Result<Args, ArgsError> {
        let mut parsed = Args {
            world: WorldSocket::UnixSocket("/run/fictionet/world.sock".into()),
            log: "honeypot.jsonl".into(),
            pcap: "honeypot.pcapng".into(),
            config: Config {
                ports: Vec::new(),
                ..Config::default()
            },
        };
        let mut args = args.into_iter();
        while let Some(arg) = args.next() {
            let Some(flag) = Flag::parse(&arg) else {
                return Err(ArgsError::Unknown(arg));
            };
            let value = args.next().ok_or(ArgsError::Missing(flag))?;
            let bad = || ArgsError::Bad {
                flag,
                value: value.clone(),
            };
            let config = &mut parsed.config;
            match flag {
                Flag::World => parsed.world = value.parse().map_err(|_| bad())?,
                Flag::Log => parsed.log = value.into(),
                Flag::Pcap => parsed.pcap = value.into(),
                Flag::Address => config.address = value.parse().map_err(|_| bad())?,
                Flag::AddressV6 => config.address_v6 = Some(value.parse().map_err(|_| bad())?),
                Flag::Internet => config.internet.set(value.parse().map_err(|_| bad())?),
                Flag::Gateway => config.gateway = value.parse().map_err(|_| bad())?,
                Flag::GatewayV6 => {
                    config.gateway_v6 = Ipv6Gateway::Configured(value.parse().map_err(|_| bad())?)
                }
                Flag::Ssh => config.ports.push(Port {
                    number: value.parse().map_err(|_| bad())?,
                    service: Service::Ssh,
                }),
                Flag::Http => config.ports.push(Port {
                    number: value.parse().map_err(|_| bad())?,
                    service: Service::Http,
                }),
                Flag::HttpProfile => {
                    config.http_profile = match value.as_str() {
                        "caddy" => HttpProfile::Caddy,
                        "nginx" => HttpProfile::Nginx,
                        _ => return Err(bad()),
                    };
                }
                Flag::BurstWindowMs => {
                    config.burst.window = Duration::from_millis(value.parse().map_err(|_| bad())?)
                }
                Flag::BurstSyns => match value.parse() {
                    Ok(n) if n > 0 => config.burst.syns = n,
                    _ => return Err(bad()),
                },
            }
        }
        if parsed.config.ports.is_empty() {
            parsed.config.ports = Config::default().ports;
        }
        Ok(parsed)
    }
}
