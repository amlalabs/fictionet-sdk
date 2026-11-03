//! What the honeypot serves and where it writes, from the command line.
//!
//! ```text
//! honeypot [--world unix:PATH] [--log PATH] [--pcap PATH]
//!          [--address ADDR] [--internet PREFIX]
//!          [--ssh PORT]... [--http PORT]...
//!          [--burst-window-ms MS] [--burst-syns N]
//! ```
//!
//! With no `--ssh` or `--http`, the server has SSH on 22 and HTTP on 80.

use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::time::Duration;

use fictionet::WorldSocket;
use fictionet::stdlib::network::route::Prefix;

/// The server's address when none is given: in TEST-NET-3 (RFC 5737).
pub const DEFAULT_ADDRESS: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));

/// The world: the server, the route the internet comes in by, and what
/// counts as a burst.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// The server's public address.
    pub address: IpAddr,
    /// The addresses the `internet` attachment carries.
    pub internet: Prefix,
    /// The server's open TCP ports, each with an MPTCP listener.
    pub ports: Vec<Port>,
    /// When SYNs from one source count as a burst.
    pub burst: Burst,
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
    /// nginx's default page.
    Http,
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
            internet: Prefix {
                addr: Ipv4Addr::UNSPECIFIED.into(),
                len: 0,
            },
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
    /// `--internet`: [`Config::internet`].
    Internet,
    /// `--ssh`: a port with [`Service::Ssh`].
    Ssh,
    /// `--http`: a port with [`Service::Http`].
    Http,
    /// `--burst-window-ms`: [`Burst::window`].
    BurstWindowMs,
    /// `--burst-syns`: [`Burst::syns`].
    BurstSyns,
}

impl Flag {
    /// Every flag.
    pub const ALL: [Flag; 9] = [
        Flag::World,
        Flag::Log,
        Flag::Pcap,
        Flag::Address,
        Flag::Internet,
        Flag::Ssh,
        Flag::Http,
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
            Flag::Internet => "--internet",
            Flag::Ssh => "--ssh",
            Flag::Http => "--http",
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
                Flag::Internet => config.internet = value.parse().map_err(|_| bad())?,
                Flag::Ssh => config.ports.push(Port {
                    number: value.parse().map_err(|_| bad())?,
                    service: Service::Ssh,
                }),
                Flag::Http => config.ports.push(Port {
                    number: value.parse().map_err(|_| bad())?,
                    service: Service::Http,
                }),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn args(line: &str) -> Result<Args, ArgsError> {
        Args::parse(line.split_whitespace().map(String::from))
    }

    /// Every flag reads back from its name, and each name is one flag's.
    #[test]
    fn flags_read_by_name() {
        for flag in Flag::ALL {
            assert_eq!(Flag::parse(flag.name()), Some(flag));
            let value = match flag {
                Flag::World => "unix:/tmp/w.sock",
                Flag::Address => "192.0.2.1",
                Flag::Internet => "0.0.0.0/0",
                _ => "7",
            };
            assert!(
                args(&format!("{} {value}", flag.name())).is_ok(),
                "{flag:?}"
            );
        }
        assert_eq!(Flag::parse("--world=unix:/x"), None);
    }

    #[test]
    fn defaults_serve_ssh_and_http() {
        let parsed = args("").unwrap();
        assert_eq!(parsed.config, Config::default());
        assert_eq!(parsed.log, PathBuf::from("honeypot.jsonl"));
    }

    #[test]
    fn flags_set_the_world() {
        let parsed = args(
            "--world unix:/tmp/w.sock --log a.jsonl --pcap a.pcapng --address 198.51.100.7 \
             --internet 198.51.0.0/16 --ssh 2222 --http 8080 --http 80 \
             --burst-window-ms 50 --burst-syns 4",
        )
        .unwrap();
        assert_eq!(parsed.world, WorldSocket::UnixSocket("/tmp/w.sock".into()));
        assert_eq!(parsed.pcap, PathBuf::from("a.pcapng"));
        let config = parsed.config;
        assert_eq!(config.address, "198.51.100.7".parse::<IpAddr>().unwrap());
        assert_eq!(config.internet, "198.51.0.0/16".parse().unwrap());
        assert_eq!(
            config.ports.iter().map(|p| p.number).collect::<Vec<_>>(),
            [2222, 8080, 80]
        );
        assert_eq!(config.ports[0].service, Service::Ssh);
        assert_eq!(config.ports[2].service, Service::Http);
        assert_eq!(
            config.burst,
            Burst {
                window: Duration::from_millis(50),
                syns: 4
            }
        );
    }

    #[test]
    fn bad_arguments_say_what_is_wrong() {
        assert_eq!(args("--ssh"), Err(ArgsError::Missing(Flag::Ssh)));
        assert_eq!(args("--port 22"), Err(ArgsError::Unknown("--port".into())));
        assert_eq!(
            args("--address example"),
            Err(ArgsError::Bad {
                flag: Flag::Address,
                value: "example".into()
            })
        );
        assert_eq!(
            args("--burst-syns 0").unwrap_err().to_string(),
            "--burst-syns: cannot use \"0\""
        );
        assert!(args("--burst-syns 0").is_err());
        assert!(args("--world /no/scheme").is_err());
    }
}
