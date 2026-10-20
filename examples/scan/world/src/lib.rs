//! A small office subnet for a port scanner, on a
//! [`fictionet::stdlib::world::net::Net`]. Four machines are simulated:
//! `www` at 10.0.0.10, `mail` at 10.0.0.11, `files` at 10.0.0.12, and
//! `printer` at 10.0.0.13. A real server attaches at 10.0.0.50.
//! The scanner uses 10.0.9.0/24, so a scan of 10.0.0.0/24 excludes it.
//!
//! Each simulated machine is a [`fictionet::stdlib::world::net::Host`].
//! Each open port runs a small [`fictionet::stdlib::services::serve::Service`].
//! It sends a banner or a page for each HTTP request, so `nmap -sV` can name it.
//! A port with no service answers a SYN with a RST. A scanner reports it
//! closed rather than filtered. An address with no host answers "host unreachable".
//! The dashboard shows "simulated hosts", with one group per machine inside it.
//! The two guests have their own groups: "real server" and "scanner".
//!
//! To run in-process, build [`office`] and add hosts or routes if needed.
//! Call [`start`] with the world's attachments. Keep the [`Ports`] handle
//! for snapshots and changes since a revision. See [`ports`] for probe facts
//! and [`banners`] for the first data each open port sends.
//!
//! ```
//! use fictionet::{RunOptions, Seed};
//! use scan_world::{office, start};
//!
//! fictionet::block_on(fictionet::lab(
//!     RunOptions::new(Seed::from_u64(42)),
//!     |fcx| async move {
//!         let (_attacher, attachments) = fictionet::attachments();
//!         let ports = start(&fcx, office(), attachments)?;
//!         let snapshot = ports.snapshot();
//!         let names: Vec<_> = snapshot.machines.iter().map(|m| m.name.as_str()).collect();
//!         assert_eq!(names, ["www", "mail", "files", "printer", "server"]);
//!         assert!(snapshot.rows.is_empty());
//!         fcx.cancel();
//!         Ok(())
//!     },
//! ))?;
//! # Ok::<(), fictionet::Error>(())
//! ```
//!
//! The server's card takes [`SERVER_LEASE`]:
//! `Link::new(Family::Serve(SERVER_LEASE), Family::Off, mtu)`.
//! Use [`fictionet::stdlib::network::ethernet::Link`] and
//! [`fictionet::stdlib::network::ethernet::Family`]. Bridge its frames
//! through the card to the [`SERVER`] attachment. The scanner's card uses
//! [`fictionet::stdlib::network::ethernet::Family::FromWorld`] and the
//! [`SCANNER`] attachment. The Net's DHCP leases it an address in [`SCANNER_SUBNET`].

pub mod banners;
pub mod ports;
pub use banners::Banner;
pub use ports::{Machine, MachineKind, PortChanges, PortMap, PortRow, PortState, Ports, Protocol};

use std::convert::Infallible;
use std::net::Ipv4Addr;
use std::sync::Arc;

use fictionet::stdlib::codec::{Collect, Wire};
use fictionet::stdlib::network::ethernet::{Cidr, Lease};
use fictionet::stdlib::network::route::Prefix;
use fictionet::stdlib::services::serve::{Driver, Flow, Service};
use fictionet::stdlib::world::net::{Host, Net};
use fictionet::stdlib::{
    protocols::{ftp, imap, pop3, smtp, ssh},
    web::httpd,
};
use fictionet::time::ms;
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

/// An office machine and the services the world runs for it.
struct HostSpec {
    name: &'static str,
    host: u8,
    kind: MachineKind,
    ports: &'static [(u16, Kind)],
}

const OPENSSH: Kind = Kind::Ssh;

const MACHINES: &[HostSpec] = &[
    HostSpec {
        name: "www",
        host: 10,
        kind: MachineKind::Simulated,
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
    HostSpec {
        name: "mail",
        host: 11,
        kind: MachineKind::Simulated,
        ports: &[(25, Kind::Smtp), (110, Kind::Pop3), (143, Kind::Imap)],
    },
    HostSpec {
        name: "files",
        host: 12,
        kind: MachineKind::Simulated,
        ports: &[(21, Kind::Ftp), (22, OPENSSH)],
    },
    HostSpec {
        name: "printer",
        host: 13,
        kind: MachineKind::Simulated,
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
    HostSpec {
        name: SERVER,
        host: SERVER_ADDR.octets()[3],
        kind: MachineKind::Real,
        ports: &[],
    },
];

/// The scanner's attachment name.
pub const SCANNER: &str = "scanner";
/// The real server's attachment name.
pub const SERVER: &str = "server";
/// The office subnet, holding the simulated machines and real server.
pub const OFFICE: Prefix = Prefix {
    addr: std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
    len: 24,
};
/// The subnet where the Net leases scanner addresses.
pub const SCANNER_SUBNET: Prefix = Prefix {
    addr: std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 9, 0)),
    len: 24,
};
/// The real server's fixed address.
pub const SERVER_ADDR: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 50);
/// The server VM's network configuration.
///
/// Give its card `Link::new(Family::Serve(SERVER_LEASE), Family::Off, mtu)`
/// and bridge its frames to the `SERVER` attachment. The scanner's card uses
/// `Family::FromWorld`, so the Net leases it an address in `SCANNER_SUBNET`.
pub const SERVER_LEASE: Lease<Ipv4Addr> = Lease {
    addr: Cidr {
        addr: SERVER_ADDR,
        prefix: 24,
    },
    gateway: Some(Ipv4Addr::new(10, 0, 0, 1)),
    dns: Some(Ipv4Addr::new(10, 0, 9, 1)),
};

/// Builds the office. Add hosts, a resolver or trusted routes before starting.
pub fn office() -> Net {
    let mut net = Net::new()
        .group("simulated hosts")
        .subnet(SCANNER_SUBNET)
        .ipv4_only();
    for m in MACHINES.iter().filter(|m| m.kind == MachineKind::Simulated) {
        let mut host = Host::new(m.name).at(Ipv4Addr::new(10, 0, 0, m.host));
        for &(port, kind) in m.ports {
            host = match kind {
                Kind::Http { server, title } => host.tcp(port, Arc::new(()), move || {
                    httpd::Http1::new(Page { server, title })
                }),
                Kind::Ssh => host.tcp(port, Arc::new(()), || Ssh),
                _ => host.tcp(port, Arc::new(()), move || Greeting(kind)),
            };
        }
        net = net.add_host(host);
    }
    net.route(
        SERVER,
        Prefix {
            addr: SERVER_ADDR.into(),
            len: 32,
        },
    )
}

/// Starts an office with delays and a passive probe tap on the scanner.
/// Other attachments pass through, including an integrator's jump host.
pub fn start(fcx: &Cx, net: Net, attachments: Attachments) -> Result<Ports> {
    let ports = Ports::new();
    let tap = ports.clone();
    // Each sandbox goes through a short delay started in its own group, so
    // the group holds the task that reads the sandbox, and the sandbox with
    // it.
    let delayed = attachments.map(fcx, move |fcx, sandbox| -> Box<dyn fictionet::Interface> {
        match sandbox.name() {
            SERVER => Box::new(fictionet::stdlib::network::delay(
                &fcx.group("real server"),
                ms(1),
                sandbox,
            )),
            SCANNER => {
                let group = fcx.group("scanner");
                let tap = tap.clone();
                Box::new(fictionet::stdlib::network::delay(
                    &group,
                    ms(2),
                    fictionet::stdlib::network::filter(
                        &group,
                        sandbox,
                        move |fcx, direction, packet| tap.tap(fcx, direction, packet),
                    ),
                ))
            }
            _ => Box::new(sandbox),
        }
    });
    net.start(fcx, delayed)?;
    Ok(ports)
}

/// Runs the default office for the socket executable.
pub async fn world(fcx: Cx, attachments: Attachments) -> Result {
    start(&fcx, office(), attachments)?;
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
                .body(httpd::Body::from(body))
                .expect("valid page headers"),
        )
    }
}

struct Greeting(Kind);

impl Service for Greeting {
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
            Kind::Smtp => {
                let greeting = smtp::Reply::new(220, "mail.corp.test ESMTP Postfix (Debian/GNU)");
                greeting.write(out).expect("valid SMTP greeting");
            }
            Kind::Pop3 => {
                let greeting = pop3::Reply::ok("Dovecot ready.");
                greeting.write(out).expect("valid POP3 greeting");
            }
            Kind::Imap => {
                let greeting = imap::Response::Status {
                    tag: None,
                    status: imap::Status::Ok,
                    code: Some("CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+ STARTTLS AUTH=PLAIN".into()),
                    text: "Dovecot ready.".into(),
                };
                greeting.write(out).expect("valid IMAP greeting");
            }
            Kind::Ftp => {
                let greeting = ftp::Reply::new(ftp::ReplyCode::new(220).unwrap(), "(vsFTPd 3.0.3)");
                greeting.write(out).expect("valid FTP greeting");
            }
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
    use super::*;
    #[test]
    fn ssh_identification_is_followed_by_kexinit_and_disconnect() {
        use fictionet::stdlib::{codec::Wire, protocols::ssh, services::serve::Harness};
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
    fn lease_matches_the_office() {
        assert_eq!(SERVER_LEASE.addr.addr, SERVER_ADDR);
        assert_eq!(
            SERVER_LEASE.dns.map(std::net::IpAddr::V4),
            SCANNER_SUBNET.nth(1)
        );
        assert_eq!(
            SERVER_LEASE.gateway.map(std::net::IpAddr::V4),
            OFFICE.nth(1)
        );
        assert_eq!(SERVER_LEASE.addr.prefix, OFFICE.len);
    }
}
