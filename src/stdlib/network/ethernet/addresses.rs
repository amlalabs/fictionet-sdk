//! How a [`Link`](super::Link) hands a VM addresses it was given: a DHCP
//! server for IPv4, and router advertisements plus a DHCPv6 server for
//! IPv6.
//!
//! These are small servers for one client on one link. Each has one fixed
//! lease, so there is no lease table: a VM that asks again, after a reboot
//! or with a new client ID, gets the same answer.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::network::route::Prefix;
use fictionet::stdlib::protocols::dhcp::{self, opt};
use fictionet::stdlib::protocols::dhcpv6::{
    self, DhcpOption, Duid, IaAddr, IaNa, Message, StatusCode, msg, status,
};

use super::frame;

/// An address with its prefix length, such as `10.0.0.2/24`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cidr<A> {
    /// The address.
    pub addr: A,
    /// The prefix length.
    pub prefix: u8,
}

/// How a [`Link`](super::Link) gives a VM one address family (IPv4 or
/// IPv6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Family<A> {
    /// The link answers the VM's DHCP (and, for IPv6, router
    /// solicitations) itself with this lease, and passes only packets from
    /// its address.
    Serve(Lease<A>),
    /// The VM's DHCP goes to the world like any other packet, and the
    /// world decides which source addresses it takes.
    FromWorld,
    /// The link gives no address and drops the VM's DHCP. A static address
    /// set inside the VM still works.
    Off,
}

/// What a link hands out by DHCP for one family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lease<A> {
    /// The VM's address and its subnet.
    pub addr: Cidr<A>,
    /// The default gateway, if there is one.
    pub gateway: Option<A>,
    /// The DNS server, if there is one.
    pub dns: Option<A>,
}

/// How long a lease lasts, in seconds, for both families. The VM renews
/// it halfway through, and the link answers the renewal with the same lease.
const LEASE_SECS: u32 = 86_400;

/// How often a link that hands out IPv6 addresses sends a router
/// advertisement without being asked. It is well inside the advertised
/// router lifetime of 30 minutes.
pub const RA_EVERY: Duration = Duration::from_secs(600);

// DHCP for IPv4

/// The address the link answers DHCP from, which the VM sends its renewals
/// to. It is the gateway when there is one. Otherwise it is the DNS
/// server, or else the subnet's first address that is not the VM's.
/// The link answers ARP for any address, so this address only has to be
/// stable.
pub(super) fn server_id(lease: &Lease<Ipv4Addr>) -> Option<Ipv4Addr> {
    if let Some(gw) = lease.gateway.or(lease.dns) {
        return Some(gw);
    }
    let prefix = Prefix {
        addr: lease.addr.addr.into(),
        len: lease.addr.prefix,
    };
    let first = prefix.nth(1)?;
    let pick = if first == IpAddr::V4(lease.addr.addr) {
        2
    } else {
        1
    };
    let IpAddr::V4(server) = prefix.nth(pick)? else {
        unreachable!("an IPv4 lease has an IPv4 DHCP server")
    };
    Some(server)
}

/// The answer to one DHCP message from the VM, as an IPv4 packet, and
/// whether it goes to the broadcast MAC. `None` when no answer is due: a
/// release, a decline, a request meant for another server, or a message
/// that is not a request.
pub(super) fn dhcp4(lease: &Lease<Ipv4Addr>, mtu: u16, request: &[u8]) -> Option<(Vec<u8>, bool)> {
    let m = dhcp::Message::parse(request).ok()?;
    if m.op != dhcp::BOOTREQUEST || m.htype != 1 || m.hlen != 6 {
        return None;
    }
    let server = server_id(lease)?;
    let addr = lease.addr.addr;
    let reply = match m.message_type()? {
        dhcp::DISCOVER => dhcp::Reply::Offer(addr),
        dhcp::REQUEST => {
            if m.option_addr(opt::SERVER_ID).is_some_and(|s| s != server) {
                // The VM chose another server's offer.
                return None;
            }
            let wanted = m.option_addr(opt::REQUESTED_IP).unwrap_or(m.ciaddr);
            if wanted == addr {
                dhcp::Reply::Ack(addr)
            } else {
                dhcp::Reply::Nak
            }
        }
        dhcp::INFORM => dhcp::Reply::Inform,
        _ => return None,
    };
    let (r, to) = dhcp::ReplyConfig {
        server,
        lease_secs: LEASE_SECS,
        subnet_mask: mask4(lease.addr.prefix),
        router: lease.gateway,
        dns: lease.dns,
        mtu: Some(mtu),
    }
    .build(&m, reply);
    Some((
        frame::udp4(
            server,
            dhcp::SERVER_PORT,
            to,
            dhcp::CLIENT_PORT,
            &r.to_bytes().ok()?,
        ),
        reply == dhcp::Reply::Nak || m.ciaddr.is_unspecified(),
    ))
}

/// The netmask of an IPv4 prefix length, 0 to 32.
fn mask4(prefix: u8) -> Ipv4Addr {
    let IpAddr::V4(mask) = (Prefix {
        addr: Ipv4Addr::UNSPECIFIED.into(),
        len: prefix,
    })
    .mask() else {
        unreachable!("an IPv4 prefix has an IPv4 mask")
    };
    mask
}

// Router advertisements

/// A router advertisement for the VM's link, as an IPv6 packet from
/// the link's link-local address to all nodes. It says:
///
/// - addresses come from DHCPv6 (the "managed" and "other" flags), so the
///   VM takes the one address the link hands out, not one of its own making;
/// - the lease's subnet is on the link, so the VM reaches the rest of
///   that subnet directly;
/// - the link is the default router, if the lease has a gateway;
/// - the MTU, and the lease's DNS server, if there is one.
pub(super) fn router_advert(lease: &Lease<Ipv6Addr>, mtu: u16) -> Vec<u8> {
    let lifetime: u16 = if lease.gateway.is_some() { 1800 } else { 0 };
    let mut b = vec![frame::ROUTER_ADVERTISEMENT, 0, 0, 0, 64, 0xc0];
    b.extend_from_slice(&lifetime.to_be_bytes());
    b.extend_from_slice(&[0; 8]);
    // Source link-layer address.
    b.extend_from_slice(&[1, 1]);
    b.extend_from_slice(&frame::GATEWAY_MAC);
    // MTU.
    b.extend_from_slice(&[5, 1, 0, 0]);
    b.extend_from_slice(&(mtu as u32).to_be_bytes());
    // Prefix information: on-link, but not for making addresses.
    let prefix = lease.addr.prefix;
    let IpAddr::V6(net) = (Prefix {
        addr: lease.addr.addr.into(),
        len: prefix,
    })
    .network() else {
        unreachable!("an IPv6 lease has an IPv6 network address")
    };
    b.extend_from_slice(&[3, 4, prefix, 0x80]);
    b.extend_from_slice(&u32::MAX.to_be_bytes());
    b.extend_from_slice(&u32::MAX.to_be_bytes());
    b.extend_from_slice(&[0; 4]);
    b.extend_from_slice(&net.octets());
    if let Some(dns) = lease.dns {
        // Recursive DNS server (RFC 8106).
        b.extend_from_slice(&[25, 3, 0, 0]);
        b.extend_from_slice(&u32::MAX.to_be_bytes());
        b.extend_from_slice(&dns.octets());
    }
    frame::icmp6(frame::link_local(frame::GATEWAY_MAC), ALL_NODES, b)
}

const ALL_NODES: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);

// DHCPv6

/// The link's DHCPv6 server ID: a DUID made from its MAC (DUID-LL).
fn server_duid() -> Duid {
    Duid::ll(dhcpv6::hardware::ETHERNET, &frame::GATEWAY_MAC)
}

/// The answer to one DHCPv6 message from the VM, as the UDP payload.
/// `None` when no answer is due: a malformed message, one for another server,
/// one missing a required client ID, or a type a server does not answer. Returns
/// `None` if the answer exceeds `budget` bytes or an option or UDP length limit.
/// Unicast is never enabled: forbidden message types are dropped, and the
/// others get UseMulticast.
pub(super) fn dhcp6(
    lease: &Lease<Ipv6Addr>,
    budget: usize,
    request: &[u8],
    multicast: bool,
) -> Option<Vec<u8>> {
    let request = Message::parse(request).ok()?;
    let kind = request.msg_type;
    if request.client_id().is_none() && kind != msg::INFORMATION_REQUEST {
        return None;
    }
    let server = server_duid();
    let server_ok = match kind {
        msg::SOLICIT | msg::CONFIRM | msg::REBIND => request.server_id().is_none(),
        msg::REQUEST | msg::RENEW | msg::RELEASE | msg::DECLINE => {
            request.server_id() == Some(&server)
        }
        msg::INFORMATION_REQUEST => request.server_id().is_none_or(|s| *s == server),
        _ => false,
    };
    if !server_ok {
        return None;
    }
    if kind == msg::INFORMATION_REQUEST
        && request.options.iter().any(|o| {
            matches!(
                o,
                DhcpOption::IaNa(_) | DhcpOption::IaTa(_) | DhcpOption::IaPd(_)
            )
        })
    {
        return None;
    }
    if !multicast
        && matches!(
            kind,
            msg::SOLICIT | msg::CONFIRM | msg::REBIND | msg::INFORMATION_REQUEST
        )
    {
        return None;
    }
    let rapid = kind == msg::SOLICIT && request.options.contains(&DhcpOption::RapidCommit);
    let reply = if kind == msg::SOLICIT && !rapid {
        msg::ADVERTISE
    } else {
        msg::REPLY
    };
    let mut out = Message::new(reply, request.transaction);
    if let Some(client) = request.client_id() {
        out.options.push(DhcpOption::ClientId(client.clone()));
    }
    out.options.push(DhcpOption::ServerId(server));
    if !multicast {
        out.options.push(status_option(status::USE_MULTICAST));
    } else if kind == msg::CONFIRM {
        out.options.push(status_option(confirm(lease, &request)?));
    } else if matches!(kind, msg::RELEASE | msg::DECLINE) {
        out.options.push(status_option(status::SUCCESS));
    } else {
        if rapid {
            out.options.push(DhcpOption::RapidCommit);
        }
        // Any other address the VM still holds, from a lease it kept across a
        // restore or a change of flags, comes back with lifetimes of 0 in a
        // Request, Renew or Rebind, so the VM drops it (RFC 8415, section
        // 18.3.4). The link passes packets only from the address it hands out.
        let retire = matches!(kind, msg::REQUEST | msg::RENEW | msg::REBIND);
        let subnet = Prefix {
            addr: lease.addr.addr.into(),
            len: lease.addr.prefix,
        };
        let address = |address, secs| {
            DhcpOption::IaAddr(IaAddr {
                address,
                preferred: secs,
                valid: secs,
                options: Vec::new(),
            })
        };
        for (i, ia) in request.ia_na().enumerate() {
            // The first IA_NA the VM asked for gets the address.
            let first = i == 0;
            let mut na = IaNa {
                iaid: ia.iaid,
                ..IaNa::default()
            };
            if kind == msg::REQUEST && ia.addresses().any(|a| !subnet.contains(a.address.into())) {
                na.options.push(status_option(status::NOT_ON_LINK));
                out.options.push(DhcpOption::IaNa(na));
                continue;
            }
            if first {
                na.t1 = LEASE_SECS / 2;
                na.t2 = LEASE_SECS / 5 * 4;
                na.options.push(address(lease.addr.addr, LEASE_SECS));
            }
            if retire {
                for stale in ia.addresses().filter(|a| a.address != lease.addr.addr) {
                    na.options.push(address(stale.address, 0));
                }
            }
            if !first {
                na.options.push(status_option(status::NO_ADDRS_AVAIL));
            }
            out.options.push(DhcpOption::IaNa(na));
        }
        for option in &request.options {
            match option {
                DhcpOption::IaTa(ia) => out.options.push(DhcpOption::IaTa(dhcpv6::IaTa {
                    iaid: ia.iaid,
                    options: vec![status_option(status::NO_ADDRS_AVAIL)],
                })),
                DhcpOption::IaPd(ia) => out.options.push(DhcpOption::IaPd(dhcpv6::IaPd {
                    iaid: ia.iaid,
                    options: vec![status_option(status::NO_PREFIX_AVAIL)],
                    ..Default::default()
                })),
                _ => {}
            }
        }
        if let Some(dns) = lease.dns {
            out.options.push(DhcpOption::DnsServers(vec![dns]));
        }
    }
    // The codec enforces option and UDP lengths. The link's budget also
    // leaves room for the IPv6 and UDP headers within the MTU.
    let bytes = out.to_bytes().ok()?;
    (bytes.len() <= budget).then_some(bytes)
}

fn status_option(code: u16) -> DhcpOption {
    DhcpOption::StatusCode(StatusCode {
        code,
        message: String::new(),
    })
}

/// The answer to a Confirm: is the VM's address still right for this link?
/// Success if every address in its IA_NAs is the lease's,
/// NotOnLink if one is not, and no answer if it names no address (RFC
/// 8415, section 18.3.3). The link passes packets only from that one
/// address, so an address it did not hand out is not usable on this link,
/// even inside the prefix. NotOnLink sends the VM back to Solicit, which
/// gets it the right one.
fn confirm(lease: &Lease<Ipv6Addr>, request: &Message) -> Option<u16> {
    let mut addrs = request.ia_na().flat_map(IaNa::addresses).peekable();
    addrs.peek()?;
    Some(if addrs.all(|a| a.address == lease.addr.addr) {
        status::SUCCESS
    } else {
        status::NOT_ON_LINK
    })
}

#[cfg(test)]
pub(super) mod tests {
    use super::frame::tests::{VM, v6_checksum_ok};
    use super::*;

    fn dhcp6(lease: &Lease<Ipv6Addr>, budget: usize, request: &[u8]) -> Option<Vec<u8>> {
        super::dhcp6(lease, budget, request, true)
    }

    pub(crate) fn lease4() -> Lease<Ipv4Addr> {
        Lease {
            addr: Cidr {
                addr: Ipv4Addr::new(10, 0, 0, 2),
                prefix: 24,
            },
            gateway: Some(Ipv4Addr::new(10, 0, 0, 1)),
            dns: Some(Ipv4Addr::new(10, 0, 0, 1)),
        }
    }

    pub(crate) fn client(kind: u8) -> dhcp::Message {
        let mut m = dhcp::Message::new(dhcp::BOOTREQUEST, 0x1234_5678);
        m.chaddr[..6].copy_from_slice(&VM);
        m.push(opt::MESSAGE_TYPE, [kind]);
        m
    }

    #[test]
    fn dhcp6_request_for_an_off_link_address_gets_not_on_link() {
        let request = request6(
            msg::REQUEST,
            vec![DhcpOption::IaNa(ia_with(
                7,
                &["2001:db8::2".parse().unwrap()],
            ))],
        );
        let reply = reply6(&request);
        let ia = reply.ia_na().next().unwrap();
        assert_eq!(ia.iaid, 7);
        assert_eq!(
            ia.options,
            vec![DhcpOption::StatusCode(StatusCode {
                code: status::NOT_ON_LINK,
                message: String::new()
            })]
        );
    }

    #[test]
    fn every_requested_identity_association_gets_an_outcome() {
        let request = request6(
            msg::SOLICIT,
            vec![
                DhcpOption::IaNa(ia_with(7, &[])),
                DhcpOption::IaNa(ia_with(8, &[])),
                DhcpOption::IaTa(dhcpv6::IaTa {
                    iaid: 8,
                    ..Default::default()
                }),
                DhcpOption::IaPd(dhcpv6::IaPd {
                    iaid: 9,
                    ..Default::default()
                }),
            ],
        );
        let reply = reply6(&request);
        let nas: Vec<_> = reply.ia_na().collect();
        assert_eq!(nas.len(), 2);
        assert_eq!(
            nas[0].addresses().next().unwrap().address,
            lease6().addr.addr
        );
        assert_eq!(nas[1].iaid, 8);
        assert_eq!(
            nas[1].options,
            vec![DhcpOption::StatusCode(StatusCode {
                code: status::NO_ADDRS_AVAIL,
                message: String::new(),
            })]
        );
        assert_eq!(
            reply.option(dhcpv6::opt::IA_TA),
            Some(&DhcpOption::IaTa(dhcpv6::IaTa {
                iaid: 8,
                options: vec![DhcpOption::StatusCode(StatusCode {
                    code: status::NO_ADDRS_AVAIL,
                    message: String::new()
                })],
            }))
        );
        assert_eq!(
            reply.option(dhcpv6::opt::IA_PD),
            Some(&DhcpOption::IaPd(dhcpv6::IaPd {
                iaid: 9,
                options: vec![DhcpOption::StatusCode(StatusCode {
                    code: status::NO_PREFIX_AVAIL,
                    message: String::new()
                })],
                ..Default::default()
            }))
        );
    }

    #[test]
    fn information_requests_with_identity_associations_are_discarded() {
        for option in [
            DhcpOption::IaNa(IaNa::default()),
            DhcpOption::IaTa(dhcpv6::IaTa::default()),
            DhcpOption::IaPd(dhcpv6::IaPd::default()),
        ] {
            let request = request6(msg::INFORMATION_REQUEST, vec![option]);
            assert!(dhcp6(&lease6(), 1452, &request.to_bytes().unwrap()).is_none());
        }
    }

    #[test]
    fn dhcp4_reply_bytes() {
        for (kind, ciaddr, wanted, reply_kind, assigned) in [
            (dhcp::DISCOVER, [0; 4], None, 2, [10, 0, 0, 2]),
            (dhcp::REQUEST, [0; 4], Some([10, 0, 0, 2]), 5, [10, 0, 0, 2]),
            (dhcp::REQUEST, [10, 0, 0, 2], None, 5, [10, 0, 0, 2]),
            (dhcp::INFORM, [10, 0, 0, 2], None, 5, [0; 4]),
            (dhcp::REQUEST, [10, 0, 0, 2], Some([10, 0, 0, 9]), 6, [0; 4]),
            (dhcp::REQUEST, [0; 4], Some([10, 0, 0, 9]), 6, [0; 4]),
        ] {
            for (flags, relay, mtu) in [
                (0, [0; 4], 1500u16),
                (0x8000, [10, 0, 0, 254], 1500),
                (0, [0; 4], 9000),
            ] {
                for server in [None, Some([10, 0, 0, 1])] {
                    let mut request = client(kind);
                    request.flags = flags;
                    request.ciaddr = ciaddr.into();
                    request.giaddr = relay.into();
                    if let Some(server) = server {
                        request.push(opt::SERVER_ID, server);
                    }
                    if let Some(wanted) = wanted {
                        request.push(opt::REQUESTED_IP, wanted);
                    }
                    let (packet, broadcast) =
                        dhcp4(&lease4(), mtu, &request.to_bytes().unwrap()).unwrap();
                    let expected_broadcast = ciaddr == [0; 4] || reply_kind == 6;
                    assert_eq!(broadcast, expected_broadcast);
                    assert_eq!(
                        &packet[16..20],
                        if expected_broadcast {
                            &[255; 4]
                        } else {
                            &ciaddr
                        }
                    );
                    let mut expected = vec![0; 240];
                    expected[..12]
                        .copy_from_slice(&[2, 1, 6, 0, 0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0]);
                    expected[10..12].copy_from_slice(&flags.to_be_bytes());
                    if kind == dhcp::INFORM {
                        expected[12..16].copy_from_slice(&ciaddr);
                    }
                    expected[16..20].copy_from_slice(&assigned);
                    expected[24..28].copy_from_slice(&relay);
                    expected[28..34].copy_from_slice(&VM);
                    expected[236..240].copy_from_slice(&[99, 130, 83, 99]);
                    expected.extend_from_slice(&[53, 1, reply_kind, 54, 4, 10, 0, 0, 1]);
                    if reply_kind != 6 {
                        if kind != dhcp::INFORM {
                            expected.extend_from_slice(&[
                                51, 4, 0, 1, 81, 128, 58, 4, 0, 0, 168, 192, 59, 4, 0, 1, 39, 80,
                            ]);
                        }
                        expected.extend_from_slice(&[
                            1, 4, 255, 255, 255, 0, 3, 4, 10, 0, 0, 1, 6, 4, 10, 0, 0, 1, 26, 2,
                        ]);
                        expected.extend_from_slice(&mtu.to_be_bytes());
                    }
                    expected.push(255);
                    expected.resize(300, 0);
                    let (port, payload) = frame::udp_to(&packet).unwrap();
                    assert_eq!(port, dhcp::CLIENT_PORT);
                    assert_eq!(&packet[12..16], &[10, 0, 0, 1]);
                    assert_eq!(payload, expected, "{kind}");
                }
            }
        }
    }

    #[test]
    fn dhcp4_leaves_other_servers_and_bad_messages_alone() {
        let mut other = client(dhcp::REQUEST);
        other.push(opt::REQUESTED_IP, [10, 0, 0, 2]);
        other.push(opt::SERVER_ID, [10, 0, 0, 254]);
        assert!(dhcp4(&lease4(), 1500, &other.to_bytes().unwrap()).is_none());
        for kind in [dhcp::RELEASE, dhcp::DECLINE, dhcp::OFFER] {
            assert!(
                dhcp4(&lease4(), 1500, &client(kind).to_bytes().unwrap()).is_none(),
                "{kind}"
            );
        }
        let mut reply = client(dhcp::DISCOVER);
        reply.op = dhcp::BOOTREPLY;
        assert!(dhcp4(&lease4(), 1500, &reply.to_bytes().unwrap()).is_none());
        assert!(dhcp4(&lease4(), 1500, &[0; 100]).is_none());
        assert!(
            dhcp4(
                &lease4(),
                1500,
                &client(dhcp::DISCOVER).to_bytes().unwrap()[..239]
            )
            .is_none()
        );
    }

    #[test]
    fn dhcp4_without_gateway_or_dns() {
        let bare = Lease {
            gateway: None,
            dns: None,
            ..lease4()
        };
        assert_eq!(server_id(&bare), Some(Ipv4Addr::new(10, 0, 0, 1)));
        let (offer, _) = dhcp4(&bare, 1500, &client(dhcp::DISCOVER).to_bytes().unwrap()).unwrap();
        let (_, payload) = frame::udp_to(&offer).unwrap();
        let m = dhcp::Message::parse(payload).unwrap();
        assert_eq!(m.option(opt::ROUTER), None);
        assert_eq!(m.option(opt::DNS), None);
        let at_first = Lease {
            addr: Cidr {
                addr: Ipv4Addr::new(10, 0, 0, 1),
                prefix: 24,
            },
            ..bare
        };
        assert_eq!(server_id(&at_first), Some(Ipv4Addr::new(10, 0, 0, 2)));
    }

    #[test]
    fn netmasks() {
        assert_eq!(mask4(0), Ipv4Addr::UNSPECIFIED);
        assert_eq!(mask4(24), Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(mask4(32), Ipv4Addr::BROADCAST);
    }

    pub(crate) fn lease6() -> Lease<Ipv6Addr> {
        Lease {
            addr: Cidr {
                addr: "fd00::2".parse().unwrap(),
                prefix: 64,
            },
            gateway: Some("fd00::1".parse().unwrap()),
            dns: Some("fd00::53".parse().unwrap()),
        }
    }

    #[test]
    fn router_advert_says_managed_on_link_and_dns() {
        let p = router_advert(&lease6(), 1500);
        assert!(v6_checksum_ok(&p));
        assert_eq!(p[7], 255);
        assert_eq!(frame::source_v6(&p), frame::link_local(frame::GATEWAY_MAC));
        assert_eq!(&p[24..40], &ALL_NODES.octets());
        let ra = &p[40..];
        assert_eq!(ra[0], frame::ROUTER_ADVERTISEMENT);
        assert_eq!(ra[5], 0xc0, "managed and other");
        assert_eq!(u16::from_be_bytes([ra[6], ra[7]]), 1800);
        let opts = &ra[16..];
        assert_eq!(&opts[0..8], &[1, 1, 0x02, 0x66, 0x6e, 0, 0, 1]);
        assert_eq!(&opts[8..16], &[5, 1, 0, 0, 0, 0, 5, 220]);
        assert_eq!(
            &opts[16..20],
            &[3, 4, 64, 0x80],
            "on-link, no autoconfiguration"
        );
        assert_eq!(
            &opts[32..48],
            &"fd00::".parse::<Ipv6Addr>().unwrap().octets()
        );
        assert_eq!(&opts[48..52], &[25, 3, 0, 0]);
        assert_eq!(
            &opts[56..72],
            &"fd00::53".parse::<Ipv6Addr>().unwrap().octets()
        );
        assert_eq!(opts.len(), 72);

        let p = router_advert(
            &Lease {
                gateway: None,
                dns: None,
                ..lease6()
            },
            1500,
        );
        assert_eq!(
            u16::from_be_bytes([p[46], p[47]]),
            0,
            "not a default router"
        );
        assert_eq!(p.len(), 40 + 16 + 48, "no DNS option");
    }

    pub(crate) fn request6(kind: u8, options: Vec<DhcpOption>) -> Message {
        let mut m = Message::new(kind, 0xabcdef);
        m.options.push(DhcpOption::ClientId(Duid(CLIENT.to_vec())));
        if matches!(
            kind,
            msg::REQUEST | msg::RENEW | msg::RELEASE | msg::DECLINE
        ) && !options.iter().any(|o| matches!(o, DhcpOption::ServerId(_)))
        {
            m.options.push(DhcpOption::ServerId(server_duid()));
        }
        m.options.extend(options);
        m
    }

    fn reply6(request: &Message) -> Message {
        Message::parse(&dhcp6(&lease6(), 1500 - 48, &request.to_bytes().unwrap()).unwrap()).unwrap()
    }

    // Raw options let malformed requests bypass the codec's writer.
    fn msg6(kind: u8, options: &[(u16, &[u8])]) -> Vec<u8> {
        let mut m = vec![kind, 0xab, 0xcd, 0xef];
        for (code, value) in options {
            m.extend_from_slice(&code.to_be_bytes());
            m.extend_from_slice(&u16::try_from(value.len()).unwrap().to_be_bytes());
            m.extend_from_slice(value);
        }
        m
    }

    const CLIENT: &[u8] = &[0, 3, 0, 1, 0x52, 0x54, 0, 0x12, 0x34, 0x56];

    pub(crate) fn ia_with(iaid: u32, addresses: &[Ipv6Addr]) -> IaNa {
        IaNa {
            iaid,
            options: addresses
                .iter()
                .map(|address| {
                    DhcpOption::IaAddr(IaAddr {
                        address: *address,
                        preferred: 0,
                        valid: 0,
                        options: vec![],
                    })
                })
                .collect(),
            ..IaNa::default()
        }
    }

    #[test]
    fn dhcp6_all_reply_types_obey_the_budget() {
        for kind in [
            msg::SOLICIT,
            msg::REQUEST,
            msg::CONFIRM,
            msg::RENEW,
            msg::REBIND,
            msg::RELEASE,
            msg::DECLINE,
            msg::INFORMATION_REQUEST,
        ] {
            for rapid in [false, true] {
                let mut request = request6(
                    kind,
                    vec![DhcpOption::IaNa(ia_with(7, &["fd00::77".parse().unwrap()]))],
                );
                if rapid {
                    request.options.push(DhcpOption::RapidCommit);
                }
                if kind == msg::INFORMATION_REQUEST {
                    request
                        .options
                        .retain(|o| !matches!(o, DhcpOption::IaNa(_)));
                }
                let request = request.to_bytes().unwrap();
                let reply = dhcp6(&lease6(), 1500 - 48, &request).unwrap();
                for budget in 0..reply.len() {
                    assert!(
                        dhcp6(&lease6(), budget, &request).is_none(),
                        "{kind}: {budget}"
                    );
                }
                assert_eq!(dhcp6(&lease6(), reply.len(), &request), Some(reply));
            }
        }
    }

    #[test]
    fn dhcp6_replies_fit_the_udp_length() {
        let ia = ia_with(7, &vec!["fd00::77".parse().unwrap(); 2336]);
        let request = |len| {
            let mut m = Message::new(msg::REBIND, 1);
            m.options = vec![
                DhcpOption::ClientId(Duid(vec![7; len])),
                DhcpOption::IaNa(ia.clone()),
            ];
            m.to_bytes().unwrap()
        };
        let reply = dhcp6(&lease6(), usize::MAX, &request(33)).unwrap();
        assert_eq!(reply.len() + 8, u16::MAX as usize);
        assert!(Message::parse(&reply).is_ok());
        assert!(dhcp6(&lease6(), usize::MAX, &request(34)).is_none());
    }

    #[test]
    fn dhcp6_solicit_advertise_request_reply() {
        let solicit = request6(msg::SOLICIT, vec![DhcpOption::IaNa(ia_with(7, &[]))]);
        let adv = reply6(&solicit);
        assert_eq!(adv.msg_type, msg::ADVERTISE);
        assert_eq!(adv.transaction, 0xabcdef);
        assert_eq!(adv.client_id(), Some(&Duid(CLIENT.to_vec())));
        assert_eq!(adv.server_id(), Some(&server_duid()));
        assert_eq!(server_duid().0, [0, 3, 0, 1, 0x02, 0x66, 0x6e, 0, 0, 1]);
        assert_eq!(
            adv.option(dhcpv6::opt::DNS_SERVERS),
            Some(&DhcpOption::DnsServers(vec![lease6().dns.unwrap()]))
        );
        let na = adv.ia_na().next().unwrap();
        assert_eq!(na.iaid, 7, "the client's IAID");
        assert_eq!((na.t1, na.t2), (LEASE_SECS / 2, LEASE_SECS / 5 * 4));
        let address = na.addresses().next().unwrap();
        assert_eq!(address.address, lease6().addr.addr);
        assert_eq!((address.preferred, address.valid), (LEASE_SECS, LEASE_SECS));

        let reply = reply6(&request6(
            msg::REQUEST,
            vec![DhcpOption::IaNa(ia_with(7, &[]))],
        ));
        assert_eq!(reply.msg_type, msg::REPLY);
        assert_eq!(reply.ia_na().next(), Some(na));

        // Rapid commit: the solicit gets a reply at once.
        let mut rapid = solicit;
        rapid.options.push(DhcpOption::RapidCommit);
        let rapid = reply6(&rapid);
        assert_eq!(rapid.msg_type, msg::REPLY);
        assert!(rapid.options.contains(&DhcpOption::RapidCommit));
        assert_eq!(rapid.ia_na().next(), Some(na));
    }

    #[test]
    fn dhcp6_rejects_bad_messages_and_answers_without_leases() {
        let missing = Message::new(msg::SOLICIT, 1);
        assert!(
            dhcp6(&lease6(), 1500 - 48, &missing.to_bytes().unwrap()).is_none(),
            "no client ID"
        );
        let m = request6(msg::ADVERTISE, vec![]);
        assert!(dhcp6(&lease6(), 1500 - 48, &m.to_bytes().unwrap()).is_none());
        let mut cut = request6(msg::SOLICIT, vec![]).to_bytes().unwrap();
        cut.pop();
        assert!(
            dhcp6(&lease6(), 1500 - 48, &cut).is_none(),
            "an option past the end"
        );
        assert!(dhcp6(&lease6(), 1500 - 48, &[1, 2]).is_none());
        // Release and Decline get a plain success, and no address or DNS.
        for kind in [msg::RELEASE, msg::DECLINE] {
            let r = reply6(&request6(kind, vec![DhcpOption::IaNa(ia_with(7, &[]))]));
            assert_eq!(r.status().unwrap().code, status::SUCCESS);
            assert_eq!(r.ia_na().count(), 0);
            assert!(r.option(dhcpv6::opt::DNS_SERVERS).is_none());
        }
        // Information-request needs no client ID.
        let r = reply6(&Message::new(msg::INFORMATION_REQUEST, 1));
        assert!(r.client_id().is_none());
        assert!(r.option(dhcpv6::opt::DNS_SERVERS).is_some());
        assert_eq!(r.ia_na().count(), 0);
    }

    #[test]
    fn dhcp6_confirm_checks_the_address() {
        for (addresses, status) in [
            (vec![lease6().addr.addr], status::SUCCESS),
            (vec!["2001:db8:99::2".parse().unwrap()], status::NOT_ON_LINK),
            (vec!["fd00::77".parse().unwrap()], status::NOT_ON_LINK),
            (
                vec![lease6().addr.addr, "fd00::77".parse().unwrap()],
                status::NOT_ON_LINK,
            ),
        ] {
            let r = reply6(&request6(
                msg::CONFIRM,
                vec![DhcpOption::IaNa(ia_with(7, &addresses))],
            ));
            assert_eq!(r.status().unwrap().code, status);
            assert_eq!(r.ia_na().count(), 0);
            assert!(r.option(dhcpv6::opt::DNS_SERVERS).is_none());
        }
        let empty = request6(msg::CONFIRM, vec![DhcpOption::IaNa(ia_with(7, &[]))]);
        assert!(dhcp6(&lease6(), 1500 - 48, &empty.to_bytes().unwrap()).is_none());
    }

    #[test]
    fn dhcp6_renew_and_rebind_retire_an_address_the_link_did_not_hand_out() {
        for kind in [msg::RENEW, msg::REBIND, msg::REQUEST] {
            let r = reply6(&request6(
                kind,
                vec![DhcpOption::IaNa(ia_with(7, &["fd00::77".parse().unwrap()]))],
            ));
            let addrs: Vec<_> = r
                .ia_na()
                .next()
                .unwrap()
                .addresses()
                .map(|a| (a.address, a.preferred, a.valid))
                .collect();
            assert_eq!(
                addrs,
                vec![
                    (lease6().addr.addr, LEASE_SECS, LEASE_SECS),
                    ("fd00::77".parse().unwrap(), 0, 0),
                ],
                "{kind}"
            );
        }
        // Every stale address, in every IA_NA, however many.
        let many: Vec<Ipv6Addr> = (3..15)
            .map(|i| Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, i))
            .collect();
        let options = vec![
            DhcpOption::IaNa(ia_with(7, &many)),
            DhcpOption::IaNa(ia_with(8, &["fd00::99".parse().unwrap()])),
        ];
        let r = reply6(&request6(msg::RENEW, options.clone()));
        let nas: Vec<_> = r.ia_na().collect();
        assert_eq!(nas.len(), 2);
        assert_eq!(nas[0].addresses().count(), 1 + 12);
        assert_eq!((nas[1].iaid, nas[1].t1, nas[1].t2), (8, 0, 0));
        assert_eq!(nas[1].addresses().count(), 1);
        let other = nas[1].addresses().next().unwrap();
        assert_eq!(other.address, "fd00::99".parse::<Ipv6Addr>().unwrap());
        assert_eq!((other.preferred, other.valid), (0, 0));
        // A Solicit names no stale address and allocates only the first IA.
        let s = reply6(&request6(msg::SOLICIT, options));
        assert_eq!(s.ia_na().count(), 2);
        assert_eq!(s.ia_na().next().unwrap().addresses().count(), 1);
        // The address the link hands out is not named twice, even across IAs.
        let r = reply6(&request6(
            msg::RENEW,
            vec![
                DhcpOption::IaNa(ia_with(7, &[lease6().addr.addr])),
                DhcpOption::IaNa(ia_with(8, &[lease6().addr.addr])),
            ],
        ));
        assert_eq!(r.ia_na().count(), 2);
        assert_eq!(r.ia_na().next().unwrap().addresses().count(), 1);
        let second = r.ia_na().nth(1).unwrap();
        assert_eq!(second.addresses().count(), 0);
        assert_eq!(
            second.options,
            vec![DhcpOption::StatusCode(StatusCode {
                code: status::NO_ADDRS_AVAIL,
                message: String::new(),
            })]
        );
    }

    #[test]
    fn dhcp6_validates_every_duid_length() {
        use dhcpv6::opt;
        for len in [0, 1, 2, dhcpv6::MAX_DUID + 1] {
            for code in [opt::CLIENTID, opt::SERVERID] {
                // A later duplicate must be validated too.
                let request = msg6(
                    msg::REQUEST,
                    &[
                        (opt::CLIENTID, CLIENT),
                        (opt::SERVERID, &server_duid().0),
                        (code, &vec![7; len]),
                    ],
                );
                assert!(
                    dhcp6(&lease6(), 1500 - 48, &request).is_none(),
                    "{code}: {len}"
                );
            }
            let request = msg6(msg::SOLICIT, &[(opt::CLIENTID, &vec![7; len])]);
            assert!(dhcp6(&lease6(), 1500 - 48, &request).is_none());
        }
        for len in [dhcpv6::MIN_DUID, dhcpv6::MAX_DUID] {
            let client = vec![7; len];
            let request = msg6(msg::SOLICIT, &[(opt::CLIENTID, &client)]);
            let r = dhcp6(&lease6(), 1500 - 48, &request).unwrap();
            assert_eq!(Message::parse(&r).unwrap().client_id(), Some(&Duid(client)));
        }
    }

    #[test]
    fn dhcp6_rejects_requests_above_the_codec_limit() {
        let request = |len| msg6(msg::INFORMATION_REQUEST, &[(65000, &vec![0; len - 8])]);
        assert!(dhcp6(&lease6(), 1500 - 48, &request(dhcpv6::MAX_MESSAGE)).is_some());
        let oversized = request(dhcpv6::MAX_MESSAGE + 1);
        assert!(dhcp6(&lease6(), 1500 - 48, &oversized).is_none());
    }

    #[test]
    fn dhcp6_rejects_malformed_options_before_answering() {
        use dhcpv6::opt;
        let mut prefix = vec![0; 25];
        prefix[8] = 129;
        let bad = [
            (opt::IA_NA, vec![0; 11]),
            (opt::IA_TA, vec![0; 3]),
            (opt::IAADDR, vec![0; 23]),
            (opt::IA_PD, vec![0; 11]),
            (opt::IAPREFIX, prefix),
            (opt::ORO, vec![0]),
            (opt::PREFERENCE, vec![]),
            (opt::ELAPSED_TIME, vec![0]),
            (opt::AUTH, vec![0; 10]),
            (opt::UNICAST, vec![0; 15]),
            (opt::STATUS_CODE, vec![0]),
            (opt::STATUS_CODE, vec![0, 0, 0xff]),
            (opt::STATUS_CODE, vec![0, 0, b'x', 0]),
            (opt::RAPID_COMMIT, vec![0]),
            (opt::USER_CLASS, vec![]),
            (opt::USER_CLASS, vec![0, 2, 1]),
            (opt::VENDOR_CLASS, vec![0; 4]),
            (opt::VENDOR_OPTS, vec![0; 5]),
            (opt::RECONF_MSG, vec![]),
            (opt::RECONF_ACCEPT, vec![0]),
            (opt::DNS_SERVERS, vec![]),
            (opt::DNS_SERVERS, vec![0; 15]),
            (opt::DOMAIN_LIST, vec![2, b'x']),
            (opt::INFORMATION_REFRESH_TIME, vec![0; 3]),
            (opt::SOL_MAX_RT, vec![0; 3]),
            (opt::INF_MAX_RT, vec![0; 3]),
        ];
        for (code, body) in bad {
            for kind in [
                msg::SOLICIT,
                msg::REQUEST,
                msg::RENEW,
                msg::REBIND,
                msg::CONFIRM,
                msg::RELEASE,
                msg::DECLINE,
                msg::INFORMATION_REQUEST,
            ] {
                let options = if kind == msg::INFORMATION_REQUEST {
                    vec![]
                } else {
                    vec![DhcpOption::IaNa(ia_with(7, &[lease6().addr.addr]))]
                };
                let mut request = request6(kind, options).to_bytes().unwrap();
                assert!(dhcp6(&lease6(), 1500 - 48, &request).is_some());
                request.extend_from_slice(&msg6(kind, &[(code, &body)])[4..]);
                assert!(
                    dhcp6(&lease6(), 1500 - 48, &request).is_none(),
                    "{kind}: {code}"
                );
            }
        }
    }

    #[test]
    fn dhcp6_rejects_nested_errors_before_confirm_or_lease_policy() {
        use dhcpv6::opt;
        // Even after an off-link address, malformed nested options must
        // suppress Confirm's NotOnLink and Renew's replacement lease.
        for kind in [msg::CONFIRM, msg::RENEW] {
            for tail in [vec![0], vec![0, 5, 0, 1, 0], vec![0, 5, 0, 2, 0]] {
                let valid = request6(
                    kind,
                    vec![DhcpOption::IaNa(ia_with(7, &["fd00::77".parse().unwrap()]))],
                )
                .to_bytes()
                .unwrap();
                let mut ia = vec![0; 12];
                ia.extend_from_slice(&tail);
                let mut request = valid.clone();
                request.extend_from_slice(&msg6(kind, &[(opt::IA_NA, &ia)])[4..]);
                assert!(dhcp6(&lease6(), 1500 - 48, &request).is_none());
                assert!(dhcp6(&lease6(), 1500 - 48, &valid).is_some());
            }
        }
        // A malformed option followed by a truncated header gets no answer.
        let mut request = msg6(msg::SOLICIT, &[(opt::CLIENTID, &[])]);
        request.push(0);
        assert!(dhcp6(&lease6(), 1500 - 48, &request).is_none());
        // IAADDR's own nested options are validated too.
        let mut ia = vec![0; 12];
        ia.extend_from_slice(&msg6(msg::SOLICIT, &[(opt::IAADDR, &[0; 25])])[4..]);
        let request = msg6(msg::SOLICIT, &[(opt::CLIENTID, CLIENT), (opt::IA_NA, &ia)]);
        assert!(dhcp6(&lease6(), 1500 - 48, &request).is_none());
    }

    #[test]
    fn dhcp6_keeps_unknown_options_and_valid_duplicates_compatible() {
        use dhcpv6::opt;
        let request = msg6(
            msg::REQUEST,
            &[
                (opt::CLIENTID, CLIENT),
                (opt::CLIENTID, &[7; dhcpv6::MIN_DUID]),
                (opt::SERVERID, &server_duid().0),
                (opt::SERVERID, &[7; dhcpv6::MIN_DUID]),
                (65000, &[0xff]),
                // Unusual DNS label bytes stay opaque under the shared codec.
                (opt::DOMAIN_LIST, &[1, b'.', 0]),
            ],
        );
        let reply = dhcp6(&lease6(), 1500 - 48, &request).unwrap();
        let reply = Message::parse(&reply).unwrap();
        assert_eq!(reply.client_id(), Some(&Duid(CLIENT.to_vec())));
        assert_eq!(reply.server_id(), Some(&server_duid()));
        assert!(reply.option(65000).is_none());
    }
}
