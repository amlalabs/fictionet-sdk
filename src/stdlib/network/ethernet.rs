//! Ethernet lowering: a virtual machine's network card, carried as IP
//! packets.
//!
//! A VM sends and takes Ethernet frames. A world speaks IP packets. A
//! [`Link`] stands between them on the VM's side: it reads each frame from
//! the VM, answers the link-local questions itself (ARP and IPv6 neighbor
//! discovery, and DHCP when it was given addresses to hand out), passes the
//! IP packets on, and puts an Ethernet header on each packet for the VM.
//! It does no I/O: whatever carries the frames, such as
//! `fictionet attach tap` or an embedded VM, reads and writes them
//! and calls the link. [`stream`] splits the length-prefixed frame stream
//! that QEMU, libkrun and passt use.
//!
//! Every frame comes from the VM, which the agent runs, so every frame is
//! read as hostile input.

pub mod frame;
pub mod stream;

mod addresses;

use std::net::{Ipv4Addr, Ipv6Addr};

use fictionet::stdlib::protocols::{dhcp, dhcpv6};

pub use addresses::{Cidr, Family, Lease, RA_EVERY};
use frame::{Frame, Mac, Upper};

/// The VM's side of the link: what to do with each frame from the VM, and
/// how to frame each packet from the world. It does no I/O.
pub struct Link {
    v4: Family<Ipv4Addr>,
    v6: Family<Ipv6Addr>,
    mtu: u16,
    /// The VM's MAC, learned from its first frame.
    vm: Option<Mac>,
}

/// What to do with one frame from the VM.
#[derive(Debug, PartialEq, Eq)]
pub enum FromVm<'a> {
    /// Send this IP packet to the world.
    World(&'a [u8]),
    /// Send this frame back to the VM: an answer the link gives itself.
    Answer(Vec<u8>),
    /// Drop the frame.
    Drop(Why),
}

/// Why a frame from the VM was dropped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Why {
    /// Short headers, inconsistent lengths, an IP header the stack silently
    /// discards, or an unreadable UDP or ICMPv6 transport.
    Malformed,
    /// Longer than the MTU allows.
    TooBig,
    /// From a MAC other than the VM's first one.
    OtherSource,
    /// To a unicast MAC other than the link's own.
    NotForUs,
    /// Neither ARP, IPv4 nor IPv6 (VLAN tags and LLDP, for example).
    OtherType,
    /// A link-local message the link handled, or chose not to answer.
    Handled,
    /// An IP packet from a source other than the address the link handed
    /// out.
    Spoofed,
}

impl<A: Copy> Family<A> {
    fn address(&self) -> Option<A> {
        match self {
            Family::Serve(lease) => Some(lease.addr.addr),
            _ => None,
        }
    }

    /// What to do with a DHCP request or router solicitation: answered
    /// by `answer` when the link serves this family, passed to the world
    /// when the world sets it up, and dropped when it is off.
    fn handle<'a>(
        &self,
        packet: &'a [u8],
        answer: impl FnOnce(&Lease<A>) -> Option<Vec<u8>>,
    ) -> FromVm<'a> {
        match self {
            Family::Serve(lease) => {
                answer(lease).map_or(FromVm::Drop(Why::Handled), FromVm::Answer)
            }
            Family::FromWorld => FromVm::World(packet),
            Family::Off => FromVm::Drop(Why::Handled),
        }
    }
}

impl Link {
    /// A link that hands out IPv4 and IPv6 addresses as `v4` and `v6`
    /// say, for a VM whose largest IP packet is `mtu` bytes.
    ///
    /// Returns an error if a lease has an invalid prefix or the IPv4 lease
    /// has no room for a DHCP server address.
    pub fn new(
        v4: Family<Ipv4Addr>,
        v6: Family<Ipv6Addr>,
        mtu: u16,
    ) -> Result<Link, fictionet::Error> {
        if let Family::Serve(lease) = &v4 {
            if lease.addr.prefix > 32 {
                return Err(fictionet::Error::msg("the IPv4 prefix must be at most 32"));
            }
            if addresses::server_id(lease).is_none() {
                return Err(fictionet::Error::msg(
                    "the IPv4 lease needs a gateway, DNS server, or room for a DHCP server",
                ));
            }
        }
        if let Family::Serve(lease) = &v6
            && lease.addr.prefix > 128
        {
            return Err(fictionet::Error::msg("the IPv6 prefix must be at most 128"));
        }
        Ok(Link {
            v4,
            v6,
            mtu,
            vm: None,
        })
    }

    /// The VM's MAC, once its first frame has arrived.
    pub fn vm_mac(&self) -> Option<Mac> {
        self.vm
    }

    /// Decides what to do with one frame from the VM.
    pub fn frame_from_vm<'a>(&mut self, frame: &'a [u8]) -> FromVm<'a> {
        let Some(f) = Frame::parse(frame) else {
            return FromVm::Drop(Why::Malformed);
        };
        if frame.len() > frame::HEADER + self.mtu as usize {
            return FromVm::Drop(Why::TooBig);
        }
        if frame::is_group(&f.src) || f.src == [0; 6] {
            return FromVm::Drop(Why::OtherSource);
        }
        match self.vm {
            None => self.vm = Some(f.src),
            Some(vm) if vm != f.src => return FromVm::Drop(Why::OtherSource),
            Some(_) => {}
        }
        if !frame::is_group(&f.dst) && f.dst != frame::GATEWAY_MAC {
            return FromVm::Drop(Why::NotForUs);
        }
        match f.ethertype {
            frame::ARP => match frame::arp_reply(f.payload, f.src, self.v4.address()) {
                Some(reply) => FromVm::Answer(reply),
                None => FromVm::Drop(Why::Handled),
            },
            frame::IPV4 => match frame::ip_packet(frame::IPV4, f.payload) {
                Some(p) => self.ipv4(p, f.src),
                None => FromVm::Drop(Why::Malformed),
            },
            frame::IPV6 => match frame::ip_packet(frame::IPV6, f.payload) {
                Some(p) => self.ipv6(p, f.src),
                None => FromVm::Drop(Why::Malformed),
            },
            _ => FromVm::Drop(Why::OtherType),
        }
    }

    fn ipv4<'a>(&self, p: &'a [u8], vm: Mac) -> FromVm<'a> {
        let Ok(upper) = frame::upper(p) else {
            return FromVm::Drop(Why::Malformed);
        };
        match upper {
            Upper::Udp {
                port: dhcp::SERVER_PORT,
                payload: request,
            } => {
                return self.v4.handle(p, |lease| {
                    let (packet, broadcast) = addresses::dhcp4(lease, self.mtu, request)?;
                    let to = if broadcast { frame::BROADCAST } else { vm };
                    Some(frame::frame(to, frame::GATEWAY_MAC, frame::IPV4, &packet))
                });
            }
            // The link does not put fragments back together, so it answers no
            // fragmented DHCP request, and lets none past when it owns DHCP.
            // The rest of the request cannot be put together in the world
            // without this first fragment.
            Upper::UdpFragment {
                port: dhcp::SERVER_PORT,
            } if self.v4 != Family::FromWorld => {
                return FromVm::Drop(Why::Handled);
            }
            _ => {}
        }
        // Packets from 0.0.0.0, such as a multicast report sent before the
        // VM has an address, stay on the link: they cannot be answered.
        let src = frame::source_v4(p);
        if src.is_unspecified() && self.v4 != Family::FromWorld {
            return FromVm::Drop(Why::Handled);
        }
        match self.v4.address() {
            Some(own) if src != own => FromVm::Drop(Why::Spoofed),
            _ => FromVm::World(p),
        }
    }

    fn ipv6<'a>(&self, p: &'a [u8], vm: Mac) -> FromVm<'a> {
        let Ok(upper) = frame::upper(p) else {
            return FromVm::Drop(Why::Malformed);
        };
        match upper {
            // The world answers a packet like this with Parameter Problem,
            // so it goes on like any other, unless it hides neighbor
            // discovery, which stays on the link.
            Upper::Problem if frame::problem_hides_neighbor_discovery(p) => {
                return FromVm::Drop(Why::Handled);
            }
            // Neighbor discovery is never fragmented (RFC 6980), and only
            // makes sense on the link.
            Upper::Icmp6 {
                kind,
                fragment: true,
                ..
            } if frame::is_neighbor_discovery(kind) => {
                return FromVm::Drop(Why::Handled);
            }
            Upper::Icmp6 {
                kind: frame::NEIGHBOR_SOLICITATION,
                msg,
                ..
            } => {
                return match frame::neighbor_advert(p, msg, vm, self.v6.address()) {
                    Some(reply) => FromVm::Answer(reply),
                    None => FromVm::Drop(Why::Handled),
                };
            }
            Upper::Icmp6 {
                kind: frame::ROUTER_SOLICITATION,
                msg,
                ..
            } => {
                if !frame::solicitation_valid(p, msg, 8) {
                    return FromVm::Drop(Why::Handled);
                }
                return self.v6.handle(p, |_| self.router_advert());
            }
            // Advertisements and redirects only make sense on the link.
            Upper::Icmp6 { kind, .. } if frame::is_neighbor_discovery(kind) => {
                return FromVm::Drop(Why::Handled);
            }
            Upper::Udp {
                port: dhcpv6::SERVER_PORT,
                payload: request,
            } => {
                return self.v6.handle(p, |lease| {
                    let answer = addresses::dhcp6(
                        lease,
                        // Leave room for the IPv6 and UDP headers.
                        usize::from(self.mtu).saturating_sub(40 + 8),
                        request,
                        frame::destination_v6(p).is_multicast(),
                    )?;
                    let packet = frame::udp6(
                        frame::link_local(frame::GATEWAY_MAC),
                        dhcpv6::SERVER_PORT,
                        frame::source_v6(p),
                        dhcpv6::CLIENT_PORT,
                        &answer,
                    );
                    Some(frame::frame(vm, frame::GATEWAY_MAC, frame::IPV6, &packet))
                });
            }
            // As for DHCP over IPv4: no answer to a fragment, and none past
            // when the link owns DHCPv6.
            Upper::UdpFragment {
                port: dhcpv6::SERVER_PORT,
            } if self.v6 != Family::FromWorld => {
                return FromVm::Drop(Why::Handled);
            }
            _ => {}
        }
        // Link-scope traffic, such as multicast listener reports, stays on
        // the link, unless the world was left to set up IPv6.
        let src = frame::source_v6(p);
        if self.v6 != Family::FromWorld && (src.is_unspecified() || src.is_unicast_link_local()) {
            return FromVm::Drop(Why::Handled);
        }
        match self.v6.address() {
            Some(own) if src != own => FromVm::Drop(Why::Spoofed),
            _ => FromVm::World(p),
        }
    }

    /// Whether the link hands out IPv6 addresses, and so sends router
    /// advertisements. Cheap, unlike building one with
    /// [`router_advert`](Link::router_advert).
    pub fn advertises(&self) -> bool {
        matches!(self.v6, Family::Serve(_))
    }

    /// A router advertisement frame, when the link hands out IPv6 addresses.
    pub fn router_advert(&self) -> Option<Vec<u8>> {
        let Family::Serve(lease) = &self.v6 else {
            return None;
        };
        let ra = addresses::router_advert(lease, self.mtu);
        let (dst, _) = frame::destination(&ra, self.vm, None)?;
        Some(frame::frame(dst, frame::GATEWAY_MAC, frame::IPV6, &ra))
    }

    /// The Ethernet header for a packet from the world, or `None` to drop
    /// it: it is not IPv4 or IPv6, is longer than the MTU, or is unicast
    /// before the VM's MAC is known.
    pub fn to_vm(&self, packet: &[u8]) -> Option<[u8; frame::HEADER]> {
        if packet.len() > self.mtu as usize {
            return None;
        }
        let subnet = match &self.v4 {
            Family::Serve(lease) => Some((lease.addr.addr, lease.addr.prefix)),
            _ => None,
        };
        let (dst, ethertype) = frame::destination(packet, self.vm, subnet)?;
        Some(frame::header(dst, frame::GATEWAY_MAC, ethertype))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use addresses::tests::{client, ia_with, lease4, lease6, request6};
    use dhcpv6::{DhcpOption, Duid, Message, msg, status};
    use fictionet::stdlib::codec::Wire;
    use frame::tests::{
        VM, arp_request, behind_options, fragment6, fragments4, fragments6, router_solicit,
        solicitation,
    };

    fn served() -> Link {
        Link::new(
            Family::Serve(lease4()),
            Family::Serve(Lease {
                dns: None,
                ..lease6()
            }),
            1500,
        )
        .unwrap()
    }

    fn eth(src: Mac, dst: Mac, ethertype: u16, payload: &[u8]) -> Vec<u8> {
        frame::frame(dst, src, ethertype, payload)
    }

    fn discover() -> Vec<u8> {
        let mut m = client(dhcp::DISCOVER);
        m.xid = 7;
        let p = frame::udp4(
            Ipv4Addr::UNSPECIFIED,
            68,
            Ipv4Addr::BROADCAST,
            67,
            &m.to_bytes().unwrap(),
        );
        eth(VM, frame::BROADCAST, frame::IPV4, &p)
    }

    #[test]
    fn dhcp6_server_identifier_and_destination_rules() {
        let server_id = Duid::ll(1, &frame::GATEWAY_MAC);
        for (kind, servers, directed) in [
            (msg::SOLICIT, [true, false, false], false),
            (msg::CONFIRM, [true, false, false], false),
            (msg::REBIND, [true, false, false], false),
            (msg::INFORMATION_REQUEST, [true, true, false], false),
            (msg::REQUEST, [false, true, false], true),
            (msg::RENEW, [false, true, false], true),
            (msg::RELEASE, [false, true, false], true),
            (msg::DECLINE, [false, true, false], true),
        ] {
            for (server, server_ok) in [None, Some(server_id.clone()), Some(Duid::ll(1, &[1; 6]))]
                .into_iter()
                .zip(servers)
            {
                let mut request = request6(
                    kind,
                    if kind == msg::INFORMATION_REQUEST {
                        vec![]
                    } else {
                        vec![DhcpOption::IaNa(ia_with(7, &["fd00::2".parse().unwrap()]))]
                    },
                );
                request
                    .options
                    .retain(|o| !matches!(o, DhcpOption::ServerId(_)));
                if let Some(id) = &server {
                    request.options.push(DhcpOption::ServerId(id.clone()));
                }
                for multicast in [true, false] {
                    let dst = if multicast {
                        "ff02::1:2".parse().unwrap()
                    } else {
                        frame::link_local(frame::GATEWAY_MAC)
                    };
                    let packet = frame::udp6(
                        frame::link_local(VM),
                        546,
                        dst,
                        547,
                        &request.to_bytes().unwrap(),
                    );
                    let f = eth(VM, frame::GATEWAY_MAC, frame::IPV6, &packet);
                    let result = served().frame_from_vm(&f);
                    if server_ok && (multicast || directed) {
                        let FromVm::Answer(answer) = result else {
                            panic!("no reply: {kind}, {server:?}, {multicast}")
                        };
                        if !multicast {
                            let f = Frame::parse(&answer).unwrap();
                            let (_, data) = frame::udp_to(f.payload).unwrap();
                            let reply = Message::parse(data).unwrap();
                            assert_eq!(reply.msg_type, msg::REPLY);
                            assert_eq!(reply.status().unwrap().code, status::USE_MULTICAST);
                            assert_eq!(reply.ia_na().count(), 0);
                        }
                    } else {
                        assert_eq!(
                            result,
                            FromVm::Drop(Why::Handled),
                            "{kind}: {server:?}, {multicast}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn router_advertisement_prefix_fits_an_ipv6_address() {
        for prefix in [0, 64, 128, 129, 200, 255] {
            let lease = Lease {
                addr: Cidr {
                    addr: "fd00::2".parse().unwrap(),
                    prefix,
                },
                gateway: None,
                dns: None,
            };
            let link = Link::new(Family::Off, Family::Serve(lease), 1500);
            if prefix > 128 {
                assert!(link.is_err());
            } else {
                let ra = link.unwrap().router_advert().unwrap();
                assert_eq!(ra[frame::HEADER + 40 + 16 + 16 + 2], prefix);
            }
        }
    }

    #[test]
    fn bare_narrow_lease_is_rejected_before_frames_arrive() {
        for prefix in [31, 32, 40] {
            assert!(
                Link::new(
                    Family::Serve(Lease {
                        addr: Cidr {
                            addr: Ipv4Addr::new(10, 0, 0, 1),
                            prefix
                        },
                        gateway: None,
                        dns: None,
                    }),
                    Family::Off,
                    1500
                )
                .is_err(),
                "/{prefix}"
            );
        }
        for prefix in [0, 30, 31, 32] {
            let mut link = Link::new(
                Family::Serve(Lease {
                    addr: Cidr {
                        addr: Ipv4Addr::new(10, 0, 0, 2),
                        prefix,
                    },
                    gateway: Some(Ipv4Addr::new(10, 0, 0, 1)),
                    dns: None,
                }),
                Family::Off,
                1500,
            )
            .unwrap();
            assert!(matches!(link.frame_from_vm(&discover()), FromVm::Answer(_)));
        }
    }

    #[test]
    fn invalid_solicitations_get_no_answer() {
        let ll = frame::link_local(VM);
        for (src, hop, body) in [
            (ll, 64, vec![133, 0, 0, 0, 0, 0, 0, 0]),
            (ll, 255, vec![133, 1, 0, 0, 0, 0, 0, 0]),
            (ll, 255, vec![133, 0, 0, 0]),
            (ll, 255, vec![133, 0, 0, 0, 0, 0, 0, 0, 99, 0]),
            (ll, 255, vec![133, 0, 0, 0, 0, 0, 0, 0, 99, 2, 0]),
            (
                Ipv6Addr::UNSPECIFIED,
                255,
                vec![133, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0],
            ),
        ] {
            let p = frame::ipv6(src, "ff02::2".parse().unwrap(), 58, hop, &body);
            assert_eq!(
                served().frame_from_vm(&eth(VM, frame::GATEWAY_MAC, frame::IPV6, &p)),
                FromVm::Drop(Why::Handled),
                "{hop}: {body:?}"
            );
        }
        for (src, target, hop, own) in [
            (ll, ll, 255, None),
            (Ipv6Addr::UNSPECIFIED, "fd00::2".parse().unwrap(), 255, None),
            (ll, "fd00::1".parse().unwrap(), 64, None),
            (ll, "ff02::1".parse().unwrap(), 255, None),
            (
                ll,
                "fd00::1".parse().unwrap(),
                255,
                Some("fd00::1".parse().unwrap()),
            ),
        ] {
            let v6 = own.map_or(Family::Off, |addr| {
                Family::Serve(Lease {
                    addr: Cidr { addr, prefix: 64 },
                    ..lease6()
                })
            });
            let mut link = Link::new(Family::Off, v6, 1500).unwrap();
            let p = solicitation(src, target, hop);
            assert_eq!(
                link.frame_from_vm(&eth(VM, frame::GATEWAY_MAC, frame::IPV6, &p)),
                FromVm::Drop(Why::Handled)
            );
        }
        let short = solicitation(ll, "fd00::1".parse().unwrap(), 255);
        assert_eq!(
            served().frame_from_vm(&eth(VM, frame::GATEWAY_MAC, frame::IPV6, &short[..60])),
            FromVm::Drop(Why::Malformed)
        );
        for options in [&[1, 0][..], &[1, 2, 0][..], &[1][..]] {
            let p = solicitation(ll, "fd00::1".parse().unwrap(), 255);
            let body = [&p[40..64], options].concat();
            let p = frame::icmp6(ll, "ff02::1".parse().unwrap(), body);
            assert_eq!(
                served().frame_from_vm(&eth(VM, frame::GATEWAY_MAC, frame::IPV6, &p)),
                FromVm::Drop(Why::Handled)
            );
        }
        for src in [ll, Ipv6Addr::UNSPECIFIED] {
            let p = frame::ipv6(
                src,
                "ff02::2".parse().unwrap(),
                58,
                255,
                &[133, 0, 0x12, 0x34, 1, 2, 3, 4, 99, 1, 0, 0, 0, 0, 0, 0],
            );
            assert!(matches!(
                served().frame_from_vm(&eth(VM, frame::GATEWAY_MAC, frame::IPV6, &p)),
                FromVm::Answer(_)
            ));
        }
    }

    #[test]
    fn parameter_problems_reach_the_world_after_source_checks() {
        use fictionet::stdlib::network::ip::{self, Header, Reject};
        for (next, body) in [
            (0, vec![6, 0, 0x80, 0, 0, 0, 0, 0]),
            (43, vec![6, 0, 99, 1, 0, 0, 0, 0]),
            (44, vec![6, 0, 0, 1, 0, 0, 0, 1]),
            (44, vec![60, 0, 0, 1, 0, 0, 0, 1, 6, 1, 0, 0, 0, 0, 0, 0]),
        ] {
            for (src, expected) in [
                ("fd00::2", None),
                ("fd00::77", Some(Why::Spoofed)),
                ("fe80::1", Some(Why::Handled)),
                ("::", Some(Why::Handled)),
            ] {
                let p = frame::ipv6(
                    src.parse().unwrap(),
                    "fd00::1".parse().unwrap(),
                    next,
                    64,
                    &body,
                );
                let reject = Header::check(&p).unwrap_err();
                assert!(matches!(reject, Reject::Problem { .. }));
                if expected.is_none() {
                    assert!(ip::parameter_problem(&p, reject).is_some());
                }
                let f = eth(VM, frame::GATEWAY_MAC, frame::IPV6, &p);
                assert_eq!(
                    served().frame_from_vm(&f),
                    expected.map_or(FromVm::World(&p), FromVm::Drop)
                );
                let mut world = Link::new(Family::Off, Family::FromWorld, 1500).unwrap();
                assert_eq!(world.frame_from_vm(&f), FromVm::World(&p));
                let mut off = Link::new(Family::Off, Family::Off, 1500).unwrap();
                assert_eq!(
                    off.frame_from_vm(&f),
                    if expected == Some(Why::Handled) {
                        FromVm::Drop(Why::Handled)
                    } else {
                        FromVm::World(&p)
                    }
                );
            }
        }
        for v6 in [served().v6, Family::FromWorld, Family::Off] {
            let mut link = Link::new(Family::Off, v6, 1500).unwrap();
            for kind in 133..=137 {
                let body = [
                    vec![58, 0, 0x80, 0, 0, 0, 0, 0],
                    vec![kind, 0, 0, 0, 0, 0, 0, 0],
                ]
                .concat();
                let p = frame::ipv6(
                    "fd00::2".parse().unwrap(),
                    "fd00::1".parse().unwrap(),
                    0,
                    255,
                    &body,
                );
                assert_eq!(
                    link.frame_from_vm(&eth(VM, frame::GATEWAY_MAC, frame::IPV6, &p)),
                    FromVm::Drop(Why::Handled)
                );
            }
            for dst in ["fe80::1", "ff02::1"] {
                let p = frame::ipv6(
                    "fd00::2".parse().unwrap(),
                    dst.parse().unwrap(),
                    0,
                    255,
                    &[6, 0, 0x80, 0, 0, 0, 0, 0],
                );
                assert_eq!(
                    link.frame_from_vm(&eth(VM, frame::GATEWAY_MAC, frame::IPV6, &p)),
                    FromVm::World(&p)
                );
            }
        }
    }

    #[test]
    fn learns_the_vm_mac_and_drops_other_sources() {
        let mut link = served();
        let ping = frame::ipv4(
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(10, 0, 0, 1),
            1,
            &[8, 0, 0, 0],
        );
        let f = eth(VM, frame::GATEWAY_MAC, frame::IPV4, &ping);
        assert_eq!(
            link.frame_from_vm(&f),
            FromVm::World(&ping[..]),
            "padding trimmed"
        );
        assert_eq!(link.vm_mac(), Some(VM));
        let other = eth(
            [0x52, 0, 0, 0, 0, 9],
            frame::GATEWAY_MAC,
            frame::IPV4,
            &ping,
        );
        assert_eq!(link.frame_from_vm(&other), FromVm::Drop(Why::OtherSource));
        let group = eth(
            [0x01, 0, 0, 0, 0, 9],
            frame::GATEWAY_MAC,
            frame::IPV4,
            &ping,
        );
        assert_eq!(
            Link::new(Family::Off, Family::Off, 1500)
                .unwrap()
                .frame_from_vm(&group),
            FromVm::Drop(Why::OtherSource)
        );
        let elsewhere = eth(VM, [0x52, 0, 0, 0, 0, 1], frame::IPV4, &ping);
        assert_eq!(link.frame_from_vm(&elsewhere), FromVm::Drop(Why::NotForUs));
        assert_eq!(
            link.frame_from_vm(&eth(VM, frame::GATEWAY_MAC, 0x8100, &ping)),
            FromVm::Drop(Why::OtherType)
        );
        assert_eq!(link.frame_from_vm(&f[..13]), FromVm::Drop(Why::Malformed));
        let mut lying = ping.clone();
        lying[2..4].copy_from_slice(&100u16.to_be_bytes());
        assert_eq!(
            link.frame_from_vm(&eth(VM, frame::GATEWAY_MAC, frame::IPV4, &lying)),
            FromVm::Drop(Why::Malformed)
        );
    }

    #[test]
    fn world_directed_broadcast_uses_the_served_subnet() {
        let mut link = served();
        link.frame_from_vm(&discover());
        for (dst, mac) in [
            ("10.0.0.255", frame::BROADCAST),
            ("10.0.1.255", VM),
            ("10.0.0.2", VM),
        ] {
            let p = frame::ipv4(Ipv4Addr::new(10, 0, 0, 1), dst.parse().unwrap(), 1, &[]);
            assert_eq!(link.to_vm(&p).unwrap()[..6], mac);
        }
        for prefix in [0, 30, 31, 32] {
            let Family::Serve(lease) = &mut link.v4 else {
                unreachable!()
            };
            lease.addr.prefix = prefix;
            let dst = if prefix == 0 {
                Ipv4Addr::BROADCAST
            } else {
                Ipv4Addr::new(10, 0, 0, if prefix == 32 { 2 } else { 3 })
            };
            let p = frame::ipv4(Ipv4Addr::new(10, 0, 0, 1), dst, 1, &[]);
            let mac = if prefix < 31 { frame::BROADCAST } else { VM };
            assert_eq!(link.to_vm(&p).unwrap()[..6], mac);
        }
        link.v4 = Family::FromWorld;
        let p = frame::ipv4(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 255),
            1,
            &[],
        );
        assert_eq!(link.to_vm(&p).unwrap()[..6], VM);
    }

    #[test]
    fn frames_over_the_mtu_are_dropped_both_ways() {
        let mut link = served();
        for size in [1500, 1501] {
            let packet = frame::udp4(
                Ipv4Addr::new(10, 0, 0, 2),
                1,
                Ipv4Addr::new(10, 0, 0, 1),
                2,
                &vec![0; size - 28],
            );
            assert_eq!(packet.len(), size);
            let expected = if size == 1500 {
                FromVm::World(&packet)
            } else {
                FromVm::Drop(Why::TooBig)
            };
            assert_eq!(
                link.frame_from_vm(&eth(VM, frame::GATEWAY_MAC, frame::IPV4, &packet)),
                expected
            );
            assert_eq!(link.to_vm(&packet).is_some(), size == 1500);
        }
        assert!(link.to_vm(&[0x10; 40]).is_none(), "not IP");
    }

    #[test]
    fn dhcp_is_answered_passed_or_dropped_by_the_flags() {
        let mut link = served();
        let FromVm::Answer(offer) = link.frame_from_vm(&discover()) else {
            panic!("no offer")
        };
        let f = Frame::parse(&offer).unwrap();
        assert_eq!((f.dst, f.src), (frame::BROADCAST, frame::GATEWAY_MAC));
        let (port, payload) = frame::udp_to(f.payload).unwrap();
        assert_eq!(port, 68);
        let m = dhcp::Message::parse(payload).unwrap();
        assert_eq!(m.yiaddr, Ipv4Addr::new(10, 0, 0, 2));

        let d = discover();
        let mut world = Link::new(Family::FromWorld, Family::Off, 1500).unwrap();
        assert!(matches!(world.frame_from_vm(&d), FromVm::World(_)));
        let mut off = Link::new(Family::Off, Family::Off, 1500).unwrap();
        assert_eq!(off.frame_from_vm(&d), FromVm::Drop(Why::Handled));
    }

    #[test]
    fn served_addresses_are_the_only_sources_passed() {
        let mut link = served();
        for (packet, ethertype) in [
            (
                frame::ipv4(
                    Ipv4Addr::new(10, 0, 0, 77),
                    Ipv4Addr::new(10, 0, 0, 1),
                    1,
                    &[],
                ),
                frame::IPV4,
            ),
            (
                frame::udp6(
                    "fd00::77".parse().unwrap(),
                    1,
                    "fd00::1".parse().unwrap(),
                    2,
                    &[],
                ),
                frame::IPV6,
            ),
        ] {
            let f = eth(VM, frame::GATEWAY_MAC, ethertype, &packet);
            assert_eq!(link.frame_from_vm(&f), FromVm::Drop(Why::Spoofed));
            let mut world = Link::new(Family::FromWorld, Family::FromWorld, 1500).unwrap();
            assert_eq!(world.frame_from_vm(&f), FromVm::World(&packet));
        }
        // A multicast listener report: a hop-by-hop header with a router
        // alert, then ICMPv6 type 143.
        let mld = frame::ipv6(
            frame::link_local(VM),
            "ff02::16".parse().unwrap(),
            0,
            1,
            &[frame::ICMPV6, 0, 5, 2, 0, 0, 1, 0, 143, 0, 0, 0, 0, 0, 0, 0],
        );
        assert_eq!(
            link.frame_from_vm(&eth(VM, [0x33, 0x33, 0, 0, 0, 0x16], frame::IPV6, &mld)),
            FromVm::Drop(Why::Handled)
        );
        let ok6 = frame::udp6(
            "fd00::2".parse().unwrap(),
            1,
            "fd00::1".parse().unwrap(),
            2,
            &[],
        );
        assert!(matches!(
            link.frame_from_vm(&eth(VM, frame::GATEWAY_MAC, frame::IPV6, &ok6)),
            FromVm::World(_)
        ));
    }

    #[test]
    fn neighbor_discovery_stays_on_the_link() {
        let mut link = served();
        let ll = frame::link_local(VM);
        let ns = solicitation(ll, "fd00::1".parse().unwrap(), 255);
        let FromVm::Answer(na) =
            link.frame_from_vm(&eth(VM, [0x33, 0x33, 0xff, 0, 0, 1], frame::IPV6, &ns))
        else {
            panic!("no advertisement")
        };
        let target = "fd00::1".parse::<Ipv6Addr>().unwrap();
        let f = Frame::parse(&na).unwrap();
        assert_eq!(
            (f.dst, f.src, f.ethertype),
            (VM, frame::GATEWAY_MAC, frame::IPV6)
        );
        let p = f.payload;
        assert!(frame::tests::v6_checksum_ok(p));
        assert_eq!(p[7], 255, "hop limit");
        assert_eq!(frame::source_v6(p), target);
        assert_eq!(&p[24..40], &ll.octets());
        assert_eq!(p[40], frame::NEIGHBOR_ADVERTISEMENT);
        assert_eq!(p[44], 0xe0, "router, solicited, override");
        assert_eq!(&p[48..64], &target.octets());
        assert_eq!(&p[64..72], &[2, 1, 0x74, 0x83, 0xc2, 0x9a, 0x47, 0xd1]);

        let rs = router_solicit(ll);
        let rs_frame = eth(VM, [0x33, 0x33, 0, 0, 0, 2], frame::IPV6, &rs);
        let FromVm::Answer(ra) = link.frame_from_vm(&rs_frame) else {
            panic!("no advertisement")
        };
        let f = Frame::parse(&ra).unwrap();
        assert_eq!(f.dst, [0x33, 0x33, 0, 0, 0, 1]);
        assert_eq!(f.payload[40], frame::ROUTER_ADVERTISEMENT);
        // Left to the world, the solicitation goes there; turned off, nowhere.
        let mut world = Link::new(Family::Off, Family::FromWorld, 1500).unwrap();
        assert!(matches!(world.frame_from_vm(&rs_frame), FromVm::World(_)));
        assert!(world.router_advert().is_none());
        assert!(!world.advertises());
        assert!(link.advertises());
        let mut off = Link::new(Family::Off, Family::Off, 1500).unwrap();
        assert_eq!(off.frame_from_vm(&rs_frame), FromVm::Drop(Why::Handled));
        // An advertisement from the VM never leaves the link.
        let ra_from_vm = addresses::router_advert(&addresses::tests::lease6(), 1500);
        assert_eq!(
            link.frame_from_vm(&eth(VM, [0x33, 0x33, 0, 0, 0, 1], frame::IPV6, &ra_from_vm)),
            FromVm::Drop(Why::Handled)
        );
        // Also behind a hop-by-hop header, with the world left to set up IPv6.
        let mut ext = vec![frame::ICMPV6, 0, 1, 4, 0, 0, 0, 0];
        ext.extend_from_slice(&ra_from_vm[40..]);
        let hidden = frame::ipv6(ll, "ff02::1".parse().unwrap(), 0, 255, &ext);
        let mut world = Link::new(Family::Off, Family::FromWorld, 1500).unwrap();
        assert_eq!(
            world.frame_from_vm(&eth(VM, [0x33, 0x33, 0, 0, 0, 1], frame::IPV6, &hidden)),
            FromVm::Drop(Why::Handled)
        );
    }

    #[test]
    fn dhcp6_solicit_answers_and_fragments() {
        let mut link = served();
        let mut solicit = request6(msg::SOLICIT, vec![DhcpOption::IaNa(ia_with(1, &[]))])
            .to_bytes()
            .unwrap();
        let p = frame::udp6(
            frame::link_local(VM),
            546,
            "ff02::1:2".parse().unwrap(),
            547,
            &solicit,
        );
        let FromVm::Answer(adv) =
            link.frame_from_vm(&eth(VM, [0x33, 0x33, 0, 1, 0, 2], frame::IPV6, &p))
        else {
            panic!("no advertise")
        };
        let f = Frame::parse(&adv).unwrap();
        assert_eq!(f.dst, VM);
        assert!(frame::tests::v6_checksum_ok(f.payload));
        assert_eq!(&f.payload[24..40], &frame::link_local(VM).octets());
        let (port, payload) = frame::udp_to(f.payload).unwrap();
        assert_eq!((port, payload[0]), (546, 2));
        let Family::Serve(lease) = &link.v6 else {
            unreachable!()
        };
        assert_eq!(
            payload,
            addresses::dhcp6(lease, 1452, &solicit, true).unwrap()
        );
        solicit.extend_from_slice(&[0; 80]);
        let whole = frame::udp6(
            frame::link_local(VM),
            546,
            "ff02::1:2".parse().unwrap(),
            547,
            &solicit,
        );
        let (first, _) = fragments6(&whole, 48);
        let to = [0x33, 0x33, 0, 1, 0, 2];
        assert_eq!(
            link.frame_from_vm(&eth(VM, to, frame::IPV6, &first)),
            FromVm::Drop(Why::Handled)
        );
        let mut off = Link::new(Family::Off, Family::Off, 1500).unwrap();
        assert_eq!(
            off.frame_from_vm(&eth(VM, to, frame::IPV6, &first)),
            FromVm::Drop(Why::Handled)
        );
        let mut world = Link::new(Family::Off, Family::FromWorld, 1500).unwrap();
        assert!(matches!(
            world.frame_from_vm(&eth(VM, to, frame::IPV6, &first)),
            FromVm::World(_)
        ));
        // A UDP length that does not fit the packet is not clamped to it.
        let mut lying = whole.clone();
        lying[44..46].copy_from_slice(&200u16.to_be_bytes());
        assert_eq!(
            link.frame_from_vm(&eth(VM, to, frame::IPV6, &lying)),
            FromVm::Drop(Why::Malformed)
        );
    }

    fn rebind(stale: usize, client_len: u16) -> Vec<u8> {
        let addresses: Vec<_> = (0..stale)
            .map(|i| Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 1, i as u16))
            .collect();
        let mut request = request6(msg::REBIND, vec![DhcpOption::IaNa(ia_with(1, &addresses))]);
        request.transaction = 1;
        let mut client = Duid::ll(1, &VM);
        client.0.resize(usize::from(client_len), 0);
        request.options[0] = DhcpOption::ClientId(client);
        let p = frame::udp6(
            frame::link_local(VM),
            546,
            "ff02::1:2".parse().unwrap(),
            547,
            &request.to_bytes().unwrap(),
        );
        eth(VM, [0x33, 0x33, 0, 1, 0, 2], frame::IPV6, &p)
    }

    #[test]
    fn dhcp6_replies_fit_the_mtu_exactly() {
        for (mtu, stale, client_len) in [(1280, 40, 26), (1500, 48, 22), (u16::MAX, 2335, 21)] {
            let mut link = served();
            link.mtu = mtu;
            let Family::Serve(lease) = &mut link.v6 else {
                unreachable!()
            };
            lease.dns = Some("fd00::53".parse().unwrap());
            let request = rebind(stale, client_len);
            assert!(request.len() < frame::HEADER + usize::from(mtu));
            let FromVm::Answer(reply) = link.frame_from_vm(&request) else {
                panic!("no reply at MTU {mtu}")
            };
            assert_eq!(reply.len(), frame::HEADER + usize::from(mtu));
            let f = Frame::parse(&reply).unwrap();
            assert_eq!(f.dst, VM);
            assert_eq!(f.src, frame::GATEWAY_MAC);
            assert_eq!(f.ethertype, frame::IPV6);
            assert_eq!(frame::ip_packet(frame::IPV6, f.payload), Some(f.payload));
            assert!(frame::tests::v6_checksum_ok(f.payload));
            let (port, payload) = frame::udp_to(f.payload).unwrap();
            assert_eq!(port, 546);
            assert_eq!(&payload[..4], &[7, 0, 0, 1]);
            let udp_len = u16::from_be_bytes([f.payload[44], f.payload[45]]) as usize;
            assert_eq!(udp_len, 8 + payload.len());
            assert_eq!(40 + udp_len, usize::from(mtu));

            // One more copied byte still fits on input but exceeds the reply MTU.
            let too_big = rebind(stale, client_len + 1);
            assert!(too_big.len() <= frame::HEADER + usize::from(mtu));
            assert_eq!(link.frame_from_vm(&too_big), FromVm::Drop(Why::Handled));
            assert!(matches!(link.frame_from_vm(&request), FromVm::Answer(_)));
            if mtu == u16::MAX {
                let request = rebind(2337, 10);
                assert_eq!(request.len(), frame::HEADER + 65_518);
                assert!(request.len() <= frame::HEADER + usize::from(link.mtu));
                assert_eq!(link.frame_from_vm(&request), FromVm::Drop(Why::Handled));
                assert!(matches!(
                    link.frame_from_vm(&rebind(0, 10)),
                    FromVm::Answer(_)
                ));
            }
        }
    }

    #[test]
    fn arp_answers_every_address_but_probes_gratuitous_and_its_own() {
        for (spa, tpa, own, answer) in [
            ([10, 0, 0, 2], [10, 0, 0, 1], false, true),
            ([10, 0, 0, 2], [10, 0, 0, 1], true, true),
            ([10, 0, 0, 2], [10, 0, 0, 77], false, true),
            ([0; 4], [10, 0, 0, 2], false, false),
            ([10, 0, 0, 2], [10, 0, 0, 2], false, false),
            ([10, 0, 0, 9], [10, 0, 0, 2], true, false),
        ] {
            let request = eth(VM, frame::BROADCAST, frame::ARP, &arp_request(spa, tpa));
            let v4 = if own {
                Family::Serve(lease4())
            } else {
                Family::Off
            };
            let result = Link::new(v4, Family::Off, 1500)
                .unwrap()
                .frame_from_vm(&request);
            if answer {
                let FromVm::Answer(reply) = result else {
                    panic!("no ARP reply")
                };
                let f = Frame::parse(&reply).unwrap();
                assert_eq!(
                    (f.dst, f.src, f.ethertype),
                    (VM, frame::GATEWAY_MAC, frame::ARP)
                );
                assert_eq!(&f.payload[6..8], &[0, 2]);
                assert_eq!(&f.payload[8..14], &frame::GATEWAY_MAC);
                assert_eq!(&f.payload[14..18], &tpa);
                assert_eq!(&f.payload[18..24], &VM);
                assert_eq!(&f.payload[24..28], &spa);
            } else {
                assert_eq!(result, FromVm::Drop(Why::Handled));
            }
        }
        for (offset, value, len) in [(7, 2, 28), (1, 6, 28), (7, 1, 27)] {
            let mut arp = arp_request([10, 0, 0, 2], [10, 0, 0, 1]);
            arp[offset] = value;
            // Keep the short request short instead of padding its Ethernet frame.
            let mut request = frame::header(frame::BROADCAST, VM, frame::ARP).to_vec();
            request.extend_from_slice(&arp[..len]);
            assert_eq!(served().frame_from_vm(&request), FromVm::Drop(Why::Handled));
        }
    }

    #[test]
    fn control_messages_behind_any_extension_headers_stay_on_the_link() {
        let ll = frame::link_local(VM);
        let all: Ipv6Addr = "ff02::1".parse().unwrap();
        let ra = addresses::router_advert(&addresses::tests::lease6(), 1500);
        let to_all = [0x33, 0x33, 0, 0, 0, 1];
        for v6 in [Family::FromWorld, Family::Off] {
            let mut link = Link::new(Family::Off, v6, 1500).unwrap();
            for n in [1, 8, 9, 30] {
                let p = behind_options(ll, all, n, frame::ICMPV6, &ra[40..]);
                assert_eq!(
                    link.frame_from_vm(&eth(VM, to_all, frame::IPV6, &p)),
                    FromVm::Drop(Why::Handled),
                    "{n}"
                );
            }
            // Behind an authentication header.
            let mut ah = vec![frame::ICMPV6, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            ah.extend_from_slice(&ra[40..]);
            let p = frame::ipv6(ll, all, 51, 255, &ah);
            assert_eq!(
                link.frame_from_vm(&eth(VM, to_all, frame::IPV6, &p)),
                FromVm::Drop(Why::Handled)
            );
            // A redirect in a first fragment.
            let redirect = frame::icmp6(
                ll,
                all,
                [vec![frame::REDIRECT, 0, 0, 0], vec![0; 36]].concat(),
            );
            let (first, _) = fragments6(&redirect, 8);
            assert_eq!(
                link.frame_from_vm(&eth(VM, to_all, frame::IPV6, &first)),
                FromVm::Drop(Why::Handled)
            );
            // A chain that cannot be read is dropped, not passed on.
            let cut = frame::ipv6(ll, all, 60, 255, &[frame::ICMPV6, 3, 0, 0, 0, 0, 0, 0]);
            assert_eq!(
                link.frame_from_vm(&eth(VM, to_all, frame::IPV6, &cut)),
                FromVm::Drop(Why::Malformed)
            );
        }
    }

    #[test]
    fn a_fragmented_neighbor_solicitation_is_not_answered() {
        let mut link = served();
        let ns = solicitation(frame::link_local(VM), "fd00::1".parse().unwrap(), 255);
        let (first, _) = fragments6(&ns, 24);
        assert_eq!(
            link.frame_from_vm(&eth(VM, [0x33, 0x33, 0xff, 0, 0, 1], frame::IPV6, &first)),
            FromVm::Drop(Why::Handled)
        );
        // An atomic fragment (offset 0, no more fragments) is not answered
        // either, and a router solicitation in one does not reach the world.
        let atomic = |p: &[u8]| fragment6(p, 0, false, &p[40..]);
        let to = [0x33, 0x33, 0xff, 0, 0, 1];
        assert_eq!(
            link.frame_from_vm(&eth(VM, to, frame::IPV6, &atomic(&ns))),
            FromVm::Drop(Why::Handled)
        );
        let ll = frame::link_local(VM);
        let rs = router_solicit(ll);
        let mut world = Link::new(Family::Off, Family::FromWorld, 1500).unwrap();
        let to = [0x33, 0x33, 0, 0, 0, 2];
        assert_eq!(
            world.frame_from_vm(&eth(VM, to, frame::IPV6, &atomic(&rs))),
            FromVm::Drop(Why::Handled)
        );
    }

    #[test]
    fn fragmented_dhcp_is_never_answered_and_passes_only_when_left_to_the_world() {
        // A DISCOVER from a static address, split in two.
        let mut m = client(dhcp::DISCOVER);
        m.xid = 7;
        let whole = frame::udp4(
            Ipv4Addr::new(10, 0, 0, 2),
            68,
            Ipv4Addr::BROADCAST,
            67,
            &m.to_bytes().unwrap(),
        );
        let (first, second) = fragments4(&whole, 64);
        let frame = |p: &[u8]| eth(VM, frame::BROADCAST, frame::IPV4, p);
        for v4 in [served().v4, Family::Off, Family::FromWorld] {
            let expected = if v4 == Family::FromWorld {
                FromVm::World(&first)
            } else {
                FromVm::Drop(Why::Handled)
            };
            let mut link = Link::new(v4, Family::Off, 1500).unwrap();
            assert_eq!(link.frame_from_vm(&frame(&first)), expected);
        }
        let mut off = Link::new(Family::Off, Family::Off, 1500).unwrap();
        assert_eq!(
            off.frame_from_vm(&frame(&whole)),
            FromVm::Drop(Why::Handled)
        );
        // Later fragments have no UDP header.
        assert_eq!(off.frame_from_vm(&frame(&second)), FromVm::World(&second));
        // A first fragment cut inside the UDP header cannot be read.
        let (stub, _) = fragments4(&whole, 0);
        assert_eq!(
            off.frame_from_vm(&frame(&stub)),
            FromVm::Drop(Why::Malformed)
        );
    }

    #[test]
    fn world_packets_get_the_vm_or_group_mac() {
        let mut link = served();
        let packets = [
            ("10.0.0.2", VM, frame::IPV4),
            ("255.255.255.255", frame::BROADCAST, frame::IPV4),
            ("239.129.2.3", [1, 0, 0x5e, 1, 2, 3], frame::IPV4),
            ("fd00::2", VM, frame::IPV6),
            (
                "ff02::1:ff12:3456",
                [0x33, 0x33, 0xff, 0x12, 0x34, 0x56],
                frame::IPV6,
            ),
        ]
        .map(|(dst, mac, ethertype)| {
            let packet = match ethertype {
                frame::IPV4 => {
                    frame::ipv4(Ipv4Addr::new(10, 0, 0, 1), dst.parse().unwrap(), 1, &[])
                }
                _ => frame::ipv6(
                    frame::link_local(frame::GATEWAY_MAC),
                    dst.parse().unwrap(),
                    6,
                    64,
                    &[],
                ),
            };
            (packet, mac, ethertype)
        });
        let ra = link.router_advert().unwrap();
        assert_eq!(ra[..6], [0x33, 0x33, 0, 0, 0, 1]);
        for v4 in [Family::Serve(lease4()), Family::FromWorld] {
            link.v4 = v4;
            link.vm = None;
            for learned in [false, true] {
                for (packet, mac, ethertype) in &packets {
                    let expected = (learned || *mac != VM)
                        .then(|| frame::header(*mac, frame::GATEWAY_MAC, *ethertype));
                    assert_eq!(link.to_vm(packet), expected);
                }
                for bad in [&[0x50; 40][..], &[0x45; 19], &[]] {
                    assert!(link.to_vm(bad).is_none());
                }
                link.frame_from_vm(&discover());
            }
        }
        link.v4 = Family::Serve(lease4());
        let mut renew = client(dhcp::REQUEST);
        renew.xid = 8;
        renew.ciaddr = Ipv4Addr::new(10, 0, 0, 2);
        let p = frame::udp4(
            renew.ciaddr,
            68,
            Ipv4Addr::new(10, 0, 0, 1),
            67,
            &renew.to_bytes().unwrap(),
        );
        let FromVm::Answer(answer) =
            link.frame_from_vm(&eth(VM, frame::GATEWAY_MAC, frame::IPV4, &p))
        else {
            panic!("DHCP renewal answer");
        };
        assert_eq!(answer[..6], VM);
    }
}
