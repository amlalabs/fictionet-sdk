//! Ethernet lowering: a virtual machine's network card, carried as IP
//! packets.
//!
//! A VM sends and takes Ethernet frames. A world speaks IP packets. A
//! [`Link`] stands between them on the VM's side: it reads each frame from
//! the VM, answers the link-local questions itself (ARP and IPv6 neighbor
//! discovery, and DHCP when it was given addresses to hand out), passes the
//! IP packets on, and puts an Ethernet header on each packet for the VM.
//! It does no I/O: whatever carries the frames, such as
//! `fictionet attach --type tap` or an embedded VM, reads and writes them
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
/// how to frame each packet from the world. It does no I/O, so the tests
/// drive it directly.
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
    /// Shorter than its headers, an IP header that does not add up, or a
    /// transport the link cannot read: an IPv6 extension header that runs
    /// past its end, a UDP or ICMPv6 header cut short, or a UDP length that
    /// does not fit the packet.
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

impl Link {
    /// A link that hands out IPv4 and IPv6 addresses as `v4` and `v6`
    /// say, for a VM whose largest IP packet is `mtu` bytes.
    pub fn new(v4: Family<Ipv4Addr>, v6: Family<Ipv6Addr>, mtu: u16) -> Link {
        Link {
            v4,
            v6,
            mtu,
            vm: None,
        }
    }

    /// The VM's MAC, once its first frame has arrived.
    pub fn vm_mac(&self) -> Option<Mac> {
        self.vm
    }

    fn own_v4(&self) -> Option<Ipv4Addr> {
        match &self.v4 {
            Family::Serve(l) => Some(l.addr.addr),
            _ => None,
        }
    }

    fn own_v6(&self) -> Option<Ipv6Addr> {
        match &self.v6 {
            Family::Serve(l) => Some(l.addr.addr),
            _ => None,
        }
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
            frame::ARP => match frame::arp_reply(f.payload, f.src, self.own_v4()) {
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
                return match &self.v4 {
                    Family::Serve(lease) => match addresses::dhcp4(lease, self.mtu, request) {
                        Some((packet, broadcast)) => {
                            let to = if broadcast { frame::BROADCAST } else { vm };
                            FromVm::Answer(frame::frame(
                                to,
                                frame::GATEWAY_MAC,
                                frame::IPV4,
                                &packet,
                            ))
                        }
                        None => FromVm::Drop(Why::Handled),
                    },
                    Family::FromWorld => FromVm::World(p),
                    Family::Off => FromVm::Drop(Why::Handled),
                };
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
        match self.own_v4() {
            Some(own) if src != own => FromVm::Drop(Why::Spoofed),
            _ => FromVm::World(p),
        }
    }

    fn ipv6<'a>(&self, p: &'a [u8], vm: Mac) -> FromVm<'a> {
        let Ok(upper) = frame::upper(p) else {
            return FromVm::Drop(Why::Malformed);
        };
        match upper {
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
                ..
            } => {
                return match frame::neighbor_advert(p, vm, self.own_v6()) {
                    Some(reply) => FromVm::Answer(reply),
                    None => FromVm::Drop(Why::Handled),
                };
            }
            Upper::Icmp6 {
                kind: frame::ROUTER_SOLICITATION,
                ..
            } => {
                return match &self.v6 {
                    Family::Serve(_) => match self.router_advert() {
                        Some(ra) => FromVm::Answer(ra),
                        None => FromVm::Drop(Why::Handled),
                    },
                    Family::FromWorld => FromVm::World(p),
                    Family::Off => FromVm::Drop(Why::Handled),
                };
            }
            // Advertisements and redirects only make sense on the link.
            Upper::Icmp6 { kind, .. } if frame::is_neighbor_discovery(kind) => {
                return FromVm::Drop(Why::Handled);
            }
            Upper::Udp {
                port: dhcpv6::SERVER_PORT,
                payload: request,
            } => {
                return match &self.v6 {
                    Family::Serve(lease) => match addresses::dhcp6(
                        lease,
                        // Leave room for the IPv6 and UDP headers.
                        usize::from(self.mtu).saturating_sub(40 + 8),
                        request,
                    ) {
                        Some(answer) => {
                            let packet = addresses::dhcp6_packet(p, &answer);
                            FromVm::Answer(frame::frame(
                                vm,
                                frame::GATEWAY_MAC,
                                frame::IPV6,
                                &packet,
                            ))
                        }
                        None => FromVm::Drop(Why::Handled),
                    },
                    Family::FromWorld => FromVm::World(p),
                    Family::Off => FromVm::Drop(Why::Handled),
                };
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
        match self.own_v6() {
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
    use fictionet::stdlib::codec::Wire;
    use frame::tests::{VM, solicitation};

    fn served() -> Link {
        Link::new(
            Family::Serve(Lease {
                addr: Cidr {
                    addr: Ipv4Addr::new(10, 0, 0, 2),
                    prefix: 24,
                },
                gateway: Some(Ipv4Addr::new(10, 0, 0, 1)),
                dns: Some(Ipv4Addr::new(10, 0, 0, 1)),
            }),
            Family::Serve(Lease {
                addr: Cidr {
                    addr: "fd00::2".parse().unwrap(),
                    prefix: 64,
                },
                gateway: Some("fd00::1".parse().unwrap()),
                dns: None,
            }),
            1500,
        )
    }

    fn eth(src: Mac, dst: Mac, ethertype: u16, payload: &[u8]) -> Vec<u8> {
        frame::frame(dst, src, ethertype, payload)
    }

    fn discover() -> Vec<u8> {
        let mut m = dhcp::Message::new(dhcp::BOOTREQUEST, 7);
        m.chaddr[..6].copy_from_slice(&VM);
        m.push(dhcp::opt::MESSAGE_TYPE, [dhcp::DISCOVER]);
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
            Link::new(Family::Off, Family::Off, 1500).frame_from_vm(&group),
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
        let big = frame::udp4(
            Ipv4Addr::new(10, 0, 0, 2),
            1,
            Ipv4Addr::new(10, 0, 0, 1),
            2,
            &[0; 1472],
        );
        assert_eq!(big.len(), 1500);
        assert!(matches!(
            link.frame_from_vm(&eth(VM, frame::GATEWAY_MAC, frame::IPV4, &big)),
            FromVm::World(_)
        ));
        let bigger = frame::udp4(
            Ipv4Addr::new(10, 0, 0, 2),
            1,
            Ipv4Addr::new(10, 0, 0, 1),
            2,
            &[0; 1473],
        );
        assert_eq!(
            link.frame_from_vm(&eth(VM, frame::GATEWAY_MAC, frame::IPV4, &bigger)),
            FromVm::Drop(Why::TooBig)
        );
        assert!(link.to_vm(&big).is_some());
        assert!(link.to_vm(&bigger).is_none());
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
        let mut world = Link::new(Family::FromWorld, Family::Off, 1500);
        assert!(matches!(world.frame_from_vm(&d), FromVm::World(_)));
        let mut off = Link::new(Family::Off, Family::Off, 1500);
        assert_eq!(off.frame_from_vm(&d), FromVm::Drop(Why::Handled));
    }

    #[test]
    fn served_addresses_are_the_only_sources_passed() {
        let mut link = served();
        let spoof = frame::ipv4(
            Ipv4Addr::new(10, 0, 0, 77),
            Ipv4Addr::new(10, 0, 0, 1),
            1,
            &[],
        );
        assert_eq!(
            link.frame_from_vm(&eth(VM, frame::GATEWAY_MAC, frame::IPV4, &spoof)),
            FromVm::Drop(Why::Spoofed)
        );
        let spoof6 = frame::udp6(
            "fd00::77".parse().unwrap(),
            1,
            "fd00::1".parse().unwrap(),
            2,
            &[],
        );
        assert_eq!(
            link.frame_from_vm(&eth(VM, frame::GATEWAY_MAC, frame::IPV6, &spoof6)),
            FromVm::Drop(Why::Spoofed)
        );
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
        // With the address left to the world, any source goes to the world,
        // which decides.
        let mut world = Link::new(Family::FromWorld, Family::FromWorld, 1500);
        assert!(matches!(
            world.frame_from_vm(&eth(VM, frame::GATEWAY_MAC, frame::IPV4, &spoof)),
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
        assert_eq!(
            Frame::parse(&na).unwrap().payload[40],
            frame::NEIGHBOR_ADVERTISEMENT
        );

        let rs = frame::icmp6(
            ll,
            "ff02::2".parse().unwrap(),
            vec![frame::ROUTER_SOLICITATION, 0, 0, 0, 0, 0, 0, 0],
        );
        let rs_frame = eth(VM, [0x33, 0x33, 0, 0, 0, 2], frame::IPV6, &rs);
        let FromVm::Answer(ra) = link.frame_from_vm(&rs_frame) else {
            panic!("no advertisement")
        };
        let f = Frame::parse(&ra).unwrap();
        assert_eq!(f.dst, [0x33, 0x33, 0, 0, 0, 1]);
        assert_eq!(f.payload[40], frame::ROUTER_ADVERTISEMENT);
        // Left to the world, the solicitation goes there; turned off, nowhere.
        let mut world = Link::new(Family::Off, Family::FromWorld, 1500);
        assert!(matches!(world.frame_from_vm(&rs_frame), FromVm::World(_)));
        assert!(world.router_advert().is_none());
        assert!(!world.advertises());
        assert!(link.advertises());
        let mut off = Link::new(Family::Off, Family::Off, 1500);
        assert_eq!(off.frame_from_vm(&rs_frame), FromVm::Drop(Why::Handled));
        // An advertisement from the VM never leaves the link.
        let ra_from_vm = frame::icmp6(
            ll,
            "ff02::1".parse().unwrap(),
            vec![frame::ROUTER_ADVERTISEMENT, 0, 0, 0, 0, 0, 0, 0],
        );
        assert_eq!(
            link.frame_from_vm(&eth(VM, [0x33, 0x33, 0, 0, 0, 1], frame::IPV6, &ra_from_vm)),
            FromVm::Drop(Why::Handled)
        );
        // Also behind a hop-by-hop header, with the world left to set up IPv6.
        let mut ext = vec![frame::ICMPV6, 0, 1, 4, 0, 0, 0, 0];
        ext.extend_from_slice(&ra_from_vm[40..]);
        let hidden = frame::ipv6(ll, "ff02::1".parse().unwrap(), 0, 255, &ext);
        let mut world = Link::new(Family::Off, Family::FromWorld, 1500);
        assert_eq!(
            world.frame_from_vm(&eth(VM, [0x33, 0x33, 0, 0, 0, 1], frame::IPV6, &hidden)),
            FromVm::Drop(Why::Handled)
        );
    }

    #[test]
    fn dhcp6_is_answered_to_the_vm() {
        let mut link = served();
        let mut solicit = vec![1, 0, 0, 1];
        solicit.extend_from_slice(&[0, 1, 0, 10, 0, 3, 0, 1]);
        solicit.extend_from_slice(&VM);
        solicit.extend_from_slice(&[0, 3, 0, 12, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0]);
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
        let (port, payload) = frame::udp_to(f.payload).unwrap();
        assert_eq!((port, payload[0]), (546, 2));
    }

    fn rebind(stale: usize, client_len: u16) -> Vec<u8> {
        let mut request = vec![6, 0, 0, 1];
        request.extend_from_slice(&1u16.to_be_bytes()); // Client ID.
        request.extend_from_slice(&client_len.to_be_bytes());
        request.extend_from_slice(&[0, 3, 0, 1]);
        request.extend_from_slice(&VM);
        request.resize(8 + usize::from(client_len), 0);
        request.extend_from_slice(&3u16.to_be_bytes()); // IA_NA.
        request.extend_from_slice(&u16::try_from(12 + stale * 28).unwrap().to_be_bytes());
        request.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0]);
        for i in 0..stale {
            request.extend_from_slice(&[0, 5, 0, 24]); // IAADDR.
            request.extend_from_slice(&Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 1, i as u16).octets());
            request.extend_from_slice(&[0; 8]);
        }
        let p = frame::udp6(
            frame::link_local(VM),
            546,
            "ff02::1:2".parse().unwrap(),
            547,
            &request,
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
        }
    }

    #[test]
    fn dhcp6_rebind_cannot_overflow_the_udp_length() {
        let mut link = served();
        link.mtu = u16::MAX;
        let Family::Serve(lease) = &mut link.v6 else {
            unreachable!()
        };
        lease.dns = Some("fd00::53".parse().unwrap());
        let request = rebind(2337, 10);
        assert_eq!(request.len(), frame::HEADER + 65_518);
        assert!(request.len() <= frame::HEADER + usize::from(link.mtu));
        assert_eq!(link.frame_from_vm(&request), FromVm::Drop(Why::Handled));
        assert!(matches!(
            link.frame_from_vm(&rebind(0, 10)),
            FromVm::Answer(_)
        ));
    }

    #[test]
    fn arp_for_the_gateway() {
        let mut link = served();
        let mut a = vec![0, 1, 8, 0, 6, 4, 0, 1];
        a.extend_from_slice(&VM);
        a.extend_from_slice(&[10, 0, 0, 2, 0, 0, 0, 0, 0, 0, 10, 0, 0, 1]);
        let FromVm::Answer(reply) = link.frame_from_vm(&eth(VM, frame::BROADCAST, frame::ARP, &a))
        else {
            panic!("no reply")
        };
        assert_eq!(
            &Frame::parse(&reply).unwrap().payload[8..18],
            &[0x02, 0x66, 0x6e, 0, 0, 1, 10, 0, 0, 1]
        );
    }

    /// `n` destination options headers in front of `inner`, whose protocol
    /// is `proto`, in an IPv6 packet with hop limit 255.
    fn behind_options(src: Ipv6Addr, dst: Ipv6Addr, n: usize, proto: u8, inner: &[u8]) -> Vec<u8> {
        let mut ext = Vec::new();
        for i in 0..n {
            ext.extend_from_slice(&[if i + 1 == n { proto } else { 60 }, 0, 1, 4, 0, 0, 0, 0]);
        }
        ext.extend_from_slice(inner);
        frame::ipv6(src, dst, if n == 0 { proto } else { 60 }, 255, &ext)
    }

    /// The first `cut` bytes of `packet`'s payload as an IPv6 first
    /// fragment, and the rest as the second.
    fn fragments6(packet: &[u8], cut: usize) -> (Vec<u8>, Vec<u8>) {
        let (src, dst) = (
            frame::source_v6(packet),
            Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).unwrap()),
        );
        let body = &packet[40..];
        let mut first = vec![packet[6], 0, 0, 1, 0, 0, 0, 42];
        first.extend_from_slice(&body[..cut]);
        let mut second = vec![packet[6], 0];
        second.extend_from_slice(&(cut as u16).to_be_bytes());
        second.extend_from_slice(&[0, 0, 0, 42]);
        second.extend_from_slice(&body[cut..]);
        (
            frame::ipv6(src, dst, 44, packet[7], &first),
            frame::ipv6(src, dst, 44, packet[7], &second),
        )
    }

    /// The first `cut` bytes of `packet`'s payload as an IPv4 first
    /// fragment, and the rest as the second.
    fn fragments4(packet: &[u8], cut: usize) -> (Vec<u8>, Vec<u8>) {
        let (src, dst) = (
            frame::source_v4(packet),
            Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]),
        );
        let mut first = frame::ipv4(src, dst, packet[9], &packet[20..20 + cut]);
        first[6] = 0x20;
        let mut second = frame::ipv4(src, dst, packet[9], &packet[20 + cut..]);
        second[6..8].copy_from_slice(&((cut / 8) as u16).to_be_bytes());
        (first, second)
    }

    #[test]
    fn control_messages_behind_any_extension_headers_stay_on_the_link() {
        let ll = frame::link_local(VM);
        let all: Ipv6Addr = "ff02::1".parse().unwrap();
        let ra = frame::icmp6(
            ll,
            all,
            vec![frame::ROUTER_ADVERTISEMENT, 0, 0, 0, 64, 0, 0, 0],
        );
        let to_all = [0x33, 0x33, 0, 0, 0, 1];
        for v6 in [Family::FromWorld, Family::Off] {
            let mut link = Link::new(Family::Off, v6, 1500);
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
        let atomic = |p: &[u8]| {
            let mut body = vec![p[6], 0, 0, 0, 0, 0, 0, 9];
            body.extend_from_slice(&p[40..]);
            frame::ipv6(
                frame::source_v6(p),
                Ipv6Addr::from(<[u8; 16]>::try_from(&p[24..40]).unwrap()),
                44,
                255,
                &body,
            )
        };
        let to = [0x33, 0x33, 0xff, 0, 0, 1];
        assert_eq!(
            link.frame_from_vm(&eth(VM, to, frame::IPV6, &atomic(&ns))),
            FromVm::Drop(Why::Handled)
        );
        let ll = frame::link_local(VM);
        let rs = frame::icmp6(
            ll,
            "ff02::2".parse().unwrap(),
            vec![frame::ROUTER_SOLICITATION, 0, 0, 0, 0, 0, 0, 0],
        );
        let mut world = Link::new(Family::Off, Family::FromWorld, 1500);
        let to = [0x33, 0x33, 0, 0, 0, 2];
        assert_eq!(
            world.frame_from_vm(&eth(VM, to, frame::IPV6, &atomic(&rs))),
            FromVm::Drop(Why::Handled)
        );
    }

    #[test]
    fn fragmented_dhcp_is_never_answered_and_passes_only_when_left_to_the_world() {
        // A DISCOVER from a static address, split in two.
        let mut m = dhcp::Message::new(dhcp::BOOTREQUEST, 7);
        m.chaddr[..6].copy_from_slice(&VM);
        m.push(dhcp::opt::MESSAGE_TYPE, [dhcp::DISCOVER]);
        let whole = frame::udp4(
            Ipv4Addr::new(10, 0, 0, 2),
            68,
            Ipv4Addr::BROADCAST,
            67,
            &m.to_bytes().unwrap(),
        );
        let (first, second) = fragments4(&whole, 64);
        let frame = |p: &[u8]| eth(VM, frame::BROADCAST, frame::IPV4, p);
        let mut off = Link::new(Family::Off, Family::Off, 1500);
        assert_eq!(
            off.frame_from_vm(&frame(&whole)),
            FromVm::Drop(Why::Handled)
        );
        assert_eq!(
            off.frame_from_vm(&frame(&first)),
            FromVm::Drop(Why::Handled),
            "--no-ip-addr"
        );
        // The second fragment alone carries no UDP header, and the world
        // cannot put the request together without the first.
        assert!(matches!(
            off.frame_from_vm(&frame(&second)),
            FromVm::World(_)
        ));
        let mut link = served();
        assert_eq!(
            link.frame_from_vm(&frame(&first)),
            FromVm::Drop(Why::Handled),
            "the link answers no fragment"
        );
        let mut world = Link::new(Family::FromWorld, Family::Off, 1500);
        assert!(
            matches!(world.frame_from_vm(&frame(&first)), FromVm::World(_)),
            "left to the world"
        );
        // A first fragment cut inside the UDP header cannot be read.
        let (stub, _) = fragments4(&whole, 0);
        assert_eq!(
            off.frame_from_vm(&frame(&stub)),
            FromVm::Drop(Why::Malformed)
        );
    }

    #[test]
    fn a_first_fragment_of_a_dhcp6_solicit_gets_no_answer() {
        let mut solicit = vec![1, 0, 0, 1];
        solicit.extend_from_slice(&[0, 1, 0, 10, 0, 3, 0, 1]);
        solicit.extend_from_slice(&VM);
        solicit.extend_from_slice(&[0, 3, 0, 12, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0]);
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
        let mut link = served();
        assert_eq!(
            link.frame_from_vm(&eth(VM, to, frame::IPV6, &first)),
            FromVm::Drop(Why::Handled)
        );
        let mut off = Link::new(Family::Off, Family::Off, 1500);
        assert_eq!(
            off.frame_from_vm(&eth(VM, to, frame::IPV6, &first)),
            FromVm::Drop(Why::Handled)
        );
        let mut world = Link::new(Family::Off, Family::FromWorld, 1500);
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

    #[test]
    fn world_unicast_waits_for_the_vm_mac() {
        let mut link = served();
        let unicast = frame::ipv6(
            "fd00::1".parse().unwrap(),
            "fd00::2".parse().unwrap(),
            6,
            64,
            &[],
        );
        assert!(link.to_vm(&unicast).is_none());
        for (dst, mac) in [
            (Ipv4Addr::BROADCAST, frame::BROADCAST),
            (Ipv4Addr::new(239, 129, 2, 3), [1, 0, 0x5e, 1, 2, 3]),
        ] {
            let p = frame::ipv4(Ipv4Addr::new(10, 0, 0, 1), dst, 17, &[]);
            assert_eq!(link.to_vm(&p).unwrap()[..6], mac);
        }
        let ra = link.router_advert().unwrap();
        assert_eq!(ra[..6], [0x33, 0x33, 0, 0, 0, 1]);
        let FromVm::Answer(answer) = link.frame_from_vm(&discover()) else {
            panic!("DHCP answer")
        };
        assert_eq!(answer[..6], frame::BROADCAST);
        let mut renew = dhcp::Message::new(dhcp::BOOTREQUEST, 8);
        renew.chaddr[..6].copy_from_slice(&VM);
        renew.ciaddr = Ipv4Addr::new(10, 0, 0, 2);
        renew.push(dhcp::opt::MESSAGE_TYPE, [dhcp::REQUEST]);
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
        assert_eq!(link.to_vm(&unicast).unwrap()[..6], VM);
    }

    #[test]
    fn world_packets_get_the_vm_or_group_mac() {
        let mut link = served();
        let to_vm = frame::ipv4(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            1,
            &[],
        );
        assert!(link.to_vm(&to_vm).is_none(), "before the VM's MAC is known");
        link.frame_from_vm(&discover());
        let h = link.to_vm(&to_vm).unwrap();
        assert_eq!(h, frame::header(VM, frame::GATEWAY_MAC, frame::IPV4));
    }
}
