//! Complete Ethernet frames reach this world before any protocol parsing.

use std::io::Write;
use std::sync::Arc;
use std::task::Waker;
use std::time::Duration;

use fictionet::stdlib::network::ethernet::frame::Mac;
use fictionet::stdlib::network::ethernet::host::{self, Host, Ipv4Config, Ipv6Config, Received};
use fictionet::sync::Mutex;
use fictionet::time::Instant;
use fictionet::{Cx, Interface, Packet};
use fictionet_host::raw::{EthernetFrame, RawAttachment, RawSender};

use crate::observe::{Direction, Hex, Sink, Sinks};
use crate::{Clock, Config, Honeypot, INTERNET};

/// The largest IP packet one Ethernet frame carries.
const MTU: u16 = 1500;

struct Capture {
    writer: Sink,
    lost: u64,
    clock: Clock,
}

impl Capture {
    fn frame(&mut self, fcx: &Cx, direction: Direction, bytes: &[u8]) {
        let record = serde_json::json!({
            "at_us": self.clock.micros(fcx.now()),
            "direction": direction,
            "bytes": Hex(bytes.to_vec()),
            "lost": self.lost,
        });
        let mut line = serde_json::to_vec(&record).expect("a frame record is serializable");
        line.push(b'\n');
        if self.writer.put(&line) {
            self.lost = 0;
        } else {
            self.lost = self.lost.saturating_add(1);
        }
    }
}

/// The server's side of the link: the host that speaks ARP and neighbor
/// discovery for it, the frame log, and the card's transmit queue.
struct Link {
    host: Host,
    capture: Capture,
    sender: RawSender,
    /// The task that waits for the host's timers. It is woken after every
    /// call that may have moved [`Host::poll_at`].
    timer: Option<Waker>,
}

impl Link {
    /// Logs `frame`, then queues it on the card. A frame the full transmit
    /// queue cannot take is dropped, as a host's full queue drops it.
    fn put(&mut self, fcx: &Cx, frame: Vec<u8>) -> fictionet::Result {
        self.capture.frame(fcx, Direction::Out, &frame);
        self.sender.try_send(EthernetFrame(frame))?;
        Ok(())
    }

    /// Sends every frame the host has to send now, and wakes the timer
    /// task to read the host's next deadline.
    fn transmit(&mut self, fcx: &Cx) -> fictionet::Result {
        while let Some(frame) = self.host.transmit(fcx.now()) {
            self.put(fcx, frame)?;
        }
        self.wake_timer();
        Ok(())
    }

    fn wake_timer(&mut self) {
        if let Some(timer) = self.timer.take() {
            timer.wake();
        }
    }
}

/// The host the server is on its link: the card's MAC, both of the
/// server's addresses and both gateways from `config`, and an MTU of
/// 1500 bytes.
fn host(config: &Config, mac: Mac, now: Instant) -> fictionet::Result<Host> {
    let host = Host::new(
        host::Config {
            mac,
            mtu: MTU,
            ipv4: Some(Ipv4Config {
                address: config.address,
                gateway: config.gateway,
            }),
            ipv6: config.address_v6.map(|address| Ipv6Config {
                address,
                gateway: config.gateway_v6,
            }),
        },
        now,
    )?;
    Ok(host)
}

/// Starts the existing honeypot behind a complete Ethernet attachment.
///
/// `raw_log` receives every frame, both ways, including malformed headers,
/// VLAN tags, unknown EtherTypes and Ethernet padding, as hexadecimal JSON
/// lines before parsing. Refused records are counted in the next accepted
/// record; partial records are completed before the next one. `sinks`
/// retain the existing IP capture and TCP option observations.
///
/// The link-layer work is done by an
/// [`ethernet::Host`](fictionet::stdlib::network::ethernet::Host), as a
/// Linux host does it. It answers ARP for [`Config::address`]. With
/// [`Config::address_v6`], it also has a link-local address made from the
/// card's MAC, checks both IPv6 addresses with duplicate address
/// detection before it uses them, joins their solicited-node groups with
/// MLDv2 reports, and answers neighbor solicitations for them. It resolves
/// [`Config::gateway`] with ARP, and the IPv6 gateway
/// ([`Config::gateway_v6`]) with neighbor solicitations, after learning it
/// from router advertisements when it is not configured. It asks again
/// every second until the gateway answers.
///
/// Only untagged IPv4 and IPv6 packets to one of the server's usable
/// addresses, in frames to the card's MAC, broadcast, or a multicast group
/// the host joined, enter the IP attachment. Every packet from the world
/// goes to the gateway of its family, whatever its destination. Packets
/// are dropped while that gateway is unresolved, when they are over the
/// Ethernet MTU of 1500 bytes, and when the card's transmit queue is full;
/// so are the host's own frames when the queue is full.
///
/// The driver and its polling thread must be opened outside
/// `fictionet::run` and kept alive for the run.
pub fn start_raw(
    fcx: &Cx,
    config: &Config,
    clock: Clock,
    sinks: Sinks,
    raw: RawAttachment,
    raw_log: Box<dyn Write + Send>,
) -> fictionet::Result<Honeypot> {
    let host = host(config, raw.mac_address(), fcx.now())?;
    let (sender, mut receiver) = raw.split();
    let (attacher, attachments) = fictionet::attachments();
    let end = Arc::new(Mutex::new(attacher.attach(INTERNET)?));
    let honeypot = crate::start(fcx, config, clock, sinks, attachments)?;
    let link = Arc::new(Mutex::new(Link {
        host,
        capture: Capture {
            writer: Sink::new(raw_log),
            lost: 0,
            clock,
        },
        sender,
        timer: None,
    }));
    let incoming_end = end.clone();
    let incoming = link.clone();
    fcx.spawn(move |fcx| async move {
        // Keep the attacher alive for the lifetime of its internet endpoint.
        let _attacher = attacher;
        loop {
            let EthernetFrame(bytes) = receiver.recv(&fcx).await?;
            incoming.lock().capture.frame(&fcx, Direction::In, &bytes);
            fcx.yield_now().await?;
            let mut link = incoming.lock();
            if let Received::World(packet) = link.host.receive(fcx.now(), &bytes) {
                incoming_end.lock().send(Packet(packet.to_vec()));
            }
            link.transmit(&fcx)?;
        }
    });
    let timed = link.clone();
    fcx.spawn(move |fcx| async move {
        let mut timer = fictionet::Timer::new(&fcx);
        loop {
            std::future::poll_fn(|cx| {
                let mut link = timed.lock();
                link.timer = Some(cx.waker().clone());
                let deadline = link
                    .host
                    .poll_at()
                    .unwrap_or(Instant::from_since_start(Duration::MAX));
                timer.poll_until(cx, deadline)
            })
            .await?;
            timed.lock().transmit(&fcx)?;
        }
    });
    fcx.spawn(move |fcx| async move {
        loop {
            let packet = std::future::poll_fn(|cx| end.lock().poll_recv(&fcx, cx)).await?;
            let mut link = link.lock();
            if let Ok(frame) = link.host.send(fcx.now(), &packet.0) {
                link.put(&fcx, frame)?;
            }
            link.wake_timer();
        }
    });
    Ok(honeypot)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use fictionet::stdlib::network::ethernet::frame::{self, Frame};
    use fictionet::stdlib::network::ethernet::host::{AddressState, Dropped, Ipv6Gateway, Unsent};
    use fictionet::stdlib::network::ip;
    use fictionet::stdlib::protocols::ndp::{
        self, Message, NdOption, NeighborSolicitation, RouterAdvertisement,
    };

    use super::*;

    const MAC: Mac = [2; 6];
    const ROUTER: Mac = [4; 6];
    const ADDRESS: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 10);
    const GATEWAY: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 1);
    const ADDRESS6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x10);

    fn config() -> Config {
        Config {
            address: ADDRESS,
            gateway: GATEWAY,
            ..Config::default()
        }
    }

    fn dual_stack() -> Config {
        Config {
            address_v6: Some(ADDRESS6),
            ..config()
        }
    }

    fn at(secs: u64) -> Instant {
        Instant::from_since_start(Duration::from_secs(secs))
    }

    /// Every frame the host has to send at `now`.
    fn drain(host: &mut Host, now: Instant) -> Vec<Vec<u8>> {
        std::iter::from_fn(|| host.transmit(now)).collect()
    }

    /// An Ethernet/IPv4 ARP packet, byte by byte as RFC 826 lays it out.
    fn arp(op: u8, sender: Mac, sender_ip: Ipv4Addr, target: Mac, target_ip: Ipv4Addr) -> Vec<u8> {
        let mut p = vec![0, 1, 8, 0, 6, 4, 0, op];
        p.extend_from_slice(&sender);
        p.extend_from_slice(&sender_ip.octets());
        p.extend_from_slice(&target);
        p.extend_from_slice(&target_ip.octets());
        p
    }

    fn arp_request(sender: Mac, sender_ip: Ipv4Addr, target_ip: Ipv4Addr) -> Vec<u8> {
        let p = arp(1, sender, sender_ip, [0; 6], target_ip);
        frame::frame(frame::BROADCAST, sender, frame::ARP, &p)
    }

    /// A host that has sent its first frames, with no gateway known yet.
    fn started(config: &Config) -> Host {
        let mut host = host(config, MAC, at(0)).unwrap();
        drain(&mut host, at(0));
        host
    }

    /// The host's first ARP request for the gateway, and the reply that
    /// resolves it.
    #[test]
    fn gateway_is_learned_from_requests_and_replies() {
        let mut host = host(&config(), MAC, at(0)).unwrap();
        let sent = drain(&mut host, at(0));
        assert_eq!(sent, [arp_request(MAC, ADDRESS, GATEWAY)]);
        let request = Frame::parse(&sent[0]).unwrap();
        assert_eq!(
            (request.src, request.dst, request.ethertype),
            (MAC, frame::BROADCAST, frame::ARP)
        );
        assert_eq!(&request.payload[..8], &[0, 1, 8, 0, 6, 4, 0, 1]);
        assert_eq!(&request.payload[8..14], &MAC);
        assert_eq!(&request.payload[14..18], &ADDRESS.octets());
        assert_eq!(&request.payload[18..24], &[0; 6]);
        assert_eq!(&request.payload[24..28], &GATEWAY.octets());
        // Asked again every second until answered.
        assert_eq!(host.poll_at(), Some(at(1)));
        assert_eq!(drain(&mut host, at(1)), sent);
        let reply = frame::frame(
            MAC,
            ROUTER,
            frame::ARP,
            &arp(2, ROUTER, GATEWAY, MAC, ADDRESS),
        );
        assert_eq!(host.receive(at(1), &reply), Received::Handled);
        assert_eq!(host.ipv4_gateway(), Some(ROUTER));
        assert!(drain(&mut host, at(2)).is_empty());

        let mut host = started(&config());
        let request = arp_request(ROUTER, GATEWAY, ADDRESS);
        host.receive(at(0), &request);
        assert_eq!(host.ipv4_gateway(), Some(ROUTER));
        for target in [GATEWAY, Ipv4Addr::new(203, 0, 113, 20)] {
            let mut host = started(&config());
            host.receive(at(0), &arp_request([6; 6], GATEWAY, target));
            assert_eq!(host.ipv4_gateway(), Some([6; 6]));
        }
    }

    #[test]
    fn other_senders_and_invalid_arp_do_not_resolve_the_gateway() {
        let request = arp_request(ROUTER, GATEWAY, ADDRESS);
        for (offset, value) in [(12, 0x86), (14, 1), (18, 5), (21, 3), (22, 1), (28, 192)] {
            let mut bad = request.clone();
            bad[offset] = value;
            let mut host = started(&config());
            host.receive(at(0), &bad);
            assert_eq!(host.ipv4_gateway(), None, "byte {offset}");
        }
        let mut host = started(&config());
        assert_eq!(
            host.receive(at(0), &request[..41]),
            Received::Drop(Dropped::Malformed)
        );
        host.receive(at(0), &arp_request([0; 6], GATEWAY, ADDRESS));
        let packet = ip::packet(GATEWAY.into(), ADDRESS.into(), 1, &[8, 0, 0, 0]);
        host.receive(at(0), &frame::frame(MAC, ROUTER, frame::IPV4, &packet.0));
        assert_eq!(host.ipv4_gateway(), None);
    }

    #[test]
    fn all_ipv4_destinations_use_the_gateway_mac() {
        let mut host = started(&config());
        let packets: Vec<_> = ["192.0.2.5", "198.51.100.27"]
            .into_iter()
            .map(|to| ip::packet(ADDRESS.into(), to.parse().unwrap(), 1, &[0, 0, 0, 0]))
            .collect();
        for packet in &packets {
            assert_eq!(host.send(at(0), &packet.0), Err(Unsent::Unresolved));
        }
        let reply = frame::frame(
            MAC,
            ROUTER,
            frame::ARP,
            &arp(2, ROUTER, GATEWAY, MAC, ADDRESS),
        );
        host.receive(at(0), &reply);
        for packet in &packets {
            let bytes = host.send(at(0), &packet.0).unwrap();
            let parsed = Frame::parse(&bytes).unwrap();
            assert_eq!(
                (parsed.src, parsed.dst, parsed.ethertype),
                (MAC, ROUTER, frame::IPV4)
            );
            assert_eq!(
                frame::ip_packet(parsed.ethertype, parsed.payload),
                Some(packet.0.as_slice())
            );
        }
    }

    #[test]
    fn oversized_replies_are_dropped() {
        let mut host = started(&config());
        let reply = frame::frame(
            MAC,
            ROUTER,
            frame::ARP,
            &arp(2, ROUTER, GATEWAY, MAC, ADDRESS),
        );
        host.receive(at(0), &reply);
        let packet = ip::packet(
            ADDRESS.into(),
            "192.0.2.5".parse().unwrap(),
            1,
            &[0; MTU as usize - 20],
        );
        assert!(host.send(at(0), &packet.0).is_ok());
        let mut oversized = packet.0;
        oversized.push(0);
        assert_eq!(host.send(at(0), &oversized), Err(Unsent::TooBig));
    }

    #[test]
    fn ethernet_padding_is_not_an_ip_payload() {
        let mut host = started(&config());
        let packet = ip::packet(
            "192.0.2.5".parse().unwrap(),
            ADDRESS.into(),
            1,
            &[8, 0, 0, 0],
        );
        let bytes = frame::frame(MAC, ROUTER, frame::IPV4, &packet.0);
        assert!(bytes.len() > 14 + packet.0.len(), "the frame is padded");
        assert_eq!(
            host.receive(at(0), &bytes),
            Received::World(packet.0.as_slice())
        );
        let mut malformed = bytes.clone();
        malformed[16..18].copy_from_slice(&200u16.to_be_bytes());
        assert_eq!(
            host.receive(at(0), &malformed),
            Received::Drop(Dropped::Malformed)
        );
        let vlan = frame::frame(MAC, ROUTER, 0x8100, &packet.0);
        assert_eq!(
            host.receive(at(0), &vlan),
            Received::Drop(Dropped::OtherType)
        );
        let unknown = frame::frame(MAC, ROUTER, 0x88b5, &packet.0);
        assert_eq!(
            host.receive(at(0), &unknown),
            Received::Drop(Dropped::OtherType)
        );
    }

    #[test]
    fn arp_answers_only_for_the_configured_address() {
        let mut host = started(&config());
        let peer = [4; 6];
        let request = arp_request(peer, Ipv4Addr::new(192, 0, 2, 5), ADDRESS);
        assert_eq!(host.receive(at(0), &request), Received::Handled);
        let sent = drain(&mut host, at(0));
        assert_eq!(sent.len(), 1);
        let reply = Frame::parse(&sent[0]).unwrap();
        assert_eq!(
            (reply.src, reply.dst, reply.ethertype),
            (MAC, peer, frame::ARP)
        );
        assert_eq!(&reply.payload[6..8], &[0, 2]);
        assert_eq!(&reply.payload[8..14], &MAC);
        assert_eq!(&reply.payload[14..18], &[203, 0, 113, 10]);
        assert_eq!(&reply.payload[18..24], &peer);
        assert_eq!(&reply.payload[24..28], &[192, 0, 2, 5]);
        let other = arp_request(
            peer,
            Ipv4Addr::new(192, 0, 2, 5),
            Ipv4Addr::new(203, 0, 113, 11),
        );
        host.receive(at(0), &other);
        assert!(drain(&mut host, at(0)).is_empty());
        assert_eq!(
            host.receive(at(0), &[0; 13]),
            Received::Drop(Dropped::Malformed)
        );
    }

    /// Linux answers to the hardware address the request gives, even when
    /// the frame came from another.
    #[test]
    fn arp_answers_the_sender_the_request_names() {
        let mut host = started(&config());
        let named = [6; 6];
        let p = arp(1, named, Ipv4Addr::new(192, 0, 2, 5), [0; 6], ADDRESS);
        let request = frame::frame(frame::BROADCAST, [4; 6], frame::ARP, &p);
        host.receive(at(0), &request);
        let sent = drain(&mut host, at(0));
        let reply = Frame::parse(&sent[0]).unwrap();
        assert_eq!(reply.dst, named);
        assert_eq!(&reply.payload[18..24], &named);
    }

    /// The router's advertisement from its link-local address, with its MAC.
    fn advertisement() -> Vec<u8> {
        let ra = Message::RouterAdvertisement(RouterAdvertisement {
            cur_hop_limit: 64,
            managed: false,
            other: false,
            router_lifetime: 1800,
            reachable_time: 0,
            retrans_timer: 0,
            options: vec![NdOption::SourceLinkLayer(ROUTER)],
        });
        let packet = ra
            .packet(frame::link_local(ROUTER), ndp::ALL_NODES)
            .unwrap();
        frame::frame(
            frame::multicast_mac(ndp::ALL_NODES),
            ROUTER,
            frame::IPV6,
            &packet,
        )
    }

    /// With an IPv6 address, the host checks it and its link-local address
    /// before it uses them, learns its router from the router's
    /// advertisement, and then frames IPv6 replies to the router's MAC.
    #[test]
    fn ipv6_replies_go_to_the_router_after_its_advertisement() {
        let mut host = host(&dual_stack(), MAC, at(0)).unwrap();
        let link_local = frame::link_local(MAC);
        drain(&mut host, at(0));
        assert_eq!(host.address_state(ADDRESS6), Some(AddressState::Tentative));
        let client: IpAddr = "2001:db8:1::1".parse().unwrap();
        let reply = ip::packet(ADDRESS6.into(), client, 6, &[0; 20]);
        assert_eq!(host.send(at(0), &reply.0), Err(Unsent::Source));
        drain(&mut host, at(1));
        for address in [ADDRESS6, link_local] {
            assert_eq!(host.address_state(address), Some(AddressState::Preferred));
        }
        assert_eq!(host.send(at(1), &reply.0), Err(Unsent::Unresolved));
        assert_eq!(host.receive(at(1), &advertisement()), Received::Handled);
        assert_eq!(
            host.ipv6_gateway(),
            Some((frame::link_local(ROUTER), Some(ROUTER)))
        );
        let bytes = host.send(at(1), &reply.0).unwrap();
        let parsed = Frame::parse(&bytes).unwrap();
        assert_eq!(
            (parsed.src, parsed.dst, parsed.ethertype),
            (MAC, ROUTER, frame::IPV6)
        );
        assert_eq!(
            frame::ip_packet(parsed.ethertype, parsed.payload),
            Some(reply.0.as_slice())
        );
        // Without an IPv6 address, IPv6 is off.
        let mut host = started(&config());
        assert_eq!(host.send(at(0), &reply.0), Err(Unsent::Off));
    }

    /// A configured IPv6 gateway, such as Hetzner's `fe80::1`, is resolved
    /// by neighbor solicitation and needs no advertisement.
    #[test]
    fn a_configured_ipv6_gateway_is_resolved() {
        let gateway: Ipv6Addr = "fe80::1".parse().unwrap();
        let config = Config {
            gateway_v6: Ipv6Gateway::Configured(gateway),
            ..dual_stack()
        };
        let mut host = host(&config, MAC, at(0)).unwrap();
        drain(&mut host, at(0));
        let sent = drain(&mut host, at(1));
        let solicited = frame::multicast_mac(ndp::solicited_node(gateway));
        assert!(
            sent.iter()
                .any(|f| Frame::parse(f).is_some_and(|f| f.dst == solicited)),
            "the host solicits its gateway"
        );
        assert_eq!(host.ipv6_gateway(), Some((gateway, None)));
    }

    /// The host takes in frames to the solicited-node group of each of its
    /// IPv6 addresses, and answers neighbor solicitations for its address
    /// to the asker, and only once the address passed its check.
    #[test]
    fn neighbor_solicitations_are_answered() {
        let mut host = host(&dual_stack(), MAC, at(0)).unwrap();
        let link_local = frame::link_local(MAC);
        for address in [ADDRESS6, link_local] {
            assert!(host.accepts(frame::multicast_mac(ndp::solicited_node(address))));
        }
        assert!(!host.accepts(frame::multicast_mac(ndp::solicited_node(
            "2001:db8::99".parse().unwrap()
        ))));
        let router = frame::link_local(ROUTER);
        let ns = Message::NeighborSolicitation(NeighborSolicitation {
            target: ADDRESS6,
            options: vec![NdOption::SourceLinkLayer(ROUTER)],
        });
        let group = ndp::solicited_node(ADDRESS6);
        let packet = ns.packet(router, group).unwrap();
        let solicitation = frame::frame(frame::multicast_mac(group), ROUTER, frame::IPV6, &packet);
        drain(&mut host, at(0));
        host.receive(at(0), &solicitation);
        assert!(
            drain(&mut host, at(0)).is_empty(),
            "a tentative address is not answered"
        );
        drain(&mut host, at(1));
        assert_eq!(host.receive(at(1), &solicitation), Received::Handled);
        let sent = drain(&mut host, at(1));
        assert_eq!(sent.len(), 1);
        let answer = Frame::parse(&sent[0]).unwrap();
        assert_eq!((answer.src, answer.dst), (MAC, ROUTER));
        let packet = frame::ip_packet(answer.ethertype, answer.payload).unwrap();
        let envelope = ndp::Envelope::of(packet).unwrap();
        assert_eq!((envelope.source, envelope.destination), (ADDRESS6, router));
        let header = ip::Header::parse(packet).unwrap();
        let Message::NeighborAdvertisement(na) =
            Message::receive(&envelope, header.payload(packet)).unwrap()
        else {
            panic!("a neighbor advertisement")
        };
        assert_eq!(na.target, ADDRESS6);
        assert!(na.solicited && na.overrides && !na.router);
        assert_eq!(na.options, [NdOption::TargetLinkLayer(MAC)]);
    }

    /// IPv6 to the server's address, once it passed its check, enters the
    /// world, and so does IPv4 to its IPv4 address; other destinations do
    /// not.
    #[test]
    fn packets_to_both_addresses_enter_the_world() {
        let mut host = host(&dual_stack(), MAC, at(0)).unwrap();
        drain(&mut host, at(0));
        let from: SocketAddr = "[2001:db8:1::1]:40000".parse().unwrap();
        let syn = ip::packet(from.ip(), ADDRESS6.into(), 6, &[0; 20]);
        let bytes = frame::frame(MAC, ROUTER, frame::IPV6, &syn.0);
        assert_eq!(
            host.receive(at(0), &bytes),
            Received::Drop(Dropped::NotOurs)
        );
        drain(&mut host, at(1));
        assert_eq!(
            host.receive(at(1), &bytes),
            Received::World(syn.0.as_slice())
        );
        let elsewhere = ip::packet(from.ip(), "2001:db8::11".parse().unwrap(), 6, &[0; 20]);
        let bytes = frame::frame(MAC, ROUTER, frame::IPV6, &elsewhere.0);
        assert_eq!(
            host.receive(at(1), &bytes),
            Received::Drop(Dropped::NotOurs)
        );
        let syn = ip::packet("192.0.2.5".parse().unwrap(), ADDRESS.into(), 6, &[0; 20]);
        let bytes = frame::frame(MAC, ROUTER, frame::IPV4, &syn.0);
        assert_eq!(
            host.receive(at(1), &bytes),
            Received::World(syn.0.as_slice())
        );
    }
}
