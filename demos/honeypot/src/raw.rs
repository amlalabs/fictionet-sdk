//! Complete Ethernet frames reach this world before any protocol parsing.

use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use fictionet::stdlib::network::ethernet::frame::{self, Frame, Mac};
use fictionet::stdlib::network::ip;
use fictionet::sync::Mutex;
use fictionet::{Cx, Interface, Packet};
use fictionet_host::raw::{EthernetFrame, RawAttachment};

use crate::observe::{Direction, Hex, Sink, Sinks};
use crate::{Clock, Config, Honeypot, INTERNET};

/// Linux's initial ARP retransmission interval.
const ARP_RETRY: Duration = Duration::from_secs(1);

/// The largest IP packet one Ethernet frame carries.
const MTU: usize = 1500;

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

/// Starts the existing honeypot behind a complete Ethernet attachment.
/// The server's address must be IPv4: the adapter answers ARP, and does
/// not do IPv6 neighbor discovery.
///
/// `raw_log` receives every frame, including malformed headers, VLAN tags,
/// unknown EtherTypes and Ethernet padding, as hexadecimal JSON lines before
/// parsing. Refused records are counted in the next accepted record; partial
/// records are completed before the next one. `sinks` retain the existing IP
/// capture and TCP option observations.
///
/// Only untagged IPv4 and IPv6 addressed to this NIC enter the IP attachment.
/// ARP for the configured IPv4 address is answered here. The adapter broadcasts
/// an ARP request for [`Config::gateway`] at startup and every second until it
/// learns the gateway's MAC from its own ARP requests or replies.
/// Every IPv4 reply goes to that MAC, regardless of its destination IP;
/// replies are dropped until the gateway is known. IPv6 replies are dropped:
/// the configuration supplies only an IPv4 gateway and no neighbor discovery.
/// Outgoing packets over the Ethernet MTU of 1500 bytes are dropped, as are
/// those sent while the NIC's transmit queue is full. The driver and its
/// polling thread must be opened outside
/// `fictionet::run` and kept alive for the run.
pub fn start_raw(
    fcx: &Cx,
    config: &Config,
    clock: Clock,
    sinks: Sinks,
    raw: RawAttachment,
    raw_log: Box<dyn Write + Send>,
) -> fictionet::Result<Honeypot> {
    let IpAddr::V4(address) = config.address else {
        return Err(fictionet::Error::msg(
            "a raw Ethernet honeypot needs an IPv4 address",
        ));
    };
    let mac = raw.mac_address();
    let (sender, mut receiver) = raw.split();
    let (attacher, attachments) = fictionet::attachments();
    let end = Arc::new(Mutex::new(attacher.attach(INTERNET)?));
    let honeypot = crate::start(fcx, config, clock, sinks, attachments)?;
    let gateway = config.gateway;
    let gateway_mac = Arc::new(Mutex::new(None));
    let capture = Arc::new(Mutex::new(Capture {
        writer: Sink::new(raw_log),
        lost: 0,
        clock,
    }));
    let incoming_end = end.clone();
    let incoming_gateway = gateway_mac.clone();
    let incoming_capture = capture.clone();
    let incoming_sender = sender.clone();
    fcx.spawn(move |fcx| async move {
        // Keep the attacher alive for the lifetime of its internet endpoint.
        let _attacher = attacher;
        loop {
            let EthernetFrame(bytes) = receiver.recv(&fcx).await?;
            incoming_capture.lock().frame(&fcx, Direction::In, &bytes);
            fcx.yield_now().await?;
            let Some(frame) = Frame::parse(&bytes) else {
                continue;
            };
            if frame::is_group(&frame.src) || (frame.dst != mac && frame.dst != frame::BROADCAST) {
                continue;
            }
            if let Some(learned) = arp_gateway(&frame, gateway) {
                *incoming_gateway.lock() = Some(learned);
            }
            if let Some(reply) = arp_reply(&frame, mac, address) {
                incoming_capture.lock().frame(&fcx, Direction::Out, &reply);
                incoming_sender.send(&fcx, EthernetFrame(reply)).await?;
                continue;
            }
            let Some(packet) = frame::ip_packet(frame.ethertype, frame.payload) else {
                continue;
            };
            incoming_end.lock().send(Packet(packet.to_vec()));
        }
    });
    let resolving_gateway = gateway_mac.clone();
    let resolving_capture = capture.clone();
    let resolving_sender = sender.clone();
    fcx.spawn(move |fcx| async move {
        while resolving_gateway.lock().is_none() {
            let bytes = arp_request(mac, address, gateway);
            resolving_capture.lock().frame(&fcx, Direction::Out, &bytes);
            resolving_sender.try_send(EthernetFrame(bytes))?;
            fcx.sleep(ARP_RETRY).await?;
        }
        Ok(())
    });
    fcx.spawn(move |fcx| async move {
        loop {
            let packet = std::future::poll_fn(|cx| end.lock().poll_recv(&fcx, cx)).await?;
            let Some(bytes) = outgoing(&packet.0, mac, *gateway_mac.lock()) else {
                continue;
            };
            capture.lock().frame(&fcx, Direction::Out, &bytes);
            sender.try_send(EthernetFrame(bytes))?;
        }
    });
    Ok(honeypot)
}

fn outgoing(packet: &[u8], mac: Mac, gateway: Option<Mac>) -> Option<Vec<u8>> {
    // Reassembly can produce a reply larger than the Ethernet MTU.
    if packet.len() > MTU || !ip::Header::parse(packet)?.dst.is_ipv4() {
        return None;
    }
    Some(frame::frame(gateway?, mac, frame::IPV4, packet))
}

fn arp_request(mac: Mac, address: Ipv4Addr, gateway: Ipv4Addr) -> Vec<u8> {
    let mut request = vec![0, 1, 8, 0, 6, 4, 0, 1];
    request.extend_from_slice(&mac);
    request.extend_from_slice(&address.octets());
    request.extend_from_slice(&[0; 6]);
    request.extend_from_slice(&gateway.octets());
    frame::frame(frame::BROADCAST, mac, frame::ARP, &request)
}

fn arp_gateway(frame: &Frame<'_>, gateway: Ipv4Addr) -> Option<Mac> {
    let p = frame.payload;
    if frame.ethertype != frame::ARP
        || p.len() < 28
        || p[..6] != [0, 1, 8, 0, 6, 4]
        || !matches!(&p[6..8], [0, 1] | [0, 2])
        || p[14..18] != gateway.octets()
    {
        return None;
    }
    let sender: Mac = p[8..14].try_into().expect("six bytes");
    (!frame::is_group(&sender) && sender != [0; 6]).then_some(sender)
}

/// The reply to an Ethernet/IPv4 ARP request for `address`, as Linux
/// sends it: to the sender's hardware address the request gives.
fn arp_reply(frame: &Frame<'_>, mac: Mac, address: Ipv4Addr) -> Option<Vec<u8>> {
    let p = frame.payload;
    if frame.ethertype != frame::ARP
        || p.len() < 28
        || p[..8] != [0, 1, 8, 0, 6, 4, 0, 1]
        || p[24..28] != address.octets()
    {
        return None;
    }
    let sender: Mac = p[8..14].try_into().expect("six bytes");
    let mut reply = p[..28].to_vec();
    reply[6..8].copy_from_slice(&2u16.to_be_bytes());
    reply[18..24].copy_from_slice(&sender);
    reply[24..28].copy_from_slice(&p[14..18]);
    reply[8..14].copy_from_slice(&mac);
    reply[14..18].copy_from_slice(&address.octets());
    Some(frame::frame(sender, mac, frame::ARP, &reply))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gateway_is_learned_from_requests_and_replies() {
        let address = Ipv4Addr::new(203, 0, 113, 10);
        let gateway = Ipv4Addr::new(203, 0, 113, 1);
        let mac = [2; 6];
        let router = [4; 6];
        let bytes = arp_request(mac, address, gateway);
        let request = Frame::parse(&bytes).unwrap();
        assert_eq!(
            (request.src, request.dst, request.ethertype),
            (mac, frame::BROADCAST, frame::ARP)
        );
        assert_eq!(&request.payload[..8], &[0, 1, 8, 0, 6, 4, 0, 1]);
        assert_eq!(&request.payload[8..14], &mac);
        assert_eq!(&request.payload[14..18], &address.octets());
        assert_eq!(&request.payload[18..24], &[0; 6]);
        assert_eq!(&request.payload[24..28], &gateway.octets());
        let reply = arp_reply(&request, router, gateway).unwrap();
        assert_eq!(
            arp_gateway(&Frame::parse(&reply).unwrap(), gateway),
            Some(router)
        );
        let request = arp_request(router, gateway, address);
        assert_eq!(
            arp_gateway(&Frame::parse(&request).unwrap(), gateway),
            Some(router)
        );
        for target in [gateway, Ipv4Addr::new(203, 0, 113, 20)] {
            let request = arp_request([6; 6], gateway, target);
            assert_eq!(
                arp_gateway(&Frame::parse(&request).unwrap(), gateway),
                Some([6; 6])
            );
        }
    }

    #[test]
    fn other_senders_and_invalid_arp_do_not_resolve_the_gateway() {
        let address = Ipv4Addr::new(203, 0, 113, 10);
        let gateway = Ipv4Addr::new(203, 0, 113, 1);
        let request = arp_request([4; 6], gateway, address);
        for (offset, value) in [(12, 0x86), (14, 1), (18, 5), (21, 3), (22, 1), (28, 192)] {
            let mut bad = request.clone();
            bad[offset] = value;
            assert_eq!(arp_gateway(&Frame::parse(&bad).unwrap(), gateway), None);
        }
        let truncated = Frame::parse(&request[..41]).unwrap();
        assert_eq!(arp_gateway(&truncated, gateway), None);
        let empty_mac = arp_request([0; 6], gateway, address);
        assert_eq!(
            arp_gateway(&Frame::parse(&empty_mac).unwrap(), gateway),
            None
        );
        let packet = ip::packet(gateway.into(), address.into(), 1, &[8, 0, 0, 0]);
        let bytes = frame::frame([2; 6], [4; 6], frame::IPV4, &packet.0);
        assert_eq!(arp_gateway(&Frame::parse(&bytes).unwrap(), gateway), None);
    }

    #[test]
    fn all_ipv4_destinations_use_the_gateway_mac() {
        let address = "203.0.113.10".parse().unwrap();
        for destination in ["192.0.2.5", "198.51.100.27"] {
            let packet = ip::packet(address, destination.parse().unwrap(), 1, &[0, 0, 0, 0]);
            let bytes = outgoing(&packet.0, [2; 6], Some([4; 6])).unwrap();
            let parsed = Frame::parse(&bytes).unwrap();
            assert_eq!(
                (parsed.src, parsed.dst, parsed.ethertype),
                ([2; 6], [4; 6], frame::IPV4)
            );
            assert_eq!(
                frame::ip_packet(parsed.ethertype, parsed.payload),
                Some(packet.0.as_slice())
            );
            assert!(outgoing(&packet.0, [2; 6], None).is_none());
        }
    }

    #[test]
    fn oversized_and_ipv6_replies_are_dropped() {
        let packet = ip::packet(
            "203.0.113.10".parse().unwrap(),
            "192.0.2.5".parse().unwrap(),
            1,
            &[0; MTU - 20],
        );
        assert!(outgoing(&packet.0, [2; 6], Some([4; 6])).is_some());
        let mut oversized = packet.0;
        oversized.push(0);
        assert!(outgoing(&oversized, [2; 6], Some([4; 6])).is_none());
        let packet = ip::packet(
            "2001:db8::1".parse().unwrap(),
            "2001:db8::2".parse().unwrap(),
            58,
            &[0; 8],
        );
        assert!(outgoing(&packet.0, [2; 6], Some([4; 6])).is_none());
    }

    #[test]
    fn ethernet_padding_is_not_an_ip_payload() {
        let source = "192.0.2.5".parse().unwrap();
        let destination = "203.0.113.10".parse().unwrap();
        let packet = ip::packet(source, destination, 1, &[8, 0, 0, 0]);
        let bytes = frame::frame([2; 6], [4; 6], frame::IPV4, &packet.0);
        let parsed = Frame::parse(&bytes).unwrap();
        assert_eq!(
            frame::ip_packet(parsed.ethertype, parsed.payload),
            Some(packet.0.as_slice())
        );
        let mut malformed = bytes.clone();
        malformed[16..18].copy_from_slice(&200u16.to_be_bytes());
        let malformed = Frame::parse(&malformed).unwrap();
        assert!(frame::ip_packet(malformed.ethertype, malformed.payload).is_none());
        let vlan = frame::frame([2; 6], [4; 6], 0x8100, &packet.0);
        let vlan = Frame::parse(&vlan).unwrap();
        assert!(frame::ip_packet(vlan.ethertype, vlan.payload).is_none());
        let unknown = frame::frame([2; 6], [4; 6], 0x88b5, &packet.0);
        let unknown = Frame::parse(&unknown).unwrap();
        assert!(frame::ip_packet(unknown.ethertype, unknown.payload).is_none());
    }

    #[test]
    fn arp_answers_only_for_the_configured_address() {
        let mac = [2; 6];
        let peer = [4; 6];
        let address = "203.0.113.10".parse().unwrap();
        let mut payload = vec![0, 1, 8, 0, 6, 4, 0, 1];
        payload.extend_from_slice(&peer);
        payload.extend_from_slice(&[192, 0, 2, 5]);
        payload.extend_from_slice(&[0; 6]);
        payload.extend_from_slice(&[203, 0, 113, 10]);
        let bytes = frame::frame(frame::BROADCAST, peer, frame::ARP, &payload);
        let request = Frame::parse(&bytes).unwrap();
        let bytes = arp_reply(&request, mac, address).unwrap();
        let reply = Frame::parse(&bytes).unwrap();
        assert_eq!(
            (reply.src, reply.dst, reply.ethertype),
            (mac, peer, frame::ARP)
        );
        assert_eq!(&reply.payload[6..8], &[0, 2]);
        assert_eq!(&reply.payload[8..14], &mac);
        assert_eq!(&reply.payload[14..18], &[203, 0, 113, 10]);
        assert_eq!(&reply.payload[18..24], &peer);
        assert_eq!(&reply.payload[24..28], &[192, 0, 2, 5]);
        assert!(arp_reply(&request, mac, "203.0.113.11".parse().unwrap()).is_none());
        assert!(Frame::parse(&[0; 13]).is_none());
    }

    /// Linux answers to the hardware address the request gives, even when
    /// the frame came from another.
    #[test]
    fn arp_answers_the_sender_the_request_names() {
        let named = [6; 6];
        let mut payload = vec![0, 1, 8, 0, 6, 4, 0, 1];
        payload.extend_from_slice(&named);
        payload.extend_from_slice(&[192, 0, 2, 5]);
        payload.extend_from_slice(&[0; 6]);
        payload.extend_from_slice(&[203, 0, 113, 10]);
        let bytes = frame::frame(frame::BROADCAST, [4; 6], frame::ARP, &payload);
        let request = Frame::parse(&bytes).unwrap();
        let address = "203.0.113.10".parse().unwrap();
        let bytes = arp_reply(&request, [2; 6], address).unwrap();
        let reply = Frame::parse(&bytes).unwrap();
        assert_eq!(reply.dst, named);
        assert_eq!(&reply.payload[18..24], &named);
    }
}
