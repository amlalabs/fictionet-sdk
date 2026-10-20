//! A server card and IP stack, driven entirely by the simulated clock.
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::task::Poll;

use fictionet::prelude::*;
use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::network::ethernet::{Family, FromVm, Link, frame};
use fictionet::stdlib::network::ports::{Event, Ports};
use fictionet::stdlib::network::{ConnError, icmp, ip, tcp, udp};
use fictionet::stdlib::protocols::{dhcp, dns};
use fictionet::stdlib::services::serve;
use fictionet::{Cx, End, Interface, InterfaceExt, Packet};
use scan_world::{SCANNER, SERVER, SERVER_ADDR, SERVER_LEASE, office, start};

const MAC: [u8; 6] = [2, 0, 0, 0, 0, 50];
const SSH: &[u8] = b"SSH-2.0-test_server\r\n";

struct Mirror;

impl serve::Service for Mirror {
    type Decoder = fictionet::stdlib::codec::Collect<Vec<u8>, true>;
    type State = ();
    type Error = std::convert::Infallible;

    fn decoder(&self) -> Self::Decoder {
        fictionet::stdlib::codec::Collect::bytes(1024)
    }

    fn on_open(
        &mut self,
        _: &(),
        driver: &mut serve::Driver<'_, Self::Decoder>,
    ) -> Result<serve::Flow, Self::Error> {
        driver.reply().extend_from_slice(b"mirror bytes\n");
        Ok(serve::Flow::Close)
    }

    fn on_item(
        &mut self,
        _: Vec<u8>,
        _: &(),
        _: &mut serve::Driver<'_, Self::Decoder>,
    ) -> Result<serve::Flow, Self::Error> {
        Ok(serve::Flow::Close)
    }
}

fn bridge(fcx: &Cx, sandbox: End) -> End {
    let (vm, frames) = fictionet::pair();
    fcx.spawn(move |fcx| async move {
        let mut link = Link::new(Family::Serve(SERVER_LEASE), Family::Off, 1500)?;
        let mut ports = Ports::new(vec![sandbox, frames]);
        loop {
            match ports.next(&fcx, None, |_| Poll::Pending).await? {
                Event::Packet(0, packet) => {
                    let mut frame = link.to_vm(&packet.0).expect("learned VM MAC").to_vec();
                    frame.extend_from_slice(&packet.0);
                    ports.send(1, Packet(frame));
                }
                Event::Packet(1, frame) => match link.frame_from_vm(&frame.0) {
                    FromVm::World(packet) => ports.send(0, Packet(packet.to_vec())),
                    FromVm::Answer(reply) => ports.send(1, Packet(reply)),
                    FromVm::Drop(why) => panic!("unexpected frame drop: {why:?}"),
                },
                Event::Closed(_) => break,
                _ => unreachable!(),
            }
        }
        Ok(())
    });
    vm
}

async fn lease(fcx: &Cx, frames: &mut End) {
    let mut request = dhcp::Message::new(dhcp::BOOTREQUEST, 7);
    request.chaddr[..6].copy_from_slice(&MAC);
    request.push(dhcp::opt::MESSAGE_TYPE, [dhcp::DISCOVER]);
    for expected in [dhcp::OFFER, dhcp::ACK] {
        let data = request.to_bytes().unwrap();
        let mut datagram = vec![0; 8 + data.len()];
        udp::encode(
            (Ipv4Addr::UNSPECIFIED, 68).into(),
            (Ipv4Addr::BROADCAST, 67).into(),
            &data,
            &mut datagram,
        )
        .unwrap();
        let packet = ip::packet(
            Ipv4Addr::UNSPECIFIED.into(),
            Ipv4Addr::BROADCAST.into(),
            17,
            &datagram,
        )
        .0;
        frames.send(Packet(frame::frame(
            frame::BROADCAST,
            MAC,
            frame::IPV4,
            &packet,
        )));
        let reply = frames.recv(fcx).await.unwrap();
        let ethernet = frame::Frame::parse(&reply.0).unwrap();
        assert_eq!(ethernet.dst, frame::BROADCAST);
        let h = ip::Header::parse(ethernet.payload).unwrap();
        let offer = dhcp::Message::parse(&h.payload(ethernet.payload)[8..]).unwrap();
        assert_eq!(offer.message_type(), Some(expected));
        assert_eq!(offer.xid, 7);
        assert_eq!(offer.yiaddr, SERVER_ADDR);
        assert_eq!(
            offer.option_addr(dhcp::opt::SUBNET_MASK),
            Some(Ipv4Addr::new(255, 255, 255, 0))
        );
        assert_eq!(offer.option_addr(dhcp::opt::ROUTER), SERVER_LEASE.gateway);
        assert_eq!(offer.option_addr(dhcp::opt::DNS), SERVER_LEASE.dns);
        request = dhcp::Message::new(dhcp::BOOTREQUEST, 7);
        request.chaddr[..6].copy_from_slice(&MAC);
        request.push(dhcp::opt::MESSAGE_TYPE, [dhcp::REQUEST]);
        request.push(dhcp::opt::REQUESTED_IP, SERVER_ADDR.octets());
        request.push(
            dhcp::opt::SERVER_ID,
            offer.option_addr(dhcp::opt::SERVER_ID).unwrap().octets(),
        );
    }
}

fn vm_stack(fcx: &Cx, frames: End) -> End {
    let (stack, packets) = fictionet::pair();
    fcx.spawn(move |fcx| async move {
        let mut ports = Ports::new(vec![frames, packets]);
        loop {
            match ports.next(&fcx, None, |_| Poll::Pending).await? {
                Event::Packet(0, frame) => {
                    let eth = frame::Frame::parse(&frame.0).unwrap();
                    assert_eq!(eth.dst, MAC);
                    assert_eq!(eth.src, frame::GATEWAY_MAC);
                    let h = ip::Header::parse(eth.payload).unwrap();
                    assert_eq!(h.dst, SERVER_ADDR);
                    ports.send(1, Packet(eth.payload[..h.payload.end].to_vec()));
                }
                Event::Packet(1, packet) => ports.send(
                    0,
                    Packet(frame::frame(
                        frame::GATEWAY_MAC,
                        MAC,
                        frame::IPV4,
                        &packet.0,
                    )),
                ),
                Event::Closed(_) => break,
                _ => unreachable!(),
            }
        }
        Ok(())
    });
    stack
}

fn listeners(fcx: &Cx, tcp: &tcp::Endpoint) {
    for (port, banner) in [(22, SSH), (80, &b"server web\n"[..])] {
        let mut listener = tcp.listen(port).unwrap();
        fcx.spawn(move |fcx| async move {
            while let Ok(mut conn) = listener.accept(&fcx).await {
                conn.write_all(&fcx, banner).await?;
                conn.shutdown(&fcx).await?;
            }
            Ok(())
        });
    }
}

async fn banner(fcx: &Cx, tcp: &tcp::Endpoint, to: SocketAddr, expected: &[u8]) {
    let mut conn = tcp.connect(fcx, to).await.unwrap();
    let mut bytes = vec![0; expected.len()];
    let mut filled = 0;
    while filled < bytes.len() {
        let n = conn.read(fcx, &mut bytes[filled..]).await.unwrap();
        assert_ne!(n, 0);
        filled += n;
    }
    assert_eq!(bytes, expected);
}

#[test]
fn server_card_reaches_the_office_and_accepts_scans_and_admin_connections() {
    fictionet::block_on(fictionet::lab(
        fictionet::RunOptions::new(fictionet::Seed::from_u64(42)),
        |fcx| async move {
            let (attacher, attachments) = fictionet::attachments();
            let net = office()
                .host("mirror", |h| {
                    h.dns_name("archive.ubuntu.com")
                        .tcp(80, Arc::new(()), || Mirror)
                })
                .route("jump", "10.10.5.20/32".parse().unwrap());
            start(&fcx, net, attachments)?;
            let mut frames = bridge(&fcx, attacher.attach(SERVER)?);
            lease(&fcx, &mut frames).await;
            let (t, u, mut echo, _other) = ip::split_protocols(&fcx, vm_stack(&fcx, frames));
            let server = tcp::endpoint(&fcx, t, SERVER_ADDR.into());
            listeners(&fcx, &server);
            fcx.spawn(move |fcx| async move {
                while let Ok(packet) = echo.recv(&fcx).await {
                    echo.send(icmp::echo_reply(&packet, SERVER_ADDR.into()).unwrap());
                }
                Ok(())
            });
            let (t, _u, mut ping, _o) = ip::split_protocols(&fcx, attacher.attach(SCANNER)?);
            let scanner_addr = Ipv4Addr::new(10, 0, 9, 2);
            let scanner = tcp::endpoint(&fcx, t, scanner_addr.into());
            let mut payload = [8, 0, 0, 0, 0x51, 0x52, 0, 1];
            let sum = ip::checksum(&payload);
            payload[2..4].copy_from_slice(&sum.to_be_bytes());
            ping.send(ip::packet(
                scanner_addr.into(),
                SERVER_ADDR.into(),
                1,
                &payload,
            ));
            let reply = ping.recv(&fcx).await?;
            let h = ip::Header::parse(&reply.0).unwrap();
            assert_eq!((h.src, h.dst), (SERVER_ADDR.into(), scanner_addr.into()));
            assert_eq!(h.payload(&reply.0), &[0, 0, 174, 172, 0x51, 0x52, 0, 1]);
            banner(&fcx, &scanner, (SERVER_ADDR, 22).into(), SSH).await;
            banner(&fcx, &scanner, (SERVER_ADDR, 80).into(), b"server web\n").await;
            assert!(matches!(
                scanner.connect(&fcx, (SERVER_ADDR, 25).into()).await,
                Err(ConnError::Refused)
            ));
            let udp = udp::endpoint(&fcx, u, SERVER_ADDR.into());
            let mut dns_socket = udp.bind(49152)?;
            let mut query = dns::op::Message::query();
            query.queries.push(dns::op::Query::query(
                dns::rr::Name::from_ascii("archive.ubuntu.com").unwrap(),
                dns::rr::RecordType::A,
            ));
            dns_socket.send_to(
                &query.to_vec().unwrap(),
                (SERVER_LEASE.dns.unwrap(), 53).into(),
            );
            let (bytes, from) = dns_socket.recv(&fcx).await?;
            assert_eq!(from, (SERVER_LEASE.dns.unwrap(), 53).into());
            let answer = dns::op::Message::from_vec(&bytes).unwrap();
            assert_eq!(answer.answers.len(), 1);
            let dns::rr::RData::A(addr) = answer.answers[0].data else {
                panic!("expected A record")
            };
            banner(&fcx, &server, (addr.0, 80).into(), b"mirror bytes\n").await;
            let jump = tcp::endpoint(
                &fcx,
                attacher.attach("jump")?,
                "10.10.5.20".parse().unwrap(),
            );
            banner(&fcx, &jump, (SERVER_ADDR, 22).into(), SSH).await;
            fcx.cancel();
            Ok(())
        },
    ))
    .unwrap();
}
