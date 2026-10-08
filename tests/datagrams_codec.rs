//! One datagram per bounded collection, with exact wire round trips, and
//! Wake-on-LAN magic packets found in a datagram's payload.

use core::fmt::Debug;
use std::net::{Ipv4Addr, Ipv6Addr};

use fictionet::stdlib::codec::{
    Collect, CollectError, Decode, Fail, Lcg, Stream, Wire, finish, pump,
};
use fictionet::stdlib::test_support::contract;

use fictionet::stdlib::test_support::{chunks, decode_all, mutate};
use fictionet::stdlib::{geneve, gre, igmp, ipsec, ospf, pim, rip, vrrp, wake_on_lan as wol};

fn round_trip<M>(value: &M, limit: usize) -> Vec<u8>
where
    M: Wire + Clone + Debug + PartialEq,
    M::ParseError: Clone + Debug + PartialEq,
    M::WriteError: Debug,
{
    let bytes = contract::check_written(value);
    assert!(bytes.len() <= limit);
    assert_eq!(
        contract::check_decode_with_alloc_limit(|| Collect::<M>::new(limit), &bytes, 2 * (limit + 1)),
        (vec![value.clone()], None)
    );

    let mut stream = Stream::new(Collect::<M>::new(limit));
    for chunk in chunks(&bytes, &[1, 7, 2, 31]) {
        assert_eq!(stream.push(chunk), chunk.len());
        assert!(stream.next().is_none());
        assert!(stream.buffered() <= limit);
        assert_eq!(stream.held(), 0);
    }
    stream.end();
    let (decoded, span) = stream.next_span().unwrap().unwrap();
    assert_eq!(&decoded, value);
    assert_eq!(span, 0..bytes.len() as u64);
    // The collection's configured limit fails before EOF, once.
    if !bytes.is_empty() {
        let small = bytes.len() - 1;
        assert_eq!(
            contract::check_decode_with_alloc_limit(|| Collect::<M>::new(small), &bytes, 2 * (small + 1)),
            (vec![], Some(Fail::Protocol(CollectError::TooLong { limit: small })))
        );
        let mut stream = Stream::new(Collect::<M>::new(small));
        assert_eq!(stream.push(&bytes), bytes.len());
        let error = Fail::Protocol(CollectError::TooLong { limit: small });
        assert_eq!(stream.next(), Some(Err(error)));
    }
    bytes
}

fn parse_failure<M>(bytes: &[u8], limit: usize)
where
    M: Wire + Debug + PartialEq,
    M::ParseError: Clone + Debug + PartialEq,
{
    let expected = M::parse(bytes).unwrap_err();
    assert_eq!(
        contract::check_decode_with_alloc_limit(|| Collect::<M>::new(limit), bytes, 2 * (limit + 1)),
        (vec![], Some(Fail::Protocol(CollectError::Parse(expected.clone()))))
    );
    let mut stream = Stream::new(Collect::<M>::new(limit));
    assert_eq!(stream.push(bytes), bytes.len());
    assert!(stream.next().is_none());
    stream.end();
    let error = Fail::Protocol(CollectError::Parse(expected));
    assert_eq!(stream.next(), Some(Err(error.clone())));
}

#[test]
fn geneve_datagram() {
    let packet = geneve::Packet {
        header: geneve::Header {
            control: false,
            protocol: geneve::protocol::IPV4,
            vni: 42,
            options: vec![geneve::GeneveOption {
                class: 0x102,
                kind: 3,
                critical: true,
                data: vec![1, 2, 3, 4],
            }],
        },
        payload: vec![0x45, 0, 0, 20],
    };
    round_trip(&packet, geneve::MAX_DATAGRAM);
    let mut header = round_trip(&packet.header, geneve::MAX_HEADER_LEN);
    header.push(0);
    assert_eq!(
        geneve::Header::parse(&header),
        Err(geneve::Error::Trailing { remaining: 1 })
    );
    parse_failure::<geneve::Header>(&header, geneve::MAX_HEADER_LEN);
    parse_failure::<geneve::Packet>(&[], geneve::MAX_DATAGRAM);
    let mut bad = packet;
    bad.header.vni = geneve::MAX_VNI + 1;
    contract::check_refused(&bad);
}

#[test]
fn gre_packets_and_exact_pptp_boundary() {
    let packet = gre::Packet {
        header: gre::Header::Gre(gre::PlainHeader {
            protocol: gre::protocol::IPV4,
            checksum: true,
            key: Some(7),
            sequence: Some(9),
        }),
        payload: vec![0x45, 0, 1],
    };
    round_trip(&packet, gre::MAX_PACKET);
    let pptp = gre::Packet {
        header: gre::Header::Pptp(gre::PptpHeader {
            call_id: 3,
            sequence: Some(7),
            ack: Some(6),
        }),
        payload: vec![1, 2, 3],
    };
    let mut padded = round_trip(&pptp, gre::MAX_PACKET);
    padded.extend_from_slice(&[0, 0]);
    assert_eq!(
        <gre::Packet as Wire>::parse(&padded),
        Err(gre::Error::Trailing { remaining: 2 })
    );
    parse_failure::<gre::Packet>(&padded, gre::MAX_PACKET);
    parse_failure::<gre::Packet>(&[], gre::MAX_PACKET);
    contract::check_refused(&gre::Packet {
        payload: vec![],
        ..pptp
    });
}

fn igmp_checksum(bytes: &mut [u8]) {
    bytes.get_mut(2..4).unwrap().fill(0);
    let checksum = fictionet::stdlib::ip::checksum(bytes);
    bytes
        .get_mut(2..4)
        .unwrap()
        .copy_from_slice(&checksum.to_be_bytes());
}

#[test]
fn igmp_versions_auxiliary_data_and_exact_boundary() {
    round_trip(&igmp::Code(992), 1);
    contract::check_refused(&igmp::Code(1000));
    let group = Ipv4Addr::new(239, 1, 2, 3);
    let messages = [
        igmp::Message::Query {
            max_resp_time: 0,
            group: Ipv4Addr::UNSPECIFIED,
        },
        igmp::Message::ReportV1 { group },
        igmp::Message::ReportV2 { group },
        igmp::Message::Leave { group },
        igmp::Message::QueryV3(igmp::QueryV3 {
            max_resp_code: 100,
            group,
            suppress: true,
            qrv: 2,
            qqic: 125,
            sources: vec![Ipv4Addr::new(192, 0, 2, 1)],
        }),
        igmp::Message::ReportV3 {
            records: vec![igmp::GroupRecord {
                kind: igmp::RecordType::ModeIsExclude,
                group,
                sources: vec![],
            }],
        },
    ];
    for message in &messages {
        let mut padded = round_trip(message, igmp::MAX_MESSAGE);
        // An eight-byte query becomes a different query format when extended.
        if matches!(message, igmp::Message::Query { .. }) {
            continue;
        }
        padded.extend_from_slice(&[0, 0, 0, 0]);
        igmp_checksum(&mut padded);
        assert_eq!(
            <igmp::Message as Wire>::parse(&padded),
            Err(igmp::Error::Trailing { remaining: 4 })
        );
        parse_failure::<igmp::Message>(&padded, igmp::MAX_MESSAGE);
    }
    let report = messages.last().unwrap();
    let mut auxiliary = Wire::to_bytes(report).unwrap();
    *auxiliary.get_mut(9).unwrap() = 1;
    auxiliary.extend_from_slice(&[1, 2, 3, 4]);
    igmp_checksum(&mut auxiliary);
    assert_eq!(
        <igmp::Message as Wire>::parse(&auxiliary).as_ref(),
        Ok(report)
    );
    contract::check_wire::<igmp::Message>(&auxiliary);
    contract::check_decode_with_alloc_limit(
        || Collect::<igmp::Message>::new(igmp::MAX_MESSAGE),
        &auxiliary,
        2 * (igmp::MAX_MESSAGE + 1),
    );
    parse_failure::<igmp::Message>(&[], igmp::MAX_MESSAGE);
    contract::check_refused(&igmp::Message::Query {
        max_resp_time: 0,
        group,
    });
}

#[test]
fn ipsec_carriers() {
    let esp = ipsec::EspPacket {
        spi: 7,
        sequence: 11,
        payload: vec![0xde, 0xad, 0, 4],
    };
    round_trip(&esp, ipsec::MAX_PACKET);
    let ah = ipsec::AhPacket {
        header: ipsec::AhHeader::new(ipsec::next_header::IPV4, 9, 12, vec![0xa5; 12]),
        payload: vec![0x45, 0, 0, 20],
    };
    round_trip(&ah, ipsec::MAX_PACKET);
    let mut header = round_trip(&ah.header, ipsec::MAX_AH_LEN);
    header.push(0);
    assert_eq!(
        ipsec::AhHeader::parse(&header),
        Err(ipsec::Error::Trailing { remaining: 1 })
    );
    parse_failure::<ipsec::AhHeader>(&header, ipsec::MAX_AH_LEN);
    let plain = ipsec::Plaintext::padded(vec![1, 2, 3], 4, 8).unwrap();
    round_trip(&plain, ipsec::MAX_PACKET);
    for datagram in [
        ipsec::Datagram::Keepalive,
        ipsec::Datagram::Ike(vec![1, 2]),
        ipsec::Datagram::Esp(esp.clone()),
    ] {
        round_trip(&datagram, ipsec::MAX_DATAGRAM);
    }
    parse_failure::<ipsec::EspPacket>(&[], ipsec::MAX_PACKET);
    parse_failure::<ipsec::AhPacket>(&[], ipsec::MAX_PACKET);
    parse_failure::<ipsec::Datagram>(&[], ipsec::MAX_DATAGRAM);
    contract::check_refused(&ipsec::EspPacket { spi: 0, ..esp });
    let mut bad = ah;
    bad.header.icv.push(0);
    contract::check_refused(&bad);
}

#[test]
fn rip_and_ripng_messages() {
    for version in [rip::Version::V1, rip::Version::V2] {
        round_trip(
            &rip::Message::whole_table_request(version),
            rip::MAX_MESSAGE,
        );
    }
    let route = rip::RouteEntry {
        tag: 0,
        address: Ipv4Addr::new(10, 0, 0, 0),
        mask: Ipv4Addr::new(255, 0, 0, 0),
        next_hop: Ipv4Addr::UNSPECIFIED,
        metric: 1,
    };
    let received = rip::Message {
        command: rip::Command::Response,
        version: rip::Version::V2,
        auth: Some(rip::Auth::Crypto(rip::Crypto {
            key_id: 1,
            sequence: 2,
            data_len: 255,
            data: vec![0xa5; 255],
        })),
        entries: rip::Entries::Routes(vec![route; rip::MAX_ENTRIES - 1]),
    };
    let bytes = round_trip(&received, rip::MAX_MESSAGE);
    assert_eq!(bytes.len(), rip::MAX_MESSAGE);
    assert!(!received.fits_datagram());
    assert_eq!(received.to_bytes().unwrap(), bytes);
    assert_eq!(rip::Message::parse(&bytes), Ok(received));
    round_trip(&rip::NgMessage::whole_table_request(), rip::MAX_NG_MESSAGE);
    let ng = rip::NgMessage {
        command: rip::Command::Response,
        entries: rip::NgEntries::Entries(vec![rip::NgEntry::NextHop(Ipv6Addr::LOCALHOST)]),
    };
    contract::check_refused(&ng); // The parser normalizes this next hop to ::.
    parse_failure::<rip::Message>(&[], rip::MAX_MESSAGE);
    parse_failure::<rip::NgMessage>(&[], rip::MAX_NG_MESSAGE);
}

// Context stays in a closure, as in the RPC/NFS reference stack.
fn context_round_trip<D, M, E>(bytes: &[u8], limit: usize, parse: impl Fn(&[u8]) -> Result<M, E>)
where
    D: Wire + Clone + Debug + PartialEq,
    D::ParseError: Clone + Debug + PartialEq,
    D::WriteError: Debug,
    M: Debug + PartialEq,
    E: Debug + PartialEq,
{
    let raw = D::parse(bytes).unwrap();
    assert_eq!(round_trip(&raw, limit), bytes);
    let make =
        || Collect::<D>::new(limit).map(|datagram| parse(&Wire::to_bytes(&datagram).unwrap()));
    let (items, failure) = contract::check_decode_with_alloc_limit(make, bytes, 2 * (limit + 1));
    assert_eq!(items, vec![parse(bytes)]);
    assert_eq!(failure, None);
}

#[test]
fn ospf_context_stays_in_the_mapping() {
    let endpoints = [
        ospf::Endpoints::V4 {
            source: Ipv4Addr::new(192, 0, 2, 1),
            destination: ospf::ALL_SPF_ROUTERS_V4,
        },
        ospf::Endpoints::V6 {
            source: "fe80::1".parse().unwrap(),
            destination: ospf::ALL_SPF_ROUTERS_V6,
        },
    ];
    for endpoints in endpoints {
        let header = match endpoints {
            ospf::Endpoints::V4 { .. } => ospf::Header::V2 {
                auth: ospf::Auth::Null,
            },
            ospf::Endpoints::V6 { .. } => ospf::Header::V3 { instance_id: 1 },
        };
        let packet = ospf::Packet {
            router_id: Ipv4Addr::new(192, 0, 2, 1),
            area_id: Ipv4Addr::UNSPECIFIED,
            header,
            lls: None,
            body: ospf::Body::LinkStateRequest(vec![ospf::LsaKey {
                ls_type: 1,
                link_state_id: Ipv4Addr::new(192, 0, 2, 2),
                advertising_router: Ipv4Addr::new(192, 0, 2, 3),
            }]),
        };
        let mut bytes = packet.frame(&endpoints).and_then(|frame| frame.to_bytes()).unwrap();
        assert_eq!(ospf::Packet::parse(&bytes, &endpoints), Ok(packet));
        context_round_trip::<ospf::Datagram, _, _>(&bytes, ospf::MAX_MESSAGE, |b| {
            ospf::Packet::parse(b, &endpoints)
        });
        *bytes.get_mut(12).unwrap() ^= 1;
        assert_eq!(
            ospf::Packet::parse(&bytes, &endpoints),
            Err(ospf::Error::Checksum)
        );
        context_round_trip::<ospf::Datagram, _, _>(&bytes, ospf::MAX_MESSAGE, |b| {
            ospf::Packet::parse(b, &endpoints)
        });
        bytes.pop();
        context_round_trip::<ospf::Datagram, _, _>(&bytes, ospf::MAX_MESSAGE, |b| {
            ospf::Packet::parse(b, &endpoints)
        });
    }
    contract::check_refused(&ospf::Datagram(vec![0; ospf::MAX_MESSAGE + 1]));
    parse_failure::<ospf::Datagram>(&vec![0; ospf::MAX_MESSAGE + 1], ospf::MAX_MESSAGE + 1);
}

#[test]
fn pim_context_stays_in_the_mapping() {
    let endpoints = [
        pim::Endpoints::V4 {
            source: Ipv4Addr::new(192, 0, 2, 1),
            destination: pim::ALL_PIM_ROUTERS_V4,
        },
        pim::Endpoints::V6 {
            source: "fe80::1".parse().unwrap(),
            destination: pim::ALL_PIM_ROUTERS_V6,
        },
    ];
    for endpoints in endpoints {
        let message = pim::Message::Hello(vec![pim::HelloOption::Holdtime(105)]);
        let mut bytes = message.frame(&endpoints).and_then(|frame| frame.to_bytes()).unwrap();
        assert_eq!(pim::Message::parse(&bytes, &endpoints), Ok(message));
        context_round_trip::<pim::Datagram, _, _>(&bytes, pim::MAX_MESSAGE, |b| {
            pim::Message::parse(b, &endpoints)
        });
        *bytes.get_mut(2).unwrap() ^= 1;
        assert_eq!(
            pim::Message::parse(&bytes, &endpoints),
            Err(pim::Error::Checksum)
        );
        context_round_trip::<pim::Datagram, _, _>(&bytes, pim::MAX_MESSAGE, |b| {
            pim::Message::parse(b, &endpoints)
        });
        context_round_trip::<pim::Datagram, _, _>(&[], pim::MAX_MESSAGE, |b| {
            pim::Message::parse(b, &endpoints)
        });
    }
    contract::check_refused(&pim::Datagram(vec![0; pim::MAX_MESSAGE + 1]));
    parse_failure::<pim::Datagram>(&vec![0; pim::MAX_MESSAGE + 1], pim::MAX_MESSAGE + 1);
}

#[test]
fn vrrp_context_stays_in_the_mapping() {
    let v4 = vrrp::Endpoints::V4 {
        source: Ipv4Addr::new(192, 0, 2, 1),
        destination: vrrp::GROUP_V4,
    };
    let v6 = vrrp::Endpoints::V6 {
        source: "fe80::1".parse().unwrap(),
        destination: vrrp::GROUP_V6,
    };
    let cases = [
        (
            v4,
            vrrp::Advertisement::V2(vrrp::AdvertisementV2 {
                vrid: 1,
                priority: 100,
                auth_type: 0,
                interval: 1,
                addresses: vec![Ipv4Addr::new(192, 0, 2, 10)],
                auth_data: [0; 8],
            }),
        ),
        (
            v4,
            vrrp::Advertisement::V3(vrrp::AdvertisementV3 {
                vrid: 1,
                priority: 100,
                interval: 100,
                addresses: vrrp::Addresses::V4(vec![Ipv4Addr::new(192, 0, 2, 10)]),
            }),
        ),
        (
            v6,
            vrrp::Advertisement::V3(vrrp::AdvertisementV3 {
                vrid: 1,
                priority: 100,
                interval: 100,
                addresses: vrrp::Addresses::V6(vec!["fe80::10".parse().unwrap()]),
            }),
        ),
    ];
    for (endpoints, advertisement) in cases {
        let mut bytes = advertisement.frame(&endpoints).and_then(|frame| frame.to_bytes()).unwrap();
        assert_eq!(
            vrrp::Advertisement::parse(&bytes, &endpoints),
            Ok(advertisement)
        );
        context_round_trip::<vrrp::Datagram, _, _>(&bytes, vrrp::MAX_MESSAGE, |b| {
            vrrp::Advertisement::parse(b, &endpoints)
        });
        *bytes.get_mut(6).unwrap() ^= 1;
        assert_eq!(
            vrrp::Advertisement::parse(&bytes, &endpoints),
            Err(vrrp::Error::Checksum)
        );
        context_round_trip::<vrrp::Datagram, _, _>(&bytes, vrrp::MAX_MESSAGE, |b| {
            vrrp::Advertisement::parse(b, &endpoints)
        });
        bytes.push(0);
        assert_eq!(
            vrrp::Advertisement::parse(&bytes, &endpoints),
            Err(vrrp::Error::Trailing { remaining: 1 })
        );
        context_round_trip::<vrrp::Datagram, _, _>(&bytes, vrrp::MAX_MESSAGE, |b| {
            vrrp::Advertisement::parse(b, &endpoints)
        });
    }
    contract::check_refused(&vrrp::Datagram(vec![0; vrrp::MAX_MESSAGE + 1]));
    parse_failure::<vrrp::Datagram>(&vec![0; vrrp::MAX_MESSAGE + 1], vrrp::MAX_MESSAGE + 1);
}

#[test]
fn streams_report_header_errors_once() {
    parse_failure::<geneve::Packet>(&[0x40], geneve::MAX_DATAGRAM);
    parse_failure::<igmp::Message>(&[0xff], igmp::MAX_MESSAGE);
    parse_failure::<ipsec::EspPacket>(&[0; 4], ipsec::MAX_PACKET);
}

const MAC: wol::Mac = [0, 1, 2, 3, 4, 5];

#[test]
fn wake_on_lan_payload_and_exact_packet() {
    for password in [
        None,
        Some(wol::Password::Four([1, 2, 3, 4])),
        Some(wol::Password::Six([1, 2, 3, 4, 5, 6])),
    ] {
        let packet = wol::MagicPacket { mac: MAC, password };
        contract::check_wire_value(&packet);
        let bytes = Wire::to_bytes(&packet).unwrap();
        contract::check_wire::<wol::MagicPacket>(&bytes);
        let mut payload = b"prefix".to_vec();
        payload.extend_from_slice(&bytes);
        contract::check_decode_with_alloc_limit(
            wol::MagicPackets::new,
            &payload,
            2 * wol::MagicPackets::new().capacity(),
        );
        assert!(<wol::MagicPacket as Wire>::parse(&payload).is_err());
        let mut stream = Stream::new(wol::MagicPackets::new());
        pump(&mut stream, &payload, |_| panic!("packet before EOF")).unwrap();
        let mut got = Vec::new();
        finish(&mut stream, |p| got.push(p)).unwrap();
        assert_eq!(got, [(6, packet)]);
        assert_eq!(
            <wol::MagicPacket as Wire>::parse(&Wire::to_bytes(&got[0].1).unwrap()),
            Ok(packet)
        );
    }
    let bytes = wol::MagicPacket::new(MAC).to_bytes().unwrap();
    for tail in [1, 2, 3, 5, 7] {
        let mut payload = bytes.clone();
        payload.extend(vec![7; tail]);
        assert!(<wol::MagicPacket as Wire>::parse(&payload).is_err());
        assert_eq!(
            decode_all(wol::MagicPackets::new, &payload),
            (vec![(0, wol::MagicPacket::new(MAC))], None)
        );
    }
    contract::check_decode_with_alloc_limit(
        wol::MagicPackets::new,
        b"no packet",
        2 * wol::MagicPackets::new().capacity(),
    );
    assert_eq!(
        decode_all(wol::MagicPackets::new, b"no packet"),
        (vec![], Some(Fail::Protocol(wol::Error::NotFound)))
    );
}

#[test]
fn wake_on_lan_rejects_oversize_payload() {
    let mut payload = vec![0; wol::MAX_PAYLOAD - wol::PACKET_LEN];
    payload.extend(wol::MagicPacket::new(MAC).to_bytes().unwrap());
    assert_eq!(
        decode_all(wol::MagicPackets::new, &payload),
        (
            vec![(
                wol::MAX_PAYLOAD - wol::PACKET_LEN,
                wol::MagicPacket::new(MAC)
            )],
            None
        )
    );
    payload.push(0);
    let mut stream = Stream::new(wol::MagicPackets::new());
    assert_eq!(stream.decoder().capacity(), wol::MAX_PAYLOAD + 1);
    assert_eq!(stream.push(&payload), wol::MAX_PAYLOAD + 1);
    assert_eq!(
        stream.next(),
        Some(Err(Fail::Protocol(wol::Error::TooLong)))
    );
    assert!(stream.next().is_none());
    contract::check_decode_with_alloc_limit(
        wol::MagicPackets::new,
        &payload,
        2 * wol::MagicPackets::new().capacity(),
    );
}

#[test]
fn wake_on_lan_contracts_on_mutated_payloads() {
    let mut rng = Lcg::new(0x5eed);
    let seed = wol::MagicPacket::with_password(MAC, wol::Password::Six([9; 6]))
        .to_bytes()
        .unwrap();
    for _ in 0..64 {
        let mut bytes = seed.clone();
        for _ in 0..rng.index(4) {
            mutate(&mut rng, &mut bytes);
        }
        let end = rng.index(bytes.len() + 1);
        bytes.truncate(end);
        contract::check_decode_with_alloc_limit(
            wol::MagicPackets::new,
            &bytes,
            2 * wol::MagicPackets::new().capacity(),
        );
        // Adapter consistency: the decoder finds the packet as `find` does.
        let expected = match wol::MagicPacket::find(&bytes) {
            Ok(packet) => (vec![packet], None),
            Err(e) => (vec![], Some(Fail::Protocol(e))),
        };
        assert_eq!(decode_all(wol::MagicPackets::new, &bytes), expected);
    }
}
