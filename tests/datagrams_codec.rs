//! One datagram per bounded collection, with exact wire round trips.

use core::fmt::Debug;
use std::net::{Ipv4Addr, Ipv6Addr};

use fictionet::stdlib::codec::{
    Collect, CollectError, Decode, Fail, Stream, Wire, contract, finish, pump, test_support::chunks,
};
use fictionet::stdlib::{geneve, gre, igmp, ipsec, ospf, pim, rip, vrrp};

fn round_trip<M>(value: &M, limit: usize) -> Vec<u8>
where
    M: Wire + Clone + Debug + PartialEq,
    M::ParseError: Clone + Debug + PartialEq,
    M::WriteError: Debug,
{
    contract::check_wire_value(value);
    let bytes = Wire::to_bytes(value).unwrap();
    assert!(bytes.len() <= limit);
    contract::check_wire::<M>(&bytes);
    contract::check_decode(|| Collect::<M>::new(limit), &bytes);
    for pattern in [&[][..], &[1][..], &[3, 1, 17][..]] {
        let mut stream = Stream::new(Collect::<M>::new(limit));
        for part in chunks(&bytes, pattern) {
            assert_eq!(
                pump(&mut stream, part, |_| panic!("item before EOF")),
                Ok(part.len())
            );
            assert!(stream.buffered() <= limit);
            assert_eq!(stream.held(), 0);
        }
        stream.end();
        let (decoded, span) = stream.next_span().unwrap().unwrap();
        assert_eq!(&decoded, value);
        assert_eq!(span, 0..bytes.len() as u64);
        let mut out = vec![0xa5];
        Wire::write(&decoded, &mut out).unwrap();
        assert_eq!(out.first(), Some(&0xa5));
        assert_eq!(M::parse(out.get(1..).unwrap()).as_ref(), Ok(value));
        assert_eq!(stream.next(), None);
        assert!(stream.is_done());
        assert_eq!(stream.failed(), None);
    }
    // The collection's configured limit fails before EOF, once.
    if !bytes.is_empty() {
        let small = bytes.len() - 1;
        contract::check_decode(|| Collect::<M>::new(small), &bytes);
        let mut stream = Stream::new(Collect::<M>::new(small));
        assert_eq!(stream.push(&bytes), bytes.len());
        let error = Fail::Protocol(CollectError::TooLong { limit: small });
        assert_eq!(stream.next(), Some(Err(error.clone())));
        assert_eq!(stream.failed(), Some(&error));
        assert_eq!(stream.next(), None);
    }
    bytes
}

fn parse_failure<M>(bytes: &[u8], limit: usize)
where
    M: Wire + Debug + PartialEq,
    M::ParseError: Clone + Debug + PartialEq,
{
    let expected = M::parse(bytes).unwrap_err();
    contract::check_decode(|| Collect::<M>::new(limit), bytes);
    let mut stream = Stream::new(Collect::<M>::new(limit));
    for part in chunks(bytes, &[1]) {
        assert_eq!(
            pump(&mut stream, part, |_| panic!("item before EOF")),
            Ok(part.len())
        );
    }
    stream.end();
    let error = Fail::Protocol(CollectError::Parse(expected));
    assert_eq!(stream.next(), Some(Err(error.clone())));
    assert_eq!(stream.failed(), Some(&error));
    assert_eq!(stream.next(), None);
}

fn refused<M: Wire + Debug + PartialEq>(value: &M) {
    contract::check_wire_value(value);
    let mut out = vec![1, 2, 3];
    assert!(Wire::write(value, &mut out).is_err());
    assert_eq!(out, [1, 2, 3]);
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
    parse_failure::<geneve::Packet>(&[], geneve::MAX_DATAGRAM);
    let mut bad = packet;
    bad.header.vni = geneve::MAX_VNI + 1;
    refused(&bad);
}

#[test]
fn gre_packets_and_exact_pptp_boundary() {
    let packet = gre::Packet {
        header: gre::Header::Gre(gre::GreHeader {
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
    assert_eq!(gre::Packet::parse(&padded), Ok(pptp.clone()));
    assert_eq!(
        <gre::Packet as Wire>::parse(&padded),
        Err(gre::ParseError::Trailing { remaining: 2 })
    );
    let mut legacy = gre::Decoder::new();
    legacy.feed(&padded).unwrap();
    assert_eq!(legacy.finish(), Ok(pptp.clone()));
    parse_failure::<gre::Packet>(&padded, gre::MAX_PACKET);
    parse_failure::<gre::Packet>(&[], gre::MAX_PACKET);
    refused(&gre::Packet {
        payload: vec![],
        ..pptp
    });
}

fn igmp_checksum(bytes: &mut [u8]) {
    bytes.get_mut(2..4).unwrap().fill(0);
    let checksum = igmp::checksum(bytes);
    bytes
        .get_mut(2..4)
        .unwrap()
        .copy_from_slice(&checksum.to_be_bytes());
}

#[test]
fn igmp_versions_auxiliary_data_and_exact_boundary() {
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
        assert_eq!(igmp::Message::parse(&padded).as_ref(), Ok(message));
        assert_eq!(
            <igmp::Message as Wire>::parse(&padded),
            Err(igmp::ParseError::Trailing { remaining: 4 })
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
    contract::check_decode(
        || Collect::<igmp::Message>::new(igmp::MAX_MESSAGE),
        &auxiliary,
    );
    parse_failure::<igmp::Message>(&[], igmp::MAX_MESSAGE);
    refused(&igmp::Message::Query {
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
    refused(&ipsec::EspPacket { spi: 0, ..esp });
    let mut bad = ah;
    bad.header.icv.push(0);
    refused(&bad);
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
    assert_eq!(received.to_bytes(), Err(rip::RipError::TooManyEntries));
    assert_eq!(rip::Message::parse(&bytes), Ok(received));
    round_trip(&rip::NgMessage::whole_table_request(), rip::MAX_NG_MESSAGE);
    let ng = rip::NgMessage {
        command: rip::Command::Response,
        entries: rip::NgEntries::Entries(vec![rip::NgEntry::NextHop(Ipv6Addr::LOCALHOST)]),
    };
    refused(&ng); // The old parser normalizes this next hop to ::.
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
    contract::check_stack(make, bytes);
    for pattern in [&[][..], &[1][..], &[5, 2, 31][..]] {
        let mut stream = Stream::new(make());
        for part in chunks(bytes, pattern) {
            pump(&mut stream, part, |_| panic!("item before EOF")).unwrap();
        }
        let mut items = Vec::new();
        finish(&mut stream, |item| items.push(item)).unwrap();
        assert_eq!(items, vec![parse(bytes)]);
        assert!(stream.failed().is_none());
        assert_eq!(stream.next(), None);
    }
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
        let mut bytes = packet.to_bytes(&endpoints).unwrap();
        assert_eq!(ospf::Packet::parse(&bytes, &endpoints), Ok(packet));
        context_round_trip::<ospf::Datagram, _, _>(&bytes, ospf::MAX_MESSAGE, |b| {
            ospf::Packet::parse(b, &endpoints)
        });
        *bytes.get_mut(12).unwrap() ^= 1;
        assert_eq!(
            ospf::Packet::parse(&bytes, &endpoints),
            Err(ospf::OspfError::Checksum)
        );
        context_round_trip::<ospf::Datagram, _, _>(&bytes, ospf::MAX_MESSAGE, |b| {
            ospf::Packet::parse(b, &endpoints)
        });
        bytes.pop();
        context_round_trip::<ospf::Datagram, _, _>(&bytes, ospf::MAX_MESSAGE, |b| {
            ospf::Packet::parse(b, &endpoints)
        });
    }
    refused(&ospf::Datagram(vec![0; ospf::MAX_MESSAGE + 1]));
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
        let mut bytes = message.to_bytes(&endpoints).unwrap();
        assert_eq!(pim::Message::parse(&bytes, &endpoints), Ok(message));
        context_round_trip::<pim::Datagram, _, _>(&bytes, pim::MAX_MESSAGE, |b| {
            pim::Message::parse(b, &endpoints)
        });
        *bytes.get_mut(2).unwrap() ^= 1;
        assert_eq!(
            pim::Message::parse(&bytes, &endpoints),
            Err(pim::PimError::Checksum)
        );
        context_round_trip::<pim::Datagram, _, _>(&bytes, pim::MAX_MESSAGE, |b| {
            pim::Message::parse(b, &endpoints)
        });
        context_round_trip::<pim::Datagram, _, _>(&[], pim::MAX_MESSAGE, |b| {
            pim::Message::parse(b, &endpoints)
        });
    }
    refused(&pim::Datagram(vec![0; pim::MAX_MESSAGE + 1]));
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
        let mut bytes = advertisement.to_bytes(&endpoints).unwrap();
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
            Err(vrrp::VrrpError::Checksum)
        );
        context_round_trip::<vrrp::Datagram, _, _>(&bytes, vrrp::MAX_MESSAGE, |b| {
            vrrp::Advertisement::parse(b, &endpoints)
        });
        bytes.push(0);
        assert_eq!(
            vrrp::Advertisement::parse(&bytes, &endpoints),
            Err(vrrp::VrrpError::Trailing)
        );
        context_round_trip::<vrrp::Datagram, _, _>(&bytes, vrrp::MAX_MESSAGE, |b| {
            vrrp::Advertisement::parse(b, &endpoints)
        });
    }
    refused(&vrrp::Datagram(vec![0; vrrp::MAX_MESSAGE + 1]));
    parse_failure::<vrrp::Datagram>(&vec![0; vrrp::MAX_MESSAGE + 1], vrrp::MAX_MESSAGE + 1);
}

#[test]
fn legacy_collectors_keep_early_and_repeated_errors() {
    let mut geneve = geneve::Decoder::new();
    assert_eq!(geneve.feed(&[0x40]), Err(geneve::GeneveError::Version(1)));
    assert_eq!(geneve.feed(&[]), Err(geneve::GeneveError::Version(1)));
    let mut igmp = igmp::Decoder::new();
    assert_eq!(igmp.feed(&[0xff]), Err(igmp::IgmpError::UnknownType(0xff)));
    assert_eq!(igmp.finish(), Err(igmp::IgmpError::UnknownType(0xff)));
    let mut ipsec = ipsec::Decoder::new(ipsec::Kind::Esp);
    assert_eq!(ipsec.feed(&[0; 4]), Err(ipsec::IpsecError::ZeroSpi));
    assert_eq!(ipsec.kind(), ipsec::Kind::Esp);
}
