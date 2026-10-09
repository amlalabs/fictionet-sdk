//! RTCP protocol cases moved from the former RTP control-packet implementation.
use fictionet::stdlib::{
    codec::Wire,
    rtcp::{self, *},
    rtp,
    test_support::contract,
};

fn report() -> Packet {
    Body::ReceiverReport(ReceiverReport {
        ssrc: 1,
        reports: vec![],
        extension: vec![],
    })
    .into()
}
fn cname() -> Packet {
    Body::SourceDescription(vec![SdesChunk {
        ssrc: 1,
        items: vec![SdesItem {
            kind: sdes::CNAME,
            text: b"a@b".to_vec(),
        }],
    }])
    .into()
}
fn payload(message: PayloadMessage) -> Packet {
    Body::PayloadFeedback(PayloadFeedback {
        sender_ssrc: 1,
        media_ssrc: 2,
        message,
    })
    .into()
}
fn transport(message: TransportMessage) -> Packet {
    Body::TransportFeedback(TransportFeedback {
        sender_ssrc: 1,
        media_ssrc: 2,
        message,
    })
    .into()
}
fn refuses(body: Body) {
    let packet = Packet::from(body);
    contract::check_wire_value(&packet);
    assert_eq!(packet.to_bytes(), Err(Error::Unwritable));
}

#[test]
fn rtp_and_rtcp_packets_go_in_one_frame_writer() {
    fn framed<P: Wire>(packet: &P) -> Result<Vec<u8>, rtcp::Error> {
        let frame = rtcp::Frame::from_packet(packet)?;
        let mut bytes = Vec::new();
        frame.write(&mut bytes)?;
        Ok(bytes)
    }
    let media = rtp::Packet {
        marker: false,
        payload_type: 96,
        sequence: 1,
        timestamp: 2,
        ssrc: 3,
        csrcs: vec![],
        extension: None,
        payload: vec![4],
        padding: 0,
    };
    for (bytes, packet) in [
        (framed(&media).unwrap(), rtp::Demux::Rtp(media)),
        (
            framed(&report()).unwrap(),
            rtp::Demux::Rtcp(Datagram(vec![report()])),
        ),
    ] {
        let frame = rtcp::Frame::parse(&bytes).unwrap();
        assert_eq!(rtp::Demux::parse(&frame.0), Ok(packet.clone()));
        assert_eq!(framed(&packet).unwrap(), bytes);
    }
    let mut invalid = report();
    invalid.padding = 1;
    assert_eq!(framed(&invalid), Err(rtcp::Error::Unwritable));
}

#[test]
fn rtcp_errors() {
    assert_eq!(Datagram::parse(&[0x80]), Err(Error::Truncated));
    assert_eq!(
        Datagram::parse(&[0x80, 201, 0, 1, 0, 0]),
        Err(Error::Truncated)
    );
    assert_eq!(Datagram::parse(&[0x40, 201, 0, 0]), Err(Error::Version(1)));
    assert_eq!(
        Datagram::parse(&vec![0; MAX_DATAGRAM + 1]),
        Err(Error::TooLong(MAX_DATAGRAM + 1))
    );
    let body = |pt: u8, count: u8, body: &[u8]| {
        let mut b = vec![0x80 | count, pt, 0, (body.len() / 4) as u8];
        b.extend_from_slice(body);
        Datagram::parse(&b)
    };
    // Reports shorter than their fixed part or their count.
    assert_eq!(body(200, 0, &[0; 20]), Err(Error::PacketContents(200)));
    assert_eq!(body(200, 1, &[0; 24]), Err(Error::PacketContents(200)));
    assert_eq!(body(201, 0, &[]), Err(Error::PacketContents(201)));
    assert_eq!(body(201, 2, &[0; 28]), Err(Error::PacketContents(201)));
    assert!(body(201, 1, &[0; 28]).is_ok());
    // SDES: a chunk with no end, an item past the end, an extra word,
    // and a missing chunk.
    assert_eq!(
        body(202, 1, &[0, 0, 0, 1, 1, 2, b'a', b'b']),
        Err(Error::PacketContents(202))
    );
    assert_eq!(
        body(202, 1, &[0, 0, 0, 1, 1, 9, b'a', b'b']),
        Err(Error::PacketContents(202))
    );
    assert_eq!(
        body(202, 1, &[0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0]),
        Err(Error::PacketContents(202))
    );
    assert_eq!(
        body(202, 2, &[0, 0, 0, 1, 0, 0, 0, 0]),
        Err(Error::PacketContents(202))
    );
    assert_eq!(body(202, 1, &[0, 0, 0, 1]), Err(Error::PacketContents(202)));
    // BYE: too few sources, a reason past the end, too much after it.
    assert_eq!(body(203, 2, &[0, 0, 0, 1]), Err(Error::PacketContents(203)));
    assert_eq!(
        body(203, 0, &[9, b'a', b'b', b'c']),
        Err(Error::PacketContents(203))
    );
    assert_eq!(
        body(203, 0, &[1, b'a', 0, 0, 0, 0, 0, 0]),
        Err(Error::PacketContents(203))
    );
    // APP and feedback shorter than their SSRCs and name.
    assert_eq!(body(204, 0, &[0, 0, 0, 1]), Err(Error::PacketContents(204)));
    assert_eq!(body(205, 1, &[0, 0, 0, 1]), Err(Error::PacketContents(205)));
    assert_eq!(body(206, 1, &[0, 0, 0, 1]), Err(Error::PacketContents(206)));
    // A PLI with FCI, an RPSI with none, an RPSI with too many padding bits.
    assert_eq!(
        body(206, 1, &[0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 0]),
        Err(Error::PacketContents(206))
    );
    assert_eq!(
        body(206, 3, &[0, 0, 0, 1, 0, 0, 0, 2]),
        Err(Error::PacketContents(206))
    );
    assert_eq!(
        body(206, 3, &[0, 0, 0, 1, 0, 0, 0, 2, 17, 96, 0, 0]),
        Err(Error::PacketContents(206))
    );
    assert!(body(206, 3, &[0, 0, 0, 1, 0, 0, 0, 2, 16, 96, 0, 0]).is_ok());
}

#[test]
fn rtp_demux_checks_typed_feedback_and_xr_layouts() {
    for (pt, fmt, body) in [
        (205, 3, vec![0; 8]),  // TMMBR needs an entry.
        (205, 3, vec![0; 12]), // TMMBR and TMMBN entries occupy two words.
        (205, 4, vec![0; 12]),
        (206, 4, vec![0; 8]), // FIR needs a two-word entry.
        (206, 4, vec![0; 12]),
        (206, 15, [vec![0; 8], b"REMB".to_vec()].concat()),
        (207, 0, vec![]),                       // XR needs an SSRC.
        (207, 0, vec![0, 0, 0, 1, 4, 0, 0, 0]), // RRT needs two words.
    ] {
        let mut bytes = vec![0x80 | fmt, pt, 0, (body.len() / 4) as u8];
        bytes.extend_from_slice(&body);
        assert_eq!(
            rtp::Demux::parse(&bytes),
            Err(rtp::Error::Rtcp(Error::PacketContents(pt)))
        );
    }
    for padding_bits in [31, 32, 48] {
        let mut bytes = vec![0x83, 206, 0, 4, 0, 0, 0, 1, 0, 0, 0, 2, padding_bits, 96];
        bytes.extend([0; 6]);
        assert_eq!(rtp::Demux::parse(&bytes).is_ok(), padding_bits < 32);
    }
    let mut remb = Packet::from(Body::PayloadFeedback(PayloadFeedback {
        sender_ssrc: 1,
        media_ssrc: 0,
        message: PayloadMessage::Remb(Remb {
            exponent: 0,
            mantissa: 1,
            ssrcs: vec![2],
        }),
    }))
    .to_bytes()
    .unwrap();
    assert!(rtp::Demux::parse(&remb).is_ok());
    remb[0] |= 0x20;
    remb[3] += 1;
    remb.extend([0, 0, 0, 4]);
    assert_eq!(
        rtp::Demux::parse(&remb),
        Err(rtp::Error::Rtcp(Error::PacketContents(206)))
    );
}

#[test]
fn sender_report_bytes() {
    let sr = Packet::from(Body::SenderReport(SenderReport {
        ssrc: 0x0102_0304,
        ntp_timestamp: 0xe000_0000_8000_0000,
        rtp_timestamp: 0x10,
        packet_count: 2,
        octet_count: 320,
        reports: vec![ReportBlock {
            ssrc: 0x0a0b_0c0d,
            fraction_lost: 0x40,
            cumulative_lost: -1,
            highest_sequence: 0x0001_0005,
            jitter: 7,
            last_sr: 0x1234_5678,
            delay_since_last_sr: 0x0001_0000,
        }],
        extension: vec![],
    }));
    let b = sr.to_bytes().unwrap();
    assert_eq!(b.len(), 52);
    assert_eq!(&b[..8], &[0x81, 200, 0, 12, 1, 2, 3, 4]);
    assert_eq!(&b[8..16], &[0xe0, 0, 0, 0, 0x80, 0, 0, 0]);
    assert_eq!(
        &b[28..36],
        &[0x0a, 0x0b, 0x0c, 0x0d, 0x40, 0xff, 0xff, 0xff]
    );
    assert_eq!(Packet::parse(&b), Ok(sr));
    assert!(rtp::is_rtcp(&b));
}

#[test]
fn sdes_bye_app_bytes() {
    let sdes = Packet::from(Body::SourceDescription(vec![SdesChunk {
        ssrc: 1,
        items: vec![SdesItem {
            kind: sdes::CNAME,
            text: b"ab".to_vec(),
        }],
    }]));
    assert_eq!(
        sdes.to_bytes().unwrap(),
        [0x81, 202, 0, 3, 0, 0, 0, 1, 1, 2, b'a', b'b', 0, 0, 0, 0]
    );
    let bye = Packet::from(Body::Bye(Bye {
        sources: vec![1],
        reason: Some(b"bye".to_vec()),
    }));
    assert_eq!(
        bye.to_bytes().unwrap(),
        [0x81, 203, 0, 2, 0, 0, 0, 1, 3, b'b', b'y', b'e']
    );
    for reason in [None, Some(vec![])] {
        let bye = Packet::from(Body::Bye(Bye {
            sources: vec![],
            reason,
        }));
        assert!(bye.to_bytes().is_ok());
        contract::check_wire_value(&bye);
    }
    assert_eq!(
        Packet::from(Body::Bye(Bye {
            sources: vec![],
            reason: None
        }))
        .to_bytes()
        .unwrap(),
        [0x80, 203, 0, 0]
    );
    refuses(Body::App(App {
        subtype: 0x3f,
        ssrc: 2,
        name: *b"abcd",
        data: vec![1],
    }));
    let app = Packet::from(Body::App(App {
        subtype: 0x1f,
        ssrc: 2,
        name: *b"abcd",
        data: vec![1, 0, 0, 0],
    }));
    assert_eq!(
        app.to_bytes().unwrap(),
        [
            0x9f, 204, 0, 3, 0, 0, 0, 2, b'a', b'b', b'c', b'd', 1, 0, 0, 0
        ]
    );
}

#[test]
fn feedback_bytes() {
    let nack = transport(TransportMessage::Nack(vec![Nack { pid: 100, blp: 5 }]));
    assert_eq!(
        nack.to_bytes().unwrap(),
        [0x81, 205, 0, 3, 0, 0, 0, 1, 0, 0, 0, 2, 0, 100, 0, 5]
    );
    assert_eq!(Nack { pid: 100, blp: 5 }.lost(), [100, 101, 103]);
    assert_eq!(Nack { pid: 65535, blp: 1 }.lost(), [65535, 0]);
    assert_eq!(
        payload(PayloadMessage::Pli).to_bytes().unwrap(),
        [0x81, 206, 0, 2, 0, 0, 0, 1, 0, 0, 0, 2]
    );
    let sli = payload(PayloadMessage::Sli(vec![Sli {
        first: 1,
        number: 2,
        picture_id: 3,
    }]));
    assert_eq!(
        &sli.to_bytes().unwrap()[12..],
        &(1u32 << 19 | 2 << 6 | 3).to_be_bytes()
    );
    let invalid = payload(PayloadMessage::Rpsi(Rpsi {
        padding_bits: 3,
        payload_type: 0xe0,
        data: vec![0xff],
    }));
    assert_eq!(invalid.to_bytes(), Err(Error::Unwritable));
    let rpsi = payload(PayloadMessage::Rpsi(Rpsi {
        padding_bits: 11,
        payload_type: 96,
        data: vec![0xf8, 0],
    }));
    assert_eq!(&rpsi.to_bytes().unwrap()[12..], &[11, 96, 0xf8, 0]);
    contract::check_wire_value(&rpsi);
    let other = transport(TransportMessage::Other {
        fmt: 15,
        fci: vec![1, 2, 3, 4],
    });
    assert!(other.to_bytes().is_ok());
    contract::check_wire_value(&other);
    // FMT 3 has the TMMBR layout in the shared implementation.
    assert_eq!(
        transport(TransportMessage::Other {
            fmt: 3,
            fci: vec![1, 2, 3, 4]
        })
        .to_bytes(),
        Err(Error::Unwritable)
    );
}

#[test]
fn compound_round_trip_and_truncated_prefixes() {
    let packets = vec![
        Packet::from(Body::SenderReport(SenderReport {
            ssrc: 1,
            ntp_timestamp: 0xe000_0000_8000_0000,
            rtp_timestamp: 160,
            packet_count: 2,
            octet_count: 320,
            reports: vec![ReportBlock {
                ssrc: 2,
                fraction_lost: 64,
                cumulative_lost: -1,
                highest_sequence: 0x0001_0005,
                jitter: 7,
                last_sr: 0x1234_5678,
                delay_since_last_sr: 0x0001_0000,
            }],
            extension: vec![1, 2, 3, 4],
        })),
        report(),
        cname(),
        Packet::from(Body::App(App {
            subtype: 3,
            ssrc: 1,
            name: *b"test",
            data: vec![1, 2, 3, 4],
        })),
        payload(PayloadMessage::Pli),
        payload(PayloadMessage::Sli(vec![Sli {
            first: 1,
            number: 2,
            picture_id: 3,
        }])),
        payload(PayloadMessage::Rpsi(Rpsi {
            padding_bits: 11,
            payload_type: 96,
            data: vec![0xf8, 0],
        })),
        payload(PayloadMessage::Other {
            fmt: 8,
            fci: vec![1, 2, 3, 4],
        }),
        transport(TransportMessage::Nack(vec![Nack { pid: 5, blp: 3 }])),
        Packet::from(Body::Other {
            packet_type: 208,
            count: 2,
            data: vec![5; 4],
        }),
        Packet::from(Body::Bye(Bye {
            sources: vec![1, 7],
            reason: Some(b"done".to_vec()),
        })),
    ];
    let compound = Compound(packets.clone());
    let bytes = compound.to_bytes().unwrap();
    assert_eq!(bytes, Datagram(packets.clone()).to_bytes().unwrap());
    assert_eq!(Compound::parse(&bytes), Ok(compound));
    assert_eq!(
        rtp::Demux::parse(&bytes),
        Ok(rtp::Demux::Rtcp(Datagram(packets.clone())))
    );
    assert_eq!(
        rtp::Demux::Rtcp(Datagram(packets.clone())).to_bytes(),
        Ok(bytes.clone())
    );
    let mut ends = vec![];
    let mut end = 0;
    for p in &packets {
        let b = p.to_bytes().unwrap();
        end += b.len();
        ends.push(end);
        assert_eq!(Datagram::parse(&b), Ok(Datagram(vec![p.clone()])));
    }
    assert_eq!(Datagram::parse(&[]), Err(Error::Empty));
    for n in 1..bytes.len() {
        if ends.contains(&n) {
            assert!(Datagram::parse(&bytes[..n]).is_ok());
            assert!(rtp::Demux::parse(&bytes[..n]).is_ok());
        } else {
            assert_eq!(Datagram::parse(&bytes[..n]), Err(Error::Truncated));
            if n >= 2 {
                assert_eq!(
                    rtp::Demux::parse(&bytes[..n]),
                    Err(rtp::Error::Rtcp(Error::Truncated))
                );
            }
        }
    }
}

#[test]
fn padding_on_the_last_packet() {
    let mut last = cname();
    last.padding = 8;
    let bytes = Compound(vec![report(), last.clone()]).to_bytes().unwrap();
    let packets = Compound::parse(&bytes).unwrap();
    assert_eq!(packets.0[1], last);
    assert_eq!(
        rtp::Demux::parse(&bytes),
        Ok(rtp::Demux::Rtcp(Datagram(packets.0)))
    );
    let mut bad = bytes.clone();
    bad[0] |= 0x20;
    assert_eq!(
        rtp::Demux::parse(&bad),
        Err(rtp::Error::Rtcp(Error::Padding))
    );

    // The first packet's padding is valid on its own, but not before SDES.
    let first = Packet::from(Body::ReceiverReport(ReceiverReport {
        ssrc: 1,
        reports: vec![],
        extension: vec![0, 0, 0, 4],
    }));
    let mut bad = Datagram(vec![first, cname()]).to_bytes().unwrap();
    assert!(rtp::Demux::parse(&bad).is_ok());
    bad[0] |= 0x20;
    let datagram = Datagram::parse(&bad).unwrap();
    assert_eq!(datagram.0[0].padding, 4);
    assert_eq!(
        rtp::Demux::parse(&bad),
        Err(rtp::Error::Rtcp(Error::Padding))
    );
    let packet = rtp::Demux::Rtcp(datagram);
    let mut out = vec![9, 8, 7];
    assert_eq!(packet.write(&mut out), Err(rtp::Error::Unwritable));
    assert_eq!(out, [9, 8, 7]);
    contract::check_wire_value(&packet);
    let mut first = report();
    first.padding = 4;
    assert_eq!(
        Compound(vec![first, cname()]).to_bytes(),
        Err(Error::Unwritable)
    );
    for count in [0, 6, 24] {
        let mut bad = bytes.clone();
        *bad.last_mut().unwrap() = count;
        assert_eq!(Datagram::parse(&bad), Err(Error::Padding));
    }
    assert_eq!(Datagram::parse(&[0xa0, 203, 0, 0]), Err(Error::Padding));
    assert_eq!(
        Datagram::parse(&[0xa0, 201, 0, 1, 0, 0, 0, 4]),
        Err(Error::PacketContents(201))
    );
    assert_eq!(
        Datagram::parse(&[0xa0, 201, 0, 1, 0, 0, 0, 0]),
        Err(Error::Padding)
    );
}

#[test]
fn compound_rules_and_cname_order() {
    assert_eq!(Compound::parse(&[]), Err(Error::Empty));
    assert_eq!(check_compound(&[]), Err(Error::NoPackets));
    assert_eq!(
        check_compound(&[cname(), report()]),
        Err(Error::FirstNotReport(202))
    );
    assert_eq!(check_compound(&[report()]), Err(Error::NoCname));
    let no_cname = Packet::from(Body::SourceDescription(vec![SdesChunk {
        ssrc: 1,
        items: vec![SdesItem {
            kind: sdes::NAME,
            text: b"x".to_vec(),
        }],
    }]));
    assert_eq!(
        check_compound(&[report(), no_cname.clone()]),
        Err(Error::NoCname)
    );
    let late = vec![report(), payload(PayloadMessage::Pli), cname()];
    assert_eq!(check_compound(&late), Err(Error::FeedbackOrder));
    assert_eq!(
        Compound::parse(&Datagram(late).to_bytes().unwrap()),
        Err(Error::FeedbackOrder)
    );
    let app = Packet::from(Body::App(App {
        subtype: 1,
        ssrc: 2,
        name: *b"abcd",
        data: vec![],
    }));
    let bye = Packet::from(Body::Bye(Bye {
        sources: vec![1],
        reason: None,
    }));
    for between in [app, bye] {
        let packets = vec![report(), between, cname()];
        assert_eq!(check_compound(&packets), Err(Error::NoCname));
        assert_eq!(
            Compound::parse(&Datagram(packets.clone()).to_bytes().unwrap()),
            Err(Error::NoCname)
        );
        assert_eq!(Compound(packets).to_bytes(), Err(Error::Unwritable));
    }
    let valid = Compound(vec![
        report(),
        report(),
        no_cname,
        cname(),
        payload(PayloadMessage::Pli),
    ]);
    assert!(valid.to_bytes().is_ok());
    contract::check_wire_value(&valid);
    for late in [report(), cname()] {
        let packets = vec![report(), cname(), payload(PayloadMessage::Pli), late];
        let bytes = Datagram(packets.clone()).to_bytes().unwrap();
        assert_eq!(Compound::parse(&bytes), Err(Error::FeedbackOrder));
        assert_eq!(Compound(packets).to_bytes(), Err(Error::Unwritable));
    }
    let mut chunks = vec![
        SdesChunk {
            ssrc: 9,
            items: vec![]
        };
        MAX_COUNT
    ];
    chunks.push(SdesChunk {
        ssrc: 1,
        items: vec![SdesItem {
            kind: sdes::CNAME,
            text: b"a@b".to_vec(),
        }],
    });
    assert_eq!(
        Compound(vec![
            report(),
            Packet::from(Body::SourceDescription(chunks))
        ])
        .to_bytes(),
        Err(Error::Unwritable)
    );
    assert_eq!(Compound::parse(&[0x80]), Err(Error::Truncated));
    assert_eq!(
        rtp::Demux::parse(&[0x80, 200, 0]),
        Err(rtp::Error::Rtcp(Error::Truncated))
    );
    assert_eq!(
        rtp::Demux::parse(&[0x80, 100, 0]),
        Err(rtp::Error::Truncated)
    );
}

#[test]
fn rtcp_writers_refuse_clipping() {
    let block = ReportBlock {
        ssrc: 1,
        fraction_lost: 0,
        cumulative_lost: i32::MIN,
        highest_sequence: 0,
        jitter: 0,
        last_sr: 0,
        delay_since_last_sr: 0,
    };
    refuses(Body::SenderReport(SenderReport {
        ssrc: 1,
        ntp_timestamp: 0,
        rtp_timestamp: 0,
        packet_count: 0,
        octet_count: 0,
        reports: vec![block; 40],
        extension: vec![1; 100_000],
    }));
    refuses(Body::ReceiverReport(ReceiverReport {
        ssrc: 1,
        reports: vec![block; 40],
        extension: vec![],
    }));
    for item in [
        SdesItem {
            kind: sdes::END,
            text: b"gone".to_vec(),
        },
        SdesItem {
            kind: sdes::NOTE,
            text: vec![b'n'; 300],
        },
    ] {
        refuses(Body::SourceDescription(vec![SdesChunk {
            ssrc: 1,
            items: vec![item],
        }]));
    }
    refuses(Body::SourceDescription(vec![
        SdesChunk {
            ssrc: 1,
            items: vec![]
        };
        40
    ]));
    refuses(Body::Bye(Bye {
        sources: (0..50).collect(),
        reason: Some(vec![b'r'; 400]),
    }));
    assert_eq!(
        transport(TransportMessage::Nack(vec![
            Nack { pid: 1, blp: 0 };
            20_000
        ]))
        .to_bytes(),
        Err(Error::Unwritable)
    );
    assert_eq!(
        payload(PayloadMessage::Rpsi(Rpsi {
            padding_bits: 255,
            payload_type: 0,
            data: vec![]
        }))
        .to_bytes(),
        Err(Error::Unwritable)
    );
    refuses(Body::Other {
        packet_type: 200,
        count: 0,
        data: vec![],
    });
    assert_eq!(
        payload(PayloadMessage::Other {
            fmt: 1,
            fci: vec![0; 4]
        })
        .to_bytes(),
        Err(Error::Unwritable)
    );
    let big = Packet::from(Body::App(App {
        subtype: 0,
        ssrc: 0,
        name: *b"BIG ",
        data: vec![0; 40_000],
    }));
    assert_eq!(
        Datagram(vec![big.clone(), big, cname()]).to_bytes(),
        Err(Error::Unwritable)
    );
}

#[test]
fn compound_writer_checks_every_packet() {
    let big = Packet::from(Body::ReceiverReport(ReceiverReport {
        ssrc: 1,
        reports: vec![],
        extension: vec![0; 65_524],
    }));
    let packets = vec![big, cname()];
    assert_eq!(check_compound(&packets), Ok(()));
    assert_eq!(Compound(packets).to_bytes(), Err(Error::Unwritable));
    assert_eq!(
        Compound(vec![
            report(),
            cname(),
            transport(TransportMessage::Nack(vec![]))
        ])
        .to_bytes(),
        Err(Error::Unwritable)
    );
    assert_eq!(Compound(vec![]).to_bytes(), Err(Error::Unwritable));
    assert_eq!(
        Compound(vec![cname(), report()]).to_bytes(),
        Err(Error::Unwritable)
    );
}

#[test]
fn empty_nack_and_sli_are_rejected() {
    for pt in [205, 206] {
        let fmt = if pt == 205 { 1 } else { 2 };
        assert_eq!(
            Datagram::parse(&[0x80 | fmt, pt, 0, 2, 0, 0, 0, 1, 0, 0, 0, 2]),
            Err(Error::PacketContents(pt))
        );
    }
    assert_eq!(
        transport(TransportMessage::Nack(vec![])).to_bytes(),
        Err(Error::Unwritable)
    );
    assert_eq!(
        payload(PayloadMessage::Sli(vec![])).to_bytes(),
        Err(Error::Unwritable)
    );
}

#[test]
fn sdes_and_bye_padding_must_be_null() {
    for bytes in [
        vec![0x81, 202, 0, 2, 0, 0, 0, 1, 0, 0, 0, 0],
        vec![0x81, 203, 0, 2, 0, 0, 0, 1, 2, b'h', b'i', 0],
    ] {
        assert!(Datagram::parse(&bytes).is_ok());
        assert!(rtp::Demux::parse(&bytes).is_ok());
    }
    for (pt, bytes) in [
        (202, vec![0x81, 202, 0, 2, 0, 0, 0, 1, 0, 0, 1, 0]),
        (203, vec![0x81, 203, 0, 2, 0, 0, 0, 1, 1, b'a', 1, 0]),
    ] {
        assert_eq!(Datagram::parse(&bytes), Err(Error::PacketContents(pt)));
    }
}

#[test]
fn rpsi_padding_bits_are_zero() {
    for (pb, data, valid) in [
        (3, [0xab, 7], false),
        (9, [1, 0], false),
        (3, [0xab, 8], true),
        (9, [2, 0], true),
        (16, [0, 0], true),
        (0, [255, 255], true),
    ] {
        let mut bytes = vec![0x83, 206, 0, 3, 0, 0, 0, 1, 0, 0, 0, 2, pb, 96];
        bytes.extend_from_slice(&data);
        assert_eq!(Datagram::parse(&bytes).is_ok(), valid);
    }
    for pb in 0..=40 {
        assert_eq!(
            payload(PayloadMessage::Rpsi(Rpsi {
                padding_bits: pb,
                payload_type: 96,
                data: vec![0xff; 3]
            }))
            .to_bytes(),
            Err(Error::Unwritable)
        );
    }
}

#[test]
fn long_text_is_refused_without_cutting_characters() {
    for text in ["é".repeat(128).into_bytes(), vec![0xff; 300]] {
        refuses(Body::SourceDescription(vec![SdesChunk {
            ssrc: 1,
            items: vec![SdesItem {
                kind: sdes::NOTE,
                text: text.clone(),
            }],
        }]));
        refuses(Body::Bye(Bye {
            sources: vec![1],
            reason: Some(text),
        }));
    }
    for text in ["é".repeat(127).into_bytes(), b"abc".to_vec()] {
        let bye = Packet::from(Body::Bye(Bye {
            sources: vec![1],
            reason: Some(text),
        }));
        assert!(bye.to_bytes().is_ok());
        contract::check_wire_value(&bye);
    }
}

#[test]
fn priv_prefix_length_is_checked() {
    for bytes in [
        vec![0x81, 202, 0, 2, 0, 0, 0, 1, 8, 1, 255, 0],
        vec![0x81, 202, 0, 2, 0, 0, 0, 1, 8, 0, 0, 0],
    ] {
        assert_eq!(Datagram::parse(&bytes), Err(Error::PacketContents(202)));
    }
    for bytes in [
        vec![0x81, 202, 0, 3, 0, 0, 0, 1, 8, 4, 2, b'a', b'b', b'x', 0, 0],
        vec![0x81, 202, 0, 2, 0, 0, 0, 1, 8, 1, 0, 0],
    ] {
        contract::check_wire::<Datagram>(&bytes);
        assert!(Datagram::parse(&bytes).is_ok());
    }
    for text in [vec![], vec![5, b'a'], [vec![255], vec![b'p'; 300]].concat()] {
        refuses(Body::SourceDescription(vec![SdesChunk {
            ssrc: 1,
            items: vec![SdesItem {
                kind: sdes::PRIV,
                text,
            }],
        }]));
    }
    let valid = Packet::from(Body::SourceDescription(vec![SdesChunk {
        ssrc: 1,
        items: vec![SdesItem {
            kind: sdes::PRIV,
            text: b"\x01ab".to_vec(),
        }],
    }]));
    assert!(valid.to_bytes().is_ok());
    contract::check_wire_value(&valid);
}
