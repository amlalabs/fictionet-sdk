//! RTP datagrams, multiplexed RTCP, and RFC 4571 envelopes.
#![no_main]
use fictionet::stdlib::codec::Frames;
use fictionet::stdlib::codec::Stream;
use fictionet::stdlib::codec::{Decode, Wire};
use fictionet::stdlib::protocols::{rtcp, rtp::*};
use fictionet::stdlib::test_support::{assert_write, chunks, decode_all, decode_chunks};
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    rtcp::harness::datagram(data);
    let bound = 2 * (MAX_PACKET + 2);
    assert_eq!(
        decode_chunks(
            &mut Stream::new(Frames::<rtcp::Frame>::new()),
            chunks(data, &[1, 7, 64]),
            |s| {
                assert!(s.allocated() <= bound);
            }
        ),
        decode_all(Frames::<rtcp::Frame>::new, data),
    );
    assert_eq!(
        decode_chunks(
            &mut Stream::new(Frames::<rtcp::Frame>::with_limit(usize::from(
                data.first().copied().unwrap_or(0)
            ))),
            chunks(data, &[1, 7, 64]),
            |s| {
                assert!(s.allocated() <= 514);
            }
        ),
        decode_all(
            || Frames::<rtcp::Frame>::with_limit(usize::from(data.first().copied().unwrap_or(0))),
            data
        ),
    );
    let bound = 2 * (MAX_PACKET + 2);
    assert_eq!(
        decode_chunks(
            &mut Stream::new(Frames::<rtcp::Frame>::new().map(|frame| Demux::parse(&frame.0))),
            chunks(data, &[1, 7, 64]),
            |s| {
                assert!(s.allocated() <= bound);
            }
        ),
        decode_all(
            || Frames::<rtcp::Frame>::new().map(|frame| Demux::parse(&frame.0)),
            data
        ),
    );
    if let Ok(value) = <rtcp::Frame as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Packet as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Demux as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <rtcp::Datagram as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <rtcp::Compound as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    let payload = &data[..data.len().min(MAX_PACKET + 1)];
    let _ = assert_write(&rtcp::Frame(payload.to_vec()));
    let elements = vec![Element {
        id: data.first().copied().unwrap_or(0),
        data: payload[..payload.len().min(256)].to_vec(),
    }];
    for extension in [
        None,
        Some(HeaderExtension::OneByte(elements.clone())),
        Some(HeaderExtension::TwoByte {
            app_bits: data.get(1).copied().unwrap_or(0),
            elements,
        }),
        Some(HeaderExtension::Other {
            profile: u16::from_be_bytes([
                data.first().copied().unwrap_or(0),
                data.get(1).copied().unwrap_or(0),
            ]),
            data: payload.to_vec(),
        }),
    ] {
        let packet = Packet {
            marker: data.len() % 2 == 0,
            payload_type: data.first().copied().unwrap_or(0),
            sequence: 0,
            timestamp: 0,
            ssrc: 0,
            csrcs: vec![0; usize::from(data.get(2).copied().unwrap_or(0) % 17)],
            extension,
            payload: payload.to_vec(),
            padding: data.get(3).copied().unwrap_or(0),
        };
        let _ = assert_write(&packet);
        let _ = assert_write(&Demux::Rtp(packet));
    }
});
