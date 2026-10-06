//! RTP datagrams, multiplexed RTCP, and RFC 4571 envelopes.
#![no_main]
use fictionet::stdlib::codec::{Decode, Wire, contract};
use fictionet::stdlib::{rtcp, rtp::*};
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    contract::check_decode_with_alloc_limit(rtcp::Frames::new, data, 2 * (MAX_PACKET + 2));
    contract::check_decode_with_alloc_limit(
        || rtcp::Frames::with_limit(usize::from(data.first().copied().unwrap_or(0))),
        data,
        514,
    );
    contract::check_decode_with_alloc_limit(
        || rtcp::Frames::new().map(|frame| Packet::parse(&frame.0)),
        data,
        2 * (MAX_PACKET + 2),
    );
    contract::check_wire::<rtcp::Frame>(data);
    contract::check_wire::<RtpPacket>(data);
    contract::check_wire::<Packet>(data);
    contract::check_wire::<rtcp::Datagram>(data);
    contract::check_wire::<rtcp::Compound>(data);
    let payload = &data[..data.len().min(MAX_PACKET + 1)];
    contract::check_wire_value(&rtcp::Frame(payload.to_vec()));
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
        let packet = RtpPacket {
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
        contract::check_wire_value(&packet);
        contract::check_wire_value(&Packet::Rtp(packet));
    }
});
