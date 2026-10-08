//! RTCP datagrams and RFC 4571 streams, as a world playing a media server
//! reads them, and packets a world builds, as it writes them.
#![no_main]

use fictionet::stdlib::codec::Frames;
use arbitrary::{Result, Unstructured};
use fictionet::stdlib::codec::{Decode, Wire};
use fictionet::stdlib::test_support::contract;
use fictionet::stdlib::test_support::decode_all;
use fictionet::stdlib::rtcp::Frame;
use fictionet::stdlib::rtcp::{
    App, Body, Bye, Datagram, Compound, DlrrItem, ExtendedReport, Fir, MAX_DATAGRAM, MAX_PACKET, Nack, Packet,
    PayloadFeedback, PayloadMessage, ReceiverReport, Remb, ReportBlock, Rpsi, SdesChunk, SdesItem, SenderReport, Sli,
    Tmmb, TransportFeedback, TransportMessage, XrBlock, check_compound, classify,
};
use libfuzzer_sys::fuzz_target;
fn datagram(data: &[u8]) {
    let _ = classify(data);
    contract::check_wire::<Packet>(data);
    contract::check_wire::<Datagram>(data);
    contract::check_wire::<Compound>(data);
    if let Ok(packets) = Datagram::parse(data) {
        assert_eq!(packets.to_bytes().unwrap().len(), data.len());
        assert_eq!(
            Compound::parse(data).is_ok(),
            check_compound(&packets.0).is_ok()
        );
    }
}

/// Up to `max` fuzz bytes.
fn bytes(u: &mut Unstructured, max: usize) -> Result<Vec<u8>> {
    let n = u.int_in_range(0..=max)?;
    Ok(u.bytes(n)?.to_vec())
}

/// Payload bytes: usually up to 40 fuzz bytes, sometimes one byte repeated
/// up to past the longest packet, to test the writers' size limits.
fn data(u: &mut Unstructured) -> Result<Vec<u8>> {
    if u.ratio(1, 8)? {
        let byte: u8 = u.arbitrary()?;
        let n = u.int_in_range(MAX_PACKET - 16..=MAX_PACKET + 8)?;
        Ok(vec![byte; n])
    } else {
        bytes(u, 40)
    }
}

/// A media SSRC: 0 half the time, as TMMBR, TMMBN, FIR and REMB need.
fn media_ssrc(u: &mut Unstructured) -> Result<u32> {
    if u.arbitrary()? { Ok(0) } else { u.arbitrary() }
}

/// Up to `max` values built by `f`.
fn list<T>(u: &mut Unstructured, max: usize, mut f: impl FnMut(&mut Unstructured) -> Result<T>) -> Result<Vec<T>> {
    let n = u.int_in_range(0..=max)?;
    (0..n).map(|_| f(u)).collect()
}

fn report_block(u: &mut Unstructured) -> Result<ReportBlock> {
    Ok(ReportBlock {
        ssrc: u.arbitrary()?,
        fraction_lost: u.arbitrary()?,
        cumulative_lost: u.arbitrary()?,
        highest_sequence: u.arbitrary()?,
        jitter: u.arbitrary()?,
        last_sr: u.arbitrary()?,
        delay_since_last_sr: u.arbitrary()?,
    })
}

fn tmmb(u: &mut Unstructured) -> Result<Tmmb> {
    Ok(Tmmb {
        ssrc: u.arbitrary()?,
        exponent: u.int_in_range(0..=64)?,
        mantissa: u.int_in_range(0..=1 << 17)?,
        overhead: u.int_in_range(0..=512)?,
    })
}

/// A packet built from fuzz bytes, valid or not.
fn packet(u: &mut Unstructured) -> Result<Packet> {
    let body = match u.int_in_range(0..=8u8)? {
        0 => Body::SenderReport(SenderReport {
            ssrc: u.arbitrary()?,
            ntp_timestamp: u.arbitrary()?,
            rtp_timestamp: u.arbitrary()?,
            packet_count: u.arbitrary()?,
            octet_count: u.arbitrary()?,
            reports: list(u, 33, report_block)?,
            extension: data(u)?,
        }),
        1 => Body::ReceiverReport(ReceiverReport {
            ssrc: u.arbitrary()?,
            reports: list(u, 33, report_block)?,
            extension: data(u)?,
        }),
        2 => Body::SourceDescription(list(u, 33, |u| {
            Ok(SdesChunk {
                ssrc: u.arbitrary()?,
                items: list(u, 5, |u| Ok(SdesItem { kind: u.arbitrary()?, text: bytes(u, 260)? }))?,
            })
        })?),
        3 => Body::Bye(Bye {
            sources: list(u, 33, |u| u.arbitrary())?,
            reason: if u.arbitrary()? { Some(bytes(u, 260)?) } else { None },
        }),
        4 => Body::App(App { subtype: u.arbitrary()?, ssrc: u.arbitrary()?, name: u.arbitrary()?, data: data(u)? }),
        5 => {
            let message = match u.int_in_range(0..=3u8)? {
                0 => TransportMessage::Nack(list(u, 20, |u| Ok(Nack { pid: u.arbitrary()?, blp: u.arbitrary()? }))?),
                1 => TransportMessage::Tmmbr(list(u, 5, tmmb)?),
                2 => TransportMessage::Tmmbn(list(u, 5, tmmb)?),
                _ => TransportMessage::Other { fmt: u.arbitrary()?, fci: data(u)? },
            };
            Body::TransportFeedback(TransportFeedback {
                sender_ssrc: u.arbitrary()?,
                media_ssrc: media_ssrc(u)?,
                message,
            })
        }
        6 => {
            let message = match u.int_in_range(0..=6u8)? {
                0 => PayloadMessage::Pli,
                1 => PayloadMessage::Sli(list(u, 5, |u| {
                    Ok(Sli {
                        first: u.int_in_range(0..=8192)?,
                        number: u.int_in_range(0..=8192)?,
                        picture_id: u.int_in_range(0..=64)?,
                    })
                })?),
                2 => PayloadMessage::Rpsi(Rpsi {
                    payload_type: u.arbitrary()?,
                    padding_bits: u.arbitrary()?,
                    data: data(u)?,
                }),
                3 => PayloadMessage::Fir(list(u, 5, |u| Ok(Fir { ssrc: u.arbitrary()?, sequence: u.arbitrary()? }))?),
                4 => PayloadMessage::Remb(Remb {
                    exponent: u.int_in_range(0..=64)?,
                    mantissa: u.int_in_range(0..=1 << 18)?,
                    ssrcs: list(u, 260, |u| u.arbitrary())?,
                }),
                5 => PayloadMessage::Afb(data(u)?),
                _ => PayloadMessage::Other { fmt: u.arbitrary()?, fci: data(u)? },
            };
            Body::PayloadFeedback(PayloadFeedback { sender_ssrc: u.arbitrary()?, media_ssrc: media_ssrc(u)?, message })
        }
        7 => Body::ExtendedReport(ExtendedReport {
            ssrc: u.arbitrary()?,
            blocks: list(u, 5, |u| {
                // Mostly the types RFC 3611 defines, whose lengths are set.
                let block_type = if u.ratio(3, 4)? { u.int_in_range(1..=7)? } else { u.arbitrary()? };
                let type_specific = if u.arbitrary()? { 0 } else { u.arbitrary()? };
                Ok(XrBlock { block_type, type_specific, data: bytes(u, 40)? })
            })?,
        }),
        _ => Body::Other { packet_type: u.arbitrary()?, count: u.arbitrary()?, data: data(u)? },
    };
    Ok(Packet { body, padding: u.arbitrary()? })
}

/// Packets a world builds: whatever a writer accepts reads back the same.
fn built(data: &[u8]) -> Result<()> {
    let mut u = Unstructured::new(data);
    let packets = list(&mut u, 6, packet)?;
    for p in &packets {
        contract::check_wire_value(p);
        if let Ok(bytes) = p.to_bytes() {
            assert!(bytes.len() <= MAX_PACKET && bytes.len() % 4 == 0);
            assert_eq!(Packet::parse(&bytes), Ok(p.clone()));
        }
    }
    if let Ok(bytes) = Datagram(packets.clone()).to_bytes() {
        assert!(bytes.len() <= MAX_DATAGRAM);
        assert_eq!(Datagram::parse(&bytes).map(|p| p.0), Ok(packets.clone()));
    }
    if let Ok(bytes) = Compound(packets.clone()).to_bytes() {
        assert_eq!(Compound::parse(&bytes).map(|p| p.0), Ok(packets));
    }
    // NACK entries built from lost sequence numbers ask for each of them.
    let lost: Vec<u16> = list(&mut u, 40, |u| u.arbitrary())?;
    let nacks = Nack::from_lost(&lost);
    assert!(nacks.len() <= lost.len());
    let asked: Vec<u16> = nacks.iter().flat_map(Nack::lost).collect();
    assert!(lost.iter().all(|s| asked.contains(s)));
    // A DLRR block built from items gives them back, and is written only
    // when it fits a packet.
    let items = list(&mut u, 40, |u| {
        Ok(DlrrItem { ssrc: u.arbitrary()?, last_rr: u.arbitrary()?, delay_since_last_rr: u.arbitrary()? })
    })?;
    let block = XrBlock::dlrr(&items).unwrap();
    assert_eq!(block.dlrr_items(), Some(items));
    let ntp = XrBlock::receiver_reference_time(u.arbitrary()?);
    assert!(ntp.ntp_timestamp().is_some());
    let report = Packet::from(Body::ExtendedReport(ExtendedReport { ssrc: u.arbitrary()?, blocks: vec![ntp, block] }));
    let bytes = report.to_bytes().unwrap();
    assert_eq!(Packet::parse(&bytes), Ok(report));
    Ok(())
}

fuzz_target!(|data: &[u8]| {
    contract::check_decode_with_alloc_limit(Frames::<Frame>::new, data, 2 * (MAX_DATAGRAM + 2));
    contract::check_decode_with_alloc_limit(
        || Frames::<Frame>::with_limit(usize::from(data.first().copied().unwrap_or(0))),
        data,
        514,
    );
    contract::check_decode_with_alloc_limit(
        || Frames::<Frame>::new().map(|frame| Datagram::parse(&frame.0)),
        data,
        2 * (MAX_DATAGRAM + 2),
    );
    contract::check_wire::<Frame>(data);
    contract::check_wire::<Packet>(data);
    let envelope = Frame(data.get(..MAX_DATAGRAM + 1).unwrap_or(data).to_vec());
    contract::check_wire_value(&envelope);
    if let Ok(bytes) = Wire::to_bytes(&envelope) {
        contract::check_wire::<Frame>(&bytes);
    }

    // The bytes as one datagram.
    datagram(data);
    for frame in decode_all(Frames::<Frame>::new, data).0 {
        datagram(&frame.0);
    }
    let _ = built(data);
});
