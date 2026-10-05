//! RTCP datagrams and RFC 4571 streams, as a world playing a media server
//! reads them, and packets a world builds, as it writes them.
#![no_main]

use arbitrary::{Result, Unstructured};
use fictionet::stdlib::rtcp::{
    App, Body, Bye, Decoder, ExtendedReport, Fir, MAX_BUFFERED, MAX_DATAGRAM, MAX_PACKET, Nack, Packet,
    PayloadFeedback, PayloadMessage, ReceiverReport, Remb, ReportBlock, Rpsi, SdesChunk, SdesItem, SenderReport, Sli,
    Tmmb, TransportFeedback, TransportMessage, XrBlock, check_compound, classify, frame, parse_compound, parse_packets,
    write_compound, write_packets,
};
use libfuzzer_sys::fuzz_target;

/// Feeds `data` in chunks, taking datagrams out after each feed, as a
/// world does.
fn split(data: &[u8], bytewise: bool) -> Vec<Vec<u8>> {
    let mut decoder = Decoder::new();
    let mut out = Vec::new();
    let chunks: Vec<&[u8]> = if bytewise { data.chunks(1).collect() } else { vec![data] };
    for chunk in chunks {
        let mut rest = chunk;
        while !rest.is_empty() {
            let took = decoder.feed(rest);
            assert!(decoder.buffered() <= MAX_BUFFERED);
            rest = &rest[took..];
            let mut progress = took > 0;
            while let Some(d) = decoder.next_frame() {
                out.push(d);
                progress = true;
            }
            // A full decoder always gives a datagram.
            assert!(progress);
        }
    }
    out
}

/// A datagram read every way there is. Whatever reads is written back, and
/// reads back the same.
fn datagram(data: &[u8]) {
    let _ = classify(data);
    if let Ok(packets) = parse_packets(data) {
        let bytes = write_packets(&packets).unwrap();
        assert_eq!(bytes.len(), data.len());
        assert_eq!(parse_packets(&bytes), Ok(packets.clone()));
        assert_eq!(parse_compound(data).is_ok(), check_compound(&packets).is_ok());
    }
    if let Ok((p, used)) = Packet::parse(data) {
        assert!(used <= data.len());
        let bytes = p.to_bytes().unwrap();
        assert_eq!(Packet::parse(&bytes), Ok((p, bytes.len())));
    }
}

/// Up to `max` fuzz bytes.
fn bytes(u: &mut Unstructured, max: usize) -> Result<Vec<u8>> {
    let n = u.int_in_range(0..=max)?;
    Ok(u.bytes(n)?.to_vec())
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
            extension: bytes(u, 40)?,
        }),
        1 => Body::ReceiverReport(ReceiverReport {
            ssrc: u.arbitrary()?,
            reports: list(u, 33, report_block)?,
            extension: bytes(u, 40)?,
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
        4 => {
            Body::App(App { subtype: u.arbitrary()?, ssrc: u.arbitrary()?, name: u.arbitrary()?, data: bytes(u, 40)? })
        }
        5 => {
            let message = match u.int_in_range(0..=3u8)? {
                0 => TransportMessage::Nack(list(u, 20, |u| Ok(Nack { pid: u.arbitrary()?, blp: u.arbitrary()? }))?),
                1 => TransportMessage::Tmmbr(list(u, 5, tmmb)?),
                2 => TransportMessage::Tmmbn(list(u, 5, tmmb)?),
                _ => TransportMessage::Other { fmt: u.arbitrary()?, fci: bytes(u, 40)? },
            };
            Body::TransportFeedback(TransportFeedback {
                sender_ssrc: u.arbitrary()?,
                media_ssrc: u.arbitrary()?,
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
                    data: bytes(u, 40)?,
                }),
                3 => PayloadMessage::Fir(list(u, 5, |u| Ok(Fir { ssrc: u.arbitrary()?, sequence: u.arbitrary()? }))?),
                4 => PayloadMessage::Remb(Remb {
                    exponent: u.int_in_range(0..=64)?,
                    mantissa: u.int_in_range(0..=1 << 18)?,
                    ssrcs: list(u, 260, |u| u.arbitrary())?,
                }),
                5 => PayloadMessage::Afb(bytes(u, 40)?),
                _ => PayloadMessage::Other { fmt: u.arbitrary()?, fci: bytes(u, 40)? },
            };
            Body::PayloadFeedback(PayloadFeedback { sender_ssrc: u.arbitrary()?, media_ssrc: u.arbitrary()?, message })
        }
        7 => Body::ExtendedReport(ExtendedReport {
            ssrc: u.arbitrary()?,
            blocks: list(u, 5, |u| {
                Ok(XrBlock { block_type: u.arbitrary()?, type_specific: u.arbitrary()?, data: bytes(u, 40)? })
            })?,
        }),
        _ => Body::Other { packet_type: u.arbitrary()?, count: u.arbitrary()?, data: bytes(u, 40)? },
    };
    Ok(Packet { body, padding: u.arbitrary()? })
}

/// Packets a world builds: whatever a writer accepts reads back the same.
fn built(data: &[u8]) -> Result<()> {
    let mut u = Unstructured::new(data);
    let packets = list(&mut u, 6, packet)?;
    for p in &packets {
        if let Ok(bytes) = p.to_bytes() {
            assert!(bytes.len() <= MAX_PACKET && bytes.len() % 4 == 0);
            assert_eq!(Packet::parse(&bytes), Ok((p.clone(), bytes.len())));
        }
    }
    if let Ok(bytes) = write_packets(&packets) {
        assert!(bytes.len() <= MAX_DATAGRAM);
        assert_eq!(parse_packets(&bytes), Ok(packets.clone()));
    }
    if let Ok(bytes) = write_compound(&packets) {
        assert_eq!(parse_compound(&bytes), Ok(packets));
    }
    // NACK entries built from lost sequence numbers ask for each of them.
    let lost: Vec<u16> = list(&mut u, 40, |u| u.arbitrary())?;
    let nacks = Nack::from_lost(&lost);
    assert!(nacks.len() <= lost.len());
    let asked: Vec<u16> = nacks.iter().flat_map(Nack::lost).collect();
    assert!(lost.iter().all(|s| asked.contains(s)));
    Ok(())
}

fuzz_target!(|data: &[u8]| {
    // The bytes as one datagram.
    datagram(data);
    // The bytes as an RFC 4571 stream, split two ways: all at once, and a
    // byte at a time. Both give the same datagrams.
    let datagrams = split(data, false);
    assert_eq!(split(data, true), datagrams);
    for d in &datagrams {
        assert_eq!(split(&frame(d).unwrap(), false), vec![d.clone()]);
        datagram(d);
    }
    let _ = built(data);
});
