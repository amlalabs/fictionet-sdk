//! Git pkt-lines, requests, advertisements and negotiation lines, as a
//! world playing a Git server reads them.
#![no_main]

use fictionet::stdlib::codec::{Wire, contract};
use fictionet::stdlib::git_protocol::{
    Advertisement, Band, CapabilityAdvertisement, ClientLine, Command, Decoder, Demux, Demuxed, Frames, LsRef, MAX_BUFFERED,
    Packet, PacketError, ParseError, ProtoRequest, ServerLine, V2Request, band_packets, parse_service_header,
    service_header, split_band,
};
use libfuzzer_sys::fuzz_target;

/// The packets in `data`, fed `step` bytes at a time, and the error that
/// stopped the stream, if one did.
fn decode(mut data: &[u8], step: usize) -> (Vec<Packet>, Option<PacketError>) {
    let mut d = Decoder::new();
    let mut packets = Vec::new();
    loop {
        let n = d.feed(&data[..data.len().min(step)]);
        data = &data[n..];
        while let Some(p) = d.next_packet() {
            match p {
                Ok(p) => packets.push(p),
                Err(e) => return (packets, Some(e)),
            }
        }
        assert!(d.buffered() <= MAX_BUFFERED);
        if data.is_empty() {
            return (packets, None);
        }
    }
}

/// The same for a side-band demultiplexer.
fn demux(mut data: &[u8], step: usize) -> (Vec<Demuxed>, Option<ParseError>) {
    let mut d = Demux::new();
    let mut items = Vec::new();
    loop {
        let n = d.feed(&data[..data.len().min(step)]);
        data = &data[n..];
        while let Some(i) = d.next_item() {
            match i {
                Ok(i) => items.push(i),
                Err(e) => return (items, Some(e)),
            }
        }
        assert!(d.buffered() <= MAX_BUFFERED);
        if data.is_empty() {
            return (items, None);
        }
    }
}

fuzz_target!(|data: &[u8]| {
    contract::check_decode(Frames::new, data);
    contract::check_wire::<Packet>(data);
    let packet = Packet::Data(data.get(..fictionet::stdlib::git_protocol::MAX_DATA + 1).unwrap_or(data).to_vec());
    contract::check_wire_value(&packet);
    if let Ok(bytes) = Wire::to_bytes(&packet) {
        contract::check_wire::<Packet>(&bytes);
        contract::check_decode(Frames::new, &bytes);
    }

    // The stream, split two ways: all at once, and a byte at a time. Both
    // find the same packets and stop at the same error.
    let (packets, failed) = decode(data, usize::MAX);
    assert_eq!(decode(data, 1), (packets.clone(), failed));

    // What a decoder has not taken out is handed over as it came.
    if failed.is_none() && data.len() <= MAX_BUFFERED {
        let mut d = Decoder::new();
        assert_eq!(d.feed(data), data.len());
        while let Some(p) = d.next_packet() {
            p.unwrap();
        }
        let used: usize = packets.iter().map(|p| p.to_bytes().len()).sum();
        assert_eq!(d.into_rest(), &data[used..]);
    }

    for p in &packets {
        // A packet read can be written, and reads back the same.
        let bytes = p.to_bytes();
        contract::check_wire::<Packet>(&bytes);
        assert_eq!(Packet::parse(&bytes), Ok(Some((p.clone(), bytes.len()))));
        let Some(d) = p.data() else { continue };
        // So can each kind of line it may hold.
        if let Ok(l) = ClientLine::parse(d) {
            assert_eq!(ClientLine::parse(l.to_packet().data().unwrap()), Ok(l));
        }
        if let Ok(l) = ServerLine::parse(d) {
            assert_eq!(ServerLine::parse(l.to_packet().data().unwrap()), Ok(l));
        }
        if let Ok(r) = LsRef::parse(d) {
            assert_eq!(LsRef::parse(r.to_packet().data().unwrap()), Ok(r));
        }
        if let Ok(r) = ProtoRequest::from_data(d) {
            assert_eq!(ProtoRequest::from_data(r.to_packet().data().unwrap()), Ok(r));
        }
        let _ = split_band(d);
    }

    // Any bytes as each whole message.
    if let Ok(Some((ad, _))) = Advertisement::parse(data) {
        let bytes = ad.to_bytes();
        assert_eq!(Advertisement::parse(&bytes), Ok(Some((ad, bytes.len()))));
    }
    if let Ok(Some((ad, _))) = CapabilityAdvertisement::parse(data) {
        let bytes = ad.to_bytes();
        assert_eq!(CapabilityAdvertisement::parse(&bytes), Ok(Some((ad, bytes.len()))));
    }
    if let Ok(Some((req, _))) = V2Request::parse(data) {
        let bytes = req.to_bytes();
        assert_eq!(V2Request::parse(&bytes), Ok(Some((req.clone(), bytes.len()))));
        if let V2Request::Command(c) = &req {
            // Each fetch argument read writes back and reads back the same.
            if let Ok(args) = c.fetch_args() {
                for a in args {
                    assert_eq!(ClientLine::parse(a.to_packet().data().unwrap()), Ok(a));
                }
            }
            // So does each ls-refs argument, as a line in a request.
            if let Ok(args) = c.ls_refs_args() {
                let back = Command { name: c.name.clone(), capabilities: vec![], args: args.iter().map(|a| a.to_line()).collect() };
                assert_eq!(back.ls_refs_args(), Ok(args));
            }
        }
    }
    if let Ok(Some((s, _))) = parse_service_header(data) {
        assert_eq!(parse_service_header(&service_header(s)).unwrap().unwrap().0, s);
    }
    let _ = ProtoRequest::parse(data);

    // The side-band demultiplexer, split both ways too.
    assert_eq!(demux(data, usize::MAX), demux(data, 1));

    // Any bytes go out on a band and come back the same.
    let max = data.first().map_or(0, |&b| usize::from(b) * 300);
    let mut back = Vec::new();
    for item in demux(&band_packets(Band::Pack, data, max), usize::MAX).0 {
        let Demuxed::Data(Band::Pack, p) = item else { panic!("{item:?}") };
        back.extend(p);
    }
    assert_eq!(back, data);
});
