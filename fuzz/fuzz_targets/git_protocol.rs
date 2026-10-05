//! Git pkt-lines, requests, advertisements and negotiation lines, as a
//! world playing a Git server reads them.
#![no_main]

use fictionet::stdlib::git_protocol::{
    Advertisement, CapabilityAdvertisement, ClientLine, Command, Decoder, Demux, LsRef, Packet, ProtoRequest, ServerLine,
    V2Request, parse_service_header, service_header, split_band,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The stream, split two ways: all at once, and a byte at a time.
    let mut whole = Decoder::new();
    whole.feed(data);
    let mut packets = Vec::new();
    while let Some(Ok(p)) = whole.next_packet() {
        packets.push(p);
    }
    let mut bytewise = Decoder::new();
    let mut again = Vec::new();
    for b in data {
        bytewise.feed(std::slice::from_ref(b));
        while let Some(Ok(p)) = bytewise.next_packet() {
            again.push(p);
        }
    }
    assert_eq!(packets, again);

    for p in &packets {
        // A packet read can be written, and reads back the same.
        let bytes = p.to_bytes();
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
    let mut whole = Demux::new();
    whole.feed(data);
    let mut items = Vec::new();
    while let Some(Ok(i)) = whole.next_item() {
        items.push(i);
    }
    let mut bytewise = Demux::new();
    let mut again = Vec::new();
    for b in data {
        bytewise.feed(std::slice::from_ref(b));
        while let Some(Ok(i)) = bytewise.next_item() {
            again.push(i);
        }
    }
    assert_eq!(items, again);
});
