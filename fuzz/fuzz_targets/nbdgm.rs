//! NetBIOS datagram service packets, as a world playing the machines on a
//! LAN reads them, and the reassembler that puts fragments back together.
#![no_main]

use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::nbdgm::{Body, Error, ErrorCode, MAX_PENDING, Name, Packet, Reassembler};
use fictionet::stdlib::test_support::contract;
use libfuzzer_sys::fuzz_target;
use std::net::Ipv4Addr;

/// SEQ\0, then big-endian u16 lengths and independently supplied UDP packets.
/// Bound both packet count and size, including the oracle's retained bytes.
fn packets(mut data: &[u8]) -> impl Iterator<Item = &[u8]> {
    (0..32).map_while(move |_| {
        let length = u16::from_be_bytes(data.get(..2)?.try_into().unwrap()) as usize;
        data = &data[2..];
        if length > 1024 || length > data.len() {
            return None;
        }
        let (packet, rest) = data.split_at(length);
        data = rest;
        Some(packet)
    })
}

/// Tracks wire coverage without split so the expected fragments are independent.
#[derive(Default)]
struct Sequence {
    reassembler: Reassembler,
    /// Whole wire headers followed by the contiguous encoded name/data region.
    pending: Vec<Vec<u8>>,
}

impl Sequence {
    /// Checks parsing and reassembly against the supplied wire bytes.
    fn push(&mut self, raw: &[u8]) -> Option<Packet> {
        let packet = Packet::parse(raw).ok()?;
        let mut want = None;
        if matches!(packet.body, Body::Datagram(_) | Body::Fragment(_)) {
            let total = u16::from_be_bytes([raw[10], raw[11]]) as usize;
            let offset = u16::from_be_bytes([raw[12], raw[13]]) as usize;
            let end = offset + raw.len() - 14;
            let first = raw[1] & 2 != 0;
            let more = raw[1] & 1 != 0;
            assert!(end <= total);
            assert_eq!(first, offset == 0);
            assert_eq!(!more, end == total);
            if let Body::Fragment(f) = &packet.body {
                assert_eq!(usize::from(f.total_length), total);
                assert_eq!(usize::from(f.offset), offset);
                assert_eq!(f.data, raw[14..]);
            }
            // The key is the datagram ID, source IP and source port on the wire.
            let at = self.pending.iter().position(|p| p[2..10] == raw[2..10]);
            if first {
                if let Some(at) = at {
                    self.pending.remove(at);
                }
                if more {
                    if self.pending.len() == MAX_PENDING {
                        self.pending.remove(0);
                    }
                    self.pending.push(raw.to_vec());
                } else {
                    want = Some(packet.clone());
                }
            } else if let Some(at) = at {
                let mut whole = self.pending.remove(at);
                if whole.len() - 14 == offset
                    && whole[10..12] == raw[10..12]
                    && whole[0] == raw[0]
                    && whole[1] & 0x0c == raw[1] & 0x0c
                {
                    whole.extend_from_slice(&raw[14..]);
                    if more {
                        self.pending.insert(at, whole);
                    } else {
                        assert_eq!(whole.len() - 14, total);
                        whole[1] &= !1;
                        // Decode names only after checking the wire coverage.
                        want = Packet::parse(&whole).ok();
                    }
                }
            }
        }
        let got = self.reassembler.push(packet);
        assert_eq!(got, want);
        assert_eq!(self.reassembler.pending(), self.pending.len());
        assert!(self.reassembler.pending() <= MAX_PENDING);
        got
    }
}

/// Checks a bounded wire sequence and recovery with an independent fragment pair.
fn sequence(data: &[u8]) {
    let mut sequence = Sequence::default();
    for raw in packets(data) {
        sequence.push(raw);
    }
    // Reuse the same state and key after malformed or incomplete sequences.
    // RFC 1001 section 17.1.2: 68 name bytes plus 512 user bytes, cut at 534.
    let mut payload =
        b" EGFCEFEECACACACACACACACACACACACA\0 CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\0".to_vec();
    payload.extend((0..512).map(|i| i as u8));
    let mut first = vec![0x10, 3, 0, 7, 10, 0, 0, 1, 0, 138, 2, 68, 0, 0];
    first.extend_from_slice(&payload[..534]);
    let mut last = vec![0x10, 0, 0, 7, 10, 0, 0, 1, 0, 138, 2, 68, 2, 22];
    last.extend_from_slice(&payload[534..]);
    assert_eq!(sequence.push(&first), None);
    let whole = sequence.push(&last).unwrap();
    let datagram = whole.as_datagram().unwrap();
    assert_eq!(datagram.source, Name::new("FRED", b' '));
    assert_eq!(datagram.destination, Name::wildcard());
    assert_eq!(datagram.data, (0..512).map(|i| i as u8).collect::<Vec<_>>());
}

fuzz_target!(|data: &[u8]| {
    if let Some(data) = data.strip_prefix(b"SEQ\0") {
        sequence(data);
        return;
    }
    contract::check_wire::<Name>(data);
    contract::check_wire::<Packet>(data);

    let here = Ipv4Addr::new(10, 0, 0, 1);
    let mut reassembler = Reassembler::new();
    // Check short prefixes and the whole datagram with bounded prefix work.
    for n in (0..=data.len().min(256)).chain((data.len() > 256).then_some(data.len())) {
        let Ok(p) = Packet::parse(&data[..n]) else {
            continue;
        };
        // A packet read can be written, and reads back the same.
        let bytes = p.to_bytes().unwrap();
        let back = Packet::parse(&bytes).unwrap();
        assert_eq!(back, p);
        assert_eq!(back.to_bytes().unwrap(), bytes);
        // Replies and fragments read back too.
        for present in [true, false] {
            if let Some(r) = p.query_response(here, 138, present) {
                contract::check_wire_value(&r);
                assert!(r.to_bytes().is_ok());
            }
        }
        let e = p.error(here, 138, ErrorCode::DestinationNameNotPresent);
        contract::check_wire_value(&e);
        assert!(e.to_bytes().is_ok());
        let mut whole = None;
        let fragments = if matches!(p.body, Body::Fragment(_)) {
            assert_eq!(p.split(534), Err(Error::Unwritable));
            vec![p.clone()]
        } else {
            p.split(1 + n % 128).unwrap()
        };
        for f in fragments {
            contract::check_wire_value(&f);
            assert!(f.to_bytes().is_ok());
            if let Some(w) = reassembler.push(f) {
                assert!(w.flags.first && !w.flags.more);
                whole = Some(w);
            }
            assert!(reassembler.pending() <= MAX_PENDING);
        }
        // The fragments of a datagram put back together give its data.
        if let Some(d) = p.as_datagram() {
            let got = whole
                .as_ref()
                .and_then(Packet::as_datagram)
                .map(|w| &w.data);
            assert_eq!(got, Some(&d.data));
        }
    }
});
