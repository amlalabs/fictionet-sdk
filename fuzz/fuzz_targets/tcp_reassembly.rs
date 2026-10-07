#![no_main]

use arbitrary::Arbitrary;
use fictionet::stdlib::tcp_reassembly::{FlowKey, Limits, Reassembler, Segment, Chunk};
use libfuzzer_sys::fuzz_target;
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;

#[derive(Arbitrary, Debug)]
struct Input {
    byte_limit: u16,
    segment_limit: u8,
    flow_limit: u8,
    segments: Vec<Captured>,
}

#[derive(Arbitrary, Debug)]
struct Captured {
    flow: u8,
    seq: u32,
    ack: u32,
    flags: u8,
    relative: bool,
    payload: Vec<u8>,
}

fn key(flow: u8) -> FlowKey {
    let key = (
        Ipv4Addr::new(192, 0, 2, 1).into(),
        40000 + u16::from(flow / 2),
        Ipv4Addr::new(192, 0, 2, 2).into(),
        80,
    );
    if flow & 1 == 0 {
        key
    } else {
        (key.2, key.3, key.0, key.1)
    }
}

fuzz_target!(|input: Input| {
    let mut tcp = Reassembler::new(Limits {
        max_buffered: usize::from(input.byte_limit),
        max_segments: usize::from(input.segment_limit),
        max_flows: usize::from(input.flow_limit % 9),
    });
    let limits = tcp.limits();
    let mut positions = HashMap::<FlowKey, u64>::new();
    let mut ended = HashSet::new();
    let mut fed = 0usize;
    let mut delivered = 0usize;
    let mut octets = [0usize; 256];
    let mut next = [u32::MAX - 16; 8];
    for captured in input.segments.iter().take(1024) {
        let flow = captured.flow % 8;
        let dir = key(flow);
        let payload = &captured.payload[..captured.payload.len().min(4096)];
        let seq = if captured.relative {
            next[usize::from(flow)].wrapping_add((captured.seq as i8 as i32) as u32)
        } else {
            captured.seq
        };
        let flags = if captured.flags & 0x80 != 0 {
            captured.flags
        } else {
            match captured.flags % 8 {
                0 => 2,
                1 => 0x11,
                2 => 0x14,
                _ => 0x18,
            }
        };
        next[usize::from(flow)] = seq
            .wrapping_add(payload.len() as u32)
            .wrapping_add(u32::from(flags & 2 != 0));
        fed = fed.checked_add(payload.len()).unwrap();
        for byte in payload {
            octets[usize::from(*byte)] += 1;
        }
        let previous_buffered = tcp.buffered();
        let output = tcp.push(Segment {
            key: dir,
            seq,
            ack: captured.ack,
            flags,
            payload,
        });
        if output.cleared {
            positions.clear();
            ended.clear();
        }
        if output.restarted {
            positions.remove(&(dir.2, dir.3, dir.0, dir.1));
            ended.remove(&(dir.2, dir.3, dir.0, dir.1));
        }
        if flags & 2 != 0 {
            positions.remove(&dir);
            ended.remove(&dir);
        }
        let mut released = 0usize;
        let mut closed = false;
        for event in output.events {
            assert!(!closed, "end must be the last event for this segment");
            match event {
                Chunk::Bytes {
                    dir: event_dir,
                    offset,
                    bytes,
                    input_offset,
                } => {
                    assert_eq!(event_dir, dir);
                    assert!(!bytes.is_empty());
                    let position = positions.entry(dir).or_default();
                    assert_eq!(offset, *position);
                    *position = position.checked_add(bytes.len() as u64).unwrap();
                    if let Some(start) = input_offset {
                        let end = start.checked_add(bytes.len()).unwrap();
                        assert_eq!(payload.get(start..end), Some(bytes.as_slice()));
                    }
                    for byte in &bytes {
                        let remaining = &mut octets[usize::from(*byte)];
                        *remaining = remaining.checked_sub(1).expect("output must have been fed");
                    }
                    released = released.checked_add(bytes.len()).unwrap();
                }
                Chunk::Gap {
                    dir: event_dir,
                    offset,
                    ..
                } => {
                    assert_eq!(event_dir, dir);
                    assert_eq!(offset, *positions.entry(dir).or_default());
                }
                Chunk::End {
                    dir: event_dir,
                    offset,
                    reset,
                } => {
                    assert_eq!(event_dir, dir);
                    assert_eq!(offset, *positions.entry(dir).or_default());
                    assert!(ended.insert(dir), "close is reported once per direction");
                    assert_eq!(reset, flags & 4 != 0);
                    assert!(flags & 5 != 0);
                    closed = true;
                }
            }
        }
        delivered = delivered.checked_add(released).unwrap();
        assert!(delivered <= fed);
        assert!(tcp.buffered() <= limits.max_buffered);
        assert!(tcp.flows() <= limits.max_flows);
        assert!(
            tcp.buffered().checked_add(released).unwrap()
                <= previous_buffered.checked_add(payload.len()).unwrap()
        );
        for flow in 0..8 {
            assert!(tcp.buffered_segments(key(flow)) <= limits.max_segments);
        }
    }
});
