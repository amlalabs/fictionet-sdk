//! TFTP packets, as a world's TFTP server reads them from the agent, the
//! options it negotiates from them, and a read transfer driven by ACKs
//! the agent picks.
#![no_main]

use fictionet::stdlib::tftp::{
    DEFAULT_BLOCK_SIZE, Event, MAX_BLOCK_SIZE, MAX_REQUEST, Negotiated, NetasciiDecoder, Packet, ReadTransfer,
    TftpOption, from_netascii, negotiate, parse_number, to_netascii,
};
use libfuzzer_sys::fuzz_target;

/// Runs a transfer to the end as a client would: ACK 0 for an OACK, then
/// each block in order, stopping at the first block shorter than the
/// block size the OACK gave (or 512 without one). Returns what the client
/// received.
fn receive(mut t: ReadTransfer) -> Vec<u8> {
    let mut size = usize::from(DEFAULT_BLOCK_SIZE);
    let mut got = Vec::new();
    let mut packet = t.current().expect("a new transfer has a packet in flight");
    loop {
        let ack = match &packet {
            Packet::OptionAck { options } => {
                assert!(!options.is_empty());
                assert_eq!(Packet::parse(&packet.to_bytes()), Ok(packet.clone()));
                if let Some(o) = options.iter().find(|o| o.name.eq_ignore_ascii_case("blksize")) {
                    size = parse_number(&o.value).and_then(|v| usize::try_from(v).ok()).expect("a valid blksize");
                }
                0
            }
            Packet::Data { block, data } => {
                assert!(data.len() <= size);
                got.extend_from_slice(data);
                if data.len() < size {
                    assert_eq!(t.on_ack(*block), Event::Complete);
                    assert_eq!(t.current(), None);
                    return got;
                }
                *block
            }
            other => panic!("sent {other:?}"),
        };
        match t.on_ack(ack) {
            Event::Send(p) => packet = p,
            other => panic!("got {other:?} before the client saw a short block"),
        }
    }
}

fuzz_target!(|data: &[u8]| {
    if let Ok(p) = Packet::parse(data) {
        // What was read can be written, and reads back the same.
        let bytes = p.to_bytes();
        if matches!(p, Packet::ReadRequest(_) | Packet::WriteRequest(_)) {
            assert!(bytes.len() <= MAX_REQUEST);
        }
        assert_eq!(Packet::parse(&bytes), Ok(p.clone()));
        let options = match &p {
            Packet::ReadRequest(r) | Packet::WriteRequest(r) => Some(&r.options),
            Packet::OptionAck { options } => Some(options),
            _ => None,
        };
        if let Some(options) = options {
            let agreed = negotiate(options, Some(data.len() as u64), MAX_BLOCK_SIZE);
            let oack = Packet::OptionAck { options: agreed.oack.clone() };
            assert_eq!(Packet::parse(&oack.to_bytes()), Ok(oack));
            // The transfer follows the parsed options as given, too, even
            // when they were not negotiated.
            for agreed in [agreed.clone(), Negotiated { oack: options.clone(), ..agreed }] {
                assert_eq!(receive(ReadTransfer::negotiated(data.to_vec(), &agreed)), data);
            }
        }
    }
    // A transfer of the input, with block size and ACKs taken from it.
    if let [a, b, rest @ ..] = data {
        let blksize = u16::from_be_bytes([*a, *b]).to_string();
        let agreed = negotiate(&[TftpOption::new("blksize", &blksize)], None, MAX_BLOCK_SIZE);
        let mut t = ReadTransfer::negotiated(rest.to_vec(), &agreed);
        for ack in rest.chunks_exact(2) {
            if let Event::Send(Packet::Data { data, .. }) = t.on_ack(u16::from_be_bytes([ack[0], ack[1]])) {
                assert!(data.len() <= usize::from(t.block_size()));
            }
        }
        let _ = t.current();
        assert_eq!(receive(ReadTransfer::negotiated(rest.to_vec(), &agreed)), rest);
        assert_eq!(receive(ReadTransfer::new(rest.to_vec())), rest);
        // Netascii read block by block gives what the whole file does.
        let size = usize::from(*a % 16) + 1;
        let mut d = NetasciiDecoder::new();
        let mut text = Vec::new();
        for block in rest.chunks(size) {
            let out = d.decode(block);
            assert!(out.len() <= block.len() + 1);
            text.extend(out);
        }
        text.extend(d.finish());
        assert_eq!(text, from_netascii(rest));
    }
    assert_eq!(from_netascii(&to_netascii(data)), data);
});
