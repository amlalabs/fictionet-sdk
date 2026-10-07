//! TFTP packets, as a world's TFTP server reads them from the agent, the
//! options it negotiates from them, and a read transfer driven by ACKs
//! the agent picks.
#![no_main]

use fictionet::stdlib::codec::{Wire, contract};
use fictionet::stdlib::tftp::{
    DEFAULT_BLOCK_SIZE, Event, MAX_BLOCK_SIZE, MAX_REQUEST, Negotiated, NetasciiBytes, NetasciiByte,
    Packet, ReadTransfer, TftpOption, negotiate, parse_number,
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
        contract::check_wire_value(&packet);
        assert!(packet.to_bytes().is_ok());
        let ack = match &packet {
            Packet::OptionAck { options } => {
                assert!(!options.is_empty());
                assert_eq!(
                    Packet::parse(&packet.to_bytes().unwrap()),
                    Ok(packet.clone())
                );
                if let Some(o) = options.iter().find(|o| o.name.eq_ignore_ascii_case("blksize")) {
                    size = parse_number(&o.value).and_then(|v| usize::try_from(v).ok()).expect("a valid blksize");
                }
                0
            }
            Packet::Data { block, data } => {
                assert!(data.len() <= size);
                got.extend_from_slice(data);
                if data.len() < size {
                    assert_eq!(t.receive_ack(*block), Event::Complete);
                    assert_eq!(t.current(), None);
                    return got;
                }
                *block
            }
            other => panic!("sent {other:?}"),
        };
        match t.receive_ack(ack) {
            Event::Send(p) => packet = p,
            other => panic!("got {other:?} before the client saw a short block"),
        }
    }
}

fuzz_target!(|data: &[u8]| {
    contract::check_wire::<Packet>(data);
    contract::check_wire::<NetasciiByte>(data);
    contract::check_decode_with_alloc_limit(|| NetasciiBytes, data, 4);
    if let Ok(p) = Packet::parse(data) {
        // What was read can be written, and reads back the same.
        let bytes = p.to_bytes().unwrap();
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
            contract::check_wire_value(&oack);
            assert!(oack.to_bytes().is_ok());
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
            if let Event::Send(Packet::Data { data, .. }) = t.receive_ack(u16::from_be_bytes([ack[0], ack[1]])) {
                assert!(data.len() <= usize::from(t.block_size()));
            }
        }
        let _ = t.current();
        assert_eq!(receive(ReadTransfer::negotiated(rest.to_vec(), &agreed)), rest);
        assert_eq!(receive(ReadTransfer::new(rest.to_vec())), rest);
    }
    let mut encoded = Vec::new();
    for &byte in data {
        NetasciiByte(byte).write(&mut encoded).unwrap();
    }
    let (decoded, failure) =
        fictionet::stdlib::codec::test_support::decode_all(|| NetasciiBytes, &encoded);
    assert_eq!(failure, None);
    assert_eq!(decoded.into_iter().map(|b| b.0).collect::<Vec<_>>(), data);
});
