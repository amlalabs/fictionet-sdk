//! TFTP packets, as a world's TFTP server reads them from the agent, the
//! options it negotiates from them, and a read transfer driven by ACKs
//! the agent picks.
#![no_main]

use fictionet::stdlib::tftp::{
    Event, MAX_BLOCK_SIZE, MAX_REQUEST, Packet, ReadTransfer, from_netascii, negotiate, to_netascii,
};
use libfuzzer_sys::fuzz_target;

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
            let _ = ReadTransfer::negotiated(data.to_vec(), &agreed).current();
        }
    }
    // A transfer of the input, with block size and ACKs taken from it.
    if let [a, b, rest @ ..] = data {
        let mut t = ReadTransfer::new(rest.to_vec(), u16::from_be_bytes([*a, *b]));
        for ack in rest.chunks_exact(2) {
            if let Event::Send(Packet::Data { data, .. }) = t.on_ack(u16::from_be_bytes([ack[0], ack[1]])) {
                assert!(data.len() <= usize::from(t.block_size()));
            }
        }
        let _ = t.current();
    }
    assert_eq!(from_netascii(&to_netascii(data)), data);
});
