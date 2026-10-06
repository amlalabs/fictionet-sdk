//! memcached text commands and replies, binary packets and UDP frames, as
//! a world playing a cache server reads them.
#![no_main]

use fictionet::stdlib::codec::{
    Wire,
    contract::{check_decode_with_alloc_limit, check_decode_with_held_limit, check_wire, check_wire_value},
    test_support::decode_all,
};
use fictionet::stdlib::memcache::{
    BINARY_HEADER_LEN, Command, Commands, CounterExtras, Frames, MAX_BINARY_BUFFERED, MAX_LINE,
    MAX_TEXT_HELD, MetaFlag, MetaStatus, Packet, Response, Responses, Status, StoreExtras,
    UDP_HEADER_LEN, UDP_MAX_DATAGRAM, UdpError, UdpFrame,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    check_decode_with_alloc_limit(Commands::new, data, 2 * MAX_LINE);
    check_decode_with_alloc_limit(Responses::new, data, 2 * MAX_LINE);
    check_decode_with_alloc_limit(Frames::new, data, 2 * MAX_BINARY_BUFFERED);
    check_decode_with_held_limit(Commands::new, data, MAX_TEXT_HELD);
    check_decode_with_held_limit(Responses::new, data, MAX_TEXT_HELD);
    check_decode_with_alloc_limit(|| Commands::with_limit(17), data, 2 * MAX_LINE);
    check_decode_with_alloc_limit(|| Responses::with_limit(17), data, 2 * MAX_LINE);
    check_decode_with_alloc_limit(
        || Frames::with_limit(17),
        data,
        2 * (BINARY_HEADER_LEN + 17),
    );
    check_decode_with_held_limit(|| Commands::with_limit(17), data, MAX_TEXT_HELD);
    check_decode_with_held_limit(|| Responses::with_limit(17), data, MAX_TEXT_HELD);
    check_decode_with_held_limit(Frames::new, data, 0);
    check_wire::<Command>(data);
    check_wire::<Response>(data);
    check_wire::<Packet>(data);
    check_wire::<UdpFrame>(data);
    check_wire::<StoreExtras>(data);
    check_wire::<CounterExtras>(data);

    for command in decode_all(Commands::new, data).0.iter().flatten() {
        check_wire_value(command);
        let bytes = command.to_bytes().unwrap();
        assert_eq!(decode_all(Commands::new, &bytes), (vec![Ok(command.clone())], None));
    }
    for response in decode_all(Responses::new, data).0.iter().flatten() {
        check_wire_value(response);
        let bytes = response.to_bytes().unwrap();
        assert_eq!(decode_all(Responses::new, &bytes), (vec![Ok(response.clone())], None));
    }

    // Writers given values built from the input, not read from it.
    let words: Vec<Vec<u8>> = data.split(|&b| b == b' ').map(<[u8]>::to_vec).collect();
    let flags: Vec<MetaFlag> = words.iter().skip(1).filter_map(|w| Some(MetaFlag::new(*w.first()?, &w[1..]))).collect();
    let first = words.first().cloned().unwrap_or_default();
    check_wire_value(&Command::Get { keys: words.clone(), cas: data.len() % 2 == 0 });
    check_wire_value(&Command::Stats { args: words.clone() });
    check_wire_value(&Command::MetaGet { key: first.clone(), flags: flags.clone() });
    check_wire_value(&Command::MetaArithmetic { key: first.clone(), flags: flags.clone() });
    check_wire_value(&Command::MetaSet { key: first.clone(), flags: flags.clone(), data: data.to_vec() });
    check_wire_value(&Response::ServerError(data.to_vec()));
    check_wire_value(&Response::Stat { name: first.clone(), value: data.to_vec() });
    check_wire_value(&Response::Meta { status: MetaStatus::Header, flags });

    for packet in decode_all(Frames::new, data).0 {
        check_wire_value(&packet);
        assert_eq!(Packet::parse(&packet.to_bytes().unwrap()), Ok(packet.clone()));
        assert_eq!(Status::from_code(packet.status).code(), packet.status);
        check_wire::<StoreExtras>(&packet.extras);
        check_wire::<CounterExtras>(&packet.extras);
    }

    // Any bytes as one UDP datagram.
    if let Ok(f) = UdpFrame::parse(data) {
        assert_eq!(f.to_bytes().unwrap(), data);
    }
    // Any bytes as a reply, split into datagrams and put back together.
    let split = UdpFrame::split(7, data);
    // Even an unusually large corpus entry must not panic at the count limit.
    if data.len().div_ceil(UDP_MAX_DATAGRAM - UDP_HEADER_LEN) > usize::from(u16::MAX) {
        assert_eq!(split, Err(UdpError::TooLong(data.len())));
        return;
    }
    let frames = split.unwrap();
    let mut back = Vec::new();
    for (i, f) in frames.iter().enumerate() {
        let bytes = f.to_bytes().unwrap();
        assert!(bytes.len() <= UDP_MAX_DATAGRAM);
        let again = UdpFrame::parse(&bytes).unwrap();
        assert_eq!((again.request_id, usize::from(again.sequence), usize::from(again.total)), (7, i, frames.len()));
        back.extend(again.payload);
    }
    assert_eq!(back, data);
});
