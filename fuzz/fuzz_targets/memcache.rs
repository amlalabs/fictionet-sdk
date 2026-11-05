//! memcached text commands and replies, binary packets and UDP frames, as
//! a world playing a cache server reads them.
#![no_main]

use fictionet::stdlib::codec::Frames;
use fictionet::stdlib::codec::Stream;
use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::protocols::memcache::{
    BINARY_HEADER_LEN, Command, Commands, CounterExtras, Error, MAX_BINARY_BUFFERED, MAX_LINE,
    MAX_TEXT_HELD, MetaFlag, MetaStatus, Packet, Response, Responses, Status, StoreExtras,
    UDP_HEADER_LEN, UDP_MAX_DATAGRAM, UdpFrame,
};
use fictionet::stdlib::test_support::decode_all;
use fictionet::stdlib::test_support::{assert_write, chunks, decode_chunks};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    assert_eq!(
        decode_chunks(
            &mut Stream::new(Commands::new()),
            chunks(data, &[1, 7, 64]),
            |s| {
                assert!(s.allocated() <= 2 * MAX_LINE);
                assert!(s.held() <= MAX_TEXT_HELD);
            }
        ),
        decode_all(Commands::new, data),
    );
    assert_eq!(
        decode_chunks(
            &mut Stream::new(Responses::new()),
            chunks(data, &[1, 7, 64]),
            |s| {
                assert!(s.allocated() <= 2 * MAX_LINE);
                assert!(s.held() <= MAX_TEXT_HELD);
            }
        ),
        decode_all(Responses::new, data),
    );
    assert_eq!(
        decode_chunks(
            &mut Stream::new(Frames::<Packet>::new()),
            chunks(data, &[1, 7, 64]),
            |s| {
                assert!(s.allocated() <= 2 * MAX_BINARY_BUFFERED);
                assert_eq!(s.held(), 0);
            }
        ),
        decode_all(Frames::<Packet>::new, data),
    );
    assert_eq!(
        decode_chunks(
            &mut Stream::new(Commands::with_limit(17)),
            chunks(data, &[1, 7, 64]),
            |s| {
                assert!(s.allocated() <= 2 * MAX_LINE);
                assert!(s.held() <= MAX_TEXT_HELD);
            }
        ),
        decode_all(|| Commands::with_limit(17), data),
    );
    assert_eq!(
        decode_chunks(
            &mut Stream::new(Responses::with_limit(17)),
            chunks(data, &[1, 7, 64]),
            |s| {
                assert!(s.allocated() <= 2 * MAX_LINE);
                assert!(s.held() <= MAX_TEXT_HELD);
            }
        ),
        decode_all(|| Responses::with_limit(17), data),
    );
    let bound = 2 * (BINARY_HEADER_LEN + 17);
    assert_eq!(
        decode_chunks(
            &mut Stream::new(Frames::<Packet>::with_limit(17)),
            chunks(data, &[1, 7, 64]),
            |s| {
                assert!(s.allocated() <= bound);
            }
        ),
        decode_all(|| Frames::<Packet>::with_limit(17), data),
    );
    if let Ok(value) = <Command as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Response as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Packet as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <UdpFrame as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <StoreExtras as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <CounterExtras as Wire>::parse(data) {
        let _ = assert_write(&value);
    }

    for command in decode_all(Commands::new, data).0.iter().flatten() {
        let _ = assert_write(command);
        let bytes = command.to_bytes().unwrap();
        assert_eq!(
            decode_all(Commands::new, &bytes),
            (vec![Ok(command.clone())], None)
        );
    }
    for response in decode_all(Responses::new, data).0.iter().flatten() {
        let _ = assert_write(response);
        let bytes = response.to_bytes().unwrap();
        assert_eq!(
            decode_all(Responses::new, &bytes),
            (vec![Ok(response.clone())], None)
        );
    }

    // Writers given values built from the input, not read from it.
    let words: Vec<Vec<u8>> = data.split(|&b| b == b' ').map(<[u8]>::to_vec).collect();
    let flags: Vec<MetaFlag> = words
        .iter()
        .skip(1)
        .filter_map(|w| Some(MetaFlag::new(*w.first()?, &w[1..])))
        .collect();
    let first = words.first().cloned().unwrap_or_default();
    let _ = assert_write(&Command::Get {
        keys: words.clone(),
        cas: data.len() % 2 == 0,
    });
    let _ = assert_write(&Command::Stats {
        args: words.clone(),
    });
    let _ = assert_write(&Command::MetaGet {
        key: first.clone(),
        flags: flags.clone(),
    });
    let _ = assert_write(&Command::MetaArithmetic {
        key: first.clone(),
        flags: flags.clone(),
    });
    let _ = assert_write(&Command::MetaSet {
        key: first.clone(),
        flags: flags.clone(),
        data: data.to_vec(),
    });
    let _ = assert_write(&Response::ServerError(data.to_vec()));
    let _ = assert_write(&Response::Stat {
        name: first.clone(),
        value: data.to_vec(),
    });
    let _ = assert_write(&Response::Meta {
        status: MetaStatus::Header,
        flags,
    });

    for packet in decode_all(Frames::<Packet>::new, data).0 {
        let _ = assert_write(&packet);
        assert_eq!(
            Packet::parse(&packet.to_bytes().unwrap()),
            Ok(packet.clone())
        );
        assert_eq!(Status::from_code(packet.status).code(), packet.status);
        if let Ok(value) = <StoreExtras as Wire>::parse(&packet.extras) {
            let _ = assert_write(&value);
        }
        if let Ok(value) = <CounterExtras as Wire>::parse(&packet.extras) {
            let _ = assert_write(&value);
        }
    }

    // Any bytes as one UDP datagram.
    if let Ok(f) = UdpFrame::parse(data) {
        assert_eq!(f.to_bytes().unwrap(), data);
    }
    // Any bytes as a reply, split into datagrams and put back together.
    let split = UdpFrame::split(7, data);
    // Even an unusually large corpus entry must not panic at the count limit.
    if data.len().div_ceil(UDP_MAX_DATAGRAM - UDP_HEADER_LEN) > usize::from(u16::MAX) {
        assert_eq!(split, Err(Error::PayloadTooLong(data.len())));
        return;
    }
    let frames = split.unwrap();
    let mut back = Vec::new();
    for (i, f) in frames.iter().enumerate() {
        let bytes = f.to_bytes().unwrap();
        assert!(bytes.len() <= UDP_MAX_DATAGRAM);
        let again = UdpFrame::parse(&bytes).unwrap();
        assert_eq!(
            (
                again.request_id,
                usize::from(again.sequence),
                usize::from(again.total)
            ),
            (7, i, frames.len())
        );
        back.extend(again.payload);
    }
    assert_eq!(back, data);
});
