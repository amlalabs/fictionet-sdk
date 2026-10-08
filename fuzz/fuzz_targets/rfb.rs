//! RFB (VNC) sessions, as a world playing a server or a client reads them.
#![no_main]

use fictionet::stdlib::{
    codec::Wire,
    rfb::{ClientMessages, ServerMessages},
    test_support::chunks,
    test_support::contract,
};

use fictionet::stdlib::rfb::harness;
use fictionet::stdlib::rfb::{
    ClientMessage, Dialect, Phase, PixelFormat, ServerInit, ServerMessage, Text, Version,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    contract::check_wire::<Version>(data);
    contract::check_wire::<Text>(data);
    contract::check_wire::<PixelFormat>(data);
    contract::check_wire::<ServerInit>(data);
    contract::check_wire::<ClientMessage>(data);
    contract::check_wire_value(&ClientMessage::ClientCutText(
        data.iter().take(4097).copied().collect(),
    ));
    contract::check_decode_with_alloc_limit(
        ClientMessages::new,
        data,
        2 * fictionet::stdlib::rfb::MAX_CLIENT_MESSAGE,
    );
    contract::check_decode_with_alloc_limit(
        ServerMessages::new,
        data,
        2 * fictionet::stdlib::rfb::MAX_MESSAGE,
    );
    let selectors = [
        data.first().copied().unwrap_or(0),
        data.get(1).copied().unwrap_or(0),
        data.get(2).copied().unwrap_or(0),
        data.get(3).copied().unwrap_or(0),
    ];
    let input = data.get(4..).unwrap_or_default();
    let client_phase = [
        Phase::ClientVersion,
        Phase::SecurityChoice,
        Phase::VncResponse,
        Phase::ClientInit,
        Phase::Normal,
        Phase::Closed,
    ][usize::from(selectors[0]) % 6];
    let server_phase = [
        Phase::ServerVersion,
        Phase::SecurityOffer,
        Phase::VncChallenge,
        Phase::SecurityResult,
        Phase::ServerInit,
        Phase::Normal,
        Phase::Unsupported(42),
    ][usize::from(selectors[1]) % 7];
    let dialect = [Dialect::V3_3, Dialect::V3_7, Dialect::V3_8][usize::from(selectors[2]) % 3];
    let format = [
        PixelFormat::TRUE_COLOR_32,
        PixelFormat {
            bits_per_pixel: 8,
            depth: 8,
            true_color: false,
            ..PixelFormat::TRUE_COLOR_32
        },
        PixelFormat {
            bits_per_pixel: 16,
            depth: 16,
            true_color: false,
            ..PixelFormat::TRUE_COLOR_32
        },
    ][usize::from(selectors[3]) % 3];
    contract::check_decode_with_alloc_limit(
        || {
            let mut d = ClientMessages::with_limit(4096);
            d.set_phase(client_phase).unwrap();
            d
        },
        input,
        8192,
    );
    contract::check_decode_with_alloc_limit(
        || {
            let mut d = ServerMessages::with_limit(4096);
            d.set_phase(server_phase, dialect, format).unwrap();
            d
        },
        input,
        8192,
    );
    let Some((&choice, data)) = data.split_first() else {
        return;
    };
    let vnc = choice & 1 == 1;
    let version = [
        Version::V3_3,
        Version::V3_7,
        Version::V3_8,
        Version {
            major: 3,
            minor: 889,
        },
    ][usize::from(choice >> 1) % 4];

    // Compare the sessions across pushes, including sends inside partial units.
    let data = &data[..data.len().min(4096)];
    let whole = harness::as_server(vnc, [data]);
    assert_eq!(whole, harness::as_server(vnc, chunks(data, &[1])));
    for message in whole.iter().flatten().flatten() {
        if !message.is_handshake() {
            assert!(message.to_bytes().is_ok());
            contract::check_wire_value(message);
        }
    }
    let whole = harness::as_client(version, vnc, [data]);
    assert_eq!(whole, harness::as_client(version, vnc, chunks(data, &[1])));
    for (message, format) in whole.iter().flatten().flatten() {
        if !message.is_handshake() {
            let mut bytes = Vec::new();
            message.write(Dialect::V3_8, format, &mut bytes).unwrap();
            assert_eq!(ServerMessage::parse(&bytes, format), Ok(message.clone()));
        }
    }
    // Context-dependent writes are transactional too.
    if let Ok(message) = ServerMessage::parse(data, &format) {
        let mut bytes = vec![7, 8];
        match message.write(dialect, &format, &mut bytes) {
            Ok(()) => assert_eq!(ServerMessage::parse(&bytes[2..], &format), Ok(message)),
            Err(_) => assert_eq!(bytes, [7, 8]),
        }
    }
});
