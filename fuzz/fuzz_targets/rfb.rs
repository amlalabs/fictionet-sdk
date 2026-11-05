//! RFB (VNC) sessions, as a world playing a server or a client reads them.
#![no_main]

use fictionet::stdlib::codec::Stream;
use fictionet::stdlib::test_support::{assert_write, decode_all, decode_chunks};
use fictionet::stdlib::{
    codec::Wire,
    protocols::rfb::{ClientMessages, ServerMessages},
    test_support::chunks,
};

use fictionet::stdlib::protocols::rfb::harness;
use fictionet::stdlib::protocols::rfb::{
    ClientMessage, Dialect, Phase, PixelFormat, ServerInit, ServerMessage, Text, Version,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(value) = <Version as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Text as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <PixelFormat as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <ServerInit as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <ClientMessage as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    let _ = assert_write(&ClientMessage::ClientCutText(
        data.iter().take(4097).copied().collect(),
    ));
    assert_eq!(
        decode_chunks(
            &mut Stream::new(ClientMessages::new()),
            chunks(data, &[1, 7, 64]),
            |s| {
                assert!(s.allocated() <= 2 * fictionet::stdlib::protocols::rfb::MAX_CLIENT_MESSAGE);
            }
        ),
        decode_all(ClientMessages::new, data),
    );
    assert_eq!(
        decode_chunks(
            &mut Stream::new(ServerMessages::new()),
            chunks(data, &[1, 7, 64]),
            |s| {
                assert!(s.allocated() <= 2 * fictionet::stdlib::protocols::rfb::MAX_MESSAGE);
            }
        ),
        decode_all(ServerMessages::new, data),
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
    let client = || {
        let mut d = ClientMessages::with_limit(4096);
        d.set_phase(client_phase).unwrap();
        d
    };
    assert_eq!(
        decode_chunks(
            &mut Stream::new(client()),
            chunks(input, &[1, 7, 64]),
            |s| {
                assert!(s.allocated() <= 8192);
            }
        ),
        decode_all(client, input),
    );
    let server = || {
        let mut d = ServerMessages::with_limit(4096);
        d.set_phase(server_phase, dialect, format).unwrap();
        d
    };
    assert_eq!(
        decode_chunks(
            &mut Stream::new(server()),
            chunks(input, &[1, 7, 64]),
            |s| {
                assert!(s.allocated() <= 8192);
            }
        ),
        decode_all(server, input),
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
            let _ = assert_write(message);
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
