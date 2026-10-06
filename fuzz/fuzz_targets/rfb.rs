//! RFB (VNC) sessions, as a world playing a server or a client reads them.
#![no_main]

use fictionet::stdlib::{
    codec::contract,
    rfb::{ClientMessages, ServerMessages},
};

use fictionet::stdlib::rfb::{
    ClientMessage, Client, Dialect, PixelFormat, Phase, ServerInit, ServerMessage, Server, Version, Text,
};
use libfuzzer_sys::fuzz_target;

/// A server that answers whenever it is its turn, with VNC Authentication
/// or None.
fn server_turn(s: &Server, vnc: bool) -> Option<ServerMessage> {
    Some(match s.phase() {
        Phase::ServerVersion => ServerMessage::Version(Version::V3_8),
        Phase::SecurityOffer if s.dialect() == Dialect::V3_3 => ServerMessage::SecurityType(if vnc { 2 } else { 1 }),
        Phase::SecurityOffer => ServerMessage::SecurityTypes(vec![1, 2]),
        Phase::VncChallenge => ServerMessage::VncChallenge([7; 16]),
        Phase::SecurityResult => ServerMessage::SecurityOk,
        Phase::ServerInit => {
            ServerMessage::ServerInit(ServerInit { width: 4, height: 3, format: PixelFormat::TRUE_COLOR_32, name: vec![] })
        }
        _ => return None,
    })
}

/// A client that answers whenever it is its turn.
fn client_turn(s: &Client, version: Version, vnc: bool) -> Option<ClientMessage> {
    Some(match s.phase() {
        Phase::ClientVersion => ClientMessage::Version(version),
        Phase::SecurityChoice => {
            // Type 0 is not a type, and cannot be picked.
            let offered = s.offered();
            let pick = [if vnc { 2 } else { 1 }, 1, 2].into_iter().find(|t| offered.contains(t));
            ClientMessage::SecurityType(pick.or_else(|| offered.iter().copied().find(|&t| t != 0))?)
        }
        Phase::VncResponse => ClientMessage::VncResponse([9; 16]),
        Phase::ClientInit => ClientMessage::ClientInit { shared: true },
        _ => return None,
    })
}

fuzz_target!(|data: &[u8]| {
    contract::check_wire::<Version>(data);
    contract::check_wire::<Text>(data);
    contract::check_wire::<PixelFormat>(data);
    contract::check_wire::<ServerInit>(data);
    contract::check_wire::<ClientMessage>(data);
    contract::check_wire_value(&ClientMessage::ClientCutText(
        data.iter().take(4097).copied().collect(),
    ));
    contract::check_decode_with_alloc_limit(ClientMessages::new, data, 2 * fictionet::stdlib::rfb::MAX_CLIENT_MESSAGE);
    contract::check_decode_with_alloc_limit(ServerMessages::new, data, 2 * fictionet::stdlib::rfb::MAX_MESSAGE);
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
            d.set_mode(server_phase, dialect, format).unwrap();
            d
        },
        input,
        8192,
    );
    let Some((&choice, data)) = data.split_first() else { return };
    let vnc = choice & 1 == 1;
    let version = [Version::V3_3, Version::V3_7, Version::V3_8, Version { major: 3, minor: 889 }][usize::from(choice >> 1) % 4];

    // Exercise the sessions' two-direction state with bounded input.
    let data = &data[..data.len().min(4096)];
    let mut server = Server::with_limit(4096);
    server.send(&ServerMessage::Version(Version::V3_8)).unwrap();
    let _ = server.push(data);
    loop {
        if let Some(message) = server_turn(&server, vnc) {
            server.send(&message).unwrap();
            continue;
        }
        match server.next_message() {
            Some(Ok(Ok(message))) => {
                if !message.is_handshake() { contract::check_wire_value(&message); }
            }
            _ => break,
        }
    }
    let mut client = Client::with_limit(4096);
    let _ = client.push(data);
    loop {
        if let Some(message) = client_turn(&client, version, vnc) {
            if client.send(&message).is_err() { break; }
            continue;
        }
        match client.next_message() {
            Some(Ok(Ok(message))) if !message.is_handshake() => {
                let mut bytes = Vec::new();
                message.write(client.dialect(), &client.pixel_format(), &mut bytes).unwrap();
                assert_eq!(ServerMessage::parse(&bytes, &client.pixel_format()), Ok(message));
            }
            Some(Ok(Ok(_))) => {}
            _ => break,
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
