//! RFB (VNC) sessions, as a world playing a server or a client reads them.
#![no_main]

use fictionet::stdlib::{
    codec::{self, Wire, contract, test_support::chunks},
    rfb::{ClientMessages, ServerMessages},
};

use fictionet::stdlib::rfb::{
    ClientMessage, Client, Dialect, Error, FrameError, PixelFormat, Phase, ServerInit, ServerMessage, Server, Version, Text,
};
use libfuzzer_sys::fuzz_target;

mod sessions {
    use super::{Client, ClientMessage, Dialect, Error, FrameError, Phase, PixelFormat, Server, ServerInit, ServerMessage, Version, codec};

    /// One session result, preserving both unit and terminal failures.
    pub type Item<T> = Result<Result<T, Error>, codec::Fail<FrameError>>;

    fn server_turn(server: &Server, vnc: bool) -> Option<ServerMessage> {
        Some(match server.phase() {
            Phase::ServerVersion => ServerMessage::Version(Version::V3_8),
            Phase::SecurityOffer if server.dialect() == Dialect::V3_3 => ServerMessage::SecurityType(if vnc { 2 } else { 1 }),
            Phase::SecurityOffer => ServerMessage::SecurityTypes(vec![1, 2]),
            Phase::VncChallenge => ServerMessage::VncChallenge([7; 16]),
            Phase::SecurityResult => ServerMessage::SecurityOk,
            Phase::ServerInit => ServerMessage::ServerInit(ServerInit {
                width: 4, height: 3, format: PixelFormat::TRUE_COLOR_32, name: vec![],
            }),
            _ => return None,
        })
    }

    fn client_turn(client: &Client, version: Version, vnc: bool) -> Option<ClientMessage> {
        Some(match client.phase() {
            Phase::ClientVersion => ClientMessage::Version(version),
            Phase::SecurityChoice => {
                let offered = client.offered();
                let pick = [if vnc { 2 } else { 1 }, 1, 2].into_iter().find(|t| offered.contains(t));
                ClientMessage::SecurityType(pick.or_else(|| offered.iter().copied().find(|&t| t != 0))?)
            }
            Phase::VncResponse => ClientMessage::VncResponse([9; 16]),
            Phase::ClientInit => ClientMessage::ClientInit { shared: true },
            _ => return None,
        })
    }

    fn server_pump(server: &mut Server, vnc: bool, got: &mut Vec<Item<ClientMessage>>) -> bool {
        loop {
            if let Some(message) = server_turn(server, vnc) {
                server.send(&message).unwrap();
                continue;
            }
            match server.next() {
                Some(item) => {
                    let failed = !matches!(item, Ok(Ok(_)));
                    got.push(item);
                    if failed {
                        return false;
                    }
                }
                None => {
                    // Sends between pushes must preserve an incomplete peer unit.
                    if server.phase() == Phase::Normal {
                        server.send(&ServerMessage::Bell).unwrap();
                    }
                    return true;
                }
            }
        }
    }

    /// Reads bounded client input with scripted server replies and intervening Bells.
    pub fn as_server<'a>(vnc: bool, chunks: impl IntoIterator<Item = &'a [u8]>) -> Vec<Item<ClientMessage>> {
        let mut server = Server::new();
        let mut got = Vec::new();
        server_pump(&mut server, vnc, &mut got);
        for chunk in chunks {
            assert_eq!(server.push(chunk), chunk.len());
            if !server_pump(&mut server, vnc, &mut got) {
                break;
            }
        }
        got
    }

    /// Reads bounded server input with scripted client replies and intervening pointer events.
    pub fn as_client<'a>(
        version: Version,
        vnc: bool,
        chunks: impl IntoIterator<Item = &'a [u8]>,
    ) -> Vec<Item<(ServerMessage, PixelFormat)>> {
        let mut client = Client::new();
        let mut got = Vec::new();
        'input: for chunk in chunks {
            assert_eq!(client.push(chunk), chunk.len());
            loop {
                if let Some(message) = client_turn(&client, version, vnc) {
                    client.send(&message).unwrap();
                    continue;
                }
                match client.next() {
                    Some(item) => {
                        let failed = !matches!(item, Ok(Ok(_)));
                        got.push(item.map(|result| result.map(|message| (message, client.pixel_format()))));
                        if failed {
                            break 'input;
                        }
                    }
                    None => {
                        // Even a send inside an update must preserve decoder progress.
                        if client.phase() == Phase::Normal {
                            client.send(&ClientMessage::PointerEvent { buttons: 0, x: 1, y: 1 }).unwrap();
                        }
                        break;
                    }
                }
            }
        }
        got
    }
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
            d.set_phase(server_phase, dialect, format).unwrap();
            d
        },
        input,
        8192,
    );
    let Some((&choice, data)) = data.split_first() else { return };
    let vnc = choice & 1 == 1;
    let version = [Version::V3_3, Version::V3_7, Version::V3_8, Version { major: 3, minor: 889 }][usize::from(choice >> 1) % 4];

    // Compare the sessions across pushes, including sends inside partial units.
    let data = &data[..data.len().min(4096)];
    let whole = sessions::as_server(vnc, [data]);
    assert_eq!(whole, sessions::as_server(vnc, chunks(data, &[1])));
    for message in whole.iter().flatten().flatten() {
        if !message.is_handshake() {
            assert!(message.to_bytes().is_ok());
            contract::check_wire_value(message);
        }
    }
    let whole = sessions::as_client(version, vnc, [data]);
    assert_eq!(whole, sessions::as_client(version, vnc, chunks(data, &[1])));
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
