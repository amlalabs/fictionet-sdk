//! RFB (VNC) sessions, as a world playing a server or a client reads them.
#![no_main]

use fictionet::stdlib::rfb::{
    ClientMessage, ClientSession, Dialect, Error, PixelFormat, Phase, ServerInit, ServerMessage, ServerSession, Version,
};
use libfuzzer_sys::fuzz_target;

/// A server that answers whenever it is its turn, with VNC Authentication
/// or None.
fn server_turn(s: &ServerSession, vnc: bool) -> Option<ServerMessage> {
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
fn client_turn(s: &ClientSession, version: Version, vnc: bool) -> Option<ClientMessage> {
    Some(match s.phase() {
        Phase::ClientVersion => ClientMessage::Version(version),
        Phase::SecurityChoice => {
            let offered = s.offered();
            let pick = [if vnc { 2 } else { 1 }, 1, 2].into_iter().find(|t| offered.contains(t));
            ClientMessage::SecurityType(pick.unwrap_or(offered[0]))
        }
        Phase::VncResponse => ClientMessage::VncResponse([9; 16]),
        Phase::ClientInit => ClientMessage::ClientInit { shared: true },
        _ => return None,
    })
}

fn as_server<'a>(vnc: bool, chunks: impl Iterator<Item = &'a [u8]>) -> Vec<Result<ClientMessage, Error>> {
    let mut s = ServerSession::new();
    let mut got = Vec::new();
    for chunk in chunks {
        s.feed(chunk);
        loop {
            if let Some(m) = server_turn(&s, vnc) {
                s.send(&m).unwrap();
                continue;
            }
            match s.next_message() {
                Some(Ok(m)) => got.push(Ok(m)),
                Some(Err(e)) => {
                    got.push(Err(e));
                    return got;
                }
                None => break,
            }
        }
    }
    got
}

fn as_client<'a>(
    version: Version,
    vnc: bool,
    chunks: impl Iterator<Item = &'a [u8]>,
) -> Vec<Result<(ServerMessage, PixelFormat), Error>> {
    let mut s = ClientSession::new();
    let mut got = Vec::new();
    for chunk in chunks {
        s.feed(chunk);
        loop {
            if let Some(m) = client_turn(&s, version, vnc) {
                s.send(&m).unwrap();
                continue;
            }
            match s.next_message() {
                Some(Ok(m)) => got.push(Ok((m, s.pixel_format()))),
                Some(Err(e)) => {
                    got.push(Err(e));
                    return got;
                }
                None => break,
            }
        }
    }
    got
}

fuzz_target!(|data: &[u8]| {
    let Some((&choice, data)) = data.split_first() else { return };
    let vnc = choice & 1 == 1;
    let version = [Version::V3_3, Version::V3_7, Version::V3_8, Version { major: 3, minor: 889 }][usize::from(choice >> 1) % 4];

    // The stream as a server reads it, split two ways: all at once, and a
    // byte at a time.
    let whole = as_server(vnc, std::iter::once(data));
    assert_eq!(whole, as_server(vnc, data.chunks(1)));
    for m in whole.iter().flatten() {
        // A message read can be written, and reads back the same.
        let bytes = m.to_bytes();
        if !m.is_handshake() {
            assert_eq!(ClientMessage::parse(&bytes), Ok(Some((m.clone(), bytes.len()))));
        }
    }

    // The same bytes as a client reads them.
    let whole = as_client(version, vnc, std::iter::once(data));
    assert_eq!(whole, as_client(version, vnc, data.chunks(1)));
    for (m, format) in whole.iter().flatten() {
        if !m.is_handshake() {
            let bytes = m.to_bytes(Dialect::V3_8, format).unwrap();
            assert_eq!(ServerMessage::parse(&bytes, format), Ok(Some((m.clone(), bytes.len()))));
        }
    }

    // Any bytes as a message on their own.
    let _ = Version::parse(data);
    if let Ok(Some((m, _))) = ClientMessage::parse(data) {
        assert_eq!(ClientMessage::parse(&m.to_bytes()).unwrap().unwrap().0, m);
    }
    let mut format = PixelFormat::TRUE_COLOR_32;
    format.bits_per_pixel = [8, 16, 32, 24][usize::from(choice) % 4];
    if let Ok(Some((m, _))) = ServerMessage::parse(data, &format) {
        let bytes = m.to_bytes(Dialect::V3_8, &format).unwrap();
        assert_eq!(ServerMessage::parse(&bytes, &format).unwrap().unwrap().0, m);
    }
});
