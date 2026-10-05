//! MySQL packets, handshakes, commands and result sets, as a world playing
//! a database server or client reads them.
#![no_main]

use fictionet::stdlib::mysql::{
    Column, Command, Decoder, Eof, ErrPacket, Handshake, HandshakeResponse, MAX_INFO, OkPacket, ResultReader,
    SslRequest, capability, parse_row, read_lenenc_int, write_lenenc_int, write_row,
};
use libfuzzer_sys::fuzz_target;

/// Flag sets the readers are tried under: none, before 4.1, 4.1, and a
/// modern client's.
const CAPS: [u32; 4] = [
    0,
    capability::TRANSACTIONS,
    capability::PROTOCOL_41 | capability::SECURE_CONNECTION | capability::TRANSACTIONS,
    capability::PROTOCOL_41
        | capability::SECURE_CONNECTION
        | capability::TRANSACTIONS
        | capability::PLUGIN_AUTH
        | capability::PLUGIN_AUTH_LENENC_CLIENT_DATA
        | capability::CONNECT_WITH_DB
        | capability::CONNECT_ATTRS
        | capability::SESSION_TRACK
        | capability::DEPRECATE_EOF
        | capability::QUERY_ATTRIBUTES
        | capability::OPTIONAL_RESULTSET_METADATA,
];

/// Every reader on one payload: none may panic, and what one reads, its
/// writer writes so that it reads back the same.
fn payload(b: &[u8]) {
    if let Ok(h) = Handshake::parse(b) {
        assert_eq!(Handshake::parse(&h.to_payload()), Ok(h));
    }
    if let Ok(h) = HandshakeResponse::parse(b) {
        assert_eq!(HandshakeResponse::parse(&h.to_payload()), Ok(h));
    }
    if let Ok(s) = SslRequest::parse(b) {
        assert_eq!(SslRequest::parse(&s.to_payload()), Ok(s));
    }
    if let Ok(c) = Column::parse(b) {
        assert_eq!(Column::parse(&c.to_payload()), Ok(c));
    }
    for caps in CAPS {
        if let Ok(ok) = OkPacket::parse(b, caps) {
            // Writers cut longer text, so only shorter text comes back whole.
            if ok.info.len() <= MAX_INFO && ok.session_state.len() <= MAX_INFO {
                assert_eq!(OkPacket::parse(&ok.to_payload(caps), caps), Ok(ok.clone()));
                assert_eq!(OkPacket::parse(&ok.to_end_payload(caps), caps), Ok(ok));
            }
        }
        if let Ok(e) = ErrPacket::parse(b, caps) {
            assert_eq!(ErrPacket::parse(&e.to_payload(caps), caps), Ok(e));
        }
        if let Ok(e) = Eof::parse(b, caps) {
            assert_eq!(Eof::parse(&e.to_payload(caps), caps), Ok(e));
        }
        if let Ok(c) = Command::parse(b, caps) {
            assert_eq!(Command::parse(&c.to_payload(caps), caps), Ok(c));
        }
    }
    for n in 0..4 {
        if let Ok(row) = parse_row(b, n) {
            assert_eq!(parse_row(&write_row(&row), n), Ok(row));
        }
    }
    if let Ok((v, used)) = read_lenenc_int(b) {
        assert!(used <= b.len());
        let mut out = Vec::new();
        write_lenenc_int(&mut out, v);
        assert_eq!(read_lenenc_int(&out), Ok((v, out.len())));
    }
}

fuzz_target!(|data: &[u8]| {
    // The stream, split two ways: all at once, and a byte at a time.
    let mut whole = Decoder::new();
    whole.feed(data);
    let mut messages = Vec::new();
    while let Some(Ok(m)) = whole.next_message() {
        messages.push(m);
    }
    let mut bytewise = Decoder::new();
    let mut again = Vec::new();
    for b in data {
        bytewise.feed(std::slice::from_ref(b));
        while let Some(Ok(m)) = bytewise.next_message() {
            again.push(m);
        }
    }
    assert_eq!(messages, again);

    for m in &messages {
        // A message read can be written, and reads back the same.
        let mut d = Decoder::new();
        d.feed(&m.to_bytes());
        assert_eq!(d.next_message().as_ref(), Some(&Ok(m.clone())));
        payload(&m.payload);
    }
    // The messages as one server answer, read under each flag set.
    for caps in CAPS {
        let mut reader = ResultReader::new(caps);
        for m in &messages {
            let _ = reader.push(&m.payload);
        }
    }
    // Any bytes as a payload on their own.
    payload(data);
});
