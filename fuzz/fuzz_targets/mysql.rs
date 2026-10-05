//! MySQL packets, handshakes, commands and result sets, as a world playing
//! a database server or client reads them.
#![no_main]

use fictionet::stdlib::codec::{Wire, contract};
use fictionet::stdlib::mysql::{
    Column, Command, Decoder, Eof, ErrPacket, Frame, FrameError, Frames, Handshake,
    HandshakeResponse, Message, OkPacket, ResultEvent, ResultReader, ResultSet, SslRequest,
    capability, parse_row, read_lenenc_int, write_lenenc_int, write_messages, write_row,
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
        | capability::OPTIONAL_RESULTSET_METADATA
        | capability::LOCAL_FILES,
];

/// Every reader on one payload: none may panic, and what one reads, its
/// writer writes so that it reads back the same.
fn payload(b: &[u8]) {
    if let Ok(h) = Handshake::parse(b) {
        assert_eq!(Handshake::parse(&h.to_payload().unwrap()), Ok(h));
    }
    if let Ok(h) = HandshakeResponse::parse(b) {
        assert_eq!(HandshakeResponse::parse(&h.to_payload().unwrap()), Ok(h));
    }
    if let Ok(s) = SslRequest::parse(b) {
        assert_eq!(SslRequest::parse(&s.to_payload()), Ok(s));
    }
    if let Ok(c) = Column::parse(b) {
        assert_eq!(Column::parse(&c.to_payload()), Ok(c));
    }
    for caps in CAPS {
        if let Ok(ok) = OkPacket::parse(b, caps) {
            assert_eq!(OkPacket::parse(&ok.to_payload(caps), caps), Ok(ok.clone()));
            assert_eq!(OkPacket::parse(&ok.to_end_payload(caps).unwrap(), caps), Ok(ok));
        }
        if let Ok(e) = ErrPacket::parse(b, caps) {
            assert_eq!(ErrPacket::parse(&e.to_payload(caps).unwrap(), caps), Ok(e));
        }
        if let Ok(e) = Eof::parse(b, caps) {
            assert_eq!(Eof::parse(&e.to_payload(caps), caps), Ok(e));
        }
        if let Ok(c) = Command::parse(b, caps) {
            assert_eq!(Command::parse(&c.to_payload(caps).unwrap(), caps), Ok(c));
        }
    }
    for n in 0..4 {
        if let Ok(row) = parse_row(b, n) {
            assert_eq!(parse_row(&write_row(&row).unwrap(), n), Ok(row));
        }
    }
    if let Ok((v, used)) = read_lenenc_int(b) {
        assert!(used <= b.len());
        let mut out = Vec::new();
        write_lenenc_int(&mut out, v);
        assert_eq!(read_lenenc_int(&out), Ok((v, out.len())));
    }
}

/// Values built straight from the bytes, not read by a parser: whatever a
/// writer accepts must read back the same.
fn values(b: &[u8]) {
    let Some((&first, rest)) = b.split_first() else { return };
    let caps = CAPS[usize::from(first) % CAPS.len()];
    let c = Command::Other { command: first, data: rest.to_vec() };
    if let Ok(p) = c.to_payload(caps) {
        assert_eq!(Command::parse(&p, caps), Ok(c));
    }
    let e = ErrPacket { code: u16::from(first), sql_state: None, message: rest.to_vec() };
    if let Ok(p) = e.to_payload(caps) {
        assert_eq!(ErrPacket::parse(&p, caps), Ok(e));
    }
    // A row of up to 4335 values, so some pass the column limit.
    let row: Vec<Option<Vec<u8>>> =
        (0..usize::from(first) * 17).map(|i| rest.get(i).map(|&x| vec![x; usize::from(x) % 4])).collect();
    if let Ok(p) = write_row(&row) {
        assert_eq!(parse_row(&p, row.len()), Ok(row));
    }
    let h = HandshakeResponse {
        capabilities: u32::from_le_bytes([first, rest.first().copied().unwrap_or(0), 0x7f, 0x1f]),
        username: rest.to_vec(),
        auth_response: rest.to_vec(),
        database: rest.to_vec(),
        auth_plugin: rest.to_vec(),
        attributes: rest.chunks(3).map(|c| (c.to_vec(), c.to_vec())).collect(),
        zstd_level: first,
        ..HandshakeResponse::default()
    };
    if let Ok(p) = h.to_payload() {
        let mut want = h.clone();
        want.capabilities |= capability::PROTOCOL_41;
        let back = HandshakeResponse::parse(&p).unwrap();
        // Fields the flags leave out are not written.
        if want.capabilities & capability::CONNECT_WITH_DB == 0 {
            want.database.clear();
        }
        if want.capabilities & capability::PLUGIN_AUTH == 0 {
            want.auth_plugin.clear();
        }
        if want.capabilities & capability::CONNECT_ATTRS == 0 {
            want.attributes.clear();
        }
        if want.capabilities & capability::ZSTD_COMPRESSION_ALGORITHM == 0 {
            want.zstd_level = 0;
        }
        assert_eq!(back, want);
    }
    let g = Handshake {
        server_version: rest.to_vec(),
        auth_data: rest.to_vec(),
        capabilities: u32::from(first) << 12,
        charset: first,
        auth_plugin: rest.to_vec(),
        ..Handshake::default()
    };
    if let Ok(p) = g.to_payload() {
        let mut want = g.clone();
        if want.capabilities & capability::PLUGIN_AUTH == 0 {
            want.auth_plugin.clear();
        }
        assert_eq!(Handshake::parse(&p), Ok(want));
    }
    // A result set, written and followed whole by a reader.
    let ncols = usize::from(first % 4);
    let set = ResultSet {
        columns: (0..ncols).map(|i| Column::new(&[b'a' + i as u8], first)).collect(),
        rows: rest
            .chunks(ncols.max(1))
            .map(|c| c.iter().map(|&x| (x % 3 != 0).then(|| vec![x; 2])).collect())
            .collect(),
        status: u16::from(first) & !0x8,
        warnings: u16::from(first),
    };
    if let Ok(payloads) = set.to_payloads(caps) {
        let (bytes, _) = write_messages(0, &payloads).unwrap();
        let (messages, error, left) = read_stream(&mut Decoder::new(), &bytes, bytes.len());
        assert_eq!((messages.len(), error, left), (payloads.len(), None, 0));
        let mut reader = ResultReader::new(caps);
        let mut rows = Vec::new();
        let mut end = None;
        for m in &messages {
            match reader.push(&m.payload).unwrap() {
                ResultEvent::Row(r) => rows.push(r),
                ResultEvent::End(ok) | ResultEvent::Ok(ok) => end = Some(ok),
                _ => {}
            }
        }
        assert!(reader.is_done());
        assert_eq!(rows, set.rows);
        // The status goes only with 4.1 or TRANSACTIONS, the warnings only
        // with 4.1.
        let end = end.unwrap();
        if caps & capability::PROTOCOL_41 != 0 {
            assert_eq!((end.status, end.warnings), (set.status, set.warnings));
        } else if caps & capability::TRANSACTIONS != 0 {
            assert_eq!(end.status, set.status);
        }
    }
}

/// Feeds `bytes` to `d` in chunks of `chunk`, taking messages out until
/// the first error. It returns the messages, the error, and how many
/// bytes the decoder never took.
fn read_stream(d: &mut Decoder, bytes: &[u8], chunk: usize) -> (Vec<Message>, Option<FrameError>, usize) {
    let mut out = Vec::new();
    let mut rest = bytes;
    while !rest.is_empty() {
        let n = d.feed(&rest[..chunk.max(1).min(rest.len())]);
        rest = &rest[n..];
        let mut took = false;
        while let Some(m) = d.next_message() {
            took = true;
            match m {
                Ok(m) => out.push(m),
                Err(e) => return (out, Some(e), 0),
            }
        }
        // A full decoder always gives a message or an error.
        assert!(n > 0 || took);
        assert!(d.buffered() <= d.capacity());
    }
    (out, None, rest.len())
}

fuzz_target!(|data: &[u8]| {
    contract::check_decode(Frames::new, data);
    contract::check_decode(|| Frames::with_limit(64), data);
    contract::check_wire::<Frame>(data);
    let frame = Frame {
        seq: data.first().copied().unwrap_or(0),
        payload: data.get(..fictionet::stdlib::mysql::MAX_PACKET_PAYLOAD + 1).unwrap_or(data).to_vec(),
    };
    contract::check_wire_value(&frame);
    if let Ok(bytes) = Wire::to_bytes(&frame) {
        contract::check_wire::<Frame>(&bytes);
        contract::check_decode(Frames::new, &bytes);
    }

    // The stream, split three ways: all at once, a byte at a time, and in
    // chunks, under a limit the first byte picks. Each must give the same
    // messages, the same error and leave the same bytes.
    let limit = match data.first() {
        Some(&b) if b & 1 == 1 => usize::from(b) * 3,
        _ => fictionet::stdlib::mysql::MAX_MESSAGE,
    };
    let whole = read_stream(&mut Decoder::with_limit(limit), data, data.len());
    assert_eq!(read_stream(&mut Decoder::with_limit(limit), data, 1), whole);
    assert_eq!(read_stream(&mut Decoder::with_limit(limit), data, 7), whole);
    let messages = whole.0;

    for m in &messages {
        // A message read can be written, and reads back the same.
        let mut d = Decoder::new();
        d.feed(&m.to_bytes().unwrap());
        assert_eq!(d.next_message().as_ref(), Some(&Ok(m.clone())));
        payload(&m.payload);
    }
    // The messages as one server answer, read under each flag set. An
    // error leaves the reader where it was.
    for caps in CAPS {
        let mut reader = ResultReader::new(caps);
        for m in &messages {
            let (done, columns) = (reader.is_done(), reader.columns());
            match reader.push(&m.payload) {
                Ok(ResultEvent::End(ok)) if caps & capability::DEPRECATE_EOF != 0 => {
                    assert_eq!(OkPacket::parse(&ok.to_end_payload(caps).unwrap(), caps), Ok(ok));
                }
                Ok(_) => {}
                Err(_) => assert_eq!((reader.is_done(), reader.columns()), (done, columns)),
            }
        }
    }
    // Any bytes as a payload on their own, and as values.
    payload(data);
    values(data);
});
