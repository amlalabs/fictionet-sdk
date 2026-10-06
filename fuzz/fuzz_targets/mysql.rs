//! MySQL packet, payload, and result-set contracts.
#![no_main]

use fictionet::stdlib::codec::{Wire, contract, test_support::decode_all};
use fictionet::stdlib::mysql::*;
use libfuzzer_sys::fuzz_target;

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

fn payload(bytes: &[u8]) {
    contract::check_wire::<Handshake>(bytes);
    contract::check_wire::<HandshakeResponse>(bytes);
    contract::check_wire::<SslRequest>(bytes);
    contract::check_wire::<Column>(bytes);
    contract::check_wire::<Row>(bytes);
    contract::check_wire::<LenencInt>(bytes);
    contract::check_wire::<LenencString>(bytes);
    contract::check_wire::<LocalInfile>(bytes);
    for caps in CAPS {
        if let Ok(value) = OkPacket::parse(bytes, caps) {
            assert_eq!(OkPacket::parse(&value.message(0, caps).unwrap().payload, caps), Ok(value.clone()));
            if let Ok(message) = value.end_message(0, caps) {
                assert_eq!(OkPacket::parse(&message.payload, caps), Ok(value));
            }
        }
        if let Ok(value) = ErrPacket::parse(bytes, caps) {
            assert_eq!(ErrPacket::parse(&value.message(0, caps).unwrap().payload, caps), Ok(value));
        }
        if let Ok(value) = Eof::parse(bytes, caps) {
            assert_eq!(Eof::parse(&value.message(0, caps).unwrap().payload, caps), Ok(value));
        }
        if let Ok(value) = Command::parse(bytes, caps) {
            assert_eq!(Command::parse(&value.message(0, caps).unwrap().payload, caps), Ok(value));
        }
    }
    for columns in 0..4 {
        if let Ok(row) = parse_row(bytes, columns) { contract::check_wire_value(&row); }
    }

}

fn values(bytes: &[u8]) {
    let Some((&first, rest)) = bytes.split_first() else { return };
    let caps = CAPS[usize::from(first) % CAPS.len()];
    let command = Command::Other { command: first, data: rest.to_vec() };
    if let Ok(message) = command.message(0, caps) {
        assert_eq!(Command::parse(&message.payload, caps), Ok(command));
    }
    let error = ErrPacket { code: u16::from(first), sql_state: None, message: rest.to_vec() };
    if let Ok(message) = error.message(0, caps) {
        assert_eq!(ErrPacket::parse(&message.payload, caps), Ok(error));
    }
    let row = Row((0..usize::from(first) * 17)
        .map(|i| rest.get(i).map(|&x| vec![x; usize::from(x) % 4])).collect());
    contract::check_wire_value(&row);
    contract::check_wire_value(&HandshakeResponse {
        capabilities: u32::from_le_bytes([first, rest.first().copied().unwrap_or(0), 0x7f, 0x1f]),
        username: rest.to_vec(), auth_response: rest.to_vec(), database: rest.to_vec(),
        auth_plugin: rest.to_vec(),
        attributes: rest.chunks(3).take(MAX_ATTRIBUTES + 1).map(|c| (c.to_vec(), c.to_vec())).collect(),
        zstd_level: first, ..HandshakeResponse::default()
    });
    contract::check_wire_value(&Handshake {
        server_version: rest.to_vec(), auth_data: rest.to_vec(), capabilities: u32::from(first) << 12,
        charset: first, auth_plugin: rest.to_vec(), ..Handshake::default()
    });
    let columns = usize::from(first % 4);
    let set = ResultSet {
        columns: (0..columns).map(|i| Column::new(&[b'a' + i as u8], first)).collect(),
        rows: rest.chunks(columns.max(1)).map(|c|
            Row(c.iter().map(|&x| (x % 3 != 0).then(|| vec![x; 2])).collect())).collect(),
        status: u16::from(first) & !status::MORE_RESULTS_EXISTS, warnings: u16::from(first),
    };
    if let Ok(messages) = set.messages(0, caps) {
        let mut bytes = Vec::new();
        for message in &messages { message.write(&mut bytes).unwrap(); }
        assert_eq!(decode_all(Messages::new, &bytes), (messages.clone(), None));
        let mut reader = ResultReader::new(caps);
        let mut rows = Vec::new();
        let mut end = None;
        for message in messages {
            match reader.push(&message.payload).unwrap() {
                ResultEvent::Row(row) => rows.push(row),
                ResultEvent::End(ok) | ResultEvent::Ok(ok) => end = Some(ok),
                _ => {}
            }
        }
        assert!(reader.is_done());
        assert_eq!(rows, set.rows);
        let end = end.unwrap();
        assert_eq!((end.status, end.warnings), (set.status, set.warnings));
    }
}

fuzz_target!(|data: &[u8]| {
    contract::check_decode_with_alloc_limit(Frames::new, data, 2 * MAX_FRAME);
    contract::check_decode_with_alloc_limit(|| Frames::with_limit(64), data, 2 * (64 + HEADER_LEN));
    contract::check_wire::<Frame>(data);
    contract::check_wire::<Message>(data);
    let frame = Frame { seq: data.first().copied().unwrap_or(0), payload: data.to_vec() };
    contract::check_wire_value(&frame);
    let limit = data.first().map_or(MAX_MESSAGE, |&b| if b & 1 == 1 { usize::from(b) * 3 } else { MAX_MESSAGE });
    contract::check_decode_with_alloc_limit(|| Messages::with_limit(limit), data,
        2 * (HEADER_LEN + limit.min(MAX_PACKET_PAYLOAD)));
    let messages = decode_all(|| Messages::with_limit(limit), data).0;
    for message in &messages {
        contract::check_wire_value(message);
        payload(&message.payload);
    }
    for caps in CAPS {
        let mut reader = ResultReader::new(caps);
        for message in &messages {
            let before = (reader.is_done(), reader.columns());
            match reader.push(&message.payload) {
                Ok(ResultEvent::End(ok)) if caps & capability::DEPRECATE_EOF != 0 => {
                    assert_eq!(OkPacket::parse(&ok.end_message(0, caps).unwrap().payload, caps), Ok(ok));
                }
                Ok(_) => {}
                Err(_) => assert_eq!((reader.is_done(), reader.columns()), before),
            }
        }
    }
    payload(data);
    values(data);
});
