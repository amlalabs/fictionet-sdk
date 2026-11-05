//! MySQL packet, payload, and result-set contracts.
#![no_main]

use fictionet::stdlib::codec::Frames;
use fictionet::stdlib::codec::Stream;
use fictionet::stdlib::test_support::{assert_write, chunks, decode_chunks};

use fictionet::stdlib::codec::Wire;

use fictionet::stdlib::protocols::mysql::harness::check_payload;
use fictionet::stdlib::protocols::mysql::*;
use fictionet::stdlib::test_support::decode_all;
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

fn values(bytes: &[u8]) {
    let Some((&first, rest)) = bytes.split_first() else {
        return;
    };
    let caps = CAPS[usize::from(first) % CAPS.len()];
    let command = Command::Other {
        command: first,
        data: rest.to_vec(),
    };
    if let Ok(message) = command.message(0, caps) {
        assert_eq!(Command::parse(&message.payload, caps), Ok(command));
    }
    let error = ErrPacket {
        code: u16::from(first),
        sql_state: None,
        message: rest.to_vec(),
    };
    if let Ok(message) = error.message(0, caps) {
        assert_eq!(ErrPacket::parse(&message.payload, caps), Ok(error));
    }
    let row = Row((0..usize::from(first) * 17)
        .map(|i| rest.get(i).map(|&x| vec![x; usize::from(x) % 4]))
        .collect());
    let _ = assert_write(&row);
    let _ = assert_write(&HandshakeResponse {
        capabilities: u32::from_le_bytes([first, rest.first().copied().unwrap_or(0), 0x7f, 0x1f]),
        username: rest.to_vec(),
        auth_response: rest.to_vec(),
        database: rest.to_vec(),
        auth_plugin: rest.to_vec(),
        attributes: rest
            .chunks(3)
            .take(MAX_ATTRIBUTES + 1)
            .map(|c| (c.to_vec(), c.to_vec()))
            .collect(),
        zstd_level: first,
        ..HandshakeResponse::default()
    });
    let _ = assert_write(&Handshake {
        server_version: rest.to_vec(),
        auth_data: rest.to_vec(),
        capabilities: u32::from(first) << 12,
        charset: first,
        auth_plugin: rest.to_vec(),
        ..Handshake::default()
    });
    let columns = usize::from(first % 4);
    let set = ResultSet {
        columns: (0..columns)
            .map(|i| Column::new(&[b'a' + i as u8], first))
            .collect(),
        rows: rest
            .chunks(columns.max(1))
            .map(|c| {
                Row(c
                    .iter()
                    .map(|&x| (x % 3 != 0).then(|| vec![x; 2]))
                    .collect())
            })
            .collect(),
        status: u16::from(first) & !status::MORE_RESULTS_EXISTS,
        warnings: u16::from(first),
    };
    if let Ok(messages) = set.messages(0, caps) {
        let mut bytes = Vec::new();
        for message in &messages {
            message.write(&mut bytes).unwrap();
        }
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
    assert_eq!(
        decode_chunks(
            &mut Stream::new(Frames::<Packet>::new()),
            chunks(data, &[1, 7, 64]),
            |s| {
                assert!(s.allocated() <= 2 * MAX_FRAME);
            }
        ),
        decode_all(Frames::<Packet>::new, data),
    );
    let bound = 2 * (64 + HEADER_LEN);
    assert_eq!(
        decode_chunks(
            &mut Stream::new(Frames::<Packet>::with_limit(64)),
            chunks(data, &[1, 7, 64]),
            |s| {
                assert!(s.allocated() <= bound);
            }
        ),
        decode_all(|| Frames::<Packet>::with_limit(64), data),
    );
    if let Ok(value) = <Packet as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Message as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    let frame = Packet {
        seq: data.first().copied().unwrap_or(0),
        payload: data.to_vec(),
    };
    let _ = assert_write(&frame);
    let limit = data.first().map_or(MAX_MESSAGE, |&b| {
        if b & 1 == 1 {
            usize::from(b) * 3
        } else {
            MAX_MESSAGE
        }
    });
    let bound = 2 * (HEADER_LEN + limit.min(MAX_PACKET_PAYLOAD));
    assert_eq!(
        decode_chunks(
            &mut Stream::new(Messages::with_limit(limit)),
            chunks(data, &[1, 7, 64]),
            |s| {
                assert!(s.allocated() <= bound);
            }
        ),
        decode_all(|| Messages::with_limit(limit), data),
    );
    let messages = decode_all(|| Messages::with_limit(limit), data).0;
    for message in &messages {
        assert!(message.to_bytes().is_ok(), "{message:?}");
        let _ = assert_write(message);
        check_payload(&message.payload, &CAPS);
    }
    for caps in CAPS {
        let mut reader = ResultReader::new(caps);
        for message in &messages {
            let before = (reader.is_done(), reader.columns());
            match reader.push(&message.payload) {
                Ok(ResultEvent::End(ok)) if caps & capability::DEPRECATE_EOF != 0 => {
                    assert_eq!(
                        OkPacket::parse(&ok.end_message(0, caps).unwrap().payload, caps),
                        Ok(ok)
                    );
                }
                Ok(_) => {}
                Err(_) => assert_eq!((reader.is_done(), reader.columns()), before),
            }
        }
    }
    check_payload(data, &CAPS);
    values(data);
});
