//! TDS packet, message, login, batch, and token contracts.
#![no_main]

use fictionet::stdlib::codec::Frames;

use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::test_support::contract;

use fictionet::stdlib::tds::*;
use libfuzzer_sys::fuzz_target;

const LIMIT: usize = 1 << 16;

/// A value of the kind `ty` holds, made from `b`.
fn value_for(ty: u8, b: &[u8]) -> Value {
    let n = |k: usize| {
        let mut x = [0u8; 16];
        let k = k.min(b.len());
        x[..k].copy_from_slice(&b[..k]);
        u128::from_le_bytes(x)
    };
    match ty {
        data_type::INTN => Value::Int(n(4) as i32),
        data_type::DECIMALN => Value::Decimal {
            positive: b.first().is_some_and(|x| x & 1 == 1),
            value: n(16),
        },
        data_type::TIMEN => Value::Time(n(8) as u64),
        data_type::DATETIMEOFFSETN => Value::DateTimeOffset {
            time: n(5) as u64,
            date: (n(8) >> 40) as u32 & 0xff_ffff,
            offset: (n(10) >> 64) as i16,
        },
        data_type::NVARCHAR => Value::Text(String::from_utf8_lossy(b).into_owned()),
        _ => Value::Bytes(b.to_vec()),
    }
}

fn check_nbcrows(data: &[u8]) {
    let byte = |i: usize| data.get(i % data.len().max(1)).copied().unwrap_or(0);
    let count = usize::from(byte(1) % 65);
    let columns = vec![Column::new("", TypeInfo::fixed(data_type::INT1)); count];
    let mut bytes = TokenStream(vec![Token::ColMetadata(Some(columns.clone()))])
        .to_bytes()
        .unwrap();
    let start = bytes.len();
    for row in 0..usize::from(byte(2) % 9 + 1) {
        bytes.push(token::NBCROW);
        let bitmap: Vec<u8> = (0..count.div_ceil(8)).map(|i| byte(row + i)).collect();
        bytes.extend_from_slice(&bitmap);
        for i in 0..count {
            if bitmap[i / 8] & (1 << (i % 8)) == 0 {
                bytes.push(byte(row + i + 3));
            }
        }
    }
    let stream = TokenStream::parse(&bytes).unwrap();
    contract::check_wire_value(&stream);
    assert_eq!(
        TokenReader::with_columns(&bytes[start..], columns)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap(),
        stream.0[1..]
    );

    if data.len() < 4 || byte(0) != 0 || byte(1) != 0 {
        return;
    }
    // The documented production budget. Build compact wire data directly
    // to exercise the decoder's allocation limit.
    const UNITS: usize = 1 << 20;
    let limit = [UNITS - 1, UNITS, UNITS + 1][usize::from(byte(2) % 3)];
    let count = [511, 512, 513, 4095, MAX_COLUMNS][usize::from(byte(3) % 5)];
    let columns = vec![Column::new("", TypeInfo::fixed(data_type::INT1)); count];
    let mut bytes = TokenStream(vec![Token::ColMetadata(Some(columns))])
        .to_bytes()
        .unwrap();
    let rows = (limit - count - 1) / (count + 1);
    for _ in 0..rows {
        bytes.push(token::NBCROW);
        bytes.resize(bytes.len() + count.div_ceil(8), 0xff);
    }
    for _ in 0..limit - (rows + 1) * (count + 1) {
        bytes.extend_from_slice(&[token::COLMETADATA, 0xff, 0xff]);
    }
    assert!(bytes.len() < MAX_MESSAGE);
    match TokenStream::parse(&bytes) {
        Ok(stream) => {
            assert!(limit <= UNITS);
            let encoded = stream.to_bytes().unwrap();
            assert_eq!(TokenStream::parse(&encoded), Ok(stream));
        }
        Err(error) => {
            assert_eq!(limit, UNITS + 1);
            assert_eq!(error, Error::Limit("response decoded units"));
            let mut stream = TokenStream::parse(&bytes[..bytes.len() - 3]).unwrap();
            stream.0.push(Token::ColMetadata(None));
            let mut out = vec![42];
            assert_eq!(stream.write(&mut out), Err(Error::Unwritable));
            assert_eq!(out, [42]);
        }
    }
}

fuzz_target!(|data: &[u8]| {
    check_nbcrows(data);
    contract::check_decode_with_alloc_limit(Frames::<Packet>::new, data, 2 * MAX_PACKET);
    contract::check_decode_with_alloc_limit(|| Frames::<Packet>::with_limit(64), data, 128);
    harness::check_payload(data, LIMIT);
    harness::check_payload(data, 64);
    contract::check_wire_value(&Packet {
        packet_type: data.first().copied().unwrap_or(0),
        status: data.get(1).copied().unwrap_or(0),
        spid: u16::from(data.get(2).copied().unwrap_or(0)),
        id: data.get(3).copied().unwrap_or(0),
        window: data.get(4).copied().unwrap_or(0),
        data: data.to_vec(),
    });
    let tokens: Vec<Token> = TokenReader::new(data).map_while(Result::ok).collect();
    if let Some(columns) = tokens.iter().rev().find_map(|t| match t {
        Token::ColMetadata(Some(c)) => Some(c.clone()),
        _ => None,
    }) {
        for token in TokenReader::with_columns(data, columns).unwrap().take(64) {
            if token.is_err() {
                break;
            }
        }
    }
    let (head, rest) = data.split_at(data.len().min(8));
    let text = String::from_utf8_lossy(rest);
    let valid = head.first().is_none_or(|b| b & 3 != 0);
    let mut prelogin = Prelogin::new(Version::default(), encryption::OFF);
    for (i, chunk) in rest
        .chunks(9)
        .take(if valid { MAX_PRELOGIN_OPTIONS - 2 } else { 40 })
        .enumerate()
    {
        prelogin.options.push(PreloginOption {
            token: if valid {
                9 + i as u8
            } else {
                head[i % head.len()] % 10
            },
            data: chunk.to_vec(),
        });
    }
    if valid {
        assert!(prelogin.to_bytes().is_ok(), "{prelogin:?}");
    }
    contract::check_wire_value(&prelogin);
    let login = Login7 {
        option_flags3: head.first().copied().unwrap_or(0) & !option_flags3::EXTENSION,
        user_name: text.chars().take(200).collect(),
        password: text.chars().rev().take(200).collect(),
        change_password: text.chars().skip(3).take(5).collect(),
        ..Login7::new()
    };
    if let Err(error) = login.to_bytes() {
        assert_eq!(error, Error::Unwritable);
        let units = |s: &str| s.encode_utf16().count();
        assert!(
            units(&login.user_name) > MAX_LOGIN_NAME
                || units(&login.password) > MAX_LOGIN_NAME
                || (login.option_flags3 & option_flags3::CHANGE_PASSWORD == 0
                    && !login.change_password.is_empty())
        );
    }
    contract::check_wire_value(&login);
    let mut batch = SqlBatch::new(&text);
    batch.headers.as_mut().unwrap().extend(
        rest.chunks(13)
            .take(if valid { MAX_HEADERS - 1 } else { 20 })
            .enumerate()
            .map(|(i, c)| StreamHeader {
                kind: if valid {
                    0x100 + i as u16
                } else {
                    u16::from(c[0] % 4)
                },
                data: c[1..].to_vec(),
            }),
    );
    let message = batch.message();
    if valid && rest.len() <= MAX_MESSAGE / 4 {
        assert!(message.is_ok(), "{batch:?}");
    }
    if let Ok(message) = message {
        assert_eq!(SqlBatch::parse(&message.data, true), Ok(batch));
        assert!(message.to_bytes().is_ok(), "{message:?}");
        contract::check_wire_value(&message);
    }
    let kinds = [
        TypeInfo::nullable(data_type::INTN, 4),
        TypeInfo {
            max_len: [5, 9, 13, 17][head.get(3).map_or(0, |b| usize::from(*b) % 4)],
            ..TypeInfo::decimal(head.first().map_or(1, |p| p % 38 + 1), 0)
        },
        TypeInfo::scaled(data_type::TIMEN, head.get(1).map_or(0, |s| s % 8)),
        TypeInfo::scaled(data_type::DATETIMEOFFSETN, head.get(2).map_or(0, |s| s % 8)),
        TypeInfo::string(data_type::NVARCHAR, 40),
        TypeInfo {
            max_len: 8016,
            ..TypeInfo::binary(data_type::SSVARIANT, 0)
        },
    ];
    let columns = kinds.iter().map(|t| Column::new("c", t.clone())).collect();
    let row = kinds.iter().map(|t| value_for(t.ty, rest)).collect();
    contract::check_wire_value(&TokenStream(vec![
        Token::ColMetadata(Some(columns)),
        Token::Row(row),
    ]));
});
