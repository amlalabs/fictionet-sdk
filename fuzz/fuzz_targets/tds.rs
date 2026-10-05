//! TDS packets, PRELOGIN, LOGIN7, SQL batches and response tokens, as a
//! world playing SQL Server reads them, and values world code builds, as
//! the writers write them.
#![no_main]

use fictionet::stdlib::tds::{
    Column, Decoder, Error, Login7, MAX_LOGIN_NAME, MAX_PACKET, Message, Packet, Prelogin,
    PreloginOption, SqlBatch, StreamHeader, Token, TokenReader, TokenWriter, TypeInfo, Value,
    data_type,
};
use libfuzzer_sys::fuzz_target;

const LIMIT: usize = 1 << 16;

/// Every message in `data`, fed in pieces of `piece` bytes (all at once
/// for 0). A decoder takes what fits and holds no more than its bound.
fn run(data: &[u8], piece: usize) -> Vec<Result<Message, fictionet::stdlib::tds::FrameError>> {
    let mut d = Decoder::with_limit(LIMIT);
    let mut got = Vec::new();
    let mut chunks: Box<dyn Iterator<Item = &[u8]>> = if piece == 0 {
        Box::new(std::iter::once(data))
    } else {
        Box::new(data.chunks(piece))
    };
    'feed: while let Some(mut rest) = chunks.next() {
        while !rest.is_empty() {
            let took = d.feed(rest);
            rest = &rest[took..];
            assert!(d.buffered() <= 2 * LIMIT + MAX_PACKET);
            let mut any = false;
            while let Some(m) = d.next_message() {
                any = true;
                let stop = m.is_err();
                got.push(m);
                if stop {
                    break 'feed;
                }
            }
            // A decoder that took nothing always has a message to give.
            assert!(took > 0 || any);
        }
    }
    got
}

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

fuzz_target!(|data: &[u8]| {
    // The stream, split three ways: all at once, a byte at a time, and in
    // pieces. A message read can be written, and reads back the same.
    let messages = run(data, 0);
    assert_eq!(messages, run(data, 1));
    assert_eq!(messages, run(data, 7));
    for m in messages.into_iter().flatten() {
        let mut d = Decoder::new();
        let bytes = m.to_packets(4096).unwrap();
        assert_eq!(d.feed(&bytes), bytes.len());
        assert_eq!(d.next_message(), Some(Ok(m)));
    }

    // Any bytes as a single packet.
    if let Ok(Some((p, used))) = Packet::parse(data) {
        assert_eq!(Packet::parse(&p.to_bytes()), Ok(Some((p, used))));
    }

    // Any bytes as each kind of message data. What is read, written,
    // reads back the same.
    if let Ok(p) = Prelogin::parse(data) {
        assert_eq!(Prelogin::parse(&p.to_bytes()), Ok(p));
    }
    if let Ok(l) = Login7::parse(data) {
        assert_eq!(Login7::parse(&l.to_bytes().unwrap()), Ok(l));
    }
    for all_headers in [true, false] {
        if let Ok(s) = SqlBatch::parse(data, all_headers) {
            assert_eq!(SqlBatch::parse(&s.to_bytes(), all_headers), Ok(s));
        }
    }
    let tokens: Vec<Token> = TokenReader::new(data).map_while(Result::ok).collect();
    let mut w = TokenWriter::new();
    for t in &tokens {
        w.push(t).unwrap();
    }
    let back: Vec<Token> = TokenReader::new(w.bytes())
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(back, tokens);
    // Columns read can start another reader, as for a response split
    // over messages.
    let columns = tokens.iter().rev().find_map(|t| match t {
        Token::ColMetadata(Some(c)) => Some(c.clone()),
        _ => None,
    });
    if let Some(columns) = columns {
        let reader = TokenReader::with_columns(data, columns).unwrap();
        for t in reader.take(64) {
            if t.is_err() {
                break;
            }
        }
    }

    // Values world code builds, from the same bytes. The writers either
    // refuse them or write what reads back the same.
    let (head, rest) = data.split_at(data.len().min(8));
    let text = String::from_utf8_lossy(rest);
    let mut p = Prelogin::default();
    for (i, chunk) in rest.chunks(9).take(40).enumerate() {
        let token = head.get(i % head.len().max(1)).copied().unwrap_or(0) % 10;
        p.options.push(PreloginOption {
            token,
            data: chunk.to_vec(),
        });
    }
    let read = Prelogin::parse(&p.to_bytes()).unwrap();
    assert!(read.options.iter().all(Prelogin::option_valid));

    let mut l = Login7::new();
    l.option_flags3 = head.first().copied().unwrap_or(0);
    l.user_name = text.chars().take(200).collect();
    l.password = text.chars().rev().take(200).collect();
    l.change_password = text.chars().skip(3).take(5).collect();
    match l.to_bytes() {
        Ok(b) => {
            let mut want = l.clone();
            want.option_flags3 &= !0x10;
            assert_eq!(Login7::parse(&b), Ok(want));
        }
        Err(e) => {
            assert_eq!(e, Error::Unwritable);
            let units = |s: &str| s.encode_utf16().count();
            assert!(
                units(&l.user_name) > MAX_LOGIN_NAME
                    || units(&l.password) > MAX_LOGIN_NAME
                    || (l.option_flags3 & 1 == 0 && !l.change_password.is_empty())
            );
        }
    }

    let batch = SqlBatch {
        headers: Some(
            rest.chunks(13)
                .take(20)
                .map(|c| StreamHeader {
                    kind: u16::from(c[0] % 4),
                    data: c[1..].to_vec(),
                })
                .collect(),
        ),
        text: text.into_owned(),
    };
    let read = SqlBatch::parse(&batch.to_bytes(), true).unwrap();
    assert!(read.headers.unwrap().iter().all(StreamHeader::is_valid));

    let kinds = [
        TypeInfo::nullable(data_type::INTN, 4),
        TypeInfo::decimal(head.first().map_or(1, |p| p % 38 + 1), 0),
        TypeInfo::scaled(data_type::TIMEN, head.get(1).map_or(0, |s| s % 8)),
        TypeInfo::scaled(data_type::DATETIMEOFFSETN, head.get(2).map_or(0, |s| s % 8)),
        TypeInfo::string(data_type::NVARCHAR, 40),
        TypeInfo {
            max_len: 8016,
            ..TypeInfo::binary(data_type::SSVARIANT, 0)
        },
    ];
    let mut w = TokenWriter::new();
    let cols: Vec<Column> = kinds.iter().map(|t| Column::new("c", t.clone())).collect();
    w.push(&Token::ColMetadata(Some(cols))).unwrap();
    let row: Vec<Value> = kinds.iter().map(|t| value_for(t.ty, rest)).collect();
    let pushed = w.push(&Token::Row(row.clone()));
    let back: Vec<Token> = TokenReader::new(w.bytes())
        .collect::<Result<_, _>>()
        .unwrap();
    if pushed.is_ok() {
        assert_eq!(back.last(), Some(&Token::Row(row)));
    } else {
        assert_eq!(back.len(), 1);
    }
});
