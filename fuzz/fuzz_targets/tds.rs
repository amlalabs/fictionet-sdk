//! TDS packets, PRELOGIN, LOGIN7, SQL batches and response tokens, as a
//! world playing SQL Server reads them.
#![no_main]

use fictionet::stdlib::tds::{
    Decoder, Login7, Packet, Prelogin, SqlBatch, Token, TokenReader, TokenWriter,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The stream, split two ways: all at once, and a byte at a time.
    let run = |chunked: bool| {
        let mut d = Decoder::with_limit(1 << 16);
        let mut got = Vec::new();
        let pieces: Vec<&[u8]> = if chunked {
            data.chunks(1).collect()
        } else {
            vec![data]
        };
        'feed: for p in pieces {
            d.feed(p);
            while let Some(m) = d.next_message() {
                let stop = m.is_err();
                got.push(m);
                if stop {
                    break 'feed;
                }
            }
        }
        got
    };
    let messages = run(false);
    assert_eq!(messages, run(true));

    for m in messages.into_iter().flatten() {
        // A message read can be written, and reads back the same.
        let mut d = Decoder::new();
        d.feed(&m.to_packets(4096));
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
        assert_eq!(Login7::parse(&l.to_bytes()), Ok(l));
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
});
