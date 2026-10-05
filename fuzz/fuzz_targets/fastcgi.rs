//! FastCGI records, name and value pairs, and requests and responses put
//! back together, as a world playing an application or a web server reads
//! them.
#![no_main]

use fictionet::stdlib::codec::{Decode, contract};
use fictionet::stdlib::fastcgi::{
    BeginRequest, Client, ClientEvent, Decoder, EndRequest, Frames, MAX_BUFFERED, MAX_CONTENT,
    MAX_HELD, MAX_REQUESTS, Record, Server, ServerEvent, StreamError, encode_pairs, kind,
    parse_pairs, stream_bytes,
};
use libfuzzer_sys::fuzz_target;

/// The records in `bytes`, up to the first error.
fn records(bytes: &[u8]) -> Vec<Record> {
    let mut d = Decoder::new();
    d.feed(bytes);
    let mut out = Vec::new();
    while let Some(Ok(r)) = d.next_record() {
        out.push(r);
    }
    out
}

fuzz_target!(|data: &[u8]| {
    contract::check_decode(Frames::new, data);
    contract::check_wire::<Record>(data);
    contract::check_decode(
        || Frames::with_limit(usize::from(data.first().copied().unwrap_or(0))),
        data,
    );
    contract::check_decode(
        || Frames::new().map(|record| BeginRequest::parse(&record.content)),
        data,
    );
    let built = Record {
        kind: data.first().copied().unwrap_or(0),
        request_id: 1,
        content: data.iter().take(MAX_CONTENT + 1).copied().collect(),
        padding: data.last().copied().unwrap_or(0),
    };
    contract::check_wire_value(&built);

    // The stream, split two ways: all at once, and a byte at a time.
    let whole = records(data);
    let mut bytewise = Decoder::new();
    let mut again = Vec::new();
    for b in data {
        bytewise.feed(std::slice::from_ref(b));
        assert!(bytewise.buffered() <= MAX_BUFFERED);
        while let Some(Ok(r)) = bytewise.next_record() {
            again.push(r);
        }
    }
    // A feed past MAX_BUFFERED breaks the decoder fed all at once, while
    // one drained a byte at a time reads the records before it.
    if data.len() <= MAX_BUFFERED {
        assert_eq!(whole, again);
    } else {
        assert!(whole.is_empty());
    }

    let mut server = Server::new();
    let mut client = Client::new();
    let mut client_failed = std::collections::BTreeSet::new();
    for r in &whole {
        // A record read can be written, and reads back the same.
        let bytes = r.to_bytes();
        let (back, used) = Record::parse(&bytes).unwrap().unwrap();
        assert_eq!(&back, r);
        assert_eq!(used, bytes.len());

        // A request put together can be written, and is put together the
        // same again. Some requests are answered and ended, so their IDs
        // can be used again.
        let event = server.receive(r);
        match &event {
            Ok(Some(ServerEvent::Request(req))) if req.id % 2 == 0 => assert!(server.end(req.id)),
            Ok(Some(ServerEvent::Abort(id))) => assert!(server.end(*id)),
            _ => {}
        }
        if let Ok(Some(ServerEvent::Request(req))) = event {
            let mut s = Server::new();
            let mut got = None;
            for r in records(&req.to_bytes()) {
                if let Some(ServerEvent::Request(back)) = s.receive(&r).unwrap() {
                    got = Some(back);
                }
            }
            assert_eq!(got, Some(req));
        }
        // So can a response. One with an error reported is never given.
        let failed_before =
            matches!(r.kind, kind::STDOUT | kind::STDERR) && client_failed.contains(&r.request_id);
        let got = client.receive(r);
        match &got {
            Err(StreamError::AfterEnd { id, .. } | StreamError::TooLarge { id, .. }) => {
                client_failed.insert(*id);
            }
            Ok(Some(ClientEvent::Response(resp))) => assert!(!client_failed.contains(&resp.id)),
            _ => {}
        }
        if r.kind == kind::END_REQUEST {
            client_failed.remove(&r.request_id);
        }
        if failed_before {
            assert_eq!(got, Ok(None));
        }
        if let Ok(Some(ClientEvent::Response(resp))) = got {
            let mut c = Client::new();
            let mut got = None;
            for r in records(&resp.to_bytes()) {
                got = c.receive(&r).unwrap();
            }
            assert_eq!(got, Some(ClientEvent::Response(resp)));
        }
        assert!(server.open() <= MAX_REQUESTS);
        assert!(client.open() <= MAX_REQUESTS);
        assert!(server.held() <= MAX_HELD);
        assert!(client.held() <= MAX_HELD);
    }

    // Any bytes as pairs and as bodies on their own.
    if let Ok(pairs) = parse_pairs(data) {
        assert_eq!(parse_pairs(&encode_pairs(&pairs)), Ok(pairs));
    }
    if let Ok(b) = BeginRequest::parse(data) {
        assert_eq!(BeginRequest::parse(&b.to_bytes()), Ok(b));
    }
    if let Ok(e) = EndRequest::parse(data) {
        assert_eq!(EndRequest::parse(&e.to_bytes()), Ok(e));
    }

    // Any bytes as a stream, written and read back whole.
    let mut c = Client::new();
    let mut got = Vec::new();
    for r in records(&stream_bytes(kind::STDOUT, 1, data)) {
        assert!(r.content.len() <= MAX_CONTENT);
        assert_eq!(c.receive(&r), Ok(None));
        got = r.content;
    }
    assert!(got.is_empty());
    // Any bytes split into names for GET_VALUES, which a server reads back.
    let names: Vec<&[u8]> = data.split(|&b| b == b',').collect();
    let ask = Record::get_values(&names);
    assert!(ask.content.len() <= MAX_CONTENT);
    match Server::new().receive(&ask) {
        Ok(Some(ServerEvent::GetValues(back))) => assert!(back.len() <= names.len()),
        other => panic!("{other:?}"),
    }
});
