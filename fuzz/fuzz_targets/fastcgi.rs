//! FastCGI records, name and value pairs, and requests and responses put
//! back together, as a world playing an application or a web server reads
//! them.
#![no_main]

use fictionet::stdlib::fastcgi::{
    BeginRequest, Client, ClientEvent, Decoder, EndRequest, MAX_BUFFERED, MAX_HELD, MAX_REQUESTS, Record, Server,
    ServerEvent, encode_pairs, parse_pairs,
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
    assert_eq!(whole, again);

    let mut server = Server::new();
    let mut client = Client::new();
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
        // So can a response.
        if let Ok(Some(ClientEvent::Response(resp))) = client.receive(r) {
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
});
