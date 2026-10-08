//! FastCGI records, name and value pairs, and requests and responses put
//! back together, as a world playing an application or a web server reads
//! them.
#![no_main]

use fictionet::stdlib::codec::Frames;
use fictionet::stdlib::codec::{Decode, Wire};
use fictionet::stdlib::test_support::contract;
use fictionet::stdlib::test_support::decode_all;
use fictionet::stdlib::fastcgi::{
    BeginRequest, Client, ClientEvent, EndRequest, Error, MAX_CONTENT, MAX_HELD, MAX_REQUESTS, Record,
    Pairs, Request, Response, RecordStream, UnknownType, Server, ServerEvent, kind,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    contract::check_decode_with_alloc_limit(Frames::<Record>::new, data, 2 * Frames::<Record>::new().capacity());
    contract::check_wire::<Record>(data);
    let limit = usize::from(data.first().copied().unwrap_or(0));
    contract::check_decode_with_alloc_limit(
        || Frames::<Record>::with_limit(limit), data, 2 * Frames::<Record>::with_limit(limit).capacity(),
    );
    contract::check_decode_with_alloc_limit(|| Frames::<Record>::new().map(|record| BeginRequest::parse(&record.content)), data, 2 * Frames::<Record>::new().capacity());
    let built = Record {
        kind: data.first().copied().unwrap_or(0),
        request_id: 1,
        content: data.iter().take(MAX_CONTENT + 1).copied().collect(),
        padding: data.last().copied().unwrap_or(0),
    };
    contract::check_wire_value(&built);

    let whole = decode_all(Frames::<Record>::new, data).0;

    let mut server = Server::new();
    let mut client = Client::new();
    let mut client_failed = std::collections::BTreeSet::new();
    for r in &whole {
        // A record read can be written, and reads back the same.
        let bytes = r.to_bytes().unwrap();
        let back = Record::parse(&bytes).unwrap();
        assert_eq!(&back, r);

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
            for r in decode_all(Frames::<Record>::new, &req.to_bytes().unwrap()).0 {
                if let Some(ServerEvent::Request(back)) = s.receive(&r).unwrap() {
                    got = Some(back);
                }
            }
            assert_eq!(got, Some(req));
        }
        // So can a response. One with an error reported is never given.
        let failed_before = matches!(r.kind, kind::STDOUT | kind::STDERR) && client_failed.contains(&r.request_id);
        let got = client.receive(r);
        match &got {
            Err(Error::AfterEnd { id, .. } | Error::TooLarge { id, .. }) => {
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
            for r in decode_all(Frames::<Record>::new, &resp.to_bytes().unwrap()).0 {
                got = c.receive(&r).unwrap();
            }
            assert_eq!(got, Some(ClientEvent::Response(resp)));
        }
        assert!(server.open() <= MAX_REQUESTS);
        assert!(client.open() <= MAX_REQUESTS);
        assert!(server.held() <= MAX_HELD);
        assert!(client.held() <= MAX_HELD);
    }

    contract::check_wire::<Pairs>(data);
    contract::check_wire::<BeginRequest>(data);
    contract::check_wire::<EndRequest>(data);
    contract::check_wire::<UnknownType>(data);
    contract::check_wire::<RecordStream>(data);
    contract::check_wire::<Request>(data);
    contract::check_wire::<Response>(data);

    let stream = RecordStream { kind: kind::STDOUT, request_id: 1, data: data.to_vec() };
    contract::check_wire_value(&stream);
    if let Ok(bytes) = stream.to_bytes() {
        let mut client = Client::new();
        let mut got = Vec::new();
        for r in decode_all(Frames::<Record>::new, &bytes).0 {
            assert!(r.content.len() <= MAX_CONTENT);
            assert_eq!(client.receive(&r), Ok(None));
            got = r.content;
        }
        assert!(got.is_empty());
    }
    let names: Vec<&[u8]> = data.split(|&b| b == b',').collect();
    if let Ok(ask) = Record::get_values(&names) {
        assert!(ask.content.len() <= MAX_CONTENT);
        match Server::new().receive(&ask) {
            Ok(Some(ServerEvent::GetValues(back))) => assert_eq!(back, names),
            other => panic!("{other:?}"),
        }
    }
});
