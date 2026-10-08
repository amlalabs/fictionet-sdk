//! HTTP/1 as a service (`httpd::Http1` with a router), driven by
//! `serve::Harness` with no runtime. The fuzzer's bytes are the client's,
//! cut into two chunks at a point the first byte picks; the replies must
//! not depend on where the cut falls, the service must never panic, and
//! every answered request is one event.
#![no_main]

use bytes::Bytes;
use fictionet::stdlib::httpd::{Http1, Router};
use fictionet::stdlib::serve::Harness;
use libfuzzer_sys::fuzz_target;

fn router() -> Router {
    Router::new()
        .get("/", |_, _| http::Response::new(Bytes::from("home\n")))
        .post("/echo", |_, r: http::Request<Bytes>| {
            http::Response::new(r.into_body())
        })
        .get("/files/*", |_, r| {
            http::Response::new(Bytes::from(r.uri().path().to_owned()))
        })
}

fn run(chunks: &[&[u8]]) -> (Vec<u8>, usize, bool) {
    let mut h = Harness::new(fictionet::Seed::from_u64(0), Http1::new(router()), ());
    for chunk in chunks {
        if h.push(chunk).is_err() {
            break;
        }
    }
    let _ = h.end();
    (h.output().to_vec(), h.events().len(), h.closed())
}

fuzz_target!(|data: &[u8]| {
    let Some((&cut, bytes)) = data.split_first() else {
        return;
    };
    let at = usize::from(cut).min(bytes.len());
    let whole = run(&[bytes]);
    let split = run(&[&bytes[..at], &bytes[at..]]);
    assert_eq!(whole, split, "the cut at {at} changed the replies");
    assert!(whole.2, "the connection ends at the end of input");
});
