//! HTTP/1 as a service (`httpd::Http1` with a handler), driven by
//! `serve::Harness` with no runtime. The fuzzer's bytes are the client's,
//! cut into two chunks at a point the first byte picks; the replies must
//! not depend on where the cut falls, the service must never panic, and
//! every answered request is one event.
#![no_main]

use bytes::Bytes;
use fictionet::stdlib::services::serve::Harness;
use fictionet::stdlib::web::httpd::{Body, Exchange, Handler, Http1, Reply};
use libfuzzer_sys::fuzz_target;

struct Pages;
impl Handler for Pages {
    fn call(&self, request: http::Request<Body>, _: &mut Exchange<'_>) -> Reply {
        let (parts, body) = request.into_parts();
        let Some(body) = body.bytes() else {
            return Reply::Now(
                http::Response::builder()
                    .status(400)
                    .body(Body::empty())
                    .unwrap(),
            );
        };
        let request = http::Request::from_parts(parts, body);
        let response = match (request.method().as_str(), request.uri().path()) {
            ("GET" | "HEAD", "/") => http::Response::new(Bytes::from("home\n")),
            ("POST", "/echo") => http::Response::new(request.into_body()),
            ("GET" | "HEAD", path) if path == "/files" || path.starts_with("/files/") => {
                http::Response::new(Bytes::from(path.to_owned()))
            }
            (_, "/" | "/echo") => http::Response::builder()
                .status(405)
                .body(Bytes::new())
                .unwrap(),
            _ => http::Response::builder()
                .status(404)
                .body(Bytes::new())
                .unwrap(),
        };
        Reply::Now(response.map(Body::from))
    }
}

#[derive(Default)]
struct Count(std::sync::atomic::AtomicUsize);

impl fictionet::events::Observer for Count {
    fn enabled(&self, interest: fictionet::events::Interest<'_>) -> bool {
        let fictionet::events::Interest::Event(_, _) = interest else {
            return false;
        };
        true
    }

    fn observe(&self, _: fictionet::events::Stamp, _: fictionet::events::Observation<'_>) {
        self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

fn run(chunks: &[&[u8]]) -> (Vec<u8>, usize, bool) {
    let events = std::sync::Arc::new(Count::default());
    let mut h =
        Harness::new(fictionet::Seed::from_u64(0), Http1::new(Pages), ()).observer(events.clone());
    for chunk in chunks {
        if h.push(chunk).is_err() {
            break;
        }
    }
    let _ = h.end();
    (
        h.output().to_vec(),
        events.0.load(std::sync::atomic::Ordering::Relaxed),
        h.closed(),
    )
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
