use fictionet::stdlib::codec::{Collect, Stream, Wire, finish, pump};
use fictionet::stdlib::http1::{Header, Request, Response};

// A generic item interceptor needs no protocol-specific decoder path.
fn rewrite<M: Wire>(bytes: &[u8], edit: impl FnOnce(&mut M)) -> Vec<u8>
where
    M::ParseError: Clone,
    M::WriteError: std::fmt::Debug,
{
    let mut stream = Stream::new(Collect::<M>::new(4096));
    let mut value = None;
    for chunk in bytes.chunks(3) {
        assert_eq!(
            pump(&mut stream, chunk, |item| value = Some(item)).unwrap(),
            chunk.len()
        );
    }
    finish(&mut stream, |item| value = Some(item)).unwrap();
    let mut value = value.unwrap();
    edit(&mut value);
    let mut output = Vec::new();
    value.write(&mut output).unwrap();
    output
}

#[test]
fn proxy_rewrites_a_request_header_and_body_through_wire() {
    let input = b"POST /tools HTTP/1.1\r\nHost: api.test\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n";
    let bytes = rewrite::<Request>(input, |request| {
        request
            .head
            .headers
            .retain(|h| !h.name.eq_ignore_ascii_case("transfer-encoding"));
        request.head.headers.push(Header {
            name: "X-Trace".into(),
            value: b"proxy".to_vec(),
        });
        request.body = br#"{"test":true}"#.to_vec();
        request.head.headers.push(Header {
            name: "Content-Length".into(),
            value: request.body.len().to_string().into_bytes(),
        });
    });
    let request = Request::parse(&bytes).unwrap();
    assert_eq!(request.body, br#"{"test":true}"#);
    assert!(
        request
            .head
            .headers
            .iter()
            .any(|h| h.name == "X-Trace" && h.value == b"proxy")
    );
}

#[test]
fn the_same_interceptor_can_rewrite_a_response() {
    let bytes = rewrite::<Response>(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}",
        |response| {
            response.head.status = 503;
            response.head.reason = b"Service Unavailable".to_vec();
            response.head.headers.push(Header {
                name: "Retry-After".into(),
                value: b"1".to_vec(),
            });
        },
    );
    let response = Response::parse(&bytes).unwrap();
    assert_eq!(response.head.status, 503);
    assert_eq!(response.body, b"{}");
}

#[test]
fn the_copied_module_uses_the_same_public_traits() {
    use fictionet_copy_modules::http1 as copied;
    let request = copied::Request::parse(b"GET / HTTP/1.1\r\nHost: api.test\r\n\r\n").unwrap();
    assert_eq!(
        Request::parse(&request.to_bytes().unwrap())
            .unwrap()
            .head
            .method,
        "GET"
    );
}
