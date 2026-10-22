use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use fictionet::stdlib::services::serve::ConnInfo;
use fictionet::stdlib::services::serve::Harness;
use fictionet::stdlib::web::httpd::{self, Http1};

use crate::common::world;
use world::world;

// ---------------------------------------------------------------------------
// HTTP/1 as a service

fn http_text(h: &Harness<Http1>) -> String {
    String::from_utf8_lossy(h.output()).into_owned()
}

struct StreamPieces(std::vec::IntoIter<&'static [u8]>);

impl http_body::Body for StreamPieces {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Bytes>, std::convert::Infallible>>> {
        Poll::Ready(
            self.0
                .next()
                .map(|data| Ok(http_body::Frame::data(Bytes::from_static(data)))),
        )
    }
}

struct StreamHandler;

impl httpd::Handler for StreamHandler {
    fn call(
        &self,
        request: http::Request<httpd::Body>,
        _ex: &mut httpd::Exchange<'_>,
    ) -> httpd::Reply {
        let pieces: Vec<&'static [u8]> = match request.uri().path() {
            "/empty" => vec![],
            "/empty-frame" => vec![b"hello", b"", b" world"],
            _ => vec![b"hello", b" world"],
        };
        httpd::Reply::Now(http::Response::new(httpd::Body::new(StreamPieces(
            pieces.into_iter(),
        ))))
    }
}

#[test]
fn http1_streams_chunks_once_and_keeps_alive() {
    let answer = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
    for path in ["/", "/empty-frame", "/empty"] {
        let expected = if path == "/empty" {
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
        } else {
            answer
        };

        let mut h = Harness::new(fictionet::Seed::from_u64(0), Http1::new(StreamHandler), ());
        let request = format!("GET {path} HTTP/1.1\r\nHost: a.test\r\n\r\n");
        h.push(request.as_bytes()).unwrap();
        assert_eq!(http_text(&h), expected);
        assert!(!h.closed());
        h.push(request.as_bytes()).unwrap();
        assert_eq!(http_text(&h), expected.repeat(2));
        assert!(!h.closed());
    }
}

#[test]
fn http1_answers_routes_head_errors_and_keep_alive() {
    let router = {
        let route_0 = |ex: &mut fictionet::stdlib::web::httpd::Exchange<'_>,
                       _: http::Request<bytes::Bytes>| {
            assert_eq!(ex.conn().id, Some(1));
            http::Response::new(Bytes::from("hi\n"))
        };
        let route_1 = |_: &mut fictionet::stdlib::web::httpd::Exchange<'_>,
                       r: http::Request<Bytes>| {
            http::Response::new(r.into_body())
        };
        let route_2 = |_: &mut fictionet::stdlib::web::httpd::Exchange<'_>,
                       r: http::Request<bytes::Bytes>| {
            http::Response::new(Bytes::from(r.uri().path().to_owned()))
        };
        fictionet_test_support::handler(move |ex, request| {
            if request.uri().path() == "/hi"
                && (request.method() == http::Method::GET || request.method() == http::Method::HEAD)
            {
                return route_0(ex, request);
            }
            if request.uri().path() == "/echo" && (request.method() == http::Method::POST) {
                return route_1(ex, request);
            }
            if (request.uri().path() == "/files" || request.uri().path().starts_with("/files/"))
                && (request.method() == http::Method::GET || request.method() == http::Method::HEAD)
            {
                return route_2(ex, request);
            }
            if request.uri().path() == "/hi"
                || request.uri().path() == "/echo"
                || (request.uri().path() == "/files" || request.uri().path().starts_with("/files/"))
            {
                return http::Response::builder()
                    .status(405)
                    .body(bytes::Bytes::new())
                    .unwrap();
            }
            http::Response::builder()
                .status(404)
                .body(bytes::Bytes::new())
                .unwrap()
        })
    };

    let mut h = Harness::new(fictionet::Seed::from_u64(0), Http1::new(router), ());
    // Two pipelined requests, then HEAD, then an unknown path and method.
    h.push(b"GET /hi HTTP/1.1\r\nHost: a.test\r\n\r\nPOST /echo HTTP/1.1\r\nHost: a.test\r\nContent-Length: 4\r\n\r\nping").unwrap();
    h.push(b"HEAD /hi HTTP/1.1\r\nHost: a.test\r\n\r\n")
        .unwrap();
    h.push(b"GET /files/a/b HTTP/1.1\r\nHost: a.test\r\n\r\n")
        .unwrap();
    h.push(
        b"GET /nope HTTP/1.1\r\nHost: a.test\r\n\r\nDELETE /hi HTTP/1.1\r\nHost: a.test\r\n\r\n",
    )
    .unwrap();
    let text = http_text(&h);
    let answers: Vec<&str> = text.split("HTTP/1.1 ").skip(1).collect();
    assert_eq!(answers.len(), 6, "{text}");
    assert!(
        answers[0].starts_with("200 OK\r\n")
            && answers[0].ends_with("Content-Length: 3\r\n\r\nhi\n"),
        "{}",
        answers[0]
    );
    assert!(answers[1].ends_with("\r\n\r\nping"));
    // HEAD: the length a GET would have, and no body.
    assert!(
        answers[2].ends_with("Content-Length: 3\r\n\r\n"),
        "{}",
        answers[2]
    );
    assert!(answers[3].ends_with("\r\n\r\n/files/a/b"));
    assert!(answers[4].starts_with("404 Not Found"));
    assert!(answers[5].starts_with("405 Method Not Allowed"));
    assert!(!h.closed());
}

#[test]
fn http1_response_policy_preserves_native_framing() {
    for (method, status, given, length, body) in [
        ("GET", 101, "7", None, ""),
        ("GET", 103, "7", None, ""),
        ("GET", 204, "7", None, ""),
        ("GET", 304, "7", None, ""),
        ("HEAD", 200, "invalid", Some("4"), ""),
        ("GET", 200, "7", Some("4"), "body"),
    ] {
        let router = fictionet_test_support::handler(
            move |_: &mut fictionet::stdlib::web::httpd::Exchange<'_>,
                  _: http::Request<bytes::Bytes>| {
                http::Response::builder()
                    .status(status)
                    .header("content-length", given)
                    .body(Bytes::from_static(b"body"))
                    .unwrap()
            },
        );

        let mut h = Harness::new(fictionet::Seed::from_u64(0), Http1::new(router), ());
        let request = format!("{method} / HTTP/1.1\r\nHost: a.test\r\n\r\n");
        let reply = String::from_utf8(h.push(request.as_bytes()).unwrap()).unwrap();
        let (head, got) = reply.split_once("\r\n\r\n").unwrap();
        assert!(head.starts_with(&format!("HTTP/1.1 {status} ")), "{reply}");
        assert_eq!(got, body, "{reply}");
        assert_eq!(
            head.lines()
                .find_map(|line| line.strip_prefix("Content-Length: ")),
            length,
            "{reply}"
        );
        assert!(!head.contains("Transfer-Encoding"), "{reply}");
    }
}

/// Pending polls and empty frames do not terminate a chunked response.
/// The next response on the connection starts after the body's EOF.
/// Before, an HTTP/1.1 body of unknown length began with the zero-size
/// chunk, so the client saw an empty body and misread what followed.
#[test]
fn an_http11_body_of_unknown_length_ends_only_at_eof() {
    use fictionet::stdlib::web::httpd::{Body, Exchange, Handler, Reply};
    use http_body::Frame;

    struct Frames(std::vec::IntoIter<Option<&'static [u8]>>);

    impl http_body::Body for Frames {
        type Data = Bytes;
        type Error = fictionet::Error;

        fn poll_frame(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, fictionet::Error>>> {
            match self.get_mut().0.next() {
                Some(Some(data)) => Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(data))))),
                Some(None) => {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                None => Poll::Ready(None),
            }
        }
    }

    struct Paced;

    impl Handler for Paced {
        fn call(&self, request: http::Request<Body>, _: &mut Exchange<'_>) -> Reply {
            let body = if request.uri().path() == "/next" {
                Body::from(Bytes::from_static(b"next\n"))
            } else {
                Body::new(Frames(
                    vec![
                        None,
                        Some(b"".as_slice()),
                        Some(b"stream".as_slice()),
                        None,
                        Some(b"".as_slice()),
                        Some(b"ed\n".as_slice()),
                        Some(b"".as_slice()),
                        None,
                    ]
                    .into_iter(),
                ))
            };
            Reply::Now(http::Response::new(body))
        }
    }

    let mut h = Harness::new(fictionet::Seed::from_u64(0), Http1::new(Paced), ());
    let mut reply = h.push(b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n").unwrap();
    let text = std::str::from_utf8(&reply).unwrap();
    let (head, body) = text.split_once("\r\n\r\n").unwrap();
    assert!(head.contains("Transfer-Encoding: chunked"), "{head}");
    assert_eq!(
        body, "6\r\nstream\r\n3\r\ned\n\r\n0\r\n\r\n",
        "wire: {text:?}"
    );
    assert_eq!(h.end_reason(), None);

    reply.extend(
        h.push(b"GET /next HTTP/1.1\r\nHost: a.test\r\n\r\n")
            .unwrap(),
    );
    let mut responses = fictionet::stdlib::codec::Stream::new(
        fictionet::stdlib::protocols::http1::Responses::default(),
    );
    assert_eq!(responses.push(&reply), reply.len());
    let first = responses.next().unwrap().unwrap();
    assert_eq!(first.head.status, 200);
    assert_eq!(first.body, b"streamed\n");
    let second = responses.next().unwrap().unwrap();
    assert_eq!(second.head.status, 200);
    assert_eq!(second.body, b"next\n");
    assert!(responses.next().is_none());
    assert_eq!(h.end_reason(), None);
}

#[test]
fn an_http11_request_with_no_host_gets_400_from_the_service() {
    let vhosts = httpd::VirtualHosts::new();

    let mut h = Harness::new(fictionet::Seed::from_u64(0), Http1::new(vhosts), ());
    let _ = h.push(b"GET /x HTTP/1.1\r\nAccept: */*\r\n\r\n");
    assert!(
        http_text(&h).starts_with("HTTP/1.1 400 Bad Request"),
        "{}",
        http_text(&h)
    );
    assert!(h.closed());
}

#[test]
fn an_http11_absolute_request_with_no_host_gets_400_from_the_service() {
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let vhosts = httpd::VirtualHosts::new();
    vhosts.insert(
        "a.test",
        httpd::VHost::new(fictionet_test_support::handler(
            move |_: &mut fictionet::stdlib::web::httpd::Exchange<'_>,
                  _: http::Request<bytes::Bytes>| {
                count.fetch_add(1, Ordering::SeqCst);
                http::Response::new(Bytes::from("ok"))
            },
        )),
    );

    let mut h = Harness::new(fictionet::Seed::from_u64(0), Http1::new(vhosts), ());
    assert!(h.push(b"GET http://a.test/ HTTP/1.1\r\n\r\n").is_err());
    assert!(
        http_text(&h).starts_with("HTTP/1.1 400 Bad Request"),
        "{}",
        http_text(&h)
    );
    assert!(http_text(&h).ends_with("\r\n\r\nThe request names no host.\n"));
    assert!(h.closed());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn a_router_receives_no_host_requests_only_for_http10() {
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let router = fictionet_test_support::handler(
        move |_: &mut fictionet::stdlib::web::httpd::Exchange<'_>,
              _: http::Request<bytes::Bytes>| {
            count.fetch_add(1, Ordering::SeqCst);
            http::Response::new(Bytes::from("ok"))
        },
    );
    let mut h = Harness::new(fictionet::Seed::from_u64(0), Http1::new(router.clone()), ());
    assert!(h.push(b"GET /x HTTP/1.1\r\n\r\n").is_err());
    assert!(
        http_text(&h).starts_with("HTTP/1.1 400 Bad Request"),
        "{}",
        http_text(&h)
    );
    assert!(h.closed());
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    let mut h = Harness::new(fictionet::Seed::from_u64(0), Http1::new(router), ());
    h.push(b"GET /x HTTP/1.0\r\n\r\n").unwrap();
    assert!(http_text(&h).starts_with("HTTP/1.0 200 OK"));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn http1_closes_when_asked_and_on_http10() {
    let router = fictionet_test_support::handler(
        |_: &mut fictionet::stdlib::web::httpd::Exchange<'_>, _: http::Request<bytes::Bytes>| {
            http::Response::new(Bytes::from("x"))
        },
    );
    let mut h = Harness::new(fictionet::Seed::from_u64(0), Http1::new(router.clone()), ());
    h.push(b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n")
        .unwrap();
    assert!(h.closed());
    assert!(http_text(&h).contains("Connection: close\r\n"));
    let mut h = Harness::new(fictionet::Seed::from_u64(0), Http1::new(router.clone()), ());
    h.push(b"GET / HTTP/1.0\r\n\r\n").unwrap();
    assert!(h.closed());
    assert!(http_text(&h).starts_with("HTTP/1.0 200 OK"));
    // HTTP/1.0 with keep-alive stays open.
    let mut h = Harness::new(fictionet::Seed::from_u64(0), Http1::new(router), ());
    h.push(b"GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n")
        .unwrap();
    assert!(!h.closed());
    assert!(http_text(&h).contains("Connection: keep-alive\r\n"));
}

#[test]
fn http1_handler_connection_close() {
    for connection in ["close", "keep-alive, Close", "keep-alive, \tClose \t"] {
        let router = fictionet_test_support::handler(
            move |_: &mut fictionet::stdlib::web::httpd::Exchange<'_>,
                  _: http::Request<bytes::Bytes>| {
                http::Response::builder()
                    .header("connection", connection)
                    .body(Bytes::from("first"))
                    .unwrap()
            },
        );
        let mut h = Harness::new(fictionet::Seed::from_u64(0), Http1::new(router), ());
        h.push(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n").unwrap();
        assert!(
            http_text(&h).contains("Connection: close\r\n"),
            "{connection}"
        );
        assert!(http_text(&h).ends_with("\r\n\r\nfirst"));
        assert!(h.closed());
    }
}

#[test]
fn http1_handler_connection_close_stops_pipeline() {
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let router = fictionet_test_support::handler(
        move |_: &mut fictionet::stdlib::web::httpd::Exchange<'_>,
              _: http::Request<bytes::Bytes>| {
            count.fetch_add(1, Ordering::SeqCst);
            http::Response::builder()
                .header("connection", "close")
                .body(Bytes::from("first"))
                .unwrap()
        },
    );
    let mut h = Harness::new(fictionet::Seed::from_u64(0), Http1::new(router), ());
    h.push(b"GET / HTTP/1.1\r\nHost: a\r\n\r\nGET / HTTP/1.1\r\nHost: a\r\n\r\n")
        .unwrap();
    assert_eq!(http_text(&h).matches("HTTP/1.1 200 OK").count(), 1);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(http_text(&h).contains("Connection: close\r\n"));
    assert!(h.closed());
}

#[test]
fn http1_handler_connection_keep_alive_is_stripped() {
    let router = fictionet_test_support::handler(
        |_: &mut fictionet::stdlib::web::httpd::Exchange<'_>, _: http::Request<bytes::Bytes>| {
            http::Response::builder()
                .header("connection", "keep-alive")
                .body(Bytes::from("ok"))
                .unwrap()
        },
    );
    let mut h = Harness::new(fictionet::Seed::from_u64(0), Http1::new(router), ());
    h.push(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n").unwrap();
    assert!(http_text(&h).starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(!http_text(&h).contains("Connection:"));
    assert!(!h.closed());
}

#[test]
fn http1_handler_connection_close_async() {
    world(Duration::from_secs(10), |fcx| async move {
        let router = fictionet_test_support::async_handler(
            |_: fictionet::Cx, _: http::Request<bytes::Bytes>| async {
                http::Response::builder()
                    .header("connection", "close")
                    .body(Bytes::from("first"))
                    .unwrap()
            },
        );
        let mut h =
            Harness::new(fictionet::Seed::from_u64(0), Http1::new(router), ()).with_fcx(fcx);
        h.push(b"GET / HTTP/1.1\r\nHost: a\r\n\r\nGET / HTTP/1.1\r\nHost: a\r\n\r\n")
            .unwrap();
        assert!(http_text(&h).contains("Connection: close\r\n"));
        assert_eq!(http_text(&h).matches("HTTP/1.1 200 OK").count(), 1);
        assert!(http_text(&h).ends_with("\r\n\r\nfirst"));
        assert!(h.closed());
        Ok(())
    });
}

#[test]
fn http1_rejects_unsupported_transfer_codings_before_dispatch() {
    for (coding, status) in [
        ("gzip, chunked", "501 Not Implemented"),
        ("gzip", "400 Bad Request"),
    ] {
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let router = fictionet_test_support::handler(
            move |_: &mut fictionet::stdlib::web::httpd::Exchange<'_>,
                  _: http::Request<bytes::Bytes>| {
                count.fetch_add(1, Ordering::SeqCst);
                http::Response::new(Bytes::new())
            },
        );

        let mut h = Harness::new(fictionet::Seed::from_u64(0), Http1::new(router), ());
        let request = format!(
            "POST /u HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: {coding}\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
        );
        let result = h.push(request.as_bytes());
        assert_eq!(calls.load(Ordering::SeqCst), 0, "{coding}");
        assert!(result.is_err());
        assert!(http_text(&h).starts_with(&format!("HTTP/1.1 {status}\r\n")));
        assert!(h.closed());
    }
}

#[test]
fn http1_answers_bytes_that_are_not_http_with_400_() {
    let mut h = Harness::new(
        fictionet::Seed::from_u64(0),
        Http1::new(fictionet_test_support::handler(|_, _| {
            http::Response::builder()
                .status(404)
                .body(bytes::Bytes::new())
                .unwrap()
        })),
        (),
    );
    assert!(h.push(b"\x16\x03\x01\x00\x05hello\r\n\r\n").is_err());
    assert!(http_text(&h).starts_with("HTTP/1.1 400 Bad Request"));
    assert!(h.closed());
}

#[test]
fn http1_sends_100_continue_and_rejects_a_cut_off_body_before_the_router_callback() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let keep = seen.clone();
    let router = fictionet_test_support::handler(
        move |_: &mut fictionet::stdlib::web::httpd::Exchange<'_>, r: http::Request<Bytes>| {
            keep.lock().unwrap().push(r.body().len());
            http::Response::new(Bytes::new())
        },
    );
    let mut h = Harness::new(fictionet::Seed::from_u64(0), Http1::new(router), ());
    h.push(b"POST /u HTTP/1.1\r\nHost: a\r\nExpect: 100-continue\r\nContent-Length: 2\r\n\r\n")
        .unwrap();
    assert!(http_text(&h).starts_with("HTTP/1.1 100 Continue\r\n\r\n"));
    h.push(b"ok").unwrap();
    assert_eq!(*seen.lock().unwrap(), [2]);
    // A body cut off by the end of input never reaches the byte callback.
    h.push(b"POST /u HTTP/1.1\r\nHost: a\r\nContent-Length: 10\r\n\r\nabc")
        .unwrap();
    let _ = h.end();
    assert_eq!(*seen.lock().unwrap(), [2]);
    assert!(http_text(&h).contains("HTTP/1.1 400 Bad Request\r\n"));
    assert!(h.closed());
}

#[test]
fn http1_router_accepts_valid_empty_post_bodies() {
    let seen = Arc::new(AtomicUsize::new(0));
    let keep = seen.clone();
    let router = fictionet_test_support::handler(
        move |_: &mut fictionet::stdlib::web::httpd::Exchange<'_>,
              request: http::Request<bytes::Bytes>| {
            assert!(request.body().is_empty());
            keep.fetch_add(1, Ordering::Relaxed);
            http::Response::new(Bytes::new())
        },
    );
    for body in [
        "\r\n",
        "Content-Length: 0\r\n\r\n",
        "Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
    ] {
        let mut h = Harness::new(fictionet::Seed::from_u64(0), Http1::new(router.clone()), ());
        h.push(format!("POST /u HTTP/1.1\r\nHost: a\r\n{body}").as_bytes())
            .unwrap();
        assert!(http_text(&h).starts_with("HTTP/1.1 200 OK\r\n"));
    }
    assert_eq!(seen.load(Ordering::Relaxed), 3);
}

#[test]
fn http1_custom_handler_receives_partial_body_then_error() {
    use http_body::Body as _;

    struct Partial(Arc<AtomicUsize>);
    impl httpd::Handler for Partial {
        fn call(
            &self,
            request: http::Request<httpd::Body>,
            _: &mut httpd::Exchange<'_>,
        ) -> httpd::Reply {
            self.0.fetch_add(1, Ordering::Relaxed);
            let mut body = request.into_body();
            assert!(body.bytes().is_none());
            let mut cx = Context::from_waker(std::task::Waker::noop());
            let Poll::Ready(Some(Ok(frame))) = Pin::new(&mut body).poll_frame(&mut cx) else {
                panic!("missing partial body");
            };
            assert_eq!(frame.into_data().unwrap(), b"abc"[..]);
            let Poll::Ready(Some(Err(error))) = Pin::new(&mut body).poll_frame(&mut cx) else {
                panic!("missing body error");
            };
            assert_eq!(error.to_string(), "the request body was cut off");
            assert!(matches!(
                Pin::new(&mut body).poll_frame(&mut cx),
                Poll::Ready(None)
            ));
            httpd::Reply::Now(http::Response::new(httpd::Body::empty()))
        }
    }
    let seen = Arc::new(AtomicUsize::new(0));
    let mut h = Harness::new(
        fictionet::Seed::from_u64(0),
        Http1::new(Partial(seen.clone())),
        (),
    );
    h.push(b"POST /u HTTP/1.1\r\nHost: a\r\nContent-Length: 10\r\n\r\nabc")
        .unwrap();
    let _ = h.end();
    assert_eq!(seen.load(Ordering::Relaxed), 1);
    assert!(http_text(&h).starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(h.closed());
}

#[test]
fn http1_closes_after_its_header_timeout() {
    let mut h = Harness::new(
        fictionet::Seed::from_u64(0),
        Http1::new(fictionet_test_support::handler(|_, _| {
            http::Response::builder()
                .status(404)
                .body(bytes::Bytes::new())
                .unwrap()
        })),
        (),
    );
    h.open().unwrap();
    assert_eq!(h.advance(Duration::from_secs(29)).unwrap(), b"");
    assert!(!h.closed());
    h.advance(Duration::from_secs(2)).unwrap();
    assert!(h.closed());
}

#[test]
fn world_host_names_match_http_sites_and_tls_names() {
    use fictionet::stdlib::world::net::Sni;

    for (name, expected) in [
        ("a.test", "a.test"),
        ("A.TeSt.", "a.test"),
        ("A.TEST...", "a.test"),
        ("", ""),
        ("...", ""),
        (".A..TEST.", ".a..test"),
        (" A.TEST ", " a.test "),
        ("É.TEST.", "É.test"),
    ] {
        assert_eq!(httpd::normalize(name), expected);
        assert_eq!(Sni::from(name), Sni::Name(expected.to_owned()));
        let vhosts = httpd::VirtualHosts::new();
        vhosts.insert(
            name,
            httpd::VHost::new(fictionet_test_support::handler(|_, _| {
                http::Response::builder()
                    .status(404)
                    .body(bytes::Bytes::new())
                    .unwrap()
            })),
        );
        assert!(vhosts.get(expected).is_some(), "{name:?}");
    }

    for authority in ["A.TeSt", "A.TEST.:80", "A.Test...:443"] {
        let request = http::Request::builder()
            .header("host", authority)
            .body(())
            .unwrap();
        assert_eq!(httpd::request_host(&request).as_deref(), Some("a.test"));
        let request = http::Request::builder()
            .uri(format!("https://{authority}/"))
            .header("host", "other.test")
            .body(())
            .unwrap();
        assert_eq!(httpd::request_host(&request).as_deref(), Some("a.test"));
    }
}

#[test]
fn virtual_hosts_pick_a_site_by_host() {
    let vhosts = httpd::VirtualHosts::new();
    vhosts.insert(
        "a.test",
        httpd::VHost::new(fictionet_test_support::handler(
            |_: &mut fictionet::stdlib::web::httpd::Exchange<'_>,
             r: http::Request<bytes::Bytes>| {
                let t = r.extensions().get::<httpd::Target>().cloned().unwrap();
                http::Response::new(Bytes::from(format!("a {} {}", t.host, t.port)))
            },
        )),
    );
    let mut secure = httpd::VHost::new(fictionet_test_support::handler(
        |_: &mut fictionet::stdlib::web::httpd::Exchange<'_>, _: http::Request<bytes::Bytes>| {
            http::Response::new(Bytes::from("b"))
        },
    ));
    secure.https = true;
    vhosts.insert("b.test", secure);
    let conn = ConnInfo::new(
        1,
        "203.0.113.1:80".parse().unwrap(),
        "10.0.0.2:5000".parse().unwrap(),
    );

    let mut h = Harness::new(fictionet::Seed::from_u64(0), Http1::new(vhosts), ()).with_conn(conn);
    h.push(b"GET / HTTP/1.1\r\nHost: A.Test.\r\n\r\n").unwrap();
    h.push(b"GET /x?y HTTP/1.1\r\nHost: b.test\r\n\r\n")
        .unwrap();
    h.push(b"GET / HTTP/1.1\r\nHost: c.test\r\n\r\n").unwrap();
    h.push(b"GET / HTTP/1.0\r\n\r\n").unwrap();
    let text = http_text(&h);
    assert!(text.contains("\r\n\r\na a.test 80"), "{text}");
    assert!(
        text.contains("HTTP/1.1 301 Moved Permanently\r\n")
            && text.contains("Location: https://b.test/x?y\r\n")
    );
    assert!(text.contains("HTTP/1.1 421 Misdirected Request\r\n"));
    assert!(text.contains("HTTP/1.0 400 Bad Request\r\n"));
}

/// What the `serve_http1` fuzz target checks, over inputs made from
/// pieces of requests and random bytes: no panic, and the same replies
/// wherever the input is cut.
#[test]
fn http1_survives_mixed_and_random_input() {
    let pieces: [&[u8]; 12] = [
        b"GET / HTTP/1.1\r\nHost: a\r\n\r\n",
        b"POST /echo HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\n\r\nabc",
        b"POST /echo HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nxyz\r\n0\r\n\r\n",
        b"HEAD /files/x HTTP/1.1\r\nHost: a\r\n\r\n",
        b"GET / HTTP/1.0\r\n\r\n",
        b"\r\n",
        b"CONNECT a:443 HTTP/1.1\r\nHost: a:443\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: a\r\nExpect: 100-continue\r\nContent-Length: 1\r\n\r\nz",
        b"GET /\x00 HTTP/1.1\r\n\r\n",
        b"Content-Length: 99999999999999999999\r\n",
        b"POST /echo HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n",
        b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
    ];
    let router = || {
        let route_0 =
            |_: &mut fictionet::stdlib::web::httpd::Exchange<'_>,
             _: http::Request<bytes::Bytes>| http::Response::new(Bytes::from("home\n"));
        let route_1 = |_: &mut fictionet::stdlib::web::httpd::Exchange<'_>,
                       r: http::Request<Bytes>| {
            http::Response::new(r.into_body())
        };
        let route_2 = |_: &mut fictionet::stdlib::web::httpd::Exchange<'_>,
                       r: http::Request<bytes::Bytes>| {
            http::Response::new(Bytes::from(r.uri().path().to_owned()))
        };
        fictionet_test_support::handler(move |ex, request| {
            if request.uri().path() == "/"
                && (request.method() == http::Method::GET || request.method() == http::Method::HEAD)
            {
                return route_0(ex, request);
            }
            if request.uri().path() == "/echo" && (request.method() == http::Method::POST) {
                return route_1(ex, request);
            }
            if (request.uri().path() == "/files" || request.uri().path().starts_with("/files/"))
                && (request.method() == http::Method::GET || request.method() == http::Method::HEAD)
            {
                return route_2(ex, request);
            }
            if request.uri().path() == "/"
                || request.uri().path() == "/echo"
                || (request.uri().path() == "/files" || request.uri().path().starts_with("/files/"))
            {
                return http::Response::builder()
                    .status(405)
                    .body(bytes::Bytes::new())
                    .unwrap();
            }
            http::Response::builder()
                .status(404)
                .body(bytes::Bytes::new())
                .unwrap()
        })
    };
    let run = |chunks: &[&[u8]]| {
        let mut h = Harness::new(fictionet::Seed::from_u64(0), Http1::new(router()), ());
        for c in chunks {
            if h.push(c).is_err() {
                break;
            }
        }
        let _ = h.end();
        (h.output().to_vec(), h.closed())
    };
    let mut rng = fictionet::stdlib::codec::Lcg::new(42);
    for _ in 0..400 {
        let mut input = Vec::new();
        for _ in 0..rng.below(5) + 1 {
            if rng.coin() {
                input.extend_from_slice(pieces[rng.below(pieces.len() as u64) as usize]);
            } else {
                input.extend(rng.bytes(40));
            }
        }
        let whole = run(&[&input]);
        let at = rng.index(input.len() + 1);
        assert_eq!(
            run(&[&input[..at], &input[at..]]),
            whole,
            "cut at {at} of {:?}",
            String::from_utf8_lossy(&input)
        );
        assert!(whole.1);
    }
}

/// A body that trickles in is cut off by its own timer. Before, the head
/// timer was cancelled on the head and nothing replaced it.
#[test]
fn http1_closes_a_request_whose_body_never_finishes() {
    let mut h = Harness::new(
        fictionet::Seed::from_u64(0),
        Http1::new(fictionet_test_support::handler(|_, _| {
            http::Response::builder()
                .status(404)
                .body(bytes::Bytes::new())
                .unwrap()
        })),
        (),
    );
    h.push(b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 10\r\n\r\nabc")
        .unwrap();
    assert_eq!(h.advance(Duration::from_secs(29)).unwrap(), b"");
    assert!(!h.closed());
    h.advance(Duration::from_secs(2)).unwrap();
    assert!(h.closed());
}

// ---------------------------------------------------------------------------

/// An oversized body is refused before dispatch.
#[test]
fn http1_oversized_body_returns_413_without_calling_handler() {
    let seen = Arc::new(Mutex::new(None));
    let s = seen.clone();
    let router = fictionet_test_support::handler(
        move |_: &mut fictionet::stdlib::web::httpd::Exchange<'_>, r: http::Request<Bytes>| {
            *s.lock().unwrap() = Some(r.body().len());
            http::Response::new(Bytes::from("ok\n"))
        },
    );
    let limits = httpd::Limits {
        body: 10,
        ..Default::default()
    };
    let mut h = Harness::new(
        fictionet::Seed::from_u64(0),
        Http1::with(Arc::new(router), limits),
        (),
    );
    let _ = h.push(
        b"POST /up HTTP/1.1\r\nHost: a.test\r\nContent-Length: 20\r\n\r\n01234567890123456789",
    );
    let out = http_text(&h);
    assert!(out.starts_with("HTTP/1.1 413"), "expected 413, got {out:?}");
    assert_eq!(*seen.lock().unwrap(), None);
}

/// Header timeouts close the connection and record their cause.
#[test]
fn http1_header_timeout_closes_the_connection() {
    let mut h = Harness::new(
        fictionet::Seed::from_u64(0),
        Http1::new(fictionet_test_support::handler(|_, _| {
            http::Response::builder()
                .status(404)
                .body(bytes::Bytes::new())
                .unwrap()
        })),
        (),
    );
    h.open().unwrap();
    let _ = h.push(b"GET / HTTP/1.1\r\n");
    let _ = h.advance(Duration::from_secs(31));
    assert!(h.closed());
}

#[test]
fn http1_idle_keep_alive_timeout_closes_without_an_error() {
    let router = fictionet_test_support::handler(
        |_: &mut fictionet::stdlib::web::httpd::Exchange<'_>, _: http::Request<bytes::Bytes>| {
            http::Response::new(Bytes::from("ok"))
        },
    );

    let mut h = Harness::new(fictionet::Seed::from_u64(0), Http1::new(router), ());
    let reply = h.push(b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n").unwrap();
    assert!(reply.starts_with(b"HTTP/1.1 200"));
    assert!(!h.closed());
    h.advance(Duration::from_secs(31)).unwrap();
    assert!(h.closed());
}

#[test]
fn http1_pipelined_partial_head_timeout_closes_the_connection() {
    let router = fictionet_test_support::handler(
        |_: &mut fictionet::stdlib::web::httpd::Exchange<'_>, _: http::Request<bytes::Bytes>| {
            http::Response::new(Bytes::from("ok"))
        },
    );

    let mut h = Harness::new(fictionet::Seed::from_u64(0), Http1::new(router), ());
    let reply = h
        .push(b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\nGET / HTTP/1.1\r\n")
        .unwrap();
    assert!(reply.starts_with(b"HTTP/1.1 200"));
    assert!(!h.closed());
    h.advance(Duration::from_secs(31)).unwrap();
    assert!(h.closed());
}

/// A known path takes precedence over the fallback.

#[test]
fn http1_body_timeout_closes_the_connection() {
    let mut h = Harness::new(
        fictionet::Seed::from_u64(0),
        Http1::new(fictionet_test_support::handler(|_, _| {
            http::Response::builder()
                .status(404)
                .body(bytes::Bytes::new())
                .unwrap()
        })),
        (),
    );
    h.open().unwrap();
    h.push(b"POST / HTTP/1.1\r\nHost: a.test\r\nContent-Length: 20\r\n\r\na")
        .unwrap();
    h.advance(Duration::from_secs(61)).unwrap();
    assert!(h.closed());
}
