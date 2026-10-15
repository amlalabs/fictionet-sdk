#[path = "common/benchmark.rs"]
mod benchmark;

use benchmark::{Observer, ObserverStatus};
use fictionet::relay::observer::Value;
use std::io::{self, ErrorKind, Read, Write};
use std::net::TcpListener;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

fn fetch(response: &'static [u8], expected_status: u16) -> Vec<u8> {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            socket.read_exact(&mut byte).unwrap();
            request.extend_from_slice(&byte);
        }
        assert_eq!(
            request,
            b"GET http://plain.test/ HTTP/1.1\r\nHost: plain.test\r\nProxy-Authorization: Basic test\r\nConnection: close\r\n\r\n"
        );
        socket.write_all(response).unwrap();
    });
    let result = std::panic::catch_unwind(|| {
        benchmark::fetch(addr, "plain.test", "Basic test", expected_status)
    });
    server.join().unwrap();
    match result {
        Ok(body) => body,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

macro_rules! rejected_response {
    ($name:ident, $response:expr, $reason:literal) => {
        #[test]
        #[should_panic(expected = $reason)]
        fn $name() {
            fetch($response, 200);
        }
    };
}

rejected_response!(
    benchmark_rejects_header_only,
    b"HTTP/1.1 200 OK\r\ncontent-length: 11\r\n\r\n",
    "HTTP body length"
);
rejected_response!(
    benchmark_rejects_partial_body,
    b"HTTP/1.1 200 OK\r\ncontent-length: 11\r\n\r\nplain",
    "HTTP body length"
);
rejected_response!(
    benchmark_rejects_extra_body,
    b"HTTP/1.1 200 OK\r\ncontent-length: 11\r\n\r\nplain site\n!",
    "HTTP body length"
);
rejected_response!(
    benchmark_rejects_incomplete_head,
    b"HTTP/1.1 200 OK\r\ncontent-length: 11\r\n",
    "complete HTTP response head"
);
rejected_response!(
    benchmark_rejects_missing_length,
    b"HTTP/1.1 200 OK\r\n\r\nplain site\n",
    "missing Content-Length"
);
rejected_response!(
    benchmark_rejects_invalid_length,
    b"HTTP/1.1 200 OK\r\nContent-Length: +11\r\n\r\nplain site\n",
    "invalid Content-Length"
);
rejected_response!(
    benchmark_rejects_duplicate_length,
    b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\ncontent-length: 11\r\n\r\nplain site\n",
    "duplicate Content-Length"
);
rejected_response!(
    benchmark_rejects_conflicting_length,
    b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\ncontent-length: 5\r\n\r\nplain site\n",
    "duplicate Content-Length"
);
rejected_response!(
    benchmark_rejects_transfer_encoding,
    b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\ntRaNsFeR-EnCoDiNg: chunked\r\n\r\nplain site\n",
    "requires Content-Length framing"
);
rejected_response!(
    benchmark_rejects_wrong_status,
    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 11\r\n\r\nplain site\n",
    "HTTP status"
);
rejected_response!(
    benchmark_rejects_status_prefix,
    b"HTTP/1.1 2000 OK\r\nContent-Length: 11\r\n\r\nplain site\n",
    "HTTP status"
);
rejected_response!(
    benchmark_rejects_invalid_header,
    b"HTTP/1.1 200 OK\r\nContent-Length : 11\r\n\r\nplain site\n",
    "HTTP header name"
);

#[test]
fn benchmark_accepts_complete_body() {
    assert_eq!(
        fetch(
            b"HTTP/1.1 200 OK\r\ncontent-length: 11\r\n\r\nplain site\n",
            200
        ),
        b"plain site\n"
    );
}

#[test]
fn benchmark_accepts_complete_502() {
    assert_eq!(
        fetch(
            b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 26\r\n\r\nno such name in the world\n",
            502
        ),
        b"no such name in the world\n"
    );
}

#[test]
#[should_panic(expected = "HTTP body length")]
fn benchmark_rejects_partial_502() {
    fetch(
        b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 26\r\n\r\nno such name",
        502,
    );
}

struct Script<F> {
    requests: Vec<String>,
    read: F,
}

impl<F: FnMut() -> io::Result<Option<Value>>> Observer for Script<F> {
    fn request(&mut self, json: &str) -> io::Result<u32> {
        self.requests.push(json.to_owned());
        // Nonconsecutive ids ensure readiness uses the returned ids.
        Ok(self.requests.len() as u32 * 10)
    }

    fn next_value(&mut self) -> io::Result<Option<Value>> {
        (self.read)()
    }
}

fn value(id: u32, bytes: &str) -> Value {
    Value {
        id,
        bytes: bytes.as_bytes().to_vec(),
        binary: false,
        end: false,
    }
}

fn acknowledged() -> Vec<Value> {
    vec![
        value(
            10,
            r#"{"nodes":[{"id":"s1","kind":"sandbox"},{"id":"s2","kind":"sandbox"}],"edges":[{"id":"e1","a":"t1","b":"s1"},{"id":"e2","a":"t2","b":"s2"}]}"#,
        ),
        value(20, r#"{"event":"snapshot","data":{}}"#),
        value(30, r#"{"event":"link","data":{}}"#),
        value(40, r#"{"event":"link","data":{}}"#),
    ]
}

fn watch(
    read: impl FnMut() -> io::Result<Option<Value>>,
    stop: &AtomicBool,
    status: &Mutex<ObserverStatus>,
    measuring: &AtomicBool,
) -> io::Result<u64> {
    let mut script = Script {
        requests: Vec::new(),
        read,
    };
    let result = benchmark::watch_world(&mut script, true, 2, stop, status, measuring);
    assert_eq!(
        script.requests,
        [
            r#"{"op":"graph"}"#,
            r#"{"op":"watch"}"#,
            r#"{"op":"packets","link":"e1","after":0}"#,
            r#"{"op":"packets","link":"e2","after":0}"#,
        ]
    );
    result
}

#[test]
fn observer_dies_after_ready() {
    let status = Mutex::new(ObserverStatus::Waiting);
    let mut values = acknowledged().into_iter();
    let error = watch(
        || {
            let next = values.next();
            if next.is_none() {
                assert_eq!(*status.lock().unwrap(), ObserverStatus::Ready);
            }
            Ok(next)
        },
        &AtomicBool::new(false),
        &status,
        &AtomicBool::new(true),
    )
    .expect_err("EOF must not report observed rows");
    assert_eq!(error.kind(), ErrorKind::UnexpectedEof);
    assert!(status.lock().unwrap().ready().is_err());
}

#[test]
fn observer_fails_mid_measurement() {
    for id in [20, 30] {
        let mut end = value(id, r#"{"event":"packet","data":{}}"#);
        end.end = true;
        for failure in [
            value(id, r#" { "error" : "observer failed" } "#),
            end,
            value(id, r#"{"data":{},"event":"end"}"#),
            value(id, r#"{"data":{},"event":"ended"}"#),
            value(id, r#"{"event":"packet","data":"#),
        ] {
            let status = Mutex::new(ObserverStatus::Waiting);
            let raw = String::from_utf8(failure.bytes.clone()).unwrap();
            let mut values = acknowledged();
            values.push(value(30, r#"{"event":"packet","data":{}}"#));
            values.push(failure);
            let mut values = values.into_iter();
            let error = watch(
                || Ok(values.next()),
                &AtomicBool::new(false),
                &status,
                &AtomicBool::new(true),
            )
            .expect_err("a failed observer must not report its collected rows");
            assert_eq!(error.kind(), ErrorKind::InvalidData);
            assert!(error.to_string().contains(&raw), "{error}");
            assert!(status.lock().unwrap().ready().is_err());
        }
    }
}

#[test]
fn watch_error_reply_fails_readiness() {
    for id in [20, 30, 40] {
        let mut values = acknowledged();
        let at = values.iter().position(|v| v.id == id).unwrap();
        values[at] = value(id, r#"{"error":"subscription refused"}"#);
        let mut values = values.into_iter();
        let status = Mutex::new(ObserverStatus::Waiting);
        let error = watch(
            || Ok(Some(values.next().expect("error reply must end readiness"))),
            &AtomicBool::new(false),
            &status,
            &AtomicBool::new(false),
        )
        .unwrap_err();
        assert!(error.to_string().contains("subscription refused"));
        assert!(status.lock().unwrap().ready().is_err());
    }
}

#[test]
fn readiness_needs_each_link_id() {
    let mut values = acknowledged();
    values[3].id = 30;
    let mut values = values.into_iter();
    let status = Mutex::new(ObserverStatus::Waiting);
    let error = watch(
        || {
            let next = values.next();
            if next.is_none() {
                assert_eq!(*status.lock().unwrap(), ObserverStatus::Waiting);
                assert!(!status.lock().unwrap().ready().unwrap());
            }
            Ok(next)
        },
        &AtomicBool::new(false),
        &status,
        &AtomicBool::new(false),
    )
    .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::UnexpectedEof);
}

#[test]
fn observer_stop_then_eof_reports_measured_rows() {
    let stop = AtomicBool::new(false);
    let measuring = AtomicBool::new(false);
    let status = Mutex::new(ObserverStatus::Waiting);
    let mut values = acknowledged().into_iter();
    let mut packets = 0;
    let rows = watch(
        || {
            if let Some(v) = values.next() {
                return Ok(Some(v));
            }
            assert_eq!(*status.lock().unwrap(), ObserverStatus::Ready);
            packets += 1;
            match packets {
                1 => Ok(Some(value(30, r#"{"event":"packet","data":{}}"#))),
                2 => {
                    measuring.store(true, Ordering::Release);
                    Ok(Some(value(40, r#" { "data": {}, "event": "packet" } "#)))
                }
                3 => {
                    measuring.store(false, Ordering::Release);
                    stop.store(true, Ordering::Release);
                    Ok(None)
                }
                _ => panic!("read after stop"),
            }
        },
        &stop,
        &status,
        &measuring,
    )
    .unwrap();
    assert_eq!(rows, 1);
}
