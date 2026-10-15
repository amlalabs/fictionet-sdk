#[path = "common/benchmark.rs"]
mod benchmark;

use std::io::{Read, Write};
use std::net::TcpListener;
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
