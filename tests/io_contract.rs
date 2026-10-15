mod common;
#[path = "common/done.rs"]
mod done;
#[path = "common/io.rs"]
mod io;
#[path = "common/world.rs"]
mod world;

use std::io::{ErrorKind, Read};
use std::net::{TcpListener, TcpStream};
use std::task::{Context, Poll};
use std::time::Duration;

use fictionet::stdlib::{ConnError, Connection};
use fictionet::{Cx, RaceError};
use world::world;

struct Script(&'static [u8], Poll<Result<usize, ConnError>>);
impl Connection for Script {
    fn poll_read(
        &mut self,
        _: &Cx,
        _: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, ConnError>> {
        if self.0.is_empty() {
            self.1
        } else {
            Poll::Ready(Ok(self.0.read(buf).unwrap()))
        }
    }
    fn poll_write(
        &mut self,
        _: &Cx,
        _: &mut Context<'_>,
        _: &[u8],
    ) -> Poll<Result<usize, ConnError>> {
        panic!("unexpected write")
    }
    fn poll_shutdown(&mut self, _: &Cx, _: &mut Context<'_>) -> Poll<Result<(), ConnError>> {
        panic!("unexpected shutdown")
    }
}
struct Reset;
impl Read for Reset {
    fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
        Err(ErrorKind::ConnectionReset.into())
    }
}

#[test]
fn read_prefix_then_error() {
    world(Duration::from_secs(5), |fcx| async move {
        for error in [ConnError::Reset, ConnError::Broken] {
            let mut conn = Script(b"prefix", Poll::Ready(Err(error)));
            let got = io::read_to_end(&fcx, &mut conn, fcx.now() + Duration::from_secs(1)).await;
            assert_eq!(got, Ok(Err(error)));
        }
        let mut conn = Script(b"prefix", Poll::Ready(Ok(0)));
        assert_eq!(
            io::read_to_end(&fcx, &mut conn, fcx.now()).await,
            Ok(Ok(b"prefix".to_vec()))
        );
        Ok(())
    });
}

#[test]
fn deadline_is_not_eof() {
    world(Duration::from_secs(5), |fcx| async move {
        for prefix in [b"".as_slice(), b"prefix"] {
            let mut conn = Script(prefix, Poll::Pending);
            let deadline = fcx.now() + Duration::from_secs(1);
            assert_eq!(
                io::read_to_end(&fcx, &mut conn, deadline).await,
                Err(RaceError::Deadline)
            );
            assert_eq!(fcx.now(), deadline);
        }
        Ok(())
    });
}

#[test]
fn cancelled_wait() {
    world(Duration::from_secs(5), |fcx| async move {
        fcx.region(|fcx| async move {
            fcx.cancel();
            let mut conn = Script(b"prefix", Poll::Pending);
            let got = io::read_to_end(&fcx, &mut conn, fcx.now() + Duration::from_secs(1)).await;
            assert_eq!(got, Err(RaceError::Cancelled));
            Ok(())
        })
        .await?;
        Ok(())
    });
}

#[test]
#[should_panic(expected = "read until EOF")]
fn sync_read_prefix_then_error() {
    io::read_all(&mut b"prefix".as_slice().chain(Reset));
}

#[test]
#[should_panic(expected = "read until EOF")]
fn timeout_is_not_close() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (_peer, _) = listener.accept().unwrap();
    client
        .set_read_timeout(Some(Duration::from_millis(20)))
        .unwrap();
    io::read_all(&mut client);
}

#[test]
fn delimiter_does_not_consume_body() {
    let mut bytes = b"head\r\n\r\nbody".as_slice();
    assert_eq!(io::read_until(&mut bytes, b"\r\n\r\n"), b"head\r\n\r\n");
    assert_eq!(io::read_all(&mut bytes), b"body");
    world(Duration::from_secs(5), |fcx| async move {
        let mut conn = Script(b"head\r\n\r\nbody", Poll::Ready(Ok(0)));
        assert_eq!(
            io::read_until_async(&fcx, &mut conn, fcx.now(), b"\r\n\r\n")
                .await
                .unwrap(),
            b"head\r\n\r\n"
        );
        assert_eq!(conn.0, b"body");
        Ok(())
    });
}

#[test]
#[should_panic(expected = "read until delimiter")]
fn delimiter_requires_completion() {
    io::read_until(&mut b"HTTP/1.1 200 OK\r\n".as_slice(), b"\r\n\r\n");
}

macro_rules! rejected_response {
    ($name:ident, $bytes:expr) => {
        #[test]
        #[should_panic(expected = "complete HTTP response")]
        fn $name() {
            io::response($bytes, "GET", false);
        }
    };
}
rejected_response!(partial_status, b"HTTP/1.1 20");
rejected_response!(
    short_content_length,
    b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nabc"
);
rejected_response!(
    missing_chunk_terminator,
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n"
);
rejected_response!(
    trailing_bytes,
    b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc!"
);

#[test]
#[should_panic(expected = "requires explicit opt-in")]
fn close_delimited_requires_opt_in() {
    io::response(b"HTTP/1.1 200 OK\r\n\r\nabc", "GET", false);
}

#[test]
fn complete_responses() {
    for bytes in [
        b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc".as_slice(),
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
    ] {
        let response = io::response(bytes, "GET", false);
        assert_eq!(response.head.status, 200);
        assert_eq!(response.body, b"abc");
    }
    assert_eq!(
        io::response(b"HTTP/1.1 200 OK\r\n\r\nabc", "GET", true).body,
        b"abc"
    );
    assert!(
        io::response(
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n",
            "HEAD",
            false
        )
        .body
        .is_empty()
    );
}
