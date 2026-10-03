//! The recipes' worlds, run against a client inside the test.

use std::time::Duration;

use fictionet::prelude::*;
use fictionet::stdlib::{ConnError, tcp};
use fictionet::{Cx, block_on, pair, run};

#[allow(dead_code)]
mod route_change {
    include!("../examples/route_change.rs");

    pub const MAX: usize = MAX_CONNECTIONS;
    pub const LIMIT: Duration = TIME_LIMIT;

    /// The bank's machine at 203.0.113.10, on `side`.
    pub fn bank(cx: &Cx, side: impl Interface) {
        web_machine(cx, side, "203.0.113.10".parse().unwrap(), "the real bank\n").unwrap();
    }
}

/// Runs `f` on its own thread and fails the test if it takes longer than
/// `limit`, instead of hanging.
fn within<T: Send + 'static>(limit: Duration, f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(limit).expect("timed out")
}

/// Sends `request` to the bank and reads the whole answer.
async fn ask(cx: &Cx, client: &tcp::Endpoint, request: &[u8]) -> fictionet::Result<Vec<u8>> {
    let mut conn = client.connect(cx, "203.0.113.10:80".parse()?).await?;
    conn.write_all(cx, request).await?;
    let mut response = Vec::new();
    let mut bytes = [0; 1024];
    loop {
        let n = conn.read(cx, &mut bytes).await?;
        if n == 0 {
            return Ok(response);
        }
        response.extend_from_slice(&bytes[..n]);
    }
}

#[test]
fn route_change_answers_get_with_the_body_and_head_without() {
    within(Duration::from_secs(10), || {
        block_on(run(|cx| async move {
            let (client, server) = pair();
            route_change::bank(&cx, server);
            let client = tcp::endpoint(&cx, client, "10.0.0.2".parse()?);
            let get = ask(&cx, &client, b"GET / HTTP/1.1\r\nHost: bank\r\n\r\n").await?;
            assert!(get.ends_with(b"content-length: 14\r\nconnection: close\r\n\r\nthe real bank\n"));
            let head = ask(&cx, &client, b"HEAD / HTTP/1.1\r\nHost: bank\r\n\r\n").await?;
            assert!(head.ends_with(b"content-length: 14\r\nconnection: close\r\n\r\n"), "{head:?}");
            cx.cancel();
            Ok(())
        }))
        .unwrap();
    });
}

/// A client that opens many connections and never finishes a request
/// holds at most `MAX_CONNECTIONS` of them open, and each for at most
/// `TIME_LIMIT`. The machine resets the others, so their sockets do not
/// linger.
#[test]
fn route_change_limits_unfinished_requests() {
    within(Duration::from_secs(30), || {
        block_on(run(|cx| async move {
            let (client, server) = pair();
            route_change::bank(&cx, server);
            let client = tcp::endpoint(&cx, client, "10.0.0.2".parse()?);
            let mut conns = Vec::new();
            for _ in 0..route_change::MAX + 16 {
                let mut conn = client.connect(&cx, "203.0.113.10:80".parse()?).await?;
                conn.write_all(&cx, b"GET / HTTP/1.1\r\nHost: bank").await?;
                conns.push(conn);
            }
            // The connections past the limit are reset without an answer.
            let started = cx.now();
            for conn in &mut conns[route_change::MAX..] {
                let mut byte = [0];
                assert_eq!(conn.read(&cx, &mut byte).await, Err(ConnError::Reset));
            }
            assert!(cx.now().since_start() - started.since_start() < Duration::from_secs(5));
            // The rest are reset when their time is up.
            for conn in &mut conns[..route_change::MAX] {
                let mut byte = [0];
                assert_eq!(conn.read(&cx, &mut byte).await, Err(ConnError::Reset));
            }
            let waited = cx.now().since_start() - started.since_start();
            assert!(waited >= route_change::LIMIT - Duration::from_secs(1), "{waited:?}");
            cx.cancel();
            Ok(())
        }))
        .unwrap();
    });
}
