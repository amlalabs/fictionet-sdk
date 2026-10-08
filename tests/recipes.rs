//! The recipes' worlds, run against a client inside the test.

mod common;

use common::within;

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
    pub fn bank(fcx: &Cx, side: impl Interface) {
        web_machine(fcx, side, "203.0.113.10".parse().unwrap(), "the real bank\n").unwrap();
    }
}

/// Sends `request` to the bank and reads the whole answer.
async fn ask(fcx: &Cx, client: &tcp::Endpoint, request: &[u8]) -> fictionet::Result<Vec<u8>> {
    let mut conn = client.connect(fcx, "203.0.113.10:80".parse()?).await?;
    conn.write_all(fcx, request).await?;
    let mut response = Vec::new();
    let mut bytes = [0; 1024];
    loop {
        let n = conn.read(fcx, &mut bytes).await?;
        if n == 0 {
            return Ok(response);
        }
        response.extend_from_slice(&bytes[..n]);
    }
}

#[test]
fn route_change_answers_get_with_the_body_and_head_without() {
    within(Duration::from_secs(10), || {
        block_on(run(|fcx| async move {
            let (client, server) = pair();
            route_change::bank(&fcx, server);
            let client = tcp::endpoint(&fcx, client, "10.0.0.2".parse()?);
            let get = ask(&fcx, &client, b"GET / HTTP/1.1\r\nHost: bank\r\nConnection: close\r\n\r\n").await?;
            let get = std::str::from_utf8(&get).unwrap();
            let (headers, body) = get.split_once("\r\n\r\n").unwrap();
            assert!(headers.starts_with("HTTP/1.1 200 OK\r\n"));
            assert!(headers.lines().any(|line| line == "content-length: 14"));
            assert_eq!(body, "the real bank\n");
            let head = ask(&fcx, &client, b"HEAD / HTTP/1.1\r\nHost: bank\r\nConnection: close\r\n\r\n").await?;
            let head = std::str::from_utf8(&head).unwrap();
            let (headers, body) = head.split_once("\r\n\r\n").unwrap();
            assert!(headers.starts_with("HTTP/1.1 200 OK\r\n"));
            assert!(headers.lines().any(|line| line == "content-length: 14"));
            assert!(body.is_empty());
            fcx.cancel();
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
        block_on(run(|fcx| async move {
            let (client, server) = pair();
            route_change::bank(&fcx, server);
            let client = tcp::endpoint(&fcx, client, "10.0.0.2".parse()?);
            let mut conns = Vec::new();
            for _ in 0..route_change::MAX + 16 {
                let mut conn = client.connect(&fcx, "203.0.113.10:80".parse()?).await?;
                conn.write_all(&fcx, b"GET / HTTP/1.1\r\nHost: bank").await?;
                conns.push(conn);
            }
            // The connections past the limit are reset without an answer.
            let started = fcx.now();
            for conn in &mut conns[route_change::MAX..] {
                let mut byte = [0];
                assert_eq!(conn.read(&fcx, &mut byte).await, Err(ConnError::Reset));
            }
            // The rest close without an answer when their idle time is up.
            for conn in &mut conns[..route_change::MAX] {
                let mut byte = [0];
                assert_eq!(conn.read(&fcx, &mut byte).await, Ok(0));
            }
            let waited = fcx.now().since_start() - started.since_start();
            assert!(waited >= route_change::LIMIT - Duration::from_secs(1), "{waited:?}");
            assert!(waited <= route_change::LIMIT + Duration::from_secs(10), "{waited:?}");
            fcx.cancel();
            Ok(())
        }))
        .unwrap();
    });
}
