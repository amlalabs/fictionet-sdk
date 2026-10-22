//! The quick-start world with bulk transfers and a real upstream for tests.
//!
//! `web_fixture <socket> <ca path> [observation.sock]` serves the world.
//! `--upstream <port>` instead runs a real HTTP server on the host's network
//! for the proxy.

use std::io::{Read, Write};

use fictionet::Result;
use fictionet_test_support::web_fixture::world;

use fictionet_extras::web_world;

fn main() -> Result {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("--upstream") {
        let port = args.get(2).map(|p| p.parse()).transpose()?.unwrap_or(80);
        return upstream(port);
    }
    web_world::run(&args, world)
}

fn upstream(port: u16) -> Result {
    let listener = std::net::TcpListener::bind(("0.0.0.0", port))?;
    println!("upstream listening on port {port}");
    for conn in listener.incoming() {
        let Ok(mut conn) = conn else { continue };
        std::thread::spawn(move || {
            let mut request = Vec::new();
            let mut buf = [0u8; 4096];
            while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                match conn.read(&mut buf) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => request.extend_from_slice(&buf[..n]),
                }
            }
            let first = String::from_utf8_lossy(&request)
                .lines()
                .next()
                .unwrap_or("")
                .to_owned();
            println!("upstream got: {first}");
            let body = format!("hello from the real upstream: {first}\n");
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = conn.write_all(response.as_bytes());
        });
    }
    Ok(())
}

#[test]
fn the_client_report_is_the_recorded_one() {
    assert_eq!(
        fictionet_test_support::web_fixture::recorded_report(),
        include_str!("golden.txt")
    );
}
