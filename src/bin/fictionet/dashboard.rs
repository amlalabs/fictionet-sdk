//! `fictionet dashboard`: serves the dashboard app, and carries its API
//! calls to the world as an observer.
//!
//! The app is the static files in the repository's `dashboard/` folder,
//! built into this binary. Every `GET /api/<op>?<key>=<value>...` becomes
//! one observe request, `{"op":"<op>","<key>":<value>,...}`, on a new
//! observer session. Streams (`watch`, `packets`) come back as server-sent
//! events, binary values as downloads, and the rest as JSON. So the app
//! uses the observe API and nothing else.
//!
//! `packets` and `pcap` also take a list of links, `link=e3,e7`, for an
//! edge of the drawing that stands for several links, such as one into a
//! closed group. `packets` then sends one `packets` request per link on
//! one session, and merges the streams into one, with each packet's
//! `link` added. `pcap` asks for each link's capture and joins them: a
//! pcapng file may hold several sections, and Wireshark reads them all.
//! A link without a capture fails the whole download. The JSON error names
//! every failed link and gives its reason.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use fictionet::relay::observer::Client;
use fictionet::relay::proxy::auth::Token;

use crate::args::take_world;
use crate::config::world_path;

mod api;
mod assets;
mod auth;
mod http;
mod sse;

use api::api;
use auth::Auth;
use http::{host_allowed, parse_request, read_head, same_site};

pub(crate) const USAGE: &str = "\
usage: fictionet dashboard --world unix:<path> --token-file <path> [--listen <address:port>]

Serves the dashboard, a live view of the world on <path>, at
http://127.0.0.1:7878/ (or --listen). It connects to the world socket as an
observer, so the world needs no flag of its own.

The dashboard shows everything the world carries, decrypted TLS included.
The token file is required. Open /#token=<URL-encoded-token> once to sign in.
The page removes the fragment and stores the token for this origin and tab.
API calls, streams and downloads send Authorization: Bearer <token>.
Cookies do not authenticate; the app shell expires the old login cookie.
Log out or close the tab to clear the stored token.
Restart the dashboard to use the bootstrap URL again. Keep the token outside
the sandbox. Use loopback or a trusted TLS tunnel; HTTP carries the token
in plaintext. Every container in a Kubernetes pod shares loopback, so
127.0.0.1 does not keep an agent in that pod away from the dashboard.";

/// Connections served at once. More are closed at once.
const MAX_CONNECTIONS: usize = 64;

pub(crate) fn main(args: &[String]) -> i32 {
    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!("{USAGE}");
        return 0;
    }
    let parsed = take_world(args).and_then(|(world, rest)| {
        let path = world_path(&world)?;
        let mut listen = "127.0.0.1:7878".to_owned();
        let mut token_file = None;
        let mut args = rest.iter();
        while let Some(arg) = args.next() {
            let (flag, value) = match arg.split_once('=') {
                Some(pair) => pair,
                None => (
                    arg.as_str(),
                    args.next()
                        .ok_or_else(|| format!("{arg} needs a value"))?
                        .as_str(),
                ),
            };
            match flag {
                "--listen" => listen = value.to_owned(),
                "--token-file" if token_file.is_none() => token_file = Some(value.to_owned()),
                _ => return Err(format!("unexpected argument: {flag}")),
            }
        }
        let token_file = token_file.ok_or("--token-file is required")?;
        let token = Token::from_file(std::path::Path::new(&token_file))?;
        Ok((path, listen, token))
    });
    let (path, listen, token) = match parsed {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("fictionet dashboard: {msg}");
            return 2;
        }
    };
    // Check the world is there, so a wrong path fails now, not in a browser.
    match Client::connect(&path, "fictionet dashboard") {
        Ok(_) => {}
        Err(msg) => {
            eprintln!("fictionet dashboard: {msg}");
            return 1;
        }
    }
    let listener = match TcpListener::bind(&listen) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("fictionet dashboard: listening on {listen}: {e}");
            return 1;
        }
    };
    let bound = listener
        .local_addr()
        .expect("a bound listener has an address");
    println!("fictionet dashboard: serving the world at {path} on http://{bound}/");
    let path: Arc<str> = path.into();
    let auth = Arc::new(Auth {
        token,
        bootstrap_used: AtomicBool::new(false),
    });
    let connections = Arc::new(AtomicUsize::new(0));
    for conn in listener.incoming() {
        let Ok(conn) = conn else { continue };
        if connections.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
            connections.fetch_sub(1, Ordering::SeqCst);
            continue;
        }
        let (path, connections, auth) = (path.clone(), connections.clone(), auth.clone());
        std::thread::spawn(move || {
            let _ = serve(&path, bound, conn, &auth);
            connections.fetch_sub(1, Ordering::SeqCst);
        });
    }
    0
}

fn respond(
    conn: &mut TcpStream,
    status: &str,
    kind: &str,
    body: &[u8],
    extra: &str,
) -> io::Result<()> {
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {kind}\r\nContent-Length: {}\r\nCache-Control: no-store\r\n\
         X-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\n\
         Content-Security-Policy: default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; frame-ancestors 'none'\r\n\
         {extra}Connection: close\r\n\r\n",
        body.len()
    );
    conn.write_all(head.as_bytes())?;
    conn.write_all(body)?;
    conn.flush()
}

fn serve(world: &str, bound: SocketAddr, mut conn: TcpStream, auth: &Auth) -> io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(10);
    // A browser that stops reading is given up on.
    conn.set_write_timeout(Some(Duration::from_secs(10)))?;
    #[expect(
        clippy::let_underscore_must_use,
        reason = "TCP_NODELAY only lowers latency; reads and writes below report their own errors"
    )]
    let _ = conn.set_nodelay(true);
    let Some(buf) = read_head(deadline, |remaining, chunk| {
        conn.set_read_timeout(Some(remaining))?;
        conn.read(chunk)
    })?
    else {
        return Ok(());
    };
    let text = "text/plain; charset=utf-8";
    let Some(req) = parse_request(&buf) else {
        return Ok(());
    };
    if !host_allowed(req.host.as_deref(), bound) {
        return respond(&mut conn, "403 Forbidden", text, b"bad Host header\n", "");
    }
    if req.method != "GET" {
        return respond(
            &mut conn,
            "405 Method Not Allowed",
            text,
            b"GET only\n",
            "Allow: GET\r\n",
        );
    }
    if !same_site(&req) {
        return respond(
            &mut conn,
            "403 Forbidden",
            text,
            b"cross-site request\n",
            "",
        );
    }
    if let Some((kind, body)) = assets::lookup(req.path.as_str()) {
        // Remove the old port-wide credential when an existing browser upgrades.
        let extra = if matches!(req.path.as_str(), "/" | "/index.html") {
            "Set-Cookie: fictionet_token=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict\r\n"
        } else {
            ""
        };
        return respond(&mut conn, "200 OK", kind, body.as_bytes(), extra);
    }
    if req.path == "/api/bootstrap" {
        return if auth.bootstrap(&req) {
            respond(&mut conn, "204 No Content", text, b"", "")
        } else {
            respond(
                &mut conn,
                "401 Unauthorized",
                text,
                b"invalid or used bootstrap\n",
                "WWW-Authenticate: Bearer\r\n",
            )
        };
    }
    if !auth.allows(&req) {
        return respond(
            &mut conn,
            "401 Unauthorized",
            text,
            b"dashboard token required\n",
            "WWW-Authenticate: Bearer\r\n",
        );
    }
    match req.path.strip_prefix("/api/") {
        Some(op) if !op.is_empty() && op.bytes().all(|b| b.is_ascii_lowercase() || b == b'_') => {
            api(world, conn, op, &req.query)
        }
        _ => respond(&mut conn, "404 Not Found", text, b"not found\n", ""),
    }
}

#[cfg(test)]
mod tests {
    use super::api::{merged_links, observe_request, with_link};
    use super::sse::{add_link, event};
    use super::*;

    #[test]
    fn api_paths_become_observe_requests() {
        let r = parse_request(
            b"GET /api/packet?link=e5&seq=12&q=a%20b HTTP/1.1\r\nHost: localhost:7878\r\n\r\n",
        )
        .unwrap();
        assert_eq!(r.path, "/api/packet");
        assert_eq!(r.host.as_deref(), Some("localhost:7878"));
        assert_eq!(
            observe_request("packet", &r.query),
            r#"{"op":"packet","link":"e5","seq":12,"q":"a b"}"#
        );
    }

    #[test]
    fn merged_calls_name_several_links() {
        let q = |v: &str| {
            vec![
                ("link".to_owned(), v.to_owned()),
                ("after".to_owned(), "0".to_owned()),
            ]
        };
        assert_eq!(
            merged_links("packets", &q("e3,e7,e7")),
            Some(vec!["e3".to_owned(), "e7".to_owned()])
        );
        assert_eq!(merged_links("pcap", &q("e3,e7")).map(|l| l.len()), Some(2));
        assert_eq!(merged_links("packets", &q("e3")), None);
        assert_eq!(merged_links("packet", &q("e3,e7")), None);
        assert_eq!(
            observe_request("packets", &with_link(&q("e3,e7"), "e7")),
            r#"{"op":"packets","link":"e7","after":0}"#
        );
        assert_eq!(add_link(r#"{"seq":1}"#, "e7"), r#"{"link":"e7","seq":1}"#);
        assert_eq!(add_link("{}", "e7"), r#"{"link":"e7"}"#);
        assert_eq!(add_link("{ }", "e7"), r#"{"link":"e7"}"#);
        assert_eq!(add_link("{\n }", "e7"), r#"{"link":"e7"}"#);
        assert_eq!(
            add_link("{\n\"reason\": \"x\" }", "e7"),
            "{\"link\":\"e7\",\n\"reason\": \"x\" }",
        );
    }

    #[test]
    fn stream_values_split_into_events() {
        let inspect = |bytes: &[u8]| {
            event(&fictionet::relay::observer::Value {
                id: 1,
                bytes: bytes.to_vec(),
                binary: false,
                end: false,
            })
            .map(|(name, data)| (name, data.to_owned()))
        };
        for (bytes, data) in [
            (
                br#"{"event":"node","data":{"id":"t1"}}"#.as_slice(),
                r#"{"id":"t1"}"#,
            ),
            (
                b" { \"data\": {\n\"id\": \"t1\" }, \"event\": \"no\\u0064e\" } \n",
                "{\n\"id\": \"t1\" }",
            ),
        ] {
            assert_eq!(inspect(bytes), Some(("node".into(), data.into())));
        }
        let gap = br#"{"event":"packet_gap","data":{"after":1,"next":4,"missed":2}}"#;
        let (name, data) = inspect(gap).unwrap();
        assert_eq!(name, "packet_gap");
        assert_eq!(
            add_link(&data, "e7"),
            r#"{"link":"e7","after":1,"next":4,"missed":2}"#
        );
        for bytes in [
            br#"{"error":"x"}"#.as_slice(),
            br#"{"event":"node","data":}"#,
            br#"{"event":"node","data":{}} trailing"#,
            br#"{"event":"node\ninjected","data":{}}"#,
            br#"{"event":"node\rinjected","data":{}}"#,
        ] {
            assert_eq!(inspect(bytes), None);
        }
    }
}
