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

use std::io::{self, BufWriter, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use fictionet::relay::observer::Client;
use fictionet::relay::proxy::auth::Token;

use crate::observe::{take_world, world_path};

mod assets;
mod auth;
mod http;

use auth::Auth;
use http::{host_allowed, parse_request, read_head, same_site};

pub(crate) const USAGE: &str = "\
usage: fictionet dashboard --world unix:<path> --token-file <path> [--listen <address:port>]

Serves the dashboard, a live view of the world on <path>, at
http://127.0.0.1:7878/ (or --listen). It connects to the world socket as an
observer, so the world needs no flag of its own.

The dashboard shows everything the world carries, decrypted TLS included.
The token file is required. Open /login?token=<URL-encoded-token> once to
set an HttpOnly session cookie, or send Authorization: Bearer <token>.
Restart the dashboard to use the login URL again. Keep the token outside
the sandbox. Use loopback or a trusted TLS tunnel; HTTP carries the token
in plaintext. Every container in a Kubernetes pod shares loopback, so
127.0.0.1 does not keep an agent in that pod away from the dashboard.";

/// Ops whose replies are streams of `{"event":...,"data":...}` values.
const STREAMS: [&str; 2] = ["watch", "packets"];
/// Connections served at once. More are closed at once.
const MAX_CONNECTIONS: usize = 64;
/// Links one merged `packets` or `pcap` call may name.
const MAX_MERGED: usize = 32;

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
        login_used: AtomicBool::new(false),
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

/// The observe request for `GET /api/<op>?...`: query values that are
/// whole numbers are sent as numbers, the rest as strings.
pub(crate) fn observe_request(op: &str, query: &[(String, String)]) -> String {
    let mut out = format!("{{\"op\":{}", quote(op));
    for (k, v) in query {
        let value = if !v.is_empty() && v.len() < 16 && v.bytes().all(|b| b.is_ascii_digit()) {
            v.clone()
        } else {
            quote(v)
        };
        out.push_str(&format!(",{}:{value}", quote(k)));
    }
    out.push('}');
    out
}

fn quote(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
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
    if req.path == "/login" {
        if let Some(cookie) = auth.login(&req) {
            return respond(
                &mut conn,
                "303 See Other",
                text,
                b"",
                &format!(
                    "Location: /\r\nSet-Cookie: fictionet_token={cookie}; Path=/; HttpOnly; SameSite=Strict\r\n"
                ),
            );
        }
        return respond(
            &mut conn,
            "401 Unauthorized",
            text,
            b"invalid or used login URL\n",
            "",
        );
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
    if let Some((kind, body)) = assets::lookup(req.path.as_str()) {
        return respond(&mut conn, "200 OK", kind, body.as_bytes(), "");
    }
    match req.path.strip_prefix("/api/") {
        Some(op) if !op.is_empty() && op.bytes().all(|b| b.is_ascii_lowercase() || b == b'_') => {
            api(world, conn, op, &req.query)
        }
        _ => respond(&mut conn, "404 Not Found", text, b"not found\n", ""),
    }
}

/// Carries one API call to the world and its reply back.
fn api(world: &str, mut conn: TcpStream, op: &str, query: &[(String, String)]) -> io::Result<()> {
    let mut client = match Client::connect(world, "fictionet dashboard") {
        Ok(c) => c,
        Err(msg) => {
            let body = format!("{{\"error\":{}}}", quote(&msg));
            return respond(
                &mut conn,
                "502 Bad Gateway",
                "application/json",
                body.as_bytes(),
                "",
            );
        }
    };
    if let Some(links) = merged_links(op, query) {
        if links.len() > MAX_MERGED {
            return respond(
                &mut conn,
                "400 Bad Request",
                "application/json",
                br#"{"error":"too many links"}"#,
                "",
            );
        }
        return if op == "packets" {
            stream_merged(client, conn, query, &links)
        } else {
            pcap_merged(client, conn, &links)
        };
    }
    let request = observe_request(op, query);
    client.request(&request)?;
    if STREAMS.contains(&op) {
        return stream(client, conn);
    }
    client.set_timeout(Some(Duration::from_secs(30)))?;
    let Some(value) = client.next_value()? else {
        return respond(
            &mut conn,
            "502 Bad Gateway",
            "application/json",
            br#"{"error":"the world closed"}"#,
            "",
        );
    };
    if value.binary {
        let (kind, name) = match op {
            "pcap" => (
                "application/vnd.tcpdump.pcap",
                format!(
                    "fictionet-{}.pcapng",
                    query
                        .iter()
                        .find(|(k, _)| k == "link")
                        .map_or("link", |(_, v)| v)
                ),
            ),
            _ => ("text/plain; charset=utf-8", format!("fictionet-{op}.txt")),
        };
        let name: String = name
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.'))
            .collect();
        let disposition = format!("Content-Disposition: attachment; filename=\"{name}\"\r\n");
        return respond(&mut conn, "200 OK", kind, &value.bytes, &disposition);
    }
    let status = if value.bytes.starts_with(br#"{"error":"#) {
        "404 Not Found"
    } else {
        "200 OK"
    };
    respond(&mut conn, status, "application/json", &value.bytes, "")
}

/// The links of a `packets` or `pcap` call that names more than one.
fn merged_links(op: &str, query: &[(String, String)]) -> Option<Vec<String>> {
    if op != "packets" && op != "pcap" {
        return None;
    }
    let (_, value) = query.iter().find(|(k, _)| k == "link")?;
    if !value.contains(',') {
        return None;
    }
    let mut links: Vec<String> = value
        .split(',')
        .filter(|l| !l.is_empty())
        .map(str::to_owned)
        .collect();
    links.dedup();
    Some(links)
}

/// The query with `link` set to one link.
fn with_link(query: &[(String, String)], link: &str) -> Vec<(String, String)> {
    query
        .iter()
        .map(|(k, v)| {
            (
                k.clone(),
                if k == "link" {
                    link.to_owned()
                } else {
                    v.clone()
                },
            )
        })
        .collect()
}

/// `data` (a JSON object) with `"link":"<link>"` added first.
pub(crate) fn add_link(data: &str, link: &str) -> String {
    match data.strip_prefix('{') {
        Some(rest) if rest.trim_start().starts_with('}') => format!("{{\"link\":{}}}", quote(link)),
        Some(rest) => format!("{{\"link\":{},{rest}", quote(link)),
        None => data.to_owned(),
    }
}

/// Relays the `packets` streams of several links as one stream of
/// server-sent events. Each event's data gets the link it is from. A link
/// whose stream ends sends `link_end`; the stream ends when all have.
fn stream_merged(
    mut client: Client,
    conn: TcpStream,
    query: &[(String, String)],
    links: &[String],
) -> io::Result<()> {
    let mut open = std::collections::HashMap::new();
    for link in links {
        let id = client.request(&observe_request("packets", &with_link(query, link)))?;
        open.insert(id, link.clone());
    }
    let mut out = BufWriter::new(conn.try_clone()?);
    out.write_all(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-store\r\n\
          X-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n",
    )?;
    out.flush()?;
    client.set_timeout(Some(Duration::from_secs(5)))?;
    while !open.is_empty() {
        match client.next_value() {
            Ok(Some(value)) => {
                let Some(link) = open.get(&value.id).cloned() else {
                    continue;
                };
                match split_event(&value.bytes) {
                    Some(("end", data)) => {
                        write!(out, "event: link_end\ndata: {}\n\n", add_link(data, &link))?
                    }
                    Some((name, data)) => {
                        write!(out, "event: {name}\ndata: {}\n\n", add_link(data, &link))?
                    }
                    None => {
                        let data = format!(
                            "{{\"error\":{}}}",
                            quote(&String::from_utf8_lossy(&value.bytes))
                        );
                        write!(out, "event: link_end\ndata: {}\n\n", add_link(&data, &link))?
                    }
                }
                out.flush()?;
                if value.end {
                    open.remove(&value.id);
                }
            }
            Ok(None) => break,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                out.write_all(b": ping\n\n")?;
                out.flush()?;
            }
            Err(e) => return Err(e),
        }
    }
    write!(
        out,
        "event: end\ndata: {{\"reason\":\"every link closed\"}}\n\n"
    )?;
    out.flush()
}

/// The captures of several links, one pcapng section after another.
fn pcap_merged(mut client: Client, mut conn: TcpStream, links: &[String]) -> io::Result<()> {
    client.set_timeout(Some(Duration::from_secs(30)))?;
    let mut file = Vec::new();
    for link in links {
        let value = client.call(&observe_request(
            "pcap",
            &[("link".to_owned(), link.clone())],
        ))?;
        if value.binary {
            file.extend_from_slice(&value.bytes);
        }
    }
    if file.is_empty() {
        return respond(
            &mut conn,
            "404 Not Found",
            "application/json",
            br#"{"error":"nothing is watching those links"}"#,
            "",
        );
    }
    let disposition = "Content-Disposition: attachment; filename=\"fictionet-links.pcapng\"\r\n";
    respond(
        &mut conn,
        "200 OK",
        "application/vnd.tcpdump.pcap",
        &file,
        disposition,
    )
}

/// Splits a stream value, `{"event":"<name>","data":<data>}`, into its
/// name and data.
pub(crate) fn split_event(value: &[u8]) -> Option<(&str, &str)> {
    let text = std::str::from_utf8(value).ok()?;
    let rest = text.strip_prefix(r#"{"event":""#)?;
    let (name, rest) = rest.split_once('"')?;
    let data = rest.strip_prefix(r#","data":"#)?.strip_suffix('}')?;
    Some((name, data))
}

/// Relays a stream as server-sent events until either side closes.
fn stream(mut client: Client, conn: TcpStream) -> io::Result<()> {
    let mut out = BufWriter::new(conn.try_clone()?);
    out.write_all(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-store\r\n\
          X-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n",
    )?;
    out.flush()?;
    // Wake now and then to send a comment, so a closed browser is noticed
    // even when the world has nothing to say.
    client.set_timeout(Some(Duration::from_secs(5)))?;
    loop {
        match client.next_value() {
            Ok(Some(value)) => {
                match split_event(&value.bytes) {
                    Some((name, data)) => write!(out, "event: {name}\ndata: {data}\n\n")?,
                    None => write!(
                        out,
                        "event: error\ndata: {}\n\n",
                        String::from_utf8_lossy(&value.bytes)
                    )?,
                }
                out.flush()?;
                if value.end {
                    return Ok(());
                }
            }
            Ok(None) => {
                write!(
                    out,
                    "event: end\ndata: {{\"reason\":\"the world closed\"}}\n\n"
                )?;
                return out.flush();
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                out.write_all(b": ping\n\n")?;
                out.flush()?;
            }
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
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
    }

    #[test]
    fn stream_values_split_into_events() {
        assert_eq!(
            split_event(br#"{"event":"node","data":{"id":"t1"}}"#),
            Some(("node", r#"{"id":"t1"}"#))
        );
        assert_eq!(split_event(br#"{"error":"x"}"#), None);
    }
}
