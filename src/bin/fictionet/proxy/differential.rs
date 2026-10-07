//! The proxy door's old parsers (httparse and hand-written SOCKS5) against
//! the library's, on the fuzz corpus and generated input. Valid traffic
//! must get the same result from both; differences on invalid traffic are
//! counted and printed.

use std::collections::BTreeMap;

use fictionet::relay::proxy as new;
use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::http1::{RequestHead, ResponseHead};

use super::{auth, http, socks5};

fn corpus(name: &str) -> Vec<Vec<u8>> {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/corpus").join(name);
    let mut out: Vec<Vec<u8>> = std::fs::read_dir(&dir)
        .map(|d| d.filter_map(|e| std::fs::read(e.ok()?.path()).ok()).collect())
        .unwrap_or_default();
    out.sort();
    out
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len() as u64) as usize]
    }
}

fn http_inputs() -> Vec<Vec<u8>> {
    let mut inputs = corpus("proxy_http");
    let mut rng = Rng(0x2545_f491_4f6c_dd1d);
    let methods = ["GET", "POST", "CONNECT", "HEAD", "PUT", "OPTIONS", "DELETE"];
    let targets = [
        "http://plain.test/x?y=1",
        "http://plain.test",
        "HTTP://Plain.Test:8080/a/b",
        "http://198.18.0.1:81/",
        "http://[fd00::1]:8080/v6",
        "example.test:443",
        "203.0.113.10:8443",
        "[fd00::1]:443",
        "http://a/?",
        "/",
        "https://x/",
        "http://u:p@a/",
        "http://a/#f",
    ];
    let fields = [
        "Host: plain.test",
        "Host: example.test:443",
        "Proxy-Authorization: Basic ZmljdGlvbmV0OnMzY3JldC10b2tlbg==",
        "Proxy-Connection: keep-alive",
        "Connection: keep-alive, X-Secret",
        "Connection: Upgrade",
        "Upgrade: websocket",
        "X-Secret: 1",
        "Content-Length: 3",
        "Transfer-Encoding: chunked",
        "User-Agent: curl/8.0",
        "Accept: */*",
        "TE: trailers",
        "X-Empty:",
        "X-Spaces:   padded   ",
    ];
    for _ in 0..4000 {
        let method = rng.pick(&methods);
        let target = rng.pick(&targets);
        let version = if rng.below(4) == 0 { "HTTP/1.0" } else { "HTTP/1.1" };
        let mut head = format!("{method} {target} {version}\r\n");
        for _ in 0..rng.below(6) {
            head.push_str(rng.pick(&fields));
            head.push_str("\r\n");
        }
        head.push_str("\r\n");
        let mut bytes = head.into_bytes();
        if rng.below(3) == 0 {
            bytes.extend_from_slice(b"abc");
        }
        // Cut some short, and spoil a byte in some.
        if rng.below(5) == 0 {
            let at = rng.below(bytes.len() as u64) as usize;
            bytes.truncate(at);
        } else if rng.below(5) == 0 {
            let at = rng.below(bytes.len() as u64) as usize;
            bytes[at] = rng.next() as u8;
        }
        inputs.push(bytes);
    }
    let statuses = ["100 Continue", "101 Switching Protocols", "200 OK", "204 No Content", "302 Found", "404 Not Found", "500 Oops"];
    let answer_fields = [
        "Content-Length: 5",
        "Connection: keep-alive",
        "Connection: upgrade",
        "Upgrade: websocket",
        "Keep-Alive: timeout=5",
        "Content-Type: text/html; charset=utf-8",
        "Transfer-Encoding: chunked",
        "Set-Cookie: a=b; Path=/",
        "Sec-WebSocket-Accept: abc",
    ];
    for _ in 0..3000 {
        let version = if rng.below(4) == 0 { "HTTP/1.0" } else { "HTTP/1.1" };
        let mut head = format!("{version} {}\r\n", rng.pick(&statuses));
        for _ in 0..rng.below(6) {
            head.push_str(rng.pick(&answer_fields));
            head.push_str("\r\n");
        }
        head.push_str("\r\nhello");
        let mut bytes = head.into_bytes();
        if rng.below(5) == 0 {
            let at = rng.below(bytes.len() as u64) as usize;
            bytes.truncate(at);
        } else if rng.below(5) == 0 {
            let at = rng.below(bytes.len() as u64) as usize;
            bytes[at] = rng.next() as u8;
        }
        inputs.push(bytes);
    }
    inputs
}

fn old_target(t: &http::Target) -> String {
    match t {
        http::Target::Connect { host, port } => format!("connect {host} {port}"),
        http::Target::Forward { host, port, authority, path } => format!("forward {host} {port} {authority} {path}"),
    }
}

fn new_target(t: &new::http::Target) -> String {
    match t {
        new::http::Target::Connect { host, port } => format!("connect {host} {port}"),
        new::http::Target::Forward { host, port, authority, path } => format!("forward {host} {port} {authority} {path}"),
    }
}

#[test]
fn http_requests_and_answers_read_the_same() {
    let mut differ: BTreeMap<String, (usize, Vec<u8>)> = BTreeMap::new();
    let (mut accepted, mut valid, mut answers) = (0, 0, 0);
    for data in http_inputs() {
        let mut note = |what: String| {
            let e = differ.entry(what).or_insert((0, data.clone()));
            e.0 += 1;
        };
        let old = http::parse_request(&data);
        let new = new::http::parse_request(&data);
        match (&old, &new) {
            (Ok(Some((o, olen))), _) => {
                // Every request the old door took reads the same, valid by
                // RFC 9112 or not: the door relays, and leaves the rules
                // to the site.
                let Ok(Some((n, nlen))) = &new else {
                    panic!("a request the old door took is refused: {:?} {new:?}", String::from_utf8_lossy(&data));
                };
                let same = o.method == n.head.method
                    && old_target(&o.target) == new_target(&n.target)
                    && o.version == (n.head.version == fictionet::stdlib::http1::Version::Http11) as u8
                    && o.headers.len() == n.head.headers.len()
                    && o.headers.iter().zip(&n.head.headers).all(|((name, value), h)| *name == h.name && *value == h.value)
                    && olen == nlen
                    && match o.target {
                        http::Target::Forward { .. } => http::forward_head(o) == new::http::forward_head(n),
                        http::Target::Connect { .. } => true,
                    };
                assert!(same, "a request the old door took reads differently: {:?}", String::from_utf8_lossy(&data));
                accepted += 1;
                valid += usize::from(RequestHead::parse(&data[..*olen]).is_ok());
            }
            (Ok(None), Ok(None)) => {}
            (Err(o), Err(n)) if o.status == n.status => {}
            (o, n) => note(format!(
                "request: old {:?}, new {:?}",
                o.as_ref().map(|r| r.is_some()).map_err(|r| r.status),
                n.as_ref().map(|r| r.is_some()).map_err(|r| r.status)
            )),
        }
        let old = http::rewrite_response(&data);
        let new = new::http::rewrite_response(&data);
        match (&old, &new) {
            (Ok(Some(o)), Ok(Some(n))) => {
                let strict = ResponseHead::parse(&data[..o.len]).is_ok() || (o.interim && o.head.ends_with(b"\r\n\r\n"));
                let same = o.head == n.head && o.status == n.status && o.interim == n.interim && o.len == n.len;
                assert!(same || !strict, "a valid answer is rewritten differently: {:?}", String::from_utf8_lossy(&data));
                answers += usize::from(strict);
                if !same {
                    // Only heads with bare LF line ends, which the old
                    // door rewrote into broken heads.
                    let bare_lf = data[..o.len].windows(2).any(|w| w[1] == b'\n' && w[0] != b'\r') || data.starts_with(b"\n");
                    assert!(bare_lf, "an answer is rewritten differently: {:?}", String::from_utf8_lossy(&data));
                    note("old and new rewrite an answer with bare LF line ends differently".into());
                }
            }
            (Ok(Some(o)), n) => {
                assert!(ResponseHead::parse(&data[..o.len]).is_err(), "a valid answer is refused: {:?}", String::from_utf8_lossy(&data));
                note(format!(
                    "old took, new refused an answer RFC 9112 refuses ({:?}): {:?}",
                    ResponseHead::parse(&data[..o.len]).err(),
                    n.as_ref().map(|a| a.is_some())
                ));
            }
            (Ok(None), Ok(None)) | (Err(_), Err(_)) => {}
            (o, n) => note(format!(
                "answer: old {:?}, new {:?}",
                o.as_ref().map(|a| a.is_some()).is_ok(),
                n.as_ref().map(|a| a.is_some())
            )),
        }
    }
    eprintln!("{accepted} requests ({valid} valid by RFC 9112) and {answers} valid answers read the same; differences on the rest:");
    for (what, (n, example)) in &differ {
        eprintln!("  {n:5}  {what}\n         such as {:?}", String::from_utf8_lossy(&example[..example.len().min(120)]));
    }
    assert!(valid > 300 && answers > 300, "the corpus has valid heads: {valid} {answers}");
}

fn old_refusal(r: &Result<(socks5_host::Host, u16), socks5::Refusal>) -> String {
    match r {
        Ok((host, port)) => format!("ok {host} {port}"),
        Err(socks5::Refusal::Malformed(why)) => format!("malformed: {why}"),
        Err(socks5::Refusal::NoMethod) => "no method".into(),
        Err(socks5::Refusal::BadToken) => "bad token".into(),
        Err(socks5::Refusal::Reply(code, why)) => format!("reply {code}: {why}"),
    }
}

fn new_refusal(r: &Result<new::socks5::Connect, new::socks5::Refusal>) -> String {
    match r {
        Ok(c) => format!("ok {} {}", c.host, c.port),
        Err(new::socks5::Refusal::Malformed(why)) => format!("malformed: {why}"),
        Err(new::socks5::Refusal::NoMethod) => "no method".into(),
        Err(new::socks5::Refusal::BadToken) => "bad token".into(),
        Err(new::socks5::Refusal::Reply(code, why)) => format!("reply {}: {why}", code.code()),
    }
}

mod socks5_host {
    pub(super) use super::super::stack::Host;
}

fn run_both(input: &[u8]) -> ((String, Vec<u8>), (String, Vec<u8>)) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async move {
        let (mut client, mut server) = duplex(1 << 16);
        client.write_all(input).await.unwrap();
        client.shutdown().await.unwrap();
        let old = socks5::handshake(&mut server, &auth::Token::new(b"tok").unwrap()).await;
        drop(server);
        let mut old_out = Vec::new();
        client.read_to_end(&mut old_out).await.unwrap();

        let (mut client, mut server) = duplex(1 << 16);
        client.write_all(input).await.unwrap();
        client.shutdown().await.unwrap();
        let new = new::socks5::handshake(&mut server, &new::auth::Token::new(b"tok").unwrap()).await;
        drop(server);
        let mut new_out = Vec::new();
        client.read_to_end(&mut new_out).await.unwrap();
        ((old_refusal(&old), old_out), (new_refusal(&new), new_out))
    })
}

/// A handshake by the rules: greeting, login and request, each well formed.
fn valid_handshake(rng: &mut Rng) -> Vec<u8> {
    let mut v = vec![5];
    let mut methods: Vec<u8> = (0..rng.below(4)).map(|_| *rng.pick(&[0u8, 1, 2, 3, 0x80])).collect();
    if rng.below(8) != 0 {
        methods.insert(rng.below(methods.len() as u64 + 1) as usize, 2);
    }
    v.push(methods.len() as u8);
    v.extend_from_slice(&methods);
    let user: &[u8] = rng.pick(&[&b"fictionet"[..], b"", b"tok", b"x"]);
    let password: &[u8] = rng.pick(&[&b"tok"[..], b"", b"nope", b"toke"]);
    v.extend_from_slice(&[1, user.len() as u8]);
    v.extend_from_slice(user);
    v.push(password.len() as u8);
    v.extend_from_slice(password);
    v.extend_from_slice(&[5, *rng.pick(&[1u8, 1, 1, 2, 3]), 0]);
    match rng.below(3) {
        0 => v.extend_from_slice(&[1, 203, 0, 113, rng.next() as u8]),
        1 => {
            let name: &str = rng.pick(&["example.test", "Example.TEST.", "a b", "x", "203.0.113.9", "[fd00::1]", "a..b", "ä.test"]);
            v.extend_from_slice(&[3, name.len() as u8]);
            v.extend_from_slice(name.as_bytes());
        }
        _ => {
            v.push(4);
            v.extend_from_slice(&[0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        }
    }
    v.extend_from_slice(&(rng.next() as u16).to_be_bytes());
    v
}

#[test]
fn socks5_handshakes_go_the_same_way() {
    let mut differ: BTreeMap<String, usize> = BTreeMap::new();
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let mut valid = 0;
    for _ in 0..3000 {
        let input = valid_handshake(&mut rng);
        let (old, new) = run_both(&input);
        assert_eq!(old, new, "a valid handshake goes differently: {input:?}");
        valid += 1;
    }
    let mut inputs = corpus("proxy_socks5");
    for _ in 0..3000 {
        let mut v = valid_handshake(&mut rng);
        match rng.below(3) {
            0 => v.truncate(rng.below(v.len() as u64) as usize),
            1 => {
                let at = rng.below(v.len() as u64) as usize;
                v[at] = rng.next() as u8;
            }
            _ => v = (0..rng.below(40)).map(|_| rng.next() as u8).collect(),
        }
        inputs.push(v);
    }
    for input in inputs {
        let (old, new) = run_both(&input);
        if old != new {
            *differ.entry(format!("old {:?} {:?}, new {:?} {:?}", old.0, old.1.len(), new.0, new.1.len())).or_default() += 1;
            // Where the old door took the request, only a reserved byte
            // that is not 0 (RFC 1928 says it is) may change that.
            if old.0.starts_with("ok") {
                assert!(new.0.contains("malformed") || new.0.starts_with("reply 1"), "{input:?}: {old:?} {new:?}");
            }
        }
    }
    eprintln!("{valid} valid handshakes go the same way; differences on the rest:");
    for (what, n) in &differ {
        eprintln!("  {n:5}  {what}");
    }
}
