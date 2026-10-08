//! `fictionet attach --type http_proxy` and `--type socks5`: the binary
//! against a `web::Sites` world in this process, with clients that speak
//! the proxy protocols by hand, and curl where it is installed.
//!
//! The Docker test in `tests/docker/proxy` runs the same engine with more
//! clients (wget, git, Python, Go, Node) and measures it.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post};
use fictionet::stdlib::{tls, web};
use rcgen::{BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

const BIN: &str = env!("CARGO_BIN_EXE_fictionet");
const TOKEN: &str = "tok-3f9a2c";
/// "relay:tok-3f9a2c" in base64.
const BASIC: &str = "Basic cmVsYXk6dG9rLTNmOWEyYw==";
/// The address `secure.test` has, with TLS on 443.
const SECURE: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 10);

fn temp_dir() -> PathBuf {
    // Unix socket paths must be short, so not under a long target dir.
    let n = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_nanos();
    let dir = std::env::temp_dir().join(format!("fn-proxy-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A world in a thread: `plain.test` (plain HTTP) and `secure.test`
/// (HTTPS, at 203.0.113.10), every other name NXDOMAIN.
struct World {
    dir: PathBuf,
    sock: String,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
    /// The source and destination IPv4 addresses of the packets a
    /// [`World::black_hole`] has taken in.
    seen: Arc<Mutex<HashSet<[u8; 8]>>>,
    /// How many `A` queries for each name reached the world's DNS.
    queries: Arc<Mutex<std::collections::HashMap<String, usize>>>,
}

impl World {
    fn start() -> World {
        let dir = temp_dir();
        let sock = dir.join("w.sock").to_str().unwrap().to_owned();
        let ca_path = dir.join("ca.pem");
        let stop = Arc::new(AtomicBool::new(false));
        let (stop2, sock2) = (stop.clone(), sock.clone());
        let queries: Arc<Mutex<std::collections::HashMap<String, usize>>> = Arc::default();
        let queries2 = queries.clone();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            let (chain, key) = certs(&ca_path);
            let (attacher, attachments) = fictionet::attachments();
            let listening = fictionet::listen(fictionet::WorldSocket::UnixSocket(sock2.clone().into()), attacher).unwrap();
            ready_tx.send(()).unwrap();
            // A tokio runtime polls the world: axum runs WebSockets in tokio
            // tasks.
            let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
            let _ = rt.block_on(fictionet::run(move |fcx| async move {
                let config = Arc::new(
                    tls::config_builder(&fcx, SystemTime::now(), rustls::crypto::ring::default_provider())
                        .with_safe_default_protocol_versions()?
                        .with_no_client_auth()
                        .with_single_cert(chain, key)?,
                );
                let app = axum::Router::new()
                    .route("/", get(|| async { "plain site\n" }))
                    .route("/mb", get(|| async { vec![b'x'; 1 << 20] }))
                    .route("/upload", post(upload).layer(DefaultBodyLimit::disable()));
                let secure = axum::Router::new().route("/", get(|| async { "secure site\n" }));
                fcx.events().subscribe(move |e| {
                    if e.is("dns", "query")
                        && e.u64("qtype") == Some(1)
                        && let Some(name) = e.str("name")
                    {
                        *queries2.lock().unwrap().entry(name.to_owned()).or_default() += 1;
                    }
                });
                let ws = axum::Router::new().route(
                    "/echo",
                    get(|ws: axum::extract::ws::WebSocketUpgrade| async move {
                        ws.on_upgrade(|mut socket| async move {
                            while let Some(Ok(axum::extract::ws::Message::Text(t))) = socket.recv().await {
                                let reply = format!("echo: {}", t.as_str());
                                let _ = socket.send(axum::extract::ws::Message::Text(reply.into())).await;
                            }
                        })
                    }),
                );
                web::Sites::new(move |host: &str| match host {
                    "plain.test" => Some(web::Site::new(app.clone())),
                    "ws.test" => Some(web::Site::new(ws.clone())),
                    "secure.test" => Some(web::Site::new(secure.clone()).at(SECURE).tls({
                        let c = config.clone();
                        move |_| c.clone()
                    })),
                    _ => None,
                })
                .serve(&fcx, attachments)?;
                while !stop2.load(Ordering::SeqCst) {
                    fcx.sleep(fictionet::time::ms(20)).await?;
                }
                // Ends the run: every attachment closes.
                Err::<(), fictionet::Error>(fictionet::Error::msg("stopped"))
            }));
            drop(listening);
        });
        ready_rx.recv().unwrap();
        World { dir, sock, stop, thread: Some(thread), seen: Arc::default(), queries }
    }

    /// A world that takes every packet from every sandbox and answers
    /// none. A connection through attach waits for an answer to its SYN
    /// until the world stops.
    fn black_hole() -> World {
        use fictionet::InterfaceExt;
        let dir = temp_dir();
        let sock = dir.join("w.sock").to_str().unwrap().to_owned();
        let stop = Arc::new(AtomicBool::new(false));
        let seen: Arc<Mutex<HashSet<[u8; 8]>>> = Arc::default();
        let (stop2, sock2, seen2) = (stop.clone(), sock.clone(), seen.clone());
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            let (attacher, mut attachments) = fictionet::attachments();
            let listening = fictionet::listen(fictionet::WorldSocket::UnixSocket(sock2.clone().into()), attacher).unwrap();
            ready_tx.send(()).unwrap();
            let _ = fictionet::block_on(fictionet::run(move |fcx| async move {
                fcx.spawn(move |fcx| async move {
                    while let Ok(mut sandbox) = attachments.next(&fcx).await {
                        let seen = seen2.clone();
                        fcx.spawn(move |fcx| async move {
                            while let Ok(p) = sandbox.recv(&fcx).await {
                                if let Some(addrs) = p.0.get(12..20) {
                                    seen.lock().unwrap().insert(addrs.try_into().unwrap());
                                }
                            }
                            Ok(())
                        });
                    }
                    Ok(())
                });
                while !stop2.load(Ordering::SeqCst) {
                    fcx.sleep(fictionet::time::ms(20)).await?;
                }
                // Ends the run: every attachment closes.
                Err::<(), fictionet::Error>(fictionet::Error::msg("stopped"))
            }));
            drop(listening);
        });
        ready_rx.recv().unwrap();
        World { dir, sock, stop, thread: Some(thread), seen, queries: Arc::default() }
    }

    fn ca(&self) -> PathBuf {
        self.dir.join("ca.pem")
    }

    /// Ends the world: attach reads its connection close.
    fn stop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            t.join().unwrap();
        }
    }
}

impl Drop for World {
    fn drop(&mut self) {
        self.stop();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Answers a POST with the number of bytes in its body.
async fn upload(body: axum::body::Body) -> String {
    use http_body_util::BodyExt;
    let mut body = body;
    let mut n = 0usize;
    while let Some(Ok(frame)) = body.frame().await {
        n += frame.data_ref().map_or(0, |d| d.len());
    }
    format!("{n}\n")
}

/// A CA, written to `ca_path`, and a certificate for `secure.test`.
fn certs(ca_path: &Path) -> (Vec<rustls::pki_types::CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca.distinguished_name.push(rcgen::DnType::CommonName, "proxy test CA");
    let ca_key = KeyPair::generate().unwrap();
    let ca = ca.self_signed(&ca_key).unwrap();
    let mut leaf = CertificateParams::new(vec!["secure.test".to_owned()]).unwrap();
    leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    leaf.use_authority_key_identifier_extension = true;
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = leaf.signed_by(&leaf_key, &ca, &ca_key).unwrap();
    std::fs::write(ca_path, ca.pem()).unwrap();
    (vec![leaf.der().clone()], PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())))
}

/// A running attach.
struct Attach {
    child: Child,
    addr: SocketAddr,
    log: Arc<Mutex<String>>,
}

impl Attach {
    /// Starts attach with `kind` on a free port and waits until it says
    /// it is attached.
    fn start(world: &World, kind: &str, name: &str, ip: &str) -> Attach {
        let token = world.dir.join("token");
        std::fs::write(&token, format!("{TOKEN}\n")).unwrap();
        let mut child = Command::new(BIN)
            .args(["attach", "--world", &format!("unix:{}", world.sock), "--name", name, "--type", kind])
            .args(["--listen", "127.0.0.1:0", "--token-file", token.to_str().unwrap()])
            .args(["--ip-addr", ip, "--dns", "10.0.0.1"])
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut lines = BufReader::new(child.stderr.take().unwrap()).lines();
        let first = lines.next().unwrap().unwrap();
        // "... attached; HTTP proxy on 127.0.0.1:41234, as ..."
        let addr = first.split(" on ").nth(1).and_then(|r| r.split(',').next()).unwrap_or_else(|| panic!("{first}"));
        let addr: SocketAddr = addr.parse().unwrap();
        let log = Arc::new(Mutex::new(format!("{first}\n")));
        let log2 = log.clone();
        std::thread::spawn(move || {
            for line in lines.map_while(Result::ok) {
                log2.lock().unwrap().push_str(&(line + "\n"));
            }
        });
        Attach { child, addr, log }
    }

    fn connect(&self) -> TcpStream {
        let s = TcpStream::connect(self.addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
        s
    }

    fn log(&self) -> String {
        self.log.lock().unwrap().clone()
    }

    /// Waits up to 5 s for attach to log a line containing `text`. Lines
    /// about a connection come when it ends.
    fn logged(&self, text: &str) -> bool {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if self.log().contains(text) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        false
    }

    /// Waits for attach to exit, at most 10 s.
    fn wait(&mut self) -> std::process::ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(s) = self.child.try_wait().unwrap() {
                return s;
            }
            assert!(Instant::now() < deadline, "attach did not exit");
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Attach {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Reads until the other side closes.
fn read_all(s: &mut TcpStream) -> Vec<u8> {
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    out
}

/// Reads one HTTP head, byte by byte, so nothing after it is taken.
fn read_head(s: &mut TcpStream) -> String {
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match s.read(&mut b) {
            Ok(1) => head.push(b[0]),
            _ => break,
        }
    }
    String::from_utf8_lossy(&head).into_owned()
}

/// Sends `CONNECT target` with `auth`, and returns the answer's head.
fn connect(a: &Attach, target: &str, auth: Option<&str>) -> (TcpStream, String) {
    let mut s = a.connect();
    let auth = auth.map(|v| format!("Proxy-Authorization: {v}\r\n")).unwrap_or_default();
    write!(s, "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n{auth}\r\n").unwrap();
    let head = read_head(&mut s);
    (s, head)
}

/// An HTTP/1.1 request with `Connection: close` on `s`, and the whole
/// answer.
fn http_get(s: &mut TcpStream, host: &str, path: &str) -> String {
    write!(s, "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").unwrap();
    String::from_utf8_lossy(&read_all(s)).into_owned()
}

fn body(answer: &str) -> &str {
    answer.split_once("\r\n\r\n").map_or("", |(_, b)| b)
}

/// The SOCKS5 greeting and login. Returns the server's two answers.
fn socks_login(s: &mut TcpStream, user: &[u8], password: &[u8]) -> ([u8; 2], [u8; 2]) {
    s.write_all(&[5, 1, 2]).unwrap();
    let mut method = [0u8; 2];
    s.read_exact(&mut method).unwrap();
    let mut login = vec![1, user.len() as u8];
    login.extend_from_slice(user);
    login.push(password.len() as u8);
    login.extend_from_slice(password);
    s.write_all(&login).unwrap();
    let mut status = [0u8; 2];
    s.read_exact(&mut status).unwrap();
    (method, status)
}

/// A SOCKS5 CONNECT by name, after logging in with the token. Returns the
/// stream and the reply.
fn socks_connect(a: &Attach, name: &str, port: u16) -> (TcpStream, [u8; 10]) {
    let mut s = a.connect();
    assert_eq!(socks_login(&mut s, b"relay", TOKEN.as_bytes()), ([5, 2], [1, 0]));
    let mut req = vec![5, 1, 0, 3, name.len() as u8];
    req.extend_from_slice(name.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).unwrap();
    let mut reply = [0u8; 10];
    s.read_exact(&mut reply).unwrap();
    (s, reply)
}

fn curl() -> bool {
    Command::new("curl").arg("--version").stdout(Stdio::null()).status().is_ok_and(|s| s.success())
}

#[test]
fn http_door_connects_and_forwards() {
    let world = World::start();
    let a = Attach::start(&world, "http_proxy", "h1", "10.0.0.2");

    // CONNECT, then HTTP inside the tunnel.
    let (mut s, head) = connect(&a, "plain.test:80", Some(BASIC));
    assert!(head.starts_with("HTTP/1.1 200 "), "{head}");
    let answer = http_get(&mut s, "plain.test", "/");
    assert!(answer.starts_with("HTTP/1.1 200 OK\r\n"), "{answer}");
    assert_eq!(body(&answer), "plain site\n");
    // The tunnel ends, and is logged, once both sides have closed.
    drop(s);

    // A plain-HTTP request in absolute form: passed on, and answered with
    // Connection: close.
    let mut s = a.connect();
    write!(s, "GET http://plain.test/ HTTP/1.1\r\nHost: plain.test\r\nProxy-Authorization: {BASIC}\r\n\r\n").unwrap();
    let answer = String::from_utf8_lossy(&read_all(&mut s)).into_owned();
    assert!(answer.starts_with("HTTP/1.1 200 OK\r\n"), "{answer}");
    assert!(answer.contains("\r\nConnection: close\r\n"), "{answer}");
    assert_eq!(body(&answer), "plain site\n");
    drop(s);

    // Bearer works too, and the CONNECT target may be an address. (Sites
    // gives plain.test its address at the first lookup, above.)
    let (_, head) = connect(&a, "198.18.0.1:80", Some(&format!("Bearer {TOKEN}")));
    assert!(head.starts_with("HTTP/1.1 200 "), "{head}");

    assert!(a.logged("CONNECT plain.test:80 (198.18.0.1) 200"), "{}", a.log());
    assert!(a.logged("GET http://plain.test:80/ (198.18.0.1) 200"), "{}", a.log());
}

#[test]
fn https_through_both_doors_with_curl() {
    if !curl() {
        eprintln!("skipped: no curl");
        return;
    }
    let world = World::start();
    let h = Attach::start(&world, "http_proxy", "c1", "10.0.0.2");
    let s = Attach::start(&world, "socks5", "c2", "10.0.0.3");
    let ca = world.ca();
    let run = |proxy: String, url: &str, ca: Option<&Path>| {
        let mut c = Command::new("curl");
        c.args(["-sS", "-m", "20", "-x", &proxy, url]);
        if let Some(ca) = ca {
            c.arg("--cacert").arg(ca);
        }
        let out = c.output().unwrap();
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr)
    };
    let http = format!("http://relay:{TOKEN}@{}", h.addr);
    let socks = format!("socks5h://relay:{TOKEN}@{}", s.addr);
    assert_eq!(run(http.clone(), "https://secure.test/", Some(&ca)), "secure site\n");
    assert_eq!(run(http.clone(), "http://plain.test/", None), "plain site\n");
    assert_eq!(run(socks.clone(), "https://secure.test/", Some(&ca)), "secure site\n");
    assert_eq!(run(socks.clone(), "http://plain.test/", None), "plain site\n");
    // TLS is end to end: without the world's CA, curl refuses the site.
    assert!(run(http.clone(), "https://secure.test/", None).contains("(60)"));
    // Failures, as curl reports them.
    assert!(run(http.clone(), "https://nope.test/", None).contains("response 502"));
    assert!(run(socks.clone(), "https://nope.test/", None).contains("(4)"));
    assert!(run(format!("http://{}", h.addr), "https://secure.test/", None).contains("response 407"));
    assert!(run(format!("socks5h://relay:wrong@{}", s.addr), "https://secure.test/", None).contains("rejected"));
}

/// An axum WebSocket handler in the world, through the HTTP door with a
/// plain `ws://` request: the upgrade passes through, then messages go
/// both ways.
#[test]
fn websockets_pass_through_the_http_door() {
    use fictionet::stdlib::codec::{Stream, Wire};
    use fictionet::stdlib::websocket::{Message, Messages, Role};
    let world = World::start();
    let a = Attach::start(&world, "http_proxy", "ws1", "10.0.0.2");
    let mut s = a.connect();
    write!(
        s,
        "GET http://ws.test/echo HTTP/1.1\r\nHost: ws.test\r\nProxy-Authorization: {BASIC}\r\nUpgrade: websocket\r\n\
         Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
    )
    .unwrap();
    let head = read_head(&mut s).to_lowercase();
    assert!(head.starts_with("http/1.1 101 "), "{head}");
    assert!(head.contains("\r\nupgrade: websocket\r\n"), "{head}");
    assert!(head.contains("sec-websocket-accept: s3pplmbitxaq9kygzzhzrbk+xoo="), "{head}");
    let frame = Message::Text("hello".into()).to_frame(Some([9, 8, 7, 6])).unwrap();
    s.write_all(&frame.to_bytes().unwrap()).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut stream = Stream::new(Messages::new(Role::Client));
    let mut buf = [0u8; 1024];
    let reply = loop {
        if let Some(m) = stream.next() {
            break m.unwrap();
        }
        let n = s.read(&mut buf).unwrap();
        assert!(n > 0, "the WebSocket closed");
        assert_eq!(stream.push(&buf[..n]), n);
    };
    assert_eq!(reply, Message::Text("echo: hello".into()));
}

#[test]
fn tokens_are_checked() {
    let world = World::start();
    let a = Attach::start(&world, "http_proxy", "t1", "10.0.0.2");
    for auth in [None, Some("Basic cmVsYXk6d3Jvbmc="), Some("Bearer wrong"), Some("Basic !!")] {
        let (mut s, head) = connect(&a, "plain.test:80", auth);
        assert!(head.starts_with("HTTP/1.1 407 Proxy Authentication Required\r\n"), "{auth:?}: {head}");
        assert!(head.contains("Proxy-Authenticate: Basic realm=\"proxy\""), "{head}");
        // And the connection is closed.
        let _ = read_all(&mut s);
    }
    // Plain-HTTP requests need it too.
    let mut s = a.connect();
    write!(s, "GET http://plain.test/ HTTP/1.1\r\nHost: plain.test\r\n\r\n").unwrap();
    assert!(String::from_utf8_lossy(&read_all(&mut s)).starts_with("HTTP/1.1 407 "));

    let b = Attach::start(&world, "socks5", "t2", "10.0.0.3");
    let mut s = b.connect();
    assert_eq!(socks_login(&mut s, b"relay", b"wrong"), ([5, 2], [1, 1]));
    assert_eq!(read_all(&mut s), b"", "closed after a wrong token");
    // A client that offers only "no authentication" is turned away.
    let mut s = b.connect();
    s.write_all(&[5, 1, 0]).unwrap();
    assert_eq!(read_all(&mut s), [5, 0xff]);
    assert!(a.logged("CONNECT plain.test:80 407 no token"), "{}", a.log());
    assert!(a.logged("CONNECT plain.test:80 407 wrong token"), "{}", a.log());
    assert!(b.logged("socks5: wrong token"), "{}", b.log());
}

#[test]
fn failures_get_proxy_answers() {
    let world = World::start();
    let a = Attach::start(&world, "http_proxy", "f1", "10.0.0.2");
    let cases = [
        ("nope.test:443", "502 Bad Gateway", "no such name in the world"),
        ("plain.test:443", "502 Bad Gateway", "connection refused"),
        // An address with no machine: the world answers "host
        // unreachable", and the answer comes at once.
        ("192.0.2.1:443", "502 Bad Gateway", "host unreachable"),
        // Nothing outside the world: a real address is just another
        // address in the world, and has no machine either.
        ("1.1.1.1:443", "502 Bad Gateway", "host unreachable"),
        ("[2606:4700::1111]:443", "502 Bad Gateway", "IPv6 is not supported: attach's stack is IPv4 only"),
    ];
    for (target, status, why) in cases {
        let started = Instant::now();
        let (_, head) = connect(&a, target, Some(BASIC));
        assert!(head.starts_with(&format!("HTTP/1.1 {status}\r\n")), "{target}: {head}");
        assert!(head.contains(&format!("X-Proxy-Error: {why}\r\n")), "{target}: {head}");
        assert!(started.elapsed() < Duration::from_secs(3), "{target} took {:?}", started.elapsed());
    }
    // A request that is not a proxy request.
    let mut s = a.connect();
    write!(s, "GET / HTTP/1.1\r\nHost: plain.test\r\n\r\n").unwrap();
    let answer = String::from_utf8_lossy(&read_all(&mut s)).into_owned();
    assert!(answer.starts_with("HTTP/1.1 400 "), "{answer}");

    let b = Attach::start(&world, "socks5", "f2", "10.0.0.3");
    for (name, port, code) in [("nope.test", 443, 4), ("plain.test", 443, 5), ("192.0.2.1", 80, 4), ("1.1.1.1", 443, 4)] {
        let (_, reply) = socks_connect(&b, name, port);
        assert_eq!(reply[..2], [5, code], "{name}:{port}");
    }
    // UDP ASSOCIATE: not supported.
    let mut s = b.connect();
    socks_login(&mut s, b"", TOKEN.as_bytes());
    s.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
    assert_eq!(read_all(&mut s)[..2], [5, 7]);
}

#[test]
fn socks5_carries_bytes_both_ways() {
    let world = World::start();
    let a = Attach::start(&world, "socks5", "s1", "10.0.0.2");
    let (mut s, reply) = socks_connect(&a, "plain.test", 80);
    // Succeeded, bound at the sandbox's address.
    assert_eq!(reply[..8], [5, 0, 0, 1, 10, 0, 0, 2]);
    let answer = http_get(&mut s, "plain.test", "/");
    assert_eq!(body(&answer), "plain site\n");
    // By address, with ATYP 1.
    let mut s = a.connect();
    socks_login(&mut s, b"x", TOKEN.as_bytes());
    s.write_all(&[5, 1, 0, 1, 198, 18, 0, 1, 0, 80]).unwrap();
    let mut reply = [0u8; 10];
    s.read_exact(&mut reply).unwrap();
    assert_eq!(reply[1], 0);
    assert_eq!(body(&http_get(&mut s, "plain.test", "/")), "plain site\n");
}

/// Writes a POST of `n` bytes to /upload and returns the answer's body.
fn post_upload(s: &mut TcpStream, n: usize, absolute: bool) -> String {
    let target = if absolute { "http://plain.test/upload" } else { "/upload" };
    let auth = if absolute { format!("Proxy-Authorization: {BASIC}\r\n") } else { String::new() };
    write!(s, "POST {target} HTTP/1.1\r\nHost: plain.test\r\n{auth}Content-Length: {n}\r\nConnection: close\r\n\r\n").unwrap();
    let chunk = vec![b'u'; 64 * 1024];
    let mut left = n;
    while left > 0 {
        let k = left.min(chunk.len());
        s.write_all(&chunk[..k]).unwrap();
        left -= k;
    }
    body(&String::from_utf8_lossy(&read_all(s))).to_owned()
}

#[test]
fn big_uploads_and_many_downloads_at_once() {
    let world = World::start();
    let a = Attach::start(&world, "http_proxy", "u1", "10.0.0.2");
    let n = 8 << 20;
    let (mut s, head) = connect(&a, "plain.test:80", Some(BASIC));
    assert!(head.starts_with("HTTP/1.1 200 "), "{head}");
    assert_eq!(post_upload(&mut s, n, false), format!("{n}\n"), "through CONNECT");
    let mut s = a.connect();
    assert_eq!(post_upload(&mut s, n, true), format!("{n}\n"), "as a plain-HTTP request");

    // Ten downloads at once, each 1 MiB, all of it.
    let addr = a.addr;
    let threads: Vec<_> = (0..10)
        .map(|_| {
            std::thread::spawn(move || {
                let mut s = TcpStream::connect(addr).unwrap();
                write!(s, "CONNECT plain.test:80 HTTP/1.1\r\nProxy-Authorization: {BASIC}\r\n\r\n").unwrap();
                let head = read_head(&mut s);
                assert!(head.starts_with("HTTP/1.1 200 "), "{head}");
                write!(s, "GET /mb HTTP/1.1\r\nHost: plain.test\r\nConnection: close\r\n\r\n").unwrap();
                let answer = read_all(&mut s);
                let at = answer.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
                answer.len() - at
            })
        })
        .collect();
    for t in threads {
        assert_eq!(t.join().unwrap(), 1 << 20);
    }
}

#[test]
fn the_world_closing_ends_attach_and_closes_the_port() {
    let mut world = World::start();
    let mut a = Attach::start(&world, "http_proxy", "w1", "10.0.0.2");
    let (_, head) = connect(&a, "plain.test:80", Some(BASIC));
    assert!(head.starts_with("HTTP/1.1 200 "), "{head}");
    world.stop();
    let status = a.wait();
    assert_eq!(status.code(), Some(0), "{}", a.log());
    assert!(a.logged("the world closed the connection; the proxy is closed"), "{}", a.log());
    // Fails closed: nothing listens any more.
    assert!(TcpStream::connect(a.addr).is_err());
}

#[test]
fn a_second_attach_under_the_same_name_is_refused() {
    let world = World::start();
    let _a = Attach::start(&world, "socks5", "dup", "10.0.0.2");
    let token = world.dir.join("token");
    let out = Command::new(BIN)
        .args(["attach", "--world", &format!("unix:{}", world.sock), "--name", "dup", "--type", "http_proxy"])
        .args(["--listen", "127.0.0.1:0", "--token-file", token.to_str().unwrap(), "--ip-addr", "10.0.0.3", "--dns", "10.0.0.1"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&out.stderr).contains("the world refused: dup is already attached"));
}

#[test]
fn proxy_types_refuse_tun_flags_and_need_a_token() {
    let base = ["attach", "--world", "unix:/nowhere", "--name", "a", "--type", "http_proxy", "--listen", "127.0.0.1:0"];
    let out = Command::new(BIN)
        .args(base)
        .args(["--token-file", "/t", "--ip-addr", "10.0.0.2", "--dns", "10.0.0.1", "--gateway", "10.0.0.1"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("--type http_proxy takes no --gateway: attach makes the packets itself"), "{err}");

    let out = Command::new(BIN).args(base).args(["--ip-addr", "10.0.0.2", "--dns", "10.0.0.1"]).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("needs --token-file"));

    // A token file that is missing or empty stops attach before it
    // connects to the world.
    let dir = temp_dir();
    let empty = dir.join("empty");
    std::fs::write(&empty, "\n").unwrap();
    for (file, why) in [(dir.join("missing"), "reading the token file"), (empty, "it is empty")] {
        let out = Command::new(BIN)
            .args(base)
            .args(["--token-file", file.to_str().unwrap(), "--ip-addr", "10.0.0.2", "--dns", "10.0.0.1"])
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(1));
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains(why), "{err}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn clients_waiting_for_a_connection_hear_that_the_world_is_gone() {
    let mut world = World::black_hole();
    let mut h = Attach::start(&world, "http_proxy", "g1", "10.0.0.2");
    let mut s = Attach::start(&world, "socks5", "g2", "10.0.0.3");
    // Clients on both doors, each waiting for an answer to its SYN. Each
    // goes to an address of its own, so the world can tell when every one
    // has sent its SYN.
    let n: u8 = 8;
    let mut https = Vec::new();
    let mut socks = Vec::new();
    for i in 1..=n {
        let mut c = h.connect();
        write!(c, "CONNECT 192.0.2.{i}:443 HTTP/1.1\r\nProxy-Authorization: {BASIC}\r\n\r\n").unwrap();
        https.push(c);
        let mut c = s.connect();
        assert_eq!(socks_login(&mut c, b"relay", TOKEN.as_bytes()), ([5, 2], [1, 0]));
        c.write_all(&[5, 1, 0, 1, 192, 0, 2, i, 1, 187]).unwrap();
        socks.push(c);
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while world.seen.lock().unwrap().len() < 2 * n as usize {
        assert!(Instant::now() < deadline, "the world saw {} connections", world.seen.lock().unwrap().len());
        std::thread::sleep(Duration::from_millis(10));
    }
    world.stop();
    for mut c in https {
        let head = read_head(&mut c);
        assert!(head.starts_with("HTTP/1.1 503 "), "{head:?}\n{}", h.log());
        assert!(head.contains("X-Proxy-Error: the world is gone\r\n"), "{head}");
    }
    for mut c in socks {
        let mut reply = [0u8; 10];
        c.read_exact(&mut reply).unwrap_or_else(|e| panic!("{e}\n{}", s.log()));
        assert_eq!(reply[..2], [5, 1], "general failure");
    }
    assert_eq!(h.wait().code(), Some(0), "{}", h.log());
    assert_eq!(s.wait().code(), Some(0), "{}", s.log());
}

/// A world that answers one `hello` with `answer`, then closes. It
/// listens on `sock` before this returns.
fn answer_hello(sock: &Path, answer: Vec<u8>) -> std::thread::JoinHandle<()> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    // SAFETY: plain syscalls on fds this function owns, and a sockaddr_un
    // filled within its bounds.
    let listener = unsafe {
        let fd = libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0);
        assert!(fd >= 0);
        let listener = OwnedFd::from_raw_fd(fd);
        let (addr, len) = fictionet::relay::unix::address(sock).unwrap();
        assert_eq!(libc::bind(fd, (&raw const addr).cast(), len), 0);
        assert_eq!(libc::listen(fd, 1), 0);
        listener
    };
    std::thread::spawn(move || {
        // SAFETY: accept on the listener this thread owns.
        let conn = unsafe { OwnedFd::from_raw_fd(libc::accept(listener.as_raw_fd(), std::ptr::null_mut(), std::ptr::null_mut())) };
        fictionet::relay::unix::raise_buffers(conn.as_raw_fd());
        let mut buf = vec![0u8; fictionet::relay::MAX_MESSAGE];
        fictionet::relay::unix::recv(conn.as_raw_fd(), &mut buf, false).unwrap();
        fictionet::relay::unix::send(conn.as_raw_fd(), &answer, false).unwrap();
        // Hold the connection until attach has read the answer and closed.
        let _ = fictionet::relay::unix::recv(conn.as_raw_fd(), &mut buf, false);
    })
}

#[test]
fn an_oversized_answer_to_hello_is_an_error_not_a_refusal() {
    let dir = temp_dir();
    let sock = dir.join("w.sock");
    let token = dir.join("token");
    std::fs::write(&token, format!("{TOKEN}\n")).unwrap();
    let attach = |sock: &Path| {
        Command::new(BIN)
            .args(["attach", "--world", &format!("unix:{}", sock.display()), "--name", "big", "--type", "http_proxy"])
            .args(["--listen", "127.0.0.1:0", "--token-file", token.to_str().unwrap(), "--ip-addr", "10.0.0.2", "--dns", "10.0.0.1"])
            .output()
            .unwrap()
    };
    // A refuse of 65,537 bytes in all: one byte past the limit.
    let mut refuse = vec![3u8];
    refuse.resize(fictionet::relay::MAX_MESSAGE + 1, b'a');
    let world = answer_hello(&sock, refuse);
    let out = attach(&sock);
    world.join().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(err.contains("longer than 65,536 bytes"), "{err}");
    // A refuse at the limit is still a refusal.
    std::fs::remove_file(&sock).unwrap();
    let mut refuse = vec![3u8];
    refuse.resize(fictionet::relay::MAX_MESSAGE, b'a');
    let world = answer_hello(&sock, refuse);
    let out = attach(&sock);
    world.join().unwrap();
    assert_eq!(out.status.code(), Some(3), "{}", String::from_utf8_lossy(&out.stderr));
    let _ = std::fs::remove_dir_all(&dir);
}

/// Clients that ask for the same name at once share one lookup, and a name
/// the world does not know is not asked for again right away.
#[test]
fn lookups_of_one_name_are_shared_and_misses_remembered() {
    let world = World::start();
    let attach = Attach::start(&world, "http_proxy", "dns-share", "10.0.0.2");
    let gate = Arc::new(std::sync::Barrier::new(16));
    let clients: Vec<_> = (0..16)
        .map(|_| {
            let (gate, mut s) = (gate.clone(), attach.connect());
            std::thread::spawn(move || {
                gate.wait();
                write!(s, "GET http://plain.test/ HTTP/1.1\r\nHost: plain.test\r\nProxy-Authorization: {BASIC}\r\n\r\n").unwrap();
                String::from_utf8_lossy(&read_all(&mut s)).into_owned()
            })
        })
        .collect();
    for c in clients {
        let answer = c.join().unwrap();
        assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
    }
    assert_eq!(world.queries.lock().unwrap().get("plain.test"), Some(&1));
    for _ in 0..5 {
        let mut s = attach.connect();
        write!(s, "GET http://nope.test/ HTTP/1.1\r\nHost: nope.test\r\nProxy-Authorization: {BASIC}\r\n\r\n").unwrap();
        let answer = String::from_utf8_lossy(&read_all(&mut s)).into_owned();
        assert!(answer.starts_with("HTTP/1.1 502"), "{answer}");
    }
    assert_eq!(world.queries.lock().unwrap().get("nope.test"), Some(&1));
    drop(attach);
}
