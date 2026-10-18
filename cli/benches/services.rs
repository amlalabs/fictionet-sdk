use bytes::Bytes;
use divan::{Bencher, counter::ItemsCount};
use fictionet::prelude::*;
use fictionet::relay::{self, Hello, Message as RelayMessage, unix};
use fictionet::stdlib::web;
use fictionet::{Interface, WorldSocket, block_on, listen, run};
use fictionet_test_support::bench::finish;
use fictionet_test_support::bench::http as http_world;
use http_world::{HttpCase, Page, Watch, socket_path};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[global_allocator]
static ALLOC: divan::AllocProfiler = divan::AllocProfiler::system();

fn main() {
    divan::main();
}

#[divan::bench_group(name = "relay")]
mod relay_benches {
    use super::*;

    #[divan::bench(name = "socketpair_sends", sample_count = 3, sample_size = 1)]
    fn socketpair_sends(bencher: Bencher) {
        let n = 200_000_u64;
        let payload = vec![0x45; 1500];
        bencher
            .counter(ItemsCount::new(n))
            .with_inputs(|| {
                let mut fds = [0; 2];
                // SAFETY: socketpair fills two descriptors, owned from here.
                assert_eq!(
                    unsafe {
                        libc::socketpair(
                            libc::AF_UNIX,
                            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                            0,
                            fds.as_mut_ptr(),
                        )
                    },
                    0
                );
                let (a, b) =
                    unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
                let reader = std::thread::spawn(move || {
                    let mut buf = vec![0; relay::MAX_MESSAGE];
                    for _ in 0..n {
                        let got = unix::recv(b.as_raw_fd(), &mut buf, false).unwrap();
                        assert_eq!(got, 1501);
                    }
                });
                (a, reader)
            })
            .bench_local_values(|(a, reader)| {
                for _ in 0..n {
                    unix::send_parts(a.as_raw_fd(), &[&[relay::PACKET], &payload], false).unwrap();
                }
                reader.join().unwrap();
                a
            });
    }

    #[divan::bench(args = [1, 64], sample_count = 3, sample_size = 1)]
    fn listen_echo(bencher: Bencher, outstanding: usize) {
        let payload = vec![0x45; 1500];
        let mut buf = vec![0; relay::MAX_MESSAGE + 1];
        bencher
            .counter(ItemsCount::new(100_000_u64))
            .with_inputs(Echo::new)
            .bench_local_values(|echo| {
                let fd = echo.fd.as_ref().unwrap().as_raw_fd();
                let mut sent = 0;
                let mut back = 0;
                while back < 100_000 {
                    while sent < 100_000 && sent - back < outstanding {
                        unix::send_parts(fd, &[&[relay::PACKET], &payload], false).unwrap();
                        sent += 1;
                    }
                    let got = unix::recv(fd, &mut buf, false).unwrap();
                    assert_eq!(got, 1501, "the echo came back whole");
                    back += 1;
                }
                echo
            });
    }
}

struct Echo {
    fd: Option<OwnedFd>,
    world: Option<std::thread::JoinHandle<()>>,
    listening: Option<fictionet::Listening>,
}

impl Echo {
    fn new() -> Self {
        let path = socket_path("echo");
        let (attacher, mut attachments) = fictionet::attachments();
        let listening = listen(WorldSocket::UnixSocket(path.clone()), attacher).unwrap();
        let world = std::thread::spawn(move || {
            finish(block_on(run(
                fictionet::Seed::random(),
                move |fcx| async move {
                    let mut agent = attachments.get(&fcx, "agent").await?;
                    loop {
                        match agent.recv(&fcx).await {
                            Ok(p) => agent.send(p),
                            Err(_) => return Ok(()),
                        }
                    }
                },
            )));
        });
        let fd = unix::connect(&path).unwrap();
        let hello = Hello {
            version: relay::VERSION,
            mtu: 1500,
            kind: "tun".into(),
            name: "agent".into(),
        };
        unix::send(fd.as_raw_fd(), &RelayMessage::Hello(hello).encode(), false).unwrap();
        let mut buf = vec![0u8; relay::MAX_MESSAGE + 1];
        let got = unix::recv(fd.as_raw_fd(), &mut buf, false).unwrap();
        assert_eq!(&buf[..got], &[relay::ACCEPT]);
        Self {
            fd: Some(fd),
            world: Some(world),
            listening: Some(listening),
        }
    }
}

impl Drop for Echo {
    fn drop(&mut self) {
        drop(self.fd.take());
        self.world.take().unwrap().join().unwrap();
        drop(self.listening.take());
    }
}

mod sites {
    use super::*;

    #[divan::bench(args = [1, 10], sample_count = 3, sample_size = 1)]
    fn http1(bencher: Bencher, sandboxes: usize) {
        requests(bencher, sandboxes, false, false);
    }

    #[divan::bench(args = [1, 10], sample_count = 3, sample_size = 1)]
    fn http2(bencher: Bencher, sandboxes: usize) {
        requests(bencher, sandboxes, true, false);
    }

    #[divan::bench(sample_count = 3, sample_size = 1)]
    fn event_hooks(bencher: Bencher) {
        requests(bencher, 10, false, true);
    }

    fn requests(bencher: Bencher, sandboxes: usize, h2: bool, hooks: bool) {
        http_world::bench(
            bencher,
            HttpCase {
                sandboxes,
                h2,
                requests: 30_000,
                body: 1024,
                sites: 1,
                watch: Watch::None,
                hooks,
                writer: false,
            },
        );
    }

    #[divan::bench(sample_count = 3, sample_size = 1)]
    fn proxy_cold(bencher: Bencher) {
        proxy(bencher, true);
    }

    #[divan::bench(sample_count = 3, sample_size = 1)]
    fn proxy_missing(bencher: Bencher) {
        proxy(bencher, false);
    }

    fn proxy(bencher: Bencher, cold: bool) {
        let mut last = None;
        bencher
            .counter(ItemsCount::new(if cold { 32_u64 } else { 50 }))
            .with_inputs(Proxy::new)
            .bench_local_values(|proxy| {
                let start = Instant::now();
                let host = if cold {
                    let gate = Arc::new(std::sync::Barrier::new(32));
                    let threads: Vec<_> = (0..32)
                        .map(|_| {
                            let gate = gate.clone();
                            let addr = proxy.addr;
                            std::thread::spawn(move || {
                                gate.wait();
                                fetch(addr, "plain.test", PROXY_AUTH, 200)
                            })
                        })
                        .collect();
                    for thread in threads {
                        assert_eq!(thread.join().unwrap(), b"plain site\n");
                    }
                    "plain.test"
                } else {
                    for _ in 0..50 {
                        fetch(proxy.addr, "missing.test", PROXY_AUTH, 502);
                    }
                    "missing.test"
                };
                let elapsed = start.elapsed();
                let queries = proxy
                    .queries
                    .lock()
                    .unwrap()
                    .get(host)
                    .copied()
                    .unwrap_or(0);
                last = Some((queries, elapsed));
                proxy
            });
        if let Some((queries, elapsed)) = last {
            eprintln!("last proxy run: DNS queries={queries}, elapsed={elapsed:?}");
        }
    }
}

const PROXY_TOKEN: &str = "bench-token";
const PROXY_AUTH: &str = "Basic cmVsYXk6YmVuY2gtdG9rZW4=";

struct Proxy {
    addr: SocketAddr,
    queries: Arc<Mutex<std::collections::HashMap<String, u64>>>,
    child: std::process::Child,
    stderr: Option<std::thread::JoinHandle<()>>,
    stop: Arc<AtomicBool>,
    world: Option<std::thread::JoinHandle<()>>,
    listening: Option<fictionet::Listening>,
    token: std::path::PathBuf,
}

impl Proxy {
    fn new() -> Self {
        use std::io::BufRead;
        let path = socket_path("proxy");
        let token = path.with_extension("token");
        std::fs::write(&token, PROXY_TOKEN).unwrap();
        let queries: Arc<Mutex<std::collections::HashMap<String, u64>>> = Arc::default();
        let stop = Arc::new(AtomicBool::new(false));
        let (attacher, attachments) = fictionet::attachments();
        let listening = listen(WorldSocket::UnixSocket(path.clone()), attacher).unwrap();
        let world = {
            let (queries, stop) = (queries.clone(), stop.clone());
            std::thread::spawn(move || {
                finish(block_on(run(
                    fictionet::Seed::random(),
                    move |fcx| async move {
                        let page = Page(Bytes::from_static(b"plain site\n"));
                        fcx.events().subscribe(move |e| {
                            if e.is("dns", "query")
                                && let Some(name) = e.str("name")
                                && e.u64("qtype") == Some(1)
                            {
                                *queries.lock().unwrap().entry(name.to_owned()).or_default() += 1;
                            }
                        });
                        web::Sites::new(move |host: &str| {
                            (host == "plain.test")
                                .then(|| web::Site::new(page.clone()).plain_http())
                        })
                        .start(&fcx, attachments)?;
                        while !stop.load(Ordering::Acquire) {
                            fcx.sleep(fictionet::time::ms(10)).await?;
                        }
                        fcx.cancel();
                        Ok(())
                    },
                )));
            })
        };
        let mut child = std::process::Command::new(
            std::env::var("FICTIONET_BIN")
                .unwrap_or_else(|_| env!("CARGO_BIN_EXE_fictionet").to_string()),
        )
        .args([
            "attach",
            "--world",
            &format!("unix:{}", path.display()),
            "--name",
            "agent",
            "--type",
            "http_proxy",
        ])
        .args([
            "--listen",
            "127.0.0.1:0",
            "--token-file",
            token.to_str().unwrap(),
            "--ip-addr",
            "10.0.0.2",
            "--dns",
            "10.0.0.1",
        ])
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("fictionet attach");
        let mut lines = std::io::BufReader::new(child.stderr.take().unwrap()).lines();
        let first = lines.next().unwrap().unwrap();
        let addr: SocketAddr = first
            .split(" on ")
            .nth(1)
            .and_then(|r| r.split(',').next())
            .and_then(|a| a.parse().ok())
            .unwrap_or_else(|| panic!("attach said: {first}"));
        let stderr = std::thread::spawn(move || {
            for line in lines {
                line.unwrap();
            }
        });
        Self {
            addr,
            queries,
            child,
            stderr: Some(stderr),
            stop,
            world: Some(world),
            listening: Some(listening),
            token,
        }
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.child.kill().unwrap();
        self.child.wait().unwrap();
        self.stderr.take().unwrap().join().unwrap();
        self.stop.store(true, Ordering::Release);
        self.world.take().unwrap().join().unwrap();
        drop(self.listening.take());
        std::fs::remove_file(&self.token).unwrap();
    }
}

/// Fetches one proxy response, requiring EOF, the expected status and exact framing.
/// Returns the body. I/O errors and invalid responses panic before a timing is used.
pub fn fetch(addr: SocketAddr, host: &str, auth: &str, expected_status: u16) -> Vec<u8> {
    let mut s = TcpStream::connect(addr)
        .unwrap_or_else(|error| panic!("connect to proxy for {host}: {error}"));
    s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    write!(s, "GET http://{host}/ HTTP/1.1\r\nHost: {host}\r\nProxy-Authorization: {auth}\r\nConnection: close\r\n\r\n")
        .unwrap_or_else(|error| panic!("write proxy request for {host}: {error}"));
    let mut out = Vec::new();
    s.read_to_end(&mut out)
        .unwrap_or_else(|error| panic!("read proxy response for {host}: {error}"));
    response_body(&out, expected_status).to_vec()
}

// These workloads use one Content-Length response. Reject other framing, including
// duplicate lengths, rather than guessing where a successful transfer ends.
fn response_body(bytes: &[u8], expected_status: u16) -> &[u8] {
    let end = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("complete HTTP response head");
    let head = std::str::from_utf8(&bytes[..end]).expect("HTTP response head text");
    let body = &bytes[end + 4..];
    let mut lines = head.split("\r\n");
    let mut status = lines.next().unwrap().splitn(3, ' ');
    assert_eq!(status.next(), Some("HTTP/1.1"), "HTTP version");
    assert_eq!(
        status.next().expect("HTTP status code"),
        expected_status.to_string(),
        "HTTP status"
    );
    let reason = status.next().expect("HTTP status reason");
    assert!(
        reason.bytes().all(|b| b == b'\t' || (32..127).contains(&b)),
        "HTTP status reason"
    );
    let mut length = None;
    for line in lines {
        let (name, value) = line.split_once(':').expect("HTTP header");
        assert!(
            !name.is_empty()
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)),
            "HTTP header name"
        );
        assert!(
            value.bytes().all(|b| b == b'\t' || (32..127).contains(&b)),
            "HTTP header value"
        );
        assert!(
            !name.eq_ignore_ascii_case("transfer-encoding"),
            "proxy benchmark requires Content-Length framing"
        );
        if name.eq_ignore_ascii_case("content-length") {
            assert!(length.is_none(), "duplicate Content-Length");
            let value = value.trim_matches([' ', '\t']);
            assert!(
                !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()),
                "invalid Content-Length"
            );
            length = Some(value.parse::<usize>().expect("Content-Length in range"));
        }
    }
    assert_eq!(
        body.len(),
        length.expect("missing Content-Length"),
        "HTTP body length"
    );
    body
}
