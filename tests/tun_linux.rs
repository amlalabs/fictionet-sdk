//! TCP and UDP endpoints against a real Linux network stack, through a tun
//! device. Needs root and /dev/net/tun, so it is ignored by default and
//! runs with `--ignored`. `tests/docker/tcpudp/run.sh` runs it that way in
//! a container.
//!
//! The container's kernel is the client: it has 10.9.0.1/24 and fd09::1/64
//! on the tun device, and the endpoints are 10.9.0.2 and fd09::2.

#[path = "common/done.rs"]
mod done;

use done::Done;

use std::future::poll_fn;
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpStream, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::task::Poll;
use std::time::{Duration, Instant};

use fictionet::prelude::*;
use fictionet::stdlib::{tcp, udp};
use fictionet::{Cx, End, Interface, Packet, RecvError, block_on, pair, run};

/// The world's side of the tun device: packets the kernel sends come out of
/// `rx` (fed by a reading thread), and `send` writes to the device.
struct Tun {
    fd: Arc<OwnedFd>,
    rx: End,
}

impl Interface for Tun {
    fn poll_recv(
        &mut self,
        fcx: &Cx,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<Packet, RecvError>> {
        self.rx.poll_recv(fcx, cx)
    }
    fn send(&mut self, packet: Packet) {
        unsafe {
            libc::write(
                self.fd.as_raw_fd(),
                packet.0.as_ptr().cast(),
                packet.0.len(),
            )
        };
    }
}

fn open_tun(name: &str) -> Tun {
    let fd = unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR) };
    assert!(
        fd >= 0,
        "open /dev/net/tun: {}",
        std::io::Error::last_os_error()
    );
    let fd = Arc::new(unsafe { OwnedFd::from_raw_fd(fd) });
    let mut req = [0u8; 40];
    req[..name.len()].copy_from_slice(name.as_bytes());
    let flags = (libc::IFF_TUN | libc::IFF_NO_PI) as u16;
    req[16..18].copy_from_slice(&flags.to_ne_bytes());
    let r = unsafe { libc::ioctl(fd.as_raw_fd(), libc::TUNSETIFF, req.as_mut_ptr()) };
    assert!(r >= 0, "TUNSETIFF: {}", std::io::Error::last_os_error());
    let (rx, mut feed) = pair();
    let reader = fd.clone();
    std::thread::spawn(move || {
        let mut buf = vec![0u8; 65536];
        loop {
            let n = unsafe { libc::read(reader.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
            if n <= 0 {
                return;
            }
            feed.send(Packet(buf[..n as usize].to_vec()));
        }
    });
    Tun { fd, rx }
}

fn sh(cmd: &str) {
    let s = std::process::Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .status()
        .unwrap();
    assert!(s.success(), "{cmd} failed");
}

/// Sorts the tun's packets to four endpoints' cables by IP version and
/// protocol, and drops a share of the TCP packets that carry data, in both
/// directions, while `LOSS` is set (per mille).
static LOSS: AtomicUsize = AtomicUsize::new(0);

fn demux(fcx: &Cx, tun: Tun) -> [End; 4] {
    let (a, wa) = pair();
    let (b, wb) = pair();
    let (c, wc) = pair();
    let (d, wd) = pair();
    fcx.spawn(move |fcx| async move {
        let mut tun = tun;
        let mut sides = [wa, wb, wc, wd];
        let mut seed = 0x9e3779b97f4a7c15u64;
        let trace = std::env::var("FICTIONET_TRACE").is_ok();
        let mut lose = move |p: &Packet| {
            let loss = LOSS.load(Ordering::Relaxed) as u64;
            if loss == 0 {
                return false;
            }
            let (proto, hdr) = if p.0[0] >> 4 == 4 {
                (p.0[9], (p.0[0] & 15) as usize * 4)
            } else {
                (p.0[6], 40)
            };
            if proto != 6
                || p.0.len() < hdr + 20
                || p.0.len() <= hdr + ((p.0[hdr + 12] >> 4) as usize) * 4
            {
                return false;
            }
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed % 1000 < loss
        };
        loop {
            let ev = poll_fn(|cx| {
                if let Poll::Ready(r) = tun.poll_recv(&fcx, cx) {
                    return Poll::Ready(r.map(|p| (None, p)));
                }
                for (i, s) in sides.iter_mut().enumerate() {
                    if let Poll::Ready(r) = s.poll_recv(&fcx, cx) {
                        return Poll::Ready(r.map(|p| (Some(i), p)));
                    }
                }
                Poll::Pending
            })
            .await;
            let lost = matches!(&ev, Ok((_, p)) if lose(p));
            if let Ok((from, p)) = &ev {
                trace_packet(&fcx, from.is_none(), p, trace, lost);
            }
            match ev {
                Ok(_) if lost => {}
                Ok((Some(_), p)) => tun.send(p),
                Ok((None, p)) => {
                    let (v6, proto) = if p.0[0] >> 4 == 6 {
                        (true, p.0[6])
                    } else {
                        (false, p.0[9])
                    };
                    let i = match (v6, proto) {
                        (false, 6) => 0,
                        (false, 17) => 1,
                        (true, 6) => 2,
                        (true, 17) => 3,
                        _ => continue,
                    };
                    sides[i].send(p);
                }
                Err(_) => return Ok(()),
            }
        }
    });
    [a, b, c, d]
}

/// The last packets seen, printed when the traffic stalls.
static RING: Mutex<std::collections::VecDeque<String>> =
    Mutex::new(std::collections::VecDeque::new());
static LAST: Mutex<Option<Instant>> = Mutex::new(None);

fn trace_packet(fcx: &Cx, from_kernel: bool, p: &Packet, print: bool, lost: bool) {
    *LAST.lock().unwrap() = Some(Instant::now());
    let (proto, hdr) = if p.0[0] >> 4 == 4 {
        (p.0[9], (p.0[0] & 15) as usize * 4)
    } else {
        (p.0[6], 40)
    };
    if proto != 6 {
        return;
    }
    let t = &p.0[hdr..];
    let off = ((t[12] >> 4) as usize) * 4;
    let line = format!(
        "{:>12.6} {} {}>{} seq={} ack={} flags={:02x} win={} len={}{}",
        fcx.now().since_start().as_secs_f64(),
        if from_kernel { "K>W" } else { "W>K" },
        u16::from_be_bytes([t[0], t[1]]),
        u16::from_be_bytes([t[2], t[3]]),
        u32::from_be_bytes([t[4], t[5], t[6], t[7]]),
        u32::from_be_bytes([t[8], t[9], t[10], t[11]]),
        t[13],
        u16::from_be_bytes([t[14], t[15]]),
        p.0.len() - hdr - off,
        if lost { " LOST" } else { "" }
    );
    if print {
        eprintln!("{line}");
    }
    let mut ring = RING.lock().unwrap();
    if ring.len() == 300 {
        ring.pop_front();
    }
    ring.push_back(line);
}

#[path = "common/pattern.rs"]
mod payload;
use payload::pattern;

/// Serves on a TCP endpoint: port 80 echoes until EOF, port 81 sends
/// `DOWNLOAD` bytes and closes.
const DOWNLOAD: usize = 20 * 1024 * 1024;

fn serve(fcx: &Cx, ep: &tcp::Endpoint) -> fictionet::Result {
    let mut echo = ep.listen(80)?;
    fcx.spawn(move |fcx| async move {
        while let Ok(mut conn) = echo.accept(&fcx).await {
            fcx.spawn(move |fcx| async move {
                let mut buf = vec![0; 65536];
                loop {
                    match conn.read(&fcx, &mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            if conn.write_all(&fcx, &buf[..n]).await.is_err() {
                                return Ok(());
                            }
                        }
                        Err(_) => return Ok(()),
                    }
                }
                let _ = conn.shutdown(&fcx).await;
                // Wait for the client's FIN so the FIN is not lost on drop.
                let _ = conn.read(&fcx, &mut buf).await;
                Ok(())
            });
        }
        Ok(())
    });
    let mut down = ep.listen(81)?;
    fcx.spawn(move |fcx| async move {
        let data = Arc::new(pattern(DOWNLOAD, 7));
        while let Ok(mut conn) = down.accept(&fcx).await {
            let data = data.clone();
            fcx.spawn(move |fcx| async move {
                if conn.write_all(&fcx, &data).await.is_ok() {
                    let _ = conn.shutdown(&fcx).await;
                    let mut buf = [0; 16];
                    let _ = conn.read(&fcx, &mut buf).await;
                }
                Ok(())
            });
        }
        Ok(())
    });
    Ok(())
}

fn udp_echo(fcx: &Cx, ep: &udp::Endpoint) -> fictionet::Result {
    let mut s = ep.bind(53)?;
    fcx.spawn(move |fcx| async move {
        while let Ok((data, from)) = s.recv(&fcx).await {
            s.send_to(&data, from);
        }
        Ok(())
    });
    Ok(())
}

/// The client checks, run by the kernel on another thread.
fn client(log: &Mutex<Vec<String>>) {
    let say = |s: String| {
        eprintln!("{s}");
        log.lock().unwrap().push(s);
    };
    let only_loss = std::env::var("FICTIONET_ONLY_LOSS").is_ok();
    for host in ["10.9.0.2", "fd09::2"] {
        if only_loss {
            break;
        }
        let ip: IpAddr = host.parse().unwrap();
        // Echo, both ways at once.
        let data = pattern(10 * 1024 * 1024, 3);
        let started = Instant::now();
        let mut s = TcpStream::connect(SocketAddr::new(ip, 80)).unwrap();
        let mut r = s.try_clone().unwrap();
        let d2 = data.clone();
        let writer = std::thread::spawn(move || {
            s.write_all(&d2).unwrap();
            s.shutdown(Shutdown::Write).unwrap();
        });
        let mut back = Vec::new();
        r.read_to_end(&mut back).unwrap();
        writer.join().unwrap();
        assert!(back == data, "{host}: the echo differs");
        let t = started.elapsed();
        say(format!(
            "{host}: 10 MiB echoed in {t:?} ({:.0} Mbit/s each way)",
            data.len() as f64 * 8.0 / t.as_secs_f64() / 1e6
        ));

        // Download.
        let started = Instant::now();
        let mut s = TcpStream::connect(SocketAddr::new(ip, 81)).unwrap();
        let mut got = Vec::new();
        s.read_to_end(&mut got).unwrap();
        assert!(got == pattern(DOWNLOAD, 7), "{host}: the download differs");
        let t = started.elapsed();
        say(format!(
            "{host}: 20 MiB download in {t:?} ({:.0} Mbit/s)",
            got.len() as f64 * 8.0 / t.as_secs_f64() / 1e6
        ));

        // A closed port.
        let started = Instant::now();
        let e = TcpStream::connect_timeout(&SocketAddr::new(ip, 82), Duration::from_millis(300))
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::ConnectionRefused, "{host}: {e}");
        say(format!(
            "{host}: closed port refused in {:?}",
            started.elapsed()
        ));

        // UDP echo, and port unreachable on a connected socket.
        let local: SocketAddr = if ip.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        let u = UdpSocket::bind(local).unwrap();
        u.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        u.connect(SocketAddr::new(ip, 53)).unwrap();
        u.send(b"ping").unwrap();
        let mut buf = [0; 64];
        let n = u.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"ping");
        u.connect(SocketAddr::new(ip, 54)).unwrap();
        u.send(b"anyone?").unwrap();
        let e = u.recv(&mut buf).unwrap_err();
        assert_eq!(
            e.kind(),
            ErrorKind::ConnectionRefused,
            "{host}: UDP to a closed port: {e}"
        );
        say(format!("{host}: UDP echo and port unreachable work"));
    }

    // Every port, as a port scan with a 0.3 s timeout does it.
    let started = Instant::now();
    let scan_from = if only_loss { 65536 } else { 1 };
    let next = Arc::new(AtomicUsize::new(scan_from));
    let open = Arc::new(Mutex::new(Vec::new()));
    let failures = Arc::new(Mutex::new(Vec::new()));
    let threads: Vec<_> = (0..256)
        .map(|_| {
            let (next, open, failures) = (next.clone(), open.clone(), failures.clone());
            std::thread::spawn(move || {
                loop {
                    let port = next.fetch_add(1, Ordering::Relaxed);
                    if port > 65535 {
                        return;
                    }
                    let to = SocketAddr::new("10.9.0.2".parse().unwrap(), port as u16);
                    match TcpStream::connect_timeout(&to, Duration::from_millis(300)) {
                        Ok(_) => open.lock().unwrap().push(port),
                        Err(e) if e.kind() == ErrorKind::ConnectionRefused => {}
                        Err(e) => failures.lock().unwrap().push((port, e.kind())),
                    }
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    let mut open = open.lock().unwrap().clone();
    open.sort();
    let failures = failures.lock().unwrap().clone();
    say(format!(
        "scan of 65,535 ports in {:?}: open {open:?}, failures {}",
        started.elapsed(),
        failures.len()
    ));
    if !only_loss {
        assert_eq!(open, [80, 81]);
    }
    assert!(
        failures.is_empty(),
        "ports that were not refused: {:?}",
        &failures[..failures.len().min(20)]
    );

    // A download with 1% of the data packets lost, each way.
    LOSS.store(10, Ordering::Relaxed);
    let started = Instant::now();
    let mut s = TcpStream::connect("10.9.0.2:81").unwrap();
    let mut got = Vec::new();
    s.read_to_end(&mut got).unwrap();
    assert!(got == pattern(DOWNLOAD, 7), "the lossy download differs");
    let t = started.elapsed();
    say(format!(
        "20 MiB download with 1% loss in {t:?} ({:.0} Mbit/s)",
        got.len() as f64 * 8.0 / t.as_secs_f64() / 1e6
    ));
    LOSS.store(0, Ordering::Relaxed);
}

#[test]
#[ignore = "needs root and /dev/net/tun; tests/docker/tcpudp/run.sh runs it"]
fn a_linux_client_through_tun() {
    let tun = open_tun("fn0");
    sh(
        "ip link set fn0 up mtu 1500 && ip addr add 10.9.0.1/24 dev fn0 && ip -6 addr add fd09::1/64 dev fn0 nodad",
    );
    let log = Arc::new(Mutex::new(Vec::new()));
    let (done_tx, done_rx) = mpsc::channel::<()>();
    let l = log.clone();
    let result = block_on(run(fictionet::Seed::random(), move |fcx| async move {
        let [t4, u4, t6, u6] = demux(&fcx, tun);
        let tcp4 = tcp::endpoint(&fcx, t4, "10.9.0.2".parse()?);
        let udp4 = udp::endpoint(&fcx, u4, "10.9.0.2".parse()?);
        let tcp6 = tcp::endpoint(&fcx, t6, "fd09::2".parse()?);
        let udp6 = udp::endpoint(&fcx, u6, "fd09::2".parse()?);
        serve(&fcx, &tcp4)?;
        serve(&fcx, &tcp6)?;
        udp_echo(&fcx, &udp4)?;
        udp_echo(&fcx, &udp6)?;
        let checks = std::thread::spawn(move || {
            client(&l);
            let _ = done_tx.send(());
        });
        // Wait for the client thread without blocking the run.
        let mut dumped = false;
        loop {
            match done_rx.try_recv() {
                Ok(()) => break,
                Err(mpsc::TryRecvError::Empty) => {
                    fcx.sleep(Duration::from_millis(50)).await?;
                    let quiet = LAST
                        .lock()
                        .unwrap()
                        .is_some_and(|t| t.elapsed() > Duration::from_secs(5));
                    if quiet && !dumped {
                        dumped = true;
                        eprintln!("STALL: no packets for 5 s. The last ones:");
                        for l in RING.lock().unwrap().iter() {
                            eprintln!("{l}");
                        }
                    }
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    let e = checks.join().unwrap_err();
                    let msg = e
                        .downcast_ref::<String>()
                        .cloned()
                        .or(e.downcast_ref::<&str>().map(|s| s.to_string()));
                    return Err(fictionet::Error::msg(format!(
                        "the client checks failed: {msg:?}"
                    )));
                }
            }
        }
        Err(fictionet::Error::from(Done))
    }));
    match result {
        Err(e) if e.downcast_ref::<Done>().is_some() => {}
        Err(e) => panic!("{e}"),
        Ok(()) => panic!("the world should end with Done"),
    }
}
