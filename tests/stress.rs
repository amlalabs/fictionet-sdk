//! Many attachments and many packets through `listen`, with real sockets.
//! In its own test binary, because it measures the CPU time of Fictionet's
//! threads.

use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use fictionet::prelude::*;
use fictionet::relay::{self, Hello, Message, unix};
use fictionet::{Interface, RecvError, attachments, block_on, listen, pair, run};

/// The `stat` files of the threads whose name starts with one of `prefixes`.
fn thread_stats(prefixes: &[&str]) -> Vec<(String, std::fs::File)> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir("/proc/self/task").unwrap() {
        let dir = entry.unwrap().path();
        let comm = std::fs::read_to_string(dir.join("comm")).unwrap_or_default();
        let comm = comm.trim_end().to_owned();
        if prefixes.iter().any(|p| comm.starts_with(p)) {
            files.push((comm, std::fs::File::open(dir.join("stat")).unwrap()));
        }
    }
    files
}

/// CPU time each thread has used so far, in clock ticks.
fn ticks(stats: &[(String, std::fs::File)]) -> Vec<(String, u64)> {
    use std::os::unix::fs::FileExt;
    stats
        .iter()
        .map(|(name, file)| {
            let mut buf = [0u8; 1024];
            let n = file.read_at(&mut buf, 0).unwrap();
            let stat = std::str::from_utf8(&buf[..n]).unwrap();
            let rest = &stat[stat.rfind(')').unwrap() + 2..];
            let fields: Vec<&str> = rest.split(' ').collect();
            (name.clone(), fields[11].parse::<u64>().unwrap() + fields[12].parse::<u64>().unwrap())
        })
        .collect()
}

fn connect(path: &str, name: &str) -> OwnedFd {
    let fd = unix::connect(path).unwrap();
    let tv = libc::timeval { tv_sec: 15, tv_usec: 0 };
    unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&raw const tv).cast(),
            std::mem::size_of::<libc::timeval>() as u32,
        )
    };
    let hello = Message::Hello(Hello { version: relay::VERSION, mtu: 1500, kind: "tun".into(), name: name.into() });
    unix::send(fd.as_raw_fd(), &hello.encode(), false).unwrap();
    let mut buf = [0u8; 64];
    let n = unix::recv(fd.as_raw_fd(), &mut buf, false).unwrap();
    assert_eq!(&buf[..n], &[relay::ACCEPT], "{name} was not accepted");
    fd
}

/// Packet `seq` of client `id`: its id, its number, then filler of a size
/// that changes from packet to packet.
fn packet(id: u32, seq: u32) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&id.to_be_bytes());
    p.extend_from_slice(&seq.to_be_bytes());
    let len = (seq as usize * 37 + id as usize * 11) % 1400;
    p.extend((0..len).map(|i| (i as u32 ^ seq ^ id) as u8));
    p
}

const CLIENTS: u32 = 32;
const PACKETS: u32 = 3000;
/// Packets each client keeps in flight: well under what the socket buffers
/// hold, so no packet may be lost.
const WINDOW: u32 = 48;

#[test]
fn many_attachments_lose_nothing_and_idle_costs_nothing() {
    let path = format!("{}/fictionet-test-{}-stress.sock", std::env::temp_dir().display(), std::process::id());
    let (attacher, mut attachments) = attachments();
    let listening = listen(fictionet::WorldSocket::UnixSocket(path.clone().into()), attacher).unwrap();
    let (stop, mut stopped) = pair();
    let (ready_tx, ready_rx) = mpsc::channel();
    let world = std::thread::Builder::new()
        .name("world".into())
        .spawn(move || {
            block_on(run(move |cx| async move {
                // A long timer stays pending the whole time.
                cx.spawn(|cx| async move {
                    cx.sleep(Duration::from_secs(3600)).await?;
                    Ok(())
                });
                for _ in 0..CLIENTS {
                    let mut a = attachments.next(&cx).await?;
                    cx.spawn(move |cx| async move {
                        loop {
                            match a.recv(&cx).await {
                                Ok(p) => a.send(p),
                                Err(RecvError::Closed) => return Ok(()),
                                Err(e) => return Err(e.into()),
                            }
                        }
                    });
                }
                ready_tx.send(()).unwrap();
                // Wait for the test to say stop, then fail the region to
                // cancel the timer.
                let _ = stopped.recv(&cx).await;
                Err(fictionet::Error::msg("stop"))
            }))
            .map_err(|e| e.to_string())
        })
        .unwrap();

    let fds: Vec<OwnedFd> = (0..CLIENTS).map(|i| connect(&path, &format!("s{i}"))).collect();
    ready_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    // A new thread sets its own name, so it may not have one yet.
    let mut stats = thread_stats(&["world", "fictionet-"]);
    for _ in 0..100 {
        if stats.len() >= 3 {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
        stats = thread_stats(&["world", "fictionet-"]);
    }
    assert!(stats.len() >= 3, "{:?}", stats.iter().map(|s| &s.0).collect::<Vec<_>>());

    let started = Instant::now();
    let before = ticks(&stats);
    let clients: Vec<_> = fds
        .into_iter()
        .enumerate()
        .map(|(id, fd)| {
            let id = id as u32;
            std::thread::spawn(move || {
                let raw = fd.as_raw_fd();
                let mut buf = vec![0u8; relay::MAX_MESSAGE + 1];
                let mut sent = 0;
                for got in 0..PACKETS {
                    while sent < PACKETS && sent < got + WINDOW {
                        unix::send_parts(raw, &[&[relay::PACKET], &packet(id, sent)], false).unwrap();
                        sent += 1;
                    }
                    let n = unix::recv(raw, &mut buf, false)
                        .unwrap_or_else(|e| panic!("client {id} waiting for packet {got}: {e}"));
                    assert_eq!(buf[0], relay::PACKET);
                    assert_eq!(&buf[1..n], &packet(id, got)[..], "client {id} packet {got}");
                }
                fd
            })
        })
        .collect();
    let fds: Vec<OwnedFd> = clients.into_iter().map(|c| c.join().unwrap()).collect();
    let busy = ticks(&stats);
    eprintln!(
        "{} packets each way in {:?}; CPU ticks: {:?}",
        CLIENTS * PACKETS,
        started.elapsed(),
        busy.iter().zip(&before).map(|((n, b), (_, a))| (n, b - a)).collect::<Vec<_>>()
    );

    // Everyone attached and idle, with a timer pending: no thread of
    // Fictionet may use the CPU.
    std::thread::sleep(Duration::from_millis(100));
    let idle_start = ticks(&stats);
    std::thread::sleep(Duration::from_millis(1500));
    let idle_end = ticks(&stats);
    for ((name, a), (_, b)) in idle_start.iter().zip(&idle_end) {
        assert!(b - a <= 2, "{name} used {} ticks in 1.5 s while idle", b - a);
    }

    // The attachments still work after the idle time.
    for (id, fd) in fds.iter().enumerate() {
        unix::send_parts(fd.as_raw_fd(), &[&[relay::PACKET], &packet(id as u32, 9)], false).unwrap();
        let mut buf = vec![0u8; 2048];
        let n = unix::recv(fd.as_raw_fd(), &mut buf, false).unwrap();
        assert_eq!(&buf[1..n], &packet(id as u32, 9)[..]);
    }

    drop(fds);
    drop(stop);
    assert_eq!(world.join().unwrap(), Err("stop".to_owned()));
    drop(listening);
}
