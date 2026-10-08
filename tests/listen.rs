//! `listen` end to end, with a test client that speaks the relay protocol
//! over a real Unix SOCK_SEQPACKET socket.

#[path = "common/poll.rs"]
mod poll;

use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use fictionet::prelude::*;
use fictionet::relay::{self, Hello, Message, unix};
use fictionet::{Interface, Packet, RecvError, WorldSocket, attachments, block_on, listen, run};

fn socket_path(tag: &str) -> String {
    static N: AtomicU32 = AtomicU32::new(0);
    let n = N.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir();
    format!("{}/fictionet-test-{}-{tag}-{n}.sock", dir.display(), std::process::id())
}

/// A test client: the attach side of the protocol.
struct Client {
    fd: OwnedFd,
}

impl Client {
    fn connect(path: &str) -> Client {
        let fd = unix::connect(path).expect("connect");
        let client = Client { fd };
        // Never hang a test: reads give up after 15 s.
        client.set_timeout(Duration::from_secs(15));
        client
    }

    fn set_timeout(&self, d: Duration) {
        let _ = unix::set_timeout(self.fd.as_raw_fd(), libc::SO_RCVTIMEO, Some(d));
    }

    /// The next message, or `None` if none comes within the timeout.
    fn try_recv(&self) -> Option<Vec<u8>> {
        let mut buf = vec![0u8; relay::MAX_MESSAGE + 1];
        match unix::recv(self.fd.as_raw_fd(), &mut buf, false) {
            Ok(n) if n > 0 => Some(buf[..n].to_vec()),
            _ => None,
        }
    }

    fn send(&self, message: &Message) {
        unix::send(self.fd.as_raw_fd(), &message.encode(), false).expect("send");
    }

    fn hello(&self, name: &str, mtu: u16) {
        self.send(&Message::Hello(Hello { version: relay::VERSION, mtu, kind: "tun".into(), name: name.into() }));
    }

    /// The next message, or `None` when the world closed the connection.
    fn recv(&self) -> Option<Vec<u8>> {
        let mut buf = vec![0u8; relay::MAX_MESSAGE + 1];
        let n = unix::recv(self.fd.as_raw_fd(), &mut buf, false).expect("recv");
        if n == 0 { None } else { Some(buf[..n].to_vec()) }
    }

    fn attach(path: &str, name: &str) -> Client {
        let client = Client::connect(path);
        client.hello(name, 1500);
        assert_eq!(client.recv().as_deref(), Some(&[relay::ACCEPT][..]));
        client
    }
}

#[test]
fn attach_echo_and_detach() {
    let path = socket_path("echo");
    let (attacher, mut attachments) = attachments();
    let listening = listen(WorldSocket::UnixSocket(path.clone().into()), attacher).unwrap();

    let (done_tx, done_rx) = mpsc::channel();
    let echoed = std::sync::Arc::new(AtomicU32::new(0));
    let count = echoed.clone();
    std::thread::spawn(move || {
        let out = block_on(run(move |fcx| async move {
            let mut abc = attachments.get(&fcx, "abc").await?;
            assert_eq!(abc.name(), "abc");
            assert_eq!(abc.mtu(), 9000);
            // Echo every packet back with its bytes reversed, until detach.
            loop {
                match abc.recv(&fcx).await {
                    Ok(Packet(mut bytes)) => {
                        bytes.reverse();
                        abc.send(Packet(bytes));
                        count.fetch_add(1, Ordering::SeqCst);
                    }
                    Err(RecvError::Closed) => return Ok(()),
                    Err(e) => return Err(e.into()),
                }
            }
        }));
        done_tx.send(out.map_err(|e| e.to_string())).unwrap();
    });

    let client = Client::connect(&path);
    client.hello("abc", 9000);
    assert_eq!(client.recv(), Some(vec![relay::ACCEPT]));

    client.send(&Message::Packet(&[1, 2, 3]));
    assert_eq!(client.recv(), Some(vec![relay::PACKET, 3, 2, 1]));

    // Bursts of more than one turn's worth all come back in order. A burst
    // stays small enough for the socket buffers: when they are full, the
    // world drops packets instead of waiting.
    for burst in 0..5u32 {
        for i in burst * 100..(burst + 1) * 100 {
            client.send(&Message::Packet(&i.to_be_bytes()));
        }
        for i in burst * 100..(burst + 1) * 100 {
            let mut want = i.to_be_bytes().to_vec();
            want.reverse();
            want.insert(0, relay::PACKET);
            assert_eq!(client.recv(), Some(want));
        }
    }

    // When attach does not read, packets that find the connection full wait
    // in a queue in the world, and all come through, in order, once attach
    // reads again. The world never blocks. 20,000 packets of 1,400 bytes
    // are far more than the 4 MiB socket buffers hold.
    let payload = |i: u32, len: usize| {
        let mut p = vec![0u8; len];
        p[..4].copy_from_slice(&i.to_be_bytes());
        p
    };
    let index = |mut m: Vec<u8>| {
        assert_eq!(m.remove(0), relay::PACKET);
        m.reverse();
        u32::from_be_bytes(m[..4].try_into().unwrap())
    };
    for i in 0..20_000u32 {
        client.send(&Message::Packet(&payload(i, 1400)));
    }
    poll::until(Duration::from_secs(15), || echoed.load(Ordering::SeqCst) == 20_501);
    client.set_timeout(Duration::from_millis(500));
    let mut got = 0;
    while let Some(m) = client.try_recv() {
        assert_eq!(m.len(), 1401);
        assert_eq!(index(m), got);
        got += 1;
    }
    assert_eq!(got, 20_000);

    // The queue is bounded: past 32 MiB, packets are dropped. 1,000
    // packets of 60,000 bytes do not all fit. Those that arrive are whole
    // and in order.
    for i in 0..1_000u32 {
        client.send(&Message::Packet(&payload(i, 60_000)));
    }
    poll::until(Duration::from_secs(15), || echoed.load(Ordering::SeqCst) == 21_501);
    let mut last = None;
    let mut got = 0;
    while let Some(m) = client.try_recv() {
        assert_eq!(m.len(), 60_001);
        let i = index(m);
        assert!(last.is_none_or(|l| i > l));
        last = Some(i);
        got += 1;
    }
    assert!(got > 500 && got < 1_000, "{got}");
    client.set_timeout(Duration::from_secs(15));
    // With room again, packets flow.
    client.send(&Message::Packet(&[1, 2]));
    assert_eq!(client.recv(), Some(vec![relay::PACKET, 2, 1]));

    // A large packet survives whole.
    let big: Vec<u8> = (0..60_000u32).map(|i| i as u8).collect();
    client.send(&Message::Packet(&big));
    let mut back = client.recv().unwrap();
    assert_eq!(back.remove(0), relay::PACKET);
    back.reverse();
    assert_eq!(back, big);

    // Closing is the detach: the world reads Closed and returns.
    drop(client);
    let out = done_rx.recv_timeout(Duration::from_secs(5)).expect("world did not end");
    assert_eq!(out, Ok(()));
    drop(listening);
    assert!(!std::path::Path::new(&path).exists());
}

#[test]
fn refuses_taken_and_bad_names_and_frees_names_on_close() {
    let path = socket_path("names");
    let (attacher, _attachments) = attachments();
    let _listening = listen(WorldSocket::UnixSocket(path.clone().into()), attacher.clone()).unwrap();

    let first = Client::attach(&path, "abc");

    let second = Client::connect(&path);
    second.hello("abc", 1500);
    let refuse = second.recv().unwrap();
    assert_eq!(relay::decode(&refuse), Ok(Message::Refuse("abc is already attached".into())));
    assert_eq!(second.recv(), None, "the world closes after refuse");

    // The name set is shared with the attacher.
    assert_eq!(attacher.attach("abc").unwrap_err(), fictionet::AttachError::Taken);
    let _test_end = attacher.attach("by-test").unwrap();
    let third = Client::connect(&path);
    third.hello("by-test", 1500);
    assert!(matches!(relay::decode(&third.recv().unwrap()), Ok(Message::Refuse(_))));

    let empty = Client::connect(&path);
    empty.hello("", 1500);
    assert_eq!(
        relay::decode(&empty.recv().unwrap()),
        Ok(Message::Refuse("name must be 1 to 255 bytes".into()))
    );

    let old = Client::connect(&path);
    old.send(&Message::Hello(Hello { version: 2, mtu: 1500, kind: "tun".into(), name: "v2".into() }));
    assert!(matches!(relay::decode(&old.recv().unwrap()), Ok(Message::Refuse(_))));

    // Something other than hello first closes the connection.
    let rude = Client::connect(&path);
    rude.send(&Message::Packet(&[1]));
    assert_eq!(rude.recv(), None);

    // When attach closes, the name is free again, even though the world
    // never took the attachment.
    drop(first);
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let again = Client::connect(&path);
        again.hello("abc", 1500);
        match relay::decode(&again.recv().unwrap()) {
            Ok(Message::Accept) => break,
            _ if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(5)),
            other => panic!("name was not freed: {other:?}"),
        }
    }
}

#[test]
fn the_world_closing_detaches_attach() {
    let path = socket_path("worldclose");
    let (attacher, mut attachments) = attachments();
    let _listening = listen(WorldSocket::UnixSocket(path.clone().into()), attacher).unwrap();
    let client = Client::attach(&path, "abc");

    let out = block_on(run(move |fcx| async move {
        let mut abc = attachments.get(&fcx, "abc").await?;
        abc.send(Packet(vec![42]));
        drop(abc);
        Ok(())
    }));
    out.unwrap();
    assert_eq!(client.recv(), Some(vec![relay::PACKET, 42]));
    assert_eq!(client.recv(), None);
    // And the name is free.
    let _again = Client::attach(&path, "abc");
}

#[test]
fn an_unknown_kind_closes_the_connection() {
    let path = socket_path("unknown");
    let (attacher, mut attachments) = attachments();
    let _listening = listen(WorldSocket::UnixSocket(path.clone().into()), attacher).unwrap();
    let client = Client::attach(&path, "abc");
    client.send(&Message::Packet(&[1]));
    unix::send(client.fd.as_raw_fd(), &[9, 9], false).unwrap();
    let out = block_on(run(move |fcx| async move {
        let mut abc = attachments.get(&fcx, "abc").await?;
        assert_eq!(abc.recv(&fcx).await, Ok(Packet(vec![1])));
        assert_eq!(abc.recv(&fcx).await, Err(RecvError::Closed));
        Ok(())
    }));
    out.unwrap();
    assert_eq!(client.recv(), None);
}

#[test]
fn handshake_times_out() {
    let path = socket_path("timeout");
    let (attacher, _attachments) = attachments();
    let _listening = listen(WorldSocket::UnixSocket(path.clone().into()), attacher).unwrap();
    let start = Instant::now();
    let silent = Client::connect(&path);
    silent.set_timeout(Duration::from_secs(25));
    assert_eq!(silent.recv(), None);
    let took = start.elapsed();
    assert!(took >= Duration::from_millis(9_900) && took < Duration::from_secs(20), "{took:?}");
}

#[test]
fn dropping_listening_closes_the_socket_but_keeps_attachments() {
    let path = socket_path("drop");
    let (attacher, mut attachments) = attachments();
    let listening = listen(WorldSocket::UnixSocket(path.clone().into()), attacher).unwrap();
    let client = Client::attach(&path, "abc");
    drop(listening);
    assert!(unix::connect(&path).is_err());

    // The attachment still carries packets both ways, and idle wakeups
    // still come from the helper thread.
    let (tx, rx) = mpsc::channel::<()>();
    let world = std::thread::spawn(move || {
        block_on(run(move |fcx| async move {
            let mut abc = attachments.get(&fcx, "abc").await?;
            tx.send(()).unwrap();
            let p = abc.recv(&fcx).await?;
            abc.send(p);
            Ok(())
        }))
    });
    rx.recv_timeout(Duration::from_secs(5)).unwrap();
    client.send(&Message::Packet(&[5]));
    assert_eq!(client.recv(), Some(vec![relay::PACKET, 5]));
    world.join().unwrap().unwrap();
}

#[test]
fn a_stale_socket_file_is_replaced_and_a_live_one_is_not() {
    let path = socket_path("stale");
    let (attacher, _attachments) = attachments();
    let listening = listen(WorldSocket::UnixSocket(path.clone().into()), attacher.clone()).unwrap();
    // A live world owns the path.
    assert!(listen(WorldSocket::UnixSocket(path.clone().into()), attacher.clone()).is_err());
    // A socket file whose world is gone: leave one behind by hand.
    std::mem::forget(listening);
    let stale_path = socket_path("stale2");
    {
        let fd = unix_bind(&stale_path);
        drop(fd);
    }
    assert!(std::path::Path::new(&stale_path).exists());
    let _l = listen(WorldSocket::UnixSocket(stale_path.clone().into()), attacher).unwrap();
    let _c = Client::attach(&stale_path, "x");
}

fn unix_bind(path: &str) -> std::os::unix::net::UnixListener {
    std::os::unix::net::UnixListener::bind(path).unwrap()
}

/// Many idle attachments, each woken by the helper thread.
#[test]
fn many_idle_attachments_wake() {
    let path = socket_path("many");
    let (attacher, mut attachments) = attachments();
    let _listening = listen(WorldSocket::UnixSocket(path.clone().into()), attacher).unwrap();
    let clients: Vec<Client> = (0..20).map(|i| Client::attach(&path, &format!("s{i}"))).collect();
    let (ready_tx, ready_rx) = mpsc::channel::<()>();
    let world = std::thread::spawn(move || {
        block_on(run(move |fcx| async move {
            for _ in 0..20 {
                let mut a = attachments.next(&fcx).await.unwrap();
                fcx.spawn(move |fcx| async move {
                    let p = a.recv(&fcx).await?;
                    a.send(p);
                    Ok(())
                });
            }
            ready_tx.send(()).unwrap();
            Ok(())
        }))
    });
    ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    for (i, c) in clients.iter().enumerate().rev() {
        c.send(&Message::Packet(&[i as u8]));
    }
    for (i, c) in clients.iter().enumerate() {
        assert_eq!(c.recv(), Some(vec![relay::PACKET, i as u8]));
    }
    world.join().unwrap().unwrap();
}

/// The largest IP packet, 65,535 bytes, crosses whole in both directions
/// with an MTU of 65,535.
#[test]
fn the_largest_packet_crosses_both_ways() {
    let path = socket_path("maxmtu");
    let (attacher, mut attachments) = attachments();
    let _listening = listen(WorldSocket::UnixSocket(path.clone().into()), attacher).unwrap();
    let world = std::thread::spawn(move || {
        block_on(run(move |fcx| async move {
            let mut a = attachments.get(&fcx, "big").await?;
            assert_eq!(a.mtu(), 65_535);
            let p = a.recv(&fcx).await?;
            assert_eq!(p.0.len(), 65_535);
            a.send(p);
            // And one the world makes itself.
            a.send(Packet(vec![7u8; 65_535]));
            Ok(())
        }))
    });
    let client = Client::connect(&path);
    client.hello("big", 65_535);
    assert_eq!(client.recv(), Some(vec![relay::ACCEPT]));
    let big: Vec<u8> = (0..65_535u32).map(|i| (i * 7) as u8).collect();
    client.send(&Message::Packet(&big));
    let mut back = client.recv().unwrap();
    assert_eq!(back.remove(0), relay::PACKET);
    assert_eq!(back, big);
    let mut back = client.recv().unwrap();
    assert_eq!(back.remove(0), relay::PACKET);
    assert_eq!(back, vec![7u8; 65_535]);
    world.join().unwrap().unwrap();
}

/// A message longer than the protocol allows closes the connection. The
/// world never sees it cut short as a packet.
#[test]
fn an_oversized_message_closes_the_connection() {
    let path = socket_path("oversize");
    let (attacher, mut attachments) = attachments();
    let _listening = listen(WorldSocket::UnixSocket(path.clone().into()), attacher).unwrap();
    let world = std::thread::spawn(move || {
        block_on(run(move |fcx| async move {
            let mut a = attachments.get(&fcx, "o").await?;
            let first = a.recv(&fcx).await?;
            assert_eq!(first, Packet(vec![1]));
            match a.recv(&fcx).await {
                Err(RecvError::Closed) => Ok(()),
                Ok(p) => Err(fictionet::Error::msg(format!("got a packet of {} bytes", p.0.len()))),
                Err(e) => Err(e.into()),
            }
        }))
    });
    let client = Client::attach(&path, "o");
    client.send(&Message::Packet(&[1]));
    // One kind byte and 65,536 bytes: one more than the protocol allows.
    let too_long = vec![0u8; relay::MAX_MESSAGE + 1];
    unix::send_parts(client.fd.as_raw_fd(), &[&[relay::PACKET], &too_long], false).unwrap();
    world.join().unwrap().map_err(|e| e.to_string()).unwrap();
    assert_eq!(client.recv(), None);
}

/// A sandbox that detaches and attaches again before the world asks for it
/// reaches the world as the new attachment, not the closed one.
#[test]
fn reattaching_before_the_world_asks_gives_the_new_connection() {
    let path = socket_path("reattach");
    let (attacher, mut attachments) = attachments();
    let _listening = listen(WorldSocket::UnixSocket(path.clone().into()), attacher).unwrap();
    drop(Client::attach(&path, "abc"));
    let deadline = Instant::now() + Duration::from_secs(5);
    let client = loop {
        let c = Client::connect(&path);
        c.hello("abc", 1500);
        if c.recv() == Some(vec![relay::ACCEPT]) {
            break c;
        }
        assert!(Instant::now() < deadline, "the name was never freed");
        std::thread::sleep(Duration::from_millis(5));
    };
    client.send(&Message::Packet(&[5]));
    let out = block_on(run(move |fcx| async move {
        let mut a = attachments.get(&fcx, "abc").await?;
        assert_eq!(a.recv(&fcx).await?, Packet(vec![5]));
        Ok(())
    }));
    out.unwrap();
}

/// The world sends a burst far past the connection's buffer and then waits
/// for the test to finish, never reading from the attachment. The queue is
/// still written out, in order, as attach reads.
#[test]
fn a_world_that_only_sends_gets_its_queue_written_out() {
    let path = socket_path("sendonly");
    let (attacher, mut attachments) = attachments();
    let _listening = listen(WorldSocket::UnixSocket(path.clone().into()), attacher).unwrap();
    let (stop, mut stopped) = fictionet::pair();
    let world = std::thread::spawn(move || {
        block_on(run(move |fcx| async move {
            let mut abc = attachments.get(&fcx, "abc").await?;
            for i in 0..10_000u32 {
                let mut p = vec![0u8; 1400];
                p[..4].copy_from_slice(&i.to_be_bytes());
                abc.send(Packet(p));
            }
            assert_eq!(stopped.recv(&fcx).await, Err(RecvError::Closed));
            drop(abc);
            Ok(())
        }))
    });
    let client = Client::attach(&path, "abc");
    client.set_timeout(Duration::from_secs(15));
    let mut got = 0u32;
    while got < 10_000 {
        let m = client.recv().expect("the world closed before the burst arrived");
        assert_eq!(m[0], relay::PACKET);
        assert_eq!(u32::from_be_bytes(m[1..5].try_into().unwrap()), got, "in order");
        got += 1;
    }
    assert_eq!(got, 10_000, "only {got} of 10,000 packets arrived before the world closed");
    drop(stop);
    world.join().unwrap().unwrap();
    assert_eq!(client.recv(), None);
}

/// `Attachments::map` keeps a socket attachment's name and MTU, and skips
/// one whose sandbox detached after the map task passed it on but before
/// the world took it. The skipped one is never wrapped.
#[test]
fn mapped_socket_attachments_keep_their_mtu_and_skip_detached_ones() {
    let path = socket_path("map");
    let (attacher, attachments) = attachments();
    let _listening = listen(WorldSocket::UnixSocket(path.clone().into()), attacher).unwrap();
    let (wrapped_tx, wrapped_rx) = mpsc::channel();
    let (go_tx, go_rx) = mpsc::channel::<()>();
    let (queued_tx, queued_rx) = mpsc::channel();
    let world = std::thread::spawn(move || {
        block_on(run(move |fcx| async move {
            let mut mapped = attachments.map(&fcx, move |fcx, sandbox| {
                let _ = wrapped_tx.send(sandbox.mtu());
                fictionet::stdlib::filter(fcx, sandbox, |_, _, _| true)
            });
            let barrier = mapped.get(&fcx, "barrier").await?;
            queued_tx.send(()).unwrap();
            drop(barrier);
            // Wait for the test thread without blocking the run's thread,
            // so the map task can pass sandboxes on meanwhile.
            while go_rx.try_recv().is_err() {
                fcx.sleep(fictionet::time::ms(5)).await?;
            }
            let mut a = mapped.get(&fcx, "agent").await?;
            assert_eq!(a.mtu(), 1400);
            assert_eq!(a.recv(&fcx).await?, Packet(vec![6]));
            Ok(())
        }))
    });
    let first = Client::attach(&path, "agent");
    // The map task passes the first sandbox on while it is attached. Only
    // then does it detach.
    let barrier = Client::attach(&path, "barrier");
    queued_rx.recv_timeout(Duration::from_secs(10)).expect("the map did not pass the barrier");
    drop(barrier);
    drop(first);
    let deadline = Instant::now() + Duration::from_secs(5);
    let client = loop {
        let c = Client::connect(&path);
        c.hello("agent", 1400);
        if c.recv() == Some(vec![relay::ACCEPT]) {
            break c;
        }
        assert!(Instant::now() < deadline, "the name was never freed");
        std::thread::sleep(Duration::from_millis(5));
    };
    client.send(&Message::Packet(&[6]));
    go_tx.send(()).unwrap();
    world.join().unwrap().map_err(|e| e.to_string()).unwrap();
    // Only the barrier and the sandbox the world took were wrapped.
    assert_eq!(wrapped_rx.try_iter().collect::<Vec<_>>(), [1500, 1400]);
}
