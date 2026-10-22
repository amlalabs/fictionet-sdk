//! `listen` when the process runs out of file descriptors. Each test runs
//! in a process of its own, because it lowers the process's descriptor limit.

use crate::common::threads;
use fictionet_test_support::poll;

use std::os::fd::{AsRawFd, OwnedFd};
use std::time::Duration;

use fictionet::relay::{self, Hello, Message, unix};
use fictionet::{WorldSocket, attachments, listen};

static LIMIT_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// When `accept` fails for lack of descriptors, the helper thread does not
/// spin on the listening socket. It accepts again once descriptors are free.
#[test]
fn running_out_of_descriptors_does_not_spin_the_helper() {
    if crate::common::ran_in_own_process(
        "fd_limit::running_out_of_descriptors_does_not_spin_the_helper",
    ) {
        return;
    }
    let _lock = LIMIT_LOCK.lock().unwrap();
    let path = format!(
        "{}/fictionet-test-{}-fdlimit.sock",
        std::env::temp_dir().display(),
        std::process::id()
    );
    let (attacher, _attachments) = attachments();
    let _listening = listen(WorldSocket::UnixSocket(path.clone().into()), attacher).unwrap();
    // A new thread sets its own name, so it may not have one yet.
    let mut stats = threads::stats(&["fictionet-liste"]);
    poll::until(Duration::from_secs(10), "listener thread name", || {
        stats = threads::stats(&["fictionet-liste"]);
        !stats.is_empty()
    });
    assert_eq!(stats.len(), 1);

    // Use up every descriptor, keeping one back for the client.
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) };
    let low = libc::rlimit {
        rlim_cur: 256.min(limit.rlim_max),
        rlim_max: limit.rlim_max,
    };
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &low) }, 0);
    let null = std::fs::File::open("/dev/null").unwrap();
    let mut filler: Vec<OwnedFd> = Vec::new();
    while let Ok(fd) = null.try_clone() {
        filler.push(fd.into());
    }
    filler.pop();
    let client = unix::connect(&path).unwrap();
    // The table is full: the world cannot accept the connection.

    let before = threads::ticks(&stats)[0].1;
    std::thread::sleep(Duration::from_millis(1000));
    let used = threads::ticks(&stats)[0].1 - before;

    drop(filler);
    unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) };
    // Clock ticks are usually 10 ms: a spinning thread uses about 100.
    assert!(
        used < 20,
        "the helper thread used {used} ticks in a second while it could not accept"
    );

    // With descriptors free again, the waiting client is accepted.
    let _ = unix::set_timeout(
        client.as_raw_fd(),
        libc::SO_RCVTIMEO,
        Some(Duration::from_secs(5)),
    );
    let hello = Message::Hello(Hello {
        version: relay::VERSION,
        mtu: 1500,
        kind: "tun".into(),
        name: "late".into(),
    });
    unix::send(client.as_raw_fd(), &hello.encode(), false).unwrap();
    let mut buf = vec![0u8; 16];
    let n = unix::recv(client.as_raw_fd(), &mut buf, false)
        .expect("no answer after descriptors were freed");
    assert_eq!(&buf[..n], &[relay::ACCEPT]);
}

#[test]
fn reconnects_reclaim_pending_sockets_without_world_polling() {
    use fictionet::{Interface, InterfaceExt, Packet, Seed, block_on, run};
    use std::sync::mpsc;

    if crate::common::ran_in_own_process(
        "fd_limit::reconnects_reclaim_pending_sockets_without_world_polling",
    ) {
        return;
    }
    let _lock = LIMIT_LOCK.lock().unwrap();
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    assert_eq!(
        unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) },
        0
    );
    let low = libc::rlimit {
        rlim_cur: 64.min(limit.rlim_cur),
        rlim_max: limit.rlim_max,
    };
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &low) }, 0);
    struct RestoreLimit(libc::rlimit);
    impl Drop for RestoreLimit {
        fn drop(&mut self) {
            assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &self.0) }, 0);
        }
    }
    let _restore = RestoreLimit(limit);

    {
        let path = format!(
            "{}/fictionet-test-{}-churn.sock",
            std::env::temp_dir().display(),
            std::process::id()
        );
        let (attacher, attachments) = attachments();
        let _listening = listen(WorldSocket::UnixSocket(path.clone().into()), attacher).unwrap();
        let (ready_tx, ready_rx) = mpsc::channel();
        let (mut go, mut wait) = fictionet::pair();
        let world = std::thread::spawn(move || {
            block_on(run(Seed::from_u64(0), move |fcx| async move {
                let mut attachments = attachments;
                for _ in 0..128 {
                    drop(attachments.get(&fcx, "barrier").await?);
                    ready_tx.send(()).unwrap();
                    // Keep the stream alive without polling it during detach.
                    wait.recv(&fcx).await?;
                }
                Ok(())
            }))
        });
        let connect = |name: &str| {
            let fd = unix::connect(&path).unwrap();
            unix::set_timeout(
                fd.as_raw_fd(),
                libc::SO_RCVTIMEO,
                Some(Duration::from_secs(5)),
            )
            .unwrap();
            let hello = Message::Hello(Hello {
                version: relay::VERSION,
                mtu: 1500,
                kind: "tun".into(),
                name: name.into(),
            });
            unix::send(fd.as_raw_fd(), &hello.encode(), false).unwrap();
            let mut buf = [0u8; 256];
            let n = unix::recv(fd.as_raw_fd(), &mut buf, false).unwrap();
            assert_eq!(&buf[..n], &[relay::ACCEPT]);
            fd
        };
        for _ in 0..128 {
            let agent = connect("agent");
            let barrier = connect("barrier");
            ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            drop(barrier);
            // Leave a received packet behind, then half-close. Closing the
            // unread socket can report either EOF or a connection reset.
            unix::send(agent.as_raw_fd(), &Message::Packet(&[42]).encode(), false).unwrap();
            assert_eq!(
                unsafe { libc::shutdown(agent.as_raw_fd(), libc::SHUT_WR) },
                0
            );
            let mut buf = [0u8; 1];
            match unix::recv(agent.as_raw_fd(), &mut buf, false) {
                Ok(0) => {}
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
                other => panic!("pending socket was not reclaimed: {other:?}"),
            }
            drop(agent);
            go.send(Packet(vec![]));
        }
        world.join().unwrap().unwrap();
    }
}
