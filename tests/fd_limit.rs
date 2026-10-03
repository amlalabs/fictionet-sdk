//! `listen` when the process runs out of file descriptors. In its own test
//! binary, because it lowers the process's descriptor limit.

use std::os::fd::{AsRawFd, OwnedFd};
use std::time::Duration;

use fictionet::relay::{self, Hello, Message, unix};
use fictionet::{WorldSocket, attachments, listen};

/// The `stat` files of the threads whose name starts with `prefix`, opened
/// now, so they can be read when no descriptors are left.
fn thread_stats(prefix: &str) -> Vec<std::fs::File> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir("/proc/self/task").unwrap() {
        let dir = entry.unwrap().path();
        let comm = std::fs::read_to_string(dir.join("comm")).unwrap_or_default();
        if comm.trim_end().starts_with(prefix) {
            files.push(std::fs::File::open(dir.join("stat")).unwrap());
        }
    }
    files
}

/// CPU time the threads have used so far, in clock ticks.
fn ticks(stats: &[std::fs::File]) -> u64 {
    use std::os::unix::fs::FileExt;
    let mut total = 0;
    for file in stats {
        let mut buf = [0u8; 1024];
        let n = file.read_at(&mut buf, 0).unwrap();
        let stat = std::str::from_utf8(&buf[..n]).unwrap();
        // Fields after the ")" that ends the name: state is field 3, utime
        // and stime are fields 14 and 15.
        let rest = &stat[stat.rfind(')').unwrap() + 2..];
        let fields: Vec<&str> = rest.split(' ').collect();
        total += fields[11].parse::<u64>().unwrap() + fields[12].parse::<u64>().unwrap();
    }
    total
}

/// When `accept` fails for lack of descriptors, the helper thread does not
/// spin on the listening socket. It accepts again once descriptors are free.
#[test]
fn running_out_of_descriptors_does_not_spin_the_helper() {
    let path = format!("{}/fictionet-test-{}-fdlimit.sock", std::env::temp_dir().display(), std::process::id());
    let (attacher, _attachments) = attachments();
    let _listening = listen(WorldSocket::UnixSocket(path.clone().into()), attacher).unwrap();
    // A new thread sets its own name, so it may not have one yet.
    let mut stats = thread_stats("fictionet-liste");
    for _ in 0..100 {
        if !stats.is_empty() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
        stats = thread_stats("fictionet-liste");
    }
    assert_eq!(stats.len(), 1);

    // Use up every descriptor, keeping one back for the client.
    let mut limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) };
    let low = libc::rlimit { rlim_cur: 256.min(limit.rlim_max), rlim_max: limit.rlim_max };
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &low) }, 0);
    let null = std::fs::File::open("/dev/null").unwrap();
    let mut filler: Vec<OwnedFd> = Vec::new();
    while let Ok(fd) = null.try_clone() {
        filler.push(fd.into());
    }
    filler.pop();
    let client = unix::connect(&path).unwrap();
    // The table is full: the world cannot accept the connection.

    std::thread::sleep(Duration::from_millis(100));
    let before = ticks(&stats);
    std::thread::sleep(Duration::from_millis(1000));
    let used = ticks(&stats) - before;

    drop(filler);
    unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) };
    // Clock ticks are usually 10 ms: a spinning thread uses about 100.
    assert!(used < 20, "the helper thread used {used} ticks in a second while it could not accept");

    // With descriptors free again, the waiting client is accepted.
    let tv = libc::timeval { tv_sec: 5, tv_usec: 0 };
    unsafe {
        libc::setsockopt(
            client.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&raw const tv).cast(),
            std::mem::size_of::<libc::timeval>() as u32,
        )
    };
    let hello = Message::Hello(Hello { version: relay::VERSION, mtu: 1500, kind: "tun".into(), name: "late".into() });
    unix::send(client.as_raw_fd(), &hello.encode(), false).unwrap();
    let mut buf = vec![0u8; 16];
    let n = unix::recv(client.as_raw_fd(), &mut buf, false).expect("no answer after descriptors were freed");
    assert_eq!(&buf[..n], &[relay::ACCEPT]);
}
