//! The `fictionet attach` binary against a real `listen` in this process.
//!
//! Tests that need a tun device run attach under `unshare -rnm` (a new user,
//! network and mount namespace), so they need no root. Where user namespaces
//! are not allowed, they print a note and pass. The Docker test in
//! `tests/docker/ping` covers the same ground with real containers.

use std::process::{Command, Stdio};
use std::time::Duration;

use fictionet::stdlib::ip::checksum;
use fictionet::{Interface, Packet, RecvError};

const BIN: &str = env!("CARGO_BIN_EXE_fictionet");

fn temp_dir() -> std::path::PathBuf {
    // Unix socket paths must be short, so not under a long target dir.
    let n: u64 = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() as u64;
    let dir = std::env::temp_dir().join(format!("fn-attach-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn left_out_flags_exit_2_and_say_dhcp_is_missing() {
    let out = Command::new(BIN).args(["attach", "--world", "unix:/nowhere", "--name", "a", "--type", "tun"]).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("DHCP is not implemented yet"), "{err}");
}

#[test]
fn no_subcommand_is_a_usage_error() {
    let out = Command::new(BIN).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("usage: fictionet attach"));
}

#[test]
fn attach_help_goes_to_stdout_and_exits_0() {
    for flag in ["--help", "-h"] {
        let out = Command::new(BIN).args(["attach", flag]).output().unwrap();
        assert_eq!(out.status.code(), Some(0), "{flag}");
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(text.contains("usage: fictionet attach"), "{text}");
        assert!(text.contains("--resolv-conf"), "{text}");
        assert!(out.stderr.is_empty(), "{}", String::from_utf8_lossy(&out.stderr));
    }
}

#[test]
fn a_flag_after_a_value_flag_is_a_usage_error() {
    let out = Command::new(BIN)
        .args(["attach", "--world", "unix:/nowhere", "--name", "a", "--type", "tun", "--resolv-conf", "--no-resolv-conf"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("--resolv-conf needs a value"), "{err}");
}

fn userns_works() -> bool {
    Command::new("unshare")
        .args(["-rnm", "true"])
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Starts attach in new namespaces, with a private resolv.conf bound over
/// /etc/resolv.conf.
fn spawn_attach(dir: &std::path::Path, sock: &str, name: &str, resolv: &str) -> std::process::Child {
    let resolv = dir.join(resolv);
    std::fs::write(&resolv, "nameserver 192.0.2.1\n").unwrap();
    let script = format!(
        "mount --bind {resolv} /etc/resolv.conf && exec {BIN} attach --world unix:{sock} --name {name} --type tun \
         --ip-addr 10.0.0.2/24 --gateway 10.0.0.1 --dns 10.0.0.1 \
         --no-ip-addr-v6 --no-gateway-v6 --no-dns-v6 --mtu 1400",
        resolv = resolv.display()
    );
    Command::new("unshare")
        .args(["-rnm", "sh", "-c", &script])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

/// An ICMPv4 echo request from 10.0.0.1 to 10.0.0.2.
fn echo_request(seq: u16) -> Vec<u8> {
    let mut p = vec![
        0x45, 0, 0, 28 + 8, 0, 0, 0, 0, 64, 1, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2, // IPv4
        8, 0, 0, 0, 0x12, 0x34, (seq >> 8) as u8, seq as u8, // ICMP echo request
        b'f', b'i', b'c', b't', b'i', b'o', b'n', b'!',
    ];
    let sum = checksum(&p[..20]);
    p[10..12].copy_from_slice(&sum.to_be_bytes());
    let sum = checksum(&p[20..]);
    p[22..24].copy_from_slice(&sum.to_be_bytes());
    p
}

#[test]
fn packets_cross_both_ways_and_refuse_and_world_close_end_attach() {
    if !userns_works() {
        eprintln!("skipped: unshare -rnm is not allowed here");
        return;
    }
    let dir = temp_dir();
    let sock = dir.join("w.sock").to_str().unwrap().to_owned();
    let (attacher, mut attachments) = fictionet::attachments();
    let listening = fictionet::listen(fictionet::WorldSocket::UnixSocket(sock.clone().into()), attacher).unwrap();

    let mut first = spawn_attach(&dir, &sock, "abc", "resolv-first");

    // The world: take abc, ping the sandbox, check the sandbox's kernel
    // answers, then let a second attach under the same name be refused,
    // then close.
    let sock2 = sock.clone();
    let dir2 = dir.clone();
    let slot = std::sync::Arc::new(std::sync::Mutex::new(None));
    let out = slot.clone();
    fictionet::block_on(fictionet::run(move |fcx| async move {
            let mut abc = attachments.get(&fcx, "abc").await?;
            let mtu = abc.mtu();
            // Send echo requests until one is answered: the device may come up
            // a moment after accept is sent.
            let mut reply = None;
            for seq in 0..50u16 {
                abc.send(Packet(echo_request(seq)));
                fcx.sleep(fictionet::time::ms(100)).await?;
                // Drain what came back.
                loop {
                    let next = futures_poll_once(&fcx, &mut abc);
                    match next {
                        Some(Ok(Packet(p))) if p.len() >= 28 && p[9] == 1 && p[20] == 0 => reply = Some(p),
                        Some(Ok(_)) => continue,
                        Some(Err(RecvError::Closed)) => return Err(fictionet::Error::msg("attach closed")),
                        Some(Err(RecvError::Cancelled)) => return Err(fictionet::Error::msg("cancelled")),
                        None => break,
                    }
                }
                if reply.is_some() {
                    break;
                }
            }
            let reply = reply.ok_or_else(|| fictionet::Error::msg("the sandbox never answered the echo request"))?;

            // A second attach under the same name is refused. Waiting for it
            // blocks this thread, which is fine: the listen helper thread
            // does the handshake.
            let second = spawn_attach(&dir2, &sock2, "abc", "resolv-second").wait_with_output()?;
            drop(abc);
            *out.lock().unwrap() = Some((mtu, reply, second));
            Ok(())
        }))
    .unwrap();
    let (mtu, reply, second) = slot.lock().unwrap().take().unwrap();
    drop(listening);

    assert_eq!(mtu, 1400);
    assert_eq!(&reply[12..16], &[10, 0, 0, 2], "the reply comes from the sandbox");
    assert_eq!(&reply[28..], b"fiction!");
    assert_eq!(second.status.code(), Some(3), "{}", String::from_utf8_lossy(&second.stderr));
    assert!(String::from_utf8_lossy(&second.stderr).contains("the world refused: abc is already attached"));

    // The world closed the attachment: attach exits 0.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(s) = first.try_wait().unwrap() {
            break s;
        }
        assert!(std::time::Instant::now() < deadline, "attach did not exit after the world closed");
        std::thread::sleep(Duration::from_millis(50));
    };
    let out = first.wait_with_output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(status.code(), Some(0), "{err}");
    assert!(err.contains("the world closed the connection"), "{err}");
    assert_eq!(std::fs::read_to_string(dir.join("resolv-first")).unwrap(), "# Written by attach.\nnameserver 10.0.0.1\n");
    // The refused attach never touched its resolv.conf.
    assert_eq!(std::fs::read_to_string(dir.join("resolv-second")).unwrap(), "nameserver 192.0.2.1\n");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Polls `recv` once: `None` if nothing is waiting.
fn futures_poll_once(fcx: &fictionet::Cx, i: &mut fictionet::Attachment) -> Option<Result<Packet, RecvError>> {
    let waker = std::task::Waker::noop();
    let mut cx = std::task::Context::from_waker(waker);
    match i.poll_recv(fcx, &mut cx) {
        std::task::Poll::Ready(r) => Some(r),
        std::task::Poll::Pending => None,
    }
}

/// `--resolv-conf <path>` writes the DNS servers there, making the
/// directory. A write that fails ends attach with status 1 and a message
/// that names the path and the ways out.
#[test]
fn resolv_conf_flag_picks_the_file_and_a_failed_write_names_it() {
    if !userns_works() {
        eprintln!("skipped: unshare -rnm is not allowed here");
        return;
    }
    let dir = temp_dir();
    let sock = dir.join("w.sock").to_str().unwrap().to_owned();
    let (attacher, mut attachments) = fictionet::attachments();
    let listening = fictionet::listen(fictionet::WorldSocket::UnixSocket(sock.clone().into()), attacher).unwrap();
    let attach = |name: &str, path: &str| {
        let script = format!(
            "exec {BIN} attach --world unix:{sock} --name {name} --type tun \
             --ip-addr 10.0.0.2/24 --gateway 10.0.0.1 --dns 10.0.0.1 \
             --no-ip-addr-v6 --no-gateway-v6 --no-dns-v6 --resolv-conf {path}"
        );
        Command::new("unshare")
            .args(["-rnm", "sh", "-c", &script])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    };
    let custom = dir.join("dns/resolv.conf");
    let bad = "/proc/fictionet-no-such-dir/resolv.conf";
    let good = attach("good", custom.to_str().unwrap());
    let failed = attach("bad", bad).wait_with_output().unwrap();

    let written = custom.clone();
    fictionet::block_on(fictionet::run(move |fcx| async move {
        let abc = attachments.get(&fcx, "good").await?;
        for _ in 0..100 {
            if written.exists() {
                break;
            }
            fcx.sleep(fictionet::time::ms(50)).await?;
        }
        drop(abc);
        Ok(())
    }))
    .unwrap();
    let out = good.wait_with_output().unwrap();
    drop(listening);

    assert_eq!(out.status.code(), Some(0), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(std::fs::read_to_string(&custom).unwrap(), "# Written by attach.\nnameserver 10.0.0.1\n");
    let err = String::from_utf8_lossy(&failed.stderr);
    assert_eq!(failed.status.code(), Some(1), "{err}");
    assert!(err.contains(bad) && err.contains("--no-resolv-conf"), "{err}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Runs `script` under `unshare -rn` (or `-rnm`), with its output piped.
fn unshare(flags: &str, script: &str) -> std::process::Child {
    Command::new("unshare")
        .args([flags, "sh", "-c", script])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

const V4_ONLY: &str = "--ip-addr 10.0.0.2/24 --gateway 10.0.0.1 --dns 10.0.0.1 \
                       --no-ip-addr-v6 --no-gateway-v6 --no-dns-v6 --no-resolv-conf";

/// A world that takes the attachment `name`, keeps it until the file
/// `done` exists (10 s at most), then closes it.
fn hold_until(attachments: fictionet::Attachments, name: &'static str, done: std::path::PathBuf) {
    let mut attachments = attachments;
    fictionet::block_on(fictionet::run(move |fcx| async move {
        let held = attachments.get(&fcx, name).await?;
        for _ in 0..200 {
            if done.exists() {
                break;
            }
            fcx.sleep(fictionet::time::ms(50)).await?;
        }
        drop(held);
        Ok(())
    }))
    .unwrap();
}

/// A pod's `eth0` (a dummy link here) has addresses and default routes,
/// IPv4 and IPv6. Attach alone fails to add its default route, and says
/// to use `--down-link`. With `--down-link eth0`, eth0 is down with no
/// address and no route, in any table, and tun0 has both default routes.
#[test]
fn down_link_clears_a_pods_eth0_before_tun0_takes_the_default_route() {
    if !userns_works() {
        eprintln!("skipped: unshare -rnm is not allowed here");
        return;
    }
    let dir = temp_dir();
    let sock = dir.join("w.sock").to_str().unwrap().to_owned();
    let (attacher, attachments) = fictionet::attachments();
    let listening = fictionet::listen(fictionet::WorldSocket::UnixSocket(sock.clone().into()), attacher).unwrap();
    let d = dir.display();
    let script = format!(
        "set -e
        ip link add eth0 type dummy
        ip link set eth0 up
        ip addr add 192.0.2.5/24 dev eth0
        ip -6 addr add 2001:db8::5/64 dev eth0 nodad
        ip route add default via 192.0.2.1 dev eth0
        ip -6 route add default via 2001:db8::1 dev eth0
        set +e
        {BIN} attach --world unix:{sock} --name abc --type tun {V4_ONLY} 2> {d}/plain.err
        echo $? > {d}/plain.status
        {BIN} attach --world unix:{sock} --name abc --type tun \
            --ip-addr 10.0.0.2/24 --gateway 10.0.0.1 --dns 10.0.0.1 \
            --ip-addr-v6 fd00::2/64 --gateway-v6 fd00::1 --no-dns-v6 --no-resolv-conf \
            --down-link eth0 --ready-file {d}/ready &
        attach=$!
        i=0
        while [ ! -e {d}/ready ] && [ $i -lt 100 ]; do sleep 0.1; i=$((i + 1)); done
        ip -o link show eth0 > {d}/link
        ip -o addr show dev eth0 > {d}/addrs
        ip route show table all > {d}/routes
        ip -6 route show table all >> {d}/routes
        touch {d}/done
        wait $attach
        echo $? > {d}/attach.status"
    );
    let child = unshare("-rn", &script);
    hold_until(attachments, "abc", dir.join("done"));
    let out = child.wait_with_output().unwrap();
    drop(listening);
    let read = |f: &str| std::fs::read_to_string(dir.join(f)).unwrap_or_default();
    let err = String::from_utf8_lossy(&out.stderr);

    assert_eq!(read("plain.status").trim(), "1", "{}", read("plain.err"));
    assert!(read("plain.err").contains("another link already has one"), "{}", read("plain.err"));
    assert!(read("plain.err").contains("--down-link eth0"), "{}", read("plain.err"));

    assert_eq!(read("attach.status").trim(), "0", "{err}");
    assert!(err.contains("eth0 is down, with no routes or addresses"), "{err}");
    let link = read("link");
    assert!(link.contains("state DOWN"), "{link}");
    assert!(!link.contains(",UP") && !link.contains("<UP"), "{link}");
    assert_eq!(read("addrs"), "", "eth0 keeps no address");
    let routes = read("routes");
    assert!(!routes.contains("dev eth0"), "{routes}");
    assert!(routes.contains("default via 10.0.0.1 dev tun0"), "{routes}");
    assert!(routes.contains("default via fd00::1 dev tun0"), "{routes}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// `--down-link` names a link that is not there: attach stops before it
/// makes anything.
#[test]
fn down_link_with_no_such_link_fails() {
    if !userns_works() {
        eprintln!("skipped: unshare -rnm is not allowed here");
        return;
    }
    let script = format!("exec {BIN} attach --world unix:/nowhere --name a --type tun {V4_ONLY} --down-link eth9");
    let out = unshare("-rn", &script).wait_with_output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(err.contains("--down-link eth9: no such link"), "{err}");
}

/// `--world-wait` waits for a world that starts later. Without a world,
/// it gives up when the wait is over and says how long it waited.
#[test]
fn world_wait_waits_for_a_late_world() {
    if !userns_works() {
        eprintln!("skipped: unshare -rnm is not allowed here");
        return;
    }
    let dir = temp_dir();
    let sock = dir.join("w.sock").to_str().unwrap().to_owned();
    let late = unshare("-rn", &format!("exec {BIN} attach --world unix:{sock} --name late --type tun {V4_ONLY} --world-wait 20"));
    let started = std::time::Instant::now();
    let never = unshare(
        "-rn",
        &format!("exec {BIN} attach --world unix:{}/none.sock --name n --type tun {V4_ONLY} --world-wait 1", dir.display()),
    );
    std::thread::sleep(Duration::from_millis(1500));
    let (attacher, attachments) = fictionet::attachments();
    let listening = fictionet::listen(fictionet::WorldSocket::UnixSocket(sock.clone().into()), attacher).unwrap();
    std::fs::write(dir.join("done"), "").unwrap();
    hold_until(attachments, "late", dir.join("done"));
    let out = late.wait_with_output().unwrap();
    drop(listening);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{err}");
    assert!(err.contains("waiting up to 20 s for the world"), "{err}");
    assert!(err.contains("late attached as tun0"), "{err}");

    let out = never.wait_with_output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(err.contains("No such file or directory (os error 2), after waiting 1 s"), "{err}");
    assert!(started.elapsed() >= Duration::from_secs(1));
    let _ = std::fs::remove_dir_all(&dir);
}

/// With no `/dev/net/tun`, attach tries to make it. In a user namespace
/// `mknod` is not allowed, so the error says what was missing and how to
/// fix it.
#[test]
fn a_missing_tun_node_that_cannot_be_made_says_why() {
    if !userns_works() {
        eprintln!("skipped: unshare -rnm is not allowed here");
        return;
    }
    let script = format!("mount -t tmpfs tmpfs /dev/net && exec {BIN} attach --world unix:/nowhere --name a --type tun {V4_ONLY}");
    let out = unshare("-rnm", &script).wait_with_output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(err.contains("/dev/net/tun is missing, and attach could not make it: Operation not permitted"), "{err}");
    assert!(err.contains("CAP_MKNOD"), "{err}");
}

#[test]
fn ready_exits_0_only_when_the_file_exists() {
    let dir = temp_dir();
    let file = dir.join("ready");
    let run = |args: &[&str]| Command::new(BIN).arg("ready").args(args).output().unwrap();
    let out = run(&[file.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("does not exist"));
    std::fs::write(&file, "abc\n").unwrap();
    assert_eq!(run(&[file.to_str().unwrap()]).status.code(), Some(0));
    assert_eq!(run(&[]).status.code(), Some(2));
    assert_eq!(run(&["a", "b"]).status.code(), Some(2));
    // Help goes to stdout and exits 0, as every other subcommand's does.
    let help = run(&["--help"]);
    assert_eq!(help.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&help.stdout).contains("usage: fictionet ready"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn wait_blocked_waits_while_an_address_answers_and_exits_0_once_it_stops() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let open = listener.local_addr().unwrap().to_string();
    // A port with nothing listening: refused, which counts as blocked.
    let closed = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().to_string()
    };
    let run = |args: &[&str]| Command::new(BIN).arg("wait-blocked").args(args).output().unwrap();

    let out = run(&[&closed]);
    assert_eq!(out.status.code(), Some(0), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stderr).contains("unreachable 3 times in a row"));

    // One address still answers: no exit 0, however many others fail.
    let out = run(&["--timeout", "1", &closed, &open]);
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains(&format!("after 1 s, {open} still reachable")), "{err}");

    // It exits 0 soon after the address stops answering.
    let mut child = Command::new(BIN).args(["wait-blocked", "--timeout", "20", &open]).stderr(Stdio::piped()).spawn().unwrap();
    std::thread::sleep(Duration::from_millis(1500));
    assert!(child.try_wait().unwrap().is_none(), "exited while the address still answered");
    drop(listener);
    let started = std::time::Instant::now();
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(String::from_utf8_lossy(&out.stderr).contains("still reachable; waiting"));

    assert_eq!(run(&[]).status.code(), Some(2));
    assert_eq!(run(&["example.com:443"]).status.code(), Some(2));
}
