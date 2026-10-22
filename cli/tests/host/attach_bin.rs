//! The `fictionet attach` binary with a tun device, against a real `listen`
//! in this process.
//!
//! These run attach under `unshare -rnm` (a new user, network and mount
//! namespace), so they need no root, but they fail where user namespaces
//! are not allowed. The Docker test in `tests/docker/ping` covers the same
//! ground with real containers.

use fictionet_test_support::{logged, poll, temp};

use std::process::{Command, Stdio};
use std::time::Duration;

use fictionet::stdlib::network::ip::checksum;
use fictionet::{Interface, InterfaceExt, Packet};

const BIN: &str = env!("CARGO_BIN_EXE_fictionet");

fn userns_works() -> bool {
    Command::new("unshare")
        .args(["-rnm", "true"])
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Starts attach in new namespaces, with `--resolv-conf` naming a private
/// resolv.conf. A bind mount over /etc/resolv.conf would not do: where the
/// host's /etc/resolv.conf is a symlink, as with systemd-resolved, the mount
/// lands on its target, and attach does not write through the symlink.
fn spawn_attach(
    dir: &std::path::Path,
    sock: &str,
    name: &str,
    resolv: &str,
) -> std::process::Child {
    let resolv = dir.join(resolv);
    std::fs::write(&resolv, "nameserver 192.0.2.1\n").unwrap();
    let script = format!(
        "exec {BIN} attach tun --world unix:{sock} --name {name} --resolv-conf {resolv} \
         --ip-addr 10.0.0.2/24 --gateway 10.0.0.1 --dns 10.0.0.1 \
          --mtu 1400",
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
        0x45,
        0,
        0,
        28 + 8,
        0,
        0,
        0,
        0,
        64,
        1,
        0,
        0,
        10,
        0,
        0,
        1,
        10,
        0,
        0,
        2, // IPv4
        8,
        0,
        0,
        0,
        0x12,
        0x34,
        (seq >> 8) as u8,
        seq as u8, // ICMP echo request
        b'f',
        b'i',
        b'c',
        b't',
        b'i',
        b'o',
        b'n',
        b'!',
    ];
    let sum = checksum(&p[..20]);
    p[10..12].copy_from_slice(&sum.to_be_bytes());
    let sum = checksum(&p[20..]);
    p[22..24].copy_from_slice(&sum.to_be_bytes());
    p
}

#[test]
fn packets_cross_both_ways_and_refuse_and_world_close_end_attach() {
    assert!(userns_works(), "unshare -rnm is not allowed here");
    let dir = temp::dir();
    let sock = dir.join("w.sock").to_str().unwrap().to_owned();
    let (attacher, mut attachments) = fictionet::attachments();
    let listening = fictionet::listen(
        fictionet::WorldSocket::UnixSocket(sock.clone().into()),
        attacher,
    )
    .unwrap();

    let mut first = spawn_attach(&dir, &sock, "abc", "resolv-first");

    // The world: take abc, ping the sandbox, check the sandbox's kernel
    // answers, then let a second attach under the same name be refused,
    // then close.
    let sock2 = sock.clone();
    let dir2 = dir.clone();
    let slot = std::sync::Arc::new(std::sync::Mutex::new(None));
    let out = slot.clone();
    let result = fictionet::block_on(fictionet::run(
        fictionet::Seed::random(),
        move |fcx| async move {
            let mut abc = fcx
                .race(
                    Some(fcx.now() + Duration::from_secs(10)),
                    attachments.get(&fcx, "abc"),
                )
                .await
                .map_err(|err| match err {
                    fictionet::RaceError::Deadline => fictionet::Error::msg("abc never attached"),
                    fictionet::RaceError::Cancelled => err.into(),
                })??;
            let mtu = abc.mtu();
            // Attach configures the device before its world handshake.
            abc.send(Packet(echo_request(0)));
            let reply = fcx
                .race(Some(fcx.now() + Duration::from_secs(5)), async {
                    loop {
                        let Packet(p) = abc.recv(&fcx).await?;
                        if p.len() >= 28 && p[9] == 1 && p[20] == 0 {
                            break Ok::<_, fictionet::RecvError>(p);
                        }
                    }
                })
                .await??;

            // A second attach under the same name is refused. Waiting for it
            // blocks this thread, which is fine: the listen helper thread
            // does the handshake.
            let second = spawn_attach(&dir2, &sock2, "abc", "resolv-second").wait_with_output()?;
            drop(abc);
            *out.lock().unwrap() = Some((mtu, reply, second));
            Ok(())
        },
    ));
    if let Err(err) = result {
        first
            .kill()
            .unwrap_or_else(|kill_err| panic!("world failed: {err}; killing attach: {kill_err}"));
        let out = first.wait_with_output().unwrap_or_else(|output_err| {
            panic!("world failed: {err}; collecting attach output: {output_err}")
        });
        panic!(
            "world failed: {err}\nattach stderr:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let (mtu, reply, second) = slot.lock().unwrap().take().unwrap();
    drop(listening);

    assert_eq!(mtu, 1400);
    assert_eq!(
        &reply[12..16],
        &[10, 0, 0, 2],
        "the reply comes from the sandbox"
    );
    assert_eq!(&reply[28..], b"fiction!");
    assert_eq!(
        second.status.code(),
        Some(3),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );
    assert!(
        String::from_utf8_lossy(&second.stderr)
            .contains("the world refused: abc is already attached")
    );

    // The world closed the attachment: attach exits 0.
    let (exited, exit) = std::sync::mpsc::channel();
    let child = std::thread::spawn(move || exited.send(first.wait_with_output().unwrap()).unwrap());
    let out = exit
        .recv_timeout(Duration::from_secs(10))
        .expect("attach did not exit after the world closed");
    child.join().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{err}");
    assert!(err.contains("the world closed the connection"), "{err}");
    assert_eq!(
        std::fs::read_to_string(dir.join("resolv-first")).unwrap(),
        "# Written by attach.\nnameserver 10.0.0.1\n"
    );
    // The refused attach never touched its resolv.conf.
    assert_eq!(
        std::fs::read_to_string(dir.join("resolv-second")).unwrap(),
        "nameserver 192.0.2.1\n"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// `--resolv-conf <path>` writes the DNS servers there, making the
/// directory. A write that fails ends attach with status 1 and a message
/// that names the path and the ways out.
#[test]
fn resolv_conf_flag_picks_the_file_and_a_failed_write_names_it() {
    assert!(userns_works(), "unshare -rnm is not allowed here");
    let dir = temp::dir();
    let sock = dir.join("w.sock").to_str().unwrap().to_owned();
    let (attacher, mut attachments) = fictionet::attachments();
    let listening = fictionet::listen(
        fictionet::WorldSocket::UnixSocket(sock.clone().into()),
        attacher,
    )
    .unwrap();
    let attach = |name: &str, path: &str| {
        let script = format!(
            "exec {BIN} attach tun --world unix:{sock} --name {name} \
             --ip-addr 10.0.0.2/24 --gateway 10.0.0.1 --dns 10.0.0.1 \
              --resolv-conf {path}"
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
    fictionet::block_on(fictionet::run(
        fictionet::Seed::random(),
        move |fcx| async move {
            let abc = attachments.get(&fcx, "good").await?;
            poll::until(Duration::from_secs(5), "sandbox resolver file", || {
                written.exists()
            });
            drop(abc);
            Ok(())
        },
    ))
    .unwrap();
    let out = good.wait_with_output().unwrap();
    drop(listening);

    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(&custom).unwrap(),
        "# Written by attach.\nnameserver 10.0.0.1\n"
    );
    let err = String::from_utf8_lossy(&failed.stderr);
    assert_eq!(failed.status.code(), Some(1), "{err}");
    assert!(
        err.contains(bad) && err.contains("--no-resolv-conf"),
        "{err}"
    );
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
                        --no-resolv-conf";

/// A world that takes the attachment `name`, keeps it until the file
/// `done` exists, then closes it. Fails if `done` does not appear within 10 s.
fn hold_until(attachments: fictionet::Attachments, name: &'static str, done: std::path::PathBuf) {
    let mut attachments = attachments;
    fictionet::block_on(fictionet::run(
        fictionet::Seed::random(),
        move |fcx| async move {
            let held = attachments.get(&fcx, name).await?;
            poll::until(Duration::from_secs(10), "sandbox completion file", || {
                done.exists()
            });
            drop(held);
            Ok(())
        },
    ))
    .unwrap();
}

/// A pod's `eth0` (a dummy link here) has addresses and default routes,
/// IPv4 and IPv6. Attach alone fails to add its default route, and says
/// to use `--down-link`. With `--down-link eth0`, eth0 is down with no
/// address and no route, in any table, and tun0 has both default routes.
#[test]
fn down_link_clears_a_pods_eth0_before_tun0_takes_the_default_route() {
    assert!(userns_works(), "unshare -rnm is not allowed here");
    let dir = temp::dir();
    let sock = dir.join("w.sock").to_str().unwrap().to_owned();
    let (attacher, attachments) = fictionet::attachments();
    let listening = fictionet::listen(
        fictionet::WorldSocket::UnixSocket(sock.clone().into()),
        attacher,
    )
    .unwrap();
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
        {BIN} attach tun --world unix:{sock} --name abc {V4_ONLY} 2> {d}/plain.err
        echo $? > {d}/plain.status
        {BIN} attach tun --world unix:{sock} --name abc \
            --ip-addr 10.0.0.2/24 --gateway 10.0.0.1 --dns 10.0.0.1 \
            --ip-addr-v6 fd00::2/64 --gateway-v6 fd00::1 --no-resolv-conf \
            --down-link eth0 --ready-file {d}/ready &
        attach=$!
        i=0
        while [ ! -e {d}/ready ] && [ $i -lt 100 ]; do sleep 0.1; i=$((i + 1)); done
        [ -e {d}/ready ] || {{ echo 'ready file never appeared' >&2; exit 1; }}
        {{ ip -o link show eth0; echo \"end $?\"; }} > {d}/link
        {{ ip -o addr show dev eth0; echo \"end $?\"; }} > {d}/addrs
        {{ ip route show table all; echo \"end IPv4 $?\"; }} > {d}/routes
        {{ ip -6 route show table all; echo \"end IPv6 $?\"; }} >> {d}/routes
        touch {d}/done
        wait $attach
        echo $? > {d}/attach.status"
    );
    let child = unshare("-rn", &script);
    hold_until(attachments, "abc", dir.join("done"));
    let out = child.wait_with_output().unwrap();
    drop(listening);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "shell exited with {}: {err}",
        out.status
    );
    let read = |f: &str| {
        std::fs::read_to_string(dir.join(f)).unwrap_or_else(|e| panic!("reading {f}: {e}\n{err}"))
    };

    assert_eq!(read("plain.status").trim(), "1", "{}", read("plain.err"));
    assert!(
        read("plain.err").contains("another link already has one"),
        "{}",
        read("plain.err")
    );
    assert!(
        read("plain.err").contains("--down-link eth0"),
        "{}",
        read("plain.err")
    );

    assert_eq!(read("attach.status").trim(), "0", "{err}");
    assert!(
        err.contains("eth0 is down, with no routes or addresses"),
        "{err}"
    );
    let link = read("link");
    assert!(link.ends_with("end 0\n"), "{link}\n{err}");
    assert!(link.contains("state DOWN"), "{link}");
    assert!(!link.contains(",UP") && !link.contains("<UP"), "{link}");
    assert_eq!(read("addrs"), "end 0\n", "eth0 keeps no address\n{err}");
    let routes = read("routes");
    assert!(
        routes.lines().any(|line| line == "end IPv4 0"),
        "{routes}\n{err}"
    );
    assert!(routes.ends_with("end IPv6 0\n"), "{routes}\n{err}");
    assert!(!routes.contains("dev eth0"), "{routes}");
    assert!(routes.contains("default via 10.0.0.1 dev tun0"), "{routes}");
    assert!(routes.contains("default via fd00::1 dev tun0"), "{routes}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// `--down-link` names a link that is not there: attach stops before it
/// makes anything.
#[test]
fn down_link_with_no_such_link_fails() {
    assert!(userns_works(), "unshare -rnm is not allowed here");
    let script =
        format!("exec {BIN} attach tun --world unix:/nowhere --name a {V4_ONLY} --down-link eth9");
    let out = unshare("-rn", &script).wait_with_output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(err.contains("--down-link eth9: no such link"), "{err}");
}

/// `--world-wait` waits for a world that starts later. Without a world,
/// it gives up when the wait is over and says how long it waited.
#[test]
fn world_wait_waits_for_a_late_world() {
    assert!(userns_works(), "unshare -rnm is not allowed here");
    let dir = temp::dir();
    let sock = dir.join("w.sock").to_str().unwrap().to_owned();
    let mut late = unshare(
        "-rn",
        &format!("exec {BIN} attach tun --world unix:{sock} --name late {V4_ONLY} --world-wait 20"),
    );
    let started = std::time::Instant::now();
    let never = unshare(
        "-rn",
        &format!(
            "exec {BIN} attach tun --world unix:{}/none.sock --name n {V4_ONLY} --world-wait 1",
            dir.display()
        ),
    );
    let log = logged(
        late.stderr.take().unwrap(),
        "waiting up to 20 s for the world",
    );
    let (attacher, attachments) = fictionet::attachments();
    let listening = fictionet::listen(
        fictionet::WorldSocket::UnixSocket(sock.clone().into()),
        attacher,
    )
    .unwrap();
    std::fs::write(dir.join("done"), "").unwrap();
    hold_until(attachments, "late", dir.join("done"));
    let out = late.wait_with_output().unwrap();
    drop(listening);
    let err = log.join().unwrap();
    assert_eq!(out.status.code(), Some(0), "{err}");
    assert!(err.contains("waiting up to 20 s for the world"), "{err}");
    assert!(err.contains("late attached as tun0"), "{err}");

    let out = never.wait_with_output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(
        err.contains("No such file or directory (os error 2), after waiting 1 s"),
        "{err}"
    );
    assert!(started.elapsed() >= Duration::from_secs(1));
    let _ = std::fs::remove_dir_all(&dir);
}

/// With no `/dev/net/tun`, attach tries to make it. In a user namespace
/// `mknod` is not allowed, so the error says what was missing and how to
/// fix it.
#[test]
fn a_missing_tun_node_that_cannot_be_made_says_why() {
    assert!(userns_works(), "unshare -rnm is not allowed here");
    let script = format!(
        "mount -t tmpfs tmpfs /dev/net && exec {BIN} attach tun --world unix:/nowhere --name a {V4_ONLY}"
    );
    let out = unshare("-rnm", &script).wait_with_output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(
        err.contains(
            "/dev/net/tun is missing, and attach could not make it: Operation not permitted"
        ),
        "{err}"
    );
    assert!(err.contains("CAP_MKNOD"), "{err}");
}
