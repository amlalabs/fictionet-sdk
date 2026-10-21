//! `fictionet attach --type tap --vm qemu:<path>` against a real `listen`
//! in this process, with the test playing QEMU: it connects to attach's
//! socket and speaks QEMU's stream framing (a 32-bit big-endian length,
//! then an Ethernet frame). No VM, KVM or privileges are needed.
//! cargo xtask vm does the same with a real VM.

use std::io::{Read, Write};
use std::net::Ipv4Addr;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::time::Duration;

use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::network::ip::checksum;
use fictionet::stdlib::protocols::dhcp;
use fictionet::{Interface, InterfaceExt, Packet, RecvError};
use fictionet_test_support::{poll, temp, within};

const BIN: &str = env!("CARGO_BIN_EXE_fictionet");
const VM: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
const GATEWAY: [u8; 6] = [0x74, 0x83, 0xc2, 0x9a, 0x47, 0xd1];

fn ipv4(src: [u8; 4], dst: [u8; 4], proto: u8, payload: &[u8]) -> Vec<u8> {
    let mut p = vec![0x45, 0];
    p.extend_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
    p.extend_from_slice(&[0, 0, 0, 0, 64, proto, 0, 0]);
    p.extend_from_slice(&src);
    p.extend_from_slice(&dst);
    let c = checksum(&p);
    p[10..12].copy_from_slice(&c.to_be_bytes());
    p.extend_from_slice(payload);
    p
}

/// A UDP datagram with no checksum, which IPv4 allows.
fn udp4(src: [u8; 4], sport: u16, dst: [u8; 4], dport: u16, data: &[u8]) -> Vec<u8> {
    let mut u = Vec::new();
    u.extend_from_slice(&sport.to_be_bytes());
    u.extend_from_slice(&dport.to_be_bytes());
    u.extend_from_slice(&((8 + data.len()) as u16).to_be_bytes());
    u.extend_from_slice(&[0, 0]);
    u.extend_from_slice(data);
    ipv4(src, dst, 17, &u)
}

fn echo_request(src: [u8; 4]) -> Vec<u8> {
    let mut icmp = vec![8, 0, 0, 0, 0, 1, 0, 1];
    icmp.extend_from_slice(b"fiction!");
    let c = checksum(&icmp);
    icmp[2..4].copy_from_slice(&c.to_be_bytes());
    ipv4(src, [10, 0, 0, 1], 1, &icmp)
}

/// The world's answer: any IPv4 packet to the VM.
fn from_world() -> Vec<u8> {
    ipv4([10, 0, 0, 1], [10, 0, 0, 2], 253, b"from the world")
}

fn frame(dst: [u8; 6], ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&dst);
    f.extend_from_slice(&VM);
    f.extend_from_slice(&ethertype.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

fn send(qemu: &mut UnixStream, frame: &[u8]) {
    qemu.write_all(&(frame.len() as u32).to_be_bytes()).unwrap();
    qemu.write_all(frame).unwrap();
}

fn recv(qemu: &mut UnixStream) -> Vec<u8> {
    let mut len = [0u8; 4];
    qemu.read_exact(&mut len).unwrap();
    let mut f = vec![0u8; u32::from_be_bytes(len) as usize];
    qemu.read_exact(&mut f).unwrap();
    f
}

/// Attach answers DHCP, ARP and nothing else itself; the VM's ping reaches
/// the world and the world's answer reaches the VM, with Ethernet headers;
/// a spoofed source never reaches the world; and when QEMU closes the
/// socket, attach exits 0 and the world sees the detach.
#[test]
fn a_fake_qemu_gets_dhcp_arp_and_the_world() {
    let dir = temp::dir();
    let world = dir.join("w.sock").to_str().unwrap().to_owned();
    let vm_sock = dir.join("vm.sock");
    let ready = dir.join("ready");
    let (attacher, mut attachments) = fictionet::attachments();
    let listening = fictionet::listen(
        fictionet::WorldSocket::UnixSocket(world.clone().into()),
        attacher,
    )
    .unwrap();

    let attach = Command::new(BIN)
        .args([
            "attach",
            "--world",
            &format!("unix:{world}"),
            "--name",
            "vm1",
            "--type",
            "tap",
        ])
        .arg(format!("--vm=qemu:{}", vm_sock.display()))
        .args([
            "--ip-addr",
            "10.0.0.2/24",
            "--gateway",
            "10.0.0.1",
            "--dns",
            "10.0.0.1",
            "--no-ip-addr-v6",
        ])
        .arg(format!("--ready-file={}", ready.display()))
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let qemu_side = std::thread::spawn(move || {
        poll::until(Duration::from_secs(5), "QEMU socket readiness file", || {
            ready.exists()
        });
        let mode = std::fs::metadata(&vm_sock).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "only attach's user may connect");
        let mut qemu = UnixStream::connect(&vm_sock).unwrap();
        qemu.set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();

        // DHCP: discover, then the offer from attach, broadcast.
        let mut m = dhcp::Message::new(dhcp::BOOTREQUEST, 42);
        m.chaddr[..6].copy_from_slice(&VM);
        m.push(dhcp::opt::MESSAGE_TYPE, [dhcp::DISCOVER]);
        send(
            &mut qemu,
            &frame(
                [0xff; 6],
                0x0800,
                &udp4([0; 4], 68, [255; 4], 67, &m.to_bytes().unwrap()),
            ),
        );
        let offer = recv(&mut qemu);
        assert_eq!(&offer[0..12], &[[0xff; 6], GATEWAY].concat()[..]);
        let ip = &offer[14..];
        let reply = dhcp::Message::parse(&ip[28..]).unwrap();
        assert_eq!(reply.message_type(), Some(dhcp::OFFER));
        assert_eq!(reply.yiaddr, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(
            reply.option_addr(dhcp::opt::ROUTER),
            Some(Ipv4Addr::new(10, 0, 0, 1))
        );

        // The socket file is gone once QEMU is connected: one VM only.
        assert!(!vm_sock.exists());

        // ARP for the gateway.
        let mut arp = vec![0, 1, 8, 0, 6, 4, 0, 1];
        arp.extend_from_slice(&VM);
        arp.extend_from_slice(&[10, 0, 0, 2, 0, 0, 0, 0, 0, 0, 10, 0, 0, 1]);
        send(&mut qemu, &frame([0xff; 6], 0x0806, &arp));
        let a = recv(&mut qemu);
        assert_eq!(&a[0..6], &VM);
        assert_eq!(
            &a[14 + 8..14 + 18],
            &[GATEWAY.as_slice(), &[10, 0, 0, 1]].concat()[..]
        );

        // A spoofed ping, then a real one. Only the real one reaches the
        // world, which answers it.
        send(
            &mut qemu,
            &frame(GATEWAY, 0x0800, &echo_request([10, 0, 0, 77])),
        );
        send(
            &mut qemu,
            &frame(GATEWAY, 0x0800, &echo_request([10, 0, 0, 2])),
        );
        let back = recv(&mut qemu);
        assert_eq!(
            &back[0..14],
            &[VM.as_slice(), &GATEWAY, &[8, 0]].concat()[..]
        );
        assert_eq!(&back[14..], &from_world()[..]);
        drop(qemu);
    });

    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let out = seen.clone();
    fictionet::block_on(fictionet::run(
        fictionet::RunOptions::new(fictionet::Seed::random()),
        move |fcx| async move {
            let mut vm1 = attachments.get(&fcx, "vm1").await?;
            loop {
                match vm1.recv(&fcx).await {
                    Ok(Packet(p)) => {
                        let from_vm = p[12..16] == [10, 0, 0, 2];
                        out.lock().unwrap().push(p);
                        if from_vm {
                            vm1.send(Packet(from_world()));
                        }
                    }
                    // QEMU closed its socket: attach detached.
                    Err(RecvError::Closed) => break,
                    Err(e) => return Err(fictionet::Error::msg(format!("{e:?}"))),
                }
            }
            Ok(())
        },
    ))
    .unwrap();
    qemu_side.join().unwrap();
    drop(listening);

    let packets = seen.lock().unwrap().clone();
    assert_eq!(
        packets.len(),
        1,
        "only the real ping reached the world: {packets:?}"
    );
    assert_eq!(packets[0], echo_request([10, 0, 0, 2]));

    let out = attach.wait_with_output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{err}");
    assert!(err.contains("the VM's MAC is 52:54:00:12:34:56"), "{err}");
    assert!(
        err.contains("1 frames from the VM dropped: from an address attach did not hand out"),
        "{err}"
    );
    assert!(
        err.contains("QEMU closed the connection; vm1 detached"),
        "{err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// DHCPv6 validation happens before lease policy over the QEMU socket too.
#[test]
fn a_fake_qemu_gets_dhcpv6_after_malformed_requests() {
    use fictionet::stdlib::protocols::dhcpv6::{self, DhcpOption, Duid, IaNa, Message, msg};

    let dir = temp::dir();
    let world = dir.join("w.sock");
    let vm_sock = dir.join("vm.sock");
    let ready = dir.join("ready");
    let (attacher, mut attachments) = fictionet::attachments();
    let listening =
        fictionet::listen(fictionet::WorldSocket::UnixSocket(world.clone()), attacher).unwrap();
    let attach = Command::new(BIN)
        .args([
            "attach",
            "--world",
            &format!("unix:{}", world.display()),
            "--name",
            "vm6",
            "--type",
            "tap",
        ])
        .arg(format!("--vm=qemu:{}", vm_sock.display()))
        .args([
            "--no-ip-addr",
            "--ip-addr-v6",
            "fd00::2/64",
            "--gateway-v6",
            "fd00::1",
            "--dns-v6",
            "fd00::53",
        ])
        .arg(format!("--ready-file={}", ready.display()))
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let (received, attached) = std::sync::mpsc::channel();
    let qemu_side = std::thread::spawn(move || {
        attached.recv_timeout(Duration::from_secs(5)).unwrap();
        poll::until(Duration::from_secs(5), "QEMU socket readiness file", || {
            ready.exists()
        });
        let mut qemu = UnixStream::connect(&vm_sock).unwrap();
        qemu.set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let send_request = |qemu: &mut UnixStream, request: &[u8]| {
            let builder = etherparse::PacketBuilder::ipv6(
                "fe80::5054:ff:fe12:3456"
                    .parse::<std::net::Ipv6Addr>()
                    .unwrap()
                    .octets(),
                dhcpv6::ALL_DHCP_RELAY_AGENTS_AND_SERVERS.octets(),
                64,
            )
            .udp(dhcpv6::CLIENT_PORT, dhcpv6::SERVER_PORT);
            let mut packet = Vec::new();
            builder.write(&mut packet, request).unwrap();
            send(qemu, &frame([0x33, 0x33, 0, 1, 0, 2], 0x86dd, &packet));
        };
        let recv_reply = |qemu: &mut UnixStream| loop {
            let frame = recv(qemu);
            assert_eq!(&frame[12..14], &[0x86, 0xdd]);
            let ip = &frame[14..];
            if ip[6] == 58 {
                assert_eq!(ip[40], 134, "router advertisement");
                continue;
            }
            assert_eq!(&frame[..6], &VM);
            assert_eq!(ip[6], 17);
            assert_eq!(u16::from_be_bytes([ip[42], ip[43]]), dhcpv6::CLIENT_PORT);
            break Message::parse(&ip[48..]).unwrap();
        };
        let client = Duid::ll(dhcpv6::hardware::ETHERNET, &VM);
        let mut request = Message::new(msg::SOLICIT, 1);
        request.options = vec![
            DhcpOption::ClientId(client.clone()),
            DhcpOption::IaNa(IaNa {
                iaid: 7,
                ..IaNa::default()
            }),
        ];
        let valid = request.to_bytes().unwrap();
        // Short DUID, nonempty Rapid Commit, and a truncated nested IAADDR.
        for malformed in [
            vec![1, 0, 0, 0, 0, 1, 0, 2, 0, 3],
            [valid.as_slice(), &[0, 14, 0, 1, 0]].concat(),
            [
                valid.as_slice(),
                &[0, 3, 0, 13, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            ]
            .concat(),
        ] {
            send_request(&mut qemu, &malformed);
        }
        send_request(&mut qemu, &valid);
        let advertise = recv_reply(&mut qemu);
        assert_eq!(
            (advertise.msg_type, advertise.transaction),
            (msg::ADVERTISE, 1)
        );
        assert_eq!(advertise.client_id(), Some(&client));
        let server = Duid::ll(dhcpv6::hardware::ETHERNET, &GATEWAY);
        assert_eq!(advertise.server_id(), Some(&server));
        let ia = advertise.ia_na().next().unwrap();
        assert_eq!(ia.iaid, 7);
        assert_eq!(
            ia.addresses().next().unwrap().address,
            "fd00::2".parse::<std::net::Ipv6Addr>().unwrap()
        );
        assert_eq!(
            advertise.option(dhcpv6::opt::DNS_SERVERS),
            Some(&DhcpOption::DnsServers(vec!["fd00::53".parse().unwrap()]))
        );
        request.msg_type = msg::REQUEST;
        request.transaction = 2;
        request.options.push(DhcpOption::ServerId(server));
        send_request(&mut qemu, &request.to_bytes().unwrap());
        let reply = recv_reply(&mut qemu);
        assert_eq!((reply.msg_type, reply.transaction), (msg::REPLY, 2));
        assert_eq!(reply.ia_na().next(), Some(ia));
    });
    fictionet::block_on(fictionet::run(
        fictionet::RunOptions::new(fictionet::Seed::from_u64(6)),
        move |fcx| async move {
            let mut vm = fcx
                .race(
                    Some(fcx.now() + Duration::from_secs(10)),
                    attachments.get(&fcx, "vm6"),
                )
                .await??;
            // DHCP stays in attach, so the peer must not detach before we take it.
            received.send(()).unwrap();
            assert_eq!(
                vm.recv(&fcx).await,
                Err(RecvError::Closed),
                "DHCPv6 must stay in attach"
            );
            Ok(())
        },
    ))
    .unwrap();
    qemu_side.join().unwrap();
    drop(listening);
    let out = attach.wait_with_output().unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A live socket of another program at the path is never replaced, even
/// with a space in the path; a stale one is.
#[test]
fn a_live_socket_is_refused_and_a_stale_one_replaced() {
    let dir = temp::dir();
    let path = dir.join("vm one.sock");
    let live = std::os::unix::net::UnixListener::bind(&path).unwrap();
    let run = || {
        Command::new(BIN)
            .args([
                "attach",
                "--world",
                "unix:/nonexistent/w.sock",
                "--name",
                "vm1",
                "--type",
                "tap",
            ])
            .arg(format!("--vm=qemu:{}", path.display()))
            .output()
            .unwrap()
    };
    let out = run();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(err.contains("a live socket is bound there"), "{err}");
    drop(live);
    // Now stale: attach replaces it, then fails on the missing world, and
    // removes its own socket file.
    let out = run();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(err.contains("connecting to the world"), "{err}");
    assert!(!path.exists());
    let _ = std::fs::remove_dir_all(&dir);
}

/// A second attach at the path of a waiting one is refused, by another
/// spelling of the path too, and leaves the first one's socket and ready
/// file alone. The first still takes QEMU's connection.
#[test]
fn a_second_attach_leaves_the_waiting_one_alone() {
    let dir = temp::dir();
    let world = dir.join("w.sock").to_str().unwrap().to_owned();
    let vm_sock = dir.join("vm one.sock");
    let ready = dir.join("ready");
    let (attacher, _attachments) = fictionet::attachments();
    let listening = fictionet::listen(
        fictionet::WorldSocket::UnixSocket(world.clone().into()),
        attacher,
    )
    .unwrap();
    let attach = |name: &str| {
        Command::new(BIN)
            .args([
                "attach",
                "--world",
                &format!("unix:{world}"),
                "--name",
                name,
                "--type",
                "tap",
            ])
            .arg(format!("--vm=qemu:{}", vm_sock.display()))
            .arg(format!("--ready-file={}", ready.display()))
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    };
    let first = attach("vm1");
    poll::until(Duration::from_secs(5), "QEMU socket readiness file", || {
        ready.exists()
    });
    assert!(ready.exists());
    let second = attach("vm2").wait_with_output().unwrap();
    let err = String::from_utf8_lossy(&second.stderr);
    assert_eq!(second.status.code(), Some(1), "{err}");
    assert!(err.contains("another attach is using"), "{err}");
    // The same path, spelled relative to the directory.
    let third = Command::new(BIN)
        .current_dir(&dir)
        .args([
            "attach",
            "--world",
            &format!("unix:{world}"),
            "--name",
            "vm3",
            "--type",
            "tap",
        ])
        .arg("--vm=qemu:./vm one.sock")
        .arg(format!("--ready-file={}", ready.display()))
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&third.stderr);
    assert_eq!(third.status.code(), Some(1), "{err}");
    assert!(err.contains("another attach is using"), "{err}");
    assert!(vm_sock.exists(), "the first attach's socket is still there");
    assert!(
        ready.exists(),
        "the first attach's ready file is still there"
    );
    // The first attach is still waiting, and takes this connection.
    let qemu = UnixStream::connect(&vm_sock).unwrap();
    drop(qemu);
    let out = first.wait_with_output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{err}");
    assert!(
        err.contains("QEMU connected") && err.contains("QEMU closed the connection; vm1 detached"),
        "{err}"
    );
    drop(listening);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A world that accepts the attachment, then sends `message`.
fn fake_world(path: &std::path::Path, message: Vec<u8>) -> std::thread::JoinHandle<()> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    // SAFETY: plain syscalls on fds owned here; `addr` is a valid
    // sockaddr_un.
    let listener = unsafe {
        let fd = libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0);
        assert!(fd >= 0);
        let fd = OwnedFd::from_raw_fd(fd);
        let (addr, len) = fictionet::relay::unix::address(path).unwrap();
        assert_eq!(libc::bind(fd.as_raw_fd(), (&raw const addr).cast(), len), 0);
        assert_eq!(libc::listen(fd.as_raw_fd(), 1), 0);
        fd
    };
    std::thread::spawn(move || {
        // Close-on-exec, so a child process that another test starts does not
        // keep the connection open.
        // SAFETY: as above.
        let conn = unsafe {
            let fd = libc::accept4(
                listener.as_raw_fd(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                libc::SOCK_CLOEXEC,
            );
            assert!(fd >= 0);
            OwnedFd::from_raw_fd(fd)
        };
        let mut buf = vec![0u8; 70_000];
        let n = fictionet::relay::unix::recv(conn.as_raw_fd(), &mut buf, false).unwrap();
        assert!(matches!(
            fictionet::relay::decode(&buf[..n]),
            Ok(fictionet::relay::Message::Hello(_))
        ));
        fictionet::relay::unix::send(
            conn.as_raw_fd(),
            &fictionet::relay::Message::Accept.encode(),
            false,
        )
        .unwrap();
        fictionet::relay::unix::send(conn.as_raw_fd(), &message, false).unwrap();
        // Wait for attach to close its end.
        let _ = fictionet::relay::unix::recv(conn.as_raw_fd(), &mut buf, false);
    })
}

/// While attach waits for QEMU, a packet from the world is dropped, and
/// anything else the relay protocol does not allow after accept ends
/// attach with an error, as it does once QEMU is connected.
#[test]
fn messages_from_the_world_are_checked_while_waiting_for_qemu() {
    let cases: [(&str, Vec<u8>, Option<&str>); 3] = [
        (
            "packet",
            fictionet::relay::Message::Packet(&from_world()).encode(),
            None,
        ),
        (
            "unknown kind",
            vec![99, 1, 2, 3],
            Some("the world sent a bad message"),
        ),
        (
            "accept again",
            fictionet::relay::Message::Accept.encode(),
            Some("after accept"),
        ),
    ];
    for (what, message, error) in cases {
        let dir = temp::dir();
        let world = dir.join("w.sock");
        let vm_sock = dir.join("vm.sock");
        let ready = dir.join("ready");
        let world_side = fake_world(&world, message);
        let mut attach = Command::new(BIN)
            .args([
                "attach",
                "--world",
                &format!("unix:{}", world.display()),
                "--name",
                "vm1",
                "--type",
                "tap",
            ])
            .arg(format!("--vm=qemu:{}", vm_sock.display()))
            .arg(format!("--ready-file={}", ready.display()))
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        match error {
            Some(want) => {
                let out = within(Duration::from_secs(2), move || {
                    attach.wait_with_output().unwrap()
                });
                let err = String::from_utf8_lossy(&out.stderr);
                assert_eq!(out.status.code(), Some(1), "{what}: {err}");
                assert!(err.contains(want), "{what}: {err}");
                assert!(
                    !ready.exists() && !vm_sock.exists(),
                    "{what}: attach cleaned up"
                );
            }
            None => {
                poll::until(Duration::from_secs(2), "QEMU socket readiness file", || {
                    ready.exists()
                });
                assert!(
                    attach.try_wait().unwrap().is_none(),
                    "{what}: attach exited"
                );
                // Still waiting: QEMU connects, then leaves.
                drop(UnixStream::connect(&vm_sock).unwrap());
                let out = attach.wait_with_output().unwrap();
                assert_eq!(
                    out.status.code(),
                    Some(0),
                    "{what}: {}",
                    String::from_utf8_lossy(&out.stderr)
                );
            }
        }
        world_side.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
