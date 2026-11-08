//! Programs on a network's machines, delays on their links, and hosts
//! placed while the network runs.

use super::*;
use fictionet::stdlib::world::net::{Endpoints, NetHandle, Placed};
use tokio::sync::mpsc;

const ECHO_AT: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 10);
const CLIENT_AT: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 20);
const LATE_AT: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 30);

/// A host at `addr` that serves the echo service on TCP port 7.
fn echo_host(label: &str, addr: Ipv4Addr) -> Host {
    Host::new(label).at(addr).tcp_stack(7, |_| Echo::stack())
}

/// Waits up to ten seconds of world time for what a program sends.
async fn from_program<T>(fcx: &Cx, rx: &mut mpsc::UnboundedReceiver<T>) -> T {
    timeout(fcx, Duration::from_secs(10), rx.recv())
        .await
        .flatten()
        .expect("the program sent nothing")
}

#[test]
fn a_program_connects_to_another_host_through_the_router() {
    world(Duration::from_secs(60), |fcx| async move {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let client =
            Host::new("client")
                .at(CLIENT_AT)
                .program(move |fcx: Cx, machine: Endpoints| {
                    let tx = tx.clone();
                    async move {
                        let to = SocketAddr::new(ECHO_AT.into(), 7);
                        let mut conn = machine.tcp.connect(&fcx, to).await?;
                        let mut got = read_some(&fcx, &mut conn, b"hello\n".len()).await;
                        conn.write_all(&fcx, b"ping\n").await?;
                        got.extend(read_some(&fcx, &mut conn, b"ping\n".len()).await);
                        let _ = tx.send((machine.addr, conn.local_addr(), got));
                        Ok(())
                    }
                });
        let (_attacher, attachments) = fictionet::attachments();
        Net::new(fictionet_extras::network::cdn_pools())
            .ipv4_only()
            .add_host(echo_host("echo", ECHO_AT))
            .add_host(client)
            .start(&fcx, attachments)?;
        let (addr, local, got) = from_program(&fcx, &mut rx).await;
        assert_eq!(addr, IpAddr::from(CLIENT_AT));
        assert_eq!(local.ip(), IpAddr::from(CLIENT_AT));
        assert_eq!(got, b"hello\nping\n");
        Ok(())
    });
}

#[test]
fn a_program_receives_and_sends_udp() {
    world(Duration::from_secs(60), |fcx| async move {
        let (tx, mut rx) = mpsc::unbounded_channel();
        // Answers each datagram with the sender's sandbox name and the
        // datagram's bytes.
        let answerer =
            Host::new("answerer")
                .at(ECHO_AT)
                .program(move |fcx: Cx, machine: Endpoints| {
                    let tx = tx.clone();
                    async move {
                        let mut socket = machine.udp.bind(5000)?;
                        // An address no sandbox has is no sandbox's.
                        let elsewhere = "203.0.113.9".parse().expect("an address");
                        assert_eq!(machine.sandbox_of(elsewhere), None);
                        let _ = tx.send(());
                        loop {
                            let (bytes, from) = socket.recv(&fcx).await?;
                            let sandbox = machine.sandbox_of(from.ip()).expect("a sandbox");
                            let mut reply = sandbox.name.as_bytes().to_vec();
                            reply.push(b':');
                            reply.extend_from_slice(&bytes);
                            socket.send_to(&reply, from);
                        }
                    }
                });
        let (attacher, attachments) = fictionet::attachments();
        Net::new(fictionet_extras::network::cdn_pools())
            .ipv4_only()
            .add_host(answerer)
            .start(&fcx, attachments)?;
        from_program(&fcx, &mut rx).await;
        let guest = machine(&fcx, attacher.attach("guest")?, ME);
        let mut socket = guest.udp.bind(0)?;
        socket.send_to(b"hi", SocketAddr::new(ECHO_AT.into(), 5000));
        let (reply, from) = timeout(&fcx, Duration::from_secs(5), socket.recv(&fcx))
            .await
            .expect("an answer")?;
        assert_eq!(from, SocketAddr::new(ECHO_AT.into(), 5000));
        assert_eq!(reply, b"guest:hi");
        Ok(())
    });
}

#[test]
fn a_delay_holds_each_packet_that_long_each_way() {
    let by = Duration::from_millis(40);
    world(Duration::from_secs(60), move |fcx| async move {
        let (tx, mut rx) = mpsc::unbounded_channel();
        // Reports when each datagram arrived, then answers it.
        let far =
            Host::new("far")
                .at(ECHO_AT)
                .delay(by)
                .program(move |fcx: Cx, machine: Endpoints| {
                    let tx = tx.clone();
                    async move {
                        let mut socket = machine.udp.bind(5000)?;
                        let _ = tx.send(None);
                        loop {
                            let (bytes, from) = socket.recv(&fcx).await?;
                            let _ = tx.send(Some(fcx.now()));
                            socket.send_to(&bytes, from);
                        }
                    }
                });
        let (attacher, attachments) = fictionet::attachments();
        Net::new(fictionet_extras::network::cdn_pools())
            .ipv4_only()
            .add_host(far)
            .start(&fcx, attachments)?;
        assert_eq!(from_program(&fcx, &mut rx).await, None);
        let guest = machine(&fcx, attacher.attach("guest")?, ME);
        let mut socket = guest.udp.bind(0)?;
        let sent = fcx.now();
        socket.send_to(b"x", SocketAddr::new(ECHO_AT.into(), 5000));
        let (reply, _) = timeout(&fcx, Duration::from_secs(5), socket.recv(&fcx))
            .await
            .expect("an answer")?;
        let answered = fcx.now();
        assert_eq!(reply, b"x");
        let arrived = from_program(&fcx, &mut rx).await.expect("an arrival");
        let there = arrived.since_start() - sent.since_start();
        let back = answered.since_start() - arrived.since_start();
        assert_eq!((there, back), (by, by));
        Ok(())
    });
}

#[test]
fn a_host_added_while_running_is_reached_by_a_sandbox() {
    world(Duration::from_secs(60), |fcx| async move {
        let (attacher, attachments) = fictionet::attachments();
        let net = Net::new(fictionet_extras::network::cdn_pools()).ipv4_only();
        let handle = net.handle();
        net.start(&fcx, attachments)?;
        let placed = handle.add_host(echo_host("late", LATE_AT).dns_name("late.test"))?;
        assert_eq!(
            placed,
            Placed {
                v4: Some(LATE_AT),
                v6: None
            }
        );
        let guest = machine(&fcx, attacher.attach("guest")?, ME);
        let answer = guest
            .lookup(
                &fcx,
                Ipv4Addr::new(10, 0, 0, 1).into(),
                "late.test",
                RecordType::A,
            )
            .await?;
        let found: Vec<_> = answer
            .answers
            .iter()
            .filter_map(|a| match &a.data {
                RData::A(a) => Some(a.0),
                _ => None,
            })
            .collect();
        assert_eq!(found, [LATE_AT]);
        let mut conn = guest
            .tcp
            .connect(&fcx, SocketAddr::new(LATE_AT.into(), 7))
            .await?;
        assert_eq!(read_some(&fcx, &mut conn, 6).await, b"hello\n");
        Ok(())
    });
}

#[test]
fn a_program_added_at_an_existing_machine_runs_there() {
    world(Duration::from_secs(60), |fcx| async move {
        let (_attacher, attachments) = fictionet::attachments();
        let net = Net::new(fictionet_extras::network::cdn_pools())
            .ipv4_only()
            .add_host(echo_host("echo", ECHO_AT));
        let handle = net.handle();
        net.start(&fcx, attachments)?;
        let (tx, mut rx) = mpsc::unbounded_channel();
        let joiner =
            Host::new("joiner")
                .at(ECHO_AT)
                .program(move |_fcx: Cx, machine: Endpoints| {
                    let tx = tx.clone();
                    async move {
                        // The echo service already listens on port 7 of this
                        // machine, so the program cannot.
                        let _ = tx.send((machine.addr, machine.tcp.listen(7).is_err()));
                        Ok(())
                    }
                });
        handle.add_host(joiner)?;
        assert_eq!(
            from_program(&fcx, &mut rx).await,
            (IpAddr::from(ECHO_AT), true)
        );
        Ok(())
    });
}

/// A program may use the network's handle before its first await, also
/// when its host is added while the network runs.
#[test]
fn a_program_uses_the_handle_from_its_first_line() {
    world(Duration::from_secs(10), |fcx| async move {
        let (_attacher, attachments) = fictionet::attachments();
        let net = Net::new(fictionet_extras::network::cdn_pools()).ipv4_only();
        let handle = net.handle();
        net.start(&fcx, attachments)?;
        let (tx, mut rx) = mpsc::unbounded_channel();
        let inner = handle.clone();
        let late = Host::new("late")
            .at(LATE_AT)
            .program(move |_fcx: Cx, machine: Endpoints| {
                let placed = inner.has_machine(machine.addr);
                let tx = tx.clone();
                async move {
                    let _ = tx.send(placed);
                    Ok(())
                }
            });
        handle.add_host(late)?;
        assert!(from_program(&fcx, &mut rx).await);
        Ok(())
    });
}

#[test]
fn adding_a_host_fails_before_start_and_on_the_sandboxes_subnet() {
    world(Duration::from_secs(60), |fcx| async move {
        let (_attacher, attachments) = fictionet::attachments();
        let net = Net::new(fictionet_extras::network::cdn_pools())
            .ipv4_only()
            .add_host(echo_host("echo", ECHO_AT));
        let handle = net.handle();
        assert!(handle.add_host(echo_host("early", LATE_AT)).is_err());
        assert!(!handle.has_machine(ECHO_AT.into()));
        net.start(&fcx, attachments)?;
        assert!(
            !handle.has_machine(LATE_AT.into()),
            "the early host is not placed"
        );
        let inside = Ipv4Addr::new(10, 0, 0, 5);
        assert!(handle.add_host(echo_host("inside", inside)).is_err());
        assert!(!handle.has_machine(inside.into()));
        Ok(())
    });
}

#[test]
fn has_machine_reports_placed_addresses_only() {
    world(Duration::from_secs(60), |fcx| async move {
        let (_attacher, attachments) = fictionet::attachments();
        let net = Net::new(fictionet_extras::network::cdn_pools())
            .ipv4_only()
            .add_host(echo_host("echo", ECHO_AT));
        let handle: NetHandle = net.handle();
        net.start(&fcx, attachments)?;
        assert!(handle.has_machine(ECHO_AT.into()));
        assert!(!handle.has_machine(CLIENT_AT.into()));
        Ok(())
    });
}

#[test]
fn hosts_adds_each_host() {
    world(Duration::from_secs(60), |fcx| async move {
        let (_attacher, attachments) = fictionet::attachments();
        let net = Net::new(fictionet_extras::network::cdn_pools())
            .ipv4_only()
            .hosts([
                echo_host("one", ECHO_AT),
                echo_host("two", CLIENT_AT),
                echo_host("three", LATE_AT),
            ]);
        let handle = net.handle();
        net.start(&fcx, attachments)?;
        for addr in [ECHO_AT, CLIENT_AT, LATE_AT] {
            assert!(handle.has_machine(addr.into()), "{addr} has a machine");
        }
        Ok(())
    });
}
