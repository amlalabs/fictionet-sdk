use super::super::*;
use super::*;
use fictionet::stdlib::network::ConnectionExt;
use fictionet::stdlib::network::ip::{set_header_checksum, transport_checksum};
use fictionet::stdlib::test_support::rounds;
use fictionet::{InterfaceExt, Packet, Seed, block_on, lab, pair, run};

#[test]
fn stopping_releases_native_factories_without_polling_applications() {
    use std::sync::atomic::{AtomicBool, Ordering};
    struct Capture(Arc<Shared>, Arc<AtomicBool>);
    impl Drop for Capture {
        fn drop(&mut self) {
            assert!(self.0.state.try_lock().is_some());
            self.1.store(true, Ordering::SeqCst);
        }
    }
    block_on(lab(Seed::from_u64(1), |cx| async move {
        let (endpoint, driver) = prepare_transport(
            &cx,
            "10.0.0.1".parse()?,
            Options::default(),
            &Factory::default(),
        );
        let released = Arc::new(AtomicBool::new(false));
        let capture = Capture(endpoint.shared.clone(), released.clone());
        let mut listener = endpoint.listen(80)?;
        listener.attach(Application {
            make: Arc::new(move |_, _, _| {
                let _ = &capture;
                panic!("no incoming connection");
            }),
            budget: Arc::new(|_, _| Budget::unlimited()),
        });
        assert!(!released.load(Ordering::SeqCst));
        drop(driver);
        assert!(released.load(Ordering::SeqCst));
        drop(listener);
        cx.cancel();
        Ok(())
    }))
    .unwrap();
}

#[derive(Debug)]
struct TestCookies;

impl SynCookies for TestCookies {
    fn issue(&self, input: &CookieInput<'_>) -> CookieReply {
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, input.key);
        let mut message = Vec::new();
        put_ends(&mut message, [input.local, input.remote]);
        message.extend_from_slice(&input.sequence.to_be_bytes());
        message.extend_from_slice(&(input.now.as_secs() / 37).to_be_bytes());
        let tag = ring::hmac::sign(&key, &message);
        CookieReply {
            sequence: u32::from_be_bytes(tag.as_ref()[..4].try_into().unwrap()),
            options: Vec::new(),
            ecn: false,
        }
    }

    fn validate(&self, input: &CookieInput<'_>, cookie: u32) -> Option<CookieState> {
        (self.issue(input).sequence == cookie).then_some(CookieState {
            mss: 536,
            scale: None,
            sack: false,
            ecn: false,
            timestamp: None,
        })
    }
}

fn cookie_options() -> Options {
    Options::default().settings(Settings {
        cookies: Some(&TestCookies),
        ..Settings::default()
    })
}

/// The run's time, as smoltcp counts it.
fn smol_now(fcx: &Cx) -> smoltcp::time::Instant {
    smol(fcx.now())
}

/// Hands over `h`, a connection a test took out of its accept queue by
/// hand, to the endpoint's handles, as an accept would.
fn accept_by_hand(ep: &Endpoint, host: &mut Host, h: Id) -> TcpConnection {
    let port = host.conns[&h].local.port();
    host.adopt(h);
    host.pump();
    host.accepted(&ep.shared, port)
        .expect("the listener took the connection")
}

/// Sets the IP length fields and the checksums of a TCP packet that ends at
/// `packet.len()` and whose TCP header starts at `tcp_at`.
fn fix_lengths(packet: &mut [u8], tcp_at: usize, src: IpAddr, dst: IpAddr) {
    let len = packet.len();
    if src.is_ipv4() {
        packet[2..4].copy_from_slice(&(len as u16).to_be_bytes());
        let ihl = (packet[0] & 15) as usize * 4;
        set_header_checksum(&mut packet[..ihl]);
    } else {
        packet[4..6].copy_from_slice(&((len - 40) as u16).to_be_bytes());
    }
    packet[tcp_at + 16..tcp_at + 18].copy_from_slice(&[0, 0]);
    let sum = transport_checksum(src, dst, TCP, &packet[tcp_at..]);
    packet[tcp_at + 16..tcp_at + 18].copy_from_slice(&sum.to_be_bytes());
}

#[test]
fn closed_port_observations_follow_validation_and_release_the_lock() {
    block_on(lab(Seed::from_u64(1), |fcx| async move {
        let (mut raw, side) = pair();
        let local: SocketAddr = "10.0.0.1:80".parse()?;
        let peer: SocketAddr = "10.0.0.2:1234".parse()?;
        let endpoint = endpoint(&fcx, side, local.ip());
        let shared = Arc::downgrade(&endpoint.shared);
        let observed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = observed.clone();
        endpoint.on_refused(Arc::new(move |_, _| {
            assert!(shared.upgrade().unwrap().state.try_lock().is_some());
            count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }));
        let valid = segment(peer, local, 7, 0, 2);
        let mut invalid = valid.clone();
        invalid.0[36] ^= 1;
        raw.send(invalid);
        raw.send(valid);
        raw.recv(&fcx).await?;
        assert_eq!(observed.load(std::sync::atomic::Ordering::Relaxed), 1);
        fcx.cancel();
        Ok(())
    }))
    .unwrap();
}

/// A reader's waker runs once the endpoint is unlocked: a waker runs code
/// of its own, which may lock the endpoint again.
#[test]
fn wakers_run_once_the_endpoint_is_unlocked() {
    use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
    struct Probe {
        shared: std::sync::Weak<Shared>,
        woken: AtomicUsize,
        while_locked: AtomicUsize,
    }
    impl std::task::Wake for Probe {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.woken.fetch_add(1, SeqCst);
            if let Some(shared) = self.shared.upgrade()
                && shared.state.try_lock().is_none()
            {
                self.while_locked.fetch_add(1, SeqCst);
            }
        }
    }
    let result = block_on(lab(Seed::from_u64(1), |fcx| async move {
        let (a, b) = pair();
        let server = endpoint(&fcx, a, "10.0.0.1".parse().unwrap());
        let client = endpoint(&fcx, b, "10.0.0.2".parse().unwrap());
        let mut listener = server.listen(80)?;
        let mut c = client.connect(&fcx, "10.0.0.1:80".parse().unwrap()).await?;
        let mut s = listener.accept(&fcx).await?;
        let probe = Arc::new(Probe {
            shared: Arc::downgrade(&server.shared),
            woken: AtomicUsize::new(0),
            while_locked: AtomicUsize::new(0),
        });
        let waker = Waker::from(probe.clone());
        let mut buf = [0u8; 4];
        let read = s.poll_read(&fcx, &mut Context::from_waker(&waker), &mut buf);
        assert!(read.is_pending());
        c.write_all(&fcx, b"ping").await?;
        while probe.woken.load(SeqCst) == 0 {
            fcx.sleep(Duration::from_millis(1)).await?;
        }
        assert_eq!(
            probe.while_locked.load(SeqCst),
            0,
            "a waker ran while the endpoint was locked"
        );
        Err::<(), fictionet::Error>(fictionet::Error::msg("done"))
    }));
    assert_eq!(result.unwrap_err().to_string(), "done");
}

#[test]
fn transmit_batches_retain_descriptor_capacity() {
    block_on(run(Seed::from_u64(1), |fcx| async move {
        let (_raw, side) = pair();
        let ep = endpoint(&fcx, side, "10.0.0.1".parse()?);
        let mut host = ep.shared.lock();
        let peer = "10.0.0.2:1234".parse()?;
        let local = "10.0.0.1:80".parse()?;
        for n in 0..8 {
            host.dev.tx.push(segment(local, peer, n, 0, 4).0);
        }
        let capacity = host.dev.tx.capacity();
        host.flush_transmit();
        assert!(host.dev.tx.is_empty());
        assert!(host.dev.tx.capacity() >= capacity);
        assert_eq!(host.dev.out.len(), 8);
        for (n, packet) in host.dev.out.iter().enumerate() {
            let tcp = Header::parse_whole(packet).unwrap().payload(packet);
            assert_eq!(u32::from_be_bytes(tcp[4..8].try_into().unwrap()), n as u32);
        }
        Ok(())
    }))
    .unwrap();
}

#[test]
fn device_output_yields_and_preserves_waiting_input() {
    let mut dev = Dev::default();
    let now = smoltcp::time::Instant::from_micros(0);
    for _ in 0..EGRESS_PACKETS {
        dev.transmit(now).unwrap().consume(MTU, |_| {});
    }
    assert!(dev.transmit(now).is_none());
    dev.rx = Some(vec![1, 2, 3]);
    assert!(dev.receive(now).is_none());
    assert_eq!(dev.rx.as_deref(), Some([1, 2, 3].as_slice()));
    dev.tx.clear();
    let (rx, tx) = dev.receive(now).unwrap();
    rx.consume(|p| assert_eq!(p, [1, 2, 3]));
    tx.consume(40, |_| {});
    assert_eq!(dev.tx.len(), 1);
}

#[test]
fn orphan_waits_for_reset_when_output_is_full() {
    block_on(run(Seed::random(), |fcx| async move {
        let (_raw, side) = pair();
        let local: SocketAddr = "10.0.0.1:80".parse().unwrap();
        let peer: SocketAddr = "10.0.0.2:1234".parse().unwrap();
        let ep = endpoint(&fcx, side, local.ip());
        let _listener = ep.listen(local.port())?;
        let now = smol_now(&fcx);
        let mut st = ep.shared.lock();
        st.ingress(
            &fcx,
            &Budget::unlimited(),
            now,
            segment(peer, local, 100, 0, 2).0,
        );
        let syn_ack = egress(&mut st, now);
        let t = Header::parse_whole(&syn_ack[0])
            .unwrap()
            .payload(&syn_ack[0]);
        let ack = u32::from_be_bytes(t[4..8].try_into().unwrap()).wrapping_add(1);
        st.ingress(
            &fcx,
            &Budget::unlimited(),
            now,
            segment(peer, local, 101, ack, 16).0,
        );
        st.housekeeping();
        let h = st
            .listeners
            .get_mut(&80)
            .unwrap()
            .ready
            .pop_front()
            .unwrap();
        st.orphan(h, true);
        for _ in 0..EGRESS_PACKETS {
            st.dev.transmit(now).unwrap().consume(40, |_| {});
        }
        let st: &mut TcpLayer = &mut st;
        st.iface.poll_egress(now, &mut st.dev, &mut st.sockets);
        st.housekeeping();
        assert!(
            st.conns.contains_key(&h),
            "unsent reset must keep its socket"
        );
        st.dev.tx.clear();
        let packets = egress(st, now);
        assert_eq!(packets.len(), 1);
        let t = Header::parse_whole(&packets[0])
            .unwrap()
            .payload(&packets[0]);
        assert_eq!(t[13] & 4, 4);
        st.housekeeping();
        assert!(!st.conns.contains_key(&h));
        Ok(())
    }))
    .unwrap();
}

/// The entropy of helpers that make sockets with the default settings,
/// which draw nothing for a socket.
struct NoDraws;

impl Entropy for NoDraws {
    fn fill_random(&self, _: &mut [u8]) {
        unreachable!("default settings draw nothing for a socket")
    }
}

const NO_DRAWS: NoDraws = NoDraws;

/// Handshakes a connection. Returns its socket and next send sequence.
fn established(
    st: &mut TcpLayer,
    now: smoltcp::time::Instant,
    local: SocketAddr,
    peer: SocketAddr,
) -> (Id, u32) {
    st.ingress(
        &NO_DRAWS,
        &Budget::unlimited(),
        now,
        segment(peer, local, 100, 0, 2).0,
    );
    let syn_ack = egress(st, now);
    let t = Header::parse_whole(&syn_ack[0])
        .unwrap()
        .payload(&syn_ack[0]);
    let ack = u32::from_be_bytes(t[4..8].try_into().unwrap()).wrapping_add(1);
    st.ingress(
        &NO_DRAWS,
        &Budget::unlimited(),
        now,
        segment(peer, local, 101, ack, 16).0,
    );
    st.housekeeping();
    let l = st.listeners.get_mut(&local.port()).unwrap();
    let h = l.ready.pop_front().unwrap();
    l.left(peer.ip());
    (h, ack)
}

/// Handshakes and actively closes a connection, leaving its final ACK
/// for egress. Returns the dropped socket and the peer's FIN.
fn time_wait(
    st: &mut TcpLayer,
    now: smoltcp::time::Instant,
    local: SocketAddr,
    peer: SocketAddr,
) -> (Id, Packet) {
    let (h, ack) = established(st, now, local, peer);
    st.sock(h).close();
    let fin = egress(st, now);
    assert_eq!(
        Header::parse_whole(&fin[0]).unwrap().payload(&fin[0])[13],
        0x11
    );
    let peer_fin = segment(peer, local, 101, ack.wrapping_add(1), 0x11);
    st.ingress(&NO_DRAWS, &Budget::unlimited(), now, peer_fin.0.clone());
    assert_eq!(st.get(h).state(), TcpState::TimeWait);
    st.orphan(h, false);
    (h, peer_fin)
}

#[test]
fn time_wait_survives_full_output_and_expires_after_retransmission() {
    block_on(lab(Seed::from_u64(1), |fcx| async move {
        let (_raw, side) = pair();
        let local: SocketAddr = "10.0.0.1:80".parse()?;
        let peer: SocketAddr = "10.0.0.2:1234".parse()?;
        let ep = endpoint(&fcx, side, local.ip());
        let _listener = ep.listen(local.port())?;
        let now = smol_now(&fcx);
        let mut st = ep.shared.lock();
        let (h, fin) = time_wait(&mut st, now, local, peer);
        let id = st.adopt(h);
        drop(st);
        let watch = GoneWatch {
            shared: ep.shared.clone(),
            id,
        };
        let held = Arc::new(());
        watch.hold_until_gone(Box::new(held.clone()));
        let log = Arc::new(Mutex::new(Vec::new()));
        let waker = Waker::from(Arc::new(WakeLog(0, log.clone())));
        assert!(
            watch
                .poll_gone(&mut Context::from_waker(&waker))
                .is_pending()
        );
        let mut st = ep.shared.lock();
        while st.dev.tx.len() < EGRESS_PACKETS {
            st.dev.transmit(now).unwrap().consume(40, |_| {});
        }
        let later = now + smoltcp::time::Duration::from_millis(20);
        {
            let st: &mut TcpLayer = &mut st;
            st.iface.poll_egress(later, &mut st.dev, &mut st.sockets);
        }
        st.housekeeping();
        st.pump();
        assert!(
            st.conns.contains_key(&h),
            "full egress must retain TIME-WAIT"
        );
        assert_eq!(Arc::strong_count(&held), 1);
        assert_eq!(*log.lock(), [0]);
        drop(st);
        assert!(watch.poll_gone(&mut Context::from_waker(&waker)).is_ready());
        watch.reset();
        watch.hold_until_gone(Box::new(held.clone()));
        assert_eq!(Arc::strong_count(&held), 1);
        let mut st = ep.shared.lock();
        let st: &mut TcpLayer = &mut st;
        assert_eq!(st.get(h).state(), TcpState::TimeWait);
        st.dev.tx.clear();
        let packets = egress(st, later);
        assert_eq!(packets.len(), 1);
        let t = Header::parse_whole(&packets[0])
            .unwrap()
            .payload(&packets[0]);
        assert_eq!(t[13], 0x10);
        assert_eq!(u32::from_be_bytes(t[8..12].try_into().unwrap()), 102);
        // FINs near expiry restart the two-MSL timer, even past the
        // orphan timeout for sockets that have not reached TIME-WAIT.
        for seconds in [239, 478, 717, 956, 1195, 1434, 1673] {
            let retry = now + smoltcp::time::Duration::from_secs(seconds);
            st.ingress(&fcx, &Budget::unlimited(), retry, fin.0.clone());
            let packets = egress(st, retry);
            assert_eq!(packets.len(), 1);
            let t = Header::parse_whole(&packets[0])
                .unwrap()
                .payload(&packets[0]);
            assert_eq!(t[13], 0x10);
        }
        let before = now + smoltcp::time::Duration::from_secs(1912);
        assert!(egress(st, before).is_empty());
        st.housekeeping();
        assert!(st.conns.contains_key(&h));
        let expiry = now + smoltcp::time::Duration::from_secs(1913);
        assert!(egress(st, expiry).is_empty());
        st.housekeeping();
        assert!(!st.conns.contains_key(&h));
        assert!(!st.handles.contains_key(&h));
        assert!(!st.pages.contains_key(&h));
        assert!(!st.by_tuple.contains_key(&(local, peer)));
        assert!(!st.orphans.contains(&h));
        assert!(st.time_wait.is_empty());
        assert_eq!(Arc::strong_count(&held), 1);
        Ok(())
    }))
    .unwrap();
}

#[test]
fn time_wait_overflow_evicts_the_oldest_dropped_connections() {
    block_on(lab(Seed::from_u64(1), |fcx| async move {
        let (_raw, side) = pair();
        let local: SocketAddr = "10.0.0.1:80".parse()?;
        let peer: IpAddr = "10.0.0.2".parse()?;
        let ep = endpoint_with(
            &fcx,
            side,
            local.ip(),
            Options::default().buffer(MIN_BUFFER),
        );
        let _listener = ep.listen(local.port())?;
        let now = smol_now(&fcx);
        let mut st = ep.shared.lock();
        let (kept, _) = time_wait(&mut st, now, local, SocketAddr::new(peer, 1000));
        // Model a TIME-WAIT socket whose application still holds it.
        st.orphans.clear();
        egress(&mut st, now);
        let recent_peer = SocketAddr::new(peer, 1001);
        let (recent, ack) = established(&mut st, now, local, recent_peer);
        let mut dropped = Vec::new();
        for port in 1002..1002 + MAX_TIME_WAIT as u16 {
            let (h, _) = time_wait(&mut st, now, local, SocketAddr::new(peer, port));
            dropped.push(h);
            egress(&mut st, now);
            st.housekeeping();
        }
        // The older connection enters TIME-WAIT last. Evict by entry
        // order, even when the orphan list has been rearranged.
        st.orphans.reverse();
        let later = now + smoltcp::time::Duration::from_secs(1);
        st.sock(recent).close();
        assert_eq!(egress(&mut st, later).len(), 1);
        let fin = segment(recent_peer, local, 101, ack.wrapping_add(1), 0x11);
        st.ingress(&fcx, &Budget::unlimited(), later, fin.0);
        assert_eq!(st.get(recent).state(), TcpState::TimeWait);
        st.orphan(recent, false);
        egress(&mut st, later);
        st.housekeeping();
        assert_eq!(st.orphans.len(), MAX_TIME_WAIT);
        assert_eq!(st.time_wait.len(), MAX_TIME_WAIT);
        assert!(st.conns.contains_key(&kept));
        assert!(st.conns.contains_key(&recent));
        assert!(!st.conns.contains_key(&dropped[0]));
        assert!(!st.handles.contains_key(&dropped[0]));
        assert!(
            !st.by_tuple
                .contains_key(&(local, SocketAddr::new(peer, 1002)))
        );
        assert!(dropped[1..].iter().all(|h| st.conns.contains_key(h)));
        // Eviction itself emits nothing. Normal expiry frees the rest.
        assert!(egress(&mut st, later).is_empty());
        let expiry = later + smoltcp::time::Duration::from_secs(240);
        assert!(egress(&mut st, expiry).is_empty());
        st.housekeeping();
        assert!(st.orphans.is_empty());
        assert!(st.time_wait.is_empty());
        assert_eq!(st.conns.len(), 1);
        assert!(st.conns.contains_key(&kept));
        Ok(())
    }))
    .unwrap();
}

struct WakeLog(u16, Arc<Mutex<Vec<u16>>>);
impl std::task::Wake for WakeLog {
    fn wake(self: Arc<Self>) {
        self.1.lock().push(self.0);
    }
}

#[test]
fn local_reset_wakes_watches_before_rst_egress() {
    for reset in 0..3 {
        block_on(lab(Seed::from_u64(1), move |fcx| async move {
            let (a, b) = pair();
            let server = endpoint(&fcx, a, "10.0.0.1".parse().unwrap());
            let client = endpoint(&fcx, b, "10.0.0.2".parse().unwrap());
            let mut listener = server.listen(80)?;
            let _client = client.connect(&fcx, "10.0.0.1:80".parse().unwrap()).await?;
            let conn = listener.accept(&fcx).await?;
            let h = server.shared.lock().socket_of(conn.id);
            let watches = [conn.gone_watch(), conn.gone_watch()];
            let log = Arc::new(Mutex::new(Vec::new()));
            for (i, watch) in watches.iter().enumerate() {
                let waker = Waker::from(Arc::new(WakeLog(i as u16, log.clone())));
                assert!(
                    watch
                        .poll_gone(&mut Context::from_waker(&waker))
                        .is_pending()
                );
            }
            let mut conn = Some(conn);
            match reset {
                0 => watches[0].reset(),
                1 => conn.take().unwrap().reset(),
                _ => server.abort_peers(|peer| peer == client.addr()),
            }
            assert_eq!(*log.lock(), [0, 1]);
            let cx = &mut Context::from_waker(Waker::noop());
            for watch in &watches {
                assert!(watch.poll_gone(cx).is_ready());
            }
            if let Some(conn) = &mut conn {
                assert!(matches!(
                    conn.poll_read(&fcx, cx, &mut [0]),
                    Poll::Ready(Err(ConnError::Reset))
                ));
                assert!(matches!(
                    conn.poll_write(&fcx, cx, b"x"),
                    Poll::Ready(Err(ConnError::Reset))
                ));
            }
            let now = smol_now(&fcx);
            {
                let mut st = server.shared.lock();
                st.dev.tx.clear();
                for _ in 0..EGRESS_PACKETS {
                    st.dev.transmit(now).unwrap().consume(40, |_| {});
                }
                let st: &mut TcpLayer = &mut st;
                st.iface.poll_egress(now, &mut st.dev, &mut st.sockets);
                st.housekeeping();
                assert!(
                    st.conns.contains_key(&h),
                    "unsent reset must keep its socket"
                );
                assert!(st.get(h).remote_endpoint().is_some());
                st.dev.tx.clear();
                let packets = egress(st, now);
                assert_eq!(packets.len(), 1);
                let t = Header::parse_whole(&packets[0])
                    .unwrap()
                    .payload(&packets[0]);
                assert_eq!(t[13] & 4, 4);
                st.housekeeping();
                assert_eq!(st.conns.contains_key(&h), conn.is_some());
            }
            drop(conn);
            let mut st = server.shared.lock();
            st.housekeeping();
            assert!(!st.conns.contains_key(&h));
            drop(st);
            fcx.cancel();
            Ok(())
        }))
        .unwrap();
    }
}

#[test]
fn stop_wakes_watches_with_retained_connection() {
    block_on(lab(Seed::from_u64(1), |fcx| async move {
        let (a, b) = pair();
        let server = endpoint(&fcx, a, "10.0.0.1".parse().unwrap());
        let client = endpoint(&fcx, b, "10.0.0.2".parse().unwrap());
        let mut listener = server.listen(80)?;
        let _client = client.connect(&fcx, "10.0.0.1:80".parse().unwrap()).await?;
        let mut conn = listener.accept(&fcx).await?;
        let watches = [conn.gone_watch(), conn.gone_watch()];
        let log = Arc::new(Mutex::new(Vec::new()));
        for (i, watch) in watches.iter().enumerate() {
            let waker = Waker::from(Arc::new(WakeLog(i as u16, log.clone())));
            assert!(
                watch
                    .poll_gone(&mut Context::from_waker(&waker))
                    .is_pending()
            );
        }
        server.shared.stop();
        assert_eq!(*log.lock(), [0, 1]);
        let cx = &mut Context::from_waker(Waker::noop());
        for watch in &watches {
            assert!(watch.poll_gone(cx).is_ready());
        }
        assert!(matches!(
            conn.poll_read(&fcx, cx, &mut [0]),
            Poll::Ready(Err(ConnError::Closed))
        ));
        assert!(matches!(
            conn.poll_write(&fcx, cx, b"x"),
            Poll::Ready(Err(ConnError::Closed))
        ));
        {
            let st = server.shared.lock();
            assert!(st.conns.contains_key(&st.socket_of(conn.id)));
        }
        fcx.cancel();
        Ok(())
    }))
    .unwrap();
}

#[test]
fn stop_wakes_listeners_in_port_order() {
    block_on(run(fictionet::Seed::random(), |fcx| async move {
        let (_raw, side) = pair();
        let ep = endpoint(&fcx, side, "10.0.0.1".parse().unwrap());
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut listeners = Vec::new();
        for port in [9000, 80, 443, 22, 8080] {
            listeners.push(ep.listen(port)?);
            ep.shared
                .state
                .lock()
                .routes
                .listeners
                .get_mut(&port)
                .unwrap()
                .waker = Some(Waker::from(Arc::new(WakeLog(port, log.clone()))));
        }
        ep.shared.stop();
        assert_eq!(*log.lock(), [22, 80, 443, 8080, 9000]);
        fcx.cancel();
        Ok(())
    }))
    .unwrap();
}

#[test]
fn abort_peers_wakes_connections_in_socket_order() {
    block_on(run(fictionet::Seed::random(), |fcx| async move {
        let (_raw, side) = pair();
        let ep = endpoint(&fcx, side, "10.0.0.1".parse().unwrap());
        let log = Arc::new(Mutex::new(Vec::new()));
        {
            let mut st = ep.shared.lock();
            for port in [9000, 80, 443, 22, 8080] {
                let id = st.add_socket(&fcx, new_socket(MIN_BUFFER));
                let conn = Conn::new(
                    "10.0.0.1:80".parse().unwrap(),
                    SocketAddr::new("10.0.0.2".parse().unwrap(), port),
                    Side::Server,
                );
                st.conns.insert(id, conn);
                let child = st.adopt(id);
                st.routes
                    .watches
                    .entry(child)
                    .or_default()
                    .push(Waker::from(Arc::new(WakeLog(port, log.clone()))));
            }
        }
        let peer: IpAddr = "10.0.0.2".parse().unwrap();
        ep.abort_peers(|p| p == peer);
        assert_eq!(*log.lock(), [9000, 80, 443, 22, 8080]);
        fcx.cancel();
        Ok(())
    }))
    .unwrap();
}

#[test]
fn compaction_keeps_socket_id_scan_order() {
    block_on(run(fictionet::Seed::random(), |fcx| async move {
        let (_raw, side) = pair();
        let ep = endpoint(&fcx, side, "10.0.0.1".parse().unwrap());
        let mut st = ep.shared.lock();
        let mut ids = Vec::new();
        for _ in 0..COMPACT_SLOTS {
            ids.push(st.add_socket(&fcx, new_socket(MIN_BUFFER)));
        }
        let kept = [ids[3], ids[17], ids[93], ids[201]];
        for id in ids {
            if !kept.contains(&id) {
                st.remove_socket(id);
            }
        }
        // Reuse a low storage slot with a newer SDK ID.
        let newest = st.add_socket(&fcx, new_socket(MIN_BUFFER));
        assert!(st.slots >= COMPACT_SLOTS);
        st.compact();
        assert_eq!(st.slots, 5);
        let scan: Vec<_> = st
            .sockets
            .iter()
            .map(|(slot, _)| *st.handles.iter().find(|(_, h)| **h == slot).unwrap().0)
            .collect();
        assert_eq!(scan, [kept[0], kept[1], kept[2], kept[3], newest]);
        drop(st);
        fcx.cancel();
        Ok(())
    }))
    .unwrap();
}

/// Resident pages of every socket's buffers on `e`.
fn resident(e: &Endpoint) -> usize {
    let st = e.shared.lock();
    st.pages.values().map(Pages::resident).sum()
}

fn pattern(n: usize, salt: u8) -> Vec<u8> {
    (0..n)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(salt))
        .collect()
}

/// A TCP segment from `src` to `dst` with no options.
fn segment(src: SocketAddr, dst: SocketAddr, seq: u32, ack: u32, flags: u8) -> Packet {
    data_segment(src, dst, seq, ack, flags, &[])
}

fn data_segment(
    src: SocketAddr,
    dst: SocketAddr,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Packet {
    let mut t = vec![0u8; 20];
    t.extend_from_slice(payload);
    t[0..2].copy_from_slice(&src.port().to_be_bytes());
    t[2..4].copy_from_slice(&dst.port().to_be_bytes());
    t[4..8].copy_from_slice(&seq.to_be_bytes());
    t[8..12].copy_from_slice(&ack.to_be_bytes());
    t[12] = 5 << 4;
    t[13] = flags;
    t[14..16].copy_from_slice(&65535u16.to_be_bytes());
    let sum = transport_checksum(src.ip(), dst.ip(), TCP, &t);
    t[16..18].copy_from_slice(&sum.to_be_bytes());
    fictionet::stdlib::network::ip::packet(src.ip(), dst.ip(), TCP, &t)
}

/// Drives the stack at one fixed time, without running its background task.
fn egress(st: &mut TcpLayer, now: smoltcp::time::Instant) -> Vec<Vec<u8>> {
    while st.iface.poll_egress(now, &mut st.dev, &mut st.sockets)
        != smoltcp::iface::PollResult::None
    {}
    let mut packets = std::mem::take(&mut st.dev.tx);
    for p in &mut packets {
        st.sent(p);
    }
    packets
}

#[test]
fn icmp_requires_the_current_syn_and_a_valid_quote() {
    use fictionet::stdlib::network::{icmp, ip};

    block_on(lab(Seed::from_u64(1), |fcx| async move {
        let (_raw, side) = pair();
        let local: SocketAddr = "10.0.0.1:49152".parse().unwrap();
        let peer: SocketAddr = "10.0.0.2:80".parse().unwrap();
        let ep = endpoint(&fcx, side, local.ip());
        let mut st = ep.shared.lock();
        let mut previous = None;
        for (attempt, options) in [false, true].into_iter().enumerate() {
            // The second attempt comes a millisecond later. Its initial
            // sequence number then differs from the first's, which on
            // the same endpoints at the same instant it would not
            // (RFC 6528).
            let now = smol_now(&fcx) + smoltcp::time::Duration::from_millis(attempt as u64);
            st.iface.poll_maintenance(now);
            let mut socket = new_socket(MIN_BUFFER);
            socket.0.connect(st.iface.context(), peer, local).unwrap();
            let h = st.add_socket(&fcx, socket);
            st.conns.insert(h, Conn::new(local, peer, Side::Client));
            st.by_tuple.insert((local, peer), h);
            st.take_port(local.port());
            let syn = egress(&mut st, now).remove(0);
            if let Some(old) = previous.take() {
                // The same local port and peer now belong to a new attempt.
                st.ingress(&fcx, &Budget::unlimited(), now, old);
                assert_eq!(st.get(h).state(), TcpState::SynSent);
            }
            let fragmentation_needed =
                icmp::error(&syn, "10.0.0.254".parse().unwrap(), 3, 4, 1400).unwrap();
            st.ingress(&fcx, &Budget::unlimited(), now, fragmentation_needed.0);
            assert_eq!(st.get(h).state(), TcpState::SynSent, "fragmentation needed");
            let error = icmp::host_unreachable(&syn, "10.0.0.254".parse().unwrap())
                .unwrap()
                .0;
            for fault in [
                "outer_ip",
                "icmp_checksum",
                "type",
                "code",
                "destination",
                "version",
                "quoted_ip",
                "protocol",
                "fragment",
                "local_ip",
                "remote_ip",
                "local_port",
                "remote_port",
                "sequence",
                "flags",
                "tcp_checksum",
                "length",
            ] {
                let mut p = error.clone();
                match fault {
                    "outer_ip" => p[10] ^= 1,
                    "icmp_checksum" => p[22] ^= 1,
                    "type" => p[20] = 11,
                    "code" => p[21] = 16,
                    "destination" => p[19] ^= 1,
                    "version" => p[28] = 0x65,
                    "quoted_ip" => p[38] ^= 1,
                    "protocol" => p[37] = 17,
                    "fragment" => p[35] = 1,
                    "local_ip" => p[43] ^= 1,
                    "remote_ip" => p[47] ^= 1,
                    "local_port" => p[49] ^= 1,
                    "remote_port" => p[51] ^= 1,
                    "sequence" => p[55] ^= 1,
                    "flags" => p[61] = 0x10,
                    "tcp_checksum" => p[64] ^= 1,
                    "length" => p[31] = 28,
                    _ => unreachable!(),
                }
                if matches!(
                    fault,
                    "local_ip" | "remote_ip" | "local_port" | "remote_port" | "sequence"
                ) {
                    // The minimum quote has no TCP checksum to mask a tuple mismatch.
                    p.truncate(56);
                    p[2..4].copy_from_slice(&56u16.to_be_bytes());
                }
                // Keep unrelated checksums valid so each rejection is tested.
                if !matches!(
                    fault,
                    "outer_ip" | "icmp_checksum" | "quoted_ip" | "version"
                ) {
                    ip::set_header_checksum(&mut p[28..48]);
                    ip::set_header_checksum(&mut p[..20]);
                }
                if fault != "icmp_checksum" {
                    p[22..24].fill(0);
                    let sum = checksum(&p[20..]);
                    p[22..24].copy_from_slice(&sum.to_be_bytes());
                }
                st.ingress(&fcx, &Budget::unlimited(), now, p);
                assert_eq!(st.get(h).state(), TcpState::SynSent, "{fault}");
            }
            // A truncated quote must contain all eight identity bytes.
            for len in 0..28 {
                let mut message = vec![3, 1, 0, 0, 0, 0, 0, 0];
                message.extend_from_slice(&syn[..len]);
                let sum = checksum(&message);
                message[2..4].copy_from_slice(&sum.to_be_bytes());
                let p = ip::packet(peer.ip(), local.ip(), ICMP, &message);
                st.ingress(&fcx, &Budget::unlimited(), now, p.0);
                assert_eq!(st.get(h).state(), TcpState::SynSent, "quote length {len}");
            }
            // Also accept the minimum quote with IPv4 options.
            let mut valid = error.clone();
            if options {
                valid.splice(48..48, [1; 4]);
                valid[28] = 0x46;
                let total = u16::from_be_bytes([valid[30], valid[31]]) + 4;
                valid[30..32].copy_from_slice(&total.to_be_bytes());
                ip::set_header_checksum(&mut valid[28..52]);
                valid.truncate(60);
                valid[2..4].copy_from_slice(&60u16.to_be_bytes());
                ip::set_header_checksum(&mut valid[..20]);
                valid[22..24].fill(0);
                let sum = checksum(&valid[20..]);
                valid[22..24].copy_from_slice(&sum.to_be_bytes());
            }
            st.ingress(&fcx, &Budget::unlimited(), now, valid);
            assert_eq!(st.get(h).state(), TcpState::Closed);
            assert_eq!(st.closed_reason(h), ConnError::Unreachable(1));
            previous = Some(error);
            st.remove_conn(h);
        }
        drop(st);
        fcx.cancel();
        Ok(())
    }))
    .unwrap();
}

#[test]
fn syn_rst_does_not_prepare_a_listening_socket() {
    block_on(lab(Seed::from_u64(1), |fcx| async move {
        let (_raw, side) = pair();
        let local: SocketAddr = "10.0.0.1:80".parse()?;
        let peer: SocketAddr = "10.0.0.2:1234".parse()?;
        let ep = endpoint(&fcx, side, local.ip());
        let _listener = ep.listen(local.port())?;
        let now = smol_now(&fcx);
        let mut st = ep.shared.lock();
        st.ingress(
            &fcx,
            &Budget::unlimited(),
            now,
            segment(peer, local, 7, 0, 0x02).0,
        );
        egress(&mut st, now);
        assert!(st.listeners[&80].idle.is_empty());
        let count = st.sockets.iter().count();
        let other = SocketAddr::new(peer.ip(), peer.port() + 1);
        st.ingress(
            &fcx,
            &Budget::unlimited(),
            now,
            segment(other, local, 7, 0, 0x06).0,
        );
        assert_eq!(st.sockets.iter().count(), count);
        assert!(st.listeners[&80].idle.is_empty());
        assert!(!st.by_tuple.contains_key(&(local, other)));
        assert!(egress(&mut st, now).is_empty());
        drop(st);
        fcx.cancel();
        Ok(())
    }))
    .unwrap();
}

#[test]
fn rejected_syn_acks_leave_handshake_bookkeeping_unchanged() {
    rejected_syn_acks(false);
}

#[test]
fn unsolicited_syn_acks_leave_established_bookkeeping_unchanged() {
    rejected_syn_acks(true);
}

fn rejected_syn_acks(established: bool) {
    for (local, peer) in [
        ("10.0.0.1:1234", "10.0.0.2:80"),
        ("[fd00::1]:1234", "[fd00::2]:80"),
    ] {
        let local: SocketAddr = local.parse().unwrap();
        let peer: SocketAddr = peer.parse().unwrap();
        block_on(lab(Seed::from_u64(1), |fcx| async move {
            let (_raw, side) = pair();
            let ep = endpoint_with(
                &fcx,
                side,
                local.ip(),
                Options::default().buffer(MIN_BUFFER),
            );
            let now = smol_now(&fcx);
            let mut st = ep.shared.lock();
            let mut s = new_socket(MIN_BUFFER);
            s.0.connect(st.iface.context(), peer, local).unwrap();
            let h = st.add_socket(&fcx, s);
            st.conns.insert(h, Conn::new(local, peer, Side::Client));
            st.by_tuple.insert((local, peer), h);
            let packets = egress(&mut st, now);
            let t = Header::parse_whole(&packets[0])
                .unwrap()
                .payload(&packets[0]);
            let ack = u32::from_be_bytes(t[4..8].try_into().unwrap()).wrapping_add(1);
            let irs = u32::MAX - 3;
            if established {
                st.ingress(
                    &fcx,
                    &Budget::unlimited(),
                    now,
                    segment(peer, local, irs, ack, 0x12).0,
                );
                egress(&mut st, now);
                assert_eq!(st.get(h).state(), TcpState::Established);
            }
            let before = st.get(h).state();
            for fault in [
                "empty_checksum",
                "checksum",
                "ack",
                "offset",
                "options",
                "flags",
                "ip",
                "none",
            ] {
                // A valid SYN-ACK can establish, and RST can close the socket.
                if matches!(fault, "none" | "flags") && !established
                    || fault == "ip" && local.is_ipv6()
                {
                    continue;
                }
                // This origin would put the receive edge at the first real byte.
                let seq = irs.wrapping_sub(MIN_BUFFER as u32);
                let mut p = segment(peer, local, seq, ack, 0x12).0;
                let tcp_at = Header::parse_whole(&p).unwrap().payload.start;
                if !matches!(fault, "empty_checksum" | "none") {
                    p.extend_from_slice(b"ignored");
                }
                match fault {
                    "ack" => p[tcp_at + 8..tcp_at + 12]
                        .copy_from_slice(&ack.wrapping_add(1).to_be_bytes()),
                    "offset" => p[tcp_at + 12] = 4 << 4,
                    "options" => {
                        p[tcp_at + 12] = 6 << 4;
                        p[tcp_at + 20..tcp_at + 24].copy_from_slice(&[2, 1, 0, 0]);
                    }
                    "flags" => p[tcp_at + 13] |= 4,
                    _ => {}
                }
                fix_lengths(&mut p, tcp_at, peer.ip(), local.ip());
                if matches!(fault, "empty_checksum" | "checksum") {
                    p[tcp_at + 16] ^= 1;
                } else if fault == "ip" {
                    p[10] ^= 1;
                }
                st.ingress(&fcx, &Budget::unlimited(), now, p);
                assert_eq!(st.get(h).state(), before, "{fault}");
                assert_eq!(st.get(h).recv_queue(), 0, "{fault}");
                assert!(!st.get(h).has_pending_recv(), "{fault}");
                assert!(!st.dirty.contains(&h), "{fault}");
                egress(&mut st, now);
            }
            if !established {
                st.ingress(
                    &fcx,
                    &Budget::unlimited(),
                    now,
                    segment(peer, local, irs, ack, 0x12).0,
                );
                egress(&mut st, now);
            }
            assert_eq!(st.get(h).state(), TcpState::Established);
            // Out-of-order data crosses zero. Releasing quiet pages must
            // preserve it until the gap fills.
            let expected = b"abcdefgh";
            for begin in [4usize, 0] {
                let seq = irs.wrapping_add(1).wrapping_add(begin as u32);
                let mut p = segment(peer, local, seq, ack, 0x10).0;
                let tcp_at = Header::parse_whole(&p).unwrap().payload.start;
                p.extend_from_slice(&expected[begin..begin + 4]);
                fix_lengths(&mut p, tcp_at, peer.ip(), local.ip());
                st.ingress(&fcx, &Budget::unlimited(), now, p);
                egress(&mut st, now);
                st.release_quiet();
            }
            let mut got = [0; 8];
            assert_eq!(st.sock(h).recv_slice(&mut got).unwrap(), expected.len());
            assert_eq!(&got, expected);
            if !established {
                let local = SocketAddr::new(local.ip(), local.port() + 1);
                let mut s = new_socket(MIN_BUFFER);
                s.0.connect(st.iface.context(), peer, local).unwrap();
                let h = st.add_socket(&fcx, s);
                st.conns.insert(h, Conn::new(local, peer, Side::Client));
                st.by_tuple.insert((local, peer), h);
                let packets = egress(&mut st, now);
                let t = Header::parse_whole(&packets[0])
                    .unwrap()
                    .payload(&packets[0]);
                let ack = u32::from_be_bytes(t[4..8].try_into().unwrap()).wrapping_add(1);
                let seq = irs.wrapping_sub(MIN_BUFFER as u32);
                let mut p = segment(peer, local, seq, ack, 0x16).0;
                let tcp_at = Header::parse_whole(&p).unwrap().payload.start;
                p.extend_from_slice(b"ignored");
                fix_lengths(&mut p, tcp_at, peer.ip(), local.ip());
                // RFC 9293 section 3.10.7.3 accepts RST with an acceptable ACK in SYN-SENT.
                st.ingress(&fcx, &Budget::unlimited(), now, p);
                assert_eq!(st.get(h).state(), TcpState::Closed);
                assert_eq!(st.closed_reason(h), ConnError::Reset);
                assert_eq!(st.get(h).recv_queue(), 0, "flags");
                assert!(!st.get(h).has_pending_recv(), "flags");
                assert!(!st.dirty.contains(&h), "flags");
                assert!(egress(&mut st, now).is_empty());
            }
            drop(st);
            fcx.cancel();
            Ok(())
        }))
        .unwrap();
    }
}

#[test]
fn simultaneous_open_records_the_accepted_syn_origin() {
    block_on(lab(Seed::from_u64(1), |fcx| async move {
        let (_raw, side) = pair();
        let local: SocketAddr = "10.0.0.1:1234".parse()?;
        let peer: SocketAddr = "10.0.0.2:80".parse()?;
        let ep = endpoint(&fcx, side, local.ip());
        let now = smol_now(&fcx);
        let mut st = ep.shared.lock();
        let mut s = new_socket(MIN_BUFFER);
        s.0.connect(st.iface.context(), peer, local).unwrap();
        let h = st.add_socket(&fcx, s);
        st.conns.insert(h, Conn::new(local, peer, Side::Client));
        st.by_tuple.insert((local, peer), h);
        egress(&mut st, now);
        st.ingress(
            &fcx,
            &Budget::unlimited(),
            now,
            segment(peer, local, u32::MAX, 0, 0x02).0,
        );
        assert_eq!(st.get(h).state(), TcpState::SynReceived);
        let packets = egress(&mut st, now);
        let t = Header::parse_whole(&packets[0])
            .unwrap()
            .payload(&packets[0]);
        assert_eq!(t[13], 0x12);
        assert_eq!(u32::from_be_bytes(t[8..12].try_into().unwrap()), 0);
        drop(st);
        fcx.cancel();
        Ok(())
    }))
    .unwrap();
}

#[test]
fn a_window_update_after_shutdown_retransmits_refused_data() {
    for drop_handle in [false, true] {
        window_reopens(drop_handle, b"abcdefghijkl");
    }
}

#[test]
fn a_window_update_retransmits_the_last_unacked_bytes() {
    window_reopens(false, b"abcdefgh");
}

#[test]
fn far_future_ack_does_not_free_send_buffer() {
    ack_window_boundary(7);
}

#[test]
fn wraparound_window_boundary() {
    ack_window_boundary(u32::MAX - MIN_BUFFER as u32 / 2);
}

#[test]
fn a_rejected_ack_does_not_free_send_buffer() {
    block_on(lab(Seed::from_u64(1), |fcx| async move {
        let (_raw, side) = pair();
        let local: SocketAddr = "10.0.0.1:80".parse()?;
        let peer: SocketAddr = "10.0.0.2:1234".parse()?;
        let ep = endpoint(&fcx, side, local.ip());
        let _listener = ep.listen(local.port())?;
        let now = smol_now(&fcx);
        let mut st = ep.shared.lock();
        // No window has been advertised for this tuple.
        st.ingress(
            &fcx,
            &Budget::unlimited(),
            now,
            segment(peer, local, 102, 100, 0x10).0,
        );
        let packets = egress(&mut st, now);
        assert_eq!(packets.len(), 1);
        assert_eq!(
            Header::parse_whole(&packets[0])
                .unwrap()
                .payload(&packets[0])[13],
            4
        );
        assert!(!st.by_tuple.contains_key(&(local, peer)));
        let (h, start) = established(&mut st, now, local, peer);
        assert_eq!(st.sock(h).send_slice(b"abcdefgh").unwrap(), 8);
        egress(&mut st, now);
        for (seq, corrupt) in [(102, true), (100, false)] {
            let mut p = segment(peer, local, seq, start.wrapping_add(4), 0x10).0;
            if corrupt {
                p[36] ^= 1;
            }
            st.ingress(&fcx, &Budget::unlimited(), now, p);
            assert_eq!(st.get(h).send_queue(), 8);
            assert_eq!(st.get(h).recv_queue(), 0);
            let packets = egress(&mut st, now);
            if corrupt {
                assert!(packets.is_empty());
            } else {
                assert_eq!(packets.len(), 1);
                let t = Header::parse_whole(&packets[0])
                    .unwrap()
                    .payload(&packets[0]);
                assert_eq!(u32::from_be_bytes(t[8..12].try_into().unwrap()), 101);
            }
        }
        st.ingress(
            &fcx,
            &Budget::unlimited(),
            now,
            segment(peer, local, 101, start.wrapping_add(4), 0x10).0,
        );
        assert_eq!(st.get(h).send_queue(), 4);
        drop(st);
        fcx.cancel();
        Ok(())
    }))
    .unwrap();
}

/// Bytes the peer sent before its FIN were acknowledged, so they stay
/// readable after TIME-WAIT ends, as a kernel keeps them until the
/// application closes the socket. The application reads them, then
/// end of stream.
#[test]
fn unread_bytes_outlive_time_wait() {
    block_on(lab(Seed::from_u64(1), |fcx| async move {
        let (_raw, side) = pair();
        let local: SocketAddr = "10.0.0.1:80".parse()?;
        let peer: SocketAddr = "10.0.0.2:1234".parse()?;
        let ep = endpoint(&fcx, side, local.ip());
        let _listener = ep.listen(local.port())?;
        let now = smol_now(&fcx);
        let mut conn = {
            let mut st = ep.shared.lock();
            let (h, ack) = established(&mut st, now, local, peer);
            let conn = accept_by_hand(&ep, &mut st, h);
            // This side shuts down first; the peer answers with its last
            // bytes, its FIN and the ACK of this side's FIN.
            st.conns.get_mut(&h).unwrap().shut = true;
            st.close_if_drained(h);
            egress(&mut st, now);
            let mut last = segment(peer, local, 101, ack.wrapping_add(1), 0x19).0;
            last.extend_from_slice(b"last words");
            fix_lengths(&mut last, 20, peer.ip(), local.ip());
            st.ingress(&fcx, &Budget::unlimited(), now, last);
            assert_eq!(st.get(h).state(), TcpState::TimeWait);
            assert_eq!(st.get(h).recv_queue(), 10);
            egress(&mut st, now);
            // The application reads only after TIME-WAIT is over.
            egress(&mut st, now + smoltcp::time::Duration::from_secs(241));
            assert_eq!(st.get(h).state(), TcpState::Closed);
            st.housekeeping();
            conn
        };
        let mut buf = [0; 32];
        let n = conn.read(&fcx, &mut buf).await?;
        assert_eq!(&buf[..n], b"last words");
        assert_eq!(conn.read(&fcx, &mut buf).await?, 0);
        drop(conn);
        fcx.cancel();
        Ok(())
    }))
    .unwrap();
}

#[test]
fn client_advertised_window_uses_negotiated_scale() {
    for scaled in [false, true] {
        block_on(lab(Seed::from_u64(1), move |fcx| async move {
            let (_raw, side) = pair();
            let local: SocketAddr = "10.0.0.1:1234".parse()?;
            let peer: SocketAddr = "10.0.0.2:80".parse()?;
            let ep = endpoint(&fcx, side, local.ip());
            let now = smol_now(&fcx);
            let mut st = ep.shared.lock();
            let mut socket = new_socket(BUFFER);
            socket.0.connect(st.iface.context(), peer, local).unwrap();
            let h = st.add_socket(&fcx, socket);
            st.conns.insert(h, Conn::new(local, peer, Side::Client));
            st.by_tuple.insert((local, peer), h);
            let packets = egress(&mut st, now);
            let t = Header::parse_whole(&packets[0])
                .unwrap()
                .payload(&packets[0]);
            assert_eq!(
                TcpPacket::new_unchecked(t)
                    .options_summary()
                    .unwrap()
                    .window_scale,
                Some(3)
            );
            assert_eq!(t[13] & 16, 0, "a SYN has no ACK");
            let start = st.conns[&h].iss.unwrap().wrapping_add(1);
            let mut p = segment(peer, local, 7, start, 0x12).0;
            if scaled {
                p[32] = 6 << 4;
                p.extend_from_slice(&[1, 3, 3, 7]);
                fix_lengths(&mut p, 20, peer.ip(), local.ip());
            }
            st.ingress(&fcx, &Budget::unlimited(), now, p);
            assert_eq!(st.get(h).state(), TcpState::Established);
            let packets = egress(&mut st, now);
            let t = Header::parse_whole(&packets[0])
                .unwrap()
                .payload(&packets[0]);
            let shift = if scaled { 3 } else { 0 };
            let win = (u16::from_be_bytes([t[14], t[15]]) as u32) << shift;
            assert_eq!(win, if scaled { BUFFER as u32 } else { 65535 });
            assert_eq!(
                u32::from_be_bytes(t[8..12].try_into().unwrap()).wrapping_add(win),
                8 + win
            );
            drop(st);
            fcx.cancel();
            Ok(())
        }))
        .unwrap();
    }
}

#[test]
fn legitimate_rounded_window_recovery() {
    for irs in [7u32, u32::MAX - BUFFER as u32 / 2] {
        block_on(lab(Seed::from_u64(1), move |fcx| async move {
            let (_raw, side) = pair();
            let local: SocketAddr = "10.0.0.1:80".parse()?;
            let peer: SocketAddr = "10.0.0.2:1234".parse()?;
            let ep = endpoint(&fcx, side, local.ip());
            let _listener = ep.listen(local.port())?;
            let now = smol_now(&fcx);
            let mut st = ep.shared.lock();
            let mut syn = segment(peer, local, irs, 0, 0x02).0;
            syn[32] = 6 << 4;
            syn.extend_from_slice(&[1, 3, 3, 7]);
            fix_lengths(&mut syn, 20, peer.ip(), local.ip());
            st.ingress(&fcx, &Budget::unlimited(), now, syn);
            let syn_ack = egress(&mut st, now).remove(0);
            let t = Header::parse_whole(&syn_ack).unwrap().payload(&syn_ack);
            let start = u32::from_be_bytes(t[4..8].try_into().unwrap()).wrapping_add(1);
            let origin = irs.wrapping_add(1);
            let h = st.by_tuple[&(local, peer)];
            assert_eq!(
                TcpPacket::new_unchecked(t)
                    .options_summary()
                    .unwrap()
                    .window_scale,
                Some(3)
            );
            assert_eq!(
                u32::from_be_bytes(t[8..12].try_into().unwrap())
                    .wrapping_add(u16::from_be_bytes([t[14], t[15]]) as u32),
                origin.wrapping_add(65535)
            );
            st.ingress(
                &fcx,
                &Budget::unlimited(),
                now,
                segment(peer, local, origin, start, 0x10).0,
            );
            st.sock(h).set_ack_delay(None);
            assert_eq!(st.sock(h).send_slice(b"abcdefgh").unwrap(), 8);
            let sent = egress(&mut st, now);
            assert!(sent.iter().any(|p| {
                let t = Header::parse_whole(p).unwrap().payload(p);
                &t[((t[12] >> 4) as usize) * 4..] == b"abcdefgh"
            }));
            let edge = origin.wrapping_add(BUFFER as u32);
            let t = Header::parse_whole(&sent[0]).unwrap().payload(&sent[0]);
            assert_eq!(
                u32::from_be_bytes(t[8..12].try_into().unwrap())
                    .wrapping_add((u16::from_be_bytes([t[14], t[15]]) as u32) << 3),
                edge
            );
            let expected = pattern(BUFFER, 7);
            let incoming = |begin: usize, end: usize, ack: u32| {
                let mut p = segment(peer, local, origin.wrapping_add(begin as u32), ack, 0x10).0;
                p.extend_from_slice(&expected[begin..end]);
                fix_lengths(&mut p, 20, peer.ip(), local.ip());
                p
            };
            // Fill to the advertised edge out of order, leaving two
            // bytes missing. Then advance the ACK by just one byte.
            for begin in (2..BUFFER).step_by(1024) {
                st.ingress(
                    &fcx,
                    &Budget::unlimited(),
                    now,
                    incoming(begin, (begin + 1024).min(BUFFER), start),
                );
                egress(&mut st, now);
            }
            assert_eq!(st.get(h).recv_queue(), 0);
            st.ingress(&fcx, &Budget::unlimited(), now, incoming(0, 1, start));
            let sent = egress(&mut st, now);
            let t = Header::parse_whole(sent.last().unwrap())
                .unwrap()
                .payload(sent.last().unwrap());
            let ack = u32::from_be_bytes(t[8..12].try_into().unwrap());
            let win = (u16::from_be_bytes([t[14], t[15]]) as u32) << 3;
            assert_eq!(ack, origin.wrapping_add(1));
            assert_eq!(ack.wrapping_add(win), edge.wrapping_sub(7));
            assert_eq!(st.get(h).recv_queue(), 1);
            // The peer is at the old edge. An ACK outside our send
            // range must still be rejected even at that sequence.
            st.ingress(
                &fcx,
                &Budget::unlimited(),
                now,
                segment(peer, local, edge, start.wrapping_add(9), 0x10).0,
            );
            assert_eq!(st.get(h).send_queue(), 8);
            st.ingress(
                &fcx,
                &Budget::unlimited(),
                now,
                segment(peer, local, edge, start.wrapping_add(4), 0x10).0,
            );
            assert_eq!(
                st.get(h).send_queue(),
                4,
                "the rounded window must not strand ACKs"
            );
            st.ingress(
                &fcx,
                &Budget::unlimited(),
                now,
                incoming(1, 2, start.wrapping_add(4)),
            );
            assert_eq!(
                st.get(h).recv_queue(),
                BUFFER,
                "the hole's retransmission must be accepted"
            );
            let mut got = vec![0; BUFFER];
            assert_eq!(st.sock(h).recv_slice(&mut got).unwrap(), BUFFER);
            assert_eq!(got, expected);
            let sent = egress(&mut st, now);
            let t = Header::parse_whole(sent.last().unwrap())
                .unwrap()
                .payload(sent.last().unwrap());
            assert_eq!(
                u32::from_be_bytes(t[8..12].try_into().unwrap())
                    .wrapping_add((u16::from_be_bytes([t[14], t[15]]) as u32) << 3),
                edge.wrapping_add(BUFFER as u32)
            );
            drop(st);
            fcx.cancel();
            Ok(())
        }))
        .unwrap();
    }
}

fn ack_window_boundary(irs: u32) {
    for reopened in [false, true] {
        block_on(lab(Seed::from_u64(1), move |fcx| async move {
            let (_raw, side) = pair();
            let local: SocketAddr = "10.0.0.1:80".parse()?;
            let peer: SocketAddr = "10.0.0.2:1234".parse()?;
            let ep = endpoint_with(
                &fcx,
                side,
                local.ip(),
                Options::default().buffer(MIN_BUFFER),
            );
            let _listener = ep.listen(local.port())?;
            let now = smol_now(&fcx);
            let mut st = ep.shared.lock();
            st.ingress(
                &fcx,
                &Budget::unlimited(),
                now,
                segment(peer, local, irs, 0, 0x02).0,
            );
            let syn_ack = egress(&mut st, now).remove(0);
            let t = Header::parse_whole(&syn_ack).unwrap().payload(&syn_ack);
            let start = u32::from_be_bytes(t[4..8].try_into().unwrap()).wrapping_add(1);
            let rcv_nxt = irs.wrapping_add(1);
            let edge = rcv_nxt.wrapping_add(u16::from_be_bytes([t[14], t[15]]) as u32);
            assert_eq!(edge, rcv_nxt.wrapping_add(MIN_BUFFER as u32));
            st.ingress(
                &fcx,
                &Budget::unlimited(),
                now,
                segment(peer, local, rcv_nxt, start, 0x10).0,
            );
            let h = st.by_tuple[&(local, peer)];
            assert_eq!(st.get(h).state(), TcpState::Established);
            assert_eq!(
                st.sock(h).send_slice(&vec![0x5a; MIN_BUFFER]).unwrap(),
                MIN_BUFFER
            );
            let sent = egress(&mut st, now);
            assert!(sent.iter().any(|p| {
                let t = Header::parse_whole(p).unwrap().payload(p);
                t.len() - ((t[12] >> 4) as usize) * 4 >= 4
            }));
            if reopened {
                let mut p = segment(peer, local, rcv_nxt, start, 0x10).0;
                p[34..36].copy_from_slice(&0u16.to_be_bytes());
                fix_lengths(&mut p, 20, peer.ip(), local.ip());
                st.ingress(&fcx, &Budget::unlimited(), now, p);
                egress(&mut st, now);
            }
            for seq in [rcv_nxt.wrapping_add(10_000_000), edge.wrapping_add(1), edge] {
                let p = segment(peer, local, seq, start.wrapping_add(4), 0x10).0;
                st.ingress(&fcx, &Budget::unlimited(), now, p);
                let accepted = seq == edge;
                assert_eq!(
                    st.get(h).send_queue(),
                    MIN_BUFFER - if accepted { 4 } else { 0 },
                    "seq={seq}, edge={edge}, reopened={reopened}"
                );
                if !accepted && reopened {
                    assert!(
                        egress(&mut st, now).iter().all(|p| {
                            let t = Header::parse_whole(p).unwrap().payload(p);
                            t.len() == ((t[12] >> 4) as usize) * 4
                        }),
                        "an out-of-window ACK must not reopen the send window"
                    );
                }
            }
            drop(st);
            fcx.cancel();
            Ok(())
        }))
        .unwrap();
    }
}

#[test]
fn sack_ack_ahead_without_advertised_window_is_unchanged() {
    block_on(lab(Seed::from_u64(1), |fcx| async move {
        let (_raw, side) = pair();
        let local: SocketAddr = "10.0.0.1:80".parse()?;
        let peer: SocketAddr = "10.0.0.2:1234".parse()?;
        let ep = endpoint(&fcx, side, local.ip());
        let _listener = ep.listen(local.port())?;
        let now = smol_now(&fcx);
        let mut st = ep.shared.lock();
        let mut p = segment(peer, local, 9, 100, 0x10).0;
        p[32] = 8 << 4;
        p[34..36].copy_from_slice(&456u16.to_be_bytes());
        p.extend_from_slice(&[5, 10, 0, 0, 0, 104, 0, 0, 0, 105, 0, 0]);
        fix_lengths(&mut p, 20, peer.ip(), local.ip());
        st.ingress(&fcx, &Budget::unlimited(), now, p);
        assert!(!st.by_tuple.contains_key(&(local, peer)));
        let packets = egress(&mut st, now);
        assert_eq!(packets.len(), 1);
        let t = Header::parse_whole(&packets[0])
            .unwrap()
            .payload(&packets[0]);
        assert_eq!(t[13], 4);
        assert_eq!(u32::from_be_bytes(t[4..8].try_into().unwrap()), 100);
        assert_eq!(transport_checksum(local.ip(), peer.ip(), TCP, t), 0);
        drop(st);
        fcx.cancel();
        Ok(())
    }))
    .unwrap();
}

#[test]
fn sack_acks_preserve_zero_window_changes() {
    for (old, win) in [(123u16, 0u16), (0, 123), (123, 456)] {
        block_on(lab(Seed::from_u64(1), |fcx| async move {
            let (_raw, side) = pair();
            let local: SocketAddr = "10.0.0.1:80".parse()?;
            let peer: SocketAddr = "10.0.0.2:1234".parse()?;
            let ep = endpoint(&fcx, side, local.ip());
            let _listener = ep.listen(local.port())?;
            let now = smol_now(&fcx);
            let mut st = ep.shared.lock();
            let mut syn = segment(peer, local, 7, 0, 2).0;
            syn[32] = 6 << 4;
            syn.extend_from_slice(&[4, 2, 0, 0]);
            fix_lengths(&mut syn, 20, peer.ip(), local.ip());
            st.ingress(&fcx, &Budget::unlimited(), now, syn);
            let packets = egress(&mut st, now);
            let t = Header::parse_whole(&packets[0])
                .unwrap()
                .payload(&packets[0]);
            assert!(
                TcpPacket::new_unchecked(t)
                    .options_summary()
                    .unwrap()
                    .sack_permitted
            );
            let start = u32::from_be_bytes(t[4..8].try_into().unwrap()).wrapping_add(1);
            st.ingress(
                &fcx,
                &Budget::unlimited(),
                now,
                segment(peer, local, 8, start, 16).0,
            );
            let h = st.by_tuple[&(local, peer)];
            let ack = |window: u16, sack: bool| {
                let mut p = segment(peer, local, 8, start, 16).0;
                p[34..36].copy_from_slice(&window.to_be_bytes());
                if sack {
                    p[32] = 8 << 4;
                    p.extend_from_slice(&[5, 10]);
                    p.extend_from_slice(&start.wrapping_add(4).to_be_bytes());
                    p.extend_from_slice(&start.wrapping_add(5).to_be_bytes());
                    p.extend_from_slice(&[0, 0]);
                }
                fix_lengths(&mut p, 20, peer.ip(), local.ip());
                p
            };
            st.ingress(&fcx, &Budget::unlimited(), now, ack(old, false));
            assert_eq!(st.sock(h).send_slice(b"abcdefgh").unwrap(), 8);
            let packets = egress(&mut st, now);
            assert_eq!(packets.len(), usize::from(old != 0));
            if old != 0 {
                let t = Header::parse_whole(&packets[0])
                    .unwrap()
                    .payload(&packets[0]);
                assert_eq!(&t[((t[12] >> 4) as usize) * 4..], b"abcdefgh");
            }
            for i in 0..3 {
                // Changing nonzero windows still count toward fast retransmit.
                st.ingress(
                    &fcx,
                    &Budget::unlimited(),
                    now,
                    ack(if win == 456 { win - i } else { win }, true),
                );
                let packets = egress(&mut st, now);
                let sends = old == 0 && i == 0 || old != 0 && win != 0 && i == 2;
                assert_eq!(packets.len(), usize::from(sends));
                for p in packets {
                    let t = Header::parse_whole(&p).unwrap().payload(&p);
                    assert_eq!(u32::from_be_bytes(t[4..8].try_into().unwrap()), start);
                    assert_eq!(&t[((t[12] >> 4) as usize) * 4..], b"abcdefgh");
                    assert_eq!(transport_checksum(local.ip(), peer.ip(), TCP, t), 0);
                }
            }
            assert_eq!(st.get(h).send_queue(), 8);
            drop(st);
            fcx.cancel();
            Ok(())
        }))
        .unwrap();
    }
}

#[test]
fn payload_at_buffer_end_preserves_data_and_defers_fin() {
    for (local, peer) in [
        ("10.0.0.1:80", "10.0.0.2:1234"),
        ("[fd00::1]:80", "[fd00::2]:1234"),
    ] {
        let local: SocketAddr = local.parse().unwrap();
        let peer: SocketAddr = peer.parse().unwrap();
        for (offset, keep) in [(-10i32, 10usize), (0, 0), (10, 0), (-20, 20)] {
            block_on(lab(Seed::from_u64(1), |fcx| async move {
                let (_raw, side) = pair();
                let ep = endpoint_with(
                    &fcx,
                    side,
                    local.ip(),
                    Options::default().buffer(MIN_BUFFER),
                );
                let _listener = ep.listen(local.port())?;
                let now = smol_now(&fcx);
                let mut st = ep.shared.lock();
                let irs = u32::MAX - MIN_BUFFER as u32;
                let origin = irs.wrapping_add(1);
                st.ingress(
                    &fcx,
                    &Budget::unlimited(),
                    now,
                    segment(peer, local, irs, 0, 2).0,
                );
                let packets = egress(&mut st, now);
                let t = Header::parse_whole(&packets[0])
                    .unwrap()
                    .payload(&packets[0]);
                let start = u32::from_be_bytes(t[4..8].try_into().unwrap()).wrapping_add(1);
                st.ingress(
                    &fcx,
                    &Budget::unlimited(),
                    now,
                    segment(peer, local, origin, start, 16).0,
                );
                let h = st.by_tuple[&(local, peer)];
                st.sock(h).set_ack_delay(None);
                let expected = pattern(MIN_BUFFER + 49, 7);
                let incoming = |begin: usize, end: usize, fin: bool| {
                    let mut p = segment(
                        peer,
                        local,
                        origin.wrapping_add(begin as u32),
                        start,
                        16 | u8::from(fin),
                    )
                    .0;
                    let tcp_at = Header::parse_whole(&p).unwrap().payload.start;
                    p.extend_from_slice(&expected[begin..end]);
                    fix_lengths(&mut p, tcp_at, peer.ip(), local.ip());
                    p
                };
                st.ingress(&fcx, &Budget::unlimited(), now, incoming(0, 19, false));
                egress(&mut st, now);
                let mut prefix = [0; 19];
                assert_eq!(st.sock(h).recv_slice(&mut prefix).unwrap(), 19);
                assert_eq!(prefix, expected[..19]);
                // A duplicate elicits the window opened by the read.
                st.ingress(&fcx, &Budget::unlimited(), now, incoming(0, 19, false));
                egress(&mut st, now);
                let edge = 19 + MIN_BUFFER;
                let begin = edge.checked_add_signed(offset as isize).unwrap();
                let p = incoming(begin, begin + 20, true);
                let mut bad = p.clone();
                let tcp_at = Header::parse_whole(&bad).unwrap().payload.start;
                bad[tcp_at + 16] ^= 1;
                st.ingress(&fcx, &Budget::unlimited(), now, bad);
                assert!(egress(&mut st, now).is_empty());
                assert_eq!(st.get(h).recv_queue(), 0);
                assert!(!st.get(h).has_pending_recv());
                assert!(!st.conns[&h].fin);
                st.ingress(&fcx, &Budget::unlimited(), now, p);
                assert_eq!(st.get(h).recv_queue(), 0);
                assert_eq!(st.get(h).has_pending_recv(), keep != 0);
                assert_eq!(st.get(h).state(), TcpState::Established);
                assert!(!st.conns[&h].fin);
                let packets = egress(&mut st, now);
                assert_eq!(packets.len(), 1);
                let t = Header::parse_whole(&packets[0])
                    .unwrap()
                    .payload(&packets[0]);
                assert_eq!(
                    u32::from_be_bytes(t[8..12].try_into().unwrap()),
                    origin.wrapping_add(19)
                );
                assert_eq!(transport_checksum(local.ip(), peer.ip(), TCP, t), 0);
                let gap_end = edge - keep;
                for at in (19..gap_end).step_by(1024) {
                    st.ingress(
                        &fcx,
                        &Budget::unlimited(),
                        now,
                        incoming(at, (at + 1024).min(gap_end), false),
                    );
                    egress(&mut st, now);
                }
                let mut got = vec![0; MIN_BUFFER];
                assert_eq!(st.sock(h).recv_slice(&mut got).unwrap(), MIN_BUFFER);
                assert_eq!(got, expected[19..edge]);
                assert!(!st.conns[&h].fin);
                egress(&mut st, now);
                // The discarded tail and FIN fit after the application reads.
                st.ingress(
                    &fcx,
                    &Budget::unlimited(),
                    now,
                    incoming(edge, begin + 20, true),
                );
                let packets = egress(&mut st, now);
                assert_eq!(packets.len(), 1);
                let t = Header::parse_whole(&packets[0])
                    .unwrap()
                    .payload(&packets[0]);
                assert_eq!(
                    u32::from_be_bytes(t[8..12].try_into().unwrap()),
                    origin.wrapping_add((begin + 21) as u32)
                );
                assert_eq!(transport_checksum(local.ip(), peer.ip(), TCP, t), 0);
                let mut tail = [0; 30];
                if begin + 20 != edge {
                    let len = st.sock(h).recv_slice(&mut tail).unwrap();
                    assert_eq!(len, begin + 20 - edge);
                    assert_eq!(&tail[..len], &expected[edge..begin + 20]);
                }
                assert_eq!(
                    st.sock(h).recv_slice(&mut tail),
                    Err(stcp::RecvError::Finished)
                );
                assert!(st.conns[&h].fin);
                drop(st);
                fcx.cancel();
                Ok(())
            }))
            .unwrap();
        }
    }
}

#[test]
fn scaled_syn_ack_data_crossing_buffer_end() {
    scaled_syn_ack_buffer_end(false);
}

#[test]
fn scaled_syn_ack_data_past_buffer_end() {
    scaled_syn_ack_buffer_end(true);
}

fn scaled_syn_ack_buffer_end(read_as_received: bool) {
    for (local, peer) in [
        ("10.0.0.1:80", "10.0.0.2:1234"),
        ("[fd00::1]:80", "[fd00::2]:1234"),
    ] {
        let local: SocketAddr = local.parse().unwrap();
        let peer: SocketAddr = peer.parse().unwrap();
        let result = block_on(run(fictionet::Seed::random(), move |fcx| async move {
            let (side, _raw) = pair();
            let server = endpoint_with(&fcx, side, local.ip(), Options::default());
            let mut listener = server.listen(local.port())?;
            let now = smoltcp::time::Instant::from_millis(100);
            let tcp_at = if local.is_ipv4() { 20 } else { 40 };
            // Cross sequence number zero while filling the buffer.
            let irs = u32::MAX - 131072;
            let start = {
                let mut syn = segment(peer, local, irs, 0, 0x02).0;
                syn[tcp_at + 12] = 6 << 4;
                syn.extend_from_slice(&[1, 3, 3, 7]);
                fix_lengths(&mut syn, tcp_at, peer.ip(), local.ip());
                let mut st = server.shared.lock();
                st.ingress(&fcx, &Budget::unlimited(), now, syn);
                let packets = egress(&mut st, now);
                let t = Header::parse_whole(&packets[0])
                    .unwrap()
                    .payload(&packets[0]);
                assert_eq!(t[13], 0x12);
                let start = u32::from_be_bytes(t[4..8].try_into().unwrap()).wrapping_add(1);
                st.ingress(
                    &fcx,
                    &Budget::unlimited(),
                    now,
                    segment(peer, local, irs.wrapping_add(1), start, 0x10).0,
                );
                st.housekeeping();
                egress(&mut st, now);
                start
            };
            let mut conn = listener.accept(&fcx).await?;
            let capacity = {
                let st = server.shared.lock();
                st.get(st.socket_of(conn.id)).recv_capacity()
            };
            assert_eq!(capacity, 256 * 1024);
            // Vary the pattern across buffer laps so overwritten bytes differ.
            let expected: Vec<u8> = (0..(capacity + 4096).div_ceil(997))
                .flat_map(|i| pattern(997, i as u8))
                .collect();
            let incoming = |begin: usize, end: usize| {
                let seq = irs.wrapping_add(1).wrapping_add(begin as u32);
                let mut p = segment(peer, local, seq, start, 0x10).0;
                p.extend_from_slice(&expected[begin..end]);
                fix_lengths(&mut p, tcp_at, peer.ip(), local.ip());
                let mut st = server.shared.lock();
                st.ingress(&fcx, &Budget::unlimited(), now, p);
                egress(&mut st, now);
            };
            let ahead = if read_as_received {
                capacity + 37
            } else {
                capacity - 37
            };
            incoming(ahead, ahead + 100);
            let mut got = vec![0; expected.len()];
            let mut read = 0;
            let first_end = if read_as_received {
                expected.len()
            } else {
                ahead
            };
            for begin in (0..first_end).step_by(1024) {
                let end = (begin + 1024).min(first_end);
                incoming(begin, end);
                if read_as_received {
                    while read < end {
                        let n = conn.read(&fcx, &mut got[read..end]).await?;
                        assert!(n > 0);
                        read += n;
                    }
                    assert_eq!(
                        got[..end],
                        expected[..end],
                        "stream differs at offset {begin}"
                    );
                }
            }
            if !read_as_received {
                while read < capacity {
                    let n = conn.read(&fcx, &mut got[read..capacity]).await?;
                    assert!(n > 0);
                    read += n;
                }
                assert_eq!(got[..capacity], expected[..capacity]);
                // Resend the trimmed tail once application reads make room.
                egress(&mut server.shared.lock(), now);
                incoming(capacity, expected.len());
                while read < expected.len() {
                    let n = conn.read(&fcx, &mut got[read..]).await?;
                    assert!(n > 0);
                    read += n;
                }
            }
            assert_eq!(got, expected);
            Err::<(), fictionet::Error>(fictionet::Error::msg("done"))
        }));
        assert_eq!(result.unwrap_err().to_string(), "done");
    }
}

fn window_reopens(drop_handle: bool, data: &'static [u8]) {
    let result = block_on(run(fictionet::Seed::random(), move |fcx| async move {
        let (side, _raw) = pair();
        let local: SocketAddr = "10.0.0.1:80".parse().unwrap();
        let peer: SocketAddr = "10.0.0.2:1234".parse().unwrap();
        let server = endpoint(&fcx, side, local.ip());
        let mut listener = server.listen(local.port())?;
        let now = smoltcp::time::Instant::from_millis(100);
        let incoming = |seq, ack, flags, win: u16| {
            let mut p = segment(peer, local, seq, ack, flags).0;
            p[34..36].copy_from_slice(&win.to_be_bytes());
            fix_lengths(&mut p, 20, peer.ip(), local.ip());
            p
        };
        let start = {
            let mut st = server.shared.lock();
            st.ingress(&fcx, &Budget::unlimited(), now, incoming(7, 0, 0x02, 8));
            let packets = egress(&mut st, now);
            let t = Header::parse_whole(&packets[0])
                .unwrap()
                .payload(&packets[0]);
            assert_eq!(t[13], 0x12);
            let start = u32::from_be_bytes(t[4..8].try_into().unwrap()).wrapping_add(1);
            // The peer closes its send half before reading the reply.
            st.ingress(&fcx, &Budget::unlimited(), now, incoming(8, start, 0x11, 8));
            st.housekeeping();
            egress(&mut st, now);
            start
        };
        let mut conn = listener.accept(&fcx).await?;
        let h = server.shared.lock().socket_of(conn.id);
        conn.write_all(&fcx, data).await?;
        if drop_handle {
            drop(conn);
        } else {
            conn.shutdown(&fcx).await?;
            assert_eq!(conn.write_all(&fcx, b"late").await, Err(ConnError::Closed));
        }
        let mut st = server.shared.lock();
        let sent = egress(&mut st, now);
        assert!(sent.iter().any(|p| {
            let t = Header::parse_whole(p).unwrap().payload(p);
            t[((t[12] >> 4) as usize) * 4..] == data[..8]
        }));
        // Only the first four bytes arrived. The other four were sent
        // on a stale window and refused after the window closed.
        st.ingress(
            &fcx,
            &Budget::unlimited(),
            now,
            incoming(9, start.wrapping_add(4), 0x10, 0),
        );
        assert_eq!(st.get(h).send_queue(), data.len() - 4);
        egress(&mut st, now);
        st.ingress(
            &fcx,
            &Budget::unlimited(),
            now,
            incoming(9, start.wrapping_add(4), 0x10, 32768),
        );
        let sent = egress(&mut st, now);
        drop(st);
        assert!(
            sent.iter().any(|p| {
                let t = Header::parse_whole(p).unwrap().payload(p);
                u32::from_be_bytes(t[4..8].try_into().unwrap()) == start.wrapping_add(4)
                    && t[((t[12] >> 4) as usize) * 4..].starts_with(b"efgh")
            }),
            "the refused bytes must be retransmitted when the window opens"
        );
        // The FIN follows the data's ACK, so a hole cannot hide it.
        assert!(
            sent.iter()
                .all(|p| Header::parse_whole(p).unwrap().payload(p)[13] & 1 == 0)
        );
        let end = start.wrapping_add(data.len() as u32);
        let mut st = server.shared.lock();
        st.ingress(
            &fcx,
            &Budget::unlimited(),
            now,
            incoming(9, end, 0x10, 32768),
        );
        let sent = egress(&mut st, now);
        assert!(
            sent.iter().any(|p| {
                let t = Header::parse_whole(p).unwrap().payload(p);
                t[13] & 1 != 0 && u32::from_be_bytes(t[4..8].try_into().unwrap()) == end
            }),
            "all data was acknowledged, so the FIN must follow"
        );
        st.ingress(
            &fcx,
            &Budget::unlimited(),
            now,
            incoming(9, end.wrapping_add(1), 0x10, 32768),
        );
        assert_eq!(st.get(h).state(), TcpState::Closed);
        drop(st);
        Err::<(), fictionet::Error>(fictionet::Error::msg("done"))
    }));
    assert_eq!(result.unwrap_err().to_string(), "done");
}

/// A listening port holds at most its backlog of connections not
/// accepted yet. Further SYNs get SYN cookies, until the connections
/// waiting for accept alone fill the backlog: then SYNs, and ACKs that
/// return cookies, are dropped until accept takes one.
#[test]
fn syns_past_the_backlog_get_cookies_until_accept_falls_behind() {
    assert_eq!(Options::default().backlog, 4096);
    assert_eq!(
        (
            Options::default().backlog(0).backlog,
            Options::default().backlog(1 << 20).backlog
        ),
        (1, MAX_BACKLOG)
    );
    block_on(lab(Seed::from_u64(1), |fcx| async move {
        let (mut raw, side) = pair();
        let server = endpoint_with(
            &fcx,
            side,
            "10.0.0.1".parse().unwrap(),
            cookie_options().backlog(4),
        );
        let mut listener = server.listen(80)?;
        let to: SocketAddr = "10.0.0.1:80".parse().unwrap();
        let from = |port| SocketAddr::new("10.0.0.2".parse().unwrap(), port);
        for port in 1000..1010u16 {
            raw.send(segment(from(port), to, 7, 0, 0x02));
        }
        let mut iss = BTreeMap::new();
        while iss.len() < 10 {
            let p = raw.recv(&fcx).await?;
            let t = Header::parse_whole(&p.0).unwrap().payload(&p.0).to_vec();
            assert_eq!(t[13], 0x12, "a SYN-ACK");
            let port = u16::from_be_bytes([t[2], t[3]]);
            iss.insert(port, u32::from_be_bytes([t[4], t[5], t[6], t[7]]));
        }
        for (&port, &iss) in &iss {
            raw.send(segment(from(port), to, 8, iss.wrapping_add(1), 0x10));
        }
        /// Whether a second passes with nothing from the endpoint.
        async fn quiet(fcx: &Cx, raw: &mut crate::End) -> bool {
            let deadline = fcx.now() + Duration::from_secs(1);
            fcx.race(Some(deadline), raw.recv(fcx)).await.is_err()
        }
        assert!(
            quiet(&fcx, &mut raw).await,
            "cookie ACKs past a full queue are dropped"
        );
        assert_eq!(server.shared.lock().listeners[&80].ready.len(), 4);
        raw.send(segment(from(2000), to, 7, 0, 0x02));
        assert!(
            quiet(&fcx, &mut raw).await,
            "a SYN to a full queue is dropped"
        );

        let first = listener.accept(&fcx).await?;
        assert_eq!(first.peer_addr().port(), 1000);
        raw.send(segment(from(1009), to, 8, iss[&1009].wrapping_add(1), 0x10));
        let mut ports = Vec::new();
        for _ in 0..4 {
            ports.push(listener.accept(&fcx).await?.peer_addr().port());
        }
        assert_eq!(ports, [1001, 1002, 1003, 1009]);
        fcx.cancel();
        Ok(())
    }))
    .unwrap();
}

#[test]
fn spoofed_syns_cannot_block_a_real_peer_cookie_handshake() {
    block_on(lab(Seed::from_u64(1), |fcx| async move {
        let (_raw, side) = pair();
        let local: SocketAddr = "10.0.0.1:80".parse()?;
        let peer = |port| SocketAddr::new("10.0.0.2".parse().unwrap(), port);
        let server = endpoint_with(&fcx, side, local.ip(), cookie_options());
        let mut listener = server.listen(local.port())?;
        let now = smol_now(&fcx);
        {
            let mut st = server.shared.lock();
            for port in 1000..1000 + BACKLOG_PER_PEER as u16 {
                st.ingress(
                    &fcx,
                    &Budget::unlimited(),
                    now,
                    segment(peer(port), local, 7, 0, 0x02).0,
                );
                egress(&mut st, now);
            }
            st.ingress(
                &fcx,
                &Budget::unlimited(),
                now,
                segment(peer(9000), local, 0, 0, 0x02).0,
            );
            let packets = egress(&mut st, now);
            assert_eq!(packets.len(), 1);
            let t = Header::parse_whole(&packets[0])
                .unwrap()
                .payload(&packets[0]);
            assert_eq!(t[13], 0x12);
            let iss = u32::from_be_bytes(t[4..8].try_into().unwrap());
            assert_eq!(st.listeners[&80].embryonic.len(), BACKLOG_PER_PEER);
            st.ingress(
                &fcx,
                &Budget::unlimited(),
                now,
                segment(peer(9000), local, 1, iss.wrapping_add(1), 0x10).0,
            );
            assert_eq!(st.listeners[&80].ready.len(), 1);
        }
        let accepted = listener.accept(&fcx).await?;
        let handshake = accepted.handshake().unwrap();
        assert_eq!(handshake.origin, HandshakeOrigin::Cookie);
        assert_eq!(handshake.irs, 0);
        assert!(handshake.syn.is_none());
        fcx.cancel();
        Ok(())
    }))
    .unwrap();
}

/// The connections waiting for accept never outnumber the backlog, whether
/// a handshake was kept or answered with a cookie. Two kept handshakes
/// and one cookie fill a backlog of two the moment the cookie's ACK and
/// one kept ACK arrive; the other kept ACK waits, and completes once
/// accept has taken one.
#[test]
fn kept_handshakes_complete_only_while_the_backlog_has_room() {
    block_on(lab(Seed::from_u64(1), |fcx| async move {
        let (_raw, side) = pair();
        let local: SocketAddr = "10.0.0.1:80".parse()?;
        let peer = |port| SocketAddr::new("10.0.0.2".parse().unwrap(), port);
        let server = endpoint_with(&fcx, side, local.ip(), cookie_options().backlog(2));
        let mut listener = server.listen(local.port())?;
        let now = smol_now(&fcx);
        let syn_ack_iss = |packets: Vec<Vec<u8>>| {
            assert_eq!(packets.len(), 1);
            let t = Header::parse_whole(&packets[0])
                .unwrap()
                .payload(&packets[0]);
            assert_eq!(t[13], 0x12, "a SYN-ACK");
            u32::from_be_bytes(t[4..8].try_into().unwrap())
        };
        let ack = |port, iss: u32| segment(peer(port), local, 1, iss.wrapping_add(1), 0x10).0;
        let mut iss = BTreeMap::new();
        {
            let mut st = server.shared.lock();
            for port in [1000, 1001, 1002] {
                st.ingress(
                    &fcx,
                    &Budget::unlimited(),
                    now,
                    segment(peer(port), local, 0, 0, 0x02).0,
                );
                iss.insert(port, syn_ack_iss(egress(&mut st, now)));
            }
            assert_eq!(
                st.listeners[&80].embryonic.len(),
                2,
                "the third SYN got a cookie"
            );
            // The cookie's ACK and one kept ACK fill the backlog.
            st.ingress(&fcx, &Budget::unlimited(), now, ack(1002, iss[&1002]));
            st.ingress(&fcx, &Budget::unlimited(), now, ack(1000, iss[&1000]));
            assert_eq!(st.listeners[&80].ready.len(), 2);
            // The other kept ACK finds no room: its handshake stays open.
            st.ingress(&fcx, &Budget::unlimited(), now, ack(1001, iss[&1001]));
            let l = &st.listeners[&80];
            assert!(
                l.ready.len() <= l.backlog,
                "{} connections wait for accept with a backlog of {}",
                l.ready.len(),
                l.backlog
            );
            assert_eq!(l.embryonic.len(), 1, "the handshake is still open");
            let h = st.by_tuple[&(local, peer(1001))];
            assert_eq!(st.get(h).state(), TcpState::SynReceived);
        }
        let first = listener.accept(&fcx).await?;
        assert_eq!(first.peer_addr().port(), 1002);
        {
            // The peer answers the SYN-ACK sent again.
            let mut st = server.shared.lock();
            st.ingress(&fcx, &Budget::unlimited(), now, ack(1001, iss[&1001]));
            assert_eq!(st.listeners[&80].ready.len(), 2);
            assert!(st.listeners[&80].embryonic.is_empty());
        }
        let mut ports = Vec::new();
        for _ in 0..2 {
            ports.push(listener.accept(&fcx).await?.peer_addr().port());
        }
        assert_eq!(ports, [1000, 1001]);
        fcx.cancel();
        Ok(())
    }))
    .unwrap();
}

/// A burst of handshakes that the peer resets in SYN-RECEIVED leaves
/// at most one spare listening socket, not one per SYN.
#[test]
fn a_burst_of_reset_handshakes_leaves_no_pool_of_sockets() {
    let result = block_on(run(fictionet::Seed::random(), |fcx| async move {
        let (mut raw, side) = pair();
        let server = endpoint(&fcx, side, "10.0.0.1".parse().unwrap());
        let _listener = server.listen(80)?;
        let to: SocketAddr = "10.0.0.1:80".parse().unwrap();
        for port in 1000..1250u16 {
            raw.send(segment(
                SocketAddr::new("10.0.0.2".parse().unwrap(), port),
                to,
                7,
                0,
                0x02,
            ));
        }
        let mut acks = 0;
        while acks < 250 {
            let p = raw.recv(&fcx).await?;
            let ip = Header::parse_whole(&p.0).unwrap();
            let t = ip.payload(&p.0);
            assert_eq!(t[13], 0x12, "a SYN-ACK");
            let port = u16::from_be_bytes([t[2], t[3]]);
            let isn = u32::from_be_bytes([t[4], t[5], t[6], t[7]]);
            let from = SocketAddr::new("10.0.0.2".parse().unwrap(), port);
            raw.send(segment(from, to, 8, isn.wrapping_add(1), 0x04));
            acks += 1;
        }
        fcx.sleep(Duration::from_millis(100)).await?;
        let st = server.shared.lock();
        let l = &st.listeners[&80];
        assert!(l.embryonic.is_empty() && l.ready.is_empty());
        assert!(
            l.idle.len() <= 1,
            "{} spare listening sockets",
            l.idle.len()
        );
        assert!(st.sockets.iter().count() <= 1);
        drop(st);
        Err::<(), fictionet::Error>(fictionet::Error::msg("done"))
    }));
    assert_eq!(result.unwrap_err().to_string(), "done");
}

/// SYNs from many addresses that never answer the SYN-ACK, as spoofed
/// ones do, are forgotten once the handshake times out: no connection,
/// socket or per-peer count is left behind for any of them.
#[test]
fn unanswered_syns_from_many_addresses_leave_nothing_behind() {
    block_on(lab(Seed::from_u64(1), |fcx| async move {
        let (mut raw, side) = pair();
        let server = endpoint(&fcx, side, "10.0.0.1".parse().unwrap());
        let _listener = server.listen(80)?;
        let to: SocketAddr = "10.0.0.1:80".parse().unwrap();
        let sources = 1000u32;
        for n in 0..sources {
            let from = std::net::Ipv4Addr::from(0x0b00_0000 + n);
            raw.send(segment(SocketAddr::new(from.into(), 4000), to, 7, 0, 0x02));
        }
        let mut syn_acks = 0;
        while syn_acks < sources {
            let p = raw.recv(&fcx).await?;
            let t = Header::parse_whole(&p.0).unwrap().payload(&p.0).to_vec();
            assert_eq!(t[13], 0x12, "a SYN-ACK");
            syn_acks += 1;
        }
        {
            let st = server.shared.lock();
            let l = &st.listeners[&80];
            assert_eq!(l.embryonic.len(), sources as usize);
            assert_eq!(l.per_peer.len(), sources as usize);
        }
        // The SYN-ACKs are sent again, unanswered, until the timeout.
        fcx.spawn(move |fcx| async move {
            while raw.recv(&fcx).await.is_ok() {}
            Ok(())
        });
        fcx.sleep(TIMEOUT + Duration::from_secs(5)).await?;
        let st = server.shared.lock();
        let l = &st.listeners[&80];
        assert!(l.embryonic.is_empty() && l.ready.is_empty());
        assert!(l.per_peer.is_empty(), "{} peers kept", l.per_peer.len());
        assert!(st.conns.is_empty(), "{} connections kept", st.conns.len());
        assert!(st.by_tuple.is_empty());
        assert!(st.handles.len() <= 1, "{} sockets kept", st.handles.len());
        drop(st);
        fcx.cancel();
        Ok(())
    }))
    .unwrap();
}

/// Handshakes wait in the order their SYNs came, and each is dropped
/// [`Settings::handshake_timeout`] after its own SYN; the next one due is the
/// endpoint's next timer. Housekeeping looks only at those a segment
/// reached: one completed among many waiting is accepted, and nothing
/// is left for it to look at once the turn is over.
#[test]
fn handshakes_wait_and_expire_in_the_order_they_came() {
    block_on(lab(Seed::from_u64(1), |fcx| async move {
        let (mut raw, side) = pair();
        let server = endpoint(&fcx, side, "10.0.0.1".parse().unwrap());
        let mut listener = server.listen(80)?;
        let to: SocketAddr = "10.0.0.1:80".parse().unwrap();
        let from = |n: u32| SocketAddr::new(std::net::Ipv4Addr::from(0x0b00_0000 + n).into(), 4000);
        let start = fcx.now();
        // Two batches of SYNs, ten seconds apart, each answered.
        let mut isn = HashMap::new();
        for batch in 0..2u32 {
            for n in 0..100 {
                raw.send(segment(from(batch * 100 + n), to, 7, 0, 0x02));
            }
            while isn.len() < (batch as usize + 1) * 100 {
                let p = raw.recv(&fcx).await?;
                let ip = Header::parse_whole(&p.0).unwrap();
                let t = ip.payload(&p.0);
                if t[13] == 0x12 {
                    isn.insert(ip.dst, u32::from_be_bytes([t[4], t[5], t[6], t[7]]));
                }
            }
            if batch == 0 {
                fcx.sleep(Duration::from_secs(10)).await?;
            }
        }
        let due = |st: &TcpLayer| {
            let l = &st.listeners[&80];
            let first = l.embryonic.first().unwrap();
            (l.embryonic.len(), first.0, st.touched.len())
        };
        {
            let st = server.shared.lock();
            let (waiting, next, touched) = due(&st);
            assert_eq!(waiting, 200);
            assert_eq!(touched, 0, "nothing left to look at");
            assert_eq!(st.next_expiry(), Some(next));
        }
        // One of the second batch completes, among 199 waiting.
        let late = from(150);
        raw.send(segment(late, to, 8, isn[&late.ip()].wrapping_add(1), 0x10));
        let conn = listener.accept(&fcx).await?;
        assert_eq!(conn.peer_addr(), late);
        fcx.spawn(move |fcx| async move {
            while raw.recv(&fcx).await.is_ok() {}
            Ok(())
        });
        // Each batch expires at the configured handshake deadline, the second
        // ten seconds later.
        fcx.sleep_until(start + Settings::default().handshake_timeout + Duration::from_secs(5))
            .await?;
        {
            let st = server.shared.lock();
            let (waiting, _, touched) = due(&st);
            assert_eq!(waiting, 99);
            assert_eq!(touched, 0);
        }
        fcx.sleep_until(start + Settings::default().handshake_timeout + Duration::from_secs(15))
            .await?;
        let st = server.shared.lock();
        assert!(st.listeners[&80].embryonic.is_empty());
        assert_eq!(st.next_expiry(), None);
        drop(st);
        drop(conn);
        fcx.cancel();
        Ok(())
    }))
    .unwrap();
}

/// A SYN from an address that cannot be one host's (unspecified,
/// multicast or the limited broadcast) gets nothing back, whether the
/// listener would refuse it or the backlog is full and it would get a
/// SYN cookie.
#[test]
fn syns_from_no_host_s_address_get_nothing() {
    block_on(lab(Seed::from_u64(1), |fcx| async move {
        let (mut raw, side) = pair();
        let server = endpoint_with(
            &fcx,
            side,
            "10.0.0.1".parse().unwrap(),
            Options::default().backlog(1),
        );
        let mut refusing = server.listen(80)?;
        refusing.answer(Box::new(|_: &Syn<'_>| SynAnswer::Refuse(Vec::new())));
        let _cookies = server.listen(81)?;
        let martians = ["0.0.0.0", "224.0.0.1", "239.1.2.3", "255.255.255.255"];
        // The backlog of port 81 is full.
        raw.send(segment(
            "10.0.0.9:4000".parse().unwrap(),
            "10.0.0.1:81".parse().unwrap(),
            7,
            0,
            0x02,
        ));
        let p = raw.recv(&fcx).await?;
        assert_eq!(Header::parse_whole(&p.0).unwrap().payload(&p.0)[13], 0x12);
        for port in [80, 81] {
            let to = SocketAddr::new("10.0.0.1".parse().unwrap(), port);
            for (n, src) in martians.iter().enumerate() {
                let from = SocketAddr::new(src.parse().unwrap(), 4000 + n as u16);
                raw.send(segment(from, to, 7, 0, 0x02));
            }
        }
        // Shorter than the second before the first SYN-ACK is sent again.
        let quiet = fcx
            .race(Some(fcx.now() + Duration::from_millis(500)), raw.recv(&fcx))
            .await;
        assert!(quiet.is_err(), "an answer: {quiet:?}");
        // A host's address gets the RST and the SYN cookie.
        for port in [80, 81] {
            let to = SocketAddr::new("10.0.0.1".parse().unwrap(), port);
            raw.send(segment("10.0.0.8:4000".parse().unwrap(), to, 7, 0, 0x02));
            let p = raw.recv(&fcx).await?;
            let flags = Header::parse_whole(&p.0).unwrap().payload(&p.0)[13];
            assert_eq!(flags, if port == 80 { 0x14 } else { 0x12 });
        }
        fcx.cancel();
        Ok(())
    }))
    .unwrap();
}

/// After many connections come and go, the socket set is rebuilt
/// without its empty slots, and a connection that stayed open keeps
/// working.
#[test]
fn the_socket_set_shrinks_after_a_crowd_leaves() {
    let result = block_on(lab(Seed::from_u64(1), |fcx| async move {
        let (a, b) = pair();
        // Exercise reclamation with a short configured segment lifetime.
        let settings = Settings {
            socket: SocketSettings {
                time_wait: smoltcp::time::Duration::from_secs(10),
                ..SocketSettings::default()
            },
            ..Settings::default()
        };
        let options = Options::default().settings(settings);
        let server = endpoint_with(&fcx, a, "10.0.0.1".parse().unwrap(), options);
        let client = endpoint_with(&fcx, b, "10.0.0.2".parse().unwrap(), options);
        let mut listener = server.listen(80)?;
        let mut keep_c = client.connect(&fcx, "10.0.0.1:80".parse().unwrap()).await?;
        let mut keep_s = listener.accept(&fcx).await?;
        let mut crowd = Vec::new();
        for _ in 0..400 {
            let c = client.connect(&fcx, "10.0.0.1:80".parse().unwrap()).await?;
            let s = listener.accept(&fcx).await?;
            crowd.push((c, s));
        }
        assert!(server.shared.lock().slots >= 401);
        drop(crowd);
        let deadline = fcx.now() + Duration::from_secs(11);
        while ![&server, &client].iter().all(|e| {
            let st = e.shared.lock();
            st.handles.len() <= 3 && st.slots < COMPACT_SLOTS
        }) {
            assert!(fcx.now() < deadline, "closed connections kept socket slots");
            fcx.sleep(Duration::from_millis(5)).await?;
        }
        for e in [&server, &client] {
            let st = e.shared.lock();
            assert!(st.handles.len() <= 3, "{} sockets left", st.handles.len());
            // Compacted on the way down: fewer than 256 slots remain,
            // not the 401 it had.
            assert!(st.slots < COMPACT_SLOTS, "{} slots left", st.slots);
            assert_eq!(st.sockets.iter().count(), st.handles.len());
        }
        let size = rounds(1 << 20);
        let data = pattern(size, 9);
        let writer = {
            let data = data.clone();
            fcx.spawn(move |fcx| async move {
                keep_s.write_all(&fcx, &data).await?;
                Ok(())
            })
        };
        let mut got = vec![0u8; size];
        let mut at = 0;
        while at < got.len() {
            at += keep_c.read(&fcx, &mut got[at..]).await?;
        }
        writer.join(&fcx).await?;
        assert!(got == data, "the connection that stayed open still works");
        Err::<(), fictionet::Error>(fictionet::Error::msg("done"))
    }));
    assert_eq!(result.unwrap_err().to_string(), "done");
}

/// Dropping a connection applies the configured orphan timeout.
#[test]
fn a_dropped_connection_uses_the_orphan_timeout() {
    let result = block_on(run(fictionet::Seed::random(), |fcx| async move {
        let (a, b) = pair();
        let server = endpoint(&fcx, a, "10.0.0.1".parse().unwrap());
        let client = endpoint(&fcx, b, "10.0.0.2".parse().unwrap());
        let mut listener = server.listen(80)?;
        let _c = client.connect(&fcx, "10.0.0.1:80".parse().unwrap()).await?;
        let s = listener.accept(&fcx).await?;
        let h = server.shared.lock().socket_of(s.id);
        assert_eq!(server.shared.lock().get(h).timeout(), Some(TIMEOUT.into()));
        drop(s);
        fcx.sleep(Duration::from_millis(50)).await?;
        let st = server.shared.lock();
        assert_eq!(
            st.get(h).state(),
            TcpState::FinWait2,
            "the client never closes its side"
        );
        assert_eq!(st.get(h).timeout(), Some(st.settings.orphan_timeout.into()));
        drop(st);
        Err::<(), fictionet::Error>(fictionet::Error::msg("done"))
    }));
    assert_eq!(result.unwrap_err().to_string(), "done");
}

/// A dropped connection whose peer acknowledged its FIN expires at the
/// configured deadline even if the peer keeps sending ACKs.
#[test]
fn an_orphan_in_fin_wait_2_expires_despite_peer_acks() {
    let result = block_on(lab(Seed::from_u64(1), |fcx| async move {
        let (mut raw, side) = pair();
        let server = endpoint(&fcx, side, "10.0.0.1".parse().unwrap());
        let mut listener = server.listen(80)?;
        let to: SocketAddr = "10.0.0.1:80".parse().unwrap();
        let peer: SocketAddr = "10.0.0.2:3000".parse().unwrap();
        raw.send(segment(peer, to, 7, 0, 0x02));
        let isn = syn_ack_isn(&mut raw, &fcx, 3000).await;
        raw.send(segment(peer, to, 8, isn.wrapping_add(1), 0x10));
        let conn = listener.accept(&fcx).await?;
        drop(conn);
        loop {
            let p = raw.recv(&fcx).await?;
            let t = Header::parse_whole(&p.0).unwrap().payload(&p.0).to_vec();
            if t[13] & 0x01 != 0 {
                break;
            }
        }
        let acked = isn.wrapping_add(2);
        raw.send(segment(peer, to, 8, acked, 0x10));
        fcx.sleep(Duration::from_millis(10)).await?;
        let open = |server: &Endpoint| {
            let st = server.shared.lock();
            st.conns.values().any(|c| c.remote == peer)
        };
        assert!(open(&server), "FIN-WAIT-2 for now");
        // A bare ACK every 50 seconds, for two and a half minutes.
        for _ in 0..3 {
            fcx.sleep(Duration::from_secs(50)).await?;
            raw.send(segment(peer, to, 8, acked, 0x10));
        }
        fcx.sleep(Duration::from_millis(10)).await?;
        assert!(!open(&server), "forgotten at the orphan deadline");
        // Data now gets a RST: there is no connection.
        raw.send(data_segment(peer, to, 8, acked, 0x18, b"x"));
        let p = raw.recv(&fcx).await?;
        let t = Header::parse_whole(&p.0).unwrap().payload(&p.0).to_vec();
        assert_eq!(t[13] & 0x04, 0x04, "a RST");
        Err::<(), fictionet::Error>(fictionet::Error::msg("done"))
    }));
    assert_eq!(result.unwrap_err().to_string(), "done");
}

/// The SYN-ACK a peer gets for one connection does not depend on what
/// other connections were opened before it, so the numbers a peer sees
/// on its own connections tell it nothing about another's. It depends
/// on the endpoints, the clock and the endpoint's secret.
#[test]
fn initial_sequence_numbers_tell_nothing_of_other_connections() {
    let to: SocketAddr = "10.0.0.1:80".parse().unwrap();
    let isn_of = |seed: u64, before: u16, at_secs: u64, peer: SocketAddr| {
        let seen = Arc::new(Mutex::new(None));
        let out = seen.clone();
        let result = block_on(lab(Seed::from_u64(seed), move |fcx| async move {
            let (mut raw, side) = pair();
            let server = endpoint(&fcx, side, to.ip());
            let _listener = server.listen(80)?;
            for port in 0..before {
                let other = SocketAddr::new(peer.ip(), 40_000 + port);
                raw.send(segment(other, to, 7, 0, 0x02));
                syn_ack_isn(&mut raw, &fcx, other.port()).await;
            }
            fcx.sleep_until(Instant::from_since_start(Duration::from_secs(at_secs)))
                .await?;
            raw.send(segment(peer, to, 7, 0, 0x02));
            *seen.lock() = Some(syn_ack_isn(&mut raw, &fcx, peer.port()).await);
            Err::<(), fictionet::Error>(fictionet::Error::msg("done"))
        }));
        assert_eq!(result.unwrap_err().to_string(), "done");
        out.lock().expect("a SYN-ACK")
    };
    let peer: SocketAddr = "10.0.0.2:3000".parse().unwrap();
    let alone = isn_of(1, 0, 5, peer);
    assert_eq!(isn_of(1, 3, 5, peer), alone, "others' SYNs change nothing");
    // The clock adds one every 4 microseconds.
    assert_eq!(isn_of(1, 0, 6, peer), alone.wrapping_add(250_000));
    // Another address, port or secret gets an unrelated number.
    let other = "10.0.0.3:3000".parse().unwrap();
    assert_ne!(isn_of(1, 0, 5, other), alone);
    assert_ne!(isn_of(1, 0, 5, "10.0.0.2:3001".parse().unwrap()), alone);
    assert_ne!(isn_of(2, 0, 5, peer), alone);
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn mappings_reject_lengths_that_cannot_form_slices() {
    for buffer in [0, isize::MAX as usize, usize::MAX] {
        assert!(Pages::map(buffer).is_none());
    }
}

#[test]
fn options_set_the_buffers_of_every_connection() {
    assert_eq!(Options::default().buffer(1).buffer, MIN_BUFFER);
    assert_eq!(Options::default().buffer(usize::MAX).buffer, MAX_BUFFER);
    for size in [MIN_BUFFER, 1 << 20] {
        let result = block_on(run(fictionet::Seed::random(), move |fcx| async move {
            let (a, b) = pair();
            let options = Options::default().buffer(size);
            let server = endpoint_with(&fcx, a, "10.0.0.1".parse().unwrap(), options);
            let client = endpoint_with(&fcx, b, "10.0.0.2".parse().unwrap(), options);
            let mut listener = server.listen(80)?;
            let mut c = client.connect(&fcx, "10.0.0.1:80".parse().unwrap()).await?;
            let mut s = listener.accept(&fcx).await?;
            for (ep, id) in [(&server, s.id), (&client, c.id)] {
                let st = ep.shared.lock();
                let h = st.socket_of(id);
                assert_eq!(st.get(h).recv_capacity(), size);
                assert_eq!(st.get(h).send_capacity(), size);
            }
            // 3 MiB arrive unchanged, through buffers smaller and larger
            // than the default.
            let data = pattern(3 << 20, 7);
            let sent = data.clone();
            let writer = fcx.spawn(move |fcx| async move { Ok(s.write_all(&fcx, &sent).await?) });
            let mut got = vec![0u8; data.len()];
            let mut at = 0;
            while at < got.len() {
                at += c.read(&fcx, &mut got[at..]).await?;
            }
            assert!(
                got == data,
                "the data came through unchanged with {size}-byte buffers"
            );
            writer.join(&fcx).await?;
            Err::<(), fictionet::Error>(fictionet::Error::msg("done"))
        }));
        assert_eq!(result.unwrap_err().to_string(), "done");
    }
}

#[test]
fn quiet_connections_give_their_buffer_pages_back() {
    let result = block_on(lab(Seed::from_u64(1), |fcx| async move {
        let (a, b) = pair();
        let server = endpoint(&fcx, a, "10.0.0.1".parse().unwrap());
        let client = endpoint(&fcx, b, "10.0.0.2".parse().unwrap());
        let mut listener = server.listen(80)?;
        let mut c = client.connect(&fcx, "10.0.0.1:80".parse().unwrap()).await?;
        let mut s = listener.accept(&fcx).await?;
        // A fresh connection costs (almost) no pages.
        assert!(resident(&server) <= 4, "{}", resident(&server));

        let size = rounds(1 << 20);
        for round in 0..2u8 {
            // Transfers in both directions fill the 256 KiB buffers.
            let down = pattern(size, round);
            let up = pattern(size, round + 100);
            let slot = Arc::new(Mutex::new(None));
            let writer = {
                let (down, slot) = (down.clone(), slot.clone());
                fcx.spawn(move |fcx| async move {
                    s.write_all(&fcx, &down).await?;
                    let mut got = vec![0u8; size];
                    let mut at = 0;
                    while at < got.len() {
                        at += s.read(&fcx, &mut got[at..]).await?;
                    }
                    *slot.lock() = Some((s, got));
                    Ok(())
                })
            };
            let mut got = vec![0u8; size];
            let mut at = 0;
            while at < got.len() {
                at += c.read(&fcx, &mut got[at..]).await?;
            }
            assert!(
                got == down,
                "the download came through unchanged in round {round}"
            );
            c.write_all(&fcx, &up).await?;
            writer.join(&fcx).await?;
            let (back, got_up) = slot.lock().take().unwrap();
            s = back;
            assert!(
                got_up == up,
                "the upload came through unchanged in round {round}"
            );
            // Both sides wrote whole buffers.
            assert!(resident(&server) >= 64, "{}", resident(&server));
            // Once the connection is quiet, its pages go back, while it
            // stays open.
            let deadline = fcx.now() + 3 * RELEASE_EVERY;
            while resident(&server) != 0 || resident(&client) != 0 {
                assert!(
                    fcx.now() < deadline,
                    "quiet connections kept buffer pages: server {}, client {}",
                    resident(&server),
                    resident(&client)
                );
                fcx.sleep(Duration::from_millis(50)).await?;
            }
            assert_eq!(resident(&server), 0);
            assert_eq!(resident(&client), 0);
        }
        drop((c, s));
        // Err ends the run, and with it the endpoints' drivers.
        Err::<(), fictionet::Error>(fictionet::Error::msg("done"))
    }));
    assert_eq!(result.unwrap_err().to_string(), "done");
}

async fn syn_ack_isn(raw: &mut fictionet::End, fcx: &Cx, port: u16) -> u32 {
    loop {
        let p = raw.recv(fcx).await.unwrap();
        let t = Header::parse_whole(&p.0).unwrap().payload(&p.0).to_vec();
        if t[13] == 0x12 && u16::from_be_bytes([t[2], t[3]]) == port {
            return u32::from_be_bytes([t[4], t[5], t[6], t[7]]);
        }
    }
}

#[test]
fn retransmitted_syn_reuses_the_existing_socket() {
    let result = block_on(lab(Seed::from_u64(1), |fcx| async move {
        let (mut raw, side) = pair();
        let server = endpoint(&fcx, side, "10.0.0.1".parse().unwrap());
        let _listener = server.listen(80)?;
        let to: SocketAddr = "10.0.0.1:80".parse().unwrap();
        let p1: SocketAddr = "10.0.0.2:1000".parse().unwrap();
        let p2: SocketAddr = "10.0.0.2:2000".parse().unwrap();
        raw.send(segment(p1, to, 7, 0, 0x02));
        let isn1 = syn_ack_isn(&mut raw, &fcx, 1000).await;
        raw.send(segment(p2, to, 7, 0, 0x02));
        let _isn2 = syn_ack_isn(&mut raw, &fcx, 2000).await;
        // Reset the first handshake: its socket goes back to LISTEN and
        // becomes the spare.
        raw.send(segment(p1, to, 8, isn1.wrapping_add(1), 0x04));
        fcx.sleep(Duration::from_millis(100)).await?;
        // The peer retransmits its SYN for p2.
        raw.send(segment(p2, to, 7, 0, 0x02));
        fcx.sleep(Duration::from_millis(100)).await?;
        let st = server.shared.lock();
        let for_p2 = st.conns.values().filter(|c| c.remote == p2).count();
        drop(st);
        assert_eq!(for_p2, 1, "one socket per tuple");
        Err::<(), fictionet::Error>(fictionet::Error::msg("done"))
    }));
    assert_eq!(result.unwrap_err().to_string(), "done");
}

#[test]
fn out_of_window_rst_keeps_the_connection_open() {
    let result = block_on(lab(Seed::from_u64(1), |fcx| async move {
        let (mut raw, side) = pair();
        let server = endpoint(&fcx, side, "10.0.0.1".parse().unwrap());
        let mut listener = server.listen(80)?;
        let to: SocketAddr = "10.0.0.1:80".parse().unwrap();
        let peer: SocketAddr = "10.0.0.2:3000".parse().unwrap();
        raw.send(segment(peer, to, 7, 0, 0x02));
        let isn = syn_ack_isn(&mut raw, &fcx, 3000).await;
        raw.send(segment(peer, to, 8, isn.wrapping_add(1), 0x10));
        let conn = listener.accept(&fcx).await?;
        // A RST far outside the receive window.
        raw.send(segment(peer, to, 8u32.wrapping_add(0x4000_0000), 0, 0x04));
        fcx.sleep(Duration::from_millis(50)).await?;
        let gone = std::future::poll_fn(|cx| Poll::Ready(conn.poll_gone(cx).is_ready())).await;
        let state = {
            let st = server.shared.lock();
            st.get(st.socket_of(conn.id)).state()
        };
        assert_eq!(state, TcpState::Established);
        assert!(!gone, "an out-of-window RST was taken as a reset");
        Err::<(), fictionet::Error>(fictionet::Error::msg("done"))
    }));
    assert_eq!(result.unwrap_err().to_string(), "done");
}
#[test]
fn rejected_fin_does_not_mark_the_receive_side_closed() {
    let result = block_on(lab(Seed::from_u64(1), |fcx| async move {
        let (mut raw, side) = pair();
        let server = endpoint(&fcx, side, "10.0.0.1".parse()?);
        let mut listener = server.listen(80)?;
        let to: SocketAddr = "10.0.0.1:80".parse()?;
        let peer: SocketAddr = "10.0.0.2:3000".parse()?;
        raw.send(segment(peer, to, 7, 0, 0x02));
        let isn = syn_ack_isn(&mut raw, &fcx, 3000).await;
        raw.send(segment(peer, to, 8, isn.wrapping_add(1), 0x10));
        let conn = listener.accept(&fcx).await?;
        raw.send(segment(
            peer,
            to,
            8u32.wrapping_add(0x4000_0000),
            isn.wrapping_add(1),
            0x11,
        ));
        fcx.sleep(Duration::from_millis(50)).await?;
        let (state, fin) = {
            let st = server.shared.lock();
            let h = st.socket_of(conn.id);
            let state = st.get(h).state();
            let c = &st.conns[&h];
            (state, c.fin)
        };
        assert_eq!(state, TcpState::Established);
        assert!(!fin);
        Err::<(), fictionet::Error>(fictionet::Error::msg("done"))
    }));
    assert_eq!(result.unwrap_err().to_string(), "done");
}

/// The SYN-ACK `local` sent to `peer`, by its sequence number.
fn syn_ack_to(packets: &[Vec<u8>], peer: SocketAddr) -> u32 {
    packets
        .iter()
        .find_map(|p| {
            let ip = Header::parse_whole(p).unwrap();
            let t = ip.payload(p);
            let to = SocketAddr::new(ip.dst, u16::from_be_bytes([t[2], t[3]]));
            (to == peer && t[13] == 0x12).then(|| u32::from_be_bytes(t[4..8].try_into().unwrap()))
        })
        .expect("a SYN-ACK to the peer")
}

#[test]
fn a_handshake_reset_in_one_batch_does_not_lend_its_socket_to_another_peer() {
    block_on(lab(Seed::from_u64(1), |fcx| async move {
        let (_raw, side) = pair();
        let local: SocketAddr = "10.0.0.1:80".parse()?;
        let first: SocketAddr = "10.0.0.2:1000".parse()?;
        let second: SocketAddr = "10.0.0.3:2000".parse()?;
        let ep = endpoint(&fcx, side, local.ip());
        let _listener = ep.listen(local.port())?;
        let now = smol_now(&fcx);
        let mut st = ep.shared.lock();
        // One batch: housekeeping runs only after all three packets.
        st.ingress(
            &fcx,
            &Budget::unlimited(),
            now,
            segment(first, local, 100, 0, 0x02).0,
        );
        st.ingress(
            &fcx,
            &Budget::unlimited(),
            now,
            segment(first, local, 101, 0, 0x04).0,
        );
        st.ingress(
            &fcx,
            &Budget::unlimited(),
            now,
            segment(second, local, 500, 0, 0x02).0,
        );
        let isn = syn_ack_to(&egress(&mut st, now), second);
        st.ingress(
            &fcx,
            &Budget::unlimited(),
            now,
            segment(second, local, 501, isn.wrapping_add(1), 0x10).0,
        );
        st.housekeeping();
        for (&h, c) in &st.conns {
            if let Some(remote) = st.get(h).remote_endpoint() {
                assert_eq!(
                    c.remote,
                    SocketAddr::from(remote),
                    "the peer its socket talks to"
                );
            }
        }
        let l = &st.listeners[&80];
        let h = *l
            .ready
            .front()
            .expect("the second peer's connection is ready");
        assert_eq!(st.conns[&h].remote, second);
        assert_eq!(st.by_tuple.get(&(local, second)), Some(&h));
        assert_eq!(l.per_peer.get(&second.ip()), Some(&1));
        assert_eq!(l.per_peer.get(&first.ip()), None);
        drop(st);
        fcx.cancel();
        Ok(())
    }))
    .unwrap();
}

#[test]
fn a_handshake_restarted_in_one_batch_is_not_reported_reset() {
    block_on(lab(Seed::from_u64(1), |fcx| async move {
        let (_raw, side) = pair();
        let local: SocketAddr = "10.0.0.1:80".parse()?;
        let peer: SocketAddr = "10.0.0.2:1000".parse()?;
        let ep = endpoint(&fcx, side, local.ip());
        let _listener = ep.listen(local.port())?;
        let now = smol_now(&fcx);
        let mut st = ep.shared.lock();
        // The peer resets its handshake and starts again, in one batch.
        st.ingress(
            &fcx,
            &Budget::unlimited(),
            now,
            segment(peer, local, 100, 0, 0x02).0,
        );
        st.ingress(
            &fcx,
            &Budget::unlimited(),
            now,
            segment(peer, local, 101, 0, 0x04).0,
        );
        st.ingress(
            &fcx,
            &Budget::unlimited(),
            now,
            segment(peer, local, 300, 0, 0x02).0,
        );
        let isn = syn_ack_to(&egress(&mut st, now), peer);
        st.ingress(
            &fcx,
            &Budget::unlimited(),
            now,
            segment(peer, local, 301, isn.wrapping_add(1), 0x10).0,
        );
        st.housekeeping();
        let h = *st.listeners[&80]
            .ready
            .front()
            .expect("the new handshake finished");
        assert_eq!(st.get(h).state(), TcpState::Established);
        let l = st.listeners.get_mut(&80).unwrap();
        l.ready.pop_front();
        l.left(peer.ip());
        let id = st.adopt(h);
        drop(st);
        let watch = GoneWatch {
            shared: ep.shared.clone(),
            id,
        };
        assert!(
            watch
                .poll_gone(&mut Context::from_waker(Waker::noop()))
                .is_pending(),
            "an established connection is not gone"
        );
        fcx.cancel();
        Ok(())
    }))
    .unwrap();
}

#[test]
fn bytes_after_the_peers_fin_are_not_read() {
    block_on(lab(Seed::from_u64(1), |fcx| async move {
        let (_raw, side) = pair();
        let local: SocketAddr = "10.0.0.1:80".parse()?;
        let peer: SocketAddr = "10.0.0.2:1234".parse()?;
        let ep = endpoint(&fcx, side, local.ip());
        let _listener = ep.listen(local.port())?;
        let now = smol_now(&fcx);
        let mut st = ep.shared.lock();
        let (h, ack) = established(&mut st, now, local, peer);
        st.ingress(
            &fcx,
            &Budget::unlimited(),
            now,
            segment(peer, local, 101, ack, 0x11).0,
        );
        assert_eq!(st.get(h).state(), TcpState::CloseWait);
        egress(&mut st, now);
        let mut buf = [0; 8];
        assert_eq!(
            st.sock(h).recv_slice(&mut buf),
            Err(stcp::RecvError::Finished)
        );
        // The peer sends more after its FIN, next in sequence.
        let mut late = segment(peer, local, 102, ack, 0x18).0;
        late.extend_from_slice(b"late");
        fix_lengths(&mut late, 20, peer.ip(), local.ip());
        st.ingress(&fcx, &Budget::unlimited(), now, late);
        assert_eq!(
            st.get(h).recv_queue(),
            0,
            "bytes after the FIN entered the stream"
        );
        assert_eq!(
            st.sock(h).recv_slice(&mut buf),
            Err(stcp::RecvError::Finished)
        );
        drop(st);
        fcx.cancel();
        Ok(())
    }))
    .unwrap();
}

#[test]
fn closing_in_syn_received_waits_for_the_fin_to_be_acknowledged() {
    block_on(lab(Seed::from_u64(1), |fcx| async move {
        let (_raw, side) = pair();
        let local: SocketAddr = "10.0.0.1:49152".parse()?;
        let peer: SocketAddr = "10.0.0.2:80".parse()?;
        let ep = endpoint(&fcx, side, local.ip());
        let now = smol_now(&fcx);
        let mut st = ep.shared.lock();
        let mut s = new_socket(MIN_BUFFER);
        s.0.connect(st.iface.context(), peer, local).unwrap();
        let h = st.add_socket(&fcx, s);
        st.conns.insert(h, Conn::new(local, peer, Side::Client));
        st.by_tuple.insert((local, peer), h);
        egress(&mut st, now);
        let iss = st.conns[&h].iss.unwrap();
        // Simultaneous open: the peer's own SYN crosses ours.
        st.ingress(
            &fcx,
            &Budget::unlimited(),
            now,
            segment(peer, local, 7, 0, 0x02).0,
        );
        assert_eq!(st.get(h).state(), TcpState::SynReceived);
        egress(&mut st, now);
        // The connect is abandoned, which drops its connection.
        st.orphan(h, false);
        assert_eq!(st.get(h).state(), TcpState::FinWait1);
        assert!(
            egress(&mut st, now)
                .iter()
                .all(|p| { Header::parse_whole(p).unwrap().payload(p)[13] & 1 == 0 })
        );
        // The peer acknowledges our SYN, not a FIN it never saw.
        st.ingress(
            &fcx,
            &Budget::unlimited(),
            now,
            segment(peer, local, 8, iss.wrapping_add(1), 0x10).0,
        );
        assert_eq!(
            st.get(h).state(),
            TcpState::FinWait1,
            "only our SYN was acknowledged"
        );
        let sent = egress(&mut st, now);
        assert!(
            sent.iter().any(|p| {
                let t = Header::parse_whole(p).unwrap().payload(p);
                t[13] & 1 != 0
                    && u32::from_be_bytes(t[4..8].try_into().unwrap()) == iss.wrapping_add(1)
            }),
            "the FIN follows the SYN"
        );
        drop(st);
        fcx.cancel();
        Ok(())
    }))
    .unwrap();
}

#[test]
fn a_reused_listening_socket_forgets_the_previous_peers_mss() {
    block_on(lab(Seed::from_u64(1), |fcx| async move {
        let (_raw, side) = pair();
        let local: SocketAddr = "10.0.0.1:80".parse()?;
        let first: SocketAddr = "10.0.0.2:1000".parse()?;
        let second: SocketAddr = "10.0.0.3:2000".parse()?;
        let ep = endpoint(&fcx, side, local.ip());
        let _listener = ep.listen(local.port())?;
        let now = smol_now(&fcx);
        let mut st = ep.shared.lock();
        // The first peer offers a 1460-byte MSS, then resets its handshake.
        let mut syn = segment(first, local, 100, 0, 0x02).0;
        syn[32] = 6 << 4;
        syn.extend_from_slice(&[2, 4, 0x05, 0xb4]);
        fix_lengths(&mut syn, 20, first.ip(), local.ip());
        st.ingress(&fcx, &Budget::unlimited(), now, syn);
        egress(&mut st, now);
        st.ingress(
            &fcx,
            &Budget::unlimited(),
            now,
            segment(first, local, 101, 0, 0x04).0,
        );
        st.housekeeping();
        let spare = st.listeners[&80].idle.clone();
        assert_eq!(spare.len(), 1, "the reset socket is the spare");
        // The second peer sends no MSS option: RFC 9293 says 536 then.
        st.ingress(
            &fcx,
            &Budget::unlimited(),
            now,
            segment(second, local, 500, 0, 0x02).0,
        );
        let isn = syn_ack_to(&egress(&mut st, now), second);
        st.ingress(
            &fcx,
            &Budget::unlimited(),
            now,
            segment(second, local, 501, isn.wrapping_add(1), 0x10).0,
        );
        st.housekeeping();
        let h = *st.listeners[&80]
            .ready
            .front()
            .expect("the second connection");
        assert_eq!(h, spare[0], "the spare socket served the second peer");
        assert_eq!(st.sock(h).send_slice(&[0x5a; 2000]).unwrap(), 2000);
        let sent = egress(&mut st, now);
        let largest = sent
            .iter()
            .map(|p| {
                let t = Header::parse_whole(p).unwrap().payload(p);
                t.len() - ((t[12] >> 4) as usize) * 4
            })
            .max()
            .unwrap();
        assert!(largest > 0);
        assert!(
            largest <= 536,
            "sent a {largest}-byte segment to a peer that offered no MSS"
        );
        drop(st);
        fcx.cancel();
        Ok(())
    }))
    .unwrap();
}

// ---------------------------------------------------------------------------
// The layer on its own, driven with no runtime

mod layer {
    use super::*;
    use fictionet::stdlib::layer::{Chain, Datagram, MuxOp, PacketEvent};
    use fictionet::stdlib::network::packet::{Ingress, IpLayer, NetworkInput, Origin, Scopes};
    use fictionet::{Seed, SeededEntropy};

    /// One machine: the IP layer, then TCP, run by a driver.
    type Stack = Driver<Chain<IpLayer, TcpLayer>>;
    type Up = MuxEvent<ByteStream, Messages<TcpNotice, TcpControl>, TcpOpening>;

    const SERVER: &str = "10.9.0.1";
    const CLIENT: &str = "10.9.0.2";

    fn stack(addr: &str, seed: u64, budget: Budget) -> Stack {
        let entropy: Arc<dyn Entropy> = Arc::new(SeededEntropy::new(Seed::from_u64(seed)));
        let options = Options::default().buffer(MIN_BUFFER);
        let tcp = TcpLayer::new(addr.parse().unwrap(), options, &*entropy, Instant::ZERO);
        Driver::new(
            Chain::new(IpLayer::host(), tcp),
            entropy,
            budget,
            Instant::ZERO,
        )
    }

    fn control(stack: &mut Stack, control: TcpControl) {
        let command = MuxCommand::control(MessageCommand::Send(control));
        assert!(matches!(stack.command(command), Ok(Admit::Taken)));
    }

    /// Everything `stack` says to the layer above.
    fn events(stack: &mut Stack) -> Vec<Up> {
        let mut seen = Vec::new();
        stack.send_above(|event| {
            seen.push(event);
            Admit::Taken
        });
        seen
    }

    /// The packets `stack` sends.
    fn sent(stack: &mut Stack) -> Vec<Vec<u8>> {
        let _ = stack.run();
        let mut out = Vec::new();
        stack.send_below(|command| {
            if let PacketCommand::Send(packet) = command {
                out.push(packet.to_vec());
            }
            Admit::Taken
        });
        out
    }

    /// Hands `packets` to `stack`, a packet at a time.
    fn receive(stack: &mut Stack, packets: Vec<Vec<u8>>) {
        for packet in packets {
            let mut raw = PacketEvent::Packet(Chunk::new(packet));
            loop {
                match stack.deliver(raw) {
                    Ok(Admit::Blocked(back)) => raw = back,
                    Ok(_) => break,
                    Err(never) => match never {},
                }
                let _ = stack.run();
            }
            let _ = stack.run();
        }
    }

    /// Carries packets between the two stacks until neither sends any,
    /// passing each through `keep` first, and collects what each says.
    /// Delayed acknowledgments are let go by moving the clock up to 100 ms;
    /// a retransmission timeout is a second or more, so none fires here.
    fn exchange(
        a: &mut Stack,
        b: &mut Stack,
        mut keep: impl FnMut(&[u8]) -> bool,
    ) -> (Vec<Up>, Vec<Up>) {
        let horizon = a.now().max(b.now()) + Duration::from_millis(100);
        let (mut seen_a, mut seen_b) = (Vec::new(), Vec::new());
        for _ in 0..1000 {
            let to_b: Vec<_> = sent(a).into_iter().filter(|p| keep(p)).collect();
            let to_a: Vec<_> = sent(b).into_iter().filter(|p| keep(p)).collect();
            let quiet = to_a.is_empty() && to_b.is_empty();
            receive(b, to_b);
            receive(a, to_a);
            seen_a.extend(events(a));
            seen_b.extend(events(b));
            if quiet {
                let next = [a.deadline(), b.deadline()].into_iter().flatten().min();
                match next {
                    Some(at) if at <= horizon => {
                        a.set_now(at);
                        b.set_now(at);
                    }
                    _ => break,
                }
            }
        }
        (seen_a, seen_b)
    }

    fn opened(seen: &mut Vec<Up>) -> (Child, TcpOpening) {
        let at = seen
            .iter()
            .position(|e| matches!(e, MuxEvent::Opened(..)))
            .expect("a child opened");
        let MuxEvent::Opened(child, opening, _) = seen.remove(at) else {
            unreachable!()
        };
        (child, opening)
    }

    fn data(seen: &[Up], id: ChildId) -> Vec<u8> {
        seen.iter()
            .filter_map(|e| match e {
                MuxEvent::Child(child, StreamEvent::Data(bytes)) if *child == id => {
                    Some(bytes.to_vec())
                }
                _ => None,
            })
            .flatten()
            .collect()
    }

    fn credit(seen: &[Up], id: ChildId) -> u64 {
        seen.iter()
            .filter_map(|e| match e {
                MuxEvent::Credit(child, n) if *child == id => Some(*n),
                _ => None,
            })
            .sum()
    }

    fn tcp_flags(packet: &[u8]) -> Option<u8> {
        let ip = Header::parse_whole(packet)?;
        (ip.protocol == TCP).then(|| ip.payload(packet)[13])
    }

    /// A server listening on port 80 that accepts one connection, a
    /// client connected to it, and both children.
    #[allow(clippy::type_complexity)]
    fn connected() -> (Stack, Stack, (Child, TcpOpening), (Child, TcpOpening)) {
        let mut server = stack(SERVER, 1, Budget::unlimited());
        let mut client = stack(CLIENT, 2, Budget::unlimited());
        control(
            &mut server,
            TcpControl::Listen {
                port: 80,
                backlog: None,
                answer: None,
            },
        );
        assert!(events(&mut server).iter().any(|e| matches!(
            e,
            MuxEvent::Control(MessageEvent::Message(TcpNotice::Listening { port: 80 }))
        )));
        control(&mut server, TcpControl::Accept { port: 80, count: 1 });
        let remote: SocketAddr = format!("{SERVER}:80").parse().unwrap();
        control(
            &mut client,
            TcpControl::Connect {
                request: Request(7),
                remote,
            },
        );
        let mut at_client = events(&mut client);
        let (mut from_server, more) = exchange(&mut server, &mut client, |_| true);
        at_client.extend(more);
        let accepted = opened(&mut from_server);
        let connecting = opened(&mut at_client);
        assert!(
            credit(&at_client, connecting.0.id()) > 0,
            "the client may write"
        );
        assert!(
            credit(&from_server, accepted.0.id()) > 0,
            "the server may write"
        );
        (server, client, accepted, connecting)
    }

    #[test]
    fn two_layers_carry_a_stream_each_way_with_no_runtime() {
        let (mut server, mut client, (s, accepted), (c, connecting)) = connected();
        assert_eq!(connecting.origin, TcpOrigin::Connected(Request(7)));
        assert_eq!(accepted.local, connecting.remote);
        assert_eq!(accepted.remote, connecting.local);
        assert!(matches!(&accepted.origin, TcpOrigin::Accepted(h) if h.syn.is_some()));

        let request = pattern(3000, 1);
        let write: Command = c.send(StreamCommand::Write(Chunk::new(request.clone())));
        assert!(matches!(client.command(write), Ok(Admit::Taken)));
        let written = events(&mut client);
        assert!(written.iter().any(|e| matches!(
            e,
            MuxEvent::Child(id, StreamEvent::Written(n)) if *id == c.id() && *n == 3000
        )));
        let end: Command = c.send(StreamCommand::End);
        assert!(matches!(client.command(end), Ok(Admit::Taken)));
        let (mut at_server, _) = exchange(&mut server, &mut client, |_| true);
        // Nothing comes up before the server asks for it.
        assert!(data(&at_server, s.id()).is_empty());
        let grant: Command = s.grant(10_000);
        assert!(matches!(server.command(grant), Ok(Admit::Taken)));
        at_server.extend(events(&mut server));
        assert_eq!(data(&at_server, s.id()), request);
        let ended = at_server
            .iter()
            .position(|e| matches!(e, MuxEvent::Child(id, StreamEvent::Ended) if *id == s.id()))
            .expect("the client's FIN ends the stream");
        let last_data = at_server
            .iter()
            .rposition(|e| matches!(e, MuxEvent::Child(_, StreamEvent::Data(_))))
            .unwrap();
        assert!(last_data < ended, "the end comes after the bytes");

        let reply = pattern(500, 2);
        let write: Command = s.send(StreamCommand::Write(Chunk::new(reply.clone())));
        assert!(matches!(server.command(write), Ok(Admit::Taken)));
        let grant: Command = c.grant(10_000);
        assert!(matches!(client.command(grant), Ok(Admit::Taken)));
        let (_, at_client) = exchange(&mut server, &mut client, |_| true);
        assert_eq!(data(&at_client, c.id()), reply);
    }

    #[test]
    fn checked_packets_and_owned_inputs_reach_tcp() {
        let tunnel = Scopes::default().tunnel();
        let client: SocketAddr = format!("{CLIENT}:40000").parse().unwrap();
        let server: SocketAddr = format!("{SERVER}:80").parse().unwrap();
        let syn = segment(client, server, 1000, 0, 0x02).0;
        let listen = || {
            MuxCommand::control(MessageCommand::Send(TcpControl::Listen {
                port: 80,
                backlog: None,
                answer: None,
            }))
        };
        let syn_acks = |sent: &[Vec<u8>]| {
            sent.iter()
                .filter(|p| {
                    tcp_flags(p) == Some(0x12) && Header::parse_whole(p).unwrap().dst == client.ip()
                })
                .count()
        };
        let entropy: Arc<dyn Entropy> = Arc::new(SeededEntropy::new(Seed::from_u64(3)));
        let options = Options::default().buffer(MIN_BUFFER);
        let tcp = TcpLayer::new(SERVER.parse().unwrap(), options, &*entropy, Instant::ZERO);
        let mut alone = Driver::new(tcp, entropy, Budget::unlimited(), Instant::ZERO);
        assert!(matches!(alone.command(listen()), Ok(Admit::Taken)));
        let packet = CheckedIpPacket::checked(Chunk::new(syn.clone()), Origin::Arrived).unwrap();
        assert!(matches!(
            alone.deliver(PacketEvent::Packet(packet)),
            Ok(Admit::Taken)
        ));
        alone.run().unwrap();
        let mut sent_packets = Vec::new();
        alone.send_below(|command| {
            if let PacketCommand::Send(packet) = command {
                sent_packets.push(packet.to_vec());
            }
            Admit::Taken
        });
        assert_eq!(syn_acks(&sent_packets), 1);

        let entropy: Arc<dyn Entropy> = Arc::new(SeededEntropy::new(Seed::from_u64(4)));
        let tcp = TcpLayer::new(SERVER.parse().unwrap(), options, &*entropy, Instant::ZERO);
        let mut stack = Driver::new(
            Chain::new(IpLayer::host(), tcp),
            entropy,
            Budget::unlimited(),
            Instant::ZERO,
        );
        assert!(matches!(stack.command(listen()), Ok(Admit::Taken)));
        let mut malformed = syn.clone();
        malformed[10] ^= 1;
        assert!(matches!(
            stack.deliver(PacketEvent::Packet(Chunk::new(malformed))),
            Ok(Admit::Taken)
        ));
        assert_eq!(syn_acks(&sent(&mut stack)), 0);
        let input = NetworkInput::new(tunnel);
        let mut answers = Vec::new();
        let mut rejected = 0;
        for ingress in [
            Ingress::default(),
            Ingress {
                scope: tunnel,
                ..Ingress::default()
            },
        ] {
            match input.accept(Datagram::new(Chunk::new(syn.clone()), ingress)) {
                Ok(raw) => assert!(matches!(
                    stack.deliver(PacketEvent::Packet(raw)),
                    Ok(Admit::Taken)
                )),
                Err(_) => rejected += 1,
            }
            answers.push(syn_acks(&sent(&mut stack)));
        }
        assert_eq!(rejected, 1);
        assert_eq!(answers, [0, 1]);
    }

    #[test]
    fn a_lost_segment_is_sent_again_when_its_deadline_comes() {
        let (mut server, mut client, (s, _), (c, _)) = connected();
        let bytes = pattern(1000, 3);
        let write: Command = c.send(StreamCommand::Write(Chunk::new(bytes.clone())));
        assert!(matches!(client.command(write), Ok(Admit::Taken)));
        let grant: Command = s.grant(10_000);
        assert!(matches!(server.command(grant), Ok(Admit::Taken)));
        let mut dropped = 0;
        let (mut at_server, _) = exchange(&mut server, &mut client, |p| {
            let carries_data = Header::parse_whole(p).is_some_and(|ip| {
                ip.payload(p).len() > 20 + ((ip.payload(p)[12] >> 4) as usize - 5) * 4
            });
            if carries_data && dropped == 0 {
                dropped += 1;
                return false;
            }
            true
        });
        assert_eq!(dropped, 1);
        assert!(data(&at_server, s.id()).is_empty());
        // Only time brings the segment back.
        let due = client.deadline().expect("the client waits to send again");
        assert!(due > client.now());
        server.set_now(due);
        client.set_now(due);
        let (more, _) = exchange(&mut server, &mut client, |_| true);
        at_server.extend(more);
        assert_eq!(data(&at_server, s.id()), bytes);
    }

    #[test]
    fn closing_a_child_closes_the_connection_and_says_it_is_gone() {
        let (mut server, mut client, (s, _), (c, _)) = connected();
        let s_id = s.id();
        let close: Command = s.close();
        assert!(matches!(server.command(close), Ok(Admit::Taken)));
        let mut fins = 0;
        let (_, at_client) = exchange(&mut server, &mut client, |p| {
            fins += usize::from(tcp_flags(p).is_some_and(|f| f & 1 != 0));
            true
        });
        assert!(fins >= 1, "closing sends a FIN");
        assert!(
            at_client
                .iter()
                .any(|e| matches!(e, MuxEvent::Child(id, StreamEvent::Ended) if *id == c.id())),
            "the client sees the end of the stream"
        );
        let close: Command = c.close();
        assert!(matches!(client.command(close), Ok(Admit::Taken)));
        let (at_server, _) = exchange(&mut server, &mut client, |_| true);
        assert!(
            at_server.iter().any(|e| matches!(
                e,
                MuxEvent::Control(MessageEvent::Message(TcpNotice::Gone(id))) if *id == s_id
            )),
            "the server's connection retires into TIME-WAIT"
        );
        // A closed child takes no more commands.
        let late: Command = MuxCommand::control(MessageCommand::Send(TcpControl::Abort(s_id)));
        assert!(matches!(server.command(late), Ok(Admit::Taken)));
        assert!(
            sent(&mut server).is_empty(),
            "a retired connection is not reset"
        );
    }

    #[test]
    fn a_connection_waits_in_the_backlog_until_it_is_accepted() {
        let mut server = stack(SERVER, 1, Budget::unlimited());
        let mut client = stack(CLIENT, 2, Budget::unlimited());
        control(
            &mut server,
            TcpControl::Listen {
                port: 80,
                backlog: Some(1),
                answer: None,
            },
        );
        let remote: SocketAddr = format!("{SERVER}:80").parse().unwrap();
        for request in [1, 2] {
            control(
                &mut client,
                TcpControl::Connect {
                    request: Request(request),
                    remote,
                },
            );
        }
        let mut syn_acks = 0;
        let (at_server, _) = exchange(&mut server, &mut client, |p| {
            syn_acks += usize::from(tcp_flags(p) == Some(0x12));
            true
        });
        assert!(at_server.iter().all(|e| !matches!(e, MuxEvent::Opened(..))));
        assert_eq!(syn_acks, 1, "a full backlog drops the second SYN");
        control(&mut server, TcpControl::Accept { port: 80, count: 5 });
        let mut seen = events(&mut server);
        let (_, opening) = opened(&mut seen);
        assert!(matches!(opening.origin, TcpOrigin::Accepted(_)));
        assert_eq!(opening.local, remote);
    }

    #[test]
    fn buffers_that_do_not_fit_the_budget_are_refused_before_a_socket() {
        let remote: SocketAddr = format!("{SERVER}:80").parse().unwrap();
        // Two buffers of MIN_BUFFER do not fit.
        let mut client = stack(CLIENT, 2, Budget::new(MIN_BUFFER));
        control(
            &mut client,
            TcpControl::Connect {
                request: Request(3),
                remote,
            },
        );
        let seen = events(&mut client);
        assert!(seen.iter().any(|e| matches!(
            e,
            MuxEvent::Control(MessageEvent::Message(TcpNotice::ConnectFailed {
                request: Request(3),
                error: ConnError::Refused,
            }))
        )));
        assert!(sent(&mut client).is_empty(), "no SYN goes out");
        assert_eq!(client.budget().used(), 0);

        let mut server = stack(SERVER, 1, Budget::new(MIN_BUFFER));
        let mut client = stack(CLIENT, 2, Budget::unlimited());
        control(
            &mut server,
            TcpControl::Listen {
                port: 80,
                backlog: None,
                answer: None,
            },
        );
        control(
            &mut client,
            TcpControl::Connect {
                request: Request(4),
                remote,
            },
        );
        let mut answered = 0;
        let _ = exchange(&mut server, &mut client, |p| {
            let from_server = Header::parse_whole(p).is_some_and(|ip| ip.src.to_string() == SERVER);
            answered += usize::from(from_server);
            true
        });
        assert_eq!(answered, 0, "a SYN whose buffers do not fit gets nothing");
        assert_eq!(server.budget().used(), 0);
    }

    #[test]
    fn a_syn_for_a_closed_port_is_reset_and_reported() {
        let mut server = stack(SERVER, 1, Budget::unlimited());
        let mut client = stack(CLIENT, 2, Budget::unlimited());
        let remote: SocketAddr = format!("{SERVER}:81").parse().unwrap();
        control(
            &mut client,
            TcpControl::Connect {
                request: Request(5),
                remote,
            },
        );
        let opened_at_client = events(&mut client);
        let (at_server, at_client) = exchange(&mut server, &mut client, |_| true);
        assert!(at_server.iter().any(|e| matches!(
            e,
            MuxEvent::Control(MessageEvent::Message(TcpNotice::Refused { local, .. })) if *local == remote
        )));
        let MuxEvent::Opened(child, ..) = &opened_at_client[0] else {
            panic!("the connect opened its child at once");
        };
        let id = child.id();
        assert!(at_client.iter().any(|e| matches!(
            e,
            MuxEvent::Control(MessageEvent::Message(TcpNotice::ConnectFailed {
                request: Request(5),
                error: ConnError::Refused,
            }))
        )));
        assert!(
            at_client
                .iter()
                .any(|e| matches!(e, MuxEvent::Closed(closed) if *closed == id))
        );
        assert!(
            client.layer().upper().conns.is_empty(),
            "the refused attempt leaves nothing behind"
        );
    }

    #[test]
    fn a_write_past_the_credit_is_handed_back() {
        let (_server, mut client, _, (c, _)) = connected();
        let write: Command = c.send(StreamCommand::Write(Chunk::new(vec![0; MIN_BUFFER + 1])));
        let back = client.command(write);
        assert!(
            matches!(&back, Ok(Admit::Blocked(command)) if matches!(command.op(), MuxOp::Child(id, StreamCommand::Write(bytes)) if *id == c.id() && bytes.len() == MIN_BUFFER + 1)),
            "the whole write comes back"
        );
    }

    /// A step hands its packets on and keeps the emptied vector they were
    /// sent into, so the next step that sends allocates none.
    #[test]
    fn a_step_keeps_the_vector_it_sent_into() {
        let (mut server, _client, (s, _), _) = connected();
        let write: Command = s.send(StreamCommand::Write(Chunk::new(pattern(3000, 1))));
        assert!(matches!(server.command(write), Ok(Admit::Taken)));
        assert!(!sent(&mut server).is_empty());
        let tx = &server.layer().upper().dev.tx;
        assert!(tx.is_empty());
        assert!(tx.capacity() > 0, "the vector went with the packets");
    }

    /// Hands the server's layer a token to keep until the connection of
    /// `id` is gone, as a limit that counts connections does.
    fn hold(stack: &mut Stack, id: ChildId) -> Arc<()> {
        let token = Arc::new(());
        control(
            stack,
            TcpControl::Hold {
                child: id,
                item: Box::new(token.clone()),
            },
        );
        token
    }

    fn said_gone(seen: &[Up], id: ChildId) -> bool {
        seen.iter().any(|e| {
            matches!(
                e,
                MuxEvent::Control(MessageEvent::Message(TcpNotice::Gone(gone))) if *gone == id
            )
        })
    }

    /// Steps `stack` alone, from timer to timer, until `until`, and
    /// collects what it says.
    fn alone_until(stack: &mut Stack, until: Instant) -> Vec<Up> {
        let mut seen = Vec::new();
        loop {
            let _ = sent(stack);
            seen.extend(events(stack));
            match stack.deadline() {
                Some(at) if at <= until => stack.set_now(at),
                _ => return seen,
            }
        }
    }

    /// A connection whose peer falls silent times out while the layer
    /// above still holds its child. The transport has let it go, so it is
    /// gone, and what a limit kept for it is released without waiting for
    /// the child to close.
    #[test]
    fn a_connection_that_times_out_is_gone_with_its_child_open() {
        let (mut server, _client, (s, _), _) = connected();
        let token = hold(&mut server, s.id());
        let write: Command = s.send(StreamCommand::Write(Chunk::new(pattern(100, 4))));
        assert!(matches!(server.command(write), Ok(Admit::Taken)));
        let until = server.now() + TIMEOUT + Duration::from_secs(120);
        let seen = alone_until(&mut server, until);
        assert!(
            seen.iter()
                .any(|e| matches!(e, MuxEvent::Child(id, StreamEvent::Reset) if *id == s.id())),
            "the connection timed out"
        );
        assert!(said_gone(&seen, s.id()), "a timed-out connection is gone");
        assert_eq!(Arc::strong_count(&token), 1, "what it held is let go");
    }

    /// A connection that reaches TIME-WAIT while the layer above still
    /// holds its child is gone, as one whose child was closed is.
    #[test]
    fn an_open_child_in_time_wait_lets_go_of_what_it_held() {
        let (mut server, mut client, (s, _), (c, _)) = connected();
        let token = hold(&mut server, s.id());
        let end: Command = s.send(StreamCommand::End);
        assert!(matches!(server.command(end), Ok(Admit::Taken)));
        let _ = exchange(&mut server, &mut client, |_| true);
        let close: Command = c.close();
        assert!(matches!(client.command(close), Ok(Admit::Taken)));
        let (at_server, _) = exchange(&mut server, &mut client, |_| true);
        let h = server.layer().upper().socket_of(s.id());
        assert_eq!(server.layer().upper().get(h).state(), TcpState::TimeWait);
        assert!(said_gone(&at_server, s.id()), "TIME-WAIT is gone");
        assert_eq!(Arc::strong_count(&token), 1, "what it held is let go");
    }

    /// Something handed to a connection the peer already reset is let go
    /// at once, as for any connection that is gone, while the child is
    /// still open.
    #[test]
    fn a_hold_after_the_peers_reset_is_let_go_at_once() {
        let (mut server, mut client, (s, _), (c, _)) = connected();
        let reset: Command = c.send(StreamCommand::Reset);
        assert!(matches!(client.command(reset), Ok(Admit::Taken)));
        let (at_server, _) = exchange(&mut server, &mut client, |_| true);
        assert!(said_gone(&at_server, s.id()), "the peer's reset is gone");
        let token = hold(&mut server, s.id());
        assert_eq!(
            Arc::strong_count(&token),
            1,
            "a gone connection keeps nothing"
        );
    }

    /// The end of the layer below stops the endpoint and resets every
    /// connection. What open children held is released, and each is gone.
    #[test]
    fn a_stop_lets_go_of_what_open_children_held() {
        let (mut server, _client, (s, _), _) = connected();
        let token = hold(&mut server, s.id());
        assert!(matches!(
            server.deliver(PacketEvent::Ended),
            Ok(Admit::Taken)
        ));
        let _ = sent(&mut server);
        let seen = events(&mut server);
        assert!(
            said_gone(&seen, s.id()),
            "a stopped endpoint's connection is gone"
        );
        assert_eq!(Arc::strong_count(&token), 1, "what it held is let go");
    }

    /// Resetting a child whose connection is already gone into TIME-WAIT
    /// does nothing, as the command's contract says: no RST goes out.
    #[test]
    fn an_abort_after_time_wait_sends_nothing() {
        let (mut server, mut client, (s, _), (c, _)) = connected();
        let end: Command = s.send(StreamCommand::End);
        assert!(matches!(server.command(end), Ok(Admit::Taken)));
        let _ = exchange(&mut server, &mut client, |_| true);
        let close: Command = c.close();
        assert!(matches!(client.command(close), Ok(Admit::Taken)));
        let _ = exchange(&mut server, &mut client, |_| true);
        let h = server.layer().upper().socket_of(s.id());
        assert_eq!(server.layer().upper().get(h).state(), TcpState::TimeWait);
        control(&mut server, TcpControl::Abort(s.id()));
        let resets = sent(&mut server)
            .iter()
            .filter(|p| tcp_flags(p).is_some_and(|f| f & 4 != 0))
            .count();
        assert_eq!(resets, 0, "a connection in TIME-WAIT is not reset");
        assert_eq!(server.layer().upper().get(h).state(), TcpState::TimeWait);
    }

    /// Resetting a connection from above makes it gone at once, so what a
    /// limit kept for it is let go then, though the child is still open.
    #[test]
    fn an_abort_lets_go_of_what_the_connection_held() {
        let (mut server, _client, (s, _), _) = connected();
        let token = hold(&mut server, s.id());
        control(&mut server, TcpControl::Abort(s.id()));
        let seen = events(&mut server);
        assert!(said_gone(&seen, s.id()), "an aborted connection is gone");
        assert_eq!(Arc::strong_count(&token), 1, "what it held is let go");
    }

    /// Closing a child does not let go of what a limit kept for its
    /// connection while the connection is still closing: it counts until
    /// the transport retires it into TIME-WAIT.
    #[test]
    fn a_closed_childs_connection_counts_until_it_retires() {
        let (mut server, mut client, (s, _), (c, _)) = connected();
        let id = s.id();
        let token = hold(&mut server, id);
        let close: Command = s.close();
        assert!(matches!(server.command(close), Ok(Admit::Taken)));
        let (at_server, _) = exchange(&mut server, &mut client, |_| true);
        let h = server.layer().upper().socket_of(id);
        assert_eq!(server.layer().upper().get(h).state(), TcpState::FinWait2);
        assert!(
            !said_gone(&at_server, id),
            "a closing connection is not gone"
        );
        assert_eq!(
            Arc::strong_count(&token),
            2,
            "a closing connection still counts"
        );
        let close: Command = c.close();
        assert!(matches!(client.command(close), Ok(Admit::Taken)));
        let (at_server, _) = exchange(&mut server, &mut client, |_| true);
        assert!(said_gone(&at_server, id), "TIME-WAIT is gone");
        assert_eq!(Arc::strong_count(&token), 1, "what it held is let go");
    }

    /// A connection the peer resets while it waits in the backlog still
    /// opens a child when it is accepted, and that child is told at once
    /// that its connection is gone, not only once it is closed.
    #[test]
    fn a_connection_reset_before_it_is_accepted_opens_gone() {
        let mut server = stack(SERVER, 1, Budget::unlimited());
        let mut client = stack(CLIENT, 2, Budget::unlimited());
        control(
            &mut server,
            TcpControl::Listen {
                port: 80,
                backlog: None,
                answer: None,
            },
        );
        let remote: SocketAddr = format!("{SERVER}:80").parse().unwrap();
        control(
            &mut client,
            TcpControl::Connect {
                request: Request(1),
                remote,
            },
        );
        let mut at_client = events(&mut client);
        let (at_server, more) = exchange(&mut server, &mut client, |_| true);
        at_client.extend(more);
        assert!(at_server.iter().all(|e| !matches!(e, MuxEvent::Opened(..))));
        let (c, _) = opened(&mut at_client);
        let reset: Command = c.send(StreamCommand::Reset);
        assert!(matches!(client.command(reset), Ok(Admit::Taken)));
        let mut resets = 0;
        let _ = exchange(&mut server, &mut client, |p| {
            resets += usize::from(tcp_flags(p).is_some_and(|f| f & 4 != 0));
            true
        });
        assert!(resets >= 1, "the client's RST reached the server");
        control(&mut server, TcpControl::Accept { port: 80, count: 1 });
        let _ = sent(&mut server);
        let mut seen = events(&mut server);
        let (s, _) = opened(&mut seen);
        assert!(
            said_gone(&seen, s.id()),
            "a connection reset before accept is gone when its child opens"
        );
    }
}
