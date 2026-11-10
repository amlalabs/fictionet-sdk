//! The set's scheduling, driven as an endpoint drives it: deadlines kept
//! in an index, and one segment per ready socket each pass, rotating past
//! the last one served when the output fills.

use fictionet_buf::Budget;

use super::*;
use crate::socket::tcp::Socket;
use crate::wire::Ipv4Address;

fn socket() -> Socket {
    Socket::new(64, 64, Budget::unlimited())
}

const LOCAL: (Ipv4Address, u16) = (Ipv4Address::new(192, 168, 1, 1), 4242);
const REMOTE: Ipv4Address = Ipv4Address::new(192, 168, 1, 2);

/// One egress pass at `now` with room for `room` segments, as an endpoint
/// makes it: the destination port of each segment sent.
fn egress(sockets: &mut SocketSet, cx: &mut Context, now: Instant, room: usize) -> Vec<u16> {
    cx.set_now(now);
    let mut sent = Vec::new();
    let count = sockets.prepare(cx, now);
    for _ in 0..count {
        let Some(handle) = sockets.next_ready() else {
            break;
        };
        let result = sockets.get_mut(handle).dispatch(cx, |_, (_, tcp, _)| {
            if sent.len() == room {
                return Err(());
            }
            sent.push(tcp.dst_port);
            Ok(())
        });
        sockets.dispatched(handle, result.is_err());
        if result.is_err() {
            return sent;
        }
    }
    sockets.finish_egress();
    sent
}

/// The deadline the index gives is the earliest any socket asks for.
fn check(sockets: &mut SocketSet, cx: &mut Context, now: Instant) {
    cx.set_now(now);
    let expected = sockets
        .iter()
        .filter_map(|(_, socket)| match socket.poll_at(cx) {
            PollAt::Ingress => None,
            PollAt::Time(at) => Some(at),
            PollAt::Now => Some(Instant::ZERO),
        })
        .min();
    sockets.schedule(cx);
    assert_eq!(sockets.next_deadline(), expected);
}

#[test]
fn indexed_deadlines_follow_mutation_removal_and_slot_reuse() {
    let mut cx = crate::tests::context();
    let mut sockets = SocketSet::default();
    let mut handles = Vec::new();
    for port in [80, 81, 82] {
        let mut s = socket();
        s.connect(&mut cx, (REMOTE, port), LOCAL).unwrap();
        handles.push(sockets.add(s));
    }
    for millis in [0, 500, 1000, 2000] {
        let now = Instant::from_millis(millis);
        check(&mut sockets, &mut cx, now);
        egress(&mut sockets, &mut cx, now, usize::MAX);
        check(&mut sockets, &mut cx, now);
    }
    sockets
        .get_mut(handles[0])
        .set_timeout(Some(crate::time::Duration::from_millis(2500)));
    check(&mut sockets, &mut cx, Instant::from_millis(2000));
    sockets.remove(handles[0]);
    let mut listener = socket();
    listener.listen(4243).unwrap();
    assert_eq!(sockets.add(listener), handles[0]);
    check(&mut sockets, &mut cx, Instant::from_millis(2000));
    for h in handles {
        sockets.remove(h);
    }
    sockets.schedule(&mut cx);
    assert_eq!(sockets.next_deadline(), None);
}

#[test]
fn egress_keeps_slot_order_after_an_unsaturated_pass() {
    let mut cx = crate::tests::context();
    let mut sockets = SocketSet::default();
    let mut handles = Vec::new();
    for port in [80, 81] {
        let mut s = socket();
        s.connect(&mut cx, (REMOTE, port), LOCAL).unwrap();
        handles.push(sockets.add(s));
    }
    egress(&mut sockets, &mut cx, Instant::ZERO, usize::MAX);
    sockets.get_mut(handles[0]).abort();
    egress(&mut sockets, &mut cx, Instant::ZERO, usize::MAX);
    sockets
        .get_mut(handles[0])
        .connect(&mut cx, (REMOTE, 80), LOCAL)
        .unwrap();
    sockets.get_mut(handles[1]).abort();
    let ports = egress(&mut sockets, &mut cx, Instant::ZERO, usize::MAX);
    assert_eq!(ports, [80, 81]);
}

#[test]
fn egress_rotates_when_an_earlier_socket_becomes_ready_again() {
    let mut cx = crate::tests::context();
    let mut sockets = SocketSet::default();
    let mut handles = Vec::new();
    for port in [80, 81] {
        let mut s = socket();
        s.connect(&mut cx, (REMOTE, port), LOCAL).unwrap();
        handles.push(sockets.add(s));
    }
    let mut ports = egress(&mut sockets, &mut cx, Instant::ZERO, 1);
    sockets.get_mut(handles[0]).abort();
    ports.extend(egress(&mut sockets, &mut cx, Instant::ZERO, 1));
    // The output took one segment each time: the second pass serves the
    // socket after the one served last, though the first is ready again.
    assert_eq!(ports, [80, 81]);
    assert_eq!(egress(&mut sockets, &mut cx, Instant::ZERO, 1), [80]);
}
