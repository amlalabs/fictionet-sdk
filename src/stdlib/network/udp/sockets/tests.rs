//! The UDP layer under the IP layer, fed packets built here and read back
//! by their headers.

use super::*;
use core::convert::Infallible;
use std::sync::Arc;

use fictionet::stdlib::layer::{
    Budget, Chain, Child, Children, Closing, Driver, MuxCommand, Side, Top,
};
use fictionet::stdlib::network::ip::Header;
use fictionet::stdlib::network::packet::{Ingress, IpLayer, NetworkInput, Scope, Scopes};
use fictionet::time::Instant;
use fictionet::{Seed, SeededEntropy};

type Stack = Chain<IpLayer, UdpLayer>;
type Up = EventOf<Udp>;

const HOST: &str = "10.0.0.1";

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

fn stack(budget: Budget) -> Driver<Stack> {
    let entropy = Arc::new(SeededEntropy::new(Seed::from_u64(7)));
    let udp = UdpLayer::new(HOST.parse().unwrap(), &*entropy);
    Driver::new(
        Chain::new(IpLayer::host(), udp),
        entropy,
        budget,
        Instant::ZERO,
    )
}

/// A UDP packet from `from` to `to`, its checksum computed over the
/// pseudo-header here.
fn datagram(from: SocketAddr, to: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut udp = [
        &from.port().to_be_bytes()[..],
        &to.port().to_be_bytes(),
        &((8 + payload.len()) as u16).to_be_bytes(),
        &[0, 0],
        payload,
    ]
    .concat();
    let sum = ip::transport_checksum(from.ip(), to.ip(), protocol::UDP, &udp);
    udp[6..8].copy_from_slice(&sum.to_be_bytes());
    ip::packet(from.ip(), to.ip(), protocol::UDP, &udp).into_vec()
}

/// Offers one raw packet and runs the stack.
fn arrive(d: &mut Driver<Stack>, bytes: Vec<u8>) {
    let raw = fictionet::Packet::new(bytes);
    assert!(matches!(
        d.deliver(PacketEvent::Packet(raw)),
        Ok(Admit::Taken)
    ));
    d.run().unwrap();
}

fn command(d: &mut Driver<Stack>, command: MuxCommand<Datagrams<SocketAddr>, Control>) {
    assert!(matches!(d.command(command), Ok(Admit::Taken)));
    d.run().unwrap();
}

type Control = Messages<UdpNotice, UdpControl>;

fn control(c: UdpControl) -> MuxCommand<Datagrams<SocketAddr>, Control> {
    MuxCommand::control(MessageCommand::Send(c))
}

/// Everything the stack hands up now.
fn up(d: &mut Driver<Stack>) -> Vec<Up> {
    let mut out = Vec::new();
    d.send_above(|event| {
        out.push(event);
        Admit::Taken
    });
    out
}

/// Everything the stack hands down, through the IP layer's one slot.
fn down(d: &mut Driver<Stack>) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let moved = d.send_below(|command| {
            if let PacketCommand::Send(bytes) = command {
                out.push(bytes.to_vec());
            }
            Admit::Taken
        });
        let ran = d.run().unwrap();
        if !moved && !ran {
            return out;
        }
    }
}

/// Binds `port` and returns the child with its opening and the send
/// credit that came with it.
fn bind(d: &mut Driver<Stack>, request: u64, port: u16) -> (Child, UdpBound, u64) {
    command(
        d,
        control(UdpControl::Bind {
            request: Request(request),
            port,
        }),
    );
    let mut opened = None;
    let mut credit = 0;
    for event in up(d) {
        match event {
            MuxEvent::Opened(child, bound, max) => {
                assert_eq!(max, 1, "one datagram costs one unit");
                opened = Some((child, bound));
            }
            MuxEvent::Credit(_, units) => credit += units,
            _ => panic!("a bind brought something else up"),
        }
    }
    let (child, bound) = opened.expect("the bind opened a child");
    (child, bound, credit)
}

/// The child events and notices among `events`, as plain values.
#[derive(Debug, PartialEq, Eq)]
enum Seen {
    Datagram(ChildId, Vec<u8>, SocketAddr),
    Ended(ChildId),
    Closed(ChildId),
    Notice(UdpNotice),
}

fn seen(events: Vec<Up>) -> Vec<Seen> {
    events
        .into_iter()
        .filter_map(|event| match event {
            MuxEvent::Child(id, DatagramEvent::Datagram(d)) => {
                let (payload, peer) = d.into_parts();
                Some(Seen::Datagram(id, payload.to_vec(), peer))
            }
            MuxEvent::Child(id, DatagramEvent::Ended) => Some(Seen::Ended(id)),
            MuxEvent::Closed(id) => Some(Seen::Closed(id)),
            MuxEvent::Control(MessageEvent::Message(notice)) => Some(Seen::Notice(notice)),
            _ => None,
        })
        .collect()
}

#[test]
fn send_completions_follow_handoff_and_pass_receive_credit() {
    let entropy = SeededEntropy::new(Seed::from_u64(11));
    let budget = Budget::unlimited();
    let mut reports = fictionet::stdlib::layer::Observations::new(0);
    let mut env = Env::new(Instant::ZERO, &entropy, &budget, &mut reports);
    let mut udp = UdpLayer::new(HOST.parse().unwrap(), &entropy);
    assert!(matches!(
        udp.on_command(
            &mut env,
            control(UdpControl::Bind {
                request: Request(0),
                port: 53,
            })
        ),
        Ok(Admit::Taken)
    ));
    let Some(MuxEvent::Opened(child, _, _)) = udp.take_event() else {
        panic!("socket not opened")
    };
    assert!(matches!(udp.take_event(), Some(MuxEvent::Credit(_, _))));
    let peer = addr("10.0.0.2:1234");
    // A valid send, a local drop, and an untracked send share one queue.
    // A local drop must not complete the earlier send before its handoff.
    for (to, tracked) in [(peer, true), (addr("[::1]:1234"), true), (peer, false)] {
        let datagram = Datagram::new(Chunk::unpaid(Vec::new()), to);
        let datagram = if tracked {
            datagram.with_completion()
        } else {
            datagram
        };
        assert!(matches!(
            udp.on_command(&mut env, child.send(DatagramCommand::Send(datagram))),
            Ok(Admit::Taken)
        ));
    }
    assert!(udp.take_event().is_none());
    assert!(udp.take_urgent().is_none());
    assert!(udp.take_command(&mut env).is_some());
    assert!(
        matches!(udp.take_urgent(), Some(MuxEvent::Child(id, DatagramEvent::Sent(1))) if id == child.id())
    );
    assert!(udp.take_urgent().is_none());
    assert!(udp.take_command(&mut env).is_some());
    assert!(
        matches!(udp.take_urgent(), Some(MuxEvent::Child(id, DatagramEvent::Sent(1))) if id == child.id())
    );
    assert!(udp.take_command(&mut env).is_none());
    assert!(udp.take_urgent().is_none());
    assert!(matches!(udp.take_event(), Some(MuxEvent::Credit(_, 3))));
    assert!(udp.take_event().is_none());
}

#[test]
fn a_bound_socket_gets_each_datagram_whole_with_its_peer() {
    let mut d = stack(Budget::unlimited());
    let (child, bound, _) = bind(&mut d, 4, 53);
    assert_eq!(
        bound,
        UdpBound {
            local: addr("10.0.0.1:53"),
            request: Request(4),
        }
    );
    command(&mut d, child.grant(8));
    let peer = addr("10.0.0.2:1234");
    let sent: [&[u8]; 3] = [b"", b"query", &[0; 1400]];
    for payload in sent {
        arrive(&mut d, datagram(peer, bound.local, payload));
    }
    let expected: Vec<Seen> = sent
        .iter()
        .map(|payload| Seen::Datagram(child.id(), payload.to_vec(), peer))
        .collect();
    assert_eq!(seen(up(&mut d)), expected);
}

/// A packet whose IPv4 header checksum is wrong, and a good one labelled
/// with a tunnel's network on input that carries both networks, reach no
/// socket, though each carries a good UDP datagram for the bound port.
#[test]
fn malformed_and_foreign_host_packets_reach_no_socket() {
    let mut d = stack(Budget::unlimited());
    let (child, bound, _) = bind(&mut d, 1, 53);
    let peer = addr("10.0.0.2:1234");
    let mut bad_header = datagram(peer, bound.local, b"observed");
    bad_header[10] ^= 1;
    arrive(&mut d, bad_header);
    let input = NetworkInput::new(Scope::ROOT);
    let tunnel = Scopes::default().tunnel();
    for (scope, payload) in [(tunnel, &b"tunnel"[..]), (Scope::ROOT, b"mine")] {
        let labelled = Datagram::new(
            Chunk::unpaid(datagram(peer, bound.local, payload)),
            Ingress {
                scope,
                ..Ingress::default()
            },
        );
        if let Ok(raw) = input.accept(labelled) {
            arrive(&mut d, raw.into_vec());
        }
    }
    assert!(matches!(d.command(child.grant(4)), Ok(Admit::Taken)));
    d.run().unwrap();
    assert_eq!(
        seen(up(&mut d)),
        [Seen::Datagram(child.id(), b"mine".to_vec(), peer)]
    );
}

#[test]
fn datagrams_go_up_only_within_the_credit_granted() {
    let mut d = stack(Budget::unlimited());
    let (child, bound, _) = bind(&mut d, 0, 53);
    let peer = addr("10.0.0.2:1234");
    for n in 0..3u8 {
        arrive(&mut d, datagram(peer, bound.local, &[n]));
    }
    assert_eq!(seen(up(&mut d)), []);
    command(&mut d, child.grant(1));
    assert_eq!(
        seen(up(&mut d)),
        [Seen::Datagram(child.id(), vec![0], peer)]
    );
    command(&mut d, child.grant(5));
    assert_eq!(
        seen(up(&mut d)),
        [
            Seen::Datagram(child.id(), vec![1], peer),
            Seen::Datagram(child.id(), vec![2], peer),
        ]
    );
}

/// The ICMP error in `answer`, as (type, code, quoted bytes), checked to
/// come from the host and go back to `peer`.
fn icmp_error(answer: &[u8], peer: SocketAddr) -> (u8, u8, Vec<u8>) {
    let header = Header::parse_whole(answer).expect("a whole IP packet");
    assert_eq!(header.src, HOST.parse::<IpAddr>().unwrap());
    assert_eq!(header.dst, peer.ip());
    assert_eq!(header.protocol, protocol::ICMP);
    let message = header.payload(answer);
    (message[0], message[1], message[8..].to_vec())
}

#[test]
fn a_closed_port_is_answered_and_reported_and_port_zero_can_be_silent() {
    let mut d = stack(Budget::unlimited());
    let peer = addr("10.0.0.2:1234");
    for port in [9, 0] {
        let local = SocketAddr::new(HOST.parse().unwrap(), port);
        let packet = datagram(peer, local, b"hello");
        arrive(&mut d, packet.clone());
        let answers = down(&mut d);
        assert_eq!(answers.len(), 1, "port {port} is answered by default");
        assert_eq!(icmp_error(&answers[0], peer), (3, 3, packet));
        assert_eq!(
            seen(up(&mut d)),
            [Seen::Notice(UdpNotice::Refused { peer, local })]
        );
    }

    d.layer_mut().upper_mut().set_settings(Settings {
        port_zero: PortZero::Silent,
    });
    let zero = addr("10.0.0.1:0");
    arrive(&mut d, datagram(peer, zero, b"hello"));
    assert_eq!(down(&mut d), Vec::<Vec<u8>>::new());
    assert_eq!(
        seen(up(&mut d)),
        [Seen::Notice(UdpNotice::Refused { peer, local: zero })]
    );
    // Only port zero is silent.
    arrive(&mut d, datagram(peer, addr("10.0.0.1:9"), b"hello"));
    assert_eq!(down(&mut d).len(), 1);
}

#[test]
fn bad_checksums_bad_lengths_and_other_addresses_are_dropped() {
    let mut d = stack(Budget::unlimited());
    let peer = addr("10.0.0.2:1234");
    let local = addr("10.0.0.1:9");
    let mut bad_sum = datagram(peer, local, b"query");
    *bad_sum.last_mut().unwrap() ^= 1;
    let mut short = datagram(peer, local, b"query");
    // A UDP length of seven, below the header's own eight bytes.
    short[24..26].copy_from_slice(&7u16.to_be_bytes());
    let mut long = datagram(peer, local, b"query");
    long[24..26].copy_from_slice(&100u16.to_be_bytes());
    let elsewhere = datagram(peer, addr("10.0.0.3:9"), b"query");
    // Over IPv6 a zero checksum is not "no checksum".
    let (src6, dst6) = (addr("[fd00::2]:1234"), addr("[fd00::1]:9"));
    let mut udp6 = datagram(src6, dst6, b"query");
    udp6[46..48].copy_from_slice(&[0, 0]);
    for packet in [bad_sum, short, long, elsewhere] {
        arrive(&mut d, packet);
    }
    assert_eq!(seen(up(&mut d)), []);
    assert_eq!(down(&mut d), Vec::<Vec<u8>>::new());

    let entropy = SeededEntropy::new(Seed::from_u64(1));
    let udp = UdpLayer::new(dst6.ip(), &entropy);
    let mut d6 = Driver::new(
        Chain::new(IpLayer::host(), udp),
        Arc::new(entropy),
        Budget::unlimited(),
        Instant::ZERO,
    );
    arrive(&mut d6, udp6);
    assert_eq!(seen(up(&mut d6)), []);
    assert_eq!(down(&mut d6), Vec::<Vec<u8>>::new());
}

#[test]
fn a_joined_group_reaches_its_port_and_goes_unanswered_elsewhere() {
    let mut d = stack(Budget::unlimited());
    let (child, _, _) = bind(&mut d, 0, 5353);
    command(&mut d, child.grant(8));
    let group: IpAddr = "239.1.2.3".parse().unwrap();
    let peer = addr("10.0.0.2:5353");
    arrive(
        &mut d,
        datagram(peer, SocketAddr::new(group, 5353), b"before"),
    );
    assert_eq!(seen(up(&mut d)), []);

    command(&mut d, control(UdpControl::Join(group)));
    command(
        &mut d,
        control(UdpControl::Join("10.0.0.9".parse().unwrap())),
    );
    command(
        &mut d,
        control(UdpControl::Join("ff02::fb".parse().unwrap())),
    );
    assert_eq!(
        seen(up(&mut d)),
        [
            Seen::Notice(UdpNotice::JoinFailed("10.0.0.9".parse().unwrap())),
            Seen::Notice(UdpNotice::JoinFailed("ff02::fb".parse().unwrap())),
        ]
    );
    arrive(
        &mut d,
        datagram(peer, SocketAddr::new(group, 5353), b"member"),
    );
    arrive(
        &mut d,
        datagram(peer, SocketAddr::new(group, 9), b"nobody bound"),
    );
    assert_eq!(
        seen(up(&mut d)),
        [Seen::Datagram(child.id(), b"member".to_vec(), peer)]
    );
    assert_eq!(down(&mut d), Vec::<Vec<u8>>::new());

    command(&mut d, control(UdpControl::Leave(group)));
    arrive(
        &mut d,
        datagram(peer, SocketAddr::new(group, 5353), b"after"),
    );
    assert_eq!(seen(up(&mut d)), []);
}

#[test]
fn binding_zero_takes_free_ephemeral_ports_and_a_taken_port_fails() {
    let mut d = stack(Budget::unlimited());
    let (_, first, _) = bind(&mut d, 1, 0);
    let (_, second, _) = bind(&mut d, 2, 0);
    for bound in [first, second] {
        assert!(bound.local.port() >= 49152, "{bound:?}");
        assert!(d.layer().upper().is_bound(bound.local.port()));
    }
    assert_ne!(first.local.port(), second.local.port());
    assert!(!d.layer().upper().is_bound(0));

    let (child, _, _) = bind(&mut d, 3, 53);
    command(
        &mut d,
        control(UdpControl::Bind {
            request: Request(4),
            port: 53,
        }),
    );
    assert_eq!(
        seen(up(&mut d)),
        [Seen::Notice(UdpNotice::BindFailed {
            request: Request(4),
            port: 53,
        })]
    );
    // A socket that ends frees its port, and says it closed.
    let id = child.id();
    command(&mut d, child.send(DatagramCommand::End));
    assert_eq!(seen(up(&mut d)), [Seen::Closed(id)]);
    assert!(!d.layer().upper().is_bound(53));
    let (again, bound, _) = bind(&mut d, 5, 53);
    assert_ne!(again.id(), id);
    assert_eq!(bound.local.port(), 53);
    // So does a handle's close, with nothing more to say.
    command(&mut d, again.close(Closing::Done));
    assert_eq!(seen(up(&mut d)), []);
    assert!(!d.layer().upper().is_bound(53));
}

#[test]
fn a_full_queue_drops_what_does_not_fit_and_charges_go_with_datagrams() {
    let budget = Budget::new(4 << 20);
    let mut d = stack(budget.clone());
    let (child, bound, _) = bind(&mut d, 0, 53);
    let peer = addr("10.0.0.2:1234");
    let payload = vec![7; 60_000];
    let cost = payload.len() + DATAGRAM_COST;
    let fits = QUEUE / cost;
    let sent = fits + 3;
    for _ in 0..sent {
        arrive(&mut d, datagram(peer, bound.local, &payload));
    }
    let dropped: Vec<UdpReport> = d
        .observations()
        .drain()
        .filter_map(|report| match report {
            Side::Upper(report) => Some(report),
            Side::Lower(_) => None,
        })
        .collect();
    assert_eq!(
        dropped,
        vec![
            UdpReport::Dropped {
                local: bound.local,
                peer,
                cause: Dropped::QueueFull,
            };
            sent - fits
        ]
    );
    let held = budget.used();
    assert!(held >= fits * cost, "{held} for {fits} datagrams");

    command(&mut d, child.grant(1));
    let mut first = up(&mut d);
    assert_eq!(first.len(), 1);
    // The datagram took the charge for its bytes up with it, and its place
    // in the queue went back as it left.
    assert_eq!(budget.used(), held - DATAGRAM_COST);
    first.clear();
    assert_eq!(budget.used(), held - cost);
    // And room for one more.
    arrive(&mut d, datagram(peer, bound.local, &payload));
    assert_eq!(d.observations().drain().count(), 0);
}

#[test]
fn a_datagram_the_budget_has_no_room_for_is_dropped() {
    let budget = Budget::new(100);
    let mut d = stack(budget.clone());
    let (child, bound, _) = bind(&mut d, 0, 53);
    let peer = addr("10.0.0.2:1234");
    arrive(&mut d, datagram(peer, bound.local, &[1; 50]));
    let reports: Vec<_> = d.observations().drain().collect();
    assert_eq!(
        reports,
        [Side::Upper(UdpReport::Dropped {
            local: bound.local,
            peer,
            cause: Dropped::Budget,
        })]
    );
    assert_eq!(budget.used(), 0);
    arrive(&mut d, datagram(peer, bound.local, b""));
    command(&mut d, child.grant(1));
    assert_eq!(
        seen(up(&mut d)),
        [Seen::Datagram(child.id(), Vec::new(), peer)]
    );
}

#[test]
fn a_socket_sends_each_datagram_whole_in_one_packet_from_its_port() {
    let mut d = stack(Budget::unlimited());
    let (child, bound, credit) = bind(&mut d, 0, 5353);
    assert!(credit > 0);
    let peer = addr("10.0.0.2:40000");
    let sent: [&[u8]; 2] = [b"", b"answer"];
    for payload in sent {
        let datagram = Datagram::new(Chunk::unpaid(payload.to_vec()), peer);
        command(&mut d, child.send(DatagramCommand::Send(datagram)));
    }
    let packets = down(&mut d);
    assert_eq!(packets.len(), sent.len());
    let mut ids = Vec::new();
    for (packet, payload) in packets.iter().zip(sent) {
        let header = Header::parse_whole(packet).expect("a whole IP packet");
        assert_eq!((header.src, header.dst), (bound.local.ip(), peer.ip()));
        assert_eq!(header.protocol, protocol::UDP);
        assert!(header.fragment.is_none());
        let udp = header.payload(packet);
        assert!(ip::udp_checksum_ok(header.src, header.dst, udp));
        let read = wire::Datagram::parse(udp).unwrap();
        assert_eq!(read.source_port(), bound.local.port());
        assert_eq!(read.destination_port(), peer.port());
        assert_eq!(read.payload(), payload);
        ids.push(u16::from_be_bytes([packet[4], packet[5]]));
    }
    assert_eq!(ids[1], ids[0].wrapping_add(1));

    // Too long for one packet, or for the other IP version: lost, and the
    // credit comes back.
    for (payload, to) in [
        (vec![0; 70_000], peer),
        (b"v6".to_vec(), addr("[fd00::2]:40000")),
    ] {
        let datagram = Datagram::new(Chunk::unpaid(payload), to);
        command(&mut d, child.send(DatagramCommand::Send(datagram)));
    }
    assert_eq!(down(&mut d), Vec::<Vec<u8>>::new());
    let returned: u64 = up(&mut d)
        .into_iter()
        .map(|event| match event {
            MuxEvent::Credit(id, units) if id == child.id() => units,
            _ => panic!("only credit comes back"),
        })
        .sum();
    assert_eq!(returned, 4, "every unit used comes back");
}

#[test]
fn a_command_beyond_the_credit_granted_is_an_overrun() {
    let mut d = stack(Budget::unlimited());
    let (child, _, credit) = bind(&mut d, 0, 5353);
    let peer = addr("10.0.0.2:40000");
    for _ in 0..credit {
        let datagram = Datagram::new(Chunk::unpaid(b"x".to_vec()), peer);
        assert!(matches!(
            d.command(child.send(DatagramCommand::Send(datagram))),
            Ok(Admit::Taken)
        ));
    }
    let datagram = Datagram::new(Chunk::unpaid(b"x".to_vec()), peer);
    assert!(matches!(
        d.command(child.send(DatagramCommand::Send(datagram))),
        Err(Side::Upper(Overrun(id))) if id == child.id()
    ));
}

#[test]
fn each_socket_ends_after_the_datagrams_it_holds() {
    let mut d = stack(Budget::unlimited());
    let (child, bound, _) = bind(&mut d, 0, 53);
    let peer = addr("10.0.0.2:1234");
    for payload in [b"one", b"two"] {
        arrive(&mut d, datagram(peer, bound.local, payload));
    }
    assert!(matches!(d.deliver(PacketEvent::Ended), Ok(Admit::Taken)));
    d.run().unwrap();
    assert_eq!(seen(up(&mut d)), []);
    command(&mut d, child.grant(2));
    assert_eq!(
        seen(up(&mut d)),
        [
            Seen::Datagram(child.id(), b"one".to_vec(), peer),
            Seen::Datagram(child.id(), b"two".to_vec(), peer),
            Seen::Ended(child.id()),
        ]
    );
    // A socket bound after the end ends at once.
    command(
        &mut d,
        control(UdpControl::Bind {
            request: Request(1),
            port: 54,
        }),
    );
    let later = up(&mut d);
    let id = match &later[0] {
        MuxEvent::Opened(child, _, _) => child.id(),
        _ => panic!("the bind opened no child"),
    };
    assert_eq!(seen(later), [Seen::Ended(id)]);
}

#[test]
fn a_full_layer_refuses_a_packet_unchanged() {
    let mut d = stack(Budget::unlimited());
    let peer = addr("10.0.0.2:1234");
    let local = addr("10.0.0.1:9");
    // Refusals nobody takes fill the layer, and then the slots below it.
    let mut taken = 0;
    let back = loop {
        assert!(taken <= 2 * HELD, "the layer kept taking packets");
        let packet = datagram(peer, local, &(taken as u32).to_be_bytes());
        let raw = fictionet::Packet::new(packet.clone());
        match d.deliver(PacketEvent::Packet(raw)) {
            Ok(Admit::Taken) => taken += 1,
            Ok(Admit::Blocked(PacketEvent::Packet(back))) => break (back, packet),
            _ => panic!("the layer neither took nor refused a packet"),
        }
        d.run().unwrap();
    };
    assert!(taken >= HELD, "only {taken} packets were taken");
    let (back, packet) = back;
    assert_eq!(&back[..], &packet[..]);
    // Once its output is taken, every packet it took is answered and
    // reported once, and the refused one goes in as it was.
    let (mut notices, mut answers) = (0, 0);
    for _ in 0..taken {
        notices += seen(up(&mut d)).len();
        answers += down(&mut d).len();
        d.run().unwrap();
    }
    assert_eq!((notices, answers), (taken, taken));
    arrive(&mut d, packet);
    assert_eq!(seen(up(&mut d)).len(), 1);
}

/// Answers every datagram with the same bytes, and ends when its socket
/// does.
struct Echo {
    out: VecDeque<DatagramCommand<SocketAddr>>,
}

impl Layer for Echo {
    type Lower = Datagrams<SocketAddr>;
    type Upper = Top;
    type Report = ();
    type Timer = ();
    type Work = ();
    type Done = ();
    type Error = Infallible;

    fn on_event(
        &mut self,
        _: &mut Env<'_, ()>,
        event: DatagramEvent<SocketAddr>,
    ) -> Result<Admit<DatagramEvent<SocketAddr>>, Infallible> {
        self.out.push_back(match event {
            DatagramEvent::Datagram(d) => DatagramCommand::Send(d),
            DatagramEvent::Ended => DatagramCommand::End,
            DatagramEvent::Sent(_) => return Ok(Admit::Taken),
        });
        Ok(Admit::Taken)
    }

    fn on_command(
        &mut self,
        _: &mut Env<'_, ()>,
        command: Infallible,
    ) -> Result<Admit<Infallible>, Infallible> {
        match command {}
    }

    fn take_command(
        &mut self,
        _: &mut Env<'_, Self::Report>,
    ) -> Option<DatagramCommand<SocketAddr>> {
        self.out.pop_front()
    }

    fn take_event(&mut self) -> Option<Infallible> {
        None
    }
}

#[test]
fn an_application_on_each_socket_answers_through_ip_and_udp() {
    let entropy = Arc::new(SeededEntropy::new(Seed::from_u64(9)));
    let udp = UdpLayer::new(HOST.parse().unwrap(), &*entropy);
    let apps = Children::<Echo, Control, UdpBound>::new(4, 8, |_, bound, _| {
        assert_eq!(bound.local.ip(), HOST.parse::<IpAddr>().unwrap());
        Some(Echo {
            out: VecDeque::new(),
        })
    });
    let mut d = Driver::new(
        Chain::new(Chain::new(IpLayer::host(), udp), apps),
        entropy,
        Budget::new(1 << 20),
        Instant::ZERO,
    );
    for (request, port) in [(1, 7), (2, 0)] {
        let bind = MessageCommand::Send(UdpControl::Bind {
            request: Request(request),
            port,
        });
        assert!(matches!(d.command(bind), Ok(Admit::Taken)));
    }
    d.run().unwrap();
    let echo = addr("10.0.0.1:7");
    let peers = [addr("10.0.0.2:1000"), addr("10.0.0.3:2000")];
    let sent: [&[u8]; 3] = [b"", b"ping", b"again"];
    let mut expected = Vec::new();
    for (n, payload) in sent.iter().enumerate() {
        let peer = peers[n % peers.len()];
        let raw = fictionet::Packet::new(datagram(peer, echo, payload));
        assert!(matches!(
            d.deliver(PacketEvent::Packet(raw)),
            Ok(Admit::Taken)
        ));
        d.run().unwrap();
        expected.push((peer, payload.to_vec()));
    }
    let mut answers = Vec::new();
    for _ in 0..4 {
        d.send_below(|command| {
            if let PacketCommand::Send(bytes) = command {
                answers.push(bytes.to_vec());
            }
            Admit::Taken
        });
        d.run().unwrap();
    }
    let got: Vec<(SocketAddr, Vec<u8>)> = answers
        .iter()
        .map(|packet| {
            let header = Header::parse_whole(packet).unwrap();
            let read = wire::Datagram::parse(header.payload(packet)).unwrap();
            assert_eq!(SocketAddr::new(header.src, read.source_port()), echo);
            (
                SocketAddr::new(header.dst, read.destination_port()),
                read.payload().to_vec(),
            )
        })
        .collect();
    assert_eq!(got, expected);
    // Nothing above is told about the sockets' traffic.
    let mut notices = 0;
    d.send_above(|event| {
        if let MessageEvent::Message(_) = event {
            notices += 1;
        }
        Admit::Taken
    });
    assert_eq!(notices, 0);
}
