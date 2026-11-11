//! Resource properties of TCP and below, on sessions built to stress them
//! (verification/README.md, "Resource properties"): fragment reassembly
//! under floods of tiny fragments, in and out of order, and of first
//! fragments that time out; UDP sockets under floods of tiny datagrams;
//! and the blocks a sandbox's packets arrive in. Every step is costed
//! with verification/resources/cost.rs: what is live at any moment stays
//! within the charge, and the bytes a step asks for stay linear in its
//! input. The bounds and their constants are in
//! verification/packet-udp/README.md, "Resource properties".

use std::net::{IpAddr, Ipv4Addr};

use fictionet::stdlib::network::ip::{self, Fields, Intake, Reassembly};
use fictionet::time::{Duration, Instant};
use fictionet::{Chunk, Packet};

use crate::common::cost::{Charged, Costs, Linear};

/// An IPv4 fragment from `src` with identification `id`: `data` at
/// `offset` bytes, with "more fragments" set when `more`.
fn fragment(src: u32, id: u16, offset: usize, more: bool, data: &[u8]) -> Chunk {
    let p = ip::packet_with(
        IpAddr::V4(Ipv4Addr::from(src)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        17,
        Fields {
            id,
            dont_fragment: false,
            ..Fields::default()
        },
        data,
    );
    let mut bytes = p.into_vec();
    let word = ((offset / 8) as u16) | if more { 0x2000 } else { 0 };
    bytes[6..8].copy_from_slice(&word.to_be_bytes());
    bytes[10..12].copy_from_slice(&[0, 0]);
    let sum = ip::checksum(&bytes[..20]);
    bytes[10..12].copy_from_slice(&sum.to_be_bytes());
    Packet::new(bytes).into_chunk()
}

/// A step's linear bound. The packet the step takes in is built inside it,
/// as cost.rs asks, so that freeing it is the step's: its bytes and two
/// chunk headers (`fragment`). Then the fragment's data and the first
/// fragment's headers are copied once each, and they are disjoint parts
/// of the packet: two bytes asked for each byte of input in all. Besides,
/// an entry added to a `BTreeMap` may split a node at every level: three
/// trees (the packets, their deadlines, and a packet's pieces, or the
/// first fragments kept), at most 8 levels for the entries 4 MiB can
/// count, and at most 2 KiB a node.
const REASSEMBLY_STEP: Linear = Linear {
    num: 2,
    den: 1,
    fixed: 3 * 8 * 2048 + 2 * Chunk::HEADER,
};

/// What a step hands out, which its taker pays for when it takes it in:
/// a whole packet, or a first fragment kept for an answer, each in a chunk
/// of its own.
fn handed_out(chunk: &Chunk) -> usize {
    chunk.len() + Chunk::HEADER
}

/// One fragment for [`push`]: [`fragment`]'s arguments.
struct Frag<'a> {
    src: u32,
    id: u16,
    offset: usize,
    more: bool,
    data: &'a [u8],
}

/// Builds `f` and pushes it at `now` as one costed step: within
/// `Reassembly::MOST_HELD`, and linear in the packet.
fn push(costs: &mut Costs, r: &mut Reassembly, f: Frag<'_>, now: Instant) -> &'static str {
    let input = 20 + f.data.len();
    costs.step(input, Reassembly::MOST_HELD, REASSEMBLY_STEP, || {
        let packet = fragment(f.src, f.id, f.offset, f.more, f.data);
        let intake = r.push(packet, now);
        let (value, charged) = match &intake {
            Intake::Whole(whole) => ("whole", handed_out(whole)),
            Intake::Waiting => ("waiting", 0),
            Intake::Discarded => ("discarded", 0),
            Intake::Refused { packet, answer } => (
                "refused",
                handed_out(packet) + answer.as_ref().map_or(0, handed_out),
            ),
        };
        drop(intake);
        Charged::new(value, charged)
    })
}

/// Expires what is due at `now` as one costed step. It copies nothing: it
/// moves each first fragment it keeps, and asks only for the nodes of the
/// map that keeps them, which their count covers. That count is never more
/// than their packets counted, so the step's input is what was counted
/// before it ([`Reassembly::counted`]), one byte asked for each at most.
fn expire(costs: &mut Costs, r: &mut Reassembly, now: Instant) {
    let counted = r.counted();
    let moved = Linear {
        num: 1,
        den: 1,
        fixed: 0,
    };
    costs.step(counted, Reassembly::MOST_HELD, moved, || {
        r.expire(now);
        Charged::new((), 0)
    });
}

/// Expires what is due at `now`, then takes every first fragment kept, as
/// costed steps.
fn expire_and_take(costs: &mut Costs, r: &mut Reassembly, now: Instant) -> usize {
    expire(costs, r, now);
    let mut taken = 0;
    while costs.step(0, Reassembly::MOST_HELD, REASSEMBLY_STEP, || {
        let first = r.take_expired();
        let charged = first.as_ref().map_or(0, handed_out);
        Charged::new(first.is_some(), charged)
    }) {
        taken += 1;
    }
    taken
}

fn at(secs: u64) -> Instant {
    Instant::from_since_start(Duration::from_secs(secs))
}

/// The cap's own work: more unfinished packets than 4 MiB can count, each
/// one fragment of eight bytes, so every one counts mostly bookkeeping.
#[test]
fn many_tiny_packets_stay_within_most_held() {
    let mut costs = Costs::new("tiny packets");
    let mut r = Reassembly::default();
    for i in 0..40_000u32 {
        let f = Frag {
            src: 0x0a00_0100 + (i >> 16),
            id: i as u16,
            offset: 8,
            more: true,
            data: &[7; 8],
        };
        assert_eq!(push(&mut costs, &mut r, f, at(0)), "waiting");
    }
    expire_and_take(&mut costs, &mut r, at(31));
    eprintln!("cost: tiny packets: {}", costs.summary());
}

/// Many pieces of eight bytes in each packet, with a gap after each so
/// that none completes, in three orders: ascending, descending, and the
/// even pieces up then the odd ones down.
#[test]
fn many_small_pieces_in_any_order_stay_within_most_held() {
    let pieces: Vec<usize> = (0..4000).map(|k| 8 + 16 * k).collect();
    let descending: Vec<usize> = pieces.iter().rev().copied().collect();
    let (even, odd): (Vec<usize>, Vec<usize>) = pieces.iter().partition(|o| (*o / 16) % 2 == 0);
    let interleaved: Vec<usize> = even.into_iter().chain(odd.into_iter().rev()).collect();
    for (name, order) in [
        ("ascending", pieces.clone()),
        ("descending", descending),
        ("interleaved", interleaved),
    ] {
        let mut costs = Costs::new(format!("pieces, {name}"));
        let mut r = Reassembly::default();
        for src in 0..20u32 {
            for &offset in &order {
                let f = Frag {
                    src: 0x0a00_0100 + src,
                    id: 1,
                    offset,
                    more: true,
                    data: &[7; 8],
                };
                push(&mut costs, &mut r, f, at(0));
            }
        }
        eprintln!("cost: pieces, {name}: {}", costs.summary());
    }
}

/// First fragments that time out are kept for their answers; with no one
/// taking them, new packets keep arriving, and the kept fragments count
/// against the cap with what keeps them.
#[test]
fn first_fragments_kept_for_answers_stay_within_most_held() {
    let mut costs = Costs::new("expired first fragments");
    let mut r = Reassembly::default();
    for round in 0..4u64 {
        for i in 0..20_000u32 {
            let src = 0x0a00_0100 + (round as u32) * 4 + (i >> 16);
            let f = Frag {
                src,
                id: i as u16,
                offset: 0,
                more: true,
                data: &[7; 8],
            };
            push(&mut costs, &mut r, f, at(40 * round));
        }
        expire(&mut costs, &mut r, at(40 * round + 31));
    }
    let taken = expire_and_take(&mut costs, &mut r, at(1000));
    assert!(taken > 0, "no first fragment was kept");
    eprintln!("cost: expired first fragments: {}", costs.summary());
}

/// Packets of 8,000 bytes sent as a thousand pieces of eight, shuffled:
/// each completes on its last piece and is handed out whole.
#[test]
fn packets_completed_from_small_pieces_stay_within_most_held() {
    let mut costs = Costs::new("completed from small pieces");
    let mut r = Reassembly::default();
    let mut state = 0x2545_f491_4f6c_dd1du64;
    let mut whole = 0;
    for src in 0..20u32 {
        let mut offsets: Vec<usize> = (0..1000).map(|k| 8 * k).collect();
        for i in (1..offsets.len()).rev() {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            offsets.swap(i, (state % (i as u64 + 1)) as usize);
        }
        for offset in offsets {
            let more = offset != 8 * 999;
            let data = [src as u8; 8];
            let f = Frag {
                src: 0x0a00_0100 + src,
                id: 9,
                offset,
                more,
                data: &data,
            };
            if push(&mut costs, &mut r, f, at(0)) == "whole" {
                whole += 1;
            }
        }
    }
    assert_eq!(whole, 20);
    eprintln!("cost: completed from small pieces: {}", costs.summary());
}

/// UDP sockets under floods of datagrams, through the IP layer as a host
/// runs them: what a socket keeps is paid for by the layer's budget.
mod udp {
    use std::net::SocketAddr;
    use std::sync::Arc;

    use fictionet::stdlib::layer::{
        Admit, Budget, Chain, Child, Datagrams, Driver, MessageCommand, Messages, MuxCommand,
        MuxEvent, PacketEvent,
    };
    use fictionet::stdlib::network::ip::{self, protocol};
    use fictionet::stdlib::network::packet::IpLayer;
    use fictionet::stdlib::network::transport::{Request, UdpControl, UdpNotice};
    use fictionet::stdlib::network::udp::UdpLayer;
    use fictionet::time::Instant;
    use fictionet::{Chunk, Packet, Seed, SeededEntropy};

    use crate::common::cost::{Charged, Costs, Linear};

    type Stack = Chain<IpLayer, UdpLayer>;
    type Command = MuxCommand<Datagrams<SocketAddr>, Messages<UdpNotice, UdpControl>>;

    /// What the stack holds outside the budget while a step runs: the
    /// packet the step takes in (built inside it, at most 1,500 bytes and
    /// two chunk headers), and the layers' queues of control events and
    /// packets, at most 64 entries each (`HELD` in udp/sockets.rs), which
    /// a flood with no reader leaves empty.
    const STACK: usize = 4096;

    /// A step's linear bound, besides what it charged to the budget: the
    /// packet built (its bytes and two chunk headers) and the datagram's
    /// bytes copied out of it, two bytes for each byte of input. Growing
    /// the queue is charged before it is allocated, and counted with the
    /// step's charge. The layers' own queues ([`STACK`]) may grow in any
    /// step, outside the budget, up to their bound.
    const STEP: Linear = Linear {
        num: 2,
        den: 1,
        fixed: 2 * Chunk::HEADER + STACK,
    };

    struct Host {
        d: Driver<Stack>,
        budget: Budget,
        child: Child,
        local: SocketAddr,
    }

    /// A host at 10.0.0.1 with a socket on port 53 and `limit` bytes of
    /// budget.
    fn host(limit: usize) -> Host {
        let budget = Budget::new(limit);
        let entropy = Arc::new(SeededEntropy::new(Seed::from_u64(7)));
        let udp = UdpLayer::new("10.0.0.1".parse().unwrap(), &*entropy);
        let mut d = Driver::new(
            Chain::new(IpLayer::host(), udp),
            entropy,
            budget.clone(),
            Instant::ZERO,
        );
        let bind: Command = MuxCommand::control(MessageCommand::Send(UdpControl::Bind {
            request: Request(0),
            port: 53,
        }));
        assert!(matches!(d.command(bind), Ok(Admit::Taken)));
        d.run().unwrap();
        let mut opened = None;
        d.send_above(|event| {
            if let MuxEvent::Opened(child, bound, _) = event {
                opened = Some((child, bound.local));
            }
            Admit::Taken
        });
        let (child, local) = opened.expect("port 53 opened");
        Host {
            d,
            budget,
            child,
            local,
        }
    }

    /// A UDP packet from `from` to `to`, its checksum filled in.
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

    /// Runs `f` on the host as one costed step: within what the budget
    /// paid before it, what the step charged, and [`STACK`]. Of what it
    /// charged, all but `kept` (a datagram's bytes and its chunk's header)
    /// is places the queue grew by; growing to at least twice its places,
    /// it moved no more than that.
    fn step(costs: &mut Costs, h: &mut Host, input: usize, kept: usize, f: impl FnOnce(&mut Host)) {
        let before = h.budget.used();
        costs.step(input, before + STACK, STEP, || {
            f(h);
            let charged = h.budget.used().saturating_sub(before);
            Charged::new((), charged).moved(charged.saturating_sub(kept))
        });
    }

    /// A datagram of `payload` from `peer` arrives, as one costed step.
    fn arrive(costs: &mut Costs, h: &mut Host, peer: SocketAddr, payload: &[u8]) {
        let input = 28 + payload.len();
        let kept = payload.len() + Chunk::HEADER;
        step(costs, h, input, kept, |h| {
            let packet = Packet::new(datagram(peer, h.local, payload));
            assert!(matches!(
                h.d.deliver(PacketEvent::Packet(packet)),
                Ok(Admit::Taken)
            ));
            h.d.run().unwrap();
            // A runner reads what the stack reports as it goes.
            h.d.observations().drain().for_each(drop);
        });
    }

    /// The port above takes `n` datagrams, as one costed step.
    fn take(costs: &mut Costs, h: &mut Host, n: u64) {
        step(costs, h, 0, 0, |h| {
            let grant: Command = h.child.grant(n);
            assert!(matches!(h.d.command(grant), Ok(Admit::Taken)));
            h.d.run().unwrap();
            h.d.send_above(|event| {
                drop(event);
                Admit::Taken
            });
        });
    }

    /// Floods of tiny datagrams, then of mixed sizes, each past what one
    /// socket keeps; then the port above takes them all and the flood
    /// comes again, into places the queue already paid for.
    #[test]
    fn floods_of_tiny_datagrams_stay_within_what_the_budget_paid() {
        let mut costs = Costs::new("udp floods");
        let mut h = host(64 << 20);
        let peer: SocketAddr = "10.0.0.2:1234".parse().unwrap();
        for round in 0..2 {
            for size in [0usize, 1, 7] {
                for _ in 0..3000 {
                    arrive(&mut costs, &mut h, peer, &vec![round as u8; size]);
                }
            }
            for i in 0..3000usize {
                arrive(&mut costs, &mut h, peer, &vec![1; i % 1400]);
            }
            take(&mut costs, &mut h, 20_000);
        }
        eprintln!("cost: udp floods: {}", costs.summary());
    }

    /// A budget smaller than a flood: datagrams are dropped once it is
    /// spent, and what is kept stays within it.
    #[test]
    fn a_flood_past_the_budget_stays_within_it() {
        let mut costs = Costs::new("udp budget");
        let mut h = host(256 << 10);
        let peer: SocketAddr = "10.0.0.2:1234".parse().unwrap();
        for i in 0..5000usize {
            arrive(&mut costs, &mut h, peer, &vec![2; i % 300]);
        }
        assert!(h.budget.used() <= 256 << 10);
        eprintln!("cost: udp budget: {}", costs.summary());
    }
}

/// DNS queries as a server parses them (`Request::parse`), with records
/// whose names are compression pointers: two octets on the wire for a
/// name of up to 255 octets in memory.
mod dns {
    use fictionet::stdlib::network::Transport;
    use fictionet::stdlib::protocols::dns::rr::Record;
    use fictionet::stdlib::protocols::dns::{Parsed, Request};

    use crate::common::cost::{Charged, Costs, Linear};

    /// The most a decoded record holds besides its place in its section:
    /// its name, up to 255 octets and an index of up to 128 label ends.
    const NAME: usize = 255 + 128;

    /// The fewest octets a record takes on the wire: a compression pointer
    /// for its name, its type, class, TTL and RDATA length.
    const WIRE: usize = 12;

    /// What a parse holds at any moment: every record of the message
    /// decoded, its place in a section that may have doubled (twice a
    /// `Record`) and its name; and the question, whose name is at most
    /// [`NAME`] and whose octets the request copies, at most the message.
    fn holds(len: usize) -> usize {
        len.div_ceil(WIRE) * (2 * size_of::<Record>() + NAME) + len + 4 * NAME
    }

    /// What a parse asks for: the records' places in sections that double
    /// as they grow, each place asked for twice over all the growth, and
    /// their names; and the question as in [`holds`].
    const fn asks(len: usize) -> Linear {
        Linear {
            num: 4 * size_of::<Record>() + NAME,
            den: WIRE,
            fixed: len + 4 * NAME,
        }
    }

    /// What a request keeps once parsed: its question's name and octets
    /// and its header, none of the records.
    fn keeps(len: usize) -> usize {
        len + 4 * NAME
    }

    /// A query for a name of 255 octets, with `records` A records in the
    /// section at `section` (answer, authority or additional) whose names
    /// point back at it.
    fn query(records: usize, section: usize) -> Vec<u8> {
        let mut counts = [0u16; 3];
        counts[section] = records as u16;
        let mut bytes = vec![0x12, 0x34, 0x01, 0x00, 0, 1];
        for count in counts {
            bytes.extend_from_slice(&count.to_be_bytes());
        }
        for label in [63u8, 63, 63, 61] {
            bytes.push(label);
            bytes.extend(std::iter::repeat_n(b'a', label as usize));
        }
        bytes.push(0);
        bytes.extend_from_slice(&[0, 1, 0, 1]);
        for i in 0..records {
            bytes.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
            bytes.extend_from_slice(&(i as u32).to_be_bytes());
        }
        bytes
    }

    /// Each query parsed as one costed step, up to a TCP message of 64 KiB:
    /// within [`holds`] at any moment, within [`asks`], and keeping no more
    /// than [`keeps`] in the request it makes.
    #[test]
    fn queries_full_of_compressed_names_keep_none_of_them() {
        let mut all = Costs::new("dns queries");
        for section in 0..3 {
            for records in [0usize, 1, 10, 100, 1000, 4000] {
                let bytes = query(records, section);
                let len = bytes.len();
                let mut costs = Costs::new(format!("dns query, {records} records"));
                let parsed = costs.step(len, holds(len), asks(len), || {
                    Charged::new(Request::parse(&bytes, Transport::Tcp), 0)
                });
                let Parsed::Request(_) = &parsed else {
                    panic!("{records} records in section {section}: not a request");
                };
                // What the step left allocated is the request.
                let kept = costs.live();
                assert!(
                    kept <= keeps(len),
                    "{records} records in section {section}: the request keeps {kept} \
                     bytes, past {}",
                    keeps(len)
                );
                all.absorb(&costs);
            }
        }
        eprintln!("cost: dns queries: {}", all.summary());
    }
}

/// The resolver's cache: what it keeps is charged to its budget, by its
/// own estimate, before it is kept.
mod cache {
    use std::net::Ipv4Addr;

    use fictionet::stdlib::layer::Budget;
    use fictionet::stdlib::protocols::dns::dnssec::Validation;
    use fictionet::stdlib::protocols::dns::rr::rdata::A;
    use fictionet::stdlib::protocols::dns::rr::{Name, RData, Record, RecordSet, RecordType};
    use fictionet::stdlib::services::dns::resolver::{Cache, Limits, Offer, Rank};
    use fictionet::time::{Duration, Instant};

    use crate::common::cost::{Charged, Costs, Linear};

    /// A step's linear bound, over the session ([`Costs::amortized`]): an
    /// offer's records are built in the step ([`built`], its input). The
    /// cache keeps a normalized copy (`normalized` in cache.rs): its records
    /// cloned into a vector that doubles as it grows, then set into the
    /// copy, at most three times what was built. What it keeps is charged
    /// in the step, or grows its maps into room charged when the cache was
    /// made (`Cache::storage`), the first step's charge.
    const STEP: Linear = Linear {
        num: 4,
        den: 1,
        fixed: 0,
    };

    /// RRsets of one to 32 addresses at 3,000 names, each offered as it
    /// arrives from an authority, every insert a costed step: what the
    /// cache holds stays within what its budget was charged.
    /// What building an offer of `per` addresses allocates, at most: its
    /// records in a vector that doubles as it grows, the RRset's own copy
    /// of the name and type, and the name's text.
    fn built(per: u32) -> usize {
        (2 * per as usize + 2) * size_of::<Record>() + 64
    }

    #[test]
    fn rrsets_offered_stay_within_what_the_cache_charged() {
        let limits = Limits {
            max_ttl: Duration::from_secs(1000),
            max_negative_ttl: Duration::from_secs(100),
            failure_ttl: Duration::from_secs(1),
            stale: Duration::ZERO,
            max_entries: 4096,
        };
        for per in [1u32, 4, 32] {
            let budget = Budget::new(64 << 20);
            let mut costs = Costs::amortized(format!("cache, {per} a set"));
            let storage = Cache::storage(limits.max_entries).unwrap();
            let mut cache = costs.step(storage, 0, STEP, || {
                Charged::new(Cache::new(limits, &budget).expect("room"), budget.used())
                    // The maps double as they grow into that room: over all
                    // their growth they ask for it twice, once charged and
                    // once moved.
                    .moved(storage)
            });
            for i in 0..3000u32 {
                let before = budget.used();
                costs.step(built(per), before, STEP, || {
                    let name = Name::from_ascii(format!("n{i}.a-long-label.example.")).unwrap();
                    let mut set = RecordSet::with_ttl(name.clone(), RecordType::A, 300);
                    for k in 0..per {
                        let address = RData::A(A(Ipv4Addr::from(k)));
                        set.insert(Record::from_rdata(name.clone(), 300, address), 0);
                    }
                    let offer = Offer::Positive {
                        set,
                        rank: Rank::AuthAnswer,
                        validation: Validation::NotPerformed,
                        proof: Vec::new(),
                        truncated: false,
                    };
                    cache.insert(Instant::ZERO, offer);
                    Charged::new((), budget.used().saturating_sub(before))
                });
            }
            eprintln!("cost: cache, {per} a set: {}", costs.summary());
        }
    }
}
