// RFC 9293 segment arrival: the socket against the Lean model's vectors.
//
// Included in `tcp.rs`'s test module. `cargo xtask tcp-rfc-verify diff`
// writes the vectors of `verification/tcp-rfc/lean/Gen.lean` and runs this
// test with `TCP_RFC_VECTORS` naming their directory. Each vector is a
// connection record and a segment, and the record and reply `arrive` gives
// with smoltcp's departures. The test builds a socket in that record, as
// the `socket_*` helpers do, feeds it the segment and compares.
//
// The socket is built so that it has sent everything it holds and owes
// nothing: SND.NXT is `local_seq_max` and `remote_last_seq`, the text in
// flight sits in `tx_buffer`, RCV.NXT is `remote_seq_no` with an empty
// receive buffer, and RCV.WND is the receive buffer's capacity, advertised
// up to `remote_win_end`. The reply is what `process` returns, or, when it
// returns nothing, what one `dispatch` at the same instant sends (the
// SYN-ACK of a new connection, the ACK of taken text or a FIN): the RFC
// lets an ACK go out at once or later, and the socket is set to send it at
// once (`ack_delay` off). In LISTEN and CLOSED the socket does not take
// the segment, and the reply is the interface's (`process_tcp`): a RST for
// anything but a RST.
//
// Every vector runs twice: with the challenge-ACK rate limit open, where a
// challenge ACK must go out, and closed, where it must not and nothing else
// may change.

/// The record fields the vectors compare after a segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RfcRecord {
    state: State,
    una: u32,
    nxt: u32,
    rcv_nxt: u32,
    wnd: u32,
    peer_fin: bool,
    passive: bool,
}

/// A reply, as the model names it and as the socket's segment reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RfcReply {
    None,
    Ack { seq: u32, ack: u32 },
    Challenge { seq: u32, ack: u32 },
    Rst { seq: u32 },
    RstAck { ack: u32 },
    SynAck { seq: u32, ack: u32 },
}

/// One line of `arrive.txt`.
#[derive(Debug)]
struct RfcVector {
    state: State,
    una: u32,
    nxt: u32,
    rcv_nxt: u32,
    wnd: u32,
    fin_sent: bool,
    peer_fin: bool,
    passive: bool,
    seq: u32,
    ack: Option<u32>,
    control: TcpControl,
    text: usize,
    after: RfcRecord,
    reply: RfcReply,
}

const RFC_STATES: [State; 11] = [
    State::Closed,
    State::Listen,
    State::SynSent,
    State::SynReceived,
    State::Established,
    State::FinWait1,
    State::FinWait2,
    State::CloseWait,
    State::Closing,
    State::LastAck,
    State::TimeWait,
];

fn rfc_parse(line: &str) -> Result<RfcVector, String> {
    let nums: Vec<u64> = line
        .split_whitespace()
        .map(|n| n.parse::<u64>().map_err(|e| format!("{n}: {e}")))
        .collect::<Result<_, _>>()?;
    if nums.len() != 26 {
        return Err(format!("{} fields, not 26", nums.len()));
    }
    let seq = |i: usize| u32::try_from(nums[i]).map_err(|e| format!("field {i}: {e}"));
    let flag = |i: usize| match nums[i] {
        0 => Ok(false),
        1 => Ok(true),
        n => Err(format!("field {i}: {n} is not a Boolean")),
    };
    let state = |i: usize| {
        RFC_STATES
            .get(nums[i] as usize)
            .copied()
            .ok_or(format!("field {i}: no state {}", nums[i]))
    };
    let control = match nums[14] {
        0 => TcpControl::None,
        1 => TcpControl::Syn,
        2 => TcpControl::Fin,
        3 => TcpControl::Rst,
        n => return Err(format!("no control {n}")),
    };
    let reply = match nums[23] {
        0 => RfcReply::None,
        1 => RfcReply::Ack {
            seq: seq(24)?,
            ack: seq(25)?,
        },
        2 => RfcReply::Challenge {
            seq: seq(24)?,
            ack: seq(25)?,
        },
        3 => RfcReply::Rst { seq: seq(24)? },
        4 => RfcReply::RstAck { ack: seq(25)? },
        5 => RfcReply::SynAck {
            seq: seq(24)?,
            ack: seq(25)?,
        },
        n => return Err(format!("no reply {n}")),
    };
    Ok(RfcVector {
        state: state(0)?,
        una: seq(3)?,
        nxt: seq(4)?,
        rcv_nxt: seq(5)?,
        wnd: seq(6)?,
        fin_sent: flag(8)?,
        peer_fin: flag(9)?,
        passive: flag(10)?,
        seq: seq(11)?,
        ack: if flag(12)? { Some(seq(13)?) } else { None },
        control,
        text: nums[15] as usize,
        after: RfcRecord {
            state: state(16)?,
            una: seq(17)?,
            nxt: seq(18)?,
            rcv_nxt: seq(19)?,
            wnd: seq(20)?,
            peer_fin: flag(21)?,
            passive: flag(22)?,
        },
        reply,
    })
}

fn rfc_seq(n: u32) -> TcpSeqNumber {
    TcpSeqNumber::new(n)
}

/// The instant every vector runs at.
fn rfc_now() -> Instant {
    Instant::from_millis(10_000)
}

/// A socket in the vector's record.
fn rfc_socket(v: &RfcVector) -> TestSocket {
    let syn_unacked = matches!(v.state, State::SynSent | State::SynReceived);
    let fin_unacked =
        v.fin_sent && matches!(v.state, State::FinWait1 | State::Closing | State::LastAck);
    let in_flight = match v.state {
        State::Closed | State::Listen => 0,
        _ => {
            v.nxt.wrapping_sub(v.una) as usize - usize::from(syn_unacked) - usize::from(fin_unacked)
        }
    };
    let mut s = socket_with_buffer_sizes(in_flight.max(1), v.wnd as usize);
    s.cx.set_now(rfc_now());
    s.state = v.state;
    match v.state {
        State::Closed => return s,
        State::Listen => {
            s.listen_endpoint = Some(LISTEN_END);
            return s;
        }
        _ => {}
    }
    s.tuple = Some(TUPLE);
    if v.passive {
        s.listen_endpoint = Some(LISTEN_END);
    }
    assert_eq!(s.tx_buffer.enqueue_slice(&vec![0; in_flight]), in_flight);
    s.local_seq_no = rfc_seq(v.una);
    s.local_seq_max = rfc_seq(v.nxt);
    s.remote_last_seq = rfc_seq(v.nxt);
    s.remote_win_len = 256;
    s.remote_last_win = s.scaled_window();
    s.timer = match v.state {
        State::TimeWait => Timer::Close {
            expires_at: rfc_now() + Duration::from_secs(60),
        },
        _ => Timer::new(),
    };
    // In SYN-SENT RCV.NXT is not known yet (0, as `Socket::new` leaves it)
    // and the SYN carried no ACK; RCV.WND is the window it offered.
    s.remote_seq_no = rfc_seq(v.rcv_nxt);
    s.remote_win_end = Some(rfc_seq(v.rcv_nxt) + v.wnd as usize);
    s.rx_fin_received = v.peer_fin;
    if v.state != State::SynSent {
        s.remote_last_ack = Some(rfc_seq(v.rcv_nxt));
    }
    s
}

fn rfc_segment<'a>(v: &RfcVector, payload: &'a [u8]) -> TcpRepr<'a> {
    TcpRepr {
        control: v.control,
        seq_number: rfc_seq(v.seq),
        ack_number: v.ack.map(rfc_seq),
        payload: &payload[..v.text],
        ..SEND_TEMPL
    }
}

/// What a segment the socket sent reads as, or why it reads as none.
fn rfc_read(repr: &TcpRepr) -> Result<RfcReply, String> {
    let seq = repr.seq_number.to_bits();
    let ack = repr.ack_number.map(TcpSeqNumber::to_bits);
    match (repr.control.quash_psh(), ack, repr.payload.is_empty()) {
        (TcpControl::None, Some(ack), true) => Ok(RfcReply::Ack { seq, ack }),
        (TcpControl::Rst, None, true) => Ok(RfcReply::Rst { seq }),
        (TcpControl::Rst, Some(ack), true) if seq == 0 => Ok(RfcReply::RstAck { ack }),
        (TcpControl::Syn, Some(ack), true) => Ok(RfcReply::SynAck { seq, ack }),
        _ => Err(format!("{repr:?}")),
    }
}

fn rfc_record(s: &TestSocket) -> RfcRecord {
    let rcv_nxt = s.remote_seq_no + s.rx_buffer.len();
    RfcRecord {
        state: s.state,
        una: s.local_seq_no.to_bits(),
        nxt: s.local_seq_max.to_bits(),
        rcv_nxt: rcv_nxt.to_bits(),
        wnd: (s.receive_window_end() - rcv_nxt) as u32,
        peer_fin: s.rx_fin_received,
        passive: s.listen_endpoint.is_some(),
    }
}

/// Feeds the vector's segment to a socket in its record, with the
/// challenge-ACK rate limit `open` or not, and gives the record and reply.
fn rfc_run(v: &RfcVector, open: bool) -> Result<(RfcRecord, RfcReply), String> {
    let mut s = rfc_socket(v);
    s.challenge_ack_timer = if open {
        Instant::from_millis(0)
    } else {
        rfc_now() + Duration::from_millis(1)
    };
    let payload = vec![0x61; v.text];
    let repr = rfc_segment(v, &payload);
    let ip_repr = IpReprIpvX(IpvXRepr {
        identification: 0,
        options: crate::wire::Ipv4OptionBytes::EMPTY,
        wire_dst: None,
        src_addr: REMOTE_ADDR,
        dst_addr: LOCAL_ADDR,
        next_header: IpProtocol::Tcp,
        payload_len: repr.buffer_len(),
        hop_limit: 64,
    });
    // As `InterfaceInner::process_tcp`: a segment no socket takes is
    // answered with a RST unless it is one.
    let processed = if s.socket.accepts(&mut s.cx, &ip_repr, &repr) {
        s.socket
            .process(&mut s.cx, &ip_repr, &repr, &[])
            .map(|(_, reply)| reply)
    } else if repr.control != TcpControl::Rst {
        Some(Socket::rst_reply(&ip_repr, &repr).1)
    } else {
        None
    };
    let first = processed.as_ref().map(rfc_read).transpose()?;
    let mut sent = Vec::new();
    let result: Result<(), ()> = s.socket.dispatch(&mut s.cx, |_, (_, reply)| {
        sent.push(rfc_read(&reply));
        Ok(())
    });
    result.map_err(|()| "dispatch failed".to_string())?;
    let mut replies: Vec<RfcReply> = first.into_iter().collect();
    for reply in sent {
        replies.push(reply?);
    }
    let reply = match replies.as_slice() {
        [] => RfcReply::None,
        [one] => *one,
        more => return Err(format!("{} segments: {more:?}", more.len())),
    };
    Ok((rfc_record(&s), reply))
}

/// What the socket must send for the model's `reply`: a challenge ACK goes
/// out as an ACK while the rate limit is open, and not at all while it is
/// closed.
fn rfc_expected(reply: RfcReply, open: bool) -> RfcReply {
    match reply {
        RfcReply::Challenge { seq, ack } if open => RfcReply::Ack { seq, ack },
        RfcReply::Challenge { .. } => RfcReply::None,
        other => other,
    }
}

/// The socket's record matches the model's: every field while the
/// connection lives, only the state once it is CLOSED or back in LISTEN,
/// where the record is deleted (3.10.7.4).
fn rfc_matches(model: &RfcRecord, code: &RfcRecord) -> bool {
    match model.state {
        State::Closed | State::Listen => model.state == code.state,
        _ => model == code,
    }
}

/// The kind of a reply, without its numbers, to group disagreements by.
fn rfc_kind(reply: &RfcReply) -> &'static str {
    match reply {
        RfcReply::None => "none",
        RfcReply::Ack { .. } => "ack",
        RfcReply::Challenge { .. } => "challenge",
        RfcReply::Rst { .. } => "rst",
        RfcReply::RstAck { .. } => "rst-ack",
        RfcReply::SynAck { .. } => "syn-ack",
    }
}

/// How the socket's outcome differs from the model's, in words that group
/// alike disagreements.
fn rfc_difference(
    want: &(RfcRecord, RfcReply),
    got: &Result<(RfcRecord, RfcReply), String>,
) -> String {
    match got {
        Err(e) => format!("socket sent {e}"),
        Ok((record, reply)) => {
            let mut parts = Vec::new();
            if *reply != want.1 {
                parts.push(format!(
                    "reply {} for {}",
                    rfc_kind(reply),
                    rfc_kind(&want.1)
                ));
            }
            if !rfc_matches(&want.0, record) {
                let fields = [
                    ("state", want.0.state != record.state),
                    ("SND.UNA", want.0.una != record.una),
                    ("SND.NXT", want.0.nxt != record.nxt),
                    ("RCV.NXT", want.0.rcv_nxt != record.rcv_nxt),
                    ("RCV.WND", want.0.wnd != record.wnd),
                    ("peer FIN", want.0.peer_fin != record.peer_fin),
                    ("passive", want.0.passive != record.passive),
                ];
                for (name, differs) in fields {
                    if differs {
                        parts.push(name.to_string());
                    }
                }
            }
            parts.join(", ")
        }
    }
}

#[test]
#[ignore = "run cargo xtask tcp-rfc-verify diff"]
fn rfc9293_arrival_vectors() {
    let dir = std::env::var("TCP_RFC_VECTORS").expect("TCP_RFC_VECTORS names the vectors");
    let path = std::path::Path::new(&dir).join("arrive.txt");
    let text = std::fs::read_to_string(&path).expect("arrive.txt");
    let mut cases = 0;
    let mut disagree = 0;
    let mut by_state = [0usize; 11];
    // Disagreements grouped by state, control, ACK, rate limit and what
    // differs: the count and the first line of each.
    let mut groups: std::collections::BTreeMap<String, (usize, String)> =
        std::collections::BTreeMap::new();
    for (number, line) in text.lines().enumerate() {
        let v = rfc_parse(line).unwrap_or_else(|e| panic!("line {}: {e}", number + 1));
        cases += 1;
        by_state[RFC_STATES.iter().position(|s| *s == v.state).unwrap()] += 1;
        for open in [true, false] {
            let want = (v.after, rfc_expected(v.reply, open));
            let got = rfc_run(&v, open);
            let agrees = matches!(&got, Ok((record, reply))
                if rfc_matches(&want.0, record) && *reply == want.1);
            if !agrees {
                disagree += 1;
                let key = format!(
                    "{:?} {:?} {} rate limit {}: {}",
                    v.state,
                    v.control,
                    if v.ack.is_some() {
                        "with ACK"
                    } else {
                        "no ACK"
                    },
                    if open { "open" } else { "closed" },
                    rfc_difference(&want, &got)
                );
                let example = format!(
                    "line {}: {line}\n    vector {v:?}\n    model  {want:?}\n    socket {got:?}",
                    number + 1
                );
                groups.entry(key).or_insert((0, example)).0 += 1;
            }
        }
    }
    for (key, (count, example)) in &groups {
        println!("disagree {count}x {key}\n  {example}");
    }
    for (state, count) in RFC_STATES.iter().zip(by_state) {
        println!("  {state:?}: {count} cases");
    }
    println!("arrive: {cases} cases, {disagree} disagree");
    assert!(cases > 0, "no vectors in {}", path.display());
    assert_eq!(disagree, 0, "the socket and the model disagree");
}
