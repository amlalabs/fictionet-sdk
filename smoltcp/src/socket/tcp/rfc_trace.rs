// Logs of the real socket for verification/tcp-rfc/tla/RfcTrace.tla.
//
// Included in the socket's test module, so it reads the socket's fields.
// `trace_against_rfc9293` drives one socket per seed with a seeded mix of
// user calls, dispatches, time and peer segments, and after every step
// writes the socket's fields read as Rfc9293's variables (the mapping of
// Engine.tla). `cargo xtask tcp-rfc-verify trace` runs it with
// TCP_RFC_TRACE_DIR set and replays each log with TLC.

mod rfc_trace {
    use super::*;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};
    use std::fmt::Write as _;

    /// The receive buffer: Rfc9293's Cap, and MaxText.
    const CAP: usize = 4;
    /// Octets the user sends in one connection: Rfc9293's Data.
    const DATA: usize = 3;
    /// The sequence space of the replay. Every number the driver draws is
    /// within a few dozen of one it aims at, so modulo 2^20 tells them apart
    /// as modulo 2^32 does.
    const N: i64 = 1 << 20;
    /// Steps per seed, and the seeds.
    const STEPS: usize = 2000;
    const SEEDS: std::ops::RangeInclusive<u64> = 1..=8;

    struct Driver {
        s: TestSocket,
        rng: StdRng,
        iss: TcpSeqNumber,
        irs: TcpSeqNumber,
        now: u64,
        /// Octets the user queued in this connection: Rfc9293's `queued`.
        queued: usize,
        entries: Vec<String>,
    }

    /// One mapped state: Rfc9293's variables but `out` and `seg`.
    #[derive(Clone, PartialEq)]
    struct Mapped {
        st: State,
        passive: bool,
        una: i64,
        nxt: i64,
        queued: usize,
        fin_q: bool,
        rnxt: i64,
        redge: i64,
        rbuf: usize,
        held: Vec<i64>,
        sfin: bool,
    }

    fn modn(x: i64) -> i64 {
        x.rem_euclid(N)
    }

    impl Driver {
        fn new(seed: u64) -> Driver {
            let mut rng = StdRng::seed_from_u64(seed);
            // Both ends start near 2^32, so the code's numbers wrap.
            let iss = TcpSeqNumber::new(u32::MAX - rng.gen_range(0..64));
            let irs = TcpSeqNumber::new(u32::MAX - rng.gen_range(0..64));
            let mut device = crate::tests::TestingDevice::new();
            let config = crate::iface::Config {
                initial_seq: Box::new(move |_, _, _| iss.to_bits()),
                ip_addr: IpAddress::Ipv4(LOCAL_ADDR),
            };
            let iface = crate::iface::Interface::new(config, &mut device, Instant::ZERO);
            let mut socket = Socket::new(
                SocketBuffer::new(vec![0; CAP]),
                SocketBuffer::new(vec![0; DATA]),
            );
            socket.set_ack_delay(None);
            Driver {
                s: TestSocket {
                    socket,
                    cx: iface.inner,
                },
                rng,
                iss,
                irs,
                now: 0,
                queued: 0,
                entries: Vec::new(),
            }
        }

        /// A send-side number as an offset from the ISS.
        fn local(&self, x: TcpSeqNumber) -> i64 {
            modn(i64::from(x.relative_to(self.iss) as i32))
        }

        /// A peer-side number, the IRS at N - 1.
        fn remote(&self, x: TcpSeqNumber) -> i64 {
            modn(i64::from(x.relative_to(self.irs + 1) as i32))
        }

        fn rcv_nxt(&self) -> TcpSeqNumber {
            self.s.remote_seq_no + self.s.rx_buffer.len()
        }

        fn map(&self) -> Mapped {
            let s = &self.s;
            let st = s.state;
            let open = st != State::Closed;
            let sends = open && st != State::Listen;
            let receives = sends && st != State::SynSent;
            let rnxt = self.rcv_nxt();
            let held = if receives && !s.rx_fin_received {
                let mut held: Vec<i64> = s
                    .assembler
                    .iter_data()
                    .flat_map(|(left, right)| left..right)
                    .map(|o| self.remote(rnxt + o))
                    .collect();
                held.sort_unstable();
                held
            } else {
                Vec::new()
            };
            Mapped {
                st,
                passive: open && s.listen_endpoint.is_some(),
                una: if sends { self.local(s.local_seq_no) } else { 0 },
                nxt: if sends { self.local(s.local_seq_max) } else { 0 },
                queued: if sends { self.queued } else { 0 },
                fin_q: matches!(
                    st,
                    State::FinWait1
                        | State::FinWait2
                        | State::Closing
                        | State::TimeWait
                        | State::LastAck
                ),
                rnxt: if receives { self.remote(rnxt) } else { 0 },
                redge: if receives {
                    self.remote(s.receive_window_end())
                } else {
                    0
                },
                rbuf: s.rx_buffer.len(),
                held,
                sfin: receives && s.rx_fin_received,
            }
        }

        fn out_of(&self, reply: Option<&TcpRepr>) -> String {
            match reply {
                None => "NoOut".into(),
                Some(r) if r.control == TcpControl::Rst => match r.ack_number {
                    Some(ack) => format!("RstAckOut({})", self.remote(ack)),
                    None => format!("RstOut({})", self.local(r.seq_number)),
                },
                Some(r) => format!(
                    "AckOut({}, {})",
                    self.local(r.seq_number),
                    self.remote(r.ack_number.expect("an ACK reply"))
                ),
            }
        }

        fn record(&mut self, action: &str, seg: Option<&TcpRepr>, out: String, m: &Mapped) {
            let seg = match seg {
                None => "NoSeg".to_owned(),
                Some(r) => format!(
                    "[seq |-> {}, ack |-> {}, ctl |-> \"{}\", len |-> {}]",
                    self.remote(r.seq_number),
                    r.ack_number.map_or(-1, |a| self.local(a)),
                    match r.control {
                        TcpControl::Syn => "SYN",
                        TcpControl::Fin => "FIN",
                        TcpControl::Rst => "RST",
                        TcpControl::None | TcpControl::Psh => "NONE",
                    },
                    r.payload.len()
                ),
            };
            let held: Vec<String> = m.held.iter().map(i64::to_string).collect();
            self.entries.push(format!(
                "[a |-> \"{action}\", seg |-> {seg}, st |-> \"{:?}\", passive |-> {}, \
                 una |-> {}, nxt |-> {}, queued |-> {}, finQ |-> {}, rnxt |-> {}, \
                 redge |-> {}, rbuf |-> {}, held |-> {{{}}}, sfin |-> {}, out |-> {out}]",
                m.st,
                tla_bool(m.passive),
                m.una,
                m.nxt,
                m.queued,
                tla_bool(m.fin_q),
                m.rnxt,
                m.redge,
                m.rbuf,
                held.join(", "),
                tla_bool(m.sfin),
            ));
        }

        fn tick(&mut self) {
            self.now += self.rng.gen_range(0..700);
            self.s.cx.set_now(Instant::from_millis(self.now as i64));
        }

        /// A number near one of `aims`.
        fn near(&mut self, aims: &[TcpSeqNumber]) -> TcpSeqNumber {
            let aim = aims[self.rng.gen_range(0..aims.len())];
            match self.rng.gen_range(0..10) {
                0 => aim + self.rng.gen_range(2..24),
                1 => aim - self.rng.gen_range(2..24),
                2 => aim + 1,
                3 => aim - 1,
                _ => aim,
            }
        }

        fn peer(&mut self) {
            let st = self.s.state;
            if st == State::Closed {
                return;
            }
            let ctl = match self.rng.gen_range(0..10) {
                0 | 1 => TcpControl::Syn,
                2 | 3 => TcpControl::Fin,
                4 => TcpControl::Rst,
                5 => TcpControl::Psh,
                _ => TcpControl::None,
            };
            let rnxt = self.rcv_nxt();
            let edge = self.s.receive_window_end();
            let seq = if ctl == TcpControl::Syn && matches!(st, State::Listen | State::SynSent) {
                self.irs
            } else {
                self.near(&[rnxt, rnxt, edge, self.irs + 1])
            };
            let ack = if self.rng.gen_range(0..6) == 0 {
                None
            } else {
                let (una, max) = (self.s.local_seq_no, self.s.local_seq_max);
                Some(self.near(&[una, max, max, self.iss + 1]))
            };
            let len = match ctl {
                TcpControl::Syn | TcpControl::Rst => 0,
                _ => self.rng.gen_range(0..=CAP),
            };
            let payload = &b"abcd"[..len];
            let repr = TcpRepr {
                control: ctl,
                seq_number: seq,
                ack_number: ack,
                window_len: 64,
                payload,
                ..SEND_TEMPL
            };
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
            self.tick();
            let reply = if self.s.socket.accepts(&mut self.s.cx, &ip_repr, &repr) {
                self.s
                    .socket
                    .process(&mut self.s.cx, &ip_repr, &repr, &[])
                    .map(|(_, r)| r)
            } else {
                // The interface's answer when no socket takes the segment.
                (ctl != TcpControl::Rst).then(|| Socket::rst_reply(&ip_repr, &repr).1)
            };
            let out = self.out_of(reply.as_ref());
            let m = self.map();
            if m.st == State::Closed {
                self.queued = 0;
            }
            self.record("Arrive", Some(&repr), out, &m);
        }

        /// One dispatch, logged as the Rfc9293 steps it amounts to.
        fn dispatch(&mut self) {
            self.tick();
            let before = self.map();
            let _ = self
                .s
                .socket
                .dispatch(&mut self.s.cx, |_, _| Ok::<(), ()>(()));
            let after = self.map();
            if after == before {
                return;
            }
            if after.st == State::Closed && before.st != State::Closed {
                self.queued = 0;
                let name = if before.st == State::TimeWait {
                    "TimeWaitEnds"
                } else {
                    "Abort"
                };
                self.record(name, None, "NoOut".into(), &after);
                return;
            }
            let k = modn(after.nxt - before.nxt);
            for j in 1..=k {
                let step = Mapped {
                    nxt: modn(before.nxt + j),
                    ..after.clone()
                };
                self.record("SendNext", None, "NoOut".into(), &step);
            }
            if k == 0 {
                self.record("Advertise", None, "NoOut".into(), &after);
            }
        }

        fn user(&mut self) {
            let st = self.s.state;
            let opens = matches!(st, State::Closed | State::TimeWait);
            let done = match self.rng.gen_range(0..7) {
                0 if opens => self.s.listen(LISTEN_END).is_ok().then_some("Listen"),
                1 if opens => {
                    let cx = &mut self.s.cx;
                    let ok = self.s.socket.connect(cx, REMOTE_END, LOCAL_END).is_ok();
                    ok.then_some("Connect")
                }
                2 if matches!(st, State::Established | State::CloseWait) && self.queued < DATA => {
                    (self.s.send_slice(b"x") == Ok(1)).then_some("Send")
                }
                3 if !self.s.rx_buffer.is_empty() => {
                    (self.s.recv_slice(&mut [0]) == Ok(1)).then_some("Receive")
                }
                4 if matches!(
                    st,
                    State::Listen
                        | State::SynSent
                        | State::SynReceived
                        | State::Established
                        | State::CloseWait
                ) =>
                {
                    self.s.close();
                    Some("Close")
                }
                5 if st != State::Closed && self.rng.gen_range(0..4) == 0 => {
                    self.s.abort();
                    Some("Abort")
                }
                _ => None,
            };
            if let Some(name) = done {
                if matches!(name, "Listen" | "Connect") {
                    self.queued = 0;
                }
                if name == "Send" {
                    self.queued += 1;
                }
                if self.s.state == State::Closed {
                    self.queued = 0;
                }
                let m = self.map();
                self.record(name, None, "NoOut".into(), &m);
            }
        }

        fn run(&mut self) {
            for _ in 0..STEPS {
                match self.rng.gen_range(0..10) {
                    0..=4 => self.peer(),
                    5..=7 => self.dispatch(),
                    _ => self.user(),
                }
            }
        }
    }

    fn tla_bool(b: bool) -> &'static str {
        if b { "TRUE" } else { "FALSE" }
    }

    #[test]
    #[ignore = "run cargo xtask tcp-rfc-verify trace"]
    fn trace_against_rfc9293() {
        let dir = std::env::var_os("TCP_RFC_TRACE_DIR").expect("set TCP_RFC_TRACE_DIR");
        let dir = std::path::Path::new(&dir);
        for seed in SEEDS {
            let mut d = Driver::new(seed);
            d.run();
            assert!(!d.entries.is_empty());
            let mut module = String::new();
            let _ = writeln!(module, "---- MODULE Trace{seed} ----");
            let _ = writeln!(module, "EXTENDS RfcTrace");
            let _ = writeln!(module, "TheLog == <<");
            let _ = writeln!(module, "  {}", d.entries.join(",\n  "));
            let _ = writeln!(module, ">>");
            let _ = writeln!(module, "====");
            std::fs::write(dir.join(format!("Trace{seed}.tla")), module).unwrap();
            let cfg = format!(
                "CONSTANTS\n  N = {N}\n  Cap = {CAP}\n  Data = {DATA}\n  MaxText = {CAP}\n  \
                 IRS = {}\n  RepeatSynAck = FALSE\n  AckBeforeSeqInSynReceived = TRUE\n  \
                 ChallengeSynInSynReceived = TRUE\n  NoAckDroppedFirst = TRUE\n  \
                 AckCheckedBeforeSeq = TRUE\n  RateLimitEmptyOutOfWindow = TRUE\n  \
                 EmptyAckAtRightEdge = TRUE\n  FinAtRightEdge = TRUE\n  \
                 OpenInTimeWait = TRUE\n  Log <- TheLog\nSPECIFICATION TSpec\n",
                N - 1
            );
            std::fs::write(dir.join(format!("Trace{seed}.cfg")), cfg).unwrap();
            println!("seed {seed}: {} entries", d.entries.len());
        }
    }
}
