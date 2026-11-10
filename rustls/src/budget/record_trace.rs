//! A real server, paid from a budget that refuses on demand, and a real
//! client, driven through seeded schedules and logged as the record-level
//! observations that `verification/tls-rfc/tla/RecordTrace.tla` checks
//! against the RFC model `Record.tla`: each record leaving either side
//! (outer type, length class, inner kind where known), each record read
//! (accepted or failed, plaintext delivered), the sequence numbers after
//! each call, garbage records injected, and each budget refusal with
//! whether any state changed across it.
//!
//! Reads are split at random boundaries; writes are of 0, 1 and 2^14
//! bytes; key updates go both ways; either side may close. With
//! `FICTIONET_RECORD_TRACE_DIR` set, each seed's log is written there as a
//! TLA+ module `RecLog_<version>_<seed>.tla` and its TLC config; the test
//! itself checks nothing about the protocol, TLC does.

use alloc::collections::VecDeque;
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use std::io::{self, Read, Write};

use pki_types::pem::PemObject;
use pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};

use super::testing::Limit;
use crate::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use crate::client::{ClientConnection, Resumption};
use crate::crypto::ring::default_provider;
use crate::enums::{AlertDescription, SignatureScheme};
use crate::server::{NoServerSessionStorage, ServerConnection};
use crate::sync::Arc;
use crate::version::{TLS12, TLS13};
use crate::{ClientConfig, DigitallySignedStruct, Error, ServerConfig, SupportedProtocolVersion};

/// How many schedules each version runs.
const SEEDS: u64 = 24;

/// How many actions one schedule takes before everything left is delivered.
const STEPS: usize = 40;

/// Room enough that only the injected refusals refuse.
const ROOM: usize = 1 << 20;

fn server_config() -> Arc<ServerConfig> {
    let chain = vec![
        CertificateDer::from(&include_bytes!("../../test-ca/rsa-2048/end.der")[..]),
        CertificateDer::from(&include_bytes!("../../test-ca/rsa-2048/inter.der")[..]),
    ];
    let key =
        PrivateKeyDer::from_pem_reader(&mut &include_bytes!("../../test-ca/rsa-2048/end.key")[..])
            .unwrap();
    let mut config = ServerConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
    // No tickets and no session cache: the records are the handshake's own.
    config.send_tls13_tickets = 0;
    config.session_storage = Arc::new(NoServerSessionStorage {});
    Arc::new(config)
}

/// The client trusts any server: the schedule is about records.
#[derive(Debug)]
struct TrustAnything;

impl ServerCertVerifier for TrustAnything {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn client(version: &'static SupportedProtocolVersion) -> ClientConnection {
    let mut config = ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_protocol_versions(&[version])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(TrustAnything))
        .with_no_client_auth();
    config.resumption = Resumption::disabled();
    ClientConnection::new(
        Arc::new(config),
        ServerName::try_from("testserver.com").unwrap(),
    )
    .unwrap()
}

/// A small seeded generator, so that a schedule can be run again.
struct Rng(u64);

impl Rng {
    fn below(&mut self, n: usize) -> usize {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 % n as u64) as usize
    }

    fn chance(&mut self, percent: usize) -> bool {
        self.below(100) < percent
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Side {
    Client,
    Server,
}

impl Side {
    fn name(self) -> &'static str {
        match self {
            Self::Client => "C",
            Self::Server => "S",
        }
    }
}

/// Record.tla's length class of a record or plaintext length.
fn class(len: usize) -> &'static str {
    match len {
        0 => "Z",
        1..=16_383 => "S",
        16_384 => "F",
        16_385..=16_640 => "O1",
        16_641..=18_431 => "O2",
        18_432 => "O3",
        _ => "O4",
    }
}

fn outer(typ: u8) -> &'static str {
    match typ {
        20 => "ccs",
        21 => "alert",
        22 => "hs",
        _ => "app",
    }
}

/// One observation, with every field RecordTrace.tla may read.
struct Entry {
    a: &'static str,
    x: &'static str,
    t: &'static str,
    len: &'static str,
    it: &'static str,
    o: &'static str,
    data: &'static str,
    v: u64,
    changed: bool,
}

impl Entry {
    fn new(a: &'static str, x: Side) -> Self {
        Self {
            a,
            x: x.name(),
            t: "none",
            len: "Z",
            it: "?",
            o: "none",
            data: "none",
            v: 0,
            changed: false,
        }
    }

    fn tla(&self) -> String {
        format!(
            "[a |-> \"{}\", x |-> \"{}\", t |-> \"{}\", len |-> \"{}\", it |-> \"{}\", \
             o |-> \"{}\", data |-> \"{}\", v |-> {}, changed |-> {}]",
            self.a,
            self.x,
            self.t,
            self.len,
            self.it,
            self.o,
            self.data,
            self.v,
            if self.changed { "TRUE" } else { "FALSE" }
        )
    }
}

/// A record on its way, with the log entry of its sending, if it was sent
/// rather than injected.
struct InFlight {
    bytes: Vec<u8>,
    sent: Option<usize>,
}

/// What made the records a drain finds, for their inner kind until the
/// reader says.
enum Call {
    /// A write of this many records' worth.
    Write(usize),
    Refresh,
    Close,
    /// Processing records, which failed or not.
    Process(bool),
}

/// Everything the server's state is made of that a refusal must not
/// change.
#[derive(PartialEq, Debug)]
struct ServerState {
    read_seq: u64,
    write_seq: u64,
    queued: usize,
    plaintext: usize,
    held: usize,
    handshaking: bool,
    closed: bool,
}

struct Run {
    version: &'static str,
    rng: Rng,
    limit: Arc<Limit>,
    server: ServerConnection,
    client: ClientConnection,
    /// Records from the client, then from the server, in order.
    to_server: VecDeque<InFlight>,
    to_client: VecDeque<InFlight>,
    log: Vec<Entry>,
    dead: [bool; 2],
    closed: [bool; 2],
    forged: usize,
}

fn index(side: Side) -> usize {
    match side {
        Side::Client => 0,
        Side::Server => 1,
    }
}

impl Run {
    fn new(version: &'static SupportedProtocolVersion, seed: u64) -> Self {
        let limit = Limit::new(ROOM);
        let mut run = Self {
            version: if version.version == TLS13.version {
                "1.3"
            } else {
                "1.2"
            },
            rng: Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1),
            server: ServerConnection::with_budget(server_config(), limit.clone()).unwrap(),
            limit,
            client: client(version),
            to_server: VecDeque::new(),
            to_client: VecDeque::new(),
            log: Vec::new(),
            dead: [false; 2],
            closed: [false; 2],
            forged: 0,
        };
        run.drain(Side::Client, Call::Process(false));
        run
    }

    fn server_state(&mut self) -> ServerState {
        let common = &self.server.core.common_state;
        ServerState {
            read_seq: common.record_layer.read_seq(),
            write_seq: common.record_layer.write_seq(),
            queued: common.sendable_tls.len(),
            plaintext: common.received_plaintext.len(),
            held: self.server.buffers_held(),
            handshaking: self.server.is_handshaking(),
            closed: common.has_received_close_notify,
        }
    }

    fn write_seq(&self, side: Side) -> u64 {
        match side {
            Side::Client => self.client.core.common_state.record_layer.write_seq(),
            Side::Server => self.server.core.common_state.record_layer.write_seq(),
        }
    }

    fn read_state(&self, side: Side) -> (bool, u64) {
        let layer = match side {
            Side::Client => &self.client.core.common_state.record_layer,
            Side::Server => &self.server.core.common_state.record_layer,
        };
        (layer.is_decrypting(), layer.read_seq())
    }

    /// Takes everything `side` has queued, logging each record in order.
    fn drain(&mut self, side: Side, call: Call) {
        let mut wire = Vec::new();
        loop {
            let wants = match side {
                Side::Client => self.client.wants_write(),
                Side::Server => self.server.wants_write(),
            };
            if !wants {
                break;
            }
            match side {
                Side::Client => self.client.write_tls(&mut wire).unwrap(),
                Side::Server => self.server.write_tls(&mut wire).unwrap(),
            };
        }
        let mut records = Vec::new();
        let mut rest = &wire[..];
        while rest.len() >= 5 {
            let len = usize::from(u16::from_be_bytes([rest[3], rest[4]]));
            let (record, after) = rest.split_at(5 + len);
            records.push(record.to_vec());
            rest = after;
        }
        assert!(rest.is_empty(), "write_tls wrote part of a record");
        let count = records.len();
        for (n, record) in records.into_iter().enumerate() {
            let last = n + 1 == count;
            let it = match call {
                Call::Write(apps) if count == apps + 1 && n == 0 => "chg",
                Call::Write(_) => "app",
                Call::Refresh => "chg",
                Call::Close if last => "close",
                Call::Close => "chg",
                Call::Process(true) if last => "fatal",
                Call::Process(_) => "?",
            };
            let mut entry = Entry::new("send", side);
            entry.t = outer(record[0]);
            entry.len = class(record.len() - 5);
            entry.it = it;
            self.log.push(entry);
            let flight = InFlight {
                bytes: record,
                sent: Some(self.log.len() - 1),
            };
            match side {
                Side::Client => self.to_server.push_back(flight),
                Side::Server => self.to_client.push_back(flight),
            }
        }
        let mut entry = Entry::new("wseq", side);
        entry.v = self.write_seq(side);
        self.log.push(entry);
    }

    /// Logs a refusal of `what` at the server, given its state before.
    ///
    /// A refused write still queues a KeyUpdate that was waiting to go
    /// (buffer_plaintext calls perhaps_write_key_update before it pays for
    /// anything): what was queued is logged first, as the records it is,
    /// and the buffers it held are then left out of the comparison.
    fn refused(&mut self, before: ServerState, what: &'static str) {
        let logged = self.log.len();
        self.drain(Side::Server, Call::Write(0));
        let moved = self.log[logged..].iter().any(|entry| entry.a == "send");
        let mut after = self.server_state();
        if moved {
            after.held = before.held;
        }
        let mut entry = Entry::new("refuse", Side::Server);
        entry.o = what;
        entry.changed = before != after;
        if entry.changed {
            std::eprintln!("{what} refused, and the server changed: {before:?} -> {after:?}");
        }
        self.log.push(entry);
        self.limit.set_limit(ROOM);
    }

    /// Takes the server's room away, for the next growth to be refused.
    fn no_room(&mut self) -> ServerState {
        self.limit.set_limit(self.limit.used());
        self.server_state()
    }

    /// The plaintext `side` has, taken out.
    fn plaintext(&mut self, side: Side) -> usize {
        let mut got = 0;
        match side {
            Side::Server => {
                while let Ok(chunk) = self.server.reader().take_first_chunk() {
                    let (bytes, _charge) = chunk.into_parts();
                    if bytes.is_empty() {
                        break;
                    }
                    got += bytes.len();
                }
            }
            Side::Client => {
                let mut buf = vec![0; 1 << 15];
                while let Ok(n) = self.client.reader().read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    got += n;
                }
            }
        }
        got
    }

    /// Gives the next record of the other side's stream to `side`, read in
    /// random pieces, and processes it.
    fn deliver(&mut self, side: Side) {
        let flight = match side {
            Side::Server => self.to_server.pop_front(),
            Side::Client => self.to_client.pop_front(),
        }
        .unwrap();
        let record = flight.bytes;
        let (decrypting, read_seq) = self.read_state(side);
        let mut rest = &record[..];
        while !rest.is_empty() {
            let piece = 1 + self.rng.below(rest.len());
            if side == Side::Server && self.rng.chance(10) {
                let before = self.no_room();
                let mut probe = &rest[..piece];
                match self.server.read_tls(&mut probe) {
                    Err(error) if error.kind() == io::ErrorKind::OutOfMemory => {
                        self.refused(before, "read");
                        continue;
                    }
                    Ok(n) => {
                        self.limit.set_limit(ROOM);
                        rest = &rest[n..];
                        continue;
                    }
                    Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                        self.limit.set_limit(ROOM);
                        break;
                    }
                    Err(error) => panic!("read_tls: {error}"),
                }
            }
            let mut chunk = &rest[..piece];
            let read = match side {
                Side::Server => self.server.read_tls(&mut chunk),
                Side::Client => self.client.read_tls(&mut chunk),
            };
            match read {
                Ok(n) => rest = &rest[n..],
                // A header longer than the buffer may hold: it is read up
                // to the limit, and processing fails on the header.
                Err(error) if error.kind() == io::ErrorKind::InvalidData => break,
                Err(error) => panic!("read_tls: {error}"),
            }
        }
        if side == Side::Server && self.rng.chance(15) {
            let before = self.no_room();
            let result = self.server.process_new_packets();
            if result.is_ok() && self.server.wants_budget() {
                self.refused(before, "process");
            } else {
                self.limit.set_limit(ROOM);
                return self.processed(
                    side,
                    record,
                    flight.sent,
                    result.map(|_| ()),
                    (decrypting, read_seq),
                );
            }
        }
        let result = match side {
            Side::Server => self.server.process_new_packets().map(|_| ()),
            Side::Client => self.client.process_new_packets().map(|_| ()),
        };
        self.processed(side, record, flight.sent, result, (decrypting, read_seq));
    }

    /// Logs what `side` made of `record`, and what it sent for it.
    fn processed(
        &mut self,
        side: Side,
        record: Vec<u8>,
        sent: Option<usize>,
        result: Result<(), Error>,
        (decrypting, read_seq): (bool, u64),
    ) {
        let got = self.plaintext(side);
        let (decrypting_after, read_seq_after) = self.read_state(side);
        let closed = match side {
            Side::Client => self.client.core.common_state.has_received_close_notify,
            Side::Server => self.server.core.common_state.has_received_close_notify,
        };
        let mut entry = Entry::new("recv", side);
        entry.t = outer(record[0]);
        entry.len = class(record.len() - 5);
        entry.data = match got {
            0 => "none",
            16_384 => "F",
            _ => "S",
        };
        // What the reader made of it says what it was.
        let kind = match &result {
            Err(Error::AlertReceived(AlertDescription::CloseNotify)) => "close",
            Err(Error::AlertReceived(_)) => "fatal",
            Err(_) => "?",
            Ok(()) if closed && !self.closed[1 - index(side)] => "close",
            Ok(()) if got > 0 => "app",
            Ok(()) if !decrypting && decrypting_after => "chg",
            // TLS 1.3's change_cipher_spec is never protected.
            Ok(()) if record[0] == 20 => "ccs",
            Ok(()) if decrypting && read_seq_after != read_seq + 1 => "chg",
            Ok(()) => "hs",
        };
        entry.o = match &result {
            Ok(()) | Err(Error::AlertReceived(_)) => "accept",
            Err(_) => "fail",
        };
        if let Some(sent) = sent {
            if kind != "?" {
                self.log[sent].it = kind;
            }
        }
        self.log.push(entry);
        if closed {
            self.closed[1 - index(side)] = true;
        }
        let failed = result.is_err();
        if failed {
            self.dead[index(side)] = true;
        }
        self.drain(
            side,
            Call::Process(failed && !matches!(result, Err(Error::AlertReceived(_)))),
        );
        if !failed {
            let mut entry = Entry::new("rseq", side);
            entry.v = self.read_state(side).1;
            self.log.push(entry);
        }
    }

    fn handshaking(&self, side: Side) -> bool {
        match side {
            Side::Client => self.client.is_handshaking(),
            Side::Server => self.server.is_handshaking(),
        }
    }

    /// Whether `side` may still be asked to write.
    fn writing(&self, side: Side) -> bool {
        let i = index(side);
        !self.dead[i] && !self.sent_close(side) && !self.dead[1 - i]
    }

    fn sent_close(&self, side: Side) -> bool {
        match side {
            Side::Client => self.client.core.common_state.has_sent_close_notify,
            Side::Server => self.server.core.common_state.has_sent_close_notify,
        }
    }

    fn write(&mut self, side: Side) {
        let size = [0, 1, 16_384][self.rng.below(3)];
        let data = vec![7; size];
        if side == Side::Server && size > 0 && self.rng.chance(20) {
            let before = self.no_room();
            let n = self.server.writer().write(&data).unwrap();
            if n == 0 {
                self.refused(before, "write");
                return;
            }
            self.limit.set_limit(ROOM);
            return self.drain(side, Call::Write(1));
        }
        let n = match side {
            Side::Client => self.client.writer().write(&data).unwrap(),
            Side::Server => self.server.writer().write(&data).unwrap(),
        };
        assert_eq!(n, size, "a write took part of one record");
        self.drain(side, Call::Write(usize::from(size > 0)));
    }

    fn refresh(&mut self, side: Side) {
        if side == Side::Server && self.rng.chance(20) {
            let before = self.no_room();
            match self.server.refresh_traffic_keys() {
                Err(Error::BudgetExhausted) => {
                    self.refused(before, "refresh");
                    return;
                }
                result => {
                    self.limit.set_limit(ROOM);
                    result.unwrap();
                }
            }
        } else {
            match side {
                Side::Client => self.client.refresh_traffic_keys().unwrap(),
                Side::Server => self.server.refresh_traffic_keys().unwrap(),
            }
        }
        self.drain(side, Call::Refresh);
    }

    fn close(&mut self, side: Side) {
        match side {
            Side::Client => assert!(self.client.send_close_notify()),
            Side::Server => {
                if self.rng.chance(20) {
                    let before = self.no_room();
                    if !self.server.send_close_notify() {
                        self.refused(before, "close");
                        return;
                    }
                    self.limit.set_limit(ROOM);
                } else {
                    assert!(self.server.send_close_notify());
                }
            }
        }
        self.drain(side, Call::Close);
    }

    /// A garbage application data record at the end of `side`'s stream.
    fn forge(&mut self, side: Side) {
        let len = match (self.rng.chance(50), self.version) {
            (true, _) => 100,
            (false, "1.3") => (1 << 14) + 300,
            (false, _) => (1 << 14) + 2049,
        };
        let mut bytes = vec![23, 3, 3];
        bytes.extend_from_slice(&u16::try_from(len).unwrap().to_be_bytes());
        bytes.resize(5 + len, 0x5a);
        let mut entry = Entry::new("forge", side);
        entry.len = class(len);
        self.log.push(entry);
        self.forged += 1;
        let flight = InFlight { bytes, sent: None };
        match side {
            Side::Client => self.to_server.push_back(flight),
            Side::Server => self.to_client.push_back(flight),
        }
    }

    /// Whether `side` may be given the next record of the other's stream.
    fn can_deliver(&self, side: Side) -> bool {
        let i = index(side);
        let queue = match side {
            Side::Server => &self.to_server,
            Side::Client => &self.to_client,
        };
        !queue.is_empty() && !self.dead[i] && !self.closed[1 - i]
    }

    fn step(&mut self) -> bool {
        let mut choices: Vec<u8> = Vec::new();
        for side in [Side::Client, Side::Server] {
            let s = side as u8;
            if self.can_deliver(side) {
                // Delivering is the commonest step.
                choices.extend_from_slice(&[s * 10, s * 10, s * 10]);
            }
            if self.writing(side) {
                choices.push(s * 10 + 1);
                if !self.handshaking(side) {
                    choices.push(s * 10 + 1);
                    if self.version == "1.3" {
                        choices.push(s * 10 + 2);
                    }
                    if self.rng.chance(30) {
                        choices.push(s * 10 + 3);
                    }
                }
            }
            if self.forged < 1 && !self.dead[0] && !self.dead[1] && self.rng.chance(10) {
                choices.push(s * 10 + 4);
            }
        }
        if choices.is_empty() {
            return false;
        }
        let choice = choices[self.rng.below(choices.len())];
        let side = if choice / 10 == 0 {
            Side::Client
        } else {
            Side::Server
        };
        match choice % 10 {
            0 => self.deliver(side),
            1 => self.write(side),
            2 => self.refresh(side),
            3 => self.close(side),
            _ => self.forge(side),
        }
        true
    }

    fn run(&mut self) {
        for _ in 0..STEPS {
            if !self.step() {
                break;
            }
        }
        // Everything left that may be delivered is.
        loop {
            if self.can_deliver(Side::Server) {
                self.deliver(Side::Server);
            } else if self.can_deliver(Side::Client) {
                self.deliver(Side::Client);
            } else {
                break;
            }
        }
    }

    /// The log as a TLA+ module and its TLC config.
    fn files(&self, name: &str) -> (String, String) {
        let entries: Vec<String> = self.log.iter().map(Entry::tla).collect();
        let module = format!(
            "---- MODULE {name} ----\nEXTENDS RecordTrace\nTraceLog == <<\n  {}\n>>\n====\n",
            entries.join(",\n  ")
        );
        let config = format!(
            "SPECIFICATION TraceSpec\nCONSTANTS\n  V = \"{}\"\n  Early = \"none\"\n  \
             Allowance = 0\n  Frag = FALSE\n  Compat = {}\n  Wide = FALSE\n  \
             AppPls = {{\"S\", \"F\"}}\n  MaxAppC = 40\n  MaxAppS = 40\n  MaxKU = 20\n  \
             MaxForge = 1\n  MaxBad = 0\n  MaxHs = 4\n  Misbehave = FALSE\n  \
             ReplyFirst = TRUE\n  CheckSeq = TRUE\n  IgnoreAfterClose = TRUE\n  \
             QuietAfterClose = TRUE\n  CheckSize = TRUE\n  Log <- TraceLog\n\
             INVARIANTS\n  TraceIncomplete\n  AuthBeforeDeliver\n  NonceUnique\n  NoGap\n  \
             KUOrder\n  KUReplyFirst\n  NoSendAfterClose\n  IgnoreAfterCloseProp\n  \
             FatalEnds\n  AccLegal\n  RightAlert\n  NoFalseReject\n  HonestWriter\n\
             CHECK_DEADLOCK FALSE\n",
            self.version,
            // TLS 1.3's compatibility change_cipher_spec.
            if self.version == "1.3" {
                "TRUE"
            } else {
                "FALSE"
            }
        );
        (module, config)
    }
}

/// Runs every seed for both versions, and writes the logs where
/// `FICTIONET_RECORD_TRACE_DIR` says.
#[test]
fn record_trace() {
    let dir = std::env::var_os("FICTIONET_RECORD_TRACE_DIR").map(std::path::PathBuf::from);
    let mut entries = 0;
    for version in [&TLS13, &TLS12] {
        for seed in 1..=SEEDS {
            let mut run = Run::new(version, seed);
            run.run();
            entries += run.log.len();
            if let Some(dir) = &dir {
                let name = format!("RecLog_{}_{seed}", run.version.replace('.', ""));
                let (module, config) = run.files(&name);
                std::fs::create_dir_all(dir).unwrap();
                std::fs::write(dir.join(format!("{name}.tla")), module).unwrap();
                std::fs::write(dir.join(format!("{name}.cfg")), config).unwrap();
            }
        }
    }
    assert!(entries > 0);
}
