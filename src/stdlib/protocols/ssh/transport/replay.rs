//! Behaviors of `verification/ssh-layer/tla/Transport.tla`, replayed on
//! the production [`Transport`] against a client written from RFC 4253,
//! strict KEX and RFC 8308, with real keys and ciphers.
//!
//! A trace is the list of the model's actions, one per line, as TLC
//! printed them for a configuration named in the README. Each action is
//! one step here: `ServerRecv` hands the server the client's next packet,
//! `ClientRecv` opens the server's next packet, and so on. The model's
//! checks are made on the real bytes: every packet opens under the
//! receiver's own sequence number and key (the AEAD fails otherwise), the
//! server's exchange messages come in order, EXT_INFO comes right after
//! the first NEWKEYS, no application message comes while the server is
//! in an exchange, and the server signs the exchange hash the client
//! computed. Without strict KEX every sequence number starts just short
//! of 2^32, so they wrap during the run.

use super::*;
use std::collections::VecDeque;

/// What the client put on the wire, so the replay knows which packet
/// breaks strict KEX.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Sent {
    Proper,
    Injected,
}

const CIPHER: &str = "chacha20-poly1305@openssh.com";

struct Client {
    id: Identification,
    server_id: Identification,
    strict: bool,
    ext: bool,
    out: Direction,
    inc: Direction,
    rng: ChaCha20Rng,
    wire: VecDeque<(Vec<u8>, Sent)>,
    /// Our KEXINIT and the server's, for the exchange hash.
    ours: Vec<u8>,
    theirs: Vec<u8>,
    secret: Option<x25519_dalek::StaticSecret>,
    round: u8,
    session_id: Vec<u8>,
    next_out: Option<Direction>,
    next_in: Option<Direction>,
    /// The client's side of the current exchange.
    idle: bool,
    sent30: bool,
    got_reply: bool,
    sent_newkeys: bool,
    got_newkeys: bool,
    server_in_kex: bool,
    newkeys_seen: bool,
    after_first_newkeys: bool,
    ext_info: bool,
    buffer: Vec<u8>,
    version_read: bool,
}

impl Client {
    fn send(&mut self, payload: &[u8], sent: Sent) {
        let mut bytes = Vec::new();
        self.out.write(payload, &mut self.rng, &mut bytes).unwrap();
        self.wire.push_back((bytes, sent));
    }

    /// Our KEXINIT. A wrong guess names first a method the server does
    /// not run, so the server's choice differs from it.
    fn kexinit(&mut self, guess: Option<bool>) {
        let mut kex = Vec::new();
        if guess == Some(false) {
            kex.push("diffie-hellman-group14-sha256".to_owned());
        }
        kex.push("curve25519-sha256".to_owned());
        if self.strict {
            kex.push(STRICT_CLIENT.to_owned());
        }
        if self.ext {
            kex.push("ext-info-c".to_owned());
        }
        let names = |n: &str| vec![n.to_owned()];
        self.ours = Message::KexInit(KexInit {
            cookie: [self.round; 16],
            kex_algorithms: kex,
            server_host_key_algorithms: names("ssh-ed25519"),
            encryption_client_to_server: names(CIPHER),
            encryption_server_to_client: names(CIPHER),
            mac_client_to_server: names("hmac-sha2-256"),
            mac_server_to_client: names("hmac-sha2-256"),
            compression_client_to_server: names("none"),
            compression_server_to_client: names("none"),
            first_kex_packet_follows: guess.is_some(),
            ..KexInit::default()
        })
        .to_bytes()
        .unwrap();
        let payload = self.ours.clone();
        self.send(&payload, Sent::Proper);
        self.idle = false;
    }

    fn ecdh(&mut self) {
        self.round += 1;
        let secret = x25519_dalek::StaticSecret::from([self.round.wrapping_mul(29) | 1; 32]);
        let public = x25519_dalek::PublicKey::from(&secret);
        self.secret = Some(secret);
        self.sent30 = true;
        let mut payload = vec![30];
        put_string(&mut payload, public.as_bytes());
        self.send(&payload, Sent::Proper);
    }

    /// ECDH_REPLY: check the host signature over the exchange hash and
    /// derive the next keys of both directions (RFC 4253 sections 7.2, 8).
    fn reply(&mut self, payload: &[u8]) {
        let mut reader = Reader::new(&payload[1..]);
        let host = reader.string().unwrap();
        let server_public = reader.string().unwrap();
        let signature = reader.string().unwrap();
        reader.finish().unwrap();
        let secret = self.secret.take().expect("we sent ECDH_INIT");
        let ours = x25519_dalek::PublicKey::from(&secret);
        let peer: [u8; 32] = server_public.try_into().unwrap();
        let shared = secret.diffie_hellman(&x25519_dalek::PublicKey::from(peer));
        let k = Mpint::from_unsigned_bytes(shared.as_bytes())
            .unwrap()
            .to_bytes()
            .unwrap();
        let mut transcript = Vec::new();
        put_string(&mut transcript, &version_text(&self.id).unwrap());
        put_string(&mut transcript, &version_text(&self.server_id).unwrap());
        put_string(&mut transcript, &self.ours);
        put_string(&mut transcript, &self.theirs);
        put_string(&mut transcript, host);
        put_string(&mut transcript, ours.as_bytes());
        put_string(&mut transcript, server_public);
        transcript.extend_from_slice(&k);
        let hash = digest::digest(&digest::SHA256, &transcript);
        let mut blob = Reader::new(signature);
        assert_eq!(blob.string().unwrap(), b"ssh-ed25519");
        let raw = blob.string().unwrap();
        let mut key = Reader::new(host);
        assert_eq!(key.string().unwrap(), b"ssh-ed25519");
        signature::UnparsedPublicKey::new(&signature::ED25519, key.string().unwrap())
            .verify(hash.as_ref(), raw)
            .expect("the server signs the exchange hash the client computed");
        if self.session_id.is_empty() {
            self.session_id = hash.as_ref().to_vec();
        }
        let derive = |letter, length| {
            derive_key(
                &digest::SHA256,
                &k,
                hash.as_ref(),
                &self.session_id,
                letter,
                length,
            )
        };
        self.next_out =
            Some(Direction::encrypted(CIPHER, &derive(b'C', 64), &derive(b'A', 12)).unwrap());
        self.next_in =
            Some(Direction::encrypted(CIPHER, &derive(b'D', 64), &derive(b'B', 12)).unwrap());
        self.got_reply = true;
    }

    /// The round is over once NEWKEYS has gone both ways.
    fn end_round(&mut self) {
        if self.sent_newkeys && self.got_newkeys {
            self.idle = true;
            self.sent30 = false;
            self.got_reply = false;
            self.sent_newkeys = false;
            self.got_newkeys = false;
        }
    }

    /// Opens the server's next packet and makes the model's checks.
    fn receive(&mut self, server_out: &mut Vec<u8>) {
        self.buffer.append(server_out);
        if !self.version_read {
            let end = self.buffer.windows(2).position(|w| w == b"\r\n").unwrap() + 2;
            assert_eq!(&self.buffer[..end], self.server_id.to_bytes().unwrap());
            self.buffer.drain(..end);
            self.version_read = true;
            return;
        }
        let Step::Item(TransportEvent::Packet { payload, .. }, used) = self
            .inc
            .read(&self.buffer)
            .expect("the packet opens under our sequence number and key")
        else {
            panic!("the server's next packet is incomplete");
        };
        self.buffer.drain(..used);
        let after_first_newkeys = std::mem::take(&mut self.after_first_newkeys);
        match payload[0] {
            20 => {
                self.theirs = payload;
                self.server_in_kex = true;
                // Section 7.1: a KEXINIT while idle is answered with ours.
                if self.idle {
                    self.kexinit(None);
                }
            }
            31 => {
                assert!(self.sent30, "ECDH_REPLY before ECDH_INIT");
                self.reply(&payload);
            }
            21 => {
                assert!(self.got_reply, "NEWKEYS before ECDH_REPLY");
                let mut inc = self.next_in.take().unwrap();
                inc.sequence = if self.strict { 0 } else { self.inc.sequence };
                self.inc = inc;
                self.server_in_kex = false;
                self.after_first_newkeys = !self.newkeys_seen;
                self.newkeys_seen = true;
                self.got_newkeys = true;
                self.end_round();
            }
            7 => {
                assert!(
                    self.ext && after_first_newkeys && !self.ext_info,
                    "EXT_INFO once, right after the first NEWKEYS, when asked for"
                );
                self.ext_info = true;
            }
            _ => assert!(
                !self.server_in_kex && self.newkeys_seen,
                "no application message while the server is in an exchange"
            ),
        }
    }

    fn newkeys(&mut self) {
        self.send(&[21], Sent::Proper);
        let mut out = self.next_out.take().expect("keys from the reply");
        out.sequence = if self.strict { 0 } else { self.out.sequence };
        self.out = out;
        self.sent_newkeys = true;
        self.end_round();
    }
}

/// Replays `trace`, the client asking for strict KEX and EXT_INFO as
/// given. Without strict KEX, sequence numbers start at `u32::MAX - 1`.
fn replay(trace: &str, strict: bool, ext: bool) -> bool {
    let host = Arc::new(HostKey::ed25519_from_seed([7; 32]).unwrap());
    let server_id = Identification::new("2.0", "server", None).unwrap();
    let mut server = Transport::new(host, server_id.clone());
    server.seed([19; 32]).unwrap();
    let mut client = Client {
        id: Identification::new("2.0", "client", None).unwrap(),
        server_id,
        strict,
        ext,
        out: Direction::plain(),
        inc: Direction::plain(),
        rng: ChaCha20Rng::from_seed([23; 32]),
        wire: VecDeque::new(),
        ours: Vec::new(),
        theirs: Vec::new(),
        secret: None,
        round: 0,
        session_id: Vec::new(),
        next_out: None,
        next_in: None,
        idle: true,
        sent30: false,
        got_reply: false,
        sent_newkeys: false,
        got_newkeys: false,
        server_in_kex: false,
        newkeys_seen: false,
        after_first_newkeys: false,
        ext_info: false,
        buffer: Vec::new(),
        version_read: false,
    };
    if !strict {
        let start = u32::MAX - 1;
        server.outgoing.sequence = start;
        server.incoming.sequence = start;
        client.out.sequence = start;
        client.inc.sequence = start;
    }
    let mut s2c = Vec::new();
    server.start(&mut s2c).unwrap();
    let version = client.id.to_bytes().unwrap();
    client.wire.push_back((version, Sent::Proper));
    let mut steps = 0;
    for action in trace.lines().map(str::trim).filter(|l| !l.is_empty()) {
        steps += 1;
        match action {
            "ServerRecv" => {
                let (bytes, sent) = client.wire.pop_front().expect("a client packet to read");
                let handled = server.decode(&bytes, false).and_then(|step| match step {
                    Step::Item(event, used) => {
                        assert_eq!(used, bytes.len());
                        server.handle(event, &mut s2c)
                    }
                    _ => panic!("one whole packet decodes"),
                });
                if sent == Sent::Injected {
                    assert_eq!(handled, Err(TransportError::State), "strict KEX refuses it");
                    return true;
                }
                handled.unwrap_or_else(|e| panic!("step {steps} {action}: {e}"));
            }
            "ClientRecv" => client.receive(&mut s2c),
            "ClientKexInit" => client.kexinit(None),
            "ClientGuessRight" => {
                client.kexinit(Some(true));
                client.ecdh();
            }
            "ClientGuessWrong" => {
                client.kexinit(Some(false));
                client.ecdh();
                // The server ignores it; the real one follows.
                client.sent30 = false;
                client.secret = None;
            }
            "ClientEcdh" => client.ecdh(),
            "ClientNewKeys" => client.newkeys(),
            "ClientApp" => client.send(&[94, 0, 0, 0, 0, 1], Sent::Proper),
            "ClientIgnore" | "ClientInject" => {
                let sent = if action == "ClientInject" {
                    Sent::Injected
                } else {
                    Sent::Proper
                };
                client.send(&Message::Ignore(vec![1]).to_bytes().unwrap(), sent)
            }
            "ServerApp" | "ServerHandleReply" => server
                .write_packet(&[94, 0, 0, 0, 0, 2], &mut s2c)
                .unwrap_or_else(|e| panic!("step {steps} {action}: {e}")),
            "ServerHandleQuiet" => {}
            "ServerRekey" => server.rekey(&mut s2c).unwrap(),
            other => panic!("unknown action {other}"),
        }
    }
    assert!(steps > 0);
    assert!(client.wire.is_empty() && s2c.is_empty() && client.buffer.is_empty());
    assert!(server.is_established() && !server.is_rekeying());
    false
}

#[test]
fn transport_traces_replay_on_the_production_transport() {
    let trace = |name: &str| match name {
        "loose" => include_str!("../../../../../verification/ssh-layer/traces/loose.txt"),
        "strict" => include_str!("../../../../../verification/ssh-layer/traces/strict.txt"),
        "wrong" => include_str!("../../../../../verification/ssh-layer/traces/wrong.txt"),
        "inject" => include_str!("../../../../../verification/ssh-layer/traces/inject.txt"),
        _ => unreachable!(),
    };
    assert!(!replay(trace("loose"), false, true));
    assert!(!replay(trace("strict"), true, true));
    assert!(!replay(trace("wrong"), false, false));
    assert!(
        replay(trace("inject"), true, false),
        "the injected IGNORE ends it"
    );
}
