//! The sending side of the record layer against the Lean model's vectors
//! (`verification/tls-rfc/lean/Gen.lean`, `nonce.txt`).
//!
//! Each vector is a sequence of records, KeyUpdate requests and KeyUpdate
//! replies, each with what the budget does to it: pays (`queued`), refuses
//! before encryption (`refused`), or pays and then refuses the larger
//! allocation the encrypter made (`dropped`). `TlsRecord.Nonce.run` gives
//! the records that reach the wire, whether the connection failed, and how
//! many records were encrypted. This test drives a real [`CommonState`]
//! through the same sequence, with an encrypter that writes the key and
//! sequence number it was given into each record, and compares.
//!
//! It runs when named, with the vectors' directory in `TLS_RECORD_VECTORS`:
//!
//! ```text
//! cargo xtask tls-verify vectors
//! TLS_RECORD_VECTORS=<dir> cargo test -p fictionet-rustls --lib nonce_vectors -- --ignored
//! ```

use alloc::string::String;
use core::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::{eprintln, format};

use super::*;
use crate::budget::testing::Limit as Budget;
use crate::crypto::cipher::MessageEncrypter;
use crate::msgs::message::{OutboundOpaqueMessage, PrefixedPayload};

/// What every record's payload holds: its key's number, its sequence
/// number and its inner content type.
const TAGGED: usize = 4 + 8 + 1;

/// Room the budget leaves for an operation it pays for: more than any
/// record and the queue's places, less than [`EXTRA`].
const ROOM: usize = 1 << 16;

/// The capacity added to a record whose allocation the budget refuses.
const EXTRA: usize = 1 << 20;

/// Every (key, sequence number) handed to an encrypter, in order.
type Used = Arc<Mutex<Vec<(u32, u64)>>>;

/// Encrypts under key number `epoch`: writes the key's number, the
/// sequence number and the content type in place of a ciphertext, in an
/// allocation `extra` bytes larger than it says.
struct Tagging {
    epoch: u32,
    used: Used,
    extra: Arc<AtomicUsize>,
}

impl MessageEncrypter for Tagging {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        self.used.lock().unwrap().push((self.epoch, seq));
        let extra = self.extra.load(Ordering::SeqCst);
        let mut payload = PrefixedPayload::with_capacity(TAGGED + extra);
        payload.extend_from_slice(&self.epoch.to_be_bytes());
        payload.extend_from_slice(&seq.to_be_bytes());
        payload.extend_from_slice(&[u8::from(msg.typ)]);
        Ok(OutboundOpaqueMessage::new(msg.typ, msg.version, payload))
    }

    fn encrypted_payload_len(&self, _payload_len: usize) -> usize {
        TAGGED
    }
}

/// A connection's sending side, under the replay's control.
struct Sender {
    state: CommonState,
    budget: Arc<Budget>,
    epoch: u32,
    used: Used,
    extra: Arc<AtomicUsize>,
}

impl Sender {
    fn new() -> Self {
        let budget = Budget::new(ROOM);
        let mut state = CommonState::new(Side::Server);
        state.pay_from(Some(budget.clone()));
        state.may_send_application_data = true;
        let mut sender = Self {
            state,
            budget,
            epoch: 0,
            used: Arc::new(Mutex::new(Vec::new())),
            extra: Arc::new(AtomicUsize::new(0)),
        };
        sender.install_key();
        sender
    }

    /// `set_message_encrypter` with key number `self.epoch`.
    fn install_key(&mut self) {
        let encrypter = Tagging {
            epoch: self.epoch,
            used: self.used.clone(),
            extra: self.extra.clone(),
        };
        self.state
            .record_layer
            .set_message_encrypter(Box::new(encrypter), u64::MAX);
    }

    fn next_key(&mut self) {
        self.epoch += 1;
        self.install_key();
    }

    /// Sets the budget and the encrypter for what `outcome` says.
    fn arrange(&mut self, outcome: &str) {
        let used = self.budget.used();
        let (room, extra) = match outcome {
            "queued" => (ROOM, 0),
            "refused" => (0, 0),
            "dropped" => (ROOM, EXTRA),
            other => panic!("unknown outcome {other}"),
        };
        self.budget.set_limit(used + room);
        self.extra.store(extra, Ordering::SeqCst);
    }

    fn apply(&mut self, op: &str) {
        let (kind, outcome) = op.split_once('.').expect("an op is <kind>.<outcome>");
        self.arrange(outcome);
        match kind {
            // An application data record: `send_plain_non_buffering`, as a
            // write after the handshake.
            "send" => {
                self.state
                    .send_plain_non_buffering(b"x"[..].into(), Limit::No, false);
            }
            // A KeyUpdate request: `refresh_traffic_keys`, then
            // `request_key_update_and_update_encrypter`.
            "request" => {
                let sent = self.state.with_control_room(1, |common| {
                    common.send_msg_encrypt(Message::build_key_update_request().into())
                });
                if sent {
                    self.next_key();
                }
            }
            // The reply to a peer's update_requested: `should_update_key`,
            // then `update_encrypter_and_notify`.
            "reply" => {
                if self.state.queued_key_update_message.is_none() {
                    self.state.enqueue_key_update_notification();
                    self.next_key();
                }
            }
            other => panic!("unknown op {other}"),
        }
        self.extra.store(0, Ordering::SeqCst);
    }

    /// The records queued for the wire, oldest first, as the vectors write
    /// them.
    fn wire(&mut self) -> Vec<String> {
        let mut bytes = Vec::new();
        self.state.sendable_tls.write_to(&mut bytes).unwrap();
        bytes
            .chunks(HEADER_SIZE + TAGGED)
            .map(|record| {
                assert_eq!(record.len(), HEADER_SIZE + TAGGED, "a torn record");
                let body = &record[HEADER_SIZE..];
                let epoch = u32::from_be_bytes(body[..4].try_into().unwrap());
                let seq = u64::from_be_bytes(body[4..12].try_into().unwrap());
                let kind = match ContentType::from(body[12]) {
                    ContentType::ApplicationData => "data",
                    ContentType::Handshake => "key_update",
                    other => panic!("unexpected record type {other:?}"),
                };
                format!("{epoch}.{seq}.{kind}")
            })
            .collect()
    }
}

#[test]
#[ignore = "needs TLS_RECORD_VECTORS from the Lean model: cargo xtask tls-verify vectors"]
fn nonce_vectors() {
    let dir = std::env::var("TLS_RECORD_VECTORS").expect("TLS_RECORD_VECTORS names the vectors");
    let text = std::fs::read_to_string(format!("{dir}/nonce.txt")).unwrap();
    let mut cases = 0;
    let mut wrong: Vec<String> = Vec::new();
    for line in text.lines().filter(|line| !line.is_empty()) {
        let parts: Vec<&str> = line.split(" | ").collect();
        let [ops, wire, end] = parts[..] else {
            panic!("malformed vector: {line}");
        };
        let expected_wire: Vec<&str> = match wire {
            "-" => Vec::new(),
            wire => wire.split(' ').collect(),
        };
        let (failed, used) = end.split_once(' ').expect("<failed> <used>");
        let used: usize = used.parse().expect("<used> is a number");
        cases += 1;

        let mut sender = Sender::new();
        for op in ops.split(' ') {
            sender.apply(op);
        }
        let got_wire = sender.wire();
        let got_failed = sender.state.output_paid().is_err();
        let got_used = sender.used.lock().unwrap().clone();
        let mut distinct = got_used.clone();
        distinct.sort_unstable();
        distinct.dedup();

        if got_wire != expected_wire
            || got_failed != (failed == "1")
            || got_used.len() != used
            || distinct.len() != got_used.len()
        {
            wrong.push(format!(
                "{line}\n  got: {} | failed {got_failed} | used {got_used:?}",
                got_wire.join(" ")
            ));
        }
    }
    eprintln!("nonce_vectors: {cases} cases");
    assert!(cases > 0, "no vectors in {dir}/nonce.txt");
    assert!(
        wrong.is_empty(),
        "{} of {cases} disagree:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}
