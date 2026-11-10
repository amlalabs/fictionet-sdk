//! The record checks before decryption against the Lean model's vectors
//! (`verification/tls-rfc/lean/Gen.lean`, `header.txt`).
//!
//! Each vector names a read state (no keys yet, TLS 1.2 or TLS 1.3 traffic
//! keys), a record header (content type, legacy version, length) and what
//! `TlsRecord.check` says the record layer does with it. The test sends that
//! record, its body all zeros, to a real server connection in that state
//! and compares what happens:
//!
//! - a refusal is the error that names it, with the alert the client then
//!   receives: record_overflow, unexpected_message, or decode_error for a
//!   bad version or an empty fragment;
//! - an accepted record is anything else, and for a protected record it is
//!   the AEAD failure of its zero body: it reached decryption.
//!
//! It runs when named, with the vectors' directory in `TLS_RECORD_VECTORS`:
//!
//! ```text
//! cargo xtask tls-verify vectors
//! TLS_RECORD_VECTORS=<dir> cargo test -p fictionet-rustls --lib record_vectors -- --ignored
//! ```

use alloc::string::String;
use alloc::vec::Vec;
use std::{eprintln, format};

use super::*;
use crate::error::InvalidMessage;

/// What the vectors say.
#[derive(Debug, PartialEq, Clone, Copy)]
enum Verdict {
    Accept,
    RecordOverflow,
    UnexpectedType,
    BadVersion,
    EmptyFragment,
}

impl Verdict {
    fn parse(name: &str) -> Self {
        match name {
            "accept" => Self::Accept,
            "record_overflow" => Self::RecordOverflow,
            "unexpected_type" => Self::UnexpectedType,
            "bad_version" => Self::BadVersion,
            "empty_fragment" => Self::EmptyFragment,
            other => panic!("unknown verdict {other}"),
        }
    }

    /// The verdict an error from processing the record names.
    fn of(error: &Error) -> Self {
        match error {
            Error::PeerSentOversizedRecord => Self::RecordOverflow,
            Error::InvalidMessage(InvalidMessage::InvalidContentType) => Self::UnexpectedType,
            Error::InvalidMessage(InvalidMessage::UnknownProtocolVersion) => Self::BadVersion,
            Error::InvalidMessage(InvalidMessage::InvalidEmptyPayload) => Self::EmptyFragment,
            _ => Self::Accept,
        }
    }

    /// The alert a refusal sends.
    fn alert(self) -> Option<AlertDescription> {
        match self {
            Self::Accept => None,
            Self::RecordOverflow => Some(AlertDescription::RecordOverflow),
            Self::UnexpectedType => Some(AlertDescription::UnexpectedMessage),
            Self::BadVersion | Self::EmptyFragment => Some(AlertDescription::DecodeError),
        }
    }
}

/// A server and its client in the read state named, past the handshake
/// for a TLS version.
fn pair(state: &str) -> (ServerConnection, ClientConnection) {
    let version = match state {
        "plain" => {
            let server =
                ServerConnection::with_budget(server_config(), Limit::new(1 << 20)).unwrap();
            return (server, client(&TLS13));
        }
        "tls12" => &TLS12,
        "tls13" => &TLS13,
        other => panic!("unknown state {other}"),
    };
    let mut server = ServerConnection::with_budget(server_config(), Limit::new(1 << 20)).unwrap();
    let mut client = client(version);
    handshake(&mut server, &mut client);
    assert!(!server.is_handshaking());
    (server, client)
}

/// The record a vector describes, its body all zeros.
fn wire(typ: u8, version: u16, len: usize) -> Vec<u8> {
    let mut bytes = vec![typ];
    bytes.extend_from_slice(&version.to_be_bytes());
    bytes.extend_from_slice(&u16::try_from(len).unwrap().to_be_bytes());
    bytes.resize(HEADER_SIZE + len, 0);
    bytes
}

/// The alert the client receives from what the server queued.
fn alert_received(server: &mut ServerConnection, client: &mut ClientConnection) -> Option<Error> {
    let mut out = Vec::new();
    while server.wants_write() {
        server.write_tls(&mut out).unwrap();
    }
    let mut rest = &out[..];
    while !rest.is_empty() {
        if client.read_tls(&mut rest).is_err() {
            return None;
        }
        if let Err(error) = client.process_new_packets() {
            return Some(error);
        }
    }
    None
}

#[test]
#[ignore = "needs TLS_RECORD_VECTORS from the Lean model: cargo xtask tls-verify vectors"]
fn record_vectors() {
    let dir = std::env::var("TLS_RECORD_VECTORS").expect("TLS_RECORD_VECTORS names the vectors");
    let text = std::fs::read_to_string(format!("{dir}/header.txt")).unwrap();
    let mut cases = 0;
    let mut wrong: Vec<String> = Vec::new();
    for line in text.lines().filter(|line| !line.is_empty()) {
        let fields: Vec<&str> = line.split(' ').collect();
        let [state, typ, version, len, verdict, protected] = fields[..] else {
            panic!("malformed vector: {line}");
        };
        let typ: u8 = typ.parse().unwrap();
        let version: u16 = version.parse().unwrap();
        let len: usize = len.parse().unwrap();
        let expected = Verdict::parse(verdict);
        let protected = protected == "1";
        cases += 1;

        let (mut server, mut client) = pair(state);
        let mut rest = &wire(typ, version, len)[..];
        let mut result = Ok(());
        while !rest.is_empty() && result.is_ok() {
            match server.read_tls(&mut rest) {
                Ok(n) => assert!(n > 0),
                Err(error) => panic!("{line}: read failed: {error}"),
            }
            result = server.process_new_packets().map(|_| ());
        }
        let got = match &result {
            Ok(()) => Verdict::Accept,
            Err(error) => Verdict::of(error),
        };
        if got != expected {
            wrong.push(format!("{line}: got {got:?} from {result:?}"));
            continue;
        }
        if expected == Verdict::Accept && protected && result != Err(Error::DecryptError) {
            wrong.push(format!("{line}: accepted but not decrypted: {result:?}"));
            continue;
        }
        if let Some(alert) = expected.alert() {
            let received = alert_received(&mut server, &mut client);
            if received != Some(Error::AlertReceived(alert)) {
                wrong.push(format!("{line}: the client got {received:?}"));
            }
        }
    }
    eprintln!("record_vectors: {cases} cases");
    assert!(cases > 0, "no vectors in {dir}/header.txt");
    assert!(
        wrong.is_empty(),
        "{} of {cases} disagree:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}
