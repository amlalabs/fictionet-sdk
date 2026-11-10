//! The differential test: the Rust DNS code against the vectors the Lean
//! model writes (`verification/dns/lean/Gen.lean`).
//!
//! It runs when named, with the directory of the vectors in `DNS_VECTORS`.
//! `cargo xtask dns-verify diff` writes each seed's vectors to
//! `target/dns-verify/vectors/<seed>` and runs it on each; the second line
//! runs it again on the first seed's:
//!
//! ```text
//! cargo xtask dns-verify diff
//! DNS_VECTORS=target/dns-verify/vectors/1 cargo test --test dns_vectors -- --nocapture
//! ```
//!
//! Each test reads one kind of vector, runs the Rust code on every case,
//! and fails listing the cases where Rust and Lean disagree. Each prints
//! how many cases it read, and how many it could not compare whole and
//! why. The Lean definitions behind each kind are listed in
//! `verification/dns/lean/README.md`. What each test compares, and what it
//! leaves out where the Lean model does not describe what Rust does, is
//! said at the test and in `verification/dns/README.md`.
//!
//! Signatures in `signed.json` and `chain.json` are symbolic: a key is a
//! number, and a signature is the private key with the message it signs
//! (Lean's `Dnssec.Symbolic.scheme`). [`Symbolic`] signs that way through
//! the Rust [`Sign`] trait and [`Oracle`] checks such signatures through
//! the Rust [`Verify`] trait, so the Rust signer and validator run
//! unchanged. A second test signs the same zones with real keys and
//! checks them with [`Ring`], which ties the symbolic scheme to real
//! cryptography.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::layer::Budget;
use fictionet::stdlib::network::Transport;
use fictionet::stdlib::protocols::dns::dnssec::rdata::{DNSKEY, DNSSECRData, DS, RRSIG};
use fictionet::stdlib::protocols::dns::dnssec::{
    AlgorithmPolicy, Anchors, Chain, DigestType, Fetched, Insecure, KeyFlags, KeySet, Link,
    PublicKey, PublicKeyBuf, Ring, Sign, Treatment, Validation, Verify, Window, ZoneKey, ds,
    key_tag, signed_data, validate_denial, validate_rrset,
};
use fictionet::stdlib::protocols::dns::op::{
    Edns, Header, Message, MessageType, OpCode, Query, ResponseCode,
};
use fictionet::stdlib::protocols::dns::rr::{
    DNSClass, LowerName, Name, RData, Record, RecordSet, RecordType,
};
use fictionet::stdlib::protocols::dns::serialize::binary::{
    BinDecodable, BinDecoder, BinEncodable, BinEncoder, NameEncoding,
};
use fictionet::stdlib::protocols::dns::{Limit, Parsed, Request, Response, fit, read_message};
use fictionet::stdlib::protocols::json::Value;
use fictionet::stdlib::services::dns::authority::{
    AuthorityEngine, ServerConfig, Zones, bare_reply,
};
use fictionet::stdlib::services::dns::memory::{MemoryNet, drive};
use fictionet::stdlib::services::dns::resolver::{
    Cache, Checked, Config, Entry, FailureKind, Key, Limits, Negative, Offer, Rank, Resolver, Work,
};
use fictionet::stdlib::services::dns::zone::{
    Answered, AnyResponse, Denial, Denied, Fact, Node, Revision, View, Zone, ZoneData, ZoneError,
    answer, check_chain,
};
use fictionet::stdlib::services::dns::{Client, ClientQuery, WallClock};
use fictionet::time::Instant;
use fictionet::{Seed, SeededEntropy};
use fictionet_extras::dns::unbound;

// ---------------------------------------------------------------------
// Reading the vectors
// ---------------------------------------------------------------------

/// The cases of one kind: `$DNS_VECTORS/<kind>.json`.
fn vectors(kind: &str) -> Value {
    let dir = std::env::var_os("DNS_VECTORS")
        .expect("DNS_VECTORS names the directory `cargo xtask dns-verify vectors` writes");
    let path = PathBuf::from(dir).join(format!("{kind}.json"));
    let text = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    Value::parse(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn field<'a>(value: &'a Value, key: &str) -> &'a Value {
    value
        .get(key)
        .unwrap_or_else(|| panic!("a vector has no field {key:?}"))
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    field(value, key)
        .as_str()
        .unwrap_or_else(|| panic!("{key:?} is not a string"))
}

fn number(value: &Value, key: &str) -> u64 {
    field(value, key)
        .as_u64()
        .unwrap_or_else(|| panic!("{key:?} is not a number"))
}

fn flag(value: &Value, key: &str) -> bool {
    field(value, key)
        .as_bool()
        .unwrap_or_else(|| panic!("{key:?} is not a boolean"))
}

fn list<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    field(value, key)
        .as_array()
        .unwrap_or_else(|| panic!("{key:?} is not an array"))
}

fn texts(value: &Value, key: &str) -> Vec<String> {
    list(value, key)
        .iter()
        .map(|line| line.as_str().expect("an array of strings").to_string())
        .collect()
}

/// Runs `check` on every case of `kind` and fails listing the cases where
/// Rust and Lean disagree. `check` notes in the [`Tally`] each case it
/// could not compare whole, and why: where the Lean model leaves out what
/// Rust does, or a standard lets the two differ. The notes are printed
/// with the count of cases.
fn each_case(kind: &str, mut check: impl FnMut(&Value, &mut Tally) -> Result<(), String>) {
    let cases = vectors(kind);
    let cases = cases
        .as_array()
        .expect("a vector file is an array of cases");
    let mut tally = Tally::default();
    let mut failures = Vec::new();
    for (index, case) in cases.iter().enumerate() {
        if let Err(why) = check(case, &mut tally) {
            failures.push(format!("case {index}: {why}"));
        }
    }
    let notes: Vec<String> = tally
        .notes
        .iter()
        .map(|(why, count)| format!("{count} {why}"))
        .collect();
    eprintln!(
        "{kind}: {} cases, {} disagree{}",
        cases.len(),
        failures.len(),
        if notes.is_empty() {
            String::new()
        } else {
            format!("; noted: {}", notes.join("; "))
        }
    );
    if !failures.is_empty() {
        let shown: Vec<&String> = failures.iter().take(12).collect();
        panic!(
            "{} of {} {kind} cases disagree with the Lean model:\n{}",
            failures.len(),
            cases.len(),
            shown
                .iter()
                .map(|f| f.as_str())
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
}

/// The cases a test could not compare whole, by reason.
#[derive(Default)]
struct Tally {
    notes: BTreeMap<&'static str, usize>,
}

impl Tally {
    fn note(&mut self, why: &'static str) {
        *self.notes.entry(why).or_default() += 1;
    }
}

/// `Ok` when `lean` and `rust` are equal, else the difference.
fn same<T: PartialEq + std::fmt::Debug>(what: &str, lean: T, rust: T) -> Result<(), String> {
    if lean == rust {
        Ok(())
    } else {
        Err(format!("{what}: Lean {lean:?}, Rust {rust:?}"))
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("lowercase hex"))
        .collect()
}

// ---------------------------------------------------------------------
// Names and records in the vectors' presentation form
// ---------------------------------------------------------------------

/// The labels of a name as the vectors write it, with a trailing dot:
/// `\DDD` is the octet with decimal value DDD and `\X` is X
/// (RFC 1035 §5.1).
///
/// hickory's own text parser reads `\DDD` as octal, so names go through
/// this reader and [`Name::from_labels`].
fn labels(text: &str) -> Vec<Vec<u8>> {
    if text == "." {
        return Vec::new();
    }
    let bytes = text.as_bytes();
    let mut labels = Vec::new();
    let mut label = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' if bytes.get(i + 1).is_some_and(u8::is_ascii_digit) => {
                let digits = std::str::from_utf8(&bytes[i + 1..i + 4]).expect("ASCII digits");
                label.push(digits.parse().expect("an octet in decimal"));
                i += 4;
            }
            b'\\' => {
                label.push(bytes[i + 1]);
                i += 2;
            }
            b'.' => {
                labels.push(std::mem::take(&mut label));
                i += 1;
            }
            octet => {
                label.push(octet);
                i += 1;
            }
        }
    }
    assert!(
        label.is_empty(),
        "{text}: names in the vectors end with a dot"
    );
    labels
}

fn name(text: &str) -> Name {
    Name::from_labels(labels(text)).unwrap_or_else(|e| panic!("{text}: {e}"))
}

/// Octets that stand for themselves in a label, as `Gen.lean` writes
/// names. Every other octet is `\DDD`.
fn plain(octet: u8) -> bool {
    octet.is_ascii_alphanumeric() || matches!(octet, b'-' | b'_' | b'*')
}

fn labels_text(labels: &[Vec<u8>]) -> String {
    if labels.is_empty() {
        return ".".to_string();
    }
    let mut out = String::new();
    for label in labels {
        for &octet in label {
            if plain(octet) {
                out.push(char::from(octet));
            } else {
                let _ = write!(out, "\\{octet:03}");
            }
        }
        out.push('.');
    }
    out
}

fn name_text(name: &Name) -> String {
    let labels: Vec<Vec<u8>> = name.iter().map(<[u8]>::to_vec).collect();
    labels_text(&labels)
}

fn type_text(code: u16) -> String {
    let known = match code {
        1 => "A",
        2 => "NS",
        3 => "MD",
        4 => "MF",
        5 => "CNAME",
        6 => "SOA",
        7 => "MB",
        8 => "MG",
        9 => "MR",
        12 => "PTR",
        13 => "HINFO",
        14 => "MINFO",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        39 => "DNAME",
        41 => "OPT",
        43 => "DS",
        46 => "RRSIG",
        47 => "NSEC",
        48 => "DNSKEY",
        50 => "NSEC3",
        251 => "IXFR",
        252 => "AXFR",
        253 => "MAILB",
        254 => "MAILA",
        255 => "ANY",
        _ => return format!("TYPE{code}"),
    };
    known.to_string()
}

fn type_code(text: &str) -> u16 {
    if let Some(number) = text.strip_prefix("TYPE") {
        return number.parse().expect("TYPE<number>");
    }
    (0..=u16::MAX)
        .find(|&code| type_text(code) == text)
        .unwrap_or_else(|| panic!("unknown type {text}"))
}

fn class_text(code: u16) -> String {
    match code {
        1 => "IN".to_string(),
        3 => "CH".to_string(),
        4 => "HS".to_string(),
        254 => "NONE".to_string(),
        255 => "ANY".to_string(),
        _ => format!("CLASS{code}"),
    }
}

fn class_code(text: &str) -> u16 {
    match text {
        "IN" => 1,
        "CH" => 3,
        "HS" => 4,
        "NONE" => 254,
        "ANY" => 255,
        _ => text
            .strip_prefix("CLASS")
            .and_then(|n| n.parse().ok())
            .unwrap_or_else(|| panic!("unknown class {text}")),
    }
}

/// The tokens of a presentation line: blank-separated, with quoted
/// character strings kept whole.
fn tokens(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut token = String::new();
    let mut quoted = false;
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                token.push(c);
                if let Some(next) = chars.next() {
                    token.push(next);
                }
            }
            '"' => {
                token.push(c);
                quoted = !quoted;
            }
            ' ' if !quoted => {
                if !token.is_empty() {
                    out.push(std::mem::take(&mut token));
                }
            }
            _ => token.push(c),
        }
    }
    if !token.is_empty() {
        out.push(token);
    }
    out
}

fn name_wire(labels: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for label in labels {
        out.push(u8::try_from(label.len()).expect("a label is at most 63 octets"));
        out.extend_from_slice(label);
    }
    out.push(0);
    out
}

/// A quoted character string as wire octets with its length first.
fn character_string(token: &str) -> Vec<u8> {
    let inner = token
        .strip_prefix('"')
        .and_then(|t| t.strip_suffix('"'))
        .expect("a quoted character string");
    let bytes = inner.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && bytes.get(i + 1).is_some_and(u8::is_ascii_digit) {
            let digits = std::str::from_utf8(&bytes[i + 1..i + 4]).expect("ASCII digits");
            out.push(digits.parse().expect("an octet in decimal"));
            i += 4;
        } else if bytes[i] == b'\\' {
            out.push(bytes[i + 1]);
            i += 2;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    let mut string = vec![u8::try_from(out.len()).expect("a character string is short")];
    string.extend(out);
    string
}

/// The RDATA octets of a record of type `rtype` written in the forms
/// `Gen.lean` uses.
fn rdata_octets(rtype: u16, fields: &[String]) -> Vec<u8> {
    let num = |i: usize| -> u64 { fields[i].parse().expect("a number") };
    if fields.first().is_some_and(|f| f == "\\#") {
        let length: usize = fields[1].parse().expect("an RDATA length");
        let octets = fields.get(2).map_or_else(Vec::new, |h| unhex(h));
        assert_eq!(octets.len(), length, "the RFC 3597 length");
        return octets;
    }
    let mut out = Vec::new();
    match rtype {
        1 => {
            for part in fields[0].split('.') {
                out.push(part.parse().expect("an IPv4 octet"));
            }
        }
        28 => {
            let addr: std::net::Ipv6Addr = fields[0].parse().expect("an IPv6 address");
            out.extend_from_slice(&addr.octets());
        }
        2 | 3 | 4 | 5 | 7 | 8 | 9 | 12 | 39 => out = name_wire(&labels(&fields[0])),
        14 => {
            out = name_wire(&labels(&fields[0]));
            out.extend(name_wire(&labels(&fields[1])));
        }
        15 => {
            out.extend_from_slice(&(num(0) as u16).to_be_bytes());
            out.extend(name_wire(&labels(&fields[1])));
        }
        6 => {
            out = name_wire(&labels(&fields[0]));
            out.extend(name_wire(&labels(&fields[1])));
            for i in 2..7 {
                out.extend_from_slice(&(num(i) as u32).to_be_bytes());
            }
        }
        33 => {
            for i in 0..3 {
                out.extend_from_slice(&(num(i) as u16).to_be_bytes());
            }
            out.extend(name_wire(&labels(&fields[3])));
        }
        13 | 16 => {
            for field in fields {
                out.extend(character_string(field));
            }
        }
        43 => {
            out.extend_from_slice(&(num(0) as u16).to_be_bytes());
            out.push(num(1) as u8);
            out.push(num(2) as u8);
            out.extend(unhex(&fields[3]));
        }
        _ => panic!("no presentation form for type {rtype}: {fields:?}"),
    }
    out
}

/// A record from one presentation line, read through hickory's own
/// decoder from the record's wire form, or hickory's reason for refusing
/// it.
fn try_record(line: &str) -> Result<Record, String> {
    let tokens = tokens(line);
    let rtype = type_code(&tokens[3]);
    let rdata = rdata_octets(rtype, &tokens[4..]);
    let mut wire = name_wire(&labels(&tokens[0]));
    wire.extend_from_slice(&rtype.to_be_bytes());
    wire.extend_from_slice(&class_code(&tokens[2]).to_be_bytes());
    wire.extend_from_slice(&tokens[1].parse::<u32>().expect("a TTL").to_be_bytes());
    wire.extend_from_slice(&u16::try_from(rdata.len()).unwrap().to_be_bytes());
    wire.extend(rdata);
    Record::read(&mut BinDecoder::new(&wire)).map_err(|e| format!("{line}: {e}"))
}

fn record(line: &str) -> Record {
    try_record(line).unwrap_or_else(|e| panic!("{e}"))
}

/// Whether hickory refuses the record of `line` inside a message: one it
/// cannot read alone.
fn refused_in_messages(line: &str) -> bool {
    try_record(line).is_err()
}

/// The name at `start` in a whole message, following compression pointers
/// that point backwards: its labels and where the name ends.
fn wire_name(bytes: &[u8], start: usize) -> Option<(Vec<Vec<u8>>, usize)> {
    let mut labels = Vec::new();
    let mut at = start;
    let mut end = None;
    loop {
        let length = usize::from(*bytes.get(at)?);
        match length {
            0 => return Some((labels, end.unwrap_or(at + 1))),
            1..=63 => {
                labels.push(bytes.get(at + 1..at + 1 + length)?.to_vec());
                at += 1 + length;
            }
            0xc0.. => {
                let pointer = (length & 0x3f) << 8 | usize::from(*bytes.get(at + 1)?);
                if pointer >= at {
                    return None;
                }
                end.get_or_insert(at + 2);
                at = pointer;
            }
            _ => return None,
        }
    }
}

/// The owner, in lowercase, and the type of each record of one section.
type SectionKeys = Vec<(String, u16)>;

/// The owner and type of every record in the answer, authority, and
/// additional sections of a message, and its TC bit, read without
/// hickory, so that records with empty RDATA count too.
fn record_keys(bytes: &[u8]) -> Option<(bool, [SectionKeys; 3])> {
    let count = |i: usize| usize::from(u16::from_be_bytes([bytes[i], bytes[i + 1]]));
    let mut at = 12;
    for _ in 0..count(4) {
        at = wire_name(bytes, at)?.1 + 4;
    }
    let mut sections: [SectionKeys; 3] = Default::default();
    for (section, count) in sections.iter_mut().zip([count(6), count(8), count(10)]) {
        for _ in 0..count {
            let (owner, end) = wire_name(bytes, at)?;
            let rtype = u16::from_be_bytes([*bytes.get(end)?, *bytes.get(end + 1)?]);
            let length = usize::from(u16::from_be_bytes([
                *bytes.get(end + 8)?,
                *bytes.get(end + 9)?,
            ]));
            section.push((labels_text(&owner).to_ascii_lowercase(), rtype));
            at = end + 10 + length;
        }
    }
    Some((bytes[2] & 0x02 != 0, sections))
}

/// A record's RDATA as uncompressed wire octets, in the case it has.
fn rdata_of(record: &Record) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut encoder = BinEncoder::new(&mut bytes);
    encoder.set_name_encoding(NameEncoding::Uncompressed);
    record
        .data
        .emit(&mut encoder)
        .unwrap_or_else(|e| panic!("{record}: {e}"));
    bytes
}

/// Reads RDATA octets field by field.
struct Fields<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Fields<'_> {
    fn u8(&mut self) -> u8 {
        self.at += 1;
        self.bytes[self.at - 1]
    }

    fn u16(&mut self) -> u16 {
        self.at += 2;
        u16::from_be_bytes([self.bytes[self.at - 2], self.bytes[self.at - 1]])
    }

    fn u32(&mut self) -> u32 {
        self.at += 4;
        u32::from_be_bytes(self.bytes[self.at - 4..self.at].try_into().unwrap())
    }

    fn take(&mut self, n: usize) -> &[u8] {
        self.at += n;
        &self.bytes[self.at - n..self.at]
    }

    fn rest(&mut self) -> &[u8] {
        let rest = &self.bytes[self.at..];
        self.at = self.bytes.len();
        rest
    }

    fn done(&self) -> bool {
        self.at >= self.bytes.len()
    }

    /// An uncompressed name, as text.
    fn name(&mut self) -> String {
        let mut labels = Vec::new();
        loop {
            let length = usize::from(self.u8());
            if length == 0 {
                return labels_text(&labels);
            }
            labels.push(self.take(length).to_vec());
        }
    }

    fn character_string(&mut self) -> String {
        let length = usize::from(self.u8());
        let mut out = String::from("\"");
        for &octet in self.take(length) {
            if octet == b'"' || octet == b'\\' {
                out.push('\\');
                out.push(char::from(octet));
            } else if (32..=126).contains(&octet) {
                out.push(char::from(octet));
            } else {
                let _ = write!(out, "\\{octet:03}");
            }
        }
        out.push('"');
        out
    }

    /// An NSEC or NSEC3 type bitmap (RFC 4034 §4.1.2), as type names in
    /// numeric order.
    fn bitmap(&mut self) -> Vec<String> {
        let mut types = Vec::new();
        while !self.done() {
            let window = u16::from(self.u8());
            let length = usize::from(self.u8());
            for (i, &octet) in self.take(length).iter().enumerate() {
                for bit in 0..8 {
                    if octet & (0x80 >> bit) != 0 {
                        types.push(type_text(window * 256 + (i as u16) * 8 + bit));
                    }
                }
            }
        }
        types
    }
}

fn generic(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        "\\# 0".to_string()
    } else {
        format!("\\# {} {}", bytes.len(), hex(bytes))
    }
}

fn dotted(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(".")
}

/// An IPv6 address as `Gen.lean` writes it: eight groups of lowercase hex
/// without leading zeros, and no `::`.
fn groups(bytes: &[u8]) -> String {
    bytes
        .chunks(2)
        .map(|pair| format!("{:x}", u16::from_be_bytes([pair[0], pair[1]])))
        .collect::<Vec<_>>()
        .join(":")
}

fn base64(bytes: &[u8]) -> String {
    const DIGITS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, &b)| n | u32::from(b) << (16 - 8 * i));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(DIGITS[(n >> (18 - 6 * i) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// A 160-bit NSEC3 hash in lowercase base32hex (RFC 4648 §7).
fn base32hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8] = b"0123456789abcdefghijklmnopqrstuv";
    let mut out = String::new();
    let mut buffer = 0u64;
    let mut bits = 0;
    for &octet in bytes {
        buffer = buffer << 8 | u64::from(octet);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(DIGITS[(buffer >> bits & 31) as usize]));
        }
    }
    out
}

/// How a record's RDATA is written: as `Gen.lean` writes records of the
/// wire codec, or records of zones.
#[derive(Clone, Copy)]
enum Form<'a> {
    /// `Wire.RData`: A and AAAA as addresses, the RFC 1035 name types with
    /// their names, everything else as RFC 3597 octets.
    Wire,
    /// `Zone.RData` and the DNSSEC records of `signed.json`. RRSIG key
    /// tags are written as the symbolic key they belong to, through
    /// `tags`.
    Zone(&'a BTreeMap<u16, u16>),
}

fn rdata_text(rtype: u16, bytes: &[u8], form: Form<'_>) -> String {
    let mut f = Fields { bytes, at: 0 };
    match form {
        Form::Wire => match rtype {
            1 if bytes.len() == 4 => dotted(bytes),
            28 if bytes.len() == 16 => groups(bytes),
            15 => {
                let preference = f.u16();
                format!("{preference} {}", f.name())
            }
            6 => {
                let names = [f.name(), f.name()];
                let numbers: Vec<String> = (0..5).map(|_| f.u32().to_string()).collect();
                format!("{} {}", names.join(" "), numbers.join(" "))
            }
            2 | 3 | 4 | 5 | 7 | 8 | 9 | 12 => f.name(),
            14 => format!("{} {}", f.name(), f.name()),
            _ => generic(bytes),
        },
        Form::Zone(tags) => match rtype {
            1 => dotted(bytes),
            28 => groups(bytes),
            2 | 5 | 12 | 39 => f.name(),
            15 => {
                let preference = f.u16();
                format!("{preference} {}", f.name())
            }
            33 => {
                let (priority, weight, port) = (f.u16(), f.u16(), f.u16());
                format!("{priority} {weight} {port} {}", f.name())
            }
            13 | 16 => {
                let mut strings = Vec::new();
                while !f.done() {
                    strings.push(f.character_string());
                }
                strings.join(" ")
            }
            6 => {
                let names = [f.name(), f.name()];
                let numbers: Vec<String> = (0..5).map(|_| f.u32().to_string()).collect();
                format!("{} {}", names.join(" "), numbers.join(" "))
            }
            43 => {
                let (tag, algorithm, digest) = (f.u16(), f.u8(), f.u8());
                format!("{tag} {algorithm} {digest} {}", hex(f.rest()))
            }
            48 => {
                let (flags, protocol, algorithm) = (f.u16(), f.u8(), f.u8());
                format!("{flags} {protocol} {algorithm} {}", base64(f.rest()))
            }
            46 => {
                let covered = type_text(f.u16());
                let (algorithm, labels) = (f.u8(), f.u8());
                let (ttl, expiration, inception) = (f.u32(), f.u32(), f.u32());
                let tag = f.u16();
                let tag = tags.get(&tag).copied().unwrap_or(tag);
                let signer = f.name();
                // A symbolic signature starts with the private key as two
                // octets; Lean writes those two.
                let signature = f.rest();
                let private = &signature[..signature.len().min(2)];
                format!(
                    "{covered} {algorithm} {labels} {ttl} {expiration} {inception} {tag} {signer} {}",
                    base64(private)
                )
            }
            47 => {
                let next = f.name();
                format!("{next} {}", f.bitmap().join(" "))
            }
            50 => {
                let (_algorithm, flags, iterations) = (f.u8(), f.u8(), f.u16());
                let salt_length = usize::from(f.u8());
                let salt = hex(f.take(salt_length));
                let salt = if salt.is_empty() {
                    "-".to_string()
                } else {
                    salt
                };
                let hash_length = usize::from(f.u8());
                let next = base32hex(f.take(hash_length));
                let types = f.bitmap();
                let mut line = format!("1 {flags} {iterations} {salt} {next}");
                if !types.is_empty() {
                    line.push(' ');
                    line.push_str(&types.join(" "));
                }
                line
            }
            _ => generic(bytes),
        },
    }
}

/// A record as one presentation line in `form`. Zone records are always
/// in class IN, as `Gen.lean` writes them.
fn line(record: &Record, form: Form<'_>) -> String {
    let rtype = u16::from(record.record_type());
    let class = match form {
        Form::Wire => class_text(u16::from(record.dns_class)),
        Form::Zone(_) => "IN".to_string(),
    };
    format!(
        "{} {} {class} {} {}",
        name_text(&record.name),
        record.ttl,
        type_text(rtype),
        rdata_text(rtype, &rdata_of(record), form)
    )
}

/// Zone-form lines with no symbolic keys.
fn zone_line(record: &Record) -> String {
    line(record, Form::Zone(&BTreeMap::new()))
}

/// The owner and type of a presentation line; an RRSIG line counts under
/// the type it covers.
fn rrset_key(line: &str) -> (String, String) {
    let tokens = tokens(line);
    let rtype = if tokens[3] == "RRSIG" {
        tokens[4].clone()
    } else {
        tokens[3].clone()
    };
    (tokens[0].to_ascii_lowercase(), rtype)
}

/// Lines grouped into RRsets in order of first appearance, each RRset's
/// lines sorted, for comparing sections whose RRset and record order
/// RFC 1035 gives no meaning.
fn rrsets_of(lines: &[String]) -> Vec<((String, String), BTreeSet<String>)> {
    let mut sets: Vec<((String, String), BTreeSet<String>)> = Vec::new();
    for line in lines {
        let key = rrset_key(line);
        match sets.iter_mut().find(|(k, _)| *k == key) {
            Some((_, set)) => {
                set.insert(line.clone());
            }
            None => sets.push((key, BTreeSet::from([line.clone()]))),
        }
    }
    sets
}

/// A section's lines as a set of RRsets.
fn section(lines: &[String]) -> BTreeSet<BTreeSet<String>> {
    rrsets_of(lines).into_iter().map(|(_, set)| set).collect()
}

/// An additional section split at `required` RRsets: the RRsets a reply
/// needs and the optional rest, each as a set.
fn additional(
    lines: &[String],
    required: usize,
) -> (BTreeSet<BTreeSet<String>>, BTreeSet<BTreeSet<String>>) {
    let sets = rrsets_of(lines);
    let required = required.min(sets.len());
    let (needed, rest) = sets.split_at(required);
    (
        needed.iter().map(|(_, s)| s.clone()).collect(),
        rest.iter().map(|(_, s)| s.clone()).collect(),
    )
}

fn rcode_text(rcode: ResponseCode) -> String {
    match rcode {
        ResponseCode::NoError => "NOERROR".to_string(),
        ResponseCode::NXDomain => "NXDOMAIN".to_string(),
        ResponseCode::YXDomain => "YXDOMAIN".to_string(),
        ResponseCode::Refused => "REFUSED".to_string(),
        ResponseCode::ServFail => "SERVFAIL".to_string(),
        other => format!("{other:?}"),
    }
}

/// What a server sends for QTYPE ANY, as `input`'s `any` field says,
/// with the HINFO TTL in `hinfo_ttl`.
fn any_response(input: &Value) -> AnyResponse {
    match text(input, "any") {
        "hinfo" => AnyResponse::Hinfo {
            ttl: u32::try_from(number(input, "hinfo_ttl")).expect("a TTL"),
        },
        // The model sends the name's first RRset; the preferred type only
        // decides which one Rust sends (see `compare_answer`).
        "one_rrset" => AnyResponse::OneRrset(RecordType::SOA),
        "all" => AnyResponse::All,
        other => panic!("unknown ANY response {other}"),
    }
}

/// The request a server sees for `qname` and `qtype` over UDP, with
/// DNSSEC records asked for when `dnssec_ok`.
fn request(qname: &Name, qtype: RecordType, dnssec_ok: bool) -> Request {
    let mut message = Message::new(4660, MessageType::Query, OpCode::Query);
    message.add_query(Query::query(qname.clone(), qtype));
    if dnssec_ok {
        let mut edns = Edns::new();
        edns.set_max_payload(1232).set_dnssec_ok(true);
        message.set_edns(edns);
    }
    match Request::parse(&message.to_vec().unwrap(), Transport::Udp) {
        Parsed::Request(request) => request,
        other => panic!("a well-formed query is a request: {other:?}"),
    }
}

/// The request a vector gives as `qname` and `qtype`.
fn vector_request(value: &Value, dnssec_ok: bool) -> Request {
    let qname = name(text(value, "qname"));
    let qtype = RecordType::from(type_code(text(value, "qtype")));
    request(&qname, qtype, dnssec_ok)
}

/// Checks that Rust's builder refuses a vector's `zone` for the rule the
/// Lean builder names first, as `Gen.lean`'s `zoneErrorStr` writes it.
fn refused(value: &Value, rule: &str) -> Result<(), String> {
    let lines = texts(value, "records");
    let error = match Zone::from_master(&lines.join("\n"), None) {
        Ok(_) => return Err(format!("Rust builds a zone Lean refuses for {rule}")),
        Err(error) => error,
    };
    let rust = match &error {
        ZoneError::OutOfZone { .. } => "out_of_zone",
        ZoneError::CnameWithOtherData { .. } => "cname_with_other_data",
        ZoneError::CnameAtApex => "cname_at_apex",
        ZoneError::TwoDnames { .. } => "two_dnames",
        ZoneError::DataBelowDname { .. } => "data_below_dname",
        ZoneError::DataBelowCut { .. } => "data_below_cut",
        ZoneError::DsNotAtCut { .. } => "ds_not_at_cut",
        ZoneError::MissingInDomainGlue { .. } => "missing_in_domain_glue",
        ZoneError::TargetIsAlias { .. } => "target_is_alias",
        ZoneError::RrsetTtlsDiffer { .. } => "rrset_ttls_differ",
        ZoneError::TtlTooLarge { .. } => "ttl_too_large",
        ZoneError::MissingApexNs => "missing_apex_ns",
        other => return Err(format!("Lean refuses for {rule}, Rust for {other}")),
    };
    same("the rule broken first", rule.to_string(), rust.to_string())
}

/// A zone from a vector's `zone`: master file lines, read with
/// [`Zone::from_master`].
fn vector_zone(value: &Value) -> Result<Zone, String> {
    let lines = texts(value, "records");
    Zone::from_master(&lines.join("\n"), None).map_err(|e| format!("the zone does not build: {e}"))
}

/// What `Gen.lean` writes for a response (`responseJson`), from the Rust
/// one: lines of every section and the count of required additional
/// RRsets.
fn compare_response(expected: &Value, response: &Response) -> Result<(), String> {
    let message = &response.message;
    let lines = |records: &[Record]| -> Vec<String> { records.iter().map(zone_line).collect() };
    same(
        "rcode",
        text(expected, "rcode").to_string(),
        rcode_text(message.metadata.response_code),
    )?;
    same("aa", flag(expected, "aa"), message.metadata.authoritative)?;
    same(
        "answer",
        section(&texts(expected, "answer")),
        section(&lines(&message.answers)),
    )?;
    same(
        "authority",
        section(&texts(expected, "authority")),
        section(&lines(&message.authorities)),
    )?;
    let required = number(expected, "required_additional") as usize;
    same(
        "required additional RRsets",
        required,
        response.required_additional,
    )?;
    same(
        "additional",
        additional(&texts(expected, "additional"), required),
        additional(&lines(&message.additionals), response.required_additional),
    )
}

// ---------------------------------------------------------------------
// names.json: LowerName order and folding, and wire length
// ---------------------------------------------------------------------

#[test]
fn names() {
    each_case("names", |case, _| {
        let input = field(case, "input");
        let expected = field(case, "expected");
        let a = name(text(input, "a"));
        let b = name(text(input, "b"));
        let (lower_a, lower_b) = (LowerName::new(&a), LowerName::new(&b));
        let cmp = match lower_a.cmp(&lower_b) {
            std::cmp::Ordering::Less => -1,
            std::cmp::Ordering::Equal => 0,
            std::cmp::Ordering::Greater => 1,
        };
        same("cmp", field(expected, "cmp").as_i64().unwrap(), cmp)?;
        same("eq_ci", flag(expected, "eq_ci"), lower_a == lower_b)?;
        same("eq_ci of Name", flag(expected, "eq_ci"), a == b)?;
        same(
            "folding",
            flag(expected, "eq_ci"),
            a.to_lowercase().eq_case(&b.to_lowercase()),
        )?;
        let lengths: Vec<u64> = list(expected, "wire_len")
            .iter()
            .map(|n| n.as_u64().unwrap())
            .collect();
        let wire = |n: &Name| n.to_bytes().unwrap().len() as u64;
        same("wire_len", lengths, vec![wire(&a), wire(&b)])
    });
}

// ---------------------------------------------------------------------
// wire.json: hickory's decoder and encoder
// ---------------------------------------------------------------------

/// hickory keeps no field for the reserved Z bit (RFC 1035 §4.1.1), so
/// flags are compared without it.
const Z: u16 = 0x0040;

fn flags_of(message: &Message) -> u16 {
    let mut bytes = Vec::new();
    Header {
        metadata: message.metadata,
        counts: Default::default(),
    }
    .emit(&mut BinEncoder::new(&mut bytes))
    .unwrap();
    u16::from_be_bytes([bytes[2], bytes[3]])
}

fn question_line(query: &Query) -> String {
    format!(
        "{} {} {}",
        name_text(query.name()),
        class_text(u16::from(query.query_class())),
        type_text(u16::from(query.query_type()))
    )
}

/// Where in `bytes` hickory's reader first fails on a record, counting the
/// records of the answer, authority, and additional sections in turn, or
/// `None` when the header or a question fails or every record reads.
fn first_refused_record(bytes: &[u8]) -> Option<usize> {
    let mut decoder = BinDecoder::new(bytes);
    let header = Header::read(&mut decoder).ok()?;
    for _ in 0..header.counts.queries {
        Query::read(&mut decoder).ok()?;
    }
    let counts = header.counts;
    let records = usize::from(counts.answers)
        + usize::from(counts.authorities)
        + usize::from(counts.additionals);
    (0..records).find(|_| Record::read(&mut decoder).is_err())
}

/// The records of a message's additional section, with the OPT record
/// hickory moves into `edns` put back.
fn additionals_with_opt(message: &Message) -> Vec<Record> {
    let mut records = message.additionals.clone();
    if let Some(edns) = &message.edns {
        records.push(Record::from(edns));
    }
    records
}

#[test]
fn wire() {
    each_case("wire", |case, tally| {
        let bytes = unhex(text(field(case, "input"), "bytes"));
        let expected = field(case, "expected");
        // The decoder the engines read replies with, which takes empty
        // RDATA of any type (RFC 3597 §4).
        let decoded = read_message(&bytes);
        match (flag(expected, "ok"), decoded) {
            (true, Ok(message)) => {
                let lean = field(expected, "message");
                let header = field(lean, "header");
                same("id", number(header, "id"), u64::from(message.metadata.id))?;
                same(
                    "flags",
                    number(header, "flags") as u16 & !Z,
                    flags_of(&message),
                )?;
                let lines = |records: &[Record]| -> Vec<String> {
                    records.iter().map(|r| line(r, Form::Wire)).collect()
                };
                same(
                    "question",
                    texts(lean, "question"),
                    message.queries.iter().map(question_line).collect(),
                )?;
                same("answer", texts(lean, "answer"), lines(&message.answers))?;
                same(
                    "authority",
                    texts(lean, "authority"),
                    lines(&message.authorities),
                )?;
                same(
                    "additional",
                    texts(lean, "additional"),
                    lines(&additionals_with_opt(&message)),
                )?;
                let mut canonical = Vec::new();
                let mut encoder = BinEncoder::new(&mut canonical);
                encoder.set_name_encoding(NameEncoding::Uncompressed);
                message.emit(&mut encoder).map_err(|e| e.to_string())?;
                let mut lean_canonical = unhex(text(expected, "canonical"));
                lean_canonical[3] &= !(Z as u8);
                same("canonical octets", hex(&lean_canonical), hex(&canonical))
            }
            (false, Err(_)) => Ok(()),
            (true, Err(error)) => {
                // hickory reads the RDATA of every type it knows by that
                // type's rules; the Lean codec carries every type but the
                // RFC 1035 name types as octets (RFC 3597). Such a message
                // agrees when the first record hickory fails on is one
                // hickory refuses on its own.
                let lean = field(expected, "message");
                let lines: Vec<String> = ["answer", "authority", "additional"]
                    .iter()
                    .flat_map(|s| texts(lean, s))
                    .collect();
                let rejected = first_refused_record(&bytes)
                    .and_then(|index| lines.get(index))
                    .is_some_and(|line| refused_in_messages(line));
                if rejected {
                    tally.note("messages with a record hickory refuses");
                    Ok(())
                } else {
                    Err(format!("Lean decodes it, hickory does not: {error}"))
                }
            }
            (false, Ok(message)) => Err(format!(
                "Lean rejects it ({}), hickory decodes {message:?}",
                text(expected, "error")
            )),
        }
    });
}

// ---------------------------------------------------------------------
// respond.json: Request::parse, the rejection header, and the server front
// ---------------------------------------------------------------------

#[test]
fn respond() {
    each_case("respond", |case, _| {
        let input = field(case, "input");
        let expected = field(case, "expected");
        let bytes = unhex(text(input, "bytes"));
        let transport = match text(input, "transport") {
            "udp" => Transport::Udp,
            _ => Transport::Tcp,
        };
        let parsed = Request::parse(&bytes, transport);
        match (text(expected, "parsed"), parsed) {
            ("silent", Parsed::Silent) => Ok(()),
            ("reject", Parsed::Reject(reply)) => {
                let rcode = u16::from(reply.metadata.response_code);
                same("rcode", number(expected, "rcode") as u16, rcode)?;
                let flags = field(expected, "flags");
                let m = &reply.metadata;
                let rust = [
                    ("qr", m.message_type == MessageType::Response),
                    ("aa", m.authoritative),
                    ("tc", m.truncation),
                    ("rd", m.recursion_desired),
                    ("ra", m.recursion_available),
                    ("ad", m.authentic_data),
                    ("cd", m.checking_disabled),
                ];
                for (bit, value) in rust {
                    same(bit, flag(flags, bit), value)?;
                }
                same("opcode", number(flags, "opcode") as u8, u8::from(m.op_code))?;
                same(
                    "header rcode",
                    number(flags, "rcode") as u16,
                    u16::from(m.response_code.low()),
                )?;
                same("z", flag(flags, "z"), flags_of(&reply) & Z != 0)?;
                let opt = field(expected, "opt");
                let lean_opt = if opt.is_null() {
                    None
                } else {
                    Some(number(opt, "version") as u8)
                };
                same("OPT", lean_opt, reply.edns.as_ref().map(Edns::version))
            }
            ("request", Parsed::Request(request)) => {
                same("rd", flag(expected, "rd"), request.rd)?;
                same("cd", flag(expected, "cd"), request.cd)?;
                same("ad", flag(expected, "ad"), request.ad)?;
                same(
                    "question",
                    text(expected, "question").to_string(),
                    question_line(&request.question),
                )?;
                let edns = field(expected, "edns");
                let lean = (!edns.is_null()).then(|| {
                    (
                        number(edns, "payload") as u16,
                        number(edns, "version") as u8,
                        flag(edns, "do"),
                        flag(edns, "nsid"),
                    )
                });
                let rust = request
                    .edns
                    .map(|e| (e.payload, e.version, e.dnssec_ok, e.nsid));
                same("EDNS", lean, rust)?;

                // An authoritative NOERROR answer through the server front.
                let mut answer = bare_reply(&request, ResponseCode::NoError, None);
                answer.message.metadata.authoritative = true;
                let reply = ServerConfig::generic().front(&request, answer).message;
                let flags = field(expected, "answer");
                let m = &reply.metadata;
                let rust = [
                    ("qr", m.message_type == MessageType::Response),
                    ("aa", m.authoritative),
                    ("tc", m.truncation),
                    ("rd", m.recursion_desired),
                    ("ra", m.recursion_available),
                    ("ad", m.authentic_data),
                    ("cd", m.checking_disabled),
                ];
                for (bit, value) in rust {
                    same(&format!("answer {bit}"), flag(flags, bit), value)?;
                }
                same(
                    "answer opcode",
                    number(flags, "opcode") as u8,
                    u8::from(m.op_code),
                )?;
                same(
                    "answer rcode",
                    number(flags, "rcode") as u16,
                    u16::from(m.response_code.low()),
                )?;
                same("answer id", request.message.metadata.id, m.id)?;
                let opt = field(expected, "answer_opt");
                let lean =
                    (!opt.is_null()).then(|| (number(opt, "version") as u8, flag(opt, "do")));
                let rust = reply
                    .edns
                    .as_ref()
                    .map(|edns| (edns.version(), edns.flags().dnssec_ok));
                same("answer OPT", lean, rust)
            }
            (lean, rust) => Err(format!("Lean {lean}, Rust {rust:?}")),
        }
    });
}

// ---------------------------------------------------------------------
// fit.json: protocols::dns::fit
// ---------------------------------------------------------------------

#[test]
fn fit_vectors() {
    each_case("fit", |case, tally| {
        let input = field(case, "input");
        let expected = field(case, "expected");
        let lean_response = field(input, "response");
        if split_rrset(lean_response) {
            tally.note("responses with one RRset split in two, which Lean keeps apart");
            return Ok(());
        }
        let header = field(lean_response, "header");
        let flags = number(header, "flags") as u16;
        let mut bytes = (number(header, "id") as u16).to_be_bytes().to_vec();
        bytes.extend_from_slice(&flags.to_be_bytes());
        bytes.extend_from_slice(&[0; 8]);
        let mut message = Message::from_vec(&bytes).unwrap();
        for question in texts(lean_response, "question") {
            let tokens = tokens(&question);
            let mut query = Query::query(name(&tokens[0]), RecordType::from(type_code(&tokens[2])));
            query.set_query_class(DNSClass::from(class_code(&tokens[1])));
            message.add_query(query);
        }
        let sets = |key: &str| -> Vec<Vec<Record>> {
            list(lean_response, key)
                .iter()
                .map(|set| {
                    set.as_array()
                        .unwrap()
                        .iter()
                        .map(|l| record(l.as_str().unwrap()))
                        .collect()
                })
                .collect()
        };
        let (answer, authority, extra) = (sets("answer"), sets("authority"), sets("additional"));
        message.answers = answer.iter().flatten().cloned().collect();
        message.authorities = authority.iter().flatten().cloned().collect();
        message.additionals = extra.iter().flatten().cloned().collect();
        let opt = field(lean_response, "opt");
        if !opt.is_null() {
            message.set_edns(Edns::from(&record(opt.as_str().unwrap())));
        }
        let response = Response {
            message,
            required_additional: number(lean_response, "required_additional") as usize,
        };
        let limit_value = field(input, "limit");
        let limit = match text(limit_value, "kind") {
            "udp512" => Limit::Udp512,
            "udp_edns" => Limit::UdpEdns(number(limit_value, "size") as u16),
            _ => Limit::Stream,
        };
        let fitted = fit(&response, limit).map_err(|e| e.to_string())?;
        if fitted.bytes.len() > number(expected, "size_le") as usize {
            return Err(format!("{} octets past the limit", fitted.bytes.len()));
        }
        same("tc", flag(expected, "tc"), fitted.truncated)?;
        same(
            "length",
            number(expected, "length") as usize,
            fitted.bytes.len(),
        )?;
        let (tc, kept) = record_keys(&fitted.bytes).ok_or("the output does not read")?;
        same("TC bit", fitted.truncated, tc)?;
        let lean = field(expected, "kept");
        for (section, records) in ["answer", "authority", "additional"].iter().zip(&kept) {
            let mut rrsets: Vec<&(String, u16)> = Vec::new();
            for key in records.iter().filter(|(_, rtype)| *rtype != 41) {
                if !rrsets.contains(&key) {
                    rrsets.push(key);
                }
            }
            same(
                &format!("{section} RRsets kept"),
                number(lean, section) as usize,
                rrsets.len(),
            )?;
        }
        same(
            "OPT last",
            !opt.is_null(),
            kept[2].last().is_some_and(|(_, rtype)| *rtype == 41),
        )
    });
}

/// Whether a section of a `fit.json` response holds two RRsets with the
/// same owner and type. The Lean model keeps them apart; RFC 2181 §5
/// makes them one RRset, which `fit` writes together.
fn split_rrset(response: &Value) -> bool {
    ["answer", "authority", "additional"].iter().any(|section| {
        let mut seen = BTreeSet::new();
        list(response, section).iter().any(|set| {
            let first = set.as_array().unwrap()[0].as_str().unwrap();
            !seen.insert(rrset_key(first))
        })
    })
}

// ---------------------------------------------------------------------
// zone.json and partial.json: zone::answer over Zone and over views
// ---------------------------------------------------------------------

#[test]
fn zone_answers() {
    each_case("zone", |case, tally| {
        let input = field(case, "input");
        let expected = field(case, "expected");
        if let Some(error) = expected.get("error") {
            return refused(field(input, "zone"), error.as_str().unwrap_or_default());
        }
        let zone = vector_zone(field(input, "zone"))?;
        let req = vector_request(field(input, "request"), false);
        // Without DO, Lean's `all` is both `All` and `AllFollowingDo`.
        let anys = match any_response(input) {
            AnyResponse::All => vec![AnyResponse::All, AnyResponse::AllFollowingDo],
            any => vec![any],
        };
        for any in anys {
            match answer(&zone, &req, any) {
                Answered::Response(response) => {
                    compare_answer(&zone, &req, any, expected, &response, tally)?
                }
                Answered::Unknown { name, .. } => {
                    return Err(format!(
                        "a complete zone answered Unknown at {}",
                        name_text(&Name::from(&name))
                    ));
                }
            }
        }
        Ok(())
    });
}

/// Compares Rust's answer with Lean's, as [`compare_response`] does.
///
/// RFC 8482 §4.1 lets a server answer QTYPE ANY with any one RRset of the
/// name. The Lean model takes the first RRset in the order the zone lists
/// them, which a master file does not carry into a zone; Rust takes the
/// RRset of the type it prefers, or else the RRset of the lowest type. When the two pick different RRsets, Rust's
/// answer is still one RRset with the additional data Lean's has (none,
/// for an answer to ANY), and asked for the type of Lean's RRset, Rust must
/// answer with Lean's RCODE, AA, answer, and authority.
fn compare_answer(
    view: &dyn View,
    req: &Request,
    any: AnyResponse,
    expected: &Value,
    response: &Response,
    tally: &mut Tally,
) -> Result<(), String> {
    let exact = compare_response(expected, response);
    let lean_answer = texts(expected, "answer");
    let lean_sets = rrsets_of(&lean_answer);
    let one_rrset =
        matches!(any, AnyResponse::OneRrset(_)) && req.question.query_type() == RecordType::ANY;
    if exact.is_ok() || !one_rrset || lean_sets.len() != 1 {
        return exact;
    }
    let rust_lines: Vec<String> = response.message.answers.iter().map(zone_line).collect();
    same(
        "RRsets in an answer to ANY",
        1,
        rrsets_of(&rust_lines).len(),
    )?;
    let additional_lines: Vec<String> =
        response.message.additionals.iter().map(zone_line).collect();
    same(
        "additional",
        section(&texts(expected, "additional")),
        section(&additional_lines),
    )?;
    let lean_type = RecordType::from(type_code(&lean_sets[0].0.1));
    let typed = request(req.question.name(), lean_type, false);
    let mut typed = match answer(view, &typed, any) {
        Answered::Response(typed) => typed,
        Answered::Unknown { name, .. } => {
            return Err(format!("unknown at {}", name_text(&Name::from(&name))));
        }
    };
    typed.message.additionals = response.message.additionals.clone();
    typed.required_additional = response.required_additional;
    compare_response(expected, &typed)?;
    tally.note("answers to ANY where Lean and Rust pick different RRsets (RFC 8482 §4.1)");
    Ok(())
}

/// A complete zone's view with the facts at some names made unknown, as
/// `partial.json` gives them.
struct Partial {
    zone: Zone,
    unknown: BTreeSet<LowerName>,
}

impl View for Partial {
    fn apex(&self) -> &LowerName {
        self.zone.apex()
    }

    fn revision(&self) -> Revision {
        View::revision(&self.zone)
    }

    fn soa(&self) -> &RecordSet {
        View::soa(&self.zone)
    }

    fn node(&self, name: &LowerName) -> Fact<&Node> {
        if self.unknown.contains(name) {
            Fact::Unknown
        } else {
            View::node(&self.zone, name)
        }
    }

    fn denial(&self, name: &LowerName, kind: Denied) -> Fact<Vec<RecordSet>> {
        View::denial(&self.zone, name, kind)
    }
}

#[test]
fn partial_answers() {
    each_case("partial", |case, tally| {
        let input = field(case, "input");
        let expected = field(case, "expected");
        let zone = vector_zone(field(input, "zone"))?;
        let unknown = texts(input, "unknown")
            .iter()
            .map(|n| LowerName::new(&name(n)))
            .collect();
        let view = Partial { zone, unknown };
        let req = vector_request(field(input, "request"), false);
        let any = any_response(input);
        let rust = answer(&view, &req, any);
        match (expected.get("unknown"), rust) {
            (Some(lean), Answered::Unknown { name, .. }) => same(
                "unknown name",
                lean.as_str().unwrap().to_string(),
                name_text(&Name::from(&name)),
            ),
            (None, Answered::Response(response)) => compare_answer(
                &view,
                &req,
                any,
                field(expected, "response"),
                &response,
                tally,
            ),
            (Some(lean), Answered::Response(response)) => Err(format!(
                "Lean: unknown at {}; Rust answered {}",
                lean.as_str().unwrap(),
                rcode_text(response.message.metadata.response_code)
            )),
            (None, Answered::Unknown { name, .. }) => Err(format!(
                "Lean answered; Rust: unknown at {}",
                name_text(&Name::from(&name))
            )),
        }
    });
}

// ---------------------------------------------------------------------
// policy.json: AlgorithmPolicy
// ---------------------------------------------------------------------

/// The policy a vector names: `"iana"` for the Lean model's `Policy.iana`,
/// which is Rust's [`AlgorithmPolicy::iana`], so every case under it holds
/// the policy Rust ships to the one the theorems are about; otherwise the
/// lists it gives.
fn vector_policy(value: &Value) -> AlgorithmPolicy {
    if value.as_str() == Some("iana") {
        return AlgorithmPolicy::iana();
    }
    let set = |key: &str| -> BTreeSet<u8> {
        list(value, key)
            .iter()
            .map(|n| n.as_u64().unwrap() as u8)
            .collect()
    };
    AlgorithmPolicy {
        validate: set("validate"),
        digests: set("digests"),
        max_nsec3_iterations: number(value, "max_nsec3_iterations") as u16,
        ..AlgorithmPolicy::iana()
    }
}

#[test]
fn policy() {
    each_case("policy", |case, _| {
        let input = field(case, "input");
        let algorithm = number(input, "algorithm") as u8;
        let digest = number(input, "digest") as u8;
        let policy = vector_policy(field(input, "policy"));
        let rust = match policy.treat(algorithm, digest) {
            Treatment::Supported => "supported",
            Treatment::UnsupportedAlgorithm => "unsupported_algorithm",
            Treatment::UnsupportedDigest => "unsupported_digest",
        };
        same(
            "treatment",
            text(field(case, "expected"), "treatment"),
            rust,
        )
    });
}

// ---------------------------------------------------------------------
// The symbolic scheme
// ---------------------------------------------------------------------

/// A symbolic key of `signed.json` and `chain.json`.
#[derive(Clone, Copy, Debug)]
struct KeySpec {
    id: u8,
    algorithm: u8,
    sep: bool,
    corrupt: bool,
    mistag: bool,
}

fn key_specs(value: &Value) -> Vec<KeySpec> {
    list(value, "keys")
        .iter()
        .map(|k| KeySpec {
            id: number(k, "id") as u8,
            algorithm: number(k, "alg") as u8,
            sep: flag(k, "sep"),
            corrupt: flag(k, "corrupt"),
            mistag: flag(k, "mistag"),
        })
        .collect()
}

/// A DNSKEY with the given flags, algorithm, and public key octets.
fn dnskey(sep: bool, algorithm: u8, public: Vec<u8>) -> DNSKEY {
    let algorithm = hickory_proto::dnssec::Algorithm::from_u8(algorithm);
    DNSKEY::new(true, sep, false, PublicKeyBuf::new(public, algorithm))
}

/// Lean's symbolic signer: the public key is the key's number as one
/// octet, and a signature is the private key as two octets followed by
/// the message. A corrupted key signs with private key `id + 1000`, which
/// is no key's.
struct Symbolic(KeySpec);

impl Sign for Symbolic {
    fn dnskey(&self) -> DNSKEY {
        dnskey(self.0.sep, self.0.algorithm, vec![self.0.id])
    }

    fn sign(&self, tbs: &[u8]) -> Vec<u8> {
        let private = u16::from(self.0.id) + if self.0.corrupt { 1000 } else { 0 };
        let mut signature = private.to_be_bytes().to_vec();
        signature.extend_from_slice(tbs);
        signature
    }
}

/// The verifier of the symbolic scheme (`Symbolic.scheme.verify`): a
/// signature verifies under a key when its private key is the key's
/// public octet and its message is the to-be-signed octets.
struct Oracle;

impl Verify for Oracle {
    fn verify(&self, key: &DNSKEY, tbs: &[u8], signature: &[u8]) -> bool {
        let public = key.public_key().public_bytes();
        signature.len() >= 2
            && public.len() == 1
            && u16::from_be_bytes([signature[0], signature[1]]) == u16::from(public[0])
            && &signature[2..] == tbs
    }
}

/// How keys of one case are made: symbolically, or as real keys.
trait Keys {
    fn sign(&mut self, spec: KeySpec) -> Arc<dyn Sign>;
}

struct SymbolicKeys;

impl Keys for SymbolicKeys {
    fn sign(&mut self, spec: KeySpec) -> Arc<dyn Sign> {
        Arc::new(Symbolic(spec))
    }
}

fn key_set(specs: &[KeySpec], keys: &mut impl Keys) -> KeySet {
    KeySet {
        keys: specs.iter().map(|spec| keys.sign(*spec)).collect(),
    }
}

/// The RRSIG key tags of `keys` mapped to the symbolic numbers Lean
/// writes as tags, the tags of `mistags` included.
fn tag_names(
    specs: &[KeySpec],
    keys: &KeySet,
    mistags: &BTreeMap<u16, Mistag>,
) -> BTreeMap<u16, u16> {
    specs
        .iter()
        .zip(&keys.keys)
        .map(|(spec, key)| (key_tag(&key.dnskey()), u16::from(spec.id)))
        .chain(mistags.values().map(|m| (m.wrong, m.symbolic)))
        .collect()
}

/// How a mistagged key's RRSIGs reach the validator (`Gen.lean`'s
/// `retag`): with a key tag no key of the zone has, signed over that tag
/// by the same key, as a broken server may send them.
struct Mistag {
    /// The key tag they carry.
    wrong: u16,
    /// The tag Lean writes for it: the key's number plus 512.
    symbolic: u16,
    /// The key.
    key: Arc<dyn Sign>,
}

/// The mistagged keys of `specs`, by their own key tags.
fn mistags(specs: &[KeySpec], keys: &KeySet) -> BTreeMap<u16, Mistag> {
    let tags: BTreeSet<u16> = keys.keys.iter().map(|key| key_tag(&key.dnskey())).collect();
    let mut taken = tags.clone();
    let mut out = BTreeMap::new();
    for (spec, key) in specs.iter().zip(&keys.keys) {
        if !spec.mistag {
            continue;
        }
        let tag = key_tag(&key.dnskey());
        let mut wrong = tag.wrapping_add(1);
        while taken.contains(&wrong) {
            wrong = wrong.wrapping_add(1);
        }
        taken.insert(wrong);
        out.insert(
            tag,
            Mistag {
                wrong,
                symbolic: u16::from(spec.id) + 512,
                key: key.clone(),
            },
        );
    }
    out
}

/// `set` with the RRSIGs of mistagged keys as they reach the validator.
fn mistag_set(set: &RecordSet, mistags: &BTreeMap<u16, Mistag>) -> RecordSet {
    let rrsigs = set
        .rrsigs()
        .iter()
        .map(|record| {
            let RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) = &record.data else {
                return record.clone();
            };
            let Some(mistag) = mistags.get(&rrsig.input().key_tag) else {
                return record.clone();
            };
            let mut input = rrsig.input().clone();
            input.key_tag = mistag.wrong;
            let tbs = signed_data(set, &input).expect("a signed RRset encodes");
            let signature = mistag.key.sign(tbs.as_ref());
            let mut record = record.clone();
            record.data = RData::DNSSEC(DNSSECRData::RRSIG(RRSIG::from_sig(input, signature)));
            record
        })
        .collect();
    let mut set = set.clone();
    set.set_rrsigs(rrsigs);
    set
}

/// `records` with the RRSIGs of mistagged keys as they reach the
/// validator, each RRset's records followed by its RRSIGs.
fn mistag_records(records: &[Record], mistags: &BTreeMap<u16, Mistag>) -> Vec<Record> {
    if mistags.is_empty() {
        return records.to_vec();
    }
    record_sets(records)
        .iter()
        .flat_map(|set| {
            let set = mistag_set(set, mistags);
            let mut out: Vec<Record> = set.records_without_rrsigs().cloned().collect();
            out.extend(set.rrsigs().iter().cloned());
            out
        })
        .collect()
}

fn time(seconds: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(seconds)
}

fn vector_window(value: &Value) -> Window {
    Window {
        inception: time(number(value, "inception")),
        expiration: time(number(value, "expiration")),
    }
}

fn vector_denial(value: &Value) -> Denial {
    match text(value, "kind") {
        "nsec" => Denial::Nsec,
        _ => Denial::Nsec3 {
            opt_out: flag(value, "opt_out"),
            salt: Vec::new(),
        },
    }
}

fn validation_text(validation: Validation) -> String {
    match validation {
        Validation::NotPerformed => "not_performed".to_string(),
        Validation::Secure => "secure".to_string(),
        Validation::Insecure(why) => format!(
            "insecure {}",
            match why {
                Insecure::ProvenNoDs => "proven_no_ds",
                Insecure::OptOutCovered => "opt_out_covered",
                Insecure::NoAnchor => "no_anchor",
                Insecure::UnsupportedAlgorithm => "unsupported_algorithm",
                Insecure::UnsupportedDigest => "unsupported_digest",
                Insecure::Nsec3Iterations => "nsec3_iterations",
            }
        ),
        Validation::Bogus(ede) => format!("bogus {}", ede.0),
        Validation::Indeterminate => "indeterminate".to_string(),
    }
}

fn lean_validation(value: &Value) -> String {
    match text(value, "result") {
        "insecure" => format!("insecure {}", text(value, "why")),
        "bogus" => format!("bogus {}", number(value, "ede")),
        other => other.to_string(),
    }
}

/// A section's records grouped into RRsets, each RRSIG in the RRset it
/// covers.
fn record_sets(records: &[Record]) -> Vec<RecordSet> {
    let mut sets: Vec<RecordSet> = Vec::new();
    for record in records {
        let covered = match &record.data {
            RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) => Some(rrsig.input().type_covered),
            _ => None,
        };
        let rtype = covered.unwrap_or(record.record_type());
        let position = sets
            .iter()
            .position(|s| *s.name() == record.name && s.record_type() == rtype);
        let set = match position {
            Some(i) => &mut sets[i],
            None => {
                sets.push(RecordSet::with_ttl(record.name.clone(), rtype, record.ttl));
                sets.last_mut().unwrap()
            }
        };
        if covered.is_some() {
            set.insert_rrsig(record.clone());
        } else {
            set.insert(record.clone(), 0);
        }
    }
    sets
}

/// A record's type, or for an RRSIG the type it covers.
fn covered_type(record: &Record) -> RecordType {
    match &record.data {
        RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) => rrsig.input().type_covered,
        _ => record.record_type(),
    }
}

fn is_denial(record: &Record) -> bool {
    matches!(covered_type(record), RecordType::NSEC | RecordType::NSEC3)
}

/// The name a negative answer is about: the target of the last CNAME in
/// the answer, unless the question was for CNAME (Lean's `finalName`).
fn final_name(qname: &Name, qtype: RecordType, answers: &[Record]) -> Name {
    if qtype == RecordType::CNAME {
        return qname.clone();
    }
    match answers
        .iter()
        .rfind(|r| r.record_type() != RecordType::RRSIG)
    {
        Some(Record {
            data: RData::CNAME(target),
            ..
        }) => target.0.clone(),
        _ => qname.clone(),
    }
}

/// Compares `message`, an answer from a signed zone, with the answer Lean
/// writes for it (`signedAnswerFields`): the RCODE, AA, every section with
/// its RRSIGs in `form`, and the denial records.
fn compare_signed(expected: &Value, message: &Message, form: Form<'_>) -> Result<(), String> {
    let lines = |records: &mut dyn Iterator<Item = &Record>| -> Vec<String> {
        records.map(|r| line(r, form)).collect()
    };
    same(
        "rcode",
        text(expected, "rcode").to_string(),
        rcode_text(message.metadata.response_code),
    )?;
    same("aa", flag(expected, "aa"), message.metadata.authoritative)?;
    same(
        "answer",
        section(&texts(expected, "answer")),
        section(&lines(&mut message.answers.iter())),
    )?;
    same(
        "authority",
        section(&texts(expected, "authority")),
        section(&lines(
            &mut message.authorities.iter().filter(|r| !is_denial(r)),
        )),
    )?;
    // Lean writes one record each time a proof needs it; a message
    // holds each record once (RFC 2181 §5).
    let lean_denial: BTreeSet<String> = texts(expected, "denial").into_iter().collect();
    let rust_denial: BTreeSet<String> =
        lines(&mut message.authorities.iter().filter(|r| is_denial(r)))
            .into_iter()
            .collect();
    same("denial", lean_denial, rust_denial)?;
    // The Lean model's signed answers carry no RRSIGs in the
    // additional section.
    let rust_additional = lines(
        &mut message
            .additionals
            .iter()
            .filter(|r| r.record_type() != RecordType::RRSIG),
    );
    same(
        "additional",
        section(&texts(expected, "additional")),
        section(&rust_additional),
    )
}

/// Signs a `signed.json` zone with `keys`, answers its question with
/// DO=1, and validates the answer with `verify`: the answer lines and the
/// validations, or `unknown`.
fn signed_case(
    case: &Value,
    maker: &mut impl Keys,
    verify: &impl Verify,
    compare_lines: bool,
) -> Result<(), String> {
    let input = field(case, "input");
    let expected = field(case, "expected");
    let zone = vector_zone(field(input, "zone"))?;
    let specs = key_specs(input);
    let keys = key_set(&specs, maker);
    let mistags = mistags(&specs, &keys);
    let tags = tag_names(&specs, &keys, &mistags);
    let window = vector_window(field(input, "window"));
    let signed = zone
        .signed(&keys, window, vector_denial(field(input, "denial")))
        .map_err(|e| format!("signing failed: {e}"))?;
    let req = vector_request(field(input, "request"), true);
    let response = match answer(&signed, &req, AnyResponse::All) {
        Answered::Response(response) => response,
        Answered::Unknown { name, .. } => {
            return same(
                "unknown",
                expected
                    .get("unknown")
                    .and_then(Value::as_str)
                    .map(String::from),
                Some(name_text(&Name::from(&name))),
            );
        }
    };
    // The answer as it reaches the validator, mistagged RRSIGs and all.
    let mut message = response.message.clone();
    message.answers = mistag_records(&message.answers, &mistags);
    message.authorities = mistag_records(&message.authorities, &mistags);
    if flag(input, "strip_soa") {
        message
            .authorities
            .retain(|r| r.record_type() != RecordType::RRSIG || covered_type(r) != RecordType::SOA);
    }
    let message = &message;
    let answers = &message.answers;
    let qtype = req.question.query_type();
    let form = Form::Zone(&tags);
    let lines = |records: &mut dyn Iterator<Item = &Record>| -> Vec<String> {
        records.map(|r| line(r, form)).collect()
    };
    let rcode = message.metadata.response_code;
    if compare_lines {
        compare_signed(expected, message, form)?;
    }
    let apex = Name::from(signed.apex());
    let dnskeys = match signed.node(signed.apex()) {
        Some(Node::Data(sets)) => sets.get(&RecordType::DNSKEY).cloned(),
        _ => None,
    }
    .ok_or("the signed zone has no DNSKEY RRset")?;
    let dnskeys = mistag_set(&dnskeys, &mistags);
    if compare_lines {
        same(
            "dnskey",
            section(&texts(expected, "dnskey")),
            section(&lines(&mut dnskeys.records(true))),
        )?;
    }

    // A zone below a signed parent validates from the parent's anchor,
    // down the delegation the parent serves; any other from its own.
    let (anchors, chain) = match input.get("parent").filter(|parent| !parent.is_null()) {
        Some(parent) => parent_chain(
            parent,
            &apex,
            dnskeys,
            window,
            maker,
            expected,
            compare_lines,
        )?,
        None => (
            Anchors::of(vec![keys.anchor(&apex)]),
            Chain {
                links: vec![Link {
                    zone: apex,
                    ds: Fetched::Failed,
                    dnskey: Fetched::Answer(dnskeys),
                }],
            },
        ),
    };
    let policy = vector_policy(field(input, "policy"));
    let at = time(number(input, "time"));
    let authority = record_sets(&message.authorities);
    let lean = field(expected, "validation");
    let lean_answers: Vec<String> = list(lean, "answer").iter().map(lean_validation).collect();
    // Lean's results are in the order of its answer RRsets, which an
    // answer to ANY may list in another order than Rust's.
    let lean_sets: Vec<(String, String)> = rrsets_of(&texts(expected, "answer"))
        .into_iter()
        .map(|(key, _)| key)
        .collect();
    same("answer RRsets", lean_sets.len(), lean_answers.len())?;
    let sets = record_sets(answers);
    same("answer RRsets validated", lean_answers.len(), sets.len())?;
    for set in &sets {
        let key = (
            name_text(set.name()).to_ascii_lowercase(),
            type_text(u16::from(set.record_type())),
        );
        let lean = lean_sets
            .iter()
            .position(|lean| *lean == key)
            .map(|i| &lean_answers[i])
            .ok_or_else(|| format!("Lean validated no answer RRset {} {}", key.0, key.1))?;
        let rust = validation_text(
            validate_rrset(set, &authority, &chain, &anchors, &policy, at, verify).validation,
        );
        if *lean == rust {
            continue;
        }
        return Err(format!(
            "validation of {} {}: Lean {lean}, Rust {rust}",
            name_text(set.name()),
            set.record_type()
        ));
    }
    let qname = req.question.name().clone();
    let negative = rcode == ResponseCode::NXDomain
        || (rcode == ResponseCode::NoError
            && message
                .authorities
                .iter()
                .any(|r| r.record_type() == RecordType::SOA));
    let rust_denial = negative.then(|| {
        let about = Query::query(final_name(&qname, qtype, answers), qtype);
        validation_text(
            validate_denial(
                &about, rcode, &authority, &chain, &anchors, &policy, at, verify,
            )
            .validation,
        )
    });
    let denial = field(lean, "denial");
    let lean_denial = (!denial.is_null()).then(|| lean_validation(denial));
    same("denial validation", lean_denial, rust_denial)
}

/// The anchors and chain for a zone at `apex`, with DNSKEY RRset
/// `dnskeys`, below the signed parent `parent` gives. The parent is built
/// from its records, its DS records for the zone made real for `maker`'s
/// keys, signed with its own keys, and asked for the zone's DS RRset with
/// DO, as a resolver asks it. The validation then walks from the parent's
/// anchor across the delegation, as Lean's does.
fn parent_chain(
    parent: &Value,
    apex: &Name,
    dnskeys: RecordSet,
    window: Window,
    maker: &mut impl Keys,
    expected: &Value,
    compare_lines: bool,
) -> Result<(Anchors, Chain), String> {
    let records: Vec<String> = texts(field(parent, "zone"), "records")
        .iter()
        .map(|line| real_ds_line(line, maker))
        .collect();
    let zone = Zone::from_master(&records.join("\n"), None)
        .map_err(|e| format!("the parent does not build: {e}"))?;
    let specs = key_specs(parent);
    let keys = key_set(&specs, maker);
    let signed = zone
        .signed(&keys, window, vector_denial(field(parent, "denial")))
        .map_err(|e| format!("signing the parent failed: {e}"))?;
    let papex = Name::from(signed.apex());
    let parent_keys = match signed.node(signed.apex()) {
        Some(Node::Data(sets)) => sets.get(&RecordType::DNSKEY).cloned(),
        _ => None,
    }
    .ok_or("the signed parent has no DNSKEY RRset")?;
    let reply = match answer(
        &signed,
        &request(apex, RecordType::DS, true),
        AnyResponse::All,
    ) {
        Answered::Response(response) => response.message,
        Answered::Unknown { name, .. } => return Err(format!("the parent does not know {name}")),
    };
    let ds_set = record_sets(&reply.answers)
        .into_iter()
        .find(|set| set.record_type() == RecordType::DS);
    if compare_lines {
        let tags = tag_names(&specs, &keys, &BTreeMap::new());
        let form = Form::Zone(&tags);
        let lines = |records: &mut dyn Iterator<Item = &Record>| -> Vec<String> {
            records.map(|r| line(r, form)).collect()
        };
        same(
            "parent dnskey",
            section(&texts(expected, "parent_dnskey")),
            section(&lines(&mut parent_keys.records(true))),
        )?;
        // The parent's DS records hold real digests here and symbolic ones
        // in Lean, so a DS RRset is compared by its presence and a denial
        // record by record.
        let lean = texts(expected, "delegation");
        let lean_ds = lean.iter().any(|l| tokens(l)[3] == "DS");
        same("delegation by a DS RRset", lean_ds, ds_set.is_some())?;
        if !lean_ds {
            let lean: BTreeSet<String> = lean.into_iter().collect();
            let rust: BTreeSet<String> =
                lines(&mut reply.authorities.iter().filter(|r| is_denial(r)))
                    .into_iter()
                    .collect();
            same("delegation", lean, rust)?;
        }
    }
    let ds = match ds_set {
        Some(set) => Fetched::Answer(set),
        None => Fetched::Denied(record_sets(&reply.authorities)),
    };
    let anchors = Anchors::of(vec![keys.anchor(&papex)]);
    let chain = Chain {
        links: vec![
            Link {
                zone: papex,
                ds: Fetched::Failed,
                dnskey: Fetched::Answer(parent_keys),
            },
            Link {
                zone: apex.clone(),
                ds,
                dnskey: Fetched::Answer(dnskeys),
            },
        ],
    };
    Ok((anchors, chain))
}

/// `signed.json` with the symbolic signer and the oracle verifier: the
/// signed zone's answer with DO=1 and its validation under the zone's own
/// anchor, or its parent's.
#[test]
fn signed_symbolic() {
    each_case("signed", |case, _| {
        signed_case(case, &mut SymbolicKeys, &Oracle, true)
    });
}

/// Real keys for the symbolic ones, made once per number and algorithm
/// from a seed, so the same case always signs the same way. A corrupted
/// key's signatures have one bit flipped.
struct RealKeys {
    made: BTreeMap<(u8, u8), Arc<dyn Sign>>,
}

impl Keys for RealKeys {
    fn sign(&mut self, spec: KeySpec) -> Arc<dyn Sign> {
        let key = self
            .made
            .entry((spec.id, spec.algorithm))
            .or_insert_with(|| real_key(spec))
            .clone();
        Arc::new(Real {
            key,
            sep: spec.sep,
            corrupt: spec.corrupt,
        })
    }
}

/// A real key for `spec`'s number and algorithm. Algorithm 5 (RSA/SHA-1),
/// which no world may sign with (RFC 9905 §2), is signed here with the
/// `rsa` crate over an RSA key the SDK makes.
fn real_key(spec: KeySpec) -> Arc<dyn Sign> {
    use fictionet::stdlib::protocols::dns::dnssec::Algorithm;
    let entropy = SeededEntropy::new(Seed::from_u64(
        u64::from(spec.id) << 8 | u64::from(spec.algorithm),
    ));
    match Algorithm::from_number(spec.algorithm) {
        Some(algorithm) => Arc::new(ZoneKey::generate(&entropy, algorithm, KeyFlags::ZSK)),
        None if spec.algorithm == 5 => Arc::new(RsaSha1::new(ZoneKey::generate(
            &entropy,
            Algorithm::RsaSha256,
            KeyFlags::ZSK,
        ))),
        None => panic!("no real key for algorithm {}", spec.algorithm),
    }
}

/// RSA/SHA-1 (RFC 3110) over the RSA key of a [`ZoneKey`].
struct RsaSha1 {
    key: rsa::RsaPrivateKey,
    public: Vec<u8>,
}

impl RsaSha1 {
    fn new(key: ZoneKey) -> RsaSha1 {
        use rsa::pkcs8::DecodePrivateKey;
        let public = key.dnskey().public_key().public_bytes().to_vec();
        let key = rsa::RsaPrivateKey::from_pkcs8_der(&key.to_pkcs8()).expect("an RSA key");
        RsaSha1 { key, public }
    }
}

impl Sign for RsaSha1 {
    fn dnskey(&self) -> DNSKEY {
        dnskey(false, 5, self.public.clone())
    }

    fn sign(&self, tbs: &[u8]) -> Vec<u8> {
        // The DER prefix of a SHA-1 DigestInfo (RFC 8017 §9.2).
        const SHA1: [u8; 15] = [
            0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04,
            0x14,
        ];
        let scheme = rsa::Pkcs1v15Sign {
            hash_len: Some(20),
            prefix: SHA1.to_vec().into_boxed_slice(),
        };
        let digest = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, tbs);
        self.key
            .sign(scheme, digest.as_ref())
            .expect("an RSA key signs a SHA-1 digest")
    }
}

/// A real key with the DNSKEY flags of a symbolic one.
struct Real {
    key: Arc<dyn Sign>,
    sep: bool,
    corrupt: bool,
}

impl Sign for Real {
    fn dnskey(&self) -> DNSKEY {
        let inner = self.key.dnskey();
        DNSKEY::new(true, self.sep, false, inner.public_key().clone())
    }

    fn sign(&self, tbs: &[u8]) -> Vec<u8> {
        let mut signature = self.key.sign(tbs);
        if self.corrupt {
            signature[0] ^= 1;
        }
        signature
    }
}

/// `signed.json` signed for real: every valid symbolic signature becomes
/// a real one and every invalid one a real signature with a bit flipped,
/// and [`Ring`] must reach the validations Lean reached with symbolic
/// signatures.
#[test]
fn signed_real() {
    let mut keys = RealKeys {
        made: BTreeMap::new(),
    };
    each_case("signed", |case, _| {
        signed_case(case, &mut keys, &Ring, false)
    });
}

// ---------------------------------------------------------------------
// chain.json: zone::check_chain
// ---------------------------------------------------------------------

/// The symbolic DS digest (`Symbolic.scheme.digest`) read back: the
/// owner's canonical wire form, the SEP bit, the algorithm, and the
/// public key. `None` for octets that are not such a digest.
fn symbolic_digest(owner: &Name, digest: &[u8]) -> Option<(bool, u8, Vec<u8>)> {
    let wire = owner.to_lowercase().to_bytes().ok()?;
    let rest = digest.strip_prefix(wire.as_slice())?;
    match rest {
        [sep @ (0 | 1), algorithm, public @ ..] if !public.is_empty() => {
            Some((*sep == 1, *algorithm, public.to_vec()))
        }
        _ => None,
    }
}

/// A DS line with a symbolic digest, rewritten as the real DS record of
/// the real key standing for the symbolic key the digest names, with the
/// line's digest type. Lines whose digest names no key, or whose digest
/// type has no real digest here, stay as they are; a validator cannot use
/// them either way.
fn real_ds_line(line: &str, keys: &mut impl Keys) -> String {
    let fields = tokens(line);
    if fields[3] != "DS" {
        return line.to_string();
    }
    let owner = name(&fields[0]);
    let digest_type = fields[6].parse().expect("a digest type");
    let named = symbolic_digest(&owner, &unhex(&fields[7]));
    match (named, DigestType::from_number(digest_type)) {
        (Some((sep, algorithm, public)), Some(digest)) if public.len() == 1 => {
            let spec = KeySpec {
                id: public[0],
                algorithm,
                sep,
                corrupt: false,
                mistag: false,
            };
            let real: DS = ds(&owner, &keys.sign(spec).dnskey(), digest);
            format!(
                "{} {} IN DS {} {algorithm} {digest_type} {}",
                fields[0],
                fields[1],
                real.key_tag(),
                hex(real.digest())
            )
        }
        _ => line.to_string(),
    }
}

/// `chain.json` with real keys standing for the symbolic ones, since
/// `check_chain` checks signatures with [`Ring`].
#[test]
fn chain() {
    let mut keys = RealKeys {
        made: BTreeMap::new(),
    };
    each_case("chain", |case, tally| {
        let input = field(case, "input");
        let corrupt = list(input, "tree")
            .iter()
            .any(|member| key_specs(member).iter().any(|k| k.corrupt));
        let mut zones = Vec::new();
        let policy = vector_policy(field(input, "policy"));
        for member in list(input, "tree") {
            let records: Vec<String> = texts(field(member, "zone"), "records")
                .iter()
                .map(|line| real_ds_line(line, &mut keys))
                .collect();
            let zone = Zone::from_master(&records.join("\n"), None)
                .map_err(|e| format!("the zone does not build: {e}"))?;
            let specs = key_specs(member);
            let zone = if specs.is_empty() {
                zone
            } else {
                zone.signed(
                    &key_set(&specs, &mut keys),
                    vector_window(field(member, "window")),
                    vector_denial(field(member, "denial")),
                )
                .map_err(|e| format!("signing failed: {e}"))?
            };
            zones.push(zone);
        }
        let at = time(number(input, "time"));
        let refs: Vec<&Zone> = zones.iter().collect();
        let rust: BTreeSet<String> = check_chain(&refs, &policy, at)
            .into_iter()
            .map(|problem| {
                use fictionet::stdlib::services::dns::zone::ChainProblem;
                let n = |n: &LowerName| name_text(&Name::from(n));
                match problem {
                    ChainProblem::DsMismatch { parent, child } => {
                        format!("ds_mismatch {} {}", n(&parent), n(&child))
                    }
                    ChainProblem::NoDsProofMissing { parent, child } => {
                        format!("no_ds_proof_missing {} {}", n(&parent), n(&child))
                    }
                    ChainProblem::WindowClosed { apex, at } => format!(
                        "window_closed {} {}",
                        n(&apex),
                        at.duration_since(UNIX_EPOCH).unwrap().as_secs()
                    ),
                    ChainProblem::UnsupportedAlgorithm { apex, algorithm } => {
                        format!("unsupported_algorithm {} {algorithm}", n(&apex))
                    }
                    ChainProblem::SignatureInvalid { apex, owner, rtype } => {
                        format!("signature_invalid {} {} {rtype}", n(&apex), n(&owner))
                    }
                }
            })
            .collect();
        // `check_complete` and `check_reports_real` say which problems
        // are reported, not in which order.
        let lean: BTreeSet<String> = list(field(case, "expected"), "problems")
            .iter()
            .map(|p| match text(p, "kind") {
                "window_closed" => {
                    format!("window_closed {} {}", text(p, "apex"), number(p, "time"))
                }
                "unsupported_algorithm" => format!(
                    "unsupported_algorithm {} {}",
                    text(p, "apex"),
                    number(p, "algorithm")
                ),
                kind => format!("{kind} {} {}", text(p, "parent"), text(p, "child")),
            })
            .collect();
        // `check_sound` assumes honest signers: the Lean check reads no
        // signature, so the breaks a corrupted key makes are not its to
        // report. Rust's check verifies signatures and reports them as a
        // DS that selects no key signing the child's DNSKEY RRset, a
        // no-DS proof that does not verify, or an RRset whose RRSIGs do
        // not verify; it reports everything else Lean does.
        if corrupt {
            let extra: Vec<&String> = rust.difference(&lean).collect();
            let signature_breaks = extra.iter().all(|p| {
                p.starts_with("ds_mismatch ")
                    || p.starts_with("no_ds_proof_missing ")
                    || p.starts_with("signature_invalid ")
            });
            if lean.is_subset(&rust) && signature_breaks {
                if !extra.is_empty() {
                    tally
                        .note("trees with a corrupted key: Rust also reports its signature breaks");
                }
                return Ok(());
            }
        }
        same("problems", lean, rust)
    });
}

// ---------------------------------------------------------------------
// cache.json: resolver::Cache
// ---------------------------------------------------------------------

fn rank(text: &str) -> Rank {
    match text {
        "glue" => Rank::Glue,
        "non_auth_authority" => Rank::NonAuthAuthority,
        "non_auth_answer" => Rank::NonAuthAnswer,
        "auth_authority" => Rank::AuthAuthority,
        _ => Rank::AuthAnswer,
    }
}

fn vector_validation(value: &Value) -> Validation {
    match text(value, "result") {
        "secure" => Validation::Secure,
        "not_performed" => Validation::NotPerformed,
        "indeterminate" => Validation::Indeterminate,
        "insecure" => Validation::Insecure(match text(value, "why") {
            "proven_no_ds" => Insecure::ProvenNoDs,
            "opt_out_covered" => Insecure::OptOutCovered,
            "no_anchor" => Insecure::NoAnchor,
            "unsupported_algorithm" => Insecure::UnsupportedAlgorithm,
            "unsupported_digest" => Insecure::UnsupportedDigest,
            _ => Insecure::Nsec3Iterations,
        }),
        _ => Validation::Bogus(fictionet::stdlib::protocols::dns::EdeCode(
            number(value, "ede") as u16,
        )),
    }
}

fn failure_kind(value: &Value) -> FailureKind {
    match text(value, "kind") {
        "no_reachable_authority" => FailureKind::NoReachableAuthority,
        "work_exceeded" => FailureKind::WorkExceeded,
        "unknown" => FailureKind::Unknown,
        other => panic!("no failure kind {other}"),
    }
}

fn failure_text(kind: FailureKind) -> String {
    match kind {
        FailureKind::NoReachableAuthority => "no_reachable_authority".to_string(),
        FailureKind::WorkExceeded => "work_exceeded".to_string(),
        FailureKind::Unknown => "unknown".to_string(),
    }
}

fn cache_key(value: &Value) -> Key {
    Key::new(
        LowerName::new(&name(text(value, "name"))),
        RecordType::from(type_code(text(value, "type"))),
        DNSClass::IN,
    )
}

/// The RRset of a vector's one-RRset `set` lines.
fn vector_rrset(lines: &[String]) -> RecordSet {
    let records: Vec<Record> = lines.iter().map(|l| record(l)).collect();
    let first = &records[0];
    let mut set = RecordSet::with_ttl(first.name.clone(), first.record_type(), first.ttl);
    for record in records {
        set.insert(record, 0);
    }
    set
}

fn at(seconds: u64) -> Instant {
    Instant::from_since_start(Duration::from_secs(seconds))
}

/// A set's lines with its TTL as `ttl`, as a served entry shows it.
fn served_lines(set: &RecordSet, ttl: u64) -> Vec<String> {
    set.records_without_rrsigs()
        .map(|record| {
            let mut record = record.clone();
            record.ttl = ttl as u32;
            zone_line(&record)
        })
        .collect()
}

/// What the cache serves for `key` at `now`, as `cache.json` writes it:
/// an NXDOMAIN at the name first, as the resolver looks (RFC 8020), then
/// the entry under the key itself.
fn served(cache: &Cache, key: &Key, now: Instant) -> String {
    let left = |expires: Instant| {
        expires
            .since_start()
            .saturating_sub(now.since_start())
            .as_secs()
    };
    let entry = cache
        .nxdomain_above(&key.name, key.class, now)
        .filter(|(at, _)| **at == key.name)
        .map(|(_, entry)| entry)
        .or_else(|| cache.get(key, now));
    match entry {
        None => "null".to_string(),
        Some(Entry::Positive {
            set,
            validation,
            expires,
            ..
        }) => format!(
            "positive {:?} {}",
            served_lines(set, left(*expires)),
            validation_text(*validation)
        ),
        Some(Entry::Negative {
            kind,
            soa,
            validation,
            expires,
            ..
        }) => format!(
            "negative {} {:?} {}",
            match kind {
                Negative::NxDomain => "nxdomain",
                Negative::NoData => "nodata",
            },
            served_lines(soa, left(*expires)),
            validation_text(*validation)
        ),
        Some(Entry::Failure { why, .. }) => format!("failure {}", failure_text(*why)),
    }
}

fn lean_served(value: &Value) -> String {
    if value.is_null() {
        return "null".to_string();
    }
    if let Some(set) = value.get("positive") {
        let lines: Vec<String> = set
            .as_array()
            .unwrap()
            .iter()
            .map(|l| l.as_str().unwrap().to_string())
            .collect();
        return format!(
            "positive {lines:?} {}",
            lean_validation(field(value, "validation"))
        );
    }
    if let Some(kind) = value.get("negative") {
        return format!(
            "negative {} {:?} {}",
            kind.as_str().unwrap(),
            texts(value, "soa"),
            lean_validation(field(value, "validation"))
        );
    }
    let failure = field(value, "failure");
    format!(
        "failure {}",
        match text(failure, "kind") {
            "bogus" => format!("bogus {}", number(failure, "ede")),
            kind => kind.to_string(),
        }
    )
}

#[test]
fn cache() {
    each_case("cache", |case, _| {
        let input = field(case, "input");
        let limits_value = field(input, "limits");
        let max_ttl = Duration::from_secs(number(limits_value, "max_ttl"));
        let limits = Limits {
            max_ttl,
            // The Lean cache bounds negative answers by `max_ttl` alone.
            max_negative_ttl: max_ttl,
            failure_ttl: Duration::from_secs(number(limits_value, "failure_ttl")),
            stale: Duration::ZERO,
            // The Lean cache has no capacity. A case offers at most a
            // dozen things, far fewer than this holds.
            max_entries: 1024,
        };
        let mut cache = Cache::new(limits, &Budget::unlimited()).expect("an unlimited budget");
        let mut rust = Vec::new();
        for op in list(input, "ops") {
            let now = at(number(op, "time"));
            match text(op, "op") {
                "offer" => offer(&mut cache, field(op, "offer"), now, limits),
                "advance" => cache.clear(),
                _ => rust.push(served(&cache, &cache_key(field(op, "key")), now)),
            }
        }
        let lean: Vec<String> = list(field(case, "expected"), "served")
            .iter()
            .map(lean_served)
            .collect();
        same("served", lean, rust)
    });
}

/// Offers one `cache.json` offer, then hands the cache what validation
/// established through [`Cache::validated`], with the RRSIGs' first
/// expiration and smallest Original TTL, as the resolver does once
/// validation is done (RFC 4035 §5.3.3, RFC 9520 §3.2), when the offer was
/// stored.
fn offer(cache: &mut Cache, offer: &Value, now: Instant, limits: Limits) {
    if text(offer, "kind") == "failure" {
        // The resolution that failed began and ended at `now`.
        let key = cache_key(field(offer, "key"));
        let follows = cache.persisting(&key, now);
        return cache.insert(
            now,
            Offer::Failure {
                key,
                why: failure_kind(field(offer, "why")),
                cd: false,
                follows,
            },
        );
    }
    let validation = vector_validation(field(offer, "validation"));
    let truncated = flag(offer, "truncated");
    // Stored and validated at once, so the RRSIGs' TTL counts from now.
    // A TTL with the top bit set reads as 0 (RFC 2181 §8).
    let signatures_expire = field(offer, "sig_expires").as_u64().map(at);
    let ttl_bound = field(offer, "original_ttl").as_u64().map(|ttl| {
        let ttl = if ttl & 0x8000_0000 != 0 { 0 } else { ttl };
        now + Duration::from_secs(ttl)
    });
    let secure_until = match (signatures_expire, ttl_bound) {
        (Some(expire), Some(ttl)) => Some(expire.min(ttl)),
        (expire, ttl) => expire.or(ttl),
    };
    match text(offer, "kind") {
        "positive" => {
            let set = vector_rrset(&texts(offer, "set"));
            let rank = rank(text(offer, "rank"));
            let key = Key::new(LowerName::new(set.name()), set.record_type(), DNSClass::IN);
            let ttl = if set.ttl() & 0x8000_0000 != 0 {
                0
            } else {
                set.ttl()
            };
            let fresh = now + Duration::from_secs(u64::from(ttl)).min(limits.max_ttl);
            let checked = Checked::Rrset(set.clone());
            cache.insert(
                now,
                Offer::Positive {
                    set,
                    rank,
                    validation,
                    proof: Vec::new(),
                    truncated,
                },
            );
            let stored = !truncated
                && matches!(
                    cache.get(&key, now),
                    Some(Entry::Positive { expires, rank: r, .. }) if *expires == fresh && *r == rank
                );
            if stored {
                cache.validated(&key, &checked, validation, secure_until, now);
            }
        }
        "negative" => {
            let soa = field(offer, "soa");
            let soa = (!soa.is_null()).then(|| {
                vector_rrset(
                    &soa.as_array()
                        .unwrap()
                        .iter()
                        .map(|l| l.as_str().unwrap().to_string())
                        .collect::<Vec<_>>(),
                )
            });
            let key = cache_key(field(offer, "key"));
            // A proven negative lives no longer than its NSEC records
            // (RFC 9077 §3); the offer carries their TTL.
            let denial: Vec<RecordSet> = field(offer, "denial_ttl")
                .as_u64()
                .map(|ttl| {
                    let mut set =
                        RecordSet::with_ttl(Name::from(&key.name), RecordType::NSEC, ttl as u32);
                    set.set_ttl(ttl as u32);
                    set
                })
                .into_iter()
                .collect();
            let kind = match text(offer, "negative") {
                "nxdomain" => Negative::NxDomain,
                _ => Negative::NoData,
            };
            let rank = rank(text(offer, "rank"));
            // An NXDOMAIN is kept under type ANY, and its result holds for
            // its copy under the type asked too.
            let stored_key = match kind {
                Negative::NxDomain => Key::new(key.name.clone(), RecordType::ANY, key.class),
                Negative::NoData => key.clone(),
            };
            let fresh = soa
                .as_ref()
                .map(|soa| now + cache.negative_ttl(soa, &denial));
            let checked = Checked::Denial {
                soa: soa.clone(),
                denial: denial.clone(),
            };
            cache.insert(
                now,
                Offer::Negative {
                    key,
                    kind,
                    soa,
                    rank,
                    denial,
                    validation,
                    truncated,
                },
            );
            let stored = !truncated
                && matches!(
                    cache.get(&stored_key, now),
                    Some(Entry::Negative { expires, rank: r, .. }) if Some(*expires) == fresh && *r == rank
                );
            if stored {
                cache.validated(&stored_key, &checked, validation, secure_until, now);
            }
        }
        other => panic!("no offer kind {other}"),
    }
}

// ---------------------------------------------------------------------
// resolver.json: the Resolver engine through MemoryNet
// ---------------------------------------------------------------------

/// The addresses the zones of a `resolver.json` case give each name, in
/// their data and in their glue.
fn server_addresses(zones: &[Zone]) -> BTreeMap<LowerName, BTreeSet<IpAddr>> {
    let mut addresses: BTreeMap<LowerName, BTreeSet<IpAddr>> = BTreeMap::new();
    for zone in zones {
        for (_, node) in zone.nodes() {
            let sets: Vec<&RecordSet> = match node {
                Node::Cut { glue, .. } => glue.iter().collect(),
                other => other.rrsets(),
            };
            for record in sets.iter().flat_map(|set| set.records_without_rrsigs()) {
                if let RData::A(a) = &record.data {
                    addresses
                        .entry(LowerName::new(&record.name))
                        .or_default()
                        .insert(IpAddr::V4(a.0));
                }
            }
        }
    }
    addresses
}

/// The hierarchy of a `resolver.json` case in a [`MemoryNet`]: each
/// address the zones' glue gives a name server serves every zone that
/// names that server, as one authoritative engine.
fn hierarchy(zones: &[Zone]) -> MemoryNet {
    let addresses = server_addresses(zones);
    let mut served: BTreeMap<IpAddr, Vec<Arc<dyn ZoneData>>> = BTreeMap::new();
    for zone in zones {
        let Some(Node::Data(sets)) = zone.node(zone.apex()) else {
            continue;
        };
        let Some(ns) = sets.get(&RecordType::NS) else {
            continue;
        };
        for record in ns.records_without_rrsigs() {
            let RData::NS(target) = &record.data else {
                continue;
            };
            for addr in addresses
                .get(&LowerName::new(&target.0))
                .into_iter()
                .flatten()
            {
                let list = served.entry(*addr).or_default();
                if !list.iter().any(|z| z.apex() == zone.apex()) {
                    list.push(Arc::new(zone.clone()));
                }
            }
        }
    }
    let mut net = MemoryNet::new();
    for (addr, zones) in served {
        let server = ServerConfig {
            ede: false,
            any: AnyResponse::All,
            ..ServerConfig::generic()
        };
        net.serve(
            addr,
            AuthorityEngine::new(Zones::new(zones), server, SocketAddr::new(addr, 53)),
        );
    }
    net
}

fn client() -> Client {
    Client {
        peer: "198.51.100.7:5300".parse().unwrap(),
        local: "192.0.2.53:53".parse().unwrap(),
        transport: Transport::Udp,
        connection: None,
        sandbox: None,
    }
}

/// A client's query for `question`, with RD and no EDNS.
fn client_query(question: &Value) -> ClientQuery {
    query_for(
        name(text(question, "qname")),
        RecordType::from(type_code(text(question, "qtype"))),
    )
}

/// A client's query for `qname` `qtype`, with RD and no EDNS.
fn query_for(qname: Name, qtype: RecordType) -> ClientQuery {
    let mut message = Message::new(4242, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(qname, qtype));
    ClientQuery {
        client: client(),
        bytes: message.to_vec().unwrap(),
    }
}

/// An answer as the resolver's client sees it, as text: the RCODE and the
/// answer and authority sections. TTLs are left out when `ttl` is false,
/// for answers given after a lost query made the resolver wait.
///
/// Lean's expected answer is the authoritative server's (`Resolver.spec`).
/// Its AA bit and its additional section are not compared: a resolver
/// clears AA (§9.7) and, like Unbound with its default
/// `minimal-responses: yes`, sends no additional data with an answer.
fn resolver_answer(message: &Message, ttl: bool) -> String {
    let lines = |records: &[Record]| -> BTreeSet<BTreeSet<String>> {
        let lines: Vec<String> = records
            .iter()
            .map(|r| {
                let mut r = r.clone();
                if !ttl {
                    r.ttl = 0;
                }
                zone_line(&r)
            })
            .collect();
        section(&lines)
    };
    format!(
        "{} answer {:?} authority {:?}",
        rcode_text(message.metadata.response_code),
        lines(&message.answers),
        lines(&message.authorities)
    )
}

fn lean_resolver_answer(value: &Value, ttl: bool) -> String {
    let lines = |key: &str| -> BTreeSet<BTreeSet<String>> {
        let lines: Vec<String> = texts(value, key)
            .iter()
            .map(|l| {
                if ttl {
                    l.clone()
                } else {
                    let mut tokens = tokens(l);
                    tokens[1] = "0".to_string();
                    tokens.join(" ")
                }
            })
            .collect();
        section(&lines)
    };
    format!(
        "{} answer {:?} authority {:?}",
        text(value, "rcode"),
        lines("answer"),
        lines("authority")
    )
}

/// The hierarchy's answer to `question`, as Lean's `Resolver.spec` defines
/// it, from [`answer`] over each zone: from the root down, the first
/// answer that is not a referral; SERVFAIL for a referral that does not go
/// strictly down toward the name, or to a cut with no zone.
fn hierarchy_answer(zones: &[Zone], question: &Value) -> Message {
    let qname = name(text(question, "qname"));
    let qtype = RecordType::from(type_code(text(question, "qtype")));
    let req = request(&qname, qtype, false);
    let servfail = || {
        let mut message = Message::response(req.message.metadata.id, OpCode::Query);
        message.metadata.response_code = ResponseCode::ServFail;
        message
    };
    let zone_at = |apex: &LowerName| zones.iter().find(|z| z.apex() == apex);
    let Some(mut zone) = zone_at(&LowerName::new(&Name::root())) else {
        return servfail();
    };
    loop {
        let Answered::Response(response) = answer(zone, &req, AnyResponse::All) else {
            return servfail();
        };
        let message = response.message;
        let referral = message.metadata.response_code == ResponseCode::NoError
            && !message.metadata.authoritative
            && message.answers.is_empty()
            && !message.authorities.is_empty()
            && message.authorities.iter().all(|r| {
                r.record_type() == RecordType::NS && r.name == message.authorities[0].name
            });
        if !referral {
            return message;
        }
        let cut = LowerName::new(&message.authorities[0].name);
        let descends = zone.apex().zone_of(&cut)
            && cut.num_labels() > zone.apex().num_labels()
            && cut.zone_of(&LowerName::new(&qname));
        match zone_at(&cut) {
            Some(below) if descends => zone = below,
            _ => return servfail(),
        }
    }
}

/// A resolver for a `resolver.json` case: the hints with their addresses
/// from the root zone, no QNAME minimisation, no validation, no case
/// randomisation, and `queries` as its work bound.
fn vector_resolver(input: &Value, zones: &[Zone], queries: u16) -> Resolver {
    let root = zones
        .iter()
        .find(|z| z.apex().is_root())
        .expect("a root zone");
    let mut hints = Vec::new();
    for hint in texts(input, "hints") {
        let owner = LowerName::new(&name(&hint));
        if let Some(Node::Data(sets)) = root.node(&owner)
            && let Some(set) = sets.get(&RecordType::A)
        {
            for record in set.records_without_rrsigs() {
                if let RData::A(a) = &record.data {
                    hints.push((name(&hint), IpAddr::V4(a.0)));
                }
            }
        }
    }
    let config = Config {
        hints,
        local: Vec::new(),
        minimise: None,
        anchors: None,
        ede: false,
        aggressive_nsec: false,
        any: AnyResponse::All,
        work: Work { queries, depth: 11 },
        ..unbound::config()
    };
    Resolver::new(
        config,
        Ring,
        WallClock {
            start: time(1_750_000_000),
        },
    )
    .unwrap()
}

#[test]
fn resolver() {
    each_case("resolver", |case, _| {
        let input = field(case, "input");
        let expected = field(case, "expected");
        let zones = list(input, "zones")
            .iter()
            .map(vector_zone)
            .collect::<Result<Vec<Zone>, String>>()?;
        let questions = list(input, "questions");
        let lean_answers = list(expected, "answers");
        let entropy = SeededEntropy::new(Seed::from_u64(53));

        // Nothing lost and work to spare: every answer is the hierarchy's
        // (`Resolver.spec`). By `resolve_correct` so is every Lean answer
        // that is not SERVFAIL, and with nothing lost and work for every
        // level, every Lean SERVFAIL too.
        let mut net = hierarchy(&zones);
        let mut whole = vector_resolver(input, &zones, 200);
        let losses: Vec<bool> = list(input, "losses")
            .iter()
            .map(|b| b.as_bool().unwrap())
            .collect();
        let lossless = losses.iter().all(|lost| !lost);
        for (question, lean) in questions.iter().zip(lean_answers) {
            let answers = drive(
                &mut whole,
                &mut net,
                vec![client_query(question)],
                Instant::ZERO,
                &entropy,
            );
            let message = Message::from_vec(&answers[0].bytes).map_err(|e| e.to_string())?;
            let rust = resolver_answer(&message, true);
            let hierarchy_answer = resolver_answer(&hierarchy_answer(&zones, question), true);
            same(
                "answer against the hierarchy",
                hierarchy_answer,
                rust.clone(),
            )?;
            if lean.is_null() {
                return Err("Lean gave no answer".to_string());
            }
            // A Lean answer other than SERVFAIL is the hierarchy's
            // (`resolve_correct`), whatever was lost and whatever work it
            // had; its SERVFAILs are compared under the same bound below.
            if text(lean, "rcode") != "SERVFAIL" {
                same("answer", lean_resolver_answer(lean, true), rust)?;
            }
        }

        // Nothing lost, under Lean's work bound: the same answers,
        // SERVFAILs included. Lean starts from the hints; the Rust
        // resolver first primes the root (RFC 8109), a query Lean does not
        // send, so it is primed before the questions.
        if lossless {
            let mut net = hierarchy(&zones);
            let mut bounded = vector_resolver(input, &zones, number(input, "work") as u16);
            drive(
                &mut bounded,
                &mut net,
                vec![query_for(Name::root(), RecordType::NS)],
                Instant::ZERO,
                &entropy,
            );
            for (question, lean) in questions.iter().zip(lean_answers) {
                let answers = drive(
                    &mut bounded,
                    &mut net,
                    vec![client_query(question)],
                    Instant::ZERO,
                    &entropy,
                );
                let message = Message::from_vec(&answers[0].bytes).map_err(|e| e.to_string())?;
                same(
                    "answer under the work bound",
                    lean_resolver_answer(lean, true),
                    resolver_answer(&message, true),
                )?;
            }
        }

        // What Lean cached is in the Rust cache at the same or a higher
        // rank: every cut's NS RRset, glue, and the RRsets of answers.
        let cache = whole.cache();
        for item in list(expected, "cache") {
            let rank_wanted = rank(text(item, "rank"));
            let sets: Vec<Vec<String>> = if let Some(cut) = item.get("cut") {
                vec![
                    cut.as_array()
                        .unwrap()
                        .iter()
                        .map(|l| l.as_str().unwrap().to_string())
                        .collect(),
                ]
            } else if let Some(glue) = item.get("glue") {
                vec![
                    glue.as_array()
                        .unwrap()
                        .iter()
                        .map(|l| l.as_str().unwrap().to_string())
                        .collect(),
                ]
            } else {
                let response = field(item, "response");
                rrsets_of(&texts(response, "answer"))
                    .into_iter()
                    .map(|(_, lines)| lines.into_iter().collect())
                    .collect()
            };
            for lines in sets {
                let set = vector_rrset(&lines);
                let key = Key::new(LowerName::new(set.name()), set.record_type(), DNSClass::IN);
                match cache.get(&key, Instant::ZERO) {
                    Some(Entry::Positive {
                        set: held, rank, ..
                    }) if *rank >= rank_wanted => {
                        // Data of a higher rank replaced what Lean holds,
                        // such as a zone's own NS RRset its parent's
                        // referral, with the zone's own TTL.
                        let ttl = |line: &String| -> String {
                            let mut tokens = tokens(line);
                            if *rank > rank_wanted {
                                tokens[1] = "0".to_string();
                            }
                            tokens.join(" ")
                        };
                        let held: BTreeSet<String> = held
                            .records_without_rrsigs()
                            .map(|r| ttl(&zone_line(r)))
                            .collect();
                        let wanted: BTreeSet<String> = lines.iter().map(ttl).collect();
                        same("cached RRset", wanted, held)?;
                    }
                    other => {
                        return Err(format!(
                            "Lean cached {lines:?} at {}; the Rust cache holds {other:?}",
                            text(item, "rank")
                        ));
                    }
                }
            }
        }

        // With the case's dead servers never answering, and work to spare:
        // the same answers as Lean's, SERVFAILs included. Lean drops a
        // server at its first loss and Rust after RFC 9520's three tries,
        // in either order, so both answer exactly when every zone on the
        // way has a server left.
        let addresses = server_addresses(&zones);
        let dead: BTreeSet<IpAddr> = texts(input, "dead")
            .iter()
            .flat_map(|server| {
                addresses
                    .get(&LowerName::new(&name(server)))
                    .into_iter()
                    .flatten()
                    .copied()
            })
            .collect();
        let mut net = hierarchy(&zones);
        net.lose(move |transmit| dead.contains(&transmit.to.ip()));
        let mut lossy = vector_resolver(input, &zones, 200);
        for (index, (question, lean)) in questions
            .iter()
            .zip(list(expected, "dead_answers"))
            .enumerate()
        {
            if lean.is_null() {
                return Err("Lean gave no answer with the dead servers".to_string());
            }
            // A dead server makes the resolver wait; each question starts
            // after the last one's waits are over, so TTLs are not compared.
            let start = at(600 * index as u64);
            let answers = drive(
                &mut lossy,
                &mut net,
                vec![client_query(question)],
                start,
                &entropy,
            );
            let message = Message::from_vec(&answers[0].bytes).map_err(|e| e.to_string())?;
            same(
                "answer with dead servers",
                lean_resolver_answer(lean, false),
                resolver_answer(&message, false),
            )?;
        }

        // The case's loss script, with work to spare. Lean gives up on a
        // server at its first lost query and Rust after RFC 9520's three
        // tries, and they pick servers in different orders, so a script of
        // lost sends means different servers to each. What carries over is
        // which servers each question lost: those stay silent for that
        // question in Rust, and the answers must be the same, SERVFAILs
        // included.
        let silent: Arc<Mutex<BTreeSet<IpAddr>>> = Arc::default();
        let mut net = hierarchy(&zones);
        let quiet = silent.clone();
        net.lose(move |transmit| quiet.lock().unwrap().contains(&transmit.to.ip()));
        let mut lossy = vector_resolver(input, &zones, 200);
        for (index, (question, lean)) in questions
            .iter()
            .zip(list(expected, "lossy_answers"))
            .enumerate()
        {
            if lean.is_null() {
                return Err("Lean gave no answer under the loss script".to_string());
            }
            *silent.lock().unwrap() = texts(lean, "gone")
                .iter()
                .flat_map(|server| {
                    addresses
                        .get(&LowerName::new(&name(server)))
                        .into_iter()
                        .flatten()
                        .copied()
                })
                .collect();
            // As with dead servers, each question starts after the last
            // one's failure has left the cache.
            let start = at(600 * index as u64);
            let answers = drive(
                &mut lossy,
                &mut net,
                vec![client_query(question)],
                start,
                &entropy,
            );
            let message = Message::from_vec(&answers[0].bytes).map_err(|e| e.to_string())?;
            same(
                "answer under the loss script",
                lean_resolver_answer(field(lean, "response"), false),
                resolver_answer(&message, false),
            )?;
        }
        Ok(())
    });
}
