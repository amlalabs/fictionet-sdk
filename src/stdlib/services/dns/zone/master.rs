//! Reading a zone from master file text (RFC 1035 §5), enough for the
//! real root zone as IANA publishes it.
//!
//! The text is split into entries here, with parentheses, quotes,
//! escapes, comments, and the `$ORIGIN` and `$TTL` directives. RDATA of
//! the types hickory reads from text goes through hickory's own parser.
//! DNSSEC types (DNSKEY, DS, RRSIG, NSEC, NSEC3, NSEC3PARAM, and their
//! CDS and CDNSKEY forms), DNAME, ZONEMD (RFC 8976), and the generic
//! `\# <length> <hex>` form of RFC 3597 are written to wire format here
//! and decoded by hickory.

// A zone error names the owners it is about. It comes once per read,
// never on a path that answers questions, so its size costs nothing.
#![allow(clippy::result_large_err)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::str::FromStr;

use fictionet::stdlib::protocols::dns::rr::{
    LowerName, Name, RData, Record, RecordSet, RecordType,
};
use fictionet::stdlib::protocols::dns::serialize::binary::{BinDecoder, Restrict};
use fictionet::stdlib::protocols::dns::serialize::txt::{Parser, parse_ttl};
use hickory_proto::dnssec::rdata::DNSSECRData;

use super::zone::{Zone, ZoneBuilder, ZoneError};

/// Why master file text did not read. [`ZoneError::Master`] gives the
/// line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MasterError {
    /// A quoted string that never closes.
    UnclosedQuote,
    /// A `(` that never closes, or a `)` with no `(`.
    UnbalancedParentheses,
    /// A `$` directive other than `$ORIGIN`, `$TTL`, and `$INCLUDE`.
    UnknownDirective,
    /// `$INCLUDE`, which would read another file. A world joins the texts
    /// itself.
    Include,
    /// A record that starts with a blank before any owner was named.
    NoOwner,
    /// A name that does not read, or a relative name with no origin.
    BadName,
    /// A TTL that does not read.
    BadTtl,
    /// A record with no TTL of its own, no `$TTL`, and no earlier TTL to
    /// take.
    NoTtl,
    /// A record without a type.
    NoType,
    /// A type that is neither a known mnemonic nor `TYPE<number>`
    /// (RFC 3597 §5).
    UnknownType,
    /// A class other than IN.
    Class,
    /// RDATA that does not read as its type.
    Rdata {
        /// The record's type.
        rtype: RecordType,
    },
    /// No SOA record.
    NoSoa,
    /// A second SOA record.
    SecondSoa,
    /// An RRSIG whose RRset is not in the text.
    SignatureWithoutRrset {
        /// The type the RRSIG covers.
        covered: RecordType,
    },
}

impl fmt::Display for MasterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MasterError::UnclosedQuote => f.write_str("a quoted string does not close"),
            MasterError::UnbalancedParentheses => f.write_str("parentheses do not balance"),
            MasterError::UnknownDirective => f.write_str("an unknown $ directive"),
            MasterError::Include => f.write_str("$INCLUDE is not read"),
            MasterError::NoOwner => f.write_str("a record has no owner"),
            MasterError::BadName => f.write_str("a name does not read"),
            MasterError::BadTtl => f.write_str("a TTL does not read"),
            MasterError::NoTtl => f.write_str("a record has no TTL"),
            MasterError::NoType => f.write_str("a record has no type"),
            MasterError::UnknownType => f.write_str("an unknown record type"),
            MasterError::Class => f.write_str("a class other than IN"),
            MasterError::Rdata { rtype } => write!(f, "{rtype} RDATA does not read"),
            MasterError::NoSoa => f.write_str("there is no SOA record"),
            MasterError::SecondSoa => f.write_str("a second SOA record"),
            MasterError::SignatureWithoutRrset { covered } => {
                write!(f, "an RRSIG covers {covered} records that are not here")
            }
        }
    }
}

impl std::error::Error for MasterError {}

impl Zone {
    /// The zone in master file `text` (RFC 1035 §5). `origin` is the
    /// origin before any `$ORIGIN`. The SOA record's owner is the apex.
    ///
    /// A record without a TTL takes the last `$TTL`, or else the TTL of
    /// the record before it (RFC 2308 §4). RRSIGs join the RRsets they
    /// cover. The zone is checked like any other, so the public root zone
    /// (`https://www.internic.net/domain/root.zone`) reads as a complete
    /// zone a world can edit and sign.
    pub fn from_master(text: &str, origin: Option<Name>) -> Result<Zone, ZoneError> {
        let entries = lex(text)?;
        let mut reader = Reader {
            origin,
            default_ttl: None,
            last_ttl: None,
            owner: None,
        };
        let mut records = Vec::new();
        for entry in &entries {
            let at = |error| ZoneError::Master {
                line: entry.line,
                error,
            };
            if let Some(record) = reader.read(entry).map_err(at)? {
                records.push((entry.line, record));
            }
        }
        assemble(records, text.lines().count().max(1))
    }
}

/// One entry: the tokens of one line, or of several joined by
/// parentheses.
struct Entry {
    /// The line it starts on.
    line: usize,
    /// It starts with a blank, so its owner is the last one named.
    blank: bool,
    /// Its tokens as written, quotes and escapes kept.
    tokens: Vec<String>,
}

/// Splits `text` into entries (RFC 1035 §5.1).
fn lex(text: &str) -> Result<Vec<Entry>, ZoneError> {
    let mut entries = Vec::new();
    let mut line = 1;
    let mut depth = 0usize;
    let mut token = String::new();
    let mut entry = Entry {
        line,
        blank: false,
        tokens: Vec::new(),
    };
    let mut at_start = true;
    let mut chars = text.chars().peekable();
    let fail = |line, error| ZoneError::Master { line, error };
    let end_token = |token: &mut String, entry: &mut Entry| {
        if !token.is_empty() {
            entry.tokens.push(std::mem::take(token));
        }
    };

    while let Some(c) = chars.next() {
        if at_start {
            at_start = false;
            entry = Entry {
                line,
                blank: c == ' ' || c == '\t',
                tokens: Vec::new(),
            };
        }
        match c {
            '"' => {
                let opened = line;
                token.push(c);
                loop {
                    match chars.next() {
                        None => return Err(fail(opened, MasterError::UnclosedQuote)),
                        Some('\\') => {
                            token.push('\\');
                            if let Some(escaped) = chars.next() {
                                line += usize::from(escaped == '\n');
                                token.push(escaped);
                            }
                        }
                        Some('"') => {
                            token.push('"');
                            break;
                        }
                        Some(inner) => {
                            line += usize::from(inner == '\n');
                            token.push(inner);
                        }
                    }
                }
            }
            '\\' => {
                token.push('\\');
                if let Some(escaped) = chars.next() {
                    line += usize::from(escaped == '\n');
                    token.push(escaped);
                }
            }
            ';' => while chars.next_if(|&next| next != '\n').is_some() {},
            '(' => {
                end_token(&mut token, &mut entry);
                depth += 1;
            }
            ')' => {
                end_token(&mut token, &mut entry);
                if depth == 0 {
                    return Err(fail(line, MasterError::UnbalancedParentheses));
                }
                depth -= 1;
            }
            '\n' => {
                end_token(&mut token, &mut entry);
                line += 1;
                if depth == 0 {
                    if !entry.tokens.is_empty() {
                        entries.push(std::mem::replace(
                            &mut entry,
                            Entry {
                                line,
                                blank: false,
                                tokens: Vec::new(),
                            },
                        ));
                    }
                    at_start = true;
                }
            }
            ' ' | '\t' | '\r' => end_token(&mut token, &mut entry),
            _ => token.push(c),
        }
    }
    end_token(&mut token, &mut entry);
    if depth > 0 {
        return Err(fail(line, MasterError::UnbalancedParentheses));
    }
    if !entry.tokens.is_empty() {
        entries.push(entry);
    }
    Ok(entries)
}

/// The state that carries from one entry to the next.
struct Reader {
    origin: Option<Name>,
    default_ttl: Option<u32>,
    last_ttl: Option<u32>,
    owner: Option<Name>,
}

impl Reader {
    /// Reads one entry: a directive, which gives no record, or a record.
    fn read(&mut self, entry: &Entry) -> Result<Option<Record>, MasterError> {
        let tokens = &entry.tokens;
        if !entry.blank && tokens[0].starts_with('$') {
            let argument = tokens.get(1).map(String::as_str);
            match tokens[0].to_ascii_uppercase().as_str() {
                "$ORIGIN" => {
                    let origin =
                        absolute(argument.ok_or(MasterError::BadName)?, self.origin.as_ref());
                    self.origin = Some(origin.ok_or(MasterError::BadName)?);
                }
                "$TTL" => {
                    let ttl = parse_ttl(argument.ok_or(MasterError::BadTtl)?);
                    self.default_ttl = Some(ttl.map_err(|_| MasterError::BadTtl)?);
                }
                "$INCLUDE" => return Err(MasterError::Include),
                _ => return Err(MasterError::UnknownDirective),
            }
            return Ok(None);
        }

        let (owner, mut rest) = if entry.blank {
            (self.owner.clone().ok_or(MasterError::NoOwner)?, &tokens[..])
        } else {
            let owner = absolute(&tokens[0], self.origin.as_ref()).ok_or(MasterError::BadName)?;
            (owner, &tokens[1..])
        };
        self.owner = Some(owner.clone());

        // A TTL and a class may come before the type, in either order.
        let mut ttl = None;
        let mut class = None;
        let rtype = loop {
            let (token, more) = rest.split_first().ok_or(MasterError::NoType)?;
            rest = more;
            if ttl.is_none() && token.starts_with(|c: char| c.is_ascii_digit()) {
                ttl = Some(parse_ttl(token).map_err(|_| MasterError::BadTtl)?);
            } else if let (None, Some(internet)) = (class, is_internet(token)) {
                class = Some(internet);
            } else {
                break record_type(token).ok_or(MasterError::UnknownType)?;
            }
        };
        if class == Some(false) {
            return Err(MasterError::Class);
        }
        let ttl = match ttl {
            Some(ttl) => {
                self.last_ttl = Some(ttl);
                ttl
            }
            None => self
                .default_ttl
                .or(self.last_ttl)
                .ok_or(MasterError::NoTtl)?,
        };
        let data = rdata(rtype, rest, self.origin.as_ref(), &owner)?;
        Ok(Some(Record::from_rdata(owner, ttl, data)))
    }
}

/// Gathers records into RRsets, joins RRSIGs to what they cover, and
/// builds the zone. `lines` is where a missing SOA is reported.
fn assemble(records: Vec<(usize, Record)>, lines: usize) -> Result<Zone, ZoneError> {
    let mut soa: Option<Record> = None;
    let mut sets: BTreeMap<(LowerName, RecordType), Vec<Record>> = BTreeMap::new();
    let mut rrsigs = Vec::new();
    for (line, record) in records {
        let owner = LowerName::new(&record.name);
        match &record.data {
            RData::SOA(_) if soa.is_some() => {
                return Err(ZoneError::Master {
                    line,
                    error: MasterError::SecondSoa,
                });
            }
            RData::SOA(_) => soa = Some(record),
            RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) => {
                let covered = rrsig.input().type_covered;
                rrsigs.push((line, (owner, covered), record));
            }
            _ => sets
                .entry((owner, record.record_type()))
                .or_default()
                .push(record),
        }
    }
    let soa = soa.ok_or(ZoneError::Master {
        line: lines,
        error: MasterError::NoSoa,
    })?;
    let apex = soa.name.clone();
    let mut soa_set = rrset(vec![soa]);

    let mut sets: BTreeMap<(LowerName, RecordType), RecordSet> = sets
        .into_iter()
        .map(|(key, records)| (key, rrset(records)))
        .collect();
    for (line, key, rrsig) in rrsigs {
        let set = if key == (LowerName::new(&apex), RecordType::SOA) {
            &mut soa_set
        } else {
            sets.get_mut(&key).ok_or(ZoneError::Master {
                line,
                error: MasterError::SignatureWithoutRrset { covered: key.1 },
            })?
        };
        set.insert_rrsig(rrsig);
    }

    sets.into_values()
        .fold(ZoneBuilder::with_soa(apex, soa_set), ZoneBuilder::rrset)
        .build()
}

/// The RRset of `records`, which share an owner and type. The builder
/// collapses duplicates and checks their TTLs.
fn rrset(records: Vec<Record>) -> RecordSet {
    let first = &records[0];
    let mut set = RecordSet::with_ttl(first.name.clone(), first.record_type(), first.ttl);
    set.set_records(records);
    set
}

/// `token` as an absolute name: `@` is the origin, and a name without a
/// final dot is relative to it (RFC 1035 §5.1).
fn absolute(token: &str, origin: Option<&Name>) -> Option<Name> {
    if token == "@" {
        return origin.cloned();
    }
    Name::parse(token, origin)
        .ok()
        .filter(|name| name.is_fqdn())
}

/// Whether `token` names the IN class, `None` when it names no class.
fn is_internet(token: &str) -> Option<bool> {
    let upper = token.to_ascii_uppercase();
    match upper.as_str() {
        "IN" => Some(true),
        "CH" | "CS" | "HS" | "NONE" | "ANY" => Some(false),
        _ => upper
            .strip_prefix("CLASS")
            .and_then(|number| number.parse::<u16>().ok())
            .map(|number| number == 1),
    }
}

/// A type mnemonic, or `TYPE<number>` (RFC 3597 §5).
fn record_type(token: &str) -> Option<RecordType> {
    let upper = token.to_ascii_uppercase();
    if let Some(number) = upper.strip_prefix("TYPE") {
        return number.parse::<u16>().ok().map(RecordType::from);
    }
    match upper.as_str() {
        // ZONEMD (RFC 8976), which hickory has no mnemonic for.
        "ZONEMD" => Some(RecordType::from(ZONEMD)),
        _ => RecordType::from_str(&upper).ok(),
    }
}

/// The ZONEMD type code (RFC 8976 §2).
const ZONEMD: u16 = 63;

/// The RDATA of a record of `rtype` from its tokens.
fn rdata(
    rtype: RecordType,
    tokens: &[String],
    origin: Option<&Name>,
    owner: &Name,
) -> Result<RData, MasterError> {
    let bad = || MasterError::Rdata { rtype };
    let mut fields = Fields { tokens, at: 0 };
    let mut wire = Vec::new();

    if tokens.first().is_some_and(|token| token == "\\#") {
        // RFC 3597 §5: `\# <length> <hex>`.
        fields.next().ok_or_else(bad)?;
        let length: usize = fields.number().ok_or_else(bad)?;
        wire = hex(fields.rest()).ok_or_else(bad)?;
        if wire.len() != length {
            return Err(bad());
        }
        return decode(rtype, &wire);
    }

    match u16::from(rtype) {
        // KEY, DNSKEY, CDNSKEY (RFC 4034 §2.2, RFC 7344 §3.2)
        25 | 48 | 60 => {
            wire.extend(fields.number::<u16>().ok_or_else(bad)?.to_be_bytes());
            wire.push(fields.number::<u8>().ok_or_else(bad)?);
            wire.push(fields.number::<u8>().ok_or_else(bad)?);
            wire.extend(base64(fields.rest()).ok_or_else(bad)?);
        }
        // DS, CDS (RFC 4034 §5.3, RFC 7344 §3.1)
        43 | 59 => {
            wire.extend(fields.number::<u16>().ok_or_else(bad)?.to_be_bytes());
            wire.push(fields.number::<u8>().ok_or_else(bad)?);
            wire.push(fields.number::<u8>().ok_or_else(bad)?);
            wire.extend(hex(fields.rest()).ok_or_else(bad)?);
        }
        // RRSIG (RFC 4034 §3.2)
        46 => {
            let covered = record_type(fields.next().ok_or_else(bad)?).ok_or_else(bad)?;
            wire.extend(u16::from(covered).to_be_bytes());
            wire.push(fields.number::<u8>().ok_or_else(bad)?);
            wire.push(fields.number::<u8>().ok_or_else(bad)?);
            wire.extend(fields.number::<u32>().ok_or_else(bad)?.to_be_bytes());
            wire.extend(
                signature_time(fields.next().ok_or_else(bad)?)
                    .ok_or_else(bad)?
                    .to_be_bytes(),
            );
            wire.extend(
                signature_time(fields.next().ok_or_else(bad)?)
                    .ok_or_else(bad)?
                    .to_be_bytes(),
            );
            wire.extend(fields.number::<u16>().ok_or_else(bad)?.to_be_bytes());
            let signer = absolute(fields.next().ok_or_else(bad)?, origin).ok_or_else(bad)?;
            write_name(&mut wire, &signer);
            wire.extend(base64(fields.rest()).ok_or_else(bad)?);
        }
        // NSEC (RFC 4034 §4.2)
        47 => {
            let next = absolute(fields.next().ok_or_else(bad)?, origin).ok_or_else(bad)?;
            write_name(&mut wire, &next);
            wire.extend(type_bitmap(fields.rest()).ok_or_else(bad)?);
        }
        // NSEC3 and NSEC3PARAM (RFC 5155 §3.3 and §4.3)
        50 | 51 => {
            wire.push(fields.number::<u8>().ok_or_else(bad)?);
            wire.push(fields.number::<u8>().ok_or_else(bad)?);
            wire.extend(fields.number::<u16>().ok_or_else(bad)?.to_be_bytes());
            let salt = match fields.next().ok_or_else(bad)? {
                "-" => Vec::new(),
                salt => hex(&[salt.to_string()]).ok_or_else(bad)?,
            };
            wire.push(u8::try_from(salt.len()).map_err(|_| bad())?);
            wire.extend(salt);
            if u16::from(rtype) == 50 {
                let next = base32hex(fields.next().ok_or_else(bad)?).ok_or_else(bad)?;
                wire.push(u8::try_from(next.len()).map_err(|_| bad())?);
                wire.extend(next);
                wire.extend(type_bitmap(fields.rest()).ok_or_else(bad)?);
            }
        }
        // DNAME (RFC 6672 §2.1)
        39 => {
            let target = absolute(fields.next().ok_or_else(bad)?, origin).ok_or_else(bad)?;
            write_name(&mut wire, &target);
        }
        // ZONEMD (RFC 8976 §2.3)
        ZONEMD => {
            wire.extend(fields.number::<u32>().ok_or_else(bad)?.to_be_bytes());
            wire.push(fields.number::<u8>().ok_or_else(bad)?);
            wire.push(fields.number::<u8>().ok_or_else(bad)?);
            wire.extend(hex(fields.rest()).ok_or_else(bad)?);
        }
        _ => return hickory_text(rtype, tokens, origin, owner),
    }
    if !fields.rest().is_empty() {
        return Err(bad());
    }
    decode(rtype, &wire)
}

/// RDATA read by hickory's own master file parser, one record at a time.
fn hickory_text(
    rtype: RecordType,
    tokens: &[String],
    origin: Option<&Name>,
    owner: &Name,
) -> Result<RData, MasterError> {
    let bad = || MasterError::Rdata { rtype };
    // Every other type hickory does not read from text needs the generic
    // form.
    if matches!(rtype, RecordType::Unknown(_)) {
        return Err(bad());
    }
    // hickory's parser reads one line here. A line break inside a quoted
    // string would start another line, where `$INCLUDE` would make it
    // read a file.
    if tokens.iter().any(|token| token.contains(['\n', '\r'])) {
        return Err(bad());
    }
    let line = format!("{owner} 0 IN {rtype} {}\n", tokens.join(" "));
    let origin = origin.cloned().unwrap_or_else(Name::root);
    let (_, sets) = Parser::new(line, None, Some(origin))
        .parse()
        .map_err(|_| bad())?;
    sets.into_values()
        .next()
        .and_then(|set| set.records_without_rrsigs().next().map(|r| r.data.clone()))
        .ok_or_else(bad)
}

/// RDATA of `rtype` from its wire form.
fn decode(rtype: RecordType, wire: &[u8]) -> Result<RData, MasterError> {
    let bad = || MasterError::Rdata { rtype };
    let length = u16::try_from(wire.len()).map_err(|_| bad())?;
    let mut decoder = BinDecoder::new(wire);
    RData::read(&mut decoder, rtype, Restrict::new(length)).map_err(|_| bad())
}

/// The RDATA tokens of one record, read left to right.
struct Fields<'a> {
    tokens: &'a [String],
    at: usize,
}

impl<'a> Fields<'a> {
    fn next(&mut self) -> Option<&'a str> {
        let token = self.tokens.get(self.at)?;
        self.at += 1;
        Some(token)
    }

    fn number<T: FromStr>(&mut self) -> Option<T> {
        self.next()?.parse().ok()
    }

    /// The tokens not read yet. Reading them all is up to the caller.
    fn rest(&mut self) -> &'a [String] {
        let rest = &self.tokens[self.at..];
        self.at = self.tokens.len();
        rest
    }
}

/// Writes `name` uncompressed, keeping its case.
fn write_name(wire: &mut Vec<u8>, name: &Name) {
    for label in name.iter() {
        wire.push(label.len() as u8);
        wire.extend_from_slice(label);
    }
    wire.push(0);
}

/// An NSEC or NSEC3 type bitmap: windows of 256 types, each written up to
/// its last type present (RFC 4034 §4.1.2).
fn type_bitmap(tokens: &[String]) -> Option<Vec<u8>> {
    let types = tokens
        .iter()
        .map(|token| record_type(token).map(u16::from))
        .collect::<Option<BTreeSet<u16>>>()?;
    let mut windows: BTreeMap<u8, [u8; 32]> = BTreeMap::new();
    for code in types {
        let [window, low] = code.to_be_bytes();
        windows.entry(window).or_insert([0; 32])[usize::from(low / 8)] |= 0x80 >> (low % 8);
    }
    let mut wire = Vec::new();
    for (window, bits) in windows {
        let length = bits
            .iter()
            .rposition(|&byte| byte != 0)
            .map_or(0, |last| last + 1);
        wire.push(window);
        wire.push(length as u8);
        wire.extend_from_slice(&bits[..length]);
    }
    Some(wire)
}

/// An RRSIG time: `YYYYMMDDHHmmSS` in UTC, or seconds since 1970, either
/// way taken modulo 2^32 (RFC 4034 §3.1.5, §3.2).
fn signature_time(token: &str) -> Option<u32> {
    if token.len() != 14 || !token.bytes().all(|b| b.is_ascii_digit()) {
        return token.parse().ok();
    }
    let field = |range: std::ops::Range<usize>| token[range].parse::<i64>().ok();
    let (year, month, day) = (field(0..4)?, field(4..6)?, field(6..8)?);
    let (hour, minute, second) = (field(8..10)?, field(10..12)?, field(12..14)?);
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    let seconds = days_since_epoch(year, month, day) * 86400 + hour * 3600 + minute * 60 + second;
    Some(seconds.rem_euclid(1 << 32) as u32)
}

/// Days from 1970-01-01 to a date of the proleptic Gregorian calendar.
fn days_since_epoch(year: i64, month: i64, day: i64) -> i64 {
    // Years start in March, so the leap day ends one.
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let day_of_year = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146097 + day_of_era - 719468
}

/// Bytes from hexadecimal digits spread over tokens.
fn hex(tokens: &[String]) -> Option<Vec<u8>> {
    let digits: Vec<u8> = tokens
        .iter()
        .flat_map(|token| token.bytes())
        .map(|b| char::from(b).to_digit(16).map(|d| d as u8))
        .collect::<Option<_>>()?;
    if !digits.len().is_multiple_of(2) {
        return None;
    }
    Some(
        digits
            .chunks(2)
            .map(|pair| pair[0] << 4 | pair[1])
            .collect(),
    )
}

/// Bytes from base64 spread over tokens (RFC 4648 §4).
fn base64(tokens: &[String]) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0;
    for c in tokens.iter().flat_map(|token| token.bytes()) {
        let value = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => continue,
            _ => return None,
        };
        buffer = (buffer << 6 | u32::from(value)) & 0xffff;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            bytes.push((buffer >> bits) as u8);
        }
    }
    Some(bytes)
}

/// Bytes from base32 with the extended hex alphabet, unpadded, either case
/// (RFC 4648 §7), as NSEC3 writes the next hashed owner.
fn base32hex(token: &str) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0;
    for c in token.bytes() {
        let value = char::from(c).to_digit(32)?;
        buffer = (buffer << 5 | value) & 0xffff;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            bytes.push((buffer >> bits) as u8);
        }
    }
    Some(bytes)
}
