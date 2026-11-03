//! Reading a zone from master file text (RFC 1035 §5), enough for the
//! real root zone as IANA publishes it.
//!
//! The text is split into entries here, with parentheses, quotes,
//! escapes, comments, and the `$ORIGIN` and `$TTL` directives. Names are
//! read here, as BIND reads them: `@`, `\DDD` and `\X` escapes, and any
//! octets in a label. Character-strings are read the same way. The types
//! whose RDATA is names and numbers (NS, CNAME, PTR, DNAME, MX, SRV, SOA),
//! the types that hold character-strings (TXT, SPF, HINFO, CAA, NAPTR,
//! SVCB, HTTPS), the DNSSEC types (DNSKEY, DS, RRSIG, NSEC, NSEC3,
//! NSEC3PARAM, and their CDS and CDNSKEY forms), ZONEMD (RFC 8976), and
//! the generic `\# <length> <hex>` form of RFC 3597 are written to wire
//! format here and decoded by hickory. RDATA of the other types hickory
//! reads from text goes through hickory's own parser.

// A zone error names the owners it is about. It comes once per read,
// never on a path that answers questions, so its size costs nothing.
#![allow(clippy::result_large_err)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use fictionet::stdlib::protocols::dns::dnssec::proof::base32hex;
use fictionet::stdlib::protocols::dns::dnssec::rdata::DNSSECRData;
use fictionet::stdlib::protocols::dns::rr::rdata::svcb::SvcParamKey;
use fictionet::stdlib::protocols::dns::rr::{
    LowerName, Name, RData, Record, RecordSet, RecordType,
};
use fictionet::stdlib::protocols::dns::serialize::binary::{BinDecoder, Restrict};
use fictionet::stdlib::protocols::dns::serialize::txt::{Parser, parse_ttl};

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
        let data = rdata(rtype, rest, self.origin.as_ref())?;
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

/// The name `token` in RDATA, as [`absolute`] reads it. A relative name
/// with no origin is [`MasterError::BadName`], as it is for an owner
/// (RFC 1035 §5.1); a name that does not read is `bad`.
fn rdata_name(
    token: &str,
    origin: Option<&Name>,
    bad: impl Fn() -> MasterError,
) -> Result<Name, MasterError> {
    match absolute(token, origin) {
        Some(name) => Ok(name),
        None if origin.is_none() && absolute(token, Some(&Name::root())).is_some() => {
            Err(MasterError::BadName)
        }
        None => Err(bad()),
    }
}

/// `token` as an absolute name (RFC 1035 §5.1): `@` is the origin, and a
/// name without a final dot is relative to it. Inside a label, `\DDD` is
/// the octet with that decimal value and `\X` is X itself, such as an
/// escaped dot, and every other character stands for its own octets, so
/// a label may be any octet string (RFC 2181 §11), as BIND reads it. The
/// case is kept.
fn absolute(token: &str, origin: Option<&Name>) -> Option<Name> {
    if token == "@" {
        return origin.cloned();
    }
    if token == "." {
        return Some(Name::root());
    }
    let mut labels: Vec<Vec<u8>> = Vec::new();
    let mut label = Vec::new();
    // Whether the last character read was a dot that ends a label.
    let mut dotted = false;
    let mut bytes = token.bytes();
    while let Some(byte) = bytes.next() {
        dotted = false;
        match byte {
            b'.' => {
                if label.is_empty() {
                    return None;
                }
                labels.push(std::mem::take(&mut label));
                dotted = true;
            }
            b'\\' => {
                let escaped = bytes.next()?;
                if escaped.is_ascii_digit() {
                    let digits = [escaped, bytes.next()?, bytes.next()?];
                    if !digits.iter().all(u8::is_ascii_digit) {
                        return None;
                    }
                    let value = digits
                        .iter()
                        .fold(0u16, |value, digit| value * 10 + u16::from(digit - b'0'));
                    label.push(u8::try_from(value).ok()?);
                } else {
                    label.push(escaped);
                }
            }
            _ => label.push(byte),
        }
    }
    if !label.is_empty() {
        labels.push(label);
    }
    // hickory refuses a name past 255 octets on the wire (RFC 1035
    // §2.3.4).
    let name = Name::from_labels(labels.iter().map(Vec::as_slice)).ok()?;
    if dotted {
        Some(name)
    } else {
        name.append_name(origin?).ok()
    }
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
            wire.push(algorithm(fields.next().ok_or_else(bad)?).ok_or_else(bad)?);
            wire.extend(base64(fields.rest()).ok_or_else(bad)?);
        }
        // DS, CDS (RFC 4034 §5.3, RFC 7344 §3.1)
        43 | 59 => {
            wire.extend(fields.number::<u16>().ok_or_else(bad)?.to_be_bytes());
            wire.push(algorithm(fields.next().ok_or_else(bad)?).ok_or_else(bad)?);
            wire.push(fields.number::<u8>().ok_or_else(bad)?);
            wire.extend(hex(fields.rest()).ok_or_else(bad)?);
        }
        // RRSIG (RFC 4034 §3.2)
        46 => {
            let covered = record_type(fields.next().ok_or_else(bad)?).ok_or_else(bad)?;
            wire.extend(u16::from(covered).to_be_bytes());
            wire.push(algorithm(fields.next().ok_or_else(bad)?).ok_or_else(bad)?);
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
            let signer = rdata_name(fields.next().ok_or_else(bad)?, origin, bad)?;
            write_name(&mut wire, &signer);
            wire.extend(base64(fields.rest()).ok_or_else(bad)?);
        }
        // NSEC (RFC 4034 §4.2)
        47 => {
            let next = rdata_name(fields.next().ok_or_else(bad)?, origin, bad)?;
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
                let next = base32hex(fields.next().ok_or_else(bad)?.as_bytes()).ok_or_else(bad)?;
                wire.push(u8::try_from(next.len()).map_err(|_| bad())?);
                wire.extend(next);
                wire.extend(type_bitmap(fields.rest()).ok_or_else(bad)?);
            }
        }
        // NS, CNAME, PTR (RFC 1035 §3.3.11, §3.3.1, §3.3.12) and DNAME
        // (RFC 6672 §2.1): one name.
        2 | 5 | 12 | 39 => {
            let target = rdata_name(fields.next().ok_or_else(bad)?, origin, bad)?;
            write_name(&mut wire, &target);
        }
        // MX (RFC 1035 §3.3.9): a preference and an exchange.
        15 => {
            wire.extend(fields.number::<u16>().ok_or_else(bad)?.to_be_bytes());
            let exchange = rdata_name(fields.next().ok_or_else(bad)?, origin, bad)?;
            write_name(&mut wire, &exchange);
        }
        // SRV (RFC 2782): a priority, a weight, a port, and a target.
        33 => {
            for _ in 0..3 {
                wire.extend(fields.number::<u16>().ok_or_else(bad)?.to_be_bytes());
            }
            let target = rdata_name(fields.next().ok_or_else(bad)?, origin, bad)?;
            write_name(&mut wire, &target);
        }
        // SOA (RFC 1035 §3.3.13): two names, the serial, and four times,
        // which may be written as TTLs are, such as `1h` (RFC 2308 §4).
        6 => {
            for _ in 0..2 {
                let name = rdata_name(fields.next().ok_or_else(bad)?, origin, bad)?;
                write_name(&mut wire, &name);
            }
            wire.extend(fields.number::<u32>().ok_or_else(bad)?.to_be_bytes());
            for _ in 0..4 {
                let time = parse_ttl(fields.next().ok_or_else(bad)?).map_err(|_| bad())?;
                wire.extend(time.to_be_bytes());
            }
        }
        // ZONEMD (RFC 8976 §2.3)
        ZONEMD => {
            wire.extend(fields.number::<u32>().ok_or_else(bad)?.to_be_bytes());
            wire.push(fields.number::<u8>().ok_or_else(bad)?);
            wire.push(fields.number::<u8>().ok_or_else(bad)?);
            wire.extend(hex(fields.rest()).ok_or_else(bad)?);
        }
        // TXT (RFC 1035 §3.3.14) and SPF (RFC 7208 §3.1): one or more
        // character-strings.
        16 | 99 => {
            let strings = fields.rest();
            if strings.is_empty() {
                return Err(bad());
            }
            for token in strings {
                write_string(&mut wire, token).ok_or_else(bad)?;
            }
        }
        // HINFO (RFC 1035 §3.3.2): the CPU and the OS.
        13 => {
            for _ in 0..2 {
                write_string(&mut wire, fields.next().ok_or_else(bad)?).ok_or_else(bad)?;
            }
        }
        // CAA (RFC 8659 §4.1.1): the flags, the tag, and the value, which
        // takes the rest of the RDATA.
        257 => {
            wire.push(fields.number::<u8>().ok_or_else(bad)?);
            write_string(&mut wire, fields.next().ok_or_else(bad)?).ok_or_else(bad)?;
            wire.extend(octets(fields.next().ok_or_else(bad)?).ok_or_else(bad)?);
        }
        // NAPTR (RFC 3403 §4.1): the order, the preference, the flags,
        // the services, the regular expression, and the replacement.
        35 => {
            for _ in 0..2 {
                wire.extend(fields.number::<u16>().ok_or_else(bad)?.to_be_bytes());
            }
            for _ in 0..3 {
                write_string(&mut wire, fields.next().ok_or_else(bad)?).ok_or_else(bad)?;
            }
            let replacement = rdata_name(fields.next().ok_or_else(bad)?, origin, bad)?;
            write_name(&mut wire, &replacement);
        }
        // SVCB and HTTPS (RFC 9460 §2.1): the priority, the target, and
        // the SvcParams.
        64 | 65 => {
            wire.extend(fields.number::<u16>().ok_or_else(bad)?.to_be_bytes());
            let target = rdata_name(fields.next().ok_or_else(bad)?, origin, bad)?;
            write_name(&mut wire, &target);
            wire.extend(svc_params(fields.rest()).ok_or_else(bad)?);
        }
        _ => return hickory_line(rtype, tokens, origin),
    }
    if !fields.rest().is_empty() {
        return Err(bad());
    }
    decode(rtype, &wire)
}

/// The octets of a character-string (RFC 1035 §5.1), in quotes or not:
/// `\DDD` is the octet with that decimal value, `\X` is X itself, and
/// every other character stands for its own octets, as BIND reads it.
/// `None` for a string that does not read.
fn octets(token: &str) -> Option<Vec<u8>> {
    let text = match token.strip_prefix('"') {
        Some(rest) => rest.strip_suffix('"')?,
        None => token,
    };
    let mut out = Vec::new();
    let mut bytes = text.bytes();
    while let Some(byte) = bytes.next() {
        match byte {
            b'\\' => {
                let escaped = bytes.next()?;
                if escaped.is_ascii_digit() {
                    let digits = [escaped, bytes.next()?, bytes.next()?];
                    if !digits.iter().all(u8::is_ascii_digit) {
                        return None;
                    }
                    let value = digits
                        .iter()
                        .fold(0u16, |value, digit| value * 10 + u16::from(digit - b'0'));
                    out.push(u8::try_from(value).ok()?);
                } else {
                    out.push(escaped);
                }
            }
            // A quote or a line break inside a string must be escaped.
            b'"' | b'\n' => return None,
            _ => out.push(byte),
        }
    }
    Some(out)
}

/// Writes `token` as a character-string: its length, then its octets,
/// at most 255 (RFC 1035 §3.3).
fn write_string(wire: &mut Vec<u8>, token: &str) -> Option<()> {
    let octets = octets(token)?;
    wire.push(u8::try_from(octets.len()).ok()?);
    wire.extend(octets);
    Some(())
}

/// SvcParams in presentation format (RFC 9460 §2.1), each `key=value` or
/// a key alone, written in increasing order of key (§2.2), as BIND writes
/// them whatever order the text has. A key written twice, the invalid key
/// 65535, or a value that does not read as its key's gives `None`.
fn svc_params(tokens: &[String]) -> Option<Vec<u8>> {
    let mut params: BTreeMap<SvcParamKey, Vec<u8>> = BTreeMap::new();
    for token in tokens {
        let (key, value) = match token.split_once('=') {
            Some((key, value)) => (key, Some(octets(value)?)),
            None => (token.as_str(), None),
        };
        let key = SvcParamKey::from_str(key).ok()?;
        if key == SvcParamKey::Key65535 {
            return None;
        }
        let value = svc_value(key, value)?;
        if params.insert(key, value).is_some() {
            return None;
        }
    }
    let mut wire = Vec::new();
    for (key, value) in params {
        wire.extend(u16::from(key).to_be_bytes());
        wire.extend(u16::try_from(value.len()).ok()?.to_be_bytes());
        wire.extend(value);
    }
    Some(wire)
}

/// The wire form of the value of SvcParam `key`, from the octets of its
/// presentation value (RFC 9460 §7, Appendix A).
fn svc_value(key: SvcParamKey, value: Option<Vec<u8>>) -> Option<Vec<u8>> {
    let text = |value: &[u8]| String::from_utf8(value.to_vec()).ok();
    match key {
        // Keys in increasing order, none twice (RFC 9460 §8).
        SvcParamKey::Mandatory => {
            let mut keys = value_list(&value?)?
                .iter()
                .map(|item| SvcParamKey::from_str(&text(item)?).ok())
                .collect::<Option<Vec<_>>>()?;
            keys.sort();
            if keys.windows(2).any(|pair| pair[0] == pair[1]) {
                return None;
            }
            Some(
                keys.into_iter()
                    .flat_map(|k| u16::from(k).to_be_bytes())
                    .collect(),
            )
        }
        // Each ALPN ID after its length (RFC 9460 §7.1.1).
        SvcParamKey::Alpn => {
            let mut wire = Vec::new();
            for id in value_list(&value?)? {
                wire.push(u8::try_from(id.len()).ok()?);
                wire.extend(id);
            }
            Some(wire)
        }
        SvcParamKey::NoDefaultAlpn => value.is_none_or(|value| value.is_empty()).then(Vec::new),
        SvcParamKey::Port => Some(text(&value?)?.parse::<u16>().ok()?.to_be_bytes().to_vec()),
        SvcParamKey::Ipv4Hint => value_list(&value?)?
            .iter()
            .map(|item| Some(text(item)?.parse::<Ipv4Addr>().ok()?.octets().to_vec()))
            .collect::<Option<Vec<_>>>()
            .map(|addresses| addresses.concat()),
        SvcParamKey::Ipv6Hint => value_list(&value?)?
            .iter()
            .map(|item| Some(text(item)?.parse::<Ipv6Addr>().ok()?.octets().to_vec()))
            .collect::<Option<Vec<_>>>()
            .map(|addresses| addresses.concat()),
        SvcParamKey::EchConfigList => base64(&[text(&value?)?]),
        // Any other key's value is its octets (RFC 9460 Appendix A.1). Key
        // 65535 is refused before.
        SvcParamKey::Key(_) | SvcParamKey::Key65535 | SvcParamKey::Unknown(_) => {
            Some(value.unwrap_or_default())
        }
    }
}

/// The items of a comma-separated value list (RFC 9460 Appendix A.1.1):
/// a backslash makes the octet after it part of the item, and no item is
/// empty.
fn value_list(value: &[u8]) -> Option<Vec<Vec<u8>>> {
    let mut items = vec![Vec::new()];
    let mut bytes = value.iter();
    while let Some(&byte) = bytes.next() {
        match byte {
            b'\\' => items.last_mut()?.push(*bytes.next()?),
            b',' => items.push(Vec::new()),
            _ => items.last_mut()?.push(byte),
        }
    }
    items.iter().all(|item| !item.is_empty()).then_some(items)
}

/// A DNSSEC algorithm field: a decimal number or the algorithm's mnemonic
/// (RFC 4034 §2.2, Appendix A.1), the IANA registry's or BIND's.
fn algorithm(token: &str) -> Option<u8> {
    if let Ok(number) = token.parse() {
        return Some(number);
    }
    Some(match token.to_ascii_uppercase().as_str() {
        "RSAMD5" => 1,
        "DH" => 2,
        "DSA" => 3,
        "RSASHA1" => 5,
        "DSA-NSEC3-SHA1" | "NSEC3DSA" => 6,
        "RSASHA1-NSEC3-SHA1" | "NSEC3RSASHA1" => 7,
        "RSASHA256" => 8,
        "RSASHA512" => 10,
        "ECC-GOST" | "ECCGOST" => 12,
        "ECDSAP256SHA256" => 13,
        "ECDSAP384SHA384" => 14,
        "ED25519" => 15,
        "ED448" => 16,
        "INDIRECT" => 252,
        "PRIVATEDNS" => 253,
        "PRIVATEOID" => 254,
        _ => return None,
    })
}

/// RDATA of `rtype` that hickory's parser reads from `tokens`.
fn hickory_line(
    rtype: RecordType,
    tokens: &[String],
    origin: Option<&Name>,
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
    // The owner is the root, since only the RDATA is kept, and hickory
    // reads an owner as it reads names.
    let line = format!(". 0 IN {rtype} {}\n", tokens.join(" "));
    let read = |origin: Name| {
        let (_, sets) = Parser::new(line.clone(), None, Some(origin))
            .parse()
            .map_err(|_| bad())?;
        sets.into_values()
            .next()
            .and_then(|set| set.records_without_rrsigs().next().map(|r| r.data.clone()))
            .ok_or_else(bad)
    };
    match origin {
        Some(origin) => read(origin.clone()),
        None => {
            // hickory reads a relative name against whatever origin it is
            // given, so RDATA that reads differently under two origins
            // holds a relative name, which needs an origin (RFC 1035 §5.1).
            let data = read(Name::root())?;
            let elsewhere = Name::from_ascii("origin.invalid.").expect("a valid name");
            if read(elsewhere)? != data {
                return Err(MasterError::BadName);
            }
            Ok(data)
        }
    }
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
