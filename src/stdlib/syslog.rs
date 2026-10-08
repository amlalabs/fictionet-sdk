//! Syslog: reading and writing log messages in the formats of RFC 5424 and
//! RFC 3164, and splitting a TCP stream of them per RFC 6587, with no I/O.
//!
//! `Message`, `BsdMessage`, and `Entry` implement `Wire`, and `Frames` decodes
//! RFC 6587 stream envelopes. There is no collector session or `Service`, log
//! storage, or TLS transport.
//!
//! Syslog is how Unix machines, routers, firewalls and most appliances send
//! their logs to a collector. Every message starts with a priority in angle
//! brackets, such as `<34>`, which packs two numbers: the facility (which
//! part of the system logged it) and the severity (how bad it is). What
//! follows comes in two formats:
//!
//! - RFC 5424, the current one: a version, an ISO 8601 timestamp, the host,
//!   application, process and message type, then structured data (named
//!   elements of name and value pairs), then free text. [`Message`] reads
//!   and writes it.
//! - RFC 3164, the older "BSD" format most devices still send: a timestamp
//!   such as `Oct 11 22:14:15` with no year, the host, a tag naming the
//!   program, and free text. [`BsdMessage`] reads and writes it.
//!
//! [`Entry::parse`] reads either, telling them apart by the version number
//! that only RFC 5424 has.
//!
//! Over UDP, usually to port 514, each datagram holds one message. Over TCP
//! (RFC 6587) messages are framed one of two ways: octet counting, where a
//! decimal length and a space come before each message, or non-transparent
//! framing, where a newline ends each one. A [`Stream<Frames>`](fictionet::stdlib::codec::Stream) splits a stream
//! framed either way, and tells them apart frame by frame, as RFC 6587
//! suggests receivers do.
//!
//! Nothing here reads a socket. A world that plays a log collector pushes
//! the bytes it reads from a TCP connection to a
//! [`Stream<Frames>`](fictionet::stdlib::codec::Stream), gets [`Frame`]s back, and reads each one with
//! [`Entry::parse`]. Every reader checks lengths and characters, because
//! the agent can send any bytes it likes, and no message may be longer
//! than [`MAX_MESSAGE_LEN`]. The stream returns the bounded prefix of an
//! oversized message and marks it truncated. Writers refuse values they
//! cannot write unchanged.
//!
//! ```
//! use fictionet::stdlib::codec::{Stream, Wire};
//! use fictionet::stdlib::syslog::{
//!     Frames, Entry, Facility, Frame, Framing, Message, Priority, SdElement, Severity,
//! };
//!
//! // A world playing an application writes a message.
//! let mut message = Message::new(Priority::new(Facility::Auth, Severity::Critical));
//! message.hostname = Some("mymachine.example.com".into());
//! message.app_name = Some("su".into());
//! message.msg_id = Some("ID47".into());
//! message.structured_data.push(SdElement::new("origin").param("ip", "192.0.2.1"));
//! message.msg = b"'su root' failed".to_vec();
//! let bytes = message.to_bytes().unwrap();
//! assert_eq!(
//!     bytes,
//!     b"<34>1 - mymachine.example.com su - ID47 [origin ip=\"192.0.2.1\"] 'su root' failed"
//! );
//!
//! // A world playing a collector reads it from a TCP stream, framed both
//! // ways, and an old BSD-style message after it. A decoder takes what
//! // it has room for and says how much; this stream fits at once.
//! let mut stream = Frame::new(Framing::OctetCounting, bytes.clone()).to_bytes().unwrap();
//! stream.extend(Frame::new(Framing::NonTransparent, bytes).to_bytes().unwrap());
//! stream.extend(b"<13>Oct  5 12:00:00 gw sshd[42]: Accepted publickey\n");
//! let mut decoder = Stream::new(Frames::new());
//! assert_eq!(decoder.push(&stream), stream.len());
//! let mut got = Vec::new();
//! while let Some(frame) = decoder.next() {
//!     got.push(Entry::parse(&frame.unwrap().message).unwrap());
//! }
//! assert_eq!(got.len(), 3);
//! assert_eq!(got[0], Entry::Rfc5424(message));
//! let Entry::Bsd(bsd) = &got[2] else { panic!("not a BSD message") };
//! assert_eq!(bsd.priority.facility, Facility::User);
//! assert_eq!(bsd.priority.severity, Severity::Notice);
//! assert_eq!(bsd.tag.as_deref(), Some("sshd"));
//! assert_eq!(bsd.pid.as_deref(), Some("42"));
//! assert_eq!(bsd.content, b"Accepted publickey");
//! ```

use fictionet::stdlib::codec::civil::days_in_month;
use std::borrow::Cow;

use fictionet::stdlib::codec::{Decode, Step, Wire};

/// The UDP port syslog collectors listen on (RFC 5426). Plain TCP syslog
/// has no assigned port and most collectors use 514 for it too.
pub const UDP_PORT: u16 = 514;
/// The TCP port for syslog over TLS (RFC 5425).
pub const TLS_PORT: u16 = 6514;
/// The longest message any reader here accepts, and any writer produces.
/// RFC 5424 asks receivers to take at least 2048 bytes and lets them take
/// more. This allows the long messages real senders produce while keeping
/// a decoder's buffer bounded.
pub const MAX_MESSAGE_LEN: usize = 65_536;
/// The most bytes a [`Stream<Frames>`](fictionet::stdlib::codec::Stream) holds beyond those taken out: one message
/// of [`MAX_MESSAGE_LEN`] bytes and the longest octet count before it, 20
/// digits and a space. It also holds a message ended by CR LF.
pub const MAX_BUFFERED: usize = MAX_MESSAGE_LEN + 21;
/// The largest priority value: facility 23, severity 7.
pub const MAX_PRIVAL: u8 = 191;
/// The largest RFC 5424 version number: three digits.
pub const MAX_VERSION: u16 = 999;
/// The version of RFC 5424 itself, which writers use by default.
pub const VERSION: u16 = 1;
/// The longest RFC 5424 host name. RFC 3164 sets no limit, and its reader
/// here uses the same one.
pub const MAX_HOSTNAME: usize = 255;
/// The longest RFC 5424 application name.
pub const MAX_APP_NAME: usize = 48;
/// The longest RFC 5424 process identifier.
pub const MAX_PROCID: usize = 128;
/// The longest RFC 5424 message type identifier.
pub const MAX_MSGID: usize = 32;
/// The longest structured data element ID or parameter name.
pub const MAX_SD_NAME: usize = 32;
/// The most structured data elements one message may hold here.
pub const MAX_SD_ELEMENTS: usize = 256;
/// The most parameters one structured data element may hold here.
pub const MAX_SD_PARAMS: usize = 256;
/// The longest RFC 3164 tag (the program name).
pub const MAX_TAG: usize = 32;
/// The longest RFC 3164 process ID, in the brackets after the tag.
pub const MAX_PID: usize = 128;
/// The byte order mark that starts an RFC 5424 message's text when it is
/// UTF-8.
pub const BOM: [u8; 3] = [0xef, 0xbb, 0xbf];
/// The RFC 5424 nil value: a field that is not given is written as this.
pub const NILVALUE: &str = "-";

/// Which part of the system logged a message: the high bits of the
/// priority value. The names are the ones syslog configuration files use.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Facility {
    /// 0, `kern`: kernel messages.
    Kern,
    /// 1, `user`: user-level messages.
    User,
    /// 2, `mail`: the mail system.
    Mail,
    /// 3, `daemon`: system daemons.
    Daemon,
    /// 4, `auth`: security and authorization messages.
    Auth,
    /// 5, `syslog`: messages the syslog daemon generates itself.
    Syslog,
    /// 6, `lpr`: the line printer subsystem.
    Lpr,
    /// 7, `news`: the network news subsystem.
    News,
    /// 8, `uucp`: the UUCP subsystem.
    Uucp,
    /// 9, `cron`: the clock daemon.
    Cron,
    /// 10, `authpriv`: private security and authorization messages.
    Authpriv,
    /// 11, `ftp`: the FTP daemon.
    Ftp,
    /// 12, `ntp`: the NTP subsystem.
    Ntp,
    /// 13, `audit`: log audit.
    Audit,
    /// 14, `alert`: log alert.
    Alert,
    /// 15, `clock`: the second clock daemon.
    Clock,
    /// 16, `local0`: local use.
    Local0,
    /// 17, `local1`: local use.
    Local1,
    /// 18, `local2`: local use.
    Local2,
    /// 19, `local3`: local use.
    Local3,
    /// 20, `local4`: local use.
    Local4,
    /// 21, `local5`: local use.
    Local5,
    /// 22, `local6`: local use.
    Local6,
    /// 23, `local7`: local use.
    Local7,
}

const FACILITIES: [(Facility, &str); 24] = [
    (Facility::Kern, "kern"),
    (Facility::User, "user"),
    (Facility::Mail, "mail"),
    (Facility::Daemon, "daemon"),
    (Facility::Auth, "auth"),
    (Facility::Syslog, "syslog"),
    (Facility::Lpr, "lpr"),
    (Facility::News, "news"),
    (Facility::Uucp, "uucp"),
    (Facility::Cron, "cron"),
    (Facility::Authpriv, "authpriv"),
    (Facility::Ftp, "ftp"),
    (Facility::Ntp, "ntp"),
    (Facility::Audit, "audit"),
    (Facility::Alert, "alert"),
    (Facility::Clock, "clock"),
    (Facility::Local0, "local0"),
    (Facility::Local1, "local1"),
    (Facility::Local2, "local2"),
    (Facility::Local3, "local3"),
    (Facility::Local4, "local4"),
    (Facility::Local5, "local5"),
    (Facility::Local6, "local6"),
    (Facility::Local7, "local7"),
];

impl Facility {
    /// The facility's number, 0 to 23.
    pub fn code(self) -> u8 {
        self as u8
    }

    /// The facility numbered `code`, if there is one.
    pub fn from_code(code: u8) -> Option<Facility> {
        FACILITIES.get(usize::from(code)).map(|&(f, _)| f)
    }

    /// The facility's name, such as `auth` or `local4`.
    pub fn name(self) -> &'static str {
        FACILITIES[usize::from(self.code())].1
    }

    /// The facility called `name`, ignoring case.
    pub fn from_name(name: &str) -> Option<Facility> {
        FACILITIES
            .iter()
            .find(|(_, n)| n.eq_ignore_ascii_case(name))
            .map(|&(f, _)| f)
    }
}

impl std::fmt::Display for Facility {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// How bad a message is: the low three bits of the priority value. Lower
/// numbers are worse.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Severity {
    /// 0, `emerg`: the system is unusable.
    Emergency,
    /// 1, `alert`: action must be taken at once.
    Alert,
    /// 2, `crit`: critical conditions.
    Critical,
    /// 3, `err`: error conditions.
    Error,
    /// 4, `warning`: warning conditions.
    Warning,
    /// 5, `notice`: normal but significant conditions.
    Notice,
    /// 6, `info`: informational messages.
    Informational,
    /// 7, `debug`: debug-level messages.
    Debug,
}

const SEVERITIES: [(Severity, &str); 8] = [
    (Severity::Emergency, "emerg"),
    (Severity::Alert, "alert"),
    (Severity::Critical, "crit"),
    (Severity::Error, "err"),
    (Severity::Warning, "warning"),
    (Severity::Notice, "notice"),
    (Severity::Informational, "info"),
    (Severity::Debug, "debug"),
];

impl Severity {
    /// The severity's number, 0 to 7.
    pub fn code(self) -> u8 {
        self as u8
    }

    /// The severity numbered `code`, if there is one.
    pub fn from_code(code: u8) -> Option<Severity> {
        SEVERITIES.get(usize::from(code)).map(|&(s, _)| s)
    }

    /// The severity's name, such as `crit` or `info`.
    pub fn name(self) -> &'static str {
        SEVERITIES[usize::from(self.code())].1
    }

    /// The severity called `name`, ignoring case. The older spellings
    /// `panic`, `error` and `warn` are read too.
    pub fn from_name(name: &str) -> Option<Severity> {
        let alias = [
            ("panic", Severity::Emergency),
            ("error", Severity::Error),
            ("warn", Severity::Warning),
        ];
        if let Some(&(_, s)) = alias.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)) {
            return Some(s);
        }
        SEVERITIES
            .iter()
            .find(|(_, n)| n.eq_ignore_ascii_case(name))
            .map(|&(s, _)| s)
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// A message's priority: its facility and severity. On the wire it is one
/// number, the facility times 8 plus the severity, in angle brackets.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Priority {
    /// Which part of the system logged the message.
    pub facility: Facility,
    /// How bad it is.
    pub severity: Severity,
}

impl Priority {
    /// The priority with this facility and severity.
    pub fn new(facility: Facility, severity: Severity) -> Priority {
        Priority { facility, severity }
    }

    /// The priority value: the facility times 8 plus the severity.
    pub fn value(self) -> u8 {
        self.facility.code() * 8 + self.severity.code()
    }

    /// The priority with value `v`, if `v` is at most [`MAX_PRIVAL`].
    pub fn from_value(v: u8) -> Option<Priority> {
        Some(Priority {
            facility: Facility::from_code(v / 8)?,
            severity: Severity::from_code(v % 8)?,
        })
    }
}

impl std::fmt::Display for Priority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.facility, self.severity)
    }
}

/// The fraction of a second in an RFC 5424 timestamp, kept as written so
/// that `.5` and `.500` stay apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Fraction {
    /// The digits after the point, as a number: 3 for `.003`.
    pub value: u32,
    /// How many digits there are, 1 to 6.
    pub digits: u8,
}

impl Fraction {
    /// The fraction in microseconds.
    pub fn micros(self) -> u32 {
        let digits = self.digits.clamp(1, 6);
        self.value.min(10u32.pow(u32::from(digits)) - 1) * 10u32.pow(6 - u32::from(digits))
    }
}

/// The offset of an RFC 5424 timestamp from UTC.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Offset {
    /// Written `Z`.
    Utc,
    /// Written `+hh:mm` or `-hh:mm`, as minutes east of UTC. `Minutes(0)`
    /// is written `+00:00`.
    Minutes(i16),
    /// Written `-00:00`: the time is in UTC, and the local offset is not
    /// known (RFC 3339 section 4.3).
    Unknown,
}

/// The largest offset from UTC, in minutes: 23 hours 59 minutes.
pub const MAX_OFFSET_MINUTES: i16 = 23 * 60 + 59;

/// An RFC 5424 timestamp: an RFC 3339 date and time, such as
/// `2003-10-11T22:14:15.003Z`. Readers check every field's range,
/// including the day against the month and leap years. Leap seconds
/// (second 60) are not allowed, as RFC 5424 says.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Timestamp {
    /// The year, 0 to 9999.
    pub year: u16,
    /// The month, 1 to 12.
    pub month: u8,
    /// The day of the month, from 1.
    pub day: u8,
    /// The hour, 0 to 23.
    pub hour: u8,
    /// The minute, 0 to 59.
    pub minute: u8,
    /// The second, 0 to 59.
    pub second: u8,
    /// The fraction of a second, if one is written.
    pub fraction: Option<Fraction>,
    /// The offset from UTC.
    pub offset: Offset,
}

impl Timestamp {
    /// Reads a timestamp such as `2003-08-24T05:14:15.000003-07:00`. The
    /// `T` and `Z` must be upper case.
    fn parse_prefix(t: &[u8]) -> Option<Timestamp> {
        let year = num(t, 0, 4)? as u16;
        expect(t, 4, b'-')?;
        let month = num(t, 5, 2)? as u8;
        expect(t, 7, b'-')?;
        let day = num(t, 8, 2)? as u8;
        expect(t, 10, b'T')?;
        let hour = num(t, 11, 2)? as u8;
        expect(t, 13, b':')?;
        let minute = num(t, 14, 2)? as u8;
        expect(t, 16, b':')?;
        let second = num(t, 17, 2)? as u8;
        let mut i = 19;
        let mut fraction = None;
        if t.get(i) == Some(&b'.') {
            let digits = t
                .get(i + 1..)?
                .iter()
                .take_while(|b| b.is_ascii_digit())
                .count();
            if digits == 0 || digits > 6 {
                return None;
            }
            fraction = Some(Fraction {
                value: num(t, i + 1, digits)?,
                digits: digits as u8,
            });
            i += 1 + digits;
        }
        let offset = match t.get(i)? {
            b'Z' => {
                i += 1;
                Offset::Utc
            }
            &sign @ (b'+' | b'-') => {
                let oh = num(t, i + 1, 2)?;
                expect(t, i + 3, b':')?;
                let om = num(t, i + 4, 2)?;
                if oh > 23 || om > 59 {
                    return None;
                }
                i += 6;
                let m = (oh * 60 + om) as i16;
                match (sign, m) {
                    (b'-', 0) => Offset::Unknown,
                    (b'-', m) => Offset::Minutes(-m),
                    (_, m) => Offset::Minutes(m),
                }
            }
            _ => return None,
        };
        if i != t.len() {
            return None;
        }
        if !(1..=12).contains(&month) || day == 0 || day > days_in_month(i64::from(year), month) {
            return None;
        }
        if hour > 23 || minute > 59 || second > 59 {
            return None;
        }
        Some(Timestamp {
            year,
            month,
            day,
            hour,
            minute,
            second,
            fraction,
            offset,
        })
    }
}

impl Wire for Timestamp {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads an RFC 5424 timestamp, such as `2003-08-24T05:14:15.000003-07:00`.
    /// Requires uppercase `T` and `Z`. Refuses invalid dates, times, fractions,
    /// offsets, and trailing bytes.
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        Self::parse_prefix(bytes).ok_or(Error::Timestamp)
    }

    /// Appends a timestamp. Refuses invalid dates, times, fractions, and offsets.
    /// Leaves `out` unchanged on error.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        if self.year > 9999
            || !(1..=12).contains(&self.month)
            || self.day == 0
            || self.day > days_in_month(i64::from(self.year), self.month)
            || self.hour > 23
            || self.minute > 59
            || self.second > 59
        {
            return Err(Error::Unwritable);
        }
        let mut text = format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
            self.year, self.month, self.day, self.hour, self.minute, self.second
        );
        if let Some(fr) = self.fraction {
            if !(1..=6).contains(&fr.digits) || fr.value >= 10u32.pow(u32::from(fr.digits)) {
                return Err(Error::Unwritable);
            }
            text.push_str(&format!(
                ".{:0width$}",
                fr.value,
                width = usize::from(fr.digits)
            ));
        }
        match self.offset {
            Offset::Utc => text.push('Z'),
            Offset::Unknown => text.push_str("-00:00"),
            Offset::Minutes(m) => {
                if !(-MAX_OFFSET_MINUTES..=MAX_OFFSET_MINUTES).contains(&m) {
                    return Err(Error::Unwritable);
                }
                let sign = if m < 0 { '-' } else { '+' };
                let a = m.unsigned_abs();
                text.push_str(&format!("{sign}{:02}:{:02}", a / 60, a % 60));
            }
        }
        out.extend_from_slice(text.as_bytes());
        Ok(())
    }
}

/// One parameter of a structured data element: a name and a value.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SdParam {
    /// The parameter's name, 1 to [`MAX_SD_NAME`] printable ASCII
    /// characters other than `=`, space, `]` and `"`.
    pub name: String,
    /// The value, any UTF-8 text. On the wire `"`, `\` and `]` are
    /// escaped with a backslash; this holds the text unescaped. A
    /// backslash followed by any other character is an invalid escape,
    /// which RFC 5424 section 6.3.3 reads as a plain backslash and says
    /// must not be altered, so writers leave such a backslash as it is.
    pub value: String,
}

/// A structured data element: an ID, such as `timeQuality` or
/// `exampleSDID@32473`, and its parameters. IDs without an `@` are the
/// ones IANA registers. An ID with one is a name, an `@` and a private
/// enterprise number, which is decimal and may have parts split by
/// periods (`32473.1.2`). A parameter name may repeat within an element.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SdElement {
    /// The element's ID. The same ID may appear only once in a message.
    pub id: String,
    /// The parameters, in the order written.
    pub params: Vec<SdParam>,
}

impl SdElement {
    /// An element with this ID and no parameters.
    pub fn new(id: impl Into<String>) -> SdElement {
        SdElement {
            id: id.into(),
            params: Vec::new(),
        }
    }

    /// The element with one more parameter.
    pub fn param(mut self, name: impl Into<String>, value: impl Into<String>) -> SdElement {
        self.params.push(SdParam {
            name: name.into(),
            value: value.into(),
        });
        self
    }

    /// The value of the first parameter called `name`.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|p| p.name == name)
            .map(|p| p.value.as_str())
    }
}

/// An RFC 5424 message. Header fields that are `None` are the nil value,
/// written `-`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Message {
    /// The facility and severity.
    pub priority: Priority,
    /// The format version, 1 to [`MAX_VERSION`]. RFC 5424 is version 1.
    pub version: u16,
    /// When the message was made.
    pub timestamp: Option<Timestamp>,
    /// The machine that made it: a name or an address, up to
    /// [`MAX_HOSTNAME`] printable ASCII characters.
    pub hostname: Option<String>,
    /// The program that made it, up to [`MAX_APP_NAME`] characters.
    pub app_name: Option<String>,
    /// The process that made it, up to [`MAX_PROCID`] characters.
    pub proc_id: Option<String>,
    /// The type of message, up to [`MAX_MSGID`] characters.
    pub msg_id: Option<String>,
    /// The structured data elements. Empty is the nil value.
    pub structured_data: Vec<SdElement>,
    /// Whether the text starts with a byte order mark, which says it is
    /// UTF-8. When it does, `msg` holds the text after the mark and is
    /// valid UTF-8.
    pub bom: bool,
    /// The free-form text, which may be any bytes when `bom` is false.
    pub msg: Vec<u8>,
}

/// Why bytes are not a syslog message or frame, or why a value cannot be
/// written. After [`Error::Length`], [`Error::CountTooLarge`] or
/// [`Error::Incomplete`] from [`Frames`] a reader cannot find where the
/// next message starts, and a real collector closes the connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Error {
    /// The bytes are longer than [`MAX_MESSAGE_LEN`].
    TooLong(usize),
    /// The priority is missing, is not 1 to 3 digits in angle brackets,
    /// has a leading zero, or is above [`MAX_PRIVAL`].
    Priority,
    /// The version is not 1 to 3 digits starting with a nonzero one.
    Version,
    /// The bytes end before the header does, or hold no complete frame.
    Truncated,
    /// The timestamp is not a valid RFC 5424 timestamp.
    Timestamp,
    /// The host name is too long or holds a character other than
    /// printable ASCII.
    Hostname,
    /// The application name is too long or holds a bad character.
    AppName,
    /// The process ID is too long or holds a bad character.
    ProcId,
    /// The message ID is too long or holds a bad character.
    MsgId,
    /// The structured data is malformed: a bad element ID or parameter
    /// name (an ID with an `@` must be a name, one `@` and a private
    /// enterprise number), a missing quote, `=` or `]`, an unescaped `]` in a value,
    /// a value that is not UTF-8, too many elements or parameters, or
    /// something other than a space after it.
    StructuredData,
    /// Two structured data elements have the same ID.
    DuplicateSdId,
    /// The text starts with a byte order mark but is not UTF-8.
    Utf8,
    /// An octet count's digits were followed by this byte, not a space.
    Length(u8),
    /// An octet count too large to hold in a `usize`.
    CountTooLarge,
    /// EOF interrupted the tail of an oversized octet-counted message.
    Incomplete {
        /// Bytes still required by its count after the retained prefix.
        remaining: usize,
    },
    /// Bytes followed the frame.
    Trailing,
    /// The input exceeds [`MAX_BUFFERED`] or its message exceeds
    /// [`MAX_MESSAGE_LEN`].
    FrameTooLong,
    /// The value cannot be written without changing it: invalid fields,
    /// ambiguous framing, size limits, and truncated frames are refused.
    /// Writers leave the caller's output unchanged.
    Unwritable,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::TooLong(n) => write!(
                f,
                "message of {n} bytes, over the limit of {MAX_MESSAGE_LEN}"
            ),
            Error::Priority => f.write_str("missing or malformed priority"),
            Error::Version => f.write_str("malformed version"),
            Error::Truncated => f.write_str("message ends inside its header"),
            Error::Timestamp => f.write_str("malformed timestamp"),
            Error::Hostname => f.write_str("malformed host name"),
            Error::AppName => f.write_str("malformed application name"),
            Error::ProcId => f.write_str("malformed process ID"),
            Error::MsgId => f.write_str("malformed message ID"),
            Error::StructuredData => f.write_str("malformed structured data"),
            Error::DuplicateSdId => f.write_str("structured data element ID used twice"),
            Error::Utf8 => f.write_str("text marked as UTF-8 is not UTF-8"),
            Error::Length(c) => write!(f, "octet count followed by byte {c:#04x}, not a space"),
            Error::CountTooLarge => f.write_str("octet count too large"),
            Error::Incomplete { remaining } => {
                write!(f, "syslog message needs {remaining} more bytes")
            }
            Error::Trailing => f.write_str("bytes after the syslog frame"),
            Error::FrameTooLong => f.write_str("syslog frame exceeds its wire limit"),
            Error::Unwritable => f.write_str("syslog value cannot be written without changing it"),
        }
    }
}

impl std::error::Error for Error {}

impl Message {
    /// A version 1 message with this priority, every header field nil, no
    /// structured data and no text.
    pub fn new(priority: Priority) -> Message {
        Message {
            priority,
            version: VERSION,
            timestamp: None,
            hostname: None,
            app_name: None,
            proc_id: None,
            msg_id: None,
            structured_data: Vec::new(),
            bom: false,
            msg: Vec::new(),
        }
    }

    /// The text, with bytes that are not UTF-8 replaced.
    pub fn text(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(&self.msg)
    }

    /// The structured data element with ID `id`.
    pub fn element(&self, id: &str) -> Option<&SdElement> {
        self.structured_data.iter().find(|e| e.id == id)
    }
}

impl Wire for Message {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads one complete message. Refuses invalid protocol fields and messages above [`MAX_MESSAGE_LEN`].
    fn parse(b: &[u8]) -> Result<Message, Error> {
        if b.len() > MAX_MESSAGE_LEN {
            return Err(Error::TooLong(b.len()));
        }
        let (priority, mut pos) = parse_pri(b).ok_or(Error::Priority)?;
        let digits = b[pos..]
            .iter()
            .take(4)
            .take_while(|c| c.is_ascii_digit())
            .count();
        if digits == 0 || digits > 3 || b[pos] == b'0' {
            return Err(Error::Version);
        }
        let version = num(b, pos, digits).ok_or(Error::Version)? as u16;
        pos += digits;
        space(b, &mut pos, Error::Version)?;

        let t = token(b, &mut pos);
        let timestamp = if t == b"-" {
            None
        } else {
            Some(Timestamp::parse(t)?)
        };
        space(b, &mut pos, Error::Timestamp)?;
        let hostname = header_field(token(b, &mut pos), MAX_HOSTNAME, Error::Hostname)?;
        space(b, &mut pos, Error::Hostname)?;
        let app_name = header_field(token(b, &mut pos), MAX_APP_NAME, Error::AppName)?;
        space(b, &mut pos, Error::AppName)?;
        let proc_id = header_field(token(b, &mut pos), MAX_PROCID, Error::ProcId)?;
        space(b, &mut pos, Error::ProcId)?;
        let msg_id = header_field(token(b, &mut pos), MAX_MSGID, Error::MsgId)?;
        space(b, &mut pos, Error::MsgId)?;

        let structured_data = parse_sd(b, &mut pos)?;
        let (bom, msg) = match b.get(pos) {
            None => (false, Vec::new()),
            Some(b' ') => {
                let rest = &b[pos + 1..];
                match rest.strip_prefix(&BOM) {
                    Some(text) => {
                        std::str::from_utf8(text).map_err(|_| Error::Utf8)?;
                        (true, text.to_vec())
                    }
                    None => (false, rest.to_vec()),
                }
            }
            Some(_) => return Err(Error::StructuredData),
        };
        Ok(Message {
            priority,
            version,
            timestamp,
            hostname,
            app_name,
            proc_id,
            msg_id,
            structured_data,
            bom,
            msg,
        })
    }

    /// Appends an RFC 5424 message. Refuses invalid headers, timestamps,
    /// structured data, UTF-8 marks, and size limits.
    /// Leaves `out` unchanged on error.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        if !(1..=MAX_VERSION).contains(&self.version)
            || self.structured_data.len() > MAX_SD_ELEMENTS
            || self.msg.len() > MAX_MESSAGE_LEN
            || (self.bom && std::str::from_utf8(&self.msg).is_err())
            || (!self.bom && self.msg.starts_with(&BOM))
        {
            return Err(Error::Unwritable);
        }
        let mut bytes = format!("<{}>{} ", self.priority.value(), self.version).into_bytes();
        match &self.timestamp {
            Some(t) => t.write(&mut bytes)?,
            None => bytes.push(b'-'),
        }
        for (field, max) in [
            (&self.hostname, MAX_HOSTNAME),
            (&self.app_name, MAX_APP_NAME),
            (&self.proc_id, MAX_PROCID),
            (&self.msg_id, MAX_MSGID),
        ] {
            bytes.push(b' ');
            match field {
                Some(s) if valid_field(s, max, b"") && s != "-" => {
                    bytes.extend_from_slice(s.as_bytes())
                }
                Some(_) => return Err(Error::Unwritable),
                None => bytes.push(b'-'),
            }
        }
        bytes.push(b' ');
        let mut ids = std::collections::HashSet::new();
        for element in &self.structured_data {
            if !valid_field(&element.id, MAX_SD_NAME, b"=\"]")
                || !is_sd_id(&element.id)
                || !ids.insert(element.id.as_str())
            {
                return Err(Error::Unwritable);
            }
            write_sd_element(&mut bytes, &element.id, &element.params)?;
        }
        if self.structured_data.is_empty() {
            bytes.push(b'-');
        }
        if self.bom || !self.msg.is_empty() {
            append(&mut bytes, b" ")?;
            if self.bom {
                append(&mut bytes, &BOM)?;
            }
            append(&mut bytes, &self.msg)?;
        }
        out.extend_from_slice(&bytes);
        Ok(())
    }
}

/// An RFC 3164 timestamp, such as `Oct 11 22:14:15`. It has no year and no
/// time zone.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BsdTimestamp {
    /// The month, 1 to 12.
    pub month: u8,
    /// The day of the month, from 1. February may have 29 days, since the
    /// year is not known.
    pub day: u8,
    /// The hour, 0 to 23.
    pub hour: u8,
    /// The minute, 0 to 59.
    pub minute: u8,
    /// The second, 0 to 59.
    pub second: u8,
}

const MONTHS: [&[u8; 3]; 12] = [
    b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec",
];

/// How many bytes an RFC 3164 timestamp takes.
pub const BSD_TIMESTAMP_LEN: usize = 15;

impl BsdTimestamp {
    /// Reads the 15-byte timestamp at the start of `t`. The day is a space
    /// and a digit or two digits; a leading zero is read too, though the
    /// RFC asks for a space.
    fn parse_prefix(t: &[u8]) -> Option<BsdTimestamp> {
        let t = t.get(..BSD_TIMESTAMP_LEN)?;
        let month = MONTHS.iter().position(|m| &t[..3] == *m)? as u8 + 1;
        expect(t, 3, b' ')?;
        let day = match (t[4], t[5]) {
            (b' ', d @ b'1'..=b'9') => d - b'0',
            _ => num(t, 4, 2)? as u8,
        };
        expect(t, 6, b' ')?;
        let hour = num(t, 7, 2)? as u8;
        expect(t, 9, b':')?;
        let minute = num(t, 10, 2)? as u8;
        expect(t, 12, b':')?;
        let second = num(t, 13, 2)? as u8;
        if day == 0 || day > days_in_month(2000, month) || hour > 23 || minute > 59 || second > 59 {
            return None;
        }
        Some(BsdTimestamp {
            month,
            day,
            hour,
            minute,
            second,
        })
    }
}

impl Wire for BsdTimestamp {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads one 15-byte BSD timestamp. A one-digit day may have a leading
    /// space or zero. Refuses invalid dates, times, syntax, and trailing bytes.
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != BSD_TIMESTAMP_LEN {
            return Err(Error::Timestamp);
        }
        Self::parse_prefix(bytes).ok_or(Error::Timestamp)
    }

    /// Appends a timestamp. Refuses invalid dates and times.
    /// Leaves `out` unchanged on error.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        if !(1..=12).contains(&self.month)
            || self.day == 0
            || self.day > days_in_month(2000, self.month)
            || self.hour > 23
            || self.minute > 59
            || self.second > 59
        {
            return Err(Error::Unwritable);
        }
        out.extend_from_slice(MONTHS[usize::from(self.month - 1)]);
        out.extend_from_slice(
            format!(
                " {:>2} {:02}:{:02}:{:02}",
                self.day, self.hour, self.minute, self.second
            )
            .as_bytes(),
        );
        Ok(())
    }
}

/// The timestamp and host of an RFC 3164 message, which come together or
/// not at all.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BsdHeader {
    /// When the message was made.
    pub timestamp: BsdTimestamp,
    /// The machine that made it, 1 to [`MAX_HOSTNAME`] printable ASCII
    /// characters.
    pub hostname: String,
}

/// An RFC 3164 ("BSD") message: `<PRI>TIMESTAMP HOSTNAME TAG[PID]: TEXT`.
///
/// RFC 3164 describes what senders were seen to do rather than a strict
/// format, and this reader is as lenient as it asks. Only the priority is
/// required. Without a valid timestamp and host after it, everything
/// after the priority is the message part. The message part starts with a
/// tag when it begins with up to [`MAX_TAG`] printable characters (not
/// `[`, `]` or `:`) followed by `:` or by a process ID in brackets and
/// `:`. One space after the colon is skipped. Otherwise all of it is
/// content.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BsdMessage {
    /// The facility and severity.
    pub priority: Priority,
    /// The timestamp and host, if both were found.
    pub header: Option<BsdHeader>,
    /// The program's name.
    pub tag: Option<String>,
    /// The process ID in brackets after the tag, 1 to [`MAX_PID`]
    /// printable characters other than `]`. Only written with a tag.
    pub pid: Option<String>,
    /// The rest of the message, any bytes.
    pub content: Vec<u8>,
}

impl BsdMessage {
    /// A message with this priority and content, and no header or tag.
    pub fn new(priority: Priority, content: impl Into<Vec<u8>>) -> BsdMessage {
        BsdMessage {
            priority,
            header: None,
            tag: None,
            pid: None,
            content: content.into(),
        }
    }

    /// The content, with bytes that are not UTF-8 replaced.
    pub fn text(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(&self.content)
    }
}

impl Wire for BsdMessage {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads one BSD message. Recognizes a timestamp and host together,
    /// then an optional tag and process ID. Refuses a bad priority or more
    /// than [`MAX_MESSAGE_LEN`] bytes; other unrecognized bytes remain content.
    fn parse(b: &[u8]) -> Result<BsdMessage, Error> {
        if b.len() > MAX_MESSAGE_LEN {
            return Err(Error::TooLong(b.len()));
        }
        let (priority, pos) = parse_pri(b).ok_or(Error::Priority)?;
        let mut rest = &b[pos..];
        let mut header = None;
        if let Some(timestamp) = BsdTimestamp::parse_prefix(rest)
            && rest.get(BSD_TIMESTAMP_LEN) == Some(&b' ')
        {
            let after = &rest[BSD_TIMESTAMP_LEN + 1..];
            let host_len = after.iter().position(|&c| c == b' ').unwrap_or(after.len());
            let host = &after[..host_len];
            if !host.is_empty() && host.len() <= MAX_HOSTNAME && host.iter().all(|&c| is_print(c)) {
                let hostname = String::from_utf8_lossy(host).into_owned();
                header = Some(BsdHeader {
                    timestamp,
                    hostname,
                });
                rest = after.get(host_len + 1..).unwrap_or(&[]);
            }
        }
        let (tag, pid, content) = match split_tag(rest) {
            Some((tag, pid, content)) => (Some(tag), pid, content),
            None => (None, None, rest),
        };
        Ok(BsdMessage {
            priority,
            header,
            tag,
            pid,
            content: content.to_vec(),
        })
    }

    /// Appends a BSD message. Refuses invalid headers, tags, process IDs,
    /// ambiguous content, and size limits.
    /// Leaves `out` unchanged on error.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        if self.content.len() > MAX_MESSAGE_LEN || (self.pid.is_some() && self.tag.is_none()) {
            return Err(Error::Unwritable);
        }
        let mut bytes = format!("<{}>", self.priority.value()).into_bytes();
        if let Some(h) = &self.header {
            if !valid_field(&h.hostname, MAX_HOSTNAME, b"") {
                return Err(Error::Unwritable);
            }
            h.timestamp.write(&mut bytes)?;
            bytes.push(b' ');
            bytes.extend_from_slice(h.hostname.as_bytes());
            if self.tag.is_some() || !self.content.is_empty() {
                bytes.push(b' ');
            }
        }
        if let Some(tag) = &self.tag {
            if !valid_field(tag, MAX_TAG, b"[]:") {
                return Err(Error::Unwritable);
            }
            bytes.extend_from_slice(tag.as_bytes());
            if let Some(pid) = &self.pid {
                if !valid_field(pid, MAX_PID, b"]") {
                    return Err(Error::Unwritable);
                }
                bytes.push(b'[');
                bytes.extend_from_slice(pid.as_bytes());
                bytes.push(b']');
            }
            bytes.push(b':');
            let fits = bytes
                .len()
                .checked_add(1)
                .and_then(|n| n.checked_add(self.content.len()))
                .is_some_and(|n| n <= MAX_MESSAGE_LEN);
            if !self.content.is_empty() && (fits || self.content[0] == b' ') {
                bytes.push(b' ');
            }
        }
        append(&mut bytes, &self.content)?;
        if Self::parse(&bytes).as_ref() != Ok(self) {
            return Err(Error::Unwritable);
        }
        out.extend_from_slice(&bytes);
        Ok(())
    }
}

/// A syslog message in either format.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Entry {
    /// An RFC 5424 message.
    Rfc5424(Message),
    /// An RFC 3164 message.
    Bsd(BsdMessage),
}

impl Entry {
    /// The message's priority.
    pub fn priority(&self) -> Priority {
        match self {
            Entry::Rfc5424(m) => m.priority,
            Entry::Bsd(m) => m.priority,
        }
    }
}

impl Wire for Entry {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads an RFC 5424 message when a valid version and message follow
    /// its priority. Otherwise reads BSD, which accepts any bytes after
    /// the priority. Refuses a bad priority or more than [`MAX_MESSAGE_LEN`]
    /// bytes. Use [`Message::parse`] for RFC 5424 field errors.
    fn parse(b: &[u8]) -> Result<Entry, Error> {
        if b.len() > MAX_MESSAGE_LEN {
            return Err(Error::TooLong(b.len()));
        }
        let (_, pos) = parse_pri(b).ok_or(Error::Priority)?;
        let rest = &b[pos..];
        let digits = rest
            .iter()
            .take(4)
            .take_while(|c| c.is_ascii_digit())
            .count();
        if (1..=3).contains(&digits)
            && rest[0] != b'0'
            && rest.get(digits) == Some(&b' ')
            && let Ok(m) = Message::parse(b)
        {
            return Ok(Entry::Rfc5424(m));
        }
        BsdMessage::parse(b).map(Entry::Bsd)
    }

    /// Appends a message. Refuses unwritable fields or a change of format.
    /// Leaves `out` unchanged on error.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let bytes = match self {
            Self::Rfc5424(message) => message.to_bytes()?,
            Self::Bsd(message) => message.to_bytes()?,
        };
        if Self::parse(&bytes).as_ref() != Ok(self) {
            return Err(Error::Unwritable);
        }
        out.extend_from_slice(&bytes);
        Ok(())
    }
}

/// How a message is framed on a TCP stream (RFC 6587).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Framing {
    /// The message's length in decimal and a space come first. The
    /// message may hold any bytes.
    OctetCounting,
    /// A newline ends the message. The writer refuses embedded newlines
    /// and a first byte from `1` through `9`, which would start a count.
    NonTransparent,
}

/// One message taken from a TCP stream, and how it was framed.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Frame {
    /// How the message was framed.
    pub framing: Framing,
    /// The message, without its framing: 1 to [`MAX_MESSAGE_LEN`] bytes.
    pub message: Vec<u8>,
    /// Whether the message on the wire was longer than
    /// [`MAX_MESSAGE_LEN`], so `message` holds only its first bytes. RFC
    /// 5424 section 6.1 asks receivers to cut such messages at the end.
    pub truncated: bool,
}

impl Frame {
    /// A frame holding `message`, whole.
    pub fn new(framing: Framing, message: Vec<u8>) -> Frame {
        Frame {
            framing,
            message,
            truncated: false,
        }
    }
}

/// What a decoder throws away before the next frame: the rest of a
/// message it has truncated.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum Skip {
    #[default]
    Nothing,
    /// This many more bytes of an octet counted message.
    Bytes(usize),
    /// Everything up to and including the next newline.
    Line,
}

/// Reads syslog TCP frames without retaining input bytes.
///
/// Use with [`fictionet::stdlib::codec::Stream`] for at most [`MAX_BUFFERED`] unread
/// bytes. Empty lines are skipped. Oversized messages yield a prefix of
/// [`MAX_MESSAGE_LEN`] bytes with [`Frame::truncated`] set, then skip the
/// remaining bytes. A scan cursor keeps bytewise line input linear.
///
/// At EOF, a final non-transparent frame needs no newline. A partial
/// octet-counted frame returns [`Step::Need`] so the driver reports
/// truncation. EOF in an oversized counted tail is [`Error::Incomplete`].
/// Invalid octet counts end the stream. Message parse errors can be kept
/// as items by mapping each frame through [`Entry::parse`].
///
/// ```
/// use fictionet::stdlib::{syslog::{Frame, Frames, Framing}, codec::Stream};
///
/// let mut stream = Stream::new(Frames::new());
/// assert_eq!(stream.push(b"last message"), 12);
/// assert_eq!(stream.next(), None);
/// stream.end();
/// assert_eq!(stream.next(), Some(Ok(Frame::new(
///     Framing::NonTransparent, b"last message".to_vec(),
/// ))));
/// assert_eq!(stream.next(), None);
/// ```
#[derive(Clone, Debug, Default)]
pub struct Frames {
    scanned: usize,
    skip: Skip,
}

impl Frames {
    /// Creates a decoder with no retained state.
    pub fn new() -> Self {
        Self::default()
    }

    fn octet_counted(&mut self, input: &[u8]) -> Result<Step<Frame>, Error> {
        let mut length = 0usize;
        let mut at = 0usize;
        loop {
            let Some(&byte) = input.get(at) else {
                return Ok(Step::Need);
            };
            if byte == b' ' {
                break;
            }
            if !byte.is_ascii_digit() {
                return Err(Error::Length(byte));
            }
            length = length
                .checked_mul(10)
                .and_then(|n| n.checked_add(usize::from(byte - b'0')))
                .ok_or(Error::CountTooLarge)?;
            at = at.checked_add(1).ok_or(Error::CountTooLarge)?;
        }
        let start = at.checked_add(1).ok_or(Error::CountTooLarge)?;
        let keep = length.min(MAX_MESSAGE_LEN);
        let used = start.checked_add(keep).ok_or(Error::CountTooLarge)?;
        let Some(message) = input.get(start..used) else {
            return Ok(Step::Need);
        };
        if length > keep {
            self.skip = Skip::Bytes(length - keep);
        }
        self.scanned = 0;
        Ok(Step::Item(
            Frame {
                framing: Framing::OctetCounting,
                message: message.to_vec(),
                truncated: length > keep,
            },
            used,
        ))
    }

    fn non_transparent(&mut self, input: &[u8], eof: bool) -> Step<Frame> {
        let suffix = input.get(self.scanned..).unwrap_or_default();
        if let Some(n) = suffix.iter().position(|&byte| byte == b'\n') {
            let at = self.scanned.saturating_add(n);
            let end = if at.checked_sub(1).and_then(|i| input.get(i)) == Some(&b'\r') {
                at.saturating_sub(1)
            } else {
                at
            };
            let keep = end.min(MAX_MESSAGE_LEN);
            self.scanned = 0;
            let used = at.saturating_add(1);
            return if keep == 0 {
                Step::Skip(used)
            } else {
                Step::Item(
                    Frame {
                        framing: Framing::NonTransparent,
                        message: input.get(..keep).unwrap_or_default().to_vec(),
                        truncated: end > keep,
                    },
                    used,
                )
            };
        }
        if input.len() > MAX_MESSAGE_LEN + 1 || eof {
            let keep = input.len().min(MAX_MESSAGE_LEN);
            self.scanned = 0;
            if !eof {
                self.skip = Skip::Line;
            }
            return Step::Item(
                Frame {
                    framing: Framing::NonTransparent,
                    message: input.get(..keep).unwrap_or_default().to_vec(),
                    truncated: input.len() > keep,
                },
                input.len(),
            );
        }
        self.scanned = input.len();
        Step::Need
    }
}

impl Decode for Frames {
    type Item = Frame;
    type Error = Error;
    const NAME: &'static str = "syslog TCP";

    fn capacity(&self) -> usize {
        MAX_BUFFERED
    }

    fn decode(&mut self, input: &[u8], eof: bool) -> Result<Step<Frame>, Error> {
        match self.skip {
            Skip::Bytes(remaining) => {
                if input.is_empty() {
                    return if eof {
                        Err(Error::Incomplete { remaining })
                    } else {
                        Ok(Step::Need)
                    };
                }
                let used = remaining.min(input.len());
                self.skip = if used == remaining {
                    Skip::Nothing
                } else {
                    Skip::Bytes(remaining - used)
                };
                return Ok(Step::Skip(used));
            }
            Skip::Line => {
                if input.is_empty() {
                    return Ok(Step::Need);
                }
                let used = match input.iter().position(|&byte| byte == b'\n') {
                    Some(at) => {
                        self.skip = Skip::Nothing;
                        at.saturating_add(1)
                    }
                    None => input.len(),
                };
                return Ok(Step::Skip(used));
            }
            Skip::Nothing => {}
        }
        let Some(&first) = input.first() else {
            return Ok(Step::Need);
        };
        if matches!(first, b'1'..=b'9') {
            self.octet_counted(input)
        } else {
            Ok(self.non_transparent(input, eof))
        }
    }
}

impl Wire for Frame {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads exactly one frame. A final non-transparent frame may omit
    /// its newline. Refuses bad counts, oversized frames, missing bodies, and trailing bytes.
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_BUFFERED {
            return Err(Error::FrameTooLong);
        }
        match Frames::new().decode(bytes, true)? {
            Step::Item(frame, _) if frame.truncated => Err(Error::FrameTooLong),
            Step::Item(frame, used) if used == bytes.len() => Ok(frame),
            Step::Item(_, _) => Err(Error::Trailing),
            _ => Err(Error::Truncated),
        }
    }

    /// Appends a frame. Refuses empty, truncated, oversized, or ambiguous messages.
    /// Leaves `out` unchanged on error.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let msg = &self.message;
        if self.truncated
            || msg.is_empty()
            || msg.len() > MAX_MESSAGE_LEN
            || (self.framing == Framing::NonTransparent
                && (matches!(msg[0], b'1'..=b'9') || msg.contains(&b'\n')))
        {
            return Err(Error::Unwritable);
        }
        match self.framing {
            Framing::OctetCounting => {
                out.extend_from_slice(format!("{} ", msg.len()).as_bytes());
                out.extend_from_slice(msg);
            }
            Framing::NonTransparent => {
                out.extend_from_slice(msg);
                if msg.last() == Some(&b'\r') {
                    out.push(b'\r');
                }
                out.push(b'\n');
            }
        }
        Ok(())
    }
}

fn parse_pri(b: &[u8]) -> Option<(Priority, usize)> {
    if b.first() != Some(&b'<') {
        return None;
    }
    let digits = b[1..]
        .iter()
        .take(4)
        .take_while(|c| c.is_ascii_digit())
        .count();
    if digits == 0 || digits > 3 || (digits > 1 && b[1] == b'0') || b.get(1 + digits) != Some(&b'>')
    {
        return None;
    }
    let v = num(b, 1, digits)?;
    if v > u32::from(MAX_PRIVAL) {
        return None;
    }
    Some((Priority::from_value(v as u8)?, digits + 2))
}

/// The bytes from `pos` up to the next space or the end, moving `pos` past
/// them.
fn token<'a>(b: &'a [u8], pos: &mut usize) -> &'a [u8] {
    let rest = b.get(*pos..).unwrap_or(&[]);
    let n = rest.iter().position(|&c| c == b' ').unwrap_or(rest.len());
    *pos += n;
    &rest[..n]
}

/// Moves past the space at `pos`. The end of the bytes is
/// [`Error::Truncated`]; anything else is `err`.
fn space(b: &[u8], pos: &mut usize, err: Error) -> Result<(), Error> {
    match b.get(*pos) {
        Some(b' ') => {
            *pos += 1;
            Ok(())
        }
        None => Err(Error::Truncated),
        Some(_) => Err(err),
    }
}

/// An RFC 5424 header field: nil, or 1 to `max` printable ASCII bytes.
fn header_field(t: &[u8], max: usize, err: Error) -> Result<Option<String>, Error> {
    if t.is_empty() {
        // Two spaces in a row, or a space at the very end.
        return Err(err);
    }
    if t == b"-" {
        return Ok(None);
    }
    if t.len() > max || !t.iter().all(|&c| is_print(c)) {
        return Err(err);
    }
    Ok(Some(String::from_utf8_lossy(t).into_owned()))
}

/// Writes `[id name="value" ...]` at the end of `out`. Returns
/// [`Error::Unwritable`] once the message would pass [`MAX_MESSAGE_LEN`].
/// The caller stages `out` so a refused message leaves its output unchanged.
/// In values, `"`, `]` and a backslash are escaped,
/// except a backslash followed by a character that is none of the three:
/// that is an invalid escape, which reads back as the same backslash and
/// is kept as it is (RFC 5424 section 6.3.3).
fn write_sd_element(out: &mut Vec<u8>, id: &str, params: &[SdParam]) -> Result<(), Error> {
    if params.len() > MAX_SD_PARAMS {
        return Err(Error::Unwritable);
    }
    append(out, b"[")?;
    append(out, id.as_bytes())?;
    for p in params {
        if !valid_field(&p.name, MAX_SD_NAME, b"=\"]") {
            return Err(Error::Unwritable);
        }
        append(out, b" ")?;
        append(out, p.name.as_bytes())?;
        append(out, b"=\"")?;
        let v = p.value.as_bytes();
        for (i, &c) in v.iter().enumerate() {
            let escape = match c {
                b'"' | b']' => true,
                b'\\' => matches!(v.get(i + 1), None | Some(b'"' | b'\\' | b']')),
                _ => false,
            };
            if escape {
                append(out, b"\\")?;
            }
            append(out, &[c])?;
        }
        append(out, b"\"")?;
    }
    append(out, b"]")
}

fn append(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), Error> {
    if out
        .len()
        .checked_add(bytes.len())
        .is_none_or(|n| n > MAX_MESSAGE_LEN)
    {
        return Err(Error::Unwritable);
    }
    out.extend_from_slice(bytes);
    Ok(())
}

fn valid_field(s: &str, max: usize, forbidden: &[u8]) -> bool {
    !s.is_empty() && s.len() <= max && s.bytes().all(|c| is_print(c) && !forbidden.contains(&c))
}

/// Reads RFC 5424 structured data at `pos`: the nil value or one or more
/// elements.
fn parse_sd(b: &[u8], pos: &mut usize) -> Result<Vec<SdElement>, Error> {
    let err = Error::StructuredData;
    let mut elements: Vec<SdElement> = Vec::new();
    match b.get(*pos) {
        None => return Err(Error::Truncated),
        Some(b'-') => {
            *pos += 1;
            return Ok(elements);
        }
        Some(b'[') => {}
        Some(_) => return Err(err),
    }
    while b.get(*pos) == Some(&b'[') {
        if elements.len() == MAX_SD_ELEMENTS {
            return Err(err);
        }
        *pos += 1;
        let id = sd_name_at(b, pos)?;
        if !is_sd_id(&id) {
            return Err(err);
        }
        if elements.iter().any(|e| e.id == id) {
            return Err(Error::DuplicateSdId);
        }
        let mut params = Vec::new();
        loop {
            match b.get(*pos) {
                Some(b']') => {
                    *pos += 1;
                    break;
                }
                Some(b' ') => *pos += 1,
                _ => return Err(err),
            }
            if params.len() == MAX_SD_PARAMS {
                return Err(err);
            }
            let name = sd_name_at(b, pos)?;
            if b.get(*pos) != Some(&b'=') || b.get(*pos + 1) != Some(&b'"') {
                return Err(err);
            }
            *pos += 2;
            let mut value = Vec::new();
            loop {
                match b.get(*pos) {
                    None | Some(b']') => return Err(err),
                    Some(b'"') => {
                        *pos += 1;
                        break;
                    }
                    Some(b'\\') => match b.get(*pos + 1) {
                        Some(&c @ (b'"' | b'\\' | b']')) => {
                            value.push(c);
                            *pos += 2;
                        }
                        // Any other escape is a plain backslash.
                        _ => {
                            value.push(b'\\');
                            *pos += 1;
                        }
                    },
                    Some(&c) => {
                        value.push(c);
                        *pos += 1;
                    }
                }
            }
            let value = String::from_utf8(value).map_err(|_| err)?;
            params.push(SdParam { name, value });
        }
        elements.push(SdElement { id, params });
    }
    Ok(elements)
}

/// An SD-NAME at `pos`: 1 to [`MAX_SD_NAME`] printable ASCII bytes other
/// than `=`, space, `]` and `"`.
fn sd_name_at(b: &[u8], pos: &mut usize) -> Result<String, Error> {
    let rest = b.get(*pos..).unwrap_or(&[]);
    let n = rest
        .iter()
        .take(MAX_SD_NAME + 1)
        .take_while(|&&c| is_sd_name(c))
        .count();
    if n == 0 || n > MAX_SD_NAME {
        return Err(Error::StructuredData);
    }
    *pos += n;
    Ok(String::from_utf8_lossy(&rest[..n]).into_owned())
}

fn is_sd_name(c: u8) -> bool {
    is_print(c) && !matches!(c, b'=' | b']' | b'"')
}

/// Whether an SD-NAME may be an SD-ID. RFC 5424 section 6.3.2: a name
/// with an at-sign is `name@<private enterprise number>`, where the name
/// holds no at-sign and the number is decimal, its parts split by periods,
/// such as `32473` or `32473.1.2`.
fn is_sd_id(id: &str) -> bool {
    let Some((name, pen)) = id.split_once('@') else {
        return true;
    };
    !name.is_empty()
        && pen
            .split('.')
            .all(|p| !p.is_empty() && p.bytes().all(|c| c.is_ascii_digit()))
}

fn is_print(c: u8) -> bool {
    (33..=126).contains(&c)
}

/// The tag, process ID and content of an RFC 3164 message part, if it
/// starts with a tag.
fn split_tag(m: &[u8]) -> Option<(String, Option<String>, &[u8])> {
    let n = m
        .iter()
        .take(MAX_TAG + 1)
        .take_while(|&&c| is_print(c) && !matches!(c, b'[' | b']' | b':'))
        .count();
    if n == 0 || n > MAX_TAG {
        return None;
    }
    let tag = String::from_utf8_lossy(&m[..n]).into_owned();
    let mut i = n;
    let mut pid = None;
    if m.get(i) == Some(&b'[') {
        let rest = &m[i + 1..];
        let p = rest
            .iter()
            .take(MAX_PID + 1)
            .take_while(|&&c| is_print(c) && c != b']')
            .count();
        if p == 0 || p > MAX_PID || rest.get(p) != Some(&b']') {
            return None;
        }
        pid = Some(String::from_utf8_lossy(&rest[..p]).into_owned());
        i += p + 2;
    }
    if m.get(i) != Some(&b':') {
        return None;
    }
    i += 1;
    if m.get(i) == Some(&b' ') {
        i += 1;
    }
    Some((tag, pid, &m[i..]))
}

/// The `n` decimal digits at `t[i..]` as a number, if they are all there
/// and all digits. `n` is at most 9, so the number fits.
fn num(t: &[u8], i: usize, n: usize) -> Option<u32> {
    let d = t.get(i..i.checked_add(n)?)?;
    if n == 0 || n > 9 || !d.iter().all(|c| c.is_ascii_digit()) {
        return None;
    }
    Some(d.iter().fold(0, |v, &c| v * 10 + u32::from(c - b'0')))
}

fn expect(t: &[u8], i: usize, c: u8) -> Option<()> {
    (t.get(i) == Some(&c)).then_some(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::codec::{Fail, Lcg, Stream, pump};
    use fictionet::stdlib::test_support::contract;
    use fictionet::stdlib::test_support::{assert_linear, rounds};
    use fictionet::stdlib::test_support::{decode_all, mutate};

    /// The four examples of RFC 5424 section 6.5, with the BOM bytes in
    /// place of "BOM" and the third one's text shortened.
    const EX1: &[u8] =
        b"<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - \xef\xbb\xbf'su root' failed for lonvick on /dev/pts/8";
    const EX2: &[u8] =
        b"<165>1 2003-08-24T05:14:15.000003-07:00 192.0.2.1 myproc 8710 - - %% It's time to make the do-nuts.";
    const EX3: &[u8] = b"<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"] \xef\xbb\xbfAn application event log entry...";
    const EX4: &[u8] = b"<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"][examplePriority@32473 class=\"high\"]";

    #[test]
    fn accepted_structured_data_names_and_repeats_write_unchanged() {
        let bytes = br#"<13>1 - - - - - [x[ p[="one" p[="two"]"#;
        let message = Message::parse(bytes).unwrap();
        assert_eq!(message.structured_data[0].params.len(), 2);
        assert_eq!(message.to_bytes().unwrap(), bytes);
        contract::check_wire::<Message>(bytes);
    }

    #[test]
    fn rfc5424_example_1() {
        let m = Message::parse(EX1).unwrap();
        assert_eq!(
            m.priority,
            Priority::new(Facility::Auth, Severity::Critical)
        );
        assert_eq!(m.priority.to_string(), "auth.crit");
        assert_eq!(m.version, 1);
        let t = m.timestamp.unwrap();
        assert_eq!(
            (t.year, t.month, t.day, t.hour, t.minute, t.second),
            (2003, 10, 11, 22, 14, 15)
        );
        assert_eq!(
            t.fraction,
            Some(Fraction {
                value: 3,
                digits: 3
            })
        );
        assert_eq!(t.fraction.unwrap().micros(), 3000);
        assert_eq!(t.offset, Offset::Utc);
        assert_eq!(m.hostname.as_deref(), Some("mymachine.example.com"));
        assert_eq!(m.app_name.as_deref(), Some("su"));
        assert_eq!(m.proc_id, None);
        assert_eq!(m.msg_id.as_deref(), Some("ID47"));
        assert!(m.structured_data.is_empty());
        assert!(m.bom);
        assert_eq!(m.text(), "'su root' failed for lonvick on /dev/pts/8");
        assert_eq!(m.to_bytes().unwrap(), EX1);
    }

    #[test]
    fn rfc5424_example_2() {
        let m = Message::parse(EX2).unwrap();
        assert_eq!(
            m.priority,
            Priority::new(Facility::Local4, Severity::Notice)
        );
        let t = m.timestamp.unwrap();
        assert_eq!(
            t.fraction,
            Some(Fraction {
                value: 3,
                digits: 6
            })
        );
        assert_eq!(t.offset, Offset::Minutes(-7 * 60));
        assert_eq!(m.hostname.as_deref(), Some("192.0.2.1"));
        assert_eq!(m.proc_id.as_deref(), Some("8710"));
        assert_eq!(m.msg_id, None);
        assert!(!m.bom);
        assert_eq!(m.msg, b"%% It's time to make the do-nuts.");
        assert_eq!(m.to_bytes().unwrap(), EX2);
    }

    #[test]
    fn rfc5424_examples_3_and_4() {
        let m = Message::parse(EX3).unwrap();
        assert_eq!(m.structured_data.len(), 1);
        let e = m.element("exampleSDID@32473").unwrap();
        assert_eq!(e.get("iut"), Some("3"));
        assert_eq!(e.get("eventSource"), Some("Application"));
        assert_eq!(e.get("eventID"), Some("1011"));
        assert_eq!(m.text(), "An application event log entry...");
        assert_eq!(m.to_bytes().unwrap(), EX3);

        let m = Message::parse(EX4).unwrap();
        assert_eq!(m.structured_data.len(), 2);
        assert_eq!(
            m.element("examplePriority@32473").unwrap().get("class"),
            Some("high")
        );
        assert!(m.msg.is_empty() && !m.bom);
        assert_eq!(m.to_bytes().unwrap(), EX4);
    }

    #[test]
    fn rfc5424_timestamps() {
        // RFC 5424 section 6.2.3.1.
        for ok in [
            "1985-04-12T23:20:50.52Z",
            "1985-04-12T19:20:50.52-04:00",
            "2003-10-11T22:14:15.003Z",
            "2003-08-24T05:14:15.000003-07:00",
            "2000-02-29T00:00:00+14:00",
        ] {
            let t = Timestamp::parse(ok.as_bytes()).unwrap_or_else(|_| panic!("{ok}"));
            assert_eq!(t.to_bytes().unwrap(), ok.as_bytes());
        }
        for bad in [
            "2003-08-24T05:14:15.000000003-07:00",
            "1990-12-31T23:59:60Z",
            "2003-10-11t22:14:15Z",
            "2003-10-11T22:14:15z",
            "2003-10-11T22:14:15",
            "2003-10-11T22:14:15.Z",
            "1900-02-29T00:00:00Z",
            "2003-04-31T00:00:00Z",
            "2003-13-01T00:00:00Z",
            "2003-00-01T00:00:00Z",
            "2003-10-11T24:00:00Z",
            "2003-10-11T22:60:00Z",
            "2003-10-11T22:14:15+24:00",
            "2003-10-11T22:14:15+01:60",
            "2003-10-11T22:14:15+0100",
            "2003-10-11T22:14:15ZZ",
            "2003-10-11 22:14:15Z",
        ] {
            assert_eq!(
                Timestamp::parse(bad.as_bytes()),
                Err(Error::Timestamp),
                "{bad}"
            );
        }
        // -00:00 is UTC with the local offset not known (RFC 3339 section
        // 4.3), which +00:00 is not, so the two stay apart.
        let t = Timestamp::parse(b"2003-10-11T22:14:15-00:00").unwrap();
        assert_eq!(t.offset, Offset::Unknown);
        assert_eq!(t.to_bytes().unwrap(), b"2003-10-11T22:14:15-00:00");
        let t = Timestamp::parse(b"2003-10-11T22:14:15+00:00").unwrap();
        assert_eq!(t.offset, Offset::Minutes(0));
        assert_eq!(t.to_bytes().unwrap(), b"2003-10-11T22:14:15+00:00");
    }

    #[test]
    fn rfc3164_examples() {
        // RFC 3164 section 5.4.
        let m = BsdMessage::parse(
            b"<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8",
        )
        .unwrap();
        assert_eq!(
            m.priority,
            Priority::new(Facility::Auth, Severity::Critical)
        );
        let h = m.header.as_ref().unwrap();
        assert_eq!(
            h.timestamp,
            BsdTimestamp {
                month: 10,
                day: 11,
                hour: 22,
                minute: 14,
                second: 15
            }
        );
        assert_eq!(h.hostname, "mymachine");
        assert_eq!(m.tag.as_deref(), Some("su"));
        assert_eq!(m.pid, None);
        assert_eq!(m.content, b"'su root' failed for lonvick on /dev/pts/8");
        assert_eq!(
            m.to_bytes().unwrap(),
            b"<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8"
        );

        let raw = b"<13>Feb  5 17:32:18 10.0.0.99 Use the BFG!";
        let m = BsdMessage::parse(raw).unwrap();
        assert_eq!(m.header.as_ref().unwrap().timestamp.day, 5);
        assert_eq!(m.header.as_ref().unwrap().hostname, "10.0.0.99");
        assert_eq!(m.tag, None);
        assert_eq!(m.content, b"Use the BFG!");
        assert_eq!(m.to_bytes().unwrap(), raw);

        let m =
            BsdMessage::parse(b"<165>Aug 24 05:34:00 CST 1987 mymachine myproc[10]: %% It's time")
                .unwrap();
        assert_eq!(m.priority.facility, Facility::Local4);
        assert_eq!(m.header.as_ref().unwrap().hostname, "CST");
        assert_eq!(m.content, b"1987 mymachine myproc[10]: %% It's time");

        let raw = b"<0>1990 Oct 22 10:52:01 TZ-6 scapegoat.dmz.example.org 10.1.2.3 sched[0]: That's All Folks!";
        let m = BsdMessage::parse(raw).unwrap();
        assert_eq!(
            m.priority,
            Priority::new(Facility::Kern, Severity::Emergency)
        );
        assert_eq!(m.header, None);
        assert_eq!(m.content, &raw[3..]);
        assert_eq!(Entry::parse(raw), Ok(Entry::Bsd(m)));
    }

    #[test]
    fn rfc3164_tags() {
        let m = BsdMessage::parse(b"<13>Oct  5 01:02:03 gw sshd[42]: hello").unwrap();
        assert_eq!(
            (m.tag.as_deref(), m.pid.as_deref()),
            (Some("sshd"), Some("42"))
        );
        assert_eq!(m.content, b"hello");
        assert_eq!(
            m.to_bytes().unwrap(),
            b"<13>Oct  5 01:02:03 gw sshd[42]: hello"
        );
        // No space after the colon, and no content.
        let m = BsdMessage::parse(b"<13>app:x").unwrap();
        assert_eq!((m.tag.as_deref(), &m.content[..]), (Some("app"), &b"x"[..]));
        let m = BsdMessage::parse(b"<13>app:").unwrap();
        assert_eq!((m.tag.as_deref(), &m.content[..]), (Some("app"), &b""[..]));
        assert_eq!(m.to_bytes().unwrap(), b"<13>app:");
        // Not tags: an unclosed bracket, an empty process ID, a tag too long.
        for raw in [
            &b"<13>app[12: x"[..],
            b"<13>app[]: x",
            b"<13>abcdefghijklmnopqrstuvwxyz0123456: x",
            b"<13>:x",
        ] {
            let m = BsdMessage::parse(raw).unwrap();
            assert_eq!(m.tag, None);
            assert_eq!(m.content, &raw[4..]);
        }
        // A leading zero in the day is read, and written with a space.
        let m = BsdMessage::parse(b"<13>Oct 05 01:02:03 gw x").unwrap();
        assert_eq!(m.to_bytes().unwrap(), b"<13>Oct  5 01:02:03 gw x");
        // A host name and nothing after it.
        let m = BsdMessage::parse(b"<13>Oct  5 01:02:03 gw").unwrap();
        assert_eq!(m.header.unwrap().hostname, "gw");
        // A timestamp with no host is part of the content.
        let m = BsdMessage::parse(b"<13>Oct  5 01:02:03  x").unwrap();
        assert_eq!(m.header, None);
        // Bad dates are not timestamps.
        assert_eq!(
            BsdTimestamp::parse(b"Feb 30 01:02:03"),
            Err(Error::Timestamp)
        );
        assert_eq!(BsdTimestamp::parse(b"Feb 29 01:02:03").unwrap().day, 29);
        assert_eq!(
            BsdTimestamp::parse(b"Oct  0 01:02:03"),
            Err(Error::Timestamp)
        );
        assert_eq!(
            BsdTimestamp::parse(b"oct  1 01:02:03"),
            Err(Error::Timestamp)
        );
        assert_eq!(
            BsdTimestamp::parse(b"Oct  1 24:02:03"),
            Err(Error::Timestamp)
        );
    }

    #[test]
    fn priorities_and_names() {
        for v in 0..=255u8 {
            match Priority::from_value(v) {
                Some(p) => assert_eq!(p.value(), v),
                None => assert!(v > MAX_PRIVAL),
            }
        }
        for c in 0..24 {
            let f = Facility::from_code(c).unwrap();
            assert_eq!(f.code(), c);
            assert_eq!(Facility::from_name(f.name()), Some(f));
        }
        assert_eq!(Facility::from_code(24), None);
        for c in 0..8 {
            let s = Severity::from_code(c).unwrap();
            assert_eq!(s.code(), c);
            assert_eq!(Severity::from_name(s.name()), Some(s));
        }
        assert_eq!(Severity::from_code(8), None);
        assert_eq!(Severity::from_name("WARN"), Some(Severity::Warning));
        assert_eq!(Facility::from_name("LOCAL7"), Some(Facility::Local7));
        assert_eq!(Facility::from_name("nope"), None);
        assert_eq!(
            Priority::from_value(165).unwrap().to_string(),
            "local4.notice"
        );
        // PRI forms.
        assert!(parse_pri(b"<0>").is_some());
        assert!(parse_pri(b"<191>").is_some());
        for bad in [
            &b"<192>"[..],
            b"<00>",
            b"<01>",
            b"<1000>",
            b"<>",
            b"<1",
            b"1>",
            b"<a>",
            b"",
        ] {
            assert_eq!(parse_pri(bad), None, "{:?}", String::from_utf8_lossy(bad));
        }
    }

    #[test]
    fn rfc5424_error_paths() {
        let cases: &[(&[u8], Error)] = &[
            (b"34>1 - - - - - -", Error::Priority),
            (b"<192>1 - - - - - -", Error::Priority),
            (b"<34>0 - - - - - -", Error::Version),
            (b"<34>1000 - - - - - -", Error::Version),
            (b"<34>1x - - - - - -", Error::Version),
            (b"<34>", Error::Version),
            (b"<34>1", Error::Truncated),
            (b"<34>1 - - - - -", Error::Truncated),
            (b"<34>1 - - - - - ", Error::Truncated),
            (b"<34>1 2003-10-11 - - - - -", Error::Timestamp),
            (b"<34>1 - h\x01 - - - -", Error::Hostname),
            (b"<34>1 -  - - - -", Error::Hostname),
            (b"<34>1 - - \xc3\xa9 - - -", Error::AppName),
            (
                b"<34>1 - - aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa - - -",
                Error::AppName,
            ),
            (b"<34>1 - - - p\x7f - -", Error::ProcId),
            (
                b"<34>1 - - - - aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa -",
                Error::MsgId,
            ),
            (b"<34>1 - - - - - x", Error::StructuredData),
            (b"<34>1 - - - - - -x", Error::StructuredData),
            (b"<34>1 - - - - - [a", Error::StructuredData),
            (b"<34>1 - - - - - []", Error::StructuredData),
            (b"<34>1 - - - - - [a b]", Error::StructuredData),
            (b"<34>1 - - - - - [a b=c]", Error::StructuredData),
            (b"<34>1 - - - - - [a b=\"c]", Error::StructuredData),
            (b"<34>1 - - - - - [a b=\"c]\"]", Error::StructuredData),
            (b"<34>1 - - - - - [a b=\"\xff\"]", Error::StructuredData),
            (b"<34>1 - - - - - [a  b=\"c\"]", Error::StructuredData),
            (b"<34>1 - - - - - [a][b]x", Error::StructuredData),
            (
                b"<34>1 - - - - - [aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa]",
                Error::StructuredData,
            ),
            (b"<34>1 - - - - - [a][a]", Error::DuplicateSdId),
            (b"<34>1 - - - - - - \xef\xbb\xbf\xff", Error::Utf8),
        ];
        for (raw, want) in cases {
            assert_eq!(
                Message::parse(raw),
                Err(*want),
                "{:?}",
                String::from_utf8_lossy(raw)
            );
            assert!(!want.to_string().is_empty());
        }
        let long = vec![b'<'; MAX_MESSAGE_LEN + 1];
        assert_eq!(
            Message::parse(&long),
            Err(Error::TooLong(MAX_MESSAGE_LEN + 1))
        );
        assert_eq!(
            BsdMessage::parse(&long),
            Err(Error::TooLong(MAX_MESSAGE_LEN + 1))
        );
        assert_eq!(
            Entry::parse(&long),
            Err(Error::TooLong(MAX_MESSAGE_LEN + 1))
        );
        assert_eq!(BsdMessage::parse(b"no priority"), Err(Error::Priority));
        assert_eq!(Entry::parse(b""), Err(Error::Priority));
        // Too many elements and parameters.
        let mut many = b"<34>1 - - - - - ".to_vec();
        for i in 0..=MAX_SD_ELEMENTS {
            many.extend_from_slice(format!("[e{i}]").as_bytes());
        }
        assert_eq!(Message::parse(&many), Err(Error::StructuredData));
        let mut many = b"<34>1 - - - - - [e".to_vec();
        for _ in 0..=MAX_SD_PARAMS {
            many.extend_from_slice(b" p=\"\"");
        }
        many.push(b']');
        assert_eq!(Message::parse(&many), Err(Error::StructuredData));
    }

    #[test]
    fn structured_data_escapes() {
        let raw = br#"<34>1 - - - - - [x@1 a="q\"b\\s\]e" b="\n" c="" a="2"]"#;
        let m = Message::parse(raw).unwrap();
        let e = &m.structured_data[0];
        assert_eq!(e.get("a"), Some(r#"q"b\s]e"#));
        // Any other escape is a backslash and the character after it.
        assert_eq!(e.get("b"), Some(r"\n"));
        assert_eq!(e.get("c"), Some(""));
        assert_eq!(e.params.len(), 4);
        let again = m.to_bytes().unwrap();
        assert_eq!(Message::parse(&again).unwrap(), m);
        // The invalid escape `\n` is kept as it was (RFC 5424 section
        // 6.3.3). A backslash before an ordinary character reads the same
        // escaped or not, and is written as it.
        assert_eq!(
            again,
            br#"<34>1 - - - - - [x@1 a="q\"b\s\]e" b="\n" c="" a="2"]"#
        );
        // A backslash before a character that must be escaped, or at the
        // end, is escaped itself.
        let mut m = Message::new(Priority::new(Facility::User, Severity::Notice));
        m.structured_data.push(
            SdElement::new("x")
                .param("a", r#"\"\\\]\"#)
                .param("b", r"C:\path"),
        );
        let bytes = m.to_bytes().unwrap();
        assert_eq!(
            bytes,
            br#"<13>1 - - - - - [x a="\\\"\\\\\\\]\\" b="C:\path"]"#
        );
        assert_eq!(Message::parse(&bytes).unwrap(), m);
        // A trailing space means an empty text.
        let m = Message::parse(b"<34>1 - - - - - - ").unwrap();
        assert!(m.msg.is_empty());
        assert_eq!(m.to_bytes().unwrap(), b"<34>1 - - - - - -");
        // A BOM with no text after it.
        let m = Message::parse(b"<34>1 - - - - - - \xef\xbb\xbf").unwrap();
        assert!(m.bom && m.msg.is_empty());
        assert_eq!(m.to_bytes().unwrap(), b"<34>1 - - - - - - \xef\xbb\xbf");
    }

    #[test]
    fn entry_picks_the_format() {
        assert!(matches!(Entry::parse(EX1), Ok(Entry::Rfc5424(_))));
        assert!(matches!(
            Entry::parse(b"<13>Oct  5 01:02:03 gw x"),
            Ok(Entry::Bsd(_))
        ));
        assert!(matches!(Entry::parse(b"<13>0 x"), Ok(Entry::Bsd(_))));
        assert!(matches!(Entry::parse(b"<13>1234 x"), Ok(Entry::Bsd(_))));
        // Bytes that start like RFC 5424 but do not read as it are BSD.
        assert_eq!(Message::parse(b"<13>12 x"), Err(Error::Timestamp));
        let Ok(Entry::Bsd(m)) = Entry::parse(b"<13>12 x") else {
            panic!("not BSD")
        };
        assert_eq!(m.content, b"12 x");
        let e = Entry::parse(EX2).unwrap();
        assert_eq!(e.priority().value(), 165);
        assert_eq!(e.to_bytes().unwrap(), EX2);
    }

    #[test]
    fn writers_refuse_values_that_would_change() {
        let base = Message::new(Priority::new(Facility::Kern, Severity::Debug));
        let mut values = Vec::new();
        for version in [0, MAX_VERSION + 1] {
            values.push(Message {
                version,
                ..base.clone()
            });
        }
        for hostname in [
            "host name\n".into(),
            "x".repeat(MAX_HOSTNAME + 1),
            String::new(),
            "-".into(),
        ] {
            values.push(Message {
                hostname: Some(hostname),
                ..base.clone()
            });
        }
        values.push(Message {
            app_name: Some("é".repeat(100)),
            ..base.clone()
        });
        values.push(Message {
            proc_id: Some(String::new()),
            ..base.clone()
        });
        values.push(Message {
            msg_id: Some("-".into()),
            ..base.clone()
        });
        for structured_data in [
            vec![SdElement::new("a=b")],
            vec![SdElement::new("a").param("x y", "v")],
            vec![SdElement::new("")],
            vec![SdElement::new("x").param("", "]")],
            vec![SdElement::new("a"), SdElement::new("a")],
            (0..400).map(|i| SdElement::new(format!("e{i}"))).collect(),
            vec![SdElement {
                id: "x".into(),
                params: vec![
                    SdParam {
                        name: "v".into(),
                        value: "x".into()
                    };
                    MAX_SD_PARAMS + 1
                ],
            }],
        ] {
            values.push(Message {
                structured_data,
                ..base.clone()
            });
        }
        values.push(Message {
            bom: true,
            msg: vec![0xff, 0xfe],
            ..base.clone()
        });
        values.push(Message {
            msg: [&BOM[..], &BOM, b"x"].concat(),
            ..base.clone()
        });
        values.push(Message {
            bom: true,
            msg: "é".repeat(MAX_MESSAGE_LEN).into_bytes(),
            ..base.clone()
        });
        for m in values {
            assert!(m.to_bytes().is_err());
            contract::check_wire_value(&m);
        }
        let t = Timestamp::parse(b"2003-02-28T12:00:00Z").unwrap();
        for bad in [
            Timestamp { year: 20000, ..t },
            Timestamp { month: 0, ..t },
            Timestamp { day: 31, ..t },
            Timestamp { hour: 99, ..t },
            Timestamp { minute: 99, ..t },
            Timestamp { second: 60, ..t },
            Timestamp {
                fraction: Some(Fraction {
                    value: 12345678,
                    digits: 9,
                }),
                ..t
            },
            Timestamp {
                fraction: Some(Fraction {
                    value: 10,
                    digits: 1,
                }),
                ..t
            },
            Timestamp {
                fraction: Some(Fraction {
                    value: 0,
                    digits: 0,
                }),
                ..t
            },
            Timestamp {
                offset: Offset::Minutes(-5000),
                ..t
            },
        ] {
            assert!(bad.to_bytes().is_err());
            contract::check_wire_value(&bad);
            assert!(
                Message {
                    timestamp: Some(bad),
                    ..base.clone()
                }
                .to_bytes()
                .is_err()
            );
        }
        let base = BsdMessage::new(base.priority, "x");
        let t = BsdTimestamp {
            month: 1,
            day: 31,
            hour: 12,
            minute: 0,
            second: 0,
        };
        for bad in [
            BsdTimestamp { month: 0, ..t },
            BsdTimestamp { day: 40, ..t },
            BsdTimestamp { hour: 30, ..t },
            BsdTimestamp { minute: 70, ..t },
            BsdTimestamp { second: 70, ..t },
        ] {
            assert!(bad.to_bytes().is_err());
            contract::check_wire_value(&bad);
        }
        for bad in [
            BsdMessage {
                header: Some(BsdHeader {
                    timestamp: t,
                    hostname: String::new(),
                }),
                ..base.clone()
            },
            BsdMessage {
                tag: Some("my app".into()),
                ..base.clone()
            },
            BsdMessage {
                tag: Some("app".into()),
                pid: Some("1]".into()),
                ..base.clone()
            },
            BsdMessage {
                pid: Some("7".into()),
                ..base.clone()
            },
            BsdMessage {
                content: vec![b'x'; 2 * MAX_MESSAGE_LEN],
                ..base.clone()
            },
            BsdMessage {
                content: b"app: x".to_vec(),
                ..base.clone()
            },
        ] {
            assert!(bad.to_bytes().is_err());
            contract::check_wire_value(&bad);
        }
    }

    #[test]
    fn frames_both_ways() {
        // RFC 6587 section 3.4.1: octet counting.
        let mut d = Stream::new(Frames::new());
        assert_eq!(d.push(b"7 <34>1 x"), b"7 <34>1 x".len());
        assert_eq!(
            d.next(),
            Some(Ok(Frame::new(Framing::OctetCounting, b"<34>1 x".to_vec())))
        );
        assert_eq!(d.next(), None);
        // Section 3.4.2: a trailer ends the message.
        assert_eq!(
            d.push(b"<13>a\r\n\n\n<13>b\n<13>c"),
            b"<13>a\r\n\n\n<13>b\n<13>c".len()
        );
        assert_eq!(
            d.next(),
            Some(Ok(Frame::new(Framing::NonTransparent, b"<13>a".to_vec())))
        );
        assert_eq!(
            d.next(),
            Some(Ok(Frame::new(Framing::NonTransparent, b"<13>b".to_vec())))
        );
        assert_eq!(d.next(), None);
        assert_eq!(d.buffered(), 5);
        // Octet counted messages may hold newlines.
        assert_eq!(d.push(b"\n5 a\nb\nc"), b"\n5 a\nb\nc".len());
        assert_eq!(d.next().unwrap().unwrap().message, b"<13>c");
        assert_eq!(d.next().unwrap().unwrap().message, b"a\nb\nc");
        assert_eq!(d.buffered(), 0);

        // Writers.
        assert_eq!(
            Frame::new(Framing::OctetCounting, b"<1>x".to_vec())
                .to_bytes()
                .unwrap(),
            b"4 <1>x"
        );
        for frame in [
            Frame::new(Framing::NonTransparent, b"<1>x\ny".to_vec()),
            Frame::new(Framing::NonTransparent, b"12".to_vec()),
            Frame::new(Framing::NonTransparent, Vec::new()),
            Frame::new(Framing::OctetCounting, Vec::new()),
            Frame::new(Framing::OctetCounting, vec![b'x'; MAX_MESSAGE_LEN + 10]),
            Frame {
                truncated: true,
                ..Frame::new(Framing::OctetCounting, b"x".to_vec())
            },
        ] {
            assert!(frame.to_bytes().is_err());
            contract::check_wire_value(&frame);
        }
    }

    #[test]
    fn frame_errors() {
        let mut d = Stream::new(Frames::new());
        assert_eq!(d.push(b"12x <34>1"), b"12x <34>1".len());
        assert_eq!(d.next(), Some(Err(Fail::Protocol(Error::Length(b'x')))));
        assert_eq!(d.push(b"<13>fine\n"), 9);
        assert_eq!(d.next(), None);

        // A count over the limit is fine; one past usize is not.
        let mut d = Stream::new(Frames::new());
        assert_eq!(
            d.push(format!("{} ", MAX_MESSAGE_LEN + 1).as_bytes()),
            format!("{} ", MAX_MESSAGE_LEN + 1).as_bytes().len()
        );
        assert_eq!(d.next(), None);
        let mut d = Stream::new(Frames::new());
        assert_eq!(
            d.push(b"99999999999999999999999999"),
            b"99999999999999999999999999".len()
        );
        assert_eq!(d.next(), Some(Err(Fail::Protocol(Error::CountTooLarge))));

        // A message without a newline may be MAX_MESSAGE_LEN bytes; past
        // that it is cut.
        let mut d = Stream::new(Frames::new());
        assert_eq!(
            d.push(&vec![b'<'; MAX_MESSAGE_LEN]),
            vec![b'<'; MAX_MESSAGE_LEN].len()
        );
        assert_eq!(d.next(), None);
        assert_eq!(d.push(b"\n"), b"\n".len());
        let f = d.next().unwrap().unwrap();
        assert_eq!((f.message.len(), f.truncated), (MAX_MESSAGE_LEN, false));
        let mut d = Stream::new(Frames::new());
        assert_eq!(
            d.push(&vec![b'<'; MAX_MESSAGE_LEN + 1]),
            vec![b'<'; MAX_MESSAGE_LEN + 1].len()
        );
        assert_eq!(d.next(), None);
        assert_eq!(d.push(b"<"), b"<".len());
        assert!(d.next().unwrap().unwrap().truncated);
        assert_eq!(d.buffered(), 0);
        assert_eq!(d.push(b"<<\n<13>x\n"), b"<<\n<13>x\n".len());
        assert_eq!(d.next().unwrap().unwrap().message, b"<13>x");
        assert!(!Error::CountTooLarge.to_string().is_empty());
        let kinds: std::collections::HashSet<Error> =
            [Error::CountTooLarge, Error::Length(0)].into();
        assert_eq!(kinds.len(), 2);
        let kinds: std::collections::HashSet<Error> = [Error::Priority, Error::Utf8].into();
        assert_eq!(kinds.len(), 2);
        assert!(!Error::Length(0).to_string().is_empty());
    }

    #[test]
    fn truncated_prefixes() {
        for raw in [EX1, EX2, EX3, EX4] {
            // The header ends after the space following MSGID.
            let header_end = {
                let mut spaces = 0;
                raw.iter()
                    .position(|&c| {
                        spaces += usize::from(c == b' ');
                        spaces == 6
                    })
                    .unwrap()
                    + 1
            };
            for n in 0..raw.len() {
                let r = Message::parse(&raw[..n]);
                if n <= header_end {
                    assert!(r.is_err(), "{n} bytes");
                }
                let _ = Entry::parse(&raw[..n]);
                let _ = BsdMessage::parse(&raw[..n]);
            }
            assert!(Message::parse(raw).is_ok());
            // Framed, every prefix yields no frame and no error.
            for framing in [Framing::OctetCounting, Framing::NonTransparent] {
                let framed = Frame::new(framing, raw.to_vec()).to_bytes().unwrap();
                contract::check_decode_with_alloc_limit(Frames::new, &framed, 2 * MAX_BUFFERED);
                for n in 0..framed.len() {
                    assert_eq!(Frames::new().decode(&framed[..n], false), Ok(Step::Need));
                }
                assert_eq!(Frame::parse(&framed).unwrap().message, raw);
            }
        }
        let bsd = b"<13>Oct  5 01:02:03 gw sshd[42]: hello";
        for n in 0..bsd.len() {
            let r = BsdMessage::parse(&bsd[..n]);
            assert_eq!(r.is_err(), n < 4, "{n} bytes");
        }
    }

    #[test]
    fn sd_ids_with_an_at_sign() {
        // RFC 5424 section 6.3.2: name@<private enterprise number>, the
        // name without an at-sign, the number decimal with dotted parts.
        for ok in [
            "[a@1]",
            "[exampleSDID@32473]",
            "[a@32473.1.2]",
            "[timeQuality]",
        ] {
            let raw = format!("<34>1 - - - - - {ok}");
            assert!(Message::parse(raw.as_bytes()).is_ok(), "{ok}");
        }
        for bad in [
            "[a@b@1]", "[a@x]", "[@1]", "[a@]", "[a@1.]", "[a@.1]", "[a@1..2]", "[a@1@2]",
        ] {
            let raw = format!("<34>1 - - - - - {bad}");
            assert_eq!(
                Message::parse(raw.as_bytes()),
                Err(Error::StructuredData),
                "{bad}"
            );
        }
        // Parameter names may hold an at-sign.
        assert!(Message::parse(b"<34>1 - - - - - [a@1 b@c=\"\"]").is_ok());
        // The writer makes IDs the reader takes.
        for id in [
            "a@b@1",
            "a@x",
            "@1",
            "a@",
            "a@1.",
            "x@32473",
            "abcdefghijklmnopqrstuvwxyz0123@1234",
        ] {
            let mut m = Message::new(Priority::new(Facility::User, Severity::Notice));
            m.structured_data.push(SdElement::new(id));
            assert_eq!(m.to_bytes().is_ok(), id == "x@32473", "{id}");
            contract::check_wire_value(&m);
        }
        let mut m = Message::new(Priority::new(Facility::User, Severity::Notice));
        m.structured_data.push(SdElement::new("x@32473"));
        assert_eq!(
            Message::parse(&m.to_bytes().unwrap())
                .unwrap()
                .structured_data[0]
                .id,
            "x@32473"
        );
    }

    #[test]
    fn crlf_trailers() {
        // RFC 6587 section 3.4.2: some senders end each message with CR LF.
        let mut d = Stream::new(Frames::new());
        assert_eq!(
            d.push(b"<34>1 - - - - - -\r\n\r\n<13>b\r\r\n"),
            b"<34>1 - - - - - -\r\n\r\n<13>b\r\r\n".len()
        );
        let f = d.next().unwrap().unwrap();
        assert_eq!(f.message, b"<34>1 - - - - - -");
        assert!(Message::parse(&f.message).is_ok());
        // A CR LF on its own is a blank line, and only one CR is a trailer.
        assert_eq!(d.next().unwrap().unwrap().message, b"<13>b\r");
        assert_eq!(d.next(), None);
        // A message ending in CR keeps it when written.
        let f = Frame::new(Framing::NonTransparent, b"<13>b\r".to_vec());
        let mut d = Stream::new(Frames::new());
        assert_eq!(d.push(&f.to_bytes().unwrap()), f.to_bytes().unwrap().len());
        assert_eq!(d.next().unwrap().unwrap().message, b"<13>b\r");
    }

    #[test]
    fn long_frames_are_truncated() {
        // RFC 5424 section 6.1: a receiver SHOULD truncate a message longer
        // than it supports, or MAY discard it, and the stream goes on.
        let long = [b"<13>".as_slice(), &vec![b'x'; MAX_MESSAGE_LEN + 100]].concat();
        let mut counted = format!("{} ", long.len()).into_bytes();
        counted.extend_from_slice(&long);
        let nl = [long.as_slice(), b"\n"].concat();
        let crlf = [long.as_slice(), b"\r\n"].concat();
        for framed in [counted, nl, crlf] {
            let stream = [framed.as_slice(), b"<13>next\n"].concat();
            contract::check_decode_with_alloc_limit(Frames::new, &stream, 2 * MAX_BUFFERED);
            let (got, error) = decode_all(Frames::new, &stream);
            assert_eq!(error, None);
            assert_eq!(got.len(), 2);
            assert_eq!(got[0].message, &long[..MAX_MESSAGE_LEN]);
            assert!(got[0].truncated);
            assert_eq!(got[1].message, b"<13>next");
            assert!(!got[1].truncated);
        }
        // A message of exactly the limit is whole.
        let exact = vec![b'<'; MAX_MESSAGE_LEN];
        let mut d = Stream::new(Frames::new());
        assert_eq!(
            d.push(&[exact.as_slice(), b"\r\n"].concat()),
            [exact.as_slice(), b"\r\n"].concat().len()
        );
        let f = d.next().unwrap().unwrap();
        assert_eq!((f.message.len(), f.truncated), (MAX_MESSAGE_LEN, false));
    }

    #[test]
    fn many_frames_in_one_push_take_linear_time() {
        assert_linear(
            "many_frames_in_one_push_take_linear_time",
            rounds(100000),
            |size| {
                let n = size;
                let data = b"<13>x\n".repeat(n);
                let mut stream = Stream::new(Frames::new());
                let mut count = 0;
                pump(&mut stream, &data, |f| {
                    assert_eq!(f.message, b"<13>x");
                    count += 1;
                })
                .unwrap();
                assert_eq!((count, stream.buffered()), (n, 0));
                pump(&mut stream, &vec![b'\n'; 6 * n], |_| panic!("blank frame")).unwrap();
                assert_eq!(stream.buffered(), 0);
                // Bytes held after a frame is taken still count, and still frame.
                let mut d = Stream::new(Frames::new());
                assert_eq!(d.push(b"<13>a\n<13>b\n<13>"), b"<13>a\n<13>b\n<13>".len());
                assert_eq!(d.next().unwrap().unwrap().message, b"<13>a");
                assert_eq!(d.buffered(), 10);
                assert_eq!(d.push(b"c\n"), b"c\n".len());
                assert_eq!(d.next().unwrap().unwrap().message, b"<13>b");
                assert_eq!(d.next().unwrap().unwrap().message, b"<13>c");
                assert_eq!(d.buffered(), 0);
            },
        );
    }

    #[test]
    fn end_takes_the_last_unended_message() {
        let (frames, error) = decode_all(Frames::new, b"<13>a\n<13>last");
        assert_eq!(error, None);
        assert_eq!(
            frames,
            [
                Frame::new(Framing::NonTransparent, b"<13>a".to_vec()),
                Frame::new(Framing::NonTransparent, b"<13>last".to_vec())
            ]
        );
        assert!(matches!(
            decode_all(Frames::new, b"10 <13>").1,
            Some(Fail::Truncated { .. })
        ));
        assert!(matches!(
            decode_all(Frames::new, b"1x").1,
            Some(Fail::Protocol(_))
        ));
        assert_eq!(decode_all(Frames::new, b""), (vec![], None));
        for len in [MAX_MESSAGE_LEN + 1, MAX_MESSAGE_LEN + 2] {
            let bytes = vec![b'<'; len];
            contract::check_decode_with_alloc_limit(Frames::new, &bytes, 2 * MAX_BUFFERED);
            let (frames, error) = decode_all(Frames::new, &bytes);
            assert_eq!(error, None);
            assert_eq!(frames.len(), 1);
            assert_eq!(
                (frames[0].message.len(), frames[0].truncated),
                (MAX_MESSAGE_LEN, true)
            );
        }
        let mut frames = Frames::new();
        assert_eq!(frames.decode(b"<13>x", false), Ok(Step::Need));
        assert_eq!(
            frames.clone().decode(b"<13>x\n", false),
            Ok(Step::Item(
                Frame::new(Framing::NonTransparent, b"<13>x".to_vec()),
                6
            ))
        );
    }

    #[test]
    fn module_example() {
        let mut message = Message::new(Priority::new(Facility::Auth, Severity::Critical));
        message.hostname = Some("mymachine.example.com".into());
        message.app_name = Some("su".into());
        message.msg_id = Some("ID47".into());
        message
            .structured_data
            .push(SdElement::new("origin").param("ip", "192.0.2.1"));
        message.msg = b"'su root' failed".to_vec();
        let bytes = message.to_bytes().unwrap();
        assert_eq!(
            bytes,
            b"<34>1 - mymachine.example.com su - ID47 [origin ip=\"192.0.2.1\"] 'su root' failed"
        );
        let mut decoder = Stream::new(Frames::new());
        assert_eq!(
            decoder.push(
                &Frame::new(Framing::OctetCounting, bytes.clone())
                    .to_bytes()
                    .unwrap()
            ),
            Frame::new(Framing::OctetCounting, bytes.clone())
                .to_bytes()
                .unwrap()
                .len()
        );
        assert_eq!(
            decoder.push(
                &Frame::new(Framing::NonTransparent, bytes.clone())
                    .to_bytes()
                    .unwrap()
            ),
            Frame::new(Framing::NonTransparent, bytes)
                .to_bytes()
                .unwrap()
                .len()
        );
        assert_eq!(
            decoder.push(b"<13>Oct  5 12:00:00 gw sshd[42]: Accepted publickey\n"),
            b"<13>Oct  5 12:00:00 gw sshd[42]: Accepted publickey\n".len()
        );
        let mut got = Vec::new();
        while let Some(frame) = decoder.next() {
            got.push(Entry::parse(&frame.unwrap().message).unwrap());
        }
        assert_eq!(got.len(), 3);
        assert_eq!(got[0], Entry::Rfc5424(message));
        let Entry::Bsd(bsd) = &got[2] else {
            panic!("not a BSD message")
        };
        assert_eq!(bsd.priority.facility, Facility::User);
        assert_eq!(bsd.priority.severity, Severity::Notice);
        assert_eq!(bsd.tag.as_deref(), Some("sshd"));
        assert_eq!(bsd.pid.as_deref(), Some("42"));
        assert_eq!(bsd.content, b"Accepted publickey");
    }

    #[test]
    fn stream_holds_a_bounded_number_of_bytes() {
        let big = vec![b'<'; rounds(4 << 20)];
        contract::check_decode_with_alloc_limit(Frames::new, &big, 2 * MAX_BUFFERED);
        let (frames, error) = decode_all(Frames::new, &big);
        assert_eq!(error, None);
        assert_eq!(frames.len(), 1);
        assert!(frames[0].truncated);
        let bytes = [
            format!("{} ", usize::MAX).as_bytes(),
            &vec![b'x'; MAX_MESSAGE_LEN],
        ]
        .concat();
        let (frames, error) = decode_all(Frames::new, &bytes);
        assert_eq!(
            (frames[0].message.len(), frames[0].truncated),
            (MAX_MESSAGE_LEN, true)
        );
        assert!(matches!(
            error,
            Some(Fail::Protocol(Error::Incomplete { .. }))
        ));
        let mut stream = Stream::new(Frames::new());
        assert_eq!(stream.push(b"1x"), 2);
        assert!(stream.next().unwrap().is_err());
        assert_eq!(stream.push(&big), big.len());
    }

    #[test]
    fn structured_data_writer_stops_at_the_limit() {
        // Escaping a value used to build the whole element, twice the
        // value's size, before checking it fit.
        let mut out = b"<13>1 - - - - - ".to_vec();
        let params = [SdParam {
            name: "p".into(),
            value: "\\".repeat(1 << 20),
        }];
        assert!(write_sd_element(&mut out, "x", &params).is_err());
        assert!(out.len() <= MAX_MESSAGE_LEN + 2);
        let mut m = Message::new(Priority::new(Facility::User, Severity::Notice));
        m.structured_data
            .push(SdElement::new("x").param("p", "\\".repeat(1 << 20)));
        assert!(m.to_bytes().is_err());
    }

    #[test]
    fn parsed_messages_near_the_limit_write_back_whole() {
        // Each invalid escape used to be written as three bytes, so this
        // 44 kB message grew past the limit and lost its element.
        let raw = [
            &b"<13>1 - - - - - [x@32473 p=\""[..],
            &br"\n".repeat(22_000),
            b"\"]",
        ]
        .concat();
        let m = Message::parse(&raw).unwrap();
        assert_eq!(m.to_bytes().unwrap(), raw);
        assert_eq!(Message::parse(&m.to_bytes().unwrap()).unwrap(), m);
        // A BSD message at the limit with no space after the tag's colon
        // used to lose its last byte to the space the writer added.
        let raw = [&b"<13>app:"[..], &vec![b'x'; MAX_MESSAGE_LEN - 8]].concat();
        let m = BsdMessage::parse(&raw).unwrap();
        assert_eq!(m.to_bytes().unwrap(), raw);
        assert_eq!(BsdMessage::parse(&m.to_bytes().unwrap()).unwrap(), m);
        // A required separator cannot displace content at the size limit.
        let mut m = BsdMessage::new(
            Priority::new(Facility::User, Severity::Notice),
            vec![b' '; MAX_MESSAGE_LEN],
        );
        m.tag = Some("app".into());
        assert!(m.to_bytes().is_err());
        contract::check_wire_value(&m);
    }

    #[test]
    fn entries_written_always_read() {
        // A BSD message whose text starts with a short number and a space
        // used to be written as bytes Entry::parse rejected.
        for content in [&b"1 x"[..], b"12 - x", b"999 "] {
            let e = Entry::Bsd(BsdMessage::new(
                Priority::new(Facility::User, Severity::Notice),
                content,
            ));
            assert_eq!(Entry::parse(&e.to_bytes().unwrap()), Ok(e));
        }
        // Content that is an RFC 5424 message reads as one.
        let e = Entry::Bsd(BsdMessage::new(
            Priority::new(Facility::User, Severity::Notice),
            "1 - - - - - -",
        ));
        assert!(e.to_bytes().is_err());
        contract::check_wire_value(&e);
    }

    #[test]
    fn non_transparent_frames_keep_newlines() {
        let msg = b"<13>1 - - - - - - first\nsecond".to_vec();
        let f = Frame::new(Framing::NonTransparent, msg.clone());
        assert!(f.to_bytes().is_err());
        contract::check_wire_value(&f);
        let f = Frame::new(Framing::OctetCounting, msg);
        contract::check_wire_value(&f);
    }

    fn check_round_trip(raw: &[u8]) {
        contract::check_wire::<Message>(raw);
        contract::check_wire::<BsdMessage>(raw);
        contract::check_wire::<Entry>(raw);
        contract::check_wire::<Timestamp>(raw);
        contract::check_wire::<BsdTimestamp>(raw);
    }

    fn check_stream(data: &[u8]) {
        contract::check_decode_with_alloc_limit(Frames::new, data, 2 * MAX_BUFFERED);
        for frame in decode_all(Frames::new, data).0 {
            assert!(!frame.message.is_empty() && frame.message.len() <= MAX_MESSAGE_LEN);
            contract::check_wire_value(&frame);
            check_round_trip(&frame.message);
        }
    }

    #[test]
    fn lcg_fuzz() {
        let mut rng = Lcg::new(0x5eed_5151_0601);
        let pieces: &[&[u8]] = &[
            b"<34>",
            b"<165>",
            b"<0>",
            b"<192>",
            b"<",
            b">",
            b"1",
            b"12",
            b" ",
            b"-",
            b"2003-10-11T22:14:15.003Z",
            b"2003-08-24T05:14:15.000003-07:00",
            b"host",
            b"[",
            b"]",
            b"id@1",
            b"=",
            b"\"",
            b"\\",
            b"v",
            b"\xef\xbb\xbf",
            b"\xff",
            b"Oct 11 22:14:15",
            b"Feb  5 17:32:18",
            b"tag",
            b"[42]",
            b":",
            b"\n",
            b"\r",
            b"7 ",
            b"\xc3\xa9",
        ];
        for _ in 0..4000 {
            // Bytes built from pieces of real messages, and plain noise.
            let mut buf = Vec::new();
            for _ in 0..rng.index(24) {
                if rng.index(4) == 0 {
                    buf.push(rng.next() as u8);
                } else {
                    buf.extend_from_slice(pieces[rng.index(pieces.len())]);
                }
            }
            if rng.coin() {
                mutate(&mut rng, &mut buf);
            }
            check_round_trip(&buf);
            check_stream(&buf);
            for n in 0..buf.len() {
                let _ = Entry::parse(&buf[..n]);
            }
        }
        for _ in 0..12 {
            // Streams with messages near and past the length limit, framed
            // both ways, some with CR LF trailers and some left unended.
            let mut buf = Vec::new();
            let count = rng.index(4) + 1;
            for i in 0..count {
                let len = MAX_MESSAGE_LEN - 2 + rng.index(5);
                if rng.index(3) == 0 {
                    buf.extend_from_slice(format!("{len} ").as_bytes());
                    buf.extend_from_slice(&vec![b'<'; len]);
                } else {
                    buf.extend_from_slice(&vec![b'<'; len]);
                    if i + 1 < count || rng.coin() {
                        buf.extend_from_slice([&b"\n"[..], b"\r\n", b"\r\r\n"][rng.index(3)]);
                    }
                }
            }
            check_stream(&buf);
        }
        let alphabet = ["é", "\n"];
        for round in 0..2000 {
            // Messages built from random values: what is written reads back,
            // and writing that again gives the same bytes.
            let mut m = Message::new(Priority::from_value(rng.index(192) as u8).unwrap());
            m.version = rng.index(1200) as u16;
            if rng.coin() {
                m.timestamp = Some(Timestamp {
                    year: rng.index(10500) as u16,
                    month: rng.index(14) as u8,
                    day: rng.index(33) as u8,
                    hour: rng.index(26) as u8,
                    minute: rng.index(62) as u8,
                    second: rng.index(62) as u8,
                    fraction: if rng.coin() {
                        None
                    } else {
                        Some(Fraction {
                            value: rng.next() as u32,
                            digits: rng.index(9) as u8,
                        })
                    },
                    offset: if rng.coin() {
                        Offset::Utc
                    } else {
                        Offset::Minutes(rng.next() as i16)
                    },
                });
            }
            m.hostname = (rng.index(3) > 0).then(|| rng.text(300));
            m.app_name = (rng.index(3) > 0).then(|| rng.text(60));
            m.proc_id = (rng.index(3) > 0).then(|| rng.text(10));
            m.msg_id = (rng.index(3) > 0).then(|| rng.text(40));
            for _ in 0..rng.index(4) {
                let mut e = SdElement::new(rng.text(40));
                for _ in 0..rng.index(4) {
                    let mut value = rng.text(10);
                    if rng.coin() {
                        value.push_str(alphabet[rng.index(alphabet.len())]);
                    }
                    e = e.param(rng.text(5), value);
                }
                m.structured_data.push(e);
            }
            m.bom = rng.coin();
            m.msg = if rng.coin() {
                rng.text(20).into_bytes()
            } else {
                rng.bytes(19)
            };
            if round % 2 == 0 {
                m.version = 1 + rng.index(usize::from(MAX_VERSION)) as u16;
                if let Some(t) = &mut m.timestamp {
                    t.year %= 10000;
                    t.month = 1 + t.month % 12;
                    t.day = 1 + t.day % 28;
                    t.hour %= 24;
                    t.minute %= 60;
                    t.second %= 60;
                    if let Some(f) = &mut t.fraction {
                        f.digits = 6;
                        f.value %= 1_000_000;
                    }
                    if let Offset::Minutes(m) = &mut t.offset {
                        *m %= MAX_OFFSET_MINUTES + 1;
                    }
                }
                for field in [
                    &mut m.hostname,
                    &mut m.app_name,
                    &mut m.proc_id,
                    &mut m.msg_id,
                ] {
                    if field.is_some() {
                        *field = Some(format!("field{}", rng.index(10000)));
                    }
                }
                for (i, element) in m.structured_data.iter_mut().enumerate() {
                    element.id = format!("id{i}@32473");
                    for (j, param) in element.params.iter_mut().enumerate() {
                        param.name = format!("p{j}");
                    }
                }
                m.msg = rng.text(20).into_bytes();
            }
            if m.bom && rng.coin() {
                m.msg
                    .extend_from_slice(alphabet[rng.index(alphabet.len())].as_bytes());
            }
            if round % 2 == 0 {
                assert!(m.to_bytes().is_ok());
            }
            contract::check_wire_value(&m);
            if let Ok(bytes) = m.to_bytes() {
                let framing = if rng.coin() {
                    Framing::OctetCounting
                } else {
                    Framing::NonTransparent
                };
                let frame = Frame::new(framing, bytes);
                contract::check_wire_value(&frame);
                if let Ok(bytes) = frame.to_bytes() {
                    check_stream(&bytes);
                }
            }

            let mut b = BsdMessage::new(m.priority, m.msg.clone());
            if rng.coin() {
                b.header = Some(BsdHeader {
                    timestamp: BsdTimestamp {
                        month: rng.index(14) as u8,
                        day: rng.index(33) as u8,
                        hour: rng.index(26) as u8,
                        minute: rng.index(62) as u8,
                        second: rng.index(62) as u8,
                    },
                    hostname: rng.text(10),
                });
            }
            b.tag = rng.coin().then(|| rng.text(8));
            b.pid = rng.coin().then(|| rng.text(4));
            contract::check_wire_value(&b);
        }
    }
}
