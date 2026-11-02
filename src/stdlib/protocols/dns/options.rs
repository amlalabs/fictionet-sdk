//! EDNS options hickory carries without a type of its own: Extended DNS
//! Errors (RFC 8914) and Padding (RFC 7830), plus the server identifier
//! NSID (RFC 5001), which hickory types as
//! [`EdnsOption::NSID`](super::rr::rdata::opt::EdnsOption::NSID).
//!
//! Each type converts to and from one [`EdnsOption`] in an OPT record.
//! A message may carry several Extended DNS Errors (RFC 8914 §3).

use std::fmt;

use super::rr::rdata::opt::{EdnsOption, NSIDPayload};

/// The EDNS option code of an Extended DNS Error (RFC 8914 §2).
const EDE: u16 = 15;
/// The EDNS option code of Padding (RFC 7830 §3).
const PADDING: u16 = 12;
/// The EDNS option code of NSID (RFC 5001 §2.3).
const NSID: u16 = 3;

/// An Extended DNS Error: a code from the IANA registry and optional text
/// for a person to read (RFC 8914 §2).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Ede {
    /// What went wrong.
    pub code: EdeCode,
    /// More detail, for a person, never for a program (RFC 8914 §2).
    pub text: Option<String>,
}

impl Ede {
    /// An error with `code` and no text.
    pub fn new(code: EdeCode) -> Ede {
        Ede { code, text: None }
    }

    /// The option: INFO-CODE in two octets, then EXTRA-TEXT in UTF-8 with
    /// no terminating NUL (RFC 8914 §2).
    ///
    /// # Panics
    ///
    /// If the text is longer than 65533 octets, since an option's data
    /// has a 16-bit length (RFC 6891 §6.1.2).
    pub fn to_option(&self) -> EdnsOption {
        let mut data = self.code.0.to_be_bytes().to_vec();
        if let Some(text) = &self.text {
            data.extend_from_slice(text.as_bytes());
        }
        assert!(
            data.len() <= usize::from(u16::MAX),
            "an Extended DNS Error's text fits in one EDNS option"
        );
        EdnsOption::Unknown(EDE, data)
    }

    /// The Extended DNS Error in `option`, or `None` if `option` is another
    /// option or shorter than an INFO-CODE. An unassigned code is carried.
    /// Text that is not UTF-8 is read with each bad sequence replaced by
    /// U+FFFD, and empty text is `None`.
    pub fn from_option(option: &EdnsOption) -> Option<Ede> {
        let EdnsOption::Unknown(EDE, data) = option else {
            return None;
        };
        let (code, text) = data.split_first_chunk::<2>()?;
        Some(Ede {
            code: EdeCode(u16::from_be_bytes(*code)),
            text: (!text.is_empty()).then(|| String::from_utf8_lossy(text).into_owned()),
        })
    }
}

impl fmt::Display for Ede {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.code)?;
        if let Some(text) = &self.text {
            write!(f, ": {text}")?;
        }
        Ok(())
    }
}

/// An Extended DNS Error code. The constants are every code the IANA
/// registry assigned when it was read on 2026-11-01 (0 to 35). Any other
/// value, such as one a real server sends from a newer registry or the
/// private use range, is carried as it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EdeCode(pub u16);

macro_rules! ede_codes {
    ($($(#[$doc:meta])* $name:ident = $code:literal, $purpose:literal;)*) => {
        impl EdeCode {
            $(
                $(#[$doc])*
                pub const $name: EdeCode = EdeCode($code);
            )*

            /// The code's purpose as the IANA registry names it, or `None`
            /// for a code that was unassigned when the registry was read.
            pub fn purpose(self) -> Option<&'static str> {
                match self.0 {
                    $($code => Some($purpose),)*
                    _ => None,
                }
            }
        }
    };
}

ede_codes! {
    /// RFC 8914 §4.1.
    OTHER = 0, "Other Error";
    /// RFC 8914 §4.2.
    UNSUPPORTED_DNSKEY_ALGORITHM = 1, "Unsupported DNSKEY Algorithm";
    /// RFC 8914 §4.3.
    UNSUPPORTED_DS_DIGEST_TYPE = 2, "Unsupported DS Digest Type";
    /// RFC 8914 §4.4 and RFC 8767.
    STALE_ANSWER = 3, "Stale Answer";
    /// RFC 8914 §4.5.
    FORGED_ANSWER = 4, "Forged Answer";
    /// RFC 8914 §4.6.
    DNSSEC_INDETERMINATE = 5, "DNSSEC Indeterminate";
    /// RFC 8914 §4.7.
    DNSSEC_BOGUS = 6, "DNSSEC Bogus";
    /// RFC 8914 §4.8.
    SIGNATURE_EXPIRED = 7, "Signature Expired";
    /// RFC 8914 §4.9.
    SIGNATURE_NOT_YET_VALID = 8, "Signature Not Yet Valid";
    /// RFC 8914 §4.10.
    DNSKEY_MISSING = 9, "DNSKEY Missing";
    /// RFC 8914 §4.11.
    RRSIGS_MISSING = 10, "RRSIGs Missing";
    /// RFC 8914 §4.12.
    NO_ZONE_KEY_BIT_SET = 11, "No Zone Key Bit Set";
    /// RFC 8914 §4.13.
    NSEC_MISSING = 12, "NSEC Missing";
    /// RFC 8914 §4.14.
    CACHED_ERROR = 13, "Cached Error";
    /// RFC 8914 §4.15.
    NOT_READY = 14, "Not Ready";
    /// RFC 8914 §4.16.
    BLOCKED = 15, "Blocked";
    /// RFC 8914 §4.17.
    CENSORED = 16, "Censored";
    /// RFC 8914 §4.18.
    FILTERED = 17, "Filtered";
    /// RFC 8914 §4.19.
    PROHIBITED = 18, "Prohibited";
    /// RFC 8914 §4.20.
    STALE_NXDOMAIN_ANSWER = 19, "Stale NXDomain Answer";
    /// RFC 8914 §4.21.
    NOT_AUTHORITATIVE = 20, "Not Authoritative";
    /// RFC 8914 §4.22.
    NOT_SUPPORTED = 21, "Not Supported";
    /// RFC 8914 §4.23.
    NO_REACHABLE_AUTHORITY = 22, "No Reachable Authority";
    /// RFC 8914 §4.24.
    NETWORK_ERROR = 23, "Network Error";
    /// RFC 8914 §4.25.
    INVALID_DATA = 24, "Invalid Data";
    /// Registered for Unbound.
    SIGNATURE_EXPIRED_BEFORE_VALID = 25, "Signature Expired before Valid";
    /// RFC 9250.
    TOO_EARLY = 26, "Too Early";
    /// RFC 9276.
    UNSUPPORTED_NSEC3_ITERATIONS = 27, "Unsupported NSEC3 Iterations Value";
    /// draft-homburg-dnsop-codcp.
    UNABLE_TO_CONFORM_TO_POLICY = 28, "Unable to conform to policy";
    /// Registered for PowerDNS.
    SYNTHESIZED = 29, "Synthesized";
    /// RFC 9824.
    INVALID_QUERY_TYPE = 30, "Invalid Query Type";
    /// draft-muks-dns-ede-rate-limited §2.
    RATE_LIMITED = 31, "Rate Limited";
    /// draft-muks-dns-ede-rate-limited §3.
    OVER_QUOTA = 32, "Over Quota";
    /// draft-farrokhi-dnsop-ede-nta.
    NEGATIVE_TRUST_ANCHOR = 33, "Negative Trust Anchor";
    /// draft-ietf-deleg.
    NEW_DELEGATION_ONLY = 34, "New Delegation Only";
    /// The structured DNS error RFC of the dnsop working group.
    BLOCKED_BY_UPSTREAM = 35, "Blocked by Upstream DNS Server";
}

impl fmt::Display for EdeCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.purpose() {
            Some(purpose) => write!(f, "{} ({purpose})", self.0),
            None => write!(f, "{}", self.0),
        }
    }
}

/// A name server identifier: opaque octets a server chooses to say which
/// server answered (RFC 5001 §2.3). In a query the option is empty and
/// asks for one.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Nsid(pub Vec<u8>);

impl Nsid {
    /// The option.
    ///
    /// # Panics
    ///
    /// If the identifier is longer than 65535 octets, since an option's
    /// data has a 16-bit length (RFC 6891 §6.1.2).
    pub fn to_option(&self) -> EdnsOption {
        EdnsOption::NSID(NSIDPayload::new(self.0.clone()).expect("an NSID fits in one EDNS option"))
    }

    /// The identifier in `option`, or `None` for another option.
    pub fn from_option(option: &EdnsOption) -> Option<Nsid> {
        match option {
            EdnsOption::NSID(payload) => Some(Nsid(payload.as_ref().to_vec())),
            EdnsOption::Unknown(NSID, data) => Some(Nsid(data.clone())),
            _ => None,
        }
    }
}

/// Padding: this many zero octets, which make a message's length tell less
/// about its content (RFC 7830 §3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Padding(pub u16);

impl Padding {
    /// The option, its octets all zero (RFC 7830 §3).
    pub fn to_option(&self) -> EdnsOption {
        EdnsOption::Unknown(PADDING, vec![0; usize::from(self.0)])
    }

    /// The padding in `option`, or `None` for another option. The octets
    /// are counted whatever their value, since a receiver must ignore
    /// them (RFC 7830 §3).
    pub fn from_option(option: &EdnsOption) -> Option<Padding> {
        let EdnsOption::Unknown(PADDING, data) = option else {
            return None;
        };
        u16::try_from(data.len()).ok().map(Padding)
    }
}

#[cfg(test)]
mod tests {
    use super::super::op::{Edns, Message, MessageType, OpCode};
    use super::super::rr::rdata::opt::EdnsCode;
    use super::*;

    /// `option` written in an OPT record and read back.
    fn on_the_wire(option: EdnsOption) -> EdnsOption {
        let mut message = Message::new(1, MessageType::Response, OpCode::Query);
        let mut edns = Edns::new();
        edns.options_mut().insert(option);
        message.set_edns(edns);
        let back = Message::from_vec(&message.to_vec().unwrap()).unwrap();
        let options = back.edns.unwrap().options().as_ref().to_vec();
        assert_eq!(options.len(), 1);
        options.into_iter().next().unwrap().1
    }

    #[test]
    fn ede_round_trips_with_and_without_text() {
        for ede in [
            Ede::new(EdeCode::NO_REACHABLE_AUTHORITY),
            Ede {
                code: EdeCode::CACHED_ERROR,
                text: Some("from the failure cache".into()),
            },
            Ede::new(EdeCode(49152)),
        ] {
            let option = ede.to_option();
            assert_eq!(Ede::from_option(&option), Some(ede.clone()));
            assert_eq!(Ede::from_option(&on_the_wire(option)), Some(ede));
        }
    }

    #[test]
    fn ede_wire_form_is_the_code_then_the_text() {
        let ede = Ede {
            code: EdeCode::UNSUPPORTED_NSEC3_ITERATIONS,
            text: Some("x".into()),
        };
        assert_eq!(ede.to_option(), EdnsOption::Unknown(15, vec![0, 27, b'x']));
        assert_eq!(Ede::from_option(&EdnsOption::Unknown(15, vec![0])), None);
        assert_eq!(
            Ede::from_option(&EdnsOption::Unknown(15, vec![0, 6])),
            Some(Ede::new(EdeCode::DNSSEC_BOGUS))
        );
        assert_eq!(
            Ede::from_option(&EdnsOption::Unknown(15, vec![0, 6, 0xff])),
            Some(Ede {
                code: EdeCode::DNSSEC_BOGUS,
                text: Some("\u{fffd}".into())
            })
        );
        assert_eq!(Ede::from_option(&Padding(2).to_option()), None);
    }

    #[test]
    fn every_assigned_code_has_its_registry_purpose() {
        let assigned: Vec<u16> = (0..=u16::MAX)
            .filter(|&code| EdeCode(code).purpose().is_some())
            .collect();
        assert_eq!(assigned, (0..=35).collect::<Vec<_>>());
        assert_eq!(EdeCode::OTHER, EdeCode(0));
        assert_eq!(EdeCode::CACHED_ERROR, EdeCode(13));
        assert_eq!(EdeCode::NO_REACHABLE_AUTHORITY, EdeCode(22));
        assert_eq!(EdeCode::UNSUPPORTED_NSEC3_ITERATIONS, EdeCode(27));
        assert_eq!(EdeCode::BLOCKED_BY_UPSTREAM, EdeCode(35));
        assert_eq!(
            EdeCode::NOT_AUTHORITATIVE.to_string(),
            "20 (Not Authoritative)"
        );
        assert_eq!(EdeCode(36).to_string(), "36");
    }

    #[test]
    fn nsid_round_trips() {
        for nsid in [Nsid(Vec::new()), Nsid(b"a.root-servers.net".to_vec())] {
            let option = nsid.to_option();
            assert_eq!(EdnsCode::from(&option), EdnsCode::NSID);
            assert_eq!(Nsid::from_option(&option), Some(nsid.clone()));
            assert_eq!(Nsid::from_option(&on_the_wire(option)), Some(nsid));
        }
        assert_eq!(
            Nsid::from_option(&EdnsOption::Unknown(3, vec![1])),
            Some(Nsid(vec![1]))
        );
        assert_eq!(Nsid::from_option(&Padding(1).to_option()), None);
    }

    #[test]
    fn padding_round_trips() {
        for padding in [Padding(0), Padding(1), Padding(468)] {
            let option = padding.to_option();
            assert_eq!(Padding::from_option(&option), Some(padding));
            assert_eq!(Padding::from_option(&on_the_wire(option)), Some(padding));
        }
        assert_eq!(
            Padding::from_option(&EdnsOption::Unknown(12, vec![1, 2, 3])),
            Some(Padding(3))
        );
        assert_eq!(
            Padding::from_option(&Ede::new(EdeCode::OTHER).to_option()),
            None
        );
    }
}
