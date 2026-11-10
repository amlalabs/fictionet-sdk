//! Signing one RRset: the RRSIG record of RFC 4034 §3.
//!
//! The bytes signed are hickory's to-be-signed form (RFC 4034 §3.1.8.1):
//! the RRSIG fields without the signature, then each record of the set in
//! canonical form and order. The signature comes from a [`Sign`], which
//! for a [`ZoneKey`](super::ZoneKey) draws no randomness, so the same set,
//! key, and window always give the same record.

use std::time::{SystemTime, UNIX_EPOCH};

use super::keys::{Sign, key_tag};
use super::rdata::{DNSSECRData, RRSIG, SigInput};
use crate::stdlib::protocols::dns::ProtoError;
use crate::stdlib::protocols::dns::rr::{Name, RData, Record, RecordSet, RecordType, SerialNumber};
use hickory_proto::dnssec::{PublicKey, TBS};

/// When a signature is valid: from `inception` to `expiration`, both
/// included (RFC 4034 §3.1.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Window {
    /// The first second the signature is valid.
    pub inception: SystemTime,
    /// The last second the signature is valid.
    pub expiration: SystemTime,
}

/// One RRSIG over `set` by `key`, for the zone `signer`.
///
/// The RRSIG has the set's owner, class, and TTL, which is also its
/// original TTL. Its labels field leaves out a leading `*`, so a wildcard
/// set signs as RFC 4035 §5.3.4 expects. Any RRSIGs already in `set` are
/// not covered. The error is hickory's, for a record whose data does not
/// encode.
pub fn sign(
    key: &dyn Sign,
    set: &RecordSet,
    signer: &Name,
    window: Window,
) -> Result<Record, ProtoError> {
    let dnskey = key.dnskey();
    let input = SigInput {
        type_covered: set.record_type(),
        algorithm: dnskey.public_key().algorithm(),
        num_labels: set.name().num_labels(),
        original_ttl: set.ttl(),
        sig_expiration: serial(window.expiration),
        sig_inception: serial(window.inception),
        key_tag: key_tag(&dnskey),
        // RFC 6840 §5.1: the signer's name in canonical, lowercase form.
        signer_name: signer.to_lowercase(),
    };
    let tbs = signed_data(set, &input)?;
    let signature = key.sign(tbs.as_ref());
    let mut record = Record::from_rdata(
        set.name().clone(),
        set.ttl(),
        RData::DNSSEC(DNSSECRData::RRSIG(RRSIG::from_sig(input, signature))),
    );
    record.dns_class = set.dns_class();
    Ok(record)
}

/// The bytes an RRSIG with `input` signs over `set` (RFC 4035 §5.3.2):
/// the RRSIG's fields, then each record in canonical form and order.
///
/// hickory writes each record in canonical form, with the names in its
/// RDATA in lowercase (RFC 4034 §6.2 item 3, as RFC 6840 §5.1 amends it)
/// for the types it knows; those on that list it carries as unknown RDATA
/// are lowercased here. hickory would order the records by their TTL and
/// their RDATA as written, case and all, so each record is written alone
/// and put in canonical order here: by its canonical RDATA, as a string of
/// octets (RFC 4034 §6.3), with records whose canonical forms are equal
/// written once, as §6.3 requires of an RRset that holds such duplicates.
/// The error is hickory's, for a record whose data does not encode.
pub fn signed_data(set: &RecordSet, input: &SigInput) -> Result<TBS, ProtoError> {
    let fields = TBS::from_input(set.name(), set.dns_class(), input, std::iter::empty())?;
    let fields = fields.as_ref();
    let mut records = set
        .records_without_rrsigs()
        .map(|record| {
            let mut record = record.clone();
            if let RData::Unknown { code, rdata } = &mut record.data {
                lowercase_names(*code, &mut rdata.anything);
            }
            let alone =
                TBS::from_input(set.name(), set.dns_class(), input, std::iter::once(&record))?;
            Ok(alone.as_ref()[fields.len()..].to_vec())
        })
        .collect::<Result<Vec<Vec<u8>>, ProtoError>>()?;
    records.sort_by(|a, b| rdata(a).cmp(rdata(b)));
    // Records that differ only in the case of a name are one record in
    // canonical form, and all but one of them must go (RFC 4034 §6.3).
    records.dedup();
    Ok(TBS::from(&[fields, &records.concat()].concat()[..]))
}

/// The RDATA of `record`, one record of the signed data: what follows its
/// uncompressed owner name, type, class, TTL, and RDATA length.
fn rdata(record: &[u8]) -> &[u8] {
    let mut at = 0;
    while let Some(&length) = record.get(at).filter(|length| **length != 0) {
        at += 1 + usize::from(length);
    }
    record.get(at + 1 + 10..).unwrap_or_default()
}

/// Lowercases the uncompressed names in `rdata`, the RDATA of a type on
/// the list of RFC 4034 §6.2 item 3 that hickory carries as unknown RDATA.
/// The RDATA of any other type is left as it is, and so is a name that
/// does not read.
fn lowercase_names(rtype: RecordType, rdata: &mut [u8]) {
    // Where the first name starts, and how many names follow one another
    // from there.
    let (start, names) = match u16::from(rtype) {
        // MD, MF, MB, MG, MR (RFC 1035 §3.3), NXT, whose type bitmap
        // follows its name (RFC 2535 §5.2), and DNAME (RFC 6672 §2.1).
        3 | 4 | 7 | 8 | 9 | 30 | 39 => (0, 1),
        // MINFO (RFC 1035 §3.3.7) and RP (RFC 1183 §2.2).
        14 | 17 => (0, 2),
        // AFSDB (RFC 1183 §1), RT (RFC 1183 §3.3), and KX (RFC 2230 §3.1),
        // each after a 16-bit field.
        18 | 21 | 36 => (2, 1),
        // PX, after its preference (RFC 2163 §4).
        26 => (2, 2),
        // A6: the prefix length, the address suffix, then the prefix name
        // when the prefix length is not 0 (RFC 2874 §3.1.1).
        38 => match rdata.first() {
            Some(&prefix @ 1..=128) => (1 + usize::from(128 - prefix).div_ceil(8), 1),
            _ => return,
        },
        _ => return,
    };
    let mut at = start;
    for _ in 0..names {
        // Labels until the root; a length above 63 is no label.
        loop {
            let Some(&length) = rdata.get(at) else {
                return;
            };
            let length = usize::from(length);
            if length == 0 {
                at += 1;
                break;
            }
            let Some(label) = rdata
                .get_mut(at + 1..at + 1 + length)
                .filter(|_| length <= 63)
            else {
                return;
            };
            label.make_ascii_lowercase();
            at += 1 + length;
        }
    }
}

/// A time as an RRSIG field: seconds since 1970 modulo 2^32, compared with
/// serial number arithmetic (RFC 4034 §3.1.5, RFC 1982). Times before 1970
/// read as 0.
pub(crate) fn serial(time: SystemTime) -> SerialNumber {
    let seconds = time
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    SerialNumber::new(seconds as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stdlib::protocols::dns::dnssec::{Algorithm, KeyFlags, Ring, Verify, ZoneKey};
    use crate::stdlib::protocols::dns::rr::RecordType;
    use crate::stdlib::protocols::dns::rr::rdata::A;
    use fictionet::{Seed, SeededEntropy};
    use std::time::Duration;

    fn window() -> Window {
        Window {
            inception: UNIX_EPOCH + Duration::from_secs(1_700_000_000),
            expiration: UNIX_EPOCH + Duration::from_secs(1_800_000_000),
        }
    }

    fn a_set(owner: &str) -> RecordSet {
        let name = Name::from_ascii(owner).unwrap();
        let mut set = RecordSet::with_ttl(name.clone(), RecordType::A, 300);
        for last in [1, 2] {
            let rdata = RData::A(A::new(192, 0, 2, last));
            set.insert(Record::from_rdata(name.clone(), 300, rdata), 0);
        }
        set
    }

    fn verifies(key: &ZoneKey, set: &RecordSet, rrsig: &Record) -> bool {
        let RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) = &rrsig.data else {
            panic!("an RRSIG");
        };
        let tbs = signed_data(set, rrsig.input()).unwrap();
        Ring.verify(&key.dnskey(), tbs.as_ref(), rrsig.sig())
    }

    #[test]
    fn every_algorithm_signs_deterministically_and_ring_verifies() {
        let entropy = SeededEntropy::new(Seed::from_u64(7));
        let rsa = ZoneKey::generate(&entropy, Algorithm::RsaSha256, KeyFlags::KSK).to_pkcs8();
        let keys = Algorithm::ALL.map(|algorithm| match algorithm {
            // One RSA modulus serves both RSA algorithms; generating it is
            // the slow part.
            Algorithm::RsaSha256 | Algorithm::RsaSha512 => {
                ZoneKey::from_pkcs8(&rsa, algorithm, KeyFlags::KSK).unwrap()
            }
            _ => ZoneKey::generate(&entropy, algorithm, KeyFlags::ZSK),
        });
        let set = a_set("www.Example.");
        let signer = Name::from_ascii("Example.").unwrap();
        for key in &keys {
            let rrsig = sign(key, &set, &signer, window()).unwrap();
            assert_eq!(
                sign(key, &set, &signer, window()).unwrap(),
                rrsig,
                "{:?} signs deterministically",
                key.algorithm()
            );
            assert!(verifies(key, &set, &rrsig), "{:?}", key.algorithm());
            let RData::DNSSEC(DNSSECRData::RRSIG(fields)) = &rrsig.data else {
                panic!("an RRSIG");
            };
            assert_eq!(u8::from(fields.input().algorithm), key.algorithm().number());
            assert_eq!(fields.input().signer_name.to_string(), "example.");
            assert_eq!(fields.input().num_labels, 2);
            assert_eq!(rrsig.ttl, 300);

            // Another record set does not verify under this signature.
            assert!(!verifies(key, &a_set("ftp.example."), &rrsig));
        }
    }

    #[test]
    fn wildcard_owners_leave_the_star_out_of_the_label_count() {
        let key = ZoneKey::generate(
            &SeededEntropy::new(Seed::from_u64(1)),
            Algorithm::Ed25519,
            KeyFlags::ZSK,
        );
        let set = a_set("*.example.");
        let rrsig = sign(&key, &set, &Name::from_ascii("example.").unwrap(), window()).unwrap();
        let RData::DNSSEC(DNSSECRData::RRSIG(fields)) = &rrsig.data else {
            panic!("an RRSIG");
        };
        assert_eq!(fields.input().num_labels, 1);
    }

    /// An RRset of two RP records (RFC 1183 §2.2), which hickory carries
    /// as unknown RDATA, whose mailbox names differ only in case.
    fn rp_set(mailboxes: &[&str]) -> RecordSet {
        let owner = Name::from_ascii("example.").unwrap();
        let rtype = RecordType::from(17);
        let mut set = RecordSet::with_ttl(owner.clone(), rtype, 300);
        for mailbox in mailboxes {
            let mut rdata = Vec::new();
            for label in [*mailbox, "example"] {
                rdata.push(label.len() as u8);
                rdata.extend_from_slice(label.as_bytes());
            }
            rdata.extend_from_slice(&[0, 0]);
            let rdata = RData::Unknown {
                code: rtype,
                rdata: hickory_proto::rr::rdata::NULL::with(rdata),
            };
            set.insert(Record::from_rdata(owner.clone(), 300, rdata), 0);
        }
        set
    }

    #[test]
    fn records_equal_in_canonical_form_are_signed_once() {
        let both = rp_set(&["Admin", "admin"]);
        assert_eq!(both.records_count(), 2);
        let one = rp_set(&["admin"]);
        let key = ZoneKey::generate(
            &SeededEntropy::new(Seed::from_u64(3)),
            Algorithm::Ed25519,
            KeyFlags::ZSK,
        );
        let signer = Name::from_ascii("example.").unwrap();
        // RFC 4034 §6.3: the duplicate goes before the canonical form is
        // taken, so a signer that holds one record and a validator that
        // was sent both agree on the signed bytes.
        let rrsig = sign(&key, &one, &signer, window()).unwrap();
        assert!(verifies(&key, &both, &rrsig));
    }

    #[test]
    fn window_times_are_seconds_modulo_two_to_the_32() {
        let past = UNIX_EPOCH + Duration::from_secs((1 << 32) + 5);
        assert_eq!(serial(past).get(), 5);
        assert_eq!(serial(UNIX_EPOCH - Duration::from_secs(1)).get(), 0);
    }
}
