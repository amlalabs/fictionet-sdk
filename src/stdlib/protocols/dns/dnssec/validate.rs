//! Deciding whether an answer is Secure, Insecure, Bogus, or
//! Indeterminate (RFC 4035 §4.3, §5).
//!
//! The validator is a function of records, trust anchors, an algorithm
//! policy, a time, and a [`Verify`]. It has no path to a signer or to
//! anything that serves records: whoever gathered the records hands them
//! over in a [`Chain`], so changing how zones are signed or served cannot
//! change what it accepts for the same records.
//!
//! A chain runs from a trust anchor down to the zone that holds the
//! answer. At each zone the DS records, from the anchor or proven by the
//! parent's keys, select the DNSKEYs that may sign the zone's DNSKEY
//! RRset; that RRset, once its signature verifies, holds the keys for the
//! zone's data and for the DS records of its children. Any one valid path
//! is enough: not every key or algorithm needs to verify (RFC 6840 §5.11).
//!
//! Missing records are never Insecure. A fetch that failed is
//! [`Validation::Indeterminate`]; records that arrived without the
//! signatures or proofs they need are [`Validation::Bogus`].

use std::time::SystemTime;

use super::keys::{KeyFlags, digest_of, key_tag};
use super::policy::{AlgorithmPolicy, Treatment};
use super::proof::{self, Proof};
use super::rdata::{DNSKEY, DNSSECRData, DS, SigInput};
use super::sign::{serial, signed_data};
use super::{Anchors, TrustAnchor, Verify};
use crate::stdlib::protocols::dns::op::{Query, ResponseCode};
use crate::stdlib::protocols::dns::rr::{Name, RData, RecordSet, RecordType, SerialNumber};
use crate::stdlib::protocols::dns::{EdeCode, label_count};
use hickory_proto::dnssec::PublicKey;

/// What a validator established for one answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Validation {
    /// The resolver did not validate: it has no trust anchors, or the
    /// client set CD and the resolver skipped validation. The validator
    /// functions never return it; a resolver uses it so that an answer it
    /// did not check is never mistaken for an Insecure one.
    NotPerformed,
    /// A chain of signatures from a trust anchor proves the answer.
    Secure,
    /// The answer is provably outside any secure chain.
    Insecure(Insecure),
    /// The answer should be secure but its signatures or proofs fail, for
    /// the reason the Extended DNS Error code gives (RFC 8914).
    Bogus(EdeCode),
    /// Records the validation needs could not be obtained (RFC 4035 §4.3).
    Indeterminate,
}

/// Why an answer is Insecure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Insecure {
    /// The parent's signed NSEC or NSEC3 record shows a delegation with no
    /// DS (RFC 4035 §5.2, RFC 5155 §8.9).
    ProvenNoDs,
    /// An NSEC3 opt-out span covers the name, so an unsigned delegation
    /// may sit there (RFC 5155 §6, §8.9).
    OptOutCovered,
    /// No trust anchor covers the name (RFC 4035 §4.3).
    NoAnchor,
    /// Every DS record at a delegation names an algorithm the policy does
    /// not validate (RFC 4035 §5.2, RFC 9905 §2).
    UnsupportedAlgorithm,
    /// Every DS record at a delegation with a validated algorithm uses a
    /// digest type the policy does not accept (RFC 4035 §5.2).
    UnsupportedDigest,
    /// An NSEC3 record has more iterations than the policy allows
    /// (RFC 9276 §3.2).
    Nsec3Iterations,
}

impl Validation {
    /// The Extended DNS Error a resolver reports with this result, if any
    /// (RFC 8914 §4, RFC 9276 §3.2).
    pub fn ede(&self) -> Option<EdeCode> {
        match self {
            Validation::NotPerformed | Validation::Secure => None,
            Validation::Insecure(Insecure::UnsupportedAlgorithm) => {
                Some(EdeCode::UNSUPPORTED_DNSKEY_ALGORITHM)
            }
            Validation::Insecure(Insecure::UnsupportedDigest) => {
                Some(EdeCode::UNSUPPORTED_DS_DIGEST_TYPE)
            }
            Validation::Insecure(Insecure::Nsec3Iterations) => {
                Some(EdeCode::UNSUPPORTED_NSEC3_ITERATIONS)
            }
            Validation::Insecure(_) => None,
            Validation::Bogus(code) => Some(*code),
            Validation::Indeterminate => Some(EdeCode::DNSSEC_INDETERMINATE),
        }
    }
}

/// How one RRset a validation needs was fetched.
#[derive(Clone, Debug, PartialEq)]
pub enum Fetched {
    /// The server answered with the RRset, its RRSIGs included.
    Answer(RecordSet),
    /// The server said the RRset does not exist, or referred onward
    /// without it, with these authority-section RRsets: SOA, NSEC, or
    /// NSEC3, each with its RRSIGs.
    Denied(Vec<RecordSet>),
    /// The RRset could not be obtained: every server failed or stayed
    /// silent.
    Failed,
}

/// What a resolver fetched for one zone on the path from a trust anchor
/// down to an answer.
#[derive(Clone, Debug, PartialEq)]
pub struct Link {
    /// The zone's apex.
    pub zone: Name,
    /// The zone's DS RRset, as the parent zone served it. Unused for the
    /// zone of the trust anchor, whose DS records are the anchor's.
    pub ds: Fetched,
    /// The zone's DNSKEY RRset, as the zone served it.
    pub dnskey: Fetched,
}

/// An RRset whose RRSIG verified, and how long that RRSIG lets the RRset
/// count as Secure: until the RRSIG's Signature Expiration, and no longer
/// than its Original TTL from when the RRset arrived (RFC 4035 §5.3.3).
/// Other RRSIGs of the RRset, which did not verify, bound nothing.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Verified {
    /// The RRset's owner.
    pub owner: Name,
    /// The RRset's type.
    pub rtype: RecordType,
    /// The RRSIG's Signature Expiration (RFC 4034 §3.1.5).
    pub expiration: SerialNumber,
    /// The RRSIG's Original TTL (RFC 4034 §3.1.4).
    pub original_ttl: u32,
}

impl Verified {
    fn of(set: &RecordSet, input: &SigInput) -> Verified {
        Verified {
            owner: set.name().clone(),
            rtype: set.record_type(),
            expiration: input.sig_expiration,
            original_ttl: input.original_ttl,
        }
    }

    /// Whether this is what verified `set`.
    pub fn signs(&self, set: &RecordSet) -> bool {
        self.rtype == set.record_type() && self.owner == *set.name()
    }
}

/// What [`validate_rrset`] established about an RRset.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedRrset {
    /// The result.
    pub validation: Validation,
    /// When the result is Secure, the RRSIG that verified each RRset it
    /// rests on: the RRset, and for a wildcard answer the NSEC or NSEC3
    /// records of its proof. Empty for any other result.
    pub verified: Vec<Verified>,
}

impl From<Validation> for ValidatedRrset {
    fn from(validation: Validation) -> ValidatedRrset {
        ValidatedRrset {
            validation,
            verified: Vec::new(),
        }
    }
}

/// The DS, DNSKEY, RRSIG, and denial records gathered from a trust anchor
/// down to an answer: one [`Link`] for each zone cut on the way, in any
/// order. Links for zones off the path are ignored.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Chain {
    /// The zones on the path.
    pub links: Vec<Link>,
}

/// Validates `set`, an RRset from an answer section, with its RRSIGs in
/// it. `authority` is the authority section of the same reply, which
/// holds the NSEC or NSEC3 records a wildcard answer needs to show that
/// no closer name matched (RFC 4035 §5.3.4). A wildcard answer is Bogus
/// when any NSEC or NSEC3 RRset there fails to verify, as Unbound fails
/// such a reply.
pub fn validate_rrset(
    set: &RecordSet,
    authority: &[RecordSet],
    chain: &Chain,
    anchors: &Anchors,
    policy: &AlgorithmPolicy,
    at: SystemTime,
    verify: &impl Verify,
) -> ValidatedRrset {
    let check = Check {
        policy,
        at: serial(at),
        verify,
    };
    let name = set.name();
    // A DS RRset is the parent's, except at the root, which has no parent.
    let ds = set.record_type() == RecordType::DS && !name.is_root();
    let (zone, keys) = match check.zone_keys(chain, anchors, name, ds) {
        Ok(found) => found,
        Err(result) => return result.into(),
    };
    if deeper_signer(std::slice::from_ref(set), &zone, name, ds) {
        return Validation::Indeterminate.into();
    }
    let input = match check.rrset(set, &zone, &keys) {
        Ok(input) => input,
        Err(code) => return Validation::Bogus(code).into(),
    };
    let answer = Verified::of(set, input);
    if input.num_labels >= name.num_labels() {
        return ValidatedRrset {
            validation: Validation::Secure,
            verified: vec![answer],
        };
    }
    let found = check.authenticate(authority, &zone, &keys);
    let proof = proof::wildcard_answer(
        name,
        input.num_labels,
        &zone,
        &found.proven,
        policy.max_nsec3_iterations,
    );
    match (from_proof(proof, found.failure), found.failure) {
        // The proof goes out beside the answer, so a record of it that did
        // not verify would reach a client under AD (RFC 4035 §3.2.3).
        (Validation::Secure, Some(code)) => Validation::Bogus(code).into(),
        (Validation::Secure, None) => ValidatedRrset {
            validation: Validation::Secure,
            verified: std::iter::once(answer).chain(found.verified).collect(),
        },
        (validation, _) => validation.into(),
    }
}

/// What [`validate_denial`] established about a negative answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedDenial {
    /// The result.
    pub validation: Validation,
    /// Why an NSEC or NSEC3 RRset of the authority section failed to
    /// verify, if one did. The proof may still stand on the others, but
    /// such a record is not authentic: a resolver may not use it to deny
    /// other names (RFC 8198 §5.1), nor send it on as authentic data
    /// (RFC 4035 §3.2.3).
    pub unverified: Option<EdeCode>,
    /// When the result is Secure, the RRSIG that verified the zone's SOA
    /// and each NSEC or NSEC3 RRset that did verify. Empty for any other
    /// result.
    pub verified: Vec<Verified>,
}

impl From<Validation> for ValidatedDenial {
    fn from(validation: Validation) -> ValidatedDenial {
        ValidatedDenial {
            validation,
            unverified: None,
            verified: Vec::new(),
        }
    }
}

/// Validates a negative answer to `query`: an NXDOMAIN, or a NOERROR with
/// no records of the type asked for. `authority` is the reply's authority
/// section. Other response codes deny nothing, and give
/// [`Validation::Indeterminate`].
#[allow(clippy::too_many_arguments)]
pub fn validate_denial(
    query: &Query,
    rcode: ResponseCode,
    authority: &[RecordSet],
    chain: &Chain,
    anchors: &Anchors,
    policy: &AlgorithmPolicy,
    at: SystemTime,
    verify: &impl Verify,
) -> ValidatedDenial {
    let check = Check {
        policy,
        at: serial(at),
        verify,
    };
    let name = query.name();
    let qtype = query.query_type();
    let ds = qtype == RecordType::DS && !name.is_root();
    let (zone, keys) = match check.zone_keys(chain, anchors, name, ds) {
        Ok(found) => found,
        Err(result) => return result.into(),
    };
    if deeper_signer(authority, &zone, name, ds) {
        return Validation::Indeterminate.into();
    }
    let mut verified = Vec::new();
    for soa in authority
        .iter()
        .filter(|set| set.record_type() == RecordType::SOA && *set.name() == zone)
    {
        match check.rrset(soa, &zone, &keys) {
            Ok(input) => verified.push(Verified::of(soa, input)),
            Err(code) => return Validation::Bogus(code).into(),
        }
    }
    let found = check.authenticate(authority, &zone, &keys);
    let max = policy.max_nsec3_iterations;
    let proof = match rcode {
        ResponseCode::NXDomain => proof::nxdomain(name, &zone, &found.proven, max),
        ResponseCode::NoError => proof::nodata(name, qtype, &zone, &found.proven, max),
        _ => return Validation::Indeterminate.into(),
    };
    let validation = from_proof(proof, found.failure);
    if validation == Validation::Secure {
        verified.extend(found.verified);
    } else {
        verified.clear();
    }
    ValidatedDenial {
        validation,
        unverified: found.failure,
        verified,
    }
}

/// The result a denial proof gives. `failure` is why some denial records
/// failed to verify, if any did.
fn from_proof(proof: Proof, failure: Option<EdeCode>) -> Validation {
    match proof {
        Proof::Proven => Validation::Secure,
        Proof::OptOut => Validation::Insecure(Insecure::OptOutCovered),
        Proof::Iterations => Validation::Insecure(Insecure::Nsec3Iterations),
        Proof::Unproven => Validation::Bogus(failure.unwrap_or(EdeCode::NSEC_MISSING)),
    }
}

/// Whether `sets` carry an RRSIG by a zone below `zone` that holds
/// `name`, strictly for a DS RRset: a zone the chain did not reach.
fn deeper_signer(sets: &[RecordSet], zone: &Name, name: &Name, ds: bool) -> bool {
    sets.iter()
        .flat_map(|set| set.rrsigs())
        .filter_map(|record| match &record.data {
            RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) => Some(&rrsig.input().signer_name),
            _ => None,
        })
        .any(|signer| {
            label_count(signer) > label_count(zone)
                && zone.zone_of(signer)
                && holds(signer, name, ds)
        })
}

/// Whether the zone at `apex` holds `name`, strictly below the apex when
/// `ds`, since a DS RRset belongs to the parent side of its cut.
fn holds(apex: &Name, name: &Name, ds: bool) -> bool {
    // A name's label count leaves out a leading `*`, so a wildcard owner
    // is told from its parent by the names, not by their counts.
    apex.zone_of(name) && (!ds || apex != name)
}

/// Why one RRSIG failed, from least to most telling, so the most telling
/// reason across all RRSIGs is the one reported.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Failure {
    NoKey,
    BadSignature,
    NotYetValid,
    Expired,
    ExpiredBeforeValid,
}

impl Failure {
    fn ede(self) -> EdeCode {
        match self {
            Failure::NoKey => EdeCode::DNSKEY_MISSING,
            Failure::BadSignature => EdeCode::DNSSEC_BOGUS,
            Failure::NotYetValid => EdeCode::SIGNATURE_NOT_YET_VALID,
            Failure::Expired => EdeCode::SIGNATURE_EXPIRED,
            Failure::ExpiredBeforeValid => EdeCode::SIGNATURE_EXPIRED_BEFORE_VALID,
        }
    }
}

/// The NSEC and NSEC3 RRsets of a section that verified, with the RRSIG
/// that verified each, and the most telling reason any others failed.
struct Authenticated {
    proven: Vec<RecordSet>,
    verified: Vec<Verified>,
    failure: Option<EdeCode>,
}

/// The inputs every check shares.
struct Check<'a, V: Verify> {
    policy: &'a AlgorithmPolicy,
    at: SerialNumber,
    verify: &'a V,
}

impl<V: Verify> Check<'_, V> {
    /// The zone that holds `name` and its proven keys, walking the chain
    /// down from the closest trust anchor.
    fn zone_keys(
        &self,
        chain: &Chain,
        anchors: &Anchors,
        name: &Name,
        ds: bool,
    ) -> Result<(Name, Vec<DNSKEY>), Validation> {
        let Some(anchor) = anchors.closest(name, ds) else {
            return Err(Validation::Insecure(Insecure::NoAnchor));
        };
        let mut links: Vec<&Link> = chain
            .links
            .iter()
            .filter(|link| anchor.owner.zone_of(&link.zone) && holds(&link.zone, name, ds))
            .collect();
        links.sort_by_key(|link| label_count(&link.zone));
        links.dedup_by(|a, b| a.zone == b.zone);
        match links.first() {
            Some(first) if first.zone == anchor.owner => {}
            _ => return Err(Validation::Indeterminate),
        }
        self.walk(&links, anchor)
    }

    fn walk(
        &self,
        links: &[&Link],
        anchor: &TrustAnchor,
    ) -> Result<(Name, Vec<DNSKEY>), Validation> {
        let mut parent: Option<(&Name, Vec<DNSKEY>)> = None;
        for link in links {
            let ds = match &parent {
                None => anchor.ds.clone(),
                Some((zone, keys)) => self.delegation(link, zone, keys)?,
            };
            parent = Some((&link.zone, self.dnskeys(link, &ds)?));
        }
        let (zone, keys) = parent.expect("the walk starts at the anchor's link");
        Ok((zone.clone(), keys))
    }

    /// The DS records for `link`'s zone, proven by its parent `zone`'s
    /// `keys`, or why there are none to trust.
    fn delegation(&self, link: &Link, zone: &Name, keys: &[DNSKEY]) -> Result<Vec<DS>, Validation> {
        // Records signed by a zone between the parent and this link mean
        // the chain skipped a cut.
        let skipped = |sets: &[RecordSet]| deeper_signer(sets, zone, &link.zone, true);
        let records = match &link.ds {
            Fetched::Failed => return Err(Validation::Indeterminate),
            Fetched::Denied(records) if skipped(records) => return Err(Validation::Indeterminate),
            Fetched::Denied(records) => records,
            Fetched::Answer(set) if skipped(std::slice::from_ref(set)) => {
                return Err(Validation::Indeterminate);
            }
            Fetched::Answer(set) => {
                if set.record_type() != RecordType::DS || *set.name() != link.zone {
                    return Err(Validation::Bogus(EdeCode::DNSSEC_BOGUS));
                }
                self.rrset(set, zone, keys).map_err(Validation::Bogus)?;
                let ds: Vec<DS> = set
                    .records_without_rrsigs()
                    .filter_map(|record| match &record.data {
                        RData::DNSSEC(DNSSECRData::DS(ds)) => Some(ds.clone()),
                        _ => None,
                    })
                    .collect();
                if ds.is_empty() {
                    return Err(Validation::Bogus(EdeCode::NSEC_MISSING));
                }
                return Ok(ds);
            }
        };
        let found = self.authenticate(records, zone, keys);
        let proof = proof::no_ds(
            &link.zone,
            zone,
            &found.proven,
            self.policy.max_nsec3_iterations,
        );
        Err(match proof {
            Proof::Proven => Validation::Insecure(Insecure::ProvenNoDs),
            other => from_proof(other, found.failure),
        })
    }

    /// The keys of `link`'s zone: its DNSKEY RRset, signed by a key one of
    /// the trusted `ds` records selects.
    fn dnskeys(&self, link: &Link, ds: &[DS]) -> Result<Vec<DNSKEY>, Validation> {
        let usable = self.policy.usable_ds(ds);
        if usable.is_empty() {
            // Every record is unsupported: for its digest when any has an
            // algorithm the policy validates, else for its algorithm.
            let digest = ds.iter().any(|ds| {
                self.policy
                    .treat(u8::from(ds.algorithm()), u8::from(ds.digest_type()))
                    == Treatment::UnsupportedDigest
            });
            return Err(Validation::Insecure(if digest {
                Insecure::UnsupportedDigest
            } else {
                Insecure::UnsupportedAlgorithm
            }));
        }

        let set = match &link.dnskey {
            Fetched::Failed => return Err(Validation::Indeterminate),
            Fetched::Denied(_) => return Err(Validation::Bogus(EdeCode::DNSKEY_MISSING)),
            Fetched::Answer(set) => set,
        };
        if set.record_type() != RecordType::DNSKEY || *set.name() != link.zone {
            return Err(Validation::Bogus(EdeCode::DNSKEY_MISSING));
        }
        let keys: Vec<&DNSKEY> = set
            .records_without_rrsigs()
            .filter_map(|record| match &record.data {
                RData::DNSSEC(DNSSECRData::DNSKEY(key)) => Some(key),
                _ => None,
            })
            .collect();
        let selected: Vec<&DNSKEY> = keys
            .iter()
            .copied()
            .filter(|key| {
                usable.iter().any(|(ds, digest)| {
                    ds.key_tag() == key_tag(key)
                        && ds.algorithm() == key.public_key().algorithm()
                        && ds.digest() == digest_of(&link.zone, key, *digest).as_slice()
                })
            })
            .collect();
        let entry: Vec<DNSKEY> = selected
            .iter()
            .filter(|key| usable_key(key))
            .map(|key| (*key).clone())
            .collect();
        if entry.is_empty() {
            let no_zone_bit = !selected.is_empty()
                && selected.iter().all(|key| !KeyFlags(key.flags()).zone_key());
            return Err(Validation::Bogus(if no_zone_bit {
                EdeCode::NO_ZONE_KEY_BIT_SET
            } else {
                EdeCode::DNSKEY_MISSING
            }));
        }
        self.rrset(set, &link.zone, &entry)
            .map_err(Validation::Bogus)?;
        Ok(keys
            .into_iter()
            .filter(|key| {
                usable_key(key)
                    && self
                        .policy
                        .validates(u8::from(key.public_key().algorithm()))
            })
            .cloned()
            .collect())
    }

    /// The NSEC and NSEC3 RRsets in `sets` whose signatures by `zone`'s
    /// `keys` verify for their own owner, and the most telling reason any
    /// others failed.
    fn authenticate(&self, sets: &[RecordSet], zone: &Name, keys: &[DNSKEY]) -> Authenticated {
        let mut found = Authenticated {
            proven: Vec::new(),
            verified: Vec::new(),
            failure: None,
        };
        for set in sets
            .iter()
            .filter(|set| matches!(set.record_type(), RecordType::NSEC | RecordType::NSEC3))
        {
            match self.rrset(set, zone, keys) {
                Ok(input) if input.num_labels == set.name().num_labels() => {
                    found.proven.push(set.clone());
                    found.verified.push(Verified::of(set, input));
                }
                // A record a wildcard expanded, signed for fewer labels
                // than its owner has, proves nothing about that owner
                // (RFC 4035 §5.4), and no server sends one as a denial.
                Ok(_) => found.failure = found.failure.or(Some(EdeCode::NSEC_MISSING)),
                Err(code) => found.failure = found.failure.or(Some(code)),
            }
        }
        found
    }

    /// Checks the RRSIGs of `set` by `zone`'s `keys` (RFC 4035 §5.3). On
    /// success, the RRSIG that verified, whose labels field is below the
    /// owner's label count for a wildcard answer.
    fn rrset<'s>(
        &self,
        set: &'s RecordSet,
        zone: &Name,
        keys: &[DNSKEY],
    ) -> Result<&'s SigInput, EdeCode> {
        let mut worst: Option<Failure> = None;
        for record in set.rrsigs() {
            let RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) = &record.data else {
                continue;
            };
            let input = rrsig.input();
            let algorithm = u8::from(input.algorithm);
            if input.type_covered != set.record_type()
                || record.name != *set.name()
                || input.signer_name != *zone
                || !self.policy.validates(algorithm)
            {
                continue;
            }
            let failure = match self.signature(set, input, rrsig.sig(), keys) {
                Ok(()) => return Ok(input),
                Err(failure) => failure,
            };
            worst = worst.max(Some(failure));
        }
        Err(worst.map_or(EdeCode::RRSIGS_MISSING, Failure::ede))
    }

    fn signature(
        &self,
        set: &RecordSet,
        input: &SigInput,
        signature: &[u8],
        keys: &[DNSKEY],
    ) -> Result<(), Failure> {
        // RFC 4035 §5.3.1: the labels field counts at most the owner's
        // labels.
        if input.num_labels > set.name().num_labels() {
            return Err(Failure::BadSignature);
        }
        // RFC 4034 §3.1.5: both ends are included, compared as serial
        // numbers, which have no order for values exactly 2^31 apart.
        use std::cmp::Ordering::{Equal, Greater, Less};
        if !matches!(
            input.sig_expiration.partial_cmp(&input.sig_inception),
            Some(Greater | Equal)
        ) {
            return Err(Failure::ExpiredBeforeValid);
        }
        if !matches!(
            self.at.partial_cmp(&input.sig_expiration),
            Some(Less | Equal)
        ) {
            return Err(Failure::Expired);
        }
        if !matches!(
            self.at.partial_cmp(&input.sig_inception),
            Some(Greater | Equal)
        ) {
            return Err(Failure::NotYetValid);
        }
        let candidates: Vec<&DNSKEY> = keys
            .iter()
            .filter(|key| key.public_key().algorithm() == input.algorithm)
            .filter(|key| key_tag(key) == input.key_tag)
            .collect();
        if candidates.is_empty() {
            return Err(Failure::NoKey);
        }
        let tbs = signed_data(set, input).map_err(|_| Failure::BadSignature)?;
        if candidates
            .iter()
            .any(|key| self.verify.verify(key, tbs.as_ref(), signature))
        {
            Ok(())
        } else {
            Err(Failure::BadSignature)
        }
    }
}

/// Whether a DNSKEY may verify zone data: the Zone Key bit set (RFC 4034
/// §2.1.1) and not revoked (RFC 5011 §3).
fn usable_key(key: &DNSKEY) -> bool {
    let flags = KeyFlags(key.flags());
    flags.zone_key() && !flags.revoked()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stdlib::protocols::dns::dnssec::proof::base32hex_encode;
    use crate::stdlib::protocols::dns::dnssec::rdata::{NSEC, NSEC3};
    use crate::stdlib::protocols::dns::dnssec::{
        Algorithm, DigestType, KeySet, Nsec3HashAlgorithm, Ring, Sign, Window, ZoneKey, ds, sign,
    };
    use crate::stdlib::protocols::dns::rr::Record;
    use crate::stdlib::protocols::dns::rr::rdata::{A, SOA};
    use fictionet::{Seed, SeededEntropy};
    use hickory_proto::dnssec::Algorithm as Number;
    use std::sync::Arc;
    use std::time::{Duration, UNIX_EPOCH};

    fn name(text: &str) -> Name {
        Name::from_ascii(text).unwrap()
    }

    fn time(seconds: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(seconds)
    }

    const NOW: u64 = 1_750_000_000;

    fn window() -> Window {
        Window {
            inception: time(1_700_000_000),
            expiration: time(1_800_000_000),
        }
    }

    fn key(seed: u64, algorithm: Algorithm, flags: KeyFlags) -> Arc<dyn Sign> {
        let entropy = SeededEntropy::new(Seed::from_u64(seed));
        Arc::new(ZoneKey::generate(&entropy, algorithm, flags))
    }

    fn rrset(owner: &Name, rdatas: Vec<RData>) -> RecordSet {
        let kind = rdatas[0].record_type();
        let mut set = RecordSet::with_ttl(owner.clone(), kind, 300);
        for rdata in rdatas {
            set.insert(Record::from_rdata(owner.clone(), 300, rdata), 0);
        }
        set
    }

    fn signed(
        mut set: RecordSet,
        keys: &[&Arc<dyn Sign>],
        signer: &Name,
        window: Window,
    ) -> RecordSet {
        for key in keys {
            let rrsig = sign(key.as_ref(), &set, signer, window).unwrap();
            set.insert_rrsig(rrsig);
        }
        set
    }

    fn a(last: u8) -> RData {
        RData::A(A::new(192, 0, 2, last))
    }

    fn nsec(owner: &str, next: &str, types: &[RecordType]) -> RecordSet {
        let rdata = NSEC::new_cover_self(name(next), types.iter().copied());
        rrset(&name(owner), vec![RData::DNSSEC(DNSSECRData::NSEC(rdata))])
    }

    fn ds_rdata(ds: DS) -> RData {
        RData::DNSSEC(DNSSECRData::DS(ds))
    }

    /// A signed root and a signed `example.` below it, with `www.example.`
    /// A records.
    struct Fixture {
        root_zsk: Arc<dyn Sign>,
        example_ksk: Arc<dyn Sign>,
        example_zsk: Arc<dyn Sign>,
        anchors: Anchors,
        chain: Chain,
        www: RecordSet,
    }

    impl Fixture {
        fn new() -> Fixture {
            let root_ksk = key(1, Algorithm::Ed25519, KeyFlags::KSK);
            let root_zsk = key(2, Algorithm::Ed25519, KeyFlags::ZSK);
            let example_ksk = key(3, Algorithm::EcdsaP256Sha256, KeyFlags::KSK);
            let example_zsk = key(4, Algorithm::EcdsaP256Sha256, KeyFlags::ZSK);
            let root_keys = KeySet {
                keys: vec![root_ksk.clone(), root_zsk.clone()],
            };
            let example_keys = KeySet {
                keys: vec![example_ksk.clone(), example_zsk.clone()],
            };
            let root = Name::root();
            let example = name("example.");
            let policy = AlgorithmPolicy::iana();

            let root_dnskey = signed(
                root_keys.dnskey_rrset(&root, 3600),
                &[&root_ksk],
                &root,
                window(),
            );
            let example_ds = example_keys
                .ds(&example, 3600, DigestType::Sha256, &policy)
                .unwrap();
            let example_ds = signed(example_ds, &[&root_zsk], &root, window());
            let example_dnskey = signed(
                example_keys.dnskey_rrset(&example, 3600),
                &[&example_ksk],
                &example,
                window(),
            );
            let www = signed(
                rrset(&name("www.example."), vec![a(1), a(2)]),
                &[&example_zsk],
                &example,
                window(),
            );
            Fixture {
                anchors: Anchors::of(vec![root_keys.anchor(&root)]),
                chain: Chain {
                    links: vec![
                        Link {
                            zone: root,
                            ds: Fetched::Failed,
                            dnskey: Fetched::Answer(root_dnskey),
                        },
                        Link {
                            zone: example,
                            ds: Fetched::Answer(example_ds),
                            dnskey: Fetched::Answer(example_dnskey),
                        },
                    ],
                },
                root_zsk,
                example_ksk,
                example_zsk,
                www,
            }
        }

        fn link(&mut self, zone: &str) -> &mut Link {
            let zone = name(zone);
            self.chain
                .links
                .iter_mut()
                .find(|link| link.zone == zone)
                .unwrap()
        }

        /// Replaces the DS records for `example.` with `rdatas`, signed by
        /// the root.
        fn example_ds(&mut self, rdatas: Vec<RData>) {
            let set = signed(
                rrset(&name("example."), rdatas),
                &[&self.root_zsk.clone()],
                &Name::root(),
                window(),
            );
            self.link("example.").ds = Fetched::Answer(set);
        }

        /// Replaces `example.`'s DS with a denial: `records`, signed by the
        /// root.
        fn example_denied(&mut self, records: Vec<RecordSet>) {
            let zsk = self.root_zsk.clone();
            let records = records
                .into_iter()
                .map(|set| signed(set, &[&zsk], &Name::root(), window()))
                .collect();
            self.link("example.").ds = Fetched::Denied(records);
        }

        fn validate(&self, set: &RecordSet) -> Validation {
            self.validate_with(set, &[])
        }

        fn validate_with(&self, set: &RecordSet, authority: &[RecordSet]) -> Validation {
            validate_rrset(
                set,
                authority,
                &self.chain,
                &self.anchors,
                &AlgorithmPolicy::iana(),
                time(NOW),
                &Ring,
            )
            .validation
        }

        fn deny(
            &self,
            qname: &str,
            qtype: RecordType,
            rcode: ResponseCode,
            authority: &[RecordSet],
        ) -> Validation {
            validate_denial(
                &Query::query(name(qname), qtype),
                rcode,
                authority,
                &self.chain,
                &self.anchors,
                &AlgorithmPolicy::iana(),
                time(NOW),
                &Ring,
            )
            .validation
        }

        /// `set` signed by `example.`'s zone-signing key.
        fn in_example(&self, set: RecordSet) -> RecordSet {
            signed(set, &[&self.example_zsk], &name("example."), window())
        }
    }

    /// An NSEC3 chain over `names` in `zone`, each name with its types.
    fn nsec3_chain(
        zone: &str,
        names: &[(&str, &[RecordType])],
        opt_out: bool,
        iterations: u16,
    ) -> Vec<RecordSet> {
        let mut hashed: Vec<(Vec<u8>, &[RecordType])> = names
            .iter()
            .map(|(owner, types)| {
                let hash = Nsec3HashAlgorithm::SHA1
                    .hash(&[], &name(owner), iterations)
                    .unwrap();
                (hash.as_ref().to_vec(), *types)
            })
            .collect();
        hashed.sort();
        (0..hashed.len())
            .map(|i| {
                let (hash, types) = &hashed[i];
                let next = hashed[(i + 1) % hashed.len()].0.clone();
                let rdata = NSEC3::new(
                    Nsec3HashAlgorithm::SHA1,
                    opt_out,
                    iterations,
                    Vec::new(),
                    next,
                    types.iter().copied().chain([RecordType::RRSIG]),
                );
                let owner = name(&base32hex_encode(hash))
                    .append_domain(&name(zone))
                    .unwrap();
                rrset(&owner, vec![RData::DNSSEC(DNSSECRData::NSEC3(rdata))])
            })
            .collect()
    }

    const ROOT_TYPES: &[RecordType] = &[RecordType::SOA, RecordType::NS, RecordType::DNSKEY];
    const DELEGATION: &[RecordType] = &[RecordType::NS, RecordType::DS];

    #[test]
    fn a_signed_chain_is_secure() {
        let fixture = Fixture::new();
        assert_eq!(fixture.validate(&fixture.www), Validation::Secure);
        // The DS RRset belongs to the root's side of the cut.
        let Fetched::Answer(ds) = &fixture.chain.links[1].ds else {
            unreachable!()
        };
        assert_eq!(fixture.validate(ds), Validation::Secure);
    }

    #[test]
    fn no_anchor_is_insecure() {
        let mut fixture = Fixture::new();
        fixture.anchors = Anchors::default();
        assert_eq!(
            fixture.validate(&fixture.www),
            Validation::Insecure(Insecure::NoAnchor)
        );
    }

    #[test]
    fn a_proven_absent_ds_is_insecure() {
        let mut fixture = Fixture::new();
        let unsigned = rrset(&name("www.example."), vec![a(1)]);
        fixture.example_denied(vec![nsec("example.", "net.", &[RecordType::NS])]);
        assert_eq!(
            fixture.validate(&unsigned),
            Validation::Insecure(Insecure::ProvenNoDs)
        );

        // The same proof through NSEC3: a matching record with NS and no DS.
        let chain = nsec3_chain(
            ".",
            &[(".", ROOT_TYPES), ("example.", &[RecordType::NS])],
            false,
            0,
        );
        fixture.example_denied(chain);
        assert_eq!(
            fixture.validate(&unsigned),
            Validation::Insecure(Insecure::ProvenNoDs)
        );
    }

    #[test]
    fn a_denial_that_shows_a_ds_proves_nothing() {
        let mut fixture = Fixture::new();
        fixture.example_denied(vec![nsec("example.", "net.", DELEGATION)]);
        let unsigned = rrset(&name("www.example."), vec![a(1)]);
        assert_eq!(
            fixture.validate(&unsigned),
            Validation::Bogus(EdeCode::NSEC_MISSING)
        );
        // An NSEC3 span without opt-out over the name proves no delegation.
        let chain = nsec3_chain(".", &[(".", ROOT_TYPES), ("com.", DELEGATION)], false, 0);
        fixture.example_denied(chain);
        assert_eq!(
            fixture.validate(&unsigned),
            Validation::Bogus(EdeCode::NSEC_MISSING)
        );
    }

    #[test]
    fn an_opt_out_span_is_insecure() {
        let mut fixture = Fixture::new();
        let chain = nsec3_chain(".", &[(".", ROOT_TYPES), ("com.", DELEGATION)], true, 0);
        fixture.example_denied(chain);
        let unsigned = rrset(&name("www.example."), vec![a(1)]);
        assert_eq!(
            fixture.validate(&unsigned),
            Validation::Insecure(Insecure::OptOutCovered)
        );
    }

    #[test]
    fn too_many_nsec3_iterations_is_insecure_with_ede_27() {
        let mut fixture = Fixture::new();
        let chain = nsec3_chain(
            ".",
            &[(".", ROOT_TYPES), ("example.", &[RecordType::NS])],
            false,
            150,
        );
        fixture.example_denied(chain);
        let result = fixture.validate(&rrset(&name("www.example."), vec![a(1)]));
        assert_eq!(result, Validation::Insecure(Insecure::Nsec3Iterations));
        assert_eq!(result.ede(), Some(EdeCode::UNSUPPORTED_NSEC3_ITERATIONS));

        // RFC 9276 §3.2: the NSEC3 records must still verify first.
        let unsigned = nsec3_chain(
            ".",
            &[(".", ROOT_TYPES), ("example.", &[RecordType::NS])],
            false,
            150,
        );
        fixture.link("example.").ds = Fetched::Denied(unsigned);
        assert_eq!(
            fixture.validate(&rrset(&name("www.example."), vec![a(1)])),
            Validation::Bogus(EdeCode::RRSIGS_MISSING)
        );
    }

    #[test]
    fn algorithms_5_and_7_are_insecure_under_the_iana_policy() {
        for algorithm in [5, 7] {
            let mut fixture = Fixture::new();
            let tag = key_tag(&fixture.example_ksk.dnskey());
            fixture.example_ds(vec![ds_rdata(DS::new(
                tag,
                Number::from_u8(algorithm),
                DigestType::Sha256.hickory(),
                vec![0; 32],
            ))]);
            let result = fixture.validate(&fixture.www);
            assert_eq!(
                result,
                Validation::Insecure(Insecure::UnsupportedAlgorithm),
                "{algorithm}"
            );
            assert_eq!(result.ede(), Some(EdeCode::UNSUPPORTED_DNSKEY_ALGORITHM));
        }
    }

    #[test]
    fn unsupported_digests_are_insecure_and_sha1_still_validates() {
        let mut fixture = Fixture::new();
        let ksk = fixture.example_ksk.dnskey();
        fixture.example_ds(vec![ds_rdata(DS::new(
            key_tag(&ksk),
            Number::ECDSAP256SHA256,
            hickory_proto::dnssec::DigestType::from(6),
            vec![0; 32],
        ))]);
        let result = fixture.validate(&fixture.www);
        assert_eq!(result, Validation::Insecure(Insecure::UnsupportedDigest));
        assert_eq!(result.ede(), Some(EdeCode::UNSUPPORTED_DS_DIGEST_TYPE));

        // RFC 9905 forbids creating SHA-1 DS records, not validating them.
        fixture.example_ds(vec![ds_rdata(ds(
            &name("example."),
            &ksk,
            DigestType::Sha1,
        ))]);
        assert_eq!(fixture.validate(&fixture.www), Validation::Secure);

        // Next to a SHA-256 DS, a wrong SHA-1 DS is ignored (RFC 4509 §3).
        let mut wrong = ds(&name("example."), &ksk, DigestType::Sha1);
        wrong = DS::new(
            wrong.key_tag(),
            wrong.algorithm(),
            wrong.digest_type(),
            vec![0; 20],
        );
        fixture.example_ds(vec![
            ds_rdata(wrong),
            ds_rdata(ds(&name("example."), &ksk, DigestType::Sha256)),
        ]);
        assert_eq!(fixture.validate(&fixture.www), Validation::Secure);
    }

    #[test]
    fn missing_records_are_bogus_or_indeterminate_never_insecure() {
        let check = |change: &dyn Fn(&mut Fixture), expected: Validation| {
            let mut fixture = Fixture::new();
            change(&mut fixture);
            let result = fixture.validate(&fixture.www.clone());
            assert_eq!(result, expected);
            assert!(!matches!(result, Validation::Insecure(_)));
        };
        check(
            &|f| f.link("example.").dnskey = Fetched::Failed,
            Validation::Indeterminate,
        );
        check(
            &|f| f.link("example.").ds = Fetched::Failed,
            Validation::Indeterminate,
        );
        check(
            &|f| f.link(".").dnskey = Fetched::Failed,
            Validation::Indeterminate,
        );
        check(
            &|f| f.link("example.").dnskey = Fetched::Denied(Vec::new()),
            Validation::Bogus(EdeCode::DNSKEY_MISSING),
        );
        check(
            &|f| f.link("example.").ds = Fetched::Denied(Vec::new()),
            Validation::Bogus(EdeCode::NSEC_MISSING),
        );
        check(
            &|f| f.www.clear_rrsigs(),
            Validation::Bogus(EdeCode::RRSIGS_MISSING),
        );
        check(
            &|f| {
                let Fetched::Answer(ds) = &mut f.link("example.").ds else {
                    unreachable!()
                };
                ds.clear_rrsigs();
            },
            Validation::Bogus(EdeCode::RRSIGS_MISSING),
        );
        // The chain stops above the zone that signed the answer.
        check(
            &|f| f.chain.links.retain(|link| link.zone.is_root()),
            Validation::Indeterminate,
        );
        // The chain skips the cut at example., whose keys sign the DS of a
        // zone below it.
        check(
            &|f| {
                let sub = name("sub.example.");
                let keys = KeySet {
                    keys: vec![f.example_ksk.clone()],
                };
                let ds = keys
                    .ds(&sub, 3600, DigestType::Sha256, &AlgorithmPolicy::iana())
                    .unwrap();
                let ds = signed(ds, &[&f.example_zsk], &name("example."), window());
                f.chain.links.retain(|link| link.zone.is_root());
                f.chain.links.push(Link {
                    zone: sub,
                    ds: Fetched::Answer(ds),
                    dnskey: Fetched::Failed,
                });
                f.www = rrset(&name("www.sub.example."), vec![a(1)]);
            },
            Validation::Indeterminate,
        );
        // The chain does not start at the anchor.
        check(
            &|f| f.chain.links.retain(|link| !link.zone.is_root()),
            Validation::Indeterminate,
        );
        assert_eq!(
            Validation::Indeterminate.ede(),
            Some(EdeCode::DNSSEC_INDETERMINATE)
        );
    }

    #[test]
    fn signature_problems_have_their_own_codes() {
        let fixture = Fixture::new();
        let example = name("example.");
        let www = |window: Window| {
            signed(
                rrset(&name("www.example."), vec![a(1)]),
                &[&fixture.example_zsk],
                &example,
                window,
            )
        };
        let expired = Window {
            inception: time(1_600_000_000),
            expiration: time(1_700_000_000),
        };
        let future = Window {
            inception: time(1_800_000_000),
            expiration: time(1_900_000_000),
        };
        let backwards = Window {
            inception: time(1_800_000_000),
            expiration: time(1_700_000_000),
        };
        assert_eq!(
            fixture.validate(&www(expired)),
            Validation::Bogus(EdeCode::SIGNATURE_EXPIRED)
        );
        assert_eq!(
            fixture.validate(&www(future)),
            Validation::Bogus(EdeCode::SIGNATURE_NOT_YET_VALID)
        );
        assert_eq!(
            fixture.validate(&www(backwards)),
            Validation::Bogus(EdeCode::SIGNATURE_EXPIRED_BEFORE_VALID)
        );

        // Records changed after signing.
        let mut forged = rrset(&name("www.example."), vec![a(66)]);
        for rrsig in fixture.www.rrsigs() {
            forged.insert_rrsig(rrsig.clone());
        }
        assert_eq!(
            fixture.validate(&forged),
            Validation::Bogus(EdeCode::DNSSEC_BOGUS)
        );

        // Signed by a key the zone does not publish.
        let stranger = key(9, Algorithm::EcdsaP256Sha256, KeyFlags::ZSK);
        let unknown = signed(
            rrset(&name("www.example."), vec![a(1)]),
            &[&stranger],
            &example,
            window(),
        );
        assert_eq!(
            fixture.validate(&unknown),
            Validation::Bogus(EdeCode::DNSKEY_MISSING)
        );

        // Signed by the root instead of the zone that holds the name.
        let root = signed(
            rrset(&name("www.example."), vec![a(1)]),
            &[&fixture.root_zsk],
            &Name::root(),
            window(),
        );
        assert_eq!(
            fixture.validate(&root),
            Validation::Bogus(EdeCode::RRSIGS_MISSING)
        );
    }

    #[test]
    fn a_ds_for_a_key_without_the_zone_bit_is_bogus() {
        let mut fixture = Fixture::new();
        let sep_only = key(5, Algorithm::EcdsaP256Sha256, KeyFlags(0x0001));
        let example = name("example.");
        let keys = KeySet {
            keys: vec![sep_only.clone(), fixture.example_zsk.clone()],
        };
        let dnskey = signed(
            keys.dnskey_rrset(&example, 3600),
            &[&sep_only],
            &example,
            window(),
        );
        fixture.link("example.").dnskey = Fetched::Answer(dnskey);
        fixture.example_ds(vec![ds_rdata(ds(
            &example,
            &sep_only.dnskey(),
            DigestType::Sha256,
        ))]);
        assert_eq!(
            fixture.validate(&fixture.www),
            Validation::Bogus(EdeCode::NO_ZONE_KEY_BIT_SET)
        );
    }

    #[test]
    fn a_rollover_set_validates_through_either_key() {
        let mut fixture = Fixture::new();
        let example = name("example.");
        let old = fixture.example_ksk.clone();
        let new = key(6, Algorithm::Ed25519, KeyFlags::KSK);
        let keys = KeySet {
            keys: vec![old.clone(), new.clone(), fixture.example_zsk.clone()],
        };
        let both = keys
            .ds(&example, 3600, DigestType::Sha256, &AlgorithmPolicy::iana())
            .unwrap();
        assert_eq!(both.records_count(), 2);
        let both: Vec<RData> = both
            .records_without_rrsigs()
            .map(|r| r.data.clone())
            .collect();
        fixture.example_ds(both.clone());
        for signer in [&old, &new] {
            let dnskey = signed(
                keys.dnskey_rrset(&example, 3600),
                &[signer],
                &example,
                window(),
            );
            fixture.link("example.").dnskey = Fetched::Answer(dnskey);
            assert_eq!(fixture.validate(&fixture.www), Validation::Secure);
        }

        // With only the new key's DS, a DNSKEY set only the old key signed
        // has no trusted path.
        let new_only = ds(&example, &new.dnskey(), DigestType::Sha256);
        fixture.example_ds(vec![ds_rdata(new_only)]);
        let dnskey = signed(
            keys.dnskey_rrset(&example, 3600),
            &[&old],
            &example,
            window(),
        );
        fixture.link("example.").dnskey = Fetched::Answer(dnskey);
        assert_eq!(
            fixture.validate(&fixture.www),
            Validation::Bogus(EdeCode::DNSKEY_MISSING)
        );
    }

    /// `example.`'s NSEC chain: the apex, `a.example.`, the empty
    /// non-terminal `b.example.` above `c.b.example.`, and `www.example.`.
    fn example_nsec(fixture: &Fixture) -> Vec<RecordSet> {
        [
            nsec(
                "example.",
                "a.example.",
                &[RecordType::SOA, RecordType::NS, RecordType::DNSKEY],
            ),
            nsec("a.example.", "c.b.example.", &[RecordType::A]),
            nsec("c.b.example.", "www.example.", &[RecordType::A]),
            nsec("www.example.", "example.", &[RecordType::A]),
        ]
        .into_iter()
        .map(|set| fixture.in_example(set))
        .collect()
    }

    #[test]
    fn nsec_denials() {
        let fixture = Fixture::new();
        let chain = example_nsec(&fixture);
        let soa = fixture.in_example(rrset(
            &name("example."),
            vec![RData::SOA(SOA::new(
                name("ns.example."),
                name("hostmaster.example."),
                1,
                7200,
                3600,
                1209600,
                300,
            ))],
        ));
        let with_soa = |sets: &[&RecordSet]| -> Vec<RecordSet> {
            let mut all: Vec<RecordSet> = sets.iter().map(|set| (*set).clone()).collect();
            all.push(soa.clone());
            all
        };

        // NXDOMAIN: the name and the wildcard at its closest encloser are
        // both covered.
        let nx = with_soa(&[&chain[2], &chain[0]]);
        assert_eq!(
            fixture.deny("m.example.", RecordType::A, ResponseCode::NXDomain, &nx),
            Validation::Secure
        );
        let half = with_soa(&[&chain[2]]);
        assert_eq!(
            fixture.deny("m.example.", RecordType::A, ResponseCode::NXDomain, &half),
            Validation::Bogus(EdeCode::NSEC_MISSING)
        );
        // An empty non-terminal exists, so it cannot be NXDOMAIN.
        let ent = with_soa(&[&chain[1], &chain[0]]);
        assert_eq!(
            fixture.deny("b.example.", RecordType::A, ResponseCode::NXDomain, &ent),
            Validation::Bogus(EdeCode::NSEC_MISSING)
        );
        assert_eq!(
            fixture.deny("b.example.", RecordType::A, ResponseCode::NoError, &ent),
            Validation::Secure
        );

        // NODATA at a name that exists without the type.
        let a = with_soa(&[&chain[1]]);
        assert_eq!(
            fixture.deny("a.example.", RecordType::TXT, ResponseCode::NoError, &a),
            Validation::Secure
        );
        assert_eq!(
            fixture.deny("a.example.", RecordType::A, ResponseCode::NoError, &a),
            Validation::Bogus(EdeCode::NSEC_MISSING)
        );

        // Unsigned denial records, and a tampered SOA.
        let mut bare = chain[1].clone();
        bare.clear_rrsigs();
        assert_eq!(
            fixture.deny(
                "a.example.",
                RecordType::TXT,
                ResponseCode::NoError,
                &[bare]
            ),
            Validation::Bogus(EdeCode::RRSIGS_MISSING)
        );
        let mut forged_soa = rrset(
            &name("example."),
            vec![RData::SOA(SOA::new(
                name("evil."),
                name("evil."),
                2,
                1,
                1,
                1,
                1,
            ))],
        );
        for rrsig in soa.rrsigs() {
            forged_soa.insert_rrsig(rrsig.clone());
        }
        assert_eq!(
            fixture.deny(
                "a.example.",
                RecordType::TXT,
                ResponseCode::NoError,
                &[chain[1].clone(), forged_soa]
            ),
            Validation::Bogus(EdeCode::DNSSEC_BOGUS)
        );

        // A response code that denies nothing.
        assert_eq!(
            fixture.deny("a.example.", RecordType::TXT, ResponseCode::ServFail, &a),
            Validation::Indeterminate
        );

        // A DS query at the cut, answered by the root.
        let mut fixture = fixture;
        let cut = signed(
            nsec("example.", "net.", &[RecordType::NS]),
            &[&fixture.root_zsk],
            &Name::root(),
            window(),
        );
        fixture.link("example.").ds = Fetched::Failed;
        assert_eq!(
            fixture.deny("example.", RecordType::DS, ResponseCode::NoError, &[cut]),
            Validation::Secure
        );
    }

    #[test]
    fn a_wildcard_answer_needs_proof_of_no_closer_match() {
        let fixture = Fixture::new();
        let example = name("example.");
        let wildcard = signed(
            rrset(&name("*.example."), vec![a(9)]),
            &[&fixture.example_zsk],
            &example,
            window(),
        );
        // The answer to x.example., expanded from the wildcard.
        let x = name("x.example.");
        let mut answer = rrset(&x, vec![a(9)]);
        for rrsig in wildcard.rrsigs() {
            let mut rrsig = rrsig.clone();
            rrsig.name = x.clone();
            answer.insert_rrsig(rrsig);
        }
        let chain = example_nsec(&fixture);
        assert_eq!(
            fixture.validate_with(&answer, &[chain[3].clone()]),
            Validation::Secure
        );
        assert_eq!(
            fixture.validate_with(&answer, &[]),
            Validation::Bogus(EdeCode::NSEC_MISSING)
        );
        // A covering NSEC whose closest encloser is deeper than the
        // wildcard's parent shows a closer name exists.
        let deeper = name("d.c.b.example.");
        let mut answer = rrset(&deeper, vec![a(9)]);
        for rrsig in wildcard.rrsigs() {
            let mut rrsig = rrsig.clone();
            rrsig.name = deeper.clone();
            answer.insert_rrsig(rrsig);
        }
        assert_eq!(
            fixture.validate_with(&answer, &[chain[2].clone()]),
            Validation::Bogus(EdeCode::NSEC_MISSING)
        );
    }

    #[test]
    fn a_policy_without_the_algorithm_makes_the_zone_insecure() {
        let fixture = Fixture::new();
        let mut policy = AlgorithmPolicy::iana();
        policy.validate.remove(&13);
        let result = validate_rrset(
            &fixture.www,
            &[],
            &fixture.chain,
            &fixture.anchors,
            &policy,
            time(NOW),
            &Ring,
        );
        assert_eq!(
            result.validation,
            Validation::Insecure(Insecure::UnsupportedAlgorithm)
        );
    }
}
