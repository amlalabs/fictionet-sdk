//! What NSEC and NSEC3 records prove about names that are not there.
//!
//! Each check takes the denial records of one zone, whose signatures the
//! caller has already verified, and says whether they prove a claim: that
//! a name does not exist (RFC 4035 §5.4, RFC 5155 §8.4), that it has no
//! records of a type (RFC 4035 §5.4, RFC 5155 §8.5 to §8.7), that a
//! delegation has no DS (RFC 4035 §5.2, RFC 5155 §8.9), or that a
//! wildcard answer had no closer match (RFC 4035 §5.3.4, RFC 5155 §8.8).
//!
//! Records from the parent side of a zone cut prove nothing about the
//! names below it or about other types at the cut (RFC 6840 §4.1). An
//! NSEC3 opt-out span that covers the next closer name proves only that
//! any delegation there is unsigned, so a claim that rests on it is never
//! [`Proof::Proven`] (RFC 5155 §6, §8.9). NSEC3 hashes use SHA-1 with each
//! record's own salt and iterations, as RFC 5155 §5 requires.

use std::cmp::Ordering;

use super::rdata::{DNSSECRData, NSEC, NSEC3};
use crate::stdlib::protocols::dns::label_count;
use crate::stdlib::protocols::dns::rr::{Name, RData, RecordSet, RecordType};
use hickory_proto::dnssec::Nsec3HashAlgorithm;

/// What a set of denial records establishes about a claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Proof {
    /// The records prove the claim.
    Proven,
    /// An NSEC3 opt-out span covers the next closer name. The claim holds
    /// unless an unsigned delegation sits there, so it is Insecure, never
    /// Secure (RFC 5155 §6, §8.9).
    OptOut,
    /// An NSEC3 record the proof needs has more iterations than the
    /// policy allows (RFC 9276 §3.2).
    Iterations,
    /// The records do not prove the claim.
    Unproven,
}

/// Whether `records` prove that `name` does not exist in `zone`.
pub fn nxdomain(name: &Name, zone: &Name, records: &[RecordSet], max_iterations: u16) -> Proof {
    let name = fqdn(name);
    Denial::new(zone, records).decide(
        max_iterations,
        |nsec| nsec.nxdomain(&name),
        |nsec3| nsec3.nxdomain(&name),
    )
}

/// Whether `records` prove that `name` in `zone` has no records of type
/// `qtype`, at the name itself, as an empty non-terminal, or through a
/// wildcard that has none.
pub fn nodata(
    name: &Name,
    qtype: RecordType,
    zone: &Name,
    records: &[RecordSet],
    max_iterations: u16,
) -> Proof {
    let name = fqdn(name);
    Denial::new(zone, records).decide(
        max_iterations,
        |nsec| nsec.nodata(&name, qtype),
        |nsec3| nsec3.nodata(&name, qtype),
    )
}

/// The NSEC RRsets among `records` that prove `name` does not exist in
/// `zone`, the ones a reply carries for the claim (RFC 4035 §3.1.3.2), or
/// `None` when NSEC records do not prove it.
pub fn nxdomain_nsecs(name: &Name, zone: &Name, records: &[RecordSet]) -> Option<Vec<RecordSet>> {
    let name = fqdn(name);
    let owners = Denial::new(zone, records).nsec.nxdomain_owners(&name)?;
    Some(nsecs_of(records, &owners))
}

/// The NSEC RRsets among `records` that prove `name` in `zone` has no
/// records of type `qtype`, the ones a reply carries for the claim
/// (RFC 4035 §3.1.3.1 and §3.1.3.4), or `None` when NSEC records do not
/// prove it.
pub fn nodata_nsecs(
    name: &Name,
    qtype: RecordType,
    zone: &Name,
    records: &[RecordSet],
) -> Option<Vec<RecordSet>> {
    let name = fqdn(name);
    let owners = Denial::new(zone, records)
        .nsec
        .nodata_owners(&name, qtype)?;
    Some(nsecs_of(records, &owners))
}

/// The NSEC RRsets among `records` owned by one of `owners`.
fn nsecs_of(records: &[RecordSet], owners: &[&Name]) -> Vec<RecordSet> {
    records
        .iter()
        .filter(|set| set.record_type() == RecordType::NSEC && owners.contains(&set.name()))
        .cloned()
        .collect()
}

/// Whether `records` from the parent `zone` prove that `name` is a
/// delegation without DS records: an insecure delegation (RFC 4035 §5.2,
/// RFC 5155 §8.9).
pub fn no_ds(name: &Name, zone: &Name, records: &[RecordSet], max_iterations: u16) -> Proof {
    let name = fqdn(name);
    Denial::new(zone, records).decide(
        max_iterations,
        |nsec| nsec.no_ds(&name),
        |nsec3| nsec3.no_ds(&name),
    )
}

/// Whether `records` prove that a wildcard in `zone` was the closest
/// match for `name`, where `labels` is the label count of the RRSIG over
/// the expanded answer, which names the wildcard `*.` followed by the
/// last `labels` labels of `name` (RFC 4035 §5.3.4, RFC 5155 §8.8).
pub fn wildcard_answer(
    name: &Name,
    labels: u8,
    zone: &Name,
    records: &[RecordSet],
    max_iterations: u16,
) -> Proof {
    let name = fqdn(name);
    Denial::new(zone, records).decide(
        max_iterations,
        |nsec| nsec.wildcard_answer(&name, labels),
        |nsec3| nsec3.wildcard_answer(&name, labels),
    )
}

/// The RRsets among `records`, the NSEC or NSEC3 RRsets `zone` sent to
/// deny `name`, that the parent of a delegation at `name` without DS
/// sends with it (RFC 4035 §3.1.4.1, RFC 5155 §7.2.4 and §7.2.7): the
/// record matching `name`, or else, with NSEC3, the closest encloser's
/// record and the one covering the next closer name, or with NSEC the
/// record covering `name`. A record that proves only that no wildcard
/// matched says nothing of a delegation, and is left out.
pub fn delegation_proof(name: &Name, zone: &Name, records: &[RecordSet]) -> Vec<RecordSet> {
    let name = fqdn(name);
    let denial = Denial::new(zone, records);
    let nsec = denial
        .nsec
        .matching(&name)
        .map(|_| &name)
        .or_else(|| denial.nsec.covering(&name).map(|(owner, _)| owner));
    let hashes = denial.nsec3.delegation_proof(&name);
    records
        .iter()
        .filter(|set| match set.record_type() {
            RecordType::NSEC => nsec.is_some_and(|owner| set.name() == owner),
            RecordType::NSEC3 => set
                .name()
                .iter()
                .next()
                .and_then(base32hex)
                .is_some_and(|hash| set.name().base_name() == *zone && hashes.contains(&hash)),
            _ => false,
        })
        .cloned()
        .collect()
}

fn fqdn(name: &Name) -> Name {
    let mut name = name.clone();
    name.set_fqdn(true);
    name
}

/// A zone's denial records, NSEC and NSEC3 apart.
struct Denial<'a> {
    nsec: Nsecs<'a>,
    nsec3: Nsec3s<'a>,
}

impl<'a> Denial<'a> {
    fn new(zone: &'a Name, records: &'a [RecordSet]) -> Denial<'a> {
        let mut nsec = Vec::new();
        let mut nsec3 = Vec::new();
        for record in records.iter().flat_map(|set| set.records_without_rrsigs()) {
            match &record.data {
                RData::DNSSEC(DNSSECRData::NSEC(rdata)) if zone.zone_of(&record.name) => {
                    nsec.push((&record.name, rdata));
                }
                RData::DNSSEC(DNSSECRData::NSEC3(rdata)) => {
                    // RFC 5155 §3: the owner is the hash in base32hex,
                    // one label directly under the zone's apex.
                    let mut labels = record.name.iter();
                    let hash = labels.next().and_then(base32hex);
                    if let Some(hash) = hash
                        && record.name.base_name() == *zone
                    {
                        nsec3.push((hash, rdata));
                    }
                }
                _ => {}
            }
        }
        Denial {
            nsec: Nsecs(nsec),
            nsec3: Nsec3s {
                zone,
                records: nsec3,
            },
        }
    }

    /// The NSEC answer when NSEC records prove the claim, else the NSEC3
    /// answer.
    fn decide(
        &self,
        max_iterations: u16,
        nsec: impl Fn(&Nsecs<'a>) -> bool,
        nsec3: impl Fn(&Nsec3s<'a>) -> Proof,
    ) -> Proof {
        if nsec(&self.nsec) {
            return Proof::Proven;
        }
        if self.nsec3.records.is_empty() {
            return Proof::Unproven;
        }
        // RFC 9276 §3.2: past the limit, no hash is computed at all.
        if self
            .nsec3
            .records
            .iter()
            .any(|(_, rdata)| rdata.iterations() > max_iterations)
        {
            return Proof::Iterations;
        }
        nsec3(&self.nsec3)
    }
}

/// The NSEC records of one zone, each with its owner.
struct Nsecs<'a>(Vec<(&'a Name, &'a NSEC)>);

impl<'a> Nsecs<'a> {
    fn matching(&self, name: &Name) -> Option<&'a NSEC> {
        self.0
            .iter()
            .find(|(owner, _)| *owner == name)
            .map(|(_, rdata)| *rdata)
    }

    /// The NSEC whose span holds `name` strictly between its owner and its
    /// next name, wrapping past the last name back to the apex. An NSEC at
    /// a cut above `name` does not count (RFC 6840 §4.1).
    fn covering(&self, name: &Name) -> Option<(&'a Name, &'a NSEC)> {
        self.0.iter().copied().find(|(owner, rdata)| {
            let next = rdata.next_domain_name();
            let between = match owner.cmp(&next) {
                Ordering::Less => *owner < name && name < next,
                _ => *owner < name || name < next,
            };
            let above_cut = rdata.is_ancestor_delegation() && owner.zone_of(name);
            between && !above_cut
        })
    }

    /// The closest encloser of `name` given the NSEC that covers it: the
    /// deepest ancestor `name` shares with the NSEC's owner or next name,
    /// both of which exist.
    fn closest_encloser(name: &Name, owner: &Name, rdata: &NSEC) -> Name {
        let a = common_ancestor(name, owner);
        let b = common_ancestor(name, rdata.next_domain_name());
        if label_count(&a) >= label_count(&b) {
            a
        } else {
            b
        }
    }

    fn nxdomain(&self, name: &Name) -> bool {
        self.nxdomain_owners(name).is_some()
    }

    /// The owners of the records that prove `name` does not exist: the one
    /// covering it and the one covering the wildcard at its closest
    /// encloser.
    fn nxdomain_owners(&self, name: &Name) -> Option<Vec<&'a Name>> {
        if self.matching(name).is_some() {
            return None;
        }
        let (owner, rdata) = self.covering(name)?;
        // A next name below `name` makes `name` an empty non-terminal,
        // which exists.
        if is_below(rdata.next_domain_name(), name) {
            return None;
        }
        let encloser = Nsecs::closest_encloser(name, owner, rdata);
        let wildcard = encloser.prepend_label("*").ok()?;
        if self.matching(&wildcard).is_some() {
            return None;
        }
        let (wildcard_owner, _) = self.covering(&wildcard)?;
        Some(vec![owner, wildcard_owner])
    }

    fn nodata(&self, name: &Name, qtype: RecordType) -> bool {
        self.nodata_owners(name, qtype).is_some()
    }

    /// The owners of the records that prove `name` has no `qtype`: the one
    /// matching it, the one covering it as an empty non-terminal, or the
    /// one covering it and the one matching the wildcard that has no
    /// `qtype`.
    fn nodata_owners(&self, name: &Name, qtype: RecordType) -> Option<Vec<&'a Name>> {
        if let Some((owner, rdata)) = self.0.iter().find(|(owner, _)| *owner == name) {
            let types = rdata.type_set();
            let usable = if qtype == RecordType::DS && !name.is_root() {
                // A child apex's NSEC cannot deny the DS its parent holds.
                // The root has no parent, so its own apex NSEC denies it.
                !types.contains(RecordType::SOA)
            } else {
                // A parent's NSEC at a cut cannot deny the child's types. A
                // DNAME bit stops proofs for names below the owner only,
                // not for types at it (RFC 6840 §4.1).
                !(types.contains(RecordType::NS) && !types.contains(RecordType::SOA))
            };
            let denied = usable && !types.contains(qtype) && !types.contains(RecordType::CNAME);
            return denied.then(|| vec![*owner]);
        }
        let (owner, rdata) = self.covering(name)?;
        // An empty non-terminal: a name below it exists, it has no records.
        if is_below(rdata.next_domain_name(), name) {
            return Some(vec![owner]);
        }
        let encloser = Nsecs::closest_encloser(name, owner, rdata);
        let wildcard = encloser.prepend_label("*").ok()?;
        let (wildcard_owner, rdata) = self.0.iter().find(|(owner, _)| **owner == wildcard)?;
        let types = rdata.type_set();
        (!types.contains(qtype) && !types.contains(RecordType::CNAME))
            .then(|| vec![owner, *wildcard_owner])
    }

    fn no_ds(&self, name: &Name) -> bool {
        self.matching(name).is_some_and(|rdata| {
            let types = rdata.type_set();
            types.contains(RecordType::NS)
                && !types.contains(RecordType::DS)
                && !types.contains(RecordType::SOA)
        })
    }

    fn wildcard_answer(&self, name: &Name, labels: u8) -> bool {
        let encloser = name.trim_to(usize::from(labels));
        if self.matching(name).is_some() {
            return false;
        }
        self.covering(name)
            .is_some_and(|(owner, rdata)| Nsecs::closest_encloser(name, owner, rdata) == encloser)
    }
}

/// The NSEC3 records of one zone, each with its owner's hash.
struct Nsec3s<'a> {
    zone: &'a Name,
    records: Vec<(Vec<u8>, &'a NSEC3)>,
}

impl<'a> Nsec3s<'a> {
    fn hash(name: &Name, rdata: &NSEC3) -> Option<Vec<u8>> {
        Nsec3HashAlgorithm::SHA1
            .hash(rdata.salt(), name, rdata.iterations())
            .ok()
            .map(|digest| digest.as_ref().to_vec())
    }

    fn matching(&self, name: &Name) -> Option<&'a NSEC3> {
        self.matching_entry(name).map(|(_, rdata)| *rdata)
    }

    /// The NSEC3 matching `name`, with its owner's hash.
    fn matching_entry(&self, name: &Name) -> Option<&(Vec<u8>, &'a NSEC3)> {
        self.records
            .iter()
            .find(|(owner, rdata)| Nsec3s::hash(name, rdata).as_ref() == Some(owner))
    }

    /// The NSEC3 whose span holds the hash of `name` strictly between its
    /// owner's hash and the next hash, wrapping at the end of the chain.
    fn covering(&self, name: &Name) -> Option<&'a NSEC3> {
        self.covering_entry(name).map(|(_, rdata)| *rdata)
    }

    /// [`covering`](Nsec3s::covering), with the owner's hash.
    fn covering_entry(&self, name: &Name) -> Option<&(Vec<u8>, &'a NSEC3)> {
        self.records.iter().find(|(owner, rdata)| {
            let Some(hash) = Nsec3s::hash(name, rdata) else {
                return false;
            };
            let next = rdata.next_hashed_owner_name();
            match owner.as_slice().cmp(next) {
                Ordering::Less => *owner < hash && hash.as_slice() < next,
                _ => *owner < hash || hash.as_slice() < next,
            }
        })
    }

    /// The owner hashes of the NSEC3 records that show `name` is no
    /// signed delegation: the record matching it, or else the closest
    /// encloser's record and the one covering the next closer name.
    fn delegation_proof(&self, name: &Name) -> Vec<Vec<u8>> {
        if let Some((hash, _)) = self.matching_entry(name) {
            return vec![hash.clone()];
        }
        let labels = label_count(name);
        let apex = label_count(self.zone);
        for count in (apex..labels).rev() {
            let encloser = name.trim_to(count);
            if let Some((hash, _)) = self.matching_entry(&encloser) {
                let mut kept = vec![hash.clone()];
                let next_closer = name.trim_to(count + 1);
                kept.extend(
                    self.covering_entry(&next_closer)
                        .map(|(hash, _)| hash.clone()),
                );
                return kept;
            }
        }
        Vec::new()
    }

    /// The closest encloser proof of RFC 5155 §8.3: the deepest ancestor
    /// of `name` with a matching NSEC3, and whether the NSEC3 covering the
    /// next closer name has opt-out set. A matching NSEC3 at a cut means
    /// `name` lies in another zone, and proves nothing.
    fn closest_encloser(&self, name: &Name) -> Option<(Name, bool)> {
        let labels = label_count(name);
        let apex = label_count(self.zone);
        for count in (apex..labels).rev() {
            let encloser = name.trim_to(count);
            if let Some(rdata) = self.matching(&encloser) {
                if rdata.is_ancestor_delegation() {
                    return None;
                }
                let next_closer = name.trim_to(count + 1);
                return self
                    .covering(&next_closer)
                    .map(|cover| (encloser, cover.opt_out()));
            }
        }
        None
    }

    fn nxdomain(&self, name: &Name) -> Proof {
        if self.matching(name).is_some() {
            return Proof::Unproven;
        }
        let Some((encloser, opt_out)) = self.closest_encloser(name) else {
            return Proof::Unproven;
        };
        let Ok(wildcard) = encloser.prepend_label("*") else {
            return Proof::Unproven;
        };
        if self.matching(&wildcard).is_some() || self.covering(&wildcard).is_none() {
            return Proof::Unproven;
        }
        if opt_out {
            Proof::OptOut
        } else {
            Proof::Proven
        }
    }

    fn nodata(&self, name: &Name, qtype: RecordType) -> Proof {
        if let Some(rdata) = self.matching(name) {
            let types = rdata.type_set();
            let usable = if qtype == RecordType::DS && !name.is_root() {
                !types.contains(RecordType::SOA)
            } else {
                // As for NSEC: a cut stops the proof, a DNAME does not.
                !(types.contains(RecordType::NS) && !types.contains(RecordType::SOA))
            };
            let denied = usable && !types.contains(qtype) && !types.contains(RecordType::CNAME);
            return if denied {
                Proof::Proven
            } else {
                Proof::Unproven
            };
        }
        let Some((encloser, opt_out)) = self.closest_encloser(name) else {
            return Proof::Unproven;
        };
        // RFC 5155 §8.6 for DS, and its erratum 3441 for other types: with
        // no matching NSEC3, an opt-out span over the next closer name
        // means an unsigned delegation may be there.
        if opt_out {
            return Proof::OptOut;
        }
        // RFC 5155 §8.7: a wildcard at the closest encloser without the
        // type.
        let Ok(wildcard) = encloser.prepend_label("*") else {
            return Proof::Unproven;
        };
        match self.matching(&wildcard) {
            Some(rdata)
                if !rdata.type_set().contains(qtype)
                    && !rdata.type_set().contains(RecordType::CNAME) =>
            {
                Proof::Proven
            }
            _ => Proof::Unproven,
        }
    }

    fn no_ds(&self, name: &Name) -> Proof {
        if let Some(rdata) = self.matching(name) {
            let types = rdata.type_set();
            let unsigned = types.contains(RecordType::NS)
                && !types.contains(RecordType::DS)
                && !types.contains(RecordType::SOA);
            return if unsigned {
                Proof::Proven
            } else {
                Proof::Unproven
            };
        }
        match self.closest_encloser(name) {
            Some((_, true)) => Proof::OptOut,
            _ => Proof::Unproven,
        }
    }

    fn wildcard_answer(&self, name: &Name, labels: u8) -> Proof {
        let next_closer = name.trim_to(usize::from(labels) + 1);
        match self.covering(&next_closer) {
            Some(cover) if cover.opt_out() => Proof::OptOut,
            Some(_) => Proof::Proven,
            None => Proof::Unproven,
        }
    }
}

/// The deepest name that is an ancestor of, or equal to, both `a` and `b`.
fn common_ancestor(a: &Name, b: &Name) -> Name {
    let shared = a
        .iter()
        .rev()
        .zip(b.iter().rev())
        .take_while(|(x, y)| x.eq_ignore_ascii_case(y))
        .count();
    a.trim_to(shared)
}

/// Whether `name` is strictly below `ancestor`, `*.<ancestor>` included.
fn is_below(name: &Name, ancestor: &Name) -> bool {
    ancestor.zone_of(name) && label_count(name) > label_count(ancestor)
}

/// A base32hex label (RFC 4648 §7) decoded, ignoring case, as NSEC3
/// owners and next hashed owners are written (RFC 5155 §3.3). Bits past
/// the last whole octet are dropped.
pub(crate) fn base32hex(label: &[u8]) -> Option<Vec<u8>> {
    let mut bits = 0u64;
    let mut count = 0;
    let mut out = Vec::with_capacity(label.len() * 5 / 8);
    for c in label {
        let value = match c.to_ascii_lowercase() {
            c @ b'0'..=b'9' => c - b'0',
            c @ b'a'..=b'v' => c - b'a' + 10,
            _ => return None,
        };
        bits = (bits << 5) | u64::from(value);
        count += 5;
        if count >= 8 {
            count -= 8;
            out.push((bits >> count) as u8);
        }
    }
    Some(out)
}

/// `bytes` in base32 with the extended hex alphabet, in lowercase and
/// unpadded, as NSEC3 owner labels are written (RFC 4648 §7, RFC 5155
/// §3.3).
pub(crate) fn base32hex_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"0123456789abcdefghijklmnopqrstuv";
    let mut bits = 0u64;
    let mut count = 0;
    let mut out = String::new();
    for byte in bytes {
        bits = (bits << 8) | u64::from(*byte);
        count += 8;
        while count >= 5 {
            count -= 5;
            out.push(ALPHABET[((bits >> count) & 31) as usize] as char);
        }
    }
    if count > 0 {
        out.push(ALPHABET[((bits << (5 - count)) & 31) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stdlib::protocols::dns::rr::Record;

    fn name(text: &str) -> Name {
        Name::from_ascii(text).unwrap()
    }

    fn set(owner: &Name, rdata: DNSSECRData) -> RecordSet {
        RecordSet::from(Record::from_rdata(owner.clone(), 300, RData::DNSSEC(rdata)))
    }

    fn nsec(owner: &str, next: &str, types: &[RecordType]) -> RecordSet {
        set(
            &name(owner),
            DNSSECRData::NSEC(NSEC::new(name(next), types.iter().copied())),
        )
    }

    /// An NSEC3 chain for `zone` over `names`, with no salt.
    fn nsec3(zone: &str, names: &[(&str, &[RecordType])], opt_out: bool) -> Vec<RecordSet> {
        let mut hashed: Vec<(Vec<u8>, &[RecordType])> = names
            .iter()
            .map(|(owner, types)| {
                let hash = Nsec3HashAlgorithm::SHA1.hash(&[], &name(owner), 0).unwrap();
                (hash.as_ref().to_vec(), *types)
            })
            .collect();
        hashed.sort();
        (0..hashed.len())
            .map(|i| {
                let next = hashed[(i + 1) % hashed.len()].0.clone();
                let rdata = NSEC3::new(
                    Nsec3HashAlgorithm::SHA1,
                    opt_out,
                    0,
                    Vec::new(),
                    next,
                    hashed[i].1.iter().copied(),
                );
                let owner = name(&format!("{}.{zone}", base32hex_encode(&hashed[i].0)));
                set(&owner, DNSSECRData::NSEC3(rdata))
            })
            .collect()
    }

    const APEX: &[RecordType] = &[RecordType::SOA, RecordType::NS];

    #[test]
    fn base32hex_round_trips() {
        let hash = [
            0xffu8, 0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
            10,
        ];
        let text = base32hex_encode(&hash);
        assert_eq!(text.len(), 32);
        assert_eq!(base32hex(text.to_uppercase().as_bytes()).unwrap(), hash);
        assert_eq!(base32hex(b"w"), None);
    }

    #[test]
    fn a_parent_side_nsec_proves_nothing_below_its_cut() {
        let zone = name("example.");
        // sub.example. is delegated; the NSEC there sits on the parent side.
        let records = [nsec("sub.example.", "z.example.", &[RecordType::NS])];
        assert_eq!(
            nxdomain(&name("a.sub.example."), &zone, &records, 0),
            Proof::Unproven
        );
        assert_eq!(
            nodata(&name("sub.example."), RecordType::A, &zone, &records, 0),
            Proof::Unproven
        );
        assert_eq!(
            nodata(&name("sub.example."), RecordType::DS, &zone, &records, 0),
            Proof::Proven
        );
        assert_eq!(
            no_ds(&name("sub.example."), &zone, &records, 0),
            Proof::Proven
        );
        // A child apex's NSEC cannot deny the parent's DS.
        let apex = [nsec("sub.example.", "a.sub.example.", APEX)];
        assert_eq!(
            nodata(&name("sub.example."), RecordType::DS, &zone, &apex, 0),
            Proof::Unproven
        );
    }

    #[test]
    fn nsec3_nxdomain_needs_the_closest_encloser_and_the_wildcard() {
        let zone = name("example.");
        let records = nsec3(
            "example.",
            &[("example.", APEX), ("a.example.", &[RecordType::A])],
            false,
        );
        // Two records cover every other hash, the wildcard's included.
        assert_eq!(
            nxdomain(&name("x.y.example."), &zone, &records, 0),
            Proof::Proven
        );
        assert_eq!(
            nxdomain(&name("a.example."), &zone, &records, 0),
            Proof::Unproven
        );
        assert_eq!(
            nodata(&name("a.example."), RecordType::TXT, &zone, &records, 0),
            Proof::Proven
        );
        assert_eq!(
            nodata(&name("a.example."), RecordType::A, &zone, &records, 0),
            Proof::Unproven
        );
        // Without the apex record there is no closest encloser.
        assert_eq!(
            nxdomain(&name("x.example."), &zone, &records[..0], 0),
            Proof::Unproven
        );
        let only_a: Vec<RecordSet> = records
            .iter()
            .filter(|set| {
                let RData::DNSSEC(DNSSECRData::NSEC3(rdata)) =
                    &set.records_without_rrsigs().next().unwrap().data
                else {
                    unreachable!()
                };
                rdata.type_set().contains(RecordType::A)
            })
            .cloned()
            .collect();
        assert_eq!(
            nxdomain(&name("x.example."), &zone, &only_a, 0),
            Proof::Unproven
        );
        // Records for another zone do not count.
        assert_eq!(
            nxdomain(&name("x.y.other."), &name("other."), &records, 0),
            Proof::Unproven
        );
    }

    #[test]
    fn nsec3_opt_out_is_never_proven() {
        let zone = name("example.");
        let records = nsec3(
            "example.",
            &[
                ("example.", APEX),
                ("a.example.", &[RecordType::NS, RecordType::DS]),
            ],
            true,
        );
        assert_eq!(
            nxdomain(&name("x.example."), &zone, &records, 0),
            Proof::OptOut
        );
        assert_eq!(
            nodata(&name("x.example."), RecordType::DS, &zone, &records, 0),
            Proof::OptOut
        );
        assert_eq!(
            no_ds(&name("x.example."), &zone, &records, 0),
            Proof::OptOut
        );
        assert_eq!(
            wildcard_answer(&name("x.example."), 1, &zone, &records, 0),
            Proof::OptOut
        );
        assert_eq!(
            nxdomain(&name("x.example."), &zone, &records, 0).clone(),
            Proof::OptOut
        );
    }

    #[test]
    fn iterations_past_the_limit_are_not_hashed() {
        let zone = name("example.");
        let records = nsec3("example.", &[("example.", APEX)], false);
        assert_eq!(
            nxdomain(&name("x.example."), &zone, &records, 0),
            Proof::Proven
        );
        let rdata = NSEC3::new(
            Nsec3HashAlgorithm::SHA1,
            false,
            101,
            Vec::new(),
            vec![0; 20],
            [],
        );
        let owner = name(&format!("{}.example.", base32hex_encode(&[0; 20])));
        let heavy = [set(&owner, DNSSECRData::NSEC3(rdata))];
        assert_eq!(
            nxdomain(&name("x.example."), &zone, &heavy, 100),
            Proof::Iterations
        );
    }
}
