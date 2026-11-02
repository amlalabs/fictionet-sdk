//! Checking a tree of zones a world built for breaks in its chain of
//! trust.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use fictionet::stdlib::protocols::dns::dnssec::proof::{self, Proof};
use fictionet::stdlib::protocols::dns::dnssec::rdata::{DNSKEY, DNSSECRData, DS};
use fictionet::stdlib::protocols::dns::dnssec::{
    AlgorithmPolicy, DigestType, KeyFlags, PublicKey, Ring, TBS, Verify, ds, key_tag,
};
use fictionet::stdlib::protocols::dns::rr::{
    LowerName, Name, RData, Record, RecordSet, RecordType, SerialNumber,
};

use super::data::{Denied, Fact, View};
use super::zone::{Node, Zone};

/// A break in a chain of trust that [`check_chain`] found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChainProblem {
    /// The parent's DS RRset for `child` names no DNSKEY of the child that
    /// signs the child's DNSKEY RRset, so validators find the child Bogus
    /// (RFC 4035 §5.2).
    DsMismatch {
        /// The parent zone's apex.
        parent: LowerName,
        /// The child zone's apex.
        child: LowerName,
    },
    /// The signed parent has no DS RRset for `child` and no signed NSEC or
    /// NSEC3 record proving there is none, so validators find the
    /// delegation Bogus instead of Insecure (RFC 4035 §5.2, RFC 5155 §8.9).
    NoDsProofMissing {
        /// The parent zone's apex.
        parent: LowerName,
        /// The delegated child's apex.
        child: LowerName,
    },
    /// An RRSIG in the zone at `apex` is not valid at `at`: its window has
    /// not opened, has closed, or ends before it starts (RFC 4034 §3.1.5).
    WindowClosed {
        /// The zone's apex.
        apex: LowerName,
        /// The time checked.
        at: SystemTime,
    },
    /// The zone at `apex` is signed, or its parent's DS records point, with
    /// a DNSKEY algorithm the policy does not validate, so validators find
    /// it Insecure (RFC 4035 §5.2, RFC 9905 §2).
    UnsupportedAlgorithm {
        /// The zone's apex.
        apex: LowerName,
        /// The registry number of the algorithm.
        algorithm: u8,
    },
}

impl fmt::Display for ChainProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChainProblem::DsMismatch { parent, child } => {
                write!(
                    f,
                    "the DS records in {parent} match no signing key of {child}"
                )
            }
            ChainProblem::NoDsProofMissing { parent, child } => {
                write!(f, "{parent} does not prove that {child} has no DS records")
            }
            ChainProblem::WindowClosed { apex, at } => {
                let seconds = at.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
                write!(
                    f,
                    "a signature in {apex} is not valid at {seconds} seconds past 1970"
                )
            }
            ChainProblem::UnsupportedAlgorithm { apex, algorithm } => {
                write!(
                    f,
                    "{apex} uses DNSKEY algorithm {algorithm}, which the policy does not validate"
                )
            }
        }
    }
}

/// The breaks in the chains of trust of `zones`, as a validator with
/// `policy` would see them at `at`.
///
/// A zone in `zones` is the parent of another when it holds a zone cut at
/// the other's apex. Each delegation is checked from the parent's side,
/// and from the child's when the child is in `zones` too: a DS RRset must
/// select a key of the child that signs the child's DNSKEY RRset, and a
/// signed parent without one must prove there is none. Every zone's
/// signatures must be valid at `at`, and its keys must use algorithms the
/// policy validates.
///
/// The check is advisory. A world that wants a broken chain, to play a
/// zone like `dnssec-failed.org`, leaves the problem in, and resolvers
/// then do what the standards say. Problems come zone by zone, in the
/// order of `zones`, each once.
pub fn check_chain(zones: &[&Zone], policy: &AlgorithmPolicy, at: SystemTime) -> Vec<ChainProblem> {
    let mut problems = Vec::new();
    for zone in zones {
        let apex = zone.apex();
        let keys = dnskeys(zone);
        for algorithm in keys
            .iter()
            .map(|key| u8::from(key.public_key().algorithm()))
        {
            if !policy.validates(algorithm) {
                problems.push(ChainProblem::UnsupportedAlgorithm {
                    apex: apex.clone(),
                    algorithm,
                });
            }
        }
        if signatures(zone).iter().any(|rrsig| !inside(rrsig, at)) {
            problems.push(ChainProblem::WindowClosed {
                apex: apex.clone(),
                at,
            });
        }
        for (child, node) in zone.nodes() {
            let Node::Cut { ds, .. } = node else {
                continue;
            };
            let below = zones.iter().find(|other| other.apex() == child);
            match ds {
                Some(ds) => problems.extend(delegation(apex, child, ds, below, policy)),
                None if !keys.is_empty() => {
                    let records = match zone.denial(child, Denied::Type(RecordType::DS)) {
                        Fact::Present(records) => records,
                        Fact::Absent | Fact::Unknown => Vec::new(),
                    };
                    let parent = Name::from(apex);
                    let verified: Vec<RecordSet> = records
                        .into_iter()
                        .filter(|set| verifies(set, &parent, &keys, policy))
                        .collect();
                    let proof = proof::no_ds(
                        &Name::from(child),
                        &parent,
                        &verified,
                        policy.max_nsec3_iterations,
                    );
                    if proof == Proof::Unproven {
                        problems.push(ChainProblem::NoDsProofMissing {
                            parent: apex.clone(),
                            child: child.clone(),
                        });
                    }
                }
                None => {}
            }
        }
    }
    let mut once = Vec::new();
    for problem in problems {
        if !once.contains(&problem) {
            once.push(problem);
        }
    }
    once
}

/// The problems with a delegation that has DS records: algorithms the
/// policy does not validate, and DS records that select no key of the
/// child, when the child is known.
fn delegation(
    parent: &LowerName,
    child: &LowerName,
    ds_set: &RecordSet,
    below: Option<&&Zone>,
    policy: &AlgorithmPolicy,
) -> Vec<ChainProblem> {
    let records: Vec<&DS> = ds_set
        .records_without_rrsigs()
        .filter_map(|record| match &record.data {
            RData::DNSSEC(DNSSECRData::DS(ds)) => Some(ds),
            _ => None,
        })
        .collect();
    let mut problems: Vec<ChainProblem> = records
        .iter()
        .map(|ds| u8::from(ds.algorithm()))
        .filter(|algorithm| !policy.validates(*algorithm))
        .map(|algorithm| ChainProblem::UnsupportedAlgorithm {
            apex: child.clone(),
            algorithm,
        })
        .collect();
    let usable: Vec<(&DS, DigestType)> = records
        .iter()
        .copied()
        .filter(|ds| policy.validates(u8::from(ds.algorithm())))
        .filter(|ds| policy.accepts_digest(u8::from(ds.digest_type())))
        .filter_map(|ds| Some((ds, DigestType::from_number(u8::from(ds.digest_type()))?)))
        .collect();
    let Some(below) = below else {
        return problems;
    };
    // With no DS a validator can use, the child is Insecure, which is not
    // a break.
    if usable.is_empty() {
        return problems;
    }
    let owner = Name::from(child);
    let selected: Vec<DNSKEY> = dnskeys(below)
        .into_iter()
        .filter(|key| {
            usable.iter().any(|(record, digest)| {
                let made = ds(&owner, key, *digest);
                made.key_tag() == record.key_tag()
                    && made.algorithm() == record.algorithm()
                    && made.digest() == record.digest()
            })
        })
        .collect();
    let dnskey_set = match below.node(child) {
        Some(Node::Data(sets)) => sets.get(&RecordType::DNSKEY),
        _ => None,
    };
    let signs = dnskey_set.is_some_and(|set| verifies(set, &owner, &selected, policy));
    if !signs {
        problems.push(ChainProblem::DsMismatch {
            parent: parent.clone(),
            child: child.clone(),
        });
    }
    problems
}

/// The zone's DNSKEYs that may verify its data: the Zone Key bit set
/// (RFC 4034 §2.1.1) and not revoked (RFC 5011 §3).
fn dnskeys(zone: &Zone) -> Vec<DNSKEY> {
    let Some(Node::Data(sets)) = zone.node(zone.apex()) else {
        return Vec::new();
    };
    let Some(set) = sets.get(&RecordType::DNSKEY) else {
        return Vec::new();
    };
    set.records_without_rrsigs()
        .filter_map(|record| match &record.data {
            RData::DNSSEC(DNSSECRData::DNSKEY(key)) => Some(key.clone()),
            _ => None,
        })
        .filter(|key| {
            let flags = KeyFlags(key.flags());
            flags.zone_key() && !flags.revoked()
        })
        .collect()
}

/// Every RRSIG in the zone: those of each node's RRsets, a cut's DS
/// included, and those of the denial records at each node's name, which
/// reach every NSEC and NSEC3 record of a complete chain.
fn signatures(zone: &Zone) -> Vec<Record> {
    let mut sets: Vec<RecordSet> = Vec::new();
    for (name, node) in zone.nodes() {
        sets.extend(node.rrsets().into_iter().cloned());
        if let Fact::Present(denial) = zone.denial(name, Denied::Type(RecordType::NULL)) {
            sets.extend(denial);
        }
    }
    sets.iter()
        .flat_map(|set| set.rrsigs().iter().cloned())
        .collect()
}

/// Whether `rrsig` is valid at `at`: its inception at or before it and its
/// expiration at or after it, compared as serial numbers (RFC 4034
/// §3.1.5, RFC 1982).
fn inside(rrsig: &Record, at: SystemTime) -> bool {
    let RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) = &rrsig.data else {
        return true;
    };
    use std::cmp::Ordering::{Equal, Greater, Less};
    let input = rrsig.input();
    let at = SerialNumber::new(at.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs()) as u32);
    matches!(
        input.sig_expiration.partial_cmp(&input.sig_inception),
        Some(Greater | Equal)
    ) && matches!(at.partial_cmp(&input.sig_expiration), Some(Less | Equal))
        && matches!(at.partial_cmp(&input.sig_inception), Some(Greater | Equal))
}

/// Whether one of `set`'s RRSIGs by the zone at `signer` verifies under
/// one of `keys` with an algorithm the policy validates. Times are left
/// to [`inside`].
fn verifies(set: &RecordSet, signer: &Name, keys: &[DNSKEY], policy: &AlgorithmPolicy) -> bool {
    set.rrsigs().iter().any(|record| {
        let RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) = &record.data else {
            return false;
        };
        let input = rrsig.input();
        if input.type_covered != set.record_type()
            || input.signer_name != *signer
            || !policy.validates(u8::from(input.algorithm))
        {
            return false;
        }
        let Ok(tbs) = TBS::from_input(
            set.name(),
            set.dns_class(),
            input,
            set.records_without_rrsigs(),
        ) else {
            return false;
        };
        keys.iter()
            .filter(|key| key.public_key().algorithm() == input.algorithm)
            .filter(|key| key_tag(key) == input.key_tag)
            .any(|key| Ring.verify(key, tbs.as_ref(), rrsig.sig()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stdlib::services::dns::zone::signed::tests::{
        NOW, a, builder, keys, lower, name, ns, parent, parent_with_ds_for, rrset, secure_child,
        time, window,
    };
    use crate::stdlib::services::dns::zone::{Denial, Zone};

    fn plain() -> Zone {
        builder("plain.example.")
            .rrset(rrset("www.plain.example.", vec![a(40)]))
            .build()
            .unwrap()
    }

    fn check(zones: &[&Zone]) -> Vec<ChainProblem> {
        check_chain(zones, &AlgorithmPolicy::iana(), time(NOW))
    }

    #[test]
    fn a_correct_tree_passes() {
        let (child, _) = secure_child();
        let denials = [
            Denial::Nsec,
            Denial::Nsec3 {
                opt_out: false,
                salt: Vec::new(),
            },
            Denial::Nsec3 {
                opt_out: true,
                salt: vec![1],
            },
        ];
        for denial in denials {
            let example = parent()
                .signed(&keys(10), window(), denial.clone())
                .unwrap();
            assert_eq!(check(&[&example, &child, &plain()]), [], "{denial:?}");
        }
        // Nothing signed has nothing to break.
        assert_eq!(check(&[&parent(), &plain()]), []);
    }

    #[test]
    fn a_ds_for_other_keys_is_a_mismatch() {
        let (child, _) = secure_child();
        let example = parent_with_ds_for(&keys(50))
            .signed(&keys(10), window(), Denial::Nsec)
            .unwrap();
        assert_eq!(
            check(&[&example, &child]),
            [ChainProblem::DsMismatch {
                parent: lower("example."),
                child: lower("secure.example."),
            }]
        );
        // A child that is not signed at all mismatches too.
        let unsigned = builder("secure.example.").build().unwrap();
        let example = parent().signed(&keys(10), window(), Denial::Nsec).unwrap();
        assert_eq!(
            check(&[&example, &unsigned]),
            [ChainProblem::DsMismatch {
                parent: lower("example."),
                child: lower("secure.example."),
            }]
        );
    }

    #[test]
    fn a_delegation_added_after_signing_lacks_its_no_ds_proof() {
        let example = parent().signed(&keys(10), window(), Denial::Nsec).unwrap();
        let later = example
            .with_delegation(
                name("late.example."),
                rrset("late.example.", vec![ns("ns.elsewhere.test.")]),
                Vec::new(),
                None,
            )
            .unwrap();
        assert_eq!(
            check(&[&later]),
            [ChainProblem::NoDsProofMissing {
                parent: lower("example."),
                child: lower("late.example."),
            }]
        );
    }

    #[test]
    fn signatures_outside_their_window_are_reported_per_zone() {
        let (child, _) = secure_child();
        let example = parent().signed(&keys(10), window(), Denial::Nsec).unwrap();
        for at in [time(1_600_000_000), time(1_900_000_000)] {
            let problems = check_chain(&[&example, &child, &plain()], &AlgorithmPolicy::iana(), at);
            assert_eq!(
                problems,
                [
                    ChainProblem::WindowClosed {
                        apex: lower("example."),
                        at,
                    },
                    ChainProblem::WindowClosed {
                        apex: lower("secure.example."),
                        at,
                    },
                ]
            );
        }
    }

    #[test]
    fn algorithms_the_policy_does_not_validate_are_reported() {
        let (child, _) = secure_child();
        let example = parent().signed(&keys(10), window(), Denial::Nsec).unwrap();
        // The key-signing keys use Ed25519, algorithm 15, which the DS
        // records name too, so the child is Insecure under this policy.
        let mut policy = AlgorithmPolicy::iana();
        policy.validate.remove(&15);
        assert_eq!(
            check_chain(&[&example, &child, &plain()], &policy, time(NOW)),
            [
                ChainProblem::UnsupportedAlgorithm {
                    apex: lower("example."),
                    algorithm: 15,
                },
                ChainProblem::UnsupportedAlgorithm {
                    apex: lower("secure.example."),
                    algorithm: 15,
                },
            ]
        );

        // The zone-signing keys use ECDSA P-256, algorithm 13. Without it
        // the parent's NSEC records do not verify, so the unsigned
        // delegation loses its proof as well.
        let mut policy = AlgorithmPolicy::iana();
        policy.validate.remove(&13);
        assert_eq!(
            check_chain(&[&example, &child, &plain()], &policy, time(NOW)),
            [
                ChainProblem::UnsupportedAlgorithm {
                    apex: lower("example."),
                    algorithm: 13,
                },
                ChainProblem::NoDsProofMissing {
                    parent: lower("example."),
                    child: lower("plain.example."),
                },
                ChainProblem::UnsupportedAlgorithm {
                    apex: lower("secure.example."),
                    algorithm: 13,
                },
            ]
        );
    }
}
