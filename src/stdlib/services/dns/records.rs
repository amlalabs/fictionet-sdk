//! Records of one message section gathered into RRsets.

use fictionet::stdlib::protocols::dns::dnssec::rdata::DNSSECRData;
use fictionet::stdlib::protocols::dns::rr::{RData, Record, RecordSet, RecordType};

/// `records` gathered into RRsets in order of first appearance, by owner,
/// type, and class, each RRSIG with the RRset it covers and each RRset at
/// the lowest TTL among its records (RFC 2181 §5.2). An OPT record is no
/// RRset (RFC 6891 §6.1.1) and is left out.
pub fn rrsets(records: &[Record]) -> Vec<RecordSet> {
    let mut sets: Vec<RecordSet> = Vec::new();
    for record in records {
        let covered = match &record.data {
            RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) => Some(rrsig.input().type_covered),
            _ => None,
        };
        let rtype = covered.unwrap_or(record.record_type());
        if rtype == RecordType::OPT {
            continue;
        }
        let index = sets.iter().position(|set| {
            set.name() == &record.name
                && set.record_type() == rtype
                && set.dns_class() == record.dns_class
        });
        let index = index.unwrap_or_else(|| {
            let mut set = RecordSet::with_ttl(record.name.clone(), rtype, record.ttl);
            set.set_dns_class(record.dns_class);
            sets.push(set);
            sets.len() - 1
        });
        let set = &mut sets[index];
        match covered {
            Some(_) => set.insert_rrsig(record.clone()),
            // An RRSIG that came first set no TTL for the data.
            None => {
                let ttl = if set.is_empty() {
                    record.ttl
                } else {
                    set.ttl().min(record.ttl)
                };
                let mut record = record.clone();
                record.name = set.name().clone();
                set.insert(record, 0);
                set.set_ttl(ttl);
            }
        }
    }
    sets
}

/// The RRSIG records among `records` as RRsets of type RRSIG, by owner and
/// class, for a question that asks for RRSIG itself (RFC 4035 §3.2.1).
pub(super) fn signatures(records: &[Record]) -> Vec<RecordSet> {
    let mut sets: Vec<RecordSet> = Vec::new();
    for record in records {
        if record.record_type() != RecordType::RRSIG {
            continue;
        }
        let index = sets
            .iter()
            .position(|set| set.name() == &record.name && set.dns_class() == record.dns_class);
        let index = index.unwrap_or_else(|| {
            let mut set = RecordSet::with_ttl(record.name.clone(), RecordType::RRSIG, record.ttl);
            set.set_dns_class(record.dns_class);
            sets.push(set);
            sets.len() - 1
        });
        let set = &mut sets[index];
        let ttl = set.ttl().min(record.ttl);
        let mut record = record.clone();
        record.name = set.name().clone();
        set.insert(record, 0);
        set.set_ttl(ttl);
    }
    sets
}

/// The label count of the wildcard's parent when `set`'s RRSIGs show a
/// wildcard expansion: a Labels field below the owner's label count, a
/// leading `*` not counted (RFC 4034 §3.1.3, RFC 4035 §5.3.4).
pub fn expanded_from(set: &RecordSet) -> Option<usize> {
    let owner = usize::from(set.name().num_labels());
    set.rrsigs().iter().find_map(|record| match &record.data {
        RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) => {
            let labels = usize::from(rrsig.input().num_labels);
            (labels < owner).then_some(labels)
        }
        _ => None,
    })
}
