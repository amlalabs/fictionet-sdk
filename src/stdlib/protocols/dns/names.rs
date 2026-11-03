//! Name arithmetic hickory leaves out or does differently.

use hickory_proto::rr::Name;

/// The number of labels in `name`, the root not counted. hickory's
/// `Name::num_labels` leaves out a leading `*`, as the Labels field of an
/// RRSIG does (RFC 4034 §3.1.3). Everywhere else a `*` is a label like any
/// other, so a count of labels comes from here.
pub fn label_count(name: &Name) -> usize {
    name.iter().count()
}

/// The name a DNAME at `owner` with `target` makes of `name`: the labels
/// of `name` above `owner`, followed by `target` (RFC 6672 §2.2). `None`
/// when `name` is not strictly below `owner`, or when the new name would
/// take more than 255 octets, which hickory refuses (RFC 1035 §2.3.4).
pub fn dname_substitute(name: &Name, owner: &Name, target: &Name) -> Option<Name> {
    if !owner.zone_of(name) {
        return None;
    }
    let keep = label_count(name)
        .checked_sub(label_count(owner))
        .filter(|keep| *keep > 0)?;
    Name::from_labels(name.iter().take(keep))
        .and_then(|prefix| prefix.append_domain(target))
        .ok()
}
