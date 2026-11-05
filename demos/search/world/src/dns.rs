//! Which names get a site, and the names the world blocks.
//!
//! The world answers DNS itself ([`net`](crate::net)): the gateway's
//! resolver serves a zone in which each name the session serves gets a
//! site the first time it is asked, and every other name does not exist.

use fictionet::stdlib::protocols::dns::rr::LowerName;
use fictionet_extras::dns::public;

/// Public encrypted resolvers are unavailable to guests in every mode.
pub(crate) fn encrypted_resolver(host: &str) -> bool {
    public::PUBLIC_RESOLVERS
        .iter()
        .flat_map(|resolver| resolver.doh())
        .any(|name| {
            name.to_ascii()
                .trim_end_matches('.')
                .eq_ignore_ascii_case(host.trim_end_matches('.'))
        })
}

/// Top-level domains that never resolve on the internet: reserved by RFC
/// 2606 and 6761, used for mDNS, or used only inside private networks.
const NOT_ON_THE_INTERNET: [&str; 12] = [
    "test",
    "example",
    "invalid",
    "localhost",
    "local",
    "internal",
    "lan",
    "home",
    "corp",
    "intranet",
    "private",
    "arpa",
];

/// Whether `name` gets a site. `Err` says why not, for the log.
///
/// A name gets a site when it could be a host on the internet: at least two
/// labels, each 1 to 63 letters, digits or hyphens, not starting or ending
/// with a hyphen, at most 253 characters in all, and a top-level domain of
/// two or more letters (or an `xn--` one) that is not reserved or private.
pub fn admit(name: &str) -> Result<(), &'static str> {
    if !name.contains('.') {
        return Err("single label");
    }
    if name.len() > 253 {
        return Err("too long");
    }
    let labels: Vec<&str> = name.split('.').collect();
    if !labels.iter().all(|label| host_label(label)) {
        return Err("not a host name");
    }
    let tld = labels[labels.len() - 1];
    if !(tld.starts_with("xn--")
        || (tld.len() >= 2 && tld.bytes().all(|b| b.is_ascii_alphabetic())))
    {
        return Err("not a top-level domain");
    }
    if NOT_ON_THE_INTERNET.contains(&tld) {
        return Err("reserved or private top-level domain");
    }
    Ok(())
}

/// Whether `label` may be part of a host name: 1 to 63 letters, digits,
/// or hyphens, not starting or ending with a hyphen (RFC 1123 §2.1).
fn host_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && !label.starts_with('-')
        && !label.ends_with('-')
}

/// `name` as a host name: lowercase, without the trailing dot.
pub(crate) fn host(name: &LowerName) -> String {
    name.to_ascii().trim_end_matches('.').to_owned()
}
