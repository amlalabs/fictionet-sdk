//! Assign stable public addresses to admitted DNS names.

use super::*;

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
    for label in &labels {
        let ok = !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-');
        if !ok {
            return Err("not a host name");
        }
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

/// Every host's address: fixed ones (search engines, the seed), then the
/// next free one from the pools.
pub struct Addresses {
    inner: Mutex<Inner>,
}

struct Inner {
    by_host: HashMap<String, (Ipv4Addr, &'static str)>,
    used: HashSet<Ipv4Addr>,
    next: u32,
}

/// The pools: two /16s that many ordinary sites live in. Addresses
/// alternate between them, and step through each one in a scattered
/// order, so hosts looked up one after another do not get neighbouring
/// addresses.
const POOLS: [[u8; 2]; 2] = [[104, 21], [172, 67]];

impl Addresses {
    /// `fixed` maps hosts to addresses with the reason (`"search engine"`,
    /// `"seed"`).
    pub fn new(fixed: HashMap<String, (Ipv4Addr, &'static str)>) -> Addresses {
        Addresses {
            inner: Mutex::new(Inner {
                used: fixed.values().map(|(a, _)| *a).collect(),
                by_host: fixed,
                next: 0,
            }),
        }
    }

    /// The address of `host`, and why it has that one: its fixed address,
    /// or the next free one from the pools (`"pool"`). Returns `None` after
    /// one full traversal if the pools are exhausted.
    pub fn assign(&self, host: &str) -> Option<(Ipv4Addr, &'static str)> {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(found) = inner.by_host.get(host) {
            return Some(*found);
        }
        let addr = (0..131_072).find_map(|_| {
            let n = inner.next;
            inner.next = (inner.next + 1) % 131_072;
            let [a, b] = POOLS[(n % 2) as usize];
            // An odd multiplier makes this a permutation of 0..65536.
            let offset = ((n / 2).wrapping_mul(40503).wrapping_add(12345)) & 0xffff;
            let (c, d) = ((offset >> 8) as u8, offset as u8);
            let addr = Ipv4Addr::new(a, b, c, d);
            if d != 0 && d != 255 && !inner.used.contains(&addr) {
                Some(addr)
            } else {
                None
            }
        })?;
        inner.used.insert(addr);
        inner.by_host.insert(host.to_owned(), (addr, "pool"));
        Some((addr, "pool"))
    }
}
