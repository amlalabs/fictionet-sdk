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

/// Every host's address: fixed ones (search engines, the seed), ones
/// recorded on the same store, then the next free one from the pools.
/// Recorded history must be readable and consistent. New addresses are
/// published only after their records have been written. Worlds sharing a
/// store assign under `store.lock`, after reading what the others
/// recorded, so each address goes to one host.
pub struct Addresses {
    inner: Mutex<Inner>,
}

struct Inner {
    by_host: HashMap<String, (Ipv4Addr, &'static str)>,
    used: HashSet<Ipv4Addr>,
    /// The host each recorded address was recorded for.
    recorded: HashMap<Ipv4Addr, String>,
    next: u32,
    failure: Option<(io::ErrorKind, String)>,
    /// The store's `addresses.jsonl` and `store.lock`, for a world with a
    /// store.
    record: Option<Record>,
}

struct Record {
    lines: Appended,
    lock: std::fs::File,
}

/// One line of `addresses.jsonl`.
#[derive(Serialize, Deserialize)]
struct Assigned {
    host: String,
    addr: Ipv4Addr,
}

impl Inner {
    /// Applies what this and other worlds have appended to
    /// `addresses.jsonl` since it was last read. The caller holds
    /// `store.lock`.
    fn read_on(&mut self) -> io::Result<()> {
        let Some(record) = &mut self.record else {
            return Ok(());
        };
        let (by_host, used, recorded) = (&mut self.by_host, &mut self.used, &mut self.recorded);
        record.lines.read_on(true, |line: Assigned| {
            let Assigned { host, addr } = line;
            if let Some(previous) = recorded.get(&addr)
                && *previous != host
            {
                return Err(format!("{addr} is recorded for both {previous} and {host}"));
            }
            recorded.insert(addr, host.clone());
            if let Some((previous, _)) = by_host.get(&host) {
                if *previous != addr {
                    return Err(format!("{host} has both {previous} and {addr}"));
                }
                return Ok(());
            }
            if !used.insert(addr) {
                return Err(format!("{addr} is already assigned to another host"));
            }
            by_host.insert(host, (addr, "recorded"));
            Ok(())
        })
    }
}

/// The pools: two /16s that many ordinary sites live in. Addresses
/// alternate between them, and step through each one in a scattered
/// order, so hosts looked up one after another do not get neighbouring
/// addresses.
const POOLS: [[u8; 2]; 2] = [[104, 21], [172, 67]];

impl Addresses {
    /// `fixed` maps hosts to addresses with the reason (`"search engine"`,
    /// `"seed"`). With `store`, the store's directory, its
    /// `addresses.jsonl` is read first, as `"recorded"`, and new
    /// assignments are appended to it. A missing file starts a new record.
    /// Other read errors, invalid records and conflicting assignments fail
    /// construction.
    pub fn new(
        fixed: HashMap<String, (Ipv4Addr, &'static str)>,
        store: Option<&Path>,
    ) -> io::Result<Addresses> {
        let mut names: Vec<_> = fixed.keys().cloned().collect();
        names.sort();
        let record = store
            .map(|root| {
                Ok::<_, io::Error>(Record {
                    lines: Appended::open(&root.join("addresses.jsonl"))?,
                    lock: files::store_lock(root)?,
                })
            })
            .transpose()?;
        let mut inner = Inner {
            used: fixed.values().map(|(a, _)| *a).collect(),
            by_host: fixed,
            recorded: HashMap::new(),
            next: 0,
            failure: None,
            record,
        };
        let held = (inner.record.as_ref())
            .map(|r| FileLock::take(&r.lock))
            .transpose()?;
        inner.read_on()?;
        drop(held);
        Ok(Addresses {
            inner: Mutex::new(inner),
        })
    }

    /// The address of `host`, and why it has that one: its fixed or
    /// recorded address, or the next free one from the pools (`"pool"`).
    /// Returns `Ok(None)` after one full traversal if the pools are exhausted.
    /// An append failure returns an error without publishing the address.
    /// Later calls for unrecorded hosts return the same error; fixed and
    /// already recorded hosts still answer.
    pub fn assign(&self, host: &str) -> io::Result<Option<(Ipv4Addr, &'static str)>> {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(found) = inner.by_host.get(host) {
            return Ok(Some(*found));
        }
        if let Some((kind, reason)) = &inner.failure {
            return Err(io::Error::new(*kind, reason.clone()));
        }
        let _held = (inner.record.as_ref())
            .map(|r| FileLock::take(&r.lock))
            .transpose()?;
        inner.read_on()?;
        if let Some(found) = inner.by_host.get(host) {
            return Ok(Some(*found));
        }
        let Some(addr) = (0..131_072).find_map(|_| {
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
        }) else {
            return Ok(None);
        };
        let line = Assigned {
            host: host.to_owned(),
            addr,
        };
        let appended = match &mut inner.record {
            Some(record) => record.lines.append(&line),
            None => Ok(()),
        };
        if let Err(e) = appended {
            inner.failure = Some((e.kind(), e.to_string()));
            return Err(e);
        }
        inner.used.insert(addr);
        inner.recorded.insert(addr, host.to_owned());
        inner.by_host.insert(host.to_owned(), (addr, "pool"));
        Ok(Some((addr, "pool")))
    }
}
