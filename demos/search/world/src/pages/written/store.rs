//! Everything the world has made: pages, result lists, the mentions that
//! pointed at a URL before it existed, site layouts and the cast.
//!
//! A store lives in memory. With a directory it is also kept there, so a
//! later world on the same directory starts from everything an earlier one
//! made:
//!
//! ```text
//! store.json         format version, the seed's declaration, the generator
//! world.jsonl        everything made, one object per line, in order
//! generations.jsonl  every model attempt, stored call and prefetch error
//! addresses.jsonl    every pool address given out (see `Addresses`)
//! store.lock         held while a world checks or writes these files
//! locks/             one lock file per page, result list and the cast
//! ```
//!
//! Several worlds can use one store at once. A world writes only while it
//! holds `store.lock`, after reading what the others wrote. Making a page,
//! a result list or the cast holds that item's file in `locks/`, so the
//! first world to ask makes it and the others wait and read it. A store
//! answers only for the seed it was made with and, to make more, for the
//! same generator: provider, model and reasoning setting. Anything else
//! fails with how to start over.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::make::Profile;
use super::model::Usage;
use super::prompts::{Claim, HostPage, Person};
use super::{Mention, Seed};
use crate::files::{self, Appended, FileLock};

/// The format of `store.json` and `world.jsonl`.
const VERSION: u64 = 1;

/// A page as the world serves it, and what it was made from.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PageRecord {
    pub url: String,
    pub host: String,
    pub target: String,
    pub status: u16,
    pub content_type: String,
    #[serde(with = "body")]
    pub body: Vec<u8>,
    pub headers: Vec<(String, String)>,
    pub title: String,
    pub description: String,
    pub date: String,
    pub claims: Vec<super::prompts::Statement>,
    /// The mentions the page was made from, in their recorded order.
    pub mentions: Vec<Mention>,
    pub tells: Vec<String>,
    pub unsupported_snippets: Vec<String>,
    pub unchecked_snippets: Vec<String>,
    /// Made ahead of its first request.
    pub prefetched: bool,
    /// A fixed page from the seed, captured on first use.
    pub fixed: bool,
    /// What making it cost; none for a fixed page.
    pub usage: Option<Usage>,
}

/// A result list, shared by every engine that shows the query.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SearchRecord {
    pub key: String,
    pub query: String,
    #[serde(flatten)]
    pub search: fictionet_extras::search::Search,
    pub usage: Usage,
}

/// The people pages name.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CastRecord {
    pub people: Vec<Person>,
    pub usage: Usage,
}

/// One line of `world.jsonl`.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Entry {
    Page(PageRecord),
    Search(SearchRecord),
    Mention {
        host: String,
        target: String,
        mention: Mention,
    },
    Site {
        host: String,
        profile: Profile,
    },
    Cast(CastRecord),
}

/// A page body: text when it is UTF-8, else `{"base64": ...}`.
mod body {
    use fictionet::stdlib::codec::base64;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[derive(Serialize, Deserialize)]
    #[serde(untagged)]
    enum Form {
        Text(String),
        Bytes { base64: String },
    }

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        match std::str::from_utf8(bytes) {
            Ok(text) => Form::Text(text.into()),
            Err(_) => Form::Bytes {
                base64: base64::encode(bytes),
            },
        }
        .serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        match Form::deserialize(d)? {
            Form::Text(text) => Ok(text.into_bytes()),
            Form::Bytes { base64: text } => {
                base64::decode(text.as_bytes(), base64::Padding::Required)
                    .ok_or_else(|| serde::de::Error::custom("a body is not base64"))
            }
        }
    }
}

struct Files {
    root: PathBuf,
    world: Appended,
    generations: File,
    /// `store.lock`.
    lock: File,
}

/// The world's store. See the [module](self).
pub struct Store {
    pages: HashMap<(String, String), PageRecord>,
    /// Pages in the order they were made.
    order: Vec<(String, String)>,
    mentions: HashMap<(String, String), Vec<Mention>>,
    sites: Vec<(String, Profile)>,
    searches: HashMap<String, SearchRecord>,
    cast: Option<CastRecord>,
    claims: Vec<Claim>,
    files: Option<Files>,
}

fn key(host: &str, target: &str) -> (String, String) {
    (host.to_owned(), target.to_owned())
}

/// What a stored page is about, in words: its title, description, its
/// address's own words and its claims. Its full text is not matched, since
/// a long page shares a word or two with almost anything.
fn about(page: &PageRecord) -> String {
    let mut about = format!(
        "{} {} {}",
        page.title,
        page.description,
        super::make::title_from(&page.host, &page.target)
    );
    for claim in &page.claims {
        about.push(' ');
        about.push_str(&claim.text);
    }
    about
}

/// Why a store cannot be used, and how to start over.
fn incompatible(root: &Path, reason: &str) -> String {
    format!(
        "cannot reuse store {}: {reason}; rebuild in a fresh --store \
        (--store for the world). Keep the old store for audit",
        root.display()
    )
}

impl Store {
    /// A store kept in memory only.
    pub fn memory() -> Self {
        Self {
            pages: HashMap::new(),
            order: Vec::new(),
            mentions: HashMap::new(),
            sites: Vec::new(),
            searches: HashMap::new(),
            cast: None,
            claims: Vec::new(),
            files: None,
        }
    }

    /// Opens the store at `root` for `seed`, creating it if it is empty.
    /// `generator` is the identity of what will make new pages (see
    /// [`Model::identity`](super::model::Model::identity)), or `None` to
    /// serve only what the store holds. Returns the store and the identity
    /// of the generator that made it.
    pub fn open(
        root: &Path,
        seed: &Seed,
        generator: Option<&Value>,
    ) -> Result<(Self, Value), String> {
        let fail = |e: io::Error| format!("{}: {e}", root.display());
        std::fs::create_dir_all(root).map_err(fail)?;
        let lock = files::store_lock(root).map_err(fail)?;
        let held = FileLock::take(&lock).map_err(fail)?;
        let identity_path = root.join("store.json");
        let declared = seed.declaration();
        let made_by = match std::fs::read(&identity_path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let other = std::fs::read_dir(root)
                    .map_err(fail)?
                    .filter_map(|entry| entry.ok())
                    .any(|entry| entry.file_name() != "store.lock");
                if other {
                    return Err(incompatible(
                        root,
                        "the directory holds files of no store of this version",
                    ));
                }
                let Some(generator) = generator else {
                    return Err(incompatible(root, "replay needs a store a generator made"));
                };
                let identity =
                    json!({"version": VERSION, "seed": declared, "generator": generator});
                write_new(&identity_path, &identity).map_err(fail)?;
                generator.clone()
            }
            Err(e) => return Err(fail(e)),
            Ok(text) => {
                let identity: Value = serde_json::from_slice(&text)
                    .map_err(|e| incompatible(root, &format!("store.json is not JSON: {e}")))?;
                if identity["version"] != VERSION {
                    return Err(incompatible(root, "unsupported store format version"));
                }
                if identity["seed"] != declared {
                    return Err(incompatible(root, "the seed's declaration differs"));
                }
                if !identity["generator"].is_object() {
                    return Err(incompatible(root, "it names no generator"));
                }
                if generator.is_some_and(|g| *g != identity["generator"]) {
                    return Err(incompatible(root, "generator configuration mismatch"));
                }
                identity["generator"].clone()
            }
        };
        let generations = OpenOptions::new()
            .create(true)
            .append(true)
            .open(root.join("generations.jsonl"))
            .map_err(fail)?;
        let mut store = Self::memory();
        store.files = Some(Files {
            root: root.to_owned(),
            world: Appended::open(&root.join("world.jsonl")).map_err(|e| e.to_string())?,
            generations,
            lock,
        });
        store.read_on(true).map_err(|e| e.to_string())?;
        drop(held);
        Ok((store, made_by))
    }

    /// Applies what other worlds have written to `world.jsonl` since this
    /// world last read it; `held` says whether this world holds
    /// `store.lock` (see [`Appended::read_on`]).
    fn read_on(&mut self, held: bool) -> io::Result<()> {
        let Some(files) = &mut self.files else {
            return Ok(());
        };
        let mut entries = Vec::new();
        files.world.read_on(held, |entry: Entry| {
            entries.push(entry);
            Ok(())
        })?;
        for entry in entries {
            self.apply(entry);
        }
        Ok(())
    }

    /// Reads what other worlds have added to the store since this world
    /// last did. Writes read it too, so a failure here also fails the
    /// next write.
    pub fn catch_up(&mut self) -> io::Result<()> {
        self.read_on(false)
    }

    /// Takes `store.lock` and reads what other worlds wrote, so a check made
    /// next sees the whole store until the lock drops. `None` for a store
    /// kept in memory.
    fn hold(&mut self) -> io::Result<Option<FileLock>> {
        let Some(files) = &self.files else {
            return Ok(None);
        };
        let held = FileLock::take(&files.lock)?;
        self.read_on(true)?;
        Ok(Some(held))
    }

    /// The directory the store is kept in, if any.
    pub fn root(&self) -> Option<&Path> {
        self.files.as_ref().map(|f| f.root.as_path())
    }

    fn apply(&mut self, entry: Entry) {
        match entry {
            Entry::Page(page) => {
                let at = key(&page.host, &page.target);
                // A page recorded again, laid out anew, keeps its place.
                if !self.pages.contains_key(&at) {
                    self.claims.extend(page.claims.iter().map(|claim| Claim {
                        url: page.url.clone(),
                        claim: claim.clone(),
                    }));
                    self.order.push(at.clone());
                }
                self.pages.insert(at, page);
            }
            Entry::Search(search) => {
                self.searches.insert(search.key.clone(), search);
            }
            Entry::Mention {
                host,
                target,
                mention,
            } => self
                .mentions
                .entry(key(&host, &target))
                .or_default()
                .push(mention),
            Entry::Site { host, profile } => {
                if let Some((_, old)) = self.sites.iter_mut().find(|(h, _)| *h == host) {
                    *old = profile;
                } else {
                    self.sites.push((host, profile));
                }
            }
            Entry::Cast(cast) => self.cast = Some(cast),
        }
    }

    /// Writes `entry` to the store's file, then applies it. Nothing is
    /// applied if the write fails. The caller holds `store.lock`.
    fn record(&mut self, entry: Entry) -> io::Result<()> {
        if let Some(files) = &mut self.files {
            files.world.append(&entry)?;
        }
        self.apply(entry);
        Ok(())
    }

    /// Appends a row to `generations.jsonl`, for a store with a directory.
    pub fn log_generation(&mut self, row: &Value) -> io::Result<()> {
        let _held = self.hold()?;
        if let Some(files) = &mut self.files {
            let mut line = serde_json::to_vec(row).map_err(io::Error::other)?;
            line.push(b'\n');
            files.generations.write_all(&line)?;
        }
        Ok(())
    }

    pub fn page(&self, host: &str, target: &str) -> Option<&PageRecord> {
        self.pages.get(&key(host, target))
    }

    pub fn insert_page(&mut self, page: PageRecord) -> io::Result<()> {
        let _held = self.hold()?;
        self.record(Entry::Page(page))
    }

    /// The host's pages about `subject`, newest first, as its next prompt
    /// shows them.
    pub fn host_pages(&self, host: &str, subject: &str) -> Vec<HostPage> {
        self.order
            .iter()
            .rev()
            .filter(|(h, _)| h == host)
            .map(|at| &self.pages[at])
            .filter(|page| super::make::related(subject, &about(page)))
            .map(|page| HostPage {
                url: page.url.clone(),
                title: page.title.clone(),
                claims: page.claims.clone(),
            })
            .collect()
    }

    /// What a page at `host` and `target` is about, in words: its address's
    /// own words and what every search and link said of it. Addresses and
    /// field names are not words about it.
    pub fn subject(&self, host: &str, target: &str) -> String {
        let mut subject = super::make::title_from(host, target);
        for mention in self.mentions(host, target) {
            let said: &[&str] = match mention {
                Mention::Search {
                    query,
                    title,
                    snippet,
                    ..
                } => &[query, title, snippet],
                Mention::Link { anchor, .. } => &[anchor],
            };
            for text in said {
                subject.push(' ');
                subject.push_str(text);
            }
        }
        subject
    }

    /// Pages the world has: the seed's fixed pages and every page made with
    /// status 200 and a title, oldest first.
    pub fn known(&self, seed: &Seed) -> Vec<fictionet_extras::search::Result> {
        let fixed = seed.fixed.iter().map(|f| fictionet_extras::search::Result {
            url: f.url.clone(),
            title: f.title.clone(),
            snippet: f.description.clone(),
            date: String::new(),
        });
        let made = self
            .order
            .iter()
            .filter(|at| {
                !seed
                    .fixed
                    .iter()
                    .any(|f| f.host == at.0 && f.target == at.1)
            })
            .map(|at| &self.pages[at])
            .filter(|p| {
                p.status == 200
                    && !p.title.is_empty()
                    && (!super::make::directory(&p.target)
                        || (!p.description.is_empty() && p.description != p.title))
            })
            .map(|p| fictionet_extras::search::Result {
                url: p.url.clone(),
                title: p.title.clone(),
                snippet: p.description.clone(),
                date: super::make::result_date(&p.date),
            });
        fixed.chain(made).collect()
    }

    /// What the world has said about `subject`: the claims, published text
    /// and search promises of pages and searches about it. Published text
    /// is context even when a writer omitted CLAIMS. Pages about other
    /// things stay out, so one question's facts do not leak into another's
    /// pages.
    pub fn writing_context(&self, subject: &str) -> Vec<Claim> {
        let related = |text: &str| super::make::related(subject, text);
        let mut claims: Vec<Claim> = self
            .claims
            .iter()
            .filter(|claim| {
                let (host, target) = super::text::target_of(&claim.url);
                related(&format!(
                    "{} {}",
                    super::make::title_from(&host, &target),
                    claim.claim.text
                ))
            })
            .cloned()
            .collect();
        for page in self
            .order
            .iter()
            .rev()
            .map(|key| &self.pages[key])
            .filter(|page| page.status == 200)
        {
            if related(&about(page)) {
                let body = String::from_utf8_lossy(&page.body);
                let text = if page.content_type.starts_with("text/html") {
                    super::text::text_of(&body)
                } else {
                    body.into_owned()
                };
                claims.push(Claim {
                    url: page.url.clone(),
                    claim: super::prompts::Statement {
                        text: format!("{}: {text}", page.title),
                        known_on: super::seed::parse_date(&page.date).ok(),
                    },
                });
            }
        }
        for search in self
            .searches
            .values()
            .filter(|search| related(&search.query))
        {
            claims.extend(search.search.results.iter().map(Claim::search));
        }
        claims
    }

    /// A destination inherits the search that listed its exact address,
    /// even when an opaque path shares no words with the query.
    pub fn page_context(&self, host: &str, target: &str) -> Vec<Claim> {
        let url = format!("https://{host}{target}");
        let mut claims = self.writing_context(&self.subject(host, target));
        for search in self
            .searches
            .values()
            .filter(|search| search.search.results.iter().any(|result| result.url == url))
        {
            for result in &search.search.results {
                let claim = Claim::search(result);
                if !claims.contains(&claim) {
                    claims.push(claim);
                }
            }
        }
        claims
    }

    pub fn mentions(&self, host: &str, target: &str) -> &[Mention] {
        self.mentions
            .get(&key(host, target))
            .map_or(&[], Vec::as_slice)
    }

    /// Records a mention of a URL, unless it is already recorded.
    pub fn add_mention(&mut self, host: &str, target: &str, mention: Mention) -> io::Result<()> {
        let _held = self.hold()?;
        self.mention_held(host, target, mention)
    }

    fn mention_held(&mut self, host: &str, target: &str, mention: Mention) -> io::Result<()> {
        if self.mentions(host, target).contains(&mention) {
            return Ok(());
        }
        self.record(Entry::Mention {
            host: host.into(),
            target: target.into(),
            mention,
        })
    }

    /// Chooses a search result's title and snippet and records it as a
    /// mention: a page that exists gives its title and description, then the
    /// seed's declaration of a fixed page, then the first title a mention
    /// showed. Returns the mention as recorded, so every engine shows it.
    /// While the page is being written, only what it was asked to show
    /// can be promised: the first recorded mention's title, snippet and date.
    pub fn reserve_mention(
        &mut self,
        seed: &Seed,
        host: &str,
        target: &str,
        mut mention: Mention,
        writing: bool,
    ) -> io::Result<Mention> {
        let _held = self.hold()?;
        let page = self
            .page(host, target)
            .filter(|p| !p.title.is_empty())
            .map(|p| (p.title.clone(), p.description.clone()));
        let declared = seed
            .fixed_for(host, target)
            .map(|f| (f.title.clone(), f.description.clone()));
        if let Mention::Search {
            title,
            snippet,
            date,
            ..
        } = &mut mention
        {
            let promised = self
                .mentions(host, target)
                .iter()
                .find_map(|recorded| match recorded {
                    Mention::Search {
                        title,
                        snippet,
                        date,
                        ..
                    } if !title.is_empty() => Some((title.clone(), snippet.clone(), *date)),
                    _ => None,
                });
            if let Some((chosen_title, description)) = page.or(declared) {
                if !chosen_title.is_empty() {
                    *title = chosen_title;
                }
                if !description.is_empty() {
                    *snippet = description;
                }
            } else if writing && let Some((chosen_title, chosen_snippet, chosen_date)) = promised {
                *title = chosen_title;
                *snippet = chosen_snippet;
                *date = chosen_date;
            } else if let Some(chosen) = self
                .mentions(host, target)
                .iter()
                .filter_map(Mention::title)
                .find(|title| !title.is_empty())
            {
                *title = chosen.into();
            }
            if let Some(chosen) = self
                .page(host, target)
                .and_then(|page| super::seed::parse_date(&page.date).ok())
                .or_else(|| self.publication_date(host, target))
            {
                *date = Some(chosen);
            }
        }
        self.mention_held(host, target, mention.clone())?;
        Ok(mention)
    }

    pub(super) fn publication_date(&self, host: &str, target: &str) -> Option<time::Date> {
        self.mentions(host, target)
            .iter()
            .filter_map(Mention::date)
            .min()
    }

    pub fn site(&self, host: &str) -> Option<&Profile> {
        self.sites.iter().find(|(h, _)| h == host).map(|(_, p)| p)
    }

    /// The host's layout: the first one recorded for it. A new one gets
    /// `style`, the number of hosts that had a layout before it.
    pub fn site_once(&mut self, host: &str, mut profile: Profile) -> io::Result<Profile> {
        let _held = self.hold()?;
        if let Some(old) = self.site(host) {
            if !old.css.is_empty() {
                return Ok(old.clone());
            }
            profile.style = old.style;
        } else {
            profile.style = self.sites.len();
        }
        self.record(Entry::Site {
            host: host.into(),
            profile: profile.clone(),
        })?;
        Ok(profile)
    }

    pub fn search(&self, key: &str) -> Option<&SearchRecord> {
        self.searches.get(key)
    }

    /// Every page, in the order they were made.
    pub fn pages(&self) -> impl Iterator<Item = &PageRecord> {
        self.order.iter().map(|at| &self.pages[at])
    }

    /// Every result list, in no particular order.
    pub fn searches(&self) -> impl Iterator<Item = &SearchRecord> {
        self.searches.values()
    }

    pub fn insert_search(&mut self, search: SearchRecord) -> io::Result<()> {
        let _held = self.hold()?;
        self.record(Entry::Search(search))
    }

    pub fn cast(&self) -> Option<&CastRecord> {
        self.cast.as_ref()
    }

    pub fn set_cast(&mut self, cast: CastRecord) -> io::Result<()> {
        let _held = self.hold()?;
        self.record(Entry::Cast(cast))
    }
}

/// Writes `value` to a new file at `path`, through a temporary file, so a
/// reader never sees half of it.
fn write_new(path: &Path, value: &Value) -> io::Result<()> {
    let tmp = path.with_extension("json.tmp");
    std::fs::write(
        &tmp,
        serde_json::to_vec_pretty(value).map_err(io::Error::other)?,
    )?;
    std::fs::rename(tmp, path)
}
