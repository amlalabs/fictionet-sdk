//! Seeds and fixed pages, loaded together or embedded in the executable.

use super::text::target_of;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::HashMap, io, net::Ipv4Addr, path::Path};

/// A page whose bytes come from the seed's files.
#[derive(Clone, Debug)]
pub struct Fixed {
    /// Full page URL.
    pub url: String,
    /// The file, as the seed names it, relative to the seed.
    pub file: String,
    /// Lowercase hostname from the URL.
    pub host: String,
    /// Request path and query string.
    pub target: String,
    /// Title used in search results.
    pub title: String,
    /// Text used in search snippets.
    pub description: String,
    /// Media type and optional charset.
    pub content_type: String,
    /// File bytes captured when the seed is loaded.
    pub body: Vec<u8>,
}

/// A prose brief, world date and optional fixed pages.
#[derive(Clone, Debug)]
pub struct Seed {
    /// Brief name.
    pub name: String,
    /// World date in year-month-day form.
    pub date: String,
    /// The complete prose brief for the page writer.
    pub instructions: String,
    /// Pages served from captured file bytes.
    pub fixed: Vec<Fixed>,
    /// Explicit hostname assignments from the seed.
    pub addresses: HashMap<String, Ipv4Addr>,
    /// The copied web selected by this world.
    pub corpus: Option<Corpus>,
}

/// A capture directory under the downloads root and its crawl starting URLs.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Corpus {
    pub directory: String,
    pub urls: Vec<String>,
    /// Prepared offline references shared across research corpora.
    #[serde(default)]
    pub reference: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Front {
    date: Option<toml::Value>,
    fixed: Vec<FixedFile>,
    addresses: HashMap<String, String>,
    corpus: Option<Corpus>,
}

#[derive(Deserialize)]
struct FixedFile {
    url: String,
    file: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    description: String,
    #[serde(default = "html_type")]
    content_type: String,
}
fn html_type() -> String {
    "text/html; charset=utf-8".into()
}
fn invalid(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

impl Seed {
    /// Parses front matter and reads each fixed file relative to the seed.
    pub fn parse(
        name: &str,
        text: &str,
        mut read_fixed_file: impl FnMut(&str) -> io::Result<Vec<u8>>,
    ) -> io::Result<Self> {
        let rest = text
            .strip_prefix("+++")
            .ok_or_else(|| invalid("a seed starts with +++ and TOML front matter"))?;
        let (front, body) = rest
            .split_once("+++")
            .ok_or_else(|| invalid("missing closing +++"))?;
        let front: Front = toml::from_str(front).map_err(invalid)?;
        let date = match front.date {
            None => time::OffsetDateTime::now_utc().date().to_string(),
            Some(toml::Value::String(s)) if s.is_empty() => {
                time::OffsetDateTime::now_utc().date().to_string()
            }
            Some(toml::Value::String(s)) => s,
            Some(toml::Value::Datetime(d)) => d.to_string(),
            _ => return Err(invalid("date must be an ISO date")),
        };
        parse_date(&date)?;
        let fixed = front
            .fixed
            .into_iter()
            .map(|f| {
                let (host, target) = target_of(&f.url);
                Ok(Fixed {
                    body: read_fixed_file(&f.file)?,
                    file: f.file,
                    url: f.url,
                    host,
                    target,
                    title: f.title,
                    description: f.description,
                    content_type: f.content_type,
                })
            })
            .collect::<io::Result<_>>()?;
        let addresses = front
            .addresses
            .into_iter()
            .map(|(h, a)| Ok((h.to_lowercase(), a.parse().map_err(invalid)?)))
            .collect::<io::Result<_>>()?;
        Ok(Self {
            name: name.into(),
            date,
            instructions: body.trim().into(),
            fixed,
            addresses,
            corpus: front.corpus,
        })
    }

    /// Loads a seed and captures the bytes of all its fixed pages.
    pub fn load(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path)?;
        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| invalid("seed has no name"))?;
        Self::parse(name, &text, |file| {
            std::fs::read(path.parent().unwrap_or(Path::new(".")).join(file))
        })
    }

    /// Loads a bundled brief without reading any files.
    pub fn builtin(name: &str) -> io::Result<Self> {
        let text = match name {
            "web" => include_str!("../../../seeds/web.md"),
            "security" => include_str!("../../../seeds/security.md"),
            "corvane-acquisition" => include_str!("../../../seeds/corvane-acquisition.md"),
            "fastjsonl-package" => include_str!("../../../seeds/fastjsonl-package.md"),
            _ => return Err(invalid(format!("no seed named {name:?}"))),
        };
        Self::parse(name, text, |file| {
            Err(invalid(format!("no bundled fixed file {file:?}")))
        })
    }

    /// What the seed declares, without its fixed pages' bytes or where it
    /// is installed: a store made with one seed serves only that seed.
    pub fn declaration(&self) -> Value {
        let addresses: std::collections::BTreeMap<_, _> = self
            .addresses
            .iter()
            .map(|(host, addr)| (host.clone(), addr.to_string()))
            .collect();
        let fixed: Vec<_> = self
            .fixed
            .iter()
            .map(|f| {
                json!({
                    "url": f.url,
                    "file": f.file,
                    "title": f.title,
                    "description": f.description,
                    "content_type": f.content_type,
                })
            })
            .collect();
        let mut declaration = json!({
            "name": self.name,
            "date": self.date,
            "instructions": self.instructions,
            "fixed": fixed,
            "addresses": addresses,
        });
        if let Some(corpus) = &self.corpus {
            declaration["corpus"] = json!(corpus);
        }
        declaration
    }

    /// Finds a fixed page by host and request target.
    pub fn fixed_for(&self, host: &str, target: &str) -> Option<&Fixed> {
        self.fixed
            .iter()
            .find(|f| f.host == host && f.target == target)
    }

    /// Addresses in the same shape as the world's `fixed_addresses` function.
    pub fn fixed_addresses(&self) -> HashMap<String, (Ipv4Addr, &'static str)> {
        let mut out: HashMap<_, _> = [
            ("www.google.com", "142.250.180.4"),
            ("google.com", "142.250.180.14"),
            ("html.duckduckgo.com", "52.142.124.215"),
            ("duckduckgo.com", "52.142.124.215"),
            ("lite.duckduckgo.com", "52.142.124.215"),
            ("www.bing.com", "150.171.27.10"),
            ("bing.com", "150.171.28.10"),
        ]
        .into_iter()
        .map(|(h, a)| (h.into(), (a.parse().unwrap(), "search engine")))
        .collect();
        out.extend(
            self.addresses
                .iter()
                .map(|(h, a)| (h.clone(), (*a, "seed"))),
        );
        out
    }
}

/// Parses a year-month-day date.
pub(super) fn parse_date(s: &str) -> io::Result<time::Date> {
    let parts: Vec<_> = s.split('-').collect();
    let [y, m, d] = parts[..] else {
        return Err(invalid("date must be YYYY-MM-DD"));
    };
    time::Date::from_calendar_date(
        y.parse().map_err(invalid)?,
        time::Month::try_from(m.parse::<u8>().map_err(invalid)?).map_err(invalid)?,
        d.parse().map_err(invalid)?,
    )
    .map_err(invalid)
}
