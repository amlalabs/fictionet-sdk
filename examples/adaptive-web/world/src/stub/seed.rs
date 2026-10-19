//! Seeds and fixed pages, loaded together or embedded in the executable.

use super::text::{normalize_space, strip, target_of};
use serde::Deserialize;
use std::{collections::HashMap, io, net::Ipv4Addr, path::Path};

/// A site described by the scenario.
#[derive(Clone, Debug, Deserialize)]
pub struct Site {
    /// Hostname used for matching search text.
    pub host: String,
    /// Description used to generate search results.
    #[serde(default)]
    pub about: String,
}

/// A page whose bytes come from the seed's files.
#[derive(Clone, Debug)]
pub struct Fixed {
    /// Full page URL.
    pub url: String,
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

/// A scenario and its fixed pages and addresses.
#[derive(Clone, Debug)]
pub struct Seed {
    /// Scenario name.
    pub name: String,
    /// World date in year-month-day form.
    pub date: String,
    /// Initial search question with normalized whitespace.
    pub question: String,
    /// Markdown body after the front matter.
    pub scenario: String,
    /// Statements available to generated pages and snippets.
    pub facts: Vec<String>,
    /// Sites described in the front matter.
    pub sites: Vec<Site>,
    /// Pages served from captured file bytes.
    pub fixed: Vec<Fixed>,
    /// Explicit hostname assignments from the seed.
    pub addresses: HashMap<String, Ipv4Addr>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Front {
    date: Option<toml::Value>,
    question: String,
    facts: Vec<String>,
    sites: Vec<Site>,
    fixed: Vec<FixedFile>,
    addresses: HashMap<String, String>,
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
            question: normalize_space(&front.question),
            scenario: strip(body).into(),
            facts: front.facts,
            sites: front
                .sites
                .into_iter()
                .map(|s| Site {
                    host: s.host.to_lowercase(),
                    ..s
                })
                .collect(),
            fixed,
            addresses,
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

    /// Loads one of the three bundled scenarios without reading any files.
    pub fn builtin(name: &str) -> io::Result<Self> {
        let text = match name {
            "halvard-cve" => include_str!("../../../seeds/halvard-cve.md"),
            "corvane-acquisition" => include_str!("../../../seeds/corvane-acquisition.md"),
            "fastjsonl-package" => include_str!("../../../seeds/fastjsonl-package.md"),
            _ => return Err(invalid(format!("no seed named {name:?}"))),
        };
        Self::parse(name, text, |file| match file {
            "fixed/halvard-hsa-2026-014.html" => {
                Ok(include_bytes!("../../../seeds/fixed/halvard-hsa-2026-014.html").to_vec())
            }
            _ => Err(invalid(format!("no bundled fixed file {file:?}"))),
        })
    }

    /// Finds a fixed page by host and request target.
    pub fn fixed_for(&self, host: &str, target: &str) -> Option<&Fixed> {
        self.fixed
            .iter()
            .find(|f| f.host == host && f.target == target)
    }

    /// Returns the scenario's description of a host.
    pub fn about(&self, host: &str) -> Option<&str> {
        self.sites
            .iter()
            .find(|s| s.host == host)
            .map(|s| s.about.as_str())
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bundled_seeds_equal_files() {
        for name in ["halvard-cve", "corvane-acquisition", "fastjsonl-package"] {
            let bundled = Seed::builtin(name).unwrap();
            let loaded = Seed::load(
                Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("../seeds/{name}.md")),
            )
            .unwrap();
            assert_eq!(bundled.question, loaded.question);
            assert_eq!(bundled.scenario, loaded.scenario);
            assert_eq!(bundled.facts, loaded.facts);
            assert_eq!(bundled.fixed_addresses(), loaded.fixed_addresses());
            assert_eq!(
                bundled.fixed.iter().map(|f| &f.body).collect::<Vec<_>>(),
                loaded.fixed.iter().map(|f| &f.body).collect::<Vec<_>>()
            );
        }
    }
    #[test]
    fn parsing_captures_bytes_and_preserves_targets() {
        let text = "+++\ndate = 2026-10-07\nquestion = ' one  two '\n[[fixed]]\nurl = 'https://EXAMPLE.com/a/../é?q=x#frag'\nfile = 'a'\n[addresses]\n'GOOGLE.COM' = '1.2.3.4'\n+++\n body \n";
        let s = Seed::parse("test", text, |f| {
            assert_eq!(f, "a");
            Ok(vec![0, 255])
        })
        .unwrap();
        assert_eq!(s.question, "one two");
        assert_eq!(s.scenario, "body");
        assert_eq!(s.fixed[0].host, "example.com");
        assert_eq!(s.fixed[0].target, "/a/../é?q=x");
        assert_eq!(s.fixed[0].body, [0, 255]);
        assert_eq!(
            s.fixed_addresses()["google.com"],
            ("1.2.3.4".parse().unwrap(), "seed")
        );
        assert!(Seed::parse("bad", "+++\ndate='2026-02-30'\n+++", |_| Ok(vec![])).is_err());
        assert!(
            Seed::parse(
                "bad",
                "+++\n[[fixed]]\nurl='https://a.com'\nfile='missing'\n+++",
                |_| Err(io::Error::from(io::ErrorKind::NotFound))
            )
            .is_err()
        );
    }
}
