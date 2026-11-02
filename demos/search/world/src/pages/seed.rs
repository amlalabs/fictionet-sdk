//! Seeds, embedded in the executable.

use serde::{Deserialize, Serialize};
use std::io;

/// A world date and the copied web.
#[derive(Clone, Debug)]
pub struct Seed {
    /// World date in year-month-day form.
    pub date: String,
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
#[serde(default, deny_unknown_fields)]
struct Front {
    date: Option<toml::Value>,
    corpus: Option<Corpus>,
}

fn invalid(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

impl Seed {
    /// Parses a seed's TOML front matter.
    pub fn parse(text: &str) -> io::Result<Self> {
        let rest = text
            .strip_prefix("+++")
            .ok_or_else(|| invalid("a seed starts with +++ and TOML front matter"))?;
        let (front, _) = rest
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
        Ok(Self {
            date,
            corpus: front.corpus,
        })
    }

    /// Loads a bundled seed.
    pub fn builtin(name: &str) -> io::Result<Self> {
        let text = match name {
            "security" => include_str!("../../../seeds/security.md"),
            _ => return Err(invalid(format!("no seed named {name:?}"))),
        };
        Self::parse(text)
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
