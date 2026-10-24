//! Editorial commitments carried from searches and links into a document.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "via", rename_all = "snake_case")]
pub enum Mention {
    Search {
        #[serde(default)]
        query: String,
        #[serde(default)]
        rank: u64,
        #[serde(default)]
        title: String,
        #[serde(default)]
        snippet: String,
        #[serde(default, with = "publication")]
        date: Option<time::Date>,
    },
    Link {
        #[serde(default)]
        from: String,
        #[serde(default)]
        anchor: String,
    },
}

impl Mention {
    pub fn search(
        query: &str,
        rank: u64,
        result: &fictionet_extras::search::Result,
    ) -> Result<Self, super::prompts::Unreadable> {
        let date = if result.date.is_empty() {
            None
        } else {
            Some(*super::answers::dates(&result.date).first().ok_or_else(|| {
                super::prompts::Unreadable::Format("Search DATE needs a full calendar date".into())
            })?)
        };
        Ok(Self::Search {
            query: query.into(),
            rank,
            title: result.title.clone(),
            snippet: result.snippet.clone(),
            date,
        })
    }

    pub fn title(&self) -> Option<&str> {
        match self {
            Self::Search { title, .. } => Some(title),
            _ => None,
        }
    }
    pub fn snippet(&self) -> Option<&str> {
        match self {
            Self::Search { snippet, .. } => Some(snippet),
            _ => None,
        }
    }
    pub fn source(&self) -> Option<&str> {
        match self {
            Self::Link { from, .. } => Some(from),
            _ => None,
        }
    }
    pub fn date(&self) -> Option<time::Date> {
        match self {
            Self::Search { date, .. } => *date,
            _ => None,
        }
    }
}

mod publication {
    use super::*;
    pub fn serialize<S: serde::Serializer>(
        date: &Option<time::Date>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&date.map(|date| date.to_string()).unwrap_or_default())
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<time::Date>, D::Error> {
        let text = Option::<String>::deserialize(deserializer)?.unwrap_or_default();
        if text.is_empty() {
            return Ok(None);
        }
        let dates = super::super::answers::dates(&text);
        match dates.as_slice() {
            [date] => Ok(Some(*date)),
            _ => Err(serde::de::Error::custom(
                "publication needs one full calendar date",
            )),
        }
    }
}
