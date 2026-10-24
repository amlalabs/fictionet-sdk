//! Parse result lists, people and page replies from the model.

use super::make::{Link, Page, Profile};
use super::prompts::*;
use fictionet_extras::models::DocumentType;
use fictionet_extras::search::{Ad, Result as Listed, Search};
use regex::Regex;
use serde_json::Value;
use std::sync::OnceLock;

pub fn read_cast(text: &str) -> Result<Vec<Person>, Unreadable> {
    let people: Vec<_> = text
        .lines()
        .filter_map(|line| {
            let parts: Vec<_> = line
                .split('|')
                .map(|p| p.trim_matches(|c: char| " -*`".contains(c)))
                .collect();
            match parts[..] {
                [name, role, organization]
                    if !name.is_empty() && !role.is_empty() && !organization.is_empty() =>
                {
                    Some(Person {
                        name: name.into(),
                        role: role.into(),
                        organization: organization.into(),
                    })
                }
                _ => None,
            }
        })
        .collect();
    if people.len() < 3 {
        return Err(Unreadable::Format(
            "fewer than three people in the cast answer".into(),
        ));
    }
    Ok(people)
}

pub fn read_search(text: &str) -> Result<Search, Unreadable> {
    let mut results: Vec<Listed> = Vec::new();
    let mut search = Search::default();
    for raw in text.trim().lines() {
        let line = raw.trim().trim_matches('`');
        let (key, value) = line.split_once(':').unwrap_or((line, ""));
        let (key, value) = (key.trim().to_uppercase(), value.trim());
        let split = |value: &str| -> Vec<String> {
            value
                .split(" | ")
                .map(str::trim)
                .filter(|x| !x.is_empty())
                .map(str::to_owned)
                .collect()
        };
        if line.eq_ignore_ascii_case("RESULT") {
            results.push(Listed::default());
        } else if let Some(result) = results.last_mut()
            && matches!(key.as_str(), "URL" | "TITLE" | "SNIPPET" | "DATE")
        {
            let value = value.to_owned();
            match key.as_str() {
                "URL" => result.url = value,
                "TITLE" => result.title = value,
                "SNIPPET" => result.snippet = value,
                _ if value.eq_ignore_ascii_case("none") => result.date = String::new(),
                _ => result.date = value,
            }
        } else if key == "RELATED" {
            search.related = split(value);
        } else if key == "QUESTIONS" {
            search.questions = split(value);
        } else if key == "AD" {
            let parts: Vec<_> = value.split(" | ").map(str::trim).collect();
            if let [url, title, text] = parts[..]
                && url.starts_with("http")
            {
                search.ads.push(Ad {
                    url: url.into(),
                    title: title.into(),
                    text: text.into(),
                });
            }
        }
    }
    search.results = results
        .into_iter()
        .filter(|r| r.url.starts_with("http") && !r.title.is_empty())
        .collect();
    if search.results.is_empty() {
        return Err(Unreadable::Format("no results in the search answer".into()));
    }
    for url in search
        .results
        .iter()
        .map(|result| result.url.as_str())
        .chain(search.ads.iter().map(|ad| ad.url.as_str()))
    {
        let public = url::Url::parse(url).ok().is_some_and(|url| {
            matches!(url.scheme(), "http" | "https")
                && url.host_str().is_some_and(|host| {
                    let host = host.trim_end_matches('.');
                    host.contains('.')
                        && ![
                            "example.com",
                            "example.net",
                            "example.org",
                            "example",
                            "test",
                            "invalid",
                            "localhost",
                        ]
                        .iter()
                        .any(|suffix| {
                            host == *suffix
                                || host
                                    .strip_suffix(suffix)
                                    .is_some_and(|prefix| prefix.ends_with('.'))
                        })
                })
        });
        if !public {
            return Err(Unreadable::Format(
                "search results need public site domains".into(),
            ));
        }
    }
    Ok(search)
}

fn links(line: &str) -> Vec<Link> {
    line.split(',').filter_map(Link::parse).collect()
}

pub fn read_page(text: &str, expected: Option<&str>, referenced: bool) -> Result<Page, Unreadable> {
    static FENCE: OnceLock<Regex> = OnceLock::new();
    static CLOSE: OnceLock<Regex> = OnceLock::new();
    let text = text.trim();
    let text = FENCE
        .get_or_init(|| Regex::new(r"^```[a-z]*\s*\n").unwrap())
        .replace(text, "");
    let Some((head, body)) = text.split_once("\nBODY:") else {
        return Err(Unreadable::Format(
            "no BODY: line in the page answer".into(),
        ));
    };
    let body = body.trim_start_matches('\n').trim_end();
    let body = CLOSE
        .get_or_init(|| Regex::new(r"\n```\s*$").unwrap())
        .replace(body, "")
        .into_owned();
    let mut page = Page {
        status: 200,
        content_type: "text/html; charset=utf-8".into(),
        body,
        ..Page::default()
    };
    let mut site = Profile::default();
    let mut section = "";
    for raw in head.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(item) = line.strip_prefix("- ")
            && matches!(section, "claims" | "sidebar")
        {
            let item = item.trim();
            if section == "claims" {
                let (known_on, statement) = if let Some((date, statement)) = item.split_once(" | ")
                {
                    (
                        Some(super::seed::parse_date(date).map_err(|_| {
                            Unreadable::Format(
                                "CLAIMS needs a known-on date in YYYY-MM-DD form".into(),
                            )
                        })?),
                        statement,
                    )
                } else {
                    (None, item)
                };
                page.claims.push(super::prompts::Statement {
                    text: statement.into(),
                    known_on,
                });
            } else if let Some((label, href)) = item.split_once('|') {
                page.sidebar.push((label.trim().into(), href.trim().into()));
            }
            continue;
        }
        let (key, value) = line.split_once(':').unwrap_or((line, ""));
        let (key, value) = (key.trim().to_uppercase(), value.trim());
        let none = value.is_empty() || value.eq_ignore_ascii_case("none");
        section = "";
        match key.as_str() {
            "STATUS" => {
                let digits: String = value.chars().filter(char::is_ascii_digit).collect();
                page.status = digits
                    .parse()
                    .unwrap_or(if digits.is_empty() { 200 } else { 0 });
            }
            "CONTENT_TYPE" => {
                let normalized = value.split(';').next().unwrap().trim().to_ascii_lowercase();
                let ctype = normalized.as_str();
                let ctype = if ctype.is_empty() { "text/html" } else { ctype };
                let charset = ctype.starts_with("text/") || ctype.contains("json");
                page.content_type =
                    format!("{ctype}{}", if charset { "; charset=utf-8" } else { "" });
            }
            "TITLE" => page.title = value.into(),
            "DESCRIPTION" => page.description = value.into(),
            "DATE" => page.date = if none { String::new() } else { value.into() },
            "CLAIMS" => section = "claims",
            "SIDEBAR" => section = "sidebar",
            "AD" => page.ad = if none { String::new() } else { value.into() },
            "SITE_NAME" => site.name = value.into(),
            "SITE_KIND" => {
                site.kind = value
                    .parse()
                    .map_err(|_| Unreadable::Format("Unknown site category".into()))?
            }
            "SITE_TAGLINE" => site.tagline = if none { String::new() } else { value.into() },
            "SITE_NAV" => site.nav = links(value),
            "SITE_FOOTER" => site.footer = links(value),
            "SITE_CSS" => site.css = value.into(),
            _ => {}
        }
    }
    if page.title.is_empty() {
        return Err(Unreadable::Format(
            "no TITLE: line in the page answer".into(),
        ));
    }
    if let Some(expected) = expected {
        let charset = if expected == "application/xml" {
            ""
        } else {
            "; charset=utf-8"
        };
        page.content_type = format!("{expected}{charset}");
    }
    if DocumentType::from(page.content_type.as_str()) == DocumentType::Json
        && serde_json::from_str::<Value>(&page.body).is_err()
    {
        return Err(Unreadable::Format(
            "the body of a JSON URL is not JSON".into(),
        ));
    }
    if !matches!(page.status, 200 | 404) {
        return Err(Unreadable::Format(format!(
            "STATUS must be 200 or 404, got {}",
            page.status
        )));
    }
    if referenced && page.status == 404 {
        return Err(Unreadable::Format(
            "a referenced page cannot have STATUS 404; a search result or link points here".into(),
        ));
    }
    if !site.name.is_empty() || !site.css.is_empty() {
        page.site = Some(site);
    }
    Ok(page)
}

/// Calendar dates in publication metadata and document prose.
pub(super) fn dates(text: &str) -> Vec<time::Date> {
    static DATES: OnceLock<Regex> = OnceLock::new();
    let dates = DATES.get_or_init(|| Regex::new(
        r"(?i)\b(?:[0-9]{4}-[0-9]{2}-[0-9]{2}|(?:[0-9]{1,2}\s+)?(?:January|February|March|April|May|June|July|August|September|October|November|December|Jan|Feb|Mar|Apr|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\.?\s+[0-9]{1,4}(?:,?\s+[0-9]{4})?)\b"
    ).unwrap());
    dates
        .find_iter(text)
        .filter_map(|found| {
            let text = found.as_str();
            if let Ok(date) = super::seed::parse_date(text) {
                return Some(date);
            }
            let words: Vec<_> = text
                .split(|c: char| c.is_whitespace() || c == ',' || c == '.')
                .filter(|word| !word.is_empty())
                .collect();
            let [first, second, year] = words.as_slice() else {
                return None;
            };
            let (day, month) = if first.bytes().all(|b| b.is_ascii_digit()) {
                (*first, *second)
            } else {
                (*second, *first)
            };
            let month = match &month.to_ascii_lowercase()[..3] {
                "jan" => time::Month::January,
                "feb" => time::Month::February,
                "mar" => time::Month::March,
                "apr" => time::Month::April,
                "may" => time::Month::May,
                "jun" => time::Month::June,
                "jul" => time::Month::July,
                "aug" => time::Month::August,
                "sep" => time::Month::September,
                "oct" => time::Month::October,
                "nov" => time::Month::November,
                "dec" => time::Month::December,
                _ => return None,
            };
            time::Date::from_calendar_date(year.parse().ok()?, month, day.parse().ok()?).ok()
        })
        .collect()
}

pub(super) fn chronology(page: &Page, latest: time::Date) -> Result<(), Unreadable> {
    let dateline = if page.date.is_empty() {
        latest
    } else {
        super::seed::parse_date(&page.date)
            .map_err(|_| Unreadable::Chronology("DATE must be YYYY-MM-DD".into()))?
    };
    if dateline > latest {
        return Err(Unreadable::Chronology(format!(
            "DATE must be on or before {latest}, when a referring page already links here. Write only what was known by then."
        )));
    }
    let later: Vec<_> = page
        .claims
        .iter()
        .filter(|claim| claim.known_on.is_some_and(|date| date > dateline))
        .map(|claim| {
            format!(
                "- {} | {}",
                claim.known_on.expect("dated claim"),
                claim.text
            )
        })
        .collect();
    if !later.is_empty() {
        return Err(Unreadable::Chronology(format!(
            "The document is dated {dateline}, but these CLAIMS lines were first known later:\n{}\nRemove those lines and any text that depends on them, or explicitly update DATE and its visible dateline, no later than {latest}.",
            later.join("\n")
        )));
    }
    Ok(())
}

/// Publication text that needs semantic review: dates alone cannot distinguish
/// an announced plan from knowledge of its eventual outcome. Explicit calendar
/// dates select documents for semantic review; this does not prove the accuracy
/// of arbitrary undated prose or scientific claims.
pub(super) trait Publication {
    fn later_text(&self, latest: time::Date) -> Vec<(time::Date, String)>;
}
impl Publication for Page {
    fn later_text(&self, latest: time::Date) -> Vec<(time::Date, String)> {
        let dateline = super::seed::parse_date(&self.date).unwrap_or(latest);
        let text = format!(
            "{}\n{}\n{}",
            self.title,
            self.description,
            if self.content_type.starts_with("text/html") {
                super::text::text_of(&self.body)
            } else {
                self.body.clone()
            }
        );
        if dates(&text).iter().any(|date| *date > dateline) {
            vec![(dateline, text)]
        } else {
            Vec::new()
        }
    }
}
impl Publication for Search {
    fn later_text(&self, latest: time::Date) -> Vec<(time::Date, String)> {
        self.results
            .iter()
            .flat_map(|result| {
                Page {
                    date: dates(&result.date)
                        .first()
                        .map(ToString::to_string)
                        .unwrap_or_default(),
                    title: result.title.clone(),
                    body: result.snippet.clone(),
                    content_type: "text/plain".into(),
                    ..Default::default()
                }
                .later_text(latest)
            })
            .collect()
    }
}
impl Publication for String {
    fn later_text(&self, _: time::Date) -> Vec<(time::Date, String)> {
        Vec::new()
    }
}
impl Publication for Vec<Person> {
    fn later_text(&self, _: time::Date) -> Vec<(time::Date, String)> {
        Vec::new()
    }
}
