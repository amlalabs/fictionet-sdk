//! Shared text, branding and stored-page helpers for the model writer.

use super::{Seed, seed::parse_date, text::*};
use fictionet_extras::search::{Result, Search};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::borrow::Cow;
use std::sync::OnceLock;

const STOP: &[&str] = &[
    "a", "an", "and", "are", "at", "be", "by", "can", "do", "does", "for", "from", "how", "i",
    "in", "is", "it", "its", "my", "of", "on", "or", "should", "the", "to", "what", "when",
    "which", "who", "why", "with", "you", "our", "we", "this", "that", "was", "will", "about",
    "online", "news", "com", "www", "https", "http", "best", "example", "details", "safe",
    "owners", "version", "fixed", "fix", "latest",
];
/// Bylines assigned to stored articles.
pub(super) const AUTHORS: [&str; 16] = [
    "Priya Raman",
    "Tomasz Wierzbicki",
    "Aoife Gallagher",
    "Kwame Mensah",
    "Lucía Ortega",
    "Henrik Lindqvist",
    "Mei Tanaka",
    "Oluwaseun Adeyemi",
    "Dmitri Volkov",
    "Fatima Benali",
    "Rhys Pritchard",
    "Ingrid Solberg",
    "Mateus Carvalho",
    "Yusuf Demir",
    "Chloé Marchand",
    "Arjun Mehta",
];
/// Forum and Q&A user names.
pub(super) const USERS: [&str; 12] = [
    "netadmin_dk",
    "ferrous_wheel",
    "kb_ops",
    "sysop42",
    "lenkaP",
    "grumpy_firewall",
    "jbrandt",
    "mikko_v",
    "routerroot",
    "tamsin.h",
    "oldschool_ccna",
    "pfeiffer_it",
];
/// Editorial layout selected while decoding a site description.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SiteKind {
    News,
    Blog,
    Company,
    Government,
    Shop,
    Forum,
    Docs,
    Wiki,
    Qa,
    Package,
    Weather,
    Marketplace,
    Review,
    Listings,
    Lodging,
    Howto,
    Recipe,
    Advisory,
    #[default]
    #[serde(alias = "")]
    Other,
}
impl std::str::FromStr for SiteKind {
    type Err = serde_json::Error;
    fn from_str(text: &str) -> std::result::Result<Self, Self::Err> {
        serde_json::from_value(Value::String(text.to_lowercase()))
    }
}
impl std::fmt::Display for SiteKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = serde_json::to_value(self).expect("site category");
        f.write_str(text.as_str().expect("category name"))
    }
}

/// A navigation destination with its displayed label.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Link {
    pub label: String,
    pub href: String,
}
impl<'de> Deserialize<'de> for Link {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Saved {
            Fields { label: String, href: String },
            Text(String),
        }
        match Saved::deserialize(deserializer)? {
            Saved::Fields { label, href } => Ok(Self { label, href }),
            Saved::Text(text) => Self::parse(&text)
                .ok_or_else(|| serde::de::Error::custom("invalid saved navigation link")),
        }
    }
}

impl Link {
    pub(super) fn parse(text: &str) -> Option<Self> {
        let (label, href) = text.split_once('|')?;
        Some(Self {
            label: label.trim().into(),
            href: href.trim().into(),
        })
    }
}

/// Site branding and layout settings shared by its pages.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Profile {
    /// Display name derived from the hostname.
    pub name: String,
    /// Site category, such as news.
    pub kind: SiteKind,
    /// Short text below the site name.
    pub tagline: String,
    /// Navigation labels and destinations.
    pub nav: Vec<Link>,
    /// Footer labels and destinations.
    pub footer: Vec<Link>,
    /// Stylesheet shared by every page on the host.
    #[serde(default)]
    pub css: String,
    /// Creation-order index used to choose layouts and server headers.
    pub style: usize,
}
/// Generated page content before layout rendering.
#[derive(Clone, Debug, Default, Serialize)]
pub struct Page {
    /// HTTP status code.
    pub status: u16,
    /// Media type and optional charset.
    pub content_type: String,
    /// Page heading and search result title.
    pub title: String,
    /// Description used in page metadata and search snippets.
    pub description: String,
    /// Publication date in year-month-day form.
    pub date: String,
    /// Claims supported by prior mentions.
    pub claims: Vec<super::prompts::Statement>,
    /// HTML fragment or complete text or JSON body.
    pub body: String,
    /// Sidebar links as label and target pairs.
    pub sidebar: Vec<(String, String)>,
    /// Advertisement text.
    pub ad: String,
    /// How the generator describes the site, for a host's first page.
    pub site: Option<Profile>,
}

/// Extracts lowercase search words, excluding common stop words.
pub fn words(s: &str) -> Vec<String> {
    static WORD: OnceLock<Regex> = OnceLock::new();
    WORD.get_or_init(|| Regex::new(r"[a-z0-9][a-z0-9\-\.]*[a-z0-9]|[a-z0-9]").unwrap())
        .find_iter(&s.to_lowercase())
        .filter(|w| !STOP.contains(&w.as_str()))
        .map(|w| w.as_str().into())
        .collect()
}
pub(super) fn shares_words(a: &str, b: &str) -> bool {
    let a = words(a);
    words(b).iter().any(|w| w != "not" && a.contains(w))
}
/// A stable number for `text`, to vary dates, counts and names by URL.
pub(super) fn hash(text: &str) -> usize {
    text.bytes()
        .fold(0usize, |n, b| n.wrapping_mul(31).wrapping_add(b as usize))
}
/// Removes branding from a result title for headings and directory links.
pub(super) fn heading(title: &str) -> &str {
    [" - ", " — ", " – ", " | ", " · ", " • ", " : r/"]
        .iter()
        .filter_map(|separator| title.split_once(separator))
        .map(|(subject, _)| subject.trim())
        .min_by_key(|subject| subject.len())
        .unwrap_or(title)
}

/// Directory and section routes have navigation content rather than articles.
pub(super) fn directory(target: &str) -> bool {
    let path = target.split('?').next().unwrap_or(target);
    path == "/"
        || (path.ends_with('/') && path.trim_matches('/').split('/').count() == 1)
        || [
            "/latest",
            "/categories",
            "/top",
            "/search",
            "/search/",
            "/results",
            "/w/index.php",
        ]
        .contains(&path)
}

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];
/// A date as result lists and bylines show it: `3 Oct 2026`.
pub fn short_date(d: time::Date) -> String {
    format!(
        "{} {} {}",
        d.day(),
        MONTHS[d.month() as usize - 1],
        d.year()
    )
}
/// A page's `YYYY-MM-DD` date as a result list shows it, or empty.
pub fn result_date(date: &str) -> String {
    parse_date(date).map(short_date).unwrap_or_default()
}
/// The known pages that share words with `query`, the most shared words
/// first; ties keep their order.
pub fn rank<'a>(known: &'a [Result], query: &str) -> Vec<&'a Result> {
    let mut asked = words(query);
    asked.sort();
    asked.dedup();
    let mut scored: Vec<(usize, &Result)> = known
        .iter()
        .map(|k| {
            let (host, _) = target_of(&k.url);
            let have = words(&format!(
                "{} {} {} {}",
                k.title,
                k.url,
                k.snippet,
                host.split('.')
                    .map(|s| s.trim_start_matches("the"))
                    .collect::<Vec<_>>()
                    .join(" ")
            ));
            (asked.iter().filter(|w| have.contains(w)).count(), k)
        })
        .filter(|(score, _)| *score > 0)
        .collect();
    scored.sort_by_key(|(score, _)| std::cmp::Reverse(*score));
    scored.into_iter().map(|(_, k)| k).collect()
}

/// Requires shared subject words, or a named site in a navigational query.
pub(super) fn relevant(result: &Result, query: &str) -> bool {
    let mut asked = words(query);
    asked.sort();
    asked.dedup();
    let have = words(&format!(
        "{} {} {}",
        result.title, result.url, result.snippet
    ));
    let score = asked.iter().filter(|w| have.contains(w)).count();
    if asked.iter().any(|w| {
        ["lisbon", "naples", "tokyo", "porto", "leeds", "dublin"].contains(&w.as_str())
            && !have.contains(w)
    }) {
        return false;
    }
    let (host, _) = target_of(&result.url);
    let named = asked.iter().any(|w| {
        w.len() > 3
            && host
                .split('.')
                .any(|label| label.trim_start_matches("the") == w)
    });
    named || (score > 0 && score >= asked.len().min(2) && score * 2 >= asked.len())
}

/// Text cut from a page as a snippet shows it: at most about 160
/// characters, ending at a word with "...".
pub fn excerpt(text: &str) -> String {
    let text = normalize_space(text);
    if text.chars().count() <= 160 {
        return if text.ends_with(['.', '!', '?']) {
            text
        } else {
            format!("{text}.")
        };
    }
    let words: Vec<&str> = text.split(' ').collect();
    let mut out = String::new();
    for word in words {
        if out.chars().count() + word.chars().count() + 5 > 160 {
            out.push_str(" ...");
            break;
        }
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(word);
    }
    if !out.ends_with(['.', '!', '?']) {
        out.push('.');
    }
    out
}

pub(super) fn finish_listing(search: &mut Search) {
    let mut urls = std::collections::HashSet::new();
    search.results.retain(|r| urls.insert(r.url.clone()));
}

/// Search only known page metadata when no model is configured.
pub fn search(query: &str, known: &[Result]) -> Search {
    Search {
        results: rank(known, query).into_iter().take(10).cloned().collect(),
        ..Default::default()
    }
}

/// Video listings drawn from the world's stored video pages.
pub fn videos<'a>(query: &str, pages: impl Iterator<Item = (&'a String, String)>) -> Search {
    use kuchiki::traits::TendrilSink;
    let mut known = Vec::new();
    for (url, html) in pages {
        let dom = kuchiki::parse_html().one(html);
        for card in dom.select("article, .video-item").unwrap() {
            let Ok(link) = card.as_node().select_first("h2 a[href], h3 a[href]") else {
                continue;
            };
            let href = link.attributes.borrow().get("href").unwrap().to_owned();
            let Some(url) = join(url, &href) else {
                continue;
            };
            let snippet = card
                .as_node()
                .select("p")
                .unwrap()
                .map(|p| p.text_contents())
                .collect::<Vec<_>>()
                .join(" • ");
            if !known.iter().any(|r: &Result| r.url == url) {
                known.push(Result {
                    url,
                    title: link.text_contents(),
                    snippet,
                    date: String::new(),
                });
            }
        }
    }
    let results = if query.is_empty() {
        known.iter().take(12).cloned().collect::<Vec<_>>()
    } else {
        rank(&known, query)
            .into_iter()
            .filter(|r| relevant(r, query))
            .take(10)
            .cloned()
            .collect::<Vec<_>>()
    };
    Search {
        results,
        ..Search::default()
    }
}

pub use super::branding::site_profile;

/// Shared layouts for each kind of site.
pub(super) fn stylesheet(kind: SiteKind) -> String {
    let base = r#"
* { box-sizing: border-box; }
body { margin: 0; color: #263345; background: #f5f6f8; font: 16px/1.65 Arial, sans-serif; }
a { color: var(--accent); text-decoration: none; } a:hover { text-decoration: underline; }
header { background: #fff; border-top: 5px solid var(--accent); border-bottom: 1px solid #d9dee5; padding: 24px max(24px, calc((100% - 1160px)/2)); }
.brand a, .logo, .home { color: inherit; font-size: 30px; font-weight: 800; letter-spacing: -1px; }
.tagline { display: block; font-size: 13px; color: inherit; }
.cookie-banner { position: fixed; bottom: 0; left: 0; right: 0; z-index: 100; display: flex; align-items: center; gap: 16px; padding: 12px 24px; background: #fff; border-top: 1px solid #bdc6d1; box-shadow: 0 -2px 12px #0002; }
body:has(.cookie-banner) { padding-bottom: 80px; }
nav ul, .nav, .footer-links, .topbar ul { list-style: none; padding: 0; display: flex; gap: 24px; flex-wrap: wrap; }
nav a, .nav a { color: inherit; font-size: 14px; font-weight: 600; }
.layout, .columns { max-width: 1160px; margin: 36px auto; display: grid; gap: 40px; grid-template-columns: minmax(0, 1fr) 260px; padding: 0 24px; }
main { min-width: 0; background: #fff; padding: 32px; }
body > main { max-width: 1000px; margin: 32px auto; }
h1 { font-size: clamp(28px, 3vw, 42px); line-height: 1.18; letter-spacing: -.7px; margin: 0 0 24px; }
h2 { font-size: 23px; margin-top: 32px; } h3 { font-size: 18px; }
p { margin: 16px 0; } .byline, .aside, .breadcrumb { color: #647085; font-size: 14px; }
.breadcrumb, .topbar { max-width: 1160px; margin: auto; padding: 12px 24px; font-size: 13px; }
.rail { border-top: 3px solid var(--accent); } .rail li { padding: 10px 0; border-bottom: 1px solid #d9dee5; }
.rail ol { padding-left: 22px; } .ad-slot, .newsletter, .promo-banner, .sponsor { background: #eaf0f4; padding: 22px; margin: 24px 0; }
.ad-label { font-size: 10px; text-transform: uppercase; letter-spacing: 2px; color: #647085; }
input, button { font: inherit; border: 1px solid #bdc6d1; border-radius: 4px; padding: 8px 12px; max-width: 100%; }
button, .btn { background: var(--accent); color: white; padding: 9px 16px; border: 0; }
footer { border-top: 1px solid #d9dee5; padding: 28px max(24px, calc((100% - 1112px)/2)); color: #647085; font-size: 13px; }
.related { max-width: 1000px; margin: 24px auto; padding: 24px; } table { border-collapse: collapse; width: 100%; font-size: 14px; }
th, td { border-bottom: 1px solid #d9dee5; text-align: left; padding: 10px 12px; } th { background: #edf1f5; }
pre { overflow-x: auto; padding: 20px; background: #edf1f5; } code { font-family: monospace; } blockquote { border-left: 3px solid var(--accent); margin-left: 0; padding-left: 20px; }
.docs header { display: flex; align-items: center; gap: 32px; } .search { margin-left: auto; }
.columns { grid-template-columns: 220px minmax(0, 1fr); } .sidebar ul { display: block; } .sidebar li { margin: 12px 0; }
.skip-link { position: absolute; left: -9999px; } .skip-link:focus { left: 16px; background: white; padding: 8px; }
@media(max-width: 760px) { .layout, .columns { grid-template-columns: minmax(0, 1fr); margin: 20px auto; gap: 20px; } header, .docs header { padding: 20px; flex-wrap: wrap; } main { padding: 24px; } nav ul { gap: 14px; } .search { margin-left: 0; } }
"#;
    let theme = match kind {
        SiteKind::Docs => {
            ":root {--accent:#3156ad} header {background:#edf1f5} main {border:1px solid #d9dee5;border-radius:6px} h1 {font-size:34px}"
        }
        SiteKind::Qa => {
            ":root {--accent:#a74320;--app-made:#237a3b;--app-rule:#d9dee5;--app-soft:#edf1f5;--accent-text:#a74320} .qa header{display:flex;align-items:center;gap:24px}.qa main{max-width:1000px;margin:20px auto;padding:24px}.qa header a{color:var(--accent-text)}.qa h1{margin-bottom:16px}.qa h2{margin:20px 0 8px}.question-meta{font-size:13px}.question-post,.answer{display:grid;grid-template-columns:56px minmax(0,1fr);gap:20px;padding:16px 0;border-bottom:1px solid var(--app-rule)}.votes{font-size:24px;text-align:center}.accepted-mark{display:block;color:var(--app-made);font-size:32px}.tags{display:flex;gap:8px}.tags span{background:var(--app-soft);padding:3px 8px;border-radius:4px}.author{font-size:13px}.answer-cards .answer{border:1px solid var(--app-rule);border-radius:8px;padding:20px;margin:20px 0}.answer-cards .question-post{display:block}.answer-cards .question-post>.votes{display:none}"
        }
        SiteKind::Forum => {
            ":root {--accent:#a74320} body {background:#f2ede8} header {border-top:0} main {border:1px solid #d8cec5;border-radius:8px} main p {padding:14px;background:#faf8f5;border-radius:5px} h1 {font-size:30px}"
        }
        SiteKind::Shop => {
            ":root {--accent:#265f4a} header {text-align:center;background:#eff5ed} header nav ul {justify-content:center} h1 {font-weight:500} main {border-radius:12px} .promo-banner {text-align:center;background:#dfeadd}"
        }
        SiteKind::Company => {
            ":root {--accent:#164d88} header {background:#edf1f5} header a {color:inherit} h1 {color:#153c63} main {border-top:4px solid var(--accent)} .topbar {text-align:right}"
        }
        SiteKind::Wiki => {
            ":root {--accent:#365c99} body {background:white;font-family:Georgia,serif} header {border-top:0} h1 {font-weight:400;border-bottom:1px solid #aeb5be;padding-bottom:14px} nav, header, footer {font-family:Arial,sans-serif} main {padding-top:0}"
        }
        SiteKind::Blog => {
            ":root {--accent:#805235} body {background:#f5f1e9} .masthead {background:#f5f1e9;border-top:0} .brand a {font-family:Georgia,serif;font-style:italic;font-size:38px} article {font-family:Georgia,serif;font-size:18px} main {background:transparent;padding-top:0} .rail {border-top:1px solid #cbbca9}"
        }
        _ => {
            ":root {--accent:#ab242b} .brand a {font-family:Georgia,serif;font-size:40px} .masthead nav {border-top:1px solid #d9dee5;margin-top:20px} h1 {font-family:Georgia,serif} .layout {border-top:1px solid #d9dee5;padding-top:28px}"
        }
    };
    format!("@layer {{\n{base}\n{theme}\n}}")
}
/// Derive a heading from a URL when no stored title exists.
pub fn title_from(host: &str, target: &str) -> String {
    let path = target
        .split('?')
        .next()
        .unwrap_or(target)
        .trim_end_matches('/');
    let part = path.rsplit('/').next().unwrap_or_default();
    if part.is_empty() {
        site_profile(host).name
    } else {
        part.replace(['-', '_'], " ")
    }
}

/// The path part of a request target, percent-decoded. A path is not form
/// data, so a literal `&` or `+` stays as it is.
fn decoded_path(target: &str) -> Cow<'_, str> {
    let path = target.split('?').next().unwrap_or(target);
    percent_encoding::percent_decode_str(path).decode_utf8_lossy()
}

pub(super) fn git_path(target: &str) -> bool {
    let decoded = decoded_path(target);
    decoded.split('/').any(|part| {
        matches!(part, "git-upload-pack" | "git-receive-pack") || part.ends_with(".git")
    }) || decoded.ends_with("/info/refs")
}

/// Rejects pasted addresses and domain names inside a page path.
pub(super) fn broken_path(target: &str) -> bool {
    static BROKEN: OnceLock<Regex> = OnceLock::new();
    let decoded = decoded_path(target);
    BROKEN
        .get_or_init(|| {
            Regex::new(r"(?i)https?:|(?:^|/)[^/]*\.(?:com|org|net|co\.uk)(?:/|$)").unwrap()
        })
        .is_match(&decoded)
}

/// Close spellings of established hosts have no address.
pub(crate) fn misspelled_host(host: &str) -> bool {
    let close = |known: &str| {
        let a = host.as_bytes();
        let b = known.as_bytes();
        if a == b || a.len().abs_diff(b.len()) > 1 {
            return false;
        }
        if a.len() == b.len() {
            return a.iter().zip(b).filter(|(x, y)| x != y).count() == 1;
        }
        let (short, long) = if a.len() < b.len() { (a, b) } else { (b, a) };
        let at = short
            .iter()
            .zip(long)
            .position(|(x, y)| x != y)
            .unwrap_or(short.len());
        short[at..] == long[at + 1..]
    };
    let known = || {
        crate::route::SEARCH_HOSTS.into_iter().chain([
            "en.wikipedia.org",
            "www.reddit.com",
            "www.theregister.com",
            "stackoverflow.com",
            "medium.com",
            "www.techradar.com",
            "github.com",
            "www.bbc.co.uk",
            "www.youtube.com",
            "www.quora.com",
            "news.ycombinator.com",
            "www.linkedin.com",
        ])
    };
    !known().any(|k| k == host) && known().any(close)
}

/// Builds directory and search pages from the pages already known on a host.
pub(super) fn page_with_known(
    seed: &Seed,
    host: &str,
    target: &str,
    mentions: &[super::Mention],
    kind: SiteKind,
    known: &[Result],
) -> Page {
    if host == "www.youtube.com" && target == "/" {
        let mut body = String::from("<h1>Recommended</h1><div class=\"video-grid\">");
        let videos: Vec<_> = known
            .iter()
            .filter(|r| r.url.contains("youtube.com/watch?"))
            .collect();
        for video in videos {
            body.push_str(&format!("<article><a href=\"{}\"><img alt=\"\" src=\"{}\"></a><h2><a href=\"{}\">{}</a></h2><p>{}</p></article>", escape(&video.url), fictionet_extras::search::video_thumbnail(&video.title), escape(&video.url), escape(heading(&video.title)), escape(&video.snippet)));
        }
        body.push_str("</div>");
        return Page {
            status: 200,
            content_type: "text/html; charset=utf-8".into(),
            title: "YouTube".into(),
            body,
            date: seed.date.clone(),
            ..Page::default()
        };
    }
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let article = form_urlencoded::parse(query.as_bytes())
        .any(|(key, value)| key == "p" && !value.is_empty());
    let query = form_urlencoded::parse(query.as_bytes())
        .find(|(k, _)| ["q", "search", "search_query", "searchTerm"].contains(&k.as_ref()))
        .map(|(_, v)| v.into_owned());
    let search = query.is_some() && directory(target);
    let directory = !article
        && directory(target)
        && mentions
            .iter()
            .all(|m| !matches!(m, super::Mention::Search { .. }));
    if !search && !directory {
        return page(host, target, mentions);
    }

    let title = if let Some(query) = &query {
        format!("Search results for {query}")
    } else if path == "/" && kind == SiteKind::Forum {
        "Latest discussions".into()
    } else if path == "/" {
        site_profile(host).name
    } else {
        title_from(host, path.trim_end_matches('/'))
    };
    let matching: Vec<_> = known
        .iter()
        .filter(|r| {
            let (h, t) = target_of(&r.url);
            h == host
                && t != target
                && (search
                    || path == "/"
                    || ["/latest", "/categories", "/top"].contains(&path)
                    || t.starts_with(path))
        })
        .cloned()
        .collect();
    let matching: Vec<_> = if let Some(query) = &query {
        rank(&matching, query)
            .into_iter()
            .filter(|r| relevant(r, query))
            .collect()
    } else {
        matching.iter().collect()
    };
    let mut body = format!("<h1>{}</h1>", escape(&title));
    for mention in mentions {
        if let Some(snippet) = mention.snippet() {
            body.push_str(&format!("<p>{}</p>", escape(snippet)));
        }
    }
    if matching.is_empty() {
        body.push_str("<p>No matching pages were found.</p>");
    } else {
        body.push_str("<ul class=\"page-list\">");
        for r in matching {
            body.push_str(&format!(
                "<li><h2><a href=\"{}\">{}</a></h2><p>{}</p></li>",
                escape(&r.url),
                escape(heading(&r.title)),
                escape(&r.snippet)
            ));
        }
        body.push_str("</ul>");
    }
    Page {
        status: 200,
        content_type: "text/html; charset=utf-8".into(),
        title,
        body,
        date: seed.date.clone(),
        ..Page::default()
    }
}

/// Preserve prior mentions without inventing page content.
pub fn page(host: &str, target: &str, mentions: &[super::Mention]) -> Page {
    let title = mentions
        .iter()
        .find_map(|m| m.title())
        .map(str::to_owned)
        .unwrap_or_else(|| title_from(host, target));
    let mut body = format!("<h1>{}</h1>", escape(&title));
    for snippet in mentions.iter().filter_map(|m| m.snippet()) {
        body.push_str(&format!("<p>{}</p>", escape(snippet)));
    }
    Page {
        status: 200,
        content_type: "text/html; charset=utf-8".into(),
        title,
        body,
        ..Default::default()
    }
}
