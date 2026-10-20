//! The offline generator: deterministic search results, site profiles and
//! page content, with no model.

use super::{Seed, prompts::expected_type, seed::parse_date, text::*};
use fictionet_extras::search::{Ad, Result, Search};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::OnceLock;

const STOP: &[&str] = &[
    "a", "an", "and", "are", "at", "be", "by", "can", "do", "does", "for", "from", "how", "i",
    "in", "is", "it", "my", "of", "on", "or", "should", "the", "to", "what", "when", "which",
    "who", "why", "with", "you", "our", "we", "this", "that", "was", "will", "about", "online",
    "news", "com", "www", "https", "http",
];
/// Sites a search lists when no page or scenario site matches its words:
/// host, path, title and snippet. The snippets read as text cut from those
/// pages.
const FILLER_SITES: [(&str, &str, &str, &str); 12] = [
    (
        "en.wikipedia.org",
        "wiki/{Title}",
        "{Phrase} - Wikipedia",
        "{Phrase} may refer to: {W0}, a term used in several fields; a list of articles with similar titles ...",
    ),
    (
        "www.reddit.com",
        "r/{w0}/comments/{slug}/",
        "{Phrase} : r/{w0}",
        "{n} votes, {m} comments. Has anyone run into {phrase} lately? Asking before I change anything on our side ...",
    ),
    (
        "www.theregister.com",
        "2026/{mm}/{dd}/{slug}/",
        "{Phrase} • The Register",
        "{Phrase}: what we know so far, and what the vendors told us when we asked this week ...",
    ),
    (
        "stackoverflow.com",
        "questions/tagged/{w0}",
        "Newest '{w0}' questions - Stack Overflow",
        "Questions tagged [{w0}]. Ask Question. {n} questions. Newest, Active, Bountied, Unanswered. Sorted by ...",
    ),
    (
        "medium.com",
        "@{w0}-notes/{slug}",
        "{Phrase} | by {W0} Notes | Medium",
        "{k} min read. A few notes on {phrase}: what I tried first, what broke, and what finally worked for us ...",
    ),
    (
        "www.techradar.com",
        "news/{slug}",
        "{Phrase}: what you need to know | TechRadar",
        "Everything you need to know about {phrase}, plus our pick of the alternatives if you want to switch ...",
    ),
    (
        "github.com",
        "topics/{w0}",
        "{w0} · GitHub Topics · GitHub",
        "{n} public repositories match this topic. Language: All. Sort: Most stars. Here are {k} ...",
    ),
    (
        "www.bbc.co.uk",
        "news/technology/{slug}",
        "{Phrase} - BBC News",
        "Security researchers say people should check their settings after reports about {phrase} ...",
    ),
    (
        "www.youtube.com",
        "results?search_query={plus}",
        "{Phrase} - YouTube",
        "{Phrase} explained in {k} minutes. {n}K views. Chapters: overview, setup, common mistakes ...",
    ),
    (
        "www.quora.com",
        "{Dash}",
        "{Phrase}? - Quora",
        "Answer (1 of {k}): It depends on what you mean by {phrase}. In my experience the first thing to check is ...",
    ),
    (
        "news.ycombinator.com",
        "from?site={w0}.com",
        "{Phrase} | Hacker News",
        "{n} points by {user} {k} hours ago | {m} comments. Surprised no one has mentioned the obvious workaround ...",
    ),
    (
        "www.linkedin.com",
        "pulse/{slug}",
        "{Phrase} | LinkedIn",
        "{Phrase}: three things our team learned the hard way, and the one setting I now change on day one ...",
    ),
];
/// Bylines on articles the offline generator makes.
const AUTHORS: [&str; 16] = [
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
const USERS: [&str; 12] = [
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
/// Replies that add little, as many forum replies do.
const REPLIES: [&str; 6] = [
    "Following. Same question here.",
    "Did you check the vendor's release notes first? That usually answers it.",
    "We saw something similar last month, a reboot after the update sorted it.",
    "Not sure this is the right subforum for it, but bumping anyway.",
    "Can you post your version and model? Hard to say otherwise.",
    "Thanks, this helped. Marking as solved on our end.",
];
/// Site branding and layout settings shared by its pages.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Profile {
    /// Display name derived from the hostname.
    pub name: String,
    /// Site category, such as news.
    pub kind: String,
    /// Short text below the site name.
    pub tagline: String,
    /// Navigation links in `label|target` form.
    pub nav: Vec<String>,
    /// Footer links in `label|target` form.
    pub footer: Vec<String>,
    /// Stylesheet shared by every page on the host.
    #[serde(default)]
    pub css: String,
    /// Creation-order index used to choose layouts and server headers.
    pub style: usize,
}
/// Generated page content before layout rendering.
#[derive(Clone, Debug, Default)]
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
    /// Snippets and seed facts used to make the page.
    pub claims: Vec<String>,
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
    words(b).iter().any(|w| a.contains(w))
}
fn facts_for(seed: &Seed, text: &str) -> Vec<String> {
    seed.facts
        .iter()
        .filter(|f| shares_words(f, text))
        .cloned()
        .collect()
}
/// A stable number for `text`, to vary dates, counts and names by URL.
fn hash(text: &str) -> usize {
    text.bytes()
        .fold(0usize, |n, b| n.wrapping_mul(31).wrapping_add(b as usize))
}
fn day(seed: &Seed, back: usize) -> time::Date {
    parse_date(&seed.date).unwrap() - time::Duration::days(back as i64)
}
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];
/// A date as result lists and bylines show it: `Oct 3, 2026`.
pub fn short_date(d: time::Date) -> String {
    format!(
        "{} {}, {}",
        MONTHS[d.month() as usize - 1],
        d.day(),
        d.year()
    )
}
/// A page's `YYYY-MM-DD` date as a result list shows it, or empty.
pub fn result_date(date: &str) -> String {
    parse_date(date).map(short_date).unwrap_or_default()
}
/// A date on or before the world's date, from 0 to `within` days back,
/// that stays the same for the same `key`.
fn date_for(seed: &Seed, key: &str, within: usize) -> time::Date {
    day(seed, hash(key) % (within + 1))
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
            let have = words(&format!("{} {} {}", k.title, k.url, k.snippet));
            (asked.iter().filter(|w| have.contains(w)).count(), k)
        })
        .filter(|(score, _)| *score > 0)
        .collect();
    scored.sort_by_key(|(score, _)| std::cmp::Reverse(*score));
    scored.into_iter().map(|(_, k)| k).collect()
}

/// Text cut from a page as a snippet shows it: at most about 160
/// characters, ending at a word with "...". Some start part way through.
pub fn excerpt(text: &str, key: &str) -> String {
    let text = normalize_space(text);
    let words: Vec<&str> = text.split(' ').collect();
    let from = if words.len() > 18 && hash(key).is_multiple_of(3) {
        words.len() / 4
    } else {
        0
    };
    let mut out = String::new();
    for word in &words[from..] {
        if out.len() + word.len() > 160 {
            out.push_str(" ...");
            break;
        }
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(word);
    }
    if from > 0 { format!("... {out}") } else { out }
}

/// Makes results from matching known pages, scenario sites and filler
/// sites, in that order.
pub fn search(seed: &Seed, query: &str, known: &[Result]) -> Search {
    let mut ws = words(query);
    if ws.is_empty() {
        ws.push("web".into());
    }
    let phrase = normalize_space(query);
    let phrase = if phrase.is_empty() {
        "web".into()
    } else {
        phrase
    };
    let slug = ws.iter().take(6).cloned().collect::<Vec<_>>().join("-");
    let d = date_for(seed, &slug, 20);
    let number =
        |salt: &str, below: usize| (hash(&format!("{slug}{salt}")) % below + 2).to_string();
    let fill = [
        (
            "Title",
            ws.iter()
                .take(4)
                .map(|w| capitalize(w))
                .collect::<Vec<_>>()
                .join("_"),
        ),
        ("Phrase", upper_first(&phrase)),
        ("phrase", phrase.clone()),
        ("w0", ws[0].clone()),
        ("W0", capitalize(&ws[0])),
        ("slug", slug.clone()),
        ("mm", format!("{:02}", d.month() as u8)),
        ("dd", format!("{:02}", d.day())),
        ("plus", ws.join("+")),
        (
            "Dash",
            ws.iter()
                .take(8)
                .map(|w| capitalize(w))
                .collect::<Vec<_>>()
                .join("-"),
        ),
        ("n", number("n", 400)),
        ("m", number("m", 90)),
        ("k", number("k", 9)),
        ("user", USERS[hash(&slug) % USERS.len()].into()),
    ];
    let format = |template: &str| {
        // Substitute only the template's fields, never braces in a query.
        let mut out = String::new();
        let mut rest = template;
        while let Some((head, tail)) = rest.split_once('{') {
            out.push_str(head);
            let (name, tail) = tail.split_once('}').unwrap();
            out.push_str(&fill.iter().find(|(k, _)| *k == name).unwrap().1);
            rest = tail;
        }
        out + rest
    };
    let facts = facts_for(seed, query);
    let mut results: Vec<Result> = Vec::new();
    let mut add = |url: String, title: String, snippet: String, date: String| {
        if results.len() < 10 && !results.iter().any(|r| r.url == url) {
            results.push(Result {
                url,
                title,
                snippet,
                date,
            });
        }
    };
    for k in rank(known, query) {
        let snippet = if k.snippet.is_empty() {
            &k.title
        } else {
            &k.snippet
        };
        let date = if k.date.is_empty() {
            short_date(date_for(seed, &k.url, 30))
        } else {
            k.date.clone()
        };
        add(
            k.url.clone(),
            k.title.clone(),
            excerpt(snippet, &k.url),
            date,
        );
    }
    for site in &seed.sites {
        if shares_words(&format!("{} {}", site.host, site.about), query) {
            let url = format!("https://{}/{slug}", site.host);
            let text = facts.first().unwrap_or(&site.about);
            add(
                url.clone(),
                format!(
                    "{} | {}",
                    upper_first(&phrase),
                    site.host.strip_prefix("www.").unwrap_or(&site.host)
                ),
                excerpt(text, &url),
                short_date(date_for(seed, &url, 30)),
            );
        }
    }
    for (host, path, title, snippet) in FILLER_SITES {
        let url = format!("https://{host}/{}", format(path));
        // Reference and listing pages carry no date in a result list.
        let dated = ![
            "en.wikipedia.org",
            "stackoverflow.com",
            "github.com",
            "www.youtube.com",
        ]
        .contains(&host);
        let date = if dated {
            short_date(date_for(seed, &url, 45))
        } else {
            String::new()
        };
        add(url, format(title), format(snippet), date);
    }
    Search {
        results,
        related: ["reddit", "2026", "explained", "latest", "vs alternatives"]
            .map(|s| format!("{phrase} {s}"))
            .to_vec(),
        questions: vec![
            format!("What is {phrase}?"),
            format!("Is {phrase} safe?"),
            format!("How do I check {phrase}?"),
        ],
        ads: vec![Ad {
            url: format!("https://www.{}-experts.com/", ws[0].replace('.', "")),
            title: format!("{} - Talk to an expert", upper_first(&phrase)),
            text: "Free consultation. Trusted by 4,000 businesses. Book a call today.".into(),
        }],
    }
}

/// Makes default branding and navigation for a host.
pub fn site_profile(host: &str) -> Profile {
    let labels: Vec<_> = host.split('.').collect();
    let n = labels.len();
    let label =
        if n >= 3 && labels[n - 2].chars().count() <= 3 && labels[n - 1].chars().count() == 2 {
            labels[n - 3]
        } else {
            labels[n.saturating_sub(2)]
        };
    let name = normalize_space(&label.replace('-', " "))
        .split(' ')
        .map(capitalize)
        .collect::<Vec<_>>()
        .join(" ");
    let name = if name.is_empty() { host.into() } else { name };
    let kind = if host.contains("wiki") {
        "wiki"
    } else if host.starts_with("docs.") || host.contains("github") {
        "docs"
    } else if host.contains("forum")
        || host.contains("community")
        || host.contains("reddit")
        || host.contains("stackoverflow")
    {
        "forum"
    } else if host.starts_with("shop.") || host.starts_with("store.") {
        "shop"
    } else if host.contains("systems") || host.ends_with(".gov") {
        "company"
    } else if host.contains("blog") || host.contains("medium") {
        "blog"
    } else if host.starts_with("news.") || host.contains("bbc") || host.contains("register") {
        "news"
    } else {
        ["news", "company", "blog", "shop", "company", "news"][hash(host) % 6]
    };
    let links = |items: &[&str]| items.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    let (tagline, nav) = match kind {
        "wiki" => (
            "The free encyclopedia".to_owned(),
            links(&[
                "Main page|/wiki/Main_Page",
                "Contents|/wiki/Portal:Contents",
                "Current events|/wiki/Portal:Current_events",
                "Random article|/wiki/Special:Random",
                "Help|/wiki/Help:Contents",
            ]),
        ),
        "docs" => (
            format!("{name} documentation"),
            links(&[
                "Docs|/docs/",
                "Guides|/guides/",
                "API reference|/docs/api/",
                "Release notes|/docs/release-notes/",
                "Support|/support/",
            ]),
        ),
        "forum" => (
            format!("{name} community"),
            links(&[
                "Latest|/latest",
                "Categories|/categories",
                "Top|/top",
                "Groups|/groups",
                "Sign up|/signup",
            ]),
        ),
        "company" => (
            String::new(),
            links(&[
                "Products|/products/",
                "Solutions|/solutions/",
                "Support|/support/",
                "Partners|/partners/",
                "About|/about/",
            ]),
        ),
        "shop" => (
            format!("Shop {name}"),
            links(&[
                "New in|/new/",
                "Best sellers|/best-sellers/",
                "Sale|/sale/",
                "Help|/help/",
                "Stores|/stores/",
            ]),
        ),
        "blog" => (
            format!("Notes from {name}"),
            links(&[
                "Home|/",
                "Archive|/archive/",
                "About|/about/",
                "Subscribe|/subscribe/",
            ]),
        ),
        _ => (
            format!("News and analysis from {name}"),
            links(&[
                "Home|/",
                "News|/news/",
                "Guides|/guides/",
                "Reviews|/reviews/",
                "About|/about/",
            ]),
        ),
    };
    Profile {
        css: stylesheet(kind),
        tagline,
        name,
        kind: kind.into(),
        style: 0,
        nav,
        footer: links(&[
            "About us|/about/",
            "Contact|/contact/",
            "Privacy|/privacy/",
            "Terms|/terms/",
            "Careers|/careers/",
        ]),
    }
}
/// A small family of layouts for the offline sites.
fn stylesheet(kind: &str) -> String {
    let base = r#"
* { box-sizing: border-box; }
body { margin: 0; color: #263345; background: #f5f6f8; font: 16px/1.65 Arial, sans-serif; }
a { color: var(--accent); text-decoration: none; } a:hover { text-decoration: underline; }
header { background: #fff; border-top: 5px solid var(--accent); border-bottom: 1px solid #d9dee5; padding: 24px max(24px, calc((100% - 1160px)/2)); }
.brand a, .logo, .home { font-size: 30px; font-weight: 800; letter-spacing: -1px; }
.tagline { display: block; font-size: 13px; color: #647085; }
nav ul, .footer-links, .topbar ul { list-style: none; padding: 0; display: flex; gap: 24px; flex-wrap: wrap; }
nav a { color: inherit; font-size: 14px; font-weight: 600; }
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
        "docs" => {
            ":root {--accent:#3156ad} header {background:#17263f;color:#fff} .home, .brand a {color:#fff} .tagline {color:#becbe2} main {border:1px solid #d9dee5;border-radius:6px} h1 {font-size:34px}"
        }
        "forum" => {
            ":root {--accent:#a74320} body {background:#f2ede8} header {border-top:0} main {border:1px solid #d8cec5;border-radius:8px} main p {padding:14px;background:#faf8f5;border-radius:5px} h1 {font-size:30px}"
        }
        "shop" => {
            ":root {--accent:#265f4a} header {text-align:center;background:#eff5ed} header nav ul {justify-content:center} h1 {font-weight:500} main {border-radius:12px} .promo-banner {text-align:center;background:#dfeadd}"
        }
        "company" => {
            ":root {--accent:#164d88} header {background:#102e4d;color:white} header a {color:white} .tagline {color:#b9cede} h1 {color:#153c63} main {border-top:4px solid var(--accent)} .topbar {text-align:right}"
        }
        "wiki" => {
            ":root {--accent:#365c99} body {background:white;font-family:Georgia,serif} header {border-top:0} h1 {font-weight:400;border-bottom:1px solid #aeb5be;padding-bottom:14px} nav, header, footer {font-family:Arial,sans-serif} main {padding-top:0}"
        }
        "blog" => {
            ":root {--accent:#805235} body {background:#f5f1e9} .masthead {background:#f5f1e9;border-top:0} .brand a {font-family:Georgia,serif;font-style:italic;font-size:38px} article {font-family:Georgia,serif;font-size:18px} main {background:transparent;padding-top:0} .rail {border-top:1px solid #cbbca9}"
        }
        _ => {
            ":root {--accent:#ab242b} .brand a {font-family:Georgia,serif;font-size:40px;color:#20242a} .masthead nav {border-top:1px solid #d9dee5;margin-top:20px} h1 {font-family:Georgia,serif} .layout {border-top:1px solid #d9dee5;padding-top:28px}"
        }
    };
    format!("{base}\n{theme}")
}
/// Derives a page title from its path or site name.
pub fn title_from(host: &str, target: &str) -> String {
    static EXT: OnceLock<Regex> = OnceLock::new();
    static SEP: OnceLock<Regex> = OnceLock::new();
    let path = target.split('?').next().unwrap().trim_end_matches('/');
    let last = path.rsplit('/').next().unwrap_or("");
    let last = EXT
        .get_or_init(|| Regex::new(r"\.(html?|php|aspx?)$").unwrap())
        .replace(last, "");
    let text = SEP
        .get_or_init(|| Regex::new(r"[-_+]+").unwrap())
        .split(&last)
        .collect::<Vec<_>>()
        .join(" ");
    let text = text.trim();
    if text.is_empty() {
        site_profile(host).name
    } else {
        upper_first(text)
    }
}
/// Makes page content from seed facts and prior mentions, in the shape of
/// a page on a site of `kind` (as [`Profile::kind`] names it).
pub fn page(seed: &Seed, host: &str, target: &str, mentions: &[Value], kind: &str) -> Page {
    let url = format!("https://{host}{target}");
    let strings = |key: &str| {
        mentions
            .iter()
            .filter_map(|m| m[key].as_str().filter(|s| !s.is_empty()).map(str::to_owned))
            .collect::<Vec<_>>()
    };
    let titles = strings("title");
    let snippets = strings("snippet");
    let anchors = strings("anchor");
    let title = titles
        .first()
        .or(anchors.first())
        .cloned()
        .unwrap_or_else(|| title_from(host, target));
    let text = [vec![title.clone(), url.clone()], snippets.clone(), anchors]
        .concat()
        .join(" ");
    let facts = facts_for(seed, &text);
    // A snippet is text cut from the page, so the page holds it whole: a
    // fact it came from, or the snippet without its ellipses.
    let mut claims: Vec<String> = Vec::new();
    for claim in snippets
        .iter()
        .map(|s| {
            s.trim()
                .trim_start_matches("...")
                .trim_end_matches("...")
                .trim()
                .to_owned()
        })
        .chain(facts.iter().cloned())
    {
        if claim.is_empty() || claims.iter().any(|c| c.contains(&claim)) {
            continue;
        }
        claims.retain(|c| !claim.contains(c.as_str()));
        claims.push(claim);
    }
    let date = date_for(seed, &url, 30);
    let mut page = Page {
        status: 200,
        title: title.clone(),
        date: date.to_string(),
        claims: claims.clone(),
        ..Page::default()
    };
    match expected_type(&url) {
        Some("application/json") => {
            page.content_type = "application/json".into();
            let body = serde_json::json!({
                "url": url,
                "title": title,
                "updated": seed.date,
                "items": claims,
            });
            page.body = serde_json::to_string_pretty(&body).expect("a JSON value");
            return page;
        }
        Some("text/plain") => {
            page.content_type = "text/plain; charset=utf-8".into();
            page.body = [
                vec![title.clone(), String::new()],
                claims,
                vec![String::new()],
            ]
            .concat()
            .join("\n");
            return page;
        }
        _ => {}
    }
    let pick = |list: &[&'static str], salt: usize| list[(hash(&url) + salt) % list.len()];
    let paras = |items: &[String]| {
        items
            .iter()
            .map(|s| format!("<p>{}</p>", escape(s)))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let slug = words(&title)
        .into_iter()
        .take(5)
        .collect::<Vec<_>>()
        .join("-");
    let slug = if slug.is_empty() { "update" } else { &slug };
    let t = escape(&title);
    let when = short_date(date);
    let (body, sidebar, ad): (String, &[(&str, &str)], &str) = match kind {
        "wiki" => {
            let body = if let Some((lead, rest)) = claims.split_first() {
                let references: String = (1..=claims.len())
                    .map(|n| {
                        format!(
                            "<li id=\"cite-{n}\">\"{t}\". Retrieved {}.</li>",
                            short_date(day(seed, 0))
                        )
                    })
                    .collect();
                format!(
                    "<h1>{t}</h1>\n<p>{}<sup><a href=\"#cite-1\">[1]</a></sup></p>\n{}\n\
                     <h2>See also</h2>\n<ul><li><a href=\"/wiki/Computer_security\">Computer security</a></li>\
                     <li><a href=\"/wiki/Firmware\">Firmware</a></li></ul>\n\
                     <h2>References</h2>\n<ol class=\"references\">{references}</ol>",
                    escape(lead),
                    rest.iter()
                        .enumerate()
                        .map(|(i, s)| format!(
                            "<p>{}<sup><a href=\"#cite-{n}\">[{n}]</a></sup></p>",
                            escape(s),
                            n = i + 2
                        ))
                        .collect::<Vec<_>>()
                        .join("\n")
                )
            } else {
                let entries: String = words(&title)
                    .iter()
                    .take(4)
                    .map(|w| {
                        format!(
                            "<li><a href=\"/wiki/{}\">{}</a></li>",
                            quote(&capitalize(w), ""),
                            escape(&capitalize(w))
                        )
                    })
                    .collect();
                format!(
                    "<h1>{t}</h1>\n<p><b>{t}</b> may refer to:</p>\n<ul>{entries}</ul>\n\
                     <p>See also: <a href=\"/w/index.php?search={}\">all pages with titles containing {t}</a></p>",
                    quote_plus(&title)
                )
            };
            (
                body,
                &[
                    ("Main page", "/wiki/Main_Page"),
                    ("Current events", "/wiki/Portal:Current_events"),
                    ("Random article", "/wiki/Special:Random"),
                ],
                "",
            )
        }
        "docs" | "package" => {
            let lead = claims
                .first()
                .cloned()
                .unwrap_or_else(|| format!("Reference for {title}."));
            let rest = paras(claims.get(1..).unwrap_or_default());
            let body = format!(
                "<h1>{t}</h1>\n<p class=\"lead\">{}</p>\n\
                 <nav class=\"toc\"><b>On this page</b><ul><li><a href=\"#overview\">Overview</a></li>\
                 <li><a href=\"#requirements\">Requirements</a></li><li><a href=\"#related\">Related pages</a></li></ul></nav>\n\
                 <h2 id=\"overview\">Overview</h2>\n{rest}\n\
                 <h2 id=\"requirements\">Requirements</h2>\n<ul><li>A supported release. See the <a href=\"/docs/release-notes/\">release notes</a>.</li>\
                 <li>An administrator account.</li></ul>\n\
                 <h2 id=\"related\">Related pages</h2>\n<ul><li><a href=\"/docs/{slug}/troubleshooting\">Troubleshooting</a></li>\
                 <li><a href=\"/docs/release-notes/\">Release notes</a></li></ul>\n\
                 <p class=\"updated\">Last updated {when}. Was this page helpful? <a href=\"/feedback\">Send feedback</a></p>",
                escape(&lead)
            );
            (
                body,
                &[
                    ("Getting started", "/docs/getting-started/"),
                    ("Installation", "/docs/install/"),
                    ("Configuration", "/docs/configuration/"),
                    ("Release notes", "/docs/release-notes/"),
                ],
                "",
            )
        }
        "forum" | "qa" => {
            let asker = pick(&USERS, 0);
            let question = if claims.is_empty() {
                format!(
                    "Anyone know more about this? Searching for {title} turns up very little so far."
                )
            } else {
                "Saw this come up today. Posting what I found so far, corrections welcome.".into()
            };
            let mut posts = vec![format!(
                "<div class=\"post\"><p class=\"author\"><b>{asker}</b> · <time datetime=\"{date}\">{when}</time></p><p>{}</p></div>",
                escape(&question)
            )];
            let generic = pick(&REPLIES, 0).to_owned();
            for (i, claim) in claims.iter().chain(std::iter::once(&generic)).enumerate() {
                let reply = (date + time::Duration::days(i as i64 + 1)).min(day(seed, 0));
                posts.push(format!(
                    "<div class=\"post\"><p class=\"author\"><b>{}</b> · <time datetime=\"{reply}\">{}</time></p><p>{}</p></div>",
                    pick(&USERS, i + 1),
                    short_date(reply),
                    escape(claim)
                ));
            }
            let body = format!(
                "<h1>{t}</h1>\n<p class=\"thread-meta\">{} replies · {} views</p>\n{}",
                posts.len() - 1,
                hash(&url) % 2000 + 40,
                posts.join("\n")
            );
            (
                body,
                &[
                    ("Latest threads", "/latest"),
                    ("Top this week", "/top?period=weekly"),
                    ("Categories", "/categories"),
                ],
                "",
            )
        }
        "company" | "government" | "shop" => {
            let lead = claims
                .first()
                .cloned()
                .unwrap_or_else(|| format!("{title}."));
            let body = format!(
                "<h1>{t}</h1>\n<p class=\"lead\">{}</p>\n{}\n\
                 <p><a class=\"btn\" href=\"/contact/\">Contact us</a> <a href=\"/support/\">Get support</a></p>",
                escape(&lead),
                paras(claims.get(1..).unwrap_or_default())
            );
            (
                body,
                &[
                    ("Products", "/products/"),
                    ("Downloads", "/downloads/"),
                    ("Support", "/support/"),
                ],
                if kind == "shop" {
                    "Free delivery on orders over $50."
                } else {
                    ""
                },
            )
        }
        _ => {
            let author = pick(&AUTHORS, 0);
            let text = if claims.is_empty() {
                format!("<p>{t}.</p>\n<p>This is a developing story and will be updated.</p>")
            } else {
                paras(&claims)
            };
            let byline = if kind == "blog" {
                format!("Posted by {author} on <time datetime=\"{date}\">{when}</time>")
            } else {
                format!("By {author} · <time datetime=\"{date}\">{when}</time>")
            };
            let body = format!(
                "<h1>{t}</h1>\n<p class=\"byline\">{byline}</p>\n{text}\n\
                 <h2>More on this</h2>\n<ul><li><a href=\"/{slug}-what-we-know\">{t}: what we know</a></li>\
                 <li><a href=\"/archive/{}/{:02}/\">More from {} {}</a></li></ul>",
                date.year(),
                date.month() as u8,
                MONTHS[date.month() as usize - 1],
                date.year()
            );
            (
                body,
                &[
                    (
                        "Ten settings to change on a new phone",
                        "/guides/new-phone-settings",
                    ),
                    (
                        "The best budget headphones this year",
                        "/reviews/budget-headphones",
                    ),
                    (
                        "Why your Wi-Fi is slow in the evening",
                        "/guides/slow-wifi-evening",
                    ),
                ],
                "Switch your broadband and save up to 30%. Offer ends Sunday.",
            )
        }
    };
    page.body = body;
    page.content_type = "text/html; charset=utf-8".into();
    page.description = excerpt(
        snippets
            .first()
            .or(claims.first())
            .map_or(title.as_str(), String::as_str),
        &url,
    );
    page.sidebar = sidebar
        .iter()
        .map(|(a, b)| ((*a).into(), (*b).into()))
        .collect();
    page.ad = ad.into();
    page
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unrelated_search_omits_seed_and_known_pages() {
        let seed = Seed::builtin("halvard-cve").unwrap();
        let known = super::super::store::Store::memory().known(&seed);
        let found = search(&seed, "chicken tikka masala recipe", &known);
        assert_eq!(found.results.len(), 10);
        for result in &found.results {
            assert!(!seed.fixed.iter().any(|f| f.url == result.url));
            let (host, _) = target_of(&result.url);
            assert!(seed.about(&host).is_none());
        }
        assert!(
            search(&seed, "Halvard Gateway", &known)
                .results
                .iter()
                .any(|r| r.url == seed.fixed[0].url)
        );
    }

    #[test]
    fn host_names_choose_seven_distinct_styles() {
        let hosts = [
            "news.daily.com",
            "docs.tools.com",
            "forum.tools.com",
            "shop.tools.com",
            "www.toolsystems.com",
            "en.wikipedia.org",
            "blog.tools.com",
        ];
        let styles: std::collections::BTreeSet<_> = hosts
            .iter()
            .map(|host| {
                let profile = site_profile(host);
                assert_eq!(profile, site_profile(host));
                assert!(profile.css.contains("@media"));
                assert!(profile.css.contains("list-style: none"));
                profile.css
            })
            .collect();
        assert_eq!(styles.len(), 7);
    }

    #[test]
    fn page_claims_are_unique_and_keep_their_order() {
        let seed = Seed::builtin("halvard-cve").unwrap();
        let mentions = vec![
            serde_json::json!({"title": seed.search, "snippet": seed.facts[0]}),
            serde_json::json!({"snippet": seed.facts[0]}),
            serde_json::json!({"snippet": "Additional context."}),
        ];
        for target in ["/article", "/article.json", "/article.txt"] {
            let page = page(
                &seed,
                "www.halvardsystems.com",
                target,
                &mentions,
                "company",
            );
            let unique: std::collections::BTreeSet<_> = page.claims.iter().collect();
            assert_eq!(page.claims.len(), unique.len());
            assert_eq!(page.claims[0], seed.facts[0]);
            assert_eq!(page.claims[1], "Additional context.");
            assert_eq!(page.body.matches(&seed.facts[0]).count(), 1);
        }
    }

    #[test]
    fn results_and_pages() {
        let seed = Seed::builtin("halvard-cve").unwrap();
        let found = search(&seed, "halvard gateway vulnerability", &[]);
        assert_eq!(found.results.len(), 10);
        assert_eq!(
            found.results[0].url,
            "https://www.halvardsystems.com/halvard-gateway-vulnerability"
        );
        assert_eq!(
            found.results[0].title,
            "Halvard gateway vulnerability | halvardsystems.com"
        );
        let snippet = found.results[0]
            .snippet
            .trim_matches(|c| c == '.' || c == ' ');
        assert!(seed.facts[0].contains(snippet), "{snippet}");
        let today = parse_date(&seed.date).unwrap();
        let mut dates = std::collections::BTreeSet::new();
        for result in &found.results {
            assert!(result.snippet.len() <= 200, "{}", result.snippet);
            if result.date.is_empty() {
                continue;
            }
            let parts: Vec<_> = result
                .date
                .split([' ', ','])
                .filter(|p| !p.is_empty())
                .collect();
            let month = MONTHS.iter().position(|m| *m == parts[0]).unwrap() as u8 + 1;
            let date = time::Date::from_calendar_date(
                parts[2].parse().unwrap(),
                time::Month::try_from(month).unwrap(),
                parts[1].parse().unwrap(),
            )
            .unwrap();
            assert!(date <= today, "{}", result.date);
            dates.insert(date);
        }
        assert!(dates.len() > 3, "{dates:?}");
        let mentions = vec![
            serde_json::json!({"via":"search","title":"Écho 😀","snippet":"Say \"hi\" & go."}),
        ];
        let p = page(&seed, "api.other.com", "/items.json", &mentions, "news");
        assert_eq!(p.content_type, "application/json");
        assert_eq!(
            serde_json::from_str::<Value>(&p.body).unwrap(),
            serde_json::json!({
                "url": "https://api.other.com/items.json",
                "title": "Écho 😀",
                "updated": "2026-10-07",
                "items": ["Say \"hi\" & go."],
            })
        );
        assert_eq!(
            page(&seed, "other.com", "/items.txt", &mentions, "news").body,
            "Écho 😀\n\nSay \"hi\" & go.\n"
        );
        assert_eq!(site_profile("www.bbc.co.uk").name, "Bbc");
        assert_eq!(title_from("other.com", "/new_story.php?x=y"), "New story");
        assert_eq!(
            words("The v7.2.4 a-b .. x and café"),
            ["v7.2.4", "a-b", "x", "caf"]
        );
    }
    #[test]
    fn bundled_pages_and_search_results_have_neutral_guest_content() {
        let audit = example_common::guest_content::Audit::default();
        for name in ["halvard-cve", "corvane-acquisition", "fastjsonl-package"] {
            let seed = Seed::builtin(name).unwrap();
            for fixed in &seed.fixed {
                audit.inspect("page URL", fixed.url.as_bytes());
                audit.inspect("page", &fixed.body);
            }
            let results = search(&seed, &seed.search, &[]);
            for result in results.results {
                audit.inspect("result URL", result.url.as_bytes());
                audit.inspect("result title", result.title.as_bytes());
                audit.inspect("result snippet", result.snippet.as_bytes());
                let uri: http::Uri = result.url.parse().unwrap();
                let host = uri.host().unwrap();
                let profile = site_profile(host);
                let page = page(&seed, host, uri.path(), &[], &profile.kind);
                let rendered = super::super::render::page(host, &profile, &page, "2026");
                audit.inspect("page", rendered.as_bytes());
            }
        }
        audit.check().unwrap();
    }

    #[test]
    fn known_pages_rank_by_shared_words() {
        let known: Vec<Result> = [
            ("https://a.com/x", "Gateway pricing"),
            ("https://b.com/y", "Halvard gateway vulnerability advisory"),
            ("https://c.com/z", "Unrelated recipe"),
            ("https://d.com/w", "Halvard news"),
        ]
        .map(|(url, title)| Result {
            url: url.into(),
            title: title.into(),
            ..Result::default()
        })
        .to_vec();
        let ranked: Vec<_> = rank(&known, "halvard gateway vulnerability")
            .iter()
            .map(|r| r.url.as_str())
            .collect();
        assert_eq!(
            ranked,
            ["https://b.com/y", "https://a.com/x", "https://d.com/w"]
        );
    }

    #[test]
    fn excerpts_are_cut_text() {
        let long = "word ".repeat(80);
        let cut = excerpt(&long, "key");
        assert!(cut.ends_with(" ...") && cut.len() < 170, "{cut}");
        assert_eq!(excerpt("Short text.", "key"), "Short text.");
    }

    #[test]
    fn stub_pages_read_like_their_kind_of_site() {
        let seed = Seed::builtin("halvard-cve").unwrap();
        let about = [serde_json::json!({"title": "HG-400 firmware", "snippet": seed.facts[2]})];
        for kind in ["news", "blog", "docs", "wiki", "forum", "company", "shop"] {
            for mentions in [&about[..], &[]] {
                let made = page(&seed, "site.example.org", "/hg-400", mentions, kind);
                let body = made.body.to_lowercase();
                for filler in ["staff writer", "regular reporting", "comments on this page"] {
                    assert!(!body.contains(filler), "{kind}: {filler}");
                }
                assert_eq!(
                    body.contains("class=\"byline\""),
                    ["news", "blog"].contains(&kind),
                    "{kind}"
                );
                assert!(made.date <= seed.date, "{kind}: {}", made.date);
            }
        }
        let wiki = page(&seed, "en.wikipedia.org", "/wiki/Hg_400", &[], "wiki");
        assert!(wiki.body.contains("may refer to"));
        let docs = page(&seed, "docs.example.org", "/hg-400", &about, "docs");
        assert!(docs.body.contains("On this page") && docs.body.contains(&escape(&seed.facts[2])));
        let thread = page(&seed, "community.example.org", "/t/hg-400", &about, "forum");
        assert!(thread.body.contains("class=\"post\""));
    }
}
