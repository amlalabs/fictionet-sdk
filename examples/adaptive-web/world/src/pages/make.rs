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
const CLUTTER: [&str; 8] = [
    "Comments on this page are moderated. Please keep discussion on topic and respectful.",
    "Updated with a correction to the second paragraph after publication.",
    "This article is part of our weekly roundup. Last week's roundup covered cloud price changes and a new browser release.",
    "Our team reviews hundreds of products a year. We may earn a commission from links on this page.",
    "Sign up to our newsletter for a short summary every Tuesday morning.",
    "Elsewhere this week: a major airline's booking site was down for three hours, and two retailers changed their returns policies.",
    "Reader question of the week: is it worth upgrading a five-year-old laptop? Our answer is in the archive.",
    "Photo: file image. Some details in this story were first reported by a partner publication.",
];
const FILLER_SITES: [(&str, &str, &str); 12] = [
    ("en.wikipedia.org", "wiki/{Title}", "{Phrase} - Wikipedia"),
    (
        "www.reddit.com",
        "r/{w0}/comments/{slug}/",
        "{Phrase} : r/{w0}",
    ),
    (
        "www.theregister.com",
        "2026/{mm}/{dd}/{slug}/",
        "{Phrase} • The Register",
    ),
    (
        "stackoverflow.com",
        "questions/tagged/{w0}",
        "Newest '{w0}' questions - Stack Overflow",
    ),
    (
        "medium.com",
        "@{w0}-notes/{slug}",
        "{Phrase} | by {W0} Notes | Medium",
    ),
    (
        "www.techradar.com",
        "news/{slug}",
        "{Phrase}: what you need to know | TechRadar",
    ),
    ("github.com", "topics/{w0}", "{w0} · GitHub Topics · GitHub"),
    (
        "www.bbc.co.uk",
        "news/technology/{slug}",
        "{Phrase} - BBC News",
    ),
    (
        "www.youtube.com",
        "results?search_query={plus}",
        "{Phrase} - YouTube",
    ),
    ("www.quora.com", "{Dash}", "{Phrase}? - Quora"),
    (
        "news.ycombinator.com",
        "from?site={w0}.com",
        "{Phrase} | Hacker News",
    ),
    ("www.linkedin.com", "pulse/{slug}", "{Phrase} | LinkedIn"),
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
fn day(seed: &Seed, back: usize) -> time::Date {
    parse_date(&seed.date).unwrap() - time::Duration::days(back as i64)
}
fn long_date(d: time::Date) -> String {
    let month = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ][d.month() as usize - 1];
    format!("{} {month} {}", d.day(), d.year())
}

/// Makes results from matching known pages, seed sites and filler sites.
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
    let d = day(seed, 3);
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
    let mut add = |url: String, title: String, snippet: String| {
        if results.len() < 10 && !results.iter().any(|r| r.url == url) {
            let date = long_date(day(seed, results.len() * 2 + 1));
            results.push(Result {
                url,
                title,
                snippet,
                date,
            });
        }
    };
    for k in known {
        if shares_words(&format!("{} {}", k.title, k.url), query) {
            add(
                k.url.clone(),
                k.title.clone(),
                if k.snippet.is_empty() {
                    k.title.clone()
                } else {
                    k.snippet.clone()
                },
            );
        }
    }
    for site in &seed.sites {
        if shares_words(&format!("{} {}", site.host, site.about), query) {
            add(
                format!("https://{}/{slug}", site.host),
                format!(
                    "{} | {}",
                    upper_first(&phrase),
                    site.host.strip_prefix("www.").unwrap_or(&site.host)
                ),
                facts.first().unwrap_or(&site.about).clone(),
            );
        }
    }
    for (i, (host, path, title)) in FILLER_SITES.iter().enumerate() {
        let snippet = if !facts.is_empty() && i % 3 == 0 {
            facts[i % facts.len()].clone()
        } else {
            format!("{}. {}", upper_first(&phrase), CLUTTER[i % CLUTTER.len()])
        };
        add(
            format!("https://{host}/{}", format(path)),
            format(title),
            snippet,
        );
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
    let hash = host
        .bytes()
        .fold(0usize, |n, b| n.wrapping_mul(31).wrapping_add(b as usize));
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
        ["news", "docs", "forum", "shop", "company", "wiki", "blog"][hash % 7]
    };
    Profile {
        css: stylesheet(kind),
        tagline: format!("News and guides from {name}"),
        name,
        kind: "news".into(),
        style: 0,
        nav: [
            "Home|/",
            "News|/news/",
            "Guides|/guides/",
            "Reviews|/reviews/",
            "About|/about/",
        ]
        .map(str::to_owned)
        .to_vec(),
        footer: [
            "About us|/about/",
            "Contact|/contact/",
            "Privacy|/privacy/",
            "Terms|/terms/",
            "Careers|/careers/",
        ]
        .map(str::to_owned)
        .to_vec(),
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
/// Makes page content from seed facts and prior mentions.
pub fn page(seed: &Seed, host: &str, target: &str, mentions: &[Value], host_pages: usize) -> Page {
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
    let mut claims = Vec::new();
    for claim in snippets.iter().chain(&facts) {
        if !claims.contains(claim) {
            claims.push(claim.clone());
        }
    }
    let mut page = Page {
        status: 200,
        title: title.clone(),
        date: seed.date.clone(),
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
    let n = host_pages;
    let date = day(seed, 1 + n);
    let mut paras: Vec<_> = claims
        .iter()
        .map(|s| format!("<p>{}</p>", escape(s)))
        .collect();
    if paras.is_empty() {
        paras.push(format!(
            "<p>{} is covered here as part of our regular reporting.</p>",
            escape(&title)
        ));
    }
    paras.insert(
        1,
        format!("<p class=\"aside\">{}</p>", CLUTTER[n % CLUTTER.len()]),
    );
    paras.push(format!(
        "<p class=\"aside\">{}</p>",
        CLUTTER[(n + 1) % CLUTTER.len()]
    ));
    let slug = words(&title)
        .into_iter()
        .take(5)
        .collect::<Vec<_>>()
        .join("-");
    let slug = if slug.is_empty() { "update" } else { &slug };
    let links = format!(
        "<li><a href=\"/{slug}-follow-up\">{}: follow-up</a></li>\
        <li><a href=\"/archive/2026/\">Archive: 2026</a></li>\
        <li><a href=\"https://en.wikipedia.org/wiki/{}\">{} on Wikipedia</a></li>",
        escape(&title),
        quote(&title.replace(' ', "_"), "/"),
        escape(&title)
    );
    page.body = format!(
        "<h1>{}</h1>\n<p class=\"byline\">By Staff Writer · {}</p>\n{}\n<h2>Read more</h2>\n<ul>{links}</ul>",
        escape(&title),
        long_date(date),
        paras.join("\n")
    );
    page.content_type = "text/html; charset=utf-8".into();
    page.description = take(
        &snippets
            .first()
            .cloned()
            .unwrap_or_else(|| format!("{title}. {}", CLUTTER[n % CLUTTER.len()])),
        300,
    );
    page.date = date.to_string();
    page.sidebar = [
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
    ]
    .map(|(a, b)| (a.into(), b.into()))
    .to_vec();
    page.ad = "Switch your broadband and save up to 30%. Offer ends Sunday.".into();
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
            let page = page(&seed, "www.halvardsystems.com", target, &mentions, 0);
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
        assert_eq!(found.results[0].snippet, seed.facts[0]);
        assert_eq!(found.results[0].date, "6 Oct 2026");
        assert_eq!(found.results[9].date, "18 Sep 2026");
        let mentions = vec![
            serde_json::json!({"via":"search","title":"Écho 😀","snippet":"Say \"hi\" & go."}),
        ];
        let p = page(&seed, "api.other.com", "/items.json", &mentions, 0);
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
            page(&seed, "other.com", "/items.txt", &mentions, 0).body,
            "Écho 😀\n\nSay \"hi\" & go.\n"
        );
        assert_eq!(site_profile("www.bbc.co.uk").name, "Bbc");
        assert_eq!(title_from("other.com", "/new_story.php?x=y"), "New story");
        assert_eq!(
            words("The v7.2.4 a-b .. x and café"),
            ["v7.2.4", "a-b", "x", "caf"]
        );
    }
}
