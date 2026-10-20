//! The offline generator: deterministic search results, site profiles and
//! page content, with no model.

use super::{Seed, prompts::expected_type, seed::parse_date, text::*};
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

/// One generated search result.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Result {
    /// Destination URL.
    pub url: String,
    /// Link title.
    pub title: String,
    /// Preview text shown below the title.
    pub snippet: String,
    /// Display date with an English month abbreviation.
    #[serde(default)]
    pub date: String,
}
/// A sponsored search result.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Ad {
    /// Destination URL.
    pub url: String,
    /// Advertisement heading.
    pub title: String,
    /// Advertisement body text.
    pub text: String,
}
/// Content shared by the search engine layouts.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Search {
    /// Results in ranking order.
    pub results: Vec<Result>,
    /// Related search phrases.
    pub related: Vec<String>,
    /// Suggested follow-up questions.
    pub questions: Vec<String>,
    /// Sponsored results.
    pub ads: Vec<Ad>,
}
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
fn shares_words(a: &str, b: &str) -> bool {
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
    Profile {
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
    let claims = [snippets.clone(), facts.clone()].concat();
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
    let mut paras: Vec<_> = snippets
        .iter()
        .chain(&facts)
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
