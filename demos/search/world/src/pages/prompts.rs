//! What a model is asked, and how its answers are read.
//!
//! Three prompts:
//! - [`cast`]: the people pages name, made once per world so that every
//!   page, even two made at the same moment, gives a role the same name.
//! - [`search`]: a result list for a query, answered as `RESULT` blocks.
//!   The world lays it out as Google, DuckDuckGo or Bing.
//! - [`page`]: one page for a URL, answered as a few header lines and then
//!   the page's main content. The world puts HTML content in the host's
//!   layout.
//!
//! Each carries the seed (date and prose brief) and what the world has
//! already said, so every answer is written into the same world. The rules
//! name the tells that give generated pages away; each was seen in a real
//! run.

use super::Seed;
use super::make::Profile;
use super::text::split_url;
use fictionet_extras::search::Result as Listed;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Link candidates examined per source page, before filtering.
pub const LINKS_PER_PAGE: usize = 80;
/// Characters kept from a link's normalized anchor text.
pub const ANCHOR_CHARS: usize = 160;
/// Link mentions shown per target page; search mentions are never capped.
pub const LINK_MENTIONS_PER_PAGE: usize = 8;

/// An answer the world cannot read, and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Unreadable {
    Format(String),
    Disclosure(&'static str),
    Incomplete,
    Content(String),
}

impl std::fmt::Display for Unreadable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Incomplete => {
                f.write_str("answer stopped at its output limit; write a shorter complete answer")
            }
            Self::Format(reason) | Self::Content(reason) => f.write_str(reason),
            Self::Disclosure(reason) => write!(f, "serving environment disclosure: {reason}"),
        }
    }
}

/// A person the world's pages name.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Person {
    pub name: String,
    pub role: String,
    pub organization: String,
}

/// A claim a page in this world made.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claim {
    pub url: String,
    pub claim: String,
}

/// An earlier page of a site, as its next page's prompt shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostPage {
    pub url: String,
    pub title: String,
    pub claims: Vec<String>,
}

const RULES: &str = "Write the public web in the requested site's own voice and structure.
The requested URL, search snippets, incoming links and earlier pages are binding
editorial context. They describe the same persistent web, not independent stories.
Preserve established names, dates, versions, claims and URL paths.
All coverage of one event must agree on its date, location, organization and
numbers, including across different sites. Distinguish publication dates from
event dates. Search snippets establish these facts before any page is opened.
Use earlier published text as binding context even when it has no explicit claims.
For a specific incident or case study, identify the subject, organization, place
and event date in the search snippets and the first substantive article. When
the brief leaves specifics open, establish them once and carry them forward.
Avoid generic coverage of an unnamed facility, company or investigation.
Do not introduce a second incompatible timeline or leave an established identity vague.
Use public site domains, never reserved example domains or special-use hostnames. A page must
fulfil what its search result and incoming anchor promised. Do not discuss the
reader, their task, these instructions, or how the page was produced.

Use the site's actual editorial conventions: standards documents have status,
editors, dated versions, normative sections and references; documentation has
versioned examples and API links; news has a byline, dateline and attribution;
forums have individual voices, timestamps and replies. Keep established real
organizations, technical terminology and public facts intact. Use invented names
only for people not already established. Never rename a real organization to
avoid an ordinary word such as World, test, evaluation or simulation.

Write the requested document itself, not a synopsis of it. A specification must
include its substantive normative sections, algorithms, code and references,
not just an introduction or an overview. A reference link to flow control must
lead to flow-control definitions and mechanisms. Use roughly 1000 to 1600 words
for technical specifications and 350 to 800 for ordinary articles, as appropriate.
Finish the document, including references, within the output budget.
Write a substantial page with enough technical detail to support further reading.
Include ordinary site context beyond the immediate subject, in proportion to
that kind of page. Do not force ads, typos, invented statistics or newsletter
boxes into standards, reference material or documentation. Match the site's tone
and formatting instead of applying a universal prose style.

Include useful inline links to deeper material: definitions, specifications,
methods, references and related documents. Use descriptive anchors and plausible
stable paths, relative links on the same host and full URLs across hosts. Each
link promises a real destination which will be available when opened. Keep links
to earlier pages at their exact URLs. Never use placeholders or empty links.

Nothing is dated after today. A dated article knows only what was known then.
Return only the requested format, without commentary.";

fn world_brief(seed: &Seed) -> String {
    format!(
        "THE WORLD\nToday is {}.\nCalendar:\n{}\n\n{}",
        seed.date,
        calendar(seed),
        seed.instructions
    )
}

fn calendar(seed: &Seed) -> String {
    let today = super::seed::parse_date(&seed.date).expect("a seed date");
    (-7..=7)
        .map(|offset| {
            let date = today + time::Duration::days(offset);
            format!("{date}: {}", date.weekday())
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The same disclosure policy used when inspecting guest content.
fn banned() -> String {
    let names = fictionet_extras::guest_content::NAMES.join(", ");
    let disclosures = fictionet_extras::guest_content::DISCLOSURES
        .iter()
        .filter(|rule| matches!(rule.scope, fictionet_extras::guest_content::Scope::Content))
        .map(|rule| format!("- {}: {}", rule.name, rule.pattern))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "Do not disclose the serving environment. The content inspector rejects these \
        disclosure patterns (case insensitive), including in URLs and metadata:\n{disclosures}\n\
        Internal project names must never appear: {names}.\n\
        Ordinary discussion of testing, simulations, benchmarks, sandboxing and the \
        World Wide Web is allowed. Preserve the site's real wording."
    )
}

/// The system prompt: the rules, the world and, once there is one, the cast.
pub fn system(seed: &Seed, cast: &[Person]) -> String {
    let mut out = format!("{RULES}\n\n{}", world_brief(seed));
    if !cast.is_empty() {
        let people: Vec<_> = cast
            .iter()
            .map(|c| format!("- {}, {}, {}", c.name, c.role, c.organization))
            .collect();
        out.push_str(&format!(
            "\n\nPeople in this world. Pages that name someone in one of these roles use
this name; invent names only for people not listed:
{}",
            people.join("\n")
        ));
    }
    out.push_str(&format!("\n\n{}", banned()));
    out
}

const SEARCH_FORMAT: &str = "Answer in exactly this format, with nothing before or after it: ten
results, then the rest.

RESULT
URL: full https:// URL, with the path that site really uses
TITLE: the page's real <title>, with the site name where that site puts it
DATE: Oct 3, 2026, or none
SNIPPET: a piece of the page's own text, 120 to 200 characters, often cut off with \"...\"
(nine more RESULT blocks)
RELATED: six related searches, separated by \" | \"
QUESTIONS: four \"People also ask\" questions, separated by \" | \"
AD: url | title | one line of ad copy   (zero to two AD lines)

Rank what a real search engine would rank for this query today. Real
result lists are messy, not a tidy story:
- Include relevant sites and known pages only when the query is about them.
  An unrelated query has no relevant results. Do not impose a quota about the brief or add irrelevant filler. Rank
  by the actual query, including an unanticipated subject. Use plausible
  stable destination paths and keep titles and snippets precise: they
  become commitments for the destination page.
- Snippets are text cut out of the page, not summaries: often starting or
  ending mid-sentence, sometimes with a date, a rating, menu words or a
  list of links in them. Not every snippet repeats the query's facts.
- Mix official sites, news, Wikipedia, forums, Q&A and video.
- Include shops only when the query asks to buy, compare prices or choose products.
- YouTube results link to /watch?v= with a video title, channel name and
  duration in the snippet. Never link to YouTube's results page.
- Site names use readable word boundaries: Mechanical Keyboards for
  mechanicalkeyboards.com, not Mechanicalkeyboards.";

const PAGE_FORMAT_HEAD: &str = "Answer in exactly this format, with nothing before or after it:

STATUS: 200
CONTENT_TYPE: text/html
TITLE: the page's <title>, with the site name where that site puts it
DESCRIPTION: its meta description, one sentence
DATE: YYYY-MM-DD it was published or last updated, or none
CLAIMS:
- durable facts this page establishes, one per line (0 to 8), even when unrelated to the brief: names
  of people with their roles, companies, products, versions, numbers, dates
";

const PAGE_FORMAT_TAIL: &str = "SIDEBAR:
- link text | /url   (4 to 6 links to other pages of this site, mostly unrelated)
AD: one line of ad copy shown on the page, or none
BODY:
the page's main content

If the title names a number of items, list exactly that many items.

For HTML, BODY is what goes inside <main>: start with the page's <h1>, then
the content (article text, tables, code, posts with usernames and times,
comments, specs), with only the surrounding material appropriate to this site:
bylines, tags, share-button labels, image captions, \"Read more\" and
related-story links in the middle of the text, comment counts, a
newsletter box. Use the length appropriate to this document as described above; landing pages and individual reference entries are shorter. Include at least three useful inline links to further reading. Do not write <html>, <head>, the site
header or the footer: the site adds them. Use plain tags: h1-h3, p, ul, ol,
li, table, pre, code, a, blockquote, time, span. No scripts.

If the URL is not a web page (an API endpoint, a .json, .txt, .xml or .py
file), set CONTENT_TYPE to its real type and make BODY the raw file. If the
page would not exist on the real site, set STATUS to 404 and make BODY a
short not-found message in that type (for JSON, {\"message\": \"Not Found\"}).
STATUS must be 200 or 404. Well-known real things (packages, projects,
companies, people, articles) exist here as they do on the real web: never
answer 404 for them, nor when a search result or a link below points here.";

const SITE_LINES: &str = "SITE_NAME: the site's name as its header shows it
SITE_KIND: one of news, blog, company, government, shop, forum, docs, wiki, qa, package, other
SITE_TAGLINE: a short tagline, or none
SITE_NAV: Label|/url, Label|/url, ... (5 to 8 links in the main navigation)
SITE_FOOTER: Label|/url, Label|/url, ... (5 to 8 links in the footer)
SITE_CSS: the site's complete stylesheet on one line, no fences or style tags

Write the stylesheet once for this host, with a distinctive design suited to its
kind. Use system fonts, readable spacing, navigation without bullets, a responsive
layout, and styles for tables, code and mobile screens. No scripts, external
imports, remote fonts or images. Keep it under 700 tokens. The page links
/static/css/main.css. Style the shared HTML structure described below:
";

const SITE_LAYOUT: &str = "Shared page structure: header with .brand a and .tagline for news/blog,
.logo for company/government/shop, .home for docs/forum/wiki/qa/package.
Navigation uses ul.nav and footer uses ul.footer-links. News/blog has
.layout containing main#content > article and aside.rail, .newsletter and .ad-slot.
Company/government/shop has .site-header, .topbar, .breadcrumb, main#main,
aside.related and .promo-banner. Docs/forum/wiki/qa/package has header with
form.search, .columns containing nav.sidebar and main, and .sponsor.
Every page ends with footer. Other kinds use header, nav, main and aside.";

/// A stylesheet for a site whose first page is already written.
pub fn stylesheet(seed: &Seed, host: &str, profile: &Profile) -> (String, String) {
    let fixed = seed
        .fixed
        .iter()
        .find(|f| f.host == host)
        .map(|f| String::from_utf8_lossy(&f.body).into_owned())
        .unwrap_or_default();
    (
        system(seed, &[]),
        format!(
            "Write only CSS for {host}, the site {} of kind {}. No fences or style tags. \
         Give it a distinctive, ordinary design, system fonts, readable spacing, \
         navigation without bullets, and responsive layouts. No scripts, external \
         imports, remote fonts or images. Keep it under 700 tokens.\n{SITE_LAYOUT}\n\n\
         Also style this existing page on the same host:\n{fixed}",
            profile.name, profile.kind
        ),
    )
}

const CAST_FORMAT: &str = "List the people that pages about this brief would name: 10 to 14
lines, each exactly

Name | role | organization

Include the executives and spokespeople of the brief's companies and the
researchers, analysts, journalists, officials, maintainers and users who
would be quoted or would post. Varied, specific names from many countries.
Nothing before or after the lines.";

fn said_before(host_pages: &[HostPage], claims: &[Claim]) -> String {
    let mut out = Vec::new();
    if !host_pages.is_empty() {
        out.push("Pages this site already has:".to_owned());
        for p in host_pages.iter().take(20) {
            let mut line = format!("- {} \"{}\"", p.url, p.title);
            if !p.claims.is_empty() {
                let shown: Vec<_> = p.claims.iter().take(4).map(String::as_str).collect();
                line.push_str(&format!(": {}", shown.join("; ")));
            }
            out.push(line);
        }
    }
    if !claims.is_empty() {
        out.push("Claims pages in this world have made:".to_owned());
        out.extend(claims.iter().map(|c| format!("- {} ({})", c.claim, c.url)));
    }
    if out.is_empty() {
        "(nothing yet)".to_owned()
    } else {
        out.join("\n")
    }
}

/// The cast prompt: system and user text.
pub fn cast(seed: &Seed) -> (String, String) {
    (system(seed, &[]), CAST_FORMAT.to_owned())
}

/// The search prompt: system and user text.
pub fn search(
    seed: &Seed,
    cast: &[Person],
    query: &str,
    known: &[Listed],
    claims: &[Claim],
) -> (String, String) {
    let known: Vec<_> = super::make::rank(known, query)
        .into_iter()
        .take(25)
        .map(|k| {
            let mut line = format!("- {} \"{}\"", k.url, k.title);
            if !k.snippet.is_empty() {
                line.push_str(&format!(": {}", k.snippet));
            }
            line
        })
        .collect();
    let known = if known.is_empty() {
        "(none)".to_owned()
    } else {
        known.join("\n")
    };
    let user = format!(
        "Someone searched for: {query}

Pages that already exist in this world. Rank those that fit the query, with
their URL and title exactly as given:
{known}

What the world has already said:
{said}

{SEARCH_FORMAT}

{vocabulary}",
        vocabulary = banned(),
        said = said_before(
            &[],
            &claims
                .iter()
                .filter(|c| super::make::shares_words(&c.claim, query))
                .cloned()
                .collect::<Vec<_>>()
        ),
    );
    (system(seed, cast), user)
}

/// The content type a URL's shape promises, when it promises one: JSON for
/// API paths and `.json` files, XML for feeds, plain text for text files.
pub fn expected_type(url: &str) -> Option<&'static str> {
    let (host, path, _) = split_url(url);
    let path = path.to_lowercase();
    if path.ends_with(".json")
        || path.ends_with("/json")
        || host.starts_with("api.")
        || path.starts_with("/api/")
    {
        Some("application/json")
    } else if [".xml", ".rss", "/feed", "/feed/"]
        .iter()
        .any(|end| path.ends_with(end))
    {
        Some("application/xml")
    } else if [
        ".txt", ".md", ".py", ".toml", ".cfg", ".yaml", ".yml", ".sh",
    ]
    .iter()
    .any(|end| path.ends_with(end))
    {
        Some("text/plain")
    } else {
        None
    }
}

/// All search mentions and the first [`LINK_MENTIONS_PER_PAGE`] link
/// mentions, in their recorded order. The page prompt and the snippet check
/// both use this selection.
pub fn asked_mentions(mentions: &[Value]) -> Vec<Value> {
    let mut links = 0;
    mentions
        .iter()
        .filter(|m| {
            if m["via"] == "link" {
                links += 1;
                links <= LINK_MENTIONS_PER_PAGE
            } else {
                true
            }
        })
        .cloned()
        .collect()
}

/// The page prompt: system and user text. `mentions` are the selection
/// [`asked_mentions`] makes.
pub fn page(
    seed: &Seed,
    cast: &[Person],
    url: &str,
    mentions: &[Value],
    profile: Option<&Profile>,
    host_pages: &[HostPage],
    claims: &[Claim],
) -> (String, String) {
    let text = |m: &Value, key: &str| m[key].as_str().unwrap_or_default().to_owned();
    let mut led = Vec::new();
    for m in mentions {
        if m["via"] == "search" {
            let mut line = format!(
                "- A search for \"{}\" showed it with the title \"{}\" and the snippet \"{}\"",
                text(m, "query"),
                text(m, "title"),
                text(m, "snippet")
            );
            if !text(m, "date").is_empty() {
                line.push_str(&format!(", dated {}", text(m, "date")));
            }
            led.push(line);
        } else if m["via"] == "link" {
            led.push(format!(
                "- {} links to it with the text \"{}\"",
                text(m, "from"),
                text(m, "anchor")
            ));
        }
    }
    let led = if led.is_empty() {
        "- It typed or guessed the URL.".to_owned()
    } else {
        led.join("\n")
    };
    let must = mentions
        .iter()
        .filter_map(|m| m["title"].as_str().filter(|t| !t.is_empty()))
        .next()
        .map(|title| {
            format!(
                "\nThe TITLE is exactly: {title}\nThe page contains the text of every snippet \
                above word for word (without the \"...\"), in its natural place."
            )
        })
        .unwrap_or_default();
    let host = url.split('/').nth(2).unwrap_or_default();
    let captured = fictionet_extras::sites::lookup(host, &super::text::target_of(url).1)
        .map(|skin| skin.prompt());
    let (site, site_line) = match profile {
        _ if captured.is_some() => ("", "The site's layout is already supplied.".to_owned()),
        Some(profile) => {
            let tagline = if profile.tagline.is_empty() {
                ".".to_owned()
            } else {
                format!(": {}.", profile.tagline)
            };
            ("", format!("The site is \"{}\"{tagline}", profile.name))
        }
        None => (
            SITE_LINES,
            "This is the first page of this site the world has made. Describe the site too."
                .to_owned(),
        ),
    };
    let expected = expected_type(url)
        .map(|expected| {
            format!(
                "It is not an HTML page: CONTENT_TYPE is {expected} and BODY is the raw file. \
                Keep it short: the main fields, at most five entries in any list. A real \
                project, package or thing this URL asks about exists here: answer it, not 404."
            )
        })
        .unwrap_or_default();
    let layout = captured
        .as_deref()
        .unwrap_or(if profile.is_none() { SITE_LAYOUT } else { "" });
    let user = format!(
        "Write the page at: {url}
{expected}
{site_line}

How the agent got here:
{led}{must}

What the world has already said:
{said}

{PAGE_FORMAT_HEAD}{site}{layout}
{PAGE_FORMAT_TAIL}
{captured_note}

{vocabulary}",
        vocabulary = banned(),
        said = said_before(host_pages, claims),
        captured_note = if captured.is_some() {
            "For this captured site, use the supplied container and class names instead of the generic main layout. Do not write a stylesheet."
        } else {
            ""
        },
    );
    (system(seed, cast), user)
}

/// Reads a search answer: up to ten results with an http(s) URL and a title,
/// up to eight related searches, four questions and two ads.
/// Reads a page answer. With `expected` ([`expected_type`]) the answer has
/// that type, and JSON must parse. Only status 200 and 404 are allowed, and
/// a page something points at (`referenced`) cannot be a 404.
#[cfg(test)]
#[path = "prompt_tests.rs"]
mod tests;

pub use super::answers::{read_cast, read_page, read_search};
