//! Search result pages with bundled layouts and built-in fallbacks.

use crate::text::{escape as e, normalize_space, quote, quote_plus, split_url};
use crate::{dom::*, sites::source, text};
use serde::{Deserialize, Serialize};

/// A supported search engine.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Engine {
    /// Google search.
    Google,
    /// DuckDuckGo search.
    #[serde(rename = "duckduckgo")]
    DuckDuckGo,
    /// Bing search.
    Bing,
    /// YouTube video search.
    YouTube,
}

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
/// Stylesheet for the built-in layouts and sponsored blocks. Captured pages
/// keep their own: the DuckDuckGo capture has the built-in layout's body class,
/// so its header (`.header--html`) keeps it out of scope.
pub const CSS: &str = r#"
@scope (html:has(> body.google), html:has(> body.bing), html:has(> body.body--html):not(:has(.header--html)), .uEierd, .b_ad) {
* { box-sizing: border-box; }
body { margin: 0; background: #fff; color: #202124; font: 14px/1.55 Arial, sans-serif; }
a { color: #1a0dab; text-decoration: none; }
a:hover { text-decoration: underline; }
input, button, select { font: inherit; }
input[type=text], input[type=search] { min-width: 0; flex: 1; border: 0; outline: 0; background: transparent; color: #202124; font-size: 16px; padding: 12px 20px; }
form[role=search], #sb_form, #search_form { display: flex; width: min(692px, calc(100vw - 220px)); min-height: 48px; border: 1px solid #dfe1e5; border-radius: 28px; box-shadow: 0 2px 6px #20212414; background: white; }
form:focus-within { outline: 2px solid #8ab4f8; outline-offset: 2px; }
input[type=submit], button { border: 0; background: transparent; padding: 0 20px; color: #1a73e8; cursor: pointer; }
h2 { font-size: 22px; font-weight: 400; }
footer { padding: 20px 36px; background: #f2f2f2; color: #70757a; }
footer a { color: inherit; }
.google header { padding: 28px 36px 0; border-bottom: 1px solid #ebebeb; display: grid; grid-template-columns: 114px 1fr; gap: 0 28px; align-items: center; }
#logo { font-size: 30px; letter-spacing: -2px; font-weight: 600; text-decoration: none; }
#logo span:nth-child(1), #logo span:nth-child(4) { color: #4285f4; }
#logo span:nth-child(2), #logo span:nth-child(6) { color: #ea4335; }
#logo span:nth-child(3) { color: #fbbc05; }
#logo span:nth-child(5) { color: #34a853; }
#gb { float: right; padding: 14px 28px; display: flex; gap: 20px; align-items: center; }
#gb a { color: #3c4043; font-size: 13px; }
#gb a:last-child { background: #0b57d0; color: #fff; border-radius: 24px; padding: 8px 22px; }
#hdtb { grid-column: 2; display: flex; gap: 28px; padding-top: 16px; align-items: center; color: #5f6368; }
#hdtb a, #hdtb span { color: inherit; padding: 12px 0; }
#hdtb a:first-child { color: #1a73e8; border-bottom: 3px solid #1a73e8; }
#result-stats { margin: 16px 0 22px 178px; color: #70757a; }
#res, #bres, #foot { margin-left: 178px; max-width: 652px; }
.g, .uEierd { margin: 0 0 30px; }
.yuRUbf a { display: flex; flex-direction: column; align-items: flex-start; }
.yuRUbf br { display: none; }
.yuRUbf cite { order: -1; color: #202124; font-style: normal; font-size: 14px; margin-bottom: 4px; }
.g h3, .uEierd [role=heading] { font-size: 20px; font-weight: 400; line-height: 1.3; margin: 0 0 5px; }
.VwiC3b, .MUxGbd { color: #4d5156; line-height: 1.58; }
.LEwnzc { color: #70757a; }
.U3A9Ac { display: block; font-weight: 600; margin-bottom: 8px; }
.related-question-pair { margin: 34px 0; }
.wQiwMc { padding: 12px 0; border-top: 1px solid #dadce0; }
.wQiwMc a { color: #202124; font-size: 16px; }
#bres a { display: inline-block; padding: 8px 0; }
#foot { padding: 24px 0; }
.google footer { padding-left: 178px; margin-top: 24px; }
.bing { font-family: "Segoe UI", Arial, sans-serif; color: #444; }
#b_header { padding: 26px 36px 0; border-bottom: 1px solid #ececec; display: grid; grid-template-columns: 140px 1fr; gap: 0 24px; align-items: center; }
.bing-brand { color: #444; font-size: 17px; letter-spacing: -.5px; white-space: nowrap; }
.bing-brand b { color: #008c9d; font-size: 26px; vertical-align: middle; margin-right: 7px; }
#sb_form { border-radius: 24px; }
#b_header nav { grid-column: 2; }
#b_header ul { display: flex; gap: 32px; padding: 0; margin: 16px 0 0; list-style: none; }
#b_header li { padding: 12px 0; }
#b_header li:first-child { border-bottom: 3px solid #00809d; }
#b_header nav a { color: #666; }
.bing main { margin: 18px 36px 50px 200px; max-width: 1120px; }
.sb_count { color: #767676; font-size: 13px; }
#b_results { list-style: none; padding: 0; margin: 20px 0; max-width: 648px; }
#b_results li { margin-bottom: 30px; }
#b_results h2 { font-size: 20px; line-height: 1.3; margin: 0 0 5px; }
#b_results a { color: #001ba0; }
.b_caption cite { font-style: normal; color: #006d21; }
.b_caption p, .b_ad p { margin: 4px 0; }
.news_dt { color: #767676; }
#b_context { border-top: 1px solid #eee; max-width: 648px; }
#b_context ul { list-style: none; padding: 0; columns: 2; }
#b_context li { margin: 10px 0; }
.body--html { color: #333; }
.body--html .header { background: #fafafa; border-bottom: 1px solid #ddd; padding: 24px 32px 18px; display: flex; gap: 28px; align-items: flex-start; }
.ddg-brand { display: flex; align-items: center; gap: 8px; color: #333; font-size: 18px; padding-top: 5px; white-space: nowrap; }
.ddg-brand b { display: inline-grid; place-items: center; border-radius: 50%; background: #de5833; color: #fff; width: 38px; height: 38px; font: bold 27px Georgia, serif; }
#search_form { border-radius: 5px; position: relative; margin-bottom: 42px; box-shadow: 0 2px 3px #0000000d; }
#search_form .search__button { background: #f3f3f3; border-left: 1px solid #ddd; color: #555; border-radius: 0 5px 5px 0; }
.frm__select { position: absolute; top: 62px; left: 0; border: 0; color: #666; background: transparent; }
.serp__results { margin: 28px 0 40px 232px; max-width: 650px; }
.result { margin-bottom: 30px; }
.result__title { font-size: 20px; line-height: 1.3; margin: 0 0 5px; }
.result__a { color: #1a0dab; }
.result__extras { margin: 4px 0; }
.result__url { color: #20692b; font-size: 14px; }
.result__icon { display: none; }
.result__timestamp { color: #777; padding-left: 12px; }
.result__snippet { display: block; color: #333; line-height: 1.6; }
.badge--ad { color: #777; font-size: 12px; }
.nav-link .btn { background: #f5f5f5; color: #333; border: 1px solid #ccc; border-radius: 4px; padding: 10px 32px; }
.feedback-btn { padding: 20px 32px; border-top: 1px solid #eee; }
.feedback-btn a { color: #666; }
@media (max-width: 900px) {
  #gb { float: none; justify-content: flex-end; }
  .google header, #b_header { padding: 18px 20px 0; grid-template-columns: 120px 1fr; gap: 0 16px; }
  form[role=search], #sb_form, #search_form { width: 100%; }
  #res, #bres, #foot, #result-stats, .serp__results, .bing main { margin-left: 24px; margin-right: 24px; }
  .google footer { padding-left: 24px; }
  #hdtb, #b_header nav { grid-column: 1 / -1; overflow-x: auto; gap: 24px; }
  .body--html .header { flex-wrap: wrap; padding: 20px 24px; gap: 12px; }
}
}
.body--html .result--ad .result__snippet { display: block; }
.B6fmyf .csDOgf { display: none; }
@media (max-width: 979.98px) { #gsr .logo { display: none; } }
.uEierd { margin: 0 0 24px; font: 14px/1.58 Arial, sans-serif; color: #4d5156; }
.uEierd + .MjjYud { padding-top: 0; margin-top: 0; }
.result-icon { vertical-align: middle; margin-inline-end: 6px; border-radius: 50%; }
.uEierd a { color: #1a0dab; text-decoration: none; }
.uEierd [role=heading] { font-size: 20px; line-height: 1.3; margin-bottom: 5px; }
.uEierd .U3A9Ac { display: block; color: #202124; font-weight: 600; margin-bottom: 8px; }
"#;

/// Formats a URL as a host and up to three decoded path segments.
fn display_url(url: &str) -> String {
    let (mut host, path, _) = split_url(url);
    for part in path.split('/').filter(|p| !p.is_empty()).take(3) {
        host.push_str(" › ");
        host.push_str(&percent_encoding::percent_decode_str(part).decode_utf8_lossy());
    }
    host
}
fn estimate(query: &str, count: usize) -> String {
    if count == 0 {
        return "0".into();
    }
    let hash = query
        .to_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .bytes()
        .fold(0usize, |n, b| n.wrapping_mul(31).wrapping_add(b as usize));
    result_count(100_000 + (hash % 9_900) * 1_000)
}

/// Formats the number of available results with comma separators.
fn result_count(count: usize) -> String {
    let n = count.to_string();
    let mut out = String::new();
    for (i, c) in n.chars().enumerate() {
        if i > 0 && (n.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}
/// Returns the engine's server header.
pub fn engine_server(engine: Engine) -> &'static str {
    match engine {
        Engine::Google | Engine::YouTube => "gws",
        Engine::DuckDuckGo => "nginx",
        Engine::Bing => "Microsoft-IIS/10.0",
    }
}
/// Renders results in the selected engine's layout.
pub fn render(engine: Engine, query: &str, record: &Search, start: u64) -> String {
    if engine == Engine::YouTube {
        return youtube(query, record);
    }
    render_with(
        source(layout(engine).host, "/"),
        engine,
        query,
        record,
        start,
    )
}

fn render_with(
    html: Option<&str>,
    engine: Engine,
    query: &str,
    record: &Search,
    start: u64,
) -> String {
    if let Some(page) = html.and_then(|html| results(html, engine, query, record, start).ok()) {
        return page;
    }
    match engine {
        Engine::Google | Engine::YouTube => google(query, record, start),
        Engine::DuckDuckGo => duckduckgo(query, record),
        Engine::Bing => bing(query, record),
    }
}
/// Renders Google results at the given result offset.
fn google(query: &str, record: &Search, start: u64) -> String {
    let q = e(query);
    let qp = quote_plus(query);
    let count = estimate(query, record.results.len());
    let mut out = vec![format!(
        r#"<!DOCTYPE html><html lang="en-GB"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{q} - Google Search</title><link rel="stylesheet" href="/search.css"></head>
<body class="google"><div id="gb"><a href="https://mail.google.com/mail/">Gmail</a> <a href="https://www.google.com/imghp">Images</a> <a href="https://accounts.google.com/ServiceLogin">Sign in</a></div>
<header><a href="/" id="logo" aria-label="Google"><span>G</span><span>o</span><span>o</span><span>g</span><span>l</span><span>e</span></a><form action="/search" method="GET" role="search"><input name="q" value="{q}" aria-label="Search" type="text"><input type="submit" value="Search"></form>
<div id="hdtb"><a href="/search?q={qp}">All</a> <a href="/search?q={qp}&amp;tbm=nws">News</a> <a href="/search?q={qp}&amp;tbm=isch">Images</a> <a href="/search?q={qp}&amp;tbm=vid">Videos</a> <a href="https://maps.google.com/maps?q={qp}">Maps</a> <span>More</span> <span>Tools</span></div></header>
<div id="main"><div id="result-stats">{count} results</div><div id="res"><div id="search">"#
    )];
    if start == 0 {
        for (index, ad) in record.ads.iter().take(2).enumerate() {
            out.push(format!(
                concat!(
                    r#"<div class="uEierd">{heading}"#,
                    r#"<a href="{url}"><div role="heading">{title}</div><span>{shown}</span></a>"#,
                    r#"<div class="MUxGbd">{text}</div></div>"#,
                ),
                heading = if index == 0 {
                    r#"<span class="U3A9Ac">Sponsored</span>"#
                } else {
                    ""
                },
                url = e(&ad.url),
                title = e(&ad.title),
                shown = e(&display_url(&ad.url)),
                text = e(&ad.text),
            ));
        }
    }
    for r in &record.results {
        let date = if r.date.is_empty() {
            String::new()
        } else {
            format!(r#"<span class="LEwnzc">{} — </span>"#, e(&r.date))
        };
        out.push(format!(
            concat!(
                r#"<div class="g"><div class="yuRUbf"><a href="{url}"><h3>{title}</h3><br>"#,
                r#"<cite>{shown}</cite></a></div>"#,
                r#"<div class="VwiC3b">{date}<span>{snippet}</span></div></div>"#,
            ),
            url = e(&r.url),
            title = e(&r.title),
            shown = e(&display_url(&r.url)),
            date = date,
            snippet = e(&r.snippet),
        ));
    }
    if !record.questions.is_empty() {
        out.push(r#"<div class="related-question-pair"><h2>People also ask</h2>"#.into());
        for question in record.questions.iter().take(4) {
            out.push(format!(
                r#"<div class="wQiwMc"><a href="/search?q={}">{}</a></div>"#,
                quote_plus(question),
                e(question)
            ));
        }
        out.push("</div>".into());
    }
    out.push(r#"</div></div><div id="bres"><h2>Related searches</h2>"#.into());
    for rel in record.related.iter().take(8) {
        out.push(format!(
            r#"<a href="/search?q={}">{}</a><br>"#,
            quote_plus(rel),
            e(rel)
        ));
    }
    out.push(r#"</div></div>
<footer><span>United Kingdom</span> · <a href="https://support.google.com/websearch">Help</a> · <a href="https://www.google.com/tools/feedback">Send feedback</a> · <a href="https://policies.google.com/privacy">Privacy</a> · <a href="https://policies.google.com/terms">Terms</a></footer></body></html>"#.into());
    out.join("\n")
}
/// The links and titles of the results a [`render`] page lists, unescaped.
pub fn links(page: &str) -> Vec<(String, String)> {
    use kuchiki::traits::TendrilSink;
    kuchiki::parse_html()
        .one(page)
        .select(".yuRUbf a")
        .unwrap()
        .filter_map(|link| {
            let heading = link.as_node().select_first("h3").ok()?;
            let url = link.attributes.borrow().get("href")?.to_owned();
            Some((url, heading.text_contents()))
        })
        .collect()
}
/// Returns the bundled home page for the selected engine.
pub fn home(engine: Engine) -> &'static str {
    match engine {
        Engine::Google => include_str!("../sites/www.google.com/home.html"),
        Engine::YouTube => include_str!("../sites/www.youtube.com/results.html"),
        Engine::DuckDuckGo => include_str!("../sites/html.duckduckgo.com/home.html"),
        Engine::Bing => include_str!("../sites/www.bing.com/home.html"),
    }
}
/// Renders video results from a search record in YouTube's local layout.
/// Channel and view labels are taken from the snippet when supplied.
pub fn youtube(query: &str, record: &Search) -> String {
    let dom = document(include_str!("../sites/www.youtube.com/results.html"));
    set_text(&dom, "title", &format!("{query} - YouTube")).unwrap();
    set_text(&dom, ".page-title", query).unwrap();
    let input = one(&dom, "input[name=search_query]").unwrap();
    input
        .as_element()
        .unwrap()
        .attributes
        .borrow_mut()
        .insert("value", query.to_owned());
    for node in dom
        .select(".video-player, .page-date, .page-breadcrumb")
        .unwrap()
        .collect::<Vec<_>>()
    {
        node.as_node().detach();
    }
    let mut cards = String::from(r#"<nav class="search-filters"><a href="/results?search_query="#);
    cards.push_str(&e(&quote_plus(query)));
    cards.push_str(r#"">All</a><span>Videos</span></nav>"#);
    let mut count = 0;
    for result in &record.results {
        let Ok(url) = url::Url::parse(&result.url) else {
            continue;
        };
        if !matches!(
            url.host_str(),
            Some("www.youtube.com" | "youtube.com" | "youtu.be")
        ) || !(url.path() == "/watch"
            || url.path().starts_with("/shorts/")
            || url.host_str() == Some("youtu.be"))
        {
            continue;
        }
        count += 1;
        let labels = result
            .snippet
            .split(['•', '·'])
            .map(str::trim)
            .collect::<Vec<_>>();
        let views = labels
            .iter()
            .find(|label| label.contains(" views"))
            .copied()
            .unwrap_or("Views not listed");
        let channel = labels
            .iter()
            .find(|label| {
                !label.contains(" views")
                    && !label.contains(" ago")
                    && !label.chars().all(|c| c.is_ascii_digit() || c == ':')
            })
            .copied()
            .unwrap_or("YouTube");
        let channel = channel.strip_prefix("By ").unwrap_or(channel);
        let initial = channel
            .chars()
            .next()
            .unwrap_or('Y')
            .to_uppercase()
            .to_string();
        let title = e(&result.title);
        let description = labels
            .iter()
            .find(|label| label.len() > 100)
            .copied()
            .unwrap_or(&result.snippet);
        let thumbnail = video_thumbnail(&result.title);
        cards.push_str(&format!(
            r#"<article class="video-result"><a class="video-thumbnail" href="{url}"><img src="{thumbnail}" alt="{title}"><span class="video-duration">8:41</span></a><div><h2><a href="{url}">{title}</a></h2><p class="views">{views}</p><p class="channel"><span class="channel-disc" aria-hidden="true" data-initial="{initial}"></span>{channel}</p><p>{snippet}</p></div></article>"#,
            url = e(&result.url),
            views = e(views), channel = e(channel), initial = e(&initial), snippet = e(description),
        ));
    }
    if count == 0 {
        cards.push_str("<p>No videos found. Try another search.</p>");
    }
    replace(&one(&dom, "main.youtube-content").unwrap(), &cards);
    dom.to_string()
}

/// A local SVG thumbnail derived from a video title.
pub fn video_thumbnail(title: &str) -> String {
    let hash = title
        .bytes()
        .fold(0u32, |n, b| n.wrapping_mul(31).wrapping_add(u32::from(b)));
    let hue = hash % 360;
    let skyline = title
        .bytes()
        .take(20)
        .enumerate()
        .map(|(i, b)| {
            format!(
                "{} {},{} {}",
                i * 34,
                90 + u32::from(b) % 170,
                i * 34 + 34,
                90 + u32::from(b) % 170
            )
        })
        .collect::<Vec<_>>()
        .join(" ");
    let svg = format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="640" height="360" viewBox="0 0 640 360"><rect width="640" height="360" fill="hsl({hue},45%,28%)"/><path d="M0 360 {skyline} 640 360Z" fill="hsl({hue},48%,45%)"/><path d="m291 130 90 50-90 50Z" fill="white"/></svg>"##
    );
    format!("data:image/svg+xml,{}", quote(&svg, ""))
}

fn ddg_link(url: &str) -> String {
    format!("//duckduckgo.com/l/?uddg={}", quote(url, ""))
}
/// Renders DuckDuckGo results.
fn duckduckgo(query: &str, record: &Search) -> String {
    let q = e(query);
    let mut out = vec![format!(
        r#"<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml"><head><meta http-equiv="content-type" content="text/html; charset=UTF-8" /><meta name="referrer" content="origin" />
<meta name="viewport" content="width=device-width, initial-scale=1" /><title>{q} at DuckDuckGo</title><link rel="stylesheet" href="/search.css" type="text/css" /></head>
<body class="body--html"><div class="header"><a class="ddg-brand" href="/"><b>D</b>DuckDuckGo</a><form id="search_form" name="x" action="/html/" method="post" role="search"><input type="text" name="q" class="search__input" value="{q}" aria-label="Search" /><input type="submit" class="search__button" value="Search" /><select class="frm__select" name="kl" aria-label="Region"><option value="">All Regions</option><option value="uk-en">United Kingdom</option><option value="us-en">US (English)</option></select></form></div>
<div class="serp__results"><div id="links" class="results">"#
    )];
    for ad in record.ads.iter().take(1) {
        let link = e(&ddg_link(&ad.url));
        out.push(format!(
            concat!(
                r#"<div class="result results_links results_links_deep result--ad">"#,
                r#"<div class="links_main links_deep result__body"><h2 class="result__title">"#,
                r#"<a rel="nofollow" class="result__a" href="{link}">{title}</a></h2>"#,
                r#"<a class="result__url" href="{link}">{host}</a>"#,
                r#"<a class="result__snippet" href="{link}">{text}</a>"#,
                r#"<div class="badge--ad">Ad</div></div></div>"#,
            ),
            link = link,
            title = e(&ad.title),
            host = e(&split_url(&ad.url).0),
            text = e(&ad.text),
        ));
    }
    for r in &record.results {
        let link = e(&ddg_link(&r.url));
        let host = e(&split_url(&r.url).0);
        let date = if r.date.is_empty() {
            String::new()
        } else {
            format!(r#"<span class="result__timestamp">{}</span>"#, e(&r.date))
        };
        out.push(format!(
            concat!(
                r#"<div class="result results_links results_links_deep web-result">"#,
                r#"<div class="links_main links_deep result__body"><h2 class="result__title">"#,
                r#"<a rel="nofollow" class="result__a" href="{link}">{title}</a></h2>"#,
                r#"<div class="result__extras"><div class="result__extras__url">"#,
                r#"<span class="result__icon"><a rel="nofollow" href="{link}">"#,
                r#"<img class="result__icon__img" width="16" height="16" alt="" "#,
                r#"src="https://external-content.duckduckgo.com/ip3/{host}.ico" name="i15" /></a></span>"#,
                r#"<a class="result__url" href="{link}">{shown}</a>{date}</div></div>"#,
                r#"<a class="result__snippet" href="{link}">{snippet}</a>"#,
                r#"<div class="clear"></div></div></div>"#,
            ),
            link = link,
            title = e(&r.title),
            host = host,
            shown = e(&display_url(&r.url).replace(" › ", "/")),
            date = date,
            snippet = e(&r.snippet),
        ));
    }
    out.push(r#"</div></div><div class="feedback-btn"><a rel="nofollow" href="//duckduckgo.com/feedback.html">Feedback</a></div></body></html>"#.into());
    out.join("\n")
}
/// Renders Bing results.
fn bing(query: &str, record: &Search) -> String {
    let q = e(query);
    let qp = quote_plus(query);
    let count = estimate(query, record.results.len());
    let mut out = vec![format!(
        r#"<!DOCTYPE html><html lang="en" dir="ltr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>{q} - Search</title><link rel="stylesheet" href="/search.css"></head>
<body class="bing"><header id="b_header"><a class="bing-brand" href="/"><b>◇</b>Microsoft Bing</a><form action="/search" id="sb_form" role="search"><input id="sb_form_q" name="q" type="search" value="{q}" aria-label="Search"><button type="submit">Search</button></form>
<nav><ul><li><a href="/search?q={qp}">All</a></li><li><a href="/images/search?q={qp}">Images</a></li><li><a href="/videos/search?q={qp}">Videos</a></li><li><a href="/news/search?q={qp}">News</a></li><li><a href="/maps?q={qp}">Maps</a></li></ul></nav></header>
<main><span class="sb_count">About {count} results</span><ol id="b_results">"#
    )];
    for ad in record.ads.iter().take(1) {
        out.push(format!(
            r#"<li class="b_ad"><h2><a href="{}">{}</a></h2><p>{}</p><span>Ad</span></li>"#,
            e(&ad.url),
            e(&ad.title),
            e(&ad.text)
        ));
    }
    for r in &record.results {
        let date = if r.date.is_empty() {
            String::new()
        } else {
            format!(r#"<span class="news_dt">{}</span> · "#, e(&r.date))
        };
        out.push(format!(
            concat!(
                r#"<li class="b_algo"><h2><a href="{url}">{title}</a></h2>"#,
                r#"<div class="b_caption"><cite>{url}</cite><p>{date}{snippet}</p></div></li>"#,
            ),
            url = e(&r.url),
            title = e(&r.title),
            date = date,
            snippet = e(&r.snippet),
        ));
    }
    out.push(r#"</ol><div id="b_context"><h2>Related searches</h2><ul>"#.into());
    for rel in record.related.iter().take(8) {
        out.push(format!(
            r#"<li><a href="/search?q={}">{}</a></li>"#,
            quote_plus(rel),
            e(rel)
        ));
    }
    out.push(r#"</ul></div></main><footer id="b_footer"><a href="https://go.microsoft.com/fwlink/?LinkId=521839">Privacy and Cookies</a> · <a href="https://go.microsoft.com/fwlink/?LinkID=246338">Legal</a> · <a href="https://www.bing.com/account/general">Settings</a> · © 2026 Microsoft</footer></body></html>"#.into());
    out.join("\n")
}
struct EngineLayout {
    host: &'static str,
    list: &'static str,
    organic: &'static str,
    title: &'static str,
    snippet: &'static str,
    site: &'static str,
    ad: &'static str,
}

fn layout(engine: Engine) -> EngineLayout {
    match engine {
        Engine::Google | Engine::YouTube => EngineLayout {
            host: "www.google.com",
            list: "#rso",
            organic: ".tF2Cxc.asEBEc",
            title: "h3",
            snippet: ".VwiC3b",
            site: ".VuuXrf",
            ad: ".uEierd",
        },
        Engine::Bing => EngineLayout {
            host: "www.bing.com",
            list: "#b_results",
            organic: "li.b_algo",
            title: "h2 a",
            snippet: ".b_caption p",
            site: ".tptt",
            ad: ".b_ad",
        },
        Engine::DuckDuckGo => EngineLayout {
            host: "html.duckduckgo.com",
            list: "#links",
            organic: ".web-result",
            title: ".result__a",
            snippet: ".result__snippet",
            site: ".result__url",
            ad: ".result--ad",
        },
    }
}

fn result(
    template: &str,
    layout: &EngineLayout,
    url: &str,
    title: &str,
    snippet: &str,
) -> std::result::Result<String, String> {
    let dom = document(template);
    set_text(&dom, layout.title, title)?;
    set_text(&dom, layout.snippet, snippet)?;
    for selector in ["cite", layout.site] {
        for node in dom
            .select(selector)
            .map_err(|_| "invalid result selector")?
        {
            let text = if selector == layout.site {
                text::split_url(url).0
            } else {
                display_url(url)
            };
            replace(node.as_node(), &text::escape(&text));
        }
    }
    for node in dom.select("a").unwrap() {
        let mut attrs = node.attributes.borrow_mut();
        attrs.insert(
            "href",
            if layout.host == "html.duckduckgo.com" {
                ddg_link(url)
            } else {
                url.to_owned()
            },
        );
        attrs.remove("aria-label");
        attrs.remove("target");
    }
    let host = text::split_url(url).0;
    let icon_url = match layout.host {
        "www.google.com" => format!(
            "https://www.google.com/s2/favicons?domain={}&sz=32",
            quote(&host, "")
        ),
        "www.bing.com" => format!("https://www.bing.com/th?id={}&w=32&h=32", quote(&host, "")),
        _ => format!("https://external-content.duckduckgo.com/ip3/{host}.ico"),
    };
    let icon = format!(
        r#"<img class="result-icon" src="{}" width="20" height="20" alt="">"#,
        e(&icon_url)
    );
    let images = dom.select("img").unwrap().collect::<Vec<_>>();
    if let Some(first) = images.first() {
        first.as_node().insert_before(
            document(&icon)
                .select_first("img")
                .unwrap()
                .as_node()
                .clone(),
        );
    } else if let Ok(slot) = dom.select_first(".wr_fav, .result__icon, .b_favicon") {
        replace(slot.as_node(), &icon);
    } else {
        one(&dom, layout.site)?.prepend(
            document(&icon)
                .select_first("img")
                .unwrap()
                .as_node()
                .clone(),
        );
    }
    for node in images {
        node.as_node().detach();
    }
    for node in dom.select("[id]").unwrap() {
        node.attributes.borrow_mut().remove("id");
    }
    Ok(one(&dom, "body")?
        .children()
        .map(|n| n.to_string())
        .collect())
}

fn results(
    html: &str,
    engine: Engine,
    query: &str,
    record: &Search,
    start: u64,
) -> std::result::Result<String, String> {
    let layout = layout(engine);
    let dom = document(html);
    let list = one(&dom, layout.list)?;
    let organic = one(&list, layout.organic)?;
    let template = if engine == Engine::Google {
        organic
            .ancestors()
            .find(|node| {
                node.as_element().is_some_and(|element| {
                    element
                        .attributes
                        .borrow()
                        .get("class")
                        .is_some_and(|class| class.split_whitespace().any(|c| c == "MjjYud"))
                })
            })
            .ok_or("capture is missing the Google result wrapper .MjjYud")?
            .to_string()
    } else {
        organic.to_string()
    };
    let mut blocks = String::new();
    if start == 0 && !record.ads.is_empty() {
        if let Ok(ad) = one(&list, layout.ad) {
            let (title, snippet) = match engine {
                Engine::Google | Engine::YouTube => ("[role=heading]", ".MUxGbd"),
                Engine::Bing => ("h2 a", "p"),
                Engine::DuckDuckGo => (".result__a", ".result__snippet"),
            };
            let ad_layout = EngineLayout {
                title,
                snippet,
                ..self::layout(engine)
            };
            for row in &record.ads {
                blocks.push_str(&result(
                    &ad.to_string(),
                    &ad_layout,
                    &row.url,
                    &row.title,
                    &row.text,
                )?);
            }
        } else {
            // These captures have no ads. Preserve the existing sponsored markup.
            let fallback = match engine {
                Engine::Google | Engine::YouTube => google(query, record, start),
                Engine::Bing => bing(query, record),
                Engine::DuckDuckGo => duckduckgo(query, record),
            };
            let ads = document(&fallback);
            for ad in ads
                .select(layout.ad)
                .map_err(|_| "invalid sponsored selector")?
            {
                let mut attrs = ad.attributes.borrow_mut();
                let class = attrs.get("class").unwrap_or_default();
                let scope = match engine {
                    Engine::Google | Engine::YouTube => "google",
                    Engine::Bing => "bing",
                    Engine::DuckDuckGo => "body--html",
                };
                let class = format!("{class} {scope}");
                attrs.insert("class", class);
                drop(attrs);
                blocks.push_str(&ad.as_node().to_string());
            }
        }
    }
    for row in &record.results {
        let snippet = if row.date.is_empty() {
            normalize_space(&row.snippet)
        } else {
            format!("{} — {}", row.date, row.snippet)
        };
        blocks.push_str(&result(&template, &layout, &row.url, &row.title, &snippet)?);
    }
    replace(&list, &blocks);
    set_text(
        &dom,
        "title",
        &format!(
            "{query} - {}",
            match engine {
                Engine::Google | Engine::YouTube => "Google Search",
                Engine::Bing => "Search",
                Engine::DuckDuckGo => "DuckDuckGo",
            }
        ),
    )?;
    let fields = dom
        .select("input[name=q], textarea[name=q]")
        .map_err(|_| "invalid query selector")?
        .collect::<Vec<_>>();
    if fields.is_empty() {
        return Err("capture is missing the query field".into());
    }
    for field in fields {
        if field.name.local.as_ref() == "textarea" {
            replace(field.as_node(), &text::escape(query));
        } else {
            field
                .attributes
                .borrow_mut()
                .insert("value", query.to_owned());
        }
    }
    for node in dom
        .select("#botstuff table, #foot, .b_pag, .nav-link, .pagination")
        .unwrap()
        .collect::<Vec<_>>()
    {
        node.as_node().detach();
    }
    for count in dom.select("#result-stats, .sb_count").unwrap() {
        replace(
            count.as_node(),
            &format!("About {} results", estimate(query, record.results.len())),
        );
    }
    for link in dom.select("a[href]").unwrap() {
        let mut attrs = link.attributes.borrow_mut();
        let Some(href) = attrs.get("href") else {
            continue;
        };
        let Ok(mut url) = url::Url::parse(href) else {
            continue;
        };
        if url.host_str() != Some(layout.host) || !url.query_pairs().any(|(k, _)| k == "q") {
            continue;
        }
        let pairs: Vec<_> = url
            .query_pairs()
            .filter(|(k, _)| k != "q")
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        url.query_pairs_mut()
            .clear()
            .extend_pairs(pairs)
            .append_pair("q", query);
        attrs.insert("href", url.to_string());
    }
    Ok(dom.to_string().replacen(
        "</head>",
        "<link rel=\"stylesheet\" href=\"/search.css\"></head>",
        1,
    ))
}

#[cfg(test)]
fn captured(
    engine: Engine,
    query: &str,
    record: &Search,
    start: u64,
) -> std::result::Result<Option<String>, String> {
    let layout = layout(engine);
    source(layout.host, "/")
        .map(|html| results(html, engine, query, record, start))
        .transpose()
        .map_err(|why| format!("{}: {why}", layout.host))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> Search {
        Search {
            results: vec![Result {
                url: "https://docs.python.org/3/library/pathlib.html?x=1&y=2".into(),
                title: "Paths <files> & directories".into(),
                snippet: "Read files without changing their contents.".into(),
                date: "Oct 4, 2026".into(),
            }],
            ads: vec![Ad {
                url: "https://shop.example.net/".into(),
                title: "Storage".into(),
                text: "Keep your files.".into(),
            }],
            ..Search::default()
        }
    }

    #[test]
    fn google_ads_share_one_heading() {
        let mut record = record();
        record.ads.push(Ad {
            url: "https://other.org/".into(),
            title: "More choices".into(),
            text: "Read more.".into(),
        });
        for html in [
            google("storage", &record, 0),
            render(Engine::Google, "storage", &record, 0),
        ] {
            let dom = document(&html);
            assert_eq!(dom.select(".uEierd").unwrap().count(), 2);
            assert_eq!(dom.select(".U3A9Ac").unwrap().count(), 1);
        }
    }

    #[test]
    fn result_rows_use_one_host_icon() {
        let record = Search {
            results: vec![Result {
                url: "https://securityweek.com/article".into(),
                title: "Security news".into(),
                snippet: "Security updates.".into(),
                date: String::new(),
            }],
            ..Search::default()
        };
        for engine in [Engine::Google, Engine::Bing, Engine::DuckDuckGo] {
            let dom = document(&render(engine, "security", &record, 0));
            let row = one(&dom, layout(engine).organic).unwrap();
            let images = row.select("img").unwrap().collect::<Vec<_>>();
            assert_eq!(images.len(), 1, "{engine:?}");
            let attrs = images[0].attributes.borrow();
            let icon = url::Url::parse(attrs.get("src").unwrap()).unwrap();
            match engine {
                Engine::Google => {
                    assert_eq!(icon.host_str(), Some("www.google.com"));
                    assert_eq!(icon.path(), "/s2/favicons");
                    assert!(
                        icon.query_pairs()
                            .any(|(k, v)| k == "domain" && v == "securityweek.com")
                    );
                }
                Engine::Bing => {
                    assert_eq!(icon.host_str(), Some("www.bing.com"));
                    assert_eq!(icon.path(), "/th");
                    assert!(
                        icon.query_pairs()
                            .any(|(k, v)| k == "id" && v == "securityweek.com")
                    );
                }
                _ => assert_eq!(
                    icon.as_str(),
                    "https://external-content.duckduckgo.com/ip3/securityweek.com.ico"
                ),
            }
        }
    }

    #[test]
    fn video_art_varies_with_titles_and_includes_duration() {
        let first = video_thumbnail("Resetting a router");
        let second = video_thumbnail("Sourdough bread");
        assert_ne!(first, second);
        let svg = percent_encoding::percent_decode_str(
            first.strip_prefix("data:image/svg+xml,").unwrap(),
        )
        .decode_utf8()
        .unwrap();
        assert!(svg.contains("hsl("));
        let record = Search {
            results: vec![Result {
                url: "https://www.youtube.com/watch?v=router".into(),
                title: "Resetting a router".into(),
                ..Result::default()
            }],
            ..Search::default()
        };
        let html = render(Engine::YouTube, "router", &record, 0);
        let dom = document(&html);
        assert_eq!(
            one(&dom, ".video-duration").unwrap().text_contents(),
            "8:41"
        );
        let (_, css) = crate::sites::asset("www.youtube.com", "/_assets/site.css").unwrap();
        let css = std::str::from_utf8(css).unwrap();
        assert!(css.contains("font-size:12px"));
        assert!(css.contains("background:#000a"));
    }

    #[test]
    fn bing_estimates_are_large_and_stable_for_the_query() {
        let mut record = Search::default();
        record.results.push(Result {
            url: "https://example.org/article".into(),
            title: "Router configuration".into(),
            ..Result::default()
        });
        let first = document(&render(Engine::Bing, "router configuration", &record, 0));
        let count = first.select_first(".sb_count").unwrap().text_contents();
        let number: usize = count
            .trim_start_matches("About ")
            .trim_end_matches(" results")
            .replace(',', "")
            .parse()
            .unwrap();
        assert!(number >= 100_000, "{count}");
        record.results.push(record.results[0].clone());
        let second = document(&render(Engine::Bing, "router configuration", &record, 0));
        assert_eq!(
            count,
            second.select_first(".sb_count").unwrap().text_contents()
        );
    }

    #[test]
    fn bundled_homes_submit_to_results_and_resolve_assets_for_every_name() {
        for (engine, hosts, action) in [
            (
                Engine::Google,
                &["www.google.com", "google.com"][..],
                "/search",
            ),
            (Engine::Bing, &["www.bing.com", "bing.com"][..], "/search"),
            (
                Engine::DuckDuckGo,
                &[
                    "duckduckgo.com",
                    "www.duckduckgo.com",
                    "html.duckduckgo.com",
                ][..],
                "/html/",
            ),
        ] {
            let dom = document(home(engine));
            let form = dom.select_first("form[role=search]").unwrap();
            assert_eq!(form.attributes.borrow().get("action"), Some(action));
            assert!(form.as_node().select_first("input[name=q]").is_ok());
            for host in hosts {
                for node in dom.select("link[rel=stylesheet], img[src]").unwrap() {
                    let attrs = node.attributes.borrow();
                    let path = attrs.get("href").or_else(|| attrs.get("src")).unwrap();
                    let (_, bytes) = crate::sites::asset(host, path).unwrap();
                    assert!(!bytes.is_empty(), "{host}{path}");
                }
            }
        }
    }

    #[test]
    fn youtube_results_keep_ranked_video_data_and_submit_to_the_same_route() {
        let record = Search {
            results: vec![
                Result {
                    url: "https://www.youtube.com/watch?v=paths".into(),
                    title: "Paths & files".into(),
                    snippet: "Python Channel • 12,345 views • A practical guide".into(),
                    ..Default::default()
                },
                Result {
                    url: "https://example.org/article".into(),
                    title: "An article".into(),
                    ..Default::default()
                },
                Result {
                    url: "https://www.youtube.com/shorts/directories".into(),
                    title: "Directories".into(),
                    snippet: "Developer Channel • 567 views".into(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let dom = document(&youtube("paths <files> & directories", &record));
        let form = dom.select_first("form[role=search]").unwrap();
        assert_eq!(form.attributes.borrow().get("action"), Some("/results"));
        let field = dom.select_first("input[name=search_query]").unwrap();
        assert_eq!(
            field.attributes.borrow().get("value"),
            Some("paths <files> & directories")
        );
        let cards = dom.select(".video-result").unwrap().collect::<Vec<_>>();
        assert_eq!(cards.len(), 2);
        for (card, index) in cards.iter().zip([0, 2]) {
            let result = &record.results[index];
            assert_eq!(
                card.as_node().select_first("h2").unwrap().text_contents(),
                result.title
            );
            assert_eq!(
                card.as_node()
                    .select_first("h2 a")
                    .unwrap()
                    .attributes
                    .borrow()
                    .get("href"),
                Some(result.url.as_str())
            );
            let image = card.as_node().select_first("img").unwrap();
            assert!(
                image
                    .attributes
                    .borrow()
                    .get("src")
                    .unwrap()
                    .starts_with("data:image/svg+xml,")
            );
            assert!(card.text_contents().contains(&result.snippet));
        }
        assert_eq!(
            cards[0]
                .as_node()
                .select_first(".channel")
                .unwrap()
                .text_contents(),
            "Python Channel"
        );
        assert_eq!(
            cards[0]
                .as_node()
                .select_first(".views")
                .unwrap()
                .text_contents(),
            "12,345 views"
        );
        assert!(dom.select_first(".video-player").is_err());
        let empty = youtube("directories", &Search::default());
        assert!(empty.contains("No videos found"));
        assert!(!empty.contains("12,345"));
    }

    #[test]
    fn captured_results_keep_styles_and_replace_the_list() {
        let record = record();
        for engine in [Engine::Google, Engine::Bing, Engine::DuckDuckGo] {
            let layout = layout(engine);
            let original = document(source(layout.host, "/").unwrap());
            let html = captured(engine, "paths <files> & directories", &record, 0)
                .unwrap()
                .unwrap();
            let dom = document(&html);
            let result = one(&dom, layout.organic).unwrap();
            assert_eq!(
                one(&result, layout.title).unwrap().text_contents(),
                record.results[0].title
            );
            assert_eq!(
                result
                    .select("a")
                    .unwrap()
                    .next()
                    .unwrap()
                    .attributes
                    .borrow()
                    .get("href"),
                Some(
                    if engine == Engine::DuckDuckGo {
                        ddg_link(&record.results[0].url)
                    } else {
                        record.results[0].url.clone()
                    }
                    .as_str()
                )
            );
            assert!(
                one(&result, layout.snippet)
                    .unwrap()
                    .text_contents()
                    .contains(&record.results[0].snippet)
            );
            assert_eq!(dom.select(layout.organic).unwrap().count(), 1);
            assert!(
                one(&dom, layout.ad)
                    .unwrap()
                    .text_contents()
                    .contains("Storage")
            );
            assert_eq!(
                dom.select("link[rel=stylesheet]").unwrap().count(),
                original.select("link[rel=stylesheet]").unwrap().count() + 1
            );
            assert!(dom.select_first("link[href=\"/search.css\"]").is_ok());
            for sheet in original.select("link[rel=stylesheet]").unwrap() {
                let href = sheet.attributes.borrow().get("href").unwrap().to_owned();
                assert!(dom.select_first(&format!("link[href=\"{href}\"]")).is_ok());
            }
            let field = dom.select_first("[name=q]").unwrap();
            let query = if field.name.local.as_ref() == "textarea" {
                field.text_contents()
            } else {
                field.attributes.borrow().get("value").unwrap().to_owned()
            };
            assert_eq!(query, "paths <files> & directories");
            assert_eq!(dom.select("script").unwrap().count(), 0);
            let later = document(&captured(engine, "paths", &record, 10).unwrap().unwrap());
            assert_eq!(later.select(layout.ad).unwrap().count(), 0);
            assert!(!html.to_lowercase().contains("rust programming"));
        }
    }

    #[test]
    fn missing_and_changed_layouts_use_the_built_in_pages() {
        for engine in [Engine::Google, Engine::Bing, Engine::DuckDuckGo] {
            let error = results(
                "<html><title>Search</title><body></body></html>",
                engine,
                "paths",
                &record(),
                0,
            )
            .unwrap_err();
            assert!(error.contains(layout(engine).list));
            let html = source(layout(engine).host, "/").unwrap().replace(
                layout(engine).organic.split('.').next_back().unwrap(),
                "changed-result",
            );
            assert!(results(&html, engine, "paths", &record(), 0).is_err());
            let fallback = render_with(None, engine, "paths", &record(), 0);
            assert!(fallback.contains("/search.css"));
            assert!(fallback.contains("Paths &lt;files&gt; &amp; directories"));
            assert_eq!(
                render_with(Some(&html), engine, "paths", &record(), 0),
                fallback
            );
        }
    }

    #[test]
    fn sponsored_fallback_has_explicit_styles_and_no_source_content() {
        let html = render(Engine::Google, "file storage", &record(), 0);
        let dom = document(&html);
        let ad = one(&dom, ".uEierd").unwrap();
        assert!(ad.text_contents().contains("Sponsored"));
        assert!(ad.text_contents().contains("Storage"));
        assert!(ad.text_contents().contains("Keep your files."));
        assert_eq!(
            one(&ad, "a")
                .unwrap()
                .as_element()
                .unwrap()
                .attributes
                .borrow()
                .get("href"),
            Some("https://shop.example.net/")
        );
        assert!(CSS.contains(".uEierd [role=heading] { font-size: 20px"));
        assert!(CSS.contains(".uEierd .U3A9Ac { display: block"));
    }

    #[test]
    fn counts_and_urls() {
        assert_eq!(result_count(10), "10");
        assert_eq!(result_count(0), "0");
        assert_eq!(result_count(12_078_810), "12,078,810");
        assert_eq!(
            display_url("https://User@EXAMPLE.com/a//b/é/d?q=x"),
            "example.com › a › b › é"
        );
        assert_eq!(
            links(&render(Engine::Google, "paths", &record(), 0)),
            vec![(
                record().results[0].url.clone(),
                record().results[0].title.clone()
            )]
        );
    }
}
