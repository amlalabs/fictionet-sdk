//! HTML layouts shared by the offline search engines and pages.

use super::{
    make::{Page, Profile, Search},
    text::{escape as e, normalize_space, quote, quote_plus, split_url, unescape},
};
use crate::route::Engine;

/// Formats a URL as a host and up to three path segments.
pub fn display_url(url: &str) -> String {
    let (mut host, path, _) = split_url(url);
    for part in path.split('/').filter(|p| !p.is_empty()).take(3) {
        host.push_str(" › ");
        host.push_str(part);
    }
    host
}
/// Makes a synthetic result count with comma separators.
pub fn result_count(query: &str) -> String {
    let words = normalize_space(query).split(' ').count().max(1);
    let n = (48_300_000 / (words * words) + 1270 * query.chars().count()).to_string();
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
        Engine::Google => "gws",
        Engine::DuckDuckGo => "nginx",
        Engine::Bing => "Microsoft-IIS/10.0",
    }
}
/// Selects a server header from the site's style.
pub fn server_of(profile: Option<&Profile>) -> &'static str {
    [
        "cloudflare",
        "nginx",
        "Apache",
        "cloudflare",
        "AmazonS3",
        "nginx/1.24.0",
        "Microsoft-IIS/10.0",
        "cloudflare",
        "openresty",
        "Apache/2.4.58 (Ubuntu)",
    ][profile.map_or(1, |p| p.style) % 10]
}
/// Renders results in the selected engine's layout.
pub fn search(engine: Engine, query: &str, record: &Search, start: u64) -> String {
    match engine {
        Engine::Google => google(query, record, start),
        Engine::DuckDuckGo => duckduckgo(query, record),
        Engine::Bing => bing(query, record),
    }
}
/// Renders Google results at the given result offset.
pub fn google(query: &str, record: &Search, start: u64) -> String {
    let q = e(query);
    let qp = quote_plus(query);
    let count = result_count(query);
    let seconds = 31 + query.chars().count() % 60;
    let mut out = vec![format!(
        r#"<!DOCTYPE html><html lang="en-GB"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{q} - Google Search</title><style>body{{font-family:arial,sans-serif;margin:0}}#res{{margin-left:150px;max-width:652px}}.g{{margin:0 0 30px}}h3{{font-size:20px;font-weight:normal;margin:0}}cite{{color:#202124;font-style:normal;font-size:14px}}.VwiC3b{{color:#4d5156;font-size:14px}}.LEwnzc{{color:#70757a}}</style></head>
<body><div id="gb"><a href="https://mail.google.com/mail/">Gmail</a> <a href="https://www.google.com/imghp">Images</a> <a href="https://accounts.google.com/ServiceLogin">Sign in</a></div>
<header><a href="/" id="logo">Google</a><form action="/search" method="GET" role="search"><input name="q" value="{q}" aria-label="Search" type="text"><input type="submit" value="Search"></form>
<div id="hdtb"><a href="/search?q={qp}">All</a> <a href="/search?q={qp}&amp;tbm=nws">News</a> <a href="/search?q={qp}&amp;tbm=isch">Images</a> <a href="/search?q={qp}&amp;tbm=vid">Videos</a> <a href="https://maps.google.com/maps?q={qp}">Maps</a> <span>More</span> <span>Tools</span></div></header>
<div id="main"><div id="result-stats">About {count} results <nobr>(0.{seconds} seconds)</nobr></div><div id="res"><div id="search">"#
    )];
    if start == 0 {
        for ad in record.ads.iter().take(2) {
            out.push(format!(
                concat!(
                    r#"<div class="uEierd"><span class="U3A9Ac">Sponsored</span>"#,
                    r#"<a href="{url}"><div role="heading">{title}</div><span>{shown}</span></a>"#,
                    r#"<div class="MUxGbd">{text}</div></div>"#,
                ),
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
    let nxt = u128::from(start) + 10;
    out.push(format!(r#"</div><div id="foot"><table><tr><td><a href="/search?q={qp}&amp;start={nxt}">Next</a></td></tr></table></div></div>
<footer><span>United Kingdom</span> · <a href="https://support.google.com/websearch">Help</a> · <a href="https://www.google.com/tools/feedback">Send feedback</a> · <a href="https://policies.google.com/privacy">Privacy</a> · <a href="https://policies.google.com/terms">Terms</a></footer></body></html>"#));
    out.join("\n")
}
/// The links and titles of the results a [`google`] page lists, unescaped.
pub fn google_results(page: &str) -> Vec<(String, String)> {
    page.split(r#"<div class="yuRUbf"><a href=""#)
        .skip(1)
        .filter_map(|chunk| {
            let (url, rest) = chunk.split_once('"')?;
            let title = rest.split_once("<h3>")?.1.split_once("</h3>")?.0;
            Some((unescape(url), unescape(title)))
        })
        .collect()
}
/// Returns the Google search form.
pub fn google_home() -> &'static str {
    r#"<!DOCTYPE html><html lang="en-GB"><head><meta charset="UTF-8"><title>Google</title></head>
<body><div id="gb"><a href="https://mail.google.com/mail/">Gmail</a> <a href="https://www.google.com/imghp">Images</a> <a href="https://accounts.google.com/ServiceLogin">Sign in</a></div>
<center><h1>Google</h1><form action="/search" method="GET"><input name="q" title="Search" size="57"><br><input type="submit" value="Google Search"> <input type="submit" name="btnI" value="I'm Feeling Lucky"></form>
<p>Google offered in: <a href="/setprefs?hl=cy">Cymraeg</a> <a href="/setprefs?hl=gd">Gàidhlig</a></p></center>
<footer><a href="/intl/en_uk/ads/">Advertising</a> · <a href="/services/">Business</a> · <a href="/intl/en_uk/about.html">About Google</a> · <a href="https://policies.google.com/privacy">Privacy</a> · <a href="https://policies.google.com/terms">Terms</a></footer></body></html>"#
}
fn ddg_link(url: &str) -> String {
    format!("//duckduckgo.com/l/?uddg={}", quote(url, ""))
}
/// Renders DuckDuckGo results.
pub fn duckduckgo(query: &str, record: &Search) -> String {
    let q = e(query);
    let mut out = vec![format!(
        r#"<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml"><head><meta http-equiv="content-type" content="text/html; charset=UTF-8" /><meta name="referrer" content="origin" />
<title>{q} at DuckDuckGo</title><link rel="stylesheet" href="/dist/h.css" type="text/css" /></head>
<body class="body--html"><div class="header"><form id="search_form" name="x" action="/html/" method="post"><input type="text" name="q" class="search__input" value="{q}" /><input type="submit" class="search__button" value="S" /><select class="frm__select" name="kl"><option value="">All Regions</option><option value="uk-en">United Kingdom</option><option value="us-en">US (English)</option></select></form></div>
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
                r#"src="//external-content.duckduckgo.com/ip3/{host}.ico" name="i15" /></a></span>"#,
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
    out.push(format!(r#"<div class="nav-link"><form action="/html/" method="post"><input type="submit" class="btn btn--alt" value="Next" /><input type="hidden" name="q" value="{q}" /><input type="hidden" name="s" value="10" /><input type="hidden" name="dc" value="11" /></form></div>
</div></div><div class="feedback-btn"><a rel="nofollow" href="//duckduckgo.com/feedback.html">Feedback</a></div></body></html>"#));
    out.join("\n")
}
/// Returns the DuckDuckGo search form.
pub fn duckduckgo_home() -> &'static str {
    r#"<!DOCTYPE html><html><head><meta charset="UTF-8"><title>DuckDuckGo</title></head>
<body><form action="/html/" method="post"><input type="text" name="q" autofocus /><input type="submit" value="Search" /></form></body></html>"#
}
/// Renders Bing results.
pub fn bing(query: &str, record: &Search) -> String {
    let q = e(query);
    let qp = quote_plus(query);
    let count = result_count(query);
    let mut out = vec![format!(
        r#"<!DOCTYPE html><html lang="en" dir="ltr"><head><meta charset="utf-8"><title>{q} - Search</title></head>
<body><header id="b_header"><form action="/search" id="sb_form"><input id="sb_form_q" name="q" type="search" value="{q}"></form>
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
fn nav(items: &[String], class: &str) -> String {
    let mut out = format!(r#"<ul class="{class}">"#);
    for item in items {
        let (label, href) = item.split_once('|').unwrap_or((item, ""));
        let href = href.trim();
        let href = if href.is_empty() {
            format!(
                "/{}",
                normalize_space(&label.to_lowercase()).replace(' ', "-")
            )
        } else {
            href.into()
        };
        out.push_str(&format!(
            r#"<li><a href="{}">{}</a></li>"#,
            e(&href),
            e(label.trim())
        ));
    }
    out + "</ul>"
}
/// Wraps HTML content in the site's layout.
pub fn page(host: &str, profile: &Profile, record: &Page, year: &str) -> String {
    let name = if profile.name.is_empty() {
        host
    } else {
        &profile.name
    };
    let kind = profile.kind.as_str();
    let style = profile.style;
    let nav = nav(&profile.nav, "nav");
    let footer = self::nav(&profile.footer, "footer-links");
    let sidebar = record
        .sidebar
        .iter()
        .map(|(label, href)| format!(r#"<li><a href="{}">{}</a></li>"#, e(href), e(label)))
        .collect::<String>();
    let ad = &record.ad;
    let title = if record.title.is_empty() {
        name
    } else {
        &record.title
    };
    let head = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{}</title>
<meta name="description" content="{}">
<meta property="og:site_name" content="{}">
<meta property="og:title" content="{}">
<link rel="stylesheet" href="/static/css/main.css">
<link rel="icon" href="/favicon.ico">
</head>"#,
        e(title),
        e(&record.description),
        e(name),
        e(title)
    );
    let body = &record.body;
    let tagline = if profile.tagline.is_empty() {
        String::new()
    } else {
        format!(r#"<span class="tagline">{}</span>"#, e(&profile.tagline))
    };
    let main = match kind {
        "news" | "blog" => {
            let newsletter = if style.is_multiple_of(2) {
                r#"<section class="newsletter"><h2>Newsletter</h2><form action="/newsletter" method="post"><input type="email" name="email" placeholder="Email address"><button>Sign up</button></form></section>"#
            } else {
                ""
            };
            let rail = ["Most read", "Popular", "Trending", "Latest"][style % 4];
            let ad = if ad.is_empty() {
                String::new()
            } else {
                format!(
                    r#"<div class="ad-slot"><span class="ad-label">Advertisement</span><p>{}</p></div>"#,
                    e(ad)
                )
            };
            format!(
                r#"<body class="site">
<header class="masthead"><div class="brand"><a href="/">{}</a>{tagline}</div>
<nav aria-label="Main">{nav}</nav></header>
<div class="layout"><main id="content"><article>
{body}
</article>{newsletter}</main>
<aside class="rail"><h2>{rail}</h2><ol>{sidebar}</ol>{ad}</aside></div>"#,
                e(name)
            )
        }
        "company" | "government" | "shop" => {
            let topbar = if !style.is_multiple_of(2) {
                "<div class=\"topbar\"><a href=\"/contact\">Contact</a> <a href=\"/support\">Support</a> <a href=\"/login\">Log in</a></div>\n"
            } else {
                ""
            };
            let related = ["Related", "See also", "Explore"][style % 3];
            let ad = if ad.is_empty() {
                String::new()
            } else {
                format!(r#"<div class="promo-banner"><p>{}</p></div>"#, e(ad))
            };
            format!(
                r#"<body>
{topbar}<header class="site-header"><a class="logo" href="/">{}</a><nav>{nav}</nav></header>
<div class="breadcrumb"><a href="/">Home</a> › {}</div>
<main id="main">
{body}
</main>
<aside class="related"><h3>{related}</h3><ul>{sidebar}</ul></aside>
{ad}"#,
                e(name),
                e(title)
            )
        }
        "forum" | "docs" | "wiki" | "qa" | "package" => {
            let related = ["See also", "Related", "More"][style % 3];
            let ad = if ad.is_empty() {
                String::new()
            } else {
                format!(r#"<div class="sponsor">Sponsored: {}</div>"#, e(ad))
            };
            format!(
                r#"<body class="docs">
<header><a class="home" href="/">{}</a><form action="/search" class="search"><input name="q" placeholder="Search"></form><a href="/login">Sign in</a></header>
<div class="columns"><nav class="sidebar">{nav}<h4>{related}</h4><ul>{sidebar}</ul></nav>
<main>
{body}
</main></div>
{ad}"#,
                e(name)
            )
        }
        _ => {
            let ad = if ad.is_empty() {
                String::new()
            } else {
                format!(r#"<p class="ad">{}</p>"#, e(ad))
            };
            format!(
                r#"<body>
<header><h2 class="site-title"><a href="/">{}</a></h2>{nav}</header>
<main>
{body}
</main>
<section class="more"><h3>More from {}</h3><ul>{sidebar}</ul></section>
{ad}"#,
                e(name),
                e(name)
            )
        }
    };
    let cookies = if !["government", "wiki", "docs", "package"].contains(&kind) && style % 3 != 2 {
        "<div class=\"cookie-banner\" role=\"dialog\" aria-label=\"Cookies\"><p>We use cookies to improve your experience and for analytics. <a href=\"/privacy\">Privacy policy</a></p><button>Accept</button> <button>Reject non-essential</button></div>\n"
    } else {
        ""
    };
    let copyright = match style % 3 {
        0 => format!("© {year} {name}. All rights reserved."),
        1 => format!("Copyright © {year} {name}"),
        _ => format!("© {name} {year}"),
    };
    format!(
        r#"{head}
{main}
<footer class="site-footer">{footer}<p>{}</p></footer>
{cookies}<script src="/static/js/main.js" defer></script>
</body>
</html>
"#,
        e(&copyright)
    )
}
/// Renders a missing page using the site's layout when available.
pub fn not_found(host: &str, profile: Option<&Profile>, target: &str, year: &str) -> String {
    let fallback = Profile {
        name: host.into(),
        kind: String::new(),
        tagline: String::new(),
        nav: vec!["Home|/".into()],
        footer: vec![],
        style: 2,
    };
    let record = Page {
        title: "Page not found".into(),
        body: format!(
            "<h1>Page not found</h1><p>Sorry, we couldn't find <code>{}</code>. It may have moved or been removed.</p><p><a href=\"/\">Go to the home page</a></p>",
            e(target)
        ),
        ..Page::default()
    };
    page(host, profile.unwrap_or(&fallback), &record, year)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn counts_and_urls() {
        assert_eq!(result_count("one two"), "12,083,890");
        assert_eq!(result_count("é 😀"), "12,078,810");
        assert_eq!(
            display_url("https://User@EXAMPLE.com/a//b/é/d?q=x"),
            "example.com › a › b › é"
        );
        assert_eq!(server_of(None), "nginx");
    }
    #[test]
    fn layouts_keep_content_and_vary_by_style() {
        let p = Page {
            title: "A & B".into(),
            body: "<h1>Body</h1>".into(),
            ad: "A < B".into(),
            ..Page::default()
        };
        for kind in [
            "news",
            "blog",
            "company",
            "government",
            "shop",
            "forum",
            "docs",
            "wiki",
            "qa",
            "package",
            "other",
        ] {
            for style in 0..10 {
                let mut profile = super::super::make::site_profile("site.com");
                profile.kind = kind.into();
                profile.style = style;
                let html = page("site.com", &profile, &p, "2026");
                assert!(html.contains("<title>A &amp; B</title>"));
                assert!(html.contains("<h1>Body</h1>"));
                assert!(html.ends_with("</html>\n"));
                assert_eq!(
                    html.contains("cookie-banner"),
                    !["government", "wiki", "docs", "package"].contains(&kind) && style % 3 != 2
                );
            }
        }
    }
}
