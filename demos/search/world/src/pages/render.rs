//! Generic layouts for hosts without a bundled skin.

use super::{
    make::{Page, Profile, SiteKind},
    text::escape as e,
};

pub(crate) use super::normalize::*;

pub(crate) use super::layout::{cookie_host, cookie_words, counted, nav, question_body};
pub use super::layout::{favicon, server_of};

/// Wraps HTML content in the site's layout.
pub fn page(host: &str, profile: &Profile, record: &Page, today: &str) -> String {
    page_at(host, "/", profile, record, today)
}

/// Renders a page using the captured section layout when available.
pub fn page_at(host: &str, target: &str, profile: &Profile, record: &Page, today: &str) -> String {
    let (title, body) = counted(&record.title, &record.body);
    let adjusted = Page {
        title,
        body,
        ..record.clone()
    };
    let record = &adjusted;
    let question;
    let record = if profile.kind == SiteKind::Qa {
        question = Page {
            body: question_body(record, today),
            ..record.clone()
        };
        &question
    } else {
        record
    };
    let path = target.split('?').next().unwrap_or(target);
    let forum_listing = profile.kind == SiteKind::Forum
        && ["/", "/search", "/search/", "/latest", "/categories", "/top"].contains(&path);
    if !forum_listing
        && let Some(skin) = fictionet_extras::sites::lookup(host, target)
        && let Ok(today) = super::seed::parse_date(today)
        && let Some(html) = skin.render(
            &record.title,
            &record.body,
            super::seed::parse_date(&record.date).unwrap_or(today),
            today,
        )
    {
        use kuchiki::traits::TendrilSink;
        let dom = kuchiki::parse_html().one(html.as_str());
        let mut changed = false;
        let lists: Vec<_> = dom.select("ul, ol").unwrap().collect();
        for list in lists {
            if list.as_node().text_contents().trim().is_empty()
                && list.as_node().select("li").unwrap().next().is_none()
                && let Some(panel) = list.as_node().parent()
                && panel
                    .select("h1, h2, h3, h4, h5, h6")
                    .unwrap()
                    .next()
                    .is_some()
                && panel
                    .select("a, p, img, table, input, pre")
                    .unwrap()
                    .next()
                    .is_none()
            {
                panel.detach();
                changed = true;
            }
        }
        return if changed { dom.to_string() } else { html };
    }
    let year = today.get(..4).unwrap_or(today);
    let name = if profile.name.is_empty() {
        host
    } else {
        &profile.name
    };
    let kind = profile.kind;
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
    let title = super::make::heading(title);
    let body = &record.body;
    let flights = super::make::words(title)
        .iter()
        .any(|word| ["flight", "flights", "airfare", "airline"].contains(&word.as_str()));
    let tagline = if profile.tagline.is_empty() {
        String::new()
    } else {
        format!(r#"<span class="tagline">{}</span>"#, e(&profile.tagline))
    };
    let main = match kind {
        SiteKind::Listings | SiteKind::Lodging | SiteKind::Howto => format!(
            r#"<body class="{kind}"><header><div class="brand"><a href="/">{}</a></div><nav>{nav}</nav></header><div class="site-content"><p class="page-breadcrumb"><a href="/">Home</a> › {}</p><div class="filters"><span>{}</span><span>{}</span><span>{}</span></div><article>{body}</article></div></body></html>"#,
            e(name),
            e(title),
            if flights {
                "Flights"
            } else if kind == SiteKind::Lodging {
                "Stays"
            } else if kind == SiteKind::Listings {
                "Restaurants"
            } else {
                "Steps"
            },
            if flights {
                "Connections"
            } else if kind == SiteKind::Lodging {
                "Room type"
            } else if kind == SiteKind::Listings {
                "Cuisine"
            } else {
                "Tips"
            },
            if kind == SiteKind::Listings {
                "Price"
            } else {
                "Related articles"
            }
        ),
        SiteKind::News | SiteKind::Blog => {
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
        SiteKind::Company
        | SiteKind::Government
        | SiteKind::Shop
        | SiteKind::Weather
        | SiteKind::Review
        | SiteKind::Marketplace
        | SiteKind::Advisory => {
            let topbar = if !style.is_multiple_of(2) {
                "<div class=\"topbar\"><a href=\"/contact\">Contact</a> <a href=\"/support\">Support</a> <a href=\"/login\">Log in</a></div>\n"
            } else {
                ""
            };
            let related = ["Related", "See also", "Explore"][style % 3];
            let related = if sidebar.is_empty() {
                String::new()
            } else {
                format!(r#"<aside class="related"><h3>{related}</h3><ul>{sidebar}</ul></aside>"#)
            };
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
{related}
{ad}"#,
                e(name),
                e(title)
            )
        }
        SiteKind::Qa => format!(
            r#"<body class="qa"><header><a class="home" href="/">{}</a><form action="/search" class="search"><input name="q" aria-label="Search" placeholder="Search"></form><a href="/login">Sign in</a></header><main class="{}">{body}</main>"#,
            e(name),
            if host.contains("quora.com") {
                "answer-cards"
            } else {
                "questions"
            }
        ),
        SiteKind::Forum | SiteKind::Docs | SiteKind::Wiki | SiteKind::Package => {
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
    let cookies = if ![
        SiteKind::Government,
        SiteKind::Wiki,
        SiteKind::Docs,
        SiteKind::Package,
    ]
    .contains(&kind)
        && cookie_host(host)
    {
        let (message, accept, reject) = cookie_words(host);
        r#"<div class="cookie-banner" style="position:fixed;bottom:0;left:0;right:0;z-index:100;background:white;display:flex;align-items:center;gap:12px;padding:8px 20px;border-top:1px solid #bdc6d1;font:14px/1.4 system-ui,sans-serif" role="dialog" aria-label="Cookies"><p style="margin:0;flex:1">{message} <a href="/privacy">Privacy policy</a></p><button style="padding:6px 12px;margin:0" data-choice="accept">{accept}</button><button style="padding:6px 12px;margin:0" data-choice="reject">{reject}</button></div><script>(()=>{const bar=document.querySelector('.cookie-banner');let choice='seen';const remember=(value)=>{choice=value;document.cookie='site_cookies='+value+'; Max-Age=31536000; Path=/; SameSite=Lax';};if(document.cookie.split(';').some(value=>value.trim().startsWith('site_cookies='))){bar.remove();return;}remember('seen');bar.querySelectorAll('button').forEach(button=>button.addEventListener('click',()=>{remember(button.dataset.choice);bar.remove();}));window.addEventListener('pagehide',()=>remember(choice),{once:true});})();</script>"#.replace("{message}", message).replace("{accept}", accept).replace("{reject}", reject)
    } else {
        String::new()
    };
    let copyright = match style % 3 {
        0 => format!("© {year} {name}. All rights reserved."),
        1 => format!("Copyright © {year} {name}"),
        _ => format!("© {name} {year}"),
    };
    let main = if sidebar.is_empty() {
        let main = main.replace(
            &format!(
                "<h4>{}</h4><ul></ul>",
                ["See also", "Related", "More"][style % 3]
            ),
            "",
        );
        main.replace(
            &format!(
                r#"<section class="more"><h3>More from {}</h3><ul></ul></section>"#,
                e(name)
            ),
            "",
        )
        .replace(
            &format!(
                r#"<aside class="rail"><h2>{}</h2><ol></ol></aside>"#,
                ["Most read", "Popular", "Trending", "Latest"][style % 4]
            ),
            "",
        )
    } else {
        main
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
/// A stored page on a host with a captured layout, laid out again with the
/// layout as it is now. None for a page on any other host, or unchanged.
pub fn again(
    host: &str,
    target: &str,
    title: &str,
    html: &str,
    date: &str,
    today: &str,
) -> Option<String> {
    let path = target.split('?').next().unwrap_or(target);
    if super::make::site_profile(host).kind == SiteKind::Forum
        && ["/", "/search", "/search/", "/latest", "/categories", "/top"].contains(&path)
    {
        return None;
    }
    let profile = super::make::site_profile(host);
    let skin = fictionet_extras::sites::lookup(host, target);
    if skin.is_none() && profile.kind != SiteKind::Qa {
        return None;
    }
    let today = super::seed::parse_date(today).ok()?;
    let published = super::seed::parse_date(date).unwrap_or(today);
    use kuchiki::traits::TendrilSink;
    let content = skin.and_then(|skin| skin.content(html)).or_else(|| {
        let dom = kuchiki::parse_html().one(html);
        let main = dom
            .select_first("main")
            .or_else(|_| dom.select_first("article"))
            .or_else(|_| dom.select_first("body"))
            .ok()?;
        Some(main.as_node().children().map(|n| n.to_string()).collect())
    })?;
    let page = page_at(
        host,
        target,
        &super::make::site_profile(host),
        &Page {
            title: title.into(),
            body: content,
            date: published.to_string(),
            ..Page::default()
        },
        &today.to_string(),
    );
    (page != html).then_some(page)
}

/// Renders a missing page using the site's layout when available.
pub fn not_found(host: &str, profile: Option<&Profile>, target: &str, year: &str) -> String {
    let fallback = super::make::site_profile(host);
    let record = Page {
        title: "Page not found".into(),
        body: format!(
            "<h1>Page not found</h1><p>Sorry, we couldn't find <code>{}</code>. It may have moved or been removed.</p><p><a href=\"/\">Go to the home page</a></p>",
            e(target)
        ),
        ..Page::default()
    };
    page_at(host, target, profile.unwrap_or(&fallback), &record, year)
}
