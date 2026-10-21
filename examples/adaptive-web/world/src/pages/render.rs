//! Generic layouts for hosts without a bundled skin.

use super::{
    make::{Page, Profile},
    text::{escape as e, normalize_space},
};

/// Returns a host's tab icon.
pub fn favicon(host: &str) -> String {
    let lower = host.to_lowercase();
    let key = lower.strip_prefix("www.").unwrap_or(&lower);
    let hash = key.bytes().fold(0x811c9dc5u32, |n, b| {
        (n ^ u32::from(b)).wrapping_mul(0x01000193)
    });
    let hue = f64::from(hash % 360) / 60.0;
    let chroma = (1.0 - (2.0 * 0.36f64 - 1.0).abs()) * 0.52;
    let x = chroma * (1.0 - (hue % 2.0 - 1.0).abs());
    let (r, g, b) = match hue as u8 {
        0 => (chroma, x, 0.0),
        1 => (x, chroma, 0.0),
        2 => (0.0, chroma, x),
        3 => (0.0, x, chroma),
        4 => (x, 0.0, chroma),
        _ => (chroma, 0.0, x),
    };
    let channel = |v: f64| ((v + 0.36 - chroma / 2.0) * 255.0).round() as u8;
    let color = format!("#{:02x}{:02x}{:02x}", channel(r), channel(g), channel(b));
    let letter = key.chars().next().unwrap_or('?').to_uppercase().to_string();
    let (color, letter) = match key {
        "google.com" => ("#4285f4", "G"),
        "bing.com" => ("#00809d", "B"),
        "duckduckgo.com" | "html.duckduckgo.com" | "lite.duckduckgo.com" => ("#de5833", "D"),
        "reddit.com" => ("#ff4500", "R"),
        "github.com" => ("#181717", "G"),
        "wikipedia.org" => ("#333333", "W"),
        _ if key.ends_with(".wikipedia.org") => ("#333333", "W"),
        _ => (color.as_str(), letter.as_str()),
    };
    let mark = if matches!(key, "youtube.com" | "youtu.be") {
        r##"<rect x="1" y="5" width="30" height="22" rx="6" fill="#ff0000"/><path d="m13 10 10 6-10 6Z" fill="white"/>"##.into()
    } else {
        format!(
            r#"<rect width="32" height="32" rx="16" fill="{color}"/><text x="16" y="17" dominant-baseline="middle" text-anchor="middle" font-family="Arial,sans-serif" font-size="21" font-weight="700" fill="white">{}</text>"#,
            e(letter)
        )
    };
    format!(
        r#"<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 32 32">{mark}</svg>"#
    )
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
fn question_body(record: &Page) -> String {
    use kuchiki::traits::TendrilSink;
    let dom = kuchiki::parse_html().one(record.body.as_str());
    if dom.select_first(".question-post").is_ok() {
        return record.body.clone();
    }
    let posts = dom.select(".post").unwrap().collect::<Vec<_>>();
    if posts.is_empty() {
        return record.body.clone();
    }
    let mut out = format!(
        "<h1>{}</h1><p class=\"question-meta\">Asked 3 days ago · Modified today · Viewed 960 times</p>",
        e(super::make::heading(&record.title))
    );
    for (index, post) in posts.iter().enumerate() {
        let (class, score, mark) = if index == 0 {
            ("question-post", 12, "")
        } else if index == 1 {
            (
                "answer accepted",
                24,
                "<span class=\"accepted-mark\" role=\"img\" aria-label=\"Accepted answer\">✓</span>",
            )
        } else {
            ("answer", 7, "")
        };
        if index == 1 {
            out.push_str(&format!(
                "<h2>{} {}</h2>",
                posts.len() - 1,
                if posts.len() == 2 {
                    "answer"
                } else {
                    "answers"
                }
            ));
        }
        let body = post
            .as_node()
            .children()
            .map(|n| n.to_string())
            .collect::<String>();
        out.push_str(&format!(
            "<section class=\"{class}\"><div class=\"votes\">{score}{mark}</div><div>{body}"
        ));
        if index == 0 {
            let tags = super::make::words(&record.title)
                .into_iter()
                .filter(|s| s.len() > 3)
                .take(3)
                .map(|tag| format!("<span>{}</span>", e(&tag)))
                .collect::<String>();
            out.push_str(&format!("<div class=\"tags\">{tags}</div>"));
        }
        out.push_str("</div></section>");
    }
    out
}

fn host_hash(host: &str) -> usize {
    host.trim_start_matches("www.")
        .bytes()
        .fold(0usize, |n, b| n.wrapping_mul(31).wrapping_add(b as usize))
}

pub(super) fn cookie_host(host: &str) -> bool {
    host_hash(host).is_multiple_of(4)
}

pub(super) fn cookie_words(host: &str) -> (&'static str, &'static str, &'static str) {
    match host_hash(host) % 3 {
        0 => (
            "Cookies help us remember your preferences.",
            "Got it",
            "Manage choices",
        ),
        1 => (
            "Choose how cookies are used on this site.",
            "Allow all",
            "Only essential",
        ),
        _ => (
            "We use cookies to improve your visit.",
            "Accept cookies",
            "No thanks",
        ),
    }
}

fn hero(title: &str, name: &str) -> String {
    let hash = host_hash(title);
    let accent = if hash.is_multiple_of(2) {
        "var(--accent, var(--app-photo-warm))"
    } else {
        "var(--app-mem, var(--app-photo-cool))"
    };
    let mut shapes = String::new();
    for index in 0..6 + hash % 4 {
        let mut n = (hash as u64).wrapping_add((index as u64 + 1).wrapping_mul(0x9e3779b97f4a7c15));
        n = (n ^ (n >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        n = (n ^ (n >> 27)).wrapping_mul(0x94d049bb133111eb);
        n ^= n >> 31;
        let x = n % 840;
        let y = n.rotate_left(13) % 360;
        let width = 90 + n.rotate_left(7) % 330;
        let height = 35 + n.rotate_left(19) % 155;
        let opacity = 25 + n % 45;
        let color = if index % 3 == 0 {
            accent
        } else if index % 3 == 1 {
            "var(--app-ink, currentColor)"
        } else {
            "var(--app-pane, var(--app-photo-paper))"
        };
        if index.is_multiple_of(2) {
            shapes.push_str(&format!(
                r#"<ellipse cx="{x}" cy="{y}" rx="{width}" ry="{height}" fill="{color}" opacity=".{opacity}"/>"#
            ));
        } else {
            shapes.push_str(&format!(
                r#"<rect x="{x}" y="{y}" width="{width}" height="{height}" rx="{}" transform="rotate({} {x} {y})" fill="{color}" opacity=".{opacity}"/>"#,
                height / 2,
                (n % 70) as isize - 35,
            ));
        }
    }
    format!(
        r#"<figure class="article-hero" style="width:100%;margin:24px 0;--app-photo-paper:light-dark(#ffffff,#141917);--app-photo-warm:light-dark(#df5835,#f0704c);--app-photo-cool:light-dark(#2552c4,#86a4f6);--app-photo-mute:light-dark(#5d6761,#93a09a)"><svg role="img" aria-label="{}" viewBox="0 0 840 360" preserveAspectRatio="xMidYMid slice" style="display:block;width:100%;height:auto;aspect-ratio:21/9;max-height:300px;overflow:hidden"><defs><linearGradient id="article-ground" x1="0" y1="0" x2="1" y2="1"><stop stop-color="var(--app-pane, var(--app-photo-paper))"/><stop offset="1" stop-color="var(--accent, var(--app-ink, currentColor))"/></linearGradient><filter id="article-blur" x="-30%" y="-50%" width="160%" height="200%"><feGaussianBlur stdDeviation="24"/></filter></defs><rect width="840" height="360" fill="url(#article-ground)"/><g filter="url(#article-blur)">{shapes}</g></svg><figcaption style="color:var(--app-mute, var(--app-photo-mute));font:12px/1.5 system-ui,sans-serif;margin-top:6px">Photo: {}</figcaption></figure>"#,
        e(title),
        e(name)
    )
}

/// Aligns a numbered list title with its main list or comparison table.
pub(super) fn counted(title: &str, html: &str) -> (String, String) {
    use kuchiki::traits::TendrilSink;
    use std::sync::OnceLock;
    static NUMBER: OnceLock<regex::Regex> = OnceLock::new();
    let re = NUMBER.get_or_init(|| {
        regex::Regex::new(r"(?i)^(?:the )?(\d{1,2}) (?:best|top|ways|tips|steps|things|reasons)\b")
            .unwrap()
    });
    let Some(caps) = re.captures(title) else {
        return (title.into(), html.into());
    };
    let dom = kuchiki::parse_html().one(html);
    let content = dom
        .select_first("main")
        .or_else(|_| dom.select_first("article"))
        .or_else(|_| dom.select_first("body"))
        .unwrap();
    let tables = content
        .as_node()
        .select("table")
        .unwrap()
        .map(|node| {
            node.as_node()
                .select("tr")
                .unwrap()
                .filter(|r| r.as_node().select_first("td").is_ok())
                .count()
        })
        .max()
        .unwrap_or(0);
    let count = if tables > 0 {
        tables
    } else {
        content
            .as_node()
            .select("ol")
            .unwrap()
            .map(|node| {
                node.as_node()
                    .children()
                    .filter(|n| {
                        n.as_element()
                            .is_some_and(|e| e.name.local.as_ref() == "li")
                    })
                    .count()
            })
            .max()
            .unwrap_or(0)
    };
    let number = caps.get(1).unwrap();
    if count == 0 || number.as_str().parse::<usize>().ok() == Some(count) {
        return (title.into(), html.into());
    }
    let mut title = title.to_owned();
    title.replace_range(number.range(), &count.to_string());
    for node in dom.select("title, h1").unwrap() {
        let text = node.text_contents();
        if let Some(caps) = re.captures(&text) {
            let mut text = text.clone();
            text.replace_range(caps.get(1).unwrap().range(), &count.to_string());
            for child in node.as_node().children().collect::<Vec<_>>() {
                child.detach();
            }
            node.as_node().append(kuchiki::NodeRef::new_text(text));
        }
    }
    let html = if html.to_lowercase().contains("<html") {
        dom.to_string()
    } else {
        dom.select_first("body")
            .unwrap()
            .as_node()
            .children()
            .map(|n| n.to_string())
            .collect()
    };
    (title, html)
}

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
    let mut illustrated;
    let record = if ["news", "howto", "recipe"].contains(&profile.kind.as_str())
        && !record.body.contains("article-hero")
    {
        illustrated = record.clone();
        let picture = hero(&record.title, &profile.name);
        use kuchiki::traits::TendrilSink;
        let dom = kuchiki::parse_html().one(record.body.as_str());
        let first = dom.select("p:not(.byline):not(.author)").unwrap().next();
        if let Some(first) = first {
            let fragment = kuchiki::parse_html().one(picture);
            let figure = fragment.select_first("figure").unwrap();
            first.as_node().insert_before(figure.as_node().clone());
            illustrated.body = dom
                .select_first("body")
                .unwrap()
                .as_node()
                .children()
                .map(|n| n.to_string())
                .collect();
        }
        &illustrated
    } else {
        record
    };
    let advisory = super::make::advisory(host, target, &record.title, &record.date);
    let record = advisory.as_ref().unwrap_or(record);
    let vendor = host == "www.halvardsystems.com" || host == "halvardsystems.com";
    let mut canonical;
    let profile = if vendor {
        canonical = super::make::site_profile(host);
        if advisory.is_some() {
            canonical.kind = "advisory".into();
        } else if profile.kind == "news" {
            canonical.kind = "news".into();
        }
        &canonical
    } else {
        profile
    };
    let question;
    let record = if profile.kind == "qa" {
        question = Page {
            body: question_body(record),
            ..record.clone()
        };
        &question
    } else {
        record
    };
    let path = target.split('?').next().unwrap_or(target);
    let forum_listing = profile.kind == "forum"
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
        "listings" | "lodging" | "howto" => format!(
            r#"<body class="{kind}"><header><div class="brand"><a href="/">{}</a></div><nav>{nav}</nav></header><div class="site-content"><p class="page-breadcrumb"><a href="/">Home</a> › {}</p><div class="filters"><span>{}</span><span>{}</span><span>{}</span></div><article>{body}</article></div></body></html>"#,
            e(name),
            e(title),
            if flights {
                "Flights"
            } else if kind == "lodging" {
                "Stays"
            } else if kind == "listings" {
                "Restaurants"
            } else {
                "Steps"
            },
            if flights {
                "Connections"
            } else if kind == "lodging" {
                "Room type"
            } else if kind == "listings" {
                "Cuisine"
            } else {
                "Tips"
            },
            if kind == "listings" {
                "Price"
            } else {
                "Related articles"
            }
        ),
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
        "company" | "government" | "shop" | "weather" | "review" | "marketplace" | "advisory" => {
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
        "qa" => format!(
            r#"<body class="qa"><header><a class="home" href="/">{}</a><form action="/search" class="search"><input name="q" aria-label="Search" placeholder="Search"></form><a href="/login">Sign in</a></header><main class="{}">{body}</main>"#,
            e(name),
            if host.contains("quora.com") {
                "answer-cards"
            } else {
                "questions"
            }
        ),
        "forum" | "docs" | "wiki" | "package" => {
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
    let cookies = if !["government", "wiki", "docs", "package"].contains(&kind) && cookie_host(host)
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
    let main = if vendor {
        let source = include_str!("../../../seeds/fixed/halvard-hsa-2026-014.html");
        let start = source.find("<header").unwrap();
        let end = source[start..].find("</header>").unwrap() + start + "</header>".len();
        let header = &source[start..end];
        let start = main.find("<header").unwrap();
        let end = main[start..].find("</header>").unwrap() + start + "</header>".len();
        format!("{}{header}{}", &main[..start], &main[end..])
    } else {
        main
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
    if let Some(record) = super::make::advisory(host, target, title, date) {
        let mut profile = super::make::site_profile(host);
        profile.kind = "advisory".into();
        return Some(page_at(host, target, &profile, &record, today));
    }
    let path = target.split('?').next().unwrap_or(target);
    if super::make::site_profile(host).kind == "forum"
        && ["/", "/search", "/search/", "/latest", "/categories", "/top"].contains(&path)
    {
        return None;
    }
    let profile = super::make::site_profile(host);
    let skin = fictionet_extras::sites::lookup(host, target);
    if skin.is_none() && profile.kind != "qa" {
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn numbered_titles_follow_the_article_count() {
        let body = "<h1>The 7 Best Keyboards</h1><table><tr><th>Model</th></tr><tr><td>A</td></tr><tr><td>B</td></tr><tr><td>C</td></tr></table>";
        let (title, html) = counted("The 7 Best Keyboards", body);
        assert_eq!(title, "The 3 Best Keyboards");
        assert!(html.contains("<h1>The 3 Best Keyboards</h1>"));
        assert_eq!(counted("The 3 Best Keyboards", &html), (title, html));
        assert_eq!(
            counted("7 October 2026", body),
            ("7 October 2026".into(), body.into())
        );
    }

    #[test]
    fn article_pictures_are_local_and_vary_with_the_title() {
        use kuchiki::traits::TendrilSink;
        for host in ["www.bbc.com", "www.wikihow.com", "www.allrecipes.com"] {
            let profile = super::super::make::site_profile(host);
            let record = Page {
                title: "Cleaning a dishwasher filter".into(),
                body: "<h1>Cleaning a dishwasher filter</h1><p>Remove the filter.</p>".into(),
                ..Page::default()
            };
            let html = page(host, &profile, &record, "2026-10-07");
            let dom = kuchiki::parse_html().one(html.clone());
            assert_eq!(dom.select("figure.article-hero").unwrap().count(), 1);
            let picture = dom.select_first(".article-hero svg").unwrap();
            assert_eq!(
                picture.attributes.borrow().get("viewBox"),
                Some("0 0 840 360")
            );
            assert!(
                dom.select_first("figcaption")
                    .unwrap()
                    .text_contents()
                    .eq(&format!("Photo: {}", profile.name))
            );
            let svg = picture.as_node();
            assert_eq!(svg.select("circle, path, polygon").unwrap().count(), 0);
            let shapes = svg.select("g ellipse, g rect").unwrap().collect::<Vec<_>>();
            assert!((6..=9).contains(&shapes.len()));
            assert!(svg.select_first("g ellipse").is_ok());
            assert!(svg.select_first("g rect[rx]").is_ok());
            assert!(shapes.iter().all(|shape| {
                let attrs = shape.attributes.borrow();
                attrs.get("fill").unwrap().starts_with("var(--")
                    && attrs.get("opacity").unwrap().parse::<f32>().unwrap() < 1.0
            }));
            assert_eq!(
                svg.select_first("feGaussianBlur")
                    .unwrap()
                    .attributes
                    .borrow()
                    .get("stdDeviation"),
                Some("24")
            );
            assert_eq!(
                svg.select_first("g")
                    .unwrap()
                    .attributes
                    .borrow()
                    .get("filter"),
                Some("url(#article-blur)")
            );
            assert!(svg.select_first("linearGradient stop").is_ok());
            let attrs = picture.attributes.borrow();
            let style = attrs.get("style").unwrap();
            for rule in ["width:100%", "aspect-ratio:21/9", "max-height:300px"] {
                assert!(style.contains(rule));
            }
            let caption = dom.select_first("figcaption").unwrap();
            let attrs = caption.attributes.borrow();
            let style = attrs.get("style").unwrap();
            assert!(style.contains("color:var(--app-mute, var(--app-photo-mute))"));
            assert!(style.contains("font:12px/1.5"));
            assert!(html.find("article-hero").unwrap() < html.find("<p>Remove").unwrap());
            assert!(!picture.as_node().to_string().contains("href="));
            assert_ne!(hero(&record.title, "Daily"), hero("Growing basil", "Daily"));
            assert_eq!(hero(&record.title, "Daily"), hero(&record.title, "Daily"));
        }
    }

    #[test]
    fn other_site_kinds_have_no_article_picture() {
        use kuchiki::traits::TendrilSink;
        let record = Page {
            title: "Maintenance update".into(),
            body: "<h1>Maintenance update</h1><p>New firmware is available.</p>".into(),
            ..Page::default()
        };
        for kind in [
            "vendor",
            "wiki",
            "docs",
            "forum",
            "shop",
            "qa",
            "government",
        ] {
            let mut profile = super::super::make::site_profile("daily.org");
            profile.kind = kind.into();
            let html = page("daily.org", &profile, &record, "2026-10-07");
            let dom = kuchiki::parse_html().one(html);
            assert_eq!(dom.select(".article-hero").unwrap().count(), 0, "{kind}");
        }
    }

    #[test]
    fn cookie_choices_vary_on_a_quarter_of_hosts() {
        let mut shown = 0;
        let mut messages = std::collections::BTreeSet::new();
        for number in 0..120 {
            let host = format!("daily{number}.org");
            let profile = super::super::make::site_profile(&host);
            let html = page(&host, &profile, &Page::default(), "2026-10-07");
            if cookie_host(&host) {
                shown += 1;
                assert!(html.contains("display:flex;align-items:center"));
                assert!(html.contains("pagehide"));
                assert!(html.contains("document.cookie"));
                assert!(html.contains("Max-Age=31536000; Path=/; SameSite=Lax"));
                assert!(html.contains("addEventListener('click'"));
                messages.insert(
                    html.split("<p style=\"margin:0;flex:1\">")
                        .nth(1)
                        .unwrap()
                        .split("</p>")
                        .next()
                        .unwrap()
                        .to_owned(),
                );
            } else {
                assert!(!html.contains("cookie-banner"));
            }
        }
        assert!((25..=35).contains(&shown), "{shown}");
        assert_eq!(messages.len(), 3);
    }
    #[test]
    fn layouts_keep_content_and_vary_by_style() {
        assert_eq!(server_of(None), "nginx");
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
                    !["government", "wiki", "docs", "package"].contains(&kind)
                        && host_hash("site.com").is_multiple_of(4)
                );
            }
        }
    }
}
