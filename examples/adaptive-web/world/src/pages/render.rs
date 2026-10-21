//! Generic layouts for hosts without a bundled skin.

use super::{
    make::{Page, Profile},
    text::{escape as e, normalize_space},
};

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
/// Wraps HTML content in the site's layout.
pub fn page(host: &str, profile: &Profile, record: &Page, today: &str) -> String {
    page_at(host, "/", profile, record, today)
}

/// Renders a page using the captured section layout when available.
pub fn page_at(host: &str, target: &str, profile: &Profile, record: &Page, today: &str) -> String {
    let vendor = host == "www.halvardsystems.com" || host == "halvardsystems.com";
    let canonical;
    let profile = if vendor {
        canonical = super::make::site_profile(host);
        &canonical
    } else {
        profile
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
        "company" | "government" | "shop" | "weather" | "review" | "marketplace" => {
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
    let cookies = if !["government", "wiki", "docs", "package"].contains(&kind)
        && (kind == "forum" || style % 3 != 2)
    {
        r#"<div class="cookie-banner" style="position:fixed;bottom:0;left:0;right:0;z-index:100;background:white;display:flex;align-items:center;gap:12px;padding:8px 20px;border-top:1px solid #bdc6d1;font:14px/1.4 system-ui,sans-serif" role="dialog" aria-label="Cookies"><p style="margin:0;flex:1">We use cookies for site preferences and analytics. <a href="/privacy">Privacy policy</a></p><button style="padding:6px 12px;margin:0" data-choice="accept">Accept</button><button style="padding:6px 12px;margin:0" data-choice="reject">Reject non-essential</button></div><script>(()=>{const bar=document.querySelector('.cookie-banner');let choice='seen';const remember=(value)=>{choice=value;document.cookie='site_cookies='+value+'; Max-Age=31536000; Path=/; SameSite=Lax';};if(document.cookie.split(';').some(value=>value.trim().startsWith('site_cookies='))){bar.remove();return;}remember('seen');bar.querySelectorAll('button').forEach(button=>button.addEventListener('click',()=>{remember(button.dataset.choice);bar.remove();}));window.addEventListener('pagehide',()=>remember(choice),{once:true});})();</script>"#
    } else {
        ""
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
    let path = target.split('?').next().unwrap_or(target);
    if super::make::site_profile(host).kind == "forum"
        && ["/", "/search", "/search/", "/latest", "/categories", "/top"].contains(&path)
    {
        return None;
    }
    let skin = fictionet_extras::sites::lookup(host, target)?;
    let today = super::seed::parse_date(today).ok()?;
    let published = super::seed::parse_date(date).unwrap_or(today);
    use kuchiki::traits::TendrilSink;
    let content = skin.content(html).or_else(|| {
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
                        && (kind == "forum" || style % 3 != 2)
                );
            }
        }
    }
}
