//! Shared HTML fragments and site display details.

use super::{
    make::{Link, Page, Profile},
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
pub(crate) fn nav(items: &[Link], class: &str) -> String {
    let mut out = format!(r#"<ul class="{class}">"#);
    for item in items {
        let (label, href) = (item.label.as_str(), item.href.as_str());
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
pub(crate) fn question_body(record: &Page, today: &str) -> String {
    use kuchiki::traits::TendrilSink;
    let dom = kuchiki::parse_html().one(record.body.as_str());
    if dom.select_first(".question-post").is_ok() {
        return record.body.clone();
    }
    let posts = dom.select(".post").unwrap().collect::<Vec<_>>();
    if posts.is_empty() {
        return record.body.clone();
    }
    let date = if record.date.is_empty() {
        today
    } else {
        &record.date
    };
    let mut out = format!(
        "<h1>{}</h1><p class=\"question-meta\">Asked {}</p>",
        e(super::make::heading(&record.title)),
        e(date)
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

pub(crate) fn host_hash(host: &str) -> usize {
    host.trim_start_matches("www.")
        .bytes()
        .fold(0usize, |n, b| n.wrapping_mul(31).wrapping_add(b as usize))
}

pub(crate) fn cookie_host(host: &str) -> bool {
    host_hash(host).is_multiple_of(4)
}

pub(crate) fn cookie_words(host: &str) -> (&'static str, &'static str, &'static str) {
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

pub(crate) fn hero(title: &str, name: &str) -> String {
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
pub(crate) fn counted(title: &str, html: &str) -> (String, String) {
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
