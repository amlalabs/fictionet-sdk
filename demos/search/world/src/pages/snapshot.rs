//! A still picture of a served page for the host's own screen: the page's
//! markup without scripts, its stylesheets, images and fonts pointed at
//! what the world holds.

use kuchiki::traits::TendrilSink;
use regex::Regex;
use std::sync::OnceLock;

/// The served `html` of `url` with every dependency the picture needs
/// renamed by `held` (an absolute URL in, the address to load it from out).
/// Scripts, frames, forms and event handlers are removed, and links stay on
/// the picture: following one would leave the world for the real site.
pub fn page(url: &url::Url, html: &str, held: &dyn Fn(&url::Url) -> String) -> String {
    let dom = kuchiki::parse_html().one(html);
    let base = dom
        .select_first("base[href]")
        .ok()
        .and_then(|node| {
            let href = node.attributes.borrow().get("href")?.to_owned();
            url.join(&href).ok()
        })
        .unwrap_or_else(|| url.clone());
    for selector in [
        "script",
        "noscript",
        "iframe",
        "frame",
        "object",
        "embed",
        "base",
        "meta[http-equiv]",
        "link:not([rel~=stylesheet])",
    ] {
        for node in dom.select(selector).unwrap().collect::<Vec<_>>() {
            node.as_node().detach();
        }
    }
    // A `data:` address carries its file and stays as it is; a bare `#id`
    // names no file at all.
    let resolve = |value: &str| {
        let value = value.trim();
        if value.starts_with('#') {
            return None;
        }
        base.join(value).ok().map(|url| match url.scheme() {
            "data" => url.to_string(),
            _ => held(&url),
        })
    };
    for node in dom.select("*").unwrap() {
        let mut attributes = node.attributes.borrow_mut();
        let names: Vec<_> = attributes
            .map
            .keys()
            .map(|name| name.local.to_string())
            .collect();
        // An `integrity` hash names the file as the site served it; the
        // picture loads a copy with its addresses renamed, which the hash
        // would refuse, leaving the page unstyled.
        for name in names {
            if name.starts_with("on") || name == "srcset" || name == "action" || name == "integrity"
            {
                attributes.remove(name.as_str());
            }
        }
        let element = node.name.local.as_ref();
        if matches!(element, "a" | "area")
            && attributes
                .get("href")
                .is_some_and(|href| !href.trim_start().starts_with('#'))
        {
            attributes.insert("href", "#".into());
        }
        let source = match element {
            "link" => Some("href"),
            "img" | "source" | "input" => Some("src"),
            "video" => Some("poster"),
            _ => None,
        };
        if let Some(source) = source
            && let Some(value) = attributes.get(source).map(str::to_owned)
        {
            match resolve(&value) {
                Some(address) => attributes.insert(source, address),
                None => attributes.remove(source),
            };
        }
        // Lazy images keep their address in data attributes until a script runs.
        if element == "img"
            && !attributes.contains("src")
            && let Some(value) = attributes.get("data-src").map(str::to_owned)
            && let Some(address) = resolve(&value)
        {
            attributes.insert("src", address);
        }
        // An icon drawn from another file's sprite: the sandboxed picture
        // may not load another document's symbols, and Chrome asks again on
        // every repaint, so only a symbol of the page itself stays.
        if element == "use" {
            attributes.map.retain(|name, attribute| {
                name.local.as_ref() != "href" || attribute.value.trim_start().starts_with('#')
            });
        }
        // An image loads as it comes into view, so a picture of the top of
        // a page asks only for the images there.
        if element == "img" {
            attributes.insert("loading", "lazy".into());
        }
        if let Some(style) = attributes.get("style").map(str::to_owned) {
            attributes.insert("style", stylesheet(&base, &style, held));
        }
    }
    for node in dom.select("style").unwrap() {
        let text = node.text_contents();
        let rewritten = stylesheet(&base, &text, held);
        let node = node.as_node();
        for child in node.children().collect::<Vec<_>>() {
            child.detach();
        }
        node.append(kuchiki::NodeRef::new_text(rewritten));
    }
    // A page made only for desktops (it names no viewport, like a filing
    // laid out for letter paper) is pictured the way a phone shows it:
    // laid out 980 px wide and zoomed out to fit, not cut to its left edge.
    let desktop_only = dom.select_first("meta[name=viewport]").is_err();
    let zoom = if desktop_only {
        format!("html{{zoom:{DESKTOP_ZOOM}}}")
    } else {
        String::new()
    };
    // The picture scrolls as one page, down only: a box inside it that
    // scrolls (a contents list a script would have folded away) shows no
    // scrollbar of its own. The parser always gives a document its head.
    dom.to_string().replacen(
        "</head>",
        &format!("<style>{zoom}{PICTURE_STYLE}</style></head>"),
        1,
    )
}

/// The picture's own style: one scrollbar, the frame's.
const PICTURE_STYLE: &str = "html{overflow-x:hidden}body *{scrollbar-width:none}";

/// The zoom that fits a page laid out 980 px wide on the workstation
/// phone's 390 px screen.
const DESKTOP_ZOOM: &str = "0.398";

/// A stylesheet served at `base` with its `url()` and `@import` addresses
/// renamed by `held`. A `url(#id)` names an element of the page itself (an
/// SVG filter, clip path or gradient) and stays as it is: as a `held`
/// address the sandboxed picture may not load it, and Chrome asks again on
/// every repaint.
pub fn stylesheet(base: &url::Url, css: &str, held: &dyn Fn(&url::Url) -> String) -> String {
    static ADDRESS: OnceLock<Regex> = OnceLock::new();
    let address = ADDRESS.get_or_init(|| {
        Regex::new(
            r#"url\(\s*(?:"([^"]*)"|'([^']*)'|([^)'"\s]*))\s*\)|@import\s+(?:"([^"]*)"|'([^']*)')"#,
        )
        .unwrap()
    });
    address
        .replace_all(css, |found: &regex::Captures<'_>| {
            let import = found.get(4).or(found.get(5));
            let value = found
                .get(1)
                .or(found.get(2))
                .or(found.get(3))
                .or(import)
                .map_or("", |m| m.as_str());
            if value.starts_with("data:") || value.starts_with('#') || value.is_empty() {
                return found[0].to_owned();
            }
            let renamed = base.join(value).map(|url| held(&url)).unwrap_or_default();
            if import.is_some() {
                format!("@import \"{renamed}\"")
            } else {
                format!("url(\"{renamed}\")")
            }
        })
        .into_owned()
}
