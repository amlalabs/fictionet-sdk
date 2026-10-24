//! A still picture of a served page for the host's own screen: the page's
//! markup without scripts, its stylesheets, images and fonts pointed at
//! what the world holds.

use kuchiki::traits::TendrilSink;
use regex::Regex;
use std::sync::OnceLock;

/// The served `html` of `url` with every dependency the picture needs
/// renamed by `held` (an absolute URL in, the address to load it from out).
/// Scripts, frames, forms and event handlers are removed.
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
    let resolve = |value: &str| base.join(value.trim()).ok().map(|url| held(&url));
    for node in dom.select("*").unwrap() {
        let mut attributes = node.attributes.borrow_mut();
        let names: Vec<_> = attributes
            .map
            .keys()
            .map(|name| name.local.to_string())
            .collect();
        for name in names {
            if name.starts_with("on") || name == "srcset" || name == "action" {
                attributes.remove(name.as_str());
            }
        }
        let element = node.name.local.as_ref();
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
    dom.to_string()
}

/// A stylesheet served at `base` with its `url()` and `@import` addresses
/// renamed by `held`.
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
            if value.starts_with("data:") || value.is_empty() {
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
