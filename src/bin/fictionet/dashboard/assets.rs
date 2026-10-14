const INDEX_HTML: &str = include_str!("../../../../dashboard/index.html");
const APP_JS: &str = include_str!("../../../../dashboard/app.mjs");
const GROUPS_JS: &str = include_str!("../../../../dashboard/groups.mjs");
const PACKETS_JS: &str = include_str!("../../../../dashboard/packets.mjs");
const STATE_JS: &str = include_str!("../../../../dashboard/state.mjs");
const TRANSPORT_JS: &str = include_str!("../../../../dashboard/transport.mjs");
const DOM_JS: &str = include_str!("../../../../dashboard/dom.mjs");
const APP_CSS: &str = include_str!("../../../../dashboard/app.css");
const ICON_SVG: &str = include_str!("../../../../dashboard/icon.svg");

/// The content type and body of the embedded file served at `path`.
pub(super) fn lookup(path: &str) -> Option<(&'static str, &'static str)> {
    match path {
        "/" | "/index.html" => Some(("text/html; charset=utf-8", INDEX_HTML)),
        "/app.mjs" => Some(("text/javascript; charset=utf-8", APP_JS)),
        "/groups.mjs" => Some(("text/javascript; charset=utf-8", GROUPS_JS)),
        "/packets.mjs" => Some(("text/javascript; charset=utf-8", PACKETS_JS)),
        "/state.mjs" => Some(("text/javascript; charset=utf-8", STATE_JS)),
        "/transport.mjs" => Some(("text/javascript; charset=utf-8", TRANSPORT_JS)),
        "/dom.mjs" => Some(("text/javascript; charset=utf-8", DOM_JS)),
        "/app.css" => Some(("text/css; charset=utf-8", APP_CSS)),
        "/icon.svg" => Some(("image/svg+xml", ICON_SVG)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::lookup;

    #[test]
    fn module_imports_are_served() {
        let (_, html) = lookup("/").unwrap();
        let mut pending = Vec::new();
        for script in html.split("<script ").skip(1) {
            let tag = script.split_once('>').unwrap().0;
            if tag.contains("type=\"module\"") {
                let src = tag
                    .split_once("src=\"")
                    .unwrap()
                    .1
                    .split('"')
                    .next()
                    .unwrap();
                pending.push(format!("/{}", src.trim_start_matches("./")));
            }
        }
        assert!(!pending.is_empty(), "no module entry point in index.html");
        let mut visited = std::collections::BTreeSet::new();
        while let Some(path) = pending.pop() {
            if !visited.insert(path.clone()) {
                continue;
            }
            let (content_type, source) =
                lookup(&path).unwrap_or_else(|| panic!("module {path} is not served"));
            assert!(
                content_type.starts_with("text/javascript"),
                "module {path} has content type {content_type}"
            );
            for import in source.split("from ").skip(1) {
                let import = import.trim_start();
                if let Some(quote @ ('\'' | '"')) = import.chars().next() {
                    let name = import[1..].split(quote).next().unwrap();
                    if let Some(name) = name.strip_prefix("./") {
                        let parent = path.rsplit_once('/').unwrap().0;
                        pending.push(format!("{parent}/{name}"));
                    }
                }
            }
        }
    }
}
