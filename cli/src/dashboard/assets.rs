const INDEX_HTML: &str = include_str!("../../../dashboard/index.html");
const APP_JS: &str = include_str!("../../../dashboard/app.mjs");
const GRAPH_JS: &str = include_str!("../../../dashboard/graph.mjs");
const GROUPS_JS: &str = include_str!("../../../dashboard/groups.mjs");
const INTERACTION_JS: &str = include_str!("../../../dashboard/interaction.mjs");
const LAYOUT_JS: &str = include_str!("../../../dashboard/layout.mjs");
const PACKETS_JS: &str = include_str!("../../../dashboard/packets.mjs");
const STATE_JS: &str = include_str!("../../../dashboard/state.mjs");
const TABLES_JS: &str = include_str!("../../../dashboard/tables.mjs");
const TRANSPORT_JS: &str = include_str!("../../../dashboard/transport.mjs");
const DOM_JS: &str = include_str!("../../../dashboard/dom.mjs");
const APP_CSS: &str = include_str!("../../../dashboard/app.css");
const ICON_SVG: &str = include_str!("../../../dashboard/icon.svg");

/// The content type and body of the embedded file served at `path`.
pub(super) fn lookup(path: &str) -> Option<(&'static str, &'static str)> {
    match path {
        "/" | "/index.html" => Some(("text/html; charset=utf-8", INDEX_HTML)),
        "/app.mjs" => Some(("text/javascript; charset=utf-8", APP_JS)),
        "/graph.mjs" => Some(("text/javascript; charset=utf-8", GRAPH_JS)),
        "/groups.mjs" => Some(("text/javascript; charset=utf-8", GROUPS_JS)),
        "/interaction.mjs" => Some(("text/javascript; charset=utf-8", INTERACTION_JS)),
        "/layout.mjs" => Some(("text/javascript; charset=utf-8", LAYOUT_JS)),
        "/packets.mjs" => Some(("text/javascript; charset=utf-8", PACKETS_JS)),
        "/state.mjs" => Some(("text/javascript; charset=utf-8", STATE_JS)),
        "/tables.mjs" => Some(("text/javascript; charset=utf-8", TABLES_JS)),
        "/transport.mjs" => Some(("text/javascript; charset=utf-8", TRANSPORT_JS)),
        "/dom.mjs" => Some(("text/javascript; charset=utf-8", DOM_JS)),
        "/theme.mjs" => Some((
            "text/javascript; charset=utf-8",
            include_str!("../../../dashboard/theme.mjs"),
        )),
        "/selection.mjs" => Some((
            "text/javascript; charset=utf-8",
            include_str!("../../../dashboard/selection.mjs"),
        )),
        "/format.mjs" => Some((
            "text/javascript; charset=utf-8",
            include_str!("../../../dashboard/format.mjs"),
        )),
        "/components/map.mjs" => Some((
            "text/javascript; charset=utf-8",
            include_str!("../../../dashboard/components/map.mjs"),
        )),
        "/components/labels.mjs" => Some((
            "text/javascript; charset=utf-8",
            include_str!("../../../dashboard/components/labels.mjs"),
        )),
        "/components/packets.mjs" => Some((
            "text/javascript; charset=utf-8",
            include_str!("../../../dashboard/components/packets.mjs"),
        )),
        "/components/events.mjs" => Some((
            "text/javascript; charset=utf-8",
            include_str!("../../../dashboard/components/events.mjs"),
        )),
        "/tokens.css" => Some((
            "text/css; charset=utf-8",
            include_str!("../../../dashboard/tokens.css"),
        )),
        "/components.css" => Some((
            "text/css; charset=utf-8",
            include_str!("../../../dashboard/components.css"),
        )),
        "/app.css" => Some(("text/css; charset=utf-8", APP_CSS)),
        "/icon.svg" => Some(("image/svg+xml", ICON_SVG)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::lookup;

    #[test]
    fn stylesheets_and_their_imports_are_served() {
        let (_, html) = lookup("/").unwrap();
        let mut pending: Vec<String> = Vec::new();
        for link in html.split("<link ").skip(1) {
            let tag = link.split_once('>').unwrap().0;
            if tag.contains("rel=\"stylesheet\"") {
                let href = tag
                    .split_once("href=\"")
                    .unwrap()
                    .1
                    .split('"')
                    .next()
                    .unwrap();
                pending.push(format!("/{}", href.trim_start_matches("./")));
            }
        }
        assert!(!pending.is_empty(), "index.html links no stylesheet");
        let mut seen = std::collections::BTreeSet::new();
        while let Some(path) = pending.pop() {
            if !seen.insert(path.clone()) {
                continue;
            }
            let (kind, css) = lookup(&path).unwrap_or_else(|| panic!("{path} is not served"));
            assert!(kind.starts_with("text/css"), "{path} is served as {kind}");
            for import in css.split("@import url(\"").skip(1) {
                let name = import.split('"').next().unwrap();
                pending.push(format!("/{}", name.trim_start_matches("./")));
            }
        }
        assert!(seen.contains("/components.css") && seen.contains("/tokens.css"));
    }

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
                    if name.starts_with('.') || name.starts_with('/') {
                        let parent = path.rsplit_once('/').unwrap().0;
                        let joined = if name.starts_with('/') {
                            name.to_owned()
                        } else {
                            format!("{parent}/{name}")
                        };
                        let mut parts = Vec::new();
                        for part in joined.split('/') {
                            match part {
                                "" | "." => {}
                                ".." => {
                                    parts.pop().expect("import stays inside the site");
                                }
                                _ => parts.push(part),
                            }
                        }
                        pending.push(format!("/{}", parts.join("/")));
                    }
                }
            }
        }
    }
}
