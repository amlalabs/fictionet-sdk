use std::fmt::Write;

include!(concat!(env!("OUT_DIR"), "/vendor.rs"));

pub(super) const HTML: &str = include_str!("../../../dashboard/page.html");

pub(super) fn lookup(path: &str) -> Option<(&'static str, &'static [u8])> {
    let bytes: &[u8] = match path {
        "/dom.mjs" => include_bytes!("../../../dashboard/dom.mjs"),
        "/format.mjs" => include_bytes!("../../../dashboard/format.mjs"),
        "/graph.mjs" => include_bytes!("../../../dashboard/graph.mjs"),
        "/groups.mjs" => include_bytes!("../../../dashboard/groups.mjs"),
        "/interaction.mjs" => include_bytes!("../../../dashboard/interaction.mjs"),
        "/layout.mjs" => include_bytes!("../../../dashboard/layout.mjs"),
        "/packets.mjs" => include_bytes!("../../../dashboard/packets.mjs"),
        "/tables.mjs" => include_bytes!("../../../dashboard/tables.mjs"),
        "/components/left-the-box.mjs" => {
            include_bytes!("../../../dashboard/components/left-the-box.mjs")
        }
        "/components/containment.mjs" => {
            include_bytes!("../../../dashboard/components/containment.mjs")
        }
        "/components/labels.mjs" => include_bytes!("../../../dashboard/components/labels.mjs"),
        "/components/map.mjs" => include_bytes!("../../../dashboard/components/map.mjs"),
        "/components/packets.mjs" => include_bytes!("../../../dashboard/components/packets.mjs"),
        "/components/events.mjs" => include_bytes!("../../../dashboard/components/events.mjs"),
        "/components/table.mjs" => include_bytes!("../../../dashboard/components/table.mjs"),
        "/components/event-table.mjs" => {
            include_bytes!("../../../dashboard/components/event-table.mjs")
        }
        "/components/control.mjs" => include_bytes!("../../../dashboard/components/control.mjs"),
        "/components/custom.mjs" => include_bytes!("../../../dashboard/components/custom.mjs"),
        "/components.css" => include_bytes!("../../../dashboard/components.css"),
        "/streams.mjs" => include_bytes!("../../../dashboard/streams.mjs"),
        "/page.mjs" => include_bytes!("../../../dashboard/page.mjs"),
        "/theme.mjs" => include_bytes!("../../../dashboard/theme.mjs"),
        "/selection.mjs" => include_bytes!("../../../dashboard/selection.mjs"),
        "/components/screen.mjs" => include_bytes!("../../../dashboard/components/screen.mjs"),
        "/components/terminal.mjs" => include_bytes!("../../../dashboard/components/terminal.mjs"),
        "/tokens.css" => include_bytes!("../../../dashboard/tokens.css"),
        "/page.css" => include_bytes!("../../../dashboard/page.css"),
        "/state.mjs" => include_bytes!("../../../dashboard/state.mjs"),
        "/transport.mjs" => include_bytes!("../../../dashboard/transport.mjs"),
        "/icon.svg" => include_bytes!("../../../dashboard/icon.svg"),
        _ => vendored(path.strip_prefix("/vendor/")?)?,
    };
    Some((content_type(path), bytes))
}

pub(super) fn content_type(path: &str) -> &'static str {
    match path.rsplit('.').next() {
        Some("js" | "mjs") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("svg") => "image/svg+xml",
        _ => "text/plain; charset=utf-8",
    }
}

pub(super) fn vendored(path: &str) -> Option<&'static [u8]> {
    VENDOR
        .binary_search_by_key(&path, |(name, _)| name)
        .ok()
        .map(|i| VENDOR[i].1)
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

pub(super) fn licenses() -> String {
    let mut html = String::from(concat!(
        "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\">",
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
        "<title>Library licenses</title>",
        "<link rel=\"icon\" href=\"/icon.svg\" type=\"image/svg+xml\">",
        "<link rel=\"stylesheet\" href=\"/tokens.css\">",
        "<link rel=\"stylesheet\" href=\"/page.css\">",
        "<body class=\"licenses\"><main><p><a href=\"/\">Back to the demo</a></p>",
        "<h1>Library licenses</h1>",
    ));
    for (path, bytes) in VENDOR {
        let Some((library, name)) = path.split_once('/') else {
            continue;
        };
        let filename = name.rsplit('/').next().expect("a name");
        if filename != "LICENSE" && !filename.starts_with("LICENSE.") {
            continue;
        }
        let version = vendored(&format!("{library}/version.txt"))
            .map(String::from_utf8_lossy)
            .unwrap_or_default();
        write!(
            html,
            "<h2>{}</h2><h3>{}</h3><pre>{}</pre>",
            escape(&version),
            escape(name),
            escape(&String::from_utf8_lossy(bytes))
        )
        .expect("a String");
    }
    if VENDOR.is_empty() {
        html.push_str(concat!(
            "<p>No browser libraries in this build. ",
            "Run <code>cargo xtask demo assets</code>, then rebuild.</p>",
        ));
    }
    html.push_str("<p><a href=\"/\">Back to the demo</a></p></main></body></html>");
    html
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolve(parent: &str, name: &str) -> String {
        let path = if name.starts_with('/') {
            name.to_owned()
        } else {
            format!("{}/{name}", parent.rsplit_once('/').unwrap().0)
        };
        let mut parts = vec![];
        for part in path.split('/') {
            match part {
                "" | "." => {}
                ".." => {
                    parts.pop().expect("import stays inside the site");
                }
                _ => parts.push(part),
            }
        }
        format!("/{}", parts.join("/"))
    }

    #[test]
    fn stylesheets_and_their_imports_are_served() {
        let mut pending: Vec<String> = Vec::new();
        for page in [HTML, &licenses()] {
            for link in page.split("<link ").skip(1) {
                let tag = link.split_once('>').unwrap().0;
                if tag.contains("rel=\"stylesheet\"") {
                    let href = tag
                        .split_once("href=\"")
                        .unwrap()
                        .1
                        .split('"')
                        .next()
                        .unwrap();
                    pending.push(href.to_owned());
                }
            }
        }
        assert!(!pending.is_empty(), "the page links no stylesheet");
        let mut seen = std::collections::BTreeSet::new();
        while let Some(path) = pending.pop() {
            if !seen.insert(path.clone()) {
                continue;
            }
            let (kind, bytes) = lookup(&path).unwrap_or_else(|| panic!("{path} is not served"));
            assert!(kind.starts_with("text/css"), "{path} is served as {kind}");
            let css = std::str::from_utf8(bytes).unwrap();
            for import in css.split("@import url(\"").skip(1) {
                let name = import.split('"').next().unwrap();
                pending.push(resolve(&path, name));
            }
        }
        assert!(seen.contains("/components.css") && seen.contains("/tokens.css"));
    }

    fn imports(source: &str) -> Vec<&str> {
        let bytes = source.as_bytes();
        let mut names = vec![];
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i..].starts_with(b"//") {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            } else if bytes[i..].starts_with(b"/*") {
                i += 2;
                while i + 1 < bytes.len() && !bytes[i..].starts_with(b"*/") {
                    i += 1;
                }
                i = (i + 2).min(bytes.len());
            } else if matches!(bytes[i], b'\'' | b'"' | b'`') {
                quoted(source, &mut i);
            } else if bytes[i].is_ascii_alphabetic() || matches!(bytes[i], b'_' | b'$') {
                let start = i;
                while i < bytes.len()
                    && (bytes[i].is_ascii_alphanumeric() || matches!(bytes[i], b'_' | b'$'))
                {
                    i += 1;
                }
                if matches!(&source[start..i], "import" | "from") {
                    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                        i += 1;
                    }
                    if bytes.get(i) == Some(&b'(') {
                        i += 1;
                        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                            i += 1;
                        }
                    }
                    if matches!(bytes.get(i), Some(b'\'' | b'"')) {
                        names.push(quoted(source, &mut i));
                    }
                }
            } else {
                i += 1;
            }
        }
        names
    }

    fn quoted<'a>(source: &'a str, i: &mut usize) -> &'a str {
        let bytes = source.as_bytes();
        let quote = bytes[*i];
        *i += 1;
        let start = *i;
        while *i < bytes.len() && bytes[*i] != quote {
            *i += if bytes[*i] == b'\\' { 2 } else { 1 };
        }
        let end = (*i).min(bytes.len());
        *i = (*i + 1).min(bytes.len());
        &source[start..end]
    }

    fn pinned(path: &str) -> bool {
        let Some(path) = path.strip_prefix("/vendor/") else {
            return false;
        };
        let pins = include_str!("../../../xtask/src/demo/libraries.rs");
        pins.split("Library {").skip(2).any(|pin| {
            let name = pin
                .split_once("name: \"")
                .unwrap()
                .1
                .split('"')
                .next()
                .unwrap();
            let Some(member) = path.strip_prefix(&format!("{name}/")) else {
                return false;
            };
            let members = pin
                .split_once("members: &")
                .unwrap()
                .1
                .split_once(']')
                .unwrap()
                .0;
            let members: Vec<String> =
                serde_json::from_str(&format!("{}]", members.trim_end().trim_end_matches(',')))
                    .unwrap();
            members
                .iter()
                .any(|item| member == item || member.starts_with(&format!("{item}/")))
        })
    }

    #[test]
    fn module_imports_are_served() {
        let map = HTML
            .split_once("type=\"importmap\"")
            .unwrap()
            .1
            .split_once('>')
            .unwrap()
            .1
            .split_once("</script>")
            .unwrap()
            .0;
        let map: serde_json::Value = serde_json::from_str(map).unwrap();
        let map = map["imports"].as_object().unwrap();
        let mut pending: Vec<String> = map.values().map(|v| v.as_str().unwrap().into()).collect();
        let mut entries = 0;
        for script in HTML.split("<script ").skip(1) {
            let tag = script.split_once('>').unwrap().0;
            if tag.contains("type=\"module\"") {
                let src = tag
                    .split_once("src=\"")
                    .unwrap()
                    .1
                    .split('"')
                    .next()
                    .unwrap();
                pending.push(resolve("/page.html", src));
                entries += 1;
            }
        }
        assert!(entries > 0, "page.html needs a module entry");
        pending.extend([
            "/components/screen.mjs".into(),
            "/components/terminal.mjs".into(),
        ]);
        let mut visited = std::collections::BTreeSet::new();
        while let Some(path) = pending.pop() {
            if !visited.insert(path.clone()) {
                continue;
            }
            if path.starts_with("/vendor/") {
                assert!(pinned(&path), "module {path} is not pinned");
                assert!(content_type(&path).starts_with("text/javascript"));
                if lookup(&path).is_none() {
                    continue;
                }
            }
            let (kind, bytes) =
                lookup(&path).unwrap_or_else(|| panic!("module {path} is not served"));
            assert!(
                kind.starts_with("text/javascript"),
                "module {path} has type {kind}"
            );
            for name in imports(std::str::from_utf8(bytes).unwrap()) {
                pending.push(if name.starts_with('.') || name.starts_with('/') {
                    resolve(&path, name)
                } else {
                    map.get(name)
                        .unwrap_or_else(|| panic!("unmapped import {name}"))
                        .as_str()
                        .unwrap()
                        .into()
                });
            }
        }
    }

    #[test]
    fn license_text_is_escaped() {
        assert_eq!(escape("<&>\"'"), "&lt;&amp;&gt;&quot;&#39;");
        let html = licenses();
        assert!(!html.contains("<script"));
        assert!(!html.contains("<style"));
        for path in ["/tokens.css", "/page.css", "/icon.svg"] {
            assert!(html.contains(&format!("href=\"{path}\"")));
        }
        assert_eq!(html.matches("Back to the demo").count(), 2);
        for (path, bytes) in VENDOR {
            if path.ends_with("/LICENSE") || path.ends_with("/LICENSE.txt") {
                assert!(html.contains(&escape(&String::from_utf8_lossy(bytes))));
                let (library, name) = path.split_once('/').unwrap();
                assert!(html.contains(&format!("<h3>{}</h3>", escape(name))));
                let version = vendored(&format!("{library}/version.txt")).unwrap();
                assert!(html.contains(&format!(
                    "<h2>{}</h2>",
                    escape(&String::from_utf8_lossy(version))
                )));
            }
        }
    }

    #[test]
    fn imports_ignore_comments_and_quoted_text() {
        assert_eq!(
            imports(
                r#"
            // from 'not-a-module'
            /* import('not-a-module') */
            const label = "from 'not-a-module'";
            import { mount } from './panel.mjs';
            export { mount } from '/panel.mjs';
            const load = () => import('/vendor/three/build/three.module.js');
        "#
            ),
            [
                "./panel.mjs",
                "/panel.mjs",
                "/vendor/three/build/three.module.js"
            ]
        );
    }

    #[test]
    fn vendor_files_keep_their_content_types_and_paths() {
        for (path, bytes) in VENDOR {
            let route = format!("/vendor/{path}");
            let (kind, served) = lookup(&route).unwrap();
            assert_eq!(served, *bytes);
            assert_eq!(kind, content_type(path));
        }
        assert!(content_type("novnc/core/rfb.js").starts_with("text/javascript"));
        assert!(content_type("xterm/lib/xterm.mjs").starts_with("text/javascript"));
        assert!(content_type("xterm/css/xterm.css").starts_with("text/css"));
        assert!(content_type("novnc/docs/LICENSE.MPL-2.0").starts_with("text/plain"));
        assert!(lookup("/vendor/../page.mjs").is_none());
        assert!(lookup("/vendor/novnc/../../page.mjs").is_none());
    }
}
