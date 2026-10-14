const INDEX_HTML: &str = include_str!("../../../../dashboard/index.html");
const APP_JS: &str = include_str!("../../../../dashboard/app.js");
const GROUPS_JS: &str = include_str!("../../../../dashboard/groups.js");
const APP_CSS: &str = include_str!("../../../../dashboard/app.css");
const ICON_SVG: &str = include_str!("../../../../dashboard/icon.svg");

/// The content type and body of the embedded file served at `path`.
pub(super) fn lookup(path: &str) -> Option<(&'static str, &'static str)> {
    match path {
        "/" | "/index.html" => Some(("text/html; charset=utf-8", INDEX_HTML)),
        "/app.js" => Some(("text/javascript; charset=utf-8", APP_JS)),
        "/groups.js" => Some(("text/javascript; charset=utf-8", GROUPS_JS)),
        "/app.css" => Some(("text/css; charset=utf-8", APP_CSS)),
        "/icon.svg" => Some(("image/svg+xml", ICON_SVG)),
        _ => None,
    }
}
