/// Joins runs of whitespace with one space and trims both ends.
pub fn normalize_space(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}
/// Escapes HTML text and both kinds of quotes.
pub fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}
/// Percent-encodes UTF-8 bytes, keeping unreserved and `safe` characters.
pub fn quote(s: &str, safe: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric()
            || b"_.-~".contains(&b)
            || (b.is_ascii() && safe.as_bytes().contains(&b))
        {
            out.push(b as char);
        } else {
            use std::fmt::Write;
            write!(&mut out, "%{b:02X}").unwrap();
        }
    }
    out
}
/// Encodes a form value, using plus signs for spaces.
pub fn quote_plus(s: &str) -> String {
    quote(s, " ").replace(' ', "+")
}

/// Returns the host, path and query of an absolute URL, as a browser
/// parses it; all empty for one that does not parse.
pub fn split_url(s: &str) -> (String, String, String) {
    let Ok(url) = url::Url::parse(s) else {
        return Default::default();
    };
    (
        url.host_str().unwrap_or_default().to_owned(),
        url.path().into(),
        url.query().unwrap_or_default().into(),
    )
}
