//! String, HTML and URL helpers for the pages and their checks.

use regex::Regex;
use std::sync::OnceLock;

/// Joins runs of whitespace with one space and trims both ends.
pub fn normalize_space(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}
/// Takes at most `n` Unicode code points.
pub fn take(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}
/// Uppercases the first character and keeps the rest unchanged.
pub fn upper_first(s: &str) -> String {
    let mut chars = s.chars();
    chars
        .next()
        .map(|c| c.to_uppercase().collect::<String>() + chars.as_str())
        .unwrap_or_default()
}
/// Uppercases the first character and lowercases the rest.
pub fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    chars
        .next()
        .map(|c| c.to_uppercase().collect::<String>() + &chars.as_str().to_lowercase())
        .unwrap_or_default()
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
/// Returns the host and request target, using `/` for an empty path.
pub fn target_of(s: &str) -> (String, String) {
    let (host, path, query) = split_url(s);
    let mut target = if path.is_empty() { "/".into() } else { path };
    if !query.is_empty() {
        target.push('?');
        target.push_str(&query);
    }
    (host, target)
}

/// Resolves a link against the page it is on, as a browser does.
pub fn join(base: &str, href: &str) -> Option<String> {
    url::Url::parse(base)
        .ok()?
        .join(href)
        .ok()
        .map(String::from)
}

fn named(name: &str) -> Option<&'static str> {
    Some(match name {
        "amp" | "AMP" => "&",
        "lt" | "LT" => "<",
        "gt" | "GT" => ">",
        "quot" | "QUOT" => "\"",
        "apos" => "'",
        "nbsp" => "\u{a0}",
        "copy" | "COPY" => "©",
        "reg" | "REG" => "®",
        "trade" => "™",
        "rsaquo" => "›",
        "lsaquo" => "‹",
        "raquo" => "»",
        "laquo" => "«",
        "middot" => "·",
        "ndash" => "–",
        "mdash" => "—",
        "hellip" => "…",
        "lsquo" => "‘",
        "rsquo" => "’",
        "ldquo" => "“",
        "rdquo" => "”",
        "bull" => "•",
        "euro" => "€",
        "pound" => "£",
        "yen" => "¥",
        "cent" => "¢",
        _ => return None,
    })
}
/// Decodes named and numeric HTML character references. A reference to
/// no character, or to NUL, becomes U+FFFD.
pub fn unescape(s: &str) -> String {
    static ENTITY: OnceLock<Regex> = OnceLock::new();
    ENTITY
        .get_or_init(|| Regex::new(r"&(#[xX][0-9a-fA-F]+;?|#[0-9]+;?|[a-zA-Z]{1,32};)").unwrap())
        .replace_all(s, |c: &regex::Captures<'_>| {
            let raw = &c[1];
            if let Some(n) = raw.strip_prefix('#') {
                let n = n.trim_end_matches(';');
                let code = match n.strip_prefix(['x', 'X']) {
                    Some(hex) => u32::from_str_radix(hex, 16),
                    None => n.parse(),
                };
                return code
                    .ok()
                    .and_then(char::from_u32)
                    .filter(|c| *c != '\0')
                    .unwrap_or('\u{fffd}')
                    .to_string();
            }
            match named(raw.trim_end_matches(';')) {
                Some(value) => value.into(),
                None => c[0].into(),
            }
        })
        .into_owned()
}

fn word_char(c: char) -> bool {
    c == '_' || c.is_alphanumeric()
}

/// Extracts normalized text from HTML, excluding scripts and styles.
pub fn text_of(markup: &str) -> String {
    static START: OnceLock<Regex> = OnceLock::new();
    static TAG: OnceLock<Regex> = OnceLock::new();
    let start = START.get_or_init(|| Regex::new(r"(?is)<(script|style)").unwrap());
    let mut rest = markup;
    let mut out = String::new();
    // A `<script` or `<style` followed by a word character opens another tag.
    while let Some(c) = start.captures_iter(rest).find(|c| {
        !rest[c.get(0).unwrap().end()..]
            .chars()
            .next()
            .is_some_and(word_char)
    }) {
        let matched = c.get(0).unwrap();
        let close = format!("</{}>", c[1].to_ascii_lowercase());
        let end = rest[matched.end()..].to_ascii_lowercase().find(&close);
        if let Some(end) = end {
            out.push_str(&rest[..matched.start()]);
            out.push(' ');
            rest = &rest[matched.end() + end + close.len()..];
        } else {
            out.push_str(&rest[..matched.end()]);
            rest = &rest[matched.end()..];
        }
    }
    out.push_str(rest);
    let text = TAG
        .get_or_init(|| Regex::new(r"<[^>]+>").unwrap())
        .replace_all(&out, " ");
    normalize_space(&unescape(&text))
}
/// Normalizes case, quotes, dashes and whitespace for snippet comparison.
pub fn normalize_snippet(s: &str) -> String {
    normalize_space(
        &s.chars()
            .map(|c| match c {
                '‘' | '’' | '‚' | '‛' => '\'',
                '“' | '”' | '„' | '‟' => '"',
                '‐' | '‑' | '‒' | '–' | '—' | '―' => '-',
                c => c,
            })
            .collect::<String>()
            .to_lowercase(),
    )
}
/// Splits a snippet into the pieces a page must contain: separated by
/// sentences, fields (` | `, ` · `) and ellipses, without a leading date,
/// with boundary punctuation stripped. A piece with no letter or digit is
/// left out.
pub fn snippet_pieces(s: &str) -> Vec<String> {
    static DATE: OnceLock<Regex> = OnceLock::new();
    static PUNCT: OnceLock<Regex> = OnceLock::new();
    let s = normalize_snippet(s);
    let date = DATE.get_or_init(|| {
        Regex::new(
            r"^((jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec) \d{1,2}, \d{4}|\d+ (days?|hours?) ago)\s*-\s*",
        )
        .unwrap()
    });
    let s = date.replace(&s, "");
    let punct = PUNCT.get_or_init(|| Regex::new(r"^\p{P}$").unwrap());
    let cs: Vec<_> = s.chars().collect();
    let mut parts = Vec::new();
    let (mut begin, mut i) = (0, 0);
    while i < cs.len() {
        let mut end = i;
        if cs[i] == '…' {
            while end < cs.len() && cs[end] == '…' {
                end += 1;
            }
        } else if cs[i] == '.' && cs.get(i + 1) == Some(&'.') && cs.get(i + 2) == Some(&'.') {
            while end < cs.len() && cs[end] == '.' {
                end += 1;
            }
        } else if cs[i].is_whitespace() && i > 0 && ".!?:".contains(cs[i - 1]) {
            while end < cs.len() && cs[end].is_whitespace() {
                end += 1;
            }
        } else if "|·".contains(cs[i])
            && i > 0
            && cs[i - 1].is_whitespace()
            && cs.get(i + 1).is_some_and(|c| c.is_whitespace())
        {
            end += 1;
        }
        if end != i {
            parts.push(cs[begin..i].iter().collect::<String>());
            begin = end;
            i = end;
        } else {
            i += 1;
        }
    }
    parts.push(cs[begin..].iter().collect());
    parts
        .into_iter()
        .filter_map(|s| {
            let s = s.trim_matches(|c: char| c.is_whitespace() || punct.is_match(&c.to_string()));
            s.chars().any(char::is_alphanumeric).then(|| s.to_owned())
        })
        .collect()
}

/// Lists the phrases and patterns that give generated text away.
pub fn tells(text: &str) -> Vec<String> {
    const PHRASES: &[&str] = &[
        "it's important to note",
        "it is important to note",
        "in today's",
        "navigate the",
        "landscape",
        "delve",
        "robust",
        "stay vigilant",
        "key takeaways",
        "in conclusion",
        "whether you're",
        "game-changer",
        "leverage",
        "seamless",
        "a testament to",
        "plays a crucial role",
        "ever-evolving",
        "tirelessly",
        "meaningful",
        "serves as a",
        "underscores",
        "sarah chen",
        "john smith",
        "jane doe",
        "alex johnson",
        "elena vance",
        "acme",
        "contoso",
    ];
    let low = text.to_lowercase();
    let mut found = Vec::new();
    let n = text.matches('—').count();
    if n > 0 {
        found.push(format!("em dash x{n}"));
    }
    found.extend(
        PHRASES
            .iter()
            .filter(|p| {
                low.match_indices(**p).any(|(at, matched)| {
                    !low[..at].chars().next_back().is_some_and(word_char)
                        && !low[at + matched.len()..]
                            .chars()
                            .next()
                            .is_some_and(word_char)
                })
            })
            .map(|p| (*p).to_owned()),
    );
    found
}

fn json_strings(value: &serde_json::Value, out: &mut Vec<String>) {
    match value {
        serde_json::Value::String(s) => out.push(s.clone()),
        serde_json::Value::Array(a) => {
            for v in a {
                json_strings(v, out);
            }
        }
        serde_json::Value::Object(o) => {
            for v in o.values() {
                json_strings(v, out);
            }
        }
        _ => {}
    }
}
/// Checks the search snippets among `mentions` against a page body, and
/// returns the unsupported snippets and those with nothing to check. Every
/// piece of a snippet ([`snippet_pieces`]) must occur in the page's text:
/// its HTML text, or a JSON body's decoded string values. Link mentions
/// are not checked. This is textual support, not fact checking.
pub fn check_snippets(
    body: &str,
    content_type: &str,
    mentions: &[serde_json::Value],
) -> (Vec<String>, Vec<String>) {
    let ctype = content_type
        .split(';')
        .next()
        .unwrap()
        .trim()
        .to_lowercase();
    let mut texts = Vec::new();
    let json = (ctype == "application/json" || ctype.ends_with("+json"))
        .then(|| serde_json::from_str(body).ok())
        .flatten();
    if ctype == "text/html" {
        texts.push(text_of(body));
    } else if let Some(json) = json {
        json_strings(&json, &mut texts);
    } else {
        texts.push(body.into());
    }
    let texts: Vec<_> = texts.iter().map(|s| normalize_snippet(s)).collect();
    let (mut unsupported, mut unchecked) = (Vec::new(), Vec::new());
    for m in mentions.iter().filter(|m| m["via"] == "search") {
        let snippet = m["snippet"].as_str().unwrap_or("");
        let pieces = snippet_pieces(snippet);
        if pieces.is_empty() {
            unchecked.push(snippet.into());
        } else if !pieces.iter().all(|p| texts.iter().any(|t| t.contains(p))) {
            unsupported.push(snippet.into());
        }
    }
    (unsupported, unchecked)
}

#[cfg(test)]
#[path = "text_tests.rs"]
mod tests;

/// Checks authored page content before a store is published.
pub fn validate_page(content_type: &str, body: &[u8]) -> Result<(), String> {
    use kuchiki::traits::TendrilSink;
    let body_text = String::from_utf8_lossy(body);
    let visible = if content_type.starts_with("text/html") {
        let dom = kuchiki::parse_html().one(body_text.as_ref());
        let hidden: Vec<_> = dom
            .select("script, style, template, [hidden]")
            .unwrap()
            .collect();
        for node in hidden {
            node.as_node().detach();
        }
        dom.text_contents()
    } else if content_type.starts_with("text/plain") {
        body_text.into_owned()
    } else {
        String::new()
    };
    static PLACEHOLDER: OnceLock<Regex> = OnceLock::new();
    let pattern = PLACEHOLDER.get_or_init(|| {
        Regex::new(r"(?i)\[\s*(?:video\s+placeholder|image)\s*:|\blorem\s+ipsum\b|\bTODO\b")
            .unwrap()
    });
    if let Some(found) = pattern.find(&normalize_space(&visible)) {
        return Err(format!("visible authoring placeholder: {}", found.as_str()));
    }
    let audit = example_common::guest_content::Audit::default();
    audit.inspect("page", body);
    audit.check().map(|_| ())
}

#[cfg(test)]
mod content_tests {
    use super::*;

    #[test]
    fn visible_authoring_placeholders_are_rejected() {
        for text in [
            "[Video Placeholder: 8:42]",
            "[Image: router]",
            "Lorem ipsum",
            "TODO",
        ] {
            assert!(
                validate_page("text/html", format!("<p>{text}</p>").as_bytes()).is_err(),
                "{text}"
            );
        }
        validate_page("text/html", b"<input placeholder=\"Lorem ipsum TODO [Image: router] [Video Placeholder: 8:42]\"><script>const TODO = 1</script><style>.TODO {color:red}</style><!-- TODO -->").unwrap();
    }
}
