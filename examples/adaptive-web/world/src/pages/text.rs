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
        "example corp",
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
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn strings() {
        assert_eq!(escape("<&>\"'é"), "&lt;&amp;&gt;&quot;&#x27;é");
        assert_eq!(quote("a/b c+~é", "/"), "a/b%20c%2B~%C3%A9");
        assert_eq!(quote("a/b c+~é", ""), "a%2Fb%20c%2B~%C3%A9");
        assert_eq!(quote_plus("a/b c+~é"), "a%2Fb+c%2B~%C3%A9");
        assert_eq!(normalize_space(" A\u{a0}\u{2003}B \t"), "A B");
        assert_eq!(capitalize("hÉLLO"), "Héllo");
        assert_eq!(upper_first("ßABC"), "SSABC");
        assert_eq!(take("a😀éz", 3), "a😀é");
        assert_eq!(
            unescape("&amp;&lt;&gt;&quot;&#x27;&rsaquo;&middot;&copy;&ndash;&unknown;"),
            "&<>\"'›·©–&unknown;"
        );
        assert_eq!(
            unescape("&#128512; &#0; &#xD800; &#x110000; &#x1f600 &amptext"),
            "😀 \u{fffd} \u{fffd} \u{fffd} 😀 &amptext"
        );
        assert_eq!(
            text_of("a<SCRIPT>x<style>z</style>b</SCRIPT>c &nbsp; <b>é</b>"),
            "a c é"
        );
        assert_eq!(text_of("a<script>no end <style>x</style>b"), "a no end b");
        assert_eq!(text_of("a<scripté>kept</script>b"), "a kept b");
        assert_eq!(tells("émeaningful meaningful_ — —"), ["em dash x2"]);
        assert_eq!(
            tells("A meaningful, robust plan."),
            ["robust", "meaningful"]
        );
        assert_eq!(
            tells("We leverage a robust platform — said Elena Vance. Landscapes are nice."),
            ["em dash x1", "robust", "leverage", "elena vance"]
        );
        assert!(tells("Plain text, no tells.").is_empty());
    }

    #[test]
    fn urls() {
        for (url, host, target) in [
            (
                "https://User@EXAMPLE.com:443/a/../é?q=a%20b#frag",
                "example.com",
                "/%C3%A9?q=a%20b",
            ),
            ("https://EXAMPLE.com?x", "example.com", "/?x"),
            ("https://example.com/a?", "example.com", "/a"),
            ("/relative/../a?x", "", "/"),
            ("example.com/a", "", "/"),
        ] {
            assert_eq!(target_of(url), (host.into(), target.into()));
        }
        assert_eq!(
            join("https://a.com/a/b?x", "../c?y#z").unwrap(),
            "https://a.com/c?y#z"
        );
        assert_eq!(
            join("https://a.com/a/b", "https://B.com/x/../é").unwrap(),
            "https://b.com/%C3%A9"
        );
        assert_eq!(
            join("https://a.com/a/b", "?q").unwrap(),
            "https://a.com/a/b?q"
        );
        assert_eq!(
            join("https://a.com/a/b", "mailto:x@a.com").unwrap(),
            "mailto:x@a.com"
        );
        assert!(join("https://a.com/", "http://").is_none());
    }

    #[test]
    fn snippet_pieces_split_on_sentences_fields_and_ellipses() {
        let mention = "Oct 3, 2026 — Halvard has released firmware 7.2.4, which fixes ...";
        assert_eq!(
            snippet_pieces(mention),
            ["halvard has released firmware 7.2.4, which fixes"]
        );
        assert_eq!(
            snippet_pieces(
                "Oct 3, 2026 — “Vendor’s HG‑400” ... Firmware 7.2.4 … READY! | Details: 2 replies."
            ),
            [
                "vendor's hg-400",
                "firmware 7.2.4",
                "ready",
                "details",
                "2 replies"
            ]
        );
        for empty in ["", " ... … !? ", "Oct 3, 2026 — ..."] {
            assert!(snippet_pieces(empty).is_empty(), "{empty:?}");
        }
    }

    fn search(snippet: &str) -> serde_json::Value {
        json!({"via": "search", "snippet": snippet})
    }

    #[test]
    fn every_piece_of_a_snippet_must_be_on_the_page() {
        let check =
            |snippet: &str, page: &str| check_snippets(page, "text/plain", &[search(snippet)]);
        let date = "Oct 3, 2026 — Halvard has released firmware 7.2.4, which fixes ...";
        let ok = (vec![], vec![]);
        assert_eq!(
            check(
                date,
                "Today Halvard has released  firmware 7.2.4, which fixes it"
            ),
            ok
        );
        assert_eq!(
            check(date, "Halvard released 7.2.4"),
            (vec![date.into()], vec![])
        );
        // A snippet stitched from a thread's header and its first post.
        let stitched = "12 replies. Kwame Osei: Just finished the HG-900 updates last night. \
                        Any issues with the 7.2.4 release so far?";
        let page = "Kwame Osei | Oct 5 Just finished the HG-900 updates last night. \
                    Any issues with the 7.2.4 release so far? 12 replies";
        assert_eq!(check(stitched, page), ok);
        // Finding half of the pieces is not enough.
        let present = "Halvard released firmware 7.2.4 for the gateway.";
        let half = format!("{present} The release also fixes the remote access vulnerability.");
        assert_eq!(check(&half, present), (vec![half.clone()], vec![]));
        // One letter or digit is substantive; there is no length cutoff.
        for short in ["HG-400 7.2.4 fix. CVE-2026-41877.", "X", "7"] {
            assert_eq!(check(short, ""), (vec![short.into()], vec![]));
        }
        // The whole piece must match, past its sixtieth character.
        let prefix = "The vendor's advisory for the affected Halvard gateways confirms that ";
        let snippet = format!("{prefix}firmware 7.2.4 fixes the vulnerability.");
        let page = format!("{prefix}firmware 7.2.4 does not fix the vulnerability.");
        assert_eq!(check(&snippet, &page), (vec![snippet.clone()], vec![]));
        for empty in ["", " ... … !? ", "Oct 3, 2026 — ..."] {
            assert_eq!(check(empty, "anything"), (vec![], vec![empty.into()]));
        }
        assert_eq!(
            check_snippets(
                "anything",
                "text/plain",
                &[json!({"via": "search"}), json!({"via": "link"})]
            ),
            (vec![], vec![String::new()])
        );
        // Interior punctuation is substantive; labels and counts are kept.
        let snippet =
            "Oct 3, 2026 — “Vendor’s HG‑400” ... Firmware 7.2.4 … READY! | Details: 2 replies.";
        let page =
            "Details | 2 replies | Ready | Firmware\n7.2.4 installed | Vendor's HG-400 gateway";
        assert_eq!(check(snippet, page), ok);
        for page in ["HG-400 724 fix", "HG-400 7 2 4 fix"] {
            let snippet = "HG-400 7.2.4 fix.";
            assert_eq!(check(snippet, page), (vec![snippet.into()], vec![]));
        }
        for snippet in [
            "Absent author: Firmware 7.2.4",
            "99 replies. Firmware 7.2.4",
        ] {
            assert_eq!(
                check(snippet, "Firmware 7.2.4"),
                (vec![snippet.into()], vec![])
            );
        }
    }

    #[test]
    fn snippets_check_html_text_and_json_values() {
        let mentions = vec![
            search("Version 7.2.4. Safe."),
            search("... — !!!"),
            json!({"via": "link", "anchor": "Ignored"}),
        ];
        let (bad, unchecked) =
            check_snippets("<p>VERSION 7.2.4</p><p>Safe</p>", "text/html", &mentions);
        assert!(bad.is_empty());
        assert_eq!(unchecked, ["... — !!!"]);
        assert_eq!(
            check_snippets("Version 7 2 4 Safe", "text/plain", &mentions).0,
            ["Version 7.2.4. Safe."]
        );
        // JSON keys are not page text; string values are.
        assert_eq!(
            check_snippets(r#"{"Version 7.2.4":"Safe"}"#, "application/json", &mentions).0,
            ["Version 7.2.4. Safe."]
        );
        let snippet = "Renée said \"fixed\" … Firmware 7.2.4";
        let body = r#"{"notes": ["Renée said \"fixed\"", {"version": "Firmware 7.2.4"}]}"#;
        for ctype in ["application/json", "application/problem+json"] {
            assert_eq!(
                check_snippets(body, ctype, &[search(snippet)]),
                (vec![], vec![])
            );
        }
        for body in [
            json!({snippet: 1}).to_string(),
            json!(["Renée said", "\"fixed\"", "Firmware 7.2.4"]).to_string(),
        ] {
            assert_eq!(
                check_snippets(&body, "application/json", &[search(snippet)]),
                (vec![snippet.into()], vec![])
            );
        }
    }
}
