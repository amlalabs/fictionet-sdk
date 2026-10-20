//! Reproduces Python's string, HTML and URL behavior so the Rust and Python
//! stubs return the same page bytes and metadata.

use regex::Regex;
use std::sync::OnceLock;

/// Tests whitespace with Python's additional control characters.
pub fn whitespace(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}
/// Trims Python whitespace from both ends.
pub fn strip(s: &str) -> &str {
    s.trim_matches(whitespace)
}
/// Joins runs of words with one space.
pub fn normalize_space(s: &str) -> String {
    s.split(whitespace)
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
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
/// Titlecases the first character and lowercases the rest, as Python does.
pub fn capitalize(s: &str) -> String {
    let Some(first) = s.chars().next() else {
        return String::new();
    };
    let title = match first {
        'Ǆ' | 'ǅ' | 'ǆ' => "ǅ".into(),
        'Ǉ' | 'ǈ' | 'ǉ' => "ǈ".into(),
        'Ǌ' | 'ǋ' | 'ǌ' => "ǋ".into(),
        'Ǳ' | 'ǲ' | 'ǳ' => "ǲ".into(),
        '\u{1f80}'..='\u{1f87}' | '\u{1f90}'..='\u{1f97}' | '\u{1fa0}'..='\u{1fa7}' => {
            char::from_u32(first as u32 + 8).unwrap().to_string()
        }
        '\u{1f88}'..='\u{1f8f}'
        | '\u{1f98}'..='\u{1f9f}'
        | '\u{1fa8}'..='\u{1faf}'
        | '\u{1fbc}'
        | '\u{1fcc}'
        | '\u{1ffc}' => first.to_string(),
        '\u{1fb3}' | '\u{1fc3}' | '\u{1ff3}' => {
            char::from_u32(first as u32 + 9).unwrap().to_string()
        }
        _ => {
            let mut cased = false;
            first
                .to_uppercase()
                .map(|c| {
                    if cased {
                        c.to_lowercase().collect::<String>()
                    } else {
                        cased = c.is_uppercase();
                        c.to_string()
                    }
                })
                .collect::<String>()
        }
    };
    // Lowercase the whole string so a final Greek sigma sees its context.
    title
        + &s.to_lowercase()
            .chars()
            .skip(first.to_lowercase().count())
            .collect::<String>()
}
/// Escapes HTML text and both kinds of quotes.
pub fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}
/// Percent-encodes UTF-8 bytes, preserving unreserved and `safe` characters.
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

/// Returns the host, path and query without changing path segments or escapes.
pub fn split_url(s: &str) -> (String, String, String) {
    let s = s
        .trim_start_matches(|c| c <= '\u{20}')
        .replace(['\t', '\r', '\n'], "");
    let mut rest = s.as_str();
    if let Some((scheme, tail)) = rest.split_once(':')
        && scheme.starts_with(|c: char| c.is_ascii_alphabetic())
        && scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c))
    {
        rest = tail;
    }
    let mut host = String::new();
    if let Some(authority) = rest.strip_prefix("//") {
        let end = authority.find(['/', '?', '#']).unwrap_or(authority.len());
        let authority_host = authority[..end].rsplit('@').next().unwrap_or("");
        host = if let Some(v6) = authority_host.strip_prefix('[') {
            v6.split(']').next().unwrap_or("").to_lowercase()
        } else {
            authority_host
                .split(':')
                .next()
                .unwrap_or("")
                .to_lowercase()
        };
        rest = &authority[end..];
    }
    let rest = rest.split('#').next().unwrap_or("");
    let (path, query) = rest.split_once('?').unwrap_or((rest, ""));
    (host, path.into(), query.into())
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

/// Resolves links while leaving absolute URLs as written, like urljoin.
pub fn join(base: &str, href: &str) -> Option<String> {
    if href.is_empty() {
        return Some(base.into());
    }
    let (scheme, rest) = base.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    let href = if let Some((other, tail)) = href.split_once(':')
        && other.starts_with(|c: char| c.is_ascii_alphabetic())
        && other
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c))
    {
        if !other.eq_ignore_ascii_case(&scheme) {
            return Some(href.into());
        }
        tail
    } else {
        href
    };
    if href.starts_with("//") {
        return Some(format!("{scheme}:{href}"));
    }
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let origin = format!("{scheme}://{}", &rest[..end]);
    let (_, base_path, base_query) = split_url(base);
    let (link, fragment) = href
        .split_once('#')
        .map_or((href, None), |(p, f)| (p, Some(f)));
    let (path, query) = link
        .split_once('?')
        .map_or((link, None), |(p, q)| (p, Some(q)));
    let query_present =
        query.is_some() || (path.is_empty() && base.split('#').next().unwrap().contains('?'));
    let (path, query) = if path.is_empty() {
        (base_path, query.unwrap_or(&base_query))
    } else {
        let merged = if path.starts_with('/') {
            path.into()
        } else {
            format!(
                "{}/{path}",
                base_path.rsplit_once('/').map_or("", |(p, _)| p)
            )
        };
        let mut segments = Vec::new();
        let parts: Vec<_> = merged.split('/').collect();
        for (i, segment) in parts.iter().enumerate() {
            if !path.starts_with('/') && segment.is_empty() && i > 0 && i + 1 < parts.len() {
                continue;
            }
            match *segment {
                "." => {}
                ".." => {
                    segments.pop();
                }
                _ => segments.push(*segment),
            }
        }
        if merged.ends_with("/.") || merged.ends_with("/..") {
            segments.push("");
        }
        let resolved = segments.join("/");
        (
            if resolved.starts_with('/') {
                resolved
            } else {
                format!("/{resolved}")
            },
            query.unwrap_or(""),
        )
    };
    Some(format!(
        "{origin}{path}{}{}",
        if !query_present {
            String::new()
        } else {
            format!("?{query}")
        },
        fragment.map_or(String::new(), |f| format!("#{f}"))
    ))
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
fn numeric(n: u32) -> String {
    let n = match n {
        0 | 0xd800..=0xdfff | 0x110000.. => 0xfffd,
        0x80 => 0x20ac,
        0x82 => 0x201a,
        0x83 => 0x192,
        0x84 => 0x201e,
        0x85 => 0x2026,
        0x86 => 0x2020,
        0x87 => 0x2021,
        0x88 => 0x2c6,
        0x89 => 0x2030,
        0x8a => 0x160,
        0x8b => 0x2039,
        0x8c => 0x152,
        0x8e => 0x17d,
        0x91 => 0x2018,
        0x92 => 0x2019,
        0x93 => 0x201c,
        0x94 => 0x201d,
        0x95 => 0x2022,
        0x96 => 0x2013,
        0x97 => 0x2014,
        0x98 => 0x2dc,
        0x99 => 0x2122,
        0x9a => 0x161,
        0x9b => 0x203a,
        0x9c => 0x153,
        0x9e => 0x17e,
        0x9f => 0x178,
        1..=8 | 11 | 14..=31 | 127 | 0xfdd0..=0xfdef => return String::new(),
        n if n & 0xffff == 0xfffe || n & 0xffff == 0xffff => return String::new(),
        n => n,
    };
    char::from_u32(n).unwrap_or('\u{fffd}').to_string()
}
/// Decodes supported HTML entities with Python's numeric reference rules.
pub fn unescape(s: &str) -> String {
    static ENTITY: OnceLock<Regex> = OnceLock::new();
    ENTITY
        .get_or_init(|| {
            Regex::new(r"&(#(?:[xX][0-9a-fA-F]+|[0-9]+);?|[^\t\n\x0c <&#;]{1,32};?)").unwrap()
        })
        .replace_all(s, |c: &regex::Captures<'_>| {
            let raw = &c[1];
            if let Some(n) = raw.strip_prefix('#') {
                let n = n.trim_end_matches(';');
                let (n, radix) = if n.starts_with(['x', 'X']) {
                    (&n[1..], 16)
                } else {
                    (n, 10)
                };
                return numeric(u32::from_str_radix(n, radix).unwrap_or(u32::MAX));
            }
            if let Some(name) = raw.strip_suffix(';')
                && let Some(value) = named(name)
            {
                return value.into();
            }
            // These legacy names can omit their semicolon, including before text.
            for name in [
                "quot", "QUOT", "nbsp", "copy", "COPY", "reg", "REG", "amp", "AMP", "lt", "LT",
                "gt", "GT",
            ] {
                if let Some(tail) = raw.strip_prefix(name) {
                    return format!("{}{tail}", named(name).unwrap());
                }
            }
            c[0].into()
        })
        .into_owned()
}

fn alphanumeric(c: char) -> bool {
    static LETTER_OR_NUMBER: OnceLock<Regex> = OnceLock::new();
    LETTER_OR_NUMBER
        .get_or_init(|| Regex::new(r"^[\p{L}\p{N}]$").unwrap())
        .is_match(c.encode_utf8(&mut [0; 4]))
}
fn word_char(c: char) -> bool {
    c == '_' || alphanumeric(c)
}

/// Extracts normalized text from HTML, excluding scripts and styles.
pub fn text_of(markup: &str) -> String {
    static START: OnceLock<Regex> = OnceLock::new();
    static TAG: OnceLock<Regex> = OnceLock::new();
    let start = START.get_or_init(|| Regex::new(r"(?is)<(script|style)").unwrap());
    let mut rest = markup;
    let mut out = String::new();
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
/// Splits a snippet into searchable phrases without date prefixes.
pub fn snippet_pieces(s: &str) -> Vec<String> {
    static DATE: OnceLock<Regex> = OnceLock::new();
    static PUNCT: OnceLock<Regex> = OnceLock::new();
    let s = normalize_snippet(s);
    let s = DATE.get_or_init(|| Regex::new(r"^((jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec) \d{1,2}, \d{4}|\d+ (days?|hours?) ago)\s*-\s*").unwrap()).replace(&s, "");
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
        } else if whitespace(cs[i]) && i > 0 && ".!?:".contains(cs[i - 1]) {
            while end < cs.len() && whitespace(cs[end]) {
                end += 1;
            }
        } else if "|·".contains(cs[i])
            && i > 0
            && whitespace(cs[i - 1])
            && cs.get(i + 1).is_some_and(|c| whitespace(*c))
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
            let s = s.trim_matches(|c| whitespace(c) || punct.is_match(&c.to_string()));
            s.chars().any(alphanumeric).then(|| s.to_owned())
        })
        .collect()
}

/// Python's indented JSON uses ASCII escapes, including surrogate pairs.
pub fn json_pretty(value: &serde_json::Value) -> String {
    let json = serde_json::to_string_pretty(value).unwrap();
    let mut out = String::new();
    for c in json.chars() {
        if c < '\u{7f}' {
            out.push(c);
        } else {
            use std::fmt::Write;
            for code in c.encode_utf16(&mut [0; 2]) {
                write!(&mut out, "\\u{code:04x}").unwrap();
            }
        }
    }
    out
}

/// Lists matching phrases and patterns associated with generated text.
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
/// Returns unsupported snippets and snippets with no searchable text.
pub fn rescore_snippets(
    body: &str,
    content_type: &str,
    mentions: &[serde_json::Value],
) -> (Vec<String>, Vec<String>) {
    let ctype = strip(content_type.split(';').next().unwrap()).to_lowercase();
    let mut texts = Vec::new();
    if ctype == "text/html" {
        texts.push(text_of(body));
    } else if ctype == "application/json" || ctype.ends_with("+json") {
        json_strings(
            &serde_json::from_str(body).expect("generated JSON"),
            &mut texts,
        );
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
    #[test]
    fn python_strings() {
        assert_eq!(escape("<&>\"'é"), "&lt;&amp;&gt;&quot;&#x27;é");
        assert_eq!(quote("a/b c+~é", "/"), "a/b%20c%2B~%C3%A9");
        assert_eq!(quote("a/b c+~é", ""), "a%2Fb%20c%2B~%C3%A9");
        assert_eq!(quote_plus("a/b c+~é"), "a%2Fb+c%2B~%C3%A9");
        assert_eq!(normalize_space("\u{1c} A\u{a0}\u{2003}B \u{1f}"), "A B");
        assert_eq!(capitalize("hÉLLO"), "Héllo");
        assert_eq!(capitalize("ΟΣ"), "Ος");
        assert_eq!(capitalize("ßABC"), "Ssabc");
        assert_eq!(capitalize("ǳABC"), "ǲabc");
        assert_eq!(capitalize("ᾀABC"), "ᾈabc");
        assert_eq!(upper_first("ßABC"), "SSABC");
        assert_eq!(take("a😀éz", 3), "a😀é");
        assert_eq!(
            unescape("&amp;&lt;&gt;&quot;&#x27;&rsaquo;&middot;&copy;&ndash;&unknown;"),
            "&<>\"'›·©–&unknown;"
        );
        assert_eq!(
            unescape("&#128; &#0; &#xD800; &#x110000; &#13; &#1; &#x1f600; &amptext"),
            "€ � � � \r  😀 &text"
        );
        assert_eq!(
            text_of("a<SCRIPT>x<style>z</style>b</SCRIPT>c &nbsp; <b>é</b>"),
            "a c é"
        );
        assert_eq!(text_of("a<script>no end <style>x</style>b"), "a no end b");
        assert_eq!(text_of("a<script\u{301}>gone</script>b"), "a b");
        assert_eq!(text_of("a<scripté>kept</script>b"), "a kept b");
        assert_eq!(
            tells("émeaningful meaningful\u{301} meaningful_ — —"),
            ["em dash x2", "meaningful"]
        );
        assert!(snippet_pieces("\u{345}").is_empty());
        assert_eq!(
            snippet_pieces("Oct 3, 2026 — ‘7.2.4’. Next… wow | yes · 3 days ago: end!"),
            ["7.2.4", "next", "wow", "yes", "3 days ago", "end"]
        );
        assert_eq!(
            json_pretty(&serde_json::json!({"a":"é😀"})),
            "{\n  \"a\": \"\\u00e9\\ud83d\\ude00\"\n}"
        );
    }
    #[test]
    fn python_urls() {
        for (url, host, target) in [
            (
                "https://User@EXAMPLE.com:443/a/../é?q=a%20b#frag",
                "example.com",
                "/a/../é?q=a%20b",
            ),
            ("https://EXAMPLE.com?x", "example.com", "/?x"),
            ("/relative/../a?x", "", "/relative/../a?x"),
            ("//EXAMPLE.com/a?", "example.com", "/a"),
        ] {
            assert_eq!(target_of(url), (host.into(), target.into()));
        }
        assert_eq!(
            join("https://a.com/a/b?x", "../c?y#z").unwrap(),
            "https://a.com/c?y#z"
        );
        assert_eq!(
            join("https://a.com/a/b", "https://B.com/x/../é").unwrap(),
            "https://B.com/x/../é"
        );
        assert_eq!(
            join("https://a.com/a/b", "../é x").unwrap(),
            "https://a.com/é x"
        );
        assert_eq!(
            join("https://a.com/a//b", "c//d").unwrap(),
            "https://a.com/a/c/d"
        );
        assert_eq!(
            join("https://a.com/a/b", "/c//d").unwrap(),
            "https://a.com/c//d"
        );
        assert_eq!(
            join("https://a.com/a/b", "HTTPS://B.com/../x").unwrap(),
            "https://B.com/../x"
        );
        assert_eq!(
            join("https://a.com/a/b?x", "?").unwrap(),
            "https://a.com/a/b?"
        );
        assert_eq!(json_pretty(&serde_json::json!("\u{7f}")), "\"\\u007f\"");
    }
    #[test]
    fn snippets_check_each_piece_and_json_values() {
        let mentions = vec![
            serde_json::json!({"via":"search","snippet":"Version 7.2.4. Safe."}),
            serde_json::json!({"via":"search","snippet":"... — !!!"}),
            serde_json::json!({"via":"link","anchor":"Ignored"}),
        ];
        let (bad, unchecked) =
            rescore_snippets("<p>VERSION 7.2.4</p><p>Safe</p>", "text/html", &mentions);
        assert!(bad.is_empty());
        assert_eq!(unchecked, ["... — !!!"]);
        assert_eq!(
            rescore_snippets("Version 7 2 4 Safe", "text/plain", &mentions).0,
            ["Version 7.2.4. Safe."]
        );
        assert_eq!(
            rescore_snippets(r#"{"Version 7.2.4":"Safe"}"#, "application/json", &mentions).0,
            ["Version 7.2.4. Safe."]
        );
        assert!(
            rescore_snippets(
                r#"["Version 7.2.4", "Safe"]"#,
                "application/json",
                &mentions
            )
            .0
            .is_empty()
        );
    }
}
