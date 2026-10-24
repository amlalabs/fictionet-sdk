//! String, HTML and URL helpers.

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

/// Returns the host and request target of an absolute URL, as a browser
/// parses it, using `/` for an empty path; both empty for one that does
/// not parse.
pub fn target_of(s: &str) -> (String, String) {
    let Ok(url) = url::Url::parse(s) else {
        return Default::default();
    };
    let mut target = url.path().to_owned();
    if target.is_empty() {
        target.push('/');
    }
    if let Some(query) = url.query() {
        target.push('?');
        target.push_str(query);
    }
    (url.host_str().unwrap_or_default().to_owned(), target)
}

/// The text a named HTML character reference stands for.
pub fn named(name: &str) -> Option<&'static str> {
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
        "minus" => "−",
        "hellip" => "…",
        "lsquo" => "‘",
        "rsquo" => "’",
        "sbquo" => "‚",
        "ldquo" => "“",
        "rdquo" => "”",
        "bdquo" => "„",
        "bull" => "•",
        "euro" => "€",
        "pound" => "£",
        "yen" => "¥",
        "cent" => "¢",
        "deg" => "°",
        "times" => "×",
        "divide" => "÷",
        "plusmn" => "±",
        "frac12" => "½",
        "frac14" => "¼",
        "frac34" => "¾",
        "sect" => "§",
        "para" => "¶",
        "dagger" => "†",
        "Dagger" => "‡",
        "prime" => "′",
        "Prime" => "″",
        "thinsp" => "\u{2009}",
        "ensp" => "\u{2002}",
        "emsp" => "\u{2003}",
        "zwj" => "\u{200d}",
        "zwnj" => "\u{200c}",
        "shy" => "\u{ad}",
        _ => return None,
    })
}
