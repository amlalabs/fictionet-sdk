//! Separates Rust source from line docs and raw documentation attributes.

pub fn parts(source: &str) -> (String, String) {
    let (mut code, mut docs) = (String::new(), String::new());
    let mut closing: Option<String> = None;
    for line in source.lines() {
        let mut text = line;
        if closing.is_none() {
            let trimmed = line.trim_start();
            if let Some(doc) = trimmed
                .strip_prefix("//!")
                .or_else(|| trimmed.strip_prefix("///"))
            {
                docs.push_str(doc.strip_prefix(' ').unwrap_or(doc));
                docs.push('\n');
                continue;
            }
            if trimmed.starts_with("//") {
                continue;
            }
            if trimmed.starts_with("#[doc =") || trimmed.starts_with("#![doc =") {
                let value = trimmed.split_once('=').unwrap().1.trim_start();
                if let Some(rest) = value.strip_prefix('r') {
                    let hashes = rest.bytes().take_while(|&byte| byte == b'#').count();
                    if rest.as_bytes().get(hashes) == Some(&b'"') {
                        closing = Some(format!("\"{}", "#".repeat(hashes)));
                        text = &rest[hashes + 1..];
                    }
                }
            }
        }
        if let Some(end) = &closing {
            if let Some(at) = text.find(end) {
                docs.push_str(&text[..at]);
                docs.push('\n');
                closing = None;
            } else {
                docs.push_str(text);
                docs.push('\n');
            }
        } else {
            code.push_str(line);
            code.push('\n');
        }
    }
    (code, docs)
}

/// Tokens for the catalog's textual checks. Comments are omitted and literals
/// stay whole, so their contents cannot introduce declarations or delimiters.
pub fn tokens(mut source: &str) -> Vec<&str> {
    let mut out = Vec::new();
    while !source.is_empty() {
        source = source.trim_start();
        if source.is_empty() {
            break;
        }
        if source.starts_with("//") {
            source = &source[source.find('\n').unwrap_or(source.len())..];
            continue;
        }
        if source.starts_with("/*") {
            let mut depth = 1;
            let mut end = 2;
            while depth != 0 {
                assert!(end < source.len(), "unclosed block comment");
                match source.as_bytes().get(end..end + 2) {
                    Some(b"/*") => {
                        depth += 1;
                        end += 2;
                    }
                    Some(b"*/") => {
                        depth -= 1;
                        end += 2;
                    }
                    _ => end += 1,
                }
            }
            source = &source[end..];
            continue;
        }
        let raw = source
            .strip_prefix('r')
            .or_else(|| source.strip_prefix("br"));
        let raw_hashes = raw.map(|s| s.bytes().take_while(|&b| b == b'#').count());
        let end = if let Some((raw, hashes)) = raw.zip(raw_hashes)
            && raw.as_bytes().get(hashes) == Some(&b'"')
        {
            let start = source.len() - raw.len() + hashes + 1;
            let closing = format!("\"{}", "#".repeat(hashes));
            start + source[start..].find(&closing).expect("closed raw literal") + closing.len()
        } else if source.starts_with('"') {
            let mut end = 1;
            loop {
                match source.as_bytes().get(end).expect("closed string literal") {
                    b'\\' => end += 2,
                    b'"' => break end + 1,
                    _ => end += 1,
                }
            }
        } else if source.starts_with('\'') && source[1..].starts_with('\\') {
            let end = if source[2..].starts_with('u') {
                3 + source[3..].find('}').expect("closed Unicode escape") + 1
            } else if source[2..].starts_with('x') {
                5
            } else {
                3
            };
            assert_eq!(
                source.as_bytes().get(end),
                Some(&b'\''),
                "closed character literal"
            );
            end + 1
        } else if source.starts_with('\'')
            && let Some(ch) = source[1..].chars().next()
            && source.as_bytes().get(1 + ch.len_utf8()) == Some(&b'\'')
        {
            ch.len_utf8() + 2
        } else {
            let first = source.chars().next().unwrap();
            if first.is_alphanumeric() || first == '_' {
                source
                    .find(|c: char| !c.is_alphanumeric() && c != '_')
                    .unwrap_or(source.len())
            } else {
                first.len_utf8()
            }
        };
        out.push(&source[..end]);
        source = &source[end..];
    }
    out
}

#[test]
fn literals_and_comments_do_not_introduce_tokens() {
    assert_eq!(
        tokens(
            r###"/* pub mod fake; /* nested */ */ pub type T = Map<A, F>; // }
            const S: &str = r#"pub mod fake; {"#; const C: char = '}';"###
        ),
        [
            "pub",
            "type",
            "T",
            "=",
            "Map",
            "<",
            "A",
            ",",
            "F",
            ">",
            ";",
            "const",
            "S",
            ":",
            "&",
            "str",
            "=",
            "r#\"pub mod fake; {\"#",
            ";",
            "const",
            "C",
            ":",
            "char",
            "=",
            "'}'",
            ";"
        ]
    );
    assert_eq!(
        tokens(r#"'a '\'' "\"}" b'}'"#),
        ["'", "a", "'\\''", "\"\\\"}\"", "b", "'}'"]
    );
}

#[test]
fn examples_are_documentation_not_implementations() {
    let source = r####"/// Request handler.
/// ```rust
/// impl Service for Example {}
/// ```
impl Service for Actual {}
"####;
    let (code, docs) = parts(source);
    assert_eq!(code, "impl Service for Actual {}\n");
    assert_eq!(
        docs,
        "Request handler.\n```rust\nimpl Service for Example {}\n```\n"
    );
}

#[test]
fn ordinary_doc_attributes_are_not_raw_strings() {
    let source = "#[doc = \"Identifier\"]\npub struct Id;\n";
    assert_eq!(parts(source).0, source);
    let source = "#[doc = r#\"Example impl Decode for Fake {}\"#]\npub struct Id;\n";
    assert_eq!(
        parts(source),
        (
            "pub struct Id;\n".into(),
            "Example impl Decode for Fake {}\n".into()
        )
    );
}
