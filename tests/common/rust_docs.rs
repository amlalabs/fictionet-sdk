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
                for (at, ch) in line.char_indices() {
                    if ch != 'r' {
                        continue;
                    }
                    let rest = &line[at + 1..];
                    let hashes = rest.bytes().take_while(|&byte| byte == b'#').count();
                    if rest.as_bytes().get(hashes) == Some(&b'"') {
                        closing = Some(format!("\"{}", "#".repeat(hashes)));
                        text = &rest[hashes + 1..];
                        break;
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
