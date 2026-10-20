/// The source without its `#[cfg(test)]` items, wherever they appear.
fn production(source: &str) -> String {
    const MARK: &str = "#[cfg(test)]";
    let mut model = String::new();
    let mut rest = source;
    while let Some(at) = rest.find(MARK) {
        model.push_str(&rest[..at]);
        rest = &rest[at + MARK.len()..];
        rest = &rest[item_len(rest)..];
    }
    model.push_str(rest);
    model
}

/// The length of the item at the start of `text`: up to the brace closing
/// its first block, or its first semicolon outside any block. Braces in
/// comments, strings and character literals do not count.
fn item_len(text: &str) -> usize {
    let bytes = text.as_bytes();
    let mut depth = 0usize;
    let mut i = 0;
    while i < bytes.len() {
        let next = bytes.get(i + 1).copied();
        match bytes[i] {
            b'/' if next == Some(b'/') => {
                i += text[i..].find('\n').unwrap_or(text.len() - i);
                continue;
            }
            b'/' if next == Some(b'*') => {
                i += 2 + text[i + 2..].find("*/").expect("closed comment") + 2;
                continue;
            }
            b'r' if matches!(next, Some(b'"' | b'#'))
                && (i == 0 || !bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'b') =>
            {
                let hashes = text[i + 1..].bytes().take_while(|&b| b == b'#').count();
                let open = i + 1 + hashes;
                if bytes.get(open) == Some(&b'"') {
                    let close = format!("\"{}", "#".repeat(hashes));
                    i = open
                        + 1
                        + text[open + 1..].find(&close).expect("closed raw string")
                        + close.len();
                    continue;
                }
            }
            b'"' => {
                i += 1;
                while bytes[i] != b'"' {
                    i += if bytes[i] == b'\\' { 2 } else { 1 };
                }
            }
            b'\'' => {
                if next == Some(b'\\') {
                    i += 2 + text[i + 2..].find('\'').expect("closed character") + 1;
                    continue;
                }
                let c = text[i + 1..].chars().next().expect("character");
                if bytes.get(i + 1 + c.len_utf8()) == Some(&b'\'') {
                    i += 2 + c.len_utf8();
                    continue;
                }
            }
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return i + 1;
                }
            }
            b';' if depth == 0 => return i + 1,
            _ => {}
        }
        i += 1;
    }
    panic!("unterminated test item");
}

#[test]
fn production_items_after_a_test_module_are_scanned() {
    let source = concat!(
        "fn a() {}\n",
        "#[cfg(test)]\n",
        "use super::*;\n",
        "#[cfg(test)]\n",
        "mod tests {\n",
        "    // A comment's brace: }\n",
        "    fn t<'a>(x: &'a str) { let s = \"}\"; let c = '{'; let r = r#\"}\"#; }\n",
        "}\n",
        "fn b(x: f64) -> f64 { x.sqrt() }\n",
    );
    let model = production(source);
    assert!(model.contains("fn a()"));
    assert!(model.contains("x.sqrt()"), "{model}");
    assert!(!model.contains("fn t<"), "{model}");
    assert!(!model.contains("use super"), "{model}");
    let protection = production(include_str!("../src/protection.rs"));
    assert!(protection.contains("fn automatic_actions("));
    assert!(!protection.contains("mod automatic_tests"));
}

#[test]
fn model_sources_use_fixed_arithmetic_without_clocks() {
    let sources = [
        ("kinetics", include_str!("../src/kinetics.rs")),
        ("plant", include_str!("../src/plant.rs")),
        ("commands", include_str!("../src/plant/commands.rs")),
        ("steam", include_str!("../src/steam.rs")),
        ("sensors", include_str!("../src/sensors.rs")),
        ("protection", include_str!("../src/protection.rs")),
        ("faults", include_str!("../src/faults.rs")),
        ("command", include_str!("../src/command.rs")),
        ("snapshot", include_str!("../src/snapshot.rs")),
        ("stages", include_str!("../src/stages.rs")),
        ("severe", include_str!("../src/severe.rs")),
        ("primary", include_str!("../src/severe/primary.rs")),
        ("core", include_str!("../src/severe/core.rs")),
        ("vessel", include_str!("../src/severe/vessel.rs")),
        ("containment", include_str!("../src/severe/containment.rs")),
        ("cavity", include_str!("../src/severe/cavity.rs")),
        ("spaces", include_str!("../src/severe/spaces.rs")),
        ("stylized", include_str!("../src/stylized.rs")),
        ("scenarios", include_str!("../src/scenarios.rs")),
    ];
    let forbidden = [
        ".exp(",
        ".exp2(",
        ".exp_m1(",
        ".ln(",
        ".ln_1p(",
        ".log(",
        ".log2(",
        ".log10(",
        ".powf(",
        ".powi(",
        ".sqrt(",
        ".cbrt(",
        ".sin(",
        ".cos(",
        ".tan(",
        ".sinh(",
        ".cosh(",
        ".tanh(",
        ".asin(",
        ".acos(",
        ".atan(",
        ".atan2(",
        ".hypot(",
        "mul_add",
        "Instant",
        "SystemTime",
    ];
    for (name, source) in sources {
        let model = production(source);
        let compact: String = model.chars().filter(|c| !c.is_whitespace()).collect();
        for call in forbidden {
            assert!(!compact.contains(call), "{name} contains {call}");
        }
    }
}
