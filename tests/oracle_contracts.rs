//! Structural guards for executable growth and shared-oracle claims.
//!
//! These checks find measurements and calls, not semantic correctness or the
//! right scaling dimension. Counter bounds and helper mutations still need
//! their executable tests. Imports are resolved textually, without expanding
//! macros or evaluating feature gates.

#[path = "common/rust_docs.rs"]
mod rust_docs;

use std::collections::BTreeMap;
use std::fs;
use std::ops::Range;
use std::path::{Path, PathBuf};

const ROOT: &str = env!("CARGO_MANIFEST_DIR");
const MEASURES: &[&str] = &[
    "assert_linear",
    "assert_linear_with_setup",
    "assert_linear_work",
    "assert_constant_work",
    "check_work",
    "pump_with_copy_bound",
];

fn sources(dir: &Path) -> BTreeMap<PathBuf, String> {
    let mut out = BTreeMap::new();
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            out.extend(sources(&path));
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.insert(path.clone(), fs::read_to_string(path).unwrap());
        }
    }
    out
}

fn contains(tokens: &[&str], needle: &[&str]) -> bool {
    tokens.windows(needle.len()).any(|part| part == needle)
}

fn group_end(tokens: &[&str], start: usize) -> usize {
    let closing = match tokens[start] {
        "(" => ")",
        "[" => "]",
        "{" => "}",
        other => panic!("expected group, got {other}"),
    };
    let mut at = start + 1;
    while tokens.get(at) != Some(&closing) {
        match tokens.get(at).expect("closed token group") {
            &"(" | &"[" | &"{" => at = group_end(tokens, at),
            &")" | &"]" | &"}" => panic!("mismatched token group"),
            _ => {}
        }
        at += 1;
    }
    at
}

#[derive(Debug)]
struct Item<'a> {
    name: &'a str,
    head: Range<usize>,
    body: Range<usize>,
}

fn items<'a>(tokens: &[&'a str], kind: &str) -> Vec<Item<'a>> {
    let mut out = Vec::new();
    for at in 0..tokens.len().saturating_sub(2) {
        if tokens[at] != kind || !identifier(tokens[at + 1]) {
            continue;
        }
        let start = tokens[..at]
            .iter()
            .rposition(|t| matches!(*t, ";" | "{" | "}"))
            .map_or(0, |i| i + 1);
        let mut body = at + 2;
        while body < tokens.len() && !matches!(tokens[body], "{" | ";") {
            if matches!(tokens[body], "(" | "[") {
                body = group_end(tokens, body);
            }
            body += 1;
        }
        if tokens.get(body) == Some(&"{") {
            out.push(Item {
                name: tokens[at + 1],
                head: start..at,
                body: body + 1..group_end(tokens, body),
            });
        }
    }
    out
}

fn identifier(token: &str) -> bool {
    token.starts_with(|c: char| c.is_alphabetic() || c == '_')
        && token.chars().all(|c| c.is_alphanumeric() || c == '_')
}

fn unmeasured_tests(source: &str) -> Vec<String> {
    let tokens = rust_docs::tokens(source);
    items(&tokens, "fn")
        .into_iter()
        .filter(|item| {
            contains(&tokens[item.head.clone()], &["#", "[", "test", "]"])
                && (item.name.contains("linear") || item.name.contains("quadratic"))
        })
        .filter(|item| {
            let body = &tokens[item.body.clone()];
            let helper = body
                .windows(2)
                .any(|call| MEASURES.contains(&call[0]) && call[1] == "(");
            // Raw counters count only as upper bounds in assertions, never
            // as a discarded read or a positive-work check.
            let bound = body.windows(3).enumerate().any(|(at, words)| {
                if words != ["assert", "!", "("] {
                    return false;
                }
                let condition = &body[at + 3..group_end(body, at + 2)];
                condition.windows(5).enumerate().any(|(i, call)| {
                    (call == [".", "examined", "(", ")", "<"]
                        || call == [".", "moved", "(", ")", "<"]
                        || (call == [".", "used", "(", ")", "<"]
                            && condition.get(i.wrapping_sub(1)) == Some(&"work")))
                        && condition.get(i + 5) != Some(&"<")
                })
            });
            !helper && !bound
        })
        .map(|item| item.name.to_owned())
        .collect()
}

fn parity_claims(source: &str) -> Vec<String> {
    let tokens = rust_docs::tokens(source);
    let modules = items(&tokens, "mod");
    items(&tokens, "fn")
        .into_iter()
        .filter(|item| {
            let parents: Vec<_> = modules
                .iter()
                .filter(|module| module.body.contains(&item.head.end))
                .collect();
            let test = parents.iter().any(|m| {
                contains(
                    &tokens[m.head.clone()],
                    &["#", "[", "cfg", "(", "test", ")", "]"],
                )
            });
            let harness = parents
                .iter()
                .any(|m| m.name == "harness" && tokens[m.head.clone()].contains(&"pub"));
            if !test || harness {
                return false;
            }
            let start = item.head.start.checked_sub(1).map_or(0, |i| {
                tokens[i].as_ptr() as usize - source.as_ptr() as usize + tokens[i].len()
            });
            let end = tokens[item.head.end].as_ptr() as usize - source.as_ptr() as usize;
            let (_, docs) = rust_docs::parts(&source[start..end]);
            let docs = docs
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
                .to_lowercase();
            [
                "what the fuzz target checks",
                "everything the fuzz target checks",
                "the checks the fuzz target makes",
                "the same checks the fuzz target makes",
            ]
            .iter()
            .any(|claim| docs.contains(claim))
        })
        .map(|item| item.name.to_owned())
        .collect()
}

#[derive(Clone, Debug)]
struct Import {
    path: Vec<String>,
    local: String,
}

fn use_tree(tokens: &[&str], prefix: &[String], out: &mut Vec<Import>) {
    let mut path = prefix.to_vec();
    let mut at = 0;
    while at < tokens.len() {
        match tokens[at] {
            ":" => at += 1,
            "{" => {
                let end = group_end(tokens, at);
                let mut start = at + 1;
                at = start;
                while at < end {
                    if tokens[at] == "{" {
                        at = group_end(tokens, at);
                    } else if tokens[at] == "," {
                        use_tree(&tokens[start..at], &path, out);
                        start = at + 1;
                    }
                    at += 1;
                }
                use_tree(&tokens[start..end], &path, out);
                return;
            }
            "as" => {
                out.push(Import {
                    path,
                    local: tokens[at + 1].to_owned(),
                });
                return;
            }
            word => {
                if word != "self" || path.is_empty() {
                    path.push(word.to_owned());
                }
                at += 1;
            }
        }
    }
    if let Some(local) = path.last() {
        out.push(Import {
            local: local.clone(),
            path,
        });
    }
}

fn imports<'a>(tokens: &[&'a str]) -> (Vec<Import>, Vec<&'a str>) {
    let mut out = Vec::new();
    let mut code = Vec::new();
    let mut at = 0;
    while at < tokens.len() {
        if tokens[at] == "use" {
            let end = at
                + tokens[at..]
                    .iter()
                    .position(|t| *t == ";")
                    .expect("use terminator");
            use_tree(&tokens[at + 1..end], &[], &mut out);
            at = end + 1;
        } else {
            code.push(tokens[at]);
            at += 1;
        }
    }
    (out, code)
}

fn absolute(path: &[String], scope: &[String]) -> Option<Vec<String>> {
    let mut base = scope.to_vec();
    let mut at = 0;
    while path.get(at).is_some_and(|p| p == "super") {
        base.pop()?;
        at += 1;
    }
    if path.get(at).is_some_and(|p| p == "self") {
        at += 1;
    } else if at == 0 {
        return Some(path.to_vec());
    }
    base.extend_from_slice(&path[at..]);
    Some(base)
}

fn harness_called(tokens: &[&str], module: &str, scope: &[String], exports: &[String]) -> bool {
    let (uses, code) = imports(tokens);
    let prefix = ["fictionet", "stdlib", module, "harness"].map(str::to_owned);
    let is_harness = |path: &[String]| {
        path.starts_with(&prefix) && path.get(4).is_some_and(|name| exports.contains(name))
    };
    for at in 0..code.len() {
        if !identifier(code[at]) || (at > 0 && matches!(code[at - 1], ":" | "." | "fn")) {
            continue;
        }
        let mut path = vec![code[at].to_owned()];
        let mut end = at + 1;
        while code.get(end..end + 2) == Some(&[":", ":"])
            && code.get(end + 2).is_some_and(|t| identifier(t))
        {
            path.push(code[end + 2].to_owned());
            end += 3;
        }
        if code.get(end..end + 3) == Some(&[":", ":", "<"]) {
            end += 3;
            let mut depth = 1;
            while depth > 0 {
                match *code.get(end).expect("closed generic arguments") {
                    "<" => depth += 1,
                    ">" => depth -= 1,
                    _ => {}
                }
                end += 1;
            }
        }
        let mapped =
            at >= 3 && code[at - 3..at] == [".", "map", "("] && code.get(end) == Some(&")");
        if code.get(end) != Some(&"(") && !mapped {
            continue;
        }
        if absolute(&path, scope).is_some_and(|path| is_harness(&path)) {
            return true;
        }
        for import in &uses {
            let Some(mut resolved) = absolute(&import.path, scope) else {
                continue;
            };
            if import.local == "*" {
                resolved.pop();
                resolved.extend_from_slice(&path);
            } else if import.local == path[0] {
                resolved.extend_from_slice(&path[1..]);
            } else {
                continue;
            }
            if is_harness(&resolved) {
                return true;
            }
        }
    }
    false
}

fn harness_gaps(
    module: &str,
    source: &str,
    targets: &[(String, String)],
    tests: &[String],
) -> Vec<String> {
    let tokens = rust_docs::tokens(source);
    let modules = items(&tokens, "mod");
    let Some(harness) = modules
        .iter()
        .find(|m| m.name == "harness" && tokens[m.head.clone()].contains(&"pub"))
    else {
        return Vec::new();
    };
    let exports: Vec<_> = tokens[harness.body.clone()]
        .windows(3)
        .filter(|words| words[0] == "pub" && matches!(words[1], "fn" | "struct" | "enum" | "type"))
        .map(|words| words[2].to_owned())
        .collect();
    let root = ["fictionet", "stdlib", module].map(str::to_owned);
    let mut gaps = Vec::new();
    let mut target_count = 0;
    for (name, target) in targets {
        let target = rust_docs::tokens(target);
        let (uses, _) = imports(&target);
        if uses.iter().any(|import| import.path.starts_with(&root)) {
            target_count += 1;
            if !harness_called(&target, module, &[], &exports) {
                gaps.push(format!("{module}: {name} does not call its harness"));
            }
        }
    }
    if target_count == 0 {
        gaps.push(format!("{module}: no importing fuzz target"));
    }
    let unit_call = modules
        .iter()
        .filter(|m| {
            contains(
                &tokens[m.head.clone()],
                &["#", "[", "cfg", "(", "test", ")", "]"],
            )
        })
        .any(|test| {
            let mut scope = root.to_vec();
            for parent in &modules {
                if parent.body.contains(&test.head.end) {
                    scope.push(parent.name.to_owned());
                }
            }
            scope.push(test.name.to_owned());
            harness_called(&tokens[test.body.clone()], module, &scope, &exports)
        });
    if !unit_call
        && !tests
            .iter()
            .any(|test| harness_called(&rust_docs::tokens(test), module, &[], &exports))
    {
        gaps.push(format!("{module}: no test-side harness call"));
    }
    gaps
}

#[test]
fn growth_claims_have_measurements() {
    for dir in ["src/stdlib", "tests"] {
        for (file, source) in sources(&Path::new(ROOT).join(dir)) {
            let missing = unmeasured_tests(&source);
            assert!(
                missing.is_empty(),
                "{}: unmeasured tests {missing:?}",
                file.display()
            );
        }
    }
}

#[test]
fn shared_harnesses_have_both_callers() {
    let targets: Vec<_> = sources(&Path::new(ROOT).join("fuzz/fuzz_targets"))
        .into_iter()
        .map(|(path, source)| (path.display().to_string(), source))
        .collect();
    let tests: Vec<_> = sources(&Path::new(ROOT).join("tests"))
        .into_values()
        .collect();
    let mut gaps = Vec::new();
    for (path, source) in sources(&Path::new(ROOT).join("src/stdlib")) {
        let module = path.file_stem().unwrap().to_str().unwrap();
        gaps.extend(harness_gaps(module, &source, &targets, &tests));
    }
    assert!(gaps.is_empty(), "{}", gaps.join("\n"));
}

#[test]
fn parity_docs_belong_to_harnesses() {
    for (path, source) in sources(&Path::new(ROOT).join("src/stdlib")) {
        let claims = parity_claims(&source);
        assert!(
            claims.is_empty(),
            "{}: unshared parity claims {claims:?}",
            path.display()
        );
    }
}

#[test]
fn measurement_fixtures() {
    let source = r#"
        #[test] fn count_in_linear_time() { assert_eq!(count, 10); }
        #[test] fn comments_are_linear() {
            // assert_linear("ignored", 1, run);
            let text = "check_work(make, bytes, measured, 1, 1)";
            let reference = assert_linear_work;
        }
        #[test] fn linear_counter_read() { frames.examined(); }
        #[test] fn quadratic_positive_work() { assert!(frames.work.used() > 0); }
        #[test] fn linear_unasserted_bound() { let _ = stream.moved() <= bytes.len(); }
        #[test] fn measured_is_linear() { assert_linear_work("decode", "bytes", 16, measure); }
        #[test] fn copies_are_linear() { assert!(stream.moved() <= input.len()); }
        #[test] fn linear_scan() { assert!(frames.examined() < bound); }
        #[test] fn quadratic_guard() { assert!(frames.work.used() <= bound); }
        #[test] fn pumped_copies_are_linear() { pump_with_copy_bound(&mut stream, &input, on).unwrap(); }
        #[test] fn state_is_linear() { assert_constant_work("read", "held bytes", 16, measure); }
        #[test] fn timed_in_linear_time() { assert_linear("decode", 16, run); }
        #[test] fn setup_is_linear() { assert_linear_with_setup("decode", 16, setup, run, check); }
        #[test] fn audited_is_linear() { check_work(make, bytes, measured, 1, 1); }
        fn unrelated_is_linear() { assert_linear("elsewhere", 16, run); }
    "#;
    assert_eq!(
        unmeasured_tests(source),
        [
            "count_in_linear_time",
            "comments_are_linear",
            "linear_counter_read",
            "quadratic_positive_work",
            "linear_unasserted_bound",
        ]
    );
}

#[test]
fn harness_fixtures() {
    let declaration = "#[cfg(any(test, fuzzing))] pub mod harness { pub fn check(data: &[u8]) {} }";
    let source = format!(
        "{declaration} #[cfg(test)] mod tests {{ use super::harness::check as run; #[test] fn sample() {{ run(b\"\"); }} }}"
    );
    for target in [
        "use fictionet::stdlib::demo::harness; fuzz_target!(|data| { harness::check(data); });",
        "use fictionet::stdlib::{demo as d}; fuzz_target!(|data| { d::harness::check(data); });",
        "use fictionet::stdlib::demo::{harness::{check as run}}; fuzz_target!(|data| { run(data); });",
        "use fictionet::stdlib::demo::harness::check; fuzz_target!(|data| { check::<Vec<u8>>(data); });",
        "use fictionet::stdlib::demo::harness::check; fuzz_target!(|data| { data.iter().map(check).sum::<usize>(); });",
    ] {
        assert!(harness_gaps("demo", &source, &[("demo".into(), target.into())], &[]).is_empty());
    }
    let target = vec![(
        "demo".into(),
        "use fictionet::stdlib::demo::*; fuzz_target!(|data| { harness::check(data); });".into(),
    )];
    assert_eq!(
        harness_gaps("demo", declaration, &target, &[]),
        ["demo: no test-side harness call"]
    );
    let import_only = format!(
        "{declaration} #[cfg(test)] mod tests {{ use super::harness; #[test] fn sample() {{ let text = \"harness::check(data)\"; }} }}"
    );
    assert_eq!(
        harness_gaps("demo", &import_only, &target, &[]),
        ["demo: no test-side harness call"]
    );
    let bypass = vec![(
        "demo".into(),
        "use fictionet::stdlib::demo::harness::check; fuzz_target!(|data| { other(data); });"
            .into(),
    )];
    assert_eq!(
        harness_gaps("demo", &source, &bypass, &[]),
        ["demo: demo does not call its harness"]
    );
    let integration =
        "use fictionet::stdlib::demo::harness; #[test] fn check() { harness::check(b\"\"); }";
    assert!(harness_gaps("demo", declaration, &target, &[integration.into()]).is_empty());
    let nested = "pub mod harness { pub fn check(data: &[u8]) {} #[cfg(test)] mod tests { use super::*; #[test] fn sample() { check(b\"\"); } } }";
    assert!(harness_gaps("demo", nested, &target, &[]).is_empty());
}

#[test]
fn parity_fixtures() {
    for claim in [
        "What the fuzz target checks.",
        "Everything the fuzz target checks.",
        "The checks the fuzz target makes.",
        "The same checks the fuzz target makes.",
    ] {
        let source =
            format!("#[cfg(test)] mod tests {{\n/// {claim}\nfn check(data: &[u8]) {{}}\n}}");
        assert_eq!(parity_claims(&source), ["check"]);
        let shared = format!("pub mod harness {{ {source} }}");
        assert!(parity_claims(&shared).is_empty());
    }
    assert!(
        parity_claims(
            r#"#[cfg(test)] mod tests {
        // What the fuzz target checks was moved to the harness.
        /// Regression for an input found by the fuzz target.
        fn historical_case() { let text = "What the fuzz target checks"; }
    }"#
        )
        .is_empty()
    );
}
