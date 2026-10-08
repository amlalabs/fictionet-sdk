//! Keeps the docs' `fictionet attach` flags true to the binary.
//!
//! A newcomer meets attach's flags on many pages: the README, the crate
//! root, `getting_started`, `running`, `lowering`, `stdlib::web` and
//! `recipes`. These tests read those pages as text and check three things
//! against `ATTACH_USAGE`, the help text in `src/bin/fictionet/args.rs`:
//!
//! - every flag in a `fictionet attach` command shown in the docs is one
//!   attach takes;
//! - the flag table in `attaching`, [Every flag], lists every flag attach
//!   takes, so a page can link there for any of them;
//! - every page that names an attach flag in its prose links to
//!   `attaching`, where the flag is explained.
//!
//! The roadmap is left out: it shows planned flags on purpose.

use std::collections::BTreeSet;

/// Every page a reader can land on, by its path in the repository.
const PAGES: &[(&str, &str)] = &[
    ("README.md", include_str!("../README.md")),
    ("src/lib.rs", include_str!("../src/lib.rs")),
    (
        "src/getting_started.rs",
        include_str!("../src/getting_started.rs"),
    ),
    ("src/running.rs", include_str!("../src/running.rs")),
    ("src/attaching.rs", include_str!("../src/attaching.rs")),
    ("src/lowering.rs", include_str!("../src/lowering.rs")),
    ("src/recipes.rs", include_str!("../src/recipes.rs")),
    ("src/observe.rs", include_str!("../src/observe.rs")),
    ("src/proto.rs", include_str!("../src/proto.rs")),
    ("src/stdlib/mod.rs", include_str!("../src/stdlib/mod.rs")),
    ("src/stdlib/web.rs", include_str!("../src/stdlib/web.rs")),
    (
        "examples/attach/netns.sh",
        include_str!("../examples/attach/netns.sh"),
    ),
];

const ARGS: &str = include_str!("../src/bin/fictionet/args.rs");

/// The text of `ATTACH_USAGE`.
fn usage() -> &'static str {
    let head = "ATTACH_USAGE: &str = \"\\";
    let start = ARGS.find(head).expect("ATTACH_USAGE in args.rs") + head.len();
    let len = ARGS[start..].find("\";").expect("the end of ATTACH_USAGE");
    &ARGS[start..start + len]
}

/// Every `--flag` in `text`, without a value after `=`.
fn flags(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    while let Some(at) = text[i..].find("--") {
        let start = i + at;
        let mut end = start + 2;
        while end < bytes.len()
            && (bytes[end].is_ascii_lowercase()
                || bytes[end].is_ascii_digit()
                || bytes[end] == b'-')
        {
            end += 1;
        }
        // `--` alone, or a long rule of dashes, is not a flag.
        let before_ok =
            start == 0 || !(bytes[start - 1].is_ascii_alphanumeric() || bytes[start - 1] == b'-');
        if end > start + 2 && bytes[start + 2].is_ascii_lowercase() && before_ok {
            out.insert(text[start..end].trim_end_matches('-').to_owned());
        }
        i = end.max(start + 2);
    }
    out
}

/// The text of a page that a reader sees: the `//!` and `///` lines of a
/// Rust file, or the whole of any other file.
fn doc_text(path: &str, text: &str) -> String {
    if !path.ends_with(".rs") {
        return text.to_owned();
    }
    text.lines()
        .filter_map(|l| {
            l.trim_start()
                .strip_prefix("//!")
                .or_else(|| l.trim_start().strip_prefix("///"))
        })
        .map(|l| l.strip_prefix(' ').unwrap_or(l))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Each `fictionet attach ...` command in `text`, with its `\` line
/// continuations joined.
fn attach_commands(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let lines: Vec<&str> = text.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        if lines[i].contains("fictionet attach --") {
            let mut command = lines[i].to_owned();
            while command.trim_end().ends_with('\\') && i + 1 < lines.len() {
                i += 1;
                command = format!(
                    "{} {}",
                    command.trim_end().trim_end_matches('\\'),
                    lines[i].trim()
                );
            }
            let from = command.find("fictionet attach").unwrap();
            out.push(command[from..].to_owned());
        }
        i += 1;
    }
    out
}

/// The prose of `text`: everything outside ``` fences.
fn prose(text: &str) -> String {
    let mut out = String::new();
    let mut fenced = false;
    for line in text.lines() {
        if line.trim_start().starts_with("```") {
            fenced = !fenced;
            continue;
        }
        if !fenced {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

#[test]
fn the_usage_text_is_found() {
    let known = flags(usage());
    for flag in [
        "--world",
        "--name",
        "--type",
        "--down-link",
        "--world-wait",
        "--ready-file",
        "--vm",
        "--token-file",
    ] {
        assert!(
            known.contains(flag),
            "ATTACH_USAGE should mention {flag}; found {known:?}"
        );
    }
}

#[test]
fn every_attach_command_in_the_docs_uses_real_flags() {
    let mut known = flags(usage());
    known.insert("--help".into());
    let mut bad = Vec::new();
    for (path, text) in PAGES {
        for command in attach_commands(&doc_text(path, text)) {
            for flag in flags(&command) {
                if !known.contains(&flag) {
                    bad.push(format!("{path}: {flag} in `{command}`"));
                }
            }
        }
    }
    assert!(
        bad.is_empty(),
        "flags that fictionet attach does not take:\n{}",
        bad.join("\n")
    );
}

#[test]
fn attaching_lists_every_flag() {
    let attaching = doc_text("src/attaching.rs", include_str!("../src/attaching.rs"));
    let start = attaching
        .find("\n# Every flag\n")
        .expect("attaching has an 'Every flag' section");
    let rest = &attaching[start + 1..];
    let end = rest[1..].find("\n# ").map_or(rest.len(), |e| e + 1);
    let table = flags(&rest[..end]);
    let missing: Vec<_> = flags(usage())
        .into_iter()
        .filter(|f| f != "--help")
        // `--no-dns` and the like are covered by the row for their flag.
        .filter(|f| {
            !table.contains(f)
                && !f
                    .strip_prefix("--no-")
                    .is_some_and(|base| table.contains(&format!("--{base}")))
        })
        // The `-v6` forms, and their `--no-` forms, are covered by the row
        // for the IPv4 flag.
        .filter(|f| {
            let base = f.strip_suffix("-v6").map(|b| b.replacen("--no-", "--", 1));
            !base.is_some_and(|b| table.contains(&b))
        })
        .collect();
    assert!(
        missing.is_empty(),
        "attaching's 'Every flag' table should list {missing:?}"
    );
}

#[test]
fn a_page_that_names_an_attach_flag_links_to_attaching() {
    // Flags that other commands take as well, and so say nothing about
    // attach on their own.
    let shared = ["--world", "--listen", "--help"];
    let known = flags(usage());
    let mut bad = Vec::new();
    for (path, text) in PAGES {
        if *path == "src/attaching.rs" || path.ends_with(".sh") {
            continue;
        }
        let text = doc_text(path, text);
        let named: Vec<_> = flags(&prose(&text))
            .into_iter()
            .filter(|f| known.contains(f) && !shared.contains(&f.as_str()))
            .collect();
        let links = text.contains("crate::attaching")
            || text.contains("fictionet::attaching")
            || text.contains("(attaching")
            || text.contains("[`attaching`]")
            || text.contains("src/attaching.rs");
        if !named.is_empty() && !links {
            bad.push(format!(
                "{path} names {named:?} but never links to attaching"
            ));
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}
