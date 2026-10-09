//! The protocol catalog in `src/stdlib/mod.rs` must match the code.
//!
//! The catalog is a Markdown table in the module docs, one row per stdlib
//! module. These tests read it as text and check each column against its
//! source of truth:
//!
//! - the module list against the files in `src/stdlib/`;
//! - **Wire**, **Decode** (including `Prefixed`) and **Service** against the `impl` blocks in the
//!   module's file (doc comments and other comments are skipped first, so a
//!   doctest's example impl does not count);
//! - **State** against the `pub struct` and `pub enum` declarations;
//! - **Observe** against the built-ins the default registry gets in
//!   `src/observe/app.rs`; no module implements `Present`, which belongs
//!   in `src/observe/`;
//! - **Fuzz** against the targets in `fuzz/Cargo.toml`;
//! - **Copy** against the modules of `tests/copy_and_own/modules.rs`.
//!
//! A hidden module (`#[doc(hidden)]`) is listed without a link, because
//! rustdoc would make a dead one.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

const ROOT: &str = env!("CARGO_MANIFEST_DIR");
const MOD_RS: &str = include_str!("../src/stdlib/mod.rs");
const FUZZ_MANIFEST: &str = include_str!("../fuzz/Cargo.toml");
const COPY_MODULES: &str = include_str!("../tests/copy_and_own/modules.rs");
const OBSERVE_APP: &str = include_str!("../src/observe/app.rs");

/// Fuzz targets that fuzz no single stdlib module: the attach proxy, the
/// relay, the packet stack and the code generator. Any other target must
/// belong to a module, so a new one lands in the catalog.
const TARGETS_WITHOUT_A_MODULE: &[&str] = &[
    "codegen_ir",
    "packets",
    "proxy_http",
    "proxy_socks5",
    "relay",
    "stack",
];

/// One row of the table.
#[derive(Debug)]
struct Row {
    module: String,
    linked: bool,
    what: String,
    wire: bool,
    decode: bool,
    state: Vec<String>,
    service: Vec<String>,
    observe: String,
    fuzz: bool,
    copy: bool,
}

/// The names inside backticks in a cell, in order.
fn names(cell: &str) -> Vec<String> {
    cell.split('`')
        .skip(1)
        .step_by(2)
        .map(str::to_owned)
        .collect()
}

fn yes(cell: &str, column: &str, module: &str) -> bool {
    match cell {
        "yes" => true,
        "" => false,
        other => panic!("{module}: the {column} cell must be `yes` or empty, not {other:?}"),
    }
}

/// Parses the catalog table out of the module docs.
fn catalog() -> Vec<Row> {
    let lines: Vec<&str> = MOD_RS
        .lines()
        .skip_while(|l| l.trim() != "//! # The catalog")
        .filter_map(|l| l.strip_prefix("//! |"))
        .collect();
    let header = lines
        .first()
        .expect("the catalog table under `# The catalog` in src/stdlib/mod.rs");
    assert_eq!(
        header.trim(),
        "Module | What it is | Wire | Decode | State | Service | Observe | Fuzz | Copy |",
        "the catalog's columns"
    );
    let mut rows = Vec::new();
    for line in &lines[2..] {
        let cells: Vec<&str> = line.split('|').map(str::trim).collect();
        assert_eq!(cells.len(), 10, "nine cells in {line:?}");
        let module_cell = cells[0];
        let (module, linked) = if let Some(m) = module_cell
            .strip_prefix("[`")
            .and_then(|m| m.strip_suffix("`]"))
        {
            (m, true)
        } else if let Some(m) = module_cell
            .strip_prefix('`')
            .and_then(|m| m.strip_suffix('`'))
        {
            (m, false)
        } else {
            panic!("the module cell {module_cell:?} is neither [`name`] nor `name`");
        };
        assert!(!cells[1].is_empty(), "{module} has no description");
        assert!(
            cells[1].ends_with('.'),
            "{module}: the description is a sentence"
        );
        rows.push(Row {
            module: module.to_owned(),
            linked,
            what: cells[1].to_owned(),
            wire: yes(cells[2], "Wire", module),
            decode: yes(cells[3], "Decode", module),
            state: names(cells[4]),
            service: names(cells[5]),
            observe: cells[6].to_owned(),
            fuzz: yes(cells[7], "Fuzz", module),
            copy: yes(cells[8], "Copy", module),
        });
    }
    rows
}

/// The modules of `src/stdlib/`: every file and every directory with a
/// `mod.rs`, less the private ones (`mod x;` without `pub`).
fn modules_on_disk() -> BTreeMap<String, Vec<PathBuf>> {
    let private: BTreeSet<&str> = MOD_RS
        .lines()
        .filter_map(|l| l.strip_prefix("mod ").and_then(|l| l.strip_suffix(';')))
        .collect();
    let dir = Path::new(ROOT).join("src/stdlib");
    let mut modules = BTreeMap::new();
    for entry in fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_str().unwrap().to_owned();
        if path.is_dir() {
            let mut files: Vec<PathBuf> = fs::read_dir(&path)
                .unwrap()
                .map(|e| e.unwrap().path())
                .filter(|p| p.extension().is_some_and(|e| e == "rs"))
                .collect();
            files.sort();
            modules.insert(name, files);
        } else if let Some(stem) = name.strip_suffix(".rs")
            && stem != "mod"
            && !private.contains(stem)
        {
            modules.insert(stem.to_owned(), vec![path]);
        }
    }
    modules
}

/// A module's source with every comment line taken out, so that doc
/// examples do not count as implementations.
fn code(files: &[PathBuf]) -> String {
    let mut out = String::new();
    for file in files {
        for line in fs::read_to_string(file).unwrap().lines() {
            if !line.trim_start().starts_with("//") {
                out.push_str(line);
                out.push('\n');
            }
        }
    }
    out
}

/// The identifier right after each occurrence of `needle`.
fn idents_after<'a>(code: &'a str, needle: &str) -> BTreeSet<&'a str> {
    code.match_indices(needle)
        .map(|(i, _)| {
            let rest = &code[i + needle.len()..];
            let end = rest
                .find(|c: char| !(c.is_alphanumeric() || c == '_'))
                .unwrap_or(rest.len());
            &rest[..end]
        })
        .filter(|s| !s.is_empty())
        .collect()
}

fn declares(code: &str, name: &str) -> bool {
    ["pub struct ", "pub enum "]
        .iter()
        .any(|kw| idents_after(code, kw).contains(name))
}

fn hidden_modules() -> BTreeSet<&'static str> {
    let lines: Vec<&str> = MOD_RS.lines().collect();
    lines
        .windows(2)
        .filter(|w| w[0].trim() == "#[doc(hidden)]")
        .filter_map(|w| {
            w[1].strip_prefix("pub mod ")
                .and_then(|l| l.strip_suffix(';'))
        })
        .collect()
}

fn fuzz_targets() -> Vec<&'static str> {
    let lines: Vec<&str> = FUZZ_MANIFEST.lines().collect();
    lines
        .windows(2)
        .filter(|w| w[0].trim() == "[[bin]]")
        .map(|w| {
            w[1].strip_prefix("name = \"")
                .and_then(|l| l.strip_suffix('"'))
                .expect("a name after [[bin]]")
        })
        .collect()
}

/// The module a fuzz target belongs to: the longest module name that is the
/// target's name, or a prefix of it before an underscore, or the target's
/// name after `observe_`.
fn owner<'a>(target: &str, modules: impl Iterator<Item = &'a str>) -> Option<&'a str> {
    modules
        .filter(|m| {
            target == *m || target.starts_with(&format!("{m}_")) || target == format!("observe_{m}")
        })
        .max_by_key(|m| m.len())
}

/// The protocols `Registry::default()` registers, by name.
fn observe_builtins() -> BTreeSet<&'static str> {
    let lines: Vec<&str> = OBSERVE_APP.lines().collect();
    lines
        .windows(2)
        .filter(|w| w[0].trim_start().starts_with("registry.register"))
        .map(|w| {
            w[1].trim()
                .strip_prefix('"')
                .and_then(|l| l.strip_suffix("\","))
                .unwrap_or_else(|| panic!("a protocol name after {:?}", w[0]))
        })
        .collect()
}

#[test]
fn the_catalog_lists_every_module_once_in_order() {
    let rows = catalog();
    let listed: Vec<&str> = rows.iter().map(|r| r.module.as_str()).collect();
    let mut sorted = listed.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(
        listed, sorted,
        "the catalog is in alphabetical order, each module once"
    );
    let modules = modules_on_disk();
    let on_disk: Vec<&str> = modules.keys().map(String::as_str).collect();
    assert_eq!(
        listed, on_disk,
        "the catalog's modules and the files in src/stdlib/"
    );
}

#[test]
fn hidden_modules_are_not_linked() {
    let hidden = hidden_modules();
    assert_eq!(
        hidden.len(),
        MOD_RS.matches("#[doc(hidden)]\npub mod ").count(),
        "the parser found the hidden modules: {hidden:?}"
    );
    for row in catalog() {
        assert_eq!(
            row.linked,
            !hidden.contains(row.module.as_str()),
            "{}: a hidden module is listed as `name`, a documented one as [`name`]",
            row.module
        );
    }
}

#[test]
fn front_pages_describe_about_a_hundred_protocol_and_format_codecs() {
    assert!(include_str!("../README.md").contains("codecs (no I/O) for about a hundred"));
    assert!(include_str!("../src/lib.rs").contains("codecs (no I/O) for about a hundred"));
    let count = catalog()
        .iter()
        .filter(|row| row.wire || row.decode)
        .filter(|row| {
            !matches!(
                row.module.as_str(),
                "codec" | "test_support" | "huffman" | "prefix_int"
            )
        })
        .count();
    assert!(
        (90..=110).contains(&count),
        "front-page codec count needs updating: {count}"
    );
}

#[test]
fn wire_decode_and_service_columns_match_the_impls() {
    let modules = modules_on_disk();
    for row in catalog() {
        let code = code(&modules[&row.module]);
        assert_eq!(
            row.wire,
            code.contains("Wire for") || code.contains("codec::layout!"),
            "{}: the Wire column",
            row.module
        );
        assert_eq!(
            row.decode,
            (code.contains("Decode for") || code.contains("Prefixed for")),
            "{}: the Decode column",
            row.module
        );
        let services: BTreeSet<String> = idents_after(&code, "Service for ")
            .into_iter()
            .map(str::to_owned)
            .collect();
        let listed: BTreeSet<String> = row.service.iter().cloned().collect();
        assert_eq!(listed, services, "{}: the Service column", row.module);
        assert_eq!(
            listed.len(),
            row.service.len(),
            "{}: each service once",
            row.module
        );
    }
}

#[test]
fn state_names_are_public_types_of_the_module() {
    let modules = modules_on_disk();
    for row in catalog() {
        let code = code(&modules[&row.module]);
        for name in &row.state {
            assert!(
                declares(&code, name),
                "{}: the State column names {name}, which is not a pub struct or enum there",
                row.module
            );
        }
    }
}

#[test]
fn observe_column_matches_the_registry_and_the_presenters() {
    let builtins = observe_builtins();
    assert!(
        builtins.contains("dns") && builtins.contains("http1"),
        "the parser found the built-ins: {builtins:?}"
    );
    let modules = modules_on_disk();
    for name in &builtins {
        assert!(
            modules.contains_key(*name),
            "the built-in observe protocol {name} is named after a stdlib module"
        );
    }
    for row in catalog() {
        let code = code(&modules[&row.module]);
        assert!(
            !code.contains("Present for"),
            "{}: a presenter belongs in src/observe/, not in the protocol's module",
            row.module
        );
        let expected = if builtins.contains(row.module.as_str()) {
            "built in"
        } else {
            ""
        };
        assert_eq!(row.observe, expected, "{}: the Observe column", row.module);
    }
}

#[test]
fn fuzz_column_matches_the_fuzz_targets() {
    let rows = catalog();
    let targets = fuzz_targets();
    assert!(
        targets.len() > 100,
        "the parser found the fuzz targets: {}",
        targets.len()
    );
    let mut fuzzed = BTreeSet::new();
    let mut unowned = Vec::new();
    for target in &targets {
        match owner(target, rows.iter().map(|r| r.module.as_str())) {
            Some(m) => {
                fuzzed.insert(m);
            }
            None => unowned.push(*target),
        }
    }
    unowned.sort();
    assert_eq!(
        unowned, TARGETS_WITHOUT_A_MODULE,
        "every other fuzz target is named after its module"
    );
    for row in &rows {
        assert_eq!(
            row.fuzz,
            fuzzed.contains(row.module.as_str()),
            "{}: the Fuzz column",
            row.module
        );
    }
}

#[test]
fn copy_column_matches_the_copy_and_own_fixture() {
    for row in catalog() {
        let dir = Path::new(ROOT)
            .join("src/stdlib")
            .join(&row.module)
            .is_dir();
        let copied = if dir {
            COPY_MODULES.contains(&format!("src/stdlib/{}/", row.module))
        } else {
            COPY_MODULES.contains(&format!("\"../../src/stdlib/{}.rs\"", row.module))
        };
        assert_eq!(row.copy, copied, "{}: the Copy column", row.module);
    }
}

#[test]
fn every_implementation_file_is_copied() {
    let root = Path::new(ROOT);
    let mut dirs = vec![root.join("src/stdlib")];
    while let Some(dir) = dirs.pop() {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                dirs.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs")
                && path
                    .file_name()
                    .is_some_and(|name| name != "mod.rs" && name != "tests.rs")
            {
                let relative = path.strip_prefix(root).unwrap().to_str().unwrap();
                let direct = COPY_MODULES.contains(&format!("\"../../{relative}\""));
                let parent = path.with_file_name("mod.rs");
                let parent_relative = parent.strip_prefix(root).unwrap().to_str().unwrap();
                let nested = if COPY_MODULES.contains(&format!("\"../../{parent_relative}\"")) {
                    let name = path.file_stem().unwrap().to_str().unwrap();
                    fs::read_to_string(&parent).unwrap().lines().any(|line| {
                        let line = line.trim();
                        line == format!("pub mod {name};") || line == format!("mod {name};")
                    })
                } else {
                    false
                };
                assert!(
                    direct || nested,
                    "{relative}: missing from the copy fixture"
                );
            }
        }
    }
}

#[test]
fn descriptions_are_one_line_each() {
    for row in catalog() {
        assert!(
            row.what.len() <= 160,
            "{}: the description fits one line ({} chars)",
            row.module,
            row.what.len()
        );
    }
}
