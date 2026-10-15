//! The protocol catalog in `catalog/stdlib.rs` must match the code.
//!
//! The catalog has one declarative record per stdlib module. These tests
//! render `src/stdlib/catalog.md` deterministically and reject drift. Set
//! `BLESS_STDLIB_CATALOG=1` to update that documentation, following the golden
//! test convention. Each record is checked against independent sources:
//!
//! - the module list against external `pub mod` declarations, following literal `#[path]`
//!   attributes, ordinary `name.rs`/`name/mod.rs` paths, private child modules
//!   and the `cfg_std!`, `cfg_tokio!`, `cfg_observe!`, `cfg_web_proxy!` wrappers;
//! - **Wire**, **Decode** (including `Prefixed`) and **Service** against declarations
//!   in those files, excluding private types (line docs are skipped first,
//!   so a doctest's example impl does not count);
//! - **State** against the `pub struct` and `pub enum` declarations;
//! - **Observe** against the built-ins the default registry gets in
//!   `src/observe/app.rs`; no module implements `Present`, which belongs
//!   in `src/observe/`;
//! - **Fuzz** against the targets in `fuzz/Cargo.toml`;
//! - **Copy** against the modules of `tests/copy_and_own/modules.rs`.
//!
//! A hidden module (`#[doc(hidden)]`) is listed without a link, because
//! rustdoc would make a dead one.
//!
//! Trait discovery recognizes explicit impls, `text_wire!`, `prefixed!`,
//! `codec::layout!` and macros containing an impl. Decode also recognizes
//! module-level `pub type` aliases and `pub fn` return types headed by a
//! codec decoder (bare or codec-qualified), and functions returning
//! `impl Decode`. Decoder heads come from codec's own non-test impls.
//! Private aliases, methods and locally declared names do not count as
//! decoder exports. COTP and ONC RPC aliases also have compiled trait checks.
//!
//! This is textual discovery, not Rust name resolution or macro expansion.
//! Arbitrary re-exports, alias chains, new declaration macros and generic
//! wrappers require extending these checks. Feature gates are not evaluated.
//! Module traversal ignores explicit `#[cfg(test)]` declarations; file
//! inventories omit `tests.rs`. Impl matching remains textual within each file.
//! Independent file inventories catch undeclared and uncopied implementations.

#[path = "common/catalog.rs"]
mod catalog;
#[path = "common/rust_docs.rs"]
mod rust_docs;

use catalog::manifest::MODULES;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

const ROOT: &str = env!("CARGO_MANIFEST_DIR");
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

/// A textual item header and its optional brace body. Only the existing
/// feature-selection wrappers are transparent; ordinary bodies stay opaque.
#[derive(Debug)]
struct Item<'a> {
    head: &'a [&'a str],
    body: Option<&'a [&'a str]>,
}

fn group_end(tokens: &[&str], start: usize) -> usize {
    let closing = match tokens[start] {
        "(" => ")",
        "[" => "]",
        "{" => "}",
        other => panic!("expected a group, got {other}"),
    };
    let mut at = start + 1;
    while tokens.get(at) != Some(&closing) {
        match tokens.get(at).unwrap_or_else(|| {
            panic!(
                "unclosed group: {:?}",
                &tokens[start..tokens.len().min(start + 12)]
            )
        }) {
            &"(" | &"[" | &"{" => at = group_end(tokens, at),
            &")" | &"]" | &"}" => panic!("mismatched token group"),
            _ => {}
        }
        at += 1;
    }
    at
}

fn items<'a>(tokens: &'a [&'a str]) -> Vec<Item<'a>> {
    let mut out = Vec::new();
    let (mut start, mut at) = (0, 0);
    while at < tokens.len() {
        // Inner attributes belong to the file, not its first declaration.
        if tokens[at..].starts_with(&["#", "!", "["]) {
            at = group_end(tokens, at + 2) + 1;
            start = at;
            continue;
        }
        match tokens[at] {
            "(" | "[" => at = group_end(tokens, at),
            ";" | "{" => {
                let head = &tokens[start..at];
                let body = if tokens[at] == "{" {
                    let end = group_end(tokens, at);
                    let body = &tokens[at + 1..end];
                    at = end;
                    Some(body)
                } else {
                    None
                };
                let feature_wrapper = head.ends_with(&["!"])
                    && head.iter().any(|t| {
                        matches!(
                            *t,
                            "cfg_std" | "cfg_tokio" | "cfg_observe" | "cfg_web_proxy"
                        )
                    });
                if feature_wrapper && !test_only(head) {
                    out.extend(items(body.expect("feature wrapper body")));
                } else if !head.is_empty() {
                    out.push(Item { head, body });
                }
                start = at + 1;
            }
            _ => {}
        }
        at += 1;
    }
    assert_eq!(
        start,
        tokens.len(),
        "unterminated item: {:?}",
        &tokens[start..]
    );
    out
}

fn declaration<'a>(mut head: &'a [&'a str]) -> &'a [&'a str] {
    while head.starts_with(&["#", "["]) {
        head = &head[group_end(head, 1) + 1..];
    }
    head
}

fn test_only(head: &[&str]) -> bool {
    head.windows(6)
        .any(|w| w == ["#", "[", "cfg", "(", "test", ")"])
}

fn path_attribute<'a>(head: &[&'a str]) -> Option<&'a str> {
    let paths: Vec<_> = head
        .windows(6)
        .filter(|w| w[..4] == ["#", "[", "path", "="] && w[5] == "]")
        .map(|w| {
            w[4].strip_prefix('"')
                .and_then(|s| s.strip_suffix('"'))
                .expect("literal module path")
        })
        .collect();
    assert!(paths.len() <= 1, "ambiguous path attributes: {head:?}");
    assert_eq!(
        head.iter().filter(|&&t| t == "path").count(),
        paths.len(),
        "unsupported path attribute: {head:?}"
    );
    paths.first().copied()
}

fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for part in path.components() {
        if part == std::path::Component::ParentDir {
            assert!(out.pop(), "path escapes source tree: {}", path.display());
        } else {
            out.push(part);
        }
    }
    out
}

type Sources = BTreeMap<PathBuf, String>;

fn sources_on_disk(dir: &Path) -> Sources {
    let mut sources = Sources::new();
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            sources.extend(sources_on_disk(&path));
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            sources.insert(path.clone(), fs::read_to_string(path).unwrap());
        }
    }
    sources
}

#[derive(Debug)]
struct Module {
    public: bool,
    hidden: bool,
    inline: bool,
    files: BTreeSet<PathBuf>,
}

/// Resolve external declarations from their declaring file, not their public
/// name. Private descendants count too, including implementations re-exported
/// by a facade. `cfg(test)` modules are not implementation sources.
fn declared_modules(sources: &Sources, file: &Path) -> BTreeMap<String, Module> {
    discover(sources, file, false, &mut BTreeSet::new())
}

fn discover(
    sources: &Sources,
    file: &Path,
    path_loaded: bool,
    ancestors: &mut BTreeSet<PathBuf>,
) -> BTreeMap<String, Module> {
    assert!(
        ancestors.insert(file.to_owned()),
        "cyclic module source: {}",
        file.display()
    );
    fn collect(
        sources: &Sources,
        path_dir: &Path,
        dir: &Path,
        tokens: &[&str],
        ancestors: &mut BTreeSet<PathBuf>,
    ) -> BTreeMap<String, Module> {
        let mut modules = BTreeMap::new();
        for item in items(tokens) {
            if test_only(item.head) {
                continue;
            }
            let decl = declaration(item.head);
            let (public, decl) = match decl.strip_prefix(&["pub"]) {
                Some(decl) if decl.starts_with(&["("]) => (false, &decl[group_end(decl, 0) + 1..]),
                Some(decl) => (true, decl),
                None => (false, decl),
            };
            if !decl.starts_with(&["mod"]) {
                continue;
            }
            assert_eq!(decl.len(), 2, "module declaration: {decl:?}");
            let name = decl[1];
            let path = path_attribute(item.head);
            let mut files = BTreeSet::new();
            if let Some(body) = item.body {
                let child_dir = dir.join(path.unwrap_or(name));
                for module in
                    collect(sources, &child_dir, &child_dir, body, ancestors).into_values()
                {
                    files.extend(module.files);
                }
            } else {
                let candidates = if let Some(path) = path {
                    vec![normalize(&path_dir.join(path))]
                } else {
                    vec![
                        dir.join(format!("{name}.rs")),
                        dir.join(name).join("mod.rs"),
                    ]
                };
                let found: Vec<_> = candidates
                    .iter()
                    .filter(|p| sources.contains_key(*p))
                    .collect();
                assert_eq!(
                    found.len(),
                    1,
                    "missing or ambiguous module {name}: {candidates:?}"
                );
                files.insert(found[0].clone());
                for module in discover(sources, found[0], path.is_some(), ancestors).into_values() {
                    files.extend(module.files);
                }
            }
            let hidden = item
                .head
                .windows(6)
                .any(|w| w == ["#", "[", "doc", "(", "hidden", ")"]);
            assert!(
                modules
                    .insert(
                        name.to_owned(),
                        Module {
                            public,
                            hidden,
                            inline: item.body.is_some(),
                            files
                        }
                    )
                    .is_none(),
                "duplicate module {name}"
            );
        }
        modules
    }

    let source = sources
        .get(file)
        .unwrap_or_else(|| panic!("missing source: {}", file.display()));
    // Rust resolves children of every #[path]-loaded file as for mod.rs.
    let dir = if path_loaded || file.file_name().unwrap() == "mod.rs" {
        file.parent().unwrap().to_owned()
    } else {
        file.with_extension("")
    };
    let modules = collect(
        sources,
        file.parent().unwrap(),
        &dir,
        &rust_docs::tokens(source),
        ancestors,
    );
    assert!(ancestors.remove(file));
    modules
}

fn modules_on_disk() -> BTreeMap<String, Vec<PathBuf>> {
    let dir = Path::new(ROOT).join("src/stdlib");
    declared_modules(&sources_on_disk(&dir), &dir.join("mod.rs"))
        .into_iter()
        .filter(|(_, module)| module.public)
        .map(|(name, module)| {
            assert!(
                !module.inline,
                "inline catalog facade {name} needs scoped capability discovery"
            );
            (name, module.files.into_iter().collect())
        })
        .collect()
}

#[test]
fn component_sources_keep_the_entry_file_and_children() {
    let modules = modules_on_disk();
    let root = Path::new(ROOT);
    assert!(modules["net"].contains(&root.join("src/stdlib/net.rs")));
    assert!(modules["net"].contains(&root.join("src/stdlib/net/hosts.rs")));
    assert!(modules["codec"].contains(&root.join("src/stdlib/codec/combinators.rs")));
    assert!(!modules["codec"].contains(&root.join("src/stdlib/codec/tests.rs")));
}

/// A module's source with every comment line taken out, so that doc
/// examples do not count as implementations.
fn code(files: &[PathBuf]) -> String {
    files
        .iter()
        .map(|file| rust_docs::parts(&fs::read_to_string(file).unwrap()).0)
        .collect()
}

/// The identifier right after each occurrence of `needle`.
fn idents_after<'a>(code: &'a str, needle: &'a str) -> impl Iterator<Item = &'a str> {
    code.split(needle)
        .skip(1)
        .filter_map(|rest| {
            rest.split(|c: char| !(c.is_alphanumeric() || c == '_'))
                .next()
        })
        .filter(|s| !s.is_empty())
}

/// Derive decoder heads from codec implementations, so adding a combinator
/// does not require maintaining a second list here.
fn decoder_heads() -> &'static BTreeSet<String> {
    static HEADS: std::sync::OnceLock<BTreeSet<String>> = std::sync::OnceLock::new();
    HEADS.get_or_init(|| {
        let mut heads = BTreeSet::new();
        for file in &modules_on_disk()["codec"] {
            let source = fs::read_to_string(file).unwrap();
            let tokens = rust_docs::tokens(&source);
            for item in items(&tokens) {
                if !test_only(item.head) && declaration(item.head).starts_with(&["impl"]) {
                    for words in item.head.windows(3) {
                        if words[..2] == ["Decode", "for"] && declares(&source, words[2]) {
                            heads.insert(words[2].to_owned());
                        }
                    }
                }
            }
        }
        assert!(
            !heads.is_empty(),
            "codec decoder implementations were discovered"
        );
        heads
    })
}

fn decoder_export(code: &str) -> bool {
    let tokens = rust_docs::tokens(code);
    items(&tokens).iter().any(|item| {
        if test_only(item.head) {
            return false;
        }
        let head = declaration(item.head);
        let result = if head.starts_with(&["pub", "type"]) {
            signature_token(head, "=").map(|at| &head[at + 1..])
        } else if head.starts_with(&["pub", "fn"]) {
            signature_token(head, "(")
                .and_then(|at| head[group_end(head, at) + 1..].strip_prefix(&["-", ">"]))
        } else {
            None
        };
        let Some(mut result) = result else {
            return false;
        };
        let opaque = result.starts_with(&["impl"]);
        if opaque {
            result = &result[1..];
        }
        let mut end = 1;
        while result.get(end..end + 2) == Some(&[":", ":"]) {
            end += 3;
        }
        let Some(&name) = result.get(end - 1) else {
            panic!("missing exported return type: {head:?}");
        };
        let prefix = &result[..end - 1];
        let codec_path = prefix == ["codec", ":", ":"]
            || prefix == ["fictionet", ":", ":", "stdlib", ":", ":", "codec", ":", ":"];
        (prefix.is_empty() || codec_path)
            && !tokens
                .windows(2)
                .any(|w| matches!(w[0], "struct" | "enum" | "type") && w[1] == name)
            && if opaque {
                name == "Decode"
            } else {
                decoder_heads().contains(name)
            }
    })
}

/// Find a signature delimiter outside generic arguments and grouped tokens.
fn signature_token(head: &[&str], needle: &str) -> Option<usize> {
    let (mut at, mut depth) = (0, 0usize);
    while at < head.len() {
        if depth == 0 && head[at] == needle {
            return Some(at);
        }
        match head[at] {
            "<" => depth += 1,
            ">" if at == 0 || head[at - 1] != "-" => {
                depth = depth.checked_sub(1).expect("balanced generic arguments");
            }
            "(" | "[" | "{" => at = group_end(head, at),
            _ => {}
        }
        at += 1;
    }
    None
}

fn catalog_impl(code: &str, trait_name: &str) -> bool {
    // Strings and comments may describe impls without declaring one.
    let syntax = rust_docs::tokens(code)
        .into_iter()
        .filter(|token| !token.contains(['"', '\'']))
        .collect::<Vec<_>>()
        .join(" ");
    let needle = format!("{trait_name} for ");
    let (declaration, type_index, separator) = match trait_name {
        "Wire" => ("text_wire ! (", 2, ","),
        "Prefixed" => ("prefixed ! {", 0, "= > ("),
        _ => ("", 0, ""),
    };
    let declared = syntax
        .split(declaration)
        .skip(1)
        .take_while(|_| !declaration.is_empty())
        .filter_map(|call| call.split(separator).nth(type_index));
    (trait_name == "Decode" && decoder_export(code))
        || (trait_name == "Wire" && syntax.contains("codec : : layout !"))
        || syntax.contains(&format!("{needle}$"))
        || idents_after(&syntax, &needle)
            .chain(declared)
            .any(|name| catalog_type(&syntax, name.trim()))
}

fn declares(code: &str, name: &str) -> bool {
    rust_docs::tokens(code)
        .windows(3)
        .any(|w| w[0] == "pub" && matches!(w[1], "struct" | "enum") && w[2] == name)
}

// Macro-generated types are checked by their modules' compile tests. Exclude
// explicit private declarations while retaining those generated impls.
fn catalog_type(code: &str, name: &str) -> bool {
    declares(code, name)
        || !["struct ", "enum "]
            .iter()
            .any(|keyword| idents_after(code, keyword).any(|n| n == name))
}

#[test]
fn private_helpers_do_not_count_as_catalog_types() {
    let source = "struct DnsQueries; struct Dns; pub struct Public; pub(crate) struct Internal;";
    assert!(!catalog_type(source, "DnsQueries"));
    assert!(!catalog_type(source, "Dns"));
    assert!(!catalog_type(source, "Internal"));
    assert!(catalog_type(source, "Public"));
    for (name, declaration) in [
        ("Prefixed", "fictionet::prefixed! { A => (A, E, ()); }"),
        ("Wire", "fictionet::text_wire!(E, LIMIT, A, parse, write);"),
        ("Wire", "der_wire!(asn1, impl Wire for A, E, E::Bad);"),
        ("Decode", "impl Decode for A {}"),
    ] {
        assert!(!catalog_impl("pub struct A;", name));
        assert!(catalog_impl(&format!("pub struct A; {declaration}"), name));
        assert!(!catalog_impl(&format!("struct A; {declaration}"), name));
    }
}

fn hidden_modules() -> BTreeSet<String> {
    let dir = Path::new(ROOT).join("src/stdlib");
    declared_modules(&sources_on_disk(&dir), &dir.join("mod.rs"))
        .into_iter()
        .filter(|(_, module)| module.public && module.hidden)
        .map(|(name, _)| name)
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
fn catalog_documentation_is_current() {
    let expected = catalog::render(MODULES);
    assert_eq!(expected, catalog::render(MODULES));
    let path = Path::new(ROOT).join("src/stdlib/catalog.md");
    if std::env::var_os("BLESS_STDLIB_CATALOG").is_some() {
        fs::write(&path, &expected).unwrap();
    }
    let actual = fs::read_to_string(&path)
        .expect("read src/stdlib/catalog.md; set BLESS_STDLIB_CATALOG=1 to generate it");
    catalog::assert_documentation(&actual, &expected);
}

#[test]
fn the_catalog_lists_every_module_once_in_order() {
    let rows = MODULES;
    let listed: Vec<&str> = rows.iter().map(|r| r.module).collect();
    let mut sorted = listed.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(
        listed, sorted,
        "the catalog is in alphabetical order, each module once"
    );
    let modules = modules_on_disk();
    assert_module_names(&listed, modules.keys().cloned());
}

#[test]
fn hidden_modules_are_not_linked() {
    let hidden = hidden_modules();
    for row in MODULES {
        assert_eq!(
            row.linked,
            !hidden.contains(row.module),
            "{}: a hidden module is listed as `name`, a documented one as [`name`]",
            row.module
        );
    }
}

#[test]
fn front_pages_describe_about_a_hundred_protocol_and_format_codecs() {
    assert!(include_str!("../README.md").contains("codecs (no I/O) for about a hundred"));
    assert!(include_str!("../src/lib.rs").contains("codecs (no I/O) for about a hundred"));
    let count = MODULES
        .iter()
        .filter(|row| row.wire || row.decode)
        .filter(|row| {
            !matches!(
                row.module,
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
    for row in MODULES {
        let code = code(&modules[row.module]);
        assert_eq!(
            row.wire,
            catalog_impl(&code, "Wire"),
            "{}: the Wire column",
            row.module
        );
        assert_decode_column(row.module, row.decode, &code);
        let services: BTreeSet<&str> = idents_after(&code, "Service for ")
            .filter(|name| catalog_type(&code, name))
            .collect();
        let listed: BTreeSet<&str> = row.service.iter().copied().collect();
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
    for row in MODULES {
        let code = code(&modules[row.module]);
        for name in row.state {
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
    for row in MODULES {
        let code = code(&modules[row.module]);
        assert!(
            !code.contains("Present for"),
            "{}: a presenter belongs in src/observe/, not in the protocol's module",
            row.module
        );
        let expected = builtins.contains(row.module);
        assert_eq!(row.observe, expected, "{}: the Observe column", row.module);
    }
}

#[test]
fn fuzz_column_matches_the_fuzz_targets() {
    let rows = MODULES;
    let targets = fuzz_targets();
    assert!(
        targets.len() > 100,
        "the parser found the fuzz targets: {}",
        targets.len()
    );
    let mut fuzzed = BTreeSet::new();
    let mut unowned = Vec::new();
    for target in &targets {
        match owner(target, rows.iter().map(|r| r.module)) {
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
    for row in rows {
        assert_eq!(
            row.fuzz,
            fuzzed.contains(row.module),
            "{}: the Fuzz column",
            row.module
        );
    }
}

/// The copy fixture uses literal #[path] declarations inside its protocols!
/// macro. Follow their children just as for the stdlib declarations.
fn copied_sources(sources: &Sources, fixture: &str, base: &Path) -> BTreeSet<PathBuf> {
    let tokens = rust_docs::tokens(fixture);
    let mut copied = BTreeSet::new();
    for (at, words) in tokens.windows(6).enumerate() {
        if words[..4] != ["#", "[", "path", "="] {
            continue;
        }
        let path = path_attribute(words).expect("copy module path");
        let decl = &tokens[at + 6..];
        let decl = decl.strip_prefix(&["pub"]).unwrap_or(decl);
        assert!(
            decl.starts_with(&["mod"]) && decl.get(2) == Some(&";"),
            "copy path must declare a module"
        );
        let file = normalize(&base.join(path));
        if sources.contains_key(&file) {
            copied.insert(file.clone());
            for module in discover(sources, &file, true, &mut BTreeSet::new()).into_values() {
                copied.extend(module.files);
            }
        } else {
            // Other copy units (observe and generated code) have their own
            // source roots; only stdlib files belong to this inventory.
            assert!(
                !path.contains("/stdlib/"),
                "missing copy source: {}",
                file.display()
            );
        }
    }
    copied
}

fn assert_implementation_coverage(
    sources: &Sources,
    covered: &BTreeSet<PathBuf>,
    root: &Path,
    copy: bool,
) {
    for file in sources.keys() {
        let name = file.file_name().unwrap();
        if file == root || name == "tests.rs" || (copy && name == "mod.rs") {
            continue;
        }
        assert!(
            covered.contains(file),
            "{}: missing from {}",
            file.display(),
            if copy {
                "the copy fixture"
            } else {
                "module declarations"
            }
        );
    }
}

#[test]
fn copy_column_matches_the_copy_and_own_fixture() {
    let dir = Path::new(ROOT).join("src/stdlib");
    let sources = sources_on_disk(&dir);
    let copied = copied_sources(
        &sources,
        COPY_MODULES,
        &Path::new(ROOT).join("tests/copy_and_own"),
    );
    let modules = modules_on_disk();
    for row in MODULES {
        let files = &modules[row.module];
        assert!(
            !files.is_empty(),
            "{}: no implementation files found",
            row.module
        );
        assert_eq!(
            row.copy,
            files.iter().any(|p| copied.contains(p))
                && files
                    .iter()
                    .filter(|p| p.file_name().unwrap() != "mod.rs")
                    .all(|p| copied.contains(p)),
            "{}: the Copy column",
            row.module
        );
    }
}

#[test]
fn every_implementation_file_is_copied() {
    let dir = Path::new(ROOT).join("src/stdlib");
    let sources = sources_on_disk(&dir);
    let copied = copied_sources(
        &sources,
        COPY_MODULES,
        &Path::new(ROOT).join("tests/copy_and_own"),
    );
    assert_implementation_coverage(&sources, &copied, &dir.join("mod.rs"), true);
}

#[test]
fn every_implementation_file_is_declared() {
    let dir = Path::new(ROOT).join("src/stdlib");
    let sources = sources_on_disk(&dir);
    let declared = declared_modules(&sources, &dir.join("mod.rs"))
        .into_values()
        .flat_map(|module| module.files)
        .collect();
    assert_implementation_coverage(&sources, &declared, &dir.join("mod.rs"), false);
}

fn source_fixture() -> Sources {
    [
        (
            "src/stdlib/mod.rs",
            r#"
            pub mod ordinary;
            fictionet::cfg_std! { #[path = "protocols/moved.rs"] pub mod moved; }
            #[doc(hidden)] #[path = "component/mod.rs"] pub mod component;
            #[path = "shared/helper.rs"] mod helper;
            pub use helper::Helper;
        "#,
        ),
        ("src/stdlib/ordinary.rs", "pub struct Packet;"),
        ("src/stdlib/protocols/moved.rs", "pub struct Frame;"),
        (
            "src/stdlib/component/mod.rs",
            "mod implementation; pub use implementation::*;",
        ),
        (
            "src/stdlib/component/implementation.rs",
            "pub struct Messages; impl Decode for Messages {}",
        ),
        ("src/stdlib/shared/helper.rs", "pub struct Helper;"),
    ]
    .into_iter()
    .map(|(path, source)| (PathBuf::from(path), source.to_owned()))
    .collect()
}

#[test]
fn discovery_follows_declarations_and_private_reexported_children() {
    let sources = source_fixture();
    let modules = declared_modules(&sources, Path::new("src/stdlib/mod.rs"));
    assert_eq!(
        modules.keys().map(String::as_str).collect::<Vec<_>>(),
        ["component", "helper", "moved", "ordinary"]
    );
    assert_eq!(
        modules["moved"].files,
        BTreeSet::from([PathBuf::from("src/stdlib/protocols/moved.rs")])
    );
    assert!(modules["component"].hidden);
    assert!(
        modules["component"]
            .files
            .contains(Path::new("src/stdlib/component/implementation.rs"))
    );
    assert!(!modules["helper"].public);
    let component: String = modules["component"]
        .files
        .iter()
        .map(|file| sources[file].as_str())
        .collect();
    assert!(catalog_impl(&component, "Decode"));
    let copied = copied_sources(
        &sources,
        r#"
        macro_rules! protocols { () => {
            #[path = "../../src/stdlib/ordinary.rs"] pub mod ordinary;
            fictionet::cfg_std! { #[path = "../../src/stdlib/protocols/moved.rs"] pub mod moved; }
            #[path = "../../src/stdlib/component/mod.rs"] pub mod component;
            #[path = "../../src/stdlib/shared/helper.rs"] mod helper;
        }; }
        protocols!();
    "#,
        Path::new("tests/copy_and_own"),
    );
    assert_implementation_coverage(&sources, &copied, Path::new("src/stdlib/mod.rs"), true);
}

#[test]
fn path_loaded_files_resolve_plain_children_as_siblings() {
    let mut sources = source_fixture();
    sources.insert(
        PathBuf::from("src/stdlib/protocols/moved.rs"),
        "pub mod child;".into(),
    );
    sources.insert(
        PathBuf::from("src/stdlib/protocols/child.rs"),
        "pub struct Child;".into(),
    );
    let expected = BTreeSet::from([
        PathBuf::from("src/stdlib/protocols/moved.rs"),
        PathBuf::from("src/stdlib/protocols/child.rs"),
    ]);
    let modules = declared_modules(&sources, Path::new("src/stdlib/mod.rs"));
    assert_eq!(modules["moved"].files, expected);
    assert_eq!(
        copied_sources(
            &sources,
            r#"#[path = "../../src/stdlib/protocols/moved.rs"] pub mod moved;"#,
            Path::new("tests/copy_and_own"),
        ),
        expected
    );
}

#[test]
#[should_panic(expected = "missing or ambiguous module child")]
fn path_loaded_files_reject_plain_children_under_the_file_stem() {
    let mut sources = source_fixture();
    sources.insert(
        PathBuf::from("src/stdlib/protocols/moved.rs"),
        "pub mod child;".into(),
    );
    sources.insert(
        PathBuf::from("src/stdlib/protocols/moved/child.rs"),
        "pub struct Child;".into(),
    );
    declared_modules(&sources, Path::new("src/stdlib/mod.rs"));
}

#[test]
fn path_loaded_files_resolve_inline_paths_from_the_parent_directory() {
    let mut sources = source_fixture();
    sources.insert(
        PathBuf::from("src/stdlib/protocols/moved.rs"),
        "mod inner { #[path = \"child.rs\"] mod child; }".into(),
    );
    sources.insert(
        PathBuf::from("src/stdlib/protocols/inner/child.rs"),
        "pub struct Child;".into(),
    );
    let expected = BTreeSet::from([
        PathBuf::from("src/stdlib/protocols/moved.rs"),
        PathBuf::from("src/stdlib/protocols/inner/child.rs"),
    ]);
    let modules = declared_modules(&sources, Path::new("src/stdlib/mod.rs"));
    assert_eq!(modules["moved"].files, expected);
    assert_eq!(
        copied_sources(
            &sources,
            r#"#[path = "../../src/stdlib/protocols/moved.rs"] pub mod moved;"#,
            Path::new("tests/copy_and_own"),
        ),
        expected
    );
}

#[test]
#[should_panic(expected = "missing or ambiguous module moved")]
fn a_missing_declared_file_fails_discovery() {
    let mut sources = source_fixture();
    sources
        .remove(Path::new("src/stdlib/protocols/moved.rs"))
        .unwrap();
    declared_modules(&sources, Path::new("src/stdlib/mod.rs"));
}

#[test]
#[should_panic(expected = "missing or ambiguous module ordinary")]
fn ambiguous_module_paths_fail_discovery() {
    let mut sources = source_fixture();
    sources.insert(PathBuf::from("src/stdlib/ordinary/mod.rs"), String::new());
    declared_modules(&sources, Path::new("src/stdlib/mod.rs"));
}

#[test]
#[should_panic(expected = "cyclic module source")]
fn cyclic_module_paths_fail_discovery() {
    let mut sources = source_fixture();
    sources.insert(
        PathBuf::from("src/stdlib/ordinary.rs"),
        "#[path = \"ordinary.rs\"] mod cycle;".into(),
    );
    declared_modules(&sources, Path::new("src/stdlib/mod.rs"));
}

#[test]
#[should_panic(expected = "unsupported path attribute")]
fn conditional_paths_require_explicit_discovery_support() {
    let sources = Sources::from([(
        PathBuf::from("src/stdlib/mod.rs"),
        "#[cfg_attr(feature = \"std\", path = \"alternate.rs\")] pub mod ordinary;".into(),
    )]);
    declared_modules(&sources, Path::new("src/stdlib/mod.rs"));
}

#[test]
fn inline_children_resolve_paths_from_their_module_directory() {
    let mut sources = source_fixture();
    sources.insert(
        PathBuf::from("src/stdlib/ordinary.rs"),
        "mod inner { #[path = \"child.rs\"] mod child; }".into(),
    );
    sources.insert(
        PathBuf::from("src/stdlib/ordinary/inner/child.rs"),
        "pub struct Child;".into(),
    );
    let modules = declared_modules(&sources, Path::new("src/stdlib/mod.rs"));
    assert!(
        modules["ordinary"]
            .files
            .contains(Path::new("src/stdlib/ordinary/inner/child.rs"))
    );
}

#[test]
#[should_panic(expected = "orphan.rs: missing from module declarations")]
fn undeclared_implementation_files_fail_coverage() {
    let mut sources = source_fixture();
    sources.insert(
        PathBuf::from("src/stdlib/protocols/orphan.rs"),
        String::new(),
    );
    let declared = declared_modules(&sources, Path::new("src/stdlib/mod.rs"))
        .into_values()
        .flat_map(|module| module.files)
        .collect();
    assert_implementation_coverage(&sources, &declared, Path::new("src/stdlib/mod.rs"), false);
}

#[test]
#[should_panic(expected = "implementation.rs: missing from the copy fixture")]
fn uncopied_private_implementations_fail_coverage() {
    let sources = source_fixture();
    let mut copied: BTreeSet<_> = sources.keys().cloned().collect();
    assert!(copied.remove(Path::new("src/stdlib/component/implementation.rs")));
    assert_implementation_coverage(&sources, &copied, Path::new("src/stdlib/mod.rs"), true);
}

fn assert_module_names(listed: &[&str], declared: impl Iterator<Item = String>) {
    assert_eq!(
        listed,
        declared.collect::<Vec<_>>(),
        "the catalog's modules and the declarations in src/stdlib/mod.rs"
    );
}

#[test]
#[should_panic(expected = "the catalog's modules and the declarations")]
fn an_uncataloged_declaration_fails() {
    let modules = declared_modules(&source_fixture(), Path::new("src/stdlib/mod.rs"));
    assert_module_names(
        &["component", "ordinary"],
        modules
            .into_iter()
            .filter(|(_, module)| module.public)
            .map(|(name, _)| name),
    );
}

#[test]
#[should_panic(expected = "the catalog's modules and the declarations")]
fn a_cataloged_module_without_a_declaration_fails() {
    let modules = declared_modules(&source_fixture(), Path::new("src/stdlib/mod.rs"));
    assert_module_names(
        &["component", "extra", "moved", "ordinary"],
        modules
            .into_iter()
            .filter(|(_, module)| module.public)
            .map(|(name, _)| name),
    );
}

#[test]
fn exported_decoder_compositions_count() {
    for source in [
        "pub struct A; pub type T = Map<A, F>;",
        "pub type T = codec::Assemble<A, F>;",
        "pub type T<A = Map<B, F>> = codec::Assemble<A, F>;",
        "pub type T = fictionet::stdlib::codec::Frames<A>;",
        "pub fn messages() -> Lines { todo!() }",
        "pub fn messages() -> codec::Map<A, F> { todo!() }",
        "pub fn messages() -> impl Decode<Item = A> { todo!() }",
        "pub fn messages() -> impl codec::Decode<Item = A> { todo!() }",
        "pub fn messages<F: Fn() -> Lines>(f: F) -> Lines { f() }",
        "fictionet::cfg_std! { pub type T = Map<A, F>; }",
    ] {
        assert!(catalog_impl(source, "Decode"), "{source}");
    }
    for source in [
        "type T = Map<A, F>;",
        "pub(crate) type T = Map<A, F>;",
        "pub struct Map; pub type T = Map<A, F>;",
        "struct Map; pub type T = Map<A, F>;",
        "pub\nstruct Map; pub type T = Map<A, F>;",
        "pub type T = unrelated::Map<A, F>;",
        "pub type T = Vec<A>;",
        "pub type T<A = Map<B, F>> = Vec<A>;",
        "fn messages() -> Lines { todo!() }",
        "pub fn count(f: fn() -> Lines) -> usize { 0 }",
        "pub fn count<F: Fn() -> Lines>(f: F) -> usize { 0 }",
        "impl Service for S { fn decoder(&self) -> Lines { todo!() } }",
        "impl S { pub fn decoder(&self) -> Lines { todo!() } }",
        "#[cfg(test)] pub fn decoder() -> Lines { todo!() }",
        "#[cfg(test)] fictionet::cfg_std! { pub type T = Map<A, F>; }",
        "const DOC: &str = \"pub type T = Map<A, F>;\";",
        "const DOC: &str = \"impl Decode for Fake {}\";",
        "/* impl Decode for Fake {} */",
        "/* pub type T = Map<A, F>; */",
    ] {
        assert!(!catalog_impl(source, "Decode"), "{source}");
    }
}

fn assert_decode_column(module: &str, listed: bool, code: &str) {
    assert_eq!(
        listed,
        catalog_impl(code, "Decode") || catalog_impl(code, "Prefixed"),
        "{module}: the Decode column"
    );
}

#[test]
#[should_panic(expected = "composed: the Decode column")]
fn an_unlisted_composed_decoder_fails() {
    assert_decode_column("composed", false, "pub type T = Assemble<A, F>;");
}

#[test]
fn exported_compositions_implement_decode() {
    use fictionet::stdlib::{codec::Decode, cotp, onc_rpc};
    fn is_decode<T: Decode>() {}
    is_decode::<cotp::Tpdus>();
    is_decode::<cotp::Messages>();
    is_decode::<onc_rpc::Records>();
}

#[test]
fn descriptions_are_one_line_each() {
    for row in MODULES {
        assert!(!row.what.is_empty(), "{} has no description", row.module);
        assert!(
            row.what.ends_with('.'),
            "{}: the description is a sentence",
            row.module
        );
        assert!(
            !row.what.contains(['\n', '\r', '|']),
            "{}: the description is one table cell",
            row.module
        );
        assert!(
            row.what.len() <= 160,
            "{}: the description fits one line ({} chars)",
            row.module,
            row.what.len()
        );
    }
}
