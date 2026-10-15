//! Rendering for the canonical stdlib catalog, the module declarations and the
//! fuzz target inventory. Source discovery stays separate.

#[path = "../../catalog/stdlib.rs"]
pub mod manifest;

use std::collections::BTreeMap;
use std::fmt::Write;

use manifest::{CopyPart, FuzzOwner, FuzzTarget, Gate, Module};

/// The line before the generated public modules in `src/stdlib/mod.rs`.
pub const DECLARATIONS_BEGIN: &str = "// Generated from catalog/stdlib.rs. Update with BLESS_STDLIB_CATALOG=1 cargo nextest run --locked --test stdlib_catalog.\n";
/// The line after the generated public modules in `src/stdlib/mod.rs`.
pub const DECLARATIONS_END: &str = "// End of the generated module declarations.\n";
/// The line before the generated modules in `tests/copy_and_own/modules.rs`.
pub const COPY_BEGIN: &str = "        // Generated from catalog/stdlib.rs. Update with BLESS_STDLIB_CATALOG=1 cargo nextest run --locked --test stdlib_catalog.\n";
/// The line after the generated modules in `tests/copy_and_own/modules.rs`.
pub const COPY_END: &str = "        // End of the generated copy declarations.\n";

/// The line before the generated `[[bin]]` records in `fuzz/Cargo.toml`.
pub const FUZZ_BINS_BEGIN: &str = "# Generated from catalog/stdlib.rs. Update with BLESS_STDLIB_CATALOG=1 cargo nextest run --locked --test stdlib_catalog.\n";
/// The line after the generated `[[bin]]` records in `fuzz/Cargo.toml`.
pub const FUZZ_BINS_END: &str = "# End of the generated fuzz targets.\n";
/// The line before the generated list in `fuzz/README.md`.
pub const UNOWNED_FUZZ_BEGIN: &str = "<!-- Generated from catalog/stdlib.rs. Update with BLESS_STDLIB_CATALOG=1 cargo nextest run --locked --test stdlib_catalog. -->\n";
/// The line after the generated list in `fuzz/README.md`.
pub const UNOWNED_FUZZ_END: &str = "<!-- End of the generated list. -->\n";

pub fn render(modules: &[Module]) -> String {
    let mut out = String::from(
        "<!-- Generated from catalog/stdlib.rs. Update with BLESS_STDLIB_CATALOG=1 cargo nextest run --locked --test stdlib_catalog. -->\n\n\
         | Module | What it is | Wire | Decode | State | Service | Observe | Fuzz | Copy |\n\
         |---|---|---|---|---|---|---|---|---|\n",
    );
    for module in modules {
        let name = if module.linked {
            format!("[`{}`]", module.module)
        } else {
            format!("`{}`", module.module)
        };
        writeln!(
            out,
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} |",
            name,
            module.what,
            yes(module.wire),
            yes(module.decode),
            names(module.state),
            names(module.service),
            if module.observe { "built in" } else { "" },
            yes(module.fuzz),
            yes(module.copy),
        )
        .unwrap();
    }
    out
}

fn yes(present: bool) -> &'static str {
    if present { "yes" } else { "" }
}

fn names(names: &[&str]) -> String {
    names
        .iter()
        .map(|name| format!("`{name}`"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn gate_macro(gate: Gate) -> Option<&'static str> {
    match gate {
        Gate::Always => None,
        Gate::Std => Some("cfg_std"),
        Gate::Observe => Some("cfg_observe"),
    }
}

/// The public module declarations of `src/stdlib/mod.rs`, in record order. A
/// gated declaration sits on one line inside its macro.
pub fn render_declarations(modules: &[Module]) -> String {
    let mut out = String::new();
    for module in modules {
        let mut lines = Vec::new();
        if let Some(docs) = module.docs {
            lines.push(format!("#[doc = include_str!(\"{docs}\")]"));
        }
        if !module.linked {
            lines.push("#[doc(hidden)]".to_owned());
        }
        // Rust finds `<module>.rs` and `<module>/mod.rs` without a path.
        let name = module.module;
        if let Some(file) = module
            .file
            .filter(|&file| file != format!("{name}.rs") && file != format!("{name}/mod.rs"))
        {
            lines.push(format!("#[path = \"{file}\"]"));
        }
        lines.push(format!("pub mod {name};"));
        match gate_macro(module.gate) {
            None => writeln!(out, "{}", lines.join("\n")),
            Some(gate) => writeln!(out, "fictionet::{gate}! {{ {} }}", lines.join(" ")),
        }
        .unwrap();
    }
    out
}

/// The module declarations of `tests/copy_and_own/modules.rs`, in name order:
/// the entry file of each copied module and every copy part. A module with
/// `copy_parts` is declared through its parts alone.
pub fn render_copy_declarations(modules: &[Module], parts: &[CopyPart]) -> String {
    let entries = modules
        .iter()
        .filter(|module| module.copy && !module.copy_parts)
        .map(|module| {
            let file = match module.file {
                Some(file) => format!("src/stdlib/{file}"),
                None => format!("src/stdlib/{}.rs", module.module),
            };
            (module.module, (file, true, module.gate))
        })
        .chain(
            parts
                .iter()
                .map(|part| (part.name, (part.file.to_owned(), part.public, part.gate))),
        );
    let mut sorted = BTreeMap::new();
    for (name, entry) in entries {
        assert!(
            sorted.insert(name, entry).is_none(),
            "the copy fixture declares {name} more than once"
        );
    }
    let mut out = String::new();
    for (name, (file, public, gate)) in sorted {
        let visibility = if public { "pub " } else { "" };
        let declaration =
            format!("        #[path = \"../../{file}\"]\n        {visibility}mod {name};\n");
        match gate_macro(gate) {
            None => out.push_str(&declaration),
            Some(gate) => writeln!(
                out,
                "        fictionet::{gate}! {{\n{declaration}        }}"
            )
            .unwrap(),
        }
    }
    out
}

/// The `[[bin]]` record of each target, in record order, each after a blank line.
pub fn render_fuzz_bins(targets: &[FuzzTarget]) -> String {
    let mut out = String::new();
    for target in targets {
        write!(
            out,
            "\n[[bin]]\nname = \"{0}\"\npath = \"fuzz_targets/{0}.rs\"\ntest = false\ndoc = false\nbench = false\n",
            target.name
        )
        .unwrap();
    }
    out.push('\n');
    out
}

/// The README list of targets without a stdlib module, in name order.
pub fn render_unowned_fuzz_targets(targets: &[FuzzTarget]) -> String {
    let mut unowned: Vec<(&str, &str)> = targets
        .iter()
        .filter_map(|target| match target.owner {
            FuzzOwner::Module(_) => None,
            FuzzOwner::Unowned(what) => Some((target.name, what)),
        })
        .collect();
    unowned.sort();
    let mut out = String::from("\n");
    for (name, what) in unowned {
        writeln!(out, "- [`{name}`](fuzz_targets/{name}.rs) {what}").unwrap();
    }
    out.push('\n');
    out
}

/// `document` with the text between the `begin` and `end` lines replaced by
/// `generated`. Each marker must be a whole line that appears once, in order.
pub fn splice(file: &str, document: &str, begin: &str, end: &str, generated: &str) -> String {
    let start = marker(file, document, begin) + begin.len();
    let stop = marker(file, document, end);
    assert!(start <= stop, "{file}: {end:?} comes before {begin:?}");
    format!("{}{generated}{}", &document[..start], &document[stop..])
}

fn marker(file: &str, document: &str, line: &str) -> usize {
    let found: Vec<usize> = document
        .match_indices(line)
        .map(|(at, _)| at)
        .filter(|&at| at == 0 || document.as_bytes()[at - 1] == b'\n')
        .collect();
    match found[..] {
        [at] => at,
        [] => panic!("{file} has no line {line:?}"),
        _ => panic!("{file} has the line {line:?} more than once"),
    }
}

pub fn assert_documentation(actual: &str, expected: &str) {
    assert_generated("src/stdlib/catalog.md", actual, expected);
}

pub fn assert_generated(file: &str, actual: &str, expected: &str) {
    assert_eq!(
        actual, expected,
        "{file} differs from the catalog; set BLESS_STDLIB_CATALOG=1 to update"
    );
}

#[test]
fn rendering_keeps_columns_links_names_and_record_order() {
    let modules = [
        Module {
            module: "visible",
            linked: true,
            what: "A protocol with `Wire` values.",
            wire: true,
            decode: false,
            state: &["Client", "Server"],
            service: &["Responder", "Other"],
            observe: true,
            fuzz: false,
            copy: true,
            copy_parts: false,
            file: None,
            docs: None,
            gate: Gate::Always,
        },
        Module {
            module: "hidden",
            linked: false,
            what: "A hidden decoder.",
            wire: false,
            decode: true,
            state: &[],
            service: &[],
            observe: false,
            fuzz: true,
            copy: false,
            copy_parts: false,
            file: None,
            docs: None,
            gate: Gate::Always,
        },
    ];
    let expected = "<!-- Generated from catalog/stdlib.rs. Update with BLESS_STDLIB_CATALOG=1 cargo nextest run --locked --test stdlib_catalog. -->\n\n\
        | Module | What it is | Wire | Decode | State | Service | Observe | Fuzz | Copy |\n\
        |---|---|---|---|---|---|---|---|---|\n\
        | [`visible`] | A protocol with `Wire` values. | yes |  | `Client`, `Server` | `Responder`, `Other` | built in |  | yes |\n\
        | `hidden` | A hidden decoder. |  | yes |  |  |  | yes |  |\n";
    assert_eq!(render(&modules), expected);
    assert_eq!(render(&modules), render(&modules));
}

#[test]
#[should_panic(expected = "src/stdlib/catalog.md differs from the catalog")]
fn changed_metadata_rejects_stale_documentation() {
    let actual = render(manifest::MODULES);
    let mut changed = manifest::MODULES.to_vec();
    changed[0].what = "A changed description.";
    assert_documentation(&actual, &render(&changed));
}

#[test]
#[should_panic(expected = "src/stdlib/catalog.md differs from the catalog")]
fn edited_documentation_fails_the_drift_check() {
    let expected = render(manifest::MODULES);
    let actual = format!("{expected}\nAn ungenerated addition.\n");
    assert_documentation(&actual, &expected);
}

#[test]
fn fuzz_bins_keep_names_paths_flags_and_record_order() {
    let targets = [
        FuzzTarget {
            name: "zeta",
            owner: FuzzOwner::Module("zeta"),
        },
        FuzzTarget {
            name: "alpha_events",
            owner: FuzzOwner::Unowned("checks events."),
        },
    ];
    let expected = "\n[[bin]]\nname = \"zeta\"\npath = \"fuzz_targets/zeta.rs\"\ntest = false\ndoc = false\nbench = false\n\
        \n[[bin]]\nname = \"alpha_events\"\npath = \"fuzz_targets/alpha_events.rs\"\ntest = false\ndoc = false\nbench = false\n\n";
    assert_eq!(render_fuzz_bins(&targets), expected);
    assert_eq!(render_fuzz_bins(&targets), render_fuzz_bins(&targets));
}

#[test]
fn the_unowned_list_has_only_unowned_targets_in_name_order() {
    let targets = [
        FuzzTarget {
            name: "stack",
            owner: FuzzOwner::Unowned("feeds packets to endpoints."),
        },
        FuzzTarget {
            name: "modbus",
            owner: FuzzOwner::Module("modbus"),
        },
        FuzzTarget {
            name: "packets",
            owner: FuzzOwner::Unowned("checks packet sorting."),
        },
    ];
    let expected = "\n- [`packets`](fuzz_targets/packets.rs) checks packet sorting.\n\
        - [`stack`](fuzz_targets/stack.rs) feeds packets to endpoints.\n\n";
    assert_eq!(render_unowned_fuzz_targets(&targets), expected);
    assert_eq!(
        render_unowned_fuzz_targets(&targets),
        render_unowned_fuzz_targets(&targets)
    );
}

#[test]
fn splicing_replaces_only_the_text_between_the_markers() {
    let document = "head\nBEGIN\nold\nEND\ntail\n";
    assert_eq!(
        splice("doc", document, "BEGIN\n", "END\n", "new\n"),
        "head\nBEGIN\nnew\nEND\ntail\n"
    );
}

#[test]
#[should_panic(expected = "doc has no line \"END\\n\"")]
fn splicing_requires_the_end_marker() {
    splice("doc", "BEGIN\nold\n", "BEGIN\n", "END\n", "new\n");
}

#[test]
#[should_panic(expected = "doc has the line \"BEGIN\\n\" more than once")]
fn splicing_rejects_a_repeated_marker() {
    splice("doc", "BEGIN\nBEGIN\nEND\n", "BEGIN\n", "END\n", "new\n");
}

#[test]
#[should_panic(expected = "doc has no line \"BEGIN\\n\"")]
fn splicing_ignores_markers_inside_a_line() {
    splice("doc", "# BEGIN\nEND\n", "BEGIN\n", "END\n", "new\n");
}

#[test]
#[should_panic(expected = "doc: \"END\\n\" comes before \"BEGIN\\n\"")]
fn splicing_rejects_markers_out_of_order() {
    splice("doc", "END\nBEGIN\n", "BEGIN\n", "END\n", "new\n");
}

#[test]
#[should_panic(expected = "fuzz/Cargo.toml differs from the catalog")]
fn changed_fuzz_records_reject_stale_bins() {
    let actual = render_fuzz_bins(manifest::FUZZ_TARGETS);
    let mut changed = manifest::FUZZ_TARGETS.to_vec();
    changed[0].name = "renamed";
    assert_generated("fuzz/Cargo.toml", &actual, &render_fuzz_bins(&changed));
}

#[test]
#[should_panic(expected = "fuzz/README.md differs from the catalog")]
fn changed_fuzz_owners_reject_a_stale_readme_list() {
    let actual = render_unowned_fuzz_targets(manifest::FUZZ_TARGETS);
    let mut changed = manifest::FUZZ_TARGETS.to_vec();
    let owned = changed
        .iter()
        .position(|target| matches!(target.owner, FuzzOwner::Module(_)))
        .unwrap();
    changed[owned].owner = FuzzOwner::Unowned("checks something else.");
    assert_generated(
        "fuzz/README.md",
        &actual,
        &render_unowned_fuzz_targets(&changed),
    );
}

fn record(module: &'static str) -> Module {
    Module {
        module,
        linked: true,
        what: "A module.",
        wire: false,
        decode: false,
        state: &[],
        service: &[],
        observe: false,
        fuzz: false,
        copy: true,
        copy_parts: false,
        file: None,
        docs: None,
        gate: Gate::Always,
    }
}

#[test]
fn declarations_keep_docs_hidden_paths_gates_and_record_order() {
    let modules = [
        Module {
            docs: Some("zeta/docs.md"),
            file: Some("zeta/mod.rs"),
            ..record("zeta")
        },
        Module {
            linked: false,
            file: Some("hidden.rs"),
            ..record("hidden")
        },
        Module {
            file: Some("protocols/moved.rs"),
            ..record("moved")
        },
        Module {
            gate: Gate::Std,
            ..record("served")
        },
        Module {
            gate: Gate::Observe,
            linked: false,
            file: Some("protocols/shown.rs"),
            ..record("shown")
        },
    ];
    let expected = "#[doc = include_str!(\"zeta/docs.md\")]\npub mod zeta;\n\
        #[doc(hidden)]\npub mod hidden;\n\
        #[path = \"protocols/moved.rs\"]\npub mod moved;\n\
        fictionet::cfg_std! { pub mod served; }\n\
        fictionet::cfg_observe! { #[doc(hidden)] #[path = \"protocols/shown.rs\"] pub mod shown; }\n";
    assert_eq!(render_declarations(&modules), expected);
    assert_eq!(render_declarations(&modules), render_declarations(&modules));
}

#[test]
fn copy_declarations_list_copied_entries_and_parts_in_name_order() {
    let modules = [
        Module {
            gate: Gate::Std,
            ..record("web")
        },
        Module {
            file: Some("tree/mod.rs"),
            ..record("tree")
        },
        Module {
            copy: false,
            ..record("uncopied")
        },
        Module {
            copy_parts: true,
            ..record("codec")
        },
    ];
    let parts = [
        CopyPart {
            name: "private",
            file: "src/stdlib/private.rs",
            public: false,
            gate: Gate::Always,
        },
        CopyPart {
            name: "helper",
            file: "src/stdlib/codec/helper.rs",
            public: true,
            gate: Gate::Always,
        },
        CopyPart {
            name: "observed",
            file: "src/observe/observed.rs",
            public: true,
            gate: Gate::Observe,
        },
    ];
    let expected = r#"        #[path = "../../src/stdlib/codec/helper.rs"]
        pub mod helper;
        fictionet::cfg_observe! {
        #[path = "../../src/observe/observed.rs"]
        pub mod observed;
        }
        #[path = "../../src/stdlib/private.rs"]
        mod private;
        #[path = "../../src/stdlib/tree/mod.rs"]
        pub mod tree;
        fictionet::cfg_std! {
        #[path = "../../src/stdlib/web.rs"]
        pub mod web;
        }
"#;
    assert_eq!(render_copy_declarations(&modules, &parts), expected);
    assert_eq!(
        render_copy_declarations(&modules, &parts),
        render_copy_declarations(&modules, &parts)
    );
}

#[test]
#[should_panic(expected = "the copy fixture declares shared more than once")]
fn copy_declarations_reject_a_part_named_like_a_copied_module() {
    let part = CopyPart {
        name: "shared",
        file: "src/stdlib/shared/helper.rs",
        public: true,
        gate: Gate::Always,
    };
    render_copy_declarations(&[record("shared")], &[part]);
}

#[test]
#[should_panic(expected = "src/stdlib/mod.rs differs from the catalog")]
fn a_removed_module_record_rejects_stale_declarations() {
    let actual = render_declarations(manifest::MODULES);
    let mut changed = manifest::MODULES.to_vec();
    changed.remove(0);
    assert_generated("src/stdlib/mod.rs", &actual, &render_declarations(&changed));
}

#[test]
#[should_panic(expected = "src/stdlib/mod.rs differs from the catalog")]
fn a_changed_gate_rejects_stale_declarations() {
    let actual = render_declarations(manifest::MODULES);
    let mut changed = manifest::MODULES.to_vec();
    changed[0].gate = Gate::Std;
    assert_generated("src/stdlib/mod.rs", &actual, &render_declarations(&changed));
}

#[test]
#[should_panic(expected = "tests/copy_and_own/modules.rs differs from the catalog")]
fn an_uncopied_module_rejects_stale_copy_declarations() {
    let actual = render_copy_declarations(manifest::MODULES, manifest::COPY_PARTS);
    let mut changed = manifest::MODULES.to_vec();
    changed[0].copy = false;
    assert_generated(
        "tests/copy_and_own/modules.rs",
        &actual,
        &render_copy_declarations(&changed, manifest::COPY_PARTS),
    );
}

#[test]
#[should_panic(expected = "tests/copy_and_own/modules.rs differs from the catalog")]
fn an_added_copy_part_rejects_stale_copy_declarations() {
    let actual = render_copy_declarations(manifest::MODULES, manifest::COPY_PARTS);
    let mut changed = manifest::COPY_PARTS.to_vec();
    changed.push(CopyPart {
        name: "extra",
        file: "src/stdlib/extra.rs",
        public: true,
        gate: Gate::Always,
    });
    assert_generated(
        "tests/copy_and_own/modules.rs",
        &actual,
        &render_copy_declarations(manifest::MODULES, &changed),
    );
}
