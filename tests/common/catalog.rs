//! Rendering for the canonical stdlib catalog and the fuzz target inventory.
//! Source discovery stays separate.

#[path = "../../catalog/stdlib.rs"]
pub mod manifest;

use std::fmt::Write;

use manifest::{FuzzOwner, FuzzTarget, Module};

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
