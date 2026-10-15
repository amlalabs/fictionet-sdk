//! Rendering for the canonical stdlib catalog. Source discovery stays separate.

#[path = "../../catalog/stdlib.rs"]
pub mod manifest;

use std::fmt::Write;

use manifest::Module;

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

pub fn assert_documentation(actual: &str, expected: &str) {
    assert_eq!(
        actual, expected,
        "src/stdlib/catalog.md differs from the catalog; set BLESS_STDLIB_CATALOG=1 to update"
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
