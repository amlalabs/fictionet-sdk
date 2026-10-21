//! Regenerates the code generator outputs and the web fixture report.
use crate::process::Result;
use fictionet_codegen::{FrontEnd, Input, IrFrontEnd, Limits, emit_fuzz, generate, validate};
use std::fs;

pub fn run() -> Result {
    let root = crate::root();
    for name in [
        "primitives",
        "groups",
        "recursive",
        "xdr",
        "budgets",
        "edges",
        "one_field",
        "short_names",
        "long_names",
        "float_nulls",
        "blocks",
        "sbe_sample",
    ] {
        let (format, extension) = if name == "sbe_sample" {
            ("sbe", "xml")
        } else {
            ("ir", "json")
        };
        let limits = if name == "budgets" {
            Limits {
                max_message: 128,
                max_collection: 8,
                max_depth: 4,
                max_allocation: 32,
                max_nodes: 8,
            }
        } else {
            Limits::default()
        };
        let input = Input {
            name: format!("{name}.{extension}"),
            bytes: fs::read(root.join(format!("codegen/tests/schemas/{name}.{extension}")))?,
        };
        fs::write(
            root.join(format!("codegen/tests/golden/{name}.rs")),
            generate(format, std::slice::from_ref(&input), limits)?.source,
        )?;
        if name == "recursive" {
            let checked = validate(IrFrontEnd.parse(&[input], limits)?, limits)?;
            fs::write(
                root.join("fuzz/fuzz_targets/codegen_ir.rs"),
                emit_fuzz(
                    "ir",
                    &checked,
                    "fictionet_codegen_golden::recursive",
                    &["recursive.json".into()],
                )?,
            )?;
        }
    }
    let path = root.join("src/stdlib/protocols/cme_mdp3/mod.rs");
    let module = fs::read_to_string(&path)?;
    let input = Input {
        name: "templates_FixBinary.xml".into(),
        bytes: fs::read(root.join("data/cme/templates_FixBinary.xml"))?,
    };
    let generated = generate("sbe", &[input], Limits::default())?.source;
    let header = |source: &str| {
        source
            .split_inclusive('\n')
            .take_while(|line| line.starts_with("//"))
            .map(str::len)
            .sum::<usize>()
    };
    let tail = &module[module
        .find("\n// Hand-written below this line")
        .ok_or("missing framing marker")?..];
    fs::write(
        path,
        format!(
            "{}{}{tail}",
            &module[..header(&module)],
            &generated[header(&generated)..]
        ),
    )?;
    fs::write(
        root.join("tests/web_fixture/golden.txt"),
        fictionet_test_support::web_fixture::recorded_report(),
    )?;
    Ok(())
}
