//! Writes one module per random schema into OUT_DIR, and `layouts.rs`,
//! which declares them.
use std::{fmt::Write, path::PathBuf};

#[path = "../support/schemas.rs"]
mod schemas;

fn main() {
    // The output depends only on this script, its schemas module and the
    // generator, and a change to any of them rebuilds the script.
    println!("cargo::rerun-if-changed=build.rs");
    let out = PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    let mut modules = String::new();
    for seed in 0..schemas::SEEDS {
        let source = fictionet_codegen::emit(&schemas::random_schema(seed), &[]).unwrap();
        let path = out.join(format!("seed_{seed}.rs"));
        std::fs::write(&path, source).unwrap();
        writeln!(
            modules,
            "#[path = {:?}]\nmod seed_{seed};",
            path.display().to_string()
        )
        .unwrap();
    }
    std::fs::write(out.join("layouts.rs"), modules).unwrap();
}
