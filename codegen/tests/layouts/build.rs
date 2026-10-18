//! Writes `layouts.rs` into OUT_DIR: one inline module per random schema.
use std::{fmt::Write, path::PathBuf};

mod schemas;

fn main() {
    // The output depends only on this script, its schemas module and the
    // generator, and a change to any of them rebuilds the script.
    println!("cargo::rerun-if-changed=build.rs");
    let out = PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    let mut modules = String::new();
    for seed in 0..schemas::SEEDS {
        let source = fictionet_codegen::emit("ir", &schemas::random_schema(seed), &[]).unwrap();
        writeln!(modules, "mod seed_{seed} {{\n{source}}}").unwrap();
    }
    std::fs::write(out.join("layouts.rs"), modules).unwrap();
}
