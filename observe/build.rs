//! Embeds downloaded browser libraries when the page feature is enabled.

use std::fmt::Write;
use std::path::{Path, PathBuf};

fn main() {
    println!("cargo::rerun-if-changed=downloads/vendor");
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let vendor = manifest.join("downloads/vendor");
    let mut files = Vec::new();
    if cfg!(feature = "page") && vendor.is_dir() {
        walk(&vendor, &mut files);
    }
    files.sort();
    let mut table = String::from("static VENDOR: &[(&str, &[u8])] = &[\n");
    for path in files {
        let name = path
            .strip_prefix(&vendor)
            .expect("walked from it")
            .to_str()
            .expect("vendor paths are UTF-8");
        writeln!(table, "    ({name:?}, include_bytes!({path:?})),").expect("a String");
    }
    table.push_str("];\n");
    let out = PathBuf::from(std::env::var_os("OUT_DIR").expect("cargo sets it"));
    std::fs::write(out.join("vendor.rs"), table).expect("writing vendor.rs");
}

fn walk(dir: &Path, files: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("reading vendor directory") {
        let entry = entry.expect("reading vendor entry");
        let kind = entry.file_type().expect("reading vendor type");
        if kind.is_dir() {
            walk(&entry.path(), files);
        } else if kind.is_file() {
            files.push(entry.path());
        }
    }
}
