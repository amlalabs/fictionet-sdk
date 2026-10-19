//! Embeds the files `cargo xtask demo assets` downloads to
//! `downloads/cloudimage` when they are there, so a workspace build without
//! them still compiles. noVNC's files become a table in `OUT_DIR/novnc.rs`,
//! empty without them.
//! Cloud Hypervisor's static binary becomes `OUT_DIR/ch_bin.rs`, `None`
//! without it, so the shared kit can run it from memory with nothing
//! written to disk.

use std::fmt::Write;
use std::path::{Path, PathBuf};

fn main() {
    println!("cargo::rerun-if-changed=downloads/cloudimage/novnc");
    // Read at run time: a build script compiled for another checkout that
    // shares the target directory would carry that checkout's path.
    let manifest = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").expect("cargo sets it"));
    let novnc = manifest.join("downloads/cloudimage/novnc");
    let mut files = Vec::new();
    if novnc.is_dir() {
        walk(&novnc, &mut files);
    }
    files.sort();
    let mut table = String::from(
        "/// noVNC's files, each by its path under `novnc/`.\n\
         pub static NOVNC: &[(&str, &[u8])] = &[\n",
    );
    for path in &files {
        let name = path
            .strip_prefix(&novnc)
            .expect("walked from it")
            .to_str()
            .expect("noVNC's file names are UTF-8");
        writeln!(table, "    ({name:?}, include_bytes!({path:?})),").expect("a String");
    }
    table.push_str("];\n");
    let out = PathBuf::from(std::env::var_os("OUT_DIR").expect("cargo sets it"));
    std::fs::write(out.join("novnc.rs"), table).expect("writing novnc.rs");

    // Cloud Hypervisor's static binary, embedded when it has been downloaded.
    println!("cargo::rerun-if-changed=downloads/cloudimage/cloud-hypervisor");
    let ch = manifest.join("downloads/cloudimage/cloud-hypervisor");
    let ch_rs = if ch.is_file() {
        format!(
            "/// Cloud Hypervisor's static binary (Apache-2.0 / BSD-3-Clause,\n\
             /// (c) The Cloud Hypervisor Authors), embedded to run from memory.\n\
             pub static CH_BIN: Option<&[u8]> = Some(include_bytes!({ch:?}));\n"
        )
    } else {
        "/// Set once `cargo xtask demo assets` has downloaded the binary.\n\
         pub static CH_BIN: Option<&[u8]> = None;\n"
            .to_string()
    };
    std::fs::write(out.join("ch_bin.rs"), ch_rs).expect("writing ch_bin.rs");
}

fn walk(dir: &Path, files: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("reading novnc") {
        let path = entry.expect("reading novnc").path();
        if path.is_dir() {
            walk(&path, files);
        } else {
            files.push(path);
        }
    }
}
