//! Embeds the files `cargo xtask demo assets` downloads to
//! `downloads/cloudimage` when they are there, so a workspace build without
//! them still compiles.
//! Cloud Hypervisor's static binary becomes `OUT_DIR/ch_bin.rs`, `None`
//! without it, so the shared kit can run it from memory with nothing
//! written to disk.

use std::path::PathBuf;

fn main() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let out = PathBuf::from(std::env::var_os("OUT_DIR").expect("cargo sets it"));

    // Cloud Hypervisor's static binary, embedded when it has been downloaded.
    println!("cargo::rerun-if-changed=../downloads/cloudimage/cloud-hypervisor");
    let ch = manifest.join("../downloads/cloudimage/cloud-hypervisor");
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
