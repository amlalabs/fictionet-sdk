//! The guest assets are embedded when `cargo xtask microvm` has made them,
//! so a workspace build without them still compiles; the program then says
//! how to make them.

use std::path::Path;

const ASSETS: [&str; 3] = ["kernel.zst", "agentd.zst", "rootfs.ext4.zst"];

fn main() {
    println!("cargo::rerun-if-changed=assets");
    println!("cargo::rustc-check-cfg=cfg(guest_assets)");
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("assets");
    if ASSETS.iter().all(|name| dir.join(name).is_file()) {
        println!("cargo::rustc-cfg=guest_assets");
    }
}
