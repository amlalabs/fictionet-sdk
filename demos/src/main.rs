//! `fictionet-demo`: a Fictionet demo as one program. The world runs in
//! this process, and the sandbox is a microVM run by a child of this same
//! executable, whose network card the world serves.
//!
//! It needs KVM, and nothing installed: the guest's kernel, agent and root
//! filesystem are inside the program. `cargo xtask microvm` makes them and
//! builds the program.

mod frames;
mod web;

use std::process::ExitCode;

use fictionet_microvm::Assets;

#[cfg(guest_assets)]
const ASSETS: Assets = Assets {
    kernel: include_bytes!("../assets/kernel.zst"),
    agent: include_bytes!("../assets/agentd.zst"),
    rootfs: include_bytes!("../assets/rootfs.ext4.zst"),
};

#[cfg(not(guest_assets))]
const ASSETS: Assets = Assets {
    kernel: &[],
    agent: &[],
    rootfs: &[],
};

fn main() -> ExitCode {
    fictionet_microvm::run_if_child(ASSETS.kernel);
    if ASSETS.kernel.is_empty() {
        eprintln!(
            "fictionet-demo: this build has no guest inside; build it with `cargo xtask microvm build`"
        );
        return ExitCode::FAILURE;
    }
    let result = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(fictionet::Error::from)
        .and_then(|runtime| runtime.block_on(web::run(ASSETS)));
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("fictionet-demo: {error}");
            ExitCode::FAILURE
        }
    }
}
