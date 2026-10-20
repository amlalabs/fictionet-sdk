#!/usr/bin/env bash
# Builds Fictionet's binaries inside the VM, from the copy of the working
# tree at /src, as static musl executables. cargo xtask vm runs it; so can you,
# with `cargo xtask vm build [sdk] [border] [fakewiki] [adaptive-web]`.
#
#   sdk       fictionet and every example in the crate's Cargo.toml: web_world,
#             scan, the web_fixture test world and the rest
#   border    border-world, the world of examples/border
#   fakewiki, adaptive-web
#             fakewiki-world and adaptive-web-world, those examples' worlds
#
# Build output lives on the cache disk, so a build after a small change
# takes seconds. The binaries go to /opt/fictionet/bin, and also to
# /opt/fictionet/prebuilt, laid out the way the examples' Dockerfiles copy
# them out of their build stages (usr/local/bin/ and out/). A Compose file
# can then use that folder in place of a build stage (cargo xtask vm build border).
# Static binaries run anywhere: in the VM, and in any container image.
# Everything builds with --locked, as in CI and the examples' Dockerfiles,
# in one target directory, so the example worlds reuse the SDK's dependencies.
set -euo pipefail
export RUSTUP_HOME=/opt/rust/rustup CARGO_HOME=/cache/cargo
target=x86_64-unknown-linux-musl
out=/cache/target/sdk/$target/release
bin=/opt/fictionet/bin
pre=/opt/fictionet/prebuilt
mkdir -p "$bin" "$pre/usr/local/bin" "$pre/out"

build() {
    (cd /src && CARGO_TARGET_DIR=/cache/target/sdk cargo build --release --locked --target "$target" "$@")
}

put() {
    install -m 0755 "$1" "$bin/"
    install -m 0755 "$1" "$pre/usr/local/bin/"
}

for what in "${@:-sdk}"; do
    case "$what" in
        sdk)
            echo "Building fictionet and the examples"
            build --features web-proxy,tokio --bin fictionet --examples
            put "$out/fictionet"
            for example in "$out"/examples/*; do
                if [[ -f $example && -x $example ]]; then put "$example"; fi
            done
            install -m 0755 "$out/fictionet" "$out/examples/web_world" "$out/examples/web_fixture" "$pre/out/"
            ;;
        border | fakewiki | adaptive-web)
            echo "Building $what-world"
            build -p "$what-world" --bin "$what-world"
            put "$out/$what-world"
            ;;
        none) ;;
        *) echo "build.sh: unknown target $what" >&2; exit 2 ;;
    esac
done
