#!/usr/bin/env bash
# Builds Fictionet's binaries inside the VM, from the copy of the working
# tree at /src, as static musl executables. vm/run runs it; so can you,
# with `vm/run build [sdk] [border] [fakewiki]`.
#
#   sdk       fictionet, the web_world example and the web_fixture test world
#   border    border-world, the world of examples/border
#   fakewiki  fakewiki-world, the world of examples/fakewiki
#
# Build output lives on the cache disk, so a build after a small change
# takes seconds. The binaries go to /opt/fictionet/bin, and also to
# /opt/fictionet/prebuilt, laid out the way the examples' Dockerfiles copy
# them out of their build stages (usr/local/bin/ and out/). A Compose file
# can then use that folder in place of a build stage (see demos/border).
# Static binaries run anywhere: in the VM, and in any container image.
# The SDK builds with --locked, as in CI. The two example worlds build the
# way their Dockerfiles build them, without it.
set -euo pipefail
export RUSTUP_HOME=/opt/rust/rustup CARGO_HOME=/cache/cargo
target=x86_64-unknown-linux-musl
bin=/opt/fictionet/bin
pre=/opt/fictionet/prebuilt
mkdir -p "$bin" "$pre/usr/local/bin" "$pre/out"

put() {
    install -m 0755 "$1" "$bin/"
    install -m 0755 "$1" "$pre/usr/local/bin/"
}

for what in "${@:-sdk}"; do
    case "$what" in
        sdk)
            echo "Building fictionet, web_world and web_fixture"
            (cd /src && CARGO_TARGET_DIR=/cache/target/sdk cargo build --release --locked --target "$target" \
                --features web-proxy --bin fictionet --example web_world --example web_fixture)
            out=/cache/target/sdk/$target/release
            put "$out/fictionet"
            put "$out/examples/web_world"
            put "$out/examples/web_fixture"
            install -m 0755 "$out/fictionet" "$out/examples/web_world" "$out/examples/web_fixture" "$pre/out/"
            ;;
        border)
            echo "Building border-world"
            (cd /src/examples/border/world && CARGO_TARGET_DIR=/cache/target/border cargo build --release \
                --target "$target" --bin border-world)
            put "/cache/target/border/$target/release/border-world"
            ;;
        fakewiki)
            echo "Building fakewiki-world"
            (cd /src/examples/fakewiki/world && CARGO_TARGET_DIR=/cache/target/fakewiki cargo build --release \
                --target "$target")
            put "/cache/target/fakewiki/$target/release/fakewiki-world"
            ;;
        none) ;;
        *) echo "build.sh: unknown target $what" >&2; exit 2 ;;
    esac
done
