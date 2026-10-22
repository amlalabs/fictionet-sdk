#!/usr/bin/env bash
# Builds Fictionet's binaries inside the VM, from the copy of the working
# tree at /src, as static musl executables. cargo xtask vm runs it; so can you,
# with `cargo xtask vm build [sdk]`.
#
#   sdk       fictionet, the small demo binaries and the web test fixture
#
# Build output lives on the cache disk, so a build after a small change
# takes seconds. The binaries go to /opt/fictionet/bin, and also to
# /opt/fictionet/prebuilt, laid out the way deploy/Dockerfile copies them out
# of its build stages (usr/local/bin/ and out/), so the k8s demo builds its
# images from that folder in place of a build stage.
# Static binaries run anywhere: in the VM, and in any container image.
# Everything builds with --locked, as in CI and the Dockerfiles.
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
            echo "Building fictionet and the demo binaries"
            build -p fictionet --features web-proxy,tokio --example web_fixture \
                -p fictionet-cli -p fictionet-web-world-demo -p fictionet-ping-world-demo \
                -p fictionet-bottleneck-sites-demo -p fictionet-capture-sites-demo \
                -p fictionet-delayed-sites-demo -p fictionet-lossy-sites-demo \
                -p fictionet-custom-protocol-demo -p fictionet-route-change-demo \
                -p fictionet-goad-demo -p fictionet-h2spec-world-demo --bins
            for executable in "$out"/* "$out/examples/web_fixture"; do
                if [[ -f $executable && -x $executable ]]; then put "$executable"; fi
            done
            install -m 0755 "$out/fictionet" "$out/web_world" "$out/examples/web_fixture" "$pre/out/"
            ;;
        none) ;;
        *) echo "build.sh: unknown target $what" >&2; exit 2 ;;
    esac
done
