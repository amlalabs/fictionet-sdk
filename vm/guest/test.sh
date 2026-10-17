#!/usr/bin/env bash
# Runs one of the repository's test suites inside the VM, as root, from the
# copy of the working tree at /src. `cargo xtask vm test <name>` runs it. The
# suites run unchanged: this script only starts them the way their READMEs
# say, and decides pass or fail.
set -euo pipefail
export RUSTUP_HOME=/opt/rust/rustup CARGO_HOME=/cache/cargo
export UV_CACHE_DIR=/cache/uv UV_PYTHON_INSTALL_DIR=/cache/uv/python UV_LINK_MODE=copy
name="$1"
cd /src

pull() { docker image inspect "$1" >/dev/null 2>&1 || docker pull -q "$1" >/dev/null; }

# Run the no-model eval and require every sample's checks to pass.
inspect_suite() {
    local world="$1" mode="$2"
    shift 2
    local setting status=0
    for setting in "$@"; do
        local log_dir="logs/vm-${world}_${mode#--}-$setting"
        rm -rf "$log_dir"
        local args=()
        [[ $setting != - ]] && args=(-T "setting=$setting")
        echo "== cargo xtask eval $world $mode ${args[*]}"
        cargo xtask eval "$world" "$mode" "${args[@]}" --display plain --log-dir "$log_dir" ||
            status=1
    done
    return "$status"
}

case "$name" in
    netns)
        bash /src/vm/guest/build.sh sdk
        bash /src/vm/guest/tests/netns.sh
        ;;
    docker-web | docker-proxy | docker-ping | docker-tcpudp)
        CARGO_TARGET_DIR=/cache/target/xtask cargo xtask docker "${name#docker-}"
        ;;
    k8s | k8s-proxy)
        # kind makes its cluster from the node image its release was built
        # for, supplied by xtask. Pulling it first only saves time.
        pull "$KIND_NODE_IMAGE"
        if [[ $name == k8s ]]; then cargo xtask k8s tun; else cargo xtask k8s proxy; fi
        ;;
    border-world)
        cd /src/examples/border/world
        CARGO_TARGET_DIR=/cache/target/border-test cargo test
        ;;
    border-scripted)
        inspect_suite border --scripted lab home
        ;;
    border-probes)
        inspect_suite border --probes lab home
        ;;
    fakewiki-probes)
        inspect_suite fakewiki --probes -
        echo
        echo "== uv run python -m inspect_fictionet.worlds.fakewiki.negative_control"
        for log in logs/vm-fakewiki_probes--/*.eval; do
            uv run --project python/inspect_fictionet --locked python -m inspect_fictionet.worlds.fakewiki.negative_control "$log"
        done
        ;;
    cargo)
        export CARGO_TARGET_DIR=/cache/target/test
        cargo test --locked --features web-proxy
        # The tests that need user namespaces, root and a tun device, which the VM has.
        cargo test --locked --features web-proxy --test host
        ;;
    *)
        echo "test.sh: no suite named $name" >&2
        exit 2
        ;;
esac
