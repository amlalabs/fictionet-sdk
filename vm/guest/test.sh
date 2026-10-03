#!/usr/bin/env bash
# Runs one of the repository's test suites inside the VM, as root, from the
# copy of the working tree at /src. `vm/run test <name>` runs it; `vm/run
# test list` lists the names. The suites run unchanged: this script only
# starts them the way their READMEs say, and decides pass or fail.
set -euo pipefail
export RUSTUP_HOME=/opt/rust/rustup CARGO_HOME=/cache/cargo
export UV_CACHE_DIR=/cache/uv UV_PYTHON_INSTALL_DIR=/cache/uv/python UV_LINK_MODE=copy
# shellcheck source=../versions.sh
. /src/vm/versions.sh
name="$1"
cd /src

pull() { docker image inspect "$1" >/dev/null 2>&1 || docker pull -q "$1" >/dev/null; }

# inspect_suite DIR TASK SETTING...: runs an Inspect task with the mock
# model for each setting, then prints its checks with the example's own
# show_probes.py. Fails if a check fails, or a sample has no score.
inspect_suite() {
    local dir="$1" task="$2"
    shift 2
    cd "/src/examples/$dir"
    uv sync --quiet
    local logs=() setting status=0
    for setting in "$@"; do
        local log_dir="logs/vm-${task##*@}-$setting"
        rm -rf "$log_dir"
        local args=()
        [[ $setting != - ]] && args=(-T "setting=$setting")
        echo "== uv run inspect eval $task --model mockllm/model ${args[*]}"
        uv run inspect eval "$task" --model mockllm/model "${args[@]}" --display plain --log-dir "$log_dir" ||
            status=1
        logs+=("$(ls "$log_dir"/*.eval)")
    done
    echo
    echo "== uv run python scripts/show_probes.py"
    local out
    out="$(uv run python scripts/show_probes.py "${logs[@]}")"
    echo "$out"
    grep -q 'status=success\|status: success' <<<"$out" || status=1
    if grep -qE '^ *(FAIL|ERROR) ' <<<"$out" || grep -q 'status=error\|status: error' <<<"$out"; then status=1; fi
    return "$status"
}

case "$name" in
    netns)
        bash /src/vm/guest/build.sh sdk
        bash /src/vm/guest/tests/netns.sh
        ;;
    docker-web | docker-proxy | docker-ping | docker-tcpudp)
        bash "/src/tests/docker/${name#docker-}/run.sh"
        ;;
    k8s | k8s-proxy)
        # kind makes its cluster from the node image its release was built
        # for, the one versions.sh names. Pulling it first only saves time.
        pull "$KIND_NODE_IMAGE"
        if [[ $name == k8s ]]; then bash /src/tests/k8s/run.sh; else bash /src/tests/k8s/proxy.sh; fi
        ;;
    border-world)
        cd /src/examples/border/world
        CARGO_TARGET_DIR=/cache/target/border-test cargo test
        ;;
    border-scripted)
        inspect_suite border src/border_eval/probes.py@border_scripted lab home
        ;;
    border-probes)
        inspect_suite border src/border_eval/probes.py@border_probes lab home
        ;;
    fakewiki-probes)
        inspect_suite fakewiki src/fakewiki_eval/probes.py@fakewiki_probes -
        echo
        echo "== uv run python scripts/negative_control.py"
        out="$(uv run python scripts/negative_control.py "$(ls logs/vm-fakewiki_probes--/*.eval)")"
        echo "$out"
        # The control world's pages, judged as control, have no leaks; judged
        # as altered, they must.
        grep -qE 'judged as control *: +0 leak' <<<"$out"
        ! grep -qE 'judged as altered_(one|all) *: +0 leak' <<<"$out"
        ;;
    cargo)
        CARGO_TARGET_DIR=/cache/target/test FICTIONET_TUN_TEST=1 cargo test --locked --features tokio
        ;;
    *)
        echo "test.sh: no suite named $name" >&2
        exit 2
        ;;
esac
