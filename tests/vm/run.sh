#!/usr/bin/env bash
# The VM test for `fictionet attach --type tap`: a Debian cloud image under
# QEMU with KVM, attached to a world through QEMU's -netdev stream socket.
#
#   tests/vm/run.sh            run the test (skips if /dev/kvm or the image is missing)
#   tests/vm/run.sh --fetch    download and prepare the image first (once)
#
# No root is needed. The image lives in .vm/ at the top of the repository
# (gitignored), or in $FICTIONET_VM_DIR (see common.sh). --fetch downloads a
# pinned Debian 13 genericcloud image, checks its SHA-512, and boots it once
# with QEMU's user-mode network to install dig. That boot is the only one
# with a network other than the world's.
#
# Two boots of the same image follow, each with a fresh disk overlay:
#
#   1. web_fixture, IPv4. The guest's own DHCP client gets its address from
#      attach (--ip-addr). Then dig resolves a world name, curl --cacert
#      fetches an HTTPS page and 16 MiB, ping reaches the gateway, and an
#      unknown name and an unknown address both fail fast.
#   2. ping_world, IPv4 and IPv6. Attach hands out both families (DHCP,
#      and router advertisements plus DHCPv6), and the guest pings the
#      gateway over each.
#
# After each boot it checks that attach exited 0 when QEMU closed the
# socket. It prints the guest's commands and outputs, then PASS or FAIL
# lines, and exits 1 if anything failed.

set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
source "$here/common.sh"

if [ "${1:-}" = --fetch ]; then
    command -v genisoimage >/dev/null || { echo "genisoimage is missing"; exit 1; }
    fetch_guest
fi

[ -r /dev/kvm ] && [ -w /dev/kvm ] || skip "/dev/kvm is missing or not usable by $(id -un)"
command -v qemu-system-x86_64 >/dev/null || skip "qemu-system-x86_64 is missing"
command -v genisoimage >/dev/null || skip "genisoimage is missing"
[ -f "$prepared" ] || skip "no VM image at $prepared; run tests/vm/run.sh --fetch once to make it"

echo "building fictionet, web_fixture and ping_world"
(cd "$repo" && cargo build --quiet --features web-proxy --bin fictionet --example web_fixture --example ping_world)
target="$(target_dir)"
bin="$target/debug/fictionet"
examples="$target/debug/examples"

run="$(mktemp -d "$vmdir/run.XXXXXX")"
pids=()
cleanup() {
    for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
    wait 2>/dev/null || true
    rm -rf "$run"
}
trap cleanup EXIT

failures=0
pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; failures=$((failures + 1)); }

# The guest's half of each boot: cloud-init runs it once the network is up.
# Its output goes to the second serial port, away from the console.
guest_script() {
    cat <<'EOF'
#!/bin/bash
exec > /dev/ttyS1 2>&1
ip() { command ip -color=never "$@"; }
show() { echo "\$ $*"; "$@"; echo "[exit $?]"; }
timed() { local t0 t1; t0=$(date +%s%N); show "$@"; t1=$(date +%s%N); echo "[took $(( (t1 - t0) / 1000000 )) ms]"; }
echo "=== guest begin"
show ip -br link
show ip -br addr show dev ens3
show ip route
show ip -6 route
EOF
    cat
    echo 'echo "=== guest end"'
    echo 'poweroff'
}

# Boots the image once. $1: a name for this boot. The guest commands come on
# stdin. A network-config may be given as $2.
boot() {
    local name="$1" seed="$run/$1-seed"
    mkdir -p "$seed"
    guest_script > "$seed/check.sh"
    {
        echo '#cloud-config'
        echo 'write_files:'
        echo '  - path: /root/ca.pem'
        echo '    encoding: b64'
        echo "    content: $(base64 -w0 "$run/ca.pem" 2>/dev/null || true)"
        echo '  - path: /root/check.sh'
        echo "    permissions: '0755'"
        echo '    encoding: b64'
        echo "    content: $(base64 -w0 "$seed/check.sh")"
        echo 'runcmd:'
        echo '  - [/root/check.sh]'
    } > "$seed/user-data"
    printf 'instance-id: %s-%s\nlocal-hostname: agent\n' "$name" "$RANDOM" > "$seed/meta-data"
    local files=("$seed/user-data" "$seed/meta-data")
    if [ -n "${2:-}" ]; then
        printf '%s\n' "$2" > "$seed/network-config"
        files+=("$seed/network-config")
    fi
    genisoimage -quiet -output "$seed/seed.iso" -volid cidata -joliet -rock "${files[@]}"
    qemu-img create -q -f qcow2 -b "$prepared" -F qcow2 "$seed/disk.qcow2"
    timeout 300 "${qemu_base[@]}" -m 1G -smp 2 -serial "file:$run/$name-console.log" -serial "file:$run/$name-out.txt" \
        -drive "file=$seed/disk.qcow2,if=virtio" \
        -drive "file=$seed/seed.iso,if=virtio,media=cdrom,readonly=on" \
        -netdev "stream,id=n0,server=off,addr.type=unix,addr.path=$run/vm.sock" \
        -device virtio-net-pci,netdev=n0 || true
    tr -d '\r' < "$run/$name-out.txt" > "$run/$name-guest.txt"
    echo "--- $name: in the guest"
    cat "$run/$name-guest.txt"
    echo "---"
}

# Starts attach for one boot and waits until it is ready. Flags in "$@".
start_attach() {
    rm -f "$run/ready"
    "$bin" attach --world "unix:$run/world.sock" --name agent --type tap --vm "qemu:$run/vm.sock" \
        --ready-file "$run/ready" --world-wait 10 "$@" 2> "$run/attach.log" &
    attach_pid=$!
    pids+=("$attach_pid")
    for _ in $(seq 100); do [ -f "$run/ready" ] && return 0; sleep 0.1; done
    cat "$run/attach.log"
    return 1
}

# Checks that attach exited 0 after QEMU closed its socket.
attach_ended() {
    local status=0
    for _ in $(seq 50); do kill -0 "$attach_pid" 2>/dev/null || break; sleep 0.1; done
    # Still running after 5 s: a failure, not a hang.
    if kill -0 "$attach_pid" 2>/dev/null; then
        kill -9 "$attach_pid"
        wait "$attach_pid" 2>/dev/null || true
        status=still-running
    else
        wait "$attach_pid" || status=$?
    fi
    echo "--- attach's messages"
    cat "$run/attach.log"
    if [ "$status" = 0 ] && grep -q "QEMU closed the connection; agent detached" "$run/attach.log"; then
        pass "attach exited 0 when QEMU closed the connection"
    else
        fail "attach did not exit 0 after QEMU closed the connection (status $status)"
    fi
}

# Whether the guest's output has a line matching $1 (an extended regex).
says() { grep -Eq -- "$1" "$run/$2-guest.txt"; }

# The time the command after the line matching $1 took, in ms.
took() { grep -A20 -F -- "$1" "$run/$2-guest.txt" | grep -m1 -o 'took [0-9]*' | grep -o '[0-9]*'; }

echo "=== 1. web_fixture, IPv4, DHCP from attach"
"$examples/web_fixture" "$run/world.sock" "$run/ca.pem" > "$run/world.log" 2>&1 &
pids+=($!)
start_attach --ip-addr 10.0.0.2/24 --gateway 10.0.0.1 --dns 10.0.0.1 --no-ip-addr-v6
boot web <<'EOF'
show cat /etc/resolv.conf
show dig +short example.test
show curl -sS --cacert /root/ca.pem https://example.test/
echo
show curl -sS --cacert /root/ca.pem -o /dev/null -w 'size %{size_download} time %{time_total}\n' https://example.test/big
show ping -c 3 10.0.0.1
timed curl -sS --max-time 10 http://nowhere.test/
timed curl -sS --max-time 10 http://192.0.2.1/
EOF
attach_ended
says 'inet 10\.0\.0\.2/24|ens3 +UP +10\.0\.0\.2/24' web && pass "the guest got 10.0.0.2/24 by DHCP" || fail "the guest has no 10.0.0.2/24"
says '^default via 10\.0\.0\.1 dev ens3' web && pass "default route via 10.0.0.1" || fail "no default route via 10.0.0.1"
says '^203\.0\.113\.10$' web && pass "dig resolved example.test to 203.0.113.10" || fail "dig did not resolve example.test"
says '^hello from https example\.test 443' web && pass "curl --cacert fetched https://example.test/" || fail "curl did not fetch https://example.test/"
says '^size 16777216 ' web && pass "curl fetched 16 MiB over HTTPS" || fail "the 16 MiB download did not complete"
says '3 packets transmitted, 3 received' web && pass "ping reached the gateway" || fail "ping did not reach the gateway"
t=$(took 'http://nowhere.test/' web || echo 99999)
says 'Could not resolve host: nowhere.test' web && [ "$t" -lt 2000 ] \
    && pass "an unknown name failed in $t ms" || fail "an unknown name did not fail fast ($t ms)"
t=$(took 'http://192.0.2.1/' web || echo 99999)
says 'Failed to connect to 192\.0\.2\.1' web && [ "$t" -lt 2000 ] \
    && pass "an unknown address failed in $t ms" || fail "an unknown address did not fail fast ($t ms)"
kill "${pids[0]}" 2>/dev/null || true
wait "${pids[0]}" 2>/dev/null || true
pids=()

echo
echo "=== 2. ping_world, IPv4 and IPv6, both handed out by attach"
"$examples/ping_world" "$run/world.sock" > "$run/world.log" 2>&1 &
pids+=($!)
start_attach --ip-addr 10.0.0.2/24 --gateway 10.0.0.1 --dns 10.0.0.1 \
    --ip-addr-v6 fd00::2/64 --gateway-v6 fd00::1 --dns-v6 fd00::1
# The image's default network config asks for DHCP on IPv4 only.
network_config='network:
  version: 2
  ethernets:
    ens3:
      dhcp4: true
      dhcp6: true'
# The guest's script starts once the network is online, which systemd
# counts from the IPv4 lease, so DHCPv6 may still be running: wait up to
# 20 s for the address.
boot dual "$network_config" <<'EOF'
for i in $(seq 40); do ip -6 addr show dev ens3 | grep -q 'fd00::2/128' && break; sleep 0.5; done
show ip -br addr show dev ens3
show ip -6 route
show ping -c 3 10.0.0.1
show ping -c 3 fd00::1
show ping -c 3 2001:db8::99
EOF
attach_ended
says 'fd00::2/128' dual && pass "the guest got fd00::2 by DHCPv6" || fail "the guest has no fd00::2"
says '^default (nhid [0-9]+ )?via fe80::66:6eff:fe00:1 dev ens3' dual && pass "IPv6 default route via attach's link-local address" \
    || fail "no IPv6 default route via attach"
[ "$(grep -c '3 packets transmitted, 3 received' "$run/dual-guest.txt")" = 3 ] \
    && pass "ping reached the world over IPv4 and IPv6" || fail "a ping did not reach the world"

echo
if [ "$failures" -gt 0 ]; then
    echo "$failures checks failed; the logs are in $run"
    trap - EXIT
    for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
    exit 1
fi
echo "all checks passed"
