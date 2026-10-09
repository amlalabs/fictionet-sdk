#!/usr/bin/env bash
# The nested VM test for `fictionet attach --type tap --vm tap:<name>`: real
# TAP devices, without root on this machine.
#
#   tests/vm/nested.sh            run the test (skips if KVM, nesting or the images are missing)
#   tests/vm/nested.sh --fetch    download and prepare everything first (once)
#
# It boots an outer VM (L1) under QEMU with KVM and -cpu host, so L1 can
# run VMs of its own. Inside L1, as root, nested-l1.sh runs a world
# (web_fixture) and, one after another, QEMU with -netdev tap, Firecracker
# and Cloud Hypervisor. Each nested guest (L2) is on a TAP device, tap0,
# and attach redirects tap0's frames to a TAP device of its own. The
# guest gets its address from attach by DHCP, then checks DNS, HTTPS,
# ping, and that an unknown name and address fail fast (l2-check.sh).
#
# --fetch needs the internet, and takes several minutes: it prepares the
# guest image as tests/vm/run.sh --fetch does, then an L1 image with QEMU
# installed, and downloads pinned releases of Firecracker and Cloud
# Hypervisor and Firecracker's CI guest kernel, each checked by SHA-256.
# All of it is cached in .vm/ (gitignored), or in $FICTIONET_VM_DIR.

set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
source "$here/common.sh"

if [ "${1:-}" = --fetch ]; then
    command -v genisoimage >/dev/null || { echo "genisoimage is missing"; exit 1; }
    fetch_nested
fi

[ -r /dev/kvm ] && [ -w /dev/kvm ] || skip "/dev/kvm is missing or not usable by $(id -un)"
nested=$(cat /sys/module/kvm_amd/parameters/nested /sys/module/kvm_intel/parameters/nested 2>/dev/null | head -1 || true)
[ "$nested" = 1 ] || [ "$nested" = Y ] || skip "nested virtualization is off (kvm_amd or kvm_intel nested=1)"
command -v qemu-system-x86_64 >/dev/null || skip "qemu-system-x86_64 is missing"
command -v genisoimage >/dev/null || skip "genisoimage is missing"
for f in "$prepared_l1" "$assets/$kernel" "$assets/$fc_bin" "$assets/$ch_bin" "$assets/$l2_root"; do
    [ -f "$f" ] || skip "$f is missing; run tests/vm/nested.sh --fetch once to make it"
done

echo "building fictionet and web_fixture (release)"
(cd "$repo" && cargo build --quiet --release --features web-proxy --bin fictionet --example web_fixture)
target="$(target_dir)"

run="$(mktemp -d "$vmdir/nested.XXXXXX")"
cleanup() { rm -rf "$run"; }
trap cleanup EXIT

# Two read-only disks for L1: the large files, cached between runs, and
# this run's binaries and scripts.
assets_iso="$vmdir/assets/assets-$release-$fc_version-$ch_version-$kernel.iso"
if [ ! -f "$assets_iso" ]; then
    echo "making $assets_iso"
    genisoimage -quiet -output "$assets_iso.part" -volid FNASSETS -rock -graft-points \
        "vmlinux=$assets/$kernel" "firecracker=$assets/$fc_bin" \
        "cloud-hypervisor=$assets/$ch_bin" "l2-root.qcow2=$assets/$l2_root"
    mv "$assets_iso.part" "$assets_iso"
fi
genisoimage -quiet -output "$run/run.iso" -volid FNRUN -rock -graft-points \
    "fictionet=$target/release/fictionet" "web_fixture=$target/release/examples/web_fixture" \
    "nested-l1.sh=$here/nested-l1.sh" "l2-check.sh=$here/l2-check.sh"

cat > "$run/user-data" <<'EOF'
#cloud-config
runcmd:
  - [sh, -c, 'mkdir -p /mnt/assets /mnt/run && mount -o ro LABEL=FNASSETS /mnt/assets && mount -o ro LABEL=FNRUN /mnt/run && bash /mnt/run/nested-l1.sh > /dev/ttyS1 2>&1; poweroff']
EOF
printf 'instance-id: nested-%s\nlocal-hostname: l1\n' "$RANDOM" > "$run/meta-data"
genisoimage -quiet -output "$run/seed.iso" -volid cidata -joliet -rock "$run/user-data" "$run/meta-data"
qemu-img create -q -f qcow2 -b "$prepared_l1" -F qcow2 "$run/l1.qcow2"

echo "booting L1"
t0=$(date +%s)
timeout 1200 "${qemu_base[@]}" -m 5G -smp 4 \
    -serial "file:$run/l1-console.log" -serial "file:$run/l1-out.txt" \
    -drive "file=$run/l1.qcow2,if=virtio" \
    -drive "file=$run/seed.iso,if=virtio,media=cdrom,readonly=on" \
    -drive "file=$assets_iso,if=virtio,media=cdrom,readonly=on" \
    -drive "file=$run/run.iso,if=virtio,media=cdrom,readonly=on" \
    -nic none || true
echo "L1 ran for $(($(date +%s) - t0)) s"
tr -d '\r' < "$run/l1-out.txt"

passed=$(grep -c '^PASS: ' "$run/l1-out.txt" || true)
failed=$(grep -c '^FAIL: ' "$run/l1-out.txt" || true)
echo
if ! grep -q '^=== L1 done' "$run/l1-out.txt"; then
    echo "L1 did not finish; the logs are in $run"
    trap - EXIT
    exit 1
fi
if [ "$failed" -gt 0 ] || [ "$passed" = 0 ]; then
    echo "$failed checks failed, $passed passed; the logs are in $run"
    trap - EXIT
    exit 1
fi
echo "all $passed checks passed"
