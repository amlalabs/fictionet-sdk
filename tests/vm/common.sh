# Shared by tests/vm/run.sh and tests/vm/nested.sh: where the cached images
# live, which ones are pinned, and how to fetch and prepare them.
# Everything is cached in .vm/ at the top of the repository (gitignored), or
# in $FICTIONET_VM_DIR.

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
vmdir="${FICTIONET_VM_DIR:-$repo/.vm}"

release=20261001-2618
image_name="debian-13-genericcloud-amd64-$release.qcow2"
image_url="https://cloud.debian.org/images/cloud/trixie/$release/$image_name"
image_sha512=f46f0671a6e5bdec5291ab8972bae2f10e5408c2f64a74078f11efc2f06a436a9d0313ed50e0472542eeabf780e9f7c792ac0a314c6c20507fcd9fd81b468c3d
base="$vmdir/$image_name"
# The image with dig installed: the guest of tests/vm/run.sh, and the root
# filesystem of the nested guests.
prepared="$vmdir/prepared-$release.qcow2"
# The image with QEMU installed: the outer VM of tests/vm/nested.sh.
prepared_l1="$vmdir/prepared-l1-$release.qcow2"

# The nested guests' kernel, VM programs and root filesystem.
assets="$vmdir/assets/iso"
fc_version=v1.17.0
fc_tgz="firecracker-$fc_version-x86_64.tgz"
fc_url="https://github.com/firecracker-microvm/firecracker/releases/download/$fc_version/$fc_tgz"
fc_sha256=06094a1108ae9e82aa4c23a775aa92758f53f1175d422270d9d6162cb9ade558
fc_bin="firecracker-$fc_version-x86_64"
ch_version=v53.0
ch_bin="cloud-hypervisor-static-$ch_version"
ch_url="https://github.com/cloud-hypervisor/cloud-hypervisor/releases/download/$ch_version/cloud-hypervisor-static"
ch_sha256=448af3d4e59b22c2987f7df94c213ad40fb53a10d437e42b5ee6c4fce7c29ecc
# Firecracker's CI guest kernel: an uncompressed vmlinux with PVH boot and
# virtio over both MMIO and PCI built in, so Firecracker, Cloud Hypervisor
# and QEMU all boot it directly.
kernel=vmlinux-6.1.155
kernel_url="https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.15/x86_64/$kernel"
kernel_sha256=e20e46d0c36c55c0d1014eb20576171b3f3d922260d9f792017aeff53af3d4f2
l2_root="l2-root-$release.qcow2"

# Where cargo puts its builds: target/ at the top of the repository, or
# wherever CARGO_TARGET_DIR or a cargo config sends them.
target_dir() {
    (cd "$repo" && cargo metadata --format-version 1 --no-deps) |
        sed -n "s/.*\"target_directory\":\"\([^\"]*\)\".*/\1/p"
}

qemu_base=(qemu-system-x86_64 -enable-kvm -cpu host -display none -no-reboot)

skip() {
    if [ "${CI+x}" = x ]; then echo "FAIL: $* (required in CI)"; exit 1; fi
    echo "SKIP: $*"
    exit 0
}

# Downloads $1 to $2 and checks its SHA-512 ($3) or SHA-256 ($4).
download() {
    local url="$1" to="$2" sha512="${3:-}" sha256="${4:-}"
    [ -f "$to" ] && return 0
    echo "downloading $url"
    mkdir -p "$(dirname "$to")"
    curl -fSL -o "$to.part" "$url"
    if [ -n "$sha512" ]; then echo "$sha512  $to.part" | sha512sum -c --quiet; fi
    if [ -n "$sha256" ]; then echo "$sha256  $to.part" | sha256sum -c --quiet; fi
    mv "$to.part" "$to"
}

# Boots a copy-on-write copy of image $1 once with QEMU's user-mode network
# (the internet), runs cloud-init user-data $3 in it, and keeps the result
# as $2. $4: the disk size.
prepare_image() {
    local from="$1" to="$2" user_data="$3" size="$4" prep
    [ -f "$to" ] && return 0
    echo "preparing $(basename "$to"): one boot with a user-mode network"
    prep="$(mktemp -d "$vmdir/prep.XXXXXX")"
    printf '%s\n' "$user_data" > "$prep/user-data"
    printf 'instance-id: prep-%s\nlocal-hostname: prep\n' "$RANDOM" > "$prep/meta-data"
    genisoimage -quiet -output "$prep/seed.iso" -volid cidata -joliet -rock "$prep/user-data" "$prep/meta-data"
    qemu-img create -q -f qcow2 -b "$from" -F qcow2 "$prep/disk.qcow2" "$size"
    timeout 1800 "${qemu_base[@]}" -m 2G -smp 2 -serial "file:$prep/console.log" \
        -drive "file=$prep/disk.qcow2,if=virtio" \
        -drive "file=$prep/seed.iso,if=virtio,media=cdrom,readonly=on" \
        -nic user,model=virtio-net-pci
    if ! grep -aq FICTIONET-PREP-DONE "$prep/console.log"; then
        echo "preparing the image failed; the console log is in $prep/console.log"
        exit 1
    fi
    mv "$prep/disk.qcow2" "$to"
    rm -rf "$prep"
}

prep_user_data() {
    cat <<EOF
#cloud-config
package_update: true
packages: [$1]
runcmd:
  - [sh, -c, 'echo FICTIONET-PREP-DONE > /dev/ttyS0']
power_state: {mode: poweroff, condition: true}
EOF
}

# The guest image of tests/vm/run.sh.
fetch_guest() {
    download "$image_url" "$base" "$image_sha512"
    prepare_image "$base" "$prepared" "$(prep_user_data 'bind9-dnsutils, curl, iputils-ping')" 4G
}

# Everything tests/vm/nested.sh needs.
fetch_nested() {
    fetch_guest
    prepare_image "$prepared" "$prepared_l1" "$(prep_user_data 'qemu-system-x86, qemu-utils')" 16G
    mkdir -p "$assets"
    download "$fc_url" "$vmdir/assets/$fc_tgz" "" "$fc_sha256"
    if [ ! -f "$assets/$fc_bin" ]; then
        tar xzf "$vmdir/assets/$fc_tgz" -C "$assets" --strip-components=1 "release-$fc_version-x86_64/$fc_bin"
    fi
    download "$ch_url" "$assets/$ch_bin" "" "$ch_sha256"
    chmod +x "$assets/$ch_bin"
    download "$kernel_url" "$assets/$kernel" "" "$kernel_sha256"
    if [ ! -f "$assets/$l2_root" ]; then
        # The guest image's root partition, alone: the nested guests boot
        # the kernel above directly, with this as /dev/vda.
        echo "extracting the root filesystem for the nested guests"
        local raw="$vmdir/full.raw" start size
        qemu-img convert -O raw "$prepared" "$raw"
        start=$(sfdisk -J "$raw" | python3 -c 'import json,sys; p=json.load(sys.stdin)["partitiontable"]["partitions"]; print(max(p, key=lambda x: x["size"])["start"])')
        size=$(sfdisk -J "$raw" | python3 -c 'import json,sys; p=json.load(sys.stdin)["partitiontable"]["partitions"]; print(max(p, key=lambda x: x["size"])["size"])')
        dd if="$raw" of="$vmdir/root.raw" bs=512 skip="$start" count="$size" conv=sparse status=none
        qemu-img convert -O qcow2 "$vmdir/root.raw" "$assets/$l2_root"
        rm -f "$raw" "$vmdir/root.raw"
    fi
}
