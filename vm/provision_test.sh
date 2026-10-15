#!/usr/bin/env bash
# Provisioning fixtures; no VM, network, or Rust installation needed.
set -euo pipefail
repo="$(cd "$(dirname "$0")/.." && pwd)"
source "$repo/vm/run"
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

# Both consumers share the identity and retain their own disk locations.
appliance_release="$DEBIAN_BUILD"
appliance_sha512="$DEBIAN_IMAGE_SHA512"
appliance_base="$base"
(
    # Test the default location, independent of the caller's override.
    unset FICTIONET_VM_DIR
    source "$repo/tests/vm/common.sh"
    [[ $release == "$appliance_release" && $image_name == "$debian_file" ]] ||
        fail 'both consumers must use the same Debian release and filename'
    [[ $image_url == "$debian_dir/$debian_file" ]] ||
        fail 'both consumers must use the same Debian URL'
    [[ $image_sha512 == "$appliance_sha512" ]] ||
        fail 'both consumers must use the same Debian checksum'
    [[ $base == "$repo/.vm/$image_name" && $appliance_base == "$repo/.vm/images/$image_name" ]] ||
        fail 'TAP-test and appliance base disks must keep separate locations'
    [[ $prepared == "$repo/.vm/prepared-$release.qcow2" ]] ||
        fail 'the TAP-test prepared disk must keep its location'
    [[ $prepared_l1 == "$repo/.vm/prepared-l1-$release.qcow2" ]] ||
        fail 'the nested TAP-test prepared disk must keep its location'
    download() {
        [[ $# == 3 && $1 == "$DEBIAN_IMAGE_URL" && $2 == "$base" && $3 == "$DEBIAN_IMAGE_SHA512" ]] ||
            fail 'TAP-test download must use the descriptor and its base disk'
    }
    prepare_image() {
        [[ $# == 4 && $1 == "$base" && $2 == "$prepared" && $4 == 4G ]] ||
            fail 'TAP-test preparation must use its own disks and size'
        [[ $3 == "$(prep_user_data 'bind9-dnsutils, curl, iputils-ping')" ]] ||
            fail 'TAP-test preparation must keep its provisioning inputs'
    }
    fetch_guest
)
echo 'PASS: shared Debian identity and separate TAP-test preparation inputs'

root="$scratch/checkout"
here="$root/vm"
vmdir="$root/.vm"
images="$vmdir/images"
rundir="$vmdir/run"
sshdir="$vmdir/ssh"
base="$images/$debian_file"
bundle="$scratch/bundle"
mkdir -p "$here/guest"
cp "$repo/vm/versions.sh" "$here/versions.sh"
cp "$repo/vm/debian-image.sh" "$here/debian-image.sh"
cp "$repo/vm/guest/provision.sh" "$here/guest/provision.sh"
cp "$repo/rust-toolchain.toml" "$root/rust-toolchain.toml"

# Exercise ensure_prepared's real key, bundle, and cache reuse paths.
check_host() { :; }
fetch_base() { mkdir -p "$images"; touch "$base"; }
ssh_key() { mkdir -p "$sshdir"; echo fixture-key >"$sshdir/id_ed25519.pub"; }
qemu-img() { touch "$tmp"; }
make_seed() { :; }
boot() { :; }
wait_ssh() { :; }
stop_vm() { :; }
vm_ssh() {
    case "$1" in
        'mkdir -p /root/provision') mkdir -p "$bundle" ;;
        'tar -xf - -C /root/provision') tar -xf - -C "$bundle" ;;
        'bash /root/provision/guest/provision.sh')
            echo prepare >>"$scratch/prepares"
            echo prepared
            ;;
        *) fail "unexpected SSH command: $*" ;;
    esac
}

# Run only the Rust section of the bundled script. Stub its downloads,
# installation and system symlinks; every other provisioning step needs root.
step() { :; }
fetch() {
    case "$2" in
        rustup-init)
            cat >"$2" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ $RUSTUP_HOME == /opt/rust/rustup && $CARGO_HOME == /opt/rust/cargo ]]
[[ $* == '-y -q --no-modify-path --profile minimal --default-toolchain none' ]]
echo init >>"$test_log"
EOF
            ;;
        rustup-init.sum) echo fixture-checksum >"$2" ;;
        *) fail "unexpected download: $*" ;;
    esac
}
check() { :; }
ln() { :; }
rustup() {
    [[ $RUSTUP_HOME == /opt/rust/rustup && $CARGO_HOME == /opt/rust/cargo ]] ||
        fail 'toolchain must be installed in the image'
    cmp "$root/rust-toolchain.toml" rust-toolchain.toml ||
        fail 'rustup must select the bundled checkout descriptor'
    local channel
    channel="$(sed -n 's/^channel = "\(.*\)"/\1/p' rust-toolchain.toml)"
    case "$*" in
        'toolchain install') echo install >>"$test_log" ;;
        'target add x86_64-unknown-linux-musl') echo musl >>"$test_log" ;;
        'show active-toolchain') echo "$channel-x86_64-unknown-linux-gnu (directory override)" ;;
        "default $channel-x86_64-unknown-linux-gnu") echo default >>"$test_log" ;;
        *) fail "unexpected rustup command: $*" ;;
    esac
}
check_rust() (
    cmp "$here/versions.sh" "$bundle/versions.sh"
    cmp "$here/guest/provision.sh" "$bundle/guest/provision.sh"
    cmp "$root/rust-toolchain.toml" "$bundle/rust-toolchain.toml"
    sed -n '/^step "Rust /,/^# Toolchains stay/{ /^# Toolchains stay/d; p; }' \
        "$bundle/guest/provision.sh" >"$scratch/rust.sh"
    here="$bundle/guest"
    export test_log="$scratch/rust.log"
    : >"$test_log"
    cd "$scratch"
    source "$scratch/rust.sh"
    [[ $(cat "$test_log") == $'init\ninstall\nmusl\ndefault' ]] ||
        fail 'install the selected toolchain before adding its musl target'
)

ensure_prepared
check_rust
first="$prepared"
ensure_prepared
[[ $prepared == "$first" && $(wc -l <"$scratch/prepares") == 1 ]] ||
    fail 'unchanged inputs must reuse the prepared image'
echo 'PASS: bundled checkout toolchain, musl target, and cache reuse'

sed -i 's/^channel = .*/channel = "0.0.1"/' "$root/rust-toolchain.toml"
ensure_prepared
[[ $prepared != "$first" && $(wc -l <"$scratch/prepares") == 2 ]] ||
    fail 'a compiler change must prepare a new image'
check_rust
second="$prepared"
echo 'PASS: a changed compiler is provisioned in a new image'

sed -i 's/^components = .*/components = ["rustfmt", "rust-src"]/' "$root/rust-toolchain.toml"
ensure_prepared
[[ $prepared != "$second" && $(wc -l <"$scratch/prepares") == 3 ]] ||
    fail 'a component change must prepare a new image'
check_rust
echo 'PASS: changed components are provisioned in a new image'

third="$prepared"
sed -i 's/^DEBIAN_BUILD=.*/DEBIAN_BUILD=fixture-build/' "$here/debian-image.sh"
ensure_prepared
[[ $prepared != "$third" && $(wc -l <"$scratch/prepares") == 4 ]] ||
    fail 'a Debian descriptor change must prepare a new image'
echo 'PASS: changed Debian descriptor invalidates the prepared image'

# Each workflow's image cache key must hash the shared descriptor.
hash_files='hashFiles\(([^)]*)\)'
descriptor="(^|,)[[:space:]]*'vm/debian-image\.sh'[[:space:]]*(,|$)"
for workflow in vm-demo.yml nightly.yml; do
    case "$workflow" in
        vm-demo.yml) prefix=vm-debian- ;;
        nightly.yml) prefix=integration-vm- ;;
    esac
    key="$(sed -n "/^[[:space:]]*key: $prefix/p" "$repo/.github/workflows/$workflow")"
    [[ $key =~ $hash_files ]] ||
        fail "$workflow's cache key must call hashFiles"
    [[ ${BASH_REMATCH[1]} =~ $descriptor ]] ||
        fail "$workflow's cache key must hash vm/debian-image.sh"
    echo "PASS: $workflow's cache key includes the descriptor in hashFiles"
    if [[ $workflow == vm-demo.yml ]]; then
        [[ $key != *vm/versions.sh* ]] ||
            fail "vm-demo.yml's Debian cache key must not include vm/versions.sh"
        echo "PASS: vm-demo.yml's cache key excludes vm/versions.sh"
    fi
done
