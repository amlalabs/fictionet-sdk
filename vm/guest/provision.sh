#!/usr/bin/env bash
# Runs once inside a fresh Debian 13 cloud VM, as root, to make the prepared
# image that every later run of vm/run boots from. vm/run copies this file
# and versions.sh into the VM and runs it; it is not meant to be run by hand.
#
# It installs Docker Engine with the Compose and Buildx plugins, kind,
# kubectl, helm, uv, Rust with the musl target, and the network tools the
# demos use (curl, dig, ping, traceroute, ip). Docker keeps its data on the
# cache disk at /cache, so pulled images and build caches outlive each run.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../versions.sh
. "$here/../versions.sh"
export DEBIAN_FRONTEND=noninteractive
step() { printf '\n== %s\n' "$*"; }

step "Waiting for cloud-init to finish its first boot"
cloud-init status --wait >/dev/null || true

step "Turning off background jobs that slow a short-lived VM"
systemctl disable --now apt-daily.timer apt-daily-upgrade.timer man-db.timer \
    e2scrub_all.timer fstrim.timer >/dev/null 2>&1 || true
apt-get remove -y -q --purge unattended-upgrades >/dev/null 2>&1 || true

step "The cache disk: /cache, made on first use"
# vm/run attaches a second disk with serial "fncache". systemd formats it
# (x-systemd.makefs) the first time and mounts it at /cache on every boot.
mkdir -p /cache
grep -q ' /cache ' /etc/fstab ||
    echo '/dev/disk/by-id/virtio-fncache /cache ext4 defaults,discard,x-systemd.makefs,nofail,x-systemd.device-timeout=20s 0 2' >>/etc/fstab
systemctl daemon-reload
systemctl start cache.mount
df -h /cache | tail -1

step "Packages"
apt-get update -q
apt-get install -y -q --no-install-recommends \
    ca-certificates curl gpg dnsutils iproute2 iputils-ping traceroute \
    python3 git jq procps psmisc less build-essential musl-tools

step "Docker Engine, Compose and Buildx, from Docker's apt repository"
install -d -m 0755 /etc/apt/keyrings /etc/docker
curl -fsSL --retry 3 https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
# Docker's release key, as published at https://docs.docker.com/engine/install/debian/.
gpg --show-keys --with-colons /etc/apt/keyrings/docker.asc |
    grep -q '^fpr:::::::::9DC858229FC7DD38854AE2D88D81803C0EBFCD88:$'
echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian trixie stable" \
    >/etc/apt/sources.list.d/docker.list
# Images and build caches live on the cache disk. The classic image store
# keeps everything under data-root.
cat >/etc/docker/daemon.json <<'EOF'
{
  "data-root": "/cache/docker",
  "features": { "containerd-snapshotter": false },
  "log-driver": "local"
}
EOF
mkdir -p /etc/systemd/system/docker.service.d /etc/systemd/system/containerd.service.d
printf '[Unit]\nRequiresMountsFor=/cache\n' >/etc/systemd/system/docker.service.d/cache.conf
apt-get update -q
apt-get install -y -q docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
systemctl enable docker >/dev/null
docker version --format 'Docker Engine {{.Server.Version}}'
docker compose version

work="$(mktemp -d)"
cd "$work"
fetch() { curl -fsSL --retry 3 -o "$2" "$1"; }
# check FILE HASH: the file's SHA-256 (or SHA-512, by length) must match.
check() {
    local sum=sha256sum
    [[ ${#2} == 128 ]] && sum=sha512sum
    echo "$2  $1" | "$sum" -c --quiet -
}

step "kind $KIND_VERSION"
fetch "https://github.com/kubernetes-sigs/kind/releases/download/$KIND_VERSION/kind-linux-amd64" kind
fetch "https://github.com/kubernetes-sigs/kind/releases/download/$KIND_VERSION/kind-linux-amd64.sha256sum" kind.sum
check kind "$(awk '{print $1}' kind.sum)"
install -m 0755 kind /usr/local/bin/kind

step "kubectl $KUBECTL_VERSION"
fetch "https://dl.k8s.io/release/$KUBECTL_VERSION/bin/linux/amd64/kubectl" kubectl
fetch "https://dl.k8s.io/release/$KUBECTL_VERSION/bin/linux/amd64/kubectl.sha256" kubectl.sum
check kubectl "$(cat kubectl.sum)"
install -m 0755 kubectl /usr/local/bin/kubectl

step "helm $HELM_VERSION"
fetch "https://get.helm.sh/helm-$HELM_VERSION-linux-amd64.tar.gz" helm.tgz
fetch "https://get.helm.sh/helm-$HELM_VERSION-linux-amd64.tar.gz.sha256sum" helm.sum
check helm.tgz "$(awk '{print $1}' helm.sum)"
tar -xzf helm.tgz linux-amd64/helm
install -m 0755 linux-amd64/helm /usr/local/bin/helm

step "uv $UV_VERSION"
fetch "https://github.com/astral-sh/uv/releases/download/$UV_VERSION/uv-x86_64-unknown-linux-gnu.tar.gz" uv.tgz
fetch "https://github.com/astral-sh/uv/releases/download/$UV_VERSION/uv-x86_64-unknown-linux-gnu.tar.gz.sha256" uv.sum
check uv.tgz "$(awk '{print $1}' uv.sum)"
tar -xzf uv.tgz
install -m 0755 uv-x86_64-unknown-linux-gnu/uv uv-x86_64-unknown-linux-gnu/uvx /usr/local/bin/

step "Rust $RUST_VERSION with the musl target"
fetch https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init rustup-init
fetch https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init.sha256 rustup-init.sum
check rustup-init "$(awk '{print $1}' rustup-init.sum)"
chmod +x rustup-init
RUSTUP_HOME=/opt/rust/rustup CARGO_HOME=/opt/rust/cargo ./rustup-init -y -q --no-modify-path \
    --profile minimal --default-toolchain "$RUST_VERSION" --target x86_64-unknown-linux-musl
# rustup's proxies (cargo, rustc, rustdoc and the rest), on every PATH.
for tool in /opt/rust/cargo/bin/*; do ln -sf "$tool" "/usr/local/bin/${tool##*/}"; done
# Toolchains stay in the image. The registry, build output and uv's
# downloads go to the cache disk, so they last between runs.
cat >/etc/environment <<'EOF'
RUSTUP_HOME=/opt/rust/rustup
CARGO_HOME=/cache/cargo
UV_CACHE_DIR=/cache/uv
UV_PYTHON_INSTALL_DIR=/cache/uv/python
EOF
RUSTUP_HOME=/opt/rust/rustup rustc --version

step "Name lookups that follow each namespace's resolv.conf"
# Debian's cloud image looks names up through systemd-resolved's NSS module,
# which asks resolved over a socket. Resolved lives in the VM's own network
# namespace, so a program in a sandbox namespace would get the VM's real DNS
# instead of the world's, whatever /etc/netns/<name>/resolv.conf says. With
# plain "dns", glibc reads resolv.conf, which `ip netns exec` swaps.
sed -i -E 's/^hosts:.*/hosts:          files myhostname dns/' /etc/nsswitch.conf

step "No new connections from the VM to your machine"
# QEMU's user network maps 10.0.2.2 to the host's own 127.0.0.1. The VM
# needs the internet, but nothing in it needs the host's local services,
# so new connections to 10.0.2.2 are dropped, from the VM and from its
# containers. SSH from the host still works: it comes in, not out.
apt-get install -y -q --no-install-recommends nftables >/dev/null
cat >/etc/fictionet-guard.nft <<'EOF'
table inet fictionet_guard
delete table inet fictionet_guard
table inet fictionet_guard {
    chain output {
        type filter hook output priority 0; policy accept;
        ip daddr 10.0.2.2 ct state new drop
    }
    chain forward {
        type filter hook forward priority 0; policy accept;
        ip daddr 10.0.2.2 ct state new drop
    }
}
EOF
cat >/etc/systemd/system/fictionet-guard.service <<'EOF'
[Unit]
Description=Drop new connections from the VM to the host (10.0.2.2)
Before=network-pre.target docker.service
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f /etc/fictionet-guard.nft

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now fictionet-guard.service
if curl -s -m 3 -o /dev/null http://10.0.2.2:1/ 2>/dev/null || [[ $? != 28 ]]; then
    echo "10.0.2.2 is still reachable" >&2
    exit 1
fi

step "Kernel settings for kind"
cat >/etc/sysctl.d/90-fictionet-vm.conf <<'EOF'
fs.inotify.max_user_instances = 1024
fs.inotify.max_user_watches = 524288
EOF
sysctl -q --system

step "Tidying up"
cd /
rm -rf "$work"
apt-get clean
rm -rf /var/lib/apt/lists/*
# Later boots come from this image with the SSH key already in place, so
# cloud-init has nothing left to do. Turning it off saves seconds per boot.
touch /etc/cloud/cloud-init.disabled
fstrim -a >/dev/null 2>&1 || true
echo "prepared"
