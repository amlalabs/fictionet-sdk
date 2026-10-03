# Pinned versions for the VM image. vm/run reads this file, and so does
# vm/guest/provision.sh inside the VM. Changing anything here (or in
# provision.sh) makes vm/run prepare a new image.
#
# Every download is checked against the checksum its publisher posts next
# to it.

# The Debian 13 (trixie) cloud image, a dated build from
# https://cloud.debian.org/images/cloud/trixie/. Debian keeps dated builds
# for some months; when this one is gone, pick a newer one from that page.
DEBIAN_BUILD=20261001-2618

# Tools installed into the image.
KIND_VERSION=v0.33.0
# The node image this kind release was built for (from its release notes).
KIND_NODE_IMAGE=kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5
KUBECTL_VERSION=v1.37.1
HELM_VERSION=v4.3.0
UV_VERSION=0.12.22
# The same Rust as deploy/Dockerfile and the test images.
RUST_VERSION=1.92.0
