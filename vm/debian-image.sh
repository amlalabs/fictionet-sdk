# Debian image identity shared by vm/run and tests/vm/common.sh.
# Debian keeps dated builds for some months. To update, pick a build from
# https://cloud.debian.org/images/cloud/trixie/ and copy its SHA512SUMS entry.
DEBIAN_BUILD=20261001-2618
DEBIAN_IMAGE_NAME="debian-13-genericcloud-amd64-$DEBIAN_BUILD.qcow2"
DEBIAN_IMAGE_URL="https://cloud.debian.org/images/cloud/trixie/$DEBIAN_BUILD/$DEBIAN_IMAGE_NAME"
DEBIAN_IMAGE_SHA512=f46f0671a6e5bdec5291ab8972bae2f10e5408c2f64a74078f11efc2f06a436a9d0313ed50e0472542eeabf780e9f7c792ac0a314c6c20507fcd9fd81b468c3d
