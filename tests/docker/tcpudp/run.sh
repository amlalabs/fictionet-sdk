#!/bin/sh
# Runs tests/tun_linux.rs in a container, against the container's kernel.
# Builds the test binary in Docker (see the Dockerfile).
set -eu
root=$(cd "$(dirname "$0")/../../.." && pwd)
profile=${PROFILE:-release}
docker build -q -t fictionet-tcpudp-test --build-arg PROFILE="$profile" \
    -f "$root/tests/docker/tcpudp/Dockerfile" "$root" >/dev/null
docker run --rm --name fictionet-tcpudp-test-$$ --cap-add NET_ADMIN --device /dev/net/tun \
    --sysctl net.ipv6.conf.all.disable_ipv6=0 \
    ${FICTIONET_TRACE:+-e FICTIONET_TRACE=1} ${FICTIONET_ONLY_LOSS:+-e FICTIONET_ONLY_LOSS=1} fictionet-tcpudp-test /test --ignored --nocapture
