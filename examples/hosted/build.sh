#!/usr/bin/env bash
# Builds fictionet and web_world for Debian bookworm with the crate's own
# Docker test image, and copies them into bin/ here and into the Harbor
# task's environment, for the Dockerfiles that use them.
#
#   examples/hosted/build.sh
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
docker build -q -f "$root/tests/docker/web/Dockerfile" --target runtime -t fictionet-hosted-build:dev "$root" >/dev/null
id="$(docker create fictionet-hosted-build:dev)"
trap 'docker rm "$id" >/dev/null' EXIT
for dir in "$here/bin" "$here/harbor/fictionet-web/environment/bin"; do
    mkdir -p "$dir"
    docker cp -q "$id:/usr/local/bin/fictionet" "$dir/"
    docker cp -q "$id:/usr/local/bin/web_world" "$dir/"
done
ls -l "$here/bin"
