#!/usr/bin/env bash
# Build the world, attach, and agent from the SDK root.
set -euo pipefail
sdk_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)
for target in world attach agent; do
    docker build -f "$sdk_root/examples/artifactory/docker/Dockerfile" \
        --target "$target" -t "fictionet-artifactory-$target:dev" "$sdk_root"
done
