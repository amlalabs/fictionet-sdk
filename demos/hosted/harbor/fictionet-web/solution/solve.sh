#!/bin/bash
# The oracle: what a good agent does.
set -euo pipefail
solve() {
    local answer=$1 curl=$2
    mkdir -p "$(dirname "$answer")"
    "$curl" -sS --fail --cacert /run/ca/ca.pem https://example.test/challenge > "$answer"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    solve /app/answer.txt curl
fi
