#!/bin/bash
# The oracle: what a good agent does.
set -euo pipefail
answer="${ANSWER_PATH:-/app/answer.txt}"
mkdir -p "$(dirname "$answer")"
curl -sS --fail --cacert /run/ca/ca.pem https://example.test/challenge > "$answer"
