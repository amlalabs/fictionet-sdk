#!/usr/bin/env bash
# Runs every fuzz target for the given number of seconds (default 60), one
# after another, and reports the ones that failed at the end instead of
# stopping at the first. Needs nightly and cargo-fuzz; build first with
# `cargo +nightly fuzz build -O -a`. Extra arguments go to libFuzzer.
#
#   fuzz/run-all.sh 60 -timeout=20 -rss_limit_mb=4096
#
# Set FUZZ_TRIPLE=x86_64-unknown-linux-gnu where the default target is
# musl (see README.md).
set -uo pipefail
cd "$(dirname "$0")/.."

seconds=${1:-60}
shift || true

triple=()
[ -n "${FUZZ_TRIPLE:-}" ] && triple=(--target "$FUZZ_TRIPLE")

failed=()
for t in $(cargo +nightly fuzz list); do
  echo "::group::$t"
  # libFuzzer refuses a corpus directory that does not exist.
  mkdir -p "fuzz/corpus/$t"
  if ! cargo +nightly fuzz run -O -a "${triple[@]}" "$t" "fuzz/corpus/$t" -- -max_total_time="$seconds" "$@"; then
    echo "::error::fuzz target $t failed"
    failed+=("$t")
  fi
  echo "::endgroup::"
done

if [ ${#failed[@]} -ne 0 ]; then
  echo "${#failed[@]} fuzz target(s) failed: ${failed[*]}"
  exit 1
fi
echo "every fuzz target ran for ${seconds} s without a failure"
