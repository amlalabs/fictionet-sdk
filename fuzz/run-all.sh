#!/usr/bin/env bash
# Runs each selected fuzz target for the given number of seconds (default
# 60), one after another, and reports the ones that failed at the end
# instead of stopping at the first. Needs nightly and cargo-fuzz; each
# selected target is built before running. Extra arguments go to libFuzzer.
# Fails if target discovery fails or returns no targets. FUZZ_SHARD_INDEX
# (default 0) selects one of FUZZ_SHARD_COUNT shards (default 1). Targets are
# sorted in C locale and assigned round-robin, starting at shard 0.
#
#   fuzz/run-all.sh 60 -timeout=20 -rss_limit_mb=4096
#
# Set FUZZ_TRIPLE=x86_64-unknown-linux-gnu where the default target is
# musl (see README.md).
set -uo pipefail
cd "$(dirname "$0")/.."

seconds=${1:-60}
shift || true

shard_index=${FUZZ_SHARD_INDEX-0}
shard_count=${FUZZ_SHARD_COUNT-1}
# Bound decimal inputs before shell arithmetic to reject overflow and expressions.
if [[ ! "$shard_index" =~ ^(0|[1-9][0-9]{0,8})$ ||
      ! "$shard_count" =~ ^[1-9][0-9]{0,8}$ ]]; then
  echo "::error::FUZZ_SHARD_INDEX and FUZZ_SHARD_COUNT must be decimal integers in 0..999999999 and 1..999999999" >&2
  exit 1
fi
if (( shard_index >= shard_count )); then
  echo "::error::FUZZ_SHARD_INDEX must be less than FUZZ_SHARD_COUNT" >&2
  exit 1
fi

triple=()
[ -n "${FUZZ_TRIPLE:-}" ] && triple=(--target "$FUZZ_TRIPLE")

if ! targets=$(cargo +nightly fuzz list); then
  echo "::error::fuzz target discovery failed" >&2
  exit 1
fi
if [[ -z "${targets//[[:space:]]/}" ]]; then
  echo "::error::fuzz target discovery returned no targets" >&2
  exit 1
fi

if ! targets=$(printf '%s\n' "$targets" | LC_ALL=C sort); then
  echo "::error::fuzz target sorting failed" >&2
  exit 1
fi
failed=()
position=0
for t in $targets; do
  selected=$((position % shard_count))
  position=$((position + 1))
  (( selected == shard_index )) || continue
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
echo "every fuzz target in shard $shard_index/$shard_count ran for ${seconds} s without a failure"
