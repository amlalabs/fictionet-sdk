#!/usr/bin/env bash
# Checks that every target in fuzz_targets/ has a [[bin]] in Cargo.toml and a
# corpus directory, and that every [[bin]] has its source file. CI runs it;
# so can you, from anywhere.
set -euo pipefail
cd "$(dirname "$0")"

problems=0
bins=$(awk '/^\[\[bin\]\]/ { inbin = 1; next } /^\[/ { inbin = 0 } inbin && /^name *=/ { gsub(/.*= *"|".*/, ""); print }' Cargo.toml | sort)

for src in fuzz_targets/*.rs; do
  t=$(basename "$src" .rs)
  if ! grep -qx "$t" <<<"$bins"; then
    echo "fuzz target $t has no [[bin]] in fuzz/Cargo.toml"
    problems=$((problems + 1))
  fi
  if [ ! -d "corpus/$t" ]; then
    echo "fuzz target $t has no corpus directory (fuzz/corpus/$t)"
    problems=$((problems + 1))
  fi
done
for t in $bins; do
  if [ ! -f "fuzz_targets/$t.rs" ]; then
    echo "[[bin]] $t has no fuzz_targets/$t.rs"
    problems=$((problems + 1))
  fi
done

if [ "$problems" -ne 0 ]; then
  echo "$problems problem(s)"
  exit 1
fi
echo "$(wc -l <<<"$bins") fuzz targets, each with a [[bin]] and a corpus directory"
