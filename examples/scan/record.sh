#!/usr/bin/env bash
# Records the dashboard while nmap scans the scan example's subnet.
#
#   examples/scan/record.sh [out dir]
#
# Builds and starts the Docker Compose stack, records with Playwright and
# Chromium (record.py), converts the video to MP4 (H.264) and a GIF, and
# removes the stack again. Needs docker, uv and ffmpeg. Set CHROMIUM to a
# Chromium binary, or leave it unset to use Playwright's own.
#
# Environment: SCAN_PROJECT (compose project, default fn-scan-demo),
# SCAN_DASHBOARD_PORT (default 7880), KEEP=1 to leave the stack running.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
out=$(realpath -m "${1:-$here/recording}")
project=${SCAN_PROJECT:-fn-scan-demo}
export SCAN_DASHBOARD_PORT=${SCAN_DASHBOARD_PORT:-7880}
compose=(docker compose -p "$project" -f "$here/compose.yaml")

cleanup() { [ "${KEEP:-}" = 1 ] || "${compose[@]}" down -v --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT

"${compose[@]}" build
"${compose[@]}" up -d --wait
url="http://127.0.0.1:$SCAN_DASHBOARD_PORT/"
for _ in $(seq 50); do curl -fs "$url" >/dev/null && break; sleep 0.2; done

mkdir -p "$out"
uv run -q --with playwright python "$here/record.py" "$url" "$out" "${compose[@]}"

# H.264 for players and slides; a GIF at half size and 6 frames a second for pages and chats.
ffmpeg -v error -y -i "$out/dashboard.webm" -c:v libx264 -preset slow -crf 20 -pix_fmt yuv420p -movflags +faststart "$out/dashboard.mp4"
ffmpeg -v error -y -i "$out/dashboard.webm" \
  -vf "fps=6,scale=960:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=96:stats_mode=diff[p];[b][p]paletteuse=dither=none:diff_mode=rectangle" \
  "$out/dashboard.gif"
ls -l "$out"
