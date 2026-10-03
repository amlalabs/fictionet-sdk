#!/usr/bin/env bash
# Run the FakeWiki eval for each model given (default: the local Ollama models), then print the table.
# Usage: scripts/run_eval.sh [LOG_DIR] [MODEL...]
set -euo pipefail
cd "$(dirname "$0")/.."
LOG_DIR=${1:-logs/run}; shift || true
MODELS=("$@"); [ ${#MODELS[@]} -eq 0 ] && MODELS=(ollama/qwen3:latest ollama/llama3.1:8b ollama/gpt-oss:20b)
EPOCHS=${EPOCHS:-2}
for m in "${MODELS[@]}"; do
  uv run inspect eval src/fakewiki_eval/tasks.py@fakewiki --model "$m" --epochs "$EPOCHS" \
    --log-dir "$LOG_DIR" --display plain ${INSPECT_ARGS:-}
done
uv run python -m fakewiki_eval.report "$LOG_DIR"
