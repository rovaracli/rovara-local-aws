#!/usr/bin/env bash
# Speed gate. Measures a build and fails on any target miss:
#   start-up to first answer <= 0.5 s, idle private memory <= 64 MiB, peak private memory <= 128 MiB during the
#   54-call matrix (private = RssAnon from /proc on Linux, the physical footprint from `footprint` on macOS; total RSS is
#   printed and recorded beside it as information and never fails the gate, see perf/RESULTS.md), matrix passes at least 52 of 54. The median call (3 ms) is REPORT-ONLY since 2026-11-03
#   (owner): a miss prints a WARNING and is recorded, but does not fail the gate.
#
# Usage: scripts/perf-gate.sh [native|jvm]            (default native)
# Env:   ROVARA_PERF_PYTHON  python with boto3 (required)
#        ROVARA_PERF_RUNS    runs to take the median/peak over (default 3)
#        ROVARA_PERF_CMD     launch command, to override the default for the mode
#        ROVARA_PERF_OUT     result file (default perf/out/<mode>.json)
#        ROVARA_PERF_REPORT_ONLY=1  record every verdict, never fail (for emulated CPUs, where the numbers mean nothing)
set -euo pipefail
cd "$(dirname "$0")/.."
MODE="${1:-native}"
: "${ROVARA_PERF_PYTHON:?set ROVARA_PERF_PYTHON to a python with boto3 installed}"
# The default build is looked up only when ROVARA_PERF_CMD is not given: with pipefail a missing target/ makes the
# `ls` fail and ended the script silently (exit 2) before the override was read.
if [ -n "${ROVARA_PERF_CMD:-}" ]; then
  CMD="$ROVARA_PERF_CMD"
else
  case "$MODE" in
    native) CMD="$(ls target/rovara-local-aws-*-runner 2>/dev/null | head -1 || true)" ;;
    jvm)    CMD="java -XX:+UseSerialGC -Xshare:auto -jar target/quarkus-app/quarkus-run.jar" ;;
    *) echo "mode must be native or jvm" >&2; exit 2 ;;
  esac
fi
[ -n "$CMD" ] || { echo "no build found for mode $MODE; run scripts/build.sh first" >&2; exit 2; }
OUT="${ROVARA_PERF_OUT:-perf/out/$MODE.json}"
mkdir -p "$(dirname "$OUT")"
EXTRA=()
[ "${ROVARA_PERF_REPORT_ONLY:-0}" = 1 ] && EXTRA+=(--report-only)
export DOCKER_HOST=unix:///nonexistent AWS_EC2_METADATA_DISABLED=true
exec python3 -I perf/measure.py --label "$MODE" --cmd "$CMD" --python "$ROVARA_PERF_PYTHON" \
  --runs "${ROVARA_PERF_RUNS:-3}" --out "$OUT" --check ${EXTRA[@]+"${EXTRA[@]}"}
