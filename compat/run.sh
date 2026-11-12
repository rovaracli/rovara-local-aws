#!/usr/bin/env bash
# Compatibility suite and release gates for Rovara local AWS.
#
#   compat/run.sh [native|jvm]
#
# Starts three instances on loopback with the connect guard loaded (compat/netgate), runs the SDK suites
# (boto3, AWS SDK for JavaScript v3, AWS SDK for Java v2, AWS SDK for Go v2 when `go` exists) and the
# 54-call matrix, then checks:
#   * network silence: the guard logged no attempt to reach a non-loopback address (and blocked it);
#   * listening sockets: each instance listens on 127.0.0.1 and its one API port only.
# Exit code 0 only when every suite passes and both checks hold.
#
# Environment:
#   COMPAT_PYTHON       python with boto3 (required)
#   COMPAT_NODE_MODULES a node_modules directory holding @aws-sdk/client-* (JS suite skipped when unset)
#   COMPAT_NODE         directory holding the node binary (default: node on PATH)
#   COMPAT_CMD          launch command, overriding the default for the mode
#   MAVEN_REPO_LOCAL    scratch Maven repository for the Java suite's classpath
#   COMPAT_OUT          results directory (default compat/out)
set -uo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"
MODE="${1:-native}"
OUT="${COMPAT_OUT:-$ROOT/compat/out}"
: "${COMPAT_PYTHON:?set COMPAT_PYTHON to a python with boto3}"
mkdir -p "$OUT"
rm -f "$OUT"/*.json "$OUT"/*.log

export DOCKER_HOST=unix:///nonexistent AWS_EC2_METADATA_DISABLED=true
export AWS_SHARED_CREDENTIALS_FILE=/dev/null AWS_CONFIG_FILE=/dev/null
unset AWS_PROFILE AWS_SESSION_TOKEN AWS_ENDPOINT_URL

case "$MODE" in
  native) DEFAULT_CMD="$(ls "$ROOT"/target/rovara-local-aws-*-runner 2>/dev/null | head -1)" ;;
  jvm)    DEFAULT_CMD="java -XX:+UseSerialGC -jar $ROOT/target/quarkus-app/quarkus-run.jar" ;;
  *) echo "mode must be native or jvm" >&2; exit 2 ;;
esac
CMD="${COMPAT_CMD:-$DEFAULT_CMD}"
[ -n "$CMD" ] || { echo "no build found for mode $MODE; run scripts/build.sh first" >&2; exit 2; }

# ---- the connect guard ----
GUARD_DIR="$ROOT/compat/netgate/build"
mkdir -p "$GUARD_DIR"
if [ "$(uname)" = "Darwin" ]; then
  GUARD="$GUARD_DIR/connect_guard.dylib"; PRELOAD_VAR=DYLD_INSERT_LIBRARIES
  clang -dynamiclib -o "$GUARD" compat/netgate/connect_guard.c || exit 2
else
  GUARD="$GUARD_DIR/connect_guard.so"; PRELOAD_VAR=LD_PRELOAD
  cc -shared -fPIC -o "$GUARD" compat/netgate/connect_guard.c -ldl || exit 2
fi
export ROVARA_NETGUARD_LOG="$OUT/netguard.log" ROVARA_NETGUARD_BLOCK=1

free_port() { "$COMPAT_PYTHON" -I -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])'; }
P1=$(free_port); P2=$(free_port); P3=$(free_port)
TOKEN2="ct$(date +%s)$RANDOM"
PIDS=()
start() {  # port, label, extra env...
  local port="$1" label="$2"; shift 2
  ( cd "$OUT" && exec env "$PRELOAD_VAR=$GUARD" ROVARA_AWS_PORT="$port" QUARKUS_HTTP_PORT="$port" \
      ROVARA_AWS_BASE_URL="http://127.0.0.1:$port" "$@" $CMD > "$OUT/$label.log" 2>&1 ) &
  PIDS+=("$!")
  for _ in $(seq 1 200); do curl -sf "http://127.0.0.1:$port/_rovara/health" >/dev/null && return 0; sleep 0.1; done
  echo "instance $label did not start; see $OUT/$label.log" >&2; return 1
}
cleanup() { for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done; }
trap cleanup EXIT

# main: the control paths are open on purpose (the explicit development switch); validated: behind a token;
# closed: neither token nor switch, so every control path must answer 403 (FORK-CTRL-1).
start "$P1" main ROVARA_AWS_DEV_OPEN_CONTROL=1 || exit 2
# a token means a run, so the run contract applies: both secrets set explicitly (the base URL is set by start)
start "$P2" validated ROVARA_AWS_AUTH_VALIDATE_SIGNATURES=true ROVARA_AWS_CONTROL_TOKEN="$TOKEN2" \
  ROVARA_AWS_AUTH_PRESIGN_SECRET="presign-$TOKEN2-$RANDOM" ROVARA_AWS_SERVICES_SQS_RECEIPT_HANDLE_SECRET="receipt-$TOKEN2-$RANDOM" || exit 2
start "$P3" closed || exit 2
EP1="http://127.0.0.1:$P1"; EP2="http://127.0.0.1:$P2"; EP3="http://127.0.0.1:$P3"
FAIL=0

# ---- connection sampler: a second line of defence, and the only one for a binary that refuses the guard ----
( while kill -0 "${PIDS[0]}" 2>/dev/null; do
    for p in "${PIDS[@]}"; do
      lsof -nP -a -p "$p" -i -Fn 2>/dev/null | grep '^n' | grep -- '->' | sed 's/^n//' | \
        grep -Ev -- '->(127\.0\.0\.1|\[::1\]|localhost):' | sed 's/^/sampled /'
    done >> "$OUT/netsample.log"
    sleep 0.3
  done ) &
CONN_SAMPLER=$!
# ---- RSS sampler for the main instance ----
( while kill -0 "${PIDS[0]}" 2>/dev/null; do ps -o rss= -p "${PIDS[0]}" 2>/dev/null; sleep 0.2; done ) > "$OUT/rss.log" &
SAMPLER=$!

echo "== boto3 =="
"$COMPAT_PYTHON" -I compat/python/run_boto3.py --endpoint "$EP1" --validated-endpoint "$EP2" \
  --validated-control-token "$TOKEN2" --closed-endpoint "$EP3" --out "$OUT/boto3.json" || FAIL=1

echo "== 54-call matrix =="
"$COMPAT_PYTHON" -I perf/matrix.py compat "$EP1" "$OUT/matrix.json" > "$OUT/matrix.log" 2>&1
PASSED=$("$COMPAT_PYTHON" -I -c 'import json,sys;d=json.load(open(sys.argv[1]))["results"];print(sum(1 for r in d if r["status"]=="PASS"), len(d))' "$OUT/matrix.json")
echo "matrix: $PASSED passed (need at least 52 of 54)"
[ "${PASSED%% *}" -ge 52 ] || FAIL=1

echo "== AWS SDK for JavaScript v3 =="
if [ -n "${COMPAT_NODE_MODULES:-}" ]; then
  NODE="${COMPAT_NODE:+$COMPAT_NODE/}node"
  NODE_PATH="$COMPAT_NODE_MODULES" COMPAT_ENDPOINT="$EP1" COMPAT_VALIDATED_ENDPOINT="$EP2" \
    "$NODE" --test compat/node/compat.test.js > "$OUT/node.log" 2>&1 || FAIL=1
  grep -E "^# (pass|fail)" "$OUT/node.log"
else
  echo "js: not run (set COMPAT_NODE_MODULES)"
fi

echo "== AWS SDK for Java v2 =="
JAVA_CP="$OUT/java-classpath.txt"
MVN=(./mvnw -B -o -q); [ -n "${MAVEN_REPO_LOCAL:-}" ] && MVN+=("-Dmaven.repo.local=$MAVEN_REPO_LOCAL")
if "${MVN[@]}" dependency:build-classpath "-Dmdep.outputFile=$JAVA_CP" -Dmdep.includeScope=test > "$OUT/java-cp.log" 2>&1; then
  ( env -u "$PRELOAD_VAR" java -cp "$(cat "$JAVA_CP")" compat/java/Compat.java "$EP1" "$EP2" ) > "$OUT/java.log" 2>&1 || FAIL=1
  grep -E "^\[java-sdk-v2\]" "$OUT/java.log" | tail -n +1 | grep -E "fail|passed"
else
  echo "java: not run (could not build the classpath offline; see $OUT/java-cp.log)"
fi

echo "== AWS SDK for Go v2 =="
if command -v go >/dev/null 2>&1; then
  ( cd compat/go && COMPAT_ENDPOINT="$EP1" go test ./... ) > "$OUT/go.log" 2>&1 || FAIL=1
  tail -3 "$OUT/go.log"
else
  echo "go: not run (no Go toolchain on this machine)"
fi

# ---- gates ----
kill "$SAMPLER" "$CONN_SAMPLER" 2>/dev/null; wait "$SAMPLER" "$CONN_SAMPLER" 2>/dev/null
echo "== listening sockets =="
for i in 0 1 2; do
  PID="${PIDS[$i]}"
  LISTEN=$(lsof -nP -a -p "$PID" -iTCP -sTCP:LISTEN -Fn 2>/dev/null | grep '^n' | sort -u)
  PORT=$([ "$i" = 0 ] && echo "$P1" || { [ "$i" = 1 ] && echo "$P2" || echo "$P3"; })
  if [ "$LISTEN" = "n127.0.0.1:$PORT" ]; then echo "pid $PID: listens only on 127.0.0.1:$PORT"; else echo "FAIL pid $PID listens on: $LISTEN"; FAIL=1; fi
done

echo "== network silence =="
# the guard must really be inside both emulator processes, and must see an outbound attempt when one is made
GUARD_LOADED=1
for i in 0 1 2; do
  if ! { lsof -p "${PIDS[$i]}" 2>/dev/null | grep -q connect_guard || grep -q connect_guard "/proc/${PIDS[$i]}/maps" 2>/dev/null; }; then
    GUARD_LOADED=0
  fi
done
if [ "$GUARD_LOADED" = 0 ]; then
  if [ "$MODE" = native ]; then
    echo "FAIL: the connect guard is not loaded in the native binary"; FAIL=1
  else
    echo "note: this launcher is signed with the hardened runtime and drops the guard; only connection sampling covers $MODE mode"
  fi
fi
SELF_LOG="$OUT/netguard-selftest.log"; rm -f "$SELF_LOG"
cc -o "$GUARD_DIR/selftest" compat/netgate/selftest.c && \
  env ROVARA_NETGUARD_LOG="$SELF_LOG" "$PRELOAD_VAR=$GUARD" "$GUARD_DIR/selftest"
if grep -q '^connect 192.0.2.1:9' "$SELF_LOG" 2>/dev/null; then echo "guard self-test: a deliberate outbound attempt was recorded"; else echo "FAIL: the guard did not record a deliberate outbound attempt"; FAIL=1; fi
cat "$OUT/netguard.log" "$OUT/netsample.log" > "$OUT/netwatch.log" 2>/dev/null
if [ -s "$OUT/netwatch.log" ]; then
  echo "FAIL: non-loopback attempts were recorded:"; sort "$OUT/netwatch.log" | uniq -c | head; FAIL=1
else
  echo "no attempt to reach a non-loopback address (connect guard: $([ "$GUARD_LOADED" = 1 ] && echo loaded || echo not loaded); connections sampled every 0.3 s)"
fi
PEAK=$(sort -n "$OUT/rss.log" | tail -1)
echo "peak RSS of the main instance: $(( ${PEAK:-0} / 1024 )) MiB"
[ "$FAIL" = 0 ] && echo "COMPAT OK" || echo "COMPAT FAILED"
exit "$FAIL"
