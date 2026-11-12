#!/usr/bin/env bash
# Starts a real build (the JVM jar, or the native binary, or any command that runs the emulator) several times and
# checks the control-path rules over real HTTP. No Docker, no network beyond loopback.
#
#   scripts/control-check.sh java -XX:+UseSerialGC -jar target/quarkus-app/quarkus-run.jar
#   scripts/control-check.sh dist/native/rovara-local-aws
#
# Cases (each starts its own process on a free loopback port):
#   closed     no token, no switch: every /_rovara/* control path answers 403; health 200; a virtual-host name
#              (X-Forwarded-Host: _rovara.localhost) does not reach the ledger or reset
#   dev        ROVARA_AWS_DEV_OPEN_CONTROL=1: control paths answer 200
#   dev-true   ROVARA_AWS_DEV_OPEN_CONTROL=true: still closed (exactly 1 only)
#   token      a control token with the run contract met: 403 without or with a wrong header, 200 with the token
#   contract   a control token WITHOUT the base URL and secrets: the process refuses to start (exits non-zero) and
#              nothing listens
# Exit 0 only when every case holds. Tokens and secrets are built at run time.
set -uo pipefail
[ $# -ge 1 ] || { echo "usage: $0 <command that starts the emulator>" >&2; exit 2; }
CMD=("$@")
WORK="$(mktemp -d "${TMPDIR:-/tmp}/control-check.XXXXXX")"
PID=""
cleanup() { [ -n "$PID" ] && kill "$PID" 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT
export DOCKER_HOST=unix:///nonexistent AWS_EC2_METADATA_DISABLED=true
FAIL=0
bad() { echo "FAIL: $*"; FAIL=1; }
good() { echo "ok:   $*"; }

free_port() { python3 -I -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])'; }
rand() { python3 -I -c 'import secrets;print(secrets.token_hex(16))'; }
code() { curl -s -o "$WORK/body" -w '%{http_code}' --max-time 10 "$@"; }

start() {  # label, env...   -> sets PORT and PID; returns 1 when it never answered health
  local label="$1"; shift
  PORT="$(free_port)"
  env "$@" ROVARA_AWS_PORT="$PORT" QUARKUS_HTTP_PORT="$PORT" "${CMD[@]}" > "$WORK/$label.log" 2>&1 &
  PID=$!
  for _ in $(seq 1 300); do
    curl -sf --max-time 2 "http://127.0.0.1:$PORT/_rovara/health" >/dev/null 2>&1 && return 0
    kill -0 "$PID" 2>/dev/null || return 1
    sleep 0.2
  done
  return 1
}
stop() { [ -n "$PID" ] && kill "$PID" 2>/dev/null; wait "$PID" 2>/dev/null; PID=""; }
expect() {  # description expected-code actual-code
  if [ "$2" = "$3" ]; then good "$1 -> $3"; else bad "$1: expected $2, got $3"; fi
}
expect_in() {  # description actual-code allowed...
  local d="$1" a="$2"; shift 2
  for x in "$@"; do [ "$a" = "$x" ] && { good "$d -> $a"; return; }; done
  bad "$d: got $a, expected one of $*"
}
BASE() { echo "http://127.0.0.1:$PORT"; }

echo "== closed (no token, no switch) =="
if start closed ROVARA_AWS_BASE_URL="http://127.0.0.1:0"; then
  for rq in "POST /_rovara/reset" "POST /_rovara/seed" "GET /_rovara/ledger" "DELETE /_rovara/ledger" "POST /_rovara/tick/all" "POST /_rovara/state/reset" "GET /_rovara/sqs/messages"; do
    expect "$rq" 403 "$(code -X "${rq% *}" "$(BASE)${rq#* }")"
  done
  expect "GET /_rovara/health" 200 "$(code "$(BASE)/_rovara/health")"
  for host in _rovara.localhost _rovara.s3.localhost; do
    expect_in "DELETE /ledger as $host (X-Forwarded-Host)" "$(code -X DELETE -H "X-Forwarded-Host: $host" "$(BASE)/ledger")" 400 403 404
    expect_in "POST /reset as $host (Host)" "$(code -X POST -H "Host: $host" "$(BASE)/reset")" 400 403 404
  done
else bad "closed: the process did not start; see $WORK/closed.log"; tail -5 "$WORK/closed.log"; fi
stop

echo "== dev (ROVARA_AWS_DEV_OPEN_CONTROL=1) =="
if start dev ROVARA_AWS_DEV_OPEN_CONTROL=1; then
  expect "POST /_rovara/reset" 200 "$(code -X POST "$(BASE)/_rovara/reset")"
  expect "GET /_rovara/ledger" 200 "$(code "$(BASE)/_rovara/ledger")"
  grep -q 'DEVELOPMENT SWITCH ON' "$WORK/dev.log" && good "one WARN line announces the switch" || bad "no start-up WARN line for the switch"
else bad "dev: the process did not start"; fi
stop

echo "== dev-true (ROVARA_AWS_DEV_OPEN_CONTROL=true is not 1) =="
if start devtrue ROVARA_AWS_DEV_OPEN_CONTROL=true; then
  expect "POST /_rovara/reset" 403 "$(code -X POST "$(BASE)/_rovara/reset")"
else bad "dev-true: the process did not start"; fi
stop

echo "== token (run contract met) =="
T="$(rand)"
if start token ROVARA_AWS_CONTROL_TOKEN="$T" ROVARA_AWS_BASE_URL="http://aws:4566" \
     ROVARA_AWS_AUTH_PRESIGN_SECRET="$(rand)" ROVARA_AWS_SERVICES_SQS_RECEIPT_HANDLE_SECRET="$(rand)"; then
  expect "POST /_rovara/reset without a header" 403 "$(code -X POST "$(BASE)/_rovara/reset")"
  expect "POST /_rovara/reset with a wrong token" 403 "$(code -X POST -H "X-Rovara-Control-Token: $(rand)" "$(BASE)/_rovara/reset")"
  expect "POST /_rovara/reset with the token" 200 "$(code -X POST -H "X-Rovara-Control-Token: $T" "$(BASE)/_rovara/reset")"
  expect "GET /_rovara/health" 200 "$(code "$(BASE)/_rovara/health")"
  expect_in "DELETE /ledger as _rovara.localhost, no header" "$(code -X DELETE -H "X-Forwarded-Host: _rovara.localhost" "$(BASE)/ledger")" 400 403 404
else bad "token: the process did not start; see $WORK/token.log"; tail -5 "$WORK/token.log"; fi
stop

echo "== contract (token without the base URL and secrets must not start) =="
if start contract ROVARA_AWS_CONTROL_TOKEN="$(rand)"; then
  bad "contract: a process with a token and the development defaults started"
else
  sleep 1
  if kill -0 "$PID" 2>/dev/null; then bad "contract: the process is still running"; else good "the process refused to start"; fi
  if grep -q 'ROVARA_AWS_BASE_URL' "$WORK/contract.log" && grep -q 'ROVARA_AWS_AUTH_PRESIGN_SECRET' "$WORK/contract.log" \
     && grep -q 'ROVARA_AWS_SERVICES_SQS_RECEIPT_HANDLE_SECRET' "$WORK/contract.log"; then good "the error names the three settings"; else bad "the error does not name the three settings"; tail -5 "$WORK/contract.log"; fi
  grep -q 'local-emulator-secret' "$WORK/contract.log" && bad "a secret value was printed"
  curl -sf --max-time 2 "http://127.0.0.1:$PORT/_rovara/health" >/dev/null 2>&1 && bad "something is listening" || good "nothing listens"
fi
PID=""

[ "$FAIL" = 0 ] && echo "CONTROL CHECK OK" || echo "CONTROL CHECK FAILED"
exit "$FAIL"
