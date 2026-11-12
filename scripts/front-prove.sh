#!/usr/bin/env bash
# Proves the front against the real AWS Emulator, on Linux (the colima VM), in an environment shaped like the Cloud worker's
# container: user 10001, a read-only root, a 64 MiB noexec /tmp tmpfs, a memory limit of 512 MiB, 512 pids, one CPU (these
# three limits are on the front's own cgroup scope, so the test client does not share them), and a network namespace that
# has only loopback and one dummy address (no route out at all).
#
#   scripts/front-prove.sh                 builds the front, then runs every phase
#   FRONT_BIN=<binary> ENGINE_BIN=<aws-emulator> COMPAT_PYTHON=<python with boto3> scripts/front-prove.sh
#
# Phases (each writes into $OUT, default /tmp/front-prove-out):
#   worker   the front as the worker starts it (token, run address 10.99.0.2, secrets, services switched off); then
#            front/tools/cloud_worker_sim.py plays the worker: health, seed, ledger summary, reset
#   measure  start-to-healthy time, private memory (front + engine) idle and at peak while the 54-call matrix runs, median
#            call, and every outbound connection of the two processes sampled every 50 ms
#   compat   the fork's own boto3 suite (all groups, three instances: main with a token, a second tokened one, a closed one)
#            and the matrix, against the front
# Needs sudo (namespaces and a cgroup scope) and a Linux kernel with cgroup v2; never touches Docker or any other VM state.
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${OUT:-/tmp/front-prove-out}"
PY="${PY:-${COMPAT_PYTHON:-}}"
[ -n "$PY" ] || { echo "set COMPAT_PYTHON to a python with boto3"; exit 2; }
ENGINE_BIN="${ENGINE_BIN:-/opt/aws-emulator/bin/aws-emulator}"
INSTALL=/usr/local/bin/rovara-aws-front
RUN_UID=10001

if [ "${1:-}" = inner ]; then
  # ---- inside the namespaces: root, new mount and net namespace, in a cgroup scope ----
  PHASE="$2"
  mount --make-rprivate /
  mount --bind / / && mount -o remount,ro,bind /
  mount -t tmpfs -o size=64m,mode=1777,noexec,nosuid,nodev tmpfs /tmp
  ip link set lo up
  ip link add dummy0 type dummy && ip addr add 10.99.0.2/24 dev dummy0 && ip link set dummy0 up
  mkdir -p "$OUT"; chmod 777 "$OUT"
  # the worker's env file (service-helpers.ts "local-aws" family) with throwaway values
  TOKEN="tk$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n' | head -c 24)"
  PRESIGN="ps$(head -c 20 /dev/urandom | od -An -tx1 | tr -d ' \n' | head -c 20)"
  RECEIPT="rc$(head -c 20 /dev/urandom | od -An -tx1 | tr -d ' \n' | head -c 20)"
  KEEP="s3,sqs,dynamodb"
  OFF=""
  for k in ssm sqs s3 dynamodb sns lambda apigateway apigatewayv2 iam eventbridge eventbridgev2 cloudwatchlogs secretsmanager kinesis kms cognito stepfunctions sagemaker; do
    case ",$KEEP," in *",$k,"*) ;; *) OFF="$OFF ROVARA_AWS_SERVICES_$(echo "$k" | tr '[:lower:]' '[:upper:]')_ENABLED=false";; esac
  done
  start_front() { # <bind host> <port> [extra env...]; writes $OUT/front.pid, returns after spawn
    local host="$1" port="$2"; shift 2
    date +%s.%N > "$OUT/spawned-at"
    # shellcheck disable=SC2086
    systemd-run --scope --quiet --collect -p MemoryMax=512M -p MemorySwapMax=0 -p TasksMax=512 -p CPUQuota=100% -- \
    setpriv --reuid=$RUN_UID --regid=$RUN_UID --clear-groups --no-new-privs \
      env -i HOME=/tmp QUARKUS_HTTP_HOST="$host" QUARKUS_HTTP_PORT="$port" ROVARA_AWS_BASE_URL=http://aws:4566 \
        ROVARA_AWS_AUTH_PRESIGN_SECRET="$PRESIGN" ROVARA_AWS_SERVICES_SQS_RECEIPT_HANDLE_SECRET="$RECEIPT" ROVARA_AWS_CONTROL_TOKEN="$TOKEN" \
        ROVARA_AWS_DEFAULT_REGION=us-east-1 ROVARA_AWS_HOSTNAME=aws ROVARA_AWS_ENGINE_BIN="$ENGINE_BIN" ROVARA_AWS_FRONT_WORKDIR=/tmp "$@" \
        "$INSTALL" > "$OUT/front-$port.log" 2>&1 &
    echo $! > "$OUT/front.pid"
  }
  as_user() { setpriv --reuid="$SUDO_UID" --regid="$SUDO_GID" --init-groups --reset-env "$@"; }
  sample_net() { # <file>: every socket of the front and its engine, every 50 ms, until the front is gone
    local fpid; fpid="$(cat "$OUT/front.pid")"
    while kill -0 "$fpid" 2>/dev/null; do
      epids="$(pgrep -P "$fpid" | tr '\n' '|')"
      ss -tanpH 2>/dev/null | grep -E "pid=($fpid${epids:+|${epids%|}})," >> "$1" || true
      sleep 0.05
    done
  }
  case "$PHASE" in
    worker)
      # shellcheck disable=SC2086
      start_front 10.99.0.2 4566 $OFF
      for _ in $(seq 1 100); do curl -sf "http://10.99.0.2:4566/_rovara/health" >/dev/null && break; sleep 0.1; done
      echo "--- worker environment: uid $(ps -o uid= -p "$(cat "$OUT/front.pid")" | tr -d ' '), root mounted $(awk '$2=="/" {print $4}' /proc/self/mounts | head -1 | cut -d, -f1), /tmp $(awk '$2=="/tmp" {print $3, $4}' /proc/self/mounts)"
      echo "--- listening: $(ss -tlnpH | grep -E '4566' | awk '{print $4}' | tr '\n' ' ')"
      as_user "$PY" -I "$HERE/front/tools/cloud_worker_sim.py" --host 10.99.0.2 --port 4566 --token "$TOKEN" --alias aws \
        --disabled "$(echo "$OFF" | tr ' ' '\n' | sed -n 's/^ROVARA_AWS_SERVICES_\(.*\)_ENABLED=false$/\1/p' | tr '[:upper:]' '[:lower:]' | sed 's/^eventbridgev2$/eventsv2/;s/^eventbridge$/events/;s/^cloudwatchlogs$/logs/;s/^stepfunctions$/states/;s/^cognito$/cognito-idp/' | paste -sd,)"
      rc=$?
      echo "--- processes: $(pgrep -P "$(cat "$OUT/front.pid")" | wc -l) child; the engine's directory under /tmp: $(find /tmp -mindepth 1 -maxdepth 1 -printf '%f ')"
      kill "$(cat "$OUT/front.pid")"; sleep 1; echo "--- after SIGTERM, /tmp holds: $(find /tmp -mindepth 1 -maxdepth 1 -printf '%f ')"
      exit $rc ;;
    measure)
      start_front 127.0.0.1 4566
      : > "$OUT/netsample.log"
      sleep 0.2; sample_net "$OUT/netsample.log" &
      as_user "$PY" -I "$HERE/front/tools/measure_front.py" --pidfile "$OUT/front.pid" --spawned-at "$(cat "$OUT/spawned-at")" \
        --endpoint http://127.0.0.1:4566 --python "$PY" --matrix "$HERE/perf/matrix.py" --out "$OUT/measure.json"
      rc=$?
      kill "$(cat "$OUT/front.pid")"; wait
      echo "--- network: sockets seen for the front and its engine (distinct local -> remote pairs, listeners and accepted connections not counted as outbound)"
      awk '{print $1, $4, $5}' "$OUT/netsample.log" | sort -u | awk '{ n=split($3,r,":"); l=$2; sub(/.*:/,"",l); print $0 }' > "$OUT/netsample.distinct"
      out_conn="$(awk '$1!="LISTEN" {print $3}' "$OUT/netsample.distinct" | sed 's/:[0-9]*$//' | sort -u | tr '\n' ' ')"
      echo "remote addresses of every connection the two processes had: ${out_conn:-none}"
      echo "listening sockets: $(awk '$1=="LISTEN" {print $2}' "$OUT/netsample.distinct" | sort -u | tr '\n' ' ')"
      bad="$(awk '$1!="LISTEN" {print $3}' "$OUT/netsample.distinct" | sed 's/:[0-9]*$//' | grep -v '^127\.0\.0\.1$' | sort -u | tr '\n' ' ')"
      if [ -n "${bad// /}" ]; then echo "FAIL: connections to $bad"; rc=1; else echo "ok: every connection stayed on 127.0.0.1 ($(wc -l < "$OUT/netsample.log") samples)"; fi
      exit $rc ;;
    compat)
      for spec in "14580 main" "14581 valid" "14582 closed"; do
        read -r wport _ <<<"$spec"
        mkdir -p "/tmp/w$wport"; chown "$RUN_UID" "/tmp/w$wport"
      done
      T1="ctmain$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')"; T2="ctvalid$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')"
      launch() { # port workdir extra env...
        local port="$1" wd="$2"; shift 2
        setpriv --reuid=$RUN_UID --regid=$RUN_UID --clear-groups --no-new-privs \
          env -i HOME=/tmp QUARKUS_HTTP_HOST=127.0.0.1 QUARKUS_HTTP_PORT="$port" ROVARA_AWS_BASE_URL="http://127.0.0.1:$port" \
            ROVARA_AWS_ENGINE_BIN="$ENGINE_BIN" ROVARA_AWS_FRONT_WORKDIR="$wd" "$@" "$INSTALL" > "$OUT/front-$port.log" 2>&1 &
        for _ in $(seq 1 100); do curl -sf "http://127.0.0.1:$port/_rovara/health" >/dev/null && return 0; sleep 0.1; done
        echo "front $port did not start"; cat "$OUT/front-$port.log"; return 1
      }
      launch 14580 /tmp/w14580 ROVARA_AWS_CONTROL_TOKEN="$T1" ROVARA_AWS_AUTH_PRESIGN_SECRET="presign-$T1-xx" ROVARA_AWS_SERVICES_SQS_RECEIPT_HANDLE_SECRET="receipt-$T1-xx" || exit 2
      launch 14581 /tmp/w14581 ROVARA_AWS_CONTROL_TOKEN="$T2" ROVARA_AWS_AUTH_PRESIGN_SECRET="presign-$T2-xx" ROVARA_AWS_SERVICES_SQS_RECEIPT_HANDLE_SECRET="receipt-$T2-xx" || exit 2
      launch 14582 /tmp/w14582 || exit 2
      cd "$HERE" || exit 2
      as_user "$PY" -I compat/python/run_boto3.py --endpoint http://127.0.0.1:14580 --control-token "$T1" --validated-endpoint http://127.0.0.1:14581 \
        --validated-control-token "$T2" --closed-endpoint http://127.0.0.1:14582 --out "$OUT/boto3-front.json" > "$OUT/boto3-front.log" 2>&1
      grep -v ' pass ' "$OUT/boto3-front.log" | cut -c1-200
      as_user "$PY" -I perf/matrix.py compat http://127.0.0.1:14580 "$OUT/matrix-front.json" > "$OUT/matrix-front.log" 2>&1
      tail -1 "$OUT/matrix-front.log" | cut -c1-200
      pkill -TERM -f "$INSTALL"; sleep 1
      exit 0 ;;
  esac
  exit 0
fi

# ---- outer: build, install, and re-enter in the scope and namespaces ----
command -v go >/dev/null || { echo "go is required"; exit 2; }
BUILD="$(mktemp -d)"
( cd "$HERE/front" && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=prove" -o "$BUILD/rovara-aws-front" . ) || exit 2
sudo install -m 0755 "$BUILD/rovara-aws-front" "$INSTALL"
export OUT PY ENGINE_BIN INSTALL RUN_UID
rc=0
for phase in ${PHASES:-worker measure compat}; do
  echo "=================== phase: $phase"
  sudo --preserve-env=OUT,PY,ENGINE_BIN,INSTALL,RUN_UID \
    unshare --mount --net --propagation private -- bash "$HERE/scripts/front-prove.sh" inner "$phase" || rc=1
done
sudo rm -f "$INSTALL"
exit $rc
