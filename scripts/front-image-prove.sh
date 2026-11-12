#!/usr/bin/env bash
# Runs the BUILT engine image the way the Cloud worker runs a helper, on a Linux host with its own Docker engine (the spike VM), and
# proves it: health, seed, ledger summary and reset (front/tools/cloud_worker_sim.py), the 54-call matrix with start-up time and
# private memory of the front and the engine together, the escape project's aws tests, and every connection of the container's
# processes.
#
#   IMAGE=<ref> COMPAT_PYTHON=<python with boto3> [ESCAPE_DIR=<project dir>] [NODE=node] scripts/front-image-prove.sh
#
# The container is started with the catalog entry's run settings: user 10001:10001, read-only root, a 64 MiB noexec /tmp tmpfs,
# 512 MiB memory (no swap), 512 pids, all capabilities dropped, no-new-privileges, --init, the network alias `aws`, and an env file
# in the shape service-helpers.ts writes. The only difference from the worker: one port is published on 127.0.0.1 (the perf matrix and
# the escape tests only accept loopback endpoints). A first run with --network none shows the image starts with no network at all.
# Needs sudo for docker. Removes its container and network (and the image with REMOVE_IMAGE=1).
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="${IMAGE:?set IMAGE}"
PY="${COMPAT_PYTHON:?set COMPAT_PYTHON}"
D="sudo docker"
NAME="front-image-prove-$$"
NET="front-prove-net-$$"
SUBNET="172.31.$((RANDOM % 200 + 20)).0/24"
IP="${SUBNET%.0/24}.2"
OUT="${OUT:-/tmp/front-image-prove-out}"
mkdir -p "$OUT"
rc=0
# shellcheck disable=SC2317  # run by the EXIT trap
cleanup() { $D rm -f "$NAME" "$NAME-none" "$NAME-all" >/dev/null 2>&1; $D network rm "$NET" >/dev/null 2>&1; [ "${REMOVE_IMAGE:-0}" = 1 ] && $D rmi -f "$IMAGE" >/dev/null 2>&1; rm -f "$OUT/run.env"; }
trap cleanup EXIT
ok() { echo "ok:   $*"; }
bad() { echo "FAIL: $*"; rc=1; }

rand() { head -c 20 /dev/urandom | od -An -tx1 | tr -d ' \n' | head -c "$1"; }
TOKEN="tk$(rand 24)"; PRESIGN="ps$(rand 20)"; RECEIPT="rc$(rand 20)"
env_file() { # <bind host> [all]: with "all" no service is switched off (the matrix and the escape tests use every service)
  {
    echo "QUARKUS_HTTP_HOST=$1"; echo "ROVARA_AWS_BASE_URL=http://aws:4566"; echo "ROVARA_AWS_AUTH_PRESIGN_SECRET=$PRESIGN"
    echo "ROVARA_AWS_SERVICES_SQS_RECEIPT_HANDLE_SECRET=$RECEIPT"; echo "ROVARA_AWS_CONTROL_TOKEN=$TOKEN"; echo "ROVARA_AWS_DEFAULT_REGION=us-east-1"; echo "ROVARA_AWS_HOSTNAME=aws"
    if [ "${2:-}" != all ]; then
      for k in ssm sns lambda apigateway apigatewayv2 iam eventbridge eventbridgev2 cloudwatchlogs secretsmanager kinesis kms cognito stepfunctions sagemaker; do
        echo "ROVARA_AWS_SERVICES_$(echo "$k" | tr '[:lower:]' '[:upper:]')_ENABLED=false"
      done
    fi
  } > "$OUT/run.env"; chmod 600 "$OUT/run.env"
}
run_args=(--user 10001:10001 --read-only --tmpfs "/tmp:rw,noexec,nosuid,nodev,size=64m,uid=10001,gid=10001" --memory 512m --memory-swap 512m --pids-limit 512 --cpus 1
  --cap-drop ALL --security-opt no-new-privileges --init --env-file "$OUT/run.env")

echo "== image: $($D image inspect "$IMAGE" --format '{{.Architecture}} {{.Config.User}} exposed={{json .Config.ExposedPorts}} size={{.Size}}')"
echo "== run with no network at all"
env_file 127.0.0.1
$D run -d --name "$NAME-none" --network none "${run_args[@]}" "$IMAGE" >/dev/null
sleep 3
if [ "$($D inspect -f '{{.State.Running}}' "$NAME-none")" = true ] && $D logs "$NAME-none" 2>&1 | grep -q 'listening on 127.0.0.1:4566'; then ok "the image starts and keeps running with --network none"; else bad "the image did not stay up with --network none"; $D logs "$NAME-none" 2>&1 | tail -5; fi
$D rm -f "$NAME-none" >/dev/null

echo "== run on a network, as the worker does"
$D network create --subnet "$SUBNET" "$NET" >/dev/null
env_file "$IP"
SPAWN="$(date +%s.%N)"
$D run -d --name "$NAME" --network "$NET" --ip "$IP" --network-alias aws -p 127.0.0.1:14566:4566 "${run_args[@]}" "$IMAGE" >/dev/null
for _ in $(seq 1 200); do curl -sf "http://$IP:4566/_rovara/health" >/dev/null && break; sleep 0.05; done
UP="$(date +%s.%N)"
echo "docker run to healthy: $(python3 -c "print(round($UP - $SPAWN, 2))") s"
$D inspect "$NAME" --format 'user={{.Config.User}} readonlyRoot={{.HostConfig.ReadonlyRootfs}} memory={{.HostConfig.Memory}} pids={{.HostConfig.PidsLimit}} tmpfs={{json .HostConfig.Tmpfs}}'
if curl -sf "http://$IP:4566/_rovara/health" | grep -q '"version":"0.1.0"'; then ok "health answers on the run address"; else bad "no health"; fi
PID="$($D inspect -f '{{.State.Pid}}' "$NAME")"
echo "$PID" > "$OUT/pid"

echo "== the worker's calls (health, seed, ledger summary, reset)"
"$PY" -I "$HERE/front/tools/cloud_worker_sim.py" --host "$IP" --port 4566 --token "$TOKEN" --alias aws \
  --disabled "ssm,sns,lambda,apigateway,apigatewayv2,iam,events,eventsv2,logs,secretsmanager,kinesis,kms,cognito-idp,states,sagemaker" | grep -v '^ok:   .*403' || rc=1

echo "== second container with every service on (the matrix, the escape tests and the differential need them)"
$D rm -f "$NAME" >/dev/null
env_file "$IP" all
SPAWN="$(date +%s.%N)"
$D run -d --name "$NAME-all" --network "$NET" --ip "$IP" --network-alias aws -p 127.0.0.1:14566:4566 "${run_args[@]}" "$IMAGE" >/dev/null
for _ in $(seq 1 200); do curl -sf "http://$IP:4566/_rovara/health" >/dev/null && break; sleep 0.05; done
echo "docker run to healthy: $(python3 -c "import time;print(round(time.time() - $SPAWN, 2))") s"
NAME="$NAME-all"
PID="$($D inspect -f '{{.State.Pid}}' "$NAME")"
echo "$PID" > "$OUT/pid"
echo "== connections of the container's processes while the matrix runs"
tree() { local p=$1; echo "$p"; for c in $(pgrep -P "$p"); do tree "$c"; done; }
: > "$OUT/net.log"
( while $D inspect -f '{{.State.Running}}' "$NAME" 2>/dev/null | grep -q true; do
    pat="$(tree "$PID" | tr '\n' '|' | sed 's/|$//')"
    sudo nsenter -t "$PID" -n ss -tanpH 2>/dev/null | grep -E "pid=($pat)," >> "$OUT/net.log"
    sleep 0.1
  done ) &
SAMPLER=$!
echo "== matrix, start-up and memory (the front and the engine together)"
"$PY" -I "$HERE/front/tools/measure_front.py" --pidfile "$OUT/pid" --spawned-at "$(date +%s.%N)" --endpoint http://127.0.0.1:14566 --python "$PY" \
  --matrix "$HERE/perf/matrix.py" --median-warn --out "$OUT/measure.json" | grep -E '"(processes|idle_private_mib|peak_private_mib|peak_rss_mib|front_private_mib|matrix_passed|matrix_total|median_call_ms)"' || rc=1
CG="/sys/fs/cgroup$(cut -d: -f3 "/proc/$PID/cgroup")"
echo "cgroup $CG: memory.peak $(( $(cat "$CG/memory.peak" 2>/dev/null || echo 0) / 1048576 )) MiB (the limit is 512, /tmp tmpfs included), oom kills: $($D inspect -f '{{.State.OOMKilled}}' "$NAME")"
if [ "$($D inspect -f '{{.State.OOMKilled}}' "$NAME")" = false ]; then ok "no out-of-memory kill"; else bad "the container was OOM killed"; fi

if [ -n "${ESCAPE_DIR:-}" ]; then
  echo "== escape project, aws tests"
  "$PY" -I - "$TOKEN" <<'PY'
import http.client, json, sys
doc = {"region": "us-east-1", "s3": {"buckets": [{"name": "orders-archive"}]},
       "dynamodb": {"tables": [{"request": {"TableName": "orders", "KeySchema": [{"AttributeName": "orderId", "KeyType": "HASH"}],
                                             "AttributeDefinitions": [{"AttributeName": "orderId", "AttributeType": "S"}], "BillingMode": "PAY_PER_REQUEST"}}]},
       "sqs": {"queues": [{"name": "order-events"}]}}
c = http.client.HTTPConnection("127.0.0.1", 14566)
c.request("POST", "/_rovara/reset", "", {"x-rovara-control-token": sys.argv[1]}); c.getresponse().read()
c.request("POST", "/_rovara/seed", json.dumps(doc), {"x-rovara-control-token": sys.argv[1]})
r = c.getresponse(); print("seed", r.status)
PY
  ( cd "$ESCAPE_DIR" && AWS_ENDPOINT_URL_S3=http://127.0.0.1:14566 AWS_ENDPOINT_URL_SQS=http://127.0.0.1:14566 AWS_ENDPOINT_URL_DYNAMODB=http://127.0.0.1:14566 \
      "${NODE:-node}" --test tests/ 2>&1 | grep -E '^(ok|not ok|# (tests|pass|fail))' ) || rc=1
fi

echo "== route differential against the image's own front (every request refused or served by the engine's service)"
if [ -n "${ENGINE_BIN:-}" ]; then
  python3 -I "$HERE/front/tools/route_differential.py" --front http://127.0.0.1:14566 --token "$TOKEN" --engine-bin "$ENGINE_BIN" | tail -3 || rc=1
fi

kill "$SAMPLER" 2>/dev/null; wait "$SAMPLER" 2>/dev/null
echo "== network: remote addresses of every connection the container's processes had"
awk '$1 != "LISTEN" {print $5}' "$OUT/net.log" | sed 's/:[0-9]*$//' | sort -u | tr '\n' ' '; echo
echo "listening: $(awk '$1 == "LISTEN" {print $4}' "$OUT/net.log" | sort -u | tr '\n' ' ')"
# a socket is outbound when its local port is not a listening port of the container
awk '$1 == "LISTEN" {n=split($4,a,":"); print a[n]}' "$OUT/net.log" | sort -u > "$OUT/listen.ports"
outbound="$(awk '$1 != "LISTEN" {n=split($4,l,":"); lp=l[n]; m=split($5,r,":"); rh=$5; sub(/:[0-9]*$/,"",rh); print lp, rh}' "$OUT/net.log" | sort -u | while read -r lp rh; do grep -qx "$lp" "$OUT/listen.ports" || echo "$rh"; done | sort -u | tr '\n' ' ')"
if [ -z "${outbound// /}" ] || [ "${outbound// /}" = "127.0.0.1" ]; then ok "every outbound connection stayed on 127.0.0.1 (${outbound:-none})"; else bad "outbound connections to: $outbound"; fi
$D logs "$NAME" 2>&1 | tail -3
echo "== logs hold no secret"
if $D logs "$NAME" 2>&1 | grep -qE "$TOKEN|$PRESIGN|$RECEIPT"; then bad "a secret is in the container's log"; else ok "no secret in the container's log"; fi
exit "$rc"
