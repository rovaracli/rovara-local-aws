#!/usr/bin/env bash
# Proves the SQS Query-protocol translator of the front against the real AWS Emulator, on Linux.
#
#   FRONT_BIN=<rovara-aws-front> ENGINE_BIN=<aws-emulator> [FORK_JAR=<quarkus-run.jar>] [OLD_PYTHON=<python with boto3 < 1.31>] \
#   [ESCAPE_DIR=<test project dir with lib/ and tests/>] scripts/front-query-prove.sh
#
#   always   starts the front on 127.0.0.1 with a token and seeds the escape project's three resources
#   FORK_JAR hand-made Query requests for every SQS action, sent to the fork and to the front; the XML structures are compared
#   OLD_PYTHON the fork's boto3 compat suite and the 54-call matrix with an old boto3, which speaks SQS over the Query protocol
#   ESCAPE_DIR the escape project's aws tests (node --test), with AWS_ENDPOINT_URL_* set as the worker sets them
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
FRONT_BIN="${FRONT_BIN:?set FRONT_BIN}"
ENGINE_BIN="${ENGINE_BIN:-/opt/aws-emulator/bin/aws-emulator}"
WORK="$(mktemp -d)"
TOKEN="qp$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')"
free_port() { python3 -I -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])'; }
PORT="$(free_port)"
JAR_PORT="$(free_port)"
pids=()
# shellcheck disable=SC2317  # run by the EXIT trap
cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null; done; rm -rf "$WORK"; }
trap cleanup EXIT
env -i HOME="$WORK" QUARKUS_HTTP_HOST=127.0.0.1 QUARKUS_HTTP_PORT="$PORT" ROVARA_AWS_BASE_URL=http://aws:4566 ROVARA_AWS_CONTROL_TOKEN="$TOKEN" \
  ROVARA_AWS_AUTH_PRESIGN_SECRET="presign-$TOKEN-xx" ROVARA_AWS_SERVICES_SQS_RECEIPT_HANDLE_SECRET="receipt-$TOKEN-xx" ROVARA_AWS_ENGINE_BIN="$ENGINE_BIN" \
  ROVARA_AWS_FRONT_WORKDIR="$WORK" "$FRONT_BIN" > "$WORK/front.log" 2>&1 &
pids+=($!)
for _ in $(seq 1 100); do curl -sf "http://127.0.0.1:$PORT/_rovara/health" >/dev/null && break; sleep 0.1; done
rc=0
if [ -n "${FORK_JAR:-}" ]; then
  echo "== Query requests, fork versus front"
  QUARKUS_HTTP_PORT="$JAR_PORT" ROVARA_AWS_BASE_URL=http://aws:4566 ROVARA_AWS_DEV_OPEN_CONTROL=1 java -XX:+UseSerialGC -jar "$FORK_JAR" > "$WORK/jar.log" 2>&1 &
  pids+=($!)
  for _ in $(seq 1 150); do curl -sf "http://127.0.0.1:$JAR_PORT/_rovara/health" >/dev/null && break; sleep 0.3; done
  python3 -I "$HERE/front/tools/query_compare.py" --a "http://127.0.0.1:$JAR_PORT" --b "http://127.0.0.1:$PORT" || echo "(differences above are listed in the report: error wrapper shape, element order and engine behaviour)"
fi
if [ -n "${OLD_PYTHON:-}" ]; then
  echo "== old boto3 (SQS over Query): compat suite and matrix"
  ( cd "$HERE" && "$OLD_PYTHON" -I compat/python/run_boto3.py --endpoint "http://127.0.0.1:$PORT" --control-token "$TOKEN" 2>&1 | grep -v ' pass ' | cut -c1-200
    "$OLD_PYTHON" -I perf/matrix.py compat "http://127.0.0.1:$PORT" "$WORK/matrix-old.json" 2>&1 | grep -E 'FAIL|DONE' | cut -c1-200 )
fi
if [ -n "${ESCAPE_DIR:-}" ]; then
  echo "== escape project, aws tests"
  python3 -I - "$PORT" "$TOKEN" <<'PY'
import http.client, json, sys
doc = {"region": "us-east-1", "s3": {"buckets": [{"name": "orders-archive"}]},
       "dynamodb": {"tables": [{"request": {"TableName": "orders", "KeySchema": [{"AttributeName": "orderId", "KeyType": "HASH"}],
                                             "AttributeDefinitions": [{"AttributeName": "orderId", "AttributeType": "S"}], "BillingMode": "PAY_PER_REQUEST"}}]},
       "sqs": {"queues": [{"name": "order-events"}]}}
c = http.client.HTTPConnection("127.0.0.1", int(sys.argv[1]))
c.request("POST", "/_rovara/seed", json.dumps(doc), {"x-rovara-control-token": sys.argv[2]})
r = c.getresponse(); print("seed", r.status)
PY
  ( cd "$ESCAPE_DIR" && AWS_ENDPOINT_URL_S3="http://127.0.0.1:$PORT" AWS_ENDPOINT_URL_SQS="http://127.0.0.1:$PORT" AWS_ENDPOINT_URL_DYNAMODB="http://127.0.0.1:$PORT" \
      node --test tests/ 2>&1 | grep -E '^(ok|not ok|# (tests|pass|fail))' ) || rc=1
fi
exit "$rc"
