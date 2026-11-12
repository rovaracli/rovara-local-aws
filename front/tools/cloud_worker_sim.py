#!/usr/bin/env python3
"""Plays the Rovara Cloud worker against a running rovara-aws-front, with the Python standard library for the control
calls (the worker's probe program does the same: plain HTTP, the token in x-rovara-control-token) and boto3 for the
customer code. The parsers below are ports of the Cloud worker's (packages/worker/src/emulator-ledger.ts
parseLedgerSummary, service-seed-aws.ts buildAwsSeedDocument and seedReportCovers, service-probe.ts), so a shape the
worker would refuse fails here.

    cloud_worker_sim.py --host 10.99.0.2 --port 4566 --token <token> [--alias aws] [--region us-east-1]
                        [--disabled ssm,kms,...] [--skip-sdk]

Exit 0 when every check passes. Prints one line per check."""
import argparse
import http.client
import json
import re
import sys
import time

CONTROL_ANSWER_MAX_BYTES = 256 * 1024
LEDGER_LIMITS = dict(services=64, operationsPerService=200, operationChars=200, count=1_000_000_000_000)
SERVICE_KEY = re.compile(r"^[a-z][a-z0-9-]{0,39}$")
PLAIN_TOKEN = re.compile(r"^[A-Za-z0-9]{8,64}$")
FAILS = []


def check(name, ok, detail=""):
    print(("ok:   " if ok else "FAIL: ") + name + ((" - " + str(detail)) if (detail and not ok) else ""), flush=True)
    if not ok:
        FAILS.append(name)
    return ok


def call(host, port, method, path, token=None, body=None, timeout=30):
    """One control call as service-probe.ts makes it: connection close, the token header, a JSON body for a POST."""
    c = http.client.HTTPConnection(host, port, timeout=timeout)
    headers = {"connection": "close"}
    if token is not None:
        headers["x-rovara-control-token"] = token
    data = None
    if body is not None:
        data = body if isinstance(body, bytes) else body.encode()
        headers["content-type"] = "application/json"
    if method == "POST":
        headers["content-length"] = str(len(data or b""))
    c.request(method, path, body=data, headers=headers)
    r = c.getresponse()
    raw = r.read(CONTROL_ANSWER_MAX_BYTES + 1)
    c.close()
    return r.status, raw.decode("utf-8", "replace"), len(raw) > CONTROL_ANSWER_MAX_BYTES


def count_of(v):
    if not isinstance(v, int) or isinstance(v, bool) or v < 0 or v > LEDGER_LIMITS["count"]:
        raise ValueError("not a count")
    return v


def parse_ledger_summary(text):
    """emulator-ledger.ts parseLedgerSummary: exactly the summary shape within the limits, or ValueError."""
    parsed = json.loads(text)
    if not isinstance(parsed, dict):
        raise ValueError("not an object")
    if len(parsed) > LEDGER_LIMITS["services"]:
        raise ValueError("too_many")
    services = []
    for service, value in parsed.items():
        if not SERVICE_KEY.match(service) or not isinstance(value, dict):
            raise ValueError("service key or value")
        counts = {k: count_of(value.get(k)) for k in ("calls", "unsupported", "errors")}
        ops = value.get("operations")
        if not isinstance(ops, dict):
            raise ValueError("operations")
        if len(ops) > LEDGER_LIMITS["operationsPerService"]:
            raise ValueError("too_many")
        rows = {}
        for op, row in ops.items():
            if not 1 <= len(op) <= LEDGER_LIMITS["operationChars"] or not isinstance(row, dict):
                raise ValueError("operation")
            rows[op] = {k: count_of(row.get(k)) for k in ("calls", "unsupported", "errors")}
        services.append((service, counts, rows))
    return services


def build_seed_document(region, resources):
    """service-seed-aws.ts buildAwsSeedDocument."""
    doc = {"region": region}
    buckets = [{"name": r["name"]} for r in resources if r["kind"] == "bucket"]
    tables = []
    for r in resources:
        if r["kind"] != "table":
            continue
        pk, sk = r["keySchema"]["partitionKey"], r["keySchema"].get("sortKey")
        keys = [{"AttributeName": pk["name"], "KeyType": "HASH"}] + ([{"AttributeName": sk["name"], "KeyType": "RANGE"}] if sk else [])
        defs = [{"AttributeName": pk["name"], "AttributeType": pk["type"]}] + ([{"AttributeName": sk["name"], "AttributeType": sk["type"]}] if sk else [])
        tables.append({"request": {"TableName": r["name"], "KeySchema": keys, "AttributeDefinitions": defs, "BillingMode": "PAY_PER_REQUEST"}})
    queues = [({"name": r["name"], "attributes": {"FifoQueue": "true"}} if r["name"].endswith(".fifo") else {"name": r["name"]})
              for r in resources if r["kind"] == "queue"]
    if buckets:
        doc["s3"] = {"buckets": buckets}
    if tables:
        doc["dynamodb"] = {"tables": tables}
    if queues:
        doc["sqs"] = {"queues": queues}
    return doc


STEP_OF_KIND = {"bucket": ("s3", "CreateBucket"), "table": ("dynamodb", "CreateTable"), "queue": ("sqs", "CreateQueue")}


def seed_report_covers(report, resources):
    """service-seed-aws.ts seedReportCovers: ok, failed 0, every resource has exactly its ok step, nothing else."""
    if not isinstance(report, dict):
        return False
    if report.get("ok") is not True or report.get("failed") != 0 or not isinstance(report.get("steps"), list) or len(report["steps"]) != len(resources):
        return False
    seen = set()
    for st in report["steps"]:
        if not isinstance(st, dict) or st.get("ok") is not True or not all(isinstance(st.get(k), str) for k in ("service", "action", "name")):
            return False
        seen.add((st["service"], st["action"], st["name"]))
    return all((STEP_OF_KIND[r["kind"]] + (r["name"],)) in seen for r in resources)


RESOURCES = [
    {"kind": "bucket", "name": "orders-archive"},
    {"kind": "table", "name": "orders", "keySchema": {"partitionKey": {"name": "id", "type": "S"}, "sortKey": {"name": "ts", "type": "N"}}},
    {"kind": "table", "name": "customers", "keySchema": {"partitionKey": {"name": "customer", "type": "S"}}},
    {"kind": "queue", "name": "orders-events"},
    {"kind": "queue", "name": "orders-dlq.fifo"},
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=4566)
    ap.add_argument("--token", required=True)
    ap.add_argument("--alias", default="aws")
    ap.add_argument("--region", default="us-east-1")
    ap.add_argument("--disabled", default="")
    ap.add_argument("--skip-sdk", action="store_true")
    a = ap.parse_args()
    H, P, T = a.host, a.port, a.token
    disabled = [d for d in a.disabled.split(",") if d]
    check("the token is in the worker's plain form (8-64 letters and digits)", bool(PLAIN_TOKEN.match(T)))

    # 1. health: a plain GET with no token that must answer 2xx (service-probe.ts)
    t0 = time.time()
    st, body, _ = call(H, P, "GET", "/_rovara/health")
    check("health answers 2xx with no token", 200 <= st < 300, (st, body[:200]))
    h = json.loads(body)
    check("health body has the fork's shape (services + version)", isinstance(h.get("services"), dict) and h.get("version") == "0.1.0", body[:200])
    check("health names the disabled services as 'available' and the rest 'running'",
          all(h["services"].get(k) == "available" for k in disabled) or not disabled, h["services"])

    # 2. what a sandbox can send (no token, a wrong one) is refused on every control path
    for method, path in (("GET", "/_rovara/ledger/summary"), ("POST", "/_rovara/seed"), ("POST", "/_rovara/reset"), ("GET", "/_rovara/ledger"), ("GET", "/_rovara/tick"), ("DELETE", "/_rovara/ledger")):
        s1 = call(H, P, method, path, None, b"{}" if method == "POST" else None)[0]
        s2 = call(H, P, method, path, "guessguessguess1", b"{}" if method == "POST" else None)[0]
        check(f"{method} {path}: 403 without the token and with a guess", s1 == 403 and s2 == 403, (s1, s2))

    # 3. reset, then seed the project's resources exactly as the worker builds the document
    st, body, _ = call(H, P, "POST", "/_rovara/reset", T)
    check("reset answers 2xx", 200 <= st < 300, (st, body))
    doc = build_seed_document(a.region, RESOURCES)
    t1 = time.time()
    st, body, big = call(H, P, "POST", "/_rovara/seed", T, json.dumps(doc))
    seed_s = time.time() - t1
    check("seed answers 2xx", 200 <= st < 300, (st, body[:400]))
    try:
        report = json.loads(body)
    except ValueError:
        report = None
    check("the seed report covers every resource, step by step (seedReportCovers)", seed_report_covers(report, RESOURCES), body[:400])
    print(f"      seed took {seed_s:.2f} s (5 resources, two DynamoDB tables waited for ACTIVE together)")
    check("the seed fits the worker's 8 s wall-clock limit for a control call", seed_s < 8.0, f"{seed_s:.2f} s")
    st, body, _ = call(H, P, "POST", "/_rovara/seed", T, json.dumps(doc))
    check("a second seed of the same document is refused with 422 and ok=false (the fork's rule)", st == 422 and json.loads(body).get("ok") is False, (st, body[:200]))
    st, body, _ = call(H, P, "POST", "/_rovara/seed", T, "{not json")
    check("a seed that is not JSON is 400", st == 400, (st, body))
    call(H, P, "POST", "/_rovara/reset", T)
    st, body, _ = call(H, P, "POST", "/_rovara/seed", T, json.dumps(doc))
    check("after a reset the same seed works again and is covered", seed_report_covers(json.loads(body), RESOURCES), body[:300])

    # 4. the customer's code, as the worker configures it: global endpoint, fake keys, region from env, plain HTTP
    if not a.skip_sdk:
        import os
        os.environ.update(AWS_ACCESS_KEY_ID="ROVARATESTKEY", AWS_SECRET_ACCESS_KEY="rovaratestsecret", AWS_DEFAULT_REGION=a.region,
                          AWS_ENDPOINT_URL=f"http://{H}:{P}", AWS_EC2_METADATA_DISABLED="true",
                          AWS_SHARED_CREDENTIALS_FILE="/dev/null", AWS_CONFIG_FILE="/dev/null")
        import boto3
        from botocore.config import Config
        cfg = Config(retries={"max_attempts": 1}, s3={"addressing_style": "path"})
        def cl(svc):
            return boto3.client(svc, config=cfg)
        s3, ddb, sqs = cl("s3"), cl("dynamodb"), cl("sqs")
        check("customer code sees the seeded bucket", [b["Name"] for b in s3.list_buckets()["Buckets"]] == ["orders-archive"])
        d = ddb.describe_table(TableName="orders")["Table"]
        check("customer code sees the seeded table, ACTIVE", d["TableStatus"] == "ACTIVE" and d["KeySchema"][0]["AttributeName"] == "id")
        ddb.put_item(TableName="orders", Item={"id": {"S": "o1"}, "ts": {"N": "1"}})
        check("a table put and get works at once", ddb.get_item(TableName="orders", Key={"id": {"S": "o1"}, "ts": {"N": "1"}}).get("Item") is not None)
        url = sqs.get_queue_url(QueueName="orders-events")["QueueUrl"]
        check("the queue URL the code sees is the base URL, never an engine or AWS name", url == f"http://{a.alias}:4566/000000000000/orders-events", url)
        fifo = sqs.get_queue_url(QueueName="orders-dlq.fifo")["QueueUrl"]
        check("the FIFO queue was seeded as FIFO", fifo.endswith("/orders-dlq.fifo") and
              sqs.get_queue_attributes(QueueUrl=fifo, AttributeNames=["FifoQueue"])["Attributes"]["FifoQueue"] == "true")
        check("ListQueues rewrites every URL", all(u.startswith(f"http://{a.alias}:4566/") for u in sqs.list_queues()["QueueUrls"]))
        if "ssm" in disabled:
            try:
                cl("ssm").get_parameter(Name="/x")
                check("a call to a switched-off service is refused", False)
            except Exception as e:
                code = getattr(e, "response", {}).get("Error", {}).get("Code")
                check("a call to a switched-off service is refused with ServiceNotAvailableException", code == "ServiceNotAvailableException", e)
        try:
            import urllib.request
            req = urllib.request.Request(f"http://{H}:{P}/", data=b"{}", method="POST",
                                         headers={"X-Amz-Target": "AmazonSQS.NopeOperation", "Content-Type": "application/x-amz-json-1.0"})
            try:
                urllib.request.urlopen(req)
            except Exception as e:
                check("an operation the engine does not know is refused by the engine (HTTP 501)", getattr(e, "code", None) == 501, e)
        except Exception as e:
            check("unsupported-operation probe ran", False, e)

    # 5. the ledger, read as the worker reads it
    st, body, big = call(H, P, "GET", "/_rovara/ledger/summary", T)
    check("ledger summary answers 2xx and is under the 256 KiB limit", 200 <= st < 300 and not big, (st, len(body)))
    try:
        services = parse_ledger_summary(body)
        check("the ledger summary parses with the worker's parser", True)
    except Exception as e:
        services = []
        check("the ledger summary parses with the worker's parser", False, f"{e}: {body[:300]}")
    by = {s: (c, r) for s, c, r in services}
    if not a.skip_sdk:
        check("the ledger counts the customer's calls (s3, dynamodb, sqs present)", all(k in by for k in ("s3", "dynamodb", "sqs")), list(by))
        if "sqs" in by:
            ops = by["sqs"][1]
            check("sqs: GetQueueUrl counted", ops.get("GetQueueUrl", {}).get("calls", 0) >= 2, ops)
            check("sqs: the unknown operation is counted as unsupported", ops.get("NopeOperation", {}).get("unsupported") == 1 and ops["NopeOperation"]["errors"] == 1, ops.get("NopeOperation"))
        if "ssm" in disabled:
            check("ssm: the refused call is counted as an error", by.get("ssm", ({"errors": 0}, {}))[0]["errors"] >= 1, by.get("ssm"))
        check("no engine or AWS host name in the summary", "127.0.0.1" not in body and "amazonaws" not in body)
    # the reset keeps the ledger (the fork's behaviour); DELETE empties it
    call(H, P, "POST", "/_rovara/reset", T)
    st, body2, _ = call(H, P, "GET", "/_rovara/ledger/summary", T)
    check("a reset does not clear the ledger", body2 == body or json.loads(body2) == json.loads(body), body2[:200])
    st, _, _ = call(H, P, "DELETE", "/_rovara/ledger", T)
    st2, body3, _ = call(H, P, "GET", "/_rovara/ledger/summary", T)
    check("DELETE /_rovara/ledger empties it", st == 200 and body3 == "{}")

    print(f"cloud_worker_sim: {'FAILED (' + ', '.join(FAILS) + ')' if FAILS else 'all checks passed'}")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
