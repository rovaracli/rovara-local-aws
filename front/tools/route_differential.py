#!/usr/bin/env python3
"""Differential test of request routing: how the front and the real AWS Emulator each pick the SERVICE of a request.

A table of crafted requests (scope in the Authorization header or the query, SigV4 and other schemes, every Content-Type the engine
might read as a form, Action in the query or the body, X-Amz-Target, Host and X-Forwarded-Host tricks, REST and CBOR paths) is
sent to the engine directly and to the front. For each one the service the ENGINE executed is read from its own answer
(the namespace of an XML answer, the shape of a JSON one). The front passes a request when it either refuses it itself, or
forwards it and (1) the engine's service is one of the front's catalog, (2) the front's answer is the engine's service's answer,
(3) the front's ledger names that very service. Anything else, above all a non-catalog service answering through the front, fails.

    route_differential.py --front http://127.0.0.1:4566 --token <control token> --engine-bin /opt/aws-emulator/bin/aws-emulator

The front must have been started with a control token (it is used to read the ledger) and every service enabled. The script starts
its own engine for the direct side. Exit 0 when no request fails."""
import argparse
import http.client
import itertools
import json
import os
import re
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.parse

CATALOG = {"s3", "dynamodb", "sqs", "sns", "iam", "sts", "kms", "ssm", "secretsmanager", "events", "logs", "kinesis", "states",
           "cognito-idp", "lambda", "sagemaker", "apigateway", "apigatewayv2"}
XMLNS_SERVICE = {"ec2": "ec2", "monitoring": "monitoring", "cloudformation": "cloudformation", "iam": "iam", "sts": "sts", "sns": "sns",
                 "queue": "sqs", "sqs": "sqs", "s3": "s3", "elasticloadbalancing": "elb", "autoscaling": "autoscaling", "rds": "rds",
                 "redshift": "redshift", "elasticache": "elasticache", "ses": "ses", "email": "ses"}
JSON_SHAPES = [("TableNames", "dynamodb"), ("QueueUrls", "sqs"), ("queueUrls", "sqs"), ("Keys", "kms"), ("SecretList", "secretsmanager"),
               ("UserPools", "cognito-idp"), ("stateMachines", "states"), ("StreamNames", "kinesis"), ("Rules", "events"),
               ("DatabaseList", "glue"), ("repositories", "ecr"), ("logGroups", "logs"), ("Functions", "lambda"), ("Commands", "ssm"),
               ("Parameters", "ssm"), ("Streams", "dynamodb")]


def detect(status, body):
    """The service whose answer this is, or None when it cannot be told (an error that names nothing)."""
    text = body.decode("utf-8", "replace")
    m = re.search(r'xmlns="https?://([a-z0-9-]+)\.amazonaws\.com', text)
    if m:
        return XMLNS_SERVICE.get(m.group(1), m.group(1))
    try:
        j = json.loads(text)
        if isinstance(j, dict):
            for key, svc in JSON_SHAPES:
                if key in j:
                    return svc
    except ValueError:
        pass
    if re.search(r"<ListAllMyBucketsResult|<Error><Code>(NoSuchBucket|NoSuchKey|InvalidBucketName)", text):
        return "s3"
    return None


def start_engine(binary):
    home = tempfile.mkdtemp()
    env = {"HOME": home, "EMULATOR_TELEMETRY": "off", "PATH": "/usr/bin:/bin"}
    p = subprocess.Popen([binary, "-b", "127.0.0.1", "-p", "0", "-t", "off", "-a", "off"], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    for line in p.stdout:
        if "endpoint_url" in line:
            info = json.loads(line)["fields"]
            threading_drain(p)
            return p, info["endpoint_url"], info["ca_file"]
    raise SystemExit("the engine did not start")


def threading_drain(p):
    import threading
    threading.Thread(target=lambda: [None for _ in p.stdout], daemon=True).start()


class Target:
    def __init__(self, url, ca=None):
        u = urllib.parse.urlparse(url)
        self.host, self.port, self.tls = u.hostname, u.port, u.scheme == "https"
        self.ctx = ssl.create_default_context(cafile=ca) if ca else None

    def send(self, method, path, headers, body):
        c = (http.client.HTTPSConnection(self.host, self.port, context=self.ctx, timeout=20) if self.tls
             else http.client.HTTPConnection(self.host, self.port, timeout=20))
        h = dict(headers)
        try:
            c.request(method, path, body=body, headers=h)
            r = c.getresponse()
            return r.status, r.read()
        except Exception as e:  # noqa
            return 0, str(e).encode()
        finally:
            c.close()


def sigv4(svc, region="us-east-1"):
    return f"AWS4-HMAC-SHA256 Credential=AKID/20260101/{region}/{svc}/aws4_request, SignedHeaders=host, Signature=" + "0" * 64


def table():
    """Crafted requests: (name, method, path, headers, body)."""
    out = []
    bodies = [("ec2 form", b"Action=DescribeInstances&Version=2016-11-15"), ("ec2 CreateVpc", b"Action=CreateVpc&Version=2016-11-15&CidrBlock=10.9.0.0/16"),
              ("cloudwatch form", b"Action=ListMetrics&Version=2010-08-01"), ("cfn form", b"Action=ListStacks&Version=2010-05-15"),
              ("sqs form", b"Action=ListQueues&Version=2012-11-05"), ("sns form", b"Action=ListTopics&Version=2010-03-31"),
              ("sts form", b"Action=GetCallerIdentity&Version=2011-06-15"), ("iam form", b"Action=ListUsers&Version=2010-05-08"),
              ("empty", b"")]
    ctypes = [None, "application/x-www-form-urlencoded", "text/plain", "application/json", "application/octet-stream", "application/x-amz-json-1.1",
              "application/xml", "multipart/form-data; boundary=x"]
    scopes = {"none": [], "sigv4-ec2": [("Authorization", sigv4("ec2"))], "sigv4-sqs": [("Authorization", sigv4("sqs"))], "sigv4-s3": [("Authorization", sigv4("s3"))],
              "sigv4-dynamodb": [("Authorization", sigv4("dynamodb"))], "sigv4-monitoring": [("Authorization", sigv4("monitoring"))],
              "bearer-dynamodb": [("Authorization", "Bearer Credential=AKID/20260101/us-east-1/dynamodb/aws4_request")],
              "bearer-ec2": [("Authorization", "Bearer Credential=AKID/20260101/us-east-1/ec2/aws4_request")],
              "lower-sqs": [("Authorization", "aws4-hmac-sha256 Credential=AKID/20260101/us-east-1/sqs/aws4_request")],
              "basic": [("Authorization", "Basic dXNlcjpwdw==")]}
    queries = {"": "", "q-ec2": "X-Amz-Credential=AKID/20260101/us-east-1/ec2/aws4_request", "q-ec2-enc": "X-Amz-Credential=AKID%2F20260101%2Fus-east-1%2Fec2%2Faws4_request",
               "q-ec2-lower-name": "x-amz-credential=AKID/20260101/us-east-1/ec2/aws4_request", "q-sqs": "X-Amz-Credential=AKID/20260101/us-east-1/sqs/aws4_request",
               "q-two": "X-Amz-Credential=AKID/20260101/us-east-1/sqs/aws4_request&X-Amz-Credential=AKID/20260101/us-east-1/ec2/aws4_request",
               "q-action-ec2": "Action=DescribeInstances&Version=2016-11-15", "q-action-ec2-and-scope": "Action=DescribeInstances&Version=2016-11-15&X-Amz-Credential=AKID/20260101/us-east-1/ec2/aws4_request"}
    for (sn, sh), (qn, qs), (bn, b), ct in itertools.product(scopes.items(), queries.items(), bodies, ctypes):
        if qn in ("q-ec2-lower-name", "q-two", "q-action-ec2-and-scope") and bn not in ("ec2 form", "sqs form"):
            continue
        if ct in ("application/json", "application/octet-stream", "application/xml", "multipart/form-data; boundary=x", "application/x-amz-json-1.1") and bn not in ("ec2 form", "sqs form"):
            continue
        h = dict(sh)
        if ct:
            h["Content-Type"] = ct
        out.append((f"{sn} | {qn or 'no-query'} | {bn} | {ct}", "POST", "/" + ("?" + qs if qs else ""), h, b))
    # targets, hosts, paths
    for tgt in ["DynamoDB_20120810.ListTables", "AmazonSQS.ListQueues", "TrentService.ListKeys", "EC2.DescribeInstances", "AmazonEC2.DescribeInstances", "Logs_20140328.DescribeLogGroups", "ec2.DescribeInstances"]:
        for sn, sh in [("none", []), ("sigv4-s3", [("Authorization", sigv4("s3"))]), ("sigv4-ec2", [("Authorization", sigv4("ec2"))]), ("bearer-ec2", [("Authorization", "Bearer Credential=AKID/20260101/us-east-1/ec2/aws4_request")])]:
            h = dict(sh)
            h["X-Amz-Target"] = tgt
            h["Content-Type"] = "application/x-amz-json-1.0"
            out.append((f"target {tgt} | {sn}", "POST", "/", h, b"{}"))
    for host in ["ec2.amazonaws.com", "ec2.us-east-1.amazonaws.com", "dynamodb.us-east-1.amazonaws.com", "monitoring.amazonaws.com", "sqs.us-east-1.amazonaws.com", "iam.amazonaws.com"]:
        for hdr in ["Host", "X-Forwarded-Host"]:
            for ct, b in [("application/x-www-form-urlencoded", b"Action=DescribeInstances&Version=2016-11-15"), ("text/plain", b"Action=ListMetrics&Version=2010-08-01"), (None, b"")]:
                h = {hdr: host}
                if ct:
                    h["Content-Type"] = ct
                out.append((f"{hdr}: {host} | {ct}", "POST", "/", h, b))
    for path in ["/", "/bkt", "/bkt/key", "/2015-03-31/functions", "/restapis", "/service/SQS/operation/ListQueues", "/service/EC2/operation/DescribeInstances", "/v2/apis",
                 "//v2/apis", "/v2/domainnames", "/v2/vpclinks", "/v2/portals", "/v2/tags/arn%3Aaws%3Aapigateway%3Aus-east-1%3A%3A%2Fapis%2Fx", "/domainnames", "/vpclinks", "/V2/apis", "/%76%32/apis"]:
        for sn, sh in [("none", []), ("sigv4-s3", [("Authorization", sigv4("s3"))]), ("sigv4-lambda", [("Authorization", sigv4("lambda"))]), ("sigv4-ec2", [("Authorization", sigv4("ec2"))]),
                       ("sigv4-apigateway", [("Authorization", sigv4("apigateway"))]), ("sigv4-execute-api", [("Authorization", sigv4("execute-api"))])]:
            for extra in [{}, {"smithy-protocol": "rpc-v2-cbor"}]:
                h = dict(sh); h.update(extra)
                out.append((f"GET {path} | {sn} | {'cbor' if extra else 'plain'}", "GET", path, h, b""))
    return out


def ledger_last(front, token):
    st, body = front.send("GET", "/_rovara/ledger?limit=1", {"x-rovara-control-token": token}, None)
    return json.loads(body)["lastSeq"]


def ledger_after(front, token, seq):
    st, body = front.send("GET", f"/_rovara/ledger?after={seq}&limit=100", {"x-rovara-control-token": token}, None)
    return json.loads(body)["entries"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--front", required=True)
    ap.add_argument("--token", required=True)
    ap.add_argument("--engine-bin", required=True)
    ap.add_argument("--verbose", action="store_true")
    a = ap.parse_args()
    proc, url, ca = start_engine(a.engine_bin)
    engine, front = Target(url, ca), Target(a.front)
    rows = table()
    stats = dict(total=len(rows), refused=0, forwarded=0, engine_noncatalog=0, engine_catalog=0, failed=0)
    fails = []
    for name, method, path, headers, body in rows:
        ehdr = dict(headers)
        es, eb = engine.send(method, path, ehdr, body or None)
        eservice = detect(es, eb)
        seq = ledger_last(front, a.token)
        fs, fb = front.send(method, path, headers, body or None)
        entries = ledger_after(front, a.token, seq)
        text = fb.decode("utf-8", "replace")
        refused = fs in (400, 404) and ("UnknownOperationException" in text or "ServiceNotAvailableException" in text or "InvalidAction" in text)
        if eservice and eservice not in CATALOG:
            stats["engine_noncatalog"] += 1
        elif eservice:
            stats["engine_catalog"] += 1
        fservice = detect(fs, fb)
        bad = None
        if refused:
            stats["refused"] += 1
            if fs == 200:
                bad = "refusal with 200"
        else:
            stats["forwarded"] += 1
            led = {e["service"] for e in entries}
            if fservice and fservice not in CATALOG:
                bad = f"a non-catalog service answered through the front: {fservice}"
            elif fservice and eservice and fservice != eservice:
                bad = f"the front's answer is service {fservice}, the engine's is {eservice}"
            elif fservice and led and not ({fservice} | ({"sts"} if fservice == "iam" else set()) | ({"iam"} if fservice == "sts" else set())) & led:
                bad = f"the ledger says {sorted(led)} but the service that answered is {fservice}"
            elif eservice and eservice not in CATALOG and fs < 400:
                bad = f"the engine's non-catalog service {eservice} was served"
        if not refused and not bad:
            # API Gateway v1 and v2 share the SigV4 name: every /v2/ path under that name must be counted as apigatewayv2 (the v2 switch governs it)
            auth = headers.get("Authorization", "")
            first = path.split("?")[0].lstrip("/").split("/")[0]
            if first == "v2" and ("/apigateway/" in auth or "/execute-api/" in auth) and "apigatewayv2" not in {e["service"] for e in entries}:
                bad = f"a /v2/ path under the apigateway scope was counted as {sorted({e['service'] for e in entries})}, not apigatewayv2"
        if bad:
            stats["failed"] += 1
            fails.append((name, bad, fs, text[:120]))
        if a.verbose:
            print(("FAIL " if bad else "ok   ") + f"{name} | engine={eservice} front={'refused' if refused else fservice} ledger={sorted({e['service'] for e in entries})}")
    proc.terminate()
    print(json.dumps(stats))
    for f in fails[:40]:
        print("FAIL:", *f)
    print("route_differential:", "FAILED" if fails else "every request was refused or served by the service the engine executed")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
