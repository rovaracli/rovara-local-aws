#!/usr/bin/env python3
"""Live proof of the SageMaker endpoint shim: boto3 against the front and the real AWS Emulator (SM1 and SM2 of the SageMaker shim).

    sagemaker_live.py --front-bin <rovara-aws-front> --engine-bin /usr/bin/aws-emulator

Run it in the Linux VM with the spike's boto3 venv. It starts its own model stand-in (a small HTTP server with /ping, /invocations and a
chunked reply), its own front (with the engine as its child, a control token, and a plan naming sagemaker, sagemaker-runtime, s3, sns, sqs
and cloudformation) on free ports, and stops only the processes it started. It needs no AWS account and no network beyond loopback.

What it proves, each with boto3 (the SDK's own parser reads every answer):
  invoke      canned answers (a JSON-path rule, a queue, a default), a recorded-fake label, custom attributes and the production variant;
              the model stand-in (forwarded body and headers, its error statuses as ModelError with OriginalStatusCode)
  streaming   InvokeEndpointWithResponseStream parts for a canned answer and for the stand-in's chunked reply; a ModelStreamError event
  async       InvokeEndpointAsync: the output object appears in the engine's S3 at OutputLocation and the success notification arrives on
              an SQS queue subscribed to the SNS topic; a failure writes the failure object and publishes to the error topic
  errors      unknown endpoint (ValidationError), unknown variant, an async call on an endpoint with no async config, an endpoint whose
              backing is the customer's image ("not available yet"), an unmatched request (ModelError naming the hash)
  control     the endpoint table and counters, the ledger markers, the guard on the control paths, reset
  cloudformation  a stack that declares Model, EndpointConfig and Endpoint: the engine creates nothing, the front creates them through the
              engine's API, DescribeEndpoint answers and the endpoint can be invoked
Exit code 0 when every check passes.
"""
import argparse
import http.server
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

FAILED = []


def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + name + ((" :: " + str(detail)[:300]) if (detail and not ok) else ""))
    if not ok:
        FAILED.append(name)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class Helper(http.server.BaseHTTPRequestHandler):
    """The model stand-in: /ping, /invocations (echo, errors, a chunked stream)."""
    seen = []
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_GET(self):
        self.send_response(200 if self.path == "/ping" else 404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n)
        Helper.seen.append({"path": self.path, "headers": dict(self.headers), "body": body})
        if self.path != "/invocations":
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if body == b"status400":
            self.send_response(400)
            self.send_header("Content-Length", "9")
            self.end_headers()
            self.wfile.write(b"bad input")
            return
        if body == b"stream" or self.headers.get("Accept") == "text/event-stream":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for i in range(4):
                chunk = ("data: token-%d\n\n" % i).encode()
                self.wfile.write(b"%x\r\n%s\r\n" % (len(chunk), chunk))
                self.wfile.flush()
                time.sleep(0.05)
            self.wfile.write(b"0\r\n\r\n")
            return
        out = json.dumps({"echo": body.decode(), "ct": self.headers.get("Content-Type")}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Amzn-SageMaker-Custom-Attributes", "from-model")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)


def own_address():
    """The host's own non-loopback address: the front refuses a model stand-in at a loopback or link-local address."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 9))  # no packet is sent; the kernel picks the address it would use
        return s.getsockname()[0]
    finally:
        s.close()


def http_json(method, url, token=None, body=None):
    req = urllib.request.Request(url, data=(json.dumps(body).encode() if body is not None else None), method=method)
    if token:
        req.add_header("X-Rovara-Control-Token", token)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--front-bin", required=True)
    ap.add_argument("--engine-bin", default="/usr/bin/aws-emulator")
    args = ap.parse_args()
    work = tempfile.mkdtemp(prefix="sm-live-")
    hport, fport = free_port(), free_port()
    haddr = own_address()
    helper = http.server.ThreadingHTTPServer((haddr, hport), Helper)
    threading.Thread(target=helper.serve_forever, daemon=True).start()
    token = "tok" + "x" * 20
    env = {"HOME": work, "PATH": "/usr/bin:/bin", "QUARKUS_HTTP_HOST": "127.0.0.1", "QUARKUS_HTTP_PORT": str(fport),
           "ROVARA_AWS_BASE_URL": "http://127.0.0.1:%d" % fport, "ROVARA_AWS_AUTH_PRESIGN_SECRET": "presign" + "p" * 20,
           "ROVARA_AWS_SERVICES_SQS_RECEIPT_HANDLE_SECRET": "receipt" + "r" * 20, "ROVARA_AWS_CONTROL_TOKEN": token,
           "ROVARA_AWS_ENGINE_BIN": args.engine_bin, "ROVARA_AWS_FRONT_WORKDIR": work,
           "ROVARA_AWS_PLANNED_SERVICES": "sagemaker,sagemaker-runtime,s3,sns,sqs,cloudformation,iam,sts",
           "ROVARA_AWS_SAGEMAKER_HELPER": "http://%s:%d" % (haddr, hport)}
    bad = subprocess.run([args.front_bin], env=dict(env, ROVARA_AWS_SAGEMAKER_HELPER="http://127.0.0.1:%d" % hport), capture_output=True, timeout=20)
    check("config: a model stand-in at a loopback address refuses start", bad.returncode == 1 and b"loopback" in bad.stderr, bad)
    front = subprocess.Popen([args.front_bin], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    base = "http://127.0.0.1:%d" % fport
    try:
        for _ in range(200):
            try:
                if urllib.request.urlopen(base + "/_rovara/health", timeout=2).status == 200:
                    break
            except Exception:
                time.sleep(0.1)
        else:
            sys.exit("the front did not become healthy")
        run(base, token, hport)
    finally:
        front.terminate()
        try:
            front.wait(10)
        except subprocess.TimeoutExpired:
            front.kill()
        helper.shutdown()
        shutil.rmtree(work, ignore_errors=True)
    print("\n%d check(s) failed: %s" % (len(FAILED), ", ".join(FAILED)) if FAILED else "\nall checks passed")
    sys.exit(1 if FAILED else 0)


def client(name, base):
    return boto3.client(name, endpoint_url=base, region_name="us-east-1", aws_access_key_id="AKIAEXAMPLE", aws_secret_access_key="secret",
                        config=Config(retries={"max_attempts": 1}))


def put_backing(base, token, name, doc):
    st, body = http_json("PUT", "%s/_rovara/sagemaker/endpoints/%s" % (base, name), token, doc)
    check("backing for %s accepted" % name, st == 200, (st, body))


def run(base, token, hport):
    sm, rt, s3, sns, sqs, cfn = (client(n, base) for n in ("sagemaker", "sagemaker-runtime", "s3", "sns", "sqs", "cloudformation"))
    summary = lambda name: http_json("GET", "%s/_rovara/sagemaker/endpoints/%s" % (base, name), token)[1]

    # ---- the code makes its endpoints through the front (the engine serves the control plane)
    s3.create_bucket(Bucket="smlive")
    topic_ok = sns.create_topic(Name="sm-ok")["TopicArn"]
    topic_bad = sns.create_topic(Name="sm-bad")["TopicArn"]
    q = sqs.create_queue(QueueName="sm-notify")["QueueUrl"]
    qarn = sqs.get_queue_attributes(QueueUrl=q, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"}, "Action": "sqs:SendMessage", "Resource": qarn}]}
    sqs.set_queue_attributes(QueueUrl=q, Attributes={"Policy": json.dumps(policy)})
    for t in (topic_ok, topic_bad):
        sns.subscribe(TopicArn=t, Protocol="sqs", Endpoint=qarn)

    def make(name, variants=("AllTraffic",), async_cfg=None):
        sm.create_model(ModelName=name, ExecutionRoleArn="arn:aws:iam::000000000000:role/r",
                        PrimaryContainer={"Image": "000000000000.dkr.ecr.us-east-1.amazonaws.com/img:1"})
        cfg = {"EndpointConfigName": name + "-cfg", "ProductionVariants": [
            {"VariantName": v, "ModelName": name, "InitialInstanceCount": 1, "InstanceType": "ml.m5.large", "InitialVariantWeight": 1.0} for v in variants]}
        if async_cfg:
            cfg["AsyncInferenceConfig"] = async_cfg
        sm.create_endpoint_config(**cfg)
        sm.create_endpoint(EndpointName=name, EndpointConfigName=name + "-cfg")

    async_cfg = {"OutputConfig": {"S3OutputPath": "s3://smlive/out", "S3FailurePath": "s3://smlive/err",
                                  "NotificationConfig": {"SuccessTopic": topic_ok, "ErrorTopic": topic_bad,
                                                         "IncludeInferenceResponseIn": ["SUCCESS_NOTIFICATION_TOPIC"]}}}
    make("canned", ("A", "B"), async_cfg)
    make("stand")
    make("image")
    make("plain")
    time.sleep(1.5)  # the engine's endpoints are InService after about a second
    d = sm.describe_endpoint(EndpointName="canned")
    check("DescribeEndpoint answers from the engine", d["EndpointStatus"] == "InService" and d["EndpointName"] == "canned", d)
    s = summary("canned")
    check("the table learned the endpoint from the calls", s.get("exists") and s["source"] == "api" and s["variants"] == ["A", "B"] and s["asyncConfigured"], s)

    # ---- invoke: canned answers
    put_backing(base, token, "canned", {"source": "recorded", "recordedOn": "2026-11-20", "asyncDelayMs": 50, "rules": [
        {"match": {"contentType": "application/json", "jsonPath": "$.id", "equals": 7},
         "response": {"json": {"score": 0.97}, "customAttributes": "trace=1", "variant": "A"}},
        {"match": {"jsonPath": "$.id", "equals": 8}, "response": {"error": {"code": "ModelError", "originalStatusCode": 500, "originalMessage": "the model fell over"}}},
        {"match": {"bodyContains": "stream-me"}, "response": {"body": "alpha beta gamma delta epsilon", "partSize": 7}},
        {"match": {"bodyContains": "broken"}, "response": {"parts": ["one", "two"], "streamError": {"errorCode": "StreamBroken", "message": "cut"}}},
        {"match": {"operation": "async", "jsonPath": "$.job"}, "response": {"json": {"result": "finished"}}},
        {"match": {"operation": "async", "jsonPath": "$.bad"}, "response": {"error": {"code": "ModelError", "originalStatusCode": 500, "originalMessage": "bad row"}}}],
        "default": {"body": "made-up answer", "contentType": "text/plain"}})
    r = rt.invoke_endpoint(EndpointName="canned", ContentType="application/json", Body=b'{"id": 7}', CustomAttributes="x")
    check("invoke: a matched canned answer", json.loads(r["Body"].read()) == {"score": 0.97} and r["ContentType"] == "application/json"
          and r["CustomAttributes"] == "trace=1" and r["InvokedProductionVariant"] == "A", r)
    r = rt.invoke_endpoint(EndpointName="canned", ContentType="text/csv", Accept="text/plain", Body=b"1,2,3")
    check("invoke: the default answer", r["Body"].read() == b"made-up answer" and r["ContentType"] == "text/plain", r)
    try:
        rt.invoke_endpoint(EndpointName="canned", ContentType="application/json", Body=b'{"id": 8}')
        check("invoke: a canned ModelError", False)
    except ClientError as e:
        er = e.response
        check("invoke: a canned ModelError (boto3 parses OriginalStatusCode)", er["Error"]["Code"] == "ModelError" and er["OriginalStatusCode"] == 500
              and er["OriginalMessage"] == "the model fell over" and er["ResponseMetadata"]["HTTPStatusCode"] == 424, er)
    try:
        rt.invoke_endpoint(EndpointName="canned", Body=b"x", TargetVariant="Z")
        check("invoke: an unknown variant", False)
    except ClientError as e:
        check("invoke: an unknown variant is a ValidationError", e.response["Error"]["Code"] == "ValidationError", e.response)
    r = rt.invoke_endpoint(EndpointName="canned", Body=b"x", TargetVariant="B")
    check("invoke: TargetVariant is honoured", r["InvokedProductionVariant"] == "B", r)

    # ---- errors
    try:
        rt.invoke_endpoint(EndpointName="does-not-exist", Body=b"x")
        check("unknown endpoint", False)
    except ClientError as e:
        er = e.response["Error"]
        check("unknown endpoint: ValidationError in AWS's words", er["Code"] == "ValidationError" and er["Message"] == "Endpoint does-not-exist of account 000000000000 not found.", er)
    put_backing(base, token, "plain", {})
    try:
        rt.invoke_endpoint(EndpointName="plain", ContentType="text/csv", Body=b"9,9")
        check("unmatched request", False)
    except ClientError as e:
        check("an unmatched request is a ModelError that names its hash", e.response["Error"]["Code"] == "ModelError" and "sha256" in e.response["Error"]["Message"], e.response)
    put_backing(base, token, "image", {"mode": "image"})
    try:
        rt.invoke_endpoint(EndpointName="image", Body=b"x")
        check("image mode", False)
    except ClientError as e:
        check("the customer's image: ServiceUnavailable, not available yet", e.response["Error"]["Code"] == "ServiceUnavailable"
              and "not available yet" in e.response["Error"]["Message"], e.response)
    try:
        rt.invoke_endpoint_async(EndpointName="plain", InputLocation="s3://smlive/in")
        check("async on an endpoint with no async config", False)
    except ClientError as e:
        check("async with no AsyncInferenceConfig is a ValidationError", e.response["Error"]["Code"] == "ValidationError", e.response)
    try:
        rt.invoke_endpoint(EndpointName="canned", Body=b"a" * (6 * 1024 * 1024 + 1))
        check("oversize body", False)
    except ClientError as e:
        check("a body over 6 MiB is a ValidationError", e.response["Error"]["Code"] == "ValidationError", e.response)

    # ---- invoke: the model stand-in
    r = rt.invoke_endpoint(EndpointName="stand", ContentType="text/csv", Accept="application/json", Body=b"4,5", CustomAttributes="c1")
    doc = json.loads(r["Body"].read())
    seen = Helper.seen[-1]
    seen_h = {k.lower(): v for k, v in seen["headers"].items()}
    check("model stand-in: the reply passes, with its custom attributes", doc == {"echo": "4,5", "ct": "text/csv"} and r["CustomAttributes"] == "from-model", (doc, r))
    check("model stand-in: it was sent only what SageMaker sends", seen["path"] == "/invocations" and seen_h.get("x-amzn-sagemaker-custom-attributes") == "c1"
          and "authorization" not in seen_h and "cookie" not in seen_h, seen_h)
    try:
        rt.invoke_endpoint(EndpointName="stand", Body=b"status400")
        check("model stand-in 400", False)
    except ClientError as e:
        check("model stand-in: its 400 is a ModelError with OriginalStatusCode 400", e.response["Error"]["Code"] == "ModelError"
              and e.response["OriginalStatusCode"] == 400 and e.response["OriginalMessage"] == "bad input", e.response)

    # ---- streaming (SM2): botocore's event stream parser reads the front's frames
    r = rt.invoke_endpoint_with_response_stream(EndpointName="canned", ContentType="text/plain", Body=b"please stream-me")
    parts = [ev["PayloadPart"]["Bytes"] for ev in r["Body"] if "PayloadPart" in ev]
    check("streaming: a canned body arrives as several PayloadPart events", len(parts) >= 4 and b"".join(parts) == b"alpha beta gamma delta epsilon", parts)
    r = rt.invoke_endpoint_with_response_stream(EndpointName="canned", Body=b"it is broken")
    got, err = [], None
    try:
        for ev in r["Body"]:
            got.append(ev.get("PayloadPart", {}).get("Bytes"))
    except Exception as e:  # botocore raises the modeled exception from the stream
        err = e
    check("streaming: a ModelStreamError event ends the stream and boto3 raises it", got == [b"one", b"two"] and err is not None and "ModelStreamError" in (type(err).__name__ + str(err)), (got, err))
    r = rt.invoke_endpoint_with_response_stream(EndpointName="stand", Body=b"stream")
    parts = [ev["PayloadPart"]["Bytes"] for ev in r["Body"] if "PayloadPart" in ev]
    check("streaming: the stand-in's chunked reply, part by part", b"".join(parts) == b"".join(b"data: token-%d\n\n" % i for i in range(4)) and len(parts) >= 2, parts)

    # ---- async: the output object is really in S3 and the notification really arrives
    def drain():
        msgs = []
        for _ in range(3):
            r = sqs.receive_message(QueueUrl=q, MaxNumberOfMessages=10, WaitTimeSeconds=1)
            for m in r.get("Messages", []):
                msgs.append(json.loads(json.loads(m["Body"])["Message"]) | {"_topic": json.loads(m["Body"])["TopicArn"]})
                sqs.delete_message(QueueUrl=q, ReceiptHandle=m["ReceiptHandle"])
        return msgs

    s3.put_object(Bucket="smlive", Key="in/job.json", Body=b'{"job": 1}')
    s3.put_object(Bucket="smlive", Key="in/bad.json", Body=b'{"bad": 1}')
    r = rt.invoke_endpoint_async(EndpointName="canned", InputLocation="s3://smlive/in/job.json", InferenceId="job-1", ContentType="application/json")
    check("async: 202 with the InferenceId and both locations", r["InferenceId"] == "job-1" and r["OutputLocation"] == "s3://smlive/out/job-1.out"
          and r["FailureLocation"] == "s3://smlive/err/job-1-error.out" and r["ResponseMetadata"]["HTTPStatusCode"] == 202, r)
    out = None
    for _ in range(50):
        try:
            out = s3.get_object(Bucket="smlive", Key="out/job-1.out")["Body"].read()
            break
        except ClientError:
            time.sleep(0.1)
    check("async: the output object appears in the engine's S3", out == b'{"result":"finished"}', out)
    notes = drain()
    ok = [n for n in notes if n.get("inferenceId") == "job-1"]
    check("async: the success notification arrives on the subscribed queue", len(ok) == 1 and ok[0]["invocationStatus"] == "Completed"
          and ok[0]["responseParameters"]["outputLocation"] == "s3://smlive/out/job-1.out" and ok[0]["_topic"] == topic_ok
          and ok[0]["responseBody"] == '{"result":"finished"}' and ok[0]["requestParameters"]["endpointName"] == "canned", notes)
    rt.invoke_endpoint_async(EndpointName="canned", InputLocation="s3://smlive/in/bad.json", InferenceId="job-2")
    err_obj = None
    for _ in range(50):
        try:
            err_obj = s3.get_object(Bucket="smlive", Key="err/job-2-error.out")["Body"].read()
            break
        except ClientError:
            time.sleep(0.1)
    check("async: a failing answer writes the failure object", err_obj is not None and b"bad row" in err_obj, err_obj)
    notes = drain()
    bad = [n for n in notes if n.get("inferenceId") == "job-2"]
    check("async: the error notification arrives on the error topic", len(bad) == 1 and bad[0]["invocationStatus"] == "Failed" and bad[0]["_topic"] == topic_bad
          and "bad row" in bad[0]["failureReason"], notes)

    # ---- the ledger and the control paths
    st, led = http_json("GET", "%s/_rovara/ledger/summary" % base, token)
    ops = led.get("sagemaker-runtime", {}).get("operations", {})
    check("ledger: usage under sagemaker-runtime", ops.get("InvokeEndpoint", {}).get("calls", 0) >= 8 and ops.get("InvokeEndpointAsync", {}).get("calls") == 3
          and ops.get("InvokeEndpointWithResponseStream", {}).get("calls") == 3, ops)
    st, ent = http_json("GET", "%s/_rovara/ledger?service=sagemaker-runtime" % base, token)
    markers = {e["operation"] + ":" + e.get("marker", "") for e in ent["entries"]}
    check("ledger: entries carry the faked markers", "InvokeEndpoint:recorded fake" in markers and "InvokeEndpoint:not available yet" in markers
          and "InvokeEndpoint:unplanned endpoint" in markers and "InvokeEndpoint:Rovara model stand-in" in markers, markers)
    s = summary("canned")
    check("control: counters for the endpoint", s["faked"] and s["backing"]["label"] == "recorded fake" and s["asyncCompleted"] == 1 and s["asyncFailed"] == 1
          and s["streamed"] == 2 and s["notTested"] == "real model behaviour" and s["madeUp"] >= 1, s)
    st, _ = http_json("GET", "%s/_rovara/sagemaker/endpoints" % base)
    check("control: the endpoint paths need the token", st == 403, st)

    # ---- CloudFormation: the engine creates nothing for these types; the front does it through the API
    tpl = {"Resources": {
        "Model": {"Type": "AWS::SageMaker::Model", "Properties": {"ModelName": "cfn-model", "ExecutionRoleArn": "arn:aws:iam::000000000000:role/r",
                                                                   "PrimaryContainer": {"Image": "000000000000.dkr.ecr.us-east-1.amazonaws.com/img:1"}}},
        "Config": {"Type": "AWS::SageMaker::EndpointConfig", "Properties": {"EndpointConfigName": "cfn-cfg", "ProductionVariants": [
            {"VariantName": "AllTraffic", "ModelName": {"Fn::GetAtt": ["Model", "ModelName"]}, "InstanceType": "ml.m5.large", "InitialInstanceCount": 1, "InitialVariantWeight": 1}]}},
        "Endpoint": {"Type": "AWS::SageMaker::Endpoint", "Properties": {"EndpointName": "cfn-endpoint", "EndpointConfigName": {"Fn::GetAtt": ["Config", "EndpointConfigName"]}}}}}
    cfn.create_stack(StackName="sm-stack", TemplateBody=json.dumps(tpl))
    for _ in range(100):
        status = cfn.describe_stacks(StackName="sm-stack")["Stacks"][0]["StackStatus"]
        if status.endswith("COMPLETE") or status.endswith("FAILED"):
            break
        time.sleep(0.2)
    check("cloudformation: the stack completes", status == "CREATE_COMPLETE", status)
    try:
        d = sm.describe_endpoint(EndpointName="cfn-endpoint")
        check("cloudformation: DescribeEndpoint answers for the declared endpoint (the engine's own CloudFormation made none)", d["EndpointName"] == "cfn-endpoint", d)
    except ClientError as e:
        check("cloudformation: DescribeEndpoint answers for the declared endpoint", False, e.response)
    put_backing(base, token, "cfn-endpoint", {"default": {"json": {"from": "cloudformation"}}})
    r = rt.invoke_endpoint(EndpointName="cfn-endpoint", Body=b"{}")
    check("cloudformation: the declared endpoint can be invoked", json.loads(r["Body"].read()) == {"from": "cloudformation"})
    check("cloudformation: it is in the table as cloudformation", summary("cfn-endpoint").get("source") == "cloudformation")

    # a stack that names nothing: CloudFormation makes the names up, the engine's are <stack>-<Id>-<12 hex>, and the stack's outputs carry them
    tpl2 = {"Resources": {
        "M": {"Type": "AWS::SageMaker::Model", "Properties": {"ExecutionRoleArn": "arn:aws:iam::000000000000:role/r",
                                                              "PrimaryContainer": {"Image": "000000000000.dkr.ecr.us-east-1.amazonaws.com/img:1"}}},
        "C": {"Type": "AWS::SageMaker::EndpointConfig", "Properties": {"ProductionVariants": [
            {"VariantName": "V1", "ModelName": {"Fn::GetAtt": ["M", "ModelName"]}, "InstanceType": "ml.m5.large", "InitialInstanceCount": 1, "InitialVariantWeight": 1}]}},
        "E": {"Type": "AWS::SageMaker::Endpoint", "Properties": {"EndpointConfigName": {"Fn::GetAtt": ["C", "EndpointConfigName"]}}}},
        "Outputs": {"Name": {"Value": {"Fn::GetAtt": ["E", "EndpointName"]}}}}
    cfn.create_stack(StackName="anon", TemplateBody=json.dumps(tpl2))
    for _ in range(100):
        stk = cfn.describe_stacks(StackName="anon")["Stacks"][0]
        if stk["StackStatus"].endswith("COMPLETE") or stk["StackStatus"].endswith("FAILED"):
            break
        time.sleep(0.2)
    anon = {o["OutputKey"]: o["OutputValue"] for o in stk.get("Outputs", [])}.get("Name", "")
    check("cloudformation: an unnamed endpoint takes the name the stack's outputs carry", anon.startswith("anon-E-") and summary(anon).get("exists") is True, anon)
    put_backing(base, token, anon, {"default": {"json": {"anon": True}}})
    check("cloudformation: the unnamed endpoint can be invoked by that name", json.loads(rt.invoke_endpoint(EndpointName=anon, Body=b"{}")["Body"].read()) == {"anon": True})
    check("cloudformation: and DescribeEndpoint knows it", sm.describe_endpoint(EndpointName=anon)["EndpointName"] == anon)

    # ---- reset: the engine restarts with empty state; the table goes with it, the counters stay
    st, _ = http_json("POST", "%s/_rovara/reset" % base, token)
    check("reset", st == 200, st)
    try:
        rt.invoke_endpoint(EndpointName="canned", Body=b"x")
        check("after a reset the endpoint is gone", False)
    except ClientError as e:
        check("after a reset the endpoint is gone", e.response["Error"]["Code"] == "ValidationError", e.response)
    check("after a reset the counters stay", summary("canned").get("calls", 0) > 5)
    # the seed declares an endpoint with its answers in one call
    st, rep = http_json("POST", "%s/_rovara/seed" % base, token, {"sagemaker": {"endpoints": [
        {"name": "seeded", "backing": {"source": "recorded", "default": {"json": {"seeded": True}}}}]}})
    check("seed: an endpoint with its backing", st == 200 and rep["ok"], rep)
    r = rt.invoke_endpoint(EndpointName="seeded", Body=b"{}")
    check("seed: the seeded endpoint answers and the engine knows it", json.loads(r["Body"].read()) == {"seeded": True}
          and client("sagemaker", base).describe_endpoint(EndpointName="seeded")["EndpointName"] == "seeded")


if __name__ == "__main__":
    main()
