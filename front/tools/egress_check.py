#!/usr/bin/env python3
"""Egress check of planned mode, against the real AWS Emulator, on Linux.

Starts the front (which runs the engine) with a plan that names the services that can reach out (SNS, EventBridge, Step Functions,
CloudFormation, S3, Lambda, SQS, IAM, STS, CloudWatch Logs), then drives each way a service can open a connection or run a
program: SNS http and https subscriptions and a Publish, EventBridge API destinations (and a rule that targets one), a Step
Functions HTTP task, a CloudFormation TemplateURL (http, https and a host that does not exist), S3 bucket notifications to a topic,
a queue and a function and an object put that triggers them, Lambda functions that open a socket and run a program, and a Lambda
function URL. Every target is a TEST-NET address or a name under .invalid, so a connection that did leave would be a stuck
SYN-SENT or a DNS query, never a delivery.

While it runs, a sampler lists every socket (TCP and UDP) of the front and of every process under it every 10 ms, and the set of
processes under the front. Pass: no socket of those processes has a peer outside 127.0.0.1 and ::1, no DNS or other UDP socket
appears, and the process set stays {front, engine}.

    egress_check.py --front-bin <rovara-aws-front> --engine-bin <aws-emulator> --python-boto3-ok
(needs boto3; run it with a python that has it)"""
import argparse
import io
import json
import os
import random
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import zipfile

import boto3
from botocore.config import Config

PLAN = "sns,sqs,s3,eventbridge,sfn,cloudformation,lambda,iam,sts,cloudwatch-logs,apigatewayv2,api-gateway"


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def tree(pid):
    seen, todo = [], [pid]
    while todo:
        p = todo.pop()
        if p in seen:
            continue
        seen.append(p)
        try:
            for tid in os.listdir(f"/proc/{p}/task"):
                try:
                    todo += [int(x) for x in open(f"/proc/{p}/task/{tid}/children").read().split()]
                except OSError:
                    pass
        except OSError:
            pass
    return seen


LOOPBACK = {"0100007F", "00000000000000000000000001000000", "0000000000000000FFFF00000100007F"}
UNSET = {"00000000", "00000000000000000000000000000000"}
TCP_STATES = {"01": "ESTAB", "02": "SYN-SENT", "03": "SYN-RECV", "04": "FIN-WAIT1", "05": "FIN-WAIT2", "06": "TIME-WAIT", "07": "CLOSE", "08": "CLOSE-WAIT", "09": "LAST-ACK", "0A": "LISTEN", "0B": "CLOSING"}


def net_table():
    """inode -> (proto, state, remote host as hex) for every TCP and UDP socket of the network namespace."""
    t = {}
    for name in ("tcp", "tcp6", "udp", "udp6"):
        try:
            lines = open(f"/proc/net/{name}").read().splitlines()[1:]
        except OSError:
            continue
        for ln in lines:
            f = ln.split()
            rem = f[2].rsplit(":", 1)[0]
            t[int(f[9])] = (name, TCP_STATES.get(f[3], f[3]), rem, f[1])
    return t


def inodes_of(pid):
    out = set()
    try:
        for fd in os.listdir(f"/proc/{pid}/fd"):
            try:
                l = os.readlink(f"/proc/{pid}/fd/{fd}")
            except OSError:
                continue
            if l.startswith("socket:["):
                out.add(int(l[8:-1]))
    except OSError:
        pass
    return out


class Sampler(threading.Thread):
    """Every few ms: the sockets of every process under `root` (read from /proc, not from ss, which is too slow to catch a
    short connection), and the set of processes. A socket is a finding when it is UDP at all (DNS, or any datagram) or its
    peer is not loopback."""

    def __init__(self, root):
        super().__init__(daemon=True)
        self.root, self.stop_ev = root, threading.Event()
        self.pids, self.bad, self.samples, self.sockets = set(), [], 0, set()

    def run(self):
        while not self.stop_ev.is_set():
            ps = tree(self.root)
            self.pids.update(ps)
            tab = net_table()
            self.samples += 1
            for p in ps:
                for ino in inodes_of(p):
                    ent = tab.get(ino)
                    if ent is None:
                        continue
                    name, state, rem, local = ent
                    self.sockets.add((p, name, state, rem, local))
                    if name.startswith("udp"):
                        self.bad.append(f"pid {p}: a UDP socket ({name} local {local} peer {rem})")
                    elif state != "LISTEN" and rem not in LOOPBACK and rem not in UNSET:
                        self.bad.append(f"pid {p}: {name} {state} peer {rem}")
            time.sleep(0.001)

    def stop(self):
        self.stop_ev.set()
        self.join()


def positive_control():
    """The sampler must see what it is looking for: a process that connects out (SYN-SENT to a TEST-NET address) and one that
    sends a DNS query."""
    code = ("import socket;s=socket.socket();s.settimeout(2.5);s.connect_ex(('203.0.113.7',80));"
            "import time;time.sleep(0.2)")
    p = subprocess.Popen([sys.executable, "-c", code])
    sm = Sampler(p.pid)
    sm.start()
    p.wait()
    time.sleep(0.05)
    sm.stop()
    code2 = "import socket\ntry:\n    socket.getaddrinfo('control.invalid', 80)\nexcept Exception:\n    pass\n"
    p2 = subprocess.Popen([sys.executable, "-c", code2])
    sm2 = Sampler(p2.pid)
    sm2.start()
    p2.wait()
    sm2.stop()
    return len(sm.bad) > 0, len(sm2.bad) > 0


def zip_of(code):
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        z.writestr("index.py", code)
    return b.getvalue()


# What a function can try. The engine runs the code itself; each variant imports as little as possible, so that a missing module in
# the engine's interpreter does not hide what the next line would do.
LAMBDA_CODES = {
    "socket": "def handler(e, c):\n    import socket\n    s = socket.create_connection(('203.0.113.20', 80), timeout=2)\n    return 'connected'\n",
    "_socket": "def handler(e, c):\n    import _socket\n    s = _socket.socket()\n    s.settimeout(2)\n    s.connect(('203.0.113.21', 80))\n    return 'connected'\n",
    "urllib": "def handler(e, c):\n    import urllib.request\n    return urllib.request.urlopen('http://hook.invalid/', timeout=2).status\n",
    "os.system": "def handler(e, c):\n    import os\n    return os.system('/bin/sh -c \"echo spawned > /tmp/egress-spawned\"')\n",
    "subprocess": "def handler(e, c):\n    import subprocess\n    return subprocess.run(['/bin/sh', '-c', 'echo hi'], capture_output=True).stdout.decode()\n",
    "popen": "def handler(e, c):\n    import os\n    return os.popen('echo hi').read()\n",
    "fs": "def handler(e, c):\n    return open('/etc/hostname').read()\n",
    "ctypes": "def handler(e, c):\n    import ctypes\n    return str(ctypes.CDLL(None))\n",
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--front-bin", required=True)
    ap.add_argument("--engine-bin", required=True)
    ap.add_argument("--out", default="egress_check.json")
    a = ap.parse_args()
    port, work = free_port(), tempfile.mkdtemp()
    token = "tk" + "".join(random.choice("abcdef0123456789") for _ in range(24))
    env = {"HOME": work, "PATH": "/usr/bin:/bin", "QUARKUS_HTTP_HOST": "127.0.0.1", "QUARKUS_HTTP_PORT": str(port),
           "ROVARA_AWS_BASE_URL": f"http://127.0.0.1:{port}", "ROVARA_AWS_AUTH_PRESIGN_SECRET": "ps" + token,
           "ROVARA_AWS_SERVICES_SQS_RECEIPT_HANDLE_SECRET": "rc" + token, "ROVARA_AWS_CONTROL_TOKEN": token,
           "ROVARA_AWS_DEFAULT_REGION": "us-east-1", "ROVARA_AWS_HOSTNAME": "127.0.0.1", "ROVARA_AWS_ENGINE_BIN": a.engine_bin,
           "ROVARA_AWS_FRONT_WORKDIR": work, "ROVARA_AWS_PLANNED_SERVICES": PLAN}
    front = subprocess.Popen([a.front_bin], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    ep = f"http://127.0.0.1:{port}"
    import urllib.request
    for _ in range(300):
        try:
            if urllib.request.urlopen(ep + "/_rovara/health", timeout=1).status == 200:
                break
        except Exception:
            time.sleep(0.1)
    seen_connect, seen_dns = positive_control()
    print(f"sampler positive control: a connect to a TEST-NET address is {'seen' if seen_connect else 'NOT SEEN'}; a DNS lookup is {'seen' if seen_dns else 'not seen (too short for the sampler; the sockets are still listed)'}")
    sampler = Sampler(front.pid)
    sampler.start()
    cfg = Config(retries={"max_attempts": 1}, connect_timeout=5, read_timeout=40)
    kw = dict(endpoint_url=ep, region_name="us-east-1", aws_access_key_id="AK", aws_secret_access_key="SK", config=cfg)
    results = []

    def step(name, fn):
        t0 = time.time()
        try:
            r = fn()
            results.append((name, "ok", str(r)[:300], round(time.time() - t0, 2)))
        except Exception as e:  # the call may legitimately be refused; what matters is the network
            results.append((name, type(e).__name__, str(e)[:400], round(time.time() - t0, 2)))

    tmpl = json.dumps({"Resources": {"Q": {"Type": "AWS::SQS::Queue"}}})
    sns, sqs, s3, ev = boto3.client("sns", **kw), boto3.client("sqs", **kw), boto3.client("s3", **kw), boto3.client("events", **kw)
    sfn, cfn, lam, iam = boto3.client("stepfunctions", **kw), boto3.client("cloudformation", **kw), boto3.client("lambda", **kw), boto3.client("iam", **kw)
    topic = {}

    def make_topic():
        topic["arn"] = sns.create_topic(Name="egress-t")["TopicArn"]
        return topic["arn"]

    step("sns create topic", make_topic)
    for proto, endpoint in (("http", "http://203.0.113.7/hook"), ("https", "https://203.0.113.8/hook"), ("http", "http://hook.invalid/h"),
                            ("https", "https://hook.invalid/h"), ("email", "nobody@example.invalid"), ("sms", "+15555550100")):
        step(f"sns subscribe {proto} {endpoint}", lambda p=proto, e=endpoint: sns.subscribe(TopicArn=topic["arn"], Protocol=p, Endpoint=e, ReturnSubscriptionArn=True)["SubscriptionArn"])
    step("sns publish", lambda: sns.publish(TopicArn=topic["arn"], Message="hello", Subject="s")["MessageId"])
    step("sns publish again", lambda: sns.publish(TopicArn=topic["arn"], Message="again")["MessageId"])

    conn = {}

    def make_conn():
        conn["arn"] = ev.create_connection(Name="egress-c", AuthorizationType="API_KEY",
                                           AuthParameters={"ApiKeyAuthParameters": {"ApiKeyName": "k", "ApiKeyValue": "v"}})["ConnectionArn"]
        return conn["arn"]

    step("events create connection", make_conn)
    step("events create api destination https", lambda: ev.create_api_destination(Name="egress-d", ConnectionArn=conn["arn"], InvocationEndpoint="https://203.0.113.9/x", HttpMethod="POST")["ApiDestinationArn"])
    step("events create api destination http", lambda: ev.create_api_destination(Name="egress-d2", ConnectionArn=conn["arn"], InvocationEndpoint="http://hook.invalid/x", HttpMethod="POST")["ApiDestinationArn"])
    step("events rule", lambda: ev.put_rule(Name="egress-r", EventPattern=json.dumps({"source": ["egress"]}))["RuleArn"])
    step("events target api destination", lambda: ev.put_targets(Rule="egress-r", Targets=[{"Id": "1", "Arn": f"arn:aws:events:us-east-1:000000000000:api-destination/egress-d/x",
                                                                                       "RoleArn": "arn:aws:iam::000000000000:role/r"}]))
    step("events put events", lambda: ev.put_events(Entries=[{"Source": "egress", "DetailType": "t", "Detail": "{}"}]))

    role = {}

    def make_role():
        role["arn"] = iam.create_role(RoleName="egress-role", AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Principal": {"Service": ["lambda.amazonaws.com", "states.amazonaws.com", "events.amazonaws.com"]}, "Action": "sts:AssumeRole"}]}))["Role"]["Arn"]
        return role["arn"]

    step("iam role", make_role)
    definition = json.dumps({"StartAt": "H", "States": {"H": {"Type": "Task", "Resource": "arn:aws:states:::http:invoke", "Parameters": {
        "ApiEndpoint": "https://203.0.113.10/api", "Method": "GET", "Authentication": {"ConnectionArn": conn.get("arn", "arn:aws:events:us-east-1:000000000000:connection/egress-c/x")}}, "End": True}}})
    sm = {}
    step("sfn create state machine", lambda: sm.setdefault("arn", sfn.create_state_machine(name="egress-sm", definition=definition, roleArn=role["arn"])["stateMachineArn"]))
    step("sfn start execution", lambda: sfn.start_execution(stateMachineArn=sm["arn"], input="{}")["executionArn"])
    time.sleep(2)

    for i, url in enumerate(("http://203.0.113.11/t.json", "https://203.0.113.11/t.json", "https://hook.invalid/t.json", "https://s3.amazonaws.com/b/t.json")):
        step(f"cfn create stack TemplateURL {url}", lambda i=i, url=url: cfn.create_stack(StackName=f"egress-{i}", TemplateURL=url)["StackId"])
    step("cfn validate TemplateURL", lambda: cfn.validate_template(TemplateURL="http://203.0.113.11/v.json"))
    step("cfn create stack with a template body (an SQS queue: the plan names sqs)", lambda: cfn.create_stack(StackName="egress-body", TemplateBody=tmpl)["StackId"])

    kms_tmpl = json.dumps({"Resources": {"K": {"Type": "AWS::KMS::Key", "Properties": {"KeyPolicy": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "kms:*", "Resource": "*"}]}}}}})
    step("cfn stack that creates a KMS key (kms is not in the plan: in-engine, not gated)", lambda: cfn.create_stack(StackName="egress-kms", TemplateBody=kms_tmpl)["StackId"])
    step("cfn stack status", lambda: (time.sleep(3), cfn.describe_stacks(StackName="egress-kms")["Stacks"][0]["StackStatus"], [r["ResourceStatus"] for r in cfn.describe_stack_resources(StackName="egress-kms")["StackResources"]])[1:])
    step("s3 bucket", lambda: s3.create_bucket(Bucket="egress-b"))
    step("sqs queue", lambda: sqs.create_queue(QueueName="egress-q")["QueueUrl"])
    step("lambda create function", lambda: lam.create_function(FunctionName="egress-fn", Runtime="python3.12", Role=role["arn"], Handler="index.handler", Code={"ZipFile": zip_of(LAMBDA_CODES["socket"])})["FunctionArn"])
    for name, code in LAMBDA_CODES.items():
        step(f"lambda create function {name}", lambda name=name, code=code: lam.create_function(FunctionName="egress-" + name.replace(".", "-").replace("_", ""), Runtime="python3.12", Role=role["arn"], Handler="index.handler", Code={"ZipFile": zip_of(code)})["FunctionArn"])
    def flt(prefix):
        return {"Key": {"FilterRules": [{"Name": "prefix", "Value": prefix}]}}

    dest = {"topic": ("TopicConfigurations", {"TopicArn": topic["arn"]}, "t/"),
            "queue": ("QueueConfigurations", {"QueueArn": "arn:aws:sqs:us-east-1:000000000000:egress-q"}, "q/"),
            "lambda": ("LambdaFunctionConfigurations", {"LambdaFunctionArn": "arn:aws:lambda:us-east-1:000000000000:function:egress-fn"}, "l/")}
    step("lambda permission for s3", lambda: lam.add_permission(FunctionName="egress-fn", StatementId="s3", Action="lambda:InvokeFunction", Principal="s3.amazonaws.com", SourceArn="arn:aws:s3:::egress-b"))
    step("sqs permission for s3", lambda: sqs.set_queue_attributes(QueueUrl=sqs.get_queue_url(QueueName="egress-q")["QueueUrl"], Attributes={"Policy": json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sqs:SendMessage", "Resource": "*"}]})}))
    step("sns permission for s3", lambda: sns.set_topic_attributes(TopicArn=topic["arn"], AttributeName="Policy", AttributeValue=json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sns:Publish", "Resource": topic["arn"]}]})))
    for name, (field, target, prefix) in dest.items():
        step(f"s3 notification to a {name}", lambda field=field, target=target, prefix=prefix: s3.put_bucket_notification_configuration(Bucket="egress-b", NotificationConfiguration={
            field: [dict(target, Events=["s3:ObjectCreated:*"], Filter=flt(prefix))]}))
    step("s3 notification to a topic, a queue and a function at once", lambda: s3.put_bucket_notification_configuration(Bucket="egress-b", NotificationConfiguration={
        field: [dict(target, Events=["s3:ObjectCreated:*"], Filter=flt(prefix))] for field, target, prefix in dest.values()}))
    for key in ("t/1", "q/1", "l/1"):
        step(f"s3 put object {key}", lambda key=key: s3.put_object(Bucket="egress-b", Key=key, Body=b"x")["ETag"])
    step("s3 put template", lambda: s3.put_object(Bucket="egress-b", Key="t.json", Body=tmpl.encode())["ETag"])
    step("cfn create stack from the engine's own S3", lambda: cfn.create_stack(StackName="egress-s3", TemplateURL=f"https://s3.amazonaws.com/egress-b/t.json")["StackId"])

    def active():
        for _ in range(100):
            if lam.get_function(FunctionName="egress-fn")["Configuration"].get("State") == "Active":
                return "Active"
            time.sleep(0.2)
        return "not active"

    step("lambda wait active", active)
    time.sleep(1)
    for name in LAMBDA_CODES:
        fn = "egress-" + name.replace(".", "-").replace("_", "")
        step(f"lambda invoke {name}", lambda fn=fn: lam.invoke(FunctionName=fn, Payload=b"{}")["Payload"].read().decode()[:300])
    step("lambda invoke", lambda: lam.invoke(FunctionName="egress-fn", Payload=b"{}")["Payload"].read())
    step("lambda invoke async", lambda: lam.invoke(FunctionName="egress-fn", InvocationType="Event", Payload=b"{}")["StatusCode"])
    step("sns subscription states", lambda: [x["SubscriptionArn"][-6:] + ":" + x["Protocol"] for x in sns.list_subscriptions_by_topic(TopicArn=topic["arn"])["Subscriptions"]])
    step("sfn execution status", lambda: sfn.list_executions(stateMachineArn=sm["arn"])["executions"][0]["status"])
    step("lambda function url", lambda: lam.create_function_url_config(FunctionName="egress-fn", AuthType="NONE")["FunctionUrl"])
    step("lambda event source: sqs", lambda: lam.create_event_source_mapping(FunctionName="egress-fn", EventSourceArn="arn:aws:sqs:us-east-1:000000000000:egress-q")["UUID"])
    step("lambda layer from a url-less zip", lambda: lam.publish_layer_version(LayerName="egress-l", Content={"ZipFile": zip_of("x=1")})["LayerVersionArn"])
    time.sleep(4)
    # the stack above created a KMS key in the engine although the plan does not name kms: the front recorded it
    led = json.loads(urllib.request.urlopen(urllib.request.Request(ep + "/_rovara/ledger/summary", headers={"x-rovara-control-token": token}), timeout=10).read())
    recorded = led.get("kms", {})
    print("ledger: kms outOfPlan =", recorded.get("outOfPlan"), "operations", list(recorded.get("operations", {})), "| unchecked:", led.get("cloudformation-unchecked", {}).get("operations"))
    sampler.stop()
    front.terminate()
    try:
        front.wait(10)
    except Exception:
        front.kill()
    shutil.rmtree(work, ignore_errors=True)
    for r in results:
        print(f"{r[0]:70} {r[1]:28} {r[3]:>5}s  {r[2]}")
    non_loop = sorted(sampler.bad)
    summary = dict(sampler_sees_a_connect=seen_connect, sampler_sees_dns=seen_dns, samples=sampler.samples, processes_seen=len(sampler.pids), distinct_sockets=len(sampler.sockets), non_loopback=non_loop[:20],
                   calls=len(results), refused_or_failed=[r[0] for r in results if r[1] != "ok"])
    json.dump(dict(summary=summary, results=results, sockets=sorted(map(list, sampler.sockets))[:200]), open(a.out, "w"), indent=1)
    print(json.dumps(summary, indent=1))
    ok = not non_loop and len(sampler.pids) <= 2 and seen_connect and recorded.get("outOfPlan", 0) >= 1
    print("egress_check:", "PASS: no connection left 127.0.0.1 and the engine spawned no process" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
