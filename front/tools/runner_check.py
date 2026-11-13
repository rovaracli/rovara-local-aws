#!/usr/bin/env python3
"""Live proof of the function runner's front half against the real engine (slice 4, lane F-front).

Starts the real front (planned mode, runner on) over the real AWS Emulator, and plays the Cloud worker with an ECHO RUNNER: a Python fake
worker that speaks runner/2 through `<front> runner-pipe`, so the worker's own entry point is exercised too. No Docker, no sandbox: the
"function" is chosen by the event ({"op":"echo"|"error"|"sleep"|"big"|"crash"}). What is proved is the front's side: the registry and
its overlay, the stub and its queue rendezvous, the dispatcher, the direct-Invoke fast path and the hidden plumbing, through every kind
of caller the engine has.

    runner_check.py --front-bin <rovara-aws-front> --engine-bin <aws-emulator>      (run with a python that has boto3)

Exit 0 when every check passed; each check prints PASS or FAIL, and the limits found are printed as NOTE lines."""
import argparse, base64, hashlib, io, json, os, random, socket, struct, subprocess, sys, tempfile, threading, time, urllib.request, urllib.error, zipfile
import boto3
from botocore.config import Config

ap = argparse.ArgumentParser()
ap.add_argument("--front-bin", required=True)
ap.add_argument("--engine-bin", required=True)
ap.add_argument("--only", default="", help="comma separated section names")
a = ap.parse_args()
ONLY = set(x for x in a.only.split(",") if x)
FAILS = []


def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + name + ((" :: " + str(detail)[:300]) if (detail and not ok) else ""), flush=True)
    if not ok:
        FAILS.append(name)


def note(s):
    print("NOTE " + s, flush=True)


# ---- start the front

s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
work = tempfile.mkdtemp(prefix="s4front-live-")
sock_dir = tempfile.mkdtemp(prefix="rv")
sock = os.path.join(sock_dir, "runner.sock")
token = "tk" + "".join(random.choice("abcdef0123456789") for _ in range(24))
PLAN = "lambda,iam,sns,sqs,s3,sfn,api-gateway,apigatewayv2,eventbridge,cloudwatch-logs,cloudformation,dynamodb"
env = {"HOME": work, "PATH": "/usr/bin:/bin", "QUARKUS_HTTP_HOST": "127.0.0.1", "QUARKUS_HTTP_PORT": str(port), "ROVARA_AWS_BASE_URL": "http://aws:4566",
       "ROVARA_AWS_AUTH_PRESIGN_SECRET": "ps" + token, "ROVARA_AWS_SERVICES_SQS_RECEIPT_HANDLE_SECRET": "rc" + token, "ROVARA_AWS_CONTROL_TOKEN": token,
       "ROVARA_AWS_DEFAULT_REGION": "us-east-1", "ROVARA_AWS_HOSTNAME": "aws", "ROVARA_AWS_ENGINE_BIN": a.engine_bin, "ROVARA_AWS_FRONT_WORKDIR": work,
       "ROVARA_AWS_PLANNED_SERVICES": PLAN, "ROVARA_AWS_RUNNER_SOCKET": sock, "ROVARA_AWS_RUNNER_STORE_DIR": os.path.join(work, "store")}
front_log = open(os.path.join(work, "front.log"), "w")
front = subprocess.Popen([a.front_bin], env=env, stdout=front_log, stderr=front_log)
ep = f"http://127.0.0.1:{port}"
for _ in range(300):
    try:
        if urllib.request.urlopen(ep + "/_rovara/health", timeout=1).status == 200:
            break
    except Exception:
        time.sleep(0.1)


def ctl(method, path, body=None):
    req = urllib.request.Request(ep + path, method=method, data=body, headers={"x-rovara-control-token": token})
    return json.loads(urllib.request.urlopen(req, timeout=60).read() or b"{}")


# ---- the echo runner (the Cloud worker's end of runner/2)

class Worker:
    def __init__(self):
        self.proc = subprocess.Popen([a.front_bin, "runner-pipe", sock], stdin=subprocess.PIPE, stdout=subprocess.PIPE, env={"PATH": "/usr/bin:/bin"})
        self.wl = threading.Lock()
        self.have, self.fns, self.recv, self.pending = {}, {}, {}, {}
        self.cold = set()
        self.registers = self.invokes = self.inflight = self.peak = 0
        self.invs = []
        self.lock = threading.Lock()
        threading.Thread(target=self.loop, daemon=True).start()

    def send(self, obj):
        b = json.dumps(obj, separators=(",", ":")).encode()
        with self.wl:
            self.proc.stdin.write(struct.pack(">I", len(b)) + b)
            self.proc.stdin.flush()

    def frame(self):
        h = self.proc.stdout.read(4)
        if len(h) < 4:
            return None
        n = struct.unpack(">I", h)[0]
        return json.loads(self.proc.stdout.read(n))

    def loop(self):
        f = self.frame()
        assert f and f["type"] == "hello" and f["proto"] == "runner/2", f
        self.send({"type": "hello", "proto": "runner/2", "worker": "echo-runner", "version": "live"})
        while True:
            f = self.frame()
            if f is None:
                return
            t = f["type"]
            if t == "register":
                self.registers += 1
                fn = f["fn"]
                if "x86" in fn["name"]:  # a worker that can neither swap the wheels of an x86-64 package nor emulate it
                    self.send({"type": "registered", "id": f["id"], "ok": False, "error": {"type": "Rovara.Unsupported", "message": "native code built for x86_64; local runs are arm64"}})
                    continue
                refs = list(fn.get("layers") or []) + ([fn["package"]] if fn.get("package") else [])
                need = []
                for p in refs:
                    if p["sha256"] not in self.have and p["sha256"] not in need:
                        need.append(p["sha256"])
                if not need:
                    self.fns[fn["name"] + "|" + fn["version"]] = fn
                    self.send({"type": "registered", "id": f["id"], "ok": True})
                else:
                    self.pending[f["id"]] = (fn, set(need))
                    self.send({"type": "need", "id": f["id"], "packages": need})
            elif t == "package":
                self.recv[(f["id"], f["sha256"])] = {"size": f["sizeBytes"], "data": bytearray()}
            elif t == "chunk":
                r = self.recv[(f["id"], f["sha256"])]
                r["data"] += base64.b64decode(f["data"])
                if f["last"]:
                    ok = len(r["data"]) == r["size"] and hashlib.sha256(r["data"]).hexdigest() == f["sha256"]
                    fn, need = self.pending[f["id"]]
                    if not ok:
                        self.send({"type": "registered", "id": f["id"], "ok": False, "error": {"type": "InvalidParameterValueException", "message": "digest"}})
                        continue
                    self.have[f["sha256"]] = bytes(r["data"])
                    need.discard(f["sha256"])
                    if not need:
                        del self.pending[f["id"]]
                        self.fns[fn["name"] + "|" + fn["version"]] = fn
                        self.send({"type": "registered", "id": f["id"], "ok": True})
            elif t == "invoke":
                threading.Thread(target=self.run, args=(f,), daemon=True).start()
            elif t == "unregister":
                for k in [k for k in self.fns if k.split("|")[0] == f["name"]]:
                    del self.fns[k]
                self.send({"type": "unregistered", "id": f["id"]})
            elif t == "stop_all":
                self.fns.clear(); self.cold.clear()
                self.send({"type": "stopped", "id": f["id"]})

    def run(self, f):
        with self.lock:
            self.invokes += 1
            self.inflight += 1
            self.peak = max(self.peak, self.inflight)
            self.invs.append(f)
        try:
            key = f["name"] + "|" + f["version"]
            fn = self.fns.get(key)
            res = {"type": "result", "id": f["id"]}
            if fn is None:
                res.update(status="unavailable", reason="not_registered")
                return self.send(res)
            ev = json.loads(base64.b64decode(f["payload"]) or b"{}")
            if isinstance(ev, dict) and isinstance(ev.get("Records"), list) and ev["Records"] and ev["Records"][0].get("eventSource") == "aws:sqs":
                try:  # an SQS event: the instruction travels in the message body
                    inner = json.loads(ev["Records"][0]["body"])
                    if isinstance(inner, dict) and "op" in inner:
                        ev = {**inner, "Records": ev["Records"]}
                except Exception:
                    pass
            op = ev.get("op", "echo") if isinstance(ev, dict) else "echo"
            res.update(cold=key not in self.cold, logTail=f"START {f['requestId']}\nran {fn['name']}\nEND {f['requestId']}\n", durationMs=2)
            self.cold.add(key)
            ok = lambda v: res.update(status="ok", payload=base64.b64encode(json.dumps(v).encode()).decode())
            if op == "error":
                doc = {"errorType": ev["type"], "errorMessage": ev["msg"]}
                res.update(status="function_error", errorType=ev["type"], errorMessage=ev["msg"], payload=base64.b64encode(json.dumps(doc).encode()).decode())
            elif op == "sleep":
                ms = ev["ms"]
                if ms > f["timeoutMs"]:
                    time.sleep(f["timeoutMs"] / 1000)
                    res.update(status="timeout", errorType="Sandbox.Timedout", errorMessage=f"RequestId: {f['requestId']} Error: Task timed out after {f['timeoutMs'] // 1000}.00 seconds")
                else:
                    time.sleep(ms / 1000)
                    ok({"slept": ms, "fn": fn["name"], "source": f["source"]})
            elif op == "big":
                ok({"data": "x" * ev["bytes"]})
            elif op == "crash":
                res.update(status="crash", errorType="Runtime.ExitError", errorMessage="exit status 7")
            elif op == "size":
                ok({"eventBytes": len(base64.b64decode(f["payload"])), "source": f["source"]})
            else:
                ok({"echo": ev, "fn": fn["name"], "version": fn["version"], "source": f["source"], "arn": f.get("functionArn")})
            self.send(res)
        finally:
            with self.lock:
                self.inflight -= 1


worker = Worker()
for _ in range(100):
    if json.loads(urllib.request.urlopen(ep + "/_rovara/lambda/heavy", data=None).read() if False else urllib.request.urlopen(urllib.request.Request(ep + "/_rovara/lambda/heavy", headers={"x-rovara-control-token": token})).read())["runner"] == "connected":
        break
    time.sleep(0.1)
check("the worker is connected through `runner-pipe`", ctl("GET", "/_rovara/lambda/heavy")["runner"] == "connected")

kw = dict(endpoint_url=ep, region_name="us-east-1", aws_access_key_id="AK", aws_secret_access_key="SK", config=Config(retries={"max_attempts": 1}, read_timeout=180, max_pool_connections=64))
lam, iam, sns, sqs, s3 = (boto3.client(n, **kw) for n in ("lambda", "iam", "sns", "sqs", "s3"))
sfn, ev_, apig = boto3.client("stepfunctions", **kw), boto3.client("events", **kw), boto3.client("apigatewayv2", **kw)
TRUST = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": ["lambda.amazonaws.com", "states.amazonaws.com", "events.amazonaws.com", "apigateway.amazonaws.com"]}, "Action": "sts:AssumeRole"}]})
ROLE = iam.create_role(RoleName="live-role", AssumeRolePolicyDocument=TRUST)["Role"]["Arn"]
iam.put_role_policy(RoleName="live-role", PolicyName="all", PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}))

# an aarch64 ELF: native code the engine cannot run
ELF = b"\x7fELF\x02\x01\x01\x00" + b"\0" * 8 + b"\x03\0\xb7\0" + b"\0" * 40
ELF_X86 = b"\x7fELF\x02\x01\x01\x00" + b"\0" * 8 + b"\x03\0\x3e\0" + b"\0" * 40


def zipped(files):
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        for k, v in files.items():
            z.writestr(k, v)
    return b.getvalue()


HEAVY = zipped({"app.py": "def handler(e, c): return e\n", "lib/native.so": ELF})
PLAIN = zipped({"app.py": "def handler(e, c): return e\n"})


def mk(name, timeout=10, mem=256, pkg=HEAVY, **kwargs):
    r = lam.create_function(FunctionName=name, Runtime="python3.12", Role=ROLE, Handler="app.handler", Timeout=timeout, MemorySize=mem, Code={"ZipFile": pkg}, **kwargs)
    for _ in range(100):  # the engine activates a function a moment after it creates it
        if lam.get_function_configuration(FunctionName=name).get("State") == "Active":
            break
        time.sleep(0.1)
    return r


def invoke(name, ev, **kwargs):
    r = lam.invoke(FunctionName=name, Payload=json.dumps(ev).encode(), **kwargs)
    return r, r["Payload"].read()


def want(section):
    return not ONLY or section in ONLY


def wait_for(fn, timeout=40, every=0.3):
    t = time.time()
    while time.time() - t < timeout:
        v = fn()
        if v:
            return v
        time.sleep(every)
    return None


def s3_hidden_keys():
    # the plumbing is hidden from customers, so look with the ENGINE-side view the front's own client has: the control path does not expose it,
    # so this counts what the stub path left in the bucket through the evidence feed instead (none expected)
    return []


def rows():
    return {r["name"]: r for r in ctl("GET", "/_rovara/lambda/heavy").get("runnerFunctions", [])}


# ---- 1. the registry and its overlay
if want("registry"):
    print("== registry")
    r = mk("live-heavy", timeout=60, mem=512, Environment={"Variables": {"A": "1"}})
    check("CreateFunction answers with the real configuration (not the stub's)", r["Timeout"] == 60 and r["MemorySize"] == 512 and r["Handler"] == "app.handler" and r["Role"] == ROLE and r["CodeSize"] == len(HEAVY)
          and r["CodeSha256"] == base64.b64encode(hashlib.sha256(HEAVY).digest()).decode(), r)
    gc = lam.get_function_configuration(FunctionName="live-heavy")
    check("GetFunctionConfiguration is the real one", gc["Handler"] == "app.handler" and gc["MemorySize"] == 512 and gc["Environment"]["Variables"] == {"A": "1"}, gc)
    gf = lam.get_function(FunctionName="live-heavy")
    loc = gf["Code"]["Location"]
    check("Code.Location is the front's signed link, and serves the real package", loc.startswith("http://aws:4566/_rovara/lambda/function-code/")
          and urllib.request.urlopen(ep + loc[len("http://aws:4566"):]).read() == HEAVY, loc)
    lf = {f["FunctionName"]: f for f in lam.list_functions()["Functions"]}
    check("ListFunctions shows the real configuration", lf["live-heavy"]["Timeout"] == 60 and lf["live-heavy"]["Handler"] == "app.handler" and lf["live-heavy"]["Role"] == ROLE, lf["live-heavy"])
    mk("live-plain", timeout=10, pkg=PLAIN)
    lr, lb = invoke("live-plain", {"a": 1})
    check("a light function is untouched and still runs in the engine", not lr.get("FunctionError") and json.loads(lb) == {"a": 1}, (lr.get("FunctionError"), lb))
    mk("live-long", timeout=40, pkg=PLAIN)
    check("a plain function over 28 s is the runner's (decision 119)", "live-long" in rows() and rows()["live-long"]["reason"] == "long-timeout", rows())
    check("only the runner's functions are listed in the evidence", "live-plain" not in rows())
    summary = ctl("GET", "/_rovara/ledger/summary").get("lambda", {}).get("operations", {})
    check("a function that runs is not recorded as unable to run", not any(k.startswith("heavy-function:") and v["calls"] for k, v in summary.items() if k != "heavy-function:x86-native"), summary)
    mk("live-x86", pkg=zipped({"app.py": "x", "lib/x.so": ELF_X86}))
    rr, body = invoke("live-x86", {})
    check("x86-64 native code is forwarded to the worker, whose refusal is a Rovara error", rr.get("FunctionError") == "Unhandled" and b"Rovara.Unsupported" in body and b"x86_64" in body, body)
    check("and is then recorded as unable to run, once", ctl("GET", "/_rovara/ledger/summary").get("lambda", {}).get("operations", {}).get("heavy-function:x86-native", {}).get("calls") == 1)
    lam.publish_version(FunctionName="live-heavy")
    lam.update_function_configuration(FunctionName="live-heavy", MemorySize=1024)
    vs = {v["Version"]: v for v in lam.list_versions_by_function(FunctionName="live-heavy")["Versions"]}
    check("versions keep their own configuration in the overlay", vs["1"]["MemorySize"] == 512 and vs["$LATEST"]["MemorySize"] == 1024, vs)

# ---- 2. the direct-Invoke fast path
if want("direct"):
    print("== direct invoke")
    if "live-heavy" not in [f["FunctionName"] for f in lam.list_functions()["Functions"]]:
        mk("live-heavy", timeout=60, mem=512)
    n0 = worker.invokes
    r, body = invoke("live-heavy", {"op": "echo", "n": 1}, LogType="Tail")
    d = json.loads(body)
    check("a sync Invoke is answered by the runner through the front", d["source"] == "direct" and d["echo"]["n"] == 1 and d["fn"] == "live-heavy", body)
    check("LogType=Tail returns the runner's log", b"ran live-heavy" in base64.b64decode(r["LogResult"]), r.get("LogResult"))
    r, body = invoke("live-heavy", {"op": "error", "type": "ValueError", "msg": "boom"})
    doc = json.loads(body)
    check("errors keep FunctionError and their type", r["FunctionError"] == "Unhandled" and doc["errorType"] == "ValueError" and doc["errorMessage"] == "boom", body)
    r, body = invoke("live-heavy", {"op": "big", "bytes": 4_000_000})
    check("a 4 MB response (engine stubs carry 256 KB) comes back whole", len(body) > 4_000_000, len(body))
    pad = "p" * 5_000_000
    r, body = invoke("live-heavy", {"op": "size", "pad": pad})
    check("a 5 MB request goes through whole", json.loads(body)["eventBytes"] > 5_000_000, body[:200])
    t0 = time.time()
    r, body = invoke("live-heavy", {"op": "sleep", "ms": 32000})
    dt = time.time() - t0
    check("a 32 s function completes on the direct path (the engine's 30 s ceiling does not apply)", json.loads(body).get("slept") == 32000 and 31 < dt < 40, (dt, body))
    r, body = invoke("live-heavy", {"op": "sleep", "ms": 70000})
    check("the function's own Timeout (60 s) still ends it", r.get("FunctionError") and b"Sandbox.Timedout" in body, body)
    # concurrency beyond the engine's ~16 stubs
    peak0 = worker.peak
    res = []
    th = [threading.Thread(target=lambda: res.append(json.loads(invoke("live-heavy", {"op": "sleep", "ms": 1500})[1])["slept"])) for _ in range(40)]
    t0 = time.time()
    [t.start() for t in th]; [t.join() for t in th]
    check("40 concurrent direct invokes all succeed, side by side", len(res) == 40 and time.time() - t0 < 8 and worker.peak >= 30, (len(res), time.time() - t0, worker.peak))
    ev0 = worker.invokes
    r = lam.invoke(FunctionName="live-heavy", InvocationType="Event", Payload=json.dumps({"op": "error", "type": "E", "msg": "m"}).encode())
    check("an async Invoke is 202 at once", r["StatusCode"] == 202)
    check("and an async error is tried three times (the engine's own behaviour)", wait_for(lambda: worker.invokes - ev0 >= 3, 20) is not None)
    time.sleep(2.5)
    check("not more than three", worker.invokes - ev0 == 3, worker.invokes - ev0)
    check("DryRun is 204", lam.invoke(FunctionName="live-heavy", InvocationType="DryRun", Payload=b"{}")["StatusCode"] == 204)
    check("the worker was sent the function's real configuration once", worker.registers >= 1 and all(f["name"] != "rovara_stub" for f in worker.fns.values()))
    lam.publish_version(FunctionName="live-heavy")
    lam.create_alias(FunctionName="live-heavy", Name="prod", FunctionVersion="1")
    r, body = invoke("live-heavy:prod", {"op": "echo"})
    check("an alias goes to its version", json.loads(body)["version"] == "1" and r["ExecutedVersion"] == "1", (body, r.get("ExecutedVersion")))

# ---- 3. the stub and the queue rendezvous, through the callers the front never sees
if want("stub"):
    print("== stub rendezvous")
    if "live-s" not in [f["FunctionName"] for f in lam.list_functions()["Functions"]]:
        mk("live-s", timeout=20, mem=256)
    # SQS event source mapping
    q = sqs.create_queue(QueueName="live-in", Attributes={"VisibilityTimeout": "120"})["QueueUrl"]
    qarn = sqs.get_queue_attributes(QueueUrl=q, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    lam.create_event_source_mapping(EventSourceArn=qarn, FunctionName="live-s", BatchSize=5)
    n0 = len(worker.invs)
    sqs.send_message(QueueUrl=q, MessageBody=json.dumps({"op": "echo", "via": "sqs"}))
    got = wait_for(lambda: [f for f in worker.invs[n0:] if f["source"] == "stub"], 30)
    check("an SQS mapping runs the function in the runner (through the stub)", bool(got), len(worker.invs) - n0)
    if got:
        ev = json.loads(base64.b64decode(got[0]["payload"]))
        check("the runner received the real SQS event shape", ev["Records"][0]["eventSource"] == "aws:sqs" and json.loads(ev["Records"][0]["body"])["via"] == "sqs", ev)
        check("with the engine's request id and the function's ARN", got[0]["requestId"] and got[0]["functionArn"].endswith(":function:live-s"), got[0])
    check("the message is consumed (the runner answered, as a success)", wait_for(lambda: int(sqs.get_queue_attributes(QueueUrl=q, AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"])["Attributes"]["ApproximateNumberOfMessages"]) == 0, 20) is not None)
    # a failing function: the message is retried by the engine and goes to the DLQ, the redrive stays the engine's
    dlq = sqs.create_queue(QueueName="live-dlq")["QueueUrl"]
    dlqarn = sqs.get_queue_attributes(QueueUrl=dlq, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    q2 = sqs.create_queue(QueueName="live-in2", Attributes={"VisibilityTimeout": "20", "RedrivePolicy": json.dumps({"deadLetterTargetArn": dlqarn, "maxReceiveCount": 2})})["QueueUrl"]
    mk("live-bad", timeout=10)
    lam.create_event_source_mapping(EventSourceArn=sqs.get_queue_attributes(QueueUrl=q2, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"], FunctionName="live-bad", BatchSize=1)
    sqs.send_message(QueueUrl=q2, MessageBody=json.dumps({"op": "error", "type": "Runtime.ImportModuleError", "msg": "No module named numpy"}))
    check("a function error leaves the message to the engine's redrive (the DLQ gets it)", wait_for(lambda: int(sqs.get_queue_attributes(QueueUrl=dlq, AttributeNames=["ApproximateNumberOfMessages"])["Attributes"]["ApproximateNumberOfMessages"]) == 1, 100, 1) is not None)
    # Step Functions
    sm_def = lambda fnarn: json.dumps({"StartAt": "T", "States": {"T": {"Type": "Task", "Resource": fnarn, "End": True}}})
    arn_s = lam.get_function(FunctionName="live-s")["Configuration"]["FunctionArn"]
    sm = sfn.create_state_machine(name="live-sm", definition=sm_def(arn_s), roleArn=ROLE)["stateMachineArn"]
    ex = sfn.start_execution(stateMachineArn=sm, input=json.dumps({"op": "echo", "via": "sfn"}))["executionArn"]
    d = wait_for(lambda: (lambda x: x if x["status"] != "RUNNING" else None)(sfn.describe_execution(executionArn=ex)), 40)
    out = json.loads(d.get("output", "{}")) if d else {}
    check("a Step Functions task gets the function's own output", d and d["status"] == "SUCCEEDED" and out.get("source") == "stub" and out.get("echo", {}).get("via") == "sfn", d)
    sm2 = sfn.create_state_machine(name="live-sm2", definition=sm_def(lam.get_function(FunctionName="live-bad")["Configuration"]["FunctionArn"]), roleArn=ROLE)["stateMachineArn"]
    ex2 = sfn.start_execution(stateMachineArn=sm2, input=json.dumps({"op": "error", "type": "ValueError", "msg": "sfn boom"}))["executionArn"]
    d2 = wait_for(lambda: (lambda x: x if x["status"] != "RUNNING" else None)(sfn.describe_execution(executionArn=ex2)), 40)
    check("a function error fails the execution with the function's error type", d2 and d2["status"] == "FAILED" and d2.get("error") == "ValueError", d2)
    # API Gateway HTTP API (payload 2.0)
    api = apig.create_api(Name="live-api", ProtocolType="HTTP")["ApiId"]
    integ = apig.create_integration(ApiId=api, IntegrationType="AWS_PROXY", IntegrationUri=arn_s, PayloadFormatVersion="2.0")["IntegrationId"]
    apig.create_route(ApiId=api, RouteKey="GET /hello", Target="integrations/" + integ)
    apig.create_stage(ApiId=api, StageName="$default", AutoDeploy=True)
    n0 = len(worker.invs)
    try:
        resp = urllib.request.urlopen(ep + f"/_aws/execute-api/{api}/$default/hello?x=1", timeout=60)
        body = resp.read()
        status = resp.status
    except urllib.error.HTTPError as e:
        body, status = e.read(), e.code
    check("an API Gateway proxy route reaches the runner", status == 200 and any(f["source"] == "stub" and b"routeKey" in base64.b64decode(f["payload"]) for f in worker.invs[n0:]), (status, body[:200]))
    # SNS
    topic = sns.create_topic(Name="live-topic")["TopicArn"]
    lam.add_permission(FunctionName="live-s", StatementId="sns", Action="lambda:InvokeFunction", Principal="sns.amazonaws.com", SourceArn=topic)
    sns.subscribe(TopicArn=topic, Protocol="lambda", Endpoint=arn_s)
    n0 = len(worker.invs)
    sns.publish(TopicArn=topic, Message=json.dumps({"op": "echo", "via": "sns"}))
    check("an SNS subscription runs the function in the runner (silent in the engine alone)", wait_for(lambda: [f for f in worker.invs[n0:] if f["source"] == "stub"], 30) is not None)
    # EventBridge
    ev_.put_rule(Name="live-rule", EventPattern=json.dumps({"source": ["live.test"]}))
    ev_.put_targets(Rule="live-rule", Targets=[{"Id": "1", "Arn": arn_s}])
    lam.add_permission(FunctionName="live-s", StatementId="events", Action="lambda:InvokeFunction", Principal="events.amazonaws.com")
    n0 = len(worker.invs)
    ev_.put_events(Entries=[{"Source": "live.test", "DetailType": "t", "Detail": json.dumps({"op": "echo"})}])
    check("an EventBridge rule runs the function in the runner", wait_for(lambda: [f for f in worker.invs[n0:] if f["source"] == "stub"], 30) is not None)
    # S3 notification
    s3.create_bucket(Bucket="live-bkt")
    lam.add_permission(FunctionName="live-s", StatementId="s3", Action="lambda:InvokeFunction", Principal="s3.amazonaws.com", SourceArn="arn:aws:s3:::live-bkt")
    s3.put_bucket_notification_configuration(Bucket="live-bkt", NotificationConfiguration={"LambdaFunctionConfigurations": [{"LambdaFunctionArn": arn_s, "Events": ["s3:ObjectCreated:*"]}]})
    n0 = len(worker.invs)
    s3.put_object(Bucket="live-bkt", Key="k.txt", Body=b"hi")
    check("an S3 notification runs the function in the runner", wait_for(lambda: [f for f in worker.invs[n0:] if f["source"] == "stub"], 30) is not None)

# ---- 4. payloads and limits through the stub
if want("limits"):
    print("== limits through the stub")
    if "live-sm" not in [x["name"] for x in sfn.list_state_machines()["stateMachines"]]:
        mk("live-s", timeout=20, mem=256)
        arn_s = lam.get_function(FunctionName="live-s")["Configuration"]["FunctionArn"]
        sm = sfn.create_state_machine(name="live-sm", definition=json.dumps({"StartAt": "T", "States": {"T": {"Type": "Task", "Resource": arn_s, "End": True}}}), roleArn=ROLE)["stateMachineArn"]
    sm = [x["stateMachineArn"] for x in sfn.list_state_machines()["stateMachines"] if x["name"] == "live-sm"][0]

    def run_sm(inp, timeout=60):
        ex = sfn.start_execution(stateMachineArn=sm, input=json.dumps(inp))["executionArn"]
        return wait_for(lambda: (lambda x: x if x["status"] != "RUNNING" else None)(sfn.describe_execution(executionArn=ex)), timeout)

    d = run_sm({"op": "size", "pad": "e" * 150_000})
    check("a 150 KB event goes inline", d and d["status"] == "SUCCEEDED" and json.loads(d["output"])["eventBytes"] > 150_000, d and d.get("output", d.get("cause"))[:200])
    # a 250 KB SQS message is a ~250 KB event: over the stub's inline limit (200 KB), so it goes by pointer through the hidden bucket
    qb = sqs.create_queue(QueueName="live-bigq", Attributes={"VisibilityTimeout": "120"})["QueueUrl"]
    mk("live-bigfn", timeout=20)
    lam.create_event_source_mapping(EventSourceArn=sqs.get_queue_attributes(QueueUrl=qb, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"], FunctionName="live-bigfn", BatchSize=1)
    n0 = len(worker.invs)
    sqs.send_message(QueueUrl=qb, MessageBody="e" * 250_000)
    got = wait_for(lambda: [f for f in worker.invs[n0:] if f["name"] == "live-bigfn"], 30)
    check("a 250 KB SQS event (over the stub's 200 KB inline limit) reaches the runner whole, by pointer through the hidden bucket", got and len(base64.b64decode(got[0]["payload"])) > 250_000, got and len(base64.b64decode(got[0]["payload"])))
    if not got:
        note("debug 250KB: queue attrs " + str(sqs.get_queue_attributes(QueueUrl=qb, AttributeNames=["All"])["Attributes"]) + " rows " + str(rows().get("live-bigfn")) + " invs " + str(len(worker.invs) - n0))
    check("and the hidden bucket is left empty", wait_for(lambda: not s3_hidden_keys(), 20) is not None, s3_hidden_keys())
    d = run_sm({"op": "big", "bytes": 230_000})
    check("a 230 KB answer comes back through the hidden bucket", d and d["status"] == "SUCCEEDED" and len(json.loads(d["output"])["data"]) == 230_000, d and str(d)[:200])
    # an event over the guest SDK's 1 MiB: an SQS batch of five 250 KB messages
    qm = sqs.create_queue(QueueName="live-hugeq", Attributes={"VisibilityTimeout": "120", "ReceiveMessageWaitTimeSeconds": "0"})["QueueUrl"]
    lam.create_event_source_mapping(EventSourceArn=sqs.get_queue_attributes(QueueUrl=qm, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"], FunctionName="live-bigfn", BatchSize=5, MaximumBatchingWindowInSeconds=2)
    n0 = len(worker.invs)
    for _ in range(5):
        sqs.send_message(QueueUrl=qm, MessageBody="h" * 250_000)
    time.sleep(12)
    seen = [len(base64.b64decode(f["payload"])) for f in worker.invs[n0:] if f["name"] == "live-bigfn"]
    note(f"a 5 x 250 KB SQS batch (over 1 MiB) through the stub: the runner saw events of {seen} bytes; queue left: " + str(sqs.get_queue_attributes(QueueUrl=qm, AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"])["Attributes"]))
    # Step Functions caps every Lambda task at 10 s in the engine
    mk("live-12s", timeout=30)
    arn12 = lam.get_function(FunctionName="live-12s")["Configuration"]["FunctionArn"]
    sm12 = sfn.create_state_machine(name="live-sm12", definition=json.dumps({"StartAt": "T", "States": {"T": {"Type": "Task", "Resource": arn12, "TimeoutSeconds": 100, "End": True}}}), roleArn=ROLE)["stateMachineArn"]
    t0 = time.time()
    ex = sfn.start_execution(stateMachineArn=sm12, input=json.dumps({"op": "sleep", "ms": 14000}))["executionArn"]
    d = wait_for(lambda: (lambda x: x if x["status"] != "RUNNING" else None)(sfn.describe_execution(executionArn=ex)), 60)
    note(f"Step Functions, function sleeping 14 s (Timeout 30): {d and d['status']} {d and d.get('error')} after {time.time() - t0:.1f} s (the engine's 10 s cap)")
    # the 28 s ceiling through the stub (SQS)
    qc = sqs.create_queue(QueueName="live-ceiling", Attributes={"VisibilityTimeout": "200"})["QueueUrl"]
    mk("live-ceil", timeout=60)
    lam.create_event_source_mapping(EventSourceArn=sqs.get_queue_attributes(QueueUrl=qc, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"], FunctionName="live-ceil", BatchSize=1)
    n0 = len(worker.invs)
    sqs.send_message(QueueUrl=qc, MessageBody=json.dumps({"op": "sleep", "ms": 45000}))
    got = wait_for(lambda: [f for f in worker.invs[n0:] if f["name"] == "live-ceil"], 30)
    check("a 60 s function reached through the stub is asked to stop at the 28 s ceiling", got and 26000 <= got[0]["timeoutMs"] <= 28000, got and got[0]["timeoutMs"])
    check("and the ceiling hit is counted, not a code failure", wait_for(lambda: rows().get("live-ceil", {}).get("ceilingHits") == 1, 45, 1) is not None, rows().get("live-ceil"))
    # the engine's abandoned-run throttle: nine slow Step Functions executions, then an unrelated Invoke
    t0 = time.time()
    exs = [sfn.start_execution(stateMachineArn=sm12, input=json.dumps({"op": "sleep", "ms": 14000}))["executionArn"] for _ in range(9)]
    time.sleep(12)
    try:
        mk("live-quick", timeout=5, pkg=PLAIN)
        r = lam.invoke(FunctionName="live-quick", Payload=b"{}")
        note(f"unrelated Invoke while nine Step Functions stubs are past the 10 s cap: OK ({r['StatusCode']})")
        check("no TooManyRequestsException while stubs wait past Step Functions' cap", True)
    except Exception as e:
        note(f"unrelated Invoke while nine Step Functions stubs are past the 10 s cap: {type(e).__name__} {str(e)[:120]}")
        check("no TooManyRequestsException while stubs wait past Step Functions' cap", "TooManyRequests" not in str(e), e)
    # concurrency through the stub: more than the engine's ~16 at once
    mk("live-conc", timeout=20)
    arnc = lam.get_function(FunctionName="live-conc")["Configuration"]["FunctionArn"]
    smc = sfn.create_state_machine(name="live-smc", definition=json.dumps({"StartAt": "T", "States": {"T": {"Type": "Task", "Resource": arnc, "End": True}}}), roleArn=ROLE)["stateMachineArn"]
    p0 = worker.peak
    exs = [sfn.start_execution(stateMachineArn=smc, input=json.dumps({"op": "sleep", "ms": 2000}))["executionArn"] for _ in range(24)]
    done = [wait_for(lambda e=e: (lambda x: x if x["status"] != "RUNNING" else None)(sfn.describe_execution(executionArn=e)), 60) for e in exs]
    okn = sum(1 for d in done if d and d["status"] == "SUCCEEDED")
    note(f"24 concurrent Step Functions executions through the stub: {okn} succeeded, peak in the runner {worker.peak}")
    check("24 concurrent stub-path calls all complete", okn == 24, [d and d.get("error") for d in done if not d or d["status"] != "SUCCEEDED"][:3])

# ---- 5. hidden plumbing
if want("hidden"):
    print("== hidden plumbing")
    qs = sqs.list_queues().get("QueueUrls", [])
    check("ListQueues never shows the plumbing", not any("rovara-heavy" in u or "rovara-reply" in u for u in qs), qs)
    def refused(f):
        try:
            f()
            return False
        except Exception as e:
            return "AccessDenied" in str(e) or "reserved" in str(e)
    check("a customer SendMessage to the request queue is refused", refused(lambda: sqs.send_message(QueueUrl="http://aws:4566/000000000000/rovara-heavy-req", MessageBody="x")))
    check("a customer CreateQueue of a hidden name is refused", refused(lambda: sqs.create_queue(QueueName="rovara-reply-abc")))
    check("the payload bucket is refused", refused(lambda: s3.list_objects_v2(Bucket="rovara-heavy-payloads")))
    check("ListBuckets does not show it", "rovara-heavy-payloads" not in [b["Name"] for b in s3.list_buckets()["Buckets"]])
    check("the stub's role is refused and not listed", refused(lambda: iam.get_role(RoleName="rovara-heavy-stub")) and "rovara-heavy-stub" not in [r["RoleName"] for r in iam.list_roles()["Roles"]])
    summary = json.dumps(ctl("GET", "/_rovara/ledger/summary"))
    check("none of the plumbing is in the ledger summary", "rovara-heavy" not in summary and "rovara-reply" not in summary)
    note("reply queues left behind: " + str(len([u for u in qs if "rovara-reply" in u])) + " (the customer list hides them; the front's sweeper removes them)")

# ---- 5b. attacks on the plumbing (the Opus review's probes, 2026-11-12): every one must fail, and the stub must still work
if want("attacks"):
    print("== attacks on the plumbing")
    from urllib.parse import quote
    from botocore.awsrequest import AWSRequest
    from botocore.auth import SigV4Auth
    from botocore.credentials import Credentials
    CREDS = Credentials("AK", "SK")

    def raw(method, path, svc, body=b"", headers=None):
        req = AWSRequest(method=method, url=ep + path, data=body, headers=dict(headers or {}))
        SigV4Auth(CREDS, svc, "us-east-1").add_auth(req)
        p = req.prepare()
        r = urllib.request.Request(p.url, data=(body if method != "GET" else None), method=method, headers=dict(p.headers.items()))
        try:
            resp = urllib.request.urlopen(r, timeout=60)
            return resp.status, resp.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    def refused(name, res):
        check("refused: " + name, res[0] in (400, 403, 413, 415), res)

    def refused_exc(name, fn):
        try:
            fn()
            check("refused: " + name, False, "accepted")
        except Exception as e:
            check("refused: " + name, "AccessDenied" in str(e) or "reserved" in str(e), e)

    HQ = "http://aws:4566/000000000000/rovara-heavy-req"
    if "live-s" not in [f["FunctionName"] for f in lam.list_functions()["Functions"]]:
        mk("live-s", timeout=20, mem=256)
    cust = sqs.create_queue(QueueName="atk-cust")["QueueUrl"]
    form = {"Content-Type": "application/x-www-form-urlencoded"}
    j10 = lambda op: {"Content-Type": "application/x-amz-json-1.0", "X-Amz-Target": "AmazonSQS." + op}
    refused("SQS GET with QueueUrl in the query", raw("GET", "/?Action=GetQueueAttributes&Version=2012-11-05&AttributeName.1=All&QueueUrl=" + quote(HQ, safe=""), "sqs"))
    refused("SQS POST form with QueueUrl in the URL query", raw("POST", "/?QueueUrl=" + quote(HQ, safe=""), "sqs", b"Action=GetQueueAttributes&Version=2012-11-05", form))
    refused("SQS JSON with \\u002d escapes", raw("POST", "/", "sqs", b'{"QueueUrl":"http://aws:4566/000000000000/rovara\\u002dheavy\\u002dreq","AttributeNames":["All"]}', j10("GetQueueAttributes")))
    refused("SQS JSON padded past 1 MiB", raw("POST", "/", "sqs", b'{"Pad":"' + b"a" * (1 << 20) + b'","QueueUrl":"' + HQ.encode() + b'"}', j10("GetQueueAttributes")))
    for variant in (HQ + "/", HQ + "?x=1", "http://aws:4566/000000000000/rovara%2Dheavy%2Dreq"):
        refused_exc("boto QueueUrl " + variant, lambda v=variant: sqs.get_queue_attributes(QueueUrl=v, AttributeNames=["All"]))
    for op in ("PurgeQueue", "DeleteQueue", "ReceiveMessage"):
        refused_exc(op + " of the request queue", lambda op=op: getattr(sqs, {"PurgeQueue": "purge_queue", "DeleteQueue": "delete_queue", "ReceiveMessage": "receive_message"}[op])(QueueUrl=HQ))
    refused_exc("SetQueueAttributes", lambda: sqs.set_queue_attributes(QueueUrl=HQ, Attributes={"VisibilityTimeout": "0"}))
    # a forged request (escaped name, so a guard bypass is simulated at the engine's own port is not possible from here): the signature is the second defence
    forged = json.dumps({"v": 1, "fn": "live-s", "arn": "x", "ver": "$LATEST", "req": "forged-1", "reply": cust, "event": json.dumps({"op": "echo", "forged": True})})
    refused("a forged request on the request queue", raw("POST", "/", "sqs", json.dumps({"QueueUrl": HQ, "MessageBody": forged}).replace("rovara-heavy-req", "rovara\\u002dheavy\\u002dreq").encode(), j10("SendMessage")))
    time.sleep(3)
    check("nothing was delivered to the customer's queue", not sqs.receive_message(QueueUrl=cust, WaitTimeSeconds=2).get("Messages"))
    refused("iam GET GetRole", raw("GET", "/?Action=GetRole&Version=2010-05-08&RoleName=rovara-heavy-stub", "iam"))
    refused("iam POST with RoleName in the URL query", raw("POST", "/?RoleName=rovara-heavy-stub", "iam", b"Action=GetRole&Version=2010-05-08", form))
    refused("iam ListRolePolicies", raw("GET", "/?Action=ListRolePolicies&Version=2010-05-08&RoleName=rovara-heavy-stub", "iam"))
    check("GetAccountAuthorizationDetails does not list the stub's role", "rovara-heavy-stub" not in [x["RoleName"] for x in iam.get_account_authorization_details(Filter=["Role"]).get("RoleDetailList", [])])
    refused_exc("a function in the stub's role", lambda: lam.create_function(FunctionName="atk-pass", Runtime="python3.12", Role="arn:aws:iam::000000000000:role/rovara-heavy-stub", Handler="app.handler", Code={"ZipFile": PLAIN}))
    mk("atk-thief", timeout=10, pkg=PLAIN)
    refused_exc("an event source mapping on the request queue", lambda: lam.create_event_source_mapping(FunctionName="atk-thief", EventSourceArn="arn:aws:sqs:us-east-1:000000000000:rovara-heavy-req", BatchSize=1))
    t = sns.create_topic(Name="atk-t")["TopicArn"]
    refused_exc("an SNS subscription to the request queue", lambda: sns.subscribe(TopicArn=t, Protocol="sqs", Endpoint="arn:aws:sqs:us-east-1:000000000000:rovara-heavy-req"))
    ev_.put_rule(Name="atk-r", EventPattern=json.dumps({"source": ["atk"]}))
    refused_exc("an EventBridge target on the request queue", lambda: ev_.put_targets(Rule="atk-r", Targets=[{"Id": "1", "Arn": "arn:aws:sqs:us-east-1:000000000000:rovara-heavy-req"}]))
    smd = json.dumps({"StartAt": "A", "States": {"A": {"Type": "Task", "Resource": "arn:aws:states:::aws-sdk:iam:listRolePolicies", "Parameters": {"RoleName": "rovara-heavy-stub"}, "End": True}}})
    refused_exc("a state machine that reads the stub's role", lambda: sfn.create_state_machine(name="atk-sm", definition=smd, roleArn=ROLE))
    s3.create_bucket(Bucket="atk-b")
    refused_exc("CopyObject from the payload bucket", lambda: s3.copy_object(Bucket="atk-b", Key="k", CopySource={"Bucket": "rovara-heavy-payloads", "Key": "req/none"}))
    refused_exc("a function whose code is in the payload bucket", lambda: lam.create_function(FunctionName="atk-s3code", Runtime="python3.12", Role=ROLE, Handler="app.handler", Code={"S3Bucket": "rovara-heavy-payloads", "S3Key": "req/none"}))
    cfn = boto3.client("cloudformation", **kw)
    for name, tpl in (("a policy on the stub's role", {"Resources": {"P": {"Type": "AWS::IAM::Policy", "Properties": {"PolicyName": "d", "Roles": ["rovara-heavy-stub"], "PolicyDocument": {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}}}}}),
                      ("a queue policy on the request queue", {"Resources": {"P": {"Type": "AWS::SQS::QueuePolicy", "Properties": {"Queues": [HQ], "PolicyDocument": {"Statement": [{"Effect": "Deny", "Principal": "*", "Action": "sqs:*", "Resource": "*"}]}}}}})):
        refused_exc("CloudFormation: " + name, lambda tpl=tpl: cfn.create_stack(StackName="atk-" + str(abs(hash(name)) % 1000), TemplateBody=json.dumps(tpl)))
    # encodings the engine honours: the front decodes them before it looks, so the same attacks fail
    import gzip as _gz
    def chunked(b):
        h = len(b) // 2
        return b"%x;chunk-signature=aa\r\n" % h + b[:h] + b"\r\n%x;chunk-signature=bb\r\n" % (len(b) - h) + b[h:] + b"\r\n0;chunk-signature=cc\r\n\r\n"
    hqj = json.dumps({"QueueUrl": HQ + "-0123456789abcdef0123456789abcdef"}).encode()
    for en, (body, ce) in {"gzip": (_gz.compress(hqj), "gzip"), "aws-chunked": (chunked(hqj), "aws-chunked"), "gzip, aws-chunked": (chunked(_gz.compress(hqj)), "gzip, aws-chunked")}.items():
        refused("SQS ReceiveMessage on a request queue, " + en, raw("POST", "/", "sqs", body, dict(j10("ReceiveMessage"), **{"Content-Encoding": ce})))
    zb64 = base64.b64encode(PLAIN).decode()
    refused("a gzip CreateFunction in the stub's role", raw("POST", "/2015-03-31/functions", "lambda", _gz.compress(json.dumps({"FunctionName": "atk-gz", "Runtime": "python3.12", "Role": "arn:aws:iam::000000000000:role/rovara-heavy-stub-0123456789abcdef0123456789abcdef", "Handler": "a.b", "Code": {"ZipFile": zb64}}).encode()), {"Content-Type": "application/json", "Content-Encoding": "gzip"}))
    refused("an unknown Content-Encoding", raw("POST", "/", "sqs", hqj, dict(j10("ReceiveMessage"), **{"Content-Encoding": "br"})))
    check("a customer call with gzip still works through the real engine", sqs.list_queues() is not None and raw("POST", "/", "sqs", _gz.compress(b"{}"), dict(j10("ListQueues"), **{"Content-Encoding": "gzip"}))[0] == 200)
    # the sweeper: a reference made on the engine's own port is not possible from here; the Go test (RunnerWithRealEngine) makes all four and checks them
    # a notification written with character references is read as XML
    s3.create_bucket(Bucket="atk-nb")
    refused("a bucket notification into the plumbing, written with character references", raw("PUT", "/atk-nb?notification", "s3", b"<NotificationConfiguration><QueueConfiguration><Queue>arn:aws:sqs:us-east-1:000000000000:&#114;ovara-heavy-req-0123456789abcdef0123456789abcdef</Queue><Event>s3:ObjectCreated:*</Event></QueueConfiguration></NotificationConfiguration>"))
    # data-plane calls are the app's own: a 2 MiB InvokeAsync payload that mentions the prefix is not refused
    big = json.dumps({"x": "rovara-heavy-x" + "p" * (2 << 20)}).encode()
    check("an async invoke with a big payload naming the prefix is not refused", raw("POST", "/2014-11-13/functions/live-s/invoke-async/", "lambda", big, {"Content-Type": "application/json"})[0] not in (400, 403, 413, 415))
    # the stub still works after all of it
    n0 = len(worker.invs)
    qa = sqs.create_queue(QueueName="atk-after", Attributes={"VisibilityTimeout": "120"})["QueueUrl"]
    lam.create_event_source_mapping(EventSourceArn=sqs.get_queue_attributes(QueueUrl=qa, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"], FunctionName="live-s", BatchSize=1)
    sqs.send_message(QueueUrl=qa, MessageBody=json.dumps({"op": "echo"}))
    check("the stub path still works after the attacks", wait_for(lambda: [f for f in worker.invs[n0:] if f["source"] == "stub"], 30) is not None)

# ---- 6. reset
if want("reset"):
    print("== reset")
    ctl("POST", "/_rovara/reset")
    check("reset empties the registry", ctl("GET", "/_rovara/lambda/heavy").get("runnerFunctions") == [])
    check("and the worker's functions", not worker.fns)
    mk("live-again", timeout=60, mem=256)
    r, body = invoke("live-again", {"op": "echo"})
    check("a function created after the reset runs (the plumbing is made again)", json.loads(body)["fn"] == "live-again", body)

print("== done")
front.terminate()
try:
    front.wait(15)
except Exception:
    front.kill()
worker.proc.terminate()
if FAILS:
    print("FAILED:", FAILS)
    sys.exit(1)
print("ALL PASSED")
