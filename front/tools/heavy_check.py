#!/usr/bin/env python3
"""Live check of the heavy-function detector against the real engine, through the front (planned mode).

Creates functions the engine accepts and cannot run (an image, java21, provided.al2023, a python zip with an ELF file, a layer with
one), a light python function, invokes them, wires one to SNS, and prints what the ledger and GET /_rovara/lambda/heavy say.

    heavy_check.py --front-bin <rovara-aws-front> --engine-bin <aws-emulator>   (run with a python that has boto3)"""
import argparse, io, json, os, random, socket, subprocess, sys, tempfile, time, urllib.request, zipfile
import boto3
from botocore.config import Config

ap = argparse.ArgumentParser()
ap.add_argument("--front-bin", required=True)
ap.add_argument("--engine-bin", required=True)
a = ap.parse_args()
s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
work = tempfile.mkdtemp()
token = "tk" + "".join(random.choice("abcdef0123456789") for _ in range(24))
env = {"HOME": work, "PATH": "/usr/bin:/bin", "QUARKUS_HTTP_HOST": "127.0.0.1", "QUARKUS_HTTP_PORT": str(port), "ROVARA_AWS_BASE_URL": "http://aws:4566",
       "ROVARA_AWS_AUTH_PRESIGN_SECRET": "ps" + token, "ROVARA_AWS_SERVICES_SQS_RECEIPT_HANDLE_SECRET": "rc" + token, "ROVARA_AWS_CONTROL_TOKEN": token,
       "ROVARA_AWS_DEFAULT_REGION": "us-east-1", "ROVARA_AWS_HOSTNAME": "aws", "ROVARA_AWS_ENGINE_BIN": a.engine_bin, "ROVARA_AWS_FRONT_WORKDIR": work,
       "ROVARA_AWS_PLANNED_SERVICES": "lambda,iam,sns,sqs,cloudformation"}
front = subprocess.Popen([a.front_bin], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
ep = f"http://127.0.0.1:{port}"
for _ in range(300):
    try:
        if urllib.request.urlopen(ep + "/_rovara/health", timeout=1).status == 200:
            break
    except Exception:
        time.sleep(0.1)
kw = dict(endpoint_url=ep, region_name="us-east-1", aws_access_key_id="AK", aws_secret_access_key="SK", config=Config(retries={"max_attempts": 1}))
lam, iam, sns = boto3.client("lambda", **kw), boto3.client("iam", **kw), boto3.client("sns", **kw)
role = iam.create_role(RoleName="r", AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}))["Role"]["Arn"]


def zipped(**files):
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        for k, v in files.items():
            z.writestr(k.replace("__", "/"), v)
    return b.getvalue()


ELF = b"\x7fELF\x02\x01\x01\x00" + b"\0" * 8 + b"\x03\0\xb7\0" + b"\0" * 40
CODE = "def handler(e, c):\n    return {'ran': True}\n"


def tryit(name, fn):
    try:
        fn()
    except Exception as e:
        print(f"  {name}: {type(e).__name__}: {str(e)[:100]}")


tryit("light", lambda: lam.create_function(FunctionName="light", Runtime="python3.12", Role=role, Handler="index.handler", Code={"ZipFile": zipped(**{"index.py": CODE})}))
tryit("native", lambda: lam.create_function(FunctionName="native", Runtime="python3.12", Role=role, Handler="index.handler", Code={"ZipFile": zipped(**{"index.py": CODE, "lib__x.so": ELF})}))
tryit("java", lambda: lam.create_function(FunctionName="javafn", Runtime="java21", Role=role, Handler="x.Y::z", Code={"ZipFile": zipped(**{"a.txt": "x"})}))
tryit("custom", lambda: lam.create_function(FunctionName="custom", Runtime="provided.al2023", Role=role, Handler="bootstrap", Code={"ZipFile": zipped(**{"bootstrap": "#!/bin/sh"})}))
tryit("image", lambda: lam.create_function(FunctionName="imagefn", PackageType="Image", Role=role, Code={"ImageUri": "000000000000.dkr.ecr.us-east-1.amazonaws.com/x:1"}))
layer = lam.publish_layer_version(LayerName="nl", Content={"ZipFile": zipped(**{"python__lib__y.so": ELF})}, CompatibleRuntimes=["python3.12"])["LayerVersionArn"]
tryit("with-layer", lambda: lam.create_function(FunctionName="withlayer", Runtime="python3.12", Role=role, Handler="index.handler", Layers=[layer], Code={"ZipFile": zipped(**{"index.py": CODE})}))
time.sleep(1.5)
for fn in ("light", "native", "javafn"):
    tryit("invoke " + fn, lambda fn=fn: print("  invoke", fn, "->", lam.invoke(FunctionName=fn, Payload=b"{}")["Payload"].read()[:80]))
# an SNS trigger the front cannot see: the engine reports success, the heavy record at create time is the evidence
topic = sns.create_topic(Name="t")["TopicArn"]
tryit("subscribe", lambda: sns.subscribe(TopicArn=topic, Protocol="lambda", Endpoint=lam.get_function(FunctionName="native")["Configuration"]["FunctionArn"]))
tryit("publish", lambda: sns.publish(TopicArn=topic, Message="m"))


def get(path):
    return json.loads(urllib.request.urlopen(urllib.request.Request(ep + path, headers={"x-rovara-control-token": token}), timeout=10).read())


print("heavy registry:", json.dumps(get("/_rovara/lambda/heavy")))
print("summary (lambda):", json.dumps(get("/_rovara/ledger/summary").get("lambda")))
print("entries:", [(e["operation"], e.get("function")) for e in get("/_rovara/ledger?service=lambda")["entries"] if e["operation"].startswith("heavy-function:")])
front.terminate(); front.wait(10)
