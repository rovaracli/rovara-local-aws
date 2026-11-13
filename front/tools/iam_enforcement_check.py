#!/usr/bin/env python3
"""BI0 live check: does the engine enforce IAM identity policies while the front runs it with `-a off` (signature checks off)?

    iam_enforcement_check.py --front-bin <rovara-aws-front> --engine-bin /usr/bin/aws-emulator

Starts its own front (the engine as its child) on a free port, creates an IAM user and a role with narrow policies through the front, and
calls with their keys. Prints what came back for each call; the answer to the question is the first lines ("ENFORCED" or "NOT ENFORCED").
Run it in the Linux VM with the spike's boto3. It stops only the processes it started and needs no account and no network.
"""
import argparse, json, os, shutil, socket, subprocess, sys, tempfile, time, urllib.request
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

R = {}


def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def cl(name, base, ak, sk, token=None):
    return boto3.client(name, endpoint_url=base, region_name="us-east-1", aws_access_key_id=ak, aws_secret_access_key=sk,
                        aws_session_token=token, config=Config(retries={"max_attempts": 1}))


def code(f, *a, **k):
    try:
        f(*a, **k)
        return "ALLOWED"
    except ClientError as e:
        return "DENIED:" + e.response["Error"]["Code"]
    except Exception as e:
        return "EXC:" + type(e).__name__ + ":" + str(e)[:120]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--front-bin", required=True)
    ap.add_argument("--engine-bin", default="/usr/bin/aws-emulator")
    args = ap.parse_args()
    work = tempfile.mkdtemp(prefix="bi0-")
    fport = free_port()
    token = "tok" + "x" * 20
    env = {"HOME": work, "PATH": "/usr/bin:/bin", "QUARKUS_HTTP_HOST": "127.0.0.1", "QUARKUS_HTTP_PORT": str(fport),
           "ROVARA_AWS_BASE_URL": "http://127.0.0.1:%d" % fport, "ROVARA_AWS_AUTH_PRESIGN_SECRET": "presign" + "p" * 20,
           "ROVARA_AWS_SERVICES_SQS_RECEIPT_HANDLE_SECRET": "receipt" + "r" * 20, "ROVARA_AWS_CONTROL_TOKEN": token,
           "ROVARA_AWS_ENGINE_BIN": args.engine_bin, "ROVARA_AWS_FRONT_WORKDIR": work,
           "ROVARA_AWS_PLANNED_SERVICES": "s3,sqs,dynamodb,iam,sts,bedrock-runtime"}
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
        run(base)
    finally:
        front.terminate()
        try:
            front.wait(10)
        except subprocess.TimeoutExpired:
            front.kill()
        shutil.rmtree(work, ignore_errors=True)


def run(base):
    admin = ("AKIAEXAMPLE", "secret")  # an ordinary test key, like the ones a test's own code uses
    iam, s3a, sqsa, sts = cl("iam", base, *admin), cl("s3", base, *admin), cl("sqs", base, *admin), cl("sts", base, *admin)
    s3a.create_bucket(Bucket="bi0")
    s3a.put_object(Bucket="bi0", Key="k", Body=b"x")
    qurl = sqsa.create_queue(QueueName="bi0q")["QueueUrl"]
    R["ambient: s3 PutObject"] = code(s3a.put_object, Bucket="bi0", Key="k2", Body=b"x")
    iam.create_user(UserName="limited")
    iam.put_user_policy(UserName="limited", PolicyName="p", PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::bi0/*"}]}))
    ak = iam.create_access_key(UserName="limited")["AccessKey"]
    s3u, squ = cl("s3", base, ak["AccessKeyId"], ak["SecretAccessKey"]), cl("sqs", base, ak["AccessKeyId"], ak["SecretAccessKey"])
    R["user limited (s3:GetObject only): s3 GetObject (allowed by policy)"] = code(s3u.get_object, Bucket="bi0", Key="k")
    R["user limited: s3 PutObject (not in policy)"] = code(s3u.put_object, Bucket="bi0", Key="k3", Body=b"x")
    R["user limited: s3 ListBuckets (not in policy)"] = code(s3u.list_buckets)
    R["user limited: sqs SendMessage (not in policy)"] = code(squ.send_message, QueueUrl=qurl, MessageBody="x")
    # a role session
    trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::000000000000:root"}, "Action": "sts:AssumeRole"}]}
    arn = iam.create_role(RoleName="r1", AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    iam.put_role_policy(RoleName="r1", PolicyName="p", PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": "*"}]}))
    c = sts.assume_role(RoleArn=arn, RoleSessionName="sess")["Credentials"]
    s3r, sqr = (cl(n, base, c["AccessKeyId"], c["SecretAccessKey"], c["SessionToken"]) for n in ("s3", "sqs"))
    R["role r1 session (sqs:SendMessage only): sqs SendMessage (allowed)"] = code(sqr.send_message, QueueUrl=qurl, MessageBody="x")
    R["role r1 session: sqs DeleteQueue (not in policy)"] = code(sqr.delete_queue, QueueUrl=qurl)
    R["role r1 session: s3 GetObject (not in policy)"] = code(s3r.get_object, Bucket="bi0", Key="k")
    # an access key the engine never issued
    sx = cl("s3", base, "AKIAUNKNOWNKEY0000", "whatever")
    R["unknown key (no such IAM user): s3 GetObject"] = code(sx.get_object, Bucket="bi0", Key="k")
    for k, v in R.items():
        print("%-70s %s" % (k, v))
    enforced = R["user limited: s3 PutObject (not in policy)"].startswith("DENIED") and R["role r1 session: s3 GetObject (not in policy)"].startswith("DENIED")
    print("\nBI0: the engine run with `-a off` through the front", "ENFORCES identity policies" if enforced else "does NOT enforce identity policies")


main()
