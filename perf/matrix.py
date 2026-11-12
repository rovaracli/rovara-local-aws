"""AWS emulator test matrix. Usage: python -I matrix.py <label> <endpoint> <out.json>
Everything points at the localhost endpoint with fake credentials built at runtime."""
import json, os, sys, time, uuid, base64, io, threading, zipfile, urllib.request, urllib.error

os.environ["AWS_EC2_METADATA_DISABLED"] = "true"
label, endpoint, outpath = sys.argv[1], sys.argv[2], sys.argv[3]
assert endpoint.startswith("http://127.0.0.1") or endpoint.startswith("http://localhost")
fake = "te" + "st"  # fake credential built at runtime
os.environ["AWS_ACCESS_KEY_ID"] = fake
os.environ["AWS_SECRET_ACCESS_KEY"] = fake
os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
for k in ("AWS_PROFILE", "AWS_SESSION_TOKEN", "AWS_SHARED_CREDENTIALS_FILE", "AWS_CONFIG_FILE"):
    os.environ.pop(k, None)
os.environ["AWS_SHARED_CREDENTIALS_FILE"] = "/dev/null"
os.environ["AWS_CONFIG_FILE"] = "/dev/null"

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

cfg = Config(retries={"max_attempts": 1}, connect_timeout=5, read_timeout=30,
             s3={"addressing_style": "path"})


def cl(svc, **kw):
    return boto3.client(svc, endpoint_url=endpoint, region_name="us-east-1",
                        aws_access_key_id=fake, aws_secret_access_key=fake, config=cfg, **kw)


RESULTS = []
SUF = uuid.uuid4().hex[:8]


def run(svc, name, fn, expect_error=None):
    """expect_error: error code we expect real AWS to return (call is pass if code matches)."""
    t = time.perf_counter()
    rec = {"service": svc, "call": name}
    try:
        out = fn()
        rec["latency_ms"] = round((time.perf_counter() - t) * 1000, 1)
        if expect_error:
            rec["status"] = "FAIL"
            rec["note"] = f"expected {expect_error}, call succeeded"
        else:
            rec["status"] = "PASS"
            if isinstance(out, str):
                rec["note"] = out
    except ClientError as e:
        rec["latency_ms"] = round((time.perf_counter() - t) * 1000, 1)
        code = e.response.get("Error", {}).get("Code")
        rec["error_code"] = code
        if expect_error and code == expect_error:
            rec["status"] = "PASS"
            rec["note"] = f"error code {code} as in AWS"
        else:
            rec["status"] = "FAIL"
            rec["note"] = f"{code}: {str(e)[:200]}" + (f" (AWS: {expect_error})" if expect_error else "")
    except Exception as e:  # noqa
        rec["latency_ms"] = round((time.perf_counter() - t) * 1000, 1)
        rec["status"] = "FAIL"
        rec["note"] = f"{type(e).__name__}: {str(e)[:200]}"
    RESULTS.append(rec)
    print(f"[{label}] {svc:12s} {name:40s} {rec['status']} {rec['latency_ms']}ms {rec.get('note','')[:90]}", flush=True)
    return rec


def http_get(url):
    with urllib.request.urlopen(url, timeout=10) as r:
        return r.status, r.read()


# ---------------- S3 ----------------
s3 = cl("s3")
B = f"evalbucket-{SUF}"
run("s3", "create_bucket", lambda: s3.create_bucket(Bucket=B))
run("s3", "put_object", lambda: s3.put_object(Bucket=B, Key="a/one.txt", Body=b"hello"))
run("s3", "get_object", lambda: (lambda r: None if r["Body"].read() == b"hello" else 1 / 0)(s3.get_object(Bucket=B, Key="a/one.txt")))
run("s3", "get_object_missing_key(NoSuchKey)", lambda: s3.get_object(Bucket=B, Key="nope"), expect_error="NoSuchKey")
run("s3", "head_bucket_missing(404)", lambda: s3.head_bucket(Bucket="nonexistent-" + SUF), expect_error="404")


def multipart():
    key = "mp/big.bin"
    u = s3.create_multipart_upload(Bucket=B, Key=key)["UploadId"]
    p1 = b"a" * (5 * 1024 * 1024)
    p2 = b"b" * 1024
    e1 = s3.upload_part(Bucket=B, Key=key, UploadId=u, PartNumber=1, Body=p1)["ETag"]
    e2 = s3.upload_part(Bucket=B, Key=key, UploadId=u, PartNumber=2, Body=p2)["ETag"]
    s3.complete_multipart_upload(Bucket=B, Key=key, UploadId=u,
                                 MultipartUpload={"Parts": [{"ETag": e1, "PartNumber": 1}, {"ETag": e2, "PartNumber": 2}]})
    body = s3.get_object(Bucket=B, Key=key)["Body"].read()
    assert len(body) == len(p1) + len(p2), len(body)
    return f"etag-suffix-ok={s3.head_object(Bucket=B, Key=key)['ETag'].strip(chr(34)).endswith('-2')}"


run("s3", "multipart_upload(5MiB+1KiB)", multipart)


def presigned():
    url = s3.generate_presigned_url("get_object", Params={"Bucket": B, "Key": "a/one.txt"}, ExpiresIn=60)
    st, body = http_get(url)
    assert st == 200 and body == b"hello"
    purl = s3.generate_presigned_url("put_object", Params={"Bucket": B, "Key": "a/presigned-put.txt"}, ExpiresIn=60)
    req = urllib.request.Request(purl, data=b"viaput", method="PUT", headers={"Content-Type": "application/octet-stream"})
    urllib.request.urlopen(req, timeout=10).read()
    assert s3.get_object(Bucket=B, Key="a/presigned-put.txt")["Body"].read() == b"viaput"
    return "sigv2-style url" if "AWSAccessKeyId" in url else "sigv4 url"


run("s3", "presigned_url_get_and_put(octet-stream)", presigned)


def presigned_v4():
    c4 = cl("s3")
    c4 = boto3.client("s3", endpoint_url=endpoint, region_name="us-east-1", aws_access_key_id=fake, aws_secret_access_key=fake,
                      config=Config(signature_version="s3v4", s3={"addressing_style": "path"}))
    url = c4.generate_presigned_url("get_object", Params={"Bucket": B, "Key": "a/one.txt"}, ExpiresIn=60)
    st, body = http_get(url)
    assert st == 200 and body == b"hello"
    exp = c4.generate_presigned_url("get_object", Params={"Bucket": B, "Key": "a/one.txt"}, ExpiresIn=1)
    time.sleep(2.5)
    try:
        http_get(exp)
        return "SigV4 ok; WARN expired URL still served"
    except urllib.error.HTTPError as e:
        return f"SigV4 ok; expired URL -> HTTP {e.code} (AWS: 403)"


run("s3", "presigned_url_sigv4_and_expiry", presigned_v4)


def presigned_put_formct():
    purl = s3.generate_presigned_url("put_object", Params={"Bucket": B, "Key": "a/pp2.txt"}, ExpiresIn=60)
    req = urllib.request.Request(purl, data=b"viaput", method="PUT")  # urllib/curl -d default: form-urlencoded
    urllib.request.urlopen(req, timeout=10).read()
    got = s3.get_object(Bucket=B, Key="a/pp2.txt")["Body"].read()
    assert got == b"viaput", f"stored body={got!r}"


run("s3", "presigned_put_default_form_content_type", presigned_put_formct)


def listing():
    for k in ("p/x/1", "p/x/2", "p/y/1", "p/z"):
        s3.put_object(Bucket=B, Key=k, Body=b"1")
    r = s3.list_objects_v2(Bucket=B, Prefix="p/", Delimiter="/")
    prefixes = sorted(c["Prefix"] for c in r.get("CommonPrefixes", []))
    keys = [c["Key"] for c in r.get("Contents", [])]
    assert prefixes == ["p/x/", "p/y/"] and keys == ["p/z"], (prefixes, keys)


run("s3", "list_prefix_delimiter", listing)


def versioning():
    s3.put_bucket_versioning(Bucket=B, VersioningConfiguration={"Status": "Enabled"})
    v1 = s3.put_object(Bucket=B, Key="v/k", Body=b"1")["VersionId"]
    v2 = s3.put_object(Bucket=B, Key="v/k", Body=b"2")["VersionId"]
    assert v1 != v2
    assert s3.get_object(Bucket=B, Key="v/k", VersionId=v1)["Body"].read() == b"1"
    d = s3.delete_object(Bucket=B, Key="v/k")
    assert d.get("DeleteMarker") is True
    vs = s3.list_object_versions(Bucket=B, Prefix="v/")
    assert len(vs.get("Versions", [])) == 2 and len(vs.get("DeleteMarkers", [])) == 1


run("s3", "versioning(put/get-version/delete-marker/list)", versioning)


def s3_delete():
    s3.put_bucket_versioning(Bucket=B, VersioningConfiguration={"Status": "Suspended"})
    s3.delete_object(Bucket=B, Key="a/one.txt")
    s3.delete_objects(Bucket=B, Delete={"Objects": [{"Key": "p/x/1"}, {"Key": "p/x/2"}]})
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=B):
        for v in page.get("Versions", []):
            s3.delete_object(Bucket=B, Key=v["Key"], VersionId=v["VersionId"])


run("s3", "delete_objects_and_all_versions", s3_delete)


def s3_delete_marker():
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=B):
        for v in page.get("DeleteMarkers", []):
            s3.delete_object(Bucket=B, Key=v["Key"], VersionId=v["VersionId"])


run("s3", "delete_delete_marker_by_versionid", s3_delete_marker)
run("s3", "delete_bucket", lambda: s3.delete_bucket(Bucket=B))
run("s3", "delete_nonempty_bucket(BucketNotEmpty)", lambda: (s3.create_bucket(Bucket=B + "x"), s3.put_object(Bucket=B + "x", Key="k", Body=b"1"), s3.delete_bucket(Bucket=B + "x")), expect_error="BucketNotEmpty")

# ---------------- DynamoDB ----------------
ddb = cl("dynamodb")
T = f"eval-{SUF}"
run("dynamodb", "create_table_with_GSI(+stream)", lambda: ddb.create_table(
    TableName=T,
    AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}, {"AttributeName": "sk", "AttributeType": "S"},
                          {"AttributeName": "gpk", "AttributeType": "S"}],
    KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
    GlobalSecondaryIndexes=[{"IndexName": "gsi1", "KeySchema": [{"AttributeName": "gpk", "KeyType": "HASH"}],
                             "Projection": {"ProjectionType": "ALL"}}],
    BillingMode="PAY_PER_REQUEST",
    StreamSpecification={"StreamEnabled": True, "StreamViewType": "NEW_AND_OLD_IMAGES"}))
run("dynamodb", "describe_table(ACTIVE)", lambda: ddb.describe_table(TableName=T)["Table"]["TableStatus"])
run("dynamodb", "put_item", lambda: ddb.put_item(TableName=T, Item={"pk": {"S": "u1"}, "sk": {"S": "a"}, "gpk": {"S": "g"}, "n": {"N": "1"}}))
run("dynamodb", "get_item", lambda: (lambda r: None if r["Item"]["n"]["N"] == "1" else 1 / 0)(ddb.get_item(TableName=T, Key={"pk": {"S": "u1"}, "sk": {"S": "a"}})))


def dq():
    ddb.put_item(TableName=T, Item={"pk": {"S": "u1"}, "sk": {"S": "b"}, "gpk": {"S": "g"}, "n": {"N": "2"}})
    r = ddb.query(TableName=T, KeyConditionExpression="pk = :p AND begins_with(sk, :s)",
                  ExpressionAttributeValues={":p": {"S": "u1"}, ":s": {"S": "a"}})
    assert r["Count"] == 1
    r = ddb.query(TableName=T, IndexName="gsi1", KeyConditionExpression="gpk = :g", ExpressionAttributeValues={":g": {"S": "g"}})
    assert r["Count"] == 2, r["Count"]


run("dynamodb", "query_table_and_GSI", dq)
run("dynamodb", "scan_with_filter", lambda: (lambda r: None if r["Count"] == 1 else 1 / 0)(
    ddb.scan(TableName=T, FilterExpression="n > :x", ExpressionAttributeValues={":x": {"N": "1"}})))
run("dynamodb", "conditional_put_fails(ConditionalCheckFailedException)", lambda: ddb.put_item(
    TableName=T, Item={"pk": {"S": "u1"}, "sk": {"S": "a"}}, ConditionExpression="attribute_not_exists(pk)"),
    expect_error="ConditionalCheckFailedException")


def tx():
    ddb.transact_write_items(TransactItems=[
        {"Put": {"TableName": T, "Item": {"pk": {"S": "t1"}, "sk": {"S": "a"}}}},
        {"Put": {"TableName": T, "Item": {"pk": {"S": "t2"}, "sk": {"S": "a"}}}}])
    assert ddb.get_item(TableName=T, Key={"pk": {"S": "t2"}, "sk": {"S": "a"}}).get("Item")


run("dynamodb", "transact_write_items", tx)
run("dynamodb", "transact_write_cancel(TransactionCanceledException)", lambda: ddb.transact_write_items(TransactItems=[
    {"Put": {"TableName": T, "Item": {"pk": {"S": "t3"}, "sk": {"S": "a"}}}},
    {"ConditionCheck": {"TableName": T, "Key": {"pk": {"S": "nonexist"}, "sk": {"S": "a"}}, "ConditionExpression": "attribute_exists(pk)"}}]),
    expect_error="TransactionCanceledException")


def upd():
    r = ddb.update_item(TableName=T, Key={"pk": {"S": "u1"}, "sk": {"S": "a"}},
                        UpdateExpression="SET n = n + :i, #t = :tag ADD cnt :one REMOVE gpk",
                        ExpressionAttributeNames={"#t": "tag"},
                        ExpressionAttributeValues={":i": {"N": "5"}, ":tag": {"S": "x"}, ":one": {"N": "1"}}, ReturnValues="ALL_NEW")
    a = r["Attributes"]
    assert a["n"]["N"] == "6" and a["tag"]["S"] == "x" and a["cnt"]["N"] == "1" and "gpk" not in a, a


run("dynamodb", "update_expression(SET/ADD/REMOVE)", upd)
run("dynamodb", "update_time_to_live", lambda: ddb.update_time_to_live(TableName=T, TimeToLiveSpecification={"Enabled": True, "AttributeName": "ttl"}))
run("dynamodb", "describe_time_to_live", lambda: ddb.describe_time_to_live(TableName=T)["TimeToLiveDescription"]["TimeToLiveStatus"])


def streams():
    ds = cl("dynamodbstreams")
    arn = ddb.describe_table(TableName=T)["Table"]["LatestStreamArn"]
    shards = ds.describe_stream(StreamArn=arn)["StreamDescription"]["Shards"]
    assert shards
    it = ds.get_shard_iterator(StreamArn=arn, ShardId=shards[0]["ShardId"], ShardIteratorType="TRIM_HORIZON")["ShardIterator"]
    recs = ds.get_records(ShardIterator=it)["Records"]
    assert len(recs) >= 1, len(recs)
    return f"{len(recs)} stream records"


run("dynamodb", "streams_get_records", streams)
run("dynamodb", "get_item_missing_table(ResourceNotFoundException)", lambda: ddb.get_item(TableName="nope-" + SUF, Key={"pk": {"S": "x"}}), expect_error="ResourceNotFoundException")
run("dynamodb", "delete_table", lambda: ddb.delete_table(TableName=T))

# ---------------- SQS ----------------
sqs = cl("sqs")
q = {}


def std():
    u = sqs.create_queue(QueueName=f"std-{SUF}")["QueueUrl"]
    q["std"] = u
    sqs.send_message(QueueUrl=u, MessageBody="m1", MessageAttributes={"k": {"DataType": "String", "StringValue": "v"}})
    r = sqs.receive_message(QueueUrl=u, MessageAttributeNames=["All"], WaitTimeSeconds=2)
    m = r["Messages"][0]
    assert m["Body"] == "m1" and m["MessageAttributes"]["k"]["StringValue"] == "v"
    sqs.delete_message(QueueUrl=u, ReceiptHandle=m["ReceiptHandle"])
    assert "Messages" not in sqs.receive_message(QueueUrl=u)


run("sqs", "standard_send_receive_delete", std)


def vis():
    u = sqs.create_queue(QueueName=f"vis-{SUF}")["QueueUrl"]
    sqs.send_message(QueueUrl=u, MessageBody="v")
    m = sqs.receive_message(QueueUrl=u, VisibilityTimeout=2)["Messages"][0]
    assert "Messages" not in sqs.receive_message(QueueUrl=u)
    time.sleep(3)
    m2 = sqs.receive_message(QueueUrl=u, VisibilityTimeout=30).get("Messages")
    assert m2 and m2[0]["Attributes"]["ApproximateReceiveCount"] if "Attributes" in m2[0] else m2


run("sqs", "visibility_timeout_redelivery", vis)


def fifo():
    u = sqs.create_queue(QueueName=f"f-{SUF}.fifo", Attributes={"FifoQueue": "true", "ContentBasedDeduplication": "false"})["QueueUrl"]
    for i in range(3):
        sqs.send_message(QueueUrl=u, MessageBody=f"b{i}", MessageGroupId="g", MessageDeduplicationId=f"d{i}")
    d = sqs.send_message(QueueUrl=u, MessageBody="b0dup", MessageGroupId="g", MessageDeduplicationId="d0")
    got = []
    for _ in range(6):
        r = sqs.receive_message(QueueUrl=u, MaxNumberOfMessages=10, WaitTimeSeconds=1)
        for m in r.get("Messages", []):
            got.append(m["Body"])
            sqs.delete_message(QueueUrl=u, ReceiptHandle=m["ReceiptHandle"])
        if len(got) >= 3:
            break
    assert got == ["b0", "b1", "b2"], got


run("sqs", "fifo_order_and_dedup", fifo)
run("sqs", "fifo_missing_group_id(MissingParameter)", lambda: sqs.send_message(
    QueueUrl=sqs.create_queue(QueueName=f"f2-{SUF}.fifo", Attributes={"FifoQueue": "true"})["QueueUrl"], MessageBody="x"),
    expect_error="MissingParameter")


def dlq():
    dl = sqs.create_queue(QueueName=f"dlq-{SUF}")["QueueUrl"]
    dla = sqs.get_queue_attributes(QueueUrl=dl, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    src = sqs.create_queue(QueueName=f"src-{SUF}", Attributes={
        "RedrivePolicy": json.dumps({"deadLetterTargetArn": dla, "maxReceiveCount": "2"}), "VisibilityTimeout": "1"})["QueueUrl"]
    sqs.send_message(QueueUrl=src, MessageBody="poison")
    for _ in range(2):
        r = sqs.receive_message(QueueUrl=src, WaitTimeSeconds=2)
        assert r.get("Messages")
        time.sleep(1.5)
    time.sleep(1)
    sqs.receive_message(QueueUrl=src, WaitTimeSeconds=1)  # third receive triggers move
    m = None
    for _ in range(5):
        r = sqs.receive_message(QueueUrl=dl, WaitTimeSeconds=1)
        if r.get("Messages"):
            m = r["Messages"][0]
            break
    assert m and m["Body"] == "poison", "message not in DLQ"
    q["dla"] = dla
    return "message landed in DLQ"


run("sqs", "dlq_move_on_maxReceiveCount", lambda: dlq())
run("sqs", "dlq_redrive_StartMessageMoveTask", lambda: sqs.start_message_move_task(SourceArn=q["dla"])["TaskHandle"])
run("sqs", "unknown_queue(QueueDoesNotExist)", lambda: sqs.get_queue_url(QueueName="nope-" + SUF), expect_error="AWS.SimpleQueueService.NonExistentQueue")

# ---------------- SNS ----------------
sns = cl("sns")


def fan():
    topic = sns.create_topic(Name=f"t-{SUF}")["TopicArn"]
    urls, arns = [], []
    for i in range(2):
        u = sqs.create_queue(QueueName=f"sub{i}-{SUF}")["QueueUrl"]
        a = sqs.get_queue_attributes(QueueUrl=u, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
        sns.subscribe(TopicArn=topic, Protocol="sqs", Endpoint=a)
        urls.append(u)
    sns.publish(TopicArn=topic, Message="hello fan", Subject="s")
    for u in urls:
        r = sqs.receive_message(QueueUrl=u, WaitTimeSeconds=3)
        body = json.loads(r["Messages"][0]["Body"])
        assert body["Message"] == "hello fan", body


run("sns", "topic_sqs_fanout(2 subs, envelope)", fan)

# ---------------- Secrets / SSM ----------------
sm = cl("secretsmanager")
sec = f"eval/{SUF}"
run("secretsmanager", "create_get_secret", lambda: (sm.create_secret(Name=sec, SecretString='{"a":"b"}'), None if sm.get_secret_value(SecretId=sec)["SecretString"] == '{"a":"b"}' else 1 / 0))
run("secretsmanager", "put_secret_value_new_version", lambda: (sm.put_secret_value(SecretId=sec, SecretString="v2"), None if sm.get_secret_value(SecretId=sec)["SecretString"] == "v2" else 1 / 0))
run("secretsmanager", "get_missing(ResourceNotFoundException)", lambda: sm.get_secret_value(SecretId="nope-" + SUF), expect_error="ResourceNotFoundException")
ssm = cl("ssm")
run("ssm", "put_get_parameter(SecureString)", lambda: (ssm.put_parameter(Name=f"/eval/{SUF}/p", Value="val", Type="SecureString"), None if ssm.get_parameter(Name=f"/eval/{SUF}/p", WithDecryption=True)["Parameter"]["Value"] == "val" else 1 / 0))
run("ssm", "get_parameters_by_path", lambda: (lambda r: None if len(r["Parameters"]) == 1 else 1 / 0)(ssm.get_parameters_by_path(Path=f"/eval/{SUF}", Recursive=True, WithDecryption=True)))
run("ssm", "get_missing(ParameterNotFound)", lambda: ssm.get_parameter(Name="/nope/" + SUF), expect_error="ParameterNotFound")

# ---------------- KMS ----------------
kms = cl("kms")


def kmsrt():
    kid = kms.create_key(Description="eval")["KeyMetadata"]["KeyId"]
    ct = kms.encrypt(KeyId=kid, Plaintext=b"secret-bytes", EncryptionContext={"c": "1"})["CiphertextBlob"]
    assert ct != b"secret-bytes"
    pt = kms.decrypt(CiphertextBlob=ct, EncryptionContext={"c": "1"})["Plaintext"]
    assert pt == b"secret-bytes"
    try:
        kms.decrypt(CiphertextBlob=ct, EncryptionContext={"c": "wrong"})
        return "WARN: wrong encryption context accepted"
    except ClientError as e:
        return f"wrong-context rejected with {e.response['Error']['Code']} (AWS: InvalidCiphertextException)"


run("kms", "create_key_encrypt_decrypt(+context)", kmsrt)
run("kms", "generate_data_key", lambda: kms.generate_data_key(KeyId=kms.create_key()["KeyMetadata"]["KeyId"], KeySpec="AES_256")["Plaintext"])

# ---------------- STS ----------------
sts = cl("sts")
run("sts", "get_caller_identity", lambda: json.dumps({k: v for k, v in sts.get_caller_identity().items() if k != "ResponseMetadata"}))
run("sts", "assume_role", lambda: sts.assume_role(RoleArn="arn:aws:iam::123456789012:role/eval", RoleSessionName="evalsession")["AssumedRoleUser"]["Arn"])

# ---------------- Kinesis ----------------
kin = cl("kinesis")


def kinesis():
    n = f"ks-{SUF}"
    kin.create_stream(StreamName=n, ShardCount=1)
    for _ in range(20):
        if kin.describe_stream(StreamName=n)["StreamDescription"]["StreamStatus"] == "ACTIVE":
            break
        time.sleep(0.5)
    for i in range(3):
        kin.put_record(StreamName=n, Data=f"rec{i}".encode(), PartitionKey="pk")
    kin.put_records(StreamName=n, Records=[{"Data": b"batch", "PartitionKey": "pk2"}])
    sh = kin.describe_stream(StreamName=n)["StreamDescription"]["Shards"]
    got = []
    for s in sh:
        it = kin.get_shard_iterator(StreamName=n, ShardId=s["ShardId"], ShardIteratorType="TRIM_HORIZON")["ShardIterator"]
        got += [r["Data"] for r in kin.get_records(ShardIterator=it)["Records"]]
    assert len(got) == 4, got


run("kinesis", "put_get_records", kinesis)

# ---------------- EventBridge ----------------
eb = cl("events")


def ebr():
    u = sqs.create_queue(QueueName=f"eb-{SUF}")["QueueUrl"]
    a = sqs.get_queue_attributes(QueueUrl=u, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    pol = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"}, "Action": "sqs:SendMessage", "Resource": a}]}
    sqs.set_queue_attributes(QueueUrl=u, Attributes={"Policy": json.dumps(pol)})
    eb.put_rule(Name=f"r-{SUF}", EventPattern=json.dumps({"source": ["eval.app"], "detail-type": ["Ping"]}), State="ENABLED")
    eb.put_targets(Rule=f"r-{SUF}", Targets=[{"Id": "1", "Arn": a}])
    r = eb.put_events(Entries=[{"Source": "eval.app", "DetailType": "Ping", "Detail": json.dumps({"x": 1})},
                               {"Source": "other", "DetailType": "Ping", "Detail": "{}"}])
    assert r["FailedEntryCount"] == 0
    m = sqs.receive_message(QueueUrl=u, WaitTimeSeconds=3).get("Messages")
    assert m, "no event delivered to SQS"
    body = json.loads(m[0]["Body"])
    assert body["source"] == "eval.app" and body["detail"] == {"x": 1}, body
    extra = sqs.receive_message(QueueUrl=u, WaitTimeSeconds=1).get("Messages")
    assert not extra, "non-matching event delivered"


run("events", "rule_target_put_events_to_sqs(+pattern filter)", ebr)

# ---------------- Lambda ----------------
# Runs when the gate started a function runner (a separate test-only process) for this emulator:
# ROVARA_FUNCTION_RUNNER=1. Otherwise there is nothing to run the code, so the case is skipped as before.
if os.environ.get("ROVARA_FUNCTION_RUNNER") == "1":
    lam = cl("lambda")
    fnname = f"fn-{SUF}"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("handler.py", "import time\n\ndef handler(event, context):\n"
                    "    time.sleep(event.get('sleep', 0))\n"
                    "    return {'echo': event, 'fn': context.function_name}\n")
    run("lambda", "create_function(python3.12)", lambda: lam.create_function(
        FunctionName=fnname, Runtime="python3.12", Role="arn:aws:iam::123456789012:role/lambda",
        Handler="handler.handler", Code={"ZipFile": buf.getvalue()}, Timeout=10, MemorySize=128)["State"])

    def lam_invoke(payload):
        r = lam.invoke(FunctionName=fnname, Payload=json.dumps(payload).encode())
        out = json.loads(r["Payload"].read())
        assert "FunctionError" not in r, out
        assert out["echo"] == payload and out["fn"] == fnname, out
        return f"status={r['StatusCode']}"

    run("lambda", "invoke(cold start, process runner)", lambda: lam_invoke({"a": 1}))
    run("lambda", "invoke(warm)", lambda: lam_invoke({"a": 2}))

    def lam_concurrent():
        errors = []

        def one(i):
            try:
                lam_invoke({"i": i, "sleep": 0.5})
            except Exception as e:  # noqa
                errors.append(repr(e))

        threads = [threading.Thread(target=one, args=(i,)) for i in range(4)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        assert not errors, errors
        return "4 concurrent environments"

    run("lambda", "invoke_x4_concurrent", lam_concurrent)
    run("lambda", "invoke_unhandled_error(FunctionError)", lambda: (lambda r: None if r.get("FunctionError") == "Unhandled" else 1 / 0)(
        lam.invoke(FunctionName=fnname, Payload=b'{"sleep": "x"}')))
    run("lambda", "delete_function", lambda: lam.delete_function(FunctionName=fnname))
else:
    RESULTS.append({"service": "lambda", "call": "invoke/create_function", "status": "SKIPPED", "note": "no function runner for this run", "latency_ms": None})
    print(f"[{label}] lambda SKIPPED (no function runner)")

# ---------------- Step Functions ----------------
sfn = cl("stepfunctions")


def sfnrun():
    try:
        import requests
        if label != "moto":
            raise RuntimeError("moto-only config")
        requests.post(endpoint + "/moto-api/config", json={"stepfunctions": {"execute_state_machine": True}}, timeout=5)
    except Exception:
        pass
    d = {"StartAt": "P", "States": {"P": {"Type": "Pass", "Result": {"ok": True}, "End": True}}}
    arn = sfn.create_state_machine(name=f"sm-{SUF}", definition=json.dumps(d), roleArn="arn:aws:iam::123456789012:role/sfn")["stateMachineArn"]
    ex = sfn.start_execution(stateMachineArn=arn, input='{"a":1}')["executionArn"]
    for _ in range(20):
        r = sfn.describe_execution(executionArn=ex)
        if r["status"] != "RUNNING":
            break
        time.sleep(0.5)
    return f"status={r['status']} output={r.get('output')}"


rec = run("stepfunctions", "pass_state_execution", sfnrun)
if rec["status"] == "PASS" and "SUCCEEDED" not in rec.get("note", ""):
    rec["status"] = "PARTIAL"

# ---------------- SageMaker Runtime ----------------
smr = cl("sagemaker-runtime")
run("sagemaker-runtime", "invoke_endpoint_no_endpoint (AWS: ValidationError)", lambda: smr.invoke_endpoint(EndpointName="nonexistent-" + SUF, Body=b'{"x":1}', ContentType="application/json"), expect_error="ValidationError")


def smep():
    smc = cl("sagemaker")
    smc.create_model(ModelName=f"m-{SUF}", ExecutionRoleArn="arn:aws:iam::123456789012:role/sm",
                     PrimaryContainer={"Image": "123456789012.dkr.ecr.us-east-1.amazonaws.com/none:latest"})
    smc.create_endpoint_config(EndpointConfigName=f"ec-{SUF}", ProductionVariants=[{"VariantName": "v", "ModelName": f"m-{SUF}", "InitialInstanceCount": 1, "InstanceType": "ml.t2.medium"}])
    smc.create_endpoint(EndpointName=f"ep-{SUF}", EndpointConfigName=f"ec-{SUF}")
    st = smc.describe_endpoint(EndpointName=f"ep-{SUF}")["EndpointStatus"]
    try:
        r = smr.invoke_endpoint(EndpointName=f"ep-{SUF}", Body=b'{"x":1}', ContentType="application/json")
        return f"endpoint status={st}; invoke returned {r['ResponseMetadata']['HTTPStatusCode']} body={r['Body'].read()[:80]!r}"
    except ClientError as e:
        return f"endpoint status={st}; invoke error {e.response['Error']['Code']}: {str(e)[:120]}"


run("sagemaker-runtime", "create_endpoint_without_image_then_invoke", smep)

json.dump({"label": label, "endpoint": endpoint, "results": RESULTS}, open(outpath, "w"), indent=1)
p = sum(r["status"] == "PASS" for r in RESULTS)
print(f"[{label}] DONE pass={p} total={len(RESULTS)}")
