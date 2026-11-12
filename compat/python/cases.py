"""boto3 compatibility cases for Rovara local AWS: the supported tier (S3, DynamoDB, SQS, SNS, STS, Secrets
Manager, SSM, KMS, EventBridge), the three credential cases, the cases other emulators get wrong, the
documented-behaviour fixes, and the Rovara control endpoints. Written from the AWS documentation."""
import base64
import json
import time
import urllib.parse

from botocore.config import Config

from harness import FAKE, REGION, Env, case, error_code, expect_error  # noqa: F401


def s3_bucket(env, versioning=False):
    s3 = env.client("s3")
    b = env.name("b")
    s3.create_bucket(Bucket=b)
    if versioning:
        s3.put_bucket_versioning(Bucket=b, VersioningConfiguration={"Status": "Enabled"})
    return s3, b


def ddb_wait_active(ddb, table):
    """Real DynamoDB creates a table asynchronously (CREATING, then ACTIVE); wait before using it, as AWS needs."""
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 1, "MaxAttempts": 60})


def queue(env, **attrs):
    sqs = env.client("sqs")
    url = sqs.create_queue(QueueName=env.name("q"), Attributes={k: str(v) for k, v in attrs.items()})["QueueUrl"]
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return sqs, url, arn


def sqs_allow(sqs, url, arn, principal):
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": principal}, "Action": "sqs:SendMessage", "Resource": arn}]})})


def receive_all(sqs, url, want, timeout=10):
    got, end = [], time.time() + timeout
    while len(got) < want and time.time() < end:
        for m in sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=1).get("Messages", []):
            got.append(m)
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
    return got


# ───────────────────────────── the three credential cases ─────────────────────────────

@case("credentials")
def cred_1_no_authorization_header(env):
    """No Authorization header: the request is served under the default account (IAM is not enforced)."""
    st, body = env.raw("POST", env.endpoint + "/", b"Action=ListQueues&Version=2012-11-05",
                       {"Content-Type": "application/x-www-form-urlencoded"})
    assert st == 200 and b"ListQueuesResponse" in body, (st, body[:200])
    st, body = env.raw("POST", env.endpoint + "/", b"{}", {"X-Amz-Target": "DynamoDB_20120810.ListTables",
                                                           "Content-Type": "application/x-amz-json-1.0"})
    assert st == 200 and b"TableNames" in body, (st, body[:200])
    st, body = env.raw("GET", env.endpoint + "/")
    assert st == 200 and b"ListAllMyBucketsResult" in body, (st, body[:200])


@case("credentials")
def cred_2_wrong_key_is_accepted_when_validation_is_off(env):
    """Any access key and secret are accepted while signature validation is off (the default)."""
    odd = env.client("sqs", key="AKIA" + "X" * 16, secret="y" * 40)
    odd.list_queues()
    env.client("dynamodb", key="whatever", secret="whatever").list_tables()


@case("credentials")
def cred_3_signature_validation_on(env):
    """With signature validation on: the built-in test key works, an unknown key and a wrong secret are refused."""
    if not env.validated_endpoint:
        return
    ep = env.validated_endpoint
    env.client("sqs", endpoint=ep).list_queues()
    env.client("s3", endpoint=ep).list_buckets()
    expect_error(("UnrecognizedClientException", "InvalidClientTokenId", "InvalidAccessKeyId"),
                 env.client("sqs", endpoint=ep, key="AKIA" + "Q" * 16, secret="z" * 40).list_queues)
    expect_error(("InvalidSignatureException", "SignatureDoesNotMatch"),
                 env.client("sqs", endpoint=ep, secret="not-the-secret").list_queues)
    expect_error("SignatureDoesNotMatch", env.client("s3", endpoint=ep, secret="not-the-secret").list_buckets)
    # a presigned URL signed for one key does not read another
    s3 = env.client("s3", endpoint=ep, config={"signature_version": "s3v4"})
    b = env.name("b")
    s3.create_bucket(Bucket=b)
    s3.put_object(Bucket=b, Key="a", Body=b"A")
    s3.put_object(Bucket=b, Key="b", Body=b"B")
    url = s3.generate_presigned_url("get_object", Params={"Bucket": b, "Key": "a"}, ExpiresIn=60)
    assert env.raw("GET", url)[0] == 200
    st, body = env.raw("GET", url.replace(f"/{b}/a?", f"/{b}/b?"))
    assert st == 403 and b"SignatureDoesNotMatch" in body, (st, body[:200])


# ───────────────────────────── cases other emulators get wrong ─────────────────────────────

@case("moto-regression")
def presigned_put_with_form_content_type(env):
    """A presigned PUT sent with the default form content type stores the exact bytes."""
    s3, b = s3_bucket(env)
    url = s3.generate_presigned_url("put_object", Params={"Bucket": b, "Key": "k"}, ExpiresIn=60)
    st, _ = env.raw("PUT", url, b"viaput")      # urllib's default Content-Type is application/x-www-form-urlencoded
    assert st == 200, st
    assert s3.get_object(Bucket=b, Key="k")["Body"].read() == b"viaput"


@case("moto-regression")
def delete_all_versions_marker_and_bucket(env):
    """Delete every version, delete a marker by its version id, then delete the bucket."""
    s3, b = s3_bucket(env, versioning=True)
    s3.put_object(Bucket=b, Key="k", Body=b"1")
    s3.put_object(Bucket=b, Key="k", Body=b"2")
    marker = s3.delete_object(Bucket=b, Key="k")["VersionId"]
    r = s3.delete_object(Bucket=b, Key="k", VersionId=marker)
    assert r.get("DeleteMarker") is True
    assert s3.get_object(Bucket=b, Key="k")["Body"].read() == b"2"
    for v in s3.list_object_versions(Bucket=b).get("Versions", []):
        s3.delete_object(Bucket=b, Key=v["Key"], VersionId=v["VersionId"])
    assert not s3.list_object_versions(Bucket=b).get("Versions")
    s3.delete_bucket(Bucket=b)
    expect_error("NoSuchBucket", s3.list_objects_v2, Bucket=b)


@case("moto-regression")
def sqs_dead_letter_redrive(env):
    """StartMessageMoveTask moves the messages of a dead-letter queue back to its source queue."""
    sqs = env.client("sqs")
    dlq_url = sqs.create_queue(QueueName=env.name("dlq"))["QueueUrl"]
    dlq_arn = sqs.get_queue_attributes(QueueUrl=dlq_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    src = sqs.create_queue(QueueName=env.name("src"), Attributes={
        "RedrivePolicy": json.dumps({"deadLetterTargetArn": dlq_arn, "maxReceiveCount": 1}),
        "VisibilityTimeout": "1"})["QueueUrl"]
    sqs.send_message(QueueUrl=src, MessageBody="poison")
    sqs.receive_message(QueueUrl=src, WaitTimeSeconds=1)
    time.sleep(1.5)
    sqs.receive_message(QueueUrl=src, WaitTimeSeconds=1)           # second receive moves it to the DLQ
    deadline = time.time() + 8
    while time.time() < deadline and not sqs.receive_message(QueueUrl=dlq_url, VisibilityTimeout=0).get("Messages"):
        time.sleep(0.3)
    sqs.start_message_move_task(SourceArn=dlq_arn)
    msgs = receive_all(sqs, src, 1)
    assert [m["Body"] for m in msgs] == ["poison"]


@case("moto-regression")
def sagemaker_runtime_missing_endpoint(env):
    """InvokeEndpoint on an endpoint that does not exist is a ValidationError (HTTP 400)."""
    smr = env.client("sagemaker-runtime")
    e = expect_error("ValidationError", smr.invoke_endpoint, EndpointName=env.name("noep"),
                     Body=b"{}", ContentType="application/json")
    assert e.response["ResponseMetadata"]["HTTPStatusCode"] == 400


@case("moto-regression")
def step_functions_run_to_succeeded(env):
    """A Pass state machine reaches SUCCEEDED (moto leaves it RUNNING)."""
    sfn = env.client("stepfunctions")
    arn = sfn.create_state_machine(name=env.name("sm"), roleArn="arn:aws:iam::000000000000:role/x", definition=json.dumps(
        {"StartAt": "P", "States": {"P": {"Type": "Pass", "Result": {"done": True}, "End": True}}}))["stateMachineArn"]
    ex = sfn.start_execution(stateMachineArn=arn, input="{}")["executionArn"]
    deadline = time.time() + 15
    while time.time() < deadline:
        d = sfn.describe_execution(executionArn=ex)
        if d["status"] != "RUNNING":
            break
        time.sleep(0.3)
    assert d["status"] == "SUCCEEDED" and json.loads(d["output"]) == {"done": True}, d["status"]


# ───────────────────────────── supported tier ─────────────────────────────

@case("s3")
def s3_roundtrip_metadata_tags_range(env):
    s3, b = s3_bucket(env)
    s3.put_object(Bucket=b, Key="d/k.txt", Body=b"0123456789", Metadata={"Mixed": "V"}, ContentType="text/plain",
                  Tagging="a=1&b=2")
    h = s3.head_object(Bucket=b, Key="d/k.txt")
    assert h["Metadata"] == {"mixed": "V"} and h["ContentType"] == "text/plain"
    assert s3.get_object(Bucket=b, Key="d/k.txt")["TagCount"] == 2
    assert s3.get_object(Bucket=b, Key="d/k.txt", Range="bytes=2-4")["Body"].read() == b"234"
    r = s3.list_objects_v2(Bucket=b, Prefix="d/", Delimiter="/")
    assert [o["Key"] for o in r["Contents"]] == ["d/k.txt"]
    s3.copy_object(Bucket=b, Key="c", CopySource={"Bucket": b, "Key": "d/k.txt"})
    assert s3.get_object(Bucket=b, Key="c")["Body"].read() == b"0123456789"
    s3.delete_objects(Bucket=b, Delete={"Objects": [{"Key": "c"}, {"Key": "d/k.txt"}]})
    assert "Contents" not in s3.list_objects_v2(Bucket=b)


@case("s3")
def s3_multipart_and_presigned(env):
    s3, b = s3_bucket(env)
    u = s3.create_multipart_upload(Bucket=b, Key="mp")["UploadId"]
    p1, p2 = b"a" * (5 * 1024 * 1024), b"b" * 10
    e1 = s3.upload_part(Bucket=b, Key="mp", UploadId=u, PartNumber=1, Body=p1)["ETag"]
    e2 = s3.upload_part(Bucket=b, Key="mp", UploadId=u, PartNumber=2, Body=p2)["ETag"]
    s3.complete_multipart_upload(Bucket=b, Key="mp", UploadId=u, MultipartUpload={
        "Parts": [{"ETag": e1, "PartNumber": 1}, {"ETag": e2, "PartNumber": 2}]})
    assert s3.get_object(Bucket=b, Key="mp")["Body"].read() == p1 + p2
    url = s3.generate_presigned_url("get_object", Params={"Bucket": b, "Key": "mp"}, ExpiresIn=60)
    st, body = env.raw("GET", url)
    assert st == 200 and len(body) == len(p1) + len(p2)
    expect_error("NoSuchKey", s3.get_object, Bucket=b, Key="missing")


@case("s3")
def s3_versioning_and_conditional_write(env):
    s3, b = s3_bucket(env, versioning=True)
    v1 = s3.put_object(Bucket=b, Key="k", Body=b"1")["VersionId"]
    v2 = s3.put_object(Bucket=b, Key="k", Body=b"2")["VersionId"]
    assert v1 != v2 and s3.get_object(Bucket=b, Key="k", VersionId=v1)["Body"].read() == b"1"
    d = s3.delete_object(Bucket=b, Key="k")
    assert d["DeleteMarker"] is True
    expect_error("NoSuchKey", s3.get_object, Bucket=b, Key="k")
    s3.put_object(Bucket=b, Key="lock", Body=b"x", IfNoneMatch="*")
    expect_error("PreconditionFailed", s3.put_object, Bucket=b, Key="lock", Body=b"y", IfNoneMatch="*")


@case("dynamodb")
def ddb_crud_query_update(env):
    ddb = env.client("dynamodb")
    t = env.name("t")
    ddb.create_table(TableName=t, BillingMode="PAY_PER_REQUEST",
                     AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}, {"AttributeName": "sk", "AttributeType": "N"}],
                     KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}])
    ddb_wait_active(ddb, t)
    for i in range(5):
        ddb.put_item(TableName=t, Item={"pk": {"S": "a"}, "sk": {"N": str(i)}, "v": {"S": f"v{i}"}})
    r = ddb.query(TableName=t, KeyConditionExpression="pk = :p AND sk BETWEEN :lo AND :hi",
                  ExpressionAttributeValues={":p": {"S": "a"}, ":lo": {"N": "1"}, ":hi": {"N": "3"}})
    assert [i["sk"]["N"] for i in r["Items"]] == ["1", "2", "3"]
    u = ddb.update_item(TableName=t, Key={"pk": {"S": "a"}, "sk": {"N": "0"}}, UpdateExpression="SET c = if_not_exists(c, :z) + :one",
                        ExpressionAttributeValues={":z": {"N": "0"}, ":one": {"N": "1"}}, ReturnValues="ALL_NEW")
    assert u["Attributes"]["c"] == {"N": "1"}
    expect_error("ConditionalCheckFailedException", ddb.put_item, TableName=t, Item={"pk": {"S": "a"}, "sk": {"N": "0"}},
                 ConditionExpression="attribute_not_exists(pk)")
    ddb.transact_write_items(TransactItems=[
        {"Put": {"TableName": t, "Item": {"pk": {"S": "b"}, "sk": {"N": "0"}}}},
        {"Delete": {"TableName": t, "Key": {"pk": {"S": "a"}, "sk": {"N": "4"}}}}])
    assert ddb.scan(TableName=t, Select="COUNT")["Count"] == 5


@case("dynamodb")
def ddb_ttl_expires_on_tick(env):
    ddb = env.client("dynamodb")
    t = env.name("ttl")
    ddb.create_table(TableName=t, BillingMode="PAY_PER_REQUEST",
                     AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}], KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}])
    ddb_wait_active(ddb, t)
    ddb.update_time_to_live(TableName=t, TimeToLiveSpecification={"Enabled": True, "AttributeName": "exp"})
    ddb.put_item(TableName=t, Item={"pk": {"S": "old"}, "exp": {"N": str(int(time.time()) - 10)}})
    ddb.put_item(TableName=t, Item={"pk": {"S": "new"}, "exp": {"N": str(int(time.time()) + 3600)}})
    st, out = env.control("POST", "/_rovara/tick/dynamodb-ttl")
    assert st == 200, (st, out)
    keys = sorted(i["pk"]["S"] for i in ddb.scan(TableName=t)["Items"])
    assert keys == ["new"], keys


@case("sqs")
def sqs_send_receive_visibility_batch_fifo(env):
    sqs, url, arn = queue(env, VisibilityTimeout=1)
    sqs.send_message(QueueUrl=url, MessageBody="one", MessageAttributes={"k": {"DataType": "String", "StringValue": "v"}})
    m = sqs.receive_message(QueueUrl=url, MessageAttributeNames=["All"], WaitTimeSeconds=1)["Messages"][0]
    assert m["Body"] == "one" and m["MessageAttributes"]["k"]["StringValue"] == "v"
    assert not sqs.receive_message(QueueUrl=url).get("Messages")           # invisible
    time.sleep(1.3)
    again = sqs.receive_message(QueueUrl=url, WaitTimeSeconds=1)["Messages"][0]
    sqs.delete_message(QueueUrl=url, ReceiptHandle=again["ReceiptHandle"])
    r = sqs.send_message_batch(QueueUrl=url, Entries=[{"Id": "a", "MessageBody": "x"}, {"Id": "b", "MessageBody": "y"}])
    assert len(r["Successful"]) == 2
    fifo = sqs.create_queue(QueueName=env.name("f") + ".fifo", Attributes={"FifoQueue": "true", "ContentBasedDeduplication": "true"})["QueueUrl"]
    for body in ("1", "1", "2"):
        sqs.send_message(QueueUrl=fifo, MessageBody=body, MessageGroupId="g")
    assert [x["Body"] for x in receive_all(sqs, fifo, 2)] == ["1", "2"]


@case("sns")
def sns_topic_to_sqs_with_filter(env):
    sns = env.client("sns")
    sqs, url, arn = queue(env)
    topic = sns.create_topic(Name=env.name("t"))["TopicArn"]
    sqs_allow(sqs, url, arn, "sns.amazonaws.com")
    sns.subscribe(TopicArn=topic, Protocol="sqs", Endpoint=arn, Attributes={
        "RawMessageDelivery": "true", "FilterPolicy": json.dumps({"kind": ["keep"]})})
    sns.publish(TopicArn=topic, Message="yes", MessageAttributes={"kind": {"DataType": "String", "StringValue": "keep"}})
    sns.publish(TopicArn=topic, Message="no", MessageAttributes={"kind": {"DataType": "String", "StringValue": "drop"}})
    assert [m["Body"] for m in receive_all(sqs, url, 1)] == ["yes"]
    time.sleep(0.5)
    assert not sqs.receive_message(QueueUrl=url).get("Messages")


@case("sts")
def sts_identity_assume_role_session_token(env):
    sts, iam = env.client("sts"), env.client("iam")
    acct = sts.get_caller_identity()["Account"]
    assert len(acct) == 12
    role = env.name("role")
    arn = iam.create_role(RoleName=role, AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{acct}:root"}, "Action": "sts:AssumeRole"}]}))["Role"]["Arn"]
    c = sts.assume_role(RoleArn=arn, RoleSessionName="sess", DurationSeconds=900)["Credentials"]
    assert c["AccessKeyId"] and c["SessionToken"] and c["Expiration"]
    assert sts.get_session_token(DurationSeconds=900)["Credentials"]["SessionToken"]
    # assuming a role that was never created is refused, as in AWS
    expect_error(("AccessDenied", "NoSuchEntity"), sts.assume_role, RoleArn=f"arn:aws:iam::{acct}:role/{role}-missing", RoleSessionName="sess")


@case("secretsmanager")
def secrets_versions_and_deletion(env):
    sm = env.client("secretsmanager")
    n = env.name("sec")
    sm.create_secret(Name=n, SecretString="v1")
    sm.put_secret_value(SecretId=n, SecretString="v2")
    assert sm.get_secret_value(SecretId=n)["SecretString"] == "v2"
    assert sm.get_secret_value(SecretId=n, VersionStage="AWSPREVIOUS")["SecretString"] == "v1"
    sm.delete_secret(SecretId=n, RecoveryWindowInDays=7)
    expect_error("InvalidRequestException", sm.get_secret_value, SecretId=n)
    sm.restore_secret(SecretId=n)
    assert sm.get_secret_value(SecretId=n)["SecretString"] == "v2"


@case("ssm")
def ssm_parameters_hierarchy_history(env):
    ssm = env.client("ssm")
    base = "/" + env.name("p")
    ssm.put_parameter(Name=base + "/a", Value="1", Type="String")
    ssm.put_parameter(Name=base + "/b/c", Value="2", Type="SecureString")
    ssm.put_parameter(Name=base + "/a", Value="1b", Type="String", Overwrite=True)
    assert ssm.get_parameter(Name=base + "/a")["Parameter"]["Version"] == 2
    assert ssm.get_parameter(Name=base + "/b/c", WithDecryption=True)["Parameter"]["Value"] == "2"
    r = ssm.get_parameters_by_path(Path=base, Recursive=True, WithDecryption=True)
    assert sorted(p["Name"][len(base):] for p in r["Parameters"]) == ["/a", "/b/c"]
    assert len(ssm.get_parameter_history(Name=base + "/a")["Parameters"]) == 2


@case("kms")
def kms_encrypt_decrypt_context_alias(env):
    kms = env.client("kms")
    k = kms.create_key(Description="compat")["KeyMetadata"]["KeyId"]
    alias = "alias/" + env.name("a")
    kms.create_alias(AliasName=alias, TargetKeyId=k)
    ct = kms.encrypt(KeyId=alias, Plaintext=b"secret", EncryptionContext={"a": "b"})["CiphertextBlob"]
    assert kms.decrypt(CiphertextBlob=ct, EncryptionContext={"a": "b"})["Plaintext"] == b"secret"
    expect_error("InvalidCiphertextException", kms.decrypt, CiphertextBlob=ct, EncryptionContext={"a": "other"})
    dk = kms.generate_data_key(KeyId=k, KeySpec="AES_256")
    assert len(dk["Plaintext"]) == 32 and kms.decrypt(CiphertextBlob=dk["CiphertextBlob"])["Plaintext"] == dk["Plaintext"]


@case("events")
def events_rule_to_sqs_with_pattern(env):
    ev = env.client("events")
    sqs, url, arn = queue(env)
    bus = env.name("bus")
    ev.create_event_bus(Name=bus)
    rule = env.name("rule")
    rule_arn = ev.put_rule(Name=rule, EventBusName=bus, EventPattern=json.dumps(
        {"source": ["app"], "detail": {"n": [{"numeric": [">", 1]}], "tag": [{"prefix": "x-"}]}}))["RuleArn"]
    sqs_allow(sqs, url, arn, "events.amazonaws.com")
    ev.put_targets(Rule=rule, EventBusName=bus, Targets=[{"Id": "1", "Arn": arn}])
    ev.put_events(Entries=[
        {"EventBusName": bus, "Source": "app", "DetailType": "t", "Detail": json.dumps({"n": 5, "tag": "x-1"})},
        {"EventBusName": bus, "Source": "app", "DetailType": "t", "Detail": json.dumps({"n": 1, "tag": "x-1"})}])
    got = receive_all(sqs, url, 1)
    assert len(got) == 1 and json.loads(got[0]["Body"])["detail"]["n"] == 5


# ───────────────────────────── documented behaviour that was missing ─────────────────────────────

@case("fidelity")
def ddb_expression_rules(env):
    ddb = env.client("dynamodb")
    t = env.name("t")
    ddb.create_table(TableName=t, BillingMode="PAY_PER_REQUEST",
                     AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}], KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}])
    ddb_wait_active(ddb, t)
    ddb.put_item(TableName=t, Item={"pk": {"S": "k"}, "name": {"S": "n"}})
    expect_error("ValidationException", ddb.update_item, TableName=t, Key={"pk": {"S": "k"}}, UpdateExpression="SET c = :a REMOVE c",
                 ExpressionAttributeValues={":a": {"N": "1"}})                       # two document paths overlap
    expect_error("ValidationException", ddb.get_item, TableName=t, Key={"pk": {"S": "k"}}, ProjectionExpression="name")   # reserved word
    expect_error("ValidationException", ddb.get_item, TableName=t, Key={"pk": {"S": "k"}}, ProjectionExpression="#n",
                 ExpressionAttributeNames={"#n": "name", "#unused": "x"})            # unused alias
    assert ddb.get_item(TableName=t, Key={"pk": {"S": "k"}}, ProjectionExpression="#n", ExpressionAttributeNames={"#n": "name"})["Item"] == {"name": {"S": "n"}}


@case("fidelity")
def ddb_ttl_can_change_once_an_hour(env):
    ddb = env.client("dynamodb")
    t = env.name("t")
    ddb.create_table(TableName=t, BillingMode="PAY_PER_REQUEST",
                     AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}], KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}])
    ddb_wait_active(ddb, t)
    ddb.update_time_to_live(TableName=t, TimeToLiveSpecification={"Enabled": True, "AttributeName": "e"})
    expect_error("ValidationException", ddb.update_time_to_live, TableName=t, TimeToLiveSpecification={"Enabled": True, "AttributeName": "e"})
    expect_error("ValidationException", ddb.update_time_to_live, TableName=t, TimeToLiveSpecification={"Enabled": False, "AttributeName": "e"})


@case("fidelity")
def sqs_batch_ids_and_purge_window(env):
    sqs, url, arn = queue(env)
    expect_error(("BatchEntryIdsNotDistinct", "AWS.SimpleQueueService.BatchEntryIdsNotDistinct"), sqs.send_message_batch, QueueUrl=url,
                 Entries=[{"Id": "1", "MessageBody": "a"}, {"Id": "1", "MessageBody": "b"}])
    expect_error(("InvalidBatchEntryId", "AWS.SimpleQueueService.InvalidBatchEntryId"), sqs.send_message_batch, QueueUrl=url,
                 Entries=[{"Id": "bad id!", "MessageBody": "a"}])
    sqs.purge_queue(QueueUrl=url)
    expect_error(("PurgeQueueInProgress", "AWS.SimpleQueueService.PurgeQueueInProgress"), sqs.purge_queue, QueueUrl=url)
    st, _ = env.control("POST", "/_rovara/tick/sqs-purge-window")
    assert st == 200
    sqs.purge_queue(QueueUrl=url)


@case("fidelity")
def sns_publish_batch_distinct_ids(env):
    sns = env.client("sns")
    topic = sns.create_topic(Name=env.name("t"))["TopicArn"]
    expect_error("BatchEntryIdsNotDistinct", sns.publish_batch, TopicArn=topic,
                 PublishBatchRequestEntries=[{"Id": "d", "Message": "a"}, {"Id": "d", "Message": "b"}])


@case("fidelity")
def kms_deletion_window_cancel_and_alias_rules(env):
    kms = env.client("kms")
    k = kms.create_key()["KeyMetadata"]["KeyId"]
    expect_error("ValidationException", kms.schedule_key_deletion, KeyId=k, PendingWindowInDays=1)
    r = kms.schedule_key_deletion(KeyId=k, PendingWindowInDays=7)
    assert r["KeyState"] == "PendingDeletion" and r["PendingWindowInDays"] == 7
    kms.cancel_key_deletion(KeyId=k)
    assert kms.describe_key(KeyId=k)["KeyMetadata"]["KeyState"] == "Disabled"
    alias = "alias/" + env.name("a")
    kms.create_alias(AliasName=alias, TargetKeyId=k)
    expect_error("AlreadyExistsException", kms.create_alias, AliasName=alias, TargetKeyId=k)
    expect_error("ValidationException", kms.create_alias, AliasName="no-prefix", TargetKeyId=k)


@case("fidelity")
def ssm_path_and_value_size(env):
    ssm = env.client("ssm")
    expect_error("ValidationException", ssm.get_parameters_by_path, Path="no-leading-slash")
    expect_error("ValidationException", ssm.put_parameter, Name="/" + env.name("big"), Value="x" * 5000, Type="String")
    n = "/" + env.name("adv")
    ssm.put_parameter(Name=n, Value="x" * 5000, Type="String", Tier="Advanced")
    assert len(ssm.get_parameter(Name=n)["Parameter"]["Value"]) == 5000


@case("fidelity")
def s3_bucket_names(env):
    from botocore import handlers
    s3 = env.client("s3")
    s3.meta.events.unregister("before-parameter-build.s3", handlers.validate_bucket_name)   # test the server, not the SDK
    for bad in ("UPPER-case-name", "ab", "has_underscore", "-leading", "trailing-", "a..b", "192.168.0.1", "xn--abc"):
        expect_error("InvalidBucketName", s3.create_bucket, Bucket=bad)
    s3.create_bucket(Bucket=env.name("ok").lower())


@case("fidelity")
def events_pattern_operators(env):
    ev = env.client("events")

    def t(pattern, detail, want, **top):
        event = {"id": "1", "account": "000000000000", "source": "a.b", "time": "2026-01-01T00:00:00Z", "region": REGION,
                 "resources": [], "detail-type": "t", "detail": detail, **top}
        got = ev.test_event_pattern(EventPattern=json.dumps(pattern), Event=json.dumps(event))["Result"]
        assert got is want, (pattern, detail, got)

    t({"detail": {"p": [{"numeric": [">", 10, "<=", 20]}]}}, {"p": 15}, True)
    t({"detail": {"p": [{"numeric": [">", 10, "<=", 20]}]}}, {"p": "15"}, False)
    t({"detail": {"p": [{"numeric": ["=", 5]}]}}, {"p": 5.0}, True)
    t({"detail": {"tags": ["blue"]}}, {"tags": ["red", "blue"]}, True)                          # array in the event
    t({"detail": {"o": {"x": [{"exists": True}]}}}, {"o": {"x": 0}}, True)
    t({"detail": {"o": {"x": [{"exists": True}]}}}, {"o": {"y": 0}}, False)
    t({"detail": {"g": [{"exists": False}]}}, {"n": 1}, True)
    t({"detail": {"f": [{"suffix": ".png"}]}}, {"f": "a.png"}, True)
    t({"detail": {"k": [{"equals-ignore-case": "Photo"}]}}, {"k": "PHOTO"}, True)
    t({"detail": {"w": [{"wildcard": "/data/*/raw"}]}}, {"w": "/data/x/raw"}, True)
    t({"detail": {"w": [{"wildcard": "/data/*/raw"}]}}, {"w": "/data/x/cooked"}, False)
    t({"detail": {"s": [{"anything-but": {"prefix": "test-"}}]}}, {"s": "test-1"}, False)
    t({"detail": {"ip": [{"cidr": "10.0.0.0/24"}]}}, {"ip": "10.0.0.77"}, True)
    t({"detail": {"ip": [{"cidr": "10.0.0.0/24"}]}}, {"ip": "10.0.1.1"}, False)
    t({"detail": {"z": [None]}}, {"z": None}, True)
    t({"$or": [{"source": ["nope"]}, {"detail-type": ["t"]}]}, {}, True)
    expect_error("InvalidEventPatternException", ev.test_event_pattern, EventPattern='{"source": "not-a-list"}', Event="{}")
    expect_error("InvalidEventPatternException", ev.put_rule, Name=env.name("r"), EventPattern='{"detail": {"n": [{"numeric": [">"]}]}}')


@case("fidelity")
def sagemaker_runtime_async_and_stream_missing_endpoint(env):
    smr = env.client("sagemaker-runtime")
    expect_error("ValidationError", smr.invoke_endpoint_async, EndpointName=env.name("noep"), InputLocation="s3://b/k")
    expect_error("ValidationError", smr.invoke_endpoint_with_response_stream, EndpointName=env.name("noep"), Body=b"{}",
                 ContentType="application/json")


# ───────────────────────────── Rovara control endpoints ─────────────────────────────

@case("rovara-control")
def control_reset_all_and_per_service(env):
    sqs, url, _ = queue(env)
    s3, b = s3_bucket(env)
    st, out = env.control("POST", "/_rovara/reset/sqs")
    assert st == 200 and out["reset"] == "sqs", (st, out)
    assert not [u for u in env.client("sqs").list_queues().get("QueueUrls", []) if u == url]
    assert any(x["Name"] == b for x in s3.list_buckets()["Buckets"]), "an S3 bucket survives a reset of SQS"
    st, out = env.control("POST", "/_rovara/reset/nonsense")
    assert st == 404 and "services" in out
    st, out = env.control("POST", "/_rovara/reset")
    assert st == 200
    assert not s3.list_buckets()["Buckets"]
    assert not env.client("dynamodb").list_tables()["TableNames"]
    assert not env.client("sqs").list_queues().get("QueueUrls")


@case("rovara-control")
def control_seed(env):
    env.control("POST", "/_rovara/reset")
    doc = {"s3": {"buckets": [{"name": "seed-bucket", "versioning": "Enabled", "objects": [{"key": "a.txt", "text": "hello"}]}]},
           "dynamodb": {"tables": [{"request": {"TableName": "seed-table", "BillingMode": "PAY_PER_REQUEST",
                                                  "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
                                                  "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}]},
                                       "items": [{"pk": {"S": "a"}}]}]},
           "sqs": {"queues": [{"name": "seed-queue", "messages": ["m1", "m2"]}]},
           "sns": {"topics": [{"name": "seed-topic"}]},
           "secretsmanager": {"secrets": [{"name": "seed/secret", "value": "s3cr3t"}]},
           "ssm": {"parameters": [{"name": "/seed/p", "value": "1"}]},
           "kms": {"keys": [{"alias": "alias/seed-key", "description": "seeded"}]},
           "events": {"buses": ["seed-bus"], "rules": [{"name": "seed-rule", "bus": "seed-bus", "pattern": {"source": ["x"]}}]}}
    st, out = env.control("POST", "/_rovara/seed", doc)
    assert st == 200 and out["ok"], (st, out)
    assert env.client("s3").get_object(Bucket="seed-bucket", Key="a.txt")["Body"].read() == b"hello"
    assert env.client("dynamodb").get_item(TableName="seed-table", Key={"pk": {"S": "a"}})["Item"]
    sqs = env.client("sqs")
    seeded = sqs.get_queue_url(QueueName="seed-queue")["QueueUrl"]
    assert sqs.get_queue_attributes(QueueUrl=seeded, AttributeNames=["ApproximateNumberOfMessages"])["Attributes"]["ApproximateNumberOfMessages"] == "2"
    assert env.client("secretsmanager").get_secret_value(SecretId="seed/secret")["SecretString"] == "s3cr3t"
    assert env.client("ssm").get_parameter(Name="/seed/p")["Parameter"]["Value"] == "1"
    assert env.client("kms").describe_key(KeyId="alias/seed-key")["KeyMetadata"]["Description"] == "seeded"
    assert env.client("events").describe_rule(Name="seed-rule", EventBusName="seed-bus")["Name"] == "seed-rule"
    st, out = env.control("POST", "/_rovara/seed", doc)         # a second seeding reports the clashes
    assert st == 422 and out["failed"] >= 1
    env.control("POST", "/_rovara/reset")


@case("rovara-control")
def control_ledger_counts_calls_and_unsupported(env):
    env.control("DELETE", "/_rovara/ledger")
    s3, b = s3_bucket(env)
    s3.put_object(Bucket=b, Key="k", Body=b"1")
    s3.get_object(Bucket=b, Key="k")
    s3.get_object(Bucket=b, Key="k")
    env.client("sqs").list_queues()
    # SSM Run Command needs EC2 instances and the agent: removed, so it must fail loudly and be counted
    expect_error(("UnknownOperationException", "UnsupportedOperation", "InvalidAction", "NotImplemented", "UnknownOperation"),
                 env.client("ssm").list_commands)
    st, summary = env.control("GET", "/_rovara/ledger/summary")
    assert st == 200
    ops = summary["s3"]["operations"]
    assert ops["PutObject"]["calls"] == 1 and ops["GetObject"]["calls"] == 2 and ops["CreateBucket"]["calls"] == 1, ops
    assert summary["sqs"]["operations"]["ListQueues"]["calls"] == 1
    assert summary["ssm"]["unsupported"] == 1, summary["ssm"]
    st, entries = env.control("GET", "/_rovara/ledger?service=s3&limit=2")
    assert st == 200 and len(entries["entries"]) == 2 and entries["entries"][-1]["operation"] == "GetObject"
    assert all(e["status"] == 200 for e in entries["entries"])
    st, _ = env.control("DELETE", "/_rovara/ledger")
    assert env.control("GET", "/_rovara/ledger/summary")[1] == {}


@case("rovara-control")
def control_ticks_listed_and_unknown_job(env):
    st, out = env.control("GET", "/_rovara/tick")
    names = {j["name"] for j in out["jobs"]}
    assert {"dynamodb-ttl", "sqs-retention", "sqs-purge-window", "s3-lifecycle", "events-schedule",
            "secrets-rotation", "secrets-deletion", "kms-deletion"} <= names, names
    assert env.control("POST", "/_rovara/tick/nonsense")[0] == 404
    st, out = env.control("POST", "/_rovara/tick/all")
    assert st == 200 and set(out["ran"]) == names


@case("rovara-control")
def control_secret_and_key_deletion_ticks(env):
    sm, kms = env.client("secretsmanager"), env.client("kms")
    n = env.name("sec")
    sm.create_secret(Name=n, SecretString="v")
    sm.delete_secret(SecretId=n, RecoveryWindowInDays=7)
    k = kms.create_key()["KeyMetadata"]["KeyId"]
    kms.schedule_key_deletion(KeyId=k, PendingWindowInDays=7)
    st, out = env.control("POST", "/_rovara/tick/secrets-deletion")
    assert st == 200
    expect_error("ResourceNotFoundException", sm.get_secret_value, SecretId=n)
    st, out = env.control("POST", "/_rovara/tick/kms-deletion")
    assert st == 200
    expect_error("NotFoundException", kms.describe_key, KeyId=k)


@case("rovara-control")
def control_token_is_required_when_set(env):
    if not env.validated_endpoint or not env.validated_control_token:
        return
    ep = env.validated_endpoint
    st, _ = env.raw("POST", ep + "/_rovara/reset")
    assert st == 403, st
    st, _ = env.raw("POST", ep + "/_rovara/reset", headers={"X-Rovara-Control-Token": "wrong"})
    assert st == 403
    st, _ = env.raw("POST", ep + "/_rovara/reset", headers={"X-Rovara-Control-Token": env.validated_control_token})
    assert st == 200
    assert env.raw("GET", ep + "/_rovara/health")[0] == 200           # health stays open
    env.client("sqs", endpoint=ep).list_queues()                        # the API is not behind the token


@case("rovara-control")
def control_paths_are_closed_without_a_token(env):
    # FORK-CTRL-1: no token and no development switch means every control path answers 403.
    ep = getattr(env, "closed_endpoint", None)
    if not ep:
        return
    for method, path in (("POST", "/_rovara/reset"), ("POST", "/_rovara/seed"), ("GET", "/_rovara/ledger"),
                         ("POST", "/_rovara/tick/all"), ("POST", "/_rovara/state/reset"), ("GET", "/_rovara/sqs/messages")):
        st, _ = env.raw(method, ep + path)
        assert st == 403, (path, st)
    st, _ = env.raw("POST", ep + "/_rovara/reset", headers={"X-Rovara-Control-Token": "anything"})
    assert st == 403, st
    assert env.raw("GET", ep + "/_rovara/health")[0] == 200            # health stays open
    env.client("sqs", endpoint=ep).list_queues()                        # the API is not behind the token
