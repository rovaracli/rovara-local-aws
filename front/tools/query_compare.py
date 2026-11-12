#!/usr/bin/env python3
"""Sends the same SQS Query-protocol requests (hand-made, no SDK) to two endpoints and compares the XML structure of the
answers: the fork (the reference for shapes) and the front. Values that differ by nature (ids, handles, timestamps, hosts)
are normalised; what is compared is the element tree, the status and the error codes.

    query_compare.py --a http://127.0.0.1:14590 --b http://127.0.0.1:14570

Prints one line per request and a list of differences. Exit 0 when there are none that are not on the known list."""
import argparse
import http.client
import re
import sys
import urllib.parse
import xml.etree.ElementTree as ET

KNOWN = {}  # (step, note) -> reason, filled below


def call(base, path, params, scope=True):
    u = urllib.parse.urlparse(base)
    c = http.client.HTTPConnection(u.hostname, u.port, timeout=30)
    body = urllib.parse.urlencode(params)
    h = {"Content-Type": "application/x-www-form-urlencoded"}
    if scope:
        h["Authorization"] = "AWS4-HMAC-SHA256 Credential=ROVARATESTKEY/20260101/us-east-1/sqs/aws4_request, SignedHeaders=host, Signature=" + "0" * 64
    c.request("POST", path, body=body, headers=h)
    r = c.getresponse()
    raw = r.read().decode("utf-8", "replace")
    return r.status, r.getheader("content-type"), raw


def strip(tag):
    return tag.split("}", 1)[1] if tag.startswith("{") else tag


UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
NOISE = {"RequestId", "MessageId", "ReceiptHandle", "TaskHandle", "SequenceNumber"}
COLLAPSE = {"Attribute"}  # the set of attributes differs by engine; compare as one repeated shape


def norm_text(tag, text):
    t = (text or "").strip()
    if tag in NOISE:
        return "X"
    if tag == "QueueUrl":
        return "URL:" + urllib.parse.urlparse(t).path
    t = UUID.sub("UUID", t)
    if re.fullmatch(r"\d{9,}(\.\d+)?", t):
        return "N"
    return t


def shape(el, depth=0):
    tag = strip(el.tag)
    kids = list(el)
    if not kids:
        return f"<{tag}>{norm_text(tag, el.text)}"
    out, seen = [], set()
    for k in kids:
        s = shape(k, depth + 1)
        if strip(k.tag) in COLLAPSE:
            key = strip(k.tag)
            if key in seen:
                continue
            seen.add(key)
            s = f"<{key}>*"
        out.append(s)
    return f"<{tag}>[" + " ".join(out) + "]"


def run(base, label):
    res = []
    names = {}

    def step(name, params, path="/", scope=True, capture=None):
        p = [(k, v.format(**names) if isinstance(v, str) else v) for k, v in params]
        status, ctype, raw = call(base, path.format(**names), p, scope)
        try:
            root = ET.fromstring(raw)
            sh = shape(root)
            if capture:
                for var, tag in capture.items():
                    for el in root.iter():
                        if strip(el.tag) == tag:
                            names[var] = (el.text or "").strip()
                            break
        except ET.ParseError:
            sh = "NOT-XML:" + raw[:80]
        code = re.search(r"<Code>([^<]*)</Code>", raw)
        res.append((name, status, code.group(1) if code else "", sh, raw))

    V = ("Version", "2012-11-05")
    q = "cmpq1"
    names["q"] = q
    step("CreateQueue", [("Action", "CreateQueue"), ("QueueName", "{q}"), ("Attribute.1.Name", "VisibilityTimeout"), ("Attribute.1.Value", "45"), ("Attribute.2.Name", "DelaySeconds"), ("Attribute.2.Value", "0"), ("Tag.1.Key", "env"), ("Tag.1.Value", "test"), V], capture={"url": "QueueUrl"})
    step("CreateQueue again", [("Action", "CreateQueue"), ("QueueName", "{q}"), ("Attribute.1.Name", "VisibilityTimeout"), ("Attribute.1.Value", "45"), ("Attribute.2.Name", "DelaySeconds"), ("Attribute.2.Value", "0"), V])
    step("CreateQueue conflict", [("Action", "CreateQueue"), ("QueueName", "{q}"), ("Attribute.1.Name", "VisibilityTimeout"), ("Attribute.1.Value", "99"), V])
    step("CreateQueue FIFO", [("Action", "CreateQueue"), ("QueueName", "{q}f.fifo"), ("Attribute.1.Name", "FifoQueue"), ("Attribute.1.Value", "true"), ("Attribute.2.Name", "ContentBasedDeduplication"), ("Attribute.2.Value", "true"), V])
    step("GetQueueUrl", [("Action", "GetQueueUrl"), ("QueueName", "{q}"), V])
    step("GetQueueUrl missing", [("Action", "GetQueueUrl"), ("QueueName", "nonexistent-q-zzz"), V])
    step("ListQueues prefix", [("Action", "ListQueues"), ("QueueNamePrefix", "{q}"), V])
    step("ListQueues none", [("Action", "ListQueues"), ("QueueNamePrefix", "zzzz-no-such"), V])
    step("GetQueueAttributes All", [("Action", "GetQueueAttributes"), ("QueueUrl", "{url}"), ("AttributeName.1", "All"), V])
    step("GetQueueAttributes two", [("Action", "GetQueueAttributes"), ("QueueUrl", "{url}"), ("AttributeName.1", "VisibilityTimeout"), ("AttributeName.2", "QueueArn"), V])
    step("SetQueueAttributes", [("Action", "SetQueueAttributes"), ("QueueUrl", "{url}"), ("Attribute.1.Name", "VisibilityTimeout"), ("Attribute.1.Value", "60"), V])
    step("SetQueueAttributes bad", [("Action", "SetQueueAttributes"), ("QueueUrl", "{url}"), ("Attribute.1.Name", "NoSuchAttribute"), ("Attribute.1.Value", "1"), V])
    step("SendMessage attrs", [("Action", "SendMessage"), ("QueueUrl", "{url}"), ("MessageBody", "hello <&> world"),
                                ("MessageAttribute.1.Name", "k1"), ("MessageAttribute.1.Value.DataType", "String"), ("MessageAttribute.1.Value.StringValue", "v1"),
                                ("MessageAttribute.2.Name", "k2"), ("MessageAttribute.2.Value.DataType", "Number"), ("MessageAttribute.2.Value.StringValue", "42"),
                                ("MessageAttribute.3.Name", "k3"), ("MessageAttribute.3.Value.DataType", "Binary"), ("MessageAttribute.3.Value.BinaryValue", "AQID"), V])
    step("SendMessage plain", [("Action", "SendMessage"), ("QueueUrl", "{url}"), ("MessageBody", "second"), ("DelaySeconds", "0"), V])
    step("SendMessage no body", [("Action", "SendMessage"), ("QueueUrl", "{url}"), V])
    step("SendMessage bad delay", [("Action", "SendMessage"), ("QueueUrl", "{url}"), ("MessageBody", "x"), ("DelaySeconds", "abc"), V])
    step("SendMessage missing queue", [("Action", "SendMessage"), ("QueueUrl", "http://aws:4566/000000000000/nonexistent-q-zzz"), ("MessageBody", "x"), V])
    step("SendMessageBatch", [("Action", "SendMessageBatch"), ("QueueUrl", "{url}"),
                               ("SendMessageBatchRequestEntry.1.Id", "a"), ("SendMessageBatchRequestEntry.1.MessageBody", "b1"),
                               ("SendMessageBatchRequestEntry.1.MessageAttribute.1.Name", "z"), ("SendMessageBatchRequestEntry.1.MessageAttribute.1.Value.DataType", "String"), ("SendMessageBatchRequestEntry.1.MessageAttribute.1.Value.StringValue", "zz"),
                               ("SendMessageBatchRequestEntry.2.Id", "b"), ("SendMessageBatchRequestEntry.2.MessageBody", "b2"), ("SendMessageBatchRequestEntry.2.DelaySeconds", "0"), V])
    step("SendMessageBatch dup ids", [("Action", "SendMessageBatch"), ("QueueUrl", "{url}"), ("SendMessageBatchRequestEntry.1.Id", "a"), ("SendMessageBatchRequestEntry.1.MessageBody", "x"), ("SendMessageBatchRequestEntry.2.Id", "a"), ("SendMessageBatchRequestEntry.2.MessageBody", "y"), V])
    step("SendMessageBatch empty", [("Action", "SendMessageBatch"), ("QueueUrl", "{url}"), V])
    step("ReceiveMessage", [("Action", "ReceiveMessage"), ("QueueUrl", "{url}"), ("MaxNumberOfMessages", "10"), ("AttributeName.1", "All"), ("MessageAttributeName.1", "All"), ("WaitTimeSeconds", "1"), ("VisibilityTimeout", "30"), V], capture={"rh": "ReceiptHandle"})
    step("ChangeMessageVisibility", [("Action", "ChangeMessageVisibility"), ("QueueUrl", "{url}"), ("ReceiptHandle", "{rh}"), ("VisibilityTimeout", "20"), V])
    step("ChangeMessageVisibilityBatch", [("Action", "ChangeMessageVisibilityBatch"), ("QueueUrl", "{url}"), ("ChangeMessageVisibilityBatchRequestEntry.1.Id", "e1"), ("ChangeMessageVisibilityBatchRequestEntry.1.ReceiptHandle", "{rh}"), ("ChangeMessageVisibilityBatchRequestEntry.1.VisibilityTimeout", "10"), V])
    step("DeleteMessage", [("Action", "DeleteMessage"), ("QueueUrl", "{url}"), ("ReceiptHandle", "{rh}"), V])
    step("DeleteMessage invalid handle", [("Action", "DeleteMessage"), ("QueueUrl", "{url}"), ("ReceiptHandle", "not-a-handle"), V])
    step("DeleteMessageBatch", [("Action", "DeleteMessageBatch"), ("QueueUrl", "{url}"), ("DeleteMessageBatchRequestEntry.1.Id", "d1"), ("DeleteMessageBatchRequestEntry.1.ReceiptHandle", "not-a-handle"), V])
    step("AddPermission", [("Action", "AddPermission"), ("QueueUrl", "{url}"), ("Label", "lbl"), ("AWSAccountId.1", "000000000000"), ("ActionName.1", "SendMessage"), V])
    step("RemovePermission", [("Action", "RemovePermission"), ("QueueUrl", "{url}"), ("Label", "lbl"), V])
    step("TagQueue", [("Action", "TagQueue"), ("QueueUrl", "{url}"), ("Tag.1.Key", "a"), ("Tag.1.Value", "1"), ("Tag.2.Key", "b"), ("Tag.2.Value", "2"), V])
    step("ListQueueTags", [("Action", "ListQueueTags"), ("QueueUrl", "{url}"), V])
    step("UntagQueue", [("Action", "UntagQueue"), ("QueueUrl", "{url}"), ("TagKey.1", "a"), V])
    step("ListDeadLetterSourceQueues", [("Action", "ListDeadLetterSourceQueues"), ("QueueUrl", "{url}"), V])
    step("Java v1 style: path names the queue", [("Action", "SendMessage"), ("MessageBody", "viapath"), V], path="/000000000000/{q}")
    step("Java v1 style: GetQueueAttributes", [("Action", "GetQueueAttributes"), ("AttributeName.1", "ApproximateNumberOfMessages"), V], path="/000000000000/{q}")
    step("PurgeQueue", [("Action", "PurgeQueue"), ("QueueUrl", "{url}"), V])
    step("ListMessageMoveTasks", [("Action", "ListMessageMoveTasks"), ("SourceArn", "arn:aws:sqs:us-east-1:000000000000:{q}"), V])
    step("unsigned GetQueueUrl", [("Action", "GetQueueUrl"), ("QueueName", "{q}"), V], scope=False)
    step("unknown action", [("Action", "NoSuchThing"), ("QueueUrl", "{url}"), V])
    step("DeleteQueue", [("Action", "DeleteQueue"), ("QueueUrl", "{url}"), V])
    step("GetQueueUrl after delete", [("Action", "GetQueueUrl"), ("QueueName", "{q}"), V])
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--a", required=True)
    ap.add_argument("--b", required=True)
    ap.add_argument("--show", action="store_true")
    a = ap.parse_args()
    ra, rb = run(a.a, "a"), run(a.b, "b")
    diffs = 0
    for (n, sa, ca, sha, rawa), (_, sb, cb, shb, rawb) in zip(ra, rb):
        same = sa == sb and ca == cb and sha == shb
        print(("same " if same else "DIFF ") + f"{n:38s} {sa}/{sb} {ca or '-'}" + ("" if ca == cb else f" vs {cb or '-'}"))
        if not same:
            diffs += 1
            print(f"    A {sa} {sha[:300]}\n    B {sb} {shb[:300]}")
        if a.show:
            print("    A raw:", rawa[:400]); print("    B raw:", rawb[:400])
    print(f"{len(ra) - diffs} of {len(ra)} identical in structure")
    return 0 if diffs == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
