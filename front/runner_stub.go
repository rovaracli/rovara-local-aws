package main

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"strings"
	"time"
)

// The stub: the tiny python3.12 function the engine stores in place of a function the runner runs. The engine runs it in-process (RustPython,
// boto3 over its own in-process SDK), so it works for every caller the front never sees: an SQS or Kinesis mapping, Step Functions, SNS,
// EventBridge, S3 notifications, async Invoke, API Gateway, a function URL. It does no work of its own:
//
//  1. it puts the event on the hidden queue `rovara-heavy-req` (an event over ~200 KB goes to the hidden bucket and a pointer travels),
//     naming a reply queue it has just created;
//  2. it long-polls that reply queue in short slices (a few seconds each), until a reply arrives or the time the engine left it (the
//     engine cuts every Lambda run at 30 s, whatever the Timeout) runs out less a margin. Short slices matter: a run the engine gave up
//     on but that is still polling counts toward the engine's abandoned-run throttle (reports/AWS Emulator Lambda 30s limit.md);
//  3. it returns the function's answer as its own, or raises an error of the SAME type and message (a dotted errorType such as
//     Runtime.ImportModuleError works: the engine reports the class's __name__), so FunctionError and errorType survive.
//
// The front's dispatcher does the rest (runner_dispatch.go). The stub knows no function name and no configuration; context gives it all.
const (
	// The BASES of the hidden names. The names in use add a random part of 128 bits, new at every generation (hiddenNames): that stops a
	// reference built blind (a template with an intrinsic function, an encoded body) from hitting them, and nothing more; code that runs in
	// the same engine can list them. The bases are the prefixes the guard and the list filters reserve.
	hiddenReqQueue    = "rovara-heavy-req"
	hiddenReplyPrefix = "rovara-reply-"
	hiddenBucket      = "rovara-heavy-payloads"
	hiddenRole        = "rovara-heavy-stub"
	hiddenPrefix      = "rovara-heavy-"
	stubModule        = "rovara_stub"
	stubHandler       = stubModule + ".handler"
	stubRuntime       = "python3.12"
	stubInlineMax     = 200 << 10  // events and replies above this travel through the hidden bucket
	stubS3Max         = 1000 << 10 // the engine's guest SDK carries at most 1 MiB per call: a bigger event cannot be put in the bucket
	stubMarginMs      = 1500
	stubSliceSeconds  = 2
	stubTimeoutSlack  = 5 // the stub's Timeout is the function's plus this many seconds (the engine caps every run at 30 s anyway)
	engineCeilingMs   = 30000
	ceilingMs         = 28000 // the longest a stub-path call waits (the design's 28 s)
)

const stubSource = `import hashlib
import hmac
import json
import time
import boto3

SECRET = b"__SECRET__"

REQ_QUEUE = "__REQ_QUEUE__"
REPLY_PREFIX = "__REPLY_PREFIX__"
BUCKET = "__BUCKET__"
INLINE_MAX = 204800
S3_MAX = 1024000
SLICE_S = 2
MARGIN_MS = 1500


def _sig(*parts):
    return hmac.new(SECRET, "\n".join(parts).encode("utf-8"), hashlib.sha256).hexdigest()


def _fail(error_type, message):
    cls = type(error_type, (Exception,), {})
    cls.__name__ = error_type
    raise cls(message)


def handler(event, context):
    started = time.time()
    remaining = context.get_remaining_time_in_millis()
    rid = context.aws_request_id
    text = json.dumps(event)
    size = len(text.encode("utf-8"))
    if size > S3_MAX:
        _fail("Rovara.Unsupported", "the event is " + str(size) + " bytes; a function run by the Rovara runner can be triggered with at most 1 MiB by the local engine (a direct Invoke carries 6 MB)")
    sqs = boto3.client("sqs")
    s3 = None
    msg = {"v": 1, "fn": context.function_name, "arn": context.invoked_function_arn, "ver": context.function_version,
           "req": rid, "rem": remaining}
    if size > INLINE_MAX:
        s3 = boto3.client("s3")
        key = "req/" + rid
        blob = text.encode("utf-8")
        s3.put_object(Bucket=BUCKET, Key=key, Body=blob)
        msg["s3Key"] = key
        msg["s3Sha"] = hashlib.sha256(blob).hexdigest()
    else:
        msg["event"] = text
    reply_url = sqs.create_queue(QueueName=REPLY_PREFIX + rid.replace("-", ""))["QueueUrl"]
    msg["reply"] = reply_url
    msg["sig"] = _sig("q1", rid, reply_url, context.function_name, context.function_version, str(remaining), (msg["s3Key"] + ":" + msg["s3Sha"]) if msg.get("s3Key") else text)
    req_url = sqs.get_queue_url(QueueName=REQ_QUEUE)["QueueUrl"]
    sqs.send_message(QueueUrl=req_url, MessageBody=json.dumps(msg))
    deadline = started + (remaining - MARGIN_MS) / 1000.0
    answer = None
    while answer is None:
        left = deadline - time.time()
        if left <= 0:
            break
        wait = int(min(SLICE_S, left))
        got = sqs.receive_message(QueueUrl=reply_url, MaxNumberOfMessages=1, WaitTimeSeconds=wait)
        found = got.get("Messages")
        if found:
            env = json.loads(found[0]["Body"])
            if env.get("sig") == _sig("r1", rid, env.get("m", "")):
                answer = json.loads(env["m"])
        elif wait == 0:
            time.sleep(max(0.0, min(left, 0.5)))
    try:
        sqs.delete_queue(QueueUrl=reply_url)
    except Exception:
        pass
    if answer is None:
        _fail("Rovara.TimeoutCeiling", "the Rovara function runner did not answer within " + str(int((remaining - MARGIN_MS) / 1000)) + " s, the local engine's limit for a run (AWS allows the function's own Timeout)")
    log = answer.get("log")
    if log:
        print(log)
    if not answer.get("ok"):
        _fail(answer.get("errorType") or "Rovara.RunnerError", answer.get("errorMessage") or "the function failed")
    out = answer.get("payload")
    key = answer.get("s3Key")
    if key:
        if s3 is None:
            s3 = boto3.client("s3")
        blob = s3.get_object(Bucket=BUCKET, Key=key)["Body"].read()
        if hashlib.sha256(blob).hexdigest() != answer.get("s3Sha"):
            _fail("Rovara.RunnerError", "the answer in the payload bucket does not match the digest the front signed")
        out = blob.decode("utf-8")
        try:
            s3.delete_object(Bucket=BUCKET, Key=key)
        except Exception:
            pass
    if out is None or out == "":
        return None
    return json.loads(out)
`

// buildStubZip makes the stub package (a zip holding rovara_stub.py) for one generation: the stub signs every request it puts on the hidden
// queue (and the digest of an object it puts in the bucket) with an HMAC under the generation's secret and refuses a reply that is not signed
// under it, and the dispatcher drops a request that is not. That keeps stray and mis-addressed messages out. It does NOT keep this code or
// its secret from other code running in the same engine: that code can fetch the stub's package (an API Gateway HTTP integration aimed at the
// engine's own function-code bucket returns it) and use the secret and the names. Same-run code can disrupt or tamper with its own run's
// heavy functions; the owner has been asked to accept that as a known limit. The secret changes at every reset.
func buildStubZip(secret string, n hiddenNames) ([]byte, string) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	h := &zip.FileHeader{Name: stubModule + ".py", Method: zip.Deflate, Modified: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	h.SetMode(0o644)
	w, _ := zw.CreateHeader(h)
	src := strings.NewReplacer("__SECRET__", secret, "__REQ_QUEUE__", n.req, "__REPLY_PREFIX__", n.replyPrefix, "__BUCKET__", n.bucket).Replace(stubSource)
	w.Write([]byte(src))
	zw.Close()
	return buf.Bytes(), base64.StdEncoding.EncodeToString(buf.Bytes())
}

// hiddenNames are the names of the plumbing in one generation: the bases plus 128 random bits.
type hiddenNames struct {
	req, replyPrefix, bucket, role, roleARN string
}

func newHiddenNames(token string) hiddenNames {
	return hiddenNames{
		req:         hiddenReqQueue + "-" + token,
		replyPrefix: hiddenReplyPrefix + token + "-", // + the request id without dashes: 78 characters, under SQS's 80
		bucket:      hiddenBucket + "-" + token,
		role:        hiddenRole + "-" + token,
		roleARN:     "arn:aws:iam::000000000000:role/" + hiddenRole + "-" + token,
	}
}
