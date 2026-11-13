#!/usr/bin/env python3
"""Live proof of the Bedrock runtime shim (BI1): boto3 against the front and the real AWS Emulator.

    bedrock_live.py --front-bin <rovara-aws-front> --engine-bin /usr/bin/aws-emulator [--js-sdk <dir holding node_modules/@aws-sdk>] [--node <node>]

Run it in the Linux VM with the spike's boto3. It starts its own front (with the engine as its child, a control token and a plan naming
bedrock-runtime, bedrock, iam, sts and s3) on a free port and stops only the processes it started. It needs no AWS account and no network
beyond loopback. Every answer is parsed by botocore itself (and, with --js-sdk, by the AWS SDK for JavaScript v3 in front/tools/bedrock_live.cjs).

What it proves:
  converse      canned text, a tool-use turn and the follow-up turn with the toolResult, usage, stop reasons, the default, the unmatched failure
  streams       ConverseStream and InvokeModelWithResponseStream parsed by botocore's event stream parser (text split into parts, tool input as
                partial JSON, metadata with usage), an exception event in the middle of a stream
  invoke        InvokeModel for Anthropic (messages and the old text API), Nova, Titan, Llama, Mistral, Cohere and a generic family; an embedding
  guardrails    a Converse and an InvokeModel intervention with the trace, ApplyGuardrail (blocked and none)
  faults        throttling, validation and model timeout armed through the control path; the error codes and statuses botocore reads
  count tokens  CountTokens estimates and a rule
  control       the ledger markers, the summary, the guard on the control paths, a reset
  engine        the control plane (`bedrock`) is still the engine's: ListFoundationModels, CreateGuardrail
  iam           (informational) the engine does not enforce IAM on Bedrock runtime: a user with no Bedrock permission can converse
Exit code 0 when every check passes.
"""
import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, EventStreamError

FAILED = []


def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + name + ((" :: " + str(detail)[:400]) if (detail and not ok) else ""))
    if not ok:
        FAILED.append(name)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def http_json(method, url, token=None, body=None):
    req = urllib.request.Request(url, data=(json.dumps(body).encode() if body is not None else None), method=method)
    if token:
        req.add_header("X-Rovara-Control-Token", token)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def client(name, base, ak="AKIAEXAMPLE", sk="secret", token=None):
    return boto3.client(name, endpoint_url=base, region_name="us-east-1", aws_access_key_id=ak, aws_secret_access_key=sk,
                        aws_session_token=token, config=Config(retries={"total_max_attempts": 1, "mode": "standard"}))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--front-bin", required=True)
    ap.add_argument("--engine-bin", default="/usr/bin/aws-emulator")
    ap.add_argument("--js-sdk", default="")
    ap.add_argument("--node", default="node")
    args = ap.parse_args()
    work = tempfile.mkdtemp(prefix="bedrock-live-")
    fport = free_port()
    token = "tok" + "x" * 20
    env = {"HOME": work, "PATH": "/usr/bin:/bin", "QUARKUS_HTTP_HOST": "127.0.0.1", "QUARKUS_HTTP_PORT": str(fport),
           "ROVARA_AWS_BASE_URL": "http://127.0.0.1:%d" % fport, "ROVARA_AWS_AUTH_PRESIGN_SECRET": "presign" + "p" * 20,
           "ROVARA_AWS_SERVICES_SQS_RECEIPT_HANDLE_SECRET": "receipt" + "r" * 20, "ROVARA_AWS_CONTROL_TOKEN": token,
           "ROVARA_AWS_ENGINE_BIN": args.engine_bin, "ROVARA_AWS_FRONT_WORKDIR": work,
           "ROVARA_AWS_PLANNED_SERVICES": "bedrock-runtime,bedrock,iam,sts,s3"}
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
        run(base, token)
        if args.js_sdk:
            run_js(base, token, args)
    finally:
        front.terminate()
        try:
            front.wait(10)
        except subprocess.TimeoutExpired:
            front.kill()
        shutil.rmtree(work, ignore_errors=True)
    print("\n%d check(s) failed: %s" % (len(FAILED), ", ".join(FAILED)) if FAILED else "\nall checks passed")
    sys.exit(1 if FAILED else 0)


def put(base, token, name, doc):
    st, body = http_json("PUT", "%s/_rovara/bedrock/fixtures/%s" % (base, name), token, doc)
    check("fixtures %s accepted" % name, st == 200, (st, body))


def fault(base, token, doc):
    st, body = http_json("POST", "%s/_rovara/bedrock/faults" % base, token, doc)
    check("fault armed", st == 200, (st, body))


def err_of(f, *a, **k):
    try:
        f(*a, **k)
    except (ClientError, EventStreamError) as e:
        return e
    return None


def code_of(e):
    return None if e is None else e.response["Error"]["Code"]


def user(text):
    return {"role": "user", "content": [{"text": text}]}


CLAUDE = "anthropic.claude-3-5-sonnet-20241022-v2:0"
NOVA = "us.amazon.nova-pro-v1:0"


def run(base, token):
    br = client("bedrock-runtime", base)
    ctl = "%s/_rovara" % base
    put(base, token, "claude", {"modelPrefix": "anthropic.", "rules": [
        {"match": {"toolResult": True, "toolResultContains": "22"}, "response": {"text": "It is 22 degrees in Paris."}},
        {"match": {"textMatches": "(?i)weather in (\\w+)", "toolResult": False}, "response": {"text": "Let me look that up.", "toolUse": {
            "toolUseId": "tooluse_weather_1", "name": "get_weather", "input": {"city": "Paris", "unit": "celsius"}}, "chunkSize": 12}},
        {"match": {"textContains": "hello"}, "response": {"text": "Hello from a canned Claude.", "chunkSize": 6}},
        {"match": {"textContains": "stream-then-fail"}, "response": {"text": "this stream breaks in the middle", "chunkSize": 6,
                                                                    "streamError": {"code": "throttlingException", "afterParts": 2}}},
        {"match": {"textContains": "secret", "guardrail": True}, "response": {"guardrail": {"blockedMessage": "Blocked by policy.", "assessments": {
            "topicPolicy": {"topics": [{"name": "secrets", "type": "DENY", "action": "BLOCKED"}]}}}}},
        {"match": {"operation": "count-tokens", "textContains": "fixed"}, "response": {"usage": {"inputTokens": 42}}},
    ], "default": {"text": "A default canned answer."}})
    # ApplyGuardrail names no model: its rules live in a set with no modelId and no modelPrefix
    put(base, token, "guardrail", {"rules": [
        {"match": {"operation": "apply-guardrail", "textContains": "credit card"}, "response": {"guardrail": {
            "actionReason": "Guardrail blocked.", "blockedMessage": "Card numbers are blocked.",
            "assessments": [{"sensitiveInformationPolicy": {"piiEntities": [{"type": "CREDIT_DEBIT_CARD_NUMBER", "action": "BLOCKED", "match": "4111"}]}}]}}},
        {"match": {"operation": "apply-guardrail", "textContains": "harmless"}, "response": {"guardrail": {"action": "NONE"}}}]})
    put(base, token, "nova", {"modelPrefix": "amazon.nova", "default": {"text": "Hello from a canned Nova.", "chunkSize": 7}})
    for i, prefix in enumerate(["amazon.titan-text", "meta.", "mistral.", "cohere.", "ai21."]):
        put(base, token, "other%d" % i, {"modelPrefix": prefix, "default": {"text": "canned text for any other family", "chunkSize": 9}})
    put(base, token, "embed", {"modelPrefix": "amazon.titan-embed", "default": {"embedding": {"dimensions": 8}}})

    # ---- converse
    r = br.converse(modelId=CLAUDE, messages=[user("hello world")], inferenceConfig={"maxTokens": 100})
    check("converse: text, stop reason, usage, latency",
          r["output"]["message"]["content"][0]["text"] == "Hello from a canned Claude." and r["stopReason"] == "end_turn"
          and r["usage"]["totalTokens"] == r["usage"]["inputTokens"] + r["usage"]["outputTokens"] > 0 and r["metrics"]["latencyMs"] >= 1, r)
    tools = {"tools": [{"toolSpec": {"name": "get_weather", "description": "weather", "inputSchema": {"json": {"type": "object"}}}}]}
    msgs = [user("What is the weather in Paris?")]
    r = br.converse(modelId="us." + CLAUDE, messages=msgs, toolConfig=tools)
    tu = r["output"]["message"]["content"][1]["toolUse"]
    check("converse: a tool-use turn (inference profile id)", r["stopReason"] == "tool_use" and tu["name"] == "get_weather"
          and tu["input"] == {"city": "Paris", "unit": "celsius"} and tu["toolUseId"] == "tooluse_weather_1", r)
    msgs += [r["output"]["message"], {"role": "user", "content": [{"toolResult": {"toolUseId": tu["toolUseId"], "content": [{"json": {"temp": 22}}]}}]}]
    r = br.converse(modelId=CLAUDE, messages=msgs, toolConfig=tools)
    check("converse: the follow-up turn with the toolResult is answered by its own rule",
          r["output"]["message"]["content"][0]["text"] == "It is 22 degrees in Paris." and r["stopReason"] == "end_turn", r)
    r = br.converse(modelId=CLAUDE, messages=[user("something else")])
    check("converse: the set's default", r["output"]["message"]["content"][0]["text"] == "A default canned answer.", r)
    e = err_of(br.converse, modelId="writer.palmyra-x4-v1:0", messages=[user("hi")])
    check("converse: unmatched fails, naming the missing rule", code_of(e) == "ValidationException" and "no recorded or canned answer" in str(e) and
          e.response["ResponseMetadata"]["HTTPStatusCode"] == 400, e)
    e = err_of(br.converse, modelId=CLAUDE, messages=[{"role": "assistant", "content": [{"text": "x"}]}])
    check("converse: a conversation that starts with the assistant is a ValidationException", code_of(e) == "ValidationException", e)

    # ---- ConverseStream
    r = br.converse_stream(modelId=CLAUDE, messages=[user("hello there")])
    events = list(r["stream"])
    kinds = [list(ev.keys())[0] for ev in events]
    text = "".join(ev["contentBlockDelta"]["delta"]["text"] for ev in events if "contentBlockDelta" in ev)
    meta = [ev for ev in events if "metadata" in ev][0]["metadata"]
    check("converse_stream: events, text in parts, metadata", kinds[0] == "messageStart" and kinds.count("contentBlockDelta") == 5 and text == "Hello from a canned Claude."
          and kinds[-3:] == ["contentBlockStop", "messageStop", "metadata"] and meta["usage"]["outputTokens"] > 0 and meta["metrics"]["latencyMs"] >= 1, kinds)
    r = br.converse_stream(modelId=CLAUDE, messages=[user("What is the weather in Paris?")], toolConfig=tools)
    events = list(r["stream"])
    start = [ev["contentBlockStart"] for ev in events if "contentBlockStart" in ev]
    partial = "".join(ev["contentBlockDelta"]["delta"]["toolUse"]["input"] for ev in events if "contentBlockDelta" in ev and "toolUse" in ev["contentBlockDelta"]["delta"])
    stop = [ev["messageStop"] for ev in events if "messageStop" in ev][0]
    check("converse_stream: tool use as a start event and partial JSON", start[0]["start"]["toolUse"]["name"] == "get_weather" and start[0]["contentBlockIndex"] == 1
          and json.loads(partial) == {"city": "Paris", "unit": "celsius"} and stop["stopReason"] == "tool_use", (start, partial))
    r = br.converse_stream(modelId=CLAUDE, messages=[user("please stream-then-fail")])
    got, ex = [], None
    try:
        for ev in r["stream"]:
            got.append(list(ev.keys())[0])
    except Exception as x:
        ex = x
    check("converse_stream: an exception event after two parts raises throttlingException in the SDK",
          got == ["messageStart", "contentBlockDelta", "contentBlockDelta"] and ex is not None and "throttlingException" in (type(ex).__name__ + str(ex)), (got, repr(ex)))

    # ---- InvokeModel
    inv = lambda model, body, **kw: br.invoke_model(modelId=model, body=json.dumps(body), contentType="application/json", accept="application/json", **kw)
    r = inv(CLAUDE, {"anthropic_version": "bedrock-2023-05-31", "max_tokens": 100, "messages": [{"role": "user", "content": [{"type": "text", "text": "hello"}]}]})
    d = json.loads(r["body"].read())
    check("invoke_model anthropic: messages API body", d["type"] == "message" and d["content"][0]["text"] == "Hello from a canned Claude." and d["stop_reason"] == "end_turn"
          and d["usage"]["output_tokens"] > 0 and r["contentType"] == "application/json"
          and int(r["ResponseMetadata"]["HTTPHeaders"]["x-amzn-bedrock-output-token-count"]) == d["usage"]["output_tokens"], d)
    r = inv(CLAUDE, {"anthropic_version": "bedrock-2023-05-31", "max_tokens": 100, "tools": [{"name": "get_weather", "input_schema": {"type": "object"}}],
                     "messages": [{"role": "user", "content": "What is the weather in Paris?"}]})
    d = json.loads(r["body"].read())
    check("invoke_model anthropic: tool_use block", d["stop_reason"] == "tool_use" and d["content"][1] == {"type": "tool_use", "id": "tooluse_weather_1", "name": "get_weather",
                                                                                                            "input": {"city": "Paris", "unit": "celsius"}}, d)
    d = json.loads(inv("anthropic.claude-v2", {"prompt": "\n\nHuman: hello\n\nAssistant:", "max_tokens_to_sample": 50})["body"].read())
    check("invoke_model anthropic text completion API", d["completion"] == "Hello from a canned Claude." and d["stop_reason"] == "stop_sequence", d)
    d = json.loads(inv(NOVA, {"schemaVersion": "messages-v1", "messages": [{"role": "user", "content": [{"text": "hi"}]}]})["body"].read())
    check("invoke_model nova", d["output"]["message"]["content"][0]["text"] == "Hello from a canned Nova." and d["stopReason"] == "end_turn", d)
    families = {
        "amazon.titan-text-express-v1": ({"inputText": "hi"}, lambda d: d["results"][0]["outputText"].startswith("canned text") and d["results"][0]["completionReason"] == "FINISH"),
        "meta.llama3-8b-instruct-v1:0": ({"prompt": "hi", "max_gen_len": 20}, lambda d: d["generation"].startswith("canned text") and d["stop_reason"] == "stop"),
        "mistral.mistral-7b-instruct-v0:2": ({"prompt": "hi", "max_tokens": 20}, lambda d: d["outputs"][0]["text"].startswith("canned text")),
        "cohere.command-text-v14": ({"prompt": "hi"}, lambda d: d["generations"][0]["text"].startswith("canned text")),
        "cohere.command-r-v1:0": ({"message": "hi"}, lambda d: d["text"].startswith("canned text")),
        "ai21.jamba-1-5-large-v1:0": ({"messages": []}, lambda d: d["outputText"].startswith("canned text")),
    }
    for model, (body, ok) in families.items():
        d = json.loads(inv(model, body)["body"].read())
        check("invoke_model %s" % model.split(".")[0] + " " + model.split(".")[1][:14], ok(d), d)
    d = json.loads(inv("amazon.titan-embed-text-v2:0", {"inputText": "embed me"})["body"].read())
    check("invoke_model: an embedding (8 numbers, deterministic)", len(d["embedding"]) == 8 and d == json.loads(inv("amazon.titan-embed-text-v2:0", {"inputText": "embed me"})["body"].read()), d)
    e = err_of(br.invoke_model, modelId=CLAUDE, body=b"not json", contentType="application/json")
    check("invoke_model: a body that is not JSON is a ValidationException", code_of(e) == "ValidationException", e)

    # ---- InvokeModelWithResponseStream
    def stream_chunks(model, body):
        r = br.invoke_model_with_response_stream(modelId=model, body=json.dumps(body), contentType="application/json", accept="application/json")
        return [json.loads(ev["chunk"]["bytes"]) for ev in r["body"]], r
    chunks, r = stream_chunks(CLAUDE, {"anthropic_version": "bedrock-2023-05-31", "max_tokens": 100, "messages": [{"role": "user", "content": [{"type": "text", "text": "hello"}]}]})
    text = "".join(c["delta"]["text"] for c in chunks if c["type"] == "content_block_delta")
    check("invoke_model_with_response_stream anthropic: the full event sequence", [c["type"] for c in chunks][:2] == ["message_start", "content_block_start"] and text == "Hello from a canned Claude."
          and chunks[-1]["type"] == "message_stop" and chunks[-1]["amazon-bedrock-invocationMetrics"]["outputTokenCount"] > 0 and chunks[-2]["delta"]["stop_reason"] == "end_turn"
          and r["contentType"] == "application/json", [c["type"] for c in chunks])
    chunks, _ = stream_chunks(NOVA, {"messages": [{"role": "user", "content": [{"text": "hi"}]}]})
    text = "".join(c["contentBlockDelta"]["delta"]["text"] for c in chunks if "contentBlockDelta" in c)
    check("invoke_model_with_response_stream nova", text == "Hello from a canned Nova." and "messageStop" in chunks[-1], chunks[-1])
    chunks, _ = stream_chunks("amazon.titan-text-express-v1", {"inputText": "hi"})
    check("invoke_model_with_response_stream titan", "".join(c["outputText"] for c in chunks) == "canned text for any other family" and chunks[-1]["completionReason"] == "FINISH", chunks[-1])
    chunks, _ = stream_chunks("meta.llama3-8b-instruct-v1:0", {"prompt": "hi"})
    check("invoke_model_with_response_stream llama", "".join(c["generation"] for c in chunks) == "canned text for any other family" and chunks[-1]["stop_reason"] == "stop", chunks[-1])

    # ---- guardrails
    gc = {"guardrailIdentifier": "gr-abc123", "guardrailVersion": "1", "trace": "enabled"}
    r = br.converse(modelId=CLAUDE, messages=[user("tell me a secret")], guardrailConfig=gc)
    check("converse: guardrail intervention with trace", r["stopReason"] == "guardrail_intervened" and r["output"]["message"]["content"][0]["text"] == "Blocked by policy."
          and r["trace"]["guardrail"]["inputAssessment"]["gr-abc123"]["topicPolicy"]["topics"][0]["name"] == "secrets", r)
    r = br.converse(modelId=CLAUDE, messages=[user("tell me a secret")])
    check("converse: no guardrail on the request, no intervention", r["stopReason"] == "end_turn" and r["output"]["message"]["content"][0]["text"] == "A default canned answer.", r)
    r = br.invoke_model(modelId=CLAUDE, body=json.dumps({"anthropic_version": "bedrock-2023-05-31", "max_tokens": 10, "messages": [{"role": "user", "content": "a secret"}]}),
                        guardrailIdentifier="gr-abc123", guardrailVersion="1", trace="ENABLED")
    d = json.loads(r["body"].read())
    check("invoke_model: guardrail intervention (headers in, action and trace in the body)", d["amazon-bedrock-guardrailAction"] == "INTERVENED" and d["content"][0]["text"] == "Blocked by policy."
          and "gr-abc123" in d["amazon-bedrock-trace"]["guardrail"]["inputAssessment"], d)
    r = br.apply_guardrail(guardrailIdentifier="gr-abc123", guardrailVersion="DRAFT", source="INPUT", content=[{"text": {"text": "my credit card is 4111"}}])
    check("apply_guardrail: GUARDRAIL_INTERVENED with outputs and assessments", r["action"] == "GUARDRAIL_INTERVENED" and r["outputs"][0]["text"] == "Card numbers are blocked."
          and r["assessments"][0]["sensitiveInformationPolicy"]["piiEntities"][0]["type"] == "CREDIT_DEBIT_CARD_NUMBER" and "usage" in r, r)
    r = br.apply_guardrail(guardrailIdentifier="gr-abc123", guardrailVersion="DRAFT", source="OUTPUT", content=[{"text": {"text": "harmless text"}}])
    check("apply_guardrail: NONE", r["action"] == "NONE" and r["outputs"] == [], r)

    # ---- count tokens
    r = br.count_tokens(modelId=CLAUDE, input={"converse": {"messages": [user("twelve chars")]}})
    check("count_tokens: an estimate (about four characters a token)", r["inputTokens"] == 3, r)
    r = br.count_tokens(modelId=CLAUDE, input={"converse": {"messages": [user("a fixed count")]}})
    check("count_tokens: a rule", r["inputTokens"] == 42, r)

    # ---- faults
    fault(base, token, {"modelPrefix": "anthropic.", "operation": "converse", "error": {"code": "ThrottlingException"}, "times": 2})
    codes = [code_of(err_of(br.converse, modelId=CLAUDE, messages=[user("hello")])) for _ in range(3)]
    check("faults: two throttled calls, then normal", codes == ["ThrottlingException", "ThrottlingException", None], codes)
    fault(base, token, {"operation": "invoke", "error": {"code": "ValidationException", "message": "Malformed input request: #: extraneous key [foo] is not permitted"}})
    e = err_of(br.invoke_model, modelId=CLAUDE, body=json.dumps({"anthropic_version": "bedrock-2023-05-31", "max_tokens": 1, "messages": [{"role": "user", "content": "hi"}]}))
    check("faults: a ValidationException with the caller's message", code_of(e) == "ValidationException" and "extraneous key" in str(e) and e.response["ResponseMetadata"]["HTTPStatusCode"] == 400, e)
    fault(base, token, {"modelId": NOVA, "error": {"code": "ModelTimeoutException"}})
    e = err_of(br.converse, modelId=NOVA, messages=[user("hi")])
    check("faults: a model timeout is HTTP 408", code_of(e) == "ModelTimeoutException" and e.response["ResponseMetadata"]["HTTPStatusCode"] == 408, e)
    fault(base, token, {"modelPrefix": "amazon.", "streamError": {"code": "modelTimeoutException", "afterParts": 1}})
    r = br.invoke_model_with_response_stream(modelId=NOVA, body=json.dumps({"messages": [{"role": "user", "content": [{"text": "hi"}]}]}))
    got, ex = [], None
    try:
        for ev in r["body"]:
            got.append(list(ev.keys())[0])
    except Exception as x:
        ex = x
    check("faults: a stream that ends in modelTimeoutException", got == ["chunk", "chunk"] and ex is not None and "modelTimeoutException" in (type(ex).__name__ + str(ex)), (got, repr(ex)))

    # ---- control paths, the ledger, the engine's control plane
    st, led = http_json("GET", "%s/ledger?service=bedrock-runtime" % ctl, token)
    entries = led["entries"]
    ops = {e["operation"] for e in entries}
    check("ledger: the six operations under bedrock-runtime, every answer marked faked",
          {"Converse", "ConverseStream", "InvokeModel", "InvokeModelWithResponseStream", "CountTokens", "ApplyGuardrail"} <= ops
          and all(e.get("marker", "").startswith("faked") for e in entries if e["status"] < 400 or e.get("marker")), [e.get("marker") for e in entries][:5])
    check("ledger: markers say made-up, unmatched, fault, estimated, guardrail", {m for e in entries for m in [e.get("marker", "")]} >=
          {"faked", "faked; made-up answer", "faked; unmatched", "faked; fault", "faked; estimated", "faked; guardrail intervened"}, sorted({e.get("marker", "") for e in entries}))
    st, summary = http_json("GET", "%s/bedrock/summary" % ctl, token)
    t = summary["totals"]
    check("summary: faked, notTested, counters", summary["faked"] is True and "real model behaviour" in summary["notTested"] and t["streamed"] >= 6 and t["toolUseTurns"] >= 3
          and t["guardrailInterventions"] == 2 and t["unmatched"] == 1 and t["countTokens"] == 2 and t["applyGuardrail"] == 2 and t["madeUp"] >= 1, t)
    check("guard: control paths need the token", http_json("GET", "%s/bedrock/summary" % ctl)[0] == 403)
    bd = client("bedrock", base)
    models = bd.list_foundation_models()["modelSummaries"]
    check("engine: the control plane (ListFoundationModels) is still the engine's", len(models) > 0, len(models))
    g = bd.create_guardrail(name="live-guardrail", blockedInputMessaging="no", blockedOutputsMessaging="no", wordPolicyConfig={"wordsConfig": [{"text": "badword"}]})
    check("engine: CreateGuardrail", "guardrailId" in g, g)
    st, _ = http_json("POST", "%s/reset" % ctl, token)
    e = err_of(br.converse, modelId=CLAUDE, messages=[user("hello")])
    check("reset: the fixtures are gone (unmatched again)", st == 200 and code_of(e) == "ValidationException" and "no recorded or canned answer" in str(e), e)

    # ---- IAM on Bedrock runtime (informational: the engine does not enforce it, and the front does not know who calls)
    iam = client("iam", base)
    iam.create_user(UserName="nobedrock")
    iam.put_user_policy(UserName="nobedrock", PolicyName="p", PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}))
    ak = iam.create_access_key(UserName="nobedrock")["AccessKey"]
    put(base, token, "any", {"default": {"text": "answered for a user with no Bedrock permission"}})
    r = client("bedrock-runtime", base, ak["AccessKeyId"], ak["SecretAccessKey"]).converse(modelId=CLAUDE, messages=[user("hi")])
    print("INFO IAM: a user whose only policy is s3:GetObject calls Converse -> %s (not enforced: BI2 captures it)" % r["output"]["message"]["content"][0]["text"])
    s3 = client("s3", base, ak["AccessKeyId"], ak["SecretAccessKey"])
    client("s3", base).create_bucket(Bucket="iambucket")
    e = err_of(s3.put_object, Bucket="iambucket", Key="k", Body=b"x")
    print("INFO IAM: the same user calling S3 PutObject -> %s (the engine enforces IAM for S3 with -a off)" % (code_of(e) or "allowed"))


def run_js(base, token, args):
    here = os.path.dirname(os.path.abspath(__file__))
    env = dict(os.environ, NODE_PATH=os.path.join(args.js_sdk, "node_modules"), BEDROCK_BASE=base, ROVARA_TOKEN=token)
    p = subprocess.run([args.node, os.path.join(here, "bedrock_live.cjs")], env=env, capture_output=True, text=True, timeout=120)
    sys.stdout.write(p.stdout)
    if p.returncode != 0:
        sys.stdout.write(p.stderr[-2000:])
        FAILED.append("the JavaScript SDK checks")


main()
