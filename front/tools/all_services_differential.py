#!/usr/bin/env python3
"""Differential test of planned mode for EVERY service of the engine's table (436), against the real AWS Emulator.

The property: the front never forwards a request the engine would execute as a service the plan does not name.

How "the engine executed service X" is read without a hook in the engine: for every service X the script derives, from the Smithy
models (not from the front's generated tables), a sample request per wire protocol X speaks (one operation, valid on the wire), and
sends it to the engine signed for X's own route key. The engine's answer is X's BASELINE (the engine is deterministic; ids and
timestamps are masked). An answer equal to X's baseline, to a request sent under any other route key or through the front under
any plan, means X executed it. Requests whose baseline is a routing refusal (404 UnknownService, 500 AmbiguousService, "not
implemented", InvalidAction) are not usable as a probe and are counted.

Phase 1 (engine only, the lemma the front's decision rests on): X's sample under EVERY other route key and scope name. X executed
it under a key outside {X's route key, X's alternative scope name} only where the table says X shares a route key with the service
the key names; anything else is a failure.

Phase 2 (front, three plans): for each plan the script starts its own front (with the engine as its child) and sends, for every
service X, (a) the sample under X's own scope, (b) the sample under the scope of K other services (the planned ones and random
ones: crafted mismatches), and reads the front's ledger to see which service the front decided and whether it forwarded. It fails
when: a request is forwarded for a service not in the plan; a forwarded request is answered with X's baseline while X is not in the
plan; the decided service is not planned; a planned service's valid request is refused or attributed to another service (counted
and listed: expected only for the inseparable pairs of services_gen_report.txt).

    all_services_differential.py --front-bin <rovara-aws-front> --engine-bin /usr/bin/aws-emulator \
        --table <aws-emulator-services.json> --models <engine checkout>/services --not-impl <aws-emulator-not-implemented.json>
"""
import argparse
import glob
import http.client
import json
import os
import random
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
LONGNUM = re.compile(r"\d{8,}")
ISO = re.compile(r"\d{4}-\d{2}-\d{2}T[\d:.]+Z?")
REFUSAL = re.compile(r"UnknownService|AmbiguousService|is not implemented|UnknownOperation|InvalidAction|not recognised|does not name|ServiceNotAvailable")


def mask(b: bytes) -> str:
    t = b.decode("utf-8", "replace")
    for r, s in ((UUID, "<id>"), (ISO, "<ts>"), (LONGNUM, "<n>")):
        t = r.sub(s, t)
    return t[:600]


def auth(scope, region="us-east-1"):
    return f"AWS4-HMAC-SHA256 Credential=AK/20260101/{region}/{scope}/aws4_request, SignedHeaders=host, Signature=" + "0" * 64


# ---------------------------------------------------------------- the services, from the models

def load_services(table_path, models_dir, ni_path):
    table = json.load(open(table_path))
    ni = json.load(open(ni_path))["services"]
    models = {}
    for f in sorted(glob.glob(os.path.join(models_dir, "service-*", "smithy-model", "*.json"))):
        m = json.load(open(f))
        for k, v in m["shapes"].items():
            if v["type"] == "service":
                models[k] = m
    out = []
    for s in table["services"]:
        m = models[s["smithyId"]]
        sh = m["shapes"]
        svc = sh[s["smithyId"]]
        ops, seen = set(), set()

        def walk(r):
            if r in seen:
                return
            seen.add(r)
            v = sh[r]
            for key in ("operations", "collectionOperations"):
                for o in v.get(key) or []:
                    ops.add(o["target"])
            for key in ("create", "read", "update", "delete", "list", "put"):
                if key in v:
                    ops.add(v[key]["target"])
            for x in v.get("resources") or []:
                walk(x["target"])

        for o in svc.get("operations") or []:
            ops.add(o["target"])
        for r in svc.get("resources") or []:
            walk(r["target"])
        notimpl = set(ni.get(s["key"], {}).get("notImplemented", [])) | set(ni.get(s["key"], {}).get("unwired", []))
        oplist = []
        for o in sorted(ops):
            local = o.split("#")[1]
            http_t = sh[o].get("traits", {}).get("smithy.api#http")
            oplist.append((local, http_t, local in notimpl))
        rk = s["signingName"] or s["sdkId"].lower().replace(" ", "")
        out.append(dict(key=s["key"], rk=rk, sdk=s["sdkId"], shape=s["smithyId"].split("#")[1], prefix=s["targetPrefix"],
                        qver=s["queryVersion"], protocols=s["protocols"], ops=oplist, ep=s["endpointPrefix"]))
    return out, table


def prefer(ops):
    def rank(o):
        n = o[0]
        return (0 if o[2] is False else 1, 0 if n.startswith(("List", "Describe", "Get")) else 1, n)
    return sorted(ops, key=rank)


def samples(svc, limit=4):
    limit = limit or 100000
    """Candidate sample requests of a service, per wire protocol: (protocol, op, method, path, headers, body)."""
    out = []
    prot = svc["protocols"]
    ops = [o for o in prefer(svc["ops"]) if not o[2]]
    rest = [o for o in ops if o[1]]
    if any(p in ("awsJson1_0", "awsJson1_1") for p in prot) and svc["prefix"]:
        ver = "1.0" if "awsJson1_0" in prot else "1.1"
        for local, _, _ in ops[:limit]:
            out.append(("json", local, "POST", "/", {"X-Amz-Target": f"{svc['prefix']}.{local}", "Content-Type": f"application/x-amz-json-{ver}"}, b"{}"))
    if any(p in ("awsQuery", "ec2Query") for p in prot) and svc["qver"]:
        for local, _, _ in ops[:limit]:
            out.append(("query", local, "POST", "/", {"Content-Type": "application/x-www-form-urlencoded"}, f"Action={local}&Version={svc['qver']}".encode()))
    if "rpcv2Cbor" in prot:
        for local, _, _ in ops[:limit]:
            out.append(("cbor", local, "POST", f"/service/{svc['shape']}/operation/{local}",
                        {"smithy-protocol": "rpc-v2-cbor", "Content-Type": "application/cbor", "Accept": "application/cbor"}, b"\xa0"))
    if any(p in ("restJson1", "restXml") for p in prot):
        xml = "restXml" in prot
        for local, h, _ in rest[:limit]:
            uri = h["uri"]
            q = ""
            if "?" in uri:
                uri, q = uri.split("?", 1)
            uri = re.sub(r"\{[^}]*\+\}", "x1/y2", uri)
            uri = re.sub(r"\{[^}]*\}", "x1", uri)
            method = h["method"].upper()
            hdr = {} if xml else {"Content-Type": "application/json"}
            body = b"" if xml or method in ("GET", "DELETE", "HEAD") else b"{}"
            out.append(("rest", local, method, uri + ("?" + q if q else ""), hdr, body))
    return out


# ---------------------------------------------------------------- transport

class Conn:
    def __init__(self, host, port, ctx=None):
        self.host, self.port, self.ctx = host, port, ctx
        self.c = None

    def send(self, method, path, headers, body):
        for attempt in range(3):
            try:
                if self.c is None:
                    self.c = (http.client.HTTPSConnection(self.host, self.port, context=self.ctx, timeout=30) if self.ctx
                              else http.client.HTTPConnection(self.host, self.port, timeout=30))
                self.c.request(method, path, body=body or None, headers=headers)
                r = self.c.getresponse()
                data = r.read()
                return r.status, dict(r.getheaders()), data
            except (http.client.HTTPException, OSError):
                try:
                    self.c.close()
                except Exception:
                    pass
                self.c = None
        return 0, {}, b"transport failure"


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def start_engine(binary):
    home = tempfile.mkdtemp()
    port = free_port()
    env = {"HOME": home, "EMULATOR_TELEMETRY": "off", "PATH": "/usr/bin:/bin"}
    p = subprocess.Popen([binary, "-b", "127.0.0.1", "-p", str(port), "-t", "off", "-a", "off"], env=env,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    ca = f"{home}/.aws/emulator/{port}/ca.pem"
    for _ in range(200):
        if os.path.exists(ca):
            break
        time.sleep(0.1)
    time.sleep(0.5)
    return p, port, ssl.create_default_context(cafile=ca), home


def start_front(front_bin, engine_bin, planned):
    port = free_port()
    work = tempfile.mkdtemp()
    token = "tk" + "".join(random.choice("abcdef0123456789") for _ in range(24))
    env = {"HOME": work, "PATH": "/usr/bin:/bin", "QUARKUS_HTTP_HOST": "127.0.0.1", "QUARKUS_HTTP_PORT": str(port),
           "ROVARA_AWS_BASE_URL": "http://aws:4566", "ROVARA_AWS_AUTH_PRESIGN_SECRET": "ps" + token, "ROVARA_AWS_SERVICES_SQS_RECEIPT_HANDLE_SECRET": "rc" + token,
           "ROVARA_AWS_CONTROL_TOKEN": token, "ROVARA_AWS_DEFAULT_REGION": "us-east-1", "ROVARA_AWS_HOSTNAME": "aws",
           "ROVARA_AWS_ENGINE_BIN": engine_bin, "ROVARA_AWS_FRONT_WORKDIR": work, "ROVARA_AWS_PLANNED_SERVICES": planned,
           "ROVARA_AWS_LEDGER_MAX_ENTRIES": "100000"}
    p = subprocess.Popen([front_bin], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    c = Conn("127.0.0.1", port)
    for _ in range(300):
        s, _, _ = c.send("GET", "/_rovara/health", {}, b"")
        if s == 200:
            break
        time.sleep(0.1)
    else:
        raise SystemExit("the front did not become healthy")
    return p, port, token, work


# ---------------------------------------------------------------- phases

def baselines(svcs, eng_conn_factory):
    """Per service, the usable samples with their baseline answers under the service's own route key."""
    usable = {}
    unusable = []

    def one(svc):
        conn = eng_conn_factory()
        picked, seen_proto = [], set()
        for proto, op, method, path, hdr, body in samples(svc):
            if proto in seen_proto:
                continue
            h = dict(hdr)
            h["Authorization"] = auth(svc["rk"])
            s, _, b = conn.send(method, path, h, body)
            txt = mask(b)
            if s == 0 or REFUSAL.search(txt) or s >= 500 or s in (401, 403) or method == "HEAD" or not b:
                continue  # a refusal, a failure or an empty answer (a HEAD) says nothing about who answered
            seen_proto.add(proto)
            picked.append(dict(proto=proto, op=op, method=method, path=path, hdr=hdr, body=body, base=(s, txt)))
        return svc["key"], picked

    with ThreadPoolExecutor(8) as ex:
        for key, picked in ex.map(one, svcs):
            if picked:
                usable[key] = picked
            else:
                unusable.append(key)
    return usable, unusable


def phase1(svcs, usable, eng_conn_factory, table):
    keys = sorted({s["rk"] for s in svcs} | {"cloudwatchevents", "docdb", "neptune", "s3express", "execute-api"})
    by_rk = {}
    for s in svcs:
        by_rk.setdefault(s["rk"], set()).add(s["key"])
    alt = {"cloudwatchevents": "cloudwatch-events", "docdb": "docdb", "neptune": "neptune", "s3express": "s3"}
    violations, tested, cross = [], 0, []
    lock = threading.Lock()

    def one(svc):
        nonlocal tested
        conn = eng_conn_factory()
        res = []
        for sm in usable.get(svc["key"], []):
            for k in keys:
                own = {svc["rk"]} | {a for a, kk in alt.items() if kk == svc["key"]}
                if k in own:
                    continue
                h = dict(sm["hdr"])
                h["Authorization"] = auth(k)
                s, _, b = conn.send(sm["method"], sm["path"], h, sm["body"])
                with lock:
                    tested += 1
                if (s, mask(b)) == sm["base"]:
                    res.append((svc["key"], sm["proto"], sm["op"], k))
        return res

    with ThreadPoolExecutor(8) as ex:
        for res in ex.map(one, svcs):
            cross.extend(res)
    for key, proto, op, k in cross:
        # allowed: the key names a service that has the same operation (the shared-name pair): the answer is that service's
        others = by_rk.get(k, set())
        violations.append((key, proto, op, k, sorted(others)))
    return tested, violations


DECOYS = ["account", "ssm", "sns", "kms", "sqs"]


def phase1b(svcs, eng_conn_factory):
    """EVERY operation of every service (not one sample) under a few route keys that name unrelated single-service names. The
    answer is the service's baseline (its own answer under its own key) only when the engine claims the request without regard
    for the route key: a target or path claim. Those are the services the front must not let such a request reach."""
    free = {}
    tested = [0]
    lock = threading.Lock()

    def one(svc):
        conn = eng_conn_factory()
        hits = []
        for proto, op, method, path, hdr, body in samples(svc, None):
            if method == "HEAD":
                continue
            h = dict(hdr)
            h["Authorization"] = auth(svc["rk"])
            s, _, b = conn.send(method, path, h, body)
            txt = mask(b)
            if s == 0 or REFUSAL.search(txt) or s >= 500 or s in (401, 403) or not b:
                continue
            for k in DECOYS:
                if k == svc["rk"]:
                    continue
                h["Authorization"] = auth(k)
                s2, _, b2 = conn.send(method, path, h, body)
                with lock:
                    tested[0] += 1
                if (s2, mask(b2)) == (s, txt):
                    hits.append((proto, op, method, path, k))
        return svc["key"], hits

    opsets = {}
    for sv in svcs:
        opsets.setdefault(sv["rk"], set()).update(o[0] for o in sv["ops"])
    with ThreadPoolExecutor(8) as ex:
        for key, hits in ex.map(one, svcs):
            # the decoy's own services have an operation of that name: two services answering the same request the same way
            real = [h for h in hits if h[1] not in opsets.get(h[4], set())]
            if real:
                free[key] = real
    return tested[0], free


PLANS = {
    # one planned member of several shared groups, never its siblings
    "A": "s3,sqs,dynamodb,sns,lambda,eventbridge,rds,apigatewayv2,secretsmanager,ssm,sagemaker,iam",
    # the siblings, and others
    "B": "s3-control,dynamodb-streams,cloudwatch-events,docdb,neptune,api-gateway,lambda-microvms,sts,kms,kinesis,timestream-write,cognito-identity-provider",
}


def ledger_entries(conn, token, after):
    s, _, b = conn.send("GET", f"/_rovara/ledger?after={after}&limit=10000", {"x-rovara-control-token": token}, b"")
    d = json.loads(b)
    return d["entries"], d["lastSeq"]


def phase2(svcs, usable, front_bin, engine_bin, plan_name, planned_csv, rnd):
    opsets_by_key = {sv["key"]: {o[0] for o in sv["ops"]} for sv in svcs}
    p, port, token, work = start_front(front_bin, engine_bin, planned_csv)
    try:
        conn = Conn("127.0.0.1", port)
        if planned_csv == "ALL":
            pass
        keyset = {x for x in planned_csv.split(",")}
        legacy = {"secretsmanager": "secrets-manager", "events": "eventbridge"}
        planned = {legacy.get(k, k) for k in keyset}
        stats = dict(plan=plan_name, planned=len(planned), requests=0, own_forwarded=0, own_out_of_plan=0, own_refused_planned=0,
                     own_misattributed=0, crossed=0, crossed_forwarded=0, answered_baseline_through_front=0)
        fails, refused_planned, misattr, sibling = [], [], [], []
        rks = sorted({s["rk"] for s in svcs})
        by_key = {s["key"]: s for s in svcs}
        planned_rks = sorted({by_key[k]["rk"] for k in planned if k in by_key})
        seq = 0
        for svc in svcs:
            for sm in usable.get(svc["key"], []):
                scopes = [("own", svc["rk"])] + [("cross", k) for k in rnd.sample(rks, 6) + planned_rks[:6] if k != svc["rk"]]
                for kind, scope in scopes:
                    h = dict(sm["hdr"])
                    h["Authorization"] = auth(scope)
                    s, hd, b = conn.send(sm["method"], sm["path"], h, sm["body"])
                    ents, seq2 = ledger_entries(conn, token, seq)
                    seq = seq2
                    stats["requests"] += 1
                    e = ents[-1] if ents else {}
                    decided = e.get("service", "?")
                    forwarded = decided not in ("unknown", "?") and not e.get("outOfPlan", False)
                    same_as_base = (s, mask(b)) == sm["base"]
                    X = svc["key"]
                    if forwarded and decided not in planned:
                        fails.append(("forwarded a service the plan does not name", X, sm["proto"], sm["op"], scope, decided))
                    # X's baseline through the front, X not in the plan: X executed it, unless the decided (planned) service has an
                    # operation of the same name and answers it the same way (cloudwatch-events and eventbridge, rds and docdb)
                    if forwarded and X not in planned and same_as_base and sm["op"] not in opsets_by_key.get(decided, set()):
                        fails.append(("a service outside the plan answered through the front", X, sm["proto"], sm["op"], scope, decided))
                    if kind == "own":
                        if X in planned:
                            if forwarded and decided == X:
                                stats["own_forwarded"] += 1
                            elif forwarded:
                                stats["own_misattributed"] += 1
                                misattr.append((X, sm["proto"], sm["op"], decided))
                            else:
                                stats["own_refused_planned"] += 1
                                refused_planned.append((X, sm["proto"], sm["op"], decided, e.get("outOfPlan")))
                        else:
                            if forwarded and sm["op"] not in opsets_by_key.get(decided, set()):
                                fails.append(("an unplanned service's own request was forwarded", X, sm["proto"], sm["op"], scope, decided))
                            elif forwarded:
                                stats["own_served_as_planned_sibling"] = stats.get("own_served_as_planned_sibling", 0) + 1
                                sibling.append((X, sm["op"], decided))
                            elif e.get("outOfPlan"):
                                stats["own_out_of_plan"] += 1
                    else:
                        stats["crossed"] += 1
                        if forwarded:
                            stats["crossed_forwarded"] += 1
                        if forwarded and same_as_base:
                            stats["answered_baseline_through_front"] += 1
        # the front never forwards a request it cannot place, and the engine is still alive
        s, _, _ = conn.send("GET", "/_rovara/health", {}, b"")
        stats["health_after"] = s
        stats["siblings"] = sibling
        return stats, fails, refused_planned, misattr
    finally:
        p.terminate()
        try:
            p.wait(5)
        except Exception:
            p.kill()
        shutil.rmtree(work, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--front-bin", required=True)
    ap.add_argument("--engine-bin", required=True)
    ap.add_argument("--table", required=True)
    ap.add_argument("--models", required=True)
    ap.add_argument("--not-impl", required=True)
    ap.add_argument("--out", default="all_services_differential.json")
    ap.add_argument("--limit", type=int, default=0, help="only the first N services (a quick run)")
    a = ap.parse_args()
    svcs, table = load_services(a.table, a.models, a.not_impl)
    if a.limit:
        svcs = svcs[: a.limit]
    t0 = time.time()
    eng, eport, ectx, ehome = start_engine(a.engine_bin)
    try:
        factory = lambda: Conn("127.0.0.1", eport, ectx)
        usable, unusable = baselines(svcs, factory)
        print(f"baselines: {len(usable)} of {len(svcs)} services have a usable sample; {len(unusable)} have none", flush=True)
        tested, cross = phase1(svcs, usable, factory, table)
        print(f"phase 1: {tested} engine requests (every service's sample under every other route key); {len(cross)} answered as the service itself", flush=True)
        t1b, free = phase1b(svcs, factory)
        print(f"phase 1b: {t1b} engine requests (every operation of every service under {len(DECOYS)} unrelated route keys); {len(free)} services answered a request under a foreign key", flush=True)
        for k, hits in sorted(free.items()):
            kinds = sorted({h[0] for h in hits})
            print(f"  FREE-CLAIMER {k}: {len(hits)} requests ({','.join(kinds)}), e.g. {hits[0][2]} {hits[0][3]} {hits[0][1]}")
    finally:
        eng.terminate()
        eng.wait(5)
    opsets = {}
    for s in svcs:
        opsets.setdefault(s["rk"], set()).update(o[0] for o in s["ops"])
    for k, v in {"cloudwatchevents": "cloudwatch-events", "docdb": "docdb", "neptune": "neptune", "s3express": "s3"}.items():
        opsets.setdefault(k, set()).update(o[0] for s in svcs if s["key"] == v for o in s["ops"])
    # an answer equal to the service's baseline under another service's route key is a coincidence when that other service has an
    # operation of the same name (two services that answer the same request with the same validation error); otherwise it is the
    # service itself executing under a key it should not answer to
    real_viol = [c for c in cross if c[2] not in opsets.get(c[3], set()) and c[0] not in free]
    claimed = [c for c in cross if c[0] in free]
    print(f"phase 1: {len(real_viol)} answered as the service itself under a key whose services have no operation of that name (and the service is not a target claimer); {len(claimed)} are the target claimers {sorted(free)}; {len(cross) - len(real_viol) - len(claimed)} are same-operation coincidences")
    for c in real_viol[:30]:
        print("PHASE1 FAIL:", *c[:4])
    rnd = random.Random(20261111)
    all_fails, summary = [], dict(services=len(svcs), usable=len(usable), unusable=sorted(unusable), phase1_requests=tested,
                                  phase1_cross=[list(c[:4]) + [c[4]] for c in cross], plans=[])
    plans = dict(PLANS)
    plans["ALL"] = ",".join(s["key"] for s in svcs)
    for name, csv in plans.items():
        stats, fails, refused_planned, misattr = phase2(svcs, usable, a.front_bin, a.engine_bin, name, csv, rnd)
        print(json.dumps(stats), flush=True)
        for f in fails[:20]:
            print("FAIL:", *f)
        all_fails.extend(fails)
        summary["plans"].append(dict(stats=stats, fails=[list(f) for f in fails], refused_planned=[list(r) for r in refused_planned], misattributed=[list(m) for m in misattr]))
    json.dump(summary, open(a.out, "w"), indent=1)
    print(f"all_services_differential: {len(svcs)} services in {time.time() - t0:.0f}s,", "FAILED" if (all_fails or real_viol) else "no request was forwarded for a service outside its plan")
    return 1 if (all_fails or real_viol) else 0


if __name__ == "__main__":
    sys.exit(main())
