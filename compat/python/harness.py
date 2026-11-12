"""Tiny test harness for the boto3 compatibility suite: registered cases, a fresh client factory, JSON results.

Everything talks to one loopback endpoint with fake credentials built at run time. Nothing here reads
the network beyond that endpoint."""
import json
import os
import sys
import time
import traceback
import urllib.error
import urllib.request

import boto3
from botocore.config import Config

CASES = []   # (group, name, fn)


def case(group):
    def deco(fn):
        CASES.append((group, fn.__name__, fn))
        return fn
    return deco


FAKE = "te" + "st"            # fake credential, assembled so no key-shaped literal sits in the source
REGION = "us-east-1"


class Env:
    def __init__(self, endpoint, validated_endpoint=None, control_token=None):
        assert endpoint.startswith(("http://127.0.0.1", "http://localhost")), "loopback endpoints only"
        self.endpoint = endpoint
        self.validated_endpoint = validated_endpoint
        self.control_token = control_token
        self._n = 0
        self.tag = "cx%d" % (int(time.time()) % 100000)

    def client(self, service, endpoint=None, key=FAKE, secret=FAKE, **kw):
        cfg = Config(retries={"max_attempts": 1}, connect_timeout=5, read_timeout=30,
                     s3={"addressing_style": "path"}, **kw.pop("config", {}))
        return boto3.client(service, endpoint_url=endpoint or self.endpoint, region_name=REGION,
                            aws_access_key_id=key, aws_secret_access_key=secret, config=cfg, **kw)

    def name(self, kind="r"):
        self._n += 1
        return f"{self.tag}-{kind}{self._n}"

    # ---- control endpoint ----
    def control(self, method, path, body=None):
        headers = {}
        if self.control_token:
            headers["X-Rovara-Control-Token"] = self.control_token
        data = None
        if body is not None:
            data = body if isinstance(body, bytes) else json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(self.endpoint + path, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                raw = r.read()
                return r.status, (json.loads(raw) if raw else None)
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                return e.code, json.loads(raw)
            except ValueError:
                return e.code, raw

    def raw(self, method, url, data=None, headers=None):
        req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()


def error_code(exc):
    return getattr(exc, "response", {}).get("Error", {}).get("Code")


def expect_error(codes, fn, *a, **kw):
    codes = (codes,) if isinstance(codes, str) else tuple(codes)
    try:
        fn(*a, **kw)
    except Exception as e:  # noqa
        code = error_code(e)
        assert code in codes, f"expected {codes}, got {code}: {e}"
        return e
    raise AssertionError(f"expected {codes}, but the call succeeded")


def run(env, only=None, out=None):
    results = []
    for group, name, fn in CASES:
        if only and only not in (group, name):
            continue
        t0 = time.perf_counter()
        status, msg = "pass", ""
        try:
            fn(env)
        except AssertionError as e:
            status, msg = "fail", str(e)[:300]
        except Exception as e:  # noqa
            status, msg = "fail", f"{type(e).__name__}: {str(e)[:250]} | {traceback.format_exc().strip().splitlines()[-3].strip()[:120]}"
        results.append({"group": group, "test": name, "status": status, "message": msg,
                        "ms": round((time.perf_counter() - t0) * 1000, 1)})
        print(f"[boto3] {group:12s} {name:46s} {status} {msg[:100]}", flush=True)
    failed = [r for r in results if r["status"] != "pass"]
    if out:
        with open(out, "w") as f:
            json.dump({"sdk": "boto3", "version": boto3.__version__, "passed": len(results) - len(failed),
                       "failed": len(failed), "results": results}, f, indent=1)
    print(f"[boto3] {len(results) - len(failed)}/{len(results)} passed")
    return 0 if not failed else 1
