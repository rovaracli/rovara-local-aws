#!/usr/bin/env python3
"""Measures one running rovara-aws-front (the front and its engine child together), the way decision 106 counts it.

    measure_front.py --pidfile <file with the front's pid> --spawned-at <epoch seconds> --endpoint http://127.0.0.1:4566 \
        --python <python with boto3> --matrix perf/matrix.py --out result.json

* start-up: the time from --spawned-at (the moment the process was spawned) to the first 200 from /_rovara/health;
* memory: PRIVATE memory (RssAnon from /proc/<pid>/status) summed over the front and every descendant, idle after 2 s with no
  traffic and peak, sampled every 50 ms while the 54-call matrix runs; VmRSS and RssFile are reported for information;
* median call: the median latency of the matrix calls that passed.

Gates (decision 106): start-up <= 0.5 s, peak private <= 256 MiB, median call <= 3 ms; the matrix needs >= 51 passes (the
engine fails 2-3 of 54 for reasons of its own, see the report).  Exit 0 when every gate holds."""
import argparse
import json
import os
import statistics
import subprocess
import sys
import threading
import time
import urllib.request

GATES = dict(start_s=0.5, peak_private_mib=256.0, median_ms=3.0, matrix_pass_min=51)


def children(pid):
    out = []
    try:
        for tid in os.listdir(f"/proc/{pid}/task"):
            try:
                out += [int(x) for x in open(f"/proc/{pid}/task/{tid}/children").read().split()]
            except OSError:
                pass
    except OSError:
        pass
    return out


def tree(pid):
    seen, todo = [], [pid]
    while todo:
        p = todo.pop()
        if p in seen:
            continue
        seen.append(p)
        todo += children(p)
    return seen


def mem_kib(pid):
    f = {}
    try:
        for line in open(f"/proc/{pid}/status"):
            k, _, v = line.partition(":")
            if k in ("VmRSS", "RssAnon", "RssFile", "RssShmem"):
                f[k] = int(v.split()[0])
    except OSError:
        pass
    return f


def total(pids):
    t = dict(VmRSS=0, RssAnon=0, RssFile=0, RssShmem=0)
    for p in pids:
        for k, v in mem_kib(p).items():
            t[k] += v
    return t


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pidfile", required=True)
    ap.add_argument("--spawned-at", type=float, required=True)
    ap.add_argument("--endpoint", required=True)
    ap.add_argument("--python", required=True)
    ap.add_argument("--matrix", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--median-warn", action="store_true", help="a median call over the gate is a warning, not a failure (CI)")
    a = ap.parse_args()

    # start-up: poll health until the first 200
    first = None
    while first is None and time.time() - a.spawned_at < 30:
        try:
            with urllib.request.urlopen(a.endpoint + "/_rovara/health", timeout=1) as r:
                if r.status == 200:
                    first = time.time()
        except Exception:
            time.sleep(0.005)
    if first is None:
        print("FAIL: the front never became healthy")
        return 2
    start_s = first - a.spawned_at
    pid = int(open(a.pidfile).read().strip())
    time.sleep(2.0)
    pids = tree(pid)
    idle = total(pids)

    peak = dict(idle)
    stop = threading.Event()
    series = []

    def sample():
        while not stop.is_set():
            t = total(tree(pid))
            series.append(t["RssAnon"])
            for k in peak:
                peak[k] = max(peak[k], t[k])
            time.sleep(0.05)

    th = threading.Thread(target=sample, daemon=True)
    th.start()
    out = a.out + ".matrix.json"
    t0 = time.time()
    r = subprocess.run([a.python, "-I", a.matrix, "compat", a.endpoint, out], capture_output=True, text=True)
    matrix_s = time.time() - t0
    stop.set()
    th.join()
    res = json.load(open(out))["results"]
    passed = [x for x in res if x["status"] == "PASS"]
    lat = [x["latency_ms"] for x in passed if x.get("latency_ms") is not None]
    after = total(tree(pid))
    mib = lambda kib: round(kib / 1024, 1)
    summary = dict(
        start_to_healthy_s=round(start_s, 3),
        processes=len(pids),
        idle_private_mib=mib(idle["RssAnon"]), idle_rss_mib=mib(idle["VmRSS"]), idle_file_mib=mib(idle["RssFile"]),
        peak_private_mib=mib(peak["RssAnon"]), peak_rss_mib=mib(peak["VmRSS"]), peak_file_mib=mib(peak["RssFile"]),
        after_matrix_private_mib=mib(after["RssAnon"]),
        front_private_mib=mib(mem_kib(pid).get("RssAnon", 0)),
        matrix_passed=len(passed), matrix_total=len(res), matrix_seconds=round(matrix_s, 1),
        median_call_ms=round(statistics.median(lat), 2) if lat else None,
        p95_call_ms=round(sorted(lat)[int(len(lat) * 0.95) - 1], 2) if lat else None,
        failed=[f"{x['service']} {x['call']}: {str(x.get('note'))[:80]}" for x in res if x["status"] == "FAIL"],
        skipped=[f"{x['service']} {x['call']}" for x in res if x["status"] == "SKIPPED"],
        gates=GATES,
    )
    verdict = []
    verdict.append(("start-up <= 0.5 s", summary["start_to_healthy_s"] <= GATES["start_s"]))
    verdict.append(("peak private <= 256 MiB", summary["peak_private_mib"] <= GATES["peak_private_mib"]))
    verdict.append(("median call <= 3 ms", summary["median_call_ms"] is not None and summary["median_call_ms"] <= GATES["median_ms"]))
    verdict.append((f"matrix >= {GATES['matrix_pass_min']} of 54", len(passed) >= GATES["matrix_pass_min"]))
    summary["verdict"] = {k: v for k, v in verdict}
    json.dump(summary, open(a.out, "w"), indent=1)
    print(json.dumps(summary, indent=1))
    hard = [(k, v) for k, v in verdict if not (a.median_warn and k.startswith("median call"))]
    for k, v in verdict:
        if not v and a.median_warn and k.startswith("median call"):
            print(f"::warning::{k} was missed ({summary['median_call_ms']} ms); decision 106 gate, reported not enforced here")
    return 0 if all(v for _, v in hard) else 1


if __name__ == "__main__":
    sys.exit(main())
