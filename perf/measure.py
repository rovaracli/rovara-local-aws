#!/usr/bin/env python3
"""Measure start-up, memory and call latency of one build of Rovara local AWS.

    python3 -I perf/measure.py --label native --cmd "target/rovara-local-aws-0.1.0-runner" \
        --python /path/to/python-with-boto3 --out perf/native.json [--runs 3] [--check]

Start-up is the time from spawning the process to the first successful answer from
/_rovara/health. Idle memory is read after the process has settled with no traffic. Peak memory is the
highest value sampled (every 50 ms) while the matrix (perf/matrix.py) runs. Median call is
the median latency of the matrix calls that passed.

Memory gates count the run's PRIVATE memory (owner decision, 2026-11-03): on Linux RssAnon from /proc/<pid>/status
(anonymous pages: heap, stacks, thread arenas); on macOS the physical footprint from `footprint` (dirty plus
compressed pages, no clean file-backed pages), the closest equivalent. Total RSS (which on Linux also counts the
pages of the mapped 126 MB binary, shared and reclaimable) is recorded and printed next to it as information and
never fails the run. Every run uses a loopback-only listener, fake
credentials, no instance metadata and a Docker host that does not exist.
"""
import argparse, json, os, re, shlex, socket, statistics, subprocess, sys, tempfile, threading, time
import urllib.request

TARGETS = {"start_s": 0.5, "idle_mib": 64.0, "peak_mib": 128.0, "median_ms": 3.0, "pass_min": 52}


def rss_kib(pid):
    out = subprocess.run(["ps", "-o", "rss=", "-p", str(pid)], capture_output=True, text=True).stdout.strip()
    return int(out) if out else 0


STATUS_KEYS = ("VmRSS", "RssAnon", "RssFile", "RssShmem")


def parse_status(text):
    """The memory lines of a Linux /proc/<pid>/status as {key: kB}; None when none of them is there."""
    fields = {}
    for line in text.splitlines():
        key, _, rest = line.partition(":")
        if key in STATUS_KEYS:
            try:
                fields[key] = int(rest.split()[0])
            except (ValueError, IndexError):
                return None
    return fields or None


def parse_footprint(text):
    """The footprint in KiB from the first line `... Footprint: <n> B (...)` of `footprint -f bytes`; None when absent."""
    m = re.search(r"Footprint:\s*(\d+)\s*B\b", text)
    return int(m.group(1)) // 1024 if m else None


def rss_detail_kib(pid, root="/proc"):
    """Resident memory split into anonymous (heap, stacks), file-backed (the mapped binary and libraries) and shared, from
    /proc/<pid>/status on Linux; None elsewhere."""
    try:
        return parse_status(open(f"{root}/{pid}/status").read())
    except OSError:
        return None


def mem_sample(pid, root="/proc"):
    """One memory reading: {"private_kib", "total_kib", "source"}. Private is what the gate counts: RssAnon on Linux, the
    physical footprint on macOS. Where neither exists it falls back to total RSS and says so in `source`."""
    detail = rss_detail_kib(pid, root)
    if detail and "RssAnon" in detail:
        return {"private_kib": detail["RssAnon"], "total_kib": detail.get("VmRSS", rss_kib(pid)), "source": "RssAnon (/proc/<pid>/status)"}
    if sys.platform == "darwin":
        try:
            out = subprocess.run(["footprint", "-p", str(pid), "-f", "bytes"], capture_output=True, text=True, timeout=10).stdout
            fp = parse_footprint(out)
            if fp is not None:
                return {"private_kib": fp, "total_kib": rss_kib(pid), "source": "physical footprint (footprint)"}
        except (OSError, subprocess.TimeoutExpired):
            pass
    total = rss_kib(pid)
    return {"private_kib": total, "total_kib": total, "source": "total RSS (no private measure on this system)"}


def start_runner(args):
    """The test-only function runner, in its own process so its memory is not the emulator's."""
    token = "perf-" + os.urandom(12).hex()
    script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "local_process_runner.py")
    proc = subprocess.Popen([args.python, "-I", script, "--python", args.python, "--token", token],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    line = proc.stdout.readline().split()
    if len(line) != 2 or line[0] != "LISTENING":
        proc.kill()
        raise RuntimeError("the function runner did not start")
    return proc, f"http://127.0.0.1:{line[1]}", token


def one_run(args, port):
    runner = start_runner(args) if not args.no_runner else None
    try:
        return _one_run(args, port, runner)
    finally:
        if runner:
            runner[0].terminate()
            try:
                runner[0].wait(10)
            except subprocess.TimeoutExpired:
                runner[0].kill()


def _one_run(args, port, runner):
    env = dict(os.environ)
    env.update({"DOCKER_HOST": "unix:///nonexistent", "AWS_EC2_METADATA_DISABLED": "true",
                "QUARKUS_HTTP_PORT": str(port), "ROVARA_AWS_PORT": str(port),
                "ROVARA_AWS_BASE_URL": f"http://127.0.0.1:{port}"})
    env.pop("AWS_PROFILE", None)
    if runner:
        env.update({"ROVARA_AWS_SERVICES_LAMBDA_FUNCTION_RUNNER_URL": runner[1],
                    "ROVARA_AWS_SERVICES_LAMBDA_FUNCTION_RUNNER_TOKEN": runner[2],
                    "ROVARA_FUNCTION_RUNNER": "1"})
    cmd = shlex.split(args.cmd)
    log = tempfile.NamedTemporaryFile(prefix="rovara-perf-", suffix=".log", delete=False)
    t0 = time.perf_counter()
    proc = subprocess.Popen(cmd, env=env, stdout=log, stderr=subprocess.STDOUT)
    url = f"http://127.0.0.1:{port}/_rovara/health"
    started = None
    try:
        while time.perf_counter() - t0 < 60:
            if proc.poll() is not None:
                raise RuntimeError(f"process exited early ({proc.returncode}); log {log.name}")
            try:
                with urllib.request.urlopen(url, timeout=0.2) as r:
                    if r.status == 200:
                        started = time.perf_counter() - t0
                        break
            except Exception:
                time.sleep(0.002)
        if started is None:
            raise RuntimeError("no answer within 60 s")
        time.sleep(args.settle)
        idle_s = mem_sample(proc.pid)
        idle_detail = rss_detail_kib(proc.pid)
        peak = [idle_s["private_kib"]]
        peak_total = [idle_s["total_kib"]]
        stop = threading.Event()

        def sampler():
            while not stop.is_set():
                sm = mem_sample(proc.pid)
                peak[0] = max(peak[0], sm["private_kib"])
                peak_total[0] = max(peak_total[0], sm["total_kib"])
                time.sleep(0.05)

        th = threading.Thread(target=sampler, daemon=True)
        th.start()
        out = tempfile.NamedTemporaryFile(prefix="rovara-matrix-", suffix=".json", delete=False).name
        m = subprocess.run([args.python, "-I", args.matrix, args.label, f"http://127.0.0.1:{port}", out],
                           capture_output=True, text=True, env={**env, "AWS_ACCESS_KEY_ID": "test"})
        stop.set(); th.join()
        sm = mem_sample(proc.pid)
        peak[0] = max(peak[0], sm["private_kib"])
        peak_total[0] = max(peak_total[0], sm["total_kib"])
        end_detail = rss_detail_kib(proc.pid)
        res = json.load(open(out))["results"]
        passed = [r for r in res if r.get("status") == "PASS"]
        failed = [r["call"] for r in res if r.get("status") == "FAIL"]
        lat = [r["latency_ms"] for r in passed if "latency_ms" in r]
        return {"start_s": started, "idle_mib": idle_s["private_kib"] / 1024, "peak_mib": peak[0] / 1024,
                "idle_rss_mib": idle_s["total_kib"] / 1024, "peak_rss_mib": peak_total[0] / 1024,
                "memory_source": idle_s["source"],
                "median_ms": statistics.median(lat) if lat else None,
                "pass": len(passed), "total": len(res), "failed_calls": failed,
                "matrix_stdout_tail": m.stdout.strip().splitlines()[-2:],
                "idle_detail_kib": idle_detail, "after_matrix_detail_kib": end_detail}
    finally:
        proc.terminate()
        try:
            proc.wait(10)
        except subprocess.TimeoutExpired:
            proc.kill()


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--label", required=True)
    ap.add_argument("--cmd", required=True)
    ap.add_argument("--python", required=True)
    ap.add_argument("--matrix", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "matrix.py"))
    ap.add_argument("--out", required=True)
    ap.add_argument("--runs", type=int, default=1)
    ap.add_argument("--settle", type=float, default=3.0)
    ap.add_argument("--no-runner", action="store_true", help="do not start the test-only function runner (Lambda case is skipped)")
    ap.add_argument("--check", action="store_true", help="exit 1 when a gating target is missed (start-up, idle and peak memory, matrix passes)")
    ap.add_argument("--report-only", action="store_true", help="print and record every verdict but never exit 1 (for a machine whose numbers mean nothing, such as an emulated CPU)")
    args = ap.parse_args()
    runs = [one_run(args, free_port()) for _ in range(args.runs)]
    med = lambda k: statistics.median(r[k] for r in runs)
    summary = {"label": args.label, "cmd": args.cmd, "runs": runs, "targets": TARGETS,
               "start_s": med("start_s"), "idle_mib": med("idle_mib"),
               "peak_mib": max(r["peak_mib"] for r in runs), "median_ms": med("median_ms"),
               "idle_rss_mib": med("idle_rss_mib"), "peak_rss_mib": max(r["peak_rss_mib"] for r in runs),
               "memory_source": runs[0]["memory_source"],
               "pass": min(r["pass"] for r in runs), "total": runs[0]["total"]}
    # Gating: start-up, idle and peak memory, matrix passes. The median call (3 ms) is report-only since 2026-11-03
    # (owner): a miss is a WARN in the output and the JSON, never a failure.
    verdict = {
        "start_s": summary["start_s"] <= TARGETS["start_s"],
        "idle_mib": summary["idle_mib"] <= TARGETS["idle_mib"],
        "peak_mib": summary["peak_mib"] <= TARGETS["peak_mib"],
        "pass": summary["pass"] >= TARGETS["pass_min"],
    }
    median_ok = summary["median_ms"] is not None and summary["median_ms"] <= TARGETS["median_ms"]
    summary["verdict"] = {k: ("pass" if v else "MISS") for k, v in verdict.items()}
    summary["verdict"]["median_ms"] = "pass" if median_ok else "WARN (report-only)"
    summary["reportOnly"] = bool(args.report_only)
    json.dump(summary, open(args.out, "w"), indent=1)
    print(f"{args.label}: start {summary['start_s']:.3f} s (<= {TARGETS['start_s']}) {summary['verdict']['start_s']}")
    print(f"{args.label}: idle  {summary['idle_mib']:.1f} MiB private (<= {TARGETS['idle_mib']}) {summary['verdict']['idle_mib']}   [total RSS {summary['idle_rss_mib']:.1f} MiB, information only]")
    print(f"{args.label}: peak  {summary['peak_mib']:.1f} MiB private (<= {TARGETS['peak_mib']}) {summary['verdict']['peak_mib']}   [total RSS {summary['peak_rss_mib']:.1f} MiB, information only]")
    print(f"{args.label}: private memory = {summary['memory_source']}")
    if runs[-1].get("idle_detail_kib"):
        mib = lambda d: {k: round(v / 1024, 1) for k, v in d.items()} if d else None
        print(f"{args.label}: RSS split at idle (MiB): {mib(runs[-1]['idle_detail_kib'])}; after the matrix: {mib(runs[-1].get('after_matrix_detail_kib'))}")
    print(f"{args.label}: call  {summary['median_ms']} ms median (<= {TARGETS['median_ms']}) {summary['verdict']['median_ms']}")
    print(f"{args.label}: matrix {summary['pass']}/{summary['total']} (>= {TARGETS['pass_min']}) {summary['verdict']['pass']}")
    if not median_ok:
        print(f"WARNING: {args.label}: median call {summary['median_ms']} ms is above {TARGETS['median_ms']} ms (report-only, not a failure)")
    if args.report_only:
        print(f"{args.label}: REPORT-ONLY run: no verdict fails this run")
    elif args.check and not all(verdict.values()):
        sys.exit(1)


if __name__ == "__main__":
    main()
