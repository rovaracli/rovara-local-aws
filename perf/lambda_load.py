#!/usr/bin/env python3
"""Memory of the emulator with Lambda in heavy use: N concurrent function environments, each invoked
repeatedly, run by the test-only function runner (its memory is not counted; it is another process).

    python3 -I perf/lambda_load.py --cmd target/rovara-local-aws-0.1.0-runner --python <python with boto3> \
        [--concurrency 8] [--calls 25]
"""
import argparse, io, json, os, shlex, subprocess, sys, tempfile, threading, time, zipfile
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import measure  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cmd", required=True)
    ap.add_argument("--python", required=True)
    ap.add_argument("--concurrency", type=int, default=8)
    ap.add_argument("--calls", type=int, default=25)
    args = ap.parse_args()
    port = measure.free_port()
    runner, runner_url, token = measure.start_runner(args)
    env = dict(os.environ, DOCKER_HOST="unix:///nonexistent", AWS_EC2_METADATA_DISABLED="true",
               QUARKUS_HTTP_PORT=str(port), ROVARA_AWS_PORT=str(port),
               ROVARA_AWS_BASE_URL=f"http://127.0.0.1:{port}",
               ROVARA_AWS_SERVICES_LAMBDA_FUNCTION_RUNNER_URL=runner_url,
               ROVARA_AWS_SERVICES_LAMBDA_FUNCTION_RUNNER_TOKEN=token)
    log = tempfile.NamedTemporaryFile(prefix="rovara-lambda-load-", suffix=".log", delete=False)
    proc = subprocess.Popen(shlex.split(args.cmd), env=env, stdout=log, stderr=subprocess.STDOUT)
    try:
        import urllib.request
        for _ in range(500):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/_rovara/health", timeout=0.2).read()
                break
            except Exception:
                time.sleep(0.02)
        time.sleep(2)
        idle = measure.rss_kib(proc.pid) / 1024
        os.environ.update(AWS_ACCESS_KEY_ID="test", AWS_SECRET_ACCESS_KEY="test", AWS_DEFAULT_REGION="us-east-1")
        # the gate's python is the one with boto3; import it from there
        code = r'''
import boto3, io, json, sys, threading, zipfile
from botocore.config import Config
port, conc, calls = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
lam = boto3.client("lambda", endpoint_url=f"http://127.0.0.1:{port}", region_name="us-east-1",
                   aws_access_key_id="test", aws_secret_access_key="test",
                   config=Config(retries={"max_attempts": 1}, read_timeout=60, max_pool_connections=64))
buf = io.BytesIO()
with zipfile.ZipFile(buf, "w") as z:
    z.writestr("handler.py", "import time\ndef handler(e, c):\n    time.sleep(e.get('sleep', 0))\n    return {'ok': True}\n")
lam.create_function(FunctionName="load", Runtime="python3.12", Role="arn:aws:iam::000000000000:role/r",
                    Handler="handler.handler", Code={"ZipFile": buf.getvalue()}, Timeout=30)
errors, done = [], [0]
def worker():
    for i in range(calls):
        try:
            r = lam.invoke(FunctionName="load", Payload=json.dumps({"sleep": 0.05}).encode())
            p = json.loads(r["Payload"].read())
            assert p == {"ok": True}, p
            done[0] += 1
        except Exception as e:
            errors.append(repr(e)[:300])
ts = [threading.Thread(target=worker) for _ in range(conc)]
[t.start() for t in ts]; [t.join() for t in ts]
print(json.dumps({"invocations": done[0], "errors": errors[:3]}))
'''
        peak = [idle]
        stop = threading.Event()

        def sample():
            while not stop.is_set():
                peak[0] = max(peak[0], measure.rss_kib(proc.pid) / 1024)
                time.sleep(0.05)

        th = threading.Thread(target=sample, daemon=True)
        th.start()
        t0 = time.perf_counter()
        out = subprocess.run([args.python, "-I", "-c", code, str(port), str(args.concurrency), str(args.calls)],
                             capture_output=True, text=True, env=os.environ)
        took = time.perf_counter() - t0
        stop.set(); th.join()
        time.sleep(1)
        print(json.dumps({"concurrency": args.concurrency, "calls_each": args.calls, "idle_mib": round(idle, 1),
                          "peak_mib": round(peak[0], 1), "after_mib": round(measure.rss_kib(proc.pid) / 1024, 1),
                          "seconds": round(took, 1), "result": out.stdout.strip() or out.stderr.strip()[-300:]}))
    finally:
        proc.terminate(); runner.terminate()
        try:
            proc.wait(10); runner.wait(10)
        except subprocess.TimeoutExpired:
            proc.kill(); runner.kill()


if __name__ == "__main__":
    main()
