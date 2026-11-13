#!/usr/bin/env python3
"""Integration test for the in-sandbox agent under gVisor runsc with AWS's official runtime clients.

Run inside the Linux VM as root through run.sh. Needs setup.sh to have run. Every scenario starts a
fresh sandbox (runsc with an OCI bundle: read-only root, code at /var/task, layer at /opt/python,
the agent at /agent, tmpfs /tmp, no network), speaks the framing from PROTOCOL.md on the sandbox's
stdin/stdout, and checks results. Prints one JSON line per scenario and a summary.
"""
import base64, json, os, queue, shutil, statistics, struct, subprocess, sys, threading, time

ROOT = os.environ.get("A1_ROOT", "/srv/a1")
HERE = os.path.dirname(os.path.abspath(__file__))
# the runsc binary under test: set RUNSC to its path (default ~/s4/gv/runsc)
RUNSC = os.environ.get("RUNSC", os.path.expanduser("~") + "/s4/gv/runsc")
STATE = "/run/a1runsc"
BUNDLES = ROOT + "/bundles"
UID = 993
ONLY = set(sys.argv[1:])
results = []


def load_env(name):
    env = {}
    for line in open(f"{ROOT}/rootfs/{name}.env").read().splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            env[k] = v
    return env


class Sandbox:
    def __init__(self, image, fn_dir, handler, *, layer=None, cmd=None, extra_env=None, mem=512, agent_args=(), agent=None, qemu=False, split_uid=False):
        self.name = f"a1-{os.getpid()}-{int(time.time()*1000) % 10**9}"
        env = load_env(image)
        env.update({"_HANDLER": handler, "AWS_LAMBDA_FUNCTION_NAME": "a1test", "AWS_LAMBDA_FUNCTION_VERSION": "$LATEST",
                    "AWS_LAMBDA_FUNCTION_MEMORY_SIZE": str(mem), "AWS_REGION": "us-east-1", "AWS_DEFAULT_REGION": "us-east-1",
                    "AWS_LAMBDA_LOG_GROUP_NAME": "/aws/lambda/a1test", "AWS_LAMBDA_LOG_STREAM_NAME": "s",
                    "AWS_ACCESS_KEY_ID": "x", "AWS_SECRET_ACCESS_KEY": "x", "AGENT_SECRET_TEST": "must-not-reach-the-runtime"})
        if layer:
            env["PYTHONPATH"] = "/opt/python"
        if extra_env:
            env.update(extra_env)
        mounts = [{"destination": "/proc", "type": "proc", "source": "proc"},
                  {"destination": "/dev", "type": "tmpfs", "source": "tmpfs"},
                  {"destination": "/tmp", "type": "tmpfs", "source": "tmpfs", "options": ["size=128m", "mode=1777"]},
                  {"destination": "/var/task", "type": "bind", "source": fn_dir, "options": ["rbind", "ro"]},
                  {"destination": "/agent", "type": "bind", "source": agent or f"{ROOT}/agent", "options": ["rbind", "ro"]}]
        if layer:
            mounts.append({"destination": "/opt/python", "type": "bind", "source": layer, "options": ["rbind", "ro"]})
        if split_uid:
            agent_args = list(agent_args) + ["-uid", str(UID), "-gid", str(UID)]
        args = ["/agent/agent"] + list(agent_args) + (["--"] + cmd if cmd else [])
        spec = {"ociVersion": "1.0.0", "process": {"terminal": False, "user": {"uid": 0 if split_uid else UID, "gid": 0 if split_uid else UID}, "args": args,
                "env": [f"{k}={v}" for k, v in env.items()], "cwd": "/var/task", "noNewPrivileges": True,
                "capabilities": ({k: ["CAP_SETUID", "CAP_SETGID"] for k in ("bounding", "effective", "permitted")} if split_uid else {}),
                "rlimits": [{"type": "RLIMIT_NOFILE", "hard": 4096, "soft": 4096}]},
                "root": {"path": f"{ROOT}/rootfs/{image}", "readonly": True}, "hostname": "lambda", "mounts": mounts,
                "linux": {"namespaces": [{"type": t} for t in ("pid", "network", "ipc", "uts", "mount")]}}
        self.bundle = f"{BUNDLES}/{self.name}"
        os.makedirs(self.bundle, exist_ok=True)
        json.dump(spec, open(self.bundle + "/config.json", "w"))
        self.errf = open(f"{self.bundle}/stderr.log", "wb")
        self.t_launch = time.time()
        self.p = subprocess.Popen([RUNSC, "--root", STATE, "--platform=systrap", "--network=none", "--ignore-cgroups", "--rootless=false",
                                   "run", "-bundle", self.bundle, self.name], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.errf)
        self.frames = queue.Queue()
        threading.Thread(target=self._read, daemon=True).start()
        self.seq = 0

    def _read(self):
        try:
            while True:
                h = self._exact(4)
                if not h:
                    break
                n = struct.unpack(">I", h)[0]
                body = self._exact(n)
                self.frames.put((time.time(), json.loads(body)))
        finally:
            self.frames.put((time.time(), None))

    def _exact(self, n):
        b = b""
        while len(b) < n:
            c = self.p.stdout.read(n - len(b))
            if not c:
                return None
            b += c
        return b

    def send(self, obj):
        b = json.dumps(obj).encode()
        self.p.stdin.write(struct.pack(">I", len(b)) + b)
        self.p.stdin.flush()

    def expect(self, typ, timeout=30):
        t, f = self.frames.get(timeout=timeout)
        assert f is not None, f"agent stdout closed; stderr: {open(self.bundle + '/stderr.log', errors='replace').read()[-800:]}"
        assert f["type"] == typ, f"wanted {typ}, got {json.dumps(f)[:600]}"
        return t, f

    def up(self):
        _, hello = self.expect("hello")
        t, ready = self.expect("ready")
        self.cold_ready_ms = (t - self.t_launch) * 1000
        return hello, ready

    def invoke(self, event, timeout_ms=10000, raw=None, **kw):
        self.seq += 1
        rid = f"it-{self.seq}"
        payload = raw if raw is not None else json.dumps(event).encode()
        msg = {"type": "invoke", "requestId": rid, "payload": base64.b64encode(payload).decode(), "timeoutMs": timeout_ms,
               "functionArn": "arn:aws:lambda:us-east-1:000000000000:function:a1test"}
        msg.update(kw)
        t0 = time.time()
        self.send(msg)
        t, r = self.expect("result", timeout=timeout_ms / 1000 + 30)
        assert r["requestId"] == rid, r
        r["_rtt_ms"] = (t - t0) * 1000
        return r

    def close(self):
        try:
            self.p.stdin.close()
        except Exception:
            pass
        try:
            self.p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            subprocess.run([RUNSC, "--root", STATE, "kill", self.name, "KILL"], capture_output=True)
            try:
                self.p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.p.kill()
        subprocess.run([RUNSC, "--root", STATE, "delete", "--force", self.name], capture_output=True)
        self.errf.close()
        shutil.rmtree(self.bundle, ignore_errors=True)


def payload(r):
    return base64.b64decode(r["payload"]).decode()


def scenario(fn):
    name = fn.__name__
    if ONLY and name not in ONLY:
        return fn
    t0 = time.time()
    try:
        info = fn() or {}
        results.append(True)
        print(json.dumps({"scenario": name, "result": "PASS", "secs": round(time.time() - t0, 1), **info}), flush=True)
    except Exception as e:
        results.append(False)
        print(json.dumps({"scenario": name, "result": "FAIL", "error": f"{type(e).__name__}: {e}"[:1500]}), flush=True)
    return fn


PY, NODE = "python312", "nodejs22"
FNPY, FNNODE = f"{HERE}/fn/py", f"{HERE}/fn/node"
LAYER = f"{ROOT}/layer-python"


def stats(v):
    v = sorted(v)
    return {"median_ms": round(statistics.median(v), 2), "p95_ms": round(v[int(len(v) * 0.95) - 1], 2), "max_ms": round(v[-1], 2)}


@scenario
def python_hello():
    sb = Sandbox(PY, FNPY, "app.hello")
    try:
        hello, ready = sb.up()
        assert hello["proto"] == "agent/1" and hello["pid"] == 1, hello   # PID 1 inside the sandbox
        t0 = time.time()
        r = sb.invoke({"name": "world"})
        first_ms = (time.time() - t0) * 1000
        assert r["status"] == "ok", r
        out = json.loads(payload(r))
        assert out["hello"] == "world" and out["request_id"] == r["requestId"] and out["remaining_ms_ok"], out
        assert out["arn"].endswith(":function:a1test"), out
        for want in ("START RequestId: it-1 Version: $LATEST", "hello from python world", "END RequestId: it-1", "REPORT RequestId: it-1", "Init Duration"):
            assert want in r["logTail"], (want, r["logTail"])
        assert r["maxMemoryUsed"] > 5 << 20, r["maxMemoryUsed"]
        return {"cold_to_ready_ms": round(sb.cold_ready_ms), "init_ms": ready["initDurationMs"], "first_invoke_rtt_ms": round(first_ms, 1),
                "agent_duration_ms": r["durationMs"], "max_memory_mb": round(r["maxMemoryUsed"] / 2**20, 1)}
    finally:
        sb.close()


@scenario
def python_numpy_layer():
    sb = Sandbox(PY, FNPY, "app.numpy_op", layer=LAYER)
    try:
        _, ready = sb.up()
        r = sb.invoke({})
        assert r["status"] == "ok", r
        out = json.loads(payload(r))
        assert out["sum"] == 499999500000.0 and out["numpy"].startswith("2."), out
        r2 = sb.invoke({})
        return {"numpy": out["numpy"], "cold_to_ready_ms": round(sb.cold_ready_ms), "first_invoke_ms": r["durationMs"], "warm_invoke_ms": r2["durationMs"],
                "max_memory_mb": round(r2["maxMemoryUsed"] / 2**20, 1)}
    finally:
        sb.close()


@scenario
def node_hello():
    sb = Sandbox(NODE, FNNODE, "app.hello")
    try:
        _, ready = sb.up()
        r = sb.invoke({"name": "node"})
        assert r["status"] == "ok", r
        out = json.loads(payload(r))
        assert out["hello"] == "node" and out["request_id"] == r["requestId"], out
        assert "hello from node node" in r["logTail"] and "REPORT RequestId: it-1" in r["logTail"], r["logTail"]
        return {"cold_to_ready_ms": round(sb.cold_ready_ms), "init_ms": ready["initDurationMs"], "agent_duration_ms": r["durationMs"]}
    finally:
        sb.close()


@scenario
def python_function_error():
    sb = Sandbox(PY, FNPY, "app.error")
    try:
        sb.up()
        r = sb.invoke({})
        assert r["status"] == "function_error" and r["errorType"] == "ValueError" and r["errorMessage"] == "kaboom from python", r
        doc = json.loads(payload(r))
        assert doc["errorMessage"] == "kaboom from python" and doc["stackTrace"], doc
        assert "Traceback" in r["logTail"] or "kaboom from python" in r["logTail"], r["logTail"]
        assert "Status: error\tError Type: ValueError" in r["logTail"]
        r2 = sb.invoke({})   # still warm after an error
        assert r2["status"] == "function_error"
    finally:
        sb.close()


@scenario
def node_function_error():
    sb = Sandbox(NODE, FNNODE, "app.error")
    try:
        sb.up()
        r = sb.invoke({})
        assert r["status"] == "function_error" and r["errorType"] == "TypeError" and r["errorMessage"] == "kaboom from node", r
        doc = json.loads(payload(r))
        assert doc.get("stackTrace") or doc.get("trace"), doc
    finally:
        sb.close()


@scenario
def python_timeout_kills_group_and_restarts():
    sb = Sandbox(PY, FNPY, "app.sleepy")
    try:
        sb.up()
        t0 = time.time()
        r = sb.invoke({"seconds": 30}, timeout_ms=1500)
        el = time.time() - t0
        assert r["status"] == "timeout" and r["errorType"] == "Sandbox.Timedout", r
        assert "Task timed out after 1.50 seconds" in r["errorMessage"] and "Task timed out after 1.50 seconds" in r["logTail"], r
        assert 1.4 < el < 3.5, el
        assert "Status: timeout" in r["logTail"]
        # a fresh runtime serves the next call; the old process group (and its sleep child) is gone
        return {"timeout_wall_s": round(el, 2), "reported_duration_ms": r["durationMs"]}
    finally:
        sb.close()


@scenario
def python_timeout_leaves_no_children():
    sb = Sandbox(PY, FNPY, "app.sleepy")
    try:
        sb.up()
        r = sb.invoke({"seconds": 30}, timeout_ms=1500)
        assert r["status"] == "timeout", r
        r = sb.invoke({"seconds": 0}, timeout_ms=5000)     # restarted runtime; spawns one new sleep and lists processes
        assert r["status"] == "ok" and r["initDurationMs"] > 0, r
        cmds = json.loads(payload(r))
        sleeps = [c for c in cmds if c.rstrip().endswith("sleep 300")]
        assert len(sleeps) == 1, cmds    # the killed runtime's sleep child is gone
        return {"processes_in_sandbox": cmds}
    finally:
        sb.close()


@scenario
def node_timeout_and_restart():
    sb = Sandbox(NODE, FNNODE, "app.sleepy")
    try:
        sb.up()
        r = sb.invoke({}, timeout_ms=1200)
        assert r["status"] == "timeout" and "Task timed out after 1.20 seconds" in r["errorMessage"], r
        r = sb.invoke({}, timeout_ms=600)     # fresh runtime, times out again
        assert r["status"] == "timeout" and r["initDurationMs"] > 0, r
    finally:
        sb.close()


@scenario
def python_crash_then_recovers():
    sb = Sandbox(PY, FNPY, "app.crash")
    try:
        sb.up()
        r = sb.invoke({})
        assert r["status"] == "crash" and r["errorType"] == "Runtime.ExitError" and "exit status 7" in r["errorMessage"], r
        assert "exiting hard" in r["logTail"]
        r = sb.invoke({})
        assert r["status"] == "crash" and r["initDurationMs"] > 0, r   # runtime restarted, crashed again
    finally:
        sb.close()


@scenario
def python_init_error():
    sb = Sandbox(PY, FNPY, "no_such_module.handler")
    try:
        sb.expect("hello")
        _, m = sb.expect("init_error")
        assert m["reason"] in ("runtime_reported", "exited") and "no_such_module" in (m["errorMessage"] + m["logTail"]), m
        r = sb.invoke({})
        assert r["status"] == "init_error" and "no_such_module" in (r["errorMessage"] + r["logTail"]), r
        return {"reason": m["reason"], "errorType": m["errorType"], "init_ms": m["initDurationMs"], "invoke_status": r["status"]}
    finally:
        sb.close()


@scenario
def python_handler_missing_attribute_init_error():
    sb = Sandbox(PY, FNPY, "app.nope")
    try:
        sb.expect("hello")
        _, m = sb.expect("init_error")
        assert "nope" in m["errorMessage"], m
        return {"reason": m["reason"], "errorType": m["errorType"]}
    finally:
        sb.close()


@scenario
def node_init_error():
    sb = Sandbox(NODE, FNNODE, "no_such_module.handler")
    try:
        sb.expect("hello")
        _, m = sb.expect("init_error")
        assert "no_such_module" in (m["errorMessage"] + m["logTail"]), m
        r = sb.invoke({})
        assert r["status"] == "init_error", r
        return {"reason": m["reason"], "errorType": m["errorType"]}
    finally:
        sb.close()


@scenario
def warm_reuse_python_100():
    sb = Sandbox(PY, FNPY, "app.hello")
    try:
        sb.up()
        pids, rtt, dur = set(), [], []
        for i in range(100):
            r = sb.invoke({"name": i})
            assert r["status"] == "ok", r
            pids.add(json.loads(payload(r))["pid"])
            rtt.append(r["_rtt_ms"]); dur.append(r["durationMs"])
        assert len(pids) == 1, pids
        return {"invocations": 100, "same_runtime_pid": True, "round_trip": stats(rtt), "handler": stats(dur)}
    finally:
        sb.close()


@scenario
def warm_reuse_node_100():
    sb = Sandbox(NODE, FNNODE, "app.hello")
    try:
        sb.up()
        pids, rtt, dur = set(), [], []
        for i in range(100):
            r = sb.invoke({"name": i})
            assert r["status"] == "ok", r
            pids.add(json.loads(payload(r))["pid"])
            rtt.append(r["_rtt_ms"]); dur.append(r["durationMs"])
        assert len(pids) == 1, pids
        return {"invocations": 100, "same_runtime_pid": True, "round_trip": stats(rtt), "handler": stats(dur)}
    finally:
        sb.close()


@scenario
def warm_reuse_python_numpy_100():
    sb = Sandbox(PY, FNPY, "app.numpy_op", layer=LAYER)
    try:
        sb.up()
        rtt = []
        for i in range(100):
            r = sb.invoke({})
            assert r["status"] == "ok", r
            rtt.append(r["_rtt_ms"])
        return {"invocations": 100, "round_trip": stats(rtt)}
    finally:
        sb.close()


@scenario
def payload_limits_through_real_runtime():
    sb = Sandbox(PY, FNPY, "app.echo")
    try:
        sb.up()
        # 5.5 MB in, 5.5 MB out through the official client
        data = {"blob": "y" * (5_500_000)}
        r = sb.invoke(data, timeout_ms=30000)
        assert r["status"] == "ok" and json.loads(payload(r)) == data, (r["status"], r.get("errorMessage"))
        r = sb.invoke(None, raw=b'"' + b"z" * 6_300_000 + b'"')
        assert r["status"] == "rejected" and r["errorType"] == "RequestEntityTooLargeException", r
        r = sb.invoke({"still": "ok"})
        assert r["status"] == "ok", r
    finally:
        sb.close()
    sb = Sandbox(PY, FNPY, "app.big")
    try:
        sb.up()
        r = sb.invoke({"n": 6_400_000}, timeout_ms=30000)
        assert r["status"] == "function_error" and r["errorType"] == "Function.ResponseSizeTooLarge", (r["status"], r.get("errorType"), r.get("errorMessage"))
        r = sb.invoke({"n": 100})
        assert r["status"] == "ok", r
    finally:
        sb.close()


@scenario
def node_response_too_large():
    sb = Sandbox(NODE, FNNODE, "app.big")
    try:
        sb.up()
        r = sb.invoke({"n": 6_400_000}, timeout_ms=30000)
        assert r["status"] == "function_error" and r["errorType"] == "Function.ResponseSizeTooLarge", (r["status"], r.get("errorType"), r.get("errorMessage"), r["logTail"][-600:])
        r = sb.invoke({"n": 100})
        assert r["status"] == "ok", r
        r = sb.invoke({"n": 5_000_000}, timeout_ms=30000)
        assert r["status"] == "ok" and len(payload(r)) == 5_000_002, r["status"]
    finally:
        sb.close()


@scenario
def orphans_are_reaped_by_pid1():
    d = f"{ROOT}/fn-orphan"
    os.makedirs(d, exist_ok=True)
    open(d + "/app.py", "w").write(
        "import os, time\n"
        "def run(event, context):\n"
        "    for _ in range(event.get('n', 5)):\n"
        "        if os.fork() == 0:\n"
        "            if os.fork() == 0:\n"
        "                time.sleep(0.05); os._exit(0)\n"
        "            os._exit(0)\n"
        "        os.wait()\n"
        "    time.sleep(event.get('wait', 0))\n"
        "    z = []\n"
        "    for p in os.listdir('/proc'):\n"
        "        if p.isdigit():\n"
        "            try:\n"
        "                st = open('/proc/%s/stat' % p).read()\n"
        "                if st[st.rindex(')') + 2] == 'Z': z.append(p)\n"
        "            except OSError: pass\n"
        "    return {'zombies': z}\n")
    sb = Sandbox(PY, d, "app.run")
    try:
        sb.up()
        r = sb.invoke({"n": 20, "wait": 0.5})
        z = json.loads(payload(r))["zombies"]
        assert r["status"] == "ok" and z == [], r
        return {"orphans_created": 20, "zombies_after": len(z)}
    finally:
        sb.close()
        shutil.rmtree(d, ignore_errors=True)


@scenario
def sandbox_isolation_and_env():
    sb = Sandbox(PY, FNPY, "app.net")
    try:
        sb.up()
        r = sb.invoke({})
        o = json.loads(payload(r))
        assert o["internet"].startswith("blocked") and o["host"].startswith("blocked"), o
        assert o["env_leak"] == [] and o["runtime_api"] == "127.0.0.1:9001", o
        return o
    finally:
        sb.close()


@scenario
def hostile_handler_cannot_reach_the_agent():
    sb = Sandbox(PY, FNPY, "app.hostile")
    try:
        hello, _ = sb.up()
        assert hello["pid"] == 1, hello
        r = sb.invoke({})
        assert r["status"] == "ok", r
        o = json.loads(payload(r))
        for k in ("fd0_read", "fd1_write", "fd1_read", "fd2", "environ", "mem"):
            assert o[k] == "EACCES", (k, o)
        # (listing /proc/1/fd is still allowed under gVisor; opening anything in it is not)
        assert o["self_environ_readable"] is True, o  # the runtime can still read its own
        # and no stray frame reached the worker's pipe
        time.sleep(0.2)
        assert sb.frames.empty(), sb.frames.get()
        return o
    finally:
        sb.close()


def signal_scenario(sigs, **kw):
    sb = Sandbox(PY, FNPY, "app.signal_init", **kw)
    sb.up()
    sb.send({"type": "invoke", "requestId": "sig-1", "payload": base64.b64encode(json.dumps({"sigs": sigs}).encode()).decode(),
             "timeoutMs": 4000, "functionArn": "a"})
    return sb


@scenario
def ignored_stop_signals_from_runtime():
    # same uid: SIGTSTP, SIGTTIN and SIGTTOU reach PID 1 but the agent ignores them
    sb = signal_scenario(["SIGTSTP", "SIGTTIN", "SIGTTOU"])
    try:
        _, r = sb.expect("result", timeout=10)
        assert r["status"] == "ok" and json.loads(payload(r)) == {"SIGTSTP": "SENT", "SIGTTIN": "SENT", "SIGTTOU": "SENT"}, r
        assert sb.invoke({"sigs": []})["status"] == "ok"
    finally:
        sb.close()


@scenario
def known_same_uid_sigstop_stops_pid1():
    # Characterisation, not a requirement: under runsc a same-uid process can SIGSTOP PID 1 and
    # SIGSTOP cannot be ignored, so with the runtime on the agent's uid the invoke only ends at
    # the worker's backstop. The split-uid launch (next scenario) closes this. If gVisor ever
    # refuses the signal, this scenario fails and PROTOCOL.md should be updated.
    sb = signal_scenario(["SIGSTOP"])
    try:
        try:
            sb.frames.get(timeout=6)
            raise AssertionError("agent answered: SIGSTOP no longer stops PID 1 under this runsc")
        except queue.Empty:
            return {"agent_stopped": True}
    finally:
        sb.close()


@scenario
def split_uid_blocks_signals_and_proc_access():
    # The agent runs as root with only CAP_SETUID and CAP_SETGID and starts the runtime as uid 993
    # (-uid/-gid): the runtime cannot signal PID 1 at all, and /proc/1 stays closed to it.
    sb = signal_scenario(["SIGSTOP", "SIGKILL", "SIGTERM", "SIGTSTP"], split_uid=True)
    try:
        _, r = sb.expect("result", timeout=10)
        assert r["status"] == "ok" and set(json.loads(payload(r)).values()) == {"EPERM"}, r
        assert sb.invoke({"sigs": []})["status"] == "ok"
    finally:
        sb.close()
    sb = Sandbox(PY, FNPY, "app.hostile", split_uid=True)
    try:
        sb.up()
        o = json.loads(payload(sb.invoke({})))
        for k in ("fd0_read", "fd1_write", "fd1_read", "fd2", "environ", "mem"):
            assert o[k] == "EACCES", (k, o)
        return o
    finally:
        sb.close()


@scenario
def stdin_close_shuts_down_cleanly():
    sb = Sandbox(PY, FNPY, "app.hello")
    sb.up()
    sb.invoke({"name": "x"})
    t0 = time.time()
    sb.p.stdin.close()
    rc = sb.p.wait(timeout=15)
    sb.close()
    assert rc == 0, rc
    return {"exit_code": rc, "shutdown_ms": round((time.time() - t0) * 1000)}


@scenario
def x86_python_under_qemu():
    if not os.path.isdir(f"{ROOT}/rootfs/python312-x86/var/runtime") or not os.path.exists("/usr/bin/qemu-x86_64-static"):
        return {"skipped": "x86 rootfs or qemu not present"}
    qdir = f"{ROOT}/qemu"
    os.makedirs(qdir, exist_ok=True)
    shutil.copy("/usr/bin/qemu-x86_64-static", qdir + "/qemu-x86_64-static")
    agent_dir = f"{ROOT}/agent-x86"
    os.makedirs(agent_dir, exist_ok=True)
    shutil.copy(f"{ROOT}/agent/agent", agent_dir + "/agent")          # the agent and qemu are native (arm64) binaries; only the image's files are x86_64
    shutil.copy(qdir + "/qemu-x86_64-static", agent_dir + "/qemu-x86_64-static")
    sb = Sandbox("python312-x86", FNPY, "app.hello", agent=agent_dir, cmd=["/agent/qemu-x86_64-static", "/var/lang/bin/python3.12", "/var/runtime/bootstrap.py"],
                 extra_env={"AWS_EXECUTION_ENV": "AWS_Lambda_python3.12"})
    try:
        _, ready = sb.up()
        r = sb.invoke({"name": "x86"}, timeout_ms=20000)
        assert r["status"] == "ok" and json.loads(payload(r))["hello"] == "x86", r
        return {"cold_to_ready_ms": round(sb.cold_ready_ms), "init_ms": ready["initDurationMs"]}
    finally:
        sb.close()


if __name__ == "__main__":
    os.makedirs(BUNDLES, exist_ok=True)
    ok = all(results)
    print(json.dumps({"summary": {"passed": sum(results), "failed": results.count(False)}}))
    sys.exit(0 if ok else 1)
