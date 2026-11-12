#!/usr/bin/env python3
"""TEST TOOL, not shipped. A stand-alone reference implementation of the function-runner contract
(src/main/resources/META-INF/rovara/function-runner-v1.openapi.yaml) that runs Python (and, when given
a node binary, Node) handlers as plain operating-system processes, so the speed gate can measure the
emulator with Lambda in use while the runner and the function code stay in their own processes.

    python3 -I perf/local_process_runner.py --python /path/to/python3 --token <random> [--node /path/to/node]

Prints "LISTENING <port>" on stdout once it is ready. Standard library only. It follows the
contract's rules: bearer token, the code checked against its digest, unpack caps, nothing written
outside the target, an environment made of exactly the request's variables plus a few platform values.
The Java twin used by the unit tests is src/test/.../fixture/LocalProcessFunctionRunner.java.
"""
import argparse, hashlib, hmac, http.server, json, os, shutil, signal, subprocess, sys, tempfile
import threading, urllib.request, zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
BOOTSTRAP_DIR = os.path.join(HERE, "..", "src", "test", "resources", "function-runner")
PY = {"python3.9", "python3.10", "python3.11", "python3.12", "python3.13"}
NODE = {"nodejs18.x", "nodejs20.x", "nodejs22.x", "nodejs24.x"}


class Env:
    def __init__(self, proc, directory, fingerprint):
        self.proc, self.dir, self.fingerprint = proc, directory, fingerprint


class Invalid(Exception):
    pass


def make_handler(args, root, envs, lock):
    deleted, starting = set(), {}  # ids a DELETE answered for; starts in progress (id -> [cancelled, done event])
    class H(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def reply(self, status, body=None):
            data = json.dumps(body).encode() if body is not None else b""
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def error(self, status, code, message):
            self.reply(status, {"error": {"code": code, "message": message[:300]}})

        def read_body(self):
            n = int(self.headers.get("Content-Length") or 0)
            return self.rfile.read(min(n, 1 << 20))

        def authed(self):
            got = (self.headers.get("Authorization") or "").encode()
            if not hmac.compare_digest(("Bearer " + args.token).encode(), got):
                self.read_body()
                self.error(401, "unauthorized", "unauthorized")
                return False
            if self.headers.get("X-Rovara-Contract-Version") != "1":
                self.read_body()
                self.error(400, "unsupported_contract_version", "This runner speaks contract version 1")
                return False
            return True

        def do_GET(self):
            if not self.authed():
                return
            if self.path == "/v1/info":
                runtimes = sorted(PY | (NODE if args.node else set()))
                return self.reply(200, {"contractVersion": 1, "runtimes": runtimes,
                                        "architectures": ["x86_64", "arm64"], "maxMemoryMb": 3008})
            if self.path.startswith("/v1/environments/"):
                env = envs.get(self.path.rsplit("/", 1)[1])
                if env is None:
                    return self.error(404, "environment_not_found", "no such environment")
                return self.reply(200, self.state(self.path.rsplit("/", 1)[1], env))
            self.error(404, "invalid_request", "no such path")

        def state(self, eid, env):
            code = env.proc.poll()
            if code is None:
                return {"environmentId": eid, "state": "running"}
            return {"environmentId": eid, "state": "exited", "exitCode": code if code >= 0 else 128 - code}

        def do_DELETE(self):
            if not self.authed():
                return
            eid = self.path.split("?")[0].rsplit("/", 1)[1]
            # a barrier (contract rule 6): this id never starts a process once this call has answered
            with lock:
                deleted.add(eid)
                progress = starting.get(eid)
                if progress:
                    progress[0] = True
            if progress:
                progress[1].wait(30)
            with lock:
                env = envs.pop(eid, None)
            if env is None:
                return self.error(404, "environment_not_found", "no such environment")
            kill(env)
            shutil.rmtree(env.dir, ignore_errors=True)
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_POST(self):
            if not self.authed():
                return
            if self.path != "/v1/environments":
                return self.error(404, "invalid_request", "no such path")
            try:
                body = json.loads(self.read_body())
            except ValueError:
                return self.error(400, "invalid_request", "body is not JSON")
            for field in ("contractVersion", "environmentId", "function", "runtime", "handler", "memoryMb",
                          "timeoutSeconds", "ephemeralStorageMb", "runtimeApi", "code", "limits", "environment"):
                if field not in body:
                    return self.error(400, "invalid_request", "missing " + field)
            eid = body["environmentId"]
            fingerprint = json.dumps(body, sort_keys=True)
            with lock:
                if eid in deleted:
                    return self.error(409, "environment_stopped", "this environment was stopped")
                existing = envs.get(eid)
            if existing is not None:
                if existing.fingerprint == fingerprint:
                    return self.reply(201, self.state(eid, existing))
                return self.error(409, "environment_exists", "environment id already used with another request")
            runtime = body["runtime"]
            if runtime in PY:
                interpreter, boot = args.python, "bootstrap.py"
            elif runtime in NODE and args.node:
                interpreter, boot = args.node, "bootstrap.js"
            else:
                return self.error(422, "unsupported_runtime", runtime + " is not available")
            progress = [False, threading.Event()]
            with lock:
                if eid in starting:
                    return self.error(409, "environment_exists", "a start for this environment is already running")
                starting[eid] = progress
            try:
                self.start_environment(body, eid, fingerprint, interpreter, boot, progress)
            finally:
                with lock:
                    starting.pop(eid, None)
                progress[1].set()

        def start_environment(self, body, eid, fingerprint, interpreter, boot, progress):
            directory = tempfile.mkdtemp(prefix="env-", dir=root)
            code_dir = os.path.join(directory, "code")
            try:
                fetch_and_unpack(body, directory, code_dir)
            except Invalid as e:
                shutil.rmtree(directory, ignore_errors=True)
                return self.error(422, "invalid_code", str(e))
            script = os.path.join(directory, boot)
            shutil.copy(os.path.join(BOOTSTRAP_DIR, boot), script)
            env = dict(body["environment"])
            env.update({"LAMBDA_TASK_ROOT": code_dir, "LAMBDA_RUNTIME_DIR": directory,
                        "PATH": "/usr/bin:/bin", "LANG": "en_US.UTF-8", "TZ": ":UTC"})
            with lock:
                stopped = progress[0] or eid in deleted
            if stopped:
                shutil.rmtree(directory, ignore_errors=True)
                return self.error(409, "environment_stopped", "this environment was stopped while it started")
            log = open(os.path.join(directory, "out.log"), "wb")
            proc = subprocess.Popen([interpreter, script], cwd=code_dir, env=env, stdout=log,
                                    stderr=subprocess.STDOUT, start_new_session=True)
            created = Env(proc, directory, fingerprint)
            with lock:
                envs[eid] = created
                stopped = progress[0] or eid in deleted
                if stopped:
                    envs.pop(eid, None)
            if stopped:
                kill(created)
                shutil.rmtree(directory, ignore_errors=True)
                return self.error(409, "environment_stopped", "this environment was stopped while it started")
            self.reply(201, self.state(eid, created))

    return H


def kill(env):
    try:
        os.killpg(env.proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    try:
        env.proc.wait(5)
    except subprocess.TimeoutExpired:
        pass


def fetch_and_unpack(body, directory, code_dir):
    code, limits = body["code"], body["limits"]
    if int(code["expiresInSeconds"]) < 1:
        raise Invalid("the code URL is already expired")
    max_bytes = int(code["sizeBytes"])
    try:
        with urllib.request.urlopen(code["url"], timeout=20) as r:
            data = r.read(max_bytes + 1)
    except Exception as e:  # noqa: BLE001
        raise Invalid("the code download failed: " + str(e)[:100])
    if len(data) > max_bytes:
        raise Invalid("the code is larger than announced")
    if hashlib.sha256(data).hexdigest() != code["sha256"]:
        raise Invalid("the code does not match its digest")
    archive = os.path.join(directory, "code.zip")
    with open(archive, "wb") as f:
        f.write(data)
    try:
        with zipfile.ZipFile(archive) as z:
            infos = z.infolist()
            if len(infos) > int(limits["maxEntries"]):
                raise Invalid("the archive has more entries than allowed")
            total = 0
            for info in infos:
                flat = info.filename.replace("\\", "/")
                if flat.startswith("/") or (len(flat) > 1 and flat[1] == ":") or ".." in flat.split("/"):
                    raise Invalid("an entry leaves the target directory: " + info.filename)
                total += info.file_size
                if total > int(limits["maxExpandedBytes"]):
                    raise Invalid("the archive expands past the allowed size")
            os.makedirs(code_dir)
            target = os.path.realpath(code_dir)
            for info in infos:
                dest = os.path.realpath(os.path.join(target, info.filename))
                if not dest.startswith(target + os.sep) and dest != target:
                    raise Invalid("an entry leaves the target directory: " + info.filename)
                if info.is_dir():
                    os.makedirs(dest, exist_ok=True)
                else:
                    os.makedirs(os.path.dirname(dest), exist_ok=True)
                    with z.open(info) as src, open(dest, "wb") as out:
                        shutil.copyfileobj(src, out)
    except zipfile.BadZipFile:
        raise Invalid("not a zip file")
    finally:
        os.unlink(archive)


http.server.ThreadingHTTPServer.request_queue_size = 256


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--python", required=True)
    ap.add_argument("--node")
    ap.add_argument("--token", required=True)
    ap.add_argument("--port", type=int, default=0)
    args = ap.parse_args()
    if len(args.token) < 16:
        sys.exit("token must be at least 16 characters")
    root = tempfile.mkdtemp(prefix="rovara-local-runner-")
    envs, lock = {}, threading.Lock()
    server = http.server.ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(args, root, envs, lock))
    server.daemon_threads = True
    server.socket.listen(256)
    print("LISTENING", server.server_address[1], flush=True)
    signal.signal(signal.SIGTERM, lambda *_: threading.Thread(target=server.shutdown, daemon=True).start())
    try:
        server.serve_forever()
    finally:
        for env in list(envs.values()):
            kill(env)
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    main()
