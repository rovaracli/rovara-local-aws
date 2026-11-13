import json, os, subprocess, sys, time

def hello(event, context):
    print("hello from python", event.get("name"))
    return {"hello": event.get("name"), "pid": os.getpid(), "request_id": context.aws_request_id,
            "arn": context.invoked_function_arn, "remaining_ms_ok": context.get_remaining_time_in_millis() > 0}

def echo(event, context):
    return event

def error(event, context):
    raise ValueError("kaboom from python")

def sleepy(event, context):
    # leave a child behind in the process group, then sleep past the deadline
    subprocess.Popen(["sleep", "300"])
    print("sleeping")
    time.sleep(event.get("seconds", 30))
    return procs(event, context)

def crash(event, context):
    print("exiting hard")
    os._exit(7)

def orphan(event, context):
    # double fork: the grandchild is re-parented to PID 1 (the agent) and exits shortly after
    if os.fork() == 0:
        if os.fork() == 0:
            time.sleep(0.2)
            os._exit(0)
        os._exit(0)
    os.wait()
    return "forked"

def zombies(event, context):
    out = []
    for p in os.listdir("/proc"):
        if p.isdigit():
            try:
                st = open("/proc/%s/stat" % p).read()
                state = st[st.rindex(")") + 2]
                if state == "Z":
                    out.append(p)
            except OSError:
                pass
    return {"zombies": out, "procs": [p for p in os.listdir("/proc") if p.isdigit()]}

def procs(event, context):
    cmds = []
    for p in os.listdir("/proc"):
        if p.isdigit():
            try:
                cmds.append(open("/proc/%s/cmdline" % p, "rb").read().replace(b"\0", b" ").decode().strip())
            except OSError:
                pass
    return cmds

def big(event, context):
    return "x" * event["n"]

def numpy_op(event, context):
    import numpy as np
    a = np.arange(1_000_000, dtype=np.float64)
    return {"numpy": np.__version__, "sum": float(a.sum()), "dot": float(np.dot(a[:1000], a[:1000]))}

def mem(event, context):
    b = bytearray(event["mb"] << 20)
    for i in range(0, len(b), 4096):
        b[i] = 1
    return len(b)

def net(event, context):
    import socket
    r = {}
    for name, host, port in (("internet", "1.1.1.1", 443), ("host", "192.168.5.2", 22)):
        s = socket.socket(); s.settimeout(1)
        try:
            s.connect((host, port)); r[name] = "REACHED"
        except Exception as e:
            r[name] = "blocked(%s)" % type(e).__name__
        finally:
            s.close()
    r["env_leak"] = [k for k in os.environ if k.startswith("AGENT_")]
    r["runtime_api"] = os.environ.get("AWS_LAMBDA_RUNTIME_API")
    return r


def hostile(event, context):
    # A hostile handler runs as the same uid as the agent (PID 1). None of these may be allowed:
    # they would let it forge frames to the worker, steal invoke frames, or read the agent's
    # environment. Only opens are tried; nothing is written.
    import errno
    out = {}
    for name, path, flags in (("fd0_read", "/proc/1/fd/0", os.O_RDONLY), ("fd1_write", "/proc/1/fd/1", os.O_WRONLY),
                              ("fd1_read", "/proc/1/fd/1", os.O_RDONLY), ("fd2", "/proc/1/fd/2", os.O_WRONLY),
                              ("environ", "/proc/1/environ", os.O_RDONLY), ("mem", "/proc/1/mem", os.O_RDONLY)):
        try:
            fd = os.open(path, flags)
            os.close(fd)
            out[name] = "OPENED"
        except OSError as e:
            out[name] = errno.errorcode.get(e.errno, str(e.errno))
    try:
        out["fd_listing"] = len(os.listdir("/proc/1/fd"))
    except OSError as e:
        out["fd_listing"] = errno.errorcode.get(e.errno, str(e.errno))
    out["self_environ_readable"] = len(open("/proc/self/environ", "rb").read()) > 0
    return out


def signal_init(event, context):
    # Signal PID 1 (the agent) from the runtime, which runs as the same uid.
    import errno, signal as sg
    out = {}
    for name in event.get("sigs", []):
        try:
            os.kill(1, getattr(sg, name))
            out[name] = "SENT"
        except OSError as e:
            out[name] = errno.errorcode.get(e.errno, str(e.errno))
    time.sleep(0.3)   # give a stopped agent time to show it
    return out
