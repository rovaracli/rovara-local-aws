# Rovara function runner: in-sandbox agent

`agent` is a static Go binary (standard library only, Linux only) that runs as PID 1, or under a
minimal init, inside each gVisor sandbox of the function runner. It

- serves the AWS Lambda Runtime API (version 2018-06-01) on `127.0.0.1:9001`, so AWS's own runtime
  clients run unchanged;
- starts the function's runtime and keeps it warm across invocations;
- takes invocations from the worker on **stdin** and returns results on **stdout** (framing below);
- enforces the deadline, captures logs, reports init errors, refuses oversized payloads.

It needs no network beyond loopback and never sees Rovara's control token. `AGENT_*` environment
variables are removed from the runtime's environment.

**Hardening.** The runtime runs as the same user as the agent, so the agent's first act is
`prctl(PR_SET_DUMPABLE, 0)`. That makes `/proc/1/fd/*`, `/proc/1/environ` and `/proc/1/mem` (and
ptrace) refuse the runtime with EACCES: the function's code cannot write forged frames to the
worker's pipe, read invoke frames from stdin, or read the agent's environment (the integration test
`hostile_handler_cannot_reach_the_agent` checks this under runsc). The flag is reset by `execve`, so
the runtime itself is unaffected. If the call fails the agent sends `fatal` and exits 2. This is a
second layer: the worker still treats every frame as hostile.

**Signals.** The agent ignores SIGTSTP, SIGTTIN and SIGTTOU, so the runtime cannot stop it with
those. SIGSTOP cannot be ignored, and **gVisor (runsc 20261109, systrap) does deliver SIGSTOP from a
same-uid process to PID 1** (unlike Linux, which drops signals to init that it has no handler for),
so a runtime on the agent's uid can freeze the agent and the invoke then ends only at the worker's
backstop (scenario `known_same_uid_sigstop_stops_pid1`). The fix is to keep the runtime on a
different uid from the agent: start the agent as uid 0 with only `CAP_SETUID` and `CAP_SETGID`
(OCI `process.user` 0, `capabilities` bounding/effective/permitted set to those two, no-new-privileges
on) and pass `-uid N -gid N`. The runtime then runs as N with no capabilities and every signal to
PID 1, including SIGKILL, fails with EPERM, while `/proc/1/*` stays closed (scenario
`split_uid_blocks_signals_and_proc_access`). **The worker's sandbox profile should use this split.**
Without it the agent still works, but a hostile function can stall its own sandbox (only its own).

```
agent [flags] [--] [runtime command [args...]]

  -listen        Runtime API address, loopback only (default 127.0.0.1:9001; port 0 picks one)
  -init-timeout  time the runtime may take to start polling for work (default 10s)
  -log-ring      bytes of runtime output kept (default 1 MiB)
  -uid -gid      run the runtime as this user (default: the agent's own)
  -debug         copy runtime output to the agent's stderr
```

With no command the agent runs the first executable of `/var/runtime/bootstrap`,
`/var/task/bootstrap`, `/opt/bootstrap`. Otherwise the command is run as given, for example
`agent -- /agent/qemu-x86_64-static /var/lang/bin/python3.12 /var/runtime/bootstrap.py` for an x86_64
image. The worker supplies the reserved environment (`_HANDLER`, `AWS_LAMBDA_FUNCTION_NAME`, ...);
the agent adds `AWS_LAMBDA_RUNTIME_API`, and `LAMBDA_TASK_ROOT` / `LAMBDA_RUNTIME_DIR` when absent.
The runtime starts in its own process group with stdin from `/dev/null`, stdout and stderr on one
pipe (so log order is write order), in `$LAMBDA_TASK_ROOT`.

## Framing (`agent/1`)

A frame is a 4-byte big-endian unsigned length `N` followed by `N` bytes holding one UTF-8 JSON
object. `2 <= N <= 16,777,216` (16 MiB: a 6 MiB payload as base64 plus the envelope). Every object
has a string `"type"`. Binary data is base64 (standard alphabet, padded). Field names are camelCase.
Strings that carry log text are JSON strings; bytes that are not valid UTF-8 arrive as U+FFFD.

A frame that is not a JSON object, a bad length, or an `invoke` that does not parse is a protocol
error: the agent sends `fatal`, kills the runtime and exits with code 64. A frame with an unknown
`type` is ignored (logged on stderr). Closing stdin, a `shutdown` frame, SIGTERM or SIGINT make the
agent kill the runtime's process group and exit 0.

### Start-up order

The agent sends `hello`, starts the runtime, and then sends **exactly one** of `ready` or
`init_error` before it reads any `invoke`. A worker should wait for that frame on a cold start;
`invoke` frames sent earlier simply queue until it has been sent. After an `init_error` the agent
stays up and the next `invoke` retries the start; that failure comes back as the `result` (status
`init_error`), not as another `init_error` frame.

### Worker to agent

`invoke`

| field | type | |
|---|---|---|
| `requestId` | string, required | 1-128 chars of `A-Za-z0-9-_.:`; becomes `Lambda-Runtime-Aws-Request-Id` |
| `payload` | base64 string, required (may be empty) | event bytes; at most **6,291,556** bytes decoded |
| `timeoutMs` | int | enforced from the moment the invocation is queued to the runtime |
| `deadlineMs` | int, epoch ms | used only when `timeoutMs` is absent |
| `functionArn` | string | `Lambda-Runtime-Invoked-Function-Arn` |
| `traceId` | string | `Lambda-Runtime-Trace-Id`; the agent makes one up when absent |
| `clientContext`, `cognitoIdentity` | string | sent as `Lambda-Runtime-Client-Context` / `-Cognito-Identity` only when present |
| `functionVersion` | string | for the START line; default env `AWS_LAMBDA_FUNCTION_VERSION`, else `$LATEST` |
| `memorySizeMb` | int | for the REPORT line; default env `AWS_LAMBDA_FUNCTION_MEMORY_SIZE`, else 128 |
| `logBytes` | int | size of the returned `logTail` (default 65,536; at most the ring size) |

One of `timeoutMs` and a future `deadlineMs` is required. Header values must not contain CR, LF or
NUL. Invocations are served one at a time in arrival order (Lambda semantics); a second `invoke`
queues behind the first. The `Lambda-Runtime-Deadline-Ms` header is the enforced deadline.

`shutdown`: no fields.

### Agent to worker

`hello`: first frame, before the runtime starts. `{proto:"agent/1", agent, version, pid, listen, command}`.

`ready`: the runtime reached its first `/invocation/next`. `{initDurationMs, logTail}` (`logTail` is the
init output).

`init_error`: the runtime did not come up. `{reason, errorType, errorMessage, payload, logTail,
initDurationMs}`. `reason` is `runtime_reported` (POST `/runtime/init/error`), `exited`, `timeout` (no
`/next` within `-init-timeout`) or `start_failed` (command missing or not executable; `errorType`
`Runtime.InvalidEntrypoint`). `payload` is the base64 error document. The agent stays up: the next
`invoke` starts the runtime again.

`runtime_exit`: the runtime died while idle. `{exitCode, signal, message, logTail}`. The next `invoke`
starts it again.

`result`: exactly one per `invoke` (none if the agent is shutting down).

| field | |
|---|---|
| `requestId` | echoes the invoke |
| `status` | `ok`, `function_error`, `init_error`, `timeout`, `crash`, `rejected` |
| `payloadTruncated` | true when the payload was dropped to fit one frame (omitted otherwise) |
| `payload` | base64. `ok`: the runtime's response body. `function_error`: the error document the runtime posted (what Lambda returns with `X-Amz-Function-Error: Unhandled`). `timeout`, `crash`, `init_error`: an error document written by the agent. `rejected`: empty |
| `errorType`, `errorMessage` | set unless `ok` |
| `logTail` | text of this invocation's log: START, runtime output, END, REPORT (and the init output when the invoke had to restart the runtime), newest `logBytes` bytes |
| `logTruncated` | true when older bytes were dropped (ring or `logBytes`) |
| `durationMs` | from handing the event to the runtime until its response (the full timeout for `timeout`) |
| `billedDurationMs` | `durationMs` rounded up, at least 1 |
| `initDurationMs` | present on the first result after each runtime start |
| `maxMemoryUsed` | **bytes**: peak resident memory (VmRSS, summed over the runtime's process group, sampled every 20 ms) during this invocation. gVisor has no VmHWM or cgroup files in the sandbox; the worker should prefer the host's cgroup `memory.peak` when it has it |

Statuses and their `errorType`:

- `ok`: no error.
- `function_error`: the error type from the runtime (the `errorType` in the posted JSON, else the
  `Lambda-Runtime-Function-Error-Type` header); or `Function.ResponseSizeTooLarge`, "Response payload
  size exceeded maximum allowed payload size (6291556 bytes)." when the runtime posts more than
  6,291,556 bytes (the runtime is answered 202, so it stays warm).
- `timeout`: `Sandbox.Timedout`, message `RequestId: <id> Error: Task timed out after 3.00 seconds`; the
  log gets `<time> <id> Task timed out after 3.00 seconds` and `Status: timeout` in REPORT. The runtime's
  process group is killed (as PID 1 the agent also kills everything else in the sandbox); the next
  invoke starts a fresh runtime.
- `crash`: `Runtime.ExitError`, message `RequestId: <id> Error: Runtime exited with error: exit status 7`
  (or `signal: killed`). The next invoke starts a fresh runtime.
- `init_error`: as for the `init_error` frame, for an invoke that had to (re)start the runtime and
  failed.
- `rejected`, nothing was run: `RequestEntityTooLargeException` (payload over 6,291,556 bytes),
  `InvalidRequestId`, `InvalidPayload` (bad base64), `InvalidTimeout`, `InvalidHeader`.

Error strings that come from the runtime are capped before they are encoded: `errorType` at 256
bytes, `errorMessage` at 64 KiB (the full error document is still in `payload`). Frames are encoded
without HTML escaping. If a `result` would still exceed 16 MiB the agent sheds weight rather than
fail: first `logTail` shrinks to its newest 64 KiB (`logTruncated`), then `payload` is dropped
(`payloadTruncated: true`).

`fatal`: `{message}`, sent before the agent exits on a protocol error or when it cannot start
(non-loopback `-listen`, port in use; exit code 2).

The agent writes START, END and REPORT lines into the log itself, in Lambda's format:

```
START RequestId: <id> Version: $LATEST
...runtime output...
END RequestId: <id>
REPORT RequestId: <id>	Duration: 1.57 ms	Billed Duration: 2 ms	Memory Size: 512 MB	Max Memory Used: 22 MB	Init Duration: 104.42 ms
```

## Runtime API served

| request | answer |
|---|---|
| `GET /2018-06-01/runtime/invocation/next` | blocks until an `invoke` arrives; 200, body = payload, headers `Lambda-Runtime-Aws-Request-Id`, `-Deadline-Ms`, `-Invoked-Function-Arn`, `-Trace-Id`, and `-Client-Context` / `-Cognito-Identity` when given. The first call marks the runtime ready |
| `POST .../invocation/{id}/response` | 202 `{"status":"OK"}`; 400 `InvalidRequestID` for an id that is not the one in flight or was already answered |
| `POST .../invocation/{id}/error` | 202; same 400 rule; type from the body or `Lambda-Runtime-Function-Error-Type` |
| `POST .../init/error` | 202 before the first `/next`; 403 `InvalidStateTransition` after |
| anything else | 404, or 405 for the wrong method |

The official Python and Node clients send no `Lambda-Runtime-Invocation-Id`; nothing in the agent
needs it. Response streaming (`Lambda-Runtime-Function-Response-Mode: streaming`) is not supported:
a streamed body is read to the end and treated as one buffered response.

## Process handling

- The runtime is started when the agent starts (so `ready` or `init_error` arrives without an
  invoke) and restarted on demand after a timeout, crash, init failure or idle exit.
- As PID 1 the agent reaps every orphan re-parented to it and keeps the exit status of the runtime's pid only.
  When it is not PID 1 it waits for the runtime pid only.
- The runtime API is reachable by every process in the sandbox, as on Lambda.

## Testing

- `go test ./...` (Linux): framing, ring buffer, log barrier, and the whole agent against a fake
  runtime (the test binary re-executed) over real pipes and HTTP.
- `integration/`: AWS's python 3.12 and nodejs 22 base images (arm64) under `runsc`.
  `sudo integration/setup.sh` once (exports root file systems under `/srv/a1`, removes the Docker
  images, installs the numpy layer), then `integration/run.sh`.
