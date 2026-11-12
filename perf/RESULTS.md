# Speed gate results

Machine: Apple silicon Mac (18 cores, 48 GiB), macOS, 2026-11-02. Not a Linux worker: the Linux
numbers still have to be taken (see "Not yet measured").

Targets (owner, 2026-11-02; memory counted as private memory since 2026-11-03, see below): start-up to first answer at
most 0.5 s; idle memory at most 64 MiB; peak memory at most 128 MiB during the 54-call matrix; median call at most 3 ms; the matrix passes at
least 52 (the `assume_role` case fails on a missing role exactly as AWS does). Since TS38 the matrix
also runs Lambda (59 calls) through the test-only function runner, which the gate starts as a separate
process (`perf/local_process_runner.py`), so its memory is not the emulator's.

## What the memory gate counts (owner decision, 2026-11-03): private memory

Idle and peak are gated on the run's own, private memory, with the targets unchanged (64 MiB idle, 128 MiB peak):

- **Linux: `RssAnon`** from `/proc/<pid>/status` (anonymous pages: the Java heap, thread stacks, malloc arenas).
- **macOS: the physical footprint** from `footprint -p <pid> -f bytes` (dirty plus compressed pages, no clean file-backed
  pages). It is the closest equivalent to `RssAnon`; it is not the same number.
- Where neither exists the tool falls back to total RSS and the JSON says so (`memory_source`).

**Why.** The native binary is 126 MB on disk and is mapped into the process. Linux counts every page of it that is
resident (`RssFile`) in total RSS: shared with the page cache, clean, read back from the file and reclaimable under
pressure; it is not memory the run owns. On the first arm64 Linux run total RSS was 92.9 MiB at idle, of which only
10.9 MiB was anonymous and 82.0 MiB file-backed; macOS reported about 60 MiB for the same program because it accounts
file-backed pages differently. A gate on total RSS would therefore have measured the file system, not the emulator, and
would have meant different things on the two systems.

**Total RSS is still recorded** next to it (`idle_rss_mib`, `peak_rss_mib` in the JSON, "total RSS ... information only"
in the output) and never fails the run. The earlier results in this file (2026-11-02 and before) are total RSS from `ps`
on macOS; they are not comparable one to one with the private-memory numbers below.

## How it is measured

```
scripts/build.sh native      # GraalVM CE 25.0.2 as JAVA_HOME; ~3 min
scripts/build.sh jvm
export ROVARA_PERF_PYTHON=<python with boto3>   # run by the gate with `-I`
ROVARA_PERF_RUNS=5 scripts/perf-gate.sh native   # exits 1 on any miss
ROVARA_PERF_RUNS=3 ROVARA_PERF_CMD="java -XX:+UseSerialGC -jar dist/jvm/quarkus-app/quarkus-run.jar" scripts/perf-gate.sh jvm
```

`scripts/perf-gate.sh` calls `perf/measure.py`, which starts the build on a free loopback port
with `DOCKER_HOST=unix:///nonexistent` and `AWS_EC2_METADATA_DISABLED=true`, times the process
start to the first 200 from `/_rovara/health`, reads private memory (see above) 3 s after that with no traffic (idle),
then runs `perf/matrix.py` (the 54-call matrix, fake credentials, `python -I`) while sampling private memory
and total RSS every 50 ms (peak). Median call is the median latency of the passing matrix calls. With several
runs: median of start-up, idle and median-call; the highest peak.

## Native image (the shipping mode)

Final tuning: Serial GC, `-R:MaxNewSize=24 MiB`, measured on the final commit. Five runs (`perf/results/native-2026-11-02.json`):

| Measure | Target | Result | |
|---|---|---|---|
| Start to first answer | <= 0.5 s | 0.035 s (median of 5) | pass |
| Idle RSS | <= 64 MiB | 59.7 MiB | pass |
| Peak RSS during matrix | <= 128 MiB | 102.0 MiB (worst of 5) | pass |
| Median call | <= 3 ms | 2.05 ms (median of 5; runs 1.8 to 2.15) | pass |
| Matrix | >= 52/54 | 52/54 | pass |

Notes and honest caveats:
- The very first launch of a freshly built, unsigned binary on macOS took 0.86 to 1.2 s (the OS scans it
  once); every later launch is 0.03 s. The gate takes the median, so it does not count that. A
  Linux worker has no such scan.
- Median call is the noisy figure: single runs between 1.75 ms and 3.9 ms on a busy machine, mostly
  client-side (boto3) time. Five runs and the median keep the gate stable; a single quiet run is
  not guaranteed under 3 ms. The first tuning attempt (default young generation) measured 3.05 ms
  and missed; a 32 MiB young generation fixed latency but raised peak RSS to 123 MiB (too close to
  the limit); 24 MiB gives both.
- The binary is 125 MB on disk. RSS is what the gate limits.

## JVM mode (for the record, not shipping)

| Measure | Target | JVM, Serial GC, C1 only (`-XX:TieredStopAtLevel=1 -Xss512k`) | JVM default flags + Serial GC |
|---|---|---|---|
| Start | 0.5 s | 0.84 s MISS | 1.01 s MISS |
| Idle RSS | 64 MiB | 240 MiB MISS | 428 MiB MISS |
| Peak RSS | 128 MiB | 331 MiB MISS | 582 MiB MISS |
| Median call | 3 ms | 5.8 ms MISS | 7.4 ms MISS |
| Matrix | 52/54 | 52/54 | 52/54 |

Cause of the gap: JVM mode carries the JIT, class metadata and the Quarkus/Vert.x/Jackson classes
(about 150 jars) in memory. The unstripped upstream JVM build measured 412 MB idle / 544 MB peak /
2.2 s start. Stripping took it to 240 MB idle (C1 only). Only the native image meets the targets.

## Conformance kit (rovara-aws-conformance), unstripped JVM vs stripped native

Same kit, same seed. `perf/results/conformance-compare.txt` has the full table.

| | unstripped (JVM) | stripped (native) |
|---|---|---|
| Shape operations passing | 734 / 1019 | 726 / 1019 |
| Behaviour tests passing | 76 / 101 | 76 / 101 |
| Behaviour regressions (pass before, fail now) | | 0 |
| Peak RSS | 548 MiB (unstripped JVM) | 127 MiB (the kit's 1,120 calls, more than the 54-call matrix) |
| Median shape call | 2.0 ms | 0.6 ms |
| Network check | pass | pass |

The 8 shape operations that differ are removed on purpose: SSM Run Command (`SendCommand`,
`GetCommandInvocation`, `ListCommands`, `ListCommandInvocations`, `CancelCommand`,
`DescribeInstanceInformation`; they need EC2 instances and the SSM agent) and the IAM Organizations
access report (`GenerateOrganizationsAccessReport`, `GetOrganizationsAccessReport`; they need
Organizations).

## Native image with the function runner (TS38, commit after b3b477497)

Lambda is in the matrix: create, cold invoke, warm invoke, four concurrent invokes, an unhandled
error, delete. Only `assume_role` fails (58 of 59), as in AWS. `perf/lambda_load.py` drives N
concurrent environments (25 calls each): peak RSS 84 MiB at 4, 89 MiB at 8, 92 MiB at 16 (idle 60.5).

Gate on this commit (5 runs, `perf/out/native.json`), machine load average 22 to 27 (other lanes were
building; the machine is not quiet):

| Measure | Target | Result | |
|---|---|---|---|
| Start to first answer | <= 0.5 s | 0.055 s (median; first launch of a fresh binary 1.5 s) | pass |
| Idle RSS | <= 64 MiB | 60.3 MiB | pass |
| Peak RSS during matrix (with Lambda) | <= 128 MiB | 99.8 MiB (worst of 5) | pass |
| Median call | <= 3 ms | 5.95 ms (runs 3.55 to 6.6) | MISS under load |
| Matrix | >= 52 | 58/59 | pass |

The median call misses only under load. Same-load comparison, interleaved, one run each in turn (load
23 to 33), against the unchanged 12aa140ea binary (no Lambda, `--no-runner`) and this commit with and
without the runner; median call in ms:

| Pair | 12aa140ea | this commit, no runner | this commit, with Lambda |
|---|---|---|---|
| 1 | 5.20 | 6.75 | 6.05 |
| 2 | 10.60 | 8.80 | 8.75 |
| 3 | 10.85 | 14.60 | 9.35 |
| 4 | 13.55 | 10.55 | 9.90 |
| 5 | 24.25 | 9.65 | 14.00 |
| median | 10.85 | 9.65 | 9.35 |

Peak RSS in the same runs: 88 to 93 MiB for all three. The three builds are indistinguishable at this
load. An earlier run of the same code on a quieter machine (load not recorded, binary built before two
small client edits: one retry of a broken connection, a one-call-at-a-time guard on the exit poll)
measured start 0.041 s, idle 60.5 MiB, peak 109.4 MiB, median call 2.6 ms, 58/59. The 3 ms figure has
to be confirmed on a quiet machine or the Linux worker; it is not shown by this commit's loaded run.
Idle readings of 44 to 50 MiB in a few runs are macOS memory compression under pressure, not a change.

## Native image after the review fixes (commit 4497f5244)

Gate, 5 runs, machine load average 23 to 29 (sampled every 4 s; 27 before the first run): start 0.058 s
(median; first launch of the fresh binary 1.0 s), idle 60.2 MiB, peak 93.4 MiB (worst of 5), matrix
58/59 (only `assume_role` fails, as in AWS), median call 5.85 ms (runs 5.05 to 6.4): the median misses
the 3 ms target under this load, as the previous commit did; the interleaved comparison above shows the
unchanged 12aa140ea binary at the same load is no faster (median of medians 10.85 ms). Lambda load
(`perf/lambda_load.py`, 25 calls per environment): 8 concurrent environments peak 87.8 MiB, 16 peak 90.0
MiB, 400 of 400 invocations succeeded (the earlier occasional "connection reset" at 16 is gone: the
stand-alone test runner's listen backlog was the cause). The 3 ms figure still has to be taken on a quiet
machine or the Linux worker.

## Not yet measured

- A Linux worker (arm64 and amd64): the design asks for both the Linux worker and Apple silicon.
- The median-call target with Lambda on a quiet machine or the Linux worker (see above).

## TS21: compatibility suite, behaviour fixes, control endpoints (2026-11-02)

Conformance kit on the stripped native build, same seed (`perf/results/conformance-compat-native.md`):

| | before TS21 | after |
|---|---|---|
| Behaviour tests passing | 76 / 101 | 93 / 101 |
| Shape operations passing | 726 / 1019 | 725 / 1019 |
| Peak RSS under the kit (1,120+ calls) | 127.4 MiB | 105.5 MiB (sampled once a second) |
| Network check | pass | pass |

The 8 behaviour tests still failing are not emulator gaps: 4 kit expectations that disagree with the AWS
documentation (SQS duplicate-queue error code, KMS reserved alias code, STS client-side validation,
PutEvents to a missing bus), 1 that needs signature validation (off by default; it passes with it on), and
3 Lambda tests that need the function runner (TS38). `compat/kit-fixes.diff` holds the kit-side fixes; with
them, 98 of 101 pass (the 3 Lambda tests remain). The one shape operation that moved is `sqs.PurgeQueue`:
the kit calls it twice and the second call now correctly answers `PurgeQueueInProgress`.

`compat/run.sh native`: boto3 35/35, JavaScript v3 8/8, Java v2 9/9, 54-call matrix 52/54, connect guard
loaded with no non-loopback attempt, listening only on 127.0.0.1 and the API port, peak RSS 111 MiB.

### Speed gate on the TS21 build (e751705bf), 2026-11-02 evening

The machine was shared and heavily loaded (load average 22 to 28; the earlier tuning runs had about 2).
Start-up, idle, peak and the matrix passed on every run. The median call is the figure that load moves.

| Run | Start | Idle | Peak | Median call | Matrix |
|---|---|---|---|---|---|
| 1 (load about 12, before the last edit) | 0.031 s | 59.6 MiB | 103.1 MiB | 2.5 ms pass | 52/54 |
| 2 to 6 (load 22 to 28, final binary) | 0.06 to 0.10 s | 48.7 to 60.1 MiB | 93.7 to 102.3 MiB | 5.1 to 5.8 ms MISS | 52/54 |
| unchanged 12aa140ea binary, same load, interleaved | | | 102.7 MiB | 5.1 to 8.05 ms MISS | 52/54 |

Under equal load the TS21 build is not slower than the build before it (call medians 3.95 to 6.25 ms against
5.1 to 8.05 ms). The 3 ms target is therefore not confirmed on the final binary: re-run
`ROVARA_PERF_RUNS=5 scripts/perf-gate.sh native` on a quiet machine or the Linux worker.

### Kinesis shape operations

35 of 45 Kinesis operations showed `crash` with an SSL error. The cause is the kit, not the emulator: for a
generated input that holds a `StreamId` and a garbled `StreamARN`, botocore's endpoint rules build a
`<id>.control-kinesis.<region>.amazonaws.com` host and ignore `endpoint_url`, so the kit's client tried to
open a TLS connection to that real AWS host name (the handshake failed on the certificate; nothing was
sent). `compat/kit-fixes.diff` pins every kit request to the emulator's address. With it the Kinesis shape
result is 29 pass, 16 not implemented, 0 crash.

## arm64 Linux, native image built with Mandrel (run 41667011066, 2026-11-03)

GitHub-hosted `ubuntu-24.04-arm` (aarch64, 2 vCPU, 7.9 GB), the binary taken from the image layout, `scripts/perf-gate.sh native`, 3 runs, memory counted as private memory (`RssAnon`):

| | Target | Measured | |
|---|---|---|---|
| Start-up | <= 0.5 s | 0.037 s | pass |
| Idle, private (`RssAnon`) | <= 64 MiB | 11.0 MiB | pass |
| Peak, private, during the matrix | <= 128 MiB | 38.6 MiB (worst of 3) | pass |
| Idle, total RSS (information only) | - | 92.9 MiB (11.0 anonymous + 81.9 file-backed) | not gated |
| Peak, total RSS (information only) | - | 124.5 MiB | not gated |
| Median call | <= 3 ms (report-only) | 4.75 ms | WARN |
| Matrix | >= 52 | 58 of 59 | pass |
