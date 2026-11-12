# Rovara local AWS

A small, in-memory AWS API emulator for test runs. Private fork of an MIT-licensed emulator
(`LICENSE`, `NOTICE`, `THIRD-PARTY-NOTICES.txt`), reduced to what Rovara's test environments need.

## What it is

- Services: S3, DynamoDB and Streams, SQS, SNS, STS and IAM (what STS and assume-role need),
  Secrets Manager, SSM Parameter Store, KMS, EventBridge, Lambda (code runs in an external function
  runner, see "Functions" below), SageMaker Runtime front, Kinesis, Step Functions, API Gateway definitions,
  Cognito tokens, CloudWatch Logs (accepted and dropped).
- State is in memory only. Nothing is written to disk.
- One listening socket: the API port (`4566`), bound to `127.0.0.1`. `QUARKUS_HTTP_HOST` may move
  it to one specific address; a wildcard address is refused at start-up.
- No Docker, no containers, no telemetry, no update check. The few places that can call an address a
  test chooses (SNS HTTP(S) subscriptions, the SageMaker endpoint front) only reach loopback or the
  addresses listed in `ROVARA_AWS_OUTBOUND_ALLOW`.
- Names: package `ai.rovara.localaws`, env prefix `ROVARA_AWS_`, config prefix `rovara-aws`,
  binary `rovara-local-aws`, health `GET /_rovara/health`, reset `POST /_rovara/reset` (or `/_rovara/reset/{service}`),
  seed, request ledger and tick controls under `/_rovara` (see `compat/README.md`).

## Control paths (closed by default)

Every `/_rovara/*` path except `GET /_rovara/health` is a control path (reset, seed, ledger, tick, the
inspection endpoints). They answer **403** unless:

- `ROVARA_AWS_CONTROL_TOKEN` is set: a request must then send it in `X-Rovara-Control-Token`. A run
  always sets it (a random value only the starter knows; the test's code never sees it); or
- `ROVARA_AWS_DEV_OPEN_CONTROL=1` (exactly `1`; `true`, `TRUE`, ` 1` and everything else stay closed) is set,
  and no token: the control paths are open, and one WARN line says so at start-up. Only for one person on a
  loopback socket. Never set it in a run or an image.

A token, when set, wins over the switch.

### Run contract (what the worker passes)

A control token means a run. A run must not use the local-development defaults, so with a token set (and no
development switch) the emulator **refuses to start** unless all of these are set, each random per run where
it is a secret; the error names the missing ones and never prints a value:

| Environment variable | Value |
|---|---|
| `ROVARA_AWS_CONTROL_TOKEN` | random per run; the run's own code never gets it |
| `QUARKUS_HTTP_HOST` | the run IP literal of the container (the default 127.0.0.1 is unreachable from outside; a wildcard is refused) |
| `ROVARA_AWS_BASE_URL` | `http://aws:4566` (not the default `http://localhost:4566`) |
| `ROVARA_AWS_AUTH_PRESIGN_SECRET` | random per run, 16 or more characters (not `local-emulator-secret`) |
| `ROVARA_AWS_SERVICES_SQS_RECEIPT_HANDLE_SECRET` | random per run, 16 or more characters (not `local-emulator-secret`) |

Also, as needed, `ROVARA_AWS_OUTBOUND_ALLOW` and the function-runner settings below. With no token, or with
`ROVARA_AWS_DEV_OPEN_CONTROL=1`, today's defaults stay for local use. The same list is in `image/catalog-entry.json`
(`_notes.runEnv`). Two paths under `/_rovara` are not control paths and are never
guarded: the single-use function-code download (its path token is its credential) and the SNS signing
certificate (a public certificate). `./mvnw test` runs closed: only the tests that call the control paths opt in, with
`@TestProfile(OpenControlProfile.class)`; `RovaraControlClosedIntegrationTest` and
`RovaraControlTokenIntegrationTest` run the real stack with no token and with one. `compat/run.sh` starts one
instance with the switch, one with a token and one with neither, and `scripts/control-check.sh <command>` checks
any build (jar or native binary) the same way.

## Functions (Lambda)

The emulator never starts function code itself and holds no container runtime. On a cold start it
opens a Runtime API server for the new environment (on the API address, one port per environment),
packs the function's code for a one-time download and asks an external **function runner** to start
an environment. The runner starts the function with AWS's open-source runtime interface client, which
polls the Runtime API server. Invoke, timeout, concurrency, reuse and shutdown are the existing warm
pool and executor; the launcher (`RovaraFunctionRunnerLauncher`) only maps launch, stop and "has the
process exited" onto the runner contract.

- Contract: `src/main/resources/META-INF/rovara/function-runner-v1.openapi.yaml` (versioned; the rules
  a runner must follow are in its description). `FunctionRunnerContractTest` keeps it equal to the code.
- Configuration: `rovara-aws.services.lambda.function-runner.{url,token,code-base-url,...}`
  (env `ROVARA_AWS_SERVICES_LAMBDA_FUNCTION_RUNNER_URL`, `..._TOKEN`). The URL must be loopback or a
  run address (`ROVARA_AWS_OUTBOUND_ALLOW`), the token a random per-run value of 16 or more characters;
  anything else stops the start-up. With no URL, invoking a function fails with a fixed error.
- Available in v1: zip functions on the runtimes the runner lists in `GET /v1/info`. Layers, container
  images, host-directory code and provisioned concurrency are "not available yet" (a fixed error).
- Limits: file modes are not kept when the code is handed to the runner (the zip writer carries no Unix
  permissions); Node and Python need no executable bit. An archive with an unsafe entry (empty or NUL
  name, absolute path, drive letter, a `..` path segment) is refused whole with 400
  `InvalidParameterValueException`; names that merely contain two dots (`jquery..min.js`) are kept.
- Isolation: the Runtime API has no credential, so the runner (or the worker that places it) must drop
  traffic from an environment to every Runtime API port but its own (contract rule 5).
- Tests: `LocalProcessFunctionRunner` (test fixture, not shipped) runs Python and Node handlers as plain
  processes, so invoke, SQS, SNS, EventBridge and Step Functions to Lambda are tested with no Docker.
  `perf/local_process_runner.py` is its stand-alone twin for the speed gate.

## Build

```
scripts/build.sh jvm      # dist/jvm/quarkus-app
scripts/build.sh native   # dist/native/rovara-local-aws (GraalVM CE 25 as JAVA_HOME)
./mvnw test               # unit and integration tests
scripts/no-upstream-names.sh   # fails if the upstream name appears outside LICENSE/NOTICE/THIRD-PARTY*
scripts/perf-gate.sh native    # speed gate; see perf/RESULTS.md (starts the test-only function runner itself)
python3 perf/test_measure.py   # tests of the memory measurement and the gate verdicts
scripts/client-allowlist.sh    # fails when a new class holds an HTTP, socket or URL client
compat/run.sh native           # compatibility suite (4 SDKs), network silence, listening sockets; see compat/README.md
```

The speed gate's memory targets (64 MiB idle, 128 MiB peak) count **private memory**: `RssAnon` on Linux, the physical
footprint (`footprint`) on macOS. Total RSS is printed beside it for information and never fails the gate: on Linux it
also counts the pages of the 126 MB mapped binary, which are shared and reclaimable (details in `perf/RESULTS.md`).

`DOCKER_HOST=unix:///nonexistent` is set by the scripts; no step needs a container engine.

### Image

`image/Containerfile` builds the catalog image (native binary on a distroless glibc base, numeric non-root
user 10001, read-only root with `/tmp` as the one writable path, port 4566, health `GET /_rovara/health`).
Both stages are pinned by digest. The licence files are at `/usr/share/licenses/rovara-local-aws/`.
Nothing is baked in at run time: the worker passes `ROVARA_AWS_CONTROL_TOKEN` and `QUARKUS_HTTP_HOST` (the
container's own address; a wildcard is refused).

```
scripts/image-check.sh                 # static gates, no container engine needed (runs anywhere)
scripts/image-check-test.sh            # tests of the gates and of the layout merge
scripts/image-build.sh --registry-ref <host/path>   # Linux CI runner or builder only; see the script's header
```

The build needs a container engine and a native Linux toolchain, so it never runs on a developer Mac. The
manual workflow `.github/workflows/image.yml` (workflow_dispatch only) builds, measures (the speed gate on the shipped binary, taken out of the image layout with tar), scans, makes an SBOM and signs. The first image is **linux/arm64 only** (Rovara's workers are Graviton); the `platforms` input also offers `linux/amd64` and `both`. arm64 builds natively on the GitHub-hosted `ubuntu-24.04-arm` runner (the repository variable `ARM64_RUNNER` can name another), amd64 on `ubuntu-24.04`; there is no QEMU path. The native-image builder heap is capped at 5g (`NATIVE_IMAGE_XMX`) because that runner has 7.9 GB. The `sign` input (default false) turns the sign job on; without it the run summary says "UNSIGNED: not for the catalog".
`image/catalog-entry.json` is the draft catalog entry the build fills in.

Order for the operator, after the workflow ran (owner's OK needed for anything on staging): download the
`image-release` evidence and the `image-result` layout; **verify `statement.sig` before any push** (`cosign verify-blob --key <IMAGE_SIGNING_KEY>
--signature statement.sig statement.json`), check that `statement.json` names the index digest in `index.digest`
and the sha256 of every SBOM and scan file, and only then push the layout (command in `build-info.json`) through
`~/.local/share/rovara-tools/staging-aws.sh`. The unsigned `image-result` artifact (it holds the image layout) is deleted after 1 day, so verify and push within a day; the 14-day `image-release` artifact holds only the signed statement, `statement.sig`, SBOMs, scans and digest files, never the layout.
The workflow needs the repository variables `IMAGE_SIGNING_ROLE_ARN` (AWS role assumed through OIDC) and
`IMAGE_SIGNING_KEY` (cosign key reference); without either it fails before any AWS call.

## Keeping up with the upstream project

`git remote upstream` points at the upstream repository (fetch only; never push there). A monthly
merge: `git fetch upstream && git merge upstream/main` on a branch, resolve the central dispatch
classes (`ResolvedServiceCatalog`, `Aws*Controller`, `EmulatorConfig`), then run the gates:
`./mvnw test`, `scripts/no-upstream-names.sh` (a merge brings the old package and names back; run
a rename pass again), the listening-sockets test, and `scripts/perf-gate.sh native`. A new class
holding an HTTP client must be reviewed before it ships.
