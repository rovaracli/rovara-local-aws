# Compatibility suite and release gates

`compat/run.sh native|jvm` starts three loopback instances (`main` with the development switch, `validated` with signature validation and a control
token, `closed` with neither) with the connect guard loaded, then runs:

| Suite | Where | Covers |
|---|---|---|
| boto3 | `python/` | the supported tier (S3, DynamoDB, SQS, SNS, STS, Secrets Manager, SSM, KMS, EventBridge), the three credential cases, cases other emulators get wrong, documented-behaviour fixes, the Rovara control endpoints |
| AWS SDK for JavaScript v3 | `node/` | S3, DynamoDB, SQS, SNS, STS, Secrets Manager, SSM, KMS, credentials |
| AWS SDK for Java v2 | `java/` | S3, DynamoDB, SQS, SNS, STS, Secrets Manager, SSM, EventBridge, credentials (no KMS client in the offline cache) |
| AWS SDK for Go v2 | `go/` | S3, DynamoDB, SQS, STS, SSM (needs a Go toolchain; not run on the machine that wrote it) |
| 54-call matrix | `../perf/matrix.py` | at least 52 of 54 must pass |

Gates inside `run.sh`: network silence (`netgate/connect_guard.c` records and blocks any connect, sendto or
sendmsg to a non-loopback address; a connection sampler backs it up for launchers that drop the guard) and
listening sockets (loopback and the API port only). `scripts/client-allowlist.sh` and `ClientAllowListTest`
fail when a new class holds an HTTP, socket or URL client; `FencedClientsTest` and `OutboundFenceTest` are
the no-outbound tests per fenced client. `conformance.sh` runs the separate conformance kit.

`kit-fixes.diff` holds four fixes for the kit's own tests (the kit is not edited from here).

Control endpoints (all under `/_rovara`; closed with 403 unless `ROVARA_AWS_CONTROL_TOKEN` is set, in which case they need `X-Rovara-Control-Token`, or `ROVARA_AWS_DEV_OPEN_CONTROL=1` (exactly 1) opens them for development; health stays open):
`POST reset`, `POST reset/{service}`, `POST seed`, `GET ledger`, `GET ledger/summary`, `DELETE ledger`,
`GET tick`, `POST tick/{job}`. The seed document is described in `SeedService`.
