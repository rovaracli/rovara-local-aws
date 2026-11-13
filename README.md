# Rovara local AWS

A small, in-memory AWS API emulator for test runs. Private fork of an MIT-licensed emulator
(`LICENSE`, `NOTICE`, `THIRD-PARTY-NOTICES.txt`), reduced to what Rovara's test environments need.

## What it is

- Services: S3, DynamoDB and Streams, SQS, SNS, STS and IAM (what STS and assume-role need),
  Secrets Manager, SSM Parameter Store, KMS, EventBridge, Lambda (code runs in an external function
  runner, see "Functions" below), SageMaker Runtime front, Bedrock runtime front, Kinesis, Step Functions, API Gateway definitions,
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

## The front, and planned services

`front/` is a small Go process (`rovara-aws-front`) that runs AWS Emulator (the engine, version pinned in `front/services_gen.go`) as a
child on `127.0.0.1` and keeps the contract above from the outside: the control paths, the request ledger, the base URL rewrites, the
seed. Everything below is about which AWS services it serves.

### Planned services (`ROVARA_AWS_PLANNED_SERVICES`)

The run's plan names the AWS services it may use, as a comma separated list of **keys of the engine's service table** (436 services;
the keys are those of `packages/contracts/src/generated/aws-emulator-services.json` in Rovara Code). An older spelling is read as its
key (`secretsmanager` is `secrets-manager`, `events` is `eventbridge`, `cognito-idp` is `cognito-identity-provider`, `states` is `sfn`,
`logs` is `cloudwatch-logs`), the same way Rovara Code reads it. An unknown key refuses start and names the key.

- **The plan must name every service the code calls, `sts` and `iam` included.** Nothing is added for the code: an SDK that asks STS for
  `GetCallerIdentity` or assumes a role needs `sts`, and a Lambda function or state machine needs `iam` for its role.
- A service of the table that the plan does not name is refused with `400 ServiceNotAvailableException` and counted as `outOfPlan` in the
  ledger summary (a field per service, present only when a plan is set). A request for a service that is not in the table, or that
  cannot be told apart from another (below), is refused as unsupported (404) and never forwarded. An engine 501 or `AmbiguousService`
  counts as unsupported.
- The ledger and `GET /_rovara/health` use the table's keys (`cloudwatch-logs`, `sfn`, `secrets-manager`), and the operation names of REST
  services come from the engine's Smithy route tables (`GetFunction`, not `GET /2015-03-31/functions/x`).
- **Without the setting** (for one release; workers roll out after the image) the 0.5.15 behaviour stays: 18 services,
  `ROVARA_AWS_SERVICES_<X>_ENABLED=false` switches them off. TODO: the release after the rollout sets `plannedRequired` in
  `front/config.go`, so a run without a plan is refused at start; `TestPlannedSettingIsOptionalForOneRelease` pins the current behaviour
  and flips with it. With a plan, the `_ENABLED` switches are ignored.

How a request is identified (`front/planned.go`, tables generated into `front/services_gen.go` by `front/tools/gen`, which pins the table
and the Smithy models by sha256): the SigV4 scope names the route key (the signing name); 40 signing names are shared by 112 services,
and those are narrowed by the wire protocol, the operation (X-Amz-Target operation, Query Action, CBOR path operation, or the REST
method and URI template read from the **raw** path, case-sensitively, as the engine does: `/v2/apis` is API Gateway V2 and `/v%32/apis`
is nobody's), then the target prefix or Query Version, then the most specific REST template, then a verified tie-break. What is still
more than one service is refused. `front/services_gen_report.txt` lists every shared name and how each pair is told apart, and the pairs
that cannot be (timestream-query and -write for their common operations; lambda and lambda-microvms tags; the chime family, lex,
greengrass, ivs, qconnect and wisdom, bedrock, signer for routes with identical templates). The tie-breaks: the EventBridge API under
`events` is eventbridge (cloudwatch-events answers only under its own name `cloudwatchevents`), the Query API under `rds` is rds (docdb
and neptune answer only under `docdb` and `neptune`); a plan that names only the other service gets such SDK calls refused. The engine
is always given the front's own `Authorization` naming the decided service. A request that carries two `X-Amz-Target` values, or a scope
and a target that disagree, is refused.

The engine claims a few services by their target prefix whatever the scope says (CloudTrail, CodeConnections, CodeStar Connections). The
front's rule above (a target must name a service of the scope's group) is what keeps such a request from reaching an unplanned service.

**Published addresses.** Answers that name the engine's own address are rewritten to the base URL for an allow-list of operations:
API Gateway V2 `ApiEndpoint`, IoT `DescribeEndpoint`, CloudFormation queue URLs, and Lambda function URLs, which become
`<base>/_aws/lambda-url/<id>/` (the engine's reserved data-plane path; `/_aws/<plane>/...` requests are routed to the service that owns
the plane). Names that are host names (a load balancer's DNSName, a CloudFront or OpenSearch or AppSync endpoint) cannot be rewritten
and are left as the engine says them.

**CloudFormation.** A stack creates its resources inside the engine, so a planned CloudFormation can create resources of a service the
plan does not name. The front does not block the stack; for CreateStack, UpdateStack, CreateChangeSet (and the stack set calls) it reads
the template (inline, or a TemplateURL that names the engine's own S3, fetched over loopback, at most 1 MiB), and for each resource
type of a service the plan does not name it counts one `outOfPlan` call under that service with the operation
`cloudformation:<Type>`. A nested stack, a transform or macro, a template it could not read and a namespace it cannot map are counted once
under the service `cloudformation-unchecked` (operations `cloudformation:nested`, `:transform`, `:unreadable`, `:unmapped`): the evidence
can say "nested templates are not checked". Only a request the engine accepted is counted.

**Lambda functions the engine cannot run (the heavy-function detector).** The engine runs a function in-process, python and nodejs only,
with no host network, files or processes. It accepts a function it cannot run, and when SNS, EventBridge or S3 invokes it the engine
reports success while the code never ran. Until the function runner exists the front says so; it blocks nothing. It reads
CreateFunction, UpdateFunctionCode, UpdateFunctionConfiguration, PublishLayerVersion (zip inline, or an object of the engine's own S3
over loopback; a request body above 16 MiB is not read whole) and CloudFormation templates it can read (`AWS::Lambda::Function` and
`LayerVersion`, JSON or the YAML subset of `front/yamlish.go`). A package is judged without extracting anything: the central directory
and at most 20 bytes of each regular entry (the ELF magic and machine); links are not followed, names that escape, devices, a declared
bomb and more than 20000 entries mark the zip unsafe and are never read further. A function is heavy, first match wins, for the reason
`image` (PackageType Image), `runtime` (anything but python* and nodejs*: java21, provided.al2023, dotnet, ruby, go), `x86-native` (an
ELF file in the package or an attached layer that is built for x86-64 or declared Architectures x86_64), `native-code` (any other ELF
file), `unchecked` (package or layer too large to look at). Not blocked, recorded:
- **Ledger summary** (`GET /_rovara/ledger/summary`): service `lambda`, operation `heavy-function:<reason>`, `calls` = `unsupported` =
  one per function (at create; again only if its reason changes) plus one per Invoke of it the front sees.
- **Ledger entries** (`GET /_rovara/ledger?service=lambda`): `{"service":"lambda","operation":"heavy-function:native-code","method":"POST","status":200,"unsupported":true,"function":"<name>",...}`.
  The summary has no function names; the `function` field of the entries and the registry below have.
- **Registry** (`GET /_rovara/lambda/heavy`): `{"runner":"not available","functions":[{"name":"<name>","reason":"<reason>","invocations":<n>}]}`;
  a function that stops being heavy, a DeleteFunction and `/_rovara/reset` take entries out.
Evidence line: "Lambda function `<name>` was not run locally (`<reason>`); the function runner is not available yet". The operation
name is not an upper camel case word, so a reader that validates operation names has to accept the `heavy-function:` prefix.
Invokes through SNS, EventBridge or S3 triggers are not seen by the front; the create-time record is their evidence. A CloudFormation
function with no literal name is known as `<stack>-<LogicalId>`, and an Invoke of `<stack>-<LogicalId>-<suffix>` counts.

**Calls between services inside the engine.** A planned service can be told to call another one (the call never passes the front). At the
moment it is told, the front reads that out of the request and records one `outOfPlan` call under each service the plan does not name,
operation `<source>:<service>:<action>`, without blocking: Step Functions CreateStateMachine and UpdateStateMachine (every Task
`Resource`: `arn:aws:states:::<svc>:<action>`, `arn:aws:states:::aws-sdk:<svc>:<action>`, a Lambda ARN; source `stepfunctions`),
EventBridge PutTargets and the seed's rule targets (`eventbridge`), Scheduler CreateSchedule and UpdateSchedule including the
universal target and the dead-letter ARN (`scheduler`), Pipes CreatePipe and UpdatePipe (`pipes`), SSM Automation documents
(`ssm`), and state machines declared in a CloudFormation template (`stepfunctions`). What cannot be read or placed (a JSONata or JSONPath
Resource, an unknown service name, an unreadable body) is counted under the service `targets-unchecked`. What a Lambda function's own
code calls cannot be read from outside and is not recorded. CloudFormation templates are read as documents (JSON, or the YAML subset),
never by text search; a template that is not a document, a resource Type that is not text and a nested Fn::Transform are counted under
`cloudformation-unchecked` (`:unparsed`, `:transform`). Queue URLs in Step Functions execution output are rewritten to the base URL.
Rule: **fail honest.** Anything the front cannot read with certainty is recorded as an unchecked marker, never skipped. A Step Functions
`Resource` is read by the fields the engine reads (`arn`, any partition, service `states` or `lambda`, any region and account, then
`aws-sdk:<svc>:<action>` or `<svc>:<action>`); a spelling the engine would not read, or an ARN that does not split, is
`targets-unchecked` (`stepfunctions:resource`). A definition written with an intrinsic function is read only when it is a literal
`Fn::Join` or an `Fn::Sub` whose text parses; otherwise `stepfunctions:intrinsic`. A `DefinitionS3Location` is fetched like a TemplateURL
(unversioned) or is unchecked. A `TemplateURL` with a query string (`versionId`), a Lambda package or layer with `S3ObjectVersion`, a
`Custom::` resource (`cloudformation:custom`), a third-party type (`cloudformation:unmapped`) and SSM `executeScript` and
`executeAutomation` steps (`ssm:script`) are unchecked. An EventBridge or Scheduler API-destination target is recorded under
`eventbridge` as `<source>:events:api-destination` (an outside delivery; the engine reaches nothing today). The
Scheduler universal target is read case-insensitively with any region, account and partition. Known approximation: the Query API
under the shared name `rds` is served as rds even when the code meant docdb or neptune (they answer only under their own scope names).
Everything the front reads from the engine for itself is an S3 object path only (no `_`-prefixed first segment, no `.`/`..`/encoded
slashes), within 10 s, and a package is judged only after the request body was read within a shared 64 MiB budget that nothing waits for.

**Seed.** `POST /_rovara/seed` calls the engine directly, so it obeys the plan: a section for a service the plan does not name fails its
step. Kinds: `s3`, `dynamodb`, `sqs`, `sns` (topics with subscriptions), `secretsmanager` or `secrets-manager` (`name`, `value`),
`ssm` (`name`, `value`, `type`), `kms` (`alias`, `description`), `events` or `eventbridge` (`buses`, `rules`), `sagemaker` (`endpoints`, see below; planned mode) and `calls`.

### SageMaker endpoints (`sagemaker-runtime`, planned mode)

The engine's SageMaker runtime answers every invoke with `424 ModelError`, never writes an asynchronous answer and never publishes a
notification. With `sagemaker-runtime` in the plan the front answers the three invoke operations itself (`front/sagemaker*.go`);
`InvokeEndpoint`, `InvokeEndpointAsync` and `InvokeEndpointWithResponseStream` are recognised by their route (the runtime and the control
plane both sign as `sagemaker`), the ledger counts them under `sagemaker-runtime`, and the control plane (`CreateEndpoint`,
`DescribeEndpoint`, ...) stays with the engine when the plan names `sagemaker`. The legacy mode (no plan) forwards invokes to the engine as in 0.5.15.

- **Which endpoints exist** (the endpoint table): the ones the code creates through the front (`CreateModel`, `CreateEndpointConfig`,
  `CreateEndpoint` and the deletes, read when the engine accepted them); the seed's `sagemaker.endpoints` (`name`, `variants`,
  `AsyncInferenceConfig` in the API's shape, `backing`), which the front also creates in the engine when the plan names `sagemaker`; and
  endpoints a CloudFormation template declares. The engine's CloudFormation reaches `CREATE_COMPLETE` for `AWS::SageMaker::Model`,
  `EndpointConfig` and `Endpoint` and creates nothing, so the front reads the template as a document and, once the engine accepted the
  stack (for a change set, once it is executed), creates the three through the engine's API and in the table. Names are resolved from
  literals, parameters, `AWS::StackName`/`Region`/`AccountId`, `Ref` and `GetAtt` of the stack's own SageMaker resources, S3 buckets and SNS
  topics with a literal name, `Fn::Sub` and `Fn::Join`; a resource with no name takes the physical id the engine gave it (what the stack's outputs
  carry); anything else is recorded as `cloudformation:<reason>` under `sagemaker-runtime` (fail honest). A call to a name that is no endpoint is
  `ValidationError: Endpoint <name> of account 000000000000 not found.` and counts as `unplannedEndpoints`. A reset empties the table and the
  backings; the counters go with `DELETE /_rovara/ledger`.
- **How an endpoint is answered** (its backing, `PUT /_rovara/sagemaker/endpoints/<name>`, any time, with the control token): `mode`
  `canned` (rules by content type, accept, body hash, body text or JSON path with `equals`, `matches` or `exists`, then an ordered queue,
  then a `default`; no answer at all is a `ModelError` that names the request's hash), `helper` (forwarded to the model stand-in at
  `<ROVARA_AWS_SAGEMAKER_HELPER>/invocations`, comma separated http addresses, never loopback or link-local, resolved once and kept; the first is the default for a backing that names `helper`
  without an address; the SM3 model stand-in is **parked under owner decision 141**: the code stays, but it is used only when an endpoint's backing
  explicitly says `helper`; having the variable set changes nothing for any other endpoint), or `image` (the customer's image on the function runner: answered
  `ServiceUnavailable ... not available yet`, counted unsupported). Answers can be errors (`ModelError` with `OriginalStatusCode`,
  `ValidationError`, `ModelNotReadyException`, ...), carry `customAttributes` and the answering `variant`, wait (`delayMs`), and for a
  stream be split into parts (`partSize`, or explicit `parts`, `partDelayMs`) and end in a `ModelStreamError` (`streamError`). A model's error
  status is a `ModelError` carrying it; its reply is capped at 6 MiB and only `Content-Type` and `X-Amzn-SageMaker-Custom-Attributes` pass.
  A document with a field the front does not know is refused, so a rule that silently never matches cannot be written.
- **An endpoint with no backing is not answered** (decision 141). The front never falls back to the stand-in, never makes an answer up and never
  runs the real model. `InvokeEndpoint`, `InvokeEndpointWithResponseStream` and `InvokeEndpointAsync` are refused at once (an async call is not
  accepted, so no output or error file is waited for) with `400 ValidationError`, `X-Amzn-ErrorType: ValidationError`, and the message
  `Rovara: no answer for endpoint <name>. No recording or fixture was approved for this endpoint, and the real model was not run. Nothing was made up. This test was NOT RUN: it did not pass and it did not fail.`
  The ledger entry's `marker` is exactly `no-answer: no recording for this endpoint`, so the run reports the test as **not run**, by name, with
  that reason, never as failed; the table counts it under `noAnswer` (and `errors`). A recorded or hand-written canned backing (SM1/SM2) is
  unchanged. A canned backing with no matching rule is still the `ModelError` that names the request's hash (`; unmatched`).
- **Streaming** is `application/vnd.amazon.eventstream` (`front/eventstream.go`, shared with the later Bedrock route): `PayloadPart` events whose
  payload is the part's bytes, and `ModelStreamError` as an exception event. An error before the first byte is an ordinary HTTP error.
- **Async** answers 202 with `InferenceId`, `OutputLocation` (`<S3OutputPath>/<InferenceId>.out`) and `FailureLocation`, then, after
  `asyncDelayMs` (default 100), reads the input object (up to 16 MiB; larger fails like any failure; the jobs together hold at most 48 MiB, two at a time) from the engine's S3, asks the backing for the answer, writes the output (or the error text)
  to the engine's S3 and publishes the notification to the config's success or error topic through the engine's SNS. When the plan does not name
  `s3` or `sns`, each such call is recorded as out of plan (`sagemaker-runtime:s3:PutObject`, ...) without being blocked.
- **Evidence.** Each ledger entry carries a `marker` (`recorded fake`, `hand-written fake`, `Rovara model stand-in` (explicit backing only), `; made-up answer`,
  `; unmatched`, `no-answer: no recording for this endpoint`, `unplanned endpoint`, `not available yet`); `GET /_rovara/sagemaker/endpoints[/<name>]` returns the table with each
  backing's label, `faked`, `notTested: "real model behaviour"`, and counts (calls, matched, made up, unmatched, errors, streamed, async, no answer, async completed and failed, notification failures, and the size and hash, never the body, of the newest unmatched requests).
- Not built: bidirectional streaming (`sagemaker-runtime-http2` is forwarded to the engine), the customer's image (lane SM6), the model
  stand-in itself (lane SM3), `UpdateEndpoint` (the engine answers 501), removing a stack's endpoints when the stack is deleted (a reset does).

Proofs: `go test ./...` (in `front/`; includes every service of the table), `front/tools/sagemaker_live.py` (boto3 against the front and the
real engine: invoke, streaming, async with the S3 object and the SNS-to-SQS notification, errors, CloudFormation, seed, reset),
`front/tools/eventstream_check.py` (botocore's event stream parser against golden frames and the Go encoder), `front/tools/route_differential.py --all-services` (every
service of the table against the real engine: no request is forwarded for a service outside the plan), `front/tools/egress_check.py`
(SNS, EventBridge, Step Functions, CloudFormation, S3 notifications and Lambda with every socket of the front and the engine
sampled), `front/tools/gen -check` (the generated tables match their inputs).

### Bedrock runtime (`bedrock-runtime`, planned mode)

The engine's Bedrock runtime answers `Converse`, `ConverseStream`, `InvokeModel`, `InvokeModelWithResponseStream` and `CountTokens` in the
right shapes, but with one fixed sentence ("No language model runs in this emulator"); it ignores a request's own guardrail, answers
`ApplyGuardrail` with 501 and embedding models with 424, and nothing scripts what it says. With `bedrock-runtime` in the plan the front
answers those six operations itself (`front/bedrock*.go`) from fixtures. **No model runs and none is called; every answer is a fake.** The runtime
and the control plane both sign as `bedrock`; the front tells them apart by the route (the model id is in the path), the ledger counts
the calls under `bedrock-runtime`, and the control plane (`ListFoundationModels`, guardrail CRUD) stays with the engine when the plan names
`bedrock`. The other operations of the route key (async invoke, the bidirectional stream, `InvokeGuardrailChecks`) and the legacy mode
(no plan) are forwarded to the engine as before.

- **Fixtures** (`PUT /_rovara/bedrock/fixtures/<name>`, or `PUT /_rovara/bedrock/fixtures` with `{"fixtures":[...]}` to replace all, or the seed's
  `bedrock.fixtures`; control token): a *set* belongs to a model id (`modelId`: exact, the id the code gives or the base id of an inference profile
  or ARN; `modelPrefix`: for example `anthropic.`; neither: every model) and holds ordered `rules`, a `queue` and a `default`. The answer is the first
  answer of the most specific set that has one (exact id, longest prefix, every model); inside a set the first matching rule whose `times` is not
  used up, then the queue (each entry once), then the default (counted as made up). Nothing answering is a `ValidationException` that says no rule
  matched, with the request's size and hash: never an invented answer. A document with a field the front does not know is refused.
- **Rules match on** `operation` (`converse`, `converse-stream`, `invoke`, `invoke-stream`, `count-tokens`, `apply-guardrail`; none: every call that
  makes text), the last user message (`textContains`, `textEquals`, `textMatches`), `systemContains`, `toolOffered`, `toolResult` and
  `toolResultContains`/`toolResultMatches` (the follow-up turn of a tool loop), `guardrail`, `guardrailId`, `bodyContains`, and a `jsonPath` with
  `equals`, `matches` or `exists` on the request body. Regular expressions are RE2. The same rule answers Converse and InvokeModel: the front reads
  Converse, Anthropic (messages and the old text API), Nova, Titan, Llama, Mistral, Cohere and plain `prompt` bodies. CountTokens and ApplyGuardrail
  use only rules that name their operation (never the queue or the default); ApplyGuardrail has no model, so its rules go in a set with no model.
- **An answer** is `text`, `toolUse` (`name`, `input`, `toolUseId`), or `content` blocks in Converse's shape, with `stopReason`, `usage` (default: about
  four characters a token, always fake), `latencyMs`, `guardrail` (below), `additionalModelResponseFields`, `delayMs`; for streams `chunkSize` or
  `parts`, `partDelayMs` and `streamError`; `embedding` (`dimensions`: a deterministic vector, Titan and Cohere embedding models); `raw` (a provider body
  written as it is) and `rawChunks` (provider stream chunks written as they are) for a recorded answer or a model family the front has no shape for.
  Shapes: Converse's own; InvokeModel's provider body for `anthropic.` (messages, tool_use blocks; the old completion API when the body has `prompt`),
  `amazon.nova`, `amazon.titan-text`, `meta.`, `mistral.` (outputs, or choices for a chat body), `cohere.` (generations, chat) and a generic
  `{"outputText","stopReason"}` for every other model id. An inference profile id (`us.anthropic...`) or an ARN finds the sets of its base id.
- **Streams** are `application/vnd.amazon.eventstream` (`front/eventstream.go`): ConverseStream writes `messageStart`, `contentBlockStart` (tool use),
  `contentBlockDelta` (text in parts; tool input as partial JSON), `contentBlockStop`, `messageStop`, `metadata` (usage, latency, guardrail trace);
  InvokeModelWithResponseStream writes `chunk` events whose bytes are the provider's chunks (Anthropic's message_start ... message_stop with the
  invocation metrics; Nova's Converse events; the other families' own). A `streamError` ends the stream with an exception event
  (`throttlingException`, `modelStreamErrorException`, `modelTimeoutException`, ...) after `afterParts` pieces.
- **Tool loops**: a rule returns a `toolUse` and a later rule with `toolResult: true` answers the follow-up turn; `tool_use` and `toolResult` blocks
  are read in Converse's and in Anthropic's spelling.
- **Guardrails**: only for a request that carries one (Converse `guardrailConfig`, or the `X-Amzn-Bedrock-Guardrail*` headers of InvokeModel). A
  `guardrail` section (`action` GUARDRAIL_INTERVENED by default or NONE, `blockedMessage`, `assessments` in the API's shape, `phase` input or
  output) makes the call stop with `stopReason: guardrail_intervened` and the blocked message, and, when the request asked for a trace, `trace.guardrail`
  (Converse and its stream) or `amazon-bedrock-trace` and `amazon-bedrock-guardrailAction` (InvokeModel). ApplyGuardrail answers `action`, `outputs`,
  `assessments`, `usage` and `guardrailCoverage` from the same section.
- **Faults** (`POST /_rovara/bedrock/faults`, `GET`, `DELETE`): `{"modelId"|"modelPrefix", "operation", "times", "skip", "error": {"code": "ThrottlingException" |
  "ValidationException" | "ModelTimeoutException" | ...}}` makes the next matching calls fail with the HTTP status Bedrock gives that code and the code in
  `X-Amzn-ErrorType`; `"streamError"` instead ends the next matching stream with an exception event; `delayMs` waits. A rule's answer may be an `error` too.
- **Evidence.** Every answered call is a ledger entry with the marker `faked` (`; made-up answer` for a default, `; unmatched`, `; fault`, `; estimated`
  for a CountTokens with no rule, `; guardrail intervened`). `GET /_rovara/bedrock/summary` returns `faked: true`, `notTested: "real model behaviour; token
  counts are made up"`, the totals and the counters per model id (calls, streamed, tool-use turns, guardrail interventions, matched, made up, unmatched,
  errors, faulted, and the size and hash, never the text, of the newest unmatched requests) and the fixture and fault tables. Prompts and answers are never kept.
  A reset empties the fixtures and the faults; `DELETE /_rovara/ledger` empties the counters.
- **HTTP/2.** The AWS SDK for JavaScript v3 sends every Bedrock runtime call over HTTP/2, also to an `http://` endpoint. The front speaks HTTP/2 with
  prior knowledge (h2c) as well as HTTP/1.1 when it is built with Go 1.24 or newer (the image is; `front/h2c_go124.go`); built with an older Go it
  answers such a client with a protocol error.
- **Limits.** A request body is at most 8 MiB (1 MiB with no Content-Length) and 200,000 JSON values, must arrive within 30 s, and is counted at four
  times its size against a 64 MiB budget: a request that finds the budget used up is answered `ThrottlingException` at once (the SDKs retry). An
  embedding request holds at most 96 texts or images (`ValidationException` beyond), and its answer at most 131,072 numbers (texts times
  `dimensions`). The calls the front passes to the engine (async invoke, the bidirectional stream, `InvokeGuardrailChecks`) are marked
  `emulated by the engine; not a Rovara fixture` in the ledger.
- Not built: `InvokeAgent`, Knowledge Bases `Retrieve`, async invoke and the bidirectional stream (forwarded to the engine), reasoning and image blocks in a
  stream (left out), embeddings for model families other than Titan and Cohere (use `raw`), IAM on these calls (the engine does not enforce it for Bedrock
  runtime and the front does not know the caller: lane BI2 records the permissions used), recording (`rovara record bedrock`), a default answer for a new project.

Proofs: `go test ./...` (in `front/`), `front/tools/bedrock_live.py` (boto3 and, with `--js-sdk`, the AWS SDK for JavaScript v3 against the front and the real
engine: every operation, every family, streams, tool loops, guardrails, faults, the engine's control plane, reset), `front/tools/iam_enforcement_check.py`
(whether the engine enforces IAM policies behind the front's `-a off`: it does, for the keys of IAM users and role sessions, and not for Bedrock runtime).

## Delivery sink (SNS http, https and email), the TLS listener, the DNS control socket

The engine accepts an SNS `http`, `https`, `email` or `email-json` subscription and then does nothing: it never posts, never mails, and its
`ConfirmSubscription` can never succeed. In planned mode with `sns` in the plan, the front owns these four protocols (lanes DS2 and DS3,
design `beyond-emulator-delivery-sink-db-helpers.md`). SQS and Lambda subscriptions stay with the engine.

- **How.** `Subscribe` is forwarded to the engine, then the front attaches a hidden tap (an SQS queue `rovara-sns-tap-<random>` subscribed to
  the topic with the subscription's `FilterPolicy` and scope, and the policy the engine needs), polls it on loopback and delivers from a
  bounded per-subscription queue: HTTP(S) POST in AWS's shape (`x-amz-sns-*` headers, AWS's JSON or the raw message), or an email to the mail
  catcher over SMTP. The front answers `ConfirmSubscription`, `Unsubscribe`, `GetSubscriptionAttributes` and `SetSubscriptionAttributes` for its
  own subscriptions, and rewrites `ListSubscriptions`, `ListSubscriptionsByTopic` and `ListQueues` (a confirmed subscription shows its ARN,
  an unsubscribed one is gone, the taps are not there; a request that names a tap queue is answered as "no such queue"). `SubscribeURL` and
  `UnsubscribeURL` work as links (`GET /?Action=ConfirmSubscription&TopicArn=...&Token=...`). A subscription is `pending` until confirmed
  (messages before that are dropped and counted, as on AWS) unless `ROVARA_AWS_SNS_AUTO_CONFIRM=1`. A subscription made inside the engine (a
  CloudFormation `AWS::SNS::Subscription`, a seeded one) is taken over before the next `Publish`, once a stack call or a seed was seen.
- **Walls (the customer's code is hostile).** The endpoint is judged at `Subscribe` and at every delivery and decides only a Host header and a
  key into the run's route table: a host that is a route key (`localhost`, `127.0.0.1`, a run alias: exact spellings) goes to that route's
  address at the endpoint's port; a host at or under an AWS suffix goes (https only) to the front's own TLS listener; every other name goes to the
  HTTP sink's own port; every IP address that is not a route key, any odd spelling (decimal, octal, hex, short, IPv6, mapped), a trailing dot, a
  fragment, a control character and user-info that is not plain are refused with `InvalidParameter`. The front resolves no name for a delivery
  (nothing to rebind), follows no redirect, uses no proxy, reads an answer for at most 4 KiB, ends an attempt at 15 s, and dials only through
  `sink_net.go` (three dial lines, counted by `scripts/image-check-engine.sh`), which accepts an address only if a route chose it and it is a
  private IPv4 address that is not the front's own. Caps: 64 subscriptions, 100 deliveries held per subscription, 32 MiB held in all, a
  message over 512 KiB dropped (counted), at most 5 retries, compressed timing. The confirmation token is an HMAC under a per-run secret
  (not the control token), bound to its subscription and topic. Signatures are SignatureVersion 2 over AWS's string-to-sign with a per-run RSA
  key; `SigningCertURL` has an AWS-looking host and is not served unless `ROVARA_AWS_SNS_SERVE_SIGNING_CERT=1`; the evidence says "signature
  not verified (faked)". Captures (a ring of 50 attempts per subscription, bodies up to 8 KiB, endpoints with user-info and query values
  masked) are read only through the control paths: `GET /_rovara/sns/subscriptions`, `/_rovara/sns/deliveries?subscription=<arn>` (one at a
  time) and `/_rovara/sns/summary`.
- **Encoded bodies, identity and taps.** An SQS or SNS request body that is `aws-chunked` or gzip is decoded by the front before the tap wall
  reads it (the engine decodes both; any other encoding is refused with 415, a body that is not what it says with 400, one that decodes
  to more than the runner's body cap with 413; the decoder is the function runner's, `front/runner_encoding.go`, switched on for the sink too). What the caller
  asks for (`Subscribe`, `DeleteTopic`, the lists, `GetTopicAttributes`) is forwarded with the caller's own key, session token and region, so the
  engine's authorization applies; what the sink does for itself (the tap) is made as the front, in the topic's region. A tap that is gone
  (its queue deleted, or its subscription removed from the topic: checked every 10 s) is counted (`TapLost`), recorded, shown as `tap lost`
  and rebuilt; what was published in between is not delivered. SNS over JSON or CBOR is refused. An endpoint's password is shown as `****`.
- **Settings** (all checked at start; a bad one stops the front): `ROVARA_AWS_SNS_SINK` (`off` disables), `ROVARA_AWS_SNS_ROUTES`
  (`host=ip,...`, private IPv4 only, never the front's own address), `ROVARA_AWS_SNS_SINK_ADDR` and `ROVARA_AWS_SNS_SINK_PORTS` (`http,https`,
  default `80,443`), `ROVARA_AWS_SNS_SMTP` (`host:port` of the mail catcher; unset: email is kept in the capture only),
  `ROVARA_AWS_SNS_AUTO_CONFIRM`, `ROVARA_AWS_SNS_SERVE_SIGNING_CERT`, `ROVARA_AWS_SNS_RETRY_DELAY_MS`. See `front/sink_config.go`.
- **TLS listener** (`ROVARA_AWS_TLS_ADDR`, `ROVARA_AWS_TLS_ROOT`, `ROVARA_AWS_TLS_LEAVES`): the same API on https for every AWS name the run's DNS
  sends it. It uses only leaves the worker's per-run CA made (root plus one name-constrained intermediate): at start every leaf is verified
  against the root for every name it carries, through a constrained intermediate, DNS names only, every name under an AWS suffix; one that is
  not stops the front. No default and no self-signed certificate; no SNI, an address or an uncovered name fails the handshake; HTTP/1.1 and
  TLS 1.2 or newer only; a `Host` that is not the server name is answered 421. See `front/sink_tls.go`.
- **DNS rules and control socket** (`front/sink_dns.go`, `ROVARA_AWS_DNS_CONTROL_SOCKET`, `ROVARA_AWS_DNS_PERMITTED`, `ROVARA_AWS_DNS_HELPERS`):
  the rule-table semantics and the line protocol the worker's resolver implements are specified in that file, with the conformance vectors in
  `front/testdata/dns-rules-vectors.json`. The front registers only exact AWS-suffix names under the CA's permitted names, pointing only at the
  plan's helper aliases, and unregisters them at reset.
- **Proofs:** `go test ./...` (the hostile-code tests are `TestAttack*`), and `ROVARA_REAL_ENGINE_BIN=<engine> go test -run TestRealEngineSink` against the real engine.

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

## Function runner (slice 4, the front's half)

The engine runs a Lambda function in its own process (RustPython and a JS engine), so it cannot run native wheels, Java, Go, container
images or anything longer than 30 s. With `ROVARA_AWS_RUNNER_SOCKET` set (planned mode only) the front takes such functions over and hands
them to a **runner** that the Cloud worker provides (a gVisor sandbox per function; a later lane). Nothing here starts a process or holds
a container runtime. Design: `designs-2026-10-30/slice4-function-runner-design.md`; the pipe's protocol, `runner/2`, is specified in the
header of `front/runner_proto.go`.

- **Which functions.** The ones `lambda_heavy.go` calls heavy (an ELF file in the package or a layer, a runtime the engine cannot run, an
  image) and, decision 119, any function configured with a Timeout above 28 s. The front keeps the real package in its own bounded store
  (`ROVARA_AWS_RUNNER_STORE_DIR`, required: an absolute directory on a disk, never the helper's small /tmp; `ROVARA_AWS_RUNNER_STORE_MAX_BYTES`, default 256 MiB; the front refuses to start when the file system has less free space than that) and
  the real configuration, and forwards to the engine a request for a **stub** (a 100-line python3.12 function, `runner_stub.go`) under
  the same name, in a hidden role. Every answer a caller gets (Create, Update, Get, GetConfiguration, List, ListVersions, PublishVersion)
  carries the real Runtime, Handler, MemorySize, Timeout, Layers, Role, CodeSize and CodeSha256, and `Code.Location` is a signed,
  expiring link on the front that serves the real package. Native x86-64 and mixed packages go to the worker like any other (it may swap the wheels for arm64 ones or emulate); when it
  refuses (`registered` with `Rovara.Unsupported`) the call answers `Rovara.Unsupported` and the function is recorded as
  `heavy-function:x86-native`. Container images are taken over too and answer `Rovara.Unsupported`; a function whose package does not fit the store stays with the engine and is recorded as unable to run.
  A function moves to the runner when a later change makes it heavy (the front keeps small light packages for that) and stays there.
- **Callers the front never sees** (an SQS, Kinesis or DynamoDB mapping, Step Functions, SNS, EventBridge, S3, async Invoke, API Gateway,
  a function URL) invoke the stub in the engine. The stub puts `{fn, arn, ver, req, reply, event}` on the hidden queue `rovara-heavy-req`
  (an event over 200 KB goes through the hidden bucket `rovara-heavy-payloads`), and long-polls its own reply queue in 2 s slices until
  the engine's deadline less 1.5 s. The front's dispatcher reads the request over loopback, hands it to the runner and writes the reply;
  the stub returns the answer or raises an error of the same `errorType` and message.
- **Direct Invoke fast path.** An Invoke of a held function that reaches the front is answered by the front through the runner: no stub,
  no engine slot, so no 30 s ceiling (the function runs to its own Timeout), Lambda's own 6 MB request and response (not the stub's 1 MiB),
  and up to `ROVARA_AWS_RUNNER_MAX_DIRECT` (64) calls at once (a call over that is a 429 `TooManyRequestsException`). Qualifiers, aliases
  (resolved through the engine), `LogType=Tail`, `DryRun` and `Event` are handled; an `Event` call answers 202 and runs in the
  background, three attempts two seconds apart on an error, as the engine does (destinations and `MaximumRetryAttempts` are not
  emulated there).
- **Hidden plumbing.** The queues, the bucket and the stub's role are refused to customers (403 `AccessDenied`) and left out of
  `ListQueues`, `ListBuckets`, `ListRoles` and `GetAccountAuthorizationDetails`. The guard works on decoded values (a query and a form
  merged as the front merges them, JSON read as JSON, percent- and backslash-escapes undone), looks at every service whose bodies are
  names (Lambda, Step Functions, EventBridge, Scheduler, IAM, STS, SNS, CloudFormation templates inline or fetched, S3 copy sources and
  notification configurations), and refuses a body it cannot read whole or parse exactly (bytes after the document, a duplicate key, a BOM are all read as the engine might). The
  front decodes `aws-chunked` and gzip bodies itself (the engine decodes both for every service) before the guard looks, and refuses any other
  Content-Encoding on a service but S3. A call to an API Gateway endpoint or a function URL (as the front identified it: its reserved `/_aws/` paths, never a Host header), an invoke
  of a function and the other data-plane calls (a published message, a Bedrock or SageMaker invoke, image and blob bytes) are the app's own
  bodies, and are neither decoded nor looked at. A control-plane body is read up to the engine's own 16 MiB limit, within the inspection budget.
  **Known limit: code running in the same engine as the plumbing can reach it.** That code calls every service in-process, past the front, can
  list the hidden names, and can read the stub's code (an API Gateway HTTP integration aimed at the engine's own function-code bucket returns
  the stub's package, secret included). So the stub's HMAC (a per-generation secret; it also covers the digest of an object that goes through
  the payload bucket) and the random 128-bit names (`rovara-heavy-req-<32 hex>`, the same for the bucket, the reply queues and the role) keep out
  only stray, stale and blind references: a message of another generation, a template that builds a name with an intrinsic function. They
  are not a boundary. What the front does about the rest: before every poll it puts the request queue and the bucket back as it made them, and on each tick of a
  sweeper that runs in its own goroutine (never on the path that serves heavy-function requests) it checks the stub role (its policy is read
  as a document; an idle run writes nothing and records nothing) and sweeps what points at the plumbing or leaves it (event source mappings and their
  destinations, event invoke configs, EventBridge targets on every bus, SNS subscriptions, S3 notifications, Scheduler schedules, Pipes, SQS
  redrive policies, Step Functions state machines, API Gateway v2 integrations that name it or read the function-code bucket), every time it is
  found, through every page of every listing, as a queue of small units of work run a tick at a time under a call budget and a time budget (a run
  with many buses and rules is swept over several ticks), and records each as a `security:<kind>` event in the ledger (service `rovara`). Same-run code
  can still disrupt or tamper with its own run's heavy functions (delay or drop a message, answer a request itself); the owner has been asked
  to accept that as a known limit. REST (v1) API Gateway integrations are not swept. The front's own calls to the engine are not requests of its handler, so they are in
  no ledger and count against no plan. `GET /_rovara/lambda/heavy` reports `runner` (`connected`, `disconnected`, `not available`) and,
  per function the runner holds, `runnerFunctions` (direct, viaStub, async, ok, functionErrors, cold, ceilingHits, unsupportedRuns,
  unavailable): the evidence lines read it. A function the runner runs is not recorded as unable to run.
- **The pipe.** One peer at a time (a second connection is turned away; the peer's uid, from SO_PEERCRED, must be the front's or root's);
  the socket path must be absolute and the front makes its directory private. The worker runs `docker exec -i <helper> /usr/local/bin/rovara-aws-front runner-pipe` (the socket comes from
  `ROVARA_AWS_RUNNER_SOCKET`, mode 0600, so only whoever can `docker exec` can speak to the front: no port, no token). The front
  registers a function version on the connection when it first needs it (the packages go over in 512 KiB chunks, only the ones the worker
  lacks), sends `invoke` frames, and a reset (`POST /_rovara/reset`) is a barrier: runs in flight are cancelled and awaited, the worker confirms
  `stop_all`, and nothing that read the registry before the reset can register or invoke after it.
- **Limits** (each is stated in evidence rather than hidden): through the stub a call is cut at 28 s (`Rovara.TimeoutCeiling`: "ran past
  28 s, the local engine's limit; AWS allows N s. Not tested locally"), at 10 s under Step Functions (the engine's own cap on a Lambda
  task, which the stub cannot see), an event over 1 MiB is `Rovara.Unsupported` (the engine's guest SDK carries 1 MiB a call), and about
  16 stubs run at once (the engine's memory pool; more queue). A function the engine creates itself (a CloudFormation template) is not
  taken over, because the front never holds its code: it is recorded as heavy and cannot run. The engine checks the stub's role, not
  the function's, when a mapping is created (so a missing queue or stream permission on the function's own role goes unnoticed, and the
  queue's visibility timeout is checked against the stub's Timeout, which is the function's plus 5 s). Results pass through the engine's
  JSON writer, so a response is equal in value but not byte for byte (`{"a": 1}`). The engine writes no CloudWatch logs for Lambda; the
  runner's log is returned with `LogType=Tail` and printed by the stub.
- **Proofs.** `go test ./...` (fake worker; `ROVARA_REAL_ENGINE_BIN=<aws-emulator> go test -run RunnerWithRealEngine` adds the real
  engine), and `front/tools/runner_check.py --front-bin <rovara-aws-front> --engine-bin <aws-emulator>` (the real engine, boto3, an echo
  runner behind `runner-pipe`: every kind of caller, errors, big payloads, ceilings, concurrency, hidden plumbing, reset).

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
