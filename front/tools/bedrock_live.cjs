// The AWS SDK for JavaScript v3 half of bedrock_live.py: the SDK's own parsers read every answer of the Bedrock runtime shim.
// Started by bedrock_live.py (BEDROCK_BASE, ROVARA_TOKEN and NODE_PATH are set), never by hand. Node 20 or later.
const {
  BedrockRuntimeClient, ConverseCommand, ConverseStreamCommand, InvokeModelCommand, InvokeModelWithResponseStreamCommand,
  CountTokensCommand, ApplyGuardrailCommand,
} = require("@aws-sdk/client-bedrock-runtime");

const base = process.env.BEDROCK_BASE;
const token = process.env.ROVARA_TOKEN;
let failed = 0;
const check = (name, ok, detail) => {
  console.log((ok ? "PASS " : "FAIL ") + "js: " + name + (!ok && detail !== undefined ? " :: " + JSON.stringify(detail).slice(0, 400) : ""));
  if (!ok) failed++;
};
const put = async (name, doc) => {
  const r = await fetch(`${base}/_rovara/bedrock/fixtures/${name}`, { method: "PUT", headers: { "X-Rovara-Control-Token": token }, body: JSON.stringify(doc) });
  if (r.status !== 200) throw new Error("fixtures " + name + ": " + r.status + " " + (await r.text()));
};
const post = async (path, doc) => {
  const r = await fetch(`${base}/_rovara/bedrock${path}`, { method: "POST", headers: { "X-Rovara-Control-Token": token }, body: JSON.stringify(doc) });
  if (r.status !== 200) throw new Error(path + ": " + r.status);
};
const client = new BedrockRuntimeClient({ region: "us-east-1", endpoint: base, credentials: { accessKeyId: "AKIAEXAMPLE", secretAccessKey: "secret" }, maxAttempts: 1 });
const user = (text) => ({ role: "user", content: [{ text }] });
const CLAUDE = "anthropic.claude-3-5-sonnet-20241022-v2:0";
const enc = new TextEncoder(), dec = new TextDecoder();
const attempt = async (f) => { try { await f(); return null; } catch (e) { return e; } };

(async () => {
  await put("js", {
    modelPrefix: "anthropic.", rules: [
      { match: { toolResult: true }, response: { text: "Sunny, 22 degrees." } },
      { match: { textContains: "weather" }, response: { text: "Checking.", toolUse: { name: "get_weather", toolUseId: "tooluse_js_1", input: { city: "Oslo" } }, chunkSize: 8 } },
      { match: { textContains: "secret", guardrail: true }, response: { guardrail: { blockedMessage: "Blocked (js).", assessments: { wordPolicy: { customWords: [{ match: "secret", action: "BLOCKED" }] } } } } },
    ], default: { text: "Canned answer for the JavaScript SDK, in several parts.", chunkSize: 10 },
  });

  // ApplyGuardrail names no model: its rule lives in a set with no modelId and no modelPrefix
  await put("js-guard", { rules: [{ match: { operation: "apply-guardrail", textContains: "secret" }, response: { guardrail: { blockedMessage: "Blocked (js)." } } }] });

  let r = await client.send(new ConverseCommand({ modelId: CLAUDE, messages: [user("hello")] }));
  check("Converse text", r.output.message.content[0].text.startsWith("Canned answer") && r.stopReason === "end_turn" && r.usage.totalTokens > 0 && r.metrics.latencyMs >= 1, r);

  const tools = { tools: [{ toolSpec: { name: "get_weather", inputSchema: { json: { type: "object" } } } }] };
  r = await client.send(new ConverseCommand({ modelId: CLAUDE, messages: [user("weather in Oslo?")], toolConfig: tools }));
  const tu = r.output.message.content[1].toolUse;
  check("Converse tool use turn (the SDK reads the document input)", r.stopReason === "tool_use" && tu.name === "get_weather" && tu.input.city === "Oslo", r);
  r = await client.send(new ConverseCommand({ modelId: CLAUDE, toolConfig: tools, messages: [user("weather in Oslo?"), r.output.message,
    { role: "user", content: [{ toolResult: { toolUseId: tu.toolUseId, content: [{ json: { temp: 22 } }] } }] }] }));
  check("Converse follow-up with the toolResult", r.output.message.content[0].text === "Sunny, 22 degrees.", r);

  r = await client.send(new ConverseStreamCommand({ modelId: CLAUDE, messages: [user("hello")] }));
  const kinds = []; let text = "", usage;
  for await (const ev of r.stream) {
    kinds.push(Object.keys(ev)[0]);
    if (ev.contentBlockDelta) text += ev.contentBlockDelta.delta.text;
    if (ev.metadata) usage = ev.metadata.usage;
  }
  check("ConverseStream events and metadata", kinds[0] === "messageStart" && kinds.at(-1) === "metadata" && text.startsWith("Canned answer for the JavaScript SDK") && usage.outputTokens > 0, kinds);

  r = await client.send(new ConverseStreamCommand({ modelId: CLAUDE, toolConfig: tools, messages: [user("weather in Oslo?")] }));
  let partial = "", name = "";
  for await (const ev of r.stream) {
    if (ev.contentBlockStart) name = ev.contentBlockStart.start.toolUse.name;
    if (ev.contentBlockDelta && ev.contentBlockDelta.delta.toolUse) partial += ev.contentBlockDelta.delta.toolUse.input;
  }
  check("ConverseStream tool input as partial JSON", name === "get_weather" && JSON.parse(partial).city === "Oslo", partial);

  r = await client.send(new InvokeModelCommand({ modelId: CLAUDE, contentType: "application/json", accept: "application/json",
    body: JSON.stringify({ anthropic_version: "bedrock-2023-05-31", max_tokens: 50, messages: [{ role: "user", content: [{ type: "text", text: "hello" }] }] }) }));
  let d = JSON.parse(dec.decode(r.body));
  check("InvokeModel anthropic body", d.type === "message" && d.content[0].text.startsWith("Canned answer") && r.contentType === "application/json", d);

  r = await client.send(new InvokeModelWithResponseStreamCommand({ modelId: CLAUDE, contentType: "application/json",
    body: JSON.stringify({ anthropic_version: "bedrock-2023-05-31", max_tokens: 50, messages: [{ role: "user", content: [{ type: "text", text: "hello" }] }] }) }));
  const types = []; text = "";
  for await (const ev of r.body) {
    const c = JSON.parse(dec.decode(ev.chunk.bytes));
    types.push(c.type);
    if (c.type === "content_block_delta") text += c.delta.text;
  }
  check("InvokeModelWithResponseStream chunks", types[0] === "message_start" && types.at(-1) === "message_stop" && text.startsWith("Canned answer for the JavaScript SDK"), types);

  r = await client.send(new CountTokensCommand({ modelId: CLAUDE, input: { converse: { messages: [user("twelve chars")] } } }));
  check("CountTokens", r.inputTokens === 3, r);

  r = await client.send(new ConverseCommand({ modelId: CLAUDE, messages: [user("a secret")], guardrailConfig: { guardrailIdentifier: "gr-js", guardrailVersion: "1", trace: "enabled" } }));
  check("Converse guardrail intervention with trace", r.stopReason === "guardrail_intervened" && r.trace.guardrail.inputAssessment["gr-js"].wordPolicy.customWords[0].action === "BLOCKED", r);
  r = await client.send(new ApplyGuardrailCommand({ guardrailIdentifier: "gr-js", guardrailVersion: "DRAFT", source: "INPUT", content: [{ text: { text: "a secret" } }] }));
  check("ApplyGuardrail", r.action === "GUARDRAIL_INTERVENED" && r.outputs[0].text === "Blocked (js).", r);

  await post("/faults", { modelPrefix: "anthropic.", operation: "converse", error: { code: "ThrottlingException" } });
  let e = await attempt(() => client.send(new ConverseCommand({ modelId: CLAUDE, messages: [user("hello")] })));
  check("a throttling fault is ThrottlingException with HTTP 429", e && e.name === "ThrottlingException" && e.$metadata.httpStatusCode === 429, e && [e.name, e.$metadata]);
  await post("/faults", { modelPrefix: "anthropic.", operation: "converse-stream", streamError: { code: "throttlingException", afterParts: 1 } });
  r = await client.send(new ConverseStreamCommand({ modelId: CLAUDE, messages: [user("hello")] }));
  const got = [];
  e = await attempt(async () => { for await (const ev of r.stream) got.push(Object.keys(ev)[0]); });
  check("an exception event in the middle of a stream raises in the SDK", e && e.name === "ThrottlingException" && got.join() === "messageStart,contentBlockDelta", [got, e && e.name]);

  console.log(failed ? `\n${failed} JavaScript check(s) failed` : "\nall JavaScript checks passed");
  process.exit(failed ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(2); });
