package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"
)

// ---- fixtures: parsing, matching, choosing

func mustSet(t *testing.T, doc string) *bdSet {
	t.Helper()
	s, err := parseSet([]byte(doc))
	if err != nil {
		t.Fatalf("parseSet: %v\n%s", err, doc)
	}
	return s
}

func TestBedrockFixtureValidation(t *testing.T) {
	for name, doc := range map[string]string{
		"a typo in a field":              `{"rulez":[]}`,
		"id and prefix":                  `{"modelId":"a.b","modelPrefix":"a."}`,
		"an unknown source":              `{"source":"guessed"}`,
		"an empty answer":                `{"default":{}}`,
		"text and raw":                   `{"default":{"text":"a","raw":{}}}`,
		"parts and text":                 `{"default":{"text":"a","parts":["b"]}}`,
		"tool use without a name":        `{"default":{"toolUse":{"input":{}}}}`,
		"a stop reason Converse has not": `{"default":{"text":"a","stopReason":"done"}}`,
		"bad error code":                 `{"default":{"error":{"code":"Teapot"}}}`,
		"bad stream error code":          `{"default":{"text":"a","streamError":{"code":"Nope"}}}`,
		"negative after parts":           `{"default":{"text":"a","streamError":{"afterParts":-1}}}`,
		"jsonPath without value":         `{"rules":[{"match":{"equals":1},"response":{"text":"a"}}]}`,
		"bad jsonPath":                   `{"rules":[{"match":{"jsonPath":"a.b"},"response":{"text":"a"}}]}`,
		"bad regex":                      `{"rules":[{"match":{"textMatches":"("},"response":{"text":"a"}}]}`,
		"unknown operation":              `{"rules":[{"match":{"operation":"batch"},"response":{"text":"a"}}]}`,
		"negative times":                 `{"rules":[{"match":{},"response":{"text":"a"},"times":-1}]}`,
		"delay out of range":             `{"default":{"text":"a","delayMs":999999}}`,
		"a second value":                 `{} {}`,
		"guardrail action":               `{"default":{"guardrail":{"action":"MAYBE"}}}`,
		"guardrail assessments":          `{"default":{"guardrail":{"assessments":5}}}`,
		"embedding without dims":         `{"default":{"embedding":{"dimensions":0}}}`,
		"content that is no object":      `{"default":{"content":["x"]}}`,
		"a bad name":                     `{"name":"a b"}`,
	} {
		if _, err := parseSet([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if s := mustSet(t, `{}`); s.Source != "handwritten" {
		t.Errorf("defaults: %+v", s)
	}
	for name, doc := range map[string]string{
		"nothing to do":    `{"modelId":"a.b"}`,
		"both kinds":       `{"error":{"code":"ThrottlingException"},"streamError":{}}`,
		"bad op":           `{"operation":"x","error":{"code":"ThrottlingException"}}`,
		"id and prefix":    `{"modelId":"a","modelPrefix":"b","delayMs":5}`,
		"a typo":           `{"errror":{"code":"ThrottlingException"}}`,
		"bad error":        `{"error":{"code":"Teapot"}}`,
		"too long a delay": `{"delayMs":600000}`,
	} {
		if _, err := parseFault([]byte(doc)); err == nil {
			t.Errorf("fault %s: accepted", name)
		}
	}
}

func TestBedrockModelIDs(t *testing.T) {
	for in, want := range map[string]string{
		"anthropic.claude-3-5-sonnet-20241022-v2:0":                                                   "anthropic.claude-3-5-sonnet-20241022-v2:0",
		"us.anthropic.claude-3-5-sonnet-20241022-v2:0":                                                "anthropic.claude-3-5-sonnet-20241022-v2:0",
		"eu.amazon.nova-pro-v1:0":                                                                     "amazon.nova-pro-v1:0",
		"global.anthropic.claude-sonnet-4-20250514-v1:0":                                              "anthropic.claude-sonnet-4-20250514-v1:0",
		"arn:aws:bedrock:us-east-1:123456789012:inference-profile/us.meta.llama3-1-70b-instruct-v1:0": "meta.llama3-1-70b-instruct-v1:0",
		"arn:aws:bedrock:us-east-1::foundation-model/amazon.titan-text-express-v1":                    "amazon.titan-text-express-v1",
		"us.nova":                          "us.nova",
		"mistral.mistral-7b-instruct-v0:2": "mistral.mistral-7b-instruct-v0:2",
	} {
		if got := bdBaseID(in); got != want {
			t.Errorf("bdBaseID(%q) = %q, want %q", in, got, want)
		}
	}
	for id, want := range map[string]string{
		"anthropic.claude-3-haiku-20240307-v1:0": "anthropic", "amazon.nova-lite-v1:0": "nova", "amazon.titan-text-lite-v1": "titan",
		"amazon.titan-embed-text-v2:0": "titan-embed", "meta.llama3-8b-instruct-v1:0": "llama", "mistral.mistral-large-2402-v1:0": "mistral",
		"cohere.command-r-v1:0": "cohere-text", "cohere.embed-english-v3": "cohere-embed", "ai21.jamba-1-5-large-v1:0": "generic",
	} {
		if got := bdFamily(id, map[string]any{}); got != want {
			t.Errorf("family of %s = %s, want %s", id, got, want)
		}
	}
	if bdFamily("anthropic.claude-v2", map[string]any{"prompt": "x"}) != "anthropic-text" || bdFamily("cohere.command-r-v1:0", map[string]any{"message": "x"}) != "cohere-chat" {
		t.Error("the body tells the old completion API and the chat API")
	}
}

func TestBedrockSetSpecificityAndOrder(t *testing.T) {
	sets := map[string]*bdSet{
		"any":    mustSet(t, `{"name":"any","default":{"text":"any"}}`),
		"anth":   mustSet(t, `{"name":"anth","modelPrefix":"anthropic.","default":{"text":"anth"}}`),
		"claude": mustSet(t, `{"name":"claude","modelPrefix":"anthropic.claude","default":{"text":"claude"}}`),
		"exact":  mustSet(t, `{"name":"exact","modelId":"anthropic.claude-3-haiku-20240307-v1:0","default":{"text":"exact"}}`),
	}
	names := func(id string) string {
		var out []string
		for _, s := range bdSetsFor(sets, id, bdBaseID(id)) {
			out = append(out, s.Name)
		}
		return strings.Join(out, ",")
	}
	if g := names("anthropic.claude-3-haiku-20240307-v1:0"); g != "exact,claude,anth,any" {
		t.Errorf("exact, longest prefix, shorter prefix, any: %s", g)
	}
	if g := names("us.anthropic.claude-3-haiku-20240307-v1:0"); g != "exact,claude,anth,any" {
		t.Errorf("an inference profile finds the sets of its base id: %s", g)
	}
	if g := names("meta.llama3-8b-instruct-v1:0"); g != "any" {
		t.Errorf("another provider: %s", g)
	}
}

func TestBedrockMatching(t *testing.T) {
	read := func(body string) *bdReq {
		q := &bdReq{op: bdOpConverse, body: []byte(body)}
		q.doc, q.docOK = bdDecode(q.body)
		q.readConversation(q.doc)
		return q
	}
	q := read(`{"system":[{"text":"You are terse."}],"messages":[
	  {"role":"user","content":[{"text":"first question"}]},
	  {"role":"assistant","content":[{"toolUse":{"toolUseId":"t1","name":"get_weather","input":{"city":"Paris"}}}]},
	  {"role":"user","content":[{"toolResult":{"toolUseId":"t1","content":[{"json":{"temp":22}},{"text":"sunny"}]}}]}],
	  "toolConfig":{"tools":[{"toolSpec":{"name":"get_weather"}},{"toolSpec":{"name":"get_time"}}]}}`)
	if q.text != "" || !q.toolResult || !strings.Contains(q.toolResultText, `"temp":22`) || !strings.Contains(q.toolResultText, "sunny") ||
		q.system != "You are terse." || strings.Join(q.tools, ",") != "get_weather,get_time" {
		t.Errorf("a follow-up turn of a tool loop is read: %+v", q)
	}
	yes, no := true, false
	_ = no
	m := func(doc string) bool {
		t.Helper()
		var mt bdMatch
		if err := bdStrict([]byte(doc), &mt); err != nil {
			t.Fatal(err)
		}
		if err := mt.validate(); err != nil {
			t.Fatal(err)
		}
		return mt.matches(q)
	}
	for doc, want := range map[string]bool{
		`{"toolResult":true,"toolResultContains":"sunny"}`:                       true,
		`{"toolResult":false}`:                                                   false,
		`{"toolOffered":"get_time"}`:                                             true,
		`{"toolOffered":"get_stock"}`:                                            false,
		`{"toolResultMatches":"temp\":\\s*2\\d"}`:                                true,
		`{"systemContains":"terse"}`:                                             true,
		`{"textContains":"first"}`:                                               false, // the last user message holds only the result
		`{"operation":"converse","guardrail":false}`:                             true,
		`{"operation":"invoke"}`:                                                 false,
		`{"jsonPath":"$.messages[0].content[0].text","equals":"first question"}`: true,
		`{"jsonPath":"$.messages[1].role","matches":"^assis"}`:                   true,
		`{"jsonPath":"$.inferenceConfig","exists":false}`:                        true,
		`{"bodyContains":"get_weather"}`:                                         true,
	} {
		if m(doc) != want {
			t.Errorf("%s: matches=%v, want %v", doc, !want, want)
		}
	}
	_ = yes
	// Anthropic's spelling of the same loop, and the prompt families
	a := read(`{"anthropic_version":"bedrock-2023-05-31","system":"be brief","messages":[{"role":"user","content":[{"type":"text","text":"weather?"}]},
	  {"role":"assistant","content":[{"type":"tool_use","id":"x","name":"w","input":{}}]},
	  {"role":"user","content":[{"type":"tool_result","tool_use_id":"x","content":[{"type":"text","text":"cold"}]}]}],"tools":[{"name":"w"}]}`)
	if !a.toolResult || a.toolResultText != "cold" || a.system != "be brief" || len(a.tools) != 1 || a.tools[0] != "w" {
		t.Errorf("anthropic spelling: %+v", a)
	}
	s := read(`{"messages":[{"role":"user","content":"plain string"}]}`)
	p := read(`{"prompt":"a prompt","max_gen_len":10}`)
	c := read(`{"message":"chat message","chat_history":[]}`)
	ti := read(`{"inputText":"titan text"}`)
	if s.text != "plain string" || p.text != "a prompt" || c.text != "chat message" || ti.text != "titan text" {
		t.Errorf("text of the families: %q %q %q %q", s.text, p.text, c.text, ti.text)
	}
}

func TestBedrockPickRulesQueueDefault(t *testing.T) {
	// the same choice the route makes, on the set directly: rules in order and used up by `times`, then the queue, then the default
	set := mustSet(t, `{"rules":[
	  {"match":{"textContains":"alpha"},"response":{"text":"A"},"times":1},
	  {"match":{"textMatches":"^b"},"response":{"text":"B"}}],
	 "queue":[{"text":"q1"},{"text":"q2"}],"default":{"text":"dflt"}}`)
	q := func(text string) *bdReq { return &bdReq{op: bdOpConverse, text: text} }
	pick := func(r *bdReq) string {
		for _, rule := range set.Rules {
			if bdRuleApplies(rule, r) && rule.Match.matches(r) && rule.claim() {
				return *rule.Response.Text + ":1"
			}
		}
		resp, k := set.queueOrDefault()
		if resp == nil {
			return "none"
		}
		return *resp.Text + ":" + fmt.Sprint(int(k))
	}
	got := []string{pick(q("alpha")), pick(q("alpha")), pick(q("beta")), pick(q("zzz")), pick(q("zzz"))}
	if strings.Join(got, " ") != "A:1 q1:2 B:1 q2:2 dflt:3" {
		t.Errorf("%v", got)
	}
}

// ---- the route

type bdFront struct{ *lamFront }

func startBD(t *testing.T, planned ...string) *bdFront {
	t.Helper()
	if len(planned) == 0 {
		planned = []string{"bedrock-runtime", "bedrock"}
	}
	return &bdFront{startLambdaFront(t, planned...)}
}

func (f *bdFront) control(method, path, body string) result {
	return f.do(method, "/_rovara/bedrock"+path, tok(), body)
}

func (f *bdFront) fixtures(name, doc string) {
	f.t.Helper()
	if r := f.control("PUT", "/fixtures/"+name, doc); r.status != 200 {
		f.t.Fatalf("PUT fixtures: %d %s", r.status, r.body)
	}
}

func (f *bdFront) fault(doc string) {
	f.t.Helper()
	if r := f.control("POST", "/faults", doc); r.status != 200 {
		f.t.Fatalf("POST faults: %d %s", r.status, r.body)
	}
}

func (f *bdFront) call(op, model string, headers map[string]string, body string) result {
	path := "/model/" + url.PathEscape(model) + "/" + op
	return f.do("POST", path, merge(scopeHdr("bedrock"), merge(map[string]string{"Content-Type": "application/json"}, headers)), body)
}

func (f *bdFront) lastEntry(op string) map[string]any {
	f.t.Helper()
	r := f.do("GET", "/_rovara/ledger?service=bedrock-runtime", tok(), "")
	var doc struct{ Entries []map[string]any }
	json.Unmarshal([]byte(r.body), &doc)
	for i := len(doc.Entries) - 1; i >= 0; i-- {
		if doc.Entries[i]["operation"] == op {
			return doc.Entries[i]
		}
	}
	f.t.Fatalf("no ledger entry for %s in %s", op, r.body)
	return nil
}

func (f *bdFront) summary() map[string]any {
	f.t.Helper()
	r := f.control("GET", "/summary", "")
	if r.status != 200 {
		f.t.Fatalf("summary: %d %s", r.status, r.body)
	}
	var m map[string]any
	json.Unmarshal([]byte(r.body), &m)
	return m
}

func jsonOf(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, s)
	}
	return m
}

func dig(v any, path ...any) any {
	for _, p := range path {
		switch k := p.(type) {
		case string:
			m, _ := v.(map[string]any)
			v = m[k]
		case int:
			a, _ := v.([]any)
			if k >= len(a) {
				return nil
			}
			v = a[k]
		}
	}
	return v
}

// streamEvents decodes a response body of events: the event type and the JSON payload of each.
func streamEvents(t *testing.T, r result) (types []string, docs []map[string]any, headers []map[string]any) {
	t.Helper()
	msgs, err := decodeEventStream([]byte(r.body))
	if err != nil {
		t.Fatalf("the stream is not valid framing: %v", err)
	}
	for _, m := range msgs {
		ty, _ := m.headers[":event-type"].(string)
		if ty == "" {
			ty, _ = m.headers[":exception-type"].(string)
		}
		types = append(types, ty)
		var d map[string]any
		json.Unmarshal(m.payload, &d)
		docs = append(docs, d)
		headers = append(headers, m.headers)
	}
	return
}

const converseHello = `{"messages":[{"role":"user","content":[{"text":"hello there"}]}]}`

func TestBedrockConverseCannedAnswers(t *testing.T) {
	f := startBD(t)
	f.fixtures("claude", `{"modelPrefix":"anthropic.","rules":[
	  {"match":{"textContains":"hello"},"response":{"text":"Hi! (canned)"}},
	  {"match":{"textMatches":"(?i)weather in (\\w+)"},"response":{"text":"Let me check.","toolUse":{"name":"get_weather","input":{"city":"Paris"}}}},
	  {"match":{"toolResult":true,"toolResultContains":"22"},"response":{"text":"It is 22 degrees."}}],
	  "default":{"text":"default answer"}}`)
	r := f.call("converse", "anthropic.claude-3-5-sonnet-20241022-v2:0", nil, converseHello)
	if r.status != 200 || !strings.HasPrefix(r.header.Get("Content-Type"), "application/json") {
		t.Fatalf("converse: %d %s", r.status, r.body)
	}
	d := jsonOf(t, r.body)
	if dig(d, "output", "message", "role") != "assistant" || dig(d, "output", "message", "content", 0, "text") != "Hi! (canned)" || d["stopReason"] != "end_turn" {
		t.Errorf("text answer: %s", r.body)
	}
	if in, out, tot := dig(d, "usage", "inputTokens").(float64), dig(d, "usage", "outputTokens").(float64), dig(d, "usage", "totalTokens").(float64); in != 3 || out != 3 || tot != 6 {
		t.Errorf("made-up tokens are about four characters each (11 and 12 characters): %v %v %v", in, out, tot)
	}
	if dig(d, "metrics", "latencyMs").(float64) < 1 {
		t.Errorf("latency: %s", r.body)
	}
	e := f.lastEntry("Converse")
	if e["marker"] != "faked" || e["status"].(float64) != 200 || e["service"] != "bedrock-runtime" {
		t.Errorf("the ledger says faked: %v", e)
	}

	// an inference profile id finds the same set; a tool use turn, then the follow-up with the tool result
	r = f.call("converse", "us.anthropic.claude-3-5-sonnet-20241022-v2:0", nil,
		`{"messages":[{"role":"user","content":[{"text":"What is the weather in Paris?"}]}],"toolConfig":{"tools":[{"toolSpec":{"name":"get_weather","inputSchema":{"json":{}}}}]}}`)
	d = jsonOf(t, r.body)
	tu := dig(d, "output", "message", "content", 1, "toolUse")
	if d["stopReason"] != "tool_use" || dig(tu, "name") != "get_weather" || dig(tu, "input", "city") != "Paris" || !strings.HasPrefix(dig(tu, "toolUseId").(string), "tooluse_") {
		t.Errorf("tool use turn: %s", r.body)
	}
	id := dig(tu, "toolUseId").(string)
	r = f.call("converse", "anthropic.claude-3-5-sonnet-20241022-v2:0", nil, `{"messages":[
	  {"role":"user","content":[{"text":"What is the weather in Paris?"}]},
	  {"role":"assistant","content":[{"toolUse":{"toolUseId":"`+id+`","name":"get_weather","input":{"city":"Paris"}}}]},
	  {"role":"user","content":[{"toolResult":{"toolUseId":"`+id+`","content":[{"json":{"temp":22}}]}}]}]}`)
	d = jsonOf(t, r.body)
	if dig(d, "output", "message", "content", 0, "text") != "It is 22 degrees." || d["stopReason"] != "end_turn" {
		t.Errorf("follow-up turn: %s", r.body)
	}
	// the default, counted as made up
	r = f.call("converse", "anthropic.claude-3-haiku-20240307-v1:0", nil, `{"messages":[{"role":"user","content":[{"text":"zzz"}]}]}`)
	if dig(jsonOf(t, r.body), "output", "message", "content", 0, "text") != "default answer" || f.lastEntry("Converse")["marker"] != "faked; made-up answer" {
		t.Errorf("default: %s %v", r.body, f.lastEntry("Converse"))
	}
	// no set for the provider: fails by default, with the hash, never an invented answer
	r = f.call("converse", "meta.llama3-8b-instruct-v1:0", nil, converseHello)
	code, body := errBody(t, r)
	if r.status != 400 || code != "ValidationException" || !strings.Contains(fmt.Sprint(body["message"]), "no recorded or canned answer matches") ||
		!strings.Contains(fmt.Sprint(body["message"]), "meta.llama3-8b-instruct-v1:0") || f.lastEntry("Converse")["marker"] != "faked; unmatched" {
		t.Errorf("unmatched: %d %s %v", r.status, r.body, f.lastEntry("Converse"))
	}
	sum := f.summary()
	totals := sum["totals"].(map[string]any)
	if totals["calls"].(float64) != 5 || totals["toolUseTurns"].(float64) != 1 || totals["unmatched"].(float64) != 1 || totals["madeUp"].(float64) != 1 || totals["matched"].(float64) != 3 ||
		sum["faked"] != true {
		t.Errorf("summary: %s", f.control("GET", "/summary", "").body)
	}
	if strings.Contains(f.control("GET", "/summary", "").body, "hello there") {
		t.Error("the summary never holds a prompt")
	}
}

func TestBedrockConverseValidation(t *testing.T) {
	f := startBD(t)
	f.fixtures("any", `{"default":{"text":"ok"}}`)
	for name, body := range map[string]string{
		"no messages":     `{}`,
		"empty messages":  `{"messages":[]}`,
		"assistant first": `{"messages":[{"role":"assistant","content":[{"text":"x"}]}]}`,
		"no alternation":  `{"messages":[{"role":"user","content":[{"text":"x"}]},{"role":"user","content":[{"text":"y"}]}]}`,
		"empty content":   `{"messages":[{"role":"user","content":[]}]}`,
		"a bad role":      `{"messages":[{"role":"system","content":[{"text":"x"}]}]}`,
		"not JSON":        `hello`,
	} {
		r := f.call("converse", "anthropic.claude-3-haiku-20240307-v1:0", nil, body)
		if code, _ := errBody(t, r); r.status != 400 || code != "ValidationException" {
			t.Errorf("%s: %d %s", name, r.status, r.body)
		}
	}
	if r := f.call("converse", "bad model id", nil, converseHello); r.status == 200 {
		t.Errorf("a model id with a space: %d", r.status)
	}
}

func TestBedrockConverseStream(t *testing.T) {
	f := startBD(t)
	f.fixtures("m", `{"default":{"text":"streaming answer of some length","chunkSize":8}}`)
	r := f.call("converse-stream", "amazon.nova-pro-v1:0", nil, converseHello)
	if r.status != 200 || r.header.Get("Content-Type") != "application/vnd.amazon.eventstream" {
		t.Fatalf("stream: %d %s %v", r.status, r.header.Get("Content-Type"), r.header)
	}
	types, docs, hs := streamEvents(t, r)
	want := []string{"messageStart", "contentBlockDelta", "contentBlockDelta", "contentBlockDelta", "contentBlockDelta", "contentBlockStop", "messageStop", "metadata"}
	if strings.Join(types, " ") != strings.Join(want, " ") {
		t.Fatalf("events: %v", types)
	}
	var text strings.Builder
	for i, ty := range types {
		if ty == "contentBlockDelta" {
			text.WriteString(dig(docs[i], "delta", "text").(string))
		}
		if hs[i][":message-type"] != "event" || hs[i][":content-type"] != "application/json" {
			t.Errorf("event headers: %v", hs[i])
		}
	}
	if text.String() != "streaming answer of some length" || docs[0]["role"] != "assistant" || docs[6]["stopReason"] != "end_turn" ||
		dig(docs[7], "usage", "outputTokens").(float64) < 1 || dig(docs[7], "metrics", "latencyMs") == nil {
		t.Errorf("events: %v", docs)
	}
	if f.lastEntry("ConverseStream")["marker"] != "faked; made-up answer" {
		t.Errorf("marker: %v", f.lastEntry("ConverseStream"))
	}

	// a tool use streams as a start event and partial JSON
	f.fixtures("m", `{"default":{"text":"x","toolUse":{"name":"lookup","toolUseId":"tu_1","input":{"query":"a long enough query string"}},"chunkSize":10}}`)
	r = f.call("converse-stream", "anthropic.claude-3-haiku-20240307-v1:0", nil, converseHello)
	types, docs, _ = streamEvents(t, r)
	var partial strings.Builder
	var start map[string]any
	for i, ty := range types {
		if ty == "contentBlockStart" {
			start = docs[i]
		}
		if ty == "contentBlockDelta" {
			if in, ok := dig(docs[i], "delta", "toolUse", "input").(string); ok {
				partial.WriteString(in)
			}
		}
	}
	if dig(start, "start", "toolUse", "toolUseId") != "tu_1" || dig(start, "start", "toolUse", "name") != "lookup" || dig(start, "contentBlockIndex").(float64) != 1 ||
		jsonOf(t, partial.String())["query"] != "a long enough query string" || docs[len(docs)-2]["stopReason"] != "tool_use" {
		t.Errorf("tool use stream: %v partial=%q", types, partial.String())
	}
	if sum := f.summary()["totals"].(map[string]any); sum["streamed"].(float64) != 2 {
		t.Errorf("streamed: %v", sum)
	}
}

func TestBedrockStreamFaults(t *testing.T) {
	f := startBD(t)
	f.fixtures("m", `{"default":{"text":"abcdefghijklmnopqrstuvwxyz","chunkSize":5,"streamError":{"code":"throttlingException","afterParts":2}}}`)
	r := f.call("converse-stream", "anthropic.claude-3-haiku-20240307-v1:0", nil, converseHello)
	types, docs, hs := streamEvents(t, r)
	if strings.Join(types, " ") != "messageStart contentBlockDelta contentBlockDelta throttlingException" || hs[3][":message-type"] != "exception" ||
		docs[3]["message"] != "Too many requests, please wait before trying again." {
		t.Errorf("a stream that ends in an exception after two parts: %v %v", types, docs[len(docs)-1])
	}
	// the default is after all the parts, before the closing events; a model stream error carries the original status
	f.fixtures("m", `{"default":{"text":"abcdefghij","chunkSize":5,"streamError":{"originalStatusCode":503,"originalMessage":"upstream"}}}`)
	types, docs, _ = streamEvents(t, f.call("converse-stream", "x.y", nil, converseHello))
	if strings.Join(types, " ") != "messageStart contentBlockDelta contentBlockDelta modelStreamErrorException" || docs[3]["originalStatusCode"].(float64) != 503 {
		t.Errorf("default after all parts: %v %v", types, docs)
	}
	// armed faults: before the first byte it is an HTTP error with the code in the header; skip lets calls through; times counts down
	f.fixtures("m", `{"default":{"text":"fine"}}`)
	f.fault(`{"modelPrefix":"anthropic.","operation":"converse","error":{"code":"ThrottlingException"},"skip":1,"times":2}`)
	ok := func() int {
		return f.call("converse", "anthropic.claude-3-haiku-20240307-v1:0", nil, converseHello).status
	}
	if a, b, c, d := ok(), ok(), ok(), ok(); a != 200 || b != 429 || c != 429 || d != 200 {
		t.Errorf("skip 1, fail 2, then normal: %d %d %d %d", a, b, c, d)
	}
	f.fault(`{"modelId":"anthropic.claude-3-haiku-20240307-v1:0","error":{"code":"ModelTimeoutException"}}`)
	r = f.call("converse-stream", "anthropic.claude-3-haiku-20240307-v1:0", nil, converseHello)
	if code, body := errBody(t, r); r.status != 408 || code != "ModelTimeoutException" || !strings.Contains(fmt.Sprint(body["message"]), "timeout") {
		t.Errorf("a model timeout before the stream starts: %d %s", r.status, r.body)
	}
	if f.lastEntry("ConverseStream")["marker"] != "faked; fault" {
		t.Errorf("marker: %v", f.lastEntry("ConverseStream"))
	}
	// a stream fault overlays the next stream only
	f.fault(`{"streamError":{"code":"modelTimeoutException"},"times":1}`)
	if r := f.call("converse", "anthropic.claude-3-haiku-20240307-v1:0", nil, converseHello); r.status != 200 {
		t.Errorf("a stream fault waits for a stream: %d", r.status)
	}
	types, docs, _ = streamEvents(t, f.call("converse-stream", "anthropic.claude-3-haiku-20240307-v1:0", nil, converseHello))
	if types[len(types)-1] != "modelStreamErrorException" || docs[len(docs)-1]["originalStatusCode"].(float64) != 408 {
		t.Errorf("ConverseStream has no timeout event: %v %v", types, docs)
	}
	var fl struct{ Faults []map[string]any }
	json.Unmarshal([]byte(f.control("GET", "/faults", "").body), &fl)
	if len(fl.Faults) != 3 || fl.Faults[0]["remaining"].(float64) != 0 {
		t.Errorf("faults listed: %v", fl)
	}
	f.control("DELETE", "/faults", "")
	if r := f.call("converse", "anthropic.claude-3-haiku-20240307-v1:0", nil, converseHello); r.status != 200 {
		t.Errorf("faults cleared: %d", r.status)
	}
	// the delay
	f.fault(`{"delayMs":30}`)
	r = f.call("converse", "anthropic.claude-3-haiku-20240307-v1:0", nil, converseHello)
	if r.status != 200 || f.lastEntry("Converse")["ms"].(float64) < 25 {
		t.Errorf("a delay fault: %d %v", r.status, f.lastEntry("Converse"))
	}
	// an error that is part of a rule
	f.fixtures("m", `{"rules":[{"match":{"textContains":"boom"},"response":{"error":{"code":"ModelErrorException","originalStatusCode":500,"message":"bad model"}}}]}`)
	r = f.call("converse", "x.y", nil, `{"messages":[{"role":"user","content":[{"text":"boom"}]}]}`)
	if code, body := errBody(t, r); r.status != 424 || code != "ModelErrorException" || body["originalStatusCode"].(float64) != 500 || body["message"] != "bad model" {
		t.Errorf("model error: %d %s", r.status, r.body)
	}
}

func TestBedrockInvokeFamilies(t *testing.T) {
	f := startBD(t)
	f.fixtures("all", `{"default":{"text":"the canned text","usage":{"inputTokens":7,"outputTokens":9}}}`)
	type tc struct {
		model, body string
		check       func(d map[string]any) bool
	}
	for _, c := range []tc{
		{"anthropic.claude-3-5-sonnet-20241022-v2:0", `{"anthropic_version":"bedrock-2023-05-31","max_tokens":10,"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`,
			func(d map[string]any) bool {
				return d["type"] == "message" && d["role"] == "assistant" && dig(d, "content", 0, "type") == "text" && dig(d, "content", 0, "text") == "the canned text" &&
					d["stop_reason"] == "end_turn" && dig(d, "usage", "input_tokens").(float64) == 7 && dig(d, "usage", "output_tokens").(float64) == 9 &&
					strings.HasPrefix(d["id"].(string), "msg_bdrk_") && d["model"] == "anthropic.claude-3-5-sonnet-20241022-v2:0"
			}},
		{"anthropic.claude-v2", `{"prompt":"\n\nHuman: hi\n\nAssistant:","max_tokens_to_sample":10}`,
			func(d map[string]any) bool {
				return d["completion"] == "the canned text" && d["stop_reason"] == "stop_sequence"
			}},
		{"amazon.nova-lite-v1:0", `{"schemaVersion":"messages-v1","messages":[{"role":"user","content":[{"text":"hi"}]}]}`,
			func(d map[string]any) bool {
				return dig(d, "output", "message", "content", 0, "text") == "the canned text" && d["stopReason"] == "end_turn" && dig(d, "usage", "totalTokens").(float64) == 16
			}},
		{"amazon.titan-text-express-v1", `{"inputText":"hi","textGenerationConfig":{"maxTokenCount":10}}`,
			func(d map[string]any) bool {
				return dig(d, "results", 0, "outputText") == "the canned text" && dig(d, "results", 0, "completionReason") == "FINISH" && d["inputTextTokenCount"].(float64) == 7
			}},
		{"meta.llama3-8b-instruct-v1:0", `{"prompt":"hi","max_gen_len":10}`,
			func(d map[string]any) bool {
				return d["generation"] == "the canned text" && d["stop_reason"] == "stop" && d["prompt_token_count"].(float64) == 7 && d["generation_token_count"].(float64) == 9
			}},
		{"mistral.mistral-7b-instruct-v0:2", `{"prompt":"<s>[INST] hi [/INST]","max_tokens":10}`,
			func(d map[string]any) bool {
				return dig(d, "outputs", 0, "text") == "the canned text" && dig(d, "outputs", 0, "stop_reason") == "stop"
			}},
		{"cohere.command-text-v14", `{"prompt":"hi"}`,
			func(d map[string]any) bool {
				return dig(d, "generations", 0, "text") == "the canned text" && dig(d, "generations", 0, "finish_reason") == "COMPLETE"
			}},
		{"cohere.command-r-v1:0", `{"message":"hi"}`,
			func(d map[string]any) bool { return d["text"] == "the canned text" && d["finish_reason"] == "COMPLETE" }},
		{"ai21.jamba-1-5-large-v1:0", `{"messages":[]}`,
			func(d map[string]any) bool { return d["outputText"] == "the canned text" }},
	} {
		r := f.call("invoke", c.model, map[string]string{"Accept": "application/json"}, c.body)
		if r.status != 200 || r.header.Get("Content-Type") != "application/json" {
			t.Errorf("%s: %d %s", c.model, r.status, r.body)
			continue
		}
		if !c.check(jsonOf(t, r.body)) {
			t.Errorf("%s: wrong shape: %s", c.model, r.body)
		}
		if r.header.Get("X-Amzn-Bedrock-Input-Token-Count") != "7" || r.header.Get("X-Amzn-Bedrock-Output-Token-Count") != "9" {
			t.Errorf("%s: token headers: %v", c.model, r.header)
		}
	}
	if r := f.call("invoke", "anthropic.claude-3-haiku-20240307-v1:0", nil, `not json`); r.status != 400 || !strings.Contains(r.body, "Malformed input request") {
		t.Errorf("a body that is not JSON: %d %s", r.status, r.body)
	}
	// raw: the body as the rule gives it; an embedding; a body only a stream can answer
	f.fixtures("raw", `{"modelId":"x.raw","rules":[
	  {"match":{"jsonPath":"$.k","equals":1},"response":{"raw":{"anything":["goes",1]}}},
	  {"match":{"jsonPath":"$.k","equals":2},"response":{"rawChunks":[{"a":1}]}}]}`)
	if r := f.call("invoke", "x.raw", nil, `{"k":1}`); r.body != `{"anything":["goes",1]}` {
		t.Errorf("raw: %s", r.body)
	}
	if r := f.call("invoke", "x.raw", nil, `{"k":2}`); r.status != 400 || !strings.Contains(r.body, "rawChunks") {
		t.Errorf("an answer for a stream, asked of a plain call: %d %s", r.status, r.body)
	}
	f.fixtures("emb", `{"modelPrefix":"amazon.titan-embed","default":{"embedding":{"dimensions":6}}}`)
	r := f.call("invoke", "amazon.titan-embed-text-v2:0", nil, `{"inputText":"embed me"}`)
	d := jsonOf(t, r.body)
	vec := d["embedding"].([]any)
	if r.status != 200 || len(vec) != 6 || d["inputTextTokenCount"].(float64) != 2 {
		t.Errorf("embedding: %d %s", r.status, r.body)
	}
	again := jsonOf(t, f.call("invoke", "amazon.titan-embed-text-v2:0", nil, `{"inputText":"embed me"}`).body)
	other := jsonOf(t, f.call("invoke", "amazon.titan-embed-text-v2:0", nil, `{"inputText":"another"}`).body)
	if fmt.Sprint(again["embedding"]) != fmt.Sprint(vec) || fmt.Sprint(other["embedding"]) == fmt.Sprint(vec) {
		t.Error("an embedding is deterministic for a text, and differs between texts")
	}
	f.fixtures("emb", `{"modelPrefix":"cohere.embed","default":{"embedding":{"dimensions":3}}}`)
	d = jsonOf(t, f.call("invoke", "cohere.embed-english-v3", nil, `{"texts":["a","b"],"input_type":"search_document"}`).body)
	if len(d["embeddings"].([]any)) != 2 || d["response_type"] != "embeddings_floats" {
		t.Errorf("cohere embedding: %v", d)
	}
	if r := f.call("invoke-with-response-stream", "cohere.embed-english-v3", nil, `{"texts":["a"]}`); r.status != 400 {
		t.Errorf("an embedding model does not stream: %d %s", r.status, r.body)
	}
}

func TestBedrockInvokeStreams(t *testing.T) {
	f := startBD(t)
	f.fixtures("all", `{"default":{"text":"one two three four five","chunkSize":8}}`)
	decode := func(model, body string) (types []string, chunks []map[string]any) {
		t.Helper()
		r := f.call("invoke-with-response-stream", model, nil, body)
		if r.status != 200 || r.header.Get("X-Amzn-Bedrock-Content-Type") != "application/json" {
			t.Fatalf("%s: %d %s %v", model, r.status, r.body, r.header)
		}
		ty, docs, _ := streamEvents(t, r)
		for _, d := range docs {
			raw, err := base64.StdEncoding.DecodeString(d["bytes"].(string))
			if err != nil {
				t.Fatalf("%s: chunk bytes are not base64: %v", model, err)
			}
			chunks = append(chunks, jsonOf(t, string(raw)))
		}
		return ty, chunks
	}
	anthropicBody := `{"anthropic_version":"bedrock-2023-05-31","max_tokens":9,"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`
	types, ch := decode("anthropic.claude-3-haiku-20240307-v1:0", anthropicBody)
	var text strings.Builder
	seq := []string{}
	for _, c := range ch {
		seq = append(seq, c["type"].(string))
		if c["type"] == "content_block_delta" {
			text.WriteString(dig(c, "delta", "text").(string))
		}
	}
	if types[0] != "chunk" || text.String() != "one two three four five" || seq[0] != "message_start" || seq[1] != "content_block_start" ||
		seq[len(seq)-3] != "content_block_stop" || seq[len(seq)-2] != "message_delta" || seq[len(seq)-1] != "message_stop" ||
		dig(ch[len(ch)-2], "delta", "stop_reason") != "end_turn" || dig(ch[len(ch)-1], "amazon-bedrock-invocationMetrics", "outputTokenCount") == nil {
		t.Errorf("anthropic stream: %v %q", seq, text.String())
	}
	// every other family: the text joins, and the last chunk says it stopped and carries the metrics
	for model, body := range map[string]string{
		"amazon.nova-pro-v1:0": `{"messages":[{"role":"user","content":[{"text":"hi"}]}]}`, "amazon.titan-text-express-v1": `{"inputText":"hi"}`,
		"meta.llama3-8b-instruct-v1:0": `{"prompt":"hi"}`, "mistral.mistral-7b-instruct-v0:2": `{"prompt":"hi"}`, "cohere.command-text-v14": `{"prompt":"hi"}`,
		"cohere.command-r-v1:0": `{"message":"hi"}`, "anthropic.claude-v2": `{"prompt":"hi"}`, "ai21.jamba-1-5-large-v1:0": `{"messages":[]}`,
	} {
		_, ch := decode(model, body)
		var got strings.Builder
		for _, c := range ch {
			for _, key := range []string{"outputText", "generation", "completion", "text"} {
				if s, ok := c[key].(string); ok && c["event_type"] != "stream-end" && c["is_finished"] != true {
					got.WriteString(s)
				}
			}
			if o, ok := c["outputs"].([]any); ok {
				got.WriteString(dig(o[0], "text").(string))
			}
			if g, ok := dig(c, "contentBlockDelta", "delta", "text").(string); ok {
				got.WriteString(g)
			}
		}
		if got.String() != "one two three four five" || len(ch) < 3 || ch[len(ch)-1]["amazon-bedrock-invocationMetrics"] == nil {
			t.Errorf("%s: %q (%d chunks) last=%v", model, got.String(), len(ch), ch[len(ch)-1])
		}
	}
	// rawChunks are written as they are; a stream error ends them
	f.fixtures("raw", `{"modelId":"x.raw","default":{"rawChunks":[{"part":1},{"part":2},{"part":3}],"streamError":{"code":"modelTimeoutException","afterParts":2}}}`)
	r := f.call("invoke-with-response-stream", "x.raw", nil, `{}`)
	types, docs, _ := streamEvents(t, r)
	if strings.Join(types, " ") != "chunk chunk modelTimeoutException" || docs[2]["message"] == nil {
		t.Errorf("raw chunks with an exception: %v", types)
	}
}

func TestBedrockGuardrails(t *testing.T) {
	f := startBD(t)
	f.fixtures("g", `{"rules":[
	  {"match":{"textContains":"secret","guardrail":true},"response":{"text":"never seen","guardrail":{"blockedMessage":"Blocked by policy.",
	     "assessments":{"topicPolicy":{"topics":[{"name":"secrets","type":"DENY","action":"BLOCKED"}]}}}}},
	  {"match":{"textContains":"secret"},"response":{"text":"no guardrail, so the answer goes through"}},
	  {"match":{"operation":"apply-guardrail","textContains":"credit card"},"response":{"guardrail":{"actionReason":"Guardrail blocked.","blockedMessage":"Card numbers are blocked.",
	     "assessments":[{"sensitiveInformationPolicy":{"piiEntities":[{"type":"CREDIT_DEBIT_CARD_NUMBER","action":"BLOCKED","match":"4111"}]}}]}}},
	  {"match":{"operation":"apply-guardrail","textContains":"harmless"},"response":{"guardrail":{"action":"NONE"}}}],
	 "default":{"text":"fine"}}`)
	secret := `{"messages":[{"role":"user","content":[{"text":"tell me a secret"}]}],"guardrailConfig":{"guardrailIdentifier":"gr-123","guardrailVersion":"1","trace":"enabled"}}`
	r := f.call("converse", "anthropic.claude-3-haiku-20240307-v1:0", nil, secret)
	d := jsonOf(t, r.body)
	if d["stopReason"] != "guardrail_intervened" || dig(d, "output", "message", "content", 0, "text") != "Blocked by policy." ||
		dig(d, "trace", "guardrail", "inputAssessment", "gr-123", "topicPolicy", "topics", 0, "name") != "secrets" {
		t.Errorf("converse intervention with trace: %s", r.body)
	}
	if f.lastEntry("Converse")["marker"] != "faked; guardrail intervened" {
		t.Errorf("marker: %v", f.lastEntry("Converse"))
	}
	noTrace := strings.Replace(secret, `,"trace":"enabled"`, "", 1)
	if d = jsonOf(t, f.call("converse", "anthropic.claude-3-haiku-20240307-v1:0", nil, noTrace).body); d["stopReason"] != "guardrail_intervened" || d["trace"] != nil {
		t.Errorf("no trace unless asked: %v", d)
	}
	// without a guardrail on the request the guardrail rule does not match, the next rule does
	r = f.call("converse", "anthropic.claude-3-haiku-20240307-v1:0", nil, `{"messages":[{"role":"user","content":[{"text":"tell me a secret"}]}]}`)
	if dig(jsonOf(t, r.body), "output", "message", "content", 0, "text") != "no guardrail, so the answer goes through" {
		t.Errorf("no guardrail on the request: %s", r.body)
	}
	// InvokeModel: the guardrail headers, the action in the body
	r = f.call("invoke", "anthropic.claude-3-haiku-20240307-v1:0", map[string]string{"X-Amzn-Bedrock-GuardrailIdentifier": "gr-123", "X-Amzn-Bedrock-GuardrailVersion": "1", "X-Amzn-Bedrock-Trace": "ENABLED"},
		`{"anthropic_version":"bedrock-2023-05-31","max_tokens":9,"messages":[{"role":"user","content":[{"type":"text","text":"a secret"}]}]}`)
	d = jsonOf(t, r.body)
	if d["amazon-bedrock-guardrailAction"] != "INTERVENED" || dig(d, "content", 0, "text") != "Blocked by policy." || dig(d, "amazon-bedrock-trace", "guardrail", "inputAssessment", "gr-123") == nil {
		t.Errorf("invoke intervention: %s", r.body)
	}
	// ConverseStream: the blocked message and the trace in the metadata
	types, docs, _ := streamEvents(t, f.call("converse-stream", "anthropic.claude-3-haiku-20240307-v1:0", nil, secret))
	if docs[len(docs)-2]["stopReason"] != "guardrail_intervened" || dig(docs[len(docs)-1], "trace", "guardrail", "inputAssessment", "gr-123") == nil || types[len(types)-1] != "metadata" {
		t.Errorf("stream intervention: %v %v", types, docs)
	}
	// ApplyGuardrail
	apply := func(guardrail, text string) result {
		return f.do("POST", "/guardrail/"+guardrail+"/version/DRAFT/apply", merge(scopeHdr("bedrock"), map[string]string{"Content-Type": "application/json"}),
			`{"source":"INPUT","content":[{"text":{"text":"`+text+`"}}]}`)
	}
	r = apply("gr-123", "my credit card is 4111")
	d = jsonOf(t, r.body)
	if r.status != 200 || d["action"] != "GUARDRAIL_INTERVENED" || dig(d, "outputs", 0, "text") != "Card numbers are blocked." || d["actionReason"] != "Guardrail blocked." ||
		dig(d, "assessments", 0, "sensitiveInformationPolicy", "piiEntities", 0, "type") != "CREDIT_DEBIT_CARD_NUMBER" || dig(d, "usage", "contentPolicyUnits") == nil {
		t.Errorf("ApplyGuardrail: %d %s", r.status, r.body)
	}
	if d = jsonOf(t, apply("gr-123", "harmless text").body); d["action"] != "NONE" || len(d["outputs"].([]any)) != 0 {
		t.Errorf("ApplyGuardrail none: %v", d)
	}
	if r = apply("gr-123", "something nobody wrote a rule for"); r.status != 400 || !strings.Contains(r.body, "guardrail gr-123") {
		t.Errorf("ApplyGuardrail unmatched fails: %d %s", r.status, r.body)
	}
	if r = f.do("POST", "/guardrail/gr-123/version/1/apply", merge(scopeHdr("bedrock"), nil), `{"source":"X","content":[]}`); r.status != 400 {
		t.Errorf("ApplyGuardrail validation: %d", r.status)
	}
	if f.summary()["totals"].(map[string]any)["guardrailInterventions"].(float64) != 4 {
		t.Errorf("interventions counted: %v", f.summary()["totals"])
	}
}

func TestBedrockCountTokens(t *testing.T) {
	f := startBD(t)
	f.fixtures("d", `{"default":{"text":"must not be used up by a token count"},"queue":[{"text":"queued"}],"rules":[
	  {"match":{"operation":"count-tokens","textContains":"fixed"},"response":{"usage":{"inputTokens":42}}}]}`)
	body := func(text string) string {
		return `{"input":{"converse":{"messages":[{"role":"user","content":[{"text":"` + text + `"}]}]}}}`
	}
	r := f.call("count-tokens", "anthropic.claude-3-haiku-20240307-v1:0", nil, body("twelve chars"))
	if d := jsonOf(t, r.body); r.status != 200 || d["inputTokens"].(float64) != 3 || f.lastEntry("CountTokens")["marker"] != "faked; estimated" {
		t.Errorf("estimate: %d %s %v", r.status, r.body, f.lastEntry("CountTokens"))
	}
	if d := jsonOf(t, f.call("count-tokens", "anthropic.claude-3-haiku-20240307-v1:0", nil, body("a fixed count")).body); d["inputTokens"].(float64) != 42 {
		t.Errorf("rule: %v", d)
	}
	inner := base64.StdEncoding.EncodeToString([]byte(`{"anthropic_version":"bedrock-2023-05-31","max_tokens":5,"messages":[{"role":"user","content":"eight ch"}]}`))
	if d := jsonOf(t, f.call("count-tokens", "anthropic.claude-3-haiku-20240307-v1:0", nil, `{"input":{"invokeModel":{"body":"`+inner+`"}}}`).body); d["inputTokens"].(float64) != 2 {
		t.Errorf("invokeModel input: %v", d)
	}
	if r := f.call("count-tokens", "anthropic.claude-3-haiku-20240307-v1:0", nil, `{}`); r.status != 400 {
		t.Errorf("no input: %d", r.status)
	}
	// the queue and the default were left for the calls that make text
	if d := jsonOf(t, f.call("converse", "anthropic.claude-3-haiku-20240307-v1:0", nil, converseHello).body); dig(d, "output", "message", "content", 0, "text") != "queued" {
		t.Errorf("a count did not use up the queue: %v", d)
	}
}

func TestBedrockPlanAndLegacyMode(t *testing.T) {
	// a plan that names only the control plane: the runtime is out of plan
	f := startBD(t, "bedrock")
	if r := f.call("converse", "anthropic.claude-3-haiku-20240307-v1:0", nil, converseHello); r.status != 400 || !strings.Contains(r.body, "ServiceNotAvailable") {
		t.Errorf("out of plan: %d %s", r.status, r.body)
	}
	if r := f.control("GET", "/summary", ""); r.status != 404 {
		t.Errorf("control path without the plan: %d", r.status)
	}
	// the guard: the control paths need the token
	g := startBD(t)
	if r := g.do("GET", "/_rovara/bedrock/summary", nil, ""); r.status != 403 {
		t.Errorf("control path without the token: %d", r.status)
	}
	// the other operations of the route key still go to the engine
	r := g.do("GET", "/async-invoke", scopeHdr("bedrock"), "")
	if r.header.Get("X-Fake-Path") == "" {
		t.Errorf("ListAsyncInvokes is forwarded: %d %s", r.status, r.body)
	}
}

func TestBedrockControlPaths(t *testing.T) {
	f := startBD(t)
	for name, doc := range map[string]string{"a typo": `{"rulez":[]}`, "no answer": `{"default":{}}`} {
		if r := f.control("PUT", "/fixtures/x", doc); r.status != 422 {
			t.Errorf("%s: %d %s", name, r.status, r.body)
		}
	}
	if r := f.control("PUT", "/fixtures/x", `{"name":"y","default":{"text":"a"}}`); r.status != 422 {
		t.Errorf("a name that differs from the path: %d", r.status)
	}
	if r := f.control("PUT", "/fixtures/bad name", `{"default":{"text":"a"}}`); r.status != 404 {
		t.Errorf("a bad name in the path: %d", r.status)
	}
	f.fixtures("one", `{"modelId":"anthropic.claude-3-haiku-20240307-v1:0","source":"recorded","recordedOn":"2026-11-12","rules":[{"match":{},"response":{"text":"a"}}],"queue":[{"text":"b"}],"default":{"text":"c"}}`)
	var one map[string]any
	json.Unmarshal([]byte(f.control("GET", "/fixtures/one", "").body), &one)
	if one["label"] != "recorded fake" || one["rules"].(float64) != 1 || one["queued"].(float64) != 1 || one["hasDefault"] != true || one["recordedOn"] != "2026-11-12" {
		t.Errorf("fixture summary: %v", one)
	}
	if r := f.control("PUT", "/fixtures", `{"fixtures":[{"name":"a","default":{"text":"1"}},{"name":"a","default":{"text":"2"}}]}`); r.status != 422 {
		t.Errorf("duplicate names in a replace: %d %s", r.status, r.body)
	}
	if r := f.control("PUT", "/fixtures", `{"fixtures":[{"name":"a","default":{"text":"1"}},{"name":"b","modelPrefix":"x.","default":{"text":"2"}}]}`); r.status != 200 {
		t.Errorf("replace: %d %s", r.status, r.body)
	}
	if r := f.control("GET", "/fixtures/one", ""); r.status != 404 {
		t.Errorf("replaced sets are gone: %d", r.status)
	}
	// a reset empties the fixtures; DELETE /_rovara/ledger empties the counters
	f.call("converse", "anthropic.claude-3-haiku-20240307-v1:0", nil, converseHello)
	if f.summary()["totals"].(map[string]any)["calls"].(float64) != 1 {
		t.Error("counted")
	}
	if r := f.do("POST", "/_rovara/reset", tok(), ""); r.status != 200 {
		t.Fatalf("reset: %d %s", r.status, r.body)
	}
	if r := f.call("converse", "anthropic.claude-3-haiku-20240307-v1:0", nil, converseHello); r.status != 400 || !strings.Contains(r.body, "no recorded or canned answer") {
		t.Errorf("a reset empties the fixtures: %d %s", r.status, r.body)
	}
	f.do("DELETE", "/_rovara/ledger", tok(), "")
	if f.summary()["totals"].(map[string]any)["calls"].(float64) != 0 {
		t.Error("the ledger's delete empties the counters")
	}
	// the seed
	seed := `{"bedrock":{"fixtures":[{"name":"seeded","modelPrefix":"anthropic.","default":{"text":"from the seed"}}]}}`
	if r := f.do("POST", "/_rovara/seed", tok(), seed); r.status != 200 || strings.Contains(r.body, `"ok":false`) {
		t.Errorf("seed: %d %s", r.status, r.body)
	}
	if d := jsonOf(t, f.call("converse", "anthropic.claude-3-haiku-20240307-v1:0", nil, converseHello).body); dig(d, "output", "message", "content", 0, "text") != "from the seed" {
		t.Errorf("seeded fixtures answer: %v", d)
	}
	// a seed for a plan that does not name the runtime fails its step
	h := startBD(t, "bedrock")
	if r := h.do("POST", "/_rovara/seed", tok(), seed); !strings.Contains(r.body, "not in the plan") {
		t.Errorf("seed without the plan: %d %s", r.status, r.body)
	}
}

func TestBedrockModelIDInPath(t *testing.T) {
	f := startBD(t)
	f.fixtures("a", `{"modelId":"meta.llama3-1-70b-instruct-v1:0","default":{"text":"via arn"}}`)
	arn := "arn:aws:bedrock:us-east-1:123456789012:inference-profile/us.meta.llama3-1-70b-instruct-v1:0"
	r := f.call("invoke", arn, nil, `{"prompt":"x"}`)
	if r.status != 200 || jsonOf(t, r.body)["generation"] != "via arn" {
		t.Errorf("an ARN (percent-encoded in the path) finds its base id: %d %s", r.status, r.body)
	}
	sum := f.summary()["models"].([]any)
	if len(sum) != 1 || sum[0].(map[string]any)["modelId"] != arn {
		t.Errorf("counted under the id as given: %v", sum)
	}
}

func TestBedrockLateModelFamilies(t *testing.T) {
	f := startBD(t)
	f.fixtures("a", `{"default":{"content":[{"text":"thinking out loud"},{"toolUse":{"name":"t","input":{"a":1}}}],"additionalModelResponseFields":{"x":1},"stopReason":"max_tokens"}}`)
	d := jsonOf(t, f.call("converse", "x.y", nil, converseHello).body)
	if dig(d, "output", "message", "content", 1, "toolUse", "input", "a").(float64) != 1 || d["stopReason"] != "max_tokens" || dig(d, "additionalModelResponseFields", "x").(float64) != 1 {
		t.Errorf("content blocks, an explicit stop reason and additional fields: %v", d)
	}
	f.fixtures("a", `{"default":{"content":[{"reasoningContent":{"reasoningText":{"text":"hmm"}}},{"text":"answer"}]}}`)
	d = jsonOf(t, f.call("converse", "x.y", nil, converseHello).body)
	if dig(d, "output", "message", "content", 0, "reasoningContent", "reasoningText", "text") != "hmm" {
		t.Errorf("a block the front has no shape for passes through: %v", d)
	}
	types, _, _ := streamEvents(t, f.call("converse-stream", "x.y", nil, converseHello))
	if strings.Count(strings.Join(types, " "), "contentBlockStop") != 1 {
		t.Errorf("a block with no stream form is left out of a stream: %v", types)
	}
}

func TestBedrockBodyLimit(t *testing.T) {
	f := startBD(t)
	f.fixtures("a", `{"default":{"text":"ok"}}`)
	big := `{"messages":[{"role":"user","content":[{"text":"` + strings.Repeat("a", bdMaxBodyBytes) + `"}]}]}`
	r := f.call("converse", "x.y", nil, big)
	if code, _ := errBody(t, r); r.status != 400 || code != "ValidationException" || !strings.Contains(r.body, "too long") {
		t.Errorf("a body over 8 MiB: %d %s", r.status, r.body[:min(len(r.body), 200)])
	}
	if r := f.call("converse", "x.y", nil, converseHello); r.status != 200 {
		t.Errorf("the budget is released: %d", r.status)
	}
	if left := f.srv.bd.bodies.left; left != bdBodyBudget {
		t.Errorf("every reserved byte is returned: %d of %d", left, int64(bdBodyBudget))
	}
}
