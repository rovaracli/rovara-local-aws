package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---- fixtures: parsing, matching, choosing

func mustBacking(t *testing.T, doc string) *smBacking {
	t.Helper()
	b, err := parseBacking([]byte(doc))
	if err != nil {
		t.Fatalf("parseBacking: %v\n%s", err, doc)
	}
	return b
}

func TestFixtureValidation(t *testing.T) {
	for name, doc := range map[string]string{
		"a typo in a field":         `{"rulez":[]}`,
		"an unknown mode":           `{"mode":"gpu"}`,
		"an unknown source":         `{"source":"guessed"}`,
		"two body forms":            `{"default":{"body":"a","json":1}}`,
		"bad base64":                `{"default":{"bodyBase64":"***"}}`,
		"bad error code":            `{"default":{"error":{"code":"Teapot"}}}`,
		"jsonPath without value":    `{"rules":[{"match":{"equals":1},"response":{}}]}`,
		"bad jsonPath":              `{"rules":[{"match":{"jsonPath":"a.b"},"response":{}}]}`,
		"wildcard jsonPath":         `{"rules":[{"match":{"jsonPath":"$.a[*]"},"response":{}}]}`,
		"bad regex":                 `{"rules":[{"match":{"matches":"("},"response":{}}]}`,
		"bad hash":                  `{"rules":[{"match":{"bodySha256":"abc"},"response":{}}]}`,
		"unknown operation":         `{"rules":[{"match":{"operation":"batch"},"response":{}}]}`,
		"negative times":            `{"rules":[{"match":{},"response":{},"times":-1}]}`,
		"delay out of range":        `{"default":{"delayMs":999999}}`,
		"a second value":            `{} {}`,
		"bad stream error":          `{"default":{"streamError":{"errorCode":"Nope"}}}`,
		"header value with newline": `{"default":{"contentType":"a\nb"}}`,
	} {
		if _, err := parseBacking([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	b := mustBacking(t, `{}`)
	if b.Mode != "canned" || b.Source != "handwritten" {
		t.Errorf("defaults: %+v", b)
	}
	if _, err := parseBacking(bytes.Repeat([]byte(" "), smMaxDocBytes+1)); err == nil {
		t.Error("a document over 8 MiB is refused")
	}
}

func TestFixtureMatchingAndOrder(t *testing.T) {
	b := mustBacking(t, `{
	  "rules":[
	    {"match":{"contentType":"application/json","jsonPath":"$.features[1]","equals":2.0},"response":{"json":{"score":0.9}}},
	    {"match":{"jsonPath":"$.user.name","matches":"^al"},"response":{"body":"alice"},"times":1},
	    {"match":{"bodyContains":"needle"},"response":{"body":"found"}},
	    {"match":{"bodySha256":"`+sha256hex("exact")+`"},"response":{"body":"by-hash"}},
	    {"match":{"contentType":"text/csv","operation":"stream"},"response":{"body":"csv-stream"}},
	    {"match":{"jsonPath":"$['odd key'][0]","exists":true},"response":{"body":"bracket"}}
	  ],
	  "queue":[{"body":"q1"},{"body":"q2"}],
	  "default":{"body":"dflt"}}`)
	req := func(op, ct, body string) *smRequest { return newSMRequest(op, ct, "", "", "", "", []byte(body)) }
	got := func(q *smRequest) string {
		r, k := b.pick(q)
		if r == nil {
			return "none:" + fmt.Sprint(k)
		}
		return string(r.data) + ":" + fmt.Sprint(k)
	}
	if g := got(req("invoke", "application/json; charset=utf-8", `{"features":[1,2,3]}`)); g != `{"score":0.9}:1` {
		t.Errorf("json path equals (numbers compare by value, content type without parameters): %s", g)
	}
	if g := got(req("invoke", "", `{"user":{"name":"alan"}}`)); g != "alice:1" {
		t.Errorf("regex on a path: %s", g)
	}
	// the one-time rule is used up: the same request now falls through the other rules, to the queue
	if g := got(req("invoke", "", `{"user":{"name":"alan"}}`)); g != "q1:2" {
		t.Errorf("times: %s", g)
	}
	if g := got(req("invoke", "", `a needle here`)); g != "found:1" {
		t.Errorf("contains: %s", g)
	}
	if g := got(req("invoke", "", `exact`)); g != "by-hash:1" {
		t.Errorf("hash: %s", g)
	}
	if g := got(req("stream", "text/csv", `1,2`)); g != "csv-stream:1" {
		t.Errorf("operation and content type: %s", g)
	}
	if g := got(req("invoke", "text/csv", `1,2`)); g != "q2:2" {
		t.Errorf("an operation that does not match falls to the queue (not the rule): %s", g)
	}
	if g := got(req("invoke", "", `{"odd key":[0]}`)); g != "bracket:1" {
		t.Errorf("bracket path: %s", g)
	}
	if g := got(req("invoke", "text/csv", `1,2`)); g != "dflt:3" {
		t.Errorf("the queue is used up, then the default: %s", g)
	}
	absent := mustBacking(t, `{"rules":[{"match":{"jsonPath":"$.absent","exists":false},"response":{"body":"absent"}}]}`)
	if r, _ := absent.pick(req("invoke", "", `not json`)); r == nil || string(r.data) != "absent" {
		t.Error("a path on a body that is not JSON is absent")
	}
	if r, _ := absent.pick(req("invoke", "", `{"absent":null}`)); r != nil {
		t.Error("a path that is there, even null, is not absent")
	}
	b.Rules = nil
	b.Default = nil
	if g := got(req("invoke", "", `x`)); !strings.HasPrefix(g, "none") {
		t.Errorf("nothing left: %s", g)
	}
}

func sha256hex(s string) string {
	return newSMRequest("invoke", "", "", "", "", "", []byte(s)).sha
}

func TestSplitParts(t *testing.T) {
	parts := splitParts([]byte("héllo wörld"), 2)
	var joined []byte
	for _, p := range parts {
		joined = append(joined, p...)
		if !strings.HasPrefix(fmt.Sprintf("%q", p), `"`) || string(p) == "" {
			t.Errorf("empty part")
		}
	}
	if string(joined) != "héllo wörld" || len(parts) < 4 {
		t.Errorf("parts: %q", parts)
	}
	for _, p := range parts {
		if strings.ContainsRune(string(p), '�') {
			t.Errorf("a part cuts a character: %q", p)
		}
	}
	if splitParts(nil, 4) != nil || len(splitParts([]byte("abc"), 0)) != 1 {
		t.Error("empty and default sizes")
	}
}

// ---- the route

type smFront struct {
	*lamFront
	helper *httptest.Server
}

func startSM(t *testing.T, planned ...string) *smFront {
	t.Helper()
	if len(planned) == 0 {
		planned = []string{"sagemaker", "sagemaker-runtime", "s3", "sns", "cloudformation"}
	}
	f := startLambdaFront(t, planned...)
	return &smFront{lamFront: f}
}

func (f *smFront) withHelper(handler http.HandlerFunc) {
	f.helper = httptest.NewServer(handler)
	f.t.Cleanup(f.helper.Close)
	u, _ := url.Parse(f.helper.URL)
	f.srv.sm.helpers = append(f.srv.sm.helpers, u)
	f.srv.sm.client = newHelperClient(f.srv.sm.helpers, true)
}

func (f *smFront) control(method, path, body string) result {
	return f.do(method, "/_rovara/sagemaker/endpoints"+path, tok(), body)
}

func (f *smFront) setBacking(name, doc string) {
	f.t.Helper()
	if r := f.control("PUT", "/"+name, doc); r.status != 200 {
		f.t.Fatalf("PUT backing: %d %s", r.status, r.body)
	}
}

func (f *smFront) target(op string, body any) result {
	b, _ := json.Marshal(body)
	return f.do("POST", "/", with(scopeHdr("sagemaker"), "X-Amz-Target", "SageMaker."+op, "Content-Type", "application/x-amz-json-1.1"), string(b))
}

// create makes an endpoint the way the code does: CreateModel, CreateEndpointConfig, CreateEndpoint, through the front.
func (f *smFront) create(name string, variants []string, async map[string]any) {
	f.t.Helper()
	if variants == nil {
		variants = []string{"AllTraffic"}
	}
	if r := f.target("CreateModel", map[string]any{"ModelName": name}); r.status != 200 {
		f.t.Fatalf("CreateModel: %d %s", r.status, r.body)
	}
	var pv []any
	for _, v := range variants {
		pv = append(pv, map[string]any{"VariantName": v, "ModelName": name})
	}
	cfg := map[string]any{"EndpointConfigName": name + "-cfg", "ProductionVariants": pv}
	if async != nil {
		cfg["AsyncInferenceConfig"] = async
	}
	if r := f.target("CreateEndpointConfig", cfg); r.status != 200 {
		f.t.Fatalf("CreateEndpointConfig: %d %s", r.status, r.body)
	}
	if r := f.target("CreateEndpoint", map[string]any{"EndpointName": name, "EndpointConfigName": name + "-cfg"}); r.status != 200 {
		f.t.Fatalf("CreateEndpoint: %d %s", r.status, r.body)
	}
}

func (f *smFront) invoke(name string, headers map[string]string, body string) result {
	return f.do("POST", "/endpoints/"+name+"/invocations", merge(scopeHdr("sagemaker"), headers), body)
}

func (f *smFront) stream(name string, headers map[string]string, body string) result {
	return f.do("POST", "/endpoints/"+name+"/invocations-response-stream", merge(scopeHdr("sagemaker"), headers), body)
}

func (f *smFront) async(name string, headers map[string]string) result {
	return f.do("POST", "/endpoints/"+name+"/async-invocations", merge(scopeHdr("sagemaker"), headers), "")
}

func (f *smFront) lastEntry(op string) map[string]any {
	f.t.Helper()
	r := f.do("GET", "/_rovara/ledger?service=sagemaker-runtime", tok(), "")
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

func (f *smFront) summary(name string) map[string]any {
	f.t.Helper()
	r := f.control("GET", "/"+name, "")
	if r.status != 200 {
		f.t.Fatalf("summary: %d %s", r.status, r.body)
	}
	var m map[string]any
	json.Unmarshal([]byte(r.body), &m)
	return m
}

func errBody(t *testing.T, r result) (code string, body map[string]any) {
	t.Helper()
	json.Unmarshal([]byte(r.body), &body)
	return r.header.Get("X-Amzn-Errortype"), body
}

func TestUnknownEndpointIsAValidationError(t *testing.T) {
	f := startSM(t)
	r := f.invoke("nope", map[string]string{"Content-Type": "application/json"}, `{}`)
	code, body := errBody(t, r)
	if r.status != 400 || code != "ValidationError" || body["Message"] != "Endpoint nope of account 000000000000 not found." {
		t.Errorf("unknown endpoint: %d %s %s", r.status, code, r.body)
	}
	e := f.lastEntry("InvokeEndpoint")
	if e["marker"] != "unplanned endpoint" || e["status"].(float64) != 400 {
		t.Errorf("the ledger says so: %v", e)
	}
	if r := f.invoke("bad_name", nil, `{}`); r.status != 400 || !strings.Contains(r.body, "regular expression") {
		t.Errorf("a name that is not an endpoint name: %d %s", r.status, r.body)
	}
	sum := f.do("GET", "/_rovara/sagemaker/endpoints", tok(), "").body
	if !strings.Contains(sum, `"unplannedEndpoints":{"nope":1}`) {
		t.Errorf("counted as unplanned: %s", sum)
	}
	// the plan must name sagemaker-runtime: a plan with only the control plane refuses the invoke as out of plan
	g := startSM(t, "sagemaker", "s3")
	if r := g.invoke("x", nil, `{}`); r.status != 400 || !strings.Contains(r.body, "ServiceNotAvailable") {
		t.Errorf("out of plan: %d %s", r.status, r.body)
	}
	if g.counts("sagemaker-runtime")["InvokeEndpoint"].Calls != 1 {
		t.Errorf("counted out of plan: %v", g.allCounts())
	}
}

func TestEndpointTableFromTheCodesOwnCalls(t *testing.T) {
	f := startSM(t)
	f.create("fraud", []string{"A", "B"}, nil)
	s := f.summary("fraud")
	if s["exists"] != true || s["source"] != "api" || s["configName"] != "fraud-cfg" || fmt.Sprint(s["variants"]) != "[A B]" {
		t.Errorf("the table: %v", s)
	}
	f.setBacking("fraud", `{"default":{"json":{"ok":true}}}`)
	if r := f.invoke("fraud", map[string]string{"X-Amzn-SageMaker-Target-Variant": "C"}, `{}`); r.status != 400 || !strings.Contains(r.body, "Production variant C") {
		t.Errorf("unknown variant: %d %s", r.status, r.body)
	}
	r := f.invoke("fraud", map[string]string{"X-Amzn-SageMaker-Target-Variant": "B"}, `{}`)
	if r.status != 200 || r.header.Get("x-amzn-invoked-production-variant") != "B" {
		t.Errorf("target variant: %d %v", r.status, r.header)
	}
	if r := f.target("DeleteEndpoint", map[string]any{"EndpointName": "fraud"}); r.status != 200 {
		t.Fatal(r.body)
	}
	if r := f.invoke("fraud", nil, `{}`); r.status != 400 {
		t.Errorf("a deleted endpoint is gone: %d", r.status)
	}
	// a call the engine refused is not recorded
	f2 := startSM(t)
	if r := f2.target("CreateEndpoint", map[string]any{"EndpointName": "REFUSE", "EndpointConfigName": "x"}); r.status != 400 {
		t.Fatalf("the fake engine refuses: %d", r.status)
	}
	if r := f2.invoke("REFUSE", nil, `{}`); r.status != 400 || !strings.Contains(r.body, "not found") {
		t.Errorf("a refused CreateEndpoint makes no endpoint: %d %s", r.status, r.body)
	}
}

func TestInvokeCannedAnswers(t *testing.T) {
	f := startSM(t)
	f.create("scorer", nil, nil)
	f.setBacking("scorer", `{"source":"recorded","recordedOn":"2026-11-20","rules":[
	  {"match":{"jsonPath":"$.id","equals":7},"response":{"json":{"score":0.97},"customAttributes":"trace=1","variant":"v7"}},
	  {"match":{"jsonPath":"$.id","equals":8},"response":{"error":{"code":"ModelError","originalStatusCode":500,"originalMessage":"the model fell over"}}},
	  {"match":{"jsonPath":"$.id","equals":9},"response":{"error":{"code":"ModelNotReadyException","message":"loading"}}},
	  {"match":{"jsonPath":"$.id","equals":10},"response":{"bodyBase64":"AAEC","contentType":"application/octet-stream"}}
	 ],"default":{"body":"made up","contentType":"text/plain"}}`)
	r := f.invoke("scorer", map[string]string{"Content-Type": "application/json"}, `{"id":7}`)
	if r.status != 200 || r.body != `{"score":0.97}` || r.header.Get("Content-Type") != "application/json" ||
		r.header.Get("x-amzn-sagemaker-custom-attributes") != "trace=1" || r.header.Get("x-amzn-invoked-production-variant") != "v7" {
		t.Errorf("a matched answer: %d %v %s", r.status, r.header, r.body)
	}
	if e := f.lastEntry("InvokeEndpoint"); e["marker"] != "recorded fake" {
		t.Errorf("marker: %v", e)
	}
	r = f.invoke("scorer", nil, `{"id":8}`)
	code, body := errBody(t, r)
	if r.status != 424 || code != "ModelError" || body["OriginalStatusCode"].(float64) != 500 || body["OriginalMessage"] != "the model fell over" ||
		!strings.Contains(body["Message"].(string), "Received server error (500) from primary") {
		t.Errorf("ModelError: %d %s %s", r.status, code, r.body)
	}
	if r = f.invoke("scorer", nil, `{"id":9}`); r.status != 429 || r.header.Get("X-Amzn-Errortype") != "ModelNotReadyException" {
		t.Errorf("a canned ModelNotReadyException: %d %s", r.status, r.body)
	}
	if r = f.invoke("scorer", nil, `{"id":10}`); r.body != "\x00\x01\x02" || r.header.Get("Content-Type") != "application/octet-stream" {
		t.Errorf("bytes: %q", r.body)
	}
	r = f.invoke("scorer", map[string]string{"Accept": "text/csv"}, `{"id":11}`)
	if r.body != "made up" || r.header.Get("Content-Type") != "text/plain" {
		t.Errorf("the default: %q %v", r.body, r.header)
	}
	if e := f.lastEntry("InvokeEndpoint"); e["marker"] != "recorded fake; made-up answer" {
		t.Errorf("marker: %v", e)
	}
	s := f.summary("scorer")
	if s["calls"].(float64) != 5 || s["matched"].(float64) != 4 || s["madeUp"].(float64) != 1 || s["errors"].(float64) != 2 || s["faked"] != true ||
		s["notTested"] != "real model behaviour" || s["backing"].(map[string]any)["label"] != "recorded fake" ||
		s["backing"].(map[string]any)["recordedOn"] != "2026-11-20" {
		t.Errorf("summary: %v", s)
	}
	// no answer at all: a ModelError that says why, and the size and hash for writing the fixture
	f.setBacking("scorer", `{}`)
	r = f.invoke("scorer", map[string]string{"Content-Type": "text/csv"}, `1,2,3`)
	_, body = errBody(t, r)
	if r.status != 424 || !strings.Contains(body["Message"].(string), "no recorded or canned answer matches") || !strings.Contains(body["Message"].(string), sha256hex("1,2,3")) {
		t.Errorf("unmatched: %d %s", r.status, r.body)
	}
	s = f.summary("scorer")
	last := s["lastUnmatched"].([]any)
	if s["unmatched"].(float64) != 1 || len(last) != 1 || last[0].(map[string]any)["sha256"] != sha256hex("1,2,3") || last[0].(map[string]any)["bytes"].(float64) != 5 {
		t.Errorf("unmatched summary: %v", s)
	}
	if strings.Contains(f.control("GET", "", "").body, "1,2,3") {
		t.Error("the summary never carries a body")
	}
	// the ledger summary counts usage and errors like any service; a fixture "queue" answers in order
	f.setBacking("scorer", `{"queue":[{"body":"one"},{"body":"two"}]}`)
	if a, b, c := f.invoke("scorer", nil, ``), f.invoke("scorer", nil, ``), f.invoke("scorer", nil, ``); a.body != "one" || b.body != "two" || c.status != 424 {
		t.Errorf("queue: %q %q %d", a.body, b.body, c.status)
	}
	if c := f.counts("sagemaker-runtime")["InvokeEndpoint"]; c.Calls != 9 {
		t.Errorf("ledger summary: %+v", c)
	}
}

func TestControlPathsAreGuardedAndValidated(t *testing.T) {
	f := startSM(t)
	for _, m := range []string{"GET", "PUT", "DELETE"} {
		if r := f.do(m, "/_rovara/sagemaker/endpoints/x", nil, `{}`); r.status != 403 {
			t.Errorf("%s without the token: %d", m, r.status)
		}
	}
	if r := f.do("GET", "/_rovara/sagemaker/endpoints", nil, ""); r.status != 403 {
		t.Errorf("list without the token: %d", r.status)
	}
	for _, c := range []struct{ name, doc string }{{"x", `{"rules":`}, {"x", `{"mode":"nope"}`}, {"x", `{"mode":"helper"}`}, {"x", `{"mode":"helper","helper":"http://evil:1"}`}} {
		if r := f.control("PUT", "/"+c.name, c.doc); r.status != 422 && r.status != 400 {
			t.Errorf("%s: %d %s", c.doc, r.status, r.body)
		}
	}
	if r := f.control("PUT", "/bad_name", `{}`); r.status != 404 {
		t.Errorf("a name that is not an endpoint name: %d", r.status)
	}
	if r := f.control("GET", "/missing", ""); r.status != 404 {
		t.Errorf("an unknown endpoint: %d", r.status)
	}
	if r := f.control("POST", "", ""); r.status != 405 {
		t.Errorf("method: %d", r.status)
	}
	// without a plan that names sagemaker-runtime the paths do not exist
	g := startSM(t, "s3")
	if r := g.control("GET", "", ""); r.status != 404 {
		t.Errorf("not planned: %d", r.status)
	}
	// a backing can be removed
	f.setBacking("x", `{"default":{"body":"a"}}`)
	if r := f.control("DELETE", "/x", ""); r.status != 200 {
		t.Errorf("delete: %d", r.status)
	}
	// the number of endpoints with a backing is bounded
	for i := 0; i < smMaxBackings; i++ {
		f.control("PUT", fmt.Sprintf("/b%d", i), `{}`)
	}
	if r := f.control("PUT", "/one-too-many", `{}`); r.status != 422 || !strings.Contains(r.body, "too many") {
		t.Errorf("a bound: %d %s", r.status, r.body)
	}
	if r := f.control("PUT", "/b1", `{"default":{"body":"replaced"}}`); r.status != 200 {
		t.Errorf("an endpoint that has one can replace it: %d", r.status)
	}
}

func TestResetClearsTheTableAndClearLedgerClearsTheCounters(t *testing.T) {
	f := startSM(t)
	f.create("e", nil, nil)
	f.setBacking("e", `{"default":{"body":"x"}}`)
	f.invoke("e", nil, `{}`)
	if r := f.do("POST", "/_rovara/reset", tok(), ""); r.status != 200 {
		t.Fatalf("reset: %d %s", r.status, r.body)
	}
	if r := f.invoke("e", nil, `{}`); r.status != 400 {
		t.Errorf("after a reset the endpoint is gone: %d", r.status)
	}
	s := f.control("GET", "", "").body
	if !strings.Contains(s, `"name":"e"`) || !strings.Contains(s, `"calls":1`) {
		t.Errorf("the counters stay with the ledger: %s", s)
	}
	f.do("DELETE", "/_rovara/ledger", tok(), "")
	if s := f.control("GET", "", "").body; strings.Contains(s, `"name":"e"`) || strings.Contains(s, `"nope":1`) {
		t.Errorf("DELETE /_rovara/ledger clears them: %s", s)
	}
}

// ---- the model stand-in

func TestInvokeThroughTheModelStandIn(t *testing.T) {
	f := startSM(t)
	var seen http.Header
	var seenPath string
	f.withHelper(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		seen, seenPath = r.Header.Clone(), r.URL.Path
		switch string(b) {
		case "client":
			w.WriteHeader(400)
			io.WriteString(w, "bad\ninput \x00here")
		case "server":
			w.WriteHeader(500)
			io.WriteString(w, "kaboom")
		case "big":
			w.Write(make([]byte, 7<<20))
		case "redirect":
			http.Redirect(w, r, "http://example.invalid/", 302)
		default:
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Amzn-SageMaker-Custom-Attributes", "echo")
			w.Header().Set("X-Evil", "no")
			w.Header().Set("Set-Cookie", "a=b")
			io.WriteString(w, `{"echo":`+fmt.Sprintf("%q", string(b))+`}`)
		}
	})
	f.create("stand", nil, nil)
	f.setBacking("stand", `{"mode":"helper"}`) // the stand-in is used only when the backing names it (SM3 is parked, decision 141)
	r := f.invoke("stand", map[string]string{"Content-Type": "text/csv", "Accept": "application/json", "X-Amzn-SageMaker-Custom-Attributes": "c1",
		"X-Amzn-SageMaker-Target-Model": "m.tar.gz", "Cookie": "no", "X-Other": "no"}, `1,2`)
	if r.status != 200 || r.body != `{"echo":"1,2"}` || r.header.Get("Content-Type") != "application/json" || r.header.Get("x-amzn-sagemaker-custom-attributes") != "echo" {
		t.Errorf("forwarded: %d %v %s", r.status, r.header, r.body)
	}
	if seenPath != "/invocations" || seen.Get("Content-Type") != "text/csv" || seen.Get("Accept") != "application/json" || seen.Get("X-Amzn-SageMaker-Custom-Attributes") != "c1" ||
		seen.Get("X-Amzn-SageMaker-Target-Model") != "m.tar.gz" || seen.Get("Cookie") != "" || seen.Get("X-Other") != "" || seen.Get("Authorization") != "" {
		t.Errorf("what the model sees: %s %v", seenPath, seen)
	}
	if r.header.Get("X-Evil") != "" || r.header.Get("Set-Cookie") != "" {
		t.Errorf("only SageMaker's reply headers pass: %v", r.header)
	}
	if e := f.lastEntry("InvokeEndpoint"); e["marker"] != "Rovara model stand-in" {
		t.Errorf("marker: %v", e)
	}
	r = f.invoke("stand", nil, "client")
	_, body := errBody(t, r)
	if r.status != 424 || body["OriginalStatusCode"].(float64) != 400 || !strings.Contains(body["Message"].(string), "Received client error (400)") || strings.ContainsAny(body["OriginalMessage"].(string), "\n\x00") {
		t.Errorf("a model's 400: %d %s", r.status, r.body)
	}
	r = f.invoke("stand", nil, "server")
	if _, body = errBody(t, r); r.status != 424 || body["OriginalStatusCode"].(float64) != 500 || body["OriginalMessage"] != "kaboom" {
		t.Errorf("a model's 500: %d %s", r.status, r.body)
	}
	if r = f.invoke("stand", nil, "big"); r.status != 424 || !strings.Contains(r.body, "larger than 6 MiB") {
		t.Errorf("a reply over 6 MiB: %d %.200s", r.status, r.body)
	}
	if r = f.invoke("stand", nil, "redirect"); r.status != 424 {
		t.Errorf("a redirect is an error, never followed: %d", r.status)
	}
	s := f.summary("stand")
	if s["viaHelper"].(float64) != 5 || s["backing"].(map[string]any)["mode"] != "helper" {
		t.Errorf("summary: %v", s)
	}
	// the model is gone, and slow
	f.helper.Close()
	if r = f.invoke("stand", nil, "x"); r.status != 424 || !strings.Contains(r.body, "did not answer") {
		t.Errorf("a stand-in that is down: %d %s", r.status, r.body)
	}
	g := startSM(t)
	g.srv.sm.timeout = 100 * time.Millisecond
	g.withHelper(func(w http.ResponseWriter, r *http.Request) { time.Sleep(2 * time.Second) })
	g.create("slow", nil, nil)
	g.setBacking("slow", `{"mode":"helper"}`)
	if r := g.invoke("slow", nil, "x"); r.status != 424 || !strings.Contains(r.body, "did not answer within") {
		t.Errorf("a slow model: %d %s", r.status, r.body)
	}
	// helper mode with no stand-in configured is refused when it is set, and a stand-in that is not configured cannot be named
	h := startSM(t)
	if r := h.control("PUT", "/e", `{"mode":"helper"}`); r.status != 422 || !strings.Contains(r.body, envSMHelper) {
		t.Errorf("no stand-in configured: %d %s", r.status, r.body)
	}
}

func TestImageModeIsNotAvailableYet(t *testing.T) {
	f := startSM(t)
	f.create("img", nil, nil)
	f.setBacking("img", `{"mode":"image"}`)
	r := f.invoke("img", nil, `{}`)
	code, body := errBody(t, r)
	if r.status != 503 || code != "ServiceUnavailable" || !strings.Contains(body["Message"].(string), "not available yet") {
		t.Errorf("image: %d %s", r.status, r.body)
	}
	if e := f.lastEntry("InvokeEndpoint"); e["marker"] != "not available yet" || e["unsupported"] != true {
		t.Errorf("the ledger: %v", e)
	}
	if c := f.counts("sagemaker-runtime")["InvokeEndpoint"]; c.Unsupported != 1 {
		t.Errorf("counted unsupported: %+v", c)
	}
	if s := f.summary("img"); s["notAvailable"].(float64) != 1 || s["faked"] != false || s["backing"].(map[string]any)["label"] != "not available yet" {
		t.Errorf("summary: %v", s)
	}
}

// ---- streaming

func TestStreamingCannedAndHelper(t *testing.T) {
	f := startSM(t)
	f.create("llm", nil, nil)
	f.setBacking("llm", `{"rules":[
	  {"match":{"bodyContains":"split"},"response":{"body":"héllo wörld, this is a streamed answer","partSize":8,"contentType":"text/plain"}},
	  {"match":{"bodyContains":"parts"},"response":{"parts":["a","b","c"],"partDelayMs":5}},
	  {"match":{"bodyContains":"broken"},"response":{"parts":["x","y"],"streamError":{"errorCode":"StreamBroken","message":"cut"}}},
	  {"match":{"bodyContains":"fail"},"response":{"error":{"code":"ModelError","originalStatusCode":500,"originalMessage":"nope"}}}
	]}`)
	r := f.stream("llm", map[string]string{"Content-Type": "application/json"}, "split it")
	if r.status != 200 || r.header.Get("Content-Type") != eventStreamContentType || r.header.Get("x-amzn-sagemaker-content-type") != "text/plain" ||
		r.header.Get("x-amzn-invoked-production-variant") != "AllTraffic" {
		t.Fatalf("stream headers: %d %v", r.status, r.header)
	}
	msgs, err := decodeEventStream([]byte(r.body))
	if err != nil {
		t.Fatal(err)
	}
	var joined string
	for _, m := range msgs {
		if m.headers[":event-type"] != "PayloadPart" || m.headers[":message-type"] != "event" || m.headers[":content-type"] != "application/octet-stream" {
			t.Errorf("event headers: %v", m.headers)
		}
		joined += string(m.payload)
	}
	if joined != "héllo wörld, this is a streamed answer" || len(msgs) < 4 {
		t.Errorf("parts: %d %q", len(msgs), joined)
	}
	msgs, _ = decodeEventStream([]byte(f.stream("llm", nil, "parts").body))
	if len(msgs) != 3 || string(msgs[0].payload) != "a" || string(msgs[2].payload) != "c" {
		t.Errorf("explicit parts: %v", msgs)
	}
	msgs, _ = decodeEventStream([]byte(f.stream("llm", nil, "broken").body))
	if len(msgs) != 3 || msgs[2].headers[":message-type"] != "exception" || msgs[2].headers[":exception-type"] != "ModelStreamError" ||
		!strings.Contains(string(msgs[2].payload), `"ErrorCode":"StreamBroken"`) || !strings.Contains(string(msgs[2].payload), `"Message":"cut"`) {
		t.Errorf("stream error: %+v", msgs)
	}
	if r := f.stream("llm", nil, "fail"); r.status != 424 || r.header.Get("X-Amzn-Errortype") != "ModelError" {
		t.Errorf("an error before the stream starts is an HTTP error: %d %s", r.status, r.body)
	}
	if r := f.stream("llm", nil, "nothing matches"); r.status != 424 {
		t.Errorf("unmatched: %d", r.status)
	}
	if s := f.summary("llm"); s["streamed"].(float64) != 5 {
		t.Errorf("streamed: %v", s)
	}
	if e := f.lastEntry("InvokeEndpointWithResponseStream"); e["marker"] == nil {
		t.Errorf("marker: %v", e)
	}

	// the model stand-in's chunked reply: one part per chunk; a broken reply ends with a ModelStreamError; an error status is an HTTP error
	g := startSM(t)
	g.withHelper(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if string(b) == "status" {
			w.WriteHeader(500)
			io.WriteString(w, "no stream")
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		fl := w.(http.Flusher)
		for i := 0; i < 3; i++ {
			fmt.Fprintf(w, "chunk-%d;", i)
			fl.Flush()
			time.Sleep(20 * time.Millisecond)
		}
		if string(b) == "die" {
			hj, _ := w.(http.Hijacker)
			c, _, _ := hj.Hijack()
			c.Close()
		}
	})
	g.create("m", nil, nil)
	g.setBacking("m", `{"mode":"helper"}`)
	msgs, err = decodeEventStream([]byte(g.stream("m", map[string]string{"X-Amzn-SageMaker-Accept": "text/event-stream"}, "go").body))
	if err != nil || len(msgs) < 1 {
		t.Fatalf("helper stream: %v", err)
	}
	var all string
	for _, m := range msgs {
		all += string(m.payload)
	}
	if all != "chunk-0;chunk-1;chunk-2;" || len(msgs) < 2 {
		t.Errorf("helper parts: %d %q", len(msgs), all)
	}
	r = g.stream("m", nil, "die")
	msgs, _ = decodeEventStream([]byte(r.body))
	if len(msgs) == 0 || msgs[len(msgs)-1].headers[":message-type"] != "exception" {
		t.Errorf("a broken reply ends with an exception event: %+v", msgs)
	}
	if r := g.stream("m", nil, "status"); r.status != 424 || !strings.Contains(r.body, "no stream") {
		t.Errorf("helper error status: %d %s", r.status, r.body)
	}
}

// ---- async

func (f *smFront) put(path, body string) {
	f.t.Helper()
	if r := f.do("PUT", path, merge(scopeHdr("s3"), map[string]string{"Content-Type": "application/json"}), body); r.status != 200 {
		f.t.Fatalf("PUT %s: %d", path, r.status)
	}
}

func (f *smFront) object(path string) (body, ctype string) {
	r := f.do("GET", "/__fake/smobject?p="+url.QueryEscape(path), nil, "")
	parts := strings.SplitN(r.body, "\n", 2)
	return parts[0], parts[1]
}

func (f *smFront) waitAsync() { f.srv.sm.asyncWG.Wait() }

func asyncCfg(extra map[string]any) map[string]any {
	nc := map[string]any{"SuccessTopic": "arn:aws:sns:us-east-1:000000000000:ok", "ErrorTopic": "arn:aws:sns:us-east-1:000000000000:bad",
		"IncludeInferenceResponseIn": []any{"SUCCESS_NOTIFICATION_TOPIC"}}
	for k, v := range extra {
		nc[k] = v
	}
	return map[string]any{"OutputConfig": map[string]any{"S3OutputPath": "s3://smbkt/out", "S3FailurePath": "s3://smbkt/err", "NotificationConfig": nc}}
}

func TestAsyncWritesTheOutputAndPublishes(t *testing.T) {
	f := startSM(t)
	f.create("batch", nil, asyncCfg(nil))
	f.setBacking("batch", `{"asyncDelayMs":1,"rules":[{"match":{"operation":"async","jsonPath":"$.n","equals":1},"response":{"json":{"result":"done"},"contentType":"application/json"}},
	  {"match":{"jsonPath":"$.n","equals":2},"response":{"error":{"code":"ModelError","originalStatusCode":500,"originalMessage":"bad row"}}}]}`)
	f.put("/smbkt/in-1.json", `{"n":1}`)
	f.put("/smbkt/in-2.json", `{"n":2}`)
	r := f.async("batch", map[string]string{"X-Amzn-SageMaker-InputLocation": "s3://smbkt/in-1.json", "X-Amzn-SageMaker-Inference-Id": "inf-1",
		"X-Amzn-SageMaker-Content-Type": "application/json"})
	if r.status != 202 || r.body != `{"InferenceId":"inf-1"}` || r.header.Get("x-amzn-sagemaker-outputlocation") != "s3://smbkt/out/inf-1.out" ||
		r.header.Get("x-amzn-sagemaker-failurelocation") != "s3://smbkt/err/inf-1-error.out" {
		t.Fatalf("async answer: %d %v %s", r.status, r.header, r.body)
	}
	f.waitAsync()
	if body, ctype := f.object("/smbkt/out/inf-1.out"); body != `{"result":"done"}` || ctype != "application/json" {
		t.Errorf("the output object: %q %q", body, ctype)
	}
	sns := f.do("GET", "/__fake/sns", nil, "").body
	if !strings.HasPrefix(sns, "arn:aws:sns:us-east-1:000000000000:ok {") {
		t.Fatalf("the success notification: %s", sns)
	}
	var ev map[string]any
	json.Unmarshal([]byte(strings.SplitN(sns, " ", 2)[1]), &ev)
	rp := ev["responseParameters"].(map[string]any)
	if ev["invocationStatus"] != "Completed" || ev["inferenceId"] != "inf-1" || rp["outputLocation"] != "s3://smbkt/out/inf-1.out" || ev["responseBody"] != `{"result":"done"}` ||
		ev["requestParameters"].(map[string]any)["inputLocation"] != "s3://smbkt/in-1.json" || ev["requestParameters"].(map[string]any)["endpointName"] != "batch" {
		t.Errorf("the notification: %v", ev)
	}
	// a failing answer: the error text goes to the failure location and the error topic
	r = f.async("batch", map[string]string{"X-Amzn-SageMaker-InputLocation": "s3://smbkt/in-2.json", "X-Amzn-SageMaker-Inference-Id": "inf-2"})
	f.waitAsync()
	if body, _ := f.object("/smbkt/err/inf-2-error.out"); !strings.Contains(body, "ModelError") || !strings.Contains(body, "bad row") {
		t.Errorf("the failure object: %q", body)
	}
	sns = f.do("GET", "/__fake/sns", nil, "").body
	if !strings.Contains(sns, "arn:aws:sns:us-east-1:000000000000:bad {") || !strings.Contains(sns, `"invocationStatus":"Failed"`) || !strings.Contains(sns, `"inferenceId":"inf-2"`) {
		t.Errorf("the error notification: %s", sns)
	}
	// an input that is not there fails the same way; so does an id the client made up badly
	f.async("batch", map[string]string{"X-Amzn-SageMaker-InputLocation": "s3://smbkt/missing.json", "X-Amzn-SageMaker-Inference-Id": "inf-3"})
	f.waitAsync()
	if body, _ := f.object("/smbkt/err/inf-3-error.out"); !strings.Contains(body, "input object could not be read") {
		t.Errorf("a missing input: %q", body)
	}
	s := f.summary("batch")
	if s["async"].(float64) != 3 || s["asyncCompleted"].(float64) != 1 || s["asyncFailed"].(float64) != 2 || s["matched"].(float64) != 2 || s["notificationFailures"].(float64) != 0 {
		t.Errorf("summary: %v", s)
	}
	if e := f.lastEntry("InvokeEndpointAsync"); e["status"].(float64) != 202 || !strings.Contains(e["marker"].(string), "asynchronous") {
		t.Errorf("entry: %v", e)
	}
	// an id is generated when none is sent; the locations use it
	r = f.async("batch", map[string]string{"X-Amzn-SageMaker-InputLocation": "s3://smbkt/in-1.json"})
	f.waitAsync()
	var ans map[string]string
	json.Unmarshal([]byte(r.body), &ans)
	if len(ans["InferenceId"]) != 36 || r.header.Get("x-amzn-sagemaker-outputlocation") != "s3://smbkt/out/"+ans["InferenceId"]+".out" {
		t.Errorf("a generated id: %s %v", r.body, r.header)
	}
}

func TestAsyncErrorsAndPlanRecording(t *testing.T) {
	f := startSM(t, "sagemaker", "sagemaker-runtime") // s3 and sns are not in the plan
	f.create("batch", nil, asyncCfg(nil))
	f.create("sync-only", nil, nil)
	hdr := func(loc string) map[string]string { return map[string]string{"X-Amzn-SageMaker-InputLocation": loc} }
	if r := f.async("sync-only", hdr("s3://smbkt/a")); r.status != 400 || !strings.Contains(r.body, "not configured for asynchronous inference") {
		t.Errorf("no async config: %d %s", r.status, r.body)
	}
	for _, loc := range []string{"", "http://smbkt/a", "s3://smbkt", "s3://smbkt/", "s3://Bad_Bucket/key"} {
		if r := f.async("batch", hdr(loc)); r.status != 400 || !strings.Contains(r.body, "InputLocation") {
			t.Errorf("input %q: %d %s", loc, r.status, r.body)
		}
	}
	if r := f.async("batch", with(hdr("s3://smbkt/a"), "X-Amzn-SageMaker-Inference-Id", "a/b")); r.status != 400 {
		t.Errorf("a bad inference id: %d", r.status)
	}
	if r := f.async("nope", hdr("s3://smbkt/a")); r.status != 400 || !strings.Contains(r.body, "not found") {
		t.Errorf("unknown endpoint: %d", r.status)
	}
	f.setBacking("batch", `{"asyncDelayMs":1,"default":{"body":"x"}}`)
	f.async("batch", hdr("s3://smbkt/a"))
	f.waitAsync()
	all := f.allCounts()
	if all["s3"]["sagemaker-runtime:s3:GetObject"].Calls != 1 || all["s3"]["sagemaker-runtime:s3:PutObject"].Calls != 1 ||
		all["sns"]["sagemaker-runtime:sns:Publish"].Calls != 1 {
		t.Errorf("the shim's own calls to unplanned services are recorded: %v", all)
	}
	// a bucket that does not exist: the output cannot be written; the failure is counted and published
	g := startSM(t)
	cfg := asyncCfg(nil)
	cfg["OutputConfig"].(map[string]any)["S3OutputPath"] = "s3://nobkt/out"
	g.create("nb", nil, cfg)
	g.setBacking("nb", `{"asyncDelayMs":1,"default":{"body":"x"}}`)
	g.put("/smbkt/in.json", `{}`)
	g.async("nb", map[string]string{"X-Amzn-SageMaker-InputLocation": "s3://smbkt/in.json", "X-Amzn-SageMaker-Inference-Id": "i1"})
	g.waitAsync()
	if s := g.summary("nb"); s["asyncFailed"].(float64) != 1 || s["asyncCompleted"].(float64) != 0 {
		t.Errorf("a failed write: %v", s)
	}
	if sns := g.do("GET", "/__fake/sns", nil, "").body; !strings.Contains(sns, ":bad {") || !strings.Contains(sns, "output could not be written") {
		t.Errorf("published as an error: %s", sns)
	}
}

// ---- the seed

func TestSeedDeclaresEndpoints(t *testing.T) {
	f := startSM(t)
	doc := `{"sagemaker":{"endpoints":[
	  {"name":"seeded","variants":["AllTraffic"],"AsyncInferenceConfig":` + string(mustJSON(asyncCfg(nil))) + `,"backing":{"source":"recorded","default":{"body":"hi"}}},
	  {"name":"Bad_Name"},
	  {"name":"helperless","backing":{"mode":"helper"}}]}}`
	r := f.do("POST", "/_rovara/seed", tok(), doc)
	if r.status != 422 {
		t.Fatalf("seed: %d %s", r.status, r.body)
	}
	var rep struct {
		Steps []struct {
			Name  string
			OK    bool
			Error string
		}
	}
	json.Unmarshal([]byte(r.body), &rep)
	if len(rep.Steps) != 3 || !rep.Steps[0].OK || rep.Steps[1].OK || rep.Steps[2].OK || !strings.Contains(rep.Steps[2].Error, envSMHelper) {
		t.Errorf("steps: %s", r.body)
	}
	if got := f.invoke("seeded", nil, `{}`); got.status != 200 || got.body != "hi" {
		t.Errorf("a seeded endpoint answers: %d %s", got.status, got.body)
	}
	if s := f.summary("seeded"); s["source"] != "seed" || s["asyncConfigured"] != true || s["backing"].(map[string]any)["label"] != "recorded fake" {
		t.Errorf("summary: %v", s)
	}
	calls := f.do("GET", "/__fake/smcalls", nil, "").body
	for _, want := range []string{"SageMaker.CreateModel", "SageMaker.CreateEndpointConfig", "SageMaker.CreateEndpoint", `"AsyncInferenceConfig"`} {
		if !strings.Contains(calls, want) {
			t.Errorf("the engine is told through its API (%s): %s", want, calls)
		}
	}
	// the plan must name sagemaker-runtime for the section, and the engine is told only when the plan names sagemaker
	g := startSM(t, "s3")
	if r := g.do("POST", "/_rovara/seed", tok(), `{"sagemaker":{"endpoints":[{"name":"x"}]}}`); r.status != 422 || !strings.Contains(r.body, "not in the plan") {
		t.Errorf("not planned: %d %s", r.status, r.body)
	}
	h := startSM(t, "sagemaker-runtime", "s3")
	if r := h.do("POST", "/_rovara/seed", tok(), `{"sagemaker":{"endpoints":[{"name":"x","backing":{"default":{"body":"y"}}}]}}`); r.status != 200 {
		t.Errorf("runtime only: %d %s", r.status, r.body)
	}
	if calls := h.do("GET", "/__fake/smcalls", nil, "").body; calls != "" {
		t.Errorf("the control plane is not in the plan, so the engine is not told: %s", calls)
	}
	if got := h.invoke("x", nil, `{}`); got.body != "y" {
		t.Errorf("answers: %d %s", got.status, got.body)
	}
	// the legacy mode has no shim
	l := startFront(t, nil)
	if r := l.do("POST", "/_rovara/seed", tok(), `{"sagemaker":{"endpoints":[{"name":"x"}]}}`); r.status != 422 {
		t.Errorf("legacy: %d %s", r.status, r.body)
	}
}

// ---- CloudFormation

const smTestTemplate = `{
 "Parameters": {"Suffix": {"Type":"String","Default":"dflt"}},
 "Resources": {
  "Bucket": {"Type":"AWS::S3::Bucket","Properties":{"BucketName":"smbkt"}},
  "Topic":  {"Type":"AWS::SNS::Topic","Properties":{"TopicName":"results"}},
  "Model":  {"Type":"AWS::SageMaker::Model","Properties":{"ModelName":{"Fn::Sub":"${AWS::StackName}-model"},"ExecutionRoleArn":{"Fn::GetAtt":["Role","Arn"]}}},
  "Config": {"Type":"AWS::SageMaker::EndpointConfig","Properties":{"EndpointConfigName":{"Fn::Join":["-",["cfg",{"Ref":"Suffix"}]]},
     "ProductionVariants":[{"VariantName":"AllTraffic","ModelName":{"Fn::GetAtt":["Model","ModelName"]},"InstanceType":"ml.m5.large"}],
     "AsyncInferenceConfig":{"OutputConfig":{"S3OutputPath":{"Fn::Sub":"s3://${Bucket}/out"},"NotificationConfig":{"SuccessTopic":{"Ref":"Topic"},"ErrorTopic":{"Fn::GetAtt":["Topic","TopicArn"]}}}}}},
  "Endpoint": {"Type":"AWS::SageMaker::Endpoint","Properties":{"EndpointName":"cfn-endpoint","EndpointConfigName":{"Fn::GetAtt":["Config","EndpointConfigName"]}}},
  "Unnamed": {"Type":"AWS::SageMaker::Endpoint","Properties":{"EndpointConfigName":"x"}},
  "Hidden": {"Type":"AWS::SageMaker::Endpoint","Properties":{"EndpointName":{"Ref":"Role"},"EndpointConfigName":"x"}}
 }}`

func (f *smFront) cfn(action string, params map[string]string) result {
	form := url.Values{"Action": {action}, "Version": {"2010-05-15"}}
	for k, v := range params {
		form.Set(k, v)
	}
	return f.do("POST", "/", with(scopeHdr("cloudformation"), "Content-Type", "application/x-www-form-urlencoded"), form.Encode())
}

func TestCloudFormationDeclaredEndpointsAreCreatedThroughTheAPI(t *testing.T) {
	f := startSM(t)
	if r := f.cfn("CreateStack", map[string]string{"StackName": "st", "TemplateBody": smTestTemplate}); r.status != 200 {
		t.Fatalf("CreateStack: %d %s", r.status, r.body)
	}
	s := f.summary("cfn-endpoint")
	if s["exists"] != true || s["source"] != "cloudformation" || s["configName"] != "cfg-dflt" || s["asyncConfigured"] != true || fmt.Sprint(s["variants"]) != "[AllTraffic]" {
		t.Errorf("the endpoint is in the table: %v", s)
	}
	calls := f.do("GET", "/__fake/smcalls", nil, "").body
	for _, want := range []string{`SageMaker.CreateModel {"ExecutionRoleArn"`, `"ModelName":"st-model"`, `"EndpointConfigName":"cfg-dflt"`,
		`"S3OutputPath":"s3://smbkt/out"`, `"SuccessTopic":"arn:aws:sns:us-east-1:000000000000:results"`, `"ErrorTopic":"arn:aws:sns:us-east-1:000000000000:results"`,
		`"EndpointName":"cfn-endpoint"`} {
		if !strings.Contains(calls, want) {
			t.Errorf("the engine is told %s: %s", want, calls)
		}
	}
	// a resource with no name of its own is named by the engine's physical id (what the stack's outputs and Ref carry)
	if s := f.summary("st-Unnamed-0123456789AB"); s["exists"] != true || s["configName"] != "x" {
		t.Errorf("an unnamed resource takes the engine's physical id: %v", s)
	}
	// what cannot be read is recorded, not guessed
	c := f.counts("sagemaker-runtime")
	if c["cloudformation:name-unresolved"].Unsupported != 1 || c["cloudformation:unnamed"].Calls != 0 {
		t.Errorf("unreadable resources are recorded: %v", c)
	}
	// no physical ids from the engine (yet): the unnamed resource is recorded, not created, and nothing waits for long
	smPhysicalWait = 100 * time.Millisecond
	defer func() { smPhysicalWait = 5 * time.Second }()
	h0 := startSM(t)
	h0.cfn("CreateStack", map[string]string{"StackName": "nophys", "TemplateBody": smTestTemplate})
	if c := h0.counts("sagemaker-runtime"); c["cloudformation:unnamed"].Unsupported != 1 {
		t.Errorf("an unnamed resource without a physical id: %v", c)
	}
	if r := h0.control("GET", "/cfn-endpoint", ""); r.status != 200 {
		t.Errorf("the named ones are created all the same: %d", r.status)
	}
	// it can be invoked
	f.setBacking("cfn-endpoint", `{"default":{"body":"ok"}}`)
	if r := f.invoke("cfn-endpoint", nil, `{}`); r.body != "ok" {
		t.Errorf("invoke: %d %s", r.status, r.body)
	}
	// a parameter given with the request wins over the default
	g := startSM(t)
	g.cfn("CreateStack", map[string]string{"StackName": "st2", "TemplateBody": smTestTemplate, "Parameters.member.1.ParameterKey": "Suffix", "Parameters.member.1.ParameterValue": "prod"})
	if s := g.summary("cfn-endpoint"); s["configName"] != "cfg-prod" {
		t.Errorf("parameters: %v", s)
	}
	// a change set creates nothing until it is executed
	h := startSM(t)
	h.cfn("CreateChangeSet", map[string]string{"StackName": "cs", "ChangeSetName": "set1", "TemplateBody": smTestTemplate})
	if r := h.control("GET", "/cfn-endpoint", ""); r.status != 404 {
		t.Errorf("not yet: %d", r.status)
	}
	h.cfn("ExecuteChangeSet", map[string]string{"StackName": "cs", "ChangeSetName": "set1"})
	if s := h.summary("cfn-endpoint"); s["exists"] != true {
		t.Errorf("executed: %v", s)
	}
	// the plan without sagemaker-runtime reads nothing; one without sagemaker still fills the table but never tells the engine
	i := startSM(t, "sagemaker-runtime", "cloudformation", "s3")
	i.cfn("CreateStack", map[string]string{"StackName": "st", "TemplateBody": smTestTemplate})
	if s := i.summary("cfn-endpoint"); s["exists"] != true {
		t.Errorf("table: %v", s)
	}
	if calls := i.do("GET", "/__fake/smcalls", nil, "").body; calls != "" {
		t.Errorf("the control plane is not planned: %s", calls)
	}
}

func TestTemplateResolver(t *testing.T) {
	tpl := &smTemplate{stack: "S", region: "eu-west-1", params: map[string]string{"P": "pv"}, res: map[string]map[string]any{
		"B": {"Type": "AWS::S3::Bucket", "Properties": map[string]any{"BucketName": "bkt"}},
		"U": {"Type": "AWS::S3::Bucket", "Properties": map[string]any{}},
	}}
	for in, want := range map[string]string{
		`"plain"`:                              "plain",
		`{"Ref":"AWS::StackName"}`:             "S",
		`{"Ref":"AWS::Region"}`:                "eu-west-1",
		`{"Ref":"P"}`:                          "pv",
		`{"Ref":"B"}`:                          "bkt",
		`{"Fn::Sub":"x-${P}-${!Literal}"}`:     "x-pv-${Literal}",
		`{"Fn::Sub":["${a}-${B}",{"a":"1"}]}`:  "1-bkt",
		`{"Fn::Join":[":",["a",{"Ref":"P"}]]}`: "a:pv",
	} {
		var v any
		json.Unmarshal([]byte(in), &v)
		if got, ok := tpl.resolve(v, 0); !ok || got != want {
			t.Errorf("%s: %q %v", in, got, ok)
		}
	}
	for _, in := range []string{`{"Ref":"U"}`, `{"Ref":"Nope"}`, `{"Fn::GetAtt":["B","Arn"]}`, `{"Fn::If":["c","a","b"]}`, `{"Fn::Sub":"${Missing}"}`, `5`, `{"a":1,"b":2}`,
		`{"Fn::Join":[",",[{"Ref":"Nope"}]]}`, `{"Fn::Sub":"${"}`} {
		var v any
		json.Unmarshal([]byte(in), &v)
		if got, ok := tpl.resolve(v, 0); ok {
			t.Errorf("%s resolved to %q", in, got)
		}
	}
}

// ---- configuration and the engine's own answers

// the helper client can dial nothing but the configured stand-ins
func TestHelperClientDialsOnlyConfiguredAddresses(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "yes") }))
	defer ok.Close()
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "no") }))
	defer other.Close()
	u, _ := url.Parse(ok.URL)
	c := newHelperClient([]*url.URL{u}, true)
	if resp, err := c.Get(ok.URL); err != nil {
		t.Fatalf("the configured address: %v", err)
	} else {
		resp.Body.Close()
	}
	if _, err := c.Get(other.URL); err == nil || !strings.Contains(err.Error(), "only the model stand-ins") {
		t.Errorf("another address is never dialled: %v", err)
	}
	if _, err := newHelperClient(nil, true).Get(ok.URL); err == nil {
		t.Error("with no stand-in configured nothing is dialled")
	}
}

func TestHelperConfig(t *testing.T) {
	env := func(m map[string]string) settings { return func(k string) string { return m[k] } }
	c, err := loadConfig(env(map[string]string{envSMHelper: "http://model-stand-in:8080, http://other:9000/"}))
	if err != nil || len(c.SageMakerHelpers) != 2 || c.SageMakerHelpers[0].String() != "http://model-stand-in:8080" || c.SageMakerHelpers[1].String() != "http://other:9000" {
		t.Fatalf("helpers: %v %v", err, c)
	}
	for _, bad := range []string{"https://x:1", "x:1", "http://", "http://x:1/path", "http://u:p@x:1", "http://x:1?q=1", "ftp://x"} {
		if _, err := loadConfig(env(map[string]string{envSMHelper: bad})); err == nil || !strings.Contains(err.Error(), envSMHelper) {
			t.Errorf("%s accepted", bad)
		}
	}
	if c, _ := loadConfig(env(nil)); len(c.SageMakerHelpers) != 0 {
		t.Error("none by default")
	}
}

// the legacy mode (no plan) forwards everything to the engine, as in 0.5.15: the shim is planned-mode only
func TestLegacyModeStillForwardsInvokesToTheEngine(t *testing.T) {
	f := startFront(t, nil)
	r := f.do("POST", "/endpoints/x/invocations", with(scopeHdr("sagemaker"), "Content-Type", "application/json"), `{}`)
	if r.status != 200 || r.body != "{}" {
		t.Errorf("forwarded to the (fake) engine: %d %s", r.status, r.body)
	}
	if f.srv.ledger.counts["sagemaker"] == nil {
		t.Error("counted under the legacy key")
	}
}

func TestBase64FixtureBodiesAndErrorsHaveNoNewlinesInHeaders(t *testing.T) {
	f := startSM(t)
	f.create("e", nil, nil)
	f.setBacking("e", `{"default":{"bodyBase64":"`+base64.StdEncoding.EncodeToString([]byte("raw\x00bytes"))+`","contentType":"application/x-test"}}`)
	if r := f.invoke("e", nil, ``); r.body != "raw\x00bytes" || r.header.Get("Content-Type") != "application/x-test" {
		t.Errorf("%q %v", r.body, r.header)
	}
	// a request body over 6 MiB is refused as the engine refuses it
	if r := f.invoke("e", nil, strings.Repeat("a", 6<<20+1)); r.status != 400 || !strings.Contains(r.body, "6 MiB") {
		t.Errorf("too large: %d %.100s", r.status, r.body)
	}
}

// ---- review fixes

// A template that refers to itself must not crash the front (a stack overflow cannot be recovered) and is unresolved, never followed.
func TestTemplateCyclesAreUnresolvedNotFollowed(t *testing.T) {
	tpl := &smTemplate{stack: "S", region: "us-east-1", params: map[string]string{}, res: map[string]map[string]any{
		"B":  {"Type": "AWS::S3::Bucket", "Properties": map[string]any{"BucketName": map[string]any{"Ref": "B"}}},
		"T":  {"Type": "AWS::SNS::Topic", "Properties": map[string]any{"TopicName": map[string]any{"Fn::GetAtt": []any{"T", "TopicName"}}}},
		"M":  {"Type": "AWS::SageMaker::Model", "Properties": map[string]any{"ModelName": map[string]any{"Fn::GetAtt": []any{"M", "ModelName"}}}},
		"X":  {"Type": "AWS::SageMaker::Model", "Properties": map[string]any{"ModelName": map[string]any{"Fn::GetAtt": []any{"Y", "ModelName"}}}},
		"Y":  {"Type": "AWS::SageMaker::Model", "Properties": map[string]any{"ModelName": map[string]any{"Fn::GetAtt": []any{"X", "ModelName"}}}},
		"S":  {"Type": "AWS::SNS::Topic", "Properties": map[string]any{"TopicName": map[string]any{"Fn::Sub": "${S}"}}},
		"OK": {"Type": "AWS::S3::Bucket", "Properties": map[string]any{"BucketName": "fine"}},
	}}
	for _, v := range []any{map[string]any{"Ref": "B"}, map[string]any{"Ref": "T"}, map[string]any{"Fn::GetAtt": []any{"M", "ModelName"}},
		map[string]any{"Fn::GetAtt": []any{"X", "ModelName"}}, map[string]any{"Fn::Sub": "${S}"}, map[string]any{"Fn::Sub": "a-${B}-b"}} {
		if got, ok := tpl.resolve(v, 0); ok {
			t.Errorf("%v resolved to %q", v, got)
		}
		tpl.visiting = nil
	}
	if got, ok := tpl.resolve(map[string]any{"Ref": "OK"}, 0); !ok || got != "fine" {
		t.Errorf("a resource that is not in a cycle still resolves: %q %v", got, ok)
	}
	// the names: a cycle is its own reason
	props := tpl.res["M"]["Properties"].(map[string]any)
	if _, reason := tpl.name("M", props, "ModelName", 0); reason != "cycle" {
		t.Errorf("reason: %s", reason)
	}
	// a nesting deeper than the bound is unresolved, however deep it is written (no recursion without a bound)
	var deep any = "x"
	for i := 0; i < 100000; i++ {
		deep = map[string]any{"Fn::Join": []any{"", []any{deep}}}
	}
	if _, ok := tpl.resolve(deep, 0); ok {
		t.Error("a value nested beyond the bound is unresolved")
	}
}

func TestTemplateWithCyclesDoesNotCrashTheFront(t *testing.T) {
	f := startSM(t)
	tplDoc := `{"Resources":{
	  "B":{"Type":"AWS::S3::Bucket","Properties":{"BucketName":{"Ref":"B"}}},
	  "Model":{"Type":"AWS::SageMaker::Model","Properties":{"ModelName":{"Fn::GetAtt":["Model","ModelName"]}}},
	  "Config":{"Type":"AWS::SageMaker::EndpointConfig","Properties":{"EndpointConfigName":"cyc-cfg","ProductionVariants":[{"VariantName":"V","ModelName":"m"}],
	     "AsyncInferenceConfig":{"OutputConfig":{"S3OutputPath":{"Ref":"B"}}}}},
	  "Endpoint":{"Type":"AWS::SageMaker::Endpoint","Properties":{"EndpointName":"cyc-ep","EndpointConfigName":{"Fn::GetAtt":["Config","EndpointConfigName"]}}}}}`
	if r := f.cfn("CreateStack", map[string]string{"StackName": "cyc", "TemplateBody": tplDoc}); r.status != 200 {
		t.Fatalf("CreateStack: %d %s", r.status, r.body)
	}
	c := f.counts("sagemaker-runtime")
	if c["cloudformation:cycle"].Unsupported != 1 || c["cloudformation:async-unresolved"].Unsupported != 1 {
		t.Errorf("recorded as unchecked: %v", c)
	}
	if s := f.summary("cyc-ep"); s["exists"] != true || s["asyncConfigured"] != false {
		t.Errorf("what can be read is created, the config without its async part: %v", s)
	}
}

func TestAsyncInputIsNotTruncatedAndOver16MiBIsRefused(t *testing.T) {
	f := startSM(t)
	f.create("big", nil, asyncCfg(nil))
	body7 := strings.Repeat("a", 7<<20) // more than the 6 MiB a synchronous call may carry
	f.setBacking("big", `{"asyncDelayMs":1,"rules":[{"match":{"bodySha256":"`+sha256hex(body7)+`"},"response":{"body":"whole"}}]}`)
	f.put("/smbkt/seven.bin", body7)
	f.async("big", map[string]string{"X-Amzn-SageMaker-InputLocation": "s3://smbkt/seven.bin", "X-Amzn-SageMaker-Inference-Id": "seven"})
	f.waitAsync()
	if body, _ := f.object("/smbkt/out/seven.out"); body != "whole" {
		t.Errorf("an input over 6 MiB arrives whole: %q", body)
	}
	f.put("/smbkt/huge.bin", strings.Repeat("b", 16<<20+1))
	f.async("big", map[string]string{"X-Amzn-SageMaker-InputLocation": "s3://smbkt/huge.bin", "X-Amzn-SageMaker-Inference-Id": "huge"})
	f.waitAsync()
	if body, _ := f.object("/smbkt/err/huge-error.out"); !strings.Contains(body, "larger than the 16 MiB") {
		t.Errorf("an input over 16 MiB is refused: %q", body)
	}
	if sns := f.do("GET", "/__fake/sns", nil, "").body; !strings.Contains(sns, "larger than the 16 MiB") {
		t.Errorf("and published as an error: %.300s", sns)
	}
	if e := f.lastEntry("InvokeEndpointAsync"); !strings.HasPrefix(e["marker"].(string), "hand-written fake; asynchronous") {
		t.Errorf("the async marker carries the label: %v", e["marker"])
	}
}

func TestAsyncMemoryBudget(t *testing.T) {
	b := newByteBudget(smAsyncBudget)
	b.acquire(smAsyncJobMem)
	b.acquire(smAsyncJobMem)
	var got atomic.Bool
	go func() { b.acquire(smAsyncJobMem); got.Store(true) }()
	time.Sleep(50 * time.Millisecond)
	if got.Load() {
		t.Fatal("a third job waits: the budget holds two")
	}
	b.release(smAsyncJobMem)
	for i := 0; i < 100 && !got.Load(); i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if !got.Load() {
		t.Error("a released budget lets the waiting job run")
	}
	if 2*smAsyncJobMem > smAsyncBudget || 3*smAsyncJobMem <= smAsyncBudget {
		t.Error("the budget is two jobs")
	}
}

func TestSplitPartsIsLinear(t *testing.T) {
	big := []byte(strings.Repeat("héllo wörld ", 700<<10/12*12/12)) // about 8 MiB of text
	start := time.Now()
	parts := splitParts(big, 64)
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("%d bytes took %s: splitting must be linear", len(big), d)
	}
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	if n != len(big) {
		t.Errorf("lost bytes: %d of %d", n, len(big))
	}
	// invalid UTF-8 is cut anywhere, a text never inside a character
	if parts := splitParts([]byte{0xff, 0xfe, 0xfd, 0xfc, 0xfb}, 2); len(parts) != 3 {
		t.Errorf("binary: %v", parts)
	}
}

// matching happens outside the state's lock, and a rule's `times` is still exact when calls race
func TestRuleTimesIsExactUnderConcurrency(t *testing.T) {
	f := startSM(t)
	f.create("race", nil, nil)
	f.setBacking("race", `{"rules":[{"match":{"bodyContains":"x"},"response":{"body":"rule"},"times":5}],"default":{"body":"default"}}`)
	var wg sync.WaitGroup
	var rules, defaults atomic.Int64
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			switch f.invoke("race", nil, "x").body {
			case "rule":
				rules.Add(1)
			case "default":
				defaults.Add(1)
			}
		}()
	}
	wg.Wait()
	if rules.Load() != 5 || defaults.Load() != 35 {
		t.Errorf("times: %d rule answers and %d default answers", rules.Load(), defaults.Load())
	}
}

func TestHelperAddressesNeverLoopbackOrLinkLocal(t *testing.T) {
	env := func(m map[string]string) settings { return func(k string) string { return m[k] } }
	for _, bad := range []string{"http://127.0.0.1:8080", "http://127.5.5.5", "http://[::1]:80", "http://169.254.169.254", "http://[fe80::1]:80",
		"http://0.0.0.0:80", "http://localhost-alias:80"} {
		saved := lookupIPs
		lookupIPs = func(host string) ([]net.IP, error) {
			if host == "localhost-alias" {
				return []net.IP{net.ParseIP("10.0.0.5"), net.ParseIP("127.0.0.1")}, nil
			}
			return nil, fmt.Errorf("no such host")
		}
		_, err := loadConfig(env(map[string]string{envSMHelper: bad}))
		lookupIPs = saved
		if err == nil || !strings.Contains(err.Error(), "loopback") {
			t.Errorf("%s accepted: %v", bad, err)
		}
	}
	// a stand-in that is not in DNS yet is accepted at start and resolved, once, at its first call; then the address is kept
	saved := lookupIPs
	defer func() { lookupIPs = saved }()
	var calls atomic.Int64
	answers := [][]net.IP{nil, {net.ParseIP("10.1.2.3")}, {net.ParseIP("10.9.9.9")}}
	lookupIPs = func(host string) ([]net.IP, error) {
		n := int(calls.Add(1)) - 1
		if n >= len(answers) || answers[n] == nil {
			return nil, fmt.Errorf("no such host")
		}
		return answers[n], nil
	}
	if _, err := loadConfig(env(map[string]string{envSMHelper: "http://stand-in:8080"})); err != nil {
		t.Fatalf("a name that does not resolve yet: %v", err)
	}
	if _, err := smResolveHelper("stand-in"); err != nil {
		t.Errorf("resolves at the second look: %v", err)
	}
	if _, err := smResolveHelper("127.0.0.1"); err == nil {
		t.Error("loopback refused")
	}
	if _, err := smResolveHelper("169.254.1.1"); err == nil {
		t.Error("link-local refused")
	}
}

// a stand-in's name is resolved once and the address is kept: a name that later answers differently is not followed
func TestHelperNameIsPinnedAfterTheFirstResolution(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	defer srv.Close()
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	saved := lookupIPs
	defer func() { lookupIPs = saved }()
	var calls atomic.Int64
	lookupIPs = func(host string) ([]net.IP, error) {
		if calls.Add(1) == 1 {
			return []net.IP{net.ParseIP("127.0.0.1")}, nil
		}
		return []net.IP{net.ParseIP("127.0.0.2")}, nil // where the server is not
	}
	u, _ := url.Parse("http://stand-in:" + port)
	c := newHelperClient([]*url.URL{u}, true)
	for i := 0; i < 3; i++ {
		c.CloseIdleConnections()
		resp, err := c.Get(u.String())
		if err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
		resp.Body.Close()
	}
	if calls.Load() != 1 {
		t.Errorf("the name was resolved %d times", calls.Load())
	}
}

// ---- the work one template may cost

// resolveCost builds a template of Model resources and returns how long reading all their names took, and the bytes allocated.
func resolveCost(t *testing.T, build func() map[string]map[string]any, root string) (time.Duration, uint64, *smTemplate, string, bool) {
	t.Helper()
	tpl := &smTemplate{stack: "S", region: "us-east-1", params: map[string]string{}, res: build()}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	start := time.Now()
	val, ok := tpl.resolve(map[string]any{"Fn::GetAtt": []any{root, "ModelName"}}, 0)
	d := time.Since(start)
	runtime.ReadMemStats(&after)
	return d, after.TotalAlloc - before.TotalAlloc, tpl, val, ok
}

func modelRes(name any) map[string]any {
	return map[string]any{"Type": "AWS::SageMaker::Model", "Properties": map[string]any{"ModelName": name}}
}

// The probes of the re-check: shared references fan out as W cubed (or worse) unless each attribute is read once and the template has a budget.
func TestTemplateFanOutIsBounded(t *testing.T) {
	const w = 1000
	sub := func(next string) any {
		return map[string]any{"Fn::Sub": strings.Repeat("${"+next+".ModelName}", w)}
	}
	join := func(next string, n int) any {
		items := make([]any, n)
		for i := range items {
			items[i] = map[string]any{"Fn::GetAtt": []any{next, "ModelName"}}
		}
		return map[string]any{"Fn::Join": []any{",", items}}
	}
	cases := map[string]func() map[string]map[string]any{
		"Fn::Sub W=1000 (W cubed)": func() map[string]map[string]any {
			return map[string]map[string]any{"M1": modelRes(sub("M2")), "M2": modelRes(sub("M3")), "M3": modelRes(sub("M4")), "M4": modelRes("x")}
		},
		"Fn::Join W=300": func() map[string]map[string]any {
			return map[string]map[string]any{"M1": modelRes(join("M2", 300)), "M2": modelRes(join("M3", 300)), "M3": modelRes(join("M4", 300)), "M4": modelRes("x")}
		},
		"a width-100 GetAtt DAG": func() map[string]map[string]any {
			res := map[string]map[string]any{"L5": modelRes("x")}
			for i := 4; i >= 1; i-- {
				res[fmt.Sprintf("L%d", i)] = modelRes(join(fmt.Sprintf("L%d", i+1), 100))
			}
			return res
		},
	}
	for name, build := range cases {
		root := "M1"
		if strings.Contains(name, "DAG") {
			root = "L1"
		}
		d, alloc, tpl, _, ok := resolveCost(t, build, root)
		if d > time.Second || alloc > 64<<20 {
			t.Errorf("%s: took %s and allocated %d MiB", name, d, alloc>>20)
		}
		if ok || !tpl.exceeded {
			t.Errorf("%s: the budget must be exceeded and the value unresolved (ok=%v exceeded=%v)", name, ok, tpl.exceeded)
		}
	}
	// a template within the budget still resolves, and a shared attribute is read once
	res := map[string]map[string]any{"M1": modelRes(map[string]any{"Fn::Sub": strings.Repeat("${M2.ModelName}-", 50)}), "M2": modelRes("short")}
	_, _, tpl, val, ok := resolveCost(t, func() map[string]map[string]any { return res }, "M1")
	if !ok || val != strings.Repeat("short-", 50) || tpl.exceeded {
		t.Errorf("within budget: %v %v", ok, tpl.exceeded)
	}
	if tpl.steps > 200 {
		t.Errorf("each attribute is read once, not once per reference: %d steps", tpl.steps)
	}
}

// Through the front: the probe is answered at once, recorded as cloudformation:unresolved, the front stays up, and the literal-named
// resources of the same template are still created.
func TestFanOutTemplateThroughTheFront(t *testing.T) {
	f := startSM(t)
	sub := func(next string) string {
		return `{"Fn::Sub":"` + strings.Repeat("${"+next+".ModelName}", 700) + `"}`
	}
	doc := `{"Resources":{
	  "M1":{"Type":"AWS::SageMaker::Model","Properties":{"ModelName":` + sub("M2") + `}},
	  "M2":{"Type":"AWS::SageMaker::Model","Properties":{"ModelName":` + sub("M3") + `}},
	  "M3":{"Type":"AWS::SageMaker::Model","Properties":{"ModelName":` + sub("M4") + `}},
	  "M4":{"Type":"AWS::SageMaker::Model","Properties":{"ModelName":"x"}},
	  "E":{"Type":"AWS::SageMaker::Endpoint","Properties":{"EndpointName":"fan-ep","EndpointConfigName":"fan-cfg"}}}}`
	start := time.Now()
	if r := f.cfn("CreateStack", map[string]string{"StackName": "fan", "TemplateBody": doc}); r.status != 200 {
		t.Fatalf("CreateStack: %d %s", r.status, r.body)
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("the request took %s", d)
	}
	if c := f.counts("sagemaker-runtime"); c["cloudformation:unresolved"].Unsupported != 1 {
		t.Errorf("recorded once as unresolved: %v", c)
	}
	if s := f.summary("fan-ep"); s["exists"] != true {
		t.Errorf("what is a literal is still created: %v", s)
	}
}

// the declarations are read once: the check and the creation share them
func TestDeclsAreReadOnce(t *testing.T) {
	f := startSM(t)
	tpl := f.srv.newSMTemplate(`{"Resources":{"M":{"Type":"AWS::SageMaker::Model","Properties":{"ModelName":{"Fn::Sub":"${AWS::StackName}-m"}}}}}`, url.Values{"StackName": {"s"}})
	a := tpl.decls()
	steps := tpl.steps
	b := tpl.decls()
	if &a[0] != &b[0] || tpl.steps != steps || a[0].name != "s-m" {
		t.Errorf("read twice: %d then %d steps", steps, tpl.steps)
	}
}

// ---- no backing: no answer (owner decision 141; the SM3 model stand-in is parked)

func wantNoAnswer(t *testing.T, what, name string, r result) {
	t.Helper()
	code, body := errBody(t, r)
	msg, _ := body["Message"].(string)
	if r.status != 400 || code != "ValidationError" || !strings.HasPrefix(msg, smNoAnswerMessagePrefix+name+".") ||
		!strings.Contains(msg, "No recording or fixture was approved for this endpoint") || !strings.Contains(msg, "the real model was not run") ||
		!strings.Contains(msg, "NOT RUN") || strings.Contains(r.header.Get("Content-Type"), "eventstream") {
		t.Errorf("%s: want the no-answer refusal, got %d %q %s", what, r.status, code, r.body)
	}
}

func TestNoBackingIsNeverTheStandInAndIsNotRun(t *testing.T) {
	f := startSM(t)
	var hits atomic.Int64
	f.withHelper(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		io.WriteString(w, `{"from":"the stand-in"}`)
	})
	const marker = "no-answer: no recording for this endpoint"
	f.create("orphan", nil, nil)
	f.create("batch", nil, asyncCfg(nil))
	f.put("/smbkt/in.json", `{"n":1}`)

	wantNoAnswer(t, "invoke", "orphan", f.invoke("orphan", map[string]string{"Content-Type": "application/json"}, `{"x":1}`))
	if e := f.lastEntry("InvokeEndpoint"); e["marker"] != marker || e["status"].(float64) != 400 {
		t.Errorf("invoke ledger entry: %v", e)
	}
	wantNoAnswer(t, "stream", "orphan", f.stream("orphan", map[string]string{"Content-Type": "application/json"}, `{"x":1}`))
	if e := f.lastEntry("InvokeEndpointWithResponseStream"); e["marker"] != marker {
		t.Errorf("stream ledger entry: %v", e)
	}
	// an async call is refused at once: not accepted, so no output or error file is waited for and nothing is published
	r := f.async("batch", map[string]string{"X-Amzn-SageMaker-InputLocation": "s3://smbkt/in.json", "X-Amzn-SageMaker-Inference-Id": "inf-na"})
	wantNoAnswer(t, "async", "batch", r)
	if r.header.Get("x-amzn-sagemaker-outputlocation") != "" {
		t.Errorf("an async refusal names no output: %v", r.header)
	}
	f.waitAsync()
	if e := f.lastEntry("InvokeEndpointAsync"); e["marker"] != marker {
		t.Errorf("async ledger entry: %v", e)
	}
	if body, _ := f.object("/smbkt/out/inf-na.out"); body != "" {
		t.Errorf("no output was written: %q", body)
	}
	if body, _ := f.object("/smbkt/err/inf-na-error.out"); body != "" {
		t.Errorf("no error file was written: %q", body)
	}
	if sns := f.do("GET", "/__fake/sns", nil, "").body; sns != "" {
		t.Errorf("nothing was published: %s", sns)
	}
	if hits.Load() != 0 {
		t.Fatalf("the stand-in was called %d times for endpoints with no backing", hits.Load())
	}
	s := f.summary("orphan")
	b := s["backing"].(map[string]any)
	if b["mode"] != "none" || b["label"] != "no answer" || s["faked"] != false || s["noAnswer"].(float64) != 2 || s["errors"].(float64) != 2 || s["viaHelper"].(float64) != 0 {
		t.Errorf("summary: %v", s)
	}
	if s := f.summary("batch"); s["noAnswer"].(float64) != 1 || s["async"].(float64) != 1 {
		t.Errorf("async summary: %v", s)
	}

	// the stand-in answers only an endpoint whose backing names it
	f.create("expl", nil, nil)
	f.setBacking("expl", `{"mode":"helper"}`)
	if r := f.invoke("expl", nil, "hi"); r.status != 200 || r.body != `{"from":"the stand-in"}` || hits.Load() != 1 {
		t.Errorf("an explicit stand-in backing is forwarded: %d %s hits=%d", r.status, r.body, hits.Load())
	}
	if e := f.lastEntry("InvokeEndpoint"); e["marker"] != "Rovara model stand-in" {
		t.Errorf("explicit marker: %v", e)
	}
	// canned (SM1/SM2) is unchanged: a rule, the default, and a miss
	f.create("canned", nil, nil)
	f.setBacking("canned", `{"source":"recorded","rules":[{"match":{"bodyContains":"known"},"response":{"body":"yes"}}]}`)
	if r := f.invoke("canned", nil, "known"); r.status != 200 || r.body != "yes" {
		t.Errorf("canned rule: %d %s", r.status, r.body)
	}
	if e := f.lastEntry("InvokeEndpoint"); e["marker"] != "recorded fake" {
		t.Errorf("canned marker: %v", e)
	}
	r = f.invoke("canned", nil, "other")
	if _, body := errBody(t, r); r.status != 424 || !strings.Contains(body["Message"].(string), "no recorded or canned answer matches") {
		t.Errorf("canned miss is still the unmatched ModelError: %d %s", r.status, r.body)
	}
	if e := f.lastEntry("InvokeEndpoint"); e["marker"] != "recorded fake; unmatched" {
		t.Errorf("canned miss marker: %v", e)
	}
	// removing a backing puts the endpoint back to no answer, never to the stand-in
	if r := f.control("DELETE", "/expl", ""); r.status != 200 {
		t.Fatalf("DELETE backing: %d", r.status)
	}
	wantNoAnswer(t, "after DELETE", "expl", f.invoke("expl", nil, "hi"))
	if hits.Load() != 1 {
		t.Errorf("the stand-in was called after the backing was removed: %d", hits.Load())
	}
	// "none" is what the front says, never something a document sets
	if r := f.control("PUT", "/expl", `{"mode":"none"}`); r.status != 422 {
		t.Errorf("mode none must not be settable: %d %s", r.status, r.body)
	}
}

func TestNoBackingWithNoStandInConfiguredIsAlsoNoAnswer(t *testing.T) {
	f := startSM(t)
	f.create("orphan", nil, nil)
	wantNoAnswer(t, "invoke", "orphan", f.invoke("orphan", nil, "x"))
	if e := f.lastEntry("InvokeEndpoint"); e["marker"] != "no-answer: no recording for this endpoint" {
		t.Errorf("marker: %v", e)
	}
	// the endpoint table of an endpoint nobody called says the same thing
	if s := f.summary("orphan"); s["backing"].(map[string]any)["mode"] != "none" || s["faked"] != false {
		t.Errorf("summary before any call: %v", s)
	}
}
