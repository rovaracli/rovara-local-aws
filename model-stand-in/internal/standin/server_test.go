package standin

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestPingAndExecutionParameters(t *testing.T) {
	e := newEnv(t, one(`{"kind":"fixed","body":"x"}`))
	if r := e.call("", "GET", "/ping", "", nil); r.status != 200 || r.body != "" {
		t.Fatalf("ping: %d %q", r.status, r.body)
	}
	if r := e.call("", "GET", "/execution-parameters", "", nil); r.status != 200 || !strings.Contains(r.body, "MaxPayloadInMB") {
		t.Fatalf("execution-parameters: %d %q", r.status, r.body)
	}
	if r := e.call("", "GET", "/invocations", "", nil); r.status != 405 {
		t.Fatalf("GET /invocations should be 405, got %d", r.status)
	}
	if r := e.call("", "POST", "/other", "x", nil); r.status != 404 {
		t.Fatalf("unknown path should be 404, got %d", r.status)
	}
}

func TestJSONEcho(t *testing.T) {
	e := newEnv(t, one(`{"kind":"json_echo","fields":{"model":"fraud-v3","score":0.25}}`))
	r := e.invoke(`{"amount":12.5,"id":"a1"}`, map[string]string{"Content-Type": "application/json"})
	var got map[string]any
	if r.status != 200 || json.Unmarshal([]byte(r.body), &got) != nil {
		t.Fatalf("%d %q", r.status, r.body)
	}
	if got["amount"] != 12.5 || got["id"] != "a1" || got["model"] != "fraud-v3" || got["score"] != 0.25 {
		t.Fatalf("got %v", got)
	}
	if r.header.Get("Content-Type") != "application/json" || r.header.Get("Content-Length") == "" {
		t.Fatalf("headers %v", r.header)
	}
	if r := e.invoke(`not json`, nil); r.status != 400 || strings.Contains(r.body, "not json") {
		t.Fatalf("a non-JSON body: %d %q", r.status, r.body)
	}
	w := newEnv(t, one(`{"kind":"json_echo","wrap":"input"}`))
	if r := w.invoke(`[1,2]`, nil); r.body != `{"input":[1,2]}` {
		t.Fatalf("wrap: %q", r.body)
	}
}

func TestFixed(t *testing.T) {
	e := newEnv(t, one(`{"kind":"fixed","json":{"label":"ok","n":[1,2]},"custom_attributes":"v=1"}`))
	r := e.invoke(`anything`, nil)
	if r.status != 200 || r.body != `{"label":"ok","n":[1,2]}` || r.header.Get(HeaderCustomAttributes) != "v=1" {
		t.Fatalf("%d %q %v", r.status, r.body, r.header)
	}
	b := newEnv(t, one(`{"kind":"fixed","body":"0.93","content_type":"text/plain"}`))
	if r := b.invoke(`x`, nil); r.body != "0.93" || r.header.Get("Content-Type") != "text/plain" {
		t.Fatalf("%q %v", r.body, r.header)
	}
}

func TestVectorShapeAndDeterminism(t *testing.T) {
	e := newEnv(t, `{"version":1,"seed":"s1","endpoints":{"ep":{"model":{"kind":"vector","size":3,"decimals":4}}}}`)
	body := `{"instances":[[1,2],[3,4],[5,6]]}`
	r1, r2 := e.invoke(body, nil), e.invoke(body, nil)
	if r1.body != r2.body {
		t.Fatalf("the same request must get the same answer: %q vs %q", r1.body, r2.body)
	}
	var got struct{ Predictions [][]float64 }
	if err := json.Unmarshal([]byte(strings.Replace(r1.body, "predictions", "Predictions", 1)), &got); err != nil || len(got.Predictions) != 3 {
		t.Fatalf("shape: %q %v", r1.body, err)
	}
	for _, v := range got.Predictions {
		if len(v) != 3 {
			t.Fatalf("each instance has 3 numbers: %v", v)
		}
		for _, x := range v {
			if x < 0 || x > 1 {
				t.Fatalf("outside [0,1]: %v", x)
			}
		}
	}
	if other := e.invoke(`{"instances":[[9,9]]}`, nil); other.body == r1.body {
		t.Fatal("a different request should usually differ")
	}
	// another seed gives another answer
	e2 := newEnv(t, `{"version":1,"seed":"s2","endpoints":{"ep":{"model":{"kind":"vector","size":3,"decimals":4}}}}`)
	if e2.invoke(body, nil).body == r1.body {
		t.Fatal("a different seed should differ")
	}
}

func TestVectorSingleScalarNormalizeAndKeys(t *testing.T) {
	e := newEnv(t, one(`{"kind":"vector","size":1,"scalar":true,"key":"score","min":10,"max":20,"decimals":0}`))
	var got map[string]float64
	if r := e.invoke(`{"a":1}`, nil); json.Unmarshal([]byte(r.body), &got) != nil || got["score"] < 10 || got["score"] > 20 || got["score"] != float64(int(got["score"])) {
		t.Fatalf("scalar: %q", r.body)
	}
	n := newEnv(t, one(`{"kind":"vector","size":4,"normalize":true,"key":"p","instances_key":"rows"}`))
	var probs struct{ P [][]float64 }
	r := n.invoke(`{"rows":[1,2]}`, nil)
	if json.Unmarshal([]byte(strings.Replace(r.body, `"p"`, `"P"`, 1)), &probs) != nil || len(probs.P) != 2 {
		t.Fatalf("%q", r.body)
	}
	for _, v := range probs.P {
		sum := 0.0
		for _, x := range v {
			sum += x
		}
		if sum < 0.999 || sum > 1.001 {
			t.Fatalf("normalised vector sums to %v", sum)
		}
	}
	// a top-level array is the instances
	if r := e.invoke(`[1,2,3]`, nil); !strings.HasPrefix(r.body, `{"score":[`) {
		t.Fatalf("array request: %q", r.body)
	}
}

func TestLabel(t *testing.T) {
	e := newEnv(t, one(`{"kind":"label","labels":["fraud","ok"],"with_probabilities":true}`))
	var one struct {
		Label         string
		Score         float64
		Probabilities map[string]float64
	}
	r := e.invoke(`{"amount":1}`, nil)
	if err := json.Unmarshal([]byte(strings.NewReplacer(`"label"`, `"Label"`, `"score"`, `"Score"`, `"probabilities"`, `"Probabilities"`).Replace(r.body)), &one); err != nil {
		t.Fatalf("%q %v", r.body, err)
	}
	if (one.Label != "fraud" && one.Label != "ok") || one.Score <= 0 || one.Score > 1 || len(one.Probabilities) != 2 {
		t.Fatalf("%+v", one)
	}
	if one.Probabilities[one.Label] < one.Probabilities["fraud"] || one.Probabilities[one.Label] < one.Probabilities["ok"] {
		t.Fatalf("the chosen label must have the largest probability: %+v", one)
	}
	list := e.invoke(`{"instances":[1,2,3,4]}`, nil)
	if !strings.HasPrefix(list.body, `{"predictions":[{`) || strings.Count(list.body, `"label"`) != 4 {
		t.Fatalf("%q", list.body)
	}
}

func TestCSV(t *testing.T) {
	e := newEnv(t, one(`{"kind":"csv","columns":2,"skip_header":true,"header":["a","b"],"decimals":3}`))
	r := e.invoke("x,y,z\n1,2,3\n4,5,6\n", map[string]string{"Content-Type": "text/csv"})
	lines := strings.Split(strings.TrimSpace(r.body), "\n")
	if r.status != 200 || r.header.Get("Content-Type") != "text/csv" || len(lines) != 3 || lines[0] != "a,b" {
		t.Fatalf("%d %q %v", r.status, r.body, r.header)
	}
	for _, l := range lines[1:] {
		if len(strings.Split(l, ",")) != 2 {
			t.Fatalf("two columns: %q", l)
		}
	}
	lab := newEnv(t, one(`{"kind":"csv","labels":["yes","no"]}`))
	if r := lab.invoke("1,2\n3,4\n", nil); strings.Count(r.body, "\n") != 2 {
		t.Fatalf("%q", r.body)
	}
	if r := e.invoke("a,\"b\n", nil); r.status != 200 && r.status != 400 {
		t.Fatalf("a bad CSV is answered, not crashed: %d", r.status)
	}
}

func TestSchemaKind(t *testing.T) {
	schema := `{"type":"object","properties":{
	  "id":{"type":"string","format":"uuid"},
	  "score":{"type":"number","minimum":0.5,"maximum":0.6},
	  "count":{"type":"integer","minimum":3,"maximum":5},
	  "flag":{"type":"boolean"},
	  "tags":{"type":"array","items":{"type":"string","maxLength":6},"minItems":2,"maxItems":2},
	  "kind":{"enum":["a","b"]},
	  "at":{"type":"string","format":"date-time"},
	  "nested":{"type":"object","properties":{"email":{"type":"string","format":"email"}}}}}`
	e := newEnv(t, one(`{"kind":"schema","schema":`+schema+`}`))
	r := e.invoke(`{"q":1}`, nil)
	var got struct {
		ID     string
		Score  float64
		Count  int
		Flag   bool
		Tags   []string
		Kind   string
		At     string
		Nested struct{ Email string }
	}
	fixed := strings.NewReplacer(`"id"`, `"ID"`, `"score"`, `"Score"`, `"count"`, `"Count"`, `"flag"`, `"Flag"`, `"tags"`, `"Tags"`, `"kind"`, `"Kind"`, `"at"`, `"At"`, `"nested"`, `"Nested"`, `"email"`, `"Email"`).Replace(r.body)
	if err := json.Unmarshal([]byte(fixed), &got); err != nil {
		t.Fatalf("%q %v", r.body, err)
	}
	if len(got.ID) != 36 || got.Score < 0.5 || got.Score > 0.6 || got.Count < 3 || got.Count > 5 || len(got.Tags) != 2 || len(got.Tags[0]) > 6 || (got.Kind != "a" && got.Kind != "b") || !strings.HasSuffix(got.At, "Z") || !strings.Contains(got.Nested.Email, "@") {
		t.Fatalf("%q", r.body)
	}
	if r2 := e.invoke(`{"q":1}`, nil); r2.body != r.body {
		t.Fatal("same request, same reply")
	}
	if e.invoke(`{"q":2}`, nil).body == r.body {
		t.Fatal("another request should differ")
	}
}

func TestMultiModelRouting(t *testing.T) {
	e := newEnv(t, `{"version":1,"endpoints":{"mme":{"models":{
	  "a.tar.gz":{"kind":"fixed","body":"A"},
	  "b.tar.gz":{"kind":"fixed","body":"B"}}}}}`)
	h := func(m string) map[string]string { return map[string]string{HeaderTargetModel: m} }
	if r := e.invoke("x", h("a.tar.gz")); r.body != "A" {
		t.Fatalf("a: %q", r.body)
	}
	if r := e.invoke("x", h("b.tar.gz")); r.body != "B" {
		t.Fatalf("b: %q", r.body)
	}
	if r := e.invoke("x", h("c.tar.gz")); r.status != 404 || strings.Contains(r.body, "c.tar.gz") {
		t.Fatalf("unknown model: %d %q", r.status, r.body)
	}
	if r := e.invoke("x", nil); r.status != 400 {
		t.Fatalf("no target header on a multi-model endpoint: %d", r.status)
	}
	// with a fallback model the header is optional
	f := newEnv(t, `{"version":1,"endpoints":{"mme":{"model":{"kind":"fixed","body":"D"},"models":{"a":{"kind":"fixed","body":"A"}}}}}`)
	if r := f.invoke("x", nil); r.body != "D" {
		t.Fatalf("fallback: %q", r.body)
	}
	// a single-model endpoint ignores the header
	s := newEnv(t, one(`{"kind":"fixed","body":"S"}`))
	if r := s.invoke("x", h("whatever")); r.body != "S" {
		t.Fatalf("single: %q", r.body)
	}
	// a seed makes two models answer differently for the same request
	v := newEnv(t, `{"version":1,"endpoints":{"mme":{"models":{"a":{"kind":"vector","size":4},"b":{"kind":"vector","size":4}}}}}`)
	if v.invoke("same", h("a")).body == v.invoke("same", h("b")).body {
		t.Fatal("two models should not give the same numbers")
	}
}

func TestEndpointRouting(t *testing.T) {
	e := newEnv(t, `{"version":1,"default_endpoint":"one","endpoints":{
	  "one":{"model":{"kind":"fixed","body":"1"}},
	  "two":{"port":8081,"model":{"kind":"fixed","body":"2"}}}}`)
	if r := e.invoke("x", nil); r.body != "1" {
		t.Fatalf("default: %q", r.body)
	}
	if r := e.invoke("x", map[string]string{HeaderEndpoint: "two"}); r.body != "2" {
		t.Fatalf("by header: %q", r.body)
	}
	if r := e.invoke("x", map[string]string{HeaderEndpoint: "nope"}); r.status != 404 {
		t.Fatalf("unknown endpoint: %d", r.status)
	}
	if r := e.call("two", "POST", "/invocations", "x", nil); r.body != "2" {
		t.Fatalf("own listener: %q", r.body)
	}
	ls := e.srv.Listeners()
	if len(ls) != 2 || ls[0].Addr != ":8080" || ls[1].Addr != ":8081" || ls[1].Endpoint != "two" {
		t.Fatalf("listeners: %+v", ls)
	}
	two := newEnv(t, `{"version":1,"endpoints":{"one":{"model":{"kind":"fixed","body":"1"}},"two":{"model":{"kind":"fixed","body":"2"}}}}`)
	if r := two.invoke("x", nil); r.status != 400 {
		t.Fatalf("two endpoints and no default: %d", r.status)
	}
}

func TestErrorsFailFirstAndRate(t *testing.T) {
	e := newEnv(t, one(`{"kind":"fixed","body":"ok","fail_first":2,"error_status":503,"error_message":"warming up"}`))
	for i := 0; i < 2; i++ {
		if r := e.invoke("x", nil); r.status != 503 || r.body != `{"error":"warming up"}` {
			t.Fatalf("call %d: %d %q", i, r.status, r.body)
		}
	}
	if r := e.invoke("x", nil); r.status != 200 {
		t.Fatalf("third call: %d", r.status)
	}
	rate := func() []int {
		e := newEnv(t, `{"version":1,"seed":"r","endpoints":{"ep":{"model":{"kind":"fixed","body":"ok","error_rate":0.5}}}}`)
		var out []int
		for i := 0; i < 40; i++ {
			out = append(out, e.invoke("x", nil).status)
		}
		return out
	}
	a, b := rate(), rate()
	fails := 0
	for i := range a {
		if a[i] != b[i] {
			t.Fatal("the failure sequence of one seed must repeat")
		}
		if a[i] == 500 {
			fails++
		}
	}
	if fails < 8 || fails > 32 {
		t.Fatalf("a rate of 0.5 failed %d of 40", fails)
	}
	if e.invoke("x", nil).status != 200 {
		t.Fatal("never fails at rate 0")
	}
}

func TestLatencyAndAccepts(t *testing.T) {
	e := newEnv(t, one(`{"kind":"fixed","body":"ok","latency_ms":60,"accepts":["application/json","text/csv"]}`))
	start := time.Now()
	r := e.invoke("x", map[string]string{"Content-Type": "application/json; charset=utf-8"})
	if r.status != 200 || time.Since(start) < 55*time.Millisecond {
		t.Fatalf("%d after %v", r.status, time.Since(start))
	}
	if r := e.invoke("x", map[string]string{"Content-Type": "image/png"}); r.status != 415 {
		t.Fatalf("a type the model does not take: %d", r.status)
	}
	if r := e.invoke("x", nil); r.status != 415 {
		t.Fatalf("no content type: %d", r.status)
	}
}

func TestBodyLimit(t *testing.T) {
	e := newEnv(t, one(`{"kind":"fixed","body":"ok"}`))
	if r := e.invoke(strings.Repeat("a", MaxBody), nil); r.status != 200 {
		t.Fatalf("exactly 6 MiB is accepted: %d", r.status)
	}
	if r := e.invoke(strings.Repeat("a", MaxBody+1), nil); r.status != 413 {
		t.Fatalf("over 6 MiB: %d", r.status)
	}
	// a body with no declared length (chunked) is cut at the limit too
	req := httptest.NewRequest("POST", "/invocations", io.MultiReader(strings.NewReader(strings.Repeat("a", MaxBody)), strings.NewReader("b")))
	req.ContentLength = -1
	rec := httptest.NewRecorder()
	e.srv.handler("").ServeHTTP(rec, req)
	if rec.Code != 413 {
		t.Fatalf("chunked over 6 MiB: %d", rec.Code)
	}
}

func TestReplyLimit(t *testing.T) {
	big := strings.Repeat("a", MaxReply+1)
	cfg := `{"version":1,"endpoints":{"ep":{"model":{"kind":"fixed","body":"` + big + `"}}}}`
	if _, err := ParseConfig([]byte(cfg)); err == nil {
		t.Fatal("a fixed body over 6 MiB is refused at load")
	}
	e := newEnv(t, one(`{"kind":"vector","size":200000}`))
	if r := e.invoke(`{"instances":[1,2]}`, nil); r.status != 500 || !strings.Contains(r.body, "too large") {
		t.Fatalf("an amplifying request is refused: %d %q", r.status, r.body)
	}
}

func TestStreamIsChunkedAndWhole(t *testing.T) {
	cfg, err := ParseConfig([]byte(one(`{"kind":"fixed","body":"0123456789abcdef","stream":{"chunks":4,"delay_ms":30}}`)))
	if err != nil {
		t.Fatal(err)
	}
	var logs strings.Builder
	srv := httptest.NewServer(New(cfg, newLogger(&logs)).handler(""))
	defer srv.Close()
	start := time.Now()
	resp, err := http.Post(srv.URL+"/invocations", "text/plain", strings.NewReader("x"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.ContentLength != -1 || len(resp.TransferEncoding) == 0 || resp.TransferEncoding[0] != "chunked" {
		t.Fatalf("a stream is a chunked reply: length %d, encoding %v", resp.ContentLength, resp.TransferEncoding)
	}
	var pieces []string
	buf := make([]byte, 64)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			pieces = append(pieces, string(buf[:n]))
		}
		if err != nil {
			break
		}
	}
	if strings.Join(pieces, "") != "0123456789abcdef" {
		t.Fatalf("the pieces join to the reply: %v", pieces)
	}
	if time.Since(start) < 80*time.Millisecond {
		t.Fatalf("the chunks are spaced by delay_ms: %v", time.Since(start))
	}
}

func TestLogsNeverHoldBodies(t *testing.T) {
	e := newEnv(t, `{"version":1,"endpoints":{"ep":{"models":{
	  "tenant-secret-model":{"kind":"json_echo"}}}}}`)
	marker := "PII-4111-1111-1111-1111-jane.doe@example.com"
	e.invoke(`{"card":"`+marker+`"}`, map[string]string{HeaderTargetModel: "tenant-secret-model", HeaderCustomAttributes: marker, "Authorization": "Bearer " + marker})
	e.invoke(`not json `+marker, map[string]string{HeaderTargetModel: "tenant-secret-model"})
	e.invoke(`{}`, map[string]string{HeaderTargetModel: marker}) // an unknown target model: its name came from the caller
	out := e.logs.String()
	if strings.Contains(out, "4111") || strings.Contains(out, "jane.doe") || strings.Contains(out, "Bearer") || strings.Contains(out, "PII-") {
		t.Fatalf("a request value reached the log:\n%s", out)
	}
	if strings.Count(out, "msg=invocation") != 3 || !strings.Contains(out, "in_bytes=") || !strings.Contains(out, "body_sha8=") {
		t.Fatalf("one line per request with sizes and a hash:\n%s", out)
	}
	// and the error bodies repeat nothing of the request either
	if r := e.invoke(`not json `+marker, map[string]string{HeaderTargetModel: "tenant-secret-model"}); strings.Contains(r.body, "PII") {
		t.Fatalf("an error reply echoed the request: %q", r.body)
	}
}

func TestConcurrencyLimit(t *testing.T) {
	e := newEnv(t, one(`{"kind":"fixed","body":"ok"}`))
	for i := 0; i < maxInFlight; i++ {
		e.srv.sem <- struct{}{}
	}
	if r := e.invoke("x", nil); r.status != 503 {
		t.Fatalf("over the in-flight limit: %d", r.status)
	}
	<-e.srv.sem
	if r := e.invoke("x", nil); r.status != 200 {
		t.Fatalf("after one finished: %d", r.status)
	}
}

func TestHTTPServerHasTimeouts(t *testing.T) {
	s := NewHTTPServer(Listener{Addr: ":0", Handler: http.NewServeMux()})
	if s.ReadHeaderTimeout <= 0 || s.ReadTimeout <= 0 || s.WriteTimeout <= 0 || s.IdleTimeout <= 0 || s.MaxHeaderBytes <= 0 || s.MaxHeaderBytes > 1<<20 {
		t.Fatalf("every timeout and the header limit must be set: %+v", s)
	}
}

func TestBodyBudget(t *testing.T) {
	e := newEnv(t, one(`{"kind":"fixed","body":"ok"}`))
	// two 6 MiB requests are in flight (12 MiB of 16): a third is refused, a small one still fits
	if !e.srv.reserve(MaxBody) || !e.srv.reserve(MaxBody) {
		t.Fatal("two 6 MiB requests fit")
	}
	if r := e.invoke(strings.Repeat("a", MaxBody), nil); r.status != 503 {
		t.Fatalf("a third 6 MiB request: %d", r.status)
	}
	if r := e.invoke("small", nil); r.status != 200 {
		t.Fatalf("a small one still fits: %d", r.status)
	}
	e.srv.release(MaxBody)
	if r := e.invoke(strings.Repeat("a", MaxBody), nil); r.status != 200 {
		t.Fatalf("after one finished: %d", r.status)
	}
	if e.srv.held != MaxBody {
		t.Fatalf("every reservation is released: held %d", e.srv.held)
	}
}

// Requests built to make the stand-in allocate: millions of tiny array elements, CSV rows, or numbers to echo. Each is answered (a refusal is fine) inside a small memory budget.
func TestAmplifyingBodiesStayBounded(t *testing.T) {
	cases := map[string]struct{ model, body string }{
		"vector, 3M instances": {`{"kind":"vector","size":1,"scalar":true}`, `{"instances":[` + strings.Repeat("1,", 3_000_000) + `1]}`},
		"label, 3M instances":  {`{"kind":"label","labels":["a","b"]}`, `[` + strings.Repeat("1,", 3_000_000) + `1]`},
		"csv, 3M rows":         {`{"kind":"csv","columns":1}`, strings.Repeat("a\n", 3_000_000)},
		"echo, 3M numbers":     {`{"kind":"json_echo"}`, `{"x":[` + strings.Repeat("1,", 3_000_000) + `1]}`},
		"echo, wrapped":        {`{"kind":"json_echo","wrap":"in"}`, `[` + strings.Repeat("1,", 3_000_000) + `1]`},
		"vector, a string key": {`{"kind":"vector","size":2}`, `{"instances":"x"}`},
		"vector, broken array": {`{"kind":"vector","size":2}`, `{"instances":[1,2`},
	}
	for name, c := range cases {
		e := newEnv(t, one(c.model))
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		r := e.invoke(c.body, nil)
		runtime.ReadMemStats(&after)
		if r.status != 200 && r.status != 400 && r.status != 500 {
			t.Errorf("%s: status %d", name, r.status)
		}
		if alloc := (after.TotalAlloc - before.TotalAlloc) >> 20; alloc > 192 { // total allocation (garbage included), a guard against an O(n times body) blowup; the live peak is measured in the VM run
			t.Errorf("%s: allocated %d MiB for a %d MiB body", name, alloc, len(c.body)>>20)
		}
	}
}
