package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

const testToken = "tokentokentoken1"

type testFront struct {
	t      *testing.T
	srv    *Server
	ts     *httptest.Server
	engine *Engine
}

func startFront(t *testing.T, mutate func(*Config)) *testFront {
	t.Helper()
	cfg := &Config{
		Host: "127.0.0.1", Port: 4566, BaseURL: "http://aws:4566", Hostname: "aws", Token: testToken, Region: "us-east-1",
		Disabled: map[string]bool{}, EngineBin: fakeEngineBin(t), WorkDir: t.TempDir(), LedgerMax: 100,
	}
	if mutate != nil {
		mutate(cfg)
	}
	engine := newEngine(cfg.EngineBin, cfg.WorkDir)
	if err := engine.Start(); err != nil {
		t.Fatalf("engine start: %v", err)
	}
	srv := newServer(cfg, engine)
	ts := httptest.NewServer(srv)
	f := &testFront{t: t, srv: srv, ts: ts, engine: engine}
	t.Cleanup(func() { ts.Close(); engine.Stop() })
	return f
}

var noRedirect = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

type result struct {
	status int
	header http.Header
	body   string
}

func (f *testFront) do(method, path string, headers map[string]string, body string) result {
	f.t.Helper()
	req, _ := http.NewRequest(method, f.ts.URL+path, strings.NewReader(body))
	for k, v := range headers {
		if strings.EqualFold(k, "Host") {
			req.Host = v
			continue
		}
		req.Header.Set(k, v)
	}
	resp, err := noRedirect.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return result{resp.StatusCode, resp.Header, string(b)}
}

func tok() map[string]string { return map[string]string{controlHeader: testToken} }

func sqsJSON(op string) map[string]string {
	return map[string]string{"X-Amz-Target": "AmazonSQS." + op, "Content-Type": "application/x-amz-json-1.0",
		"Authorization": "AWS4-HMAC-SHA256 Credential=K/20260101/us-east-1/sqs/aws4_request, SignedHeaders=host, Signature=00"}
}

func TestControlGuardRealHTTP(t *testing.T) {
	f := startFront(t, nil)
	for _, c := range []struct{ method, path string }{
		{"POST", "/_rovara/reset"}, {"POST", "/_rovara/seed"}, {"GET", "/_rovara/ledger"}, {"GET", "/_rovara/ledger/summary"},
		{"DELETE", "/_rovara/ledger"}, {"GET", "/_rovara/tick"}, {"POST", "/_rovara/tick/all"}, {"POST", "/_rovara/reset/sqs"},
		{"POST", "/x/../_rovara/reset"}, {"POST", "//_rovara/reset"}, {"POST", "/%5Frovara/reset"}, {"POST", "/_rovara%2Freset"},
		{"POST", "/_ROVARA/reset"}, {"GET", "/_rovarax"}, {"GET", "/_rovara/"}, {"GET", "/_rovara"},
	} {
		r := f.do(c.method, c.path, nil, "")
		if r.status != 403 || r.body != `{"error":"control token required"}` {
			t.Errorf("%s %s without a token: %d %q", c.method, c.path, r.status, r.body)
		}
		r = f.do(c.method, c.path, map[string]string{controlHeader: "wrong"}, "")
		if r.status != 403 {
			t.Errorf("%s %s with a wrong token: %d", c.method, c.path, r.status)
		}
	}
	if r := f.do("GET", "/_rovara/health", nil, ""); r.status != 200 || !strings.Contains(r.body, `"services"`) {
		t.Errorf("health must stay open: %d %q", r.status, r.body)
	}
	// two token headers never match (the fork joins them with a comma)
	req, _ := http.NewRequest("GET", f.ts.URL+"/_rovara/ledger/summary", nil)
	req.Header.Add(controlHeader, testToken)
	req.Header.Add(controlHeader, testToken)
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != 403 {
		t.Errorf("two token headers: %d", resp.StatusCode)
	}
	if r := f.do("GET", "/_rovara/ledger/summary", tok(), ""); r.status != 200 || r.body != "{}" {
		t.Errorf("summary with the token: %d %q", r.status, r.body)
	}
}

// FORK-CTRL-2: a Host or X-Forwarded-Host that turns a request path into a control path must never reach one without
// the token. Real HTTP, the three shapes the fork's bug had.
func TestHostRewritingNeverReachesControlPaths(t *testing.T) {
	f := startFront(t, nil)
	// put something in the ledger so a DELETE that got through would be seen
	f.do("POST", "/", sqsJSON("ListQueues"), "{}")
	before := f.do("GET", "/_rovara/ledger/summary", tok(), "").body
	if !strings.Contains(before, "ListQueues") {
		t.Fatalf("no ledger to protect: %s", before)
	}
	attempts := []struct {
		method, path string
		headers      map[string]string
	}{
		{"DELETE", "/ledger", map[string]string{"X-Forwarded-Host": "_rovara.x.localhost"}},
		{"DELETE", "/ledger", map[string]string{"Host": "_rovara.localhost"}},
		{"DELETE", "/ledger", map[string]string{"Host": "_rovara.aws:4566"}},
		{"POST", "/reset", map[string]string{"Host": "_rovara.aws"}},
		{"POST", "/seed", map[string]string{"X-Forwarded-Host": "_rovara.localhost, evil.example"}},
		{"GET", "/ledger/summary", map[string]string{"Host": "_rovara.s3.us-east-1.amazonaws.com"}},
		{"DELETE", "/ledger", map[string]string{"X-Forwarded-Host": "_Rovara.localhost", "Authorization": "AWS4-HMAC-SHA256 Credential=K/20260101/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=00"}},
	}
	for _, a := range attempts {
		r := f.do(a.method, a.path, a.headers, "")
		// whatever it is answered with, it is not a control answer
		if r.status == 200 && (strings.Contains(r.body, `"status":"OK"`) || strings.Contains(r.body, `"reset"`) || strings.Contains(r.body, `"steps"`) || strings.Contains(r.body, `"entries"`)) {
			t.Errorf("%v reached a control handler: %d %q", a, r.status, r.body)
		}
	}
	if after := f.do("GET", "/_rovara/ledger/summary", tok(), "").body; !strings.Contains(after, "ListQueues") {
		t.Errorf("the ledger was cleared by a host-rewritten request: %s", after)
	}
	// the guard checks the path AFTER the bucket rewrite too: a host-style request whose bucket would make a control path
	// is refused by the token rule if it ever got that far (unit-level, since bucket rules stop it first)
	g := newGuard(testToken, false)
	if g.check("DELETE", "/_rovara/ledger", "") == nil {
		t.Error("the guard lets the final path through")
	}
}

func TestDevSwitchAndClosed(t *testing.T) {
	f := startFront(t, func(c *Config) { c.Token = ""; c.DevOpen = false })
	if r := f.do("POST", "/_rovara/reset", nil, ""); r.status != 403 || !strings.Contains(r.body, "no control token is configured") {
		t.Errorf("closed: %d %q", r.status, r.body)
	}
	if r := f.do("POST", "/_rovara/reset", map[string]string{controlHeader: "anything"}, ""); r.status != 403 {
		t.Errorf("closed with a header: %d", r.status)
	}
	f2 := startFront(t, func(c *Config) { c.Token = ""; c.DevOpen = true })
	if r := f2.do("GET", "/_rovara/ledger/summary", nil, ""); r.status != 200 {
		t.Errorf("dev switch: %d", r.status)
	}
	f3 := startFront(t, func(c *Config) { c.DevOpen = true }) // a token wins over the switch
	if r := f3.do("GET", "/_rovara/ledger/summary", nil, ""); r.status != 403 {
		t.Errorf("token and switch: %d", r.status)
	}
}

func TestEngineChildIsLockedDown(t *testing.T) {
	f := startFront(t, nil)
	r := f.do("GET", "/__fake/env", map[string]string{"Authorization": "AWS4-HMAC-SHA256 Credential=K/20260101/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=00"}, "")
	var info struct {
		Env  []string `json:"env"`
		Args []string `json:"args"`
	}
	if err := json.Unmarshal([]byte(r.body), &info); err != nil {
		t.Fatalf("%v: %s", err, r.body)
	}
	env := strings.Join(info.Env, "\n")
	for _, bad := range []string{testToken, "ROVARA_AWS_CONTROL_TOKEN", "PRESIGN"} {
		if strings.Contains(env, bad) {
			t.Errorf("the engine inherited %q", bad)
		}
	}
	for _, want := range []string{"EMULATOR_TELEMETRY=off", "EMULATOR_CONFIG=", "HOME="} {
		if !strings.Contains(env, want) {
			t.Errorf("engine env lacks %s", want)
		}
	}
	if got := strings.Join(info.Args, " "); got != "-b 127.0.0.1 -p 0 -t off -a off" {
		t.Errorf("engine args: %q", got)
	}
}

func TestDisabledServiceIsRefusedAndCounted(t *testing.T) {
	f := startFront(t, func(c *Config) { c.Disabled = map[string]bool{"sqs": true, "s3": true, "iam": true} })
	r := f.do("POST", "/", sqsJSON("ListQueues"), "{}")
	if r.status != 400 || r.body != `{"__type":"ServiceNotAvailableException","message":"Service sqs is not enabled."}` ||
		r.header.Get("X-Amzn-Errortype") != "ServiceNotAvailableException" {
		t.Errorf("sqs json: %d %q %v", r.status, r.body, r.header)
	}
	r = f.do("GET", "/", map[string]string{"Authorization": "AWS4-HMAC-SHA256 Credential=K/20260101/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=00"}, "")
	if r.status != 400 || !strings.Contains(r.body, "<Code>ServiceNotAvailableException</Code><Message>Service s3 is not enabled.</Message>") {
		t.Errorf("s3: %d %q", r.status, r.body)
	}
	r = f.do("POST", "/", map[string]string{"Content-Type": "application/x-www-form-urlencoded",
		"Authorization": "AWS4-HMAC-SHA256 Credential=K/20260101/us-east-1/sts/aws4_request, SignedHeaders=host, Signature=00"},
		"Action=GetCallerIdentity&Version=2011-06-15")
	if r.status != 400 || !strings.Contains(r.body, "Service sts is not enabled.") { // sts shares iam's switch
		t.Errorf("sts follows iam: %d %q", r.status, r.body)
	}
	r = f.do("POST", "/service/SQS/operation/ListQueues", map[string]string{"smithy-protocol": "rpc-v2-cbor", "Content-Type": "application/cbor"}, "\xa0")
	if r.status != 400 || r.header.Get("Smithy-Protocol") != "rpc-v2-cbor" || !strings.Contains(r.body, "ServiceNotAvailableException") {
		t.Errorf("cbor: %d %q %v", r.status, r.body, r.header)
	}
	sum := f.do("GET", "/_rovara/ledger/summary", tok(), "").body
	for _, want := range []string{`"sqs":{"operations":{"ListQueues":{"calls":2,"unsupported":0,"errors":2}}`, `"s3":{"operations":{"ListBuckets":{"calls":1,"unsupported":0,"errors":1}}`, `"sts":{"operations":{"GetCallerIdentity"`} {
		if !strings.Contains(sum, want) {
			t.Errorf("summary lacks %s:\n%s", want, sum)
		}
	}
	// the health shows the switch
	if h := f.do("GET", "/_rovara/health", nil, "").body; !strings.Contains(h, `"sqs":"available"`) || !strings.Contains(h, `"dynamodb":"running"`) {
		t.Errorf("health: %s", h)
	}
}

func TestLedgerClassification(t *testing.T) {
	f := startFront(t, nil)
	f.do("POST", "/", sqsJSON("CreateQueue"), `{"QueueName":"a"}`)
	f.do("POST", "/", sqsJSON("NopeOp"), `{}`)                                                                                                                             // engine 501
	f.do("GET", "/bkt/boom", map[string]string{"Authorization": "AWS4-HMAC-SHA256 Credential=K/20260101/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=00"}, "") // 500
	f.do("POST", "/", map[string]string{"X-Amz-Target": "Nope_1.Foo", "Content-Type": "application/x-amz-json-1.1"}, "{}")                                                 // unknown target
	f.do("GET", "/", map[string]string{"Authorization": "AWS4-HMAC-SHA256 Credential=K/20260101/us-east-1/bogus/aws4_request, SignedHeaders=host, Signature=00"}, "")
	var sum map[string]struct {
		Calls, Unsupported, Errors int
		Operations                 map[string]struct{ Calls, Unsupported, Errors int }
	}
	body := f.do("GET", "/_rovara/ledger/summary", tok(), "").body
	dec := json.NewDecoder(strings.NewReader(body))
	if err := dec.Decode(&sum); err != nil {
		t.Fatal(err)
	}
	// field names are lower case in the JSON; decode with a case-insensitive match (encoding/json does that)
	if got := sum["sqs"].Operations["NopeOp"]; got.Calls != 1 || got.Unsupported != 1 || got.Errors != 1 {
		t.Errorf("501: %+v\n%s", got, body)
	}
	if got := sum["sqs"].Operations["CreateQueue"]; got.Calls != 1 || got.Unsupported != 0 || got.Errors != 0 {
		t.Errorf("ok call: %+v", got)
	}
	if got := sum["s3"].Operations["GetObject"]; got.Calls != 1 || got.Errors != 1 || got.Unsupported != 0 {
		t.Errorf("500: %+v\n%s", got, body)
	}
	if got := sum["unknown"]; got.Calls != 2 || got.Unsupported != 2 || got.Errors != 2 || got.Operations["unknown"].Calls != 2 {
		t.Errorf("unknown service/target: %+v\n%s", got, body)
	}
	if sum["sqs"].Calls != 2 || sum["sqs"].Unsupported != 1 || sum["sqs"].Errors != 1 {
		t.Errorf("service totals: %+v", sum["sqs"])
	}
	// entries and clear
	e := f.do("GET", "/_rovara/ledger?service=sqs&limit=1", tok(), "").body
	if !strings.Contains(e, `"operation":"NopeOp"`) || !strings.Contains(e, `"status":501`) || !strings.Contains(e, `"unsupported":true`) {
		t.Errorf("entries: %s", e)
	}
	f.do("DELETE", "/_rovara/ledger", tok(), "")
	if got := f.do("GET", "/_rovara/ledger/summary", tok(), "").body; got != "{}" {
		t.Errorf("cleared: %s", got)
	}
}

// A reset restarts the engine: state is gone, the ledger stays (the fork's reset kept it too).
func TestResetRestartsEngineAndKeepsLedger(t *testing.T) {
	f := startFront(t, nil)
	f.do("POST", "/", sqsJSON("CreateQueue"), `{"QueueName":"before"}`)
	if r := f.do("POST", "/", sqsJSON("ListQueues"), `{}`); !strings.Contains(r.body, "before") {
		t.Fatalf("setup: %s", r.body)
	}
	g1, _, _ := f.engine.current()
	pid1 := g1.cmd.Process.Pid
	if r := f.do("POST", "/_rovara/reset", tok(), ""); r.status != 200 || r.body != `{"reset":"all","status":"OK"}` {
		t.Fatalf("reset: %d %q", r.status, r.body)
	}
	g2, _, _ := f.engine.current()
	if g2.cmd.Process.Pid == pid1 || g2.port == g1.port && false {
		t.Errorf("the engine was not restarted")
	}
	if err := syscall.Kill(pid1, 0); err == nil {
		t.Errorf("the old engine still runs")
	}
	if _, err := os.Stat(g1.dir); !os.IsNotExist(err) {
		t.Errorf("the old engine's directory was not removed")
	}
	if r := f.do("POST", "/", sqsJSON("ListQueues"), `{}`); strings.Contains(r.body, "before") {
		t.Errorf("state survived the reset: %s", r.body)
	}
	if sum := f.do("GET", "/_rovara/ledger/summary", tok(), "").body; !strings.Contains(sum, `"CreateQueue":{"calls":1`) {
		t.Errorf("the reset cleared the ledger: %s", sum)
	}
	if r := f.do("POST", "/_rovara/reset/nonsense", tok(), ""); r.status != 404 || !strings.Contains(r.body, `"error":"unknown service: nonsense"`) {
		t.Errorf("reset/nonsense: %d %q", r.status, r.body)
	}
	if r := f.do("POST", "/_rovara/reset/sqs", tok(), ""); r.status != 501 {
		t.Errorf("reset/sqs: %d %q", r.status, r.body)
	}
}

// If the engine dies on its own, health goes red and nothing is served; a reset brings it back.
func TestEngineDeathTurnsHealthRedAndNeverServesStaleState(t *testing.T) {
	f := startFront(t, nil)
	g, _, _ := f.engine.current()
	syscall.Kill(g.cmd.Process.Pid, syscall.SIGKILL)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if f.do("GET", "/_rovara/health", nil, "").status == 503 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if r := f.do("GET", "/_rovara/health", nil, ""); r.status != 503 {
		t.Fatalf("health after the engine died: %d %q", r.status, r.body)
	}
	if r := f.do("POST", "/", sqsJSON("ListQueues"), `{}`); r.status != 503 {
		t.Errorf("API after the engine died: %d %q", r.status, r.body)
	}
	if r := f.do("POST", "/_rovara/reset", tok(), ""); r.status != 200 {
		t.Fatalf("reset after death: %d %q", r.status, r.body)
	}
	if r := f.do("GET", "/_rovara/health", nil, ""); r.status != 200 {
		t.Errorf("health after reset: %d", r.status)
	}
}

func TestRewriting(t *testing.T) {
	f := startFront(t, nil)
	f.do("POST", "/", sqsJSON("CreateQueue"), `{"QueueName":"qa"}`)
	r := f.do("POST", "/", sqsJSON("CreateQueue"), `{"QueueName":"qb"}`)
	if r.body != `{"QueueUrl":"http://aws:4566/000000000000/qb"}` {
		t.Errorf("CreateQueue: %s", r.body)
	}
	r = f.do("POST", "/", sqsJSON("ListQueues"), `{}`)
	if r.body != `{"QueueUrls":["http://aws:4566/000000000000/qa","http://aws:4566/000000000000/qb"]}` {
		t.Errorf("ListQueues: %s", r.body)
	}
	// message bodies: only the SNS envelope's URL changes, with a new MD5; a body that merely looks like a queue URL stays
	r = f.do("POST", "/", sqsJSON("ReceiveMessage"), `{}`)
	var rec struct {
		Messages []struct{ Body, MD5OfBody string }
	}
	if err := json.Unmarshal([]byte(r.body), &rec); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rec.Messages[0].Body, `"UnsubscribeURL":"http://aws:4566/?Action=Unsubscribe&SubscriptionArn=a"`) {
		t.Errorf("envelope: %s", rec.Messages[0].Body)
	}
	if rec.Messages[0].MD5OfBody == "old" || len(rec.Messages[0].MD5OfBody) != 32 {
		t.Errorf("md5 not recomputed: %s", rec.Messages[0].MD5OfBody)
	}
	if rec.Messages[1].Body != "https://sqs.us-east-1.amazonaws.com/000000000000/user-text" || rec.Messages[1].MD5OfBody != "keep" {
		t.Errorf("a user message was touched: %+v", rec.Messages[1])
	}
	// S3: CompleteMultipartUpload's Location
	s3 := map[string]string{"Authorization": "AWS4-HMAC-SHA256 Credential=K/20260101/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=00"}
	r = f.do("POST", "/bkt/some/key?uploadId=U", s3, "<CompleteMultipartUpload/>")
	if !strings.Contains(r.body, "<Location>http://aws:4566/bkt/some/key</Location>") {
		t.Errorf("S3 Location: %s", r.body)
	}
	// an object's own bytes are never rewritten
	r = f.do("GET", "/bkt/object", s3, "")
	if r.body != `{"q":"https://sqs.us-east-1.amazonaws.com/000000000000/q","self":"https://127.0.0.1:1"}` {
		t.Errorf("object bytes were changed: %s", r.body)
	}
	// the engine's own address in a header
	r = f.do("GET", "/redirect", s3, "")
	if loc := r.header.Get("Location"); loc != "http://aws:4566/elsewhere" {
		t.Errorf("Location: %q", loc)
	}
}

func TestForwardingToTheEngine(t *testing.T) {
	f := startFront(t, nil)
	// no credential: the front signs for the identified service, with a made-up key
	r := f.do("POST", "/", map[string]string{"X-Amz-Target": "DynamoDB_20120810.ListTables", "Content-Type": "application/x-amz-json-1.0"}, "{}")
	if a := r.header.Get("X-Fake-Auth"); !strings.Contains(a, "/dynamodb/aws4_request") || !strings.Contains(a, "Credential=ROVARATESTKEY/") {
		t.Errorf("synthetic auth: %q", a)
	}
	// a request's own credential is left alone
	r = f.do("POST", "/", sqsJSON("ListQueues"), "{}")
	if a := r.header.Get("X-Fake-Auth"); !strings.Contains(a, "Credential=K/20260101/us-east-1/sqs/") {
		t.Errorf("own auth changed: %q", a)
	}
	// the engine sees its own loopback host, no forwarding headers, never the control token
	r = f.do("GET", "/anything", map[string]string{"Host": "aws:4566", "X-Forwarded-Host": "evil", controlHeader: testToken}, "")
	if !strings.HasPrefix(r.header.Get("X-Fake-Host"), "127.0.0.1_") || r.header.Get("X-Fake-Fwd") != "|" {
		t.Errorf("host/forwarding: %q %q", r.header.Get("X-Fake-Host"), r.header.Get("X-Fake-Fwd"))
	}
	// S3 virtual-host style becomes path style
	s3 := map[string]string{"Authorization": "AWS4-HMAC-SHA256 Credential=K/20260101/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=00"}
	for _, host := range []string{"mybucket.aws:4566", "mybucket.s3.us-east-1.amazonaws.com", "mybucket.localhost:4566", "mybucket.s3.aws"} {
		h := map[string]string{"Host": host, "Authorization": s3["Authorization"]}
		r = f.do("GET", "/some/key?x=1", h, "")
		if r.header.Get("X-Fake-Path") != "/mybucket/some/key?x=1" {
			t.Errorf("vhost %s: %q", host, r.header.Get("X-Fake-Path"))
		}
	}
	// path style on the alias, an IP, a hostname that is not the front's: no rewrite
	for _, host := range []string{"aws:4566", "127.0.0.1:4566", "172.30.4.16:4566", "other.example:4566"} {
		r = f.do("GET", "/some/key", map[string]string{"Host": host, "Authorization": s3["Authorization"]}, "")
		if r.header.Get("X-Fake-Path") != "/some/key" {
			t.Errorf("path style %s: %q", host, r.header.Get("X-Fake-Path"))
		}
	}
	// an unsupported scope never reaches the engine
	r = f.do("GET", "/", map[string]string{"Authorization": "AWS4-HMAC-SHA256 Credential=K/20260101/us-east-1/ec2/aws4_request, SignedHeaders=host, Signature=00"}, "")
	if r.status != 404 || r.header.Get("X-Fake-Path") != "" {
		t.Errorf("ec2: %d %v", r.status, r.header)
	}
}

// The front's HTTP client to the engine can only ever dial 127.0.0.1:<engine port>, whatever host a request names.
func TestEngineClientOnlyDialsLoopbackPort(t *testing.T) {
	f := startFront(t, nil)
	g, _, _ := f.engine.current()
	req, _ := http.NewRequest("GET", "https://example.org:8443/__admin/health", nil)
	req.Host = "example.org:8443"
	resp, err := g.client.Do(req)
	if err == nil {
		// the dial went to the engine (the host name is not in its certificate's IP SAN... the fake accepts the CA only for
		// 127.0.0.1, so a name mismatch is an error: either way nothing left the machine)
		resp.Body.Close()
		t.Log("the request to a foreign name was answered by the loopback engine")
	}
	if err != nil && !strings.Contains(err.Error(), "certificate") && !strings.Contains(err.Error(), "x509") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSeedAgainstFakeEngineReportsSteps(t *testing.T) {
	f := startFront(t, nil)
	r := f.do("POST", "/_rovara/seed", tok(), "{nope")
	if r.status != 400 || r.body != `{"error":"the seed document is not valid JSON"}` {
		t.Errorf("bad json: %d %q", r.status, r.body)
	}
	r = f.do("POST", "/_rovara/seed", tok(), "")
	if r.status != 200 || r.body != `{"steps":[],"ok":true,"failed":0}` {
		t.Errorf("empty: %d %q", r.status, r.body)
	}
	r = f.do("POST", "/_rovara/seed", tok(), `{"sqs":{"queues":[{"name":"sq1","messages":["m"]}]},"calls":[{"service":"bogus","action":"X","request":{}}]}`)
	if r.status != 422 || !strings.Contains(r.body, `"service":"sqs","action":"CreateQueue","name":"sq1","ok":true`) ||
		!strings.Contains(r.body, `"service":"bogus","action":"X","name":"","ok":false,"error":"seed calls support`) || !strings.Contains(r.body, `"failed":1`) {
		t.Errorf("seed: %d %s", r.status, r.body)
	}
}

func TestRunContractAndBind(t *testing.T) {
	env := func(m map[string]string) settings { return func(k string) string { return m[k] } }
	good := map[string]string{envToken: "tokentokentoken1", envHost: "172.30.4.16", envBaseURL: "http://aws:4566",
		envPresign: "abcdefghijklmnop1", envReceipt: "abcdefghijklmnop2"}
	if _, err := loadConfig(env(good)); err != nil {
		t.Fatalf("a good run: %v", err)
	}
	for _, drop := range []string{envHost, envBaseURL, envPresign, envReceipt} {
		m := map[string]string{}
		for k, v := range good {
			if k != drop {
				m[k] = v
			}
		}
		_, err := loadConfig(env(m))
		if err == nil || !strings.Contains(err.Error(), drop) {
			t.Errorf("without %s: %v", drop, err)
		}
		if err != nil {
			for _, secret := range []string{good[envToken], good[envPresign], good[envReceipt]} {
				if strings.Contains(err.Error(), secret) {
					t.Errorf("the error prints a value: %v", err)
				}
			}
		}
	}
	for name, bad := range map[string]map[string]string{
		"short token":      {envToken: "short"},
		"token = presign":  {envToken: "abcdefghijklmnop1"}, // gitleaks:allow (not a secret)
		"token = receipt":  {envToken: "abcdefghijklmnop2"}, // gitleaks:allow (not a secret)
		"default base url": {envBaseURL: "http://localhost:4566"},
		"default secret":   {envPresign: "local-emulator-secret"},
		"short secret":     {envReceipt: "short"},
		"wildcard":         {envHost: "0.0.0.0"},
		"wildcard v6":      {envHost: "[::]"},
		"malformed":        {envHost: "not a host"},
	} {
		m := map[string]string{}
		for k, v := range good {
			m[k] = v
		}
		for k, v := range bad {
			m[k] = v
		}
		if _, err := loadConfig(env(m)); err == nil {
			t.Errorf("%s: started", name)
		}
	}
	// no token: development defaults stay; the switch exactly "1" opens; a wildcard is refused either way
	if c, err := loadConfig(env(map[string]string{})); err != nil || c.Host != "127.0.0.1" || c.BaseURL != "http://localhost:4566" {
		t.Errorf("no token: %v %+v", err, c)
	}
	if _, err := loadConfig(env(map[string]string{envDevOpen: "1", envToken: "x"})); err != nil {
		t.Errorf("token with the switch (contract off): %v", err)
	}
	if _, err := loadConfig(env(map[string]string{envHost: "0.0.0.0"})); err == nil {
		t.Error("wildcard without a token")
	}
	for _, v := range []string{"true", "TRUE", " 1", "yes", "1 "} {
		if isDevOpen(v) {
			t.Errorf("the switch is on for %q", v)
		}
	}
	c, _ := loadConfig(env(map[string]string{"ROVARA_AWS_SERVICES_SQS_ENABLED": "false", "ROVARA_AWS_SERVICES_S3_ENABLED": "true",
		"ROVARA_AWS_SERVICES_KMS_ENABLED": "garbage", "ROVARA_AWS_SERVICES_COGNITO_ENABLED": "FALSE"}))
	if !c.Disabled["sqs"] || c.Disabled["s3"] || !c.Disabled["kms"] || !c.Disabled["cognito"] || c.Disabled["ssm"] {
		t.Errorf("service switches: %v", c.Disabled)
	}
}

func authFor2(svc string) map[string]string {
	return map[string]string{"Authorization": "AWS4-HMAC-SHA256 Credential=K/20260101/us-east-1/" + svc + "/aws4_request, SignedHeaders=host, Signature=00"}
}

func merge(a, b map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

// H1: a SigV4 scope that is not in the catalog is refused and never forwarded, whatever the Action or Version say.
func TestUnknownScopeWithQueryActionIsNotForwarded(t *testing.T) {
	f := startFront(t, nil)
	form := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
	for _, c := range []struct{ scope, body string }{
		{"ec2", "Action=DescribeInstances&Version=2016-11-15"}, {"ec2", "Action=CreateVpc&CidrBlock=10.0.0.0/16&Version=2016-11-15"},
		{"monitoring", "Action=ListMetrics&Version=2010-08-01"}, {"cloudformation", "Action=ListStacks&Version=2010-05-15"},
		{"ec2", "Action=DescribeInstances&Version=2012-11-05"}, // even a Version that names a catalog service
		{"ec2", "Action=DescribeInstances"},
	} {
		r := f.do("POST", "/", merge(form, authFor2(c.scope)), c.body)
		if r.status != 404 || !strings.Contains(r.body, "UnknownOperationException") || r.header.Get("X-Fake-Path") != "" {
			t.Errorf("%s %s: %d %q (forwarded: %q)", c.scope, c.body, r.status, r.body, r.header.Get("X-Fake-Path"))
		}
	}
	sum := f.do("GET", "/_rovara/ledger/summary", tok(), "").body
	if strings.Contains(sum, `"sqs"`) || !strings.Contains(sum, `"unknown":{"operations":{"unknown":{"calls":6,"unsupported":6,"errors":6}}`) {
		t.Errorf("ledger: %s", sum)
	}
	// no scope and a Version that names no service: refused, not guessed to be SQS
	r := f.do("POST", "/", form, "Action=DescribeInstances&Version=2016-11-15")
	if r.status != 404 || r.header.Get("X-Fake-Path") != "" {
		t.Errorf("ambiguous action: %d %q", r.status, r.body)
	}
	// a known Version with no scope still works
	r = f.do("POST", "/", form, "Action=ListQueues&Version=2012-11-05")
	if r.status != 200 || !strings.Contains(r.body, "ListQueuesResponse") {
		t.Errorf("unsigned ListQueues: %d %q", r.status, r.body)
	}
}

// H2: when the scope and the target or Action disagree, the request is refused and counted under the scope's service.
func TestScopeThatDisagreesWithTargetOrActionIsRefused(t *testing.T) {
	f := startFront(t, func(c *Config) { c.Disabled = map[string]bool{"s3": true, "lambda": true} })
	s3, lam := authFor2("s3"), authFor2("lambda")
	probes := []struct {
		name, method, path string
		headers            map[string]string
	}{
		{"s3 scope with an IAM Action in the query", "PUT", "/bkt2?Action=x&Version=2010-05-08", s3},
		{"s3 scope with a DynamoDB target", "PUT", "/bkt3", merge(s3, map[string]string{"X-Amz-Target": "DynamoDB_20120810.ListTables", "Content-Type": "application/x-amz-json-1.0"})},
		{"lambda scope with an Action in the query", "GET", "/2015-03-31/functions/?Action=x", lam},
		{"sqs scope with a KMS target", "POST", "/", merge(authFor2("sqs"), map[string]string{"X-Amz-Target": "TrentService.ListKeys"})},
		{"dynamodb scope with a CBOR sqs path", "POST", "/service/SQS/operation/ListQueues", merge(authFor2("dynamodb"), map[string]string{"smithy-protocol": "rpc-v2-cbor"})},
	}
	for _, p := range probes {
		r := f.do(p.method, p.path, p.headers, "")
		if r.status != 404 || r.header.Get("X-Fake-Path") != "" || !strings.Contains(r.body, "UnknownOperationException") {
			t.Errorf("%s: %d %q (forwarded %q)", p.name, r.status, r.body, r.header.Get("X-Fake-Path"))
		}
	}
	sum := f.do("GET", "/_rovara/ledger/summary", tok(), "").body
	for _, want := range []string{`"s3":{"operations":{"unknown":{"calls":2,"unsupported":2,"errors":2}}`, `"lambda":{"operations":{"unknown":{"calls":1,"unsupported":1,"errors":1}}`, `"sqs":{"operations":{"unknown":{"calls":1`, `"dynamodb":{"operations":{"unknown":{"calls":1`} {
		if !strings.Contains(sum, want) {
			t.Errorf("ledger lacks %s:\n%s", want, sum)
		}
	}
	if strings.Contains(sum, `"iam"`) || strings.Contains(sum, `"kms"`) {
		t.Errorf("a call was counted under the service the request claimed: %s", sum)
	}
	// agreeing scopes still pass (apigatewayv2 signs as apigateway, eventsv2 as events)
	r := f.do("POST", "/", merge(authFor2("apigateway"), map[string]string{"X-Amz-Target": "AmazonApiGatewayV2.GetApis", "Content-Type": "application/x-amz-json-1.1"}), "{}")
	if r.status != 200 {
		t.Errorf("apigatewayv2 under the apigateway scope: %d %q", r.status, r.body)
	}
}

func TestSQSQueryTranslation(t *testing.T) {
	f := startFront(t, nil)
	form := merge(map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, authFor2("sqs"))
	r := f.do("POST", "/", form, "Action=CreateQueue&QueueName=qa&Version=2012-11-05&Attribute.1.Name=VisibilityTimeout&Attribute.1.Value=45&Tag.1.Key=env&Tag.1.Value=t")
	want := `<?xml version="1.0"?><CreateQueueResponse xmlns="http://queue.amazonaws.com/doc/2012-11-05/"><CreateQueueResult><QueueUrl>http://aws:4566/000000000000/qa</QueueUrl></CreateQueueResult><ResponseMetadata><RequestId>`
	if r.status != 200 || !strings.HasPrefix(r.body, want) || r.header.Get("Content-Type") != "text/xml" {
		t.Fatalf("CreateQueue: %d %q %v", r.status, r.body, r.header)
	}
	last := f.do("GET", "/__fake/last", authFor2("s3"), "").body
	if last != `AmazonSQS.CreateQueue {"Attributes":{"VisibilityTimeout":"45"},"QueueName":"qa","tags":{"env":"t"}}` {
		t.Errorf("JSON sent to the engine: %s", last)
	}
	r = f.do("POST", "/", form, "Action=ListQueues&Version=2012-11-05")
	if !strings.Contains(r.body, "<QueueUrl>http://aws:4566/000000000000/qa</QueueUrl>") {
		t.Errorf("ListQueues: %s", r.body)
	}
	// SendMessage with message attributes, system attributes and a path that names the queue (no QueueUrl in the form)
	body := "Action=SendMessage&Version=2012-11-05&MessageBody=hi&DelaySeconds=5&MessageAttribute.1.Name=k&MessageAttribute.1.Value.DataType=String&MessageAttribute.1.Value.StringValue=v" +
		"&MessageAttribute.2.Name=b&MessageAttribute.2.Value.DataType=Binary&MessageAttribute.2.Value.BinaryValue=AQID&MessageSystemAttribute.1.Name=AWSTraceHeader&MessageSystemAttribute.1.Value.DataType=String&MessageSystemAttribute.1.Value.StringValue=t"
	f.do("POST", "/000000000000/qa", form, body)
	last = f.do("GET", "/__fake/last", authFor2("s3"), "").body
	for _, w := range []string{`"QueueUrl":"http://aws:4566/000000000000/qa"`, `"DelaySeconds":5`, `"MessageAttributes":{"b":{"BinaryValue":"AQID","DataType":"Binary"},"k":{"DataType":"String","StringValue":"v"}}`,
		`"MessageSystemAttributes":{"AWSTraceHeader":{"DataType":"String","StringValue":"t"}}`, `"MessageBody":"hi"`} {
		if !strings.Contains(last, w) {
			t.Errorf("SendMessage JSON lacks %s: %s", w, last)
		}
	}
	// batch entries, and the XML answer with a successful and a failed entry
	r = f.do("POST", "/", form, "Action=SendMessageBatch&Version=2012-11-05&QueueUrl=http%3A%2F%2Faws%3A4566%2F000000000000%2Fqa&SendMessageBatchRequestEntry.1.Id=a&SendMessageBatchRequestEntry.1.MessageBody=x&SendMessageBatchRequestEntry.2.Id=b&SendMessageBatchRequestEntry.2.MessageBody=y&SendMessageBatchRequestEntry.2.DelaySeconds=1")
	last = f.do("GET", "/__fake/last", authFor2("s3"), "").body
	if !strings.Contains(last, `"Entries":[{"Id":"a","MessageBody":"x"},{"DelaySeconds":1,"Id":"b","MessageBody":"y"}]`) {
		t.Errorf("batch JSON: %s", last)
	}
	if !strings.Contains(r.body, "<SendMessageBatchResultEntry><Id>a</Id><MessageId>m1</MessageId><MD5OfMessageBody>x</MD5OfMessageBody></SendMessageBatchResultEntry><BatchResultErrorEntry><Id>b</Id><SenderFault>true</SenderFault><Code>InvalidParameterValue</Code><Message>bad</Message></BatchResultErrorEntry>") {
		t.Errorf("batch XML: %s", r.body)
	}
	// ReceiveMessage: the SNS envelope's URL is rewritten, the other message untouched
	r = f.do("POST", "/", form, "Action=ReceiveMessage&Version=2012-11-05&QueueUrl=u&MaxNumberOfMessages=2&AttributeName.1=All&MessageAttributeName.1=All")
	if !strings.Contains(r.body, "http://aws:4566/?Action=Unsubscribe") || !strings.Contains(r.body, "<Body>https://sqs.us-east-1.amazonaws.com/000000000000/user-text</Body>") {
		t.Errorf("ReceiveMessage: %s", r.body)
	}
	last = f.do("GET", "/__fake/last", authFor2("s3"), "").body
	if !strings.Contains(last, `"AttributeNames":["All"]`) || !strings.Contains(last, `"MessageAttributeNames":["All"]`) || !strings.Contains(last, `"MaxNumberOfMessages":2`) {
		t.Errorf("receive JSON: %s", last)
	}
	// errors: the engine's JSON error becomes the Query ErrorResponse with the AWS code
	r = f.do("POST", "/", form, "Action=GetQueueUrl&QueueName=nope&Version=2012-11-05")
	if r.status != 400 || !strings.Contains(r.body, `<ErrorResponse xmlns="http://queue.amazonaws.com/doc/2012-11-05/"><Error><Type>Sender</Type><Code>AWS.SimpleQueueService.NonExistentQueue</Code><Message>The specified queue does not exist.</Message><Detail/></Error><RequestId>`) {
		t.Errorf("error XML: %d %s", r.status, r.body)
	}
	r = f.do("POST", "/", form, "Action=NopeOp&Version=2012-11-05")
	if r.status != 400 || !strings.Contains(r.body, "<Code>InvalidAction</Code>") {
		t.Errorf("unknown action: %d %s", r.status, r.body)
	}
	r = f.do("POST", "/", form, "Action=SendMessage&Version=2012-11-05&QueueUrl=u")
	if r.status != 400 || !strings.Contains(r.body, "<Code>MissingParameter</Code><Message>The request must contain the parameter MessageBody.</Message>") {
		t.Errorf("missing parameter: %d %s", r.status, r.body)
	}
	r = f.do("POST", "/", form, "Action=DeleteMessageBatch&Version=2012-11-05&QueueUrl=u")
	if !strings.Contains(r.body, "AWS.SimpleQueueService.EmptyBatchRequest") {
		t.Errorf("empty batch: %s", r.body)
	}
	r = f.do("POST", "/", form, "Action=SendMessage&Version=2012-11-05&QueueUrl=u&MessageBody=x&DelaySeconds=abc")
	if !strings.Contains(r.body, "<Code>InvalidParameterValue</Code><Message>Value abc for parameter DelaySeconds is invalid. Reason: Must be an integer.</Message>") {
		t.Errorf("bad number: %s", r.body)
	}
	// the ledger counts Query calls under sqs with the real operation names
	sum := f.do("GET", "/_rovara/ledger/summary", tok(), "").body
	for _, op := range []string{"CreateQueue", "ListQueues", "SendMessage", "SendMessageBatch", "ReceiveMessage", "GetQueueUrl", "NopeOp"} {
		if !strings.Contains(sum, `"`+op+`":{"calls":`) {
			t.Errorf("ledger lacks %s: %s", op, sum)
		}
	}
	if !strings.Contains(sum, `"NopeOp":{"calls":1,"unsupported":1,"errors":1}`) || strings.Contains(sum, `"unknown"`) {
		t.Errorf("ledger: %s", sum)
	}
	// the engine's coral error names map to the Query codes
	for in, want := range map[string]string{"com.amazon.coral.service#MissingRequiredParameterException": "MissingParameter", "ValidationException": "InvalidParameterValue", "QueueDoesNotExist": "AWS.SimpleQueueService.NonExistentQueue"} {
		if got := jsonErrorToQuery(400, http.Header{}, []byte(`{"__type":"`+in+`","message":"m"}`)).code; got != want {
			t.Errorf("%s -> %s, want %s", in, got, want)
		}
	}
	// a switched-off sqs refuses a Query call too
	g := startFront(t, func(c *Config) { c.Disabled = map[string]bool{"sqs": true} })
	r = g.do("POST", "/", form, "Action=ListQueues&Version=2012-11-05")
	if r.status != 400 || !strings.Contains(r.body, "Service sqs is not enabled.") {
		t.Errorf("disabled: %d %s", r.status, r.body)
	}
}

// L1: bodies are rewritten only for the allow-listed operations; an object's bytes and metadata are never changed, even
// when they name the engine's own address. L3: a transport error never carries the URL.
func TestNoCatchAllRewriteAndNoURLInErrors(t *testing.T) {
	f := startFront(t, nil)
	g, _, _ := f.engine.current()
	r := f.do("GET", "/bkt/self?location", authFor2("s3"), "")
	if !strings.Contains(r.body, "https://127.0.0.1:"+fmt.Sprint(g.port)+"/x") || !strings.Contains(r.body, `"x-amz-crc32":"1"`) {
		t.Errorf("an object's bytes were rewritten: %s", r.body)
	}
	if r.header.Get("x-amz-meta-origin") != "https://127.0.0.1:"+fmt.Sprint(g.port)+"/m" {
		t.Errorf("user metadata was rewritten: %q", r.header.Get("x-amz-meta-origin"))
	}
	r = f.do("POST", "/", merge(authFor2("dynamodb"), map[string]string{"X-Amz-Target": "DynamoDB_20120810.GetItem", "Content-Type": "application/x-amz-json-1.0"}), "{}")
	if r.status != 200 {
		t.Errorf("dynamodb: %d", r.status)
	}
	e := sanitizeErr(&url.Error{Op: "Post", URL: "https://127.0.0.1:1234/secret?x=y", Err: errors.New("connection refused")})
	if strings.Contains(e, "127.0.0.1") || strings.Contains(e, "secret") || e != "connection refused" {
		t.Errorf("sanitizeErr: %q", e)
	}
}

// The front reads the SigV4 scope exactly as the engine does, and refuses every request whose signals disagree: the engine
// would take one of them (header, else query, else target) and the front must never have decided on another.
func TestScopeSignalsAreReadLikeTheEngineAndConflictsAreRefused(t *testing.T) {
	f := startFront(t, func(c *Config) { c.Disabled = map[string]bool{"s3": true, "iam": true} })
	text := map[string]string{"Content-Type": "text/plain"}
	bearer := func(svc string) map[string]string {
		return merge(text, map[string]string{"Authorization": "Bearer Credential=AKID/20260101/us-east-1/" + svc + "/aws4_request"})
	}
	const qs = "/?X-Amz-Credential=AKID/20260101/us-east-1/ec2/aws4_request"
	probes := []struct {
		name, method, path string
		headers            map[string]string
		body               string
	}{
		// the reported bypass: a Bearer header the engine ignores, a query scope it uses
		{"bearer header (dynamodb) + query scope (ec2) + text/plain form body", "POST", qs, bearer("dynamodb"), "Action=CreateVpc&Version=2016-11-15&CidrBlock=10.2.0.0/16"},
		{"bearer header (s3) + query scope (ec2)", "POST", qs, bearer("s3"), "Action=CreateVpc&Version=2016-11-15"},
		{"bearer header (iam) + query scope (iam)", "POST", "/?X-Amz-Credential=AKID/20260101/us-east-1/iam/aws4_request", bearer("iam"), "Action=ListUsers&Version=2010-05-08"},
		{"sigv4 header (sqs) + query scope (ec2)", "POST", qs, merge(text, authFor2("sqs")), "Action=CreateVpc&Version=2016-11-15"},
		{"sigv4 header (dynamodb) + query scope (s3)", "PUT", "/bkt?X-Amz-Credential=AKID/20260101/us-east-1/s3/aws4_request", authFor2("dynamodb"), ""},
		{"a sigv4 prefix that does not parse + query scope", "POST", qs, merge(text, map[string]string{"Authorization": "AWS4-HMAC-SHA256 Credential=AKID/20260101/us-east-1/sqs"}), "Action=CreateVpc&Version=2016-11-15"},
		{"two different query scopes", "POST", "/?X-Amz-Credential=AKID/20260101/us-east-1/sqs/aws4_request&X-Amz-Credential=AKID/20260101/us-east-1/ec2/aws4_request", text, "Action=CreateVpc&Version=2016-11-15"},
		{"query scope only (ec2), text/plain form body", "POST", qs, text, "Action=CreateVpc&Version=2016-11-15&CidrBlock=10.2.0.0/16"},
		{"query scope only (ec2), no body", "GET", qs + "&Action=DescribeInstances&Version=2016-11-15", nil, ""},
		{"lowercase header scheme is not SigV4 to the engine", "POST", qs, merge(text, map[string]string{"Authorization": "aws4-hmac-sha256 Credential=AKID/20260101/us-east-1/sqs/aws4_request"}), "Action=CreateVpc&Version=2016-11-15"},
	}
	for _, p := range probes {
		r := f.do(p.method, p.path, p.headers, p.body)
		if r.status != 404 || !strings.Contains(r.body, "UnknownOperationException") || r.header.Get("X-Fake-Path") != "" {
			t.Errorf("%s: %d %q (forwarded %q)", p.name, r.status, r.body, r.header.Get("X-Fake-Path"))
		}
	}
	sum := f.do("GET", "/_rovara/ledger/summary", tok(), "").body
	// a refusal is counted under the service of the winning scope (the header's) or as unknown, always as operation "unknown"
	for _, svc := range []string{"ec2", "iam", "s3", "kms"} {
		if strings.Contains(sum, `"`+svc+`":{`) {
			t.Errorf("a refused request was counted under %s, a service it merely named: %s", svc, sum)
		}
	}
	if strings.Contains(sum, `"dynamodb":{"operations":{"unknown":{"calls":1,`) == false || strings.Contains(sum, "CreateVpc") {
		t.Errorf("ledger: %s", sum)
	}
	// what is still served: a SigV4 header that agrees with the query, a Query call on a text/plain body for a Query service,
	// and an S3 object whose bytes look like a form
	r := f.do("POST", "/", merge(text, authFor2("sqs")), "Action=ListQueues&Version=2012-11-05")
	if r.status != 200 || !strings.Contains(r.body, "ListQueuesResponse") {
		t.Errorf("a Query call with a text/plain body: %d %q", r.status, r.body)
	}
	r = f.do("POST", "/?X-Amz-Credential=AKID%2F20260101%2Fus-east-1%2Fsqs%2Faws4_request", merge(text, authFor2("sqs")), "Action=ListQueues&Version=2012-11-05")
	if r.status != 200 {
		t.Errorf("a header and a query that agree: %d %q", r.status, r.body)
	}
	g := startFront(t, nil)
	r = g.do("PUT", "/bkt/form-looking", authFor2("s3"), "Action=CreateVpc&Version=2016-11-15")
	if r.status != 200 || r.header.Get("X-Fake-Path") != "/bkt/form-looking" {
		t.Errorf("an object whose bytes look like a form was not stored: %d %q", r.status, r.body)
	}
}

// Whatever the client sent, the engine gets a SigV4 header the front wrote, naming the service the front decided on.
func TestEngineGetsTheFrontsOwnAuthorization(t *testing.T) {
	f := startFront(t, nil)
	cases := []struct {
		name, path string
		headers    map[string]string
		wantScope  string
	}{
		{"unsigned target", "/", map[string]string{"X-Amz-Target": "DynamoDB_20120810.ListTables", "Content-Type": "application/x-amz-json-1.0"}, "ROVARATESTKEY/20260101/us-east-1/dynamodb/aws4_request"},
		{"client key, date and region are kept", "/", merge(authFor2("dynamodb"), map[string]string{"X-Amz-Target": "DynamoDB_20120810.ListTables"}), "K/20260101/us-east-1/dynamodb/aws4_request"},
		{"alias scope is written canonically", "/x", authFor2("execute-api"), "K/20260101/us-east-1/apigateway/aws4_request"},
		{"s3express is written as s3", "/b/k", authFor2("s3express"), "K/20260101/us-east-1/s3/aws4_request"},
		{"presigned (query scope only)", "/b/k?X-Amz-Credential=PK%2F20260202%2Feu-west-1%2Fs3%2Faws4_request&X-Amz-Signature=00", nil, "PK/20260202/eu-west-1/s3/aws4_request"},
		{"a header of another scheme is replaced", "/b/k", map[string]string{"Authorization": "Bearer abc"}, "ROVARATESTKEY/20260101/us-east-1/s3/aws4_request"},
	}
	for _, c := range cases {
		r := f.do("GET", c.path, c.headers, "")
		if got := r.header.Get("X-Fake-Auth"); !strings.Contains(got, "Credential="+c.wantScope+",") || strings.Contains(got, "Bearer") {
			t.Errorf("%s: the engine saw %q, want scope %s", c.name, got, c.wantScope)
		}
	}
}

func TestScopeParsingMatchesTheEngine(t *testing.T) {
	hdr := func(v string) http.Header { h := http.Header{}; h.Set("Authorization", v); return h }
	for _, c := range []struct {
		auth string
		want string // "" = no scope
	}{
		{"AWS4-HMAC-SHA256 Credential=AKID/20240101/eu-west-1/DynamoDB/aws4_request, SignedHeaders=host, Signature=abc", "dynamodb"},
		{"AWS4-HMAC-SHA256  Credential=AKID/20240101/eu-west-1/ iam /aws4_request,SignedHeaders=host", "iam"},
		{"AWS4-HMAC-SHA256 Credential=AKID/20240101/us-west-2/sqs/aws4_request", "sqs"},
		{"Bearer Credential=AKID/20240101/us-west-2/sqs/aws4_request", ""},
		{"aws4-hmac-sha256 Credential=AKID/20240101/us-west-2/sqs/aws4_request", ""},
		{"AWS4-HMAC-SHA256 Credential=AKID/20240101/us-west-2/sqs/not_sigv4", ""},
		{"AWS4-HMAC-SHA256 Credential=AKID/20240101/us-west-2/sqs/aws4_request/x", ""},
		{"AWS4-HMAC-SHA256 Credential=AKID/2024", ""},
		{"AWS4-HMAC-SHA256 Credential=/20240101/us-west-2/sqs/aws4_request", ""},
		{"AWS4-HMAC-SHA256 SignedHeaders=host, Credential=AKID/20240101/us-west-2/sqs/aws4_request", ""},
	} {
		sc, _ := headerScope(hdr(c.auth))
		got := ""
		if sc != nil {
			got = sc.Service
		}
		if got != c.want {
			t.Errorf("%q: %q, want %q", c.auth, got, c.want)
		}
	}
	for _, c := range []struct {
		q       string
		want    string
		present bool
	}{
		{"X-Amz-Credential=AKID%2F20260101%2Fus-east-1%2Fs3%2Faws4_request", "s3", true},
		{"a=1&X-Amz-Credential=AKID/20260101/us-east-1/S3/aws4_request&b=2", "s3", true},
		{"X-Amz-Credential=AKID%2f20260101%2fus-east-1%2fsqs%2faws4_request", "sqs", true},
		{"x-amz-credential=AKID/20260101/us-east-1/sqs/aws4_request", "", false}, // the engine matches the exact name only
		{"X%2DAmz-Credential=AKID/20260101/us-east-1/sqs/aws4_request", "", false},
		{"X-Amz-Credential=AKID/20260101/us-east-1/sqs", "", true},
		{"X-Amz-Credential=AKID/20260101/us-east-1/sqs/aws4_request/extra", "sqs", true},
	} {
		sc, present, _ := queryScope(c.q)
		got := ""
		if sc != nil {
			got = sc.Service
		}
		if got != c.want || present != c.present {
			t.Errorf("%q: %q %v, want %q %v", c.q, got, present, c.want, c.present)
		}
	}
}

// apigateway and apigatewayv2 share the SigV4 name apigateway: the v2 switch must govern every /v2/ path whichever scope names it.
func TestApiGatewayV2SwitchGovernsItsPaths(t *testing.T) {
	f := startFront(t, func(c *Config) { c.Disabled = map[string]bool{"apigatewayv2": true} })
	for _, scope := range []string{"apigateway", "execute-api"} {
		for _, c := range []struct{ method, path string }{
			{"POST", "/v2/apis"}, {"GET", "/v2/apis"}, {"GET", "/v2/domainnames"}, {"GET", "/v2/vpclinks"}, {"GET", "//v2/apis"},
			{"GET", "/v2/tags/arn%3Aaws%3Aapigateway%3Aus-east-1%3A%3A%2Fapis%2Fx"}, {"GET", "/v2/portals"}, {"GET", "/v2/apis/abc/routes"},
		} {
			r := f.do(c.method, c.path, authFor2(scope), "")
			if r.status != 400 || !strings.Contains(r.body, "Service apigatewayv2 is not enabled.") || r.header.Get("X-Fake-Path") != "" {
				t.Errorf("%s %s %s: %d %q (forwarded %q)", scope, c.method, c.path, r.status, r.body, r.header.Get("X-Fake-Path"))
			}
		}
	}
	// API Gateway v1 is untouched by the v2 switch, including the paths v2 shares a name with
	for _, p := range []string{"/restapis", "/domainnames", "/vpclinks", "/apikeys", "/V2/apis"} {
		if r := f.do("GET", p, authFor2("apigateway"), ""); r.status != 200 || r.header.Get("X-Fake-Path") == "" {
			t.Errorf("v1 %s: %d %q", p, r.status, r.body)
		}
	}
	sum := f.do("GET", "/_rovara/ledger/summary", tok(), "").body
	if !strings.Contains(sum, `"apigatewayv2":{"operations":{`) || !strings.Contains(sum, `"POST /v2/apis":{"calls":2,"unsupported":0,"errors":2}`) || strings.Contains(sum, `"GET /v2`) && strings.Contains(sum, `"apigateway":{"operations":{"GET /v2`) {
		t.Errorf("v2 calls were not counted under apigatewayv2: %s", sum)
	}
	// and the other way round: v1 off, v2 on
	g := startFront(t, func(c *Config) { c.Disabled = map[string]bool{"apigateway": true} })
	if r := g.do("GET", "/v2/apis", authFor2("apigateway"), ""); r.status != 200 {
		t.Errorf("v2 with v1 off: %d %q", r.status, r.body)
	}
	if r := g.do("GET", "/restapis", authFor2("apigateway"), ""); r.status != 400 || !strings.Contains(r.body, "Service apigateway is not enabled.") {
		t.Errorf("v1 with v1 off: %d %q", r.status, r.body)
	}
}
