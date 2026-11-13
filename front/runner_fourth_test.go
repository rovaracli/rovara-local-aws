package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The fourth review: false security rows on an idle run, unbounded reads, a data-plane exemption decided by a header, an XML text split, a
// URI test by substring, limits on legitimate big bodies, and a sweep that could not finish.

// ---- M1: an idle run writes nothing and records nothing

func TestPolicyDocumentsAreComparedAsDocuments(t *testing.T) {
	doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`
	engineStyle := `<GetRolePolicyResponse><GetRolePolicyResult><RoleName>r</RoleName><PolicyName>rendezvous</PolicyName><PolicyDocument>` +
		strings.ReplaceAll(doc, `"`, "&quot;") + `</PolicyDocument></GetRolePolicyResult></GetRolePolicyResponse>`
	awsStyle := `<GetRolePolicyResponse><GetRolePolicyResult><PolicyDocument>%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Action%22%3A%22%2A%22%2C%22Resource%22%3A%22%2A%22%7D%5D%7D</PolicyDocument></GetRolePolicyResult></GetRolePolicyResponse>`
	for name, x := range map[string]string{"engine (XML-escaped)": engineStyle, "AWS (percent-encoded)": awsStyle,
		"a single statement object and list actions": `<R><PolicyDocument>{"Statement":{"Effect":"Allow","Action":["*"],"Resource":["*"]}}</PolicyDocument></R>`} {
		if !policyIsStub(xmlText([]byte(x), "PolicyDocument")) {
			t.Errorf("%s is the stub's policy", name)
		}
	}
	for name, bad := range map[string]string{
		"a Deny":            `{"Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}`,
		"narrower":          `{"Statement":[{"Effect":"Allow","Action":"sqs:*","Resource":"*"}]}`,
		"two statements":    `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Action":"*","Resource":"*"}]}`,
		"a condition":       `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"Bool":{"x":"y"}}}]}`,
		"not a document":    `nope`,
		"an empty document": ``,
	} {
		if policyIsStub(bad) {
			t.Errorf("%s is not the stub's policy", name)
		}
	}
	trust := `<GetRoleResult><Role><AssumeRolePolicyDocument>` + strings.ReplaceAll(stubTrust, `"`, "&quot;") + `</AssumeRolePolicyDocument></Role></GetRoleResult>`
	if !trustIsLambda(xmlText([]byte(trust), "AssumeRolePolicyDocument")) {
		t.Errorf("the stub's trust document is read")
	}
	if trustIsLambda(`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}`) {
		t.Errorf("a role anyone can assume is not the stub's")
	}
}

func TestRepairRoleWritesNothingWhenNothingIsWrong(t *testing.T) {
	f := startRunnerFront(t, func(c *Config) { c.Runner.NoDispatch = true })
	nm := f.srv.runner.names()
	doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`
	sc := &scripted{h: func(svc, method, path string, hdr map[string]string, body []byte) (int, string) {
		switch {
		case strings.Contains(string(body), "Action=GetRolePolicy"):
			return 200, `<GetRolePolicyResponse><GetRolePolicyResult><PolicyDocument>` + strings.ReplaceAll(doc, `"`, "&quot;") + `</PolicyDocument></GetRolePolicyResult></GetRolePolicyResponse>`
		case strings.Contains(string(body), "Action=GetRole&"):
			return 200, `<GetRoleResponse><GetRoleResult><Role><RoleName>` + nm.role + `</RoleName><AssumeRolePolicyDocument>` + strings.ReplaceAll(stubTrust, `"`, "&quot;") + `</AssumeRolePolicyDocument></Role></GetRoleResult></GetRoleResponse>`
		case strings.Contains(string(body), "Action=ListAttachedRolePolicies"):
			return 200, `<ListAttachedRolePoliciesResponse><ListAttachedRolePoliciesResult><AttachedPolicies/></ListAttachedRolePoliciesResult></ListAttachedRolePoliciesResponse>`
		case strings.Contains(string(body), "Action=ListRolePolicies"):
			return 200, `<ListRolePoliciesResponse><ListRolePoliciesResult><PolicyNames><member>rendezvous</member></PolicyNames></ListRolePoliciesResult></ListRolePoliciesResponse>`
		}
		return 200, `<ok/>`
	}}
	f.srv.runner.call = sc.call
	for i := 0; i < 5; i++ {
		f.srv.runner.repairRole()
	}
	for _, w := range []string{"Action=PutRolePolicy", "Action=CreateRole", "Action=UpdateAssumeRolePolicy", "Action=DetachRolePolicy", "Action=DeleteRolePolicy"} {
		if sc.did(w) != 0 {
			t.Errorf("an intact role is not written to: %s (%v)", w, sc.calls)
		}
	}
	if c := f.counts("rovara"); len(c) != 0 {
		t.Errorf("and nothing is recorded: %v", c)
	}
	// a changed policy is put back, once
	doc = `{"Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}`
	f.srv.runner.repairRole()
	if sc.did("Action=PutRolePolicy") != 1 || f.counts("rovara")["security:plumbing-repaired"].Calls != 1 {
		t.Errorf("a changed policy is repaired: %v %v", sc.calls, f.counts("rovara"))
	}
}

// the real engine: an idle run over many ticks records no security event and writes nothing to IAM
func TestIdleRunWithTheRealEngineIsQuiet(t *testing.T) {
	bin := os.Getenv("ROVARA_REAL_ENGINE_BIN")
	if bin == "" {
		t.Skip("set ROVARA_REAL_ENGINE_BIN to the engine binary to run this against the real engine")
	}
	var mu sync.Mutex
	writes := map[string]int{}
	statuses := map[string][]int{}
	var tracking atomic.Bool
	f := startRunnerFrontWith(t, bin, func(c *Config) {
		c.Runner.SweepEvery = 150 * time.Millisecond
		c.Runner.CallWrap = func(next engineCall) engineCall {
			return func(service, method, path string, hdr map[string]string, body []byte, timeout time.Duration) (int, []byte, http.Header, error) {
				st, b, h, err := next(service, method, path, hdr, body, timeout)
				if tracking.Load() && service == "iam" {
					if act := formAction(body); act != "" && !strings.HasPrefix(act, "Get") && !strings.HasPrefix(act, "List") {
						mu.Lock()
						writes[act]++
						statuses[act] = append(statuses[act], st)
						mu.Unlock()
					}
				}
				return st, b, h, err
			}
		}
	})
	// the first poll provisions the plumbing (that is the one PutRolePolicy); after it the run is idle
	waitFor(t, "the plumbing", func() bool { return f.srv.runner.requestURL() != "" })
	time.Sleep(700 * time.Millisecond)
	tracking.Store(true)
	ticks0 := f.srv.runner.callN.Load()
	time.Sleep(4 * time.Second) // more than twenty ticks
	tracking.Store(false)
	if f.srv.runner.callN.Load() == ticks0 {
		t.Fatal("the sweeper ticked")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(writes) != 0 {
		t.Errorf("an idle run makes no write to IAM: %v (statuses %v)", writes, statuses)
	}
	sum := f.do("GET", "/_rovara/ledger/summary", tok(), "").body
	if strings.Contains(sum, `"security:`) || strings.Contains(sum, `"rovara"`) {
		t.Errorf("an idle run records no security event: %s", sum)
	}
}

func formAction(body []byte) string {
	for _, kv := range strings.Split(string(body), "&") {
		if strings.HasPrefix(kv, "Action=") {
			return strings.TrimPrefix(kv, "Action=")
		}
	}
	return ""
}

// ---- M2: no more of an object is read than a call can carry

func TestAnEventObjectIsReadOnlyUpToWhatACallCanCarry(t *testing.T) {
	f := startRunnerFront(t, nil)
	f.create("fl-cap", "python3.12", map[string]any{"Timeout": 30}, heavyZip())
	rs := f.srv.runner
	before := atomic.LoadInt32(&f.w.invokes)
	req := "bigobj"
	// the fake engine serves a 10 MiB object under the request's key (more than a call can carry, less than the default cap)
	if _, _, _, err := rs.engineDo("s3", http.MethodGet, "/"+rs.names().bucket+"/req/bigobj", map[string]string{capHeader: "1000"}, nil, 10*time.Second); err != errAnswerTooLarge {
		t.Errorf("engineDo stops at the cap: %v", err)
	}
	if st, _, _, err := rs.engineDo("s3", http.MethodGet, "/"+rs.names().bucket+"/req/hugeobj", nil, nil, 10*time.Second); err != errAnswerTooLarge || st != 200 {
		t.Errorf("and by default at 16 MiB (the runner frame's cap): %d %v", st, err)
	}
	sr := stubRequest{V: 1, Fn: "fl-cap", Ver: "$LATEST", Req: req, S3Key: "req/" + req, S3Sha: strings.Repeat("0", 64), Rem: 29000}
	r := rs.runStub(sr)
	if r.OK || r.ErrorType != "Rovara.Unsupported" || !strings.Contains(r.ErrorMessage, "6 MB") {
		t.Errorf("an object bigger than any call can carry is an error: %+v", r)
	}
	if atomic.LoadInt32(&f.w.invokes) != before {
		t.Errorf("and nothing is sent to the worker")
	}
	// an inline event bigger than a call can carry (a signed request can say anything)
	r = rs.runStub(stubRequest{V: 1, Fn: "fl-cap", Ver: "$LATEST", Req: "inl", Event: strings.Repeat("x", maxPayloadBytes+1), Rem: 29000})
	if r.OK || r.ErrorType != "Rovara.Unsupported" {
		t.Errorf("an inline event over 6 MB: %+v", r)
	}
	// big events are copied several times: only a few are handled at once
	if cap(rs.bigStubs) != 4 {
		t.Errorf("at most four big events at once: %d", cap(rs.bigStubs))
	}
}

// ---- M3: the data plane is decided by what the front identified, never by the Host

func TestHostHeaderNeverTurnsTheGuardOff(t *testing.T) {
	f := startRunnerFront(t, nil)
	f.create("fl-host", "java21", nil, pyZip())
	nm := f.srv.runner.names()
	host := map[string][]string{"Host": {"abc.execute-api.localhost"}}
	put := func(base map[string]string, extra map[string][]string, body []byte) result {
		h := hdrs(base, extra)
		req, _ := http.NewRequest("POST", f.ts.URL+"/", bytes.NewReader(body))
		for k, vs := range h {
			if k == "Host" {
				req.Host = vs[0]
				continue
			}
			req.Header[k] = vs
		}
		resp, err := noRedirect.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var b bytes.Buffer
		b.ReadFrom(resp.Body)
		return result{resp.StatusCode, resp.Header, b.String()}
	}
	targets := `{"Rule":"r","Targets":[{"Id":"1","Arn":"arn:aws:sqs:us-east-1:000000000000:` + nm.req + `"}]}`
	// the three probes of the review
	if r := put(jsonRPC("events", "AWSEvents.PutTargets"), host, []byte(targets)); r.status != 403 {
		t.Errorf("PutTargets naming the request queue, Host abc.execute-api.localhost: %d", r.status)
	}
	if r := put(jsonRPC("events", "AWSEvents.PutTargets"), map[string][]string{"Host": {"abc.execute-api.localhost"}, "Content-Encoding": {"gzip"}}, gz([]byte(targets))); r.status != 403 {
		t.Errorf("a gzip PutTargets, Host abc.execute-api.localhost: %d", r.status)
	}
	if r := put(formHdr("iam"), host, []byte("Action=PutRolePolicy&Version=2010-05-08&PolicyName=p&PolicyDocument=%7B%7D&RoleName="+nm.role)); r.status != 403 {
		t.Errorf("IAM PutRolePolicy on the stub role, Host abc.execute-api.localhost: %d", r.status)
	}
	// more of the same: every Host the old test accepted
	for _, h := range []string{"x.execute-api.us-east-1.amazonaws.com", "execute-api.", "a.lambda-url.localhost", "a.lambda-url.us-east-1.on.aws.evil.test"} {
		if r := put(jsonRPC("events", "AWSEvents.PutTargets"), map[string][]string{"Host": {h}}, []byte(targets)); r.status != 403 {
			t.Errorf("Host %s: %d", h, r.status)
		}
	}
	// the reserved data-plane path IS the data plane (the front routes it to the engine's API data plane, whatever else the request says)
	req, _ := http.NewRequest("POST", f.ts.URL+"/_aws/execute-api/abc123/$default/x", bytes.NewReader(gz([]byte(`{"q":"rovara-heavy-x"}`))))
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("Content-Type", "application/json")
	resp, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == 403 || resp.StatusCode == 415 {
		t.Errorf("a call to an API through its reserved path is the app's own: %d", resp.StatusCode)
	}
	// ... and the front's own names for the data planes are what decide it, not the header
	r, _ := http.NewRequest("POST", "http://aws/x", nil)
	r.Host = "abc.execute-api.localhost"
	for _, c := range []struct {
		key, op string
		want    bool
	}{{"apigatewayv2", "InvokeApi", true}, {"lambda", "InvokeFunctionUrl", true}, {"x", "DataPlaneRequest", true}, {"events", "PutTargets", false}, {"iam", "PutRolePolicy", false}, {"sqs", "SendMessage", false}} {
		if got := runnerDataPlane(r, c.key, c.op); got != c.want {
			t.Errorf("runnerDataPlane(%s, %s) with that Host: %v", c.key, c.op, got)
		}
	}
	if runnerDataPlane(r, "", "") {
		t.Errorf("the early aws-chunked decode never takes a Host for the data plane")
	}
}

// ---- L1: a function-code bucket is matched by host

func TestFunctionCodeBucketIsMatchedByHostNotBySubstring(t *testing.T) {
	for u, want := range map[string]bool{
		"https://awslambda-us-east-1-tasks.s3.us-east-1.amazonaws.com/snapshots/000000000000/fn-1": true,
		"https://awslambda-eu-west-2-layers.s3.amazonaws.com/snapshots/x":                          true,
		"http://awslambda-us-east-1-tasks.s3-us-east-1.amazonaws.com":                              true,
		"https://s3.us-east-1.amazonaws.com/awslambda-us-east-1-tasks/snapshots/000000000000/fn-1": true,
		"https://s3.amazonaws.com/awslambda-us-west-2-layers/x":                                    true,
		"https://api.example.com/awslambda-proxy/nightly-tasks.json":                               false,
		"https://example.com/awslambda-us-east-1-tasks.s3.amazonaws.com/x":                         false,
		"https://awslambda-us-east-1-tasks.s3.amazonaws.com.evil.test/x":                           false,
		"https://nightly-tasks.s3.us-east-1.amazonaws.com/awslambda-notes.txt":                     false,
		"https://s3.us-east-1.amazonaws.com/my-bucket/awslambda-us-east-1-tasks":                   false,
	} {
		if got := hiddenURI(u); got != want {
			t.Errorf("hiddenURI(%s) = %v, want %v", u, got, want)
		}
	}
	f := startRunnerFront(t, func(c *Config) { c.Runner.NoDispatch = true })
	sc := &scripted{h: func(svc, method, path string, hdr map[string]string, body []byte) (int, string) {
		switch {
		case svc == "apigatewayv2" && path == "/v2/apis?maxResults=100":
			return 200, `{"Items":[{"ApiId":"a1"}]}`
		case svc == "apigatewayv2" && strings.HasPrefix(path, "/v2/apis/a1/integrations"):
			return 200, `{"Items":[{"IntegrationId":"i-mine","IntegrationUri":"https://api.example.com/awslambda-proxy/nightly-tasks.json"},` +
				`{"IntegrationId":"i-code","IntegrationUri":"https://awslambda-us-east-1-tasks.s3.us-east-1.amazonaws.com/snapshots/000000000000/x"}]}`
		}
		return 404, `{}`
	}}
	f.srv.runner.call = sc.call
	f.srv.runner.sweepRefs()
	if sc.did("DELETE /v2/apis/a1/integrations/i-mine") != 0 || sc.did("DELETE /v2/apis/a1/integrations/i-code") != 1 {
		t.Errorf("the customer's integration survives, the function-code one goes: %v", sc.calls)
	}
}

// ---- L2: text split across CDATA, comments and processing instructions

func TestXMLTextIsJoinedBeforeItIsLooked(t *testing.T) {
	name := "rovara-heavy-req-0123"
	for label, doc := range map[string]string{
		"CDATA":                    `<Queue>rovara<![CDATA[-heavy]]>-req-0123</Queue>`,
		"a comment":                `<Queue>rovara<!-- c -->-heavy-req-0123</Queue>`,
		"a processing instruction": `<Queue>rovara<?pi x?>-heavy-req-0123</Queue>`,
		"all three":                `<Queue>ro<!--a-->va<![CDATA[ra-he]]>av<?p q?>y-req</Queue>`,
		"a reference and CDATA":    `<Queue>&#114;ovara<![CDATA[-]]>heavy-req</Queue>`,
		"nested in a document":     `<A><B><Queue>rovara<!-- c -->-heavy-req</Queue></B></A>`,
	} {
		if found, err := xmlHasHidden([]byte(doc)); !found || err != nil {
			t.Errorf("%s: found %v, err %v", label, found, err)
		}
	}
	for label, doc := range map[string]string{
		"a customer queue": `<Queue>arn:aws:sqs:us-east-1:000000000000:orders</Queue>`,
		"a longer name":    `<Queue>my-rovara<!-- c -->-heavy-req</Queue>`,
		"split elements":   `<Queue>rovara</Queue><Q2>-heavy-req</Q2>`,
	} {
		if found, err := xmlHasHidden([]byte(doc)); found || err != nil {
			t.Errorf("%s must pass: %v %v", label, found, err)
		}
	}
	_ = name
	f := startRunnerFront(t, nil)
	f.create("fl-xs", "java21", nil, pyZip())
	for label, q := range map[string]string{"CDATA": `rovara<![CDATA[-heavy]]>-req`, "comment": `rovara<!-- c -->-heavy-req`, "processing instruction": `rovara<?pi x?>-heavy-req`} {
		cfg := `<NotificationConfiguration><QueueConfiguration><Queue>arn:aws:sqs:us-east-1:000000000000:` + q + `</Queue><Event>s3:ObjectCreated:*</Event></QueueConfiguration></NotificationConfiguration>`
		if r := f.do("PUT", "/mine?notification", scopeHdr("s3"), cfg); r.status != 403 {
			t.Errorf("a notification with the name split by %s: %d %s", label, r.status, r.body)
		}
	}
}

// ---- L3: malformed XML is a plain 400; legitimate big bodies are read

func TestMalformedXMLAndBigLegitimateBodies(t *testing.T) {
	f := startRunnerFront(t, nil)
	f.create("fl-big2", "java21", nil, pyZip())
	notif := func(body []byte) result {
		return f.doRaw("PUT", "/mine?notification", hdrs(scopeHdr("s3"), nil), body)
	}
	for label, body := range map[string][]byte{
		"text that is not UTF-8":        []byte("<NotificationConfiguration><Id>\xff\xfe\xfd</Id></NotificationConfiguration>"),
		"a character reference to NUL":  []byte("<NotificationConfiguration><Id>&#0;</Id></NotificationConfiguration>"),
		"a reference to a control code": []byte("<NotificationConfiguration><Id>&#1;</Id></NotificationConfiguration>"),
		"a reference outside Unicode":   []byte("<NotificationConfiguration><Id>&#x110000;</Id></NotificationConfiguration>"),
		"an undefined entity":           []byte("<NotificationConfiguration><Id>&nope;</Id></NotificationConfiguration>"),
	} {
		r := notif(body)
		if r.status != 400 || strings.Contains(r.body, "reserved") || !strings.Contains(r.body, "could not be read") {
			t.Errorf("%s: %d %.120s", label, r.status, r.body)
		}
	}
	// a 1.5 MiB state machine definition is a legitimate control-plane call
	def := `{"StartAt":"A","Comment":"` + strings.Repeat("c", 3<<19) + `","States":{"A":{"Type":"Pass","End":true}}}`
	body := jsonStr(map[string]any{"name": "big", "roleArn": "arn:aws:iam::000000000000:role/r", "definition": def})
	if r := f.do("POST", "/", jsonRPC("states", "AWSStepFunctions.CreateStateMachine"), body); r.status == 413 || r.status == 403 || (r.status == 400 && strings.Contains(r.body, "could not be read")) {
		t.Errorf("a 1.5 MiB CreateStateMachine reaches the engine: %d %.100s", r.status, r.body)
	}
	// ... one over the engine's own 16 MiB is refused for its size, and a naming one that size is still found
	big := jsonStr(map[string]any{"name": "big", "definition": strings.Repeat("c", 17<<20)})
	if r := f.do("POST", "/", jsonRPC("states", "AWSStepFunctions.CreateStateMachine"), big); r.status != 413 {
		t.Errorf("over 16 MiB: %d", r.status)
	}
	named := jsonStr(map[string]any{"name": "big", "roleArn": "arn:aws:iam::000000000000:role/" + f.srv.runner.names().role, "definition": strings.Repeat("c", 3<<20)})
	if r := f.do("POST", "/", jsonRPC("states", "AWSStepFunctions.CreateStateMachine"), named); r.status != 403 {
		t.Errorf("a 3 MiB body that names the role: %d", r.status)
	}
	if n := f.srv.budget.used; n != 0 {
		t.Errorf("the inspection budget is released: %d", n)
	}
	// image and blob bytes are the app's own, identified by service and operation
	r, _ := http.NewRequest("POST", "http://aws/", nil)
	for _, c := range []struct{ key, op string }{{"rekognition", "DetectLabels"}, {"textract", "AnalyzeDocument"}, {"ecr", "UploadLayerPart"}} {
		if !runnerDataPlane(r, c.key, c.op) {
			t.Errorf("%s %s carries blobs", c.key, c.op)
		}
	}
	_ = base64.StdEncoding
}

// ---- L4: the sweep runs in its own goroutine and under a budget

func TestTheSweepIsBudgetedAndResumes(t *testing.T) {
	f := startRunnerFront(t, func(c *Config) { c.Runner.NoDispatch = true })
	rs := f.srv.runner
	hq := hiddenArn(f)
	const buses, rules = 30, 30
	var hiddenAt = map[string]bool{"b7/r12": true, "b29/r29": true, "b0/r0": true}
	var mu sync.Mutex
	removed := map[string]bool{}
	sc := &scripted{}
	sc.h = func(svc, method, path string, hdr map[string]string, body []byte) (int, string) {
		tgt := hdr["X-Amz-Target"]
		req := map[string]interface{}{}
		json.Unmarshal(body, &req)
		switch tgt {
		case "AWSEvents.ListEventBuses":
			var bs []string
			for i := 0; i < buses; i++ {
				bs = append(bs, `{"Name":"b`+strconv.Itoa(i)+`"}`)
			}
			return 200, `{"EventBuses":[` + strings.Join(bs, ",") + `]}`
		case "AWSEvents.ListRules":
			var rl []string
			for i := 0; i < rules; i++ {
				rl = append(rl, `{"Name":"r`+strconv.Itoa(i)+`"}`)
			}
			return 200, `{"Rules":[` + strings.Join(rl, ",") + `]}`
		case "AWSEvents.ListTargetsByRule":
			key := strOf(req, "EventBusName") + "/" + strOf(req, "Rule")
			if hiddenAt[key] {
				return 200, `{"Targets":[{"Id":"t","Arn":"` + hq + `"}]}`
			}
			return 200, `{"Targets":[{"Id":"t","Arn":"arn:aws:sqs:us-east-1:000000000000:orders"}]}`
		case "AWSEvents.RemoveTargets":
			mu.Lock()
			removed[strOf(req, "EventBusName")+"/"+strOf(req, "Rule")] = true
			mu.Unlock()
			return 200, `{}`
		}
		return 404, `{}`
	}
	rs.call = func(service, method, path string, hdr map[string]string, body []byte, d time.Duration) (int, []byte, http.Header, error) {
		rs.callN.Add(1)
		return sc.call(service, method, path, hdr, body, d)
	}
	ticks, maxPerTick := 0, 0
	for ; ticks < 200; ticks++ {
		before := rs.callN.Load()
		_, done := rs.sweepTick(100, time.Minute)
		if d := int(rs.callN.Load() - before); d > maxPerTick {
			maxPerTick = d
		}
		if done && ticks > 0 {
			break
		}
	}
	// 900 rules' targets are listed one by one: a tick may start at most its budget of calls (and finish the unit it is in)
	if maxPerTick > 100+sweepMaxPages {
		t.Errorf("a tick stays within its call budget: %d calls", maxPerTick)
	}
	if ticks < 8 {
		t.Errorf("a run this big takes several ticks, not one: %d", ticks)
	}
	mu.Lock()
	for k := range hiddenAt {
		if !removed[k] {
			t.Errorf("the reference at %s was found on a later tick: %v", k, removed)
		}
	}
	if len(removed) != len(hiddenAt) {
		t.Errorf("and nothing else was removed: %v", removed)
	}
	mu.Unlock()
	// the next cycle starts again from the beginning (it is a loop, not a one-off)
	if n, _ := rs.sweepTick(100, time.Minute); n < 0 || len(rs.swq) == 0 {
		t.Errorf("a new cycle is seeded when the queue is empty: %d units", len(rs.swq))
	}
	// the time budget stops a tick too
	rs.swq = nil
	slow := &scripted{h: func(svc, method, path string, hdr map[string]string, body []byte) (int, string) {
		time.Sleep(40 * time.Millisecond)
		return 404, `{}`
	}}
	rs.call = func(service, method, path string, hdr map[string]string, body []byte, d time.Duration) (int, []byte, http.Header, error) {
		rs.callN.Add(1)
		return slow.call(service, method, path, hdr, body, d)
	}
	t0 := time.Now()
	if _, done := rs.sweepTick(1<<30, 150*time.Millisecond); done || time.Since(t0) > 600*time.Millisecond {
		t.Errorf("a tick stops at its time budget (%v, done %v)", time.Since(t0), done)
	}
}

func TestTheSweepNeverHoldsUpThePolls(t *testing.T) {
	var polls atomic.Int64
	slowEvents := atomic.Bool{}
	f := startRunnerFront(t, func(c *Config) {
		c.Runner.SweepEvery = 50 * time.Millisecond
		c.Runner.CallWrap = func(next engineCall) engineCall {
			return func(service, method, path string, hdr map[string]string, body []byte, d time.Duration) (int, []byte, http.Header, error) {
				if hdr["X-Amz-Target"] == "AmazonSQS.ReceiveMessage" {
					polls.Add(1)
				}
				if service == "events" && slowEvents.Load() {
					time.Sleep(time.Second) // a sweep stuck in a slow listing
				}
				return next(service, method, path, hdr, body, d)
			}
		}
	})
	_ = f
	slowEvents.Store(true)
	time.Sleep(300 * time.Millisecond)
	p0 := polls.Load()
	time.Sleep(2 * time.Second)
	if n := polls.Load() - p0; n < 10 {
		t.Errorf("the dispatcher kept polling while the sweep was stuck: %d polls in two seconds", n)
	}
}
