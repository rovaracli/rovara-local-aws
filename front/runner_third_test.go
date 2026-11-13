package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// The third review: the plumbing cannot be kept secret from code that runs in the same engine, so the tests assert what the front DOES do
// (put the plumbing back, sweep every reference it finds every time, read XML and encodings as the engine does, sign what goes through the
// bucket) and that no comment or document claims more.

// ---- 1. no claim that the plumbing is secret from same-run code

func TestNoClaimThatTheHMACOrTheNamesAreASecretFromSameRunCode(t *testing.T) {
	banned := []string{"cannot be read from inside the engine", "known to the front and to this code only", "so a bypass of this guard still cannot",
		"is the first of two defences", "the plumbing's messages are signed.", "can only make the runner run a function of its own run"}
	files, _ := filepath.Glob("runner_*.go")
	files = append(files, "../README.md")
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, bad := range banned {
			if strings.Contains(string(b), bad) {
				t.Errorf("%s still claims: %q", f, bad)
			}
		}
	}
	readme, _ := os.ReadFile("../README.md")
	for _, want := range []string{"Known limit: code running in the same engine", "are not a boundary", "Same-run code"} {
		if !strings.Contains(string(readme), want) {
			t.Errorf("the README states the known limit: %q", want)
		}
	}
	for _, f := range []string{"runner_engine.go", "runner_stub.go", "runner_sweep.go"} {
		b, _ := os.ReadFile(f)
		if !strings.Contains(string(b), "known limit") && !strings.Contains(string(b), "NOT a boundary") {
			t.Errorf("%s says it is not a boundary", f)
		}
	}
}

// ---- a stand-in for the engine, for the sweeper and the repair

type scripted struct {
	mu    sync.Mutex
	calls []string
	h     func(service, method, path string, hdr map[string]string, body []byte) (int, string)
}

func (s *scripted) call(service, method, path string, hdr map[string]string, body []byte, _ time.Duration) (int, []byte, http.Header, error) {
	label := service + " " + method + " " + path
	if t := hdr["X-Amz-Target"]; t != "" {
		label += " " + t
	}
	s.mu.Lock()
	s.calls = append(s.calls, label+" "+string(body))
	s.mu.Unlock()
	st, b := s.h(service, method, path, hdr, body)
	return st, []byte(b), nil, nil
}

func (s *scripted) did(substr string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, c := range s.calls {
		if strings.Contains(c, substr) {
			n++
		}
	}
	return n
}

func hiddenArn(f *runnerFront) string {
	return "arn:aws:sqs:us-east-1:000000000000:" + f.srv.runner.names().req
}

func query(path string) url.Values {
	_, q, _ := strings.Cut(path, "?")
	v, _ := url.ParseQuery(q)
	return v
}

// ---- 2. the sweeper

func TestSweeperDealsWithAReferenceEveryTimeItIsFound(t *testing.T) {
	f := startRunnerFront(t, func(c *Config) { c.Runner.NoDispatch = true })
	hq := hiddenArn(f)
	sc := &scripted{h: func(svc, method, path string, hdr map[string]string, body []byte) (int, string) {
		if svc == "lambda" && method == "GET" && strings.HasPrefix(path, "/2015-03-31/event-source-mappings/") {
			// the same call that put the reference there puts it back: the mapping is listed again after each delete
			return 200, `{"EventSourceMappings":[{"UUID":"u-1","State":"Enabled","EventSourceArn":"` + hq + `"},{"UUID":"u-2","State":"Deleting","EventSourceArn":"` + hq + `"},{"UUID":"u-3","State":"Enabled","EventSourceArn":"arn:aws:sqs:us-east-1:000000000000:orders"}]}`
		}
		return 404, `{}`
	}}
	f.srv.runner.call = sc.call
	for i := 1; i <= 3; i++ {
		if n := f.srv.runner.sweepRefs(); n != 1 {
			t.Errorf("sweep %d removes the mapping again: %d", i, n)
		}
	}
	if sc.did("DELETE /2015-03-31/event-source-mappings/u-1") != 3 || sc.did("event-source-mappings/u-2") != 1 && sc.did("DELETE /2015-03-31/event-source-mappings/u-2") != 0 {
		t.Errorf("u-1 deleted each time, u-2 (already Deleting) and u-3 (the customer's) never: %v", sc.calls)
	}
	if c := f.counts("rovara")["security:event-source-mapping"]; c.Calls != 3 {
		t.Errorf("and recorded each time: %+v", c)
	}
}

func TestSweeperPagesThroughEveryListing(t *testing.T) {
	f := startRunnerFront(t, func(c *Config) { c.Runner.NoDispatch = true })
	hq := hiddenArn(f)
	other := "arn:aws:sqs:us-east-1:000000000000:orders"
	sc := &scripted{}
	sc.h = func(svc, method, path string, hdr map[string]string, body []byte) (int, string) {
		tgt := hdr["X-Amz-Target"]
		var req map[string]interface{}
		json.Unmarshal(body, &req)
		switch {
		case svc == "lambda" && strings.HasPrefix(path, "/2015-03-31/event-source-mappings/") && method == "GET":
			if query(path).Get("Marker") == "" {
				return 200, `{"EventSourceMappings":[{"UUID":"p1","State":"Enabled","EventSourceArn":"` + other + `"}],"NextMarker":"m2"}`
			}
			return 200, `{"EventSourceMappings":[{"UUID":"p2","State":"Enabled","EventSourceArn":"` + hq + `"}]}`
		case tgt == "AWSEvents.ListEventBuses":
			if strOf(req, "NextToken") == "" {
				return 200, `{"EventBuses":[{"Name":"default"}],"NextToken":"b2"}`
			}
			return 200, `{"EventBuses":[{"Name":"custom"}]}`
		case tgt == "AWSEvents.ListRules":
			bus, tok := strOf(req, "EventBusName"), strOf(req, "NextToken")
			if bus == "custom" && tok == "" {
				return 200, `{"Rules":[{"Name":"r1"}],"NextToken":"r2"}`
			}
			if bus == "custom" {
				return 200, `{"Rules":[{"Name":"r-beyond-100"}]}`
			}
			return 200, `{"Rules":[]}`
		case tgt == "AWSEvents.ListTargetsByRule":
			if strOf(req, "Rule") == "r-beyond-100" && strOf(req, "NextToken") == "" {
				return 200, `{"Targets":[{"Id":"t1","Arn":"` + other + `"}],"NextToken":"t2"}`
			}
			if strOf(req, "Rule") == "r-beyond-100" {
				return 200, `{"Targets":[{"Id":"t2","Arn":"` + other + `","Input":"{\"q\":\"` + strings.Replace(hq, "rovara-heavy", `rovara-heavy`, 1) + `\"}"}]}`
			}
			return 200, `{"Targets":[]}`
		case svc == "sns":
			if !strings.Contains(string(body), "NextToken") {
				return 200, `<ListSubscriptionsResponse><ListSubscriptionsResult><Subscriptions><member xmlns="x"><SubscriptionArn>sub1</SubscriptionArn><Endpoint>` + other + `</Endpoint></member></Subscriptions><NextToken>n2</NextToken></ListSubscriptionsResult></ListSubscriptionsResponse>`
			}
			return 200, `<ListSubscriptionsResponse><ListSubscriptionsResult><Subscriptions><member xmlns="x"><SubscriptionArn>sub2</SubscriptionArn><Endpoint>` + hq + `</Endpoint></member></Subscriptions></ListSubscriptionsResult></ListSubscriptionsResponse>`
		}
		return 404, `{}`
	}
	f.srv.runner.call = sc.call
	if n := f.srv.runner.sweepRefs(); n != 3 {
		t.Errorf("one reference on the second page of each listing is found: %d (%v)", n, sc.calls)
	}
	for _, want := range []string{"DELETE /2015-03-31/event-source-mappings/p2", `AWSEvents.RemoveTargets {"EventBusName":"custom","Force":true,"Ids":["t2"],"Rule":"r-beyond-100"}`, "Action=Unsubscribe&SubscriptionArn=sub2"} {
		if sc.did(want) != 1 {
			t.Errorf("a call containing %q: %v", want, sc.calls)
		}
	}
}

func TestSweeperKnowsEveryKindOfReference(t *testing.T) {
	f := startRunnerFront(t, func(c *Config) { c.Runner.NoDispatch = true })
	hq := hiddenArn(f)
	nm := f.srv.runner.names()
	sc := &scripted{}
	sc.h = func(svc, method, path string, hdr map[string]string, body []byte) (int, string) {
		tgt := hdr["X-Amz-Target"]
		switch {
		case svc == "lambda" && method == "GET" && strings.HasPrefix(path, "/2015-03-31/event-source-mappings/"):
			return 200, `{"EventSourceMappings":[{"UUID":"d1","State":"Enabled","EventSourceArn":"arn:aws:sqs:us-east-1:000000000000:orders","DestinationConfig":{"OnFailure":{"Destination":"` + hq + `"}}}]}`
		case svc == "lambda" && method == "GET" && strings.HasPrefix(path, "/2015-03-31/functions/"):
			return 200, `{"Functions":[{"FunctionName":"fn-a"},{"FunctionName":"fn-b"}]}`
		case svc == "lambda" && method == "GET" && path == "/2019-09-25/functions/fn-b/event-invoke-config":
			return 200, `{"DestinationConfig":{"OnSuccess":{"Destination":"` + hq + `"}}}`
		case svc == "lambda" && method == "GET" && strings.HasPrefix(path, "/2019-09-25/"):
			return 404, `{}`
		case svc == "scheduler" && method == "GET":
			return 200, `{"Schedules":[{"Name":"sch","GroupName":"default","Target":{"Arn":"` + hq + `"}},{"Name":"fine","GroupName":"default","Target":{"Arn":"arn:aws:sqs:us-east-1:000000000000:orders"}}]}`
		case svc == "pipes" && method == "GET":
			return 200, `{"Pipes":[{"Name":"pipe1","Source":"` + hq + `","Target":"arn:aws:sqs:us-east-1:000000000000:orders"},{"Name":"pipe2","Source":"arn:aws:sqs:us-east-1:000000000000:orders","Target":"` + hq + `"}]}`
		case tgt == "AmazonSQS.ListQueues":
			return 200, `{"QueueUrls":["http://q/000000000000/orders","http://q/000000000000/` + nm.req + `","http://q/000000000000/with-dlq"]}`
		case tgt == "AmazonSQS.GetQueueAttributes" && strings.Contains(string(body), "with-dlq"):
			return 200, `{"Attributes":{"RedrivePolicy":"{\"deadLetterTargetArn\":\"` + hq + `\",\"maxReceiveCount\":1}"}}`
		case tgt == "AmazonSQS.GetQueueAttributes":
			return 200, `{"Attributes":{}}`
		case tgt == "AWSStepFunctions.ListStateMachines":
			return 200, `{"stateMachines":[{"stateMachineArn":"arn:sm:bad"},{"stateMachineArn":"arn:sm:ok"}]}`
		case tgt == "AWSStepFunctions.DescribeStateMachine" && strings.Contains(string(body), "bad"):
			return 200, `{"definition":"{\"States\":{\"A\":{\"Parameters\":{\"QueueUrl\":\"` + hq + `\"}}}}","roleArn":"arn:aws:iam::000000000000:role/r"}`
		case tgt == "AWSStepFunctions.DescribeStateMachine":
			return 200, `{"definition":"{}","roleArn":"arn:aws:iam::000000000000:role/r"}`
		case svc == "apigatewayv2" && method == "GET" && path == "/v2/apis?maxResults=100":
			return 200, `{"Items":[{"ApiId":"api1"}]}`
		case svc == "apigatewayv2" && method == "GET" && strings.HasPrefix(path, "/v2/apis/api1/integrations"):
			return 200, `{"Items":[{"IntegrationId":"i-code","IntegrationUri":"https://awslambda-us-east-1-tasks.s3.us-east-1.amazonaws.com/snapshots/000000000000/x"},` +
				`{"IntegrationId":"i-sqs","IntegrationUri":"arn:aws:apigateway:us-east-1:sqs:path/000000000000/` + nm.req + `"},{"IntegrationId":"i-ok","IntegrationUri":"https://example.com/x"}]}`
		}
		return 404, `{}`
	}
	f.srv.runner.call = sc.call
	n := f.srv.runner.sweepRefs()
	want := map[string]int{
		"security:lambda-destination": 2, "security:scheduler-schedule": 1, "security:pipe": 2, "security:sqs-redrive": 1, "security:state-machine": 1, "security:apigateway-integration": 2,
	}
	ops := f.counts("rovara")
	total := 0
	for op, k := range want {
		if ops[op].Calls != int64(k) {
			t.Errorf("%s: %+v, want %d", op, ops[op], k)
		}
		total += k
	}
	if n != total {
		t.Errorf("removed %d, want %d (%v)", n, total, sc.calls)
	}
	for _, c := range []string{`PUT /2015-03-31/event-source-mappings/d1 {"DestinationConfig":{}}`, "DELETE /2019-09-25/functions/fn-b/event-invoke-config", "DELETE /schedules/sch?groupName=default",
		"DELETE /v1/pipes/pipe1", "DELETE /v1/pipes/pipe2", "AmazonSQS.SetQueueAttributes", "AWSStepFunctions.DeleteStateMachine", "DELETE /v2/apis/api1/integrations/i-code", "DELETE /v2/apis/api1/integrations/i-sqs"} {
		if sc.did(c) != 1 {
			t.Errorf("a call %q: %v", c, sc.calls)
		}
	}
	for _, never := range []string{"schedules/fine", "integrations/i-ok", "functions/fn-a/event-invoke-config {", "arn:sm:ok"} {
		if strings.Contains(strings.Join(sc.calls, "\n"), "DELETE /"+never) || sc.did("Delete"+never) != 0 {
			t.Errorf("the customer's %s is left alone", never)
		}
	}
}

func TestListTargetsByRuleAnswersLeaveOutTheHidden(t *testing.T) {
	f := startRunnerFront(t, nil)
	hq := hiddenArn(f)
	in := `{"Targets":[{"Id":"1","Arn":"arn:aws:sqs:us-east-1:000000000000:orders"},{"Id":"2","Arn":"` + hq + `"},{"Id":"3","Arn":"arn:aws:sqs:us-east-1:000000000000:orders","Input":"x ` + hq + `"}],"NextToken":"n"}`
	got := string(hideInLists([]byte(in)))
	if strings.Contains(got, "hiddenReq") || strings.Contains(got, f.srv.runner.names().req) || !strings.Contains(got, `"Id":"1"`) || !strings.Contains(got, `"NextToken":"n"`) {
		t.Errorf("hidden targets are left out: %s", got)
	}
	for _, key := range []string{"eventbridge", "events"} {
		if runnerRewriteKind(identified{Service: &service{Key: key}, Operation: "ListTargetsByRule"}) != rwRunnerHide {
			t.Errorf("%s ListTargetsByRule is filtered", key)
		}
	}
}

// ---- 3. repair

func TestRepairPutsThePlumbingBack(t *testing.T) {
	f := startRunnerFront(t, func(c *Config) { c.Runner.NoDispatch = true })
	nm := f.srv.runner.names()
	sc := &scripted{}
	sc.h = func(svc, method, path string, hdr map[string]string, body []byte) (int, string) {
		tgt := hdr["X-Amz-Target"]
		switch {
		case tgt == "AmazonSQS.GetQueueUrl":
			return 400, `{"__type":"QueueDoesNotExist"}`
		case tgt == "AmazonSQS.CreateQueue":
			return 200, `{"QueueUrl":"https://sqs.us-east-1.amazonaws.com/000000000000/` + nm.req + `"}`
		case tgt == "AmazonSQS.GetQueueAttributes":
			return 200, `{"Attributes":{"DelaySeconds":"900","Policy":"{\"Statement\":[{\"Effect\":\"Deny\"}]}","VisibilityTimeout":"30"}}`
		case svc == "s3" && method == "HEAD":
			return 404, ``
		case svc == "iam" && strings.Contains(string(body), "Action=GetRole&"):
			return 404, `<Error/>`
		case svc == "iam" && strings.Contains(string(body), "Action=GetRolePolicy"):
			return 404, `<Error/>`
		case svc == "iam" && strings.Contains(string(body), "Action=ListAttachedRolePolicies"):
			return 200, `<ListAttachedRolePoliciesResponse><AttachedPolicies><member><PolicyName>d</PolicyName><PolicyArn>arn:aws:iam::123:policy/deny</PolicyArn></member></AttachedPolicies></ListAttachedRolePoliciesResponse>`
		case svc == "iam" && strings.Contains(string(body), "Action=ListRolePolicies"):
			return 200, `<ListRolePoliciesResponse><PolicyNames><member>rendezvous</member><member>deny-all</member></PolicyNames></ListRolePoliciesResponse>`
		}
		return 200, `{}`
	}
	f.srv.runner.call = sc.call
	f.srv.runner.repairPlumbing()
	f.srv.runner.repairRole()
	for _, c := range []string{"AmazonSQS.CreateQueue", `"DelaySeconds":"0"`, `"Policy":""`, "s3 PUT /" + nm.bucket, "Action=CreateRole", "Action=PutRolePolicy", "Action=DetachRolePolicy", "PolicyArn=arn%3Aaws%3Aiam%3A%3A123%3Apolicy%2Fdeny", "Action=DeleteRolePolicy"} {
		if sc.did(c) < 1 {
			t.Errorf("a repair call %q: %v", c, sc.calls)
		}
	}
	if sc.did("PolicyName=rendezvous&RoleName") != 0 && sc.did("Action=DeleteRolePolicy&PolicyName=rendezvous") != 0 {
		t.Errorf("its own policy is never deleted")
	}
	for _, op := range []string{"security:plumbing-repaired"} {
		if c := f.counts("rovara")[op]; c.Calls < 6 {
			t.Errorf("each repair is a security event: %+v", c)
		}
	}
	// nothing to repair: no write
	ok := &scripted{h: func(svc, method, path string, hdr map[string]string, body []byte) (int, string) {
		switch hdr["X-Amz-Target"] {
		case "AmazonSQS.GetQueueUrl":
			return 200, `{"QueueUrl":"https://sqs.us-east-1.amazonaws.com/000000000000/` + nm.req + `"}`
		case "AmazonSQS.GetQueueAttributes":
			return 200, `{"Attributes":{"DelaySeconds":"0","VisibilityTimeout":"30","ReceiveMessageWaitTimeSeconds":"0"}}`
		}
		return 200, `{}`
	}}
	f.srv.runner.call = ok.call
	f.srv.runner.repairPlumbing()
	f.srv.runner.repairRole()
	if ok.did("SetQueueAttributes")+ok.did("CreateQueue")+ok.did(" PUT ") != 0 {
		t.Errorf("an intact plumbing is left alone: %v", ok.calls)
	}
}

// ---- 4. XML

func TestNotificationConfigurationsAreReadAsXML(t *testing.T) {
	f := startRunnerFront(t, nil)
	f.create("fl-x", "java21", nil, pyZip())
	name := f.srv.runner.names().req
	cfg := func(queue string) string {
		return `<NotificationConfiguration><QueueConfiguration><Queue>` + queue + `</Queue><Event>s3:ObjectCreated:*</Event></QueueConfiguration></NotificationConfiguration>`
	}
	hidden := []string{
		"arn:aws:sqs:us-east-1:000000000000:" + name,
		"arn:aws:sqs:us-east-1:000000000000:&#114;ovara-heavy-" + strings.TrimPrefix(name, "rovara-heavy-"),
		"arn:aws:sqs:us-east-1:000000000000:&#x72;ovara&#45;heavy-" + strings.TrimPrefix(name, "rovara-heavy-"),
		"arn:aws:sqs:us-east-1:000000000000:rovara&#x2d;heavy&#x2D;" + strings.TrimPrefix(name, "rovara-heavy-"),
		"arn:aws:sqs:us-east-1:000000000000:<![CDATA[rovara-heavy-x]]>",
	}
	for _, h := range hidden {
		if r := f.do("PUT", "/mine?notification", scopeHdr("s3"), cfg(h)); r.status != 403 {
			t.Errorf("a notification naming %q: %d %.100s", h, r.status, r.body)
		}
	}
	for name, body := range map[string]string{
		"a DOCTYPE with an entity": `<!DOCTYPE x [<!ENTITY h "rovara-heavy-x">]>` + cfg("&h;"),
		"an undefined entity":      cfg("arn:aws:sqs:us-east-1:000000000000:&nbsp;x"),
		"unbalanced":               `<NotificationConfiguration><Queue>`,
		"an attribute":             `<NotificationConfiguration x="rovara&#45;heavy-x"/>`,
	} {
		want := 400 // text that cannot be read is a plain malformed-input answer, not the "reserved" one
		if name == "an attribute" {
			want = 403
		}
		if r := f.do("PUT", "/mine?notification", scopeHdr("s3"), body); r.status != want || (want == 400 && strings.Contains(r.body, "reserved")) {
			t.Errorf("%s: %d %s", name, r.status, r.body)
		}
	}
	if r := f.do("PUT", "/mine?notification", scopeHdr("s3"), cfg("arn:aws:sqs:us-east-1:000000000000:orders")); r.status == 403 {
		t.Errorf("a customer's own queue: %d %s", r.status, r.body)
	}
	if found, err := xmlHasHidden([]byte(`<a>x &amp; rovara-heavy-x</a>`)); !found || err != nil {
		t.Errorf("a name after a decoded ampersand still starts a name: %v %v", found, err)
	}
	if found, err := xmlHasHidden([]byte(`<a>my-rovara-heavy-x</a>`)); found || err != nil {
		t.Errorf("a name inside a longer name is not it: %v %v", found, err)
	}
}

// ---- 5. the digest of an object goes into the signature

func TestObjectContentIsPartOfTheSignature(t *testing.T) {
	f := startRunnerFront(t, func(c *Config) { c.Runner.NoDispatch = true })
	rs := f.srv.runner
	f.create("fl-o", "python3.12", map[string]any{"Timeout": 30}, heavyZip())
	event := `{"op":"echo","pad":"` + strings.Repeat("z", 300) + `"}`
	sum := sha256.Sum256([]byte(event))
	sha := hex.EncodeToString(sum[:])
	req := "obj-1"
	reply := "https://sqs.us-east-1.amazonaws.com/000000000000/" + rs.names().replyPrefix + "obj1"
	mk := func(sig string, sha string) stubRequest {
		return stubRequest{V: 1, Fn: "fl-o", Ver: "$LATEST", Req: req, Reply: reply, S3Key: "req/" + req, S3Sha: sha, Rem: 29000, Sig: sig}
	}
	good := rs.sign("q1", req, reply, "fl-o", "$LATEST", "29000", "req/"+req+":"+sha)
	if !rs.authentic(mk(good, sha)) {
		t.Fatal("a pointer with the digest it was signed with")
	}
	req = "obj-2"
	reply = "https://sqs.us-east-1.amazonaws.com/000000000000/" + rs.names().replyPrefix + "obj2"
	if rs.authentic(mk(good, strings.Repeat("0", 64))) {
		t.Errorf("a different digest under the same signature is dropped")
	}
	if rs.authentic(mk(rs.sign("q1", req, reply, "fl-o", "$LATEST", "29000", "req/"+req), sha)) {
		t.Errorf("a signature that does not cover the digest is dropped")
	}
	// the dispatcher compares what it fetches with the signed digest
	nm := rs.names()
	var served string
	sc := &scripted{h: func(svc, method, path string, hdr map[string]string, body []byte) (int, string) {
		if svc == "s3" && method == "GET" && strings.Contains(path, nm.bucket) {
			return 200, served
		}
		return 200, `{}`
	}}
	rs.call = sc.call
	run := func(object string) stubReply {
		served = object
		req = "obj-3"
		reply = "https://sqs.us-east-1.amazonaws.com/000000000000/" + nm.replyPrefix + "obj3"
		sr := mk("", sha)
		return rs.runStub(sr)
	}
	if r := run(event); !r.OK {
		t.Errorf("the object the stub signed runs: %+v", r)
	}
	if r := run(`{"op":"echo","pad":"changed"}`); r.OK || r.ErrorType != "Rovara.RunnerError" || !strings.Contains(r.ErrorMessage, "digest") {
		t.Errorf("an object changed on its way is refused: %+v", r)
	}
	// the reply says what its object holds, and the stub checks it
	raw := []byte(`{"data":"` + strings.Repeat("q", 250000) + `"}`)
	res := &runnerResult{Status: "ok", Payload: base64.StdEncoding.EncodeToString(raw)}
	rep := rs.replyFor("fl-o", &fnVer{Timeout: 30}, res, false, "obj-4")
	rsum := sha256.Sum256(raw)
	if rep.S3Key == "" || rep.S3Sha != hex.EncodeToString(rsum[:]) {
		t.Errorf("the reply carries the digest of its object: %+v", rep.S3Key)
	}
	src := stubSourceOf(t, mustStub(rs))
	for _, want := range []string{`hashlib.sha256(blob).hexdigest()`, `msg["s3Sha"]`, `answer.get("s3Sha")`, `(msg["s3Key"] + ":" + msg["s3Sha"])`} {
		if !strings.Contains(src, want) {
			t.Errorf("the stub signs and checks digests: missing %s", want)
		}
	}
}

func mustStub(rs *runnerSys) []byte { b, _ := rs.stub(); return b }

// ---- 6. data-plane bodies are the app's own

func TestDataPlaneBodiesAreNotReadOrDecoded(t *testing.T) {
	f := startRunnerFront(t, nil)
	f.create("fl-d", "java21", nil, pyZip())
	big := strings.Repeat("p", 2<<20)
	name := "rovara-heavy-x"
	status := func(label string, r result) {
		t.Helper()
		if r.status == 403 || r.status == 413 || r.status == 415 || (r.status == 400 && strings.Contains(r.body, "could not be read")) {
			t.Errorf("%s must reach the engine: %d %.100s", label, r.status, r.body)
		}
	}
	lam := with(scopeHdr("lambda"), "Content-Type", "application/json")
	status("InvokeAsync with 2 MiB naming the prefix", f.do("POST", "/2014-11-13/functions/fl-d/invoke-async/", lam, `{"x":"`+name+big+`"}`))
	status("InvokeWithResponseStream", f.do("POST", "/2021-11-15/functions/fl-d/response-streaming-invocations", lam, `{"x":"`+name+big+`"}`))
	status("Invoke of a light function with a hidden-looking payload", f.do("POST", "/2015-03-31/functions/fl-plain/invocations", lam, `{"q":"`+name+`"}`))
	// an app posting to its own API Gateway endpoint or function URL: gzip and br are the app's
	for _, c := range []struct{ path, host string }{{"/_aws/execute-api/abc123/$default/x", ""}, {"/x", "abc123.execute-api.us-east-1.amazonaws.com"}, {"/x", "abc123.lambda-url.us-east-1.on.aws"}} {
		for _, enc := range []string{"gzip", "br", "aws-chunked"} {
			h := map[string][]string{"Content-Encoding": {enc}, "Content-Type": {"application/json"}}
			if c.host != "" {
				h["Host"] = []string{c.host}
			}
			req, _ := http.NewRequest("POST", f.ts.URL+c.path, bytes.NewReader(gz([]byte(`{"q":"`+name+`"}`))))
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
			resp.Body.Close()
			if resp.StatusCode == 403 || resp.StatusCode == 415 {
				t.Errorf("%s %s with Content-Encoding %s: %d", c.path, c.host, enc, resp.StatusCode)
			}
		}
	}
	// published data that merely mentions the prefix
	status("PutEvents", f.do("POST", "/", jsonRPC("events", "AWSEvents.PutEvents"), `{"Entries":[{"Source":"a","DetailType":"b","Detail":"{\"q\":\"`+name+`\"}"}]}`))
	status("SNS Publish", f.do("POST", "/", formHdr("sns"), "Action=Publish&Version=2010-03-31&TopicArn=arn%3Aaws%3Asns%3Aus-east-1%3A000000000000%3At&Message="+name))
	// ... while the control-plane calls next to them still refuse it
	if r := f.do("POST", "/", jsonRPC("events", "AWSEvents.PutTargets"), `{"Rule":"r","Targets":[{"Id":"1","Arn":"arn:aws:sqs:us-east-1:000000000000:`+name+`"}]}`); r.status != 403 {
		t.Errorf("PutTargets: %d", r.status)
	}
}

func TestShimServicesAreDataPlane(t *testing.T) {
	r, _ := http.NewRequest("POST", "http://aws/model/x/converse", nil)
	for _, key := range []string{"bedrock-runtime", "sagemaker-runtime", "s3"} {
		if !runnerDataPlane(r, key, "InvokeModel") {
			t.Errorf("%s bodies are the app's own", key)
		}
	}
	if runnerDataPlane(r, "sqs", "SendMessage") || runnerDataPlane(r, "lambda", "CreateFunction") {
		t.Errorf("control-plane calls are not data plane")
	}
}

// ---- 7. h2c: see runner_h2c_test.go (Go 1.24 and later)

var _ = fmt.Sprint
