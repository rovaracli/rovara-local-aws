package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Regression tests for the review of the runner's hidden plumbing (probes of the Opus review, 2026-11-12): the guard works on DECODED values
// (a form and a query merged, JSON read as JSON), every service that names things is looked at, the stub's messages are signed, and a reset
// is a real barrier.

const hq = "http://aws:4566/000000000000/rovara-heavy-req"

func formHdr(svc string) map[string]string {
	return with(scopeHdr(svc), "Content-Type", "application/x-www-form-urlencoded")
}

func jsonRPC(svc, target string) map[string]string {
	return with(scopeHdr(svc), "Content-Type", "application/x-amz-json-1.0", "X-Amz-Target", target)
}

func TestGuardRefusesEverySpellingOfTheHiddenNames(t *testing.T) {
	f := startRunnerFront(t, nil)
	f.create("fl-g", "java21", nil, pyZip()) // makes the plumbing
	q := url.QueryEscape(hq)
	refused := func(name string, r result) {
		t.Helper()
		if r.status != 403 {
			t.Errorf("%s: %d %.160s", name, r.status, r.body)
		}
	}
	allowed := func(name string, r result) {
		t.Helper()
		if r.status == 403 {
			t.Errorf("%s must not be refused: %.160s", name, r.body)
		}
	}
	// SQS Query: the URL query and the form are merged by the front, so both are looked at
	refused("GET with QueueUrl in the query", f.do("GET", "/?Action=GetQueueAttributes&Version=2012-11-05&AttributeName.1=All&QueueUrl="+q, scopeHdr("sqs"), ""))
	refused("POST form with QueueUrl in the URL query", f.do("POST", "/?QueueUrl="+q, formHdr("sqs"), "Action=GetQueueAttributes&Version=2012-11-05"))
	refused("form QueueUrl with the other spelled in the query", f.do("POST", "/?QueueUrl=http%3A%2F%2Faws%3A4566%2F000000000000%2Fmine", formHdr("sqs"), "Action=Purge&Version=2012-11-05&QueueUrl="+q))
	refused("PurgeQueue by form", f.do("POST", "/", formHdr("sqs"), "Action=PurgeQueue&Version=2012-11-05&QueueUrl="+q))
	refused("DeleteQueue by form", f.do("POST", "/", formHdr("sqs"), "Action=DeleteQueue&Version=2012-11-05&QueueUrl="+q))
	refused("SetQueueAttributes by form", f.do("POST", "/", formHdr("sqs"), "Action=SetQueueAttributes&Version=2012-11-05&Attribute.1.Name=VisibilityTimeout&Attribute.1.Value=0&QueueUrl="+q))
	refused("percent-escaped name", f.do("POST", "/", formHdr("sqs"), "Action=ReceiveMessage&Version=2012-11-05&QueueUrl="+url.QueryEscape("http://aws:4566/000000000000/rovara%2Dheavy%2Dreq")))
	refused("trailing slash", f.do("POST", "/", formHdr("sqs"), "Action=ReceiveMessage&Version=2012-11-05&QueueUrl="+url.QueryEscape(hq+"/")))
	refused("a query string on the URL", f.do("POST", "/", formHdr("sqs"), "Action=ReceiveMessage&Version=2012-11-05&QueueUrl="+url.QueryEscape(hq+"?x=1")))
	// SQS JSON: decoded, so an escape is a hyphen
	sq := func(op string) map[string]string { return sqsJSON(op) }
	refused("JSON \\u002d escapes", f.do("POST", "/", sq("GetQueueAttributes"), `{"QueueUrl":"http://aws:4566/000000000000/rovara\u002dheavy\u002dreq","AttributeNames":["All"]}`))
	refused("JSON escaped key order", f.do("POST", "/", sq("SendMessage"), `{"MessageBody":"x","QueueUrl":"http://aws:4566/000000000000/\u0072ovara-heavy-req"}`))
	refused("JSON batch", f.do("POST", "/", sq("DeleteMessageBatch"), `{"Entries":[],"QueueUrl":"`+hq+`/"}`))
	refused("a queue ARN in an attribute", f.do("POST", "/", sq("CreateQueue"), `{"QueueName":"x","Attributes":{"RedrivePolicy":"{\"deadLetterTargetArn\":\"arn:aws:sqs:us-east-1:000000000000:rovara-heavy-req\",\"maxReceiveCount\":1}"}}`))
	if r := f.do("POST", "/", sq("GetQueueAttributes"), `{"Pad":"`+strings.Repeat("a", 1<<20)+`","QueueUrl":"`+hq+`"}`); r.status != 403 {
		t.Errorf("a body padded past 1 MiB is read (the engine's limit is 16 MiB) and refused for what it names: %d", r.status)
	}
	if r := f.do("POST", "/", sq("GetQueueAttributes"), `{"Pad":"`+strings.Repeat("a", 17<<20)+`","QueueUrl":"`+hq+`"}`); r.status != 413 {
		t.Errorf("a body over the engine's own limit: %d", r.status)
	}
	allowed("a customer queue", f.do("POST", "/", sq("CreateQueue"), `{"QueueName":"my-rovara-heavy-notes"}`))
	allowed("a message that merely says so", f.do("POST", "/", sq("SendMessage"), `{"QueueUrl":"http://aws:4566/000000000000/orders","MessageBody":"see /rovara-heavy-req"}`))
	allowed("a Query message that merely says so", f.do("POST", "/", formHdr("sqs"), "Action=SendMessage&Version=2012-11-05&QueueUrl="+url.QueryEscape("http://aws:4566/000000000000/orders")+"&MessageBody=rovara-heavy-req"))

	// IAM, by form, by query, by GET
	refused("iam form + RoleName in the query", f.do("POST", "/?RoleName="+hiddenRole, formHdr("iam"), "Action=GetRole&Version=2010-05-08"))
	refused("iam GET", f.do("GET", "/?Action=GetRole&Version=2010-05-08&RoleName="+hiddenRole, scopeHdr("iam"), ""))
	refused("iam ListRolePolicies", f.do("GET", "/?Action=ListRolePolicies&Version=2010-05-08&RoleName="+hiddenRole, scopeHdr("iam"), ""))
	refused("iam PutRolePolicy", f.do("POST", "/", formHdr("iam"), "Action=PutRolePolicy&Version=2010-05-08&PolicyName=x&PolicyDocument=%7B%7D&RoleName="+hiddenRole))
	refused("iam a role ARN", f.do("POST", "/", formHdr("iam"), "Action=AttachRolePolicy&Version=2010-05-08&PolicyArn=x&RoleName=path%2F"+hiddenRole))
	refused("sts AssumeRole", f.do("POST", "/", formHdr("sts"), "Action=AssumeRole&Version=2011-06-15&RoleSessionName=x&RoleArn="+url.QueryEscape(f.srv.runner.names().roleARN)))
	allowed("another role", f.do("GET", "/?Action=GetRole&Version=2010-05-08&RoleName=mine", scopeHdr("iam"), ""))

	// S3: the bucket, and a copy from it
	for _, src := range []string{"/" + hiddenBucket + "/req/x", hiddenBucket + "/req/x", url.PathEscape(hiddenBucket + "/req/x"), "arn:aws:s3:::" + hiddenBucket + "/req/x"} {
		refused("CopyObject from "+src, f.do("PUT", "/mine/k", with(scopeHdr("s3"), "x-amz-copy-source", src), ""))
	}
	refused("UploadPartCopy", f.do("PUT", "/mine/k?partNumber=1&uploadId=u", with(scopeHdr("s3"), "x-amz-copy-source", "/"+hiddenBucket+"/req/x"), ""))
	refused("a bucket notification into the plumbing", f.do("PUT", "/mine?notification", scopeHdr("s3"),
		`<NotificationConfiguration><QueueConfiguration><Queue>arn:aws:sqs:us-east-1:000000000000:rovara-heavy-req</Queue><Event>s3:ObjectCreated:*</Event></QueueConfiguration></NotificationConfiguration>`))
	allowed("a copy between customer buckets", f.do("PUT", "/mine/k", with(scopeHdr("s3"), "x-amz-copy-source", "/other/k"), ""))

	// Lambda: the role, code from the bucket, a mapping on the queue, destinations
	zb := base64.StdEncoding.EncodeToString(pyZip())
	role := "arn:aws:iam::000000000000:role/"
	refused("CreateFunction with the stub's role", f.lambda("POST", "/2015-03-31/functions", map[string]any{"FunctionName": "fl-r", "Runtime": "python3.12", "Role": role + hiddenRole, "Handler": "a.b", "Code": map[string]any{"ZipFile": zb}}))
	refused("CreateFunction with the role, escaped", f.do("POST", "/2015-03-31/functions", with(scopeHdr("lambda"), "Content-Type", "application/json"),
		`{"FunctionName":"fl-r2","Runtime":"python3.12","Role":"`+role+`rovara\u002dheavy\u002dstub","Handler":"a.b","Code":{"ZipFile":"`+zb+`"}}`))
	refused("CreateFunction with code from the bucket", f.lambda("POST", "/2015-03-31/functions", map[string]any{"FunctionName": "fl-s3", "Runtime": "python3.12", "Role": role + "r", "Handler": "a.b", "Code": map[string]any{"S3Bucket": hiddenBucket, "S3Key": "req/none"}}))
	refused("UpdateFunctionCode from the bucket", f.lambda("PUT", "/2015-03-31/functions/fl-g/code", map[string]any{"S3Bucket": hiddenBucket, "S3Key": "req/none"}))
	refused("PublishLayerVersion from the bucket", f.lambda("POST", "/2018-10-31/layers/fl-hl/versions", map[string]any{"Content": map[string]any{"S3Bucket": hiddenBucket, "S3Key": "req/none"}}))
	refused("UpdateFunctionConfiguration with the role", f.lambda("PUT", "/2015-03-31/functions/fl-g/configuration", map[string]any{"Role": role + hiddenRole}))
	refused("an event source mapping on the request queue", f.lambda("POST", "/2015-03-31/event-source-mappings/", map[string]any{"FunctionName": "fl-g", "EventSourceArn": "arn:aws:sqs:us-east-1:000000000000:rovara-heavy-req"}))
	refused("a destination in the plumbing", f.lambda("PUT", "/2019-09-25/functions/fl-g/event-invoke-config", map[string]any{"DestinationConfig": map[string]any{"OnFailure": map[string]any{"Destination": "arn:aws:sqs:us-east-1:000000000000:rovara-reply-x"}}}))
	allowed("a function in another role", f.lambda("POST", "/2015-03-31/functions", map[string]any{"FunctionName": "fl-ok", "Runtime": "python3.12", "Role": role + "mine-rovara-heavy-ish", "Handler": "a.b", "Code": map[string]any{"ZipFile": zb}}))

	// Step Functions, EventBridge, Scheduler, SNS
	def := `{"StartAt":"A","States":{"A":{"Type":"Task","Resource":"arn:aws:states:::sqs:sendMessage","Parameters":{"QueueUrl":"` + hq + `","MessageBody":"x"},"End":true}}}`
	refused("a state machine that sends to the request queue", f.do("POST", "/", jsonRPC("states", "AWSStepFunctions.CreateStateMachine"), jsonStr(map[string]any{"name": "m", "definition": def, "roleArn": role + "r"})))
	esc := strings.ReplaceAll(def, "rovara-heavy-req", `rovara\u002dheavy\u002dreq`)
	refused("the same with the name escaped inside the definition", f.do("POST", "/", jsonRPC("states", "AWSStepFunctions.CreateStateMachine"), jsonStr(map[string]any{"name": "m", "definition": esc, "roleArn": role + "r"})))
	refused("a state machine in the stub's role", f.do("POST", "/", jsonRPC("states", "AWSStepFunctions.CreateStateMachine"), jsonStr(map[string]any{"name": "m", "definition": `{"StartAt":"A","States":{"A":{"Type":"Pass","End":true}}}`, "roleArn": role + hiddenRole})))
	refused("an EventBridge target on the request queue", f.do("POST", "/", jsonRPC("events", "AWSEvents.PutTargets"), `{"Rule":"r","Targets":[{"Id":"1","Arn":"arn:aws:sqs:us-east-1:000000000000:rovara-heavy-req"}]}`))
	refused("a schedule on the request queue", f.do("POST", "/schedules/s1", with(scopeHdr("scheduler"), "Content-Type", "application/json"), `{"Target":{"Arn":"arn:aws:sqs:us-east-1:000000000000:rovara-heavy-req","RoleArn":"`+role+`r"},"ScheduleExpression":"rate(1 hour)","FlexibleTimeWindow":{"Mode":"OFF"}}`))
	refused("an SNS subscription to the request queue", f.do("POST", "/", formHdr("sns"), "Action=Subscribe&Version=2010-03-31&TopicArn=arn%3Aaws%3Asns%3Aus-east-1%3A000000000000%3At&Protocol=sqs&Endpoint="+url.QueryEscape("arn:aws:sqs:us-east-1:000000000000:rovara-heavy-req")))
	allowed("an SNS publish that mentions it", f.do("POST", "/", formHdr("sns"), "Action=Publish&Version=2010-03-31&TopicArn=arn%3Aaws%3Asns%3Aus-east-1%3A000000000000%3At&Message=rovara-heavy-req"))
}

func jsonStr(v any) string { b, _ := json.Marshal(v); return string(b) }

func TestGuardRefusesTemplatesThatNameTheHiddenPlumbing(t *testing.T) {
	f := startRunnerFront(t, nil)
	cfn := func(tpl string) result {
		form := url.Values{"Action": {"CreateStack"}, "Version": {"2010-05-15"}, "StackName": {"st"}, "TemplateBody": {tpl}}
		return f.do("POST", "/", formHdr("cloudformation"), form.Encode())
	}
	policy := `{"Resources":{"P":{"Type":"AWS::IAM::Policy","Properties":{"PolicyName":"deny","Roles":["` + hiddenRole + `"],"PolicyDocument":{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}}}}}`
	if r := cfn(policy); r.status != 403 {
		t.Errorf("a policy on the stub's role: %d %.200s", r.status, r.body)
	}
	qp := `{"Resources":{"P":{"Type":"AWS::SQS::QueuePolicy","Properties":{"Queues":["` + hq + `"],"PolicyDocument":{"Statement":[{"Effect":"Deny","Principal":"*","Action":"sqs:*","Resource":"*"}]}}}}}`
	if r := cfn(qp); r.status != 403 {
		t.Errorf("a queue policy on the request queue: %d", r.status)
	}
	if r := cfn(strings.ReplaceAll(qp, "rovara-heavy-req", `rovara\u002dheavy\u002dreq`)); r.status != 403 {
		t.Errorf("an escaped name in a JSON template: %d", r.status)
	}
	yaml := "Resources:\n  P:\n    Type: AWS::IAM::Policy\n    Properties:\n      PolicyName: x\n      Roles:\n        - !Ref Nope\n        - \"rovara\\x2dheavy\\x2dstub\"\n"
	if r := cfn(yaml); r.status != 403 {
		t.Errorf("a YAML escape: %d %.200s", r.status, r.body)
	}
	if r := cfn(`{"Resources":{"Q":{"Type":"AWS::SQS::Queue","Properties":{"QueueName":"orders"}}}}`); r.status == 403 {
		t.Errorf("an ordinary template must pass: %s", r.body)
	}
	// a template fetched by URL is read the same way (the fake engine's S3 serves /tplbkt/*): the object that names the plumbing
	form := url.Values{"Action": {"CreateStack"}, "Version": {"2010-05-15"}, "StackName": {"st2"}, "TemplateURL": {"http://aws:4566/tplbkt/hidden.json"}}
	if r := f.do("POST", "/", formHdr("cloudformation"), form.Encode()); r.status != 403 {
		t.Errorf("a template fetched from the engine's S3: %d %.200s", r.status, r.body)
	}
}

func TestGuardDoesNotRefuseWhenTheRunnerIsOff(t *testing.T) {
	f := startLambdaFront(t, "sqs", "iam")
	if r := f.do("POST", "/", sqsJSON("CreateQueue"), `{"QueueName":"rovara-heavy-mine"}`); r.status == 403 {
		t.Errorf("without a runner nothing is reserved")
	}
}

// ---- the stub's messages are signed

func TestStubRequestsAreAuthenticated(t *testing.T) {
	f := startRunnerFront(t, nil)
	rs := f.srv.runner
	mk := func(req string, mut func(*stubRequest)) stubRequest {
		sr := stubRequest{V: 1, Fn: "fl-x", Ver: "$LATEST", Req: req, Reply: "https://sqs.us-east-1.amazonaws.com/000000000000/" + rs.names().replyPrefix + strings.ReplaceAll(req, "-", ""), Event: `{"a":1}`, Rem: 29000}
		sr.Sig = rs.sign("q1", sr.Req, sr.Reply, sr.Fn, sr.Ver, "29000", sr.Event)
		if mut != nil {
			mut(&sr)
		}
		return sr
	}
	if !rs.authentic(mk("r-good", nil)) {
		t.Fatal("a request signed by this generation is served")
	}
	for name, sr := range map[string]stubRequest{
		"unsigned":           mk("r-1", func(s *stubRequest) { s.Sig = "" }),
		"a bad signature":    mk("r-2", func(s *stubRequest) { s.Sig = strings.Repeat("0", 64) }),
		"a changed event":    mk("r-3", func(s *stubRequest) { s.Event = `{"a":2}` }),
		"a changed function": mk("r-4", func(s *stubRequest) { s.Fn = "fl-y" }),
		"a changed reply":    mk("r-5", func(s *stubRequest) { s.Reply = "http://aws:4566/000000000000/customer-queue" }),
		"a signed reply elsewhere": mk("r-6", func(s *stubRequest) {
			s.Reply = "http://aws:4566/000000000000/customer-queue"
			s.Sig = rs.sign("q1", s.Req, s.Reply, s.Fn, s.Ver, "29000", s.Event)
		}),
		"a pointer of another req": mk("r-7", func(s *stubRequest) { s.S3Key = "req/other" }),
		"a bad request id":         mk("r 8", nil),
		"a signature of the other kind": mk("r-9", func(s *stubRequest) {
			s.Sig = rs.sign("r1", s.Req, s.Event)
		}),
	} {
		if rs.authentic(sr) {
			t.Errorf("%s must be dropped", name)
		}
	}
	if rs.authentic(mk("r-good", nil)) {
		t.Errorf("a request id is served once: a replay is dropped")
	}
	// another generation's signature is no good
	old := mk("r-old", nil)
	rs.reset()
	if rs.authentic(old) {
		t.Errorf("after a reset the old secret signs nothing")
	}
	if !rs.authentic(mk("r-new", nil)) {
		t.Errorf("and the new one does")
	}
	// the stub bakes in the secret of its generation, and a new generation changes it and the Code.Location key
	b1, _ := rs.stub()
	rs.reset()
	if b2, _ := rs.stub(); string(b1) == string(b2) {
		t.Errorf("the stub changes with the secret")
	}
}

// ---- the reset barrier

func TestResetIsABarrier(t *testing.T) {
	f := startRunnerFront(t, nil)
	f.create("fl-b", "python3.12", map[string]any{"Timeout": 60}, heavyZip())
	f.srv.runner.retryDelay = 300 * time.Millisecond
	slow := make(chan result, 1)
	go func() { slow <- f.invoke("fl-b", `{"op":"sleep","ms":5000}`, nil) }()
	waitFor(t, "the slow invoke to start", func() bool { return atomic.LoadInt32(&f.w.inflight) == 1 })
	// an async call that fails, so it would retry after the reset
	f.invoke("fl-b", `{"op":"error","type":"E","msg":"m"}`, map[string]string{"X-Amz-Invocation-Type": "Event"})
	waitFor(t, "the first async attempt", func() bool { return atomic.LoadInt32(&f.w.invokes) >= 2 })
	before := atomic.LoadInt32(&f.w.registers)
	t0 := time.Now()
	if r := f.do("POST", "/_rovara/reset", tok(), ""); r.status != 200 {
		t.Fatalf("reset: %d", r.status)
	}
	if time.Since(t0) > 4*time.Second {
		t.Errorf("a reset does not wait for a 5 s function: it cancels it (%v)", time.Since(t0))
	}
	select {
	case r := <-slow:
		if !strings.Contains(r.body, "Rovara.RunnerUnavailable") && r.status != 499 {
			t.Errorf("the in-flight call ends with a runner error: %d %.200s", r.status, r.body)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the in-flight call never ended")
	}
	invokes := atomic.LoadInt32(&f.w.invokes)
	time.Sleep(900 * time.Millisecond) // past several retry delays
	if n := atomic.LoadInt32(&f.w.invokes); n != invokes {
		t.Errorf("an async retry ran after the reset: %d -> %d invokes", invokes, n)
	}
	if n := atomic.LoadInt32(&f.w.registers); n != before {
		t.Errorf("nothing registered after the worker confirmed stop_all: %d -> %d", before, n)
	}
	// a call made while a reset is under way is refused, and so is one that read the registry in an earlier generation
	old := f.srv.runner.genNum()
	f.srv.runner.quiesce()
	if _, _, ok := f.srv.runner.begin(old); ok {
		t.Errorf("no run is admitted between quiesce and resume")
	}
	f.srv.runner.resume()
	if _, _, ok := f.srv.runner.begin(old); ok {
		t.Errorf("a run that read the registry before the reset is not admitted after it")
	}
	if _, done, ok := f.srv.runner.begin(f.srv.runner.genNum()); !ok {
		t.Errorf("runs are admitted again after resume")
	} else {
		done()
	}
}

// ---- the socket

func TestRunnerSocketRules(t *testing.T) {
	st, _ := newRunnerStore(t.TempDir(), 1<<20)
	for _, bad := range []string{"relative/runner.sock", "runner.sock", "@abstract", "/tmp/x\x00y"} {
		if err := newRunnerHub(bad, st, "t").start(); err == nil {
			t.Errorf("%q must be refused", bad)
		}
	}
	// an existing directory of ours that is open to others is made private before the listen
	dir, _ := os.MkdirTemp("", "rd")
	defer os.RemoveAll(dir)
	os.Chmod(dir, 0o755)
	h := newRunnerHub(dir+"/s.sock", st, "t")
	if err := h.start(); err != nil {
		t.Fatal(err)
	}
	defer h.close()
	if fi, _ := os.Stat(dir); fi.Mode().Perm() != 0o700 {
		t.Errorf("the directory is chmod 0700: %v", fi.Mode().Perm())
	}
}

func TestStoreMustFitItsFileSystem(t *testing.T) {
	free, ok := freeBytes(t.TempDir())
	if !ok {
		t.Skip("no free-space check on this platform")
	}
	f := startFront(t, func(c *Config) {
		c.Planned = map[string]bool{"lambda": true}
		c.PlannedKeys = []string{"lambda"}
		c.Runner = &RunnerConfig{Socket: tmpSocket(t), StoreDir: t.TempDir(), StoreMax: free + (1 << 30), MaxDirect: 4}
	})
	if err := f.srv.startRunner(); err == nil || !strings.Contains(err.Error(), "free") {
		t.Errorf("a store bigger than its file system is refused at start: %v", err)
	}
}

func TestBigPackageBodiesAreCountedAndReleased(t *testing.T) {
	f := startRunnerFront(t, nil)
	noise := make([]byte, 6<<20)
	for i := range noise {
		noise[i] = byte(i*7 + i>>8)
	}
	big := testZip(zent{"app.py", []byte("x")}, zent{"lib/n.so", append(testELF(elfMachineAArch64), noise...)})
	if r := f.create("fl-big", "python3.12", nil, big); r.status != 201 {
		t.Fatalf("create: %d %.200s", r.status, r.body)
	}
	if !f.srv.runner.reg.isTaken("fl-big") {
		t.Fatal("a 6 MB native package is taken over")
	}
	if used := f.srv.budget.used; used != 0 {
		t.Errorf("every copy counted in the inspection budget is released: %d", used)
	}
	if n := len(f.srv.runner.big); n != 0 {
		t.Errorf("the one-at-a-time slot is released: %d", n)
	}
	_ = context.Background
}

func TestHiddenInAuthorizationDetails(t *testing.T) {
	xml := `<GetAccountAuthorizationDetailsResult><RoleDetailList><member><RoleName>a</RoleName><RolePolicyList><member><PolicyName>p</PolicyName></member></RolePolicyList></member>` +
		`<member><RoleName>` + hiddenRole + `</RoleName><RolePolicyList><member><PolicyName>rendezvous</PolicyName></member></RolePolicyList></member></RoleDetailList></GetAccountAuthorizationDetailsResult>`
	got := string(hideInLists([]byte(xml)))
	if strings.Contains(got, hiddenRole) || strings.Contains(got, "rendezvous") || !strings.Contains(got, "<RoleName>a</RoleName>") {
		t.Errorf("GetAccountAuthorizationDetails: %s", got)
	}
	if runnerRewriteKind(identified{Service: &service{Key: "iam"}, Operation: "GetAccountAuthorizationDetails"}) != rwRunnerHide {
		t.Errorf("the answer is filtered")
	}
}
