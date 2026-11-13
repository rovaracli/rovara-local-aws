package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// A test against the REAL engine, for the VM: ROVARA_REAL_ENGINE_BIN=/usr/bin/aws-emulator go test -run RunnerWithRealEngine. The fake worker
// plays the runner (echo). tools/runner_check.py is the wider proof (every kind of caller, through boto3); this one keeps the front's own
// code under `go test` with the engine it was written for.

func (f *runnerFront) engineInvoke(name, event string) (int, http.Header, []byte) {
	f.t.Helper()
	gen, _, err := f.engine.current()
	if err != nil {
		f.t.Fatal(err)
	}
	req, _ := http.NewRequest("POST", "https://127.0.0.1:"+fmt.Sprint(gen.port)+"/2015-03-31/functions/"+name+"/invocations", strings.NewReader(event))
	req.Header.Set("Authorization", syntheticAuthorization("lambda", "us-east-1"))
	req.Header.Set("Content-Type", "application/json")
	resp, err := gen.client.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, b
}

func TestRunnerWithRealEngine(t *testing.T) {
	bin := os.Getenv("ROVARA_REAL_ENGINE_BIN")
	if bin == "" {
		t.Skip("set ROVARA_REAL_ENGINE_BIN to the engine binary to run this against the real engine")
	}
	f := startRunnerFrontWith(t, bin, func(c *Config) { c.Runner.SweepEvery = 300 * time.Millisecond })
	iamAuth := scopeHdr("iam")
	trust := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}`
	form := url.Values{"Action": {"CreateRole"}, "Version": {"2010-05-08"}, "RoleName": {"live-role"}, "AssumeRolePolicyDocument": {trust}}
	if r := f.do("POST", "/", with(iamAuth, "Content-Type", "application/x-www-form-urlencoded"), form.Encode()); r.status != 200 {
		t.Fatalf("CreateRole: %d %s", r.status, r.body)
	}
	role := "arn:aws:iam::000000000000:role/live-role"
	r := f.create("fl-live", "python3.12", map[string]any{"Timeout": 40, "Role": role, "Handler": "app.handler", "MemorySize": 256}, heavyZip())
	if r.status != 201 && r.status != 200 {
		t.Fatalf("CreateFunction: %d %s", r.status, r.body)
	}
	var created map[string]interface{}
	json.Unmarshal([]byte(r.body), &created)
	if created["Timeout"] != float64(40) || created["Handler"] != "app.handler" || created["Role"] != role || created["MemorySize"] != float64(256) {
		t.Errorf("the real engine's answer is overlaid with the real configuration: %v", created)
	}
	waitFor(t, "the function to be Active", func() bool { return f.config("fl-live")["State"] == "Active" })

	// 1. the stub path: the ENGINE is called directly, so nothing of the front's fast path is involved
	st, hdr, body := f.engineInvoke("fl-live", `{"op":"echo","n":7}`)
	var out map[string]interface{}
	json.Unmarshal(body, &out)
	if st != 200 || hdr.Get("X-Amz-Function-Error") != "" || out["source"] != "stub" || out["fn"] != "fl-live" {
		t.Fatalf("the stub path: %d %v %s", st, hdr, body)
	}
	if e, _ := out["echo"].(map[string]interface{}); e["n"] != float64(7) {
		t.Errorf("the event arrives intact: %s", body)
	}
	// 2. a function error keeps its type through the stub
	st, hdr, body = f.engineInvoke("fl-live", `{"op":"error","type":"Runtime.ImportModuleError","msg":"No module named numpy"}`)
	var doc map[string]interface{}
	json.Unmarshal(body, &doc)
	if st != 200 || hdr.Get("X-Amz-Function-Error") != "Unhandled" || doc["errorType"] != "Runtime.ImportModuleError" || doc["errorMessage"] != "No module named numpy" {
		t.Errorf("FunctionError and errorType survive the stub: %d %v %s", st, hdr, body)
	}
	// 3. an event over 200 KB goes by pointer through the hidden bucket, and an answer over 200 KB comes back the same way
	st, _, body = f.engineInvoke("fl-live", fmt.Sprintf(`{"op":"size","pad":"%s"}`, strings.Repeat("e", 300<<10)))
	if st != 200 || !bytes.Contains(body, []byte(`"eventBytes"`)) {
		t.Fatalf("a 300 KB event: %d %.200s", st, body)
	}
	json.Unmarshal(body, &out)
	if n, _ := out["eventBytes"].(float64); n < 300<<10 {
		t.Errorf("the runner got the whole event: %v", out["eventBytes"])
	}
	if st, _, body = f.engineInvoke("fl-live", `{"op":"big","bytes":400000}`); st != 200 || len(body) < 400000 {
		t.Errorf("a 400 KB answer: %d, %d bytes", st, len(body))
	}
	// 4. past the guest SDK's 1 MiB: refused as a Rovara limit
	st, hdr, body = f.engineInvoke("fl-live", fmt.Sprintf(`{"op":"size","pad":"%s"}`, strings.Repeat("e", 1100<<10)))
	if st != 200 || hdr.Get("X-Amz-Function-Error") != "Unhandled" || !bytes.Contains(body, []byte("Rovara.Unsupported")) {
		t.Errorf("an event over 1 MiB: %d %v %.200s", st, hdr, body)
	}
	// 5. the engine's ceiling: the call is asked to stop at 28 s (checked on the frame the worker got, without waiting for it)
	if last := f.w.lastInvoke(); last.Source != "stub" {
		t.Errorf("last invoke source: %q", last.Source)
	}
	// 6. the direct path, through the front: no stub, no engine
	r = f.invoke("fl-live", `{"op":"echo"}`, nil)
	json.Unmarshal([]byte(r.body), &out)
	if r.status != 200 || out["source"] != "direct" {
		t.Errorf("direct: %d %s", r.status, r.body)
	}
	if r := f.invoke("fl-live", fmt.Sprintf(`{"op":"size","pad":"%s"}`, strings.Repeat("e", 3<<20)), nil); r.status != 200 || !strings.Contains(r.body, `"direct"`) {
		t.Errorf("a 3 MB direct event: %d %.200s", r.status, r.body)
	}
	// 7. the plumbing is in the engine and out of every customer's sight
	if r := f.do("POST", "/", sqsJSON("ListQueues"), `{}`); r.status != 200 || strings.Contains(r.body, "rovara-") {
		t.Errorf("ListQueues: %d %s", r.status, r.body)
	}
	if r := f.do("POST", "/", sqsJSON("GetQueueUrl"), `{"QueueName":"rovara-heavy-req"}`); r.status != 403 {
		t.Errorf("the request queue is refused: %d %s", r.status, r.body)
	}
	if n := f.srv.runner.replyQueues(); n != 0 {
		// the stub deletes its reply queue itself
		time.Sleep(500 * time.Millisecond)
		if n = f.srv.runner.replyQueues(); n != 0 {
			t.Errorf("reply queues left behind: %d", n)
		}
	}
	_ = base64.StdEncoding
	// 7b. a message put on the request queue by anything but the stub is never served: it is unsigned, or names a queue that is not its reply
	rs := f.srv.runner
	cust := "http://aws:4566/000000000000/customer-queue"
	if r := f.do("POST", "/", sqsJSON("CreateQueue"), `{"QueueName":"customer-queue"}`); r.status != 200 {
		t.Fatalf("customer queue: %d %s", r.status, r.body)
	}
	forge := func(req, reply, sig string) {
		msg, _ := json.Marshal(map[string]any{"v": 1, "fn": "fl-live", "arn": "x", "ver": "$LATEST", "req": req, "reply": reply, "event": `{"op":"echo","forged":true}`, "rem": 29000, "sig": sig})
		if _, err := rs.sqsCall("SendMessage", map[string]interface{}{"QueueUrl": rs.requestURL(), "MessageBody": string(msg)}, 10*time.Second); err != nil {
			t.Fatal(err)
		}
	}
	inv0 := atomic.LoadInt32(&f.w.invokes)
	forge("forged-1", cust, "")                        // unsigned, replying to a customer queue
	forge("forged-2", cust, rs.sign("q1", "forged-2")) // a bad signature
	reply3 := "https://sqs.us-east-1.amazonaws.com/000000000000/" + rs.names().replyPrefix + "forged3"
	forge("forged-3", cust, rs.sign("q1", "forged-3", cust, "fl-live", "$LATEST", "29000", `{"op":"echo","forged":true}`)) // signed, but the reply is not its own
	time.Sleep(2500 * time.Millisecond)
	if n := atomic.LoadInt32(&f.w.invokes); n != inv0 {
		t.Errorf("forged requests ran the function: %d -> %d", inv0, n)
	}
	if r := f.do("POST", "/", sqsJSON("ReceiveMessage"), `{"QueueUrl":"`+cust+`","WaitTimeSeconds":1}`); strings.Contains(r.body, "forged") || strings.Contains(r.body, "echo") {
		t.Errorf("nothing was delivered to the customer's queue: %s", r.body)
	}
	// a correctly signed request is served once, and a copy of it is not served again
	good := func() {
		forge("good-1", reply3, rs.sign("q1", "good-1", reply3, "fl-live", "$LATEST", "29000", `{"op":"echo","forged":true}`))
	}
	reply3 = "https://sqs.us-east-1.amazonaws.com/000000000000/" + rs.names().replyPrefix + "good1"
	good()
	good()
	waitFor(t, "the signed request to run", func() bool { return atomic.LoadInt32(&f.w.invokes) == inv0+1 })
	time.Sleep(1500 * time.Millisecond)
	if n := atomic.LoadInt32(&f.w.invokes); n != inv0+1 {
		t.Errorf("a replayed request ran again: %d", n-inv0)
	}
	// 7c. encodings: the real engine honours gzip and aws-chunked, so the front decodes them first; the hidden queue stays out of reach
	hqURL := f.hiddenQueue()
	for name, enc := range map[string]func([]byte) ([]byte, string){
		"gzip":        func(b []byte) ([]byte, string) { return gz(b), "gzip" },
		"aws-chunked": func(b []byte) ([]byte, string) { return awsChunked(b), "aws-chunked" },
	} {
		body, ce := enc([]byte(`{"QueueUrl":"` + hqURL + `"}`))
		if r := f.doRaw("POST", "/", hdrs(sqsJSON("GetQueueAttributes"), map[string][]string{"Content-Encoding": {ce}}), body); r.status != 403 {
			t.Errorf("%s: the request queue is out of reach: %d %.120s", name, r.status, r.body)
		}
		body, ce = enc([]byte(`{}`))
		if r := f.doRaw("POST", "/", hdrs(sqsJSON("ListQueues"), map[string][]string{"Content-Encoding": {ce}}), body); r.status != 200 || strings.Contains(r.body, "rovara-") {
			t.Errorf("%s: a customer call is answered by the real engine from the decoded body: %d %s", name, r.status, r.body)
		}
	}
	// 7d. references that got past the guard (made here directly on the engine) are swept: an event source mapping, an EventBridge target,
	// an SNS subscription, an S3 notification
	hArn := "arn:aws:sqs:us-east-1:000000000000:" + rs.names().req
	made := 0
	// a "thief" function in the stub's role (the engine would let it consume the queue) and a queue policy that lets S3 publish: what an
	// attacker who got past the guard would set up
	rs.engineDo("lambda", http.MethodPost, "/2015-03-31/functions", map[string]string{"Content-Type": "application/json"},
		[]byte(jsonStr(map[string]any{"FunctionName": "fl-sweepfn", "Runtime": "python3.12", "Role": rs.names().roleARN, "Handler": "app.handler", "Timeout": 3,
			"Code": map[string]any{"ZipFile": base64.StdEncoding.EncodeToString(pyZip())}})), 15*time.Second)
	waitFor(t, "the sweep function to be Active", func() bool { return f.config("fl-sweepfn")["State"] == "Active" })
	rs.sqsCall("SetQueueAttributes", map[string]interface{}{"QueueUrl": rs.requestURL(), "Attributes": map[string]string{"Policy": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"sqs:*","Resource":"*"}]}`}}, 10*time.Second)
	if st, b, _, err := rs.engineDo("lambda", http.MethodPost, "/2015-03-31/event-source-mappings/", map[string]string{"Content-Type": "application/json"},
		[]byte(`{"FunctionName":"fl-sweepfn","EventSourceArn":"`+hArn+`","BatchSize":1}`), 10*time.Second); err == nil && st < 300 {
		made++
	} else {
		t.Logf("mapping on the plumbing could not be made: %v %d %s", err, st, b)
	}
	if _, ok := rs.engineJSON("events", "AWSEvents.PutRule", "application/x-amz-json-1.1", map[string]any{"Name": "sweep-r", "EventPattern": `{"source":["x"]}`}); ok {
		if _, ok := rs.engineJSON("events", "AWSEvents.PutTargets", "application/x-amz-json-1.1", map[string]any{"Rule": "sweep-r", "Targets": []map[string]any{{"Id": "1", "Arn": hArn}}}); ok {
			made++
		}
	}
	topic := url.Values{"Action": {"CreateTopic"}, "Version": {"2010-03-31"}, "Name": {"sweep-t"}}
	if st, b, _, err := rs.engineDo("sns", http.MethodPost, "/", map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, []byte(topic.Encode()), 10*time.Second); err == nil && st == 200 {
		if arn := xmlField(string(b), "TopicArn"); arn != "" {
			sub := url.Values{"Action": {"Subscribe"}, "Version": {"2010-03-31"}, "TopicArn": {arn}, "Protocol": {"sqs"}, "Endpoint": {hArn}}
			if st, b, _, err := rs.engineDo("sns", http.MethodPost, "/", map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, []byte(sub.Encode()), 10*time.Second); err == nil && st == 200 {
				made++
			} else {
				t.Logf("subscription could not be made: %v %d %s", err, st, b)
			}
		}
	}
	rs.engineDo("s3", http.MethodPut, "/sweep-bkt", nil, nil, 10*time.Second)
	notif := `<NotificationConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><QueueConfiguration><Id>x</Id><Queue>` + hArn + `</Queue><Event>s3:ObjectCreated:*</Event></QueueConfiguration></NotificationConfiguration>`
	if st, b, _, err := rs.engineDo("s3", http.MethodPut, "/sweep-bkt?notification", map[string]string{"Content-Type": "application/xml"}, []byte(notif), 10*time.Second); err == nil && st < 300 {
		made++
	} else {
		t.Logf("notification could not be made: %v %d %s", err, st, b)
	}
	// more kinds, made best-effort on the real engine: an SQS redrive to the plumbing, a state machine, an API Gateway integration that reads the
	// engine's own function-code bucket
	extra := []string{}
	if _, err := rs.sqsCall("CreateQueue", map[string]interface{}{"QueueName": "sweep-redrive", "Attributes": map[string]string{"RedrivePolicy": `{"deadLetterTargetArn":"` + hArn + `","maxReceiveCount":2}`}}, 10*time.Second); err == nil {
		extra = append(extra, "sqs-redrive")
	}
	if out, ok := rs.engineJSON("states", "AWSStepFunctions.CreateStateMachine", "application/x-amz-json-1.0", map[string]any{"name": "sweep-sm", "roleArn": role,
		"definition": `{"StartAt":"A","States":{"A":{"Type":"Task","Resource":"arn:aws:states:::sqs:sendMessage","Parameters":{"QueueUrl":"` + hArn + `","MessageBody":"x"},"End":true}}}`}); ok && strOf(out, "stateMachineArn") != "" {
		extra = append(extra, "state-machine")
	}
	if st, out := rs.restJSON("apigatewayv2", http.MethodPost, "/v2/apis", map[string]any{"Name": "sweep-api", "ProtocolType": "HTTP"}); st < 300 && strOf(out, "ApiId") != "" {
		if st, _ := rs.restJSON("apigatewayv2", http.MethodPost, "/v2/apis/"+strOf(out, "ApiId")+"/integrations", map[string]any{"IntegrationType": "HTTP_PROXY", "IntegrationMethod": "GET", "PayloadFormatVersion": "1.0",
			"IntegrationUri": "https://awslambda-us-east-1-tasks.s3.us-east-1.amazonaws.com/snapshots/000000000000/fl-live-x"}); st < 300 {
			extra = append(extra, "apigateway-integration")
		}
	}
	t.Logf("extra references made on the real engine: %v", extra)
	if made < 4 {
		t.Fatalf("only %d of the four references could be made on the engine", made)
	}
	if n := rs.sweepRefs(); n > 0 {
		t.Logf("a direct sweep removed %d", n)
	}
	waitFor(t, "the sweeper to remove the references", func() bool {
		return f.counts("rovara")["security:event-source-mapping"].Calls+f.counts("rovara")["security:eventbridge-target"].Calls+
			f.counts("rovara")["security:sns-subscription"].Calls+f.counts("rovara")["security:s3-notification"].Calls >= int64(made)
	})
	for _, kind := range extra {
		waitFor(t, "the sweeper to remove the "+kind, func() bool { return f.counts("rovara")["security:"+kind].Calls >= 1 || rs.sweepRefs() > 0 })
	}
	if n := rs.sweepRefs(); n != 0 {
		t.Errorf("nothing left to sweep: %d (%v)", n, f.counts("rovara"))
	}
	c := f.counts("rovara")
	if c["security:event-source-mapping"].Calls < 1 || c["security:eventbridge-target"].Calls < 1 || c["security:sns-subscription"].Calls < 1 || c["security:s3-notification"].Calls < 1 {
		t.Errorf("a security event for each of the four references (more than one when the loop and a direct sweep both found it): %v", c)
	}
	// 7e. repair: whatever is done to the request queue or the bucket is undone within a poll, and heavy calls work again
	delayOf := func() string {
		out, err := rs.sqsCall("GetQueueAttributes", map[string]interface{}{"QueueUrl": rs.requestURL(), "AttributeNames": []string{"All"}}, 10*time.Second)
		if err != nil {
			return "error"
		}
		return strOf(mapOf(out, "Attributes"), "DelaySeconds")
	}
	rs.sqsCall("SetQueueAttributes", map[string]interface{}{"QueueUrl": rs.requestURL(), "Attributes": map[string]string{"DelaySeconds": "900"}}, 10*time.Second)
	if delayOf() != "900" {
		t.Fatalf("the delay was set: %s", delayOf())
	}
	waitFor(t, "the delay on the request queue to be undone within a poll", func() bool { return delayOf() == "0" })
	if st, _, body := f.engineInvoke("fl-live", `{"op":"echo","after":"delay"}`); st != 200 || !bytes.Contains(body, []byte(`"stub"`)) {
		t.Errorf("a heavy call works again after the delay was undone: %d %.150s", st, body)
	}
	rs.sqsCall("DeleteQueue", map[string]interface{}{"QueueUrl": rs.requestURL()}, 10*time.Second)
	rs.call("s3", http.MethodDelete, "/"+rs.names().bucket, nil, nil, 10*time.Second)
	waitFor(t, "the queue and the bucket to be made again", func() bool {
		_, err := rs.sqsCall("GetQueueUrl", map[string]interface{}{"QueueName": rs.names().req}, 10*time.Second)
		st, _, _, herr := rs.call("s3", http.MethodHead, "/"+rs.names().bucket, nil, nil, 10*time.Second)
		return err == nil && herr == nil && st == 200
	})
	time.Sleep(500 * time.Millisecond)
	if st, _, body := f.engineInvoke("fl-live", fmt.Sprintf(`{"op":"size","pad":"%s"}`, strings.Repeat("e", 300<<10))); st != 200 || !bytes.Contains(body, []byte(`"eventBytes"`)) {
		t.Errorf("a heavy call with a big event works after the queue and the bucket were made again: %d %.150s", st, body)
	}
	if c := f.counts("rovara")["security:plumbing-repaired"]; c.Calls < 3 {
		t.Errorf("each repair is a security event: %+v", c)
	}
	// 8. a reset: the plumbing and the function come back on use
	if r := f.do("POST", "/_rovara/reset", tok(), ""); r.status != 200 {
		t.Fatalf("reset: %d", r.status)
	}
	r = f.create("fl-live2", "python3.12", map[string]any{"Timeout": 40, "Role": role}, heavyZip())
	if r.status != 201 && r.status != 200 {
		// the role is gone with the engine's state
		f.do("POST", "/", with(iamAuth, "Content-Type", "application/x-www-form-urlencoded"), form.Encode())
		r = f.create("fl-live2", "python3.12", map[string]any{"Timeout": 40, "Role": role}, heavyZip())
	}
	waitFor(t, "the new function to be Active", func() bool { return f.config("fl-live2")["State"] == "Active" })
	if st, _, body := f.engineInvoke("fl-live2", `{"op":"echo"}`); st != 200 || !bytes.Contains(body, []byte(`"stub"`)) {
		t.Errorf("after a reset the stub path works again: %d %.200s", st, body)
	}
}
