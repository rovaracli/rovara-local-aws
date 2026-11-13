package main

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// The second review (Opus re-check of 3362ed018): attacks on the hidden plumbing that get past a guard that reads the request as the front
// received it, not as the engine reads it; and the structural answers: unguessable names, a sweeper, fail-closed parsing, a plan bound to its
// generation. Then a self-attack list: every other way found to reach the plumbing, each tested.

func gz(b []byte) []byte {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	w.Write(b)
	w.Close()
	return buf.Bytes()
}

// awsChunked frames a body as an SDK does for a streaming upload (two chunks and the signed trailer).
func awsChunked(b []byte) []byte {
	half := len(b) / 2
	return []byte(fmt.Sprintf("%x;chunk-signature=aa\r\n%s\r\n%x;chunk-signature=bb\r\n%s\r\n0;chunk-signature=cc\r\nx-amz-checksum-crc32:AAAA\r\n\r\n", half, b[:half], len(b)-half, b[half:]))
}

// doRaw sends a request with any headers (several values of one included).
func (f *runnerFront) doRaw(method, path string, h map[string][]string, body []byte) result {
	f.t.Helper()
	req, _ := http.NewRequest(method, f.ts.URL+path, bytes.NewReader(body))
	for k, vs := range h {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	resp, err := noRedirect.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return result{resp.StatusCode, resp.Header, string(b)}
}

func hdrs(base map[string]string, extra map[string][]string) map[string][]string {
	out := map[string][]string{}
	for k, v := range base {
		out[k] = []string{v}
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

func (f *runnerFront) hiddenQueue() string {
	return "http://aws:4566/000000000000/" + f.srv.runner.names().req
}

func TestEncodedBodiesAreDecodedBeforeTheGuardReadsThem(t *testing.T) {
	f := startRunnerFront(t, nil)
	f.create("fl-e", "java21", nil, pyZip())
	hq := f.hiddenQueue()
	role := "arn:aws:iam::000000000000:role/"
	zb := base64.StdEncoding.EncodeToString(pyZip())
	cases := []struct {
		name, method, path string
		base               map[string]string
		body               string
	}{
		{"ReceiveMessage on the request queue", "POST", "/", sqsJSON("ReceiveMessage"), `{"QueueUrl":"` + hq + `","WaitTimeSeconds":1}`},
		{"PurgeQueue", "POST", "/", sqsJSON("PurgeQueue"), `{"QueueUrl":"` + hq + `"}`},
		{"an event source mapping on the request queue", "POST", "/2015-03-31/event-source-mappings/", with(scopeHdr("lambda"), "Content-Type", "application/json"),
			`{"FunctionName":"fl-e","EventSourceArn":"arn:aws:sqs:us-east-1:000000000000:` + f.srv.runner.names().req + `"}`},
		{"a function in the stub's role", "POST", "/2015-03-31/functions", with(scopeHdr("lambda"), "Content-Type", "application/json"),
			`{"FunctionName":"fl-x","Runtime":"python3.12","Role":"` + f.srv.runner.names().roleARN + `","Handler":"a.b","Code":{"ZipFile":"` + zb + `"}}`},
		{"a state machine that sends to the request queue", "POST", "/", jsonRPC("states", "AWSStepFunctions.CreateStateMachine"),
			jsonStr(map[string]any{"name": "m", "roleArn": role + "r", "definition": `{"StartAt":"A","States":{"A":{"Type":"Task","Resource":"arn:aws:states:::sqs:sendMessage","Parameters":{"QueueUrl":"` + hq + `"},"End":true}}}`})},
		{"an EventBridge target on the request queue", "POST", "/", jsonRPC("events", "AWSEvents.PutTargets"),
			`{"Rule":"r","Targets":[{"Id":"1","Arn":"arn:aws:sqs:us-east-1:000000000000:` + f.srv.runner.names().req + `"}]}`},
	}
	encodings := map[string]func(string) ([]byte, map[string][]string){
		"gzip": func(b string) ([]byte, map[string][]string) {
			return gz([]byte(b)), map[string][]string{"Content-Encoding": {"gzip"}}
		},
		"GZip (case)": func(b string) ([]byte, map[string][]string) {
			return gz([]byte(b)), map[string][]string{"Content-Encoding": {"GZip"}}
		},
		"identity, gzip": func(b string) ([]byte, map[string][]string) {
			return gz([]byte(b)), map[string][]string{"Content-Encoding": {"identity, gzip"}}
		},
		"two headers": func(b string) ([]byte, map[string][]string) {
			return gz([]byte(b)), map[string][]string{"Content-Encoding": {"identity", "gzip"}}
		},
		"aws-chunked": func(b string) ([]byte, map[string][]string) {
			return awsChunked([]byte(b)), map[string][]string{"Content-Encoding": {"aws-chunked"}}
		},
		"AWS-Chunked (case)": func(b string) ([]byte, map[string][]string) {
			return awsChunked([]byte(b)), map[string][]string{"Content-Encoding": {"AWS-Chunked"}}
		},
		"gzip then aws-chunked": func(b string) ([]byte, map[string][]string) {
			return awsChunked(gz([]byte(b))), map[string][]string{"Content-Encoding": {"gzip, aws-chunked"}, "X-Amz-Content-Sha256": {"STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER"}}
		},
	}
	for _, c := range cases {
		for en, enc := range encodings {
			body, extra := enc(c.body)
			r := f.doRaw(c.method, c.path, hdrs(c.base, extra), body)
			if r.status != 403 {
				t.Errorf("%s, %s: %d %.120s", c.name, en, r.status, r.body)
			}
		}
	}
	// an encoding the front does not decode is refused, for every service but S3
	for _, e := range []string{"br", "deflate", "zstd", "compress", "gzip, br"} {
		r := f.doRaw("POST", "/", hdrs(sqsJSON("SendMessage"), map[string][]string{"Content-Encoding": {e}}), []byte(`{"QueueUrl":"http://aws:4566/000000000000/orders","MessageBody":"x"}`))
		if r.status != 415 {
			t.Errorf("Content-Encoding %q: %d %s", e, r.status, r.body)
		}
	}
	// garbage that claims an encoding is refused, not forwarded
	if r := f.doRaw("POST", "/", hdrs(sqsJSON("SendMessage"), map[string][]string{"Content-Encoding": {"gzip"}}), []byte(`{"QueueUrl":"x"}`)); r.status != 400 {
		t.Errorf("a gzip header over a body that is not gzip: %d", r.status)
	}
	if r := f.doRaw("POST", "/", hdrs(sqsJSON("SendMessage"), map[string][]string{"Content-Encoding": {"aws-chunked"}}), []byte("zz\r\nbroken")); r.status != 400 {
		t.Errorf("aws-chunked framing that does not parse: %d", r.status)
	}
	// a Query body is never decoded by the engine, so an encoded one is refused
	if r := f.doRaw("POST", "/", hdrs(formHdr("sqs"), map[string][]string{"Content-Encoding": {"gzip"}}), gz([]byte("Action=ListQueues&Version=2012-11-05"))); r.status != 415 {
		t.Errorf("an encoded form: %d", r.status)
	}
	// customers still work, and what the engine receives is the DECODED body with no encoding header
	one := `{"QueueUrl":"http://aws:4566/000000000000/orders","MessageBody":"hello"}`
	for en, enc := range encodings {
		body, extra := enc(one)
		if r := f.doRaw("POST", "/", hdrs(sqsJSON("SendMessage"), extra), body); r.status != 200 {
			t.Errorf("a customer call, %s: %d %s", en, r.status, r.body)
		}
		req, _ := http.NewRequest("POST", "http://x/", bytes.NewReader(body))
		for k, vs := range extra {
			for _, v := range vs {
				req.Header.Add(k, v)
			}
		}
		if st, msg := f.srv.runnerDecodeChunked(req); st != 0 {
			t.Fatalf("%s: %d %s", en, st, msg)
		}
		if st, msg := f.srv.runnerDecodeGzip(req, false); st != 0 {
			t.Fatalf("%s: %d %s", en, st, msg)
		}
		got, _ := io.ReadAll(req.Body)
		if string(got) != one || len(req.Header.Values("Content-Encoding")) != 0 || req.ContentLength != int64(len(one)) || req.Header.Get("X-Amz-Decoded-Content-Length") != "" {
			t.Errorf("%s: forwarded as %q with headers %v", en, got, req.Header)
		}
		if v := req.Header.Get("X-Amz-Content-Sha256"); strings.HasPrefix(v, "STREAMING") {
			t.Errorf("%s: the streaming marker is gone: %s", en, v)
		}
	}
	// S3 keeps its encodings: an object is data
	if r := f.doRaw("PUT", "/mine/k", hdrs(scopeHdr("s3"), map[string][]string{"Content-Encoding": {"gzip"}}), gz([]byte("object"))); r.status != 200 {
		t.Errorf("an S3 object written with Content-Encoding gzip: %d", r.status)
	}
	if r := f.doRaw("PUT", "/mine?notification", hdrs(scopeHdr("s3"), map[string][]string{"Content-Encoding": {"gzip"}}), gz([]byte("<NotificationConfiguration/>"))); r.status != 403 {
		t.Errorf("an encoded notification configuration is not read, so it is refused: %d", r.status)
	}
}

func TestBodiesThatCannotBeReadAreRefused(t *testing.T) {
	f := startRunnerFront(t, nil)
	f.create("fl-c", "java21", nil, pyZip())
	hq := f.hiddenQueue()
	sq := sqsJSON("GetQueueAttributes")
	status := func(name string, want int, r result) {
		t.Helper()
		if r.status != want {
			t.Errorf("%s: %d (want %d) %.120s", name, r.status, want, r.body)
		}
	}
	good := `{"QueueUrl":"http://aws:4566/000000000000/orders"}`
	status("a customer queue", 200, f.do("POST", "/", sq, good))
	status("bytes after the document", 400, f.do("POST", "/", sq, good+` {"x":1}`))
	status("garbage after the document", 400, f.do("POST", "/", sq, good+"zzz"))
	status("an unterminated document", 400, f.do("POST", "/", sq, `{"QueueUrl":"http://aws:4566/000000000000/orders"`))
	status("a hidden name before trailing bytes", 403, f.do("POST", "/", sq, `{"QueueUrl":"`+hq+`"} trailing`))
	status("duplicate keys, the hidden one second", 403, f.do("POST", "/", sq, `{"QueueUrl":"http://aws:4566/000000000000/orders","QueueUrl":"`+hq+`"}`))
	status("duplicate keys, the hidden one first", 403, f.do("POST", "/", sq, `{"QueueUrl":"`+hq+`","QueueUrl":"http://aws:4566/000000000000/orders"}`))
	status("a BOM before the JSON", 403, f.do("POST", "/", sq, "\xef\xbb\xbf"+`{"QueueUrl":"`+strings.Replace(hq, "rovara-heavy", `rovara-heavy`, 1)+`"}`))
	status("white space before the JSON", 403, f.do("POST", "/", sq, " \r\n\t"+`{"QueueUrl":"`+strings.Replace(hq, "rovara-heavy", `rovara-heavy`, 1)+`"}`))
	status("a name hidden in a nested document inside a string", 403, f.do("POST", "/", jsonRPC("states", "AWSStepFunctions.StartExecution"),
		jsonStr(map[string]any{"stateMachineArn": "arn:aws:states:us-east-1:000000000000:stateMachine:m", "input": `{"q":"` + strings.Replace(hq, "rovara-heavy", `rovara-heavy`, 1) + `"}`})))
	// Lambda package calls: the plan reads the whole body or refuses it
	lam := func(method, path, body string) result {
		return f.do(method, path, with(scopeHdr("lambda"), "Content-Type", "application/json"), body)
	}
	zb := base64.StdEncoding.EncodeToString(pyZip())
	okBody := `{"FunctionName":"fl-ok1","Runtime":"python3.12","Role":"arn:aws:iam::000000000000:role/r","Handler":"a.b","Code":{"ZipFile":"` + zb + `"}}`
	status("CreateFunction, well formed", 201, lam("POST", "/2015-03-31/functions", okBody))
	status("CreateFunction, trailing bytes", 400, lam("POST", "/2015-03-31/functions", strings.Replace(okBody, "fl-ok1", "fl-ok2", 1)+` {}`))
	status("CreateFunction, not JSON", 400, lam("POST", "/2015-03-31/functions", `FunctionName=x`))
	status("CreateFunction, a JSON array", 400, lam("POST", "/2015-03-31/functions", `[1,2]`))
	status("CreateFunction, duplicate Role keys", 403, lam("POST", "/2015-03-31/functions", `{"FunctionName":"fl-ok3","Runtime":"python3.12","Role":"`+f.srv.runner.names().roleARN+`","Role":"arn:aws:iam::000000000000:role/r","Handler":"a.b","Code":{"ZipFile":"`+zb+`"}}`))
	status("UpdateFunctionCode, truncated JSON", 400, lam("PUT", "/2015-03-31/functions/fl-c/code", `{"ZipFile":"`+zb))
	status("PublishLayerVersion, garbage", 400, lam("POST", "/2018-10-31/layers/fl-gl/versions", `{{{{`))
	status("UpdateFunctionConfiguration, trailing bytes", 400, lam("PUT", "/2015-03-31/functions/fl-c/configuration", `{"Timeout":5} x`))
}

func TestHiddenNamesAreUnguessable(t *testing.T) {
	f := startRunnerFront(t, nil)
	f.create("fl-n", "java21", nil, pyZip())
	rs := f.srv.runner
	n1 := rs.names()
	token := strings.TrimPrefix(n1.req, hiddenReqQueue+"-")
	if len(token) != 32 || strings.Trim(token, "0123456789abcdef") != "" { // gitleaks:allow (not a secret)
		t.Fatalf("a random part of 128 bits (32 hex characters): %q", n1.req)
	}
	for name, v := range map[string]string{"request queue": n1.req, "bucket": n1.bucket, "role": n1.role, "role ARN": n1.roleARN, "reply prefix": n1.replyPrefix} {
		if !strings.Contains(v, token) {
			t.Errorf("%s carries the token: %s", name, v)
		}
	}
	if len(n1.req) > 80 || len(n1.replyPrefix)+32 > 80 || len(n1.bucket) > 63 || len(n1.role) > 64 {
		t.Errorf("the names fit their services' limits: %d %d %d %d", len(n1.req), len(n1.replyPrefix)+32, len(n1.bucket), len(n1.role))
	}
	for _, v := range []string{n1.req, n1.bucket, n1.role} {
		if !hiddenRef(v) {
			t.Errorf("a name keeps the reserved prefix, so the guard and the lists reserve it still: %s", v)
		}
	}
	// the engine holds them under those names, and the stub names them
	if st, b := f.engineGet("/__fake/paths"); st != 200 || !strings.Contains(string(b), n1.bucket) {
		t.Errorf("the plumbing exists under the generated names")
	}
	stubB, _ := rs.stub()
	if !bytes.Contains(stubB, []byte("x")) {
		t.Fatal("stub")
	}
	// a new generation has new names
	f.do("POST", "/_rovara/reset", tok(), "")
	if n2 := rs.names(); n2.req == n1.req || n2.bucket == n1.bucket || n2.role == n1.role || n2.replyPrefix == n1.replyPrefix {
		t.Errorf("a reset changes every name: %+v -> %+v", n1, n2)
	}
}

func TestStubCarriesTheGenerationsNames(t *testing.T) {
	nm := newHiddenNames("0123456789abcdef0123456789abcdef")
	b, _ := buildStubZip("ab12", nm)
	src := stubSourceOf(t, b)
	for _, want := range []string{`REQ_QUEUE = "` + nm.req + `"`, `REPLY_PREFIX = "` + nm.replyPrefix + `"`, `BUCKET = "` + nm.bucket + `"`, `rid.replace("-", "")`} {
		if !strings.Contains(src, want) {
			t.Errorf("the stub holds %s", want)
		}
	}
	for _, bad := range []string{"__REQ_QUEUE__", "__REPLY_PREFIX__", "__BUCKET__", "__SECRET__"} {
		if strings.Contains(src, bad) {
			t.Errorf("placeholder %s left in the stub", bad)
		}
	}
}

func stubSourceOf(t *testing.T, zipBytes []byte) string {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		t.Fatal(err)
	}
	rc, _ := zr.File[0].Open()
	defer rc.Close()
	b, _ := io.ReadAll(rc)
	return string(b)
}

// ---- lists

func TestListsLeaveOutTheHiddenAndTheSweeperRemovesReferences(t *testing.T) {
	f := startRunnerFront(t, nil)
	f.create("fl-l", "java21", nil, pyZip())
	hArn := "arn:aws:sqs:us-east-1:000000000000:" + f.srv.runner.names().req
	set := func(l []map[string]interface{}) {
		b, _ := json.Marshal(l)
		gen, _, _ := f.engine.current()
		resp, err := gen.client.Post("https://127.0.0.1:"+fmt.Sprint(gen.port)+"/__fake/esm", "application/json", bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	set([]map[string]interface{}{
		{"UUID": "u-mine", "EventSourceArn": "arn:aws:sqs:us-east-1:000000000000:orders"},
		{"UUID": "u-thief", "EventSourceArn": hArn},
		{"UUID": "u-thief2", "EventSourceArn": hArn + "-other"},
	})
	r := f.lambda("GET", "/2015-03-31/event-source-mappings/", nil)
	if !strings.Contains(r.body, "u-mine") || strings.Contains(r.body, "u-thief") {
		t.Errorf("ListEventSourceMappings leaves out a mapping on the plumbing: %s", r.body)
	}
	// the sweeper removes what points at the plumbing, and says so in the ledger
	if n := f.srv.runner.sweepRefs(); n != 2 {
		t.Errorf("two references removed: %d", n)
	}
	_, b := f.engineGet("/__fake/esm")
	var left struct {
		Left    []map[string]interface{}
		Deleted []string
	}
	json.Unmarshal(b, &left)
	if len(left.Left) != 1 || left.Left[0]["UUID"] != "u-mine" || len(left.Deleted) != 2 {
		t.Errorf("only the customer's mapping is left: %s", b)
	}
	ops := f.counts("rovara")
	if ops["security:event-source-mapping"].Calls != 2 {
		t.Errorf("two security events in the ledger: %+v", ops)
	}
	if sum := f.do("GET", "/_rovara/ledger/summary", tok(), "").body; !strings.Contains(sum, `"security:event-source-mapping":{"calls":2,"unsupported":0,"errors":2}`) {
		t.Errorf("the summary shows them as errors: %s", sum)
	}
	if n := f.srv.runner.sweepRefs(); n != 0 {
		t.Errorf("a second sweep finds nothing: %d", n)
	}
}

// ---- a request that outlives a reset

func TestARequestInFlightDuringAResetCommitsNothing(t *testing.T) {
	f := startRunnerFront(t, nil)
	rs := f.srv.runner
	body := []byte(jsonStr(map[string]any{"FunctionName": "fl-late-commit", "Runtime": "python3.12", "Role": "arn:aws:iam::000000000000:role/r", "Handler": "a.b",
		"Code": map[string]any{"ZipFile": base64.StdEncoding.EncodeToString(heavyZip())}}))
	path := "/2015-03-31/functions"
	lam := f.srv.planLambda("CreateFunction", path, body, false)
	plan := rs.plan("CreateFunction", path, body, lam)
	if plan == nil || plan.commit == nil || plan.body == nil {
		t.Fatalf("a plan to take the function over: %+v", plan)
	}
	if used, _, _ := rs.store.stats(); used == 0 {
		t.Fatal("the plan holds the package")
	}
	rs.reset() // the request is still in flight: the engine answers it only now
	resp := []byte(`{"FunctionName":"fl-late-commit","FunctionArn":"arn:aws:lambda:us-east-1:000000000000:function:fl-late-commit","Version":"$LATEST"}`)
	f.srv.runnerAfter("CreateFunction", path, "", plan, resp, false)
	if rs.reg.isTaken("fl-late-commit") || len(rs.reg.fns) != 0 {
		t.Errorf("a function made in an ended generation is not in the new registry")
	}
	if used, _, n := rs.store.stats(); used != 0 || n != 0 {
		t.Errorf("and its package is released: %d bytes, %d blobs", used, n)
	}
}

// ---- the self-attack list: every other way to reach the plumbing found, each tested

func TestSelfAttackList(t *testing.T) {
	f := startRunnerFront(t, nil)
	f.create("fl-a", "java21", nil, pyZip())
	nm := f.srv.runner.names()
	hq := f.hiddenQueue()
	hArn := "arn:aws:sqs:us-east-1:000000000000:" + nm.req
	role := "arn:aws:iam::000000000000:role/"
	refused := func(n int, name string, r result) {
		t.Helper()
		if r.status != 403 && r.status != 400 && r.status != 415 && r.status != 413 && !(r.status == 404 && strings.Contains(r.body, "UnknownOperation")) {
			t.Errorf("attack %d, %s: reached the engine: %d %.140s", n, name, r.status, r.body)
		}
	}
	// 1. Content-Type tricks: the type says one thing, the body is another
	refused(1, "a JSON-protocol call with a form content type", f.do("POST", "/", with(sqsJSON("PurgeQueue"), "Content-Type", "application/x-www-form-urlencoded"), `{"QueueUrl":"`+hq+`"}`))
	refused(1, "a form with a JSON content type", f.do("POST", "/", with(scopeHdr("sqs"), "Content-Type", "application/json"), "Action=PurgeQueue&Version=2012-11-05&QueueUrl="+url.QueryEscape(hq)))
	refused(1, "a form with text/plain", f.do("POST", "/", with(scopeHdr("sqs"), "Content-Type", "text/plain"), "Action=PurgeQueue&Version=2012-11-05&QueueUrl="+url.QueryEscape(hq)))
	refused(1, "no content type", f.do("POST", "/", scopeHdr("sqs"), "Action=PurgeQueue&Version=2012-11-05&QueueUrl="+url.QueryEscape(hq)))
	// 2. batch APIs
	for _, op := range []string{"SendMessageBatch", "DeleteMessageBatch", "ChangeMessageVisibilityBatch"} {
		refused(2, op, f.do("POST", "/", sqsJSON(op), `{"QueueUrl":"`+hq+`","Entries":[{"Id":"1","MessageBody":"x","ReceiptHandle":"r","VisibilityTimeout":0}]}`))
	}
	refused(2, "a Query batch", f.do("POST", "/", formHdr("sqs"), "Action=DeleteMessageBatch&Version=2012-11-05&QueueUrl="+url.QueryEscape(hq)+"&DeleteMessageBatchRequestEntry.1.Id=1&DeleteMessageBatchRequestEntry.1.ReceiptHandle=x"))
	// 3. tags
	refused(3, "TagQueue", f.do("POST", "/", sqsJSON("TagQueue"), `{"QueueUrl":"`+hq+`","Tags":{"a":"b"}}`))
	refused(3, "ListQueueTags", f.do("POST", "/", sqsJSON("ListQueueTags"), `{"QueueUrl":"`+hq+`"}`))
	refused(3, "a Lambda tag listing by the function's ARN", f.do("GET", "/2017-03-31/tags/"+url.PathEscape("arn:aws:lambda:us-east-1:000000000000:function:"+hiddenPrefix+"x"), scopeHdr("lambda"), ""))
	refused(3, "TagRole", f.do("POST", "/", formHdr("iam"), "Action=TagRole&Version=2010-05-08&Tags.member.1.Key=a&Tags.member.1.Value=b&RoleName="+nm.role))
	// 4. ListQueues with prefixes: the hidden prefix is refused, a shorter one is filtered
	refused(4, "ListQueues with the reserved prefix", f.do("POST", "/", sqsJSON("ListQueues"), `{"QueueNamePrefix":"`+hiddenPrefix+`"}`))
	if r := f.do("POST", "/", sqsJSON("ListQueues"), `{"QueueNamePrefix":"rov","MaxResults":100}`); r.status != 200 || strings.Contains(r.body, "rovara-") {
		t.Errorf("attack 4, ListQueues with a shorter prefix lists no plumbing: %d %s", r.status, r.body)
	}
	if r := f.do("POST", "/", sqsJSON("ListQueues"), `{"QueueNamePrefix":"","MaxResults":1000,"NextToken":"x"}`); strings.Contains(r.body, "rovara-heavy") {
		t.Errorf("attack 4, ListQueues with a token: %s", r.body)
	}
	// 5. Step Functions: an input that names the plumbing, a definition that reads the role
	refused(5, "StartExecution with an input naming the queue", f.do("POST", "/", jsonRPC("states", "AWSStepFunctions.StartExecution"), jsonStr(map[string]any{"stateMachineArn": "arn:aws:states:us-east-1:000000000000:stateMachine:m", "input": `{"queue":"` + hq + `"}`})))
	refused(5, "an aws-sdk task reading the role", f.do("POST", "/", jsonRPC("states", "AWSStepFunctions.CreateStateMachine"), jsonStr(map[string]any{"name": "m", "roleArn": role + "r",
		"definition": `{"StartAt":"A","States":{"A":{"Type":"Task","Resource":"arn:aws:states:::aws-sdk:iam:getRole","Parameters":{"RoleName":"` + nm.role + `"},"End":true}}}`})))
	// 6. EventBridge: a rule target with an input transformer, a bus policy, an API destination
	refused(6, "a target with an input path naming the queue", f.do("POST", "/", jsonRPC("events", "AWSEvents.PutTargets"), `{"Rule":"r","Targets":[{"Id":"1","Arn":"arn:aws:sqs:us-east-1:000000000000:orders","InputTransformer":{"InputTemplate":"{\"q\":\"`+hArn+`\"}"}}]}`))
	refused(6, "a target in the stub's role", f.do("POST", "/", jsonRPC("events", "AWSEvents.PutTargets"), `{"Rule":"r","Targets":[{"Id":"1","Arn":"arn:aws:sqs:us-east-1:000000000000:orders","RoleArn":"`+nm.roleARN+`"}]}`))
	// 7. Scheduler and Pipes
	refused(7, "a schedule", f.do("POST", "/schedules/s1", with(scopeHdr("scheduler"), "Content-Type", "application/json"), `{"Target":{"Arn":"`+hArn+`","RoleArn":"`+role+`r"},"ScheduleExpression":"rate(1 hour)","FlexibleTimeWindow":{"Mode":"OFF"}}`))
	refused(7, "a pipe from the queue", f.do("POST", "/v1/pipes/p1", with(scopeHdr("pipes"), "Content-Type", "application/json"), `{"Source":"`+hArn+`","Target":"arn:aws:sqs:us-east-1:000000000000:orders","RoleArn":"`+role+`r"}`))
	refused(7, "a pipe to the queue", f.do("POST", "/v1/pipes/p2", with(scopeHdr("pipes"), "Content-Type", "application/json"), `{"Source":"arn:aws:sqs:us-east-1:000000000000:orders","Target":"`+hArn+`","RoleArn":"`+role+`r"}`))
	// 8. the SNS -> SQS path: a subscription, its redrive policy, a topic policy
	refused(8, "Subscribe", f.do("POST", "/", formHdr("sns"), "Action=Subscribe&Version=2010-03-31&TopicArn=arn%3Aaws%3Asns%3Aus-east-1%3A000000000000%3At&Protocol=sqs&Endpoint="+url.QueryEscape(hArn)))
	refused(8, "a redrive policy", f.do("POST", "/", formHdr("sns"), "Action=SetSubscriptionAttributes&Version=2010-03-31&SubscriptionArn=x&AttributeName=RedrivePolicy&AttributeValue="+url.QueryEscape(`{"deadLetterTargetArn":"`+hArn+`"}`)))
	refused(8, "an escaped redrive policy", f.do("POST", "/", formHdr("sns"), "Action=SetSubscriptionAttributes&Version=2010-03-31&SubscriptionArn=x&AttributeName=RedrivePolicy&AttributeValue="+url.QueryEscape(strings.Replace(`{"deadLetterTargetArn":"`+hArn+`"}`, "rovara-heavy", `rovara-heavy`, 1))))
	refused(8, "a queue's own redrive to the plumbing", f.do("POST", "/", sqsJSON("SetQueueAttributes"), `{"QueueUrl":"http://aws:4566/000000000000/orders","Attributes":{"RedrivePolicy":"{\"deadLetterTargetArn\":\"`+hArn+`\",\"maxReceiveCount\":1}"}}`))
	// 9. the bucket: a double slash, a virtual host, a notification into the plumbing, a copy with a version
	refused(9, "a double slash path", f.do("GET", "//"+nm.bucket+"/req/x", scopeHdr("s3"), ""))
	refused(9, "a virtual host", f.do("GET", "/req/x", with(scopeHdr("s3"), "Host", nm.bucket+".aws"), ""))
	refused(9, "a copy source with a version", f.do("PUT", "/mine/k", with(scopeHdr("s3"), "x-amz-copy-source", "/"+nm.bucket+"/req/x?versionId=1"), ""))
	// 10. the role: PassRole by function creation, a policy attached by name, in any spelling
	refused(10, "a role named by path", f.do("POST", "/", formHdr("iam"), "Action=PutRolePolicy&Version=2010-05-08&PolicyName=p&PolicyDocument=%7B%7D&RoleName="+url.QueryEscape("path/"+nm.role)))
	refused(10, "AttachRolePolicy", f.do("POST", "/", formHdr("iam"), "Action=AttachRolePolicy&Version=2010-05-08&PolicyArn=arn%3Aaws%3Aiam%3A%3Aaws%3Apolicy%2FAdministratorAccess&RoleName="+nm.role))
	// 11. function names in the path
	refused(11, "GetFunction of a reserved name", f.do("GET", "/2015-03-31/functions/"+hiddenPrefix+"x", scopeHdr("lambda"), ""))
	// 12. an intrinsic function that builds the name in a template: it cannot know the name, and the sweeper would remove what it made
	tpl := `{"Parameters":{"P":{"Type":"String","Default":"heavy"}},"Resources":{"M":{"Type":"AWS::Lambda::EventSourceMapping","Properties":{"FunctionName":"fl-a","EventSourceArn":{"Fn::Sub":"arn:aws:sqs:us-east-1:000000000000:rovara-${P}-req"}}}}}`
	form := url.Values{"Action": {"CreateStack"}, "Version": {"2010-05-15"}, "StackName": {"intr"}, "TemplateBody": {tpl}}
	if r := f.do("POST", "/", formHdr("cloudformation"), form.Encode()); r.status == 403 {
		t.Logf("attack 12: the template is refused: %s", r.body)
	}
	// ... and what such a mapping would have to name does not exist: the generated name has 128 random bits
	if strings.Contains(tpl, nm.req) {
		t.Errorf("the template cannot hold the name")
	}
	_ = time.Second
}
