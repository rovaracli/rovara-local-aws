package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"
)

// Regression tests for the findings of the review of the heavy-function detector and the CloudFormation recorder: each probe is a
// real HTTP request to the front.

func (f *lamFront) clear() { f.do("DELETE", "/_rovara/ledger", tok(), "") }

func (f *lamFront) allCounts() map[string]map[string]opCounts {
	var sum map[string]struct{ Operations map[string]opCounts }
	json.Unmarshal([]byte(f.do("GET", "/_rovara/ledger/summary", tok(), "").body), &sum)
	out := map[string]map[string]opCounts{}
	for k, v := range sum {
		out[k] = v.Operations
	}
	return out
}

func (f *lamFront) stack(name, template string) {
	form := url.Values{"Action": {"CreateStack"}, "Version": {"2010-05-15"}, "StackName": {name}, "TemplateBody": {template}}
	f.do("POST", "/", with(scopeHdr("cloudformation"), "Content-Type", "application/x-www-form-urlencoded"), form.Encode())
}

func (f *lamFront) fakePaths() string { return f.do("GET", "/__fake/paths", nil, "").body }

// HIGH 1 and 2: the Type of every resource is read from the document, whatever the text does to hide it
func TestCloudFormationTypesAreReadFromTheDocument(t *testing.T) {
	f := startLambdaFront(t, "cloudformation", "s3")
	flood := strings.Repeat(`"Type":"AWS::S3::Bucket",`, 2000)
	yamlFlood := "Metadata:\n" + strings.Repeat("  - Type: AWS::S3::Bucket\n", 2000)
	for _, c := range []struct {
		name, tpl string
		service   string // the service that must be recorded out of plan ("" for the unchecked marker)
		op        string
	}{
		{"plain json", `{"Resources":{"Q":{"Type":"AWS::SQS::Queue"}}}`, "sqs", "cloudformation:AWS::SQS::Queue"},
		{"unicode escapes in the value", `{"Resources":{"Q":{"Type":"AWS\u003a\u003aSQS\u003a\u003aQueue"}}}`, "sqs", "cloudformation:AWS::SQS::Queue"},
		{"unicode escapes in the key", `{"Resources":{"Q":{"T\u0079pe":"AWS::SQS::Queue"}}}`, "sqs", "cloudformation:AWS::SQS::Queue"},
		{"yaml folded scalar", "Resources:\n  Q:\n    Type: >-\n      AWS::SQS::Queue\n", "sqs", "cloudformation:AWS::SQS::Queue"},
		{"yaml literal scalar", "Resources:\n  Q:\n    Type: |\n      AWS::SQS::Queue\n", "sqs", "cloudformation:AWS::SQS::Queue"},
		{"yaml flow mapping", "Resources:\n  Q: {Type: AWS::SQS::Queue}\n", "sqs", "cloudformation:AWS::SQS::Queue"},
		{"yaml quoted", "Resources:\n  Q:\n    \"Type\":   'AWS::SQS::Queue'\n", "sqs", "cloudformation:AWS::SQS::Queue"},
		{"2000 copies of another type first (json)", `{"Metadata":{` + strings.TrimSuffix(flood, ",") + `},"Resources":{"Q":{"Type":"AWS::SQS::Queue"}}}`, "sqs", "cloudformation:AWS::SQS::Queue"},
		{"2000 copies of another type first (yaml)", yamlFlood + "Resources:\n  Q:\n    Type: AWS::SQS::Queue\n", "sqs", "cloudformation:AWS::SQS::Queue"},
		{"not a document", "this is [ not { a template", "", "cloudformation:unparsed"},
		{"yaml anchors are outside the reader", "Resources:\n  Q: &q\n    Type: AWS::SNS::Topic\n", "", "cloudformation:unparsed"},
		{"a resource whose Type is not text", `{"Resources":{"Q":{"Type":{"Fn::If":["c","AWS::SQS::Queue","AWS::SNS::Topic"]}}}}`, "", "cloudformation:unparsed"},
		{"a macro inside a property", `{"Resources":{"Q":{"Type":"AWS::S3::Bucket","Properties":{"X":{"Fn::Transform":{"Name":"m"}}}}}}`, "", "cloudformation:transform"},
	} {
		f.clear()
		f.stack("probe", c.tpl)
		all := f.allCounts()
		if c.service != "" {
			if all[c.service][c.op].Calls != 1 {
				t.Errorf("%s: want %s %s once, got %v", c.name, c.service, c.op, all)
			}
		} else if all[cfnUncheckedService][c.op].Calls != 1 {
			t.Errorf("%s: want %s under %s, got %v", c.name, c.op, cfnUncheckedService, all)
		}
	}
}

// HIGH 3: what a planned service is told to call is recorded
func TestTargetsOfPlannedServicesAreRecorded(t *testing.T) {
	f := startLambdaFront(t, "sfn", "iam", "eventbridge", "scheduler", "pipes", "ssm", "s3")
	js := func(target, contentType string, body any) result {
		b, _ := json.Marshal(body)
		scope := map[string]string{"AWSStepFunctions": "states", "AWSEvents": "events", "AmazonSSM": "ssm"}[strings.Split(target, ".")[0]]
		return f.do("POST", "/", with(scopeHdr(scope), "X-Amz-Target", target, "Content-Type", contentType), string(b))
	}
	sfn := func(def any) result {
		var d string
		if s, ok := def.(string); ok {
			d = s
		} else {
			b, _ := json.Marshal(def)
			d = string(b)
		}
		return js("AWSStepFunctions.CreateStateMachine", "application/x-amz-json-1.0", map[string]any{"name": "m", "roleArn": "r", "definition": d})
	}
	op := func(service, o string) int64 { return f.allCounts()[service][o].Calls }
	task := func(res string) map[string]any {
		return map[string]any{"StartAt": "T", "States": map[string]any{"T": map[string]any{"Type": "Task", "Resource": res, "End": true}}}
	}
	// the probe of the review: a task that creates a queue
	f.clear()
	if r := sfn(task("arn:aws:states:::aws-sdk:sqs:createQueue")); r.status != 200 {
		t.Fatalf("the state machine is not blocked: %d %s", r.status, r.body)
	}
	if op("sqs", "stepfunctions:sqs:createQueue") != 1 {
		t.Errorf("aws-sdk sqs: %v", f.allCounts())
	}
	for _, c := range []struct{ res, service, op string }{
		{"arn:aws:states:::sqs:sendMessage", "sqs", "stepfunctions:sqs:sendMessage"},
		{"arn:aws:states:::sqs:sendMessage.waitForTaskToken", "sqs", "stepfunctions:sqs:sendMessage"},
		{"arn:aws:states:::sns:publish", "sns", "stepfunctions:sns:publish"},
		{"arn:aws:states:::dynamodb:putItem", "dynamodb", "stepfunctions:dynamodb:putItem"},
		{"arn:aws:states:::aws-sdk:secretsmanager:getSecretValue", "secrets-manager", "stepfunctions:secretsmanager:getSecretValue"},
		{"arn:aws:states:::aws-sdk:cloudwatchlogs:createLogGroup", "cloudwatch-logs", "stepfunctions:cloudwatchlogs:createLogGroup"},
		{"arn:aws:states:::events:putEvents", "eventbridge", ""}, // planned: nothing
		{"arn:aws:states:::lambda:invoke", "lambda", "stepfunctions:lambda:invoke"},
		{"arn:aws:lambda:us-east-1:000000000000:function:f", "lambda", "stepfunctions:lambda:invoke"},
		{"arn:aws:states:::aws-sdk:kms:createKey", "kms", "stepfunctions:kms:createKey"},
		{"arn:aws:states:::aws-sdk:frobnicate:doIt", targetsUncheckedService, "stepfunctions:frobnicate:doIt"},
	} {
		f.clear()
		sfn(task(c.res))
		if c.op == "" {
			if len(f.allCounts()[c.service]) != 0 {
				t.Errorf("%s: a planned service records nothing: %v", c.res, f.allCounts())
			}
			continue
		}
		if op(c.service, c.op) != 1 {
			t.Errorf("%s: want %s %s, got %v", c.res, c.service, c.op, f.allCounts())
		}
	}
	// nested states: Parallel branches, Map iterators and item readers, Choice defaults; the planned services and an http task say nothing
	f.clear()
	sfn(map[string]any{"StartAt": "P", "States": map[string]any{
		"P": map[string]any{"Type": "Parallel", "End": true, "Branches": []any{
			task("arn:aws:states:::sqs:sendMessage"),
			map[string]any{"StartAt": "M", "States": map[string]any{"M": map[string]any{"Type": "Map", "End": true,
				"ItemReader":    map[string]any{"Resource": "arn:aws:states:::s3:getObject"},
				"ItemProcessor": task("arn:aws:states:::sns:publish")}}}}}}})
	if op("sqs", "stepfunctions:sqs:sendMessage") != 1 || op("sns", "stepfunctions:sns:publish") != 1 || len(f.allCounts()["s3"]) != 0 {
		t.Errorf("nested states: %v", f.allCounts())
	}
	// not readable: a JSONata expression as a Resource, a definition that is not JSON, a repeated call is counted once per definition
	f.clear()
	sfn(task("{% $states.input.arn %}"))
	sfn("this is not json")
	if op(targetsUncheckedService, "stepfunctions:dynamic") != 1 || op(targetsUncheckedService, "stepfunctions:unreadable") != 1 {
		t.Errorf("unchecked: %v", f.allCounts())
	}
	f.clear()
	sfn(map[string]any{"StartAt": "A", "States": map[string]any{"A": map[string]any{"Type": "Task", "Resource": "arn:aws:states:::sqs:sendMessage", "Next": "B"},
		"B": map[string]any{"Type": "Task", "Resource": "arn:aws:states:::sqs:sendMessage", "End": true}}})
	if op("sqs", "stepfunctions:sqs:sendMessage") != 1 {
		t.Errorf("one count per distinct call of a definition: %v", f.allCounts())
	}
	// the update form
	f.clear()
	js("AWSStepFunctions.UpdateStateMachine", "application/x-amz-json-1.0", map[string]any{"stateMachineArn": "arn", "definition": string(mustJSON(task("arn:aws:states:::aws-sdk:ec2:runInstances")))})
	if op("ec2", "stepfunctions:ec2:runInstances") != 1 {
		t.Errorf("UpdateStateMachine: %v", f.allCounts())
	}
	// EventBridge targets
	f.clear()
	js("AWSEvents.PutTargets", "application/x-amz-json-1.1", map[string]any{"Rule": "r", "Targets": []any{
		map[string]any{"Id": "1", "Arn": "arn:aws:sqs:us-east-1:000000000000:q"},
		map[string]any{"Id": "2", "Arn": "arn:aws:lambda:us-east-1:000000000000:function:f"},
		map[string]any{"Id": "3", "Arn": "arn:aws:states:us-east-1:000000000000:stateMachine:m"}, // sfn is planned
		map[string]any{"Id": "4", "Arn": "arn:aws:events:us-east-1:000000000000:api-destination/d/x"}}})
	if op("eventbridge", "eventbridge:events:api-destination") != 1 {
		t.Errorf("an API destination is an outside delivery, recorded: %v", f.allCounts())
	}
	for _, planned := range []string{"sfn", "eventbridge"} {
		for o := range f.allCounts()[planned] {
			if strings.HasPrefix(o, "eventbridge:") && o != "eventbridge:events:api-destination" {
				t.Errorf("a planned service records no target: %s %s", planned, o)
			}
		}
	}
	if op("sqs", "eventbridge:sqs:target") != 1 {
		t.Errorf("PutTargets: %v", f.allCounts())
	}
	if op("lambda", "eventbridge:lambda:target") != 1 {
		t.Errorf("PutTargets lambda: %v", f.allCounts())
	}
	// Scheduler: the universal target and an ordinary ARN, and the dead-letter queue
	f.clear()
	sch := func(method, body string) result {
		return f.do(method, "/schedules/s1", with(scopeHdr("scheduler"), "Content-Type", "application/json"), body)
	}
	sch("POST", `{"ScheduleExpression":"rate(1 minute)","FlexibleTimeWindow":{"Mode":"OFF"},"Target":{"Arn":"arn:aws:scheduler:::aws-sdk:sqs:createQueue","RoleArn":"r","Input":"{}"}}`)
	sch("PUT", `{"Target":{"Arn":"arn:aws:sns:us-east-1:000000000000:t","RoleArn":"r"},"DeadLetterConfig":{"Arn":"arn:aws:sqs:us-east-1:000000000000:dlq"}}`)
	if op("sqs", "scheduler:sqs:createQueue") != 1 || op("sns", "scheduler:sns:target") != 1 || op("sqs", "scheduler:sqs:target") != 1 {
		t.Errorf("Scheduler: %v", f.allCounts())
	}
	// Pipes
	f.clear()
	f.do("POST", "/v1/pipes/p1", with(scopeHdr("pipes"), "Content-Type", "application/json"),
		`{"Source":"arn:aws:sqs:us-east-1:000000000000:q","Target":"arn:aws:lambda:us-east-1:000000000000:function:f","RoleArn":"r"}`)
	if op("sqs", "pipes:sqs:target") != 1 || op("lambda", "pipes:lambda:target") != 1 {
		t.Errorf("Pipes: %v", f.allCounts())
	}
	// SSM Automation documents, JSON and YAML
	f.clear()
	js("AmazonSSM.CreateDocument", "application/x-amz-json-1.1", map[string]any{"Name": "d", "DocumentType": "Automation", "Content": `{"schemaVersion":"0.3","mainSteps":[{"name":"a","action":"aws:executeAwsApi","inputs":{"Service":"sqs","Api":"CreateQueue","QueueName":"q"}}]}`})
	js("AmazonSSM.CreateDocument", "application/x-amz-json-1.1", map[string]any{"Name": "e", "DocumentType": "Automation", "Content": "schemaVersion: '0.3'\nmainSteps:\n  - name: a\n    action: aws:executeAwsApi\n    inputs:\n      Service: sns\n      Api: CreateTopic\n  - name: b\n    action: aws:invokeLambdaFunction\n    inputs:\n      FunctionName: f\n"})
	if op("sqs", "ssm:sqs:CreateQueue") != 1 || op("sns", "ssm:sns:CreateTopic") != 1 || op("lambda", "ssm:lambda:invokeLambdaFunction") != 1 {
		t.Errorf("SSM automation: %v", f.allCounts())
	}
	// the seed's rule targets do not pass the front and are recorded too
	f.clear()
	f.do("POST", "/_rovara/seed", tok(), `{"events":{"buses":["b"],"rules":[{"name":"r","bus":"b","pattern":{"source":["x"]},"targets":[{"Id":"1","Arn":"arn:aws:sqs:us-east-1:000000000000:q"}]}]}}`)
	if op("sqs", "eventbridge:sqs:target") != 1 {
		t.Errorf("seed rule targets: %v", f.allCounts())
	}
	// a state machine's execution output that carries a queue URL it made is rewritten to the base URL
	r := js("AWSStepFunctions.DescribeExecution", "application/x-amz-json-1.0", map[string]any{"executionArn": "e"})
	if strings.Contains(r.body, "amazonaws.com") || !strings.Contains(r.body, "http://aws:4566/000000000000/made-by-sfn") {
		t.Errorf("execution output: %s", r.body)
	}
	// a state machine in a template
	f.clear()
	f.stack("sm", `{"Resources":{"M":{"Type":"AWS::StepFunctions::StateMachine","Properties":{"RoleArn":"r","DefinitionString":"{\"StartAt\":\"T\",\"States\":{\"T\":{\"Type\":\"Task\",\"Resource\":\"arn:aws:states:::aws-sdk:sqs:createQueue\",\"End\":true}}}"}}}}`)
	// cloudformation is not planned in this front: the recorder is not reached, so nothing is counted
	if len(f.allCounts()["sqs"]) != 0 {
		t.Errorf("an unplanned CloudFormation is refused before any recording: %v", f.allCounts())
	}
	// without a plan nothing is recorded
	g := startFront(t, nil)
	g.do("POST", "/", with(scopeHdr("states"), "X-Amz-Target", "AWSStepFunctions.CreateStateMachine", "Content-Type", "application/x-amz-json-1.0"),
		string(mustJSON(map[string]any{"name": "m", "definition": string(mustJSON(task("arn:aws:states:::aws-sdk:sqs:createQueue")))})))
	if s := g.do("GET", "/_rovara/ledger/summary", tok(), "").body; strings.Contains(s, "stepfunctions:") {
		t.Errorf("legacy mode records nothing: %s", s)
	}
}

func TestStateMachineInATemplateIsRecorded(t *testing.T) {
	f := startLambdaFront(t, "cloudformation", "sfn")
	f.stack("sm", `{"Resources":{"M":{"Type":"AWS::StepFunctions::StateMachine","Properties":{"RoleArn":"r","DefinitionString":"{\"StartAt\":\"T\",\"States\":{\"T\":{\"Type\":\"Task\",\"Resource\":\"arn:aws:states:::aws-sdk:sqs:createQueue\",\"End\":true}}}"}}}}`)
	f.stack("sm2", "Resources:\n  M:\n    Type: AWS::StepFunctions::StateMachine\n    Properties:\n      RoleArn: r\n      Definition:\n        StartAt: T\n        States:\n          T:\n            Type: Task\n            Resource: arn:aws:states:::sns:publish\n            End: true\n")
	all := f.allCounts()
	if all["sqs"]["stepfunctions:sqs:createQueue"].Calls != 1 || all["sns"]["stepfunctions:sns:publish"].Calls != 1 {
		t.Errorf("state machines in templates: %v", all)
	}
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

// LOW 5: only S3 object paths are fetched, and with a time limit; no slot is held across a client read
func TestInspectionFetchesOnlyObjects(t *testing.T) {
	f := startLambdaFront(t, "cloudformation", "lambda", "s3")
	for _, u := range []string{
		"https://s3.amazonaws.com/_aws/execute-api/x/y.json",
		"https://s3.amazonaws.com/bkt/../_aws/x.json",
		"https://s3.amazonaws.com/bkt/%2e%2e/_aws/x.json",
		"https://s3.amazonaws.com/bkt/a%2F..%2Fb.json",
		"https://s3.amazonaws.com/bkt/./x.json",
		"https://s3.amazonaws.com/bkt//x.json",
		"https://s3.amazonaws.com/UPPER/x.json",
		"https://s3.amazonaws.com/onlybucket",
		"http://aws:4566/_aws/lambda-url/abc/x.json",
		"http://aws:4566/_rovara/ledger",
	} {
		f.clear()
		form := url.Values{"Action": {"CreateStack"}, "Version": {"2010-05-15"}, "StackName": {"p"}, "TemplateURL": {u}}
		f.do("POST", "/", with(scopeHdr("cloudformation"), "Content-Type", "application/x-www-form-urlencoded"), form.Encode())
		if f.allCounts()[cfnUncheckedService]["cloudformation:unreadable"].Calls != 1 {
			t.Errorf("%s: want unreadable, got %v", u, f.allCounts())
		}
	}
	// Lambda packages named by S3Bucket and S3Key
	for _, c := range [][2]string{{"_aws", "x"}, {"zipbkt", "../_aws/x"}, {"zipbkt", "a/./b"}, {"zipbkt", "a%2Fb"}} {
		f.lambda("POST", "/2015-03-31/functions", map[string]any{"FunctionName": "p" + c[1][:1], "Runtime": "python3.12", "Code": map[string]any{"S3Bucket": c[0], "S3Key": c[1]}})
	}
	paths := f.fakePaths()
	for _, bad := range []string{"/_aws/", "..", "%2e", "/./", "//x", "/_rovara/", "UPPER", "/onlybucket "} {
		for _, line := range strings.Split(paths, "\n") {
			if strings.HasPrefix(line, "GET ") && strings.Contains(line, bad) && !strings.Contains(line, "/__fake/paths") {
				t.Errorf("the engine was asked for %q (matching %q)", line, bad)
			}
		}
	}
	// a read that takes too long is given up (unchecked), not waited for
	old := engineFetchTimeout
	engineFetchTimeout = 300 * time.Millisecond
	defer func() { engineFetchTimeout = old }()
	f.clear()
	start := time.Now()
	form := url.Values{"Action": {"CreateStack"}, "Version": {"2010-05-15"}, "StackName": {"p"}, "TemplateURL": {"https://s3.amazonaws.com/slowbkt/s.json"}}
	f.do("POST", "/", with(scopeHdr("cloudformation"), "Content-Type", "application/x-www-form-urlencoded"), form.Encode())
	if time.Since(start) > 2*time.Second || f.allCounts()[cfnUncheckedService]["cloudformation:unreadable"].Calls != 1 {
		t.Errorf("a slow read: %v after %v", f.allCounts(), time.Since(start))
	}
}

func TestSlowClientDoesNotBlockAnotherRequest(t *testing.T) {
	f := startLambdaFront(t, "lambda")
	conn, err := net.Dial("tcp", strings.TrimPrefix(f.ts.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// a CreateFunction that promises 100 kB and sends 100 bytes, then stops
	fmt.Fprintf(conn, "POST /2015-03-31/functions HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 100000\r\nAuthorization: %s\r\n\r\n{\"FunctionName\":\"slow\",", scopeHdr("lambda")["Authorization"])
	time.Sleep(200 * time.Millisecond)
	done := make(chan result, 1)
	go func() {
		done <- f.create("quick", "java21", nil, testZip(zent{"a.txt", []byte("x")}))
	}()
	select {
	case r := <-done:
		if r.status != 200 || f.heavy()["quick"][0] != "runtime" {
			t.Errorf("the other request: %d %v", r.status, f.heavy())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("a slow client held up another request")
	}
}

// LOW 6 and MEDIUM 4: a zip that declares more entries than the judge reads is refused before any entry is built, and is unchecked
func TestHugeDirectoriesAndEntryCaps(t *testing.T) {
	// 70000 entries: the writer makes a zip64 directory
	var many []zent
	for i := 0; i < 70000; i++ {
		many = append(many, zent{fmt.Sprintf("f%d", i), nil})
	}
	z := testZip(many...)
	if big, found := zipDirectoryTooBig(z); !found || !big {
		t.Errorf("zip64 directory of 70000 entries: big=%v found=%v", big, found)
	}
	if v, ok := judgeZip(z); !ok || !v.Unsafe || v.Entries != 0 {
		t.Errorf("judged: %+v %v", v, ok)
	}
	// a plain zip is not too big
	if big, found := zipDirectoryTooBig(testZip(zent{"a", []byte("x")})); !found || big {
		t.Errorf("small zip: %v %v", big, found)
	}
	f := startLambdaFront(t, "lambda")
	files := func(n int) []zent {
		var out []zent
		for i := 0; i < n; i++ {
			out = append(out, zent{fmt.Sprintf("f%d.txt", i), []byte("x")})
		}
		return out
	}
	// 20000 small files and then an ELF file: not "not heavy"
	if r := f.create("many-then-so", "python3.12", nil, testZip(append(files(zipMaxEntries), zent{"lib/x.so", testELF(elfMachineAArch64)})...)); r.status != 200 {
		t.Fatal(r.body)
	}
	if g := f.heavy()["many-then-so"]; g[0] != "unchecked" {
		t.Errorf("20001 entries: %v", g)
	}
	// below the cap the ELF file at the end is seen
	f.create("few-then-so", "python3.12", nil, testZip(append(files(500), zent{"lib/x.so", testELF(elfMachineAArch64)})...))
	if g := f.heavy()["few-then-so"]; g[0] != "native-code" {
		t.Errorf("501 entries: %v", g)
	}
	// an unsafe zip that shows an ELF file before it goes bad is native-code, one that shows nothing is unchecked
	f.create("traversal-so", "python3.12", nil, testZip(zent{"../x.so", testELF(elfMachineAArch64)}))
	if g := f.heavy()["traversal-so"]; g[0] != "native-code" {
		t.Errorf("an ELF file in an unsafe zip: %v", g)
	}
	_ = base64.StdEncoding
}
