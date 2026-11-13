package main

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

// Regression tests for the second review: every probe is a real HTTP request, and an input the front cannot read with certainty is
// recorded as an unchecked marker, never skipped.

func sfnTask(res string) string {
	return string(mustJSON(map[string]any{"StartAt": "T", "States": map[string]any{"T": map[string]any{"Type": "Task", "Resource": res, "End": true}}}))
}

func (f *lamFront) createMachine(def string) {
	f.do("POST", "/", with(scopeHdr("states"), "X-Amz-Target", "AWSStepFunctions.CreateStateMachine", "Content-Type", "application/x-amz-json-1.0"),
		string(mustJSON(map[string]any{"name": "m", "roleArn": "r", "definition": def})))
}

// 2: Resource ARNs are read by their fields, as the engine reads them
func TestStepFunctionsResourceARNsAreReadByFields(t *testing.T) {
	f := startLambdaFront(t, "sfn", "iam")
	for _, c := range []struct{ res, service, op string }{
		{"arn:aws:states:::aws-sdk:sqs:createQueue", "sqs", "stepfunctions:sqs:createQueue"},
		{"arn:aws:states:us-east-1:000000000000:aws-sdk:sqs:createQueue", "sqs", "stepfunctions:sqs:createQueue"},
		{"arn:aws:states:us-east-1::aws-sdk:sqs:createQueue", "sqs", "stepfunctions:sqs:createQueue"},
		{"arn:aws:states::000000000000:aws-sdk:sqs:createQueue", "sqs", "stepfunctions:sqs:createQueue"},
		{"arn:zzz:states:::aws-sdk:sqs:createQueue", "sqs", "stepfunctions:sqs:createQueue"},
		{"arn:aws-cn:states:cn-north-1:1:sns:publish", "sns", "stepfunctions:sns:publish"},
		{"arn:aws:states:::aws-sdk:sqs:createQueue.sync:2", "sqs", "stepfunctions:sqs:createQueue"},
		{"arn:zzz:lambda:us-east-1:000000000000:function:f", "lambda", "stepfunctions:lambda:invoke"},
		{"arn:aws:states:::sqs:sendMessage.waitForTaskToken", "sqs", "stepfunctions:sqs:sendMessage"},
		// spellings the engine would not read: recorded unchecked, never skipped
		{"ARN:AWS:STATES:::aws-sdk:sqs:createQueue", targetsUncheckedService, "stepfunctions:resource"},
		{"arn:aws:States:::aws-sdk:sqs:createQueue", targetsUncheckedService, "stepfunctions:resource"},
		{"arn:aws:states:::AWS-SDK:sqs:createQueue", targetsUncheckedService, "stepfunctions:resource"},
		{"arn:aws:states:::AWS-SDK:sqs:createQueue", "sqs", "stepfunctions:sqs:createQueue"},
		{"arn:aws:states:::aws-sdk:sqs", targetsUncheckedService, "stepfunctions:resource"},
		{"arn:aws:states:::", targetsUncheckedService, "stepfunctions:resource"},
		{"arn:aws:states", targetsUncheckedService, "stepfunctions:resource"},
		{"arn:aws:states:::aws-sdk:nosuchservice:go", targetsUncheckedService, "stepfunctions:nosuchservice:go"},
	} {
		f.clear()
		f.createMachine(sfnTask(c.res))
		if f.allCounts()[c.service][c.op].Calls < 1 {
			t.Errorf("%s: want %s %s, got %v", c.res, c.service, c.op, f.allCounts())
		}
	}
	// nothing to record: an activity, an HTTP task, a plain string
	for _, res := range []string{"arn:aws:states:us-east-1:000000000000:activity:a", "arn:aws:states:::http:invoke", "not-an-arn", "arn:aws:states:::states:startExecution"} {
		f.clear()
		f.createMachine(sfnTask(res))
		for svc := range f.allCounts() {
			if svc != "sfn" {
				t.Errorf("%s: nothing but the planned machine: %v", res, f.allCounts())
			}
		}
	}
	// a Resource.$ and a Resource that is an object
	f.clear()
	f.createMachine(`{"StartAt":"T","States":{"T":{"Type":"Task","Resource.$":"$.arn","End":true}}}`)
	if f.allCounts()[targetsUncheckedService]["stepfunctions:dynamic"].Calls != 1 {
		t.Errorf("Resource.$: %v", f.allCounts())
	}
}

// 2 and minor: Scheduler universal targets in any spelling, the dead-letter queue inside Target, API destinations
func TestSchedulerAndEventBridgeTargetSpellings(t *testing.T) {
	f := startLambdaFront(t, "scheduler", "eventbridge")
	sch := func(body string) {
		f.do("POST", "/schedules/s1", with(scopeHdr("scheduler"), "Content-Type", "application/json"), body)
	}
	op := func(service, o string) int64 { return f.allCounts()[service][o].Calls }
	for _, arn := range []string{"arn:aws:scheduler:::aws-sdk:sqs:createQueue", "arn:aws:scheduler:us-east-1:000000000000:aws-sdk:sqs:createQueue",
		"ARN:AWS:SCHEDULER:::AWS-SDK:sqs:createQueue", "arn:zzz:scheduler:::Aws-Sdk:sqs:createQueue"} {
		f.clear()
		sch(`{"Target":{"Arn":"` + arn + `","RoleArn":"r"}}`)
		if op("sqs", "scheduler:sqs:createQueue") != 1 {
			t.Errorf("%s: %v", arn, f.allCounts())
		}
	}
	f.clear()
	sch(`{"Target":{"Arn":"arn:aws:scheduler:::aws-sdk","RoleArn":"r"}}`)
	sch(`{"Target":{"Arn":"arn:aws:scheduler:::something:else","RoleArn":"r"}}`)
	sch(`{"Target":{"Arn":"not an arn","RoleArn":"r"}}`)
	if op(targetsUncheckedService, "scheduler:arn") != 3 {
		t.Errorf("an unreadable universal target or a non-ARN: %v", f.allCounts())
	}
	f.clear()
	sch(`{"Target":{"Arn":"arn:aws:sns:us-east-1:000000000000:t","RoleArn":"r","DeadLetterConfig":{"Arn":"arn:aws:sqs:us-east-1:000000000000:dlq"}}}`)
	if op("sqs", "scheduler:sqs:target") != 1 || op("sns", "scheduler:sns:target") != 1 {
		t.Errorf("Target.DeadLetterConfig: %v", f.allCounts())
	}
	f.clear()
	sch(`{"Target":{"Arn":"arn:aws:events:us-east-1:000000000000:api-destination/d/x","RoleArn":"r"}}`)
	if op("eventbridge", "scheduler:events:api-destination") != 1 {
		t.Errorf("API destination target: %v", f.allCounts())
	}
}

// 3: definitions written with intrinsics, and DefinitionS3Location
func TestTemplateStateMachineDefinitions(t *testing.T) {
	f := startLambdaFront(t, "cloudformation", "sfn")
	machine := func(props string) string {
		return `{"Resources":{"M":{"Type":"AWS::StepFunctions::StateMachine","Properties":{"RoleArn":"r",` + props + `}}}}`
	}
	asl := sfnTask("arn:aws:states:::aws-sdk:sqs:createQueue")
	q, _ := json.Marshal(asl)
	half1, half2 := asl[:20], asl[20:]
	h1, _ := json.Marshal(half1)
	h2, _ := json.Marshal(half2)
	type probe struct {
		name, props, service, op string
	}
	for _, c := range []probe{
		{"literal string", `"DefinitionString":` + string(q), "sqs", "stepfunctions:sqs:createQueue"},
		{"Fn::Join over literals", `"DefinitionString":{"Fn::Join":["",[` + string(h1) + `,` + string(h2) + `]]}`, "sqs", "stepfunctions:sqs:createQueue"},
		{"Fn::Sub string form", `"DefinitionString":{"Fn::Sub":` + string(q) + `}`, "sqs", "stepfunctions:sqs:createQueue"},
		{"Fn::Sub list form", `"DefinitionString":{"Fn::Sub":[` + string(q) + `,{"X":"y"}]}`, "sqs", "stepfunctions:sqs:createQueue"},
		{"Fn::Join over a Ref", `"DefinitionString":{"Fn::Join":["",[` + string(h1) + `,{"Ref":"Part"}]]}`, targetsUncheckedService, "stepfunctions:intrinsic"},
		{"Fn::Sub that substitutes the service", `"DefinitionString":{"Fn::Sub":"{\"StartAt\":\"T\",\"States\":{\"T\":{\"Type\":\"Task\",\"Resource\":\"arn:aws:states:::aws-sdk:${Svc}:create\",\"End\":true}}}"}`, targetsUncheckedService, "stepfunctions:dynamic"},
		{"Fn::If", `"DefinitionString":{"Fn::If":["c",` + string(q) + `,"{}"]}`, targetsUncheckedService, "stepfunctions:intrinsic"},
		{"Ref", `"DefinitionString":{"Ref":"Def"}`, targetsUncheckedService, "stepfunctions:intrinsic"},
		{"Fn::Sub with a fragment", `"DefinitionString":{"Fn::Sub":"{\"StartAt\":\"T\",\"States\":${States}}"}`, targetsUncheckedService, "stepfunctions:unreadable"},
		{"object definition", `"Definition":` + asl, "sqs", "stepfunctions:sqs:createQueue"},
		{"object definition with an intrinsic Resource", `"Definition":{"StartAt":"T","States":{"T":{"Type":"Task","Resource":{"Fn::Sub":"arn:aws:states:::aws-sdk:${S}:x"},"End":true}}}`, targetsUncheckedService, "stepfunctions:dynamic"},
		{"S3 location, literal", `"DefinitionS3Location":{"Bucket":"tplbkt","Key":"m.json"}`, "sqs", "stepfunctions:sqs:createQueue"},
		{"S3 location, versioned", `"DefinitionS3Location":{"Bucket":"tplbkt","Key":"m.json","Version":"v1"}`, targetsUncheckedService, "stepfunctions:intrinsic"},
		{"S3 location, a Ref", `"DefinitionS3Location":{"Bucket":{"Ref":"B"},"Key":"m.json"}`, targetsUncheckedService, "stepfunctions:intrinsic"},
		{"S3 location, an object that is not there", `"DefinitionS3Location":{"Bucket":"tplbkt","Key":"none.json"}`, targetsUncheckedService, "stepfunctions:unreadable"},
		{"S3 location, a reserved path", `"DefinitionS3Location":{"Bucket":"_aws","Key":"m.json"}`, targetsUncheckedService, "stepfunctions:unreadable"},
	} {
		f.clear()
		f.stack("m", machine(c.props))
		if f.allCounts()[c.service][c.op].Calls != 1 {
			t.Errorf("%s: want %s %s, got %v", c.name, c.service, c.op, f.allCounts())
		}
	}
	// the YAML forms
	for name, tpl := range map[string]string{
		"yaml Join": "Resources:\n  M:\n    Type: AWS::StepFunctions::StateMachine\n    Properties:\n      RoleArn: r\n      DefinitionString: !Join\n        - ''\n        - - '{}'\n",
		"yaml Sub":  "Resources:\n  M:\n    Type: AWS::StepFunctions::StateMachine\n    Properties:\n      RoleArn: r\n      DefinitionString: !Sub |\n        {\"StartAt\":\"T\",\"States\":{\"T\":{\"Type\":\"Task\",\"Resource\":\"arn:aws:states:::aws-sdk:${Svc}:x\",\"End\":true}}}\n",
	} {
		f.clear()
		f.stack("y", tpl)
		if f.allCounts()[targetsUncheckedService] == nil && f.allCounts()[cfnUncheckedService] == nil {
			t.Errorf("%s: an unreadable definition is recorded: %v", name, f.allCounts())
		}
	}
}

// 1: a TemplateURL with a query is never read (the engine picks the object by versionId; the front would read the latest)
func TestTemplateURLWithAQueryIsUnchecked(t *testing.T) {
	f := startLambdaFront(t, "cloudformation", "s3")
	for _, u := range []string{
		"https://s3.amazonaws.com/tplbkt/t.json?versionId=v1",
		"https://tplbkt.s3.us-east-1.amazonaws.com/t.json?versionId=v1",
		"http://aws:4566/tplbkt/t.json?versionId=v1",
		"https://s3.amazonaws.com/tplbkt/t.json?x-id=GetObject",
		"https://s3.amazonaws.com/tplbkt/t.json?",
		"https://s3.amazonaws.com/tplbkt/t.json#frag",
	} {
		f.clear()
		form := url.Values{"Action": {"CreateStack"}, "Version": {"2010-05-15"}, "StackName": {"p"}, "TemplateURL": {u}}
		f.do("POST", "/", with(scopeHdr("cloudformation"), "Content-Type", "application/x-www-form-urlencoded"), form.Encode())
		if f.allCounts()[cfnUncheckedService]["cloudformation:unreadable"].Calls != 1 {
			t.Errorf("%s: %v", u, f.allCounts())
		}
	}
	for _, line := range strings.Split(f.fakePaths(), "\n") {
		if strings.Contains(line, "versionId") || strings.Contains(line, "x-id") {
			t.Errorf("the engine was asked for %q", line)
		}
	}
	// Lambda packages and layers with an S3ObjectVersion
	f2 := startLambdaFront(t, "lambda")
	f2.lambda("POST", "/2015-03-31/functions", map[string]any{"FunctionName": "ver", "Runtime": "python3.12", "Code": map[string]any{"S3Bucket": "zipbkt", "S3Key": "light.zip", "S3ObjectVersion": "v1"}})
	if g := f2.heavy()["ver"]; g[0] != "unchecked" {
		t.Errorf("a versioned package: %v", g)
	}
	f2.lambda("POST", "/2018-10-31/layers/vl/versions", map[string]any{"Content": map[string]any{"S3Bucket": "zipbkt", "S3Key": "light.zip", "S3ObjectVersion": "v1"}})
}

// minor: Custom resources, third-party types, SSM scripts and automations
func TestCustomTypesAndSSMScripts(t *testing.T) {
	f := startLambdaFront(t, "cloudformation", "ssm")
	for name, c := range map[string]struct{ tpl, op string }{
		"custom":      {`{"Resources":{"C":{"Type":"Custom::Thing","Properties":{"ServiceToken":"arn"}}}}`, "cloudformation:custom"},
		"third party": {`{"Resources":{"C":{"Type":"Datadog::Monitors::Monitor"}}}`, "cloudformation:unmapped"},
		"custom yaml": {"Resources:\n  C:\n    Type: 'Custom::Other'\n", "cloudformation:custom"},
	} {
		f.clear()
		f.stack("c", c.tpl)
		if f.allCounts()[cfnUncheckedService][c.op].Calls != 1 {
			t.Errorf("%s: %v", name, f.allCounts())
		}
	}
	doc := func(step string) {
		f.do("POST", "/", with(scopeHdr("ssm"), "X-Amz-Target", "AmazonSSM.CreateDocument", "Content-Type", "application/x-amz-json-1.1"),
			string(mustJSON(map[string]any{"Name": "d", "DocumentType": "Automation", "Content": `{"schemaVersion":"0.3","mainSteps":[` + step + `]}`})))
	}
	for _, action := range []string{"aws:executeScript", "aws:executeAutomation"} {
		f.clear()
		doc(`{"name":"a","action":"` + action + `","inputs":{"Runtime":"python3.8","Script":"x"}}`)
		if f.allCounts()[targetsUncheckedService]["ssm:script"].Calls != 1 {
			t.Errorf("%s: %v", action, f.allCounts())
		}
	}
}
