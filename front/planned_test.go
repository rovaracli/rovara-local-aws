package main

import (
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"testing"
)

func scopeHdr(svc string) map[string]string {
	return map[string]string{"Authorization": "AWS4-HMAC-SHA256 Credential=K/20260101/us-east-1/" + svc + "/aws4_request, SignedHeaders=host, Signature=00"}
}

func plannedID(method, path string, h map[string]string, query, action, version string) identified {
	hh := http.Header{}
	for k, v := range h {
		hh.Set(k, v)
	}
	return identifyPlanned(method, path, path, hh, query, action, version, nil)
}

func with(h map[string]string, kv ...string) map[string]string {
	out := map[string]string{}
	for k, v := range h {
		out[k] = v
	}
	for i := 0; i+1 < len(kv); i += 2 {
		out[kv[i]] = kv[i+1]
	}
	return out
}

func TestPlannedConfig(t *testing.T) {
	env := func(m map[string]string) settings { return func(k string) string { return m[k] } }
	base := map[string]string{}
	c, err := loadConfig(env(base))
	if err != nil || c.Planned != nil {
		t.Fatalf("no setting is the legacy mode: %v %v", err, c.Planned)
	}
	base[envPlanned] = " sqs, secretsmanager ,events,cognito-idp,S3 ,sqs"
	c, err = loadConfig(env(base))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(c.PlannedKeys, ","); got != "eventbridge,cognito-identity-provider,s3,secrets-manager,sqs" && got != "cognito-identity-provider,eventbridge,s3,secrets-manager,sqs" {
		t.Errorf("legacy ids are read as their keys, once: %s", got)
	}
	base[envPlanned] = "sqs,nosuchservice"
	if _, err := loadConfig(env(base)); err == nil || !strings.Contains(err.Error(), "nosuchservice") {
		t.Errorf("an unknown key refuses start naming it: %v", err)
	}
	base[envPlanned] = ","
	if c, err := loadConfig(env(base)); err != nil || c.Planned == nil || len(c.Planned) != 0 {
		t.Errorf("an empty plan is a plan that names nothing: %v %v", err, c)
	}
}

func TestPlannedIdentification(t *testing.T) {
	type want struct{ svc, op string }
	check := func(name string, id identified, w want) {
		t.Helper()
		got := want{"unknown", id.Operation}
		if id.Service != nil {
			got.svc = id.Service.Key
		}
		if id.Reason != notRefused && id.Service == nil {
			got.op = "unknown"
		}
		if got != w {
			t.Errorf("%s: got %+v (reason %d), want %+v", name, got, id.Reason, w)
		}
	}
	js := func(target string, h map[string]string) map[string]string {
		return with(h, "X-Amz-Target", target, "Content-Type", "application/x-amz-json-1.1")
	}
	check("ssm", plannedID("POST", "/", js("AmazonSSM.GetParameter", scopeHdr("ssm")), "", "", ""), want{"ssm", "GetParameter"})
	check("secrets manager", plannedID("POST", "/", js("secretsmanager.GetSecretValue", scopeHdr("secretsmanager")), "", "", ""), want{"secrets-manager", "GetSecretValue"})
	check("a service nobody had", plannedID("POST", "/", js("AmazonSageMakerFeatureStore.X", scopeHdr("sagemaker")), "", "", ""), want{"unknown", "unknown"})
	check("sagemaker json", plannedID("POST", "/", js("SageMaker.ListEndpoints", scopeHdr("sagemaker")), "", "", ""), want{"sagemaker", "ListEndpoints"})
	check("dynamodb", plannedID("POST", "/", js("DynamoDB_20120810.ListTables", scopeHdr("dynamodb")), "", "", ""), want{"dynamodb", "ListTables"})
	check("dynamodb streams", plannedID("POST", "/", js("DynamoDBStreams_20120810.ListStreams", scopeHdr("dynamodb")), "", "", ""), want{"dynamodb-streams", "ListStreams"})
	check("a streams operation under the dynamodb prefix is still the streams service, so a plan without it refuses it",
		plannedID("POST", "/", js("DynamoDB_20120810.ListStreams", scopeHdr("dynamodb")), "", "", ""), want{"dynamodb-streams", "ListStreams"})
	check("events default is eventbridge", plannedID("POST", "/", js("AWSEvents.PutEvents", scopeHdr("events")), "", "", ""), want{"eventbridge", "PutEvents"})
	check("eventbridge-only operation", plannedID("POST", "/", js("AWSEvents.ListEndpoints", scopeHdr("events")), "", "", ""), want{"eventbridge", "ListEndpoints"})
	check("the cloudwatch events name", plannedID("POST", "/", js("AWSEvents.ListRules", scopeHdr("cloudwatchevents")), "", "", ""), want{"cloudwatch-events", "ListRules"})
	check("eventbridge v2 over cbor", plannedID("POST", "/service/AWSEventsV2/operation/PutEvents", with(scopeHdr("events"), "smithy-protocol", "rpc-v2-cbor"), "", "", ""), want{"eventbridgev2", "PutEvents"})
	check("timestream write only", plannedID("POST", "/", js("Timestream_20181101.ListDatabases", scopeHdr("timestream")), "", "", ""), want{"timestream-write", "ListDatabases"})
	check("timestream query only", plannedID("POST", "/", js("Timestream_20181101.ListScheduledQueries", scopeHdr("timestream")), "", "", ""), want{"timestream-query", "ListScheduledQueries"})
	check("timestream common operation is ambiguous", plannedID("POST", "/", js("Timestream_20181101.DescribeEndpoints", scopeHdr("timestream")), "", "", ""), want{"unknown", "unknown"})
	check("a fully qualified target prefix, as the CloudTrail SDK sends it", plannedID("POST", "/", js("com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.DescribeQuery", scopeHdr("cloudtrail")), "", "", ""), want{"cloudtrail", "DescribeQuery"})
	check("a target that names cloudtrail under another service's scope is refused", plannedID("POST", "/", js("CloudTrail_20131101.DescribeQuery", scopeHdr("ssm")), "", "", ""), want{"unknown", "unknown"})
	check("kinesis analytics v1", plannedID("POST", "/", js("KinesisAnalytics_20150814.ListApplications", scopeHdr("kinesisanalytics")), "", "", ""), want{"kinesis-analytics", "ListApplications"})
	check("kinesis analytics v2", plannedID("POST", "/", js("KinesisAnalytics_20180523.ListApplications", scopeHdr("kinesisanalytics")), "", "", ""), want{"kinesis-analytics-v2", "ListApplications"})
	check("cloudhsm", plannedID("POST", "/", js("BaldrApiService.DescribeClusters", scopeHdr("cloudhsm")), "", "", ""), want{"cloudhsm-v2", "DescribeClusters"})
	// Query
	check("sns", plannedID("POST", "/", scopeHdr("sns"), "", "Publish", "2010-03-31"), want{"sns", "Publish"})
	check("iam", plannedID("POST", "/", scopeHdr("iam"), "", "ListUsers", "2010-05-08"), want{"iam", "ListUsers"})
	check("sts", plannedID("POST", "/", scopeHdr("sts"), "", "GetCallerIdentity", "2011-06-15"), want{"sts", "GetCallerIdentity"})
	check("elb v1", plannedID("POST", "/", scopeHdr("elasticloadbalancing"), "", "DescribeLoadBalancers", "2012-06-01"), want{"elastic-load-balancing", "DescribeLoadBalancers"})
	check("elb v2", plannedID("POST", "/", scopeHdr("elasticloadbalancing"), "", "DescribeLoadBalancers", "2015-12-01"), want{"elastic-load-balancing-v2", "DescribeLoadBalancers"})
	check("rds tie-break", plannedID("POST", "/", scopeHdr("rds"), "", "DescribeDBInstances", "2014-10-31"), want{"rds", "DescribeDBInstances"})
	check("an operation only rds has", plannedID("POST", "/", scopeHdr("rds"), "", "CopyDBSnapshot", "2014-10-31"), want{"rds", "CopyDBSnapshot"})
	check("docdb under its own name", plannedID("POST", "/", scopeHdr("docdb"), "", "DescribeDBInstances", "2014-10-31"), want{"docdb", "DescribeDBInstances"})
	check("neptune under its own name", plannedID("POST", "/", scopeHdr("neptune"), "", "DescribeDBInstances", "2014-10-31"), want{"neptune", "DescribeDBInstances"})
	check("a query action on a REST service is refused", plannedID("POST", "/", scopeHdr("s3"), "", "CreateVpc", "2016-11-15"), want{"unknown", "unknown"})
	check("sqs query", plannedID("POST", "/", scopeHdr("sqs"), "", "SendMessage", "2012-11-05"), want{"sqs", "SendMessage"})
	// REST: API Gateway v1 and v2 share the apigateway scope and are told apart by their route tables
	for _, c := range []struct{ method, path, svc, op string }{
		{"GET", "/restapis", "api-gateway", "GetRestApis"},
		{"POST", "/restapis", "api-gateway", "CreateRestApi"},
		{"GET", "/domainnames", "api-gateway", "GetDomainNames"},
		{"GET", "/vpclinks", "api-gateway", "GetVpcLinks"},
		{"GET", "/v2/apis", "apigatewayv2", "GetApis"},
		{"POST", "/v2/apis", "apigatewayv2", "CreateApi"},
		{"GET", "/v2/domainnames", "apigatewayv2", "GetDomainNames"},
		{"POST", "/v2/domainnames", "apigatewayv2", "CreateDomainName"},
		{"GET", "/v2/vpclinks", "apigatewayv2", "GetVpcLinks"},
		{"GET", "/v2/apis/abc123/routes", "apigatewayv2", "GetRoutes"},
		{"GET", "/restapis/abc123/resources", "api-gateway", "GetResources"},
	} {
		check(c.method+" "+c.path, plannedID(c.method, c.path, scopeHdr("apigateway"), "", "", ""), want{c.svc, c.op})
	}
	// the raw path decides, as in the engine: an encoded first segment is not the literal it decodes to
	if id := identifyPlanned("GET", "/v2/apis", "/v%32/apis", http.Header{"Authorization": {scopeHdr("apigateway")["Authorization"]}}, "", "", "", nil); id.Service != nil {
		t.Errorf("/v%%32/apis is not an apigatewayv2 path: %s", id.Service.Key)
	}
	// s3 and s3-control: the more specific template wins
	check("s3 object", plannedID("PUT", "/bkt/key", scopeHdr("s3"), "", "", ""), want{"s3", "PutObject"})
	check("s3 list buckets", plannedID("GET", "/", scopeHdr("s3"), "", "", ""), want{"s3", "ListBuckets"})
	check("s3 control", plannedID("GET", "/v20180820/configuration/publicAccessBlock", scopeHdr("s3"), "", "", ""), want{"s3-control", "GetPublicAccessBlock"})
	// lambda
	check("lambda list functions", plannedID("GET", "/2015-03-31/functions", scopeHdr("lambda"), "", "", ""), want{"lambda", "ListFunctions"})
	check("lambda tag routes are shared with another service: refused", plannedID("POST", "/2017-03-31/tags/arn:aws:lambda:us-east-1:1:function:f", scopeHdr("lambda"), "", "", ""), want{"unknown", "unknown"})
	// unshared REST service: the operation name comes from the route table
	check("cognito identity", plannedID("POST", "/", js("AWSCognitoIdentityProviderService.ListUserPools", scopeHdr("cognito-idp")), "", "", ""), want{"cognito-identity-provider", "ListUserPools"})
	// scope and signal disagree
	check("target of another service", plannedID("POST", "/", js("AmazonSSM.GetParameter", scopeHdr("kms")), "", "", ""), want{"unknown", "unknown"})
	check("unknown scope", plannedID("POST", "/", scopeHdr("definitely-not-aws"), "", "", ""), want{"unknown", "unknown"})
	check("no scope, rest: s3 is the sink", plannedID("GET", "/bkt/key", nil, "", "", ""), want{"s3", "GetObject"})
	check("no scope, target", plannedID("POST", "/", js("TrentService.ListKeys", nil), "", "", ""), want{"kms", "ListKeys"})
	{
		hh := http.Header{}
		hh.Add("X-Amz-Target", "AmazonSSM.GetParameter")
		hh.Add("X-Amz-Target", "CloudTrail_20131101.DescribeQuery")
		hh.Set("Authorization", scopeHdr("ssm")["Authorization"])
		if id := identifyPlanned("POST", "/", "/", hh, "", "", "", nil); id.Service != nil || id.Reason != refuseMismatch {
			t.Errorf("two targets are refused: %+v", id)
		}
	}
	// execute-api (an API invoke URL signs with it) is API Gateway, as in 0.5.15
	check("execute-api", plannedID("GET", "/restapis", scopeHdr("execute-api"), "", "", ""), want{"api-gateway", "GetRestApis"})
	// the engine's data planes, behind the reserved path
	check("lambda function url", plannedID("GET", "/_aws/lambda-url/abc123/path", nil, "", "", ""), want{"lambda", "InvokeFunctionUrl"})
	check("lambda function url, host spelling", plannedID("GET", "/_aws/abc123.lambda-url.us-east-1.on.aws/", nil, "", "", ""), want{"lambda", "InvokeFunctionUrl"})
	check("api invoke", plannedID("GET", "/_aws/execute-api/abc123/stage/x", nil, "", "", ""), want{"apigatewayv2", "InvokeApi"})
	if id := identifyPlanned("GET", "/_aws/execute-api/abc123/x", "/_aws/execute-api/abc123/x", http.Header{}, "", "", "", map[string]bool{"api-gateway": true}); id.Service == nil || id.Service.Key != "api-gateway" {
		t.Errorf("an API invoke is the planned API Gateway service: %+v", id.Service)
	}
	check("an unknown data plane", plannedID("GET", "/_aws/nothing/x", nil, "", "", ""), want{"unknown", "unknown"})
	// the engine is told the service the front decided on, under the name the engine serves it by
	if id := plannedID("POST", "/", js("AWSEvents.ListRules", scopeHdr("cloudwatchevents")), "", "", ""); engineAuthorization(id) == "" || !strings.Contains(engineAuthorization(id), "/cloudwatchevents/aws4_request") {
		t.Errorf("cloudwatch-events must be signed as cloudwatchevents: %s", engineAuthorization(id))
	}
	if id := plannedID("POST", "/", scopeHdr("rds"), "", "DescribeDBInstances", "2014-10-31"); !strings.Contains(engineAuthorization(id), "/rds/aws4_request") {
		t.Errorf("rds must be signed as rds: %s", engineAuthorization(id))
	}
}

// Every service of the table, every kind of request its model has: the front decides the very service the request is for, or
// refuses it. It never names another service, which is what a plan that names one and not the other relies on.
func TestPlannedTableNeverNamesAnotherService(t *testing.T) {
	routes, refused, decided := 0, 0, 0
	for i := range genRows {
		r := &genRows[i]
		tt := tableByKey[r.Key]
		sc := r.RK
		if r.RK == "" {
			continue
		}
		h := scopeHdr(sc)
		var reqs []identified
		if r.Proto&gpJSON != 0 && r.Prefix != "" {
			op := "SomeOperation"
			if first := strings.Fields(r.Ops); len(first) > 0 {
				op = first[0]
			}
			reqs = append(reqs, plannedID("POST", "/", with(h, "X-Amz-Target", r.Prefix+"."+op), "", "", ""))
			reqs = append(reqs, plannedID("POST", "/", with(h, "X-Amz-Target", r.Prefix+".NoSuchOperationAnywhere"), "", "", ""))
		}
		if r.Proto&gpQuery != 0 && r.QVer != "" {
			op := "SomeOperation"
			if first := strings.Fields(r.Ops); len(first) > 0 {
				op = first[0]
			}
			reqs = append(reqs, plannedID("POST", "/", h, "", op, r.QVer))
		}
		if r.Proto&gpCBOR != 0 {
			reqs = append(reqs, plannedID("POST", "/service/"+r.Shape+"/operation/SomeOperation", with(h, "smithy-protocol", "rpc-v2-cbor"), "", "", ""))
		}
		if r.Proto&gpREST != 0 {
			for _, rt := range tt.restRoutes() {
				var segs []string
				for _, s := range rt.segs {
					switch s.kind {
					case 0:
						segs = append(segs, s.lit)
					default:
						segs = append(segs, "x1")
					}
				}
				routes++
				id := plannedID(rt.method, "/"+strings.Join(segs, "/"), h, "", "", "")
				if id.Service != nil && id.Service.Key != r.Key {
					t.Errorf("%s %s of %s was decided as %s", rt.method, strings.Join(segs, "/"), r.Key, id.Service.Key)
				}
				if id.Service == nil {
					refused++
				} else {
					decided++
				}
			}
		}
		for _, id := range reqs {
			if id.Service != nil && id.Service.Key != r.Key && genTieBreak[r.RK] == nil {
				// a shared scope and an operation both services have: the front may name the other service only when the request
				// carries nothing that says otherwise, and never for an operation that only this one has
				t.Errorf("a request for %s was decided as %s (%s)", r.Key, id.Service.Key, id.Operation)
			}
			if id.Service == nil {
				refused++
			} else {
				decided++
			}
		}
	}
	t.Logf("%d REST routes sampled, %d decided, %d refused", routes, decided, refused)
}

func TestPlannedGateAndLedger(t *testing.T) {
	f := startFront(t, func(c *Config) {
		c.Planned = map[string]bool{"sqs": true, "kms": true}
		c.PlannedKeys = []string{"kms", "sqs"}
	})
	f.srv.ledger.planned = true
	// in the plan: forwarded
	if r := f.do("POST", "/", sqsJSON("ListQueues"), "{}"); r.status != 200 {
		t.Fatalf("a planned service must be served: %d %s", r.status, r.body)
	}
	// a table service the plan does not name: refused, never forwarded
	ddb := map[string]string{"X-Amz-Target": "DynamoDB_20120810.ListTables", "Content-Type": "application/x-amz-json-1.0",
		"Authorization": scopeHdr("dynamodb")["Authorization"]}
	r := f.do("POST", "/", ddb, "{}")
	if r.status != 400 || !strings.Contains(r.body, "ServiceNotAvailableException") || !strings.Contains(r.body, "dynamodb") {
		t.Errorf("out of plan: %d %s", r.status, r.body)
	}
	// an unknown scope is unsupported, not out of plan
	if r := f.do("POST", "/", map[string]string{"Authorization": scopeHdr("not-a-service")["Authorization"]}, ""); r.status != 404 {
		t.Errorf("unknown scope: %d", r.status)
	}
	sum := f.do("GET", "/_rovara/ledger/summary", tok(), "").body
	if !strings.Contains(sum, `"dynamodb":{"operations":{"ListTables":{"calls":1,"unsupported":0,"errors":1}},"calls":1,"unsupported":0,"errors":1,"outOfPlan":1}`) {
		t.Errorf("summary must count outOfPlan per service: %s", sum)
	}
	if !strings.Contains(sum, `"sqs":{"operations":{"ListQueues":{"calls":1,"unsupported":0,"errors":0}},"calls":1,"unsupported":0,"errors":0,"outOfPlan":0}`) {
		t.Errorf("a planned service shows outOfPlan 0: %s", sum)
	}
	h := f.do("GET", "/_rovara/health", nil, "").body
	if h != `{"services":{"kms":"running","sqs":"running"},"version":"0.1.0"}` {
		t.Errorf("health lists the plan: %s", h)
	}
	// the seed obeys the plan too: it calls the engine directly
	s := f.do("POST", "/_rovara/seed", tok(), `{"s3":{"buckets":[{"name":"b1"}]},"sqs":{"queues":[{"name":"q1"}]}}`)
	if s.status != 422 || !strings.Contains(s.body, `"service":"s3","action":"Seed"`) || !strings.Contains(s.body, "not in the plan") ||
		!strings.Contains(s.body, `"service":"sqs","action":"CreateQueue","name":"q1","ok":true`) {
		t.Errorf("seed against the plan: %d %s", s.status, s.body)
	}
	// without a plan the summary keeps its 0.5.15 shape
	g := startFront(t, nil)
	g.do("POST", "/", sqsJSON("ListQueues"), "{}")
	if s := g.do("GET", "/_rovara/ledger/summary", tok(), "").body; strings.Contains(s, "outOfPlan") {
		t.Errorf("legacy summary shape changed: %s", s)
	}
}

func TestPlannedRefusalsAreNotForwarded(t *testing.T) {
	f := startFront(t, func(c *Config) { c.Planned = map[string]bool{"sqs": true}; c.PlannedKeys = []string{"sqs"} })
	for _, c := range []struct {
		name string
		h    map[string]string
	}{
		{"scope of one service, target of another", with(sqsJSON("ListQueues"), "Authorization", scopeHdr("dynamodb")["Authorization"])},
		{"shared name, operation of the unplanned member", map[string]string{"X-Amz-Target": "Timestream_20181101.DescribeEndpoints", "Authorization": scopeHdr("timestream")["Authorization"]}},
	} {
		r := f.do("POST", "/", c.h, "{}")
		if r.status != 404 && r.status != 400 {
			t.Errorf("%s: %d %s", c.name, r.status, r.body)
		}
		if strings.Contains(r.header.Get("X-Fake-Path"), "/") {
			t.Errorf("%s was forwarded to the engine", c.name)
		}
	}
	keys := []string{}
	for k := range tableByKey {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) != 436 {
		t.Errorf("the table has %d services, want 436 (%s)", len(keys), fmt.Sprint(genEngine))
	}
}

func cfnCall(f *testFront, form string) result {
	return f.do("POST", "/", with(scopeHdr("cloudformation"), "Content-Type", "application/x-www-form-urlencoded"), form)
}

func TestClassifyTemplate(t *testing.T) {
	planned := map[string]bool{"cloudformation": true, "sqs": true}
	yaml := "AWSTemplateFormatVersion: '2010-09-09'\nResources:\n  Q:\n    Type: AWS::SQS::Queue\n  K:\n    Type: AWS::KMS::Key\n  K2:\n    Type: \"AWS::KMS::Alias\"\n  T:\n    Type: AWS::SNS::Topic\n"
	f := classifyTemplate(yaml, planned)
	got := []string{}
	for _, o := range f.out {
		got = append(got, o.service+" "+o.op)
	}
	want := "kms cloudformation:AWS::KMS::Alias,kms cloudformation:AWS::KMS::Key,sns cloudformation:AWS::SNS::Topic"
	if strings.Join(got, ",") != want || f.unchecked != "" {
		t.Errorf("yaml: %v unchecked=%q", got, f.unchecked)
	}
	js := `{"Resources":{"A":{"Type":"AWS::Lambda::Function"},"B":{"Type":"AWS::Events::Rule"},"C":{"Type":"AWS::Logs::LogGroup"},"D":{"Type":"AWS::IAM::Role"}}}`
	f = classifyTemplate(js, planned)
	keys := []string{}
	for _, o := range f.out {
		keys = append(keys, o.service)
	}
	if strings.Join(keys, ",") != "iam,lambda,cloudwatch-logs,cloudwatch-events" && strings.Join(keys, ",") != "iam,lambda,cloudwatch-logs,eventbridge" && len(keys) != 4 {
		t.Errorf("json: %v", keys)
	}
	if f := classifyTemplate(`{"Transform":"AWS::Serverless-2016-10-31","Resources":{"F":{"Type":"AWS::Serverless::Function"}}}`, planned); f.unchecked != "transform" || len(f.out) != 0 {
		t.Errorf("a transform is unchecked: %+v", f)
	}
	if f := classifyTemplate(`{"Resources":{"N":{"Type":"AWS::CloudFormation::Stack"},"W":{"Type":"AWS::CloudFormation::WaitConditionHandle"}}}`, planned); f.unchecked != "nested" || len(f.out) != 0 {
		t.Errorf("a nested stack is unchecked and CloudFormation's own types are in the plan: %+v", f)
	}
	if f := classifyTemplate(`{"Resources":{"X":{"Type":"AWS::NoSuchNamespace::Thing"}}}`, planned); f.unchecked != "unmapped" {
		t.Errorf("an unknown namespace is unchecked: %+v", f)
	}
	// Events is the namespace of two table services; a plan that names either one covers the namespace
	if f := classifyTemplate(js, map[string]bool{"cloudwatch-events": true}); func() bool {
		for _, o := range f.out {
			if strings.Contains(o.op, "Events::") {
				return true
			}
		}
		return false
	}() {
		t.Errorf("a plan naming cloudwatch-events covers AWS::Events: %+v", f.out)
	}
}

func TestPlannedCloudFormationIsRecorded(t *testing.T) {
	f := startFront(t, func(c *Config) {
		c.Planned = map[string]bool{"cloudformation": true, "sqs": true}
		c.PlannedKeys = []string{"cloudformation", "sqs"}
	})
	f.srv.ledger.planned = true
	summary := func() string { return f.do("GET", "/_rovara/ledger/summary", tok(), "").body }
	inline := url.Values{"Action": {"CreateStack"}, "Version": {"2010-05-15"}, "StackName": {"s1"},
		"TemplateBody": {`{"Resources":{"Q":{"Type":"AWS::SQS::Queue"},"K":{"Type":"AWS::KMS::Key"},"F":{"Type":"AWS::Lambda::Function"}}}`}}
	if r := cfnCall(f, inline.Encode()); r.status != 200 {
		t.Fatalf("the stack is not blocked: %d %s", r.status, r.body)
	}
	sum := summary()
	for _, want := range []string{
		`"kms":{"operations":{"cloudformation:AWS::KMS::Key":{"calls":1,"unsupported":0,"errors":0}},"calls":1,"unsupported":0,"errors":0,"outOfPlan":1}`,
		`"lambda":{"operations":{"cloudformation:AWS::Lambda::Function":{"calls":1,"unsupported":0,"errors":0}},"calls":1,"unsupported":0,"errors":0,"outOfPlan":1}`,
	} {
		if !strings.Contains(sum, want) {
			t.Errorf("summary lacks %s\n%s", want, sum)
		}
	}
	if strings.Contains(sum, "AWS::SQS::Queue") || strings.Contains(sum, cfnUncheckedService) {
		t.Errorf("a planned service and a readable template record nothing else: %s", sum)
	}
	// a template the engine's own S3 holds is read over loopback, by the AWS-style URL and by the base URL
	for _, u := range []string{"https://s3.amazonaws.com/tplbkt/t.json", "https://tplbkt.s3.us-east-1.amazonaws.com/t.json", "http://aws:4566/tplbkt/t.json"} {
		form := url.Values{"Action": {"CreateChangeSet"}, "Version": {"2010-05-15"}, "StackName": {"s2"}, "ChangeSetName": {"c"}, "TemplateURL": {u}}
		cfnCall(f, form.Encode())
	}
	if s := summary(); !strings.Contains(s, `"kms":{"operations":{"cloudformation:AWS::KMS::Key":{"calls":4`) {
		t.Errorf("one count per request for the key (inline + 3 URLs): %s", s)
	}
	// nested, unreadable and too large are counted once under the marker; an update that reuses the template records nothing
	for _, c := range []struct{ name, key, val, op string }{
		{"nested", "TemplateURL", "https://s3.amazonaws.com/tplbkt/nested.json", "cloudformation:nested"},
		{"foreign host", "TemplateURL", "https://example.invalid/t.json", "cloudformation:unreadable"},
		{"missing object", "TemplateURL", "https://s3.amazonaws.com/tplbkt/none.json", "cloudformation:unreadable"},
		{"too large", "TemplateURL", "https://s3.amazonaws.com/tplbkt/big.json", "cloudformation:unreadable"},
		{"inline transform", "TemplateBody", `{"Transform":"AWS::Serverless-2016-10-31","Resources":{}}`, "cloudformation:transform"},
	} {
		before := summary()
		form := url.Values{"Action": {"UpdateStack"}, "Version": {"2010-05-15"}, "StackName": {"s3"}, c.key: {c.val}}
		cfnCall(f, form.Encode())
		after := summary()
		n := func(s string) int { return strings.Count(s, `"`+c.op+`"`) }
		if n(after) != 1 || !strings.Contains(after, `"`+cfnUncheckedService+`":`) || after == before {
			t.Errorf("%s: want %s once under %s: %s", c.name, c.op, cfnUncheckedService, after)
		}
		f.do("DELETE", "/_rovara/ledger", tok(), "")
	}
	f.do("DELETE", "/_rovara/ledger", tok(), "")
	reuse := url.Values{"Action": {"UpdateStack"}, "Version": {"2010-05-15"}, "StackName": {"s4"}, "UsePreviousTemplate": {"true"}}
	cfnCall(f, reuse.Encode())
	if s := summary(); strings.Contains(s, cfnUncheckedService) || strings.Contains(s, "kms") {
		t.Errorf("an update that reuses the template records nothing: %s", s)
	}
	// without a plan CloudFormation is not looked at
	g := startFront(t, nil)
	cfnCallLegacy := g.do("POST", "/", with(scopeHdr("cloudformation"), "Content-Type", "application/x-www-form-urlencoded"), inline.Encode())
	if s := g.do("GET", "/_rovara/ledger/summary", tok(), "").body; cfnCallLegacy.status == 0 || strings.Contains(s, "AWS::KMS") {
		t.Errorf("legacy mode records nothing: %s", s)
	}
}

// The plan setting is optional for ONE release (workers roll out after the image): a run with a control token and no
// ROVARA_AWS_PLANNED_SERVICES starts, in the legacy mode, and the ROVARA_AWS_SERVICES_<X>_ENABLED switches still govern. When
// plannedRequired is flipped (see config.go), this test flips with it.
func TestPlannedSettingIsOptionalForOneRelease(t *testing.T) {
	if plannedRequired {
		t.Fatal("plannedRequired was flipped: update this test to expect the refusal")
	}
	env := func(m map[string]string) settings { return func(k string) string { return m[k] } }
	run := map[string]string{envToken: "tokentokentoken1", envHost: "172.30.4.16", envBaseURL: "http://aws:4566",
		envPresign: "abcdefghijklmnop1", envReceipt: "abcdefghijklmnop2", "ROVARA_AWS_SERVICES_KMS_ENABLED": "false"}
	c, err := loadConfig(env(run))
	if err != nil {
		t.Fatalf("a run without a plan must still start for one release: %v", err)
	}
	if c.Planned != nil || !c.Disabled["kms"] {
		t.Errorf("without a plan the legacy switches govern: planned=%v disabled=%v", c.Planned, c.Disabled)
	}
	run[envPlanned] = "kms"
	c, err = loadConfig(env(run))
	if err != nil || c.Planned == nil || !c.Planned["kms"] || c.Disabled["kms"] {
		t.Errorf("with a plan the plan governs and the legacy switches are ignored: %v %v %v", err, c.Planned, c.Disabled)
	}
}
