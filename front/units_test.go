package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func TestNormalizeAndUnguarded(t *testing.T) {
	for in, want := range map[string]string{
		"/_rovara/reset": "/_rovara/reset", "//_rovara//reset": "/_rovara/reset", "/a/../_rovara/reset": "/_rovara/reset",
		"/./_rovara/./health": "/_rovara/health", "/..": "/", "": "/", "/a/b/": "/a/b/", "/a/../../_rovara": "/_rovara",
	} {
		if got := normalizePath(in); got != want {
			t.Errorf("normalize(%q) = %q, want %q", in, got, want)
		}
	}
	cases := []struct {
		method, path string
		open         bool
	}{
		{"GET", "/_rovara/health", true}, {"POST", "/_rovara/health", true}, {"GET", "/", true}, {"GET", "/bucket/key", true},
		{"POST", "/_rovara/reset", false}, {"GET", "/_rovara/ledger", false}, {"GET", "/_rovara", false}, {"GET", "/_rovarax", false},
		{"GET", "/_ROVARA/reset", false}, {"GET", "/_rovara/health/", false}, {"GET", "/_rovara/healthx", false},
		{"GET", "/_rovara/lambda/function-code/abc", true}, {"POST", "/_rovara/lambda/function-code/abc", true},
		{"GET", "/_rovara/lambda/function-code/abc/def", false}, {"GET", "/_rovara/lambda/function-code/", false},
		{"GET", "/_rovara/sns/SimpleNotificationService-AbC123.pem", true}, {"POST", "/_rovara/sns/SimpleNotificationService-AbC123.pem", false},
		{"GET", "/_rovara/sns/SimpleNotificationService-AbC123.pem/x", false},
	}
	for _, c := range cases {
		if got := unguarded(c.method, normalizePath(c.path)); got != c.open {
			t.Errorf("unguarded(%s %s) = %v, want %v", c.method, c.path, got, c.open)
		}
	}
}

func TestGuardRules(t *testing.T) {
	tokened := newGuard("secret-token-1234", false)
	if r := tokened.check("POST", "/_rovara/reset", ""); r == nil || r.message != "control token required" {
		t.Errorf("no header: %v", r)
	}
	if r := tokened.check("POST", "/_rovara/reset", "secret-token-1234x"); r == nil {
		t.Error("a longer token matched")
	}
	if r := tokened.check("POST", "/_rovara/reset", "secret-token-123"); r == nil {
		t.Error("a prefix matched")
	}
	if r := tokened.check("POST", "/_rovara/reset", "secret-token-1234"); r != nil {
		t.Errorf("the token was refused: %v", r)
	}
	if r := tokened.check("POST", "/a/../_rovara/reset", ""); r == nil {
		t.Error("a dot-segment path got through")
	}
	closed := newGuard("", false)
	if r := closed.check("POST", "/_rovara/reset", "anything"); r == nil || !strings.Contains(r.message, "no control token") {
		t.Errorf("closed: %v", r)
	}
	if r := newGuard("", true).check("POST", "/_rovara/reset", ""); r != nil {
		t.Errorf("dev switch: %v", r)
	}
	if r := newGuard("tok", true).check("POST", "/_rovara/reset", ""); r == nil {
		t.Error("a token must win over the switch")
	}
	// a token set to the empty string is no token
	if r := newGuard("", false).check("GET", "/_rovara/ledger", ""); r == nil {
		t.Error("empty token opened the guard")
	}
}

func idFor(method, path string, h map[string]string, query, action, version string) identified {
	hdr := http.Header{}
	for k, v := range h {
		hdr.Set(k, v)
	}
	return identify(method, path, path, hdr, query, action, version)
}

const authFmt = "AWS4-HMAC-SHA256 Credential=K/20260101/us-west-2/%s/aws4_request, SignedHeaders=host, Signature=00"

func authFor(svc string) map[string]string {
	return map[string]string{"Authorization": strings.Replace(authFmt, "%s", svc, 1)}
}

func TestIdentify(t *testing.T) {
	type want struct{ svc, op string }
	check := func(name string, id identified, w want) {
		t.Helper()
		got := want{"unknown", id.Operation}
		if id.Service != nil {
			got.svc = id.Service.Key
		}
		if got != w {
			t.Errorf("%s: %+v, want %+v", name, got, w)
		}
	}
	check("sqs json", idFor("POST", "/", map[string]string{"X-Amz-Target": "AmazonSQS.SendMessage"}, "", "", ""), want{"sqs", "SendMessage"})
	check("ddb streams", idFor("POST", "/", map[string]string{"X-Amz-Target": "DynamoDBStreams_20120810.ListStreams"}, "", "", ""), want{"dynamodb", "ListStreams"})
	check("target that agrees with the scope", idFor("POST", "/", map[string]string{"X-Amz-Target": "TrentService.Encrypt", "Authorization": authFor("kms")["Authorization"]}, "", "", ""), want{"kms", "Encrypt"})
	check("target that disagrees with the scope is refused under the scope's service", idFor("POST", "/", map[string]string{"X-Amz-Target": "TrentService.Encrypt", "Authorization": authFor("sqs")["Authorization"]}, "", "", ""), want{"sqs", "unknown"})
	check("apigatewayv2 under the apigateway scope", idFor("POST", "/", map[string]string{"X-Amz-Target": "AmazonApiGatewayV2.GetApis", "Authorization": authFor("apigateway")["Authorization"]}, "", "", ""), want{"apigatewayv2", "GetApis"})
	check("unknown target", idFor("POST", "/", map[string]string{"X-Amz-Target": "Nope_1.Foo"}, "", "", ""), want{"unknown", "unknown"})
	check("cbor", idFor("POST", "/service/SFN/operation/ListStateMachines", map[string]string{"smithy-protocol": "rpc-v2-cbor"}, "", "", ""), want{"states", "ListStateMachines"})
	check("cbor unknown id", idFor("POST", "/service/Zzz/operation/X", map[string]string{"smithy-protocol": "rpc-v2-cbor"}, "", "", ""), want{"unknown", "unknown"})
	check("bucket named service is not cbor", idFor("PUT", "/service/SQS/operation/x", authFor("s3"), "", "", ""), want{"s3", "PutObject"})
	check("query sqs by scope", idFor("POST", "/", authFor("sqs"), "", "SendMessage", ""), want{"sqs", "SendMessage"})
	check("query sns by scope", idFor("POST", "/", authFor("sns"), "", "Publish", ""), want{"sns", "Publish"})
	check("query sts by scope", idFor("POST", "/", authFor("sts"), "", "GetCallerIdentity", ""), want{"sts", "GetCallerIdentity"})
	check("query by version, no scope", idFor("POST", "/", nil, "", "ListTopics", "2010-03-31"), want{"sns", "ListTopics"})
	check("query with no scope and no Version is refused, not guessed", idFor("POST", "/", nil, "", "SomethingNew", ""), want{"unknown", "unknown"})
	check("query action under a non-query scope is refused", idFor("PUT", "/b", authFor("s3"), "Action=x&Version=2010-05-08", "x", "2010-05-08"), want{"s3", "unknown"})
	check("s3 list", idFor("GET", "/", authFor("s3"), "", "", ""), want{"s3", "ListBuckets"})
	check("s3 no scope", idFor("GET", "/b/k", nil, "", "", ""), want{"s3", "GetObject"})
	check("s3 put copy", idFor("PUT", "/b/k", map[string]string{"x-amz-copy-source": "/a/b"}, "", "", ""), want{"s3", "CopyObject"})
	check("presigned scope", idFor("GET", "/b/k", nil, "X-Amz-Credential=K%2F20260101%2Fus-east-1%2Fs3%2Faws4_request", "", ""), want{"s3", "GetObject"})
	check("v2 path under the apigateway scope is apigatewayv2", idFor("POST", "/v2/apis", authFor("apigateway"), "", "", ""), want{"apigatewayv2", "POST /v2/apis"})
	check("v2 path under the execute-api scope is apigatewayv2", idFor("GET", "//v2/domainnames", authFor("execute-api"), "", "", ""), want{"apigatewayv2", "GET //v2/domainnames"})
	check("v1 path stays apigateway", idFor("GET", "/restapis", authFor("apigateway"), "", "", ""), want{"apigateway", "GET /restapis"})
	check("v1 domainnames stay apigateway", idFor("GET", "/domainnames", authFor("apigateway"), "", "", ""), want{"apigateway", "GET /domainnames"})
	check("only the exact segment v2", idFor("GET", "/V2/apis", authFor("apigateway"), "", "", ""), want{"apigateway", "GET /V2/apis"})
	check("execute-api is apigateway", idFor("GET", "/x", authFor("execute-api"), "", "", ""), want{"apigateway", "GET /x"})
	check("lambda rest", idFor("GET", "/2015-03-31/functions", authFor("lambda"), "", "", ""), want{"lambda", "GET /2015-03-31/functions"})
	check("unknown scope", idFor("GET", "/", authFor("ec2"), "", "", ""), want{"unknown", "unknown"})
	if id := idFor("GET", "/", authFor("ec2"), "", "", ""); id.Reason != refuseUnknownScope {
		t.Errorf("reason: %v", id.Reason)
	}
	long := idFor("POST", "/", map[string]string{"X-Amz-Target": "AmazonSQS." + strings.Repeat("x", 500)}, "", "", "")
	if len(long.Operation) != maxOperationChars {
		t.Errorf("operation not bounded: %d", len(long.Operation))
	}
	if id := idFor("POST", "/", authFor("sqs"), "", "", ""); id.Region != "us-west-2" || !id.HasAuth {
		t.Errorf("scope: %+v", id)
	}
}

func TestS3OperationNames(t *testing.T) {
	q := func(s string) url.Values { v, _ := url.ParseQuery(s); return v }
	for _, c := range []struct {
		method, path, query string
		copy                bool
		want                string
	}{
		{"GET", "/", "", false, "ListBuckets"}, {"PUT", "/b", "", false, "CreateBucket"}, {"GET", "/b", "list-type=2", false, "ListObjectsV2"},
		{"GET", "/b/", "", false, "ListObjects"}, {"HEAD", "/b", "", false, "HeadBucket"}, {"DELETE", "/b", "", false, "DeleteBucket"},
		{"PUT", "/b", "versioning", false, "PutBucketVersioning"}, {"GET", "/b", "versions", false, "ListObjectVersions"},
		{"POST", "/b", "delete", false, "DeleteObjects"}, {"POST", "/b/k", "uploads", false, "CreateMultipartUpload"},
		{"PUT", "/b/k", "partNumber=1&uploadId=u", false, "UploadPart"}, {"PUT", "/b/k", "partNumber=1&uploadId=u", true, "UploadPartCopy"},
		{"POST", "/b/k", "uploadId=u", false, "CompleteMultipartUpload"}, {"GET", "/b/k", "tagging", false, "GetObjectTagging"},
		{"PUT", "/b/k", "", false, "PutObject"}, {"GET", "/b/k", "", false, "GetObject"}, {"DELETE", "/b/k", "", false, "DeleteObject"},
		{"PUT", "/b", "object-lock", false, "PutBucketObjectLock"}, {"GET", "/b", "publicAccessBlock", false, "GetBucketPublicAccessBlock"},
	} {
		if got := s3OperationName(c.method, c.path, q(c.query), c.copy); got != c.want {
			t.Errorf("%s %s?%s = %s, want %s", c.method, c.path, c.query, got, c.want)
		}
	}
}

func TestExtractBucket(t *testing.T) {
	for host, want := range map[string]string{
		"b.aws:4566": "b", "my.bucket.aws": "my.bucket", "b.localhost:4566": "b", "b.s3.aws": "b", "b.s3.us-east-1.aws": "b",
		"b.s3.us-east-1.amazonaws.com": "b", "b.s3.amazonaws.com": "b", "www.example.com.s3.eu-west-1.amazonaws.com": "www.example.com",
		"s3.us-east-1.amazonaws.com": "", "s3.amazonaws.com": "", "s3.aws": "", "aws": "", "aws:4566": "", "127.0.0.1:4566": "",
		"172.30.4.16": "", "localhost": "", "other.example": "", "foo.amazonaws.com": "", "my.s3.archive.aws": "my.s3.archive",
	} {
		if got := extractBucket(host, "aws"); got != want {
			t.Errorf("extractBucket(%q) = %q, want %q", host, got, want)
		}
	}
	for _, b := range []string{"_rovara", "ab", "-x-", "a_b", ""} {
		if validBucketName(b) {
			t.Errorf("%q is not a bucket name", b)
		}
	}
	r := httptest.NewRequest("GET", "/ledger", nil)
	r.Host = "_rovara.localhost"
	if b := vhostBucket(r, url.Values{}, "aws"); b != "" {
		t.Errorf("a control-looking host became a bucket: %q", b)
	}
	r = httptest.NewRequest("POST", "/", nil)
	r.Host = "b.aws"
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if b := vhostBucket(r, url.Values{}, "aws"); b != "" {
		t.Errorf("a form request was taken for S3: %q", b)
	}
}

func TestLedgerBoundsAndSummary(t *testing.T) {
	l := newLedger(3)
	for i := 0; i < 5; i++ {
		e := l.begin("sqs", "SendMessage", "POST")
		l.complete(e, 200, false, 1)
	}
	if got := len(l.entries("", 0, 100)); got != 3 {
		t.Errorf("ring kept %d entries", got)
	}
	if string(l.summaryJSON()) != `{"sqs":{"operations":{"SendMessage":{"calls":5,"unsupported":0,"errors":0}},"calls":5,"unsupported":0,"errors":0}}` {
		t.Errorf("summary: %s", l.summaryJSON())
	}
	e := l.begin("s3", "GetObject", "GET")
	l.complete(e, 404, false, 0)
	e = l.begin("s3", "GetObject", "GET")
	l.complete(e, 501, true, 0)
	if !strings.Contains(string(l.summaryJSON()), `"s3":{"operations":{"GetObject":{"calls":2,"unsupported":1,"errors":2}},"calls":2,"unsupported":1,"errors":2}`) {
		t.Errorf("summary: %s", l.summaryJSON())
	}
	// names with quotes and control characters stay valid JSON
	e = l.begin("unknown", "a\"b\\c\n", "GET")
	l.complete(e, 404, true, 0)
	if !strings.Contains(string(l.summaryJSON()), `"a\"b\\c\n"`) {
		t.Errorf("escape: %s", l.summaryJSON())
	}
	l.clear()
	if string(l.summaryJSON()) != "{}" || len(l.entries("", 0, 10)) != 0 {
		t.Error("clear")
	}
}

func TestIsUnsupported(t *testing.T) {
	for _, c := range []struct {
		status int
		hdr    string
		body   string
		want   bool
	}{
		{501, "", "", true}, {200, "", `{"__type":"NotImplemented"}`, false},
		{400, "", `{"__type":"InvalidAction","message":"x"}`, true}, {400, "", `{"__type":"com.amazonaws#UnknownOperationException"}`, true},
		{400, "", `<ErrorResponse><Error><Code>InvalidAction</Code></Error></ErrorResponse>`, true},
		{400, "UnsupportedOperation", `{}`, true}, {400, "", `{"__type":"ValidationException"}`, false}, {404, "", `<Error><Code>NoSuchKey</Code></Error>`, false},
	} {
		if got := isUnsupported(c.status, c.hdr, []byte(c.body)); got != c.want {
			t.Errorf("%+v = %v", c, got)
		}
	}
}

func TestCBORErrorMatchesTheFork(t *testing.T) {
	// the bytes the fork writes for Service sqs is not enabled.
	want := "\xbf\x66__type\x78\x1cServiceNotAvailableException\x67message\x78\x1bService sqs is not enabled.\xff"
	if got := string(cborError("ServiceNotAvailableException", "Service sqs is not enabled.")); got != want {
		t.Errorf("%q != %q", got, want)
	}
}

func TestFlattenQuery(t *testing.T) {
	out := url.Values{}
	flattenQuery("", map[string]interface{}{"TopicArn": "arn:x", "Message": "hi",
		"MessageAttributes": map[string]interface{}{"k": map[string]interface{}{"DataType": "String", "StringValue": "v"}},
		"Attributes":        map[string]interface{}{"DisplayName": "d"},
		"List":              []interface{}{"a", "b"}}, out)
	want := url.Values{"TopicArn": {"arn:x"}, "Message": {"hi"}, "MessageAttributes.entry.1.Name": {"k"},
		"MessageAttributes.entry.1.Value.DataType": {"String"}, "MessageAttributes.entry.1.Value.StringValue": {"v"},
		"Attributes.entry.1.key": {"DisplayName"}, "Attributes.entry.1.value": {"d"}, "List.member.1": {"a"}, "List.member.2": {"b"}}
	if !reflect.DeepEqual(out, want) {
		t.Errorf("%v != %v", out, want)
	}
}

func TestRewriterUnits(t *testing.T) {
	rw := newRewriter("http://aws:4566")
	if got := string(rw.queueURLsXML([]byte(`<ListQueuesResult><QueueUrl>https://sqs.eu-west-1.amazonaws.com/000000000000/q</QueueUrl></ListQueuesResult>`))); got !=
		`<ListQueuesResult><QueueUrl>http://aws:4566/000000000000/q</QueueUrl></ListQueuesResult>` {
		t.Errorf("xml: %s", got)
	}
	if got := string(rw.queueURLsJSON([]byte(`{"queueUrls":["https://sqs.us-east-1.amazonaws.com/0/a"],"Other":"https://sqs.us-east-1.amazonaws.com/0/x"}`))); !strings.Contains(got, `"queueUrls":["http://aws:4566/0/a"]`) || !strings.Contains(got, `"Other":"https://sqs.us-east-1.amazonaws.com/0/x"`) {
		t.Errorf("json: %s", got)
	}
	if got := rw.internalAddr("see https://127.0.0.1:41000/x and 127.0.0.1:41000 and http://localhost:41000/y", 41000); got != "see http://aws:4566/x and aws:4566 and http://aws:4566/y" {
		t.Errorf("internal: %s", got)
	}
	if got := rw.internalAddr("https://127.0.0.1:41001/x", 41000); got != "https://127.0.0.1:41001/x" {
		t.Errorf("another port was rewritten: %s", got)
	}
	// namespaces are never touched
	if got := string(rw.queueURLsXML([]byte(`<R xmlns="http://sqs.amazonaws.com/doc/2012-11-05/"></R>`))); strings.Contains(got, "aws:4566") {
		t.Errorf("namespace: %s", got)
	}
	if got := rw.s3Location([]byte(`<Location>https://a.b.s3.eu-west-1.amazonaws.com/k/e y</Location>`)); string(got) != `<Location>http://aws:4566/a.b/k/e y</Location>` {
		t.Errorf("location: %s", got)
	}
}
