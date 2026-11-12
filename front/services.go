package main

import (
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// proto is the wire protocol a request arrived in; it decides the shape of an error the front itself writes.
type proto int

const (
	protoQuery proto = iota
	protoJSON
	protoRestJSON
	protoRestXML
	protoCBOR
)

// service is one entry of the fork's service catalog (ResolvedServiceCatalog), reduced to what the front needs.
type service struct {
	Key         string   // the fork's external key: what the ledger and the "not enabled" message name
	ConfigKey   string   // the fork's rovara-aws.services.<key>.enabled switch
	SigningName string   // the SigV4 service name the front signs engine requests with
	Scopes      []string // SigV4 credential scopes that identify the service
	Targets     []string // X-Amz-Target prefixes
	CBORIDs     []string // rpc-v2-cbor SDK service ids
	Default     proto
}

// serviceConfigKeys is the Cloud worker's LOCAL_AWS_SERVICE_KEYS: the switches it can set to false.
var serviceConfigKeys = []string{"ssm", "sqs", "s3", "dynamodb", "sns", "lambda", "apigateway", "apigatewayv2", "iam",
	"eventbridge", "eventbridgev2", "cloudwatchlogs", "secretsmanager", "kinesis", "kms", "cognito", "stepfunctions", "sagemaker"}

// catalog is the fork's, in the fork's order (health lists them in this order too).
var catalog = []*service{
	{Key: "ssm", ConfigKey: "ssm", SigningName: "ssm", Scopes: []string{"ssm"}, Targets: []string{"AmazonSSM."}, Default: protoJSON},
	{Key: "sqs", ConfigKey: "sqs", SigningName: "sqs", Scopes: []string{"sqs"}, Targets: []string{"AmazonSQS."}, CBORIDs: []string{"SQS"}, Default: protoQuery},
	{Key: "s3", ConfigKey: "s3", SigningName: "s3", Scopes: []string{"s3", "s3express"}, Default: protoRestXML},
	{Key: "dynamodb", ConfigKey: "dynamodb", SigningName: "dynamodb", Scopes: []string{"dynamodb"},
		Targets: []string{"DynamoDB_20120810.", "DynamoDBStreams_20120810.", "DynamoDB_20111205."}, Default: protoJSON},
	{Key: "sns", ConfigKey: "sns", SigningName: "sns", Scopes: []string{"sns"}, Targets: []string{"SNS_20100331."}, CBORIDs: []string{"SNS"}, Default: protoQuery},
	{Key: "lambda", ConfigKey: "lambda", SigningName: "lambda", Scopes: []string{"lambda"}, Default: protoRestJSON},
	{Key: "apigateway", ConfigKey: "apigateway", SigningName: "apigateway", Scopes: []string{"apigateway", "execute-api"}, Default: protoRestJSON},
	{Key: "iam", ConfigKey: "iam", SigningName: "iam", Scopes: []string{"iam"}, Default: protoQuery},
	{Key: "sts", ConfigKey: "iam", SigningName: "sts", Scopes: []string{"sts"}, Default: protoQuery},
	{Key: "events", ConfigKey: "eventbridge", SigningName: "events", Scopes: []string{"events"}, Targets: []string{"AWSEvents."}, Default: protoJSON},
	{Key: "eventsv2", ConfigKey: "eventbridgev2", SigningName: "events", CBORIDs: []string{"AWSEventsV2"}, Default: protoCBOR},
	{Key: "logs", ConfigKey: "cloudwatchlogs", SigningName: "logs", Scopes: []string{"logs"}, Targets: []string{"Logs_20140328."}, Default: protoJSON},
	{Key: "secretsmanager", ConfigKey: "secretsmanager", SigningName: "secretsmanager", Scopes: []string{"secretsmanager"}, Targets: []string{"secretsmanager."}, Default: protoJSON},
	{Key: "apigatewayv2", ConfigKey: "apigatewayv2", SigningName: "apigateway", Targets: []string{"AmazonApiGatewayV2."}, Default: protoJSON},
	{Key: "kinesis", ConfigKey: "kinesis", SigningName: "kinesis", Scopes: []string{"kinesis"}, Targets: []string{"Kinesis_20131202."}, Default: protoJSON},
	{Key: "kms", ConfigKey: "kms", SigningName: "kms", Scopes: []string{"kms"}, Targets: []string{"TrentService."}, Default: protoJSON},
	{Key: "cognito-idp", ConfigKey: "cognito", SigningName: "cognito-idp", Scopes: []string{"cognito-idp"}, Targets: []string{"AWSCognitoIdentityProviderService."}, Default: protoRestJSON},
	{Key: "states", ConfigKey: "stepfunctions", SigningName: "states", Scopes: []string{"states"}, Targets: []string{"AWSStepFunctions."}, CBORIDs: []string{"SFN"}, Default: protoJSON},
	{Key: "sagemaker", ConfigKey: "sagemaker", SigningName: "sagemaker", Scopes: []string{"sagemaker", "runtime.sagemaker"}, Targets: []string{"SageMaker."}, Default: protoJSON},
}

// healthKeys are the services the fork's health lists (everything but sts), in order.
func healthServices() []*service {
	var out []*service
	for _, s := range catalog {
		if s.Key != "sts" {
			out = append(out, s)
		}
	}
	return out
}

var (
	byKey      = map[string]*service{}
	byScope    = map[string]*service{}
	byCBORID   = map[string]*service{}
	targetList []targetEntry
)

type targetEntry struct {
	prefix string
	svc    *service
}

func init() {
	for _, s := range catalog {
		byKey[s.Key] = s
		for _, sc := range s.Scopes {
			byScope[sc] = s
		}
		for _, id := range s.CBORIDs {
			byCBORID[id] = s
		}
		for _, t := range s.Targets {
			targetList = append(targetList, targetEntry{t, s})
		}
	}
	// longest prefix first so DynamoDBStreams_ never loses to a shorter one
	sort.Slice(targetList, func(i, j int) bool { return len(targetList[i].prefix) > len(targetList[j].prefix) })
}

// scopeService maps a SigV4 credential scope name to a service (the fork's byCredentialScope).
func scopeService(name string) *service {
	if name == "execute-api" {
		return byKey["apigateway"]
	}
	return byScope[name]
}

// queryServices are the services that speak the Query protocol; Version tells them apart when no scope does.
var queryVersions = map[string]string{
	"2012-11-05": "sqs",
	"2010-03-31": "sns",
	"2010-05-08": "iam",
	"2011-06-15": "sts",
}

// ---- identification

// identified is what the front knows about one API request before it is forwarded.
type identified struct {
	Service   *service // nil: not a service of the catalog
	Operation string   // bounded: at most maxOperationChars
	Proto     proto
	Region    string // from the SigV4 scope, else ""
	HasAuth   bool   // the request carries a SigV4 credential (header or query)
	// Reason is set when the front itself refuses the request without asking the engine.
	Reason refuseReason
	Target string // the X-Amz-Target as sent, for the "unknown operation" message
}

type refuseReason int

const (
	notRefused refuseReason = iota
	refuseUnknownTarget
	refuseUnknownScope
)

const maxOperationChars = 80

var credentialRe = regexp.MustCompile(`Credential=([^,\s]+)`)

// scopeFromCredential parses "<key>/<date>/<region>/<service>/aws4_request"; ok is false for any other shape.
func scopeFromCredential(cred string) (svc, region string, ok bool) {
	parts := strings.Split(cred, "/")
	if len(parts) < 5 || parts[len(parts)-1] != "aws4_request" {
		return "", "", false
	}
	return strings.ToLower(parts[len(parts)-2]), parts[len(parts)-3], true
}

// requestScope reads the SigV4 scope from the Authorization header, else from X-Amz-Credential in the query.
func requestScope(h http.Header, q url.Values) (svc, region string, ok bool) {
	if auth := h.Get("Authorization"); auth != "" {
		if m := credentialRe.FindStringSubmatch(auth); m != nil {
			if s, r, ok := scopeFromCredential(m[1]); ok {
				return s, r, true
			}
		}
	}
	if c := q.Get("X-Amz-Credential"); c != "" {
		return scopeFromCredential(c)
	}
	return "", "", false
}

var cborPath = regexp.MustCompile(`^/service/([^/]+)/operation/([^/]+)$`)

// identify works out the service and the operation of an API request from the request alone (never from an object's
// body): rpc-v2-cbor path, X-Amz-Target, Query Action, then the SigV4 scope, with S3 as the sink for the rest.
// action and version come from the query string or a small form body; the caller reads them.
func identify(method, path string, h http.Header, q url.Values, action, version string) identified {
	id := identified{Proto: protoRestXML}
	scopeName, region, hasScope := requestScope(h, q)
	id.Region, id.HasAuth = region, hasScope
	finish := func(op string) identified {
		if len(op) > maxOperationChars {
			op = op[:maxOperationChars]
		}
		id.Operation = op
		return id
	}
	unknown := func(reason refuseReason, p proto) identified {
		id.Service, id.Reason, id.Proto = nil, reason, p
		return finish("unknown")
	}
	// rpc-v2-cbor: /service/<SdkServiceId>/operation/<Operation>
	if strings.EqualFold(h.Get("smithy-protocol"), "rpc-v2-cbor") {
		m := cborPath.FindStringSubmatch(path)
		if m == nil {
			return unknown(refuseUnknownTarget, protoCBOR)
		}
		svc := byCBORID[m[1]]
		if svc == nil {
			return unknown(refuseUnknownTarget, protoCBOR)
		}
		id.Service, id.Proto = svc, protoCBOR
		return finish(m[2])
	}
	if target := h.Get("X-Amz-Target"); target != "" {
		id.Target = target
		for _, t := range targetList {
			if strings.HasPrefix(target, t.prefix) {
				id.Service, id.Proto = t.svc, protoJSON
				return finish(target[len(t.prefix):])
			}
		}
		return unknown(refuseUnknownTarget, protoJSON)
	}
	if action != "" {
		id.Proto = protoQuery
		var svc *service
		if hasScope {
			if s := scopeService(scopeName); s != nil && s.Default == protoQuery {
				svc = s
			}
		}
		if svc == nil {
			if k, ok := queryVersions[version]; ok {
				svc = byKey[k]
			} else {
				svc = byKey["sqs"] // a name no service defines goes to SQS (the fork's rule)
			}
		}
		id.Service = svc
		return finish(action)
	}
	// REST: the SigV4 scope names the service; with none, S3 is the sink for everything.
	if hasScope {
		svc := scopeService(scopeName)
		if svc == nil {
			return unknown(refuseUnknownScope, protoRestJSON)
		}
		id.Service, id.Proto = svc, svc.Default
	} else {
		id.Service, id.Proto = byKey["s3"], protoRestXML
	}
	if id.Service.Key == "s3" {
		return finish(s3OperationName(method, path, q, h.Get("x-amz-copy-source") != ""))
	}
	p := path
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return finish(method + " " + p)
}

// wantsFormBody: a POST whose form body may carry Action and Version (a small body is read; see the proxy).
func wantsFormBody(method string, h http.Header) bool {
	if method != http.MethodPost || h.Get("X-Amz-Target") != "" {
		return false
	}
	return strings.HasPrefix(strings.ToLower(h.Get("Content-Type")), "application/x-www-form-urlencoded")
}
