package main

import (
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode"
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
	AccessKey string // likewise
	Date      string // likewise
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
	refuseMismatch // the SigV4 scope names one service and the target, Action or CBOR path another
	refuseAmbiguous
)

const maxOperationChars = 80

// ---- the SigV4 scope, read exactly as the engine reads it
//
// The engine routes by the service in the SigV4 credential scope: first the Authorization header, but ONLY when it starts with
// "AWS4-HMAC-SHA256 " and is followed by "Credential=<key>/<date>/<region>/<service>/aws4_request" (exactly five fields, the first
// four not empty, anything after the first comma ignored); else the first query parameter named exactly X-Amz-Credential (the
// raw name, %2F or %2f decoded in the value, the fifth field aws4_request); else X-Amz-Target; else the Host. The front reads the
// scope with the same rules, so the service it decides on is the service the engine would route to, and it refuses every
// request whose signals disagree, because the engine would take one of them and the front another.

type sigScope struct {
	Service   string // lower case, trimmed: what the engine routes by
	Region    string
	AccessKey string
	Date      string
}

func parseCredential(cred string, exactFive bool) (*sigScope, bool) {
	f := strings.Split(cred, "/")
	if len(f) < 5 || (exactFive && len(f) != 5) || f[4] != "aws4_request" || f[0] == "" || f[1] == "" || f[2] == "" || strings.TrimSpace(f[3]) == "" {
		return nil, false
	}
	return &sigScope{Service: strings.ToLower(strings.TrimSpace(f[3])), Region: f[2], AccessKey: f[0], Date: f[1]}, true
}

// headerScope: the engine's rule for the Authorization header.
func headerScope(h http.Header) (*sigScope, bool) {
	auth := h.Get("Authorization")
	rest, ok := strings.CutPrefix(auth, "AWS4-HMAC-SHA256 ")
	if !ok {
		return nil, false
	}
	rest, ok = strings.CutPrefix(strings.TrimLeftFunc(rest, unicode.IsSpace), "Credential=")
	if !ok {
		return nil, false
	}
	cred, _, _ := strings.Cut(rest, ",")
	return parseCredential(strings.TrimSpace(cred), true)
}

// queryScope: the engine's rule for the query string: the FIRST parameter named exactly X-Amz-Credential (raw name). present
// says whether any parameter has that name; conflict says that two of them differ.
func queryScope(rawQuery string) (scope *sigScope, present, conflict bool) {
	first := ""
	for _, pair := range strings.Split(rawQuery, "&") {
		k, v, found := strings.Cut(pair, "=")
		if !found || k != "X-Amz-Credential" {
			continue
		}
		if !present {
			first, present = v, true
		} else if v != first {
			conflict = true
		}
	}
	if !present {
		return nil, false, false
	}
	scope, _ = parseCredential(strings.ReplaceAll(strings.ReplaceAll(first, "%2F", "/"), "%2f", "/"), false)
	return scope, true, conflict
}

// requestScope is the scope the engine would use. problem says the signals disagree or are ambiguous (refuse): the header and
// the query name different services, an Authorization header that gives no scope comes with an X-Amz-Credential query, or the
// query has two different X-Amz-Credential parameters.
func requestScope(h http.Header, rawQuery string) (scope *sigScope, problem bool) {
	hs, hok := headerScope(h)
	qs, qpresent, qconflict := queryScope(rawQuery)
	if qconflict {
		return hs, true
	}
	if h.Get("Authorization") != "" && !hok && qpresent {
		return hs, true
	}
	if hok && qs != nil && hs.Service != qs.Service {
		return hs, true
	}
	if hok {
		return hs, false
	}
	return qs, false
}

var cborPath = regexp.MustCompile(`^/service/([^/]+)/operation/([^/]+)$`)

// signsAs: two catalog entries are the same service for a SigV4 scope when they sign under the same name (API Gateway v2
// signs as apigateway, EventBridge v2 as events).
func signsAs(a, b *service) bool { return a == b || a.SigningName == b.SigningName }

// identify works out the service and the operation of an API request from the request alone (never from an object's body).
//
// The SigV4 credential scope is the source of truth when there is one (the engine routes by it too): a scope that is not in
// the catalog is refused, and so is a target, Action or CBOR path that names a different service than the scope (a request
// signed for S3 that says Action=CreateVpc is not an S3 request and not an EC2 one). Only with NO scope at all are the
// X-Amz-Target prefix, the Query Action with its Version, and the CBOR path used, and S3 is the sink for a plain REST call;
// an Action whose Version names no service is refused, never guessed.
// action and version come from the query string or a small form body; the caller reads them.
func identify(method, path string, h http.Header, rawQuery string, action, version string) identified {
	id := identified{Proto: protoRestXML}
	scope, problem := requestScope(h, rawQuery)
	hasScope := scope != nil
	if hasScope {
		id.Region, id.AccessKey, id.Date = scope.Region, scope.AccessKey, scope.Date
	}
	id.HasAuth = hasScope
	q, _ := url.ParseQuery(rawQuery)
	finish := func(op string) identified {
		if len(op) > maxOperationChars {
			op = op[:maxOperationChars]
		}
		id.Operation = op
		return id
	}
	refuse := func(reason refuseReason, svc *service, p proto) identified {
		id.Service, id.Reason, id.Proto = svc, reason, p
		return finish("unknown")
	}
	var scopeSvc *service
	if hasScope {
		scopeSvc = scopeService(scope.Service)
	}
	if problem {
		// the signals disagree: refused, counted under the service the winning scope names when the catalog has it
		return refuse(refuseMismatch, scopeSvc, protoRestJSON)
	}
	if hasScope && scopeSvc == nil {
		return refuse(refuseUnknownScope, nil, protoRestJSON)
	}
	// what the request itself says (target, CBOR path or Action)
	var implied *service
	op := ""
	switch {
	case strings.EqualFold(h.Get("smithy-protocol"), "rpc-v2-cbor"):
		id.Proto = protoCBOR
		m := cborPath.FindStringSubmatch(path)
		if m == nil || byCBORID[m[1]] == nil {
			return refuse(refuseUnknownTarget, nil, protoCBOR)
		}
		implied, op = byCBORID[m[1]], m[2]
	case h.Get("X-Amz-Target") != "":
		target := h.Get("X-Amz-Target")
		id.Target, id.Proto = target, protoJSON
		for _, t := range targetList {
			if strings.HasPrefix(target, t.prefix) {
				implied, op = t.svc, target[len(t.prefix):]
				break
			}
		}
		if implied == nil {
			return refuse(refuseUnknownTarget, nil, protoJSON)
		}
	case action != "":
		id.Proto = protoQuery
		op = action
		switch {
		case scopeSvc != nil && scopeSvc.Default == protoQuery:
			implied = scopeSvc
		case scopeSvc != nil:
			// a Query action on a service that does not speak Query (Action=x on an S3 or Lambda call)
			return refuse(refuseMismatch, scopeSvc, protoQuery)
		default:
			k, ok := queryVersions[version]
			if !ok {
				return refuse(refuseAmbiguous, nil, protoQuery)
			}
			implied = byKey[k]
		}
	}
	switch {
	case implied != nil:
		if scopeSvc != nil && !signsAs(implied, scopeSvc) {
			return refuse(refuseMismatch, scopeSvc, id.Proto)
		}
		id.Service = implied
		return finish(op)
	case scopeSvc != nil:
		id.Service, id.Proto = scopeSvc, scopeSvc.Default
	default:
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
