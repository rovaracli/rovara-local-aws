package main

import (
	"encoding/json"
	"sort"
	"strings"
	"sync"
)

// Services that make calls to other services INSIDE the engine. A request for such a call never passes the front, so the plan cannot
// gate it; the front records it instead, as it does for CloudFormation (cfn.go): at the moment a planned service is told which other
// service to call, it reads that out of the request and counts one outOfPlan call under each service the plan does not name, with the
// operation `<source>:<service>:<action>`. What it cannot read or place is counted under the service `targets-unchecked`, with the
// same operation naming. Nothing is blocked.
//
//	Step Functions    CreateStateMachine, UpdateStateMachine: every Task `Resource` of the definition (JSON, including the JSONata
//	                  query language, which keeps the same members): arn:aws:states:::<service>:<action>[.sync|.waitForTaskToken],
//	                  arn:aws:states:::aws-sdk:<service>:<action>, and a Lambda function ARN (service lambda); source `stepfunctions`
//	EventBridge       PutTargets: each Target Arn, by the service in the ARN; source `eventbridge`
//	Scheduler         CreateSchedule, UpdateSchedule: Target.Arn and DeadLetterConfig.Arn, and the universal target
//	                  arn:aws:scheduler:::aws-sdk:<service>:<action>; source `scheduler`
//	Pipes             CreatePipe, UpdatePipe: Source, Enrichment and Target ARNs; source `pipes`
//	SSM Automation    CreateDocument, UpdateDocument: the steps that call another service (aws:executeAwsApi and its relatives, with the
//	                  Service and Api inputs); source `ssm`
//	seed              the targets of a seeded EventBridge rule
// A Lambda function's own code can also call services in the engine; that cannot be read from outside and is not recorded here.

const targetsUncheckedService = "targets-unchecked"

// outside: the call is a delivery to an address outside the engine (an EventBridge API destination), recorded whatever the plan names.
type targetRef struct {
	svc, action string
	outside     bool
}

// targetHooks: the operations whose requests are read, by service key.
var targetHooks = map[string]map[string]func(body []byte) ([]targetRef, string){
	"sfn":               {"CreateStateMachine": sfnRequestTargets, "UpdateStateMachine": sfnRequestTargets},
	"eventbridge":       {"PutTargets": ebRequestTargets},
	"cloudwatch-events": {"PutTargets": ebRequestTargets},
	"scheduler":         {"CreateSchedule": scheduleRequestTargets, "UpdateSchedule": scheduleRequestTargets},
	"pipes":             {"CreatePipe": pipeRequestTargets, "UpdatePipe": pipeRequestTargets},
	"ssm":               {"CreateDocument": ssmRequestTargets, "UpdateDocument": ssmRequestTargets},
}

var targetSource = map[string]string{"sfn": "stepfunctions", "eventbridge": "eventbridge", "cloudwatch-events": "eventbridge", "scheduler": "scheduler",
	"pipes": "pipes", "ssm": "ssm"}

const targetBodyCap = 2 << 20

// ---- service names

var (
	aliasOnce   sync.Once
	aliasToKeys map[string][]*tsvc
	// names that more than one service answers to, or that are not the table's: the service a planned name stands for
	aliasPreferred = map[string]string{"events": "eventbridge", "eventbridge": "eventbridge", "states": "sfn", "stepfunctions": "sfn", "sfn": "sfn",
		"logs": "cloudwatch-logs", "cloudwatchlogs": "cloudwatch-logs", "secretsmanager": "secrets-manager", "cognitoidp": "cognito-identity-provider",
		"cognitoidentityprovider": "cognito-identity-provider", "es": "opensearch", "elasticloadbalancing": "elastic-load-balancing-v2",
		"elasticloadbalancingv2": "elastic-load-balancing-v2", "kinesisfirehose": "firehose", "lambda": "lambda", "cognito": "cognito-identity-provider",
		"ses": "ses", "sesv2": "sesv2", "ssm": "ssm"}
)

func buildAliases() {
	aliasToKeys = map[string][]*tsvc{}
	add := func(k string, t *tsvc) {
		k = nonAlnum.ReplaceAllString(strings.ToLower(k), "")
		if k == "" {
			return
		}
		for _, e := range aliasToKeys[k] {
			if e == t {
				return
			}
		}
		aliasToKeys[k] = append(aliasToKeys[k], t)
	}
	for i := range genRows {
		r := &genRows[i]
		t := tableByKey[r.Key]
		add(r.Key, t)
		add(r.SDKID, t)
		add(r.CFN, t)
		add(r.Endpoint, t)
	}
	for legacy, key := range genLegacy {
		add(legacy, tableByKey[key])
	}
	for _, v := range aliasToKeys {
		sort.Slice(v, func(i, j int) bool { return v[i].row.Key < v[j].row.Key })
	}
}

// servicesNamed: the table services a service name (an SDK id, an ARN service, a short name) stands for.
func servicesNamed(name string) []*tsvc {
	aliasOnce.Do(buildAliases)
	n := nonAlnum.ReplaceAllString(strings.ToLower(name), "")
	if key, ok := aliasPreferred[n]; ok {
		if t := tableByKey[key]; t != nil {
			return []*tsvc{t}
		}
	}
	return aliasToKeys[n]
}

// recordTargets writes what a request will make the engine call: each service the plan does not name once per distinct operation.
func (s *Server) recordTargets(source string, refs []targetRef, unchecked string) {
	seen := map[string]bool{}
	for _, ref := range refs {
		op := source + ":" + ref.svc + ":" + ref.action
		if seen[op] {
			continue
		}
		seen[op] = true
		if ref.outside {
			// reaches nothing today (the engine makes no outside call), but it is a delivery the code asked for
			s.ledger.recordOutOfPlan(servicesNamed("eventbridge")[0].row.Key, op)
			continue
		}
		owners := servicesNamed(ref.svc)
		if len(owners) == 0 {
			s.ledger.recordOutOfPlan(targetsUncheckedService, op)
			continue
		}
		in := false
		for _, o := range owners {
			if s.cfg.Planned[o.row.Key] {
				in = true
			}
		}
		if !in {
			s.ledger.recordOutOfPlan(owners[0].row.Key, op)
		}
	}
	if unchecked != "" {
		s.ledger.recordOutOfPlan(targetsUncheckedService, source+":"+unchecked)
	}
}

// ---- ARNs and resources

// isDynamic: a value that is computed (a JSONata expression, a JSONPath, an unresolved substitution), so the service is not known.
func isDynamic(s string) bool {
	return strings.Contains(s, "{%") || strings.Contains(s, "${") || strings.HasPrefix(s, "$.") || strings.HasPrefix(s, "$$") || strings.HasPrefix(s, "$[")
}

func trimIntegration(a string) string {
	if i := strings.Index(a, "."); i >= 0 { // <action>.sync, .sync:2, .waitForTaskToken: the engine cuts at the first dot
		a = a[:i]
	}
	return a
}

// arnFields splits an ARN the way the engine does (splitn 6 on ':'): arn, partition, service, region, account, resource. ok is false when it
// has no six fields or does not start with "arn" in any case.
func arnFields(s string) (partition, service, region, account, rest string, ok bool) {
	f := strings.SplitN(s, ":", 6)
	if len(f) != 6 || !strings.EqualFold(f[0], "arn") {
		return "", "", "", "", "", false
	}
	return f[1], f[2], f[3], f[4], f[5], true
}

// awsSDKRest reads "aws-sdk:<service>:<action>" (the segment in any case: the engine reads it case-sensitively, but a reader that
// does not is covered), or "" when rest is not that.
func awsSDKRest(rest string) (svc, action string, isSDK, wellFormed bool) {
	head, tail, found := strings.Cut(rest, ":")
	if !found || !strings.EqualFold(head, "aws-sdk") {
		return "", "", false, true
	}
	svc, action, found = strings.Cut(tail, ":")
	if !found || svc == "" || action == "" {
		return "", "", true, false
	}
	return svc, trimIntegration(action), true, true
}

// resourceTargets classifies a Step Functions Task Resource, reading it by the fields the engine reads: any partition, region and
// account; the service field "states" for an integration (aws-sdk:<svc>:<action> or <svc>:<action>), or "lambda" for a function.
// A Resource that names states, or lambda, in a spelling the engine would not read, or that has the shape of an integration and cannot be
// read, is unchecked ("resource"), never skipped.
func resourceTargets(res string) (refs []targetRef, unchecked string) {
	res = strings.TrimSpace(res)
	if isDynamic(res) {
		return nil, "dynamic"
	}
	_, svc, _, _, rest, ok := arnFields(res)
	if !ok {
		if strings.Contains(strings.ToLower(res), ":states:") || strings.HasPrefix(strings.ToLower(res), "arn") {
			return nil, "resource" // looks like an ARN and does not split into six fields
		}
		return nil, "" // not an ARN: the engine runs nothing for it
	}
	exact := strings.HasPrefix(res, "arn:")
	switch {
	case strings.EqualFold(svc, "lambda"):
		return []targetRef{{svc: "lambda", action: "invoke"}}, ""
	case !strings.EqualFold(svc, "states"):
		return nil, "" // another vendor's resource: not run
	}
	if !exact || svc != "states" {
		unchecked = "resource" // the engine would not read it, a looser reader might
	}
	if sdkSvc, action, isSDK, well := awsSDKRest(rest); isSDK {
		if !well {
			return nil, "resource"
		}
		if !strings.HasPrefix(rest, "aws-sdk:") {
			unchecked = "resource"
		}
		return []targetRef{{svc: sdkSvc, action: action}}, unchecked
	}
	kind, action, found := strings.Cut(rest, ":")
	switch {
	case !found || kind == "" || action == "":
		return nil, "resource"
	case kind == "activity" || kind == "http" || kind == "stateMachine" || kind == "execution":
		return nil, unchecked // an activity, an HTTP task, a state machine or execution ARN: no service of the engine
	}
	return []targetRef{{svc: kind, action: trimIntegration(action)}}, unchecked
}

// arnTargets classifies an ARN a planned service is told to deliver to (an EventBridge or Scheduler target, a Pipe's source,
// enrichment or target): the service field of the ARN; the Scheduler universal target (arn:*:scheduler:*:*:aws-sdk:<svc>:<action>, the
// segment in any case) as the service and action it names; an API destination as an outside delivery. A string that is not an ARN, or a
// universal target that cannot be read, is unchecked.
func arnTargets(arn string) (refs []targetRef, unchecked string) {
	arn = strings.TrimSpace(arn)
	if arn == "" {
		return nil, ""
	}
	if isDynamic(arn) {
		return nil, "dynamic"
	}
	_, svc, _, _, rest, ok := arnFields(arn)
	if !ok || svc == "" {
		return nil, "arn"
	}
	switch strings.ToLower(svc) {
	case "scheduler":
		sdkSvc, action, isSDK, well := awsSDKRest(rest)
		if !isSDK || !well {
			return nil, "arn"
		}
		return []targetRef{{svc: sdkSvc, action: action}}, ""
	case "events":
		if strings.HasPrefix(strings.ToLower(rest), "api-destination/") {
			return []targetRef{{svc: "events", action: "api-destination", outside: true}}, ""
		}
	}
	return []targetRef{{svc: svc, action: "target"}}, ""
}

// ---- Step Functions

const maxWalkNodes = 400000

// walkJSON visits every map entry of a decoded JSON document; false when the document is deeper or larger than the bounds.
func walkJSON(v any, visit func(key string, val any)) bool {
	nodes := 0
	var walk func(v any, depth int) bool
	walk = func(v any, depth int) bool {
		nodes++
		if depth > 120 || nodes > maxWalkNodes {
			return false
		}
		switch t := v.(type) {
		case map[string]any:
			for k, x := range t {
				visit(k, x)
				if !walk(x, depth+1) {
					return false
				}
			}
		case []any:
			for _, x := range t {
				if !walk(x, depth+1) {
					return false
				}
			}
		}
		return true
	}
	return walk(v, 0)
}

// aslTargets reads a state machine definition: a JSON document in a string, or already decoded. Anything else (an intrinsic function
// that is not a literal join, a parameter) is unchecked ("intrinsic").
func aslTargets(def any) (refs []targetRef, unchecked string) {
	switch t := def.(type) {
	case string:
		var d any
		if json.Unmarshal([]byte(t), &d) != nil {
			return nil, "unreadable"
		}
		def = d
	case map[string]any:
		if len(t) == 1 {
			for k, v := range t {
				if strings.HasPrefix(k, "Fn::") || k == "Ref" {
					return aslFromIntrinsic(k, v)
				}
			}
		}
	}
	reasons := map[string]bool{}
	if !walkJSON(def, func(k string, v any) {
		if k == "Resource.$" {
			reasons["dynamic"] = true
			return
		}
		if k != "Resource" {
			return
		}
		str, ok := v.(string)
		if !ok {
			reasons["dynamic"] = true
			return
		}
		r, u := resourceTargets(str)
		refs = append(refs, r...)
		if u != "" {
			reasons[u] = true
		}
	}) {
		return refs, "unreadable"
	}
	return refs, firstReason(reasons)
}

// firstReason: the most telling of the unchecked reasons (alphabetical, so a run records the same marker every time).
func firstReason(m map[string]bool) string {
	best := ""
	for r := range m {
		if best == "" || r < best {
			best = r
		}
	}
	return best
}

// aslFromIntrinsic reads a definition written with an intrinsic function: Fn::Join over literal parts is joined and read, Fn::Sub with a
// string (or the list form's string) is read as text and any ${...} left in a Resource is dynamic; everything else is unchecked.
func aslFromIntrinsic(fn string, v any) ([]targetRef, string) {
	switch fn {
	case "Fn::Join":
		args, _ := v.([]any)
		if len(args) == 2 {
			delim, _ := args[0].(string)
			parts, _ := args[1].([]any)
			var b strings.Builder
			for i, p := range parts {
				str, ok := p.(string)
				if !ok {
					return nil, "intrinsic"
				}
				if i > 0 {
					b.WriteString(delim)
				}
				b.WriteString(str)
			}
			if len(parts) > 0 {
				return aslTargets(b.String())
			}
		}
	case "Fn::Sub":
		switch t := v.(type) {
		case string:
			return aslTargets(t)
		case []any:
			if len(t) > 0 {
				if str, ok := t[0].(string); ok {
					return aslTargets(str)
				}
			}
		}
	}
	return nil, "intrinsic"
}

func sfnRequestTargets(body []byte) ([]targetRef, string) {
	var req struct {
		Definition any `json:"definition"`
	}
	if json.Unmarshal(body, &req) != nil {
		return nil, "unreadable"
	}
	if req.Definition == nil {
		return nil, "" // an update of the role or logging only
	}
	return aslTargets(req.Definition)
}

// ---- EventBridge, Scheduler, Pipes

func ebRequestTargets(body []byte) ([]targetRef, string) {
	var req struct {
		Targets []struct {
			Arn string `json:"Arn"`
		} `json:"Targets"`
	}
	if json.Unmarshal(body, &req) != nil {
		return nil, "unreadable"
	}
	return arnList(func(add func(string)) {
		for _, t := range req.Targets {
			add(t.Arn)
		}
	})
}

// arnList classifies the ARNs a request carries.
func arnList(each func(add func(string))) ([]targetRef, string) {
	var refs []targetRef
	reasons := map[string]bool{}
	each(func(arn string) {
		r, u := arnTargets(arn)
		refs = append(refs, r...)
		if u != "" {
			reasons[u] = true
		}
	})
	return refs, firstReason(reasons)
}

func scheduleRequestTargets(body []byte) ([]targetRef, string) {
	var req struct {
		Target struct {
			Arn              string
			DeadLetterConfig *struct{ Arn string }
		}
		DeadLetterConfig *struct{ Arn string }
	}
	if json.Unmarshal(body, &req) != nil {
		return nil, "unreadable"
	}
	return arnList(func(add func(string)) {
		add(req.Target.Arn)
		if req.Target.DeadLetterConfig != nil { // the dead-letter queue is a member of the target
			add(req.Target.DeadLetterConfig.Arn)
		}
		if req.DeadLetterConfig != nil {
			add(req.DeadLetterConfig.Arn)
		}
	})
}

func pipeRequestTargets(body []byte) ([]targetRef, string) {
	var req struct{ Source, Enrichment, Target string }
	if json.Unmarshal(body, &req) != nil {
		return nil, "unreadable"
	}
	return arnList(func(add func(string)) {
		add(req.Source)
		add(req.Enrichment)
		add(req.Target)
	})
}

// ---- SSM Automation

var automationServiceOf = map[string]string{"aws:invokeLambdaFunction": "lambda", "aws:createStack": "cloudformation", "aws:deleteStack": "cloudformation",
	"aws:executeStateMachine": "sfn", "aws:runCommand": "ssm", "aws:invokeWebhook": ""}

func ssmRequestTargets(body []byte) ([]targetRef, string) {
	var req struct{ Content string }
	if json.Unmarshal(body, &req) != nil {
		return nil, "unreadable"
	}
	if req.Content == "" {
		return nil, ""
	}
	var doc any
	if t := strings.TrimSpace(req.Content); strings.HasPrefix(t, "{") {
		if json.Unmarshal([]byte(t), &doc) != nil {
			return nil, "unreadable"
		}
	} else {
		var err error
		if doc, err = parseYAMLish(req.Content); err != nil {
			return nil, "unreadable"
		}
	}
	root, _ := doc.(map[string]any)
	steps, _ := root["mainSteps"].([]any)
	if len(steps) == 0 {
		return nil, ""
	}
	var refs []targetRef
	unchecked := ""
	for _, st := range steps {
		m, _ := st.(map[string]any)
		action, _ := m["action"].(string)
		inputs, _ := m["inputs"].(map[string]any)
		svc, api := "", ""
		if v, ok := inputs["Service"].(string); ok {
			svc = v
		} else if v, ok := inputs["service"].(string); ok {
			svc = v
		}
		if v, ok := inputs["Api"].(string); ok {
			api = v
		} else if v, ok := inputs["api"].(string); ok {
			api = v
		}
		switch {
		case svc != "":
			if strings.Contains(svc, "{{") {
				unchecked = "dynamic"
			} else {
				if api == "" {
					api = "api"
				}
				refs = append(refs, targetRef{svc: svc, action: api})
			}
		case automationServiceOf[action] != "":
			refs = append(refs, targetRef{svc: automationServiceOf[action], action: strings.TrimPrefix(action, "aws:")})
		case action == "aws:executeScript" || action == "aws:executeAutomation":
			unchecked = "script" // runs code, or another document, whose calls cannot be read here
		case strings.HasPrefix(action, "aws:executeAwsApi") || strings.HasPrefix(action, "aws:waitForAwsResourceProperty") || strings.HasPrefix(action, "aws:assertAwsResourceProperty"):
			unchecked = "dynamic" // an API step with no readable Service
		}
	}
	return refs, unchecked
}

// ---- the hook in the request path

// targetHook returns the reader for an operation of a planned service, or nil.
func targetHook(serviceKey, op string) func([]byte) ([]targetRef, string) {
	if h := targetHooks[serviceKey]; h != nil {
		return h[op]
	}
	return nil
}
