package main

import (
	"encoding/xml"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// CloudFormation-declared SageMaker endpoints. The engine's CloudFormation reaches CREATE_COMPLETE for AWS::SageMaker::Model,
// EndpointConfig and Endpoint and creates none of them, so the front reads the template as a document (like every other template
// it reads), resolves the names and the async configuration it can, and when the engine accepted the stack creates the three through
// the engine's API (if the plan names `sagemaker`) and in the endpoint table. A stack made through a change set is held until
// ExecuteChangeSet.
//
// What is resolved: literal strings; Ref to a parameter (the request's value, else its Default) and to AWS::StackName, AWS::Region and
// AWS::AccountId; Ref to an S3 bucket or an SNS topic that has a literal name (a bucket's name, a topic's ARN); GetAtt of a SageMaker
// resource's name (EndpointName, EndpointConfigName, ModelName) and an SNS topic's TopicName and TopicArn; Fn::Sub over those; Fn::Join
// over those. Anything else is not guessed: a resource with no readable name is not created and is recorded as unsupported
// (`cloudformation:<reason>` under sagemaker-runtime, the logical id as detail), an async config with a value that cannot be read is
// left out and recorded the same way.

const smMaxPendingChangeSets = 100

var smPhysicalWait = 5 * time.Second

type smTemplate struct {
	stack  string
	region string
	params map[string]string
	res    map[string]map[string]any // logical id -> the resource
	// physical: the physical ids the engine gave the stack's resources, for the ones the template does not name (CloudFormation makes
	// the name up: the engine's is <stack>-<LogicalId>-<12 hex>, and that is what the stack's outputs and Ref and GetAtt answers carry)
	physical map[string]string
	// visiting holds the logical ids being resolved right now: a template that refers to itself (a bucket named by a Ref to itself, a model
	// named by a GetAtt of its own name) is a cycle, which is unresolved, never followed. cycle says one was met.
	visiting map[string]bool
	cycle    bool
	// The work one template may cost, however it is written (a value that refers to the same resource many times, many times over,
	// would otherwise be read once per reference): every resolved resource attribute is read at most once (memo), the whole template
	// gets a step budget and an output budget, and a value is never longer than smMaxValue. Past a budget everything not a literal is
	// unresolved and the template is recorded as cloudformation:unresolved.
	memo     map[string]smMemo
	steps    int
	out      int
	exceeded bool
	cached   []*smDecl // decls(), computed once
}

type smMemo struct {
	val    string
	ok     bool
	reason string
}

const (
	smMaxSteps    = 100000   // resolve calls and ${} substitutions per template
	smMaxValue    = 64 << 10 // the longest resolved value
	smMaxTotalOut = 4 << 20  // all the text the resolver builds for one template
)

// spend counts one step; false (and exceeded set) when the budget is gone.
func (t *smTemplate) spend() bool {
	if t.exceeded {
		return false
	}
	t.steps++
	if t.steps > smMaxSteps {
		t.exceeded = true
		return false
	}
	return true
}

// emit counts the text a value built; false (and exceeded set) when it is too long or the total is.
func (t *smTemplate) emit(n int) bool {
	if t.exceeded {
		return false
	}
	t.out += n
	if n > smMaxValue || t.out > smMaxTotalOut {
		t.exceeded = true
		return false
	}
	return true
}

// remember stores the result of resolving one resource attribute and returns it.
func (t *smTemplate) remember(key, val string, ok bool, reason string) (string, bool, string) {
	if t.memo == nil {
		t.memo = map[string]smMemo{}
	}
	t.memo[key] = smMemo{val, ok, reason}
	return val, ok, reason
}

// enter marks a logical id as being resolved; false (and cycle set) when it already is.
func (t *smTemplate) enter(logical string) bool {
	if t.visiting == nil {
		t.visiting = map[string]bool{}
	}
	if t.visiting[logical] {
		t.cycle = true
		return false
	}
	t.visiting[logical] = true
	return true
}

func (t *smTemplate) leave(logical string) { delete(t.visiting, logical) }

// smMaxResolveDepth bounds how deep one value is read (Fn::Join inside Fn::Sub inside a Ref chain ...).
const smMaxResolveDepth = 8

// newSMTemplate reads the template as a document; nil when it is not one.
func (s *Server) newSMTemplate(text string, form url.Values) *smTemplate {
	root, ok := parseTemplate(text)
	if !ok {
		return nil
	}
	res, _ := root["Resources"].(map[string]any)
	t := &smTemplate{stack: form.Get("StackName"), region: s.cfg.Region, params: map[string]string{}, res: map[string]map[string]any{}}
	for id, r := range res {
		if rm, ok := r.(map[string]any); ok {
			t.res[id] = rm
		}
	}
	if defs, ok := root["Parameters"].(map[string]any); ok {
		for k, v := range defs {
			if vm, ok := v.(map[string]any); ok {
				if d, ok := vm["Default"]; ok {
					t.params[k] = scalarText(d)
				}
			}
		}
	}
	for i := 1; i < 200; i++ { // Parameters.member.N.ParameterKey / ParameterValue
		k := form.Get("Parameters.member." + strconv.Itoa(i) + ".ParameterKey")
		if k == "" {
			break
		}
		if v, ok := form["Parameters.member."+strconv.Itoa(i)+".ParameterValue"]; ok && len(v) > 0 {
			t.params[k] = v[0]
		}
	}
	return t
}

// decls lists the SageMaker resources the template declares, resolved as far as they can be.
func (t *smTemplate) decls() []*smDecl {
	if t.cached != nil {
		return t.cached
	}
	t.cached = t.buildDecls()
	return t.cached
}

// redecls reads the declarations again once the engine's physical ids are known (the names of the resources the template does not name
// change what refers to them); the budget is the template's, not the pass's.
func (t *smTemplate) redecls() []*smDecl {
	t.memo = nil
	t.cached = t.buildDecls()
	return t.cached
}

func (t *smTemplate) buildDecls() []*smDecl {
	ids := make([]string, 0, len(t.res))
	for id := range t.res {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var decls []*smDecl
	for _, id := range ids {
		r := t.res[id]
		typ, _ := r["Type"].(string)
		props, _ := r["Properties"].(map[string]any)
		d := &smDecl{logical: id, source: "cloudformation"}
		switch typ {
		case "AWS::SageMaker::Model":
			d.kind = "model"
			d.name, d.reason = t.name(id, props, "ModelName", 0)
		case "AWS::SageMaker::EndpointConfig":
			d.kind = "config"
			d.name, d.reason = t.name(id, props, "EndpointConfigName", 0)
			vs, _ := props["ProductionVariants"].([]any)
			for _, v := range vs {
				vm, _ := v.(map[string]any)
				vn, ok1 := t.resolve(vm["VariantName"], 0)
				mn, ok2 := t.resolve(vm["ModelName"], 0)
				if !ok1 {
					vn = "AllTraffic"
				}
				if !ok2 {
					mn = ""
				}
				d.variants = append(d.variants, smVariant{Name: vn, Model: mn})
			}
			if raw, present := props["AsyncInferenceConfig"]; present {
				if api, ok := t.asyncConfig(raw); ok {
					d.asyncRaw, d.async = api, asyncFromAPI(api)
				} else {
					d.reason = "async-unresolved" // the config is still created, without its asynchronous part
				}
			}
		case "AWS::SageMaker::Endpoint":
			d.kind = "endpoint"
			d.name, d.reason = t.name(id, props, "EndpointName", 0)
			if c, ok := t.resolve(props["EndpointConfigName"], 0); ok {
				d.config = c
			}
		default:
			continue
		}
		if _, conditional := r["Condition"]; conditional && d.reason == "" {
			d.reason = "condition"
		}
		decls = append(decls, d)
	}
	return decls
}

func scalarText(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	}
	return ""
}

// name reads a resource's own name property; the reason is why it could not. A resource with no name property has the physical id
// the engine made up for it, when that is known.
func (t *smTemplate) name(logical string, props map[string]any, key string, depth int) (string, string) {
	v, present := props[key]
	if !present {
		if p := t.physical[logical]; p != "" && smEndpointNameRe.MatchString(p) {
			return p, ""
		}
		return "", "unnamed"
	}
	mk := "n:" + logical + "/" + key
	if m, hit := t.memo[mk]; hit {
		return m.val, m.reason
	}
	if depth == 0 {
		t.cycle = false
	}
	if !t.enter(logical) {
		return "", "cycle"
	}
	defer t.leave(logical)
	n, ok := t.resolve(v, depth+1)
	switch {
	case t.exceeded:
		// the answer depends on the budget, not on the template: not remembered, and nothing else is read either
		return "", "unresolved"
	case !ok || n == "":
		if t.cycle {
			v, _, r := t.remember(mk, "", false, "cycle")
			return v, r
		}
		v, _, r := t.remember(mk, "", false, "name-unresolved")
		return v, r
	}
	v2, _, r := t.remember(mk, n, true, "")
	return v2, r
}

// asyncConfig reads an AsyncInferenceConfig into the API's shape; ok is false when any value in it could not be read.
func (t *smTemplate) asyncConfig(raw any) (map[string]any, bool) {
	cfg, _ := raw.(map[string]any)
	out, _ := cfg["OutputConfig"].(map[string]any)
	if out == nil {
		return nil, false
	}
	oc := map[string]any{}
	for _, k := range []string{"S3OutputPath", "S3FailurePath"} {
		if v, present := out[k]; present {
			s, ok := t.resolve(v, 0)
			if !ok {
				return nil, false
			}
			oc[k] = s
		}
	}
	if nc, ok := out["NotificationConfig"].(map[string]any); ok {
		n := map[string]any{}
		for _, k := range []string{"SuccessTopic", "ErrorTopic"} {
			if v, present := nc[k]; present {
				s, ok := t.resolve(v, 0)
				if !ok {
					return nil, false
				}
				n[k] = s
			}
		}
		if inc, ok := nc["IncludeInferenceResponseIn"]; ok {
			n["IncludeInferenceResponseIn"] = inc
		}
		oc["NotificationConfig"] = n
	}
	return map[string]any{"OutputConfig": oc}, true
}

// resolve reads a value that must come out as one string.
func (t *smTemplate) resolve(v any, depth int) (string, bool) {
	if s, ok := v.(string); ok {
		return s, true
	}
	if depth > smMaxResolveDepth || !t.spend() {
		return "", false
	}
	switch x := v.(type) {
	case map[string]any:
		if len(x) != 1 {
			return "", false
		}
		for fn, arg := range x {
			switch fn {
			case "Ref":
				name, _ := arg.(string)
				return t.ref(name, depth)
			case "Fn::GetAtt":
				return t.getAtt(arg, depth)
			case "Fn::Join":
				a, _ := arg.([]any)
				if len(a) != 2 {
					return "", false
				}
				delim, ok := a[0].(string)
				items, ok2 := a[1].([]any)
				if !ok || !ok2 {
					return "", false
				}
				parts := make([]string, 0, len(items))
				size := 0
				for _, it := range items {
					p, ok := t.resolve(it, depth+1)
					if !ok {
						return "", false
					}
					parts = append(parts, p)
					if size += len(p) + len(delim); size > smMaxValue {
						t.exceeded = true
						return "", false
					}
				}
				joined := strings.Join(parts, delim)
				if !t.emit(len(joined)) {
					return "", false
				}
				return joined, true
			case "Fn::Sub":
				return t.sub(arg, depth)
			}
		}
	}
	return "", false
}

func (t *smTemplate) ref(name string, depth int) (string, bool) {
	switch name {
	case "AWS::StackName":
		return t.stack, t.stack != ""
	case "AWS::Region":
		return t.region, true
	case "AWS::AccountId":
		return smAccount, true
	}
	if v, ok := t.params[name]; ok {
		return v, true
	}
	r := t.res[name]
	props, _ := r["Properties"].(map[string]any)
	key := "r:" + name
	if m, hit := t.memo[key]; hit {
		return m.val, m.ok
	}
	switch r["Type"] {
	case "AWS::S3::Bucket", "AWS::SNS::Topic":
		if !t.enter(name) {
			return "", false
		}
		defer t.leave(name)
		var val string
		var ok bool
		if r["Type"] == "AWS::S3::Bucket" {
			val, ok = t.resolve(props["BucketName"], depth+1)
		} else if n, got := t.resolve(props["TopicName"], depth+1); got {
			val, ok = "arn:aws:sns:"+t.region+":"+smAccount+":"+n, true
		}
		if t.exceeded {
			return "", false
		}
		v, o, _ := t.remember(key, val, ok, "")
		return v, o
	}
	return "", false
}

func (t *smTemplate) getAtt(arg any, depth int) (string, bool) {
	var logical, attr string
	switch a := arg.(type) {
	case []any:
		if len(a) == 2 {
			logical, _ = a[0].(string)
			attr, _ = a[1].(string)
		}
	case string:
		logical, attr, _ = strings.Cut(a, ".")
	}
	r := t.res[logical]
	props, _ := r["Properties"].(map[string]any)
	switch {
	case r["Type"] == "AWS::SageMaker::Model" && attr == "ModelName":
		n, reason := t.name(logical, props, "ModelName", depth)
		return n, reason == ""
	case r["Type"] == "AWS::SageMaker::EndpointConfig" && attr == "EndpointConfigName":
		n, reason := t.name(logical, props, "EndpointConfigName", depth)
		return n, reason == ""
	case r["Type"] == "AWS::SageMaker::Endpoint" && attr == "EndpointName":
		n, reason := t.name(logical, props, "EndpointName", depth)
		return n, reason == ""
	case r["Type"] == "AWS::SNS::Topic" && attr == "TopicName":
		key := "a:" + logical + "/TopicName"
		if m, hit := t.memo[key]; hit {
			return m.val, m.ok
		}
		if !t.enter(logical) {
			return "", false
		}
		defer t.leave(logical)
		val, ok := t.resolve(props["TopicName"], depth+1)
		if t.exceeded {
			return "", false
		}
		v, o, _ := t.remember(key, val, ok, "")
		return v, o
	case r["Type"] == "AWS::SNS::Topic" && attr == "TopicArn":
		return t.ref(logical, depth+1)
	}
	return "", false
}

func (t *smTemplate) sub(arg any, depth int) (string, bool) {
	var tpl string
	vars := map[string]any{}
	switch a := arg.(type) {
	case string:
		tpl = a
	case []any:
		if len(a) != 2 {
			return "", false
		}
		var ok bool
		if tpl, ok = a[0].(string); !ok {
			return "", false
		}
		vars, _ = a[1].(map[string]any)
	default:
		return "", false
	}
	var b strings.Builder
	for {
		i := strings.Index(tpl, "${")
		if i < 0 {
			b.WriteString(tpl)
			if !t.emit(b.Len()) {
				return "", false
			}
			return b.String(), true
		}
		j := strings.IndexByte(tpl[i:], '}')
		if j < 0 {
			return "", false
		}
		b.WriteString(tpl[:i])
		expr := tpl[i+2 : i+j]
		tpl = tpl[i+j+1:]
		if lit, ok := strings.CutPrefix(expr, "!"); ok {
			b.WriteString("${" + lit + "}")
			continue
		}
		if !t.spend() || b.Len() > smMaxValue {
			t.exceeded = true
			return "", false
		}
		var val string
		var ok bool
		if v, has := vars[expr]; has {
			val, ok = t.resolve(v, depth+1)
		} else if strings.Contains(expr, ".") {
			val, ok = t.getAtt(expr, depth+1)
		} else {
			val, ok = t.ref(expr, depth+1)
		}
		if !ok {
			return "", false
		}
		b.WriteString(val)
	}
}

// ---- when the engine accepted the stack

// smStackAccepted runs when the engine accepted CreateStack, UpdateStack or CreateChangeSet.
func (s *Server) smStackAccepted(f *cfnFinding) {
	if f.smT == nil || len(f.sm) == 0 || s.cfg.Planned == nil || !s.cfg.Planned["sagemaker-runtime"] {
		return
	}
	switch f.op {
	case "CreateChangeSet":
		s.sm.mu.Lock()
		if len(s.sm.pending) < smMaxPendingChangeSets {
			s.sm.pending[f.stack+"\x00"+f.changeSet] = f.smT
		}
		s.sm.mu.Unlock()
	default:
		s.smCreateTemplate(f.smT)
	}
}

// smExecuteChangeSet runs when the engine accepted ExecuteChangeSet: the declarations held for that change set are created.
func (s *Server) smExecuteChangeSet(form url.Values) {
	if s.cfg.Planned == nil || !s.cfg.Planned["sagemaker-runtime"] {
		return
	}
	cs, stack := form.Get("ChangeSetName"), form.Get("StackName")
	if rest, ok := strings.CutPrefix(cs, "arn:"); ok {
		if i := strings.Index(rest, ":changeSet/"); i >= 0 {
			cs = strings.SplitN(rest[i+len(":changeSet/"):], "/", 2)[0]
		}
	}
	s.sm.mu.Lock()
	var held *smTemplate
	for k, v := range s.sm.pending {
		st, name, _ := strings.Cut(k, "\x00")
		if name == cs && (stack == "" || st == stack || strings.Contains(stack, "/"+st+"/")) {
			held = v
			delete(s.sm.pending, k)
			break
		}
	}
	s.sm.mu.Unlock()
	if held != nil {
		s.smCreateTemplate(held)
	}
}

// smCreateTemplate creates the SageMaker resources of an accepted stack. A resource with no name of its own is named by the engine's
// physical id, which the front asks for (the engine makes the resources of a stack in the background, so it waits a few seconds).
func (s *Server) smCreateTemplate(t *smTemplate) {
	decls := t.decls()
	var unnamed []string
	for _, d := range decls {
		if d.reason == "unnamed" {
			unnamed = append(unnamed, d.logical)
		}
	}
	if len(unnamed) > 0 {
		if ids := s.smPhysicalIDs(t.stack, unnamed); len(ids) > 0 && !t.exceeded {
			t.physical = ids
			decls = t.redecls()
		}
	}
	if t.exceeded {
		s.ledger.recordUnsupported("sagemaker-runtime", "cloudformation:unresolved", "budget exceeded")
	}
	s.smCreateDecls(decls)
}

type smStackResources struct {
	Members []struct {
		Logical  string `xml:"LogicalResourceId"`
		Physical string `xml:"PhysicalResourceId"`
	} `xml:"DescribeStackResourcesResult>StackResources>member"`
}

// smPhysicalIDs reads the physical ids of a stack's resources from the engine, waiting until every logical id asked for has one.
func (s *Server) smPhysicalIDs(stack string, logicals []string) map[string]string {
	deadline := time.Now().Add(smPhysicalWait)
	for {
		form := url.Values{"Action": {"DescribeStackResources"}, "Version": {"2010-05-15"}, "StackName": {stack}}
		out := map[string]string{}
		if resp, err := s.engineRaw("cloudformation", http.MethodPost, "/", map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
			[]byte(form.Encode()), engineFetchTimeout, 1<<20); err == nil && resp.Status < 300 {
			var doc smStackResources
			if xml.Unmarshal(resp.Body, &doc) == nil {
				for _, m := range doc.Members {
					if m.Physical != "" {
						out[m.Logical] = m.Physical
					}
				}
			}
		}
		all := true
		for _, l := range logicals {
			all = all && out[l] != ""
		}
		if all || time.Now().After(deadline) {
			return out
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// smCreateDecls creates what a template declared and records what it could not read or create.
func (s *Server) smCreateDecls(decls []*smDecl) {
	var ok []*smDecl
	for _, d := range decls {
		switch d.reason {
		case "unresolved":
			continue // recorded once for the template (smCreateTemplate)
		case "", "async-unresolved":
			if d.name == "" {
				s.ledger.recordUnsupported("sagemaker-runtime", "cloudformation:name-unresolved", d.logical)
				continue
			}
			ok = append(ok, d)
		default:
			s.ledger.recordUnsupported("sagemaker-runtime", "cloudformation:"+d.reason, d.logical)
		}
		if d.reason == "async-unresolved" {
			s.ledger.recordUnsupported("sagemaker-runtime", "cloudformation:async-unresolved", d.logical)
		}
	}
	for _, e := range s.applyDecls(ok) {
		s.ledger.recordUnsupported("sagemaker-runtime", "cloudformation:create-failed", oneLine(e.Error()))
	}
}
