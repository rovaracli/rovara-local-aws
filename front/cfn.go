package main

import (
	"encoding/json"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// CloudFormation in planned mode: a stack creates its resources INSIDE the engine, so a planned CloudFormation can bring into
// being resources of a service the plan does not name, without any request for that service passing the front. The front does not
// block the stack; it RECORDS it. For CreateStack, UpdateStack, CreateChangeSet (and the stack set forms) it reads the template when
// it can (the inline TemplateBody, or a TemplateURL that points at the engine's own S3, fetched over loopback with a size bound),
// takes the Type of each resource, and for every service of the table that the plan does not name counts one outOfPlan call in the
// ledger, with the operation `cloudformation:<Type>`. What it cannot read or classify is counted once under the service
// `cloudformation-unchecked`: a nested stack (cloudformation:nested), a template macro or SAM transform (cloudformation:transform),
// a template it could not fetch or that is too large (cloudformation:unreadable), a namespace with no service of the table
// (cloudformation:unmapped). The evidence can then say "nested templates are not checked". Only a request the engine accepted is
// recorded.

const (
	cfnUncheckedService = "cloudformation-unchecked"
	cfnMaxTemplate      = 1 << 20
)

var cfnTemplateOps = map[string]bool{"CreateStack": true, "UpdateStack": true, "CreateChangeSet": true, "CreateStackSet": true, "UpdateStackSet": true}

var (
	cfnTypeRe      = regexp.MustCompile(`["']?\bType["']?\s*:\s*["']?(AWS::[A-Za-z0-9]+::[A-Za-z0-9:]+)`)
	cfnTransformRe = regexp.MustCompile(`["']?\b(?:Fn::)?Transform["']?\s*:`)
	nonAlnum       = regexp.MustCompile(`[^a-z0-9]`)
)

// cfnByNamespace maps a CloudFormation namespace (AWS::<ns>::*, compared in lower case without punctuation) to the table services
// that own it: by the table's cfnName, else by the service key or SDK id.
var (
	cfnByNamespace = map[string][]*tsvc{}
	cfnOnce        sync.Once
)

// cfnOwners builds the map on first use (the table itself is built by an init of another file).
func cfnOwners(ns string) []*tsvc {
	cfnOnce.Do(buildCFNNamespaces)
	return cfnByNamespace[nonAlnum.ReplaceAllString(strings.ToLower(ns), "")]
}

func buildCFNNamespaces() {
	add := func(k string, t *tsvc) {
		k = nonAlnum.ReplaceAllString(strings.ToLower(k), "")
		if k == "" {
			return
		}
		for _, e := range cfnByNamespace[k] {
			if e == t {
				return
			}
		}
		cfnByNamespace[k] = append(cfnByNamespace[k], t)
	}
	for i := range genRows {
		r := &genRows[i]
		t := tableByKey[r.Key]
		if r.CFN != "" {
			add(r.CFN, t)
		} else {
			add(r.Key, t)
			add(r.SDKID, t)
		}
	}
	for _, v := range cfnByNamespace {
		sort.Slice(v, func(i, j int) bool { return v[i].row.Key < v[j].row.Key })
	}
}

type cfnOut struct{ service, op string }

type cfnFinding struct {
	out       []cfnOut
	unchecked string // "", or the reason (nested, transform, unreadable, unmapped, lambda-unparsed)
	// Lambda functions and layers the template declares (lambda_heavy.go), for the heavy-function registry
	fns    []*lambdaFn
	layers map[string]layerInfo
	// the targets of state machines the template declares (targets.go)
	machines []map[string]any // Properties of the state machines the template declares
	// the SageMaker resources the template declares (sagemaker_cfn.go), and the request they came with
	sm                   []*smDecl
	smT                  *smTemplate
	op, stack, changeSet string
	targets              []targetRef
	targetsUnchecked     string
	// hidden: the template names the function runner's plumbing (a queue, the bucket, the stub's role): refused
	hidden bool
}

// scanTemplate lists the distinct resource types a template names anywhere in its text (JSON or YAML). It is an EXTRA signal, read
// beside the document: a Type: line of any shape counts, which can only add to what is recorded. There is no cap (the text is at
// most cfnMaxTemplate bytes), and a type is listed once however many times it is written.
func scanTemplate(text string) (types []string, transform bool) {
	seen := map[string]bool{}
	for _, m := range cfnTypeRe.FindAllStringSubmatch(text, -1) {
		if !seen[m[1]] {
			seen[m[1]] = true
			types = append(types, m[1])
		}
	}
	sort.Strings(types)
	return types, cfnTransformRe.MatchString(text)
}

// parseTemplate reads a template as a document: JSON, or the YAML subset of yamlish.go.
func parseTemplate(text string) (map[string]any, bool) {
	if t := strings.TrimSpace(text); strings.HasPrefix(t, "{") {
		var m map[string]any
		if json.Unmarshal([]byte(t), &m) != nil || m == nil {
			return nil, false
		}
		return m, true
	}
	d, err := parseYAMLish(text)
	m, _ := d.(map[string]any)
	return m, err == nil && m != nil
}

// classifyTemplate turns the text of a template into what the ledger records, given the plan.
func classifyTemplate(text string, planned map[string]bool) *cfnFinding {
	f := &cfnFinding{}
	types, transform := scanTemplate(text)
	mark := func(reason string) {
		if f.unchecked == "" {
			f.unchecked = reason
		}
	}
	// the document: every Resources.*.Type, as the structure says it, whatever way the text writes it (escapes, folded scalars, flow
	// style); a template that is not a document is counted unchecked
	if doc, ok := parseTemplate(text); !ok {
		mark("unparsed")
	} else {
		res, _ := doc["Resources"].(map[string]any)
		have := map[string]bool{}
		for _, t := range types {
			have[t] = true
		}
		for _, r := range res {
			rm, _ := r.(map[string]any)
			typ, isStr := rm["Type"].(string)
			typ = strings.TrimSpace(typ)
			if !isStr {
				mark("unparsed")
				continue
			}
			switch {
			case strings.HasPrefix(typ, "Custom::"):
				mark("custom") // a custom resource runs a function the template names: what it creates cannot be read here
			case !strings.HasPrefix(typ, "AWS::") && typ != "":
				mark("unmapped") // a third-party type or a module
			}
			if !have[typ] && strings.HasPrefix(typ, "AWS::") && strings.Count(typ, "::") >= 2 {
				have[typ] = true
				types = append(types, typ)
			}
			if typ == "AWS::StepFunctions::StateMachine" {
				props, _ := rm["Properties"].(map[string]any)
				f.machines = append(f.machines, props) // resolved by cfnCheck, which can fetch a DefinitionS3Location
			}
		}
		if _, ok := doc["Transform"]; ok {
			transform = true
		}
		walkJSON(doc, func(k string, _ any) {
			if k == "Fn::Transform" {
				transform = true
			}
		})
		sort.Strings(types)
	}
	if transform {
		mark("transform")
	}
	for _, typ := range types {
		parts := strings.Split(typ, "::")
		ns, res := parts[1], parts[2]
		switch {
		case ns == "CloudFormation" && res == "Stack":
			mark("nested")
			continue
		case ns == "Serverless":
			mark("transform")
			continue
		}
		owners := cfnOwners(ns)
		if len(owners) == 0 {
			mark("unmapped")
			continue
		}
		inPlan := false
		for _, o := range owners {
			if planned[o.row.Key] {
				inPlan = true
			}
		}
		if !inPlan {
			f.out = append(f.out, cfnOut{owners[0].row.Key, "cloudformation:" + typ})
		}
	}
	return f
}

// templateDefinition reads the definition of an AWS::StepFunctions::StateMachine: Definition (an object), DefinitionString (a string, or
// an intrinsic function over literal text), DefinitionS3Location (an object of the engine's own S3 without a version). Anything the
// front cannot read with certainty is unchecked ("intrinsic", "unreadable"), never skipped.
func (s *Server) templateDefinition(props map[string]any) ([]targetRef, string) {
	if d, present := props["Definition"]; present {
		return aslTargets(d)
	}
	if ds, present := props["DefinitionString"]; present {
		return aslTargets(ds)
	}
	if loc, present := props["DefinitionS3Location"]; present {
		m, _ := loc.(map[string]any)
		bucket, _ := m["Bucket"].(string)
		key, _ := m["Key"].(string)
		if _, versioned := m["Version"]; versioned || bucket == "" || key == "" {
			return nil, "intrinsic" // a version is not honoured by the front's read, and a non-literal name cannot be fetched
		}
		b, ok := s.engineObject("/"+url.PathEscape(bucket)+"/"+escapeKey(key), cfnMaxTemplate)
		if !ok {
			return nil, "unreadable"
		}
		return aslTargets(string(b))
	}
	return nil, ""
}

// templateObject: the bucket and key of a TemplateURL that names an object of the engine's own S3, or ok=false. The accepted
// spellings are AWS's (path style s3[.-]<region>.amazonaws.com/<bucket>/<key>, virtual host <bucket>.s3[.-]<region>.amazonaws.com/<key>)
// and the run's own base URL (path style).
var s3HostRe = regexp.MustCompile(`^(?:(.+)\.)?s3[.-](?:[a-z0-9-]+\.)?(?:amazonaws\.com(?:\.cn)?|api\.aws)$|^(?:(.+)\.)?s3\.amazonaws\.com$`)

func (s *Server) templateObjectPath(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return "", false
	}
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		// the engine picks the object by its query too (versionId); the front reads the latest object, so a TemplateURL with a query
		// is not read at all
		return "", false
	}
	host := strings.ToLower(u.Host)
	p := u.EscapedPath()
	if base, err := url.Parse(s.cfg.BaseURL); err == nil && host == strings.ToLower(base.Host) {
		return p, strings.Count(strings.Trim(p, "/"), "/") >= 1
	}
	h := strings.ToLower(u.Hostname())
	if strings.HasSuffix(h, "."+s.cfg.Hostname) && s.cfg.Hostname != "" {
		bucket := strings.TrimSuffix(h, "."+s.cfg.Hostname)
		return "/" + bucket + p, bucket != "" && strings.Trim(p, "/") != ""
	}
	m := s3HostRe.FindStringSubmatch(h)
	if m == nil {
		return "", false
	}
	if bucket := m[1] + m[2]; bucket != "" {
		return "/" + bucket + p, strings.Trim(p, "/") != ""
	}
	return p, strings.Count(strings.Trim(p, "/"), "/") >= 1
}

// fetchTemplate reads a template the request names by URL from the engine's own S3 over loopback. "" and false when it cannot.
func (s *Server) fetchTemplate(raw string) (string, bool) {
	path, ok := s.templateObjectPath(raw)
	if !ok {
		return "", false
	}
	b, ok := s.engineObject(path, cfnMaxTemplate)
	return string(b), ok
}

// cfnCheck reads what a CloudFormation request would create. nil when the request carries no template to read (an update that
// reuses the previous one).
func (s *Server) cfnCheck(form url.Values) *cfnFinding {
	body, tplURL := form.Get("TemplateBody"), strings.TrimSpace(form.Get("TemplateURL"))
	text := body
	switch {
	case body != "":
		if len(body) > cfnMaxTemplate {
			return &cfnFinding{unchecked: "unreadable"}
		}
	case tplURL != "":
		var ok bool
		if text, ok = s.fetchTemplate(tplURL); !ok {
			return &cfnFinding{unchecked: "unreadable"}
		}
	default:
		return nil
	}
	if s.runner != nil && templateHasHidden(text) {
		return &cfnFinding{hidden: true}
	}
	f := classifyTemplate(text, s.cfg.Planned)
	for _, props := range f.machines {
		refs, unchecked := s.templateDefinition(props)
		f.targets = append(f.targets, refs...)
		if unchecked != "" && f.targetsUnchecked == "" {
			f.targetsUnchecked = unchecked
		}
	}
	if strings.Contains(text, "AWS::SageMaker::") && s.cfg.Planned["sagemaker-runtime"] {
		if f.smT = s.newSMTemplate(text, form); f.smT != nil {
			f.sm = f.smT.decls()
		}
	}
	if strings.Contains(text, "AWS::Lambda::") {
		fns, layers, ok := s.cfnLambdas(text, form.Get("StackName"))
		if !ok && f.unchecked == "" {
			f.unchecked = "unparsed"
		}
		f.fns, f.layers = fns, layers
	}
	return f
}

// cfnLambdas reads the Lambda functions and layers a template declares (JSON, or the YAML subset of yamlish.go): the properties that
// decide whether the engine can run a function (Runtime, PackageType, Architectures, Layers, Code and Content with an S3 package,
// which is judged from the engine's own S3). A function with no literal FunctionName is known by <stack>-<LogicalId> (the physical
// name is that plus a random suffix). ok is false when the template could not be read as a document.
func (s *Server) cfnLambdas(text, stack string) ([]*lambdaFn, map[string]layerInfo, bool) {
	root, parsed := parseTemplate(text)
	if !parsed {
		return nil, nil, false
	}
	res, _ := root["Resources"].(map[string]any)
	if res == nil {
		return nil, nil, false
	}
	str := func(v any) string {
		if s, ok := v.(string); ok {
			return s
		}
		return ""
	}
	codeOf := func(m map[string]any) (lambdaCode, bool) { // ok false: a member is not a literal (a Ref), so the package cannot be named
		var c lambdaCode
		literal := true
		for k, dst := range map[string]*string{"ZipFile": &c.ZipFile, "S3Bucket": &c.S3Bucket, "S3Key": &c.S3Key, "ImageUri": &c.ImageURI} {
			if v, present := m[k]; present {
				if sv, isStr := v.(string); isStr {
					*dst = sv
				} else {
					literal = false
				}
			}
		}
		return c, literal
	}
	ids := make([]string, 0, len(res))
	for id := range res {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	layers := map[string]layerInfo{}
	for _, id := range ids {
		r, _ := res[id].(map[string]any)
		if str(r["Type"]) != "AWS::Lambda::LayerVersion" {
			continue
		}
		props, _ := r["Properties"].(map[string]any)
		content, _ := props["Content"].(map[string]any)
		li := layerInfo{}
		if c, literal := codeOf(content); !literal {
			li.unchecked = true
		} else {
			c.ZipFile = "" // a layer is a zip in S3
			li.elf, li.unchecked = s.judgeCode(c, false)
			if _, versioned := content["S3ObjectVersion"]; versioned {
				li.unchecked = true // the front reads the latest object, not the version the layer names
			}
		}
		layers["cfn-layer:"+stack+"/"+id] = li
	}
	var fns []*lambdaFn
	for _, id := range ids {
		r, _ := res[id].(map[string]any)
		if str(r["Type"]) != "AWS::Lambda::Function" {
			continue
		}
		props, _ := r["Properties"].(map[string]any)
		fn := &lambdaFn{name: str(props["FunctionName"]), runtime: str(props["Runtime"])}
		if fn.name == "" {
			fn.name, fn.prefix = stack+"-"+id, true
		}
		if _, hasRuntime := props["Runtime"]; hasRuntime && fn.runtime == "" {
			fn.unchecked = true // a Runtime given by a parameter: not known
		}
		fn.image = strings.EqualFold(str(props["PackageType"]), "Image")
		if list, ok := props["Architectures"].([]any); ok {
			for _, a := range list {
				fn.arches = append(fn.arches, str(a))
			}
		}
		if list, ok := props["Layers"].([]any); ok {
			for _, l := range list {
				switch lv := l.(type) {
				case string:
					fn.layers = append(fn.layers, lv)
				case map[string]any:
					if ref := str(lv["Ref"]); ref != "" {
						fn.layers = append(fn.layers, "cfn-layer:"+stack+"/"+ref)
					}
				}
			}
		}
		code, _ := props["Code"].(map[string]any)
		c, literal := codeOf(code)
		switch {
		case c.ImageURI != "":
			fn.image = true
		case !literal:
			fn.unchecked = true
		case c.S3Bucket != "":
			c.ZipFile = ""
			fn.elf, fn.unchecked = s.judgeCode(c, false)
			if _, versioned := code["S3ObjectVersion"]; versioned {
				fn.unchecked = true
			}
		}
		fns = append(fns, fn)
	}
	return fns, layers, true
}

// recordCFN writes the finding into the ledger: each unplanned service once per type, the unchecked marker once.
func (s *Server) recordCFN(f *cfnFinding) {
	for _, o := range f.out {
		s.ledger.recordOutOfPlan(o.service, o.op)
	}
	if f.unchecked != "" {
		s.ledger.recordOutOfPlan(cfnUncheckedService, "cloudformation:"+f.unchecked)
	}
	if len(f.targets) > 0 || f.targetsUnchecked != "" {
		s.recordTargets("stepfunctions", f.targets, f.targetsUnchecked)
	}
	s.smStackAccepted(f)
	s.heavy.mu.Lock()
	for k, li := range f.layers {
		s.heavy.layers[k] = li
	}
	s.heavy.mu.Unlock()
	for _, fn := range f.fns {
		s.registerHeavy(fn)
	}
}
