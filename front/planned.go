package main

import (
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// Planned mode (ROVARA_AWS_PLANNED_SERVICES): the run's plan names the AWS services it may use, by key, and the front serves any
// service of the engine's table that the plan names. A request is identified from the SigV4 scope and then narrowed, by the wire
// protocol, the operation, the target prefix or Version and the REST route table, to ONE service of the table; a service the plan
// does not name is refused (400 ServiceNotAvailableException, counted as outOfPlan), and what cannot be told apart is refused as
// unsupported (404), never forwarded. The engine is always given the front's own Authorization naming the decided service's
// route key, so the engine executes the service the front checked.
//
// Why a request that reaches the engine can only be executed as the service the front decided on: the engine claims a request for
// the services whose route key is the one in the SigV4 scope (plus state-addressed data planes: a function URL, an API stage, a
// content path, which exist only for resources a planned service created) and executes it only when exactly one claimant names the
// operation. The front's candidate set for a scope is every table service with that route key, narrowed only by signals the
// engine reads the same way (tools/group_oracle.py proves each against the running engine).

// tsvc is one service of the table.
type tsvc struct {
	row    *genRow
	svc    *service
	sign   string // the SigV4 service name the front writes for it
	opOnce sync.Once
	ops    map[string]struct{}
	rtOnce sync.Once
	routes []route
}

type route struct {
	method string
	segs   []seg
	op     string
}

type seg struct {
	kind byte // 0 literal, 1 label, 2 greedy label
	lit  string
}

var (
	tableByKey = map[string]*tsvc{}
	tableByRK  = map[string][]*tsvc{}
	byPrefix   = map[string][]*tsvc{} // lower-case exact target prefix and the one without its _<digits> suffix
	byCBORName = map[string][]*tsvc{} // lower-case SDK id and Smithy service name
	byQVersion = map[string][]*tsvc{}
	prefixRe   = regexp.MustCompile(`_\d+$`)
)

func init() {
	signAlt := map[string]string{}
	for alt, key := range genAltScopes {
		if alt != "s3express" {
			signAlt[key] = alt
		}
	}
	for i := range genRows {
		r := &genRows[i]
		t := &tsvc{row: r, sign: r.RK}
		if alt, ok := signAlt[r.Key]; ok {
			t.sign = alt
		}
		def := protoRestJSON
		switch {
		case r.Proto&gpXML != 0:
			def = protoRestXML
		case r.Proto&gpREST != 0:
		case r.Proto&gpJSON != 0:
			def = protoJSON
		case r.Proto&gpQuery != 0:
			def = protoQuery
		case r.Proto&gpCBOR != 0:
			def = protoCBOR
		}
		t.svc = &service{Key: r.Key, SigningName: t.sign, Default: def}
		tableByKey[r.Key] = t
		tableByRK[r.RK] = append(tableByRK[r.RK], t)
		if r.Prefix != "" {
			p := strings.ToLower(r.Prefix)
			byPrefix[p] = append(byPrefix[p], t)
			if n := prefixRe.ReplaceAllString(p, ""); n != p {
				byPrefix[n] = append(byPrefix[n], t)
			}
		}
		if r.Proto&gpCBOR != 0 {
			byCBORName[strings.ToLower(r.SDKID)] = append(byCBORName[strings.ToLower(r.SDKID)], t)
			if strings.ToLower(r.Shape) != strings.ToLower(r.SDKID) {
				byCBORName[strings.ToLower(r.Shape)] = append(byCBORName[strings.ToLower(r.Shape)], t)
			}
		}
		if r.QVer != "" && r.Proto&gpQuery != 0 {
			byQVersion[r.QVer] = append(byQVersion[r.QVer], t)
		}
	}
}

// normaliseServiceKey: a table key as it is, a legacy spelling as its key, anything else "".
func normaliseServiceKey(id string) string {
	id = strings.ToLower(strings.TrimSpace(id))
	if _, ok := tableByKey[id]; ok {
		return id
	}
	return genLegacy[id]
}

func (t *tsvc) operations() map[string]struct{} {
	t.opOnce.Do(func() {
		t.ops = map[string]struct{}{}
		for _, o := range strings.Fields(t.row.Ops) {
			t.ops[o] = struct{}{}
		}
	})
	return t.ops
}

func parseSegs(uri string) []seg {
	var out []seg
	for _, s := range strings.Split(uri, "/") {
		switch {
		case s == "":
		case strings.HasSuffix(s, "+}") && strings.HasPrefix(s, "{"):
			out = append(out, seg{kind: 2})
		case strings.Contains(s, "{"):
			out = append(out, seg{kind: 1})
		default:
			out = append(out, seg{lit: s})
		}
	}
	return out
}

func (t *tsvc) restRoutes() []route {
	t.rtOnce.Do(func() {
		for _, line := range strings.Split(t.row.Routes, "\n") {
			f := strings.SplitN(line, " ", 3)
			if len(f) != 3 {
				continue
			}
			t.routes = append(t.routes, route{method: f[0], segs: parseSegs(f[1]), op: f[2]})
		}
	})
	return t.routes
}

// routeMatch is a REST route the request matches: the operation, and a specificity string (per template segment a literal is "2", a
// label "1", a greedy label "0") for choosing between two services that both have a route.
type routeMatch struct {
	op    string
	score string
}

// matchRoute finds the best route of the service for the method and path segments.
func (t *tsvc) matchRoute(method string, ps []string) (routeMatch, bool) {
	var best routeMatch
	found := false
	for _, r := range t.restRoutes() {
		if r.method != method {
			continue
		}
		score, ok := matchSegs(r.segs, ps)
		if !ok {
			continue
		}
		if !found || score > best.score {
			best, found = routeMatch{r.op, score}, true
		}
	}
	return best, found
}

func matchSegs(tpl []seg, ps []string) (string, bool) {
	var b []byte
	i := 0
	for _, s := range tpl {
		switch s.kind {
		case 2:
			if i >= len(ps) {
				return "", false
			}
			b = append(b, '0')
			i = len(ps)
		case 1:
			if i >= len(ps) {
				return "", false
			}
			b = append(b, '1')
			i++
		default:
			if i >= len(ps) || ps[i] != s.lit {
				return "", false
			}
			b = append(b, '2')
			i++
		}
	}
	if i != len(ps) {
		return "", false
	}
	return string(b), true
}

func splitPath(p string) []string {
	var out []string
	for _, s := range strings.Split(p, "/") {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// scopeCandidates: the table services a SigV4 scope name can mean. Besides the route key, the engine serves a few services under
// a name of their own (genAltScopes), and the 0.5.15 front took execute-api (an API invoke URL signs with it) as API Gateway.
func scopeCandidates(name string) []*tsvc {
	if alt, ok := genAltScopes[name]; ok {
		return []*tsvc{tableByKey[alt]}
	}
	c := tableByRK[name]
	if name == "execute-api" {
		c = append(append([]*tsvc(nil), c...), tableByRK["apigateway"]...)
	}
	return c
}

func (t *tsvc) speaks(bit int) bool { return t.row.Proto&bit != 0 }

func popcount(x int) int {
	n := 0
	for ; x != 0; x &= x - 1 {
		n++
	}
	return n
}

// protoClass: the bit of the wire protocol a member would serve the request in: the one the request names when the member declares
// it, else the member's only protocol (the engine serves a single-protocol service in that protocol whatever the request is), else
// none.
func (t *tsvc) protoClass(kindBit int) int {
	bits := t.row.Proto &^ gpXML
	if kindBit != 0 && bits&kindBit != 0 {
		return kindBit
	}
	if popcount(bits) == 1 {
		return bits
	}
	return 0
}

// plannedRequest is what the front read from a request, for narrowing.
type plannedRequest struct {
	method   string
	segs     []string
	kindBit  int    // gpJSON, gpQuery, gpCBOR or 0 (REST)
	op       string // the routing key of kindBit
	prefix   string // the target prefix (json)
	cbor     string // the CBOR service id
	version  string
	scope    string
	hasScope bool
}

// names: whether the member has an operation for the request, in the protocol it would serve it in; the operation name; and, for a
// REST member, the specificity of the route.
func (t *tsvc) names(rq *plannedRequest) (ok bool, op, score string) {
	switch t.protoClass(rq.kindBit) {
	case gpJSON, gpQuery, gpCBOR:
		class := t.protoClass(rq.kindBit)
		if class != rq.kindBit || rq.op == "" {
			return false, "", "" // e.g. a single-protocol JSON member and a request with no target
		}
		if !t.row.Shared {
			return true, rq.op, ""
		}
		_, has := t.operations()[rq.op]
		return has, rq.op, ""
	case gpREST:
		m, found := t.matchRoute(rq.method, rq.segs)
		return found, m.op, m.score
	}
	return false, "", ""
}

func normPrefix(p string) string { return prefixRe.ReplaceAllString(strings.ToLower(p), "") }

// narrow reduces several members that name the request to the ones the engine's own signals leave.
func narrow(n []*tsvc, scores map[*tsvc]string, rq *plannedRequest) []*tsvc {
	if len(n) < 2 {
		return n
	}
	switch rq.kindBit {
	case gpJSON:
		if rq.prefix != "" {
			var exact, norm []*tsvc
			for _, t := range n {
				if strings.EqualFold(t.row.Prefix, rq.prefix) {
					exact = append(exact, t)
				} else if t.row.Prefix != "" && normPrefix(t.row.Prefix) == normPrefix(rq.prefix) {
					norm = append(norm, t)
				}
			}
			if len(exact) > 0 {
				n = exact
			} else if len(norm) > 0 {
				n = norm
			}
		}
	case gpQuery:
		if rq.version != "" {
			var v []*tsvc
			for _, t := range n {
				if t.row.QVer == rq.version {
					v = append(v, t)
				}
			}
			if len(v) > 0 {
				n = v
			}
		}
	case gpCBOR:
		if rq.cbor != "" {
			var v []*tsvc
			for _, t := range n {
				if strings.EqualFold(t.row.SDKID, rq.cbor) || strings.EqualFold(t.row.Shape, rq.cbor) {
					v = append(v, t)
				}
			}
			if len(v) > 0 {
				n = v
			}
		}
	}
	if len(n) > 1 && anyREST(n, rq) {
		best := ""
		for _, t := range n {
			if s := scores[t]; s > best {
				best = s
			}
		}
		var v []*tsvc
		for _, t := range n {
			if scores[t] == best && best != "" {
				v = append(v, t)
			}
		}
		if len(v) > 0 {
			n = v
		}
	}
	if len(n) > 1 {
		class := map[int]string{gpJSON: "json", gpQuery: "query", gpCBOR: "cbor"}[rq.kindBit]
		if want := genTieBreak[n[0].row.RK][class]; want != "" {
			for _, t := range n {
				if t.row.Key == want {
					return []*tsvc{t}
				}
			}
		}
	}
	return n
}

func anyREST(n []*tsvc, rq *plannedRequest) bool {
	for _, t := range n {
		if t.protoClass(rq.kindBit) == gpREST {
			return true
		}
	}
	return false
}

// normalisedTargetPrefix reads an X-Amz-Target the way the engine does for the services whose published prefix is a fully qualified
// name (com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101): the operation is what follows the last dot, the service the last
// dot-separated segment of what comes before it. (For the usual Service.Operation this is the plain split.)
func normalisedTargetPrefix(target string) (prefix, op string) {
	i := strings.LastIndex(target, ".")
	if i < 0 {
		return "", target
	}
	prefix, op = target[:i], target[i+1:]
	if j := strings.LastIndex(prefix, "."); j >= 0 {
		prefix = prefix[j+1:]
	}
	return prefix, op
}

// identifyPlanned is identify for planned mode: the same signals, read by the same rules, resolved against the whole table.
func identifyPlanned(method, path, rawPath string, h http.Header, rawQuery string, action, version string, planned map[string]bool) identified {
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
	refuse := func(reason refuseReason, p proto) identified {
		id.Service, id.Reason, id.Proto = nil, reason, p
		return finish("unknown")
	}
	if problem || len(h.Values("X-Amz-Target")) > 1 {
		// the signals disagree, or the request carries two targets (the front reads the first; refuse rather than guess which one
		// every reader inside the engine takes)
		return refuse(refuseMismatch, protoRestJSON)
	}
	if p := splitPath(rawPath); len(p) >= 2 && p[0] == "_aws" {
		return plannedDataPlane(&id, p[1], planned, finish, refuse)
	}
	var cands []*tsvc
	if hasScope {
		cands = scopeCandidates(scope.Service)
		if len(cands) == 0 {
			return refuse(refuseUnknownScope, protoRestJSON)
		}
	}
	// the REST routes are matched on the raw (still percent-encoded) path, segment by segment and case-sensitively: how the engine reads the
	// first segment that tells the services of a shared signing name apart (/v2/ is API Gateway V2, /v%32/ is nobody's)
	rq := &plannedRequest{method: method, segs: splitPath(rawPath), version: version, hasScope: hasScope}
	if hasScope {
		rq.scope = scope.Service
	}
	// what the request itself says
	var implied []*tsvc
	switch {
	case strings.EqualFold(h.Get("smithy-protocol"), "rpc-v2-cbor"):
		id.Proto, rq.kindBit = protoCBOR, gpCBOR
		m := cborPath.FindStringSubmatch(rawPath)
		if m == nil {
			return refuse(refuseUnknownTarget, protoCBOR)
		}
		rq.cbor, rq.op = m[1], m[2]
		implied = byCBORName[strings.ToLower(m[1])]
		if len(implied) == 0 {
			return refuse(refuseUnknownTarget, protoCBOR)
		}
	case h.Get("X-Amz-Target") != "":
		target := h.Get("X-Amz-Target")
		id.Target, id.Proto, rq.kindBit = target, protoJSON, gpJSON
		rq.prefix, rq.op = normalisedTargetPrefix(target)
		implied = byPrefix[strings.ToLower(rq.prefix)]
		if len(implied) == 0 {
			implied = byPrefix[normPrefix(rq.prefix)]
		}
		if len(implied) == 0 {
			return refuse(refuseUnknownTarget, protoJSON)
		}
	case action != "":
		id.Proto, rq.kindBit, rq.op = protoQuery, gpQuery, action
		if !hasScope {
			implied = byQVersion[version]
			if len(implied) == 0 {
				return refuse(refuseAmbiguous, protoQuery)
			}
		}
	}
	if hasScope && implied != nil {
		// the target, CBOR path or Action must name a service the scope can mean
		match := false
		for _, a := range implied {
			for _, c := range cands {
				if a == c {
					match = true
				}
			}
		}
		if !match {
			return refuse(refuseMismatch, id.Proto)
		}
	}
	if !hasScope {
		if implied == nil {
			// a plain REST call with no scope: S3 is the sink, as in 0.5.15
			t := tableByKey["s3"]
			id.Service, id.Proto = t.svc, protoRestXML
			return finish(s3OperationName(method, path, q, h.Get("x-amz-copy-source") != ""))
		}
		cands = implied
	}
	// the members that name the request
	var n []*tsvc
	scores := map[*tsvc]string{}
	ops := map[*tsvc]string{}
	if len(cands) == 1 && hasScope {
		// one service under this route key: nothing to tell apart. A Query call has to be to a service that speaks Query (an
		// Action on an S3 or Lambda call is not an S3 or Lambda request).
		t := cands[0]
		if rq.kindBit == gpQuery && !t.speaks(gpQuery) {
			return refuse(refuseMismatch, id.Proto)
		}
		n = []*tsvc{t}
		_, ops[t], scores[t] = t.names(rq)
	} else {
		for _, t := range cands {
			if ok, op, sc := t.names(rq); ok {
				n = append(n, t)
				scores[t], ops[t] = sc, op
			}
		}
	}
	if len(n) == 0 {
		spoken := false
		for _, t := range cands {
			if t.protoClass(rq.kindBit) != 0 {
				spoken = true
			}
		}
		if !spoken && rq.kindBit != 0 {
			return refuse(refuseMismatch, id.Proto)
		}
		return refuse(refuseUnknownTarget, id.Proto)
	}
	n = narrow(n, scores, rq)
	if len(n) != 1 {
		return refuse(refuseAmbiguous, id.Proto)
	}
	t := n[0]
	id.Service = t.svc
	if t.speaks(gpREST) && t.protoClass(rq.kindBit) == gpREST {
		id.Proto = protoRestJSON
		if t.speaks(gpXML) {
			id.Proto = protoRestXML
		}
	}
	if t.row.Key == "s3" {
		return finish(s3OperationName(method, path, q, h.Get("x-amz-copy-source") != ""))
	}
	op := ops[t]
	if op == "" {
		op = "UnknownOperation"
	}
	return finish(op)
}

// dataPlanes: the reserved path segment the engine serves a service's data plane behind on its one endpoint
// (/_aws/<plane>/<resource>/<path>, read on any host) and the services that own it. The engine claims such a request only for a
// resource a service holds, so the front decides the service from the plane and the plan decides whether it may be reached.
var dataPlanes = map[string]struct {
	keys []string
	op   string
}{
	"execute-api":            {[]string{"apigatewayv2", "api-gateway"}, "InvokeApi"},
	"lambda-url":             {[]string{"lambda"}, "InvokeFunctionUrl"},
	"elasticloadbalancing":   {[]string{"elastic-load-balancing-v2"}, "DataPlaneRequest"},
	"elasticloadbalancingv2": {[]string{"elastic-load-balancing-v2"}, "DataPlaneRequest"},
	"cloudfront":             {[]string{"cloudfront"}, "DataPlaneRequest"},
	"es":                     {[]string{"opensearch", "elasticsearch-service"}, "DataPlaneRequest"},
	"aoss":                   {[]string{"opensearchserverless"}, "DataPlaneRequest"},
	"acm-acme-enroll":        {[]string{"acm"}, "DataPlaneRequest"},
	"devicefarm-uploads":     {[]string{"devicefarm"}, "DataPlaneRequest"},
}

func plannedDataPlane(id *identified, plane string, planned map[string]bool, finish func(string) identified, refuse func(refuseReason, proto) identified) identified {
	if strings.Contains(plane, ".lambda-url.") {
		plane = "lambda-url"
	}
	dp, ok := dataPlanes[plane]
	if !ok {
		return refuse(refuseUnknownScope, protoRestJSON)
	}
	t := tableByKey[dp.keys[0]]
	for _, k := range dp.keys {
		if planned[k] {
			t = tableByKey[k]
			break
		}
	}
	id.Service, id.Proto = t.svc, protoRestJSON
	return finish(dp.op)
}

// plannedReadsForm: whether a POST body is read for Action and Version in planned mode (see readsFormBody).
func plannedReadsForm(h http.Header, rawQuery string) bool {
	sc, _ := requestScope(h, rawQuery)
	if sc == nil {
		return true
	}
	c := scopeCandidates(sc.Service)
	if len(c) == 0 {
		return true
	}
	for _, t := range c {
		if t.speaks(gpQuery) {
			return true
		}
	}
	return false
}

// parsePlanned reads the plan's service list: table keys, or legacy spellings of them. An unknown id is an error naming it.
func parsePlanned(csv string) (map[string]bool, []string, error) {
	out := map[string]bool{}
	for _, raw := range strings.Split(csv, ",") {
		id := strings.TrimSpace(raw)
		if id == "" {
			continue
		}
		key := normaliseServiceKey(id)
		if key == "" {
			return nil, nil, &unknownPlannedError{id}
		}
		out[key] = true
	}
	keys := make([]string, 0, len(out))
	for k := range out {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return out, keys, nil
}

type unknownPlannedError struct{ id string }

func (e *unknownPlannedError) Error() string {
	id := e.id
	if len(id) > 60 {
		id = id[:60]
	}
	return envPlanned + " names a service this engine does not serve: " + id
}
