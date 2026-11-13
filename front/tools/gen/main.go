// gen writes front/services_gen.go (the identification tables for every service of the AWS Emulator engine) and
// front/services_gen_report.txt (how the services that share a SigV4 signing name are told apart).
//
//	go run ./tools/gen -table <aws-emulator-services.json> -models <engine checkout>/services [-out .] [-check]
//
// Inputs are pinned by sha256: the service table (made by Rovara Code's gen-service-table.ts from the engine's Smithy models) and
// the Smithy models themselves (a hash over every model file, in directory order). A different input is refused. The output is a pure
// function of the inputs (sorted, no clock, no path), so a second run is byte-identical; -check writes nothing and exits 1 when
// a file differs.
//
// What is generated, per service of the table: its key, the route key the engine claims it under (the SigV4 signing name, or the
// SDK id in lower case when the model has none: the rule of the engine's build support), the endpoint prefix, the wire protocols it
// speaks, its awsJson target prefix, its Query version and its rpcv2-cbor service ids; for every service that shares a route key
// with another, the names of its operations (awsJson, Query and CBOR: the routing key is the operation name); for every REST service,
// its routes (method and URI template, from the Smithy http traits: the same table the engine resolves a REST request with, and the
// source of the operation names the ledger shows), and its CloudFormation namespace (AWS::<CFN>::*), which the ledger uses to say which
// service a stack resource belongs to.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"go/format"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const (
	pinTableSHA  = "404cdf0aab1e9317035dd06e062e29e3d07ed5781c730bd71fcae4a3c6e36d82"
	pinModelsSHA = "57d9aeaa481a853b2143fc59d5d7deeee8e9b3c210c333cdf67d7872cda43b73"
	pinEngine    = "aws-emulator@1.0.343"
	pinCommit    = "a9f10fef3b8215b13ffc390ace27bdd58f2aac00"
)

type tableFile struct {
	Engine       string              `json:"engine"`
	EngineCommit string              `json:"engineCommit"`
	Services     []tableService      `json:"services"`
	Shared       map[string][]string `json:"sharedSigningNames"`
}

type tableService struct {
	Key            string   `json:"key"`
	SmithyID       string   `json:"smithyId"`
	SDKID          string   `json:"sdkId"`
	SigningName    *string  `json:"signingName"`
	EndpointPrefix *string  `json:"endpointPrefix"`
	Protocols      []string `json:"protocols"`
	TargetPrefix   *string  `json:"targetPrefix"`
	QueryVersion   *string  `json:"queryVersion"`
	LegacyKeys     []string `json:"legacyKeys"`
	CfnName        *string  `json:"cfnName"`
}

type target struct {
	Target string `json:"target"`
}
type shape struct {
	Type       string                     `json:"type"`
	Operations []target                   `json:"operations"`
	Collection []target                   `json:"collectionOperations"`
	Resources  []target                   `json:"resources"`
	Create     *target                    `json:"create"`
	Read       *target                    `json:"read"`
	Update     *target                    `json:"update"`
	Delete     *target                    `json:"delete"`
	List       *target                    `json:"list"`
	Put        *target                    `json:"put"`
	Traits     map[string]json.RawMessage `json:"traits"`
}
type model struct {
	Shapes map[string]shape `json:"shapes"`
}

const (
	pJSON  = 1
	pQuery = 2
	pCBOR  = 4
	pREST  = 8
	pXML   = 16
)

type svc struct {
	t      tableService
	rk     string
	ep     string
	proto  int
	prefix string
	qver   string
	shape  string
	ops    []string // operation local names
	routes []string // "METHOD /uri"
}

// Overrides that keep what the 0.5.15 front served: SQS answers the Query protocol (awsQueryCompatible) and every one of SQS, SNS
// and Step Functions answers rpcv2-cbor. The engine's own routing does not read these; the front does.
var extraProto = map[string]int{"sqs": pQuery | pCBOR, "sns": pCBOR, "sfn": pCBOR}
var queryVersionOverride = map[string]string{"sqs": "2012-11-05"}

// tieBreak: for a shared route key, the member the engine serves a request that carries no signal telling the members apart
// (verified against the engine by tools/group_oracle.py): the EventBridge API under "events" is served by eventbridge (the
// cloudwatch-events model answers only under its own route key "cloudwatchevents"), and the Query API under "rds" by rds
// (docdb and neptune answer only under "docdb" and "neptune").
var tieBreak = map[string]map[string]string{
	"events": {"json": "eventbridge"},
	"rds":    {"query": "rds"},
}

// altScopes: SigV4 scope names (not signing names) the engine serves one service under.
var altScopes = map[string]string{"cloudwatchevents": "cloudwatch-events", "docdb": "docdb", "neptune": "neptune", "s3express": "s3"}

func main() {
	tablePath := flag.String("table", "", "aws-emulator-services.json")
	modelsDir := flag.String("models", "", "<engine checkout>/services")
	out := flag.String("out", ".", "directory to write services_gen.go and services_gen_report.txt into")
	check := flag.Bool("check", false, "write nothing; exit 1 if a file differs")
	flag.Parse()
	if *tablePath == "" || *modelsDir == "" {
		fatal("both -table and -models are required")
	}
	raw, err := os.ReadFile(*tablePath)
	must(err)
	if sum := sha(raw); sum != pinTableSHA {
		fatal("the service table is not the pinned one: sha256 " + sum)
	}
	var tf tableFile
	must(json.Unmarshal(raw, &tf))
	if tf.Engine != pinEngine || tf.EngineCommit != pinCommit {
		fatal("the table is for another engine: " + tf.Engine + " " + tf.EngineCommit)
	}
	files, err := filepath.Glob(filepath.Join(*modelsDir, "service-*", "smithy-model", "*.json"))
	must(err)
	sort.Strings(files)
	models := map[string]*svc{}
	bySmithy := map[string]*svc{}
	var all []*svc
	for _, t := range tf.Services {
		s := &svc{t: t}
		if t.SigningName != nil {
			s.rk = strings.ToLower(*t.SigningName)
		} else {
			s.rk = strings.ToLower(strings.ReplaceAll(t.SDKID, " ", ""))
		}
		if t.EndpointPrefix != nil {
			s.ep = *t.EndpointPrefix
		}
		if t.TargetPrefix != nil {
			s.prefix = *t.TargetPrefix
		}
		if t.QueryVersion != nil {
			s.qver = *t.QueryVersion
		}
		if v, ok := queryVersionOverride[t.Key]; ok {
			s.qver = v
		}
		for _, p := range t.Protocols {
			switch p {
			case "awsJson1_0", "awsJson1_1":
				s.proto |= pJSON
			case "awsQuery", "ec2Query":
				s.proto |= pQuery
			case "rpcv2Cbor":
				s.proto |= pCBOR
			case "restJson1":
				s.proto |= pREST
			case "restXml":
				s.proto |= pREST | pXML
			}
		}
		s.proto |= extraProto[t.Key]
		s.shape = t.SmithyID[strings.Index(t.SmithyID, "#")+1:]
		all = append(all, s)
		bySmithy[t.SmithyID] = s
		models[t.Key] = s
	}
	groups := map[string][]*svc{}
	for _, s := range all {
		groups[s.rk] = append(groups[s.rk], s)
	}
	shared := map[string]bool{}
	for rk, g := range groups {
		if len(g) > 1 {
			shared[rk] = true
		}
	}
	// the table's own list of shared names must be the one derived here
	if len(tf.Shared) != len(shared) {
		fatal(fmt.Sprintf("the table lists %d shared signing names, the route keys give %d", len(tf.Shared), len(shared)))
	}
	for rk := range shared {
		if _, ok := tf.Shared[rk]; !ok {
			fatal("shared route key not in the table's list: " + rk)
		}
	}
	// read the models
	h := sha256.New()
	for _, f := range files {
		b, err := os.ReadFile(f)
		must(err)
		h.Write([]byte(filepath.Base(filepath.Dir(filepath.Dir(f))) + "\x00" + sha(b) + "\n"))
		var m model
		must(json.Unmarshal(b, &m))
		b = nil
		for id, sh := range m.Shapes {
			if sh.Type != "service" {
				continue
			}
			s := bySmithy[id]
			if s == nil {
				continue // a model the table does not list
			}
			collect(s, &m, sh)
		}
	}
	modelsSum := hex.EncodeToString(h.Sum(nil))
	if pinModelsSHA == "" {
		fmt.Fprintln(os.Stderr, "models sha256 (set pinModelsSHA to this):", modelsSum)
	} else if modelsSum != pinModelsSHA {
		fatal("the Smithy models are not the pinned ones: " + modelsSum)
	}
	for _, s := range all {
		if len(s.ops) == 0 {
			fatal("no operations read for " + s.t.Key)
		}
	}

	var gen bytes.Buffer
	emit(&gen, tf, all, groups, shared, modelsSum)
	var rep bytes.Buffer
	report(&rep, all, groups, shared)
	src, err := format.Source(gen.Bytes())
	must(err)
	write(*out, "services_gen.go", src, *check)
	write(*out, "services_gen_report.txt", rep.Bytes(), *check)
}

func collect(s *svc, m *model, sh shape) {
	seen := map[string]bool{}
	ops := map[string]bool{}
	var walk func(id string)
	addOp := func(id string) { ops[id] = true }
	walk = func(id string) {
		if seen[id] {
			return
		}
		seen[id] = true
		r := m.Shapes[id]
		for _, o := range r.Operations {
			addOp(o.Target)
		}
		for _, o := range r.Collection {
			addOp(o.Target)
		}
		for _, o := range []*target{r.Create, r.Read, r.Update, r.Delete, r.List, r.Put} {
			if o != nil {
				addOp(o.Target)
			}
		}
		for _, c := range r.Resources {
			walk(c.Target)
		}
	}
	for _, o := range sh.Operations {
		addOp(o.Target)
	}
	for _, r := range sh.Resources {
		walk(r.Target)
	}
	var ids []string
	for id := range ops {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	routes := map[string]bool{}
	for _, id := range ids {
		local := id[strings.Index(id, "#")+1:]
		s.ops = append(s.ops, local)
		if raw, ok := m.Shapes[id].Traits["smithy.api#http"]; ok {
			var h struct {
				Method string `json:"method"`
				URI    string `json:"uri"`
			}
			if json.Unmarshal(raw, &h) == nil && h.URI != "" {
				path := h.URI
				if i := strings.Index(path, "?"); i >= 0 {
					path = path[:i]
				}
				routes[strings.ToUpper(h.Method)+" "+path+" "+local] = true
			}
		}
	}
	for r := range routes {
		s.routes = append(s.routes, r)
	}
	sort.Strings(s.routes)
}

func emit(b *bytes.Buffer, tf tableFile, all []*svc, groups map[string][]*svc, shared map[string]bool, modelsSum string) {
	p := func(f string, a ...any) { fmt.Fprintf(b, f, a...) }
	p("// Code generated by tools/gen from the service table and the engine's Smithy models. DO NOT EDIT.\n\n")
	p("package main\n\n")
	p("// What this file was made from.\nconst (\n\tgenEngine       = %q\n\tgenEngineCommit = %q // gitleaks:allow (a commit id, not a secret)\n\tgenTableSHA     = %q\n\tgenModelsSHA    = %q\n)\n\n", tf.Engine, tf.EngineCommit, pinTableSHA, modelsSum)
	p("// Wire protocol bits of a service.\nconst (\n\tgpJSON  = %d\n\tgpQuery = %d\n\tgpCBOR  = %d\n\tgpREST  = %d\n\tgpXML   = %d\n)\n\n", pJSON, pQuery, pCBOR, pREST, pXML)
	p("// genRow is one service of the table. Ops holds the operation names (awsJson, Query and CBOR route by them) of a service that shares\n// its route key with another; Routes the REST routes (\"METHOD /uri Operation\", one per line) of a REST service.\n")
	p("type genRow struct {\n\tKey, RK, Endpoint, SDKID, Shape, Prefix, QVer string\n\tProto int\n\tShared bool\n\tOps, Routes, CFN string\n}\n\n")
	p("var genRows = []genRow{\n")
	for _, s := range all {
		ops, routes := "", ""
		if shared[s.rk] && s.proto&^(pREST|pXML) != 0 {
			ops = strings.Join(s.ops, " ")
		}
		if s.proto&pREST != 0 {
			routes = strings.Join(s.routes, "\n")
		}
		cfn := ""
		if s.t.CfnName != nil {
			cfn = *s.t.CfnName
		}
		p("\t{%q, %q, %q, %q, %q, %q, %q, %d, %v, %q, %q, %q},\n", s.t.Key, s.rk, s.ep, s.t.SDKID, s.shape, s.prefix, s.qver, s.proto, shared[s.rk], ops, routes, cfn)
	}
	p("}\n\n")
	// legacy keys
	legacy := map[string]string{}
	for _, s := range all {
		for _, a := range s.t.LegacyKeys {
			legacy[a] = s.t.Key
		}
	}
	p("// genLegacy: an older spelling of a service key and the key it stands for.\nvar genLegacy = map[string]string{\n")
	for _, k := range sortedKeys(legacy) {
		p("\t%q: %q,\n", k, legacy[k])
	}
	p("}\n\n")
	p("// genAltScopes: SigV4 scope names that are not a signing name and that the engine serves one service under.\nvar genAltScopes = map[string]string{\n")
	for _, k := range sortedKeys(altScopes) {
		p("\t%q: %q,\n", k, altScopes[k])
	}
	p("}\n\n")
	p("// genTieBreak: the member of a shared route key the engine serves when nothing tells the members apart (protocol class -> key).\nvar genTieBreak = map[string]map[string]string{\n")
	for _, rk := range sortedKeys(tieBreak) {
		p("\t%q: {", rk)
		for _, c := range sortedKeys(tieBreak[rk]) {
			p("%q: %q, ", c, tieBreak[rk][c])
		}
		p("},\n")
	}
	p("}\n")
}

func sortedKeys[V any](m map[string]V) []string {
	var k []string
	for x := range m {
		k = append(k, x)
	}
	sort.Strings(k)
	return k
}

var trailingVersion = regexp.MustCompile(`_\d+$`)

func normPrefix(p string) string { return trailingVersion.ReplaceAllString(strings.ToLower(p), "") }

func segs(uri string) []string {
	var out []string
	for _, s := range strings.Split(uri, "/") {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// tmplShape: a template with its label names removed ({Bucket} -> {}, {Key+} -> {+}), so two templates that differ only in what they call a label compare equal.
func tmplShape(uri string) string {
	var out []string
	for _, s := range segs(uri) {
		switch {
		case strings.HasSuffix(s, "+}"):
			out = append(out, "{+}")
		case strings.HasPrefix(s, "{"):
			out = append(out, "{}")
		default:
			out = append(out, s)
		}
	}
	return strings.Join(out, "/")
}

// unify: whether two URI templates can match the same path.
func unify(a, b []string) bool {
	for i := 0; i < len(a) && i < len(b); i++ {
		x, y := a[i], b[i]
		if strings.HasSuffix(x, "+}") || strings.HasSuffix(y, "+}") {
			return true
		}
		if strings.HasPrefix(x, "{") || strings.HasPrefix(y, "{") {
			continue
		}
		if x != y {
			return false
		}
	}
	return len(a) == len(b)
}

func report(b *bytes.Buffer, all []*svc, groups map[string][]*svc, shared map[string]bool) {
	p := func(f string, a ...any) { fmt.Fprintf(b, f, a...) }
	p("Shared signing names: how the members of each are told apart (services_gen.go, %s)\n", pinEngine)
	p("Order of the signals the front reads: the SigV4 scope names the route key; then the wire protocol (the protocols the member speaks);\nthen the operation (X-Amz-Target operation, Query Action, CBOR path operation, or the REST method and URI template);\nthen the awsJson target prefix (exact, then without the _<date> suffix) or the Query Version; then the most specific REST template;\nthen the verified tie-break for the route key. What is still more than one member is refused.\n\n")
	var rks []string
	for rk := range shared {
		rks = append(rks, rk)
	}
	sort.Strings(rks)
	unseparated := 0
	for _, rk := range rks {
		g := groups[rk]
		p("== %s  (%d services)\n", rk, len(g))
		for _, s := range g {
			p("   %-34s protocols=%s", s.t.Key, strings.Join(s.t.Protocols, ","))
			if s.prefix != "" {
				p(" target=%s", s.prefix)
			}
			if s.qver != "" {
				p(" version=%s", s.qver)
			}
			p(" ops=%d\n", len(s.ops))
		}
		for i := 0; i < len(g); i++ {
			for j := i + 1; j < len(g); j++ {
				A, B := g[i], g[j]
				how := pair(A, B, rk)
				p("   %s | %s: %s\n", A.t.Key, B.t.Key, how.text)
				if how.bad {
					unseparated++
				}
			}
		}
		p("\n")
	}
	p("pairs with a signal the front cannot separate on its own: %d (each is refused when it arises, unless a tie-break above names the member)\n", unseparated)
}

type sep struct {
	text string
	bad  bool
}

func pair(A, B *svc, rk string) sep {
	var parts []string
	bad := false
	ca, cb := A.proto&^(pREST|pXML), B.proto&^(pREST|pXML)
	restA, restB := A.proto&pREST != 0, B.proto&pREST != 0
	classes := []struct {
		bit  int
		name string
	}{{pJSON, "json"}, {pQuery, "query"}, {pCBOR, "cbor"}}
	for _, c := range classes {
		if ca&c.bit == 0 || cb&c.bit == 0 {
			continue
		}
		ov := overlap(A.ops, B.ops)
		switch c.bit {
		case pJSON:
			switch {
			case A.prefix != B.prefix && A.prefix != "" && B.prefix != "":
				if normPrefix(A.prefix) == normPrefix(B.prefix) {
					parts = append(parts, "json: target prefix differs only by the _<date> suffix (exact prefix)")
				} else {
					parts = append(parts, "json: target prefix")
				}
			case len(ov) == 0:
				parts = append(parts, "json: disjoint operations")
			case tieBreak[rk]["json"] != "":
				parts = append(parts, fmt.Sprintf("json: %d operations in common, same prefix; tie-break serves %s", len(ov), tieBreak[rk]["json"]))
			default:
				parts = append(parts, fmt.Sprintf("json: %d operations in common, same prefix: NOT SEPARABLE (common operations refused)", len(ov)))
				bad = true
			}
		case pQuery:
			switch {
			case A.qver != B.qver:
				parts = append(parts, "query: Version")
			case len(ov) == 0:
				parts = append(parts, "query: disjoint operations")
			case tieBreak[rk]["query"] != "":
				parts = append(parts, fmt.Sprintf("query: %d operations in common, same Version; tie-break serves %s", len(ov), tieBreak[rk]["query"]))
			default:
				parts = append(parts, fmt.Sprintf("query: %d operations in common, same Version: NOT SEPARABLE (common operations refused)", len(ov)))
				bad = true
			}
		case pCBOR:
			if len(overlap(A.ops, B.ops)) == 0 {
				parts = append(parts, "cbor: disjoint operations")
			} else {
				parts = append(parts, "cbor: operations in common; the engine reads only the operation from the path")
				bad = true
			}
		}
	}
	if restA && restB {
		n := 0
		exact := 0
		for _, ra := range A.routes {
			fa := strings.SplitN(ra, " ", 3)
			for _, rb := range B.routes {
				fb := strings.SplitN(rb, " ", 3)
				if fa[0] == fb[0] && unify(segs(fa[1]), segs(fb[1])) {
					n++
					if tmplShape(fa[1]) == tmplShape(fb[1]) {
						exact++
					}
				}
			}
		}
		switch {
		case n == 0:
			parts = append(parts, "rest: route tables are disjoint")
		case exact == 0:
			parts = append(parts, fmt.Sprintf("rest: %d overlapping route pairs, resolved by the more specific template", n))
		default:
			parts = append(parts, fmt.Sprintf("rest: %d overlapping route pairs, %d with the same template: NOT SEPARABLE (those routes refused)", n, exact))
			bad = true
		}
	}
	if (restA && cb != 0) || (restB && ca != 0) {
		parts = append(parts, "rest/rpc: a REST member and an RPC member (the RPC member needs an X-Amz-Target, Action or CBOR path, the REST member a method and path that match a route)")
	}
	if len(parts) == 0 {
		parts = append(parts, "no protocol in common")
	}
	return sep{strings.Join(parts, "; "), bad}
}

func overlap(a, b []string) []string {
	m := map[string]bool{}
	for _, x := range a {
		m[x] = true
	}
	var out []string
	for _, y := range b {
		if m[y] {
			out = append(out, y)
		}
	}
	return out
}

func write(dir, name string, data []byte, check bool) {
	path := filepath.Join(dir, name)
	if check {
		cur, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(cur, data) {
			fmt.Fprintln(os.Stderr, name, "differs from what the generator writes")
			os.Exit(1)
		}
		return
	}
	must(os.WriteFile(path, data, 0o644))
}

func sha(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func must(err error) {
	if err != nil {
		fatal(err.Error())
	}
}
func fatal(msg string) { fmt.Fprintln(os.Stderr, "gen:", msg); os.Exit(1) }
