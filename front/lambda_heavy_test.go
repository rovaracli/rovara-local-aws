package main

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/url"
	"os"
	"strings"
	"testing"
)

type zent struct {
	name string
	data []byte
}

// testELF is the 20-byte head of an ELF file (class 64, little endian) for a machine, padded.
func testELF(machine uint16) []byte {
	b := make([]byte, 64)
	copy(b, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0})
	b[16], b[18], b[19] = 3, byte(machine), byte(machine>>8)
	return b
}

func testZip(files ...zent) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range files {
		w, _ := zw.Create(f.name)
		w.Write(f.data)
	}
	zw.Close()
	return buf.Bytes()
}

func testZipWithSymlink(target string) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	h := &zip.FileHeader{Name: "link", Method: zip.Store}
	h.SetMode(os.ModeSymlink | 0o777)
	w, _ := zw.CreateHeader(h)
	w.Write([]byte(target))
	zw.Close()
	return buf.Bytes()
}

// a zip whose central directory declares 100 GiB for an entry of ten stored bytes
func testZipBomb() []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	h := &zip.FileHeader{Name: "big.bin", Method: zip.Deflate, CompressedSize64: 10, UncompressedSize64: 100 << 30}
	w, _ := zw.CreateRaw(h)
	w.Write([]byte("0123456789"))
	zw.Close()
	return buf.Bytes()
}

func TestJudgeZip(t *testing.T) {
	py := zent{"index.py", []byte("def handler(e, c): return 1")}
	for _, c := range []struct {
		name   string
		zip    []byte
		elf    elfKind
		unsafe bool
		ok     bool
	}{
		{"plain python", testZip(py), elfNone, false, true},
		{"a .so that is text", testZip(py, zent{"lib/x.so", []byte("not an elf file at all")}), elfNone, false, true},
		{"an aarch64 .so", testZip(py, zent{"lib/x.so", testELF(elfMachineAArch64)}), elfOther, false, true},
		{"an x86-64 .so", testZip(py, zent{"lib/x.so", testELF(elfMachineX8664)}), elfX86, false, true},
		{"an executable with no extension", testZip(py, zent{"bin/tool", testELF(elfMachineAArch64)}), elfOther, false, true},
		{"a .node module", testZip(py, zent{"node_modules/a/b.node", testELF(elfMachineX8664)}), elfX86, false, true},
		{"a relative link is allowed", testZipWithSymlink("libfoo.so.1.2"), elfNone, false, true},
		{"a link out of the tree", testZipWithSymlink("../../../etc/passwd"), elfNone, true, true},
		{"an absolute link", testZipWithSymlink("/etc/passwd"), elfNone, true, true},
		{"a traversing name is flagged and never extracted", testZip(py, zent{"../../evil.so", testELF(elfMachineAArch64)}), elfOther, true, true},
		{"an absolute name", testZip(zent{"/etc/cron.d/x", []byte("x")}), elfNone, true, true},
		{"a declared bomb", testZipBomb(), elfNone, true, true},
		{"not a zip", []byte("PK nothing like a zip"), elfNone, false, false},
		{"empty", nil, elfNone, false, false},
	} {
		v, ok := judgeZip(c.zip)
		if ok != c.ok || v.ELF != c.elf || v.Unsafe != c.unsafe {
			t.Errorf("%s: got ok=%v elf=%v unsafe=%v, want ok=%v elf=%v unsafe=%v", c.name, ok, v.ELF, v.Unsafe, c.ok, c.elf, c.unsafe)
		}
	}
	// too many entries: the directory is refused before any entry is built, flagged, no crash
	var many []zent
	for i := 0; i < zipMaxEntries+50; i++ {
		many = append(many, zent{fmt.Sprintf("f%d.txt", i), []byte("x")})
	}
	if v, ok := judgeZip(testZip(many...)); !ok || !v.Unsafe || v.Entries != 0 {
		t.Errorf("a zip of %d entries: %+v %v", len(many), v, ok)
	}
	// corrupt bytes after a good prefix never crash the judge
	good := testZip(zent{"a.py", []byte("x")}, zent{"b.so", testELF(elfMachineAArch64)})
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 300; i++ {
		b := append([]byte(nil), good...)
		for j := 0; j < 1+rng.Intn(8); j++ {
			b[rng.Intn(len(b))] = byte(rng.Intn(256))
		}
		judgeZip(b[:len(b)-rng.Intn(len(b)/2)])
	}
}

func FuzzJudgeZip(f *testing.F) {
	f.Add(testZip(zent{"a.py", []byte("x")}, zent{"b.so", testELF(elfMachineAArch64)}))
	f.Add(testZipBomb())
	f.Add(testZipWithSymlink("../x"))
	f.Fuzz(func(t *testing.T, b []byte) { judgeZip(b) })
}

// ---- end to end through the front

type lamFront struct {
	*testFront
}

func startLambdaFront(t *testing.T, planned ...string) *lamFront {
	f := startFront(t, func(c *Config) {
		c.Planned = map[string]bool{}
		for _, p := range planned {
			c.Planned[p] = true
		}
		c.PlannedKeys = planned
	})
	f.srv.ledger.planned = true
	return &lamFront{f}
}

func (f *lamFront) lambda(method, path string, body any) result {
	b, _ := json.Marshal(body)
	return f.do(method, path, with(scopeHdr("lambda"), "Content-Type", "application/json"), string(b))
}

func (f *lamFront) create(name, runtime string, extra map[string]any, zipBytes []byte) result {
	req := map[string]any{"FunctionName": name, "Runtime": runtime, "Role": "arn:aws:iam::000000000000:role/r", "Handler": "index.handler",
		"Code": map[string]any{"ZipFile": base64.StdEncoding.EncodeToString(zipBytes)}}
	for k, v := range extra {
		req[k] = v
	}
	return f.lambda("POST", "/2015-03-31/functions", req)
}

type opCounts struct{ Calls, Unsupported int64 }

func (f *lamFront) counts(service string) map[string]opCounts {
	var sum map[string]struct{ Operations map[string]opCounts }
	json.Unmarshal([]byte(f.do("GET", "/_rovara/ledger/summary", tok(), "").body), &sum)
	return sum[service].Operations
}

func (f *lamFront) heavy() map[string][2]any {
	var d struct {
		Runner    string
		Functions []struct {
			Name        string
			Reason      string
			Invocations int64
		}
	}
	json.Unmarshal([]byte(f.do("GET", "/_rovara/lambda/heavy", tok(), "").body), &d)
	out := map[string][2]any{}
	for _, fn := range d.Functions {
		out[fn.Name] = [2]any{fn.Reason, fn.Invocations}
	}
	return out
}

func (f *lamFront) entryFunctions() map[string]string {
	var d struct {
		Entries []struct {
			Service, Operation, Function string
			Unsupported                  bool
		}
	}
	json.Unmarshal([]byte(f.do("GET", "/_rovara/ledger?service=lambda", tok(), "").body), &d)
	out := map[string]string{}
	for _, e := range d.Entries {
		if strings.HasPrefix(e.Operation, heavyPrefix) && e.Unsupported {
			out[e.Function] = strings.TrimPrefix(e.Operation, heavyPrefix)
		}
	}
	return out
}

func TestHeavyFunctionDetection(t *testing.T) {
	f := startLambdaFront(t, "lambda")
	py := zent{"index.py", []byte("def handler(e, c): return 1")}
	so := func(m uint16) zent { return zent{"lib/native.so", testELF(m)} }
	want := map[string]string{}
	expect := func(name, reason string, r result) {
		t.Helper()
		if r.status != 200 {
			t.Fatalf("%s: the front never blocks: %d %s", name, r.status, r.body)
		}
		if reason != "" {
			want[name] = reason
		}
	}
	expect("light-py", "", f.create("light-py", "python3.12", nil, testZip(py)))
	expect("light-node", "", f.create("light-node", "nodejs20.x", map[string]any{"Architectures": []string{"x86_64"}}, testZip(py)))
	expect("native", "native-code", f.create("native", "python3.12", nil, testZip(py, so(elfMachineAArch64))))
	expect("native-x86-built", "x86-native", f.create("native-x86-built", "python3.12", nil, testZip(py, so(elfMachineX8664))))
	expect("native-x86-declared", "x86-native", f.create("native-x86-declared", "python3.12", map[string]any{"Architectures": []string{"x86_64"}}, testZip(py, so(elfMachineAArch64))))
	expect("native-arm-declared", "native-code", f.create("native-arm-declared", "python3.12", map[string]any{"Architectures": []string{"arm64"}}, testZip(py, so(elfMachineAArch64))))
	expect("java", "runtime", f.create("java", "java21", nil, testZip(py)))
	expect("custom", "runtime", f.create("custom", "provided.al2023", nil, testZip(py)))
	expect("image", "image", f.lambda("POST", "/2015-03-31/functions", map[string]any{"FunctionName": "image", "PackageType": "Image", "Role": "r",
		"Code": map[string]any{"ImageUri": "000000000000.dkr.ecr.us-east-1.amazonaws.com/x:1"}}))
	// a layer with a .so makes the function that uses it heavy
	r := f.lambda("POST", "/2018-10-31/layers/nativelayer/versions", map[string]any{"Content": map[string]any{"ZipFile": base64.StdEncoding.EncodeToString(testZip(zent{"python/lib/x.so", testELF(elfMachineAArch64)}))}})
	if r.status != 201 {
		t.Fatalf("layer: %d %s", r.status, r.body)
	}
	f.lambda("POST", "/2018-10-31/layers/lightlayer/versions", map[string]any{"Content": map[string]any{"ZipFile": base64.StdEncoding.EncodeToString(testZip(py))}})
	expect("with-layer", "native-code", f.create("with-layer", "python3.12", map[string]any{"Layers": []string{"arn:aws:lambda:us-east-1:000000000000:layer:nativelayer:1"}}, testZip(py)))
	expect("with-light-layer", "", f.create("with-light-layer", "python3.12", map[string]any{"Layers": []string{"arn:aws:lambda:us-east-1:000000000000:layer:lightlayer:1"}}, testZip(py)))
	// the package is read from the engine's S3
	expect("from-s3", "native-code", f.lambda("POST", "/2015-03-31/functions", map[string]any{"FunctionName": "from-s3", "Runtime": "python3.12", "Code": map[string]any{"S3Bucket": "zipbkt", "S3Key": "heavy.zip"}}))
	expect("from-s3-light", "", f.lambda("POST", "/2015-03-31/functions", map[string]any{"FunctionName": "from-s3-light", "Runtime": "python3.12", "Code": map[string]any{"S3Bucket": "zipbkt", "S3Key": "light.zip"}}))
	expect("from-s3-missing", "unchecked", f.lambda("POST", "/2015-03-31/functions", map[string]any{"FunctionName": "from-s3-missing", "Runtime": "python3.12", "Code": map[string]any{"S3Bucket": "zipbkt", "S3Key": "none.zip"}}))
	// malicious packages: judged unsafe, never extracted, the front carries on; what they hold is not known, so they are unchecked (and native-code when an ELF file was seen)
	expect("evil-traversal", "unchecked", f.create("evil-traversal", "python3.12", nil, testZip(zent{"../../etc/x", []byte("x")})))
	expect("evil-traversal-elf", "native-code", f.create("evil-traversal-elf", "python3.12", nil, testZip(zent{"../../x.so", testELF(elfMachineAArch64)})))
	expect("evil-link", "unchecked", f.create("evil-link", "python3.12", nil, testZipWithSymlink("../../../etc/shadow")))
	expect("evil-bomb", "unchecked", f.create("evil-bomb", "python3.12", nil, testZipBomb()))
	expect("evil-garbage", "", f.create("evil-garbage", "python3.12", nil, []byte("this is not a zip")))
	// too large to look at: the head names the function, the package is unchecked
	big := make([]byte, lambdaInspectCap)
	expect("too-big", "unchecked", f.create("too-big", "python3.12", nil, big))

	got := f.heavy()
	for name, reason := range want {
		if g, ok := got[name]; !ok || g[0] != reason {
			t.Errorf("registry: %s should be %s, got %v", name, reason, got[name])
		}
	}
	for name := range got {
		if _, ok := want[name]; !ok {
			t.Errorf("registry: %s is not heavy", name)
		}
	}
	entries := f.entryFunctions()
	for name, reason := range want {
		if entries[name] != reason {
			t.Errorf("ledger entry of %s: %q, want %q", name, entries[name], reason)
		}
	}
	// the summary: lambda, unsupported, operation heavy-function:<reason>, a count per function
	c := f.counts("lambda")
	byReason := map[string]int64{}
	for _, reason := range want {
		byReason[reason]++
	}
	for reason, n := range byReason {
		if c[heavyPrefix+reason].Calls != n || c[heavyPrefix+reason].Unsupported != n {
			t.Errorf("summary heavy-function:%s: %+v, want %d calls, all unsupported", reason, c[heavyPrefix+reason], n)
		}
	}
	// once per function name: the same update again records nothing
	before := f.counts("lambda")[heavyPrefix+"native-code"].Calls
	f.lambda("PUT", "/2015-03-31/functions/native/code", map[string]any{"ZipFile": base64.StdEncoding.EncodeToString(testZip(py, so(elfMachineAArch64)))})
	if after := f.counts("lambda")[heavyPrefix+"native-code"].Calls; after != before {
		t.Errorf("a repeated heavy update is recorded once: %d -> %d", before, after)
	}
	// every Invoke the front sees of a heavy function is counted; of a light one, not; a partial ARN and a qualifier name the same function
	f.lambda("POST", "/2015-03-31/functions/native/invocations", map[string]any{})
	f.lambda("POST", "/2015-03-31/functions/arn:aws:lambda:us-east-1:000000000000:function:native:live/invocations", map[string]any{})
	f.lambda("POST", "/2015-03-31/functions/light-py/invocations", map[string]any{})
	if n := f.counts("lambda")[heavyPrefix+"native-code"].Calls; n != before+2 {
		t.Errorf("two invokes of a heavy function: %d -> %d", before, n)
	}
	if g := f.heavy()["native"]; g[1] != int64(2) {
		t.Errorf("the registry counts the invocations: %v", g)
	}
	// a function that stops being heavy leaves the registry; a deleted one is not counted any more
	f.lambda("PUT", "/2015-03-31/functions/native/code", map[string]any{"ZipFile": base64.StdEncoding.EncodeToString(testZip(py))})
	f.lambda("DELETE", "/2015-03-31/functions/java", nil)
	g := f.heavy()
	if _, ok := g["native"]; ok {
		t.Errorf("native is light now: %v", g["native"])
	}
	if _, ok := g["java"]; ok {
		t.Errorf("java is deleted: %v", g["java"])
	}
	before = f.counts("lambda")[heavyPrefix+"runtime"].Calls
	f.lambda("POST", "/2015-03-31/functions/java/invocations", map[string]any{})
	if after := f.counts("lambda")[heavyPrefix+"runtime"].Calls; after != before {
		t.Errorf("an invoke of a deleted function is not counted")
	}
	// UpdateFunctionConfiguration: a new runtime makes it heavy
	f.lambda("PUT", "/2015-03-31/functions/light-py/configuration", map[string]any{"Runtime": "dotnet8"})
	if g := f.heavy()["light-py"]; g[0] != "runtime" {
		t.Errorf("a runtime change to dotnet8: %v", g)
	}
	// the front still answers, and a reset empties the registry
	if r := f.do("GET", "/_rovara/health", nil, ""); r.status != 200 {
		t.Errorf("health after the malicious packages: %d", r.status)
	}
	if r := f.do("POST", "/_rovara/reset", tok(), ""); r.status != 200 {
		t.Fatalf("reset: %d", r.status)
	}
	if len(f.heavy()) != 0 {
		t.Errorf("reset empties the registry: %v", f.heavy())
	}
}

func TestHeavyFunctionOnlyInPlannedMode(t *testing.T) {
	f := startFront(t, nil)
	f.do("POST", "/2015-03-31/functions", with(scopeHdr("lambda"), "Content-Type", "application/json"), `{"FunctionName":"j","Runtime":"java21"}`)
	if s := f.do("GET", "/_rovara/ledger/summary", tok(), "").body; strings.Contains(s, "heavy-function") {
		t.Errorf("legacy mode records nothing: %s", s)
	}
}

func TestHeavyFunctionsFromCloudFormation(t *testing.T) {
	f := startLambdaFront(t, "cloudformation", "lambda")
	create := func(stack, tpl string) {
		form := url.Values{"Action": {"CreateStack"}, "Version": {"2010-05-15"}, "StackName": {stack}, "TemplateBody": {tpl}}
		if r := cfnCall(&testFront{t: t, srv: f.srv, ts: f.ts, engine: f.engine}, form.Encode()); r.status != 200 {
			t.Fatalf("%s: %d %s", stack, r.status, r.body)
		}
	}
	create("js", `{"Resources":{
		"Jv":{"Type":"AWS::Lambda::Function","Properties":{"Runtime":"java21","Handler":"x","Role":"r","Code":{"S3Bucket":"b","S3Key":"k"}}},
		"Named":{"Type":"AWS::Lambda::Function","Properties":{"FunctionName":"named-fn","Runtime":"python3.12","Code":{"S3Bucket":"zipbkt","S3Key":"heavy.zip"}}},
		"Fine":{"Type":"AWS::Lambda::Function","Properties":{"Runtime":"python3.12","Code":{"ZipFile":"def handler(e, c): return 1"}}}}}`)
	create("ym", "Resources:\n  Lay:\n    Type: AWS::Lambda::LayerVersion\n    Properties:\n      Content:\n        S3Bucket: zipbkt\n        S3Key: layer.zip\n"+
		"  Fn:\n    Type: AWS::Lambda::Function\n    Properties:\n      Runtime: python3.12\n      Handler: index.handler\n      Layers:\n        - !Ref Lay\n      Code:\n        ZipFile: |\n          def handler(e, c):\n              return 1\n"+
		"  Img:\n    Type: AWS::Lambda::Function\n    Properties:\n      PackageType: Image\n      Code:\n        ImageUri: 000000000000.dkr.ecr.us-east-1.amazonaws.com/x:1\n")
	create("bad", "Resources:\n  F:\n    Type: AWS::Lambda::Function\n    Properties: [unbalanced\n")
	g := f.heavy()
	for name, reason := range map[string]string{"js-Jv": "runtime", "named-fn": "native-code", "ym-Fn": "native-code", "ym-Img": "image"} {
		if g[name][0] != reason {
			t.Errorf("%s: %v, want %s (registry %v)", name, g[name], reason, g)
		}
	}
	if _, ok := g["js-Fine"]; ok {
		t.Errorf("an inline python function is light: %v", g)
	}
	// an invoke of the physical name (the logical name, then a random suffix)
	f.lambda("POST", "/2015-03-31/functions/js-Jv-ABC123/invocations", map[string]any{})
	if g := f.heavy()["js-Jv"]; g[1] != int64(1) {
		t.Errorf("an invoke of a CloudFormation function by its physical name: %v", g)
	}
	if c := f.counts("cloudformation-unchecked"); c["cloudformation:unparsed"].Calls != 1 {
		t.Errorf("a Lambda template that cannot be read is counted once: %v", c)
	}
}

func TestYAMLish(t *testing.T) {
	v, err := parseYAMLish("A: 1\nB:\n  - x\n  - y: 2\n    z: [a, 'b c']\nC: {Ref: Q}\nD: !Ref R\nE: !Sub \"${X}-y\"\nF: |\n  line1\n  line2\nG: 'it''s' # c\n")
	if err != nil {
		t.Fatal(err)
	}
	m := v.(map[string]any)
	if m["A"] != "1" || m["D"].(map[string]any)["Ref"] != "R" || m["C"].(map[string]any)["Ref"] != "Q" || m["G"] != "it's" || m["E"] != "${X}-y" {
		t.Errorf("scalars: %v", m)
	}
	b := m["B"].([]any)
	if b[0] != "x" || b[1].(map[string]any)["y"] != "2" || b[1].(map[string]any)["z"].([]any)[1] != "b c" {
		t.Errorf("sequence: %v", b)
	}
	if !strings.Contains(m["F"].(string), "line1\nline2") {
		t.Errorf("block scalar: %q", m["F"])
	}
	for _, bad := range []string{"", "a: &x 1\n", "a: [[1]]\n", "just text", "a: [x\n"} {
		if _, err := parseYAMLish(bad); err == nil {
			t.Errorf("%q should be refused", bad)
		}
	}
}
