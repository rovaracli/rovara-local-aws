package main

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// The heavy-function detector: the first piece of the function runner's registry (designs-2026-10-30/slice4-function-runner-design.md,
// section 2). The engine runs a Lambda function in-process, python and nodejs only, with no host files, network or processes. A
// function it cannot run is still accepted at create time, and when SNS, EventBridge or S3 invokes it the engine reports success
// while the code never ran. Until the runner exists, the front cannot run such a function either, so it SAYS so: it never blocks, it
// records.
//
// Where it looks (planned mode, the lambda service): CreateFunction, UpdateFunctionCode, UpdateFunctionConfiguration,
// PublishLayerVersion, and a CloudFormation template the front can read (cfn.go). What makes a function heavy, first match wins:
//
//	image        PackageType Image (or an ImageUri)
//	runtime      a runtime the engine cannot run: anything but python* and nodejs* (java21, provided.al2023, dotnet, ruby, go)
//	x86-native   an ELF file in the package or in an attached layer, built for x86-64 or declared Architectures x86_64
//	native-code  any other ELF file (.so, .node, a bundled binary): the ELF magic is what counts, not the name
//	unchecked    the package or a layer is too large to look at (above lambdaInspectCap), or an attached layer was not looked at
//
// What is recorded: in the ledger, a call to service lambda, answered 200 and counted unsupported, with the operation
// `heavy-function:<reason>`, once per function name (again only when the reason changes), and once more for every Invoke of the
// function that the front sees; the ledger entry carries the function name in a `function` field (GET /_rovara/ledger). The
// registry itself is readable at GET /_rovara/lambda/heavy. A function that stops being heavy (a new code update) leaves the
// registry; DeleteFunction and /_rovara/reset empty it.

const (
	lambdaInspectCap  = 16 << 20 // the most of a request body (a zip in base64, a template) the front reads to look at a package
	lambdaObjectCap   = 16 << 20 // the most of a package it reads from the engine's S3 over loopback
	zipMaxEntries     = 20000
	zipMaxDirectory   = 8 << 20 // the largest central directory the judge reads
	zipMaxDeclared    = 8 << 30 // declared uncompressed bytes above this: judged unsafe (a bomb); never read anyway
	zipMaxRatio       = 2000
	heavyPrefix       = "heavy-function:"
	elfMachineX8664   = 0x3E
	elfMachineAArch64 = 0xB7
)

// elfKind is what the ELF files of a package are built for.
type elfKind int

const (
	elfNone elfKind = iota
	elfOther
	elfX86
)

type zipVerdict struct {
	ELF     elfKind
	Unsafe  bool // names that escape, links, a bomb, too many entries: the package is not taken apart, and says so
	Entries int
}

// judgeZip looks at a zip WITHOUT extracting anything: it reads the central directory (bounded by the size it was given), and from
// each regular entry at most 20 bytes, to see the ELF magic and the machine. Names that escape, absolute names, links and entries
// that declare an absurd size or ratio mark the zip unsafe; they are not followed or read. A zip that does not parse is not a
// package (ok false): the engine refuses it itself.
func judgeZip(b []byte) (v zipVerdict, ok bool) {
	defer func() {
		if recover() != nil { // the standard reader should never panic; a corrupt input must still never reach the front's own stack
			v, ok = zipVerdict{Unsafe: true}, false
		}
	}()
	if big, found := zipDirectoryTooBig(b); found && big {
		return zipVerdict{Unsafe: true}, true // declared too many entries (or too large a directory): not read, reported unchecked
	}
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		return zipVerdict{}, false
	}
	var declared uint64
	for i, f := range zr.File {
		if i >= zipMaxEntries {
			v.Unsafe = true
			break
		}
		v.Entries++
		name := f.Name
		if strings.HasPrefix(name, "/") || strings.Contains(name, "\\") || strings.ContainsRune(name, 0) {
			v.Unsafe = true
		}
		for _, seg := range strings.Split(name, "/") {
			if seg == ".." {
				v.Unsafe = true
			}
		}
		declared += f.UncompressedSize64
		if f.UncompressedSize64 > 1<<20 && f.CompressedSize64 > 0 && f.UncompressedSize64/f.CompressedSize64 > zipMaxRatio {
			v.Unsafe = true
		}
		if declared > zipMaxDeclared {
			v.Unsafe = true
		}
		mode := f.Mode()
		switch {
		case mode.IsDir():
			continue
		case mode&os.ModeSymlink != 0:
			// a link is never followed: its target (the entry's data) is read, at most 1 KiB, to see whether it escapes the tree
			if rc, err := f.Open(); err == nil {
				t, _ := io.ReadAll(io.LimitReader(rc, 1024))
				rc.Close()
				if strings.HasPrefix(string(t), "/") || strings.Contains(string(t), "..") {
					v.Unsafe = true
				}
			}
			continue
		case !mode.IsRegular():
			v.Unsafe = true // a device, a pipe, a socket
			continue
		}
		if f.UncompressedSize64 < 4 || f.Flags&1 != 0 {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		head := make([]byte, 20)
		n, _ := io.ReadFull(io.LimitReader(rc, 20), head)
		rc.Close()
		if n < 4 || head[0] != 0x7f || head[1] != 'E' || head[2] != 'L' || head[3] != 'F' {
			continue
		}
		kind := elfOther
		if n >= 20 {
			var machine uint16
			if head[5] == 2 { // big endian
				machine = uint16(head[18])<<8 | uint16(head[19])
			} else {
				machine = uint16(head[19])<<8 | uint16(head[18])
			}
			if machine == elfMachineX8664 {
				kind = elfX86
			}
		}
		if kind > v.ELF {
			v.ELF = kind
		}
	}
	return v, true
}

// lambdaFn is what the registry knows of one function.
type lambdaFn struct {
	name      string
	prefix    bool // a CloudFormation function whose physical name is <name>-<random>
	runtime   string
	image     bool
	arches    []string
	layers    []string
	elf       elfKind // of the package
	unchecked bool    // the package was too large to look at
	timeout   int     // the configured Timeout, seconds (0: not given, the default 3)
}

type layerInfo struct {
	elf       elfKind
	unchecked bool
}

type heavyRegistry struct {
	mu       sync.Mutex
	fns      map[string]*lambdaFn
	layers   map[string]layerInfo // by layer version ARN
	recorded map[string]string    // function name -> the reason last recorded
	invokes  map[string]int64
	// longTimeout: the function runner is on, so a function configured to run longer than the engine lets any run is heavy too (decision 119)
	longTimeout bool
}

func newHeavyRegistry() *heavyRegistry {
	return &heavyRegistry{fns: map[string]*lambdaFn{}, layers: map[string]layerInfo{}, recorded: map[string]string{}, invokes: map[string]int64{}}
}

func (h *heavyRegistry) reset() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.fns, h.layers = map[string]*lambdaFn{}, map[string]layerInfo{}
	h.recorded, h.invokes = map[string]string{}, map[string]int64{}
}

func engineRuns(runtime string) bool {
	r := strings.ToLower(runtime)
	return strings.HasPrefix(r, "python") || strings.HasPrefix(r, "nodejs")
}

// reason is why the function is heavy, or "" when the engine can run it. h.mu is held.
func (h *heavyRegistry) reason(f *lambdaFn) string {
	if f.image {
		return "image"
	}
	if f.runtime != "" && !engineRuns(f.runtime) {
		return "runtime"
	}
	elf, unchecked := f.elf, f.unchecked
	for _, l := range f.layers {
		li, known := h.layers[l]
		if !known {
			continue // a layer the front never saw published (AWS's own, or another run's): nothing to say
		}
		if li.elf > elf {
			elf = li.elf
		}
		unchecked = unchecked || li.unchecked
	}
	declaredX86 := false
	for _, a := range f.arches {
		if a == "x86_64" {
			declaredX86 = true
		}
	}
	switch {
	case elf == elfX86 || (elf != elfNone && declaredX86):
		return "x86-native"
	case elf != elfNone:
		return "native-code"
	case unchecked:
		return "unchecked"
	case h.longTimeout && f.timeout > ceilingMs/1000:
		return "long-timeout"
	}
	return ""
}

// reasonOf is reason with the lock taken.
func (h *heavyRegistry) reasonOf(f *lambdaFn) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.reason(f)
}

// bareFunctionName: the function name of what an Invoke or an update names: a name, a partial or full ARN, with or without a qualifier.
func bareFunctionName(s string) string {
	if u, err := url.PathUnescape(s); err == nil {
		s = u
	}
	if i := strings.Index(s, ":function:"); i >= 0 {
		s = s[i+len(":function:"):]
	} else if parts := strings.Split(s, ":"); len(parts) == 3 && len(parts[0]) == 12 { // account:function:name
		s = parts[2]
	}
	if i := strings.Index(s, ":"); i >= 0 {
		s = s[:i]
	}
	return s
}

// lookup finds a registered function by the name an Invoke used. h.mu is held.
func (h *heavyRegistry) lookup(name string) *lambdaFn {
	if f := h.fns[name]; f != nil {
		return f
	}
	for _, f := range h.fns {
		if f.prefix && strings.HasPrefix(name, f.name+"-") {
			return f
		}
	}
	return nil
}

// ---- the request bodies

type lambdaCode struct {
	ZipFile         string `json:"ZipFile"`
	S3Bucket        string `json:"S3Bucket"`
	S3Key           string `json:"S3Key"`
	S3ObjectVersion string `json:"S3ObjectVersion"`
	ImageURI        string `json:"ImageUri"`
}

type lambdaRequest struct {
	FunctionName  string      `json:"FunctionName"`
	Runtime       string      `json:"Runtime"`
	PackageType   string      `json:"PackageType"`
	Architectures []string    `json:"Architectures"`
	Layers        []string    `json:"Layers"`
	Timeout       int         `json:"Timeout"`
	Code          *lambdaCode `json:"Code"`
	Content       *lambdaCode `json:"Content"`
	// UpdateFunctionCode carries the code members at the top
	ZipFile  string `json:"ZipFile"`
	S3Bucket string `json:"S3Bucket"`
	S3Key    string `json:"S3Key"`
	// the object version the package is taken from: the front reads the latest object, so a named version is unchecked
	S3ObjectVersion string `json:"S3ObjectVersion"`
	ImageURI        string `json:"ImageUri"`
}

func (r *lambdaRequest) code() lambdaCode {
	if r.Code != nil {
		return *r.Code
	}
	if r.Content != nil {
		return *r.Content
	}
	return lambdaCode{ZipFile: r.ZipFile, S3Bucket: r.S3Bucket, S3Key: r.S3Key, S3ObjectVersion: r.S3ObjectVersion, ImageURI: r.ImageURI}
}

// judgeCode looks at the package a code member names: inline (base64), or an object of the engine's own S3.
func (s *Server) judgeCode(c lambdaCode, bodyTruncated bool) (kind elfKind, unchecked bool) {
	var pkg []byte
	switch {
	case c.ZipFile != "":
		if bodyTruncated {
			return elfNone, true
		}
		b, err := base64.StdEncoding.DecodeString(c.ZipFile)
		if err != nil {
			return elfNone, false // the engine refuses it
		}
		pkg = b
	case c.S3Bucket != "" && c.S3Key != "":
		if c.S3ObjectVersion != "" {
			return elfNone, true
		}
		b, ok := s.engineObject("/"+url.PathEscape(c.S3Bucket)+"/"+escapeKey(c.S3Key), lambdaObjectCap)
		if !ok {
			return elfNone, true
		}
		pkg = b
	default:
		return elfNone, false
	}
	v, ok := judgeZip(pkg)
	if !ok {
		return elfNone, false
	}
	// a package judged unsafe (names that escape, a bomb, more entries than the judge reads) was not read to the end, so what it holds
	// is not known: whatever ELF file was seen counts, and the rest is unchecked
	return v.ELF, v.Unsafe
}

// read-only after start: the members looked for in the ends of a body too large to read whole
var headStringRe = map[string]*regexp.Regexp{}

func init() {
	for _, k := range []string{"FunctionName", "Runtime", "PackageType"} {
		headStringRe[k] = regexp.MustCompile(`"` + k + `"\s*:\s*"([^"\\]*)"`)
	}
}

// tailKeeper passes a reader through and keeps the last bytes that went by.
type tailKeeper struct {
	r    io.Reader
	tail []byte
}

func (t *tailKeeper) Read(p []byte) (int, error) {
	n, err := t.r.Read(p)
	if n > 0 {
		t.tail = append(t.tail, p[:n]...)
		if len(t.tail) > 128<<10 {
			t.tail = append([]byte(nil), t.tail[len(t.tail)-64<<10:]...)
		}
	}
	return n, err
}

func (t *tailKeeper) last() []byte {
	if t == nil {
		return nil
	}
	if len(t.tail) > 64<<10 {
		return t.tail[len(t.tail)-64<<10:]
	}
	return t.tail
}

func headString(head []byte, key string) string {
	if re := headStringRe[key]; re != nil {
		if m := re.FindSubmatch(head); m != nil {
			return string(m[1])
		}
	}
	return ""
}

func escapeKey(k string) string {
	parts := strings.Split(k, "/")
	for i, p := range parts {
		parts[i] = url.PathEscape(p)
	}
	return strings.Join(parts, "/")
}

// lambdaChange is what one request does to the registry, read before the request is forwarded and applied when the engine accepts it.
type lambdaChange struct {
	head    []byte      // CreateFunction too large to read whole: the head of the body,
	tk      *tailKeeper // and its tail once it has been forwarded, where the settings that come late are found
	op      string
	name    string
	fn      *lambdaFn // CreateFunction: the whole function
	patch   func(*lambdaFn)
	layer   string // PublishLayerVersion: the layer name (the version ARN is in the answer)
	layerLI layerInfo
}

// planLambda reads a Lambda request into a change. body is the (possibly truncated) request body.
func (s *Server) planLambda(op, rawPath string, body []byte, truncated bool) *lambdaChange {
	segs := splitPath(rawPath)
	nameAt := func(i int) string {
		if len(segs) > i {
			return bareFunctionName(segs[i])
		}
		return ""
	}
	var req lambdaRequest
	parse := func() bool {
		if truncated {
			return false
		}
		return json.Unmarshal(body, &req) == nil
	}
	switch op {
	case "CreateFunction":
		ok := parse()
		if !ok && !truncated {
			return nil
		}
		fn := &lambdaFn{name: req.FunctionName, runtime: req.Runtime, arches: req.Architectures, layers: req.Layers, timeout: req.Timeout}
		if !ok { // too large to read whole: the settings that come first are read from the head, the package is unchecked
			head := body
			if len(head) > 64<<10 {
				head = head[:64<<10]
			}
			fn.unchecked = true
			fn.name = bareFunctionName(headString(head, "FunctionName"))
			fn.runtime = headString(head, "Runtime")
			fn.image = strings.EqualFold(headString(head, "PackageType"), "Image")
			return &lambdaChange{op: op, name: fn.name, fn: fn, head: head}
		}
		c := req.code()
		fn.image = strings.EqualFold(req.PackageType, "Image") || c.ImageURI != ""
		if !fn.image {
			fn.elf, fn.unchecked = s.judgeCode(c, false)
		}
		fn.name = bareFunctionName(fn.name)
		return &lambdaChange{op: op, name: fn.name, fn: fn}
	case "UpdateFunctionCode":
		name := nameAt(2)
		ok := parse()
		if !ok && !truncated {
			return nil
		}
		c := req.code()
		arches := req.Architectures
		var kind elfKind
		var unchecked bool
		if ok && c.ImageURI == "" {
			kind, unchecked = s.judgeCode(c, false)
		} else if !ok {
			unchecked = true
		}
		return &lambdaChange{op: op, name: name, patch: func(f *lambdaFn) {
			f.image = c.ImageURI != ""
			f.elf, f.unchecked = kind, unchecked
			if arches != nil {
				f.arches = arches
			}
		}}
	case "UpdateFunctionConfiguration":
		name := nameAt(2)
		if !parse() {
			return nil
		}
		return &lambdaChange{op: op, name: name, patch: func(f *lambdaFn) {
			if req.Runtime != "" {
				f.runtime = req.Runtime
			}
			if req.Layers != nil {
				f.layers = req.Layers
			}
			if req.Timeout != 0 {
				f.timeout = req.Timeout
			}
		}}
	case "PublishLayerVersion":
		layer := ""
		if len(segs) > 2 {
			layer, _ = url.PathUnescape(segs[2])
		}
		li := layerInfo{}
		if parse() {
			li.elf, li.unchecked = s.judgeCode(req.code(), false)
		} else if truncated {
			li.unchecked = true
		} else {
			return nil
		}
		return &lambdaChange{op: op, layer: layer, layerLI: li}
	}
	return nil
}

var layerARNRe = regexp.MustCompile(`"LayerVersionArn"\s*:\s*"([^"]+)"`)

// applyLambda applies an accepted change and records what became heavy. resp is the (small) answer of PublishLayerVersion.
func (s *Server) applyLambda(c *lambdaChange, resp []byte) {
	if c.op == "CreateFunction" && c.fn != nil && c.head != nil {
		// the body was too large to read whole: the name and settings are looked for at its two ends
		data := append(append([]byte(nil), c.head...), c.tk.last()...)
		if c.fn.name == "" {
			c.fn.name = bareFunctionName(headString(data, "FunctionName"))
		}
		if c.fn.name == "" {
			c.fn.name = "unknown-function"
		}
		if c.fn.runtime == "" {
			c.fn.runtime = headString(data, "Runtime")
		}
		c.fn.image = c.fn.image || strings.EqualFold(headString(data, "PackageType"), "Image")
		c.name = c.fn.name
	}
	h := s.heavy
	h.mu.Lock()
	var rec *lambdaFn
	switch c.op {
	case "CreateFunction":
		if c.fn != nil && c.fn.name != "" {
			h.fns[c.fn.name] = c.fn
			rec = c.fn
		}
	case "UpdateFunctionCode", "UpdateFunctionConfiguration":
		if f := h.fns[c.name]; f != nil {
			c.patch(f)
			rec = f
		} else if c.name != "" { // a function created before the front saw it (or by CloudFormation under another name)
			f := &lambdaFn{name: c.name}
			c.patch(f)
			h.fns[c.name] = f
			rec = f
		}
	case "PublishLayerVersion":
		if m := layerARNRe.FindSubmatch(resp); m != nil {
			h.layers[string(m[1])] = c.layerLI
		}
	}
	reason := ""
	if rec != nil {
		reason = h.reason(rec)
		if reason == "" {
			delete(h.fns, rec.name)
		}
	}
	record := rec != nil && reason != "" && h.recorded[rec.name] != reason
	if record {
		h.recorded[rec.name] = reason
	}
	h.mu.Unlock()
	if record && !s.runnerHandles(rec.name, reason) {
		s.ledger.recordUnsupported("lambda", heavyPrefix+reason, rec.name)
	}
}

// heavyRecorded: a function seen heavy (CloudFormation), recorded the same way.
func (s *Server) registerHeavy(f *lambdaFn) {
	h := s.heavy
	h.mu.Lock()
	h.fns[f.name] = f
	reason := h.reason(f)
	if reason == "" {
		delete(h.fns, f.name)
	}
	record := reason != "" && h.recorded[f.name] != reason
	if record {
		h.recorded[f.name] = reason
	}
	h.mu.Unlock()
	if record {
		s.ledger.recordUnsupported("lambda", heavyPrefix+reason, f.name)
	}
}

// noteInvoke counts an Invoke the front saw of a function the registry holds as heavy.
func (s *Server) noteInvoke(rawName string) {
	name := bareFunctionName(rawName)
	h := s.heavy
	h.mu.Lock()
	f := h.lookup(name)
	reason := ""
	if f != nil {
		reason = h.reason(f)
		h.invokes[f.name]++
	}
	h.mu.Unlock()
	if reason != "" {
		s.ledger.recordUnsupported("lambda", heavyPrefix+reason, name)
	}
}

func (s *Server) dropFunction(rawName string) {
	name := bareFunctionName(rawName)
	h := s.heavy
	h.mu.Lock()
	if f := h.lookup(name); f != nil {
		delete(h.fns, f.name)
	}
	h.mu.Unlock()
}

// heavyJSON: GET /_rovara/lambda/heavy, the registry as the worker's evidence reads it.
func (s *Server) heavyJSON() []byte {
	h := s.heavy
	h.mu.Lock()
	defer h.mu.Unlock()
	type row struct{ name, reason string }
	var rows []row
	for _, f := range h.fns {
		if r := h.reason(f); r != "" {
			rows = append(rows, row{f.name, r})
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].name < rows[j].name })
	var b strings.Builder
	b.WriteString(`{"runner":"` + s.runnerState() + `","functions":[`)
	for i, r := range rows {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"name":"%s","reason":"%s","invocations":%d}`, jsonEscape(r.name), r.reason, h.invokes[r.name])
	}
	b.WriteString(`]`)
	if s.runner != nil {
		// the functions the runner holds, with what ran where (the evidence lines read this)
		rows, _ := json.Marshal(s.runner.functionsJSON())
		b.WriteString(`,"runnerFunctions":` + string(rows))
	}
	b.WriteString(`}`)
	return []byte(b.String())
}

// lambdaOps are the operations the detector reads; Invoke and DeleteFunction only update the registry.
var lambdaOps = map[string]bool{"CreateFunction": true, "UpdateFunctionCode": true, "UpdateFunctionConfiguration": true, "PublishLayerVersion": true,
	"Invoke": true, "DeleteFunction": true}
