package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// The heavy-function registry, version 2 (slice 4, designs-2026-10-30/slice4-function-runner-design.md, section 2).
//
// Version 1 (lambda_heavy.go) only recorded: a function the engine cannot run was accepted and never routed. Version 2 takes such a function
// over. At CreateFunction, UpdateFunctionCode and UpdateFunctionConfiguration the front keeps the real package (runner_store.go) and the real
// configuration, and forwards to the engine a request for the stub (runner_stub.go) under the same name: the engine's answer to the caller
// is then the real function's configuration (the overlay below), so nobody sees the stub.
//
// Which functions: the ones lambda_heavy.go calls heavy (an ELF file in the package or a layer, a runtime the engine cannot run, an
// image) and, decision 119, any function whose Timeout is above 28 s (the engine cuts every run at 30 s). The front also keeps small
// light functions' packages and configurations, so a later change (a native layer, a longer Timeout) can still move them to the runner.
// Once taken over a function stays with the runner for its life (the runner runs light code too).
//
// What the registry does not see: a function the engine creates itself (a CloudFormation template, a function that existed before the
// front) stays in the engine; it is recorded as heavy (version 1) and, if heavy, cannot run.

type fnVer struct {
	Version     string
	Runtime     string
	Handler     string
	Memory      int
	Timeout     int
	Ephemeral   int
	Env         map[string]string
	Layers      []string
	Arches      []string
	PackageType string
	ImageURI    string
	Role        string
	PkgSha      string
	PkgSize     int64
	Taken       bool   // the engine holds the stub for this version
	Reason      string // why it was taken (the heavy reason)
}

func (v *fnVer) clone() *fnVer {
	c := *v
	c.Env = make(map[string]string, len(v.Env))
	for k, x := range v.Env {
		c.Env[k] = x
	}
	c.Layers = append([]string(nil), v.Layers...)
	c.Arches = append([]string(nil), v.Arches...)
	return &c
}

type fnStats struct {
	Direct, ViaStub                       int64
	OK, FunctionErrors                    int64
	Cold, CeilingHits, Unsupported, Fails int64 // Fails: runner unavailable, throttled
	Async                                 int64
}

type fnState struct {
	name   string
	arn    string
	latest *fnVer
	vers   map[string]*fnVer
	stats  fnStats
	// refused: what the worker said when it could not take the function (native x86-64 code it can neither swap nor emulate); recorded in the
	// ledger once, as heavy-function:x86-native
	refused         string
	refusalRecorded bool
}

// noteRefusal remembers a refusal of the worker and returns the function's heavy reason and whether this is the first time to record it.
func (rg *runnerRegistry) noteRefusal(name, msg string) (reason string, first bool) {
	rg.mu.Lock()
	defer rg.mu.Unlock()
	st := rg.fns[name]
	if st == nil {
		return "", false
	}
	st.refused = msg
	first = !st.refusalRecorded
	st.refusalRecorded = true
	return st.latest.Reason, first
}

type layerBlob struct {
	sha  string
	size int64
}

type runnerRegistry struct {
	mu     sync.Mutex
	fns    map[string]*fnState
	layers map[string]layerBlob // by layer version ARN
	store  *runnerStore
}

func newRunnerRegistry(store *runnerStore) *runnerRegistry {
	return &runnerRegistry{fns: map[string]*fnState{}, layers: map[string]layerBlob{}, store: store}
}

func (rg *runnerRegistry) reset() {
	rg.mu.Lock()
	rg.fns, rg.layers = map[string]*fnState{}, map[string]layerBlob{}
	rg.mu.Unlock()
	rg.store.wipe()
}

// versionOf returns copies of the state's identity and one version's configuration. version "" or "$LATEST" is the latest.
func (rg *runnerRegistry) versionOf(name, version string) (arn string, v *fnVer, ok bool) {
	rg.mu.Lock()
	defer rg.mu.Unlock()
	st := rg.fns[name]
	if st == nil {
		return "", nil, false
	}
	if version == "" || version == "$LATEST" {
		return st.arn, st.latest.clone(), true
	}
	if x := st.vers[version]; x != nil {
		return st.arn, x.clone(), true
	}
	return st.arn, nil, false
}

func (rg *runnerRegistry) isTaken(name string) bool {
	rg.mu.Lock()
	defer rg.mu.Unlock()
	st := rg.fns[name]
	return st != nil && st.latest.Taken
}

func (rg *runnerRegistry) bump(name string, f func(*fnStats)) {
	rg.mu.Lock()
	defer rg.mu.Unlock()
	if st := rg.fns[name]; st != nil {
		f(&st.stats)
	}
}

// release drops the references a version holds.
func (rg *runnerRegistry) release(v *fnVer) {
	if v != nil {
		rg.store.unref(v.PkgSha)
	}
}

func (v *fnVer) unsupportedText() string {
	switch {
	case v.PackageType == "Image":
		return "container-image functions are not supported by the Rovara function runner yet"
	}
	return ""
}

func configHash(fn regFn) string {
	fn.ConfigHash = ""
	b, _ := json.Marshal(fn)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:8])
}

// regFor builds what the worker is told about one version. A layer the front never saw published has no bytes to send: that is the
// function's error (Rovara.Unsupported), not a silent omission.
func (rg *runnerRegistry) regFor(region, accountARN, name string, v *fnVer) (regFn, error) {
	fn := regFn{Name: name, Version: v.Version, Arn: accountARN, Runtime: v.Runtime, Handler: v.Handler, MemoryMb: v.Memory,
		TimeoutSeconds: v.Timeout, EphemeralMb: v.Ephemeral, Env: v.Env, Region: region, Architectures: v.Arches, PackageType: v.PackageType, ImageURI: v.ImageURI}
	if fn.Env == nil {
		fn.Env = map[string]string{}
	}
	if v.PkgSha != "" {
		fn.Package = &pkgRef{SHA256: v.PkgSha, SizeBytes: v.PkgSize}
	}
	rg.mu.Lock()
	var missing string
	for _, arn := range v.Layers {
		b, ok := rg.layers[arn]
		if !ok {
			missing = arn
			break
		}
		fn.Layers = append(fn.Layers, pkgRef{Arn: arn, SHA256: b.sha, SizeBytes: b.size})
	}
	rg.mu.Unlock()
	if missing != "" {
		return fn, &runnerError{"Rovara.Unsupported", "the layer " + missing + " was not published through this local AWS (its code is not available to the function runner)"}
	}
	fn.ConfigHash = configHash(fn)
	return fn, nil
}

// ---- request parsing

func rawStr(raw map[string]json.RawMessage, k string) (string, bool) {
	v, ok := raw[k]
	if !ok {
		return "", false
	}
	var s string
	if json.Unmarshal(v, &s) != nil {
		return "", false
	}
	return s, true
}

func rawInt(raw map[string]json.RawMessage, k string) (int, bool) {
	v, ok := raw[k]
	if !ok {
		return 0, false
	}
	var n int
	if json.Unmarshal(v, &n) != nil {
		return 0, false
	}
	return n, true
}

func rawStrings(raw map[string]json.RawMessage, k string) ([]string, bool) {
	v, ok := raw[k]
	if !ok {
		return nil, false
	}
	var l []string
	if json.Unmarshal(v, &l) != nil {
		return nil, false
	}
	return l, true
}

func rawEnv(raw map[string]json.RawMessage) (map[string]string, bool) {
	v, ok := raw["Environment"]
	if !ok {
		return nil, false
	}
	var e struct{ Variables map[string]string }
	if json.Unmarshal(v, &e) != nil {
		return nil, false
	}
	if e.Variables == nil {
		e.Variables = map[string]string{}
	}
	return e.Variables, true
}

func setRaw(raw map[string]json.RawMessage, k string, v interface{}) {
	b, _ := json.Marshal(v)
	raw[k] = b
}

// applyConfig merges the configuration members of a Create or Update request into v.
func applyConfig(v *fnVer, raw map[string]json.RawMessage) {
	if s, ok := rawStr(raw, "Runtime"); ok {
		v.Runtime = s
	}
	if s, ok := rawStr(raw, "Handler"); ok {
		v.Handler = s
	}
	if s, ok := rawStr(raw, "Role"); ok {
		v.Role = s
	}
	if n, ok := rawInt(raw, "MemorySize"); ok {
		v.Memory = n
	}
	if n, ok := rawInt(raw, "Timeout"); ok {
		v.Timeout = n
	}
	if l, ok := rawStrings(raw, "Layers"); ok {
		v.Layers = l
	}
	if l, ok := rawStrings(raw, "Architectures"); ok {
		v.Arches = l
	}
	if e, ok := rawEnv(raw); ok {
		v.Env = e
	}
	if s, ok := rawStr(raw, "PackageType"); ok {
		v.PackageType = s
	}
	if e, ok := raw["EphemeralStorage"]; ok {
		var es struct{ Size int }
		if json.Unmarshal(e, &es) == nil && es.Size > 0 {
			v.Ephemeral = es.Size
		}
	}
}

func newFnVer(raw map[string]json.RawMessage) *fnVer {
	v := &fnVer{Version: "$LATEST", Memory: 128, Timeout: 3, Ephemeral: 512, PackageType: "Zip", Env: map[string]string{}}
	applyConfig(v, raw)
	return v
}

// asLambdaFn is what lambda_heavy.go's reason() reads.
func (v *fnVer) asLambdaFn(name string, elf elfKind, unchecked bool) *lambdaFn {
	return &lambdaFn{name: name, runtime: v.Runtime, image: v.PackageType == "Image" || v.ImageURI != "", arches: v.Arches, layers: v.Layers,
		elf: elf, unchecked: unchecked, timeout: v.Timeout}
}

// ---- the plan of one request

// runnerPlan is what the front decided about one Lambda control-plane request before it is forwarded. body, when not nil, replaces the
// request body; commit runs when the engine accepted the request (resp is its answer, already read); abort runs when it did not.
type runnerPlan struct {
	gen    uint64 // the generation it was made in: a plan that outlives a reset commits nothing
	refuse bool   // the request names the runner's hidden plumbing: refused, never forwarded
	op     string
	name   string
	body   []byte
	commit func(resp []byte)
	abort  func()
}

// lightPackageMax is the most the front keeps of a package it did not take over (small functions only).
const lightPackageMax = 4 << 20

// runnerBodyCap is the most of a request body the front reads whole to take a function over (Lambda's 50 MB zip, base64, and the JSON).
const runnerBodyCap = 72 << 20

// runnerBigBody: a Lambda package body above this is parsed one at a time (runnerSys.big), and its copies are counted in the inspection budget.
const runnerBigBody = 4 << 20

var takeoverReasons = map[string]bool{"native-code": true, "runtime": true, "long-timeout": true, "x86-native": true, "image": true}

// codeBytes puts the package a Code member names into the store and returns the reference (the caller owns it).
func (r *runnerSys) codeBytes(c lambdaCode, limit int64) (sha string, size int64, err error) {
	switch {
	case c.ZipFile != "":
		// decoded as it is written to the store: no second copy of the package in memory
		return r.store.put(base64.NewDecoder(base64.StdEncoding, strings.NewReader(c.ZipFile)), limit)
	case c.S3Bucket != "" && c.S3Key != "":
		if c.S3ObjectVersion != "" {
			return "", 0, fmt.Errorf("a named object version is not read")
		}
		return r.fetchObject("/"+url.PathEscape(c.S3Bucket)+"/"+escapeKey(c.S3Key), limit)
	}
	return "", 0, fmt.Errorf("no package")
}

// stubify rewrites the members of a create or update request that the engine must see differently for a function it holds only as the stub.
func stubify(raw map[string]json.RawMessage, roleARN string, timeout int, hasTimeout bool) {
	setRaw(raw, "Runtime", stubRuntime)
	setRaw(raw, "Handler", stubHandler)
	setRaw(raw, "Role", roleARN)
	setRaw(raw, "MemorySize", 128)
	if hasTimeout {
		setRaw(raw, "Timeout", stubTimeout(timeout))
	}
	for _, k := range []string{"Layers", "PackageType", "ImageConfig", "Architectures"} {
		delete(raw, k)
	}
}

func stubTimeout(t int) int {
	t += stubTimeoutSlack
	if t > 900 {
		t = 900
	}
	return t
}

func marshalBody(raw map[string]json.RawMessage) []byte {
	b, _ := json.Marshal(raw)
	return b
}

// plan reads one Lambda request. lam is what lambda_heavy.go already made of it (never nil here); body is the whole body (truncated is
// false). A nil plan: forward unchanged and learn nothing.
func (r *runnerSys) plan(op, rawPath string, body []byte, lam *lambdaChange) *runnerPlan {
	gen := r.genNum()
	p := r.planInner(op, rawPath, body, lam)
	if p != nil {
		p.gen = gen
	}
	return p
}

func (r *runnerSys) planInner(op, rawPath string, body []byte, lam *lambdaChange) *runnerPlan {
	segs := splitPath(rawPath)
	nameAt := func(i int) string {
		if len(segs) > i {
			return bareFunctionName(segs[i])
		}
		return ""
	}
	if len(body) > runnerBigBody {
		// the parse below holds about three copies of the body (the body, the members, the code string): they are counted
		extra := 2 * int64(len(body))
		if !r.s.budget.reserve(extra) {
			return nil
		}
		defer r.s.budget.release(extra)
	}
	var raw map[string]json.RawMessage
	if len(body) > 0 && (op == "CreateFunction" || op == "UpdateFunctionCode" || op == "UpdateFunctionConfiguration" || op == "PublishLayerVersion") {
		// fail closed: a body that is not exactly one JSON object, or that names the hidden plumbing anywhere (the package itself is skipped),
		// is refused, never forwarded unchecked
		if found, err := scanJSON(body, dataKey); err != nil || found || json.Unmarshal(body, &raw) != nil {
			return &runnerPlan{refuse: true, op: op}
		}
	}
	switch op {
	case "CreateFunction":
		return r.planCreate(raw, lam)
	case "UpdateFunctionCode":
		return r.planUpdateCode(nameAt(2), raw, lam)
	case "UpdateFunctionConfiguration":
		return r.planUpdateConfig(nameAt(2), raw)
	case "PublishLayerVersion":
		return r.planLayer(raw)
	case "PublishVersion":
		return r.planPublish(nameAt(2))
	}
	return nil
}

func codeOf(raw map[string]json.RawMessage, key string) lambdaCode {
	var c lambdaCode
	if v, ok := raw[key]; ok {
		json.Unmarshal(v, &c)
	}
	return c
}

// topCode is the code member of an UpdateFunctionCode body (the members are at the top).
func topCode(raw map[string]json.RawMessage) lambdaCode {
	var c lambdaCode
	c.ZipFile, _ = rawStr(raw, "ZipFile")
	c.S3Bucket, _ = rawStr(raw, "S3Bucket")
	c.S3Key, _ = rawStr(raw, "S3Key")
	c.S3ObjectVersion, _ = rawStr(raw, "S3ObjectVersion")
	c.ImageURI, _ = rawStr(raw, "ImageUri")
	return c
}

func (r *runnerSys) planCreate(raw map[string]json.RawMessage, lam *lambdaChange) *runnerPlan {
	if raw == nil || lam.fn == nil {
		return nil
	}
	name, _ := rawStr(raw, "FunctionName")
	name = bareFunctionName(name)
	if name == "" {
		return nil
	}
	v := newFnVer(raw)
	code := codeOf(raw, "Code")
	if code.ImageURI != "" {
		v.PackageType, v.ImageURI = "Image", code.ImageURI
	}
	fn := v.asLambdaFn(name, lam.fn.elf, lam.fn.unchecked)
	reason := r.s.heavy.reasonOf(fn)
	taken := takeoverReasons[reason]
	limit := int64(lightPackageMax)
	if taken {
		limit = r.store.max
	}
	if v.PackageType != "Image" {
		sha, size, err := r.codeBytes(code, limit)
		switch {
		case err == nil:
			v.PkgSha, v.PkgSize = sha, size
		case taken:
			return nil // the package cannot be kept: the function stays with the engine and is recorded as unable to run
		}
	}
	if taken {
		v.Taken, v.Reason = true, reason
		for _, l := range v.Layers { // a layer must be one the front holds, or the runner cannot build the function
			r.reg.mu.Lock()
			_, ok := r.reg.layers[l]
			r.reg.mu.Unlock()
			if !ok {
				r.reg.release(v)
				return nil
			}
		}
		if len(r.stubSetup()) > 0 {
			r.reg.release(v)
			return nil
		}
	}
	p := &runnerPlan{op: "CreateFunction", name: name}
	if taken {
		hasT := raw["Timeout"] != nil
		stubify(raw, r.names().roleARN, v.Timeout, hasT)
		_, b64 := r.stub()
		setRaw(raw, "Code", map[string]string{"ZipFile": b64})
		p.body = marshalBody(raw)
	}
	p.abort = func() { r.reg.release(v) }
	p.commit = func(resp []byte) {
		var cfg struct{ FunctionArn, Version string }
		json.Unmarshal(resp, &cfg)
		arn := cfg.FunctionArn
		if arn == "" {
			arn = "arn:aws:lambda:" + r.s.cfg.Region + ":000000000000:function:" + name
		}
		r.reg.mu.Lock()
		old := r.reg.fns[name]
		st := &fnState{name: name, arn: arn, latest: v, vers: map[string]*fnVer{}}
		if old != nil { // a name created again (the engine refused? it accepted: the old one is gone)
			r.reg.releaseAllLocked(old)
		}
		r.reg.fns[name] = st
		if p, _ := rawBool(raw, "Publish"); p && cfg.Version != "" && cfg.Version != "$LATEST" {
			st.vers[cfg.Version] = v.cloneRef(r.store)
		}
		r.reg.mu.Unlock()
	}
	return p
}

func rawBool(raw map[string]json.RawMessage, k string) (bool, bool) {
	v, ok := raw[k]
	if !ok {
		return false, false
	}
	var b bool
	if json.Unmarshal(v, &b) != nil {
		return false, false
	}
	return b, true
}

// cloneRef copies a version and takes a reference to its package for the copy.
func (v *fnVer) cloneRef(st *runnerStore) *fnVer {
	c := v.clone()
	if c.PkgSha != "" {
		st.ref(c.PkgSha)
	}
	return c
}

func (rg *runnerRegistry) releaseAllLocked(st *fnState) {
	rg.store.unref(st.latest.PkgSha)
	for _, x := range st.vers {
		rg.store.unref(x.PkgSha)
	}
}

// stubSetup is a seam for the provisioning check: problems with the hidden plumbing that make takeover impossible (empty when ready).
func (r *runnerSys) stubSetup() []string {
	if err := r.ensureProvisioned(); err != nil {
		return []string{err.Error()}
	}
	return nil
}

// current returns a copy of the function's latest version, asking the engine for its configuration when the front never saw the
// function (created before the front, or by CloudFormation). The copy has no package.
func (r *runnerSys) current(name string) (*fnState, *fnVer) {
	r.reg.mu.Lock()
	st := r.reg.fns[name]
	var v *fnVer
	if st != nil {
		v = st.latest.clone()
	}
	r.reg.mu.Unlock()
	if v != nil {
		return st, v
	}
	cfg, ok := r.engineConfig(name)
	if !ok {
		return nil, nil
	}
	return nil, cfg
}

func (r *runnerSys) planUpdateCode(name string, raw map[string]json.RawMessage, lam *lambdaChange) *runnerPlan {
	if raw == nil || name == "" {
		return nil
	}
	if dry, _ := rawBool(raw, "DryRun"); dry {
		return nil
	}
	st, cur := r.current(name)
	if cur == nil {
		return nil
	}
	code := topCode(raw)
	nv := cur.clone()
	nv.Version = "$LATEST"
	if code.ImageURI != "" {
		nv.PackageType, nv.ImageURI, nv.PkgSha, nv.PkgSize = "Image", code.ImageURI, "", 0
	} else {
		nv.PackageType, nv.ImageURI = "Zip", ""
	}
	if a, ok := rawStrings(raw, "Architectures"); ok {
		nv.Arches = a
	}
	// what the engine's judge saw of the new package
	var elf elfKind
	var unchecked bool
	if lam != nil && lam.patch != nil {
		probe := &lambdaFn{}
		lam.patch(probe)
		elf, unchecked = probe.elf, probe.unchecked
	}
	reason := r.s.heavy.reasonOf(nv.asLambdaFn(name, elf, unchecked))
	wasTaken := st != nil && cur.Taken
	taken := wasTaken || takeoverReasons[reason]
	limit := int64(lightPackageMax)
	if taken {
		limit = r.store.max
	}
	oldSha := nv.PkgSha
	if nv.PackageType != "Image" {
		sha, size, err := r.codeBytes(code, limit)
		switch {
		case err == nil:
			nv.PkgSha, nv.PkgSize = sha, size
		case taken && !wasTaken:
			return nil
		default:
			nv.PkgSha, nv.PkgSize = "", 0
		}
	}
	if taken {
		nv.Taken = true
		if reason != "" {
			nv.Reason = reason
		}
		for _, l := range nv.Layers {
			r.reg.mu.Lock()
			_, ok := r.reg.layers[l]
			r.reg.mu.Unlock()
			if !ok && !wasTaken {
				r.reg.release(nv)
				return nil
			}
		}
		if !wasTaken && len(r.stubSetup()) > 0 {
			r.reg.release(nv)
			return nil
		}
	}
	p := &runnerPlan{op: "UpdateFunctionCode", name: name}
	if taken {
		_, b64 := r.stub()
		for _, k := range []string{"S3Bucket", "S3Key", "S3ObjectVersion", "ImageUri", "Architectures"} {
			delete(raw, k)
		}
		setRaw(raw, "ZipFile", b64)
		p.body = marshalBody(raw)
	}
	p.abort = func() { r.reg.release(nv) }
	p.commit = func(resp []byte) {
		var cfg struct{ FunctionArn, Version string }
		json.Unmarshal(resp, &cfg)
		r.reg.mu.Lock()
		cur := r.reg.fns[name]
		if cur == nil {
			arn := cfg.FunctionArn
			if arn == "" {
				arn = "arn:aws:lambda:" + r.s.cfg.Region + ":000000000000:function:" + name
			}
			cur = &fnState{name: name, arn: arn, vers: map[string]*fnVer{}}
			r.reg.fns[name] = cur
		} else {
			r.reg.store.unref(cur.latest.PkgSha) // the new version replaces the package; the old blob stays while a version holds it
		}
		cur.latest = nv
		if pub, _ := rawBool(raw, "Publish"); pub && cfg.Version != "" && cfg.Version != "$LATEST" {
			cur.vers[cfg.Version] = nv.cloneRef(r.store)
		}
		r.reg.mu.Unlock()
		_ = oldSha
		if taken && !wasTaken {
			r.installStubConfig(name, nv) // the engine holds real light code and a real configuration: make both the stub's
		}
	}
	return p
}

func (r *runnerSys) planUpdateConfig(name string, raw map[string]json.RawMessage) *runnerPlan {
	if raw == nil || name == "" {
		return nil
	}
	r.reg.mu.Lock()
	st := r.reg.fns[name]
	var cur *fnVer
	if st != nil {
		cur = st.latest.clone()
	}
	r.reg.mu.Unlock()
	if cur == nil {
		return nil
	}
	nv := cur.clone()
	applyConfig(nv, raw)
	nv.PkgSha = "" // the package is unchanged: the reference stays with the existing version, this copy holds none
	reason := r.s.heavy.reasonOf(nv.asLambdaFn(name, elfNone, false))
	wasTaken := cur.Taken
	canTake := cur.PkgSha != "" || cur.PackageType == "Image"
	taken := wasTaken || (takeoverReasons[reason] && canTake)
	if taken && !wasTaken {
		for _, l := range nv.Layers {
			r.reg.mu.Lock()
			_, ok := r.reg.layers[l]
			r.reg.mu.Unlock()
			if !ok {
				taken = false
			}
		}
		if taken && len(r.stubSetup()) > 0 {
			taken = false
		}
	}
	if taken {
		nv.Taken = true
		if reason != "" && !wasTaken {
			nv.Reason = reason
		}
	}
	p := &runnerPlan{op: "UpdateFunctionConfiguration", name: name}
	if taken {
		_, hasT := raw["Timeout"]
		if !wasTaken {
			hasT = true // the stub's timeout must follow the real one the first time
		}
		stubify(raw, r.names().roleARN, nv.Timeout, hasT)
		p.body = marshalBody(raw)
	}
	p.commit = func(resp []byte) {
		r.reg.mu.Lock()
		cur := r.reg.fns[name]
		if cur == nil {
			r.reg.mu.Unlock()
			return
		}
		nv.PkgSha, nv.PkgSize = cur.latest.PkgSha, cur.latest.PkgSize
		cur.latest = nv
		r.reg.mu.Unlock()
		if taken && !wasTaken {
			r.installStubCode(name)
		}
	}
	return p
}

func (r *runnerSys) planLayer(raw map[string]json.RawMessage) *runnerPlan {
	if raw == nil {
		return nil
	}
	code := codeOf(raw, "Content")
	sha, size, err := r.codeBytes(code, r.store.max)
	if err != nil {
		return nil // not kept: a function that uses it cannot be taken over, and says so
	}
	p := &runnerPlan{op: "PublishLayerVersion"}
	p.abort = func() { r.store.unref(sha) }
	p.commit = func(resp []byte) {
		if m := layerARNRe.FindSubmatch(resp); m != nil {
			r.reg.mu.Lock()
			if old, ok := r.reg.layers[string(m[1])]; ok {
				r.store.unref(old.sha)
			}
			r.reg.layers[string(m[1])] = layerBlob{sha, size}
			r.reg.mu.Unlock()
			return
		}
		r.store.unref(sha)
	}
	return p
}

func (r *runnerSys) planPublish(name string) *runnerPlan {
	if name == "" {
		return nil
	}
	if _, _, ok := r.reg.versionOf(name, ""); !ok {
		return nil
	}
	return &runnerPlan{op: "PublishVersion", name: name, commit: func(resp []byte) {
		var cfg struct{ Version string }
		json.Unmarshal(resp, &cfg)
		if cfg.Version == "" || cfg.Version == "$LATEST" {
			return
		}
		r.reg.mu.Lock()
		defer r.reg.mu.Unlock()
		if st := r.reg.fns[name]; st != nil {
			if old := st.vers[cfg.Version]; old != nil {
				r.reg.store.unref(old.PkgSha)
			}
			c := st.latest.cloneRef(r.store)
			c.Version = cfg.Version
			st.vers[cfg.Version] = c
		}
	}}
}

var versionRe = regexp.MustCompile(`^\d+$`)

// dropFunction: DeleteFunction answered 2xx. qualifier "" removes the function, a version number removes that version.
func (r *runnerSys) dropFunction(name, qualifier string) {
	r.reg.mu.Lock()
	st := r.reg.fns[name]
	if st == nil {
		r.reg.mu.Unlock()
		return
	}
	if qualifier != "" && versionRe.MatchString(qualifier) {
		if x := st.vers[qualifier]; x != nil {
			r.reg.store.unref(x.PkgSha)
			delete(st.vers, qualifier)
		}
		r.reg.mu.Unlock()
		r.hub.unregister(name, qualifier)
		return
	}
	if qualifier != "" { // an alias: the function stays
		r.reg.mu.Unlock()
		return
	}
	r.reg.releaseAllLocked(st)
	delete(r.reg.fns, name)
	r.reg.mu.Unlock()
	r.hub.unregister(name, "")
}

// ---- the overlay: the answers callers get hold the real configuration, never the stub's

var overlayOps = map[string]bool{"CreateFunction": true, "GetFunction": true, "GetFunctionConfiguration": true, "ListFunctions": true, "ListVersionsByFunction": true,
	"UpdateFunctionCode": true, "UpdateFunctionConfiguration": true, "PublishVersion": true, "ListEventSourceMappings": true}

func sha256B64(hexSum string) string {
	b, err := hex.DecodeString(hexSum)
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(b)
}

// overlay rewrites the configuration objects of a Lambda answer for the functions the runner holds.
func (r *runnerSys) overlay(op string, data []byte) []byte {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var top map[string]interface{}
	if dec.Decode(&top) != nil || top == nil {
		return data
	}
	changed := false
	var one func(m map[string]interface{})
	one = func(m map[string]interface{}) {
		name, _ := m["FunctionName"].(string)
		if name == "" {
			return
		}
		version, _ := m["Version"].(string)
		r.reg.mu.Lock()
		st := r.reg.fns[name]
		var v *fnVer
		if st != nil {
			if version == "" || version == "$LATEST" {
				v = st.latest
			} else {
				v = st.vers[version]
			}
		}
		if v == nil || !v.Taken {
			r.reg.mu.Unlock()
			return
		}
		v = v.clone()
		r.reg.mu.Unlock()
		m["Runtime"] = v.Runtime
		m["Handler"] = v.Handler
		m["MemorySize"] = v.Memory
		m["Timeout"] = v.Timeout
		if v.Role != "" {
			m["Role"] = v.Role
		}
		if v.PackageType != "" {
			m["PackageType"] = v.PackageType
		}
		if len(v.Arches) > 0 {
			m["Architectures"] = v.Arches
		}
		if len(v.Layers) > 0 {
			ls := make([]interface{}, 0, len(v.Layers))
			r.reg.mu.Lock()
			for _, arn := range v.Layers {
				ls = append(ls, map[string]interface{}{"Arn": arn, "CodeSize": r.reg.layers[arn].size})
			}
			r.reg.mu.Unlock()
			m["Layers"] = ls
		} else {
			delete(m, "Layers")
		}
		if v.Ephemeral > 0 {
			m["EphemeralStorage"] = map[string]interface{}{"Size": v.Ephemeral}
		}
		if v.PkgSha != "" {
			m["CodeSize"] = v.PkgSize
			m["CodeSha256"] = sha256B64(v.PkgSha)
		}
		changed = true
	}
	switch op {
	case "GetFunction":
		if cfg, ok := top["Configuration"].(map[string]interface{}); ok {
			one(cfg)
			if changed {
				name, _ := cfg["FunctionName"].(string)
				version, _ := cfg["Version"].(string)
				if code, ok := top["Code"].(map[string]interface{}); ok {
					r.overlayCode(code, name, version)
				}
			}
		}
	case "ListFunctions":
		if l, ok := top["Functions"].([]interface{}); ok {
			for _, e := range l {
				if m, ok := e.(map[string]interface{}); ok {
					one(m)
				}
			}
		}
	case "ListEventSourceMappings":
		// a mapping on the plumbing is never listed (the sweeper deletes it)
		if l, ok := top["EventSourceMappings"].([]interface{}); ok {
			kept := make([]interface{}, 0, len(l))
			for _, e := range l {
				if m, ok := e.(map[string]interface{}); ok {
					if arn, _ := m["EventSourceArn"].(string); hiddenQueueURL(arn) {
						changed = true
						continue
					}
				}
				kept = append(kept, e)
			}
			top["EventSourceMappings"] = kept
		}
	case "ListVersionsByFunction":
		if l, ok := top["Versions"].([]interface{}); ok {
			for _, e := range l {
				if m, ok := e.(map[string]interface{}); ok {
					one(m)
				}
			}
		}
	default:
		one(top)
	}
	if !changed {
		return data
	}
	return marshalNoEscape(top, data)
}

func (r *runnerSys) overlayCode(code map[string]interface{}, name, version string) {
	_, v, ok := r.reg.versionOf(name, version)
	if !ok || v == nil {
		return
	}
	if v.PackageType == "Image" {
		code["RepositoryType"] = "ECR"
		code["ImageUri"] = v.ImageURI
		delete(code, "Location")
		return
	}
	code["RepositoryType"] = "S3"
	code["Location"] = r.codeURL(name, version)
}

// overlayWanted says whether an answer to this operation may need the overlay at all (the functions it names are held).
func (r *runnerSys) overlayWanted(op, rawPath string) bool {
	if !overlayOps[op] {
		return false
	}
	r.reg.mu.Lock()
	defer r.reg.mu.Unlock()
	for _, st := range r.reg.fns {
		if st.latest.Taken {
			return true
		}
	}
	return false
}

// ---- evidence

// runnerJSON: the part of GET /_rovara/lambda/heavy that is about the runner.
func (r *runnerSys) functionsJSON() []map[string]interface{} {
	r.reg.mu.Lock()
	defer r.reg.mu.Unlock()
	names := make([]string, 0, len(r.reg.fns))
	for n, st := range r.reg.fns {
		if st.latest.Taken {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	out := make([]map[string]interface{}, 0, len(names))
	for _, n := range names {
		st := r.reg.fns[n]
		v := st.latest
		row := map[string]interface{}{"name": n, "reason": v.Reason, "runtime": v.Runtime, "memoryMb": v.Memory, "timeoutSeconds": v.Timeout,
			"direct": st.stats.Direct, "viaStub": st.stats.ViaStub, "async": st.stats.Async, "ok": st.stats.OK, "functionErrors": st.stats.FunctionErrors,
			"cold": st.stats.Cold, "ceilingHits": st.stats.CeilingHits, "unsupportedRuns": st.stats.Unsupported, "unavailable": st.stats.Fails}
		if t := v.unsupportedText(); t != "" {
			row["unsupported"] = t
		} else if st.refused != "" {
			row["unsupported"] = st.refused
		}
		out = append(out, row)
	}
	return out
}
