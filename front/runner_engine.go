package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// The runner's side of the engine: the hidden plumbing (a role, a request queue, a payload bucket), the dispatcher that serves the stub's
// requests, and the front's own calls to the engine for functions it holds. All of it is loopback traffic of the front to the engine; none of
// it goes through the front's HTTP handler, so none of it is in the ledger and none of it counts against the plan.

const (
	envRunnerSocket   = "ROVARA_AWS_RUNNER_SOCKET"
	envRunnerStoreDir = "ROVARA_AWS_RUNNER_STORE_DIR"
	envRunnerStoreMax = "ROVARA_AWS_RUNNER_STORE_MAX_BYTES"
	envRunnerDirect   = "ROVARA_AWS_RUNNER_MAX_DIRECT"
)

// RunnerConfig is the function runner's settings. Nil in Config means the feature is off: the front behaves as before (it records heavy
// functions, never routes them).
type RunnerConfig struct {
	Socket     string
	StoreDir   string
	StoreMax   int64
	CallWrap   func(engineCall) engineCall // tests: wraps the front's own calls to the engine (to count them, or to slow them down)
	NoDispatch bool                        // tests: do not start the dispatcher (a test drives the sweeper and the repair itself)
	SweepEvery time.Duration               // tests: how often references to the plumbing are swept (0: 5 s)
	MaxDirect  int
}

func loadRunnerConfig(s settings, workDir string, planned bool) (*RunnerConfig, error) {
	sock := strings.TrimSpace(s(envRunnerSocket))
	if sock == "" {
		return nil, nil
	}
	if !planned {
		return nil, fmt.Errorf("%s needs the run's plan (ROVARA_AWS_PLANNED_SERVICES): the function runner is part of planned mode", envRunnerSocket)
	}
	c := &RunnerConfig{Socket: sock, StoreDir: strings.TrimSpace(s(envRunnerStoreDir)), StoreMax: 256 << 20, MaxDirect: 64}
	if c.StoreDir == "" || !filepath.IsAbs(c.StoreDir) {
		// the packages are large: they must go to a disk the run provides for them, never to the helper's small /tmp (a full /tmp starves the
		// engine and the socket)
		return nil, fmt.Errorf("%s must be set to an absolute directory on disk with room for the function packages", envRunnerStoreDir)
	}
	if v := strings.TrimSpace(s(envRunnerStoreMax)); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 1<<20 {
			return nil, fmt.Errorf("%s must be a number of bytes, at least 1 MiB", envRunnerStoreMax)
		}
		c.StoreMax = n
	}
	if v := strings.TrimSpace(s(envRunnerDirect)); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 1024 {
			return nil, fmt.Errorf("%s must be between 1 and 1024", envRunnerDirect)
		}
		c.MaxDirect = n
	}
	return c, nil
}

type runnerSys struct {
	s     *Server
	cfg   *RunnerConfig
	store *runnerStore
	reg   *runnerRegistry
	hub   *runnerHub

	// the generation: one engine life. Its secret signs the stub's requests and replies and Code.Location links; everything that runs a
	// function runs under its context, so a reset can cancel and await it (quiesce), then start the next generation (resume).
	secMu     sync.RWMutex
	secret    string
	nm        hiddenNames
	stubBin   []byte
	stubB64s  string
	codeKey   []byte
	gMu       sync.RWMutex
	gCtx      context.Context
	gCancel   context.CancelFunc
	gWG       sync.WaitGroup
	resetting bool
	genN      uint64 // the generation's number: a run that read the registry in an earlier one is not admitted
	seenMu    sync.Mutex
	seenReq   map[string]time.Time
	big       slots // one takeover parse at a time (the package bodies are large)

	provMu  sync.Mutex
	provGen int
	reqURL  string

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	direct slots
	stubs  slots
	// timing knobs tests shorten
	sliceWait  int // the dispatcher's long-poll seconds
	sweepEvery time.Duration
	sweepAge   time.Duration
	refsEvery  time.Duration // how often the dispatcher sweeps references to the plumbing
	call       engineCall    // the front's own calls to the engine (a field so tests can stand in for the engine)
	callN      atomic.Int64  // how many calls the front has made to the engine (the sweeper's budget is counted in them)
	swq        []sweepUnit   // the sweeper's queue of work, kept between ticks
	sweepRun   sync.Mutex    // one sweep tick at a time
	bigStubs   slots         // stub requests with a big event (their bytes are copied several times)
	retryDelay time.Duration // between attempts of an async invoke (the engine's: 2 s)

	sweepMu   sync.Mutex
	sweepSeen map[string]time.Time
	sweptRefs map[string]bool
}

// newRunnerSys builds the runner (nothing listens yet); start binds the socket and starts the dispatcher.
func newRunnerSys(s *Server, cfg *RunnerConfig) (*runnerSys, error) {
	st, err := newRunnerStore(cfg.StoreDir, cfg.StoreMax)
	if err != nil {
		return nil, fmt.Errorf("cannot create the function package store: %w", err)
	}
	if free, ok := freeBytes(cfg.StoreDir); ok && cfg.StoreMax > free {
		return nil, fmt.Errorf("the function package store may grow to %d bytes but its file system has %d free: set %s to a bigger disk or %s lower",
			cfg.StoreMax, free, envRunnerStoreDir, envRunnerStoreMax)
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &runnerSys{s: s, cfg: cfg, store: st, reg: newRunnerRegistry(st), ctx: ctx, cancel: cancel, seenReq: map[string]time.Time{}, big: newSlots(1),
		direct: newSlots(cfg.MaxDirect), stubs: newSlots(64), sliceWait: 3, sweepEvery: 30 * time.Second, sweepAge: 120 * time.Second,
		refsEvery: sweepEveryOr(cfg.SweepEvery), retryDelay: 2 * time.Second, sweepSeen: map[string]time.Time{}, sweptRefs: map[string]bool{}}
	r.hub = newRunnerHub(cfg.Socket, st, version)
	var inner engineCall = r.engineDo
	if cfg.CallWrap != nil {
		inner = cfg.CallWrap(r.engineDo)
	}
	counted := func(service, method, path string, hdr map[string]string, body []byte, timeout time.Duration) (int, []byte, http.Header, error) {
		r.callN.Add(1)
		return inner(service, method, path, hdr, body, timeout)
	}
	r.call = counted
	r.bigStubs = newSlots(4)
	r.rotate()
	r.gCtx, r.gCancel = context.WithCancel(ctx)
	return r, nil
}

// rotate starts a new secret: the stub is rebuilt under it and the Code.Location key changes.
func (r *runnerSys) rotate() {
	sec := make([]byte, 32)
	rand.Read(sec)
	key := make([]byte, 32)
	rand.Read(key)
	tok := make([]byte, 16)
	rand.Read(tok)
	hexSec := hex.EncodeToString(sec)
	nm := newHiddenNames(hex.EncodeToString(tok))
	b, b64 := buildStubZip(hexSec, nm)
	r.secMu.Lock()
	r.secret, r.stubBin, r.stubB64s, r.codeKey, r.nm = hexSec, b, b64, key, nm
	r.secMu.Unlock()
}

// names are the hidden names of the current generation.
func (r *runnerSys) names() hiddenNames {
	r.secMu.RLock()
	defer r.secMu.RUnlock()
	return r.nm
}

// stub returns the current generation's stub package and its base64.
func (r *runnerSys) stub() ([]byte, string) {
	r.secMu.RLock()
	defer r.secMu.RUnlock()
	return r.stubBin, r.stubB64s
}

func (r *runnerSys) sign(parts ...string) string {
	r.secMu.RLock()
	m := hmac.New(sha256.New, []byte(r.secret))
	r.secMu.RUnlock()
	m.Write([]byte(strings.Join(parts, "\n")))
	return hex.EncodeToString(m.Sum(nil))
}

// genNum is the current generation: a caller reads it BEFORE it reads the registry and passes it to runCtx, so what it read can never be used
// after a reset (the registration would put a dead function back on the worker).
func (r *runnerSys) genNum() uint64 {
	r.gMu.RLock()
	defer r.gMu.RUnlock()
	return r.genN
}

// begin admits one run (a call to the worker) into the current generation. ok is false while a reset is under way.
func (r *runnerSys) begin(gen uint64) (context.Context, func(), bool) {
	r.gMu.RLock()
	defer r.gMu.RUnlock()
	if r.resetting || gen != r.genN {
		return nil, nil, false
	}
	r.gWG.Add(1)
	return r.gCtx, r.gWG.Done, true
}

// runCtx: a context for one run, cancelled when the caller's is or when the generation ends. release must be called when the run is over.
func (r *runnerSys) runCtx(parent context.Context, gen uint64) (context.Context, func(), bool) {
	gctx, done, ok := r.begin(gen)
	if !ok {
		return nil, nil, false
	}
	ctx, cancel := context.WithCancel(parent)
	stop := context.AfterFunc(gctx, cancel)
	return ctx, func() { stop(); cancel(); done() }, true
}

// quiesce is the first half of a reset: no new run is admitted, the ones in flight are cancelled and awaited, and the worker confirms every
// environment gone. After it returns nothing can register or invoke on the worker until resume.
func (r *runnerSys) quiesce() {
	r.gMu.Lock()
	r.resetting = true
	r.gCancel()
	r.gMu.Unlock()
	r.gWG.Wait()
	r.hub.stopAll()
}

// resume is the second half: the registry, the store and the plumbing state are emptied, the secret changes, and runs are admitted again.
func (r *runnerSys) resume() {
	r.reg.reset()
	r.provMu.Lock()
	r.provGen, r.reqURL = 0, ""
	r.provMu.Unlock()
	r.sweepMu.Lock()
	r.sweepSeen = map[string]time.Time{}
	r.sweptRefs = map[string]bool{}
	r.sweepMu.Unlock()
	r.seenMu.Lock()
	r.seenReq = map[string]time.Time{}
	r.seenMu.Unlock()
	r.rotate()
	r.gMu.Lock()
	r.gCtx, r.gCancel = context.WithCancel(r.ctx)
	r.genN++
	r.resetting = false
	r.gMu.Unlock()
}

// startRunner builds the runner, binds its socket and starts the dispatcher. A front with no runner configured does nothing. It must run
// before the front serves requests.
func (s *Server) startRunner() error {
	if s.cfg.Runner == nil {
		return nil
	}
	rs, err := newRunnerSys(s, s.cfg.Runner)
	if err != nil {
		return err
	}
	if err := rs.hub.start(); err != nil {
		return err
	}
	s.heavy.mu.Lock()
	s.heavy.longTimeout = true // decision 119: a function that may run longer than the engine lets any run is heavy too
	s.heavy.mu.Unlock()
	s.budget.mu.Lock()
	s.budget.max = 256 << 20 // whole packages are read to keep them (a body, and two copies of it while it is parsed)
	s.budget.mu.Unlock()
	s.rw.hideRunner = true
	s.runner = rs
	if !s.cfg.Runner.NoDispatch {
		rs.wg.Add(3)
		go func() { defer rs.wg.Done(); rs.dispatchLoop() }()
		go func() { defer rs.wg.Done(); rs.sweepLoop() }()
		go func() { defer rs.wg.Done(); rs.refsLoop() }() // off the dispatch path: heavy-function polls never wait on it
	}
	return nil
}

func (r *runnerSys) close() {
	r.cancel()
	r.hub.close()
	r.wg.Wait()
	r.store.wipe()
	os.RemoveAll(r.cfg.StoreDir)
}

// reset: quiesce then resume (the control path calls the halves around the engine's restart).
func (r *runnerSys) reset() {
	r.quiesce()
	r.resume()
}

// ---- loopback calls

// engineCall is one call of the front's own to the engine: the status, the body and the headers of the answer.
type engineCall func(service, method, path string, hdr map[string]string, body []byte, timeout time.Duration) (int, []byte, http.Header, error)

// capHeader is not a header: a caller of engineCall names with it the most of the answer it will read (engineDo removes it).
const capHeader = "X-Rovara-Answer-Cap"

var errAnswerTooLarge = errors.New("the engine's answer is larger than the limit for this call")

// signingNames: the SigV4 service names of the services the front calls that are not in the legacy catalog.
var signingNames = map[string]string{"scheduler": "scheduler", "pipes": "pipes"}

func (r *runnerSys) engineDo(service, method, path string, hdr map[string]string, body []byte, timeout time.Duration) (int, []byte, http.Header, error) {
	gen, _, err := r.s.engine.current()
	if err != nil {
		return 0, nil, nil, err
	}
	// the most of an answer that is read: 16 MiB (the runner frame's own cap) unless the caller names a smaller one
	limit := int64(16 << 20)
	if v := hdr[capHeader]; v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 && n < limit {
			limit = n
		}
		h2 := make(map[string]string, len(hdr))
		for k, x := range hdr {
			if k != capHeader {
				h2[k] = x
			}
		}
		hdr = h2
	}
	signing := signingNames[service]
	if svc := byKey[service]; svc != nil {
		signing = svc.SigningName
	}
	if signing == "" {
		return 0, nil, nil, fmt.Errorf("no service %s", service)
	}
	ctx, cancel := context.WithTimeout(r.ctx, timeout)
	defer cancel()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, "https://127.0.0.1:"+strconv.Itoa(gen.port)+path, rd)
	if err != nil {
		return 0, nil, nil, err
	}
	req.Host = "127.0.0.1:" + strconv.Itoa(gen.port)
	req.Header.Set("Authorization", syntheticAuthorization(signing, r.s.cfg.Region))
	req.Header.Set("User-Agent", "rovara-aws-front-runner")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := gen.client.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if int64(len(b)) > limit {
		return resp.StatusCode, nil, resp.Header, errAnswerTooLarge
	}
	return resp.StatusCode, b, resp.Header, nil
}

func (r *runnerSys) sqsCall(op string, req map[string]interface{}, timeout time.Duration) (map[string]interface{}, error) {
	body, _ := json.Marshal(req)
	st, b, _, err := r.call("sqs", http.MethodPost, "/", map[string]string{"X-Amz-Target": "AmazonSQS." + op, "Content-Type": "application/x-amz-json-1.0"}, body, timeout)
	if err != nil {
		return nil, err
	}
	var out map[string]interface{}
	json.Unmarshal(b, &out)
	if st >= 300 {
		code, _ := out["__type"].(string)
		return out, fmt.Errorf("%s answered %d %s", op, st, code)
	}
	return out, nil
}

func (r *runnerSys) iamCall(action string, params url.Values) (int, []byte, error) {
	params.Set("Action", action)
	params.Set("Version", "2010-05-08")
	st, b, _, err := r.call("iam", http.MethodPost, "/", map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, []byte(params.Encode()), 15*time.Second)
	return st, b, err
}

// ensureProvisioned makes the hidden resources exist in the current engine generation (a reset restarts the engine and empties them).
func (r *runnerSys) ensureProvisioned() error {
	gen, _, err := r.s.engine.current()
	if err != nil {
		return err
	}
	r.provMu.Lock()
	defer r.provMu.Unlock()
	if r.provGen == gen.n && r.reqURL != "" {
		return nil
	}
	trust := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}`
	nm := r.names()
	st, b, err := r.iamCall("CreateRole", url.Values{"RoleName": {nm.role}, "AssumeRolePolicyDocument": {trust}})
	if err != nil || (st >= 300 && !bytes.Contains(b, []byte("EntityAlreadyExists"))) {
		return fmt.Errorf("cannot create the stub's role: %v", orStatus(err, st))
	}
	// The engine checks the FUNCTION's execution role for what its callers need (an SQS mapping asks "may this role ReceiveMessage on that queue?",
	// a stream mapping the same for the stream), and the stub runs as that role, so the stub's role may do anything inside the engine. It
	// can: the ambient test key is the engine's administrator anyway, and the stub is fixed code. What this costs is fidelity: the
	// customer's own role is not checked for those mapping permissions on a function the runner holds (README, limits).
	policy := stubPolicy
	st, _, err = r.iamCall("PutRolePolicy", url.Values{"RoleName": {nm.role}, "PolicyName": {"rendezvous"}, "PolicyDocument": {policy}})
	if err != nil || st >= 300 {
		return fmt.Errorf("cannot give the stub's role its policy: %v", orStatus(err, st))
	}
	q, err := r.sqsCall("CreateQueue", map[string]interface{}{"QueueName": nm.req}, 15*time.Second)
	if err != nil {
		return fmt.Errorf("cannot create the request queue: %v", err)
	}
	u, _ := q["QueueUrl"].(string)
	if u == "" {
		return errors.New("the request queue has no URL")
	}
	st, b, _, err = r.call("s3", http.MethodPut, "/"+nm.bucket, nil, nil, 15*time.Second)
	if err != nil || (st >= 300 && !bytes.Contains(b, []byte("BucketAlreadyOwnedByYou"))) {
		return fmt.Errorf("cannot create the payload bucket: %v", orStatus(err, st))
	}
	r.provGen, r.reqURL = gen.n, u
	return nil
}

func orStatus(err error, status int) error {
	if err != nil {
		return err
	}
	return fmt.Errorf("HTTP %d", status)
}

func (r *runnerSys) requestURL() string {
	r.provMu.Lock()
	defer r.provMu.Unlock()
	return r.reqURL
}

// engineConfig reads a function's configuration from the engine, for a function the front never saw created.
func (r *runnerSys) engineConfig(name string) (*fnVer, bool) {
	st, b, _, err := r.call("lambda", http.MethodGet, "/2015-03-31/functions/"+url.PathEscape(name)+"/configuration", nil, nil, 15*time.Second)
	if err != nil || st != 200 {
		return nil, false
	}
	var cfg struct {
		Runtime, Handler, Role, PackageType string
		MemorySize, Timeout                 int
		Layers                              []struct{ Arn string }
		Architectures                       []string
		Environment                         struct{ Variables map[string]string }
		EphemeralStorage                    struct{ Size int }
	}
	if json.Unmarshal(b, &cfg) != nil {
		return nil, false
	}
	v := &fnVer{Version: "$LATEST", Runtime: cfg.Runtime, Handler: cfg.Handler, Role: cfg.Role, Memory: cfg.MemorySize, Timeout: cfg.Timeout,
		Env: cfg.Environment.Variables, PackageType: cfg.PackageType, Arches: cfg.Architectures, Ephemeral: cfg.EphemeralStorage.Size}
	if v.Env == nil {
		v.Env = map[string]string{}
	}
	if v.PackageType == "" {
		v.PackageType = "Zip"
	}
	for _, l := range cfg.Layers {
		v.Layers = append(v.Layers, l.Arn)
	}
	return v, true
}

// installStubConfig makes the engine's configuration of a function the stub's (after UpdateFunctionCode replaced a light function's code).
func (r *runnerSys) installStubConfig(name string, v *fnVer) {
	body, _ := json.Marshal(map[string]interface{}{"Runtime": stubRuntime, "Handler": stubHandler, "Role": r.names().roleARN, "MemorySize": 128,
		"Timeout": stubTimeout(v.Timeout), "Layers": []string{}})
	st, _, _, err := r.call("lambda", http.MethodPut, "/2015-03-31/functions/"+url.PathEscape(name)+"/configuration", map[string]string{"Content-Type": "application/json"}, body, 30*time.Second)
	if err != nil || st >= 300 {
		log.Printf("the stub's configuration could not be installed (%v)", orStatus(err, st))
	}
}

// installStubCode replaces the engine's code of a function with the stub (after UpdateFunctionConfiguration made a light function heavy).
func (r *runnerSys) installStubCode(name string) {
	_, b64 := r.stub()
	body, _ := json.Marshal(map[string]string{"ZipFile": b64})
	st, _, _, err := r.call("lambda", http.MethodPut, "/2015-03-31/functions/"+url.PathEscape(name)+"/code", map[string]string{"Content-Type": "application/json"}, body, 30*time.Second)
	if err != nil || st >= 300 {
		log.Printf("the stub's code could not be installed (%v)", orStatus(err, st))
	}
}

// resolveAlias returns the version an alias points at.
func (r *runnerSys) resolveAlias(name, alias string) (string, bool) {
	st, b, _, err := r.call("lambda", http.MethodGet, "/2015-03-31/functions/"+url.PathEscape(name)+"/aliases/"+url.PathEscape(alias), nil, nil, 10*time.Second)
	if err != nil || st != 200 {
		return "", false
	}
	var a struct{ FunctionVersion string }
	if json.Unmarshal(b, &a) != nil || a.FunctionVersion == "" {
		return "", false
	}
	return a.FunctionVersion, true
}

// fetchObject streams an object of the engine's S3 into the package store.
func (r *runnerSys) fetchObject(path string, limit int64) (string, int64, error) {
	if !safeObjectPath(path) {
		return "", 0, errors.New("not an object path")
	}
	gen, _, err := r.s.engine.current()
	if err != nil {
		return "", 0, err
	}
	ctx, cancel := context.WithTimeout(r.ctx, 2*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://127.0.0.1:"+strconv.Itoa(gen.port)+path, nil)
	if err != nil {
		return "", 0, err
	}
	req.Host = "127.0.0.1:" + strconv.Itoa(gen.port)
	req.Header.Set("Authorization", syntheticAuthorization("s3", r.s.cfg.Region))
	req.Header.Set("User-Agent", "rovara-aws-front-runner")
	resp, err := gen.client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("the object answered %d", resp.StatusCode)
	}
	return r.store.put(resp.Body, limit)
}

// ---- Code.Location: a signed, expiring link for the real package (the key changes at every generation)

func (r *runnerSys) codeURL(name, version string) string {
	r.secMu.RLock()
	codeKey := r.codeKey
	r.secMu.RUnlock()
	if version == "" {
		version = "$LATEST"
	}
	payload, _ := json.Marshal(map[string]interface{}{"n": name, "v": version, "e": time.Now().Add(10 * time.Minute).Unix()})
	mac := hmac.New(sha256.New, codeKey)
	mac.Write(payload)
	tok := base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return r.s.cfg.BaseURL + functionCodePrefix + tok
}

// serveCode answers GET <functionCodePrefix><token>: the real package, to a caller holding a token the front signed.
func (r *runnerSys) serveCode(w http.ResponseWriter, req *http.Request, tok string) {
	pb, mb, ok := strings.Cut(tok, ".")
	payload, err1 := base64.RawURLEncoding.DecodeString(pb)
	mac, err2 := base64.RawURLEncoding.DecodeString(mb)
	if !ok || err1 != nil || err2 != nil {
		writeBody(w, http.StatusForbidden, "application/json", jsonError("the code link is not valid"))
		return
	}
	r.secMu.RLock()
	codeKey := r.codeKey
	r.secMu.RUnlock()
	want := hmac.New(sha256.New, codeKey)
	want.Write(payload)
	var p struct {
		N, V string
		E    int64
	}
	if !hmac.Equal(want.Sum(nil), mac) || json.Unmarshal(payload, &p) != nil || time.Now().Unix() > p.E {
		writeBody(w, http.StatusForbidden, "application/json", jsonError("the code link is not valid or has expired"))
		return
	}
	_, v, found := r.reg.versionOf(p.N, p.V)
	if !found || v == nil || v.PkgSha == "" {
		writeBody(w, http.StatusNotFound, "application/json", jsonError("no such package"))
		return
	}
	f, size, err := r.store.open(v.PkgSha)
	if err != nil {
		writeBody(w, http.StatusNotFound, "application/json", jsonError("no such package"))
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	w.WriteHeader(http.StatusOK)
	if req.Method != http.MethodHead {
		io.Copy(w, f)
	}
}

// ---- the dispatcher: the stub's requests

type stubRequest struct {
	V     int    `json:"v"`
	Fn    string `json:"fn"`
	Arn   string `json:"arn"`
	Ver   string `json:"ver"`
	Req   string `json:"req"`
	Reply string `json:"reply"`
	Event string `json:"event"`
	S3Key string `json:"s3Key"`
	Rem   int64  `json:"rem"`
	S3Sha string `json:"s3Sha"` // SHA-256 (hex) of the event object, signed with the rest
	Sig   string `json:"sig"`
}

var reqIDRe = regexp.MustCompile(`^[A-Za-z0-9-]{1,80}$`)

// authentic: the request looks like one the stub of THIS generation put on the queue, and only that. The stub signs {req, reply, function,
// version, time left, event, or pointer and digest of the object}; the name of the reply queue is its request's, on the engine's own queue
// URL; and a request id is served once. This keeps stray, stale and mis-addressed messages out (a leftover of another generation, a message
// meant for another queue). It is NOT a boundary against code running in the same engine: that code can read the stub's code and its
// secret (an API Gateway HTTP integration can fetch it), and can send valid messages. Same-run code can disrupt or tamper with its own run's
// heavy functions; that is a known limit, not something this signature prevents.
func (r *runnerSys) authentic(sr stubRequest) bool {
	if !reqIDRe.MatchString(sr.Req) || sr.Reply == "" || queueNameOf(sr.Reply) != r.names().replyPrefix+strings.ReplaceAll(sr.Req, "-", "") || sr.Fn == "" || sr.Sig == "" {
		return false
	}
	if sr.S3Key != "" && sr.S3Key != "req/"+sr.Req {
		return false
	}
	part := sr.Event
	if sr.S3Key != "" {
		part = sr.S3Key + ":" + sr.S3Sha
		if len(sr.S3Sha) != 64 {
			return false
		}
	}
	want := r.sign("q1", sr.Req, sr.Reply, sr.Fn, sr.Ver, strconv.FormatInt(sr.Rem, 10), part)
	if !hmac.Equal([]byte(want), []byte(sr.Sig)) {
		return false
	}
	r.seenMu.Lock()
	defer r.seenMu.Unlock()
	if _, dup := r.seenReq[sr.Req]; dup {
		return false
	}
	now := time.Now()
	if len(r.seenReq) > 50000 {
		for k, t := range r.seenReq {
			if now.Sub(t) > 20*time.Minute {
				delete(r.seenReq, k)
			}
		}
	}
	r.seenReq[sr.Req] = now
	return true
}

func (r *runnerSys) dispatchLoop() {
	for r.ctx.Err() == nil {
		if err := r.ensureProvisioned(); err != nil {
			r.sleep(300 * time.Millisecond)
			continue
		}
		r.repairPlumbing() // before every poll: a queue attribute, a policy, a deleted queue or bucket is undone within one poll
		q := r.requestURL()
		t0 := time.Now()
		out, err := r.sqsCall("ReceiveMessage", map[string]interface{}{"QueueUrl": q, "MaxNumberOfMessages": 10, "WaitTimeSeconds": r.sliceWait}, time.Duration(r.sliceWait+15)*time.Second)
		if err != nil {
			r.sleep(200 * time.Millisecond)
			continue
		}
		msgs, _ := out["Messages"].([]interface{})
		served := 0
		for _, m := range msgs {
			mm, _ := m.(map[string]interface{})
			body, _ := mm["Body"].(string)
			if rh, _ := mm["ReceiptHandle"].(string); rh != "" {
				r.sqsCall("DeleteMessage", map[string]interface{}{"QueueUrl": q, "ReceiptHandle": rh}, 10*time.Second) // at most once: a request is never served twice
			}
			var sr stubRequest
			if json.Unmarshal([]byte(body), &sr) != nil || !r.authentic(sr) {
				continue // not a request of this generation's stub (unsigned, forged, replayed, or naming another reply queue): never served, never answered
			}
			served++
			r.wg.Add(1)
			go func() {
				defer r.wg.Done()
				r.serveStub(sr)
			}()
		}
		if served == 0 && time.Since(t0) < 50*time.Millisecond {
			r.sleep(50 * time.Millisecond) // an engine that answers a long poll at once must not be asked in a tight loop
		}
	}
}

func (r *runnerSys) sleep(d time.Duration) {
	select {
	case <-time.After(d):
	case <-r.ctx.Done():
	}
}

// stubReply is the message the stub reads.
type stubReply struct {
	OK           bool   `json:"ok"`
	Payload      string `json:"payload,omitempty"`
	S3Key        string `json:"s3Key,omitempty"`
	S3Sha        string `json:"s3Sha,omitempty"` // SHA-256 (hex) of the answer object: the reply is signed as a whole, so the object's content is too
	ErrorType    string `json:"errorType,omitempty"`
	ErrorMessage string `json:"errorMessage,omitempty"`
	Log          string `json:"log,omitempty"`
}

func errReply(t, m string) stubReply { return stubReply{ErrorType: t, ErrorMessage: m} }

func tailString(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

func (r *runnerSys) serveStub(sr stubRequest) {
	if !r.stubs.acquire(r.ctx) {
		return
	}
	defer r.stubs.release()
	reply := r.runStub(sr)
	inner, _ := json.Marshal(reply)
	body, _ := json.Marshal(map[string]string{"m": string(inner), "sig": r.sign("r1", sr.Req, string(inner))})
	if _, err := r.sqsCall("SendMessage", map[string]interface{}{"QueueUrl": sr.Reply, "MessageBody": string(body)}, 15*time.Second); err != nil {
		if !strings.Contains(err.Error(), "NonExistentQueue") && !strings.Contains(err.Error(), "QueueDoesNotExist") {
			log.Printf("a reply to the function stub could not be delivered (%v)", sanitizeErr(err))
		}
	}
}

func (r *runnerSys) runStub(sr stubRequest) stubReply {
	gen := r.genNum()
	// the event
	event := sr.Event
	if len(event) > maxPayloadBytes {
		return errReply("Rovara.Unsupported", "the event is larger than Lambda's 6 MB limit")
	}
	if len(event) > 1<<20 || sr.S3Key != "" {
		// a big event is copied several times on its way to the worker: only a few at once
		if !r.bigStubs.acquire(r.ctx) {
			return errReply("Rovara.RunnerUnavailable", "the function runner is shutting down")
		}
		defer r.bigStubs.release()
	}
	if sr.S3Key != "" {
		path := "/" + r.names().bucket + "/" + escapeKey(sr.S3Key)
		// never more than the biggest event a call can carry is read, whatever the object holds
		st, b, _, err := r.call("s3", http.MethodGet, path, map[string]string{capHeader: strconv.Itoa(maxPayloadBytes + 64<<10)}, nil, 30*time.Second)
		if errors.Is(err, errAnswerTooLarge) {
			return errReply("Rovara.Unsupported", "the event in the payload bucket is larger than Lambda's 6 MB limit")
		}
		if err != nil || st != 200 {
			return errReply("Rovara.RunnerError", "the event could not be read from the local engine")
		}
		if sum := sha256.Sum256(b); hex.EncodeToString(sum[:]) != sr.S3Sha {
			// the object is not the one the stub signed: it was changed on its way
			return errReply("Rovara.RunnerError", "the event in the payload bucket does not match the digest the stub signed")
		}
		event = string(b)
		r.call("s3", http.MethodDelete, path, nil, nil, 10*time.Second)
	}
	name := bareFunctionName(sr.Fn)
	arn, v, ok := r.reg.versionOf(name, sr.Ver)
	if !ok || v == nil {
		return errReply("Rovara.Unsupported", "the function runner does not hold version "+sr.Ver+" of "+name)
	}
	r.reg.bump(name, func(s *fnStats) { s.ViaStub++ })
	if t := v.unsupportedText(); t != "" {
		r.reg.bump(name, func(s *fnStats) { s.Unsupported++ })
		return errReply("Rovara.Unsupported", t)
	}
	fn, err := r.reg.regFor(r.s.cfg.Region, arn, name, v)
	if err != nil {
		return r.failReply(name, err)
	}
	want := int64(v.Timeout) * 1000
	timeoutMs, bound := want, false
	if sr.Rem > 0 && sr.Rem-2000 < timeoutMs {
		timeoutMs, bound = sr.Rem-2000, true
	}
	if timeoutMs > ceilingMs || timeoutMs <= 0 {
		timeoutMs, bound = ceilingMs, true
	}
	if timeoutMs >= want {
		bound = false
	}
	inv := invokeFrame{Name: name, Version: v.Version, RequestID: sr.Req, Payload: base64.StdEncoding.EncodeToString([]byte(event)), TimeoutMs: timeoutMs,
		FunctionArn: sr.Arn, LogBytes: 3000, Source: "stub"}
	rctx, release, admitted := r.runCtx(r.ctx, gen)
	if !admitted {
		return errReply("Rovara.RunnerUnavailable", "the function runner is being reset")
	}
	defer release()
	ctx, cancel := context.WithTimeout(rctx, time.Duration(timeoutMs)*time.Millisecond+30*time.Second)
	defer cancel()
	res, err := r.hub.run(ctx, fn, inv)
	if err != nil {
		return r.failReply(name, err)
	}
	return r.replyFor(name, v, res, bound, sr.Req)
}

func (r *runnerSys) failReply(name string, err error) stubReply {
	var re *runnerError
	switch {
	case errors.As(err, &re):
		r.reg.bump(name, func(s *fnStats) { s.Unsupported++ })
		if re.Type == "Rovara.Unsupported" {
			// x86-64 native code goes to the worker like any other heavy function; when it can neither swap the wheels nor emulate, it says so
			// and the function is recorded as unable to run, as before the runner existed
			if reason, first := r.reg.noteRefusal(name, re.Message); reason == "x86-native" && first {
				r.s.ledger.recordUnsupported("lambda", heavyPrefix+"x86-native", name)
			}
		}
		return errReply(re.Type, re.Message)
	case errors.Is(err, errNoRunner):
		r.reg.bump(name, func(s *fnStats) { s.Fails++ })
		return errReply("Rovara.RunnerUnavailable", "no function runner is connected to this local AWS, so a function that needs one cannot run")
	case errors.Is(err, errRunnerGone):
		r.reg.bump(name, func(s *fnStats) { s.Fails++ })
		return errReply("Rovara.RunnerUnavailable", "the function runner disconnected while the function ran")
	}
	r.reg.bump(name, func(s *fnStats) { s.Fails++ })
	return errReply("Rovara.RunnerTimeout", "the function runner did not answer in time")
}

// replyFor turns a worker's result into the stub's reply. bound says the 28 s ceiling, not the function's Timeout, set the deadline.
func (r *runnerSys) replyFor(name string, v *fnVer, res *runnerResult, bound bool, reqID string) stubReply {
	lg := tailString(res.LogTail, 3000)
	if res.Cold {
		r.reg.bump(name, func(s *fnStats) { s.Cold++ })
	}
	switch res.Status {
	case "ok":
		r.reg.bump(name, func(s *fnStats) { s.OK++ })
		raw, err := base64.StdEncoding.DecodeString(res.Payload)
		if err != nil || (len(raw) > 0 && !json.Valid(raw)) {
			return errReply("Rovara.RunnerError", "the function's answer is not a JSON document")
		}
		if len(raw) == 0 {
			raw = []byte("null")
		}
		if len(raw) > stubInlineMax {
			key := "res/" + reqID
			bucket := r.names().bucket
			st, _, _, err := r.call("s3", http.MethodPut, "/"+bucket+"/"+escapeKey(key), map[string]string{"Content-Type": "application/json"}, raw, 60*time.Second)
			if err != nil || st >= 300 {
				return errReply("Rovara.RunnerError", "the function's answer could not be handed to the local engine")
			}
			time.AfterFunc(5*time.Minute, func() {
				r.call("s3", http.MethodDelete, "/"+bucket+"/"+escapeKey(key), nil, nil, 10*time.Second)
			})
			sum := sha256.Sum256(raw)
			return stubReply{OK: true, S3Key: key, S3Sha: hex.EncodeToString(sum[:]), Log: lg}
		}
		return stubReply{OK: true, Payload: string(raw), Log: lg}
	case "function_error":
		r.reg.bump(name, func(s *fnStats) { s.FunctionErrors++ })
		return stubReply{ErrorType: orDefault(res.ErrorType, "Error"), ErrorMessage: res.ErrorMessage, Log: lg}
	case "timeout":
		r.reg.bump(name, func(s *fnStats) { s.FunctionErrors++ })
		if bound {
			r.reg.bump(name, func(s *fnStats) { s.FunctionErrors--; s.CeilingHits++ })
			return stubReply{ErrorType: "Rovara.TimeoutCeiling", ErrorMessage: fmt.Sprintf("the function ran past %d s, the local engine's limit for a run; AWS allows this function %d s. Not tested locally.", ceilingMs/1000, v.Timeout), Log: lg}
		}
		return stubReply{ErrorType: orDefault(res.ErrorType, "Sandbox.Timedout"), ErrorMessage: res.ErrorMessage, Log: lg}
	case "crash", "init_error":
		r.reg.bump(name, func(s *fnStats) { s.FunctionErrors++ })
		return stubReply{ErrorType: orDefault(res.ErrorType, "Runtime.ExitError"), ErrorMessage: res.ErrorMessage, Log: lg}
	case "rejected":
		r.reg.bump(name, func(s *fnStats) { s.Fails++ })
		return stubReply{ErrorType: orDefault(res.ErrorType, "Rovara.RunnerError"), ErrorMessage: res.ErrorMessage, Log: lg}
	case "throttled":
		r.reg.bump(name, func(s *fnStats) { s.Fails++ })
		return errReply("Rovara.Throttled", "the run's function runner has no room for this call ("+orDefault(res.Reason, "capacity")+"); not a failure of the function")
	}
	r.reg.bump(name, func(s *fnStats) { s.Fails++ })
	return errReply("Rovara.RunnerUnavailable", "the function runner could not run the function ("+orDefault(res.Reason, res.Status)+")")
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

// ---- the sweeper: reply queues of stubs that gave up are deleted

func (r *runnerSys) sweepLoop() {
	t := time.NewTicker(r.sweepEvery)
	defer t.Stop()
	for {
		select {
		case <-r.ctx.Done():
			return
		case <-t.C:
			r.sweepOnce()
		}
	}
}

func (r *runnerSys) sweepOnce() {
	out, err := r.sqsCall("ListQueues", map[string]interface{}{"QueueNamePrefix": hiddenReplyPrefix}, 10*time.Second)
	if err != nil {
		return
	}
	urls, _ := out["QueueUrls"].([]interface{})
	now := time.Now()
	live := map[string]bool{}
	r.sweepMu.Lock()
	for _, u := range urls {
		s, _ := u.(string)
		if s == "" {
			continue
		}
		live[s] = true
		first, seen := r.sweepSeen[s]
		if !seen {
			r.sweepSeen[s] = now
			continue
		}
		if now.Sub(first) > r.sweepAge {
			delete(r.sweepSeen, s)
			r.sweepMu.Unlock()
			r.sqsCall("DeleteQueue", map[string]interface{}{"QueueUrl": s}, 10*time.Second)
			r.sweepMu.Lock()
		}
	}
	for s := range r.sweepSeen {
		if !live[s] {
			delete(r.sweepSeen, s)
		}
	}
	r.sweepMu.Unlock()
}

// queueCount is for tests: how many reply queues exist now.
func (r *runnerSys) replyQueues() int {
	out, err := r.sqsCall("ListQueues", map[string]interface{}{"QueueNamePrefix": hiddenReplyPrefix}, 10*time.Second)
	if err != nil {
		return -1
	}
	l, _ := out["QueueUrls"].([]interface{})
	return len(l)
}

func sweepEveryOr(d time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return defaultSweepRefsEvery
}
