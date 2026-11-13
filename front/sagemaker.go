package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// The SageMaker endpoint shim (planned mode, the route key `sagemaker-runtime`). The engine's SageMaker runtime answers every invoke
// with 424 ModelError, never writes an asynchronous answer and never publishes to a notification topic, so the front answers the
// three invoke operations itself (sagemaker_runtime.go). Which endpoints exist is the endpoint table of this file:
//
//   - endpoints the code creates through the front (CreateModel, CreateEndpointConfig, CreateEndpoint, and their deletes), recorded
//     when the engine accepted the call;
//   - endpoints the seed document declares (`sagemaker.endpoints`);
//   - endpoints a CloudFormation template declares (AWS::SageMaker::Model, EndpointConfig and Endpoint): the engine's CloudFormation
//     reaches CREATE_COMPLETE for them and creates nothing, so the front reads the template and creates them through the engine's own
//     API (when the plan names `sagemaker`) and in this table.
//
// How an endpoint is answered (its backing) is separate from whether it exists: PUT /_rovara/sagemaker/endpoints/<name> sets it at any
// time, before or after the endpoint is created. The endpoint table and the backings are the round's state and go with a reset; the
// per-endpoint counters go with the ledger.

// the account the engine answers as, for the one error message that names it
const smAccount = "000000000000"

var smEndpointNameRe = regexp.MustCompile(`^[a-zA-Z0-9](-*[a-zA-Z0-9]){0,62}$`)

type smVariant struct{ Name, Model string }

// smAsync is a config's AsyncInferenceConfig, as far as the shim uses it.
type smAsync struct {
	OutputPath   string
	FailurePath  string
	SuccessTopic string
	ErrorTopic   string
	InclSuccess  bool // IncludeInferenceResponseIn has SUCCESS_NOTIFICATION_TOPIC
	InclError    bool
}

type smConfig struct {
	Name     string
	Variants []smVariant
	Async    *smAsync
}

type smEndpoint struct {
	Name   string
	Config string
	Source string // api, seed or cloudformation
}

// smStats are the counters of one endpoint, for the evidence. Counts only: no body, no header value is ever kept.
type smStats struct {
	Calls, Async, Streamed                 int64
	Matched, MadeUp, Unmatched, Errors     int64
	Helper, NotAvailable, NoAnswer         int64
	AsyncDone, AsyncFailed, NotifyFailures int64
	Last                                   []smUnmatched // the newest unmatched requests, by size and hash
}

type smUnmatched struct {
	Operation   string `json:"operation"`
	ContentType string `json:"contentType"`
	Bytes       int    `json:"bytes"`
	SHA256      string `json:"sha256"`
}

const (
	smMaxStatNames = 1000
	smMaxLast      = 10
)

type smState struct {
	mu        sync.Mutex
	models    map[string]bool
	configs   map[string]*smConfig
	endpoints map[string]*smEndpoint
	backing   map[string]*smBacking
	stats     map[string]*smStats
	unplanned map[string]int64 // calls to a name that is no endpoint, by name (bounded)
	pending   map[string]*smTemplate

	helpers    []*url.URL // the model stand-ins the plan allows; the first is the default
	client     *http.Client
	timeout    time.Duration // how long a model server may take (SageMaker's own limit is 60 s)
	asyncSlots chan struct{}
	asyncWG    sync.WaitGroup
	// asyncBytes bounds the memory the asynchronous jobs hold at once (their input and their answer), whatever the number of jobs waiting
	asyncBytes *byteBudget
}

func newSMState(cfg *Config) *smState {
	return &smState{
		models: map[string]bool{}, configs: map[string]*smConfig{}, endpoints: map[string]*smEndpoint{}, backing: map[string]*smBacking{},
		stats: map[string]*smStats{}, unplanned: map[string]int64{}, pending: map[string]*smTemplate{},
		helpers: cfg.SageMakerHelpers, client: newHelperClient(cfg.SageMakerHelpers, false), asyncBytes: newByteBudget(smAsyncBudget), timeout: 60 * time.Second, asyncSlots: make(chan struct{}, 64),
	}
}

// reset empties the endpoint table and the backings (the engine's state is gone, so is the round's). The counters stay with the ledger.
func (m *smState) reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.models, m.configs, m.endpoints = map[string]bool{}, map[string]*smConfig{}, map[string]*smEndpoint{}
	m.backing, m.pending = map[string]*smBacking{}, map[string]*smTemplate{}
}

// clearStats is DELETE /_rovara/ledger: the counters go with the entries.
func (m *smState) clearStats() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stats, m.unplanned = map[string]*smStats{}, map[string]int64{}
}

func (m *smState) statsFor(name string) *smStats {
	st := m.stats[name]
	if st == nil {
		if len(m.stats) >= smMaxStatNames {
			name = "(other)"
			if st = m.stats[name]; st != nil {
				return st
			}
		}
		st = &smStats{}
		m.stats[name] = st
	}
	return st
}

// ---- the endpoint table

func (m *smState) addModel(name string) {
	m.mu.Lock()
	m.models[name] = true
	m.mu.Unlock()
}

func (m *smState) addConfig(c *smConfig) {
	m.mu.Lock()
	m.configs[c.Name] = c
	m.mu.Unlock()
}

func (m *smState) addEndpoint(e *smEndpoint) {
	m.mu.Lock()
	m.endpoints[e.Name] = e
	m.mu.Unlock()
}

// lookup returns the endpoint and its config (nil when unknown).
func (m *smState) lookup(name string) (*smEndpoint, *smConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e := m.endpoints[name]
	if e == nil {
		return nil, nil
	}
	return e, m.configs[e.Config]
}

// effectiveBacking is the backing of an endpoint: the one set for it, else mode "none": no recording or fixture was approved for the
// endpoint, so the call is refused with a clear no-answer (see smNoAnswer) and the run reports the test as not run. It is never the
// model stand-in: the SM3 stand-in is PARKED under owner decision 141 and is used only when an endpoint's backing names it explicitly
// (mode "helper"); having ROVARA_AWS_SAGEMAKER_HELPER configured changes nothing for an endpoint with no backing. The "none" backing is
// not stored (nothing to keep between calls) and cannot be set: parseBacking does not accept it. The caller holds the lock.
func (m *smState) effectiveBacking(name string) *smBacking {
	if b := m.backing[name]; b != nil {
		return b
	}
	return &smBacking{Mode: smModeNone}
}

func (m *smState) helperURL(b *smBacking) *url.URL {
	if b.Helper != "" {
		for _, h := range m.helpers {
			if h.String() == b.Helper {
				return h
			}
		}
		return nil
	}
	if len(m.helpers) > 0 {
		return m.helpers[0]
	}
	return nil
}

// ---- what the code does through the front: CreateModel and the rest, read when the engine accepted the call

var smObservedOps = map[string]bool{"CreateModel": true, "DeleteModel": true, "CreateEndpointConfig": true, "DeleteEndpointConfig": true,
	"CreateEndpoint": true, "DeleteEndpoint": true}

func jstr(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

// asyncFromAPI reads an AsyncInferenceConfig in the API's shape.
func asyncFromAPI(v any) *smAsync {
	cfg, _ := v.(map[string]any)
	if cfg == nil {
		return nil
	}
	out, _ := cfg["OutputConfig"].(map[string]any)
	a := &smAsync{OutputPath: jstr(out, "S3OutputPath"), FailurePath: jstr(out, "S3FailurePath")}
	if nc, ok := out["NotificationConfig"].(map[string]any); ok {
		a.SuccessTopic, a.ErrorTopic = jstr(nc, "SuccessTopic"), jstr(nc, "ErrorTopic")
		if inc, ok := nc["IncludeInferenceResponseIn"].([]any); ok {
			for _, e := range inc {
				switch e {
				case "SUCCESS_NOTIFICATION_TOPIC":
					a.InclSuccess = true
				case "ERROR_NOTIFICATION_TOPIC":
					a.InclError = true
				}
			}
		}
	}
	return a
}

// observe records one accepted SageMaker control-plane call.
func (m *smState) observe(op string, body []byte) {
	var req map[string]any
	if json.Unmarshal(body, &req) != nil || req == nil {
		return
	}
	switch op {
	case "CreateModel":
		if n := jstr(req, "ModelName"); n != "" {
			m.addModel(n)
		}
	case "CreateEndpointConfig":
		c := &smConfig{Name: jstr(req, "EndpointConfigName"), Async: asyncFromAPI(req["AsyncInferenceConfig"])}
		vs, _ := req["ProductionVariants"].([]any)
		for _, v := range vs {
			vm, _ := v.(map[string]any)
			c.Variants = append(c.Variants, smVariant{Name: jstr(vm, "VariantName"), Model: jstr(vm, "ModelName")})
		}
		if c.Name != "" {
			m.addConfig(c)
		}
	case "CreateEndpoint":
		if n := jstr(req, "EndpointName"); n != "" {
			m.addEndpoint(&smEndpoint{Name: n, Config: jstr(req, "EndpointConfigName"), Source: "api"})
		}
	case "DeleteModel":
		m.mu.Lock()
		delete(m.models, jstr(req, "ModelName"))
		m.mu.Unlock()
	case "DeleteEndpointConfig":
		m.mu.Lock()
		delete(m.configs, jstr(req, "EndpointConfigName"))
		m.mu.Unlock()
	case "DeleteEndpoint":
		n := jstr(req, "EndpointName")
		m.mu.Lock()
		delete(m.endpoints, n)
		m.mu.Unlock()
	}
}

// ---- the engine, for the front's own calls (creating what a seed or a template declares, reading and writing the async objects,
// publishing the notifications). Every one goes to the engine's loopback port with a made-up credential, as the seed does.

// engineRaw makes one request to the engine and reads at most limit bytes of the answer (a longer answer comes back one byte over limit).
func (s *Server) engineRaw(signName, method, path string, headers map[string]string, body []byte, timeout time.Duration, limit int64) (*engineResponse, error) {
	gen, _, err := s.engine.current()
	if err != nil {
		return nil, errors.New("the engine is not ready")
	}
	var rd io.Reader
	if body != nil {
		rd = strings.NewReader(string(body))
	}
	req, err := http.NewRequest(method, "https://127.0.0.1:"+itoa(gen.port)+path, rd)
	if err != nil {
		return nil, err
	}
	req.Host = "127.0.0.1:" + itoa(gen.port)
	req.Header.Set("Authorization", syntheticAuthorization(signName, s.cfg.Region))
	req.Header.Set("User-Agent", "rovara-aws-front-sagemaker")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	ctx, cancel := contextWithTimeout(timeout)
	defer cancel()
	resp, err := gen.client.Do(req.WithContext(ctx))
	if err != nil {
		return nil, errors.New("the engine did not answer")
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	return &engineResponse{resp.StatusCode, resp.Header, b}, nil
}

// engineJSON makes an RPC call to the engine (X-Amz-Target) and returns an error for any 4xx or 5xx.
func (s *Server) engineJSON(svcKey, target, version string, request any) error {
	body, err := json.Marshal(request)
	if err != nil {
		return err
	}
	resp, err := s.engineRaw(byKey[svcKey].SigningName, http.MethodPost, "/", map[string]string{
		"X-Amz-Target": target, "Content-Type": "application/x-amz-json-" + version}, body, 20*time.Second, smMaxReplyBytes)
	if err != nil {
		return err
	}
	if resp.Status >= 400 {
		return failure(target[strings.Index(target, ".")+1:], resp)
	}
	return nil
}

// ---- creating an endpoint through the engine's API (a seed or a template declared it)

// smDecl is one SageMaker resource a seed or a template declares, already resolved to literals.
type smDecl struct {
	kind     string // model, config or endpoint
	logical  string // the template's logical id, for the markers
	name     string
	variants []smVariant
	async    *smAsync
	asyncRaw any // the AsyncInferenceConfig in the API's shape, as sent to the engine
	config   string
	source   string
	reason   string // set when something could not be read: the resource is not created (marker cfn:<reason>)
}

const (
	smPlaceholderRole  = "arn:aws:iam::" + smAccount + ":role/rovara-sagemaker-shim"
	smPlaceholderImage = smAccount + ".dkr.ecr.us-east-1.amazonaws.com/rovara-model:latest"
)

// smSageMakerPlanned: whether the plan names the control plane (the engine is told about the endpoint only then).
func (s *Server) smControlPlanned() bool { return s.cfg.Planned != nil && s.cfg.Planned["sagemaker"] }

// applyDecls creates the declared resources in the engine (when the plan names `sagemaker`) and in the endpoint table, models first.
// It returns one error per resource the engine refused (an existing name is not an error: the table is made right all the same).
func (s *Server) applyDecls(decls []*smDecl) []error {
	var errs []error
	order := map[string]int{"model": 0, "config": 1, "endpoint": 2}
	sort.SliceStable(decls, func(i, j int) bool { return order[decls[i].kind] < order[decls[j].kind] })
	engine := s.smControlPlanned()
	for _, d := range decls {
		var err error
		switch d.kind {
		case "model":
			if engine {
				err = s.engineJSON("sagemaker", "SageMaker.CreateModel", "1.1", map[string]any{"ModelName": d.name, "ExecutionRoleArn": smPlaceholderRole,
					"PrimaryContainer": map[string]any{"Image": smPlaceholderImage}})
			}
			s.sm.addModel(d.name)
		case "config":
			if engine {
				var vs []any
				for _, v := range d.variants {
					vs = append(vs, map[string]any{"VariantName": v.Name, "ModelName": v.Model, "InitialInstanceCount": 1, "InstanceType": "ml.m5.large",
						"InitialVariantWeight": 1})
				}
				req := map[string]any{"EndpointConfigName": d.name, "ProductionVariants": vs}
				if d.asyncRaw != nil {
					req["AsyncInferenceConfig"] = d.asyncRaw
				}
				err = s.engineJSON("sagemaker", "SageMaker.CreateEndpointConfig", "1.1", req)
			}
			s.sm.addConfig(&smConfig{Name: d.name, Variants: d.variants, Async: d.async})
		case "endpoint":
			if engine {
				err = s.engineJSON("sagemaker", "SageMaker.CreateEndpoint", "1.1", map[string]any{"EndpointName": d.name, "EndpointConfigName": d.config})
			}
			s.sm.addEndpoint(&smEndpoint{Name: d.name, Config: d.config, Source: d.source})
		}
		if err != nil && !strings.Contains(err.Error(), "already exist") && !strings.Contains(err.Error(), "Cannot create already") {
			errs = append(errs, fmt.Errorf("%s %s: %v", d.kind, d.name, err))
		}
	}
	return errs
}

// ---- the seed's `sagemaker` section

// seedSageMaker declares endpoints: { "endpoints": [ { "name", "variants": ["AllTraffic"], "AsyncInferenceConfig": {API shape}, "backing": {...} } ] }.
func (r *seedRun) seedSageMaker(ep map[string]any) error {
	name := text(ep["name"], "")
	if !smEndpointNameRe.MatchString(name) {
		return fmt.Errorf("the endpoint name %q is not valid", name)
	}
	variants := []string{}
	for _, v := range list(ep["variants"]) {
		variants = append(variants, text(v, ""))
	}
	if len(variants) == 0 {
		variants = []string{"AllTraffic"}
	}
	var backing *smBacking
	if raw, ok := ep["backing"]; ok {
		b, err := json.Marshal(raw)
		if err != nil {
			return err
		}
		if backing, err = parseBacking(b); err != nil {
			return err
		}
		if err := r.s.smCheckBacking(backing); err != nil {
			return err
		}
	}
	async := asyncFromAPI(ep["AsyncInferenceConfig"])
	decls := []*smDecl{{kind: "model", name: name, source: "seed"}}
	cfg := &smDecl{kind: "config", name: name, async: async, asyncRaw: ep["AsyncInferenceConfig"], source: "seed"}
	for _, v := range variants {
		cfg.variants = append(cfg.variants, smVariant{Name: v, Model: name})
	}
	decls = append(decls, cfg, &smDecl{kind: "endpoint", name: name, config: name, source: "seed"})
	if errs := r.s.applyDecls(decls); len(errs) > 0 {
		return errs[0]
	}
	if backing != nil {
		return r.s.sm.setBacking(name, backing)
	}
	return nil
}

// smMaxBackings bounds the endpoints that have a backing of their own (each may hold up to 8 MiB of answers).
const smMaxBackings = 256

func (m *smState) setBacking(name string, b *smBacking) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, has := m.backing[name]; !has && len(m.backing) >= smMaxBackings {
		return errors.New("too many endpoints have answers set (at most 256)")
	}
	m.backing[name] = b
	return nil
}

// smCheckBacking refuses a backing the run cannot serve: a model stand-in that is not configured.
func (s *Server) smCheckBacking(b *smBacking) error {
	if b.Mode == "helper" && s.sm.helperURL(b) == nil {
		if b.Helper != "" {
			return errors.New("the helper is not one of the model stand-ins this run is configured with")
		}
		return errors.New("no model stand-in is configured for this run (" + envSMHelper + ")")
	}
	return nil
}

// ---- the control paths: /_rovara/sagemaker/endpoints[/<name>]

const smControlPrefix = "/_rovara/sagemaker/endpoints"

func (s *Server) smControl(w http.ResponseWriter, r *http.Request, p string) {
	if s.cfg.Planned == nil || !s.cfg.Planned["sagemaker-runtime"] {
		writeBody(w, http.StatusNotFound, jsonCType, jsonError("the plan does not name sagemaker-runtime"))
		return
	}
	rest := strings.TrimPrefix(p, smControlPrefix)
	rest = strings.Trim(rest, "/")
	if rest == "" {
		if r.Method != http.MethodGet {
			methodNotAllowed(w, "GET")
			return
		}
		writeBody(w, 200, jsonCType, s.smSummaryJSON(""))
		return
	}
	if strings.Contains(rest, "/") || !smEndpointNameRe.MatchString(rest) {
		writeBody(w, http.StatusNotFound, "text/html; charset=utf-8", []byte(notFoundHTML))
		return
	}
	switch r.Method {
	case http.MethodGet:
		out := s.smSummaryJSON(rest)
		if out == nil {
			writeBody(w, http.StatusNotFound, jsonCType, jsonError("no such endpoint"))
			return
		}
		writeBody(w, 200, jsonCType, out)
	case http.MethodPut:
		data, err := io.ReadAll(io.LimitReader(r.Body, smMaxDocBytes+1))
		if err != nil {
			writeBody(w, http.StatusBadRequest, jsonCType, jsonError("the document could not be read"))
			return
		}
		b, err := parseBacking(data)
		if err == nil {
			err = s.smCheckBacking(b)
		}
		if err != nil {
			writeBody(w, http.StatusUnprocessableEntity, jsonCType, jsonError(err.Error()))
			return
		}
		if err := s.sm.setBacking(rest, b); err != nil {
			writeBody(w, http.StatusUnprocessableEntity, jsonCType, jsonError(err.Error()))
			return
		}
		writeBody(w, 200, jsonCType, []byte(`{"status":"OK"}`))
	case http.MethodDelete:
		s.sm.mu.Lock()
		delete(s.sm.backing, rest)
		s.sm.mu.Unlock()
		writeBody(w, 200, jsonCType, []byte(`{"status":"OK"}`))
	default:
		methodNotAllowed(w, "GET, PUT, DELETE")
	}
}

// the words the evidence uses for each backing
func smLabel(b *smBacking) (label string, faked bool) {
	switch b.Mode {
	case "helper":
		return "Rovara model stand-in", true
	case "image":
		return "not available yet", false
	case smModeNone:
		return smNoAnswerLabel, false
	}
	if b.Source == "recorded" {
		return "recorded fake", true
	}
	return "hand-written fake", true
}

// smSummaryJSON: the endpoint table with each endpoint's backing and counters. name "" is every endpoint (and the names that are
// not endpoints); a name returns just that endpoint, or nil when there is none.
func (s *Server) smSummaryJSON(name string) []byte {
	m := s.sm
	m.mu.Lock()
	defer m.mu.Unlock()
	names := map[string]bool{}
	for n := range m.endpoints {
		names[n] = true
	}
	for n := range m.stats {
		names[n] = true // the counters outlive a reset and a delete: they are the round's evidence
	}
	if name != "" {
		if _, ok := names[name]; !ok {
			return nil
		}
		names = map[string]bool{name: true}
	}
	var sorted []string
	for n := range names {
		sorted = append(sorted, n)
	}
	sort.Strings(sorted)
	type backingOut struct {
		Mode       string `json:"mode"`
		Label      string `json:"label"`
		Source     string `json:"source"`
		RecordedOn string `json:"recordedOn,omitempty"`
		Helper     string `json:"helper,omitempty"`
		Rules      int    `json:"rules"`
		Queued     int    `json:"queued"`
		HasDefault bool   `json:"hasDefault"`
	}
	type epOut struct {
		Name         string        `json:"name"`
		Exists       bool          `json:"exists"`
		Source       string        `json:"source,omitempty"`
		ConfigName   string        `json:"configName,omitempty"`
		Variants     []string      `json:"variants,omitempty"`
		Async        bool          `json:"asyncConfigured"`
		Backing      backingOut    `json:"backing"`
		Faked        bool          `json:"faked"`
		NotTested    string        `json:"notTested"`
		Calls        int64         `json:"calls"`
		AsyncCalls   int64         `json:"async"`
		Streamed     int64         `json:"streamed"`
		Matched      int64         `json:"matched"`
		MadeUp       int64         `json:"madeUp"`
		Unmatched    int64         `json:"unmatched"`
		Errors       int64         `json:"errors"`
		ViaHelper    int64         `json:"viaHelper"`
		NotAvailable int64         `json:"notAvailable"`
		NoAnswer     int64         `json:"noAnswer"`
		AsyncDone    int64         `json:"asyncCompleted"`
		AsyncFailed  int64         `json:"asyncFailed"`
		NotifyFailed int64         `json:"notificationFailures"`
		LastUnmatch  []smUnmatched `json:"lastUnmatched,omitempty"`
	}
	out := struct {
		Endpoints []epOut          `json:"endpoints"`
		Unplanned map[string]int64 `json:"unplannedEndpoints"`
		Helpers   []string         `json:"helpers"`
	}{Endpoints: []epOut{}, Unplanned: map[string]int64{}, Helpers: []string{}}
	for _, h := range m.helpers {
		out.Helpers = append(out.Helpers, h.String())
	}
	if name == "" {
		for n, c := range m.unplanned {
			out.Unplanned[n] = c
		}
	}
	for _, n := range sorted {
		b := m.effectiveBacking(n)
		label, faked := smLabel(b)
		e := epOut{Name: n, Faked: faked, NotTested: "real model behaviour"}
		e.Backing = backingOut{Mode: b.Mode, Label: label, Source: b.Source, RecordedOn: b.RecordedOn, Helper: b.Helper, Rules: len(b.Rules),
			Queued: len(b.Queue), HasDefault: b.Default != nil}
		if b.Mode == "helper" && b.Helper == "" && len(m.helpers) > 0 {
			e.Backing.Helper = m.helpers[0].String()
		}
		if ep := m.endpoints[n]; ep != nil {
			e.Exists, e.Source, e.ConfigName = true, ep.Source, ep.Config
			if c := m.configs[ep.Config]; c != nil {
				for _, v := range c.Variants {
					e.Variants = append(e.Variants, v.Name)
				}
				e.Async = c.Async != nil
			}
		}
		if st := m.stats[n]; st != nil {
			e.Calls, e.AsyncCalls, e.Streamed, e.Matched, e.MadeUp, e.Unmatched, e.Errors = st.Calls, st.Async, st.Streamed, st.Matched, st.MadeUp, st.Unmatched, st.Errors
			e.ViaHelper, e.NotAvailable, e.NoAnswer, e.AsyncDone, e.AsyncFailed, e.NotifyFailed = st.Helper, st.NotAvailable, st.NoAnswer, st.AsyncDone, st.AsyncFailed, st.NotifyFailures
			e.LastUnmatch = st.Last
		}
		out.Endpoints = append(out.Endpoints, e)
	}
	var b []byte
	if name != "" {
		b, _ = json.Marshal(out.Endpoints[0])
	} else {
		b, _ = json.Marshal(out)
	}
	return b
}
