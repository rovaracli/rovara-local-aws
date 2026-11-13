package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The SageMaker runtime: InvokeEndpoint, InvokeEndpointAsync and InvokeEndpointWithResponseStream, answered by the front (see
// sagemaker.go for why). The wire shapes are botocore's model of sagemaker-runtime (restJson1): the endpoint name is in the path,
// the body is the payload, ContentType/Accept/CustomAttributes/TargetVariant travel as headers, a stream is application/vnd.amazon.eventstream
// with PayloadPart events (the part's bytes are the event payload), and an error is JSON with a `Message` and the code in X-Amzn-ErrorType.
//
// A request is answered by the endpoint's backing: canned answers (rules, a queue, a default), the model stand-in (a fake model server
// the run starts, reached at <helper>/invocations; SM3 is PARKED under owner decision 141: only an explicit backing names it, and an
// endpoint with no backing is refused with a no-answer, see smNoAnswer), or, later, the customer's own image (answered "not available yet").

func itoa(n int) string { return strconv.Itoa(n) }

func contextWithTimeout(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}

// lookupIPs resolves a stand-in's name (a variable so the tests can name a stand-in that only they can resolve).
var lookupIPs = func(host string) ([]net.IP, error) { return net.LookupIP(host) }

// smBadAddress: the addresses a model stand-in can never be at. A stand-in is a sibling of the front in the run's network; the front's
// own loopback (the engine, the control paths) and the link-local range (instance metadata) are not siblings.
func smBadAddress(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast()
}

// smResolveHelper resolves a stand-in's host and refuses it when any address is one a stand-in cannot be at. It returns the first
// IPv4 address (else the first address).
func smResolveHelper(host string) (net.IP, error) {
	var ips []net.IP
	if ip := net.ParseIP(host); ip != nil {
		ips = []net.IP{ip}
	} else {
		var err error
		if ips, err = lookupIPs(host); err != nil || len(ips) == 0 {
			return nil, errors.New("the model stand-in's name does not resolve")
		}
	}
	best := ips[0]
	for _, ip := range ips {
		if smBadAddress(ip) {
			return nil, errors.New("the model stand-in is at a loopback, link-local or unspecified address, which is refused")
		}
		if best.To4() == nil && ip.To4() != nil {
			best = ip
		}
	}
	return best, nil
}

// newHelperClient: the client for the model stand-in. It follows no redirect, uses no environment proxy, reads the model's reply as it
// is (no transparent decompression), and can dial ONLY the addresses the run's configuration names (ROVARA_AWS_SAGEMAKER_HELPER): the
// stand-in is a sibling of the front in the run's network, and nothing a request says can make the front dial anything else. A name is
// resolved once, at start (or, if the stand-in was not yet in DNS, at the first call that can resolve it), and the address is kept: a
// name that later answers differently is not followed. allowLoopback is for the tests, which serve a stand-in on 127.0.0.1.
func newHelperClient(helpers []*url.URL, allowLoopback bool) *http.Client {
	allowed := map[string]bool{}
	var mu sync.Mutex
	pinned := map[string]string{}
	pin := func(host, port string) (string, error) {
		mu.Lock()
		defer mu.Unlock()
		key := net.JoinHostPort(host, port)
		if p := pinned[key]; p != "" {
			return p, nil
		}
		var ip net.IP
		if allowLoopback {
			if ip = net.ParseIP(host); ip == nil {
				ips, err := lookupIPs(host)
				if err != nil || len(ips) == 0 {
					return "", errors.New("the model stand-in's name does not resolve")
				}
				ip = ips[0]
			}
		} else {
			var err error
			if ip, err = smResolveHelper(host); err != nil {
				return "", err
			}
		}
		pinned[key] = net.JoinHostPort(ip.String(), port)
		return pinned[key], nil
	}
	for _, h := range helpers {
		port := h.Port()
		if port == "" {
			port = "80"
		}
		allowed[net.JoinHostPort(h.Hostname(), port)] = true
		pin(h.Hostname(), port) // once, at start; a stand-in that is not in DNS yet is resolved at its first call
	}
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				if !allowed[addr] {
					return nil, errors.New("the front dials only the model stand-ins the run is configured with")
				}
				host, port, _ := net.SplitHostPort(addr)
				target, err := pin(host, port)
				if err != nil {
					return nil, err
				}
				return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, target)
			},
			Proxy:                 nil,
			DisableCompression:    true,
			MaxIdleConnsPerHost:   8,
			IdleConnTimeout:       30 * time.Second,
			ExpectContinueTimeout: 0,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

const smOpInvoke, smOpStream, smOpAsync = "invoke", "stream", "async"

// smInvokeOps are the operations of the route key sagemaker-runtime the front answers.
var smInvokeOps = map[string]bool{"InvokeEndpoint": true, "InvokeEndpointAsync": true, "InvokeEndpointWithResponseStream": true}

// smInv is one invocation, read from the request.
type smInv struct {
	op          string // invoke, stream or async
	name        string
	body        []byte
	contentType string
	accept      string
	variant     string // the requested TargetVariant
	custom      string
	targetModel string
	inferenceID string
	inputLoc    string // async
}

// smResult is what the backing produced, before it is written to anyone.
type smResult struct {
	err          *smErrorSpec
	notAvailable bool // mode image
	noAnswer     bool // no backing for the endpoint: refused, the test is not run
	unmatched    bool // canned, nothing matched
	matched      bool // canned, a rule or the queue answered
	madeUp       bool // canned, the default answered
	viaHelper    bool

	resp   *smResponse // canned
	data   []byte      // the whole body (canned or helper, not a stream)
	ctype  string
	custom string
	// a model stand-in's answer that is read as it arrives (a stream)
	hresp   *http.Response
	release func()
}

func (res *smResult) close() {
	if res.hresp != nil {
		res.hresp.Body.Close()
	}
	if res.release != nil {
		res.release()
	}
}

// ---- errors

// writeSMError writes a sagemaker-runtime error: HTTP status from the code, JSON body with Message (and the ModelError fields), the
// code in X-Amzn-ErrorType (botocore reads it from there).
func writeSMError(w http.ResponseWriter, e *smErrorSpec) {
	status := smErrorStatus[e.Code]
	body := map[string]any{"Message": e.Message}
	if e.Code == "ModelError" {
		body["OriginalStatusCode"] = e.OriginalStatusCode
		body["OriginalMessage"] = e.OriginalMessage
	}
	b, _ := json.Marshal(body)
	h := w.Header()
	h.Set("X-Amzn-Errortype", e.Code)
	h["x-amzn-RequestId"] = []string{newUUID()}
	writeBody(w, status, "application/json", b)
}

func smValidation(msg string) *smErrorSpec {
	return &smErrorSpec{Code: "ValidationError", Message: msg}
}

// smNoAnswerMessagePrefix starts the message of every no-answer refusal, for the people and tools that read it.
const smNoAnswerMessagePrefix = "Rovara: no answer for endpoint "

// smNoAnswer is the refusal for an endpoint with no backing (no recording or fixture approved; owner decision 141): a 400
// ValidationError, which the SDKs raise as a client error they do not retry (botocore: ClientError / sagemaker-runtime ValidationError,
// code in X-Amzn-ErrorType). The message says plainly what happened; the ledger entry carries smNoAnswerMarker.
func smNoAnswer(name string) *smErrorSpec {
	return smValidation(smNoAnswerMessagePrefix + name + ". No recording or fixture was approved for this endpoint, and the real model was not run. " +
		"Nothing was made up. This test was NOT RUN: it did not pass and it did not fail.")
}

func smNoAnswerResult(name string) *smResult {
	return &smResult{noAnswer: true, err: smNoAnswer(name)}
}

// modelError is the 424 a failing model container gives: status is what the container answered with.
func smModelError(status int, detail string) *smErrorSpec {
	kind := "server"
	if status >= 400 && status < 500 {
		kind = "client"
	}
	if len(detail) > 1024 {
		detail = detail[:1024]
	}
	return &smErrorSpec{Code: "ModelError", OriginalStatusCode: status, OriginalMessage: detail,
		Message: fmt.Sprintf("Received %s error (%d) from primary with message \"%s\".", kind, status, detail)}
}

// ---- the entry point

// serveSageMaker answers one invoke operation. It runs inside Server.api, after the plan check.
func (s *Server) serveSageMaker(w http.ResponseWriter, r *http.Request, id identified, entry *ledgerEntry, done func(int, bool)) {
	m := s.sm
	segs := splitPath(r.URL.EscapedPath())
	name := ""
	if len(segs) >= 2 {
		name, _ = url.PathUnescape(segs[1])
	}
	op := map[string]string{"InvokeEndpoint": smOpInvoke, "InvokeEndpointWithResponseStream": smOpStream, "InvokeEndpointAsync": smOpAsync}[id.Operation]
	fail := func(e *smErrorSpec, marker string, unsupported bool) {
		if marker != "" {
			s.ledger.mark(entry, marker)
		}
		writeSMError(w, e)
		done(smErrorStatus[e.Code], unsupported)
	}
	if !smEndpointNameRe.MatchString(name) {
		fail(smValidation("1 validation error detected: Value '"+name+"' at 'endpointName' failed to satisfy constraint: Member must satisfy regular expression pattern: ^[a-zA-Z0-9](-*[a-zA-Z0-9]){0,62}$"), "", false)
		return
	}
	inv := &smInv{op: op, name: name}
	switch op {
	case smOpInvoke:
		inv.contentType, inv.accept = r.Header.Get("Content-Type"), r.Header.Get("Accept")
	case smOpStream:
		inv.contentType, inv.accept = r.Header.Get("Content-Type"), r.Header.Get("X-Amzn-SageMaker-Accept")
	case smOpAsync:
		inv.contentType, inv.accept = r.Header.Get("X-Amzn-SageMaker-Content-Type"), r.Header.Get("X-Amzn-SageMaker-Accept")
		inv.inputLoc, inv.inferenceID = r.Header.Get("X-Amzn-SageMaker-InputLocation"), r.Header.Get("X-Amzn-SageMaker-Inference-Id")
	}
	inv.variant = r.Header.Get("X-Amzn-SageMaker-Target-Variant")
	inv.custom = r.Header.Get("X-Amzn-SageMaker-Custom-Attributes")
	inv.targetModel = r.Header.Get("X-Amzn-SageMaker-Target-Model")

	ep, cfg := m.lookup(name)
	if ep == nil {
		m.mu.Lock()
		key := name
		if _, seen := m.unplanned[key]; !seen && len(m.unplanned) >= smMaxStatNames {
			key = "(other)"
		}
		m.unplanned[key]++
		m.mu.Unlock()
		fail(smValidation(fmt.Sprintf("Endpoint %s of account %s not found.", name, smAccount)), "unplanned endpoint", false)
		return
	}
	if inv.variant != "" && cfg != nil && len(cfg.Variants) > 0 {
		found := false
		for _, v := range cfg.Variants {
			found = found || v.Name == inv.variant
		}
		if !found {
			fail(smValidation(fmt.Sprintf("Production variant %s not found for endpoint %s.", inv.variant, name)), "", false)
			return
		}
	}
	if op == smOpAsync {
		s.smAsyncInvoke(w, r, inv, cfg, entry, done)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, smMaxReplyBytes+1))
	if err != nil {
		fail(smValidation("The request body could not be read."), "", false)
		return
	}
	if len(body) > smMaxReplyBytes {
		fail(smValidation("Request payload is larger than the 6 MiB SageMaker accepts."), "", false)
		return
	}
	inv.body = body

	res := s.smProduce(r.Context(), inv, op == smOpStream)
	defer res.close()
	m.record(name, op, res)
	label := m.markerFor(name, res)
	s.ledger.mark(entry, label)
	if res.err != nil {
		writeSMError(w, res.err)
		done(smErrorStatus[res.err.Code], res.notAvailable)
		return
	}
	variant := smVariantName(cfg, inv.variant, res.resp)
	if op == smOpStream {
		status := s.smWriteStream(w, r, res, variant)
		done(status, false)
		return
	}
	h := w.Header()
	h.Set("Content-Type", res.ctype)
	h["x-amzn-invoked-production-variant"] = []string{variant}
	if res.custom != "" {
		h["x-amzn-sagemaker-custom-attributes"] = []string{res.custom}
	}
	h["x-amzn-RequestId"] = []string{newUUID()}
	writeBody(w, http.StatusOK, res.ctype, res.data)
	done(http.StatusOK, false)
}

func smVariantName(cfg *smConfig, requested string, resp *smResponse) string {
	switch {
	case resp != nil && resp.Variant != "":
		return resp.Variant
	case requested != "":
		return requested
	case cfg != nil && len(cfg.Variants) > 0:
		return cfg.Variants[0].Name
	}
	return "AllTraffic"
}

// ---- producing the answer

// smProduce asks the endpoint's backing. For a stream, a model stand-in's answer is left open in the result.
func (s *Server) smProduce(ctx context.Context, inv *smInv, stream bool) *smResult {
	m := s.sm
	m.mu.Lock()
	back := m.effectiveBacking(inv.name)
	mode := back.Mode
	rules := back.Rules // never changed after the backing is read
	helper := m.helperURL(back)
	m.mu.Unlock()
	// decoding the body and matching the rules (up to 1000 regular expressions) is done outside the lock; only claiming a rule's turn,
	// a queued answer or the default takes it
	var resp *smResponse
	var kind smPick
	if mode == "canned" {
		q := newSMRequest(inv.op, inv.contentType, inv.accept, inv.variant, inv.custom, inv.targetModel, inv.body)
		for _, r := range rules {
			if !r.Match.matches(q) {
				continue
			}
			m.mu.Lock()
			ok := r.claim()
			m.mu.Unlock()
			if ok {
				resp, kind = &r.Response, smRuleHit
				break
			}
		}
		if resp == nil {
			m.mu.Lock()
			resp, kind = back.queueOrDefault()
			m.mu.Unlock()
		}
	}

	res := &smResult{}
	switch mode {
	case smModeNone:
		return smNoAnswerResult(inv.name)
	case "image":
		res.notAvailable = true
		res.err = &smErrorSpec{Code: "ServiceUnavailable", Message: "Endpoint " + inv.name + " is backed by the customer's inference image, which is not available yet in this run. Nothing was invoked."}
	case "helper":
		s.smCallHelper(ctx, helper, inv, stream, res)
	default:
		switch kind {
		case smNone:
			res.unmatched = true
			s.sm.noteUnmatched(inv.name, inv)
			sum := newSMRequest(inv.op, inv.contentType, inv.accept, inv.variant, inv.custom, inv.targetModel, inv.body).sha
			res.err = smModelError(500, fmt.Sprintf("Rovara: no recorded or canned answer matches this request to endpoint %s (%s, content type %q, %d bytes, sha256 %s).",
				inv.name, inv.op, mediaType(inv.contentType), len(inv.body), sum))
		default:
			res.resp = resp
			res.matched, res.madeUp = kind != smDefaultHit, kind == smDefaultHit
			if resp.DelayMs > 0 && !sleepCtx(ctx, time.Duration(resp.DelayMs)*time.Millisecond) {
				res.err = &smErrorSpec{Code: "InternalFailure", Message: "The request was cancelled."}
				return res
			}
			if resp.Error != nil {
				e := *resp.Error
				switch {
				case e.Code == "ModelError" && e.Message == "":
					e = *smModelError(e.OriginalStatusCode, e.OriginalMessage)
				case e.Message == "":
					e.Message = "Rovara: this answer is a canned error."
				}
				res.err = &e
				return res
			}
			res.data = resp.data
			res.custom = resp.CustomAttributes
			res.ctype = resp.ContentType
			if res.ctype == "" {
				res.ctype = "application/json"
				if a := mediaType(inv.accept); a != "" && a != "*/*" && !strings.Contains(a, "*") {
					res.ctype = inv.accept
				}
			}
		}
	}
	return res
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// smCallHelper sends the request to the model stand-in's /invocations and fills res: a non-200 answer is a ModelError carrying the
// status, a reply over 6 MiB is refused, and only two headers of the model's reply are passed on. A stream is left open in res.
func (s *Server) smCallHelper(ctx context.Context, helper *url.URL, inv *smInv, stream bool, res *smResult) {
	res.viaHelper = true
	if helper == nil {
		res.err = &smErrorSpec{Code: "ServiceUnavailable", Message: "No model stand-in is configured for endpoint " + inv.name + "."}
		return
	}
	cctx, cancel := context.WithTimeout(ctx, s.sm.timeout)
	res.release = cancel
	req, err := http.NewRequestWithContext(cctx, http.MethodPost, strings.TrimRight(helper.String(), "/")+"/invocations", strings.NewReader(string(inv.body)))
	if err != nil {
		res.err = smModelError(500, "the model stand-in's address is not usable")
		return
	}
	ct := inv.contentType
	if ct == "" {
		ct = "application/octet-stream"
	}
	req.Header.Set("Content-Type", ct)
	if inv.accept != "" {
		req.Header.Set("Accept", inv.accept)
	}
	if inv.custom != "" {
		req.Header.Set("X-Amzn-SageMaker-Custom-Attributes", inv.custom)
	}
	if inv.targetModel != "" {
		req.Header.Set("X-Amzn-SageMaker-Target-Model", inv.targetModel)
	}
	req.Header.Set("User-Agent", "rovara-aws-front-sagemaker")
	resp, err := s.sm.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			res.err = &smErrorSpec{Code: "InternalFailure", Message: "The request was cancelled."}
		} else if cctx.Err() != nil {
			res.err = smModelError(504, "the model did not answer within "+s.sm.timeout.String())
		} else {
			res.err = smModelError(503, "the model stand-in did not answer")
		}
		return
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1025))
		resp.Body.Close()
		res.err = smModelError(resp.StatusCode, oneLine(string(b)))
		return
	}
	res.ctype = resp.Header.Get("Content-Type")
	if res.ctype == "" {
		res.ctype = "application/octet-stream"
	}
	if c := resp.Header.Get("X-Amzn-SageMaker-Custom-Attributes"); len(c) <= 1024 {
		res.custom = c
	}
	if stream {
		res.hresp = resp
		return
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, smMaxReplyBytes+1))
	resp.Body.Close()
	switch {
	case err != nil:
		res.err = smModelError(502, "the model's reply could not be read")
	case len(b) > smMaxReplyBytes:
		res.err = smModelError(502, "the model's reply is larger than 6 MiB")
	default:
		res.data = b
	}
}

// oneLine keeps a model's error text short and on one line, valid UTF-8, free of control characters.
func oneLine(s string) string {
	var b strings.Builder
	for _, r := range strings.ToValidUTF8(s, "?") {
		if r < 0x20 || r == 0x7f {
			r = ' '
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}

// ---- writing a stream

// smWriteStream writes the headers and the events of a stream: PayloadPart events (the part's bytes are the event payload), then, for a
// fixture that ends in an error, a ModelStreamError exception event. It returns the HTTP status for the ledger.
func (s *Server) smWriteStream(w http.ResponseWriter, r *http.Request, res *smResult, variant string) int {
	h := w.Header()
	h.Set("Content-Type", eventStreamContentType)
	h["x-amzn-sagemaker-content-type"] = []string{res.ctype}
	h["x-amzn-invoked-production-variant"] = []string{variant}
	if res.custom != "" {
		h["x-amzn-sagemaker-custom-attributes"] = []string{res.custom}
	}
	h["x-amzn-RequestId"] = []string{newUUID()}
	w.WriteHeader(http.StatusOK)
	if fl, ok := w.(http.Flusher); ok {
		fl.Flush()
	}
	ew := newEventStreamWriter(w)
	defer ew.Close()
	part := func(b []byte) bool {
		return ew.Event("PayloadPart", "application/octet-stream", b) == nil
	}
	streamErr := func(code, msg string) {
		b, _ := json.Marshal(map[string]string{"Message": msg, "ErrorCode": code})
		ew.Exception("ModelStreamError", "application/json", b)
	}
	if res.hresp != nil {
		buf := make([]byte, 8<<10)
		total := 0
		for {
			n, err := res.hresp.Body.Read(buf)
			if n > 0 {
				total += n
				if total > smMaxReplyBytes {
					streamErr("StreamBroken", "the model's reply is larger than 6 MiB")
					return http.StatusOK
				}
				if !part(append([]byte(nil), buf[:n]...)) {
					return http.StatusOK
				}
			}
			if err == io.EOF {
				return http.StatusOK
			}
			if err != nil {
				if r.Context().Err() != nil {
					return http.StatusOK // the caller went away
				}
				code := "StreamBroken"
				if errors.Is(err, context.DeadlineExceeded) {
					code = "ModelInvocationTimeExceeded"
				}
				streamErr(code, "The model's reply ended with an error.")
				return http.StatusOK
			}
		}
	}
	resp := res.resp
	var parts [][]byte
	if resp != nil && len(resp.Parts) > 0 {
		for _, p := range resp.Parts {
			parts = append(parts, []byte(p))
		}
	} else {
		size := 0
		if resp != nil {
			size = resp.PartSize
		}
		parts = splitParts(res.data, size)
	}
	for i, p := range parts {
		if i > 0 && resp != nil && resp.PartDelayMs > 0 && !sleepCtx(r.Context(), time.Duration(resp.PartDelayMs)*time.Millisecond) {
			return http.StatusOK
		}
		if !part(p) {
			return http.StatusOK
		}
	}
	if resp != nil && resp.StreamError != nil {
		msg := resp.StreamError.Message
		if msg == "" {
			msg = "Rovara: this stream was told to end with an error."
		}
		streamErr(resp.StreamError.ErrorCode, msg)
	}
	return http.StatusOK
}

// ---- counters and the ledger's markers

func (m *smState) record(name, op string, res *smResult) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := m.statsFor(name)
	st.Calls++
	switch op {
	case smOpStream:
		st.Streamed++
	case smOpAsync:
		st.Async++
	}
	switch {
	case res.matched:
		st.Matched++
	case res.madeUp:
		st.MadeUp++
	case res.unmatched:
		st.Unmatched++
	}
	if res.viaHelper {
		st.Helper++
	}
	if res.notAvailable {
		st.NotAvailable++
	}
	if res.noAnswer {
		st.NoAnswer++
	}
	if res.err != nil {
		st.Errors++
	}
}

// noteUnmatched keeps the size and hash of a request nothing matched, for writing the fixture (never the body).
func (m *smState) noteUnmatched(name string, inv *smInv) {
	q := newSMRequest(inv.op, inv.contentType, inv.accept, inv.variant, inv.custom, inv.targetModel, inv.body)
	m.mu.Lock()
	defer m.mu.Unlock()
	st := m.statsFor(name)
	st.Last = append(st.Last, smUnmatched{Operation: inv.op, ContentType: mediaType(inv.contentType), Bytes: len(inv.body), SHA256: q.sha})
	if len(st.Last) > smMaxLast {
		st.Last = st.Last[len(st.Last)-smMaxLast:]
	}
}

// markerFor words one call for the ledger entry: what answered it, and that it is a fake.
func (m *smState) markerFor(name string, res *smResult) string {
	if res.noAnswer {
		return smNoAnswerMarker
	}
	m.mu.Lock()
	b := m.effectiveBacking(name)
	m.mu.Unlock()
	label, _ := smLabel(b)
	switch {
	case res.notAvailable:
		return "not available yet"
	case res.unmatched:
		return label + "; unmatched"
	case res.madeUp:
		return label + "; made-up answer"
	}
	return label
}
