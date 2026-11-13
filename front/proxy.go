package main

import (
	"bytes"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Server is the front's HTTP handler: control paths, and every AWS API request forwarded to the engine.
type Server struct {
	cfg    *Config
	engine *Engine
	ledger *Ledger
	guard  *Guard
	rw     *rewriter
	ctl    sync.Mutex // one reset or seed at a time
	// large responses held in memory at once: at most rewriteSlots documents of rewriteLimit bytes and querySlots SQS Query
	// answers of queryLimit bytes, so a crowd of long polls cannot approach the container's memory
	rewriteSlots slots
	querySlots   slots
	// the heavy-function registry (planned mode, lambda_heavy.go), and the one slot a package inspection holds its buffers in
	heavy  *heavyRegistry
	budget inspectBudget
	// the SageMaker endpoint shim (sagemaker.go)
	sm *smState
	// the Bedrock runtime shim (bedrock.go)
	bd *bdState
	// the function runner (runner_*.go): nil unless ROVARA_AWS_RUNNER_SOCKET is set (startRunner)
	runner *runnerSys
	// the delivery sink (sns_sink.go), the connections it may make (sink_net.go) and the DNS registry (sink_dns.go); nil when not configured
	sink *snsSink
	snet *sinkNet
	dns  *dnsRegistry
}

const (
	rewriteLimit = 2 << 20
	queryLimit   = 8 << 20
)

func newServer(cfg *Config, engine *Engine) *Server {
	ledger := newLedger(cfg.LedgerMax)
	ledger.planned = cfg.Planned != nil
	srv := &Server{
		cfg:          cfg,
		engine:       engine,
		ledger:       ledger,
		guard:        newGuard(cfg.Token, cfg.DevOpen),
		rw:           newRewriter(cfg.BaseURL),
		rewriteSlots: newSlots(32),
		querySlots:   newSlots(6),
		heavy:        newHeavyRegistry(),
		sm:           newSMState(cfg),
		bd:           newBDState(),
	}
	if cfg.SNS != nil || cfg.DNS != nil {
		timeout := snsDefaultAttemptTimeout
		if cfg.SNS != nil && cfg.SNS.AttemptTimeout > 0 {
			timeout = cfg.SNS.AttemptTimeout
		}
		srv.snet = newSinkNet(cfg.RunCARoots, cfg.SelfTLSAddr, net.ParseIP(trimBrackets(cfg.Host)), timeout)
		srv.snet.local = localAddrs()
		if cfg.SNS != nil && cfg.SNS.privateCheck != nil {
			srv.snet.private = cfg.SNS.privateCheck // tests only
		}
	}
	if cfg.SNS != nil {
		srv.sink = newSNSSink(srv, cfg.SNS, srv.snet, cfg.SelfTLSAddr)
	}
	if cfg.DNS != nil {
		srv.dns = newDNSRegistry(cfg.DNS, srv.snet)
	}
	return srv
}

const maxFormPeek = 4 << 20 // the largest form body read whole (an SQS message is at most 1 MiB, url-encoded up to 3x)

// ServeHTTP: guard first, on every path the request has; then control paths; then the API.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	asSent := r.URL.Path
	if asSent == "" {
		asSent = "/"
	}
	q := r.URL.Query()
	final := asSent
	bucket := vhostBucket(r, q, s.cfg.Hostname)
	if bucket != "" {
		final = "/" + bucket + asSent
	}
	token := presentedToken(r.Header)
	for _, p := range []string{asSent, final} {
		if ref := s.guard.check(r.Method, p, token); ref != nil {
			writeBody(w, http.StatusForbidden, "application/json", jsonError(ref.message))
			return
		}
	}
	if p := normalizePath(asSent); isControlPath(p) {
		s.control(w, r, p)
		return
	}
	if isControlPath(normalizePath(final)) {
		// unreachable by the bucket-name rule; refused all the same, never forwarded
		writeBody(w, http.StatusNotFound, "text/html; charset=utf-8", []byte("<html><body><h1>Resource not found</h1></body></html>"))
		return
	}
	if s.sink != nil && s.sink.serveSigningCert(w, r) {
		return
	}
	s.api(w, r, q, bucket)
}

var hopByHop = map[string]bool{"connection": true, "keep-alive": true, "proxy-authenticate": true, "proxy-authorization": true,
	"proxy-connection": true, "te": true, "trailer": true, "transfer-encoding": true, "upgrade": true}

// notForwarded: request headers the engine never sees. The token and the forwarding headers (which could steer the
// engine's own host logic) are dropped.
func notForwarded(name string) bool {
	l := strings.ToLower(name)
	if hopByHop[l] || l == "forwarded" || l == "x-real-ip" || strings.HasPrefix(l, "x-forwarded-") || l == strings.ToLower(controlHeader) || l == "expect" {
		return true
	}
	return false
}

// syntheticAuthorization is what a request with no SigV4 credential is given: the engine picks the service from the
// credential scope, and runs with signature checks off, so the signature is never looked at.
func syntheticAuthorization(signingName, region string) string {
	if region == "" {
		region = defaultRegion
	}
	return "AWS4-HMAC-SHA256 Credential=ROVARATESTKEY/20260101/" + region + "/" + signingName + // gitleaks:allow (not a secret)
		"/aws4_request, SignedHeaders=host, Signature=0000000000000000000000000000000000000000000000000000000000000000"
}

// engineAuthorization: the SigV4 header the engine is given, naming the front's decision. Signature checks are off.
func engineAuthorization(id identified) string {
	ak, date, region := id.AccessKey, id.Date, id.Region
	if ak == "" {
		ak = "ROVARATESTKEY"
	}
	if date == "" {
		date = "20260101"
	}
	if region == "" {
		region = defaultRegion
	}
	return "AWS4-HMAC-SHA256 Credential=" + ak + "/" + date + "/" + region + "/" + id.Service.SigningName +
		"/aws4_request, SignedHeaders=host, Signature=0000000000000000000000000000000000000000000000000000000000000000"
}

// readsFormBody: whether the front looks at a POST body for Action and Version. The engine reads a Query service's body as a
// form whatever the Content-Type, so the front does too, for a request that is not RPC (no X-Amz-Target, no CBOR) and whose
// scope names a Query service or none; a REST or JSON service's body is data (an object, a JSON document), never read here.
func (s *Server) readsFormBody(r *http.Request) bool {
	if r.Method != http.MethodPost || r.Header.Get("X-Amz-Target") != "" || strings.EqualFold(r.Header.Get("smithy-protocol"), "rpc-v2-cbor") {
		return false
	}
	if s.cfg.Planned != nil {
		return plannedReadsForm(r.Header, r.URL.RawQuery)
	}
	sc, _ := requestScope(r.Header, r.URL.RawQuery)
	if sc == nil {
		return true
	}
	svc := scopeService(sc.Service)
	return svc == nil || svc.Default == protoQuery
}

func (s *Server) api(w http.ResponseWriter, r *http.Request, q url.Values, bucket string) {
	start := time.Now()
	action, version := q.Get("Action"), q.Get("Version")
	if s.runner != nil || s.sink != nil {
		// aws-chunked framing is removed (the engine removes it for every service) before anything reads the body
		if st, msg := s.runnerDecodeChunked(r); st != 0 {
			writeAWSError(w, protoJSON, st, "InvalidRequest", msg, "")
			return
		}
	}
	body := io.Reader(r.Body)
	var form url.Values
	peeked := false
	if s.readsFormBody(r) {
		peeked = true
		peek, _ := io.ReadAll(io.LimitReader(r.Body, maxFormPeek+1))
		if len(peek) <= maxFormPeek {
			if f, err := url.ParseQuery(string(peek)); err == nil {
				form = f
				if a := f.Get("Action"); a != "" {
					action, version = a, f.Get("Version")
				} else if a := f.Get("Operation"); a != "" && action == "" {
					action, version = a, f.Get("Version") // the Query controller's legacy fallback
				}
			}
		}
		body = io.MultiReader(bytes.NewReader(peek), r.Body)
	}
	if s.sink != nil && s.sink.isLink(r, q) {
		// a link an SNS message carried (the SubscribeURL or the UnsubscribeURL): no credential, no version
		entry := s.ledger.begin("sns", q.Get("Action"), r.Method)
		sw := &statusWriter{ResponseWriter: w, code: http.StatusOK}
		s.sink.linkRequest(sw, r, q)
		s.ledger.complete(entry, sw.code, false, time.Since(start).Milliseconds())
		return
	}
	idPath := r.URL.Path
	if bucket != "" {
		idPath = "/" + bucket + idPath
	}
	rawPath := r.URL.EscapedPath()
	if bucket != "" {
		rawPath = "/" + bucket + rawPath
	}
	var id identified
	if s.cfg.Planned != nil {
		id = identifyPlanned(r.Method, idPath, rawPath, r.Header, r.URL.RawQuery, action, version, s.cfg.Planned)
	} else {
		id = identify(r.Method, idPath, rawPath, r.Header, r.URL.RawQuery, action, version)
	}
	svcKey := "unknown"
	if id.Service != nil {
		svcKey = id.Service.Key
	}
	entry := s.ledger.begin(svcKey, id.Operation, r.Method)
	done := func(status int, unsupported bool) {
		s.ledger.complete(entry, status, unsupported, time.Since(start).Milliseconds())
	}
	if id.Reason != notRefused {
		// not forwarded: an unknown scope or target, an ambiguous Query action, or a scope that disagrees with the request
		writeUnknown(w, id, r.Method, idPath)
		done(http.StatusNotFound, true)
		return
	}
	if s.cfg.Planned != nil {
		if !s.cfg.Planned[id.Service.Key] {
			// a service of the table the plan did not name: not forwarded, counted as out of plan
			s.ledger.outOfPlan(entry)
			writeDisabled(w, id.Proto, id.Service.Key)
			done(http.StatusBadRequest, false)
			return
		}
	} else if s.cfg.Disabled[id.Service.ConfigKey] {
		writeDisabled(w, id.Proto, id.Service.Key)
		done(http.StatusBadRequest, false)
		return
	}
	if s.runner != nil || s.sink != nil {
		if id.Service.Key != "s3" && !runnerDataPlane(r, id.Service.Key, id.Operation) {
			// gzip is decoded and any other encoding refused, so the guard reads what the engine will read (shared by the function runner and
			// the delivery sink's tap wall: both must judge the decoded body)
			if st, msg := s.runnerDecodeGzip(r, peeked); st != 0 {
				writeAWSError(w, id.Proto, st, "InvalidRequest", msg, "")
				done(st, false)
				return
			}
			if !peeked {
				body = io.Reader(r.Body)
			}
		}
	}
	if s.runner != nil {
		// the function runner: an Invoke of a function it holds is answered here; a call that names its hidden queues, bucket or role is refused
		if id.Service.Key == "lambda" && id.Operation == "Invoke" {
			if st, handled := s.runnerDirect(w, r, rawPath); handled {
				done(st, false)
				return
			}
		}
		var releaseGuard func()
		var refused bool
		body, releaseGuard, refused = s.runnerGuard(w, r, id, bucket, form, body)
		defer releaseGuard()
		if refused {
			done(http.StatusForbidden, false)
			return
		}
	}
	if s.sink != nil {
		if s.sinkIntercept(w, r, q, form, &body, id, done) {
			return
		}
	}
	if s.cfg.Planned != nil && id.Service.Key == "sagemaker-runtime" && smInvokeOps[id.Operation] {
		// the three invoke operations are answered by the front (sagemaker.go): the engine only ever says 424
		s.serveSageMaker(w, r, id, entry, done)
		return
	}
	if s.cfg.Planned != nil && id.Service.Key == "bedrock-runtime" && bdOps[id.Operation] {
		// the six operations that make text are answered by the front (bedrock.go): the engine's one fixed sentence cannot be scripted
		s.serveBedrock(w, r, id, entry, done)
		return
	}
	if s.cfg.Planned != nil && id.Service.Key == "bedrock-runtime" {
		// the other operations of the route key (async invoke, the bidirectional stream, InvokeGuardrailChecks) are the engine's own fake
		s.ledger.mark(entry, "emulated by the engine; not a Rovara fixture")
	}
	var cfn *cfnFinding
	if s.cfg.Planned != nil && id.Service.Key == "cloudformation" && cfnTemplateOps[id.Operation] {
		cfn = s.cfnCheck(form) // read now, recorded below if the engine accepts the request
		if cfn != nil {
			cfn.op, cfn.stack, cfn.changeSet = id.Operation, form.Get("StackName"), form.Get("ChangeSetName")
		}
		if cfn != nil && cfn.hidden {
			writeAWSError(w, id.Proto, http.StatusForbidden, "AccessDenied", "This template names a resource reserved by the Rovara function runner.", "")
			done(http.StatusForbidden, false)
			return
		}
	}
	// the SageMaker endpoints the code makes through the front are read, and recorded below if the engine accepts the call
	smObserve := s.cfg.Planned != nil && s.cfg.Planned["sagemaker-runtime"] && id.Service.Key == "sagemaker" && smObservedOps[id.Operation]
	var smHead []byte
	smTruncated := false
	if smObserve {
		head, truncated, release := s.readForInspection(body, r.ContentLength, 1<<20)
		defer release()
		body = io.MultiReader(bytes.NewReader(head), body)
		smHead, smTruncated = head, truncated
	}
	var lam *lambdaChange
	var rplan *runnerPlan
	rplanSettled := false
	fwdLen := r.ContentLength
	lamName := ""
	var targets func([]byte) ([]targetRef, string)
	targetSrc := ""
	if s.cfg.Planned != nil {
		targets = targetHook(id.Service.Key, id.Operation)
		targetSrc = targetSource[id.Service.Key]
	}
	if s.cfg.Planned != nil && id.Service.Key == "lambda" && lambdaOps[id.Operation] {
		segs := splitPath(rawPath)
		if len(segs) > 2 {
			lamName = segs[2]
		}
		switch id.Operation {
		case "Invoke", "DeleteFunction":
		default:
			// look at the package: the body is read (within the byte budget, never waiting for it), judged without extracting
			// anything, and forwarded unchanged
			if s.runner != nil && lambdaPackageOps[id.Operation] && (r.ContentLength < 0 || r.ContentLength > runnerBigBody) {
				// a big package body is parsed by one request at a time
				if !s.runner.big.acquire(r.Context()) {
					done(499, false)
					return
				}
				defer s.runner.big.release()
			}
			head, truncated, release := s.readForInspection(body, r.ContentLength, s.lambdaInspectLimit())
			defer release()
			if s.runner != nil && truncated && hiddenRef(string(head[:min(len(head), 64<<10)])) {
				writeAWSError(w, id.Proto, http.StatusForbidden, "AccessDenied", "This name is reserved by the Rovara function runner.", "")
				done(http.StatusForbidden, false)
				return
			}
			rest := &tailKeeper{r: body}
			body = io.MultiReader(bytes.NewReader(head), rest)
			lam = s.planLambda(id.Operation, rawPath, head, truncated)
			if lam == nil && s.runner != nil && !truncated && lambdaPackageOps[id.Operation] {
				// a body the detector could not read is refused when the runner is on: nothing is forwarded unchecked
				writeAWSError(w, id.Proto, http.StatusBadRequest, "InvalidRequest", "The request body could not be read.", "")
				done(http.StatusBadRequest, false)
				return
			}
			if lam != nil {
				lam.tk = rest
				if s.runner != nil && !truncated {
					// the function runner: keep the real package, and send the engine the stub when the function is heavy
					if rplan = s.runner.plan(id.Operation, rawPath, head, lam); rplan != nil && rplan.refuse {
						writeAWSError(w, id.Proto, http.StatusForbidden, "AccessDenied", "This name is reserved by the Rovara function runner.", "")
						done(http.StatusForbidden, false)
						return
					} else if rplan != nil && rplan.body != nil {
						body, fwdLen = bytes.NewReader(rplan.body), int64(len(rplan.body))
					}
				}
			}
		}
	}
	if s.runner != nil && rplan == nil && id.Service.Key == "lambda" && id.Operation == "PublishVersion" {
		rplan = s.runner.plan(id.Operation, rawPath, nil, nil)
	}
	defer func() {
		if rplan != nil && !rplanSettled && rplan.abort != nil {
			rplan.abort() // the request never reached an answer from the engine
		}
	}()
	var targetRefs []targetRef
	targetUnchecked := ""
	if targets != nil {
		// a call that tells a planned service which other services to call: read now, recorded below if the engine accepts it
		head, truncated, release := s.readForInspection(body, r.ContentLength, targetBodyCap)
		defer release()
		body = io.MultiReader(bytes.NewReader(head), body)
		if truncated {
			targetUnchecked = "unreadable"
		} else {
			targetRefs, targetUnchecked = targets(head)
		}
	}
	gen, state, err := s.engine.current()
	if err != nil {
		writeUnavailable(w, id.Proto, state)
		done(http.StatusServiceUnavailable, false)
		return
	}

	if id.Service.Key == "sqs" && id.Proto == protoQuery {
		status, unsupported := s.serveSQSQuery(w, r, gen, id, sqsQueryParams(q, form))
		done(status, unsupported)
		return
	}

	// the request to the engine
	escPath := r.URL.EscapedPath()
	if escPath == "" {
		escPath = "/"
	}
	if bucket != "" {
		escPath = "/" + bucket + escPath
	}
	target := "https://127.0.0.1:" + strconv.Itoa(gen.port) + escPath
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	out, err := http.NewRequestWithContext(r.Context(), r.Method, target, nil)
	if err != nil {
		writeAWSError(w, id.Proto, http.StatusBadRequest, "InvalidRequest", "the request cannot be forwarded", "")
		done(http.StatusBadRequest, false)
		return
	}
	for k, vs := range r.Header {
		if notForwarded(k) {
			continue
		}
		out.Header[k] = append([]string(nil), vs...)
	}
	out.Host = "127.0.0.1:" + strconv.Itoa(gen.port)
	if r.ContentLength != 0 || len(r.TransferEncoding) > 0 {
		out.Body = io.NopCloser(body)
		out.ContentLength = fwdLen // -1 sends chunked
	}
	if out.Header.Get("User-Agent") == "" {
		out.Header["User-Agent"] = []string{""} // no Go default
	}
	// The engine routes by the scope of this header. It always gets one the front wrote, naming the service the front decided on
	// (the client's key, date and region are kept): whatever the client sent in Authorization or X-Amz-Credential, the engine
	// executes the service the front checked, never another.
	out.Header.Set("Authorization", engineAuthorization(id))
	needsRewrite := s.needsBodyRewrite(id)
	if needsRewrite {
		out.Header.Del("Accept-Encoding") // the body is read and changed: it must arrive as text
	}

	resp, err := gen.client.Do(out)
	if err != nil {
		if r.Context().Err() != nil {
			done(499, false) // the caller went away
			return
		}
		log.Printf("the engine did not answer a %s request: %v", id.Service.Key, sanitizeErr(err))
		writeAWSError(w, id.Proto, http.StatusBadGateway, "ServiceUnavailable", "The local AWS emulator did not answer.", "")
		done(http.StatusBadGateway, false)
		return
	}
	defer resp.Body.Close()
	status := resp.StatusCode
	if cfn != nil && status < 300 {
		s.recordCFN(cfn)
	}
	if status < 300 && s.cfg.Planned != nil && id.Service.Key == "cloudformation" && id.Operation == "ExecuteChangeSet" {
		s.smExecuteChangeSet(form)
	}
	if s.sink != nil && status < 300 && id.Service.Key == "cloudformation" && sinkCFNOps[id.Operation] {
		s.sink.mayHaveUnseen.Store(true) // a stack can create an AWS::SNS::Subscription the front never saw Subscribe
	}
	if smObserve && status < 300 {
		if smTruncated {
			s.ledger.recordUnsupported("sagemaker-runtime", "sagemaker:request-too-large", id.Operation)
		} else {
			s.sm.observe(id.Operation, smHead)
		}
	}
	if targets != nil && status < 300 && (len(targetRefs) > 0 || targetUnchecked != "") {
		s.recordTargets(targetSrc, targetRefs, targetUnchecked)
	}
	ctype, enc := resp.Header.Get("Content-Type"), resp.Header.Get("Content-Encoding")
	canHaveBody := r.Method != http.MethodHead && status != http.StatusNoContent && status != http.StatusNotModified && status >= 200

	// Which responses are read whole: the ones rewritten, and errors (to classify them). Everything else streams.
	rewriteKind := s.rewriteKindFor(id, status, ctype, enc, resp.ContentLength)
	capture := (lam != nil && lam.op == "PublishLayerVersion" && status < 300) || (rplan != nil && rplan.commit != nil && status < 300) // the layer's ARN, a function's version, are in the (small) answer
	buffer := canHaveBody && (rewriteKind != rwNone || status >= 400 || capture)
	var data []byte
	var rest io.Reader
	if buffer {
		limit := int64(64 << 10)
		if rewriteKind != rwNone {
			limit = rewriteLimit
			if !s.rewriteSlots.acquire(r.Context()) {
				done(499, false)
				return
			}
			defer s.rewriteSlots.release()
		}
		data, _ = io.ReadAll(io.LimitReader(resp.Body, limit+1))
		if int64(len(data)) > limit {
			rest = io.MultiReader(bytes.NewReader(data[limit:]), resp.Body)
			data = data[:limit]
			rewriteKind = rwNone // too large to rewrite
		}
	}
	unsupported := isUnsupported(status, resp.Header.Get("x-amzn-errortype"), data)
	if s.runner != nil && id.Service.Key == "lambda" {
		if status < 300 {
			data = s.runnerAfter(id.Operation, rawPath, r.URL.Query().Get("Qualifier"), rplan, data, buffer && rest == nil)
		} else if rplan != nil && rplan.abort != nil {
			rplan.abort()
		}
		rplanSettled = true
	}
	if s.cfg.Planned != nil && status < 300 && id.Service.Key == "lambda" {
		switch {
		case lam != nil:
			s.applyLambda(lam, data)
		case id.Operation == "Invoke":
			s.noteInvoke(lamName)
		case id.Operation == "DeleteFunction":
			s.dropFunction(lamName)
		}
	}

	hdr := w.Header()
	for k, vs := range resp.Header {
		if hopByHop[strings.ToLower(k)] || strings.EqualFold(k, "Content-Length") {
			continue
		}
		name := k
		if len(k) > 6 && strings.EqualFold(k[:6], "x-amz-") {
			name = strings.ToLower(k) // AWS writes these in lower case; user metadata keys are read from the wire name
		}
		meta := strings.HasPrefix(name, "x-amz-meta-") // an object's own metadata is data, never rewritten
		for _, v := range vs {
			if !meta {
				v = s.rw.internalAddr(v, gen.port)
			}
			hdr[name] = append(hdr[name], v)
		}
	}
	if buffer && rest == nil {
		data = s.applyRewrite(rewriteKind, data, ctype, gen.port)
		hdr.Set("Content-Length", strconv.Itoa(len(data)))
		w.WriteHeader(status)
		w.Write(data)
		done(status, unsupported)
		return
	}
	if resp.ContentLength >= 0 {
		hdr.Set("Content-Length", strconv.FormatInt(resp.ContentLength, 10))
	}
	w.WriteHeader(status)
	if canHaveBody {
		if buffer {
			w.Write(data)
		}
		src := io.Reader(resp.Body)
		if rest != nil {
			src = rest
		}
		copyFlushing(w, src, resp.ContentLength < 0)
	}
	done(status, unsupported)
}

type rewriteKind int

const (
	rwNone rewriteKind = iota
	rwQueueJSON
	rwQueueXML
	rwSNSEnvelope
	rwS3Location
	rwPublishedEndpoint // planned mode: an operation whose answer names the engine's address or a function URL
	rwStackQueueURLs    // planned mode: a CloudFormation answer that names a queue by its AWS-style URL
	rwRunnerOverlay     // function runner: a Lambda answer that carries function configurations (overlaid by runnerAfter)
	rwRunnerHide        // function runner: ListBuckets and ListRoles answers, without the hidden bucket and role
)

// plannedRewrites: the planned-mode allow-list, by service key and operation (see rewrite.go).
var plannedRewrites = map[string]map[string]rewriteKind{
	"apigatewayv2": {"CreateApi": rwPublishedEndpoint, "GetApi": rwPublishedEndpoint, "GetApis": rwPublishedEndpoint, "UpdateApi": rwPublishedEndpoint,
		"ImportApi": rwPublishedEndpoint, "ReimportApi": rwPublishedEndpoint},
	"iot": {"DescribeEndpoint": rwPublishedEndpoint},
	"lambda": {"CreateFunctionUrlConfig": rwPublishedEndpoint, "GetFunctionUrlConfig": rwPublishedEndpoint, "ListFunctionUrlConfigs": rwPublishedEndpoint,
		"UpdateFunctionUrlConfig": rwPublishedEndpoint},
	// a state machine that created a queue answers with its URL in the execution output
	"sfn": {"DescribeExecution": rwStackQueueURLs, "GetExecutionHistory": rwStackQueueURLs, "StartSyncExecution": rwStackQueueURLs},
	"cloudformation": {"DescribeStacks": rwStackQueueURLs, "DescribeStackResource": rwStackQueueURLs, "DescribeStackResources": rwStackQueueURLs,
		"ListStackResources": rwStackQueueURLs},
}

func (s *Server) plannedRewrite(id identified) rewriteKind {
	if s.cfg.Planned == nil || id.Service == nil {
		return rwNone
	}
	if s.runner != nil {
		if k := runnerRewriteKind(id); k != rwNone {
			return k
		}
	}
	return plannedRewrites[id.Service.Key][id.Operation]
}

func (s *Server) needsBodyRewrite(id identified) bool {
	switch {
	case id.Service == nil:
		return false
	case id.Service.Key == "sqs" && (queueOps[id.Operation] || id.Operation == "ReceiveMessage"):
		return true
	case id.Service.Key == "s3" && id.Operation == "CompleteMultipartUpload":
		return true
	}
	return s.plannedRewrite(id) != rwNone
}

// rewriteKindFor decides what, if anything, is changed in a 2xx response body. Only a response whose type is an API
// document (JSON or XML), with no transfer encoding of its own, of a size known to be small, is ever looked at.
func (s *Server) rewriteKindFor(id identified, status int, ctype, enc string, length int64) rewriteKind {
	if status < 200 || status >= 300 || !textual(ctype, enc) {
		return rwNone
	}
	switch {
	case id.Service.Key == "sqs" && queueOps[id.Operation]:
		if strings.Contains(strings.ToLower(ctype), "xml") {
			return rwQueueXML
		}
		return rwQueueJSON
	case id.Service.Key == "sqs" && id.Operation == "ReceiveMessage" && !strings.Contains(strings.ToLower(ctype), "xml"):
		return rwSNSEnvelope
	case id.Service.Key == "s3" && id.Operation == "CompleteMultipartUpload":
		return rwS3Location
	}
	if k := s.plannedRewrite(id); k != rwNone {
		return k
	}
	// Only the operations above are ever rewritten: an explicit allow-list, no catch-all (an object's bytes and a DynamoDB item
	// with its checksum are never changed). Header values that name the engine's own address are still rewritten.
	return rwNone
}

func (s *Server) applyRewrite(kind rewriteKind, data []byte, ctype string, port int) []byte {
	switch kind {
	case rwQueueJSON:
		data = s.rw.queueURLsJSON(data)
		if s.sink != nil {
			data = hideTapQueues(data)
		}
	case rwQueueXML:
		data = s.rw.queueURLsXML(data)
	case rwSNSEnvelope:
		data = s.rw.snsEnvelopes(data)
	case rwS3Location:
		data = s.rw.s3Location(data)
	case rwPublishedEndpoint:
		data = s.rw.functionURLs(data)
	case rwStackQueueURLs:
		data = s.rw.queueURLsAnywhere(data)
	case rwRunnerHide:
		data = hideInLists(data)
	}
	if kind != rwNone {
		data = s.rw.internalAddrBytes(data, port)
	}
	return data
}

// copyFlushing streams a body to the caller. When the length is not known (a long poll, an event stream) every chunk is
// flushed as it arrives.
func copyFlushing(w http.ResponseWriter, src io.Reader, flush bool) {
	fl, _ := w.(http.Flusher)
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return
			}
			if flush && fl != nil {
				fl.Flush()
			}
		}
		if err != nil {
			return
		}
	}
}

// sanitizeErr keeps a transport error short and free of anything but the failure kind.
func sanitizeErr(err error) string {
	// a transport error from net/http wraps the request URL (with its query): only the failure itself is kept
	var ue *url.Error
	if errors.As(err, &ue) && ue.Err != nil {
		err = ue.Err
	}
	msg := err.Error()
	if i := strings.Index(msg, "\n"); i >= 0 {
		msg = msg[:i]
	}
	if len(msg) > 200 {
		msg = msg[:200]
	}
	return msg
}

// sinkCFNOps: the CloudFormation calls after which a subscription the front never saw Subscribe may exist.
var sinkCFNOps = map[string]bool{"CreateStack": true, "UpdateStack": true, "ExecuteChangeSet": true, "CreateStackInstances": true}
