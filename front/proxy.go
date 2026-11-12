package main

import (
	"bytes"
	"errors"
	"io"
	"log"
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
}

const (
	rewriteLimit = 2 << 20
	queryLimit   = 8 << 20
)

func newServer(cfg *Config, engine *Engine) *Server {
	return &Server{
		cfg:          cfg,
		engine:       engine,
		ledger:       newLedger(cfg.LedgerMax),
		guard:        newGuard(cfg.Token, cfg.DevOpen),
		rw:           newRewriter(cfg.BaseURL),
		rewriteSlots: newSlots(32),
		querySlots:   newSlots(6),
	}
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
	return "AWS4-HMAC-SHA256 Credential=ROVARATESTKEY/20260101/" + region + "/" + signingName +
		"/aws4_request, SignedHeaders=host, Signature=0000000000000000000000000000000000000000000000000000000000000000"
}

func (s *Server) api(w http.ResponseWriter, r *http.Request, q url.Values, bucket string) {
	start := time.Now()
	action, version := q.Get("Action"), q.Get("Version")
	body := io.Reader(r.Body)
	var form url.Values
	if wantsFormBody(r.Method, r.Header) {
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
	idPath := r.URL.Path
	if bucket != "" {
		idPath = "/" + bucket + idPath
	}
	id := identify(r.Method, idPath, r.Header, q, action, version)
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
	if s.cfg.Disabled[id.Service.ConfigKey] {
		writeDisabled(w, id.Proto, id.Service.Key)
		done(http.StatusBadRequest, false)
		return
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
		out.ContentLength = r.ContentLength // -1 sends chunked
	}
	if out.Header.Get("User-Agent") == "" {
		out.Header["User-Agent"] = []string{""} // no Go default
	}
	if !id.HasAuth && out.Header.Get("Authorization") == "" {
		out.Header.Set("Authorization", syntheticAuthorization(id.Service.SigningName, id.Region))
	}
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
	ctype, enc := resp.Header.Get("Content-Type"), resp.Header.Get("Content-Encoding")
	canHaveBody := r.Method != http.MethodHead && status != http.StatusNoContent && status != http.StatusNotModified && status >= 200

	// Which responses are read whole: the ones rewritten, and errors (to classify them). Everything else streams.
	rewriteKind := s.rewriteKindFor(id, status, ctype, enc, resp.ContentLength)
	buffer := canHaveBody && (rewriteKind != rwNone || status >= 400)
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
)

func (s *Server) needsBodyRewrite(id identified) bool {
	switch {
	case id.Service == nil:
		return false
	case id.Service.Key == "sqs" && (queueOps[id.Operation] || id.Operation == "ReceiveMessage"):
		return true
	case id.Service.Key == "s3" && id.Operation == "CompleteMultipartUpload":
		return true
	}
	return false
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
	// Only the operations above are ever rewritten: an explicit allow-list, no catch-all (an object's bytes and a DynamoDB item
	// with its checksum are never changed). Header values that name the engine's own address are still rewritten.
	return rwNone
}

func (s *Server) applyRewrite(kind rewriteKind, data []byte, ctype string, port int) []byte {
	switch kind {
	case rwQueueJSON:
		data = s.rw.queueURLsJSON(data)
	case rwQueueXML:
		data = s.rw.queueURLsXML(data)
	case rwSNSEnvelope:
		data = s.rw.snsEnvelopes(data)
	case rwS3Location:
		data = s.rw.s3Location(data)
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
