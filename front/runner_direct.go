package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// The direct-Invoke fast path (decision 115, slice 4 Phase 2 brought forward): an Invoke of a function the runner holds, which reaches the
// front as an HTTP request, is answered by the front itself over the runner pipe. No stub, no engine slot, so none of the engine's limits:
// not its 30 s ceiling (the function runs to its own Timeout), not the 256 KB queue message, not the ~16 stubs in flight. Lambda's own
// limits apply (6 MB request and response for a synchronous call, 256 KB for an asynchronous one).
//
// What is emulated:
//   RequestResponse  the answer waits for the function: 200 with the response, or with X-Amz-Function-Error: Unhandled and the error
//                    document; X-Amz-Log-Result with LogType=Tail; X-Amz-Executed-Version. A function that did not run for a reason of the
//                    local setup (no runner, unsupported native code, no room) is a 200 FunctionError with a Rovara.* errorType: never a
//                    code failure.
//   Event            202 at once, the run follows in the background: up to three attempts two seconds apart on a function error, as the
//                    engine does. Destinations, MaximumRetryAttempts and the dead-letter queue are NOT emulated for these (recorded as a
//                    limitation in the README).
//   DryRun           204, nothing runs.
// Calls the engine makes (an event source mapping, Step Functions, SNS, EventBridge, S3, API Gateway, a function URL) take the stub path.

const asyncPayloadMax = 256 << 10

func splitInvokeName(seg string) (name, qualifier string) {
	s, err := url.PathUnescape(seg)
	if err != nil {
		s = seg
	}
	if i := strings.Index(s, ":function:"); i >= 0 {
		s = s[i+len(":function:"):]
	} else if parts := strings.Split(s, ":"); len(parts) == 3 && len(parts[0]) == 12 {
		s = parts[2]
	}
	name, qualifier, _ = strings.Cut(s, ":")
	return
}

type lambdaFail struct {
	status  int
	errType string
	message string
}

func writeLambdaFail(w http.ResponseWriter, f lambdaFail) {
	w.Header().Set("x-amzn-RequestId", newUUID())
	w.Header().Set("X-Amzn-Errortype", f.errType)
	writeBody(w, f.status, "application/json", []byte(`{"Type":"User","Message":"`+jsonEscape(f.message)+`"}`))
}

// resolveVersion turns an Invoke's qualifier into a version of a function the runner holds.
func (r *runnerSys) resolveVersion(name, qualifier string) (string, bool) {
	switch {
	case qualifier == "" || qualifier == "$LATEST":
		return "$LATEST", true
	case versionRe.MatchString(qualifier):
		return qualifier, true
	}
	return r.resolveAlias(name, qualifier)
}

// directInvoke answers an Invoke itself when it can. handled false: the request goes to the engine as before.
func (s *Server) runnerDirect(w http.ResponseWriter, r *http.Request, rawPath string) (status int, handled bool) {
	rs := s.runner
	gen := rs.genNum()
	segs := splitPath(rawPath)
	if len(segs) < 3 {
		return 0, false
	}
	name, qual := splitInvokeName(segs[2])
	if q := r.URL.Query().Get("Qualifier"); q != "" {
		qual = q
	}
	if !rs.reg.isTaken(name) {
		return 0, false
	}
	version, ok := rs.resolveVersion(name, qual)
	if !ok {
		return 0, false // an alias the engine does not know: its own error is the right answer
	}
	arn, v, found := rs.reg.versionOf(name, version)
	if !found || v == nil || !v.Taken {
		return 0, false // a version published before the runner took the function over: the engine holds its code
	}
	invType := r.Header.Get("X-Amz-Invocation-Type")
	if invType == "" {
		invType = "RequestResponse"
	}
	limit := int64(maxPayloadBytes)
	if invType == "Event" {
		limit = asyncPayloadMax
	}
	payload, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		return 0, false
	}
	if int64(len(payload)) > limit {
		writeLambdaFail(w, lambdaFail{http.StatusRequestEntityTooLarge, "RequestEntityTooLargeException", fmt.Sprintf("Request must be smaller than %d bytes for the %s operation", limit, invOpName(invType))})
		return http.StatusRequestEntityTooLarge, true
	}
	if len(payload) > 0 && !json.Valid(payload) {
		writeLambdaFail(w, lambdaFail{http.StatusBadRequest, "InvalidRequestContentException", "Could not parse request body into json: Could not parse payload into json"})
		return http.StatusBadRequest, true
	}
	if len(payload) == 0 {
		payload = []byte("{}")
	}
	switch invType {
	case "DryRun":
		w.Header().Set("x-amzn-RequestId", newUUID())
		w.WriteHeader(http.StatusNoContent)
		return http.StatusNoContent, true
	case "Event":
		return rs.directAsync(w, gen, name, arn, v, payload), true
	case "RequestResponse":
	default:
		writeLambdaFail(w, lambdaFail{http.StatusBadRequest, "InvalidParameterValueException", "Invalid InvocationType"})
		return http.StatusBadRequest, true
	}
	select {
	case rs.direct <- struct{}{}:
		defer rs.direct.release()
	default:
		w.Header().Set("Retry-After", "1")
		writeLambdaFail(w, lambdaFail{http.StatusTooManyRequests, "TooManyRequestsException", "Rate Exceeded."})
		return http.StatusTooManyRequests, true
	}
	reqID := newUUID()
	rs.reg.bump(name, func(s *fnStats) { s.Direct++ })
	res, ferr := rs.directRun(r.Context(), gen, name, arn, v, reqID, payload, r.Header, "")
	if r.Context().Err() != nil {
		return 499, true // the caller went away; the function keeps its run, the answer is dropped
	}
	h := w.Header()
	h.Set("x-amzn-RequestId", reqID)
	h.Set("X-Amz-Executed-Version", v.Version)
	h.Set("X-Amzn-Trace-Id", "Root=1-"+reqID)
	logTail := ""
	if res != nil {
		logTail = res.LogTail
	}
	if r.Header.Get("X-Amz-Log-Type") == "Tail" {
		h.Set("X-Amz-Log-Result", base64.StdEncoding.EncodeToString([]byte(tailString(logTail, 4096))))
	}
	if ferr != nil {
		h.Set("X-Amz-Function-Error", "Unhandled")
		writeBody(w, http.StatusOK, "application/json", errorDoc(ferr.errType, ferr.message))
		return http.StatusOK, true
	}
	return rs.writeResult(w, name, v, res, reqID)
}

func invOpName(t string) string {
	if t == "Event" {
		return "InvokeAsync"
	}
	return "Invoke"
}

func errorDoc(t, m string) []byte {
	b, _ := json.Marshal(map[string]string{"errorMessage": m, "errorType": t})
	return b
}

// directRun registers (if needed) and invokes. A non-nil lambdaFail is an error the CALLER gets as a FunctionError (the local setup could
// not run the function); a nil one with a result is the worker's answer.
func (r *runnerSys) directRun(ctx context.Context, gen uint64, name, arn string, v *fnVer, reqID string, payload []byte, hdr http.Header, source string) (*runnerResult, *lambdaFail) {
	if t := v.unsupportedText(); t != "" {
		r.reg.bump(name, func(s *fnStats) { s.Unsupported++ })
		return nil, &lambdaFail{errType: "Rovara.Unsupported", message: t}
	}
	parent := ctx
	fn, err := r.reg.regFor(r.s.cfg.Region, arn, name, v)
	if err != nil {
		return nil, r.directFail(name, err)
	}
	invoked := arn
	if v.Version != "$LATEST" {
		invoked = arn + ":" + v.Version
	}
	inv := invokeFrame{Name: name, Version: v.Version, RequestID: reqID, Payload: base64.StdEncoding.EncodeToString(payload), TimeoutMs: int64(v.Timeout) * 1000,
		FunctionArn: invoked, Source: "direct", LogBytes: 4096}
	if hdr != nil {
		inv.ClientContext = hdr.Get("X-Amz-Client-Context")
		inv.TraceID = hdr.Get("X-Amzn-Trace-Id")
	}
	rctx, release, admitted := r.runCtx(ctx, gen)
	if !admitted {
		return nil, &lambdaFail{errType: "Rovara.RunnerUnavailable", message: "the function runner is being reset"}
	}
	defer release()
	ctx, cancel := context.WithTimeout(rctx, time.Duration(v.Timeout)*time.Second+30*time.Second)
	defer cancel()
	res, err := r.hub.run(ctx, fn, inv)
	if err != nil {
		if ctx.Err() != nil && !errors.Is(err, context.DeadlineExceeded) {
			if parent.Err() == nil {
				return nil, &lambdaFail{errType: "Rovara.RunnerUnavailable", message: "the function runner was reset while the function ran"}
			}
			return nil, &lambdaFail{errType: "Rovara.RunnerTimeout", message: "the caller went away"}
		}
		return nil, r.directFail(name, err)
	}
	return res, nil
}

func (r *runnerSys) directFail(name string, err error) *lambdaFail {
	rep := r.failReply(name, err)
	return &lambdaFail{errType: rep.ErrorType, message: rep.ErrorMessage}
}

// writeResult answers a synchronous Invoke from the worker's result.
func (r *runnerSys) writeResult(w http.ResponseWriter, name string, v *fnVer, res *runnerResult, reqID string) (int, bool) {
	if res.Cold {
		r.reg.bump(name, func(s *fnStats) { s.Cold++ })
	}
	payload, _ := base64.StdEncoding.DecodeString(res.Payload)
	fnErr := func(t, m string, doc []byte) (int, bool) {
		w.Header().Set("X-Amz-Function-Error", "Unhandled")
		if len(doc) == 0 {
			doc = errorDoc(t, m)
		}
		writeBody(w, http.StatusOK, "application/json", doc)
		return http.StatusOK, true
	}
	switch res.Status {
	case "ok":
		r.reg.bump(name, func(s *fnStats) { s.OK++ })
		if len(payload) == 0 {
			payload = []byte("null")
		}
		writeBody(w, http.StatusOK, "application/json", payload)
		return http.StatusOK, true
	case "function_error":
		r.reg.bump(name, func(s *fnStats) { s.FunctionErrors++ })
		return fnErr(orDefault(res.ErrorType, "Error"), res.ErrorMessage, payload)
	case "timeout":
		r.reg.bump(name, func(s *fnStats) { s.FunctionErrors++ })
		return fnErr(orDefault(res.ErrorType, "Sandbox.Timedout"), orDefault(res.ErrorMessage, fmt.Sprintf("RequestId: %s Error: Task timed out after %d.00 seconds", reqID, v.Timeout)), payload)
	case "crash", "init_error":
		r.reg.bump(name, func(s *fnStats) { s.FunctionErrors++ })
		return fnErr(orDefault(res.ErrorType, "Runtime.ExitError"), res.ErrorMessage, payload)
	case "rejected":
		r.reg.bump(name, func(s *fnStats) { s.Fails++ })
		if res.ErrorType == "RequestEntityTooLargeException" {
			writeLambdaFail(w, lambdaFail{http.StatusRequestEntityTooLarge, res.ErrorType, res.ErrorMessage})
			return http.StatusRequestEntityTooLarge, true
		}
		writeLambdaFail(w, lambdaFail{http.StatusBadRequest, orDefault(res.ErrorType, "InvalidRequestContentException"), res.ErrorMessage})
		return http.StatusBadRequest, true
	case "throttled":
		r.reg.bump(name, func(s *fnStats) { s.Fails++ })
		w.Header().Set("Retry-After", "1")
		writeLambdaFail(w, lambdaFail{http.StatusTooManyRequests, "TooManyRequestsException", "Rate Exceeded."})
		return http.StatusTooManyRequests, true
	}
	r.reg.bump(name, func(s *fnStats) { s.Fails++ })
	return fnErr("Rovara.RunnerUnavailable", "the function runner could not run the function ("+orDefault(res.Reason, res.Status)+")", nil)
}

// directAsync accepts an asynchronous Invoke: 202 now, up to three attempts two seconds apart in the background (the engine's behaviour).
func (r *runnerSys) directAsync(w http.ResponseWriter, gen uint64, name, arn string, v *fnVer, payload []byte) int {
	reqID := newUUID()
	select {
	case r.direct <- struct{}{}:
	default:
		w.Header().Set("Retry-After", "1")
		writeLambdaFail(w, lambdaFail{http.StatusTooManyRequests, "TooManyRequestsException", "Rate Exceeded."})
		return http.StatusTooManyRequests
	}
	r.reg.bump(name, func(s *fnStats) { s.Async++ })
	w.Header().Set("x-amzn-RequestId", reqID)
	w.Header().Set("X-Amz-Executed-Version", v.Version)
	w.WriteHeader(http.StatusAccepted)
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		defer r.direct.release()
		for attempt := 0; attempt < 3 && r.ctx.Err() == nil; attempt++ {
			if attempt > 0 {
				r.sleep(r.retryDelay)
			}
			res, ferr := r.directRun(r.ctx, gen, name, arn, v, reqID, payload, nil, "async")
			if ferr != nil {
				return // the local setup could not run it: retrying changes nothing
			}
			switch res.Status {
			case "ok":
				r.reg.bump(name, func(s *fnStats) { s.OK++ })
				return
			case "function_error", "timeout", "crash", "init_error":
				r.reg.bump(name, func(s *fnStats) { s.FunctionErrors++ })
			default:
				r.reg.bump(name, func(s *fnStats) { s.Fails++ })
				return
			}
		}
	}()
	return http.StatusAccepted
}
