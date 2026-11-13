package main

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"
)

// The Lambda Runtime API, version 2018-06-01, as the official runtime clients use it.

const apiPrefix = "/2018-06-01/runtime/"

func (a *agent) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(apiPrefix+"invocation/next", a.handleNext)
	mux.HandleFunc(apiPrefix+"invocation/", a.handleInvocationPost)
	mux.HandleFunc(apiPrefix+"init/error", a.handleInitError)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		apiError(w, http.StatusNotFound, "NotFound", "no such Runtime API path")
	})
	return mux
}

func apiError(w http.ResponseWriter, code int, typ, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	b, _ := json.Marshal(map[string]string{"errorMessage": msg, "errorType": typ})
	w.Write(b)
}

func apiAccepted(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	w.Write([]byte(`{"status":"OK"}` + "\n"))
}

// GET /invocation/next blocks until the worker sends an invocation.
func (a *agent) handleNext(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		apiError(w, http.StatusMethodNotAllowed, "MethodNotAllowed", "use GET")
		return
	}
	a.mu.Lock()
	rt := a.rt
	a.mu.Unlock()
	if rt != nil {
		rt.markReady()
	}
	select {
	case inv := <-a.nextCh:
		a.mu.Lock()
		inv.delivered = true
		a.mu.Unlock()
		h := w.Header()
		h.Set("Content-Type", "application/json")
		h.Set("Lambda-Runtime-Aws-Request-Id", inv.id)
		h.Set("Lambda-Runtime-Deadline-Ms", strconv.FormatInt(inv.deadline.UnixMilli(), 10))
		h.Set("Lambda-Runtime-Invoked-Function-Arn", inv.msg.FunctionArn)
		h.Set("Lambda-Runtime-Trace-Id", inv.traceID)
		if inv.msg.ClientContext != "" {
			h.Set("Lambda-Runtime-Client-Context", inv.msg.ClientContext)
		}
		if inv.msg.CognitoIdentity != "" {
			h.Set("Lambda-Runtime-Cognito-Identity", inv.msg.CognitoIdentity)
		}
		h.Set("Content-Length", strconv.Itoa(len(inv.payload)))
		w.WriteHeader(http.StatusOK)
		w.Write(inv.payload)
	case <-r.Context().Done():
	}
}

// POST /invocation/{id}/response and /invocation/{id}/error.
func (a *agent) handleInvocationPost(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, apiPrefix+"invocation/")
	parts := strings.Split(rest, "/")
	if len(parts) != 2 || parts[0] == "" || (parts[1] != "response" && parts[1] != "error") {
		apiError(w, http.StatusNotFound, "NotFound", "no such Runtime API path")
		return
	}
	if r.Method != http.MethodPost {
		apiError(w, http.StatusMethodNotAllowed, "MethodNotAllowed", "use POST")
		return
	}
	id, kind := parts[0], parts[1]
	body, tooLarge, err := readLimited(r)
	if err != nil {
		apiError(w, http.StatusBadRequest, "InvalidRequest", "could not read the request body")
		return
	}

	a.mu.Lock()
	inv := a.cur
	ok := inv != nil && inv.id == id && inv.delivered && !inv.finished
	if ok {
		inv.finished = true
	}
	a.mu.Unlock()
	if !ok {
		apiError(w, http.StatusBadRequest, "InvalidRequestID", "Invalid request ID")
		return
	}

	switch {
	case tooLarge:
		// The invoker gets Function.ResponseSizeTooLarge. The runtime is told 202 rather than 413:
		// the official Python client treats a 413 as fatal and exits, which would cost the warm
		// environment for nothing.
		inv.out = outcome{kind: outTooLarge}
		apiAccepted(w)
	case kind == "response":
		inv.out = outcome{kind: outResponse, body: body}
		apiAccepted(w)
	default:
		et, em := parseErrorBody(body)
		if h := r.Header.Get("Lambda-Runtime-Function-Error-Type"); h != "" && et == "" {
			et = capString(h, maxErrorTypeBytes)
		}
		inv.out = outcome{kind: outError, body: body, errType: et, errMsg: em}
		apiAccepted(w)
	}
	close(inv.done)
}

// POST /init/error: the runtime could not initialise.
func (a *agent) handleInitError(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		apiError(w, http.StatusMethodNotAllowed, "MethodNotAllowed", "use POST")
		return
	}
	body, _, err := readLimited(r)
	if err != nil {
		apiError(w, http.StatusBadRequest, "InvalidRequest", "could not read the request body")
		return
	}
	a.mu.Lock()
	rt := a.rt
	a.mu.Unlock()
	if rt == nil || rt.isReady() {
		apiError(w, http.StatusForbidden, "InvalidStateTransition", "init error after the runtime started polling for invocations")
		return
	}
	et, em := parseErrorBody(body)
	if h := r.Header.Get("Lambda-Runtime-Function-Error-Type"); h != "" && et == "" {
		et = h
	}
	if et == "" {
		et = "Runtime.InitError"
	}
	rt.reportInitError(&failure{reason: "runtime_reported", errType: et, errMsg: em, payload: body})
	apiAccepted(w)
}

// readLimited reads a request body of at most maxPayloadBytes. A larger body is read to the end
// (up to a hard cap) and discarded, so the client finishes sending and can read the 413 reply
// instead of seeing a reset connection.
func readLimited(r *http.Request) (body []byte, tooLarge bool, err error) {
	defer r.Body.Close()
	b, e := io.ReadAll(io.LimitReader(r.Body, maxPayloadBytes+1))
	if e != nil {
		return nil, false, e
	}
	if len(b) > maxPayloadBytes {
		io.Copy(io.Discard, io.LimitReader(r.Body, 64<<20))
		return nil, true, nil
	}
	return b, false, nil
}

func parseErrorBody(body []byte) (errType, errMsg string) {
	var e struct {
		ErrorMessage string `json:"errorMessage"`
		ErrorType    string `json:"errorType"`
	}
	if json.Unmarshal(body, &e) == nil {
		return capString(e.ErrorType, maxErrorTypeBytes), capString(e.ErrorMessage, maxErrorMessageBytes)
	}
	return "", ""
}

// capString cuts s to at most n bytes without splitting a UTF-8 sequence.
func capString(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
