package main

import (
	"io"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Control surface: the paths the Cloud worker calls (health, reset, seed, ledger/summary) and the cheap extras.
//
//   GET    /_rovara/health          open; 200 with the fork's shape while the engine answers, else 503
//   POST   /_rovara/reset           restart the engine (state is in memory only); the ledger is kept, as in the fork
//   POST   /_rovara/reset/{service} 404 for a name the fork does not know; 501 for a known one (no per-service reset)
//   POST   /_rovara/seed            the SeedService document, applied through the engine's own API
//   GET    /_rovara/ledger          entries (?service=&after=&limit=)
//   GET    /_rovara/ledger/summary  calls, unsupported and errors per service and operation
//   DELETE /_rovara/ledger          empty the ledger
//   GET    /_rovara/tick, POST /_rovara/tick/{job}   501: the engine has no jobs to run on demand

const (
	jsonCType     = "application/json;charset=UTF-8"
	notFoundHTML  = "<html><body><h1>Resource not found</h1></body></html>"
	resetServices = "s3,dynamodb,sqs,sns,secretsmanager,ssm,kms,events,sts,iam,lambda,kinesis,states,logs,apigateway,sagemaker"
)

func methodNotAllowed(w http.ResponseWriter, allow string) {
	w.Header().Set("Allow", allow)
	w.WriteHeader(http.StatusMethodNotAllowed)
}

func (s *Server) control(w http.ResponseWriter, r *http.Request, p string) {
	m := r.Method
	switch {
	case p == "/_rovara/health":
		if m != http.MethodGet {
			methodNotAllowed(w, "GET")
			return
		}
		s.health(w)
	case p == "/_rovara/reset":
		if m != http.MethodPost {
			methodNotAllowed(w, "POST")
			return
		}
		s.resetAll(w)
	case strings.HasPrefix(p, "/_rovara/reset/") && !strings.Contains(p[len("/_rovara/reset/"):], "/") && len(p) > len("/_rovara/reset/"):
		if m != http.MethodPost {
			methodNotAllowed(w, "POST")
			return
		}
		s.resetOne(w, p[len("/_rovara/reset/"):])
	case p == "/_rovara/seed":
		if m != http.MethodPost {
			methodNotAllowed(w, "POST")
			return
		}
		s.seed(w, r)
	case p == "/_rovara/ledger":
		switch m {
		case http.MethodGet:
			q := r.URL.Query()
			after, _ := strconv.ParseInt(q.Get("after"), 10, 64)
			limit := 1000
			if v, err := strconv.Atoi(q.Get("limit")); err == nil {
				limit = v
			}
			if limit < 1 {
				limit = 1
			}
			if limit > 10000 {
				limit = 10000
			}
			writeBody(w, 200, jsonCType, s.ledger.entriesJSON(q.Get("service"), after, limit))
		case http.MethodDelete:
			s.ledger.clear()
			s.sm.clearStats()
			s.bd.clearStats()
			if s.sink != nil {
				s.sink.clear()
			}
			writeBody(w, 200, jsonCType, []byte(`{"status":"OK"}`))
		default:
			methodNotAllowed(w, "GET, DELETE")
		}
	case p == "/_rovara/ledger/summary":
		if m != http.MethodGet {
			methodNotAllowed(w, "GET")
			return
		}
		writeBody(w, 200, jsonCType, s.ledger.summaryJSON())
	case p == smControlPrefix || strings.HasPrefix(p, smControlPrefix+"/"):
		s.smControl(w, r, p)
	case p == bdControlPrefix || strings.HasPrefix(p, bdControlPrefix+"/"):
		s.bdControl(w, r, p)
	case p == "/_rovara/sns" || strings.HasPrefix(p, "/_rovara/sns/"):
		s.snsControl(w, r, p)
	case p == "/_rovara/lambda/heavy":
		if m != http.MethodGet {
			methodNotAllowed(w, "GET")
			return
		}
		writeBody(w, 200, jsonCType, s.heavyJSON())
	case strings.HasPrefix(p, functionCodePrefix) && len(p) > len(functionCodePrefix) && !strings.Contains(p[len(functionCodePrefix):], "/"):
		// Code.Location of a function the runner holds: a signed, expiring link (the guard lets it through without the control token)
		if s.runner == nil || (m != http.MethodGet && m != http.MethodHead) {
			writeBody(w, http.StatusNotFound, "text/html; charset=utf-8", []byte(notFoundHTML))
			return
		}
		s.runner.serveCode(w, r, p[len(functionCodePrefix):])
	case p == "/_rovara/tick" || strings.HasPrefix(p, "/_rovara/tick/"):
		writeBody(w, http.StatusNotImplemented, jsonCType, jsonError("on-demand jobs (ticks) are not available with this engine"))
	default:
		writeBody(w, http.StatusNotFound, "text/html; charset=utf-8", []byte(notFoundHTML))
	}
}

// health: the fork's body, {"services":{"<key>":"running"|"available",...},"version":"0.1.0"}, but only while the engine
// really answers; a dead, resetting or failed engine is red (503) so a worker never seeds or runs against stale or missing state.
func (s *Server) health(w http.ResponseWriter) {
	if err := s.engine.healthy(); err != nil {
		st, last := s.engine.status()
		msg := "the engine is " + st.String()
		if last != "" && st == engineFailed {
			msg = "the engine failed"
		}
		writeBody(w, http.StatusServiceUnavailable, jsonCType, []byte(`{"status":"DOWN","error":"`+jsonEscape(msg)+`"}`))
		return
	}
	var b strings.Builder
	b.WriteString(`{"services":{`)
	if s.cfg.Planned != nil {
		// planned mode: the services the plan names, all running
		for i, k := range s.cfg.PlannedKeys {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(`"` + k + `":"running"`)
		}
	} else {
		for i, sv := range healthServices() {
			if i > 0 {
				b.WriteByte(',')
			}
			state := "running"
			if s.cfg.Disabled[sv.ConfigKey] {
				state = "available"
			}
			b.WriteString(`"` + sv.Key + `":"` + state + `"`)
		}
	}
	b.WriteString(`},"version":"0.1.0"}`)
	writeBody(w, 200, jsonCType, []byte(b.String()))
}

func (s *Server) resetAll(w http.ResponseWriter) {
	s.ctl.Lock()
	defer s.ctl.Unlock()
	if s.runner != nil {
		// nothing may register or invoke on the worker from here until the new generation starts
		s.runner.quiesce()
		defer s.runner.resume()
	}
	if err := s.engine.Restart(); err != nil {
		log.Printf("reset failed: %v", sanitizeErr(err))
		writeBody(w, http.StatusInternalServerError, jsonCType, jsonError("the engine could not be restarted"))
		return
	}
	if s.sink != nil {
		s.sink.reset() // the subscriptions, their taps and their goroutines are gone with the engine's state
	}
	if s.dns != nil {
		// the names the front registered for the engine's resources are gone with them (the resolver is the worker's and outlives the engine)
		ctx, cancel := contextWithTimeout(5 * time.Second)
		if err := s.dns.UnregisterAll(ctx); err != nil {
			log.Printf("reset: the DNS helper kept a name: %v", sanitizeErr(err))
		}
		cancel()
	}
	s.heavy.reset() // the functions are gone with the engine's state
	s.sm.reset()    // so are the SageMaker endpoints and what answers them
	s.bd.reset()    // and the Bedrock fixtures and armed faults
	writeBody(w, 200, jsonCType, []byte(`{"reset":"all","status":"OK"}`))
}

func (s *Server) resetOne(w http.ResponseWriter, name string) {
	known := strings.Split(resetServices, ",")
	found := false
	for _, k := range known {
		if k == name {
			found = true
		}
	}
	if !found {
		quoted := make([]string, len(known))
		for i, k := range known {
			quoted[i] = `"` + k + `"`
		}
		writeBody(w, http.StatusNotFound, jsonCType, []byte(`{"services":[`+strings.Join(quoted, ",")+`],"error":"unknown service: `+jsonEscape(name)+`"}`))
		return
	}
	writeBody(w, http.StatusNotImplemented, jsonCType,
		jsonError("resetting one service is not supported by this engine; POST /_rovara/reset resets everything"))
}

func (s *Server) seed(w http.ResponseWriter, r *http.Request) {
	data, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if err != nil {
		writeBody(w, http.StatusBadRequest, jsonCType, jsonError("the seed document could not be read"))
		return
	}
	s.ctl.Lock()
	defer s.ctl.Unlock()
	status, out := s.applySeed(data)
	writeBody(w, status, jsonCType, out)
}

var _ = sort.Strings

// snsControl: the sink's read-only control surface (the control token is required, as on every /_rovara path).
//
//	GET /_rovara/sns/subscriptions                      the subscriptions the front owns, with their state and counters
//	GET /_rovara/sns/deliveries?subscription=&after=&limit=   the attempts (a ring of 50 per subscription); one subscription at a time
//	GET /_rovara/sns/summary                            counts by protocol and target host, and the signature and retry words
func (s *Server) snsControl(w http.ResponseWriter, r *http.Request, p string) {
	if s.sink == nil {
		writeBody(w, http.StatusNotFound, "text/html; charset=utf-8", []byte(notFoundHTML))
		return
	}
	if r.Method != http.MethodGet {
		methodNotAllowed(w, "GET")
		return
	}
	switch p {
	case "/_rovara/sns/subscriptions":
		writeBody(w, 200, jsonCType, s.sink.subscriptionsJSON())
	case "/_rovara/sns/deliveries":
		q := r.URL.Query()
		after, _ := strconv.ParseInt(q.Get("after"), 10, 64)
		limit := 200
		if v, err := strconv.Atoi(q.Get("limit")); err == nil && v >= 1 && v <= 1000 {
			limit = v
		}
		sub := q.Get("subscription")
		if sub == "" {
			writeBody(w, http.StatusBadRequest, jsonCType, jsonError("name one subscription: ?subscription=<arn>"))
			return
		}
		writeBody(w, 200, jsonCType, s.sink.deliveriesJSON(sub, after, limit))
	case "/_rovara/sns/summary":
		writeBody(w, 200, jsonCType, s.sink.summaryJSON())
	default:
		writeBody(w, http.StatusNotFound, "text/html; charset=utf-8", []byte(notFoundHTML))
	}
}
