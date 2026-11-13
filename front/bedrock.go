package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
)

// The Bedrock runtime shim (planned mode, the route key `bedrock-runtime`). The engine's Bedrock runtime answers every call in the right
// shape but with one fixed sentence ("No language model runs in this emulator"), ignores a request's own guardrail, answers ApplyGuardrail
// with 501 and embedding models with 424, and no rule or hook sets what it says. So the front answers six operations itself, from the
// run's fixtures (bedrock_fixtures.go): Converse, ConverseStream, InvokeModel, InvokeModelWithResponseStream, CountTokens and
// ApplyGuardrail. Everything else of the route key (async invoke, the bidirectional stream, InvokeGuardrailChecks) and the whole control
// plane (`bedrock`: ListFoundationModels, guardrail CRUD) stay with the engine. The runtime and the control plane both sign as `bedrock`;
// the front tells them apart by the route (planned.go), as it does for SageMaker.
//
// No model runs here, none is called, and nothing leaves the process. Every answer is a fake and the ledger says so (marker "faked").
//
// Control paths (with the control token), under /_rovara/bedrock:
//
//	GET/PUT/DELETE /fixtures[/<name>]   fixture sets (PUT /fixtures with {"fixtures":[...]} replaces them all)
//	GET/POST/DELETE /faults             armed faults: the next calls that match fail, then calls go on as normal
//	GET /summary                        the fixture table, the faults and the counters, for the evidence
//
// The sets and the faults are the round's state and go with a reset; the counters go with the ledger (DELETE /_rovara/ledger).

const bdControlPrefix = "/_rovara/bedrock"

type bdUnmatched struct {
	Operation string `json:"operation"`
	Bytes     int    `json:"bytes"`
	SHA256    string `json:"sha256"`
}

// bdStats are the counters of one model id, for the evidence. Counts only: no prompt, no answer, no header value is ever kept.
type bdStats struct {
	Calls, Streamed, ToolUseTurns, GuardrailIntervened int64
	Matched, MadeUp, Unmatched, Errors, Faulted        int64
	CountTokens, ApplyGuardrail, Estimated             int64
	Last                                               []bdUnmatched // the newest unmatched requests, by size and hash
}

type bdState struct {
	mu     sync.Mutex
	sets   map[string]*bdSet
	faults []*bdFault
	stats  map[string]*bdStats
	// bodies bounds the memory the request bodies being answered hold at once, whatever the number of calls waiting
	bodies *byteBudget
}

// bdBodyBudget is that memory, counted in bytes of cost, not of body: a body costs about bdBodyCost times its size while it is answered
// (the body, the document decoded from it, the text read out of it). Two requests of the largest size, or very many ordinary ones.
const (
	bdBodyBudget = 64 << 20
	bdBodyCost   = 4
)

func newBDState() *bdState {
	return &bdState{sets: map[string]*bdSet{}, stats: map[string]*bdStats{}, bodies: newByteBudget(bdBodyBudget)}
}

// reset empties the fixtures and the faults (the round's state goes with the engine's). The counters stay with the ledger.
func (m *bdState) reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sets, m.faults = map[string]*bdSet{}, nil
}

// clearStats is DELETE /_rovara/ledger: the counters go with the entries.
func (m *bdState) clearStats() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stats = map[string]*bdStats{}
}

func (m *bdState) statsFor(id string) *bdStats {
	st := m.stats[id]
	if st == nil {
		if len(m.stats) >= bdMaxStatModels {
			id = "(other)"
			if st = m.stats[id]; st != nil {
				return st
			}
		}
		st = &bdStats{}
		m.stats[id] = st
	}
	return st
}

func (m *bdState) setSet(s *bdSet) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, has := m.sets[s.Name]; !has && len(m.sets) >= bdMaxSets {
		return fmt.Errorf("too many fixture sets (at most %d)", bdMaxSets)
	}
	m.sets[s.Name] = s
	return nil
}

// bdPlanned: whether the plan names the runtime, the only mode in which the front answers Bedrock calls.
func (s *Server) bdPlanned() bool { return s.cfg.Planned != nil && s.cfg.Planned["bedrock-runtime"] }

// ---- the seed's `bedrock` section: { "fixtures": [ { "name", "modelId" | "modelPrefix", "rules", "queue", "default" } ] }

func (r *seedRun) seedBedrock(set map[string]any) error {
	data, err := json.Marshal(set)
	if err != nil {
		return err
	}
	s, err := parseSet(data)
	if err != nil {
		return err
	}
	if s.Name == "" {
		return fmt.Errorf("a fixture set in the seed needs a name")
	}
	return r.s.bd.setSet(s)
}

// ---- the control paths

func (s *Server) bdControl(w http.ResponseWriter, r *http.Request, p string) {
	if !s.bdPlanned() {
		writeBody(w, http.StatusNotFound, jsonCType, jsonError("the plan does not name bedrock-runtime"))
		return
	}
	rest := strings.Trim(strings.TrimPrefix(p, bdControlPrefix), "/")
	parts := strings.Split(rest, "/")
	notFound := func() { writeBody(w, http.StatusNotFound, "text/html; charset=utf-8", []byte(notFoundHTML)) }
	ok := func() { writeBody(w, 200, jsonCType, []byte(`{"status":"OK"}`)) }
	bad := func(status int, msg string) { writeBody(w, status, jsonCType, jsonError(msg)) }
	readDoc := func(limit int64) ([]byte, bool) {
		data, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
		if err != nil || int64(len(data)) > limit {
			bad(http.StatusBadRequest, "the document could not be read or is too large")
			return nil, false
		}
		return data, true
	}
	m := s.bd
	switch parts[0] {
	case "summary":
		if len(parts) != 1 {
			notFound()
			return
		}
		if r.Method != http.MethodGet {
			methodNotAllowed(w, "GET")
			return
		}
		writeBody(w, 200, jsonCType, s.bdSummaryJSON())
	case "fixtures":
		switch {
		case len(parts) == 1:
			switch r.Method {
			case http.MethodGet:
				writeBody(w, 200, jsonCType, s.bdFixturesJSON(""))
			case http.MethodPut:
				data, good := readDoc(bdMaxDocBytes)
				if !good {
					return
				}
				var doc struct {
					Fixtures []json.RawMessage `json:"fixtures"`
				}
				if err := bdStrict(data, &doc); err != nil {
					bad(http.StatusUnprocessableEntity, "the document is not {\"fixtures\":[...]}: "+err.Error())
					return
				}
				if len(doc.Fixtures) > bdMaxSets {
					bad(http.StatusUnprocessableEntity, "too many fixture sets")
					return
				}
				next := map[string]*bdSet{}
				for i, raw := range doc.Fixtures {
					set, err := parseSet(raw)
					if err == nil && set.Name == "" {
						err = fmt.Errorf("a fixture set needs a name")
					}
					if err != nil {
						bad(http.StatusUnprocessableEntity, fmt.Sprintf("fixtures[%d]: %v", i, err))
						return
					}
					if next[set.Name] != nil {
						bad(http.StatusUnprocessableEntity, fmt.Sprintf("fixtures[%d]: the name %q is used twice", i, set.Name))
						return
					}
					next[set.Name] = set
				}
				m.mu.Lock()
				m.sets = next
				m.mu.Unlock()
				ok()
			case http.MethodDelete:
				m.mu.Lock()
				m.sets = map[string]*bdSet{}
				m.mu.Unlock()
				ok()
			default:
				methodNotAllowed(w, "GET, PUT, DELETE")
			}
		case len(parts) == 2 && bdNameRe.MatchString(parts[1]):
			name := parts[1]
			switch r.Method {
			case http.MethodGet:
				out := s.bdFixturesJSON(name)
				if out == nil {
					bad(http.StatusNotFound, "no such fixture set")
					return
				}
				writeBody(w, 200, jsonCType, out)
			case http.MethodPut:
				data, good := readDoc(bdMaxDocBytes)
				if !good {
					return
				}
				set, err := parseSet(data)
				if err == nil && set.Name != "" && set.Name != name {
					err = fmt.Errorf("the document's name %q is not the path's %q", set.Name, name)
				}
				if err == nil {
					set.Name = name
					err = m.setSet(set)
				}
				if err != nil {
					bad(http.StatusUnprocessableEntity, err.Error())
					return
				}
				ok()
			case http.MethodDelete:
				m.mu.Lock()
				delete(m.sets, name)
				m.mu.Unlock()
				ok()
			default:
				methodNotAllowed(w, "GET, PUT, DELETE")
			}
		default:
			notFound()
		}
	case "faults":
		if len(parts) != 1 {
			notFound()
			return
		}
		switch r.Method {
		case http.MethodGet:
			writeBody(w, 200, jsonCType, s.bdFaultsJSON())
		case http.MethodPost:
			data, good := readDoc(1 << 20)
			if !good {
				return
			}
			f, err := parseFault(data)
			if err == nil {
				m.mu.Lock()
				if len(m.faults) >= bdMaxFaults {
					err = fmt.Errorf("too many armed faults (at most %d)", bdMaxFaults)
				} else {
					m.faults = append(m.faults, f)
				}
				m.mu.Unlock()
			}
			if err != nil {
				bad(http.StatusUnprocessableEntity, err.Error())
				return
			}
			ok()
		case http.MethodDelete:
			m.mu.Lock()
			m.faults = nil
			m.mu.Unlock()
			ok()
		default:
			methodNotAllowed(w, "GET, POST, DELETE")
		}
	default:
		notFound()
	}
}

// the words the evidence uses for each source of answers
func bdLabel(src string) string {
	if src == "recorded" {
		return "recorded fake"
	}
	return "hand-written fake"
}

func (s *Server) bdFixturesJSON(name string) []byte {
	m := s.bd
	m.mu.Lock()
	defer m.mu.Unlock()
	type setOut struct {
		Name        string `json:"name"`
		ModelID     string `json:"modelId,omitempty"`
		ModelPrefix string `json:"modelPrefix,omitempty"`
		Source      string `json:"source"`
		Label       string `json:"label"`
		RecordedOn  string `json:"recordedOn,omitempty"`
		Rules       int    `json:"rules"`
		Queued      int    `json:"queued"`
		HasDefault  bool   `json:"hasDefault"`
	}
	var names []string
	for n := range m.sets {
		names = append(names, n)
	}
	sort.Strings(names)
	out := []setOut{}
	for _, n := range names {
		if name != "" && n != name {
			continue
		}
		st := m.sets[n]
		out = append(out, setOut{Name: n, ModelID: st.ModelID, ModelPrefix: st.ModelPrefix, Source: st.Source, Label: bdLabel(st.Source),
			RecordedOn: st.RecordedOn, Rules: len(st.Rules), Queued: len(st.Queue), HasDefault: st.Default != nil})
	}
	if name != "" {
		if len(out) == 0 {
			return nil
		}
		b, _ := json.Marshal(out[0])
		return b
	}
	b, _ := json.Marshal(map[string]any{"fixtures": out})
	return b
}

func (s *Server) bdFaultsJSON() []byte {
	m := s.bd
	m.mu.Lock()
	defer m.mu.Unlock()
	type faultOut struct {
		ModelID     string `json:"modelId,omitempty"`
		ModelPrefix string `json:"modelPrefix,omitempty"`
		Operation   string `json:"operation,omitempty"`
		Kind        string `json:"kind"`
		Code        string `json:"code,omitempty"`
		Remaining   int    `json:"remaining"`
		Skip        int    `json:"skipRemaining"`
	}
	out := []faultOut{}
	for _, f := range m.faults {
		o := faultOut{ModelID: f.ModelID, ModelPrefix: f.ModelPrefix, Operation: f.Operation, Kind: "delay", Remaining: f.Times - f.used}
		if o.Skip = f.Skip - f.seen; o.Skip < 0 {
			o.Skip = 0
		}
		switch {
		case f.Error != nil:
			o.Kind, o.Code = "error", f.Error.Code
		case f.StreamError != nil:
			o.Kind, o.Code = "streamError", f.StreamError.Code
		}
		out = append(out, o)
	}
	b, _ := json.Marshal(map[string]any{"faults": out})
	return b
}

func (s *Server) bdSummaryJSON() []byte {
	m := s.bd
	m.mu.Lock()
	var ids []string
	for id := range m.stats {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	type modelOut struct {
		ModelID             string        `json:"modelId,omitempty"`
		Calls               int64         `json:"calls"`
		Streamed            int64         `json:"streamed"`
		ToolUseTurns        int64         `json:"toolUseTurns"`
		GuardrailIntervened int64         `json:"guardrailInterventions"`
		Matched             int64         `json:"matched"`
		MadeUp              int64         `json:"madeUp"`
		Unmatched           int64         `json:"unmatched"`
		Errors              int64         `json:"errors"`
		Faulted             int64         `json:"faulted"`
		CountTokens         int64         `json:"countTokens"`
		ApplyGuardrail      int64         `json:"applyGuardrail"`
		Estimated           int64         `json:"estimated"`
		LastUnmatched       []bdUnmatched `json:"lastUnmatched,omitempty"`
	}
	models := []modelOut{}
	var tot modelOut
	for _, id := range ids {
		st := m.stats[id]
		o := modelOut{ModelID: id, Calls: st.Calls, Streamed: st.Streamed, ToolUseTurns: st.ToolUseTurns, GuardrailIntervened: st.GuardrailIntervened,
			Matched: st.Matched, MadeUp: st.MadeUp, Unmatched: st.Unmatched, Errors: st.Errors, Faulted: st.Faulted, CountTokens: st.CountTokens,
			ApplyGuardrail: st.ApplyGuardrail, Estimated: st.Estimated, LastUnmatched: st.Last}
		models = append(models, o)
		tot.Calls += o.Calls
		tot.Streamed += o.Streamed
		tot.ToolUseTurns += o.ToolUseTurns
		tot.GuardrailIntervened += o.GuardrailIntervened
		tot.Matched += o.Matched
		tot.MadeUp += o.MadeUp
		tot.Unmatched += o.Unmatched
		tot.Errors += o.Errors
		tot.Faulted += o.Faulted
		tot.CountTokens += o.CountTokens
		tot.ApplyGuardrail += o.ApplyGuardrail
		tot.Estimated += o.Estimated
	}
	m.mu.Unlock()
	var fx struct {
		Fixtures json.RawMessage `json:"fixtures"`
	}
	json.Unmarshal(s.bdFixturesJSON(""), &fx)
	var fl struct {
		Faults json.RawMessage `json:"faults"`
	}
	json.Unmarshal(s.bdFaultsJSON(), &fl)
	tot.ModelID = ""
	b, _ := json.Marshal(map[string]any{
		"faked":     true,
		"notTested": "real model behaviour; token counts are made up",
		"totals":    tot,
		"models":    models,
		"fixtures":  fx.Fixtures,
		"faults":    fl.Faults,
	})
	return b
}
