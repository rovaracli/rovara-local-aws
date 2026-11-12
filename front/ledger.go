package main

import (
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The request ledger, a port of the fork's RequestLedger. One entry per API request, written when the request arrives and
// completed when it is answered. Entries are kept in a bounded ring (oldest dropped); the per-service and per-operation
// counters are never dropped, so usage evidence stays exact however long a run is. Control paths are not recorded.
// A reset does not clear the ledger (the fork's reset never did either): DELETE /_rovara/ledger does.

type ledgerEntry struct {
	Seq         int64
	At          int64 // epoch millis
	Service     string
	Operation   string
	Method      string
	Status      int
	Unsupported bool
	Millis      int64
}

type counts struct{ Calls, Unsupported, Errors int64 }

// maxLedgerKeys bounds the distinct (service, operation) counters. Cloud refuses a summary with more than 200
// operations of one service as a flood; past this bound new names fold into one "other" row per service.
const maxLedgerKeys = 20000

type Ledger struct {
	mu       sync.Mutex
	capacity int
	ring     []*ledgerEntry
	seq      int64
	counts   map[string]map[string]*counts // service -> operation -> counters
	keys     int
}

func newLedger(capacity int) *Ledger {
	if capacity < 1 {
		capacity = 5000
	}
	return &Ledger{capacity: capacity, counts: map[string]map[string]*counts{}}
}

func (l *Ledger) row(service, operation string) *counts {
	ops := l.counts[service]
	if ops == nil {
		ops = map[string]*counts{}
		l.counts[service] = ops
	}
	c := ops[operation]
	if c == nil {
		if l.keys >= maxLedgerKeys {
			operation = "other"
			if c = ops[operation]; c != nil {
				return c
			}
		}
		c = &counts{}
		ops[operation] = c
		l.keys++
	}
	return c
}

// begin writes the entry before the request is answered.
func (l *Ledger) begin(service, operation, method string) *ledgerEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.seq++
	e := &ledgerEntry{Seq: l.seq, At: time.Now().UnixMilli(), Service: service, Operation: operation, Method: method}
	l.ring = append(l.ring, e)
	if len(l.ring) > l.capacity {
		l.ring[0] = nil
		l.ring = l.ring[1:]
	}
	l.row(service, operation).Calls++
	return e
}

// complete records the outcome: unsupported and any status of 400 or more are counted.
func (l *Ledger) complete(e *ledgerEntry, status int, unsupported bool, millis int64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e.Status, e.Unsupported, e.Millis = status, unsupported, millis
	if unsupported || status >= 400 {
		c := l.row(e.Service, e.Operation)
		if unsupported {
			c.Unsupported++
		}
		if status >= 400 {
			c.Errors++
		}
	}
}

func (l *Ledger) clear() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.ring = nil
	l.counts = map[string]map[string]*counts{}
	l.keys = 0
}

// entries after afterSeq, optionally for one service, the newest limit of them.
func (l *Ledger) entries(service string, afterSeq int64, limit int) []ledgerEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []ledgerEntry
	for _, e := range l.ring {
		if e.Seq > afterSeq && (service == "" || e.Service == service) {
			out = append(out, *e)
		}
	}
	if len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out
}

func (l *Ledger) lastSeq() int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.seq
}

// summaryJSON renders the fork's summary: { "<service>": { operations: { "<op>": {calls,unsupported,errors} }, calls,
// unsupported, errors } }, services and operations sorted, in the fork's key order.
func (l *Ledger) summaryJSON() []byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	services := make([]string, 0, len(l.counts))
	for s := range l.counts {
		services = append(services, s)
	}
	sort.Strings(services)
	var b strings.Builder
	b.WriteByte('{')
	for i, s := range services {
		if i > 0 {
			b.WriteByte(',')
		}
		ops := l.counts[s]
		names := make([]string, 0, len(ops))
		for n := range ops {
			names = append(names, n)
		}
		sort.Strings(names)
		var tot counts
		var ob strings.Builder
		for j, n := range names {
			c := ops[n]
			tot.Calls += c.Calls
			tot.Unsupported += c.Unsupported
			tot.Errors += c.Errors
			if j > 0 {
				ob.WriteByte(',')
			}
			ob.WriteString(`"` + jsonEscape(n) + `":{"calls":` + strconv.FormatInt(c.Calls, 10) + `,"unsupported":` +
				strconv.FormatInt(c.Unsupported, 10) + `,"errors":` + strconv.FormatInt(c.Errors, 10) + `}`)
		}
		b.WriteString(`"` + jsonEscape(s) + `":{"operations":{` + ob.String() + `},"calls":` + strconv.FormatInt(tot.Calls, 10) +
			`,"unsupported":` + strconv.FormatInt(tot.Unsupported, 10) + `,"errors":` + strconv.FormatInt(tot.Errors, 10) + `}`)
	}
	b.WriteByte('}')
	return []byte(b.String())
}

func (l *Ledger) entriesJSON(service string, after int64, limit int) []byte {
	es := l.entries(service, after, limit)
	var b strings.Builder
	b.WriteString(`{"entries":[`)
	for i, e := range es {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"seq":` + strconv.FormatInt(e.Seq, 10) + `,"at":` + strconv.FormatInt(e.At, 10) +
			`,"service":"` + jsonEscape(e.Service) + `","operation":"` + jsonEscape(e.Operation) + `","method":"` + jsonEscape(e.Method) +
			`","status":` + strconv.Itoa(e.Status) + `,"unsupported":` + strconv.FormatBool(e.Unsupported) +
			`,"ms":` + strconv.FormatInt(e.Millis, 10) + `}`)
	}
	b.WriteString(`],"lastSeq":` + strconv.FormatInt(l.lastSeq(), 10) + `}`)
	return []byte(b.String())
}

// unsupportedCodes are error codes that count a call as unsupported (the fork's UNSUPPORTED_CODES).
var unsupportedCodes = map[string]bool{"UnsupportedOperation": true, "UnknownOperation": true, "UnknownOperationException": true,
	"InvalidAction": true, "NotImplemented": true, "NotImplementedException": true}

// isUnsupported classifies a response: HTTP 501, or an error body (status 400+) carrying one of the codes, in JSON
// (__type, with any "ns#" prefix removed) or XML (<Code>). body may be a prefix of the real body.
func isUnsupported(status int, errorTypeHeader string, body []byte) bool {
	if status == 501 {
		return true
	}
	if status < 400 {
		return false
	}
	if t := errorTypeHeader; t != "" {
		if i := strings.IndexAny(t, ":"); i >= 0 {
			t = t[:i]
		}
		if unsupportedCodes[t] {
			return true
		}
	}
	text := string(body)
	for code := range unsupportedCodes {
		if strings.Contains(text, "<Code>"+code+"</Code>") {
			return true
		}
		if strings.Contains(text, `"__type":"`+code+`"`) || strings.Contains(text, `#`+code+`"`) {
			return true
		}
	}
	return false
}
