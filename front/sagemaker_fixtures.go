package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// What answers a SageMaker endpoint when the front does (modes (a) recorded or canned answers): a backing with matching rules, an
// ordered queue and a default. Everything here is data read from a document (the control PUT or the seed), validated when it is
// read, never when a request arrives; a typo in a field name is refused, so a rule that silently never matches cannot be written.
//
// The answer to a request is chosen in this order:
//  1. the first rule, in order, whose conditions all hold and whose `times` (when set) is not used up;
//  2. the next answer of the queue (each is used once, in order);
//  3. the default;
//  4. nothing: the call fails with a ModelError that says no fixture matched (counted as unmatched).
// An answer from the default is counted as "made up": the evidence says how many calls had no matching answer.

// limits of what a document may hold
const (
	smMaxRules      = 1000
	smMaxQueue      = 1000
	smMaxDocBytes   = 8 << 20
	smMaxReplyBytes = 6 << 20 // SageMaker's own response limit
	smMaxDelayMs    = 60000
	smMaxPartSize   = 1 << 20
	smMaxRegexLen   = 1000
)

// smMatch is the conditions of one rule; every condition present must hold.
type smMatch struct {
	Operation        string          `json:"operation"`        // invoke, stream or async (empty: any)
	ContentType      string          `json:"contentType"`      // the request's, compared without parameters and without case
	Accept           string          `json:"accept"`           // likewise
	BodySHA256       string          `json:"bodySha256"`       // hex
	BodyEquals       *string         `json:"bodyEquals"`       // the whole body, as text
	BodyContains     string          `json:"bodyContains"`     // text inside the body
	JSONPath         string          `json:"jsonPath"`         // $.a.b[0]['c'] on a JSON body, with one of equals, matches, exists
	Equals           json.RawMessage `json:"equals"`           // the value at jsonPath (JSON)
	Matches          string          `json:"matches"`          // a regular expression (RE2) the value at jsonPath, or the body, must match
	Exists           *bool           `json:"exists"`           // whether jsonPath is present
	TargetVariant    string          `json:"targetVariant"`    // the X-Amzn-SageMaker-Target-Variant header
	CustomAttributes string          `json:"customAttributes"` // the X-Amzn-SageMaker-Custom-Attributes header
	TargetModel      string          `json:"targetModel"`      // the X-Amzn-SageMaker-Target-Model header

	path []jsonStep
	re   *regexp.Regexp
	want any // Equals, decoded
}

// smErrorSpec is an error a fixture answers with.
type smErrorSpec struct {
	Code               string `json:"code"`               // ModelError (default), ValidationError, ModelNotReadyException, InternalFailure, ServiceUnavailable
	Message            string `json:"message"`            // the message
	OriginalStatusCode int    `json:"originalStatusCode"` // ModelError: the status the container answered with (default 500)
	OriginalMessage    string `json:"originalMessage"`    // ModelError: what the container said
}

// smStreamErrorSpec is a ModelStreamError event written after the parts of a stream.
type smStreamErrorSpec struct {
	ErrorCode string `json:"errorCode"` // StreamBroken (default) or ModelInvocationTimeExceeded
	Message   string `json:"message"`
}

// smResponse is one answer.
type smResponse struct {
	Body             *string            `json:"body"`             // text
	BodyBase64       *string            `json:"bodyBase64"`       // bytes
	JSON             json.RawMessage    `json:"json"`             // a JSON value, written as compact JSON
	Parts            []string           `json:"parts"`            // streaming: the parts, in order (instead of a body)
	PartSize         int                `json:"partSize"`         // streaming: split the body into parts of about this many bytes (default 64)
	PartDelayMs      int                `json:"partDelayMs"`      // streaming: wait between parts
	StreamError      *smStreamErrorSpec `json:"streamError"`      // streaming: end the stream with a ModelStreamError
	ContentType      string             `json:"contentType"`      // the reply's (default: the request's Accept when it names one, else application/json)
	CustomAttributes string             `json:"customAttributes"` // X-Amzn-SageMaker-Custom-Attributes of the reply
	Variant          string             `json:"variant"`          // the production variant that answered
	DelayMs          int                `json:"delayMs"`          // wait before answering
	Error            *smErrorSpec       `json:"error"`            // answer with this error instead of a body

	data []byte
}

// smRule is a match and its answer.
type smRule struct {
	Match    smMatch    `json:"match"`
	Response smResponse `json:"response"`
	Times    int        `json:"times"` // 0: any number of times
	used     int
}

// smBacking is how one endpoint is answered.
type smBacking struct {
	Mode         string        `json:"mode"`         // canned (default), helper (the SM3 model stand-in, parked under decision 141) or image
	Source       string        `json:"source"`       // recorded or handwritten (default): what the evidence calls the answers
	RecordedOn   string        `json:"recordedOn"`   // the date a recording was made, for the evidence
	Helper       string        `json:"helper"`       // the model stand-in's address (mode helper); one of the configured ones, default the first
	AsyncDelayMs int           `json:"asyncDelayMs"` // wait before an asynchronous answer is written (default 100)
	Rules        []*smRule     `json:"rules"`
	Queue        []*smResponse `json:"queue"`
	Default      *smResponse   `json:"default"`
}

// smModeNone is the backing of an endpoint that has none: no recording or fixture was approved for it. It is never read from a
// document (smModes does not list it) and never stored: effectiveBacking makes it on the spot.
const smModeNone = "none"

const (
	// smNoAnswerLabel is what the evidence calls such an endpoint; smNoAnswerMarker is the ledger marker of every call refused this
	// way (the worker and the evidence match on the "no-answer:" prefix and report the test as NOT RUN, not as failed).
	smNoAnswerLabel  = "no answer"
	smNoAnswerMarker = "no-answer: no recording for this endpoint"
)

var (
	smModes   = map[string]bool{"canned": true, "helper": true, "image": true}
	smSources = map[string]bool{"recorded": true, "handwritten": true}
	// the errors a fixture may answer with, and the HTTP status each has
	smErrorStatus = map[string]int{"ModelError": 424, "ValidationError": 400, "ModelNotReadyException": 429, "InternalFailure": 500,
		"ServiceUnavailable": 503}
	smOperations = map[string]bool{"invoke": true, "stream": true, "async": true}
)

// parseBacking reads and validates a backing document.
func parseBacking(data []byte) (*smBacking, error) {
	if len(data) > smMaxDocBytes {
		return nil, errors.New("the document is larger than 8 MiB")
	}
	b := &smBacking{}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(b); err != nil {
		return nil, fmt.Errorf("the document is not a valid backing: %v", err)
	}
	if dec.More() {
		return nil, errors.New("the document has more than one value")
	}
	return b, b.validate()
}

func (b *smBacking) validate() error {
	if b.Mode == "" {
		b.Mode = "canned"
	}
	if !smModes[b.Mode] {
		return fmt.Errorf("mode %q is not one of canned, helper, image", b.Mode)
	}
	if b.Source == "" {
		b.Source = "handwritten"
	}
	if !smSources[b.Source] {
		return fmt.Errorf("source %q is not one of recorded, handwritten", b.Source)
	}
	if len(b.RecordedOn) > 40 || strings.ContainsAny(b.RecordedOn, "\r\n\x00") {
		return errors.New("recordedOn is not a date")
	}
	if b.AsyncDelayMs < 0 || b.AsyncDelayMs > smMaxDelayMs {
		return errors.New("asyncDelayMs is out of range")
	}
	if len(b.Rules) > smMaxRules || len(b.Queue) > smMaxQueue {
		return errors.New("too many rules or queued answers")
	}
	total := 0
	for i, r := range b.Rules {
		if r == nil {
			return fmt.Errorf("rule %d is empty", i)
		}
		if err := r.Match.validate(); err != nil {
			return fmt.Errorf("rule %d: %v", i, err)
		}
		if r.Times < 0 {
			return fmt.Errorf("rule %d: times is negative", i)
		}
		n, err := r.Response.validate()
		if err != nil {
			return fmt.Errorf("rule %d: %v", i, err)
		}
		total += n
	}
	for i, q := range b.Queue {
		if q == nil {
			return fmt.Errorf("queue entry %d is empty", i)
		}
		n, err := q.validate()
		if err != nil {
			return fmt.Errorf("queue entry %d: %v", i, err)
		}
		total += n
	}
	if b.Default != nil {
		n, err := b.Default.validate()
		if err != nil {
			return fmt.Errorf("default: %v", err)
		}
		total += n
	}
	if total > smMaxDocBytes {
		return errors.New("the answers hold more than 8 MiB")
	}
	return nil
}

func (m *smMatch) validate() error {
	if m.Operation != "" && !smOperations[m.Operation] {
		return fmt.Errorf("operation %q is not one of invoke, stream, async", m.Operation)
	}
	if m.BodySHA256 != "" {
		m.BodySHA256 = strings.ToLower(m.BodySHA256)
		if raw, err := hex.DecodeString(m.BodySHA256); err != nil || len(raw) != sha256.Size {
			return errors.New("bodySha256 is not a hex SHA-256")
		}
	}
	hasValueCondition := len(m.Equals) > 0 || m.Exists != nil
	if m.JSONPath != "" {
		p, err := parseJSONPath(m.JSONPath)
		if err != nil {
			return err
		}
		m.path = p
		if !hasValueCondition && m.Matches == "" {
			t := true
			m.Exists = &t // a path with no other condition asks whether it is there
		}
	} else if len(m.Equals) > 0 || m.Exists != nil {
		return errors.New("equals and exists need a jsonPath")
	}
	if len(m.Equals) > 0 {
		var v any
		dec := json.NewDecoder(bytes.NewReader(m.Equals))
		dec.UseNumber()
		if err := dec.Decode(&v); err != nil {
			return errors.New("equals is not JSON")
		}
		m.want = normalizeJSON(v)
	}
	if m.Matches != "" {
		if len(m.Matches) > smMaxRegexLen {
			return errors.New("matches is too long")
		}
		re, err := regexp.Compile(m.Matches)
		if err != nil {
			return fmt.Errorf("matches is not a regular expression: %v", err)
		}
		m.re = re
	}
	return nil
}

// validate checks one answer and resolves its body; it returns the bytes the answer holds.
func (r *smResponse) validate() (int, error) {
	forms := 0
	for _, set := range []bool{r.Body != nil, r.BodyBase64 != nil, len(r.JSON) > 0, len(r.Parts) > 0} {
		if set {
			forms++
		}
	}
	if forms > 1 {
		return 0, errors.New("an answer has one of body, bodyBase64, json or parts")
	}
	switch {
	case r.Body != nil:
		r.data = []byte(*r.Body)
	case r.BodyBase64 != nil:
		d, err := base64.StdEncoding.DecodeString(*r.BodyBase64)
		if err != nil {
			return 0, errors.New("bodyBase64 is not base64")
		}
		r.data = d
	case len(r.JSON) > 0:
		var buf bytes.Buffer
		if err := json.Compact(&buf, r.JSON); err != nil {
			return 0, errors.New("json is not JSON")
		}
		r.data = buf.Bytes()
	case len(r.Parts) > 0:
		var buf bytes.Buffer
		for _, p := range r.Parts {
			buf.WriteString(p)
		}
		r.data = buf.Bytes()
	}
	if len(r.data) > smMaxReplyBytes {
		return 0, errors.New("an answer is larger than 6 MiB")
	}
	if r.PartSize < 0 || r.PartSize > smMaxPartSize || r.PartDelayMs < 0 || r.PartDelayMs > smMaxDelayMs || r.DelayMs < 0 || r.DelayMs > smMaxDelayMs {
		return 0, errors.New("partSize, partDelayMs or delayMs is out of range")
	}
	if len(r.ContentType) > 200 || strings.ContainsAny(r.ContentType+r.CustomAttributes+r.Variant, "\r\n\x00") || len(r.CustomAttributes) > 1024 || len(r.Variant) > 63 {
		return 0, errors.New("contentType, customAttributes or variant is not a header value")
	}
	if e := r.Error; e != nil {
		if e.Code == "" {
			e.Code = "ModelError"
		}
		if _, ok := smErrorStatus[e.Code]; !ok {
			return 0, fmt.Errorf("error code %q is not one of ModelError, ValidationError, ModelNotReadyException, InternalFailure, ServiceUnavailable", e.Code)
		}
		if e.OriginalStatusCode < 0 || e.OriginalStatusCode > 599 || len(e.Message) > 4096 || len(e.OriginalMessage) > 4096 {
			return 0, errors.New("an error is out of range")
		}
		if e.OriginalStatusCode == 0 {
			e.OriginalStatusCode = 500
		}
	}
	if e := r.StreamError; e != nil {
		if e.ErrorCode == "" {
			e.ErrorCode = "StreamBroken"
		}
		if e.ErrorCode != "StreamBroken" && e.ErrorCode != "ModelInvocationTimeExceeded" || len(e.Message) > 4096 {
			return 0, errors.New("streamError is not StreamBroken or ModelInvocationTimeExceeded")
		}
	}
	return len(r.data), nil
}

// ---- matching

// smRequest is what a rule is matched against.
type smRequest struct {
	op          string // invoke, stream or async
	contentType string
	accept      string
	body        []byte
	sha         string
	variant     string
	custom      string
	targetModel string
	doc         any // the body as JSON, decoded once
	docOK       bool
	docTried    bool
}

func newSMRequest(op, contentType, accept, variant, custom, targetModel string, body []byte) *smRequest {
	sum := sha256.Sum256(body)
	return &smRequest{op: op, contentType: contentType, accept: accept, variant: variant, custom: custom, targetModel: targetModel,
		body: body, sha: hex.EncodeToString(sum[:])}
}

func (q *smRequest) json() (any, bool) {
	if !q.docTried {
		q.docTried = true
		dec := json.NewDecoder(bytes.NewReader(q.body))
		dec.UseNumber()
		var v any
		if err := dec.Decode(&v); err == nil {
			if _, err := dec.Token(); err == io.EOF {
				q.doc, q.docOK = normalizeJSON(v), true
			}
		}
	}
	return q.doc, q.docOK
}

func mediaType(v string) string {
	if i := strings.IndexByte(v, ';'); i >= 0 {
		v = v[:i]
	}
	return strings.ToLower(strings.TrimSpace(v))
}

func (m *smMatch) matches(q *smRequest) bool {
	if m.Operation != "" && m.Operation != q.op {
		return false
	}
	if m.ContentType != "" && mediaType(m.ContentType) != mediaType(q.contentType) {
		return false
	}
	if m.Accept != "" && mediaType(m.Accept) != mediaType(q.accept) {
		return false
	}
	if m.BodySHA256 != "" && m.BodySHA256 != q.sha {
		return false
	}
	if m.BodyEquals != nil && *m.BodyEquals != string(q.body) {
		return false
	}
	if m.BodyContains != "" && !bytes.Contains(q.body, []byte(m.BodyContains)) {
		return false
	}
	if m.TargetVariant != "" && m.TargetVariant != q.variant {
		return false
	}
	if m.CustomAttributes != "" && m.CustomAttributes != q.custom {
		return false
	}
	if m.TargetModel != "" && m.TargetModel != q.targetModel {
		return false
	}
	if m.JSONPath != "" {
		doc, ok := q.json()
		var v any
		found := false
		if ok {
			v, found = evalJSONPath(doc, m.path)
		}
		if m.Exists != nil && *m.Exists != found {
			return false
		}
		if len(m.Equals) > 0 && !(found && jsonValuesEqual(m.want, v)) {
			return false
		}
		if m.re != nil && !(found && m.re.MatchString(jsonScalarText(v))) {
			return false
		}
	} else if m.re != nil && !m.re.Match(q.body) {
		return false
	}
	return true
}

// ---- JSON paths: $, .name, ['name'], ["name"], [n]

type jsonStep struct {
	key   string
	index int
	isIdx bool
}

func parseJSONPath(p string) ([]jsonStep, error) {
	bad := func() ([]jsonStep, error) {
		return nil, fmt.Errorf("jsonPath %q is not supported (use $.a.b[0]['c'])", p)
	}
	if len(p) > 500 || !strings.HasPrefix(p, "$") {
		return bad()
	}
	var steps []jsonStep
	i := 1
	for i < len(p) {
		switch p[i] {
		case '.':
			j := i + 1
			for j < len(p) && p[j] != '.' && p[j] != '[' {
				j++
			}
			if j == i+1 || strings.ContainsAny(p[i+1:j], "*?()@,:") {
				return bad()
			}
			steps = append(steps, jsonStep{key: p[i+1 : j]})
			i = j
		case '[':
			j := strings.IndexByte(p[i:], ']')
			if j < 0 {
				return bad()
			}
			inner := p[i+1 : i+j]
			i += j + 1
			if n := len(inner); n >= 2 && (inner[0] == '\'' && inner[n-1] == '\'' || inner[0] == '"' && inner[n-1] == '"') {
				steps = append(steps, jsonStep{key: inner[1 : n-1]})
			} else if idx, err := strconv.Atoi(inner); err == nil && idx >= 0 {
				steps = append(steps, jsonStep{index: idx, isIdx: true})
			} else {
				return bad()
			}
		default:
			return bad()
		}
	}
	return steps, nil
}

func evalJSONPath(doc any, steps []jsonStep) (any, bool) {
	cur := doc
	for _, s := range steps {
		if s.isIdx {
			a, ok := cur.([]any)
			if !ok || s.index >= len(a) {
				return nil, false
			}
			cur = a[s.index]
			continue
		}
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		v, ok := m[s.key]
		if !ok {
			return nil, false
		}
		cur = v
	}
	return cur, true
}

// normalizeJSON turns json.Number into float64 so two numbers compare by value.
func normalizeJSON(v any) any {
	switch t := v.(type) {
	case json.Number:
		f, err := t.Float64()
		if err != nil {
			return t.String()
		}
		return f
	case map[string]any:
		for k, e := range t {
			t[k] = normalizeJSON(e)
		}
	case []any:
		for i, e := range t {
			t[i] = normalizeJSON(e)
		}
	}
	return v
}

func jsonValuesEqual(a, b any) bool {
	if fa, ok := a.(float64); ok {
		fb, ok := b.(float64)
		return ok && (fa == fb || math.IsNaN(fa) && math.IsNaN(fb))
	}
	return reflect.DeepEqual(a, b)
}

// jsonScalarText is the text a `matches` expression sees for a value: a string as it is, anything else as compact JSON.
func jsonScalarText(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// ---- choosing the answer

type smPick int

const (
	smNone smPick = iota
	smRuleHit
	smQueueHit
	smDefaultHit
)

// claim uses up one turn of a rule; false when its `times` is spent. The caller holds the state's lock.
func (r *smRule) claim() bool {
	if r.Times > 0 && r.used >= r.Times {
		return false
	}
	r.used++
	return true
}

// queueOrDefault is what answers a request no rule took: the next queued answer, else the default, else nothing. The caller holds the
// state's lock.
func (b *smBacking) queueOrDefault() (*smResponse, smPick) {
	if len(b.Queue) > 0 {
		r := b.Queue[0]
		b.Queue = b.Queue[1:]
		return r, smQueueHit
	}
	if b.Default != nil {
		return b.Default, smDefaultHit
	}
	return nil, smNone
}

// pick chooses the answer to a request and uses it up (a rule's `times`, a queue entry). The caller holds the state's lock. (The
// front itself matches the rules outside the lock and takes it only to claim; see smProduce.)
func (b *smBacking) pick(q *smRequest) (*smResponse, smPick) {
	for _, r := range b.Rules {
		if r.Match.matches(q) && r.claim() {
			return &r.Response, smRuleHit
		}
	}
	return b.queueOrDefault()
}

// splitParts cuts a body into parts of about size bytes, never inside a UTF-8 character when the body is text (checked once).
func splitParts(data []byte, size int) [][]byte {
	if size <= 0 {
		size = 64
	}
	if len(data) == 0 {
		return nil
	}
	text := utf8.Valid(data)
	var parts [][]byte
	for len(data) > 0 {
		n := size
		if n >= len(data) {
			parts = append(parts, data)
			break
		}
		if text {
			for n < len(data) && !utf8.RuneStart(data[n]) {
				n++
			}
		}
		parts = append(parts, data[:n])
		data = data[n:]
	}
	return parts
}
