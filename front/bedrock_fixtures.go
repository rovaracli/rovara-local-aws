package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

// What answers a Bedrock runtime call when the front does: fixture sets (data read from a document, validated when it is read, never
// when a request arrives; a typo in a field name is refused, so a rule that silently never matches cannot be written).
//
// A set belongs to a model id (exact, or a prefix such as `anthropic.`, or every model) and holds ordered rules, an ordered queue and
// a default. The answer to a request is the first answer of the most specific set that has one: sets are tried exact id first, then
// the longest prefix, then the sets for every model; within a set the first rule whose conditions all hold and whose `times` is not
// used up, then the next queued answer (each is used once), then the default. An answer from a default is counted as "made up".
// When no set answers, the call fails with a ValidationException that says no rule matched (counted as unmatched): never a
// silent invented answer.
//
// One answer (a bdResponse) is the logical answer, not a wire body: the same rule answers Converse, ConverseStream, InvokeModel and
// InvokeModelWithResponseStream, and each operation writes it in its own shape (bedrock_shapes.go). `raw` and `rawChunks` are the
// exception: a provider body (or its stream chunks) written verbatim, for a recorded answer or a model family the front has no shape for.

const (
	bdMaxSets       = 128
	bdMaxRules      = 1000 // per set
	bdMaxQueue      = 1000
	bdMaxDocBytes   = 8 << 20
	bdMaxDelayMs    = 60000
	bdMaxRegexLen   = 1000
	bdMaxFaults     = 256
	bdMaxBlocks     = 64
	bdMaxChunk      = 1 << 20
	bdMaxEmbedDims  = 8192
	bdMaxStatModels = 1000
	bdMaxLast       = 10
)

// the operations of the route key bedrock-runtime the front answers, and the names a rule uses for them
const (
	bdOpConverse     = "converse"
	bdOpConverseStr  = "converse-stream"
	bdOpInvoke       = "invoke"
	bdOpInvokeStream = "invoke-stream"
	bdOpCount        = "count-tokens"
	bdOpApply        = "apply-guardrail"
)

var bdOpByName = map[string]string{"Converse": bdOpConverse, "ConverseStream": bdOpConverseStr, "InvokeModel": bdOpInvoke,
	"InvokeModelWithResponseStream": bdOpInvokeStream, "CountTokens": bdOpCount, "ApplyGuardrail": bdOpApply}

var bdOperations = map[string]bool{bdOpConverse: true, bdOpConverseStr: true, bdOpInvoke: true, bdOpInvokeStream: true, bdOpCount: true, bdOpApply: true}

func bdIsStream(op string) bool { return op == bdOpConverseStr || op == bdOpInvokeStream }

// the errors an answer may be, with the HTTP status Bedrock gives each (botocore's model of bedrock-runtime)
var bdErrorStatus = map[string]int{"AccessDeniedException": 403, "ThrottlingException": 429, "ResourceNotFoundException": 404,
	"ModelTimeoutException": 408, "InternalServerException": 500, "ServiceUnavailableException": 503, "ValidationException": 400,
	"ModelNotReadyException": 429, "ModelErrorException": 424, "ServiceQuotaExceededException": 400}

// the exception events a stream may end in (the first letter lower case, as the event stream names them)
var bdStreamErrors = map[string]bool{"internalServerException": true, "modelStreamErrorException": true, "validationException": true,
	"throttlingException": true, "serviceUnavailableException": true, "modelTimeoutException": true}

var bdStopReasons = map[string]bool{"end_turn": true, "tool_use": true, "max_tokens": true, "stop_sequence": true, "guardrail_intervened": true,
	"content_filtered": true, "model_context_window_exceeded": true, "malformed_model_output": true, "malformed_tool_use": true}

// ---- the document

// bdMatch holds the conditions of one rule; every condition present must hold.
type bdMatch struct {
	Operation          string          `json:"operation"`          // converse, converse-stream, invoke, invoke-stream, count-tokens, apply-guardrail (empty: any)
	TextContains       string          `json:"textContains"`       // the last user message's text (ApplyGuardrail: the content's text)
	TextEquals         *string         `json:"textEquals"`         // likewise, the whole text
	TextMatches        string          `json:"textMatches"`        // a regular expression (RE2) on that text
	SystemContains     string          `json:"systemContains"`     // text in the system prompt
	ToolOffered        string          `json:"toolOffered"`        // the request offers a tool of this name (Converse toolConfig, Anthropic tools)
	ToolResult         *bool           `json:"toolResult"`         // the last user message carries a tool result (a follow-up turn of a tool loop)
	ToolResultContains string          `json:"toolResultContains"` // text inside the tool result(s) of the last user message
	ToolResultMatches  string          `json:"toolResultMatches"`  // a regular expression on that text
	Guardrail          *bool           `json:"guardrail"`          // the request carries a guardrail (guardrailConfig, or the guardrail headers, or ApplyGuardrail)
	GuardrailID        string          `json:"guardrailId"`        // the guardrail the request names (identifier as sent)
	GuardrailSource    string          `json:"guardrailSource"`    // ApplyGuardrail: INPUT or OUTPUT
	BodyContains       string          `json:"bodyContains"`       // text inside the request body
	JSONPath           string          `json:"jsonPath"`           // $.a.b[0]['c'] on the JSON request body, with one of equals, matches, exists
	Equals             json.RawMessage `json:"equals"`             // the value at jsonPath (JSON)
	Matches            string          `json:"matches"`            // a regular expression the value at jsonPath must match
	Exists             *bool           `json:"exists"`             // whether jsonPath is present

	path      []jsonStep
	textRe    *regexp.Regexp
	toolResRe *regexp.Regexp
	valueRe   *regexp.Regexp
	want      any
	hasWant   bool
}

type bdToolUse struct {
	ToolUseID string          `json:"toolUseId"`
	Name      string          `json:"name"`
	Input     json.RawMessage `json:"input"` // any JSON value; an object when it is the input of a tool (default {})
}

type bdUsage struct {
	InputTokens  *int `json:"inputTokens"`
	OutputTokens *int `json:"outputTokens"`
}

// bdGuardrail is what a guardrail did, for a request that carries a guardrail.
type bdGuardrail struct {
	Action         string          `json:"action"`         // GUARDRAIL_INTERVENED (default) or NONE
	Phase          string          `json:"phase"`          // input (default) or output: which assessment the finding goes under in the trace
	BlockedMessage string          `json:"blockedMessage"` // the text the caller gets (default "Sorry, the model cannot answer this question.")
	Assessments    json.RawMessage `json:"assessments"`    // an object in the API's shape (topicPolicy, contentPolicy, wordPolicy, ...) or, for ApplyGuardrail, a list of them
	ActionReason   string          `json:"actionReason"`
	Outputs        []string        `json:"outputs"` // ApplyGuardrail: the output texts (default: the blocked message when it intervened)
}

type bdEmbedding struct {
	Dimensions int `json:"dimensions"` // a deterministic vector of this many numbers, made up from the text (Titan and Cohere embedding models)
}

type bdErrorSpec struct {
	Code               string `json:"code"` // ThrottlingException, ValidationException, ModelTimeoutException, ...
	Message            string `json:"message"`
	OriginalStatusCode int    `json:"originalStatusCode"` // ModelErrorException
}

type bdStreamErrorSpec struct {
	Code               string `json:"code"` // modelStreamErrorException (default), throttlingException, ...
	Message            string `json:"message"`
	AfterParts         *int   `json:"afterParts"` // content events written before the error (default: all of them)
	OriginalStatusCode int    `json:"originalStatusCode"`
	OriginalMessage    string `json:"originalMessage"`
}

// bdResponse is one answer.
type bdResponse struct {
	Text       *string           `json:"text"`
	ToolUse    *bdToolUse        `json:"toolUse"`    // after the text
	Content    []json.RawMessage `json:"content"`    // blocks in Converse's shape: {"text"}, {"toolUse"}, ... (instead of text and toolUse)
	StopReason string            `json:"stopReason"` // default end_turn, or tool_use when the answer has a tool use
	Usage      *bdUsage          `json:"usage"`      // default: made up from the text (about 4 characters a token), labelled fake
	LatencyMs  *int              `json:"latencyMs"`
	Guardrail  *bdGuardrail      `json:"guardrail"`
	Embedding  *bdEmbedding      `json:"embedding"`
	Raw        json.RawMessage   `json:"raw"`       // InvokeModel: this provider body, written as it is
	RawChunks  []json.RawMessage `json:"rawChunks"` // InvokeModelWithResponseStream: these provider chunks, written as they are
	Additional json.RawMessage   `json:"additionalModelResponseFields"`

	ChunkSize   int      `json:"chunkSize"`   // streaming: split the text into parts of about this many bytes (default 24)
	Parts       []string `json:"parts"`       // streaming: the text's parts, in order (instead of splitting it); the text is their join
	PartDelayMs int      `json:"partDelayMs"` // streaming: wait between parts
	DelayMs     int      `json:"delayMs"`     // wait before answering

	Error       *bdErrorSpec       `json:"error"`       // answer with this error (before any byte of a stream)
	StreamError *bdStreamErrorSpec `json:"streamError"` // a stream: end with this exception event

	blocks []bdBlock // resolved from text, toolUse and content, when the document was read
}

// bdBlock is one content block of an answer.
type bdBlock struct {
	kind  string // text, toolUse or other
	text  string
	id    string
	name  string
	input json.RawMessage
	raw   json.RawMessage // other: the block as the document gave it (non-stream Converse only)
}

// bdRule is a match and its answer.
type bdRule struct {
	Match    bdMatch    `json:"match"`
	Response bdResponse `json:"response"`
	Times    int        `json:"times"` // 0: any number of times
	used     int
}

// bdSet is the fixtures of one model id (or prefix, or every model).
type bdSet struct {
	Name        string        `json:"name"`
	ModelID     string        `json:"modelId"`     // exact: the id the code gives, or the base id of an inference profile or ARN
	ModelPrefix string        `json:"modelPrefix"` // a prefix of either
	Source      string        `json:"source"`      // recorded or handwritten (default)
	RecordedOn  string        `json:"recordedOn"`
	Rules       []*bdRule     `json:"rules"`
	Queue       []*bdResponse `json:"queue"`
	Default     *bdResponse   `json:"default"`
}

// bdFault is an armed fault: the next calls that match fail (or end their stream) as told, then calls go on as normal.
type bdFault struct {
	ModelID     string             `json:"modelId"`
	ModelPrefix string             `json:"modelPrefix"`
	Operation   string             `json:"operation"`
	Times       int                `json:"times"` // calls it applies to (default 1)
	Skip        int                `json:"skip"`  // matching calls let through first
	Error       *bdErrorSpec       `json:"error"`
	StreamError *bdStreamErrorSpec `json:"streamError"`
	DelayMs     int                `json:"delayMs"`

	seen, used int
}

var (
	bdSources = map[string]bool{"recorded": true, "handwritten": true}
	bdNameRe  = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}$`)
)

// bdStrict decodes one JSON value, refusing unknown fields and trailing values.
func bdStrict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("the document has more than one value")
	}
	return nil
}

// parseSet reads and validates one set document.
func parseSet(data []byte) (*bdSet, error) {
	if len(data) > bdMaxDocBytes {
		return nil, errors.New("the document is larger than 8 MiB")
	}
	s := &bdSet{}
	if err := bdStrict(data, s); err != nil {
		return nil, fmt.Errorf("the document is not a valid fixture set: %v", err)
	}
	return s, s.validate()
}

func (s *bdSet) validate() error {
	if s.Name != "" && !bdNameRe.MatchString(s.Name) {
		return errors.New("name must be letters, digits, '.', '_' or '-' (at most 63)")
	}
	if s.ModelID != "" && s.ModelPrefix != "" {
		return errors.New("a set names a modelId or a modelPrefix, not both")
	}
	for _, v := range []string{s.ModelID, s.ModelPrefix} {
		if len(v) > 2048 || strings.ContainsAny(v, "\r\n\x00 ") {
			return errors.New("modelId or modelPrefix is not a model identifier")
		}
	}
	if s.Source == "" {
		s.Source = "handwritten"
	}
	if !bdSources[s.Source] {
		return fmt.Errorf("source %q is not one of recorded, handwritten", s.Source)
	}
	if len(s.RecordedOn) > 40 || strings.ContainsAny(s.RecordedOn, "\r\n\x00") {
		return errors.New("recordedOn is not a date")
	}
	if len(s.Rules) > bdMaxRules || len(s.Queue) > bdMaxQueue {
		return errors.New("too many rules or queued answers")
	}
	total := 0
	for i, r := range s.Rules {
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
	for i, q := range s.Queue {
		if q == nil {
			return fmt.Errorf("queue entry %d is empty", i)
		}
		n, err := q.validate()
		if err != nil {
			return fmt.Errorf("queue entry %d: %v", i, err)
		}
		total += n
	}
	if s.Default != nil {
		n, err := s.Default.validate()
		if err != nil {
			return fmt.Errorf("default: %v", err)
		}
		total += n
	}
	if total > bdMaxDocBytes {
		return errors.New("the answers hold more than 8 MiB")
	}
	return nil
}

func compileRe(src, what string) (*regexp.Regexp, error) {
	if len(src) > bdMaxRegexLen {
		return nil, fmt.Errorf("%s is too long", what)
	}
	re, err := regexp.Compile(src)
	if err != nil {
		return nil, fmt.Errorf("%s is not a regular expression: %v", what, err)
	}
	return re, nil
}

func (m *bdMatch) validate() error {
	if m.Operation != "" && !bdOperations[m.Operation] {
		return fmt.Errorf("operation %q is not one of converse, converse-stream, invoke, invoke-stream, count-tokens, apply-guardrail", m.Operation)
	}
	if m.GuardrailSource != "" && m.GuardrailSource != "INPUT" && m.GuardrailSource != "OUTPUT" {
		return errors.New("guardrailSource is INPUT or OUTPUT")
	}
	var err error
	if m.TextMatches != "" {
		if m.textRe, err = compileRe(m.TextMatches, "textMatches"); err != nil {
			return err
		}
	}
	if m.ToolResultMatches != "" {
		if m.toolResRe, err = compileRe(m.ToolResultMatches, "toolResultMatches"); err != nil {
			return err
		}
	}
	hasValue := len(m.Equals) > 0 || m.Exists != nil || m.Matches != ""
	if m.JSONPath != "" {
		p, err := parseJSONPath(m.JSONPath)
		if err != nil {
			return err
		}
		m.path = p
		if !hasValue {
			t := true
			m.Exists = &t // a path with no other condition asks whether it is there
		}
	} else if hasValue {
		return errors.New("equals, matches and exists need a jsonPath")
	}
	if len(m.Equals) > 0 {
		var v any
		dec := json.NewDecoder(bytes.NewReader(m.Equals))
		dec.UseNumber()
		if err := dec.Decode(&v); err != nil {
			return errors.New("equals is not JSON")
		}
		m.want, m.hasWant = normalizeJSON(v), true
	}
	if m.Matches != "" {
		if m.valueRe, err = compileRe(m.Matches, "matches"); err != nil {
			return err
		}
	}
	return nil
}

// validate checks one answer and resolves its blocks; it returns the bytes the answer holds.
func (r *bdResponse) validate() (int, error) {
	size := 0
	forms := 0
	for _, set := range []bool{r.Text != nil || r.ToolUse != nil, len(r.Content) > 0, len(r.Raw) > 0, len(r.RawChunks) > 0, r.Embedding != nil} {
		if set {
			forms++
		}
	}
	if forms > 1 {
		return 0, errors.New("an answer has one of text and toolUse, content, raw, rawChunks or embedding")
	}
	if len(r.Parts) > 0 && (r.Text != nil || len(r.Content) > 0) {
		return 0, errors.New("parts replace the text: give one of them")
	}
	if !r.hasAnswer() {
		return 0, errors.New("an answer needs text, toolUse, content, parts, raw, rawChunks, embedding, usage, guardrail, error or streamError")
	}
	r.blocks = nil
	if len(r.Parts) > 0 {
		var sb strings.Builder
		for _, p := range r.Parts {
			sb.WriteString(p)
		}
		r.blocks = append(r.blocks, bdBlock{kind: "text", text: sb.String()})
		size += sb.Len()
	}
	if r.Text != nil {
		r.blocks = append(r.blocks, bdBlock{kind: "text", text: *r.Text})
		size += len(*r.Text)
	}
	if t := r.ToolUse; t != nil {
		b, n, err := toolBlock(t)
		if err != nil {
			return 0, err
		}
		r.blocks, size = append(r.blocks, b), size+n
	}
	if len(r.Content) > bdMaxBlocks {
		return 0, errors.New("an answer has at most 64 content blocks")
	}
	for i, raw := range r.Content {
		var blk map[string]json.RawMessage
		if err := json.Unmarshal(raw, &blk); err != nil || len(blk) == 0 {
			return 0, fmt.Errorf("content block %d is not a JSON object", i)
		}
		size += len(raw)
		if t, ok := blk["text"]; ok && len(blk) == 1 {
			var s string
			if err := json.Unmarshal(t, &s); err != nil {
				return 0, fmt.Errorf("content block %d: text is not a string", i)
			}
			r.blocks = append(r.blocks, bdBlock{kind: "text", text: s})
		} else if tu, ok := blk["toolUse"]; ok && len(blk) == 1 {
			var t bdToolUse
			if err := bdStrict(tu, &t); err != nil {
				return 0, fmt.Errorf("content block %d: toolUse: %v", i, err)
			}
			b, _, err := toolBlock(&t)
			if err != nil {
				return 0, fmt.Errorf("content block %d: %v", i, err)
			}
			r.blocks = append(r.blocks, b)
		} else {
			r.blocks = append(r.blocks, bdBlock{kind: "other", raw: raw})
		}
	}
	if r.StopReason != "" && !bdStopReasons[r.StopReason] {
		return 0, fmt.Errorf("stopReason %q is not one Converse has", r.StopReason)
	}
	if len(r.Raw) > 0 {
		if !json.Valid(r.Raw) {
			return 0, errors.New("raw is not JSON")
		}
		size += len(r.Raw)
	}
	if len(r.RawChunks) > 100000 {
		return 0, errors.New("too many rawChunks")
	}
	for i, c := range r.RawChunks {
		if !json.Valid(c) {
			return 0, fmt.Errorf("rawChunks[%d] is not JSON", i)
		}
		size += len(c)
	}
	if u := r.Usage; u != nil {
		for _, p := range []*int{u.InputTokens, u.OutputTokens} {
			if p != nil && (*p < 0 || *p > 1<<31-1) {
				return 0, errors.New("usage is out of range")
			}
		}
	}
	if r.LatencyMs != nil && (*r.LatencyMs < 0 || *r.LatencyMs > 3600000) {
		return 0, errors.New("latencyMs is out of range")
	}
	if g := r.Guardrail; g != nil {
		if g.Action == "" {
			g.Action = "GUARDRAIL_INTERVENED"
		}
		if g.Action != "GUARDRAIL_INTERVENED" && g.Action != "NONE" {
			return 0, errors.New("guardrail.action is GUARDRAIL_INTERVENED or NONE")
		}
		if g.Phase == "" {
			g.Phase = "input"
		}
		if g.Phase != "input" && g.Phase != "output" {
			return 0, errors.New("guardrail.phase is input or output")
		}
		if len(g.Assessments) > 0 {
			var v any
			if err := json.Unmarshal(g.Assessments, &v); err != nil {
				return 0, errors.New("guardrail.assessments is not JSON")
			}
			switch v.(type) {
			case map[string]any, []any:
			default:
				return 0, errors.New("guardrail.assessments is an object (or a list, for ApplyGuardrail)")
			}
			size += len(g.Assessments)
		}
		if len(g.BlockedMessage) > 4096 || len(g.ActionReason) > 4096 || len(g.Outputs) > 100 {
			return 0, errors.New("guardrail text is too long")
		}
	}
	if len(r.Additional) > 0 {
		var m map[string]any
		if json.Unmarshal(r.Additional, &m) != nil {
			return 0, errors.New("additionalModelResponseFields is not a JSON object")
		}
	}
	if e := r.Embedding; e != nil && (e.Dimensions < 1 || e.Dimensions > bdMaxEmbedDims) {
		return 0, errors.New("embedding.dimensions is 1 to 8192")
	}
	if r.ChunkSize < 0 || r.ChunkSize > bdMaxChunk || r.PartDelayMs < 0 || r.PartDelayMs > bdMaxDelayMs || r.DelayMs < 0 || r.DelayMs > bdMaxDelayMs {
		return 0, errors.New("chunkSize, partDelayMs or delayMs is out of range")
	}
	if e := r.Error; e != nil {
		if err := e.validate(); err != nil {
			return 0, err
		}
	}
	if e := r.StreamError; e != nil {
		if err := e.validate(); err != nil {
			return 0, err
		}
	}
	if len(r.Parts) > 100000 {
		return 0, errors.New("too many parts")
	}
	return size, nil
}

func (r *bdResponse) hasAnswer() bool {
	return r.Text != nil || r.ToolUse != nil || len(r.Content) > 0 || len(r.Parts) > 0 || len(r.Raw) > 0 || len(r.RawChunks) > 0 || r.Embedding != nil ||
		r.Usage != nil || r.Guardrail != nil || r.Error != nil || r.StreamError != nil
}

// toolBlock turns a document's tool use into a block: a missing id is made from the name and the input (so a replay is the same every
// time), a missing input is {}.
func toolBlock(t *bdToolUse) (bdBlock, int, error) {
	if t.Name == "" || len(t.Name) > 64 {
		return bdBlock{}, 0, errors.New("toolUse needs a name of at most 64 characters")
	}
	in := t.Input
	if len(in) == 0 {
		in = json.RawMessage("{}")
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, in); err != nil {
		return bdBlock{}, 0, errors.New("toolUse.input is not JSON")
	}
	id := t.ToolUseID
	if id == "" {
		sum := sha256.Sum256([]byte(t.Name + "\x00" + buf.String()))
		id = "tooluse_" + hex.EncodeToString(sum[:])[:22]
	}
	if len(id) > 64 || strings.ContainsAny(id, "\r\n\x00") {
		return bdBlock{}, 0, errors.New("toolUse.toolUseId is not an id")
	}
	return bdBlock{kind: "toolUse", id: id, name: t.Name, input: buf.Bytes()}, buf.Len() + len(id) + len(t.Name), nil
}

func (e *bdErrorSpec) validate() error {
	if _, ok := bdErrorStatus[e.Code]; !ok {
		return fmt.Errorf("error code %q is not one of ThrottlingException, ValidationException, ModelTimeoutException, ModelErrorException, ModelNotReadyException, ServiceUnavailableException, InternalServerException, AccessDeniedException, ResourceNotFoundException, ServiceQuotaExceededException", e.Code)
	}
	if len(e.Message) > 4096 || e.OriginalStatusCode < 0 || e.OriginalStatusCode > 599 {
		return errors.New("an error is out of range")
	}
	return nil
}

func (e *bdStreamErrorSpec) validate() error {
	if e.Code == "" {
		e.Code = "modelStreamErrorException"
	}
	if !bdStreamErrors[e.Code] {
		return fmt.Errorf("streamError code %q is not one of internalServerException, modelStreamErrorException, validationException, throttlingException, serviceUnavailableException, modelTimeoutException", e.Code)
	}
	if len(e.Message) > 4096 || len(e.OriginalMessage) > 4096 || e.OriginalStatusCode < 0 || e.OriginalStatusCode > 599 || (e.AfterParts != nil && *e.AfterParts < 0) {
		return errors.New("streamError is out of range")
	}
	return nil
}

// parseFault reads and validates a fault document.
func parseFault(data []byte) (*bdFault, error) {
	if len(data) > 1<<20 {
		return nil, errors.New("the document is larger than 1 MiB")
	}
	f := &bdFault{}
	if err := bdStrict(data, f); err != nil {
		return nil, fmt.Errorf("the document is not a valid fault: %v", err)
	}
	if f.ModelID != "" && f.ModelPrefix != "" {
		return nil, errors.New("a fault names a modelId or a modelPrefix, not both")
	}
	if f.Operation != "" && !bdOperations[f.Operation] {
		return nil, fmt.Errorf("operation %q is not one of converse, converse-stream, invoke, invoke-stream, count-tokens, apply-guardrail", f.Operation)
	}
	if f.Times < 0 || f.Skip < 0 || f.DelayMs < 0 || f.DelayMs > bdMaxDelayMs || len(f.ModelID) > 2048 || len(f.ModelPrefix) > 2048 {
		return nil, errors.New("times, skip or delayMs is out of range")
	}
	if f.Times == 0 {
		f.Times = 1
	}
	if f.Error == nil && f.StreamError == nil && f.DelayMs == 0 {
		return nil, errors.New("a fault needs an error, a streamError or a delayMs")
	}
	if f.Error != nil && f.StreamError != nil {
		return nil, errors.New("a fault has an error or a streamError, not both")
	}
	if f.Error != nil {
		if err := f.Error.validate(); err != nil {
			return nil, err
		}
	}
	if f.StreamError != nil {
		if err := f.StreamError.validate(); err != nil {
			return nil, err
		}
	}
	return f, nil
}

// ---- model ids

var bdProfileRegions = map[string]bool{"us": true, "eu": true, "apac": true, "us-gov": true, "global": true, "jp": true, "au": true, "ca": true}

// bdBaseID is the model id without the inference profile's region prefix and without an ARN: `us.anthropic.claude-3-5-sonnet-20241022-v2:0`
// and `arn:aws:bedrock:us-east-1:123456789012:inference-profile/us.anthropic.claude-3-5-sonnet-20241022-v2:0` are both
// `anthropic.claude-3-5-sonnet-20241022-v2:0`.
func bdBaseID(id string) string {
	if strings.HasPrefix(id, "arn:") {
		if i := strings.LastIndex(id, "/"); i >= 0 {
			id = id[i+1:]
		}
	}
	if i := strings.IndexByte(id, '.'); i > 0 && bdProfileRegions[id[:i]] {
		rest := id[i+1:]
		if j := strings.IndexByte(rest, '.'); j > 0 {
			return rest
		}
	}
	return id
}

// setRank orders the sets that apply to a model id: exact id first, then the longest prefix, then every model.
func (s *bdSet) rank(id, base string) (int, bool) {
	switch {
	case s.ModelID != "":
		if s.ModelID == id || s.ModelID == base {
			return 1 << 20, true
		}
	case s.ModelPrefix != "":
		if strings.HasPrefix(id, s.ModelPrefix) || strings.HasPrefix(base, s.ModelPrefix) {
			return 1<<10 + len(s.ModelPrefix), true
		}
	default:
		return 0, true
	}
	return 0, false
}

func bdSetsFor(sets map[string]*bdSet, id, base string) []*bdSet {
	type ranked struct {
		s *bdSet
		r int
	}
	var rs []ranked
	for _, s := range sets {
		if r, ok := s.rank(id, base); ok {
			rs = append(rs, ranked{s, r})
		}
	}
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].r != rs[j].r {
			return rs[i].r > rs[j].r
		}
		return rs[i].s.Name < rs[j].s.Name
	})
	out := make([]*bdSet, len(rs))
	for i, r := range rs {
		out[i] = r.s
	}
	return out
}

func (f *bdFault) applies(id, base, op string) bool {
	if f.Operation != "" && f.Operation != op {
		return false
	}
	switch {
	case f.ModelID != "":
		return f.ModelID == id || f.ModelID == base
	case f.ModelPrefix != "":
		return strings.HasPrefix(id, f.ModelPrefix) || strings.HasPrefix(base, f.ModelPrefix)
	}
	return true
}

// ---- matching

func (m *bdMatch) matches(q *bdReq) bool {
	if m.Operation != "" && m.Operation != q.op {
		return false
	}
	if m.TextContains != "" && !strings.Contains(q.text, m.TextContains) {
		return false
	}
	if m.TextEquals != nil && *m.TextEquals != q.text {
		return false
	}
	if m.textRe != nil && !m.textRe.MatchString(q.text) {
		return false
	}
	if m.SystemContains != "" && !strings.Contains(q.system, m.SystemContains) {
		return false
	}
	if m.ToolOffered != "" {
		found := false
		for _, t := range q.tools {
			found = found || t == m.ToolOffered
		}
		if !found {
			return false
		}
	}
	if m.ToolResult != nil && *m.ToolResult != q.toolResult {
		return false
	}
	if m.ToolResultContains != "" && !strings.Contains(q.toolResultText, m.ToolResultContains) {
		return false
	}
	if m.toolResRe != nil && !m.toolResRe.MatchString(q.toolResultText) {
		return false
	}
	if m.Guardrail != nil && *m.Guardrail != q.guardrail {
		return false
	}
	if m.GuardrailID != "" && m.GuardrailID != q.guardrailID {
		return false
	}
	if m.GuardrailSource != "" && m.GuardrailSource != q.guardrailSource {
		return false
	}
	if m.BodyContains != "" && !bytes.Contains(q.body, []byte(m.BodyContains)) {
		return false
	}
	if m.JSONPath != "" {
		var v any
		found := false
		if q.docOK {
			v, found = evalJSONPath(q.doc, m.path)
		}
		if m.Exists != nil && *m.Exists != found {
			return false
		}
		if m.hasWant && !(found && jsonValuesEqual(m.want, v)) {
			return false
		}
		if m.valueRe != nil && !(found && m.valueRe.MatchString(jsonScalarText(v))) {
			return false
		}
	}
	return true
}

// claim uses up one turn of a rule; false when its `times` is spent. The caller holds the state's lock.
func (r *bdRule) claim() bool {
	if r.Times > 0 && r.used >= r.Times {
		return false
	}
	r.used++
	return true
}

type bdPick int

const (
	bdNone bdPick = iota
	bdRuleHit
	bdQueueHit
	bdDefaultHit
)

// queueOrDefault is the next queued answer, else the default, else nothing. The caller holds the state's lock.
func (s *bdSet) queueOrDefault() (*bdResponse, bdPick) {
	if len(s.Queue) > 0 {
		r := s.Queue[0]
		s.Queue = s.Queue[1:]
		return r, bdQueueHit
	}
	if s.Default != nil {
		return s.Default, bdDefaultHit
	}
	return nil, bdNone
}

// bdTokens is the made-up token count of a text: about four characters a token, at least one for any text. Always labelled fake.
func bdTokens(s string) int {
	n := (utf8.RuneCountInString(s) + 3) / 4
	if n == 0 && s != "" {
		n = 1
	}
	return n
}
