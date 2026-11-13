package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// The Bedrock runtime operations the front answers (see bedrock.go for why). The wire shapes are botocore's model of bedrock-runtime
// (restJson1): the model id is in the path, Converse and ConverseStream take a JSON body, InvokeModel takes the provider's own JSON body and
// the Content-Type and guardrail headers, a stream is application/vnd.amazon.eventstream (ConverseStream: one event type per piece;
// InvokeModelWithResponseStream: `chunk` events whose `bytes` hold the provider's chunk), and an error is JSON with a `message` and the
// code in X-Amzn-ErrorType (botocore reads it from there), the same code as an exception event inside a stream.

const (
	bdMaxBodyBytes = 8 << 20 // the largest request body read (an image in a Converse request is the usual large one)
	// a body with no Content-Length (chunked) is read up to this much: the SDKs always send a length
	bdMaxUnsizedBody = 1 << 20
	// the most JSON values (members and elements) a request may hold: each costs about thirty times its size once decoded, so a body of
	// `{},{},...` is refused by this, not by its size. Real requests hold a few thousand.
	bdMaxJSONValues = 200000
	// an embedding request holds at most this many texts or images (Cohere Embed's own limit)
	bdMaxEmbedInputs = 96
	// and its answer at most this many numbers (texts times dimensions)
	bdMaxEmbedNumbers = 131072
)

// bdBodyReadTimeout is how long a request may take to send its body: a slow sender holds its share of the body budget meanwhile.
var bdBodyReadTimeout = 30 * time.Second

var bdModelIDRe = regexp.MustCompile(`^[A-Za-z0-9:._/-]+$`)

// bdOps are the operations of the route key bedrock-runtime the front answers.
var bdOps = map[string]bool{"Converse": true, "ConverseStream": true, "InvokeModel": true, "InvokeModelWithResponseStream": true,
	"CountTokens": true, "ApplyGuardrail": true}

// bdReq is one request, read once: what a rule may match on, and what the answer's made-up token counts are taken from.
type bdReq struct {
	op, id, base, family string
	body                 []byte
	sha                  string
	doc                  any // the request body (or, for CountTokens, the body inside it) as JSON
	docOK                bool
	text                 string // the last user message's text (or the prompt)
	system               string
	toolResultText       string
	toolResult           bool
	tools                []string
	texts                []string // an embedding request's texts
	inputs               int      // an embedding request's texts and images
	allText              string   // every text the request holds, for the made-up input token count
	guardrail            bool
	guardrailID          string
	guardrailVersion     string
	guardrailSource      string
	trace                bool
}

// ---- errors

func bdDefaultMessage(code string) string {
	switch code {
	case "ThrottlingException":
		return "Too many requests, please wait before trying again."
	case "ModelTimeoutException":
		return "The request took too long to process. Processing time exceeded the model timeout length."
	case "ModelNotReadyException":
		return "The model is not ready yet. Wait and try again."
	case "ModelErrorException":
		return "The model produced an invalid response. Try again."
	case "ServiceUnavailableException":
		return "The service is temporarily unavailable. Try again later."
	case "InternalServerException":
		return "An internal server error occurred. Retry your request."
	case "AccessDeniedException":
		return "You don't have access to the model with the specified model ID."
	case "ResourceNotFoundException":
		return "The specified resource could not be found."
	case "ServiceQuotaExceededException":
		return "The service quota for this model was exceeded."
	}
	return "Rovara: this answer is a canned error."
}

// writeBDError writes a bedrock-runtime error: the HTTP status from the code, JSON body with `message`, the code in X-Amzn-ErrorType.
func writeBDError(w http.ResponseWriter, e *bdErrorSpec) int {
	status := bdErrorStatus[e.Code]
	msg := e.Message
	if msg == "" {
		msg = bdDefaultMessage(e.Code)
	}
	body := map[string]any{"message": msg}
	if e.Code == "ModelErrorException" && e.OriginalStatusCode != 0 {
		body["originalStatusCode"] = e.OriginalStatusCode
	}
	b, _ := json.Marshal(body)
	h := w.Header()
	h.Set("X-Amzn-Errortype", e.Code)
	h["x-amzn-RequestId"] = []string{newUUID()}
	writeBody(w, status, "application/json", b)
	return status
}

func bdValidation(msg string) *bdErrorSpec {
	return &bdErrorSpec{Code: "ValidationException", Message: msg}
}

// ---- reading the request

// bdTextOf reads the text of one content block of any family: a string, {"text"}, {"type":"text","text"}; a tool result's content of
// either spelling (Converse's {"toolResult":{"content":[{"text"}|{"json"}]}}, Anthropic's {"type":"tool_result","content": string|[...]}).
func bdTextOf(block any) (text, toolRes string, isToolRes bool) {
	switch b := block.(type) {
	case string:
		return b, "", false
	case map[string]any:
		if t, ok := b["text"].(string); ok {
			return t, "", false
		}
		if tr, ok := b["toolResult"].(map[string]any); ok {
			return "", bdToolContent(tr["content"]), true
		}
		if b["type"] == "tool_result" {
			return "", bdToolContent(b["content"]), true
		}
	}
	return "", "", false
}

func bdToolContent(v any) string {
	switch c := v.(type) {
	case string:
		return c
	case []any:
		var parts []string
		for _, e := range c {
			switch m := e.(type) {
			case map[string]any:
				if t, ok := m["text"].(string); ok {
					parts = append(parts, t)
				} else if j, ok := m["json"]; ok {
					b, _ := json.Marshal(j)
					parts = append(parts, string(b))
				}
			case string:
				parts = append(parts, m)
			}
		}
		return strings.Join(parts, "\n")
	}
	return ""
}

// readConversation fills the request from a body of any family: messages (Converse, Nova, Anthropic, Mistral chat), a prompt (Titan,
// Llama, Mistral, Anthropic text), a message (Cohere chat), the system prompt and the tools.
func (q *bdReq) readConversation(doc any) {
	m, ok := doc.(map[string]any)
	if !ok {
		return
	}
	var all []string
	if msgs, ok := m["messages"].([]any); ok {
		var last map[string]any
		for _, e := range msgs {
			msg, _ := e.(map[string]any)
			if msg == nil {
				continue
			}
			var texts, results []string
			isRes := false
			switch c := msg["content"].(type) {
			case string:
				texts = append(texts, c)
			case []any:
				for _, blk := range c {
					t, tr, res := bdTextOf(blk)
					if t != "" {
						texts = append(texts, t)
					}
					if res {
						isRes = true
						results = append(results, tr)
					}
				}
			}
			all = append(all, texts...)
			all = append(all, results...)
			if msg["role"] == "user" || msg["role"] == nil {
				last = map[string]any{"text": strings.Join(texts, "\n"), "result": strings.Join(results, "\n"), "isResult": isRes}
			}
		}
		if last != nil {
			q.text, q.toolResultText, q.toolResult = last["text"].(string), last["result"].(string), last["isResult"].(bool)
		}
	}
	for _, k := range []string{"prompt", "inputText", "message", "input"} {
		if t, ok := m[k].(string); ok {
			all = append(all, t)
			if q.text == "" {
				q.text = t
			}
		}
	}
	if is, ok := m["images"].([]any); ok {
		q.inputs += len(is)
	}
	if ts, ok := m["texts"].([]any); ok {
		q.inputs += len(ts)
		for _, e := range ts {
			if t, ok := e.(string); ok && len(q.texts) <= bdMaxEmbedInputs {
				q.texts = append(q.texts, t)
				all = append(all, t)
			}
		}
		if q.text == "" {
			q.text = strings.Join(q.texts, "\n")
		}
	}
	switch s := m["system"].(type) {
	case string:
		q.system = s
	case []any:
		var parts []string
		for _, e := range s {
			if t, _, _ := bdTextOf(e); t != "" {
				parts = append(parts, t)
			}
		}
		q.system = strings.Join(parts, "\n")
	}
	if q.system != "" {
		all = append(all, q.system)
	}
	// the tools offered: Converse's toolConfig.tools[].toolSpec.name, Anthropic's tools[].name
	var tools []any
	if tc, ok := m["toolConfig"].(map[string]any); ok {
		tools, _ = tc["tools"].([]any)
	} else if ts, ok := m["tools"].([]any); ok {
		tools = ts
	}
	for _, e := range tools {
		t, _ := e.(map[string]any)
		if spec, ok := t["toolSpec"].(map[string]any); ok {
			t = spec
		}
		if n, ok := t["name"].(string); ok {
			q.tools = append(q.tools, n)
		}
	}
	q.allText = strings.Join(all, "\n")
}

// bdJSONValues counts the members and elements of a JSON text (its commas, colons and openers outside strings), without decoding it.
func bdJSONValues(b []byte) int {
	n := 0
	inStr, esc := false, false
	for _, c := range b {
		switch {
		case inStr && esc:
			esc = false
		case inStr && c == '\\':
			esc = true
		case inStr:
			inStr = c != '"'
		case c == '"':
			inStr = true
		case c == '{' || c == '[' || c == ',' || c == ':':
			n++
		}
	}
	return n
}

func bdDecode(b []byte) (any, bool) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, false
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, false
	}
	return normalizeJSON(v), true
}

// bdParse reads a request. It returns a ValidationException for a body the real service would refuse.
func bdParse(op, modelOrGuardrail string, r *http.Request, body []byte, gv string) (*bdReq, *bdErrorSpec) {
	q := &bdReq{op: op, body: body}
	sum := sha256.Sum256(body)
	q.sha = hex.EncodeToString(sum[:])
	q.doc, q.docOK = bdDecode(body)
	if op == bdOpApply {
		q.guardrail, q.guardrailID, q.guardrailVersion = true, modelOrGuardrail, gv
		m, ok := q.doc.(map[string]any)
		if !ok {
			return q, bdValidation("The request body is not a JSON object.")
		}
		q.guardrailSource, _ = m["source"].(string)
		if q.guardrailSource != "INPUT" && q.guardrailSource != "OUTPUT" {
			return q, bdValidation("1 validation error detected: Value '" + q.guardrailSource + "' at 'source' failed to satisfy constraint: Member must satisfy enum value set: [INPUT, OUTPUT]")
		}
		content, _ := m["content"].([]any)
		if len(content) == 0 {
			return q, bdValidation("1 validation error detected: Value '[]' at 'content' failed to satisfy constraint: Member must have length greater than or equal to 1")
		}
		var texts []string
		for _, c := range content {
			if cm, ok := c.(map[string]any); ok {
				if tm, ok := cm["text"].(map[string]any); ok {
					if t, ok := tm["text"].(string); ok {
						texts = append(texts, t)
					}
				}
			}
		}
		q.text = strings.Join(texts, "\n")
		q.allText = q.text
		return q, nil
	}
	q.id = modelOrGuardrail
	q.base = bdBaseID(q.id)
	if len(q.id) > 2048 || !bdModelIDRe.MatchString(q.id) {
		return q, bdValidation("The provided model identifier is invalid.")
	}
	switch op {
	case bdOpConverse, bdOpConverseStr:
		m, ok := q.doc.(map[string]any)
		if !ok {
			return q, bdValidation("The request body is not a JSON object.")
		}
		if err := bdCheckConverse(m); err != nil {
			return q, err
		}
		q.readConversation(m)
		if gc, ok := m["guardrailConfig"].(map[string]any); ok {
			q.guardrail = true
			q.guardrailID, _ = gc["guardrailIdentifier"].(string)
			q.guardrailVersion, _ = gc["guardrailVersion"].(string)
			tr, _ := gc["trace"].(string)
			q.trace = tr == "enabled" || tr == "enabled_full"
		}
	case bdOpInvoke, bdOpInvokeStream:
		if _, ok := q.doc.(map[string]any); !ok {
			return q, bdValidation("Malformed input request, please reformat your input and try again.")
		}
		q.readConversation(q.doc)
		if id := r.Header.Get("X-Amzn-Bedrock-GuardrailIdentifier"); id != "" {
			q.guardrail, q.guardrailID, q.guardrailVersion = true, id, r.Header.Get("X-Amzn-Bedrock-GuardrailVersion")
		}
		tr := strings.ToUpper(r.Header.Get("X-Amzn-Bedrock-Trace"))
		q.trace = tr == "ENABLED" || tr == "ENABLED_FULL"
	case bdOpCount:
		m, ok := q.doc.(map[string]any)
		in, _ := m["input"].(map[string]any)
		if !ok || in == nil {
			return q, bdValidation("1 validation error detected: Value null at 'input' failed to satisfy constraint: Member must not be null")
		}
		if conv, ok := in["converse"].(map[string]any); ok {
			q.doc = conv
			q.readConversation(conv)
		} else if inv, ok := in["invokeModel"].(map[string]any); ok {
			raw, _ := inv["body"].(string)
			dec, err := base64.StdEncoding.DecodeString(raw)
			if err != nil {
				return q, bdValidation("The invokeModel body is not base64.")
			}
			q.doc, q.docOK = bdDecode(dec)
			q.readConversation(q.doc)
		} else {
			return q, bdValidation("The input must hold either converse or invokeModel.")
		}
	}
	q.family = bdFamily(q.base, q.doc)
	if q.family == "cohere-embed" && q.inputs > bdMaxEmbedInputs {
		return q, bdValidation(fmt.Sprintf("Malformed input request: #/texts: expected maxItems: %d, found: %d, please reformat your input and try again.", bdMaxEmbedInputs, q.inputs))
	}
	return q, nil
}

// bdCheckConverse refuses a conversation Bedrock refuses.
func bdCheckConverse(m map[string]any) *bdErrorSpec {
	msgs, _ := m["messages"].([]any)
	if len(msgs) == 0 {
		return bdValidation("1 validation error detected: Value '[]' at 'messages' failed to satisfy constraint: Member must have length greater than or equal to 1")
	}
	prev := ""
	for i, e := range msgs {
		msg, _ := e.(map[string]any)
		role, _ := msg["role"].(string)
		content, _ := msg["content"].([]any)
		if role != "user" && role != "assistant" {
			return bdValidation(fmt.Sprintf("1 validation error detected: Value '%s' at 'messages.%d.member.role' failed to satisfy constraint: Member must satisfy enum value set: [user, assistant]", role, i+1))
		}
		if len(content) == 0 {
			return bdValidation(fmt.Sprintf("1 validation error detected: Value '[]' at 'messages.%d.member.content' failed to satisfy constraint: Member must have length greater than or equal to 1", i+1))
		}
		if i == 0 && role != "user" {
			return bdValidation("A conversation must start with a user message. Try again with a conversation that starts with a user message.")
		}
		if role == prev {
			return bdValidation("A conversation must alternate between user and assistant roles. Make sure the conversation alternates between user and assistant roles and try again.")
		}
		prev = role
	}
	return nil
}

// ---- the entry point

func bdMarker(parts ...string) string { return strings.Join(append([]string{"faked"}, parts...), "; ") }

// serveBedrock answers one of the six operations. It runs inside Server.api, after the plan check.
func (s *Server) serveBedrock(w http.ResponseWriter, r *http.Request, id identified, entry *ledgerEntry, done func(int, bool)) {
	start := time.Now()
	op := bdOpByName[id.Operation]
	segs := splitPath(r.URL.EscapedPath())
	name, version := "", ""
	if op == bdOpApply {
		if len(segs) >= 4 {
			name, _ = url.PathUnescape(segs[1])
			version, _ = url.PathUnescape(segs[3])
		}
	} else if len(segs) >= 2 {
		name, _ = url.PathUnescape(segs[1])
	}
	statKey := name
	if op == bdOpApply {
		statKey = "(guardrail " + name + ")"
	}
	m := s.bd
	fail := func(e *bdErrorSpec, qualifiers ...string) {
		s.ledger.mark(entry, bdMarker(qualifiers...))
		done(writeBDError(w, e), false)
	}
	count := func(f func(st *bdStats)) {
		m.mu.Lock()
		f(m.statsFor(statKey))
		m.mu.Unlock()
	}
	// the body is read within the memory budget: what the request says it holds (at most the largest body; a body with no length, a
	// smaller one), at what the body costs while it is answered. A request that finds the budget used up is throttled at once (the SDKs
	// retry it) instead of waiting, and a sender that is slower than bdBodyReadTimeout is cut off, so neither holds the budget.
	limit := r.ContentLength
	switch {
	case limit < 0:
		limit = bdMaxUnsizedBody
	case limit < 4096:
		limit = 4096
	case limit > bdMaxBodyBytes+1:
		limit = bdMaxBodyBytes + 1
	}
	hold := limit * bdBodyCost
	if !m.bodies.tryAcquire(hold) {
		count(func(st *bdStats) { st.Calls++; st.Errors++ })
		fail(&bdErrorSpec{Code: "ThrottlingException", Message: "Rovara: too many large requests are being answered at once. Retry the request."}, "throttled")
		return
	}
	defer m.bodies.release(hold)
	rc := http.NewResponseController(w)
	rc.SetReadDeadline(time.Now().Add(bdBodyReadTimeout))
	body, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	rc.SetReadDeadline(time.Time{})
	if err != nil {
		count(func(st *bdStats) { st.Calls++; st.Errors++ })
		fail(bdValidation("The request body could not be read."))
		return
	}
	if int64(len(body)) > limit || len(body) > bdMaxBodyBytes || bdJSONValues(body) > bdMaxJSONValues {
		count(func(st *bdStats) { st.Calls++; st.Errors++ })
		fail(bdValidation("Input is too long for requested model."))
		return
	}
	q, verr := bdParse(op, name, r, body, version)
	if verr != nil {
		count(func(st *bdStats) { st.Calls++; st.Errors++ })
		fail(verr)
		return
	}

	res := s.bdProduce(r.Context(), q)
	count(func(st *bdStats) {
		st.Calls++
		switch op {
		case bdOpCount:
			st.CountTokens++
		case bdOpApply:
			st.ApplyGuardrail++
		}
		if bdIsStream(op) {
			st.Streamed++
		}
		if res.faulted {
			st.Faulted++
		}
		switch {
		case res.unmatched:
			st.Unmatched++
		case res.kind == bdDefaultHit:
			st.MadeUp++
		case res.kind != bdNone:
			st.Matched++
		}
		if res.estimated {
			st.Estimated++
		}
		if res.unmatched {
			st.Last = append(st.Last, bdUnmatched{Operation: op, Bytes: len(q.body), SHA256: q.sha})
			if len(st.Last) > bdMaxLast {
				st.Last = st.Last[len(st.Last)-bdMaxLast:]
			}
		}
	})
	var qual []string
	if res.faulted {
		qual = append(qual, "fault")
	}
	switch {
	case res.unmatched:
		qual = append(qual, "unmatched")
	case res.kind == bdDefaultHit:
		qual = append(qual, "made-up answer")
	}
	if res.estimated {
		qual = append(qual, "estimated")
	}
	if res.cancelled {
		fail(&bdErrorSpec{Code: "InternalServerException", Message: "The request was cancelled."}, qual...)
		count(func(st *bdStats) { st.Errors++ })
		return
	}
	if res.err != nil {
		count(func(st *bdStats) { st.Errors++ })
		fail(res.err, qual...)
		return
	}
	resp := res.resp
	ans := bdCompose(q, resp, start)
	if ans.toolUse {
		count(func(st *bdStats) { st.ToolUseTurns++ })
	}
	if ans.intervened {
		count(func(st *bdStats) { st.GuardrailIntervened++ })
		qual = append(qual, "guardrail intervened")
	}
	// an answer of the wrong kind for the operation (rawChunks only, for a call that is not a stream, and so on)
	if bad := bdWrongKind(q, resp); bad != "" {
		count(func(st *bdStats) { st.Errors++ })
		fail(bdValidation("Rovara: the answer that matched this request "+bad), append(qual, "wrong kind of answer")...)
		return
	}
	s.ledger.mark(entry, bdMarker(qual...))
	switch q.op {
	case bdOpConverse:
		b := bdConverseBody(q, ans)
		bdWriteJSON(w, b, "")
		done(http.StatusOK, false)
	case bdOpCount:
		b, _ := json.Marshal(map[string]any{"inputTokens": ans.in})
		bdWriteJSON(w, b, "")
		done(http.StatusOK, false)
	case bdOpApply:
		b, err := bdApplyBody(q, resp, ans)
		if err != nil {
			count(func(st *bdStats) { st.Errors++ })
			fail(bdValidation("Rovara: "+err.Error()), "wrong kind of answer")
			return
		}
		bdWriteJSON(w, b, "")
		done(http.StatusOK, false)
	case bdOpInvoke:
		b, err := bdInvokeBody(q, resp, ans)
		if err != nil {
			count(func(st *bdStats) { st.Errors++ })
			fail(bdValidation("Rovara: "+err.Error()), "wrong kind of answer")
			return
		}
		h := w.Header()
		h["X-Amzn-Bedrock-Input-Token-Count"] = []string{itoa(ans.in)}
		h["X-Amzn-Bedrock-Output-Token-Count"] = []string{itoa(ans.out)}
		h["X-Amzn-Bedrock-Invocation-Latency"] = []string{itoa(ans.latency)}
		bdWriteJSON(w, b, "")
		done(http.StatusOK, false)
	case bdOpConverseStr, bdOpInvokeStream:
		var events []bdEvent
		var hdr map[string]string
		if q.op == bdOpConverseStr {
			events = bdConverseEvents(q, resp, ans)
		} else {
			evs, err := bdInvokeEvents(q, resp, ans)
			if err != nil {
				count(func(st *bdStats) { st.Errors++ })
				fail(bdValidation("Rovara: "+err.Error()), "wrong kind of answer")
				return
			}
			events = evs
			hdr = map[string]string{"X-Amzn-Bedrock-Content-Type": "application/json"}
		}
		s.bdWriteStream(w, r, q, events, resp, hdr)
		done(http.StatusOK, false)
	}
}

func bdWriteJSON(w http.ResponseWriter, b []byte, ctype string) {
	if ctype == "" {
		ctype = "application/json"
	}
	w.Header()["x-amzn-RequestId"] = []string{newUUID()}
	writeBody(w, http.StatusOK, ctype, b)
}

// bdWrongKind says why an answer cannot answer this operation, or "" when it can.
func bdWrongKind(q *bdReq, resp *bdResponse) string {
	switch q.op {
	case bdOpInvoke:
		if len(resp.RawChunks) > 0 {
			return "has rawChunks only, which answer InvokeModelWithResponseStream"
		}
	case bdOpConverse, bdOpConverseStr:
		if len(resp.Raw) > 0 || len(resp.RawChunks) > 0 || resp.Embedding != nil {
			return "is a raw provider body or an embedding, which answers InvokeModel, not Converse"
		}
	case bdOpCount, bdOpApply:
	}
	return ""
}

// ---- producing the answer

type bdResult struct {
	resp      *bdResponse
	kind      bdPick
	err       *bdErrorSpec
	unmatched bool
	faulted   bool
	estimated bool
	cancelled bool
}

// bdProduce chooses the answer to a request and uses it up (a fault's turn, a rule's `times`, a queue entry). Armed faults come first.
// CountTokens and ApplyGuardrail use only rules that name their operation, never a queue or a default: they must not use up the answers
// meant for the calls that make text.
func (s *Server) bdProduce(ctx context.Context, q *bdReq) *bdResult {
	m := s.bd
	res := &bdResult{}
	generative := q.op != bdOpCount && q.op != bdOpApply

	var fault *bdFault
	m.mu.Lock()
	for _, f := range m.faults {
		if !f.applies(q.id, q.base, q.op) {
			continue
		}
		if f.StreamError != nil && !bdIsStream(q.op) {
			continue // a stream fault waits for a stream
		}
		f.seen++
		if f.seen <= f.Skip || f.used >= f.Times {
			continue
		}
		f.used++
		fault = f
		break
	}
	sets := bdSetsFor(m.sets, q.id, q.base)
	m.mu.Unlock()

	if fault != nil {
		res.faulted = fault.Error != nil || fault.StreamError != nil
		if fault.DelayMs > 0 && !sleepCtx(ctx, time.Duration(fault.DelayMs)*time.Millisecond) {
			res.cancelled = true
			return res
		}
		if fault.Error != nil {
			e := *fault.Error
			res.err = &e
			return res
		}
	}

	var resp *bdResponse
	var kind bdPick
	for _, set := range sets {
		for _, r := range set.Rules {
			if !bdRuleApplies(r, q) || !r.Match.matches(q) {
				continue
			}
			m.mu.Lock()
			ok := r.claim()
			m.mu.Unlock()
			if ok {
				resp, kind = &r.Response, bdRuleHit
				break
			}
		}
		if resp == nil && generative {
			m.mu.Lock()
			resp, kind = set.queueOrDefault()
			m.mu.Unlock()
		}
		if resp != nil {
			break
		}
	}
	switch {
	case resp == nil && q.op == bdOpCount:
		// an estimate: CountTokens is never refused for want of a rule
		res.estimated = true
		res.resp = &bdResponse{Usage: &bdUsage{}}
	case resp == nil:
		res.unmatched = true
		what, hint := "model "+q.id, ""
		if q.op == bdOpApply {
			what, hint = "guardrail "+q.guardrailID, " (ApplyGuardrail names no model: its rules go in a fixture set with no modelId and no modelPrefix)"
		}
		res.err = bdValidation(fmt.Sprintf("Rovara: no recorded or canned answer matches this request to %s (%s, %d bytes, sha256 %s). Add a Bedrock fixture for it%s.",
			what, q.op, len(q.body), q.sha, hint))
	default:
		res.resp, res.kind = resp, kind
	}
	if res.resp == nil {
		return res
	}
	if res.resp.DelayMs > 0 && !sleepCtx(ctx, time.Duration(res.resp.DelayMs)*time.Millisecond) {
		res.cancelled = true
		return res
	}
	if e := res.resp.Error; e != nil {
		c := *e
		res.err = &c
		res.faulted = true
		return res
	}
	if fault != nil && fault.StreamError != nil {
		cp := *res.resp
		cp.StreamError = fault.StreamError
		res.resp = &cp
	}
	return res
}

// bdRuleApplies: CountTokens and ApplyGuardrail are answered only by rules that name them.
func bdRuleApplies(r *bdRule, q *bdReq) bool {
	if q.op == bdOpCount || q.op == bdOpApply {
		return r.Match.Operation == q.op
	}
	return true
}
