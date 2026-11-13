package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strings"
	"time"
)

// The shapes of the answers: Converse's, and the provider bodies of InvokeModel for each model family. An answer (a bdResponse) is one
// logical answer; these functions write it in the shape each operation and each family has. The families are told by the model id
// (without the inference profile's region prefix or the ARN) and, for a few, by the request body:
//
//	anthropic       anthropic.*  the messages API (a body with `messages`), tool_use blocks
//	anthropic-text  anthropic.*  the old text completion API (a body with `prompt`, no `messages`)
//	nova            amazon.nova* Converse's own shape inside InvokeModel (schemaVersion messages-v1), toolUse blocks
//	titan           amazon.titan-text*
//	titan-embed     amazon.titan-embed*  (an `embedding` answer)
//	llama           meta.*
//	mistral         mistral.*    outputs (a body with `prompt`), choices (a body with `messages`)
//	cohere-text     cohere.*     generations; cohere-chat: a body with `message`; cohere-embed: *embed* models
//	generic         every other model id: {"outputText","stopReason"}. A model whose shape the front does not know should be answered with `raw`.
//
// Tool use is carried by anthropic and nova only; the other families get the text of the answer.

func bdFamily(base string, doc any) string {
	m, _ := doc.(map[string]any)
	has := func(k string) bool { _, ok := m[k]; return ok }
	switch {
	case strings.HasPrefix(base, "anthropic."):
		if !has("messages") && has("prompt") {
			return "anthropic-text"
		}
		return "anthropic"
	case strings.HasPrefix(base, "amazon.nova") && strings.Contains(base, "embed"):
		return "nova-embed"
	case strings.HasPrefix(base, "amazon.nova"):
		return "nova"
	case strings.HasPrefix(base, "amazon.titan-embed"):
		return "titan-embed"
	case strings.HasPrefix(base, "amazon.titan-text"):
		return "titan"
	case strings.HasPrefix(base, "meta."):
		return "llama"
	case strings.HasPrefix(base, "mistral."):
		if has("messages") {
			return "mistral-chat"
		}
		return "mistral"
	case strings.HasPrefix(base, "cohere."):
		switch {
		case strings.Contains(base, "embed"):
			return "cohere-embed"
		case has("message"):
			return "cohere-chat"
		}
		return "cohere-text"
	}
	return "generic"
}

// ---- the composed answer

type bdAnswer struct {
	blocks     []bdBlock
	stop       string
	in, out    int
	latency    int
	toolUse    bool
	intervened bool
	trace      map[string]any // Converse's `trace`, {"guardrail": {...}}
	additional json.RawMessage
	text       string // the text blocks, joined
	guardrail  *bdGuardrail
}

const bdBlockedDefault = "Sorry, the model cannot answer this question."

// bdCompose takes an answer and a request and settles what the caller sees: the blocks (a guardrail that intervened replaces them with
// its blocked message), the stop reason, the made-up token counts and the guardrail trace.
func bdCompose(q *bdReq, resp *bdResponse, start time.Time) *bdAnswer {
	a := &bdAnswer{blocks: resp.blocks, additional: resp.Additional}
	if g := resp.Guardrail; g != nil && q.guardrail && q.op != bdOpApply {
		a.guardrail = g
		if g.Action == "GUARDRAIL_INTERVENED" {
			a.intervened = true
			msg := g.BlockedMessage
			if msg == "" {
				msg = bdBlockedDefault
			}
			a.blocks = []bdBlock{{kind: "text", text: msg}}
		}
		if q.trace && (a.intervened || len(g.Assessments) > 0) {
			a.trace = bdGuardrailTrace(q, g)
		}
	}
	if len(a.blocks) == 0 {
		a.blocks = []bdBlock{{kind: "text", text: ""}}
	}
	var texts []string
	outToks := 0
	for _, b := range a.blocks {
		switch b.kind {
		case "text":
			texts = append(texts, b.text)
			outToks += bdTokens(b.text)
		case "toolUse":
			a.toolUse = a.toolUse || !a.intervened
			outToks += bdTokens(b.name) + bdTokens(string(b.input))
		}
	}
	a.text = strings.Join(texts, "")
	a.stop = resp.StopReason
	if a.stop == "" {
		a.stop = "end_turn"
		if a.toolUse {
			a.stop = "tool_use"
		}
	}
	if a.intervened {
		a.stop = "guardrail_intervened"
	}
	a.in, a.out = bdTokens(q.allText), outToks
	if u := resp.Usage; u != nil {
		if u.InputTokens != nil {
			a.in = *u.InputTokens
		}
		if u.OutputTokens != nil {
			a.out = *u.OutputTokens
		}
	}
	a.latency = int(time.Since(start).Milliseconds())
	if a.latency < 1 {
		a.latency = 1
	}
	if resp.LatencyMs != nil {
		a.latency = *resp.LatencyMs
	}
	return a
}

// bdGuardrailTrace is Converse's `trace.guardrail`: the assessment under the guardrail's id, as the input's or the output's.
func bdGuardrailTrace(q *bdReq, g *bdGuardrail) map[string]any {
	var obj any = map[string]any{}
	arr := []any{}
	if len(g.Assessments) > 0 {
		var v any
		json.Unmarshal(g.Assessments, &v)
		switch t := v.(type) {
		case map[string]any:
			obj, arr = t, []any{t}
		case []any:
			arr = t
			if len(t) > 0 {
				obj = t[0]
			}
		}
	}
	gid := q.guardrailID
	if gid == "" {
		gid = "guardrail"
	}
	tr := map[string]any{}
	if g.Phase == "output" {
		tr["outputAssessments"] = map[string]any{gid: arr}
	} else {
		tr["inputAssessment"] = map[string]any{gid: obj}
	}
	return map[string]any{"guardrail": tr}
}

func bdUsageDoc(a *bdAnswer) map[string]any {
	return map[string]any{"inputTokens": a.in, "outputTokens": a.out, "totalTokens": a.in + a.out}
}

func bdMetrics(a *bdAnswer) map[string]any {
	return map[string]any{"inputTokenCount": a.in, "outputTokenCount": a.out, "invocationLatency": a.latency, "firstByteLatency": a.latency/2 + 1}
}

// ---- Converse

func bdConverseBlock(b bdBlock) any {
	switch b.kind {
	case "toolUse":
		return map[string]any{"toolUse": map[string]any{"toolUseId": b.id, "name": b.name, "input": json.RawMessage(b.input)}}
	case "other":
		return json.RawMessage(b.raw)
	}
	return map[string]any{"text": b.text}
}

func bdConverseBody(q *bdReq, a *bdAnswer) []byte {
	content := []any{}
	for _, b := range a.blocks {
		content = append(content, bdConverseBlock(b))
	}
	doc := map[string]any{
		"output":     map[string]any{"message": map[string]any{"role": "assistant", "content": content}},
		"stopReason": a.stop,
		"usage":      bdUsageDoc(a),
		"metrics":    map[string]any{"latencyMs": a.latency},
	}
	if a.trace != nil {
		doc["trace"] = a.trace
	}
	if len(a.additional) > 0 {
		doc["additionalModelResponseFields"] = a.additional
	}
	b, _ := json.Marshal(doc)
	return b
}

// ---- events (the pieces of a stream)

// bdEvent is one event of a stream; part marks the events that carry a piece of the answer (the ones a stream error counts and a delay
// separates).
type bdEvent struct {
	name    string // the event type: messageStart, chunk, ...
	payload []byte
	part    bool
}

func bdEv(name string, doc any, part bool) bdEvent {
	b, _ := json.Marshal(doc)
	return bdEvent{name: name, payload: b, part: part}
}

const bdDefaultChunk = 24

// bdTextParts is the pieces a text is streamed in.
func bdTextParts(resp *bdResponse, text string, first bool) []string {
	if first && len(resp.Parts) > 0 {
		return resp.Parts
	}
	if text == "" {
		return []string{""}
	}
	var out []string
	for _, p := range splitParts([]byte(text), bdChunkSize(resp)) {
		out = append(out, string(p))
	}
	return out
}

func bdChunkSize(r *bdResponse) int {
	if r.ChunkSize > 0 {
		return r.ChunkSize
	}
	return bdDefaultChunk
}

func bdConverseEvents(q *bdReq, resp *bdResponse, a *bdAnswer) []bdEvent {
	evs := []bdEvent{bdEv("messageStart", map[string]any{"role": "assistant"}, false)}
	idx := 0
	firstText := true
	for _, b := range a.blocks {
		switch b.kind {
		case "text":
			for _, p := range bdTextParts(resp, b.text, firstText && !a.intervened) {
				evs = append(evs, bdEv("contentBlockDelta", map[string]any{"contentBlockIndex": idx, "delta": map[string]any{"text": p}}, true))
			}
			firstText = false
		case "toolUse":
			evs = append(evs, bdEv("contentBlockStart", map[string]any{"contentBlockIndex": idx,
				"start": map[string]any{"toolUse": map[string]any{"toolUseId": b.id, "name": b.name}}}, false))
			for _, p := range bdTextParts(&bdResponse{ChunkSize: resp.ChunkSize}, string(b.input), false) {
				evs = append(evs, bdEv("contentBlockDelta", map[string]any{"contentBlockIndex": idx,
					"delta": map[string]any{"toolUse": map[string]any{"input": p}}}, true))
			}
		default:
			continue // a block with no stream form (reasoning, images) is left out of a stream
		}
		evs = append(evs, bdEv("contentBlockStop", map[string]any{"contentBlockIndex": idx}, false))
		idx++
	}
	stop := map[string]any{"stopReason": a.stop}
	if len(a.additional) > 0 {
		stop["additionalModelResponseFields"] = a.additional
	}
	evs = append(evs, bdEv("messageStop", stop, false))
	meta := map[string]any{"usage": bdUsageDoc(a), "metrics": map[string]any{"latencyMs": a.latency}}
	if a.trace != nil {
		meta["trace"] = a.trace
	}
	return append(evs, bdEv("metadata", meta, false))
}

// bdWriteStream writes the headers and the events of a stream, then, for an answer that ends in an error, the exception event. An
// exception event comes before the first event it follows `afterParts` pieces of (default: all pieces, before the closing events).
func (s *Server) bdWriteStream(w http.ResponseWriter, r *http.Request, q *bdReq, events []bdEvent, resp *bdResponse, hdr map[string]string) {
	h := w.Header()
	h.Set("Content-Type", eventStreamContentType)
	for k, v := range hdr {
		h[k] = []string{v}
	}
	h["x-amzn-RequestId"] = []string{newUUID()}
	w.WriteHeader(http.StatusOK)
	if fl, ok := w.(http.Flusher); ok {
		fl.Flush()
	}
	ew := newEventStreamWriter(w)
	defer ew.Close()
	total := 0
	for _, e := range events {
		if e.part {
			total++
		}
	}
	inj := resp.StreamError
	after := total
	if inj != nil && inj.AfterParts != nil {
		after = *inj.AfterParts
	}
	fire := func() {
		code := inj.Code
		doc := map[string]any{"message": inj.Message}
		if inj.Message == "" {
			doc["message"] = bdStreamDefault(code)
		}
		if q.op == bdOpConverseStr && code == "modelTimeoutException" {
			code = "modelStreamErrorException" // ConverseStream has no timeout event: the model's stream failed with the timeout's status
			doc["originalStatusCode"], doc["originalMessage"] = 408, doc["message"]
		}
		if code == "modelStreamErrorException" {
			if _, set := doc["originalStatusCode"]; !set {
				osc := inj.OriginalStatusCode
				if osc == 0 {
					osc = 500
				}
				om := inj.OriginalMessage
				if om == "" {
					om = "The model's stream ended with an error."
				}
				doc["originalStatusCode"], doc["originalMessage"] = osc, om
			}
		}
		b, _ := json.Marshal(doc)
		ew.Exception(code, "application/json", b)
	}
	written := 0
	for _, e := range events {
		if inj != nil {
			if e.part && written == after || !e.part && written >= total && after >= total {
				fire()
				return
			}
		}
		if e.part && written > 0 && resp.PartDelayMs > 0 && !sleepCtx(r.Context(), time.Duration(resp.PartDelayMs)*time.Millisecond) {
			return
		}
		if ew.Event(e.name, "application/json", e.payload) != nil {
			return
		}
		if e.part {
			written++
		}
	}
	if inj != nil && after > total {
		fire()
	}
}

func bdStreamDefault(code string) string {
	switch code {
	case "throttlingException":
		return "Too many requests, please wait before trying again."
	case "modelTimeoutException":
		return "The request took too long to process. Processing time exceeded the model timeout length."
	case "serviceUnavailableException":
		return "The service is temporarily unavailable. Try again later."
	case "internalServerException":
		return "An internal server error occurred. Retry your request."
	case "validationException":
		return "Rovara: this stream was told to end with a validation error."
	}
	return "The model's stream ended with an error."
}

// ---- InvokeModel: the provider's body

func bdStopFor(family, stop string) string {
	switch family {
	case "titan":
		switch stop {
		case "max_tokens":
			return "LENGTH"
		case "content_filtered", "guardrail_intervened":
			return "CONTENT_FILTERED"
		}
		return "FINISH"
	case "llama", "mistral", "mistral-chat":
		if stop == "max_tokens" {
			return "length"
		}
		if stop == "tool_use" {
			return "tool_calls"
		}
		return "stop"
	case "cohere-text", "cohere-chat":
		if stop == "max_tokens" {
			return "MAX_TOKENS"
		}
		return "COMPLETE"
	case "anthropic", "anthropic-text":
		switch stop {
		case "guardrail_intervened", "content_filtered":
			return "end_turn"
		}
		return stop
	}
	return stop
}

func bdMessageID(q *bdReq) string {
	sum := sha256.Sum256([]byte("msg" + q.sha + q.base))
	return "msg_bdrk_" + hex.EncodeToString(sum[:])[:22]
}

func bdAnthropicBlocks(a *bdAnswer) []any {
	out := []any{}
	for _, b := range a.blocks {
		switch b.kind {
		case "text":
			out = append(out, map[string]any{"type": "text", "text": b.text})
		case "toolUse":
			out = append(out, map[string]any{"type": "tool_use", "id": b.id, "name": b.name, "input": json.RawMessage(b.input)})
		}
	}
	return out
}

func bdNovaBlocks(a *bdAnswer) []any {
	out := []any{}
	for _, b := range a.blocks {
		switch b.kind {
		case "text", "toolUse":
			out = append(out, bdConverseBlock(b))
		}
	}
	return out
}

// bdInvokeBody is InvokeModel's body for the model's family: the rule's `raw` as it is, an embedding, or the answer in the provider's shape.
func bdInvokeBody(q *bdReq, resp *bdResponse, a *bdAnswer) ([]byte, error) {
	if len(resp.Raw) > 0 && !a.intervened {
		return resp.Raw, nil
	}
	if resp.Embedding != nil {
		return bdEmbeddingBody(q, resp.Embedding)
	}
	text := a.text
	stop := bdStopFor(q.family, a.stop)
	var doc map[string]any
	switch q.family {
	case "anthropic":
		doc = map[string]any{"id": bdMessageID(q), "type": "message", "role": "assistant", "model": q.base, "content": bdAnthropicBlocks(a),
			"stop_reason": stop, "stop_sequence": nil, "usage": map[string]any{"input_tokens": a.in, "output_tokens": a.out}}
	case "anthropic-text":
		doc = map[string]any{"completion": text, "stop_reason": map[bool]string{true: "max_tokens", false: "stop_sequence"}[stop == "max_tokens"], "stop": "\n\nHuman:"}
	case "nova":
		u := bdUsageDoc(a)
		u["cacheReadInputTokenCount"], u["cacheWriteInputTokenCount"] = 0, 0
		doc = map[string]any{"output": map[string]any{"message": map[string]any{"role": "assistant", "content": bdNovaBlocks(a)}}, "stopReason": a.stop, "usage": u}
	case "titan":
		doc = map[string]any{"inputTextTokenCount": a.in, "results": []any{map[string]any{"tokenCount": a.out, "outputText": text, "completionReason": stop}}}
	case "llama":
		doc = map[string]any{"generation": text, "prompt_token_count": a.in, "generation_token_count": a.out, "stop_reason": stop}
	case "mistral":
		doc = map[string]any{"outputs": []any{map[string]any{"text": text, "stop_reason": stop}}}
	case "mistral-chat":
		doc = map[string]any{"choices": []any{map[string]any{"index": 0, "message": map[string]any{"role": "assistant", "content": text, "tool_calls": []any{}},
			"stop_reason": stop}}}
	case "cohere-text":
		doc = map[string]any{"id": bdMessageID(q), "generations": []any{map[string]any{"id": bdMessageID(q) + "-0", "text": text, "finish_reason": stop}}, "prompt": q.text}
	case "cohere-chat":
		doc = map[string]any{"response_id": bdMessageID(q), "text": text, "generation_id": bdMessageID(q) + "-g", "chat_history": []any{}, "finish_reason": stop}
	case "titan-embed", "cohere-embed", "nova-embed":
		return nil, errors.New("this is an embedding model: answer it with an `embedding` or a `raw` body")
	default:
		doc = map[string]any{"outputText": text, "stopReason": a.stop}
	}
	bdGuardrailKeys(doc, q, a)
	b, _ := json.Marshal(doc)
	return b, nil
}

// bdGuardrailKeys adds what InvokeModel writes into the body when the request carried a guardrail.
func bdGuardrailKeys(doc map[string]any, q *bdReq, a *bdAnswer) {
	if a.guardrail == nil {
		return
	}
	doc["amazon-bedrock-guardrailAction"] = map[bool]string{true: "INTERVENED", false: "NONE"}[a.intervened]
	if a.trace != nil {
		doc["amazon-bedrock-trace"] = a.trace
	}
}

// ---- embeddings: a deterministic vector made up from the text (labelled fake: it carries no meaning)

func bdVector(text string, dims int) []float64 {
	seed := sha256.Sum256([]byte(text))
	v := make([]float64, dims)
	var norm float64
	for i := range v {
		var buf [36]byte
		copy(buf[:32], seed[:])
		binary.BigEndian.PutUint32(buf[32:], uint32(i))
		h := sha256.Sum256(buf[:])
		x := float64(binary.BigEndian.Uint32(h[:4]))/float64(math.MaxUint32)*2 - 1
		v[i] = x
		norm += x * x
	}
	norm = math.Sqrt(norm)
	for i := range v {
		v[i] = math.Round(v[i]/norm*1e8) / 1e8
	}
	return v
}

func bdEmbeddingBody(q *bdReq, e *bdEmbedding) ([]byte, error) {
	switch q.family {
	case "titan-embed":
		b, _ := json.Marshal(map[string]any{"embedding": bdVector(q.text, e.Dimensions), "inputTextTokenCount": bdTokens(q.allText)})
		return b, nil
	case "cohere-embed":
		texts := q.texts
		if len(texts) == 0 {
			texts = []string{q.text}
		}
		if len(texts)*e.Dimensions > bdMaxEmbedNumbers {
			return nil, fmt.Errorf("the answer's vectors (%d texts of %d numbers) are more than the front writes (%d numbers)", len(texts), e.Dimensions, bdMaxEmbedNumbers)
		}
		vs := make([][]float64, len(texts))
		for i, t := range texts {
			vs[i] = bdVector(t, e.Dimensions)
		}
		doc := map[string]any{"id": bdMessageID(q), "texts": texts, "embeddings": vs, "response_type": "embeddings_floats"}
		if m, ok := q.doc.(map[string]any); ok && m["embedding_types"] != nil {
			doc["embeddings"], doc["response_type"] = map[string]any{"float": vs}, "embeddings_by_type"
		}
		b, _ := json.Marshal(doc)
		return b, nil
	}
	return nil, errors.New("the front has no embedding shape for this model family: answer it with a `raw` body")
}

// ---- InvokeModelWithResponseStream: `chunk` events whose bytes are the provider's chunk

func bdChunk(doc any, part bool) bdEvent {
	b, _ := json.Marshal(doc)
	e := bdEv("chunk", map[string]any{"bytes": base64.StdEncoding.EncodeToString(b)}, part)
	return e
}

func bdInvokeEvents(q *bdReq, resp *bdResponse, a *bdAnswer) ([]bdEvent, error) {
	if len(resp.RawChunks) > 0 {
		var evs []bdEvent
		for _, c := range resp.RawChunks {
			evs = append(evs, bdEv("chunk", map[string]any{"bytes": base64.StdEncoding.EncodeToString(c)}, true))
		}
		return evs, nil
	}
	if resp.Embedding != nil {
		return nil, errors.New("an embedding model does not stream")
	}
	if len(resp.Raw) > 0 && !a.intervened {
		return []bdEvent{bdEv("chunk", map[string]any{"bytes": base64.StdEncoding.EncodeToString(resp.Raw)}, true)}, nil
	}
	text := a.text
	stop := bdStopFor(q.family, a.stop)
	metrics := bdMetrics(a)
	final := func(doc map[string]any) bdEvent {
		doc["amazon-bedrock-invocationMetrics"] = metrics
		bdGuardrailKeys(doc, q, a)
		return bdChunk(doc, false)
	}
	parts := bdTextParts(resp, text, true)
	var evs []bdEvent
	switch q.family {
	case "anthropic":
		evs = append(evs, bdChunk(map[string]any{"type": "message_start", "message": map[string]any{"id": bdMessageID(q), "type": "message", "role": "assistant",
			"model": q.base, "content": []any{}, "stop_reason": nil, "stop_sequence": nil, "usage": map[string]any{"input_tokens": a.in, "output_tokens": 1}}}, false))
		idx := 0
		firstText := true
		for _, b := range a.blocks {
			switch b.kind {
			case "text":
				evs = append(evs, bdChunk(map[string]any{"type": "content_block_start", "index": idx, "content_block": map[string]any{"type": "text", "text": ""}}, false))
				ps := []string{b.text}
				if b.text != "" || firstText {
					ps = bdTextParts(resp, b.text, firstText && !a.intervened)
				}
				for _, p := range ps {
					evs = append(evs, bdChunk(map[string]any{"type": "content_block_delta", "index": idx, "delta": map[string]any{"type": "text_delta", "text": p}}, true))
				}
				firstText = false
			case "toolUse":
				evs = append(evs, bdChunk(map[string]any{"type": "content_block_start", "index": idx,
					"content_block": map[string]any{"type": "tool_use", "id": b.id, "name": b.name, "input": map[string]any{}}}, false))
				for _, p := range bdTextParts(&bdResponse{ChunkSize: resp.ChunkSize}, string(b.input), false) {
					evs = append(evs, bdChunk(map[string]any{"type": "content_block_delta", "index": idx, "delta": map[string]any{"type": "input_json_delta", "partial_json": p}}, true))
				}
			default:
				continue
			}
			evs = append(evs, bdChunk(map[string]any{"type": "content_block_stop", "index": idx}, false))
			idx++
		}
		evs = append(evs, bdChunk(map[string]any{"type": "message_delta", "delta": map[string]any{"stop_reason": stop, "stop_sequence": nil}, "usage": map[string]any{"output_tokens": a.out}}, false))
		evs = append(evs, final(map[string]any{"type": "message_stop"}))
	case "anthropic-text":
		for _, p := range parts {
			evs = append(evs, bdChunk(map[string]any{"completion": p, "stop_reason": nil, "stop": nil}, true))
		}
		evs = append(evs, final(map[string]any{"completion": "", "stop_reason": map[bool]string{true: "max_tokens", false: "stop_sequence"}[stop == "max_tokens"], "stop": "\n\nHuman:"}))
	case "nova":
		evs = append(evs, bdChunk(map[string]any{"messageStart": map[string]any{"role": "assistant"}}, false))
		idx := 0
		firstText := true
		for _, b := range a.blocks {
			switch b.kind {
			case "text":
				for _, p := range bdTextParts(resp, b.text, firstText && !a.intervened) {
					evs = append(evs, bdChunk(map[string]any{"contentBlockDelta": map[string]any{"delta": map[string]any{"text": p}, "contentBlockIndex": idx}}, true))
				}
				firstText = false
			case "toolUse":
				evs = append(evs, bdChunk(map[string]any{"contentBlockStart": map[string]any{"start": map[string]any{"toolUse": map[string]any{"toolUseId": b.id, "name": b.name}}, "contentBlockIndex": idx}}, false))
				for _, p := range bdTextParts(&bdResponse{ChunkSize: resp.ChunkSize}, string(b.input), false) {
					evs = append(evs, bdChunk(map[string]any{"contentBlockDelta": map[string]any{"delta": map[string]any{"toolUse": map[string]any{"input": p}}, "contentBlockIndex": idx}}, true))
				}
			default:
				continue
			}
			evs = append(evs, bdChunk(map[string]any{"contentBlockStop": map[string]any{"contentBlockIndex": idx}}, false))
			idx++
		}
		evs = append(evs, final(map[string]any{"messageStop": map[string]any{"stopReason": a.stop}}))
	case "titan":
		for i, p := range parts {
			c := map[string]any{"outputText": p, "index": 0, "totalOutputTextTokenCount": nil, "completionReason": nil}
			if i == 0 {
				c["inputTextTokenCount"] = a.in
			}
			evs = append(evs, bdChunk(c, true))
		}
		evs = append(evs, final(map[string]any{"outputText": "", "index": 0, "totalOutputTextTokenCount": a.out, "completionReason": stop}))
	case "llama":
		for i, p := range parts {
			c := map[string]any{"generation": p, "prompt_token_count": nil, "generation_token_count": i + 1, "stop_reason": nil}
			if i == 0 {
				c["prompt_token_count"] = a.in
			}
			evs = append(evs, bdChunk(c, true))
		}
		evs = append(evs, final(map[string]any{"generation": "", "prompt_token_count": nil, "generation_token_count": a.out, "stop_reason": stop}))
	case "mistral":
		for _, p := range parts {
			evs = append(evs, bdChunk(map[string]any{"outputs": []any{map[string]any{"text": p, "stop_reason": nil}}}, true))
		}
		evs = append(evs, final(map[string]any{"outputs": []any{map[string]any{"text": "", "stop_reason": stop}}}))
	case "mistral-chat":
		for _, p := range parts {
			evs = append(evs, bdChunk(map[string]any{"choices": []any{map[string]any{"index": 0, "message": map[string]any{"role": "assistant", "content": p}, "stop_reason": nil}}}, true))
		}
		evs = append(evs, final(map[string]any{"choices": []any{map[string]any{"index": 0, "message": map[string]any{"role": "assistant", "content": ""}, "stop_reason": stop}}}))
	case "cohere-chat":
		for _, p := range parts {
			evs = append(evs, bdChunk(map[string]any{"is_finished": false, "event_type": "text-generation", "text": p}, true))
		}
		evs = append(evs, final(map[string]any{"is_finished": true, "event_type": "stream-end", "finish_reason": stop,
			"response": map[string]any{"response_id": bdMessageID(q), "text": text, "generation_id": bdMessageID(q) + "-g", "chat_history": []any{}, "finish_reason": stop}}))
	case "cohere-text":
		for _, p := range parts {
			evs = append(evs, bdChunk(map[string]any{"text": p, "is_finished": false}, true))
		}
		evs = append(evs, final(map[string]any{"is_finished": true, "finish_reason": stop, "response": map[string]any{"id": bdMessageID(q),
			"generations": []any{map[string]any{"id": bdMessageID(q) + "-0", "text": text, "finish_reason": stop}}, "prompt": q.text}}))
	case "titan-embed", "cohere-embed", "nova-embed":
		return nil, errors.New("this is an embedding model: it does not stream")
	default:
		for _, p := range parts {
			evs = append(evs, bdChunk(map[string]any{"outputText": p}, true))
		}
		evs = append(evs, final(map[string]any{"outputText": "", "stopReason": a.stop}))
	}
	return evs, nil
}

// ---- ApplyGuardrail

func bdApplyBody(q *bdReq, resp *bdResponse, a *bdAnswer) ([]byte, error) {
	g := resp.Guardrail
	if g == nil {
		return nil, errors.New("the answer that matched an ApplyGuardrail call has no `guardrail` section")
	}
	assess := []any{}
	if len(g.Assessments) > 0 {
		var v any
		json.Unmarshal(g.Assessments, &v)
		switch t := v.(type) {
		case []any:
			assess = t
		case map[string]any:
			assess = []any{t}
		}
	}
	outputs := []any{}
	for _, o := range g.Outputs {
		outputs = append(outputs, map[string]any{"text": o})
	}
	if len(g.Outputs) == 0 && g.Action == "GUARDRAIL_INTERVENED" {
		msg := g.BlockedMessage
		if msg == "" {
			msg = bdBlockedDefault
		}
		outputs = append(outputs, map[string]any{"text": msg})
	}
	doc := map[string]any{
		"usage": map[string]any{"topicPolicyUnits": 1, "contentPolicyUnits": 1, "wordPolicyUnits": 1, "sensitiveInformationPolicyUnits": 1,
			"sensitiveInformationPolicyFreeUnits": 0, "contextualGroundingPolicyUnits": 0},
		"action":            g.Action,
		"outputs":           outputs,
		"assessments":       assess,
		"guardrailCoverage": map[string]any{"textCharacters": map[string]any{"guarded": len([]rune(q.text)), "total": len([]rune(q.text))}},
	}
	if g.ActionReason != "" {
		doc["actionReason"] = g.ActionReason
	}
	b, _ := json.Marshal(doc)
	return b, nil
}
