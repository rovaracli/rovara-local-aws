package standin

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/csv"
	"encoding/json"
	"io"
	"math"
	"math/rand/v2"
	"strconv"
	"sync"
)

// replyError is a failure the model answers with: a status and a fixed sentence. The sentence never repeats a byte of the request.
type replyError struct {
	status int
	msg    string
}

func (e *replyError) Error() string { return e.msg }

// runtimeModel is a Model with the state it needs while it runs: the seeded sequence for errors and jitter, and the count of calls.
type runtimeModel struct {
	*Model
	endpoint string
	name     string
	seed     string

	mu    sync.Mutex
	seq   *rand.Rand
	calls int
}

func newRuntimeModel(m *Model, seed, endpoint, name string) *runtimeModel {
	rm := &runtimeModel{Model: m, endpoint: endpoint, name: name, seed: seed}
	rm.seq = rm.rngFor([]byte("sequence"))
	return rm
}

// rngFor is a random sequence that is a function of the seed, the endpoint, the model and the given bytes only: the same request gets the same answer.
func (rm *runtimeModel) rngFor(parts ...[]byte) *rand.Rand {
	h := sha256.New()
	for _, p := range append([][]byte{[]byte(rm.seed), []byte(rm.endpoint), []byte(rm.name)}, parts...) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(p)))
		h.Write(n[:])
		h.Write(p)
	}
	sum := h.Sum(nil)
	return rand.New(rand.NewPCG(binary.BigEndian.Uint64(sum[0:8]), binary.BigEndian.Uint64(sum[8:16])))
}

// next is the per-request part of the model that depends on how many requests came before: whether this one fails, and how long it waits (milliseconds).
func (rm *runtimeModel) next() (failed bool, waitMS int) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.calls++
	if rm.calls <= rm.FailFirst {
		failed = true
	}
	if rm.ErrorRate > 0 && rm.seq.Float64() < rm.ErrorRate {
		failed = true
	}
	waitMS = rm.LatencyMS
	if rm.JitterMS > 0 {
		waitMS += rm.seq.IntN(rm.JitterMS + 1)
	}
	return failed, waitMS
}

func bad(msg string) *replyError { return &replyError{status: 400, msg: msg} }

// errTooLarge is the refusal when a reply would pass 6 MiB (SageMaker's own limit): it is made as the reply is generated, before more is built, so a request or a schema cannot make
// the process build a reply it would then have to refuse.
func errTooLarge() *replyError {
	return &replyError{status: 500, msg: "Rovara model stand-in: the reply would be too large (over 6 MiB)"}
}

// meter counts the bytes of a reply as it is generated. Every generator asks it before it builds the next piece: past the reply limit the answer is errTooLarge, and the bytes are
// also reserved in the server's in-flight budget (the same one the request bodies use), so a few large replies at once are refused with 503 instead of taking the container's memory.
type meter struct {
	limit    int
	used     int
	reserve  func(n int64) bool // the server's budget; nil in unit tests of the generators
	reserved int64              // what has been taken from the budget, released by the server when the request ends
}

const meterBlock = 64 << 10

// add counts n more bytes of reply. Budget is taken in blocks, so a reply of many small values does not take the budget's lock for each.
func (m *meter) add(n int) *replyError {
	if n < 0 || m.used+n > m.limit {
		return errTooLarge()
	}
	m.used += n
	for m.reserve != nil && int64(m.used) > m.reserved {
		if !m.reserve(meterBlock) {
			return &replyError{status: 503, msg: "Rovara model stand-in: too many large requests at once"}
		}
		m.reserved += meterBlock
	}
	return nil
}

// room reports whether n more bytes could still fit (a cheap check before building something of known minimum size).
func (m *meter) room(n int) bool { return n >= 0 && m.used+n <= m.limit }

// answer is the model's reply to one request body: bytes and a content type, or an error.
func (rm *runtimeModel) answer(body []byte, m *meter) ([]byte, *replyError) {
	var out []byte
	var err *replyError
	switch rm.Kind {
	case KindJSONEcho:
		out, err = rm.jsonEcho(body, m)
	case KindFixed:
		if rm.Body != nil {
			out = []byte(*rm.Body)
		} else {
			out = rm.JSON
		}
		err = m.add(len(out))
	case KindVector:
		out, err = rm.vector(body, m)
	case KindLabel:
		out, err = rm.label(body, m)
	case KindCSV:
		out, err = rm.csv(body, m)
	case KindSchema:
		g := &generator{rng: rm.rngFor([]byte("schema"), body), m: m}
		v, gerr := g.generate(rm.schema)
		if gerr != nil {
			if re, ok := gerr.(*replyError); ok {
				return nil, re
			}
			return nil, errTooLarge()
		}
		b, merr := json.Marshal(v)
		if merr != nil {
			return nil, &replyError{status: 500, msg: "Rovara model stand-in: the reply could not be written"}
		}
		out = b
	}
	if err != nil {
		return nil, err
	}
	if len(out) > MaxReply {
		return nil, &replyError{status: 500, msg: "Rovara model stand-in: the reply is over 6 MiB"}
	}
	return out, nil
}

func (rm *runtimeModel) jsonEcho(body []byte, m *meter) ([]byte, *replyError) {
	in := bytes.TrimSpace(body)
	if len(in) == 0 || !json.Valid(in) {
		return nil, bad("Rovara model stand-in: the request body is not JSON")
	}
	// The split copy of the body and the reply built from it are both counted.
	if err := m.add(len(in)); err != nil {
		return nil, err
	}
	// Raw values: only the top level is split, so a body of millions of numbers is not boxed one by one.
	out := map[string]json.RawMessage{}
	switch {
	case rm.Wrap != "":
		out[rm.Wrap] = in
	case in[0] == '{':
		if json.Unmarshal(in, &out) != nil {
			return nil, bad("Rovara model stand-in: the request body is not JSON")
		}
	default:
		out["input"] = in
	}
	for k, v := range rm.fields {
		out[k] = v
	}
	b, err := json.Marshal(out)
	if err != nil {
		return nil, &replyError{status: 500, msg: "Rovara model stand-in: the reply could not be written"}
	}
	return b, nil
}

// instances splits a request into the instances it holds: the array under key (or the request itself when it is an array), else the whole body as one. It reads the
// array one element at a time and gives up past limit, so a body of millions of tiny elements cannot make it allocate a slice that large (tooMany).
func instances(body []byte, key string, limit int) (items [][]byte, list, tooMany bool) {
	whole := [][]byte{body}
	dec := json.NewDecoder(bytes.NewReader(body))
	first, err := dec.Token()
	if err != nil {
		return whole, false, false
	}
	readArray := func() ([][]byte, bool, bool) { // the decoder is just past '['
		var out [][]byte
		for dec.More() {
			if len(out) >= limit {
				return nil, false, true
			}
			var raw json.RawMessage
			if dec.Decode(&raw) != nil {
				return nil, false, false
			}
			out = append(out, raw)
		}
		if t, err := dec.Token(); err != nil || t != json.Delim(']') {
			return nil, false, false
		}
		return out, true, false
	}
	switch first {
	case json.Delim('['):
		if out, ok, many := readArray(); many {
			return nil, false, true
		} else if ok {
			return out, true, false
		}
	case json.Delim('{'):
		for dec.More() {
			k, err := dec.Token()
			if err != nil {
				break
			}
			if name, _ := k.(string); name == key {
				t, err := dec.Token()
				if err != nil || t != json.Delim('[') {
					break // the key holds something that is not an array: the request is one instance
				}
				if out, ok, many := readArray(); many {
					return nil, false, true
				} else if ok {
					return out, true, false
				}
				break
			}
			var skip json.RawMessage
			if dec.Decode(&skip) != nil {
				break
			}
		}
	}
	return whole, false, false
}

func (rm *runtimeModel) round(v float64) float64 {
	p := math.Pow(10, float64(rm.dec))
	return math.Round(v*p) / p
}

// numbers are n values from rng: in [min, max], or weights that sum to 1.
func (rm *runtimeModel) numbers(rng *rand.Rand, n int) []float64 {
	out := make([]float64, n)
	if rm.Normalize {
		sum := 0.0
		for i := range out {
			out[i] = 0.05 + rng.Float64()
			sum += out[i]
		}
		for i := range out {
			out[i] = rm.round(out[i] / sum)
		}
		return out
	}
	for i := range out {
		out[i] = rm.round(rm.min + rng.Float64()*(rm.max-rm.min))
	}
	return out
}

func (rm *runtimeModel) vector(body []byte, m *meter) ([]byte, *replyError) {
	items, list, tooMany := instances(body, rm.InstancesKey, MaxElements/rm.Size)
	if tooMany {
		return nil, errTooLarge()
	}
	var buf bytes.Buffer
	head := `{` + strconv.Quote(rm.Key) + `:`
	if err := m.add(len(head) + 2); err != nil {
		return nil, err
	}
	buf.WriteString(head)
	if list {
		buf.WriteByte('[')
	}
	for i, item := range items {
		// at least two bytes for each number: refuse before the numbers of one instance are built
		if !m.room(rm.Size * 2) {
			return nil, errTooLarge()
		}
		v := rm.numbers(rm.rngFor([]byte("vector"), item), rm.Size)
		var enc []byte
		var err error
		if rm.Scalar {
			enc, err = json.Marshal(v[0])
		} else {
			enc, err = json.Marshal(v)
		}
		if err != nil {
			return nil, &replyError{status: 500, msg: "Rovara model stand-in: the reply could not be written"}
		}
		if cerr := m.add(len(enc) + 1); cerr != nil {
			return nil, cerr
		}
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.Write(enc)
	}
	if list {
		buf.WriteByte(']')
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// pick is the label chosen for one instance, with every label's probability (the chosen one is the largest).
func (rm *runtimeModel) pick(item []byte) (string, float64, map[string]float64) {
	rng := rm.rngFor([]byte("label"), item)
	idx := rng.IntN(len(rm.Labels))
	weights := make([]float64, len(rm.Labels))
	sum := 0.0
	best := 0
	for i := range weights {
		weights[i] = 0.05 + rng.Float64()
		if weights[i] > weights[best] {
			best = i
		}
	}
	weights[idx], weights[best] = weights[best], weights[idx]
	for _, w := range weights {
		sum += w
	}
	probs := make(map[string]float64, len(weights))
	for i, w := range weights {
		probs[rm.Labels[i]] = rm.round(w / sum)
	}
	return rm.Labels[idx], rm.round(weights[idx] / sum), probs
}

func (rm *runtimeModel) label(body []byte, m *meter) ([]byte, *replyError) {
	items, list, tooMany := instances(body, rm.InstancesKey, MaxElements/(len(rm.Labels)+2))
	if tooMany {
		return nil, errTooLarge()
	}
	one := func(item []byte) ([]byte, error) {
		label, score, probs := rm.pick(item)
		o := map[string]any{rm.LabelKey: label, rm.ScoreKey: score}
		if rm.WithProbabilities {
			o["probabilities"] = probs
		}
		return json.Marshal(o)
	}
	var buf bytes.Buffer
	if list {
		head := `{` + strconv.Quote(rm.Key) + `:[`
		if err := m.add(len(head) + 2); err != nil {
			return nil, err
		}
		buf.WriteString(head)
	}
	for i, item := range items {
		enc, err := one(item)
		if err != nil {
			return nil, &replyError{status: 500, msg: "Rovara model stand-in: the reply could not be written"}
		}
		if cerr := m.add(len(enc) + 1); cerr != nil {
			return nil, cerr
		}
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.Write(enc)
	}
	if list {
		buf.WriteString("]}")
	}
	return buf.Bytes(), nil
}

func (rm *runtimeModel) csv(body []byte, m *meter) ([]byte, *replyError) {
	width := rm.Columns
	if width == 0 {
		width = 1
	}
	limit := MaxElements / width
	r := csv.NewReader(bytes.NewReader(body))
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	r.ReuseRecord = true
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	if rm.Header != nil {
		_ = w.Write(rm.Header)
	}
	first, rows, counted := true, 0, 0
	// bytes written so far are counted after each row, so the reply is refused as soon as it passes the cap
	count := func() *replyError {
		w.Flush()
		err := m.add(buf.Len() - counted)
		counted = buf.Len()
		return err
	}
	if err := count(); err != nil {
		return nil, err
	}
	for {
		row, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, bad("Rovara model stand-in: the request body is not CSV")
		}
		if first && rm.SkipHeader {
			first = false
			continue
		}
		first = false
		if rows++; rows > limit {
			return nil, errTooLarge()
		}
		key, _ := json.Marshal(row)
		rng := rm.rngFor([]byte("csv"), key)
		var cells []string
		if len(rm.Labels) > 0 {
			cells = []string{rm.Labels[rng.IntN(len(rm.Labels))]}
		} else {
			for _, v := range rm.numbers(rng, rm.Columns) {
				cells = append(cells, strconv.FormatFloat(v, 'f', rm.dec, 64))
			}
		}
		_ = w.Write(cells)
		if err := count(); err != nil {
			return nil, err
		}
	}
	w.Flush()
	if w.Error() != nil {
		return nil, &replyError{status: 500, msg: "Rovara model stand-in: the reply could not be written"}
	}
	return buf.Bytes(), nil
}
