package standin

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// peakHeap runs f and reports the largest HeapInuse seen while it ran, sampled every few milliseconds, and the bytes allocated in total (garbage included).
func peakHeap(f func()) (peak uint64, total uint64) {
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		var ms runtime.MemStats
		for {
			runtime.ReadMemStats(&ms)
			if ms.HeapInuse > peak {
				peak = ms.HeapInuse
			}
			select {
			case <-done:
				return
			case <-time.After(2 * time.Millisecond):
			}
		}
	}()
	f()
	close(done)
	wg.Wait()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	return peak, after.TotalAlloc - before.TotalAlloc
}

const mib = 1 << 20

// The schema bomb of the review: minItems 100 and strings of 10,000 characters at every level of a tree as deep as the config allows. A two-byte POST must be refused as soon as the reply
// passes 6 MiB, not after the whole tree (100^4 objects of 10 KB) is built.
func TestSchemaBombIsRefusedByBytes(t *testing.T) {
	level := func(inner string) string {
		return `{"type":"object","properties":{"s":{"type":"string","minLength":10000,"maxLength":10000},"a":{"type":"array","minItems":100,"maxItems":100,"items":` + inner + `}}}`
	}
	schema := `{"type":"string","minLength":10000,"maxLength":10000}`
	for i := 0; i < 4; i++ { // four objects and four arrays: the deepest tree the config allows (8 levels)
		schema = level(schema)
	}
	e := newEnv(t, one(`{"kind":"schema","schema":`+schema+`}`))
	var r resp
	peak, total := peakHeap(func() { r = e.invoke(`{}`, nil) })
	if r.status != 500 || !strings.Contains(r.body, "too large") {
		t.Fatalf("a schema bomb is refused: %d %q", r.status, r.body)
	}
	if peak > 96*mib || total > 96*mib {
		t.Fatalf("the bomb was built before it was refused: peak heap %d MiB, allocated %d MiB", peak/mib, total/mib)
	}
	if e.srv.held != 0 {
		t.Fatalf("the budget is released after a refusal: %d held", e.srv.held)
	}
}

// The label amplification of the review: a small request (87,000 instances) with a reply of several MiB, four at once. Each is answered or refused, and the whole stays inside a memory bound.
func TestLabelAmplificationStaysBounded(t *testing.T) {
	e := newEnv(t, one(`{"kind":"label","labels":["only"],"with_probabilities":true}`))
	body := "[" + strings.Repeat("10,", 87_000-1) + "10]" // 261 KB
	var single resp
	peak1, _ := peakHeap(func() { single = e.invoke(body, nil) })
	if single.status != 200 || len(single.body) < 3*mib || len(single.body) > 6*mib {
		t.Fatalf("one such request is answered: %d, %d bytes", single.status, len(single.body))
	}
	var mu sync.Mutex
	codes := map[int]int{}
	peak, _ := peakHeap(func() {
		var wg sync.WaitGroup
		for i := 0; i < 4; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				r := e.invoke(body, nil)
				mu.Lock()
				codes[r.status]++
				mu.Unlock()
			}()
		}
		wg.Wait()
	})
	if codes[200]+codes[503] != 4 || codes[200] < 1 {
		t.Fatalf("each of four at once is answered or refused with 503: %v", codes)
	}
	// four replies of 4.6 MB each would be 18 MB for the replies alone: the budget (16 MiB, shared with the bodies) refuses what does not fit
	if peak > 160*mib {
		t.Fatalf("peak heap %d MiB for four concurrent large replies (one alone: %d MiB)", peak/mib, peak1/mib)
	}
	if e.srv.held != 0 {
		t.Fatalf("every reservation is released: %d held", e.srv.held)
	}
}

func TestReplyBytesAreCountedForEveryKind(t *testing.T) {
	cases := map[string]struct{ model, body string }{
		"vector, 20 instances of 100,000 numbers": {`{"kind":"vector","size":100000}`, `{"instances":[` + strings.Repeat("1,", 19) + `1]}`},
		"csv, 100,000 rows of 100 columns":        {`{"kind":"csv","columns":100,"decimals":6}`, strings.Repeat("a\n", 100_000)},
		"echo with a 5 MiB field":                 {`{"kind":"json_echo","wrap":"in"}`, `"` + strings.Repeat("a", 5*mib+512*1024) + `"`},
		"schema, a 10,000 character enum value":   {`{"kind":"schema","schema":{"type":"array","minItems":100,"maxItems":100,"items":{"enum":["` + strings.Repeat("e", 100_000) + `"]}}}`, `{}`},
	}
	for name, c := range cases {
		e := newEnv(t, one(c.model))
		var r resp
		peak, _ := peakHeap(func() { r = e.invoke(c.body, nil) })
		if r.status == 200 && len(r.body) > MaxReply {
			t.Errorf("%s: a reply of %d bytes was written", name, len(r.body))
		}
		if r.status != 200 && r.status != 500 && r.status != 503 {
			t.Errorf("%s: status %d", name, r.status)
		}
		if peak > 160*mib {
			t.Errorf("%s: peak heap %d MiB", name, peak/mib)
		}
	}
}

func TestMeter(t *testing.T) {
	m := &meter{limit: 100}
	if err := m.add(60); err != nil {
		t.Fatal(err)
	}
	if !m.room(40) || m.room(41) {
		t.Fatal("room is what is left")
	}
	if err := m.add(41); err == nil || err.status != 500 || !strings.Contains(err.msg, "too large") {
		t.Fatalf("over the limit: %v", err)
	}
	if err := m.add(-1); err == nil {
		t.Fatal("a negative size is refused")
	}
	// the server's budget: taken in blocks, refused with 503 when it is spent, and the total taken is what the server releases
	var taken int64
	b := &meter{limit: 10 * mib, reserve: func(n int64) bool {
		if taken+n > 3*meterBlock {
			return false
		}
		taken += n
		return true
	}}
	for i := 0; i < 3; i++ {
		if err := b.add(meterBlock); err != nil {
			t.Fatalf("block %d: %v", i, err)
		}
	}
	if err := b.add(1); err == nil || err.status != 503 {
		t.Fatalf("the budget is spent: %v", err)
	}
	if b.reserved != taken || taken != 3*meterBlock {
		t.Fatalf("reserved %d, taken %d", b.reserved, taken)
	}
}

// F2: a body with no Content-Length is reserved by the bytes actually read, so small chunked bodies do not each hold 6 MiB.
func TestChunkedBodiesAreReservedByBytesRead(t *testing.T) {
	e := newEnv(t, one(`{"kind":"fixed","body":"ok"}`))
	req := func(n int) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/invocations", io.MultiReader(strings.NewReader(strings.Repeat("a", n))))
		r.ContentLength = -1
		rec := httptest.NewRecorder()
		e.srv.handler("").ServeHTTP(rec, r)
		return rec
	}
	// 11 MiB are held by others: before, a chunked request needed 6 MiB of the 5 left and was refused; now a small one fits
	if !e.srv.reserve(11 * mib) {
		t.Fatal("reserve")
	}
	if rec := req(100 << 10); rec.Code != 200 {
		t.Fatalf("a small chunked body with 5 MiB free: %d", rec.Code)
	}
	if rec := req(6 * mib); rec.Code != 503 {
		t.Fatalf("a 6 MiB chunked body with 5 MiB free is refused as it grows: %d", rec.Code)
	}
	e.srv.release(11 * mib)
	if e.srv.held != 0 {
		t.Fatalf("everything is released: %d held", e.srv.held)
	}
	// many small chunked bodies at once all fit (the old rule allowed two)
	var wg sync.WaitGroup
	var mu sync.Mutex
	codes := map[int]int{}
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := req(10 << 10).Code
			mu.Lock()
			codes[c]++
			mu.Unlock()
		}()
	}
	wg.Wait()
	if codes[200] != 20 {
		t.Fatalf("20 small chunked bodies at once: %v", codes)
	}
}

// F2: a chunked body that stalls is cut by the shorter read deadline (408), and what it held is released.
func TestStalledChunkedBodyIsCut(t *testing.T) {
	old := unknownLengthDeadline
	unknownLengthDeadline = 300 * time.Millisecond
	defer func() { unknownLengthDeadline = old }()
	cfg, err := ParseConfig([]byte(one(`{"kind":"fixed","body":"ok"}`)))
	if err != nil {
		t.Fatal(err)
	}
	srvObj := New(cfg, newLogger(io.Discard))
	ts := httptest.NewServer(srvObj.handler(""))
	defer ts.Close()
	pr, pw := io.Pipe()
	go func() { _, _ = pw.Write([]byte("partial")); time.Sleep(3 * time.Second); pw.Close() }()
	req, _ := http.NewRequest("POST", ts.URL+"/invocations", pr)
	req.ContentLength = -1
	start := time.Now()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("the stalled upload is answered: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 408 || time.Since(start) > 2*time.Second {
		t.Fatalf("status %d after %v", resp.StatusCode, time.Since(start))
	}
	pw.CloseWithError(io.ErrClosedPipe)
	time.Sleep(50 * time.Millisecond)
	srvObj.budgetMu.Lock()
	held := srvObj.held
	srvObj.budgetMu.Unlock()
	if held != 0 {
		t.Fatalf("the stalled request still holds %d bytes", held)
	}
}

// F4: an error reply is valid JSON for any message, control bytes and DEL included.
func TestErrorReplyIsValidJSON(t *testing.T) {
	msg := "a\x01b\x1fc\x7fd<e>&f g\"h\\i"
	e := newEnv(t, one(`{"kind":"fixed","body":"ok","fail_first":1,"error_message":`+mustJSON(t, msg)+`}`))
	r := e.invoke("x", nil)
	var got struct{ Error string }
	if r.status != 500 || json.Unmarshal([]byte(r.body), &got) != nil || got.Error != msg {
		t.Fatalf("%d %q", r.status, r.body)
	}
}

func mustJSON(t *testing.T, v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// F3: a bad format is named quoted, so a value with a line break or control byte cannot forge a log or error line.
func TestBadFormatIsQuotedInTheError(t *testing.T) {
	_, err := ParseConfig([]byte(one(`{"kind":"schema","schema":{"type":"string","format":"x\ny\u0007"}}`)))
	if err == nil || strings.ContainsAny(err.Error(), "\n\a") || !strings.Contains(err.Error(), `"x\ny\a"`) {
		t.Fatalf("%v", err)
	}
}
