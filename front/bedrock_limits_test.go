package main

import (
	"io"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// Limits of the Bedrock shim: what a request can make the front allocate, and how long a request can hold the body budget.

func TestBedrockCohereEmbeddingIsBounded(t *testing.T) {
	f := startBD(t)
	f.fixtures("emb", `{"modelPrefix":"cohere.embed","default":{"embedding":{"dimensions":1024}}}`)
	// 5000 empty texts in a 15 KB body used to be answered with a 58 MB body
	many := `{"texts":[` + strings.Repeat(`"",`, 4999) + `""],"input_type":"search_document"}`
	r := f.call("invoke", "cohere.embed-english-v3", nil, many)
	t.Logf("5000 texts: status %d, answer of %d bytes", r.status, len(r.body))
	if code, body := errBody(t, r); r.status != 400 || code != "ValidationException" || len(r.body) > 4096 {
		t.Errorf("more than 96 texts is a ValidationException: %d %s %v", r.status, code, body)
	}
	if r := f.call("invoke", "cohere.embed-english-v3", nil, `{"texts":["a","b"],"input_type":"search_document"}`); r.status != 200 || len(r.body) > 1<<20 {
		t.Errorf("a few texts are answered: %d (%d bytes)", r.status, len(r.body))
	}
	// 96 texts of the largest vectors is more than the front writes
	f.fixtures("emb", `{"modelPrefix":"cohere.embed","default":{"embedding":{"dimensions":8192}}}`)
	ninetySix := `{"texts":[` + strings.Repeat(`"x",`, 95) + `"x"],"input_type":"search_document"}`
	r = f.call("invoke", "cohere.embed-english-v3", nil, ninetySix)
	if r.status != 400 || len(r.body) > 4096 {
		t.Errorf("96 texts of 8192 numbers: %d (%d bytes)", r.status, len(r.body))
	}
	// images count too
	f.fixtures("emb", `{"modelPrefix":"cohere.embed","default":{"embedding":{"dimensions":4}}}`)
	imgs := `{"images":[` + strings.Repeat(`"data:image/png;base64,AAAA",`, 96) + `"data:image/png;base64,AAAA"],"input_type":"image"}`
	if r := f.call("invoke", "cohere.embed-english-v3", nil, imgs); r.status != 400 {
		t.Errorf("97 images: %d", r.status)
	}
	// a Titan vector is one vector of at most 8192 numbers
	f.fixtures("emb", `{"modelPrefix":"amazon.titan-embed","default":{"embedding":{"dimensions":8192}}}`)
	if r := f.call("invoke", "amazon.titan-embed-text-v2:0", nil, `{"inputText":"x"}`); r.status != 200 || len(r.body) > 1<<20 {
		t.Errorf("titan: %d (%d bytes)", r.status, len(r.body))
	}
}

// bdPeakHeap samples the heap while f runs and returns the highest HeapInuse above the heap at the start.
func bdPeakHeap(f func()) (peak uint64) {
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	base := ms.HeapInuse
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			if m.HeapInuse > base && m.HeapInuse-base > peak {
				peak = m.HeapInuse - base
			}
			select {
			case <-stop:
				return
			case <-time.After(2 * time.Millisecond):
			}
		}
	}()
	f()
	close(stop)
	<-done
	return peak
}

func TestBedrockWorstCaseBodiesStayUnderTheMemoryBound(t *testing.T) {
	f := startBD(t)
	f.fixtures("any", `{"default":{"text":"ok"}}`)
	// two worst cases of an 8 MiB body: the most JSON values (each costs about thirty times its size once decoded) and one huge text
	pad := `{"messages":[{"role":"user","content":[` + strings.Repeat(`{},`, (bdMaxBodyBytes-200)/3) + `{"text":"x"}]}]}`
	huge := `{"messages":[{"role":"user","content":[{"text":"` + strings.Repeat("a", bdMaxBodyBytes-200) + `"}]}]}`
	bodies := []string{pad, huge, pad, huge, pad, huge}
	var wg sync.WaitGroup
	statuses := make([]int, len(bodies))
	peak := bdPeakHeap(func() {
		for i, b := range bodies {
			wg.Add(1)
			go func(i int, b string) {
				defer wg.Done()
				statuses[i] = f.call("converse", "x.y", nil, b).status
			}(i, b)
		}
		wg.Wait()
	})
	t.Logf("peak heap above the start with %d worst-case bodies at once: %d MiB (statuses %v)", len(bodies), peak>>20, statuses)
	if peak > 192<<20 {
		t.Errorf("peak heap %d MiB: the container has 512 MiB for the front and the engine", peak>>20)
	}
	if r := f.call("converse", "x.y", nil, converseHello); r.status != 200 {
		t.Errorf("the front still answers: %d", r.status)
	}
}

func TestBedrockFullBudgetThrottlesInsteadOfWaiting(t *testing.T) {
	f := startBD(t)
	f.fixtures("any", `{"default":{"text":"ok"}}`)
	// every byte of the budget is held: a request that waited for it would wait even after its client left, because the server does not
	// watch a connection whose body is unread
	if !f.srv.bd.bodies.tryAcquire(bdBodyBudget) {
		t.Fatal("the budget is free at the start")
	}
	start := time.Now()
	r := f.call("converse", "x.y", nil, converseHello)
	f.srv.bd.bodies.release(bdBodyBudget)
	if code, _ := errBody(t, r); r.status != 429 || code != "ThrottlingException" || time.Since(start) > 2*time.Second {
		t.Errorf("a request that finds the budget used up is throttled at once: %d %s after %v", r.status, r.body, time.Since(start))
	}
	if r := f.call("converse", "x.y", nil, converseHello); r.status != 200 {
		t.Errorf("answered again once the budget is free: %d", r.status)
	}
	if f.srv.bd.bodies.left != bdBodyBudget {
		t.Errorf("every reserved byte is returned: %d", f.srv.bd.bodies.left)
	}
}

func TestBedrockSlowSenderIsCutOff(t *testing.T) {
	f := startBD(t)
	f.fixtures("any", `{"default":{"text":"ok"}}`)
	old := bdBodyReadTimeout
	bdBodyReadTimeout = 300 * time.Millisecond
	defer func() { bdBodyReadTimeout = old }()
	pr, pw := io.Pipe()
	req, _ := http.NewRequest("POST", f.ts.URL+"/model/x.y/converse", pr)
	req.ContentLength = 5 << 20 // says it holds 5 MiB and sends a few bytes
	for k, v := range merge(scopeHdr("bedrock"), map[string]string{"Content-Type": "application/json"}) {
		req.Header.Set(k, v)
	}
	go pw.Write([]byte(`{"messages":`))
	start := time.Now()
	resp, err := http.DefaultClient.Do(req)
	if err == nil {
		resp.Body.Close()
	}
	pw.Close()
	if time.Since(start) > 5*time.Second {
		t.Errorf("a sender that stalls is cut off after the read timeout: %v", time.Since(start))
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && f.srv.bd.bodies.left != bdBodyBudget {
		time.Sleep(20 * time.Millisecond)
	}
	if f.srv.bd.bodies.left != bdBodyBudget {
		t.Errorf("the slow sender's share of the budget is returned: %d of %d", f.srv.bd.bodies.left, int64(bdBodyBudget))
	}
}

func TestBedrockForwardedOperationsAreMarkedEmulated(t *testing.T) {
	f := startBD(t)
	f.do("GET", "/async-invoke", scopeHdr("bedrock"), "")
	if e := f.lastEntry("ListAsyncInvokes"); e["marker"] != "emulated by the engine; not a Rovara fixture" {
		t.Errorf("a call the engine answers is marked: %v", e)
	}
}
