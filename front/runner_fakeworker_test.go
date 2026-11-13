package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// A fake worker for the runner pipe: the Cloud worker's end of runner/2, in Go, with an echo "function" behind it. It is what the front's
// tests (and the live proof in the VM) run against until the real worker lane exists. The function's behaviour is chosen by the event:
//
//	{"op":"echo"} or anything else   the response is {"echo": <event>, "fn": <name>, "version": <version>}
//	{"op":"error","type":T,"msg":M}  function_error (type T, message M)
//	{"op":"sleep","ms":N}            sleeps N ms (past timeoutMs: status timeout), then echoes
//	{"op":"big","bytes":N}           a response of about N bytes
//	{"op":"crash"}                   status crash
//	{"op":"throttle"}                status throttled, reason concurrency
//	{"op":"raw","text":T}            the response is exactly T
type fakeWorker struct {
	t          *testing.T
	conn       net.Conn
	fr         *frameReader
	fw         *frameWriter
	mu         sync.Mutex
	have       map[string][]byte
	fns        map[string]regFn
	recv       map[string]*pkgRecv // id|sha -> bytes in flight
	pending    map[string]*pendingReg
	cold       map[string]bool
	done       chan struct{}
	registers  int32
	invokes    int32
	inflight   int32
	maxIn      int32
	refuse     func(fn regFn) *frameError                        // a registration the worker refuses
	onInvoke   func(inv invokeFrame, event []byte) *runnerResult // overrides the echo behaviour when it returns a result
	stopped    int32
	fractional bool // report timings and sizes as fractional numbers
	invs       []invokeFrame
}

type pkgRecv struct {
	size int64
	data []byte
	kind string
}

type pendingReg struct {
	fn   regFn
	need map[string]bool
}

func connectFakeWorker(t *testing.T, socket string) *fakeWorker {
	t.Helper()
	var c net.Conn
	var err error
	for i := 0; i < 100; i++ {
		if c, err = net.Dial("unix", socket); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("the worker cannot reach the runner socket: %v", err)
	}
	w := &fakeWorker{t: t, conn: c, fr: newFrameReader(c), fw: &frameWriter{w: c}, have: map[string][]byte{}, fns: map[string]regFn{},
		recv: map[string]*pkgRecv{}, pending: map[string]*pendingReg{}, cold: map[string]bool{}, done: make(chan struct{})}
	typ, _, err := w.fr.next()
	if err != nil || typ != ftHello {
		t.Fatalf("the front's hello: %v %v", typ, err)
	}
	w.fw.write(helloFrame{Type: ftHello, Proto: runnerProto, Worker: "fake-worker", Version: "test", Runtimes: []string{"python3.12", "nodejs22.x"}})
	go w.loop()
	t.Cleanup(func() { c.Close() })
	return w
}

func (w *fakeWorker) loop() {
	defer close(w.done)
	for {
		typ, raw, err := w.fr.next()
		if err != nil {
			return
		}
		switch typ {
		case ftRegister:
			var f registerFrame
			json.Unmarshal(raw, &f)
			atomic.AddInt32(&w.registers, 1)
			w.onRegister(f)
		case ftPackage:
			var f packageFrame
			json.Unmarshal(raw, &f)
			w.mu.Lock()
			w.recv[f.ID+"|"+f.SHA256] = &pkgRecv{size: f.SizeBytes, kind: f.Kind}
			w.mu.Unlock()
		case ftChunk:
			var f chunkFrame
			json.Unmarshal(raw, &f)
			w.onChunk(f)
		case ftInvoke:
			var f invokeFrame
			json.Unmarshal(raw, &f)
			go w.onInvoke_(f)
		case ftUnregister:
			var f unregisterFrame
			json.Unmarshal(raw, &f)
			w.mu.Lock()
			for k, fn := range w.fns {
				if fn.Name == f.Name && (f.Version == "" || fn.Version == f.Version) {
					delete(w.fns, k)
				}
			}
			w.mu.Unlock()
			w.fw.write(map[string]string{"type": ftUnregistered, "id": f.ID})
		case ftStopAll:
			var f stopAllFrame
			json.Unmarshal(raw, &f)
			w.mu.Lock()
			w.fns = map[string]regFn{}
			w.cold = map[string]bool{}
			w.mu.Unlock()
			atomic.AddInt32(&w.stopped, 1)
			w.fw.write(map[string]string{"type": ftStopped, "id": f.ID})
		}
	}
}

func (w *fakeWorker) onRegister(f registerFrame) {
	if w.refuse != nil {
		if e := w.refuse(f.Fn); e != nil {
			w.fw.write(map[string]interface{}{"type": ftRegistered, "id": f.ID, "ok": false, "error": e})
			return
		}
	}
	var need []string
	pr := &pendingReg{fn: f.Fn, need: map[string]bool{}}
	refs := append([]pkgRef(nil), f.Fn.Layers...)
	if f.Fn.Package != nil {
		refs = append(refs, *f.Fn.Package)
	}
	w.mu.Lock()
	for _, p := range refs {
		if _, ok := w.have[p.SHA256]; !ok && !pr.need[p.SHA256] {
			pr.need[p.SHA256] = true
			need = append(need, p.SHA256)
		}
	}
	w.mu.Unlock()
	if len(need) == 0 {
		w.finish(f.ID, f.Fn)
		return
	}
	w.mu.Lock()
	w.pending[f.ID] = pr
	w.mu.Unlock()
	w.fw.write(map[string]interface{}{"type": ftNeed, "id": f.ID, "packages": need})
}

func (w *fakeWorker) onChunk(f chunkFrame) {
	w.mu.Lock()
	r := w.recv[f.ID+"|"+f.SHA256]
	if r == nil {
		w.mu.Unlock()
		return
	}
	b, _ := base64.StdEncoding.DecodeString(f.Data)
	r.data = append(r.data, b...)
	if !f.Last {
		w.mu.Unlock()
		return
	}
	delete(w.recv, f.ID+"|"+f.SHA256)
	pr := w.pending[f.ID]
	sum := sha256.Sum256(r.data)
	ok := int64(len(r.data)) == r.size && hex.EncodeToString(sum[:]) == f.SHA256
	if ok {
		w.have[f.SHA256] = r.data
	}
	if pr != nil {
		delete(pr.need, f.SHA256)
	}
	done := pr != nil && len(pr.need) == 0
	if done {
		delete(w.pending, f.ID)
	}
	w.mu.Unlock()
	if !ok {
		w.fw.write(map[string]interface{}{"type": ftRegistered, "id": f.ID, "ok": false, "error": &frameError{Type: "InvalidParameterValueException", Message: "package digest or size did not match"}})
		return
	}
	if done {
		w.finish(f.ID, pr.fn)
	}
}

func (w *fakeWorker) finish(id string, fn regFn) {
	w.mu.Lock()
	w.fns[fn.Name+"|"+fn.Version] = fn
	w.mu.Unlock()
	w.fw.write(map[string]interface{}{"type": ftRegistered, "id": id, "ok": true})
}

func (w *fakeWorker) onInvoke_(f invokeFrame) {
	atomic.AddInt32(&w.invokes, 1)
	n := atomic.AddInt32(&w.inflight, 1)
	for {
		m := atomic.LoadInt32(&w.maxIn)
		if n <= m || atomic.CompareAndSwapInt32(&w.maxIn, m, n) {
			break
		}
	}
	defer atomic.AddInt32(&w.inflight, -1)
	w.mu.Lock()
	w.invs = append(w.invs, f)
	fn, known := w.fns[f.Name+"|"+f.Version]
	cold := !w.cold[f.Name+"|"+f.Version]
	w.cold[f.Name+"|"+f.Version] = true
	w.mu.Unlock()
	res := runnerResult{ID: f.ID}
	if !known {
		res.Status, res.Reason = "unavailable", "not_registered"
		w.fw.write(typed(ftResult, res))
		return
	}
	event, _ := base64.StdEncoding.DecodeString(f.Payload)
	if w.onInvoke != nil {
		if r := w.onInvoke(f, event); r != nil {
			r.ID = f.ID
			w.fw.write(typed(ftResult, *r))
			return
		}
	}
	var ev map[string]interface{}
	json.Unmarshal(event, &ev)
	op, _ := ev["op"].(string)
	res.Cold = cold
	res.LogTail = "START RequestId: " + f.RequestID + "\nran " + fn.Name + "\nEND RequestId: " + f.RequestID + "\n"
	res.DurationMs, res.MaxMemoryUsed = 3, 10<<20
	respond := func(v interface{}) {
		b, _ := json.Marshal(v)
		res.Status, res.Payload = "ok", base64.StdEncoding.EncodeToString(b)
	}
	switch op {
	case "error":
		t, _ := ev["type"].(string)
		m, _ := ev["msg"].(string)
		doc, _ := json.Marshal(map[string]interface{}{"errorType": t, "errorMessage": m, "stackTrace": []string{"  File \"app.py\", line 1, in handler"}})
		res.Status, res.ErrorType, res.ErrorMessage, res.Payload = "function_error", t, m, base64.StdEncoding.EncodeToString(doc)
	case "sleep":
		ms, _ := ev["ms"].(float64)
		if int64(ms) > f.TimeoutMs {
			time.Sleep(time.Duration(f.TimeoutMs) * time.Millisecond)
			res.Status, res.ErrorType, res.ErrorMessage = "timeout", "Sandbox.Timedout", "RequestId: "+f.RequestID+" Error: Task timed out after "+itoa64(f.TimeoutMs/1000)+".00 seconds"
		} else {
			time.Sleep(time.Duration(ms) * time.Millisecond)
			respond(map[string]interface{}{"echo": ev, "fn": fn.Name, "version": fn.Version})
		}
	case "big":
		n, _ := ev["bytes"].(float64)
		respond(map[string]interface{}{"data": strings.Repeat("x", int(n))})
	case "size":
		respond(map[string]interface{}{"eventBytes": len(event), "source": f.Source})
	case "crash":
		res.Status, res.ErrorType, res.ErrorMessage = "crash", "Runtime.ExitError", "RequestId: "+f.RequestID+" Error: Runtime exited with error: exit status 7"
	case "throttle":
		res.Status, res.Reason = "throttled", "concurrency"
	case "raw":
		t, _ := ev["text"].(string)
		res.Status, res.Payload = "ok", base64.StdEncoding.EncodeToString([]byte(t))
	default:
		respond(map[string]interface{}{"echo": ev, "fn": fn.Name, "version": fn.Version, "source": f.Source, "arn": f.FunctionArn})
	}
	m := typed(ftResult, res)
	if w.fractional {
		m["durationMs"], m["billedDurationMs"], m["initDurationMs"], m["maxMemoryUsed"] = 12.6, 13.2, 104.4, 22020096.5
	}
	w.fw.write(m)
}

func itoa64(n int64) string { b, _ := json.Marshal(n); return string(b) }

// typed marshals a frame body with its type.
func typed(typ string, v interface{}) map[string]interface{} {
	b, _ := json.Marshal(v)
	var m map[string]interface{}
	json.Unmarshal(b, &m)
	m["type"] = typ
	return m
}

func (w *fakeWorker) holds(sha string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	_, ok := w.have[sha]
	return ok
}

func (w *fakeWorker) registered(name, version string) (regFn, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	fn, ok := w.fns[name+"|"+version]
	return fn, ok
}

func (w *fakeWorker) lastInvoke() invokeFrame {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.invs) == 0 {
		return invokeFrame{}
	}
	return w.invs[len(w.invs)-1]
}

func tmpSocket(t *testing.T) string {
	// a unix socket path is at most ~100 bytes: t.TempDir() can be longer than that
	dir, err := os.MkdirTemp("", "rv")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "r.sock")
}
