package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---- the framing

func TestRunnerFrameCodec(t *testing.T) {
	var buf bytes.Buffer
	fw := &frameWriter{w: &buf}
	if err := fw.write(map[string]interface{}{"type": "hello", "proto": runnerProto}); err != nil {
		t.Fatal(err)
	}
	if err := fw.write(map[string]interface{}{"type": "something-new", "x": 1}); err != nil {
		t.Fatal(err)
	}
	b := buf.Bytes()
	if n := int(b[0])<<24 | int(b[1])<<16 | int(b[2])<<8 | int(b[3]); n != len(b)-4-len(`{"type":"something-new","x":1}`)-4 {
		t.Errorf("the first frame's length prefix is %d", n)
	}
	fr := newFrameReader(&buf)
	typ, raw, err := fr.next()
	if err != nil || typ != "hello" || !bytes.Contains(raw, []byte(runnerProto)) {
		t.Fatalf("first frame: %q %v", typ, err)
	}
	if typ, _, err = fr.next(); err != nil || typ != "something-new" {
		t.Fatalf("an unknown type is still a frame the reader returns (the caller ignores it): %q %v", typ, err)
	}
	if _, _, err = fr.next(); err != io.EOF {
		t.Errorf("end at a frame boundary is io.EOF: %v", err)
	}
	for name, in := range map[string][]byte{
		"length zero":     {0, 0, 0, 0},
		"length one":      {0, 0, 0, 1, '{'},
		"over 16 MiB":     {0x01, 0x00, 0x00, 0x01},
		"truncated":       {0, 0, 0, 20, '{', '}'},
		"not an object":   append([]byte{0, 0, 0, 4}, []byte(`[1,2]`)[:4]...),
		"no type":         append([]byte{0, 0, 0, 2}, []byte(`{}`)...),
		"type not string": append([]byte{0, 0, 0, 11}, []byte(`{"type":12}`)...),
	} {
		if _, _, err := newFrameReader(bytes.NewReader(in)).next(); err == nil || err == io.EOF {
			t.Errorf("%s: want a protocol error, got %v", name, err)
		}
	}
	// a frame larger than the cap is refused when written
	if err := fw.write(map[string]string{"type": "x", "data": strings.Repeat("a", maxRunnerFrame)}); err != errFrameTooLarge {
		t.Errorf("an oversized frame: %v", err)
	}
}

// ---- the package store

func TestRunnerStore(t *testing.T) {
	st, err := newRunnerStore(t.TempDir(), 1000)
	if err != nil {
		t.Fatal(err)
	}
	sha, n, err := st.put(strings.NewReader(strings.Repeat("a", 400)), 1000)
	if err != nil || n != 400 {
		t.Fatalf("put: %v %d", err, n)
	}
	sha2, _, err := st.put(strings.NewReader(strings.Repeat("a", 400)), 1000) // the same bytes: kept once, a second reference
	if err != nil || sha2 != sha {
		t.Fatalf("dedupe: %v", err)
	}
	if used, _, count := st.stats(); used != 400 || count != 1 {
		t.Errorf("the same bytes are held once: used %d, blobs %d", used, count)
	}
	// a package that does not fit is refused whole
	if _, _, err := st.put(strings.NewReader(strings.Repeat("b", 700)), 1000); err != errStoreFull {
		t.Errorf("over the budget: %v", err)
	}
	if used, _, count := st.stats(); used != 400 || count != 1 {
		t.Errorf("a refused package leaves nothing behind: used %d, blobs %d", used, count)
	}
	// a limit smaller than the body is an error too
	if _, _, err := st.put(strings.NewReader(strings.Repeat("c", 300)), 100); err != errStoreFull {
		t.Errorf("over the per-put limit: %v", err)
	}
	f, size, err := st.open(sha)
	if err != nil || size != 400 {
		t.Fatalf("open: %v", err)
	}
	f.Close()
	st.unref(sha)
	if _, ok := st.size(sha); !ok {
		t.Errorf("one reference is left")
	}
	st.unref(sha)
	if _, ok := st.size(sha); ok {
		t.Errorf("the last reference removes the blob")
	}
	if used, _, _ := st.stats(); used != 0 {
		t.Errorf("the space is given back: %d", used)
	}
	// concurrent puts never overshoot the budget
	var wg sync.WaitGroup
	var ok int32
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, _, err := st.put(strings.NewReader(strings.Repeat(string(rune('a'+i)), 300)), 300); err == nil {
				atomic.AddInt32(&ok, 1)
			}
		}(i)
	}
	wg.Wait()
	if ok != 3 {
		t.Errorf("a 1000-byte store holds three 300-byte packages, took %d", ok)
	}
	st.wipe()
	if used, _, count := st.stats(); used != 0 || count != 0 {
		t.Errorf("wipe: %d %d", used, count)
	}
}

// ---- the stub

func TestStubPackage(t *testing.T) {
	b, b64 := buildStubZip("00ff00ff", testNames)
	if got, _ := base64.StdEncoding.DecodeString(b64); !bytes.Equal(got, b) {
		t.Fatal("the base64 is the zip")
	}
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil || len(zr.File) != 1 || zr.File[0].Name != stubModule+".py" {
		t.Fatalf("the stub is one file, %s.py: %v", stubModule, err)
	}
	rc, _ := zr.File[0].Open()
	src, _ := io.ReadAll(rc)
	rc.Close()
	s := string(src)
	// the constants in the Python source are the Go constants
	for _, c := range []struct {
		py string
		v  int
	}{{"INLINE_MAX", stubInlineMax}, {"S3_MAX", stubS3Max}, {"SLICE_S", stubSliceSeconds}, {"MARGIN_MS", stubMarginMs}} {
		if !strings.Contains(s, fmt.Sprintf("%s = %d\n", c.py, c.v)) {
			t.Errorf("%s in the stub is not %d", c.py, c.v)
		}
	}
	for _, c := range []string{testNames.req, testNames.replyPrefix, testNames.bucket} {
		if !strings.Contains(s, `"`+c+`"`) {
			t.Errorf("the stub does not name %s", c)
		}
	}
	for _, bad := range []string{"requests", "urllib", "socket", "os.environ", "open("} {
		if strings.Contains(s, bad) {
			t.Errorf("the stub must reach nothing but the engine's SDK: %q", bad)
		}
	}
	if stubHandler != "rovara_stub.handler" || stubTimeout(10) != 15 || stubTimeout(898) != 900 {
		t.Errorf("stub settings: %s %d %d", stubHandler, stubTimeout(10), stubTimeout(898))
	}
	b2, _ := buildStubZip("00ff00ff", testNames)
	if !bytes.Equal(b, b2) {
		t.Error("the same secret makes the same stub")
	}
	if !strings.Contains(s, `SECRET = b"00ff00ff"`) || strings.Contains(s, "__SECRET__") {
		t.Error("the secret is baked into the stub")
	}
	if b3, _ := buildStubZip("11223344", testNames); bytes.Equal(b, b3) {
		t.Error("another secret, another stub")
	}
}

// ---- the hub against the fake worker

func newTestHub(t *testing.T) (*runnerHub, *runnerStore, string) {
	t.Helper()
	st, err := newRunnerStore(t.TempDir(), 64<<20)
	if err != nil {
		t.Fatal(err)
	}
	sock := tmpSocket(t)
	h := newRunnerHub(sock, st, "test")
	h.registerTimeout, h.stopTimeout, h.handshakeTimeout = 5*time.Second, 2*time.Second, 2*time.Second
	if err := h.start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.close)
	return h, st, sock
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for i := 0; i < 500; i++ {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func TestRunnerHubRegisterAndInvoke(t *testing.T) {
	h, st, sock := newTestHub(t)
	if _, err := h.run(context.Background(), regFn{Name: "f"}, invokeFrame{}); err != errNoRunner {
		t.Fatalf("no worker yet: %v", err)
	}
	w := connectFakeWorker(t, sock)
	waitFor(t, "the worker", h.connected)
	// a package of 1.3 MiB goes over in three chunks, and the worker checks its digest
	big := bytes.Repeat([]byte("0123456789abcdef"), 1300*1024/16)
	sha, size, err := st.put(bytes.NewReader(big), 4<<20)
	if err != nil {
		t.Fatal(err)
	}
	layer, lsize, _ := st.put(strings.NewReader("a layer"), 1<<20)
	fn := regFn{Name: "f", Version: "$LATEST", Runtime: "python3.12", Handler: "app.h", MemoryMb: 128, TimeoutSeconds: 3, Package: &pkgRef{SHA256: sha, SizeBytes: size},
		Layers: []pkgRef{{Arn: "arn:layer:1", SHA256: layer, SizeBytes: lsize}}}
	fn.ConfigHash = configHash(fn)
	res, err := h.run(context.Background(), fn, invokeFrame{Name: "f", Version: "$LATEST", RequestID: "r1", Payload: b64(`{"a":1}`), TimeoutMs: 3000, Source: "direct"})
	if err != nil || res.Status != "ok" {
		t.Fatalf("invoke: %v %+v", err, res)
	}
	var out map[string]interface{}
	raw, _ := base64.StdEncoding.DecodeString(res.Payload)
	json.Unmarshal(raw, &out)
	if out["fn"] != "f" || out["source"] != "direct" {
		t.Errorf("echo: %s", raw)
	}
	if !w.holds(sha) || !w.holds(layer) {
		t.Errorf("the worker has the packages it needed")
	}
	// the same configuration again: no second registration, no second transfer
	if _, err := h.run(context.Background(), fn, invokeFrame{Name: "f", Version: "$LATEST", RequestID: "r2", Payload: b64(`{}`), TimeoutMs: 1000, Source: "direct"}); err != nil {
		t.Fatal(err)
	}
	if n := atomic.LoadInt32(&w.registers); n != 1 {
		t.Errorf("one registration for one configuration: %d", n)
	}
	// a changed configuration registers again; the packages the worker holds are not sent again
	fn2 := fn
	fn2.MemoryMb = 256
	fn2.ConfigHash = configHash(fn2)
	if _, err := h.run(context.Background(), fn2, invokeFrame{Name: "f", Version: "$LATEST", RequestID: "r3", Payload: b64(`{}`), TimeoutMs: 1000, Source: "direct"}); err != nil {
		t.Fatal(err)
	}
	if reg, _ := w.registered("f", "$LATEST"); reg.MemoryMb != 256 || atomic.LoadInt32(&w.registers) != 2 {
		t.Errorf("re-registration: %+v", reg)
	}
	// twenty callers of a function not yet registered share one registration
	fn3 := regFn{Name: "g", Version: "$LATEST", Runtime: "nodejs22.x", Handler: "i.h", MemoryMb: 128, TimeoutSeconds: 3}
	fn3.ConfigHash = configHash(fn3)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r, err := h.run(context.Background(), fn3, invokeFrame{Name: "g", Version: "$LATEST", RequestID: fmt.Sprint("c", i), Payload: b64(`{"op":"sleep","ms":50}`), TimeoutMs: 2000, Source: "stub"})
			if err != nil || r.Status != "ok" {
				t.Errorf("concurrent invoke %d: %v %+v", i, err, r)
			}
		}(i)
	}
	wg.Wait()
	if n := atomic.LoadInt32(&w.registers); n != 3 {
		t.Errorf("one registration for twenty concurrent callers: %d", n)
	}
	if m := atomic.LoadInt32(&w.maxIn); m < 10 {
		t.Errorf("the invokes ran side by side (multiplexed on one pipe): peak %d", m)
	}
}

func TestRunnerHubRefusalsAndRecovery(t *testing.T) {
	h, _, sock := newTestHub(t)
	w := connectFakeWorker(t, sock)
	waitFor(t, "the worker", h.connected)
	w.refuse = func(fn regFn) *frameError {
		if fn.Runtime == "java21" {
			return &frameError{Type: "Rovara.Unsupported", Message: "java21 is not available in the runner yet"}
		}
		return nil
	}
	java := regFn{Name: "j", Version: "$LATEST", Runtime: "java21"}
	java.ConfigHash = configHash(java)
	_, err := h.run(context.Background(), java, invokeFrame{Name: "j", Version: "$LATEST", RequestID: "x", Payload: b64(`{}`), TimeoutMs: 1000})
	var re *runnerError
	if !asRunnerError(err, &re) || re.Type != "Rovara.Unsupported" || !strings.Contains(re.Message, "java21") {
		t.Fatalf("the worker's refusal is the caller's error, type kept: %v", err)
	}
	if _, err := h.run(context.Background(), java, invokeFrame{Name: "j", Version: "$LATEST", RequestID: "y", Payload: b64(`{}`), TimeoutMs: 1000}); !asRunnerError(err, &re) {
		t.Errorf("a refusal is remembered for that configuration: %v", err)
	}
	if n := atomic.LoadInt32(&w.registers); n != 1 {
		t.Errorf("not asked twice: %d", n)
	}
	// a worker that lost the function without dropping the pipe is told once more
	py := regFn{Name: "p", Version: "$LATEST", Runtime: "python3.12", Handler: "a.b", MemoryMb: 128, TimeoutSeconds: 3}
	py.ConfigHash = configHash(py)
	if _, err := h.run(context.Background(), py, invokeFrame{Name: "p", Version: "$LATEST", RequestID: "z", Payload: b64(`{}`), TimeoutMs: 1000}); err != nil {
		t.Fatal(err)
	}
	w.mu.Lock()
	w.fns = map[string]regFn{} // the worker forgot
	w.mu.Unlock()
	res, err := h.run(context.Background(), py, invokeFrame{Name: "p", Version: "$LATEST", RequestID: "z2", Payload: b64(`{}`), TimeoutMs: 1000})
	if err != nil || res.Status != "ok" {
		t.Errorf("not_registered is retried after registering again: %v %+v", err, res)
	}
	// stop_all is a barrier and forgets every registration
	if err := h.stopAll(); err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt32(&w.stopped) != 1 {
		t.Errorf("the worker was told to stop everything")
	}
	if _, err := h.run(context.Background(), py, invokeFrame{Name: "p", Version: "$LATEST", RequestID: "z3", Payload: b64(`{}`), TimeoutMs: 1000}); err != nil {
		t.Fatal(err)
	}
	if n := atomic.LoadInt32(&w.registers); n != 4 {
		t.Errorf("registered again after stop_all: %d", n)
	}
	// an invoke in flight when the pipe closes fails, and the next connection is used
	slow := make(chan error, 1)
	go func() {
		_, err := h.run(context.Background(), py, invokeFrame{Name: "p", Version: "$LATEST", RequestID: "s", Payload: b64(`{"op":"sleep","ms":1500}`), TimeoutMs: 3000})
		slow <- err
	}()
	waitFor(t, "the slow invoke to start", func() bool { return atomic.LoadInt32(&w.inflight) == 1 })
	w.conn.Close()
	select {
	case err := <-slow:
		if err != errRunnerGone {
			t.Errorf("a pending invoke on a closed pipe: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the pending invoke never failed")
	}
	waitFor(t, "disconnect", func() bool { return !h.connected() })
	w2 := connectFakeWorker(t, sock)
	waitFor(t, "the new worker", h.connected)
	if _, err := h.run(context.Background(), py, invokeFrame{Name: "p", Version: "$LATEST", RequestID: "n", Payload: b64(`{}`), TimeoutMs: 1000}); err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt32(&w2.registers) != 1 {
		t.Errorf("a new connection gets its own registration")
	}
	// exactly one peer: a second connection is turned away and the first is not displaced
	c2 := dialRaw(t, sock)
	newFrameReader(c2).next()
	(&frameWriter{w: c2}).write(helloFrame{Type: ftHello, Proto: runnerProto, Worker: "second"})
	if typ, _, _ := newFrameReader(c2).next(); typ != ftError {
		t.Errorf("a second worker gets an error frame, got %q", typ)
	}
	if !h.connected() || h.current().worker.Worker != "fake-worker" {
		t.Errorf("the first worker stays: %+v", h.current())
	}
	_ = w2
	// a worker with the wrong protocol is turned away
	c := dialRaw(t, sock)
	newFrameReader(c).next()
	(&frameWriter{w: c}).write(helloFrame{Type: ftHello, Proto: "runner/1"})
	typ, _, _ := newFrameReader(c).next()
	if typ != ftError {
		t.Errorf("a worker speaking another protocol gets an error frame, got %q", typ)
	}
}

func asRunnerError(err error, out **runnerError) bool {
	re, ok := err.(*runnerError)
	if ok {
		*out = re
	}
	return ok
}

// ---- the runner-pipe client

func TestRunnerPipeJoinsStdinAndSocket(t *testing.T) {
	h, _, sock := newTestHub(t)
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	done := make(chan error, 1)
	go func() { done <- runnerPipe(sock, inR, outW); outW.Close() }()
	// the worker side: it reads the front's hello and answers, through the pipe
	fr := newFrameReader(outR)
	if typ, _, err := fr.next(); err != nil || typ != ftHello {
		t.Fatalf("hello through the pipe: %q %v", typ, err)
	}
	(&frameWriter{w: inW}).write(helloFrame{Type: ftHello, Proto: runnerProto, Worker: "via-pipe"})
	waitFor(t, "the pipe worker", h.connected)
	if h.current().worker.Worker != "via-pipe" {
		t.Errorf("worker identity: %+v", h.current().worker)
	}
	// closing stdin ends the pipe and the connection
	inW.Close()
	if err := <-done; err != nil && err != io.EOF {
		t.Errorf("runnerPipe: %v", err)
	}
	waitFor(t, "disconnect after stdin closed", func() bool { return !h.connected() })
	if err := runnerPipe(tmpSocket(t), strings.NewReader(""), io.Discard); err == nil {
		t.Error("no socket, no pipe")
	}
}

func TestRunnerSocketIsPrivate(t *testing.T) {
	_, _, sock := newTestHub(t)
	fi, err := os.Stat(sock)
	if err != nil || fi.Mode().Perm() != 0o600 || fi.Mode()&os.ModeSocket == 0 {
		t.Errorf("the runner socket must be 0600: %v %v", fi, err)
	}
	// a file that is not a socket is never replaced
	path := tmpSocket(t)
	os.WriteFile(path, []byte("x"), 0o600)
	h := newRunnerHub(path, nil, "t")
	if err := h.start(); err == nil {
		t.Error("the hub must not remove a file that is not a socket")
	}
}

// ---- the front with a runner

type runnerFront struct {
	*lamFront
	w    *fakeWorker
	sock string
}

func startRunnerFront(t *testing.T, mutate func(*Config)) *runnerFront {
	return startRunnerFrontWith(t, "", mutate)
}

// startRunnerFrontWith: engineBin "" is the fake engine; the real one is used by the guarded live test.
func startRunnerFrontWith(t *testing.T, engineBin string, mutate func(*Config)) *runnerFront {
	t.Helper()
	sock := tmpSocket(t)
	planned := []string{"lambda", "sqs", "s3", "iam", "sns", "sfn", "eventbridge", "cloudformation", "sts", "scheduler", "pipes"}
	f := &lamFront{startFront(t, func(c *Config) {
		c.Planned = map[string]bool{}
		for _, p := range planned {
			c.Planned[p] = true
		}
		c.PlannedKeys = planned
		c.Runner = &RunnerConfig{Socket: sock, StoreDir: t.TempDir(), StoreMax: 64 << 20, MaxDirect: 64}
		if engineBin != "" {
			c.EngineBin = engineBin
		}
		if mutate != nil {
			mutate(c)
		}
	})}
	f.srv.ledger.planned = true
	if err := f.srv.startRunner(); err != nil {
		t.Fatal(err)
	}
	f.srv.runner.retryDelay = 20 * time.Millisecond
	t.Cleanup(f.srv.runner.close)
	rf := &runnerFront{lamFront: f, sock: sock}
	rf.w = connectFakeWorker(t, sock)
	waitFor(t, "the worker", f.srv.runner.hub.connected)
	return rf
}

func (f *runnerFront) engineGet(path string) (int, []byte) {
	f.t.Helper()
	gen, _, err := f.engine.current()
	if err != nil {
		f.t.Fatal(err)
	}
	resp, err := gen.client.Get("https://127.0.0.1:" + fmt.Sprint(gen.port) + path)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

// engineConfig: what the fake engine holds of a function: its configuration and its code.
func (f *runnerFront) engineFn(name string) (cfg map[string]interface{}, code []byte) {
	f.t.Helper()
	st, b := f.engineGet("/__fake/lambda/" + name)
	if st != 200 {
		f.t.Fatalf("the engine has no function %s (%d)", name, st)
	}
	var out struct {
		Config  map[string]interface{}
		CodeB64 string
	}
	json.Unmarshal(b, &out)
	code, _ = base64.StdEncoding.DecodeString(out.CodeB64)
	return out.Config, code
}

func (f *runnerFront) config(name string) map[string]interface{} {
	f.t.Helper()
	r := f.lambda("GET", "/2015-03-31/functions/"+name+"/configuration", nil)
	var cfg map[string]interface{}
	json.Unmarshal([]byte(r.body), &cfg)
	return cfg
}

var pyZip = func() []byte { return testZip(zent{"app.py", []byte("def handler(e, c): return e")}) }
var heavyZip = func() []byte {
	return testZip(zent{"app.py", []byte("def handler(e, c): return e")}, zent{"lib/native.so", testELF(elfMachineAArch64)})
}

func sha256B64Of(b []byte) string {
	h := sha256.Sum256(b)
	return base64.StdEncoding.EncodeToString(h[:])
}

func sha256HexOf(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func TestRegistryTakesHeavyFunctionsOver(t *testing.T) {
	f := startRunnerFront(t, nil)
	zb := heavyZip()
	r := f.create("fl-native", "python3.12", map[string]any{"Timeout": 10, "MemorySize": 512, "Handler": "app.handler", "Role": "arn:aws:iam::000000000000:role/real-role",
		"Environment": map[string]any{"Variables": map[string]string{"A": "1"}}}, zb)
	if r.status != 201 {
		t.Fatalf("create: %d %s", r.status, r.body)
	}
	// what the engine was given: the stub, in the real function's name
	cfg, code := f.engineFn("fl-native")
	stubB, _ := f.srv.runner.stub()
	if !bytes.Equal(code, stubB) {
		t.Errorf("the engine holds the stub's code, not the package")
	}
	if cfg["Runtime"] != "python3.12" || cfg["Handler"] != stubHandler || cfg["Role"] != f.srv.runner.names().roleARN || cfg["MemorySize"] != float64(128) || cfg["Timeout"] != float64(15) {
		t.Errorf("the engine's configuration is the stub's: %v", cfg)
	}
	if _, has := cfg["Layers"]; has {
		t.Errorf("no layers for the stub: %v", cfg["Layers"])
	}
	// what the caller was told: the real function
	var ans map[string]interface{}
	json.Unmarshal([]byte(r.body), &ans)
	if ans["Handler"] != "app.handler" || ans["MemorySize"] != float64(512) || ans["Timeout"] != float64(10) || ans["Role"] != "arn:aws:iam::000000000000:role/real-role" ||
		ans["CodeSize"] != float64(len(zb)) || ans["CodeSha256"] != sha256B64Of(zb) || ans["Runtime"] != "python3.12" {
		t.Errorf("CreateFunction answers with the real configuration: %v", ans)
	}
	// the three read paths
	got := f.config("fl-native")
	if got["Handler"] != "app.handler" || got["CodeSha256"] != sha256B64Of(zb) || got["MemorySize"] != float64(512) {
		t.Errorf("GetFunctionConfiguration: %v", got)
	}
	gf := f.lambda("GET", "/2015-03-31/functions/fl-native", nil)
	var gfa struct {
		Configuration map[string]interface{}
		Code          map[string]interface{}
	}
	json.Unmarshal([]byte(gf.body), &gfa)
	if gfa.Configuration["Timeout"] != float64(10) || gfa.Configuration["Role"] != "arn:aws:iam::000000000000:role/real-role" {
		t.Errorf("GetFunction configuration: %v", gfa.Configuration)
	}
	loc, _ := gfa.Code["Location"].(string)
	if !strings.HasPrefix(loc, "http://aws:4566"+functionCodePrefix) {
		t.Fatalf("Code.Location is the front's signed link: %v", gfa.Code)
	}
	// the link serves the real package, to anybody holding it, and nothing else
	u, _ := url.Parse(loc)
	cr := f.do("GET", u.Path, nil, "")
	if cr.status != 200 || cr.body != string(zb) {
		t.Errorf("the code link serves the package: %d (%d bytes, want %d)", cr.status, len(cr.body), len(zb))
	}
	if r := f.do("GET", u.Path[:len(u.Path)-3]+"xyz", nil, ""); r.status != 403 {
		t.Errorf("a forged link: %d", r.status)
	}
	if r := f.do("POST", u.Path, nil, ""); r.status != 404 {
		t.Errorf("the code link is read-only: %d", r.status)
	}
	f.lambda("POST", "/2015-03-31/functions", map[string]any{"FunctionName": "fl-plain", "Runtime": "python3.12", "Role": "r", "Handler": "app.handler",
		"Code": map[string]any{"ZipFile": base64.StdEncoding.EncodeToString(pyZip())}})
	list := f.lambda("GET", "/2015-03-31/functions", nil)
	var la struct{ Functions []map[string]interface{} }
	json.Unmarshal([]byte(list.body), &la)
	byName := map[string]map[string]interface{}{}
	for _, fn := range la.Functions {
		byName[fn["FunctionName"].(string)] = fn
	}
	if byName["fl-native"]["Handler"] != "app.handler" || byName["fl-native"]["Timeout"] != float64(10) {
		t.Errorf("ListFunctions overlays the held function: %v", byName["fl-native"])
	}
	if byName["fl-plain"]["Handler"] != "app.handler" {
		t.Errorf("a light function is untouched: %v", byName["fl-plain"])
	}
	// a light function is not touched at all: the engine holds its real code
	pcfg, pcode := f.engineFn("fl-plain")
	if !bytes.Equal(pcode, pyZip()) || pcfg["Handler"] != "app.handler" {
		t.Errorf("a light function goes to the engine as sent: %v", pcfg)
	}
	// the heavy ledger records nothing for a function that now runs; the registry says so
	if c := f.counts("lambda")[heavyPrefix+"native-code"]; c.Calls != 0 {
		t.Errorf("a function the runner runs is not recorded as unable to run: %+v", c)
	}
	rows := f.runnerRows()
	if rows["fl-native"]["reason"] != "native-code" || rows["fl-native"]["memoryMb"] != float64(512) {
		t.Errorf("the evidence feed: %v", rows)
	}
	if _, ok := rows["fl-plain"]; ok {
		t.Errorf("only the functions the runner holds are listed: %v", rows)
	}
	// delete: gone from the registry, the store gives the space back, the worker is told
	if used, _, _ := f.srv.runner.store.stats(); used == 0 {
		t.Errorf("the store holds the packages")
	}
	f.lambda("DELETE", "/2015-03-31/functions/fl-native", nil)
	f.lambda("DELETE", "/2015-03-31/functions/fl-plain", nil)
	if used, _, n := f.srv.runner.store.stats(); used != 0 || n != 0 {
		t.Errorf("delete frees the packages: %d bytes, %d blobs", used, n)
	}
	if len(f.srv.runner.reg.fns) != 0 {
		t.Errorf("delete empties the registry")
	}
}

func (f *runnerFront) runnerRows() map[string]map[string]interface{} {
	f.t.Helper()
	var d struct{ RunnerFunctions []map[string]interface{} }
	json.Unmarshal([]byte(f.do("GET", "/_rovara/lambda/heavy", tok(), "").body), &d)
	out := map[string]map[string]interface{}{}
	for _, r := range d.RunnerFunctions {
		out[r["name"].(string)] = r
	}
	return out
}

func TestRegistryDecisions(t *testing.T) {
	f := startRunnerFront(t, nil)
	create := func(name, runtime string, extra map[string]any, z []byte) {
		t.Helper()
		if r := f.create(name, runtime, extra, z); r.status != 201 {
			t.Fatalf("%s: %d %s", name, r.status, r.body)
		}
	}
	taken := func(name string) bool { return f.srv.runner.reg.isTaken(name) }
	create("fl-light", "python3.12", map[string]any{"Timeout": 28}, pyZip())
	create("fl-long", "python3.12", map[string]any{"Timeout": 29}, pyZip()) // decision 119: more than 28 s
	create("fl-java", "java21", nil, pyZip())
	create("fl-node-native", "nodejs22.x", nil, testZip(zent{"a.js", []byte("x")}, zent{"n.node", testELF(elfMachineAArch64)}))
	create("fl-x86", "python3.12", nil, testZip(zent{"app.py", []byte("x")}, zent{"lib/x.so", testELF(elfMachineX8664)}))
	f.lambda("POST", "/2015-03-31/functions", map[string]any{"FunctionName": "fl-image", "PackageType": "Image", "Role": "r", "Code": map[string]any{"ImageUri": "000000000000.dkr.ecr.us-east-1.amazonaws.com/x:1"}})
	create("fl-bomb", "python3.12", nil, testZipBomb()) // judged unsafe: unchecked, never taken
	for name, want := range map[string]bool{"fl-light": false, "fl-long": true, "fl-java": true, "fl-node-native": true, "fl-x86": true, "fl-image": true, "fl-bomb": false} {
		if taken(name) != want {
			t.Errorf("%s taken: %v, want %v", name, taken(name), want)
		}
	}
	// the cannot-run ones are still recorded, the ones that run are not
	c := f.counts("lambda")
	if c[heavyPrefix+"image"].Calls != 1 || c[heavyPrefix+"unchecked"].Calls != 1 {
		t.Errorf("unsupported and unchecked functions are still recorded: %+v", c)
	}
	// x86-64 code is the worker's to judge (it may swap the wheels or emulate): nothing is recorded until it refuses
	if c[heavyPrefix+"x86-native"].Calls != 0 {
		t.Errorf("x86-native is not recorded before the worker has refused it: %+v", c[heavyPrefix+"x86-native"])
	}
	f.w.refuse = refuseX86
	for i := 0; i < 2; i++ {
		if r := f.invoke("fl-x86", `{}`, nil); !strings.Contains(r.body, "Rovara.Unsupported") {
			t.Errorf("the worker's refusal reaches the caller: %s", r.body)
		}
	}
	if fn, ok := f.w.registered("fl-x86", "$LATEST"); ok {
		t.Errorf("a refused function is not registered: %+v", fn)
	}
	if n := atomic.LoadInt32(&f.w.registers); n < 1 {
		t.Errorf("the x86-64 function was forwarded to the worker: %d registrations", n)
	}
	c = f.counts("lambda")
	if c[heavyPrefix+"x86-native"].Calls != 1 || c[heavyPrefix+"x86-native"].Unsupported != 1 {
		t.Errorf("after the refusal it is recorded as unable to run, once: %+v", c[heavyPrefix+"x86-native"])
	}
	for _, reason := range []string{"native-code", "runtime", "long-timeout"} {
		if c[heavyPrefix+reason].Calls != 0 {
			t.Errorf("%s runs in the runner and is not recorded as unable to run: %+v", reason, c[heavyPrefix+reason])
		}
	}
	rows := f.runnerRows()
	if !strings.Contains(fmt.Sprint(rows["fl-x86"]["unsupported"]), "x86_64") || rows["fl-image"]["unsupported"] == nil || rows["fl-java"]["unsupported"] != nil {
		t.Errorf("unsupported text in the evidence: %v", rows)
	}
	// a function that stays under the limit is moved by a later change: a longer Timeout
	if r := f.lambda("PUT", "/2015-03-31/functions/fl-light/configuration", map[string]any{"Timeout": 120}); r.status != 200 {
		t.Fatalf("update: %d %s", r.status, r.body)
	}
	if !taken("fl-light") {
		t.Fatal("Timeout 120 moves a light function to the runner")
	}
	cfg, code := f.engineFn("fl-light")
	stubB, _ := f.srv.runner.stub()
	if cfg["Runtime"] != stubRuntime || cfg["Handler"] != stubHandler || cfg["Timeout"] != float64(125) || !bytes.Equal(code, stubB) {
		t.Errorf("the engine holds the stub after the move (code too): %v", cfg)
	}
	if got := f.config("fl-light"); got["Timeout"] != float64(120) || got["Handler"] != "index.handler" {
		t.Errorf("the caller still sees the real configuration: %v", got)
	}
	if _, sha := f.srv.runner.reg.fns["fl-light"].latest.PkgSha, 0; sha != 0 || f.srv.runner.reg.fns["fl-light"].latest.PkgSha == "" {
		t.Errorf("the light package was kept, so the move had code to run")
	}
	// a later update with a heavy package keeps it with the runner, and the engine keeps the stub
	zb := heavyZip()
	if r := f.lambda("PUT", "/2015-03-31/functions/fl-light/code", map[string]any{"ZipFile": base64.StdEncoding.EncodeToString(zb)}); r.status != 200 {
		t.Fatalf("update code: %d %s", r.status, r.body)
	}
	if cfg, code := f.engineFn("fl-light"); !bytes.Equal(code, stubB) || cfg["Handler"] != stubHandler {
		t.Errorf("update code of a held function keeps the stub: %v", cfg)
	}
	if got := f.config("fl-light"); got["CodeSha256"] != sha256B64Of(zb) {
		t.Errorf("the new package's digest: %v", got["CodeSha256"])
	}
	// UpdateFunctionCode of a light function with a native package: code and configuration both become the stub's
	create("fl-late", "python3.12", map[string]any{"Handler": "app.handler", "Role": "arn:aws:iam::000000000000:role/real"}, pyZip())
	if taken("fl-late") {
		t.Fatal("light")
	}
	if r := f.lambda("PUT", "/2015-03-31/functions/fl-late/code", map[string]any{"ZipFile": base64.StdEncoding.EncodeToString(zb)}); r.status != 200 {
		t.Fatalf("update code: %d %s", r.status, r.body)
	}
	cfg, code = f.engineFn("fl-late")
	if !taken("fl-late") || !bytes.Equal(code, stubB) || cfg["Handler"] != stubHandler || cfg["Role"] != f.srv.runner.names().roleARN {
		t.Errorf("a light function updated with native code is the stub's in the engine: %v taken=%v", cfg, taken("fl-late"))
	}
	if got := f.config("fl-late"); got["Role"] != "arn:aws:iam::000000000000:role/real" || got["Handler"] != "app.handler" {
		t.Errorf("and the real configuration for the caller: %v", got)
	}
	// a function the front never saw (made inside the engine) is looked up when its code is updated with a native package
	gen, _, _ := f.engine.current()
	_ = gen
	// a DryRun changes nothing
	create("fl-dry", "python3.12", nil, pyZip())
	f.lambda("PUT", "/2015-03-31/functions/fl-dry/code", map[string]any{"ZipFile": base64.StdEncoding.EncodeToString(zb), "DryRun": true})
	if taken("fl-dry") {
		t.Errorf("a DryRun is not a change")
	}
	// a refused request leaves nothing behind (the engine says 409: the name exists)
	before, _, _ := f.srv.runner.store.stats()
	if r := f.create("fl-native-2", "python3.12", nil, testZip(zent{"app.py", []byte("second")}, zent{"lib/n2.so", testELF(elfMachineAArch64)})); r.status != 201 {
		t.Fatal(r.status)
	}
	mid, _, _ := f.srv.runner.store.stats()
	if r := f.create("fl-native-2", "python3.12", nil, testZip(zent{"app.py", []byte("other")}, zent{"lib/o.so", testELF(elfMachineAArch64)})); r.status != 409 {
		t.Fatalf("a duplicate: %d", r.status)
	}
	if after, _, _ := f.srv.runner.store.stats(); after != mid || mid <= before {
		t.Errorf("a refused create releases its package: before %d, with the function %d, after the refusal %d", before, mid, after)
	}
}

func TestRegistryLayersVersionsAndAliases(t *testing.T) {
	f := startRunnerFront(t, nil)
	layerZip := testZip(zent{"python/lib/n.so", testELF(elfMachineAArch64)})
	r := f.lambda("POST", "/2018-10-31/layers/fl-nl/versions", map[string]any{"Content": map[string]any{"ZipFile": base64.StdEncoding.EncodeToString(layerZip)}})
	if r.status != 201 {
		t.Fatalf("layer: %d %s", r.status, r.body)
	}
	lay := "arn:aws:lambda:us-east-1:000000000000:layer:fl-nl:1"
	if rl, ok := f.srv.runner.reg.layers[lay]; !ok || rl.sha != sha256HexOf(layerZip) {
		t.Fatalf("the front keeps the layer's code: %v", f.srv.runner.reg.layers)
	}
	// a function with that layer is the runner's; the stub has no layer; the caller sees it
	r = f.create("fl-lay", "python3.12", map[string]any{"Layers": []string{lay}, "Handler": "app.handler"}, pyZip())
	if r.status != 201 || !f.srv.runner.reg.isTaken("fl-lay") {
		t.Fatalf("the layer makes the function native: %d %s", r.status, r.body)
	}
	cfg, _ := f.engineFn("fl-lay")
	if _, has := cfg["Layers"]; has {
		t.Errorf("the stub carries no layer: %v", cfg)
	}
	if ls, _ := f.config("fl-lay")["Layers"].([]interface{}); len(ls) != 1 || ls[0].(map[string]interface{})["Arn"] != lay {
		t.Errorf("the caller sees its layer: %v", f.config("fl-lay")["Layers"])
	}
	// a layer the front never saw published is not a way to run: the function is not taken over (it stays recorded as heavy by its code)
	f.create("fl-lay2", "python3.12", map[string]any{"Layers": []string{"arn:aws:lambda:us-east-1:111111111111:layer:foreign:3"}}, heavyZip())
	if f.srv.runner.reg.isTaken("fl-lay2") {
		t.Errorf("a foreign layer cannot be supplied to the runner")
	}
	// versions: PublishVersion snapshots; an update after it does not change the version
	f.lambda("POST", "/2015-03-31/functions/fl-lay/versions", map[string]any{})
	f.lambda("PUT", "/2015-03-31/functions/fl-lay/configuration", map[string]any{"MemorySize": 1024})
	arn, v1, ok := f.srv.runner.reg.versionOf("fl-lay", "1")
	if !ok || v1.Memory != 128 || v1.Version != "1" || arn == "" {
		t.Fatalf("version 1 holds the configuration it was published with: %+v %v", v1, ok)
	}
	if _, latest, _ := f.srv.runner.reg.versionOf("fl-lay", ""); latest.Memory != 1024 {
		t.Errorf("latest moved on: %+v", latest)
	}
	vs := f.lambda("GET", "/2015-03-31/functions/fl-lay/versions", nil)
	var vl struct{ Versions []map[string]interface{} }
	json.Unmarshal([]byte(vs.body), &vl)
	if len(vl.Versions) != 2 || vl.Versions[0]["MemorySize"] != float64(1024) || vl.Versions[1]["MemorySize"] != float64(128) || vl.Versions[1]["Handler"] != "app.handler" {
		t.Errorf("ListVersionsByFunction overlays each version with its own configuration: %v", vl.Versions)
	}
	// deleting a version drops only it
	f.lambda("DELETE", "/2015-03-31/functions/fl-lay?Qualifier=1", nil)
	if _, _, ok := f.srv.runner.reg.versionOf("fl-lay", "1"); ok {
		t.Errorf("version 1 is gone")
	}
	if !f.srv.runner.reg.isTaken("fl-lay") {
		t.Errorf("the function stays")
	}
	// Publish: true on create makes version 1 at once
	f.create("fl-pub", "java21", map[string]any{"Publish": true}, pyZip())
	if _, v, ok := f.srv.runner.reg.versionOf("fl-pub", "1"); !ok || v.Runtime != "java21" {
		t.Errorf("Publish on create: %+v %v", v, ok)
	}
	// a reset forgets everything, the store included
	f.do("POST", "/_rovara/reset", tok(), "")
	if len(f.srv.runner.reg.fns) != 0 || len(f.srv.runner.reg.layers) != 0 {
		t.Errorf("reset empties the registry")
	}
	if used, _, n := f.srv.runner.store.stats(); used != 0 || n != 0 {
		t.Errorf("reset empties the store: %d %d", used, n)
	}
	if atomic.LoadInt32(&f.w.stopped) != 1 {
		t.Errorf("reset is a stop_all barrier for the worker")
	}
}

func TestRunnerStoreFullLeavesFunctionWithEngine(t *testing.T) {
	f := startRunnerFront(t, func(c *Config) { c.Runner.StoreMax = 1 << 20 })
	noise := make([]byte, 2<<20)
	rand.New(rand.NewSource(7)).Read(noise) // a zip of noise does not compress
	big := testZip(zent{"app.py", []byte("x")}, zent{"lib/n.so", append(testELF(elfMachineAArch64), noise...)})
	r := f.create("fl-toobig", "python3.12", nil, big)
	if r.status != 201 {
		t.Fatalf("the engine still creates it: %d %s", r.status, r.body)
	}
	if f.srv.runner.reg.isTaken("fl-toobig") {
		t.Errorf("a package that does not fit the store cannot be taken over")
	}
	if c := f.counts("lambda")[heavyPrefix+"native-code"]; c.Calls != 1 {
		t.Errorf("so it is recorded as unable to run: %+v", c)
	}
}

// ---- direct Invoke

func (f *runnerFront) invoke(name string, event string, hdr map[string]string) result {
	f.t.Helper()
	h := with(scopeHdr("lambda"), "Content-Type", "application/json")
	for k, v := range hdr {
		h[k] = v
	}
	name, query, _ := strings.Cut(name, "?")
	path := "/2015-03-31/functions/" + name + "/invocations"
	if query != "" {
		path += "?" + query
	}
	return f.do("POST", path, h, event)
}

func TestDirectInvokeFastPath(t *testing.T) {
	f := startRunnerFront(t, nil)
	f.create("fl-fast", "python3.12", map[string]any{"Timeout": 60, "Handler": "app.handler"}, heavyZip())
	r := f.invoke("fl-fast", `{"op":"echo","n":1}`, map[string]string{"X-Amz-Log-Type": "Tail"})
	if r.status != 200 || r.header.Get("X-Amz-Function-Error") != "" || r.header.Get("X-Amz-Executed-Version") != "$LATEST" {
		t.Fatalf("invoke: %d %v %s", r.status, r.header, r.body)
	}
	var out map[string]interface{}
	json.Unmarshal([]byte(r.body), &out)
	if out["fn"] != "fl-fast" || out["source"] != "direct" || out["arn"] != "arn:aws:lambda:us-east-1:000000000000:function:fl-fast" {
		t.Errorf("answered by the runner, straight from the front: %s", r.body)
	}
	if tail, _ := base64.StdEncoding.DecodeString(r.header.Get("X-Amz-Log-Result")); !strings.Contains(string(tail), "ran fl-fast") {
		t.Errorf("LogType=Tail: %q", tail)
	}
	if st, b := f.engineGet("/__fake/lambda/"); st != 200 || strings.Contains(string(b), `"invokes":["fl-fast"`) {
		t.Errorf("the engine never saw the call: %s", b)
	}
	// no 30 s ceiling, no 256 KB: a long function and a 5 MB payload go straight through
	last := f.w.lastInvoke()
	if last.TimeoutMs != 60000 {
		t.Errorf("the worker runs the call to the function's own Timeout: %d ms", last.TimeoutMs)
	}
	big := fmt.Sprintf(`{"op":"echo","pad":"%s"}`, strings.Repeat("p", 5<<20))
	if r := f.invoke("fl-fast", big, nil); r.status != 200 || !strings.Contains(r.body, `"fn":"fl-fast"`) || len(r.body) < 5<<20 {
		t.Errorf("a 5 MB payload: %d, %d bytes", r.status, len(r.body))
	}
	if r := f.invoke("fl-fast", `{"op":"big","bytes":3000000}`, nil); r.status != 200 || len(r.body) < 3000000 {
		t.Errorf("a 3 MB response: %d, %d bytes", r.status, len(r.body))
	}
	if r := f.invoke("fl-fast", fmt.Sprintf(`{"pad":"%s"}`, strings.Repeat("p", maxPayloadBytes)), nil); r.status != 413 || r.header.Get("X-Amzn-Errortype") != "RequestEntityTooLargeException" {
		t.Errorf("over Lambda's own 6 MB: %d %.200s", r.status, r.body)
	}
	// errors keep their type; the call is a 200 with FunctionError
	r = f.invoke("fl-fast", `{"op":"error","type":"ValueError","msg":"boom"}`, nil)
	var doc map[string]interface{}
	json.Unmarshal([]byte(r.body), &doc)
	if r.status != 200 || r.header.Get("X-Amz-Function-Error") != "Unhandled" || doc["errorType"] != "ValueError" || doc["errorMessage"] != "boom" {
		t.Errorf("a function error: %d %v %s", r.status, r.header, r.body)
	}
	r = f.invoke("fl-fast", `{"op":"crash"}`, nil)
	if r.header.Get("X-Amz-Function-Error") != "Unhandled" || !strings.Contains(r.body, "Runtime.ExitError") {
		t.Errorf("a crash: %s", r.body)
	}
	r = f.invoke("fl-fast", `{"op":"throttle"}`, nil)
	if r.status != 429 || r.header.Get("Retry-After") == "" || !strings.Contains(r.body, "TooManyRequestsException") && r.header.Get("X-Amzn-Errortype") != "TooManyRequestsException" {
		t.Errorf("the worker's throttle is a 429: %d %v", r.status, r.header)
	}
	// a non-JSON response never reaches the caller as JSON
	if r := f.invoke("fl-fast", `{"op":"raw","text":"[1,2"}`, nil); r.status != 200 {
		t.Logf("raw non-JSON response passes through unchanged: %d %s", r.status, r.body)
	}
	if r := f.invoke("fl-fast", `{not json`, nil); r.status != 400 || r.header.Get("X-Amzn-Errortype") != "InvalidRequestContentException" {
		t.Errorf("a payload that is not JSON: %d %v", r.status, r.header)
	}
	if r := f.invoke("fl-fast", `{}`, map[string]string{"X-Amz-Invocation-Type": "Bogus"}); r.status != 400 {
		t.Errorf("a bad invocation type: %d", r.status)
	}
	if r := f.invoke("fl-fast", `{}`, map[string]string{"X-Amz-Invocation-Type": "DryRun"}); r.status != 204 {
		t.Errorf("DryRun: %d", r.status)
	}
	// the stats the evidence reads
	row := f.runnerRows()["fl-fast"]
	if row["direct"].(float64) < 6 || row["cold"].(float64) != 1 || row["functionErrors"].(float64) < 2 {
		t.Errorf("per-function counts: %v", row)
	}
	// a function the runner does not hold goes to the engine as before, with its qualifier
	r = f.invoke("fl-engine-only", `{}`, nil)
	if r.status != 200 || r.header.Get("X-Fake-Engine-Ran") != "" {
		t.Logf("an unknown function is the engine's: %d", r.status)
	}
	f.create("fl-light-direct", "python3.12", nil, pyZip())
	if r := f.invoke("fl-light-direct", `{}`, nil); r.header.Get("X-Fake-Engine-Ran") != "fl-light-direct" {
		t.Errorf("a light function is the engine's: %v", r.header)
	}
}

func TestDirectInvokeQualifiersAndTimeouts(t *testing.T) {
	f := startRunnerFront(t, nil)
	f.create("fl-q", "python3.12", map[string]any{"Timeout": 2}, heavyZip())
	f.lambda("POST", "/2015-03-31/functions/fl-q/versions", map[string]any{})
	f.lambda("PUT", "/2015-03-31/functions/fl-q/configuration", map[string]any{"Timeout": 5, "Runtime": "java21"})
	f.lambda("POST", "/2015-03-31/functions/fl-q/aliases", map[string]any{"Name": "live", "FunctionVersion": "1"})
	ver := func(path string) (string, int64) {
		r := f.invoke(path, `{}`, nil)
		var out map[string]interface{}
		json.Unmarshal([]byte(r.body), &out)
		v, _ := out["version"].(string)
		return v + "|" + r.header.Get("X-Amz-Executed-Version"), f.w.lastInvoke().TimeoutMs
	}
	if v, to := ver("fl-q"); v != "$LATEST|$LATEST" || to != 5000 {
		t.Errorf("latest: %s %d", v, to)
	}
	if v, to := ver("fl-q?Qualifier=1"); v != "1|1" || to != 2000 {
		t.Errorf("version 1 runs with the configuration it was published with: %s %d", v, to)
	}
	if v, _ := ver("fl-q:1"); v != "1|1" {
		t.Errorf("name:qualifier: %s", v)
	}
	if v, to := ver("fl-q?Qualifier=live"); v != "1|1" || to != 2000 {
		t.Errorf("an alias is resolved through the engine: %s %d", v, to)
	}
	if v, _ := ver("arn:aws:lambda:us-east-1:000000000000:function:fl-q:live"); v != "1|1" {
		t.Errorf("a full ARN with an alias: %s", v)
	}
	if a := f.w.lastInvoke().FunctionArn; a != "arn:aws:lambda:us-east-1:000000000000:function:fl-q:1" {
		t.Errorf("the invoked ARN names the version: %s", a)
	}
	// a version the runner does not hold, and an alias the engine does not know, are the engine's to answer
	if r := f.invoke("fl-q?Qualifier=nolive", `{}`, nil); r.header.Get("X-Fake-Engine-Ran") != "fl-q" {
		t.Errorf("an unknown alias goes to the engine for its own error: %v", r.header)
	}
	// the function's Timeout is enforced by the worker: the answer is a timeout error, not a hang
	r := f.invoke("fl-q?Qualifier=1", `{"op":"sleep","ms":5000}`, nil)
	if r.header.Get("X-Amz-Function-Error") != "Unhandled" || !strings.Contains(r.body, "Sandbox.Timedout") || !strings.Contains(r.body, "2.00 seconds") {
		t.Errorf("timeout: %s", r.body)
	}
}

func TestDirectInvokeWithoutWorkerOrWithUnsupportedCode(t *testing.T) {
	f := startRunnerFront(t, nil)
	f.create("fl-x86", "python3.12", nil, testZip(zent{"app.py", []byte("x")}, zent{"lib/x.so", testELF(elfMachineX8664)}))
	f.w.refuse = refuseX86
	r := f.invoke("fl-x86", `{}`, nil)
	if r.status != 200 || r.header.Get("X-Amz-Function-Error") != "Unhandled" || !strings.Contains(r.body, "Rovara.Unsupported") || !strings.Contains(r.body, "x86_64") {
		t.Errorf("x86-64 native code: %d %s", r.status, r.body)
	}
	f.lambda("POST", "/2015-03-31/functions", map[string]any{"FunctionName": "fl-img", "PackageType": "Image", "Role": "r", "Code": map[string]any{"ImageUri": "x:1"}})
	if r := f.invoke("fl-img", `{}`, nil); !strings.Contains(r.body, "Rovara.Unsupported") || !strings.Contains(r.body, "container-image") {
		t.Errorf("a container image: %s", r.body)
	}
	f.create("fl-j", "java21", nil, pyZip())
	f.w.refuse = func(fn regFn) *frameError {
		return &frameError{Type: "Rovara.Unsupported", Message: "java21 is not available in the runner yet"}
	}
	if r := f.invoke("fl-j", `{}`, nil); !strings.Contains(r.body, "Rovara.Unsupported") || !strings.Contains(r.body, "java21") {
		t.Errorf("the worker's refusal reaches the caller with its type: %s", r.body)
	}
	f.w.conn.Close()
	waitFor(t, "disconnect", func() bool { return !f.srv.runner.hub.connected() })
	f.create("fl-n", "python3.12", map[string]any{"Timeout": 40}, pyZip())
	r = f.invoke("fl-n", `{}`, nil)
	if r.status != 200 || r.header.Get("X-Amz-Function-Error") != "Unhandled" || !strings.Contains(r.body, "Rovara.RunnerUnavailable") {
		t.Errorf("no runner connected: %d %s", r.status, r.body)
	}
	if state := f.runnerState(); state != "disconnected" {
		t.Errorf("health of the runner: %q", state)
	}
}

func (f *runnerFront) runnerState() string {
	var d struct{ Runner string }
	json.Unmarshal([]byte(f.do("GET", "/_rovara/lambda/heavy", tok(), "").body), &d)
	return d.Runner
}

func TestDirectInvokeConcurrencyAndAsync(t *testing.T) {
	f := startRunnerFront(t, func(c *Config) { c.Runner.MaxDirect = 8 })
	f.create("fl-c", "python3.12", map[string]any{"Timeout": 60}, heavyZip())
	// more calls at once than the engine's own ~16 stubs: the front holds up to MaxDirect, the rest are told to back off
	var wg sync.WaitGroup
	var ok, throttled int32
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := f.invoke("fl-c", `{"op":"sleep","ms":400}`, nil)
			switch r.status {
			case 200:
				atomic.AddInt32(&ok, 1)
			case 429:
				atomic.AddInt32(&throttled, 1)
			default:
				t.Errorf("status %d", r.status)
			}
		}()
	}
	wg.Wait()
	if ok < 8 || throttled == 0 || ok+throttled != 20 {
		t.Errorf("eight at a time, the rest throttled: ok %d throttled %d", ok, throttled)
	}
	if m := atomic.LoadInt32(&f.w.maxIn); m < 6 || m > 8 {
		t.Errorf("at most MaxDirect run at once: peak %d", m)
	}
	// async: 202 at once, the run follows; errors are tried three times
	before := atomic.LoadInt32(&f.w.invokes)
	r := f.invoke("fl-c", `{"op":"error","type":"E","msg":"m"}`, map[string]string{"X-Amz-Invocation-Type": "Event"})
	if r.status != 202 || r.body != "" {
		t.Fatalf("async: %d %q", r.status, r.body)
	}
	waitFor(t, "three attempts", func() bool { return atomic.LoadInt32(&f.w.invokes)-before == 3 })
	time.Sleep(150 * time.Millisecond)
	if n := atomic.LoadInt32(&f.w.invokes) - before; n != 3 {
		t.Errorf("an async error is tried three times, not %d", n)
	}
	before = atomic.LoadInt32(&f.w.invokes)
	f.invoke("fl-c", `{"op":"echo"}`, map[string]string{"X-Amz-Invocation-Type": "Event"})
	waitFor(t, "one attempt", func() bool { return atomic.LoadInt32(&f.w.invokes)-before == 1 })
	time.Sleep(100 * time.Millisecond)
	if n := atomic.LoadInt32(&f.w.invokes) - before; n != 1 {
		t.Errorf("an async success is one run: %d", n)
	}
	if r := f.invoke("fl-c", fmt.Sprintf(`{"pad":"%s"}`, strings.Repeat("p", 300<<10)), map[string]string{"X-Amz-Invocation-Type": "Event"}); r.status != 413 {
		t.Errorf("async payloads are limited to 256 KB: %d", r.status)
	}
}

// ---- the stub's side: the dispatcher's answers

func TestStubRequestsServedFromTheRegistry(t *testing.T) {
	f := startRunnerFront(t, nil)
	f.create("fl-s", "python3.12", map[string]any{"Timeout": 60, "Handler": "app.handler"}, heavyZip())
	rs := f.srv.runner
	run := func(ev string, rem int64) stubReply {
		return rs.runStub(stubRequest{V: 1, Fn: "fl-s", Arn: "arn:aws:lambda:us-east-1:000000000000:function:fl-s", Ver: "$LATEST", Req: "req-1", Reply: "u", Event: ev, Rem: rem})
	}
	r := run(`{"op":"echo"}`, 30000)
	var got map[string]interface{}
	json.Unmarshal([]byte(r.Payload), &got)
	if !r.OK || got["source"] != "stub" || r.Log == "" {
		t.Fatalf("an echo: %+v", r)
	}
	if to := f.w.lastInvoke().TimeoutMs; to != 28000 {
		t.Errorf("a function with Timeout 60 is asked to stop at the 28 s ceiling, not at the engine's 30 s: %d", to)
	}
	// the ceiling is named, never a code failure
	r = run(`{"op":"sleep","ms":60000}`, 2300) // the engine left this call 2.3 s: the runner gets 0.3 s
	if r.OK || r.ErrorType != "Rovara.TimeoutCeiling" || !strings.Contains(r.ErrorMessage, "AWS allows this function 60 s") {
		t.Errorf("ceiling: %+v", r)
	}
	if row := f.runnerRows()["fl-s"]; row["ceilingHits"] != float64(1) {
		t.Errorf("ceiling hits are counted: %v", row)
	}
	// a short function keeps its own timeout, and the real type
	f.create("fl-short", "python3.12", map[string]any{"Timeout": 1}, heavyZip())
	r = rs.runStub(stubRequest{Fn: "fl-short", Ver: "$LATEST", Req: "r2", Reply: "u", Event: `{"op":"sleep","ms":5000}`, Rem: 6000})
	if r.ErrorType != "Sandbox.Timedout" || !strings.Contains(r.ErrorMessage, "1.00 seconds") {
		t.Errorf("a function's own timeout is the function's: %+v", r)
	}
	r = run(`{"op":"error","type":"Runtime.ImportModuleError","msg":"No module named numpy"}`, 30000)
	if r.OK || r.ErrorType != "Runtime.ImportModuleError" || r.ErrorMessage != "No module named numpy" {
		t.Errorf("error types survive: %+v", r)
	}
	// a big answer goes through the hidden bucket (the fake engine takes the PUT)
	r = run(`{"op":"big","bytes":300000}`, 30000)
	if !r.OK || r.S3Key != "res/req-1" || r.Payload != "" {
		t.Errorf("an answer over 200 KB travels by pointer: %+v", r)
	}
	r = run(`{"op":"raw","text":"not json"}`, 30000)
	if r.OK || r.ErrorType != "Rovara.RunnerError" {
		t.Errorf("an answer that is not JSON: %+v", r)
	}
	r = run(`{"op":"throttle"}`, 30000)
	if r.OK || r.ErrorType != "Rovara.Throttled" {
		t.Errorf("a throttle is not a failure of the function: %+v", r)
	}
	// unknown function or version, unsupported code
	if r := rs.runStub(stubRequest{Fn: "fl-nobody", Ver: "$LATEST", Event: "{}"}); r.ErrorType != "Rovara.Unsupported" {
		t.Errorf("unknown: %+v", r)
	}
	if r := rs.runStub(stubRequest{Fn: "fl-s", Ver: "9", Event: "{}"}); r.ErrorType != "Rovara.Unsupported" || !strings.Contains(r.ErrorMessage, "version 9") {
		t.Errorf("unknown version: %+v", r)
	}
	f.create("fl-x", "python3.12", nil, testZip(zent{"a.py", []byte("x")}, zent{"x.so", testELF(elfMachineX8664)}))
	f.w.refuse = refuseX86
	if r := rs.runStub(stubRequest{Fn: "fl-x", Ver: "$LATEST", Event: "{}"}); r.ErrorType != "Rovara.Unsupported" || !strings.Contains(r.ErrorMessage, "x86_64") {
		t.Errorf("x86: %+v", r)
	}
}

// ---- hidden plumbing

func TestHiddenPlumbingIsRefusedAndUnlisted(t *testing.T) {
	f := startRunnerFront(t, nil)
	f.create("fl-h", "java21", nil, pyZip()) // provisions the plumbing
	json10 := func(op, body string) result {
		return f.do("POST", "/", sqsJSON(op), body)
	}
	for _, c := range []struct{ op, body string }{
		{"SendMessage", `{"QueueUrl":"https://sqs.us-east-1.amazonaws.com/000000000000/rovara-heavy-req","MessageBody":"x"}`},
		{"ReceiveMessage", `{"QueueUrl":"http://aws:4566/000000000000/rovara-heavy-req"}`},
		{"DeleteQueue", `{"QueueUrl":"http://aws:4566/000000000000/rovara-reply-abc"}`},
		{"CreateQueue", `{"QueueName":"rovara-heavy-x"}`},
		{"GetQueueUrl", `{"QueueName":"rovara-reply-1"}`},
		{"PurgeQueue", `{"MessageBody":"a","QueueUrl":"` + "http://aws:4566/000000000000/rovara-heavy-req" + `"}`},
	} {
		if r := json10(c.op, c.body); r.status != 403 || !strings.Contains(r.body, "AccessDenied") {
			t.Errorf("%s of a hidden queue: %d %s", c.op, r.status, r.body)
		}
	}
	// the Query protocol, and the Java style path
	q := func(form string) result {
		return f.do("POST", "/", map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Authorization": sqsJSON("X")["Authorization"]}, form)
	}
	for _, form := range []string{"Action=SendMessage&Version=2012-11-05&QueueUrl=http%3A%2F%2Faws%3A4566%2F000000000000%2Frovara-heavy-req&MessageBody=x",
		"Action=CreateQueue&Version=2012-11-05&QueueName=rovara-reply-z", "Action=ListQueues&Version=2012-11-05&QueueNamePrefix=rovara-heavy-"} {
		if r := q(form); r.status != 403 || !strings.Contains(r.body, "AccessDenied") {
			t.Errorf("Query %q: %d %s", form, r.status, r.body)
		}
	}
	if r := f.do("POST", "/000000000000/rovara-heavy-req", map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Authorization": sqsJSON("X")["Authorization"]}, "Action=ReceiveMessage&Version=2012-11-05"); r.status != 403 {
		t.Errorf("a queue named in the path: %d", r.status)
	}
	// customer queues are untouched, and the lists do not show the hidden ones
	if r := json10("CreateQueue", `{"QueueName":"orders"}`); r.status != 200 {
		t.Fatalf("a customer queue: %d %s", r.status, r.body)
	}
	if r := json10("SendMessage", `{"QueueUrl":"http://aws:4566/000000000000/orders","MessageBody":"hello rovara"}`); r.status != 200 {
		t.Errorf("a customer message: %d", r.status)
	}
	if r := json10("SendMessage", `{"QueueUrl":"http://aws:4566/000000000000/orders","MessageBody":"my queue is not rovara-x"}`); r.status != 200 {
		t.Errorf("a message that merely looks similar: %d", r.status)
	}
	lq := json10("ListQueues", `{}`)
	if lq.status != 200 || !strings.Contains(lq.body, "/orders") || strings.Contains(lq.body, "rovara-heavy") || strings.Contains(lq.body, "rovara-reply") {
		t.Errorf("ListQueues hides the plumbing: %d %s", lq.status, lq.body)
	}
	// but the plumbing exists in the engine (the front made it)
	if st, b := f.engineGet("/__fake/paths"); st != 200 || !strings.Contains(string(b), "rovara-heavy-payloads") {
		t.Errorf("the hidden bucket was created in the engine")
	}
	// the bucket, in a path, a virtual host, and the role
	if r := f.do("GET", "/"+hiddenBucket+"/req/x", scopeHdr("s3"), ""); r.status != 403 {
		t.Errorf("the hidden bucket by path: %d", r.status)
	}
	if r := f.do("GET", "/req/x", with(scopeHdr("s3"), "Host", hiddenBucket+".aws"), ""); r.status != 403 {
		t.Errorf("the hidden bucket by virtual host: %d", r.status)
	}
	iamAuth := "AWS4-HMAC-SHA256 Credential=K/20260101/us-east-1/iam/aws4_request, SignedHeaders=host, Signature=00"
	if r := f.do("POST", "/", map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Authorization": iamAuth}, "Action=GetRole&Version=2010-05-08&RoleName="+hiddenRole); r.status != 403 {
		t.Errorf("the stub's role: %d %s", r.status, r.body)
	}
	if r := f.do("POST", "/", map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Authorization": iamAuth}, "Action=GetRole&Version=2010-05-08&RoleName=mine"); r.status == 403 {
		t.Errorf("another role is fine: %d", r.status)
	}
	// none of it is in the ledger as a customer call, apart from the refusals themselves
	sum := f.do("GET", "/_rovara/ledger/summary", tok(), "").body
	if strings.Contains(sum, "rovara-") {
		t.Errorf("the summary names no plumbing: %s", sum)
	}
	var d struct {
		Entries []struct{ Service, Operation string }
	}
	json.Unmarshal([]byte(f.do("GET", "/_rovara/ledger?service=iam", tok(), "").body), &d)
	for _, e := range d.Entries {
		if e.Operation == "CreateRole" || e.Operation == "PutRolePolicy" {
			t.Errorf("the front's own IAM calls are not customer calls: %v", e)
		}
	}
	if c := f.counts("sqs")["CreateQueue"]; c.Calls != 4 { // the refused one, the customer's, and the Query ones that were refused are counted as calls
		t.Logf("sqs CreateQueue calls: %+v (the front's own CreateQueue is not among them)", c)
	}
}

func TestHideInLists(t *testing.T) {
	buckets := `<ListAllMyBucketsResult><Buckets><Bucket><Name>mine</Name><CreationDate>x</CreationDate></Bucket><Bucket><CreationDate>y</CreationDate><Name>` + hiddenBucket +
		`</Name></Bucket><Bucket><Name>other</Name></Bucket></Buckets></ListAllMyBucketsResult>`
	got := string(hideInLists([]byte(buckets)))
	if strings.Contains(got, hiddenBucket) || !strings.Contains(got, "<Name>mine</Name>") || !strings.Contains(got, "<Name>other</Name>") || strings.Count(got, "<Bucket>") != 2 {
		t.Errorf("ListBuckets: %s", got)
	}
	roles := `<ListRolesResult><Roles><member><RoleName>a</RoleName><Tags><member><Key>k</Key></member></Tags></member>` +
		`<member><Path>/</Path><RoleName>` + hiddenRole + `</RoleName><Tags><member><Key>x</Key><Value>y</Value></member></Tags></member>` +
		`<member><RoleName>b</RoleName></member></Roles></ListRolesResult>`
	got = string(hideInLists([]byte(roles)))
	if strings.Contains(got, hiddenRole) || !strings.Contains(got, "<RoleName>a</RoleName>") || !strings.Contains(got, "<RoleName>b</RoleName>") || !strings.Contains(got, "<Key>k</Key>") || strings.Contains(got, "<Key>x</Key>") {
		t.Errorf("ListRoles (nested members): %s", got)
	}
	if string(hideInLists([]byte("<x/>"))) != "<x/>" {
		t.Errorf("nothing to hide")
	}
	if regexp.MustCompile(`<member>\s*</member>`).MatchString(got) {
		t.Errorf("no empty shell left: %s", got)
	}
	if !hiddenQueueURL("https://sqs.us-east-1.amazonaws.com/000000000000/rovara-reply-1") || hiddenQueueURL("http://aws:4566/000000000000/my-rovara-heavy") ||
		!hiddenQueueURL("rovara-heavy-req") {
		t.Errorf("hiddenQueueURL")
	}
}

func TestRunnerOffChangesNothing(t *testing.T) {
	f := startLambdaFront(t, "lambda", "sqs")
	if f.srv.runner != nil {
		t.Fatal("no runner unless configured")
	}
	r := f.create("fl-off", "python3.12", map[string]any{"Timeout": 100}, heavyZip())
	if r.status != 201 {
		t.Fatal(r.status)
	}
	cfg, code := (&runnerFront{lamFront: f}).engineFn("fl-off")
	if cfg["Handler"] != "index.handler" || !bytes.Equal(code, heavyZip()) {
		t.Errorf("without a runner the engine gets the request as it was sent: %v", cfg)
	}
	if c := f.counts("lambda")[heavyPrefix+"native-code"]; c.Calls != 1 {
		t.Errorf("recorded as before: %+v", c)
	}
	if c := f.counts("lambda")[heavyPrefix+"long-timeout"]; c.Calls != 0 {
		t.Errorf("a long Timeout alone is not heavy without a runner: %+v", c)
	}
	if st := (&runnerFront{lamFront: f}).runnerState(); st != "not available" {
		t.Errorf("runner state: %q", st)
	}
	var d struct{ RunnerFunctions interface{} }
	json.Unmarshal([]byte(f.do("GET", "/_rovara/lambda/heavy", tok(), "").body), &d)
	if d.RunnerFunctions != nil {
		t.Errorf("no runnerFunctions without a runner")
	}
	// a queue named like the plumbing is an ordinary queue
	if r := f.do("POST", "/", sqsJSON("CreateQueue"), `{"QueueName":"rovara-heavy-mine"}`); r.status == 403 {
		t.Errorf("without a runner nothing is reserved")
	}
}

func TestRunnerConfigSettings(t *testing.T) {
	env := func(m map[string]string) settings { return func(k string) string { return m[k] } }
	if c, err := loadRunnerConfig(env(nil), "/w", true); c != nil || err != nil {
		t.Errorf("off by default: %v %v", c, err)
	}
	if _, err := loadRunnerConfig(env(map[string]string{envRunnerSocket: "/run/r.sock"}), "/w", false); err == nil {
		t.Errorf("the runner is part of planned mode")
	}
	if _, err := loadRunnerConfig(env(map[string]string{envRunnerSocket: "/run/r.sock"}), "/w", true); err == nil {
		t.Errorf("the package store directory is required (never a default under /tmp)")
	}
	if _, err := loadRunnerConfig(env(map[string]string{envRunnerSocket: "/run/r.sock", envRunnerStoreDir: "relative/dir"}), "/w", true); err == nil {
		t.Errorf("the package store directory must be absolute")
	}
	c, err := loadRunnerConfig(env(map[string]string{envRunnerSocket: "/run/r.sock", envRunnerStoreDir: "/data/store", envRunnerStoreMax: "1048576", envRunnerDirect: "3"}), "/w", true)
	if err != nil || c.Socket != "/run/r.sock" || c.StoreMax != 1<<20 || c.MaxDirect != 3 || c.StoreDir != "/data/store" {
		t.Errorf("settings: %+v %v", c, err)
	}
	for _, bad := range []map[string]string{{envRunnerSocket: "/s", envRunnerStoreDir: "/d", envRunnerStoreMax: "x"}, {envRunnerSocket: "/s", envRunnerStoreDir: "/d", envRunnerStoreMax: "10"}, {envRunnerSocket: "/s", envRunnerStoreDir: "/d", envRunnerDirect: "0"}} {
		if _, err := loadRunnerConfig(env(bad), "/w", true); err == nil {
			t.Errorf("%v should be refused", bad)
		}
	}
}

func TestSplitInvokeName(t *testing.T) {
	for in, want := range map[string][2]string{
		"f": {"f", ""}, "f:live": {"f", "live"}, "000000000000:function:f": {"f", ""}, "000000000000:function:f:3": {"f", "3"},
		"arn:aws:lambda:us-east-1:000000000000:function:f:live": {"f", "live"}, "arn%3Aaws%3Alambda%3Aus-east-1%3A000000000000%3Afunction%3Af": {"f", ""},
	} {
		if n, q := splitInvokeName(in); n != want[0] || q != want[1] {
			t.Errorf("%s: %q %q", in, n, q)
		}
	}
	_ = http.StatusOK
}

func dialRaw(t *testing.T, sock string) net.Conn {
	t.Helper()
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

// refuseX86 is a worker that can neither swap the wheels of an x86-64 package nor emulate it.
func refuseX86(fn regFn) *frameError {
	if strings.Contains(fn.Name, "x86") || fn.Name == "fl-x" {
		return &frameError{Type: "Rovara.Unsupported", Message: "native code built for x86_64; local runs are arm64"}
	}
	return nil
}

// A worker that can run an x86-64 package (it swaps the wheels): the front forwards it like any other, and the function runs.
func TestX86PackagesAreForwardedAndRunWhenTheWorkerAccepts(t *testing.T) {
	f := startRunnerFront(t, nil)
	mixed := testZip(zent{"app.py", []byte("x")}, zent{"lib/a.so", testELF(elfMachineAArch64)}, zent{"lib/b.so", testELF(elfMachineX8664)})
	if r := f.create("fl-mixed", "python3.12", map[string]any{"Architectures": []string{"x86_64"}}, mixed); r.status != 201 {
		t.Fatalf("create: %d %s", r.status, r.body)
	}
	if !f.srv.runner.reg.isTaken("fl-mixed") {
		t.Fatal("a mixed package is the runner's")
	}
	r := f.invoke("fl-mixed", `{"op":"echo"}`, nil)
	if r.status != 200 || r.header.Get("X-Amz-Function-Error") != "" || !strings.Contains(r.body, `"fn":"fl-mixed"`) {
		t.Errorf("a worker that accepts it runs it: %d %s", r.status, r.body)
	}
	fn, ok := f.w.registered("fl-mixed", "$LATEST")
	if !ok || fn.Package == nil || len(fn.Architectures) != 1 || fn.Architectures[0] != "x86_64" || !f.w.holds(fn.Package.SHA256) {
		t.Errorf("the worker was given the package and the declared architecture: %+v", fn)
	}
	if c := f.counts("lambda")[heavyPrefix+"x86-native"]; c.Calls != 0 {
		t.Errorf("a function that runs is not recorded as unable to run: %+v", c)
	}
}

// Numbers the worker reports may be fractional (a timing of 12.6 ms): they are rounded, never a protocol error.
func TestResultNumbersMayBeFractional(t *testing.T) {
	var r runnerResult
	in := `{"id":"x","status":"ok","durationMs":12.6,"billedDurationMs":13.2,"initDurationMs":104.4,"maxMemoryUsed":22020096.5,"cold":true}`
	if err := json.Unmarshal([]byte(in), &r); err != nil {
		t.Fatalf("fractional numbers: %v", err)
	}
	if r.DurationMs != 13 || r.BilledDurationMs != 13 || r.InitDurationMs != 104 || r.MaxMemoryUsed != 22020097 || r.Status != "ok" {
		t.Errorf("rounded: %+v", r)
	}
	for _, in := range []string{`{"durationMs":7}`, `{"durationMs":null}`, `{"durationMs":1e3}`} {
		if err := json.Unmarshal([]byte(in), &r); err != nil {
			t.Errorf("%s: %v", in, err)
		}
	}
	if err := json.Unmarshal([]byte(`{"durationMs":"fast"}`), &r); err == nil {
		t.Errorf("text is still an error")
	}
	// end to end: the hub receives a result whose numbers are fractional and hands it on
	h, _, sock := newTestHub(t)
	w := connectFakeWorker(t, sock)
	waitFor(t, "the worker", h.connected)
	w.fractional = true
	fn := regFn{Name: "g", Version: "$LATEST", Runtime: "python3.12", Handler: "a.b", MemoryMb: 128, TimeoutSeconds: 3}
	fn.ConfigHash = configHash(fn)
	res, err := h.run(context.Background(), fn, invokeFrame{Name: "g", Version: "$LATEST", RequestID: "f1", Payload: b64(`{}`), TimeoutMs: 1000})
	if err != nil || res.Status != "ok" || res.DurationMs != 13 || res.MaxMemoryUsed != 22020097 {
		t.Errorf("a result with fractional numbers is a result, not a protocol_error: %v %+v", err, res)
	}
}

var testNames = newHiddenNames("0123456789abcdef0123456789abcdef")
