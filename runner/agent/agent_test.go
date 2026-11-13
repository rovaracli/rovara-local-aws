package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	if os.Getenv("FAKE_RUNTIME") == "1" {
		fakeRuntimeMain()
		return
	}
	os.Exit(m.Run())
}

// harness runs an agent in-process and talks to it over pipes, as the worker would.
type harness struct {
	t      *testing.T
	a      *agent
	toAg   *io.PipeWriter
	frames chan []byte
	done   chan int
	seq    int
}

type startOpts struct {
	env  map[string]string
	cmd  []string // default: the fake runtime
	init time.Duration
	ring int
}

func start(t *testing.T, o startOpts) *harness {
	t.Helper()
	t.Setenv("FAKE_RUNTIME", "1")
	for k, v := range o.env {
		t.Setenv(k, v)
	}
	cmd := o.cmd
	if cmd == nil {
		cmd = []string{os.Args[0]}
	}
	a := newAgent(config{Listen: "127.0.0.1:0", Cmd: cmd, InitTimeout: o.init, RingBytes: o.ring})
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	h := &harness{t: t, a: a, toAg: inW, frames: make(chan []byte, 1024), done: make(chan int, 1)}
	go func() { h.done <- a.run(inR, outW); outW.Close() }()
	go func() {
		for {
			b, err := readFrame(outR)
			if err != nil {
				close(h.frames)
				return
			}
			h.frames <- b
		}
	}()
	t.Cleanup(func() {
		inW.Close()
		select {
		case <-h.done:
		case <-time.After(10 * time.Second):
			t.Error("agent did not exit on stdin close")
		}
	})
	return h
}

func (h *harness) next(timeout time.Duration) map[string]any {
	h.t.Helper()
	select {
	case b, ok := <-h.frames:
		if !ok {
			h.t.Fatal("agent closed stdout")
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			h.t.Fatalf("bad frame %s: %v", b, err)
		}
		return m
	case <-time.After(timeout):
		h.t.Fatal("timed out waiting for a frame")
	}
	return nil
}

func (h *harness) expect(typ string) map[string]any {
	h.t.Helper()
	m := h.next(15 * time.Second)
	if m["type"] != typ {
		h.t.Fatalf("want %s frame, got %v", typ, m)
	}
	return m
}

func (h *harness) up() (hello, ready map[string]any) {
	hello = h.expect("hello")
	ready = h.expect("ready")
	return
}

func (h *harness) send(v any) {
	h.t.Helper()
	if err := writeFrame(h.toAg, v); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) invoke(payload string, timeoutMs int64) *resultMsg {
	h.t.Helper()
	h.seq++
	id := fmt.Sprintf("req-%d", h.seq)
	h.send(invokeMsg{Type: "invoke", RequestID: id, Payload: base64.StdEncoding.EncodeToString([]byte(payload)),
		TimeoutMs: timeoutMs, FunctionArn: "arn:aws:lambda:us-east-1:000000000000:function:t"})
	return h.result(id)
}

func (h *harness) result(id string) *resultMsg {
	h.t.Helper()
	m := h.expect("result")
	b, _ := json.Marshal(m)
	var r resultMsg
	json.Unmarshal(b, &r)
	if r.RequestID != id {
		h.t.Fatalf("result for %q, want %q", r.RequestID, id)
	}
	return &r
}

func dec(t *testing.T, s string) string {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestHelloReadyAndEcho(t *testing.T) {
	h := start(t, startOpts{})
	hello, ready := h.up()
	if hello["proto"] != protoVersion || !strings.HasPrefix(hello["listen"].(string), "127.0.0.1:") {
		t.Fatalf("hello %v", hello)
	}
	if ready["initDurationMs"].(float64) <= 0 || !strings.Contains(ready["logTail"].(string), "init done") {
		t.Fatalf("ready %v", ready)
	}
	r := h.invoke(`{"op":"echo","x":1}`, 5000)
	if r.Status != statusOK || dec(t, r.Payload) != `{"op":"echo","x":1}` {
		t.Fatalf("result %+v", r)
	}
	if r.InitDurationMs <= 0 {
		t.Errorf("first result should carry the init duration: %+v", r)
	}
	if r.MaxMemoryUsed <= 0 {
		t.Errorf("max memory %d", r.MaxMemoryUsed)
	}
	for _, want := range []string{"START RequestId: req-1 Version: $LATEST\n", "END RequestId: req-1\n", "REPORT RequestId: req-1\tDuration: ", "Billed Duration: ", "Memory Size: 128 MB", "Init Duration: "} {
		if !strings.Contains(r.LogTail, want) {
			t.Errorf("log tail lacks %q:\n%s", want, r.LogTail)
		}
	}
	// The init output belongs to the ready frame, not to the first invocation.
	if strings.Contains(r.LogTail, "init done") {
		t.Errorf("init output leaked into the invocation log:\n%s", r.LogTail)
	}
	r2 := h.invoke(`{"op":"echo"}`, 5000)
	if r2.InitDurationMs != 0 || strings.Contains(r2.LogTail, "Init Duration") {
		t.Errorf("warm result should not carry an init duration: %+v", r2)
	}
}

func TestRuntimeAPIHeaders(t *testing.T) {
	h := start(t, startOpts{})
	h.up()
	h.seq++
	h.send(invokeMsg{Type: "invoke", RequestID: "hdr-1", Payload: base64.StdEncoding.EncodeToString([]byte(`{"op":"headers"}`)),
		TimeoutMs: 5000, FunctionArn: "arn:aws:lambda:us-west-2:111122223333:function:hf", TraceID: "Root=1-5e1b4151-5ac6c58f5b5349a7d0fb4a8d;Sampled=1",
		ClientContext: "eyJjIjoxfQ==", CognitoIdentity: `{"identityId":"i"}`})
	before := time.Now().UnixMilli()
	r := h.result("hdr-1")
	var got map[string]string
	json.Unmarshal([]byte(dec(t, r.Payload)), &got)
	want := map[string]string{
		"Lambda-Runtime-Aws-Request-Id":       "hdr-1",
		"Lambda-Runtime-Invoked-Function-Arn": "arn:aws:lambda:us-west-2:111122223333:function:hf",
		"Lambda-Runtime-Trace-Id":             "Root=1-5e1b4151-5ac6c58f5b5349a7d0fb4a8d;Sampled=1",
		"Lambda-Runtime-Client-Context":       "eyJjIjoxfQ==",
		"Lambda-Runtime-Cognito-Identity":     `{"identityId":"i"}`,
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	dl, _ := strconv.ParseInt(got["Lambda-Runtime-Deadline-Ms"], 10, 64)
	if dl < before+4000 || dl > before+6000 {
		t.Errorf("deadline %d not about 5 s after %d", dl, before)
	}
	// Without trace id or optional headers the agent still sends a trace id and omits the rest.
	r = h.invoke(`{"op":"headers"}`, 5000)
	json.Unmarshal([]byte(dec(t, r.Payload)), &got)
	if !strings.HasPrefix(got["Lambda-Runtime-Trace-Id"], "Root=1-") {
		t.Errorf("trace id %q", got["Lambda-Runtime-Trace-Id"])
	}
}

func TestWarmReuse(t *testing.T) {
	h := start(t, startOpts{})
	h.up()
	first := dec(t, h.invoke(`{"op":"pid"}`, 5000).Payload)
	for i := 0; i < 100; i++ {
		r := h.invoke(`{"op":"pid"}`, 5000)
		if r.Status != statusOK || dec(t, r.Payload) != first {
			t.Fatalf("invocation %d: %+v (runtime pid changed from %s)", i, r, first)
		}
	}
}

func TestFunctionError(t *testing.T) {
	h := start(t, startOpts{})
	h.up()
	r := h.invoke(`{"op":"error"}`, 5000)
	if r.Status != statusFunctionError || r.ErrorType != "ValueError" || r.ErrorMessage != "kaboom" {
		t.Fatalf("%+v", r)
	}
	var doc map[string]any
	json.Unmarshal([]byte(dec(t, r.Payload)), &doc)
	if doc["errorMessage"] != "kaboom" || doc["stackTrace"] == nil {
		t.Fatalf("payload %v", doc)
	}
	if !strings.Contains(r.LogTail, "Status: error\tError Type: ValueError") {
		t.Errorf("log tail:\n%s", r.LogTail)
	}
	// The runtime stays warm after a function error.
	if r := h.invoke(`{"op":"echo"}`, 5000); r.Status != statusOK {
		t.Fatalf("%+v", r)
	}
}

func TestTimeoutKillsProcessGroupAndRestarts(t *testing.T) {
	h := start(t, startOpts{})
	h.up()
	pid1 := dec(t, h.invoke(`{"op":"pid"}`, 5000).Payload)
	childPid, _ := strconv.Atoi(dec(t, h.invoke(`{"op":"spawn"}`, 5000).Payload))
	if err := syscall.Kill(childPid, 0); err != nil {
		t.Fatalf("child %d should be alive: %v", childPid, err)
	}
	t0 := time.Now()
	r := h.invoke(`{"op":"sleep","n":10000}`, 1000)
	el := time.Since(t0)
	if r.Status != statusTimeout || r.ErrorType != "Sandbox.Timedout" {
		t.Fatalf("%+v", r)
	}
	if el < 900*time.Millisecond || el > 3*time.Second {
		t.Errorf("took %v", el)
	}
	if want := "Task timed out after 1.00 seconds"; !strings.Contains(r.ErrorMessage, want) || !strings.Contains(r.LogTail, want) {
		t.Errorf("message %q, log:\n%s", r.ErrorMessage, r.LogTail)
	}
	if !strings.Contains(r.LogTail, "Status: timeout") || r.DurationMs != 1000 {
		t.Errorf("report/duration: %v\n%s", r.DurationMs, r.LogTail)
	}
	if !strings.Contains(dec(t, r.Payload), "Task timed out after 1.00 seconds") {
		t.Errorf("payload %s", dec(t, r.Payload))
	}
	// The spawned child shared the process group, so it is gone too.
	deadline := time.Now().Add(3 * time.Second)
	for syscall.Kill(childPid, 0) == nil && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	// (a zombie child of the test process would still answer signal 0, so check /proc state)
	if st, err := os.ReadFile("/proc/" + strconv.Itoa(childPid) + "/stat"); err == nil && !strings.Contains(string(st), ") Z ") {
		t.Errorf("child %d survived the timeout: %s", childPid, st)
	}
	// The next invocation starts a fresh runtime, and reports its init.
	r = h.invoke(`{"op":"pid"}`, 5000)
	if r.Status != statusOK || dec(t, r.Payload) == pid1 {
		t.Fatalf("expected a restarted runtime: %+v (old pid %s)", r, pid1)
	}
	if r.InitDurationMs <= 0 || !strings.Contains(r.LogTail, "init done") {
		t.Errorf("restart init not reported: %+v\n%s", r, r.LogTail)
	}
}

func TestTimeoutFromDeadlineMs(t *testing.T) {
	h := start(t, startOpts{})
	h.up()
	h.seq++
	h.send(invokeMsg{Type: "invoke", RequestID: "d-1", Payload: base64.StdEncoding.EncodeToString([]byte(`{"op":"sleep","n":10000}`)),
		DeadlineMs: time.Now().Add(1500 * time.Millisecond).UnixMilli(), FunctionArn: "arn"})
	r := h.result("d-1")
	if r.Status != statusTimeout || !strings.Contains(r.ErrorMessage, "Task timed out after 1.") {
		t.Fatalf("%+v", r)
	}
}

func TestCrashDuringInvocationThenRecovers(t *testing.T) {
	h := start(t, startOpts{})
	h.up()
	r := h.invoke(`{"op":"crash"}`, 5000)
	if r.Status != statusCrash || r.ErrorType != "Runtime.ExitError" || !strings.Contains(r.ErrorMessage, "Runtime exited with error: exit status 3") {
		t.Fatalf("%+v", r)
	}
	if !strings.Contains(r.LogTail, "about to crash") || !strings.Contains(r.LogTail, "Error Type: Runtime.ExitError") {
		t.Errorf("log:\n%s", r.LogTail)
	}
	if r := h.invoke(`{"op":"echo"}`, 5000); r.Status != statusOK {
		t.Fatalf("no recovery: %+v", r)
	}
}

func TestIdleExitIsReported(t *testing.T) {
	h := start(t, startOpts{})
	h.up()
	if r := h.invoke(`{"op":"shutdown_after"}`, 5000); r.Status != statusOK {
		t.Fatalf("%+v", r)
	}
	m := h.expect("runtime_exit")
	if m["exitCode"].(float64) != 0 {
		t.Fatalf("%v", m)
	}
	if r := h.invoke(`{"op":"echo"}`, 5000); r.Status != statusOK {
		t.Fatalf("restart after idle exit: %+v", r)
	}
}

func TestInitErrorReportedByRuntime(t *testing.T) {
	h := start(t, startOpts{env: map[string]string{"FAKE_INIT": "error"}})
	h.expect("hello")
	m := h.expect("init_error")
	if m["reason"] != "runtime_reported" || m["errorType"] != "Runtime.ImportModuleError" ||
		!strings.Contains(m["errorMessage"].(string), "Unable to import module") || !strings.Contains(m["logTail"].(string), "importing handler") {
		t.Fatalf("%v", m)
	}
	if !strings.Contains(dec(t, m["payload"].(string)), "Unable to import module") {
		t.Fatalf("payload %v", m["payload"])
	}
	// An invoke retries init and gets the failure as its result.
	r := h.invoke(`{"op":"echo"}`, 5000)
	if r.Status != statusInitError || r.ErrorType != "Runtime.ImportModuleError" {
		t.Fatalf("%+v", r)
	}
	if !strings.Contains(r.LogTail, "importing handler") || strings.Contains(r.LogTail, "START RequestId") {
		t.Errorf("log:\n%s", r.LogTail)
	}
}

func TestInitExitAndTimeoutAndBadCommand(t *testing.T) {
	h := start(t, startOpts{env: map[string]string{"FAKE_INIT": "exit"}})
	h.expect("hello")
	m := h.expect("init_error")
	if m["reason"] != "exited" || m["errorType"] != "Runtime.ExitError" || !strings.Contains(m["logTail"].(string), "boom at startup") ||
		!strings.Contains(m["errorMessage"].(string), "exit status 2") {
		t.Fatalf("%v", m)
	}

	h = start(t, startOpts{env: map[string]string{"FAKE_INIT": "hang"}, init: 500 * time.Millisecond})
	h.expect("hello")
	m = h.expect("init_error")
	if m["reason"] != "timeout" || m["errorType"] != "Runtime.InitTimeout" {
		t.Fatalf("%v", m)
	}

	h = start(t, startOpts{cmd: []string{"/nonexistent/bootstrap"}})
	h.expect("hello")
	m = h.expect("init_error")
	if m["reason"] != "start_failed" || m["errorType"] != "Runtime.InvalidEntrypoint" {
		t.Fatalf("%v", m)
	}
}

func TestOversizedAndInvalidRequestsAreRejected(t *testing.T) {
	h := start(t, startOpts{})
	h.up()
	big := bytes.Repeat([]byte{'a'}, maxPayloadBytes+1)
	h.send(invokeMsg{Type: "invoke", RequestID: "big", Payload: base64.StdEncoding.EncodeToString(big), TimeoutMs: 5000, FunctionArn: "arn"})
	r := h.result("big")
	if r.Status != statusRejected || r.ErrorType != "RequestEntityTooLargeException" {
		t.Fatalf("%+v", r)
	}
	// Exactly at the limit is accepted and echoed back as a response of the same size
	// (the limit is the same in both directions). The echo has to fit the payload, so use a
	// JSON string of that length.
	ok := append(append([]byte(`{"op":"echo","text":"`), bytes.Repeat([]byte{'a'}, maxPayloadBytes-30)...), []byte(`"}`)...)
	h.send(invokeMsg{Type: "invoke", RequestID: "max", Payload: base64.StdEncoding.EncodeToString(ok), TimeoutMs: 20000, FunctionArn: "arn"})
	if r := h.result("max"); r.Status != statusOK || len(dec(t, r.Payload)) != len(ok) {
		t.Fatalf("at the limit: %s %s", r.Status, r.ErrorMessage)
	}

	cases := []struct {
		name string
		m    invokeMsg
		typ  string
	}{
		{"bad id", invokeMsg{RequestID: "a/b", Payload: "e30=", TimeoutMs: 100}, "InvalidRequestId"},
		{"empty id", invokeMsg{RequestID: "", Payload: "e30=", TimeoutMs: 100}, "InvalidRequestId"},
		{"bad b64", invokeMsg{RequestID: "x1", Payload: "!!!", TimeoutMs: 100}, "InvalidPayload"},
		{"no timeout", invokeMsg{RequestID: "x2", Payload: "e30="}, "InvalidTimeout"},
		{"past deadline", invokeMsg{RequestID: "x3", Payload: "e30=", DeadlineMs: 1000}, "InvalidTimeout"},
		{"header injection", invokeMsg{RequestID: "x4", Payload: "e30=", TimeoutMs: 100, FunctionArn: "a\r\nX-Evil: 1"}, "InvalidHeader"},
	}
	for _, c := range cases {
		c.m.Type = "invoke"
		h.send(c.m)
		m := h.expect("result")
		if m["status"] != statusRejected || m["errorType"] != c.typ {
			t.Errorf("%s: %v", c.name, m)
		}
	}
	// The runtime is still fine.
	if r := h.invoke(`{"op":"echo"}`, 5000); r.Status != statusOK {
		t.Fatalf("%+v", r)
	}
}

func TestResponseTooLarge(t *testing.T) {
	h := start(t, startOpts{})
	h.up()
	r := h.invoke(fmt.Sprintf(`{"op":"big","n":%d}`, maxPayloadBytes+1), 20000)
	if r.Status != statusFunctionError || r.ErrorType != "Function.ResponseSizeTooLarge" || !strings.Contains(r.ErrorMessage, "6291556") {
		t.Fatalf("%+v", r)
	}
	r = h.invoke(fmt.Sprintf(`{"op":"big","n":%d}`, maxPayloadBytes), 20000)
	if r.Status != statusOK || len(dec(t, r.Payload)) != maxPayloadBytes {
		t.Fatalf("at the limit: %s %s", r.Status, r.ErrorMessage)
	}
}

func TestLogsCaptureBothStreamsAndAreBounded(t *testing.T) {
	h := start(t, startOpts{ring: 4096})
	h.up()
	r := h.invoke(`{"op":"log","text":"hello","n":3}`, 5000)
	for _, want := range []string{"out: hello\n", "err: hello\n", "filler line 2 ", "no newline at end\nEND RequestId"} {
		if !strings.Contains(r.LogTail, want) {
			t.Errorf("log lacks %q:\n%s", want, r.LogTail)
		}
	}
	if !(strings.Index(r.LogTail, "START") < strings.Index(r.LogTail, "out: hello") && strings.Index(r.LogTail, "out: hello") < strings.Index(r.LogTail, "END")) {
		t.Errorf("order wrong:\n%s", r.LogTail)
	}
	if r.LogTruncated {
		t.Error("small log should not be truncated")
	}
	// A log larger than the ring keeps the newest bytes and says so; REPORT survives.
	r = h.invoke(`{"op":"log","text":"big","n":500}`, 5000)
	if !r.LogTruncated || len(r.LogTail) > 4096 || !strings.Contains(r.LogTail, "REPORT RequestId: req-2") || strings.Contains(r.LogTail, "START RequestId: req-2") {
		t.Errorf("truncated=%v len=%d\n...%s", r.LogTruncated, len(r.LogTail), r.LogTail[max(0, len(r.LogTail)-200):])
	}
	// logBytes narrows the tail further.
	h.seq++
	h.send(invokeMsg{Type: "invoke", RequestID: "lb", Payload: base64.StdEncoding.EncodeToString([]byte(`{"op":"log","text":"x","n":1}`)), TimeoutMs: 5000, FunctionArn: "a", LogBytes: 100})
	r = h.result("lb")
	if len(r.LogTail) != 100 || !r.LogTruncated {
		t.Errorf("len %d truncated %v", len(r.LogTail), r.LogTruncated)
	}
}

func TestMaxMemoryReflectsAllocation(t *testing.T) {
	h := start(t, startOpts{})
	h.up()
	small := h.invoke(`{"op":"echo"}`, 5000).MaxMemoryUsed
	big := h.invoke(`{"op":"mem","n":64}`, 5000).MaxMemoryUsed
	if big < small+60<<20 {
		t.Errorf("small %d, big %d", small, big)
	}
}

func TestInvocationsAreSerialised(t *testing.T) {
	h := start(t, startOpts{})
	h.up()
	for i := 1; i <= 3; i++ {
		h.send(invokeMsg{Type: "invoke", RequestID: fmt.Sprintf("q%d", i), Payload: base64.StdEncoding.EncodeToString([]byte(`{"op":"sleep","n":100}`)), TimeoutMs: 5000, FunctionArn: "a"})
	}
	for i := 1; i <= 3; i++ {
		r := h.result(fmt.Sprintf("q%d", i))
		if r.Status != statusOK {
			t.Fatalf("%+v", r)
		}
	}
}

func TestShutdownFrameAndStdinClose(t *testing.T) {
	h := start(t, startOpts{})
	h.up()
	pid, _ := strconv.Atoi(dec(t, h.invoke(`{"op":"pid"}`, 5000).Payload))
	h.send(map[string]string{"type": "shutdown"})
	select {
	case code := <-h.done:
		if code != 0 {
			t.Fatalf("exit %d", code)
		}
		h.done <- code // for the cleanup
	case <-time.After(5 * time.Second):
		t.Fatal("no exit")
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		st, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
		if err != nil || strings.Contains(string(st), ") Z ") {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("runtime still running after shutdown")
}

func TestGarbageFrameIsFatal(t *testing.T) {
	h := start(t, startOpts{})
	h.up()
	go h.toAg.Write([]byte{0, 0, 0, 3, 'x', 'y', 'z'})
	m := h.expect("fatal")
	if !strings.Contains(m["message"].(string), "not a JSON object") {
		t.Fatalf("%v", m)
	}
	if code := <-h.done; code != 64 {
		t.Fatalf("exit code %d", code)
	}
	h.done <- 64
}

func TestRejectsNonLoopbackListen(t *testing.T) {
	a := newAgent(config{Listen: "0.0.0.0:9001"})
	var out bytes.Buffer
	if code := a.run(bytes.NewReader(nil), &out); code != 2 || !strings.Contains(out.String(), "loopback") {
		t.Fatalf("code %d out %q", code, out.String())
	}
}

func TestRuntimeEnvironment(t *testing.T) {
	t.Setenv("AGENT_SECRET", "nope")
	t.Setenv("AWS_LAMBDA_RUNTIME_API", "evil:1")
	t.Setenv("LAMBDA_TASK_ROOT", "/custom")
	a := newAgent(config{})
	a.addr = "127.0.0.1:9001"
	env := strings.Join(a.runtimeEnv(), "\n")
	for _, bad := range []string{"AGENT_SECRET", "evil:1"} {
		if strings.Contains(env, bad) {
			t.Errorf("environment leaks %q", bad)
		}
	}
	for _, want := range []string{"AWS_LAMBDA_RUNTIME_API=127.0.0.1:9001", "LAMBDA_TASK_ROOT=/custom", "LAMBDA_RUNTIME_DIR=/var/runtime"} {
		if !strings.Contains(env, want) {
			t.Errorf("environment lacks %q", want)
		}
	}
}

// The tests below use a plain sleeping process as the "runtime" and play the runtime's part
// over HTTP themselves, to check the Runtime API's edge cases.

func TestRuntimeAPIEdgeCases(t *testing.T) {
	h := start(t, startOpts{cmd: []string{"/bin/sleep", "300"}})
	h.expect("hello")
	// The sleeping process is not a real runtime; wait until the agent has launched it so the
	// first /next below is the one that counts.
	for i := 0; i < 500; i++ {
		h.a.mu.Lock()
		up := h.a.rt != nil && h.a.rt.pid != 0
		h.a.mu.Unlock()
		if up {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	base := "http://" + h.a.Addr() + "/2018-06-01/runtime/"
	do := func(method, path string, body string) (int, string, http.Header) {
		req, _ := http.NewRequest(method, base+path, strings.NewReader(body))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b), resp.Header
	}
	// Before any /next: a response for an unknown request is refused.
	if c, b, _ := do("POST", "invocation/nope/response", "x"); c != 400 || !strings.Contains(b, "InvalidRequestID") {
		t.Errorf("unknown id: %d %s", c, b)
	}
	if c, _, _ := do("GET", "invocation/nope/response", ""); c != 405 {
		t.Errorf("GET response: %d", c)
	}
	if c, _, _ := do("POST", "invocation/next", ""); c != 405 {
		t.Errorf("POST next: %d", c)
	}
	if c, _, _ := do("GET", "nothing/here", ""); c != 404 {
		t.Errorf("unknown path: %d", c)
	}
	if c, _, _ := do("POST", "invocation/a/b/c", ""); c != 404 {
		t.Errorf("long path: %d", c)
	}
	if c, _, _ := do("POST", "invocation/x/other", ""); c != 404 {
		t.Errorf("bad verb: %d", c)
	}

	// Play the runtime: the first /next marks the agent ready.
	type nextResp struct {
		code int
		body string
		hdr  http.Header
	}
	nextCh := make(chan nextResp, 1)
	go func() { c, b, hd := do("GET", "invocation/next", ""); nextCh <- nextResp{c, b, hd} }()
	h.expect("ready")
	h.send(invokeMsg{Type: "invoke", RequestID: "api-1", Payload: base64.StdEncoding.EncodeToString([]byte(`{"k":"v"}`)), TimeoutMs: 5000, FunctionArn: "arn:x"})
	n := <-nextCh
	if n.code != 200 || n.body != `{"k":"v"}` || n.hdr.Get("Lambda-Runtime-Aws-Request-Id") != "api-1" || n.hdr.Get("Content-Type") != "application/json" {
		t.Fatalf("next: %d %q %v", n.code, n.body, n.hdr)
	}
	if n.hdr.Get("Lambda-Runtime-Client-Context") != "" || n.hdr.Get("Lambda-Runtime-Cognito-Identity") != "" {
		t.Errorf("optional headers must be absent: %v", n.hdr)
	}
	// Init error after the runtime started polling is refused.
	if c, b, _ := do("POST", "init/error", `{"errorMessage":"late"}`); c != 403 || !strings.Contains(b, "InvalidStateTransition") {
		t.Errorf("late init error: %d %s", c, b)
	}
	// Wrong id is refused and does not disturb the real invocation.
	if c, _, _ := do("POST", "invocation/other/response", "x"); c != 400 {
		t.Errorf("wrong id: %d", c)
	}
	c, b, _ := do("POST", "invocation/api-1/response", `"done"`)
	if c != 202 || !strings.Contains(b, `"status":"OK"`) {
		t.Errorf("response: %d %s", c, b)
	}
	// A second response for the same id is refused.
	if c, _, _ := do("POST", "invocation/api-1/response", `"again"`); c != 400 {
		t.Errorf("duplicate response: %d", c)
	}
	r := h.result("api-1")
	if r.Status != statusOK || dec(t, r.Payload) != `"done"` {
		t.Fatalf("%+v", r)
	}

	// Error path with the error type only in the header and a non-JSON body.
	go func() { c, b, hd := do("GET", "invocation/next", ""); nextCh <- nextResp{c, b, hd} }()
	h.send(invokeMsg{Type: "invoke", RequestID: "api-2", Payload: "e30=", TimeoutMs: 5000, FunctionArn: "arn:x"})
	<-nextCh
	req, _ := http.NewRequest("POST", base+"invocation/api-2/error", strings.NewReader("plain text failure"))
	req.Header.Set("Lambda-Runtime-Function-Error-Type", "Runtime.Custom")
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 202 {
		t.Fatalf("error post: %v %v", resp, err)
	}
	resp.Body.Close()
	r = h.result("api-2")
	if r.Status != statusFunctionError || r.ErrorType != "Runtime.Custom" || dec(t, r.Payload) != "plain text failure" {
		t.Fatalf("%+v", r)
	}
}

func TestHugeErrorBodyDoesNotKillTheAgent(t *testing.T) {
	h := start(t, startOpts{})
	h.up()
	// 6,000,000 "<" in the error message: every one would become six bytes if HTML-escaped.
	r := h.invoke(`{"op":"bigerror","n":6000000}`, 20000)
	if r.Status != statusFunctionError {
		t.Fatalf("%+v", r.Status)
	}
	if len(r.ErrorMessage) > maxErrorMessageBytes || len(r.ErrorType) > maxErrorTypeBytes || len(r.ErrorMessage) < maxErrorMessageBytes-4 || r.ErrorType != strings.Repeat("T", maxErrorTypeBytes) {
		t.Errorf("errorMessage %d bytes, errorType %d bytes", len(r.ErrorMessage), len(r.ErrorType))
	}
	if len(dec(t, r.Payload)) < 6000000 {
		t.Errorf("the runtime's own error document should be returned whole, got %d bytes", len(dec(t, r.Payload)))
	}
	// The agent and the runtime are both still there.
	if r := h.invoke(`{"op":"echo"}`, 5000); r.Status != statusOK || r.InitDurationMs != 0 {
		t.Fatalf("%+v", r)
	}
}

func TestSendResultShedsWeightInsteadOfFailing(t *testing.T) {
	var buf bytes.Buffer
	a := &agent{out: &frameWriter{w: &buf}}
	res := &resultMsg{Type: "result", RequestID: "r", Status: statusOK,
		Payload: strings.Repeat("A", 17<<20), LogTail: strings.Repeat("\x01", 1<<20), ErrorMessage: "m"}
	if err := a.sendResult(res); err != nil {
		t.Fatal(err)
	}
	raw, err := readFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	var got resultMsg
	json.Unmarshal(raw, &got)
	if got.RequestID != "r" || !got.LogTruncated || !got.PayloadTruncated || got.Payload != "" || len(got.LogTail) > defaultLogBytes {
		t.Fatalf("status %s logTruncated=%v payloadTruncated=%v payload=%d log=%d", got.Status, got.LogTruncated, got.PayloadTruncated, len(got.Payload), len(got.LogTail))
	}
	// A log that is too big alone only costs the log.
	buf.Reset()
	res = &resultMsg{Type: "result", RequestID: "r2", Status: statusOK, Payload: "e30=", LogTail: strings.Repeat("\x01", 4<<20)}
	if err := a.sendResult(res); err != nil {
		t.Fatal(err)
	}
	raw, _ = readFrame(&buf)
	got = resultMsg{}
	json.Unmarshal(raw, &got)
	if got.RequestID != "r2" || !got.LogTruncated || got.PayloadTruncated || got.Payload != "e30=" {
		t.Fatalf("%+v", got.RequestID)
	}
}

func TestFramesDoNotEscapeHTML(t *testing.T) {
	var buf bytes.Buffer
	writeFrame(&buf, map[string]string{"type": "x", "m": "<a>&"})
	raw, _ := readFrame(&buf)
	if string(raw) != `{"m":"<a>&","type":"x"}` {
		t.Fatalf("%s", raw)
	}
}

func TestCapString(t *testing.T) {
	if got := capString("aé", 2); got != "a" {
		t.Errorf("split a rune: %q", got)
	}
	if got := capString("abc", 5); got != "abc" {
		t.Error(got)
	}
	if got := capString("日本語", 4); got != "日" {
		t.Errorf("%q", got)
	}
}

// With a slow init, an invoke sent right after hello must not overtake ready: the agent emits
// exactly one of ready / init_error before it accepts the first invoke.
func TestReadyPrecedesFirstResult(t *testing.T) {
	h := start(t, startOpts{env: map[string]string{"FAKE_INIT_DELAY_MS": "300"}})
	h.expect("hello")
	h.send(invokeMsg{Type: "invoke", RequestID: "early", Payload: "e30=", TimeoutMs: 5000, FunctionArn: "a"})
	h.expect("ready")
	if r := h.result("early"); r.Status != statusOK {
		t.Fatalf("%+v", r)
	}
	select {
	case m := <-h.frames:
		t.Fatalf("unexpected extra frame %s", m)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestOnlyTheRuntimesStatusIsKept(t *testing.T) {
	r := newReaper()
	r.pid1 = true // reap with wait4(-1), as PID 1 does
	defer close(r.stop)
	// Orphans the reaper never registered: their statuses must not be remembered.
	for i := 0; i < 5; i++ {
		c := exec.Command("/bin/true")
		c.Start()
	}
	time.Sleep(200 * time.Millisecond)
	// Quick children registered through Start must each get their own status, even when they
	// exit before Start returns.
	for i := 0; i < 200; i++ {
		want := i % 5
		pid, ch, err := r.Start(func() (int, error) {
			return syscall.ForkExec("/bin/sh", []string{"sh", "-c", "exit " + strconv.Itoa(want)}, &syscall.ProcAttr{Files: []uintptr{0, 1, 2}})
		})
		if err != nil {
			t.Fatal(err)
		}
		select {
		case ws := <-ch:
			if !ws.Exited() || ws.ExitStatus() != want {
				t.Fatalf("child %d (pid %d): status %v, want exit %d", i, pid, ws, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("child %d (pid %d) never reported", i, pid)
		}
	}
	r.mu.Lock()
	n := len(r.watch)
	r.mu.Unlock()
	if n != 0 {
		t.Fatalf("%d watches left", n)
	}
}
