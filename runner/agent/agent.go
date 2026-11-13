package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type config struct {
	Listen      string        // Runtime API address; must be loopback. Port 0 picks a free port.
	Cmd         []string      // runtime command; empty means the default bootstrap search
	InitTimeout time.Duration // how long the runtime may take to reach its first /next
	RingBytes   int           // size of the log ring
	UID, GID    int           // run the runtime as this user when UID is not 0
	Debug       io.Writer     // when set, receives a copy of the runtime's output
}

const (
	defaultListen      = "127.0.0.1:9001"
	defaultRingBytes   = 1 << 20
	defaultLogBytes    = 64 << 10
	defaultInitTimeout = 10 * time.Second
)

// failure describes why a runtime did not come up.
type failure struct {
	reason  string // runtime_reported | exited | timeout | start_failed
	errType string
	errMsg  string
	payload []byte
}

type runtimeInst struct {
	pid      int
	exited   chan struct{} // closed when the process has been reaped; ws is valid after that
	ws       syscall.WaitStatus
	readyCh  chan struct{}
	readyOne sync.Once
	ready    atomic.Bool
	initErr  chan *failure
}

func (r *runtimeInst) markReady() {
	r.readyOne.Do(func() {
		r.ready.Store(true)
		close(r.readyCh)
	})
}
func (r *runtimeInst) isReady() bool { return r.ready.Load() }
func (r *runtimeInst) reportInitError(f *failure) {
	select {
	case r.initErr <- f:
	default:
	}
}

const (
	outResponse = iota + 1
	outError
	outTooLarge
)

type outcome struct {
	kind    int
	body    []byte
	errType string
	errMsg  string
}

type invocation struct {
	id       string
	msg      *invokeMsg
	payload  []byte
	traceID  string
	deadline time.Time
	done     chan struct{}

	// guarded by agent.mu
	delivered bool
	finished  bool
	// written before done is closed, read after
	out outcome
}

type agent struct {
	cfg   config
	out   *frameWriter
	ring  *ring
	logs  *logSink
	reap  *reaper
	addr  string
	srv   *http.Server
	ctx   context.Context
	stop  context.CancelFunc
	fatal atomic.Value // string

	invokes chan *invokeMsg
	nextCh  chan *invocation

	mu  sync.Mutex
	rt  *runtimeInst
	cur *invocation

	// dispatcher-only state
	idleMark    int64
	pendingInit float64 // init duration not yet reported in a result, ms; 0 when none
}

func newAgent(cfg config) *agent {
	if cfg.Listen == "" {
		cfg.Listen = defaultListen
	}
	if cfg.InitTimeout <= 0 {
		cfg.InitTimeout = defaultInitTimeout
	}
	if cfg.RingBytes <= 0 {
		cfg.RingBytes = defaultRingBytes
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &agent{
		cfg:     cfg,
		ring:    newRing(cfg.RingBytes),
		reap:    newReaper(),
		ctx:     ctx,
		stop:    cancel,
		invokes: make(chan *invokeMsg, 64),
		nextCh:  make(chan *invocation),
	}
}

// Shutdown asks run to finish.
func (a *agent) Shutdown() { a.stop() }

// Addr is the Runtime API address (valid after the listener is up).
func (a *agent) Addr() string { return a.addr }

func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// run serves until stdin closes, a shutdown frame arrives, or a protocol error happens. It
// returns the process exit code.
func (a *agent) run(in io.Reader, out io.Writer) int {
	a.out = &frameWriter{w: out}
	if !isLoopback(a.cfg.Listen) {
		a.out.send(fatalMsg{Type: "fatal", Message: "listen address must be a loopback IP: " + a.cfg.Listen})
		return 2
	}
	var err error
	a.logs, err = newLogSink(a.ring, a.cfg.Debug)
	if err != nil {
		a.out.send(fatalMsg{Type: "fatal", Message: "log pipe: " + err.Error()})
		return 2
	}
	ln, err := net.Listen("tcp", a.cfg.Listen)
	if err != nil {
		a.out.send(fatalMsg{Type: "fatal", Message: "listen: " + err.Error()})
		return 2
	}
	a.addr = ln.Addr().String()
	a.srv = &http.Server{Handler: a.handler(), ReadHeaderTimeout: 10 * time.Second}
	go a.srv.Serve(ln)
	defer a.srv.Close()

	cmd := a.cfg.Cmd
	a.out.send(helloMsg{Type: "hello", Proto: protoVersion, Agent: "rovara-runner-agent", Version: agentVersion,
		Pid: os.Getpid(), Listen: a.addr, Command: cmd})

	go a.readLoop(in)

	a.ensureRuntime(a.logs.ring.Mark(), true)
	for {
		var exited <-chan struct{}
		a.mu.Lock()
		if a.rt != nil {
			exited = a.rt.exited
		}
		a.mu.Unlock()
		select {
		case msg := <-a.invokes:
			if res := a.processInvoke(msg); res != nil {
				if err := a.sendResult(res); err != nil {
					a.stop()
				}
			}
		case <-exited:
			a.onIdleExit()
		case <-a.ctx.Done():
			a.mu.Lock()
			rt := a.rt
			a.mu.Unlock()
			if rt != nil {
				killGroup(rt.pid)
				select {
				case <-rt.exited:
				case <-time.After(2 * time.Second):
				}
			}
			if f, _ := a.fatal.Load().(string); f != "" {
				return 64
			}
			return 0
		}
	}
}

func (a *agent) readLoop(in io.Reader) {
	for {
		raw, err := readFrame(in)
		if err != nil {
			if err != io.EOF {
				a.protocolError("reading frame: " + err.Error())
			} else {
				a.stop()
			}
			return
		}
		var env struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(raw, &env); err != nil {
			a.protocolError("frame is not a JSON object: " + err.Error())
			return
		}
		switch env.Type {
		case "invoke":
			var m invokeMsg
			if err := json.Unmarshal(raw, &m); err != nil {
				a.protocolError("bad invoke frame: " + err.Error())
				return
			}
			select {
			case a.invokes <- &m:
			case <-a.ctx.Done():
				return
			}
		case "shutdown":
			a.stop()
			return
		default:
			fmt.Fprintf(os.Stderr, "agent: ignoring frame of unknown type %q\n", env.Type)
		}
	}
}

func (a *agent) protocolError(msg string) {
	a.fatal.Store(msg)
	a.out.send(fatalMsg{Type: "fatal", Message: msg})
	a.stop()
}

// ---- runtime lifecycle ----

func (a *agent) resolveCommand() ([]string, error) {
	if len(a.cfg.Cmd) > 0 {
		p, err := exec.LookPath(a.cfg.Cmd[0])
		if err != nil {
			return nil, err
		}
		return append([]string{p}, a.cfg.Cmd[1:]...), nil
	}
	for _, p := range []string{"/var/runtime/bootstrap", "/var/task/bootstrap", "/opt/bootstrap"} {
		if st, err := os.Stat(p); err == nil && !st.IsDir() && st.Mode()&0o111 != 0 {
			return []string{p}, nil
		}
	}
	return nil, errors.New("no bootstrap found in /var/runtime, /var/task or /opt")
}

func (a *agent) runtimeEnv() []string {
	var env []string
	have := map[string]bool{}
	for _, kv := range os.Environ() {
		k := kv
		if i := strings.IndexByte(kv, '='); i >= 0 {
			k = kv[:i]
		}
		if strings.HasPrefix(k, "AGENT_") || k == "AWS_LAMBDA_RUNTIME_API" {
			continue
		}
		have[k] = true
		env = append(env, kv)
	}
	if !have["LAMBDA_TASK_ROOT"] {
		env = append(env, "LAMBDA_TASK_ROOT=/var/task")
	}
	if !have["LAMBDA_RUNTIME_DIR"] {
		env = append(env, "LAMBDA_RUNTIME_DIR=/var/runtime")
	}
	return append(env, "AWS_LAMBDA_RUNTIME_API="+a.addr)
}

func (a *agent) launch() (*runtimeInst, *failure) {
	argv, err := a.resolveCommand()
	if err != nil {
		return nil, &failure{reason: "start_failed", errType: "Runtime.InvalidEntrypoint", errMsg: err.Error()}
	}
	devnull, err := os.Open(os.DevNull)
	if err != nil {
		return nil, &failure{reason: "start_failed", errType: "Runtime.InvalidEntrypoint", errMsg: err.Error()}
	}
	defer devnull.Close()
	dir := "/var/task"
	if v := os.Getenv("LAMBDA_TASK_ROOT"); v != "" {
		dir = v
	}
	// The instance is published before the process exists, so that a runtime that polls
	// /next the instant it starts is already counted as ready.
	rt := &runtimeInst{exited: make(chan struct{}), readyCh: make(chan struct{}), initErr: make(chan *failure, 1)}
	a.mu.Lock()
	a.rt = rt
	a.mu.Unlock()
	pid, wch, err := a.reap.Start(func() (int, error) {
		return startProcess(argv, a.runtimeEnv(), dir, devnull.Fd(), uintptr(a.logs.wfd), a.cfg.UID, a.cfg.GID)
	})
	if err != nil {
		a.dropRuntime(rt)
		return nil, &failure{reason: "start_failed", errType: "Runtime.InvalidEntrypoint", errMsg: err.Error()}
	}
	a.mu.Lock()
	rt.pid = pid
	a.mu.Unlock()
	go func() {
		rt.ws = <-wch
		close(rt.exited)
	}()
	return rt, nil
}

func exitFailure(rt *runtimeInst) *failure {
	_, _, msg := describeStatus(rt.ws)
	return &failure{reason: "exited", errType: "Runtime.ExitError", errMsg: "Runtime exited with error: " + msg}
}

// ensureRuntime starts the runtime if none is running and waits for it to reach its first
// /next. With emit set it reports the outcome to the worker as a ready or init_error frame.
// It returns nil on success.
func (a *agent) ensureRuntime(mark int64, emit bool) *failure {
	a.mu.Lock()
	cur := a.rt
	a.mu.Unlock()
	if cur != nil {
		return nil
	}
	t0 := time.Now()
	rt, f := a.launch()
	if f == nil {
		f = a.awaitReady(rt)
		if f != nil {
			killGroup(rt.pid)
			select {
			case <-rt.exited:
			case <-time.After(2 * time.Second):
			}
		}
	}
	initMs := ms(time.Since(t0))
	if f != nil {
		a.mu.Lock()
		a.rt = nil
		a.mu.Unlock()
		if emit {
			a.logs.Barrier(500 * time.Millisecond)
			tail, _ := a.ring.Since(mark, defaultLogBytes)
			a.out.send(initErrorMsg{Type: "init_error", Reason: f.reason, ErrorType: f.errType, ErrorMessage: f.errMsg,
				Payload: b64(failurePayload(f)), LogTail: string(tail), InitDurationMs: initMs})
			a.idleMark = a.ring.Mark()
		}
		return f
	}
	a.pendingInit = initMs
	if emit {
		a.logs.Barrier(500 * time.Millisecond)
		tail, _ := a.ring.Since(mark, defaultLogBytes)
		a.out.send(readyMsg{Type: "ready", InitDurationMs: initMs, LogTail: string(tail)})
		a.idleMark = a.ring.Mark()
	}
	return nil
}

func (a *agent) awaitReady(rt *runtimeInst) *failure {
	timer := time.NewTimer(a.cfg.InitTimeout)
	defer timer.Stop()
	select {
	case <-rt.readyCh:
		return nil
	case f := <-rt.initErr:
		return f
	case <-rt.exited:
		select {
		case f := <-rt.initErr:
			return f
		default:
		}
		return exitFailure(rt)
	case <-timer.C:
		return &failure{reason: "timeout", errType: "Runtime.InitTimeout",
			errMsg: fmt.Sprintf("Init phase timed out after %.2f seconds", a.cfg.InitTimeout.Seconds())}
	case <-a.ctx.Done():
		return &failure{reason: "exited", errType: "Runtime.Shutdown", errMsg: "agent is shutting down"}
	}
}

func (a *agent) onIdleExit() {
	a.mu.Lock()
	rt := a.rt
	a.rt = nil
	a.mu.Unlock()
	if rt == nil {
		return
	}
	a.logs.Barrier(500 * time.Millisecond)
	tail, _ := a.ring.Since(a.idleMark, defaultLogBytes)
	code, sig, msg := describeStatus(rt.ws)
	a.out.send(runtimeExitMsg{Type: "runtime_exit", ExitCode: code, Signal: sig, Message: msg, LogTail: string(tail)})
	a.idleMark = a.ring.Mark()
}

// sendResult sends one result frame. If the encoded frame would exceed the frame limit it sheds
// weight instead of failing: first the log tail shrinks to its newest 64 KiB (logTruncated),
// then the payload is dropped (payloadTruncated), so the worker always gets a result. Only a
// write error on the pipe itself is returned.
func (a *agent) sendResult(res *resultMsg) error {
	err := a.out.send(res)
	if !errors.Is(err, errFrameTooLarge) {
		return err
	}
	if len(res.LogTail) > defaultLogBytes {
		res.LogTail = res.LogTail[len(res.LogTail)-defaultLogBytes:]
		res.LogTruncated = true
		if err = a.out.send(res); !errors.Is(err, errFrameTooLarge) {
			return err
		}
	}
	res.Payload, res.PayloadTruncated = "", true
	if err = a.out.send(res); !errors.Is(err, errFrameTooLarge) {
		return err
	}
	res.LogTail, res.LogTruncated = "", true
	res.ErrorMessage = capString(res.ErrorMessage, 1024)
	return a.out.send(res)
}

// ---- invocations ----

func validToken(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' || c == ':') {
			return false
		}
	}
	return true
}

func headerSafe(s string) bool {
	return !strings.ContainsAny(s, "\r\n\x00") && len(s) <= 16<<10
}

func newTraceID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("Root=1-%08x-%s;Sampled=0", time.Now().Unix(), hex.EncodeToString(b[4:16]))
}

func ms(d time.Duration) float64 { return math.Round(float64(d)/float64(time.Millisecond)*100) / 100 }

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func errorDoc(typ, msg string) []byte {
	b, _ := json.Marshal(map[string]string{"errorMessage": msg, "errorType": typ})
	return b
}

func failurePayload(f *failure) []byte {
	if len(f.payload) > 0 {
		return f.payload
	}
	return errorDoc(f.errType, f.errMsg)
}

func (a *agent) processInvoke(msg *invokeMsg) *resultMsg {
	res := &resultMsg{Type: "result", RequestID: msg.RequestID, Payload: ""}
	reject := func(typ, m string) *resultMsg {
		res.Status, res.ErrorType, res.ErrorMessage = statusRejected, typ, m
		return res
	}
	if !validToken(msg.RequestID) {
		return reject("InvalidRequestId", "requestId must be 1-128 characters from A-Z a-z 0-9 - _ . :")
	}
	for _, v := range []string{msg.FunctionArn, msg.TraceID, msg.ClientContext, msg.CognitoIdentity, msg.FunctionVersion} {
		if !headerSafe(v) {
			return reject("InvalidHeader", "a header value contains a control character or is too long")
		}
	}
	if len(msg.Payload) > base64.StdEncoding.EncodedLen(maxPayloadBytes) {
		return reject("RequestEntityTooLargeException", fmt.Sprintf("Request must be smaller than %d bytes for the Invoke API", maxPayloadBytes))
	}
	payload, err := base64.StdEncoding.DecodeString(msg.Payload)
	if err != nil {
		return reject("InvalidPayload", "payload is not valid base64")
	}
	if len(payload) > maxPayloadBytes {
		return reject("RequestEntityTooLargeException", fmt.Sprintf("Request must be smaller than %d bytes for the Invoke API", maxPayloadBytes))
	}
	var timeout time.Duration
	switch {
	case msg.TimeoutMs > 0:
		timeout = time.Duration(msg.TimeoutMs) * time.Millisecond
	case msg.DeadlineMs > 0:
		timeout = time.Until(time.UnixMilli(msg.DeadlineMs))
	}
	if timeout <= 0 {
		return reject("InvalidTimeout", "timeoutMs (or a future deadlineMs) is required")
	}
	logBytes := msg.LogBytes
	if logBytes <= 0 {
		logBytes = defaultLogBytes
	}
	if logBytes > a.cfg.RingBytes {
		logBytes = a.cfg.RingBytes
	}

	mark := a.ring.Mark()
	if f := a.ensureRuntime(mark, false); f != nil {
		a.logs.Barrier(500 * time.Millisecond)
		tail, trunc := a.ring.Since(mark, logBytes)
		res.Status, res.ErrorType, res.ErrorMessage = statusInitError, f.errType, f.errMsg
		res.Payload = b64(failurePayload(f))
		res.LogTail, res.LogTruncated = string(tail), trunc
		res.InitDurationMs = a.pendingInit
		a.idleMark = a.ring.Mark()
		return res
	}
	a.mu.Lock()
	rt := a.rt
	a.mu.Unlock()

	// Sample the runtime's resident memory while the invocation runs.
	var peak atomic.Int64
	stopSampler := make(chan struct{})
	samplerDone := make(chan struct{})
	go func() {
		defer close(samplerDone)
		tk := time.NewTicker(20 * time.Millisecond)
		defer tk.Stop()
		for {
			if v := groupRSS(rt.pid); v > peak.Load() {
				peak.Store(v)
			}
			select {
			case <-stopSampler:
				return
			case <-tk.C:
			}
		}
	}()

	version := msg.FunctionVersion
	if version == "" {
		version = os.Getenv("AWS_LAMBDA_FUNCTION_VERSION")
	}
	if version == "" {
		version = "$LATEST"
	}
	a.logs.Emit(fmt.Sprintf("START RequestId: %s Version: %s\n", msg.RequestID, version))

	inv := &invocation{id: msg.RequestID, msg: msg, payload: payload, traceID: msg.TraceID, done: make(chan struct{})}
	if inv.traceID == "" {
		inv.traceID = newTraceID()
	}
	start := time.Now()
	inv.deadline = start.Add(timeout)
	a.mu.Lock()
	a.cur = inv
	a.mu.Unlock()
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	const (
		endDone = iota
		endTimeout
		endExit
		endShutdown
	)
	end := endDone
	t0 := start
	select {
	case a.nextCh <- inv:
		t0 = time.Now()
		select {
		case <-inv.done:
		case <-timer.C:
			end = endTimeout
		case <-rt.exited:
			end = endExit
		case <-a.ctx.Done():
			end = endShutdown
		}
	case <-timer.C:
		end = endTimeout
	case <-rt.exited:
		end = endExit
	case <-a.ctx.Done():
		end = endShutdown
	}

	// A response may have raced with the timeout or the exit; if the handler got there first
	// the invocation is done.
	if end != endDone {
		a.mu.Lock()
		if inv.finished {
			end = endDone
		} else if end != endShutdown {
			inv.finished = true
		}
		a.mu.Unlock()
		if end == endDone {
			<-inv.done
		}
	}
	if end == endShutdown {
		close(stopSampler)
		return nil
	}

	var dur time.Duration
	if v := groupRSS(rt.pid); v > peak.Load() { // one last look before anything is killed
		peak.Store(v)
	}
	switch end {
	case endDone:
		dur = time.Since(t0)
		o := inv.out
		switch o.kind {
		case outResponse:
			res.Status, res.Payload = statusOK, b64(o.body)
		case outError:
			res.Status, res.Payload = statusFunctionError, b64(o.body)
			res.ErrorType, res.ErrorMessage = o.errType, o.errMsg
			if len(o.body) == 0 {
				res.Payload = b64(errorDoc(o.errType, o.errMsg))
			}
		case outTooLarge:
			m := fmt.Sprintf("Response payload size exceeded maximum allowed payload size (%d bytes).", maxPayloadBytes)
			res.Status, res.ErrorType, res.ErrorMessage = statusFunctionError, "Function.ResponseSizeTooLarge", m
			res.Payload = b64(errorDoc(res.ErrorType, m))
		}
	case endTimeout:
		dur = timeout
		killGroup(rt.pid)
		select {
		case <-rt.exited:
		case <-time.After(2 * time.Second):
		}
		a.dropRuntime(rt)
		secs := fmt.Sprintf("Task timed out after %.2f seconds", timeout.Seconds())
		res.Status, res.ErrorType = statusTimeout, "Sandbox.Timedout"
		res.ErrorMessage = fmt.Sprintf("RequestId: %s Error: %s", msg.RequestID, secs)
		res.Payload = b64([]byte(fmt.Sprintf(`{"errorMessage":%s}`, jsonString(res.ErrorMessage))))
	case endExit:
		dur = time.Since(t0)
		a.dropRuntime(rt)
		_, _, st := describeStatus(rt.ws)
		res.Status, res.ErrorType = statusCrash, "Runtime.ExitError"
		res.ErrorMessage = fmt.Sprintf("RequestId: %s Error: Runtime exited with error: %s", msg.RequestID, st)
		res.Payload = b64(errorDoc(res.ErrorType, res.ErrorMessage))
	}

	a.logs.Barrier(500 * time.Millisecond)
	if end == endTimeout {
		a.logs.Emit(fmt.Sprintf("%s %s Task timed out after %.2f seconds\n", time.Now().UTC().Format("2006-01-02T15:04:05.000Z"), msg.RequestID, timeout.Seconds()))
	}
	a.logs.Emit(fmt.Sprintf("END RequestId: %s\n", msg.RequestID))
	close(stopSampler)
	<-samplerDone
	res.MaxMemoryUsed = peak.Load()
	memSize := msg.MemorySizeMb
	if memSize <= 0 {
		memSize, _ = strconv.Atoi(os.Getenv("AWS_LAMBDA_FUNCTION_MEMORY_SIZE"))
	}
	if memSize <= 0 {
		memSize = 128
	}
	res.DurationMs = ms(dur)
	res.BilledDurationMs = int64(math.Ceil(float64(dur) / float64(time.Millisecond)))
	if res.BilledDurationMs < 1 {
		res.BilledDurationMs = 1
	}
	if a.pendingInit > 0 {
		res.InitDurationMs = a.pendingInit
		a.pendingInit = 0
	}
	report := fmt.Sprintf("REPORT RequestId: %s\tDuration: %.2f ms\tBilled Duration: %d ms\tMemory Size: %d MB\tMax Memory Used: %d MB",
		msg.RequestID, res.DurationMs, res.BilledDurationMs, memSize, (res.MaxMemoryUsed+(1<<20)-1)>>20)
	if res.InitDurationMs > 0 {
		report += fmt.Sprintf("\tInit Duration: %.2f ms", res.InitDurationMs)
	}
	switch res.Status {
	case statusTimeout:
		report += "\tStatus: timeout"
	case statusFunctionError, statusCrash:
		report += "\tStatus: error\tError Type: " + res.ErrorType
	}
	a.logs.Emit(report + "\n")
	tail, trunc := a.ring.Since(mark, logBytes)
	res.LogTail, res.LogTruncated = string(tail), trunc

	a.mu.Lock()
	a.cur = nil
	a.mu.Unlock()
	a.idleMark = a.ring.Mark()
	return res
}

func (a *agent) dropRuntime(rt *runtimeInst) {
	a.mu.Lock()
	if a.rt == rt {
		a.rt = nil
	}
	a.mu.Unlock()
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
