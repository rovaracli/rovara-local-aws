package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// The hub is the front's end of the runner pipe (runner_proto.go): it listens on the unix socket, holds the one worker connection, registers
// functions on it, sends invokes and hands results back to whoever waits. It knows nothing of Lambda or of the engine.

var (
	errNoRunner   = errors.New("the function runner is not connected")
	errRunnerGone = errors.New("the function runner disconnected")
)

// runnerError is a refusal the worker gave (a registration it could not accept).
type runnerError struct{ Type, Message string }

func (e *runnerError) Error() string { return e.Type + ": " + e.Message }

type pendingMsg struct {
	typ string
	raw []byte
}

type regState struct {
	hash string
	done chan struct{}
	err  error
}

type runnerConn struct {
	hub      *runnerHub
	c        net.Conn
	fw       *frameWriter
	mu       sync.Mutex
	pending  map[string]chan pendingMsg
	regs     map[string]*regState // name|version -> state, per connection
	done     chan struct{}
	once     sync.Once
	worker   helloFrame
	lastSeen time.Time
}

type runnerHub struct {
	path    string
	store   *runnerStore
	version string
	ln      net.Listener
	mu      sync.Mutex
	cur     *runnerConn
	closed  bool
	wg      sync.WaitGroup
	// handshakeTimeout and the waits below are fields so tests can shorten them
	handshakeTimeout time.Duration
	registerTimeout  time.Duration
	stopTimeout      time.Duration
}

func newRunnerHub(path string, store *runnerStore, version string) *runnerHub {
	return &runnerHub{path: path, store: store, version: version, handshakeTimeout: 10 * time.Second,
		registerTimeout: 120 * time.Second, stopTimeout: 20 * time.Second}
}

// start binds the socket (mode 0600, in a directory only the front's user can enter) and accepts workers.
func (h *runnerHub) start() error {
	if !filepath.IsAbs(h.path) || strings.HasPrefix(h.path, "@") || strings.ContainsRune(h.path, 0) {
		return fmt.Errorf("the runner socket must be an absolute file path (not relative, not abstract)")
	}
	dir := filepath.Dir(h.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("cannot create the runner socket's directory: %w", err)
	}
	// the directory is the socket's first protection: it must be ours, and only ours
	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != os.Getuid() {
		return fmt.Errorf("the runner socket's directory %s is not owned by the front's user", dir)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(dir, 0o700); err != nil {
			return fmt.Errorf("cannot make the runner socket's directory private: %w", err)
		}
	}
	if fi, err := os.Lstat(h.path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("%s exists and is not a socket", h.path)
		}
		os.Remove(h.path) // a stale socket of an earlier front
	}
	ln, err := net.Listen("unix", h.path) // the directory is 0700, so nobody else reaches the socket in the instant before the chmod
	if err != nil {
		return fmt.Errorf("cannot listen on the runner socket: %w", err)
	}
	os.Chmod(h.path, 0o600)
	h.ln = ln
	h.wg.Add(1)
	go h.acceptLoop()
	return nil
}

func (h *runnerHub) acceptLoop() {
	defer h.wg.Done()
	for {
		c, err := h.ln.Accept()
		if err != nil {
			return
		}
		h.wg.Add(1)
		go func() {
			defer h.wg.Done()
			h.serveConn(c)
		}()
	}
}

func (h *runnerHub) close() {
	h.mu.Lock()
	h.closed = true
	cur := h.cur
	h.cur = nil
	h.mu.Unlock()
	if h.ln != nil {
		h.ln.Close()
	}
	if cur != nil {
		cur.close()
	}
	h.wg.Wait()
	os.Remove(h.path)
}

func (h *runnerHub) current() *runnerConn {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.cur
}

func (h *runnerHub) connected() bool { return h.current() != nil }

func (h *runnerHub) serveConn(c net.Conn) {
	if !peerAllowed(c) {
		c.Close() // not the front's user: not the worker
		return
	}
	rc := &runnerConn{hub: h, c: c, fw: &frameWriter{w: c}, pending: map[string]chan pendingMsg{}, regs: map[string]*regState{}, done: make(chan struct{})}
	defer rc.close()
	if err := rc.fw.write(helloFrame{Type: ftHello, Proto: runnerProto, Front: "rovara-aws-front", Version: h.version}); err != nil {
		return
	}
	fr := newFrameReader(c)
	c.SetReadDeadline(time.Now().Add(h.handshakeTimeout))
	typ, raw, err := fr.next()
	if err != nil || typ != ftHello {
		return
	}
	var hello helloFrame
	if json.Unmarshal(raw, &hello) != nil || hello.Proto != runnerProto {
		rc.fw.write(errorFrame{Type: ftError, Message: "this front speaks " + runnerProto})
		return
	}
	c.SetReadDeadline(time.Time{})
	rc.worker = hello
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return
	}
	if h.cur != nil {
		// exactly one peer at a time: a second connection is turned away, it does not displace the first. (A pipe that died is noticed at
		// once, so a worker that reconnects after losing its pipe is let in as soon as the front has seen the first one close.)
		h.mu.Unlock()
		rc.fw.write(errorFrame{Type: ftError, Message: "a worker is already connected"})
		return
	}
	h.cur = rc
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		if h.cur == rc {
			h.cur = nil
		}
		h.mu.Unlock()
	}()
	for {
		typ, raw, err := fr.next()
		if err != nil {
			return
		}
		switch typ {
		case ftNeed, ftRegistered, ftResult, ftUnregistered, ftStopped:
			var id idFrame
			if json.Unmarshal(raw, &id) != nil || id.ID == "" {
				return // a known frame that does not parse is a protocol error
			}
			rc.deliver(id.ID, pendingMsg{typ, raw})
		case ftError:
			var e errorFrame
			json.Unmarshal(raw, &e)
			if e.ID != "" {
				rc.deliver(e.ID, pendingMsg{typ, raw})
			} else {
				log.Printf("the runner reported an error: %s", sanitizeLine(e.Message))
			}
		case ftHello:
			// a second hello is ignored
		default:
			// an unknown type is ignored
		}
	}
}

func sanitizeLine(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

func (rc *runnerConn) close() {
	rc.once.Do(func() {
		close(rc.done)
		rc.c.Close()
	})
}

func (rc *runnerConn) deliver(id string, m pendingMsg) {
	rc.mu.Lock()
	ch := rc.pending[id]
	rc.mu.Unlock()
	if ch == nil {
		return // an answer nobody waits for any more (the caller went away)
	}
	select {
	case ch <- m:
	default: // the waiter's buffer is full: a worker that answers twice
	}
}

func (rc *runnerConn) expect(id string) chan pendingMsg {
	ch := make(chan pendingMsg, 8)
	rc.mu.Lock()
	rc.pending[id] = ch
	rc.mu.Unlock()
	return ch
}

func (rc *runnerConn) forget(id string) {
	rc.mu.Lock()
	delete(rc.pending, id)
	rc.mu.Unlock()
}

// register tells the worker about one function version and streams the packages it lacks. It returns nil when the worker accepted it.
func (rc *runnerConn) register(ctx context.Context, fn regFn) error {
	id := newUUID()
	ch := rc.expect(id)
	defer rc.forget(id)
	if err := rc.fw.write(registerFrame{Type: ftRegister, ID: id, Fn: fn}); err != nil {
		return errRunnerGone
	}
	ctx, cancel := context.WithTimeout(ctx, rc.hub.registerTimeout)
	defer cancel()
	for {
		select {
		case m := <-ch:
			switch m.typ {
			case ftNeed:
				var nf needFrame
				if json.Unmarshal(m.raw, &nf) != nil {
					return &runnerError{"Rovara.RunnerError", "the runner's need frame did not parse"}
				}
				for _, sha := range nf.Packages {
					if err := rc.sendPackage(ctx, id, sha, fn); err != nil {
						return err
					}
				}
			case ftRegistered:
				var rf registeredFrame
				if json.Unmarshal(m.raw, &rf) != nil {
					return &runnerError{"Rovara.RunnerError", "the runner's registered frame did not parse"}
				}
				if rf.OK {
					return nil
				}
				if rf.Error == nil {
					return &runnerError{"Rovara.Unsupported", "the function runner refused the function"}
				}
				return &runnerError{rf.Error.Type, rf.Error.Message}
			case ftError:
				var ef errorFrame
				json.Unmarshal(m.raw, &ef)
				return &runnerError{"Rovara.RunnerError", sanitizeLine(ef.Message)}
			}
		case <-rc.done:
			return errRunnerGone
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (rc *runnerConn) sendPackage(ctx context.Context, id, sha string, fn regFn) error {
	kind := "layer"
	if fn.Package != nil && fn.Package.SHA256 == sha {
		kind = "function"
	}
	f, size, err := rc.hub.store.open(sha)
	if err != nil {
		return &runnerError{"Rovara.Unsupported", "a package of the function is no longer held by the front"}
	}
	defer f.Close()
	if err := rc.fw.write(packageFrame{Type: ftPackage, ID: id, SHA256: sha, Kind: kind, SizeBytes: size}); err != nil {
		return errRunnerGone
	}
	buf := make([]byte, runnerChunkBytes)
	for seq := 0; ; seq++ {
		n, rerr := io.ReadFull(f, buf)
		last := rerr == io.EOF || rerr == io.ErrUnexpectedEOF
		if rerr != nil && !last {
			return &runnerError{"Rovara.RunnerError", "reading a package failed"}
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := rc.fw.write(chunkFrame{Type: ftChunk, ID: id, SHA256: sha, Seq: seq, Data: base64.StdEncoding.EncodeToString(buf[:n]), Last: last}); err != nil {
			return errRunnerGone
		}
		if last {
			return nil
		}
	}
}

// ensureRegistered makes sure this connection has the function version at this configuration. Concurrent callers share one registration.
func (rc *runnerConn) ensureRegistered(ctx context.Context, fn regFn) error {
	key := fn.Name + "|" + fn.Version
	rc.mu.Lock()
	st := rc.regs[key]
	if st != nil && st.hash == fn.ConfigHash {
		rc.mu.Unlock()
		select {
		case <-st.done:
			return st.err
		case <-ctx.Done():
			return ctx.Err()
		case <-rc.done:
			return errRunnerGone
		}
	}
	st = &regState{hash: fn.ConfigHash, done: make(chan struct{})}
	rc.regs[key] = st
	rc.mu.Unlock()
	st.err = rc.register(ctx, fn)
	if st.err != nil {
		var re *runnerError
		if !errors.As(st.err, &re) { // a failure that is not the worker's verdict (a cancelled caller, a dead pipe) is not remembered
			rc.mu.Lock()
			if rc.regs[key] == st {
				delete(rc.regs, key)
			}
			rc.mu.Unlock()
		}
	}
	close(st.done)
	return st.err
}

func (rc *runnerConn) forgetReg(name, version string) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	for k := range rc.regs {
		n, v, _ := strings.Cut(k, "|")
		if n == name && (version == "" || v == version) {
			delete(rc.regs, k)
		}
	}
}

// invoke sends one invoke and waits for its result.
func (rc *runnerConn) invoke(ctx context.Context, inv invokeFrame) (*runnerResult, error) {
	inv.Type, inv.ID = ftInvoke, newUUID()
	ch := rc.expect(inv.ID)
	defer rc.forget(inv.ID)
	if err := rc.fw.write(inv); err != nil {
		return nil, errRunnerGone
	}
	select {
	case m := <-ch:
		if m.typ == ftError {
			var ef errorFrame
			json.Unmarshal(m.raw, &ef)
			return &runnerResult{Status: "unavailable", Reason: "protocol_error", Detail: sanitizeLine(ef.Message)}, nil
		}
		var r runnerResult
		if json.Unmarshal(m.raw, &r) != nil {
			return &runnerResult{Status: "unavailable", Reason: "protocol_error", Detail: "the result did not parse"}, nil
		}
		return &r, nil
	case <-rc.done:
		return nil, errRunnerGone
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// run registers the function and invokes it. A worker that says it never heard of the function (it lost its state without dropping the
// pipe) is told again, once.
func (h *runnerHub) run(ctx context.Context, fn regFn, inv invokeFrame) (*runnerResult, error) {
	for attempt := 0; ; attempt++ {
		rc := h.current()
		if rc == nil {
			return nil, errNoRunner
		}
		if err := rc.ensureRegistered(ctx, fn); err != nil {
			return nil, err
		}
		res, err := rc.invoke(ctx, inv)
		if err != nil {
			return nil, err
		}
		if res.Status == "unavailable" && res.Reason == "not_registered" && attempt == 0 {
			rc.forgetReg(fn.Name, fn.Version)
			continue
		}
		return res, nil
	}
}

// unregister tells the worker to drop a function (or one version), without waiting for it. It is a barrier only through stopAll.
func (h *runnerHub) unregister(name, version string) {
	rc := h.current()
	if rc == nil {
		return
	}
	rc.forgetReg(name, version)
	rc.fw.write(unregisterFrame{Type: ftUnregister, ID: newUUID(), Name: name, Version: version})
}

// stopAll is the reset barrier: it returns after the worker confirmed every environment of the run gone, or after stopTimeout.
func (h *runnerHub) stopAll() error {
	rc := h.current()
	if rc == nil {
		return nil
	}
	id := newUUID()
	ch := rc.expect(id)
	defer rc.forget(id)
	rc.mu.Lock()
	rc.regs = map[string]*regState{}
	rc.mu.Unlock()
	if err := rc.fw.write(stopAllFrame{Type: ftStopAll, ID: id}); err != nil {
		return err
	}
	select {
	case <-ch:
		return nil
	case <-rc.done:
		return nil
	case <-time.After(h.stopTimeout):
		return errors.New("the runner did not confirm stop_all")
	}
}

// ---- the other end: `front runner-pipe`

// runnerPipe joins in and out to the front's runner socket. It is what the worker runs under `docker exec -i`. It returns when either
// side closes.
func runnerPipe(path string, in io.Reader, out io.Writer) error {
	c, err := net.DialTimeout("unix", path, 5*time.Second)
	if err != nil {
		return fmt.Errorf("cannot reach the runner socket: %w", err)
	}
	defer c.Close()
	errc := make(chan error, 2)
	go func() {
		_, err := io.Copy(c, in)
		if uc, ok := c.(*net.UnixConn); ok {
			uc.CloseWrite()
		}
		errc <- err
	}()
	go func() {
		_, err := io.Copy(out, c)
		errc <- err
	}()
	err = <-errc // the first side to finish ends the pipe: stdin closed (the worker went away) or the front closed the socket
	return err
}
