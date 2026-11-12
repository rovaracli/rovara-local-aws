package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// The engine is AWS Emulator, run as a child of the front. The front starts it on 127.0.0.1 with an OS-chosen port,
// telemetry off three ways and signature checks off, keeps its keys and CA in a private directory under the work dir
// (the container's root is read-only), and talks to it over HTTPS on loopback, trusting ONLY the CA the engine wrote
// for itself. A reset is a restart: the engine has no reset call and keeps its state in memory only.

type engineState int

const (
	engineStarting engineState = iota
	engineReady
	engineResetting
	engineFailed
	engineStopped
)

func (s engineState) String() string {
	return [...]string{"starting", "ready", "resetting", "failed", "stopped"}[s]
}

// generation is one run of the engine process.
type generation struct {
	n      int
	cmd    *exec.Cmd
	port   int
	dir    string
	client *http.Client
	exited chan struct{} // closed when the process has been reaped
	exit   error
	// stopping is set by the front itself before it signals the process, so an exit it asked for is not "unexpected".
	stopping bool
}

// Engine supervises the child.
type Engine struct {
	bin      string
	workDir  string
	mu       sync.RWMutex
	state    engineState
	gen      *generation
	genCount int
	lastErr  string
	resetMu  sync.Mutex // one start or restart at a time
}

func newEngine(bin, workDir string) *Engine {
	return &Engine{bin: bin, workDir: workDir, state: engineStarting}
}

var errEngineNotReady = errors.New("the emulator engine is not ready")

// current returns the running generation, or errEngineNotReady (with the state) when requests must be refused.
func (e *Engine) current() (*generation, engineState, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.state != engineReady || e.gen == nil {
		return nil, e.state, errEngineNotReady
	}
	return e.gen, e.state, nil
}

func (e *Engine) status() (engineState, string) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.state, e.lastErr
}

// engineEnv is the child's whole environment. It is built from scratch: nothing of the front's (the control token, the
// signing secrets) reaches the engine, and every opt-out of telemetry is set.
func engineEnv(home, configFile string) []string {
	return []string{
		"HOME=" + home,
		"EMULATOR_TELEMETRY=off",
		"EMULATOR_CONFIG=" + configFile,
		"PATH=/usr/local/bin:/usr/bin:/bin",
		"TMPDIR=" + filepath.Join(home, "tmp"),
	}
}

// engineArgs: loopback bind, a port the OS picks, telemetry off, signature checks off (any key is accepted).
func engineArgs() []string {
	return []string{"-b", "127.0.0.1", "-p", "0", "-t", "off", "-a", "off"}
}

const engineConfigTOML = "[telemetry]\nenabled = false\n"

type serverInfo struct {
	Fields struct {
		Message     string `json:"message"`
		EndpointURL string `json:"endpoint_url"`
		CAFile      string `json:"ca_file"`
	} `json:"fields"`
}

// start launches one generation and waits until the engine answers its health route.
func (e *Engine) start() error {
	e.mu.Lock()
	e.genCount++
	n := e.genCount
	e.mu.Unlock()

	dir := filepath.Join(e.workDir, fmt.Sprintf("rovara-aws-engine-%d-%d", os.Getpid(), n))
	home := filepath.Join(dir, "home")
	if err := os.MkdirAll(filepath.Join(home, "tmp"), 0o700); err != nil {
		return fmt.Errorf("cannot create the engine's work directory: %w", err)
	}
	configFile := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(configFile, []byte(engineConfigTOML), 0o600); err != nil {
		return fmt.Errorf("cannot write the engine's config: %w", err)
	}
	cmd := exec.Command(e.bin, engineArgs()...)
	cmd.Env = engineEnv(home, configFile)
	cmd.Dir = dir
	cmd.SysProcAttr = childAttrs()
	stdout, pipeW, err := os.Pipe() // one pipe for stdout and stderr
	if err != nil {
		return err
	}
	cmd.Stdout, cmd.Stderr = pipeW, pipeW
	var startErr error
	onSpawnThread(func() { startErr = cmd.Start() })
	pipeW.Close()
	if startErr != nil {
		stdout.Close()
		os.RemoveAll(dir)
		return fmt.Errorf("cannot start the engine: %w", startErr)
	}
	g := &generation{n: n, cmd: cmd, dir: dir, exited: make(chan struct{})}

	// The engine prints one JSON line with its endpoint and CA file; everything else is drained and dropped (its log
	// lines can name requests, and the front's log must never carry them).
	infoCh := make(chan serverInfo, 1)
	tail := &tailBuffer{max: 2048}
	go func() {
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 64*1024), 1<<20)
		sent := false
		for sc.Scan() {
			line := sc.Text()
			tail.add(line)
			if sent || !strings.Contains(line, "endpoint_url") {
				continue
			}
			var si serverInfo
			if json.Unmarshal([]byte(line), &si) == nil && si.Fields.EndpointURL != "" && si.Fields.CAFile != "" {
				sent = true
				infoCh <- si
			}
		}
		io.Copy(io.Discard, stdout)
		stdout.Close()
	}()
	go func() {
		g.exit = cmd.Wait()
		close(g.exited)
		e.onExit(g)
	}()

	var si serverInfo
	select {
	case si = <-infoCh:
	case <-g.exited:
		e.cleanup(g)
		return fmt.Errorf("the engine exited while starting (%v): %s", g.exit, tail.String())
	case <-time.After(20 * time.Second):
		e.kill(g)
		return fmt.Errorf("the engine did not report its endpoint within 20 s: %s", tail.String())
	}
	u := strings.TrimPrefix(si.Fields.EndpointURL, "https://")
	_, portStr, err := net.SplitHostPort(u)
	if err != nil {
		e.kill(g)
		return fmt.Errorf("the engine reported an endpoint the front cannot read")
	}
	g.port, _ = strconv.Atoi(portStr)
	client, err := engineClient(g.port, si.Fields.CAFile)
	if err != nil {
		e.kill(g)
		return err
	}
	g.client = client
	deadline := time.Now().Add(20 * time.Second)
	for {
		if err := probeEngine(g); err == nil {
			break
		}
		select {
		case <-g.exited:
			e.cleanup(g)
			return fmt.Errorf("the engine exited while starting (%v)", g.exit)
		default:
		}
		if time.Now().After(deadline) {
			e.kill(g)
			return errors.New("the engine did not become healthy within 20 s")
		}
		time.Sleep(25 * time.Millisecond)
	}
	e.mu.Lock()
	e.gen = g
	e.state = engineReady
	e.lastErr = ""
	e.mu.Unlock()
	return nil
}

// engineClient returns an HTTP client that can only ever reach 127.0.0.1:<port> and trusts only the engine's own CA.
func engineClient(port int, caFile string) (*http.Client, error) {
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("cannot read the engine's CA file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("the engine's CA file holds no certificate")
	}
	target := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	tr := &http.Transport{
		// Whatever host a request names, the connection goes to the engine's loopback port and nowhere else.
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp4", target)
		},
		TLSClientConfig:       &tls.Config{RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12},
		DisableCompression:    true, // bodies pass through exactly as the engine wrote them
		Proxy:                 nil,  // never an environment proxy
		MaxIdleConnsPerHost:   64,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: 0,
	}
	return &http.Client{
		Transport: tr,
		// A redirect is the caller's to follow; the front never does.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

func probeEngine(g *generation) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://127.0.0.1:"+strconv.Itoa(g.port)+"/__admin/health", nil)
	resp, err := g.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	if resp.StatusCode != 200 {
		return fmt.Errorf("engine health answered %d", resp.StatusCode)
	}
	return nil
}

// healthy is the live check behind GET /_rovara/health.
func (e *Engine) healthy() error {
	g, st, err := e.current()
	if err != nil {
		return fmt.Errorf("engine %s", st)
	}
	return probeEngine(g)
}

// onExit: an exit the front did not ask for turns health red for good (until a reset restarts the engine). State is
// never served from a process that died and came back.
func (e *Engine) onExit(g *generation) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if g.stopping {
		return
	}
	if e.gen == g || e.gen == nil {
		e.state = engineFailed
		e.lastErr = fmt.Sprintf("the engine exited unexpectedly: %v", g.exit)
		log.Printf("the engine exited unexpectedly (%v); health is red until a reset restarts it", g.exit)
	}
}

// stop ends one generation: SIGTERM (the engine deletes its keys), a wait, then SIGKILL; the directory is removed.
func (e *Engine) stop(g *generation) {
	if g == nil {
		return
	}
	e.mu.Lock()
	g.stopping = true
	e.mu.Unlock()
	if g.cmd.Process != nil {
		select {
		case <-g.exited:
		default:
			g.cmd.Process.Signal(syscall.SIGTERM)
			select {
			case <-g.exited:
			case <-time.After(5 * time.Second):
				g.cmd.Process.Kill()
				<-g.exited
			}
		}
	}
	if g.client != nil {
		g.client.CloseIdleConnections()
	}
	e.cleanup(g)
}

func (e *Engine) kill(g *generation) {
	e.mu.Lock()
	g.stopping = true
	e.mu.Unlock()
	if g.cmd.Process != nil {
		g.cmd.Process.Kill()
		<-g.exited
	}
	e.cleanup(g)
}

func (e *Engine) cleanup(g *generation) {
	if g.dir != "" {
		os.RemoveAll(g.dir)
	}
}

// Start brings the engine up the first time.
func (e *Engine) Start() error {
	e.resetMu.Lock()
	defer e.resetMu.Unlock()
	if err := e.start(); err != nil {
		e.mu.Lock()
		e.state = engineFailed
		e.lastErr = err.Error()
		e.mu.Unlock()
		return err
	}
	return nil
}

// Restart is the reset: the old engine is stopped completely, then a new one starts with empty state. While it runs,
// API requests are refused with 503. If the new engine cannot start, health stays red.
func (e *Engine) Restart() error {
	e.resetMu.Lock()
	defer e.resetMu.Unlock()
	e.mu.Lock()
	old := e.gen
	e.gen = nil
	e.state = engineResetting
	e.mu.Unlock()
	e.stop(old)
	if err := e.start(); err != nil {
		e.mu.Lock()
		e.state = engineFailed
		e.lastErr = err.Error()
		e.mu.Unlock()
		return err
	}
	return nil
}

// Stop ends the engine for good (the front is shutting down).
func (e *Engine) Stop() {
	e.resetMu.Lock()
	defer e.resetMu.Unlock()
	e.mu.Lock()
	old := e.gen
	e.gen = nil
	e.state = engineStopped
	e.mu.Unlock()
	e.stop(old)
}

type tailBuffer struct {
	mu   sync.Mutex
	max  int
	data string
}

func (t *tailBuffer) add(line string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.data += line + "\n"
	if len(t.data) > t.max {
		t.data = t.data[len(t.data)-t.max:]
	}
}

func (t *tailBuffer) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return strings.TrimSpace(t.data)
}
