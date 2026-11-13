package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

const runMainEnv = "ROVARA_FRONT_TEST_RUN_MAIN"

func freePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// startMain runs the front's real main() as a child of the test (the test binary re-enters as main) with a fake engine, and returns a channel
// that gets its exit, a way to stop it, and what it wrote to stderr.
func startMain(t *testing.T, extra map[string]string) (exited chan error, stop func(), stderr func() string) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe)
	env := []string{runMainEnv + "=1", "PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir(),
		envToken + "=tokentokentoken1", envHost + "=127.0.0.1", envPort + "=" + fmt.Sprint(freePort(t)), envBaseURL + "=http://aws:4566",
		envPresign + "=presignpresign1234", envReceipt + "=receiptreceipt1234", envEngineBin + "=" + fakeEngineBin(t), envWorkDir + "=" + t.TempDir(),
		envPlanned + "=sns,sqs"}
	for k, v := range extra {
		env = append(env, k+"="+v)
	}
	cmd.Env = env
	var mu sync.Mutex
	var buf bytes.Buffer
	cmd.Stderr = writerFunc(func(b []byte) (int, error) { mu.Lock(); defer mu.Unlock(); return buf.Write(b) })
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited = make(chan error, 1)
	done := make(chan struct{})
	go func() { err := cmd.Wait(); exited <- err; close(done) }()
	var once sync.Once
	stop = func() {
		once.Do(func() {
			select {
			case <-done:
				return
			default:
			}
			cmd.Process.Signal(syscall.SIGTERM)
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				cmd.Process.Kill()
			}
		})
	}
	t.Cleanup(stop)
	return exited, stop, func() string { mu.Lock(); defer mu.Unlock(); return buf.String() }
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(b []byte) (int, error) { return f(b) }

func TestFrontMainRefusesBadLeavesAndServesGoodOnes(t *testing.T) {
	p := newTestPKI(t, "amazonaws.com")
	other := newTestPKI(t, "amazonaws.com")
	goodC, goodK := p.leaf("good", leafOpts{names: []string{"sns.us-east-1.amazonaws.com"}})
	badC, badK := other.leaf("bad", leafOpts{names: []string{"sns.us-east-1.amazonaws.com"}}) // another run's CA
	tlsPort := freePort(t)
	envFor := func(chain, key string) map[string]string {
		return map[string]string{envTLSAddr: fmt.Sprintf("127.0.0.1:%d", tlsPort), envTLSRoot: p.rootFile(), envTLSLeaves: chain + ":" + key}
	}
	// a leaf the run CA did not make: the front stops, with a sentence that names no secret, and nothing listens on the TLS port
	exited, _, stderr := startMain(t, envFor(badC, badK))
	select {
	case err := <-exited:
		if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() != 1 {
			t.Errorf("exit: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the front did not stop for a leaf of another CA")
	}
	if msg := stderr(); !strings.Contains(msg, "Refusing to start") || strings.Contains(msg, "PRIVATE KEY") {
		t.Errorf("stderr: %q", msg)
	}
	if c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", tlsPort), 300*time.Millisecond); err == nil {
		c.Close()
		t.Error("something listens on the TLS port")
	}
	// the right leaf: it serves, over https, the same API, and stops on SIGTERM
	exited, stop, _ := startMain(t, envFor(goodC, goodK))
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", tlsPort))
		},
		TLSClientConfig: &tls.Config{RootCAs: p.pool(), ServerName: "sns.us-east-1.amazonaws.com"},
	}}
	var code int
	var body string
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := client.Get("https://sns.us-east-1.amazonaws.com/_rovara/health")
		if err == nil {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			code, body = resp.StatusCode, string(b)
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if code != 200 || !strings.Contains(body, `"services"`) {
		t.Fatalf("health over https: %d %s", code, body)
	}
	stop()
	select {
	case <-exited:
	case <-time.After(10 * time.Second):
		t.Error("the front did not stop")
	}
}
