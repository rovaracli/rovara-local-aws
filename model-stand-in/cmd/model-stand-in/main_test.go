package main

import (
	"bytes"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func write(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "c.json")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestValidateAndRefusals(t *testing.T) {
	var out bytes.Buffer
	good := write(t, `{"version":1,"endpoints":{"ep":{"model":{"kind":"fixed","body":"x"}}}}`)
	if code := run([]string{"--config", good, "--validate"}, &out); code != 0 || !strings.Contains(out.String(), "config ok") {
		t.Fatalf("%d %s", code, out.String())
	}
	out.Reset()
	if code := run([]string{"--config", write(t, `{"version":1}`), "--validate"}, &out); code != 1 {
		t.Fatalf("a bad config: %d", code)
	}
	out.Reset()
	if code := run([]string{"--config", filepath.Join(t.TempDir(), "missing.json")}, &out); code != 1 || strings.Contains(out.String(), t.TempDir()) {
		t.Fatalf("a missing config: %d %s", code, out.String())
	}
	if code := run([]string{"--nope"}, &out); code != 2 {
		t.Fatalf("a bad flag: %d", code)
	}
}

func freePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// A port that is taken is a start failure with exit code 1, not a process that looks healthy.
func TestBindFailureExits(t *testing.T) {
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Skip("no listener")
	}
	defer l.Close()
	port := l.Addr().(*net.TCPAddr).Port
	cfg := write(t, `{"version":1,"listen":":`+strconv.Itoa(port)+`","endpoints":{"ep":{"model":{"kind":"fixed","body":"x"}}}}`)
	done := make(chan int, 1)
	go func() { done <- run([]string{"--config", cfg}, &bytes.Buffer{}) }()
	select {
	case code := <-done:
		if code != 1 {
			t.Fatalf("exit %d", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("did not exit")
	}
}

func TestServesPingOverTCP(t *testing.T) {
	port := freePort(t)
	cfg := write(t, `{"version":1,"listen":":`+strconv.Itoa(port)+`","endpoints":{"ep":{"model":{"kind":"fixed","body":"hello"}}}}`)
	go run([]string{"--config", cfg}, &bytes.Buffer{})
	url := "http://127.0.0.1:" + strconv.Itoa(port)
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, err := http.Get(url + "/ping")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode != 200 {
				t.Fatalf("ping %d", resp.StatusCode)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("never came up")
		}
		time.Sleep(50 * time.Millisecond)
	}
	resp, err := http.Post(url+"/invocations", "text/plain", strings.NewReader("x"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var b bytes.Buffer
	b.ReadFrom(resp.Body)
	if b.String() != "hello" {
		t.Fatalf("%q", b.String())
	}
}
