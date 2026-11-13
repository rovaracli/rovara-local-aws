//go:build go1.24

package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A client that speaks HTTP/2 with prior knowledge over plain TCP (as Node's AWS SDK does) reaches the same handler, and an HTTP/1.1
// client still does.
func TestH2CAndHTTP1BothServed(t *testing.T) {
	var protos []string
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		protos = append(protos, r.Proto)
		w.Header().Set("Content-Type", "application/vnd.amazon.eventstream")
		w.WriteHeader(200)
		io.WriteString(w, "a")
		w.(http.Flusher).Flush()
		io.WriteString(w, "b")
	}))
	if !enableH2C(ts.Config) {
		t.Fatal("h2c is on with this toolchain")
	}
	ts.Start()
	defer ts.Close()
	for _, c := range []struct {
		name  string
		setup func(*http.Protocols)
		major int
	}{
		{"prior knowledge HTTP/2", func(p *http.Protocols) { p.SetUnencryptedHTTP2(true) }, 2},
		{"HTTP/1.1", func(p *http.Protocols) { p.SetHTTP1(true) }, 1},
	} {
		p := new(http.Protocols)
		c.setup(p)
		client := &http.Client{Transport: &http.Transport{Protocols: p}}
		resp, err := client.Post(ts.URL+"/model/x/converse-stream", "application/json", strings.NewReader("{}"))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.ProtoMajor != c.major || string(body) != "ab" {
			t.Errorf("%s: proto %s body %q", c.name, resp.Proto, body)
		}
	}
	if len(protos) != 2 || protos[0] != "HTTP/2.0" || protos[1] != "HTTP/1.1" {
		t.Errorf("handler saw %v", protos)
	}
}
