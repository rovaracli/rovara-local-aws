//go:build go1.24

package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The h2c path (HTTP/2 with prior knowledge, for Node's AWS SDK) reaches the same handler: the same decode and the same guard.
func TestH2CGoesThroughTheRunnerDecodeAndGuard(t *testing.T) {
	f := startRunnerFront(t, nil)
	f.create("fl-h2", "java21", nil, pyZip())
	ts := httptest.NewUnstartedServer(f.srv)
	if !enableH2C(ts.Config) {
		t.Skip("h2c needs a newer toolchain")
	}
	ts.Start()
	defer ts.Close()
	p := new(http.Protocols)
	p.SetUnencryptedHTTP2(true)
	client := &http.Client{Transport: &http.Transport{Protocols: p}}
	send := func(headers map[string][]string, body []byte) (int, string, string) {
		req, _ := http.NewRequest("POST", ts.URL+"/", bytes.NewReader(body))
		for k, vs := range headers {
			req.Header[http.CanonicalHeaderKey(k)] = vs
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, resp.Proto, string(b)
	}
	hq := f.hiddenQueue()
	json10 := sqsJSON("ReceiveMessage")
	h := func(extra map[string][]string) map[string][]string { return hdrs(json10, extra) }
	for name, c := range map[string]struct {
		extra map[string][]string
		body  []byte
	}{
		"plain":       {nil, []byte(`{"QueueUrl":"` + hq + `"}`)},
		"gzip":        {map[string][]string{"Content-Encoding": {"gzip"}}, gz([]byte(`{"QueueUrl":"` + hq + `"}`))},
		"aws-chunked": {map[string][]string{"Content-Encoding": {"aws-chunked"}}, awsChunked([]byte(`{"QueueUrl":"` + hq + `"}`))},
		"escaped":     {nil, []byte(`{"QueueUrl":"` + strings.Replace(hq, "rovara-heavy", `rovara-heavy`, 1) + `"}`)},
	} {
		st, proto, body := send(h(c.extra), c.body)
		if st != 403 || proto != "HTTP/2.0" {
			t.Errorf("%s over h2c: %d %s %.100s", name, st, proto, body)
		}
	}
	if st, _, body := send(h(map[string][]string{"Content-Encoding": {"br"}}), []byte(`{}`)); st != 415 {
		t.Errorf("an encoding that is not decoded, over h2c: %d %s", st, body)
	}
	one := `{"QueueUrl":"http://aws:4566/000000000000/orders"}`
	if st, _, body := send(h(map[string][]string{"Content-Encoding": {"gzip"}}), gz([]byte(one))); st != 200 {
		t.Errorf("a customer's gzip call over h2c: %d %s", st, body)
	}
}
