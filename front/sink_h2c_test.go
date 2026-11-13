//go:build go1.24

package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

// The front's main port also speaks HTTP/2 with prior knowledge (h2c, h2c_go124.go). Everything the sink protects lives in the handler, which
// is the same for both, but the two differ in how a body's length is known (a header, or none at all) and in how the host, the headers and the
// path arrive; so each probe below is made over HTTP/1.1 and over h2c and must be answered the same way. The TLS listener stays HTTP/1.1
// (TestTLSListenerServesRunCALeavesAndTheAPI checks the negotiated protocol).
func TestAttackH2COnTheMainPortGetsTheSameAnswersAsHTTP1(t *testing.T) {
	r := newSinkRig(t, func(c *Config, s *SinkConfig) { s.AutoConfirm = true })
	h2 := httptest.NewUnstartedServer(r.srv)
	if !enableH2C(h2.Config) {
		t.Fatal("h2c is on with this toolchain")
	}
	h2.Start()
	defer h2.Close()
	pH1, pH2 := new(http.Protocols), new(http.Protocols)
	pH1.SetHTTP1(true)
	pH2.SetUnencryptedHTTP2(true)
	c1 := &http.Client{Transport: &http.Transport{Protocols: pH1}, CheckRedirect: noRedirect.CheckRedirect}
	c2 := &http.Client{Transport: &http.Transport{Protocols: pH2}, CheckRedirect: noRedirect.CheckRedirect}

	topic := r.topic("t")
	r.subscribe(topic, "http", hookURL(r.hook, "web", "/h"))
	sub := r.onlySub()
	tapURL := "https://sqs.us-east-1.amazonaws.com/000000000000/" + sinkQueueNameOf(sub.tapQueueURL)
	sqsAuth := "AWS4-HMAC-SHA256 Credential=K/20260101/us-east-1/sqs/aws4_request, SignedHeaders=host, Signature=00"
	bigForm := url.Values{"Action": {"Subscribe"}, "Version": {"2010-03-31"}, "TopicArn": {topic}, "Protocol": {"http"}, "Endpoint": {"http://web/x"}, "Pad": {strings.Repeat("A", snsMaxControlBody+10)}}.Encode()
	subForm := func(ep string) string {
		return url.Values{"Action": {"Subscribe"}, "Version": {"2010-03-31"}, "TopicArn": {topic}, "Protocol": {"http"}, "Endpoint": {ep}}.Encode()
	}
	type probe struct {
		name, method, path, host string
		headers                  map[string]string
		body                     string
		chunked                  bool // the body has no known length
	}
	probes := []probe{
		{name: "control read, no token", method: "GET", path: "/_rovara/sns/subscriptions"},
		{name: "control read, token", method: "GET", path: "/_rovara/sns/subscriptions", headers: tok2()},
		{name: "control read, wrong token", method: "GET", path: "/_rovara/sns/summary", headers: map[string]string{controlHeader: "nope"}},
		{name: "ledger, no token", method: "GET", path: "/_rovara/ledger"},
		{name: "doubled slash", method: "GET", path: "//_rovara/sns/subscriptions"},
		{name: "upper-case prefix", method: "GET", path: "/_ROVARA/sns/subscriptions"},
		{name: "dot segments", method: "GET", path: "/x/../_rovara/sns/subscriptions"},
		{name: "a bucket-style host on a control path", method: "GET", path: "/_rovara/sns/subscriptions", host: "bkt.aws"},
		{name: "a forwarded host on a control path", method: "GET", path: "/_rovara/sns/subscriptions", headers: map[string]string{"X-Forwarded-Host": "bkt.aws"}},
		{name: "ssrf endpoint", method: "POST", path: "/", headers: snsAuth, body: subForm("http://169.254.169.254/latest/")},
		{name: "ssrf endpoint, no length", method: "POST", path: "/", headers: snsAuth, body: subForm("http://[::1]:4566/"), chunked: true},
		{name: "oversized subscribe", method: "POST", path: "/", headers: snsAuth, body: bigForm},
		{name: "oversized subscribe, no length", method: "POST", path: "/", headers: snsAuth, body: bigForm, chunked: true},
		{name: "tap queue by url", method: "POST", path: "/", headers: map[string]string{"X-Amz-Target": "AmazonSQS.ReceiveMessage", "Content-Type": "application/x-amz-json-1.0", "Authorization": sqsAuth}, body: `{"QueueUrl":"` + tapURL + `"}`},
		{name: "tap queue, no length", method: "POST", path: "/", headers: map[string]string{"X-Amz-Target": "AmazonSQS.ReceiveMessage", "Content-Type": "application/x-amz-json-1.0", "Authorization": sqsAuth}, body: `{"QueueUrl":"` + tapURL + `"}`, chunked: true},
		{name: "tap queue, escaped name", method: "POST", path: "/", headers: map[string]string{"X-Amz-Target": "AmazonSQS.GetQueueUrl", "Content-Type": "application/x-amz-json-1.0", "Authorization": sqsAuth}, body: `{"QueueName":"rovara-sns-tap-` + strings.TrimPrefix(sinkQueueNameOf(sub.tapQueueURL), snsTapPrefix) + `"}`, chunked: true},
		{name: "oversized sqs body, no length", method: "POST", path: "/", headers: map[string]string{"X-Amz-Target": "AmazonSQS.ReceiveMessage", "Content-Type": "application/x-amz-json-1.0", "Authorization": sqsAuth}, body: `{"QueueUrl":"` + tapURL + `","pad":"` + strings.Repeat("A", sqsGuardCap+10) + `"}`, chunked: true},
		{name: "confirm link, forged token", method: "GET", path: "/?Action=ConfirmSubscription&TopicArn=" + topic + "&Token=" + strings.Repeat("0", 64)},
		{name: "signing cert, not served", method: "GET", path: "/SimpleNotificationService-" + r.srv.sink.runID + ".pem"},
	}
	idRe := regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	do := func(c *http.Client, base string, p probe) (int, string) {
		var body io.Reader
		if p.body != "" {
			body = strings.NewReader(p.body)
			if p.chunked {
				pr, pw := io.Pipe()
				go func() { io.WriteString(pw, p.body); pw.Close() }()
				body = pr // no length: HTTP/1.1 sends it chunked, h2 sends no content-length
			}
		}
		req, _ := http.NewRequest(p.method, base+p.path, body)
		if p.host != "" {
			req.Host = p.host
		}
		for k, v := range p.headers {
			req.Header.Set(k, v)
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", p.name, err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, idRe.ReplaceAllString(string(b), "ID")
	}
	for _, p := range probes {
		code1, body1 := do(c1, r.ts.URL, p)
		code2, body2 := do(c2, h2.URL, p)
		if code1 != code2 || body1 != body2 {
			t.Errorf("%s: HTTP/1.1 %d %.120q, h2c %d %.120q", p.name, code1, body1, code2, body2)
		}
	}
	// and the answers are the protective ones, not two matching successes
	if code, _ := do(c2, h2.URL, probes[0]); code != 403 {
		t.Errorf("h2c control read with no token: %d", code)
	}
	if code, body := do(c2, h2.URL, probes[1]); code != 200 || !strings.Contains(body, "subscriptions") {
		t.Errorf("h2c control read with the token: %d", code)
	}
	for _, i := range []int{9, 10, 11, 12, 13, 14, 15, 16} {
		if code, _ := do(c2, h2.URL, probes[i]); code != 400 {
			t.Errorf("h2c %s: %d", probes[i].name, code)
		}
	}
	if n := len(r.subRows()); n != 1 {
		t.Errorf("%d subscriptions after the probes", n)
	}
}
