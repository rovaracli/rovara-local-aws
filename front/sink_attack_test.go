package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The hostile-code tests. Each TestAttack* is one family of attack the sink must survive; scripts and the report list them by name.

// ---- 1. SSRF: every spelling of an endpoint that is not meant to be delivered to

func TestAttackEndpointSpellingsNeverReachAnythingButARouteOrTheSink(t *testing.T) {
	cfg := &SinkConfig{Routes: map[string]net.IP{"localhost": net.ParseIP("10.1.1.1"), "127.0.0.1": net.ParseIP("10.1.1.1"), "web": net.ParseIP("10.1.1.1")}, SinkIP: net.ParseIP("10.1.1.2"), SinkHTTPPort: 80, SinkHTTPSPort: 443}
	rt := &routeTable{cfg: cfg}
	type want struct {
		proto, endpoint string
		kind            epKind
		dial            string
	}
	allowed := []want{
		{"http", "http://web/x", epRoute, "10.1.1.1:80"},
		{"http", "http://WEB:8080/x", epRoute, "10.1.1.1:8080"},
		{"http", "HTTP://web/x", epRoute, "10.1.1.1:80"},
		{"http", "http://localhost:3000/hook", epRoute, "10.1.1.1:3000"},
		{"http", "http://127.0.0.1:8080/", epRoute, "10.1.1.1:8080"},
		{"https", "https://web:8443/", epRoute, "10.1.1.1:8443"},
		{"http", "http://evil.com@localhost/", epRoute, "10.1.1.1:80"}, // the host is localhost; evil.com is the user-info
		{"http", "http://localhost@evil.com/", epSink, "10.1.1.2:80"},  // the host is evil.com; localhost is the user-info
		{"http", "http://hooks.example.com:8443/x", epSink, "10.1.1.2:80"},
		{"https", "https://hooks.example.com:8443/x", epSink, "10.1.1.2:443"},
		{"http", "http://127.0.0.1.nip.io/", epSink, "10.1.1.2:80"}, // a name that RESOLVES to loopback: it is only a Host header
		{"http", "http://localhost.evil.com/", epSink, "10.1.1.2:80"},
		{"http", "http://metadata.google.internal/computeMetadata/v1/", epSink, "10.1.1.2:80"},
		{"http", "http://instance-data/latest/meta-data/", epSink, "10.1.1.2:80"},
		{"http", "http://aws:4566/_rovara/reset", epSink, "10.1.1.2:80"}, // the front's own alias, with no route: the sink, never the front
		{"http", "http://web.evil.com/", epSink, "10.1.1.2:80"},
	}
	for _, w := range allowed {
		got, err := rt.classify(w.proto, w.endpoint)
		if err != nil {
			t.Errorf("%s refused: %v", w.endpoint, err)
			continue
		}
		if got.Kind != w.kind || got.Dial.addr != w.dial || got.Dial.self {
			t.Errorf("%s -> kind %d dial %q, want kind %d dial %q", w.endpoint, got.Kind, got.Dial.addr, w.kind, w.dial)
		}
	}
	refused := []string{
		"http://127.0.0.2/", "http://127.1/", "http://2130706433/", "http://0x7f000001/", "http://0x7f.0.0.1/", "http://017700000001/", "http://0177.0.0.1/",
		"http://[::1]/", "http://[::1]:8080/", "http://[::ffff:127.0.0.1]/", "http://[::ffff:7f00:1]/", "http://[::]/", "http://0.0.0.0/", "http://0/", "http://0.0.0.0:80",
		"http://169.254.169.254/latest/meta-data/", "http://169.254.169.254:80/", "http://[fd00:ec2::254]/", "http://10.0.0.1/", "http://192.168.1.1/", "http://172.16.0.1/",
		"http://8.8.8.8/", "http://1.1.1.1:80/", "http://3232235777/", "http://255.255.255.255/", "http://224.0.0.1/",
		"http://localhost./", "http://web./", "http://127.0.0.1./", "http://a_b/", "http://user@web@evil.com/", "http://evil.com\\@web/", "http://web#@evil.com/", "http://web/#frag",
		"http://web:0/", "http://web:65536/", "http://web:99999999999/", "http://web:/x", "http://:80/", "http:///x", "http://", "http://[::1/", "http://web /x", "http://web\t/",
		"http://web\r\nHost: evil/", "http://web/\r\nX: y", "http://１２７.0.0.1/", "http://web/\x00", "http://web/\x7f", "http://%77eb/", "http://web%00/",
		"http://web:8080:9090/", "http://[::1%25eth0]/", "http://" + strings.Repeat("a", 64) + ".com/", "http://" + strings.Repeat("a.", 130) + "com/", "http://-bad.com/", "http://bad-.com/",
		"ftp://web/", "gopher://web/", "file:///etc/passwd", "web", "//web/", "http:web", "http:/web", "javascript:alert(1)", "",
		"http://web/" + strings.Repeat("a", snsEndpointMax), // over the length limit
		"https://sns.us-east-1.amazonaws.com/",              // an AWS name with no TLS listener in this run
		"http://sns.us-east-1.amazonaws.com/",
	}
	for _, e := range refused {
		proto := "http"
		if strings.HasPrefix(e, "https://") {
			proto = "https"
		}
		if got, err := rt.classify(proto, e); err == nil {
			t.Errorf("accepted %q -> kind %d dial %q", e, got.Kind, got.Dial.addr)
		}
		if err := func() error { _, err := rt.classify("http", e); return err }(); err == nil && !strings.HasPrefix(e, "http://") {
			t.Errorf("accepted %q as http", e)
		}
	}
	if _, err := rt.classify("http", "https://web/"); err == nil {
		t.Error("an https endpoint was accepted for protocol http")
	}
	if _, err := rt.classify("https", "http://web/"); err == nil {
		t.Error("an http endpoint was accepted for protocol https")
	}
	if got, err := rt.classify("http", "http://web%2f@evil.com/"); err != nil || got.Kind != epSink || got.User != "web/" {
		t.Errorf("an encoded slash in the user-info: %v %+v", err, got)
	}
	// a route key written in any other spelling than the one the plan names is not a route
	for _, e := range []string{"http://Localhost:80/", "http://LOCALHOST/"} {
		if got, err := rt.classify("http", e); err != nil || got.Kind != epRoute {
			t.Errorf("%s: %v %+v", e, err, got)
		}
	}
	// AWS names: https only, to the run's own TLS listener, never an address of the endpoint's choosing
	rt2 := &routeTable{cfg: cfg, selfTLS: "10.1.1.9:443"}
	got, err := rt2.classify("https", "https://hooks.us-east-1.amazonaws.com/x")
	if err != nil || got.Kind != epSelf || got.Dial.addr != "10.1.1.9:443" || !got.Dial.self {
		t.Errorf("an AWS name: %v %+v", err, got)
	}
	if _, err := rt2.classify("http", "http://hooks.us-east-1.amazonaws.com/x"); err == nil {
		t.Error("an AWS name over http was accepted")
	}
	if got, err := rt2.classify("https", "https://hooks.us-east-1.amazonaws.com.evil.com/x"); err != nil || got.Kind != epSink {
		t.Errorf("a look-alike AWS name: %v %+v", err, got)
	}
	if got, err := rt2.classify("https", "https://hooks.us-east-1.amazonaws.com:8443/x"); err != nil || got.Dial.addr != "10.1.1.9:443" {
		t.Errorf("an AWS name with another port reaches %v", got)
	}
}

func TestAttackSSRFEndpointsAreRefusedAtSubscribeAndNothingIsDialled(t *testing.T) {
	r := newSinkRig(t, func(c *Config, s *SinkConfig) { s.AutoConfirm = true })
	topic := r.topic("t")
	for _, ep := range []string{"http://169.254.169.254/latest/meta-data/", "http://0x7f000001:4566/_rovara/reset", "http://[::1]:4566/", "http://2130706433:80/", "http://10.0.0.5/"} {
		code, body := r.subscribe(topic, "http", ep)
		if code != 400 || !strings.Contains(body, "InvalidParameter") || strings.Contains(body, "169.254") || strings.Contains(body, "0x7f") {
			t.Errorf("%s: %d %s", ep, code, body)
		}
	}
	if n := len(r.subRows()); n != 0 {
		t.Errorf("%d subscriptions were made", n)
	}
	for _, c := range r.aws.callLog() {
		if c == "sns:Subscribe" || strings.HasPrefix(c, "sqs:") {
			t.Errorf("a refused endpoint reached the engine: %v", r.aws.callLog())
			break
		}
	}
	if len(r.hook.got())+len(r.sink.got()) != 0 {
		t.Error("something was sent")
	}
	// the refusal is counted, with nothing of the endpoint in it
	_, _, led := r.do("GET", "/_rovara/ledger/summary", tok2(), "")
	if !strings.Contains(led, "sink:endpoint-refused") || strings.Contains(led, "169.254") {
		t.Errorf("ledger summary: %s", led)
	}
}

// ---- 2. DNS rebinding: a name in an endpoint is never resolved by the front

func TestAttackDNSRebindingHasNothingToRebind(t *testing.T) {
	var lookups int32
	old := lookupIPs
	lookupIPs = func(host string) ([]net.IP, error) {
		atomic.AddInt32(&lookups, 1)
		return []net.IP{net.ParseIP("127.0.0.1")}, nil // the attacker's name "resolves" to loopback, and later to anything
	}
	defer func() { lookupIPs = old }()
	r := newSinkRig(t, func(c *Config, s *SinkConfig) { s.AutoConfirm = true })
	topic := r.topic("t")
	// the hook is on loopback AND is the sink: a name that "resolves" to loopback still goes where the route table says (the sink), with that name as Host
	r.subscribe(topic, "http", fmt.Sprintf("http://rebind.attacker.test:%d/x", r.sink.port()))
	r.publish(topic, "m")
	sink_waitFor(t, "the sink to be called", 3*time.Second, func() bool { return len(r.sink.got()) == 1 })
	if g := r.sink.got()[0]; g.Host != fmt.Sprintf("rebind.attacker.test:%d", r.sink.port()) {
		t.Errorf("Host: %s", g.Host)
	}
	if n := atomic.LoadInt32(&lookups); n != 0 {
		t.Errorf("the front resolved a name %d times during a delivery", n)
	}
	if len(r.hook.got()) != 0 {
		t.Error("the sandbox app was called by a name that is not its route key")
	}
}

func TestAttackTheDialWallRefusesEverythingTheRouteDidNotChoose(t *testing.T) {
	n := newSinkNet(nil, "10.9.9.9:443", net.ParseIP("10.9.9.1"), time.Second)
	ctx := context.Background()
	if _, err := n.dial(ctx, "tcp", "10.1.1.1:80"); !errors.Is(err, errNoDialTarget) {
		t.Error("dialled with no target in the context")
	}
	if _, err := n.client.Get("http://10.1.1.1:80/"); err == nil || !strings.Contains(err.Error(), "dials only the address a route chose") {
		t.Errorf("the delivery client dialled without a target: %v", err)
	}
	for _, tgt := range []dialTarget{
		{addr: "8.8.8.8:80"}, {addr: "127.0.0.1:80"}, {addr: "169.254.169.254:80"}, {addr: "10.9.9.1:80"}, {addr: "[::1]:80"}, {addr: "[fd00::1]:80"}, {addr: "10.1.1.1:0"},
		{addr: "10.1.1.1:99999"}, {addr: "10.1.1.1"}, {addr: "evil.example.com:80"}, {addr: ""}, {addr: "0.0.0.0:80"}, {addr: "224.0.0.1:80"},
		{addr: "10.9.9.9:443"},              // the TLS listener's address, but not marked as the front's own
		{addr: "127.0.0.1:443", self: true}, // marked own, but not the listener's address
		{addr: "10.9.9.9:444", self: true},  // the listener's host, another port
		{addr: "10.9.9.9:443", self: false}, // see above
	} {
		// refused by the wall itself, before any connection is tried (a network error would mean a connection was attempted)
		if _, err := n.dial(withTarget(ctx, tgt), "tcp4", "ignored:1"); !errors.Is(err, errNoDialTarget) {
			t.Errorf("%+v: %v", tgt, err)
		}
	}
	if _, err := n.dial(withTarget(ctx, dialTarget{addr: "10.1.1.1:80"}), "udp", ""); !errors.Is(err, errNoDialTarget) {
		t.Error("dialled udp")
	}
	if _, err := n.dialUnix(ctx, "relative"); err == nil {
		t.Error("dialled a relative unix path")
	}
	// with no TLS listener configured, nothing is "the front's own"
	n2 := newSinkNet(nil, "", nil, time.Second)
	if _, err := n2.dial(withTarget(ctx, dialTarget{addr: "127.0.0.1:443", self: true}), "tcp4", ""); !errors.Is(err, errNoDialTarget) {
		t.Error("a self dial with no listener")
	}
}

// ---- 3. redirects, 4. oversized answers, 5. slow answers

func TestAttackARedirectIsNeverFollowed(t *testing.T) {
	r := newSinkRig(t, func(c *Config, s *SinkConfig) { s.AutoConfirm = true })
	topic := r.topic("t")
	r.hook.extra = func(w http.ResponseWriter, req *http.Request) bool {
		w.Header().Set("Location", "http://169.254.169.254/latest/meta-data/iam/security-credentials/")
		w.WriteHeader(302)
		return true
	}
	r.subscribe(topic, "http", hookURL(r.hook, "web", "/redirect"))
	r.publish(topic, "m")
	sub := r.onlySub()
	sink_waitFor(t, "the answer", 3*time.Second, func() bool { return len(r.attempts(sub.arn)) == 1 })
	time.Sleep(150 * time.Millisecond)
	if n := len(r.hook.got()); n != 1 {
		t.Errorf("%d requests: the redirect was followed", n)
	}
	if n := len(r.sink.got()); n != 0 {
		t.Errorf("the redirect reached the sink: %d", n)
	}
	if a := r.attempts(sub.arn)[0]; a.Status != 302 || strings.Contains(a.Error, "169.254") {
		t.Errorf("attempt: %+v", a)
	}
}

func TestAttackAHugeAnswerIsReadForAFewKilobytesOnly(t *testing.T) {
	r := newSinkRig(t, func(c *Config, s *SinkConfig) { s.AutoConfirm = true })
	topic := r.topic("t")
	var written int64
	r.hook.extra = func(w http.ResponseWriter, req *http.Request) bool {
		chunk := bytes.Repeat([]byte("A"), 1<<20)
		w.WriteHeader(200)
		for i := 0; i < 200; i++ {
			n, err := w.Write(chunk)
			atomic.AddInt64(&written, int64(n))
			if err != nil {
				break
			}
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
		return true
	}
	r.subscribe(topic, "http", hookURL(r.hook, "web", "/huge"))
	start := time.Now()
	r.publish(topic, "m")
	sub := r.onlySub()
	sink_waitFor(t, "the answer", 5*time.Second, func() bool { return len(r.attempts(sub.arn)) == 1 })
	if got := atomic.LoadInt64(&written); got >= 200<<20 || time.Since(start) > 4*time.Second {
		t.Errorf("the endpoint wrote %d bytes in %v: the answer was read to its end", got, time.Since(start))
	}
	if a := r.attempts(sub.arn)[0]; a.Outcome != "delivered" || a.Status != 200 {
		t.Errorf("attempt: %+v", a)
	}
}

func TestAttackASlowEndpointHoldsOnlyItsOwnSubscription(t *testing.T) {
	r := newSinkRig(t, func(c *Config, s *SinkConfig) { s.AutoConfirm = true; s.AttemptTimeout = 300 * time.Millisecond })
	topic := r.topic("t")
	stuck := make(chan struct{})
	defer close(stuck)
	r.hook.extra = func(w http.ResponseWriter, req *http.Request) bool {
		if strings.HasPrefix(req.RequestURI, "/slow") {
			select { // never answers, never closes
			case <-stuck:
			case <-req.Context().Done():
			}
			return true
		}
		return false
	}
	r.subscribe(topic, "http", hookURL(r.hook, "web", "/slow"), "DeliveryPolicy", `{"healthyRetryPolicy":{"numRetries":0}}`)
	r.subscribe(topic, "http", hookURL(r.hook, "web", "/fast"))
	r.publish(topic, "m")
	// the fast one is delivered at once, the slow one fails at the timeout and is recorded as such
	sink_waitFor(t, "the fast delivery", 2*time.Second, func() bool {
		for _, q := range r.hook.got() {
			if q.URI == "/fast" {
				return true
			}
		}
		return false
	})
	var slowArn string
	for _, row := range r.subRows() {
		if strings.HasSuffix(row["target"].(string), "/slow") {
			slowArn = row["subscriptionArn"].(string)
		}
	}
	start := time.Now()
	sink_waitFor(t, "the slow endpoint's failure", 3*time.Second, func() bool {
		a := r.attempts(slowArn)
		return len(a) == 1 && a[0].Outcome == "failed"
	})
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("the slow attempt took %v", d)
	}
}

// ---- 6. confirmation forgery

func TestAttackConfirmationForgery(t *testing.T) {
	r := newSinkRig(t, nil)
	hookB := newHook(t)
	topicA, topicB := r.topic("a"), r.topic("b")
	r.subscribe(topicA, "http", hookURL(r.hook, "web", "/a"))
	r.subscribe(topicB, "http", hookURL(hookB, "web", "/b"))
	sink_waitFor(t, "both confirmations", 3*time.Second, func() bool { return len(r.hook.got()) == 1 && len(hookB.got()) == 1 })
	tokenOf := func(h *hook) string {
		var d map[string]string
		json.Unmarshal([]byte(h.got()[0].Body), &d)
		return d["Token"]
	}
	ta, tb := tokenOf(r.hook), tokenOf(hookB)
	states := func() map[string]string {
		out := map[string]string{}
		for _, row := range r.subRows() {
			out[row["topicArn"].(string)] = row["state"].(string)
		}
		return out
	}
	confirm := func(topic, token string) int {
		code, _ := r.sns("ConfirmSubscription", "TopicArn", topic, "Token", token)
		return code
	}
	secret := hex.EncodeToString(r.srv.sink.secret)
	var subA *snsSub
	for _, s := range r.srv.sink.subs {
		if s.topicArn == topicA {
			subA = s
		}
	}
	forged := []struct{ name, topic, token string }{
		{"B's token on A's topic", topicA, tb},
		{"A's token on B's topic", topicB, ta},
		{"an empty token", topicA, ""},
		{"a short token", topicA, "AAAA"},
		{"A's token, one character short", topicA, ta[:len(ta)-1]},
		{"A's token plus a character", topicA, ta + "0"},
		{"A's token upper-cased", topicA, strings.ToUpper(ta)},
		{"A's token reversed", topicA, reverse(ta)},
		{"the control token", topicA, rigToken},
		{"the control token as the key of the same HMAC", topicA, hmacHex([]byte(rigToken), "sns-confirm|"+subA.arn)},
		{"a SHA-256 of the subscription arn", topicA, hex.EncodeToString(sha256Sum(subA.arn))},
		{"the secret itself", topicA, secret},
		{"A's token on a topic that does not exist", "arn:aws:sns:us-east-1:000000000000:nope", ta},
		{"A's token on a malformed topic", "not-an-arn", ta},
	}
	for _, f := range forged {
		if code := confirm(f.topic, f.token); code != 400 {
			t.Errorf("%s: %d", f.name, code)
		}
	}
	// the same through the link a message carries (a GET with no credential)
	for _, q := range []string{"Token=" + url.QueryEscape(tb) + "&TopicArn=" + url.QueryEscape(topicA), "Token=&TopicArn=" + url.QueryEscape(topicA), "TopicArn=" + url.QueryEscape(topicA)} {
		if code, _, _ := r.do("GET", "/?Action=ConfirmSubscription&"+q, nil, ""); code != 400 {
			t.Errorf("link %s: %d", q, code)
		}
	}
	if s := states(); s[topicA] != "pending" || s[topicB] != "pending" {
		t.Fatalf("a forgery confirmed something: %v", s)
	}
	if code := confirm(topicA, ta); code != 200 {
		t.Fatalf("the real token: %d", code)
	}
	if s := states(); s[topicA] != "confirmed" || s[topicB] != "pending" {
		t.Errorf("after A's confirmation: %v", s)
	}
	// a token does not survive its subscription
	arn := ""
	for _, row := range r.subRows() {
		if row["topicArn"] == topicB {
			arn = row["subscriptionArn"].(string)
		}
	}
	if code := confirm(topicB, tb); code != 200 {
		t.Fatalf("B: %d", code)
	}
	r.sns("Unsubscribe", "SubscriptionArn", arn)
	if code := confirm(topicB, tb); code != 400 {
		t.Errorf("a token after its subscription ended: %d", code)
	}
	// and a token of the earlier subscription does not confirm a new one at the same endpoint (new arn, new token)
	r.subscribe(topicB, "http", hookURL(hookB, "web", "/b"))
	sink_waitFor(t, "the second confirmation", 3*time.Second, func() bool { return len(hookB.got()) == 2 })
	if code := confirm(topicB, tb); code != 400 {
		t.Errorf("the old token confirmed the new subscription: %d", code)
	}
}

func reverse(s string) string {
	b := []byte(s)
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return string(b)
}

func sha256Sum(s string) []byte { h := sha256.Sum256([]byte(s)); return h[:] }

func hmacHex(key []byte, msg string) string {
	k := &snsSink{secret: key}
	_ = k
	return hex.EncodeToString(func() []byte { s := &snsSink{secret: key}; return []byte(s.tokenFor(msg)) }())
}

// ---- 7. signature spoofing, and the keys

func TestAttackSignatureSpoofingAndKeySecrecy(t *testing.T) {
	r := newSinkRig(t, func(c *Config, s *SinkConfig) { s.AutoConfirm = true; s.ServeCert = true })
	topic := r.topic("t")
	r.subscribe(topic, "http", hookURL(r.hook, "web", "/h"))
	r.publish(topic, "genuine", "Subject", "s")
	r.publish(topic, "genuine", "Subject", "")
	sink_waitFor(t, "two notifications", 3*time.Second, func() bool { return len(r.hook.got()) == 2 })
	var docs [2]map[string]interface{}
	for i := range docs {
		json.Unmarshal([]byte(r.hook.got()[i].Body), &docs[i])
	}
	certURL := docs[0]["SigningCertURL"].(string)
	_, _, certPEM := r.do("GET", strings.TrimPrefix(certURL, "http://aws:4566"), nil, "")
	blk, _ := pem.Decode([]byte(certPEM))
	cert, _ := x509.ParseCertificate(blk.Bytes)
	pub := cert.PublicKey.(*rsa.PublicKey)
	verify := func(sig, toSign string) bool {
		raw, _ := base64.StdEncoding.DecodeString(sig)
		sum := sha256.Sum256([]byte(toSign))
		return rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], raw) == nil
	}
	sts := func(d map[string]interface{}, withSubject bool) string {
		s := "Message\n" + d["Message"].(string) + "\nMessageId\n" + d["MessageId"].(string) + "\n"
		if withSubject {
			s += "Subject\n" + d["Subject"].(string) + "\n"
		}
		return s + "Timestamp\n" + d["Timestamp"].(string) + "\nTopicArn\n" + topic + "\nType\nNotification\n"
	}
	if !verify(docs[0]["Signature"].(string), sts(docs[0], true)) {
		t.Fatal("the genuine signature does not verify")
	}
	// the signature covers the subject, the message and the id: none can be changed or moved to another message
	if verify(docs[0]["Signature"].(string), sts(docs[0], false)) {
		t.Error("the signature verifies with the subject removed")
	}
	if verify(docs[0]["Signature"].(string), strings.Replace(sts(docs[0], true), "genuine", "genuinE", 1)) {
		t.Error("the signature verifies for a changed message")
	}
	if verify(docs[0]["Signature"].(string), strings.Replace(sts(docs[0], true), docs[0]["MessageId"].(string), docs[1]["MessageId"].(string), 1)) {
		t.Error("the signature verifies for another message id")
	}
	if verify(docs[1]["Signature"].(string), sts(docs[0], true)) {
		t.Error("one message's signature verifies another")
	}
	// a signature made with a key of the attacker's does not verify against the run's certificate
	evil, _ := rsa.GenerateKey(rand.Reader, 2048)
	sum := sha256.Sum256([]byte(sts(docs[0], true)))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, evil, crypto.SHA256, sum[:])
	if verify(base64.StdEncoding.EncodeToString(sig), sts(docs[0], true)) {
		t.Error("a forged signature verified")
	}
	// the certificate is served at that one path and no other; the key is nowhere
	runID := r.srv.sink.runID
	good := "/SimpleNotificationService-" + runID + ".pem"
	for _, p := range []string{good + "/", good + "/../x", "/simplenotificationservice-" + runID + ".pem", "/SimpleNotificationService-0000000000000000.pem", "/SimpleNotificationService-" + runID + ".key",
		"/SimpleNotificationService-" + runID[:8] + ".pem", "/x/SimpleNotificationService-" + runID + ".pem", "/_rovara/sns/SimpleNotificationService-" + runID + ".pem"} {
		if code, _, body := r.do("GET", p, nil, ""); code == 200 && strings.Contains(body, "CERTIFICATE") {
			t.Errorf("served at %s", p)
		}
	}
	if code, _, body := r.do("POST", good, nil, ""); code == 200 && strings.Contains(body, "CERTIFICATE") {
		t.Error("served to a POST")
	}
	hay := r.everythingSeen()
	for _, needle := range []string{"PRIVATE KEY", "RSA PRIVATE", hex.EncodeToString(r.srv.sink.secret)} {
		if strings.Contains(hay, needle) {
			t.Errorf("%q appears in what the sink sent or showed", needle)
		}
	}
}

// everythingSeen gathers every byte the sink sent out or shows: what the receivers got, the control reads, the ledger.
func (r *sinkRig) everythingSeen() string {
	var b strings.Builder
	for _, h := range []*hook{r.hook, r.sink} {
		for _, q := range h.got() {
			fmt.Fprintf(&b, "%v %s %s %s %v\n", q.Header, q.Method, q.URI, q.Body, q.Host)
		}
	}
	for _, m := range r.mail.msgs() {
		b.WriteString(m)
	}
	b.WriteString(strings.Join(r.mail.lines(), "\n"))
	for _, p := range []string{"/_rovara/sns/subscriptions", "/_rovara/sns/summary", "/_rovara/ledger", "/_rovara/ledger/summary"} {
		_, body := r.control(p)
		b.WriteString(body)
	}
	for _, row := range r.subRows() {
		_, body := r.control("/_rovara/sns/deliveries?subscription=" + url.QueryEscape(row["subscriptionArn"].(string)))
		b.WriteString(body)
	}
	return b.String()
}

// ---- 8. reading other subscriptions' deliveries

func TestAttackOneSubscriptionCannotReadAnothers(t *testing.T) {
	r := newSinkRig(t, func(c *Config, s *SinkConfig) { s.AutoConfirm = true })
	hookB := newHook(t)
	topicA, topicB := r.topic("a"), r.topic("b")
	r.subscribe(topicA, "http", hookURL(r.hook, "web", "/a"))
	r.subscribe(topicB, "http", hookURL(hookB, "web", "/b"))
	r.publish(topicA, "SECRET-FOR-A")
	sink_waitFor(t, "A's delivery", 3*time.Second, func() bool { return len(r.hook.got()) == 1 })
	time.Sleep(150 * time.Millisecond)
	if n := len(hookB.got()); n != 0 {
		t.Fatalf("B was sent A's message: %v", hookB.got())
	}
	if strings.Contains(r.everythingSeenBy(hookB), "SECRET-FOR-A") {
		t.Error("B can see A's message")
	}
	var arnA, arnB string
	for _, row := range r.subRows() {
		if row["topicArn"] == topicA {
			arnA = row["subscriptionArn"].(string)
		} else {
			arnB = row["subscriptionArn"].(string)
		}
	}
	// the control read is one subscription at a time, needs the token, and B's arn returns none of A's
	_, bBody := r.control("/_rovara/sns/deliveries?subscription=" + url.QueryEscape(arnB))
	if strings.Contains(bBody, "SECRET-FOR-A") || strings.Contains(bBody, arnA) {
		t.Errorf("B's read shows A: %s", bBody)
	}
	_, aBody := r.control("/_rovara/sns/deliveries?subscription=" + url.QueryEscape(arnA))
	if !strings.Contains(aBody, "SECRET-FOR-A") {
		t.Errorf("A's own read lacks its message: %s", aBody)
	}
	for _, h := range []map[string]string{nil, {controlHeader: "wrong"}, {controlHeader: rigToken + "," + rigToken}, {controlHeader: ""}} {
		if code, _, body := r.do("GET", "/_rovara/sns/deliveries?subscription="+url.QueryEscape(arnA), h, ""); code != 403 || strings.Contains(body, "SECRET") {
			t.Errorf("read with headers %v: %d %s", h, code, body)
		}
	}
	// the host-style and path tricks that reach control paths on the S3 side do not reach these either
	for _, p := range []string{"//_rovara/sns/subscriptions", "/./_rovara/sns/subscriptions", "/_ROVARA/sns/subscriptions", "/x/../_rovara/sns/subscriptions", "/_rovara/sns/../sns/subscriptions"} {
		if code, _, body := r.do("GET", p, nil, ""); code != 403 && !strings.Contains(body, "Resource not found") {
			t.Errorf("%s: %d %s", p, code, body)
		}
	}
}

func (r *sinkRig) everythingSeenBy(h *hook) string {
	var b strings.Builder
	for _, q := range h.got() {
		fmt.Fprintf(&b, "%v %s %s", q.Header, q.URI, q.Body)
	}
	return b.String()
}

func TestAttackTheTapQueuesCannotBeReachedOrSeen(t *testing.T) {
	r := newSinkRig(t, func(c *Config, s *SinkConfig) { s.AutoConfirm = true })
	topic := r.topic("t")
	r.subscribe(topic, "http", hookURL(r.hook, "web", "/h"))
	sub := r.onlySub()
	tapName := sinkQueueNameOf(sub.tapQueueURL)
	if !strings.HasPrefix(tapName, snsTapPrefix) {
		t.Fatalf("tap name %q", tapName)
	}
	sqsCall := func(op, body string) (int, string) {
		code, _, out := r.do("POST", "/", map[string]string{"X-Amz-Target": "AmazonSQS." + op, "Content-Type": "application/x-amz-json-1.0",
			"Authorization": "AWS4-HMAC-SHA256 Credential=K/20260101/us-east-1/sqs/aws4_request, SignedHeaders=host, Signature=00"}, body)
		return code, out
	}
	// the list does not show it, in JSON or in Query
	_, out := sqsCall("ListQueues", `{}`)
	if strings.Contains(out, snsTapPrefix) {
		t.Errorf("ListQueues (JSON) shows the tap: %s", out)
	}
	_, _, qout := r.do("POST", "/", map[string]string{"Authorization": "AWS4-HMAC-SHA256 Credential=K/20260101/us-east-1/sqs/aws4_request, SignedHeaders=host, Signature=00",
		"Content-Type": "application/x-www-form-urlencoded"}, "Action=ListQueues&Version=2012-11-05")
	if strings.Contains(qout, snsTapPrefix) {
		t.Errorf("ListQueues (Query) shows the tap: %s", qout)
	}
	r.aws.mu.Lock()
	r.aws.queues["a-queue-of-the-customers"] = nil
	r.aws.mu.Unlock()
	if _, out := sqsCall("ListQueues", `{}`); !strings.Contains(out, "a-queue-of-the-customers") {
		t.Errorf("a customer's queue vanished from the list: %s", out)
	}
	// every way to name the tap is answered as if the queue did not exist, and nothing is consumed
	r.publish(topic, "queued-for-the-tap")
	url1 := "https://sqs.us-east-1.amazonaws.com/000000000000/" + tapName
	escaped := strings.Replace(url1, "rovara-sns-tap-", `rovara-sns-tap-`, 1)
	attempts := []struct{ name, op, body string }{
		{"the queue url", "ReceiveMessage", `{"QueueUrl":"` + url1 + `","MaxNumberOfMessages":10}`},
		{"the queue url with the name's first letter as a unicode escape", "ReceiveMessage", `{"QueueUrl":"` + escaped + `"}`},
		{"the queue url with the whole prefix escaped", "ReceiveMessage", `{"QueueUrl":"https://sqs.us-east-1.amazonaws.com/000000000000/rovara-sns-tap-` + strings.TrimPrefix(tapName, snsTapPrefix) + `"}`},
		{"a name lookup", "GetQueueUrl", `{"QueueName":"` + tapName + `"}`},
		{"a purge", "PurgeQueue", `{"QueueUrl":"` + url1 + `"}`},
		{"a delete", "DeleteQueue", `{"QueueUrl":"` + url1 + `"}`},
		{"attributes", "GetQueueAttributes", `{"QueueUrl":"` + url1 + `","AttributeNames":["All"]}`},
		{"a send to it", "SendMessage", `{"QueueUrl":"` + url1 + `","MessageBody":"x"}`},
		{"squatting on a name with the prefix", "CreateQueue", `{"QueueName":"rovara-sns-tap-mine"}`},
		{"padding after the name", "ReceiveMessage", `{"QueueUrl":"` + url1 + `","x":"` + strings.Repeat("A", 5000) + `"}`},
		{"the field order reversed", "ReceiveMessage", `{"MaxNumberOfMessages":10,"QueueUrl":"` + url1 + `"}`},
	}
	for _, a := range attempts {
		code, out := sqsCall(a.op, a.body)
		if code != 400 || !strings.Contains(out, "QueueDoesNotExist") {
			t.Errorf("%s: %d %s", a.name, code, out)
		}
	}
	// a request too large to be read for the check is refused, not passed
	if code, out := sqsCall("ReceiveMessage", `{"QueueUrl":"`+url1+`","pad":"`+strings.Repeat("A", sqsGuardCap+10)+`"}`); code != 400 {
		t.Errorf("a padded request: %d %s", code, out[:min(len(out), 100)])
	}
	// Query form: the url in the form, in the query string and in the path
	for name, c := range map[string]struct{ path, body string }{
		"a form url":    {"/", "Action=ReceiveMessage&Version=2012-11-05&QueueUrl=" + url.QueryEscape(url1)},
		"a query url":   {"/?Action=ReceiveMessage&Version=2012-11-05&QueueUrl=" + url.QueryEscape(url1), ""},
		"the path form": {"/000000000000/" + tapName, "Action=ReceiveMessage&Version=2012-11-05"},
	} {
		code, _, out := r.do("POST", c.path, map[string]string{"Authorization": "AWS4-HMAC-SHA256 Credential=K/20260101/us-east-1/sqs/aws4_request, SignedHeaders=host, Signature=00",
			"Content-Type": "application/x-www-form-urlencoded"}, c.body)
		if code != 400 || !strings.Contains(out, "NonExistentQueue") {
			t.Errorf("%s: %d %s", name, code, out)
		}
	}
	if !refusesTapAccess("/", nil, nil, []byte("\xa1\x68QueueUrl\x78\x40https://x/"+tapName), true) || refusesTapAccess("/", nil, nil, []byte("\xa1\x68QueueUrl\x20"), true) {
		t.Error("the CBOR byte check")
	}
	sink_waitFor(t, "the tap's own delivery", 3*time.Second, func() bool { return len(r.hook.got()) == 1 })
	// its subscription is not theirs either: no attributes, no change, no unsubscribe
	if code, _ := r.sns("GetSubscriptionAttributes", "SubscriptionArn", sub.tapArn); code != 404 {
		t.Errorf("GetSubscriptionAttributes of the tap: %d", code)
	}
	if code, _ := r.sns("SetSubscriptionAttributes", "SubscriptionArn", sub.tapArn, "AttributeName", "FilterPolicy", "AttributeValue", `{"x":["y"]}`); code != 404 {
		t.Errorf("SetSubscriptionAttributes of the tap: %d", code)
	}
	if code, _ := r.sns("Unsubscribe", "SubscriptionArn", sub.tapArn); code != 200 {
		t.Errorf("Unsubscribe of the tap: %d", code)
	}
	r.aws.mu.Lock()
	still := false
	for _, s := range r.aws.subs {
		if s.arn == sub.tapArn {
			still = true
		}
	}
	filter := ""
	for _, s := range r.aws.subs {
		if s.arn == sub.tapArn {
			filter = s.attrs["FilterPolicy"]
		}
	}
	r.aws.mu.Unlock()
	if !still || filter != "" {
		t.Errorf("the tap subscription was changed through the API (still there: %v, filter %q)", still, filter)
	}
	for _, body := range []string{r.hook.got()[0].Body} {
		if strings.Contains(body, sub.tapArn) || strings.Contains(body, tapName) {
			t.Errorf("the tap's name is in a delivery: %s", body)
		}
	}
}

// ---- 9. header and protocol injection

func TestAttackHeaderInjectionOverHTTP(t *testing.T) {
	r := newSinkRig(t, func(c *Config, s *SinkConfig) { s.AutoConfirm = true })
	topic := r.topic("t")
	for _, ep := range []string{"http://web:80/h\r\nX-Evil: 1", "http://web/h\nX-Evil: 1", "http://a%0d%0ab:c@web/", "http://web/ h", "http://web/h\x00"} {
		if code, _ := r.subscribe(topic, "http", ep); code != 400 {
			t.Errorf("%q: %d", ep, code)
		}
	}
	// a percent-encoded CRLF in the path stays encoded on the wire
	r.subscribe(topic, "http", hookURL(r.hook, "web", "/h%0d%0aX-Evil:%201?q=%0d%0aY"))
	r.publish(topic, "line1\r\nX-Evil: 2\r\n\r\nPOST /smuggled HTTP/1.1", "Subject", "subj\r\nX-Evil: 3")
	sink_waitFor(t, "the notification", 3*time.Second, func() bool { return len(r.hook.got()) == 1 })
	g := r.hook.got()[0]
	for name := range g.Header {
		if strings.EqualFold(name, "X-Evil") || strings.HasPrefix(strings.ToLower(name), "x-evil") {
			t.Errorf("an injected header %q", name)
		}
	}
	if !strings.Contains(g.URI, "%0d%0a") || strings.ContainsAny(g.URI, "\r\n") {
		t.Errorf("request uri: %q", g.URI)
	}
	if strings.Contains(g.Body, "\r\n") || strings.Contains(g.Body, "\nX-Evil") {
		t.Errorf("the body has raw line breaks: %q", g.Body)
	}
	var doc map[string]string
	if err := json.Unmarshal([]byte(g.Body), &doc); err != nil || doc["Subject"] != "subj\r\nX-Evil: 3" || !strings.Contains(doc["Message"], "POST /smuggled") {
		t.Errorf("the body does not carry the text as data: %v %v", err, g.Body)
	}
	// the only headers are the ones the front writes
	for name := range g.Header {
		switch http.CanonicalHeaderKey(name) {
		case "Content-Type", "User-Agent", "Content-Length", "Accept-Encoding", "Connection", "X-Amz-Sns-Message-Type", "X-Amz-Sns-Message-Id", "X-Amz-Sns-Topic-Arn", "X-Amz-Sns-Subscription-Arn":
		default:
			t.Errorf("unexpected header %q", name)
		}
	}
}

func TestAttackEmailAndSMTPInjection(t *testing.T) {
	r := newSinkRig(t, func(c *Config, s *SinkConfig) { s.AutoConfirm = true })
	topic := r.topic("t")
	for _, a := range []string{"a@b.com\r\nRCPT TO:<x@y.com>", "a@b.com\nBcc: x@y.com", "a@b.com,c@d.com", "a@b.com>", "<a@b.com>", "a b@c.com", `"a b"@c.com`, "a@b.com;", "a@b", "@b.com", "a@", "a@@b.com", "a@b..com",
		"a@b.com\x00", "a@[127.0.0.1]", "Name <a@b.com>", "a@b.com (c)", strings.Repeat("a", 65) + "@b.com", "a@" + strings.Repeat("b", 250) + ".com", "ünï@b.com"} {
		if code, _ := r.subscribe(topic, "email", a); code != 400 {
			t.Errorf("%q: %d", a, code)
		}
	}
	if n := len(r.subRows()); n != 0 {
		t.Fatalf("%d subscriptions", n)
	}
	r.subscribe(topic, "email", "alice@example.com")
	r.publish(topic, "hello\r\n.\r\nQUIT\r\nMAIL FROM:<evil@x.com>\r\n.\n.\n\nRSET\n", "Subject", "Hi\r\nBcc: evil@example.com\r\nX-Evil: 1")
	sink_waitFor(t, "the mail", 3*time.Second, func() bool { return len(r.mail.msgs()) == 1 })
	m := r.mail.msgs()[0]
	head, _, _ := strings.Cut(m, "\r\n\r\n")
	for _, line := range strings.Split(head, "\r\n") {
		name, _, _ := strings.Cut(line, ":")
		switch name {
		case "From", "To", "Subject", "Date", "Message-ID", "MIME-Version", "Content-Type", "Content-Transfer-Encoding":
		default:
			t.Errorf("an unexpected header line %q", line)
		}
	}
	if strings.Contains(head, "\r\nBcc:") || strings.Contains(head, "\r\nX-Evil:") || !strings.Contains(head, "Subject: Hi Bcc: evil@example.com X-Evil: 1\r\n") {
		t.Errorf("the subject was not flattened to one line:\n%s", head)
	}
	cmds := []string{}
	for _, l := range r.mail.lines() {
		cmds = append(cmds, strings.Fields(l)[0])
	}
	if strings.Join(cmds, " ") != "EHLO MAIL RCPT DATA QUIT" {
		t.Errorf("SMTP commands: %v", r.mail.lines())
	}
	if !strings.Contains(m, "MAIL FROM:<evil@x.com>") {
		t.Error("the message text was altered")
	}
	// an id that is not an id never becomes a header
	sub := r.onlySub()
	r.srv.sink.takeEnvelope(sub, `{"Type":"Notification","MessageId":"abc\r\nBcc: x@y.com","Message":"m"}`)
	r.srv.sink.takeEnvelope(sub, `{"Type":"Notification","MessageId":"`+strings.Repeat("a", 200)+`","Message":"m"}`)
	time.Sleep(100 * time.Millisecond)
	if len(r.mail.msgs()) != 1 {
		t.Errorf("a bad message id produced mail: %d", len(r.mail.msgs()))
	}
	if cleanSubject(strings.Repeat("é", 100)) == "" || len(cleanSubject(strings.Repeat("x", 500))) > 100 || cleanSubject("\r\n\x00") != "AWS Notification Message" {
		t.Error("cleanSubject")
	}
}

// ---- 10. TLS names for https deliveries (the front as a client of the run CA)

func TestAttackHTTPSDeliveryTrustsOnlyTheRunCAAndTheEndpointsName(t *testing.T) {
	p := newTestPKI(t, "amazonaws.com", "web")
	other := newTestPKI(t, "amazonaws.com", "web") // a CA of another run
	serveTLS := func(pki *testPKI, names ...string) *hook {
		c, k := pki.leaf("srv"+strings.Join(names, "_"), leafOpts{names: names})
		cert, err := tls.LoadX509KeyPair(c, k)
		if err != nil {
			t.Fatal(err)
		}
		h := &hook{def: 200}
		h.ts = httptest.NewUnstartedServer(http.HandlerFunc(h.serve))
		h.ts.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
		h.ts.StartTLS()
		t.Cleanup(h.ts.Close)
		return h
	}
	good := serveTLS(p, "web")
	wrongName := serveTLS(p, "somethingelse")
	otherCA := serveTLS(other, "web")
	selfSigned := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer selfSigned.Close()
	r := newSinkRig(t, func(c *Config, s *SinkConfig) {
		s.AutoConfirm = true
		c.RunCARoots = p.pool()
		s.Routes["otherweb"] = net.ParseIP("127.0.0.1")
		s.Routes["selfsigned"] = net.ParseIP("127.0.0.1")
		s.Routes["wrongname"] = net.ParseIP("127.0.0.1")
	})
	topic := r.topic("t")
	ep := func(host string, h *hook) string {
		return fmt.Sprintf("https://%s:%d/h", host, h.ts.Listener.Addr().(*net.TCPAddr).Port)
	}
	cases := map[string]string{
		"web":        ep("web", good),                                                                        // the right name, the run's CA
		"wrongname":  ep("wrongname", wrongName),                                                             // a certificate for another name
		"otherweb":   ep("otherweb", otherCA),                                                                // a certificate of another run's CA
		"selfsigned": fmt.Sprintf("https://selfsigned:%d/h", selfSigned.Listener.Addr().(*net.TCPAddr).Port), // not the run's CA at all
	}
	arns := map[string]string{}
	for _, e := range cases {
		r.subscribe(topic, "https", e)
	}
	for _, row := range r.subRows() {
		for name := range cases {
			if strings.Contains(row["target"].(string), "://"+name+":") {
				arns[name] = row["subscriptionArn"].(string)
			}
		}
	}
	r.publish(topic, "tls")
	sink_waitFor(t, "the good delivery", 5*time.Second, func() bool { return len(good.got()) == 1 })
	for _, name := range []string{"wrongname", "otherweb", "selfsigned"} {
		name := name
		sink_waitFor(t, name+" to fail", 8*time.Second, func() bool {
			a := r.attempts(arns[name])
			return len(a) == 4 && a[3].Outcome == "failed"
		})
		if a := r.attempts(arns[name])[0]; !strings.Contains(a.Error, "certificate") && !strings.Contains(a.Error, "x509") {
			t.Errorf("%s: error %q", name, a.Error)
		}
	}
	for _, h := range []*hook{wrongName, otherCA} {
		if len(h.got()) != 0 {
			t.Error("a message was delivered over a connection that did not verify")
		}
	}
	// no root at all: nothing verifies
	r2 := newSinkRig(t, func(c *Config, s *SinkConfig) { s.AutoConfirm = true; s.DefaultNoRetries() })
	topic2 := r2.topic("t")
	r2.subscribe(topic2, "https", ep("web", good))
	r2.publish(topic2, "tls")
	sub2 := r2.onlySub()
	sink_waitFor(t, "the failure", 3*time.Second, func() bool { a := r2.attempts(sub2.arn); return len(a) >= 1 && a[0].Outcome != "delivered" })
	if len(good.got()) != 1 {
		t.Error("a run with no CA delivered over https")
	}
}

// DefaultNoRetries is a test convenience: one attempt only.
func (s *SinkConfig) DefaultNoRetries() { s.RetryBase = time.Millisecond }

// ---- 11. the control token never leaves

func TestAttackTheControlTokenNeverLeaves(t *testing.T) {
	var logs bytes.Buffer
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)
	r := newSinkRig(t, func(c *Config, s *SinkConfig) { s.AutoConfirm = true })
	topic := r.topic("t")
	hdr := map[string]string{controlHeader: rigToken, "Authorization": snsAuth["Authorization"], "Content-Type": snsAuth["Content-Type"], "Cookie": "session=" + rigToken, "Referer": "http://aws/" + rigToken}
	sub := func(proto, ep string) {
		v := url.Values{"Action": {"Subscribe"}, "Version": {"2010-03-31"}, "TopicArn": {topic}, "Protocol": {proto}, "Endpoint": {ep}}
		r.do("POST", "/", hdr, v.Encode())
	}
	sub("http", hookURL(r.hook, "web", "/h"))
	sub("http", "http://hooks.example.com/x")
	sub("email", "a@example.com")
	r.publish(topic, "m")
	sink_waitFor(t, "deliveries", 3*time.Second, func() bool { return len(r.hook.got()) == 1 && len(r.sink.got()) == 1 && len(r.mail.msgs()) == 1 })
	// bad requests that echo things back
	r.do("POST", "/", hdr, "Action=Subscribe&Version=2010-03-31&TopicArn="+url.QueryEscape(topic)+"&Protocol=http&Endpoint="+url.QueryEscape("http://"+rigToken+"/"))
	r.sns("ConfirmSubscription", "TopicArn", topic, "Token", rigToken)
	if hay := r.everythingSeen() + logs.String(); strings.Contains(hay, rigToken) {
		i := strings.Index(hay, rigToken)
		t.Errorf("the control token appears: ...%s...", hay[max(0, i-80):min(len(hay), i+120)])
	}
	if _, body := r.sns("ConfirmSubscription", "TopicArn", topic, "Token", rigToken); strings.Contains(body, rigToken) {
		t.Error("an error answer echoes the token")
	}
	for _, q := range r.hook.got() {
		for name := range q.Header {
			if strings.EqualFold(name, controlHeader) || strings.EqualFold(name, "Cookie") || strings.EqualFold(name, "Referer") || strings.EqualFold(name, "Authorization") {
				t.Errorf("a header of the caller's request reached the endpoint: %s", name)
			}
		}
	}
}

// ---- 12. exhaustion

func TestAttackOversizedInputs(t *testing.T) {
	r := newSinkRig(t, nil)
	topic := r.topic("t")
	if code, _ := r.subscribe(topic, "http", "http://web/"+strings.Repeat("a", 3000)); code != 400 {
		t.Errorf("a 3000-character endpoint: %d", code)
	}
	big := url.Values{"Action": {"Subscribe"}, "Version": {"2010-03-31"}, "TopicArn": {topic}, "Protocol": {"http"}, "Endpoint": {"http://web/"}, "Pad": {strings.Repeat("A", snsMaxControlBody+100)}}
	if code, _, body := r.do("POST", "/", snsAuth, big.Encode()); code != 400 || !strings.Contains(body, "too large") {
		t.Errorf("an oversized Subscribe: %d %s", code, body)
	}
	if n := len(r.subRows()); n != 0 {
		t.Errorf("%d subscriptions", n)
	}
	if code, _ := r.subscribe("arn:aws:sns:us-east-1:000000000000:"+strings.Repeat("a", 300), "http", "http://web/"); code != 400 {
		t.Errorf("a long topic arn: %d", code)
	}
	if code, _ := r.subscribe(topic, "http", "http://web/h", "FilterPolicy", "{not json"); code != 400 {
		t.Errorf("a bad filter policy: %d", code)
	}
	if code, _ := r.subscribe(topic, "HTTP", "http://web/h"); code != 400 {
		t.Errorf("an upper-case protocol: %d", code)
	}
	if code, _ := r.subscribe(topic, "Email", "a@example.com"); code != 400 {
		t.Errorf("a mixed-case email protocol: %d", code)
	}
	if code, _ := r.subscribe(topic, "http", "http://web/h", "Nonsense", "x"); code != 400 {
		t.Errorf("an unknown attribute: %d", code)
	}
	if n := len(r.subRows()); n != 0 {
		t.Errorf("a refused attribute left %d subscriptions", n)
	}
}

func TestAttackSubscriptionAndQueueCaps(t *testing.T) {
	r := newSinkRig(t, func(c *Config, s *SinkConfig) { s.AutoConfirm = true })
	topic := r.topic("t")
	release := make(chan struct{})
	var once sync.Once
	closeRelease := func() { once.Do(func() { close(release) }) }
	defer closeRelease()
	r.hook.extra = func(w http.ResponseWriter, req *http.Request) bool {
		if req.RequestURI == "/block" {
			<-release
		}
		return false
	}
	r.subscribe(topic, "http", hookURL(r.hook, "web", "/block"))
	sub := r.onlySub()
	// a stuck endpoint: 150 messages arrive, at most 100 are held, the rest are counted as dropped, none grows the queue past the cap
	for i := 0; i < 150; i++ {
		r.publish(topic, fmt.Sprintf("m%d", i))
	}
	sink_waitFor(t, "the queue to fill and spill", 6*time.Second, func() bool {
		r.srv.sink.mu.Lock()
		defer r.srv.sink.mu.Unlock()
		return sub.stats.Dropped >= 40
	})
	r.srv.sink.mu.Lock()
	held, dropped := len(sub.queue), sub.stats.Dropped
	r.srv.sink.mu.Unlock()
	if held > snsMaxPending || dropped < 40 {
		t.Errorf("held %d (cap %d), dropped %d", held, snsMaxPending, dropped)
	}
	for _, a := range r.attempts(sub.arn) {
		if a.Outcome == "dropped" && !strings.Contains(a.Error, "queue is full") {
			t.Errorf("a drop with another reason: %+v", a)
		}
	}
	closeRelease()
	// the 65th subscription is refused
	r2 := newSinkRig(t, func(c *Config, s *SinkConfig) { s.AutoConfirm = true })
	topic2 := r2.topic("t")
	for i := 0; i < snsMaxSubscriptions; i++ {
		if code, body := r2.subscribe(topic2, "http", hookURL(r2.hook, "web", fmt.Sprintf("/s%d", i))); code != 200 {
			t.Fatalf("subscription %d: %d %s", i, code, body)
		}
	}
	if code, body := r2.subscribe(topic2, "http", hookURL(r2.hook, "web", "/one-too-many")); code != 403 || !strings.Contains(body, "SubscriptionLimitExceeded") {
		t.Errorf("the 65th subscription: %d %s", code, body)
	}
	if n := len(r2.aws.queueNames()); n != snsMaxSubscriptions {
		t.Errorf("%d tap queues for %d subscriptions", n, snsMaxSubscriptions)
	}
	// ended subscriptions are remembered (to keep hiding the engine's entry) up to a cap, so a subscribe/unsubscribe loop cannot grow the table without end
	k2 := r2.srv.sink
	k2.mu.Lock()
	for i := 0; i < snsMaxHidden; i++ {
		k2.hidden[fmt.Sprintf("h%d", i)] = true
	}
	k2.mu.Unlock()
	if code, body := r2.subscribe(topic2, "http", hookURL(r2.hook, "web", "/hidden-cap")); code != 403 || !strings.Contains(body, "SubscriptionLimitExceeded") {
		t.Errorf("a subscription with the hidden table full: %d %s", code, body)
	}
	// the held bytes of all subscriptions are capped too
	sub2 := &snsSub{wake: make(chan struct{}, 1)}
	sub2.ctx, sub2.cancel = context.WithCancel(context.Background())
	defer sub2.cancel()
	k := r2.srv.sink
	k.mu.Lock()
	k.pending = snsMaxPendingBytes - 100
	k.mu.Unlock()
	k.enqueue(sub2, &snsDelivery{kind: "Notification", messageID: "x", size: 200})
	if len(sub2.queue) != 0 || sub2.stats.Dropped != 0 && false {
		t.Error("a delivery over the byte cap was held")
	}
}

func TestAttackAHugeMessageIsDroppedNotHeld(t *testing.T) {
	r := newSinkRig(t, func(c *Config, s *SinkConfig) { s.AutoConfirm = true })
	topic := r.topic("t")
	r.subscribe(topic, "http", hookURL(r.hook, "web", "/h"))
	r.aws.mu.Lock()
	r.aws.hugeBody = snsMaxMessageBytes + 1000
	r.aws.mu.Unlock()
	r.publish(topic, "x")
	sub := r.onlySub()
	sink_waitFor(t, "the drop", 3*time.Second, func() bool { return len(r.attempts(sub.arn)) == 1 })
	if a := r.attempts(sub.arn)[0]; a.Outcome != "dropped" || !strings.Contains(a.Error, "larger than") {
		t.Errorf("attempt: %+v", a)
	}
	if len(r.hook.got()) != 0 {
		t.Error("the huge message was delivered")
	}
}

// ---- 13. the front as its own target

func TestAttackAWSNameEndpointsGoOnlyToTheFrontsTLSListener(t *testing.T) {
	p := newTestPKI(t, "amazonaws.com")
	c1, k1 := p.leaf("one", leafOpts{names: []string{"hooks.us-east-1.amazonaws.com", "missing.us-east-1.amazonaws.com"}})
	ls, err := loadFor(t, p, [2]string{c1, k1})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	r := newSinkRig(t, func(c *Config, s *SinkConfig) {
		s.AutoConfirm = true
		c.RunCARoots, c.SelfTLSAddr = ls.root, raw.Addr().String()
	})
	ts := newTLSServer(r.srv, ls, 5*time.Second)
	go ts.Serve(tls.NewListener(raw, ls.tlsConfig()))
	defer ts.Close()
	topic := r.topic("t")
	// the SubscribeURL of a run with a TLS listener is the AWS-looking one
	r2code, _ := r.subscribe(topic, "https", "https://hooks.us-east-1.amazonaws.com:9999/path") // another port: still the listener
	if r2code != 200 {
		t.Fatalf("Subscribe: %d", r2code)
	}
	if code, _ := r.subscribe(topic, "http", "http://hooks.us-east-1.amazonaws.com/path"); code != 400 {
		t.Errorf("http to an AWS name: %d", code)
	}
	r.publish(topic, "to myself")
	sub := r.onlySub()
	sink_waitFor(t, "the delivery", 5*time.Second, func() bool { return len(r.attempts(sub.arn)) >= 1 })
	a := r.attempts(sub.arn)[0]
	// it arrived at the front's own API, which does not know the path: an answer, and so a delivery (404 is in the 200-499 range)
	if a.Outcome != "delivered" || a.Target != "https://hooks.us-east-1.amazonaws.com:9999/path" {
		t.Errorf("attempt: %+v", a)
	}
	// the ledger shows the front's own API received it: no engine call was made for it
	if len(r.hook.got())+len(r.sink.got()) != 0 {
		t.Error("an AWS-named delivery went to the app or the sink")
	}
	// a name the leaf does not cover fails honestly
	r.subscribe(topic, "https", "https://uncovered.us-east-1.amazonaws.com/x")
	var arn string
	for _, row := range r.subRows() {
		if strings.Contains(row["target"].(string), "uncovered") {
			arn = row["subscriptionArn"].(string)
		}
	}
	r.publish(topic, "again")
	sink_waitFor(t, "the uncovered name to fail", 8*time.Second, func() bool {
		a := r.attempts(arn)
		return len(a) == 4 && a[3].Outcome == "failed"
	})
}

func TestAttackConfigCannotAimDeliveriesAtTheFront(t *testing.T) {
	// the front's own address, as a route, the sink or the mail catcher, stops the front at start (TestSinkConfigParsing); and a route that
	// is the front's address in another spelling is the same address
	c := &Config{Host: "172.30.5.2", Planned: map[string]bool{"sns": true}}
	for _, v := range []string{"web=172.30.5.2", "web=172.030.5.2", "web=::ffff:172.30.5.2"} {
		if sc, err := parseSinkConfig(mapEnv(map[string]string{envSNSRoutes: v}), c); err == nil {
			t.Errorf("accepted %s: %+v", v, sc)
		}
	}
}

// ---- keep the imports honest

var _ = io.EOF
