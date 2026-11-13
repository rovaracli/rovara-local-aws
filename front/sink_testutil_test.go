package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---- a test copy of the run CA of worker/src/run-ca.ts: a root (path length 1, no constraint) that signs ONE intermediate (path length 0,
// a critical name constraint on the run's names, every IP excluded), which signs the leaves.

type testPKI struct {
	t        *testing.T
	root     *x509.Certificate
	rootKey  *ecdsa.PrivateKey
	rootPEM  []byte
	inter    *x509.Certificate
	interKey *ecdsa.PrivateKey
	interPEM []byte
	dir      string
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 100))
	return n.Add(n, big.NewInt(1))
}

func pemCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// newTestPKI makes the CA for the permitted names.
func newTestPKI(t *testing.T, permitted ...string) *testPKI {
	t.Helper()
	p := &testPKI{t: t, dir: t.TempDir(), rootKey: newKey(t), interKey: newKey(t)}
	now := time.Now()
	rootT := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "Rovara test root"}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(2 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, MaxPathLen: 1, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, rootT, rootT, &p.rootKey.PublicKey, p.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	p.root, _ = x509.ParseCertificate(der)
	p.rootPEM = pemCert(der)
	interT := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "Rovara test CA"}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(2 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, MaxPathLen: 0, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		PermittedDNSDomainsCritical: true, PermittedDNSDomains: permitted,
		ExcludedIPRanges: []*net.IPNet{{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}, {IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}}}
	der, err = x509.CreateCertificate(rand.Reader, interT, p.root, &p.interKey.PublicKey, p.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	p.inter, _ = x509.ParseCertificate(der)
	p.interPEM = pemCert(der)
	return p
}

type leafOpts struct {
	names     []string
	ips       []net.IP
	signer    string // "" or "inter": the intermediate; "root": the root itself
	ca        bool
	noEKU     bool
	expired   bool
	chainRoot bool // put the root in the chain file too
}

// leaf makes one leaf and writes chain.pem and key.pem; it returns the two paths.
func (p *testPKI) leaf(name string, o leafOpts) (chainPath, keyPath string) {
	p.t.Helper()
	key := newKey(p.t)
	now := time.Now()
	nb, na := now.Add(-5*time.Minute), now.Add(time.Hour)
	if o.expired {
		nb, na = now.Add(-2*time.Hour), now.Add(-time.Hour)
	}
	tmpl := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "Rovara test leaf"}, NotBefore: nb, NotAfter: na, DNSNames: o.names, IPAddresses: o.ips,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: o.ca}
	if o.noEKU {
		tmpl.ExtKeyUsage = nil
	}
	parent, pkey := p.inter, p.interKey
	chain := p.interPEM
	if o.signer == "root" {
		parent, pkey = p.root, p.rootKey
		chain = nil
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, pkey)
	if err != nil {
		p.t.Fatal(err)
	}
	full := append(pemCert(der), chain...)
	if o.chainRoot {
		full = append(full, p.rootPEM...)
	}
	kder, _ := x509.MarshalPKCS8PrivateKey(key)
	chainPath = filepath.Join(p.dir, name+"-chain.pem")
	keyPath = filepath.Join(p.dir, name+"-key.pem")
	os.WriteFile(chainPath, full, 0o644)
	os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}), 0o600)
	return
}

func (p *testPKI) rootFile() string {
	path := filepath.Join(p.dir, "root.pem")
	os.WriteFile(path, p.rootPEM, 0o644)
	return path
}

func (p *testPKI) pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(p.root)
	return pool
}

// ---- a fake engine for the SNS sink: SNS (Query) and SQS (JSON), as the real engine answers them (probed against v1.0.322)

type fakeSub struct {
	arn, topic, protocol, endpoint string
	attrs                          map[string]string
}

type fakeAWS struct {
	mu        sync.Mutex
	topics    map[string]bool
	subs      []*fakeSub
	queues    map[string][]string // name -> bodies
	policies  map[string]string
	calls     []string
	failQueue bool
	hugeBody  int // when > 0, every published message's envelope Message is this many bytes
	ts        *httptest.Server
	auths     []string // "<service> <action> <region> <access key> <token>" of every call, as the engine was told who made it
	// afterSubscribe runs after the engine has taken a non-SQS Subscribe, before its answer is read (a test's way to make something happen in between)
	afterSubscribe func()
}

func newFakeAWS(t *testing.T) *fakeAWS {
	f := &fakeAWS{topics: map[string]bool{}, queues: map[string][]string{}, policies: map[string]string{}}
	f.ts = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.ts.Close)
	return f
}

func (f *fakeAWS) engine() *Engine {
	port, _ := strconv.Atoi(strings.TrimPrefix(f.ts.URL, "https://127.0.0.1:"))
	return &Engine{state: engineReady, gen: &generation{port: port, client: f.ts.Client()}}
}

func (f *fakeAWS) callLog() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func (f *fakeAWS) queueDepth(prefix string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for name, q := range f.queues {
		if strings.HasPrefix(name, prefix) {
			n += len(q)
		}
	}
	return n
}

func (f *fakeAWS) queueNames() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for n := range f.queues {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func xmlOf(action, result string) string {
	return `<` + action + `Response xmlns="http://sns.amazonaws.com/doc/2010-03-31/">` + result + `<ResponseMetadata><RequestId>` + newUUID() + `</RequestId></ResponseMetadata></` + action + `Response>`
}

var scopeRe = regexp.MustCompile(`Credential=([^/]*)/[0-9]{8}/([^/]*)/([^/]*)/aws4_request`)

// engineBody is the body as the REAL engine reads it: aws-chunked framing removed for every service (when the first content-encoding value
// says so), then gunzipped when any value contains gzip (the RPC protocols).
func engineBody(r *http.Request, raw []byte) []byte {
	enc := strings.ToLower(strings.Join(r.Header.Values("Content-Encoding"), ","))
	if strings.HasPrefix(strings.TrimSpace(enc), "aws-chunked") {
		var out bytes.Buffer
		rest := raw
		for len(rest) > 0 {
			i := bytes.Index(rest, []byte("\r\n"))
			if i < 0 {
				break
			}
			n, err := strconv.ParseInt(strings.SplitN(string(rest[:i]), ";", 2)[0], 16, 64)
			if err != nil || n == 0 {
				break
			}
			out.Write(rest[i+2 : i+2+int(n)])
			rest = rest[i+2+int(n)+2:]
		}
		raw = out.Bytes()
	}
	if strings.Contains(enc, "gzip") {
		if zr, err := gzip.NewReader(bytes.NewReader(raw)); err == nil {
			if dec, err := io.ReadAll(zr); err == nil {
				return dec
			}
		}
	}
	return raw
}

func (f *fakeAWS) serve(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	body := engineBody(r, raw)
	action := ""
	if t := r.Header.Get("X-Amz-Target"); t != "" {
		action = t[strings.LastIndex(t, ".")+1:]
	}
	var form url.Values
	if action == "" {
		form, _ = url.ParseQuery(string(body))
		action = form.Get("Action")
	}
	if m := scopeRe.FindStringSubmatch(r.Header.Get("Authorization")); m != nil && r.URL.Path != "/__admin/health" {
		f.mu.Lock()
		f.auths = append(f.auths, m[3]+" "+action+" "+m[2]+" "+m[1]+" "+r.Header.Get("X-Amz-Security-Token"))
		f.mu.Unlock()
		if form != nil {
			form.Set("__region", m[2])
		}
	}
	if t := r.Header.Get("X-Amz-Target"); strings.HasPrefix(t, "AmazonSQS.") {
		f.sqs(w, strings.TrimPrefix(t, "AmazonSQS."), body)
		return
	}
	if r.URL.Path == "/__admin/health" {
		io.WriteString(w, "ok")
		return
	}
	f.sns(w, form.Get("Action"), form)
	if form.Get("Action") == "Subscribe" && form.Get("Protocol") != "sqs" && f.afterSubscribe != nil {
		f.afterSubscribe()
	}
}

func (f *fakeAWS) authLog() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.auths...)
}

// inject puts a raw body on a queue, as if SNS had sent it.
func (f *fakeAWS) inject(queue, body string) {
	f.mu.Lock()
	f.queues[queue] = append(f.queues[queue], body)
	f.mu.Unlock()
}

func sinkQueueNameOf(u string) string { return u[strings.LastIndexAny(u, "/:")+1:] }

func (f *fakeAWS) sqs(w http.ResponseWriter, action string, body []byte) {
	var req map[string]interface{}
	json.Unmarshal(body, &req)
	str := func(k string) string { s, _ := req[k].(string); return s }
	f.mu.Lock()
	f.calls = append(f.calls, "sqs:"+action)
	w.Header().Set("Content-Type", "application/x-amz-json-1.0")
	switch action {
	case "CreateQueue":
		if f.failQueue {
			f.mu.Unlock()
			w.WriteHeader(500)
			io.WriteString(w, `{"__type":"InternalFailure","message":"no"}`)
			return
		}
		n := str("QueueName")
		if f.queues[n] == nil {
			f.queues[n] = []string{}
		}
		f.mu.Unlock()
		fmt.Fprintf(w, `{"QueueUrl":"https://sqs.us-east-1.amazonaws.com/000000000000/%s"}`, n)
		return
	case "SetQueueAttributes":
		if at, ok := req["Attributes"].(map[string]interface{}); ok {
			f.policies[sinkQueueNameOf(str("QueueUrl"))], _ = at["Policy"].(string)
		}
		f.mu.Unlock()
		io.WriteString(w, `{}`)
		return
	case "DeleteQueue":
		delete(f.queues, sinkQueueNameOf(str("QueueUrl")))
		f.mu.Unlock()
		io.WriteString(w, `{}`)
		return
	case "DeleteMessage":
		f.mu.Unlock()
		io.WriteString(w, `{}`)
		return
	case "ListQueues":
		var urls []string
		for n := range f.queues {
			urls = append(urls, `"https://sqs.us-east-1.amazonaws.com/000000000000/`+n+`"`)
		}
		sort.Strings(urls)
		f.mu.Unlock()
		fmt.Fprintf(w, `{"QueueUrls":[%s]}`, strings.Join(urls, ","))
		return
	case "ReceiveMessage":
		name := sinkQueueNameOf(str("QueueUrl"))
		q, ok := f.queues[name]
		if !ok {
			f.mu.Unlock()
			w.WriteHeader(400)
			io.WriteString(w, `{"__type":"QueueDoesNotExist","message":"The specified queue does not exist."}`)
			return
		}
		take := q
		max := 10
		if m, ok := req["MaxNumberOfMessages"].(float64); ok && m >= 1 && m < 10 {
			max = int(m)
		}
		if len(take) > max {
			take = take[:max]
		}
		f.queues[name] = q[len(take):]
		f.mu.Unlock()
		if len(take) == 0 {
			time.Sleep(60 * time.Millisecond)
			io.WriteString(w, `{}`)
			return
		}
		var msgs []string
		for _, b := range take {
			bj, _ := json.Marshal(b)
			msgs = append(msgs, fmt.Sprintf(`{"MessageId":"%s","ReceiptHandle":"rh","Body":%s}`, newUUID(), bj))
		}
		fmt.Fprintf(w, `{"Messages":[%s]}`, strings.Join(msgs, ","))
		return
	}
	f.mu.Unlock()
	io.WriteString(w, `{}`)
}

func (f *fakeAWS) sns(w http.ResponseWriter, action string, p url.Values) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "sns:"+action)
	w.Header().Set("Content-Type", "text/xml")
	switch action {
	case "CreateTopic":
		region := p.Get("__region")
		if region == "" {
			region = "us-east-1"
		}
		arn := "arn:aws:sns:" + region + ":000000000000:" + p.Get("Name")
		f.topics[arn] = true
		io.WriteString(w, xmlOf("CreateTopic", "<CreateTopicResult><TopicArn>"+arn+"</TopicArn></CreateTopicResult>"))
	case "DeleteTopic":
		delete(f.topics, p.Get("TopicArn"))
		var keep []*fakeSub
		for _, s := range f.subs {
			if s.topic != p.Get("TopicArn") {
				keep = append(keep, s)
			}
		}
		f.subs = keep
		io.WriteString(w, xmlOf("DeleteTopic", ""))
	case "Subscribe":
		if !f.topics[p.Get("TopicArn")] {
			w.WriteHeader(404)
			io.WriteString(w, `<ErrorResponse><Error><Type>Sender</Type><Code>NotFound</Code><Message>Topic does not exist</Message></Error></ErrorResponse>`)
			return
		}
		proto, ep := p.Get("Protocol"), p.Get("Endpoint")
		if proto == "sqs" {
			if _, ok := f.queues[sinkQueueNameOf(ep)]; !ok {
				w.WriteHeader(400)
				io.WriteString(w, `<ErrorResponse><Error><Type>Sender</Type><Code>InvalidParameter</Code><Message>no queue</Message></Error></ErrorResponse>`)
				return
			}
			s := &fakeSub{arn: p.Get("TopicArn") + ":" + newUUID(), topic: p.Get("TopicArn"), protocol: proto, endpoint: ep, attrs: map[string]string{}}
			for i := 1; i < 20; i++ {
				if k := p.Get(fmt.Sprintf("Attributes.entry.%d.key", i)); k != "" {
					s.attrs[k] = p.Get(fmt.Sprintf("Attributes.entry.%d.value", i))
				}
			}
			f.subs = append(f.subs, s)
			io.WriteString(w, xmlOf("Subscribe", "<SubscribeResult><SubscriptionArn>"+s.arn+"</SubscriptionArn></SubscribeResult>"))
			return
		}
		for _, s := range f.subs {
			if s.topic == p.Get("TopicArn") && s.protocol == proto && s.endpoint == ep {
				io.WriteString(w, xmlOf("Subscribe", "<SubscribeResult><SubscriptionArn>pending confirmation</SubscriptionArn></SubscribeResult>"))
				return
			}
		}
		f.subs = append(f.subs, &fakeSub{topic: p.Get("TopicArn"), protocol: proto, endpoint: ep, attrs: map[string]string{}})
		io.WriteString(w, xmlOf("Subscribe", "<SubscribeResult><SubscriptionArn>pending confirmation</SubscriptionArn></SubscribeResult>"))
	case "ListSubscriptions", "ListSubscriptionsByTopic":
		var b strings.Builder
		for i, s := range f.subs {
			if action == "ListSubscriptionsByTopic" && s.topic != p.Get("TopicArn") {
				continue
			}
			arn := s.arn
			if arn == "" {
				arn = "PendingConfirmation"
			}
			open := "<member>"
			if i == 0 {
				open = `<member xmlns="http://sns.amazonaws.com/doc/2010-03-31/">`
			}
			b.WriteString(open + "<SubscriptionArn>" + arn + "</SubscriptionArn><Owner>000000000000</Owner><Protocol>" + s.protocol + "</Protocol><Endpoint>" +
				xmlEscape(s.endpoint) + "</Endpoint><TopicArn>" + s.topic + "</TopicArn></member>")
		}
		io.WriteString(w, xmlOf(action, "<"+action+"Result><Subscriptions>"+b.String()+"</Subscriptions></"+action+"Result>"))
	case "GetTopicAttributes":
		confirmed, pending := 0, 0
		for _, s := range f.subs {
			if s.topic == p.Get("TopicArn") {
				if s.arn == "" {
					pending++
				} else {
					confirmed++
				}
			}
		}
		io.WriteString(w, xmlOf("GetTopicAttributes", fmt.Sprintf("<GetTopicAttributesResult><Attributes><entry><key>TopicArn</key><value>%s</value></entry><entry><key>SubscriptionsPending</key><value>%d</value></entry><entry><key>SubscriptionsConfirmed</key><value>%d</value></entry><entry><key>SubscriptionsDeleted</key><value>0</value></entry></Attributes></GetTopicAttributesResult>", p.Get("TopicArn"), pending, confirmed)))
	case "SetSubscriptionAttributes":
		for _, s := range f.subs {
			if s.arn == p.Get("SubscriptionArn") && s.arn != "" {
				s.attrs[p.Get("AttributeName")] = p.Get("AttributeValue")
			}
		}
		io.WriteString(w, xmlOf("SetSubscriptionAttributes", ""))
	case "Unsubscribe":
		if p.Get("SubscriptionArn") == "PendingConfirmation" {
			w.WriteHeader(400)
			io.WriteString(w, `<ErrorResponse><Error><Type>Sender</Type><Code>InvalidParameter</Code><Message>Cannot unsubscribe a subscription that is pending confirmation</Message></Error></ErrorResponse>`)
			return
		}
		var keep []*fakeSub
		for _, s := range f.subs {
			if s.arn == "" || s.arn != p.Get("SubscriptionArn") {
				keep = append(keep, s)
			}
		}
		f.subs = keep
		io.WriteString(w, xmlOf("Unsubscribe", ""))
	case "Publish":
		topic := p.Get("TopicArn")
		id := newUUID()
		attrs := map[string]map[string]string{}
		for i := 1; i < 20; i++ {
			if n := p.Get(fmt.Sprintf("MessageAttributes.entry.%d.Name", i)); n != "" {
				attrs[n] = map[string]string{"Type": p.Get(fmt.Sprintf("MessageAttributes.entry.%d.Value.DataType", i)), "Value": p.Get(fmt.Sprintf("MessageAttributes.entry.%d.Value.StringValue", i))}
			}
		}
		for _, s := range f.subs {
			if s.topic != topic || s.protocol != "sqs" {
				continue
			}
			if _, ok := f.policies[sinkQueueNameOf(s.endpoint)]; !ok {
				continue // the engine withholds for a queue whose policy does not allow SNS
			}
			if fp := s.attrs["FilterPolicy"]; fp != "" {
				var pol map[string][]string
				json.Unmarshal([]byte(fp), &pol)
				ok := true
				for k, vals := range pol {
					got, has := attrs[k]
					match := false
					for _, v := range vals {
						if has && got["Value"] == v {
							match = true
						}
					}
					ok = ok && match
				}
				if !ok {
					continue
				}
			}
			msg := p.Get("Message")
			if f.hugeBody > 0 {
				msg = strings.Repeat("x", f.hugeBody)
			}
			env := map[string]interface{}{"Type": "Notification", "MessageId": id, "TopicArn": topic, "Message": msg, "Timestamp": time.Now().UTC().Format(time.RFC3339Nano),
				"UnsubscribeURL": "https://sns.us-east-1.amazonaws.com/?Action=Unsubscribe&SubscriptionArn=" + s.arn}
			if sj := p.Get("Subject"); sj != "" {
				env["Subject"] = sj
			}
			if len(attrs) > 0 {
				env["MessageAttributes"] = attrs
			}
			eb, _ := json.Marshal(env)
			f.queues[sinkQueueNameOf(s.endpoint)] = append(f.queues[sinkQueueNameOf(s.endpoint)], string(eb))
		}
		io.WriteString(w, xmlOf("Publish", "<PublishResult><MessageId>"+id+"</MessageId></PublishResult>"))
	default:
		io.WriteString(w, xmlOf(action, ""))
	}
}

// ---- receivers: an HTTP endpoint that records what it is sent, and a minimal SMTP server

type hookReq struct {
	Method, URI, Host string
	Header            http.Header
	Body              string
	Remote            string
}

type hook struct {
	mu       sync.Mutex
	reqs     []hookReq
	statuses []int // consumed one per request, then default
	def      int
	extra    func(w http.ResponseWriter, r *http.Request) bool // return true if it answered
	ts       *httptest.Server
}

func newHook(t *testing.T) *hook {
	h := &hook{def: 200}
	h.ts = httptest.NewServer(http.HandlerFunc(h.serve))
	t.Cleanup(h.ts.Close)
	return h
}

func (h *hook) serve(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	h.mu.Lock()
	h.reqs = append(h.reqs, hookReq{r.Method, r.RequestURI, r.Host, r.Header.Clone(), string(b), r.RemoteAddr})
	status := h.def
	if len(h.statuses) > 0 {
		status, h.statuses = h.statuses[0], h.statuses[1:]
	}
	extra := h.extra
	h.mu.Unlock()
	if extra != nil && extra(w, r) {
		return
	}
	w.WriteHeader(status)
	io.WriteString(w, "ok")
}

func (h *hook) got() []hookReq {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]hookReq(nil), h.reqs...)
}

func (h *hook) port() int { return h.ts.Listener.Addr().(*net.TCPAddr).Port }

func sink_waitFor(t *testing.T, what string, d time.Duration, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

type smtpBox struct {
	mu         sync.Mutex
	transcript []string
	messages   []string
	ln         net.Listener
}

func newSMTP(t *testing.T) *smtpBox {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	b := &smtpBox{ln: ln}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go b.session(c)
		}
	}()
	return b
}

func (b *smtpBox) session(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	rd := bufio.NewReader(c)
	say := func(s string) { io.WriteString(c, s+"\r\n") }
	say("220 mailbox ready")
	for {
		line, err := rd.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		b.mu.Lock()
		b.transcript = append(b.transcript, line)
		b.mu.Unlock()
		switch up := strings.ToUpper(line); {
		case strings.HasPrefix(up, "EHLO"), strings.HasPrefix(up, "HELO"):
			say("250 hello")
		case strings.HasPrefix(up, "MAIL"), strings.HasPrefix(up, "RCPT"):
			say("250 ok")
		case up == "DATA":
			say("354 go")
			var data strings.Builder
			for {
				l, err := rd.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				data.WriteString(l)
			}
			b.mu.Lock()
			b.messages = append(b.messages, data.String())
			b.mu.Unlock()
			say("250 queued")
		case up == "QUIT":
			say("221 bye")
			return
		default:
			say("500 what")
		}
	}
}

func (b *smtpBox) msgs() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.messages...)
}

func (b *smtpBox) lines() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.transcript...)
}

func (b *smtpBox) addr() string { return b.ln.Addr().String() }

// ---- the rig: a front with the sink on, in front of the fake engine, with loopback standing in for the run's private network

type sinkRig struct {
	t      *testing.T
	srv    *Server
	ts     *httptest.Server
	aws    *fakeAWS
	hook   *hook // the sandbox app (route keys localhost, web, 127.0.0.1)
	sink   *hook // the HTTP sink (everything else)
	mail   *smtpBox
	cfg    *Config
	lookup int32
}

const rigToken = "rig-control-token-CANARY-0123456789"

func newSinkRig(t *testing.T, mutate func(*Config, *SinkConfig)) *sinkRig {
	t.Helper()
	r := &sinkRig{t: t, aws: newFakeAWS(t), hook: newHook(t), sink: newHook(t), mail: newSMTP(t)}
	sc := &SinkConfig{
		Routes: map[string]net.IP{"localhost": net.ParseIP("127.0.0.1"), "127.0.0.1": net.ParseIP("127.0.0.1"), "web": net.ParseIP("127.0.0.1")},
		SinkIP: net.ParseIP("127.0.0.1"), SinkHTTPPort: r.sink.port(), SinkHTTPSPort: r.sink.port(), SMTP: r.mail.addr(), RetryBase: 5 * time.Millisecond, AttemptTimeout: 2 * time.Second, privateCheck: loopbackOrPrivate,
	}
	cfg := &Config{Host: "10.9.9.9", Port: 4566, BaseURL: "http://aws:4566", Hostname: "aws", Token: rigToken, Region: "us-east-1", Disabled: map[string]bool{},
		WorkDir: t.TempDir(), LedgerMax: 500, Planned: map[string]bool{"sns": true, "sqs": true, "cloudformation": true}, PlannedKeys: []string{"sns", "sqs", "cloudformation"}, SNS: sc}
	if mutate != nil {
		mutate(cfg, sc)
	}
	r.cfg = cfg
	r.srv = newServer(cfg, r.aws.engine())
	r.ts = httptest.NewServer(r.srv)
	t.Cleanup(func() { r.ts.Close(); r.srv.sink.reset() })
	return r
}

var snsAuth = map[string]string{"Authorization": "AWS4-HMAC-SHA256 Credential=K/20260101/us-east-1/sns/aws4_request, SignedHeaders=host, Signature=00",
	"Content-Type": "application/x-www-form-urlencoded"}

// do makes one request to the front.
func (r *sinkRig) do(method, path string, headers map[string]string, body string) (int, http.Header, string) {
	r.t.Helper()
	req, _ := http.NewRequest(method, r.ts.URL+path, strings.NewReader(body))
	for k, v := range headers {
		if strings.EqualFold(k, "Host") {
			req.Host = v
			continue
		}
		req.Header.Set(k, v)
	}
	resp, err := noRedirect.Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, string(b)
}

// sns calls an SNS action.
func (r *sinkRig) sns(action string, kv ...string) (int, string) {
	r.t.Helper()
	v := url.Values{"Action": {action}, "Version": {"2010-03-31"}}
	for i := 0; i+1 < len(kv); i += 2 {
		v.Set(kv[i], kv[i+1])
	}
	code, _, body := r.do("POST", "/", snsAuth, v.Encode())
	return code, body
}

// snsAs calls an SNS action as the given identity in the given region (a key of "" is the default test key).
func (r *sinkRig) snsAs(region, key, token, action string, kv ...string) (int, string) {
	r.t.Helper()
	v := url.Values{"Action": {action}, "Version": {"2010-03-31"}}
	for i := 0; i+1 < len(kv); i += 2 {
		v.Set(kv[i], kv[i+1])
	}
	if key == "" {
		key = "K"
	}
	h := map[string]string{"Authorization": "AWS4-HMAC-SHA256 Credential=" + key + "/20260101/" + region + "/sns/aws4_request, SignedHeaders=host, Signature=00",
		"Content-Type": "application/x-www-form-urlencoded"}
	if token != "" {
		h["X-Amz-Security-Token"] = token
	}
	code, _, body := r.do("POST", "/", h, v.Encode())
	return code, body
}

// sqsRaw posts an SQS JSON call with the given body and headers.
func (r *sinkRig) sqsRaw(op string, body []byte, extra map[string]string) (int, string) {
	r.t.Helper()
	h := map[string]string{"X-Amz-Target": "AmazonSQS." + op, "Content-Type": "application/x-amz-json-1.0",
		"Authorization": "AWS4-HMAC-SHA256 Credential=K/20260101/us-east-1/sqs/aws4_request, SignedHeaders=host, Signature=00"}
	for k, v := range extra {
		h[k] = v
	}
	req, _ := http.NewRequest("POST", r.ts.URL+"/", bytes.NewReader(body))
	for k, v := range h {
		req.Header.Set(k, v)
	}
	resp, err := noRedirect.Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func sink_gz(b []byte) []byte {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	w.Write(b)
	w.Close()
	return buf.Bytes()
}

func sink_awsChunked(b []byte) []byte {
	return []byte(fmt.Sprintf("%x;chunk-signature=00\r\n%s\r\n0;chunk-signature=00\r\n\r\n", len(b), b))
}

func (r *sinkRig) topic(name string) string {
	r.t.Helper()
	_, body := r.sns("CreateTopic", "Name", name)
	m := regexp.MustCompile(`<TopicArn>([^<]+)</TopicArn>`).FindStringSubmatch(body)
	if m == nil {
		r.t.Fatalf("CreateTopic: %s", body)
	}
	return m[1]
}

func (r *sinkRig) subscribe(topic, protocol, endpoint string, attrs ...string) (int, string) {
	kv := []string{"TopicArn", topic, "Protocol", protocol, "Endpoint", endpoint}
	for i := 0; i+1 < len(attrs); i += 2 {
		n := i/2 + 1
		kv = append(kv, fmt.Sprintf("Attributes.entry.%d.key", n), attrs[i], fmt.Sprintf("Attributes.entry.%d.value", n), attrs[i+1])
	}
	return r.sns("Subscribe", kv...)
}

func (r *sinkRig) publish(topic, message string, kv ...string) {
	r.t.Helper()
	args := append([]string{"TopicArn", topic, "Message", message}, kv...)
	if code, body := r.sns("Publish", args...); code != 200 {
		r.t.Fatalf("Publish: %d %s", code, body)
	}
}

func (r *sinkRig) control(path string) (int, string) {
	code, _, body := r.do("GET", path, tok2(), "")
	return code, body
}

func tok2() map[string]string { return map[string]string{controlHeader: rigToken} }

// subs returns the sink's subscriptions (the control read).
func (r *sinkRig) subRows() []map[string]interface{} {
	r.t.Helper()
	_, body := r.control("/_rovara/sns/subscriptions")
	var doc struct{ Subscriptions []map[string]interface{} }
	json.Unmarshal([]byte(body), &doc)
	return doc.Subscriptions
}

func (r *sinkRig) onlySub() *snsSub {
	r.t.Helper()
	r.srv.sink.mu.Lock()
	defer r.srv.sink.mu.Unlock()
	if len(r.srv.sink.subs) != 1 {
		r.t.Fatalf("expected one subscription, have %d", len(r.srv.sink.subs))
	}
	for _, s := range r.srv.sink.subs {
		return s
	}
	return nil
}

func (r *sinkRig) attempts(arn string) []snsAttempt {
	r.t.Helper()
	_, body := r.control("/_rovara/sns/deliveries?subscription=" + url.QueryEscape(arn))
	var doc struct{ Deliveries []snsAttempt }
	json.Unmarshal([]byte(body), &doc)
	return doc.Deliveries
}

// confirm reads the SubscriptionConfirmation the app was sent and follows its SubscribeURL through the front.
func (r *sinkRig) confirm(h *hook) {
	r.t.Helper()
	sink_waitFor(r.t, "the confirmation", 3*time.Second, func() bool { return len(h.got()) > 0 })
	var doc map[string]string
	json.Unmarshal([]byte(h.got()[0].Body), &doc)
	if doc["Type"] != "SubscriptionConfirmation" {
		r.t.Fatalf("first message: %v", doc)
	}
	u, err := url.Parse(doc["SubscribeURL"])
	if err != nil {
		r.t.Fatal(err)
	}
	code, _, body := r.do("GET", u.RequestURI(), nil, "")
	if code != 200 || !strings.Contains(body, "<SubscriptionArn>") {
		r.t.Fatalf("SubscribeURL: %d %s", code, body)
	}
}

// newTestServer serves the front over HTTP for a test.
func newTestServer(t *testing.T, srv *Server) *httptest.Server {
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	return ts
}

// do2 is do with the answer's status dropped (a body only).
func (r *sinkRig) do2(method, path string, headers map[string]string, body string) (int, string) {
	code, _, b := r.do(method, path, headers, body)
	return code, b
}

// loopbackOrPrivate is the dial wall's judge in the tests, which can only listen on loopback.
func loopbackOrPrivate(ip net.IP) bool { return ip.IsLoopback() || isPrivateIPv4(ip) }
