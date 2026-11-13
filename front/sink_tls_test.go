package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

var mapEnv = func(m map[string]string) settings { return func(k string) string { return m[k] } }

func loadFor(t *testing.T, p *testPKI, pairs ...[2]string) (*leafSet, error) {
	t.Helper()
	return loadLeafSet(&TLSListenerConfig{Addr: "127.0.0.1:0", Root: p.rootFile(), Leaves: pairs}, time.Now())
}

// tlsFront starts the TLS listener of the rig's front with the given leaves and returns a client that trusts only the run CA.
func tlsFront(t *testing.T, r *sinkRig, p *testPKI, readHeader time.Duration, pairs ...[2]string) (addr string, client func(serverName string) *http.Client) {
	t.Helper()
	ls, err := loadFor(t, p, pairs...)
	if err != nil {
		t.Fatalf("loadLeafSet: %v", err)
	}
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ts := newTLSServer(r.srv, ls, readHeader)
	go ts.Serve(tls.NewListener(raw, ls.tlsConfig()))
	t.Cleanup(func() { ts.Close() })
	addr = raw.Addr().String()
	client = func(serverName string) *http.Client {
		return &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
			},
			TLSClientConfig: &tls.Config{RootCAs: p.pool(), ServerName: serverName},
		}}
	}
	return
}

func TestTLSListenerServesRunCALeavesAndTheAPI(t *testing.T) {
	p := newTestPKI(t, "amazonaws.com")
	c1, k1 := p.leaf("one", leafOpts{names: []string{"sns.us-east-1.amazonaws.com", "sqs.us-east-1.amazonaws.com"}})
	c2, k2 := p.leaf("two", leafOpts{names: []string{"*.execute-api.us-east-1.amazonaws.com"}})
	r := newSinkRig(t, nil)
	addr, client := tlsFront(t, r, p, 15*time.Second, [2]string{c1, k1}, [2]string{c2, k2})
	_ = addr
	post := func(host string) (int, string, error) {
		req, _ := http.NewRequest("POST", "https://"+host+"/", strings.NewReader(url.Values{"Action": {"CreateTopic"}, "Version": {"2010-03-31"}, "Name": {"viaTLS"}}.Encode()))
		for k, v := range snsAuth {
			req.Header.Set(k, v)
		}
		resp, err := client(strings.Split(host, ":")[0]).Do(req)
		if err != nil {
			return 0, "", err
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b), nil
	}
	code, body, err := post("sns.us-east-1.amazonaws.com")
	if err != nil || code != 200 || !strings.Contains(body, "viaTLS") {
		t.Fatalf("sns over TLS: %v %d %s", err, code, body)
	}
	if _, _, err := post("anything.execute-api.us-east-1.amazonaws.com"); err != nil {
		t.Errorf("the wildcard leaf: %v", err)
	}
	// a name no leaf covers fails the handshake: two labels under a one-label wildcard, a sibling service, the bare suffix, another suffix
	for _, name := range []string{"a.b.execute-api.us-east-1.amazonaws.com", "dynamodb.us-east-1.amazonaws.com", "amazonaws.com", "sns.us-east-1.amazonaws.com.evil.example", "execute-api.us-east-1.amazonaws.com"} {
		if _, _, err := post(name); err == nil {
			t.Errorf("a handshake for %s succeeded", name)
		}
	}
	// the tls listener negotiates HTTP/1.1 only
	conn, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: p.pool(), ServerName: "sns.us-east-1.amazonaws.com", NextProtos: []string{"h2", "http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := conn.ConnectionState().NegotiatedProtocol; got != "http/1.1" {
		t.Errorf("ALPN: %q", got)
	}
	conn.Close()
	// TLS 1.1 is refused
	if c, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: p.pool(), ServerName: "sns.us-east-1.amazonaws.com", MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11}); err == nil {
		c.Close()
		t.Error("TLS 1.1 was accepted")
	}
}

func TestTLSHostMustBeTheServerName(t *testing.T) {
	p := newTestPKI(t, "amazonaws.com")
	c1, k1 := p.leaf("one", leafOpts{names: []string{"sns.us-east-1.amazonaws.com", "sqs.us-east-1.amazonaws.com"}})
	r := newSinkRig(t, nil)
	_, client := tlsFront(t, r, p, 15*time.Second, [2]string{c1, k1})
	try := func(serverName string, headers map[string]string, host string) int {
		req, _ := http.NewRequest("GET", "https://"+serverName+"/_rovara/health", nil)
		if host != "" {
			req.Host = host
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := client(serverName).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if got := try("sns.us-east-1.amazonaws.com", nil, ""); got == 421 {
		t.Errorf("the right host was refused")
	}
	// the host of the request is another name the connection was not made for, or the aws alias, or carries a forwarded host: 421
	for _, host := range []string{"sqs.us-east-1.amazonaws.com", "aws:4566", "127.0.0.1", "sns.us-east-1.amazonaws.com.evil.example", "evil.example"} {
		if got := try("sns.us-east-1.amazonaws.com", nil, host); got != 421 {
			t.Errorf("Host %s on a connection for sns: %d", host, got)
		}
	}
	if got := try("sns.us-east-1.amazonaws.com", map[string]string{"X-Forwarded-Host": "bucket.aws"}, ""); got != 421 {
		t.Errorf("X-Forwarded-Host: %d", got)
	}
	// the port and the case of the host are not part of the name
	if got := try("sns.us-east-1.amazonaws.com", nil, "SNS.US-EAST-1.AMAZONAWS.COM:443"); got == 421 {
		t.Errorf("the same name in another case was refused")
	}
}

func TestTLSSlowClientsAreCutOff(t *testing.T) {
	p := newTestPKI(t, "amazonaws.com")
	c1, k1 := p.leaf("one", leafOpts{names: []string{"sns.us-east-1.amazonaws.com"}})
	r := newSinkRig(t, nil)
	addr, _ := tlsFront(t, r, p, 300*time.Millisecond, [2]string{c1, k1})
	// 1. a connection that never says anything
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	start := time.Now()
	if _, err := c.Read(make([]byte, 1)); err == nil || time.Since(start) > 2*time.Second {
		t.Errorf("an idle connection was not cut off promptly: %v after %v", err, time.Since(start))
	}
	// 2. a completed handshake and a request that never finishes its headers
	tc, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: p.pool(), ServerName: "sns.us-east-1.amazonaws.com"})
	if err != nil {
		t.Fatal(err)
	}
	defer tc.Close()
	io.WriteString(tc, "GET /_rovara/health HTTP/1.1\r\nHost: sns.us-east-1.amazonaws.com\r\nX-Slow: ")
	tc.SetReadDeadline(time.Now().Add(3 * time.Second))
	start = time.Now()
	buf := make([]byte, 512)
	n, _ := tc.Read(buf)
	if time.Since(start) > 2*time.Second || (n > 0 && !strings.Contains(string(buf[:n]), "408")) {
		t.Errorf("a stalled header was not cut off promptly: %q after %v", buf[:n], time.Since(start))
	}
}

func TestLeafSetRefusesWhatTheRunCADidNotMake(t *testing.T) {
	p := newTestPKI(t, "amazonaws.com", "on.aws")
	other := newTestPKI(t, "amazonaws.com") // another run's CA
	good := func(name string, o leafOpts) [2]string { c, k := p.leaf(name, o); return [2]string{c, k} }
	ok := good("ok", leafOpts{names: []string{"sns.us-east-1.amazonaws.com"}})
	if _, err := loadFor(t, p, ok); err != nil {
		t.Fatalf("a good leaf: %v", err)
	}
	cases := map[string]func() ([2]string, *testPKI){
		"a name the CA is not constrained to (the intermediate's name constraint)": func() ([2]string, *testPKI) {
			return good("bad1", leafOpts{names: []string{"evil.example.com"}}), p
		},
		"a look-alike under another suffix": func() ([2]string, *testPKI) {
			return good("bad2", leafOpts{names: []string{"sns.us-east-1.amazonaws.com.evil.com"}}), p
		},
		"an IP address SAN": func() ([2]string, *testPKI) {
			return good("bad3", leafOpts{names: []string{"sns.us-east-1.amazonaws.com"}, ips: []net.IP{net.ParseIP("10.0.0.5")}}), p
		},
		"a wildcard over the whole suffix's parent": func() ([2]string, *testPKI) {
			return good("bad4", leafOpts{names: []string{"*.com"}}), p
		},
		"a leaf signed by the unconstrained root itself": func() ([2]string, *testPKI) {
			c, k := p.leaf("bad5", leafOpts{names: []string{"sns.us-east-1.amazonaws.com"}, signer: "root"})
			os.WriteFile(c, append(readF(t, c), p.interPEM...), 0o644) // pad the chain so its shape is right
			return [2]string{c, k}, p
		},
		"a CA certificate as a leaf": func() ([2]string, *testPKI) {
			return good("bad6", leafOpts{names: []string{"sns.us-east-1.amazonaws.com"}, ca: true}), p
		},
		"a leaf with no server-auth usage": func() ([2]string, *testPKI) {
			return good("bad7", leafOpts{names: []string{"sns.us-east-1.amazonaws.com"}, noEKU: true}), p
		},
		"an expired leaf": func() ([2]string, *testPKI) {
			return good("bad8", leafOpts{names: []string{"sns.us-east-1.amazonaws.com"}, expired: true}), p
		},
		"a leaf of another run's CA": func() ([2]string, *testPKI) {
			c, k := other.leaf("bad9", leafOpts{names: []string{"sns.us-east-1.amazonaws.com"}})
			return [2]string{c, k}, p
		},
		"a name that is not an AWS name, though the CA allows its alias": func() ([2]string, *testPKI) {
			q := newTestPKI(t, "amazonaws.com", "web")
			c, k := q.leaf("bad10", leafOpts{names: []string{"web"}})
			return [2]string{c, k}, q
		},
		"no names": func() ([2]string, *testPKI) { return good("bad11", leafOpts{}), p },
		"an upper-case name": func() ([2]string, *testPKI) {
			return good("bad12", leafOpts{names: []string{"SNS.us-east-1.amazonaws.com"}}), p
		},
		"a trailing dot": func() ([2]string, *testPKI) {
			return good("bad13", leafOpts{names: []string{"sns.us-east-1.amazonaws.com."}}), p
		},
		"a name that is the bare suffix under a wildcard": func() ([2]string, *testPKI) {
			return good("bad14", leafOpts{names: []string{"*.amazonaws.com.evil.com"}}), p
		},
		"a second name outside, next to a good one": func() ([2]string, *testPKI) {
			return good("bad15", leafOpts{names: []string{"sns.us-east-1.amazonaws.com", "evil.example.com"}}), p
		},
	}
	for name, mk := range cases {
		pair, pki := mk()
		if _, err := loadFor(t, pki, pair); err == nil {
			t.Errorf("accepted: %s", name)
		}
	}
	// a key that is not the leaf's, a chain with the key in it, files that are not there, a root that is not one CA certificate
	c1, _ := p.leaf("m1", leafOpts{names: []string{"sns.us-east-1.amazonaws.com"}})
	_, k2 := p.leaf("m2", leafOpts{names: []string{"sns.us-east-1.amazonaws.com"}})
	if _, err := loadFor(t, p, [2]string{c1, k2}); err == nil {
		t.Error("a key of another leaf was accepted")
	}
	if _, err := loadFor(t, p, [2]string{k2, k2}); err == nil {
		t.Error("a key as a chain was accepted")
	}
	if _, err := loadFor(t, p, [2]string{"/nonexistent/chain", "/nonexistent/key"}); err == nil {
		t.Error("missing files were accepted")
	}
	for name, rootFile := range map[string]string{"a leaf as the root": ok[0], "an empty file": writeF(t, p.dir, "empty.pem", ""), "a key as the root": k2} {
		if _, err := loadLeafSet(&TLSListenerConfig{Addr: "127.0.0.1:0", Root: rootFile, Leaves: [][2]string{ok}}, time.Now()); err == nil {
			t.Errorf("accepted %s", name)
		}
	}
	big := writeF(t, p.dir, "big.pem", strings.Repeat("A", tlsMaxFile+10))
	if _, err := loadLeafSet(&TLSListenerConfig{Addr: "127.0.0.1:0", Root: big, Leaves: [][2]string{ok}}, time.Now()); err == nil {
		t.Error("an oversized root file was read")
	}
	// the root in the chain file is tolerated as an extra (three certificates), four are not
	cr, kr := p.leaf("withroot", leafOpts{names: []string{"sns.us-east-1.amazonaws.com"}, chainRoot: true})
	if _, err := loadFor(t, p, [2]string{cr, kr}); err != nil {
		t.Errorf("leaf, intermediate, root: %v", err)
	}
	// no default certificate: a hello with no usable name finds none
	ls, _ := loadFor(t, p, ok)
	for _, name := range []string{"", "127.0.0.1", "[::1]", "sns.us-east-1.amazonaws.com\x00.evil.com", "sns.us-east-1.amazonaws.com ", "bad_name.amazonaws.com", "x.sns.us-east-1.amazonaws.com", "amazonaws.com", "evil.com", ".", "sns..us-east-1.amazonaws.com"} {
		if cert, err := ls.get(&tls.ClientHelloInfo{ServerName: name}); err == nil || cert != nil {
			t.Errorf("a certificate was chosen for %q", name)
		}
	}
	for _, name := range []string{"sns.us-east-1.amazonaws.com", "SNS.US-EAST-1.AMAZONAWS.COM", "sns.us-east-1.amazonaws.com."} {
		if cert, err := ls.get(&tls.ClientHelloInfo{ServerName: name}); err != nil || cert == nil {
			t.Errorf("no certificate for %q: %v", name, err)
		}
	}
}

func readF(t *testing.T, p string) []byte {
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func writeF(t *testing.T, dir, name, content string) string {
	p := filepath.Join(dir, name)
	os.WriteFile(p, []byte(content), 0o644)
	return p
}

func TestTLSConfigParsing(t *testing.T) {
	good := map[string]string{envTLSAddr: "172.30.5.2:443", envTLSRoot: "/etc/rovara/ca/run-ca.pem", envTLSLeaves: "/etc/rovara/tls/1-chain.pem:/etc/rovara/tls/1-key.pem,/etc/rovara/tls/2-chain.pem:/etc/rovara/tls/2-key.pem"}
	c, err := parseTLSConfig(mapEnv(good))
	if err != nil || c == nil || len(c.Leaves) != 2 || c.Leaves[1][1] != "/etc/rovara/tls/2-key.pem" {
		t.Fatalf("good config: %+v %v", c, err)
	}
	if c, err := parseTLSConfig(mapEnv(map[string]string{})); c != nil || err != nil {
		t.Errorf("no address means no listener: %+v %v", c, err)
	}
	bad := func(m map[string]string) map[string]string {
		out := map[string]string{}
		for k, v := range good {
			out[k] = v
		}
		for k, v := range m {
			out[k] = v
		}
		return out
	}
	for name, m := range map[string]map[string]string{
		"a wildcard bind":     bad(map[string]string{envTLSAddr: "0.0.0.0:443"}),
		"an ipv6 wildcard":    bad(map[string]string{envTLSAddr: "[::]:443"}),
		"a host name":         bad(map[string]string{envTLSAddr: "front.internal:443"}),
		"no port":             bad(map[string]string{envTLSAddr: "172.30.5.2"}),
		"a bad port":          bad(map[string]string{envTLSAddr: "172.30.5.2:70000"}),
		"a relative root":     bad(map[string]string{envTLSRoot: "run-ca.pem"}),
		"a dotdot root":       bad(map[string]string{envTLSRoot: "/etc/../run-ca.pem"}),
		"no root":             bad(map[string]string{envTLSRoot: ""}),
		"no leaves":           bad(map[string]string{envTLSLeaves: ""}),
		"an unpaired leaf":    bad(map[string]string{envTLSLeaves: "/a/chain.pem"}),
		"a relative leaf":     bad(map[string]string{envTLSLeaves: "chain.pem:/a/key.pem"}),
		"seventeen leaves":    bad(map[string]string{envTLSLeaves: strings.TrimSuffix(strings.Repeat("/a/c.pem:/a/k.pem,", 17), ",")}),
		"a newline in a path": bad(map[string]string{envTLSRoot: "/etc/ca\n.pem"}),
	} {
		if c, err := parseTLSConfig(mapEnv(m)); err == nil {
			t.Errorf("accepted %s: %+v", name, c)
		}
	}
}

// ---- the DNS rule table, the reference for the worker's resolver

func TestDNSRuleVectors(t *testing.T) {
	var doc struct {
		Default  string
		Rules    [][2]string
		Vectors  [][2]string
		BadRules [][3]string `json:"bad_rules"`
	}
	raw, err := os.ReadFile("testdata/dns-rules-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	def, _ := parseDNSTarget(doc.Default)
	rs := newDNSRuleSet(def)
	for _, r := range doc.Rules {
		if err := rs.Add(r[0], r[1]); err != nil {
			t.Fatalf("Add %s: %v", r[0], err)
		}
	}
	for _, v := range doc.Vectors {
		if got, _ := rs.Match(v[0]); got.String() != v[1] {
			t.Errorf("Match(%q) = %s, want %s", v[0], got, v[1])
		}
	}
	for _, b := range doc.BadRules {
		if err := rs.Add(b[0], b[1]); err == nil {
			t.Errorf("accepted %s", b[2])
		}
	}
	// the static table the plan sends is the first four rules of the file
	st := awsStaticRules()
	for _, name := range []string{"sns.us-east-1.amazonaws.com", "sqs.cn-north-1.amazonaws.com.cn", "x.lambda-url.us-east-1.on.aws", "x.api.aws"} {
		if got, _ := st.Match(name); got.String() != "front-tls" {
			t.Errorf("static table: %s -> %s", name, got)
		}
	}
	if got, _ := st.Match("hooks.example.com"); got.String() != "sink" {
		t.Errorf("static table default: %s", got)
	}
}

// ---- the DNS control socket

type fakeResolver struct {
	ln    net.Listener
	mu    chan struct{}
	lines []string
	reply func(line string) string
}

func newFakeResolver(t *testing.T, reply func(line string) string) (*fakeResolver, string) {
	t.Helper()
	dir, _ := os.MkdirTemp("/tmp", "dnsctl")
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "c.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Skipf("no unix sockets here: %v", err)
	}
	f := &fakeResolver{ln: ln, mu: make(chan struct{}, 1), reply: reply}
	f.mu <- struct{}{}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(3 * time.Second))
				buf := make([]byte, 8192)
				n, _ := c.Read(buf)
				line := strings.TrimRight(string(buf[:n]), "\n")
				<-f.mu
				f.lines = append(f.lines, line)
				f.mu <- struct{}{}
				io.WriteString(c, f.reply(line))
			}()
		}
	}()
	return f, path
}

func (f *fakeResolver) seen() []string {
	<-f.mu
	defer func() { f.mu <- struct{}{} }()
	return append([]string(nil), f.lines...)
}

func newRegistry(t *testing.T, sock string) *dnsRegistry {
	cfg := &DNSConfig{Socket: sock, Permitted: []string{"rds.amazonaws.com", "cache.amazonaws.com"}, Helpers: map[string]bool{"postgres": true, "valkey": true}}
	return newDNSRegistry(cfg, newSinkNet(nil, "", nil, time.Second))
}

func TestDNSRegistryRegistersOnlyWhatItMay(t *testing.T) {
	f, sock := newFakeResolver(t, func(string) string { return `{"ok":true}` + "\n" })
	d := newRegistry(t, sock)
	ctx := context.Background()
	if err := d.Register(ctx, "orders.cluster-abc.us-east-1.rds.amazonaws.com", "postgres"); err != nil {
		t.Fatalf("a good registration: %v", err)
	}
	if got := f.seen(); len(got) != 1 || got[0] != `{"name":"orders.cluster-abc.us-east-1.rds.amazonaws.com","op":"register","target":"helper:postgres","v":1}` {
		t.Fatalf("what the resolver was sent: %v", got)
	}
	if err := d.Register(ctx, "orders.cluster-abc.us-east-1.rds.amazonaws.com", "postgres"); err != nil {
		t.Errorf("the same registration again: %v", err)
	}
	for name, a := range map[string][2]string{
		"a name that is not an AWS name":    {"orders.example.com", "postgres"},
		"a name under no permitted name":    {"x.us-east-1.dynamodb.amazonaws.com", "postgres"},
		"a look-alike":                      {"x.rds.amazonaws.com.evil.com", "postgres"},
		"a wildcard":                        {"*.rds.amazonaws.com", "postgres"},
		"an address":                        {"10.0.0.1", "postgres"},
		"an upper-case name":                {"Orders.rds.amazonaws.com", "postgres"},
		"a trailing dot":                    {"orders.rds.amazonaws.com.", "postgres"},
		"a name with a newline":             {"orders.rds.amazonaws.com\n{\"op\":\"x\"}", "postgres"},
		"a name with a quote":               {`o"rders.rds.amazonaws.com`, "postgres"},
		"the permitted suffix itself, bare": {"amazonaws.com", "postgres"},
		"a helper the plan did not name":    {"x.rds.amazonaws.com", "evil"},
		"a helper alias that is an address": {"x.rds.amazonaws.com", "10.0.0.1"},
		"a helper alias with an injection":  {"x.rds.amazonaws.com", `postgres","op":"unregister`},
		"an empty name":                     {"", "postgres"},
		"a name over the length limit":      {strings.Repeat("a", 250) + ".rds.amazonaws.com", "postgres"},
	} {
		if err := d.Register(ctx, a[0], a[1]); err == nil {
			t.Errorf("accepted %s", name)
		}
	}
	if err := d.Register(ctx, "orders.cluster-abc.us-east-1.rds.amazonaws.com", "valkey"); err == nil || err.Error() != "name_taken" {
		t.Errorf("a name bound to another helper: %v", err)
	}
	if n := len(f.seen()); n != 2 { // the first and the repeat only: nothing refused ever reached the resolver
		t.Errorf("the resolver saw %d requests: %v", n, f.seen())
	}
	// the cap
	for i := 0; i < dnsMaxNames+5; i++ {
		d.Register(ctx, "n"+strings.Repeat("a", i%10)+string(rune('a'+i%26))+strings.Repeat("b", i/26)+".rds.amazonaws.com", "postgres")
	}
	if n := len(d.Registered()); n > dnsMaxNames {
		t.Errorf("registered %d names", n)
	}
	// reset's clean-up asks for the unregistration of exactly the names registered, and is repeatable
	if err := d.UnregisterAll(ctx); err != nil {
		t.Errorf("UnregisterAll: %v", err)
	}
	if len(d.Registered()) != 0 {
		t.Error("names remain")
	}
}

func TestDNSRegistryAgainstAHostileResolver(t *testing.T) {
	ctx := context.Background()
	for name, reply := range map[string]string{
		"a refusal":                  `{"ok":false,"error":"name_taken"}` + "\n",
		"garbage":                    "not json\n",
		"no newline, no end":         `{"ok":true}`,
		"a huge line":                strings.Repeat("x", 100000) + "\n",
		"a refusal with a long code": `{"ok":false,"error":"` + strings.Repeat("e", 500) + `"}` + "\n",
		"nothing at all":             "",
	} {
		_, sock := newFakeResolver(t, func(string) string { return reply })
		d := newRegistry(t, sock)
		err := d.Register(ctx, "a.rds.amazonaws.com", "postgres")
		if name == "no newline, no end" {
			// the connection closes after the write: an answer with no newline is not an answer
			if err == nil {
				t.Errorf("%s: accepted", name)
			}
			continue
		}
		if err == nil {
			t.Errorf("%s: accepted", name)
		} else if len(err.Error()) > 100 {
			t.Errorf("%s: the error carries the resolver's text: %q", name, err.Error()[:100])
		}
		if len(d.Registered()) != 0 {
			t.Errorf("%s: recorded a name the resolver did not take", name)
		}
	}
	// no socket at all, and a socket path that is not absolute
	d := newRegistry(t, "/nonexistent/dir/c.sock")
	if err := d.Register(ctx, "a.rds.amazonaws.com", "postgres"); err == nil {
		t.Error("a missing socket was accepted")
	}
	d = newRegistry(t, "relative.sock")
	if err := d.Register(ctx, "a.rds.amazonaws.com", "postgres"); err == nil {
		t.Error("a relative socket path was dialled")
	}
	// a resolver that never answers does not hold the caller for more than the timeout
	ln := t_unixListener(t)
	d = newRegistry(t, ln)
	start := time.Now()
	if err := d.Register(ctx, "a.rds.amazonaws.com", "postgres"); err == nil || time.Since(start) > 5*time.Second {
		t.Errorf("a silent resolver: %v after %v", err, time.Since(start))
	}
}

func t_unixListener(t *testing.T) string {
	dir, _ := os.MkdirTemp("/tmp", "dnsctl")
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "s.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Skipf("no unix sockets here: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { time.Sleep(10 * time.Second); c.Close() }()
		}
	}()
	return path
}

func TestDNSConfigParsing(t *testing.T) {
	good := map[string]string{envDNSSocket: "/run/dns/control.sock", envDNSPermitted: "rds.amazonaws.com, cache.amazonaws.com", envDNSHelpers: "postgres,valkey"}
	c, err := parseDNSConfig(mapEnv(good))
	if err != nil || c == nil || len(c.Permitted) != 2 || !c.Helpers["valkey"] {
		t.Fatalf("good: %+v %v", c, err)
	}
	if c, err := parseDNSConfig(mapEnv(nil)); c != nil || err != nil {
		t.Errorf("no socket, no registry: %v %v", c, err)
	}
	with := func(k, v string) map[string]string {
		m := map[string]string{}
		for a, b := range good {
			m[a] = b
		}
		m[k] = v
		return m
	}
	for name, m := range map[string]map[string]string{
		"a relative socket":            with(envDNSSocket, "control.sock"),
		"a dotdot socket":              with(envDNSSocket, "/run/../control.sock"),
		"a long socket path":           with(envDNSSocket, "/"+strings.Repeat("a", 120)),
		"a permitted name outside AWS": with(envDNSPermitted, "example.com"),
		"a wildcard permitted name":    with(envDNSPermitted, "*.amazonaws.com"),
		"no permitted names":           with(envDNSPermitted, ""),
		"no helpers":                   with(envDNSHelpers, ""),
		"a helper that is an address":  with(envDNSHelpers, "10.0.0.1"),
		"an upper-case helper":         with(envDNSHelpers, "Postgres"),
	} {
		if c, err := parseDNSConfig(mapEnv(m)); err == nil {
			t.Errorf("accepted %s: %+v", name, c)
		}
	}
}

func TestSinkConfigParsing(t *testing.T) {
	planned := func(c *Config) { c.Planned = map[string]bool{"sns": true}; c.Host = "172.30.5.2" }
	parse := func(m map[string]string) (*SinkConfig, error) {
		c := &Config{}
		planned(c)
		return parseSinkConfig(mapEnv(m), c)
	}
	sc, err := parse(map[string]string{envSNSRoutes: "localhost=172.30.5.3, 127.0.0.1=172.30.5.3,web=172.30.5.3", envSNSSinkAddr: "172.30.5.8", envSNSSMTP: "172.30.5.9:1025",
		envSNSAutoConfirm: "1", envSNSRetryDelayMs: "50", envSNSSinkPorts: "8080,8443"})
	if err != nil || sc == nil || len(sc.Routes) != 3 || !sc.Routes["web"].Equal(sc.Routes["localhost"]) || sc.SMTP != "172.30.5.9:1025" || !sc.AutoConfirm || sc.RetryBase != 50*time.Millisecond ||
		sc.SinkHTTPPort != 8080 || sc.SinkHTTPSPort != 8443 || sc.AttemptTimeout != 15*time.Second {
		t.Fatalf("good: %+v %v", sc, err)
	}
	if sc, err := parse(map[string]string{envSNSSink: "off"}); sc != nil || err != nil {
		t.Errorf("off: %v %v", sc, err)
	}
	c := &Config{Host: "172.30.5.2"}
	if sc, err := parseSinkConfig(mapEnv(nil), c); sc != nil || err != nil {
		t.Errorf("legacy mode has no sink: %v %v", sc, err)
	}
	c = &Config{Host: "172.30.5.2", Planned: map[string]bool{"sqs": true}}
	if sc, err := parseSinkConfig(mapEnv(nil), c); sc != nil || err != nil {
		t.Errorf("a plan without sns has no sink: %v %v", sc, err)
	}
	for name, m := range map[string]map[string]string{
		"a route to the TLS listener":     {envSNSRoutes: "web=172.30.5.4", envTLSAddr: "172.30.5.4:443"},
		"the TLS listener as the sink":    {envSNSSinkAddr: "172.30.5.4", envTLSAddr: "172.30.5.4:443"},
		"a route to a public address":     {envSNSRoutes: "web=8.8.8.8"},
		"a route to loopback":             {envSNSRoutes: "web=127.0.0.1"},
		"a route to the metadata address": {envSNSRoutes: "web=169.254.169.254"},
		"a route to link-local":           {envSNSRoutes: "web=169.254.1.1"},
		"a route to the front itself":     {envSNSRoutes: "web=172.30.5.2"},
		"a route to an IPv6 address":      {envSNSRoutes: "web=fd00::1"},
		"a route to 0.0.0.0":              {envSNSRoutes: "web=0.0.0.0"},
		"a route to CGNAT":                {envSNSRoutes: "web=100.64.0.1"},
		"a route to a mapped address":     {envSNSRoutes: "web=::ffff:8.8.8.8"},
		"a route without an address":      {envSNSRoutes: "web"},
		"a wildcard route":                {envSNSRoutes: "*.example.com=172.30.5.3"},
		"an AWS name route":               {envSNSRoutes: "sns.us-east-1.amazonaws.com=172.30.5.3"},
		"a route with a port":             {envSNSRoutes: "web:80=172.30.5.3"},
		"a route named twice":             {envSNSRoutes: "web=172.30.5.3,WEB=172.30.5.4"},
		"a route with a path":             {envSNSRoutes: "web/x=172.30.5.3"},
		"a public sink":                   {envSNSSinkAddr: "1.1.1.1"},
		"the front as the sink":           {envSNSSinkAddr: "172.30.5.2"},
		"a bad sink port":                 {envSNSSinkPorts: "80"},
		"a zero sink port":                {envSNSSinkPorts: "0,443"},
		"a public mail catcher":           {envSNSSMTP: "8.8.8.8:25"},
		"a mail catcher with no port":     {envSNSSMTP: "172.30.5.9"},
		"the front as the mail catcher":   {envSNSSMTP: "172.30.5.2:25"},
		"a negative retry delay":          {envSNSRetryDelayMs: "-1"},
		"a huge retry delay":              {envSNSRetryDelayMs: "999999"},
	} {
		if sc, err := parse(m); err == nil {
			t.Errorf("accepted %s: %+v", name, sc)
		}
	}
	// a route table of more than 32 names is refused
	var many []string
	for i := 0; i < 40; i++ {
		many = append(many, "h"+strings.Repeat("a", i%5)+string(rune('a'+i%26))+strings.Repeat("b", i/26)+"=172.30.5.3")
	}
	if _, err := parse(map[string]string{envSNSRoutes: strings.Join(many, ",")}); err == nil {
		t.Error("forty routes were accepted")
	}
	// a name is resolved once and every answer must be private
	old := lookupIPs
	defer func() { lookupIPs = old }()
	lookupIPs = func(host string) ([]net.IP, error) {
		if host == "split.internal" {
			return []net.IP{net.ParseIP("172.30.5.8"), net.ParseIP("8.8.8.8")}, nil
		}
		return []net.IP{net.ParseIP("172.30.5.8")}, nil
	}
	if _, err := parse(map[string]string{envSNSSinkAddr: "split.internal"}); err == nil {
		t.Error("a name that also resolves to a public address was accepted")
	}
	if sc, err := parse(map[string]string{envSNSSinkAddr: "sinkhole"}); err != nil || !sc.SinkIP.Equal(net.ParseIP("172.30.5.8")) {
		t.Errorf("a name that resolves privately: %v %v", sc, err)
	}
}

func TestLoadConfigReadsTheSinkSettings(t *testing.T) {
	m := map[string]string{envToken: "tokentokentoken1", envHost: "172.30.5.2", envBaseURL: "http://aws:4566", envPresign: "presignpresign1234", envReceipt: "receiptreceipt1234",
		envPlanned: "sns,sqs", envSNSRoutes: "web=172.30.5.3", envTLSAddr: "172.30.5.2:443", envTLSRoot: "/ca/root.pem", envTLSLeaves: "/t/c.pem:/t/k.pem",
		envDNSSocket: "/run/dns.sock", envDNSPermitted: "rds.amazonaws.com", envDNSHelpers: "postgres"}
	c, err := loadConfig(mapEnv(m))
	if err != nil || c.SNS == nil || c.TLS == nil || c.DNS == nil {
		t.Fatalf("loadConfig: %+v %v", c, err)
	}
	m[envSNSRoutes] = "web=8.8.8.8"
	if _, err := loadConfig(mapEnv(m)); err == nil {
		t.Error("a public route stopped nothing")
	}
}

var _ = httptest.NewServer

// The SubscribeURL of a run with a TLS listener is the AWS-looking one, and following it over https confirms the subscription; so does the
// UnsubscribeURL. The messages carry the https base, and the TLS listener answers them like the plain port does.
func TestSubscribeURLAndSigningCertURLOverTheTLSListener(t *testing.T) {
	p := newTestPKI(t, "amazonaws.com")
	c1, k1 := p.leaf("one", leafOpts{names: []string{"sns.us-east-1.amazonaws.com"}})
	ls, err := loadFor(t, p, [2]string{c1, k1})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := net.Listen("tcp", "127.0.0.2:0") // another loopback address than the routes' (the listener's address is the front's own)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	r := newSinkRig(t, func(c *Config, s *SinkConfig) {
		c.RunCARoots, c.SelfTLSAddr = ls.root, raw.Addr().String()
		s.ServeCert = true
	})
	ts := newTLSServer(r.srv, ls, 5*time.Second)
	go ts.Serve(tls.NewListener(raw, ls.tlsConfig()))
	defer ts.Close()
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", raw.Addr().String())
		},
		TLSClientConfig: &tls.Config{RootCAs: p.pool(), ServerName: "sns.us-east-1.amazonaws.com"},
	}}
	topic := r.topic("t")
	r.subscribe(topic, "http", hookURL(r.hook, "web", "/h"))
	sink_waitFor(t, "the confirmation", 3*time.Second, func() bool { return len(r.hook.got()) == 1 })
	var doc map[string]string
	json.Unmarshal([]byte(r.hook.got()[0].Body), &doc)
	if !strings.HasPrefix(doc["SubscribeURL"], "https://sns.us-east-1.amazonaws.com/?Action=ConfirmSubscription&TopicArn=arn:aws:sns:us-east-1:000000000000:t&Token=") ||
		!regexp.MustCompile(`^https://sns\.us-east-1\.amazonaws\.com/SimpleNotificationService-[0-9a-f]{16}\.pem$`).MatchString(doc["SigningCertURL"]) {
		t.Fatalf("urls: %v", doc)
	}
	get := func(u string) (int, string) {
		resp, err := client.Get(u)
		if err != nil {
			t.Fatalf("GET %s: %v", u, err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	if code, body := get(doc["SubscribeURL"]); code != 200 || !strings.Contains(body, "<SubscriptionArn>arn:aws:sns:") {
		t.Fatalf("SubscribeURL over https: %d %s", code, body)
	}
	if code, body := get(doc["SigningCertURL"]); code != 200 || !strings.Contains(body, "BEGIN CERTIFICATE") {
		t.Errorf("SigningCertURL over https: %d", code)
	}
	r.publish(topic, "now delivered")
	sink_waitFor(t, "the notification", 3*time.Second, func() bool { return len(r.hook.got()) == 2 })
	var n map[string]interface{}
	json.Unmarshal([]byte(r.hook.got()[1].Body), &n)
	unsub := n["UnsubscribeURL"].(string)
	if !strings.HasPrefix(unsub, "https://sns.us-east-1.amazonaws.com/?Action=Unsubscribe&SubscriptionArn=arn:aws:sns:") {
		t.Fatalf("UnsubscribeURL: %s", unsub)
	}
	if code, _ := get(unsub); code != 200 {
		t.Errorf("UnsubscribeURL over https: %d", code)
	}
	sink_waitFor(t, "the subscription to end", 3*time.Second, func() bool { return len(r.subRows()) == 0 })
}
