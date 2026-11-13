package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// The front's TLS listener (lane DS2). Run code that calls an AWS name over https (sns.us-east-1.amazonaws.com, an SDK that ignores
// AWS_ENDPOINT_URL, an SNS SubscribeURL) reaches it because the run's DNS sends every AWS name here (sink_dns.go awsStaticRules).
//
// The front invents NO trust. Its certificates are LEAVES the Cloud worker's per-run CA made (worker/src/run-ca.ts: a root the sandboxes
// trust, and one name-constrained intermediate that signs every leaf; design "Per-run test CA"), handed to the front as files:
//
//	ROVARA_AWS_TLS_ADDR     ip:port to listen on (a specific address, never a wildcard; 443 is the usual port)
//	ROVARA_AWS_TLS_ROOT     the run CA's ROOT certificate (PEM, one certificate)
//	ROVARA_AWS_TLS_LEAVES   chain.pem:key.pem pairs, comma separated (at most 16): each chain is the leaf then the intermediate (the root is
//	                        not sent), each key the leaf's PKCS#8 or EC key
//
// At start the front checks every leaf as a client would and refuses to start if one fails: the chain must verify to the ROOT for EVERY name
// the leaf carries (so the intermediate's name constraint is exercised), through a CONSTRAINED INTERMEDIATE (a leaf signed by the root itself
// is refused: the root is unconstrained), the leaf is not a CA, serves serverAuth, has DNS names only (no IP address) and every name is at or
// under an AWS suffix. There is no default certificate and no self-signed fallback: a client that names a host no leaf covers (or none at all)
// fails the handshake.

const (
	envTLSAddr   = "ROVARA_AWS_TLS_ADDR"
	envTLSRoot   = "ROVARA_AWS_TLS_ROOT"
	envTLSLeaves = "ROVARA_AWS_TLS_LEAVES"
	tlsMaxLeaves = 16
	tlsMaxFile   = 64 << 10
)

// TLSListenerConfig is the TLS listener's setting.
type TLSListenerConfig struct {
	Addr   string
	Root   string
	Leaves [][2]string // chain file, key file
}

func absFile(name, p string) error {
	if !filepath.IsAbs(p) || len(p) > 1024 || strings.ContainsAny(p, "\x00\n") || strings.Contains(p, "..") {
		return fmt.Errorf("%s must name absolute file paths", name)
	}
	return nil
}

func parseTLSConfig(s settings) (*TLSListenerConfig, error) {
	addr := strings.TrimSpace(s(envTLSAddr))
	if addr == "" {
		return nil, nil
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("%s must be ip:port", envTLSAddr)
	}
	if err := checkBindHost(host); err != nil {
		return nil, fmt.Errorf("%s: %v", envTLSAddr, err)
	}
	if net.ParseIP(trimBrackets(host)) == nil {
		return nil, fmt.Errorf("%s must name an address, not a host name", envTLSAddr)
	}
	if pn, err := strconv.Atoi(port); err != nil || pn < 1 || pn > 65535 {
		return nil, fmt.Errorf("%s must be ip:port", envTLSAddr)
	}
	c := &TLSListenerConfig{Addr: addr, Root: strings.TrimSpace(s(envTLSRoot))}
	if err := absFile(envTLSRoot, c.Root); err != nil {
		return nil, err
	}
	for _, pair := range strings.Split(s(envTLSLeaves), ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		chain, key, ok := strings.Cut(pair, ":")
		if !ok {
			return nil, fmt.Errorf("%s must be chain.pem:key.pem pairs", envTLSLeaves)
		}
		if err := absFile(envTLSLeaves, chain); err != nil {
			return nil, err
		}
		if err := absFile(envTLSLeaves, key); err != nil {
			return nil, err
		}
		c.Leaves = append(c.Leaves, [2]string{chain, key})
	}
	if len(c.Leaves) == 0 || len(c.Leaves) > tlsMaxLeaves {
		return nil, fmt.Errorf("%s must list 1 to %d leaves", envTLSLeaves, tlsMaxLeaves)
	}
	return c, nil
}

func readSmallFile(p string) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, errors.New("cannot read a TLS file")
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return nil, errors.New("a TLS file is not a regular file")
	}
	b, err := io.ReadAll(io.LimitReader(f, tlsMaxFile+1))
	if err != nil || len(b) > tlsMaxFile {
		return nil, errors.New("a TLS file is too large")
	}
	return b, nil
}

// pemCertificates parses every CERTIFICATE block; any other block (a key, a request) is an error.
func pemCertificates(data []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for {
		var blk *pem.Block
		blk, data = pem.Decode(data)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			return nil, errors.New("a certificate file holds something that is not a certificate")
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, errors.New("a certificate does not parse")
		}
		out = append(out, c)
	}
	if len(strings.TrimSpace(string(data))) != 0 {
		return nil, errors.New("a certificate file holds text that is not PEM")
	}
	return out, nil
}

// leafSet is the loaded, checked set of certificates the listener serves.
type leafSet struct {
	root  *x509.CertPool
	leafs []*servedLeaf
}

type servedLeaf struct {
	cert  tls.Certificate
	names []string
}

// loadLeafSet reads and checks the files. `now` is the clock the chains are judged at.
func loadLeafSet(cfg *TLSListenerConfig, now time.Time) (*leafSet, error) {
	rootPEM, err := readSmallFile(cfg.Root)
	if err != nil {
		return nil, fmt.Errorf("the run CA root: %v", err)
	}
	roots, err := pemCertificates(rootPEM)
	if err != nil || len(roots) != 1 || !roots[0].IsCA {
		return nil, errors.New("the run CA root must be exactly one CA certificate")
	}
	pool := x509.NewCertPool()
	pool.AddCert(roots[0])
	ls := &leafSet{root: pool}
	for _, pair := range cfg.Leaves {
		chainPEM, err := readSmallFile(pair[0])
		if err != nil {
			return nil, fmt.Errorf("a leaf's chain: %v", err)
		}
		keyPEM, err := readSmallFile(pair[1])
		if err != nil {
			return nil, fmt.Errorf("a leaf's key: %v", err)
		}
		chain, err := pemCertificates(chainPEM)
		if err != nil || len(chain) < 2 || len(chain) > 3 {
			return nil, errors.New("a leaf's chain must be the leaf then the intermediate")
		}
		names, err := checkLeaf(pool, chain, now)
		if err != nil {
			return nil, err
		}
		cert, err := tls.X509KeyPair(chainPEM, keyPEM)
		if err != nil {
			return nil, errors.New("a leaf's key does not belong to its certificate")
		}
		cert.Leaf = chain[0]
		ls.leafs = append(ls.leafs, &servedLeaf{cert: cert, names: names})
	}
	return ls, nil
}

// checkLeaf verifies the chain as a client would, for every name the leaf carries, and applies the front's own rules.
func checkLeaf(roots *x509.CertPool, chain []*x509.Certificate, now time.Time) ([]string, error) {
	leaf := chain[0]
	if leaf.IsCA || len(leaf.IPAddresses) > 0 || len(leaf.DNSNames) == 0 || len(leaf.DNSNames) > 16 || len(leaf.EmailAddresses) > 0 || len(leaf.URIs) > 0 {
		return nil, errors.New("a leaf must be a non-CA certificate with DNS names only")
	}
	serverAuth := false
	for _, e := range leaf.ExtKeyUsage {
		if e == x509.ExtKeyUsageServerAuth {
			serverAuth = true
		}
	}
	if !serverAuth {
		return nil, errors.New("a leaf must be for server authentication")
	}
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	var names []string
	for _, n := range leaf.DNSNames {
		base := strings.TrimPrefix(n, "*.")
		if dnsNameProblem(base) != "" || !isAWSName(base) || (base != n && strings.Count(base, ".") < 1) {
			return nil, errors.New("a leaf names something that is not an AWS name")
		}
		probe := n
		if base != n {
			probe = "probe." + base
		}
		chains, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, DNSName: probe, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
		if err != nil {
			return nil, errors.New("a leaf does not verify against the run CA for one of its names")
		}
		constrained := false
		for _, ch := range chains {
			// the chain is leaf, intermediate, root: the intermediate must carry a critical name constraint (the root's is none)
			if len(ch) == 3 && ch[1].PermittedDNSDomainsCritical && len(ch[1].PermittedDNSDomains) > 0 {
				constrained = true
			}
		}
		if !constrained {
			return nil, errors.New("a leaf must be signed by the run CA's name-constrained intermediate")
		}
		names = append(names, n)
	}
	return names, nil
}

// get chooses the certificate for a handshake by the client's server name; no name, an address, or a name no leaf covers is an error.
func (ls *leafSet) get(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	name := canonicalDNSName(hello.ServerName)
	if name == "" || dnsNameProblem(name) != "" {
		return nil, errors.New("no usable server name")
	}
	for _, l := range ls.leafs {
		for _, n := range l.names {
			if n == name {
				return &l.cert, nil
			}
			if strings.HasPrefix(n, "*.") {
				// one label, as X.509 reads a wildcard
				if rest, ok := strings.CutSuffix(name, n[1:]); ok && rest != "" && !strings.Contains(rest, ".") {
					return &l.cert, nil
				}
			}
		}
	}
	return nil, errors.New("no certificate for that name")
}

// serverNames lists every name the set serves (sorted by leaf), for the log line and the tests.
func (ls *leafSet) serverNames() []string {
	var out []string
	for _, l := range ls.leafs {
		out = append(out, l.names...)
	}
	return out
}

func (ls *leafSet) tlsConfig() *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: ls.get,
		NextProtos:     []string{"http/1.1"},
		ClientAuth:     tls.NoClientCert,
	}
}

// tlsHostGuard refuses a request whose Host is not the server name the handshake was for (421), so a client cannot use a certificate it
// holds for one name to talk about another, and an HTTP/1.1 request on a connection for a name no leaf covers never reaches the API.
func tlsHostGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || r.TLS.ServerName == "" || canonicalDNSName(stripPort(r.Host)) != canonicalDNSName(r.TLS.ServerName) ||
			strings.TrimSpace(r.Header.Get("X-Forwarded-Host")) != "" {
			writeBody(w, http.StatusMisdirectedRequest, "text/plain; charset=utf-8", []byte("misdirected request\n"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// newTLSServer is the http.Server of the TLS listener: the same handler as the plain port behind the host guard, HTTP/1.1 only.
func newTLSServer(h http.Handler, ls *leafSet, readHeader time.Duration) *http.Server {
	return &http.Server{
		Handler:           tlsHostGuard(h),
		TLSConfig:         ls.tlsConfig(),
		ReadHeaderTimeout: readHeader,
		ReadTimeout:       30 * time.Minute,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    1 << 20,
		TLSNextProto:      map[string]func(*http.Server, *tls.Conn, http.Handler){}, // no HTTP/2
		ErrorLog:          log.New(discardWriter{}, "", 0),
	}
}
