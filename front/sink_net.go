package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Every connection the delivery sink makes is made in THIS file, through sinkNet. There are exactly these ways out, and no other:
//
//	dial      the TCP connections of HTTP(S) deliveries and of the SMTP hand-off. The address is never taken from the endpoint: it is chosen by the
//	          route (route.go) from a table the run's plan wrote, and checked again here (a private IPv4 address of the run's network, never the
//	          front's own, loopback or link-local). The front does NO name resolution for a delivery: a host name in an endpoint is only ever a
//	          key into the route table or a Host header, so DNS rebinding has nothing to rebind.
//	dialUnix  the DNS helper's control socket (sink_dns.go), one fixed path.
//
// scripts/image-check-engine.sh counts the dial lines of the front: this file has three, and no other sink file has any.

type dialKey struct{}

// dialTarget is what one delivery attempt may connect to. It travels in the request's context; a request without one cannot dial at all.
type dialTarget struct {
	addr string // ip:port, already chosen by the route
	self bool   // the front's own TLS listener (an AWS-named https endpoint), the only loopback address ever allowed
}

type sinkNet struct {
	client *http.Client
	// selfTLS is the front's own TLS listener address (ip:port), or "": the one address a delivery may reach that is not private
	selfTLS string
	// frontIP: the front's own bind address, never a delivery target (a delivery to the front itself would reach its control paths)
	frontIP net.IP
	// selfIP: the TLS listener's own address, which only a "self" target may name
	selfIP net.IP
	// local: the front's other interface addresses (localAddrs): never a delivery target either
	local []net.IP
	// private says whether an address is one the sink may dial at all (isPrivateIPv4)
	private func(net.IP) bool
	roots   *x509.CertPool
}

// newSinkNet builds the delivery client. roots is the run CA's ROOT (an empty pool when the run has no CA: no https delivery can then
// succeed, which is the honest answer). No redirect is followed, no proxy and no keep-alive is used, and a whole attempt (connect, request,
// the start of the answer) is bounded by the timeout.
func newSinkNet(roots *x509.CertPool, selfTLS string, frontIP net.IP, timeout time.Duration) *sinkNet {
	if roots == nil {
		roots = x509.NewCertPool()
	}
	n := &sinkNet{selfTLS: selfTLS, frontIP: frontIP, roots: roots, private: isPrivateIPv4}
	if h, _, err := net.SplitHostPort(selfTLS); err == nil {
		n.selfIP = net.ParseIP(h)
	}
	n.client = &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext:            n.dial,
			Proxy:                  nil,
			DisableKeepAlives:      true,
			DisableCompression:     true,
			TLSClientConfig:        &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout:    5 * time.Second,
			ResponseHeaderTimeout:  timeout,
			MaxResponseHeaderBytes: 16 << 10,
			ExpectContinueTimeout:  0,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return n
}

var errNoDialTarget = errors.New("the sink dials only the address a route chose")

// dial connects to the address the context's dialTarget names, whatever address the caller passed.
func (n *sinkNet) dial(ctx context.Context, network, _ string) (net.Conn, error) {
	t, ok := ctx.Value(dialKey{}).(dialTarget)
	if !ok || network != "tcp" && network != "tcp4" {
		return nil, errNoDialTarget
	}
	if err := n.checkTarget(t); err != nil {
		return nil, err
	}
	return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp4", t.addr)
}

// checkTarget is the last wall before a connection: it runs on every dial, whatever chose the address.
func (n *sinkNet) checkTarget(t dialTarget) error {
	host, port, err := net.SplitHostPort(t.addr)
	if err != nil {
		return errNoDialTarget
	}
	if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
		return errNoDialTarget
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.To4() == nil {
		return errNoDialTarget
	}
	if t.self {
		if n.selfTLS == "" || t.addr != n.selfTLS {
			return errNoDialTarget
		}
		return nil
	}
	if !n.private(ip) || (n.frontIP != nil && ip.Equal(n.frontIP)) || (n.selfIP != nil && ip.Equal(n.selfIP)) {
		return errNoDialTarget
	}
	for _, l := range n.local {
		if ip.Equal(l) {
			return errNoDialTarget
		}
	}
	return nil
}

// dialUnix connects to the DNS helper's control socket.
func (n *sinkNet) dialUnix(ctx context.Context, path string) (net.Conn, error) {
	if !strings.HasPrefix(path, "/") {
		return nil, errNoDialTarget
	}
	return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", path)
}

// withTarget returns a context that lets exactly one delivery attempt connect to t.
func withTarget(ctx context.Context, t dialTarget) context.Context {
	return context.WithValue(ctx, dialKey{}, t)
}
