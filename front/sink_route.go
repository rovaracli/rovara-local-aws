package main

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// Where an SNS delivery goes. The endpoint is hostile text: it is judged at Subscribe (a bad one is refused there, loudly) and again at every
// delivery, and in the end it decides nothing but a Host header and a key into the run's route table. The connection goes to an address the
// run's plan chose (sink_config.go), through sinkNet.
//
//	1. a host that is a ROUTE KEY (localhost, 127.0.0.1, a run alias: written exactly so) goes to the route's address, the endpoint's own port
//	   (the sandbox's app listens there, on 0.0.0.0);
//	2. a host at or under an AWS suffix goes to the front's own TLS listener (https only; the certificate must be one the run CA made);
//	3. any other host name goes to the HTTP sink, at the sink's own port for the scheme, with the endpoint's host as the Host header;
//	4. everything else is refused: an IP address that is not a route key (any spelling: decimal, octal, hex, short, IPv6, IPv4-mapped), a
//	   host with a trailing dot, an underscore, a zone id or any other oddity, user-info that is not plain, a fragment, a non-ASCII or control
//	   character, a scheme that is not the subscription's protocol, a port outside 1-65535.

type epKind int

const (
	epRoute epKind = iota // the sandbox or a run service, by route key
	epSink                // the HTTP sink
	epSelf                // the front's own TLS listener
)

type endpointTarget struct {
	Kind       epKind
	Scheme     string // http or https
	Host       string // lower case, as the Host header and the TLS server name
	Port       int
	RequestURI string // path and query as written ("/" when empty)
	User, Pass string
	HasUser    bool
	Dial       dialTarget // zero when there is nowhere to send it (no sink)
	Display    string     // what a summary may show: the user-info and the query values are masked
}

// snsEndpointMax is the longest endpoint AWS accepts.
const snsEndpointMax = 2048

var (
	numericHostRe = regexp.MustCompile(`(?i)^(?:0x[0-9a-f]*|[0-9]+)(?:\.(?:0x[0-9a-f]*|[0-9]+))*$`)
	emailRe       = regexp.MustCompile("^[A-Za-z0-9.!#$%&*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$")
)

type routeTable struct {
	cfg     *SinkConfig
	selfTLS string // the front's TLS listener ip:port, "" when there is none
}

var errEndpoint = errors.New("endpoint")

func epProblem(format string, a ...interface{}) error {
	return fmt.Errorf("%w: %s", errEndpoint, fmt.Sprintf(format, a...))
}

// classify judges an http or https endpoint. The error text is safe to show (it never carries the endpoint).
func (rt *routeTable) classify(protocol, endpoint string) (*endpointTarget, error) {
	if protocol != "http" && protocol != "https" {
		return nil, epProblem("not an http or https endpoint")
	}
	if len(endpoint) > snsEndpointMax {
		return nil, epProblem("longer than %d characters", snsEndpointMax)
	}
	for i := 0; i < len(endpoint); i++ {
		if c := endpoint[i]; c < 0x21 || c > 0x7e || c == '\\' {
			return nil, epProblem("a space, control, non-ASCII or backslash character")
		}
	}
	if len(endpoint) < len(protocol)+3 || !strings.EqualFold(endpoint[:len(protocol)+3], protocol+"://") {
		return nil, epProblem("the endpoint must begin with %s://", protocol)
	}
	if strings.Contains(endpoint, "#") {
		return nil, epProblem("a fragment")
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Opaque != "" || u.Host == "" || !strings.EqualFold(u.Scheme, protocol) {
		return nil, epProblem("not a valid URL")
	}
	authority := endpoint[len(protocol)+3:]
	if i := strings.IndexAny(authority, "/?"); i >= 0 {
		authority = authority[:i]
	}
	if strings.Count(authority, "@") > 1 {
		return nil, epProblem("more than one @ in the authority")
	}
	host := strings.ToLower(u.Hostname())
	if host == "" || len(host) > 253 || strings.Contains(host, "%") {
		return nil, epProblem("no usable host")
	}
	port := 80
	if protocol == "https" {
		port = 443
	}
	if ps := u.Port(); ps != "" {
		p, err := strconv.Atoi(ps)
		if err != nil || p < 1 || p > 65535 {
			return nil, epProblem("a port outside 1-65535")
		}
		port = p
	} else if strings.HasSuffix(authority, ":") {
		return nil, epProblem("an empty port")
	}
	t := &endpointTarget{Scheme: protocol, Host: host, Port: port, RequestURI: u.RequestURI()}
	if u.User != nil {
		t.HasUser = true
		t.User = u.User.Username()
		t.Pass, _ = u.User.Password()
		if strings.ContainsAny(t.User+t.Pass, "\r\n\x00") {
			return nil, epProblem("user-info that is not plain")
		}
	}
	t.Display = redactEndpoint(t)

	if ip, found := rt.cfg.Routes[host]; found {
		t.Kind = epRoute
		t.Dial = dialTarget{addr: net.JoinHostPort(ip.String(), strconv.Itoa(port))}
		return t, nil
	}
	if net.ParseIP(host) != nil || strings.Contains(host, ":") {
		return nil, epProblem("an IP address (only the route keys the run names may be addresses)")
	}
	if numericHostRe.MatchString(host) {
		return nil, epProblem("a numeric host in an unusual spelling")
	}
	if !hostnameRe.MatchString(host) {
		return nil, epProblem("a host name with characters a name does not have")
	}
	if isAWSName(host) {
		if protocol != "https" || rt.selfTLS == "" {
			return nil, epProblem("an AWS name is reached over https through the run's own front, and this run has none")
		}
		t.Kind = epSelf
		t.Dial = dialTarget{addr: rt.selfTLS, self: true}
		return t, nil
	}
	t.Kind = epSink
	if rt.cfg.SinkIP != nil {
		sp := rt.cfg.SinkHTTPPort
		if protocol == "https" {
			sp = rt.cfg.SinkHTTPSPort
		}
		t.Dial = dialTarget{addr: net.JoinHostPort(rt.cfg.SinkIP.String(), strconv.Itoa(sp))}
	}
	return t, nil
}

// redactEndpoint is what a summary or the control read shows of an endpoint: user-info becomes ***, query values become ***.
func redactEndpoint(t *endpointTarget) string {
	var b strings.Builder
	b.WriteString(t.Scheme + "://")
	if t.HasUser {
		b.WriteString("***@")
	}
	b.WriteString(t.Host)
	if (t.Scheme == "http" && t.Port != 80) || (t.Scheme == "https" && t.Port != 443) {
		b.WriteString(":" + strconv.Itoa(t.Port))
	}
	path, query, hasQ := strings.Cut(t.RequestURI, "?")
	b.WriteString(path)
	if hasQ {
		parts := strings.Split(query, "&")
		for i, p := range parts {
			k, _, _ := strings.Cut(p, "=")
			parts[i] = k + "=***"
		}
		b.WriteString("?" + strings.Join(parts, "&"))
	}
	return b.String()
}

// emailProblem: whether `address` is an address the sink will hand to the mail catcher (one plain mailbox, no header or SMTP injection).
func emailProblem(address string) string {
	if len(address) > 254 || !emailRe.MatchString(address) || strings.Contains(address, "..") {
		return "not a plain email address"
	}
	return ""
}
