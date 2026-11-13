package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// The delivery sink's settings (lanes DS2 and DS3; design beyond-emulator-delivery-sink-db-helpers.md). Everything here comes from the run's
// plan through the Cloud worker's environment, never from repository text, and each value is checked once, at start. A bad value stops the
// front ("Refusing to start"): a sink that silently ran without its walls would be worse than none.
//
//	ROVARA_AWS_SNS_SINK              "off" turns the SNS delivery sink off. Default: on when the plan names sns (planned mode only).
//	ROVARA_AWS_SNS_ROUTES            host=ip,host=ip ... the endpoint hosts that go to the run's own sandbox or service, for example
//	                                 localhost=172.30.5.3,127.0.0.1=172.30.5.3,web=172.30.5.3. Exact names only (no wildcard). Each ip must be a
//	                                 private IPv4 address of the run's services network. The port is the endpoint's own.
//	ROVARA_AWS_SNS_SINK_ADDR         the ip of the HTTP sink (the record-only fake server). Any endpoint host that is not a route goes here, to
//	                                 ROVARA_AWS_SNS_SINK_PORTS (http,https; default 80,443) whatever port the endpoint names. Unset: such a
//	                                 delivery is recorded as undeliverable ("no sink"), never sent anywhere.
//	ROVARA_AWS_SNS_SMTP              host:port of the mail catcher (Mailpit). Unset: email is kept in the front's own capture only.
//	ROVARA_AWS_SNS_AUTO_CONFIRM      "1": a new http, https or email subscription is confirmed at once (the project setting sns.autoConfirm).
//	ROVARA_AWS_SNS_SERVE_SIGNING_CERT "1": serve the run's signing certificate at the SigningCertURL (opt-in, owner question 3). Default: the
//	                                 URL is AWS-shaped and not served, so a verifier that fetches it fails honestly.
//	ROVARA_AWS_SNS_RETRY_DELAY_MS    the base of the (compressed) retry delay, default 200; the nth retry waits n times this.
const (
	envSNSSink          = "ROVARA_AWS_SNS_SINK"
	envSNSRoutes        = "ROVARA_AWS_SNS_ROUTES"
	envSNSSinkAddr      = "ROVARA_AWS_SNS_SINK_ADDR"
	envSNSSinkPorts     = "ROVARA_AWS_SNS_SINK_PORTS"
	envSNSSMTP          = "ROVARA_AWS_SNS_SMTP"
	envSNSAutoConfirm   = "ROVARA_AWS_SNS_AUTO_CONFIRM"
	envSNSServeCert     = "ROVARA_AWS_SNS_SERVE_SIGNING_CERT"
	envSNSRetryDelayMs  = "ROVARA_AWS_SNS_RETRY_DELAY_MS"
	snsMaxRoutes        = 32
	snsDefaultRetryBase = 200 * time.Millisecond
)

// SinkConfig is the SNS delivery sink's configuration.
type SinkConfig struct {
	Routes        map[string]net.IP // endpoint host (lower case) -> the address its deliveries are dialled at
	SinkIP        net.IP            // nil: no HTTP sink
	SinkHTTPPort  int
	SinkHTTPSPort int
	SMTP          string // ip:port, resolved once; "" when there is no mail catcher
	AutoConfirm   bool
	ServeCert     bool
	RetryBase     time.Duration
	// AttemptTimeout bounds one delivery attempt end to end (connect, request, the start of the answer). 15 s, as AWS.
	AttemptTimeout time.Duration
	// TapVerifyEvery: how often each tap's subscription is checked to still be on its topic (default 10 s; tests shorten it).
	TapVerifyEvery time.Duration
	// privateCheck replaces isPrivateIPv4 as the dial wall's judge of an address. Only the tests set it (they can listen on loopback only); a
	// setting read from the environment never does.
	privateCheck func(net.IP) bool
}

// isPrivateIPv4: RFC 1918 (10/8, 172.16/12, 192.168/16). Loopback, link-local (the metadata address 169.254.169.254), unspecified, multicast,
// CGNAT, public and IPv6 addresses are not.
func isPrivateIPv4(ip net.IP) bool {
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	switch {
	case v4[0] == 10:
		return true
	case v4[0] == 172 && v4[1] >= 16 && v4[1] <= 31:
		return true
	case v4[0] == 192 && v4[1] == 168:
		return true
	}
	return false
}

// localAddrs lists the front's own non-loopback interface addresses: none of them may be a delivery target, whatever the front is bound to (a
// name, or the wildcard a container's default may be). A variable so the tests can name addresses of their own.
var localAddrs = func() []net.IP {
	var out []net.IP
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && !ipn.IP.IsLoopback() && !ipn.IP.IsUnspecified() {
			out = append(out, ipn.IP)
		}
	}
	return out
}

// parseSinkAddr reads a literal address or, for a name, resolves it once and keeps the first private IPv4 answer; every answer must be
// private (a name that also resolves somewhere else is refused, so a late change of DNS cannot move the sink).
func parseSinkAddr(name, value string) (net.IP, error) {
	value = strings.TrimSpace(value)
	var ips []net.IP
	if ip := net.ParseIP(value); ip != nil {
		ips = []net.IP{ip}
	} else {
		if value == "" || !hostnameRe.MatchString(value) {
			return nil, fmt.Errorf("%s must be an address or a host name", name)
		}
		var err error
		if ips, err = lookupIPs(value); err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("%s: the name does not resolve", name)
		}
	}
	var pick net.IP
	for _, ip := range ips {
		if !isPrivateIPv4(ip) {
			return nil, fmt.Errorf("%s must be a private IPv4 address of the run's network (never loopback, link-local, public or IPv6)", name)
		}
		if pick == nil {
			pick = ip.To4()
		}
	}
	return pick, nil
}

// parseSinkConfig reads the sink's settings. It returns nil (no sink) when the sink is off, or when the run is not planned or the plan does
// not name sns.
func parseSinkConfig(s settings, c *Config) (*SinkConfig, error) {
	if strings.EqualFold(strings.TrimSpace(s(envSNSSink)), "off") || c.Planned == nil || !c.Planned["sns"] {
		return nil, nil
	}
	sc := &SinkConfig{Routes: map[string]net.IP{}, SinkHTTPPort: 80, SinkHTTPSPort: 443, RetryBase: snsDefaultRetryBase, AttemptTimeout: snsDefaultAttemptTimeout}
	// every address the front has: the one it is bound to (an address, or a name resolved once), the TLS listener's, and its interfaces'
	frontIPs := localAddrs()
	if ip := net.ParseIP(trimBrackets(c.Host)); ip != nil {
		frontIPs = append(frontIPs, ip)
	} else if ips, err := lookupIPs(c.Host); err == nil {
		frontIPs = append(frontIPs, ips...)
	}
	if h, _, err := net.SplitHostPort(strings.TrimSpace(s(envTLSAddr))); err == nil {
		if ip := net.ParseIP(trimBrackets(h)); ip != nil {
			frontIPs = append(frontIPs, ip)
		}
	}
	refuseFront := func(name string, ip net.IP) error {
		for _, f := range frontIPs {
			if ip.Equal(f) {
				return fmt.Errorf("%s names an address of the front itself, which a delivery may never be sent to", name)
			}
		}
		return nil
	}
	if v := strings.TrimSpace(s(envSNSRoutes)); v != "" {
		for _, pair := range strings.Split(v, ",") {
			host, addr, ok := strings.Cut(strings.TrimSpace(pair), "=")
			host = strings.ToLower(strings.TrimSpace(host))
			if !ok || host == "" || len(host) > 253 || strings.ContainsAny(host, "*/@:[]\\ \t") || (!hostnameRe.MatchString(host)) {
				return nil, fmt.Errorf("%s must be a comma separated list of host=ip pairs", envSNSRoutes)
			}
			if isAWSName(host) {
				return nil, fmt.Errorf("%s may not route an AWS name (those go to the front's own TLS listener)", envSNSRoutes)
			}
			ip, err := parseSinkAddr(envSNSRoutes, addr)
			if err != nil {
				return nil, err
			}
			if err := refuseFront(envSNSRoutes, ip); err != nil {
				return nil, err
			}
			if _, dup := sc.Routes[host]; dup {
				return nil, fmt.Errorf("%s names %s twice", envSNSRoutes, host)
			}
			if len(sc.Routes) >= snsMaxRoutes {
				return nil, fmt.Errorf("%s has more than %d routes", envSNSRoutes, snsMaxRoutes)
			}
			sc.Routes[host] = ip
		}
	}
	if v := strings.TrimSpace(s(envSNSSinkAddr)); v != "" {
		ip, err := parseSinkAddr(envSNSSinkAddr, v)
		if err != nil {
			return nil, err
		}
		if err := refuseFront(envSNSSinkAddr, ip); err != nil {
			return nil, err
		}
		sc.SinkIP = ip
	}
	if v := strings.TrimSpace(s(envSNSSinkPorts)); v != "" {
		a, b, ok := strings.Cut(v, ",")
		hp, e1 := strconv.Atoi(strings.TrimSpace(a))
		sp, e2 := strconv.Atoi(strings.TrimSpace(b))
		if !ok || e1 != nil || e2 != nil || hp < 1 || hp > 65535 || sp < 1 || sp > 65535 {
			return nil, fmt.Errorf("%s must be two ports: http,https", envSNSSinkPorts)
		}
		sc.SinkHTTPPort, sc.SinkHTTPSPort = hp, sp
	}
	if v := strings.TrimSpace(s(envSNSSMTP)); v != "" {
		host, port, err := net.SplitHostPort(v)
		pn, perr := strconv.Atoi(port)
		if err != nil || perr != nil || pn < 1 || pn > 65535 {
			return nil, fmt.Errorf("%s must be host:port", envSNSSMTP)
		}
		ip, err := parseSinkAddr(envSNSSMTP, host)
		if err != nil {
			return nil, err
		}
		if err := refuseFront(envSNSSMTP, ip); err != nil {
			return nil, err
		}
		sc.SMTP = net.JoinHostPort(ip.String(), port)
	}
	sc.AutoConfirm = strings.TrimSpace(s(envSNSAutoConfirm)) == "1"
	sc.ServeCert = strings.TrimSpace(s(envSNSServeCert)) == "1"
	if v := strings.TrimSpace(s(envSNSRetryDelayMs)); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > 5000 {
			return nil, fmt.Errorf("%s must be a number of milliseconds from 0 to 5000", envSNSRetryDelayMs)
		}
		sc.RetryBase = time.Duration(n) * time.Millisecond
	}
	return sc, nil
}
