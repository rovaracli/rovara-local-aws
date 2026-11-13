package main

import (
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// Environment variable names. They are the fork's, so the Cloud worker's env file needs no change.
const (
	envToken         = "ROVARA_AWS_CONTROL_TOKEN"
	envDevOpen       = "ROVARA_AWS_DEV_OPEN_CONTROL"
	envBaseURL       = "ROVARA_AWS_BASE_URL"
	envPresign       = "ROVARA_AWS_AUTH_PRESIGN_SECRET"
	envReceipt       = "ROVARA_AWS_SERVICES_SQS_RECEIPT_HANDLE_SECRET"
	envHost          = "QUARKUS_HTTP_HOST"
	envPort          = "QUARKUS_HTTP_PORT"
	envRegion        = "ROVARA_AWS_DEFAULT_REGION"
	envHostname      = "ROVARA_AWS_HOSTNAME"
	envEngineBin     = "ROVARA_AWS_ENGINE_BIN"
	envWorkDir       = "ROVARA_AWS_FRONT_WORKDIR"
	envLedgerMax     = "ROVARA_AWS_LEDGER_MAX_ENTRIES"
	envPlanned       = "ROVARA_AWS_PLANNED_SERVICES"
	envSMHelper      = "ROVARA_AWS_SAGEMAKER_HELPER"
	defaultBaseURL   = "http://localhost:4566"
	defaultSecret    = "local-emulator-secret"
	minSecretLength  = 16
	defaultPort      = 4566
	defaultRegion    = "us-east-1"
	defaultHost      = "127.0.0.1"
	defaultEngineBin = "/opt/aws-emulator/bin/aws-emulator"
)

// Config is everything the front reads from its environment, once, at start.
type Config struct {
	Host     string
	Port     int
	BaseURL  string // no trailing slash
	Hostname string // the name the run's code reaches the front at (S3 virtual-host style)
	Token    string
	DevOpen  bool
	Region   string
	Disabled map[string]bool // fork config key (sqs, cloudwatchlogs, ...) -> switched off (legacy mode only)
	// Planned is the run's plan (ROVARA_AWS_PLANNED_SERVICES): canonical table keys. nil means legacy mode: the 0.5.15 catalog of
	// 18 services and the ROVARA_AWS_SERVICES_<X>_ENABLED switches. The legacy mode is kept for one release.
	Planned     map[string]bool
	PlannedKeys []string
	// SageMakerHelpers are the model stand-ins (ROVARA_AWS_SAGEMAKER_HELPER, comma separated http addresses, for example
	// http://model-stand-in:8080) an endpoint in mode helper is forwarded to, at <address>/invocations; the first is the default.
	SageMakerHelpers []*url.URL
	// Runner is the function runner's settings; nil: the runner is off (ROVARA_AWS_RUNNER_SOCKET unset)
	Runner    *RunnerConfig
	EngineBin string
	WorkDir   string
	LedgerMax int
	// The delivery sink (sink_config.go, sink_tls.go, sink_dns.go): nil when the run has not set it up.
	SNS *SinkConfig
	TLS *TLSListenerConfig
	DNS *DNSConfig
	// Set by main from the checked leaf set, before the server is made: the run CA's root (the only trust the sink's https deliveries use)
	// and the address the TLS listener really listens on.
	RunCARoots  *x509.CertPool
	SelfTLSAddr string
}

// settings reads one variable by name; tests pass a map-backed one.
type settings func(name string) string

func isDevOpen(v string) bool { return v == "1" }

// contractApplies: a control token is set and the development switch is not exactly "1".
func contractApplies(s settings) bool {
	return s(envToken) != "" && !isDevOpen(s(envDevOpen))
}

// TODO(the release after the 0.5.15 rollout): set plannedRequired to true. It is false for exactly one release because workers roll out
// AFTER the image, so an old worker starts a new image with no plan. TestPlannedSettingIsOptionalForOneRelease pins the current behaviour;
// when this flips, that test flips with it.
//
// plannedRequired: whether a run (control token set) must name its services in ROVARA_AWS_PLANNED_SERVICES. It is false for one
// release: a run without the setting uses the legacy catalog and switches. Flip it to refuse such a run at start.
const plannedRequired = false

// contractProblems lists what is wrong with a run's settings, one message per setting. Values are never quoted.
// Empty when the contract does not apply or is met.
func contractProblems(s settings) []string {
	var out []string
	if !contractApplies(s) {
		return out
	}
	if strings.TrimSpace(s(envHost)) == "" {
		out = append(out, envHost+" must be set to the run's own address (the development default 127.0.0.1 is unreachable from outside)")
	}
	base := s(envBaseURL)
	switch {
	case strings.TrimSpace(base) == "" || base == defaultBaseURL:
		out = append(out, envBaseURL+" must be set to the URL the run reaches the emulator at (for example http://aws:4566), not the development default")
	case !validBaseURL(base):
		out = append(out, envBaseURL+" must be an http or https URL with a host")
	}
	if plannedRequired && strings.TrimSpace(s(envPlanned)) == "" {
		out = append(out, envPlanned+" must name the AWS services the run may use (table keys, comma separated)")
	}
	out = secretProblem(out, s(envPresign), envPresign)
	out = secretProblem(out, s(envReceipt), envReceipt)
	// the control token is a secret too, and never the same value as a signing secret: holding a presigned URL or a receipt
	// handle must not open the control API
	if len(s(envToken)) < minSecretLength {
		out = append(out, envToken+" must be a random per-run value of at least "+strconv.Itoa(minSecretLength)+" characters")
	}
	if t := s(envToken); t == s(envPresign) || t == s(envReceipt) {
		out = append(out, envToken+" must differ from "+envPresign+" and "+envReceipt)
	}
	return out
}

func secretProblem(out []string, value, name string) []string {
	if strings.TrimSpace(value) == "" || value == defaultSecret || len(value) < minSecretLength {
		out = append(out, name+" must be set to a random per-run value of at least "+strconv.Itoa(minSecretLength)+
			" characters, not the development default")
	}
	return out
}

func validBaseURL(v string) bool {
	u, err := url.Parse(v)
	if err != nil {
		return false
	}
	return (u.Scheme == "http" || u.Scheme == "https") && u.Hostname() != ""
}

// requireContract returns the fork's refusal sentence when the contract applies and is not met.
func requireContract(s settings) error {
	problems := contractProblems(s)
	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("Refusing to start: a control token is set, so this is a run, and a run must set its own"+
		" settings instead of the development defaults. %s.", strings.Join(problems, "; "))
}

var (
	ipv4Re     = regexp.MustCompile(`^\d{1,3}(\.\d{1,3}){3}$`)
	hostnameRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)
)

// checkBindHost refuses a malformed host and any wildcard, as the fork's NetworkExposureGuard does.
func checkBindHost(host string) error {
	h := strings.TrimSpace(host)
	if h == "" || len(h) > 253 {
		return fmt.Errorf("Refusing to listen on malformed host: %s", host)
	}
	literal := h
	if strings.HasPrefix(literal, "[") && strings.HasSuffix(literal, "]") {
		literal = literal[1 : len(literal)-1]
	}
	if ip := net.ParseIP(literal); ip != nil {
		if ip.IsUnspecified() {
			return fmt.Errorf("Refusing to listen on %s: the API port binds 127.0.0.1 or one specific address, never a wildcard."+
				" Set QUARKUS_HTTP_HOST to that address.", host)
		}
		return nil
	}
	if ipv4Re.MatchString(h) { // dotted quad that does not parse (999.1.1.1)
		return fmt.Errorf("Refusing to listen on malformed host: %s", host)
	}
	if h == "0" || h == "*" || !hostnameRe.MatchString(h) {
		return fmt.Errorf("Refusing to listen on malformed host: %s", host)
	}
	return nil
}

// loadConfig reads and checks the environment. The run contract and the bind rules are enforced here, before anything starts.
func loadConfig(s settings) (*Config, error) {
	if err := requireContract(s); err != nil {
		return nil, err
	}
	c := &Config{
		Host:      defaultHost,
		Port:      defaultPort,
		BaseURL:   defaultBaseURL,
		Token:     s(envToken),
		DevOpen:   isDevOpen(s(envDevOpen)),
		Region:    defaultRegion,
		EngineBin: defaultEngineBin,
		WorkDir:   "/tmp",
		LedgerMax: 5000,
		Disabled:  map[string]bool{},
	}
	if v := s(envHost); strings.TrimSpace(v) != "" {
		c.Host = strings.TrimSpace(v)
	}
	if err := checkBindHost(c.Host); err != nil {
		return nil, err
	}
	if v := strings.TrimSpace(s(envPort)); v != "" {
		p, err := strconv.Atoi(v)
		if err != nil || p < 1 || p > 65535 {
			return nil, fmt.Errorf("%s must be a port number", envPort)
		}
		c.Port = p
	}
	if v := strings.TrimSpace(s(envBaseURL)); v != "" {
		if !validBaseURL(v) {
			return nil, fmt.Errorf("%s must be an http or https URL with a host", envBaseURL)
		}
		c.BaseURL = strings.TrimRight(v, "/")
	}
	if v := strings.TrimSpace(s(envRegion)); v != "" {
		c.Region = v
	}
	if v := strings.TrimSpace(s(envHostname)); v != "" {
		c.Hostname = strings.ToLower(v)
	} else if u, err := url.Parse(c.BaseURL); err == nil {
		c.Hostname = strings.ToLower(u.Hostname())
	}
	if v := s(envEngineBin); v != "" {
		c.EngineBin = v
	}
	if v := s(envWorkDir); v != "" {
		c.WorkDir = v
	}
	if v := strings.TrimSpace(s(envLedgerMax)); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 {
			c.LedgerMax = n
		}
	}
	if v := strings.TrimSpace(s(envPlanned)); v != "" {
		planned, keys, err := parsePlanned(v)
		if err != nil {
			return nil, err
		}
		c.Planned, c.PlannedKeys = planned, keys
	}
	if v := strings.TrimSpace(s(envSMHelper)); v != "" {
		for _, raw := range strings.Split(v, ",") {
			u, err := url.Parse(strings.TrimSpace(raw))
			if err != nil || u.Scheme != "http" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
				(u.Path != "" && u.Path != "/") {
				return nil, fmt.Errorf("%s must be a comma separated list of http addresses with a host and no path, for example http://model-stand-in:8080", envSMHelper)
			}
			u.Path = ""
			if ip := net.ParseIP(u.Hostname()); ip != nil && smBadAddress(ip) {
				return nil, fmt.Errorf("%s names a loopback, link-local or unspecified address, which a model stand-in cannot be at", envSMHelper)
			}
			if ips, err := lookupIPs(u.Hostname()); err == nil {
				// resolved once, here; a stand-in that is not in DNS yet is resolved at its first call (sagemaker_runtime.go)
				for _, ip := range ips {
					if smBadAddress(ip) {
						return nil, fmt.Errorf("%s names a host that resolves to a loopback, link-local or unspecified address, which a model stand-in cannot be at", envSMHelper)
					}
				}
			}
			c.SageMakerHelpers = append(c.SageMakerHelpers, u)
		}
	}
	rc, err := loadRunnerConfig(s, c.WorkDir, c.Planned != nil)
	if err != nil {
		return nil, err
	}
	c.Runner = rc
	if c.SNS, err = parseSinkConfig(s, c); err != nil {
		return nil, err
	}
	if c.TLS, err = parseTLSConfig(s); err != nil {
		return nil, err
	}
	if c.DNS, err = parseDNSConfig(s); err != nil {
		return nil, err
	}
	for _, key := range serviceConfigKeys {
		if !serviceEnabledSetting(s("ROVARA_AWS_SERVICES_" + strings.ToUpper(key) + "_ENABLED")) {
			c.Disabled[key] = true
		}
	}
	if c.Planned != nil {
		c.Disabled = map[string]bool{} // the plan governs; the legacy switches are ignored
	}
	return c, nil
}

// serviceEnabledSetting reads a boolean the way the fork's config (SmallRye) does: unset or empty keeps the default (on);
// "true", "1", "yes", "y" and "on" (any case) are on; anything else is off.
func serviceEnabledSetting(v string) bool {
	if v == "" {
		return true
	}
	switch strings.ToLower(v) {
	case "true", "1", "yes", "y", "on":
		return true
	}
	return false
}
