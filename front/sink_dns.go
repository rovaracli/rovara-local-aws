package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// DNS pattern rules and the DNS control socket (lane DS2). The run's resolver is the sealed DNS helper (a Cloud-side program, the existing
// setup-dns-watch-helper extended); the front is its client. This file is the LA half:
//
//  1. THE RULES. A rule set is the table the resolver answers from: `pattern -> target`. It is the REFERENCE for the worker's resolver, which
//     must give the same answers for the vectors in testdata/dns-rules-vectors.json (the front's own test runs them).
//       pattern  an exact name (`sns.us-east-1.amazonaws.com`) or `*.suffix`, which matches every name with at least one more label under
//                suffix (`a.b.suffix`, not `suffix`). Lower case; trailing dot and case are ignored when a name is looked up.
//       target   `front-tls` (the front's TLS listener), `sink` (the HTTP sink), `helper:<alias>` (the run's helper with that alias) or
//                `refuse` (no such name).
//       order    an exact rule beats a wildcard; among wildcards the longer suffix wins; two rules never tie (a repeated pattern is refused).
//     The static table the plan sends is awsStaticRules: every AWS name goes to the front's TLS listener, everything else to the sink.
//  2. THE REGISTRY. The front never edits the table by itself. It asks the resolver, over a unix socket, to add an exact name for a run
//     helper (a database's AWS-style name, DS5), and it asks only for what is allowed: a name at or under one of the CA's permitted names (so a
//     TLS certificate can exist for it), at or under an AWS suffix, never a wildcard, never an address, pointing only at a helper alias the
//     plan lists, at most dnsMaxNames names. The resolver MUST check the same things again (it must not trust the caller).
//
// THE CONTROL SOCKET PROTOCOL (what the worker's resolver implements): a unix stream socket in the resolver's own directory (never mounted
// into a sandbox). One request per line, one answer per line, UTF-8 JSON, at most 4096 bytes a line, then the connection is closed by the
// caller. Version 1:
//
//	{"v":1,"op":"register","name":"orders.cluster-abc.us-east-1.rds.amazonaws.com","target":"helper:postgres"}   -> {"ok":true}
//	{"v":1,"op":"unregister","name":"orders.cluster-abc.us-east-1.rds.amazonaws.com"}                           -> {"ok":true}
//	{"v":1,"op":"list"}                                                                                          -> {"ok":true,"names":[{"name":"...","target":"helper:postgres"}]}
//
// A refusal is {"ok":false,"error":"<code>"} with one of: bad_request, bad_name, name_not_permitted, bad_target, name_taken (the name is bound
// to another target: a registration never silently overrides), too_many_names, not_found (unregister of an unknown name is ok:true instead,
// so a reset can always clean up). register of a name already bound to the same target is ok:true.

// awsNameSuffixes are the only public suffixes the run's names may be under: the names AWS owns (the same list as the run CA's
// RUN_CA_AWS_SUFFIXES). A deny list of other top-level domains cannot work; this allow list does.
var awsNameSuffixes = []string{"amazonaws.com", "amazonaws.com.cn", "on.aws", "api.aws"}

const dnsMaxNames = 64
const dnsMaxLine = 4096

var dnsLabelRe = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// dnsNameProblem: what is wrong with `name` as a plain, lower-case DNS name (no wildcard, no trailing dot, not an address); "" when fine.
func dnsNameProblem(name string) string {
	if name == "" || len(name) > 253 {
		return "a name of 1 to 253 characters"
	}
	if name != strings.ToLower(name) {
		return "a lower-case name"
	}
	for _, label := range strings.Split(name, ".") {
		if !dnsLabelRe.MatchString(label) {
			return "plain labels of letters, digits and hyphens"
		}
	}
	if net.ParseIP(name) != nil || regexp.MustCompile(`^[0-9.]+$`).MatchString(name) {
		return "a name, not an address"
	}
	return ""
}

// isAWSName: `name` is at or under one of awsNameSuffixes.
func isAWSName(name string) bool {
	for _, s := range awsNameSuffixes {
		if name == s || strings.HasSuffix(name, "."+s) {
			return true
		}
	}
	return false
}

// nameUnder: `name` is `rule` or lies under it (the X.509 dNSName name-constraint rule).
func nameUnder(name, rule string) bool { return name == rule || strings.HasSuffix(name, "."+rule) }

// canonicalDNSName lower-cases a looked-up name and drops one trailing dot.
func canonicalDNSName(name string) string {
	return strings.TrimSuffix(strings.ToLower(name), ".")
}

// ---- rules

// dnsTarget is where a name resolves to.
type dnsTarget struct {
	Kind  string // front-tls, sink, helper, refuse
	Alias string // for helper
}

func (t dnsTarget) String() string {
	if t.Kind == "helper" {
		return "helper:" + t.Alias
	}
	return t.Kind
}

var dnsAliasRe = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$`)

func parseDNSTarget(s string) (dnsTarget, error) {
	switch s {
	case "front-tls", "sink", "refuse":
		return dnsTarget{Kind: s}, nil
	}
	if alias, ok := strings.CutPrefix(s, "helper:"); ok && dnsAliasRe.MatchString(alias) {
		return dnsTarget{Kind: "helper", Alias: alias}, nil
	}
	return dnsTarget{}, errors.New("a target is front-tls, sink, refuse or helper:<alias>")
}

// dnsPatternProblem: what is wrong with a rule's pattern. A wildcard is `*.` plus a name with at least two labels (so `*.com` and `*.aws` are
// refused), and every pattern is a plain name.
func dnsPatternProblem(pattern string) string {
	base := strings.TrimPrefix(pattern, "*.")
	if p := dnsNameProblem(base); p != "" {
		return p
	}
	if base != pattern && strings.Count(base, ".") < 1 {
		return "a wildcard needs at least two labels after it"
	}
	return ""
}

type dnsRule struct {
	pattern string
	target  dnsTarget
}

// dnsRuleSet is the table. It is not safe for concurrent writes; the resolver builds it once and reads it.
type dnsRuleSet struct {
	exact    map[string]dnsTarget
	wildcard []dnsRule // sorted: longest suffix first
	// Default is what an unmatched name resolves to (the sink, in a sealed run). The zero value refuses.
	Default dnsTarget
}

func newDNSRuleSet(def dnsTarget) *dnsRuleSet {
	return &dnsRuleSet{exact: map[string]dnsTarget{}, Default: def}
}

// Add appends one rule. A bad pattern or target, or a pattern already present, is an error.
func (rs *dnsRuleSet) Add(pattern, target string) error {
	if p := dnsPatternProblem(pattern); p != "" {
		return fmt.Errorf("bad pattern: %s", p)
	}
	t, err := parseDNSTarget(target)
	if err != nil {
		return err
	}
	if strings.HasPrefix(pattern, "*.") {
		for _, r := range rs.wildcard {
			if r.pattern == pattern {
				return errors.New("the pattern is already in the table")
			}
		}
		rs.wildcard = append(rs.wildcard, dnsRule{pattern, t})
		sort.SliceStable(rs.wildcard, func(i, j int) bool { return len(rs.wildcard[i].pattern) > len(rs.wildcard[j].pattern) })
		return nil
	}
	if _, dup := rs.exact[pattern]; dup {
		return errors.New("the pattern is already in the table")
	}
	rs.exact[pattern] = t
	return nil
}

// Match answers a lookup. ok is false only when nothing matched and there is no default (the caller answers NXDOMAIN).
func (rs *dnsRuleSet) Match(name string) (dnsTarget, bool) {
	name = canonicalDNSName(name)
	if dnsNameProblem(name) != "" {
		return dnsTarget{Kind: "refuse"}, false // not a name the table can speak for: an address, an empty or an oddly formed name
	}
	if t, ok := rs.exact[name]; ok {
		return t, true
	}
	for _, r := range rs.wildcard {
		suffix := r.pattern[2:]
		if strings.HasSuffix(name, "."+suffix) {
			return r.target, true
		}
	}
	if rs.Default.Kind != "" {
		return rs.Default, true
	}
	return dnsTarget{Kind: "refuse"}, false
}

// awsStaticRules is the table the plan hands the resolver at start: every AWS name to the front's TLS listener, everything else to the sink.
func awsStaticRules() *dnsRuleSet {
	rs := newDNSRuleSet(dnsTarget{Kind: "sink"})
	for _, s := range awsNameSuffixes {
		rs.Add("*."+s, "front-tls")
	}
	return rs
}

// ---- the registry (the front's side of the control socket)

// DNSConfig is the registry's configuration (ROVARA_AWS_DNS_CONTROL_SOCKET, ROVARA_AWS_DNS_PERMITTED, ROVARA_AWS_DNS_HELPERS).
type DNSConfig struct {
	Socket    string
	Permitted []string // the CA's permitted names: a registered name is at or under one of these
	Helpers   map[string]bool
}

const (
	envDNSSocket    = "ROVARA_AWS_DNS_CONTROL_SOCKET"
	envDNSPermitted = "ROVARA_AWS_DNS_PERMITTED"
	envDNSHelpers   = "ROVARA_AWS_DNS_HELPERS"
)

func parseDNSConfig(s settings) (*DNSConfig, error) {
	sock := strings.TrimSpace(s(envDNSSocket))
	if sock == "" {
		return nil, nil
	}
	if !strings.HasPrefix(sock, "/") || len(sock) > 104 || strings.ContainsAny(sock, "\x00\n") || strings.Contains(sock, "..") {
		return nil, fmt.Errorf("%s must be an absolute path of at most 104 characters", envDNSSocket)
	}
	c := &DNSConfig{Socket: sock, Helpers: map[string]bool{}}
	for _, n := range strings.Split(s(envDNSPermitted), ",") {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		if p := dnsNameProblem(n); p != "" || !isAWSName(n) {
			return nil, fmt.Errorf("%s: %q is not an AWS name (amazonaws.com and the like)", envDNSPermitted, n)
		}
		c.Permitted = append(c.Permitted, n)
	}
	if len(c.Permitted) == 0 || len(c.Permitted) > dnsMaxNames {
		return nil, fmt.Errorf("%s must list 1 to %d names", envDNSPermitted, dnsMaxNames)
	}
	for _, a := range strings.Split(s(envDNSHelpers), ",") {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		if !dnsAliasRe.MatchString(a) {
			return nil, fmt.Errorf("%s: %q is not a helper alias", envDNSHelpers, a)
		}
		c.Helpers[a] = true
	}
	if len(c.Helpers) == 0 {
		return nil, fmt.Errorf("%s must list the helper aliases a name may point at", envDNSHelpers)
	}
	return c, nil
}

// dnsRegistry registers and unregisters names with the resolver.
type dnsRegistry struct {
	cfg *DNSConfig
	net *sinkNet
	mu  sync.Mutex
	// names the front has registered, with their target alias: the front's own record, so a second registration is judged before it is sent
	names map[string]string
}

func newDNSRegistry(cfg *DNSConfig, n *sinkNet) *dnsRegistry {
	return &dnsRegistry{cfg: cfg, net: n, names: map[string]string{}}
}

// check: whether the front may ask for `name` -> helper:`alias` at all.
func (d *dnsRegistry) check(name, alias string) error {
	if p := dnsNameProblem(name); p != "" {
		return errors.New("bad_name")
	}
	if !isAWSName(name) || name == "" || isBareSuffix(name) {
		return errors.New("name_not_permitted")
	}
	ok := false
	for _, rule := range d.cfg.Permitted {
		if nameUnder(name, rule) {
			ok = true
		}
	}
	if !ok {
		return errors.New("name_not_permitted")
	}
	if !d.cfg.Helpers[alias] {
		return errors.New("bad_target")
	}
	return nil
}

func isBareSuffix(name string) bool {
	for _, s := range awsNameSuffixes {
		if name == s {
			return true
		}
	}
	return false
}

// Register adds one exact name for a run helper.
func (d *dnsRegistry) Register(ctx context.Context, name, alias string) error {
	if err := d.check(name, alias); err != nil {
		return err
	}
	d.mu.Lock()
	if have, ok := d.names[name]; ok && have != alias {
		d.mu.Unlock()
		return errors.New("name_taken")
	}
	if _, ok := d.names[name]; !ok && len(d.names) >= dnsMaxNames {
		d.mu.Unlock()
		return errors.New("too_many_names")
	}
	d.mu.Unlock()
	if _, err := d.call(ctx, map[string]interface{}{"v": 1, "op": "register", "name": name, "target": "helper:" + alias}); err != nil {
		return err
	}
	d.mu.Lock()
	d.names[name] = alias
	d.mu.Unlock()
	return nil
}

// Unregister removes a name the front registered; a name it did not register is not asked for.
func (d *dnsRegistry) Unregister(ctx context.Context, name string) error {
	d.mu.Lock()
	_, ok := d.names[name]
	d.mu.Unlock()
	if !ok {
		return nil
	}
	if _, err := d.call(ctx, map[string]interface{}{"v": 1, "op": "unregister", "name": name}); err != nil {
		return err
	}
	d.mu.Lock()
	delete(d.names, name)
	d.mu.Unlock()
	return nil
}

// UnregisterAll is the reset's clean-up: every name this front registered. It returns the first error and keeps going.
func (d *dnsRegistry) UnregisterAll(ctx context.Context) error {
	d.mu.Lock()
	names := make([]string, 0, len(d.names))
	for n := range d.names {
		names = append(names, n)
	}
	d.mu.Unlock()
	sort.Strings(names)
	var first error
	for _, n := range names {
		if err := d.Unregister(ctx, n); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// Registered lists the names the front has registered (a copy).
func (d *dnsRegistry) Registered() map[string]string {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make(map[string]string, len(d.names))
	for k, v := range d.names {
		out[k] = v
	}
	return out
}

type dnsReply struct {
	OK    bool   `json:"ok"`
	Error string `json:"error"`
}

// call makes one request on a fresh connection and reads one answer line.
func (d *dnsRegistry) call(ctx context.Context, req map[string]interface{}) (*dnsReply, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	conn, err := d.net.dialUnix(ctx, d.cfg.Socket)
	if err != nil {
		return nil, errors.New("the DNS helper's control socket is not reachable")
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	line, _ := json.Marshal(req)
	if len(line) >= dnsMaxLine {
		return nil, errors.New("bad_request")
	}
	if _, err := conn.Write(append(line, '\n')); err != nil {
		return nil, errors.New("the DNS helper's control socket did not take the request")
	}
	r := bufio.NewReaderSize(io.LimitReader(conn, dnsMaxLine+1), dnsMaxLine+1)
	answer, err := r.ReadBytes('\n')
	if err != nil || len(answer) > dnsMaxLine {
		return nil, errors.New("the DNS helper's control socket gave no answer")
	}
	var rep dnsReply
	if json.Unmarshal(answer, &rep) != nil {
		return nil, errors.New("the DNS helper's control socket gave an unreadable answer")
	}
	if !rep.OK {
		code := rep.Error
		if !regexp.MustCompile(`^[a-z_]{1,32}$`).MatchString(code) {
			code = "refused"
		}
		return &rep, errors.New(code)
	}
	return &rep, nil
}
