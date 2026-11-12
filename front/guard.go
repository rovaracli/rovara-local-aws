package main

import (
	"crypto/subtle"
	"net/http"
	"regexp"
	"strings"
)

// The control guard: a port of the fork's RovaraControlFilter. Every /_rovara/* path except GET /_rovara/health is a
// control path. It answers 403 unless the run's token is presented in X-Rovara-Control-Token, or the development switch
// (exactly "1") is on and no token is set.

const controlHeader = "X-Rovara-Control-Token"
const controlPrefix = "/_rovara"
const functionCodePrefix = "/_rovara/lambda/function-code/"

var snsCertificate = regexp.MustCompile(`^/_rovara/sns/SimpleNotificationService-[0-9A-Za-z]+\.pem$`)

// normalizePath collapses duplicate slashes and resolves dot segments, always with a leading slash (the fork's rule).
func normalizePath(path string) string {
	var out []string
	for _, seg := range strings.Split(path, "/") {
		switch seg {
		case "", ".":
		case "..":
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
		default:
			out = append(out, seg)
		}
	}
	trail := ""
	if strings.HasSuffix(path, "/") && len(out) > 0 {
		trail = "/"
	}
	return "/" + strings.Join(out, "/") + trail
}

// isControlPath: whether a NORMALIZED path is under the control prefix. The match is case-insensitive on purpose: the
// front dispatches on the exact spelling, but a path that merely looks like a control path is never forwarded to the
// engine and never answered without the token.
func isControlPath(p string) bool {
	return len(p) >= len(controlPrefix) && strings.EqualFold(p[:len(controlPrefix)], controlPrefix)
}

// unguarded reports whether a normalized path is NOT a control path (or is one of the three exemptions).
func unguarded(method, p string) bool {
	if !isControlPath(p) {
		return true
	}
	if p == "/_rovara/health" {
		return true
	}
	if strings.HasPrefix(p, functionCodePrefix) && len(p) > len(functionCodePrefix) && !strings.Contains(p[len(functionCodePrefix):], "/") {
		return true
	}
	return method == http.MethodGet && snsCertificate.MatchString(p)
}

// Guard decides whether a request may reach a control path.
type Guard struct {
	token   string
	devOpen bool
}

func newGuard(token string, devOpen bool) *Guard { return &Guard{token: token, devOpen: devOpen} }

// refusal is the 403 a refused request gets, or nil when it may go on.
type refusal struct{ message string }

// check applies the rules to one path. The caller runs it on EVERY path the request has: the one as sent and the final
// one after any host-style rewriting (FORK-CTRL-2), and refuses if either says so.
func (g *Guard) check(method, rawPath string, presented string) *refusal {
	p := normalizePath(rawPath)
	if unguarded(method, p) {
		return nil
	}
	if g.token == "" {
		if g.devOpen {
			return nil
		}
		return &refusal{"control paths are closed: no control token is configured"}
	}
	if presented != "" && subtle.ConstantTimeCompare([]byte(g.token), []byte(presented)) == 1 {
		return nil
	}
	return &refusal{"control token required"}
}

// presentedToken joins repeated headers the way the fork's servlet layer does (comma), so two headers never match.
func presentedToken(h http.Header) string {
	return strings.Join(h.Values(controlHeader), ",")
}

// jsonError renders the guard's body: {"error":"..."} (messages here hold no quote or control character).
func jsonError(message string) []byte {
	return []byte(`{"error":"` + jsonEscape(message) + `"}`)
}
