package main

import (
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// S3 virtual-host style: <bucket>.<alias> or <bucket>.s3.<region>.amazonaws.com in the Host header. The front turns it
// into a path-style request before it asks the engine (so it never depends on how the engine reads a Host), and the
// control guard checks the path that results (FORK-CTRL-2).

var (
	regionPattern = `[a-z]{2}(?:-[a-z]+)+-\d{1,2}`
	// a complete S3 qualifier at the end of the prefix: s3, s3.<region>, s3-<region>, s3.dualstack.<region>
	s3QualifierTail = regexp.MustCompile(`\.s3(?:[.-](?:dualstack\.)?` + regionPattern + `)?$`)
	bucketNameRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
)

// validBucketName: 3 to 63 characters of [a-z0-9.-], starting and ending with a letter or digit. A host label that is not
// one (a leading underscore would turn "/ledger" into "/_rovara/ledger") never becomes a path.
func validBucketName(b string) bool {
	return bucketNameRe.MatchString(strings.ToLower(b))
}

func stripPort(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return strings.Trim(host, "[]")
}

// effectiveHost: the first X-Forwarded-Host value when there is one (as the fork's filter), else the Host.
func effectiveHost(r *http.Request) string {
	if xf := r.Header.Get("X-Forwarded-Host"); strings.TrimSpace(xf) != "" {
		if first := strings.TrimSpace(strings.Split(xf, ",")[0]); first != "" {
			return first
		}
	}
	return r.Host
}

// extractBucket reads a bucket from a virtual-host Host: <bucket>[.s3[.region]].<alias>, <bucket>.localhost, or an AWS
// S3 endpoint host. Dots in the bucket survive. "" means path style.
func extractBucket(host, alias string) string {
	h := strings.ToLower(stripPort(host))
	if !strings.Contains(h, ".") || net.ParseIP(h) != nil {
		return ""
	}
	prefixOf := func(suffix string) string {
		if suffix == "" || len(h) <= len(suffix)+1 || !strings.HasSuffix(h, "."+suffix) {
			return ""
		}
		return h[:len(h)-len(suffix)-1]
	}
	best := ""
	for _, suffix := range []string{alias, "localhost"} {
		if p := prefixOf(suffix); p != "" && (best == "" || len(p) < len(best)) {
			best = p
		}
	}
	if best != "" {
		return bucketOfPrefix(best, false)
	}
	for _, suffix := range []string{"amazonaws.com", "amazonaws.com.cn"} {
		if p := prefixOf(suffix); p != "" {
			return bucketOfPrefix(p, true)
		}
	}
	return ""
}

// bucketOfPrefix removes a trailing S3 qualifier. A prefix that IS a qualifier (s3, s3.us-east-1) is the bucketless
// service endpoint.
func bucketOfPrefix(prefix string, requireQualifier bool) string {
	if prefix == "s3" || regexp.MustCompile(`^s3[.-](?:dualstack\.)?`+regionPattern+`$`).MatchString(prefix) {
		return ""
	}
	if loc := s3QualifierTail.FindStringIndex(prefix); loc != nil {
		return prefix[:loc[0]]
	}
	if requireQualifier {
		return ""
	}
	return prefix
}

// vhostBucket returns the bucket of a virtual-host style S3 request, or "" for any other request.
func vhostBucket(r *http.Request, q url.Values, alias string) string {
	auth := r.Header.Get("Authorization")
	hasCredential := strings.Contains(auth, "Credential=")
	signedForS3 := hasCredential && strings.Contains(auth, "/s3/aws4_request")
	if hasCredential && !signedForS3 {
		return ""
	}
	if strings.Contains(q.Get("X-Amz-Credential"), "/s3/aws4_request") {
		signedForS3 = true
	}
	ct := strings.ToLower(r.Header.Get("Content-Type"))
	if !signedForS3 && (strings.HasPrefix(ct, "application/x-www-form-urlencoded") || strings.HasPrefix(ct, "application/x-amz-json-")) {
		return ""
	}
	if r.Header.Get("X-Amz-Target") != "" || strings.HasPrefix(r.URL.Path, "/v20180820/") {
		return ""
	}
	b := extractBucket(effectiveHost(r), alias)
	if b == "" || !validBucketName(b) {
		return ""
	}
	return b
}
