package main

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
)

// Rewriting of what the engine says about itself. The run's code must always see ROVARA_AWS_BASE_URL (http://aws:4566),
// never the engine's internal address and never an AWS host name. Where the engine puts such a name, found by running
// the whole compat suite and the matrix through a recording proxy:
//
//   - SQS QueueUrl / QueueUrls (CreateQueue, GetQueueUrl, ListQueues, ListDeadLetterSourceQueues, JSON and Query):
//     https://sqs.<region>.amazonaws.com/<account>/<name>
//   - S3 CompleteMultipartUpload <Location>: https://<bucket>.s3.<region>.amazonaws.com/<key>
//   - SNS envelopes the engine puts in an SQS message body: UnsubscribeURL (and SubscribeURL, SigningCertURL when present)
//     https://sns.<region>.amazonaws.com/?Action=Unsubscribe...
//   - the engine's own loopback address, in any header or small API body (it never appeared in the survey; this is the net
//     under it).
//
// Nothing is rewritten in an object's bytes or in a message body except the SNS envelope's URL fields. Names that are XML
// namespaces (xmlns="http://sqs.amazonaws.com/doc/...") are not touched.

type rewriter struct {
	base     string // ROVARA_AWS_BASE_URL without a trailing slash
	baseHost string // host[:port] of the base URL
}

func newRewriter(base string) *rewriter {
	host := strings.TrimPrefix(strings.TrimPrefix(base, "http://"), "https://")
	if i := strings.Index(host, "/"); i >= 0 {
		host = host[:i]
	}
	return &rewriter{base: base, baseHost: host}
}

var (
	awsDNS       = `(?:amazonaws\.com(?:\.cn)?|api\.aws)`
	sqsHostRe    = regexp.MustCompile(`^https?://(?:sqs\.[a-z0-9-]+\.` + awsDNS + `|queue\.amazonaws\.com)/`)
	sqsXMLRe     = regexp.MustCompile(`(<QueueUrl>)\s*https?://(?:sqs\.[a-z0-9-]+\.` + awsDNS + `|queue\.amazonaws\.com)/`)
	snsURLRe     = regexp.MustCompile(`("(?:UnsubscribeURL|SubscribeURL|SigningCertURL)"\s*:\s*")https?://sns\.[a-z0-9-]+\.` + awsDNS + `/`)
	s3LocVHostRe = regexp.MustCompile(`(<Location>)\s*https?://([^/<]+?)\.s3[.-][^/<]*` + awsDNS + `(/[^<]*)(</Location>)`)
	s3LocPathRe  = regexp.MustCompile(`(<Location>)\s*https?://s3[.-][^/<]*` + awsDNS + `/`)
	queueOps     = map[string]bool{"CreateQueue": true, "GetQueueUrl": true, "ListQueues": true, "ListDeadLetterSourceQueues": true}
	jsonishCType = regexp.MustCompile(`(?i)^(?:application/(?:x-amz-json-[0-9.]+|json)|application/xml|text/xml)`)
)

// internalVariants: every way the engine could write its own loopback address, longest first.
func internalVariants(port int) []string {
	p := strconv.Itoa(port)
	return []string{"https://127.0.0.1:" + p, "http://127.0.0.1:" + p, "https://localhost:" + p, "http://localhost:" + p,
		"https://[::1]:" + p, "http://[::1]:" + p}
}

// internalAddr replaces the engine's address in a string (a header value or a small body).
func (rw *rewriter) internalAddr(s string, port int) string {
	if !strings.Contains(s, ":"+strconv.Itoa(port)) {
		return s
	}
	for _, v := range internalVariants(port) {
		s = strings.ReplaceAll(s, v, rw.base)
	}
	for _, bare := range []string{"127.0.0.1:" + strconv.Itoa(port), "localhost:" + strconv.Itoa(port), "[::1]:" + strconv.Itoa(port)} {
		s = strings.ReplaceAll(s, bare, rw.baseHost)
	}
	return s
}

func (rw *rewriter) internalAddrBytes(b []byte, port int) []byte {
	if !bytes.Contains(b, []byte(":"+strconv.Itoa(port))) {
		return b
	}
	return []byte(rw.internalAddr(string(b), port))
}

// rewriteQueueURLString: an AWS-style queue URL becomes base/<account>/<name>.
func (rw *rewriter) rewriteQueueURLString(s string) string {
	if loc := sqsHostRe.FindStringIndex(s); loc != nil {
		return rw.base + "/" + s[loc[1]:]
	}
	return s
}

// queueURLsJSON rewrites the QueueUrl and QueueUrls values of an SQS JSON response and nothing else. A body that is
// not a JSON object is returned unchanged.
func (rw *rewriter) queueURLsJSON(body []byte) []byte {
	if !bytes.Contains(body, []byte("amazonaws.com")) && !bytes.Contains(body, []byte("api.aws")) {
		return body
	}
	var v interface{}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return body
	}
	changed := false
	var walk func(x interface{})
	walk = func(x interface{}) {
		switch t := x.(type) {
		case map[string]interface{}:
			for k, val := range t {
				lk := strings.ToLower(k)
				if lk == "queueurl" {
					if s, ok := val.(string); ok {
						if n := rw.rewriteQueueURLString(s); n != s {
							t[k], changed = n, true
						}
					}
				} else if lk == "queueurls" {
					if arr, ok := val.([]interface{}); ok {
						for i, e := range arr {
							if s, ok := e.(string); ok {
								if n := rw.rewriteQueueURLString(s); n != s {
									arr[i], changed = n, true
								}
							}
						}
					}
				} else {
					walk(val)
				}
			}
		case []interface{}:
			for _, e := range t {
				walk(e)
			}
		}
	}
	walk(v)
	if !changed {
		return body
	}
	return marshalNoEscape(v, body)
}

func marshalNoEscape(v interface{}, fallback []byte) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return fallback
	}
	return bytes.TrimRight(buf.Bytes(), "\n")
}

// queueURLsXML rewrites <QueueUrl> elements of a Query-protocol SQS response.
func (rw *rewriter) queueURLsXML(body []byte) []byte {
	return sqsXMLRe.ReplaceAll(body, []byte("${1}"+strings.ReplaceAll(rw.base, "$", "$$")+"/"))
}

// snsEnvelopes rewrites the URL fields of an SNS envelope inside an SQS ReceiveMessage JSON response and recomputes
// MD5OfBody for each message it changed (SDKs verify it).
func (rw *rewriter) snsEnvelopes(body []byte) []byte {
	if !bytes.Contains(body, []byte("UnsubscribeURL")) && !bytes.Contains(body, []byte("SubscribeURL")) && !bytes.Contains(body, []byte("SigningCertURL")) {
		return body
	}
	var top map[string]interface{}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&top); err != nil {
		return body
	}
	msgs, _ := top["Messages"].([]interface{})
	changed := false
	repl := []byte("${1}" + strings.ReplaceAll(rw.base, "$", "$$") + "/")
	for _, m := range msgs {
		msg, ok := m.(map[string]interface{})
		if !ok {
			continue
		}
		text, ok := msg["Body"].(string)
		if !ok || !strings.HasPrefix(text, "{") || !strings.Contains(text, `"TopicArn"`) || !strings.Contains(text, `"Type"`) {
			continue
		}
		n := snsURLRe.ReplaceAll([]byte(text), repl)
		if string(n) == text {
			continue
		}
		sum := md5.Sum(n)
		msg["Body"] = string(n)
		msg["MD5OfBody"] = hex.EncodeToString(sum[:])
		changed = true
	}
	if !changed {
		return body
	}
	return marshalNoEscape(top, body)
}

// s3Location rewrites the <Location> of a CompleteMultipartUploadResult to the path-style URL on the base.
func (rw *rewriter) s3Location(body []byte) []byte {
	b := s3LocVHostRe.ReplaceAll(body, []byte("${1}"+strings.ReplaceAll(rw.base, "$", "$$")+"/${2}${3}${4}"))
	return s3LocPathRe.ReplaceAll(b, []byte("${1}"+strings.ReplaceAll(rw.base, "$", "$$")+"/"))
}

// textual: whether a response body is an API document (JSON or XML) the generic address rewrite may look at.
func textual(ctype, encoding string) bool {
	return (encoding == "" || strings.EqualFold(encoding, "identity")) && jsonishCType.MatchString(ctype)
}
