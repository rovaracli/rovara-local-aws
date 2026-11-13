package main

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// The hidden plumbing of the function runner: the request queue, the per-request reply queues, the payload bucket and the stub's role.
// Customer calls never reach them (they are refused with AccessDenied, whatever the protocol), and the lists a customer reads do not show
// them. The front's own calls to the engine bypass this file entirely: they are not requests of its handler, so they are in no ledger.
//
// What this does NOT hide: code that runs inside the engine reaches every service in-process, past the front. It can list the plumbing and
// read the stub's code, and so can disrupt or tamper with its own run's heavy functions. That is a known limit, not something this file prevents;
// the front's repair and sweep (runner_repair.go, runner_sweep.go) undo what they can.

func isHiddenQueueName(n string) bool {
	return n == hiddenReqQueue || strings.HasPrefix(n, hiddenReplyPrefix) || strings.HasPrefix(n, hiddenPrefix)
}

// queueNameOf is the queue name a queue URL, an ARN or a bare name designates, however it is spelled: a query string, trailing slashes and
// percent-escapes are removed first.
func queueNameOf(u string) string {
	if i := strings.IndexAny(u, "?#"); i >= 0 {
		u = u[:i]
	}
	if d, err := url.PathUnescape(u); err == nil {
		u = d
	}
	u = strings.TrimRight(u, "/")
	if strings.HasPrefix(u, "arn:") {
		if i := strings.LastIndexByte(u, ':'); i >= 0 {
			return u[i+1:]
		}
	}
	if i := strings.LastIndexByte(u, '/'); i >= 0 {
		u = u[i+1:]
	}
	return u
}

// hiddenQueueURL: a queue URL (or name, or ARN) that names a hidden queue.
func hiddenQueueURL(u string) bool { return isHiddenQueueName(queueNameOf(u)) }

// hiddenRefRe finds a hidden name anywhere in a decoded string: a queue, the bucket or the role, as a name, in a URL or in an ARN. The
// name must start where a name starts (the string's start, or after a character that cannot be part of a name), so "my-rovara-heavy-x"
// is not it.
var hiddenRefRe = regexp.MustCompile(`(?:^|[^A-Za-z0-9_.-])rovara-(?:heavy|reply)-`)

func hiddenRef(s string) bool { return hiddenRefRe.MatchString(s) }

var looseEscapeRe = regexp.MustCompile(`\\(?:x([0-9A-Fa-f]{2})|u([0-9A-Fa-f]{4})|U([0-9A-Fa-f]{8}))`)

// unescapeAll decodes the escapes a value can carry on top of its own encoding: percent-escapes (twice over) and the backslash escapes of
// JSON and YAML strings.
func unescapeAll(s string) string {
	for i := 0; i < 3; i++ {
		d, err := url.PathUnescape(s)
		if err != nil || d == s {
			break
		}
		s = d
	}
	return looseEscapeRe.ReplaceAllStringFunc(s, func(m string) string {
		h := strings.TrimLeft(m[2:], "0")
		if h == "" {
			return "\x00"
		}
		n, err := strconv.ParseUint(h, 16, 32)
		if err != nil {
			return m
		}
		return string(rune(n))
	})
}

// A decoded check, never a byte search: JSON is read as JSON (an escaped `\u002d` is a hyphen), a form as a form.
//
// scanJSON walks a JSON document token by token, so every key and value is seen (a duplicate key included: the engine may read the first
// of two, a map the last), and reports whether any string names the hidden plumbing. The values of the keys in skip are data, not names (a
// message body, a package), and are consumed without being looked at. A string that holds a document (a state machine definition, a policy)
// is scanned as one. err is set when b is not exactly one JSON document (bytes after it count): the caller refuses what it cannot read.
func scanJSON(b []byte, skip func(key string) bool) (found bool, err error) {
	b = bytes.TrimPrefix(b, []byte("\xef\xbb\xbf"))
	dec := json.NewDecoder(bytes.NewReader(b))
	found, err = walkTokens(dec, skip, 0)
	if err != nil || found {
		return found, err // a hit is a refusal, whatever follows it
	}
	if _, terr := dec.Token(); terr != io.EOF {
		return false, errors.New("bytes after the JSON document")
	}
	return found, nil
}

func walkTokens(dec *json.Decoder, skip func(string) bool, depth int) (bool, error) {
	if depth > 200 {
		return false, errors.New("JSON nested too deeply")
	}
	t, err := dec.Token()
	if err != nil {
		return false, err
	}
	switch v := t.(type) {
	case json.Delim:
		switch v {
		case '{':
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return false, err
				}
				key, _ := kt.(string)
				if hiddenRef(key) || hiddenRef(unescapeAll(key)) {
					return true, nil
				}
				if skip != nil && skip(key) {
					var raw json.RawMessage
					if err := dec.Decode(&raw); err != nil {
						return false, err
					}
					continue
				}
				if f, err := walkTokens(dec, skip, depth+1); err != nil || f {
					return f, err
				}
			}
			_, err := dec.Token()
			return false, err
		case '[':
			for dec.More() {
				if f, err := walkTokens(dec, skip, depth+1); err != nil || f {
					return f, err
				}
			}
			_, err := dec.Token()
			return false, err
		}
		return false, errors.New("unexpected JSON delimiter")
	case string:
		if hiddenRef(v) || (strings.ContainsAny(v, "%\\") && hiddenRef(unescapeAll(v))) {
			return true, nil
		}
		if in := strings.TrimSpace(v); len(in) > 1 && (in[0] == '{' || in[0] == '[') {
			if f, err := scanJSON([]byte(in), skip); err == nil && f {
				return true, nil
			}
		}
	}
	return false, nil
}

// jsonHasHidden is scanJSON for a caller that treats a document it cannot read as a hit (it refuses either way).
func jsonHasHidden(b []byte, skip func(key string) bool) bool {
	f, err := scanJSON(b, skip)
	return f || err != nil
}

// valueHasHidden: the same check over an already decoded document (a CloudFormation template parsed from JSON or YAML).
func valueHasHidden(v interface{}, depth int) bool {
	if depth > 120 {
		return true // too deep to judge: refused
	}
	switch t := v.(type) {
	case string:
		if hiddenRef(t) {
			return true
		}
		if in := strings.TrimLeft(t, " \t\r\n"); len(in) > 1 && (in[0] == '{' || in[0] == '[') {
			return jsonHasHidden([]byte(in), nil)
		}
	case map[string]interface{}:
		for k, x := range t {
			if hiddenRef(k) || valueHasHidden(x, depth+1) {
				return true
			}
		}
	case []interface{}:
		for _, x := range t {
			if valueHasHidden(x, depth+1) {
				return true
			}
		}
	}
	return false
}

// templateHasHidden: a CloudFormation template (JSON or YAML text) that names the hidden plumbing anywhere. The raw text is searched too,
// because a YAML scalar has escapes of its own; a template built with intrinsic functions that assemble the name is not caught here, and
// does not need to be: the names are random per generation, and the sweeper removes what points at the plumbing.
func templateHasHidden(text string) bool {
	if hiddenRef(text) || hiddenRef(unescapeAll(text)) {
		return true
	}
	if doc, ok := parseTemplate(text); ok {
		return valueHasHidden(doc, 0)
	}
	return false
}

// dataKey: the members whose values are customer data or code, never names.
func dataKey(k string) bool {
	return k == "ZipFile" || k == "MessageBody" || k == "StringValue" || k == "BinaryValue"
}

// formHasHidden: any value of a parsed form or query (the keys of message data are skipped).
func formHasHidden(v url.Values) bool {
	for k, vs := range v {
		if strings.HasSuffix(k, "MessageBody") || strings.HasSuffix(k, "StringValue") || strings.HasSuffix(k, "BinaryValue") || k == "Message" || strings.HasPrefix(k, "MessageAttributes") {
			continue
		}
		if hiddenRef(k) {
			return true
		}
		for _, x := range vs {
			if hiddenRef(x) || hiddenRef(unescapeAll(x)) {
				return true
			}
		}
	}
	return false
}

// dataPlane: the services whose bodies are customer data (values, records, objects), not control-plane names; they are not scanned.
var dataPlane = map[string]bool{"rekognition": true, "textract": true, "comprehend": true, "polly": true, "transcribe": true, "bedrock-runtime": true, "sagemaker-runtime": true, "bedrock-agent-runtime": true, "apigatewaymanagementapi": true, "s3": true, "dynamodb": true, "dynamodb-streams": true, "cloudwatch-logs": true, "secrets-manager": true, "ssm": true, "kms": true,
	"kinesis": true, "firehose": true, "timestream-write": true, "timestream-query": true}

// runnerDataPlane: a request whose body is the customer's DATA, not names: an invoke of a function (its payload, however big), an event or a
// message published, image and blob bytes, a call to an API Gateway endpoint or a function URL. Such a body is neither decoded nor looked at:
// an app that posts gzip to its own API must get it back untouched. It is decided from what the FRONT identified (the service and the operation:
// InvokeApi, InvokeFunctionUrl and DataPlaneRequest are the front's own names for the reserved data-plane paths) or from the reserved path
// /_aws/ itself; never from a header a caller can write, the Host included.
func runnerDataPlane(r *http.Request, key, op string) bool {
	if strings.HasPrefix(r.URL.Path, "/_aws/") {
		return true
	}
	if dataPlane[key] || (key == "lambda" && (op == "Invoke" || op == "InvokeAsync" || op == "InvokeWithResponseStream")) {
		return true
	}
	switch op {
	case "InvokeApi", "InvokeFunctionUrl", "DataPlaneRequest", "PutEvents", "Publish", "PublishBatch", "SendTaskSuccess", "SendTaskFailure", "SendTaskHeartbeat", "UploadLayerPart":
		return true
	}
	return false
}

// xmlHasHidden reads an XML document as XML: character references (&#114; and &#x72;) and the predefined entities are decoded by the parser;
// element and attribute names and values are looked at; the text of an element is joined across CDATA sections, comments and processing
// instructions before it is looked at (a parser that hands the application one string, as most do, sees "rovara-heavy-" however it was
// split); and a document it cannot read (an undefined entity, a DOCTYPE or ENTITY declaration, bad nesting, text that is not UTF-8, a
// character reference that is not a character) is an error the caller refuses.
func xmlHasHidden(b []byte) (found bool, err error) {
	d := xml.NewDecoder(bytes.NewReader(b))
	d.Strict = true
	d.Entity = nil
	check := func(s string) bool { return hiddenRef(s) || hiddenRef(unescapeAll(s)) }
	var stack []*strings.Builder
	for {
		t, err := d.Token()
		if err == io.EOF {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		switch v := t.(type) {
		case xml.Directive:
			return false, errors.New("an XML directive is not read")
		case xml.StartElement:
			if check(v.Name.Local) {
				return true, nil
			}
			for _, a := range v.Attr {
				if check(a.Name.Local) || check(a.Value) {
					return true, nil
				}
			}
			stack = append(stack, &strings.Builder{})
		case xml.CharData:
			if check(string(v)) {
				return true, nil
			}
			if len(stack) > 0 {
				stack[len(stack)-1].Write(v)
			}
		case xml.EndElement:
			if len(stack) > 0 {
				joined := stack[len(stack)-1].String()
				stack = stack[:len(stack)-1]
				if check(joined) {
					return true, nil
				}
			}
		}
	}
}

// copySourceBucket: the bucket an x-amz-copy-source header names.
func copySourceBucket(h string) string {
	if d, err := url.PathUnescape(h); err == nil {
		h = d
	}
	if i := strings.IndexByte(h, '?'); i >= 0 {
		h = h[:i]
	}
	h = strings.TrimPrefix(h, "/")
	h = strings.TrimPrefix(h, "arn:aws:s3:::")
	b, _, _ := strings.Cut(h, "/")
	return b
}

// guardHead is the most of a notification configuration that is read; guardMax is the most of any other body: the engine's own limit for what it
// decodes (it inflates an RPC body to at most 16 MiB).
const (
	guardHead = 1 << 20
	guardMax  = 16 << 20
)

// runnerGuard refuses a customer call that names the hidden plumbing. It decodes what it checks (a form, a query, a JSON document), reads
// at most guardHead of a body, and refuses a body it cannot read whole. It returns the body to forward and whether the call was refused
// (the answer is written). It keeps a customer's CALLS (through the front) from naming the plumbing. It is not a boundary against code running
// in the same engine, which reaches every service in-process and can read the stub's code; see the known limit in runner_engine.go (authentic).
func (s *Server) runnerGuard(w http.ResponseWriter, r *http.Request, id identified, bucket string, form url.Values, body io.Reader) (io.Reader, func(), bool) {
	noop := func() {}
	refuse := func() (io.Reader, func(), bool) {
		writeAWSError(w, id.Proto, http.StatusForbidden, "AccessDenied", "This name is reserved by the Rovara function runner.", "")
		return body, noop, true
	}
	// a body that is not something the engine could read: a plain malformed-input answer, not the "reserved" one
	malformed := func() (io.Reader, func(), bool) {
		writeAWSError(w, id.Proto, http.StatusBadRequest, "InvalidRequest", "The request body could not be read.", "")
		return body, noop, true
	}
	key := id.Service.Key
	q := r.URL.Query()
	if hiddenQueueURL(r.URL.Path) && key == "sqs" {
		return refuse()
	}
	switch key {
	case "s3":
		b := bucket
		if b == "" {
			b = firstSegment(r.URL.EscapedPath())
			if d, err := url.PathUnescape(b); err == nil {
				b = d
			}
		}
		if strings.HasPrefix(b, hiddenPrefix) || strings.HasPrefix(copySourceBucket(r.Header.Get("x-amz-copy-source")), hiddenPrefix) {
			return refuse()
		}
		if _, notif := q["notification"]; notif && r.Method == http.MethodPut {
			if len(r.Header.Values("Content-Encoding")) > 0 {
				return refuse() // an encoded notification configuration is not read
			}
			head, _ := io.ReadAll(io.LimitReader(body, guardHead+1))
			body = io.MultiReader(bytes.NewReader(head), body)
			if len(head) > guardHead {
				return malformed()
			}
			found, err := xmlHasHidden(head) // read as XML: references decoded, text joined
			if err != nil {
				return malformed()
			}
			if found {
				return refuse()
			}
		}
		return body, noop, false
	case "sqs":
		if formHasHidden(sqsQueryParams(q, form)) {
			return refuse()
		}
		if form != nil {
			return body, noop, false
		}
	default:
		if runnerDataPlane(r, key, id.Operation) || (key == "lambda" && lambdaPackageOps[id.Operation]) {
			return body, noop, false
		}
		if formHasHidden(q) || (form != nil && formHasHidden(form)) || hiddenRef(unescapeAll(r.URL.Path)) {
			return refuse()
		}
		if form != nil {
			return body, noop, false
		}
	}
	// a JSON, CBOR or other body of a service whose bodies are names: read whole (at most guardHead) and decoded. Content-Encoding was dealt
	// with before this (runner_encoding.go): what is looked at here is what the engine will read.
	if r.ContentLength == 0 {
		return body, noop, false
	}
	// the body is held within the inspection budget (a crowd of big control-plane calls cannot exhaust the front); one the budget cannot hold
	// is told to retry, one over the engine's own limit is refused
	head, truncated, release := s.readForInspection(body, r.ContentLength, guardMax)
	body = io.MultiReader(bytes.NewReader(head), body)
	if truncated {
		release()
		if r.ContentLength > guardMax || len(head) > guardMax {
			writeAWSError(w, id.Proto, http.StatusRequestEntityTooLarge, "RequestEntityTooLarge", "The request is too large for this service.", "")
		} else {
			w.Header().Set("Retry-After", "1")
			writeAWSError(w, id.Proto, http.StatusServiceUnavailable, "ServiceUnavailable", "The local AWS emulator is busy reading other large requests.", "")
		}
		return body, noop, true
	}
	refuseR := func() (io.Reader, func(), bool) { release(); return refuse() }
	malformedR := func() (io.Reader, func(), bool) { release(); return malformed() }
	if trimmed := bytes.TrimLeft(bytes.TrimPrefix(head, []byte("\xef\xbb\xbf")), " \t\r\n"); len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[') && id.Proto != protoCBOR {
		found, err := scanJSON(head, dataKey)
		if err != nil {
			// a document that does not parse the way the engine's parser might: refused, not guessed at
			return malformedR()
		}
		if found {
			return refuseR()
		}
		return body, release, false
	}
	if trimmed := bytes.TrimLeft(head, " \t\r\n"); len(trimmed) > 0 && trimmed[0] == '<' {
		found, err := xmlHasHidden(head)
		if err != nil {
			return malformedR()
		}
		if found {
			return refuseR()
		}
		return body, release, false
	}
	// CBOR and other bodies hold their strings unescaped
	if text := string(head); hiddenRef(text) || hiddenRef(unescapeAll(text)) {
		return refuseR()
	}
	return body, release, false
}

// lambdaPackageOps are the Lambda calls that carry code; the runner's plan reads them whole and checks them itself.
var lambdaPackageOps = map[string]bool{"CreateFunction": true, "UpdateFunctionCode": true, "PublishLayerVersion": true}

// hideTargets leaves out of a ListTargetsByRule answer the targets that name the plumbing.
func hideTargets(data []byte) []byte {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var top map[string]interface{}
	if dec.Decode(&top) != nil {
		return data
	}
	l, ok := top["Targets"].([]interface{})
	if !ok {
		return data
	}
	kept := make([]interface{}, 0, len(l))
	for _, t := range l {
		if b, err := json.Marshal(t); err == nil && jsonHasHidden(b, nil) {
			continue
		}
		kept = append(kept, t)
	}
	if len(kept) == len(l) {
		return data
	}
	top["Targets"] = kept
	return marshalNoEscape(top, data)
}

// dropBlocks removes the top-level <open>...</open> blocks of an XML answer that contain needle. Blocks of the same name may nest (a role's
// tags are members too): only the outermost are judged, and the nested ones go with them.
func dropBlocks(data []byte, open, closing, needle string) []byte {
	if !bytes.Contains(data, []byte(needle)) {
		return data
	}
	var out bytes.Buffer
	rest := data
	for {
		i := bytes.Index(rest, []byte(open))
		if i < 0 {
			out.Write(rest)
			break
		}
		depth, j := 0, i
		end := -1
		for j < len(rest) {
			o := bytes.Index(rest[j:], []byte(open))
			c := bytes.Index(rest[j:], []byte(closing))
			if c < 0 {
				break
			}
			if o >= 0 && o < c {
				depth++
				j += o + len(open)
				continue
			}
			depth--
			j += c + len(closing)
			if depth == 0 {
				end = j
				break
			}
		}
		if end < 0 { // unbalanced: leave the rest alone
			out.Write(rest)
			break
		}
		out.Write(rest[:i])
		if !bytes.Contains(rest[i:end], []byte(needle)) {
			out.Write(rest[i:end])
		}
		rest = rest[end:]
	}
	return out.Bytes()
}

// hideInLists removes the hidden bucket from a ListBuckets answer and the hidden role from a ListRoles answer (XML).
func hideInLists(data []byte) []byte {
	if t := bytes.TrimLeft(data, " \t\r\n"); len(t) > 0 && t[0] == '{' {
		return hideTargets(data) // ListTargetsByRule (JSON)
	}
	data = dropBlocks(data, "<Bucket>", "</Bucket>", "<Name>"+hiddenPrefix)
	data = dropBlocks(data, "<member>", "</member>", "<RoleName>"+hiddenPrefix)
	return data
}
