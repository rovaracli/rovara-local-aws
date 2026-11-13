package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// The SQS Query protocol, translated to the JSON protocol the engine speaks (it has no Query for SQS).
//
// Old SDKs (boto3 before about 1.31, AWS SDK for Java v1, older Ruby, PHP and .NET clients, Rovara's own proof project)
// POST application/x-www-form-urlencoded: Action=<Operation>&Version=2012-11-05&<members>. The members are flattened as
// AWS defines them: lists are Name.N, maps are Attribute.N.Name / Attribute.N.Value (tags: Tag.N.Key / Tag.N.Value),
// message attributes are MessageAttribute.N.Name / .Value.DataType / .Value.StringValue / .Value.BinaryValue, and batch
// entries are <Operation>RequestEntry.N.<member>. The request becomes {"X-Amz-Target": "AmazonSQS.<Operation>", JSON body},
// and the engine's answer becomes the Query XML AWS returns (xmlns http://queue.amazonaws.com/doc/2012-11-05/, a
// <Operation>Result element where the operation has a result, ResponseMetadata/RequestId; errors are ErrorResponse/Error with
// Type, Code, Message, Detail, with the AWS.SimpleQueueService.* codes where AWS uses them).
// The SDKs of the Java v1 family send the request to the queue's own URL and leave QueueUrl out of the form: the path
// /<account>/<queue> then names the queue.

const sqsNS = "http://queue.amazonaws.com/doc/2012-11-05/"

type fkind int

const (
	fStr fkind = iota
	fInt
	fBool
	fList     // Name.N
	fAttrMap  // Name.N.Name / Name.N.Value  -> {name: value}
	fTagMap   // Name.N.Key / Name.N.Value   -> {key: value}
	fMsgAttrs // Name.N.Name / Name.N.Value.{DataType,StringValue,BinaryValue,StringListValue.M,BinaryListValue.M}
	fEntries  // Name.N.<sub fields> -> [ {..} ]
)

type fspec struct {
	q, j string
	k    fkind
	sub  []fspec
}

var msgEntry = []fspec{
	{q: "Id", j: "Id"}, {q: "MessageBody", j: "MessageBody"}, {q: "DelaySeconds", j: "DelaySeconds", k: fInt},
	{q: "MessageAttribute", j: "MessageAttributes", k: fMsgAttrs}, {q: "MessageSystemAttribute", j: "MessageSystemAttributes", k: fMsgAttrs},
	{q: "MessageDeduplicationId", j: "MessageDeduplicationId"}, {q: "MessageGroupId", j: "MessageGroupId"},
}

var queueURL = fspec{q: "QueueUrl", j: "QueueUrl"}

// sqsSpecs: every operation of the SQS API and its Query members.
var sqsSpecs = map[string][]fspec{
	"CreateQueue":                  {{q: "QueueName", j: "QueueName"}, {q: "Attribute", j: "Attributes", k: fAttrMap}, {q: "Tag", j: "tags", k: fTagMap}},
	"DeleteQueue":                  {queueURL},
	"GetQueueUrl":                  {{q: "QueueName", j: "QueueName"}, {q: "QueueOwnerAWSAccountId", j: "QueueOwnerAWSAccountId"}},
	"ListQueues":                   {{q: "QueueNamePrefix", j: "QueueNamePrefix"}, {q: "NextToken", j: "NextToken"}, {q: "MaxResults", j: "MaxResults", k: fInt}},
	"GetQueueAttributes":           {queueURL, {q: "AttributeName", j: "AttributeNames", k: fList}},
	"SetQueueAttributes":           {queueURL, {q: "Attribute", j: "Attributes", k: fAttrMap}},
	"PurgeQueue":                   {queueURL},
	"SendMessage":                  {queueURL, {q: "MessageBody", j: "MessageBody"}, {q: "DelaySeconds", j: "DelaySeconds", k: fInt}, {q: "MessageAttribute", j: "MessageAttributes", k: fMsgAttrs}, {q: "MessageSystemAttribute", j: "MessageSystemAttributes", k: fMsgAttrs}, {q: "MessageDeduplicationId", j: "MessageDeduplicationId"}, {q: "MessageGroupId", j: "MessageGroupId"}},
	"SendMessageBatch":             {queueURL, {q: "SendMessageBatchRequestEntry", j: "Entries", k: fEntries, sub: msgEntry}},
	"ReceiveMessage":               {queueURL, {q: "AttributeName", j: "AttributeNames", k: fList}, {q: "MessageSystemAttributeName", j: "MessageSystemAttributeNames", k: fList}, {q: "MessageAttributeName", j: "MessageAttributeNames", k: fList}, {q: "MaxNumberOfMessages", j: "MaxNumberOfMessages", k: fInt}, {q: "VisibilityTimeout", j: "VisibilityTimeout", k: fInt}, {q: "WaitTimeSeconds", j: "WaitTimeSeconds", k: fInt}, {q: "ReceiveRequestAttemptId", j: "ReceiveRequestAttemptId"}},
	"DeleteMessage":                {queueURL, {q: "ReceiptHandle", j: "ReceiptHandle"}},
	"DeleteMessageBatch":           {queueURL, {q: "DeleteMessageBatchRequestEntry", j: "Entries", k: fEntries, sub: []fspec{{q: "Id", j: "Id"}, {q: "ReceiptHandle", j: "ReceiptHandle"}}}},
	"ChangeMessageVisibility":      {queueURL, {q: "ReceiptHandle", j: "ReceiptHandle"}, {q: "VisibilityTimeout", j: "VisibilityTimeout", k: fInt}},
	"ChangeMessageVisibilityBatch": {queueURL, {q: "ChangeMessageVisibilityBatchRequestEntry", j: "Entries", k: fEntries, sub: []fspec{{q: "Id", j: "Id"}, {q: "ReceiptHandle", j: "ReceiptHandle"}, {q: "VisibilityTimeout", j: "VisibilityTimeout", k: fInt}}}},
	"AddPermission":                {queueURL, {q: "Label", j: "Label"}, {q: "AWSAccountId", j: "AWSAccountIds", k: fList}, {q: "ActionName", j: "Actions", k: fList}},
	"RemovePermission":             {queueURL, {q: "Label", j: "Label"}},
	"ListQueueTags":                {queueURL},
	"TagQueue":                     {queueURL, {q: "Tag", j: "Tags", k: fTagMap}},
	"UntagQueue":                   {queueURL, {q: "TagKey", j: "TagKeys", k: fList}},
	"ListDeadLetterSourceQueues":   {queueURL, {q: "NextToken", j: "NextToken"}, {q: "MaxResults", j: "MaxResults", k: fInt}},
	"StartMessageMoveTask":         {{q: "SourceArn", j: "SourceArn"}, {q: "DestinationArn", j: "DestinationArn"}, {q: "MaxNumberOfMessagesPerSecond", j: "MaxNumberOfMessagesPerSecond", k: fInt}},
	"CancelMessageMoveTask":        {{q: "TaskHandle", j: "TaskHandle"}},
	"ListMessageMoveTasks":         {{q: "SourceArn", j: "SourceArn"}, {q: "MaxResults", j: "MaxResults", k: fInt}},
}

// sqsRequired: the members a request must carry (AWS answers MissingParameter for a missing one). QueueUrl may come from the
// request path, so it is checked after that is filled in.
var sqsRequired = map[string][]string{
	"CreateQueue": {"QueueName"}, "DeleteQueue": {"QueueUrl"}, "GetQueueUrl": {"QueueName"}, "GetQueueAttributes": {"QueueUrl"},
	"SetQueueAttributes": {"QueueUrl"}, "PurgeQueue": {"QueueUrl"}, "SendMessage": {"QueueUrl", "MessageBody"}, "ReceiveMessage": {"QueueUrl"},
	"DeleteMessage": {"QueueUrl", "ReceiptHandle"}, "ChangeMessageVisibility": {"QueueUrl", "ReceiptHandle", "VisibilityTimeout"},
	"AddPermission": {"QueueUrl", "Label"}, "RemovePermission": {"QueueUrl", "Label"}, "ListQueueTags": {"QueueUrl"}, "TagQueue": {"QueueUrl"},
	"UntagQueue": {"QueueUrl"}, "ListDeadLetterSourceQueues": {"QueueUrl"}, "CancelMessageMoveTask": {"TaskHandle"}, "StartMessageMoveTask": {"SourceArn"},
	"ListMessageMoveTasks": {"SourceArn"}, "SendMessageBatch": {"QueueUrl"}, "DeleteMessageBatch": {"QueueUrl"}, "ChangeMessageVisibilityBatch": {"QueueUrl"},
}

// sqsBatchEntries: the batch operations and the Query name of their entries.
var sqsBatchEntries = map[string]string{"SendMessageBatch": "SendMessageBatchRequestEntry", "DeleteMessageBatch": "DeleteMessageBatchRequestEntry",
	"ChangeMessageVisibilityBatch": "ChangeMessageVisibilityBatchRequestEntry"}

type queryErr struct {
	status        int
	code, message string
}

func invalidParam(name, value, reason string) *queryErr {
	return &queryErr{http.StatusBadRequest, "InvalidParameterValue", fmt.Sprintf("Value %s for parameter %s is invalid. Reason: %s.", value, name, reason)}
}

// indices: the distinct N of the keys "<prefix>.N" and "<prefix>.N.<rest>", ascending.
func indices(p url.Values, prefix string) []int {
	seen := map[int]bool{}
	pre := prefix + "."
	for k := range p {
		if !strings.HasPrefix(k, pre) {
			continue
		}
		rest := k[len(pre):]
		if i := strings.IndexByte(rest, '.'); i >= 0 {
			rest = rest[:i]
		}
		if n, err := strconv.Atoi(rest); err == nil && n > 0 && n <= 1000 {
			seen[n] = true
		}
	}
	out := make([]int, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Ints(out)
	return out
}

func sub(p url.Values, prefix string) url.Values {
	out := url.Values{}
	for k, v := range p {
		if strings.HasPrefix(k, prefix) {
			out[k[len(prefix):]] = v
		}
	}
	return out
}

func buildFields(p url.Values, specs []fspec) (map[string]interface{}, *queryErr) {
	out := map[string]interface{}{}
	for _, f := range specs {
		switch f.k {
		case fStr:
			if v, ok := p[f.q]; ok && len(v) > 0 {
				out[f.j] = v[0]
			}
		case fInt:
			if v, ok := p[f.q]; ok && len(v) > 0 {
				n, err := strconv.ParseInt(v[0], 10, 64)
				if err != nil {
					return nil, invalidParam(f.q, v[0], "Must be an integer")
				}
				out[f.j] = n
			}
		case fBool:
			if v, ok := p[f.q]; ok && len(v) > 0 {
				out[f.j] = v[0] == "true"
			}
		case fList:
			var vals []string
			for _, n := range indices(p, f.q) {
				if v, ok := p[f.q+"."+strconv.Itoa(n)]; ok {
					vals = append(vals, v[0])
				}
			}
			if len(vals) > 0 {
				out[f.j] = vals
			}
		case fAttrMap, fTagMap:
			kn, vn := "Name", "Value"
			if f.k == fTagMap {
				kn = "Key"
			}
			m := map[string]string{}
			for _, n := range indices(p, f.q) {
				pre := f.q + "." + strconv.Itoa(n) + "."
				if k, ok := p[pre+kn]; ok {
					v := ""
					if vv, ok := p[pre+vn]; ok {
						v = vv[0]
					}
					m[k[0]] = v
				}
			}
			if len(m) > 0 {
				out[f.j] = m
			}
		case fMsgAttrs:
			m := map[string]interface{}{}
			for _, n := range indices(p, f.q) {
				pre := f.q + "." + strconv.Itoa(n) + "."
				name, ok := p[pre+"Name"]
				if !ok {
					continue
				}
				val := map[string]interface{}{}
				for _, k := range []string{"DataType", "StringValue", "BinaryValue"} {
					if v, ok := p[pre+"Value."+k]; ok {
						val[k] = v[0]
					}
				}
				for _, l := range [][2]string{{"StringListValue", "StringListValues"}, {"BinaryListValue", "BinaryListValues"}} {
					var vals []string
					for _, i := range indices(p, pre+"Value."+l[0]) {
						if v, ok := p[pre+"Value."+l[0]+"."+strconv.Itoa(i)]; ok {
							vals = append(vals, v[0])
						}
					}
					if len(vals) > 0 {
						val[l[1]] = vals
					}
				}
				m[name[0]] = val
			}
			if len(m) > 0 {
				out[f.j] = m
			}
		case fEntries:
			var list []interface{}
			for _, n := range indices(p, f.q) {
				e, err := buildFields(sub(p, f.q+"."+strconv.Itoa(n)+"."), f.sub)
				if err != nil {
					return nil, err
				}
				list = append(list, e)
			}
			if len(list) > 0 {
				out[f.j] = list
			}
		}
	}
	return out, nil
}

// sqsQueryToJSON builds the JSON request body of one Query operation. ok is false for an operation SQS does not have.
func sqsQueryToJSON(action string, p url.Values) (body map[string]interface{}, known bool, err *queryErr) {
	specs, ok := sqsSpecs[action]
	if !ok {
		return nil, false, nil
	}
	body, err = buildFields(p, specs)
	return body, true, err
}

// ---- the answer

// queryErrorCodes: the JSON error code the engine speaks -> the Query code AWS returns.
var queryErrorCodes = map[string]string{
	"QueueDoesNotExist":                 "AWS.SimpleQueueService.NonExistentQueue",
	"QueueNameExists":                   "QueueAlreadyExists",
	"QueueDeletedRecently":              "AWS.SimpleQueueService.QueueDeletedRecently",
	"EmptyBatchRequest":                 "AWS.SimpleQueueService.EmptyBatchRequest",
	"BatchEntryIdsNotDistinct":          "AWS.SimpleQueueService.BatchEntryIdsNotDistinct",
	"TooManyEntriesInBatchRequest":      "AWS.SimpleQueueService.TooManyEntriesInBatchRequest",
	"InvalidBatchEntryId":               "AWS.SimpleQueueService.InvalidBatchEntryId",
	"BatchRequestTooLong":               "AWS.SimpleQueueService.BatchRequestTooLong",
	"PurgeQueueInProgress":              "AWS.SimpleQueueService.PurgeQueueInProgress",
	"MessageNotInflight":                "AWS.SimpleQueueService.MessageNotInflight",
	"ReceiptHandleIsInvalid":            "ReceiptHandleIsInvalid",
	"UnsupportedOperation":              "AWS.SimpleQueueService.UnsupportedOperation",
	"InvalidMessageContents":            "InvalidMessageContents",
	"RequestThrottled":                  "RequestThrottled",
	"ResourceNotFoundException":         "ResourceNotFoundException",
	"InvalidSecurity":                   "InvalidSecurity",
	"OverLimit":                         "OverLimit",
	"AccessDeniedException":             "AccessDenied",
	"MissingRequiredParameterException": "MissingParameter",
	"InvalidParameterValueException":    "InvalidParameterValue",
	"InvalidAction":                     "InvalidAction",
	"NotImplemented":                    "NotImplemented",
	"ServiceNotAvailableException":      "ServiceNotAvailableException",
}

// jsonErrorToQuery reads an engine error (the JSON body and its headers) as the Query error AWS would give.
func jsonErrorToQuery(status int, hdr http.Header, body []byte) *queryErr {
	var j map[string]interface{}
	_ = json.Unmarshal(body, &j)
	code := text(j["__type"], text(j["code"], ""))
	if i := strings.LastIndex(code, "#"); i >= 0 {
		code = code[i+1:]
	}
	msg := text(j["message"], text(j["Message"], ""))
	if h := hdr.Get("x-amzn-query-error"); h != "" {
		if i := strings.Index(h, ";"); i >= 0 {
			h = h[:i]
		}
		code = h
	} else if q, ok := queryErrorCodes[code]; ok {
		code = q
	}
	if code == "ValidationException" {
		if strings.Contains(msg, "must not be null") {
			code = "MissingParameter"
		} else {
			code = "InvalidParameterValue"
		}
	}
	if code == "" {
		code = "InternalError"
	}
	return &queryErr{status, code, msg}
}

type xw struct{ b strings.Builder }

func (x *xw) el(name, val string) {
	x.b.WriteString("<" + name + ">" + xmlEscape(val) + "</" + name + ">")
}
func (x *xw) open(n string) { x.b.WriteString("<" + n + ">") }
func (x *xw) end(n string)  { x.b.WriteString("</" + n + ">") }

func str(v interface{}) string { return text(v, "") }

func asList(v interface{}) []interface{} { return list(v) }

// sortedKeys: a JSON map's keys in a stable order.
func sortedKeys(m map[string]interface{}) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func (x *xw) opt(name string, m map[string]interface{}, key string) {
	if v, ok := m[key]; ok && v != nil {
		x.el(name, str(v))
	}
}

func (x *xw) attributes(m map[string]interface{}) {
	for _, k := range sortedKeys(m) {
		x.open("Attribute")
		x.el("Name", k)
		x.el("Value", str(m[k]))
		x.end("Attribute")
	}
}

func (x *xw) queueURLs(r map[string]interface{}, key string) {
	for _, u := range asList(r[key]) {
		x.el("QueueUrl", str(u))
	}
	x.opt("NextToken", r, "NextToken")
}

func (x *xw) failed(r map[string]interface{}) {
	for _, f := range asList(r["Failed"]) {
		e := asMap(f)
		x.open("BatchResultErrorEntry")
		x.el("Id", str(e["Id"]))
		x.el("SenderFault", str(e["SenderFault"]))
		x.el("Code", str(e["Code"]))
		x.opt("Message", e, "Message")
		x.end("BatchResultErrorEntry")
	}
}

func (x *xw) idEntries(r map[string]interface{}, elem string) {
	for _, s := range asList(r["Successful"]) {
		x.open(elem)
		x.el("Id", str(asMap(s)["Id"]))
		x.end(elem)
	}
	x.failed(r)
}

func (x *xw) messageAttrValue(name string, v interface{}) {
	a := asMap(v)
	x.open("MessageAttribute")
	x.el("Name", name)
	x.open("Value")
	x.opt("StringValue", a, "StringValue")
	x.opt("BinaryValue", a, "BinaryValue")
	for _, s := range asList(a["StringListValues"]) {
		x.el("StringListValue", str(s))
	}
	for _, s := range asList(a["BinaryListValues"]) {
		x.el("BinaryListValue", str(s))
	}
	x.el("DataType", str(a["DataType"]))
	x.end("Value")
	x.end("MessageAttribute")
}

// sqsResults: how each operation's JSON result is written inside <Operation>Result. nil: the operation has no result element.
var sqsResults = map[string]func(x *xw, r map[string]interface{}){
	"CreateQueue": func(x *xw, r map[string]interface{}) { x.el("QueueUrl", str(r["QueueUrl"])) },
	"GetQueueUrl": func(x *xw, r map[string]interface{}) { x.el("QueueUrl", str(r["QueueUrl"])) },
	"ListQueues":  func(x *xw, r map[string]interface{}) { x.queueURLs(r, "QueueUrls") },
	"ListDeadLetterSourceQueues": func(x *xw, r map[string]interface{}) {
		if _, ok := r["queueUrls"]; ok {
			x.queueURLs(r, "queueUrls")
		} else {
			x.queueURLs(r, "QueueUrls")
		}
	},
	"GetQueueAttributes": func(x *xw, r map[string]interface{}) { x.attributes(asMap(r["Attributes"])) },
	"SendMessage": func(x *xw, r map[string]interface{}) {
		x.opt("MD5OfMessageBody", r, "MD5OfMessageBody")
		x.opt("MD5OfMessageAttributes", r, "MD5OfMessageAttributes")
		x.opt("MD5OfMessageSystemAttributes", r, "MD5OfMessageSystemAttributes")
		x.opt("MessageId", r, "MessageId")
		x.opt("SequenceNumber", r, "SequenceNumber")
	},
	"SendMessageBatch": func(x *xw, r map[string]interface{}) {
		for _, s := range asList(r["Successful"]) {
			e := asMap(s)
			x.open("SendMessageBatchResultEntry")
			x.el("Id", str(e["Id"]))
			x.opt("MessageId", e, "MessageId")
			x.opt("MD5OfMessageBody", e, "MD5OfMessageBody")
			x.opt("MD5OfMessageAttributes", e, "MD5OfMessageAttributes")
			x.opt("MD5OfMessageSystemAttributes", e, "MD5OfMessageSystemAttributes")
			x.opt("SequenceNumber", e, "SequenceNumber")
			x.end("SendMessageBatchResultEntry")
		}
		x.failed(r)
	},
	"ReceiveMessage": func(x *xw, r map[string]interface{}) {
		for _, m := range asList(r["Messages"]) {
			e := asMap(m)
			x.open("Message")
			x.opt("MessageId", e, "MessageId")
			x.opt("ReceiptHandle", e, "ReceiptHandle")
			x.opt("MD5OfBody", e, "MD5OfBody")
			x.opt("Body", e, "Body")
			x.attributes(asMap(e["Attributes"]))
			x.opt("MD5OfMessageAttributes", e, "MD5OfMessageAttributes")
			ma := asMap(e["MessageAttributes"])
			for _, k := range sortedKeys(ma) {
				x.messageAttrValue(k, ma[k])
			}
			x.end("Message")
		}
	},
	"DeleteMessageBatch":           func(x *xw, r map[string]interface{}) { x.idEntries(r, "DeleteMessageBatchResultEntry") },
	"ChangeMessageVisibilityBatch": func(x *xw, r map[string]interface{}) { x.idEntries(r, "ChangeMessageVisibilityBatchResultEntry") },
	"ListQueueTags": func(x *xw, r map[string]interface{}) {
		t := asMap(r["Tags"])
		for _, k := range sortedKeys(t) {
			x.open("Tag")
			x.el("Key", k)
			x.el("Value", str(t[k]))
			x.end("Tag")
		}
	},
	"StartMessageMoveTask": func(x *xw, r map[string]interface{}) { x.el("TaskHandle", str(r["TaskHandle"])) },
	"CancelMessageMoveTask": func(x *xw, r map[string]interface{}) {
		x.opt("ApproximateNumberOfMessagesMoved", r, "ApproximateNumberOfMessagesMoved")
	},
	"ListMessageMoveTasks": func(x *xw, r map[string]interface{}) {
		for _, t := range asList(r["Results"]) {
			e := asMap(t)
			x.open("ListMessageMoveTasksResultEntry")
			for _, k := range []string{"TaskHandle", "Status", "SourceArn", "DestinationArn", "MaxNumberOfMessagesPerSecond",
				"ApproximateNumberOfMessagesMoved", "ApproximateNumberOfMessagesToMove", "FailureReason", "StartedTimestamp"} {
				x.opt(k, e, k)
			}
			x.end("ListMessageMoveTasksResultEntry")
		}
	},
	// no result element
	"DeleteQueue": nil, "SetQueueAttributes": nil, "PurgeQueue": nil, "DeleteMessage": nil, "ChangeMessageVisibility": nil,
	"AddPermission": nil, "RemovePermission": nil, "TagQueue": nil, "UntagQueue": nil,
}

const xmlHeader = `<?xml version="1.0"?>`

func queryOK(action string, result map[string]interface{}, requestID string) []byte {
	x := &xw{}
	x.b.WriteString(xmlHeader + `<` + action + `Response xmlns="` + sqsNS + `">`)
	if f := sqsResults[action]; f != nil {
		x.open(action + "Result")
		f(x, result)
		x.end(action + "Result")
	}
	x.open("ResponseMetadata")
	x.el("RequestId", requestID)
	x.end("ResponseMetadata")
	x.end(action + "Response")
	return []byte(x.b.String())
}

func queryError(e *queryErr, requestID string) []byte {
	typ := "Sender"
	if e.status >= 500 {
		typ = "Receiver"
	}
	return []byte(xmlHeader + `<ErrorResponse xmlns="` + sqsNS + `"><Error><Type>` + typ + `</Type><Code>` + xmlEscape(e.code) +
		`</Code><Message>` + xmlEscape(e.message) + `</Message><Detail/></Error><RequestId>` + requestID + `</RequestId></ErrorResponse>`)
}

func writeQueryError(w http.ResponseWriter, e *queryErr) {
	id := newUUID()
	w.Header().Set("x-amzn-RequestId", id)
	writeBody(w, e.status, "text/xml", queryError(e, id))
}

// ---- the request

var queuePathRe = regexp.MustCompile(`^/(\d{12})/([A-Za-z0-9_.-]{1,80})/?$`)

// sqsQueryParams: the query string and the form body together (the form wins).
func sqsQueryParams(q url.Values, form url.Values) url.Values {
	p := url.Values{}
	for k, v := range q {
		p[k] = v
	}
	for k, v := range form {
		p[k] = v
	}
	return p
}

// serveSQSQuery answers one SQS Query request through the engine's JSON API. It returns the status and whether the call
// counts as unsupported, for the ledger.
func (s *Server) serveSQSQuery(w http.ResponseWriter, r *http.Request, gen *generation, id identified, params url.Values) (int, bool) {
	action := id.Operation
	if full := params.Get("Action"); full != "" {
		action = full
	}
	body, known, qerr := sqsQueryToJSON(action, params)
	if !known {
		writeQueryError(w, &queryErr{http.StatusBadRequest, "InvalidAction", "The action or operation requested is invalid. Verify that the action is typed correctly."})
		return http.StatusBadRequest, true
	}
	if qerr != nil {
		writeQueryError(w, qerr)
		return qerr.status, false
	}
	// the Java v1 family leaves QueueUrl out of the form and posts to the queue's own path
	if _, wants := body["QueueUrl"]; !wants && hasQueueURL(action) {
		if m := queuePathRe.FindStringSubmatch(r.URL.Path); m != nil {
			body["QueueUrl"] = s.cfg.BaseURL + "/" + m[1] + "/" + m[2]
		}
	}
	for _, name := range sqsRequired[action] {
		if _, ok := body[jsonName(action, name)]; !ok {
			writeQueryError(w, &queryErr{http.StatusBadRequest, "MissingParameter", "The request must contain the parameter " + name + "."})
			return http.StatusBadRequest, false
		}
	}
	if entry, batch := sqsBatchEntries[action]; batch {
		if _, ok := body["Entries"]; !ok {
			writeQueryError(w, &queryErr{http.StatusBadRequest, "AWS.SimpleQueueService.EmptyBatchRequest", "There should be at least one " + entry + " in the request."})
			return http.StatusBadRequest, false
		}
	}
	raw, err := json.Marshal(body)
	if err != nil {
		writeQueryError(w, &queryErr{http.StatusBadRequest, "InvalidParameterValue", "the request cannot be translated"})
		return http.StatusBadRequest, false
	}
	req, _ := http.NewRequestWithContext(r.Context(), http.MethodPost, "https://127.0.0.1:"+strconv.Itoa(gen.port)+"/", bytes.NewReader(raw))
	req.Host = "127.0.0.1:" + strconv.Itoa(gen.port)
	req.Header.Set("Content-Type", "application/x-amz-json-1.0")
	req.Header.Set("X-Amz-Target", "AmazonSQS."+action)
	req.Header.Set("User-Agent", "rovara-aws-front")
	region := id.Region
	req.Header.Set("Authorization", syntheticAuthorization("sqs", region))
	resp, err := gen.client.Do(req)
	if err != nil {
		if r.Context().Err() != nil {
			return 499, false
		}
		log.Printf("the engine did not answer an sqs query request: %v", sanitizeErr(err))
		writeQueryError(w, &queryErr{http.StatusBadGateway, "ServiceUnavailable", "The local AWS emulator did not answer."})
		return http.StatusBadGateway, false
	}
	defer resp.Body.Close()
	if !s.querySlots.acquire(r.Context()) {
		return 499, false
	}
	defer s.querySlots.release()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, queryLimit+1))
	if len(data) > queryLimit {
		writeQueryError(w, &queryErr{http.StatusBadGateway, "ServiceUnavailable", "The answer is too large to translate."})
		return http.StatusBadGateway, false
	}
	rid := resp.Header.Get("x-amzn-requestid")
	if rid == "" {
		rid = newUUID()
	}
	w.Header().Set("x-amzn-RequestId", rid)
	unsupported := isUnsupported(resp.StatusCode, resp.Header.Get("x-amzn-errortype"), data)
	if resp.StatusCode >= 300 {
		e := jsonErrorToQuery(resp.StatusCode, resp.Header, data)
		if e.status == http.StatusNotFound {
			e.status = http.StatusBadRequest // SQS answers every client error in Query with 400
		}
		e.message = s.rw.internalAddr(e.message, gen.port)
		writeBody(w, e.status, "text/xml", queryError(e, rid))
		return e.status, unsupported
	}
	switch {
	case queueOps[action]:
		data = s.rw.queueURLsJSON(data)
		if s.sink != nil {
			data = hideTapQueues(data)
		}
	case action == "ReceiveMessage":
		data = s.rw.snsEnvelopes(data)
	}
	data = s.rw.internalAddrBytes(data, gen.port)
	var res map[string]interface{}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if len(bytes.TrimSpace(data)) > 0 {
		_ = dec.Decode(&res)
	}
	if res == nil {
		res = map[string]interface{}{}
	}
	writeBody(w, resp.StatusCode, "text/xml", queryOK(action, res, rid))
	return resp.StatusCode, false
}

// jsonName: the JSON member a Query member becomes in one operation.
func jsonName(action, q string) string {
	for _, f := range sqsSpecs[action] {
		if f.q == q {
			return f.j
		}
	}
	return q
}

// hasQueueURL: operations that address a queue.
func hasQueueURL(action string) bool {
	for _, f := range sqsSpecs[action] {
		if f.q == "QueueUrl" {
			return true
		}
	}
	return false
}
