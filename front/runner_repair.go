package main

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// repairPlumbing puts the hidden plumbing back as the front made it. It runs before every poll of the request queue (the role and its policies
// on every sweep tick, in repairRole): a queue attribute someone changed (DelaySeconds=900), a policy or redrive policy put on the queue, a deleted queue or
// bucket, a role whose policy was replaced, deleted or added to, is undone within one poll, and each repair is recorded as a security event.
// Code in the same engine can do it again; this keeps a single mistake or a one-time change from stopping every heavy function for the rest of
// the run (see the known limit in runner_engine.go, authentic).
func (r *runnerSys) repairPlumbing() {
	nm := r.names()
	fix := func(what string) { r.s.ledger.recordRepair(what) }

	// the request queue: present, and with its defaults
	qurl := r.requestURL()
	out, err := r.sqsCall("GetQueueUrl", map[string]interface{}{"QueueName": nm.req}, 10*time.Second)
	if err != nil {
		c, cerr := r.sqsCall("CreateQueue", map[string]interface{}{"QueueName": nm.req}, 10*time.Second)
		if cerr != nil {
			return
		}
		out = c
		fix("request-queue-recreated")
	}
	if u := strOf(out, "QueueUrl"); u != "" && u != qurl {
		r.provMu.Lock()
		r.reqURL = u
		r.provMu.Unlock()
		qurl = u
	}
	if attrs, err := r.sqsCall("GetQueueAttributes", map[string]interface{}{"QueueUrl": qurl, "AttributeNames": []string{"All"}}, 10*time.Second); err == nil {
		a := mapOf(attrs, "Attributes")
		drift := strOf(a, "Policy") != "" || strOf(a, "RedrivePolicy") != "" || strOf(a, "RedriveAllowPolicy") != ""
		for k, def := range map[string]string{"DelaySeconds": "0", "VisibilityTimeout": "30", "ReceiveMessageWaitTimeSeconds": "0"} {
			if v := strOf(a, k); v != "" && v != def {
				drift = true
			}
		}
		if drift {
			full := map[string]string{"DelaySeconds": "0", "VisibilityTimeout": "30", "ReceiveMessageWaitTimeSeconds": "0", "Policy": "", "RedrivePolicy": "", "RedriveAllowPolicy": ""}
			if _, err := r.sqsCall("SetQueueAttributes", map[string]interface{}{"QueueUrl": qurl, "Attributes": full}, 10*time.Second); err != nil {
				// an engine that refuses an empty policy still gets its numbers back
				r.sqsCall("SetQueueAttributes", map[string]interface{}{"QueueUrl": qurl, "Attributes": map[string]string{"DelaySeconds": "0", "VisibilityTimeout": "30", "ReceiveMessageWaitTimeSeconds": "0"}}, 10*time.Second)
			}
			fix("request-queue-attributes")
		}
	}
	// the payload bucket
	if st, _, _, err := r.call("s3", http.MethodHead, "/"+nm.bucket, nil, nil, 10*time.Second); err == nil && st == http.StatusNotFound {
		r.call("s3", http.MethodPut, "/"+nm.bucket, nil, nil, 10*time.Second)
		fix("payload-bucket-recreated")
	}
}

// repairRole looks after the stub's role: present, trusted by Lambda, with its one policy and nothing else. It writes only what is wrong: on an
// idle run it makes no write at all. The IAM answers are XML: the policy documents in them are read with the XML parser (whatever escaping the
// engine uses, &quot; or percent-encoding) and compared as documents, never searched as text.
func (r *runnerSys) repairRole() {
	nm := r.names()
	fix := func(what string) { r.s.ledger.recordRepair(what) }
	st, b, err := r.iamCall("GetRole", url.Values{"RoleName": {nm.role}})
	if err != nil {
		return // the engine is not answering: nothing to judge
	}
	if st == http.StatusNotFound {
		r.iamCall("CreateRole", url.Values{"RoleName": {nm.role}, "AssumeRolePolicyDocument": {stubTrust}})
		fix("stub-role-recreated")
	} else if st == http.StatusOK && !trustIsLambda(xmlText(b, "AssumeRolePolicyDocument")) {
		r.iamCall("UpdateAssumeRolePolicy", url.Values{"RoleName": {nm.role}, "PolicyDocument": {stubTrust}})
		fix("stub-role-trust")
	}
	st, b, err = r.iamCall("GetRolePolicy", url.Values{"RoleName": {nm.role}, "PolicyName": {"rendezvous"}})
	if err != nil {
		return
	}
	if st != http.StatusOK || !policyIsStub(xmlText(b, "PolicyDocument")) {
		r.iamCall("PutRolePolicy", url.Values{"RoleName": {nm.role}, "PolicyName": {"rendezvous"}, "PolicyDocument": {stubPolicy}})
		fix("stub-role-policy")
	}
	if _, b, err := r.iamCall("ListAttachedRolePolicies", url.Values{"RoleName": {nm.role}}); err == nil {
		for _, arn := range policyArnRe.FindAllStringSubmatch(string(b), 50) {
			r.iamCall("DetachRolePolicy", url.Values{"RoleName": {nm.role}, "PolicyArn": {arn[1]}})
			fix("stub-role-attached-policy")
		}
	}
	if _, b, err := r.iamCall("ListRolePolicies", url.Values{"RoleName": {nm.role}}); err == nil {
		for _, m := range policyNameRe.FindAllStringSubmatch(string(b), 50) {
			if m[1] != "rendezvous" {
				r.iamCall("DeleteRolePolicy", url.Values{"RoleName": {nm.role}, "PolicyName": {m[1]}})
				fix("stub-role-inline-policy")
			}
		}
	}
}

const stubTrust = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}`

// xmlText returns the text of the first element named name in an XML answer, entities decoded.
func xmlText(b []byte, name string) string {
	d := xml.NewDecoder(bytes.NewReader(b))
	for {
		t, err := d.Token()
		if err != nil {
			return ""
		}
		if se, ok := t.(xml.StartElement); ok && se.Name.Local == name {
			var s string
			if d.DecodeElement(&s, &se) != nil {
				return ""
			}
			return s
		}
	}
}

// policyDoc reads a policy document as the engine or AWS may hand it back: JSON text, or percent-encoded JSON text.
func policyDoc(s string) (map[string]interface{}, bool) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "%7B") || strings.HasPrefix(s, "%7b") {
		if d, err := url.QueryUnescape(s); err == nil {
			s = d
		}
	}
	var m map[string]interface{}
	if json.Unmarshal([]byte(s), &m) != nil {
		return nil, false
	}
	return m, true
}

func statements(m map[string]interface{}) []map[string]interface{} {
	var out []map[string]interface{}
	switch v := m["Statement"].(type) {
	case map[string]interface{}:
		out = append(out, v)
	case []interface{}:
		for _, x := range v {
			if sm, ok := x.(map[string]interface{}); ok {
				out = append(out, sm)
			}
		}
	}
	return out
}

// isOnly: v is the string want, or a list of exactly that string.
func isOnly(v interface{}, want string) bool {
	switch t := v.(type) {
	case string:
		return t == want
	case []interface{}:
		return len(t) == 1 && isOnly(t[0], want)
	}
	return false
}

// policyIsStub: the document allows everything and says nothing else (stubPolicy).
func policyIsStub(doc string) bool {
	m, ok := policyDoc(doc)
	if !ok {
		return false
	}
	st := statements(m)
	return len(st) == 1 && st[0]["Effect"] == "Allow" && isOnly(st[0]["Action"], "*") && isOnly(st[0]["Resource"], "*") && st[0]["Condition"] == nil
}

// trustIsLambda: the role is assumable by the Lambda service and by nothing else.
func trustIsLambda(doc string) bool {
	m, ok := policyDoc(doc)
	if !ok {
		return false
	}
	st := statements(m)
	if len(st) != 1 || st[0]["Effect"] != "Allow" || !isOnly(st[0]["Action"], "sts:AssumeRole") {
		return false
	}
	p, _ := st[0]["Principal"].(map[string]interface{})
	return len(p) == 1 && isOnly(p["Service"], "lambda.amazonaws.com")
}

// stubPolicy is the stub role's one policy: anything inside the engine (the engine checks the FUNCTION's role for what a mapping needs, and
// the stub runs as that role).
const stubPolicy = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`

var (
	policyArnRe  = regexp.MustCompile(`<PolicyArn>([^<]+)</PolicyArn>`)
	policyNameRe = regexp.MustCompile(`<member>([^<]+)</member>`)
)
