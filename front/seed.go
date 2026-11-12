package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Seed: the fork's SeedService document, applied through the engine's own APIs (signed with a made-up credential: the
// engine runs with signature checks off). Each step is reported; a failed step does not stop the rest. A DynamoDB table
// is waited for until it is ACTIVE (and so are its indexes) before its items are put or the step is reported done: the
// fork's tables are ACTIVE at once, the engine's take about 3 s as AWS's do.
//
//   { "region": "us-east-1",
//     "s3":             { "buckets": [ { "name", "versioning", "objects": [ { "key", "text" | "bodyBase64", "contentType" } ] } ] },
//     "dynamodb":       { "tables": [ { "request": {CreateTable}, "items": [ {Item} ] } ] },
//     "sqs":            { "queues": [ { "name", "attributes", "messages": [ "body" ] } ] },
//     "sns":            { "topics": [ { "name", "subscriptions": [ { "protocol", "endpoint" } ] } ] },
//     "secretsmanager": { "secrets": [ { "name", "value" } ] },
//     "ssm":            { "parameters": [ { "name", "value", "type" } ] },
//     "kms":            { "keys": [ { "alias", "description" } ] },
//     "events":         { "buses": [ "bus" ], "rules": [ { "name", "bus", "pattern", "schedule", "targets": [ {"Id","Arn"} ] } ] },
//     "calls":          [ { "service", "action", "request": {wire JSON} } ] }
//
// Report: {"steps":[{"service","action","name","ok"[,"error"]}],"ok":bool,"failed":n}; HTTP 200 when every step is ok, else 422.

const tableActiveTimeout = 60 * time.Second

type seedStep struct {
	Service, Action, Name string
	OK                    bool
	Err                   string
}

type seedRun struct {
	s      *Server
	region string
	steps  []seedStep
	failed int
}

func (r *seedRun) step(service, action, name string, f func() error) {
	st := seedStep{Service: service, Action: action, Name: name}
	if err := f(); err != nil {
		r.failed++
		st.Err = err.Error()
	} else {
		st.OK = true
	}
	r.steps = append(r.steps, st)
}

func (s *Server) applySeed(data []byte) (int, []byte) {
	var doc map[string]interface{}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		trimmed = []byte("{}")
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil || doc == nil || dec.More() {
		return http.StatusBadRequest, jsonError("the seed document is not valid JSON")
	}
	if _, _, err := s.engine.current(); err != nil {
		return http.StatusServiceUnavailable, jsonError("the engine is not ready")
	}
	region := s.cfg.Region
	if v, ok := doc["region"]; ok && v != nil {
		region = text(v, "")
	}
	run := &seedRun{s: s, region: region}

	for _, b := range list(at(doc, "s3", "buckets")) {
		bucket := asMap(b)
		name := text(bucket["name"], "")
		run.step("s3", "CreateBucket", name, func() error { return run.seedBucket(name, bucket) })
	}
	// Tables are created together and waited for together: each takes about 3 s to become ACTIVE, and the Cloud worker gives
	// a whole seed call 8 s, so a few tables one after another would not fit. The report still has one step per table.
	tables := list(at(doc, "dynamodb", "tables"))
	prepared := run.prepareTables(tables)
	for i, t := range tables {
		table := asMap(t)
		create := table["request"]
		tableName := text(asMap(create)["TableName"], "")
		run.step("dynamodb", "CreateTable", tableName, func() error {
			if prepared[i] != nil {
				return prepared[i]
			}
			return run.putItems(tableName, table)
		})
	}
	for _, q := range list(at(doc, "sqs", "queues")) {
		queue := asMap(q)
		name := text(queue["name"], "")
		run.step("sqs", "CreateQueue", name, func() error { return run.seedQueue(name, queue) })
	}
	for _, t := range list(at(doc, "sns", "topics")) {
		topic := asMap(t)
		name := text(topic["name"], "")
		run.step("sns", "CreateTopic", name, func() error { return run.seedTopic(name, topic) })
	}
	for _, sec := range list(at(doc, "secretsmanager", "secrets")) {
		secret := asMap(sec)
		name := text(secret["name"], "")
		run.step("secretsmanager", "CreateSecret", name, func() error {
			_, err := run.json11("secretsmanager", "secretsmanager.CreateSecret", map[string]interface{}{"Name": name, "SecretString": text(secret["value"], ""),
				"ClientRequestToken": newUUID()})
			return err
		})
	}
	for _, p := range list(at(doc, "ssm", "parameters")) {
		param := asMap(p)
		name := text(param["name"], "")
		run.step("ssm", "PutParameter", name, func() error {
			_, err := run.json11("ssm", "AmazonSSM.PutParameter", map[string]interface{}{"Name": name, "Value": text(param["value"], ""),
				"Type": text(param["type"], "String"), "Overwrite": true})
			return err
		})
	}
	for _, k := range list(at(doc, "kms", "keys")) {
		key := asMap(k)
		label := text(key["alias"], text(key["description"], "key"))
		run.step("kms", "CreateKey", label, func() error { return run.seedKey(key) })
	}
	for _, b := range list(at(doc, "events", "buses")) {
		bus := text(b, "")
		run.step("events", "CreateEventBus", bus, func() error {
			_, err := run.json11("events", "AWSEvents.CreateEventBus", map[string]interface{}{"Name": bus})
			return err
		})
	}
	for _, rl := range list(at(doc, "events", "rules")) {
		rule := asMap(rl)
		name := text(rule["name"], "")
		run.step("events", "PutRule", name, func() error { return run.seedRule(name, rule) })
	}
	for _, c := range list(doc["calls"]) {
		call := asMap(c)
		svc, action := text(call["service"], ""), text(call["action"], "")
		run.step(svc, action, "", func() error { return run.seedCall(svc, action, call["request"]) })
	}

	var b strings.Builder
	b.WriteString(`{"steps":[`)
	for i, st := range run.steps {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"service":"` + jsonEscape(st.Service) + `","action":"` + jsonEscape(st.Action) + `","name":"` + jsonEscape(st.Name) +
			`","ok":` + strconv.FormatBool(st.OK))
		if !st.OK {
			b.WriteString(`,"error":"` + jsonEscape(st.Err) + `"`)
		}
		b.WriteByte('}')
	}
	b.WriteString(`],"ok":` + strconv.FormatBool(run.failed == 0) + `,"failed":` + strconv.Itoa(run.failed) + `}`)
	status := http.StatusOK
	if run.failed > 0 {
		status = http.StatusUnprocessableEntity
	}
	return status, []byte(b.String())
}

// ---- JSON document helpers (the fork reads with Jackson's path().asText(): a missing value is the default)

func at(m map[string]interface{}, keys ...string) interface{} {
	var cur interface{} = m
	for _, k := range keys {
		cur = asMap(cur)[k]
	}
	return cur
}

func asMap(v interface{}) map[string]interface{} {
	if m, ok := v.(map[string]interface{}); ok {
		return m
	}
	return nil
}

func list(v interface{}) []interface{} {
	if a, ok := v.([]interface{}); ok {
		return a
	}
	return nil
}

// text is Jackson's asText(default): strings as they are, numbers and booleans as written, missing or null as def.
func text(v interface{}, def string) string {
	switch t := v.(type) {
	case nil:
		return def
	case string:
		return t
	case json.Number:
		return t.String()
	case bool:
		return strconv.FormatBool(t)
	default:
		b, _ := json.Marshal(t)
		return string(b)
	}
}

// ---- engine calls

type engineResponse struct {
	Status int
	Header http.Header
	Body   []byte
}

// engineDo makes one signed request to the current engine.
func (r *seedRun) engineDo(service *service, method, path string, headers map[string]string, body []byte) (*engineResponse, error) {
	gen, _, err := r.s.engine.current()
	if err != nil {
		return nil, fmt.Errorf("the engine is not ready")
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, "https://127.0.0.1:"+strconv.Itoa(gen.port)+path, rd)
	if err != nil {
		return nil, err
	}
	req.Host = "127.0.0.1:" + strconv.Itoa(gen.port)
	req.Header.Set("Authorization", syntheticAuthorization(service.SigningName, r.region))
	req.Header.Set("User-Agent", "rovara-aws-front-seed")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := gen.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("the engine did not answer")
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	return &engineResponse{resp.StatusCode, resp.Header, b}, nil
}

var (
	xmlCodeRe = regexp.MustCompile(`<Code>([^<]*)</Code>`)
	xmlMsgRe  = regexp.MustCompile(`<Message>([^<]*)</Message>`)
)

// failure renders a non-2xx answer as the step's error text: the action, the status, the error code and message.
func failure(action string, resp *engineResponse) error {
	code, msg := "", ""
	var j map[string]interface{}
	if json.Unmarshal(resp.Body, &j) == nil {
		code = text(j["__type"], text(j["code"], ""))
		if i := strings.Index(code, "#"); i >= 0 {
			code = code[i+1:]
		}
		msg = text(j["message"], text(j["Message"], ""))
	} else if m := xmlCodeRe.FindSubmatch(resp.Body); m != nil {
		code = string(m[1])
		if mm := xmlMsgRe.FindSubmatch(resp.Body); mm != nil {
			msg = string(mm[1])
		}
	}
	if len(msg) > 300 {
		msg = msg[:300]
	}
	return fmt.Errorf("%s answered HTTP %d: %s: %s", action, resp.Status, code, msg)
}

// jsonCall: an RPC call (X-Amz-Target) with a JSON body; contentVersion is "1.0" or "1.1". The answer is decoded.
func (r *seedRun) jsonCall(svcKey, target, contentVersion string, request interface{}) (map[string]interface{}, error) {
	svc := byKey[svcKey]
	body, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	action := target[strings.Index(target, ".")+1:]
	resp, err := r.engineDo(svc, http.MethodPost, "/", map[string]string{
		"X-Amz-Target": target, "Content-Type": "application/x-amz-json-" + contentVersion}, body)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", action, err)
	}
	if resp.Status >= 400 {
		return nil, failure(action, resp)
	}
	var out map[string]interface{}
	dec := json.NewDecoder(bytes.NewReader(resp.Body))
	dec.UseNumber()
	_ = dec.Decode(&out)
	return out, nil
}

func (r *seedRun) json11(svcKey, target string, request interface{}) (map[string]interface{}, error) {
	return r.jsonCall(svcKey, target, "1.1", request)
}

func (r *seedRun) json10(svcKey, target string, request interface{}) (map[string]interface{}, error) {
	return r.jsonCall(svcKey, target, "1.0", request)
}

// ---- the steps

func s3PathEscape(key string) string {
	parts := strings.Split(key, "/")
	for i, p := range parts {
		parts[i] = url.PathEscape(p)
	}
	return strings.Join(parts, "/")
}

func (r *seedRun) s3Do(method, path string, headers map[string]string, body []byte, action string) error {
	resp, err := r.engineDo(byKey["s3"], method, path, headers, body)
	if err != nil {
		return fmt.Errorf("%s: %v", action, err)
	}
	if resp.Status >= 300 {
		return failure(action, resp)
	}
	return nil
}

const s3NS = "http://s3.amazonaws.com/doc/2006-03-01/"

func (r *seedRun) seedBucket(name string, bucket map[string]interface{}) error {
	var body []byte
	if r.region != "us-east-1" {
		body = []byte(`<CreateBucketConfiguration xmlns="` + s3NS + `"><LocationConstraint>` + xmlEscape(r.region) + `</LocationConstraint></CreateBucketConfiguration>`)
	}
	if err := r.s3Do(http.MethodPut, "/"+s3PathEscape(name), nil, body, "CreateBucket"); err != nil {
		return err
	}
	if v := bucket["versioning"]; v != nil {
		xml := `<VersioningConfiguration xmlns="` + s3NS + `"><Status>` + xmlEscape(text(v, "")) + `</Status></VersioningConfiguration>`
		if err := r.s3Do(http.MethodPut, "/"+s3PathEscape(name)+"?versioning", nil, []byte(xml), "PutBucketVersioning"); err != nil {
			return err
		}
	}
	for _, o := range list(bucket["objects"]) {
		obj := asMap(o)
		var data []byte
		if enc := obj["bodyBase64"]; enc != nil {
			var err error
			data, err = base64.StdEncoding.DecodeString(text(enc, ""))
			if err != nil {
				return fmt.Errorf("PutObject: bodyBase64 is not base64")
			}
		} else {
			data = []byte(text(obj["text"], ""))
		}
		if data == nil {
			data = []byte{}
		}
		headers := map[string]string{"Content-Type": text(obj["contentType"], "application/octet-stream")}
		if err := r.s3Do(http.MethodPut, "/"+s3PathEscape(name)+"/"+s3PathEscape(text(obj["key"], "")), headers, data, "PutObject"); err != nil {
			return err
		}
	}
	return nil
}

// waitTableActive polls DescribeTable until the table and every index are ACTIVE.
func (r *seedRun) waitTableActive(table string) error {
	deadline := time.Now().Add(tableActiveTimeout)
	for {
		out, err := r.json10("dynamodb", "DynamoDB_20120810.DescribeTable", map[string]interface{}{"TableName": table})
		if err != nil {
			return err
		}
		desc := asMap(out["Table"])
		active := text(desc["TableStatus"], "") == "ACTIVE"
		for _, idx := range list(desc["GlobalSecondaryIndexes"]) {
			if text(asMap(idx)["IndexStatus"], "ACTIVE") != "ACTIVE" {
				active = false
			}
		}
		if active {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the table %s was not ACTIVE within %d s", table, int(tableActiveTimeout.Seconds()))
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// prepareTables creates every table of the document at once and waits until each is ACTIVE; the error of table i is at i.
func (r *seedRun) prepareTables(tables []interface{}) []error {
	errs := make([]error, len(tables))
	var wg sync.WaitGroup
	for i, t := range tables {
		wg.Add(1)
		go func(i int, table map[string]interface{}) {
			defer wg.Done()
			create := table["request"]
			if _, err := r.json10("dynamodb", "DynamoDB_20120810.CreateTable", create); err != nil {
				errs[i] = err
				return
			}
			errs[i] = r.waitTableActive(text(asMap(create)["TableName"], ""))
		}(i, asMap(t))
	}
	wg.Wait()
	return errs
}

func (r *seedRun) putItems(name string, table map[string]interface{}) error {
	for _, item := range list(table["items"]) {
		if _, err := r.json10("dynamodb", "DynamoDB_20120810.PutItem", map[string]interface{}{"TableName": name, "Item": item}); err != nil {
			return err
		}
	}
	return nil
}

func (r *seedRun) seedQueue(name string, queue map[string]interface{}) error {
	req := map[string]interface{}{"QueueName": name}
	if a, ok := queue["attributes"]; ok {
		req["Attributes"] = a
	}
	created, err := r.json10("sqs", "AmazonSQS.CreateQueue", req)
	if err != nil {
		return err
	}
	for _, m := range list(queue["messages"]) {
		if _, err := r.json10("sqs", "AmazonSQS.SendMessage", map[string]interface{}{"QueueUrl": text(created["QueueUrl"], ""), "MessageBody": text(m, "")}); err != nil {
			return err
		}
	}
	return nil
}

// queryCall: an SNS call. The engine speaks the Query protocol for SNS only; the answer is the raw XML.
func (r *seedRun) queryCall(svcKey, action string, params url.Values) ([]byte, error) {
	svc := byKey[svcKey]
	params.Set("Action", action)
	if params.Get("Version") == "" {
		params.Set("Version", map[string]string{"sns": "2010-03-31"}[svcKey])
	}
	resp, err := r.engineDo(svc, http.MethodPost, "/", map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, []byte(params.Encode()))
	if err != nil {
		return nil, fmt.Errorf("%s: %v", action, err)
	}
	if resp.Status >= 400 {
		return nil, failure(action, resp)
	}
	return resp.Body, nil
}

var topicArnRe = regexp.MustCompile(`<TopicArn>([^<]*)</TopicArn>`)

func (r *seedRun) seedTopic(name string, topic map[string]interface{}) error {
	out, err := r.queryCall("sns", "CreateTopic", url.Values{"Name": {name}})
	if err != nil {
		return err
	}
	m := topicArnRe.FindSubmatch(out)
	if m == nil {
		return fmt.Errorf("CreateTopic answered no TopicArn")
	}
	for _, s := range list(topic["subscriptions"]) {
		sub := asMap(s)
		if _, err := r.queryCall("sns", "Subscribe", url.Values{"TopicArn": {string(m[1])}, "Protocol": {text(sub["protocol"], "")}, "Endpoint": {text(sub["endpoint"], "")}}); err != nil {
			return err
		}
	}
	return nil
}

func (r *seedRun) seedKey(key map[string]interface{}) error {
	req := map[string]interface{}{}
	if d := key["description"]; d != nil {
		req["Description"] = text(d, "")
	}
	created, err := r.json11("kms", "TrentService.CreateKey", req)
	if err != nil {
		return err
	}
	if a := key["alias"]; a != nil {
		_, err := r.json11("kms", "TrentService.CreateAlias", map[string]interface{}{"AliasName": text(a, ""),
			"TargetKeyId": text(asMap(created["KeyMetadata"])["KeyId"], "")})
		return err
	}
	return nil
}

func (r *seedRun) seedRule(name string, rule map[string]interface{}) error {
	put := map[string]interface{}{"Name": name}
	if b := rule["bus"]; b != nil {
		put["EventBusName"] = text(b, "")
	}
	if p, ok := rule["pattern"]; ok {
		if s, isStr := p.(string); isStr {
			put["EventPattern"] = s
		} else {
			put["EventPattern"] = text(p, "")
		}
	}
	if sc := rule["schedule"]; sc != nil {
		put["ScheduleExpression"] = text(sc, "")
	}
	if _, err := r.json11("events", "AWSEvents.PutRule", put); err != nil {
		return err
	}
	if targets, ok := rule["targets"]; ok {
		pt := map[string]interface{}{"Rule": name, "Targets": targets}
		if b := rule["bus"]; b != nil {
			pt["EventBusName"] = text(b, "")
		}
		if _, err := r.json11("events", "AWSEvents.PutTargets", pt); err != nil {
			return err
		}
	}
	return nil
}

// rpcCalls: the services a "calls" step can name, with their target prefix and JSON version.
var rpcCalls = map[string]struct{ prefix, version string }{
	"dynamodb":       {"DynamoDB_20120810.", "1.0"},
	"sqs":            {"AmazonSQS.", "1.0"},
	"kms":            {"TrentService.", "1.1"},
	"ssm":            {"AmazonSSM.", "1.1"},
	"secretsmanager": {"secretsmanager.", "1.1"},
	"events":         {"AWSEvents.", "1.1"},
}

func (r *seedRun) seedCall(svc, action string, request interface{}) error {
	if request == nil {
		request = map[string]interface{}{}
	}
	if svc == "sns" {
		params := url.Values{}
		flattenQuery("", request, params)
		_, err := r.queryCall("sns", action, params)
		return err
	}
	rpc, ok := rpcCalls[svc]
	if !ok {
		return fmt.Errorf("seed calls support dynamodb, sqs, sns, kms, ssm, secretsmanager and events; got %s", svc)
	}
	// Secrets Manager's raw API wants a ClientRequestToken on these calls; the SDKs add one, so the front does.
	if m := asMap(request); svc == "secretsmanager" && m != nil && m["ClientRequestToken"] == nil &&
		(action == "CreateSecret" || action == "PutSecretValue" || action == "RotateSecret" || action == "UpdateSecret") {
		m["ClientRequestToken"] = newUUID()
	}
	_, err := r.jsonCall(svc, rpc.prefix+action, rpc.version, request)
	return err
}

// flattenQuery turns a wire-JSON request into Query-protocol parameters: lists are Name.member.N, the SNS map members
// (Attributes, MessageAttributes) are Name.entry.N.key / .value (MessageAttributes: .Name / .Value.<field>), other
// objects nest with dots.
func flattenQuery(prefix string, v interface{}, out url.Values) {
	join := func(k string) string {
		if prefix == "" {
			return k
		}
		return prefix + "." + k
	}
	switch t := v.(type) {
	case map[string]interface{}:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			val := t[k]
			if (k == "Attributes" || k == "MessageAttributes" || k == "Tags") && asMap(val) != nil && prefix == "" {
				m := asMap(val)
				names := make([]string, 0, len(m))
				for n := range m {
					names = append(names, n)
				}
				sort.Strings(names)
				for i, n := range names {
					e := k + ".entry." + strconv.Itoa(i+1)
					if k == "MessageAttributes" {
						out.Set(e+".Name", n)
						flattenQuery(e+".Value", m[n], out)
					} else {
						out.Set(e+".key", n)
						out.Set(e+".value", text(m[n], ""))
					}
				}
				continue
			}
			flattenQuery(join(k), val, out)
		}
	case []interface{}:
		for i, e := range t {
			flattenQuery(prefix+".member."+strconv.Itoa(i+1), e, out)
		}
	case nil:
	default:
		if prefix != "" {
			out.Set(prefix, text(t, ""))
		}
	}
}
