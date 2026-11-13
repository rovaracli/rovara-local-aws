package main

import (
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// The reference sweeper. The guard keeps a customer's calls through the front from naming the hidden plumbing, but a reference can still
// get in by a path nobody thought of, and code that runs in the same engine reaches every service in-process, past the front. So on the
// dispatcher's poll the front looks, over loopback, at everything that can point a source of messages at the plumbing, or the plumbing at
// something else, and removes what it finds. A reference is dealt with EVERY time it is found (the front remembers nothing: the same call that
// put it there can put it there again), and each removal is recorded in the ledger as a security event (service "rovara", operation
// security:<kind>). Every listing is paged through, up to a bound.
//
// Kinds: Lambda event source mappings (and their destinations), Lambda event invoke configs (destinations), EventBridge rule targets (every bus),
// SNS subscriptions, S3 bucket notifications, EventBridge Scheduler schedules, EventBridge Pipes, SQS redrive policies (a dead-letter queue that
// is the plumbing), Step Functions state machines that name it, API Gateway (v2) integrations that name it or that read the engine's own
// function-code bucket.
//
// This is a safety net against mistakes and blind references, not a boundary: code in the same run can put a reference back a moment after the
// sweep. That is the known limit (see authentic in runner_engine.go).

const defaultSweepRefsEvery = 5 * time.Second

const (
	sweepMaxPages = 20  // pages of any one listing
	sweepMaxItems = 300 // items looked at of any one kind
)

func (r *runnerSys) engineJSON(service, target, ctype string, req interface{}) (map[string]interface{}, bool) {
	if m, ok := req.(map[string]interface{}); ok {
		for _, k := range []string{"NextToken", "nextToken"} {
			if v, has := m[k]; has && v == "" {
				delete(m, k) // the first page of a listing carries no token (an engine may refuse an empty one)
			}
		}
	}
	body, _ := json.Marshal(req)
	st, b, _, err := r.call(service, http.MethodPost, "/", map[string]string{"X-Amz-Target": target, "Content-Type": ctype}, body, 10*time.Second)
	if err != nil || st >= 300 {
		return nil, false
	}
	var out map[string]interface{}
	json.Unmarshal(b, &out)
	return out, true
}

func (r *runnerSys) restJSON(service, method, path string, req interface{}) (int, map[string]interface{}) {
	var body []byte
	if req != nil {
		body, _ = json.Marshal(req)
	}
	hdr := map[string]string{}
	if body != nil {
		hdr["Content-Type"] = "application/json"
	}
	st, b, _, err := r.call(service, method, path, hdr, body, 10*time.Second)
	if err != nil {
		return 0, nil
	}
	var out map[string]interface{}
	json.Unmarshal(b, &out)
	return st, out
}

func strOf(m map[string]interface{}, k string) string {
	s, _ := m[k].(string)
	return s
}

func mapOf(m map[string]interface{}, k string) map[string]interface{} {
	x, _ := m[k].(map[string]interface{})
	return x
}

// namesHidden: any string of the document names the plumbing (decoded: escapes, nested documents).
func namesHidden(v interface{}) bool {
	b, err := json.Marshal(v)
	if err != nil {
		return false
	}
	return jsonHasHidden(b, nil)
}

// functionCodeBucketRe: the engine's own function-code buckets (virtual-host and path style), matched by host, never by a substring: a
// customer's https://api.example.com/awslambda-proxy/nightly-tasks.json is not one.
var functionCodeBucketRe = regexp.MustCompile(`(?i)^https?://(?:awslambda-[a-z0-9-]+-(?:tasks|layers)\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com|s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com/awslambda-[a-z0-9-]+-(?:tasks|layers))(?:[/:?#]|$)`)

// hiddenURI: a URI that names the plumbing, or reads the engine's own function-code bucket (which holds the stub's package).
func hiddenURI(u string) bool {
	d := unescapeAll(u)
	return hiddenRef(d) || functionCodeBucketRe.MatchString(strings.TrimSpace(d))
}

// The sweep is a queue of small units of work (one listing, one bus, one rule, one function ...), run a tick at a time under a budget of calls
// and of time, so that a run with many buses and rules is swept over several ticks instead of stalling one; the queue is kept between ticks,
// and when it is empty the next tick starts a new cycle. It runs in its own goroutine (refsLoop), never on the path that serves heavy-function
// requests.
const (
	sweepTickCalls = 300             // engine calls a tick may start (a unit in progress is finished: at most sweepMaxPages more)
	sweepTickTime  = 3 * time.Second // and the time it may take
)

type sweepUnit func(sw *sweepRun)

// sweepRun is one tick's view of the work.
type sweepRun struct {
	r *runnerSys
	n int // references removed in this tick
}

func (sw *sweepRun) rec(kind, detail string) {
	sw.n++
	sw.r.s.ledger.recordSecurity(kind, detail)
}

func (sw *sweepRun) enqueue(u sweepUnit) { sw.r.swq = append(sw.r.swq, u) }

// sweepRefs runs a whole cycle with no budget (a test, or a caller that wants everything looked at now). It returns how many references it removed.
func (r *runnerSys) sweepRefs() int {
	total := 0
	for i := 0; i < 100000; i++ {
		n, done := r.sweepTick(1<<30, time.Hour)
		total += n
		if done {
			break
		}
	}
	return total
}

// sweepTick works through the queue until the budget is used up. done says the cycle is complete (the queue is empty).
func (r *runnerSys) sweepTick(maxCalls int, maxTime time.Duration) (removed int, done bool) {
	r.sweepRun.Lock()
	defer r.sweepRun.Unlock()
	if len(r.swq) == 0 {
		r.swq = r.seedSweep()
	}
	sw := &sweepRun{r: r}
	start, calls0 := time.Now(), r.callN.Load()
	for len(r.swq) > 0 && int(r.callN.Load()-calls0) < maxCalls && time.Since(start) < maxTime && r.ctx.Err() == nil {
		u := r.swq[0]
		r.swq = r.swq[1:]
		u(sw)
	}
	return sw.n, len(r.swq) == 0
}

// refsLoop is the sweeper's own goroutine: a tick every refsEvery, and the stub role looked after on each.
func (r *runnerSys) refsLoop() {
	t := time.NewTicker(r.refsEvery)
	defer t.Stop()
	for {
		select {
		case <-r.ctx.Done():
			return
		case <-t.C:
			if _, _, err := r.s.engine.current(); err != nil {
				continue
			}
			r.repairRole()
			r.sweepTick(sweepTickCalls, sweepTickTime)
		}
	}
}

func pageOf(r *runnerSys, fetch func(token string) (items []map[string]interface{}, next string, ok bool), each func(m map[string]interface{})) {
	token, seen := "", 0
	for i := 0; i < sweepMaxPages && seen < sweepMaxItems; i++ {
		items, next, ok := fetch(token)
		if !ok {
			return
		}
		for _, m := range items {
			seen++
			if seen > sweepMaxItems {
				return
			}
			each(m)
		}
		if next == "" || next == token {
			return
		}
		token = next
	}
}

func itemsOf(out map[string]interface{}, key string) []map[string]interface{} {
	var l []map[string]interface{}
	for _, x := range asList(out[key]) {
		if m, ok := x.(map[string]interface{}); ok {
			l = append(l, m)
		}
	}
	return l
}

func qs(base string, kv ...string) string {
	v := url.Values{}
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] != "" {
			v.Set(kv[i], kv[i+1])
		}
	}
	if len(v) == 0 {
		return base
	}
	return base + "?" + v.Encode()
}

// seedSweep makes the units of a new cycle, one per kind; a unit that finds more to look at (a bus, a rule, a function) queues it.
func (r *runnerSys) seedSweep() []sweepUnit {
	return []sweepUnit{
		// Lambda event source mappings, and the destinations they carry
		func(sw *sweepRun) {
			pageOf(r, func(tok string) ([]map[string]interface{}, string, bool) {
				st, out := r.restJSON("lambda", http.MethodGet, qs("/2015-03-31/event-source-mappings/", "MaxItems", "50", "Marker", tok), nil)
				return itemsOf(out, "EventSourceMappings"), strOf(out, "NextMarker"), st == 200
			}, func(m map[string]interface{}) {
				uuid, state := strOf(m, "UUID"), strOf(m, "State")
				if state == "Deleting" || state == "Deleted" {
					return // already on its way out
				}
				switch {
				case hiddenQueueURL(strOf(m, "EventSourceArn")) || namesHidden(m["EventSourceArn"]):
					r.call("lambda", http.MethodDelete, "/2015-03-31/event-source-mappings/"+url.PathEscape(uuid), nil, nil, 10*time.Second)
					sw.rec("event-source-mapping", uuid)
				case namesHidden(m["DestinationConfig"]):
					r.restJSON("lambda", http.MethodPut, "/2015-03-31/event-source-mappings/"+url.PathEscape(uuid), map[string]interface{}{"DestinationConfig": map[string]interface{}{}})
					sw.rec("lambda-destination", uuid)
				}
			})
		},
		// Lambda event invoke configs (destinations of asynchronous calls): one unit per function
		func(sw *sweepRun) {
			pageOf(r, func(tok string) ([]map[string]interface{}, string, bool) {
				st, out := r.restJSON("lambda", http.MethodGet, qs("/2015-03-31/functions/", "MaxItems", "50", "Marker", tok), nil)
				return itemsOf(out, "Functions"), strOf(out, "NextMarker"), st == 200
			}, func(m map[string]interface{}) {
				fn := strOf(m, "FunctionName")
				sw.enqueue(func(sw *sweepRun) {
					path := "/2019-09-25/functions/" + url.PathEscape(fn) + "/event-invoke-config"
					if st, cfg := r.restJSON("lambda", http.MethodGet, path, nil); st == 200 && namesHidden(cfg["DestinationConfig"]) {
						r.call("lambda", http.MethodDelete, path, nil, nil, 10*time.Second)
						sw.rec("lambda-destination", fn)
					}
				})
			})
		},
		// EventBridge targets: one unit per bus, per rule
		func(sw *sweepRun) {
			var buses []string
			pageOf(r, func(tok string) ([]map[string]interface{}, string, bool) {
				out, ok := r.engineJSON("events", "AWSEvents.ListEventBuses", "application/x-amz-json-1.1", map[string]interface{}{"NextToken": tok})
				return itemsOf(out, "EventBuses"), strOf(out, "NextToken"), ok
			}, func(m map[string]interface{}) { buses = append(buses, strOf(m, "Name")) })
			if len(buses) == 0 {
				buses = []string{"default"}
			}
			for _, bus := range buses {
				bus := bus
				sw.enqueue(func(sw *sweepRun) {
					pageOf(r, func(tok string) ([]map[string]interface{}, string, bool) {
						out, ok := r.engineJSON("events", "AWSEvents.ListRules", "application/x-amz-json-1.1", map[string]interface{}{"EventBusName": bus, "Limit": 100, "NextToken": tok})
						return itemsOf(out, "Rules"), strOf(out, "NextToken"), ok
					}, func(m map[string]interface{}) {
						rule := strOf(m, "Name")
						sw.enqueue(func(sw *sweepRun) {
							pageOf(r, func(tok string) ([]map[string]interface{}, string, bool) {
								out, ok := r.engineJSON("events", "AWSEvents.ListTargetsByRule", "application/x-amz-json-1.1", map[string]interface{}{"Rule": rule, "EventBusName": bus, "NextToken": tok})
								return itemsOf(out, "Targets"), strOf(out, "NextToken"), ok
							}, func(t map[string]interface{}) {
								if namesHidden(t) {
									r.engineJSON("events", "AWSEvents.RemoveTargets", "application/x-amz-json-1.1", map[string]interface{}{"Rule": rule, "EventBusName": bus, "Ids": []string{strOf(t, "Id")}, "Force": true})
									sw.rec("eventbridge-target", rule+"/"+strOf(t, "Id"))
								}
							})
						})
					})
				})
			}
		},
		// SNS subscriptions
		func(sw *sweepRun) {
			token := ""
			for i := 0; i < sweepMaxPages; i++ {
				form := url.Values{"Action": {"ListSubscriptions"}, "Version": {"2010-03-31"}}
				if token != "" {
					form.Set("NextToken", token)
				}
				st, b, _, err := r.call("sns", http.MethodPost, "/", map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, []byte(form.Encode()), 10*time.Second)
				if err != nil || st != 200 {
					return
				}
				for _, m := range sweepMemberRe.FindAllString(string(b), sweepMaxItems) {
					ep := xmlField(m, "Endpoint")
					if hiddenQueueURL(ep) || hiddenRef(unescapeAll(ep)) {
						sub := xmlField(m, "SubscriptionArn")
						u := url.Values{"Action": {"Unsubscribe"}, "Version": {"2010-03-31"}, "SubscriptionArn": {sub}}
						r.call("sns", http.MethodPost, "/", map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, []byte(u.Encode()), 10*time.Second)
						sw.rec("sns-subscription", sub)
					}
				}
				next := xmlField(string(b), "NextToken")
				if next == "" || next == token {
					return
				}
				token = next
			}
		},
		// S3 bucket notifications: one unit per bucket
		func(sw *sweepRun) {
			st, b, _, err := r.call("s3", http.MethodGet, "/", nil, nil, 10*time.Second)
			if err != nil || st != 200 {
				return
			}
			for _, m := range sweepBucketRe.FindAllStringSubmatch(string(b), sweepMaxItems) {
				bucket := m[1]
				if strings.HasPrefix(bucket, hiddenPrefix) {
					continue
				}
				sw.enqueue(func(sw *sweepRun) {
					st, nb, _, err := r.call("s3", http.MethodGet, "/"+url.PathEscape(bucket)+"?notification", nil, nil, 10*time.Second)
					if err != nil || st != 200 {
						return
					}
					if found, perr := xmlHasHidden(nb); found || perr != nil {
						empty := `<NotificationConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"></NotificationConfiguration>`
						r.call("s3", http.MethodPut, "/"+url.PathEscape(bucket)+"?notification", map[string]string{"Content-Type": "application/xml"}, []byte(empty), 10*time.Second)
						sw.rec("s3-notification", bucket)
					}
				})
			}
		},
		// EventBridge Scheduler
		func(sw *sweepRun) {
			pageOf(r, func(tok string) ([]map[string]interface{}, string, bool) {
				st, out := r.restJSON("scheduler", http.MethodGet, qs("/schedules", "MaxResults", "100", "NextToken", tok), nil)
				return itemsOf(out, "Schedules"), strOf(out, "NextToken"), st == 200
			}, func(m map[string]interface{}) {
				if namesHidden(m["Target"]) {
					r.call("scheduler", http.MethodDelete, qs("/schedules/"+url.PathEscape(strOf(m, "Name")), "groupName", strOf(m, "GroupName")), nil, nil, 10*time.Second)
					sw.rec("scheduler-schedule", strOf(m, "Name"))
				}
			})
		},
		// EventBridge Pipes
		func(sw *sweepRun) {
			pageOf(r, func(tok string) ([]map[string]interface{}, string, bool) {
				st, out := r.restJSON("pipes", http.MethodGet, qs("/v1/pipes", "Limit", "100", "NextToken", tok), nil)
				return itemsOf(out, "Pipes"), strOf(out, "NextToken"), st == 200
			}, func(m map[string]interface{}) {
				if namesHidden(m["Source"]) || namesHidden(m["Target"]) {
					r.call("pipes", http.MethodDelete, "/v1/pipes/"+url.PathEscape(strOf(m, "Name")), nil, nil, 10*time.Second)
					sw.rec("pipe", strOf(m, "Name"))
				}
			})
		},
		// SQS redrive: a queue whose dead-letter target is the plumbing; one unit per queue
		func(sw *sweepRun) {
			pageOf(r, func(tok string) ([]map[string]interface{}, string, bool) {
				lq := map[string]interface{}{"MaxResults": 1000}
				if tok != "" {
					lq["NextToken"] = tok
				}
				out, err := r.sqsCall("ListQueues", lq, 10*time.Second)
				var l []map[string]interface{}
				for _, u := range asList(out["QueueUrls"]) {
					l = append(l, map[string]interface{}{"url": u})
				}
				return l, strOf(out, "NextToken"), err == nil
			}, func(m map[string]interface{}) {
				qu := strOf(m, "url")
				if qu == "" || hiddenQueueURL(qu) {
					return
				}
				sw.enqueue(func(sw *sweepRun) {
					attrs, err := r.sqsCall("GetQueueAttributes", map[string]interface{}{"QueueUrl": qu, "AttributeNames": []string{"RedrivePolicy", "RedriveAllowPolicy"}}, 10*time.Second)
					if err == nil && namesHidden(mapOf(attrs, "Attributes")) {
						r.sqsCall("SetQueueAttributes", map[string]interface{}{"QueueUrl": qu, "Attributes": map[string]string{"RedrivePolicy": "", "RedriveAllowPolicy": ""}}, 10*time.Second)
						sw.rec("sqs-redrive", queueNameOf(qu))
					}
				})
			})
		},
		// Step Functions state machines that name the plumbing; one unit per machine
		func(sw *sweepRun) {
			pageOf(r, func(tok string) ([]map[string]interface{}, string, bool) {
				out, ok := r.engineJSON("states", "AWSStepFunctions.ListStateMachines", "application/x-amz-json-1.0", map[string]interface{}{"maxResults": 100, "nextToken": tok})
				return itemsOf(out, "stateMachines"), strOf(out, "nextToken"), ok
			}, func(m map[string]interface{}) {
				arn := strOf(m, "stateMachineArn")
				sw.enqueue(func(sw *sweepRun) {
					d, ok := r.engineJSON("states", "AWSStepFunctions.DescribeStateMachine", "application/x-amz-json-1.0", map[string]interface{}{"stateMachineArn": arn})
					if ok && strOf(d, "status") != "DELETING" && namesHidden(d) {
						r.engineJSON("states", "AWSStepFunctions.DeleteStateMachine", "application/x-amz-json-1.0", map[string]interface{}{"stateMachineArn": arn})
						sw.rec("state-machine", arn)
					}
				})
			})
		},
		// API Gateway (v2) integrations that name the plumbing or read the function-code bucket; one unit per API
		func(sw *sweepRun) {
			pageOf(r, func(tok string) ([]map[string]interface{}, string, bool) {
				st, out := r.restJSON("apigatewayv2", http.MethodGet, qs("/v2/apis", "maxResults", "100", "nextToken", tok), nil)
				return itemsOf(out, "Items"), strOf(out, "NextToken"), st == 200
			}, func(api map[string]interface{}) {
				id := strOf(api, "ApiId")
				sw.enqueue(func(sw *sweepRun) {
					pageOf(r, func(tok string) ([]map[string]interface{}, string, bool) {
						st, out := r.restJSON("apigatewayv2", http.MethodGet, qs("/v2/apis/"+url.PathEscape(id)+"/integrations", "maxResults", "100", "nextToken", tok), nil)
						return itemsOf(out, "Items"), strOf(out, "NextToken"), st == 200
					}, func(in map[string]interface{}) {
						if hiddenURI(strOf(in, "IntegrationUri")) || namesHidden(in["RequestParameters"]) || namesHidden(in["RequestTemplates"]) {
							r.call("apigatewayv2", http.MethodDelete, "/v2/apis/"+url.PathEscape(id)+"/integrations/"+url.PathEscape(strOf(in, "IntegrationId")), nil, nil, 10*time.Second)
							sw.rec("apigateway-integration", id+"/"+strOf(in, "IntegrationId"))
						}
					})
				})
			})
		},
	}
}

var (
	sweepMemberRe = regexp.MustCompile(`(?s)<member[^>]*>.*?</member>`)
	sweepBucketRe = regexp.MustCompile(`<Bucket>\s*<Name>([^<]+)</Name>`)
)

func xmlField(block, name string) string {
	m := regexp.MustCompile(`<` + name + `>([^<]*)</` + name + `>`).FindStringSubmatch(block)
	if m == nil {
		return ""
	}
	return m[1]
}
